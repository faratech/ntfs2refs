//! Provision only a new owned dynamic VHDX. No caller-supplied physical disk or
//! source volume can enter the GPT/formatter boundary. Permanent attachment and
//! backing files survive failure/Drop for inspection and explicit recovery.
use crate::{
    attestation_native::Privileges,
    discovery,
    general_layout::GeneralDiskBinding,
    layout::{self, PartitionIdentity, invalid},
    native,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    mem,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, PathBuf, Prefix},
    process::{Command, Stdio},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        Storage::Vhd::*,
        System::{
            IO::DeviceIoControl,
            Ioctl::{
                CREATE_DISK, CREATE_DISK_0, CREATE_DISK_GPT, IOCTL_DISK_CREATE_DISK,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_DISK_GET_LENGTH_INFO,
                IOCTL_DISK_SET_DRIVE_LAYOUT_EX, IOCTL_DISK_UPDATE_PROPERTIES, PARTITION_STYLE_GPT,
            },
            SystemInformation::GetSystemDirectoryW,
        },
    },
    core::GUID,
};

const OFFSET: u64 = 32 << 20;
const MARGIN: u64 = 64 << 20;
const MAX_LAYOUT: usize = 48 + 128 * 144;
/// How long the partition table of a new working disk is waited for, in
/// pauses between the looks at it.
const GPT_SETTLE_SECONDS: u64 = 30;
/// How long the volume of a new working disk is waited for after it is
/// partitioned, grown or formatted, from the first look at it.
const STAGE_PUBLICATION_SECONDS: u64 = 15;

mod recovery;
pub use recovery::{ReattachedShadow, attached_image_paths, detach_left_behind, reattach_existing};
mod backing_resources;
mod retirement;
pub use backing_resources::{BackingResourceGuard, BackingResourceObservation};
mod creation_resources;
pub use creation_resources::{
    NativeCreationAdmission, NativeCreationObservation, admit_fresh_native_backing,
};
/// This is the constructor's actual configured dynamic VHDX allocation block.
pub const NATIVE_VHDX_ALLOCATION_QUANTUM_BYTES: u32 = 2 << 20;
pub use retirement::{
    ShadowRetirementReceipt, StagingAllocationMeter, StagingAllocationObservation,
};
pub mod growth_probe;
pub mod refs_extent;

/// Requested native formatter profile, not a trust or compatibility claim.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub enum TargetFormatProfile {
    #[default]
    #[serde(rename = "dev-drive")]
    DevDrive,
    #[serde(rename = "standard")]
    StandardReFs,
}

impl TargetFormatProfile {
    pub const fn is_dev_drive(self) -> bool {
        matches!(self, Self::DevDrive)
    }

    /// The format of a run that names none. On Windows Server it is the
    /// ordinary ReFS volume that a server's data volume is; on a workstation
    /// edition it is the Dev Drive, the ReFS volume that every edition of
    /// Windows 11 formats (the lab's Windows 11 refuses to format an
    /// ordinary one). A Windows boot volume is admitted as a Dev Drive only,
    /// whatever the edition.
    pub const fn default_for(windows_server: bool, windows_boot_volume: bool) -> Self {
        if windows_server && !windows_boot_volume {
            Self::StandardReFs
        } else {
            Self::DevDrive
        }
    }
}

impl std::fmt::Display for TargetFormatProfile {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::DevDrive => "dev-drive",
            Self::StandardReFs => "standard",
        })
    }
}

impl std::str::FromStr for TargetFormatProfile {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dev-drive" => Ok(Self::DevDrive),
            "standard" => Ok(Self::StandardReFs),
            _ => Err(invalid("target format must be dev-drive or standard")),
        }
    }
}

pub struct ManagedShadow {
    pub binding: GeneralDiskBinding,
    pub path: PathBuf,
    pub virtual_disk_id: String,
    format_policy: crate::volume_policy::Observation,
    // Closing a permanently attached virtual handle does not detach it.
    _attachment: AttachedDisk,
    // Same-file ownership is retained from creation. Ordinary Drop still
    // neither detaches this disk nor deletes any backing/recovery file.
    _backing: retirement::OwnedBacking,
    _owned_binding: GeneralDiskBinding,
}

impl ManagedShadow {
    /// Actual read-only observation on this newly formatted owned volume.
    /// Its trust result is not inherited by the converted source volume.
    pub fn format_policy(&self) -> &crate::volume_policy::Observation {
        &self.format_policy
    }
}
struct VirtualHandle(HANDLE);
impl Drop for VirtualHandle {
    fn drop(&mut self) {
        // SAFETY: this uniquely owns the successful provider handle. No detach
        // or deletion is attempted, including on an error path.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct CreatedDisk {
    handle: VirtualHandle,
    id: GUID,
    size: u64,
    logical: u32,
    physical: u32,
}
struct AttachedDisk {
    created: CreatedDisk,
    number: u32,
}

// Private, sealed-by-module ownership boundary. Callers cannot implement this
// trait or turn a deserialized disk route into GPT/formatter permission.
#[derive(Clone, Copy)]
struct FreshDiskGeometry {
    number: u32,
    bytes: u64,
    logical: u32,
    physical: u32,
}
trait FreshDiskOwner {
    fn geometry(&self) -> FreshDiskGeometry;
    fn verify_owned(&self) -> io::Result<()>;
}
impl FreshDiskOwner for AttachedDisk {
    fn geometry(&self) -> FreshDiskGeometry {
        FreshDiskGeometry {
            number: self.number,
            bytes: self.created.size,
            logical: self.created.logical,
            physical: self.created.physical,
        }
    }
    fn verify_owned(&self) -> io::Result<()> {
        self.verify_provider()
    }
}
fn validate_owned_partition(owner: &impl FreshDiskOwner, partition_bytes: u64) -> io::Result<()> {
    let geometry = owner.geometry();
    if partition_bytes < 4096
        || !partition_bytes.is_multiple_of(4096)
        || partition_bytes
            .checked_add(MARGIN)
            .is_none_or(|bytes| bytes > geometry.bytes)
        || geometry.bytes > i64::MAX as u64
        || !matches!(geometry.logical, 512 | 4096)
        || !matches!(geometry.physical, 512 | 4096)
        || geometry.physical < geometry.logical
    {
        return Err(invalid("owned staging partition/sector geometry differs"));
    }
    Ok(())
}

fn win(error: u32) -> io::Result<()> {
    if error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(error as i32))
    }
}
fn wide(value: &str) -> io::Result<Vec<u16>> {
    let text: Vec<_> = value.encode_utf16().collect();
    if text.len() > 32760 || text.contains(&0) {
        return Err(invalid("staging path bounds differ"));
    }
    Ok(text.into_iter().chain(Some(0)).collect())
}
fn guid_bytes(g: &GUID) -> [u8; 16] {
    let mut b = [0; 16];
    b[..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..].copy_from_slice(&g.data4);
    b
}
fn guid_text(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}
fn random_guid() -> io::Result<GUID> {
    let mut b = [0u8; 16];
    // SAFETY: initialized fixed buffer; the system-preferred RNG needs no handle.
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            b.as_mut_ptr(),
            16,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "staging GUID RNG NTSTATUS {status:#x}"
        )));
    }
    b[7] = (b[7] & 15) | 0x40;
    b[8] = (b[8] & 63) | 0x80;
    Ok(GUID {
        data1: u32::from_le_bytes(b[..4].try_into().unwrap()),
        data2: u16::from_le_bytes(b[4..6].try_into().unwrap()),
        data3: u16::from_le_bytes(b[6..8].try_into().unwrap()),
        data4: b[8..].try_into().unwrap(),
    })
}
fn control(file: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    if input.len() > MAX_LAYOUT || capacity > 65536 {
        return Err(invalid("staging IOCTL bound"));
    }
    let mut words = vec![0u64; capacity.div_ceil(8)];
    let mut used = 0;
    // SAFETY: borrowed owned-disk handle, bounded input, aligned initialized
    // output and synchronous call; pointers are not retained by Windows.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if capacity == 0 {
                ptr::null_mut()
            } else {
                words.as_mut_ptr().cast()
            },
            capacity as u32,
            &mut used,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if used as usize > capacity {
        return Err(invalid("oversized staging IOCTL output"));
    }
    // SAFETY: used is bounded by the initialized allocation advertised above.
    Ok(unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), used as usize) }.to_vec())
}

impl CreatedDisk {
    fn attach(self) -> io::Result<AttachedDisk> {
        let mut p = ATTACH_VIRTUAL_DISK_PARAMETERS::default();
        p.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
        // SAFETY: actual newly created provider handle and complete version1
        // parameters. Permanent lifetime is intentional for crash recovery.
        win(unsafe {
            AttachVirtualDisk(
                self.handle.0,
                ptr::null_mut(),
                ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME
                    | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                0,
                &p,
                ptr::null(),
            )
        })?;
        let mut path = [0u16; 256];
        let mut bytes = 512;
        // SAFETY: live provider handle and bounded initialized UTF-16 buffer.
        win(unsafe { GetVirtualDiskPhysicalPath(self.handle.0, &mut bytes, path.as_mut_ptr()) })?;
        let end = path
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| invalid("unterminated provider path"))?;
        let path =
            String::from_utf16(&path[..end]).map_err(|_| invalid("invalid provider path"))?;
        let number = path
            .strip_prefix("\\\\.\\PhysicalDrive")
            .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| invalid("provider disk path differs"))?;
        let attached = AttachedDisk {
            created: self,
            number,
        };
        attached.verify_provider()?;
        Ok(attached)
    }
}
impl AttachedDisk {
    fn query(&self, version: GET_VIRTUAL_DISK_INFO_VERSION) -> io::Result<Vec<u8>> {
        let mut words = [0u64; 32];
        words[0] = version as u64;
        let mut size = 256;
        let mut used = 0;
        // SAFETY: aligned, initialized GET_VIRTUAL_DISK_INFO union storage;
        // each checked query fits the bounded 256-byte native union.
        win(unsafe {
            GetVirtualDiskInformation(
                self.created.handle.0,
                &mut size,
                words.as_mut_ptr().cast(),
                &mut used,
            )
        })?;
        if !(8..=256).contains(&used) {
            return Err(invalid("provider query size differs"));
        }
        // SAFETY: used was checked against the initialized union storage.
        Ok(
            unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), used as usize) }
                .to_vec(),
        )
    }
    fn verify_provider(&self) -> io::Result<()> {
        let id = self.query(GET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID)?;
        let size = self.query(GET_VIRTUAL_DISK_INFO_SIZE)?;
        let kind = self.query(GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE)?;
        let physical = self.query(GET_VIRTUAL_DISK_INFO_VHD_PHYSICAL_SECTOR_SIZE)?;
        if id.get(8..24) != Some(guid_bytes(&self.created.id).as_slice())
            || layout::u64_at(&size, 8)? != self.created.size
            || layout::u32_at(&size, 24)? != 2 << 20
            || layout::u32_at(&size, 28)? != self.created.logical
            || layout::u32_at(&kind, 8)? != 3
            || layout::u32_at(&physical, 8)? != self.created.physical
        {
            return Err(invalid("created provider identity/type/geometry differs"));
        }
        Ok(())
    }
    fn initialize(
        &self,
        partition_bytes: u64,
        stage_path: &Path,
    ) -> io::Result<GeneralDiskBinding> {
        self.verify_provider()?;
        if native::current_windows_disk(&mut Vec::new())? == self.number {
            return Err(invalid("new staging provider routes to Windows disk"));
        }
        let disk =
            native::device_file(&format!("\\\\.\\PhysicalDrive{}", self.number), true, false)?;
        let binding = initialize_new_owned(self, &disk, partition_bytes)?;
        drop(disk);
        rediscover_stage(binding, stage_path, "partition-volume")
    }
}

// Only the live fresh owner and its actual retained native handle enter. The
// thin caller keeps that same WRITE-capable handle across subsequent format.
fn initialize_new_owned(
    owner: &impl FreshDiskOwner,
    disk: &File,
    partition_bytes: u64,
) -> io::Result<GeneralDiskBinding> {
    owner.verify_owned()?;
    validate_owned_partition(owner, partition_bytes)?;
    let geometry = owner.geometry();
    if native::current_windows_disk(&mut Vec::new())? == geometry.number {
        return Err(invalid("new staging provider routes to Windows disk"));
    }
    let length = control(disk, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)?;
    if layout::u64_at(&length, 0)? != geometry.bytes {
        return Err(invalid("owned staging disk length differs"));
    }
    let initial = control(disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?;
    if !(initial.len() == 48 && initial.iter().all(|v| *v == 0))
        && !(initial.len() >= 48
            && layout::u32_at(&initial, 0)? == 2
            && layout::u32_at(&initial, 4)? == 0)
    {
        return Err(invalid("new owned staging disk is not RAW"));
    }
    let disk_guid = random_guid()?;
    let partition_guid = random_guid()?;
    let mut create = CREATE_DISK::default();
    create.PartitionStyle = PARTITION_STYLE_GPT;
    create.Anonymous = CREATE_DISK_0 {
        Gpt: CREATE_DISK_GPT {
            DiskId: disk_guid,
            MaxPartitionCount: 128,
        },
    };
    // SAFETY: zero-initialized complete CREATE_DISK C layout, synchronous
    // input only; this handle belongs solely to the sealed fresh owner.
    let input = unsafe {
        std::slice::from_raw_parts(
            (&create as *const CREATE_DISK).cast::<u8>(),
            mem::size_of::<CREATE_DISK>(),
        )
    };
    control(disk, IOCTL_DISK_CREATE_DISK, input, 0)?;
    // Wait for the real GPT usable bounds. Preserve an observed MSR;
    // CREATE_DISK may leave an empty table, in which case ready_layout
    // explicitly creates the MSR on this owned new disk only.
    //
    // The table is usually there within a few tens of milliseconds, and a
    // quarter second after every look made this wait at least that long. The
    // pauses now start at 10 ms and double up to the quarter second they
    // were; the time allowed is what it was, 120 pauses of a quarter second.
    // Only a table that is not there yet is waited for: a refused control and
    // a table that differs end the wait at once, as before.
    let mut wait = native::PublicationWait::begin_for(GPT_SETTLE_SECONDS);
    let settled = loop {
        control(disk, IOCTL_DISK_UPDATE_PROPERTIES, &[], 0)?;
        let raw = control(disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?;
        if let Some(layout) = ready_layout(&raw, &disk_guid, partition_bytes)? {
            break Some(layout);
        }
        if !wait.pause() {
            break None;
        }
    };
    let (mut header, msr) = settled.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "owned staging GPT did not settle; attachment retained",
        )
    })?;
    let number = layout::u32_at(&msr, 24)?
        .checked_add(1)
        .ok_or_else(|| invalid("staging partition number overflow"))?;
    if number > 128 {
        return Err(invalid("staging partition number exceeds GPT profile"));
    }
    header[4..8].copy_from_slice(&2u32.to_le_bytes());
    let mut data = vec![0u8; 144];
    data[..4].copy_from_slice(&1u32.to_le_bytes());
    data[8..16].copy_from_slice(&OFFSET.to_le_bytes());
    data[16..24].copy_from_slice(&partition_bytes.to_le_bytes());
    data[24..28].copy_from_slice(&number.to_le_bytes());
    data[28] = 1;
    data[32..48].copy_from_slice(&layout::guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?);
    data[48..64].copy_from_slice(&guid_bytes(&partition_guid));
    for (i, c) in "n2r-shadow".encode_utf16().enumerate() {
        data[72 + i * 2..74 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    header.extend_from_slice(&msr);
    header.extend_from_slice(&data);
    control(disk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX, &header, 0)?;
    control(disk, IOCTL_DISK_UPDATE_PROPERTIES, &[], 0)?;
    let binding = GeneralDiskBinding {
        layout_profile: Default::default(),
        disk_number: geometry.number,
        // Placeholder only for syntax validation: discovery replaces this
        // with the actual volume whose physical extents match this partition.
        volume_guid: guid_text(&partition_guid),
        identity: PartitionIdentity {
            disk_guid: guid_text(&disk_guid),
            partition_guid: guid_text(&partition_guid),
            partition_number: number,
            disk_bytes: geometry.bytes,
            partition_offset: OFFSET,
            partition_bytes,
            logical_sector_bytes: geometry.logical,
            physical_sector_bytes: geometry.physical,
        },
    };
    let actual = control(disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?;
    binding.validate_layout(&actual)?;
    Ok(binding)
}

fn sidecar(path: &Path, phase: &str) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path.with_extension(phase))
}

/// Each native attempt keeps its full per-call controls and identity checks.
/// Diagnostic JSONL is bounded and never creates/replays an authority token.
///
/// The volume is usually there within a few tens of milliseconds of the
/// partitioning or the format, and a quarter second after every attempt made
/// each of these waits at least that long. The pauses now start at 10 ms and
/// double up to the quarter second they were. The time allowed is what it
/// was, [`STAGE_PUBLICATION_SECONDS`] from the first attempt, the attempts
/// themselves counted; it bounds the attempts (five more than the sixty
/// there were, at most) and with them the diagnostic. Only absence is
/// retried, and when the time has passed the caller is told what the last
/// attempt found, as before.
fn rediscover_stage(
    binding: GeneralDiskBinding,
    path: &Path,
    phase: &str,
) -> io::Result<GeneralDiskBinding> {
    let mut report = sidecar(path, &format!("{phase}.jsonl"))?;
    let started = Instant::now();
    let allowed = Duration::from_secs(STAGE_PUBLICATION_SECONDS);
    let mut wait = native::PublicationWait::begin_for(STAGE_PUBLICATION_SECONDS);
    let mut written = 0usize;
    let mut attempt = 0u32;
    let outcome = loop {
        attempt += 1;
        let mut events = Vec::new();
        let observed = native::rediscover_general_volume(binding.clone(), &mut events);
        let record = serde_json::json!({"kind":"managed-shadow-volume-discovery-attempt",
            "phase":phase,"attempt":attempt,"elapsed_milliseconds":started.elapsed().as_millis(),
            "requested_binding":binding,"observed_binding":observed.as_ref().ok(),
            "error":observed.as_ref().err().map(ToString::to_string),"events":events,
            "diagnostic_only":true,"serialized_observation_is_not_authority":true});
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        written = written
            .checked_add(bytes.len() + 1)
            .filter(|count| *count <= 16 * 1024 * 1024)
            .ok_or_else(|| invalid("staging discovery diagnostic exceeds 16 MiB"))?;
        report.write_all(&bytes)?;
        report.write_all(b"\n")?;
        match observed {
            Ok(actual) => break Ok(actual),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && started.elapsed() < allowed
                    && wait.pause() => {}
            Err(error) => break Err(error),
        }
    };
    // The diagnostic is synchronized once, when the wait is over, whichever
    // way it ended: the volume was found, the time passed, or the discovery
    // refused. A sync after every attempt's line made each attempt wait for
    // the disk, and no attempt reads the diagnostic; what the caller gets is
    // what the last attempt found. As before, a diagnostic that cannot be
    // synchronized is reported in place of that.
    report.sync_all()?;
    outcome
}

fn ready_layout(raw: &[u8], disk: &GUID, bytes: u64) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    if raw.len() < 48 || layout::u32_at(raw, 0)? != 1 {
        return Ok(None);
    }
    if raw[8..24] != guid_bytes(disk) {
        return Err(invalid("new staging GPT identity changed"));
    }
    let count = layout::u32_at(raw, 4)? as usize;
    if count > 128 || raw.len() != 48 + count * 144 {
        return Err(invalid("incomplete staging GPT layout"));
    }
    let first = layout::u64_at(raw, 24)?;
    let usable = layout::u64_at(raw, 32)?;
    let end = first
        .checked_add(usable)
        .ok_or_else(|| invalid("GPT usable bounds overflow"))?;
    if first > OFFSET || OFFSET.checked_add(bytes).is_none_or(|v| v > end) {
        return Err(invalid(
            "owned staging data extent escapes actual GPT usable bounds",
        ));
    }
    let msr_type = layout::guid_bytes("e3c9e316-0b5c-4db8-817d-f92df00215ae")?;
    let mut msr = None;
    for row in raw[48..].chunks_exact(144) {
        let number = layout::u32_at(row, 24)?;
        let length = layout::u64_at(row, 16)?;
        if number == 0 && length == 0 && row[32..48] == [0; 16] {
            continue;
        }
        let offset = layout::u64_at(row, 8)?;
        if msr.is_some()
            || layout::u32_at(row, 0)? != 1
            || number == 0
            || row[48..64] == [0; 16]
            || row[32..48] != msr_type
            || length == 0
            || length > 16 << 20
            || offset < first
            || offset.checked_add(length).is_none_or(|v| v > OFFSET)
        {
            return Err(invalid(
                "unexpected or oversized partition on owned new staging disk",
            ));
        }
        msr = Some(row.to_vec());
    }
    if msr.is_none() {
        let offset = first.max(1 << 20).div_ceil(1 << 20) * (1 << 20);
        let length = 16u64 << 20;
        if offset
            .checked_add(length)
            .is_none_or(|v| v > OFFSET || v > end)
        {
            return Err(invalid("owned staging GPT has no room for an MSR"));
        }
        let mut entry = vec![0u8; 144];
        entry[..4].copy_from_slice(&1u32.to_le_bytes());
        entry[8..16].copy_from_slice(&offset.to_le_bytes());
        entry[16..24].copy_from_slice(&length.to_le_bytes());
        entry[24..28].copy_from_slice(&1u32.to_le_bytes());
        entry[28] = 1;
        entry[32..48].copy_from_slice(&msr_type);
        entry[48..64].copy_from_slice(&guid_bytes(&random_guid()?));
        msr = Some(entry);
    }
    Ok(msr.map(|entry| (raw[..48].to_vec(), entry)))
}

/// Create/attach/partition/format only a new owned dynamic VHDX. Provider errors
/// (including unsupported format sizes) preserve staging and never touch source.
pub fn create(
    path: &Path,
    partition_bytes: u64,
    logical_sector: u32,
    physical_sector: u32,
) -> io::Result<ManagedShadow> {
    create_with_profile(
        path,
        partition_bytes,
        logical_sector,
        physical_sector,
        TargetFormatProfile::DevDrive,
    )
}

/// Format exactly the requested profile. Unsupported native formatting never
/// retries another profile or touches the source volume.
pub fn create_with_profile(
    path: &Path,
    partition_bytes: u64,
    logical_sector: u32,
    physical_sector: u32,
    target_format: TargetFormatProfile,
) -> io::Result<ManagedShadow> {
    if partition_bytes < 4096
        || !partition_bytes.is_multiple_of(4096)
        || !matches!(logical_sector, 512 | 4096)
        || !matches!(physical_sector, 512 | 4096)
        || physical_sector < logical_sector
        || !path.is_absolute()
        || path.exists()
        || path
            .extension()
            .and_then(|v| v.to_str())
            .is_none_or(|v| !v.eq_ignore_ascii_case("vhdx"))
    {
        return Err(invalid(
            "fresh dynamic staging path or sector geometry differs",
        ));
    }
    for part in path.components() {
        match part {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                return Err(invalid("local staging path required"));
            }
            Component::ParentDir => return Err(invalid("staging parent traversal refused")),
            Component::Normal(v)
                if v.to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                return Err(invalid("ambiguous staging path"));
            }
            _ => {}
        }
    }
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.file_attributes() & 0x400 != 0 {
            return Err(invalid("ordinary staging ancestry required"));
        }
    }
    // Hold the actual ordinary parent route and its independently sampled free
    // floor before CreateVirtualDisk can allocate any backing bytes.
    let capacity = admit_fresh_native_backing(path)?;
    let size = partition_bytes
        .checked_add(MARGIN)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(|| invalid("staging virtual size overflow"))?;
    let id = random_guid()?;
    let name = wide(
        path.to_str()
            .ok_or_else(|| invalid("Unicode staging path required"))?,
    )?;
    let storage = VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    let mut params = CREATE_VIRTUAL_DISK_PARAMETERS::default();
    params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    params.Anonymous = CREATE_VIRTUAL_DISK_PARAMETERS_0 {
        Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
            UniqueId: id,
            MaximumSize: size,
            BlockSizeInBytes: NATIVE_VHDX_ALLOCATION_QUANTUM_BYTES,
            SectorSizeInBytes: logical_sector,
            PhysicalSectorSizeInBytes: physical_sector,
            ..Default::default()
        },
    };
    // Refuse an unavailable management privilege before creating any backing.
    // The lease restores its actual previous state on every error path.
    let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    capacity.check()?;
    let mut handle = ptr::null_mut();
    // SAFETY: version2 default-zero parameters have no parent/source path;
    // zero flags select dynamic allocation. Creation refuses an existing file.
    win(unsafe {
        CreateVirtualDisk(
            &storage,
            name.as_ptr(),
            VIRTUAL_DISK_ACCESS_NONE,
            ptr::null_mut(),
            CREATE_VIRTUAL_DISK_FLAG_NONE,
            0,
            &params,
            ptr::null(),
            &mut handle,
        )
    })?;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(invalid("virtual disk provider returned no handle"));
    }
    let created = CreatedDisk {
        handle: VirtualHandle(handle),
        id,
        size,
        logical: logical_sector,
        physical: physical_sector,
    };
    let backing = retirement::OwnedBacking::enroll(path)?;
    capacity.require_backing(&backing)?;
    capacity.check()?;
    let attached = created.attach()?;
    capacity.check()?;
    let binding = attached.initialize(partition_bytes, path)?;
    privileges.restore()?;
    capacity.require_backing(&backing)?;
    capacity.check()?;
    let (binding, format_policy, _) = format_new_owned(&attached, binding, path, target_format)?;
    capacity.require_backing(&backing)?;
    capacity.check()?;
    Ok(ManagedShadow {
        _owned_binding: binding.clone(),
        binding,
        path: path.to_owned(),
        virtual_disk_id: guid_text(&id),
        format_policy,
        _attachment: attached,
        _backing: backing,
    })
}

/// The last lines format.com wrote, which is where it gives its reason
/// ("ReFS file system is not supported on this device."). Empty when the
/// logs cannot be read: the refusal is reported either way.
fn formatter_said(path: &Path) -> String {
    let mut lines = Vec::new();
    for log in ["format.stdout.log", "format.stderr.log"] {
        let Ok(bytes) = fs::read(path.with_extension(log)) else {
            continue;
        };
        let tail = &bytes[bytes.len().saturating_sub(4096)..];
        lines.extend(
            String::from_utf8_lossy(tail)
                .lines()
                .map(|line| {
                    line.chars()
                        .filter(|c| !c.is_control())
                        .collect::<String>()
                        .trim()
                        .to_owned()
                })
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .take(2)
                .rev(),
        );
    }
    lines.join(" / ")
}

/// What a run says when Windows will not format its working volume. The
/// source has not been written to at this point.
fn format_refusal(
    target_format: TargetFormatProfile,
    cluster_bytes: u64,
    status: &str,
    said: &str,
    path: &Path,
) -> String {
    let (asked, advice) = match target_format {
        TargetFormatProfile::DevDrive => (
            "a Dev Drive (format /FS:ReFS /DevDrv)",
            "Dev Drive formatting may be turned off on this machine, by policy or because this Windows does not have it",
        ),
        TargetFormatProfile::StandardReFs => (
            "an ordinary ReFS volume (format /FS:ReFS)",
            crate::windows_build::STANDARD_REFS_FORMAT_REFUSAL,
        ),
    };
    let said = if said.is_empty() {
        String::new()
    } else {
        format!(", saying: {said}")
    };
    format!(
        "Windows would not format the run's temporary working volume as {asked} with {cluster_bytes}-byte clusters: format.com ended with {status}{said}. {advice}. There is no fallback from one target format to the other. Nothing has been written to the volume to convert. The working files, with the formatter's full output, are kept beside {}",
        path.display()
    )
}

// Private formatting boundary, shared by VHDX and constructor-owned thin disks.
// No public API accepts an arbitrary binding as formatting authority.
fn format_new_owned(
    owner: &impl FreshDiskOwner,
    binding: GeneralDiskBinding,
    path: &Path,
    target_format: TargetFormatProfile,
) -> io::Result<(
    GeneralDiskBinding,
    crate::volume_policy::Observation,
    Vec<u8>,
)> {
    owner.verify_owned()?;
    validate_owned_partition(owner, binding.identity.partition_bytes)?;
    let geometry = owner.geometry();
    let partition_bytes = binding.identity.partition_bytes;
    if binding.disk_number != geometry.number
        || binding.identity.disk_bytes != geometry.bytes
        || binding.identity.logical_sector_bytes != geometry.logical
        || binding.identity.physical_sector_bytes != geometry.physical
    {
        return Err(invalid(
            "owned staging formatter binding differs from live owner",
        ));
    }
    let mut system = [0u16; 32768];
    // SAFETY: initialized buffer and explicit WCHAR capacity.
    let count = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count >= system.len() {
        return Err(invalid("system directory exceeds bound"));
    }
    let formatter = PathBuf::from(
        String::from_utf16(&system[..count]).map_err(|_| invalid("system directory UTF-16"))?,
    )
    .join("format.com");
    // This volume route derives ONLY from the sealed freshly owned device.
    // No shell, caller-selected physical device, stdin answer, or source enters.
    let stdout = sidecar(path, "format.stdout.log")?;
    let stderr = sidecar(path, "format.stderr.log")?;
    let mut format_args = vec![binding.volume_path()?, "/FS:ReFS".into()];
    if target_format.is_dev_drive() {
        format_args.push("/DevDrv".into());
    }
    let cluster = crate::target_cluster::bytes();
    format_args.extend([
        "/Q".to_owned(),
        // format.com spells 65536 as 64K and does not take the number.
        if cluster == 65536 {
            "/A:64K".to_owned()
        } else {
            format!("/A:{cluster}")
        },
        "/V:n2r-retained-shadow".to_owned(),
        "/Y".to_owned(),
    ]);
    let status = Command::new(formatter)
        .args(&format_args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .status()?;
    stdout.sync_all()?;
    stderr.sync_all()?;
    if !status.success() {
        let said = formatter_said(path);
        return Err(io::Error::other(format_refusal(
            target_format,
            cluster,
            &status.to_string(),
            &said,
            path,
        )));
    }
    owner.verify_owned()?;
    // Formatting may replace the filesystem's mount-manager identity. Rebind
    // only by the unchanged actual GPT partition and physical volume extents.
    let binding = rediscover_stage(binding, path, "formatted-volume")?;
    let observed = discovery::discover(&(binding.volume_path()? + "\\"), discovery::Role::Shadow)?;
    if observed.binding != binding
        || observed.filesystem != "ReFS"
        || observed.label != "n2r-retained-shadow"
        || observed.bytes_per_sector != geometry.logical
        || u64::from(observed.bytes_per_sector) * u64::from(observed.sectors_per_cluster) != cluster
    {
        return Err(invalid("formatted owned staging binding/profile differs"));
    }
    let volume = native::device_file(&binding.volume_path()?, false, false)?;
    let data = control(&volume, 0x000902d8, &[], 256)?;
    // The version is whatever this Windows formats; the run works with that
    // one from here on. A version it cannot work with is refused by name.
    if data.len() >= 64 {
        crate::target_refs_version::choose(layout::u32_at(&data, 4)?, layout::u32_at(&data, 8)?)
            .map_err(|error| {
                io::Error::other(format!(
                    "the shadow Windows formatted cannot be used: {error}; backing retained at {}",
                    path.display()
                ))
            })?;
    }
    if data.len() < 64
        || !(64..=data.len()).contains(&(layout::u32_at(&data, 0)? as usize))
        || layout::u64_at(&data, 24)? != partition_bytes / u64::from(geometry.logical)
        || layout::u64_at(&data, 32)? != partition_bytes / cluster
        || layout::u32_at(&data, 56)? != geometry.logical
        || u64::from(layout::u32_at(&data, 60)?) != cluster
    {
        // Keep full-partition admission strict. A native formatter can declare
        // a shorter filesystem extent; diagnose it without granting that
        // uncovered physical tail allocation or conversion authority.
        let extent = refs_extent::observe_formatted(&volume, &binding, &data);
        let mut extent_file = sidecar(path, "refs-extent.json")?;
        serde_json::to_writer_pretty(
            &mut extent_file,
            &serde_json::json!({
                "schema_version":1,"kind":"owned-shadow-rejected-geometry-diagnostic",
                "binding":binding,"native_refs_volume_data":data,
                "observation":extent.as_ref().ok(),
                "observation_error":extent.as_ref().err().map(ToString::to_string),
                "strict_full_partition_profile_retained":true,
                "conversion_profile_qualified":false,"grants_source_or_replay_authority":false,
            }),
        )
        .map_err(io::Error::other)?;
        extent_file.sync_all()?;
        if let Ok(extent) = extent
            && !extent.full_partition_extent_matches
        {
            return Err(invalid(&format!(
                "formatted owned staging filesystem extent {} bytes differs from physical GPT partition {} bytes; uncovered tail [{}, {}) is {} bytes with unknown allocation, not free; conversion profile unqualified",
                extent.filesystem_bytes,
                extent.physical_partition_bytes,
                extent.uncovered_tail_offset,
                extent.physical_partition_bytes,
                extent.uncovered_tail_bytes,
            )));
        }
        return Err(invalid(&format!(
            "formatted owned staging is not the selected profile: ReFS covering the whole partition in {cluster}-byte clusters",
        )));
    }
    let mut policy_events = Vec::new();
    let observed_policy = crate::volume_policy::observe(&binding, &mut policy_events);
    let mut policy_file = sidecar(path, "volume-policy.json")?;
    serde_json::to_writer_pretty(
        &mut policy_file,
        &serde_json::json!({
            "schema_version":1,"kind":"owned-shadow-format-policy",
            "requested_target_format":target_format,
            "actual_policy":observed_policy.as_ref().ok(),
            "observation_error":observed_policy.as_ref().err().map(ToString::to_string),
            "events":policy_events,"explicit_trust_or_filter_configuration_changed":false,
            "grants_source_or_replay_authority":false,
        }),
    )
    .map_err(io::Error::other)?;
    policy_file.sync_all()?;
    let format_policy = observed_policy?;
    if format_policy.developer_volume != Some(target_format.is_dev_drive()) {
        return Err(invalid(
            "formatted owned staging developer-volume designation is unknown or differs from the requested target format",
        ));
    }
    owner.verify_owned()?;
    Ok((binding, format_policy, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_that_names_no_format_gets_the_one_its_windows_makes_for_data() {
        use TargetFormatProfile::{DevDrive, StandardReFs};
        // (Windows Server, a Windows boot volume)
        assert_eq!(TargetFormatProfile::default_for(false, false), DevDrive);
        assert_eq!(TargetFormatProfile::default_for(true, false), StandardReFs);
        // A boot volume is a Dev Drive whatever the edition.
        assert_eq!(TargetFormatProfile::default_for(false, true), DevDrive);
        assert_eq!(TargetFormatProfile::default_for(true, true), DevDrive);
        // The names a run is given parse to the same two.
        assert_eq!(
            "dev-drive".parse::<TargetFormatProfile>().unwrap(),
            DevDrive
        );
        assert_eq!(
            "standard".parse::<TargetFormatProfile>().unwrap(),
            StandardReFs
        );
    }

    #[test]
    fn a_format_refusal_says_what_was_asked_what_windows_said_and_what_to_do() {
        let temp = std::env::temp_dir().join(format!("n2r-format-refusal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let path = temp.join("shadow.vhdx");
        fs::write(
            path.with_extension("format.stdout.log"),
            "The type of the file system is RAW.\r\nThe new file system is REFS.\r\n\r\nReFS file system is not supported on this device.\r\n",
        )
        .unwrap();
        let said = formatter_said(&path);
        assert!(
            said.ends_with("ReFS file system is not supported on this device."),
            "{said}"
        );
        let standard = format_refusal(
            TargetFormatProfile::StandardReFs,
            4096,
            "exit code: 4",
            &said,
            &path,
        );
        for expected in [
            "an ordinary ReFS volume",
            "4096-byte clusters",
            "exit code: 4",
            "ReFS file system is not supported on this device.",
            "--target-format dev-drive",
            "no fallback",
            "Nothing has been written to the volume to convert",
        ] {
            assert!(standard.contains(expected), "{expected}: {standard}");
        }
        // Without the formatter's output the refusal is still whole.
        let developer = format_refusal(
            TargetFormatProfile::DevDrive,
            65536,
            "exit code: 1",
            &formatter_said(&temp.join("absent.vhdx")),
            &path,
        );
        assert!(
            developer.contains("a Dev Drive") && developer.contains("exit code: 1. Dev Drive"),
            "{developer}"
        );
        fs::remove_dir_all(&temp).unwrap();
    }
}
