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
use std::{
    fs::{self, File},
    io, mem,
    os::windows::{fs::MetadataExt, io::AsRawHandle},
    path::{Component, Path, PathBuf, Prefix},
    process::{Command, Stdio},
    ptr,
    time::Duration,
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

pub struct ManagedShadow {
    pub binding: GeneralDiskBinding,
    pub path: PathBuf,
    pub virtual_disk_id: String,
    // Closing a permanently attached virtual handle does not detach it.
    _attachment: AttachedDisk,
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
            .filter(|n| *n <= 4095)
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
    fn initialize(&self, partition_bytes: u64) -> io::Result<GeneralDiskBinding> {
        self.verify_provider()?;
        if native::current_windows_disk(&mut Vec::new())? == self.number {
            return Err(invalid("new staging provider routes to Windows disk"));
        }
        let disk =
            native::device_file(&format!("\\\\.\\PhysicalDrive{}", self.number), true, false)?;
        let length = control(&disk, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)?;
        if layout::u64_at(&length, 0)? != self.created.size {
            return Err(invalid("owned staging disk length differs"));
        }
        let initial = control(&disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?;
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
        // input only; this handle belongs solely to the newly created VHDX.
        let input = unsafe {
            std::slice::from_raw_parts(
                (&create as *const CREATE_DISK).cast::<u8>(),
                mem::size_of::<CREATE_DISK>(),
            )
        };
        control(&disk, IOCTL_DISK_CREATE_DISK, input, 0)?;
        // Windows requires GPT/MSR arrival before SET_DRIVE_LAYOUT_EX. Query
        // the real layout, never synthesize usable bounds or replace its MSR.
        let mut settled = None;
        for _ in 0..120 {
            control(&disk, IOCTL_DISK_UPDATE_PROPERTIES, &[], 0)?;
            let raw = control(&disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?;
            if let Some(layout) = ready_layout(&raw, &disk_guid, partition_bytes)? {
                settled = Some(layout);
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let (mut header, msr) = settled.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "owned staging GPT/MSR did not settle; attachment retained",
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
        control(&disk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX, &header, 0)?;
        control(&disk, IOCTL_DISK_UPDATE_PROPERTIES, &[], 0)?;
        let binding = GeneralDiskBinding {
            disk_number: self.number,
            // Placeholder only for syntax validation: discovery replaces this
            // with the actual volume whose physical extents match this partition.
            volume_guid: guid_text(&partition_guid),
            identity: PartitionIdentity {
                disk_guid: guid_text(&disk_guid),
                partition_guid: guid_text(&partition_guid),
                partition_number: number,
                disk_bytes: self.created.size,
                partition_offset: OFFSET,
                partition_bytes,
                logical_sector_bytes: self.created.logical,
                physical_sector_bytes: self.created.physical,
            },
        };
        let actual = control(&disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?;
        binding.validate_layout(&actual)?;
        drop(disk);
        native::rediscover_general_volume_wait(binding, &mut Vec::new())
    }
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
            BlockSizeInBytes: 2 << 20,
            SectorSizeInBytes: logical_sector,
            PhysicalSectorSizeInBytes: physical_sector,
            ..Default::default()
        },
    };
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
    let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    let attached = created.attach()?;
    let binding = attached.initialize(partition_bytes)?;
    privileges.restore()?;
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
    // This volume route derives ONLY from the newly created provider handle.
    // No shell, caller-selected physical device, stdin answer, or source enters.
    let status = Command::new(formatter)
        .args([
            binding.volume_path()?,
            "/FS:ReFS".into(),
            "/DevDrv".into(),
            "/Q".into(),
            "/A:4096".into(),
            "/V:n2r-retained-shadow".into(),
            "/Y".into(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "owned staging native format refused ({status}); backing retained at {}",
            path.display()
        )));
    }
    attached.verify_provider()?;
    // Formatting may replace the filesystem's mount-manager identity. Rebind
    // only by the unchanged actual GPT partition and physical volume extents.
    let binding = native::rediscover_general_volume_wait(binding, &mut Vec::new())?;
    let observed = discovery::discover(&(binding.volume_path()? + "\\"), discovery::Role::Shadow)?;
    if observed.binding != binding
        || observed.filesystem != "ReFS"
        || observed.label != "n2r-retained-shadow"
        || observed.bytes_per_sector != logical_sector
        || u64::from(observed.bytes_per_sector) * u64::from(observed.sectors_per_cluster) != 4096
    {
        return Err(invalid("formatted owned staging binding/profile differs"));
    }
    let volume = native::device_file(&binding.volume_path()?, false, false)?;
    let data = control(&volume, 0x000902d8, &[], 256)?;
    if data.len() < 64
        || !(64..=data.len()).contains(&(layout::u32_at(&data, 0)? as usize))
        || layout::u32_at(&data, 4)? != 3
        || layout::u32_at(&data, 8)? != 14
        || layout::u64_at(&data, 24)? != partition_bytes / u64::from(logical_sector)
        || layout::u64_at(&data, 32)? != partition_bytes / 4096
        || layout::u32_at(&data, 56)? != logical_sector
        || layout::u32_at(&data, 60)? != 4096
    {
        return Err(invalid(
            "formatted owned staging is not the selected ReFS3.14 profile",
        ));
    }
    Ok(ManagedShadow {
        binding,
        path: path.to_owned(),
        virtual_disk_id: guid_text(&id),
        _attachment: attached,
    })
}
