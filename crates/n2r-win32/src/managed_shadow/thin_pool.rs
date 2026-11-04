//! Fresh private thin storage. Its separate consuming formatter accepts only
//! the live constructor owner, never an existing pool/binding or saved JSON.
use super::*;
use crate::{file_storage, reference_file, resource_native};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    os::windows::{ffi::OsStrExt, process::CommandExt},
};
use windows_sys::Win32::System::Ioctl::{
    IOCTL_STORAGE_GET_DEVICE_NUMBER, IOCTL_STORAGE_QUERY_PROPERTY,
};

const MEMBER_BYTES: u64 = 5 << 30;
const MEMBER_OVERHEAD: u64 = 128 << 20;
const METADATA_BYTES: u64 = 2 << 20;
const RUST_WORKSPACE: u64 = 2 << 20;
const RESPONSE_BYTES: u64 = 128 << 10;
const MAX_NOMINAL_MEMBER_BYTES: u64 = 64 << 40;
const FIXED_BACKING_PROFILE: &str = "fixed-two-5gib-members-v1";
const BOUNDED_BACKING_PROFILE: &str = "bounded-carrier-thin-overcommit-v2";
const POOL_CAPACITY_SCOPE: &str =
    "provider-reported nominal member address space; not physical carrier allocation";

mod bounded_carrier;
pub use bounded_carrier::CarrierObservation;
mod formatted;
pub use formatted::{FormattedThinShadow, FormattingObservation};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Budget {
    pub rust_ram_bytes: u64,
    /// Admission share and phase observations, NOT a child-process Job limit.
    pub powershell_ram_bytes: u64,
    pub scratch_bytes: u64,
    pub minimum_free_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct MemberRoute {
    number: u32,
    unique_id: String,
    object_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PoolRoute {
    unique_id: String,
    object_id: String,
    virtual_unique_id: String,
    virtual_object_id: String,
    number: u32,
    disk_unique_id: String,
    bytes: u64,
    divisor: u64,
    logical_sector: u32,
    physical_sector: u32,
}

/// Provider-reported mutable capacity in nominal member address space. With a
/// bounded carrier, neither allocation nor footprint measures physical host
/// backing. Carrier filesystem space and backing allocation are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PoolCapacity {
    pub size_bytes: u64,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub virtual_footprint_bytes: u64,
}

impl PoolCapacity {
    fn validate(&self, minimum_free: u64) -> io::Result<()> {
        if self.size_bytes.checked_sub(self.allocated_bytes) != Some(self.free_bytes)
            || self.virtual_footprint_bytes > self.size_bytes
            || self.free_bytes < minimum_free
        {
            return Err(invalid(
                "private thin pool cannot preserve its sampled free reserve",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema_version: u32,
    kind: String,
    success: bool,
    mode: String,
    nonce: String,
    subsystem: String,
    members: Vec<MemberRoute>,
    pool: Option<PoolRoute>,
    pool_capacity: Option<PoolCapacity>,
    sampled_child_working_set_bytes: u64,
    child_ram_hard_limit_enforced: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct Request<'a> {
    schema_version: u32,
    nonce: &'a str,
    subsystem: &'a str,
    goal_bytes: u64,
    member_virtual_bytes: u64,
    carrier_root: Option<&'a str>,
    member_numbers: [u32; 2],
    members: &'a [MemberRoute],
    pool: Option<&'a PoolRoute>,
    expected_partition: Option<&'a GeneralDiskBinding>,
    powershell_ram_bytes: u64,
    minimum_free_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RawDiskObservation {
    pub disk_number: u32,
    pub disk_bytes: u64,
    pub device: Vec<u8>,
    pub length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub layout: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub backing_profile: &'static str,
    pub nonce: String,
    pub requested_bytes: u64,
    pub actual_bytes: u64,
    pub native_size_divisor: u64,
    pub pool_unique_id: String,
    pub virtual_disk_unique_id: String,
    pub member_backing_paths: [PathBuf; 2],
    pub member_virtual_disk_ids: [String; 2],
    pub member_virtual_bytes_each: u64,
    pub nominal_member_virtual_bytes_total: u64,
    pub nominal_member_size_was_clamped: bool,
    /// Compares the native VD logical size, not actual written file data.
    pub logical_bytes_exceed_nominal_members: bool,
    pub provider_pool_capacity_scope: &'static str,
    pub bounded_carrier: Option<CarrierObservation>,
    pub host_allocation_excludes_nested_member_files: bool,
    pub native_disk: RawDiskObservation,
    pub retained_regular_file_allocation_bytes: u64,
    pub allocation_sample_precedes_this_observation_receipt: bool,
    pub sampled_available_resources: resource_native::AvailableResources,
    pub sampled_child_working_set_bytes: u64,
    pub budget: Budget,
    pub sampled_capacity_is_not_a_kernel_quota_or_reservation: bool,
    pub child_ram_hard_limit_enforced: bool,
    pub source_binding_supplied: bool,
    pub virtual_disk_gpt_created: bool,
    pub refs_formatted: bool,
    pub persistent_reattachment_qualified: bool,
    pub conversion_authorized: bool,
    pub automatic_cleanup_or_fallback: bool,
}

struct Member {
    attachment: AttachedDisk,
    backing: File,
    snapshot: reference_file::ReferenceFileSnapshot,
    path: PathBuf,
}

/// Only a successful live constructor can issue this owner. Member/provider
/// handles and root metadata identity remain held; Drop closes handles only.
/// The retained pool, virtual disk and member files survive every failure.
pub struct ThinPool {
    _members: [Member; 2],
    _root_handle: File,
    _script: File,
    _disk: File,
    root: PathBuf,
    root_file_id: String,
    root_guid_path: String,
    subsystem: String,
    nonce: String,
    goal: u64,
    budget: Budget,
    routes: Vec<MemberRoute>,
    pool: PoolRoute,
    script_snapshot: reference_file::ReferenceFileSnapshot,
    observation: Observation,
    carrier: Option<bounded_carrier::BoundedCarrier>,
}

fn text(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.encode_utf16().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(invalid("bounded storage identity required"));
    }
    Ok(())
}

fn ordinary_root(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.as_os_str().encode_wide().count() > 4096 {
        return Err(invalid(
            "bounded ordinary local thin storage directory required",
        ));
    }
    for component in path.components() {
        match component {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                return Err(invalid("local thin storage directory required"));
            }
            Component::CurDir | Component::ParentDir => {
                return Err(invalid("thin directory traversal refused"));
            }
            Component::Normal(p)
                if p.to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                return Err(invalid("ambiguous thin directory component"));
            }
            _ => {}
        }
    }
    for parent in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("thin directory ancestry is redirected"));
        }
    }
    Ok(())
}

fn file_snapshot(file: &File) -> io::Result<reference_file::ReferenceFileSnapshot> {
    let snapshot = reference_file::observe_reference_file_handle_with_limit(file, i64::MAX as u64)?;
    if snapshot.number_of_links != 1 {
        return Err(invalid("single-link owned thin storage file required"));
    }
    Ok(snapshot)
}

fn same_file(old: &reference_file::ReferenceFileSnapshot, file: &File) -> io::Result<()> {
    let now = file_snapshot(file)?;
    if old.volume_serial_number != now.volume_serial_number
        || old.file_id_128 != now.file_id_128
        || old.final_path != now.final_path
        || old.file_attributes != now.file_attributes
    {
        return Err(invalid("held thin member backing identity changed"));
    }
    Ok(())
}

fn create_member(path: &Path, virtual_bytes: u64) -> io::Result<Member> {
    if virtual_bytes < 4096
        || !virtual_bytes.is_multiple_of(2 << 20)
        || virtual_bytes > MAX_NOMINAL_MEMBER_BYTES
    {
        return Err(invalid(
            "member VHDX size exceeds the constructor profile (maximum64TiB)",
        ));
    }
    if path.exists() {
        return Err(invalid("fresh owned thin member required"));
    }
    let id = random_guid()?;
    let storage = VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    let mut parameters = CREATE_VIRTUAL_DISK_PARAMETERS::default();
    parameters.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    parameters.Anonymous = CREATE_VIRTUAL_DISK_PARAMETERS_0 {
        Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
            UniqueId: id,
            MaximumSize: virtual_bytes,
            BlockSizeInBytes: 2 << 20,
            SectorSizeInBytes: 512,
            PhysicalSectorSizeInBytes: 4096,
            ..Default::default()
        },
    };
    let name = wide(
        path.to_str()
            .ok_or_else(|| invalid("Unicode thin member path required"))?,
    )?;
    let mut handle = ptr::null_mut();
    // SAFETY: a fresh path, complete version2 parameters, no parent/source,
    // zero access/flags and a live output slot; no existing disk is accepted.
    win(unsafe {
        CreateVirtualDisk(
            &storage,
            name.as_ptr(),
            VIRTUAL_DISK_ACCESS_NONE,
            ptr::null_mut(),
            CREATE_VIRTUAL_DISK_FLAG_NONE,
            0,
            &parameters,
            ptr::null(),
            &mut handle,
        )
    })?;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(invalid("thin member provider returned no owner"));
    }
    let created = CreatedDisk {
        handle: VirtualHandle(handle),
        id,
        size: virtual_bytes,
        logical: 512,
        physical: 4096,
    };
    let backing = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let snapshot = file_snapshot(&backing)?;
    let attachment = created.attach()?;
    let member = Member {
        attachment,
        backing,
        snapshot,
        path: path.into(),
    };
    member.revalidate()?;
    let disk = native::device_file(
        &format!("\\\\.\\PhysicalDrive{}", member.attachment.number),
        false,
        false,
    )?;
    raw_disk(&disk, member.attachment.number, virtual_bytes)?;
    Ok(member)
}

impl Member {
    fn revalidate(&self) -> io::Result<()> {
        self.attachment.verify_provider()?;
        let mut path = [0u16; 256];
        let mut bytes = 512;
        // SAFETY: original live provider handle and fixed initialized output.
        win(unsafe {
            GetVirtualDiskPhysicalPath(
                self.attachment.created.handle.0,
                &mut bytes,
                path.as_mut_ptr(),
            )
        })?;
        let end = path
            .iter()
            .position(|n| *n == 0)
            .ok_or_else(|| invalid("thin member route is unterminated"))?;
        if !(2..=512).contains(&bytes)
            || !bytes.is_multiple_of(2)
            || String::from_utf16(&path[..end]).map_err(|_| invalid("thin route UTF16 differs"))?
                != format!("\\\\.\\PhysicalDrive{}", self.attachment.number)
        {
            return Err(invalid("thin member provider route changed"));
        }
        same_file(&self.snapshot, &self.backing)?;
        let current = file_snapshot(&self.backing)?;
        let admitted = self
            .attachment
            .created
            .size
            .checked_add(MEMBER_OVERHEAD)
            .ok_or_else(|| invalid("thin member file bound overflow"))?;
        if current.file_bytes > admitted || current.allocation_bytes > admitted {
            return Err(invalid("thin member backing exceeds the admitted profile"));
        }
        Ok(())
    }
}

fn native_disk(file: &File, number: u32, bytes: u64) -> io::Result<RawDiskObservation> {
    let device = control(file, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], 12)?;
    layout::validate_device(&device, number)?;
    let length = control(file, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)?;
    let mut input = [0u8; 12];
    input[..4].copy_from_slice(&6u32.to_le_bytes());
    let alignment = control(file, IOCTL_STORAGE_QUERY_PROPERTY, &input, 28)?;
    let raw = control(file, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], MAX_LAYOUT)?;
    if length.len() != 8
        || layout::u64_at(&length, 0)? != bytes
        || alignment.len() != 28
        || layout::u32_at(&alignment, 0)? != 28
        || layout::u32_at(&alignment, 4)? != 28
        || layout::u32_at(&alignment, 16)? != 512
        || layout::u32_at(&alignment, 20)? != 4096
        || layout::u32_at(&alignment, 24)? != 0
    {
        return Err(invalid(
            "owned thin provider native identity or geometry differs",
        ));
    }
    Ok(RawDiskObservation {
        disk_number: number,
        disk_bytes: bytes,
        device,
        length,
        alignment,
        layout: raw,
    })
}

fn raw_disk(file: &File, number: u32, bytes: u64) -> io::Result<RawDiskObservation> {
    let observed = native_disk(file, number, bytes)?;
    let raw = &observed.layout;
    // A fresh never-initialized owned device can return the empty all-zero
    // 48-byte response before RAW style 2. Live Storage also requires RAW.
    if !((raw.len() == 48 && raw.iter().all(|b| *b == 0))
        || (raw.len() >= 48 && layout::u32_at(raw, 0)? == 2 && layout::u32_at(raw, 4)? == 0))
    {
        return Err(invalid(
            "new thin provider is not uninitialized RAW storage",
        ));
    }
    Ok(observed)
}

fn capacity(root: &Path, budget: Budget) -> io::Result<(u64, resource_native::AvailableResources)> {
    ordinary_root(root)?;
    let available = resource_native::observe_available_resources(root)?;
    let ram = budget
        .rust_ram_bytes
        .checked_add(budget.powershell_ram_bytes)
        .ok_or_else(|| invalid("thin RAM admission overflow"))?;
    let mut allocation = 0u64;
    for (index, item) in fs::read_dir(root)?.enumerate() {
        if index >= 32 {
            return Err(invalid("unexpected thin constructor file set"));
        }
        let path = item?.path();
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(path)?;
        allocation = allocation
            .checked_add(file_snapshot(&file)?.allocation_bytes)
            .ok_or_else(|| invalid("thin file allocation overflow"))?;
    }
    if budget.rust_ram_bytes < RUST_WORKSPACE
        || budget.powershell_ram_bytes == 0
        || ram > available.available_physical_bytes
        || allocation > budget.scratch_bytes
        || available.scratch_available_bytes < budget.minimum_free_bytes
        || budget.scratch_bytes - allocation
            > available.scratch_available_bytes - budget.minimum_free_bytes
    {
        return Err(invalid(
            "thin constructor cannot preserve admitted RAM, scratch and free reserve",
        ));
    }
    Ok((allocation, available))
}

fn save<T: Serialize>(path: &Path, value: &T) -> io::Result<File> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() as u64 > RESPONSE_BYTES {
        return Err(invalid("thin metadata exceeds admitted record bound"));
    }
    save_bytes(path, &bytes)
}

fn save_bytes(path: &Path, bytes: &[u8]) -> io::Result<File> {
    if bytes.len() as u64 > RESPONSE_BYTES {
        return Err(invalid("thin constructor metadata exceeds admitted bound"));
    }
    let mut writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(path)?;
    writer.write_all(bytes)?;
    writer.sync_all()?;
    let identity = file_snapshot(&writer)?;
    // This distinct read-only bridge permits our existing writer, but never
    // DELETE. Keep it through writer closure and the stricter read-only open;
    // there is no pathname replacement window. Do not assume DuplicateHandle
    // changes the original FILE_OBJECT's share-access accounting.
    let bridge = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(path)?;
    same_file(&identity, &bridge)?;
    drop(writer);
    let mut held = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    same_file(&identity, &held)?;
    drop(bridge);
    let before = file_snapshot(&held)?;
    if before.file_bytes != bytes.len() as u64
        || crate::sha256_native::hash_range(&mut held, 0, before.file_bytes)?
            != <[u8; 32]>::from(Sha256::digest(bytes))
        || file_snapshot(&held)? != before
    {
        return Err(invalid(
            "held thin constructor metadata changed before publication",
        ));
    }
    Ok(held)
}

fn run(root: &Path, mode: &str, request: &Request<'_>, budget: Budget) -> io::Result<Reply> {
    capacity(root, budget)?;
    let input_path = root.join(format!("{mode}-request.json"));
    let output_path = root.join(format!("{mode}-result.json"));
    let _input = save(&input_path, request)?;
    let mut system = [0u16; 32768];
    // SAFETY: initialized buffer and WCHAR count.
    let count = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count >= system.len() {
        return Err(invalid("system directory exceeds bound"));
    }
    let executable = PathBuf::from(
        String::from_utf16(&system[..count]).map_err(|_| invalid("system path UTF16 differs"))?,
    )
    .join("WindowsPowerShell\\v1.0\\powershell.exe");
    // The child RAM share is sampled/admitted, not a Job memory hard limit.
    // No shell command interpolation, profile, source device or output stream
    // capture is used. The script writes one explicitly bounded result file.
    let status = Command::new(executable)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(root.join("thin-constructor.ps1"))
        .arg("-Mode")
        .arg(mode)
        .arg("-InputPath")
        .arg(&input_path)
        .arg("-OutputPath")
        .arg(&output_path)
        .creation_flags(0x0800_0000)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    let mut output = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&output_path)?;
    let before = reference_file::observe_reference_file_handle_with_limit(&output, RESPONSE_BYTES)?;
    let reply: Reply =
        serde_json::from_reader((&mut output).take(RESPONSE_BYTES)).map_err(io::Error::other)?;
    if reference_file::observe_reference_file_handle_with_limit(&output, RESPONSE_BYTES)? != before
        || before.number_of_links != 1
        || reply.schema_version != 1
        || reply.kind != "new-owned-thin-native-observation"
        || reply.nonce != request.nonce
        || reply.subsystem != request.subsystem
        || reply.mode != mode
        || reply.child_ram_hard_limit_enforced
        || reply.sampled_child_working_set_bytes > budget.powershell_ram_bytes
        || !status.success()
        || !reply.success
    {
        return Err(io::Error::other(format!(
            "thin {mode} did not close successfully: {}; all assets preserved",
            reply
                .error
                .as_deref()
                .unwrap_or("native reply or child admission differs")
        )));
    }
    capacity(root, budget)?;
    if let Some(pool_capacity) = &reply.pool_capacity {
        pool_capacity.validate(budget.minimum_free_bytes)?;
    } else if mode != "members" {
        return Err(invalid("private thin pool capacity observation absent"));
    }
    Ok(reply)
}

impl ThinPool {
    pub fn observation(&self) -> &Observation {
        &self.observation
    }

    fn verify_live(&self) -> io::Result<()> {
        ordinary_root(&self.root)?;
        if let Some(carrier) = &self.carrier {
            carrier.observe(self.budget)?;
        }
        if file_storage::file_id_info(&self._root_handle)? != self.root_file_id
            || file_storage::final_path_guid(&self._root_handle)? != self.root_guid_path
        {
            return Err(invalid("held private thin root identity changed"));
        }
        same_file(&self.script_snapshot, &self._script)?;
        for member in &self._members {
            member.revalidate()?;
        }
        native_disk(&self._disk, self.pool.number, self.pool.bytes)?;
        capacity(&self.root, self.budget)?;
        Ok(())
    }

    fn observe_stage(
        &self,
        mode: &str,
        binding: Option<&GeneralDiskBinding>,
    ) -> io::Result<PoolCapacity> {
        self.verify_live()?;
        let request = Request {
            schema_version: 1,
            nonce: &self.nonce,
            subsystem: &self.subsystem,
            goal_bytes: self.goal,
            member_virtual_bytes: self._members[0].attachment.created.size,
            carrier_root: self.carrier.as_ref().map(|c| c.member_root_text()),
            member_numbers: [
                self._members[0].attachment.number,
                self._members[1].attachment.number,
            ],
            members: &self.routes,
            pool: Some(&self.pool),
            expected_partition: binding,
            powershell_ram_bytes: self.budget.powershell_ram_bytes,
            minimum_free_bytes: self.budget.minimum_free_bytes,
        };
        let result = run(&self.root, mode, &request, self.budget);
        let closing = self.verify_live();
        let reply = match (result, closing) {
            (Ok(reply), Ok(())) => reply,
            (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
            (Err(error), Err(closing)) => {
                return Err(io::Error::other(format!(
                    "{error}; private thin closing check also failed: {closing}"
                )));
            }
        };
        if reply.members != self.routes || reply.pool.as_ref() != Some(&self.pool) {
            return Err(invalid("live private pool or member identity changed"));
        }
        reply
            .pool_capacity
            .ok_or_else(|| invalid("live private pool headroom absent"))
    }
}

impl FreshDiskOwner for ThinPool {
    fn geometry(&self) -> FreshDiskGeometry {
        FreshDiskGeometry {
            number: self.pool.number,
            bytes: self.pool.bytes,
            logical: self.pool.logical_sector,
            physical: self.pool.physical_sector,
        }
    }
    fn verify_owned(&self) -> io::Result<()> {
        self.verify_live()
    }
}

/// Create only two new fixed-profile members, a new private pool and one RAW
/// Thin virtual disk. No existing members/pools, GPT, format or recovery path.
pub fn create_new(
    directory: &Path,
    subsystem_unique_id: &str,
    requested_bytes: u64,
    budget: Budget,
) -> io::Result<ThinPool> {
    create_configured(
        directory,
        subsystem_unique_id,
        requested_bytes,
        budget,
        None,
    )
}

fn desired_bounded_member_bytes(requested_bytes: u64) -> io::Result<u64> {
    let rounding = 4u64 << 30; // Conservative implementation granularity.
    let half = requested_bytes
        .checked_add(1)
        .map(|n| n / 2)
        .ok_or_else(|| invalid("nominal member size overflow"))?;
    half.checked_add(rounding - 1)
        .map(|n| n / rounding)
        .and_then(|n| n.checked_mul(rounding))
        .and_then(|n| n.checked_add(rounding))
        .ok_or_else(|| invalid("nominal member rounding overflow"))
}

/// Create a capacity-bounded carrier with the explicit thin-overcommit profile.
/// Each member is capped at64TiB; the native thin VD may address more than the
/// total nominal pool. This supplies no promise of equivalent file-data capacity
/// and is not the public conversion backend or persistent recovery factory.
pub fn create_bounded_with_carrier(
    directory: &Path,
    subsystem_unique_id: &str,
    requested_bytes: u64,
    budget: Budget,
) -> io::Result<ThinPool> {
    if requested_bytes == 0 || requested_bytes > i64::MAX as u64 {
        return Err(invalid(
            "thin logical request must fit the positive native signed byte range",
        ));
    }
    let member_bytes = desired_bounded_member_bytes(requested_bytes)?.min(MAX_NOMINAL_MEMBER_BYTES);
    bounded_carrier::dimensions(budget)?;
    create_configured(
        directory,
        subsystem_unique_id,
        requested_bytes,
        budget,
        Some(member_bytes),
    )
}

fn create_configured(
    directory: &Path,
    subsystem_unique_id: &str,
    requested_bytes: u64,
    budget: Budget,
    bounded_member_bytes: Option<u64>,
) -> io::Result<ThinPool> {
    text(subsystem_unique_id)?;
    let maximum = MEMBER_BYTES
        .checked_add(MEMBER_OVERHEAD)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(METADATA_BYTES))
        .ok_or_else(|| invalid("thin member capacity overflow"))?;
    if directory.exists()
        || requested_bytes == 0
        || requested_bytes > i64::MAX as u64
        || (bounded_member_bytes.is_none() && budget.scratch_bytes < maximum)
        || budget.minimum_free_bytes == 0
        || budget.rust_ram_bytes < RUST_WORKSPACE
    {
        return Err(invalid(
            "fresh directory and complete thin constructor admission required",
        ));
    }
    ordinary_root(
        directory
            .parent()
            .ok_or_else(|| invalid("thin directory parent absent"))?,
    )?;
    fs::create_dir(directory)?;
    ordinary_root(directory)?;
    let root_handle = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(directory)?;
    let root_file_id = file_storage::file_id_info(&root_handle)?;
    let root_guid_path = file_storage::final_path_guid(&root_handle)?;
    capacity(directory, budget)?;
    let nonce = guid_text(&random_guid()?);
    let script = save_bytes(&directory.join("thin-constructor.ps1"), SCRIPT.as_bytes())?;
    let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    let carrier = if bounded_member_bytes.is_some() {
        Some(bounded_carrier::BoundedCarrier::create(directory, budget)?)
    } else {
        None
    };
    let member_bytes = bounded_member_bytes.unwrap_or(MEMBER_BYTES);
    let member_path = |index| -> io::Result<PathBuf> {
        match &carrier {
            Some(carrier) => carrier.member_path(index, budget),
            None => Ok(directory.join(format!("member-{index}.vhdx"))),
        }
    };
    let first = create_member(&member_path(0)?, member_bytes)?;
    capacity(directory, budget)?;
    if let Some(carrier) = &carrier {
        carrier.observe(budget)?;
    }
    let second = create_member(&member_path(1)?, member_bytes)?;
    if let Some(carrier) = &carrier {
        carrier.observe(budget)?;
    }
    if first.attachment.number == second.attachment.number {
        return Err(invalid("new thin member routes overlap"));
    }
    let members = [first, second];
    let numbers = [members[0].attachment.number, members[1].attachment.number];
    let request = Request {
        schema_version: 1,
        nonce: &nonce,
        subsystem: subsystem_unique_id,
        goal_bytes: requested_bytes,
        member_virtual_bytes: member_bytes,
        carrier_root: carrier.as_ref().map(|c| c.member_root_text()),
        member_numbers: numbers,
        members: &[],
        pool: None,
        expected_partition: None,
        powershell_ram_bytes: budget.powershell_ram_bytes,
        minimum_free_bytes: budget.minimum_free_bytes,
    };
    let discovered = run(directory, "members", &request, budget)?;
    if discovered.pool.is_some()
        || discovered.members.len() != 2
        || discovered
            .members
            .iter()
            .zip(numbers)
            .any(|(route, number)| route.number != number)
        || discovered.members[0].unique_id == discovered.members[1].unique_id
    {
        return Err(invalid("thin member native identity association differs"));
    }
    for route in &discovered.members {
        text(&route.unique_id)?;
        text(&route.object_id)?;
    }
    for member in &members {
        member.revalidate()?;
    }
    let request = Request {
        members: &discovered.members,
        ..request
    };
    let created = run(directory, "create", &request, budget)?;
    if created.members != discovered.members {
        return Err(invalid("new thin pool member set changed"));
    }
    for member in &members {
        member.revalidate()?;
    }
    let pool = created
        .pool
        .ok_or_else(|| invalid("created thin native pool observation absent"))?;
    let rounded = requested_bytes
        .checked_add(
            pool.divisor
                .checked_sub(1)
                .ok_or_else(|| invalid("native size divisor is zero"))?,
        )
        .map(|n| n / pool.divisor)
        .and_then(|n| n.checked_mul(pool.divisor))
        .ok_or_else(|| invalid("thin aligned size overflow"))?;
    for id in [
        &pool.unique_id,
        &pool.object_id,
        &pool.virtual_unique_id,
        &pool.virtual_object_id,
        &pool.disk_unique_id,
    ] {
        text(id)?;
    }
    if pool.bytes != rounded
        || pool.bytes > i64::MAX as u64
        || numbers.contains(&pool.number)
        || pool.logical_sector != 512
        || pool.physical_sector != 4096
        || native::current_windows_disk(&mut Vec::new())? == pool.number
    {
        return Err(invalid(
            "new thin pool native addressability or route differs",
        ));
    }
    let disk = native::device_file(&format!("\\\\.\\PhysicalDrive{}", pool.number), true, false)?;
    let observed = raw_disk(&disk, pool.number, pool.bytes)?;
    let request = Request {
        pool: Some(&pool),
        ..request
    };
    let closing = run(directory, "closing", &request, budget)?;
    if closing.members != discovered.members || closing.pool.as_ref() != Some(&pool) {
        return Err(invalid("new thin pool closing identity differs"));
    }
    for member in &members {
        member.revalidate()?;
    }
    if raw_disk(&disk, pool.number, pool.bytes)? != observed {
        return Err(invalid(
            "held thin RAW device changed across closing observation",
        ));
    }
    if file_storage::file_id_info(&root_handle)? != root_file_id
        || file_storage::final_path_guid(&root_handle)? != root_guid_path
    {
        return Err(invalid("held thin root identity changed"));
    }
    let (allocation, available) = capacity(directory, budget)?;
    privileges.restore()?;
    let nominal_total = member_bytes
        .checked_mul(2)
        .ok_or_else(|| invalid("nominal member total overflow"))?;
    let observation = Observation {
        schema_version: 1,
        kind: "constructor-owned-private-thin-raw-disk",
        backing_profile: if carrier.is_some() {
            BOUNDED_BACKING_PROFILE
        } else {
            FIXED_BACKING_PROFILE
        },
        nonce: nonce.clone(),
        requested_bytes,
        actual_bytes: pool.bytes,
        native_size_divisor: pool.divisor,
        pool_unique_id: pool.unique_id.clone(),
        virtual_disk_unique_id: pool.virtual_unique_id.clone(),
        member_backing_paths: [members[0].path.clone(), members[1].path.clone()],
        member_virtual_disk_ids: [
            guid_text(&members[0].attachment.created.id),
            guid_text(&members[1].attachment.created.id),
        ],
        member_virtual_bytes_each: member_bytes,
        nominal_member_virtual_bytes_total: nominal_total,
        nominal_member_size_was_clamped: bounded_member_bytes.is_some()
            && member_bytes < desired_bounded_member_bytes(requested_bytes)?,
        logical_bytes_exceed_nominal_members: pool.bytes > nominal_total,
        provider_pool_capacity_scope: POOL_CAPACITY_SCOPE,
        bounded_carrier: carrier.as_ref().map(|c| c.observe(budget)).transpose()?,
        host_allocation_excludes_nested_member_files: carrier.is_some(),
        native_disk: observed,
        retained_regular_file_allocation_bytes: allocation,
        allocation_sample_precedes_this_observation_receipt: true,
        sampled_available_resources: available,
        sampled_child_working_set_bytes: closing.sampled_child_working_set_bytes,
        budget,
        sampled_capacity_is_not_a_kernel_quota_or_reservation: true,
        child_ram_hard_limit_enforced: false,
        source_binding_supplied: false,
        virtual_disk_gpt_created: false,
        refs_formatted: false,
        persistent_reattachment_qualified: false,
        conversion_authorized: false,
        automatic_cleanup_or_fallback: false,
    };
    let _receipt = save(&directory.join("thin-owner-observation.json"), &observation)?;
    let script_snapshot = file_snapshot(&script)?;
    Ok(ThinPool {
        _members: members,
        _root_handle: root_handle,
        _script: script,
        _disk: disk,
        root: directory.into(),
        root_file_id,
        root_guid_path,
        subsystem: subsystem_unique_id.into(),
        nonce,
        goal: requested_bytes,
        budget,
        routes: discovered.members,
        pool,
        script_snapshot,
        observation,
        carrier,
    })
}

// Source controlled interop only. It receives live constructor-derived member
// routes, never a saved receipt as permission to touch an existing device.
const SCRIPT: &str = r#"
param([ValidateSet('members','create','closing','format-opening','partitioned','formatted','format-error')][string]$Mode,[string]$InputPath,[string]$OutputPath)
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
function BoundText([string]$s){Need ($s.Length-gt0-and$s.Length-le4096-and$s-cnotmatch'[\x00-\x1f]') 'Bounded native identity required'}
$request=$null;$members=@();$poolRow=$null;$poolCapacity=$null;$failure=$null;$success=$false;$reader=$null
try{
 $f=[IO.File]::Open($InputPath,'Open','Read','Read');try{Need ($f.Length-gt0-and$f.Length-le131072) 'Bounded input required';$reader=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true));$request=$reader.ReadToEnd()|ConvertFrom-Json}finally{if($null-ne$reader){$reader.Dispose()}else{$f.Dispose()}}
 Need ($request.schema_version-eq1-and$request.member_numbers.Count-eq2-and$request.member_numbers[0]-ne$request.member_numbers[1]-and$request.goal_bytes-gt0) 'Exact new-member input required'
 BoundText $request.subsystem;Need ($request.nonce-cmatch'\A[0-9a-f-]{36}\z') 'Constructor nonce required'
 function Sample{Need ((Get-Process -Id $PID).WorkingSet64-le$request.powershell_ram_bytes) 'Sampled child RAM share exceeded';Need ((Get-Volume -FilePath $InputPath).SizeRemaining-ge$request.minimum_free_bytes) 'Backing volume free reserve breached';if($null-ne$request.carrier_root){$carrierVolume=Get-Volume -FilePath $request.carrier_root;Need ($carrierVolume.FileSystem-ceq'NTFS'-and$carrierVolume.SizeRemaining-ge$request.minimum_free_bytes) 'Actual carrier NTFS free reserve breached'}}
 Sample
 $sub=@(Get-StorageSubSystem -UniqueId $request.subsystem);Need ($sub.Count-eq1-and$sub[0].UniqueId-ceq$request.subsystem-and$sub[0].FriendlyName-like'Windows Storage*') 'One exact Windows Storage subsystem required'
 $physical=@();$n=0
 foreach($number in $request.member_numbers){
  if($Mode-cnotin@('members','create')){
   # Pool claims can hide MSFT_Disk. Keep the original provider number as a
   # route binding checked by Rust, and query this exact live member identity.
   Need ($request.members.Count-eq2-and$request.members[$n].number-eq$number) 'Original live member route differs'
   BoundText ([string]$request.members[$n].unique_id);BoundText ([string]$request.members[$n].object_id)
   $p=@(Get-PhysicalDisk -UniqueId $request.members[$n].unique_id)
   Need ($p.Count-eq1-and$p[0].UniqueId-ceq$request.members[$n].unique_id-and$p[0].ObjectId-ceq$request.members[$n].object_id) 'Exact claimed member CIM identity absent'
  }else{
   $d=Get-Disk -Number $number
   Need ($d.Number-eq$number-and-not$d.IsBoot-and-not$d.IsSystem-and$d.Size-eq$request.member_virtual_bytes-and$d.LogicalSectorSize-eq512-and$d.PhysicalSectorSize-eq4096-and$d.UniqueId) 'New member geometry differs'
   $p=@(Get-PhysicalDisk -UniqueId $d.UniqueId);Need ($p.Count-eq1-and$p[0].UniqueId-ceq$d.UniqueId) 'Exact member CIM association absent'
   Need ($d.PartitionStyle.ToString()-ceq'RAW'-and-not$d.IsOffline-and-not$d.IsReadOnly-and$p[0].CanPool) 'Fresh RAW poolable member required'
  }
  Need ($p[0].Size-eq$request.member_virtual_bytes-and$p[0].LogicalSectorSize-eq512-and$p[0].PhysicalSectorSize-eq4096) 'Exact member physical geometry differs'
  $row=@{number=[uint32]$number;unique_id=[string]$p[0].UniqueId;object_id=[string]$p[0].ObjectId}
  if($Mode-cne'members'){Need ($request.members.Count-eq2-and$request.members[$n].number-eq$number-and$request.members[$n].unique_id-ceq$row.unique_id-and$request.members[$n].object_id-ceq$row.object_id) 'Live member identity changed'}
  $members+=,$row;$physical+=,$p[0];$n++
 }
 Need ($members[0].unique_id-cne$members[1].unique_id) 'Distinct member identities required'
 $poolName='n2r-private-pool-'+$request.nonce;$diskName='n2r-private-thin-'+$request.nonce
 if($Mode-ceq'create'){
  Need ($null-eq$request.pool-and@(Get-StoragePool -FriendlyName $poolName -ErrorAction SilentlyContinue).Count-eq0-and@(Get-VirtualDisk -FriendlyName $diskName -ErrorAction SilentlyContinue).Count-eq0) 'Fresh pool and virtual names required'
  $eligible=@(Get-PhysicalDisk -StorageSubsystem $sub[0]);Need ($eligible.Count-le4096) 'Subsystem metadata domain exceeds constructor admission'
  foreach($p in $physical){Need (@($eligible|Where-Object{$_.UniqueId-ceq$p.UniqueId-and$_.ObjectId-ceq$p.ObjectId}).Count-eq1) 'New member outside exact subsystem'}
  $before=@(Get-Disk|Where-Object{$_.Number-notin$request.member_numbers});Need ($before.Count-le4096) 'Disk metadata domain exceeds constructor admission'
  Sample
  $made=@(New-StoragePool -StorageSubSystemUniqueId $request.subsystem -FriendlyName $poolName -PhysicalDisks $physical -ProvisioningTypeDefault Thin -ResiliencySettingNameDefault Simple -LogicalSectorSizeDefault 512 -WriteCacheSizeDefault 0)
  Need ($made.Count-eq1-and-not$made[0].IsPrimordial-and$made[0].FriendlyName-ceq$poolName) 'One new private pool required';$pool=$made[0]
  BoundText ([string]$pool.UniqueId);BoundText ([string]$pool.ObjectId)
  $membership=@(Get-PhysicalDisk -StoragePool $pool);Need ($membership.Count-eq2-and@($membership.UniqueId|Sort-Object -Unique).Count-eq2) 'New pool membership is not exact'
  foreach($p in $physical){Need (@($membership|Where-Object{$_.UniqueId-ceq$p.UniqueId-and$_.ObjectId-ceq$p.ObjectId}).Count-eq1) 'New pool contains foreign or missing members'}
  Need (@($pool.SupportedProvisioningTypes|ForEach-Object{$_.ToString()})-ccontains'Thin') 'Thin provisioning absent from actual native pool'
  $range=@(Get-VirtualDiskSupportedSize -InputObject $pool -ResiliencySettingName Simple);Need ($range.Count-eq1) 'One native size range required'
  [decimal]$divisor=$range[0].VirtualDiskSizeDivisor;[decimal]$goal=$request.goal_bytes
  Need ($divisor-gt0-and$divisor-le[long]::MaxValue-and$goal-le[long]::MaxValue-$divisor+1) 'Size rounding overflow'
  [decimal]$aligned=[decimal]::Truncate(($goal+$divisor-1)/$divisor)*$divisor
  Need ($aligned-ge$goal-and$aligned-le[long]::MaxValue-and$aligned-ge[decimal]$range[0].VirtualDiskSizeMin) 'Aligned native request differs'
  Need (@(Get-VirtualDisk -StoragePool $pool).Count-eq0) 'Fresh pool has unexpected virtual disks'
  Sample
  $made=@(New-VirtualDisk -StoragePoolUniqueId $pool.UniqueId -FriendlyName $diskName -Size ([uint64]$aligned) -ProvisioningType Thin -ResiliencySettingName Simple -NumberOfColumns 1 -WriteCacheSize 0)
  Need ($made.Count-eq1) 'One newly created thin virtual disk required';$virtual=$made[0]
  foreach($old in $before){$now=Get-Disk -Number $old.Number;Need ($now.UniqueId-ceq$old.UniqueId-and$now.Size-eq$old.Size-and$now.PartitionStyle.ToString()-ceq$old.PartitionStyle.ToString()-and$now.IsOffline-eq$old.IsOffline-and$now.IsReadOnly-eq$old.IsReadOnly-and$now.IsBoot-eq$old.IsBoot-and$now.IsSystem-eq$old.IsSystem) 'Existing disk configuration changed'}
 }elseif($Mode-cne'members'){
  Need ($null-ne$request.pool) 'Existing live pool route required'
  $made=@(Get-StoragePool -UniqueId $request.pool.unique_id);Need ($made.Count-eq1) 'Exact newly created pool absent';$pool=$made[0]
  $made=@(Get-VirtualDisk -UniqueId $request.pool.virtual_unique_id);Need ($made.Count-eq1) 'Exact newly created thin disk absent';$virtual=$made[0]
  [uint64]$divisor=$request.pool.divisor
 } 
 if($Mode-cne'members'){
  Need (-not$pool.IsPrimordial-and-not$pool.IsReadOnly-and$pool.HealthStatus.ToString()-ceq'Healthy'-and$virtual.HealthStatus.ToString()-ceq'Healthy'-and$pool.FriendlyName-ceq$poolName-and$virtual.FriendlyName-ceq$diskName-and$virtual.ProvisioningType.ToString()-ceq'Thin'-and$virtual.ResiliencySettingName-ceq'Simple'-and$virtual.NumberOfColumns-eq1-and$virtual.WriteCacheSize-eq0) 'Actual private thin profile differs'
  $membership=@(Get-PhysicalDisk -StoragePool $pool);Need ($membership.Count-eq2-and@($membership.UniqueId|Sort-Object -Unique).Count-eq2) 'Exact two-member private pool required'
  foreach($p in $physical){Need (@($membership|Where-Object{$_.UniqueId-ceq$p.UniqueId-and$_.ObjectId-ceq$p.ObjectId}).Count-eq1) 'Foreign or missing private pool member'}
  $v=@(Get-VirtualDisk -StoragePool $pool);Need ($v.Count-eq1-and$v[0].UniqueId-ceq$virtual.UniqueId-and$v[0].ObjectId-ceq$virtual.ObjectId) 'Private pool virtual membership differs'
  $d=@(Get-Disk -VirtualDisk $virtual);Need ($d.Count-eq1-and$d[0].Number-notin$request.member_numbers-and-not$d[0].IsBoot-and-not$d[0].IsSystem-and-not$d[0].IsOffline-and-not$d[0].IsReadOnly-and$d[0].Size-eq$virtual.Size-and$d[0].Size-ge$request.goal_bytes-and$d[0].LogicalSectorSize-eq512-and$d[0].PhysicalSectorSize-eq4096) 'One exact owned thin device required'
  $style=$d[0].PartitionStyle.ToString()
  if($Mode-cin@('partitioned','formatted')){Need ($null-ne$request.expected_partition-and$style-ceq'GPT') 'Owned GPT partition observation required'}
  elseif($Mode-ceq'format-error'){Need ($style-cin@('RAW','GPT')) 'Unknown failed-format disk layout'}
  else{Need ($style-ceq'RAW') 'Fresh RAW thin disk required'}
  if($null-ne$request.expected_partition){
   $binding=$request.expected_partition;$identity=$binding.identity
   Need ($style-ceq'GPT'-and$binding.disk_number-eq$d[0].Number-and[guid]$d[0].Guid-eq[guid]$identity.disk_guid-and$d[0].Size-eq$identity.disk_bytes) 'Live owned GPT disk binding differs'
   $partition=@(Get-Partition -DiskNumber $d[0].Number -PartitionNumber $identity.partition_number)
   Need ($partition.Count-eq1-and[guid]$partition[0].Guid-eq[guid]$identity.partition_guid-and$partition[0].Offset-eq$identity.partition_offset-and$partition[0].Size-eq$identity.partition_bytes) 'Live owned GPT partition binding differs'
   if($Mode-ceq'formatted'){$volume=@(Get-Volume -Partition $partition[0]);Need ($volume.Count-eq1-and$volume[0].FileSystem-ceq'ReFS'-and$volume[0].AllocationUnitSize-eq4096-and$volume[0].FileSystemLabel-ceq'n2r-retained-shadow') 'Actual owned formatted ReFS profile differs'}
  }
  if($Mode-ceq'create'){Need ($d[0].Number-notin$before.Number) 'New thin route aliases a previous disk'}
  $poolRow=@{unique_id=[string]$pool.UniqueId;object_id=[string]$pool.ObjectId;virtual_unique_id=[string]$virtual.UniqueId;virtual_object_id=[string]$virtual.ObjectId;number=[uint32]$d[0].Number;disk_unique_id=[string]$d[0].UniqueId;bytes=[uint64]$virtual.Size;divisor=[uint64]$divisor;logical_sector=[uint32]$d[0].LogicalSectorSize;physical_sector=[uint32]$d[0].PhysicalSectorSize}
  [uint64]$poolSize=$pool.Size;[uint64]$allocated=$pool.AllocatedSize
  Need ($poolSize-ge$allocated-and$poolSize-ge[uint64]$virtual.FootprintOnPool) 'Actual pool capacity fields disagree'
  $poolCapacity=@{size_bytes=$poolSize;allocated_bytes=$allocated;free_bytes=$poolSize-$allocated;virtual_footprint_bytes=[uint64]$virtual.FootprintOnPool}
  Need ($poolCapacity.free_bytes-ge$request.minimum_free_bytes) 'Private pool free reserve breached'
 }
 Sample;$success=$true
}catch{$failure=$_.Exception.Message;if($failure.Length-gt2048){$failure=$failure.Substring(0,2048)}}
$working=[uint64](Get-Process -Id $PID).WorkingSet64
$result=@{schema_version=1;kind='new-owned-thin-native-observation';success=$success;mode=$Mode;nonce=if($null-eq$request){''}else{[string]$request.nonce};subsystem=if($null-eq$request){''}else{[string]$request.subsystem};members=@($members);pool=$poolRow;pool_capacity=$poolCapacity;sampled_child_working_set_bytes=$working;child_ram_hard_limit_enforced=$false;error=$failure}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8 -Compress));Need ($bytes.Length-le131072) 'Native result exceeds admitted metadata bound'
$file=[IO.File]::Open($OutputPath,'CreateNew','Write','Read');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
if(-not$success){exit 1}
"#;
