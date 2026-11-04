//! Target-only staged protection. No disk setter, payload writer, JSON issuer
//! or automatic Drop restoration. All transitions retain the original File.
use super::super::partition_dump_locations::{
    ConfiguredDumpObservation, observe_configured_dump_locations,
};
use super::super::partition_isolation::{
    PartitionIsolationObservation, PartitionObservationBudget, PartitionScopedReader,
    PartitionSourceBinding,
};
use super::super::partition_owner::{PartitionOwnerToken, PartitionScopedOwner};
use super::super::partition_runtime_roles::{
    RuntimeVolumeRoleObservation, observe_runtime_volume_roles,
};
use super::super::{AlignedBuffer, MAX_IO, NativeEvent, control, device_file};
use crate::attestation_partition::PartitionPagedNtfsObservation;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    sync::Arc,
    rc::Rc,
    cell::RefCell,
};

const BASIC: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
const PRIVATE: &str = "b627aadb-a893-48b6-aa0b-71e5f30ee370";
const READONLY: u64 = 0x1000_0000_0000_0000;
const GET_PARTITION: u32 = 0x0007_0048;
const SET_PARTITION: u32 = 0x0007_c04c;
const IS_WRITABLE: u32 = 0x0007_0024;
const MAX_RECORD: usize = 4 * 1024 * 1024;
const MAX_INTENT: u64 = 16 * 1024 * 1024;
const _: () = assert!(
    std::mem::size_of::<windows_sys::Win32::System::Ioctl::SET_PARTITION_INFORMATION_EX>() == 120
        && std::mem::offset_of!(
            windows_sys::Win32::System::Ioctl::SET_PARTITION_INFORMATION_EX,
            Anonymous
        ) == 8
        && std::mem::size_of::<windows_sys::Win32::System::Ioctl::PARTITION_INFORMATION_GPT>()
            == 112
        && windows_sys::Win32::System::Ioctl::IOCTL_DISK_SET_PARTITION_INFO_EX == SET_PARTITION
);
fn invalid(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}
fn require(ok: bool, m: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(m)) }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn read_at(file: &mut File, at: u64, n: usize) -> io::Result<Vec<u8>> {
    require(
        n <= 65536,
        "lifecycle metadata read exceeds its fixed bound",
    )?;
    require(
        file.seek(SeekFrom::Start(at))? == at,
        "lifecycle metadata seek differs",
    )?;
    let mut bytes = vec![0; n];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn crc(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for byte in bytes {
        c ^= u32::from(*byte);
        for _ in 0..8 {
            c = (c >> 1) ^ (0xedb8_8320u32 & 0u32.wrapping_sub(c & 1));
        }
    }
    !c
}
fn expected_header(old: &[u8], entries: &[u8]) -> io::Result<Vec<u8>> {
    let mut value = old.to_vec();
    let n = crate::layout::u32_at(old, 12)? as usize;
    require((92..=value.len()).contains(&n), "GPT header length differs")?;
    value[88..92].copy_from_slice(&crc(entries).to_le_bytes());
    value[16..20].fill(0);
    let checksum = crc(&value[..n]);
    value[16..20].copy_from_slice(&checksum.to_le_bytes());
    Ok(value)
}

#[derive(Debug)]
struct PreparationIdentity;
#[derive(Clone, Debug)]
pub struct PartitionPreparationToken(Arc<PreparationIdentity>);
impl PartitionPreparationToken {
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PartitionPreparationStage {
    BasicLocked,
    BasicReadonly,
    NativeReadonlyCaptured,
    PrivateLocked,
    Cancelled,
    Poisoned,
}
#[derive(Clone, Debug, Serialize)]
pub struct PartitionIntentReceipt {
    pub version: u32,
    pub sequence: u64,
    pub intent_bytes: u64,
    pub intent_prefix_sha256: String,
    pub intent_file: crate::reference_file::ReferenceFileSnapshot,
    pub from: PartitionPreparationStage,
    pub desired_type: [u8; 16],
    pub desired_attributes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionPreparationPin {
    pub version: u32,
    pub kind: &'static str,
    pub binding: PartitionSourceBinding,
    pub original_partition_info: Vec<u8>,
    pub original_gpt_sha256: String,
    pub original_mbr_sha256: String,
    pub ntfs_primary_sha256: String,
    pub intent_file: crate::reference_file::ReferenceFileSnapshot,
    pub intent_prefix_sha256: String,
    pub sequence: u64,
    pub observed_stage: PartitionPreparationStage,
    pub serialized_pin_grants_authority: bool,
}
/// The callback sees a real synced/read-back intent before the setter. It
/// grants no permission. Batches must be durably drained at explicit boundaries.
pub trait PartitionPreparationObserver {
    fn checkpoint(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> io::Result<()>;
    fn durable_intent(&mut self, receipt: &PartitionIntentReceipt) -> io::Result<()>;
}
/// Clone of the actual live guard's observer only. It carries no source or
/// writer authority; metadata witnesses share this durable event destination.
#[derive(Clone)]
pub(in crate::native) struct PartitionNativeEventSink {
    observer: Rc<RefCell<Box<dyn PartitionPreparationObserver>>>,
}
impl PartitionNativeEventSink {
    fn new(observer:Box<dyn PartitionPreparationObserver>)->Self {
        Self{observer:Rc::new(RefCell::new(observer))}
    }
    pub(in crate::native) fn checkpoint(&self,phase:&'static str,events:&mut Vec<NativeEvent>)->io::Result<()> {
        let mut observer=self.observer.try_borrow_mut().map_err(|_|invalid("native event sink is already borrowed"))?;
        observer.checkpoint(phase,events)?;
        require(events.is_empty(),"actual durable native event checkpoint did not drain")
    }
    fn durable_intent(&self,receipt:&PartitionIntentReceipt)->io::Result<()> {
        self.observer.try_borrow_mut().map_err(|_|invalid("intent event sink is already borrowed"))?
            .durable_intent(receipt)
    }
}
struct IntentFile {
    file: File,
    identity: crate::reference_file::ReferenceFileSnapshot,
    end: u64,
    sequence: u64,
    max_allocation: u64,
    latest_receipt: Option<PartitionIntentReceipt>,
}
struct BoundedBytes {
    bytes: Vec<u8>,
}
impl Write for BoundedBytes {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        require(
            self.bytes
                .len()
                .checked_add(b.len())
                .is_some_and(|n| n <= MAX_RECORD),
            "lifecycle intent record exceeds4MiB",
        )?;
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Serialize)]
struct Intent<'a> {
    version: u32,
    kind: &'static str,
    sequence: u64,
    stage: PartitionPreparationStage,
    binding: &'a PartitionSourceBinding,
    original_partition_info: &'a [u8],
    current_partition_info: &'a [u8],
    desired_partition_info: &'a [u8],
    original_gpt: &'a super::super::partition_isolation::PartitionGptObservation,
    original_mbr: &'a [u8],
    ntfs_primary_sha256: String,
    source_AP_issued: bool,
    process_death_recovery_authority: bool,
}
impl IntentFile {
    fn new(
        file: File,
        baseline: &PartitionIsolationObservation,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        let identity =
            crate::reference_file::observe_reference_file_handle_with_limit(&file, MAX_INTENT)?;
        require(
            identity.file_bytes == 0
                && identity.allocation_bytes == 0
                && identity.number_of_links == 1,
            "fresh ordinary unallocated external intent file required",
        )?;
        let max_allocation = MAX_INTENT
            .checked_add(crate::file_storage::artifact_allocation_slack(&file)?)
            .ok_or_else(|| invalid("intent allocation ceiling overflow"))?;
        // A compatible contender must fail specifically for sharing. A new
        // share-none open would prove nothing about this held handle's rights.
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(&identity.final_path)
        {
            Err(error) if error.raw_os_error() == Some(32) => (),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("intent exclusive-writer proof is unknown: {error}"),
                ));
            }
            Ok(contender) => {
                drop(contender);
                return Err(invalid(
                    "held intent file permits a second ordinary RW writer",
                ));
            }
        }
        require(
            crate::reference_file::observe_reference_file_handle_with_limit(&file, MAX_INTENT)?
                == identity,
            "held intent identity/metadata changed across sharing proof",
        )?;
        let end = identity
            .final_path
            .find("}\\")
            .ok_or_else(|| invalid("intent has no actual GUID volume route"))?
            + 1;
        let volume = device_file(&identity.final_path[..end], false, false)?;
        let ext = control(
            &volume,
            "partition-preparation-intent-C-extents",
            super::super::VOLUME_EXTENTS,
            &[],
            32,
            events,
        )?;
        let c = &baseline.windows_volume;
        require(
            ext.len() == 32
                && crate::layout::u32_at(&ext, 0)? == 1
                && crate::layout::u32_at(&ext, 8)? == c.disk_number
                && crate::layout::u64_at(&ext, 16)? == c.offset
                && crate::layout::u64_at(&ext, 24)? == c.length,
            "intent file is not on the actual running Windows C extent",
        )?;
        Ok(Self {
            file,
            identity,
            end: 0,
            sequence: 0,
            max_allocation,
            latest_receipt: None,
        })
    }
    fn persist(
        &mut self,
        record: &Intent<'_>,
        from: PartitionPreparationStage,
        desired: &[u8],
    ) -> io::Result<PartitionIntentReceipt> {
        let before = crate::reference_file::observe_reference_file_handle_with_limit(
            &self.file, MAX_INTENT,
        )?;
        require(
            before.volume_serial_number == self.identity.volume_serial_number
                && before.file_id_128 == self.identity.file_id_128
                && before.final_path == self.identity.final_path
                && before.file_bytes == self.end
                && before.number_of_links == 1
                && before.allocation_bytes <= self.max_allocation,
            "same held intent identity/EOF changed",
        )?;
        let mut bytes = BoundedBytes { bytes: Vec::new() };
        bytes
            .bytes
            .try_reserve_exact(MAX_RECORD)
            .map_err(io::Error::other)?;
        serde_json::to_writer(&mut bytes, record).map_err(io::Error::other)?;
        let next = self
            .end
            .checked_add(8 + 32 + bytes.bytes.len() as u64)
            .ok_or_else(|| invalid("intent length overflow"))?;
        require(
            next <= MAX_INTENT && self.sequence < 4,
            "lifecycle intent sequence exceeds fixed bound",
        )?;
        require(
            self.file.seek(SeekFrom::Start(self.end))? == self.end,
            "intent append seek differs",
        )?;
        self.file
            .write_all(&(bytes.bytes.len() as u64).to_le_bytes())?;
        self.file.write_all(&hash(&bytes.bytes))?;
        self.file.write_all(&bytes.bytes)?;
        self.file.sync_all()?;
        require(
            self.file.seek(SeekFrom::Start(self.end))? == self.end,
            "intent readback seek differs",
        )?;
        let mut length = [0u8; 8];
        let mut digest = [0u8; 32];
        self.file.read_exact(&mut length)?;
        self.file.read_exact(&mut digest)?;
        require(
            u64::from_le_bytes(length) == bytes.bytes.len() as u64 && digest == hash(&bytes.bytes),
            "new intent length/hash readback differs",
        )?;
        // Reuse one fixed64KiB workspace while preserving expected serialized
        // bytes for byte-for-byte same-file readback, before any GPT mutation.
        let mut readback = [0u8; 65536];
        for expected in bytes.bytes.chunks(readback.len()) {
            self.file.read_exact(&mut readback[..expected.len()])?;
            require(
                &readback[..expected.len()] == expected,
                "new intent body readback differs",
            )?;
        }
        // Prefix hashing reuses the admitted4MiB record workspace after exact
        // comparison has completed, rather than keeping a second4MiB buffer.
        drop(bytes);
        let prefix = crate::sha256_native::hash_range(&mut self.file, 0, next)?;
        self.end = next;
        self.sequence += 1;
        let snapshot = crate::reference_file::observe_reference_file_handle_with_limit(
            &self.file, MAX_INTENT,
        )?;
        require(
            snapshot.file_bytes == next
                && snapshot.allocation_bytes <= self.max_allocation
                && snapshot.file_id_128 == self.identity.file_id_128
                && snapshot.volume_serial_number == self.identity.volume_serial_number
                && snapshot.final_path == self.identity.final_path,
            "durable intent same-file readback differs",
        )?;
        let receipt = PartitionIntentReceipt {
            version: 1,
            sequence: self.sequence,
            intent_bytes: next,
            intent_prefix_sha256: hex::encode(prefix),
            intent_file: snapshot,
            from,
            desired_type: desired[32..48].try_into().map_err(io::Error::other)?,
            desired_attributes: crate::layout::u64_at(desired, 64)?,
        };
        self.latest_receipt = Some(receipt.clone());
        Ok(receipt)
    }
}

/// Owns real target/intent handles. There is no Deserialize/path-state issuer.
/// Failure leaves the last BasicRO/private state; Drop only closes handles.
pub struct PartitionPreparationGuard {
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    token: PartitionPreparationToken,
    volume: Option<File>,
    physical: Option<File>,
    baseline: PartitionIsolationObservation,
    original_info: Vec<u8>,
    current_info: Vec<u8>,
    mbr: Vec<u8>,
    primary: [u8; 32],
    stage: PartitionPreparationStage,
    locked: bool,
    protection: Option<PartitionReadonlyProtection>,
    native: Option<PartitionPagedNtfsObservation>,
    dumps: ConfiguredDumpObservation,
    roles: RuntimeVolumeRoleObservation,
    vss: crate::vss_observation::Observation,
    mounted_ntfs: crate::txf_native::PartitionMountedTxfObservation,
    source_label: crate::volume_label::VolumeLabel,
    mount_paths: super::super::MountPathObservation,
    intent: IntentFile,
    observer: PartitionNativeEventSink,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionReadonlyProtection {
    pub original_partition_info: Vec<u8>,
    pub readonly_partition_info: Vec<u8>,
    pub volume_extents: Vec<u8>,
    pub ntfs_volume_data: Vec<u8>,
    pub physical_disk_attributes: u64,
    pub partition_write_protect_error: i32,
}
pub struct PartitionReadonlyPhase<'a> {
    guard: &'a mut PartitionPreparationGuard,
}
impl<'guard> PartitionReadonlyPhase<'guard> {
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.guard.binding
    }
    pub(crate) fn preparation_token(&self) -> PartitionPreparationToken {
        self.guard.token.clone()
    }
    pub(crate) fn protection(&self) -> &PartitionReadonlyProtection {
        self.guard
            .protection
            .as_ref()
            .expect("phase constructor requires actual protection")
    }
    pub(crate) fn require_original_vss_catalog_clear(&self) -> io::Result<()> {
        self.guard.vss.require_observed_catalog_clear()
    }
    pub fn mounted_ntfs_before_freeze(&self) -> &crate::txf_native::PartitionMountedTxfObservation {
        &self.guard.mounted_ntfs
    }
    pub fn original_label(&self) -> &crate::volume_label::VolumeLabel {
        &self.guard.source_label
    }
    pub fn original_mount_paths(&self) -> &super::super::MountPathObservation {
        &self.guard.mount_paths
    }
    pub fn capture_mount_paths(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::super::MountPathObservation> {
        self.revalidate(events)?;
        super::super::capture_mount_paths_for_bound_volume(self.guard.binding.storage.clone())
    }
    pub fn read_source<'phase>(
        &'phase mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionReadonlyReader<'phase, 'guard>> {
        let file = self.open_readonly_volume(events)?;
        let reply = control(&file, "partition-readonly-source-extended-dasd",
            0x0009_0083, &[], 0, events)?;
        require(reply.is_empty(), "readonly extended DASD returned unexpected data")?;
        Ok(PartitionReadonlyReader {
            phase: self,
            file,
            buffer: AlignedBuffer::new()?,
            position: 0,
            poisoned: false,
        })
    }
    pub fn revalidate(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.guard.observe_readonly(events)
    }
    pub(crate) fn open_readonly_volume(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<File> {
        self.revalidate(events)?;
        let file = device_file(&self.guard.binding.storage.volume_path()?, false, false)?;
        self.guard.check_volume(&file, events)?;
        Ok(file)
    }
}
pub struct PartitionReadonlyReader<'phase, 'guard> {
    phase: &'phase mut PartitionReadonlyPhase<'guard>,
    file: File,
    buffer: AlignedBuffer,
    position: u64,
    poisoned: bool,
}
impl PartitionReadonlyReader<'_, '_> {
    pub fn byte_len(&self) -> u64 {
        self.phase.binding().storage.identity.partition_bytes
    }
    pub const fn read_buffer_memory_bytes() -> u64 {
        MAX_IO as u64
    }
}
impl Seek for PartitionReadonlyReader<'_, '_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.byte_len()) + i128::from(n),
        };
        if self.poisoned || next < 0 || next > i128::from(self.byte_len()) {
            self.poisoned = true;
            return Err(invalid("readonly phase seek outside target"));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}
impl Read for PartitionReadonlyReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let result = (|| {
            require(!self.poisoned, "readonly phase reader poisoned")?;
            if out.is_empty() || self.position == self.byte_len() {
                return Ok(0);
            }
            let lead = (self.position % 4096) as usize;
            let count =
                (out.len().min(MAX_IO - lead) as u64).min(self.byte_len() - self.position) as usize;
            let transfer = (lead + count).div_ceil(4096) * 4096;
            let at = self.position - lead as u64;
            require(
                at.checked_add(transfer as u64)
                    .is_some_and(|end| end <= self.byte_len()),
                "readonly phase transfer leaves target",
            )?;
            require(
                self.file.seek(SeekFrom::Start(at))? == at,
                "readonly phase native seek differs",
            )?;
            let got = self.file.read(&mut self.buffer.bytes_mut()[..transfer])?;
            require(got >= lead + count, "short readonly phase transfer")?;
            out[..count].copy_from_slice(&self.buffer.bytes_mut()[lead..lead + count]);
            self.position += count as u64;
            Ok(count)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
fn source_label(file: &File) -> io::Result<crate::volume_label::VolumeLabel> {
    let mut label = [0u16; 33];
    let mut fs = [0u16; 16];
    let mut serial = 0;
    let mut component = 0;
    let mut flags = 0;
    use std::os::windows::io::AsRawHandle;
    // SAFETY: actual bound mounted volume handle and fixed initialized buffers;
    // this is a query, not SetVolumeLabel or a whole-disk discovery exemption.
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let end = fs
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("filesystem query unterminated"))?;
    require(
        String::from_utf16(&fs[..end]).map_err(io::Error::other)? == "NTFS",
        "mounted source is not NTFS",
    )?;
    let end = label
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("source label unterminated"))?;
    crate::volume_label::VolumeLabel::from_utf16(label[..end].to_vec())
}
impl PartitionPreparationGuard {
    pub const fn maximum_intent_file_bytes() -> u64 {
        MAX_INTENT
    }
    pub const fn intent_working_memory_bytes() -> u64 {
        MAX_RECORD as u64 + 65536
    }
    /// `intent_file` must be a fresh exclusively owned ordinary RW C file.
    /// SDK checks its real GUID/extents and performs all durable writes itself.
    pub fn begin(
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        intent_file: File,
        mut observer: Box<dyn PartitionPreparationObserver>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        budget.validate()?;
        let required = budget
            .gpt_entry_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(u64::from(budget.native_layout_bytes) * 8))
            .and_then(|n| n.checked_add(MAX_IO as u64 + MAX_RECORD as u64 + 2 * 1024 * 1024))
            .ok_or_else(|| invalid("lifecycle RAM bound overflow"))?;
        require(
            required <= budget.ram_bytes,
            "lifecycle handles/GPT/intent workspace exceed explicit budget",
        )?;
        let reader = PartitionScopedReader::open(binding.clone(), budget, events)?;
        let baseline = reader.observation().clone();
        drop(reader);
        require(
            baseline.gpt.target_attributes == 0
                && baseline.paging.all_locations_resolved
                && baseline.source_volume_route_observed,
            "fresh BasicNTFS attrs0/current critical routes required",
        )?;
        observer.checkpoint("partition-preparation-basic-baseline", events)?;
        require(
            events.is_empty(),
            "initial lifecycle checkpoint did not drain",
        )?;
        let dumps = observe_configured_dump_locations(&binding, budget, events)?;
        let roles = observe_runtime_volume_roles(&binding, budget, events)?;
        require(
            dumps.configured_locations_outside_target
                && roles.vds_critical_role_extents_outside_target,
            "target intersects actual/configured critical volumes",
        )?;
        let vss = crate::vss_observation::observe_catalog(&format!(
            "{}\\",
            binding.storage.volume_path()?
        ))?;
        vss.require_observed_catalog_clear()?;
        let volume = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(binding.storage.volume_path()?)?;
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
            false,
            false,
        )?;
        let original_info = control(
            &volume,
            "partition-preparation-original-info",
            GET_PARTITION,
            &[],
            144,
            events,
        )?;
        require(
            original_info.len() == 144
                && original_info[32..48] == crate::layout::guid_bytes(BASIC)?
                && crate::layout::u64_at(&original_info, 64)? == 0,
            "original mounted target is not Basic attrs0",
        )?;
        let mounted_ntfs = crate::txf_native::observe_partition_before_freeze(&binding, &volume)?;
        let source_label = source_label(&volume)?;
        let mount_paths =
            super::super::capture_mount_paths_for_bound_volume(binding.storage.clone())?;
        let mbr = read_at(&mut physical, 0, 512)?;
        let primary = hash(&read_at(
            &mut physical,
            binding.storage.identity.partition_offset,
            512,
        )?);
        let intent = IntentFile::new(intent_file, &baseline, events)?;
        let mut guard = Self {
            binding,
            budget,
            token: PartitionPreparationToken(Arc::new(PreparationIdentity)),
            volume: Some(volume),
            physical: Some(physical),
            baseline,
            current_info: original_info.clone(),
            original_info,
            mbr,
            primary,
            stage: PartitionPreparationStage::BasicLocked,
            locked: false,
            protection: None,
            native: None,
            dumps,
            roles,
            vss,
            mounted_ntfs,
            source_label,
            mount_paths,
            intent,
            observer:PartitionNativeEventSink::new(observer),
        };
        guard.check_volume(guard.volume.as_ref().unwrap(), events)?;
        guard.lock_and_flush(events)?;
        guard.revalidate_current(events)?;
        Ok(guard)
    }
    pub fn stage(&self) -> PartitionPreparationStage {
        self.stage
    }
    pub fn preparation_token(&self) -> PartitionPreparationToken {
        self.token.clone()
    }
    fn checkpoint(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.observer.checkpoint(phase, events)?;
        require(
            events.is_empty(),
            "lifecycle event checkpoint did not drain",
        )
    }
    fn check_volume(&self, file: &File, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let device = control(
            file,
            "partition-preparation-volume-device",
            super::super::DEVICE,
            &[],
            12,
            events,
        )?;
        let info = control(
            file,
            "partition-preparation-volume-info",
            GET_PARTITION,
            &[],
            144,
            events,
        )?;
        let b = &self.binding.storage;
        require(
            device.len() == 12
                && crate::layout::u32_at(&device, 0)? == 7
                && crate::layout::u32_at(&device, 4)? == b.disk_number
                && crate::layout::u32_at(&device, 8)? == b.identity.partition_number
                && info == self.current_info
                && crate::layout::u64_at(&info, 8)? == b.identity.partition_offset
                && crate::layout::u64_at(&info, 16)? == b.identity.partition_bytes
                && info[48..64] == crate::layout::guid_bytes(&b.identity.partition_guid)?,
            "original volume owner device/partition identity differs",
        )
    }
    fn lock_and_flush(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if !self.locked {
            control(
                self.volume
                    .as_ref()
                    .ok_or_else(|| invalid("volume owner transferred"))?,
                "partition-preparation-lock",
                super::super::LOCK,
                &[],
                0,
                events,
            )?;
            self.locked = true;
        }
        control(
            self.volume.as_ref().unwrap(),
            "partition-preparation-dismount",
            super::super::DISMOUNT,
            &[],
            0,
            events,
        )?;
        let reply = control(self.volume.as_ref().unwrap(),
            "partition-preparation-extended-dasd", 0x0009_0083, &[], 0, events)?;
        require(reply.is_empty(), "extended DASD returned unexpected data")?;
        self.volume.as_ref().unwrap().sync_all()
    }
    fn expected_gpt(&self, current: &PartitionIsolationObservation) -> io::Result<()> {
        let old = &self.baseline.gpt;
        let actual = &current.gpt;
        let at = (old.target_slot as usize)
            .checked_sub(1)
            .and_then(|n| n.checked_mul(old.entry_bytes as usize))
            .ok_or_else(|| invalid("target GPT slot overflow"))?;
        let mut entries = old.entries.clone();
        require(
            at + 128 <= entries.len(),
            "target GPT slot leaves complete array",
        )?;
        entries[at..at + 16].copy_from_slice(&self.current_info[32..48]);
        entries[at + 48..at + 56].copy_from_slice(&self.current_info[64..72]);
        let mut native = old.native_layout.clone();
        let target = crate::layout::guid_bytes(&self.binding.storage.identity.partition_guid)?;
        let rows: Vec<usize> = (48..native.len())
            .step_by(144)
            .filter(|at| *at + 144 <= native.len() && native[*at + 48..*at + 64] == target)
            .collect();
        require(rows.len() == 1, "native target GUID is not unique")?;
        native[rows[0]..rows[0] + 144].copy_from_slice(&self.current_info);
        require(
            actual.entries == entries
                && actual.primary_header == expected_header(&old.primary_header, &entries)?
                && actual.backup_header == expected_header(&old.backup_header, &entries)?
                && actual.native_layout == native
                && actual.primary_crc_valid
                && actual.backup_crc_valid
                && actual.entry_arrays_equal,
            "GPT/siblings/unused/native fields changed beyond target type/attributes and required CRCs",
        )
    }
    fn revalidate_current(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.checkpoint("partition-preparation-revalidate", events)?;
        let private = self.current_info[32..48] == crate::layout::guid_bytes(PRIVATE)?;
        let current = if private {
            super::super::partition_isolation::observe_private(
                self.physical.as_mut().unwrap(),
                &self.binding,
                self.budget,
                events,
            )?
        } else {
            let reader = PartitionScopedReader::open(self.binding.clone(), self.budget, events)?;
            reader.observation().clone()
        };
        self.expected_gpt(&current)?;
        require(
            current.disk_device == self.baseline.disk_device
                && current.disk_length == self.baseline.disk_length
                && current.alignment == self.baseline.alignment
                && current.disk_attributes == 0
                && current.windows_volume == self.baseline.windows_volume
                && current.paging == self.baseline.paging,
            "physical/C/pagefile/sibling ownership changed",
        )?;
        require(
            read_at(self.physical.as_mut().unwrap(), 0, 512)? == self.mbr
                && hash(&read_at(
                    self.physical.as_mut().unwrap(),
                    self.binding.storage.identity.partition_offset,
                    512,
                )?) == self.primary,
            "original MBR/NTFS primary changed",
        )?;
        self.checkpoint("partition-preparation-critical-role-check", events)?;
        let dumps = observe_configured_dump_locations(&self.binding, self.budget, events)?;
        let roles = observe_runtime_volume_roles(&self.binding, self.budget, events)?;
        require(
            dumps == self.dumps && roles.same_critical_roles(&self.roles),
            "configured/current critical-role bindings changed",
        )?;
        self.check_volume(
            self.volume
                .as_ref()
                .ok_or_else(|| invalid("volume transferred"))?,
            events,
        )
    }
    fn change(
        &mut self,
        type_guid: &str,
        attrs: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.revalidate_current(events)?;
        require(
            self.locked && self.stage != PartitionPreparationStage::Poisoned,
            "actual original FS lock required before setter",
        )?;
        let mut desired = self.original_info.clone();
        desired[32..48].copy_from_slice(&crate::layout::guid_bytes(type_guid)?);
        desired[64..72].copy_from_slice(&attrs.to_le_bytes());
        let record = Intent {
            version: 1,
            kind: "partition-target-only-pre-AP-intent",
            sequence: self.intent.sequence + 1,
            stage: self.stage,
            binding: &self.binding,
            original_partition_info: &self.original_info,
            current_partition_info: &self.current_info,
            desired_partition_info: &desired,
            original_gpt: &self.baseline.gpt,
            original_mbr: &self.mbr,
            ntfs_primary_sha256: hex::encode(self.primary),
            source_AP_issued: false,
            process_death_recovery_authority: false,
        };
        let receipt = match self.intent.persist(&record, self.stage, &desired) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.stage = PartitionPreparationStage::Poisoned;
                return Err(error);
            }
        };
        if let Err(error) = self.observer.durable_intent(&receipt) {
            self.stage = PartitionPreparationStage::Poisoned;
            return Err(error);
        }
        self.revalidate_current(events)?;
        let mut input = [0u8; 120];
        input[..4].copy_from_slice(&1u32.to_le_bytes());
        input[8..120].copy_from_slice(&desired[32..144]);
        require(
            input[24..40] == self.original_info[48..64]
                && input[48..120] == self.original_info[72..144],
            "setter changed original ID/name",
        )?;
        // Phase is poisoned BEFORE the single call: failure may still change GPT.
        self.stage = PartitionPreparationStage::Poisoned;
        let result = control(
            self.volume.as_ref().unwrap(),
            "partition-preparation-SET_PARTITION_INFO_EX-once",
            SET_PARTITION,
            &input,
            0,
            events,
        )?;
        require(
            result.is_empty(),
            "single-partition setter returned unexpected bytes",
        )?;
        self.current_info = desired;
        self.revalidate_current(events)
    }
    pub fn protect_basic_readonly(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        require(
            self.stage == PartitionPreparationStage::BasicLocked,
            "Basic readonly protection is a single staged transition",
        )?;
        self.change(BASIC, READONLY, events)?;
        self.stage = PartitionPreparationStage::BasicReadonly;
        control(
            self.volume.as_ref().unwrap(),
            "partition-preparation-unlock-for-nativeRO",
            super::super::UNLOCK,
            &[],
            0,
            events,
        )?;
        self.locked = false;
        self.observe_readonly(events)
    }
    fn observe_readonly(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        require(
            matches!(
                self.stage,
                PartitionPreparationStage::BasicReadonly
                    | PartitionPreparationStage::NativeReadonlyCaptured
            ) && !self.locked,
            "mounted BasicRO native phase required",
        )?;
        self.revalidate_current(events)?;
        require(
            self.current_info[32..48] == crate::layout::guid_bytes(BASIC)?
                && crate::layout::u64_at(&self.current_info, 64)? == READONLY,
            "target lost exact BasicRO protection",
        )?;
        let volume = device_file(&self.binding.storage.volume_path()?, false, false)?;
        self.check_volume(&volume, events)?;
        let ext = control(
            &volume,
            "partition-nativeRO-volume-extents",
            super::super::VOLUME_EXTENTS,
            &[],
            32,
            events,
        )?;
        self.binding.storage.validate_volume_extent(&ext)?;
        let ntfs = control(
            &volume,
            "partition-nativeRO-NTFS-data",
            0x0009_0064,
            &[],
            128,
            events,
        )?;
        require(
            ntfs.len() >= 96 && crate::layout::u32_at(&ntfs, 40)? == 512,
            "BasicRO source is not supported NTFS",
        )?;
        let at = events.len();
        let result = control(
            &volume,
            "partition-nativeRO-IS_WRITABLE",
            IS_WRITABLE,
            &[],
            0,
            events,
        );
        require(
            result.is_err()
                && events
                    .get(at)
                    .is_some_and(|event| !event.succeeded && event.native_error == Some(19)),
            "actual target partition must report ERROR_WRITE_PROTECT19",
        )?;
        let actual_physical_attributes =
            super::super::attributes(self.physical.as_ref().unwrap(), events)?;
        require(
            actual_physical_attributes == 0,
            "physical disk availability changed during BasicRO proof",
        )?;
        let actual_write_protect_error = events
            .get(at)
            .and_then(|event| event.native_error)
            .ok_or_else(|| invalid("actual partition write-protection error missing"))?;
        self.protection = Some(PartitionReadonlyProtection {
            original_partition_info: self.original_info.clone(),
            readonly_partition_info: self.current_info.clone(),
            volume_extents: ext,
            ntfs_volume_data: ntfs,
            physical_disk_attributes: actual_physical_attributes,
            partition_write_protect_error: actual_write_protect_error,
        });
        Ok(())
    }
    pub fn collect_native_with(
        &mut self,
        events: &mut Vec<NativeEvent>,
        collect: impl FnOnce(
            &mut PartitionReadonlyPhase<'_>,
            &mut Vec<NativeEvent>,
        ) -> io::Result<PartitionPagedNtfsObservation>,
    ) -> io::Result<()> {
        require(
            self.stage == PartitionPreparationStage::BasicReadonly && self.native.is_none(),
            "native evidence must come from this actual BasicRO phase once",
        )?;
        self.observe_readonly(events)?;
        let mut phase = PartitionReadonlyPhase { guard: self };
        let native = collect(&mut phase, events)?;
        native.require_phase(&mut phase, events)?;
        phase.guard.native = Some(native);
        phase.guard.stage = PartitionPreparationStage::NativeReadonlyCaptured;
        Ok(())
    }
    /// Live pre-AP cancellation only. A parsed/crash-surviving intent is NOT
    /// sufficient; process-death/HND/ABT restoration requires a later issuer.
    pub fn cancel_before_private(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        require(
            matches!(
                self.stage,
                PartitionPreparationStage::BasicReadonly
                    | PartitionPreparationStage::NativeReadonlyCaptured
            ),
            "no live pre-private cancellation state",
        )?;
        self.native = None;
        self.protection = None;
        self.lock_and_flush(events)?;
        self.change(BASIC, 0, events)?;
        self.stage = PartitionPreparationStage::Cancelled;
        Ok(())
    }
}

pub struct PartitionNtfsAdmission {
    owner: PartitionOwnerToken,
    guard: PartitionPreparationGuard,
    native: PartitionPagedNtfsObservation,
}
impl PartitionNtfsAdmission {
    /// Consume the actual live guard. The readonly duplicate keeps the SAME
    /// intent FileObject/share-zero lock; no filename reopen is attempted.
    pub(in crate::native) fn into_terminal_preparation_owners(
        mut self,
        owner: &mut PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::super::partition_restoration::PartitionLivePreparationOwners> {
        let pin = self.durable_preparation_pin()?;
        self.revalidate_publication_handoff(owner, &pin, events)?;
        let intent = crate::file_storage::duplicate_readonly(&self.guard.intent.file)?;
        require(
            crate::reference_file::observe_reference_file_handle_with_limit(&intent, MAX_INTENT)?
                == pin.intent_file,
            "live terminal intent duplicate differs from actual guard",
        )?;
        Ok(
            super::super::partition_restoration::PartitionLivePreparationOwners {
                intent,
                native: self.native,
                pin,
                label: self.guard.source_label.clone(),
                mount_paths: self.guard.mount_paths.clone(),
            },
        )
    }
    pub fn checkpoint_native_events(&self,phase:&'static str,events:&mut Vec<NativeEvent>)->io::Result<()> {
        self.guard.observer.checkpoint(phase,events)
    }
    pub(in crate::native) fn event_sink(&self)->PartitionNativeEventSink {self.guard.observer.clone()}
    pub fn native(&self) -> &PartitionPagedNtfsObservation {
        &self.native
    }
    pub fn preparation_token(&self) -> &PartitionPreparationToken {
        &self.guard.token
    }
    pub fn original_partition_info(&self) -> &[u8] {
        &self.guard.original_info
    }
    /// Live held-guard handoff only. This authenticates the immutable external
    /// intent and actual owner binding, never OLD payload/native-content bytes.
    /// A process-death/reopened cancellation or HND/ABT issuer is separate.
    pub fn revalidate_publication_handoff(
        &mut self,
        owner: &mut PartitionScopedOwner,
        expected: &PartitionPreparationPin,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.checkpoint_native_events("partition-handoff-revalidation-opening",events)?;
        let result=(||->io::Result<()> {
        require_complete_fresh_ntfs_admission(owner, self)?;
        owner.revalidate(events)?;
        let pin = self.durable_preparation_pin()?;
        require(&pin == expected, "live preparation pin changed")?;
        let file = &mut self.guard.intent.file;
        let before =
            crate::reference_file::observe_reference_file_handle_with_limit(file, MAX_INTENT)?;
        require(
            before == pin.intent_file
                && before.allocation_bytes <= self.guard.intent.max_allocation,
            "live held preparation intent identity/allocation changed",
        )?;
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(&before.final_path)
        {
            Err(error) if error.raw_os_error() == Some(32) => (),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("intent sharing recheck unknown: {error}"),
                ));
            }
            Ok(contender) => {
                drop(contender);
                return Err(invalid("preparation intent admitted another RW writer"));
            }
        }
        let digest = crate::sha256_native::hash_range(file, 0, self.guard.intent.end)?;
        require(
            hex::encode(digest) == pin.intent_prefix_sha256
                && crate::reference_file::observe_reference_file_handle_with_limit(
                    file, MAX_INTENT,
                )? == before,
            "live preparation intent content/identity changed",
        )?;
        owner.revalidate(events)?;
        Ok(())
        })();
        let closed=self.checkpoint_native_events("partition-handoff-revalidation-closed",events);
        match(result,closed){(Ok(value),Ok(()))=>Ok(value),(Err(error),_)|(_,Err(error))=>Err(error)}
    }
    pub fn original_label(&self) -> &crate::volume_label::VolumeLabel {
        &self.guard.source_label
    }
    pub fn original_mount_paths(&self) -> &super::super::MountPathObservation {
        &self.guard.mount_paths
    }
    pub fn mounted_ntfs_before_freeze(&self) -> &crate::txf_native::PartitionMountedTxfObservation {
        &self.guard.mounted_ntfs
    }
    pub fn readonly_protection(&self) -> &PartitionReadonlyProtection {
        self.guard
            .protection
            .as_ref()
            .expect("admission owns actual BasicRO proof")
    }
    /// Authenticated held-intent routing facts; never a reopened admission.
    pub fn durable_preparation_pin(&self) -> io::Result<PartitionPreparationPin> {
        let receipt = self
            .guard
            .intent
            .latest_receipt
            .as_ref()
            .ok_or_else(|| invalid("durable preparation receipt absent"))?;
        let mut gpt = Sha256::new();
        gpt.update(&self.guard.baseline.gpt.primary_header);
        gpt.update(&self.guard.baseline.gpt.entries);
        gpt.update(&self.guard.baseline.gpt.backup_header);
        gpt.update(&self.guard.baseline.gpt.native_layout);
        Ok(PartitionPreparationPin {
            version: 1,
            kind: "partition-target-only-preparation-v1",
            binding: self.guard.binding.clone(),
            original_partition_info: self.guard.original_info.clone(),
            original_gpt_sha256: hex::encode(gpt.finalize()),
            original_mbr_sha256: hex::encode(hash(&self.guard.mbr)),
            ntfs_primary_sha256: hex::encode(self.guard.primary),
            intent_file: receipt.intent_file.clone(),
            intent_prefix_sha256: receipt.intent_prefix_sha256.clone(),
            sequence: receipt.sequence,
            observed_stage: self.guard.stage,
            serialized_pin_grants_authority: false,
        })
    }
}
pub fn freeze_mounted_ntfs_partition(
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    mut guard: PartitionPreparationGuard,
    events: &mut Vec<NativeEvent>,
) -> io::Result<(PartitionScopedOwner, PartitionNtfsAdmission)> {
    require(
        guard.binding == binding
            && guard.budget == budget
            && guard.stage == PartitionPreparationStage::NativeReadonlyCaptured,
        "complete actual BasicRO native witness required before private transition",
    )?;
    let native = guard
        .native
        .take()
        .ok_or_else(|| invalid("actual nativeRO witness missing"))?;
    {
        let mut phase = PartitionReadonlyPhase { guard: &mut guard };
        native.require_phase(&mut phase, events)?;
    }
    guard.lock_and_flush(events)?;
    guard.change(PRIVATE, 0, events)?;
    guard.stage = PartitionPreparationStage::PrivateLocked;
    // Real FSCTL_LOCK must succeed after the collector returned: retained
    // native source file readers would fail this transition, never get ignored.
    let owner = PartitionScopedOwner::adopt_lifecycle_owner(
        binding,
        budget,
        guard
            .volume
            .take()
            .ok_or_else(|| invalid("original volume owner absent"))?,
        guard
            .physical
            .take()
            .ok_or_else(|| invalid("original readonly physical owner absent"))?,
        events,
    )?;
    let admission = PartitionNtfsAdmission {
        owner: owner.owner_token(),
        guard,
        native,
    };
    Ok((owner, admission))
}
pub fn require_complete_fresh_ntfs_admission(
    owner: &PartitionScopedOwner,
    admission: &PartitionNtfsAdmission,
) -> io::Result<()> {
    require(
        admission.owner.same_owner(&owner.owner_token())
            && admission.guard.binding == *owner.binding()
            && admission.guard.stage == PartitionPreparationStage::PrivateLocked
            && admission
                .native
                .preparation_token()
                .same_owner(&admission.guard.token),
        "fresh partition admission lost actual prepared/native/owner association",
    )
}
