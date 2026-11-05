use crate::{
    general_layout::GeneralDiskBinding,
    layout::{self, DiskBinding, GRANULE, invalid},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, IntoRawHandle},
    },
    ptr::{self, NonNull},
    sync::Arc,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, ERROR_SHARING_VIOLATION, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationByHandleW,
    GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW,
    SetVolumeMountPointW,
};
use windows_sys::Win32::System::{IO::DeviceIoControl, SystemInformation::GetWindowsDirectoryW};

mod paged_write_policy;
mod paged_recovery;
mod isolation_restore;
pub mod partition_isolation;
pub use paged_write_policy::{
    HeldPagedWritePolicy, PagedPolicyIndexBuilder, PagedPolicyIndexFacts, PagedPolicyIndexRow,
};
pub use paged_recovery::{BorrowedPagedWriter, GeneralLiveConvertedObservation, PagedRecoveryDirection, PagedRecoveryPins};
pub use paged_recovery::{PartitionClosedJournalObservation, PartitionHandoffWitness,
    PartitionTerminalKind, authenticate_partition_closed_journal};

mod partition_dump_locations;
mod partition_runtime_roles;
mod partition_storage_roles;
mod partition_owner;
mod partition_source_metadata;
mod partition_target_observation;
pub use partition_source_metadata::{PartitionSourceMetadataState, PartitionSourceMetadataWitness};
pub mod partition_lifecycle;
pub mod partition_restoration;
mod partition_restoration_observation;
pub use partition_owner::{PartitionOwnerState, PartitionOwnerToken, PartitionPagedWriter, PartitionScopedOwner};
pub use partition_owner::{PartitionJournalReadView, PartitionSourceAdmissionGate};
pub use partition_owner::PartitionMixedReplayGate;

const DEVICE: u32 = 0x002d1080;
const LENGTH: u32 = 0x0007405c;
const ALIGNMENT: u32 = 0x002d1400;
const LAYOUT: u32 = 0x00070050;
const GET_ATTRIBUTES: u32 = 0x000700f0;
const SET_ATTRIBUTES: u32 = 0x0007c0f4;
const UPDATE_PROPERTIES: u32 = 0x00070140;
const VOLUME_EXTENTS: u32 = 0x00560000;
const LOCK: u32 = 0x00090018;
const UNLOCK: u32 = 0x0009001c;
const DISMOUNT: u32 = 0x00090020;
const OFFLINE: u64 = 1;
const READ_ONLY: u64 = 2;
// Largest single device request and the size of each handle's aligned buffer.
// Larger sequential requests cut per-call overhead on fast storage.
const MAX_IO: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct NativeEvent {
    pub operation: String,
    pub control_code: u32,
    pub input: Vec<u8>,
    pub succeeded: bool,
    pub native_error: Option<i32>,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PartitionSnapshot {
    pub binding: DiskBinding,
    pub disk_attributes: u64,
    pub device: Vec<u8>,
    pub length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub layout: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GeneralProbe {
    pub binding: GeneralDiskBinding,
    pub disk_attributes_before: u64,
    pub disk_attributes_after: u64,
    pub device: Vec<u8>,
    pub disk_length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub gpt_layout: Vec<u8>,
    pub volume_extents: Vec<u8>,
    pub read_only_probe: bool,
    pub source_write_requests: u64,
    pub conversion_qualified: bool,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct MountPathObservation {
    pub binding: GeneralDiskBinding,
    pub paths: Vec<String>,
    pub all_paths_resolve_to_bound_volume: bool,
}

#[derive(Debug, Serialize)]
pub struct DriveLetterRestore {
    pub requested: String,
    pub before: MountPathObservation,
    pub after: MountPathObservation,
    pub changed: bool,
    pub target_filesystem: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct GeneralDiskState {
    pub device: Vec<u8>,
    pub disk_length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub gpt_layout: Vec<u8>,
    pub disk_attributes: u64,
}
/// Created only by a physically read-only native observation bracketed by
/// actual excluded-device snapshots. Exporting it cannot recreate a lease.
#[derive(Debug, Serialize)]
pub struct LiveNtfsObservation {
    report: crate::attestation::Report,
    before: PartitionSnapshot,
    after: PartitionSnapshot,
}
#[derive(Debug, Serialize)]
pub struct GeneralLiveNtfsObservation {
    report: crate::attestation::Report,
    txf: Option<crate::txf_native::GeneralObservation>,
    txf_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vss_observation: Option<crate::vss_observation::Observation>,
    before: GeneralDiskState,
    after: GeneralDiskState,
}
/// Same live physical protection lease as GeneralLiveNtfsObservation, with
/// complete metadata rows retained in an authenticated ordinary file.
#[derive(Debug)]
pub struct GeneralLivePagedNtfsObservation {
    domain: crate::observation_pages::PagedNativeObservation,
    txf: Option<crate::txf_native::GeneralObservation>,
    txf_error: Option<String>,
    vss_observation: Option<crate::vss_observation::Observation>,
    before: GeneralDiskState,
    after: GeneralDiskState,
}
impl GeneralLivePagedNtfsObservation {
    pub fn domain(&self) -> &crate::observation_pages::PagedNativeObservation {
        &self.domain
    }
    pub fn txf(&self) -> Option<&crate::txf_native::GeneralObservation> {
        self.txf.as_ref()
    }
    pub fn txf_error(&self) -> Option<&str> {
        self.txf_error.as_deref()
    }
    pub fn vss_observation(&self) -> Option<&crate::vss_observation::Observation> {
        self.vss_observation.as_ref()
    }
    pub fn before(&self) -> &GeneralDiskState {
        &self.before
    }
    pub fn after(&self) -> &GeneralDiskState {
        &self.after
    }
}
struct CollectedGeneralNtfs<T> {
    domain: T,
    txf: Option<crate::txf_native::GeneralObservation>,
    txf_error: Option<String>,
    vss_observation: Option<crate::vss_observation::Observation>,
    before: GeneralDiskState,
    after: GeneralDiskState,
}
/// Constructed only while a frozen ReFS partition is published through a
/// physically read-only lease and returned to persistent exclusion. The raw
/// before/after image equality remains the caller's independent obligation.
#[derive(Debug, Serialize)]
pub struct GeneralLiveRefsObservation {
    report: crate::shadow_native::GeneralReport,
    before: GeneralDiskState,
    observed_readonly: GeneralDiskState,
    after: GeneralDiskState,
}
impl GeneralLiveRefsObservation {
    pub fn report(&self) -> &crate::shadow_native::GeneralReport {
        &self.report
    }
    pub fn before(&self) -> &GeneralDiskState {
        &self.before
    }
    pub fn after(&self) -> &GeneralDiskState {
        &self.after
    }
}

/// Post-freeze native metadata/layout witness issued only by the physical
/// READ_ONLY lease. Logical payload, raw before/after equality and allocation
/// graph completeness require separate proofs; this grants no write authority.
#[derive(Debug, Serialize)]
pub struct GeneralLiveRefsLayoutObservation {
    report: crate::shadow_native::GeneralLayoutReport,
    before: GeneralDiskState,
    observed_readonly: GeneralDiskState,
    after: GeneralDiskState,
}
impl GeneralLiveRefsLayoutObservation {
    pub fn report(&self) -> &crate::shadow_native::GeneralLayoutReport {
        &self.report
    }
    pub fn before(&self) -> &GeneralDiskState {
        &self.before
    }
    pub fn observed_readonly(&self) -> &GeneralDiskState {
        &self.observed_readonly
    }
    pub fn after(&self) -> &GeneralDiskState {
        &self.after
    }
}

/// A borrowed actual volume handle created only inside the exclusion lease.
/// Neither a caller-provided flag nor a serialized report can create this
/// route. No constructor or disk-state setters are exposed outside native.rs.
pub(crate) struct GeneralReadonlyRefsVolume<'a> {
    binding: &'a GeneralDiskBinding,
    management: &'a File,
    volume: &'a File,
    expected_state: &'a GeneralDiskState,
}
mod readonly_refs_access;
pub(crate) use readonly_refs_access::{ProtectedReadonlyRefsAccess, ReadonlyRefsScope};
pub use crate::shadow_native::PartitionReadonlyFidelity as PartitionTerminalNativeObservation;
impl GeneralReadonlyRefsVolume<'_> {
    pub(crate) fn binding(&self) -> &GeneralDiskBinding {
        self.binding
    }
    pub(crate) fn volume(&self) -> &File {
        self.volume
    }
    pub(crate) fn snapshot(
        &self,
        binding: &DiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionSnapshot> {
        if binding.disk_number != self.binding.disk_number
            || binding.volume_guid != self.binding.volume_guid
            || binding.identity != self.binding.identity
        {
            return Err(invalid("protected ReFS observer binding differs"));
        }
        let state = general_disk_state(self.management, self.binding, events)?;
        if state != *self.expected_state || state.disk_attributes != READ_ONLY {
            return Err(invalid(
                "protected ReFS volume is no longer physically read-only",
            ));
        }
        let extents = control(
            self.volume,
            "protected-refs-observation-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        self.binding.validate_volume_extent(&extents)?;
        Ok(PartitionSnapshot {
            binding: binding.clone(),
            disk_attributes: state.disk_attributes,
            device: state.device,
            length: state.disk_length,
            alignment: state.alignment,
            layout: state.gpt_layout,
        })
    }
}
impl GeneralLiveNtfsObservation {
    pub fn report(&self) -> &crate::attestation::Report {
        &self.report
    }
    pub fn txf(&self) -> Option<&crate::txf_native::GeneralObservation> {
        self.txf.as_ref()
    }
    pub fn txf_error(&self) -> Option<&str> {
        self.txf_error.as_deref()
    }
    pub fn vss_observation(&self) -> Option<&crate::vss_observation::Observation> {
        self.vss_observation.as_ref()
    }
}
impl LiveNtfsObservation {
    pub fn report(&self) -> &crate::attestation::Report {
        &self.report
    }
    pub fn binding(&self) -> &DiskBinding {
        &self.after.binding
    }
}
struct ReadonlyObservationLease<'a> {
    file: &'a File,
    events: &'a mut Vec<NativeEvent>,
    restoration_attempted: bool,
}
impl ReadonlyObservationLease<'_> {
    fn finish(&mut self) -> io::Result<()> {
        self.restoration_attempted = true;
        set_attributes(self.file, OFFLINE | READ_ONLY, self.events)?;
        control(
            self.file,
            "refresh-excluded-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            self.events,
        )?;
        Ok(())
    }
}
impl Drop for ReadonlyObservationLease<'_> {
    fn drop(&mut self) {
        if !self.restoration_attempted {
            let _ = self.finish();
        }
    }
}

#[derive(Clone, Debug)]
pub struct WritePolicy {
    pub allowed: Vec<(u64, u64)>,
    pub retained: Vec<(u64, u64)>,
    pub maximum_bytes: u64,
    pub journal_profile: crate::journal_file::JournalProfile,
}

enum SelectedWriteCapacity {
    Encoded {
        journal_bytes: u64,
    },
    OldZero {
        journal_bytes: u64,
        old_zero_bytes: u64,
    },
    OldZeroActualBytesV3 {
        journal_bytes: u64,
        old_zero_bytes: u64,
        pinned_max_journal_bytes: u64,
    },
    SourceFreeActualBytesV3 {
        journal_bytes: u64,
        old_zero_bytes: u64,
        source_free_bytes: u64,
        pinned_max_journal_bytes: u64,
    },
}

impl WritePolicy {
    pub fn validate(&self, length: u64) -> io::Result<()> {
        self.validate_with_byte_limit(length, self.journal_profile.max_changed_bytes())
    }

    /// Encoded selected journals retain every old byte but may synthesize the
    /// new bytes. The exact, independently checked journal length replaces the
    /// legacy assumption that every changed byte needs two payload copies.
    fn validate_encoded(&self, length: u64, journal_bytes: u64) -> io::Result<()> {
        if journal_bytes == 0 || journal_bytes > self.journal_profile.max_journal_bytes() {
            return Err(invalid(
                "encoded journal exceeds its native storage profile",
            ));
        }
        self.validate_with_byte_limit(length, journal_bytes)
    }

    /// Canonical old zeros preserve logical rollback bytes without storing a
    /// payload copy. The caller authenticates the pinned old-zero subset;
    /// these counts alone grant no journal or source authority.
    fn validate_old_zero_encoded(
        &self,
        length: u64,
        journal_bytes: u64,
        old_zero_bytes: u64,
    ) -> io::Result<()> {
        if journal_bytes == 0
            || journal_bytes > self.journal_profile.max_journal_bytes()
            || old_zero_bytes == 0
            || old_zero_bytes > self.maximum_bytes
            || !old_zero_bytes.is_multiple_of(GRANULE)
        {
            return Err(invalid(
                "old-zero journal capacity or logical byte count differs",
            ));
        }
        let reconstructed_capacity = journal_bytes
            .checked_add(old_zero_bytes)
            .ok_or_else(|| invalid("old-zero journal capacity overflow"))?;
        self.validate_with_byte_limit(
            length,
            reconstructed_capacity.min(self.journal_profile.max_encoded_changed_bytes()),
        )
    }

    /// Separate capacity admission for an explicitly pinned actual-byte
    /// policy. The caller must authenticate the complete format-four plan and
    /// journal; these scalar counts are not source or replay authority.
    fn validate_old_zero_actual_bytes_v3(
        &self,
        length: u64,
        journal_bytes: u64,
        old_zero_bytes: u64,
        pinned_max_journal_bytes: u64,
    ) -> io::Result<()> {
        let expected = crate::journal_file::JournalProfile::from_schema_and_capacity(
            3,
            Some(pinned_max_journal_bytes),
        )?;
        if self.journal_profile != expected
            || journal_bytes == 0
            || journal_bytes > pinned_max_journal_bytes
            || old_zero_bytes == 0
            || old_zero_bytes > self.maximum_bytes
            || !old_zero_bytes.is_multiple_of(GRANULE)
        {
            return Err(invalid(
                "actual-byte selected capacity differs from pinned V3 policy",
            ));
        }
        let reconstructed = journal_bytes
            .checked_add(old_zero_bytes)
            .ok_or_else(|| invalid("actual-byte selected capacity overflow"))?;
        self.validate_with_byte_limit(length, reconstructed.min(length))
    }

    /// Capacity only: frozen allocation/VSS admission and the authenticated
    /// format-five plan remain the caller's separate obligations.
    fn validate_source_free_actual_bytes_v3(
        &self,
        length: u64,
        journal_bytes: u64,
        old_zero_bytes: u64,
        source_free_bytes: u64,
        pinned_max_journal_bytes: u64,
    ) -> io::Result<()> {
        let expected = crate::journal_file::JournalProfile::from_schema_and_capacity(
            3,
            Some(pinned_max_journal_bytes),
        )?;
        let omitted = old_zero_bytes
            .checked_add(source_free_bytes)
            .ok_or_else(|| invalid("source-free omitted byte count overflow"))?;
        if self.journal_profile != expected
            || journal_bytes == 0
            || journal_bytes > pinned_max_journal_bytes
            || source_free_bytes == 0
            || !source_free_bytes.is_multiple_of(GRANULE)
            || !old_zero_bytes.is_multiple_of(GRANULE)
            || omitted > self.maximum_bytes
        {
            return Err(invalid(
                "source-free selected capacity differs from pinned V3 policy",
            ));
        }
        let reconstructed = journal_bytes
            .checked_add(omitted)
            .ok_or_else(|| invalid("source-free selected capacity overflow"))?;
        self.validate_with_byte_limit(length, reconstructed.min(length))
    }

    fn validate_with_byte_limit(&self, length: u64, byte_limit: u64) -> io::Result<()> {
        layout::validate_ranges(&self.allowed, length)?;
        // Relocation-only tree plans have no retained ranges. The native
        // fixture adapter still enforces its original one-range profile.
        if !self.retained.is_empty() {
            layout::validate_ranges(&self.retained, length)?;
        }
        let mut bytes = 0_u64;
        for &(offset, count) in &self.allowed {
            bytes = bytes
                .checked_add(count)
                .ok_or_else(|| invalid("write budget overflow"))?;
            for &(keep, keep_count) in &self.retained {
                if offset < keep + keep_count && keep < offset + count {
                    return Err(invalid("write policy overlaps retained data"));
                }
            }
        }
        if bytes > self.maximum_bytes || self.maximum_bytes > byte_limit {
            return Err(invalid(
                "native write policy exceeds the explicit journal-capacity profile",
            ));
        }
        Ok(())
    }

    fn permits(&self, offset: u64, count: u64) -> bool {
        if !offset.is_multiple_of(GRANULE) || !count.is_multiple_of(GRANULE) || count == 0 {
            return false;
        }
        offset.checked_add(count).is_some_and(|end| {
            self.allowed
                .iter()
                .any(|&(at, len)| at <= offset && end <= at + len)
        })
    }
}

#[derive(Clone,Copy)]
enum ControlInputBudget { Ordinary64, GptPartitionInformation120 }
impl ControlInputBudget {
    fn input_limit(self)->usize {match self{Self::Ordinary64=>64,Self::GptPartitionInformation120=>120}}
}
fn control(
    file:&File,name:&str,code:u32,input:&[u8],capacity:usize,events:&mut Vec<NativeEvent>,
)->io::Result<Vec<u8>> {
    control_admitted(file,name,code,input,capacity,events,ControlInputBudget::Ordinary64)
}
/// Fixed SDK single-GPT-partition setter only. The caller must already hold
/// the actual source/intent/GPT lifecycle; this helper grants none of those.
/// Ordinary control keeps its64-byte input ceiling and cannot select this case.
fn control_set_gpt_partition(
    file:&File,name:&str,input:&[u8;120],events:&mut Vec<NativeEvent>,
)->io::Result<Vec<u8>> {
    const _:()=assert!(std::mem::size_of::<windows_sys::Win32::System::Ioctl::SET_PARTITION_INFORMATION_EX>()==120
        &&std::mem::offset_of!(windows_sys::Win32::System::Ioctl::SET_PARTITION_INFORMATION_EX,Anonymous)==8
        &&std::mem::size_of::<windows_sys::Win32::System::Ioctl::PARTITION_INFORMATION_GPT>()==112);
    if input[..4]!=1u32.to_le_bytes()||input[4..8]!=[0;4] {
        return Err(invalid("typed partition setter requires exact GPT SDK header/padding"));
    }
    control_admitted(file,name,windows_sys::Win32::System::Ioctl::IOCTL_DISK_SET_PARTITION_INFO_EX,
        input,0,events,ControlInputBudget::GptPartitionInformation120)
}
fn control_admitted(
    file:&File,name:&str,code:u32,input:&[u8],capacity:usize,events:&mut Vec<NativeEvent>,budget:ControlInputBudget,
)->io::Result<Vec<u8>> {
    if matches!(budget,ControlInputBudget::GptPartitionInformation120)
        &&(code!=windows_sys::Win32::System::Ioctl::IOCTL_DISK_SET_PARTITION_INFO_EX||input.len()!=120||capacity!=0) {
        return Err(invalid("typed GPT setter control shape differs from fixed SDK contract"));
    }
    let limit=budget.input_limit();
    if input.len()>limit||capacity>65536||events.len()>=128 {
        return Err(invalid(&format!("native control budget exceeded: operation={name}, code=0x{code:08x}, input_bytes={}, output_capacity={capacity}, events={}, limits(input_bytes<={limit}, output_capacity<=65536, events<128)",input.len(),events.len())));
    }
    let mut output = vec![0; capacity];
    let mut returned = 0_u32;
    // SAFETY: File owns a live Windows handle; input/output are separately owned
    // buffers of the declared sizes. Synchronous I/O retains neither pointer.
    let success = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if output.is_empty() {
                ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } != 0;
    let error = if success {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    if returned as usize > capacity {
        return Err(invalid(
            "native control returned more bytes than its buffer",
        ));
    }
    output.truncate(returned as usize);
    events.push(NativeEvent {
        operation: name.into(),
        control_code: code,
        input: input.to_vec(),
        succeeded: success,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: output.clone(),
    });
    if let Some(error) = error {
        return Err(io::Error::new(error.kind(), format!("{name}: {error}")));
    }
    Ok(output)
}

pub(crate) fn device_file(path: &str, writable: bool, unbuffered: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(writable).share_mode(3);
    if unbuffered {
        options.custom_flags(0xa000_0000);
    } // NO_BUFFERING | WRITE_THROUGH
    options.open(path)
}

fn attributes(file: &File, events: &mut Vec<NativeEvent>) -> io::Result<u64> {
    let bytes = control(file, "get-disk-attributes", GET_ATTRIBUTES, &[], 16, events)?;
    if bytes.len() != 16 || layout::u32_at(&bytes, 0)? != 16 {
        return Err(invalid("disk attributes response differs"));
    }
    let attributes = layout::u64_at(&bytes, 8)?;
    if attributes & !(OFFLINE | READ_ONLY) != 0 {
        return Err(invalid("unknown disk attributes"));
    }
    Ok(attributes)
}

pub(crate) fn set_attributes(
    file: &File,
    value: u64,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    if value & !(OFFLINE | READ_ONLY) != 0 {
        return Err(invalid("unknown requested attributes"));
    }
    let mut bytes = [0_u8; 40];
    bytes[..4].copy_from_slice(&40_u32.to_le_bytes());
    bytes[4] = 1; // Persist: the exclusion must survive a restart.
    bytes[8..16].copy_from_slice(&value.to_le_bytes());
    bytes[16..24].copy_from_slice(&(OFFLINE | READ_ONLY).to_le_bytes());
    control(
        file,
        "set-persistent-disk-attributes",
        SET_ATTRIBUTES,
        &bytes,
        0,
        events,
    )?;
    if attributes(file, events)? != value {
        return Err(invalid("disk attribute transition did not take effect"));
    }
    // Persist=1 lands in the SYSTEM hive (the disk's Partmgr "Attributes"
    // value, observed equal to these bits), which Windows writes lazily: a hard
    // power-off after an activation reverted OFFLINE to OFFLINE|READ_ONLY. Do
    // not report the transition until the hive is on disk.
    flush_persisted_attributes(events)
}

/// RegFlushKey on HKLM\SYSTEM: returns once the hive holding the persisted
/// disk attributes is written to disk. Opens the key for query only, writes no
/// registry value and changes no attribute; failure refuses without retry.
pub(crate) fn flush_persisted_attributes(events: &mut Vec<NativeEvent>) -> io::Result<()> {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RegCloseKey, RegFlushKey, RegOpenKeyExW,
    };
    if events.len() >= 128 {
        return Err(invalid("native control budget exceeded"));
    }
    let name: Vec<u16> = "SYSTEM\0".encode_utf16().collect();
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: predefined root key, NUL-terminated name and a live output slot.
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    let status = if opened == 0 {
        // SAFETY: `key` was opened above and is closed exactly once here.
        let flushed = unsafe { RegFlushKey(key) };
        // SAFETY: as above; the close result does not change the flush outcome.
        unsafe { RegCloseKey(key) };
        flushed
    } else {
        opened
    };
    events.push(NativeEvent {
        operation: "flush-persisted-disk-attributes".into(),
        control_code: 0,
        input: b"HKLM\\SYSTEM".to_vec(),
        succeeded: status == 0,
        native_error: (status != 0).then_some(status as i32),
        output: Vec::new(),
    });
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

pub(crate) fn current_windows_disk(events: &mut Vec<NativeEvent>) -> io::Result<u32> {
    let mut name = vec![0_u16; 512];
    // SAFETY: the output buffer contains 512 writable UTF-16 elements.
    let count = unsafe { GetWindowsDirectoryW(name.as_mut_ptr(), name.len() as u32) } as usize;
    if count < 3 || count >= name.len() || name[1] != b':' as u16 || name[2] != b'\\' as u16 {
        return Err(invalid(
            "current Windows volume cannot be safely identified",
        ));
    }
    let letter =
        char::from_u32(u32::from(name[0])).ok_or_else(|| invalid("invalid system drive"))?;
    if !letter.is_ascii_alphabetic() {
        return Err(invalid("current Windows path is not a drive path"));
    }
    let volume = device_file(&format!("\\\\.\\{letter}:"), false, false)?;
    let bytes = control(
        &volume,
        "current-windows-extents",
        VOLUME_EXTENTS,
        &[],
        1024,
        events,
    )?;
    if bytes.len() != 32 || layout::u32_at(&bytes, 0)? != 1 {
        return Err(invalid("current Windows disk is not a simple volume"));
    }
    layout::u32_at(&bytes, 8)
}

pub(crate) fn snapshot(
    file: &File,
    binding: &DiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionSnapshot> {
    binding.validate()?;
    let device = control(file, "storage-device-number", DEVICE, &[], 12, events)?;
    layout::validate_device(&device, binding.disk_number)?;
    let length = control(file, "disk-length", LENGTH, &[], 8, events)?;
    if length.len() != 8 || layout::u64_at(&length, 0)? != binding.identity.disk_bytes {
        return Err(invalid("physical disk length differs"));
    }
    let mut property = [0_u8; 12];
    property[0] = 6;
    let alignment = control(file, "storage-alignment", ALIGNMENT, &property, 28, events)?;
    layout::validate_alignment(&alignment)?;
    let layout_bytes = control(file, "gpt-layout", LAYOUT, &[], 65536, events)?;
    layout::validate_layout(&layout_bytes, binding)?;
    let disk_attributes = attributes(file, events)?;
    Ok(PartitionSnapshot {
        binding: binding.clone(),
        disk_attributes,
        device,
        length,
        alignment,
        layout: layout_bytes,
    })
}

/// Recheck immutable disk route, geometry and layout through the same handle.
pub(crate) fn general_disk_state(
    disk: &File,
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskState> {
    binding.validate()?;
    let device = control(&disk, "general-storage-device", DEVICE, &[], 12, events)?;
    layout::validate_device(&device, binding.disk_number)?;
    let disk_length = control(&disk, "general-disk-length", LENGTH, &[], 8, events)?;
    if disk_length.len() != 8 || layout::u64_at(&disk_length, 0)? != binding.identity.disk_bytes {
        return Err(invalid("general disk length differs"));
    }
    let mut property = [0u8; 12];
    property[0] = 6;
    let alignment = control(
        &disk,
        "general-storage-alignment",
        ALIGNMENT,
        &property,
        28,
        events,
    )?;
    binding.validate_alignment(&alignment)?;
    let gpt_layout = control(&disk, "general-gpt-layout", LAYOUT, &[], 65536, events)?;
    binding.validate_layout(&gpt_layout)?;
    let disk_attributes = attributes(&disk, events)?;
    Ok(GeneralDiskState {
        device,
        disk_length,
        alignment,
        gpt_layout,
        disk_attributes,
    })
}

/// Observe stable GPT identity, geometry and attributes through one read-only
/// raw disk handle. Mounted-volume access is not required, and all four known
/// OFFLINE/READ_ONLY combinations are reportable. This grants no authority to
/// restore availability, activate a journal or change disk attributes.
pub fn observe_general_disk_state_readonly(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskState> {
    binding.validate()?;
    if current_windows_disk(events)? == binding.disk_number {
        return Err(invalid("current Windows disk is excluded"));
    }
    let disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        false,
        false,
    )?;
    let before = general_disk_state(&disk, &binding, events)?;
    let after = general_disk_state(&disk, &binding, events)?;
    if before != after || current_windows_disk(events)? == binding.disk_number {
        return Err(invalid(
            "general read-only disk state changed during observation",
        ));
    }
    close_file(disk, "close-general-readonly-state-observation", events)?;
    Ok(after)
}

/// Probe one dedicated non-system basic data disk without locking, dismounting,
/// setting attributes or issuing raw writes. This is not a conversion lease.
pub fn probe_general(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralProbe> {
    binding.validate()?;
    if current_windows_disk(events)? == binding.disk_number {
        return Err(invalid("current Windows disk is excluded"));
    }
    let disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        false,
        false,
    )?;
    let state = general_disk_state(&disk, &binding, events)?;
    let disk_attributes_before = state.disk_attributes;
    if disk_attributes_before != 0 {
        return Err(invalid("general data disk is not online and writable"));
    }
    let volume = device_file(&binding.volume_path()?, false, false)?;
    let volume_extents = control(
        &volume,
        "general-volume-extents",
        VOLUME_EXTENTS,
        &[],
        1024,
        events,
    )?;
    binding.validate_volume_extent(&volume_extents)?;
    let after = general_disk_state(&disk, &binding, events)?;
    let disk_attributes_after = after.disk_attributes;
    if after.device != state.device
        || after.disk_length != state.disk_length
        || after.alignment != state.alignment
        || after.gpt_layout != state.gpt_layout
    {
        return Err(invalid("general disk layout changed during probe"));
    }
    if disk_attributes_after != disk_attributes_before {
        return Err(invalid("general disk attributes changed during probe"));
    }
    Ok(GeneralProbe {
        binding,
        disk_attributes_before,
        disk_attributes_after,
        device: state.device,
        disk_length: state.disk_length,
        alignment: state.alignment,
        gpt_layout: state.gpt_layout,
        volume_extents,
        read_only_probe: true,
        source_write_requests: 0,
        conversion_qualified: false,
    })
}

/// Observe the mounted filesystem name only after the bound dedicated disk
/// has become online and writable. The GPT route is rechecked first.
pub fn mounted_filesystem_general(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<String> {
    probe_general(binding.clone(), events)?;
    let path = format!("{}\\", binding.volume_path()?);
    let mut path_wide: Vec<u16> = path.encode_utf16().collect();
    path_wide.push(0);
    let mut filesystem = [0u16; 32];
    let mut serial = 0u32;
    let mut component = 0u32;
    let mut flags = 0u32;
    // SAFETY: both buffers are initialized, the path is NUL-terminated, and
    // the synchronous API retains no pointer.
    let success = unsafe {
        GetVolumeInformationW(
            path_wide.as_ptr(),
            ptr::null_mut(),
            0,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = filesystem
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("mounted filesystem name is unterminated"))?;
    String::from_utf16(&filesystem[..end])
        .map_err(|_| invalid("mounted filesystem name is invalid UTF-16"))
}

fn decode_mount_paths(buffer: &[u16], returned: usize) -> io::Result<Vec<String>> {
    if returned == 0 || returned > buffer.len() {
        return Err(invalid("mount-path list exceeds bounded buffer"));
    }
    let mut paths = Vec::new();
    let mut start = 0usize;
    while start < returned {
        let end = buffer[start..returned]
            .iter()
            .position(|unit| *unit == 0)
            .map(|relative| start + relative)
            .ok_or_else(|| invalid("mount-path list is unterminated"))?;
        if end == start {
            return Ok(paths);
        }
        let path = String::from_utf16(&buffer[start..end])
            .map_err(|_| invalid("mount path is invalid UTF-16"))?;
        if !path.ends_with('\\') || paths.contains(&path) || paths.len() >= 128 {
            return Err(invalid("mount path is malformed or repeated"));
        }
        paths.push(path);
        start = end + 1;
    }
    Err(invalid("mount-path list has no final terminator"))
}

/// Capture every drive-letter or mounted-folder path that Windows currently
/// associates with the exact bound volume. Every returned path is resolved
/// back to the same volume GUID through a separate Mount Manager query.
pub fn capture_mount_paths_general(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<MountPathObservation> {
    probe_general(binding.clone(), events)?;
    capture_mount_paths_for_bound_volume(binding)
}

/// Read-only path enumeration for an actual journal volume. Unlike the
/// source-only probe, this role can be the Windows disk when the typed journal
/// binding explicitly permits additional GPT partitions. This creates no
/// source, replay or write capability.
pub fn capture_mount_paths_for_journal(
    journal: &crate::journal_file::GeneralJournalStorageBinding,
) -> io::Result<MountPathObservation> {
    journal.validate()?;
    let root = format!("{}\\", journal.disk.volume_path()?);
    let role = crate::discovery::Role::Journal {
        allow_additional_partitions: journal.allow_additional_partitions,
    };
    // Each native discovery independently checks the exact volume extent,
    // device/disk geometry, complete GPT non-overlap/identity, attributes,
    // Windows disk, requested role and two identical native snapshots.
    let before = crate::discovery::discover(&root, role)?;
    if before.binding != journal.disk || !before.read_only || !before.observed_twice_unchanged
        || before.source_write_requests != 0 {
        return Err(invalid("journal mount-route binding differs before enumeration"));
    }
    let paths = capture_mount_paths_for_bound_volume(journal.disk.clone())?;
    let after = crate::discovery::discover(&root, role)?;
    if after.binding != journal.disk || !after.read_only || !after.observed_twice_unchanged
        || after.source_write_requests != 0 || before.evidence != after.evidence
        || before.windows_disk_number != after.windows_disk_number
        || before.disk_is_windows_disk != after.disk_is_windows_disk
        || before.filesystem != after.filesystem || before.filesystem_flags != after.filesystem_flags
        || before.volume_serial_low32 != after.volume_serial_low32
        || before.bytes_per_sector != after.bytes_per_sector
        || before.sectors_per_cluster != after.sectors_per_cluster
        || !before.volume_guid_path.eq_ignore_ascii_case(&after.volume_guid_path)
        || paths.binding != after.binding || !paths.all_paths_resolve_to_bound_volume {
        return Err(invalid("journal mount-route identity changed during enumeration"));
    }
    Ok(paths)
}

fn capture_mount_paths_for_bound_volume(binding: GeneralDiskBinding) -> io::Result<MountPathObservation> {
    let root = format!("{}\\", binding.volume_path()?);
    let mut root_wide: Vec<u16> = root.encode_utf16().collect();
    root_wide.push(0);
    let mut buffer = [0u16; 4096];
    let mut returned = 0u32;
    // SAFETY: initialized NUL-terminated input and writable bounded output.
    let success = unsafe {
        GetVolumePathNamesForVolumeNameW(
            root_wide.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut returned,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let paths = decode_mount_paths(&buffer, returned as usize)?;
    for path in &paths {
        let mut path_wide: Vec<u16> = path.encode_utf16().collect();
        path_wide.push(0);
        let mut mapped = [0u16; 1024];
        // SAFETY: initialized NUL-terminated mount path and writable output.
        if unsafe {
            GetVolumeNameForVolumeMountPointW(
                path_wide.as_ptr(),
                mapped.as_mut_ptr(),
                mapped.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mapped_end = mapped
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("resolved mount volume name is unterminated"))?;
        let mapped_name = String::from_utf16(&mapped[..mapped_end])
            .map_err(|_| invalid("resolved mount volume name is invalid UTF-16"))?;
        if layout::guid_bytes(&enumerated_guid(&mapped_name)?)?
            != layout::guid_bytes(&binding.volume_guid)?
        {
            return Err(invalid("mount path resolves to a different volume"));
        }
    }
    Ok(MountPathObservation {
        binding,
        paths,
        all_paths_resolve_to_bound_volume: true,
    })
}

/// Add one original drive letter to a converted ReFS data volume only when
/// the letter is unbound and the volume has no different drive letter. No
/// existing mount point is deleted or reassigned by this operation.
pub fn restore_drive_letter_general(
    binding: GeneralDiskBinding,
    requested: &str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<DriveLetterRestore> {
    let bytes = requested.as_bytes();
    if bytes.len() != 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\'
    {
        return Err(invalid("requested mount point is not a drive-letter root"));
    }
    let bound = rediscover_general_volume_wait(binding, events)?;
    let filesystem = mounted_filesystem_general(bound.clone(), events)?;
    if filesystem != "ReFS" {
        return Err(invalid("drive-letter restoration requires converted ReFS"));
    }
    let before = capture_mount_paths_general(bound.clone(), events)?;
    if before
        .paths
        .iter()
        .any(|path| path.eq_ignore_ascii_case(requested))
    {
        return Ok(DriveLetterRestore {
            requested: requested.into(),
            after: before.clone(),
            before,
            changed: false,
            target_filesystem: filesystem,
        });
    }
    if before.paths.iter().any(|path| {
        let bytes = path.as_bytes();
        bytes.len() == 3 && bytes[1] == b':' && bytes[2] == b'\\'
    }) {
        return Err(invalid(
            "converted ReFS volume already has another drive letter",
        ));
    }
    let mut mount_wide: Vec<u16> = requested.encode_utf16().collect();
    mount_wide.push(0);
    let mut existing = [0u16; 1024];
    // SAFETY: bounded NUL-terminated path and initialized output buffer.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(
            mount_wide.as_ptr(),
            existing.as_mut_ptr(),
            existing.len() as u32,
        )
    } != 0
    {
        let end = existing
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("occupied drive volume name is unterminated"))?;
        let name = String::from_utf16(&existing[..end])
            .map_err(|_| invalid("occupied drive volume name is invalid UTF-16"))?;
        if layout::guid_bytes(&enumerated_guid(&name)?)? != layout::guid_bytes(&bound.volume_guid)?
        {
            return Err(invalid("requested drive letter belongs to another volume"));
        }
        return Err(invalid(
            "drive letter maps to target but was absent from mount-path enumeration",
        ));
    }
    let volume_root = format!("{}\\", bound.volume_path()?);
    let mut volume_wide: Vec<u16> = volume_root.encode_utf16().collect();
    volume_wide.push(0);
    // SAFETY: both paths are NUL-terminated and the synchronous API retains
    // no pointer. The Windows mount manager refuses occupied drive letters.
    if unsafe { SetVolumeMountPointW(mount_wide.as_ptr(), volume_wide.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let after = capture_mount_paths_general(bound, events)?;
    if !after
        .paths
        .iter()
        .any(|path| path.eq_ignore_ascii_case(requested))
    {
        return Err(invalid("new drive-letter mount point was not observed"));
    }
    Ok(DriveLetterRestore {
        requested: requested.into(),
        before,
        after,
        changed: true,
        target_filesystem: filesystem,
    })
}

fn enumerated_guid(name: &str) -> io::Result<String> {
    let guid = name
        .strip_prefix("\\\\?\\Volume{")
        .and_then(|rest| rest.strip_suffix("}\\"))
        .ok_or_else(|| invalid("enumerated volume GUID path differs"))?;
    layout::guid_bytes(guid)?;
    Ok(guid.into())
}

struct VolumeEnumeration(windows_sys::Win32::Foundation::HANDLE);
impl Drop for VolumeEnumeration {
    fn drop(&mut self) {
        // SAFETY: this is the unique live search handle returned by
        // FindFirstVolumeW; Drop runs exactly once.
        unsafe { FindVolumeClose(self.0) };
    }
}

/// Rediscover the volume-GUID path of the same GPT partition after formatting
/// changes the filesystem identity. Every candidate must resolve to the exact
/// bound physical disk/partition; zero or multiple matches are refused.
pub fn rediscover_general_volume(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskBinding> {
    binding.validate()?;
    if current_windows_disk(events)? == binding.disk_number {
        return Err(invalid("current Windows disk is excluded"));
    }
    let disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        false,
        false,
    )?;
    if general_disk_state(&disk, &binding, events)?.disk_attributes != 0 {
        return Err(invalid(
            "general volume rediscovery requires online writable disk",
        ));
    }
    let mut buffer = [0u16; 1024];
    // SAFETY: initialized writable UTF-16 buffer of the declared length.
    let handle = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let _search = VolumeEnumeration(handle);
    let mut matches = Vec::new();
    let mut finished = false;
    for _ in 0..1024 {
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("enumerated volume name is unterminated"))?;
        let name = String::from_utf16(&buffer[..end])
            .map_err(|_| invalid("enumerated volume name is invalid UTF-16"))?;
        if let Ok(guid) = enumerated_guid(&name)
            && let Ok(volume) = device_file(name.trim_end_matches('\\'), false, false)
            && let Ok(extents) = control(
                &volume,
                "rediscovered-volume-extents",
                VOLUME_EXTENTS,
                &[],
                1024,
                events,
            )
            && binding.validate_volume_extent(&extents).is_ok()
        {
            matches.push(guid);
        }
        buffer.fill(0);
        // SAFETY: the search handle and writable buffer remain live for this
        // synchronous enumeration call.
        if unsafe { FindNextVolumeW(handle, buffer.as_mut_ptr(), buffer.len() as u32) } == 0 {
            // SAFETY: the error belongs to the immediately preceding call.
            if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                return Err(io::Error::last_os_error());
            }
            finished = true;
            break;
        }
    }
    if !finished {
        return Err(invalid("volume enumeration exceeded its bounded scan"));
    }
    if matches.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "bound physical partition has no published volume-GUID path",
        ));
    }
    if matches.len() != 1 {
        return Err(invalid("physical partition has multiple volume-GUID paths"));
    }
    let mut updated = binding;
    updated.volume_guid = matches.remove(0);
    probe_general(updated.clone(), events)?;
    Ok(updated)
}

/// Wait at most 15 seconds for a newly online volume interface to appear.
/// Only absence is retried; identity, geometry and duplicate-route failures
/// remain immediate hard refusals.
pub fn rediscover_general_volume_wait(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskBinding> {
    for attempt in 0..60 {
        match rediscover_general_volume(binding.clone(), events) {
            Ok(found) => return Ok(found),
            Err(error) if error.kind() == io::ErrorKind::NotFound && attempt < 59 => {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Err(error) => return Err(error),
        }
    }
    Err(invalid("volume publication retry bound exhausted"))
}

struct AlignedBuffer {
    pointer: NonNull<u8>,
    layout: Layout,
}
impl AlignedBuffer {
    fn new() -> io::Result<Self> {
        let layout = Layout::from_size_align(MAX_IO, GRANULE as usize)
            .map_err(|_| invalid("alignment layout"))?;
        // SAFETY: layout is nonzero and valid. The allocation is owned here and
        // freed once in Drop with the identical layout; every byte is initialized.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| io::Error::other("aligned allocation failed"))?;
        Ok(Self { pointer, layout })
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: self uniquely owns MAX_IO initialized bytes at pointer.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), MAX_IO) }
    }
}
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: pointer/layout came from alloc_zeroed and are released once.
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}

/// Partition-relative stream whose raw file never escapes. Drop does not clear
/// persistent offline/read-only attributes and therefore cannot mount partial data.
pub struct OfflinePartition {
    file: File,
    binding: DiskBinding,
    read_only: bool,
    position: u64,
    buffer: AlignedBuffer,
    policy: Option<WritePolicy>,
    write_poisoned: bool,
    pub native_bytes_read: u64,
    pub native_bytes_written: u64,
    pub native_write_bytes_requested: u64,
}

/// Partition-relative, physically aligned read-only view of a currently
/// mounted dedicated data disk. Concurrent filesystem writes remain possible;
/// callers must not mistake an inspection through this handle for admission.
pub struct GeneralPartitionReader {
    file: File,
    binding: GeneralDiskBinding,
    initial_probe: GeneralProbe,
    position: u64,
    buffer: AlignedBuffer,
    pub native_bytes_read: u64,
}

/// Read-only raw partition access while a mounted data volume is locked.
/// Closing the lock handle releases the lock; no disk attributes are changed.
/// This is a short-lived observation primitive, not persistent conversion
/// exclusion or a certificate that survives process death.
pub struct GeneralLockedPartition {
    reader: GeneralPartitionReader,
    volume_lock: Option<File>,
}

impl GeneralLockedPartition {
    pub fn open(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        let reader = GeneralPartitionReader::open(binding.clone(), events)?;
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let extents = control(
            &volume,
            "policy-lock-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&extents)?;
        control(&volume, "policy-lock-volume", LOCK, &[], 0, events)?;
        Ok(Self {
            reader,
            volume_lock: Some(volume),
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.reader.byte_len()
    }
    pub fn native_bytes_read(&self) -> u64 {
        self.reader.native_bytes_read
    }

    /// Explicitly release the observation lock and verify the original route.
    /// An error also closes the local lock handle during unwinding.
    pub fn finish(mut self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralProbe> {
        let volume = self
            .volume_lock
            .take()
            .ok_or_else(|| invalid("volume lock already released"))?;
        control(&volume, "policy-unlock-volume", UNLOCK, &[], 0, events)?;
        close_file(volume, "close-policy-volume-lock", events)?;
        self.reader.revalidate_route(events)
    }
}

impl Read for GeneralLockedPartition {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reader.read(bytes)
    }
}
impl Seek for GeneralLockedPartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.reader.seek(from)
    }
}

/// Persistently excluded general data partition. This handle has no Write
/// implementation and cannot make the disk mountable.
pub struct GeneralFrozenPartition {
    file: File,
    binding: GeneralDiskBinding,
    frozen_state: GeneralDiskState,
    position: u64,
    buffer: AlignedBuffer,
    native_bytes_read: u64,
    resource_budget: Option<crate::tree_resources::ResourceBudget>,
    freeze_observation: Option<GeneralFreezeObservation>,
    allocation_capture: Option<Arc<()>>,
}

/// Read-only view of an activated, persistently offline journal target. Unlike
/// GeneralFrozenPartition, this does not assert READ_ONLY or immutable bytes:
/// the owning journal writer may change its admitted patch ranges. Callers
/// must bracket operations with state() and independently prove any complement
/// they reuse is unchanged. No Write, mount or disk-attribute setter is exposed.
pub struct GeneralJournalReadView {
    file: File,
    binding: GeneralDiskBinding,
    expected_state: GeneralDiskState,
    position: u64,
    buffer: AlignedBuffer,
    native_bytes_read: u64,
}

impl GeneralJournalReadView {
    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }

    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }

    pub fn native_bytes_read(&self) -> u64 {
        self.native_bytes_read
    }

    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        let actual = general_disk_state(&self.file, &self.binding, events)?;
        if actual != self.expected_state || actual.disk_attributes != OFFLINE {
            return Err(invalid(
                "journal read view lost offline state or device identity",
            ));
        }
        Ok(actual)
    }
}

impl Read for GeneralJournalReadView {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position).min(MAX_IO as u64) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned journal view read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read = self
            .native_bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| invalid("journal read view byte accounting overflow"))?;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short journal view aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Seek for GeneralJournalReadView {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes journal read view"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

/// The point at which a complete pair of native allocation maps was queried.
/// None certifies the allocation graph of the final frozen image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeneralAllocationPhase {
    PostLockFlush,
    PostDismount,
    ProtectedReadOnlyMount,
}

/// Every declared cluster from complete native responses, represented as
/// allocated ranges over the explicit assembled bitmap. Page proofs retain
/// original response hashes/padding separately. No ownership is inferred.
#[derive(Debug, Serialize)]
pub struct GeneralAllocationSnapshot {
    phase: GeneralAllocationPhase,
    legacy: crate::bitmap_layout::AllocationMap,
    metadata_inclusive: crate::bitmap_layout::AllocationMap,
    legacy_response_bytes: usize,
    metadata_response_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy_page_proof: Option<crate::bitmap_paging::Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_page_proof: Option<crate::bitmap_paging::Proof>,
}
impl GeneralAllocationSnapshot {
    pub fn phase(&self) -> GeneralAllocationPhase {
        self.phase
    }
    pub fn legacy(&self) -> &crate::bitmap_layout::AllocationMap {
        &self.legacy
    }
    pub fn metadata_inclusive(&self) -> &crate::bitmap_layout::AllocationMap {
        &self.metadata_inclusive
    }
}

/// Native observations made through one retained volume handle across an
/// actual lock, explicit flush, dismount and persistent exclusion transition.
/// The private in-process token binds it to the returned frozen handle:
/// reopening or deserializing an exported report cannot recreate this witness.
/// A later raw-image proof must independently bind these observations to its
/// image hash and establish the required relationship to its metadata graph.
#[derive(Debug, Serialize)]
pub struct GeneralAllocationFreezeWitness {
    schema_version: u32,
    binding: GeneralDiskBinding,
    pre_lock_state: GeneralDiskState,
    post_lock_state: GeneralDiskState,
    frozen_state: GeneralDiskState,
    volume_extents: Vec<u8>,
    filesystem: String,
    post_lock: GeneralAllocationSnapshot,
    post_dismount: Option<GeneralAllocationSnapshot>,
    post_dismount_error: Option<String>,
    post_lock_equals_frozen_graph: bool,
    raw_write_authority: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_budget: Option<crate::tree_resources::ResourceBudget>,
    #[serde(skip)]
    token: Arc<()>,
}
impl GeneralAllocationFreezeWitness {
    pub fn resource_budget(&self) -> Option<crate::tree_resources::ResourceBudget> {
        self.resource_budget
    }
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }
    pub fn post_lock(&self) -> &GeneralAllocationSnapshot {
        &self.post_lock
    }
    pub fn post_dismount(&self) -> Option<&GeneralAllocationSnapshot> {
        self.post_dismount.as_ref()
    }
    pub fn post_dismount_error(&self) -> Option<&str> {
        self.post_dismount_error.as_deref()
    }
    pub fn frozen_state(&self) -> &GeneralDiskState {
        &self.frozen_state
    }
}

/// Bitmap observations through a physically read-only mounted ReFS volume,
/// followed by restoration of the same frozen handle's exclusion. This does
/// not prove equality to the raw on-disk graph or authorize writes. Issuing
/// this witness invalidates any earlier allocation witness on this handle.
#[derive(Debug, Serialize)]
pub struct GeneralReadonlyAllocationWitness {
    schema_version: u32,
    binding: GeneralDiskBinding,
    frozen_state: GeneralDiskState,
    observed_readonly: GeneralDiskState,
    volume_extents: Vec<u8>,
    filesystem: &'static str,
    snapshot: GeneralAllocationSnapshot,
    raw_graph_verified: bool,
    raw_write_authority: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_budget: Option<crate::tree_resources::ResourceBudget>,
    #[serde(skip)]
    token: Arc<()>,
}
impl GeneralReadonlyAllocationWitness {
    pub fn resource_budget(&self) -> Option<crate::tree_resources::ResourceBudget> {
        self.resource_budget
    }
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }
    pub fn frozen_state(&self) -> &GeneralDiskState {
        &self.frozen_state
    }
    pub fn observed_readonly(&self) -> &GeneralDiskState {
        &self.observed_readonly
    }
    pub fn snapshot(&self) -> &GeneralAllocationSnapshot {
        &self.snapshot
    }
}

const MAX_ALLOCATION_WITNESS_BYTES: usize = 8 * 1024 * 1024;

fn allocation_snapshot(
    phase: GeneralAllocationPhase,
    legacy: &[u8],
    metadata: &[u8],
    partition_bytes: u64,
) -> io::Result<GeneralAllocationSnapshot> {
    Ok(GeneralAllocationSnapshot {
        phase,
        legacy: crate::bitmap_layout::allocated_ranges(legacy, partition_bytes)?,
        metadata_inclusive: crate::bitmap_layout::allocated_ranges(metadata, partition_bytes)?,
        legacy_response_bytes: legacy.len(),
        metadata_response_bytes: metadata.len(),
        legacy_page_proof: None,
        metadata_page_proof: None,
    })
}

/// Per-page events retain actual headers/status. The witness binds those pages'
/// complete response hashes to its separately identified assembled bitmap.
fn allocation_bitmap(
    volume: &File,
    name: &str,
    input: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<crate::bitmap_paging::Capture> {
    let mut assembler = crate::bitmap_paging::Assembler::default();
    let mut page = 0;
    while assembler.response_capacity() != 0 {
        if events.len() >= 128 {
            return Err(invalid("allocation query audit budget exceeded"));
        }
        let page_input = crate::bitmap_paging::page_input(input, assembler.next_lcn())?;
        let query = crate::stream_native::ioctl(
            volume,
            crate::stream_layout::GET_BITMAP,
            &page_input,
            assembler.response_capacity(),
        );
        events.push(NativeEvent {
            operation: format!("{name}-page-{page}-header-only"),
            control_code: query.code,
            input: query.input.clone(),
            succeeded: query.native_error.is_none(),
            native_error: query.native_error,
            output: query.bytes[..query.bytes.len().min(16)].to_vec(),
        });
        if let Some(error) = query
            .native_error
            .filter(|e| *e != crate::bitmap_paging::MORE_DATA)
        {
            return Err(io::Error::from_raw_os_error(error));
        }
        if assembler.push(&query, input)? {
            break;
        }
        page += 1;
    }
    assembler.finish()
}

fn capture_allocation(
    volume: &File,
    phase: GeneralAllocationPhase,
    partition_bytes: u64,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralAllocationSnapshot> {
    capture_allocation_queries(phase, partition_bytes, |name, input| {
        allocation_bitmap(volume, name, input, events)
    })
}

fn capture_allocation_with_resource_profile(
    volume: &File,
    phase: GeneralAllocationPhase,
    partition_bytes: u64,
    resource_profile: Option<crate::attestation::ResourceProfile>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralAllocationSnapshot> {
    if resource_profile.is_none() {
        return capture_allocation(volume, phase, partition_bytes, events);
    }
    let resource_admission = resource_profile
        .map(crate::attestation::ResourceProfile::resource_admission)
        .transpose()?
        .flatten();
    let limits =
        crate::attestation::source_bitmap_limits(resource_profile, partition_bytes / 4096)?;
    let mut observe = |name: &str, input: &[u8]| {
        let result = if resource_admission.is_some() {
            crate::bitmap_observation::Observation::capture_with_limits(
                volume,
                input,
                partition_bytes,
                limits,
            )
        } else {
            crate::bitmap_observation::Observation::capture(volume, input, partition_bytes, true)
        };
        // This is a complete-scan event, not a claim that the first native
        // control call succeeded without ERROR_MORE_DATA.
        let output = match &result {
            Ok(observation) => {
                serde_json::to_vec(&observation.proof()).map_err(io::Error::other)?
            }
            Err(error) => error.to_string().bytes().take(1024).collect(),
        };
        events.push(NativeEvent {
            operation: format!("{name}-streamed-complete"),
            control_code: 0,
            input: input.to_vec(),
            succeeded: result.is_ok(),
            native_error: result.as_ref().err().and_then(io::Error::raw_os_error),
            output,
        });
        result
    };
    let prefix = match phase {
        GeneralAllocationPhase::PostLockFlush => "general-post-lock",
        GeneralAllocationPhase::PostDismount => "general-post-dismount",
        GeneralAllocationPhase::ProtectedReadOnlyMount => "general-protected-readonly",
    };
    let legacy = observe(&format!("{prefix}-legacy-bitmap"), &[0; 8]);
    let mut metadata_input = [0; 16];
    metadata_input[8] = 1;
    let metadata = observe(
        &format!("{prefix}-metadata-inclusive-bitmap"),
        &metadata_input,
    );
    let legacy = legacy?;
    let metadata = metadata?;
    let legacy_proof = legacy.proof();
    let metadata_proof = metadata.proof();
    Ok(GeneralAllocationSnapshot {
        phase,
        legacy: legacy.allocation_map(partition_bytes)?,
        metadata_inclusive: metadata.allocation_map(partition_bytes)?,
        legacy_response_bytes: usize::try_from(
            legacy_proof.streaming.as_ref().unwrap().returned_bytes,
        )
        .map_err(|_| invalid("streamed legacy byte accounting exceeds addressability"))?,
        metadata_response_bytes: usize::try_from(
            metadata_proof.streaming.as_ref().unwrap().returned_bytes,
        )
        .map_err(|_| invalid("streamed metadata byte accounting exceeds addressability"))?,
        legacy_page_proof: Some(legacy_proof),
        metadata_page_proof: Some(metadata_proof),
    })
}

fn capture_allocation_queries(
    phase: GeneralAllocationPhase,
    partition_bytes: u64,
    mut query: impl FnMut(&str, &[u8]) -> io::Result<crate::bitmap_paging::Capture>,
) -> io::Result<GeneralAllocationSnapshot> {
    let (legacy_name, metadata_name) = match phase {
        GeneralAllocationPhase::PostLockFlush => (
            "general-post-lock-legacy-bitmap",
            "general-post-lock-metadata-inclusive-bitmap",
        ),
        GeneralAllocationPhase::PostDismount => (
            "general-post-dismount-legacy-bitmap",
            "general-post-dismount-metadata-inclusive-bitmap",
        ),
        GeneralAllocationPhase::ProtectedReadOnlyMount => (
            "general-protected-readonly-legacy-bitmap",
            "general-protected-readonly-metadata-inclusive-bitmap",
        ),
    };
    // Query the views independently. A legacy-view failure must not hide
    // whether the metadata-inclusive operation is supported at this phase.
    let legacy = query(legacy_name, &[0; 8]);
    let mut extended = [0; 16];
    extended[8] = 1; // GET_VOLUME_BITMAP_FLAG_MASK_METADATA includes metadata.
    let metadata = query(metadata_name, &extended);
    let legacy = legacy?;
    let metadata = metadata?;
    let mut snapshot =
        allocation_snapshot(phase, &legacy.bitmap, &metadata.bitmap, partition_bytes)?;
    snapshot.legacy_response_bytes = legacy.proof.pages.iter().map(|p| p.response_bytes).sum();
    snapshot.metadata_response_bytes = metadata.proof.pages.iter().map(|p| p.response_bytes).sum();
    snapshot.legacy_page_proof = Some(legacy.proof);
    snapshot.metadata_page_proof = Some(metadata.proof);
    Ok(snapshot)
}

fn allocation_refs_filesystem(
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    // Query a filesystem file handle rather than the raw DASD handle used for
    // LOCK and bitmap controls. Close it before requesting exclusive access.
    // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew
    let root = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x0200_0000)
        .open(format!("{}\\", binding.volume_path()?))?;
    let mut filesystem = [0u16; 32];
    // SAFETY: the handle is retained throughout this synchronous query and
    // filesystem is an initialized output buffer with the stated capacity.
    let success = unsafe {
        GetVolumeInformationByHandleW(
            root.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } != 0;
    let error = (!success).then(io::Error::last_os_error);
    events.push(NativeEvent {
        operation: "allocation-mounted-root-filesystem".into(),
        control_code: 0,
        input: vec![],
        succeeded: success,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: filesystem.iter().flat_map(|v| v.to_le_bytes()).collect(),
    });
    close_file(root, "close-allocation-root-before-lock", events)?;
    if let Some(error) = error {
        return Err(error);
    }
    if filesystem[..5] != [b'R' as u16, b'e' as u16, b'F' as u16, b'S' as u16, 0] {
        return Err(invalid("allocation freeze requires a mounted ReFS handle"));
    }
    Ok(())
}

/// Constructed only across an actual native observation, successful volume
/// lock/dismount and persistent exclusion. Reopening cannot recreate it.
#[derive(Debug, Serialize)]
pub struct GeneralFreezeObservation {
    mounted_ntfs: crate::txf_native::GeneralObservation,
    frozen_state: GeneralDiskState,
}
impl GeneralFreezeObservation {
    pub fn mounted_ntfs(&self) -> &crate::txf_native::GeneralObservation {
        &self.mounted_ntfs
    }
}

/// Activated, persistently offline general target. Writes remain unavailable
/// until the caller arms the exact patch set of a durable external journal.
/// Dropping this handle never clears OFFLINE.
pub struct GeneralJournaledPartition {
    inner: GeneralFrozenPartition,
    policy: Option<WritePolicy>,
    paged_policy: Option<HeldPagedWritePolicy>,
    write_poisoned: bool,
    pub native_bytes_written: u64,
    pub native_write_bytes_requested: u64,
}

/// Read-only-at-the-type-boundary recovery owner. The actual physical handle
/// is already open read/write with FILE_SHARE_READ only, so a later qualified
/// transition can consume the same handle without an exclusion gap. This
/// owner exposes no write, policy-arm, mount or conversion capability.
pub struct GeneralExclusiveRecoveryTarget {
    inner: GeneralJournaledPartition,
}

impl GeneralExclusiveRecoveryTarget {
    pub fn reopen(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let path = format!("\\\\.\\PhysicalDrive{}", binding.disk_number);
        // Refuse an online or mismatched disk before taking a deny-writer
        // handle. This read-only preflight stays open through the new gate.
        let preflight = device_file(&path, false, true)?;
        let before = general_disk_state(&preflight, &binding, events)?;
        if before.disk_attributes != OFFLINE {
            return Err(invalid(
                "exclusive recovery target is not persistently offline",
            ));
        }
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(1)
            .custom_flags(0xa000_0000)
            .open(&path);
        events.push(NativeEvent {
            operation: "open-exclusive-recovery-primary-route".into(),
            control_code: 0,
            input: 1u32.to_le_bytes().to_vec(),
            succeeded: opened.is_ok(),
            native_error: opened.as_ref().err().and_then(io::Error::raw_os_error),
            output: b"read-only type boundary; primary route deny-new-writers".to_vec(),
        });
        let file = opened?;
        let frozen_state = general_disk_state(&file, &binding, events)?;
        if frozen_state != before || frozen_state.disk_attributes != OFFLINE {
            return Err(invalid(
                "exclusive recovery target identity or exclusion changed while opening",
            ));
        }
        let probe = device_file(&path, true, true);
        let denied = probe.as_ref().err().and_then(io::Error::raw_os_error)
            == Some(ERROR_SHARING_VIOLATION as i32);
        events.push(NativeEvent {
            operation: "probe-exclusive-recovery-second-writer".into(),
            control_code: 0,
            input: 3u32.to_le_bytes().to_vec(),
            succeeded: probe.is_ok(),
            native_error: probe.as_ref().err().and_then(io::Error::raw_os_error),
            output: b"open-only; no payload read or write requested".to_vec(),
        });
        match probe {
            Ok(other) => {
                close_file(other, "close-unexpected-recovery-writer-probe", events)?;
                return Err(invalid("exclusive recovery route allowed a second writer"));
            }
            Err(error) if !denied => return Err(error),
            Err(_) => (),
        }
        if general_disk_state(&file, &binding, events)? != frozen_state {
            return Err(invalid(
                "exclusive recovery target identity or exclusion changed",
            ));
        }
        close_file(
            preflight,
            "close-exclusive-recovery-readonly-preflight",
            events,
        )?;
        Ok(Self {
            inner: GeneralJournaledPartition {
                inner: GeneralFrozenPartition {
                    resource_budget: None,
                    freeze_observation: None,
                    allocation_capture: None,
                    file,
                    binding,
                    frozen_state,
                    position: 0,
                    buffer: AlignedBuffer::new()?,
                    native_bytes_read: 0,
                },
                policy: None,
                paged_policy: None,
                write_poisoned: false,
                native_bytes_written: 0,
                native_write_bytes_requested: 0,
            },
        })
    }
    pub fn binding(&self) -> &GeneralDiskBinding {
        self.inner.binding()
    }
    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        self.inner.state(events)
    }
    pub fn byte_len(&self) -> u64 {
        self.inner.byte_len()
    }
}
impl Read for GeneralExclusiveRecoveryTarget {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }
}
impl Seek for GeneralExclusiveRecoveryTarget {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.inner.seek(from)
    }
}

/// Private, one-shot native gateway proof. It is constructed only after the
/// same held source, journal, marker state and paged index have been checked.
struct ResourcePolicyAuthority {
    _authenticated_markerless_recovery: (),
}

impl GeneralFrozenPartition {
    /// Bytes owned by each native frozen/read lane's aligned I/O buffer.
    /// Callers using a shared resource ledger can reserve before opening it.
    pub const fn read_buffer_memory_bytes() -> u64 {
        MAX_IO as u64
    }

    /// Pre-count source freeze with an explicit observed resource contract.
    /// Counts and raw pins do not exist yet; this creates no admission facts.
    /// All original NTFS/TxF, lock/dismount and physical route checks execute
    /// through the same implementation as the historical observed freeze.
    pub fn isolate_observed_ntfs_with_resource_budget(
        binding: GeneralDiskBinding,
        budget: crate::tree_resources::ResourceBudget,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        budget.validate()?;
        let mut frozen = Self::isolate_observed_ntfs(binding, events)?;
        frozen.resource_budget = Some(budget);
        Ok(frozen)
    }
    pub fn resource_budget(&self) -> Option<crate::tree_resources::ResourceBudget> {
        self.resource_budget
    }
    pub fn isolate_observed_ntfs(
        binding: GeneralDiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        if mounted_filesystem_general(binding.clone(), events)? != "NTFS" {
            return Err(invalid("observed source freeze requires mounted NTFS"));
        }
        let mounted_ntfs = crate::txf_native::observe_general(binding.clone())?;
        if mounted_ntfs.observation.default_rm_state()
            == crate::txf_native::DefaultRmState::Unresolved
        {
            return Err(invalid(
                "default NTFS resource manager is not idle or inactive",
            ));
        }
        let mut frozen = Self::isolate(binding, events)?;
        frozen.freeze_observation = Some(GeneralFreezeObservation {
            mounted_ntfs,
            frozen_state: frozen.frozen_state.clone(),
        });
        Ok(frozen)
    }

    pub fn freeze_observation(&self) -> Option<&GeneralFreezeObservation> {
        self.freeze_observation.as_ref().filter(|proof| {
            proof.frozen_state == self.frozen_state && proof.mounted_ntfs.binding == self.binding
        })
    }

    /// Freeze a mounted ReFS data partition while retaining complete native
    /// allocation observations from the same locked volume handle. Required
    /// post-lock queries cannot fall back to pre-lock or partial bitmaps.
    /// Post-dismount query failure is retained explicitly as a diagnostic.
    /// This path grants no new raw write or graph-equivalence authority.
    pub fn isolate_with_allocation(
        binding: GeneralDiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<(Self, GeneralAllocationFreezeWitness)> {
        Self::isolate_with_allocation_with_resource_profile(binding, None, events)
    }

    /// Explicit compact streaming observations; the default entry retains its
    /// assembled maps, bounds and witness schema. Neither grants raw writes.
    pub fn isolate_with_allocation_with_resource_profile(
        binding: GeneralDiskBinding,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<(Self, GeneralAllocationFreezeWitness)> {
        binding.validate()?;
        let resource_admission = resource_profile
            .map(crate::attestation::ResourceProfile::resource_admission)
            .transpose()?
            .flatten();
        if resource_profile.is_none()
            && 16 + (binding.identity.partition_bytes / 4096).div_ceil(8)
                > crate::bitmap_paging::MAX_COMPLETE_BYTES as u64
        {
            return Err(invalid("allocation capture exceeds complete bitmap budget"));
        }
        if resource_profile.is_some() {
            let clusters = binding.identity.partition_bytes / 4096;
            crate::bitmap_streaming::Collector::new(
                clusters,
                crate::attestation::source_bitmap_limits(resource_profile, clusters)?,
            )?;
        }
        let before = probe_general(binding.clone(), events)?;
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let pre_lock = general_disk_state(&management, &binding, events)?;
        if pre_lock.disk_attributes != 0
            || pre_lock.device != before.device
            || pre_lock.disk_length != before.disk_length
            || pre_lock.alignment != before.alignment
            || pre_lock.gpt_layout != before.gpt_layout
        {
            return Err(invalid("allocation disk changed before lock"));
        }
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let volume_extents = control(
            &volume,
            "allocation-lock-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&volume_extents)?;
        allocation_refs_filesystem(&binding, events)?;
        let buffer = AlignedBuffer::new()?;
        control(&volume, "allocation-lock-volume", LOCK, &[], 0, events)?;
        // LOCK flushes cached filesystem data; require an additional explicit
        // successful flush before capturing either bitmap through this handle.
        let flushed = volume.sync_all();
        events.push(NativeEvent {
            operation: "allocation-flush-locked-volume".into(),
            control_code: 0,
            input: vec![],
            succeeded: flushed.is_ok(),
            native_error: flushed.as_ref().err().and_then(io::Error::raw_os_error),
            output: vec![],
        });
        flushed?;
        let post_lock = capture_allocation_with_resource_profile(
            &volume,
            GeneralAllocationPhase::PostLockFlush,
            binding.identity.partition_bytes,
            resource_profile,
            events,
        )?;
        let post_lock_state = general_disk_state(&management, &binding, events)?;
        if post_lock_state != pre_lock {
            return Err(invalid("allocation disk changed across lock capture"));
        }
        let locked_extents = control(
            &volume,
            "allocation-locked-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&locked_extents)?;
        if locked_extents != volume_extents {
            return Err(invalid("allocation volume route changed under lock"));
        }
        control(
            &volume,
            "allocation-dismount-volume",
            DISMOUNT,
            &[],
            0,
            events,
        )?;
        let (post_dismount, post_dismount_error) = match capture_allocation_with_resource_profile(
            &volume,
            GeneralAllocationPhase::PostDismount,
            binding.identity.partition_bytes,
            resource_profile,
            events,
        ) {
            Ok(snapshot) => (Some(snapshot), None),
            Err(error) => (
                None,
                Some(format!("post-dismount allocation capture: {error}")),
            ),
        };
        set_attributes(&management, OFFLINE | READ_ONLY, events)?;
        close_file(volume, "close-allocation-volume-lock", events)?;
        let frozen_state = general_disk_state(&management, &binding, events)?;
        let mut expected_frozen = pre_lock.clone();
        expected_frozen.disk_attributes = OFFLINE | READ_ONLY;
        if frozen_state != expected_frozen {
            return Err(invalid("allocation exclusion or disk identity changed"));
        }
        close_file(management, "close-allocation-management", events)?;
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            true,
        )?;
        if general_disk_state(&file, &binding, events)? != frozen_state {
            return Err(invalid(
                "allocation read-only reopen differs after exclusion",
            ));
        }
        let token = Arc::new(());
        let witness = GeneralAllocationFreezeWitness {
            schema_version: if resource_admission.is_some() {
                3
            } else if resource_profile.is_some() {
                2
            } else {
                1
            },
            binding: binding.clone(),
            pre_lock_state: pre_lock,
            post_lock_state,
            frozen_state: frozen_state.clone(),
            volume_extents,
            filesystem: "ReFS".into(),
            post_lock,
            post_dismount,
            post_dismount_error,
            post_lock_equals_frozen_graph: false,
            raw_write_authority: false,
            resource_budget: resource_admission.map(|a| a.budget),
            token: Arc::clone(&token),
        };
        if let Some(admission) = resource_admission {
            admission.validate_constructor_metadata(&witness)?;
        } else {
            let encoded = serde_json::to_vec_pretty(&witness).map_err(io::Error::other)?;
            let witness_limit = if resource_profile.is_some() {
                64 * 1024 * 1024
            } else {
                MAX_ALLOCATION_WITNESS_BYTES
            };
            if encoded.len() > witness_limit {
                return Err(invalid("allocation witness exceeds bounded output profile"));
            }
        }
        Ok((
            Self {
                file,
                binding,
                frozen_state,
                position: 0,
                buffer,
                native_bytes_read: 0,
                resource_budget: resource_admission.map(|a| a.budget),
                freeze_observation: None,
                allocation_capture: Some(token),
            },
            witness,
        ))
    }

    fn owns_allocation_witness(&self, witness: &GeneralAllocationFreezeWitness) -> bool {
        self.allocation_capture
            .as_ref()
            .is_some_and(|token| Arc::ptr_eq(token, &witness.token))
            && self.binding == witness.binding
            && self.frozen_state == witness.frozen_state
            && self.frozen_state.disk_attributes == OFFLINE | READ_ONLY
            && witness
                .resource_budget
                .is_none_or(|budget| self.resource_budget == Some(budget))
    }

    /// Recheck this exact live frozen handle and the in-process capture token.
    /// This does not prove that either captured map equals the frozen graph.
    pub fn validate_allocation_witness(
        &self,
        witness: &GeneralAllocationFreezeWitness,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if !self.owns_allocation_witness(witness) {
            return Err(invalid(
                "allocation witness belongs to another freeze handle",
            ));
        }
        if self.state(events)? != witness.frozen_state {
            return Err(invalid("allocation witness frozen device state changed"));
        }
        Ok(())
    }

    /// Lock/dismount and persistently exclude a bound dedicated data disk.
    /// Dropping the returned handle does not bring the disk online.
    pub fn isolate(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        let before = probe_general(binding.clone(), events)?;
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let pre_lock = general_disk_state(&management, &binding, events)?;
        if pre_lock.disk_attributes != 0
            || pre_lock.device != before.device
            || pre_lock.disk_length != before.disk_length
            || pre_lock.alignment != before.alignment
            || pre_lock.gpt_layout != before.gpt_layout
        {
            return Err(invalid("general disk changed before lock"));
        }
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let extents = control(
            &volume,
            "general-lock-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&extents)?;
        let buffer = AlignedBuffer::new()?;
        control(&volume, "general-lock-volume", LOCK, &[], 0, events)?;
        control(&volume, "general-dismount-volume", DISMOUNT, &[], 0, events)?;
        set_attributes(&management, OFFLINE | READ_ONLY, events)?;
        close_file(volume, "close-general-volume-lock", events)?;
        let frozen = general_disk_state(&management, &binding, events)?;
        if frozen.disk_attributes != OFFLINE | READ_ONLY
            || frozen.device != pre_lock.device
            || frozen.disk_length != pre_lock.disk_length
            || frozen.alignment != pre_lock.alignment
            || frozen.gpt_layout != pre_lock.gpt_layout
        {
            return Err(invalid("general disk exclusion or identity changed"));
        }
        close_file(management, "close-general-management", events)?;
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            true,
        )?;
        if general_disk_state(&file, &binding, events)? != frozen {
            return Err(invalid("general read-only reopen differs after exclusion"));
        }
        Ok(Self {
            file,
            binding,
            frozen_state: frozen,
            position: 0,
            buffer,
            native_bytes_read: 0,
            resource_budget: None,
            freeze_observation: None,
            allocation_capture: None,
        })
    }

    pub fn reopen(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            true,
        )?;
        let frozen_state = general_disk_state(&file, &binding, events)?;
        if frozen_state.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "general disk is not persistently offline and read-only",
            ));
        }
        Ok(Self {
            file,
            binding,
            frozen_state,
            position: 0,
            buffer: AlignedBuffer::new()?,
            native_bytes_read: 0,
            resource_budget: None,
            freeze_observation: None,
            allocation_capture: None,
        })
    }

    /// Recover from process death during native observation. An already
    /// excluded disk is reopened unchanged. A still-mounted READ_ONLY disk is
    /// locked, dismounted and returned to persistent OFFLINE|READ_ONLY. Any
    /// writable, foreign or changed disk is refused.
    pub fn restore_exclusion(
        binding: GeneralDiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<(Self, bool)> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            false,
        )?;
        let before = general_disk_state(&management, &binding, events)?;
        if before.disk_attributes == OFFLINE | READ_ONLY {
            close_file(management, "close-general-already-excluded", events)?;
            return Ok((Self::reopen(binding, events)?, false));
        }
        if before.disk_attributes != READ_ONLY {
            return Err(invalid(
                "general observation recovery requires read-only disk",
            ));
        }
        let volume = device_file(&binding.volume_path()?, false, false)?;
        let extents = control(
            &volume,
            "general-recovery-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&extents)?;
        control(
            &volume,
            "general-recovery-lock-volume",
            LOCK,
            &[],
            0,
            events,
        )?;
        control(
            &volume,
            "general-recovery-dismount-volume",
            DISMOUNT,
            &[],
            0,
            events,
        )?;
        set_attributes(&management, OFFLINE | READ_ONLY, events)?;
        close_file(volume, "close-general-recovery-volume", events)?;
        let mut expected = before;
        expected.disk_attributes = OFFLINE | READ_ONLY;
        if general_disk_state(&management, &binding, events)? != expected {
            return Err(invalid(
                "general exclusion recovery changed storage identity",
            ));
        }
        close_file(management, "close-general-recovery-management", events)?;
        let restored = Self::reopen(binding, events)?;
        if restored.frozen_state != expected {
            return Err(invalid("general exclusion recovery reopen differs"));
        }
        Ok((restored, true))
    }

    pub fn revalidate_route(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if general_disk_state(&self.file, &self.binding, events)? != self.frozen_state {
            return Err(invalid("general frozen route changed"));
        }
        Ok(())
    }

    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }

    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }

    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        let state = general_disk_state(&self.file, &self.binding, events)?;
        if state != self.frozen_state {
            return Err(invalid("general frozen route changed"));
        }
        Ok(state)
    }

    pub fn native_bytes_read(&self) -> u64 {
        self.native_bytes_read
    }

    /// Abort before journal activation. A complete hash of the unchanged
    /// offline/read-only partition is required before the original NTFS disk
    /// can be made writable and mountable again.
    pub fn bring_original_online_unchanged(
        mut self,
        expected_sha256: &str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if expected_sha256.len() != 64
            || !expected_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid original NTFS SHA-256 pin"));
        }
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("original source is not offline and read-only"));
        }
        self.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; MAX_IO];
        let mut left = self.byte_len();
        while left != 0 {
            let count = left.min(MAX_IO as u64) as usize;
            self.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            left -= count as u64;
        }
        if hex::encode(hash.finalize()) != expected_sha256 || self.state(events)? != before {
            return Err(invalid("original source bytes or exclusion changed"));
        }
        let binding = self.binding.clone();
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &binding, events)? != before {
            return Err(invalid("original source control-handle route differs"));
        }
        close_file(self.file, "close-original-source-before-online", events)?;
        set_attributes(&management, 0, events)?;
        control(
            &management,
            "refresh-original-source-online-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            events,
        )?;
        let mut expected = before;
        expected.disk_attributes = 0;
        if general_disk_state(&management, &binding, events)? != expected {
            return Err(invalid(
                "original NTFS online transition changed storage identity",
            ));
        }
        close_file(
            management,
            "close-original-source-online-management",
            events,
        )
    }

    /// Temporarily publish only a READ_ONLY NTFS view for native semantic
    /// collection, then restore OFFLINE|READ_ONLY before returning. A process
    /// death can leave a write-protected mounted view requiring explicit
    /// recovery; no automatic writable fallback exists.
    pub fn observe_ntfs_files(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveNtfsObservation> {
        self.observe_ntfs_files_with_passes(request, events, false, false)
    }

    /// Keep the original two content passes and additionally observe VSS inside
    /// the existing physically READ_ONLY view. The caller must separately bind
    /// a fresh pre-freeze hosted-storage catalog; this adds no extra mount.
    pub fn observe_ntfs_files_with_vss(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveNtfsObservation> {
        self.observe_ntfs_files_with_passes(request, events, false, true)
    }

    /// As `observe_ntfs_files`, reading each stream's content once. Only for a
    /// caller that brackets the whole observation over this frozen source.
    pub fn observe_ntfs_files_single_content_pass(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveNtfsObservation> {
        self.observe_ntfs_files_with_passes(request, events, true, false)
    }

    /// Observe VSS inside the existing physically READ_ONLY native view.
    /// Offline volume GUIDs cannot be queried reliably by VSS. This adds no
    /// extra publication/mount and restores persistent exclusion before return.
    pub fn observe_ntfs_files_single_content_pass_with_vss(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveNtfsObservation> {
        self.observe_ntfs_files_with_passes(request, events, true, true)
    }

    fn observe_ntfs_files_with_passes(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
        single_content_pass: bool,
        require_vss: bool,
    ) -> io::Result<GeneralLiveNtfsObservation> {
        let collected =
            self.observe_ntfs_files_with_collector(request, events, require_vss, |request| {
                if single_content_pass {
                    crate::attestation_native::collect_file_metadata_single_content_pass(request)
                } else {
                    crate::attestation_native::collect_file_metadata(request)
                }
            })?;
        Ok(GeneralLiveNtfsObservation {
            report: collected.domain,
            txf: collected.txf,
            txf_error: collected.txf_error,
            vss_observation: collected.vss_observation,
            before: collected.before,
            after: collected.after,
        })
    }

    /// Complete paged source observation through the same physical READ_ONLY
    /// lease. No report rows are rehydrated into a whole collection. The file
    /// must be on ordinary metadata storage outside both conversion devices.
    pub fn observe_ntfs_files_paged(
        &mut self,
        request: &crate::attestation::Request,
        path: &std::path::Path,
        budget: crate::observation_pages::NativeObservationBudget,
        single_content_pass: bool,
        require_vss: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLivePagedNtfsObservation> {
        budget.validate()?;
        if let Some(admission) = request
            .resource_profile
            .map(crate::attestation::ResourceProfile::resource_admission)
            .transpose()?
            .flatten()
        {
            if self.resource_budget != Some(admission.budget) {
                return Err(invalid(
                    "native source resource budget differs from original pre-count frozen owner",
                ));
            }
        }
        let collected =
            self.observe_ntfs_files_with_collector(request, events, require_vss, |request| {
                crate::attestation_native::collect_file_metadata_paged(
                    request,
                    path,
                    budget,
                    single_content_pass,
                )
            })?;
        Ok(GeneralLivePagedNtfsObservation {
            domain: collected.domain,
            txf: collected.txf,
            txf_error: collected.txf_error,
            vss_observation: collected.vss_observation,
            before: collected.before,
            after: collected.after,
        })
    }

    /// Page-backed selectors are read from the same retained complete raw
    /// metadata owner, one record at a time. The actual selectors are retained
    /// beside their native rows in the authenticated observation file.
    pub fn observe_ntfs_files_paged_domain(
        &mut self,
        selectors: &impl crate::attestation::NativeRequestDomain,
        path: &std::path::Path,
        budget: crate::observation_pages::NativeObservationBudget,
        single_content_pass: bool,
        require_vss: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLivePagedNtfsObservation> {
        crate::attestation::validate_native_request_domain(selectors)?;
        let request = selectors.header();
        if !request.has_paged_selectors() {
            return Err(invalid("paged selector entry requires request7/8"));
        }
        let admission = request
            .resource_profile
            .unwrap()
            .resource_admission()?
            .ok_or_else(|| invalid("paged selector resource admission absent"))?;
        if self.resource_budget != Some(admission.budget) {
            return Err(invalid(
                "native paged source resource budget differs from original frozen owner",
            ));
        }
        let collected =
            self.observe_ntfs_files_with_collector(request, events, require_vss, |request| {
                let _ = request;
                crate::attestation_native::collect_file_metadata_paged_domain(
                    selectors,
                    path,
                    budget,
                    single_content_pass,
                )
            })?;
        selectors.revalidate()?;
        Ok(GeneralLivePagedNtfsObservation {
            domain: collected.domain,
            txf: collected.txf,
            txf_error: collected.txf_error,
            vss_observation: collected.vss_observation,
            before: collected.before,
            after: collected.after,
        })
    }

    /// Protected paged NTFS collection with the caller's actual shared RAM
    /// accountant retained by the resulting native observation domain.
    pub fn observe_ntfs_files_paged_domain_with_memory(
        &mut self,
        selectors: &impl crate::attestation::NativeRequestDomain,
        path: &std::path::Path,
        budget: crate::observation_pages::NativeObservationBudget,
        single_content_pass: bool,
        require_vss: bool,
        memory: Arc<dyn crate::shadow_native::report_memory::ReportMemoryAccountant>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLivePagedNtfsObservation> {
        crate::attestation::validate_native_request_domain(selectors)?;
        let request = selectors.header();
        if !request.has_paged_selectors() {
            return Err(invalid("paged selector entry requires request7/8"));
        }
        let admission = request
            .resource_profile
            .unwrap()
            .resource_admission()?
            .ok_or_else(|| invalid("paged selector resource admission absent"))?;
        if self.resource_budget != Some(admission.budget) {
            return Err(invalid(
                "native paged source resource budget differs from original frozen owner",
            ));
        }
        let collected =
            self.observe_ntfs_files_with_collector(request, events, require_vss, |request| {
                let _ = request;
                crate::attestation_native::collect_file_metadata_paged_domain_with_memory(
                    selectors,
                    path,
                    budget,
                    single_content_pass,
                    memory,
                )
            })?;
        selectors.revalidate()?;
        Ok(GeneralLivePagedNtfsObservation {
            domain: collected.domain,
            txf: collected.txf,
            txf_error: collected.txf_error,
            vss_observation: collected.vss_observation,
            before: collected.before,
            after: collected.after,
        })
    }

    fn observe_ntfs_files_with_collector<T: crate::attestation::NativeObservationDomain>(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
        require_vss: bool,
        collector: impl FnOnce(&crate::attestation::Request) -> io::Result<T>,
    ) -> io::Result<CollectedGeneralNtfs<T>> {
        request.validate()?;
        if !matches!(request.schema_version, 2 | 3 | 4 | 5 | 6 | 7 | 8)
            || request.disk_number != self.binding.disk_number
            || request.volume != format!("{}\\", self.binding.volume_path()?)
            || request.partition_offset != self.binding.identity.partition_offset
            || request.partition_length != self.byte_len()
        {
            return Err(invalid("general native observer binding differs"));
        }
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("general source is not persistently excluded"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &self.binding, events)? != before {
            return Err(invalid("general observer control-handle route differs"));
        }
        let mut lease = ReadonlyObservationLease {
            file: &management,
            events,
            restoration_attempted: false,
        };
        set_attributes(lease.file, READ_ONLY, lease.events)?;
        control(
            lease.file,
            "refresh-general-readonly-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            lease.events,
        )?;
        let mut ready = false;
        for _ in 0..60 {
            if attributes(lease.file, lease.events)? != READ_ONLY {
                return Err(invalid(
                    "general source read-only observation state changed",
                ));
            }
            match device_file(&self.binding.volume_path()?, false, false) {
                Ok(volume) => {
                    drop(volume);
                    ready = true;
                    break;
                }
                Err(error) if matches!(error.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                    std::thread::sleep(std::time::Duration::from_millis(250))
                }
                Err(error) => return Err(error),
            }
        }
        if !ready {
            return Err(invalid(
                "general read-only volume was not published within 15 seconds",
            ));
        }
        let collected = collector(request);
        let (txf, txf_error) = match crate::txf_native::observe_general(self.binding.clone()) {
            Ok(observation) => (Some(observation), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let vss_observation = (|| -> io::Result<_> {
            if !require_vss {
                return Ok(None);
            }
            if attributes(lease.file, lease.events)? != READ_ONLY {
                return Err(invalid(
                    "source lost physical write protection before VSS observation",
                ));
            }
            let observation = crate::vss_observation::observe_snapshot_presence(&request.volume)?;
            observation.require_observed_snapshot_absence()?;
            if attributes(lease.file, lease.events)? != READ_ONLY {
                return Err(invalid(
                    "source lost physical write protection during VSS observation",
                ));
            }
            Ok(Some(observation))
        })();
        let restored = lease.finish();
        drop(lease);
        restored?;
        let after = self.state(events)?;
        if before != after {
            return Err(invalid(
                "general source exclusion changed during native observation",
            ));
        }
        let domain = collected?;
        let report = domain.header();
        let vss_observation = vss_observation?;
        if report.request != *request
            || report.conversion_qualified
            || report.schema_version
                != match request.schema_version {
                    8 => 16,
                    7 => 15,
                    6 => 14,
                    5 => 13,
                    4 => 12,
                    3 => 11,
                    _ => 7,
                }
        {
            return Err(invalid("general native source report profile differs"));
        }
        if request.schema_version >= 3 {
            crate::attestation::validate_domain_resources(&domain)?;
        }
        Ok(CollectedGeneralNtfs {
            domain,
            txf,
            txf_error,
            vss_observation,
            before,
            after,
        })
    }

    /// Query both complete allocation views through a physically READ_ONLY
    /// mounted ReFS handle, then restore OFFLINE|READ_ONLY exclusion. This is
    /// not a post-lock query and does not establish raw-graph equivalence.
    pub fn observe_refs_allocation_readonly(
        &mut self,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralReadonlyAllocationWitness> {
        self.binding.validate()?;
        let resource_admission = resource_profile
            .map(crate::attestation::ResourceProfile::resource_admission)
            .transpose()?
            .flatten();
        if let Some(admission) = resource_admission {
            if self.resource_budget != Some(admission.budget) {
                return Err(invalid(
                    "protected allocation resource budget differs from original frozen owner",
                ));
            }
        }
        let length = self.binding.identity.partition_bytes;
        let maximum = resource_profile
            .map_or(crate::general_layout::MAX_LIVE_PARTITION_BYTES, |profile| {
                profile.maximum_partition_bytes()
            });
        if length > maximum {
            return Err(invalid("protected allocation exceeds resource profile"));
        }
        if resource_profile.is_none()
            && 16 + (length / 4096).div_ceil(8) > crate::bitmap_paging::MAX_COMPLETE_BYTES as u64
        {
            return Err(invalid(
                "protected allocation exceeds complete bitmap budget",
            ));
        }
        if resource_profile.is_some() {
            let clusters = length / 4096;
            crate::bitmap_streaming::Collector::new(
                clusters,
                crate::attestation::source_bitmap_limits(resource_profile, clusters)?,
            )?;
        }
        // The lease owns `events` during the callback. Keep its bitmap and
        // identity events separate and publish them even when capture fails.
        let mut callback_events = Vec::new();
        let captured = self.with_readonly_refs_binding_observation(events, |protected| {
            let state = general_disk_state(
                protected.management,
                protected.binding,
                &mut callback_events,
            )?;
            if state != *protected.expected_state || state.disk_attributes != READ_ONLY {
                return Err(invalid(
                    "protected allocation disk is not physically read-only",
                ));
            }
            let extents = control(
                protected.volume,
                "protected-allocation-volume-extents-before",
                VOLUME_EXTENTS,
                &[],
                1024,
                &mut callback_events,
            )?;
            protected.binding.validate_volume_extent(&extents)?;
            allocation_refs_filesystem(protected.binding, &mut callback_events)?;
            let snapshot = capture_allocation_with_resource_profile(
                protected.volume,
                GeneralAllocationPhase::ProtectedReadOnlyMount,
                length,
                resource_profile,
                &mut callback_events,
            )?;
            let after_extents = control(
                protected.volume,
                "protected-allocation-volume-extents-after",
                VOLUME_EXTENTS,
                &[],
                1024,
                &mut callback_events,
            )?;
            protected.binding.validate_volume_extent(&after_extents)?;
            allocation_refs_filesystem(protected.binding, &mut callback_events)?;
            let after = general_disk_state(
                protected.management,
                protected.binding,
                &mut callback_events,
            )?;
            if after != state || after_extents != extents {
                return Err(invalid(
                    "protected allocation identity changed during capture",
                ));
            }
            Ok((snapshot, extents))
        });
        events.extend(callback_events);
        let ((snapshot, volume_extents), before, observed_readonly, after) = captured?;
        if before != after || after != self.state(events)? {
            return Err(invalid("protected allocation exclusion changed"));
        }
        let token = Arc::new(());
        let witness = GeneralReadonlyAllocationWitness {
            schema_version: if resource_admission.is_some() {
                3
            } else if resource_profile.is_some() {
                2
            } else {
                1
            },
            binding: self.binding.clone(),
            frozen_state: after,
            observed_readonly,
            volume_extents,
            filesystem: "ReFS",
            snapshot,
            raw_graph_verified: false,
            raw_write_authority: false,
            resource_budget: resource_admission.map(|a| a.budget),
            token: Arc::clone(&token),
        };
        if let Some(admission) = resource_admission {
            admission.validate_constructor_metadata(&witness)?;
        } else {
            let encoded = serde_json::to_vec_pretty(&witness).map_err(io::Error::other)?;
            let witness_limit = if resource_profile.is_some() {
                64 * 1024 * 1024
            } else {
                MAX_ALLOCATION_WITNESS_BYTES
            };
            if encoded.len() > witness_limit {
                return Err(invalid(
                    "protected allocation witness exceeds output profile",
                ));
            }
        }
        // A new in-process capture replaces any earlier token for this handle.
        self.allocation_capture = Some(token);
        Ok(witness)
    }

    /// Revalidate only the originating live handle and exclusion, not the
    /// equivalence of its mounted bitmap to the frozen raw allocation graph.
    pub fn validate_readonly_allocation_witness(
        &self,
        witness: &GeneralReadonlyAllocationWitness,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let mut expected_readonly = self.frozen_state.clone();
        expected_readonly.disk_attributes = READ_ONLY;
        if !self
            .allocation_capture
            .as_ref()
            .is_some_and(|token| Arc::ptr_eq(token, &witness.token))
            || self.binding != witness.binding
            || self.frozen_state != witness.frozen_state
            || self.frozen_state.disk_attributes != OFFLINE | READ_ONLY
            || witness.observed_readonly != expected_readonly
            || witness.snapshot.phase != GeneralAllocationPhase::ProtectedReadOnlyMount
            || witness
                .resource_budget
                .is_some_and(|budget| self.resource_budget != Some(budget))
        {
            return Err(invalid(
                "protected allocation witness belongs to another frozen handle",
            ));
        }
        if self.state(events)? != witness.frozen_state {
            return Err(invalid(
                "protected allocation witness frozen device state changed",
            ));
        }
        Ok(())
    }

    /// Verify all admitted ReFS semantics through an actual retained
    /// READ_ONLY volume handle, then restore OFFLINE|READ_ONLY before returning.
    /// The opaque return value is issued only after strict native verification
    /// and a checked exclusion transition. No post-LOCK bitmap is required.
    pub fn observe_refs_files(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &[crate::shadow_native::Input<'_>],
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsObservation> {
        self.observe_refs_files_with_resource_profile(pair, input, same_security, None, events)
    }

    /// Strictly observe the same protected ReFS volume with an explicitly
    /// selected resource profile. It grants no source or write authority.
    pub fn observe_refs_files_with_resource_profile(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &[crate::shadow_native::Input<'_>],
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsObservation> {
        let (report, before, observed_readonly, after) =
            self.with_readonly_refs_observation(&pair, resource_profile, events, |protected| {
                crate::shadow_native::verify_general_ordinary_readonly_with_resource_profile(
                    pair.clone(),
                    input,
                    &same_security,
                    protected,
                    resource_profile,
                )
            })?;
        Ok(GeneralLiveRefsObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    /// Observe metadata, exact namespace, file IDs, complete retrieval maps,
    /// storage-validity and disabled integrity under the same native protection
    /// as the complete verifier. Placeholder file contents are never read.
    /// Caller must bracket this observation with independent raw-image hashes.
    pub fn observe_refs_layout_with_resource_profile(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &[crate::shadow_native::Input<'_>],
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsLayoutObservation> {
        let (report, before, observed_readonly, after) =
            self.with_readonly_refs_observation(&pair, resource_profile, events, |protected| {
                crate::shadow_native::observe_general_layout_readonly_with_resource_profile(
                    pair.clone(),
                    input,
                    &same_security,
                    protected,
                    resource_profile,
                )
            })?;
        Ok(GeneralLiveRefsLayoutObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    /// Composite-only layout observation additionally hashes initialized
    /// suffixes against source-derived expectations. Full-cluster placeholder
    /// prefixes remain unread. The zero-payload layout API is unchanged.
    pub fn observe_refs_layout_residuals_with_resource_profile(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &[crate::shadow_native::Input<'_>],
        residuals: &[crate::shadow_native::LayoutResidualExpectation],
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsLayoutObservation> {
        let (report, before, observed_readonly, after) = self.with_readonly_refs_observation(
            &pair,
            resource_profile,
            events,
            |protected| {
                crate::shadow_native::observe_general_layout_residuals_readonly_with_resource_profile(
                    pair.clone(), input, residuals, &same_security, protected, resource_profile,
                )
            },
        )?;
        Ok(GeneralLiveRefsLayoutObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    pub fn observe_refs_files_domain(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsObservation> {
        if let Some(admission) = resource_profile
            .map(crate::attestation::ResourceProfile::count_admission)
            .transpose()?
            .flatten()
            .filter(|value| value.requires_paged_metadata())
        {
            input.require_paged_metadata(
                admission.expected_page_budget()?,
                u64::from(admission.maximum_expected_tree_bytes),
            )?;
        }

        let (report, before, observed_readonly, after) =
            self.with_readonly_refs_observation(&pair, resource_profile, events, |protected| {
                crate::shadow_native::verify_general_ordinary_readonly_domain(
                    pair.clone(),
                    input,
                    &same_security,
                    protected,
                    resource_profile,
                )
            })?;
        Ok(GeneralLiveRefsObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    pub fn observe_refs_layout_domain(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsLayoutObservation> {
        if let Some(admission) = resource_profile
            .map(crate::attestation::ResourceProfile::count_admission)
            .transpose()?
            .flatten()
            .filter(|value| value.requires_paged_metadata())
        {
            input.require_paged_metadata(
                admission.expected_page_budget()?,
                u64::from(admission.maximum_expected_tree_bytes),
            )?;
        }

        let (report, before, observed_readonly, after) =
            self.with_readonly_refs_observation(&pair, resource_profile, events, |protected| {
                crate::shadow_native::observe_general_layout_readonly_domain(
                    pair.clone(),
                    input,
                    &same_security,
                    protected,
                    resource_profile,
                )
            })?;
        Ok(GeneralLiveRefsLayoutObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    pub fn observe_refs_layout_residuals_domain(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        residuals: &[crate::shadow_native::LayoutResidualExpectation],
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsLayoutObservation> {
        if let Some(admission) = resource_profile
            .map(crate::attestation::ResourceProfile::count_admission)
            .transpose()?
            .flatten()
            .filter(|value| value.requires_paged_metadata())
        {
            input.require_paged_metadata(
                admission.expected_page_budget()?,
                u64::from(admission.maximum_expected_tree_bytes),
            )?;
        }

        let (report, before, observed_readonly, after) =
            self.with_readonly_refs_observation(&pair, resource_profile, events, |protected| {
                crate::shadow_native::observe_general_layout_residuals_readonly_domain(
                    pair.clone(),
                    input,
                    residuals,
                    &same_security,
                    protected,
                    resource_profile,
                )
            })?;
        Ok(GeneralLiveRefsLayoutObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    pub fn observe_refs_layout_residuals_paged_domain(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        provider: &impl crate::layout_residual_pages::LayoutResidualProvider,
        result_path: &std::path::Path,
        result_budget: crate::metadata_pages::PageBudget,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsLayoutObservation> {
        let admission = resource_profile
            .ok_or_else(|| invalid("paged residual observation needs resource profile"))?
            .resource_admission()?
            .ok_or_else(|| invalid("paged residual observation requires V4"))?;
        input.require_resource_metadata(admission)?;
        provider.revalidate()?;
        let (report, before, observed_readonly, after) =
            self.with_readonly_refs_observation(&pair, resource_profile, events, |protected| {
                crate::shadow_native::observe_general_layout_residuals_paged_readonly_domain(
                    pair.clone(),
                    input,
                    provider,
                    result_path,
                    result_budget,
                    &same_security,
                    protected,
                    resource_profile,
                )
            })?;
        provider.revalidate()?;
        Ok(GeneralLiveRefsLayoutObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    /// Paged protected observation with the caller's live shared RAM
    /// accountant. The original non-accounted entry remains unchanged.
    pub fn observe_refs_layout_residuals_paged_domain_with_memory(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        provider: &impl crate::layout_residual_pages::LayoutResidualProvider,
        result_path: &std::path::Path,
        result_budget: crate::metadata_pages::PageBudget,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        memory: &dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsLayoutObservation> {
        let admission = resource_profile
            .ok_or_else(|| invalid("paged residual observation needs resource profile"))?
            .resource_admission()?
            .ok_or_else(|| invalid("paged residual observation requires V4"))?;
        input.require_resource_metadata(admission)?;
        provider.revalidate()?;
        let (report, before, observed_readonly, after) =
            self.with_readonly_refs_observation(&pair, resource_profile, events, |protected| {
                crate::shadow_native::observe_general_layout_residuals_paged_readonly_domain_with_memory(
                    pair.clone(), input, provider, result_path, result_budget, &same_security,
                    protected, resource_profile, memory,
                )
            })?;
        provider.revalidate()?;
        Ok(GeneralLiveRefsLayoutObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    fn with_readonly_refs_observation<T>(
        &mut self,
        pair: &crate::general_layout::GeneralSourceShadowBinding,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        events: &mut Vec<NativeEvent>,
        observe: impl FnOnce(&GeneralReadonlyRefsVolume<'_>) -> io::Result<T>,
    ) -> io::Result<(T, GeneralDiskState, GeneralDiskState, GeneralDiskState)> {
        pair.validate_with_resource_profile(resource_profile)?;
        if pair.shadow != self.binding {
            return Err(invalid(
                "protected ReFS observation is not the frozen shadow",
            ));
        }
        self.with_readonly_refs_binding_observation(events, observe)
    }

    /// Physical READ_ONLY lease shared by pair-bound observers and this
    /// binding-only allocation probe. The caller validates its own profile.
    fn with_readonly_refs_binding_observation<T>(
        &mut self,
        events: &mut Vec<NativeEvent>,
        observe: impl FnOnce(&GeneralReadonlyRefsVolume<'_>) -> io::Result<T>,
    ) -> io::Result<(T, GeneralDiskState, GeneralDiskState, GeneralDiskState)> {
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "protected ReFS observation requires frozen exclusion",
            ));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &self.binding, events)? != before {
            return Err(invalid("protected ReFS control-handle route differs"));
        }
        let mut expected_readonly = before.clone();
        expected_readonly.disk_attributes = READ_ONLY;
        let mut lease = ReadonlyObservationLease {
            file: &management,
            events,
            restoration_attempted: false,
        };
        let collected = (|| {
            set_attributes(lease.file, READ_ONLY, lease.events)?;
            control(
                lease.file,
                "refresh-protected-readonly-refs-properties",
                UPDATE_PROPERTIES,
                &[],
                0,
                lease.events,
            )?;
            let mut volume = None;
            for _ in 0..60 {
                if attributes(lease.file, lease.events)? != READ_ONLY {
                    return Err(invalid("protected ReFS disk lost its read-only state"));
                }
                match device_file(&self.binding.volume_path()?, false, false) {
                    Ok(file) => {
                        volume = Some(file);
                        break;
                    }
                    Err(error) if matches!(error.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                    Err(error) => return Err(error),
                }
            }
            let volume = volume.ok_or_else(|| {
                invalid("protected read-only ReFS volume was not published within 15 seconds")
            })?;
            if general_disk_state(lease.file, &self.binding, lease.events)? != expected_readonly {
                return Err(invalid("protected ReFS identity changed while publishing"));
            }
            let protected = GeneralReadonlyRefsVolume {
                binding: &self.binding,
                management: lease.file,
                volume: &volume,
                expected_state: &expected_readonly,
            };
            let observed = observe(&protected);
            // All native file handles close before the persistent offline
            // transition; the retained read-only volume route closes once.
            close_file(
                volume,
                "close-protected-refs-observation-volume",
                lease.events,
            )?;
            observed
        })();
        let restored = lease.finish();
        drop(lease);
        restored?;
        let after = self.state(events)?;
        if before != after {
            return Err(invalid(
                "protected ReFS exclusion changed during observation",
            ));
        }
        Ok((collected?, before, expected_readonly, after))
    }

    /// Transition only an unchanged OFFLINE|READ_ONLY source to OFFLINE. The
    /// caller must first persist and verify its external recovery journal.
    pub fn activate_for_journal(
        mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralJournaledPartition> {
        self.state(events)?;
        if self.frozen_state.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "general journal activation requires frozen read-only disk",
            ));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &self.binding, events)? != self.frozen_state {
            return Err(invalid("general activation control-handle route differs"));
        }
        set_attributes(&management, OFFLINE, events)?;
        let writable = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            true,
        )?;
        let mut expected = self.frozen_state.clone();
        expected.disk_attributes = OFFLINE;
        if general_disk_state(&writable, &self.binding, events)? != expected {
            return Err(invalid(
                "general journal activation lost persistent exclusion",
            ));
        }
        close_file(management, "close-general-activation-management", events)?;
        self.file = writable;
        self.frozen_state = expected;
        Ok(GeneralJournaledPartition {
            inner: self,
            policy: None,
            paged_policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    /// Activate while retaining a real deny-new-writers gate on the primary
    /// PhysicalDrive route. Read-only aliases remain permitted. This does not
    /// claim global exclusion of administrative/volume aliases; the caller
    /// must retain offline filesystem exclusion and own every mutable alias.
    /// No serialized flag creates this capability: the held writable File is
    /// opened without FILE_SHARE_WRITE and retained through journal handoff.
    pub fn activate_for_journal_exclusive(
        mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralJournaledPartition> {
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "exclusive journal activation requires frozen read-only disk",
            ));
        }
        let path = format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number);
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(1) // FILE_SHARE_READ; existing/new write aliases must refuse.
            .custom_flags(0xa000_0000) // NO_BUFFERING | WRITE_THROUGH, as the writer uses.
            .open(&path);
        events.push(NativeEvent {
            operation: "open-exclusive-primary-raw-route-gate".into(),
            control_code: 0,
            input: 1u32.to_le_bytes().to_vec(),
            succeeded: opened.is_ok(),
            native_error: opened.as_ref().err().and_then(io::Error::raw_os_error),
            output: b"primary-raw-route-deny-new-writers".to_vec(),
        });
        // Opening failure leaves the original OFFLINE|READ_ONLY source intact.
        let gate = opened?;
        let mut expected = before.clone();
        expected.disk_attributes = OFFLINE;
        let mut transition_attempted = false;
        let activated = (|| -> io::Result<()> {
            if general_disk_state(&gate, &self.binding, events)? != before {
                return Err(invalid("exclusive gate route differs from frozen source"));
            }
            // Prove the sharing restriction on the exact route while the
            // disk is still READ_ONLY. Opening this probe issues no payload IO.
            let probe = device_file(&path, true, true);
            let denied = probe.as_ref().err().and_then(io::Error::raw_os_error)
                == Some(ERROR_SHARING_VIOLATION as i32);
            events.push(NativeEvent {
                operation: "probe-second-primary-raw-route-writer".into(),
                control_code: 0,
                input: 3u32.to_le_bytes().to_vec(),
                succeeded: probe.is_ok(),
                native_error: probe.as_ref().err().and_then(io::Error::raw_os_error),
                output: b"open-only; no payload read or write requested".to_vec(),
            });
            match probe {
                Ok(file) => {
                    close_file(file, "close-unexpected-secondary-raw-writer-probe", events)?;
                    return Err(invalid(
                        "exclusive raw gate allowed a second writable handle",
                    ));
                }
                Err(error) if !denied => return Err(error),
                Err(_) => (),
            }
            events.push(NativeEvent {
                operation: "primary-raw-route-deny-new-writers".into(),
                control_code: 0,
                input: vec![],
                succeeded: true,
                native_error: None,
                output: serde_json::to_vec(&serde_json::json!({
                    "scope":"primary-raw-route-deny-new-writers",
                    "gate_share_mode":1,"second_writer_native_error":ERROR_SHARING_VIOLATION,
                    "filesystem_excluded":true,"source_payload_write_requests":0,
                    "global_alias_exclusion_claimed":false
                }))
                .map_err(io::Error::other)?,
            });
            // No separate management writer can coexist with the gate. The
            // same held, positively bound handle performs the transition.
            transition_attempted = true;
            set_attributes(&gate, OFFLINE, events)?;
            if general_disk_state(&gate, &self.binding, events)? != expected {
                return Err(invalid(
                    "exclusive journal activation lost exclusion or identity",
                ));
            }
            Ok(())
        })();
        if let Err(error) = activated {
            if !transition_attempted {
                // In particular, never change attributes through a handle
                // whose initial route/identity validation just failed.
                events.push(NativeEvent {
                    operation: "exclusive-activation-refused-before-attribute-change".into(),
                    control_code: 0,
                    input: vec![],
                    succeeded: true,
                    native_error: None,
                    output: b"original frozen source not changed by this activation".to_vec(),
                });
                return Err(error);
            }
            // No source payload writes have occurred. Re-establish persistent
            // protection through the gate before either owning handle closes.
            let restored = set_attributes(&gate, OFFLINE | READ_ONLY, events).and_then(|()| {
                if general_disk_state(&gate, &self.binding, events)? != before {
                    return Err(invalid("exclusive activation protection restore differs"));
                }
                Ok(())
            });
            events.push(NativeEvent {
                operation: "exclusive-activation-restore-offline-readonly".into(),
                control_code: 0,
                input: (OFFLINE | READ_ONLY).to_le_bytes().to_vec(),
                succeeded: restored.is_ok(),
                native_error: restored.as_ref().err().and_then(io::Error::raw_os_error),
                output: restored
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default()
                    .into_bytes(),
            });
            return match restored {
                Ok(()) => Err(error),
                Err(restore) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "exclusive activation failed: {error}; read-only protection restore failed: {restore}"
                    ),
                )),
            };
        }
        self.file = gate;
        self.frozen_state = expected;
        Ok(GeneralJournaledPartition {
            inner: self,
            policy: None,
            paged_policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }
}

impl GeneralJournaledPartition {
    /// Dormant V4 policy branch. A held index alone is never authorization.
    /// Legacy Vec arming remains unchanged and does not use this method.
    #[allow(dead_code)]
    fn arm_resource_paged_writes(
        &mut self,
        policy: HeldPagedWritePolicy,
        profile: crate::journal_file::JournalProfile,
        pinned_max_journal_bytes: u64,
        _authority: ResourcePolicyAuthority,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if self.policy.is_some()
            || self.paged_policy.is_some()
            || self.write_poisoned
            || self.native_write_bytes_requested != 0
        {
            return Err(invalid("general journal write policy is already consumed"));
        }
        policy.revalidate()?;
        let facts = policy.facts()?;
        let expected = crate::journal_file::JournalProfile::from_schema_and_capacity(
            3,
            Some(pinned_max_journal_bytes),
        )?;
        let omitted = facts
            .old_zero_bytes
            .checked_add(facts.source_free_bytes)
            .ok_or_else(|| invalid("paged policy omitted bytes overflow"))?;
        let reconstructed = facts
            .journal_length
            .checked_add(omitted)
            .ok_or_else(|| invalid("paged policy capacity overflow"))?;
        if profile != expected
            || facts.image_length != self.byte_len()
            || facts.journal_length == 0
            || facts.journal_length > pinned_max_journal_bytes
            || omitted > facts.selected_bytes
            || facts.selected_bytes > reconstructed.min(facts.image_length)
            || (facts.format_version == 6 && !crate::journal_file::MARKER_STORAGE_NATIVE_QUALIFIED)
        {
            return Err(invalid(
                "paged policy capacity or native marker qualification differs",
            ));
        }
        if self.state(events)?.disk_attributes != OFFLINE {
            return Err(invalid("general target is not excluded from mounting"));
        }
        self.paged_policy = Some(policy);
        Ok(())
    }

    /// Open a separate read-only native handle/cursor for a compact target's
    /// source-backed complement. This derives only from this live writer and
    /// does not reopen an activated disk as an allegedly frozen partition.
    pub fn read_only_view(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralJournalReadView> {
        let expected_state = self.state(events)?;
        if expected_state.disk_attributes != OFFLINE {
            return Err(invalid(
                "journal read view requires an activated offline target",
            ));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding().disk_number),
            false,
            true,
        )?;
        if general_disk_state(&file, self.binding(), events)? != expected_state
            || self.state(events)? != expected_state
        {
            return Err(invalid("journal read view route changed while opening"));
        }
        Ok(GeneralJournalReadView {
            file,
            binding: self.binding().clone(),
            expected_state,
            position: 0,
            buffer: AlignedBuffer::new()?,
            native_bytes_read: 0,
        })
    }

    /// Reopen an already activated target after an interruption. A missing
    /// OFFLINE attribute is a hard refusal; no attribute repair is attempted.
    pub fn reopen(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let frozen_state = general_disk_state(&file, &binding, events)?;
        if frozen_state.disk_attributes != OFFLINE {
            return Err(invalid(
                "general journal target is not persistently offline",
            ));
        }
        Ok(Self {
            inner: GeneralFrozenPartition {
                resource_budget: None,
                freeze_observation: None,
                allocation_capture: None,
                file,
                binding,
                frozen_state,
                position: 0,
                buffer: AlignedBuffer::new()?,
                native_bytes_read: 0,
            },
            policy: None,
            paged_policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.inner.byte_len()
    }

    pub fn binding(&self) -> &GeneralDiskBinding {
        self.inner.binding()
    }

    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        self.inner.state(events)
    }

    pub fn arm_writes(
        &mut self,
        policy: WritePolicy,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.arm_writes_inner(policy, None, events)
    }

    /// Caller must first authenticate the exact encoded journal and its full
    /// selected write set. This grants no source or journal authority itself.
    pub fn arm_encoded_selected_writes(
        &mut self,
        policy: WritePolicy,
        journal_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.arm_writes_inner(
            policy,
            Some(SelectedWriteCapacity::Encoded { journal_bytes }),
            events,
        )
    }

    /// Canonical old-zero encoding may have a journal shorter than its selected
    /// write set. Complete journal/plan authentication is still the caller's
    /// obligation; the selected-byte profile ceiling remains unchanged.
    pub fn arm_old_zero_selected_writes(
        &mut self,
        policy: WritePolicy,
        journal_bytes: u64,
        old_zero_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if old_zero_bytes == 0 {
            return Err(invalid(
                "old-zero write policy requires a nonempty pinned subset",
            ));
        }
        self.arm_writes_inner(
            policy,
            Some(SelectedWriteCapacity::OldZero {
                journal_bytes,
                old_zero_bytes,
            }),
            events,
        )
    }

    /// Explicit new-policy entry; legacy profile helpers retain their limits.
    /// Pinned request intent, exact format-four facts and actual journal
    /// authentication must be checked by the caller before arming.
    pub fn arm_old_zero_actual_bytes_v3_writes(
        &mut self,
        policy: WritePolicy,
        journal_bytes: u64,
        old_zero_bytes: u64,
        pinned_max_journal_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.arm_writes_inner(
            policy,
            Some(SelectedWriteCapacity::OldZeroActualBytesV3 {
                journal_bytes,
                old_zero_bytes,
                pinned_max_journal_bytes,
            }),
            events,
        )
    }

    /// Caller has authenticated a format-five journal, its explicit recovery
    /// scope, frozen allocation witness and VSS admission. Counts alone grant
    /// neither source admission nor replay authority.
    pub fn arm_source_free_actual_bytes_v3_writes(
        &mut self,
        policy: WritePolicy,
        journal_bytes: u64,
        old_zero_bytes: u64,
        source_free_bytes: u64,
        pinned_max_journal_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.arm_writes_inner(
            policy,
            Some(SelectedWriteCapacity::SourceFreeActualBytesV3 {
                journal_bytes,
                old_zero_bytes,
                source_free_bytes,
                pinned_max_journal_bytes,
            }),
            events,
        )
    }

    fn arm_writes_inner(
        &mut self,
        policy: WritePolicy,
        encoded_journal_bytes: Option<SelectedWriteCapacity>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if self.policy.is_some()
            || self.paged_policy.is_some()
            || self.write_poisoned
            || self.native_write_bytes_requested != 0
        {
            return Err(invalid("general journal write policy is already consumed"));
        }
        match encoded_journal_bytes {
            Some(SelectedWriteCapacity::Encoded { journal_bytes }) => {
                policy.validate_encoded(self.byte_len(), journal_bytes)?
            }
            Some(SelectedWriteCapacity::OldZero {
                journal_bytes,
                old_zero_bytes,
            }) => {
                policy.validate_old_zero_encoded(self.byte_len(), journal_bytes, old_zero_bytes)?
            }
            Some(SelectedWriteCapacity::OldZeroActualBytesV3 {
                journal_bytes,
                old_zero_bytes,
                pinned_max_journal_bytes,
            }) => policy.validate_old_zero_actual_bytes_v3(
                self.byte_len(),
                journal_bytes,
                old_zero_bytes,
                pinned_max_journal_bytes,
            )?,
            Some(SelectedWriteCapacity::SourceFreeActualBytesV3 {
                journal_bytes,
                old_zero_bytes,
                source_free_bytes,
                pinned_max_journal_bytes,
            }) => policy.validate_source_free_actual_bytes_v3(
                self.byte_len(),
                journal_bytes,
                old_zero_bytes,
                source_free_bytes,
                pinned_max_journal_bytes,
            )?,
            None => policy.validate(self.byte_len())?,
        }
        if self.state(events)?.disk_attributes != OFFLINE {
            return Err(invalid("general target is not excluded from mounting"));
        }
        self.policy = Some(policy);
        Ok(())
    }

    pub fn sync_all(&mut self) -> io::Result<()> {
        if let Err(error) = self.inner.file.sync_all() {
            self.write_poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Call only after a durable journal handoff or verified rollback. This
    /// consumes the handle and is the sole general target mount transition.
    pub fn bring_online(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if self.write_poisoned {
            return Err(invalid("cannot expose a failed general target"));
        }
        self.policy = None;
        self.paged_policy = None;
        self.sync_all()?;
        self.state(events)?;
        set_attributes(&self.inner.file, 0, events)?;
        control(
            &self.inner.file,
            "refresh-online-general-target-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            events,
        )?;
        close_file(self.inner.file, "close-online-general-target", events)
    }
}

impl Read for GeneralJournaledPartition {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }
}

impl Seek for GeneralJournaledPartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.inner.seek(from)
    }
}

impl Write for GeneralJournaledPartition {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        if self.policy.is_none() && self.paged_policy.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "general raw writes are not armed",
            ));
        }
        if self.policy.is_some() && self.paged_policy.is_some() {
            self.write_poisoned = true;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "general raw write policies conflict",
            ));
        }
        let attempted = self
            .native_write_bytes_requested
            .checked_add(input.len() as u64)
            .ok_or_else(|| invalid("general write accounting overflow"))?;
        if self.write_poisoned || input.len() > MAX_IO {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "general native write violates bounded journal policy",
            ));
        }
        let (permitted, maximum_bytes) = if let Some(policy) = self.policy.as_ref() {
            (
                policy.permits(self.inner.position, input.len() as u64),
                policy.maximum_bytes,
            )
        } else if let Some(policy) = self.paged_policy.as_ref() {
            match policy
                .permits(self.inner.position, input.len() as u64)
                .and_then(|allowed| policy.facts().map(|facts| (allowed, facts.selected_bytes)))
            {
                Ok(result) => result,
                Err(error) => {
                    self.write_poisoned = true;
                    return Err(error);
                }
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "general raw writes are not armed",
            ));
        };
        if !permitted || attempted > maximum_bytes {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "general native write violates bounded journal policy",
            ));
        }
        self.inner.file.seek(SeekFrom::Start(
            self.inner.binding.identity.partition_offset + self.inner.position,
        ))?;
        self.inner.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
        self.native_write_bytes_requested = attempted;
        let result = self
            .inner
            .file
            .write(&self.inner.buffer.bytes_mut()[..input.len()]);
        match result {
            Ok(count) => {
                self.native_bytes_written += count as u64;
                if count != input.len() {
                    self.write_poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short general native write; reopen through recovery",
                    ));
                }
                self.inner.position += count as u64;
                Ok(count)
            }
            Err(error) => {
                self.write_poisoned = true;
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl GeneralPartitionReader {
    pub fn open(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        let initial_probe = probe_general(binding.clone(), events)?;
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            true,
        )?;
        Ok(Self {
            file,
            binding,
            initial_probe,
            position: 0,
            buffer: AlignedBuffer::new()?,
            native_bytes_read: 0,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }

    pub fn initial_probe(&self) -> &GeneralProbe {
        &self.initial_probe
    }

    pub fn revalidate_route(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralProbe> {
        let after = probe_general(self.binding.clone(), events)?;
        if after.binding != self.initial_probe.binding
            || after.device != self.initial_probe.device
            || after.disk_length != self.initial_probe.disk_length
            || after.alignment != self.initial_probe.alignment
            || after.gpt_layout != self.initial_probe.gpt_layout
            || after.volume_extents != self.initial_probe.volume_extents
            || after.disk_attributes_after != self.initial_probe.disk_attributes_after
        {
            return Err(invalid(
                "general disk route changed during read-only inventory",
            ));
        }
        Ok(after)
    }
}

impl Read for GeneralPartitionReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned general read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read += read as u64;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short general aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Seek for GeneralPartitionReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes general partition"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

impl Read for GeneralFrozenPartition {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned frozen read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read += read as u64;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short frozen aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Seek for GeneralFrozenPartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes frozen partition"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

/// An additional read-only handle on a frozen partition, so several reads can
/// be outstanding at once. Opening proves its route equals the frozen state; it
/// exposes aligned reads only and never changes attributes or mounts.
pub struct GeneralFrozenLane {
    file: File,
    binding: GeneralDiskBinding,
    position: u64,
    buffer: AlignedBuffer,
}

// SAFETY: the lane uniquely owns its aligned allocation and device handle;
// moving it to another thread moves that exclusive ownership.
unsafe impl Send for GeneralFrozenLane {}

impl GeneralFrozenPartition {
    /// The storage transfer profile Windows reports for this frozen disk.
    pub fn io_profile(&self) -> crate::io_profile::IoProfile {
        crate::io_profile::for_disk(&self.file)
    }

    /// Open `count` read lanes, each a fresh handle whose route must equal the
    /// frozen state.
    pub fn read_lanes(
        &self,
        count: usize,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Vec<GeneralFrozenLane>> {
        let path = format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number);
        (0..count)
            .map(|_| {
                let file = device_file(&path, false, true)?;
                if general_disk_state(&file, &self.binding, events)? != self.frozen_state {
                    return Err(invalid("frozen read lane route differs"));
                }
                Ok(GeneralFrozenLane {
                    file,
                    binding: self.binding.clone(),
                    position: 0,
                    buffer: AlignedBuffer::new()?,
                })
            })
            .collect()
    }
}

impl Read for GeneralFrozenLane {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let length = self.binding.identity.partition_bytes;
        if output.is_empty() || self.position == length {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((length - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > length {
            return Err(invalid("aligned frozen lane read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short frozen lane read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Seek for GeneralFrozenLane {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let length = self.binding.identity.partition_bytes;
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(length) + i128::from(value),
        };
        if position < 0 || position > i128::from(length) {
            return Err(invalid("seek escapes frozen lane"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

pub(crate) fn refresh_disk_properties(
    file: &File,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    control(
        file,
        "refresh-disk-properties",
        UPDATE_PROPERTIES,
        &[],
        0,
        events,
    )?;
    Ok(())
}

pub(crate) fn close_file(file: File, name: &str, events: &mut Vec<NativeEvent>) -> io::Result<()> {
    let raw = file.into_raw_handle();
    // SAFETY: into_raw_handle transferred sole ownership; this is the only close.
    // On failure, do not blindly close again: the handle value could be reused.
    let success = unsafe { CloseHandle(raw) } != 0;
    let error = if success {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    events.push(NativeEvent {
        operation: name.into(),
        control_code: 0,
        input: vec![],
        succeeded: success,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: vec![],
    });
    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

impl OfflinePartition {
    /// Lock/dismount the bound volume, then persist physical disk exclusion.
    /// No raw payload write is issued. Failure does not bring anything online.
    pub fn isolate(
        binding: DiskBinding,
        read_only: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let before = snapshot(&file, &binding, events)?;
        if before.disk_attributes != 0 {
            return Err(invalid("initial disk must be online and writable"));
        }
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let extents = control(
            &volume,
            "bound-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        layout::validate_volume_extent(&extents, &binding)?;
        // Allocate before any device mutation.
        let buffer = AlignedBuffer::new()?;
        control(&volume, "lock-volume", LOCK, &[], 0, events)?;
        control(&volume, "dismount-volume", DISMOUNT, &[], 0, events)?;
        let expected = OFFLINE | if read_only { READ_ONLY } else { 0 };
        set_attributes(&file, expected, events)?;
        // Persistent exclusion is proven before closing the lock owner. Close
        // releases the volume lock; no online/unlock fallback is attempted.
        close_file(volume, "close-isolated-volume", events)?;
        let after = snapshot(&file, &binding, events)?;
        if after.disk_attributes != expected {
            return Err(invalid("disk isolation was lost"));
        }
        Ok(Self {
            file,
            binding,
            read_only,
            position: 0,
            buffer,
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    /// Reopen an already excluded device after interruption. Never changes
    /// attributes as a fallback and never selects a disk by number alone.
    pub fn reopen(
        binding: DiskBinding,
        read_only: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            !read_only,
            true,
        )?;
        let expected = OFFLINE | if read_only { READ_ONLY } else { 0 };
        let found = snapshot(&file, &binding, events)?;
        if found.disk_attributes != expected {
            return Err(invalid(
                "persistent offline state differs; no automatic repair",
            ));
        }
        Ok(Self {
            file,
            binding,
            read_only,
            position: 0,
            buffer: AlignedBuffer::new()?,
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }
    pub fn binding(&self) -> &DiskBinding {
        &self.binding
    }
    pub fn inspect(&self, events: &mut Vec<NativeEvent>) -> io::Result<PartitionSnapshot> {
        snapshot(&self.file, &self.binding, events)
    }
    /// Mount only an already frozen source read-only for supported NTFS API
    /// queries, then persist exclusion again. READ_ONLY is never cleared.
    /// A killed observer can leave a valid, write-protected NTFS mount; this
    /// operation is forbidden after reconstruction has begun.
    pub fn observe_ntfs_files(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<LiveNtfsObservation> {
        request.validate()?;
        if !self.read_only
            || self.policy.is_some()
            || self.native_write_bytes_requested != 0
            || self.native_bytes_written != 0
            || request.disk_number != self.binding.disk_number
            || request.volume.trim_end_matches('\\') != self.binding.volume_path()?
            || request.partition_offset != self.binding.identity.partition_offset
            || request.partition_length != self.byte_len()
        {
            return Err(invalid("read-only source observation binding differs"));
        }
        let before = self.inspect(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("source must already be excluded and read-only"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        let actual = snapshot(&management, &self.binding, events)?;
        if actual.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("control handle source state differs"));
        }
        let mut lease = ReadonlyObservationLease {
            file: &management,
            events,
            restoration_attempted: false,
        };
        set_attributes(lease.file, READ_ONLY, lease.events)?;
        control(
            lease.file,
            "refresh-readonly-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            lease.events,
        )?;
        // Disk attributes and volume-interface publication are distinct. Poll
        // only harmless opens, never repeat a management mutation or drop RO.
        let mut ready = false;
        for _ in 0..60 {
            if attributes(lease.file, lease.events)? != READ_ONLY {
                return Err(invalid("source read-only observation state changed"));
            }
            match device_file(&self.binding.volume_path()?, false, false) {
                Ok(volume) => {
                    drop(volume);
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                    std::thread::sleep(std::time::Duration::from_millis(250))
                }
                Err(e) => return Err(e),
            }
        }
        if !ready {
            return Err(invalid(
                "read-only source volume interface was not published within 15 seconds",
            ));
        }
        let collected = crate::attestation_native::collect_file_metadata(request);
        let restored = lease.finish();
        drop(lease);
        restored?;
        let after = self.inspect(events)?;
        if after.disk_attributes != OFFLINE | READ_ONLY
            || before.binding != after.binding
            || before.device != after.device
            || before.layout != after.layout
            || before.length != after.length
            || before.alignment != after.alignment
        {
            return Err(invalid(
                "source identity or exclusion changed during observation",
            ));
        }
        Ok(LiveNtfsObservation {
            report: collected?,
            before,
            after,
        })
    }

    /// Caller must finish and flush its complete journal and independently
    /// validate the journal ticket before supplying this explicit write set.
    pub fn enable_excluded_writes(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if !self.read_only
            || self.policy.is_some()
            || self.write_poisoned
            || self.native_write_bytes_requested != 0
            || self.inspect(events)?.disk_attributes != OFFLINE | READ_ONLY
        {
            return Err(invalid(
                "journal activation requires an unchanged excluded read-only handle",
            ));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        if snapshot(&management, &self.binding, events)?.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("activation control-handle binding differs"));
        }
        // Persist OFFLINE throughout. If reopening fails, recovery observes the
        // actual state; never retry the transition or expose the volume.
        set_attributes(&management, OFFLINE, events)?;
        let writable = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            true,
        )?;
        if snapshot(&writable, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("journal activation lost persistent exclusion"));
        }
        self.file = writable;
        self.read_only = false;
        Ok(())
    }

    /// Arm the exact ranges of an already durable, independently pinned journal.
    pub fn arm_writes(
        &mut self,
        policy: WritePolicy,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if self.read_only || self.policy.is_some() || self.write_poisoned {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write arming is unavailable in this state",
            ));
        }
        policy.validate(self.byte_len())?;
        if snapshot(&self.file, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("target is not excluded from mounting"));
        }
        self.policy = Some(policy);
        Ok(())
    }

    pub fn sync_all(&mut self) -> io::Result<()> {
        if let Err(error) = self.file.sync_all() {
            self.write_poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Explicit native mount boundary. Journal handoff (or verified rollback
    /// completion) must be durable before this is called. Consumes the stream.
    pub fn bring_online(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if self.read_only || self.write_poisoned {
            return Err(invalid("cannot expose a read-only or failed target"));
        }
        self.policy = None;
        self.sync_all()?;
        if snapshot(&self.file, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("target isolation changed before handoff"));
        }
        set_attributes(&self.file, 0, events)?;
        control(
            &self.file,
            "refresh-online-target-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            events,
        )?;
        close_file(self.file, "close-online-target", events)
    }
}

impl Read for OfflinePartition {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read += read as u64;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short native aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Write for OfflinePartition {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let policy = self.policy.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "raw writes are not armed")
        })?;
        let attempted = self
            .native_write_bytes_requested
            .checked_add(input.len() as u64)
            .ok_or_else(|| invalid("native write accounting overflow"))?;
        if self.read_only
            || self.write_poisoned
            || input.len() > MAX_IO
            || !policy.permits(self.position, input.len() as u64)
            || attempted > policy.maximum_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native write violates bounded policy",
            ));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + self.position,
        ))?;
        self.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
        // A failed/short dispatch has unknown completion. Never retry it through
        // this handle, including through Write::write_all.
        self.native_write_bytes_requested = attempted;
        let result = self.file.write(&self.buffer.bytes_mut()[..input.len()]);
        match result {
            Ok(count) => {
                self.native_bytes_written += count as u64;
                if count != input.len() {
                    self.write_poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short native write; reopen through recovery",
                    ));
                }
                self.position += count as u64;
                Ok(count)
            }
            Err(error) => {
                self.write_poisoned = true;
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl Seek for OfflinePartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes partition"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::PartitionIdentity;

    fn allocation_test_bitmap(bits: u16) -> Vec<u8> {
        let mut bytes = vec![0; 18];
        bytes[8..16].copy_from_slice(&16u64.to_le_bytes());
        bytes[16..].copy_from_slice(&bits.to_le_bytes());
        bytes
    }
    fn allocation_test_capture(bytes: &[u8], input: &[u8]) -> crate::bitmap_paging::Capture {
        crate::bitmap_paging::assemble_queries(
            &crate::attestation::IoctlQuery {
                code: crate::stream_layout::GET_BITMAP,
                input: input.to_vec(),
                bytes: bytes.to_vec(),
                native_error: None,
            },
            &[],
            input,
        )
        .unwrap()
    }

    #[test]
    fn allocation_capture_keeps_both_complete_views_and_their_phase() {
        let legacy = allocation_test_bitmap(1);
        let metadata = allocation_test_bitmap(0x8003);
        let mut queries = vec![];
        let snapshot = capture_allocation_queries(
            GeneralAllocationPhase::PostLockFlush,
            16 * 4096,
            |name, input| {
                queries.push((name.to_owned(), input.to_vec()));
                Ok(allocation_test_capture(
                    if input.len() == 8 { &legacy } else { &metadata },
                    input,
                ))
            },
        )
        .unwrap();
        assert_eq!(snapshot.phase(), GeneralAllocationPhase::PostLockFlush);
        assert_eq!(snapshot.legacy().allocated_clusters, 1);
        assert_eq!(snapshot.metadata_inclusive().allocated_clusters, 3);
        assert_ne!(
            snapshot.legacy().bitmap_sha256,
            snapshot.metadata_inclusive().bitmap_sha256
        );
        assert_eq!(queries[0].1, [0; 8]);
        let mut extended = [0; 16];
        extended[8] = 1;
        assert_eq!(queries[1].1, extended);
        assert!(queries.iter().all(|(name, _)| name.contains("post-lock")));
        let encoded = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(encoded["phase"], "post-lock-flush");
        assert_eq!(encoded["metadata_response_bytes"], 18);
        assert_eq!(
            encoded["metadata_page_proof"]["encoding"],
            crate::bitmap_paging::ENCODING
        );
        assert_eq!(
            encoded["metadata_page_proof"]["pages"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(encoded.get("raw_write_authority").is_none());
    }

    #[test]
    fn allocation_capture_refuses_partial_or_failed_required_queries() {
        let complete = allocation_test_bitmap(1);
        for (legacy, metadata) in [
            (complete[..17].to_vec(), complete.clone()),
            (complete.clone(), complete[..17].to_vec()),
        ] {
            assert!(
                allocation_snapshot(
                    GeneralAllocationPhase::PostLockFlush,
                    &legacy,
                    &metadata,
                    16 * 4096,
                )
                .is_err()
            );
        }
        let mut calls = 0;
        let error = capture_allocation_queries(
            GeneralAllocationPhase::PostLockFlush,
            16 * 4096,
            |_, input| {
                calls += 1;
                if input.len() == 16 {
                    Err(io::Error::from_raw_os_error(5))
                } else {
                    Ok(allocation_test_capture(&complete, input))
                }
            },
        )
        .unwrap_err();
        assert_eq!(calls, 2);
        assert_eq!(error.raw_os_error(), Some(5));
        let mut attempted_metadata = false;
        assert!(
            capture_allocation_queries(
                GeneralAllocationPhase::PostLockFlush,
                16 * 4096,
                |_, input| {
                    if input.len() == 8 {
                        Err(io::Error::from_raw_os_error(21))
                    } else {
                        attempted_metadata = true;
                        Ok(allocation_test_capture(&complete, input))
                    }
                },
            )
            .is_err()
        );
        assert!(attempted_metadata);
        let snapshot = allocation_snapshot(
            GeneralAllocationPhase::PostDismount,
            &complete,
            &complete,
            16 * 4096,
        )
        .unwrap();
        assert_eq!(snapshot.phase(), GeneralAllocationPhase::PostDismount);
    }

    #[test]
    fn allocation_capture_preserves_page_proofs_and_coalesces_across_pages() {
        let snapshot = capture_allocation_queries(
            GeneralAllocationPhase::PostLockFlush,
            16 * 4096,
            |_, template| {
                let mut first = vec![0; 17];
                first[8..16].copy_from_slice(&16_u64.to_le_bytes());
                first[16] = 0xff;
                let mut last = vec![0; 17];
                last[..8].copy_from_slice(&8_u64.to_le_bytes());
                last[8..16].copy_from_slice(&8_u64.to_le_bytes());
                last[16] = 0xff;
                let first = crate::attestation::IoctlQuery {
                    code: crate::stream_layout::GET_BITMAP,
                    input: template.to_vec(),
                    bytes: first,
                    native_error: Some(crate::bitmap_paging::MORE_DATA),
                };
                let last = crate::attestation::IoctlQuery {
                    code: crate::stream_layout::GET_BITMAP,
                    input: crate::bitmap_paging::page_input(template, 8)?,
                    bytes: last,
                    native_error: None,
                };
                crate::bitmap_paging::assemble_queries(&first, &[last], template)
            },
        )
        .unwrap();
        assert_eq!(snapshot.metadata_inclusive().ranges.len(), 1);
        assert_eq!(snapshot.metadata_inclusive().ranges[0].length, 16 * 4096);
        assert_eq!(snapshot.metadata_response_bytes, 34);
        let proof = snapshot.metadata_page_proof.as_ref().unwrap();
        assert_eq!(proof.pages.len(), 2);
        assert_eq!(
            proof.pages[0].native_error,
            Some(crate::bitmap_paging::MORE_DATA)
        );
        assert_eq!(proof.pages[1].input[8], 1);
        assert_eq!(
            proof.canonical_bitmap_sha256,
            snapshot.metadata_inclusive().bitmap_sha256
        );
        assert_ne!(
            proof.pages[0].response_sha256,
            proof.canonical_bitmap_sha256
        );
    }
    #[test]
    fn allocation_witness_cannot_attach_to_a_reopened_or_foreign_handle() {
        let OfflinePartition {
            file,
            binding,
            buffer,
            ..
        } = ordinary_stream();
        let binding = GeneralDiskBinding {
            disk_number: binding.disk_number,
            volume_guid: binding.volume_guid,
            identity: binding.identity,
        };
        let frozen_state = GeneralDiskState {
            device: vec![],
            disk_length: vec![],
            alignment: vec![],
            gpt_layout: vec![],
            disk_attributes: OFFLINE | READ_ONLY,
        };
        let token = Arc::new(());
        let complete = allocation_test_bitmap(1);
        let witness = GeneralAllocationFreezeWitness {
            schema_version: 1,
            binding: binding.clone(),
            pre_lock_state: GeneralDiskState {
                disk_attributes: 0,
                ..frozen_state.clone()
            },
            post_lock_state: GeneralDiskState {
                disk_attributes: 0,
                ..frozen_state.clone()
            },
            frozen_state: frozen_state.clone(),
            volume_extents: vec![],
            filesystem: "ReFS".into(),
            post_lock: allocation_snapshot(
                GeneralAllocationPhase::PostLockFlush,
                &complete,
                &complete,
                16 * 4096,
            )
            .unwrap(),
            post_dismount: None,
            post_dismount_error: Some("post-dismount allocation capture: access denied".into()),
            post_lock_equals_frozen_graph: false,
            raw_write_authority: false,
            resource_budget: None,
            token: Arc::clone(&token),
        };
        let mut frozen = GeneralFrozenPartition {
            file,
            binding,
            frozen_state,
            position: 0,
            buffer,
            native_bytes_read: 0,
            resource_budget: None,
            freeze_observation: None,
            allocation_capture: Some(token),
        };
        assert!(frozen.owns_allocation_witness(&witness));
        frozen.allocation_capture = None;
        assert!(!frozen.owns_allocation_witness(&witness));
        frozen.allocation_capture = Some(Arc::new(()));
        assert!(!frozen.owns_allocation_witness(&witness));
        frozen.allocation_capture = Some(Arc::clone(&witness.token));
        frozen.frozen_state.disk_attributes = OFFLINE;
        assert!(!frozen.owns_allocation_witness(&witness));
        frozen.frozen_state = witness.frozen_state.clone();
        frozen.binding.disk_number += 1;
        assert!(!frozen.owns_allocation_witness(&witness));
        assert!(witness.post_dismount().is_none());
        assert!(
            witness
                .post_dismount_error()
                .unwrap()
                .contains("post-dismount")
        );
        let encoded = serde_json::to_value(&witness).unwrap();
        assert!(encoded.get("token").is_none());
        assert_eq!(encoded["post_lock_equals_frozen_graph"], false);
        assert_eq!(encoded["raw_write_authority"], false);
    }

    #[test]
    fn enumerated_volume_name_must_be_a_complete_guid_root() {
        assert_eq!(
            enumerated_guid("\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\").unwrap(),
            "11111111-2222-3333-4444-555555555555"
        );
        for name in [
            "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}",
            "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\file",
            "\\\\?\\Volume{not-a-guid}\\",
        ] {
            assert!(enumerated_guid(name).is_err());
        }
    }

    #[test]
    fn mount_path_multisz_requires_final_terminator_and_no_duplicates() {
        let mut value: Vec<u16> = "F:\\".encode_utf16().collect();
        value.push(0);
        value.extend("C:\\mount\\".encode_utf16());
        value.extend([0, 0]);
        assert_eq!(
            decode_mount_paths(&value, value.len()).unwrap(),
            ["F:\\", "C:\\mount\\"]
        );
        assert!(decode_mount_paths(&value[..value.len() - 1], value.len() - 1).is_err());
        let mut repeated: Vec<u16> = "F:\\".encode_utf16().collect();
        repeated.push(0);
        repeated.extend("F:\\".encode_utf16());
        repeated.extend([0, 0]);
        assert!(decode_mount_paths(&repeated, repeated.len()).is_err());
    }

    fn ordinary_stream() -> OfflinePartition {
        let mut file = tempfile::tempfile().unwrap();
        let bytes: Vec<u8> = (0..73728).map(|n| (n % 251) as u8).collect();
        file.write_all(&bytes).unwrap();
        OfflinePartition {
            file,
            binding: DiskBinding {
                disk_number: 1,
                volume_guid: String::new(),
                identity: PartitionIdentity {
                    disk_guid: String::new(),
                    partition_guid: String::new(),
                    partition_number: 2,
                    disk_bytes: 73728,
                    partition_offset: 4096,
                    partition_bytes: 65536,
                    logical_sector_bytes: 512,
                    physical_sector_bytes: 4096,
                },
            },
            read_only: false,
            position: 0,
            buffer: AlignedBuffer::new().unwrap(),
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        }
    }

    #[test]
    fn arbitrary_reads_remain_inside_the_partition_and_match_bytes() {
        let mut stream = ordinary_stream();
        assert_eq!(stream.buffer.pointer.as_ptr() as usize % 4096, 0);
        for (at, count) in [(0, 1), (3, 5000), (4095, 4098), (65535, 10), (65536, 1)] {
            stream.seek(SeekFrom::Start(at)).unwrap();
            let mut bytes = vec![0; count];
            let read = stream.read(&mut bytes).unwrap();
            assert_eq!(read, count.min((65536 - at) as usize));
            for (index, &byte) in bytes[..read].iter().enumerate() {
                assert_eq!(byte, ((4096 + at + index as u64) % 251) as u8);
            }
        }
        assert!(stream.seek(SeekFrom::End(1)).is_err());
        assert!(stream.seek(SeekFrom::Start(u64::MAX)).is_err());
        stream.seek(SeekFrom::Start(0)).unwrap();
        assert!(stream.seek(SeekFrom::Current(-1)).is_err());
    }

    #[test]
    fn general_read_only_reader_uses_the_same_partition_bounded_bounce() {
        let OfflinePartition {
            file,
            binding,
            buffer,
            ..
        } = ordinary_stream();
        let binding = GeneralDiskBinding {
            disk_number: binding.disk_number,
            volume_guid: binding.volume_guid,
            identity: binding.identity,
        };
        let mut reader = GeneralPartitionReader {
            file,
            initial_probe: GeneralProbe {
                binding: binding.clone(),
                disk_attributes_before: 0,
                disk_attributes_after: 0,
                device: vec![],
                disk_length: vec![],
                alignment: vec![],
                gpt_layout: vec![],
                volume_extents: vec![],
                read_only_probe: true,
                source_write_requests: 0,
                conversion_qualified: false,
            },
            binding,
            position: 0,
            buffer,
            native_bytes_read: 0,
        };
        for (at, count) in [(0, 1), (3, 5000), (4095, 4098), (65535, 10)] {
            reader.seek(SeekFrom::Start(at)).unwrap();
            let mut bytes = vec![0; count];
            let read = reader.read(&mut bytes).unwrap();
            assert_eq!(read, count.min((65536 - at) as usize));
            for (index, &byte) in bytes[..read].iter().enumerate() {
                assert_eq!(byte, ((4096 + at + index as u64) % 251) as u8);
            }
        }
        assert!(reader.seek(SeekFrom::End(1)).is_err());
        assert!(reader.seek(SeekFrom::Current(-65537)).is_err());
    }

    #[test]
    fn frozen_general_reader_is_read_only_and_partition_relative() {
        let OfflinePartition {
            file,
            binding,
            buffer,
            ..
        } = ordinary_stream();
        let binding = GeneralDiskBinding {
            disk_number: binding.disk_number,
            volume_guid: binding.volume_guid,
            identity: binding.identity,
        };
        let mut reader = GeneralFrozenPartition {
            resource_budget: None,
            freeze_observation: None,
            allocation_capture: None,
            file,
            binding,
            frozen_state: GeneralDiskState {
                device: vec![],
                disk_length: vec![],
                alignment: vec![],
                gpt_layout: vec![],
                disk_attributes: OFFLINE | READ_ONLY,
            },
            position: 0,
            buffer,
            native_bytes_read: 0,
        };
        assert!(reader.freeze_observation().is_none());
        reader.seek(SeekFrom::Start(4095)).unwrap();
        let mut bytes = vec![0; 4098];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes[0], ((4096 + 4095) % 251) as u8);
        assert_eq!(bytes[4097], ((4096 + 4095 + 4097) % 251) as u8);
        assert!(reader.seek(SeekFrom::Start(65537)).is_err());
        reader.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(reader.read(&mut bytes).unwrap(), 0);
    }

    #[test]
    fn general_journal_target_requires_an_exact_armed_write_set() {
        let OfflinePartition {
            file,
            binding,
            buffer,
            ..
        } = ordinary_stream();
        let mut target = GeneralJournaledPartition {
            inner: GeneralFrozenPartition {
                resource_budget: None,
                freeze_observation: None,
                allocation_capture: None,
                file,
                binding: GeneralDiskBinding {
                    disk_number: binding.disk_number,
                    volume_guid: binding.volume_guid,
                    identity: binding.identity,
                },
                frozen_state: GeneralDiskState {
                    device: vec![],
                    disk_length: vec![],
                    alignment: vec![],
                    gpt_layout: vec![],
                    disk_attributes: OFFLINE,
                },
                position: 0,
                buffer,
                native_bytes_read: 0,
            },
            policy: None,
            paged_policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        };
        let block = vec![0xa7; 4096];
        assert!(target.write(&block).is_err());
        target.policy = Some(WritePolicy {
            allowed: vec![(0, 4096)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 4096,
            journal_profile: crate::journal_file::JournalProfile::LegacyV1,
        });
        target.write_all(&block).unwrap();
        assert_eq!(target.native_bytes_written, 4096);
        assert_eq!(target.native_write_bytes_requested, 4096);
        assert!(target.write(&block).is_err());
        target.seek(SeekFrom::Start(4096)).unwrap();
        assert!(target.write(&block).is_err());
        target.seek(SeekFrom::Start(0)).unwrap();
        let mut readback = vec![0; 4096];
        target.read_exact(&mut readback).unwrap();
        assert_eq!(readback, block);
    }

    #[test]
    fn explicit_write_set_retained_exclusion_and_attempt_budget_are_enforced() {
        let mut stream = ordinary_stream();
        let block = vec![0xa7; 4096];
        assert!(stream.write(&block).is_err());
        let policy = WritePolicy {
            allowed: vec![(0, 4096), (8192, 4096)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 8192,
            journal_profile: crate::journal_file::JournalProfile::LegacyV1,
        };
        policy.validate(stream.byte_len()).unwrap();
        let bad = WritePolicy {
            allowed: vec![(0, 8192)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 8192,
            journal_profile: crate::journal_file::JournalProfile::LegacyV1,
        };
        assert!(bad.validate(stream.byte_len()).is_err());
        stream.policy = Some(policy);
        assert!(stream.write(&block[..1]).is_err());
        stream.seek(SeekFrom::Start(4096)).unwrap();
        assert!(stream.write(&block).is_err());
        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.write_all(&block).unwrap();
        stream.seek(SeekFrom::Start(8192)).unwrap();
        stream.write_all(&block).unwrap();
        stream.sync_all().unwrap();
        stream.seek(SeekFrom::Start(0)).unwrap();
        assert!(stream.write(&block).is_err());
        assert_eq!(stream.native_bytes_written, 8192);
        assert_eq!(stream.native_write_bytes_requested, 8192);
        let mut raw = vec![0; 73728];
        stream.file.seek(SeekFrom::Start(0)).unwrap();
        stream.file.read_exact(&mut raw).unwrap();
        for (n, byte) in raw.into_iter().enumerate() {
            let changed = (4096..8192).contains(&n) || (12288..16384).contains(&n);
            assert_eq!(
                byte,
                if changed { 0xa7 } else { (n % 251) as u8 },
                "byte {n}"
            );
        }
    }
    #[test]
    fn write_policy_accepts_only_the_shared_capacity_bound() {
        let cap = crate::journal_file::MAX_CHANGED_BYTES;
        assert_eq!(cap, 376 * 1024 * 1024);
        let valid = WritePolicy {
            allowed: vec![(0, cap)],
            retained: vec![],
            maximum_bytes: cap,
            journal_profile: crate::journal_file::JournalProfile::LegacyV1,
        };
        valid.validate(cap + 4096).unwrap();
        let excessive = WritePolicy {
            allowed: vec![(0, cap + 4096)],
            retained: vec![],
            maximum_bytes: cap + 4096,
            journal_profile: crate::journal_file::JournalProfile::LegacyV1,
        };
        assert!(excessive.validate(cap + 4096).is_err());
        let underfunded = WritePolicy {
            allowed: vec![(0, cap)],
            retained: vec![],
            maximum_bytes: cap - 4096,
            journal_profile: crate::journal_file::JournalProfile::LegacyV1,
        };
        assert!(underfunded.validate(cap + 4096).is_err());
    }
    #[test]
    fn large_write_policy_requires_v2_and_keeps_overlap_and_budget_guards() {
        use crate::journal_file::JournalProfile;
        let large = crate::journal_file::MAX_CHANGED_BYTES + 4096;
        let mut policy = WritePolicy {
            allowed: vec![(4096, large)],
            retained: vec![(0, 4096)],
            maximum_bytes: large,
            journal_profile: JournalProfile::LegacyV1,
        };
        assert!(policy.validate(large + 8192).is_err());
        policy.journal_profile = JournalProfile::ExperimentalLargeV2;
        policy.validate(large + 8192).unwrap();
        let mut overlap = policy.clone();
        overlap.retained = vec![(4096, 4096)];
        assert!(overlap.validate(large + 8192).is_err());
        let mut underfunded = policy;
        underfunded.maximum_bytes -= 4096;
        assert!(underfunded.validate(large + 8192).is_err());
    }
}
