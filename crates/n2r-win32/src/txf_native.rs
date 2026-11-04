//! Read-only TxF resource-manager observations while NTFS is still mounted.
//! A pair of zero-count queries is diagnostic; source freeze and log recovery
//! still have to be proven separately before conversion.
use crate::{general_layout::GeneralDiskBinding, layout::DiskBinding};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io, mem,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{FILETIME, GetLastError, HANDLE},
    Storage::FileSystem::SetFileTime,
    System::{
        IO::{DeviceIoControl, IO_STATUS_BLOCK},
        Ioctl::{
            FILE_FS_PERSISTENT_VOLUME_INFORMATION, FSCTL_IS_VOLUME_DIRTY,
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE, FSCTL_TXFS_LIST_TRANSACTIONS,
            FSCTL_TXFS_QUERY_RM_INFORMATION, TXFS_QUERY_RM_INFORMATION,
        },
        SystemInformation::OSVERSIONINFOW,
    },
};

const MAX_REPLY: usize = 64 * 1024;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut OSVERSIONINFOW) -> i32;
    fn NtQueryVolumeInformationFile(
        handle: HANDLE,
        status: *mut IO_STATUS_BLOCK,
        information: *mut core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32;
}

fn windows_version() -> io::Result<[u32; 3]> {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: initialized SDK structure with its exact size, live for the
    // synchronous native version query.
    let status = unsafe { RtlGetVersion(&mut version) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "RtlGetVersion failed: {status:#x}"
        )));
    }
    Ok([
        version.dwMajorVersion,
        version.dwMinorVersion,
        version.dwBuildNumber,
    ])
}

#[derive(Debug, Serialize)]
pub struct RmQuery {
    pub rm_state: u32,
    pub transaction_count: u64,
    pub tail_lsn: u64,
    pub current_lsn: u64,
    pub tops_used: u64,
    pub bytes_returned: u32,
    pub reply_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct TransactionList {
    pub number_of_transactions: u64,
    pub buffer_size_required: u64,
    pub bytes_returned: u32,
    pub reply_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct PersistentState {
    pub volume_flags: u32,
    pub flag_mask: u32,
    pub version: u32,
    pub reserved: u32,
    pub requested_flag_mask: u32,
    pub requested_version: u32,
    pub queried_flags_valid: bool,
    pub short_name_creation_disabled: bool,
    pub reply_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub rm_handle_profile: &'static str,
    pub windows_version: [u32; 3],
    pub quota_before: Option<QuotaState>,
    pub quota_before_error: Option<i32>,
    pub quota_after: Option<QuotaState>,
    pub quota_after_error: Option<i32>,
    pub binding: DiskBinding,
    pub native_dirty_before: Option<u32>,
    pub native_dirty_before_error: Option<u32>,
    pub persistent_state_before: Option<PersistentState>,
    pub persistent_state_before_error: Option<u32>,
    pub query_before: Option<RmQuery>,
    pub query_before_error: Option<u32>,
    pub transaction_list: Option<TransactionList>,
    pub transaction_list_error: Option<u32>,
    pub query_after: Option<RmQuery>,
    pub query_after_error: Option<u32>,
    pub native_dirty_after: Option<u32>,
    pub native_dirty_after_error: Option<u32>,
    pub persistent_state_after: Option<PersistentState>,
    pub persistent_state_after_error: Option<u32>,
    pub native_volume_state_stably_clear: bool,
    pub short_name_state_stable: bool,
    pub queried_rm_stably_empty: bool,
    pub all_resource_managers_checked: bool,
    pub source_frozen: bool,
    pub execution_authorized: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct QuotaState {
    pub free_space_start_filtering: i64,
    pub free_space_threshold: i64,
    pub free_space_stop_filtering: i64,
    pub default_threshold: i64,
    pub default_limit: i64,
    pub control_flags: u32,
    pub reply_sha256: String,
}

fn quota(volume: &File) -> (Option<QuotaState>, Option<i32>) {
    // FILE_FS_CONTROL_INFORMATION: five LARGE_INTEGERs, flags and padding.
    let mut output = [0u64; 6];
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: aligned initialized SDK-layout output and status storage stay
    // live for the synchronous query on an ordinary synchronous volume handle.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            volume.as_raw_handle(),
            &mut io_status,
            output.as_mut_ptr().cast(),
            48,
            6,
        )
    };
    if status != 0 {
        return (None, Some(status));
    }
    if io_status.Information != 48 {
        return (None, Some(0xc000_0004u32 as i32));
    }
    let bytes: Vec<_> = output.into_iter().flat_map(u64::to_le_bytes).collect();
    (
        Some(QuotaState {
            free_space_start_filtering: output[0] as i64,
            free_space_threshold: output[1] as i64,
            free_space_stop_filtering: output[2] as i64,
            default_threshold: output[3] as i64,
            default_limit: output[4] as i64,
            control_flags: output[5] as u32,
            reply_sha256: hex::encode(Sha256::digest(&bytes)),
        }),
        None,
    )
}

#[derive(Debug, Serialize)]
pub struct GeneralObservation {
    pub binding: GeneralDiskBinding,
    pub observation: Observation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultRmState {
    QueriedEmpty,
    Inactive,
    Unresolved,
}

impl Observation {
    /// ERROR_RM_NOT_ACTIVE is an explicit inactive state, not an invented
    /// transaction count. Other native failures remain unresolved.
    pub fn default_rm_state(&self) -> DefaultRmState {
        classify_default_rm(
            self.queried_rm_stably_empty,
            [
                self.query_before.is_some(),
                self.query_after.is_some(),
                self.transaction_list.is_some(),
            ],
            [
                self.query_before_error,
                self.query_after_error,
                self.transaction_list_error,
            ],
        )
    }
}

fn classify_default_rm(
    empty: bool,
    results: [bool; 3],
    errors: [Option<u32>; 3],
) -> DefaultRmState {
    if empty && results == [true; 3] && errors == [None; 3] {
        DefaultRmState::QueriedEmpty
    } else if results == [false; 3] && errors == [Some(6801); 3] {
        DefaultRmState::Inactive
    } else {
        DefaultRmState::Unresolved
    }
}

fn control(file: &File, code: u32) -> Result<Vec<u8>, u32> {
    let mut aligned = vec![0u64; MAX_REPLY / 8];
    let mut returned = 0u32;
    // SAFETY: the borrowed handle and initialized u64-aligned output buffer
    // remain alive for this bounded synchronous FSCTL.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            ptr::null(),
            0,
            aligned.as_mut_ptr().cast(),
            MAX_REPLY as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: this is the error from the immediately preceding Win32 call.
        return Err(unsafe { GetLastError() });
    }
    if returned as usize > MAX_REPLY {
        return Err(13); // ERROR_INVALID_DATA
    }
    // SAFETY: returned is bounded by the allocated 64 KiB above; the aligned
    // storage remains alive while copying the exact initialized reply bytes.
    Ok(unsafe {
        std::slice::from_raw_parts(aligned.as_ptr().cast::<u8>(), returned as usize).to_vec()
    })
}

fn query(file: &File) -> (Option<RmQuery>, Option<u32>) {
    match control(file, FSCTL_TXFS_QUERY_RM_INFORMATION) {
        Err(code) => (None, Some(code)),
        Ok(bytes) if bytes.len() < mem::size_of::<TXFS_QUERY_RM_INFORMATION>() => (None, Some(13)),
        Ok(bytes) => {
            // SAFETY: the complete repr(C) structure is present; read_unaligned
            // handles Vec<u8>'s byte alignment without casting it to a reference.
            let info =
                unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<TXFS_QUERY_RM_INFORMATION>()) };
            (
                Some(RmQuery {
                    rm_state: info.RmState,
                    transaction_count: info.TransactionCount,
                    tail_lsn: info.TailLsn,
                    current_lsn: info.CurrentLsn,
                    tops_used: info.TopsUsed,
                    bytes_returned: bytes.len() as u32,
                    reply_sha256: hex::encode(Sha256::digest(&bytes)),
                }),
                None,
            )
        }
    }
}

fn list(file: &File) -> (Option<TransactionList>, Option<u32>) {
    match control(file, FSCTL_TXFS_LIST_TRANSACTIONS) {
        Err(code) => (None, Some(code)),
        Ok(bytes) if bytes.len() < 16 => (None, Some(13)),
        Ok(bytes) => (
            Some(TransactionList {
                number_of_transactions: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                buffer_size_required: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                bytes_returned: bytes.len() as u32,
                reply_sha256: hex::encode(Sha256::digest(&bytes)),
            }),
            None,
        ),
    }
}

fn dirty(file: &File) -> (Option<u32>, Option<u32>) {
    match control(file, FSCTL_IS_VOLUME_DIRTY) {
        Err(code) => (None, Some(code)),
        Ok(bytes) if bytes.len() != 4 => (None, Some(13)),
        Ok(bytes) => (Some(u32::from_le_bytes(bytes.try_into().unwrap())), None),
    }
}

fn persistent(file: &File) -> (Option<PersistentState>, Option<u32>) {
    let input = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
        FlagMask: 1,
        Version: 1,
        ..Default::default()
    };
    let mut output = FILE_FS_PERSISTENT_VOLUME_INFORMATION::default();
    let mut returned = 0u32;
    // SAFETY: both repr(C) structures are initialized, aligned and live for
    // this synchronous read-only volume query.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
            (&input as *const FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            mem::size_of_val(&input) as u32,
            (&mut output as *mut FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            mem::size_of_val(&output) as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: direct error from the preceding Win32 call.
        return (None, Some(unsafe { GetLastError() }));
    }
    match decode_persistent(&output, returned) {
        Ok(state) => (Some(state), None),
        Err(code) => (None, Some(code)),
    }
}

fn decode_persistent(
    output: &FILE_FS_PERSISTENT_VOLUME_INFORMATION,
    returned: u32,
) -> Result<PersistentState, u32> {
    if returned as usize != mem::size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>() {
        return Err(13);
    }
    let bytes = [
        output.VolumeFlags.to_le_bytes(),
        output.FlagMask.to_le_bytes(),
        output.Version.to_le_bytes(),
        output.Reserved.to_le_bytes(),
    ]
    .concat();
    Ok(PersistentState {
        volume_flags: output.VolumeFlags,
        flag_mask: output.FlagMask,
        version: output.Version,
        reserved: output.Reserved,
        requested_flag_mask: 1,
        requested_version: 1,
        // FlagMask and Version configure the input query; Windows does
        // not echo them in this reply. Validate only requested flags and
        // retain all returned fields for provenance.
        queried_flags_valid: output.VolumeFlags & !1 == 0 && output.Reserved == 0,
        short_name_creation_disabled: output.VolumeFlags & 1 != 0,
        reply_sha256: hex::encode(Sha256::digest(bytes)),
    })
}

pub fn observe(binding: DiskBinding) -> io::Result<Observation> {
    binding.validate()?;
    if binding.disk_number != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "lab TxF query requires disk 1",
        ));
    }
    if crate::native::current_windows_disk(&mut Vec::new())? == binding.disk_number {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows disk cannot be queried by the lab tool",
        ));
    }
    let volume = File::options()
        .read(true)
        .share_mode(3)
        .open(binding.volume_path()?)?;
    let extents =
        control(&volume, 0x00560000).map_err(|code| io::Error::from_raw_os_error(code as i32))?;
    crate::layout::validate_volume_extent(&extents, &binding)?;
    let volume_path = binding.volume_path()?;
    observe_volume(binding, volume, &volume_path)
}

/// The same read-only TxF and persistent-policy queries on a separately bound
/// dedicated NTFS data disk. The actual volume extent is checked first.
pub fn observe_general(binding: GeneralDiskBinding) -> io::Result<GeneralObservation> {
    binding.validate()?;
    if crate::native::current_windows_disk(&mut Vec::new())? == binding.disk_number {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows disk cannot be queried as a general NTFS source",
        ));
    }
    let volume = File::options()
        .read(true)
        .share_mode(3)
        .open(binding.volume_path()?)?;
    let extents =
        control(&volume, 0x00560000).map_err(|code| io::Error::from_raw_os_error(code as i32))?;
    binding.validate_volume_extent(&extents)?;
    let proxy = DiskBinding {
        disk_number: binding.disk_number,
        volume_guid: binding.volume_guid.clone(),
        identity: binding.identity.clone(),
    };
    // The diagnostic proxy preserves the binding's serialized fields, but
    // its legacy volume_path() enforces the old fixed fixture geometry.
    // Use the path from the independently validated general binding instead.
    let volume_path = binding.volume_path()?;
    let observation = observe_volume(proxy, volume, &volume_path)?;
    Ok(GeneralObservation {
        binding,
        observation,
    })
}

fn observe_volume(
    binding: DiskBinding,
    volume: File,
    volume_path: &str,
) -> io::Result<Observation> {
    observe_volume_scoped(binding, volume, volume_path, None, &mut Vec::new())
}

fn observe_volume_scoped(
    binding: DiskBinding,
    volume: File,
    volume_path: &str,
    mut partition: Option<&mut crate::native::partition_lifecycle::PartitionReadonlyPhase<'_>>,
    events: &mut Vec<crate::native::NativeEvent>,
) -> io::Result<Observation> {
    let windows_version = windows_version()?;
    let disk = File::options()
        .read(true)
        .share_mode(3)
        .open(format!("\\\\.\\PhysicalDrive{}", binding.disk_number))?;
    let disk_read_only = read_only_disk(&disk)?;
    let partition_read_only = if let Some(phase) = partition.as_deref_mut() {
        require_partition_volume(phase, &volume, events)?;
        true
    } else { false };
    let readonly_root = disk_read_only || partition_read_only;
    // TxF resource-manager controls address the RM's root directory. The
    // direct volume handle remains separate for dirty/persistent-state FSCTLs.
    let root = File::options()
        .access_mode(if readonly_root { 0x81 } else { 0x181 })
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(format!("{volume_path}\\"))?;
    let suppress = FILETIME {
        dwLowDateTime: u32::MAX,
        dwHighDateTime: u32::MAX,
    };
    // SAFETY: borrowed directory handle and documented per-handle last-access
    // suppression sentinel; no stored timestamp value is supplied.
    if !readonly_root
        && unsafe { SetFileTime(root.as_raw_handle(), ptr::null(), &suppress, ptr::null()) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let (native_dirty_before, native_dirty_before_error) = dirty(&volume);
    let (quota_before, quota_before_error) = quota(&volume);
    let (persistent_state_before, persistent_state_before_error) = persistent(&volume);
    let (before, before_error) = query(&root);
    let (transactions, list_error) = list(&root);
    let (after, after_error) = query(&root);
    let (native_dirty_after, native_dirty_after_error) = dirty(&volume);
    let (quota_after, quota_after_error) = quota(&volume);
    let (persistent_state_after, persistent_state_after_error) = persistent(&volume);
    let native_volume_state_stably_clear =
        native_dirty_before == Some(0) && native_dirty_after == Some(0);
    let short_name_state_stable = persistent_state_before
        .as_ref()
        .zip(persistent_state_after.as_ref())
        .is_some_and(|(before, after)| {
            before.queried_flags_valid
                && after.queried_flags_valid
                && before.short_name_creation_disabled == after.short_name_creation_disabled
                && before.volume_flags & 1 == after.volume_flags & 1
        });
    let queried_rm_stably_empty = before.as_ref().is_some_and(|q| q.transaction_count == 0)
        && after.as_ref().is_some_and(|q| q.transaction_count == 0)
        && transactions.as_ref().is_some_and(|l| {
            l.number_of_transactions == 0 && l.buffer_size_required <= MAX_REPLY as u64
        })
        && before
            .as_ref()
            .zip(after.as_ref())
            .is_some_and(|(a, b)| a.rm_state == b.rm_state && matches!(a.rm_state, 0 | 2));
    if read_only_disk(&disk)? != disk_read_only {
        return Err(io::Error::other(
            "disk protection changed during NTFS observation",
        ));
    }
    if let Some(phase) = partition.as_deref_mut() {
        require_partition_volume(phase, &volume, events)?;
    }
    Ok(Observation {
        schema_version: 2,
        kind: "mounted-ntfs-txf-resource-manager-observation",
        rm_handle_profile: if partition_read_only {
            "volume-root-directory-selected-partition-read-only"
        } else if disk_read_only {
            "volume-root-directory-physical-disk-read-only"
        } else {
            "volume-root-directory-access-time-suppressed"
        },
        windows_version,
        quota_before,
        quota_before_error,
        quota_after,
        quota_after_error,
        binding,
        native_dirty_before,
        native_dirty_before_error,
        persistent_state_before,
        persistent_state_before_error,
        query_before: before,
        query_before_error: before_error,
        transaction_list: transactions,
        transaction_list_error: list_error,
        query_after: after,
        query_after_error: after_error,
        native_dirty_after,
        native_dirty_after_error,
        persistent_state_after,
        persistent_state_after_error,
        native_volume_state_stably_clear,
        short_name_state_stable,
        queried_rm_stably_empty,
        all_resource_managers_checked: false,
        source_frozen: false,
        execution_authorized: false,
    })
}

/// A protected root must not request WRITE_ATTRIBUTES merely to suppress
/// access-time updates. Require both the disk attribute and storage driver's
/// write-protection response; never infer protection from a failed root open.
fn read_only_disk(disk: &File) -> io::Result<bool> {
    let attributes =
        control(disk, 0x0007_00f0).map_err(|code| io::Error::from_raw_os_error(code as i32))?;
    if attributes.len() != 16 || attributes[..4] != 16u32.to_le_bytes() {
        return Err(io::Error::other("invalid disk-attribute response"));
    }
    let flags = u64::from_le_bytes(attributes[8..16].try_into().unwrap());
    let mut returned = 0;
    // SAFETY: synchronous no-buffer IOCTL on a borrowed live disk handle.
    let writable = unsafe {
        DeviceIoControl(
            disk.as_raw_handle(),
            0x0007_0024,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    let error = if writable == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    match (flags, writable != 0, error) {
        (0, true, None) => Ok(false),
        (2, false, Some(19)) => Ok(true),
        _ => Err(io::Error::other(format!(
            "unsupported NTFS observer disk protection: attributes={flags}, writable={}, error={error:?}",
            writable != 0
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inactive_is_distinct_from_empty_and_partial_queries_never_qualify() {
        assert_eq!(
            classify_default_rm(true, [true; 3], [None; 3]),
            DefaultRmState::QueriedEmpty
        );
        assert_eq!(
            classify_default_rm(false, [false; 3], [Some(6801); 3]),
            DefaultRmState::Inactive
        );
        for slot in 0..3 {
            let mut errors = [Some(6801); 3];
            errors[slot] = Some(5);
            assert_eq!(
                classify_default_rm(false, [false; 3], errors),
                DefaultRmState::Unresolved
            );
            let mut results = [true; 3];
            results[slot] = false;
            assert_eq!(
                classify_default_rm(true, results, [None; 3]),
                DefaultRmState::Unresolved
            );
        }
        assert_eq!(
            classify_default_rm(false, [true; 3], [None; 3]),
            DefaultRmState::Unresolved
        );
    }
    #[test]
    fn native_version_query_returns_a_build_fingerprint() {
        let version = windows_version().unwrap();
        assert!(version[0] >= 6 && version[2] > 0);
    }
    #[test]
    fn persistent_reply_need_not_echo_input_mask_and_version() {
        let output = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
            VolumeFlags: 1,
            ..Default::default()
        };
        let state = decode_persistent(&output, 16).unwrap();
        assert!(state.queried_flags_valid && state.short_name_creation_disabled);
        assert_eq!((state.flag_mask, state.version), (0, 0));
        let unexpected = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
            VolumeFlags: 2,
            ..Default::default()
        };
        assert!(
            !decode_persistent(&unexpected, 16)
                .unwrap()
                .queried_flags_valid
        );
        assert!(decode_persistent(&output, 4).is_err());
    }
    #[test]
    fn persistent_volume_state_uses_the_documented_aligned_wire_shape() {
        assert_eq!(mem::size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>(), 16);
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, VolumeFlags),
            0
        );
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, FlagMask),
            4
        );
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, Version),
            8
        );
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, Reserved),
            12
        );
    }
}

/// Actual volume-scoped TxF facts tied to the retained readonly lifecycle owner.
/// Current Windows siblings remain available; no disk-wide exclusion is inferred.
pub struct PartitionTxfObservation {
    binding: crate::native::partition_isolation::PartitionSourceBinding,
    preparation: crate::native::partition_lifecycle::PartitionPreparationToken,
    observation: Observation,
}
impl PartitionTxfObservation {
    pub fn observation(&self) -> &Observation { &self.observation }
    pub(crate) fn require_phase(
        &self,
        phase: &mut crate::native::partition_lifecycle::PartitionReadonlyPhase<'_>,
        events: &mut Vec<crate::native::NativeEvent>,
    ) -> io::Result<()> {
        if self.binding != *phase.binding() || !self.preparation.same_owner(&phase.preparation_token()) {
            return Err(io::Error::other("TxF observation lost actual readonly partition preparation"));
        }
        phase.revalidate(events)
    }
}
fn require_partition_volume(
    phase: &mut crate::native::partition_lifecycle::PartitionReadonlyPhase<'_>,
    volume: &File,
    events: &mut Vec<crate::native::NativeEvent>,
) -> io::Result<()> {
    phase.revalidate(events)?;
    let extent=control(volume,0x0056_0000).map_err(|n|io::Error::from_raw_os_error(n as i32))?;
    phase.binding().storage.validate_volume_extent(&extent)?;
    let info=control(volume,0x0007_0048).map_err(|n|io::Error::from_raw_os_error(n as i32))?;
    let protection=phase.protection();
    let error=match control(volume,0x0007_0024) {
        Ok(_)=>return Err(io::Error::other("TxF selected readonly partition reports writable")),
        Err(n)=>n,
    };
    if error!=19 || protection.partition_write_protect_error!=19
        || extent!=protection.volume_extents || info!=protection.readonly_partition_info {
        return Err(io::Error::other("TxF native readonly partition identity/protection differs"));
    }
    Ok(())
}
/// Scope is provided exclusively by an actual borrowed Basic+READ_ONLY phase.
/// No public binding/path/boolean can bypass observe_general's dedicated guard.
pub(crate) fn observe_partition(
    phase: &mut crate::native::partition_lifecycle::PartitionReadonlyPhase<'_>,
    events: &mut Vec<crate::native::NativeEvent>,
) -> io::Result<PartitionTxfObservation> {
    phase.revalidate(events)?;
    let binding=phase.binding().clone();
    let preparation=phase.preparation_token();
    let volume=phase.open_readonly_volume(events)?;
    let proxy=DiskBinding {disk_number:binding.storage.disk_number,
        volume_guid:binding.storage.volume_guid.clone(),identity:binding.storage.identity.clone()};
    let path=binding.storage.volume_path()?;
    let observation=observe_volume_scoped(proxy,volume,&path,Some(phase),events)?;
    // The root/volume/disk files above are all closed before returning this fact.
    let proof=PartitionTxfObservation{binding,preparation,observation};
    proof.require_phase(phase,events)?;
    Ok(proof)
}

/// Pre-lock TxF facts from the actual original volume held by the SDK guard.
/// Constructed internally after Basic0/full critical-role enrollment, never from
/// a saved observation or by removing observe_general's Windows-disk guard.
pub struct PartitionMountedTxfObservation {
    binding: crate::native::partition_isolation::PartitionSourceBinding,
    observation: Observation,
}
impl PartitionMountedTxfObservation {
    pub fn binding(&self) -> &crate::native::partition_isolation::PartitionSourceBinding { &self.binding }
    pub fn observation(&self) -> &Observation { &self.observation }
}
pub(crate) fn observe_partition_before_freeze(
    binding: &crate::native::partition_isolation::PartitionSourceBinding,
    original_volume: &File,
) -> io::Result<PartitionMountedTxfObservation> {
    binding.validate()?;
    let extent=control(original_volume,0x0056_0000).map_err(|n|io::Error::from_raw_os_error(n as i32))?;
    binding.storage.validate_volume_extent(&extent)?;
    let info=control(original_volume,0x0007_0048).map_err(|n|io::Error::from_raw_os_error(n as i32))?;
    if info.len()!=144 || crate::layout::u32_at(&info,0)?!=1
        || crate::layout::u64_at(&info,8)?!=binding.storage.identity.partition_offset
        || crate::layout::u64_at(&info,16)?!=binding.storage.identity.partition_bytes
        || info[32..48]!=crate::layout::guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?
        || info[48..64]!=crate::layout::guid_bytes(&binding.storage.identity.partition_guid)?
        || crate::layout::u64_at(&info,64)?!=0 {
        return Err(io::Error::other("pre-freeze TxF volume is not the original Basic0 partition"));
    }
    let proxy=DiskBinding {disk_number:binding.storage.disk_number,
        volume_guid:binding.storage.volume_guid.clone(),identity:binding.storage.identity.clone()};
    let path=binding.storage.volume_path()?;
    let observation=observe_volume(proxy,original_volume.try_clone()?,&path)?;
    if observation.rm_handle_profile!="volume-root-directory-access-time-suppressed" {
        return Err(io::Error::other("mounted partition TxF requires actual online/RW physical state"));
    }
    Ok(PartitionMountedTxfObservation {binding:binding.clone(),observation})
}
