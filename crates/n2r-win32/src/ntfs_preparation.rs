//! Narrow native NTFS preparation through FSCTL_MOVE_FILE only.
//!
//! Plans and JSON supply hints, never an opened device or source certificate.
//! Opaque owners independently validate live routes, identities and mappings.
//! No raw WriteFile, formatter, retry, rollback or source admission exists here.
//! After any submitted request, success or failure, the actual post-state is
//! observed once. A failed/unverifiable submission poisons its source owner.

pub mod resource;

use crate::{
    attestation::{FileIdentity, PrivilegeState},
    attestation_native::Privileges,
    bitmap_window, bitmap_window_native, file_storage,
    general_layout::GeneralDiskBinding,
    native, retrieval_paging,
    stream_layout::Run,
    stream_native,
};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType, GetFileInformationByHandleEx,
        GetVolumeInformationByHandleW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
        LockFileEx, OpenFileById,
    },
    System::{IO::OVERLAPPED, SystemInformation::GetWindowsDirectoryW},
};

const GET_VOLUME_EXTENTS: u32 = 0x0056_0000;
const GET_NTFS_VOLUME_DATA: u32 = 0x0009_0064;
const IS_VOLUME_MOUNTED: u32 = 0x0009_0028;
const IS_DISK_WRITABLE: u32 = 0x0007_0024;
const MOVE_FILE: u32 = 0x0009_0074;
const RECORD_MASK: u64 = 0x0000_ffff_ffff_ffff;
const UNSUPPORTED_FILE_ATTRIBUTES: u32 = 0x5e15;

/// Hints which must match the held file and fresh native observations. Length
/// is the moved payload byte count; EOF is independently pinned as well.
#[derive(Clone, Debug, Serialize)]
pub struct MoveRequest {
    pub identity: FileIdentity,
    pub expected_logical_bytes: u64,
    pub starting_vcn: u64,
    pub expected_source_lcn: u64,
    pub destination_lcn: u64,
    pub cluster_count: u32,
    pub length_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VolumeGeometry {
    pub ntfs_serial: u64,
    pub total_sectors: u64,
    pub total_clusters: u64,
    pub bytes_per_sector: u32,
    pub cluster_bytes: u32,
    pub file_record_bytes: u32,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FileInformation {
    pub allocation_bytes: u64,
    pub logical_bytes: u64,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub directory: bool,
    pub attributes: u32,
    /// Creation, last-access, last-write and change FILETIMEs from the same
    /// actual FILE_BASIC_INFO query. Move verification preserves all four.
    pub basic_times: [u64; 4],
}

/// The canonical complete retrieval representation and its page proof. Native
/// capture bounds this to MAX_COMPLETE_EXTENTS/MAX_PAGES/MAX_RETURNED_BYTES;
/// window bitmap hashes below never claim a complete volume allocation map.
#[derive(Debug, Serialize)]
pub struct MappingObservation {
    pub canonical: Vec<u8>,
    pub proof: retrieval_paging::Proof,
}

#[derive(Debug, Serialize)]
pub struct FileObservation {
    pub file_id_info: Option<String>,
    pub information: Option<FileInformation>,
    pub mapping: Option<MappingObservation>,
    /// At most one error for each of the three independent observations.
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MoveObservation {
    pub schema_version: u32,
    pub request: MoveRequest,
    pub submitted: bool,
    pub native_error: Option<i32>,
    pub flush_error: Option<String>,
    pub before: FileObservation,
    pub after: FileObservation,
    pub destination_free_window: bitmap_window::Proof,
    pub post_route_error: Option<String>,
    pub identity_and_eof_unchanged: bool,
    pub mapping_outside_requested_vcns_unchanged: bool,
    pub requested_destination_observed: bool,
    pub verified: bool,
    pub source_owner_poisoned: bool,
    pub attempted_moves: u64,
    pub attempted_payload_bytes: u64,
    pub source_admitted: bool,
    pub retry_or_undo_performed: bool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| invalid("short native u32"))?
            .try_into()
            .map_err(|_| invalid("native u32 length differs"))?,
    ))
}

fn u64_at(bytes: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or_else(|| invalid("short native u64"))?
            .try_into()
            .map_err(|_| invalid("native u64 length differs"))?,
    ))
}

fn control(file: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    require(
        input.len() <= 32 && capacity <= 65_536,
        "preparation control input/output exceeds its fixed bound",
    )?;
    let query = stream_native::ioctl(file, code, input, capacity);
    if let Some(error) = query.native_error {
        return Err(io::Error::from_raw_os_error(error));
    }
    Ok(query.bytes)
}

/// Resolve the actual Windows directory through its containing volume, allowing
/// mounted folders and avoiding discovery's default partition-size profile.
fn exclude_running_windows_disk(disk_number: u32) -> io::Result<()> {
    let mut windows = vec![0u16; 32768];
    // SAFETY: initialized bounded UTF-16 output buffer.
    let count =
        unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) } as usize;
    require(
        count != 0 && count < windows.len(),
        "Windows directory resolution failed",
    )?;
    let mut mount = vec![0u16; 32768];
    // SAFETY: the first call returned a terminated path; output is bounded.
    if unsafe { GetVolumePathNameW(windows.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut guid = [0u16; 64];
    // SAFETY: terminated mount path and initialized fixed-size output buffer.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(mount.as_ptr(), guid.as_mut_ptr(), guid.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = guid
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("unterminated OS volume GUID"))?;
    let path =
        String::from_utf16(&guid[..length]).map_err(|_| invalid("invalid OS volume GUID"))?;
    crate::discovery::volume_guid(&path)?;
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(path.trim_end_matches('\\'))?;
    let bytes = control(&volume, GET_VOLUME_EXTENTS, &[], 1024)?;
    let count =
        usize::try_from(u32_at(&bytes, 0)?).map_err(|_| invalid("OS extent count overflow"))?;
    require(
        (1..=32).contains(&count) && bytes.len() == 8 + 24 * count,
        "OS volume extent response incomplete or excessive",
    )?;
    for index in 0..count {
        require(
            u32_at(&bytes, 8 + 24 * index)? != disk_number,
            "running Windows disk is excluded from NTFS preparation",
        )?;
    }
    Ok(())
}

fn filesystem_is_writable_ntfs(volume: &File) -> io::Result<()> {
    let mut filesystem = [0u16; 32];
    let mut flags = 0u32;
    // SAFETY: live handle, bounded filesystem name output, optional outputs null.
    if unsafe {
        GetVolumeInformationByHandleW(
            volume.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    require(
        filesystem[..5] == [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0]
            && flags & 0x0008_0000 == 0,
        "held volume is not writable NTFS",
    )?;
    control(volume, IS_VOLUME_MOUNTED, &[], 0)?;
    Ok(())
}

fn geometry(volume: &File, binding: &GeneralDiskBinding) -> io::Result<VolumeGeometry> {
    let bytes = control(volume, GET_NTFS_VOLUME_DATA, &[], 128)?;
    require(bytes.len() >= 96, "short NTFS volume data")?;
    let result = VolumeGeometry {
        ntfs_serial: u64_at(&bytes, 0)?,
        total_sectors: u64_at(&bytes, 8)?,
        total_clusters: u64_at(&bytes, 16)?,
        bytes_per_sector: u32_at(&bytes, 40)?,
        cluster_bytes: u32_at(&bytes, 44)?,
        file_record_bytes: u32_at(&bytes, 48)?,
        mft_lcn: u64_at(&bytes, 64)?,
        mft_mirror_lcn: u64_at(&bytes, 72)?,
    };
    let partition = binding.identity.partition_bytes;
    require(
        result.ntfs_serial != 0
            && result.bytes_per_sector == binding.identity.logical_sector_bytes
            && result.cluster_bytes.is_power_of_two()
            && result.cluster_bytes >= result.bytes_per_sector
            && result.cluster_bytes.is_multiple_of(result.bytes_per_sector)
            && result.total_clusters > 0
            && result.total_clusters <= i64::MAX as u64
            && result
                .total_clusters
                .checked_mul(u64::from(result.cluster_bytes))
                .is_some_and(|n| n <= partition)
            && result
                .total_sectors
                .checked_mul(u64::from(result.bytes_per_sector))
                .is_some_and(|n| n <= partition)
            && result.file_record_bytes.is_power_of_two()
            && result.mft_lcn > 0
            && result.mft_lcn < result.total_clusters
            && result.mft_mirror_lcn > 0
            && result.mft_mirror_lcn < result.total_clusters,
        "native NTFS geometry differs from bound data partition",
    )?;
    Ok(result)
}

fn information(file: &File) -> io::Result<FileInformation> {
    let mut standard = [0u64; 3];
    let mut basic = [0u64; 5];
    // SAFETY: live handle; aligned initialized FILE_STANDARD_INFO/FILE_BASIC_INFO.
    if unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 1, standard.as_mut_ptr().cast(), 24)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 0, basic.as_mut_ptr().cast(), 40)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    require(
        standard[0] <= i64::MAX as u64 && standard[1] <= i64::MAX as u64,
        "negative native file length/allocation",
    )?;
    let tail = standard[2].to_le_bytes();
    Ok(FileInformation {
        allocation_bytes: standard[0],
        logical_bytes: standard[1],
        number_of_links: u32::from_le_bytes(tail[..4].try_into().unwrap()),
        delete_pending: tail[4] != 0,
        directory: tail[5] != 0,
        attributes: basic[4] as u32,
        basic_times: [basic[0], basic[1], basic[2], basic[3]],
    })
}

fn identity_matches(id: &str, identity: &FileIdentity, serial: u64) -> io::Result<()> {
    let bytes = hex::decode(id).map_err(|_| invalid("invalid native file identity encoding"))?;
    require(
        bytes.len() == 24
            && u64_at(&bytes, 0)? == serial
            && u64_at(&bytes, 8)? == identity.reference()
            && bytes[16..].iter().all(|byte| *byte == 0),
        "opened file identity/sequence or NTFS volume serial differs",
    )
}

fn ordinary(info: FileInformation, eof: u64, maximum_bytes: u64) -> io::Result<()> {
    require(
        !info.directory
            && !info.delete_pending
            && info.attributes & UNSUPPORTED_FILE_ATTRIBUTES == 0
            && info.number_of_links != 0
            && info.logical_bytes == eof
            && eof != 0
            && eof <= maximum_bytes,
        "plain writable non-system nonresident unnamed DATA with unchanged EOF required",
    )
}

fn maps_to(runs: &[Run], start: u64, end: u64, first_lcn: u64) -> bool {
    let mut cursor = start;
    let mut index = runs.partition_point(|run| {
        run.vcn
            .checked_add(run.clusters)
            .is_some_and(|last| last <= start)
    });
    while cursor < end {
        let Some(run) = runs.get(index) else {
            return false;
        };
        let Some(run_end) = run.vcn.checked_add(run.clusters) else {
            return false;
        };
        if cursor < run.vcn
            || cursor >= run_end
            || run.lcn.and_then(|lcn| lcn.checked_add(cursor - run.vcn))
                != first_lcn.checked_add(cursor - start)
        {
            return false;
        }
        cursor = end.min(run_end);
        index += 1;
    }
    true
}

/// Compare physical functions over intervals, allowing different run splitting.
/// Complexity follows the two extent maps; no per-cluster comparison is used.
fn unchanged_outside(before: &[Run], after: &[Run], start: u64, end: u64) -> bool {
    let Some(total) = before.last().and_then(|r| r.vcn.checked_add(r.clusters)) else {
        return false;
    };
    if after.last().and_then(|r| r.vcn.checked_add(r.clusters)) != Some(total) {
        return false;
    }
    let (mut i, mut j, mut cursor) = (0usize, 0usize, 0u64);
    while cursor < total {
        let (Some(old), Some(new)) = (before.get(i), after.get(j)) else {
            return false;
        };
        let (Some(old_end), Some(new_end)) = (
            old.vcn.checked_add(old.clusters),
            new.vcn.checked_add(new.clusters),
        ) else {
            return false;
        };
        if cursor < old.vcn || cursor < new.vcn {
            return false;
        }
        let mut next = old_end.min(new_end);
        if cursor < start {
            next = next.min(start);
        } else if cursor < end {
            next = next.min(end);
        }
        if next <= cursor {
            return false;
        }
        if (cursor < start || cursor >= end)
            && old.lcn.and_then(|lcn| lcn.checked_add(cursor - old.vcn))
                != new.lcn.and_then(|lcn| lcn.checked_add(cursor - new.vcn))
        {
            return false;
        }
        cursor = next;
        if cursor == old_end {
            i += 1;
        }
        if cursor == new_end {
            j += 1;
        }
    }
    true
}

fn mapping_observation(capture: retrieval_paging::Capture) -> MappingObservation {
    MappingObservation {
        canonical: capture.canonical,
        proof: capture.proof,
    }
}
