//! Filesystem storage accounting and held-file scratch retirement. Accounting
//! measures GetCompressedFileSizeW storage, not physical device write traffic.
use std::{
    fs::OpenOptions,
    io,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError},
    Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FILE_STANDARD_INFO, FileAllocationInfo, FileDispositionInfo,
        FileStandardInfo, GetCompressedFileSizeW, GetFileInformationByHandleEx,
        SetFileInformationByHandle,
    },
};

/// Allocate capacity on an already-held, fresh ordinary file without changing
/// its EOF. This is not journal enrollment or permission to write a volume.
/// The caller must reserve the full maximum before calling and retain the
/// exclusive file owner. All observations use the same held handle.
pub fn preallocate_empty_file(
    file: &std::fs::File,
    requested_bytes: u64,
    maximum_allocation: u64,
) -> io::Result<()> {
    let before = crate::reference_file::observe_reference_file_handle_with_limit(file, 0)?;
    if requested_bytes == 0
        || requested_bytes > maximum_allocation
        || before.file_bytes != 0
        || before.number_of_links != 1
        || before.allocation_bytes > maximum_allocation
    {
        return Err(io::Error::other(
            "fresh bounded preallocation file required",
        ));
    }
    let allocation = i64::try_from(requested_bytes)
        .map_err(|_| io::Error::other("preallocation exceeds native signed range"))?;
    // SAFETY: FILE_ALLOCATION_INFO consists of one aligned LARGE_INTEGER;
    // this synchronous call uses the existing owned file handle and changes
    // allocation only. EOF and identity are checked through that handle.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileAllocationInfo,
            (&allocation as *const i64).cast(),
            std::mem::size_of_val(&allocation) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let after = crate::reference_file::observe_reference_file_handle_with_limit(file, 0)?;
    if after.final_path != before.final_path
        || after.volume_serial_number != before.volume_serial_number
        || after.file_id_128 != before.file_id_128
        || after.file_attributes != before.file_attributes
        || after.number_of_links != 1
        || after.file_bytes != 0
        || after.allocation_bytes < requested_bytes
        || after.allocation_bytes > maximum_allocation
    {
        return Err(io::Error::other(format!(
            "preallocated file identity, EOF, or quota differs: EOF {}, allocation {}, required {}, maximum {}",
            after.file_bytes, after.allocation_bytes, requested_bytes, maximum_allocation
        )));
    }
    Ok(())
}

/// Release allocation beyond the exact EOF of an already-held, exclusively
/// owned fresh artifact writer. Never changes EOF or writes payload bytes.
/// Call before reducing the writer to a read-only duplicate: duplicate handles
/// retain the same FILE_OBJECT and its transient NTFS growth allocation.
/// This does not retroactively prove a hard transient-allocation quota. The
/// caller must retain its existing growth admission and full post-close hash.
pub fn normalize_allocation_at_eof(
    file: &std::fs::File,
    expected_eof: u64,
    maximum_eof: u64,
    reserved_slack: u64,
) -> io::Result<AllocationNormalization> {
    use crate::reference_file::observe_reference_file_handle_with_limit;
    let bound = expected_eof
        .checked_add(reserved_slack)
        .ok_or_else(|| io::Error::other("artifact allocation bound overflow"))?;
    let before = observe_reference_file_handle_with_limit(file, maximum_eof)?;
    if before.file_bytes != expected_eof
        || expected_eof > maximum_eof
        || before.number_of_links != 1
        || before.allocation_bytes < expected_eof
    {
        return Err(io::Error::other(format!(
            "owned artifact EOF/allocation differs before normalization: EOF {}, expected {}, maximum {}, allocation {}, links {}",
            before.file_bytes,
            expected_eof,
            maximum_eof,
            before.allocation_bytes,
            before.number_of_links
        )));
    }
    let attempted = before.allocation_bytes > expected_eof;
    if attempted {
        let allocation = i64::try_from(expected_eof)
            .map_err(|_| io::Error::other("artifact allocation EOF exceeds native signed range"))?;
        // SAFETY: the caller retains the actual writable artifact owner. A
        // FILE_ALLOCATION_INFO at its current EOF releases unused allocation;
        // it cannot truncate logical content or authorize volume/source writes.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileAllocationInfo,
                (&allocation as *const i64).cast(),
                std::mem::size_of_val(&allocation) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        file.sync_all()?;
    }
    let after = observe_reference_file_handle_with_limit(file, maximum_eof)?;
    if after.final_path != before.final_path
        || after.volume_serial_number != before.volume_serial_number
        || after.file_id_128 != before.file_id_128
        || after.file_attributes != before.file_attributes
        || after.number_of_links != 1
        || after.file_bytes != expected_eof
        || after.allocation_bytes < expected_eof
        || after.allocation_bytes > before.allocation_bytes
        || after.allocation_bytes > bound
    {
        return Err(io::Error::other(format!(
            "artifact allocation normalization identity/bound differs: path {:?}, EOF {}, allocation before {}, after {}, expected {}, slack {}",
            after.final_path,
            after.file_bytes,
            before.allocation_bytes,
            after.allocation_bytes,
            expected_eof,
            reserved_slack
        )));
    }
    Ok(AllocationNormalization {
        before,
        after,
        native_trim_attempted: attempted,
    })
}

#[derive(serde::Serialize)]
pub struct AllocationNormalization {
    pub before: crate::reference_file::ReferenceFileSnapshot,
    pub after: crate::reference_file::ReferenceFileSnapshot,
    pub native_trim_attempted: bool,
}

#[derive(serde::Serialize)]
pub struct StorageUse {
    pub file_length_bytes: u64,
    pub filesystem_storage_bytes: u64,
    pub attributes: u32,
    pub file_id_info: String,
    pub data_bytes_read: u64,
    pub data_bytes_written: u64,
}

/// Stable volume/file identity from the caller's already-held handle. No path
/// reopen, payload I/O or permission changes occur here.
pub fn file_id_info(file: &std::fs::File) -> io::Result<String> {
    let mut info = [0u64; 3];
    // SAFETY: live handle and aligned initialized FILE_ID_INFO buffer.
    if unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 18, info.as_mut_ptr().cast(), 24)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(hex::encode(
        info.iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>(),
    ))
}
/// Actual GUID-volume path of this retained file or directory handle.
/// No pathname reopen, probe file or device mutation occurs.
pub fn final_path_guid(file: &std::fs::File) -> io::Result<String> {
    use windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_GUID;
    let path = final_path(file, VOLUME_NAME_GUID, "GUID")?;
    if !path.starts_with("\\\\?\\Volume{") {
        return Err(io::Error::other("held artifact is not on a GUID volume"));
    }
    Ok(path)
}
/// Actual path of this retained handle beneath its volume's device object,
/// such as `\Device\HarddiskVolume7\Windows\System32`. The device names the
/// mounted volume as exactly as its GUID path does, and handles on one volume
/// have paths beneath one device. Unlike the GUID path it is answered by the
/// object manager alone: for the GUID name Windows opens, asks and closes
/// the mount manager on every call, which made that query the largest single
/// cost of checking 112,609 short-name links, three handles to a link.
pub fn final_path_device(file: &std::fs::File) -> io::Result<String> {
    use windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_NT;
    let path = final_path(file, VOLUME_NAME_NT, "device")?;
    if !path.starts_with("\\Device\\") {
        return Err(io::Error::other("held object has no volume device path"));
    }
    Ok(path)
}
fn final_path(file: &std::fs::File, form: u32, name: &str) -> io::Result<String> {
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    let mut path = vec![0u16; 256];
    loop {
        // SAFETY: live borrowed handle and initialized declared-size output.
        let count = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                form,
            )
        } as usize;
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count < path.len() {
            return String::from_utf16(&path[..count])
                .map_err(|_| io::Error::other(format!("invalid held {name} path UTF16")));
        }
        if count > 32768 {
            return Err(io::Error::other(format!(
                "held {name} path exceeds Windows representation"
            )));
        }
        path.resize(count, 0);
    }
}
/// How far a file's on-disk allocation may run ahead of its length because
/// the filesystem pre-allocates for appends. ReFS on a large volume was seen
/// holding 442 KiB for a 220 KiB index that was still open; the surplus is
/// released when the last handle closes. Allow up to the file's own length,
/// and at least 16 MiB, on top of the cluster-rounding slack.
pub fn append_preallocation_allowance(file_bytes: u64) -> u64 {
    file_bytes.max(16 * 1024 * 1024)
}

/// Query actual filesystem and operating-system allocation quanta for an
/// already-held ordinary directory. No probe file is created.
pub fn artifact_allocation_slack(file: &std::fs::File) -> io::Result<u64> {
    use windows_sys::Win32::{
        Storage::FileSystem::GetDiskFreeSpaceW,
        System::SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    };
    let path = final_path_guid(file)?;
    let end = path
        .find("}\\")
        .ok_or_else(|| io::Error::other("GUID volume root absent"))?
        + 2;
    let root: Vec<u16> = path[..end].encode_utf16().chain([0]).collect();
    let (mut sectors, mut sector_bytes, mut free, mut total) = (0u32, 0u32, 0u32, 0u32);
    // SAFETY: terminated actual GUID root and initialized synchronous outputs.
    if unsafe {
        GetDiskFreeSpaceW(
            root.as_ptr(),
            &mut sectors,
            &mut sector_bytes,
            &mut free,
            &mut total,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SYSTEM_INFO consists of initialized SDK scalar fields.
    let mut system: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut system) };
    let cluster = u64::from(sectors)
        .checked_mul(u64::from(sector_bytes))
        .filter(|n| *n > 0)
        .ok_or_else(|| io::Error::other("filesystem allocation unit unavailable"))?;
    let quantum = cluster.max(u64::from(system.dwAllocationGranularity));
    quantum
        .checked_sub(1)
        .ok_or_else(|| io::Error::other("allocation quantum unavailable"))
}
/// Verify the granted access of an already-held metadata handle before
/// adopting it as immutable storage. This does not infer sharing from a flag.
pub fn require_readonly_access(file: &std::fs::File) -> io::Result<()> {
    use windows_sys::Win32::{Foundation::HANDLE, System::IO::IO_STATUS_BLOCK};
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationFile(
            file: HANDLE,
            status: *mut IO_STATUS_BLOCK,
            information: *mut core::ffi::c_void,
            length: u32,
            class: i32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    // SAFETY: exact initialized FILE_ACCESS_INFORMATION and IOSB outputs.
    let mut status: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut access = 0u32;
    let result = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&mut access as *mut u32).cast(),
            4,
            8,
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    if result != 0 || status.Information != 4 {
        return Err(io::Error::other("granted metadata access query incomplete"));
    }
    const MUTATION: u32 =
        0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    if access & MUTATION != 0 {
        return Err(io::Error::other(
            "artifact adoption requires actual reduced readonly access",
        ));
    }
    Ok(())
}

/// Actual link count on this same retained handle, using the stable SDK ABI.
pub fn number_of_links(file: &std::fs::File) -> io::Result<u32> {
    // SAFETY: FILE_STANDARD_INFO contains only initialized integer/BOOL fields.
    let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: exact aligned SDK structure and live synchronous metadata handle.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            (&mut info as *mut FILE_STANDARD_INFO).cast(),
            std::mem::size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info.NumberOfLinks)
}

/// Reduce this live owner's access without reopening a pathname. The duplicate
/// retains the same file object/sharing exclusion; it grants FILE_GENERIC_READ
/// only. The caller must flush writes before handing off and drop its writer.
pub fn duplicate_readonly(file: &std::fs::File) -> io::Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    let before = file.metadata()?;
    if !before.is_file() || before.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other("ordinary live file owner required"));
    }
    let id = file_id_info(file)?;
    let mut duplicated = std::ptr::null_mut();
    // SAFETY: current-process pseudo handles, caller's live file handle, and an
    // initialized output slot. No SAME_ACCESS or CLOSE_SOURCE flags are used.
    let succeeded = unsafe {
        let process = windows_sys::Win32::System::Threading::GetCurrentProcess();
        windows_sys::Win32::Foundation::DuplicateHandle(
            process,
            file.as_raw_handle(),
            process,
            &mut duplicated,
            windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
            0,
            0,
        )
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful DuplicateHandle transferred one new owned handle.
    let readonly = unsafe { std::fs::File::from_raw_handle(duplicated) };
    let after = readonly.metadata()?;
    if file_id_info(&readonly)? != id
        || file_id_info(file)? != id
        || !after.is_file()
        || before.file_attributes() != after.file_attributes()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(io::Error::other(
            "same-owner read-only duplicate identity changed",
        ));
    }
    Ok(readonly)
}

/// Mark only this already-held ordinary file for deletion when its owner
/// closes it. The caller owns DELETE access and must already have verified its
/// registered scratch identity, path, full pin and exclusion from live refs.
/// No pathname lookup, reopen, permission change or shell deletion is used.
pub fn mark_delete_on_close(file: &std::fs::File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other(
            "registered ordinary non-reparse scratch file required",
        ));
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: caller retains the live handle; the initialized SDK structure
    // has its exact size and this synchronous API only changes that file.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of_val(&disposition) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn observe(path: &Path) -> io::Result<StorageUse> {
    let file = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x00200000)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other(
            "ordinary non-reparse scratch file required",
        ));
    }
    let id = |file: &std::fs::File| -> io::Result<[u64; 3]> {
        let mut info = [0u64; 3];
        // SAFETY: live metadata handle and aligned FILE_ID_INFO output.
        if unsafe {
            GetFileInformationByHandleEx(file.as_raw_handle(), 18, info.as_mut_ptr().cast(), 24)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    };
    let original_id = id(&file)?;
    use std::os::windows::ffi::OsStrExt;
    let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    if name.len() > 32768 || name[..name.len() - 1].contains(&0) {
        return Err(io::Error::other("scratch path bounds differ"));
    }
    let mut high = 0u32;
    // SAFETY: bounded NUL-terminated path and initialized high DWORD. Clear
    // last error because low=0xffffffff can be a successful large-file size.
    unsafe { SetLastError(0) };
    let low = unsafe { GetCompressedFileSizeW(name.as_ptr(), &mut high) };
    let error = unsafe { GetLastError() };
    if low == u32::MAX && error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let reopened = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x00200000)
        .open(path)?;
    let after = file.metadata()?;
    if original_id != id(&reopened)?
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(io::Error::other(
            "scratch identity or metadata changed during storage query",
        ));
    }
    let bytes: Vec<u8> = original_id.iter().flat_map(|n| n.to_le_bytes()).collect();
    Ok(StorageUse {
        file_length_bytes: before.len(),
        filesystem_storage_bytes: (u64::from(high) << 32) | u64::from(low),
        attributes: before.file_attributes(),
        file_id_info: hex::encode(bytes),
        data_bytes_read: 0,
        data_bytes_written: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    fn held(path: &Path) -> std::fs::File {
        // Attribute access with backup semantics opens directories as well.
        std::fs::OpenOptions::new()
            .access_mode(0x80)
            .share_mode(7)
            .custom_flags(0x0200_0000)
            .open(path)
            .unwrap()
    }

    #[test]
    fn the_device_path_names_the_same_volume_and_place_as_the_guid_path() {
        let directory = tempfile::tempdir().unwrap();
        let child = directory.path().join("Child With A Long Name.txt");
        std::fs::write(&child, b"x").unwrap();
        let (parent, file) = (held(directory.path()), held(&child));

        let parent_device = final_path_device(&parent).unwrap();
        let file_device = final_path_device(&file).unwrap();
        assert!(parent_device.starts_with(r"\Device\"), "{parent_device}");
        // A child's device path is its parent's, a separator and its name:
        // what the short-name link check relies on.
        assert_eq!(file_device, format!(r"{parent_device}\Child With A Long Name.txt"));

        // Both forms end in the same path on the volume, and two handles on
        // one volume share the volume part of either form.
        let parent_guid = final_path_guid(&parent).unwrap();
        let file_guid = final_path_guid(&file).unwrap();
        let on_volume = |guid: &str| guid[guid.find('}').unwrap() + 1..].to_owned();
        assert!(parent_device.ends_with(&on_volume(&parent_guid)), "{parent_device} / {parent_guid}");
        assert!(file_device.ends_with(&on_volume(&file_guid)), "{file_device} / {file_guid}");
        let device_of = |path: &str| path[..path.len() - on_volume(&parent_guid).len()].to_owned();
        assert_eq!(
            device_of(&parent_device),
            file_device[..device_of(&parent_device).len()].to_owned()
        );
    }
}
