//! Reparse I/O on caller-held synchronous, canonical no-follow FILE/DIR handles.
//! No path reopen, target traversal, deletion, privilege enabling or source
//! write authority exists here. SET callers own the freshly constructed object.
//! Microsoft GET/SET contract: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_reparse_point
use crate::{
    file_storage, namespace_layout,
    reparse_layout::{self, Point},
};
use std::{ffi::c_void, fs::File, io, os::windows::io::AsRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_A_REPARSE_POINT, HANDLE},
    Storage::FileSystem::GetFileInformationByHandleEx,
    System::{
        IO::{DeviceIoControl, IO_STATUS_BLOCK},
        Ioctl::{FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT},
    },
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationFile(
        handle: HANDLE,
        status: *mut IO_STATUS_BLOCK,
        information: *mut c_void,
        length: u32,
        class: i32,
    ) -> i32;
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn synchronous(file: &File) -> io::Result<()> {
    let mut mode = 0u32;
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: FileModeInformation is a fixed local query with aligned initialized
    // output on the same live handle; no overlapped operation is submitted.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle(),
            &mut iosb,
            (&mut mode as *mut u32).cast(),
            4,
            16,
        )
    };
    let completion = unsafe { iosb.Anonymous.Status };
    if status != 0 || completion != 0 || iosb.Information != 4 || mode & 0x30 == 0 {
        return Err(io::Error::other(format!(
            "reparse requires a synchronous handle: status=0x{:08x}, completion=0x{:08x}, bytes={}",
            status as u32, completion as u32, iosb.Information
        )));
    }
    Ok(())
}
fn information(file: &File, class: i32, bytes: usize) -> io::Result<Vec<u8>> {
    let mut storage = vec![0u64; bytes.div_ceil(8)];
    // SAFETY: aligned initialized output is live for this synchronous bounded
    // query. These information classes do not modify file metadata.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            storage.as_mut_ptr().cast(),
            bytes as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), bytes) }.to_vec())
}
fn empty_directory(file: &File) -> io::Result<()> {
    for call in 0..namespace_layout::MAX_CALLS {
        let class = if call == 0 {
            namespace_layout::RESTART
        } else {
            namespace_layout::CONTINUE
        };
        match information(file, class, namespace_layout::CAPACITY) {
            Err(error) if error.raw_os_error() == Some(namespace_layout::END) => return Ok(()),
            Err(error)
                if call == 0 && error.raw_os_error() == Some(namespace_layout::FIRST_EMPTY) =>
            {
                continue;
            }
            Err(error) => return Err(error),
            Ok(bytes) => {
                let (entries, _) = namespace_layout::parse(&bytes)?;
                if entries
                    .iter()
                    .any(|entry| entry.name_utf16 != [46] && entry.name_utf16 != [46, 46])
                {
                    return Err(io::Error::from_raw_os_error(145));
                }
            }
        }
    }
    Err(invalid("empty-directory enumeration did not terminate"))
}

/// Requires FILE_READ_ATTRIBUTES and an already no-follow canonical handle.
/// ERROR_NOT_A_REPARSE_POINT (4390) is the only native absence result; every
/// other query, identity or buffer failure propagates explicitly.
pub fn capture(file: &File) -> io::Result<Option<Point>> {
    synchronous(file)?;
    let before = file_storage::file_id_info(file)?;
    let mut storage = vec![0u64; reparse_layout::MAX_REPARSE_BYTES / 8];
    let mut used = 0u32;
    // SAFETY: actual SDK FSCTL_GET_REPARSE_POINT (0x900a8), no input/setter;
    // aligned initialized sixteen-KiB output and synchronous held handle.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            storage.as_mut_ptr().cast(),
            reparse_layout::MAX_REPARSE_BYTES as u32,
            &mut used,
            ptr::null_mut(),
        )
    };
    let error = (ok == 0).then(io::Error::last_os_error);
    if file_storage::file_id_info(file)? != before {
        return Err(invalid("reparse identity changed during query"));
    }
    if let Some(error) = error {
        if error.raw_os_error() == Some(ERROR_NOT_A_REPARSE_POINT as i32) {
            if used != 0 {
                return Err(invalid("reparse absence returned unexpected payload bytes"));
            }
            return Ok(None);
        }
        return Err(error);
    }
    if used as usize > reparse_layout::MAX_REPARSE_BYTES {
        return Err(invalid("native reparse response exceeds sixteen KiB"));
    }
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), used as usize) };
    reparse_layout::parse(bytes).map(Some)
}

/// Only an actual constructor-owned fresh empty file/directory may be passed.
/// Ownership is supplied by the live caller, never inferred from JSON or path.
/// Requires the appropriate write access and FILE_LIST_DIRECTORY for directories.
/// Microsoft requires SeCreateSymbolicLinkPrivilege for SET. The owning native
/// shadow also uses SeRestorePrivilege for metadata restoration; it is not a
/// substitute for the link privilege. This function enables neither privilege.
/// Durability/exclusion remain the caller's barriers, not a readback claim.
pub fn restore_fresh_owned(file: &File, expected: &Point) -> io::Result<Point> {
    expected.validate()?;
    synchronous(file)?;
    let before = file_storage::file_id_info(file)?;
    let standard = information(file, 1, 24)?;
    let allocation = u64::from_le_bytes(standard[..8].try_into().unwrap());
    let length = u64::from_le_bytes(standard[8..16].try_into().unwrap());
    let links = u32::from_le_bytes(standard[16..20].try_into().unwrap());
    let directory = standard[21] != 0;
    // A constructor-owned file can already have several constructor-owned
    // aliases. Ownership comes from the live tree, never from link count.
    if standard[20] != 0 || links == 0 || (!directory && length != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "reparse restoration requires a fresh owned empty object: directory={directory}, allocation={allocation}, EOF={length}, links={links}, delete_pending={}",
                standard[20]
            ),
        ));
    }
    if !directory {
        // ReFS can report inline metadata capacity (observed 1024 bytes) for
        // an EOF-zero stream. Prove there are no physical DATA runs rather
        // than interpreting that capacity as file payload or ignoring it.
        let (first, continuation) = crate::stream_native::retrieval_queries(file);
        let empty_resident = first.native_error == Some(38) && first.bytes.is_empty();
        let empty_map = first.native_error.is_none()
            && first.bytes.len() == 16
            && u32::from_le_bytes(first.bytes[..4].try_into().unwrap()) == 0
            && u64::from_le_bytes(first.bytes[8..16].try_into().unwrap()) == 0;
        if !continuation.is_empty() || !(empty_resident || empty_map) {
            return Err(invalid(
                "fresh reparse file has allocated or unresolved DATA runs",
            ));
        }
    }
    if expected.tag() == reparse_layout::IO_REPARSE_TAG_MOUNT_POINT && !directory {
        return Err(invalid("mount-point reparse target must be a directory"));
    }
    if directory {
        empty_directory(file)?;
    }
    if capture(file)?.is_some() {
        return Err(invalid("fresh reparse target already has a point"));
    }
    if file_storage::file_id_info(file)? != before {
        return Err(invalid("owned reparse identity changed before SET"));
    }
    let mut storage = vec![0u64; expected.buffer.len().div_ceil(8)];
    unsafe {
        std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), expected.buffer.len())
    }
    .copy_from_slice(&expected.buffer);
    let mut used = 0u32;
    // SAFETY: SDK FSCTL_SET_REPARSE_POINT (0x900a4) on the caller's actual fresh
    // owned handle, complete validated input, no output/DELETE/follow operation.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            storage.as_ptr().cast(),
            expected.buffer.len() as u32,
            ptr::null_mut(),
            0,
            &mut used,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if used != 0 {
        return Err(invalid("reparse setter returned unexpected output"));
    }
    let actual = capture(file)?.ok_or_else(|| invalid("reparse point absent after SET"))?;
    if actual != *expected || file_storage::file_id_info(file)? != before {
        return Err(invalid("reparse bytes or owned identity differ after SET"));
    }
    Ok(actual)
}
