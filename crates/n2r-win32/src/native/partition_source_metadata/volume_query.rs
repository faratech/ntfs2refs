//! Query-only duplicate of an actual held source VOLUME, not an ordinary
//! file. No filesystem StandardInfo/FileID/EOF/access-information call occurs.
use super::super::partition_isolation::PartitionSourceBinding;
use super::super::{NativeEvent, PartitionOwnerToken, control};
use std::{
    ffi::c_void,
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, HANDLE},
    Storage::FileSystem::FILE_READ_ATTRIBUTES,
    System::Threading::GetCurrentProcess,
};

const QUERY_ACCESS: u32 = FILE_READ_ATTRIBUTES | 0x0010_0000; // SYNCHRONIZE
#[repr(C)]
#[derive(Default)]
struct PublicObjectBasicInformation {
    attributes: u32,
    granted_access: u32,
    handle_count: u32,
    pointer_count: u32,
    reserved: [u32; 10],
}
const _: () = assert!(
    std::mem::size_of::<PublicObjectBasicInformation>() == 56
        && std::mem::offset_of!(PublicObjectBasicInformation, granted_access) == 4
);
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(
        handle: HANDLE,
        class: i32,
        information: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}
fn context(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{operation}: {error} (Win32 error {:?})",
            error.raw_os_error()
        ),
    )
}
fn verify_access(file: &File) -> io::Result<()> {
    let mut info = PublicObjectBasicInformation::default();
    let mut returned = 0;
    // SAFETY: the retained handle and exact initialized public object-manager
    // structure remain live. ObjectBasicInformation=0 never queries the FSD.
    let status = unsafe {
        NtQueryObject(
            file.as_raw_handle(),
            0,
            (&mut info as *mut PublicObjectBasicInformation).cast(),
            56,
            &mut returned,
        )
    };
    if status != 0 || returned != 56 {
        return Err(io::Error::other(format!(
            "volume-query NtQueryObject(ObjectBasicInformation) incomplete: NTSTATUS0x{:08x}, returned={returned}, expected56",
            status as u32
        )));
    }
    if info.granted_access != QUERY_ACCESS {
        return Err(io::Error::other(format!(
            "volume-query granted access differs: actual0x{:08x}, requiredquery-only0x{QUERY_ACCESS:08x}",
            info.granted_access
        )));
    }
    Ok(())
}
fn require_native(
    file: &File,
    binding: &PartitionSourceBinding,
    expected: &[u8],
    events: &mut Vec<NativeEvent>,
    phase: &str,
) -> io::Result<()> {
    let device = control(
        file,
        "volume-query-bound-DEVICE",
        super::super::DEVICE,
        &[],
        12,
        events,
    )
    .map_err(|e| context(&format!("{phase} source DEVICE query"), e))?;
    let info = control(
        file,
        "volume-query-bound-PARTITION_INFO",
        0x0007_0048,
        &[],
        144,
        events,
    )
    .map_err(|e| context(&format!("{phase} source PARTITION_INFO_EX query"), e))?;
    if expected.len() != 144
        || device.len() != 12
        || crate::layout::u32_at(&device, 0)? != 7
        || crate::layout::u32_at(&device, 4)? != binding.storage.disk_number
        || crate::layout::u32_at(&device, 8)? != binding.storage.identity.partition_number
        || info != expected
    {
        return Err(io::Error::other(format!(
            "{phase}: actual source device/full144-byte partition identity changed"
        )));
    }
    Ok(())
}

/// Private typed kernel query handle. It has no Read/Seek/Write/AsRawHandle,
/// pathname constructor, clone, or publicly accessible File/handle field.
pub(in crate::native) struct VolumeQueryHandle {
    file: File,
    binding: PartitionSourceBinding,
    token: PartitionOwnerToken,
}
impl VolumeQueryHandle {
    pub(in crate::native) fn require_query_only_access(&self) -> io::Result<()> {
        verify_access(&self.file)
    }
    pub(in crate::native) fn require_owner(
        &self,
        binding: &PartitionSourceBinding,
        token: &PartitionOwnerToken,
    ) -> io::Result<()> {
        if &self.binding != binding || !self.token.same_owner(token) {
            return Err(io::Error::other(
                "volume-query handle belongs to another actual source owner/binding",
            ));
        }
        self.require_query_only_access()
    }
    pub(in crate::native) fn device(&self, events: &mut Vec<NativeEvent>) -> io::Result<Vec<u8>> {
        control(
            &self.file,
            "construction-original-source-device",
            super::super::DEVICE,
            &[],
            12,
            events,
        )
    }
    pub(in crate::native) fn partition_info(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Vec<u8>> {
        control(
            &self.file,
            "construction-original-source-partition",
            0x0007_0048,
            &[],
            144,
            events,
        )
    }
}

/// Caller first revalidates the ACTUAL complete source owner/admission. Only
/// that private owner can supply this retained File and stable token together.
pub(in crate::native) fn duplicate_bound(
    original: &File,
    binding: &PartitionSourceBinding,
    expected: &[u8],
    token: &PartitionOwnerToken,
    events: &mut Vec<NativeEvent>,
) -> io::Result<VolumeQueryHandle> {
    require_native(
        original,
        binding,
        expected,
        events,
        "before DuplicateHandle",
    )?;
    let process = unsafe { GetCurrentProcess() };
    let mut raw = ptr::null_mut();
    // SAFETY: duplicate this SAME live FileObject with only two explicit query
    // rights. No SAME_ACCESS, inheritance, raw read/write, or path reopen.
    let ok = unsafe {
        DuplicateHandle(
            process,
            original.as_raw_handle(),
            process,
            &mut raw,
            QUERY_ACCESS,
            0,
            0,
        )
    };
    if ok == 0 {
        return Err(context(
            "volume-query DuplicateHandle(FILE_READ_ATTRIBUTES|SYNCHRONIZE)",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: success transferred one owned kernel handle, closed on any error.
    let file = unsafe { File::from_raw_handle(raw) };
    verify_access(&file)?;
    require_native(
        &file,
        binding,
        expected,
        events,
        "after DuplicateHandle reduced query handle",
    )?;
    require_native(
        original,
        binding,
        expected,
        events,
        "closing original source handle",
    )?;
    verify_access(&file)?;
    Ok(VolumeQueryHandle {
        file,
        binding: binding.clone(),
        token: token.clone(),
    })
}
