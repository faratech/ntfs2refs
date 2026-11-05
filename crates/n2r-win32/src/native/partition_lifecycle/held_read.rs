//! Read-only data access to the original locked source FILE_OBJECT. No path
//! reopen or writer API. Its cursor mutex is shared with the actual owner.
use super::super::partition_isolation::PartitionSourceBinding;
use super::super::{NativeEvent, PartitionOwnerToken, control};
use std::{
    ffi::c_void,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, HANDLE},
    Storage::FileSystem::{FILE_READ_ATTRIBUTES, FILE_READ_DATA},
    System::Threading::GetCurrentProcess,
};
const READ_ACCESS: u32 = FILE_READ_DATA | FILE_READ_ATTRIBUTES | 0x0010_0000; // SYNCHRONIZE
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
fn verify_access(file: &File) -> io::Result<()> {
    let mut info = PublicObjectBasicInformation::default();
    let mut returned = 0;
    // SAFETY: exact public object-manager ABI and retained source handle. No
    // FSD access, EOF, FileID, metadata or path query is involved.
    let status = unsafe {
        NtQueryObject(
            file.as_raw_handle(),
            0,
            (&mut info as *mut PublicObjectBasicInformation).cast(),
            56,
            &mut returned,
        )
    };
    if status != 0 || returned != 56 || info.granted_access != READ_ACCESS {
        return Err(io::Error::other(format!(
            "held-source-read NtQueryObject: status0x{:08x},bytes{returned},access0x{:08x},required0x{READ_ACCESS:08x}",
            status as u32, info.granted_access
        )));
    }
    Ok(())
}
fn require_native(
    file: &File,
    binding: &PartitionSourceBinding,
    expected: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    let device = control(
        file,
        "held-source-read-device",
        super::super::DEVICE,
        &[],
        12,
        events,
    )?;
    let info = control(
        file,
        "held-source-read-partition",
        0x0007_0048,
        &[],
        144,
        events,
    )?;
    if device.len() != 12
        || crate::layout::u32_at(&device, 0)? != 7
        || crate::layout::u32_at(&device, 4)? != binding.storage.disk_number
        || crate::layout::u32_at(&device, 8)? != binding.storage.identity.partition_number
        || expected.len() != 144
        || info != expected
    {
        return Err(io::Error::other(
            "held-source-read actual device/full partition identity changed",
        ));
    }
    Ok(())
}
pub(in crate::native) struct HeldSourceRead {
    file: File,
    binding: PartitionSourceBinding,
    token: PartitionOwnerToken,
}
impl HeldSourceRead {
    pub(in crate::native) fn require_owner(
        &self,
        binding: &PartitionSourceBinding,
        token: &PartitionOwnerToken,
    ) -> io::Result<()> {
        if &self.binding != binding || !self.token.same_owner(token) {
            return Err(io::Error::other(
                "held-source-read actual owner/binding changed",
            ));
        }
        verify_access(&self.file)
    }
    pub(in crate::native) fn device(&self, events: &mut Vec<NativeEvent>) -> io::Result<Vec<u8>> {
        control(
            &self.file,
            "readonly-partition-lane-device",
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
            "readonly-partition-lane-info",
            0x0007_0048,
            &[],
            144,
            events,
        )
    }
    pub(in crate::native) fn read_at(&mut self, at: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if !at.is_multiple_of(4096)
            || !buffer.len().is_multiple_of(4096)
            || at
                .checked_add(buffer.len() as u64)
                .is_none_or(|end| end > self.binding.storage.identity.partition_bytes)
        {
            return Err(io::Error::other(
                "held-source-read aligned range escapes source",
            ));
        }
        // All users of this FILE_OBJECT obey this same owner-token mutex.
        // The seek/read pair is atomic relative to other lanes and RW owner.
        let _cursor = self.token.lock_data_cursor()?;
        if self.file.seek(SeekFrom::Start(at))? != at {
            return Err(io::Error::other("held-source-read seek differs"));
        }
        self.file.read(buffer)
    }
}
pub(in crate::native) fn duplicate_bound(
    original: &File,
    binding: &PartitionSourceBinding,
    expected: &[u8],
    token: &PartitionOwnerToken,
    events: &mut Vec<NativeEvent>,
) -> io::Result<HeldSourceRead> {
    require_native(original, binding, expected, events)?;
    let process = unsafe { GetCurrentProcess() };
    let mut raw = ptr::null_mut();
    // SAFETY: this same retained FILE_OBJECT, strictly reduced read access,
    // no SAME_ACCESS, inheritance, name open, writer or sharing modification.
    if unsafe {
        DuplicateHandle(
            process,
            original.as_raw_handle(),
            process,
            &mut raw,
            READ_ACCESS,
            0,
            0,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "held-source-read DuplicateHandle: {error};native_error={:?}",
                error.raw_os_error()
            ),
        ));
    }
    // SAFETY: successful duplication transferred one owned kernel handle.
    let file = unsafe { File::from_raw_handle(raw) };
    verify_access(&file)?;
    require_native(&file, binding, expected, events)?;
    require_native(original, binding, expected, events)?;
    verify_access(&file)?;
    Ok(HeldSourceRead {
        file,
        binding: binding.clone(),
        token: token.clone(),
    })
}
