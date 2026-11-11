//! Same-FileObject, query-only original source reference for SHADOW operations.
//! No source writer, byte reader, pathname constructor or serialized authority.
use super::{
    GeneralDiskState, GeneralFrozenPartition, NativeEvent, close_file, general_disk_state,
    general_disk_state_held_geometry,
};
use crate::{
    general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile},
    shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease},
};
use std::{
    ffi::c_void,
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, HANDLE},
    Storage::FileSystem::{FILE_READ_ATTRIBUTES, FILE_READ_DATA},
    System::Threading::GetCurrentProcess,
};

// IOCTL_DISK_GET_LENGTH_INFO (0x7405c) requires FILE_READ_DATA. READ_ATTRIBUTES
// alone is insufficient. No generic/SAME_ACCESS, write, delete or inheritance.
const QUERY_ACCESS: u32 = FILE_READ_DATA | FILE_READ_ATTRIBUTES | 0x0010_0000;
const RETAINED_BYTES: u64 = 9 * 1024 * 1024;

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
    // Object-manager metadata only, never an FSD access-information query.
    let status = unsafe {
        NtQueryObject(
            file.as_raw_handle(),
            0,
            (&mut info as *mut PublicObjectBasicInformation).cast(),
            56,
            &mut returned,
        )
    };
    if status != 0 || returned != 56 || info.granted_access != QUERY_ACCESS {
        return Err(io::Error::other(format!(
            "shadow-source query rights differ: NTSTATUS0x{:08x}, returned={returned}, actual0x{:08x}, required0x{QUERY_ACCESS:08x}",
            status as u32, info.granted_access
        )));
    }
    Ok(())
}

/// Issued only from an actual observed, persistently excluded Windows source.
/// Private fields and no Read/Seek/Write/AsRawHandle/Clone/Deserialize impls.
pub(crate) struct NativeFrozenShadowSourceQueryWitness {
    file: Option<File>,
    binding: GeneralDiskBinding,
    expected: GeneralDiskState,
    // The native reference and cloned state drop before their actual payer.
    _memory: Box<dyn ReportMemoryLease>,
}
impl NativeFrozenShadowSourceQueryWitness {
    pub(crate) fn from_frozen(
        source: &GeneralFrozenPartition,
        payer: &dyn ReportMemoryAccountant,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        if source.binding.layout_profile != GeneralDiskLayoutProfile::OfflineWindows
            || source.freeze_observation.is_none()
            || source.frozen_state.disk_attributes != 3
        {
            return Err(io::Error::other(
                "actual observed offline-Windows freeze required for shadow query witness",
            ));
        }
        // Prepay BEFORE duplicate creation, role workspace or state clones.
        let memory = payer.reserve(RETAINED_BYTES)?;
        let before = general_disk_state(&source.file, &source.binding, events)?;
        if before != source.frozen_state || before.disk_attributes != 3 {
            return Err(io::Error::other(
                "shadow query witness opening source freeze changed",
            ));
        }
        let process = unsafe { GetCurrentProcess() };
        let mut raw = ptr::null_mut();
        // Reduced rights on the SAME live FileObject; never reopen a path.
        if unsafe {
            DuplicateHandle(
                process,
                source.file.as_raw_handle(),
                process,
                &mut raw,
                QUERY_ACCESS,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(raw) };
        verify_access(&file)?;
        // Complete critical-role discovery surrounds the duplication itself.
        let after = general_disk_state(&file, &source.binding, events)?;
        if after != before || general_disk_state(&source.file, &source.binding, events)? != before {
            return Err(io::Error::other(
                "same-FileObject shadow query duplication changed source roles/state",
            ));
        }
        verify_access(&file)?;
        Ok(Self {
            file: Some(file),
            binding: source.binding.clone(),
            expected: before,
            _memory: memory,
        })
    }
    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("shadow source query reference is closed"))
    }
    pub(crate) fn require_binding_state(
        &self,
        binding: &GeneralDiskBinding,
        expected: &GeneralDiskState,
    ) -> io::Result<()> {
        if binding != &self.binding || expected != &self.expected || expected.disk_attributes != 3 {
            return Err(io::Error::other(
                "shadow source query witness binding/state differs",
            ));
        }
        verify_access(self.file()?)
    }
    pub(crate) fn revalidate_held(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        verify_access(self.file()?)?;
        // Every operation still checks actual DEVICE/LENGTH/ALIGNMENT/fullGPT
        // and persistent attributes3 through this exact retained FileObject.
        let actual = general_disk_state_held_geometry(self.file()?, &self.binding, events)?;
        if actual != self.expected || actual.disk_attributes != 3 {
            return Err(io::Error::other(
                "held shadow source geometry/exclusion changed",
            ));
        }
        Ok(())
    }
    pub(crate) fn revalidate_boundary(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        verify_access(self.file()?)?;
        // Preserve the old read-only observer's two full role/state captures,
        // now through the same actual retained FileObject rather than a path.
        let before = general_disk_state(self.file()?, &self.binding, events)?;
        let after = general_disk_state(self.file()?, &self.binding, events)?;
        if before != self.expected
            || after != self.expected
            || before != after
            || before.disk_attributes != 3
            || after.disk_attributes != 3
        {
            return Err(io::Error::other(
                "shadow source full critical-role boundary changed",
            ));
        }
        Ok(())
    }
    pub(crate) fn finish(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.revalidate_boundary(events)?;
        let file = self
            .file
            .take()
            .ok_or_else(|| io::Error::other("shadow source query reference absent"))?;
        let closed = close_file(
            file,
            "close-shadow-only-original-source-query-reference",
            events,
        );
        // Keep state and payer alive until the native close has completed.
        drop(self);
        closed
    }
}
