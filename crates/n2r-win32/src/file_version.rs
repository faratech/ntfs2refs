//! The file version a Windows executable or driver carries in its version
//! resource (VS_FIXEDFILEINFO), as major.minor.build.revision.
use std::{io, path::Path};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};

/// A file version: major, minor, build, revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileVersion(pub u16, pub u16, pub u16, pub u16);

impl FileVersion {
    /// The build without its revision: 10.0.26100 of 10.0.26100.1150.
    pub fn same_build(&self, other: &Self) -> bool {
        (self.0, self.1, self.2) == (other.0, other.1, other.2)
    }
}

impl std::fmt::Display for FileVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0, self.1, self.2, self.3)
    }
}

/// Reads the fixed file version of `path`.
pub fn file_version(path: &Path) -> io::Result<FileVersion> {
    let wide: Vec<u16> = path
        .as_os_str()
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-Unicode path"))?
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut handle = 0u32;
    // SAFETY: a NUL-terminated path and an output handle.
    let size = unsafe { GetFileVersionInfoSizeW(wide.as_ptr(), &mut handle) };
    if size == 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "{} has no version resource: {}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    let mut data = vec![0u8; size as usize];
    // SAFETY: a buffer of the size Windows asked for.
    if unsafe { GetFileVersionInfoW(wide.as_ptr(), 0, size, data.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "reading the version of {}: {}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    let root = [b'\\' as u16, 0];
    let mut fixed: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length = 0u32;
    // SAFETY: the buffer filled above; the result points inside it.
    if unsafe { VerQueryValueW(data.as_ptr().cast(), root.as_ptr(), &mut fixed, &mut length) } == 0
        || fixed.is_null()
        || (length as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} has no fixed file version", path.display()),
        ));
    }
    // SAFETY: VerQueryValueW returned a VS_FIXEDFILEINFO of at least this size
    // inside `data`, which outlives the read.
    let info = unsafe { std::ptr::read_unaligned(fixed as *const VS_FIXEDFILEINFO) };
    if info.dwSignature != 0xFEEF_04BD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} has a malformed fixed file version", path.display()),
        ));
    }
    Ok(FileVersion(
        (info.dwFileVersionMS >> 16) as u16,
        info.dwFileVersionMS as u16,
        (info.dwFileVersionLS >> 16) as u16,
        info.dwFileVersionLS as u16,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_running_windows_kernel_has_a_version_and_builds_compare_without_revision() {
        let windows = crate::current_windows_directory().unwrap();
        let version = file_version(&windows.join("System32\\ntoskrnl.exe")).unwrap();
        // The fixed file version of the kernel says 6.2 (as refs.sys's does),
        // whatever the product version is; the build is what is compared.
        assert!(version.2 >= 26100, "{version}");
        assert!(FileVersion(10, 0, 26100, 1).same_build(&FileVersion(10, 0, 26100, 9457)));
        assert!(!FileVersion(10, 0, 26100, 1).same_build(&FileVersion(10, 0, 26200, 1)));
    }
}
