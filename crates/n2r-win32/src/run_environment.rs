//! What a conversion needs of its process and of the Windows it runs on,
//! asked before a source is touched.
//!
//! Both used to be found out late: administrator rights when the first
//! device open failed, the Windows build when the frozen source's
//! observations were checked, minutes into a run and with the disk offline.

use std::{io, mem, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree},
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, GetTokenInformation,
        SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    },
    Storage::FileSystem::CreateDirectoryW,
    System::{
        Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW},
        SystemInformation::{GetProductInfo, OSVERSIONINFOEXW, OSVERSIONINFOW},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

/// Creates the run root and its inheritable access list in the same operation.
/// The root can contain decrypted copies, their shadow and journal data. Keep
/// access for the owner, SYSTEM and elevated local recovery administrators.
pub fn create_private_working_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let leaf = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let path = parent.canonicalize()?.join(leaf);
    let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        .encode_utf16()
        .chain([0])
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: SDDL is NUL-terminated; the out-pointer lives through the call.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: the UTF-16 path and valid allocated descriptor live through
    // creation. CreateDirectoryW does not retain either pointer.
    let created = unsafe { CreateDirectoryW(path.as_ptr(), &attributes) };
    let error = io::Error::last_os_error();
    // SAFETY: this call owns the allocation from the SDDL conversion.
    unsafe { LocalFree(descriptor) };
    if created == 0 { Err(error) } else { Ok(()) }
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut OSVERSIONINFOW) -> i32;
}

/// The running Windows as (major, minor, build), which a compatibility
/// manifest does not alter.
pub fn windows_version() -> io::Result<[u32; 3]> {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: an initialized SDK structure carrying its exact size, live for
    // the synchronous query.
    let status = unsafe { RtlGetVersion(&mut version) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "asking Windows for its version: RtlGetVersion failed with status {status:#x}"
        )));
    }
    Ok([
        version.dwMajorVersion,
        version.dwMinorVersion,
        version.dwBuildNumber,
    ])
}

/// `wProductType` of a workstation edition (VER_NT_WORKSTATION); a domain
/// controller is 2 and any other server 3.
const WORKSTATION: u8 = 1;

/// The installed Windows edition's product code, also reported as the OS SKU.
pub fn windows_edition(version: [u32; 3]) -> io::Result<u32> {
    let mut sku = 0;
    // SAFETY: the writable product-code pointer is live for the synchronous call.
    if unsafe { GetProductInfo(version[0], version[1], 0, 0, &mut sku) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sku)
}

/// The update revision of the running Windows build.
pub fn windows_revision() -> io::Result<u32> {
    let mut revision = 0u32;
    let mut bytes = mem::size_of_val(&revision) as u32;
    // SAFETY: the registry names are terminated strings and the live output
    // buffer has exactly the size of the requested DWORD.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            windows_sys::w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            windows_sys::w!("UBR"),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&mut revision as *mut u32).cast(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(revision)
}

/// Whether the running Windows is a server edition (Windows Server, a
/// domain controller included) and not a workstation one such as Windows 11.
pub fn is_windows_server() -> io::Result<bool> {
    let mut version = OSVERSIONINFOEXW {
        dwOSVersionInfoSize: mem::size_of::<OSVERSIONINFOEXW>() as u32,
        ..Default::default()
    };
    // SAFETY: RtlGetVersion fills the extended structure when the size it is
    // given is that structure's; the structure is initialized, carries that
    // size and lives for the synchronous query.
    let status = unsafe { RtlGetVersion((&mut version as *mut OSVERSIONINFOEXW).cast()) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "asking Windows whether it is a server edition: RtlGetVersion failed with status {status:#x}"
        )));
    }
    Ok(version.wProductType != WORKSTATION)
}

/// Whether this process holds an administrator's full token: an elevated
/// terminal, or a service account such as SYSTEM.
pub fn is_elevated() -> io::Result<bool> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo-handle of this process and a live out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("opening this process's token to see whether it is elevated: {error}"),
        ));
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: the token just opened, and a buffer of exactly the size of the
    // structure this information class returns.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: the handle opened above, closed once.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(io::Error::new(
            error.kind(),
            format!("asking whether this process's token is elevated: {error}"),
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_running_windows_reports_a_version_and_the_token_an_answer() {
        let version = windows_version().unwrap();
        assert!(version[0] >= 10, "{version:?}");
        assert!(version[2] > 0, "{version:?}");
        // Either answer is right for a test process; the query must succeed.
        is_elevated().unwrap();
    }
}
