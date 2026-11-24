//! What a conversion needs of its process and of the Windows it runs on,
//! asked before a source is touched.
//!
//! Both used to be found out late: administrator rights when the first
//! device open failed, the Windows build when the frozen source's
//! observations were checked, minutes into a run and with the disk offline.

use std::{io, mem, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::{
        SystemInformation::{GetProductInfo, OSVERSIONINFOEXW, OSVERSIONINFOW},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

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
