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
        SystemInformation::OSVERSIONINFOW,
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
