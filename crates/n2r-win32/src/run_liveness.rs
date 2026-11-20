//! Whether a run of this tool is still going, asked by another process
//! (#201). A run creates a named kernel mutex before its folder holds
//! anything and never closes it: Windows closes the handle when the process
//! ends, however it ends (an error, a kill, a crash), and the name exists no
//! longer. Asking is opening that name for SYNCHRONIZE only; nothing is
//! waited on, owned or released, and nothing else about the run is inferred.
//!
//! The name is in the `Global\` namespace, so that a run in another session
//! (a service, another user's terminal) is seen; creating it there takes an
//! administrator, which a conversion is.
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError,
        SetLastError,
    },
    System::Threading::{CreateMutexW, OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE},
};

/// The name of the token of the run whose folder is called `run_id`. A run
/// folder's name is letters and digits; anything else is refused before
/// Windows is asked.
pub fn token_name(run_id: &str) -> io::Result<String> {
    if run_id.is_empty()
        || run_id.len() > 64
        || !run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "a run's liveness token is named after its folder, which has to be letters, digits and hyphens (at most 64), not {run_id:?}"
            ),
        ));
    }
    Ok(format!("Global\\ntfs2refs-run-{run_id}"))
}

fn wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(Some(0)).collect()
}

/// Creates the token of the run called `run_id` and holds it until this
/// process ends: its handle is never closed. Refused when a token of that
/// name exists already, which another process then holds. Returns its name.
pub fn hold_until_this_process_ends(run_id: &str) -> io::Result<String> {
    let name = token_name(run_id)?;
    let text = wide(&name);
    // SAFETY: plain thread-local error state, read back below.
    unsafe { SetLastError(0) };
    // SAFETY: default security (the handle is not inherited by a child),
    // not owned on creation, and a NUL-terminated name that outlives the
    // synchronous call.
    let handle = unsafe { CreateMutexW(ptr::null(), 0, text.as_ptr()) };
    // SAFETY: read at once, on the thread that made the call.
    let error = unsafe { GetLastError() };
    if handle.is_null() {
        let cause = io::Error::from_raw_os_error(error as i32);
        return Err(io::Error::new(
            cause.kind(),
            format!("creating the liveness token {name}: {cause}"),
        ));
    }
    if error == ERROR_ALREADY_EXISTS {
        // SAFETY: the handle CreateMutexW returned just above, closed once:
        // it is the other process's token, not this run's.
        unsafe { CloseHandle(handle) };
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "creating the liveness token {name}: it exists already, held by another process"
            ),
        ));
    }
    // Deliberately never closed: the token lives exactly as long as this
    // process, which is what it says to whoever asks.
    Ok(name)
}

/// Whether the run called `run_id` still holds its token: `Ok(false)` only
/// when Windows says that no object of that name exists. An object that
/// exists but may not be opened here (another account's, an unelevated
/// caller) is held. Any other answer is an error, which a caller takes as
/// "cannot tell" and leaves the run alone.
pub fn is_held(run_id: &str) -> io::Result<bool> {
    let name = token_name(run_id)?;
    let text = wide(&name);
    // SAFETY: SYNCHRONIZE only, not inherited, and a NUL-terminated name that
    // outlives the synchronous call.
    let handle = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, text.as_ptr()) };
    // SAFETY: read at once, on the thread that made the call.
    let error = unsafe { GetLastError() };
    if !handle.is_null() {
        // SAFETY: the handle OpenMutexW returned just above, closed once.
        unsafe { CloseHandle(handle) };
        return Ok(true);
    }
    match error {
        ERROR_FILE_NOT_FOUND => Ok(false),
        ERROR_ACCESS_DENIED => Ok(true),
        _ => {
            let cause = io::Error::from_raw_os_error(error as i32);
            Err(io::Error::new(
                cause.kind(),
                format!("asking whether the liveness token {name} exists: {cause}"),
            ))
        }
    }
}
