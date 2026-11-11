//! Advisory counters for this process only. Transfer counts are process I/O
//! accounting, not physical disk traffic, and the two queries are not atomic.
//! This module changes no process state and supplies no source/write authority.
use serde::Serialize;
use std::io;
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::Threading::{GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS},
};

pub const SCOPE: &str = "process_io_transfer_counters_not_physical_disk_io";

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub static_scope: &'static str,
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_bytes: u64,
    pub write_transfer_bytes: u64,
    pub other_transfer_bytes: u64,
    pub user_time_100ns: u64,
    pub kernel_time_100ns: u64,
}

fn time_100ns(value: FILETIME) -> io::Result<u64> {
    u64::from(value.dwHighDateTime)
        .checked_mul(1u64 << 32)
        .and_then(|high| high.checked_add(u64::from(value.dwLowDateTime)))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process FILETIME overflow"))
}

/// Observe only the current process. Native failures propagate to the caller,
/// which must treat unavailable counters as diagnostics rather than authority.
pub fn snapshot() -> io::Result<Snapshot> {
    // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle for this
    // process. It must not be closed and remains valid for both queries.
    let process = unsafe { GetCurrentProcess() };
    let mut counters = IO_COUNTERS {
        ReadOperationCount: 0,
        WriteOperationCount: 0,
        OtherOperationCount: 0,
        ReadTransferCount: 0,
        WriteTransferCount: 0,
        OtherTransferCount: 0,
    };
    // SAFETY: the current-process pseudo-handle and writable structure live
    // throughout this synchronous query; Windows owns no output storage.
    if unsafe { GetProcessIoCounters(process, &mut counters) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut created = zero;
    let mut exited = zero;
    let mut kernel = zero;
    let mut user = zero;
    // SAFETY: each FILETIME is separately allocated writable output storage,
    // and the borrowed process pseudo-handle remains valid for this call.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Snapshot {
        static_scope: SCOPE,
        read_operation_count: counters.ReadOperationCount,
        write_operation_count: counters.WriteOperationCount,
        other_operation_count: counters.OtherOperationCount,
        read_transfer_bytes: counters.ReadTransferCount,
        write_transfer_bytes: counters.WriteTransferCount,
        other_transfer_bytes: counters.OtherTransferCount,
        user_time_100ns: time_100ns(user)?,
        kernel_time_100ns: time_100ns(kernel)?,
    })
}
