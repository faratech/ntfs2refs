//! Read-only hardware/scratch observations. These are sampled availability,
//! not reservations, conversion authority or a promise that resources persist.
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{io, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::{
    Storage::FileSystem::GetDiskFreeSpaceExW,
    System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
};

/// The most free memory a run counts, when its user set a limit; 0 when
/// there is none.
static COUNTED_FREE_LIMIT: AtomicU64 = AtomicU64::new(0);

/// Limits the memory this process may use for a conversion to `bytes`
/// (`--memory-limit`). A run uses up to two thirds of the memory that is
/// free, so no more than one and a half times `bytes` are counted as free
/// from here on, wherever free memory is read: the estimate before a run,
/// the run's ledger, the finalization's, a recovery's. Setting the same
/// limit again is accepted; a different one is refused, because budgets
/// were already made from the first.
pub fn limit_memory(bytes: u64) -> io::Result<()> {
    let counted = counted_free_for(bytes);
    match COUNTED_FREE_LIMIT.compare_exchange(0, counted, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(()),
        Err(existing) if existing == counted => Ok(()),
        Err(_) => Err(io::Error::other(
            "this process already works with another memory limit",
        )),
    }
}

/// The memory limit set for this process, if one was.
pub fn memory_limit() -> Option<u64> {
    match COUNTED_FREE_LIMIT.load(Ordering::SeqCst) {
        0 => None,
        counted => Some(counted / 3 * 2),
    }
}

/// The free memory that leaves a run `bytes` to use: it takes two thirds.
fn counted_free_for(bytes: u64) -> u64 {
    (bytes / 2).saturating_mul(3).max(3)
}

/// `free` as a run counts it: no more than its limit allows.
fn counted_free(free: u64) -> u64 {
    match COUNTED_FREE_LIMIT.load(Ordering::SeqCst) {
        0 => free,
        counted => free.min(counted),
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct AvailableResources {
    pub total_physical_bytes: u64,
    pub available_physical_bytes: u64,
    pub scratch_available_bytes: u64,
    pub scratch_total_bytes: u64,
}

/// Query the volume containing an existing ordinary metadata directory. The
/// caller separately pins its route and enforces the host/lab reserve policy.
pub fn observe_available_resources(scratch_directory: &Path) -> io::Result<AvailableResources> {
    let path = std::fs::canonicalize(scratch_directory)?;
    if !path.is_dir() {
        return Err(io::Error::other(
            "scratch resource route is not a directory",
        ));
    }
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::other("scratch resource route contains NUL"));
    }
    wide.push(0);
    let mut memory: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    memory.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: correctly sized initialized output remains live for this call.
    if unsafe { GlobalMemoryStatusEx(&mut memory) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut available = 0;
    let mut total = 0;
    let mut total_free = 0;
    // SAFETY: terminated route and disjoint initialized synchronous outputs.
    if unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut total_free) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if memory.ullAvailPhys > memory.ullTotalPhys || available > total_free || total_free > total {
        return Err(io::Error::other(
            "hardware/scratch availability observation is contradictory",
        ));
    }
    Ok(AvailableResources {
        total_physical_bytes: memory.ullTotalPhys,
        available_physical_bytes: counted_free(memory.ullAvailPhys),
        scratch_available_bytes: available,
        scratch_total_bytes: total,
    })
}

impl AvailableResources {
    /// Cross-check explicit caller allocations against this actual sample.
    /// Ongoing allocation/IO failures still fail closed; sampling reserves none.
    pub fn validate_budget(self, budget: crate::tree_resources::ResourceBudget) -> io::Result<()> {
        budget.validate()?;
        if budget.ram_bytes > self.available_physical_bytes
            || budget.scratch_bytes > self.scratch_available_bytes
        {
            return Err(io::Error::other(format!(
                "this run was sized for {} MiB of memory and {} MiB of working storage, and {} MiB of memory and {} MiB of working storage are free now: close other programs or free working storage, and run it again",
                budget.ram_bytes >> 20,
                budget.scratch_bytes >> 20,
                self.available_physical_bytes >> 20,
                self.scratch_available_bytes >> 20
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn a_limit_counts_one_and_a_half_times_itself_as_free() {
        const MIB: u64 = 1024 * 1024;
        // Two thirds of what is counted as free is what a run may use.
        assert_eq!(counted_free_for(2048 * MIB), 3072 * MIB);
        assert_eq!(counted_free_for(2048 * MIB) / 3 * 2, 2048 * MIB);
        // No limit: free memory is counted as it is. (The limit itself is
        // one for the whole process, so it is not set in a test that shares
        // the process with others.)
        assert_eq!(memory_limit(), None);
        assert_eq!(counted_free(8192 * MIB), 8192 * MIB);
    }
}
