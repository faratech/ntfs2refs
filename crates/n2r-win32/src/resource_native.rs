//! Read-only hardware/scratch observations. These are sampled availability,
//! not reservations, conversion authority or a promise that resources persist.
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// Whether this process fits its memory to the machine (see
/// [`fit_memory_to_the_machine`]).
static FITS_THE_MACHINE: AtomicBool = AtomicBool::new(false);

/// A run without `--memory-limit` fits itself to the machine: where what it
/// cannot do without is more than its share of the free memory, it goes on
/// with what Windows can still give it (the page file) and takes longer,
/// instead of stopping. Its user did not ask for a ceiling. Called once,
/// where a run starts; a process that never calls it (a test) keeps to its
/// budget exactly.
pub fn fit_memory_to_the_machine() {
    FITS_THE_MACHINE.store(true, Ordering::SeqCst);
}

/// Whether memory the run cannot do without may go beyond its budget: it
/// fits itself to the machine, and its user set no limit.
pub fn memory_fits_the_machine() -> bool {
    FITS_THE_MACHINE.load(Ordering::SeqCst) && memory_limit().is_none()
}

/// What the volume of this run wants its ledger to hold, where that is
/// known before the run's budget is made; 0 where it is not.
static MEMORY_WANTED: AtomicU64 = AtomicU64::new(0);

/// A run that fits itself to the machine is told what its volume wants.
/// Its budget is then made no smaller than that (`memory_wanted`), so that
/// the shares of the budget that bound a volume's size (its indexes, its
/// open handles, its longest row) are sized by the volume and not by what
/// happened to be free. Only ever raised.
pub fn want_memory(bytes: u64) {
    MEMORY_WANTED.fetch_max(bytes, Ordering::SeqCst);
}

/// What `want_memory` was told, for a run that fits itself to the machine;
/// 0 for one that keeps to its budget or to a limit.
pub fn memory_wanted() -> u64 {
    if memory_fits_the_machine() {
        MEMORY_WANTED.load(Ordering::SeqCst)
    } else {
        0
    }
}

/// Whether a budget of `ram_bytes` can be had with `physical` bytes of
/// memory free. A run that keeps to its budget or to a limit needs the
/// memory to be free. One that fits itself to the machine needs Windows to
/// be able to commit it, from memory and page file together: it is slower
/// with less free, and is not refused for that.
pub fn memory_is_there(ram_bytes: u64, physical: u64) -> bool {
    ram_bytes <= physical
        || (memory_fits_the_machine() && committable_bytes().is_ok_and(|can| ram_bytes <= can))
}

/// The memory Windows has available now and the memory the machine has,
/// as they are, whatever limit this process works with.
pub fn physical_memory_now() -> io::Result<(u64, u64)> {
    let mut memory: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    memory.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: the structure is initialized and its length is set.
    if unsafe { GlobalMemoryStatusEx(&mut memory) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((memory.ullAvailPhys, memory.ullTotalPhys))
}

/// What Windows can still commit to this process: free memory and free
/// page file together.
pub fn committable_bytes() -> io::Result<u64> {
    let mut memory: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    memory.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: the structure is initialized and its length is set.
    if unsafe { GlobalMemoryStatusEx(&mut memory) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(memory.ullAvailPageFile)
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
        if !memory_is_there(budget.ram_bytes, self.available_physical_bytes)
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
