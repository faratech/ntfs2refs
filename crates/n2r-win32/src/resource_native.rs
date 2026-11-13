//! Read-only hardware/scratch observations. These are sampled availability,
//! not reservations, conversion authority or a promise that resources persist.
use serde::Serialize;
use std::{io, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::{
    Storage::FileSystem::GetDiskFreeSpaceExW,
    System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
};

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
        available_physical_bytes: memory.ullAvailPhys,
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
