//! Real Windows Job Object memory ceiling for an explicitly enrolled,
//! disposable guest diagnostic. This is not a V4 resource certificate.
use std::{io, mem::size_of, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
            JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject,
        },
        ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
        },
        Threading::GetCurrentProcess,
    },
};

pub const MAX_FIXTURE_PROCESS_COMMIT: u64 = 5 * 1024 * 1024 * 1024 / 2;
const MIN_GUEST_PHYSICAL: u64 = 3 * 1024 * 1024 * 1024;
const GUEST_HEADROOM: u64 = 512 * 1024 * 1024;
const PROCESS_BASELINE_HEADROOM: u64 = 128 * 1024 * 1024;

/// Retains the actual job handle and can recheck the live limit/membership.
/// Closing it does not kill the process; the diagnostic terminates normally.
pub struct FixtureJobGuard {
    job: HANDLE,
    limit: u64,
    baseline_private: u64,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct FixtureJobObservation {
    pub process_limit_bytes: u64,
    pub job_limit_bytes: u64,
    pub baseline_private_bytes: u64,
    pub current_private_bytes: u64,
    pub process_is_member: bool,
}

fn process_private_bytes() -> io::Result<u64> {
    let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
    counters.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    // SAFETY: current-process pseudo handle and correctly sized initialized
    // PROCESS_MEMORY_COUNTERS_EX storage; the SDK accepts its base pointer.
    if unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&mut counters as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
            counters.cb,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(counters.PrivateUsage as u64)
}

impl FixtureJobGuard {
    /// Creates an actual process+job commit limit before source freeze.
    /// A failed job creation, limit, assignment or readback is a hard refusal.
    pub fn assign_current(
        limit: u64,
        shared_resource_budget: u64,
        available: crate::resource_native::AvailableResources,
    ) -> io::Result<Self> {
        let baseline = process_private_bytes()?;
        let needed = baseline
            .checked_add(shared_resource_budget)
            .and_then(|n| n.checked_add(PROCESS_BASELINE_HEADROOM))
            .ok_or_else(|| io::Error::other("fixture job memory arithmetic overflow"))?;
        let physical_headroom = available
            .available_physical_bytes
            .checked_add(baseline)
            .and_then(|n| n.checked_sub(GUEST_HEADROOM))
            .unwrap_or(0);
        if available.total_physical_bytes < MIN_GUEST_PHYSICAL
            || limit > MAX_FIXTURE_PROCESS_COMMIT
            || limit > physical_headroom
            || limit > usize::MAX as u64
            || needed > limit
        {
            return Err(io::Error::other(
                "fixture job limit does not fit actual guest RAM and baseline",
            ));
        }
        // SAFETY: null security/name inputs create a fresh unnamed job object.
        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut guard = Self {
            job,
            limit,
            baseline_private: baseline,
        };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.ProcessMemoryLimit = limit as usize;
        info.JobMemoryLimit = limit as usize;
        // SAFETY: the initialized SDK struct has the exact required size.
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both the newly created job and current-process pseudo handle
        // are live. The OS enforces nesting restrictions and reports failure.
        if unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        guard.verify()?;
        Ok(guard)
    }

    pub fn verify(&mut self) -> io::Result<FixtureJobObservation> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut returned = 0u32;
        // SAFETY: the held job and initialized output struct remain live.
        if unsafe {
            QueryInformationJobObject(
                self.job,
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut member = 0i32;
        // SAFETY: current-process and held-job handles are valid, output lives.
        if unsafe { IsProcessInJob(GetCurrentProcess(), self.job, &mut member) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
        let current = process_private_bytes()?;
        if returned as usize != size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()
            || info.BasicLimitInformation.LimitFlags & flags != flags
            || info.ProcessMemoryLimit as u64 != self.limit
            || info.JobMemoryLimit as u64 != self.limit
            || member == 0
            || current > self.limit
        {
            return Err(io::Error::other(
                "fixture job assignment or memory limit changed",
            ));
        }
        Ok(FixtureJobObservation {
            process_limit_bytes: info.ProcessMemoryLimit as u64,
            job_limit_bytes: info.JobMemoryLimit as u64,
            baseline_private_bytes: self.baseline_private,
            current_private_bytes: current,
            process_is_member: true,
        })
    }
}

impl Drop for FixtureJobGuard {
    fn drop(&mut self) {
        if !self.job.is_null() {
            // SAFETY: this owner retains exactly one live job handle.
            unsafe {
                CloseHandle(self.job);
            }
            self.job = ptr::null_mut();
        }
    }
}
