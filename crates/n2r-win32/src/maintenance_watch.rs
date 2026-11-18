//! Watches, while a run lasts, for Windows' scheduled drive optimization.
//!
//! The ScheduledDefrag task optimizes ReFS volumes too, and when it ran on
//! the volumes a conversion was reading and writing, a pass stalled for a
//! quarter of an hour (#132). The run does not stop the task: it says once
//! that it is running and how to keep it from coming back, and goes on.
use std::{
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        ProcessStatus::EnumProcesses,
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
    },
};

static STARTED: AtomicBool = AtomicBool::new(false);
const EVERY: Duration = Duration::from_secs(30);

/// What the run says when it sees the optimizer. Public for the test.
pub const NOTE: &str = "Note: Windows' drive optimization (defrag.exe, the ScheduledDefrag task) is running. It can slow a conversion a great deal while it works on the volumes; it stops by itself. To keep it from starting during a conversion: schtasks /Change /TN \"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\" /Disable (and /Enable afterwards).";

/// Starts the watch once per process; it ends with the process.
pub fn start() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = thread::Builder::new()
        .name("ntfs2refs-maintenance-watch".to_owned())
        .stack_size(256 * 1024)
        .spawn(|| {
            loop {
                if optimizer_running() {
                    eprintln!("{NOTE}");
                    return;
                }
                thread::sleep(EVERY);
            }
        });
}

/// Whether a process whose image is defrag.exe is running.
fn optimizer_running() -> bool {
    let mut ids = vec![0u32; 4096];
    let mut needed = 0u32;
    // SAFETY: a writable buffer of the size given, and an output count.
    if unsafe { EnumProcesses(ids.as_mut_ptr(), (ids.len() * 4) as u32, &mut needed) } == 0 {
        return false;
    }
    ids.truncate(needed as usize / 4);
    ids.into_iter()
        .filter(|id| *id != 0)
        .any(|id| image_is_defrag(id))
}

fn image_is_defrag(id: u32) -> bool {
    // SAFETY: query-only access to a process id; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, id) };
    if process.is_null() {
        return false;
    }
    let mut name = [0u16; 1024];
    let mut length = name.len() as u32;
    // SAFETY: a live handle and a buffer of the length given.
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut length) };
    // SAFETY: the handle opened above, closed once.
    unsafe { CloseHandle(process) };
    ok != 0 && is_defrag(&String::from_utf16_lossy(&name[..length as usize]))
}

fn is_defrag(image: &str) -> bool {
    image
        .rsplit('\\')
        .next()
        .is_some_and(|leaf| leaf.eq_ignore_ascii_case("defrag.exe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_optimizer_is_recognized_and_the_note_says_how_to_stop_it() {
        assert!(is_defrag(r"C:\Windows\System32\Defrag.exe"));
        assert!(!is_defrag(r"C:\Windows\System32\defragsvc.dll"));
        assert!(!is_defrag(r"C:\tools\notdefrag.exe"));
        assert!(NOTE.contains("ScheduledDefrag") && NOTE.contains("/Disable"));
    }
}
