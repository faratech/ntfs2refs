//! Who keeps a source volume from being locked, and how long a run waits.
//!
//! Windows refuses to lock a volume while anything has a file or folder of
//! it open, and says only "Access is denied". A run that knows which paths
//! of the volume something is likely to hold (the placeholders of a cloud
//! provider, whose provider keeps its sync root open while it runs) asks
//! the Restart Manager which processes hold them, and asks the Cloud Files
//! API which providers of them are connected, so that the wait and the
//! refusal can name them. A run that has just downloaded placeholders from a
//! provider may also wait longer for the user to close it ([`LockHints::
//! patience`]); it never closes a provider itself.
use std::{path::PathBuf, sync::Mutex, time::Duration};

/// How long a lock is waited for when nothing says otherwise.
pub const DEFAULT_PATIENCE: Duration = Duration::from_secs(20);

/// What a run tells the lock of its source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LockHints {
    /// Paths on the volume whose holders are worth naming.
    pub paths: Vec<PathBuf>,
    /// Placeholders whose cloud provider, while connected, holds its sync
    /// root open.
    pub placeholders: Vec<PathBuf>,
    /// How long to wait for the lock; [`DEFAULT_PATIENCE`] when zero.
    pub patience: Duration,
}

static HINTS: Mutex<Option<LockHints>> = Mutex::new(None);

/// What this run tells the lock of its source.
pub fn set(hints: LockHints) {
    *HINTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hints);
}

/// What this run told the lock, if anything.
pub fn get() -> Option<LockHints> {
    HINTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// How long to wait for the lock of the source.
pub fn patience() -> Duration {
    get()
        .map(|hints| hints.patience)
        .filter(|patience| !patience.is_zero())
        .unwrap_or(DEFAULT_PATIENCE)
}

/// One process that holds a file of the volume open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    pub name: String,
    pub pid: u32,
}

/// Pure: the words for what holds the volume, from the Restart Manager's
/// processes and the connected providers (each a name and the sync root
/// they were asked of). Empty when nothing is known.
pub fn describe(holders: &[Holder], providers: &[(String, String)]) -> String {
    let mut parts: Vec<String> = holders
        .iter()
        .map(|holder| {
            format!(
                "{} (pid {}) holds files on it open",
                holder.name, holder.pid
            )
        })
        .collect();
    parts.extend(providers.iter().map(|(provider, at)| {
        format!("the cloud provider {provider} is connected and holds its sync root ({at}) open: close it (quit OneDrive, say)")
    }));
    parts.join("; ")
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{io, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
        RmStartSession,
    };

    /// The processes that hold any of `paths` open, as the Restart Manager
    /// answers. (A folder's handle is not always among what it reports.)
    pub fn holders(paths: &[PathBuf]) -> io::Result<Vec<Holder>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut session = 0u32;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        // SAFETY: storage for the handle and the key of the stated size.
        let started = unsafe { RmStartSession(&mut session, 0, key.as_mut_ptr()) };
        if started != 0 {
            return Err(io::Error::from_raw_os_error(started as i32));
        }
        let result = (|| {
            let names: Vec<Vec<u16>> = paths
                .iter()
                .map(|path| path.as_os_str().encode_wide().chain(Some(0)).collect())
                .collect();
            let pointers: Vec<*const u16> = names.iter().map(|name| name.as_ptr()).collect();
            // SAFETY: terminated names that outlive the call.
            let registered = unsafe {
                RmRegisterResources(
                    session,
                    pointers.len() as u32,
                    pointers.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                )
            };
            if registered != 0 {
                return Err(io::Error::from_raw_os_error(registered as i32));
            }
            let mut room = 16usize;
            loop {
                // SAFETY: plain data, zeroed.
                let mut infos: Vec<RM_PROCESS_INFO> =
                    (0..room).map(|_| unsafe { std::mem::zeroed() }).collect();
                let (mut needed, mut count, mut reasons) = (0u32, room as u32, 0u32);
                // SAFETY: storage for `count` entries.
                let listed = unsafe {
                    RmGetList(
                        session,
                        &mut needed,
                        &mut count,
                        infos.as_mut_ptr(),
                        &mut reasons,
                    )
                };
                // ERROR_MORE_DATA: the list grew; ask again with room.
                if listed == 234 && (needed as usize) > room {
                    room = needed as usize;
                    continue;
                }
                if listed != 0 {
                    return Err(io::Error::from_raw_os_error(listed as i32));
                }
                return Ok(infos[..count as usize]
                    .iter()
                    .map(|info| {
                        let name = &info.strAppName;
                        let length = name
                            .iter()
                            .position(|unit| *unit == 0)
                            .unwrap_or(name.len());
                        Holder {
                            name: String::from_utf16_lossy(&name[..length]),
                            pid: info.Process.dwProcessId,
                        }
                    })
                    .collect());
            }
        })();
        // SAFETY: the session started above, ended once.
        unsafe { RmEndSession(session) };
        result
    }

    /// What holds the volume, as far as this run's hints let it say.
    pub fn now() -> String {
        let Some(hints) = get() else {
            return String::new();
        };
        let found = holders(&hints.paths).unwrap_or_default();
        let mut providers: Vec<(String, String)> = Vec::new();
        for placeholder in &hints.placeholders {
            if let Ok(root) = crate::cloud_native::sync_root(placeholder)
                && root.running()
                && !providers.iter().any(|(name, _)| *name == root.provider)
            {
                providers.push((root.provider, placeholder.display().to_string()));
            }
        }
        describe(&found, &providers)
    }
}

#[cfg(windows)]
pub use native::{holders, now};

#[cfg(not(windows))]
pub fn now() -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holders_and_providers_are_named() {
        let text = describe(
            &[Holder {
                name: "Microsoft OneDrive".into(),
                pid: 1234,
            }],
            &[("OneDrive".into(), "V:\\Users\\a\\OneDrive\\x.docx".into())],
        );
        assert!(
            text.contains("Microsoft OneDrive (pid 1234) holds files on it open")
                && text.contains("the cloud provider OneDrive is connected")
                && text.contains("quit OneDrive"),
            "{text}"
        );
        assert_eq!(describe(&[], &[]), "");
    }

    #[test]
    fn a_run_may_wait_longer_than_the_default_and_never_shorter_by_accident() {
        assert_eq!(patience(), DEFAULT_PATIENCE);
        set(LockHints {
            patience: Duration::from_secs(300),
            ..LockHints::default()
        });
        let longer = patience();
        set(LockHints::default());
        let zero = patience();
        *HINTS.lock().unwrap() = None;
        assert_eq!(longer, Duration::from_secs(300));
        assert_eq!(zero, DEFAULT_PATIENCE);
    }
}
