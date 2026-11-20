//! A directory's case-sensitive mark (FILE_CASE_SENSITIVE_INFO).
//!
//! Of a mounted NTFS source it is only asked, by the directory's file
//! reference ([`DirectoryCaseProbe`]): the volume and each directory are
//! opened to read attributes, nothing else. On the ReFS volume a conversion
//! builds it is set on each directory as the directory is made, while it is
//! still empty, and read back ([`settle`]), where [`CaseMarkCarry`] says the
//! running Windows was shown to hold such a directory.
use std::{
    fs::{File, OpenOptions},
    io, mem,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType, GetFileInformationByHandleEx,
        OpenFileById, SetFileInformationByHandle,
    },
};

/// FILE_READ_ATTRIBUTES: the only access asked for.
const READ_ATTRIBUTES: u32 = 0x80;
/// FILE_FLAG_BACKUP_SEMANTICS, to open a directory, with
/// FILE_FLAG_OPEN_REPARSE_POINT, so that no reparse point is followed.
const DIRECTORY_AS_ITSELF: u32 = 0x0220_0000;
/// FileCaseSensitiveInfo of FILE_INFO_BY_HANDLE_CLASS. Its answer,
/// FILE_CASE_SENSITIVE_INFO, is one ULONG of flags; 1 is case-sensitive.
const CASE_SENSITIVE_INFO: i32 = 23;

/// A volume whose directories can be asked.
pub struct DirectoryCaseProbe {
    volume: File,
}

impl DirectoryCaseProbe {
    /// `volume_root` is the volume's root directory, for example
    /// `\\?\Volume{...}\`.
    pub fn open(volume_root: &str) -> io::Result<Self> {
        let volume = OpenOptions::new()
            .access_mode(READ_ATTRIBUTES)
            .share_mode(7)
            .custom_flags(DIRECTORY_AS_ITSELF)
            .open(volume_root)?;
        Ok(Self { volume })
    }

    /// The case-sensitivity flags Windows reports for the directory with
    /// this file reference (its record number, with its sequence number in
    /// the top 16 bits): 0 for an ordinary directory, 1 for one marked
    /// case-sensitive. An error is Windows' own, with nothing assumed.
    pub fn flags(&self, file_reference: u64) -> io::Result<u32> {
        let descriptor = FILE_ID_DESCRIPTOR {
            dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                FileId: file_reference as i64,
            },
        };
        // SAFETY: an initialized descriptor and a live volume handle; the
        // access asked for is FILE_READ_ATTRIBUTES alone.
        let handle = unsafe {
            OpenFileById(
                self.volume.as_raw_handle(),
                &descriptor,
                READ_ATTRIBUTES,
                7,
                ptr::null(),
                DIRECTORY_AS_ITSELF,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: sole ownership of the handle just opened.
        let directory = unsafe { File::from_raw_handle(handle) };
        flags(&directory)
    }
}

/// The case-sensitivity flags Windows reports for an open directory: 0 for
/// an ordinary one, 1 for one marked case-sensitive. The handle needs
/// FILE_READ_ATTRIBUTES. An error is Windows' own, with nothing assumed.
pub fn flags(directory: &File) -> io::Result<u32> {
    let mut flags = 0u32;
    // SAFETY: a buffer of exactly the four bytes this class returns, and a
    // live handle, for a synchronous query.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle(),
            CASE_SENSITIVE_INFO,
            (&mut flags as *mut u32).cast(),
            mem::size_of::<u32>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags)
}

/// Sets or clears the mark on an open directory. The handle needs
/// FILE_WRITE_ATTRIBUTES.
fn set(directory: &File, marked: bool) -> io::Result<()> {
    let flags = u32::from(marked);
    // SAFETY: FILE_CASE_SENSITIVE_INFO is one ULONG of flags; the buffer is
    // exactly that, initialized, and the handle is live for the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            directory.as_raw_handle(),
            CASE_SENSITIVE_INFO,
            (&flags as *const u32).cast(),
            mem::size_of::<u32>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What [`settle`] found and did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settled {
    /// The directory already was as the source's: an unmarked one made in an
    /// unmarked directory, or a marked one made in a marked directory, which
    /// Windows marks itself.
    AsMade,
    /// The mark was set.
    Marked,
    /// The mark the directory took from its parent was cleared: the source's
    /// directory is an ordinary one inside a marked one.
    Cleared,
}

/// Makes the mark of a directory that was just made what the source's is,
/// and reads it back. A directory made inside a marked one is marked by
/// Windows, so the mark is asked for first and changed only where it
/// differs, which may mean clearing it. The handle needs
/// FILE_READ_ATTRIBUTES and FILE_WRITE_ATTRIBUTES.
///
/// An error says which step failed and with what; the caller names the
/// directory and the phase.
pub fn settle(directory: &File, marked: bool) -> io::Result<Settled> {
    settle_with(|| flags(directory), |wanted| set(directory, wanted), marked)
}

fn settle_with(
    mut flags: impl FnMut() -> io::Result<u32>,
    set: impl FnOnce(bool) -> io::Result<()>,
    marked: bool,
) -> io::Result<Settled> {
    let step = |what: &str, error: io::Error| {
        io::Error::new(
            error.kind(),
            format!(
                "{what} the case-sensitive mark of the new directory (the source's is {}): {error}",
                if marked { "set" } else { "not set" }
            ),
        )
    };
    let wanted = u32::from(marked);
    let made = flags().map_err(|error| step("asking Windows for", error))?;
    if made > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Windows reports case-sensitivity flags {made:#x} for the new directory, where 0 (an ordinary directory) or 1 (one marked case-sensitive) is what the converter knows"
            ),
        ));
    }
    if made == wanted {
        return Ok(Settled::AsMade);
    }
    set(marked).map_err(|error| step(if marked { "setting" } else { "clearing" }, error))?;
    let read_back = flags().map_err(|error| step("reading back", error))?;
    if read_back != wanted {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Windows accepted {} the case-sensitive mark of the new directory and then reports flags {read_back:#x} for it, not {wanted:#x}",
                if marked { "setting" } else { "clearing" }
            ),
        ));
    }
    Ok(if marked {
        Settled::Marked
    } else {
        Settled::Cleared
    })
}

/// Whether a conversion sets the source's case-sensitive marks on the new
/// volume, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseMarkCarry {
    /// Each directory of the new volume is given the mark its source
    /// directory has, and the mark is read back and verified.
    Carried,
    /// The new volume's directories are left unmarked; the marked ones are
    /// listed in the run's records.
    NotCarried(WhyNotCarried),
}

/// Why the mark is not set on the new volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhyNotCarried {
    /// The running Windows is not one of
    /// [`crate::windows_build::CASE_MARK_BUILDS`].
    Windows { version: [u32; 3], server: bool },
    /// The converter runs in a recovery or preinstallation environment,
    /// which is not the Windows that uses the volume afterwards and was not
    /// shown to hold a marked directory.
    RecoveryEnvironment,
    /// The volume holds a Windows installation: the Windows that mounts it
    /// afterwards is the one on it, not the one the converter runs on.
    WindowsVolume,
}

impl CaseMarkCarry {
    /// The decision for a Windows of `version` (major, minor, build), a
    /// server edition or not, in a recovery environment or not, converting a
    /// volume that holds a Windows installation or a data volume.
    pub fn decide(
        version: [u32; 3],
        server: bool,
        recovery_environment: bool,
        windows_volume: bool,
    ) -> Self {
        if windows_volume {
            Self::NotCarried(WhyNotCarried::WindowsVolume)
        } else if recovery_environment {
            Self::NotCarried(WhyNotCarried::RecoveryEnvironment)
        } else if !crate::windows_build::carries_case_mark(version, server) {
            Self::NotCarried(WhyNotCarried::Windows { version, server })
        } else {
            Self::Carried
        }
    }

    /// The decision for the running Windows.
    pub fn of_this_windows(windows_volume: bool) -> io::Result<Self> {
        Ok(Self::decide(
            crate::run_environment::windows_version()?,
            crate::run_environment::is_windows_server()?,
            crate::offline_environment::in_recovery_environment(),
            windows_volume,
        ))
    }

    pub fn carried(self) -> bool {
        self == Self::Carried
    }
}

impl WhyNotCarried {
    /// The reason, as the sentences of a notice.
    pub fn sentence(self) -> String {
        let shown = crate::windows_build::case_mark_builds();
        match self {
            Self::Windows { version, server } => format!(
                "The converter sets the mark only on {shown}, where Windows was shown to keep such a directory on ReFS; this is Windows {}{}. On Windows 11 build 26300 Windows itself stopped with a bugcheck when a ReFS volume holding a marked directory was taken offline, which a conversion does with the volume it builds.",
                crate::windows_build::describe(version),
                if server { ", a server edition" } else { "" }
            ),
            Self::RecoveryEnvironment => format!(
                "The converter sets the mark only when it runs on {shown}, where Windows was shown to keep such a directory on ReFS; this is a recovery or installation environment."
            ),
            Self::WindowsVolume => format!(
                "The converter sets the mark on data volumes only, on {shown}: the Windows that will start from this volume is not the one the converter runs on."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn the_mark_is_carried_only_to_a_data_volume_on_a_windows_that_was_shown() {
        let server_2025 = [10, 0, 26100];
        assert_eq!(
            CaseMarkCarry::decide(server_2025, true, false, false),
            CaseMarkCarry::Carried
        );
        // The lab's Windows 11, and Windows 11 24H2, whose build number is
        // the server's.
        for version in [[10, 0, 26300], server_2025] {
            assert_eq!(
                CaseMarkCarry::decide(version, false, false, false),
                CaseMarkCarry::NotCarried(WhyNotCarried::Windows {
                    version,
                    server: false
                })
            );
        }
        assert_eq!(
            CaseMarkCarry::decide([10, 0, 27000], true, false, false),
            CaseMarkCarry::NotCarried(WhyNotCarried::Windows {
                version: [10, 0, 27000],
                server: true
            })
        );
        // The server's own recovery environment, and a volume holding a
        // Windows, whichever Windows converts it.
        assert_eq!(
            CaseMarkCarry::decide(server_2025, true, true, false),
            CaseMarkCarry::NotCarried(WhyNotCarried::RecoveryEnvironment)
        );
        assert_eq!(
            CaseMarkCarry::decide(server_2025, true, false, true),
            CaseMarkCarry::NotCarried(WhyNotCarried::WindowsVolume)
        );
        assert!(CaseMarkCarry::Carried.carried());
        assert!(!CaseMarkCarry::decide([10, 0, 26300], false, false, false).carried());
    }

    #[test]
    fn each_reason_names_where_the_mark_is_set_and_what_this_is() {
        let windows = WhyNotCarried::Windows {
            version: [10, 0, 26300],
            server: false,
        }
        .sentence();
        assert!(
            windows.contains("Windows Server 2025 (build 26100)"),
            "{windows}"
        );
        assert!(windows.contains("this is Windows 10.0.26300."), "{windows}");
        assert!(windows.contains("bugcheck"), "{windows}");
        let server = WhyNotCarried::Windows {
            version: [10, 0, 27000],
            server: true,
        }
        .sentence();
        assert!(
            server.contains("this is Windows 10.0.27000, a server edition."),
            "{server}"
        );
        assert!(
            WhyNotCarried::RecoveryEnvironment
                .sentence()
                .contains("recovery or installation environment")
        );
        assert!(
            WhyNotCarried::WindowsVolume
                .sentence()
                .contains("data volumes only")
        );
    }

    /// Settles a directory whose flags are `state`, recording what was set.
    fn settle_fake(
        state: &Cell<u32>,
        sets: &RefCell<Vec<bool>>,
        marked: bool,
    ) -> io::Result<Settled> {
        settle_with(
            || Ok(state.get()),
            |wanted| {
                sets.borrow_mut().push(wanted);
                state.set(u32::from(wanted));
                Ok(())
            },
            marked,
        )
    }

    #[test]
    fn a_new_directory_is_changed_only_where_it_differs_from_the_source() {
        for (made, marked, settled, set) in [
            (0, false, Settled::AsMade, vec![]),
            // Made inside a marked directory: Windows marked it.
            (1, true, Settled::AsMade, vec![]),
            (0, true, Settled::Marked, vec![true]),
            (1, false, Settled::Cleared, vec![false]),
        ] {
            let (state, sets) = (Cell::new(made), RefCell::new(Vec::new()));
            assert_eq!(settle_fake(&state, &sets, marked).unwrap(), settled);
            assert_eq!(*sets.borrow(), set);
            assert_eq!(state.get(), u32::from(marked));
        }
    }

    #[test]
    fn a_mark_that_does_not_read_back_and_each_failed_step_are_errors() {
        // Windows says it set the mark, and the directory is still unmarked.
        let ignored = settle_with(|| Ok(0), |_| Ok(()), true).unwrap_err();
        assert_eq!(ignored.kind(), io::ErrorKind::InvalidData);
        assert!(
            ignored.to_string().contains("accepted setting")
                && ignored
                    .to_string()
                    .contains("reports flags 0x0 for it, not 0x1"),
            "{ignored}"
        );
        let kept = settle_with(|| Ok(1), |_| Ok(()), false).unwrap_err();
        assert!(kept.to_string().contains("accepted clearing"), "{kept}");

        let unknown = settle_with(|| Ok(3), |_| Ok(()), true).unwrap_err();
        assert!(unknown.to_string().contains("flags 0x3"), "{unknown}");

        let refused = || io::Error::from_raw_os_error(50);
        let asking = settle_with(|| Err(refused()), |_| Ok(()), true).unwrap_err();
        assert!(
            asking.to_string().starts_with("asking Windows for"),
            "{asking}"
        );
        let setting = settle_with(|| Ok(0), |_| Err(refused()), true).unwrap_err();
        assert!(
            setting
                .to_string()
                .starts_with("setting the case-sensitive mark")
                && setting.to_string().contains("the source's is set")
                && setting.to_string().contains("os error 50"),
            "{setting}"
        );
        let clearing = settle_with(|| Ok(1), |_| Err(refused()), false).unwrap_err();
        assert!(clearing.to_string().starts_with("clearing"), "{clearing}");
        let asked = Cell::new(0);
        let reading = settle_with(
            || {
                asked.set(asked.get() + 1);
                if asked.get() == 1 {
                    Ok(0)
                } else {
                    Err(refused())
                }
            },
            |_| Ok(()),
            true,
        )
        .unwrap_err();
        assert!(reading.to_string().starts_with("reading back"), "{reading}");
    }
}
