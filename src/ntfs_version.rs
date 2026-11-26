//! What a run does with the NTFS version $Volume states.
//!
//! Conversion reads NTFS 3.1. A volume of NTFS 1.2 (Windows NT 4.0) or 3.0
//! (Windows 2000) is not refused: with the user's agreement, given with the
//! conversion's own question, Windows mounts it read-write before the
//! freeze, which upgrades it to 3.1, and the version is read again from the
//! raw partition. The upgrade is not undone. A volume that still reads an
//! older version afterwards stops the run, with nothing else changed.
//!
//! That Windows upgrades an older NTFS volume when it mounts it read-write
//! is the long-standing behaviour of the NTFS driver; no Microsoft Learn
//! page states it for current Windows, so the run reads the version again
//! instead of relying on it.

/// The version a conversion reads.
pub const CURRENT: (u8, u8) = (3, 1);

/// What a run does with a volume of a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// NTFS 3.1: converted as it is.
    Current,
    /// NTFS 1.2 or 3.0: Windows upgrades it to 3.1 before the freeze.
    WindowsUpgrades,
    /// Any other version: refused by the frozen inspection, as before.
    Unsupported,
}

pub fn disposition(version: (u8, u8)) -> Disposition {
    match version {
        CURRENT => Disposition::Current,
        (1, 2) | (3, 0) => Disposition::WindowsUpgrades,
        _ => Disposition::Unsupported,
    }
}

/// The version in the inspection's "major.minor" form.
pub fn parse(text: &str) -> Option<(u8, u8)> {
    let (major, minor) = text.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

pub fn describe(version: (u8, u8)) -> String {
    format!("{}.{}", version.0, version.1)
}

/// Said before the question, and by `--check`.
pub fn upgrade_note(version: (u8, u8)) -> String {
    format!(
        "This volume is NTFS {}. Windows will upgrade this volume to NTFS 3.1 before conversion; this is not undone.",
        describe(version)
    )
}

/// Why a diagnose run does not start on such a volume.
pub fn diagnose_refusal(version: (u8, u8)) -> String {
    format!(
        "--diagnose cannot run on this volume: it is NTFS {}, a conversion would first have Windows upgrade it to NTFS 3.1, and diagnose never changes the source. Nothing was changed.",
        describe(version)
    )
}

/// Why a run stops when the volume still reads an older version after
/// Windows mounted it.
pub fn still_older(
    before: (u8, u8),
    after: (u8, u8),
    windows_reported: Option<(u16, u16)>,
    run: &std::path::Path,
) -> String {
    format!(
        "Windows mounted this volume read-write and it still reads NTFS {} on the disk (it read {} before{}); a conversion needs NTFS 3.1. The volume was not changed except that Windows mounted it. Upgrade it by mounting it on a Windows that upgrades it, or copy its files to a new volume. Records: {}",
        describe(after),
        describe(before),
        windows_reported
            .map(|(major, minor)| format!(", and Windows reported {major}.{minor} for it"))
            .unwrap_or_default(),
        run.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_converted_upgraded_or_refused() {
        assert_eq!(disposition((3, 1)), Disposition::Current);
        assert_eq!(disposition((3, 0)), Disposition::WindowsUpgrades);
        assert_eq!(disposition((1, 2)), Disposition::WindowsUpgrades);
        for other in [(1, 0), (1, 1), (2, 0), (3, 2), (4, 0), (0, 0)] {
            assert_eq!(disposition(other), Disposition::Unsupported, "{other:?}");
        }
        assert_eq!(parse("3.0"), Some((3, 0)));
        assert_eq!(parse("1.2"), Some((1, 2)));
        assert_eq!(parse("3"), None);
        assert_eq!(parse("x.1"), None);
    }

    #[test]
    fn the_upgrade_is_announced_as_not_undone() {
        let note = upgrade_note((3, 0));
        assert!(note.contains("NTFS 3.0"), "{note}");
        assert!(
            note.contains(
                "Windows will upgrade this volume to NTFS 3.1 before conversion; this is not undone"
            ),
            "{note}"
        );
        assert!(diagnose_refusal((1, 2)).contains("NTFS 1.2"));
        let stopped = still_older((3, 0), (3, 0), Some((3, 0)), std::path::Path::new("run"));
        assert!(stopped.contains("still reads NTFS 3.0"), "{stopped}");
        assert!(stopped.contains("Windows reported 3.0"), "{stopped}");
        assert!(stopped.contains("not changed except that Windows mounted it"));
    }
}
