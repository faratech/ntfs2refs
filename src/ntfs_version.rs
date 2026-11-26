//! What a run does with the NTFS version $Volume states.
//!
//! Conversion reads NTFS 3.1 (Windows XP and later) and NTFS 3.0 (Windows
//! 2000) itself. The two share every on-disk structure the converter reads
//! except the FILE record header: NTFS 3.1 puts the record's own number at
//! 0x2C and its update sequence array at 0x30, NTFS 3.0 has no record-number
//! field and puts the array at 0x2A. Every record is read from the offsets
//! its own header states (each checked against the record's size), and its
//! number is taken from its position in $MFT, so a 3.0 volume that Windows
//! XP or later has written to, which holds both header forms, reads as well.
//! (Linux ntfs-3g `layout.h`, `MFT_RECORD` and `MFT_RECORD_OLD`; its
//! `mft.c` places the array at 0x2A exactly when the volume is older than
//! 3.1.)
//!
//! NTFS 1.2 (Windows NT 4.0) is not read: it has no `$Extend` and no
//! `$Secure` (record 9 is `$Quota` there), which the inspection, the
//! security reconciliation and the admission gates all expect. With the
//! user's agreement, given with the conversion's own question, Windows
//! mounts such a volume read-write before the freeze, in case it upgrades it,
//! and the version is read again from the raw partition. Windows 11 (build
//! 26300) did not upgrade an NTFS 3.0 volume that way in the lab, so the
//! run says it may not happen; a volume that still reads 1.2 afterwards stops
//! the run, with nothing else changed.

/// The versions a conversion reads itself, oldest first.
pub const READ: [(u8, u8); 2] = [(3, 0), (3, 1)];

/// What a run does with a volume of a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// NTFS 3.0 or 3.1: converted as it is.
    Read,
    /// NTFS 1.2: Windows is asked to upgrade it before the freeze.
    WindowsUpgrades,
    /// Any other version: refused by the frozen inspection, as before.
    Unsupported,
}

pub fn disposition(version: (u8, u8)) -> Disposition {
    match version {
        version if reads(version) => Disposition::Read,
        (1, 2) => Disposition::WindowsUpgrades,
        _ => Disposition::Unsupported,
    }
}

/// Whether the converter reads a volume of this version itself.
pub fn reads(version: (u8, u8)) -> bool {
    READ.contains(&version)
}

/// [`reads`] for the inspection's "major.minor" form; `None` is not read.
pub fn reads_text(version: Option<&str>) -> bool {
    version.and_then(parse).is_some_and(reads)
}

/// The version in the inspection's "major.minor" form.
pub fn parse(text: &str) -> Option<(u8, u8)> {
    let (major, minor) = text.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

pub fn describe(version: (u8, u8)) -> String {
    format!("{}.{}", version.0, version.1)
}

/// The versions read, as said to the user: "NTFS 3.0 or 3.1".
pub fn describe_read() -> String {
    format!("NTFS {} or {}", describe(READ[0]), describe(READ[1]))
}

/// Said before the question, and by `--check`.
pub fn upgrade_note(version: (u8, u8)) -> String {
    format!(
        "This volume is NTFS {}, which the converter does not read; it reads {}. Before conversion, Windows mounts it read-write so that it may upgrade it; an upgrade is not undone. Windows 11 has been seen not to upgrade an older NTFS volume this way: if it stays NTFS {}, the run stops there, with nothing else changed.",
        describe(version),
        describe_read(),
        describe(version),
    )
}

/// Why a diagnose run does not start on such a volume.
pub fn diagnose_refusal(version: (u8, u8)) -> String {
    format!(
        "--diagnose cannot run on this volume: it is NTFS {}, which the converter does not read ({} is read); a conversion would first have Windows mount it read-write so that it may upgrade it, and diagnose never changes the source. Nothing was changed.",
        describe(version),
        describe_read(),
    )
}

/// Why a run stops when the volume still reads a version the converter does
/// not read after Windows mounted it.
pub fn still_older(
    before: (u8, u8),
    after: (u8, u8),
    windows_reported: Option<(u16, u16)>,
    run: &std::path::Path,
) -> String {
    format!(
        "Windows mounted this volume read-write and it still reads NTFS {} on the disk (it read {} before{}); a conversion reads {}. The volume was not changed except that Windows mounted it. Upgrade it by mounting it on a Windows that upgrades it (Windows 2000 upgrades NTFS 1.2), or copy its files to a new volume. Records: {}",
        describe(after),
        describe(before),
        windows_reported
            .map(|(major, minor)| format!(", and Windows reported {major}.{minor} for it"))
            .unwrap_or_default(),
        describe_read(),
        run.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read_upgraded_or_refused() {
        assert_eq!(disposition((3, 1)), Disposition::Read);
        assert_eq!(disposition((3, 0)), Disposition::Read);
        assert_eq!(disposition((1, 2)), Disposition::WindowsUpgrades);
        for other in [(1, 0), (1, 1), (2, 0), (3, 2), (4, 0), (0, 0)] {
            assert_eq!(disposition(other), Disposition::Unsupported, "{other:?}");
            assert!(!reads(other), "{other:?}");
        }
        assert!(reads_text(Some("3.0")) && reads_text(Some("3.1")));
        assert!(!reads_text(Some("1.2")) && !reads_text(None) && !reads_text(Some("3")));
        assert_eq!(parse("3.0"), Some((3, 0)));
        assert_eq!(parse("1.2"), Some((1, 2)));
        assert_eq!(parse("3"), None);
        assert_eq!(parse("x.1"), None);
    }

    #[test]
    fn the_upgrade_is_announced_as_uncertain_and_not_undone() {
        let note = upgrade_note((1, 2));
        assert!(note.contains("NTFS 1.2"), "{note}");
        assert!(note.contains("reads NTFS 3.0 or 3.1"), "{note}");
        assert!(note.contains("an upgrade is not undone"), "{note}");
        assert!(note.contains("may upgrade it"), "{note}");
        // Nothing promises that Windows upgrades it.
        assert!(!note.contains("Windows will upgrade"), "{note}");
        let refusal = diagnose_refusal((1, 2));
        assert!(refusal.contains("NTFS 1.2"), "{refusal}");
        assert!(!refusal.contains("3.1, and"), "{refusal}");
        let stopped = still_older((1, 2), (1, 2), Some((1, 2)), std::path::Path::new("run"));
        assert!(stopped.contains("still reads NTFS 1.2"), "{stopped}");
        assert!(stopped.contains("Windows reported 1.2"), "{stopped}");
        assert!(stopped.contains("reads NTFS 3.0 or 3.1"), "{stopped}");
        assert!(stopped.contains("not changed except that Windows mounted it"));
    }
}
