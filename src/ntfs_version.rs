//! What a run does with the NTFS version $Volume states.
//!
//! Conversion reads NTFS 3.1 (Windows XP and later), NTFS 3.0 (Windows 2000)
//! and NTFS 1.2 (Windows NT 4.0) itself.
//!
//! NTFS 3.0 and 3.1 share every on-disk structure the converter reads except
//! the FILE record header: NTFS 3.1 puts the record's own number at 0x2C and
//! its update sequence array at 0x30, NTFS 3.0 has no record-number field and
//! puts the array at 0x2A. Every record is read from the offsets its own
//! header states (each checked against the record's size), and its number is
//! taken from its position in $MFT, so a 3.0 volume that Windows XP or later
//! has written to, which holds both header forms, reads as well. (Linux
//! ntfs-3g `layout.h`, `MFT_RECORD` and `MFT_RECORD_OLD`; its `mft.c` places
//! the array at 0x2A exactly when the volume is older than 3.1.)
//!
//! NTFS 1.2 has the 3.0 record header and, besides, the layout of NT 4.0
//! ([`legacy_layout`]): no `$Extend` (so no object-ID, quota or reparse-point
//! index, no USN journal and no transaction metadata), no `$Secure` (record 9
//! is `$Quota`, records 11 to 15 are reserved), a `$SECURITY_DESCRIPTOR`
//! (0x50) on every file in place of a security ID, and the 48-byte
//! `$STANDARD_INFORMATION` without owner, security, quota or USN fields. Its
//! attribute types 0x40 ($VOLUME_VERSION), 0xC0 ($SYMBOLIC_LINK) and 0xF0
//! ($PROPERTY_SET) are not the object ID, reparse point and EA of 3.x; a file
//! that has one is refused on such a volume rather than read as the 3.x
//! attribute.

/// The versions a conversion reads itself, oldest first.
pub const READ: [(u8, u8); 3] = [(1, 2), (3, 0), (3, 1)];

/// What a run does with a volume of a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// NTFS 1.2, 3.0 or 3.1: converted as it is.
    Read,
    /// Any other version: refused by the frozen inspection, as before.
    Unsupported,
}

pub fn disposition(version: (u8, u8)) -> Disposition {
    if reads(version) {
        Disposition::Read
    } else {
        Disposition::Unsupported
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

/// Whether a volume of this version has NT 4.0's layout: no `$Extend` and
/// no `$Secure`, a descriptor on every file. NTFS 1.2 has it; 3.x does not.
pub fn legacy_layout(version: (u8, u8)) -> bool {
    version.0 < 3
}

/// [`legacy_layout`] for the inspection's "major.minor" form. (A version
/// that is not read is refused by its own blocker whatever this says.)
pub fn legacy_layout_text(version: Option<&str>) -> bool {
    version.and_then(parse).is_some_and(legacy_layout)
}

/// The version in the inspection's "major.minor" form.
pub fn parse(text: &str) -> Option<(u8, u8)> {
    let (major, minor) = text.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

pub fn describe(version: (u8, u8)) -> String {
    format!("{}.{}", version.0, version.1)
}

/// The versions read, as said to the user: "NTFS 1.2, 3.0 or 3.1".
pub fn describe_read() -> String {
    let all: Vec<String> = READ.iter().map(|&v| describe(v)).collect();
    let (last, rest) = all.split_last().expect("versions are read");
    format!("NTFS {} or {last}", rest.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read_or_refused() {
        for version in [(1, 2), (3, 0), (3, 1)] {
            assert_eq!(disposition(version), Disposition::Read, "{version:?}");
        }
        for other in [(1, 0), (1, 1), (2, 0), (3, 2), (4, 0), (0, 0)] {
            assert_eq!(disposition(other), Disposition::Unsupported, "{other:?}");
            assert!(!reads(other), "{other:?}");
        }
        assert!(reads_text(Some("1.2")) && reads_text(Some("3.0")) && reads_text(Some("3.1")));
        assert!(!reads_text(Some("1.1")) && !reads_text(None) && !reads_text(Some("3")));
        assert_eq!(parse("3.0"), Some((3, 0)));
        assert_eq!(parse("1.2"), Some((1, 2)));
        assert_eq!(parse("3"), None);
        assert_eq!(parse("x.1"), None);
        assert_eq!(describe_read(), "NTFS 1.2, 3.0 or 3.1");
    }

    #[test]
    fn only_nt4_volumes_have_the_legacy_layout() {
        assert!(legacy_layout_text(Some("1.2")));
        for version in ["3.0", "3.1", "x.y"] {
            assert!(!legacy_layout_text(Some(version)), "{version}");
        }
        assert!(!legacy_layout_text(None));
    }
}
