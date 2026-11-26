//! Bounded Microsoft symlink/mount-point REPARSE_DATA_BUFFER grammar.
//! Targets are retained as bytes, never normalized, resolved or followed.
//! Microsoft layout: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer
use serde::{Deserialize, Serialize};
use std::io;

pub const MAX_REPARSE_BYTES: usize = 16 * 1024;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xa000_000c;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xa000_0003;
pub const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001b;
/// A symbolic link made by the Windows Subsystem for Linux: its target, as
/// Linux spells it, in the point's data.
pub const IO_REPARSE_TAG_LX_SYMLINK: u32 = 0xa000_001d;
/// The other files of the Windows Subsystem for Linux that are no ordinary
/// files: a socket, a FIFO, a character device and a block device. Their
/// points have no data; what they are beyond the tag is in the file's
/// extended attributes.
pub const LX_SPECIAL_TAGS: [u32; 4] = [0x8000_0023, 0x8000_0024, 0x8000_0025, 0x8000_0026];

/// Whether the tag is one the Windows Subsystem for Linux gives its files.
/// Such a file keeps owner and mode in extended attributes beside its
/// reparse point, which no other kind of reparse point may have.
pub fn is_wsl_tag(tag: u32) -> bool {
    tag == IO_REPARSE_TAG_LX_SYMLINK || LX_SPECIAL_TAGS.contains(&tag)
}
const HEADER_BYTES: usize = 8;
/// A file WOF keeps compressed (`compact /exe`, CompactOS).
pub const IO_REPARSE_TAG_WOF: u32 = 0x8000_0017;
/// A file Data Deduplication has optimized: its data is in the volume's
/// chunk store, which the dedup filter reads it back from.
pub const IO_REPARSE_TAG_DEDUP: u32 = 0x8000_0013;

/// Whether `buffer` is a Data Deduplication reparse point, read as far as
/// its common header goes: the tag, no reserved bits, and data of the
/// length the header gives, which is the dedup filter's own (its stream map
/// reference; nothing here reads it). A file that holds one is made plain
/// from what the filter reads (`dedup_rehydrated`), never recreated.
pub fn is_dedup_point(buffer: &[u8]) -> bool {
    buffer.len() > HEADER_BYTES
        && buffer.len() <= MAX_REPARSE_BYTES
        && dword(buffer, 0).ok() == Some(IO_REPARSE_TAG_DEDUP)
        && word(buffer, 6).ok() == Some(0)
        && word(buffer, 4)
            .ok()
            .is_some_and(|data| HEADER_BYTES + usize::from(data) == buffer.len())
}

/// The named stream in which WOF's file provider keeps the compressed data.
pub const WOF_COMPRESSED_DATA: &str = "WofCompressedData";
/// WOF's file-provider algorithms: XPRESS4K, LZX, XPRESS8K, XPRESS16K.
pub const WOF_ALGORITHMS: [(u32, &str); 4] = [
    (0, "XPRESS4K"),
    (1, "LZX"),
    (2, "XPRESS8K"),
    (3, "XPRESS16K"),
];

/// The algorithm of a WOF reparse point of the file provider, read exactly:
/// the common header (the tag and the length of its data), WOF_EXTERNAL_INFO
/// (version 1, provider 2: a file) and the file provider's version 1 and
/// algorithm. That is the 16 bytes WOF writes on the disk
/// (FILE_PROVIDER_EXTERNAL_INFO_V0, as `compact /exe` leaves it in the lab);
/// the 20 of FILE_PROVIDER_EXTERNAL_INFO_V1 are read too, with no flags.
/// `None` for anything else, a WIM-backed file among them.
pub fn wof_file_algorithm(buffer: &[u8]) -> Option<u32> {
    let field = |at: usize| dword(buffer, at).ok();
    let data = usize::from(word(buffer, 4).ok()?);
    (matches!(data, 16 | 20)
        && buffer.len() == HEADER_BYTES + data
        && field(0)? == IO_REPARSE_TAG_WOF
        && word(buffer, 6).ok()? == 0
        && field(8)? == 1
        && field(12)? == 2
        && field(16)? == 1
        && (data == 16 || field(24)? == 0))
        .then(|| field(20))
        .flatten()
        .filter(|algorithm| WOF_ALGORITHMS.iter().any(|(known, _)| known == algorithm))
}

/// IO_REPARSE_TAG_CLOUD and its sixteen variants (0x9000x01A): the
/// placeholders of a Cloud Files API provider, such as OneDrive.
pub fn is_cloud_tag(tag: u32) -> bool {
    tag & 0xffff_0fff == 0x9000_001a
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Point {
    pub buffer: Vec<u8>,
}
/// What a reparse tag the converter does not carry over belongs to, and
/// what to do about it, for a refusal.
pub fn unsupported_tag_meaning(tag: u32) -> &'static str {
    match tag {
        0x8000_0013 => {
            " (Data Deduplication: turn deduplication off for the volume and let it rehydrate the files)"
        }
        0x8000_0017 => {
            " (a file compressed with `compact /exe` or by CompactOS: expand it with `compact /u /exe <file>`)"
        }
        0x9000_001c | 0xa000_0022 => {
            " (a projected file system, such as a virtualized Git repository)"
        }
        // The cloud-files tags differ in their fourth hex digit only.
        tag if tag & 0xffff_0fff == 0x9000_001a => {
            " (a cloud placeholder, such as OneDrive Files On-Demand: make the files always available on this device, or move the folder off the volume)"
        }
        0xc000_0004 | 0x8000_0006 | 0x8000_0007 => " (Remote Storage or Single Instance Storage)",
        _ => "",
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn word(bytes: &[u8], at: usize) -> io::Result<u16> {
    let end = at
        .checked_add(2)
        .ok_or_else(|| invalid("reparse word overflow"))?;
    let field = bytes
        .get(at..end)
        .ok_or_else(|| invalid("short reparse word"))?;
    Ok(u16::from_le_bytes(field.try_into().unwrap()))
}
fn dword(bytes: &[u8], at: usize) -> io::Result<u32> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| invalid("reparse dword overflow"))?;
    let field = bytes
        .get(at..end)
        .ok_or_else(|| invalid("short reparse dword"))?;
    Ok(u32::from_le_bytes(field.try_into().unwrap()))
}
fn name(paths: &[u8], offset: u16, length: u16, required: bool) -> io::Result<()> {
    let offset = usize::from(offset);
    let length = usize::from(length);
    if !offset.is_multiple_of(2) || !length.is_multiple_of(2) || (required && length == 0) {
        return Err(invalid("reparse name offset/length is unaligned or empty"));
    }
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("reparse name overflow"))?;
    let bytes = paths
        .get(offset..end)
        .ok_or_else(|| invalid("reparse name escapes PathBuffer"))?;
    let units = bytes
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]));
    for character in char::decode_utf16(units) {
        match character {
            Ok('\0') | Err(_) => {
                return Err(invalid("reparse name contains NUL or invalid UTF-16"));
            }
            Ok(_) => (),
        }
    }
    Ok(())
}
impl Point {
    /// An explicit relative path alias in the same parent directory. This is
    /// used by journaled Windows short-name preparation, never a filesystem
    /// short-name claim. The eventual creator owns file/directory semantics.
    pub fn relative_component_alias(target: &[u16]) -> io::Result<Self> {
        if target.is_empty()
            || target.len() > 255
            || target == [46]
            || target == [46, 46]
            || target.iter().any(|c| matches!(*c, 0 | 47 | 58 | 92))
        {
            return Err(invalid(
                "relative alias requires one canonical name component",
            ));
        }
        if char::decode_utf16(target.iter().copied()).any(|c| c.is_err()) {
            return Err(invalid("relative alias target is not valid UTF-16"));
        }
        let size = u16::try_from(target.len() * 2)
            .map_err(|_| invalid("relative alias name length overflow"))?;
        // Substitute name then an identical print name, as mklink writes them.
        // ReFS refuses a symbolic link whose print name is empty with
        // ERROR_INVALID_REPARSE_DATA (observed on Windows 11 build 26300).
        let mut buffer = Vec::with_capacity(20 + 2 * usize::from(size));
        buffer.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
        buffer.extend_from_slice(&(12 + 2 * size).to_le_bytes());
        buffer.extend_from_slice(&[0, 0]);
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&size.to_le_bytes());
        buffer.extend_from_slice(&size.to_le_bytes());
        buffer.extend_from_slice(&size.to_le_bytes());
        buffer.extend_from_slice(&1u32.to_le_bytes());
        for _ in 0..2 {
            for c in target {
                buffer.extend_from_slice(&c.to_le_bytes());
            }
        }
        let point = Self { buffer };
        point.validate()?;
        Ok(point)
    }
    /// Raw tag only. Malformed short buffers return zero and must still fail
    /// validate(); this getter never makes serialized bytes trustworthy.
    pub fn tag(&self) -> u32 {
        self.buffer
            .get(..4)
            .and_then(|v| v.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0)
    }
    pub fn validate(&self) -> io::Result<()> {
        let bytes = &self.buffer;
        if !(HEADER_BYTES..=MAX_REPARSE_BYTES).contains(&bytes.len())
            || HEADER_BYTES + usize::from(word(bytes, 4)?) != bytes.len()
        {
            return Err(invalid(
                "reparse buffer length differs from its common header",
            ));
        }
        if self.tag() == IO_REPARSE_TAG_APPEXECLINK {
            // Observed Windows application-execution alias format. Preserve
            // every byte, including optional trailing strings; never resolve
            // or reinterpret the package, AUMID or executable path.
            if dword(bytes, 8)? != 3 {
                return Err(invalid("unsupported application-execution alias version"));
            }
            let strings = bytes
                .get(12..)
                .ok_or_else(|| invalid("short application-execution alias"))?;
            if !strings.len().is_multiple_of(2)
                || strings.last() != Some(&0)
                || strings.get(strings.len().saturating_sub(2)) != Some(&0)
            {
                return Err(invalid(
                    "application-execution alias string framing differs",
                ));
            }
            let mut count = 0usize;
            let mut length = 0usize;
            for c in char::decode_utf16(
                strings
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]])),
            ) {
                match c {
                    Ok('\0') => {
                        if count < 3 && length == 0 {
                            return Err(invalid("empty application-execution alias field"));
                        }
                        count += 1;
                        length = 0;
                    }
                    Ok(_) => length += 1,
                    Err(_) => return Err(invalid("invalid application-execution alias UTF-16")),
                }
            }
            if count < 3 {
                return Err(invalid("incomplete application-execution alias fields"));
            }
            return Ok(());
        }
        // The Windows Subsystem for Linux. ReFS takes these tags and the
        // extended attributes beside them as NTFS does (a native control on
        // Windows 11 build 26300). Every byte is kept; nothing is resolved.
        if self.tag() == IO_REPARSE_TAG_LX_SYMLINK {
            // A version, 2, and the target in UTF-8, as Linux spells it.
            let target = bytes
                .get(HEADER_BYTES + 4..)
                .ok_or_else(|| invalid("short Linux symbolic link"))?;
            if dword(bytes, HEADER_BYTES)? != 2
                || target.is_empty()
                || target.contains(&0)
                || std::str::from_utf8(target).is_err()
            {
                return Err(invalid(
                    "a Linux symbolic link of another version, or with a target that is not UTF-8",
                ));
            }
            return Ok(());
        }
        // A file WOF's file provider keeps compressed, read exactly. It is
        // never recreated: such a file is converted to a plain file once the
        // user agrees (`wof_expanded`), and refused otherwise by admission,
        // with the remedy of `unsupported_tag_meaning`.
        if self.tag() == IO_REPARSE_TAG_WOF && wof_file_algorithm(bytes).is_some() {
            return Ok(());
        }
        // A cloud provider's placeholder: its data is the provider's own and
        // is read as bytes only. It is never recreated either: such an
        // object is made plain once the user agrees
        // (`cloud_placeholder_plain`), and refused otherwise by admission.
        if is_cloud_tag(self.tag()) {
            return Ok(());
        }
        // A deduplicated file, likewise: made plain once agreed
        // (`dedup_rehydrated`), and refused otherwise by admission.
        if self.tag() == IO_REPARSE_TAG_DEDUP && is_dedup_point(bytes) {
            return Ok(());
        }
        if LX_SPECIAL_TAGS.contains(&self.tag()) {
            if bytes.len() != HEADER_BYTES {
                return Err(invalid(
                    "a Linux socket, FIFO or device file whose reparse point carries data",
                ));
            }
            return Ok(());
        }
        let fixed = match self.tag() {
            IO_REPARSE_TAG_SYMLINK => {
                if dword(bytes, HEADER_BYTES + 8)? > 1 {
                    return Err(invalid("unsupported symbolic-link flags"));
                }
                12
            }
            IO_REPARSE_TAG_MOUNT_POINT => 8,
            tag => {
                // A decision about a reparse point that was read in full,
                // not a structure that could not be read.
                return Err(crate::refusal::io_error(format!(
                    "a reparse point of tag {tag:#010x}{} is not one the converter recreates (it carries over symbolic links, junctions, app execution aliases and the files of the Windows Subsystem for Linux)",
                    unsupported_tag_meaning(tag)
                )));
            }
        };
        let paths = bytes
            .get(HEADER_BYTES + fixed..)
            .ok_or_else(|| invalid("short reparse type-specific header"))?;
        if !paths.len().is_multiple_of(2) {
            return Err(invalid("reparse PathBuffer has an odd byte length"));
        }
        // Offsets are relative to PathBuffer, not the common/type header.
        name(paths, word(bytes, 8)?, word(bytes, 10)?, true)?;
        name(paths, word(bytes, 12)?, word(bytes, 14)?, false)?;
        // Reserved is explicitly ignored by the Microsoft query/set contract.
        // Unused bytes, terminators and name placement remain byte-identical.
        Ok(())
    }
}
pub fn parse(buffer: &[u8]) -> io::Result<Point> {
    if buffer.len() > MAX_REPARSE_BYTES {
        return Err(invalid("reparse buffer exceeds sixteen KiB"));
    }
    let point = Point {
        buffer: buffer.to_vec(),
    };
    point.validate()?;
    Ok(point)
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    fn wof_point(algorithm: u32) -> Vec<u8> {
        let mut point = Vec::new();
        point.extend_from_slice(&IO_REPARSE_TAG_WOF.to_le_bytes());
        point.extend_from_slice(&20u16.to_le_bytes());
        point.extend_from_slice(&0u16.to_le_bytes());
        for value in [1u32, 2, 1, algorithm, 0] {
            point.extend_from_slice(&value.to_le_bytes());
        }
        point
    }

    /// The point as WOF writes it on the disk: 16 bytes of data.
    fn wof_point_on_disk(algorithm: u32) -> Vec<u8> {
        let mut point = Vec::new();
        point.extend_from_slice(&IO_REPARSE_TAG_WOF.to_le_bytes());
        point.extend_from_slice(&16u16.to_le_bytes());
        point.extend_from_slice(&0u16.to_le_bytes());
        for value in [1u32, 2, 1, algorithm] {
            point.extend_from_slice(&value.to_le_bytes());
        }
        point
    }

    #[test]
    fn a_wof_point_as_written_on_the_disk_is_validated_not_refused() {
        for (algorithm, _) in WOF_ALGORITHMS {
            let point = wof_point_on_disk(algorithm);
            assert_eq!(wof_file_algorithm(&point), Some(algorithm));
            // The raw inspection validates every point it reads, and a
            // refusal there stops the reading before anything classifies
            // the file (lab, wof-plain: "is not one the converter
            // recreates").
            parse(&point).unwrap();
        }
        // A WIM-backed one is still refused by its tag, with its remedy.
        let mut wim = wof_point_on_disk(1);
        wim[12..16].copy_from_slice(&1u32.to_le_bytes());
        let refusal = parse(&wim).unwrap_err().to_string();
        assert!(refusal.contains("compact /u /exe"), "{refusal}");
        // A length that is neither form.
        let mut odd = wof_point_on_disk(1);
        odd.extend_from_slice(&[0; 4]);
        odd[4..6].copy_from_slice(&20u16.to_le_bytes());
        odd[24..28].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse(&odd).is_err());
    }

    #[test]
    fn a_dedup_point_is_read_by_its_header_and_not_refused() {
        let mut point = Vec::new();
        point.extend_from_slice(&IO_REPARSE_TAG_DEDUP.to_le_bytes());
        point.extend_from_slice(&80u16.to_le_bytes());
        point.extend_from_slice(&0u16.to_le_bytes());
        point.extend_from_slice(&[0x5a; 80]);
        assert!(is_dedup_point(&point));
        parse(&point).unwrap();
        // Reserved bits, a length the header does not give, no data at all.
        let mut reserved = point.clone();
        reserved[6] = 1;
        assert!(!is_dedup_point(&reserved));
        assert!(!is_dedup_point(&point[..40]));
        assert!(!is_dedup_point(&point[..8]));
        let refusal = parse(&reserved).unwrap_err().to_string();
        assert!(refusal.contains("Data Deduplication"), "{refusal}");
    }

    #[test]
    fn a_wof_file_point_is_read_exactly() {
        for (algorithm, _) in WOF_ALGORITHMS {
            assert_eq!(wof_file_algorithm(&wof_point(algorithm)), Some(algorithm));
        }
        assert_eq!(wof_file_algorithm(&wof_point(4)), None);
        // A WIM-backed file (provider 1), flags, another version, a short
        // or a long point, another tag: none is a file-provider point.
        for (at, value) in [(12usize, 1u32), (24, 1), (8, 2), (16, 2), (0, 0x8000_0013)] {
            let mut point = wof_point(1);
            point[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(wof_file_algorithm(&point), None, "{at}");
        }
        let mut long = wof_point(1);
        long.push(0);
        assert_eq!(wof_file_algorithm(&long), None);
        assert_eq!(wof_file_algorithm(&wof_point(1)[..20]), None);
    }

    #[test]
    fn a_reparse_point_that_is_not_carried_over_is_refused_by_what_it_is() {
        // A file compressed by `compact /exe`: a WOF reparse point.
        let mut wof = vec![0u8; 24];
        wof[..4].copy_from_slice(&0x8000_0017u32.to_le_bytes());
        wof[4..6].copy_from_slice(&16u16.to_le_bytes());
        let refusal = parse(&wof).unwrap_err().to_string();
        assert!(
            refusal.contains("0x80000017") && refusal.contains("compact /u /exe"),
            "{refusal}"
        );
        // Every cloud-files tag, whatever its fourth digit.
        for tag in [0x9000_001au32, 0x9000_301a, 0x9000_f01a] {
            assert!(
                unsupported_tag_meaning(tag).contains("cloud placeholder"),
                "{tag:#x}"
            );
        }
        assert!(unsupported_tag_meaning(0x8000_0013).contains("Deduplication"));
        // What the Windows Subsystem for Linux makes is carried over.
        let point = |tag: u32, data: &[u8]| {
            let mut buffer = tag.to_le_bytes().to_vec();
            buffer.extend_from_slice(&(data.len() as u16).to_le_bytes());
            buffer.extend_from_slice(&[0, 0]);
            buffer.extend_from_slice(data);
            Point { buffer }
        };
        let link = [&2u32.to_le_bytes()[..], b"../etc/hosts"].concat();
        assert!(point(IO_REPARSE_TAG_LX_SYMLINK, &link).validate().is_ok());
        for tag in LX_SPECIAL_TAGS {
            assert!(is_wsl_tag(tag) && point(tag, &[]).validate().is_ok());
            assert!(point(tag, &[1]).validate().is_err());
        }
        assert!(is_wsl_tag(IO_REPARSE_TAG_LX_SYMLINK) && !is_wsl_tag(IO_REPARSE_TAG_SYMLINK));
        // Another version, no target, a NUL in it, or bytes that are not UTF-8.
        for data in [
            [&1u32.to_le_bytes()[..], b"x"].concat(),
            2u32.to_le_bytes().to_vec(),
            [&2u32.to_le_bytes()[..], b"a\0b"].concat(),
            [&2u32.to_le_bytes()[..], &[0xff, 0xfe]].concat(),
        ] {
            assert!(point(IO_REPARSE_TAG_LX_SYMLINK, &data).validate().is_err());
        }
        assert_eq!(unsupported_tag_meaning(0x1234_5678), "");
    }

    #[test]
    fn a_cloud_placeholder_is_read_whole_and_refused_by_admission_not_here() {
        let point = |tag: u32, data: &[u8]| {
            let mut buffer = tag.to_le_bytes().to_vec();
            buffer.extend_from_slice(&(data.len() as u16).to_le_bytes());
            buffer.extend_from_slice(&[0, 0]);
            buffer.extend_from_slice(data);
            Point { buffer }
        };
        // Every cloud-files tag reads, whatever the provider keeps in it.
        for tag in [0x9000_001au32, 0x9000_101a, 0x9000_f01a] {
            assert!(is_cloud_tag(tag), "{tag:#x}");
            assert!(point(tag, &[1, 2, 3, 4]).validate().is_ok(), "{tag:#x}");
            assert!(point(tag, &[]).validate().is_ok(), "{tag:#x}");
        }
        // ProjFS and other tags are not cloud placeholders.
        assert!(!is_cloud_tag(0x9000_001c) && !is_cloud_tag(0x8000_001a));
        assert!(point(0x9000_001c, &[1]).validate().is_err());
        // The common header still has to say the point's length.
        let mut short = point(0x9000_001a, &[1, 2]);
        short.buffer.pop();
        assert!(short.validate().is_err());
    }
}
