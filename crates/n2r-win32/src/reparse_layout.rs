//! Bounded Microsoft symlink/mount-point REPARSE_DATA_BUFFER grammar.
//! Targets are retained as bytes, never normalized, resolved or followed.
//! Microsoft layout: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer
use serde::{Deserialize, Serialize};
use std::io;

pub const MAX_REPARSE_BYTES: usize = 16 * 1024;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xa000_000c;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xa000_0003;
pub const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001b;
const HEADER_BYTES: usize = 8;

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
        0xa000_001d | 0x8000_0023 | 0x8000_0024 | 0x8000_0025 | 0x8000_0026 => {
            " (a Windows Subsystem for Linux file: move the Linux files off the volume)"
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
        let fixed = match self.tag() {
            IO_REPARSE_TAG_SYMLINK => {
                if dword(bytes, HEADER_BYTES + 8)? > 1 {
                    return Err(invalid("unsupported symbolic-link flags"));
                }
                12
            }
            IO_REPARSE_TAG_MOUNT_POINT => 8,
            tag => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "a reparse point of tag {tag:#010x}{} is not one the converter recreates (it carries over symbolic links, junctions and app execution aliases)",
                        unsupported_tag_meaning(tag)
                    ),
                ));
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
        assert_eq!(unsupported_tag_meaning(0x1234_5678), "");
    }
}
