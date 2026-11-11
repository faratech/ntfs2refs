//! Checked EA semantics and independent NTFS/native byte layouts.
//! Windows native layout: FILE_FULL_EA_INFORMATION (MS-FSCC 2.4.16).
//! NTFS EA_INFORMATION's packed count excludes NextEntryOffset and alignment;
//! it is not the byte length of either native or on-disk unpacked records.
//! No native access, allocator changes or conversion authority is provided.
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, io};

/// Bounded initial Windows/NTFS EA profile, not a promise about every filesystem
/// provider. NTFS $EA's documented $AttrDef maximum is 65536 bytes.
pub const MAX_EA_BYTES: usize = 65536;
pub const MAX_ENTRIES: usize = MAX_EA_BYTES / 11;
pub const FILE_NEED_EA: u8 = 0x80;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub flags: u8,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Set {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<Entry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    pub packed_bytes: u16,
    pub need_ea_count: u16,
    /// Canonical native list size; its final entry has no alignment padding.
    pub native_bytes: u32,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn compare_names(a: &[u8], b: &[u8]) -> Ordering {
    a.iter()
        .map(|byte| byte.to_ascii_uppercase())
        .cmp(b.iter().map(|byte| byte.to_ascii_uppercase()))
}
fn entry_size(entry: &Entry) -> io::Result<usize> {
    9usize
        .checked_add(entry.name.len())
        .and_then(|size| size.checked_add(entry.value.len()))
        .ok_or_else(|| invalid("EA record size overflow"))
}
fn align4(size: usize) -> io::Result<usize> {
    size.checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| invalid("EA alignment overflow"))
}
fn validate_entry(entry: &Entry) -> io::Result<()> {
    if !matches!(entry.flags, 0 | FILE_NEED_EA)
        || entry.name.is_empty()
        || entry.name.len() > u8::MAX as usize
        || entry.name.iter().any(|byte| {
            !byte.is_ascii() || *byte < 0x20 || *byte == 0x7f || b"\\/:*?\"<>|,+=[];".contains(byte)
        })
    {
        return Err(invalid(
            "EA flags or ASCII name outside supported Windows profile",
        ));
    }
    // A zero-length native SET value requests deletion. Treating it as a
    // preserved empty value would silently remove the source EA.
    if entry.value.is_empty() || entry.value.len() > u16::MAX as usize {
        return Err(invalid(
            "EA value is empty/deletion-valued or exceeds native length",
        ));
    }
    Ok(())
}
impl Set {
    pub fn new(mut entries: Vec<Entry>) -> io::Result<Self> {
        if entries.len() > MAX_ENTRIES {
            return Err(invalid("EA entry count exceeds bound"));
        }
        for entry in &entries {
            validate_entry(entry)?;
        }
        entries.sort_by(|a, b| compare_names(&a.name, &b.name));
        let set = Self { entries };
        set.validate()?;
        Ok(set)
    }
    pub fn validate(&self) -> io::Result<()> {
        self.sizes().map(|_| ())
    }
    pub fn sizes(&self) -> io::Result<Sizes> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(invalid("EA entry count exceeds bound"));
        }
        let mut packed = 0usize;
        let mut native = 0usize;
        let mut needed = 0usize;
        for (index, entry) in self.entries.iter().enumerate() {
            validate_entry(entry)?;
            if index != 0
                && compare_names(&self.entries[index - 1].name, &entry.name) != Ordering::Less
            {
                return Err(invalid(
                    "EA names duplicate case-insensitively or are not canonical",
                ));
            }
            packed = packed
                .checked_add(5 + entry.name.len() + entry.value.len())
                .ok_or_else(|| invalid("EA packed accounting overflow"))?;
            let size = entry_size(entry)?;
            native = native
                .checked_add(if index + 1 == self.entries.len() {
                    size
                } else {
                    align4(size)?
                })
                .ok_or_else(|| invalid("EA native accounting overflow"))?;
            needed += usize::from(entry.flags == FILE_NEED_EA);
        }
        if packed > u16::MAX as usize || native > MAX_EA_BYTES {
            return Err(invalid("EA packed/native set exceeds supported size"));
        }
        Ok(Sizes {
            packed_bytes: packed as u16,
            need_ea_count: needed as u16,
            native_bytes: native as u32,
        })
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn heap_bytes(&self) -> usize {
        self.entries.iter().fold(
            self.entries
                .capacity()
                .saturating_mul(std::mem::size_of::<Entry>()),
            |total, entry| {
                total
                    .saturating_add(entry.name.capacity())
                    .saturating_add(entry.value.capacity())
            },
        )
    }
    /// Windows EA names compare case-insensitively. Preserve raw name bytes in
    /// reports/digests, while explicitly comparing flag/value semantics here.
    pub fn equivalent(&self, observed: &Self) -> bool {
        self.validate().is_ok()
            && observed.validate().is_ok()
            && self.entries.len() == observed.entries.len()
            && self.entries.iter().zip(&observed.entries).all(|(a, b)| {
                compare_names(&a.name, &b.name) == Ordering::Equal
                    && a.flags == b.flags
                    && a.value == b.value
            })
    }
}

/// Parse exactly the native bytes reported by IO_STATUS_BLOCK.Information.
/// Only known 4-byte alignment may follow the final zero-terminated record.
pub fn parse_native(bytes: &[u8]) -> io::Result<Set> {
    parse_list(bytes, false)
}

/// Reconcile the 8-byte NTFS $EA_INFORMATION with the complete $EA value.
/// Absence of both attributes is represented by Set::default() by the caller;
/// an orphaned attribute must not be converted into an empty set.
pub fn parse_ntfs(information: &[u8], ea: &[u8]) -> io::Result<Set> {
    if information.len() != 8 || ea.len() > MAX_EA_BYTES {
        return Err(invalid("NTFS EA_INFORMATION or EA length differs"));
    }
    let packed = u16::from_le_bytes(information[..2].try_into().unwrap());
    let needed = u16::from_le_bytes(information[2..4].try_into().unwrap());
    let unpacked = u32::from_le_bytes(information[4..8].try_into().unwrap());
    if unpacked as usize != ea.len() {
        return Err(invalid("NTFS unpacked EA length differs"));
    }
    let set = parse_list(ea, true)?;
    let sizes = set.sizes()?;
    if packed != sizes.packed_bytes || needed != sizes.need_ea_count {
        return Err(invalid("NTFS packed EA size or FILE_NEED_EA count differs"));
    }
    Ok(set)
}

fn parse_list(bytes: &[u8], ntfs: bool) -> io::Result<Set> {
    if bytes.len() > MAX_EA_BYTES {
        return Err(invalid("EA buffer exceeds bound"));
    }
    if bytes.is_empty() {
        return Ok(Set::default());
    }
    let mut entries = Vec::new();
    let mut at = 0usize;
    loop {
        if entries.len() == MAX_ENTRIES || at.checked_add(8).is_none_or(|end| end > bytes.len()) {
            return Err(invalid("EA header truncated or entry budget exhausted"));
        }
        let next = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let flags = bytes[at + 4];
        let name_length = usize::from(bytes[at + 5]);
        let value_length = usize::from(u16::from_le_bytes(
            bytes[at + 6..at + 8].try_into().unwrap(),
        ));
        let used = 9usize
            .checked_add(name_length)
            .and_then(|size| size.checked_add(value_length))
            .filter(|size| at.checked_add(*size).is_some_and(|end| end <= bytes.len()))
            .ok_or_else(|| invalid("EA name/value truncated"))?;
        if bytes[at + 8 + name_length] != 0 {
            return Err(invalid("EA name lacks its exact terminator"));
        }
        let name = bytes[at + 8..at + 8 + name_length].to_vec();
        let value = bytes[at + 9 + name_length..at + used].to_vec();
        let entry = Entry { flags, name, value };
        validate_entry(&entry)?;
        entries.push(entry);
        let padded = align4(used)?;
        if next == 0 {
            let remaining = bytes.len() - at;
            if remaining < used || remaining > padded {
                return Err(invalid("EA has unaccounted bytes after final record"));
            }
            break;
        }
        if next != padded || at.checked_add(next).is_none_or(|end| end > bytes.len()) {
            return Err(invalid("EA next offset does not match aligned record size"));
        }
        at += next;
        if at == bytes.len() {
            if !ntfs {
                return Err(invalid(
                    "native EA chain has no zero-terminated final entry",
                ));
            }
            break;
        }
    }
    Set::new(entries)
}

/// Encode a complete checked set for NtSetEaFile. This is not an NTFS raw
/// metadata writer; allocation and filesystem representation remain driver-owned.
pub fn encode_native(set: &Set) -> io::Result<Vec<u8>> {
    let size = set.sizes()?.native_bytes as usize;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| invalid("native EA buffer allocation failed"))?;
    for (index, entry) in set.entries.iter().enumerate() {
        let used = entry_size(entry)?;
        let last = index + 1 == set.entries.len();
        let span = if last { used } else { align4(used)? };
        bytes.extend_from_slice(&(if last { 0 } else { span as u32 }).to_le_bytes());
        bytes.push(entry.flags);
        bytes.push(entry.name.len() as u8);
        bytes.extend_from_slice(&(entry.value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&entry.name);
        bytes.push(0);
        bytes.extend_from_slice(&entry.value);
        bytes.resize(bytes.len() + span - used, 0);
    }
    if bytes.len() != size {
        return Err(invalid("native EA encoding size differs"));
    }
    Ok(bytes)
}
