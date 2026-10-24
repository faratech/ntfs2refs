//! Pure parsing and range validation for the initially bounded data-volume profile.
use serde::{Deserialize, Serialize};
use std::io;

pub const DISK_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const PARTITION_OFFSET: u64 = 16 * 1024 * 1024;
pub const PARTITION_BYTES: u64 = 52 * 1024 * 1024 * 1024;
pub const GRANULE: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionIdentity {
    pub disk_guid: String,
    pub partition_guid: String,
    pub partition_number: u32,
    pub disk_bytes: u64,
    pub partition_offset: u64,
    pub partition_bytes: u64,
    pub logical_sector_bytes: u32,
    pub physical_sector_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskBinding {
    // Routing is deliberately separate from persistent identity.
    pub disk_number: u32,
    pub volume_guid: String,
    pub identity: PartitionIdentity,
}

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

pub fn guid_bytes(text: &str) -> io::Result<[u8; 16]> {
    let text = text
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(text);
    require(text.len() == 36, "GUID length differs")?;
    let bytes = text.as_bytes();
    for index in [8, 13, 18, 23] {
        require(bytes[index] == b'-', "GUID separators differ")?;
    }
    let compact: Vec<u8> = bytes.iter().copied().filter(|c| *c != b'-').collect();
    require(compact.len() == 32, "GUID contains extra separators")?;
    let mut out = [0; 16];
    fn nibble(c: u8) -> io::Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(invalid("GUID is not hexadecimal")),
        }
    }
    for (index, pair) in compact.as_chunks::<2>().0.iter().enumerate() {
        out[index] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    out[0..4].reverse();
    out[4..6].reverse();
    out[6..8].reverse();
    require(out != [0; 16], "empty GUID is not an identity")?;
    Ok(out)
}

pub fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    let raw = bytes
        .get(
            at..at
                .checked_add(4)
                .ok_or_else(|| invalid("offset overflow"))?,
        )
        .ok_or_else(|| invalid("truncated u32"))?;
    Ok(u32::from_le_bytes(raw.try_into().expect("four bytes")))
}

pub fn u64_at(bytes: &[u8], at: usize) -> io::Result<u64> {
    let raw = bytes
        .get(
            at..at
                .checked_add(8)
                .ok_or_else(|| invalid("offset overflow"))?,
        )
        .ok_or_else(|| invalid("truncated u64"))?;
    Ok(u64::from_le_bytes(raw.try_into().expect("eight bytes")))
}

impl DiskBinding {
    pub fn validate(&self) -> io::Result<()> {
        require(
            self.disk_number <= 255,
            "disk number exceeds bounded profile",
        )?;
        let identity = &self.identity;
        require(
            identity.disk_bytes == DISK_BYTES
                && identity.partition_offset == PARTITION_OFFSET
                && identity.partition_bytes == PARTITION_BYTES
                && identity.partition_number == 2
                && identity.logical_sector_bytes == 512
                && identity.physical_sector_bytes == 4096,
            "unsupported disk/partition geometry",
        )?;
        guid_bytes(&identity.disk_guid)?;
        guid_bytes(&identity.partition_guid)?;
        guid_bytes(&self.volume_guid)?;
        Ok(())
    }

    pub fn volume_path(&self) -> io::Result<String> {
        self.validate()?;
        let guid = self.volume_guid.trim_matches(['{', '}']);
        Ok(format!("\\\\?\\Volume{{{guid}}}"))
    }
}

pub fn validate_device(bytes: &[u8], disk_number: u32) -> io::Result<()> {
    require(
        bytes.len() == 12
            && u32_at(bytes, 0)? == 7
            && u32_at(bytes, 4)? == disk_number
            && u32_at(bytes, 8)? == 0,
        "physical device routing differs",
    )
}

pub fn validate_alignment(bytes: &[u8]) -> io::Result<()> {
    require(
        bytes.len() == 28
            && u32_at(bytes, 0)? == 28
            && u32_at(bytes, 4)? == 28
            && u32_at(bytes, 16)? == 512
            && u32_at(bytes, 20)? == 4096
            && u32_at(bytes, 24)? == 0,
        "native sector alignment differs",
    )
}

pub fn validate_volume_extent(bytes: &[u8], binding: &DiskBinding) -> io::Result<()> {
    require(
        bytes.len() == 32
            && u32_at(bytes, 0)? == 1
            && u32_at(bytes, 8)? == binding.disk_number
            && u64_at(bytes, 16)? == binding.identity.partition_offset
            && u64_at(bytes, 24)? == binding.identity.partition_bytes,
        "volume is not the exact single bound partition",
    )
}

pub fn validate_layout(bytes: &[u8], binding: &DiskBinding) -> io::Result<()> {
    binding.validate()?;
    require(
        bytes.len() >= 48 && bytes.len() <= 65536 && u32_at(bytes, 0)? == 1,
        "only a bounded complete GPT layout is accepted",
    )?;
    require(
        bytes[8..24] == guid_bytes(&binding.identity.disk_guid)?,
        "disk GPT identity differs",
    )?;
    let count = u32_at(bytes, 4)? as usize;
    require(
        (1..=128).contains(&count) && bytes.len() == 48 + count * 144,
        "GPT partition entries are incomplete",
    )?;
    let first = u64_at(bytes, 24)?;
    let length = u64_at(bytes, 32)?;
    let last = first
        .checked_add(length)
        .ok_or_else(|| invalid("GPT usable-range overflow"))?;
    require(
        first >= 512
            && first.is_multiple_of(512)
            && length > 0
            && length.is_multiple_of(512)
            && last <= DISK_BYTES,
        "GPT usable domain differs",
    )?;
    let basic = guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?;
    let msr = guid_bytes("e3c9e316-0b5c-4db8-817d-f92df00215ae")?;
    let mut seen = Vec::new();
    let mut target = 0;
    let mut identities = Vec::new();
    for index in 0..count {
        let at = 48 + index * 144;
        let number = u32_at(bytes, at + 24)?;
        let offset = u64_at(bytes, at + 8)?;
        let length = u64_at(bytes, at + 16)?;
        let kind = &bytes[at + 32..at + 48];
        if number == 0 && length == 0 && kind == [0; 16] {
            continue;
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("partition overflow"))?;
        require(
            u32_at(bytes, at)? == 1
                && number > 0
                && length > 0
                && offset >= first
                && end <= last
                && offset.is_multiple_of(512)
                && length.is_multiple_of(512),
            "invalid GPT partition entry",
        )?;
        require(
            bytes[at + 48..at + 64] != [0; 16],
            "partition has no identity",
        )?;
        let id = bytes[at + 48..at + 64].to_vec();
        require(
            !identities.contains(&id),
            "duplicate GPT partition identity",
        )?;
        identities.push(id);
        for &(other_number, other_first, other_end) in &seen {
            require(
                number != other_number && (end <= other_first || offset >= other_end),
                "duplicate or overlapping GPT partition",
            )?;
        }
        seen.push((number, offset, end));
        if number == binding.identity.partition_number {
            require(
                kind == basic
                    && offset == PARTITION_OFFSET
                    && length == PARTITION_BYTES
                    && bytes[at + 48..at + 64] == guid_bytes(&binding.identity.partition_guid)?
                    && u64_at(bytes, at + 64)? == 0,
                "target GPT partition differs",
            )?;
            target += 1;
        } else {
            require(
                kind == msr && number == 1 && end <= PARTITION_OFFSET,
                "non-target partitions must be the bounded MSR; system/EFI disks are refused",
            )?;
        }
    }
    require(target == 1, "expected exactly one target partition")
}

pub fn validate_ranges(ranges: &[(u64, u64)], length: u64) -> io::Result<()> {
    require(
        !ranges.is_empty() && ranges.len() <= 65536,
        "range count is not bounded",
    )?;
    let mut previous_end = 0;
    for &(offset, count) in ranges {
        let end = offset
            .checked_add(count)
            .ok_or_else(|| invalid("range overflow"))?;
        require(
            count > 0
                && offset.is_multiple_of(GRANULE)
                && count.is_multiple_of(GRANULE)
                && offset >= previous_end
                && end <= length,
            "range is unaligned, overlapping or outside partition",
        )?;
        previous_end = end;
    }
    Ok(())
}
