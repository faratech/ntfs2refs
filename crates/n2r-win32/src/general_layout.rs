//! Read-only binding for a dedicated basic data disk outside the enrolled VM.
//! No raw writer accepts this type yet. A whole-disk exclusion workflow may
//! only be considered after this exact layout and current OS disk are checked.
use crate::layout::{self, PartitionIdentity, guid_bytes};
use serde::{Deserialize, Serialize};
use std::io;

const MIN_DISK: u64 = 1 << 30;
const MAX_DISK: u64 = 64 << 40;
const MIN_PARTITION: u64 = 256 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralDiskBinding {
    pub disk_number: u32,
    pub volume_guid: String,
    pub identity: PartitionIdentity,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

impl GeneralDiskBinding {
    pub fn validate(&self) -> io::Result<()> {
        let p = &self.identity;
        require(
            self.disk_number <= 4095,
            "disk route exceeds bounded profile",
        )?;
        require(
            (MIN_DISK..=MAX_DISK).contains(&p.disk_bytes)
                && p.disk_bytes.is_multiple_of(512)
                && (1..=128).contains(&p.partition_number)
                && p.partition_offset >= 1 << 20
                && p.partition_offset.is_multiple_of(4096)
                && p.partition_bytes >= MIN_PARTITION
                && p.partition_bytes.is_multiple_of(4096)
                && p.partition_offset
                    .checked_add(p.partition_bytes)
                    .and_then(|end| end.checked_add(1 << 20))
                    .is_some_and(|end| end <= p.disk_bytes)
                && matches!(p.logical_sector_bytes, 512 | 4096)
                && matches!(p.physical_sector_bytes, 512 | 4096)
                && p.physical_sector_bytes >= p.logical_sector_bytes,
            "unsupported dedicated data-disk geometry",
        )?;
        require(
            guid_bytes(&p.disk_guid)? != guid_bytes(&p.partition_guid)?,
            "disk and partition identities alias",
        )?;
        guid_bytes(&self.volume_guid)?;
        Ok(())
    }

    pub fn volume_path(&self) -> io::Result<String> {
        self.validate()?;
        let guid = self.volume_guid.trim_matches(['{', '}']);
        Ok(format!("\\\\?\\Volume{{{guid}}}"))
    }

    pub fn validate_alignment(&self, bytes: &[u8]) -> io::Result<()> {
        self.validate()?;
        require(
            bytes.len() == 28
                && layout::u32_at(bytes, 0)? == 28
                && layout::u32_at(bytes, 4)? == 28
                && layout::u32_at(bytes, 16)? == self.identity.logical_sector_bytes
                && layout::u32_at(bytes, 20)? == self.identity.physical_sector_bytes
                && layout::u32_at(bytes, 24)? == 0,
            "native sector alignment differs from general binding",
        )
    }

    pub fn validate_volume_extent(&self, bytes: &[u8]) -> io::Result<()> {
        self.validate()?;
        require(
            bytes.len() == 32
                && layout::u32_at(bytes, 0)? == 1
                && layout::u32_at(bytes, 8)? == self.disk_number
                && layout::u64_at(bytes, 16)? == self.identity.partition_offset
                && layout::u64_at(bytes, 24)? == self.identity.partition_bytes,
            "volume is not the single bound data partition",
        )
    }

    pub fn validate_layout(&self, bytes: &[u8]) -> io::Result<()> {
        self.validate()?;
        require(
            (48..=65536).contains(&bytes.len())
                && layout::u32_at(bytes, 0)? == 1
                && bytes[8..24] == guid_bytes(&self.identity.disk_guid)?,
            "GPT header or disk identity differs",
        )?;
        let count = layout::u32_at(bytes, 4)? as usize;
        require(
            (1..=128).contains(&count) && bytes.len() == 48 + count * 144,
            "GPT entry table incomplete",
        )?;
        let first = layout::u64_at(bytes, 24)?;
        let length = layout::u64_at(bytes, 32)?;
        let last = first
            .checked_add(length)
            .ok_or_else(|| invalid("GPT usable range overflow"))?;
        require(
            first >= 512
                && first.is_multiple_of(512)
                && length > 0
                && length.is_multiple_of(512)
                && last <= self.identity.disk_bytes,
            "GPT usable range differs",
        )?;
        let basic = guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?;
        let msr = guid_bytes("e3c9e316-0b5c-4db8-817d-f92df00215ae")?;
        let mut seen = Vec::<(u32, u64, u64)>::new();
        let (mut target, mut msr_count) = (0, 0);
        for index in 0..count {
            let at = 48 + index * 144;
            let number = layout::u32_at(bytes, at + 24)?;
            let offset = layout::u64_at(bytes, at + 8)?;
            let size = layout::u64_at(bytes, at + 16)?;
            let kind = &bytes[at + 32..at + 48];
            if number == 0 && size == 0 && kind == [0; 16] {
                continue;
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| invalid("GPT partition overflow"))?;
            require(
                layout::u32_at(bytes, at)? == 1
                    && number > 0
                    && size > 0
                    && offset >= first
                    && end <= last
                    && offset.is_multiple_of(512)
                    && size.is_multiple_of(512)
                    && bytes[at + 48..at + 64] != [0; 16]
                    && !seen
                        .iter()
                        .any(|&(n, lo, hi)| n == number || (offset < hi && lo < end)),
                "duplicate, overlapping or malformed GPT partition",
            )?;
            seen.push((number, offset, end));
            if number == self.identity.partition_number {
                require(
                    kind == basic
                        && offset == self.identity.partition_offset
                        && size == self.identity.partition_bytes
                        && bytes[at + 48..at + 64] == guid_bytes(&self.identity.partition_guid)?
                        && layout::u64_at(bytes, at + 64)? == 0,
                    "target basic-data GPT partition differs",
                )?;
                target += 1;
            } else {
                require(
                    kind == msr && size <= 16 << 20 && end <= self.identity.partition_offset,
                    "other data, EFI or system partitions exclude whole-disk isolation",
                )?;
                msr_count += 1;
            }
        }
        require(
            target == 1 && msr_count <= 1,
            "dedicated data-disk partition set differs",
        )
    }
}
