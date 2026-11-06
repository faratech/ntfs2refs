//! Read-only binding for a dedicated basic data disk outside the enrolled VM.
//! No raw writer accepts this type yet. A whole-disk exclusion workflow may
//! only be considered after this exact layout and current OS disk are checked.
use crate::layout::{self, PartitionIdentity, guid_bytes};
use serde::{Deserialize, Serialize};
use std::io;

/// Current native bitmap/admission profile, not an on-disk format limit.
pub const MAX_LIVE_PARTITION_BYTES: u64 = 128 * 1024 * 1024 * 1024;
/// Experimental routing bound derived from the complete 4 KiB target bitmap
/// read budget. Format, tree/data and exact journal-space checks remain separate.
pub const MAX_EXPERIMENTAL_PARTITION_BYTES: u64 =
    crate::bitmap_streaming::MAX_STREAM_BITMAP_BYTES * 8 * 4096;

/// Requested topology, never native exclusion or write authority. The Windows
/// profile additionally requires fresh runtime checks that the entire physical
/// disk is outside current boot, system, paging and dump roles.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneralDiskLayoutProfile {
    #[default]
    DedicatedData,
    OfflineWindows,
}
impl GeneralDiskLayoutProfile {
    fn is_dedicated_data(&self) -> bool { matches!(self, Self::DedicatedData) }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralDiskBinding {
    pub disk_number: u32,
    pub volume_guid: String,
    pub identity: PartitionIdentity,
    #[serde(default, skip_serializing_if = "GeneralDiskLayoutProfile::is_dedicated_data")]
    pub layout_profile: GeneralDiskLayoutProfile,
}

/// Separate physical disks with identically sized data partitions. This is a
/// read-only construction input; journal and write authority remain separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralSourceShadowBinding {
    pub source: GeneralDiskBinding,
    pub shadow: GeneralDiskBinding,
}

impl GeneralSourceShadowBinding {
    pub fn validate(&self) -> io::Result<()> {
        self.validate_with_resource_profile(None)
    }

    pub fn validate_with_resource_profile(
        &self,
        resources: Option<crate::attestation::ResourceProfile>,
    ) -> io::Result<()> {
        self.source.validate()?;
        self.shadow.validate()?;
        require(self.shadow.layout_profile == GeneralDiskLayoutProfile::DedicatedData,
            "a freshly owned shadow cannot use an installed-Windows source layout")?;
        let s = &self.source.identity;
        let t = &self.shadow.identity;
        require(
            self.source.disk_number != self.shadow.disk_number
                && guid_bytes(&s.disk_guid)? != guid_bytes(&t.disk_guid)?
                && guid_bytes(&s.partition_guid)? != guid_bytes(&t.partition_guid)?
                && guid_bytes(&self.source.volume_guid)? != guid_bytes(&self.shadow.volume_guid)?,
            "source and shadow storage identities overlap",
        )?;
        require(
            s.partition_bytes == t.partition_bytes
                && s.logical_sector_bytes == t.logical_sector_bytes
                && s.physical_sector_bytes == t.physical_sector_bytes
                && s.partition_bytes
                    <= resources.map_or(MAX_LIVE_PARTITION_BYTES, |profile| {
                        profile.maximum_partition_bytes()
                    }),
            "source and shadow geometry exceeds comparison profile",
        )
    }
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
            // Windows disk offsets are signed 64-bit values. The partition
            // and GPT checks below determine the actual minimum geometry;
            // the physical disk may be small or substantially larger than the
            // source partition without invalidating its identity.
            p.disk_bytes <= i64::MAX as u64
                && p.disk_bytes.is_multiple_of(512)
                && p.partition_number != 0
                && p.partition_offset >= u64::from(p.physical_sector_bytes)
                && p.partition_offset.is_multiple_of(4096)
                && p.partition_bytes >= 4096
                && p.partition_bytes.is_multiple_of(4096)
                && p.partition_offset
                    .checked_add(p.partition_bytes)
                    .is_some_and(|end| end <= p.disk_bytes)
                && matches!(p.logical_sector_bytes, 512 | 4096)
                && matches!(p.physical_sector_bytes, 512 | 4096)
                && p.physical_sector_bytes >= p.logical_sector_bytes,
            // Actual GPT usable bounds are enforced by validate_layout;
            // ordinary last-sector partitions need no arbitrary trailing gap.
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
            count != 0
                && count.checked_mul(144).and_then(|n| n.checked_add(48)) == Some(bytes.len()),
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
        let efi = guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")?;
        let recovery = guid_bytes("de94bba4-06d1-4d40-a16a-bfd50179d6ac")?;
        let windows = self.layout_profile == GeneralDiskLayoutProfile::OfflineWindows;
        let mut seen = Vec::<(u32, u64, u64)>::new();
        let mut seen_guids = Vec::<[u8; 16]>::new();
        let (mut target, mut msr_count) = (0, 0);
        let (mut efi_count, mut recovery_count) = (0, 0);
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
            if windows {
                let id: [u8; 16] = bytes[at + 48..at + 64].try_into().unwrap();
                require(!seen_guids.contains(&id), "Windows GPT partition GUID is duplicated")?;
                seen_guids.push(id);
            }
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
                    // An MSR has no independently mounted user filesystem.
                    // Its historical 16/128 MiB size and ordering do not
                    // change this owner's whole-disk exclusion contract.
                    kind == msr || windows && (kind == efi || kind == recovery),
                    "other data, EFI or system partitions exclude whole-disk isolation",
                )?;
                if kind == msr { msr_count += 1; }
                else if kind == efi { efi_count += 1; }
                else { recovery_count += 1; }
            }
        }
        require(
            target == 1 && msr_count <= 1
                && (!windows || msr_count == 1 && efi_count == 1 && recovery_count == 1),
            "dedicated data-disk partition set differs",
        )
    }
}

#[cfg(test)]
mod pair_tests {
    use super::*;

    fn disk(
        number: u32,
        disk_guid: &str,
        partition_guid: &str,
        volume_guid: &str,
    ) -> GeneralDiskBinding {
        GeneralDiskBinding {
            layout_profile: Default::default(),
            disk_number: number,
            volume_guid: volume_guid.into(),
            identity: PartitionIdentity {
                disk_guid: disk_guid.into(),
                partition_guid: partition_guid.into(),
                partition_number: 1,
                disk_bytes: 8 << 30,
                partition_offset: 1 << 20,
                partition_bytes: 4 << 30,
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
        }
    }

    #[test]
    fn source_shadow_pair_requires_separate_matching_data_disks() {
        let source = disk(
            1,
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
        );
        let shadow = disk(
            2,
            "44444444-4444-4444-4444-444444444444",
            "55555555-5555-5555-5555-555555555555",
            "66666666-6666-6666-6666-666666666666",
        );
        let pair = GeneralSourceShadowBinding { source, shadow };
        assert!(pair.validate().is_ok());
        let mut alias = pair.clone();
        alias.shadow.volume_guid = alias.source.volume_guid.clone();
        assert!(alias.validate().is_err());
        let mut mismatch = pair;
        mismatch.shadow.identity.partition_bytes += 4096;
        assert!(mismatch.validate().is_err());
    }
}
