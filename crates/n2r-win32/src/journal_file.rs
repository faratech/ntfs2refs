//! Read-only identity observation for the enrolled external journal file.
//!
//! The caller must already own a regular file opened with Windows sharing mode
//! zero, keep that handle open, and prevent concurrent operations through its
//! own handles. This API cannot discover or certify the handle's sharing mode.
//! It neither creates a file nor changes disk attributes, contents or privilege.
//! External MSFT_Disk.UniqueId enrollment is retained explicitly as unverified;
//! the native binding uses GPT identities, volume identity and FILE_ID_INFO.
use crate::{
    general_layout::GeneralDiskBinding,
    layout::{PartitionIdentity, guid_bytes, invalid, u32_at, u64_at},
};
use serde::{Deserialize, Serialize};
use std::io;

pub const JOURNAL_DISK_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const JOURNAL_PARTITION_OFFSET: u64 = 16 * 1024 * 1024;
pub const JOURNAL_PARTITION_BYTES: u64 = JOURNAL_DISK_BYTES - 32 * 1024 * 1024;
pub const MAX_JOURNAL_BYTES: u64 = 768 * 1024 * 1024;
/// Complete journal admission reserves metadata before the two payload copies.
pub const JOURNAL_OVERHEAD_RESERVE: u64 = 16 * 1024 * 1024;
pub const MAX_CHANGED_BYTES: u64 = (MAX_JOURNAL_BYTES - JOURNAL_OVERHEAD_RESERVE) / 2 / 4096 * 4096;
pub const MAX_EXPERIMENTAL_JOURNAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Selected explicitly by request/ticket schema, never inferred from a file's
/// size or current free space. CapacityV3 is bound into the trusted request and
/// ticket; legacy and experimental bounds stay distinct throughout recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalProfile {
    LegacyV1,
    ExperimentalLargeV2,
    CapacityPinnedV3 { max_journal_bytes: u64 },
}
impl JournalProfile {
    pub const fn version(self) -> u32 {
        match self {
            Self::LegacyV1 => 1,
            Self::ExperimentalLargeV2 => 2,
            Self::CapacityPinnedV3 { .. } => 3,
        }
    }
    pub const fn max_journal_bytes(self) -> u64 {
        match self {
            Self::LegacyV1 => MAX_JOURNAL_BYTES,
            Self::ExperimentalLargeV2 => MAX_EXPERIMENTAL_JOURNAL_BYTES,
            Self::CapacityPinnedV3 { max_journal_bytes } => max_journal_bytes,
        }
    }
    pub const fn max_changed_bytes(self) -> u64 {
        self.max_journal_bytes()
            .saturating_sub(JOURNAL_OVERHEAD_RESERVE)
            / 2
            / 4096
            * 4096
    }
    /// Encoded selection retains every old byte but can synthesize new bytes.
    /// The exact old + literal-new + metadata size must still be checked.
    pub const fn max_encoded_changed_bytes(self) -> u64 {
        self.max_journal_bytes()
            .saturating_sub(JOURNAL_OVERHEAD_RESERVE)
            / 4096
            * 4096
    }
    pub fn from_schema(version: u32) -> io::Result<Self> {
        match version {
            1 => Ok(Self::LegacyV1),
            2 => Ok(Self::ExperimentalLargeV2),
            3 => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal profile 3 requires pinned capacity",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported journal profile",
            )),
        }
    }
    /// Recover the explicit profile without inferring it from a device or file.
    /// Historical profiles must not acquire a capacity field during replay.
    pub fn from_schema_and_capacity(version: u32, capacity: Option<u64>) -> io::Result<Self> {
        match (version, capacity) {
            (1 | 2, None) => Self::from_schema(version),
            (1 | 2, Some(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "historical journal profile cannot carry pinned capacity",
            )),
            (3, Some(max_journal_bytes))
                if (JOURNAL_OVERHEAD_RESERVE + 2 * 4096..=i64::MAX as u64 - 4095)
                    .contains(&max_journal_bytes) =>
            {
                Ok(Self::CapacityPinnedV3 { max_journal_bytes })
            }
            (3, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal profile 3 requires bounded explicit pinned capacity",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported journal profile",
            )),
        }
    }
}
const MAX_PATH_UNITS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalStorageBinding {
    pub disk_number: u32,
    pub externally_enrolled_disk_unique_id: String,
    /// GUID alone, with optional braces; never a caller-provided device path.
    pub volume_guid: String,
    pub identity: PartitionIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralJournalStorageBinding {
    pub disk: GeneralDiskBinding,
    pub externally_enrolled_disk_unique_id: String,
    /// A journal may live on a separate OS disk with EFI/recovery partitions.
    /// Every GPT entry is still checked for identity, bounds and overlap.
    #[serde(default)]
    pub allow_additional_partitions: bool,
}

impl GeneralJournalStorageBinding {
    pub fn validate(&self) -> io::Result<()> {
        self.disk.validate()?;
        require(
            // Preparation reserves its bounded metadata plus both copies of
            // at least one 4 KiB changed granule. Available filesystem space
            // is checked separately and may be smaller than partition size.
            self.disk.identity.partition_bytes >= JOURNAL_OVERHEAD_RESERVE + 2 * 4096
                && !self.externally_enrolled_disk_unique_id.is_empty()
                && self.externally_enrolled_disk_unique_id.len() <= 128
                && self
                    .externally_enrolled_disk_unique_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "general journal capacity or enrollment differs",
        )
    }
}

impl JournalStorageBinding {
    pub fn validate(&self) -> io::Result<()> {
        let p = &self.identity;
        require(
            self.disk_number == 2
                && p.disk_bytes == JOURNAL_DISK_BYTES
                && p.partition_number == 2
                && p.partition_offset == JOURNAL_PARTITION_OFFSET
                && p.partition_bytes == JOURNAL_PARTITION_BYTES
                && p.logical_sector_bytes == 512
                && p.physical_sector_bytes == 4096,
            "journal storage is outside the enrolled 8 GiB profile",
        )?;
        require(
            !self.externally_enrolled_disk_unique_id.is_empty()
                && self.externally_enrolled_disk_unique_id.len() <= 128
                && self
                    .externally_enrolled_disk_unique_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "external journal enrollment identifier is invalid",
        )?;
        guid_bytes(&p.disk_guid)?;
        guid_bytes(&p.partition_guid)?;
        guid_bytes(&self.volume_guid)?;
        Ok(())
    }
}

/// Stable native identity subset for a ticket. No route, path, mutable file
/// length, allocation size, external enrollment assertion or timestamps enter
/// this value. File IDs are not content hashes and do not survive file deletion
/// and recreation as a trustworthy identity; the journal ticket also pins bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalFileIdentity {
    pub volume_serial_number: u64,
    pub file_id_128: [u8; 16],
    pub volume_guid: [u8; 16],
    pub disk_guid: [u8; 16],
    pub partition_guid: [u8; 16],
    pub partition_number: u32,
    pub disk_bytes: u64,
    pub partition_offset: u64,
    pub partition_bytes: u64,
    pub logical_sector_bytes: u32,
    pub physical_sector_bytes: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct JournalFileSnapshot {
    pub schema_version: u32,
    pub identity: JournalFileIdentity,
    pub disk_number: u32,
    pub final_path: String,
    pub file_bytes: u64,
    pub allocation_bytes: u64,
    pub file_attributes: u32,
    pub number_of_links: u32,
    pub externally_enrolled_disk_unique_id: String,
    pub external_unique_id_verified: bool,
    pub sharing_mode_verified: bool,
    pub observations_match_before_after: bool,
    pub conversion_qualified: bool,
    /// Exact returned native buffers, bounded independently of their contents.
    pub evidence: JournalFileEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JournalFileEvidence {
    pub file_id_info: [u8; 24],
    pub file_standard_info: [u8; 24],
    pub file_attribute_tag_info: [u8; 8],
    pub volume_extents: Vec<u8>,
    pub disk_device_number: Vec<u8>,
    pub disk_length: Vec<u8>,
    pub disk_alignment: Vec<u8>,
    pub disk_layout: Vec<u8>,
}

/// Ordinary-file observation only; no storage enrollment or content proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrdinaryFileSnapshot {
    pub final_path: String,
    pub volume_serial_number: u64,
    pub file_id_128: [u8; 16],
    pub file_bytes: u64,
    pub allocation_bytes: u64,
    pub file_attributes: u32,
    pub number_of_links: u32,
}

fn ordinary_snapshot(
    path: &str,
    evidence: &JournalFileEvidence,
) -> io::Result<OrdinaryFileSnapshot> {
    let guid = path
        .strip_prefix("\\\\?\\Volume{")
        .and_then(|s| s.split_once("}\\").map(|(guid, _)| guid))
        .ok_or_else(|| invalid("ordinary file has no final volume-GUID path"))?;
    final_volume_path(path, &guid_bytes(guid)?)?;
    let (file_bytes, allocation_bytes, file_attributes) = validate_file_fields(evidence)?;
    Ok(OrdinaryFileSnapshot {
        final_path: path.into(),
        volume_serial_number: u64_at(&evidence.file_id_info, 0)?,
        file_id_128: evidence.file_id_info[8..24]
            .try_into()
            .expect("fixed FILE_ID_INFO"),
        file_bytes,
        allocation_bytes,
        file_attributes,
        number_of_links: 1,
    })
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn final_volume_path(path: &str, expected: &[u8; 16]) -> io::Result<String> {
    require(
        path.encode_utf16().count() < MAX_PATH_UNITS && path.starts_with("\\\\?\\Volume{"),
        "journal final path is not a bounded volume-GUID path",
    )?;
    let (guid, suffix) = path[11..]
        .split_once("}\\")
        .ok_or_else(|| invalid("journal final path has no volume boundary"))?;
    require(
        guid_bytes(guid)? == *expected,
        "journal final volume GUID differs",
    )?;
    require(!suffix.is_empty(), "journal handle is a volume root")?;
    for component in suffix.split('\\') {
        require(
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.ends_with([' ', '.'])
                && !component.chars().any(|c| {
                    c.is_control() || matches!(c, ':' | '/' | '"' | '<' | '>' | '|' | '?' | '*')
                }),
            "journal final path contains a stream or ambiguous component",
        )?;
    }
    Ok(format!("\\\\?\\Volume{{{guid}}}"))
}

fn validate_file_fields_for_profile(
    e: &JournalFileEvidence,
    profile: JournalProfile,
) -> io::Result<(u64, u64, u32)> {
    // Reject invalid hand-constructed CapacityPinnedV3 values before the
    // allocation-rounding addition below or any native evidence is accepted.
    let capacity = match profile {
        JournalProfile::CapacityPinnedV3 { max_journal_bytes } => Some(max_journal_bytes),
        _ => None,
    };
    JournalProfile::from_schema_and_capacity(profile.version(), capacity)?;
    let standard = &e.file_standard_info;
    let allocation = u64_at(standard, 0)?;
    let length = u64_at(standard, 8)?;
    let attributes = u32_at(&e.file_attribute_tag_info, 0)?;
    // Directory, device, sparse, reparse, compressed and encrypted are excluded.
    const FORBIDDEN: u32 = 0x10 | 0x40 | 0x200 | 0x400 | 0x800 | 0x4000;
    require(
        allocation <= profile.max_journal_bytes() + 4095
            && length <= profile.max_journal_bytes()
            && u32_at(standard, 16)? == 1
            && standard[20] == 0
            && standard[21] == 0
            && attributes & FORBIDDEN == 0
            && u32_at(&e.file_attribute_tag_info, 4)? == 0,
        "journal file is oversized, linked, deleting or not an ordinary stream",
    )?;
    require(
        u64_at(&e.file_id_info, 0)? != 0 && e.file_id_info[8..24] != [0; 16],
        "journal file identity is empty",
    )?;
    Ok((length, allocation, attributes))
}

fn validate_file_fields(e: &JournalFileEvidence) -> io::Result<(u64, u64, u32)> {
    validate_file_fields_for_profile(e, JournalProfile::LegacyV1)
}

fn validate_layout(raw: &[u8], expected: &JournalStorageBinding) -> io::Result<()> {
    require(
        (48..=65536).contains(&raw.len()) && u32_at(raw, 0)? == 1,
        "journal disk must have a complete bounded GPT layout",
    )?;
    require(
        raw[8..24] == guid_bytes(&expected.identity.disk_guid)?,
        "journal GPT disk identity differs",
    )?;
    let count = u32_at(raw, 4)? as usize;
    require(
        (1..=128).contains(&count) && raw.len() == 48 + count * 144,
        "journal GPT entries are incomplete",
    )?;
    let first = u64_at(raw, 24)?;
    let usable = u64_at(raw, 32)?;
    let last = first
        .checked_add(usable)
        .ok_or_else(|| invalid("journal GPT usable range overflow"))?;
    require(
        first >= 512
            && first.is_multiple_of(512)
            && usable > 0
            && usable.is_multiple_of(512)
            && last <= JOURNAL_DISK_BYTES,
        "journal GPT usable range differs",
    )?;
    let basic = guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?;
    let msr = guid_bytes("e3c9e316-0b5c-4db8-817d-f92df00215ae")?;
    let mut seen = Vec::new();
    let mut target_count = 0;
    for index in 0..count {
        let at = 48 + index * 144;
        let number = u32_at(raw, at + 24)?;
        let offset = u64_at(raw, at + 8)?;
        let length = u64_at(raw, at + 16)?;
        let kind = &raw[at + 32..at + 48];
        if number == 0 && length == 0 && kind == [0; 16] {
            continue;
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("journal partition overflow"))?;
        let id = &raw[at + 48..at + 64];
        require(
            u32_at(raw, at)? == 1
                && number > 0
                && length > 0
                && offset >= first
                && end <= last
                && offset.is_multiple_of(512)
                && length.is_multiple_of(512)
                && id != [0; 16],
            "journal GPT partition is invalid",
        )?;
        for (n, start, stop, other_id) in &seen {
            require(
                number != *n && (end <= *start || offset >= *stop) && id != *other_id,
                "journal GPT partitions overlap or repeat an identity",
            )?;
        }
        seen.push((number, offset, end, id));
        if number == 2 {
            require(
                kind == basic
                    && offset == JOURNAL_PARTITION_OFFSET
                    && length == JOURNAL_PARTITION_BYTES
                    && id == guid_bytes(&expected.identity.partition_guid)?
                    && u64_at(raw, at + 64)? == 0,
                "journal GPT target partition differs",
            )?;
            target_count += 1;
        } else {
            require(
                kind == msr && number == 1 && end <= JOURNAL_PARTITION_OFFSET,
                "journal disk contains an unexpected or system partition",
            )?;
        }
    }
    require(
        target_count == 1,
        "journal GPT target partition is absent or duplicated",
    )
}

fn validate_evidence(
    expected: &JournalStorageBinding,
    final_path: &str,
    e: JournalFileEvidence,
) -> io::Result<JournalFileSnapshot> {
    expected.validate()?;
    let volume_guid = guid_bytes(&expected.volume_guid)?;
    final_volume_path(final_path, &volume_guid)?;
    let (file_bytes, allocation_bytes, file_attributes) = validate_file_fields(&e)?;
    crate::layout::validate_device(&e.disk_device_number, expected.disk_number)?;
    crate::layout::validate_alignment(&e.disk_alignment)?;
    require(
        e.disk_length.len() == 8 && u64_at(&e.disk_length, 0)? == JOURNAL_DISK_BYTES,
        "journal disk size differs",
    )?;
    require(
        e.volume_extents.len() == 32
            && u32_at(&e.volume_extents, 0)? == 1
            && u32_at(&e.volume_extents, 8)? == expected.disk_number
            && u64_at(&e.volume_extents, 16)? == JOURNAL_PARTITION_OFFSET
            && u64_at(&e.volume_extents, 24)? == JOURNAL_PARTITION_BYTES,
        "journal file volume is not the exact enrolled partition",
    )?;
    validate_layout(&e.disk_layout, expected)?;
    let p = &expected.identity;
    Ok(JournalFileSnapshot {
        schema_version: 1,
        identity: JournalFileIdentity {
            volume_serial_number: u64_at(&e.file_id_info, 0)?,
            file_id_128: e.file_id_info[8..24]
                .try_into()
                .expect("fixed FILE_ID_INFO"),
            volume_guid,
            disk_guid: guid_bytes(&p.disk_guid)?,
            partition_guid: guid_bytes(&p.partition_guid)?,
            partition_number: 2,
            disk_bytes: JOURNAL_DISK_BYTES,
            partition_offset: JOURNAL_PARTITION_OFFSET,
            partition_bytes: JOURNAL_PARTITION_BYTES,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        },
        disk_number: expected.disk_number,
        final_path: final_path.into(),
        file_bytes,
        allocation_bytes,
        file_attributes,
        number_of_links: 1,
        externally_enrolled_disk_unique_id: expected.externally_enrolled_disk_unique_id.clone(),
        external_unique_id_verified: false,
        sharing_mode_verified: false,
        observations_match_before_after: false,
        conversion_qualified: false,
        evidence: e,
    })
}

fn validate_general_evidence_for_profile(
    expected: &GeneralJournalStorageBinding,
    final_path: &str,
    evidence: JournalFileEvidence,
    profile: JournalProfile,
) -> io::Result<JournalFileSnapshot> {
    expected.validate()?;
    let binding = &expected.disk;
    let volume_guid = guid_bytes(&binding.volume_guid)?;
    final_volume_path(final_path, &volume_guid)?;
    let (file_bytes, allocation_bytes, file_attributes) =
        validate_file_fields_for_profile(&evidence, profile)?;
    crate::layout::validate_device(&evidence.disk_device_number, binding.disk_number)?;
    binding.validate_alignment(&evidence.disk_alignment)?;
    require(
        evidence.disk_length.len() == 8
            && u64_at(&evidence.disk_length, 0)? == binding.identity.disk_bytes,
        "general journal disk length differs",
    )?;
    binding.validate_volume_extent(&evidence.volume_extents)?;
    if expected.allow_additional_partitions {
        validate_external_journal_layout(&evidence.disk_layout, binding)?;
    } else {
        binding.validate_layout(&evidence.disk_layout)?;
    }
    let p = &binding.identity;
    Ok(JournalFileSnapshot {
        schema_version: 1,
        identity: JournalFileIdentity {
            volume_serial_number: u64_at(&evidence.file_id_info, 0)?,
            file_id_128: evidence.file_id_info[8..24]
                .try_into()
                .expect("fixed FILE_ID_INFO"),
            volume_guid,
            disk_guid: guid_bytes(&p.disk_guid)?,
            partition_guid: guid_bytes(&p.partition_guid)?,
            partition_number: p.partition_number,
            disk_bytes: p.disk_bytes,
            partition_offset: p.partition_offset,
            partition_bytes: p.partition_bytes,
            logical_sector_bytes: p.logical_sector_bytes,
            physical_sector_bytes: p.physical_sector_bytes,
        },
        disk_number: binding.disk_number,
        final_path: final_path.into(),
        file_bytes,
        allocation_bytes,
        file_attributes,
        number_of_links: 1,
        externally_enrolled_disk_unique_id: expected.externally_enrolled_disk_unique_id.clone(),
        external_unique_id_verified: false,
        sharing_mode_verified: false,
        observations_match_before_after: false,
        conversion_qualified: false,
        evidence,
    })
}

#[cfg(test)]
fn validate_general_evidence(
    expected: &GeneralJournalStorageBinding,
    final_path: &str,
    evidence: JournalFileEvidence,
) -> io::Result<JournalFileSnapshot> {
    validate_general_evidence_for_profile(expected, final_path, evidence, JournalProfile::LegacyV1)
}

fn validate_external_journal_layout(raw: &[u8], binding: &GeneralDiskBinding) -> io::Result<()> {
    let p = &binding.identity;
    require(
        (48..=65536).contains(&raw.len())
            && u32_at(raw, 0)? == 1
            && raw[8..24] == guid_bytes(&p.disk_guid)?,
        "external journal GPT header or disk identity differs",
    )?;
    let count = u32_at(raw, 4)? as usize;
    require(
        (1..=128).contains(&count) && raw.len() == 48 + count * 144,
        "external journal GPT entries are incomplete",
    )?;
    let first = u64_at(raw, 24)?;
    let usable = u64_at(raw, 32)?;
    let last = first
        .checked_add(usable)
        .ok_or_else(|| invalid("external journal GPT usable-range overflow"))?;
    require(
        first >= 512
            && first.is_multiple_of(512)
            && usable > 0
            && usable.is_multiple_of(512)
            && last <= p.disk_bytes,
        "external journal GPT usable range differs",
    )?;
    let basic = guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?;
    let mut seen = Vec::<(u32, u64, u64, [u8; 16])>::new();
    let mut target = 0;
    for index in 0..count {
        let at = 48 + index * 144;
        let number = u32_at(raw, at + 24)?;
        let offset = u64_at(raw, at + 8)?;
        let length = u64_at(raw, at + 16)?;
        let kind = &raw[at + 32..at + 48];
        if number == 0 && length == 0 && kind == [0; 16] {
            continue;
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("external journal GPT partition overflow"))?;
        let id: [u8; 16] = raw[at + 48..at + 64].try_into().unwrap();
        require(
            u32_at(raw, at)? == 1
                && number > 0
                && offset >= first
                && length > 0
                && end <= last
                && offset.is_multiple_of(512)
                && length.is_multiple_of(512)
                && kind != [0; 16]
                && id != [0; 16]
                && !seen.iter().any(|(n, lo, hi, other_id)| {
                    number == *n || (offset < *hi && *lo < end) || id == *other_id
                }),
            "external journal GPT entry is duplicate, overlapping or malformed",
        )?;
        seen.push((number, offset, end, id));
        if number == p.partition_number {
            require(
                kind == basic
                    && offset == p.partition_offset
                    && length == p.partition_bytes
                    && id == guid_bytes(&p.partition_guid)?,
                "external journal file partition differs",
            )?;
            target += 1;
        }
    }
    require(target == 1, "external journal file partition is absent")
}

fn finish_observation(
    mut before: JournalFileSnapshot,
    after_path: &str,
    after: &JournalFileEvidence,
) -> io::Result<JournalFileSnapshot> {
    require(
        before.final_path == after_path && before.evidence == *after,
        "journal file or backing storage changed during observation",
    )?;
    before.observations_match_before_after = true;
    Ok(before)
}

#[cfg(windows)]
mod marker_lab_pause;
#[cfg(windows)]
mod marker_native;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use marker_lab_pause::{LabMarkerCopy, LabMarkerCopyPause, LabMarkerPauseRequest};
#[cfg(windows)]
pub use marker_native::{
    MARKER_STORAGE_NATIVE_QUALIFIED, MarkerJournalFile, MarkerStorageObservation, MarkerStorageUse,
    UnbufferedJournalFile,
};
#[cfg(windows)]
pub use native::{
    observe_general_journal_file, observe_general_journal_file_with_profile, observe_journal_file,
    observe_ordinary_file_handle,
};

#[cfg(test)]
#[path = "../tests/support/journal_file.rs"]
mod tests;
