//! Bounded raw NTFS extended-attribute evidence.
//!
//! Retained bytes are reparsed on replay, rather than treating a serialized
//! canonical set as proof. Nonresident bytes still need the frozen source and
//! independent native observation to establish their physical authenticity.

use crate::ntfs_inspect::{AttributeInventory, FileInventory};
use anyhow::{Context, Result, ensure};
use n2r_win32::extended_attributes::{self, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_DATA_BYTES: u64 = 65_536;
const INFORMATION_BYTES: u64 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// None on both fields means that neither NTFS EA attribute was present.
    pub information_hex: Option<String>,
    pub data_hex: Option<String>,
    pub set: Set,
}

impl Inventory {
    pub fn empty() -> Self {
        Self {
            information_hex: None,
            data_hex: None,
            set: Set::default(),
        }
    }

    pub(crate) fn capture(
        information: &AttributeInventory,
        data: &AttributeInventory,
        information_bytes: &[u8],
        data_bytes: &[u8],
    ) -> Result<Self> {
        validate_storage(information, true)?;
        validate_storage(data, false)?;
        bind_bytes(information, information_bytes)?;
        bind_bytes(data, data_bytes)?;
        let set = extended_attributes::parse_ntfs(information_bytes, data_bytes)
            .context("parsing NTFS extended attributes")?;
        Ok(Self {
            information_hex: Some(hex::encode(information_bytes)),
            data_hex: Some(hex::encode(data_bytes)),
            set,
        })
    }

    /// Dynamic allocations retained in addition to the containing inventory.
    pub(crate) fn heap_bytes(&self) -> Result<u64> {
        let mut bytes = 0u64;
        for value in [&self.information_hex, &self.data_hex]
            .into_iter()
            .flatten()
        {
            bytes = bytes
                .checked_add(value.capacity() as u64)
                .context("EA evidence memory accounting overflow")?;
        }
        bytes = bytes
            .checked_add(
                (self.set.entries.capacity() as u64)
                    .checked_mul(std::mem::size_of::<extended_attributes::Entry>() as u64)
                    .context("EA entry memory accounting overflow")?,
            )
            .context("EA evidence memory accounting overflow")?;
        for entry in &self.set.entries {
            bytes = bytes
                .checked_add(entry.name.capacity() as u64)
                .and_then(|n| n.checked_add(entry.value.capacity() as u64))
                .context("EA value memory accounting overflow")?;
        }
        Ok(bytes)
    }
}

/// Locate the unique complete unnamed pair without excluding its allocations
/// from the original attribute inventory or ownership reconciliation.
pub(crate) fn storage_attributes<'a>(
    attributes: impl IntoIterator<Item = &'a AttributeInventory>,
) -> Result<Option<(&'a AttributeInventory, &'a AttributeInventory)>> {
    let mut information = None;
    let mut data = None;
    for attribute in attributes {
        match attribute.type_code {
            0xd0 => ensure!(
                information.replace(attribute).is_none(),
                "duplicate or continued EA_INFORMATION attribute"
            ),
            0xe0 => ensure!(
                data.replace(attribute).is_none(),
                "duplicate or continued EA attribute"
            ),
            _ => {}
        }
    }
    match (information, data) {
        (None, None) => Ok(None),
        (Some(information), Some(data)) => {
            validate_storage(information, true)?;
            validate_storage(data, false)?;
            Ok(Some((information, data)))
        }
        _ => anyhow::bail!("EA_INFORMATION and EA must be present together"),
    }
}

fn validate_storage(attribute: &AttributeInventory, information: bool) -> Result<()> {
    ensure!(
        attribute.type_code == if information { 0xd0 } else { 0xe0 },
        "EA storage attribute type differs"
    );
    ensure!(
        attribute.name_utf16.is_empty()
            && attribute.flags == 0
            && attribute.compression_unit == 0
            && attribute.lowest_vcn == 0,
        "named, encoded, sparse or continued EA storage is unsupported"
    );
    ensure!(
        attribute.initialized_size == attribute.logical_size,
        "EA storage must be wholly initialized"
    );
    if information {
        ensure!(
            attribute.resident && attribute.logical_size == INFORMATION_BYTES,
            "EA_INFORMATION must be an eight-byte resident attribute"
        );
    } else {
        ensure!(
            attribute.logical_size <= MAX_DATA_BYTES,
            "EA storage exceeds the bounded metadata profile"
        );
    }
    if attribute.resident {
        ensure!(
            attribute.allocated_size == attribute.logical_size
                && attribute.extents.is_empty()
                && attribute.resident_sha256.is_some()
                && attribute.resident_metadata_hex.is_some(),
            "resident EA storage evidence is incomplete"
        );
    } else {
        ensure!(
            attribute.logical_size > 0
                && attribute.resident_sha256.is_none()
                && attribute.resident_metadata_hex.is_none(),
            "nonresident EA storage has an invalid form"
        );
        let mut coverage = 0u64;
        let mut physical = Vec::with_capacity(attribute.extents.len());
        for extent in &attribute.extents {
            ensure!(
                extent.logical_offset == coverage && extent.length > 0,
                "EA mapping has a logical gap, overlap or empty extent"
            );
            coverage = coverage
                .checked_add(extent.length)
                .context("EA mapped coverage overflow")?;
            let start = extent
                .physical_offset
                .context("sparse EA storage is unsupported")?;
            let end = start
                .checked_add(extent.length)
                .context("EA physical range overflow")?;
            physical.push((start, end));
        }
        ensure!(
            coverage == attribute.allocated_size && coverage >= attribute.logical_size,
            "EA mapping does not cover its complete allocation"
        );
        physical.sort_unstable();
        ensure!(
            physical.windows(2).all(|pair| pair[0].1 <= pair[1].0),
            "EA storage contains overlapping physical ranges"
        );
    }
    Ok(())
}

fn bind_bytes(attribute: &AttributeInventory, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 == attribute.logical_size,
        "retained EA bytes differ from the attribute's logical length"
    );
    if attribute.resident {
        ensure!(
            attribute.resident_metadata_hex.as_deref() == Some(hex::encode(bytes).as_str())
                && attribute.resident_sha256.as_deref().is_some_and(|hash| {
                    crate::ntfs_attribute_list::resident_digest_matches(hash, bytes)
                }),
            "resident EA bytes differ from raw attribute evidence"
        );
    }
    Ok(())
}

fn decode_bounded(value: &str, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        value.len().is_multiple_of(2) && value.len() as u64 <= maximum * 2,
        "retained EA hex exceeds its byte bound"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "retained EA hex is not canonical"
    );
    hex::decode(value).context("decoding retained EA bytes")
}

/// Return a validated semantic set. Older reports can represent EA absence only
/// when they contain neither EA attribute; they cannot prove nonempty EAs.
pub fn file_set(file: &FileInventory) -> Result<Set> {
    let attributes = storage_attributes(&file.attributes)?;
    let Some(inventory) = &file.extended_attributes else {
        ensure!(
            attributes.is_none(),
            "EA attributes lack retained raw evidence"
        );
        return Ok(Set::default());
    };
    inventory
        .set
        .validate()
        .context("validating retained EA set")?;
    match (attributes, &inventory.information_hex, &inventory.data_hex) {
        (None, None, None) => {
            ensure!(
                inventory.set.is_empty(),
                "EA absence carries a nonempty set"
            );
            Ok(Set::default())
        }
        (Some((information, data)), Some(information_hex), Some(data_hex)) => {
            ensure!(
                file.base_file_reference == 0
                    && !file
                        .attributes
                        .iter()
                        .any(|attribute| attribute.type_code == 0x20),
                "EA attribute-list assembly is unsupported"
            );
            let information_bytes = decode_bounded(information_hex, INFORMATION_BYTES)?;
            let data_bytes = decode_bounded(data_hex, MAX_DATA_BYTES)?;
            bind_bytes(information, &information_bytes)?;
            bind_bytes(data, &data_bytes)?;
            let parsed = extended_attributes::parse_ntfs(&information_bytes, &data_bytes)
                .context("replaying raw NTFS extended attributes")?;
            ensure!(
                parsed == inventory.set,
                "retained canonical EA set differs from raw bytes"
            );
            Ok(parsed)
        }
        _ => anyhow::bail!("EA storage and retained raw evidence disagree"),
    }
}

/// Exact source EAs omitted only from the explicit Windows target projection.
/// Raw NTFS evidence and native source comparison continue to use file_set.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowsKernelPurgeEaNormalization {
    pub record_number: u64,
    pub sequence_number: u16,
    pub raw_source_ea_set_sha256: String,
    pub target_ea_set_sha256: String,
    pub omitted: Set,
}

fn set_digest(set: &Set) -> Result<String> {
    set.validate()?;
    let mut hash = Sha256::new();
    hash.update(b"ntfs2refs-exact-EA-set-v1\0");
    hash.update((set.entries.len() as u64).to_le_bytes());
    for entry in &set.entries {
        hash.update([entry.flags]);
        hash.update((entry.name.len() as u64).to_le_bytes());
        hash.update(&entry.name);
        hash.update((entry.value.len() as u64).to_le_bytes());
        hash.update(&entry.value);
    }
    Ok(hex::encode(hash.finalize()))
}

/// The caller must hold the actual Windows inspection and alias domain. These
/// user-mode-unsettable kernel caches remain archived as source facts, while
/// every ordinary target EA retains its exact flags, name bytes and value.
pub(crate) fn windows_target_projection(
    file: &FileInventory,
) -> Result<(Set, Option<WindowsKernelPurgeEaNormalization>)> {
    const KERNEL: &[u8] = b"$Kernel";
    const PURGE: &[u8] = b"$Kernel.Purge.";
    let raw = file_set(file)?;
    let mut omitted_count = 0usize;
    for entry in &raw.entries {
        if entry
            .name
            .get(..KERNEL.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(KERNEL))
        {
            ensure!(
                entry.flags == 0
                    && entry.name.len() > PURGE.len()
                    && entry
                        .name
                        .get(..PURGE.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PURGE)),
                "Windows target EA projection refuses an unsupported $Kernel name or flags at FILE {}",
                file.record_number
            );
            omitted_count += 1;
        }
    }
    if omitted_count == 0 {
        return Ok((raw, None));
    }
    let (omitted, target): (Vec<_>, Vec<_>) = raw.entries.iter().cloned().partition(|entry| {
        entry
            .name
            .get(..KERNEL.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(KERNEL))
    });
    let omitted = Set { entries: omitted };
    let target = Set { entries: target };
    omitted.validate()?;
    let normalization = WindowsKernelPurgeEaNormalization {
        record_number: file.record_number,
        sequence_number: file.sequence_number,
        raw_source_ea_set_sha256: set_digest(&raw)?,
        target_ea_set_sha256: set_digest(&target)?,
        omitted,
    };
    Ok((target, Some(normalization)))
}
