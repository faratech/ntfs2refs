//! Bounded assembly of ordinary NTFS DATA attribute segments. Inputs are raw
//! record observations, not permission flags. The caller must acquire/recheck
//! the actual allocated MFT records and conserve all physical record identities.
//! Layout follows Microsoft's ATTRIBUTE_LIST_ENTRY fields: the attribute
//! instance at +24 is local to the referenced record.
use crate::ntfs_inspect::{AttributeInventory, NtfsGeometry};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_LIST_BYTES: usize = 65_536;
pub const MAX_EXTENSION_RECORDS: usize = 1024;
pub const MAX_RUNS: usize = 1024;
const RECORD_MASK: u64 = 0x0000_ffff_ffff_ffff;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub type_code: u32,
    pub lowest_vcn: u64,
    pub record_number: u64,
    pub sequence_number: u16,
    pub instance: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordEvidence {
    pub record_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub is_directory: bool,
    pub base_file_reference: u64,
    pub raw_record_sha256: String,
    pub attributes: Vec<AttributeInventory>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assembly {
    pub schema_version: u32,
    pub base: RecordEvidence,
    pub extensions: Vec<RecordEvidence>,
    pub list_value_hex: String,
}

/// Decode a complete unnamed list. Padding within each entry is retained by
/// the assembly ledger, while trailing bytes outside entries are not accepted.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_LIST_BYTES,
        "attribute-list byte bound exceeded or list is empty"
    );
    let mut entries = Vec::new();
    let mut origins = BTreeSet::new();
    let mut previous = None;
    let mut at = 0usize;
    while at < bytes.len() {
        let header = bytes
            .get(at..at + 26)
            .context("truncated attribute-list entry")?;
        let length = u16::from_le_bytes(header[4..6].try_into()?) as usize;
        ensure!(
            length >= 26 && length.is_multiple_of(8),
            "invalid attribute-list entry length"
        );
        let end = at
            .checked_add(length)
            .context("attribute-list length overflow")?;
        ensure!(end <= bytes.len(), "attribute-list entry exceeds value");
        ensure!(
            header[6] == 0,
            "named attribute-list entries are unsupported"
        );
        let type_code = u32::from_le_bytes(header[..4].try_into()?);
        let lowest_vcn = u64::from_le_bytes(header[8..16].try_into()?);
        let reference = u64::from_le_bytes(header[16..24].try_into()?);
        let record_number = reference & RECORD_MASK;
        let sequence_number = (reference >> 48) as u16;
        let instance = u16::from_le_bytes(header[24..26].try_into()?);
        ensure!(sequence_number != 0, "zero attribute-list record sequence");
        let key = (type_code, lowest_vcn);
        ensure!(
            previous.is_none_or(|old| old < key),
            "attribute-list keys are duplicate or unsorted"
        );
        ensure!(
            origins.insert((record_number, instance)),
            "duplicate attribute-list origin"
        );
        entries.push(Entry {
            type_code,
            lowest_vcn,
            record_number,
            sequence_number,
            instance,
        });
        previous = Some(key);
        at = end;
    }
    Ok(entries)
}

fn record_identity(record: &RecordEvidence) -> Result<()> {
    ensure!(
        (16..=RECORD_MASK).contains(&record.record_number) && record.sequence_number != 0,
        "unsupported attribute-list record identity"
    );
    ensure!(
        record.raw_record_sha256.len() == 64
            && record
                .raw_record_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid raw-record SHA256"
    );
    let mut instances = BTreeSet::new();
    for attribute in &record.attributes {
        ensure!(
            instances.insert(attribute.instance),
            "duplicate record-local attribute instance"
        );
        ensure!(
            attribute.name_utf16.is_empty()
                && attribute.flags == 0
                && attribute.compression_unit == 0,
            "named or encoded attribute-list storage is unsupported"
        );
    }
    Ok(())
}

fn plain_data(attribute: &AttributeInventory) -> Result<()> {
    ensure!(
        attribute.type_code == 0x80
            && !attribute.resident
            && attribute.name_utf16.is_empty()
            && attribute.flags == 0
            && attribute.compression_unit == 0,
        "ordinary nonresident DATA segment required"
    );
    Ok(())
}

/// Establish complete initialized metadata coverage before reading a list. A
/// nonresident list must fit in this one attribute's own mapping; assembling a
/// list from further list segments (including MFT bootstrap) is a separate gate.
pub fn validate_list_storage(
    attribute: &AttributeInventory,
    geometry: &NtfsGeometry,
) -> Result<()> {
    ensure!(
        attribute.type_code == 0x20
            && attribute.name_utf16.is_empty()
            && attribute.flags == 0
            && attribute.compression_unit == 0
            && attribute.lowest_vcn == 0,
        "ordinary standalone attribute-list storage required"
    );
    ensure!(
        attribute.logical_size > 0
            && attribute.logical_size <= MAX_LIST_BYTES as u64
            && attribute.initialized_size == attribute.logical_size,
        "attribute-list bytes must be completely initialized and bounded"
    );
    if attribute.resident {
        ensure!(
            attribute.extents.is_empty()
                && attribute.allocated_size == attribute.logical_size
                && attribute
                    .resident_sha256
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "resident attribute-list storage differs"
        );
        return Ok(());
    }
    let cluster = u64::from(geometry.cluster_size);
    ensure!(
        cluster > 0 && cluster.is_power_of_two() && geometry.volume_size > 0,
        "invalid attribute-list geometry"
    );
    let rounded = attribute
        .logical_size
        .checked_next_multiple_of(cluster)
        .context("attribute-list allocation overflow")?;
    ensure!(
        attribute.resident_sha256.is_none()
            && attribute.resident_metadata_hex.is_none()
            && attribute.allocated_size == rounded
            && !attribute.extents.is_empty()
            && attribute.extents.len() <= MAX_RUNS,
        "nonresident attribute-list allocation/form exceeds profile"
    );
    let mut next = 0u64;
    let mut physical = Vec::new();
    for extent in &attribute.extents {
        ensure!(
            extent.logical_offset == next
                && extent.length > 0
                && extent.length.is_multiple_of(cluster),
            "attribute-list mapping has a gap/overlap or invalid length"
        );
        let start = extent
            .physical_offset
            .context("sparse attribute-list storage is unsupported")?;
        let end = start
            .checked_add(extent.length)
            .context("attribute-list physical overflow")?;
        ensure!(
            start.is_multiple_of(cluster) && end <= geometry.volume_size,
            "attribute-list physical extent is unaligned or out of volume"
        );
        next = next
            .checked_add(extent.length)
            .context("attribute-list coverage overflow")?;
        ensure!(next <= rounded, "attribute-list mapping exceeds allocation");
        physical.push((start, end));
    }
    ensure!(next == rounded, "attribute-list mapping is incomplete");
    physical.sort_unstable();
    ensure!(
        physical.windows(2).all(|p| p[0].1 <= p[1].0),
        "attribute-list physical extents overlap"
    );
    Ok(())
}

/// Assemble one fully enumerated ordinary base file. Continuation length/VDL/
/// allocation fields are deliberately ignored; only the VCN-zero DATA fields
/// define the logical stream. No record is fetched or source byte written here.
pub fn assemble(
    base: RecordEvidence,
    extensions: Vec<RecordEvidence>,
    list_value: &[u8],
    geometry: &NtfsGeometry,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    ensure!(
        !extensions.is_empty() && extensions.len() <= MAX_EXTENSION_RECORDS,
        "extension record count is empty or exceeds bound"
    );
    let entries = parse(list_value)?;
    ensure!(
        (4..=5).contains(&base.attributes.len()),
        "unsupported base attribute count"
    );
    record_identity(&base)?;
    ensure!(
        !base.is_directory && base.base_file_reference == 0 && base.hard_link_count == 1,
        "ordinary standalone base file with one link required"
    );
    let mut types = BTreeMap::new();
    for attribute in &base.attributes {
        ensure!(
            types.insert(attribute.type_code, attribute).is_none(),
            "duplicate base attribute type"
        );
        match attribute.type_code {
            0x10 | 0x30 | 0x50 => ensure!(
                attribute.resident && attribute.lowest_vcn == 0 && attribute.extents.is_empty(),
                "base metadata must be resident and standalone"
            ),
            0x20 => validate_list_storage(attribute, geometry)?,
            0x80 => plain_data(attribute)?,
            _ => anyhow::bail!("unsupported extra base attribute"),
        }
    }
    ensure!(
        types.contains_key(&0x10) && types.contains_key(&0x30),
        "base SI or NAME attribute absent"
    );
    let list = types.get(&0x20).context("base attribute list absent")?;
    let data = *types.get(&0x80).context("base DATA attribute absent")?;
    ensure!(data.lowest_vcn == 0, "base DATA does not begin at VCN zero");
    ensure!(
        list.logical_size == list_value.len() as u64
            && (!list.resident
                || list.resident_sha256.as_deref()
                    == Some(hex::encode(Sha256::digest(list_value)).as_str())),
        "attribute-list bytes differ from their raw attribute"
    );
    if let Some(value) = &list.resident_metadata_hex {
        ensure!(
            value.len() == list_value.len() * 2 && hex::decode(value)? == list_value,
            "resident attribute-list retained bytes differ"
        );
    }
    let base_reference = base.record_number | (u64::from(base.sequence_number) << 48);
    let mut records = BTreeSet::from([base.record_number]);
    for extension in &extensions {
        ensure!(
            extension.attributes.len() == 1,
            "extension must contain exactly one DATA attribute"
        );
        record_identity(extension)?;
        ensure!(
            records.insert(extension.record_number),
            "duplicate or self extension record"
        );
        ensure!(
            !extension.is_directory
                && extension.hard_link_count == 0
                && extension.base_file_reference == base_reference,
            "foreign extension record base or form"
        );
        plain_data(&extension.attributes[0])?;
        ensure!(
            extension.attributes[0].lowest_vcn > 0,
            "extension DATA does not continue the base"
        );
    }

    let mut attributes = BTreeMap::new();
    for record in std::iter::once(&base).chain(&extensions) {
        for attribute in &record.attributes {
            attributes.insert(
                (record.record_number, attribute.instance),
                (record.sequence_number, attribute),
            );
        }
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        let origin = (entry.record_number, entry.instance);
        let (sequence, attribute) = attributes
            .get(&origin)
            .context("attribute-list entry has no owned attribute")?;
        ensure!(
            entry.sequence_number == *sequence
                && entry.type_code == attribute.type_code
                && entry.lowest_vcn == attribute.lowest_vcn,
            "attribute-list entry identity or VCN differs"
        );
        if entry.type_code == 0x20 {
            ensure!(
                entry.record_number == base.record_number
                    && entry.instance == list.instance
                    && entry.lowest_vcn == 0,
                "attribute-list self entry is foreign"
            );
        }
        ensure!(seen.insert(origin), "duplicate listed attribute origin");
    }
    for (&origin, (_, attribute)) in &attributes {
        ensure!(
            attribute.type_code == 0x20 || seen.contains(&origin),
            "unlisted base or extension attribute"
        );
    }

    let cluster = u64::from(geometry.cluster_size);
    ensure!(
        cluster > 0 && cluster.is_power_of_two() && geometry.volume_size > 0,
        "invalid assembly geometry"
    );
    ensure!(
        data.initialized_size <= data.logical_size
            && data.logical_size <= data.allocated_size
            && data.allocated_size.is_multiple_of(cluster),
        "base DATA lengths or allocation differ"
    );
    let mut segments = vec![data];
    segments.extend(extensions.iter().map(|record| &record.attributes[0]));
    segments.sort_by_key(|attribute| attribute.lowest_vcn);
    let mut next = 0u64;
    let mut extents = Vec::new();
    let mut physical = Vec::new();
    for segment in segments {
        ensure!(
            segment.lowest_vcn.checked_mul(cluster) == Some(next) && !segment.extents.is_empty(),
            "DATA segment VCN gap, overlap or empty segment"
        );
        for extent in &segment.extents {
            ensure!(
                extents.len() < MAX_RUNS,
                "assembled DATA run budget exceeded"
            );
            ensure!(
                extent.logical_offset == next
                    && extent.length > 0
                    && extent.length.is_multiple_of(cluster),
                "DATA run gap, overlap or alignment differs"
            );
            let start = extent
                .physical_offset
                .context("sparse DATA is unsupported")?;
            let end = start
                .checked_add(extent.length)
                .context("DATA physical range overflow")?;
            ensure!(
                start.is_multiple_of(cluster) && end <= geometry.volume_size,
                "DATA physical range is unaligned or outside volume"
            );
            next = next
                .checked_add(extent.length)
                .context("DATA VCN coverage overflow")?;
            physical.push((start, end));
            extents.push(extent.clone());
        }
    }
    ensure!(
        next == data.allocated_size,
        "DATA segments do not cover the complete allocated size"
    );
    for extent in &list.extents {
        let start = extent
            .physical_offset
            .context("list storage has no physical owner")?;
        physical.push((
            start,
            start
                .checked_add(extent.length)
                .context("list physical overflow")?,
        ));
    }
    physical.sort_unstable();
    ensure!(
        physical.windows(2).all(|pair| pair[0].1 <= pair[1].0),
        "DATA or attribute-list physical ranges overlap"
    );
    let mut canonical: Vec<_> = base
        .attributes
        .iter()
        .filter(|a| a.type_code != 0x20)
        .cloned()
        .collect();
    let canonical_data = canonical
        .iter_mut()
        .find(|a| a.type_code == 0x80)
        .context("canonical DATA absent")?;
    canonical_data.extents = extents;
    Ok((
        canonical,
        Assembly {
            schema_version: if list.resident { 1 } else { 2 },
            base,
            extensions,
            list_value_hex: hex::encode(list_value),
        },
    ))
}
