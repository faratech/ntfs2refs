//! Bounded assembly of NTFS DATA segments and MFT bootstrap evidence. Inputs are raw
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

/// Per-assembly working bounds. Legacy entry points retain their historical
/// profile; resource owners derive these values from an admitted RAM window.
#[derive(Clone, Copy, Debug)]
pub struct AssemblyLimits {
    pub list_bytes: usize,
    pub extension_records: usize,
    pub runs: usize,
    pub raw_attributes: usize,
    pub streams: usize,
    pub mft_records: u64,
    pub mft_bitmap_bytes: u64,
    pub working_bytes: Option<u64>,
}
impl AssemblyLimits {
    const LEGACY: Self = Self {
        list_bytes: MAX_LIST_BYTES,
        extension_records: MAX_EXTENSION_RECORDS,
        runs: MAX_RUNS,
        raw_attributes: MAX_LIST_BYTES / 32 + 1,
        streams: n2r_win32::stream_layout::MAX_STREAMS,
        mft_records: crate::ntfs_inspect::MAX_MFT_RECORDS,
        mft_bitmap_bytes: crate::ntfs_inspect::MAX_MFT_RECORDS.div_ceil(8),
        working_bytes: None,
    };
    pub fn from_working_bytes(bytes: u64, record_bytes: u32) -> Result<Self> {
        ensure!(record_bytes > 0, "zero physical record working bytes");
        let list_bytes = usize::try_from(bytes / 16)?;
        let extension_records = usize::try_from(bytes / (u64::from(record_bytes) * 16))?;
        let runs = usize::try_from(
            bytes / (std::mem::size_of::<crate::ntfs_inspect::Extent>() as u64 * 16),
        )?;
        let raw_attributes =
            usize::try_from(bytes / (std::mem::size_of::<AttributeInventory>() as u64 * 16))?;
        ensure!(
            list_bytes >= 32 && extension_records > 0 && runs > 0 && raw_attributes > 1,
            "assembly RAM window cannot represent one complete physical record"
        );
        Ok(Self {
            list_bytes,
            extension_records,
            runs,
            raw_attributes,
            streams: raw_attributes,
            mft_records: RECORD_MASK,
            mft_bitmap_bytes: u64::MAX,
            working_bytes: Some(bytes),
        })
    }
}

fn validate_working_assembly(
    base: &RecordEvidence,
    extensions: &[RecordEvidence],
    list_bytes: usize,
    limits: AssemblyLimits,
) -> Result<()> {
    let Some(maximum) = limits.working_bytes else {
        return Ok(());
    };
    let mut bytes = (list_bytes as u64)
        .checked_mul(8)
        .context("list working RAM overflow")?;
    for record in std::iter::once(base).chain(extensions) {
        bytes = bytes
            .checked_add(std::mem::size_of::<RecordEvidence>() as u64 * 8)
            .and_then(|n| n.checked_add(record.raw_record_sha256.capacity() as u64 * 8))
            .context("assembly record working RAM overflow")?;
        for attribute in &record.attributes {
            let heap =
                (std::mem::size_of::<AttributeInventory>() as u64)
                    .checked_add((attribute.name_utf16.capacity() as u64) * 2)
                    .and_then(|n| {
                        n.checked_add((attribute.extents.capacity() as u64).checked_mul(
                            std::mem::size_of::<crate::ntfs_inspect::Extent>() as u64,
                        )?)
                    })
                    .and_then(|n| {
                        n.checked_add(
                            attribute
                                .resident_sha256
                                .as_ref()
                                .map_or(0, |s| s.capacity() as u64),
                        )
                    })
                    .and_then(|n| {
                        n.checked_add(
                            attribute
                                .resident_metadata_hex
                                .as_ref()
                                .map_or(0, |s| s.capacity() as u64),
                        )
                    })
                    .context("attribute working RAM overflow")?;
            // Raw/canonical copies, resident bytes and origin/order/coverage
            // indexes coexist during assembly and replay inside this lease.
            bytes = bytes
                .checked_add(heap.checked_mul(16).context("assembly RAM overflow")?)
                .context("assembly RAM overflow")?;
        }
    }
    ensure!(
        bytes <= maximum,
        "complete assembly exceeds admitted working RAM"
    );
    Ok(())
}

trait BitmapInput {
    fn byte_len(&self) -> u64;
    fn allocated(&self, record: u64) -> Result<bool>;
    fn tail_zero(&self, records: u64) -> Result<()>;
    fn resident_matches(&self, digest: &str) -> Result<bool>;
    fn retained_hex(&self) -> Option<String>;
}
struct SliceBitmap<'a>(&'a [u8]);
impl BitmapInput for SliceBitmap<'_> {
    fn byte_len(&self) -> u64 {
        self.0.len() as u64
    }
    fn allocated(&self, record: u64) -> Result<bool> {
        Ok(self
            .0
            .get(usize::try_from(record / 8)?)
            .is_some_and(|b| b & (1 << (record % 8)) != 0))
    }
    fn tail_zero(&self, records: u64) -> Result<()> {
        ensure!(
            (usize::try_from(records)?..self.0.len() * 8)
                .all(|bit| self.0[bit / 8] & (1 << (bit % 8)) == 0),
            "MFT bitmap allocates records beyond EOF"
        );
        Ok(())
    }
    fn resident_matches(&self, digest: &str) -> Result<bool> {
        Ok(resident_digest_matches(digest, self.0))
    }
    fn retained_hex(&self) -> Option<String> {
        Some(hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub type_code: u32,
    pub lowest_vcn: u64,
    pub record_number: u64,
    pub sequence_number: u16,
    pub instance: u16,
}

/// Exact identity from a named ordinary-file attribute-list entry. Unlike the
/// legacy parser, this representation does not discard the stream name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEntry {
    pub type_code: u32,
    pub lowest_vcn: u64,
    pub record_number: u64,
    pub sequence_number: u16,
    pub instance: u16,
    pub name_utf16: Vec<u16>,
}

/// Physical attribute supplying a canonical attribute's resident bytes, or
/// the VCN-zero header of a merged nonresident stream. Instances are local to
/// the physical record and need not equal the canonical synthetic instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalOrigin {
    pub record_number: u64,
    pub sequence_number: u16,
    pub instance: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Assembly {
    pub schema_version: u32,
    pub base: RecordEvidence,
    pub extensions: Vec<RecordEvidence>,
    pub list_value_hex: String,
    /// Present only for the MFT bootstrap profiles. Exact initialized bitmap
    /// bytes are needed to replay allocated-record checks, not a success flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mft_bitmap_hex: Option<String>,
    /// Schema 5/6 only; aligned one-for-one with the canonical attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_origins: Option<Vec<CanonicalOrigin>>,
}

fn resident_digest_valid(expected: &str) -> bool {
    matches!(expected.len(), 32 | 64)
        && expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Current resident observations use the content digest; older retained
/// evidence used SHA-256. The encoded length selects exactly one algorithm.
pub fn resident_digest_matches(expected: &str, bytes: &[u8]) -> bool {
    if !resident_digest_valid(expected) {
        return false;
    }
    match expected.len() {
        32 => n2r_win32::content_digest::of(bytes) == expected,
        64 => hex::encode(Sha256::digest(bytes)) == expected,
        _ => false,
    }
}

/// Decode a complete unnamed list. Padding within each entry is retained by
/// the assembly ledger, while trailing bytes outside entries are not accepted.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>> {
    parse_with_limit(bytes, MAX_LIST_BYTES)
}

pub fn parse_with_limit(bytes: &[u8], maximum: usize) -> Result<Vec<Entry>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
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

fn record_identity(record: &RecordEvidence, mft_base: bool) -> Result<()> {
    ensure!(
        ((mft_base && record.record_number == 0)
            || (16..=RECORD_MASK).contains(&record.record_number))
            && record.sequence_number != 0,
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
/// list from further list segments is a separate gate.
pub fn validate_list_storage(
    attribute: &AttributeInventory,
    geometry: &NtfsGeometry,
) -> Result<()> {
    validate_initialized_metadata(attribute, geometry, 0x20, MAX_LIST_BYTES as u64, MAX_RUNS)
}

pub fn validate_mft_bitmap_storage(
    attribute: &AttributeInventory,
    geometry: &NtfsGeometry,
    records: u64,
) -> Result<()> {
    ensure!(
        records > 6 && records <= crate::ntfs_inspect::MAX_MFT_RECORDS,
        "MFT record count exceeds bootstrap bounds"
    );
    validate_initialized_metadata(
        attribute,
        geometry,
        0xb0,
        crate::ntfs_inspect::MAX_MFT_RECORDS.div_ceil(8),
        MAX_RUNS,
    )?;
    ensure!(
        attribute.logical_size >= records.div_ceil(8),
        "MFT bitmap cannot cover the record domain"
    );
    Ok(())
}

fn validate_initialized_metadata(
    attribute: &AttributeInventory,
    geometry: &NtfsGeometry,
    kind: u32,
    maximum: u64,
    maximum_runs: usize,
) -> Result<()> {
    ensure!(
        attribute.type_code == kind
            && attribute.name_utf16.is_empty()
            && attribute.flags == 0
            && attribute.compression_unit == 0
            && attribute.lowest_vcn == 0,
        "ordinary standalone attribute-list storage required"
    );
    ensure!(
        attribute.logical_size > 0
            && attribute.logical_size <= maximum
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
                    .is_some_and(|hash| resident_digest_valid(hash)),
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
            && attribute.extents.len() <= maximum_runs,
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
    assemble_profile(
        base,
        extensions,
        list_value,
        geometry,
        None,
        AssemblyLimits::LEGACY,
    )
}

pub fn assemble_mft(
    base: RecordEvidence,
    extensions: Vec<RecordEvidence>,
    list_value: &[u8],
    bitmap: &[u8],
    geometry: &NtfsGeometry,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    assemble_profile(
        base,
        extensions,
        list_value,
        geometry,
        Some(&SliceBitmap(bitmap)),
        AssemblyLimits::LEGACY,
    )
}

fn assemble_profile(
    base: RecordEvidence,
    extensions: Vec<RecordEvidence>,
    list_value: &[u8],
    geometry: &NtfsGeometry,
    mft_bitmap: Option<&dyn BitmapInput>,
    limits: AssemblyLimits,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    validate_working_assembly(&base, &extensions, list_value.len(), limits)?;
    let mft = mft_bitmap.is_some();
    ensure!(
        !extensions.is_empty() && extensions.len() <= limits.extension_records,
        "extension record count is empty or exceeds bound"
    );
    let entries = parse_with_limit(list_value, limits.list_bytes)?;
    ensure!(
        if mft {
            base.attributes.len() == 5
        } else {
            (4..=5).contains(&base.attributes.len())
        },
        "unsupported base attribute count"
    );
    record_identity(&base, mft)?;
    ensure!(
        !base.is_directory
            && base.base_file_reference == 0
            && base.hard_link_count == 1
            && (!mft || base.record_number == 0),
        "ordinary standalone base file with one link required"
    );
    let mut types = BTreeMap::new();
    for attribute in &base.attributes {
        ensure!(
            types.insert(attribute.type_code, attribute).is_none(),
            "duplicate base attribute type"
        );
        match attribute.type_code {
            0x10 | 0x30 => ensure!(
                attribute.resident && attribute.lowest_vcn == 0 && attribute.extents.is_empty(),
                "base metadata must be resident and standalone"
            ),
            0x50 if !mft => ensure!(
                attribute.resident && attribute.lowest_vcn == 0 && attribute.extents.is_empty(),
                "legacy security must be resident and standalone"
            ),
            0xb0 if mft => {} // Validated against the actual MFT domain below.
            0x20 => validate_initialized_metadata(
                attribute,
                geometry,
                0x20,
                limits.list_bytes as u64,
                limits.runs,
            )?,
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
    if let Some(bitmap) = mft_bitmap {
        let boot = geometry
            .mft_lcn
            .checked_mul(u64::from(geometry.cluster_size))
            .context("MFT boot location overflow")?;
        ensure!(
            data.extents
                .first()
                .is_some_and(|run| run.logical_offset == 0 && run.physical_offset == Some(boot)),
            "MFT DATA does not begin at its boot location"
        );
        ensure!(
            geometry.file_record_size > 0
                && data
                    .logical_size
                    .is_multiple_of(u64::from(geometry.file_record_size)),
            "MFT DATA ends in a partial record"
        );
        let records = data.logical_size / u64::from(geometry.file_record_size);
        let attribute = types.get(&0xb0).context("MFT base bitmap missing")?;
        ensure!(
            records <= limits.mft_records && attribute.logical_size <= limits.mft_bitmap_bytes,
            "MFT record/bitmap exceeds the selected assembly profile"
        );
        validate_bitmap_resource(attribute, geometry, records, limits.runs)?;
        ensure!(
            bitmap.byte_len() == attribute.logical_size && bitmap.allocated(0)?,
            "MFT bitmap length or base allocation differs"
        );
        bitmap.tail_zero(records)?;
        if attribute.resident {
            ensure!(
                attribute
                    .resident_sha256
                    .as_deref()
                    .map(|hash| bitmap.resident_matches(hash))
                    .transpose()?
                    .unwrap_or(false),
                "MFT resident bitmap bytes changed"
            );
        }
        for extension in &extensions {
            ensure!(
                extension.record_number < records && bitmap.allocated(extension.record_number)?,
                "MFT extension record is unallocated"
            );
        }
    }
    ensure!(
        list.logical_size == list_value.len() as u64
            && (!list.resident
                || list
                    .resident_sha256
                    .as_deref()
                    .is_some_and(|hash| resident_digest_matches(hash, list_value))),
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
        record_identity(extension, false)?;
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
                extents.len() < limits.runs,
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
    if mft {
        let bitmap = types.get(&0xb0).context("MFT bitmap absent")?;
        for extent in &bitmap.extents {
            let start = extent
                .physical_offset
                .context("MFT bitmap has no physical owner")?;
            physical.push((
                start,
                start
                    .checked_add(extent.length)
                    .context("MFT bitmap range overflow")?,
            ));
        }
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
            schema_version: if mft {
                if list.resident { 3 } else { 4 }
            } else if list.resident {
                1
            } else {
                2
            },
            base,
            extensions,
            list_value_hex: hex::encode(list_value),
            mft_bitmap_hex: mft_bitmap.and_then(BitmapInput::retained_hex),
            canonical_origins: None,
        },
    ))
}

/// Parse ordinary-file entries without interpreting a repeated FILE_NAME key
/// as a duplicate attribute. Exact origins remain unique. Type ordering is
/// checked here; stream coverage is checked by name and VCN during assembly.
/// We do not substitute a guessed Unicode comparator for NTFS's $UpCase table.
pub fn parse_stream_entries(bytes: &[u8]) -> Result<Vec<StreamEntry>> {
    parse_stream_entries_with_limit(bytes, MAX_LIST_BYTES)
}

pub fn parse_stream_entries_with_limit(bytes: &[u8], maximum: usize) -> Result<Vec<StreamEntry>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "ordinary attribute-list byte bound exceeded or list is empty"
    );
    let mut entries = Vec::new();
    let mut origins = BTreeSet::new();
    let mut previous_type = None;
    let mut at = 0usize;
    while at < bytes.len() {
        let header = bytes
            .get(at..at + 26)
            .context("truncated ordinary attribute-list entry")?;
        let length = u16::from_le_bytes(header[4..6].try_into()?) as usize;
        ensure!(
            length >= 26 && length.is_multiple_of(8),
            "invalid ordinary attribute-list entry length"
        );
        let end = at
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .context("ordinary attribute-list entry exceeds value")?;
        let name_length = usize::from(header[6]);
        let name_offset = usize::from(header[7]);
        let name_utf16 = if name_length == 0 {
            Vec::new()
        } else {
            let name_end = name_offset
                .checked_add(name_length * 2)
                .filter(|end| *end <= length)
                .context("ordinary attribute-list name exceeds entry")?;
            ensure!(
                name_offset >= 26 && name_offset.is_multiple_of(2),
                "ordinary attribute-list name overlaps its header or is unaligned"
            );
            bytes[at + name_offset..at + name_end]
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                .collect()
        };
        let type_code = u32::from_le_bytes(header[..4].try_into()?);
        ensure!(
            previous_type.is_none_or(|old| old <= type_code),
            "ordinary attribute-list types are unsorted"
        );
        let reference = u64::from_le_bytes(header[16..24].try_into()?);
        let record_number = reference & RECORD_MASK;
        let sequence_number = (reference >> 48) as u16;
        let instance = u16::from_le_bytes(header[24..26].try_into()?);
        ensure!(
            sequence_number != 0 && origins.insert((record_number, instance)),
            "ordinary attribute-list sequence is zero or origin is duplicated"
        );
        entries.push(StreamEntry {
            type_code,
            lowest_vcn: u64::from_le_bytes(header[8..16].try_into()?),
            record_number,
            sequence_number,
            instance,
            name_utf16,
        });
        previous_type = Some(type_code);
        at = end;
    }
    Ok(entries)
}

fn stream_record_identity(record: &RecordEvidence, complete_file: bool) -> Result<()> {
    ensure!(
        ((if complete_file { 1 } else { 16 })..=RECORD_MASK).contains(&record.record_number)
            && record.sequence_number != 0
            && (complete_file || !record.is_directory)
            && record.raw_record_sha256.len() == 64
            && resident_digest_valid(&record.raw_record_sha256),
        "invalid ordinary physical record identity"
    );
    let mut instances = BTreeSet::new();
    for attribute in &record.attributes {
        ensure!(
            instances.insert(attribute.instance)
                && attribute.flags == 0
                && attribute.compression_unit == 0
                && (attribute.type_code == 0x80 || complete_file
                    && matches!(attribute.type_code, 0x90 | 0xa0 | 0xb0 | 0x100)
                    || attribute.name_utf16.is_empty()),
            "unsupported physical attribute: FILE {}, instance {}, type={:#x}, flags={:#x}, compression_unit={}, name={:?}",
            record.record_number,attribute.instance,attribute.type_code,attribute.flags,
            attribute.compression_unit,attribute.name_utf16
        );
    }
    Ok(())
}

fn ordinary_resident(attribute: &AttributeInventory, metadata: bool) -> Result<()> {
    ensure!(
        attribute.resident
            && attribute.lowest_vcn == 0
            && attribute.extents.is_empty()
            && attribute.initialized_size == attribute.logical_size
            && attribute.allocated_size == attribute.logical_size
            && attribute
                .resident_sha256
                .as_deref()
                .is_some_and(resident_digest_valid),
        "ordinary resident attribute shape or content digest differs"
    );
    if metadata || attribute.resident_metadata_hex.is_some() {
        let encoded = attribute
            .resident_metadata_hex
            .as_deref()
            .context("ordinary resident metadata bytes are absent")?;
        ensure!(
            encoded.len() as u64
                == attribute
                    .logical_size
                    .checked_mul(2)
                    .context("ordinary resident metadata byte length overflow")?,
            "ordinary resident metadata byte length differs"
        );
        let bytes = hex::decode(encoded).context("invalid ordinary resident metadata bytes")?;
        ensure!(
            resident_digest_matches(attribute.resident_sha256.as_deref().unwrap(), &bytes),
            "ordinary resident metadata content digest differs"
        );
        match attribute.type_code {
            0x10 => ensure!(bytes.len() >= 48, "short ordinary standard information"),
            0x30 => {
                ensure!(bytes.len() >= 66, "short ordinary file name");
                ensure!(
                    bytes[65] <= 3 && bytes.len() == 66 + usize::from(bytes[64]) * 2,
                    "ordinary file-name namespace or length differs"
                );
            }
            0x50 => ensure!(bytes.len() >= 20, "short ordinary security descriptor"),
            _ => {}
        }
    }
    Ok(())
}

/// Assemble a bounded ordinary file by exact stream identity. All physical
/// attributes are listed and retained or consumed into a complete DATA stream;
/// no extension record becomes a second file. Resident semantic metadata may
/// reside in any owned physical record. Directories, encoded DATA and a list
/// which itself needs continuation records remain outside this profile.
pub fn assemble_streams(
    base: RecordEvidence,
    extensions: Vec<RecordEvidence>,
    list_value: &[u8],
    geometry: &NtfsGeometry,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    assemble_streams_resource(
        base,
        extensions,
        list_value,
        geometry,
        AssemblyLimits::LEGACY,
    )
}

pub fn assemble_streams_resource(
    base: RecordEvidence,
    extensions: Vec<RecordEvidence>,
    list_value: &[u8],
    geometry: &NtfsGeometry,
    limits: AssemblyLimits,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    assemble_attributes_inner(base, extensions, list_value, geometry, limits, false)
}

/// Complete unencoded metadata/directory assembly. This conserves physical
/// attributes; namespace, security and preservation admission remain separate.
pub fn assemble_attributes_resource(
    base: RecordEvidence, extensions: Vec<RecordEvidence>, list_value: &[u8],
    geometry: &NtfsGeometry, limits: AssemblyLimits,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    assemble_attributes_inner(base, extensions, list_value, geometry, limits, true)
}

fn assemble_attributes_inner(
    base: RecordEvidence, extensions: Vec<RecordEvidence>, list_value: &[u8],
    geometry: &NtfsGeometry, limits: AssemblyLimits, complete_file: bool,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    validate_working_assembly(&base, &extensions, list_value.len(), limits)?;
    let cluster = u64::from(geometry.cluster_size);
    ensure!(
        cluster > 0 && cluster.is_power_of_two() && geometry.volume_size > 0,
        "invalid ordinary assembly geometry"
    );
    ensure!(
        extensions.len() <= limits.extension_records,
        "ordinary extension record count exceeds bound"
    );
    stream_record_identity(&base, complete_file)?;
    ensure!(
        base.base_file_reference == 0 && base.hard_link_count > 0,
        "ordinary assembly needs a base file with a positive link count"
    );
    let base_reference = base.record_number | (u64::from(base.sequence_number) << 48);
    let mut record_numbers = BTreeSet::from([base.record_number]);
    for extension in &extensions {
        stream_record_identity(extension, complete_file)?;
        ensure!(
            record_numbers.insert(extension.record_number)
                && (complete_file || extension.hard_link_count == 0)
                && (!extension.is_directory || base.is_directory)
                && extension.base_file_reference == base_reference
                && !extension.attributes.is_empty(),
            "ordinary extension identity, ownership or contents differ"
        );
    }
    let raw_count = extensions
        .iter()
        .try_fold(base.attributes.len(), |count, record| {
            count.checked_add(record.attributes.len())
        })
        .context("ordinary raw attribute count overflow")?;
    ensure!(
        raw_count > 1 && raw_count <= limits.raw_attributes,
        "ordinary raw attribute count exceeds list capacity"
    );

    let mut attributes = BTreeMap::new();
    let mut list = None;
    let mut si_count = 0usize;
    let mut name_count = 0usize;
    let mut security_count = 0usize;
    let mut streams: BTreeMap<(u32,Vec<u16>), Vec<(CanonicalOrigin, &AttributeInventory)>> =
        BTreeMap::new();
    let mut canonical = Vec::new();
    for record in std::iter::once(&base).chain(&extensions) {
        for attribute in &record.attributes {
            let origin = CanonicalOrigin {
                record_number: record.record_number,
                sequence_number: record.sequence_number,
                instance: attribute.instance,
            };
            ensure!(
                attributes
                    .insert(
                        (origin.record_number, origin.instance),
                        (origin.sequence_number, attribute)
                    )
                    .is_none(),
                "ordinary physical attribute origin is duplicated"
            );
            match attribute.type_code {
                0x20 => {
                    ensure!(
                        record.record_number == base.record_number
                            && list.replace(attribute).is_none(),
                        "ordinary list must be a single base-record attribute"
                    );
                    validate_initialized_metadata(
                        attribute,
                        geometry,
                        0x20,
                        limits.list_bytes as u64,
                        limits.runs,
                    )?;
                }
                0x10 | 0x30 | 0x50 => {
                    ordinary_resident(attribute, true)?;
                    match attribute.type_code {
                        0x10 => si_count += 1,
                        0x30 => name_count += 1,
                        0x50 => security_count += 1,
                        _ => unreachable!(),
                    }
                    canonical.push((attribute.clone(), origin));
                }
                0x80 | 0x40 | 0x60 | 0x70 | 0x90 | 0xa0 | 0xb0 | 0xc0 | 0xd0 | 0xe0 | 0x100 => {
                    ensure!(attribute.type_code == 0x80 || complete_file,
                        "ordinary stream assembly cannot accept metadata attributes");
                    ensure!(
                        attribute.name_utf16.len() <= 255,
                        "ordinary stream name exceeds bound"
                    );
                    if attribute.resident {
                        ordinary_resident(attribute, false)?;
                    } else {
                        ensure!(
                            attribute.resident_sha256.is_none()
                                && attribute.resident_metadata_hex.is_none(),
                            "nonresident DATA has resident content evidence"
                        );
                    }
                    streams
                        .entry((attribute.type_code,attribute.name_utf16.clone()))
                        .or_default()
                        .push((origin, attribute));
                }
                _ => anyhow::bail!("ordinary list contains an unsupported attribute type"),
            }
        }
    }
    ensure!(
        si_count == 1
            && name_count > 0
            && security_count <= 1
            && (complete_file || streams.contains_key(&(0x80,Vec::new())))
            && streams.len() <= limits.streams,
        "ordinary semantic metadata or DATA stream inventory differs"
    );
    let list = list.context("ordinary base attribute list is absent")?;
    ensure!(
        list.logical_size == list_value.len() as u64
            && (!list.resident
                || list
                    .resident_sha256
                    .as_deref()
                    .is_some_and(|hash| resident_digest_matches(hash, list_value))),
        "ordinary attribute-list bytes differ from physical attribute"
    );
    if let Some(encoded) = &list.resident_metadata_hex {
        ensure!(
            encoded.len() == list_value.len() * 2 && hex::decode(encoded)? == list_value,
            "ordinary retained attribute-list bytes differ"
        );
    }
    let mut listed = BTreeSet::new();
    for entry in parse_stream_entries_with_limit(list_value, limits.list_bytes)? {
        let origin = (entry.record_number, entry.instance);
        let (sequence, attribute) = attributes
            .get(&origin)
            .context("ordinary list entry has no owned physical attribute")?;
        ensure!(
            entry.sequence_number == *sequence
                && entry.type_code == attribute.type_code
                && entry.name_utf16 == attribute.name_utf16
                && entry.lowest_vcn == attribute.lowest_vcn
                && listed.insert(origin),
            "ordinary list origin, stream name, type or VCN differs"
        );
    }
    ensure!(
        attributes
            .iter()
            .all(|(origin, (_, attribute))| attribute.type_code == 0x20 || listed.contains(origin)),
        "ordinary physical attribute is missing from its list"
    );

    let mut physical = Vec::new();
    let mut total_runs = 0usize;
    for (_, mut segments) in streams {
        segments.sort_by_key(|(_, attribute)| attribute.lowest_vcn);
        let (origin, leader) = &segments[0];
        ensure!(
            leader.lowest_vcn == 0,
            "ordinary DATA has no VCN-zero leader"
        );
        let mut merged: AttributeInventory = (**leader).clone();
        if leader.resident {
            ensure!(
                segments.len() == 1,
                "resident DATA has continuation attributes"
            );
        } else {
            ensure!(
                leader.initialized_size <= leader.logical_size
                    && leader.logical_size <= leader.allocated_size
                    && leader.allocated_size.is_multiple_of(cluster),
                "ordinary DATA leader lengths or allocation differ"
            );
            let mut next = 0u64;
            let mut extents = Vec::new();
            for (_, segment) in &segments {
                ensure!(
                    !segment.resident
                        && segment.lowest_vcn.checked_mul(cluster) == Some(next)
                        && (!segment.extents.is_empty()
                            || (segments.len() == 1 && leader.allocated_size == 0)),
                    "ordinary DATA segment VCN gap, overlap or form differs"
                );
                for extent in &segment.extents {
                    total_runs = total_runs
                        .checked_add(1)
                        .context("ordinary DATA run count overflow")?;
                    ensure!(
                        total_runs <= limits.runs
                            && extent.logical_offset == next
                            && extent.length > 0
                            && extent.length.is_multiple_of(cluster),
                        "ordinary DATA run budget, coverage or alignment differs"
                    );
                    let start = extent
                        .physical_offset
                        .context("sparse ordinary DATA remains unsupported")?;
                    let end = start
                        .checked_add(extent.length)
                        .context("ordinary DATA physical overflow")?;
                    ensure!(
                        start.is_multiple_of(cluster) && end <= geometry.volume_size,
                        "ordinary DATA physical run escapes volume or alignment"
                    );
                    next = next
                        .checked_add(extent.length)
                        .context("ordinary DATA VCN overflow")?;
                    physical.push((start, end));
                    extents.push(extent.clone());
                }
            }
            ensure!(
                next == leader.allocated_size,
                "ordinary DATA segments do not cover allocation"
            );
            merged.extents = extents;
        }
        canonical.push((merged, origin.clone()));
    }
    for extent in &list.extents {
        let start = extent
            .physical_offset
            .context("ordinary list storage is sparse")?;
        physical.push((
            start,
            start
                .checked_add(extent.length)
                .context("ordinary list physical overflow")?,
        ));
    }
    physical.sort_unstable();
    ensure!(
        physical.windows(2).all(|pair| pair[0].1 <= pair[1].0),
        "ordinary DATA streams or list storage physically overlap"
    );
    canonical.sort_by(|(a, ao), (b, bo)| {
        (a.type_code, &a.name_utf16, ao.record_number, ao.instance).cmp(&(
            b.type_code,
            &b.name_utf16,
            bo.record_number,
            bo.instance,
        ))
    });
    let reserved: BTreeSet<_> = canonical
        .iter()
        .map(|(attribute, _)| attribute.instance)
        .collect();
    let mut used = BTreeSet::new();
    let mut next_instance = 0u32;
    for (attribute, _) in &mut canonical {
        if !used.insert(attribute.instance) {
            while next_instance <= u16::MAX as u32
                && (reserved.contains(&(next_instance as u16))
                    || used.contains(&(next_instance as u16)))
            {
                next_instance += 1;
            }
            ensure!(
                next_instance <= u16::MAX as u32,
                "canonical attribute instances exhausted"
            );
            attribute.instance = next_instance as u16;
            used.insert(attribute.instance);
            next_instance += 1;
        }
    }
    let (canonical, origins) = canonical.into_iter().unzip();
    Ok((
        canonical,
        Assembly {
            schema_version: if complete_file { if list.resident { 8 } else { 9 } }
                else if list.resident { 5 } else { 6 },
            base,
            extensions,
            list_value_hex: hex::encode(list_value),
            mft_bitmap_hex: None,
            canonical_origins: Some(origins),
        },
    ))
}

/// Resource-bound list validation; the caller owns the admitted working RAM.
pub fn validate_list_resource(
    attribute: &AttributeInventory,
    geometry: &NtfsGeometry,
    limits: AssemblyLimits,
) -> Result<()> {
    validate_initialized_metadata(
        attribute,
        geometry,
        0x20,
        limits.list_bytes as u64,
        limits.runs,
    )
}
pub fn validate_bitmap_resource(
    attribute: &AttributeInventory,
    geometry: &NtfsGeometry,
    records: u64,
    maximum_runs: usize,
) -> Result<()> {
    ensure!(
        records > 6 && records <= RECORD_MASK,
        "invalid intrinsic MFT record domain"
    );
    validate_initialized_metadata(
        attribute,
        geometry,
        0xb0,
        attribute.logical_size,
        maximum_runs,
    )?;
    ensure!(
        attribute.logical_size >= records.div_ceil(8),
        "MFT bitmap is too short"
    );
    Ok(())
}

#[cfg(windows)]
struct RangeBitmap<'a>(&'a dyn crate::ntfs_inspect::SourceMetadataRange);
#[cfg(windows)]
impl BitmapInput for RangeBitmap<'_> {
    fn byte_len(&self) -> u64 {
        self.0.byte_len()
    }
    fn allocated(&self, record: u64) -> Result<bool> {
        if record / 8 >= self.byte_len() {
            return Ok(false);
        }
        let mut byte = [0];
        self.0.read_exact_at(record / 8, &mut byte)?;
        Ok(byte[0] & (1 << (record % 8)) != 0)
    }
    fn tail_zero(&self, records: u64) -> Result<()> {
        ensure!(
            self.byte_len() >= records.div_ceil(8),
            "short streamed MFT bitmap"
        );
        let mut offset = records / 8;
        let mut buffer = [0u8; 4096];
        while offset < self.byte_len() {
            let count = usize::try_from((self.byte_len() - offset).min(buffer.len() as u64))?;
            self.0.read_exact_at(offset, &mut buffer[..count])?;
            for (i, byte) in buffer[..count].iter().enumerate() {
                let bit = (offset + i as u64) * 8;
                let allowed = if bit >= records {
                    0
                } else {
                    (1u8 << (records - bit)) - 1
                };
                ensure!(
                    *byte & !allowed == 0,
                    "MFT bitmap allocates records beyond EOF"
                );
            }
            offset += count as u64;
        }
        Ok(())
    }
    fn resident_matches(&self, digest: &str) -> Result<bool> {
        let mut bytes = vec![0; usize::try_from(self.byte_len())?];
        self.0.read_exact_at(0, &mut bytes)?;
        Ok(resident_digest_matches(digest, &bytes))
    }
    fn retained_hex(&self) -> Option<String> {
        None
    }
}
#[cfg(windows)]
pub fn assemble_mft_resource(
    base: RecordEvidence,
    extensions: Vec<RecordEvidence>,
    list_value: &[u8],
    bitmap: &dyn crate::ntfs_inspect::SourceMetadataRange,
    geometry: &NtfsGeometry,
    limits: AssemblyLimits,
) -> Result<(Vec<AttributeInventory>, Assembly)> {
    let (canonical, mut ledger) = assemble_profile(
        base,
        extensions,
        list_value,
        geometry,
        Some(&RangeBitmap(bitmap)),
        limits,
    )?;
    // This is a working row, never replayed as legacy schema 3/4 evidence.
    // Its complete bitmap is pinned separately by the paged resolver.
    ledger.schema_version = 7;
    Ok((canonical, ledger))
}
