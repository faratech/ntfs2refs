//! Fresh conversion evidence and separately authenticated, read-only recovery
//! map facts. Deserializing facts never recreates source or write admission.
pub(crate) mod v4_maps;
use super::*;
use crate::{
    general_composite_target::FrozenAllocationTargetPreservation,
    general_qualification::{canonical_json_sha256, pretty_json_sha256},
    general_source_admission::AllocationCertificate,
    selected_journal,
};
use anyhow::{Context, ensure};
use n2r_win32::{attestation::Snapshot, metadata_pages, shadow_native::Report};
use serde_json::Value;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
};

type StreamKey = (Vec<String>, Vec<u16>);
type StreamMaps = BTreeMap<StreamKey, StreamMap>;

pub(crate) struct FreshPayloadProof {
    expected_tree_sha256: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    native: Arc<Report>,
    maps: Vec<StreamLocation>,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    plan_sha256: String,
    ticket_sha256: String,
    tail_extent_streams: usize,
    tail_payload_bytes_verified: u64,
    map_page_budget: metadata_pages::PageBudget,
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamMap {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: Vec<u8>,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<n2r_win32::sparse_layout::SparseLayout>,
    integrity: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StreamStandard {
    Data([u8; 22]),
    // Directory tree storage may grow for the separately verified post-mount
    // indexer cache. It is not retained file payload; namespace stays checked.
    DirectoryLinksAndType([u8; 6]),
}

/// A scalar snapshot and borrowed variable-sized buffers. Comparing an already
/// collected native report must not duplicate its retrieval and integrity data.
#[derive(PartialEq, Eq, Serialize)]
struct StreamMapRef<'a> {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: &'a [u8],
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<&'a n2r_win32::sparse_layout::SparseLayout>,
    integrity: &'a [u8],
}

impl StreamMap {
    fn as_ref(&self) -> StreamMapRef<'_> {
        StreamMapRef {
            file_id: self.file_id,
            standard: self.standard,
            retrieval: &self.retrieval,
            complete_page_proof: self.complete_page_proof,
            resident: self.resident,
            sparse: self.sparse.as_ref(),
            integrity: &self.integrity,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapEntry {
    components: Vec<String>,
    name_utf16: Vec<u16>,
    map: StreamMap,
}

/// Immutable observation facts pinned by the recovery bundle. No lifecycle,
/// device exclusion, native observation or write capability can be serialized.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPayloadManifest {
    schema_version: u32,
    kind: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    expected_tree_sha256: String,
    plan_sha256: String,
    ticket_sha256: String,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    bindings: Vec<MapEntry>,
    grants_write_authority: bool,
    initial_retained_content_digests_available: bool,
}

const MAP_PAGE_PURPOSE: [u8; 8] = *b"MAPREF01";
pub(crate) const PAGED_MAP_FILENAME: &str = "recovery-payload-manifest.pages";

fn map_page_budget(
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<metadata_pages::PageBudget> {
    if let Some(admission) = resources.resource_admission()? {
        return Ok(admission.map_page_budget()?);
    }
    if let Some(admission) = resources
        .count_admission()?
        .filter(|a| a.requires_paged_metadata())
    {
        return Ok(admission.map_page_budget()?);
    }
    Ok(metadata_pages::PageBudget {
        max_page_bytes: 4 * 1024 * 1024,
        max_records_per_page: 128,
        max_records: (n2r_win32::tree_resources::OBJECT_SLOTS
            + n2r_win32::tree_resources::DATA_STREAMS
            + 1) as u64,
        max_pages: (n2r_win32::tree_resources::OBJECT_SLOTS
            + n2r_win32::tree_resources::DATA_STREAMS
            + 1) as u64,
        max_file_bytes: super::selected_artifacts::Artifact::PayloadMap.maximum_bytes() as u64,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapManifestHeader {
    schema_version: u32,
    kind: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    expected_tree_sha256: String,
    plan_sha256: String,
    ticket_sha256: String,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    bindings_count: u64,
    grants_write_authority: bool,
    initial_retained_content_digests_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
}

#[derive(Serialize)]
struct MapEntryRef<'a> {
    components: &'a [String],
    name_utf16: &'a [u16],
    map: PagedStreamMapRef<'a>,
}

// The legacy byte-array JSON expands complete fragmented maps beyond one page.
// This wire form preserves every byte and sparse range in less than 3MiB at
// the existing native bounds; it is not an alternate mapping or admission.
struct Base64Bytes<'a>(&'a [u8]);
struct Base64Ranges<'a>(&'a [n2r_win32::sparse_layout::LogicalRange]);
struct Base64Display<I>(I);
impl<I: Iterator<Item = u8> + Clone> std::fmt::Display for Base64Display<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bytes = self.0.clone();
        while let Some(a) = bytes.next() {
            let b = bytes.next();
            let c = bytes.next();
            let encoded = [
                ABC[(a >> 2) as usize],
                ABC[(((a & 3) << 4) | (b.unwrap_or(0) >> 4)) as usize],
                b.map_or(b'=', |b| {
                    ABC[(((b & 15) << 2) | (c.unwrap_or(0) >> 6)) as usize]
                }),
                c.map_or(b'=', |c| ABC[(c & 63) as usize]),
            ];
            f.write_str(std::str::from_utf8(&encoded).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for Base64Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(&Base64Display(self.0.iter().copied()))
    }
}
impl Serialize for Base64Ranges<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(&Base64Display(self.0.iter().flat_map(|r| {
            r.offset
                .to_le_bytes()
                .into_iter()
                .chain(r.length.to_le_bytes())
        })))
    }
}
fn decode_base64(value: &str, maximum: usize) -> Result<Vec<u8>> {
    let input = value.as_bytes();
    ensure!(input.len().is_multiple_of(4), "map base64 length differs");
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    ensure!(padding <= 2, "map base64 padding differs");
    let length = input
        .len()
        .checked_div(4)
        .and_then(|n| n.checked_mul(3))
        .and_then(|n| n.checked_sub(padding))
        .context("map base64 length overflow")?;
    ensure!(length <= maximum, "decoded map field exceeds native bound");
    let digit = |b: u8| -> Result<u8> {
        Ok(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => anyhow::bail!("noncanonical map base64 alphabet"),
        })
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .context("decoded map storage unavailable")?;
    for (index, chunk) in input.chunks_exact(4).enumerate() {
        let last = index + 1 == input.len() / 4;
        let a = digit(chunk[0])?;
        let b = digit(chunk[1])?;
        bytes.push((a << 2) | (b >> 4));
        if chunk[2] == b'=' {
            ensure!(
                last && chunk[3] == b'=' && b & 15 == 0,
                "noncanonical map base64 padding bits"
            );
        } else {
            let c = digit(chunk[2])?;
            bytes.push((b << 4) | (c >> 2));
            if chunk[3] == b'=' {
                ensure!(last && c & 3 == 0, "noncanonical map base64 padding bits");
            } else {
                bytes.push((c << 6) | digit(chunk[3])?);
            }
        }
    }
    ensure!(bytes.len() == length, "decoded map length differs");
    Ok(bytes)
}

#[derive(Serialize)]
struct PagedSparseRef<'a> {
    initialized_length: u64,
    allocated: Base64Ranges<'a>,
    holes: Base64Ranges<'a>,
}
#[derive(Serialize)]
struct PagedStreamMapRef<'a> {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: Base64Bytes<'a>,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<PagedSparseRef<'a>>,
    integrity: Base64Bytes<'a>,
}
impl<'a> PagedStreamMapRef<'a> {
    fn new(map: StreamMapRef<'a>) -> Result<Self> {
        Self::with_resources(map, None)
    }
    fn with_resources(
        map: StreamMapRef<'a>,
        resources: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    ) -> Result<Self> {
        let maximum = resources.map_or(
            n2r_win32::stream_layout::COMPLETE_RETRIEVAL_CAPACITY as u64,
            |a| a.budget.max_row_bytes,
        );
        ensure!(
            map.retrieval.len() as u64 <= maximum && map.integrity.len() <= 16,
            "native map wire field exceeds complete bound"
        );
        if let Some(sparse) = map.sparse {
            ensure!(
                sparse
                    .allocated
                    .len()
                    .checked_add(sparse.holes.len())
                    .is_some_and(|n| n
                        <= resources.map_or(n2r_win32::sparse_layout::MAX_LAYOUT_RANGES, |a| (a
                            .budget
                            .max_row_bytes
                            / 16)
                            as usize)),
                "native sparse map wire exceeds complete bound"
            );
        }
        Ok(Self {
            file_id: map.file_id,
            standard: map.standard,
            retrieval: Base64Bytes(map.retrieval),
            complete_page_proof: map.complete_page_proof,
            resident: map.resident,
            integrity: Base64Bytes(map.integrity),
            sparse: map.sparse.map(|s| PagedSparseRef {
                initialized_length: s.initialized_length,
                allocated: Base64Ranges(&s.allocated),
                holes: Base64Ranges(&s.holes),
            }),
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedSparse {
    initialized_length: u64,
    allocated: String,
    holes: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedStreamMap {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: String,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<PagedSparse>,
    integrity: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedMapEntry {
    components: Vec<String>,
    name_utf16: Vec<u16>,
    map: PagedStreamMap,
}
fn decode_ranges(value: &str) -> Result<Vec<n2r_win32::sparse_layout::LogicalRange>> {
    decode_ranges_with_limit(value, n2r_win32::sparse_layout::MAX_LAYOUT_RANGES)
}
fn decode_ranges_with_limit(
    value: &str,
    maximum_ranges: usize,
) -> Result<Vec<n2r_win32::sparse_layout::LogicalRange>> {
    let bytes = decode_base64(
        value,
        maximum_ranges
            .checked_mul(16)
            .context("sparse range budget overflow")?,
    )?;
    ensure!(
        bytes.len().is_multiple_of(16),
        "packed sparse map length differs"
    );
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(bytes.len() / 16)
        .context("sparse map storage unavailable")?;
    for pair in bytes.chunks_exact(16) {
        ranges.push(n2r_win32::sparse_layout::LogicalRange {
            offset: u64::from_le_bytes(pair[..8].try_into()?),
            length: u64::from_le_bytes(pair[8..].try_into()?),
        });
    }
    Ok(ranges)
}
impl PagedMapEntry {
    fn decode(bytes: &[u8]) -> Result<MapEntry> {
        let entry: Self = serde_json::from_slice(bytes)?;
        entry.into_entry(None)
    }
    fn into_entry(
        self,
        resources: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    ) -> Result<MapEntry> {
        let entry = self;
        let maximum = resources
            .map(|a| usize::try_from(a.budget.max_row_bytes))
            .transpose()?
            .unwrap_or(n2r_win32::stream_layout::COMPLETE_RETRIEVAL_CAPACITY);
        let maximum_ranges = resources.map_or(n2r_win32::sparse_layout::MAX_LAYOUT_RANGES, |_| {
            maximum / 16
        });
        let map = entry.map;
        let sparse = map
            .sparse
            .map(|s| -> Result<_> {
                let allocated = if resources.is_some() {
                    decode_ranges_with_limit(&s.allocated, maximum_ranges)?
                } else {
                    decode_ranges(&s.allocated)?
                };
                let holes = if resources.is_some() {
                    decode_ranges_with_limit(&s.holes, maximum_ranges)?
                } else {
                    decode_ranges(&s.holes)?
                };
                ensure!(
                    allocated
                        .len()
                        .checked_add(holes.len())
                        .is_some_and(|n| n <= maximum_ranges),
                    "decoded sparse map exceeds combined native bound"
                );
                Ok(n2r_win32::sparse_layout::SparseLayout {
                    initialized_length: s.initialized_length,
                    allocated,
                    holes,
                })
            })
            .transpose()?;
        Ok(MapEntry {
            components: entry.components,
            name_utf16: entry.name_utf16,
            map: StreamMap {
                file_id: map.file_id,
                standard: map.standard,
                retrieval: decode_base64(&map.retrieval, maximum)?,
                complete_page_proof: map.complete_page_proof,
                resident: map.resident,
                sparse,
                integrity: decode_base64(&map.integrity, 16)?,
            },
        })
    }
}

/// Prefix-free keys preserve the existing (component strings, UTF16 name)
/// tuple order. Header key is empty; every stream key starts with tag1.
fn encoded_stream_key(components: &[String], name: &[u16]) -> Result<Vec<u8>> {
    let mut key = vec![1];
    for component in components {
        ensure!(
            !component.is_empty() && !component.as_bytes().contains(&0),
            "invalid recovery map component key"
        );
        key.extend_from_slice(component.as_bytes());
        key.push(0);
    }
    key.push(0);
    for unit in name {
        ensure!(*unit != 0, "invalid recovery map stream key");
        key.extend_from_slice(&unit.to_be_bytes());
    }
    key.extend_from_slice(&[0, 0]);
    Ok(key)
}

fn record_json(value: &impl Serialize) -> Result<Vec<u8>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= 4 * 1024 * 1024)
                .ok_or_else(|| std::io::Error::other("recovery map record exceeds page budget"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count.0)
        .context("recovery map record storage unavailable")?;
    serde_json::to_writer(&mut bytes, value)?;
    ensure!(
        bytes.len() == count.0,
        "borrowed recovery map record changed during serialization"
    );
    Ok(bytes)
}

fn chunk_key(base: &[u8], ordinal: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(base.len() + 8);
    key.extend_from_slice(base);
    key.extend_from_slice(&ordinal.to_be_bytes());
    key
}
fn chunk_capacity(budget: metadata_pages::PageBudget, key_bytes: usize) -> Result<usize> {
    let available = (budget.max_page_bytes as usize)
        .checked_sub(64 + 8 + key_bytes + 8 + 2)
        .context("map key leaves no page chunk space")?;
    let bytes = available / 4 * 3;
    ensure!(bytes > 0, "map key leaves no page chunk space");
    Ok(bytes)
}
fn row_size(value: &impl Serialize, maximum: u64) -> Result<u64> {
    struct Count {
        used: u64,
        maximum: u64,
    }
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.used = self
                .used
                .checked_add(b.len() as u64)
                .filter(|n| *n <= self.maximum)
                .ok_or_else(|| io::Error::other("map row encoding exceeds admitted budget"))?;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count { used: 0, maximum };
    serde_json::to_writer(&mut count, value)?;
    Ok(count.used)
}
#[derive(Clone, Copy)]
enum MapMemoryKind {
    Entry,
    Map,
    Sparse,
    Standard,
    Path,
    Name,
    Fixed,
    Text,
    Blob,
    RangeBlob,
    Scalar,
}
#[derive(Clone, Copy)]
struct MapMemory<'a> {
    kind: MapMemoryKind,
    used: &'a Cell<u64>,
    maximum: u64,
}
impl MapMemory<'_> {
    fn charge<E: serde::de::Error>(&self, n: u64) -> std::result::Result<(), E> {
        self.used.set(
            self.used
                .get()
                .checked_add(n)
                .filter(|n| *n <= self.maximum)
                .ok_or_else(|| {
                    E::custom("map encoded/decoded allocation exceeds resource row budget")
                })?,
        );
        Ok(())
    }
    fn text<E: serde::de::Error>(&self, length: u64) -> std::result::Result<(), E> {
        let string = length
            .checked_mul(2)
            .and_then(|n| n.checked_add(8))
            .ok_or_else(|| E::custom("map string allocation overflow"))?;
        self.charge(string)?;
        let decoded = length
            .checked_div(4)
            .and_then(|n| n.checked_mul(3))
            .ok_or_else(|| E::custom("map decoded length overflow"))?;
        match self.kind {
            MapMemoryKind::Blob => self.charge(decoded),
            MapMemoryKind::RangeBlob => self.charge(
                decoded
                    .checked_mul(2)
                    .ok_or_else(|| E::custom("map range allocation overflow"))?,
            ),
            _ => Ok(()),
        }
    }
    fn vector<E: serde::de::Error>(&self, count: u64, size: usize) -> std::result::Result<(), E> {
        if count == 0 || size == 0 {
            return Ok(());
        }
        let capacity = count
            .checked_next_power_of_two()
            .map(|n| n.max(8))
            .ok_or_else(|| E::custom("map vector capacity overflow"))?;
        self.charge(
            capacity
                .checked_mul(size as u64)
                .ok_or_else(|| E::custom("map vector allocation overflow"))?,
        )
    }
    fn field(self, name: &str) -> Option<MapMemoryKind> {
        use MapMemoryKind::*;
        Some(match (self.kind, name) {
            (Entry, "components") => Path,
            (Entry, "name_utf16") => Name,
            (Entry, "map") => Map,
            (Map, "file_id") => Fixed,
            (Map, "standard") => Standard,
            (Map, "retrieval" | "integrity") => Blob,
            (Map, "complete_page_proof" | "resident") => Scalar,
            (Map, "sparse") => Sparse,
            (Sparse, "initialized_length") => Scalar,
            (Sparse, "allocated" | "holes") => RangeBlob,
            (Standard, "data" | "directory_links_and_type") => Fixed,
            _ => return None,
        })
    }
}
impl<'de> serde::de::DeserializeSeed<'de> for MapMemory<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for MapMemory<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded typed recovery map row")
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        self.charge(0)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        self.charge(0)
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        self.charge(0)
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        self.charge(0)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        self.charge(0)
    }
    fn visit_str<E: serde::de::Error>(self, text: &str) -> std::result::Result<(), E> {
        if matches!(
            self.kind,
            MapMemoryKind::Text | MapMemoryKind::Blob | MapMemoryKind::RangeBlob
        ) {
            self.text(text.len() as u64)
        } else {
            self.charge(0)
        }
    }
    fn visit_string<E: serde::de::Error>(self, text: String) -> std::result::Result<(), E> {
        self.visit_str(&text)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<(), A::Error> {
        use MapMemoryKind::*;
        let (kind, size) = match self.kind {
            Path => (Text, std::mem::size_of::<String>()),
            Name => (Scalar, 2),
            Fixed => (Scalar, 0),
            _ => {
                return Err(<A::Error as serde::de::Error>::custom(
                    "unexpected map allocation sequence",
                ));
            }
        };
        let mut count = 0u64;
        while seq
            .next_element_seed(MapMemory {
                kind,
                used: self.used,
                maximum: self.maximum,
            })?
            .is_some()
        {
            count = count.checked_add(1).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom("map vector count overflow")
            })?;
        }
        self.vector(count, size)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<(), A::Error> {
        while let Some(field) = map.next_key::<String>()? {
            let kind = self
                .field(&field)
                .ok_or_else(|| <A::Error as serde::de::Error>::custom("unknown typed map field"))?;
            map.next_value_seed(MapMemory {
                kind,
                used: self.used,
                maximum: self.maximum,
            })?;
        }
        self.charge(0)
    }
}
fn initial_row_memory(bytes: u64, maximum: u64) -> Result<Cell<u64>> {
    let used = bytes
        .checked_add(std::mem::size_of::<PagedMapEntry>() as u64)
        .and_then(|n| n.checked_add(std::mem::size_of::<MapEntry>() as u64))
        .filter(|n| *n <= maximum)
        .context("map row base allocation exceeds resource budget")?;
    Ok(Cell::new(used))
}
fn validate_borrowed_row_memory(entry: &MapEntryRef<'_>, bytes: u64, maximum: u64) -> Result<()> {
    let used = initial_row_memory(bytes, maximum)?;
    let charge = MapMemory {
        kind: MapMemoryKind::Entry,
        used: &used,
        maximum,
    };
    charge.vector::<serde_json::Error>(
        entry.components.len() as u64,
        std::mem::size_of::<String>(),
    )?;
    charge.vector::<serde_json::Error>(entry.name_utf16.len() as u64, 2)?;
    for component in entry.components {
        MapMemory {
            kind: MapMemoryKind::Text,
            ..charge
        }
        .text::<serde_json::Error>(component.len() as u64)?;
    }
    let encoded = |bytes: usize| -> Result<u64> {
        (bytes as u64)
            .checked_add(2)
            .and_then(|n| n.checked_div(3))
            .and_then(|n| n.checked_mul(4))
            .context("map wire length overflow")
    };
    for blob in [entry.map.retrieval.0, entry.map.integrity.0] {
        MapMemory {
            kind: MapMemoryKind::Blob,
            ..charge
        }
        .text::<serde_json::Error>(encoded(blob.len())?)?;
    }
    if let Some(sparse) = &entry.map.sparse {
        for ranges in [sparse.allocated.0, sparse.holes.0] {
            let bytes = ranges
                .len()
                .checked_mul(16)
                .context("map sparse wire length overflow")?;
            MapMemory {
                kind: MapMemoryKind::RangeBlob,
                ..charge
            }
            .text::<serde_json::Error>(encoded(bytes)?)?;
        }
    }
    Ok(())
}
struct MapChunkWriter<'a> {
    writer: &'a mut metadata_pages::Writer,
    key: &'a [u8],
    maximum: usize,
    limit: u64,
    buffer: Vec<u8>,
    chunks: u64,
    bytes: u64,
}
impl MapChunkWriter<'_> {
    fn emit(&mut self) -> io::Result<()> {
        let encoded = serde_json::to_vec(&Base64Bytes(&self.buffer)).map_err(io::Error::other)?;
        self.writer
            .push(&chunk_key(self.key, self.chunks), &encoded)?;
        self.chunks = self
            .chunks
            .checked_add(1)
            .ok_or_else(|| io::Error::other("map chunk count overflow"))?;
        self.buffer.clear();
        Ok(())
    }
}
impl Write for MapChunkWriter<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        self.bytes = self
            .bytes
            .checked_add(length as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::other("map row exceeds admitted resource budget"))?;
        while !bytes.is_empty() {
            let n = bytes.len().min(self.maximum - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.buffer.len() == self.maximum {
                self.emit()?;
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct MapChunkReader<'a> {
    reader: &'a mut metadata_pages::Reader,
    key: &'a [u8],
    row: MapRowLocation,
    maximum: usize,
    next: u64,
    loaded: u64,
    buffer: Vec<u8>,
    position: usize,
}
impl Read for MapChunkReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.position == self.buffer.len() {
            if self.next == self.row.chunks {
                if self.loaded != self.row.bytes {
                    return Err(io::Error::other("complete map chunk bytes differ"));
                }
                return Ok(0);
            }
            let record = self.reader.get(self.row.first + self.next)?;
            if record.key != chunk_key(self.key, self.next) {
                return Err(io::Error::other("map chunk key differs"));
            }
            let text: &str = serde_json::from_slice(&record.payload).map_err(io::Error::other)?;
            self.buffer = decode_base64(text, self.maximum).map_err(io::Error::other)?;
            self.loaded = self
                .loaded
                .checked_add(self.buffer.len() as u64)
                .filter(|n| *n <= self.row.bytes)
                .ok_or_else(|| io::Error::other("map chunk bytes overflow"))?;
            self.next += 1;
            self.position = 0;
        }
        let n = out.len().min(self.buffer.len() - self.position);
        out[..n].copy_from_slice(&self.buffer[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}
fn read_map_row(
    reader: &mut metadata_pages::Reader,
    key: &[u8],
    row: MapRowLocation,
    admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
) -> Result<MapEntry> {
    if let Some(admission) = admission {
        ensure!(
            row.bytes <= admission.budget.max_row_bytes,
            "map row exceeds resource budget"
        );
        let maximum = chunk_capacity(admission.map_page_budget()?, key.len())?;
        {
            let input = MapChunkReader {
                reader: &mut *reader,
                key,
                row,
                maximum,
                next: 0,
                loaded: 0,
                buffer: Vec::new(),
                position: 0,
            };
            let used = initial_row_memory(row.bytes, admission.budget.max_row_bytes)?;
            let mut decoder = serde_json::Deserializer::from_reader(input);
            serde::de::DeserializeSeed::deserialize(
                MapMemory {
                    kind: MapMemoryKind::Entry,
                    used: &used,
                    maximum: admission.budget.max_row_bytes,
                },
                &mut decoder,
            )?;
            decoder.end()?;
        }
        let input = MapChunkReader {
            reader: &mut *reader,
            key,
            row,
            maximum,
            next: 0,
            loaded: 0,
            buffer: Vec::new(),
            position: 0,
        };
        let mut decoder = serde_json::Deserializer::from_reader(input);
        let entry = PagedMapEntry::deserialize(&mut decoder)?;
        decoder.end()?;
        let entry = entry.into_entry(Some(admission))?;
        check_decoded_map_memory(&entry, row.bytes, admission.budget.max_row_bytes)?;
        Ok(entry)
    } else {
        let record = reader.get(row.first)?;
        ensure!(record.key == key, "held map record key changed");
        PagedMapEntry::decode(&record.payload)
    }
}
fn check_decoded_map_memory(entry: &MapEntry, compact: u64, maximum: u64) -> Result<()> {
    let mut used = compact
        .checked_add(std::mem::size_of::<MapEntry>() as u64)
        .context("decoded map base allocation overflow")?;
    let mut charge = |bytes: usize| -> Result<()> {
        used = used
            .checked_add(bytes as u64)
            .filter(|n| *n <= maximum)
            .context("actual decoded map exceeds resource budget")?;
        Ok(())
    };
    charge(
        entry
            .components
            .capacity()
            .checked_mul(std::mem::size_of::<String>())
            .context("map path allocation overflow")?,
    )?;
    for component in &entry.components {
        charge(component.capacity())?;
    }
    charge(
        entry
            .name_utf16
            .capacity()
            .checked_mul(2)
            .context("map stream name allocation overflow")?,
    )?;
    charge(entry.map.retrieval.capacity())?;
    charge(entry.map.integrity.capacity())?;
    if let Some(sparse) = &entry.map.sparse {
        charge(
            sparse
                .allocated
                .capacity()
                .checked_add(sparse.holes.capacity())
                .and_then(|n| {
                    n.checked_mul(std::mem::size_of::<n2r_win32::sparse_layout::LogicalRange>())
                })
                .context("map sparse allocation overflow")?,
        )?;
    }
    Ok(())
}

/// Only scalar facts are needed after parsing and checking the complete pinned
/// manifest. Its binding buffers move into the proof's sole canonical map.
struct RecoveryPayloadHeader {
    schema_version: u32,
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    expected_tree_sha256: String,
    plan_sha256: String,
    ticket_sha256: String,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
}

enum RecoveryMaps {
    Legacy(StreamMaps),
    Paged {
        reader: RefCell<metadata_pages::Reader>,
        index: Vec<(Vec<u8>, MapRowLocation)>,
        resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    },
}
#[derive(Clone, Copy)]
struct MapRowLocation {
    first: u64,
    chunks: u64,
    bytes: u64,
}

impl RecoveryMaps {
    fn len(&self) -> usize {
        match self {
            Self::Legacy(maps) => maps.len(),
            Self::Paged { index, .. } => index.len(),
        }
    }
}

pub(crate) struct RecoveryPayloadProof {
    facts: RecoveryPayloadHeader,
    maps: RecoveryMaps,
}

fn query(snapshot: &Snapshot, class: i32) -> Result<&[u8]> {
    let mut found = snapshot.queries.iter().filter(|query| query.class == class);
    let value = found.next().context("fast stream binding query absent")?;
    ensure!(
        found.next().is_none() && value.native_error.is_none() && value.bytes.len() == 24,
        "fast stream binding query refused or ambiguous"
    );
    Ok(&value.bytes)
}

fn stream_map_ref<'a>(
    snapshot: &Snapshot,
    retrieval: &'a [u8],
    paged: bool,
    resident: bool,
    sparse: Option<&'a n2r_win32::sparse_layout::SparseLayout>,
    integrity: &'a [u8],
) -> Result<StreamMapRef<'a>> {
    let identity = query(snapshot, 18)?;
    let standard = query(snapshot, 1)?;
    ensure!(standard[20] == 0, "fast stream is delete pending");
    // File identities live in the copied ReFS metadata graph. Volume paths and
    // disk numbers change at cutover; neither substitutes for the 128-bit ID.
    Ok(StreamMapRef {
        file_id: identity[8..].try_into()?,
        standard: if standard[21] == 0 {
            StreamStandard::Data(standard[..22].try_into()?)
        } else {
            StreamStandard::DirectoryLinksAndType(standard[16..22].try_into()?)
        },
        retrieval,
        complete_page_proof: paged,
        resident,
        sparse,
        integrity,
    })
}

type StreamKeyRef<'a> = (&'a [String], &'a [u16]);

/// Numeric indexes into the shared immutable observation; paths and variable
/// map buffers remain owned only by that original native report.
#[derive(Clone, Copy)]
struct StreamLocation {
    object: usize,
    named: Option<usize>,
}

impl StreamLocation {
    /// The path and stream name of this binding, lent to `read`: a row of
    /// the report is borrowed only while it is being read.
    fn with_key<T>(self, report: &Report, read: impl FnOnce(StreamKeyRef<'_>) -> T) -> T {
        report
            .objects
            .with(self.object, |object| {
                let name = self.named.map_or(&[] as &[u16], |index| {
                    object.named_streams[index].name_utf16.as_slice()
                });
                Ok(read((object.components.as_slice(), name)))
            })
            .expect("a stream location names a row of its own report")
    }

    /// How this binding's key orders against `other`'s, both of `report`.
    fn cmp_key(self, other: Self, report: &Report) -> std::cmp::Ordering {
        self.with_key(report, |a| other.with_key(report, |b| a.cmp(&b)))
    }

    /// The key and the map of this binding, lent to `read`.
    fn view<T>(
        self,
        report: &Report,
        read: impl FnOnce(StreamKeyRef<'_>, StreamMapRef<'_>) -> Result<T>,
    ) -> Result<T> {
        report.objects.try_with(self.object, |object| {
            let (name, snapshot, retrieval, paged, resident, sparse, integrity) =
                if let Some(index) = self.named {
                    let stream = &object.named_streams[index];
                    (
                        stream.name_utf16.as_slice(),
                        &stream.before,
                        stream.retrieval.as_slice(),
                        stream.retrieval_page_proof.is_some(),
                        stream.resident_data,
                        stream.sparse.as_ref().map(|sparse| &sparse.expected),
                        stream.integrity.as_slice(),
                    )
                } else {
                    (
                        &[] as &[u16],
                        &object.before,
                        object.retrieval.as_slice(),
                        object.retrieval_page_proof.is_some(),
                        object.resident_data,
                        object.sparse.as_ref().map(|sparse| &sparse.expected),
                        object.integrity.as_slice(),
                    )
                };
            read(
                (object.components.as_slice(), name),
                stream_map_ref(snapshot, retrieval, paged, resident, sparse, integrity)?,
            )
        })
    }
}

/// A binding ordered by its key, which stays in the report: the key is read
/// from the binding's row whenever two bindings are compared.
struct KeyOrdered<'a> {
    location: StreamLocation,
    report: &'a Report,
}

impl Ord for KeyOrdered<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.location.cmp_key(other.location, self.report)
    }
}

impl PartialOrd for KeyOrdered<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for KeyOrdered<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for KeyOrdered<'_> {}

fn maps(report: &Report) -> Result<Vec<StreamLocation>> {
    // The keys' slice tuples have the same lexicographic ordering as the old
    // owned Vec tuples, preserving the exact manifest binding sequence.
    let mut maps = BTreeSet::new();
    report
        .objects
        .try_for_each(|object_index, object| -> Result<()> {
            ensure!(
                object.before == object.after,
                "fast object metadata changed during observation"
            );
            let location = StreamLocation {
                object: object_index,
                named: None,
            };
            location.view(report, |_, _| Ok(()))?;
            ensure!(
                maps.insert(KeyOrdered { location, report }),
                "duplicate fast canonical object"
            );
            for (stream_index, stream) in object.named_streams.iter().enumerate() {
                ensure!(
                    stream.before == stream.after,
                    "fast named stream metadata changed"
                );
                let location = StreamLocation {
                    object: object_index,
                    named: Some(stream_index),
                };
                location.view(report, |_, _| Ok(()))?;
                ensure!(
                    !stream.name_utf16.is_empty() && maps.insert(KeyOrdered { location, report }),
                    "duplicate fast named stream"
                );
            }
            Ok(())
        })?;
    Ok(maps.into_iter().map(|binding| binding.location).collect())
}
fn maps_with_resources(
    report: &Report,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
) -> Result<Vec<StreamLocation>> {
    admission.validate()?;
    ensure!(
        report.resource_profile
            == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                Some(admission)
            )),
        "native map owner resource admission differs"
    );
    let mut count = 0usize;
    report.objects.try_for_each(|_, o| -> Result<()> {
        count = count
            .checked_add(1)
            .and_then(|n| n.checked_add(o.named_streams.len()))
            .context("native map count overflow")?;
        Ok(())
    })?;
    ensure!(
        count as u64
            == admission
                .directories
                .checked_add(admission.data_streams)
                .context("native map count overflow")?,
        "native complete map count differs from actual admitted tree"
    );
    let maximum = (count as u64)
        .checked_mul(
            (std::mem::size_of::<StreamLocation>() + std::mem::size_of::<(&StreamLocation, bool)>())
                as u64,
        )
        .context("native map index memory overflow")?;
    ensure!(
        maximum <= admission.budget.retained_index_bytes,
        "native map index exceeds resource budget"
    );
    let mut locations = Vec::new();
    locations.try_reserve_exact(count)?;
    ensure!(
        (locations.capacity() as u64)
            .checked_mul(std::mem::size_of::<StreamLocation>() as u64)
            .is_some_and(|n| n <= admission.budget.retained_index_bytes),
        "actual native map index allocation exceeds budget"
    );
    report
        .objects
        .try_for_each(|object_index, object| -> Result<()> {
            ensure!(
                object.before == object.after,
                "fast object metadata changed during observation"
            );
            locations.push(StreamLocation {
                object: object_index,
                named: None,
            });
            for (index, stream) in object.named_streams.iter().enumerate() {
                ensure!(
                    stream.before == stream.after && !stream.name_utf16.is_empty(),
                    "fast named stream metadata changed or unnamed"
                );
                locations.push(StreamLocation {
                    object: object_index,
                    named: Some(index),
                });
            }
            Ok(())
        })?;
    locations.sort_unstable_by(|a, b| a.cmp_key(*b, report));
    ensure!(
        locations
            .windows(2)
            .all(|v| v[0].cmp_key(v[1], report).is_lt()),
        "duplicate native map binding"
    );
    Ok(locations)
}

/// Compare every reported binding without constructing another owning map.
/// The sorted index reads keys and buffers where they are held; one seen flag
/// per binding preserves duplicate detection and complete-set equality.
/// `order` is how an expected binding's key orders against a reported key,
/// and `same` whether its map is the reported one.
fn maps_match<T>(
    report: &Report,
    expected: impl IntoIterator<Item = T>,
    order: impl Fn(&T, StreamKeyRef<'_>) -> std::cmp::Ordering,
    same: impl Fn(&T, &StreamMapRef<'_>) -> Result<bool>,
) -> Result<bool> {
    let mut bindings: Vec<_> = expected.into_iter().map(|value| (value, false)).collect();
    let mut match_stream = |components: &[String], name: &[u16], value: StreamMapRef<'_>| {
        let found = bindings.binary_search_by(|(binding, _)| order(binding, (components, name)));
        let Ok(index) = found else {
            return Ok(false);
        };
        let (expected, seen) = &mut bindings[index];
        ensure!(!*seen, "duplicate fast canonical stream");
        *seen = true;
        same(expected, &value)
    };
    // Once a binding differs the answer is known and the rows after it are
    // passed by unread, as they were when the walk ended there.
    let mut matched = true;
    report.objects.try_for_each(|_, object| -> Result<()> {
        if !matched {
            return Ok(());
        }
        ensure!(
            object.before == object.after,
            "fast object metadata changed during observation"
        );
        if !match_stream(
            &object.components,
            &[],
            stream_map_ref(
                &object.before,
                &object.retrieval,
                object.retrieval_page_proof.is_some(),
                object.resident_data,
                object.sparse.as_ref().map(|sparse| &sparse.expected),
                &object.integrity,
            )?,
        )? {
            matched = false;
            return Ok(());
        }
        for stream in &object.named_streams {
            ensure!(
                stream.before == stream.after,
                "fast named stream metadata changed"
            );
            ensure!(!stream.name_utf16.is_empty(), "duplicate fast named stream");
            if !match_stream(
                &object.components,
                &stream.name_utf16,
                stream_map_ref(
                    &stream.before,
                    &stream.retrieval,
                    stream.retrieval_page_proof.is_some(),
                    stream.resident_data,
                    stream.sparse.as_ref().map(|sparse| &sparse.expected),
                    &stream.integrity,
                )?,
            )? {
                matched = false;
                return Ok(());
            }
        }
        Ok(())
    })?;
    Ok(matched && bindings.iter().all(|(_, seen)| *seen))
}

impl FreshPayloadProof {
    pub(crate) fn new(
        proof: &FrozenAllocationTargetPreservation,
        certificate: &AllocationCertificate,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<Self> {
        expected.revalidate_domain()?;
        let expected_tree_sha256 = pretty_json_sha256(expected)?;
        ensure!(
            certificate.binds(proof)
                && proof.data_ties_verified()
                && proof.expected_tree_sha256() == expected_tree_sha256
                && certificate.expected_tree_sha256() == expected_tree_sha256
                && serde_json::to_vec(plan)?
                    == serde_json::to_vec(&proof.plan(plan.max_journal_bytes)?)?,
            "fresh payload proof differs from the original live certificate or exact selected plan"
        );
        // The explicit ticket profile chooses the exact marker-body length.
        let (selected_bytes, journal_bytes) =
            plan.validate_marker_profile(ticket.marker_profile)?;
        ensure!(
            ticket.image_length == proof.pair().source.identity.partition_bytes
                && ticket.selected_bytes == selected_bytes
                && ticket.journal_length == journal_bytes
                && ticket.range_count as usize == plan.ranges.len()
                && !ticket.whole_image_verified
                && ticket.new_selected_sha256 != ticket.old_selected_sha256,
            "fresh payload ticket differs from its prepared plan"
        );
        let native = proof
            .protected_layout()
            .native()
            .report()
            .native_observation();
        let resource_admission = resources.resource_admission()?;
        if let Some(admission) = resource_admission {
            expected.require_resource_metadata(admission)?;
            ensure!(
                native.resource_profile == resources.native_profile(),
                "fresh native map resource profile differs from admitted owner"
            );
        }
        let native_maps = if let Some(admission) = resource_admission {
            maps_with_resources(&native, admission)?
        } else {
            maps(&native)?
        };
        if let Some(admission) = resource_admission {
            let expected_keys = resource_expected_keys(expected, admission)?;
            ensure!(
                expected_keys.len() == native_maps.len(),
                "fresh native map set differs from actual expected owner"
            );
            for (key, location) in expected_keys.iter().zip(&native_maps) {
                let encoded = location.with_key(&native, |(components, name)| {
                    encoded_stream_key(components, name)
                })?;
                ensure!(
                    *key == encoded,
                    "fresh native map key set differs from actual expected owner"
                );
            }
        }
        let protected = proof.protected_layout().native().report();
        let mut tail_extent_streams = 0usize;
        let mut tail_payload_bytes_verified = 0u64;
        for object_index in 0..expected.object_count() {
            let object = expected.object(object_index)?;
            for stream in object.data_streams().filter(|s| {
                s.source_evidence
                    == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
            }) {
                let actual = protected
                    .residual_for(object_index, stream.name_utf16)?
                    .context("extent-only partial tail has no retained protected observation")?;
                ensure!(
                    protected.residual_contents_verified()
                        && actual.logical_offset == n2r_win32::target_cluster::floor(stream.length)
                        && actual.length == stream.length % n2r_win32::target_cluster::bytes()
                        && actual.sha256.len() == 64,
                    "extent-only partial tail lacks exact protected source-to-target residual verification"
                );
                tail_extent_streams += 1;
                tail_payload_bytes_verified = tail_payload_bytes_verified
                    .checked_add(actual.length)
                    .context("verified extent-tail byte count overflow")?;
            }
        }
        Ok(Self {
            expected_tree_sha256,
            source: proof.pair().source.clone(),
            maps: native_maps,
            base_sectors: native.base_sectors,
            native,
            new_selected_sha256: ticket.new_selected_sha256,
            selected_bytes,
            range_count: ticket.range_count,
            plan_sha256: canonical_json_sha256(plan)?,
            ticket_sha256: canonical_json_sha256(ticket)?,
            tail_extent_streams,
            tail_payload_bytes_verified,
            map_page_budget: map_page_budget(resources)?,
            resource_admission,
        })
    }

    /// Stream one borrowed native binding at a time. The bundle pins the
    /// finished immutable page file, never a serialized capability.
    pub(crate) fn write_recovery_manifest(&self, path: &Path) -> Result<String> {
        let header = MapManifestHeader {
            schema_version: if self.resource_admission.is_some() {
                3
            } else {
                2
            },
            kind: if self.resource_admission.is_some() {
                "protected-target-stream-map-pages-v3"
            } else {
                "protected-target-stream-map-pages-v2"
            }
            .into(),
            source: self.source.clone(),
            expected_tree_sha256: self.expected_tree_sha256.clone(),
            plan_sha256: self.plan_sha256.clone(),
            ticket_sha256: self.ticket_sha256.clone(),
            base_sectors: self.base_sectors,
            new_selected_sha256: self.new_selected_sha256,
            selected_bytes: self.selected_bytes,
            range_count: self.range_count,
            bindings_count: self.maps.len() as u64,
            grants_write_authority: false,
            initial_retained_content_digests_available: false,
            resource_admission: self.resource_admission,
        };
        let mut writer = metadata_pages::Writer::new(path, MAP_PAGE_PURPOSE, self.map_page_budget)?;
        writer.push(&[], &record_json(&header)?)?;
        let mut total = 0u64;
        for location in &self.maps {
            location.view(&self.native, |(components, name_utf16), map| {
                let key = encoded_stream_key(components, name_utf16)?;
                let entry = MapEntryRef {
                    components,
                    name_utf16,
                    map: if self.resource_admission.is_some() {
                        PagedStreamMapRef::with_resources(map, self.resource_admission)?
                    } else {
                        PagedStreamMapRef::new(map)?
                    },
                };
                if let Some(admission) = self.resource_admission {
                    let compact = row_size(&entry, admission.budget.max_row_bytes)?;
                    validate_borrowed_row_memory(&entry, compact, admission.budget.max_row_bytes)?;
                    total = total
                        .checked_add(compact)
                        .filter(|n| *n <= admission.semantic_byte_budget())
                        .context("complete map encoding exceeds semantic resource budget")?;
                    let mut chunks = MapChunkWriter {
                        writer: &mut writer,
                        key: &key,
                        maximum: chunk_capacity(self.map_page_budget, key.len())?,
                        limit: admission.budget.max_row_bytes,
                        buffer: Vec::new(),
                        chunks: 0,
                        bytes: 0,
                    };
                    serde_json::to_writer(&mut chunks, &entry)?;
                    chunks.emit()?;
                } else {
                    writer.push(&key, &record_json(&entry)?)?;
                }
                Ok(())
            })?;
        }
        Ok(writer.finish()?.sha256)
    }

    fn verify(
        &self,
        scope: &NativeVerificationScope<'_>,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        applied: &selected_journal::SelectedResult,
        handoff: &selected_journal::SelectedResult,
        native: &shadow_native::GeneralConvertedReport,
    ) -> Result<Value> {
        ensure!(
            scope.pair.source == self.source
                && native.pair.source.identity == self.source.identity
                && pretty_json_sha256(expected)? == self.expected_tree_sha256,
            "fresh payload source or expected tree changed at handoff"
        );
        for result in [applied, handoff] {
            ensure!(
                result.selected_sha256 == self.new_selected_sha256
                    && result.selected_bytes == self.selected_bytes
                    && result.range_count == self.range_count
                    && !result.whole_image_verified,
                "fresh payload apply/handoff checksum differs"
            );
        }
        ensure!(
            handoff.replay_closed,
            "extent verification requires a durable closed handoff"
        );
        let observation = native
            .content_observation
            .as_ref()
            .context("metadata observation scope absent")?;
        ensure!(
            !observation.full_file_hashes
                && observation.admitted_payload_bytes_read == 0
                && observation.metadata_and_namespace_verified
                && observation.complete_stream_mappings_observed
                && observation.data_storage_validity_checked
                && native.native.base_sectors == self.base_sectors
                && maps_match(
                    &native.native,
                    &self.maps,
                    |location, key| location.with_key(&self.native, |held| held.cmp(&key)),
                    |location, value| location.view(&self.native, |_, map| Ok(map == *value)),
                )?,
            "mounted file identities, complete physical maps or storage validity differ from the protected candidate"
        );
        Ok(
            serde_json::json!({"schema_version":1,"scope":"fresh-conversion-extent-identity-v1",
            "expected_tree_sha256":self.expected_tree_sha256,"stream_and_directory_bindings":self.maps.len(),
            "selected_bytes_checksummed":self.selected_bytes,"selected_sha256":hex::encode(self.new_selected_sha256),
            "retained_bytes_proven_by_same_physical_mapping":true,
            "resident_and_residual_bytes_bound_by_selected_image":true,
            "all_complete_maps_identical":true,"handoff_replay_closed":true,
            "extent_only_partial_streams":self.tail_extent_streams,
            "materialized_extent_tail_bytes_verified":self.tail_payload_bytes_verified,
            "target_full_file_hashes":false,"target_admitted_payload_bytes_read":0,
            "saved_receipt_grants_execution_authority":false}),
        )
    }
}

fn expected_map_keys(
    expected: &impl shadow_tree::ExpectedObjectDomain,
) -> Result<BTreeSet<Vec<u8>>> {
    let mut keys = BTreeSet::new();
    for index in 0..expected.object_count() {
        let object = expected.object(index)?;
        ensure!(
            keys.insert(encoded_stream_key(&object.path, &[])?),
            "duplicate expected map object"
        );
        for stream in &object.named_streams {
            ensure!(
                keys.insert(encoded_stream_key(&object.path, &stream.name_utf16)?),
                "duplicate expected map stream"
            );
        }
    }
    Ok(keys)
}
fn expected_binding_count(expected: &impl shadow_tree::ExpectedObjectDomain) -> Result<u64> {
    let mut count = 0u64;
    for i in 0..expected.object_count() {
        let object = expected.object(i)?;
        count = count
            .checked_add(1)
            .and_then(|n| n.checked_add(object.named_streams.len() as u64))
            .context("map binding count overflow")?;
    }
    Ok(count)
}
fn resource_expected_keys(
    expected: &impl shadow_tree::ExpectedObjectDomain,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
) -> Result<Vec<Vec<u8>>> {
    expected.require_resource_metadata(admission)?;
    let count = expected_binding_count(expected)?;
    let fixed = count
        .checked_mul(
            (std::mem::size_of::<Vec<u8>>() + std::mem::size_of::<(Vec<u8>, MapRowLocation)>())
                as u64,
        )
        .and_then(|n| {
            (expected.object_count() as u64)
                .checked_mul(24)
                .and_then(|o| n.checked_add(o))
        })
        .context("map index memory overflow")?;
    ensure!(
        fixed <= admission.budget.retained_index_bytes,
        "map index exceeds resource budget"
    );
    let mut keys = Vec::new();
    keys.try_reserve_exact(usize::try_from(count)?)?;
    let mut used = (keys.capacity() as u64)
        .checked_mul(std::mem::size_of::<Vec<u8>>() as u64)
        .and_then(|n| {
            count
                .checked_mul(std::mem::size_of::<(Vec<u8>, MapRowLocation)>() as u64)
                .and_then(|i| n.checked_add(i))
        })
        .and_then(|n| {
            (expected.object_count() as u64)
                .checked_mul(24)
                .and_then(|o| n.checked_add(o))
        })
        .context("actual map index allocation overflow")?;
    ensure!(
        used <= admission.budget.retained_index_bytes,
        "actual map key index allocation exceeds budget"
    );
    for i in 0..expected.object_count() {
        let object = expected.object(i)?;
        for name in std::iter::once(&[][..])
            .chain(object.named_streams.iter().map(|s| s.name_utf16.as_slice()))
        {
            let key = encoded_stream_key(&object.path, name)?;
            used = used
                .checked_add(key.capacity() as u64)
                .filter(|n| *n <= admission.budget.retained_index_bytes)
                .context("map key storage exceeds resource budget")?;
            keys.push(key);
        }
    }
    keys.sort_unstable();
    ensure!(
        keys.windows(2).all(|v| v[0] < v[1]),
        "duplicate resource expected map key"
    );
    Ok(keys)
}

pub(crate) fn extent_stream_counts(
    expected: &impl shadow_tree::ExpectedObjectDomain,
) -> Result<(usize, usize)> {
    let (mut extents, mut partials) = (0usize, 0usize);
    for index in 0..expected.object_count() {
        let object = expected.object(index)?;
        for stream in object.data_streams() {
            if stream.source_evidence.is_some() {
                extents = extents
                    .checked_add(1)
                    .context("extent stream count overflow")?;
            }
            if stream.source_evidence
                == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
            {
                partials = partials
                    .checked_add(1)
                    .context("partial extent stream count overflow")?;
            }
        }
    }
    Ok((extents, partials))
}

fn validate_map_entry(
    entry: &MapEntry,
    expected_keys: &BTreeSet<Vec<u8>>,
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
) -> Result<()> {
    ensure!(
        expected_keys
            .contains(encoded_stream_key(&entry.components, &entry.name_utf16)?.as_slice())
            && entry.map.file_id != [0; 16],
        "unexpected recovery map binding"
    );
    ensure!(
        entry.map.retrieval.len() as u64
            <= resource_admission.map_or(
                n2r_win32::retrieval_paging::MAX_RETURNED_BYTES as u64,
                |a| a.budget.max_row_bytes
            ),
        "recovery stream map exceeds retrieval bound"
    );
    Ok(())
}

fn validate_map_header(
    facts: &MapManifestHeader,
    schema_version: u32,
    kind: &str,
    source: &n2r_win32::general_layout::GeneralDiskBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    plan: &selected_journal::SelectedPlan,
    ticket: &selected_journal::SelectedTicket,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<()> {
    resources.count_admission()?;
    let resource_admission = resources.resource_admission()?;
    ensure!(
        facts.resource_admission == resource_admission,
        "map manifest resource admission differs from the actual expected owner"
    );
    if let Some(admission) = resource_admission {
        expected.require_resource_metadata(admission)?;
    }
    ensure!(
        resources.is_streaming(),
        "recovery map facts require the pinned streaming resource profile"
    );
    expected.revalidate_domain()?;
    shadow_tree::validate_expected_domain(expected, resources)?;
    let (selected_bytes, journal_bytes) = plan.validate_marker_profile(ticket.marker_profile)?;
    ensure!(
        expected.has_extent_only_streams()?
            && facts.schema_version == schema_version
            && facts.kind == kind
            && !facts.grants_write_authority
            && !facts.initial_retained_content_digests_available
            && &facts.source == source
            && facts.expected_tree_sha256 == pretty_json_sha256(expected)?
            && facts.plan_sha256 == canonical_json_sha256(plan)?
            && facts.ticket_sha256 == canonical_json_sha256(ticket)?
            && ticket.image_length == source.identity.partition_bytes
            && !ticket.whole_image_verified
            && ticket.selected_bytes == selected_bytes
            && ticket.journal_length == journal_bytes
            && ticket.range_count as usize == plan.ranges.len()
            && facts.new_selected_sha256 == ticket.new_selected_sha256
            && facts.selected_bytes == selected_bytes
            && facts.range_count == ticket.range_count
            && facts.bindings_count
                == if resource_admission.is_some() {
                    expected_binding_count(expected)?
                } else {
                    expected_map_keys(expected)?.len() as u64
                },
        "pinned recovery map facts differ from tree, source, selected plan or trusted ticket"
    );
    Ok(())
}

fn proof_header(facts: MapManifestHeader) -> RecoveryPayloadHeader {
    RecoveryPayloadHeader {
        schema_version: facts.schema_version,
        resource_admission: facts.resource_admission,
        source: facts.source,
        expected_tree_sha256: facts.expected_tree_sha256,
        plan_sha256: facts.plan_sha256,
        ticket_sha256: facts.ticket_sha256,
        base_sectors: facts.base_sectors,
        new_selected_sha256: facts.new_selected_sha256,
        selected_bytes: facts.selected_bytes,
        range_count: facts.range_count,
    }
}

impl RecoveryPayloadProof {
    /// Legacy JSON1 remains readable with its original pinned-input protocol.
    pub(crate) fn from_pinned_manifest(
        bytes: &[u8],
        source: &n2r_win32::general_layout::GeneralDiskBinding,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<Self> {
        ensure!(
            resources.resource_admission()?.is_none(),
            "V4 recovery requires its authenticated chunked map owner"
        );
        ensure!(
            bytes.len() <= super::selected_artifacts::Artifact::PayloadMap.maximum_bytes(),
            "recovery map artifact exceeds bound"
        );
        let old: RecoveryPayloadManifest = serde_json::from_slice(bytes)?;
        let header = MapManifestHeader {
            schema_version: old.schema_version,
            kind: old.kind,
            source: old.source,
            expected_tree_sha256: old.expected_tree_sha256,
            plan_sha256: old.plan_sha256,
            ticket_sha256: old.ticket_sha256,
            base_sectors: old.base_sectors,
            new_selected_sha256: old.new_selected_sha256,
            selected_bytes: old.selected_bytes,
            range_count: old.range_count,
            bindings_count: old.bindings.len() as u64,
            grants_write_authority: old.grants_write_authority,
            initial_retained_content_digests_available: old
                .initial_retained_content_digests_available,
            resource_admission: None,
        };
        validate_map_header(
            &header,
            1,
            "protected-target-stream-map-facts-v1",
            source,
            expected,
            plan,
            ticket,
            resources,
        )?;
        let keys = expected_map_keys(expected)?;
        let mut maps = BTreeMap::new();
        for entry in old.bindings {
            validate_map_entry(&entry, &keys, None)?;
            ensure!(
                maps.insert((entry.components, entry.name_utf16), entry.map)
                    .is_none(),
                "duplicate recovery map binding"
            );
        }
        Ok(Self {
            facts: proof_header(header),
            maps: RecoveryMaps::Legacy(maps),
        })
    }

    /// Full file/page/header/map-set closure precedes journal or target opening.
    /// Only keys/ordinals survive; retrieval/sparse/integrity buffers are decoded
    /// one record at a time from the exact held immutable page owner.
    pub(crate) fn from_pinned_pages(
        path: &Path,
        expected_sha256: &str,
        source: &n2r_win32::general_layout::GeneralDiskBinding,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<Self> {
        let resource_admission = resources.resource_admission()?;
        let budget = map_page_budget(resources)?;
        let mut reader =
            metadata_pages::Reader::open(path, expected_sha256, MAP_PAGE_PURPOSE, budget)?;
        let record = reader.get(0)?;
        ensure!(
            record.key.is_empty(),
            "paged recovery map header key differs"
        );
        let header: MapManifestHeader = serde_json::from_slice(&record.payload)?;
        validate_map_header(
            &header,
            if resource_admission.is_some() { 3 } else { 2 },
            if resource_admission.is_some() {
                "protected-target-stream-map-pages-v3"
            } else {
                "protected-target-stream-map-pages-v2"
            },
            source,
            expected,
            plan,
            ticket,
            resources,
        )?;
        let mut index = Vec::new();
        if let Some(admission) = resource_admission {
            let keys = resource_expected_keys(expected, admission)?;
            ensure!(
                header.bindings_count == keys.len() as u64,
                "resource map binding count differs"
            );
            index.try_reserve_exact(keys.len())?;
            let index_bytes = (keys.capacity() as u64)
                .checked_mul(std::mem::size_of::<Vec<u8>>() as u64)
                .and_then(|n| {
                    (index.capacity() as u64)
                        .checked_mul(std::mem::size_of::<(Vec<u8>, MapRowLocation)>() as u64)
                        .and_then(|i| n.checked_add(i))
                })
                .and_then(|n| {
                    (expected.object_count() as u64)
                        .checked_mul(24)
                        .and_then(|o| n.checked_add(o))
                })
                .context("map index capacity overflow")?;
            let used = keys.iter().try_fold(index_bytes, |n, key| {
                n.checked_add(key.capacity() as u64)
                    .context("map key capacity overflow")
            })?;
            ensure!(
                used <= admission.budget.retained_index_bytes,
                "actual retained map indexes exceed resource budget"
            );
            let mut ordinal = 1u64;
            let mut total = 0u64;
            for key in keys {
                let first = ordinal;
                let maximum = chunk_capacity(budget, key.len())?;
                let mut chunks = 0u64;
                let mut bytes = 0u64;
                loop {
                    ensure!(
                        ordinal < reader.len(),
                        "resource map row lacks terminal chunk"
                    );
                    let record = reader.get(ordinal)?;
                    ensure!(
                        record.key == chunk_key(&key, chunks),
                        "resource map chunk key/order differs"
                    );
                    let text: &str = serde_json::from_slice(&record.payload)?;
                    let data = decode_base64(text, maximum)?;
                    bytes = bytes
                        .checked_add(data.len() as u64)
                        .filter(|n| *n <= admission.budget.max_row_bytes)
                        .context("resource map row byte budget exhausted")?;
                    chunks = chunks.checked_add(1).context("map chunk count overflow")?;
                    ordinal = ordinal
                        .checked_add(1)
                        .context("map record ordinal overflow")?;
                    if data.len() < maximum {
                        break;
                    }
                }
                total = total
                    .checked_add(bytes)
                    .filter(|n| *n <= admission.semantic_byte_budget())
                    .context("resource map complete semantic budget exceeded")?;
                let location = MapRowLocation {
                    first,
                    chunks,
                    bytes,
                };
                let entry = read_map_row(&mut reader, &key, location, Some(admission))?;
                ensure!(
                    entry.map.file_id != [0; 16]
                        && encoded_stream_key(&entry.components, &entry.name_utf16)? == key,
                    "resource map payload key/identity differs"
                );
                index.push((key, location));
            }
            ensure!(
                ordinal == reader.len(),
                "resource map has extra rows/chunks"
            );
        } else {
            ensure!(
                header.bindings_count.checked_add(1) == Some(reader.len()),
                "paged recovery map record count differs"
            );
            let keys = expected_map_keys(expected)?;
            index.try_reserve_exact(usize::try_from(header.bindings_count)?)?;
            for ordinal in 1..reader.len() {
                let record = reader.get(ordinal)?;
                let entry = PagedMapEntry::decode(&record.payload)?;
                validate_map_entry(&entry, &keys, None)?;
                ensure!(
                    record.key == encoded_stream_key(&entry.components, &entry.name_utf16)?,
                    "paged recovery map key differs from payload"
                );
                ensure!(
                    index
                        .last()
                        .is_none_or(|(previous, _)| previous < &record.key),
                    "paged maps duplicated or out of order"
                );
                index.push((
                    record.key,
                    MapRowLocation {
                        first: ordinal,
                        chunks: 0,
                        bytes: record.payload.len() as u64,
                    },
                ));
            }
            ensure!(index.len() == keys.len(), "complete paged map set differs");
        }
        reader.revalidate()?;
        Ok(Self {
            facts: proof_header(header),
            maps: RecoveryMaps::Paged {
                reader: RefCell::new(reader),
                index,
                resource_admission,
            },
        })
    }

    pub(crate) fn paged_final_path(&self) -> Option<String> {
        match &self.maps {
            RecoveryMaps::Paged { reader, .. } => Some(reader.borrow().final_path().to_owned()),
            RecoveryMaps::Legacy(_) => None,
        }
    }

    pub(crate) fn revalidate_paged_manifest(&self) -> Result<()> {
        if let RecoveryMaps::Paged { reader, .. } = &self.maps {
            reader.borrow_mut().revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn copy_paged_manifest(&self, output: &Path) -> Result<()> {
        if let RecoveryMaps::Paged { reader, .. } = &self.maps {
            reader
                .borrow_mut()
                .copy_to(&output.join(PAGED_MAP_FILENAME))?;
        }
        Ok(())
    }

    fn maps_match(&self, report: &Report) -> Result<bool> {
        match &self.maps {
            RecoveryMaps::Legacy(expected) => maps_match(
                report,
                expected,
                |(held, _), key| (held.0.as_slice(), held.1.as_slice()).cmp(&key),
                |(_, map), value| Ok(map.as_ref() == *value),
            ),
            RecoveryMaps::Paged {
                reader,
                index,
                resource_admission,
            } => {
                let actual = if let Some(admission) = resource_admission {
                    let held = (index.capacity() as u64)
                        .checked_mul(std::mem::size_of::<(Vec<u8>, MapRowLocation)>() as u64)
                        .and_then(|n| {
                            admission
                                .objects()
                                .ok()
                                .and_then(|o| o.checked_mul(24))
                                .and_then(|o| n.checked_add(o))
                        })
                        .context("retained map index accounting overflow")?;
                    let held = index.iter().try_fold(held, |n, (key, _)| {
                        n.checked_add(key.capacity() as u64)
                            .context("retained map key accounting overflow")
                    })?;
                    ensure!(
                        (index.len() as u64)
                            .checked_mul(std::mem::size_of::<StreamLocation>() as u64)
                            .and_then(|n| n.checked_add(held))
                            .is_some_and(|n| n <= admission.budget.retained_index_bytes),
                        "mounted native map lookup exceeds retained index budget"
                    );
                    let actual = maps_with_resources(report, *admission)?;
                    ensure!(
                        (actual.capacity() as u64)
                            .checked_mul(std::mem::size_of::<StreamLocation>() as u64)
                            .and_then(|n| n.checked_add(held))
                            .is_some_and(|n| n <= admission.budget.retained_index_bytes),
                        "actual mounted map lookup allocation exceeds budget"
                    );
                    actual
                } else {
                    maps(report)?
                };
                if actual.len() != index.len() {
                    return Ok(false);
                }
                let mut reader = reader.borrow_mut();
                for (location, (expected_key, row)) in actual.iter().zip(index) {
                    let same = location.view(report, |(components, name), value| {
                        if encoded_stream_key(components, name)? != *expected_key {
                            return Ok(false);
                        }
                        let entry =
                            read_map_row(&mut reader, expected_key, *row, *resource_admission)?;
                        ensure!(
                            encoded_stream_key(&entry.components, &entry.name_utf16)?
                                == *expected_key,
                            "held map key changed"
                        );
                        Ok(value == entry.map.as_ref())
                    })?;
                    if !same {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }
}

/// Lab metadata inspection only. Full page and semantic closure is required;
/// this opens no journal or source device and returns no execution capability.
pub(crate) fn inspect_pinned_recovery_pages(
    path: &Path,
    sha256: &str,
    source: &n2r_win32::general_layout::GeneralDiskBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    plan: &selected_journal::SelectedPlan,
    ticket: &selected_journal::SelectedTicket,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<Value> {
    expected.revalidate_domain()?;
    let proof = RecoveryPayloadProof::from_pinned_pages(
        path, sha256, source, expected, plan, ticket, resources,
    )?;
    proof.revalidate_paged_manifest()?;
    expected.revalidate_domain()?;
    let RecoveryMaps::Paged { reader, index, .. } = &proof.maps else {
        anyhow::bail!("paged metadata inspection requires a page owner");
    };
    let reader = reader.borrow();
    Ok(serde_json::json!({
        "schema_version":1,"kind":"read-only-pinned-recovery-map-pages-inspection",
        "file_sha256":sha256,"actual_final_path":reader.final_path(),
        "bytes":reader.byte_len(),"pages":reader.page_count(),"records":reader.len(),
        "bindings":index.len(),"complete_paged_and_expected_map_set_validated":true,
        "manifest_schema_version":proof.facts.schema_version,
        "resource_admission":proof.facts.resource_admission,
        "source":proof.facts.source,
        "expected_tree_sha256":proof.facts.expected_tree_sha256,
        "plan_sha256":proof.facts.plan_sha256,"ticket_sha256":proof.facts.ticket_sha256,
        "base_sectors":proof.facts.base_sectors,
        "new_selected_sha256":proof.facts.new_selected_sha256,
        "selected_bytes":proof.facts.selected_bytes,"range_count":proof.facts.range_count,
        "grants_source_admission":false,"grants_write_authority":false,
        "initial_retained_content_digests_available":false,
        "journal_opened":false,"source_device_opened":false,
    }))
}

/// Recovery never reissues a fresh source certificate. Its existing journal
/// protocol first proves a closed target against the complete immutable body;
/// this routine then compares all mounted maps against independently pinned facts.
pub(crate) fn verify_native_recovery_extents_scoped(
    scope: &NativeVerificationScope<'_>,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    report: &mut Finalization,
    proof: &RecoveryPayloadProof,
    closed: &selected_journal::SelectedResult,
    restored_label: bool,
) -> Result<Value> {
    let facts = &proof.facts;
    ensure!(
        scope.pair.source == facts.source
            && closed.replay_closed
            && !closed.whole_image_verified
            && closed.selected_sha256 == facts.new_selected_sha256
            && closed.selected_bytes == facts.selected_bytes
            && closed.range_count == facts.range_count
            && facts.expected_tree_sha256 == pretty_json_sha256(expected)?,
        "recovery requires the actual closed selected-target result for its pinned maps"
    );
    let native = observe_native_metadata(scope, expected, report, restored_label)?;
    let observation = native
        .content_observation
        .as_ref()
        .context("recovery metadata observation absent")?;
    let known = observation
        .known_content
        .as_ref()
        .context("recovery known-content checks absent")?;
    let mut known_streams = 0usize;
    let mut unknown_streams = 0usize;
    let mut known_bytes = 0u64;
    let mut unknown_partial_streams = 0usize;
    let mut unknown_partial_tail_bytes = 0u64;
    for index in 0..expected.object_count() {
        let object = expected.object(index)?;
        for stream in object.data_streams() {
            if stream.sha256.is_some() {
                known_streams += 1;
                known_bytes = known_bytes
                    .checked_add(stream.length)
                    .context("recovery known stream total overflow")?;
            } else {
                unknown_streams += 1;
                if stream.source_evidence
                    == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
                {
                    unknown_partial_streams += 1;
                    unknown_partial_tail_bytes = unknown_partial_tail_bytes
                        .checked_add(stream.length % n2r_win32::target_cluster::bytes())
                        .context("recovery extent-tail byte total overflow")?;
                }
            }
        }
    }
    ensure!(
        observation.metadata_and_namespace_verified
            && observation.complete_stream_mappings_observed
            && observation.data_storage_validity_checked
            && !observation.full_file_hashes
            && observation.admitted_payload_bytes_read == known_bytes
            && known.payload_bytes_read == known_bytes
            && known.streams_hashed == known_streams
            && known.streams_without_content_baseline == unknown_streams
            && native.pair.source.identity == facts.source.identity
            && native.native.base_sectors == facts.base_sectors
            && proof.maps_match(&native.native)?,
        "recovery mounted metadata, storage validity or complete maps differ from pinned target facts"
    );
    record_mount_paths_scoped(scope, &native, report);
    report.native = Some(native);
    if report.error.is_none() && !restored_label {
        restore_source_label_scoped(scope, report);
    }
    report.success = report.error.is_none();
    Ok(
        serde_json::json!({"schema_version":1,"scope":"recovery-selected-checksums-and-pinned-stream-maps-v1",
        "all_complete_maps_identical":true,"stream_and_directory_bindings":proof.maps.len(),
        "selected_bytes_checksummed":closed.selected_bytes,"selected_sha256":hex::encode(closed.selected_sha256),
        "handoff_replay_closed":true,"full_file_hashes":false,"initial_retained_content_digests_available":false,
        "known_content_streams_hashed":known_streams,"known_content_payload_bytes_read":known_bytes,
        "extent_only_streams":unknown_streams,
        "extent_only_partial_streams":unknown_partial_streams,
        "extent_only_partial_tail_bytes":unknown_partial_tail_bytes,
        "post_operational_source_equality_claimed":false,"grants_fresh_source_or_write_authority":false}),
    )
}

fn observe_native_metadata(
    scope: &NativeVerificationScope<'_>,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    report: &mut Finalization,
    restored_label: bool,
) -> Result<shadow_native::GeneralConvertedReport> {
    let mut pair = scope.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, &mut report.events)?;
    expected.revalidate_domain()?;
    let input = crate::general_shadow::ExpectedInputs(expected);
    Ok(
        shadow_native::verify_general_converted_known_contents_domain(
            pair,
            &input,
            if restored_label {
                scope.expected_source_label
            } else {
                None
            },
            |a, b| {
                ntfs_attestation::same_security(a, b)
                    .map_err(|error| io::Error::other(error.to_string()))
            },
            scope
                .source_resource_profile
                .unwrap_or_default()
                .native_profile(),
        )?,
    )
}

/// Only the fresh allocation route can supply this in-memory proof and its
/// actual Apply/HND results. Recovery uses its distinct pinned-fact protocol.
pub(crate) fn verify_native_extents_scoped(
    scope: &NativeVerificationScope<'_>,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    report: &mut Finalization,
    proof: &FreshPayloadProof,
    applied: &selected_journal::SelectedResult,
    handoff: &selected_journal::SelectedResult,
) -> Result<Value> {
    let mut pair = scope.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, &mut report.events)?;
    expected.revalidate_domain()?;
    let input = crate::general_shadow::ExpectedInputs(expected);
    let native = shadow_native::observe_general_converted_metadata_domain(
        pair,
        &input,
        None,
        |a, b| {
            ntfs_attestation::same_security(a, b)
                .map_err(|error| io::Error::other(error.to_string()))
        },
        scope
            .source_resource_profile
            .unwrap_or_default()
            .native_profile(),
    )?;
    let receipt = proof.verify(scope, expected, applied, handoff, &native)?;
    record_mount_paths_scoped(scope, &native, report);
    report.native = Some(native);
    if report.error.is_none() {
        restore_source_label_scoped(scope, report);
    }
    report.success = report.error.is_none();
    Ok(receipt)
}
