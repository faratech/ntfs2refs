//! Bounded, read-only physical container-tree observations for ReFS 3.14/4 KiB.
//! No virtual address is followed and no mapping is an allocation/free-space
//! certificate. Root inputs must come from independently checked checkpoints.

use crate::{refs_bootstrap::crc64_nvme, refs_inspect::RefsGeometry, refs_node};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
};

const PAGE: usize = 16384;
const CLUSTER: u64 = 4096;
const CPC: u64 = 16384;
const KEY_TAG: u64 = 0x0000_0001_0000_0000;

/// A container value has exactly 160 bytes in this format profile. Keep the
/// actual bytes in memory and encode hex only at the diagnostic boundary.
/// Malformed imported diagnostic strings remain representable so validation
/// can refuse them explicitly; they never become a usable container value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerValue(ContainerValueStorage);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContainerValueStorage {
    Bytes([u8; 160]),
    InvalidDiagnostic(String),
}

impl ContainerValue {
    pub fn from_bytes(bytes: [u8; 160]) -> Self {
        Self(ContainerValueStorage::Bytes(bytes))
    }

    pub fn bytes(&self) -> Result<&[u8; 160]> {
        match &self.0 {
            ContainerValueStorage::Bytes(bytes) => Ok(bytes),
            ContainerValueStorage::InvalidDiagnostic(_) => {
                anyhow::bail!("container raw value is not exactly 160 decoded bytes")
            }
        }
    }
}

impl From<String> for ContainerValue {
    fn from(value: String) -> Self {
        let mut bytes = [0; 160];
        if value.len() == 320 && hex::decode_to_slice(&value, &mut bytes).is_ok() {
            Self::from_bytes(bytes)
        } else {
            Self(ContainerValueStorage::InvalidDiagnostic(value))
        }
    }
}

impl Serialize for ContainerValue {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match &self.0 {
            ContainerValueStorage::Bytes(bytes) => {
                let mut encoded = [0; 320];
                hex::encode_to_slice(bytes, &mut encoded).expect("fixed container hex buffer");
                serializer.serialize_str(std::str::from_utf8(&encoded).expect("hex is ASCII"))
            }
            ContainerValueStorage::InvalidDiagnostic(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for ContainerValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(String::deserialize(deserializer)?.into())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ContainerLimits {
    pub max_pages_per_tree: u32,
    pub max_total_pages: u32,
    pub max_rows_per_tree: u32,
    /// Root is depth zero. The implementation additionally caps this at four.
    pub max_depth: u8,
}
impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            max_pages_per_tree: 32,
            max_total_pages: 128,
            max_rows_per_tree: 4096,
            max_depth: 4,
        }
    }
}

/// Caller-supplied binding from a CRC/header-checked physical bootstrap root.
/// This API does not independently authenticate its checkpoint provenance.
#[derive(Debug, Clone)]
pub struct ContainerRootTarget {
    pub checkpoint_lcn: u64,
    pub root_index: usize,
    pub table_id: u64,
    pub volume_signature: u32,
    pub lcn_slots: [u64; 4],
    pub expected_crc64: u64,
    pub expected_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerTablesProbe {
    pub profile: String,
    pub limits: ContainerLimits,
    pub pages_read: u32,
    pub bytes_read: u64,
    pub trees: Vec<ContainerTreeObservation>,
    pub failover_comparisons: Vec<ContainerPairComparison>,
    pub authoritative_checkpoint_selected: bool,
    pub metadata_verified: bool,
    pub allocation_verified: bool,
    pub conversion_profile_qualified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerTreeObservation {
    pub checkpoint_lcn: u64,
    pub root_index: usize,
    pub table_id: u64,
    pub root_lcn_slots: [u64; 4],
    pub expected_root_rows: Option<u64>,
    pub root_count_matches: Option<bool>,
    pub walk_finished: bool,
    pub pages: Vec<ContainerPageObservation>,
    /// Sorted by container ID only after a successful walk; partial data remain
    /// explicitly rejected. All flags/counts are raw, with no allocation policy.
    pub mappings: Vec<ContainerMapping>,
    pub rejection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPageObservation {
    pub lcn_slots: [u64; 4],
    pub depth: u8,
    pub parent_page_index: Option<usize>,
    pub parent_row_index: Option<usize>,
    pub sha256: String,
    pub stored_crc64: String,
    pub computed_crc64: String,
    pub checksum_matches: bool,
    pub header_matches: bool,
    pub node_level: Option<u8>,
    pub row_count: Option<u32>,
    pub rejection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerMapping {
    pub container_id: u64,
    pub physical_start_lcn: u64,
    pub clusters_per_container: u32,
    pub raw_flags: u32,
    pub raw_free_clusters_64: u64,
    pub raw_free_clusters_32: u32,
    pub free_clusters_64_is_sentinel: bool,
    pub value_bytes_hex: ContainerValue,
    pub row_sha256: String,
    pub source_page_index: usize,
    pub source_row_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPairComparison {
    pub checkpoint_lcn: u64,
    pub root_indices: [usize; 2],
    pub both_walks_finished: bool,
    pub both_root_counts_match: bool,
    pub mapping_entries_equal: Option<bool>,
    pub raw_values_equal: Option<bool>,
    pub rejection: Option<String>,
}

#[derive(Clone)]
struct PendingPage {
    slots: [u64; 4],
    crc: u64,
    depth: u8,
    parent: Option<usize>,
    row: Option<usize>,
    expected_level: Option<u8>,
}

fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().expect("bounded field"))
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().expect("bounded field"))
}
fn u64le(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().expect("bounded field"))
}
fn slots(b: &[u8]) -> [u64; 4] {
    [u64le(b, 0), u64le(b, 8), u64le(b, 16), u64le(b, 24)]
}

fn validate_slots(lcns: &[u64; 4], volume_bytes: u64) -> Result<()> {
    for (index, lcn) in lcns.iter().enumerate() {
        ensure!(
            *lcn != 0 && !lcns[..index].contains(lcn),
            "empty or duplicate page cluster"
        );
        let end = lcn
            .checked_add(1)
            .and_then(|x| x.checked_mul(CLUSTER))
            .context("page address overflow")?;
        ensure!(end <= volume_bytes, "page address outside volume");
    }
    Ok(())
}

fn read_page<R: Read + Seek>(reader: &mut R, lcns: &[u64; 4]) -> Result<[u8; PAGE]> {
    let mut bytes = [0; PAGE];
    for (slot, lcn) in lcns.iter().enumerate() {
        reader
            .seek(SeekFrom::Start(lcn * CLUSTER))
            .context("seek container page")?;
        reader
            .read_exact(&mut bytes[slot * 4096..(slot + 1) * 4096])
            .context("read container page")?;
    }
    Ok(bytes)
}

fn row_parts(row: &refs_node::NodeRowObservation) -> Result<(Vec<u8>, Vec<u8>)> {
    // Every row originates in the bounded node parser. Recheck its serialized
    // shape here so these offsets never become an unchecked public-input slice.
    ensure!(
        row.row_bytes_hex.len() <= PAGE * 2,
        "row hex exceeds page bound"
    );
    let bytes = hex::decode(&row.row_bytes_hex).context("decode observed row")?;
    ensure!(
        bytes.len() == row.size as usize,
        "observed row size mismatch"
    );
    let key =
        usize::from(row.key_offset)..usize::from(row.key_offset) + usize::from(row.key_length);
    let value = usize::from(row.value_offset)
        ..usize::from(row.value_offset) + usize::from(row.value_length);
    Ok((
        bytes.get(key).context("key outside observed row")?.to_vec(),
        bytes
            .get(value)
            .context("value outside observed row")?
            .to_vec(),
    ))
}

fn child_reference(
    row: &refs_node::NodeRowObservation,
    parent: usize,
    level: u8,
    depth: u8,
) -> Result<PendingPage> {
    let (key, value) = row_parts(row)?;
    ensure!(
        key.is_empty() || (key.len() == 16 && u64le(&key, 0) >= 2 && u64le(&key, 8) == KEY_TAG),
        "unsupported container index key"
    );
    ensure!(
        value.len() == 48,
        "container child reference is not 48 bytes"
    );
    ensure!(
        u16le(&value, 0x20) == 0
            && value[0x22] == 2
            && value[0x23] == 8
            && u32le(&value, 0x24) == 8,
        "unsupported child checksum descriptor"
    );
    Ok(PendingPage {
        slots: slots(&value),
        crc: u64le(&value, 0x28),
        depth: depth + 1,
        parent: Some(parent),
        row: Some(row.index),
        expected_level: Some(level - 1),
    })
}

fn leaf_mapping(
    row: &refs_node::NodeRowObservation,
    page: usize,
    volume_clusters: u64,
) -> Result<ContainerMapping> {
    let (key, value) = row_parts(row)?;
    ensure!(
        key.len() == 16 && value.len() == 160,
        "unsupported container leaf key/value size"
    );
    ensure!(
        row.key_offset == row.value_offset && key == value[..16],
        "container key is not the echoed value prefix"
    );
    let id = u64le(&key, 0);
    ensure!(
        id >= 2 && u64le(&key, 8) == KEY_TAG,
        "unsupported container key identity"
    );
    ensure!(
        u32le(&value, 0x10) == 1,
        "unsupported container value version"
    );
    ensure!(
        u32le(&value, 0x18) == CPC as u32 && u32le(&value, 0x98) == CPC as u32,
        "container cluster count mismatch"
    );
    let start = u64le(&value, 0x90);
    ensure!(
        start
            .checked_add(CPC)
            .is_some_and(|end| end <= volume_clusters),
        "container extent outside volume or overflowing"
    );
    Ok(ContainerMapping {
        container_id: id,
        physical_start_lcn: start,
        clusters_per_container: CPC as u32,
        raw_flags: u32le(&value, 0x14),
        raw_free_clusters_64: u64le(&value, 0x20),
        raw_free_clusters_32: u32le(&value, 0x28),
        free_clusters_64_is_sentinel: u64le(&value, 0x20) == u64::MAX,
        value_bytes_hex: ContainerValue::from_bytes(
            value
                .as_slice()
                .try_into()
                .context("container value size differs")?,
        ),
        row_sha256: row.row_sha256.clone(),
        source_page_index: page,
        source_row_index: row.index,
    })
}

/// Walk at most four caller-bound roots (two checkpoint pairs). Reads are
/// bounded independently of on-disk counts. I/O errors propagate; malformed
/// trees retain partial observations with walk_finished=false and a rejection.
pub fn inspect_container_tables<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    roots: &[ContainerRootTarget],
    protected_lcns: &BTreeSet<u64>,
    limits: ContainerLimits,
) -> Result<ContainerTablesProbe> {
    ensure!(
        geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_cluster == 4096
            && geometry.volume_bytes.is_multiple_of(CLUSTER),
        "unsupported container traversal geometry"
    );
    ensure!(
        roots.len() <= 4 && protected_lcns.len() <= 128,
        "too many container roots or protected anchor clusters"
    );
    ensure!(
        (1..=32).contains(&limits.max_pages_per_tree)
            && (1..=128).contains(&limits.max_total_pages)
            && (1..=4096).contains(&limits.max_rows_per_tree)
            && limits.max_depth <= 4,
        "invalid container traversal limits"
    );
    let mut identifiers = BTreeSet::new();
    for root in roots {
        ensure!(
            matches!(root.root_index, 7 | 8)
                && matches!(root.table_id, 11 | 12)
                && identifiers.insert((root.checkpoint_lcn, root.root_index)),
            "invalid or duplicate container root identity"
        );
        ensure!(
            root.expected_sha256.len() == 64
                && root.expected_sha256.bytes().all(|x| x.is_ascii_hexdigit()),
            "invalid root SHA binding"
        );
    }
    ensure!(
        roots
            .iter()
            .map(|root| root.checkpoint_lcn)
            .collect::<BTreeSet<_>>()
            .len()
            <= 2,
        "more than two checkpoint pairs"
    );
    let mut result = ContainerTablesProbe {
        profile: "candidate ReFS 3.14, 4 KiB, 48-byte CRC64, 160-byte container values".into(),
        limits,
        pages_read: 0,
        bytes_read: 0,
        trees: Vec::new(),
        failover_comparisons: Vec::new(),
        authoritative_checkpoint_selected: false,
        metadata_verified: false,
        allocation_verified: false,
        conversion_profile_qualified: false,
    };
    for root in roots {
        let mut tree = ContainerTreeObservation {
            checkpoint_lcn: root.checkpoint_lcn,
            root_index: root.root_index,
            table_id: root.table_id,
            root_lcn_slots: root.lcn_slots,
            expected_root_rows: None,
            root_count_matches: None,
            walk_finished: false,
            pages: Vec::new(),
            mappings: Vec::new(),
            rejection: None,
        };
        let mut stack = vec![PendingPage {
            slots: root.lcn_slots,
            crc: root.expected_crc64,
            depth: 0,
            parent: None,
            row: None,
            expected_level: None,
        }];
        let mut visited = BTreeSet::new();
        let mut mappings: Vec<ContainerMapping> = Vec::new();
        let mut extents = Vec::new();
        while let Some(pending) = stack.pop() {
            let preflight = (|| -> Result<()> {
                ensure!(
                    tree.pages.len() < limits.max_pages_per_tree as usize
                        && result.pages_read < limits.max_total_pages,
                    "container page-read budget exhausted"
                );
                ensure!(
                    pending.depth <= limits.max_depth,
                    "container depth budget exhausted"
                );
                validate_slots(&pending.slots, geometry.volume_bytes)?;
                for lcn in pending.slots {
                    ensure!(
                        !visited.contains(&lcn),
                        "container page cycle, repeated child, or overlapping page clusters"
                    );
                    if pending.depth != 0 {
                        ensure!(
                            !protected_lcns.contains(&lcn)
                                && !roots.iter().any(|other| other.lcn_slots.contains(&lcn)),
                            "container child overlaps bootstrap/root page"
                        );
                    }
                }
                Ok(())
            })();
            if let Err(error) = preflight {
                tree.rejection = Some(error.to_string());
                break;
            }
            visited.extend(pending.slots);
            let bytes = read_page(reader, &pending.slots)?;
            result.pages_read += 1;
            result.bytes_read += PAGE as u64;
            let actual_crc = crc64_nvme(&bytes);
            let page_sha = hex::encode(Sha256::digest(bytes));
            let header_matches = &bytes[..4] == b"MSB+"
                && u32le(&bytes, 4) == 2
                && u32le(&bytes, 8) == 0
                && u32le(&bytes, 0xc) == root.volume_signature
                && slots(&bytes[0x20..]) == pending.slots
                && u64le(&bytes, 0x40) == 0
                && u64le(&bytes, 0x48) == root.table_id;
            let mut observation = ContainerPageObservation {
                lcn_slots: pending.slots,
                depth: pending.depth,
                parent_page_index: pending.parent,
                parent_row_index: pending.row,
                sha256: page_sha.clone(),
                stored_crc64: format!("{:016x}", pending.crc),
                computed_crc64: format!("{actual_crc:016x}"),
                checksum_matches: actual_crc == pending.crc,
                header_matches,
                node_level: None,
                row_count: None,
                rejection: None,
            };
            let parsed = (|| -> Result<(u8, Vec<refs_node::NodeRowObservation>)> {
                ensure!(actual_crc == pending.crc, "container page CRC64 mismatch");
                ensure!(
                    header_matches,
                    "container page header/self-location/table mismatch"
                );
                if pending.depth == 0 {
                    ensure!(
                        page_sha.eq_ignore_ascii_case(&root.expected_sha256),
                        "container root SHA binding mismatch"
                    );
                    let node = refs_node::inspect_root_node(&bytes)?;
                    tree.expected_root_rows = Some(node.whole_table_row_count);
                    Ok((node.node_level, node.rows))
                } else {
                    let node = refs_node::inspect_container_child_node(&bytes)?;
                    ensure!(
                        Some(node.node_level) == pending.expected_level,
                        "container child level does not descend by one"
                    );
                    Ok((node.node_level, node.rows))
                }
            })();
            let page_index = tree.pages.len();
            let (level, rows) = match parsed {
                Ok(node) => node,
                Err(error) => {
                    observation.rejection = Some(error.to_string());
                    tree.rejection = observation.rejection.clone();
                    tree.pages.push(observation);
                    break;
                }
            };
            observation.node_level = Some(level);
            observation.row_count = Some(rows.len() as u32);
            tree.pages.push(observation);
            let contents = (|| -> Result<()> {
                if level != 0 {
                    ensure!(
                        pending.depth < limits.max_depth,
                        "container depth budget exhausted before following children"
                    );
                    ensure!(!rows.is_empty(), "empty container index node");
                    ensure!(
                        tree.pages.len() + stack.len() + rows.len()
                            <= limits.max_pages_per_tree as usize,
                        "pending container nodes exceed page budget"
                    );
                    for row in rows.iter().rev() {
                        stack.push(child_reference(row, page_index, level, pending.depth)?);
                    }
                } else {
                    ensure!(
                        mappings.len() + rows.len() <= limits.max_rows_per_tree as usize,
                        "container row budget exhausted"
                    );
                    for row in &rows {
                        let mapping =
                            leaf_mapping(row, page_index, geometry.volume_bytes / CLUSTER)?;
                        ensure!(
                            mappings.last().is_none_or(|previous| previous.container_id < mapping.container_id),
                            "duplicate or unsorted container key"
                        );
                        let start = mapping.physical_start_lcn;
                        extents.push(start);
                        mappings.push(mapping);
                    }
                }
                Ok(())
            })();
            if let Err(error) = contents {
                tree.rejection = Some(error.to_string());
                break;
            }
        }
        if tree.rejection.is_none() {
            extents.sort_unstable();
            if extents.windows(2).any(|pair| pair[0] + CPC > pair[1]) {
                tree.rejection = Some("container physical extents overlap".into());
            }
        }
        tree.mappings = mappings;
        tree.walk_finished = tree.rejection.is_none();
        if tree.walk_finished {
            tree.root_count_matches = tree
                .expected_root_rows
                .map(|expected| expected == tree.mappings.len() as u64);
        }
        result.trees.push(tree);
    }
    for checkpoint in roots
        .iter()
        .map(|root| root.checkpoint_lcn)
        .collect::<BTreeSet<_>>()
    {
        let first = result
            .trees
            .iter()
            .find(|tree| tree.checkpoint_lcn == checkpoint && tree.root_index == 7);
        let second = result
            .trees
            .iter()
            .find(|tree| tree.checkpoint_lcn == checkpoint && tree.root_index == 8);
        let mut comparison = ContainerPairComparison {
            checkpoint_lcn: checkpoint,
            root_indices: [7, 8],
            both_walks_finished: false,
            both_root_counts_match: false,
            mapping_entries_equal: None,
            raw_values_equal: None,
            rejection: None,
        };
        if let (Some(first), Some(second)) = (first, second) {
            comparison.both_walks_finished = first.walk_finished && second.walk_finished;
            comparison.both_root_counts_match =
                first.root_count_matches == Some(true) && second.root_count_matches == Some(true);
            if first.table_id == second.table_id {
                comparison.rejection = Some("failover pair repeats the same table ID".into());
            } else if comparison.both_walks_finished {
                comparison.mapping_entries_equal = Some(
                    first
                        .mappings
                        .iter()
                        .map(|m| {
                            (
                                m.container_id,
                                m.physical_start_lcn,
                                m.clusters_per_container,
                            )
                        })
                        .eq(second.mappings.iter().map(|m| {
                            (
                                m.container_id,
                                m.physical_start_lcn,
                                m.clusters_per_container,
                            )
                        })),
                );
                comparison.raw_values_equal = Some(
                    first
                        .mappings
                        .iter()
                        .map(|m| (m.container_id, &m.value_bytes_hex))
                        .eq(second
                            .mappings
                            .iter()
                            .map(|m| (m.container_id, &m.value_bytes_hex))),
                );
            } else {
                comparison.rejection = Some("one or both bounded walks did not finish".into());
            }
        } else {
            comparison.rejection = Some("only one eligible failover root was supplied".into());
        }
        result.failover_comparisons.push(comparison);
    }
    Ok(result)
}
