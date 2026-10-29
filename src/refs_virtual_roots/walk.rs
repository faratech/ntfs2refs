//! Authenticated index descendants of the ten virtual checkpoint roots.
//! Leaf values can contain additional trees, streams and log references. This
//! traversal deliberately does not claim that those have been accounted for.
use super::*;
use crate::refs_node;
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, Copy, Serialize)]
pub struct WalkLimits {
    pub max_pages: u32,
    pub max_depth: u8,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_pages: 65_536,
            max_depth: 8,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TreeFootprint {
    pub root_index: Option<usize>,
    pub object_id: Option<u64>,
    pub table_id: u64,
    pub observed_schema_id: u32,
    pub pages_read: u32,
    pub leaf_rows: u64,
    pub expected_leaf_rows: u64,
    pub index_descendants_complete: bool,
    pub leaf_external_references_followed: bool,
}

#[derive(Debug, Serialize)]
pub struct MetadataFootprint {
    pub profile: &'static str,
    pub checkpoint_lcn: u64,
    pub checkpoint_sha256: String,
    pub mapping_sha256: String,
    pub limits: WalkLimits,
    pub pages_read: u32,
    pub bytes_read: u64,
    pub physical_ranges: Vec<crate::refs_write_set::ByteRange>,
    pub page_transcript_sha256: String,
    pub trees: Vec<TreeFootprint>,
    pub complete_allocation_graph_verified: bool,
    pub selective_capture_executable: bool,
}

struct Pending {
    slots: [u64; 4],
    checksum: u64,
    level: Option<u8>,
    depth: u8,
}

struct TreeRequest {
    root_index: Option<usize>,
    object_id: Option<u64>,
    table_id: u64,
    slots: [u64; 4],
    checksum: u64,
}

fn enqueue(
    rows: &[refs_node::NodeRowObservation],
    level: u8,
    depth: u8,
    pending: &mut Vec<Pending>,
    read: u32,
    limits: WalkLimits,
) -> Result<()> {
    ensure!(
        level > 0 && !rows.is_empty() && depth < limits.max_depth,
        "metadata index level, children or depth unsupported"
    );
    ensure!(
        u64::from(read) + pending.len() as u64 + rows.len() as u64 <= u64::from(limits.max_pages),
        "metadata page budget exhausted before following children"
    );
    for row in rows.iter().rev() {
        let bytes = hex::decode(&row.row_bytes_hex)?;
        let start = usize::from(row.value_offset);
        let end = start
            .checked_add(usize::from(row.value_length))
            .context("metadata child bounds overflow")?;
        let value = bytes
            .get(start..end)
            .context("metadata child value outside row")?;
        ensure!(
            value.len() == 48 && value[0x20..0x28] == [0, 0, 2, 8, 8, 0, 0, 0],
            "metadata index child is not the supported 48-byte CRC64 reference"
        );
        pending.push(Pending {
            slots: std::array::from_fn(|i| u64le(value, i * 8)),
            checksum: u64le(value, 0x28),
            level: Some(level - 1),
            depth: depth + 1,
        });
    }
    Ok(())
}

/// Call only with bootstrap/container observations collected from this same
/// frozen reader. Each referenced page is freshly read and authenticated. This
/// is a read-only footprint, never a certificate made from a serialized report.
pub fn inspect<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    checkpoint: &AnchorProbe,
    containers: &ContainerTablesProbe,
    protected_lcns: &BTreeSet<u64>,
    limits: WalkLimits,
) -> Result<MetadataFootprint> {
    ensure!(
        geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_cluster == 4096
            && geometry.volume_bytes.is_multiple_of(CLUSTER)
            && geometry.volume_bytes <= geometry.image_bytes,
        "unsupported metadata footprint geometry"
    );
    ensure!(
        (10..=1_048_576).contains(&limits.max_pages) && (1..=8).contains(&limits.max_depth),
        "metadata footprint limits exceed bounded profile"
    );
    let mut binding = VirtualMapBinding {
        checkpoint_lcn: checkpoint.lcn,
        checkpoint_sha256: checkpoint.sha256.clone(),
        container_root_indices: [7, 8],
        container_table_ids: None,
        mapping_rows: None,
        common_mapping_sha256: None,
        both_complete_count_matching_maps_agree: false,
        rejection: None,
    };
    let clusters = geometry.volume_bytes / CLUSTER;
    let map = common_map(checkpoint, containers, clusters, &mut binding)?;
    let fields = checkpoint
        .checkpoint
        .as_ref()
        .context("checkpoint fields absent")?;
    let signature = checkpoint
        .header
        .as_ref()
        .context("checkpoint header absent")?
        .volume_signature;
    let mut protected = protected_lcns.clone();
    for tree in containers
        .trees
        .iter()
        .filter(|tree| tree.checkpoint_lcn == checkpoint.lcn)
    {
        for page in &tree.pages {
            protected.extend(page.lcn_slots);
        }
    }
    let mut visited = BTreeSet::new();
    let mut transcript = Sha256::new();
    transcript.update(b"n2r-refs-virtual-and-object-index-footprint-v2\0");
    let mut total_pages = 0u32;
    let mut trees = Vec::new();
    let mut requests = VecDeque::new();
    for (root_index, table_id) in ROOTS {
        let reference = &fields.roots[root_index];
        requests.push_back(TreeRequest {
            root_index: Some(root_index),
            object_id: None,
            table_id,
            slots: reference.lcn_slots,
            checksum: reference_crc(reference)?,
        });
    }
    let mut primary_objects = BTreeMap::new();
    let mut duplicate_objects = BTreeMap::new();
    while let Some(request) = requests.pop_front() {
        let TreeRequest {
            root_index,
            object_id,
            table_id,
            slots,
            checksum,
        } = request;
        ensure!(
            trees.len() < 65_546,
            "metadata tree count exceeds bounded profile"
        );
        let mut pending = vec![Pending {
            slots,
            checksum,
            level: None,
            depth: 0,
        }];
        let start_pages = total_pages;
        let mut expected_rows = None;
        let mut schema_id = None;
        let mut leaves = 0u64;
        while let Some(item) = pending.pop() {
            ensure!(
                total_pages < limits.max_pages,
                "metadata footprint page budget exhausted"
            );
            let mut physical = [0; 4];
            for (index, &vlcn) in item.slots.iter().enumerate() {
                ensure!(
                    vlcn != 0 && vlcn & CPC == 0 && !item.slots[..index].contains(&vlcn),
                    "metadata child has zero, duplicate or reserved virtual cluster"
                );
                let (base, _) = map
                    .lookup(vlcn >> 15)
                    .context("metadata child container absent")?;
                let lcn = base
                    .checked_add(vlcn & (CPC - 1))
                    .context("metadata physical cluster overflow")?;
                ensure!(
                    lcn < clusters && !protected.contains(&lcn) && visited.insert(lcn),
                    "metadata page overlaps bootstrap, container pages or an earlier page"
                );
                physical[index] = lcn;
            }
            let mut bytes = [0u8; PAGE];
            for (index, &lcn) in physical.iter().enumerate() {
                reader.seek(SeekFrom::Start(lcn * CLUSTER))?;
                reader.read_exact(&mut bytes[index * 4096..(index + 1) * 4096])?;
            }
            ensure!(
                crc64_nvme(&bytes) == item.checksum
                    && &bytes[..4] == b"MSB+"
                    && u32le(&bytes, 4) == 2
                    && u32le(&bytes, 8) == 0
                    && u32le(&bytes, 12) == signature
                    && u64le(&bytes, 0x40) == 0
                    && u64le(&bytes, 0x48) == table_id
                    && (0..4).all(|i| u64le(&bytes, 0x20 + i * 8) == item.slots[i]),
                "metadata page checksum, header, table or self-address differs"
            );
            total_pages += 1;
            transcript.update(
                root_index
                    .map_or(u64::MAX, |index| index as u64)
                    .to_le_bytes(),
            );
            transcript.update(table_id.to_le_bytes());
            for lcn in physical {
                transcript.update(lcn.to_le_bytes());
            }
            transcript.update(&bytes);
            let (level, index_node, rows) = if item.depth == 0 {
                let root = if object_id.is_some() {
                    refs_node::inspect_object_root_node(&bytes, table_id)
                } else {
                    refs_node::inspect_system_root_node(&bytes, table_id)
                }
                .with_context(|| format!("metadata root {root_index:?} table {table_id}"))?;
                expected_rows = Some(root.whole_table_row_count);
                schema_id = Some(root.schema_id);
                (root.node_level, root.index_node, root.rows)
            } else {
                let node = if object_id.is_some() {
                    refs_node::inspect_object_child_node(&bytes, table_id)
                } else {
                    refs_node::inspect_system_child_node(&bytes, table_id)
                }
                .with_context(|| {
                    format!("metadata child of root {root_index:?} table {table_id}")
                })?;
                (node.node_level, node.index_node, node.rows)
            };
            ensure!(
                level <= limits.max_depth
                    && item.level.is_none_or(|expected| expected == level)
                    && index_node == (level > 0),
                "metadata node level or index form differs"
            );
            if index_node {
                enqueue(&rows, level, item.depth, &mut pending, total_pages, limits)?;
            } else {
                if matches!(root_index, Some(0 | 5)) {
                    let objects = if root_index == Some(0) {
                        &mut primary_objects
                    } else {
                        &mut duplicate_objects
                    };
                    for row in &rows {
                        let reference = crate::refs_object_refs::decode_object_leaf_row(row)?;
                        ensure!(
                            objects.len() < 65_536
                                && objects.insert(reference.object_id, reference).is_none(),
                            "Object Table contains duplicate OIDs or exceeds budget"
                        );
                    }
                }
                leaves = leaves
                    .checked_add(rows.len() as u64)
                    .context("metadata leaf row count overflow")?;
            }
        }
        let expected = expected_rows.context("metadata root was not visited")?;
        ensure!(
            leaves == expected,
            "metadata leaf count differs from root descriptor"
        );
        trees.push(TreeFootprint {
            root_index,
            object_id,
            table_id,
            observed_schema_id: schema_id.context("root schema was not observed")?,
            pages_read: total_pages - start_pages,
            leaf_rows: leaves,
            expected_leaf_rows: expected,
            index_descendants_complete: true,
            leaf_external_references_followed: false,
        });
        if root_index == Some(5) {
            ensure!(
                primary_objects == duplicate_objects && primary_objects.contains_key(&0x600),
                "Object Table copies disagree or root directory is absent"
            );
            ensure!(
                u64::from(total_pages) + requests.len() as u64 + primary_objects.len() as u64
                    <= u64::from(limits.max_pages),
                "metadata page budget cannot cover Object Table roots"
            );
            for reference in primary_objects.values() {
                requests.push_back(TreeRequest {
                    root_index: None,
                    object_id: Some(reference.object_id),
                    table_id: reference.object_id,
                    slots: reference.virtual_lcn_slots,
                    checksum: reference.root_crc64_nvme,
                });
            }
        }
    }
    let mut ranges: Vec<crate::refs_write_set::ByteRange> = Vec::new();
    for lcn in visited {
        let offset = lcn * CLUSTER;
        if let Some(last) = ranges
            .last_mut()
            .filter(|last| last.offset + last.length == offset)
        {
            last.length += CLUSTER;
        } else {
            ensure!(
                ranges.len() < 65_536,
                "metadata physical range budget exhausted"
            );
            ranges.push(crate::refs_write_set::ByteRange {
                offset,
                length: CLUSTER,
            });
        }
    }
    Ok(MetadataFootprint {
        profile: "refs-3.14-4k-crc64-virtual-and-object-index-footprint-v2",
        checkpoint_lcn: checkpoint.lcn,
        checkpoint_sha256: checkpoint.sha256.clone(),
        mapping_sha256: binding
            .common_mapping_sha256
            .context("mapping pin absent")?,
        limits,
        pages_read: total_pages,
        bytes_read: u64::from(total_pages) * PAGE as u64,
        physical_ranges: ranges,
        page_transcript_sha256: hex::encode(transcript.finalize()),
        trees,
        complete_allocation_graph_verified: false,
        selective_capture_executable: false,
    })
}
