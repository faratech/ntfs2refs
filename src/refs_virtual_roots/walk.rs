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
    pub embedded_attribute_tables: usize,
    pub own_record_attribute_tables: usize,
    pub external_attribute_pages: u32,
    pub external_extent_pages: u32,
    /// DATA allocation records of this tree in a form the walk does not
    /// interpret: their extents were not followed and are in no range list.
    pub uninterpreted_data_records: u64,
    /// Whether this tree's leaf rows were read as file records. Only object
    /// trees of schema 0x130 are; the rows of any other tree are counted and
    /// nothing in them is followed.
    pub file_records_interpreted: bool,
    /// False when a DATA record of this tree was left uninterpreted: its
    /// extent tree is a descendant that was not walked.
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
    pub budget_pages_charged: u32,
    pub bytes_read: u64,
    pub physical_ranges: Vec<crate::refs_write_set::ByteRange>,
    pub page_transcript_sha256: String,
    pub trees: Vec<TreeFootprint>,
    pub data_storage: DataStorageFootprint,
    pub log_storage: LogStorageFootprint,
    pub complete_allocation_graph_verified: bool,
    pub selective_capture_executable: bool,
}

#[derive(Debug, Serialize)]
pub struct LogStorageFootprint {
    pub information_copies_agree: bool,
    pub data_range: crate::refs_write_set::ByteRange,
    pub control_ranges: Vec<crate::refs_write_set::ByteRange>,
    pub controls: Vec<crate::refs_mlog_refs::ControlObservation>,
    pub unparsed_information_value_bytes: usize,
    pub log_data_bytes_read: u64,
    pub log_transactions_verified: bool,
}

struct Pending {
    slots: [u64; 4],
    checksum: u64,
    level: Option<u8>,
    depth: u8,
    attribute_tree: Option<usize>,
    extent_tree: bool,
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
    attribute_tree: Option<usize>,
    reserved_roots: usize,
) -> Result<()> {
    ensure!(
        level > 0 && !rows.is_empty() && depth < limits.max_depth,
        "metadata index level, children or depth unsupported"
    );
    ensure!(
        u64::from(read) + pending.len() as u64 + rows.len() as u64 + reserved_roots as u64
            <= u64::from(limits.max_pages),
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
            attribute_tree,
            extent_tree: false,
        });
    }
    Ok(())
}

#[derive(Debug, Default, Serialize)]
pub struct DataStorageFootprint {
    pub streams_observed: u64,
    pub extent_records: u64,
    pub allocated_cluster_references: u64,
    pub distinct_physical_clusters: u64,
    pub sparse_clusters: u64,
    pub physical_ranges: Vec<crate::refs_write_set::ByteRange>,
    pub external_payload_bytes_read: u64,
    /// DATA allocation records met in a form the walk does not interpret.
    /// Their clusters are missing from `physical_ranges`.
    pub uninterpreted_data_records: u64,
    pub complete_stream_inventory: bool,
}

fn consume_extent_node(
    node: crate::refs_extent_refs::ExtentNode,
    map: &CommonMap<'_>,
    volume_clusters: u64,
    storage: &mut DataStorageFootprint,
    pending: &mut Vec<Pending>,
    depth: u8,
    total_pages: u32,
    limits: WalkLimits,
    reserved_roots: usize,
) -> Result<()> {
    use crate::refs_extent_refs::{ExtentKind, ExtentNodeRows};
    match node.rows {
        ExtentNodeRows::Leaf(records) => {
            for record in records {
                storage.extent_records = storage
                    .extent_records
                    .checked_add(1)
                    .context("extent record count overflow")?;
                if record.kind == ExtentKind::SparseHole {
                    storage.sparse_clusters = storage
                        .sparse_clusters
                        .checked_add(u64::from(record.clusters))
                        .context("sparse count overflow")?;
                    continue;
                }
                // This initial profile admits only runs contained by one
                // virtual container. It never guesses how a wider run steps
                // across the reserved virtual-address gap.
                let offset = record.virtual_lcn & (CPC - 1);
                let count = u64::from(record.clusters);
                ensure!(
                    count <= CPC - offset,
                    "cross-container extent translation is not implemented"
                );
                let (base, _) = map
                    .lookup(record.virtual_lcn >> 15)
                    .context("data extent container absent")?;
                let physical = base
                    .checked_add(offset)
                    .context("data physical address overflow")?;
                ensure!(
                    physical
                        .checked_add(count)
                        .is_some_and(|end| end <= volume_clusters),
                    "data extent outside volume"
                );
                ensure!(
                    storage.physical_ranges.len() < 131_072,
                    "data extent range budget exceeded"
                );
                storage
                    .physical_ranges
                    .push(crate::refs_write_set::ByteRange {
                        offset: physical * CLUSTER,
                        length: count * CLUSTER,
                    });
                storage.allocated_cluster_references = storage
                    .allocated_cluster_references
                    .checked_add(count)
                    .context("allocated extent count overflow")?;
            }
        }
        ExtentNodeRows::Index(children) => {
            ensure!(
                depth < limits.max_depth
                    && u64::from(total_pages)
                        + pending.len() as u64
                        + children.len() as u64
                        + reserved_roots as u64
                        <= u64::from(limits.max_pages),
                "extent child page/depth budget exceeded"
            );
            for child in children {
                pending.push(Pending {
                    slots: child.virtual_lcn_slots,
                    checksum: child.crc64_nvme,
                    level: Some(child.expected_child_level),
                    depth: depth + 1,
                    attribute_tree: None,
                    extent_tree: true,
                });
            }
        }
    }
    Ok(())
}

fn consume_attribute_rows(
    rows: &[refs_node::NodeRowObservation],
    map: &CommonMap<'_>,
    volume_clusters: u64,
    storage: &mut DataStorageFootprint,
    pending: &mut Vec<Pending>,
    depth: u8,
    total_pages: u32,
    limits: WalkLimits,
    reserved_roots: usize,
) -> Result<u64> {
    // How many DATA records here were in the form that is not interpreted.
    let mut uninterpreted = 0u64;
    for row in rows {
        if crate::refs_record_refs::is_uninterpreted_data_record(row)? {
            uninterpreted += 1;
            storage.uninterpreted_data_records = storage
                .uninterpreted_data_records
                .checked_add(1)
                .context("uninterpreted DATA record count overflow")?;
        } else if let Some(data) = crate::refs_record_refs::inspect_data_extent_node(row)? {
            storage.streams_observed = storage
                .streams_observed
                .checked_add(1)
                .context("data stream count overflow")?;
            consume_extent_node(
                data.node,
                map,
                volume_clusters,
                storage,
                pending,
                depth,
                total_pages,
                limits,
                reserved_roots,
            )?;
        }
    }
    Ok(uninterpreted)
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
    transcript.update(b"n2r-refs-index-attribute-and-extent-footprint-v4\0");
    let mut total_pages = 0u32;
    let mut trees = Vec::new();
    let mut data_storage = DataStorageFootprint::default();
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
    let mut log_references = BTreeMap::new();
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
            attribute_tree: None,
            extent_tree: false,
        }];
        let start_pages = total_pages;
        let mut expected_rows = None;
        let mut schema_id = None;
        let mut leaves = 0u64;
        let mut attribute_expected = Vec::new();
        let mut attribute_observed = Vec::new();
        let mut attribute_pages = 0u32;
        let mut extent_pages = 0u32;
        let mut embedded_tables = 0usize;
        let mut own_tables = 0usize;
        let mut tree_uninterpreted = 0u64;
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
            if item.attribute_tree.is_some() {
                attribute_pages += 1;
            }
            transcript.update(
                root_index
                    .map_or(u64::MAX, |index| index as u64)
                    .to_le_bytes(),
            );
            transcript.update(table_id.to_le_bytes());
            transcript.update([u8::from(item.extent_tree)]);
            transcript.update(
                item.attribute_tree
                    .map_or(u64::MAX, |id| id as u64)
                    .to_le_bytes(),
            );
            for lcn in physical {
                transcript.update(lcn.to_le_bytes());
            }
            transcript.update(&bytes);
            if item.extent_tree {
                extent_pages += 1;
                let offset = 0x50usize
                    .checked_add(u32le(&bytes, 0x50) as usize)
                    .context("extent page node offset overflow")?;
                let node = crate::refs_extent_refs::inspect_extent_node(&bytes, offset)?;
                ensure!(item.level == Some(node.level), "extent child level differs");
                consume_extent_node(
                    node,
                    &map,
                    clusters,
                    &mut data_storage,
                    &mut pending,
                    item.depth,
                    total_pages,
                    limits,
                    requests.len(),
                )?;
                continue;
            }
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
                enqueue(
                    &rows,
                    level,
                    item.depth,
                    &mut pending,
                    total_pages,
                    limits,
                    item.attribute_tree,
                    requests.len(),
                )?;
            } else {
                if let Some(oid @ (9 | 10)) = object_id {
                    ensure!(
                        item.attribute_tree.is_none(),
                        "log table unexpectedly contains attribute pages"
                    );
                    for row in &rows {
                        if let Some(reference) =
                            crate::refs_record_refs::inspect_logfile_information_row(
                                oid,
                                row,
                                geometry.volume_bytes,
                            )?
                        {
                            ensure!(
                                log_references.insert(oid, reference).is_none(),
                                "duplicate log location row"
                            );
                        }
                    }
                }
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
                if let Some(index) = item.attribute_tree {
                    let count: &mut u64 = attribute_observed
                        .get_mut(index)
                        .context("attribute tree counter absent")?;
                    *count = count
                        .checked_add(rows.len() as u64)
                        .context("attribute row count overflow")?;
                    tree_uninterpreted += consume_attribute_rows(
                        &rows,
                        &map,
                        clusters,
                        &mut data_storage,
                        &mut pending,
                        item.depth,
                        total_pages,
                        limits,
                        requests.len(),
                    )?;
                } else {
                    leaves = leaves
                        .checked_add(rows.len() as u64)
                        .context("metadata leaf row count overflow")?;
                    if object_id.is_some() && schema_id == Some(0x130) {
                        for row in &rows {
                            let file_record = if let Some(record) =
                                crate::refs_record_refs::inspect_embedded_file(row)?
                            {
                                embedded_tables += 1;
                                Some(record)
                            } else if let Some(record) =
                                crate::refs_split_refs::inspect_own_record(row)?
                            {
                                own_tables += 1;
                                Some(crate::refs_record_refs::EmbeddedFileRecord {
                                    expected_attribute_rows: record.expected_attribute_rows,
                                    node: record.node,
                                })
                            } else {
                                None
                            };
                            if let Some(record) = file_record {
                                ensure!(
                                    attribute_expected.len() < 65_536,
                                    "embedded attribute table budget exceeded"
                                );
                                let index = attribute_expected.len();
                                attribute_expected.push(record.expected_attribute_rows);
                                attribute_observed.push(if record.node.index_node {
                                    0
                                } else {
                                    record.node.rows.len() as u64
                                });
                                if record.node.index_node {
                                    ensure!(
                                        item.depth < limits.max_depth
                                            && record.node.node_level <= limits.max_depth
                                            && u64::from(total_pages)
                                                + pending.len() as u64
                                                + record.node.rows.len() as u64
                                                + requests.len() as u64
                                                <= u64::from(limits.max_pages),
                                        "embedded attribute page/depth budget exceeded"
                                    );
                                    for row in &record.node.rows {
                                        let child = crate::refs_record_refs::attribute_child(row)?;
                                        pending.push(Pending {
                                            slots: child.virtual_slots,
                                            checksum: child.crc64_nvme,
                                            level: Some(record.node.node_level - 1),
                                            depth: item.depth + 1,
                                            attribute_tree: Some(index),
                                            extent_tree: false,
                                        });
                                    }
                                } else {
                                    tree_uninterpreted += consume_attribute_rows(
                                        &record.node.rows,
                                        &map,
                                        clusters,
                                        &mut data_storage,
                                        &mut pending,
                                        item.depth,
                                        total_pages,
                                        limits,
                                        requests.len(),
                                    )?;
                                }
                            }
                        }
                    }
                }
            }
        }
        let expected = expected_rows.context("metadata root was not visited")?;
        ensure!(
            leaves == expected,
            "metadata leaf count differs from root descriptor"
        );
        ensure!(
            attribute_expected == attribute_observed,
            "embedded attribute row totals differ"
        );
        trees.push(TreeFootprint {
            root_index,
            object_id,
            table_id,
            observed_schema_id: schema_id.context("root schema was not observed")?,
            pages_read: total_pages - start_pages,
            leaf_rows: leaves,
            expected_leaf_rows: expected,
            embedded_attribute_tables: embedded_tables,
            own_record_attribute_tables: own_tables,
            external_attribute_pages: attribute_pages,
            external_extent_pages: extent_pages,
            uninterpreted_data_records: tree_uninterpreted,
            file_records_interpreted: object_id.is_some() && schema_id == Some(0x130),
            index_descendants_complete: tree_uninterpreted == 0,
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
    let log = log_references
        .get(&9)
        .context("primary Logfile Information reference absent")?;
    let duplicate = log_references
        .get(&10)
        .context("duplicate Logfile Information reference absent")?;
    ensure!(
        log.data_offset == duplicate.data_offset
            && log.data_length == duplicate.data_length
            && log.control_offsets == duplicate.control_offsets
            && log.unparsed_value_bytes == duplicate.unparsed_value_bytes
            && log.value_sha256 == duplicate.value_sha256,
        "Logfile Information copies disagree"
    );
    let mut control_ranges = Vec::new();
    let log_data_range = log.data_offset / CLUSTER..(log.data_offset + log.data_length) / CLUSTER;
    ensure!(
        visited.range(log_data_range.clone()).next().is_none()
            && protected.range(log_data_range).next().is_none(),
        "log data overlaps metadata or protected bootstrap/container pages"
    );
    ensure!(
        total_pages
            .checked_add(2)
            .is_some_and(|count| count <= limits.max_pages),
        "log control page budget exhausted"
    );
    let mut controls = Vec::new();
    for offset in log.control_offsets {
        ensure!(
            !visited.contains(&(offset / CLUSTER)) && !protected.contains(&(offset / CLUSTER)),
            "log control overlaps another required metadata page"
        );
        let mut bytes = [0u8; 4096];
        reader.seek(SeekFrom::Start(offset))?;
        reader.read_exact(&mut bytes)?;
        let control = crate::refs_mlog_refs::inspect_control(&bytes, offset, log)?;
        transcript.update(b"MLog-control");
        transcript.update(offset.to_le_bytes());
        transcript.update(bytes);
        controls.push(control);
        control_ranges.push(crate::refs_write_set::ByteRange {
            offset,
            length: CLUSTER,
        });
    }
    ensure!(
        controls[0].format_magic == controls[1].format_magic
            && controls[0].log_uuid == controls[1].log_uuid,
        "log controls belong to different log instances"
    );
    let log_storage = LogStorageFootprint {
        information_copies_agree: true,
        data_range: crate::refs_write_set::ByteRange {
            offset: log.data_offset,
            length: log.data_length,
        },
        control_ranges,
        controls,
        unparsed_information_value_bytes: log.unparsed_value_bytes,
        log_data_bytes_read: 0,
        log_transactions_verified: false,
    };
    for range in &data_storage.physical_ranges {
        let span = range.offset / CLUSTER..(range.offset + range.length) / CLUSTER;
        ensure!(
            visited.range(span.clone()).next().is_none() && protected.range(span).next().is_none(),
            "observed data extent overlaps metadata or protected bootstrap/container storage"
        );
        ensure!(
            range.offset + range.length <= log.data_offset
                || range.offset >= log.data_offset + log.data_length,
            "observed data extent overlaps log storage"
        );
        ensure!(
            log.control_offsets
                .iter()
                .all(|offset| *offset + CLUSTER <= range.offset
                    || *offset >= range.offset + range.length),
            "observed data extent overlaps log controls"
        );
    }
    data_storage
        .physical_ranges
        .sort_unstable_by_key(|range| range.offset);
    let mut data_ranges: Vec<crate::refs_write_set::ByteRange> = Vec::new();
    for range in data_storage.physical_ranges.drain(..) {
        if let Some(last) = data_ranges
            .last_mut()
            .filter(|last| last.offset + last.length >= range.offset)
        {
            last.length =
                (last.offset + last.length).max(range.offset + range.length) - last.offset;
        } else {
            data_ranges.push(range);
        }
    }
    data_storage.physical_ranges = data_ranges;
    data_storage.distinct_physical_clusters =
        data_storage
            .physical_ranges
            .iter()
            .try_fold(0u64, |count, range| {
                count
                    .checked_add(range.length / CLUSTER)
                    .context("distinct data cluster count overflow")
            })?;
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
        profile: "refs-3.14-4k-crc64-index-attribute-extent-and-log-footprint-v5",
        checkpoint_lcn: checkpoint.lcn,
        checkpoint_sha256: checkpoint.sha256.clone(),
        mapping_sha256: binding
            .common_mapping_sha256
            .context("mapping pin absent")?,
        limits,
        pages_read: total_pages,
        budget_pages_charged: total_pages + 2,
        bytes_read: u64::from(total_pages) * PAGE as u64 + 8192,
        physical_ranges: ranges,
        page_transcript_sha256: hex::encode(transcript.finalize()),
        trees,
        data_storage,
        log_storage,
        complete_allocation_graph_verified: false,
        selective_capture_executable: false,
    })
}
