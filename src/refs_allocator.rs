//! Bounded read-only walk of the ReFS 3.14 Medium allocator on one candidate
//! checkpoint. It is an allocator observation, not whole-volume ownership:
//! the Small allocator and reachable metadata pages must also be reconciled.
use crate::{refs_bootstrap::crc64_nvme, refs_inspect, refs_node};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
};

const CLUSTER: u64 = 4096;
const PAGE: usize = 16384;
const CPC: u64 = 16384;

#[derive(Debug, Clone, Serialize)]
pub struct AllocatorRow {
    pub start_lcn: u64,
    pub clusters: u64,
    pub flags: u16,
    pub free_clusters: u64,
    pub allocated_clusters: u64,
    pub bitmap_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AllocatedRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Serialize)]
pub struct MediumAllocatorObservation {
    pub profile: &'static str,
    pub checkpoint_lcn: u64,
    pub checkpoint_clock: u64,
    pub root_physical_lcns: [u64; 4],
    pub child_pages: Vec<[u64; 4]>,
    pub rows: Vec<AllocatorRow>,
    pub free_clusters: u64,
    pub allocated_clusters: u64,
    pub allocated_ranges: Vec<AllocatedRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streamed: Option<AllocatorStreamSummary>,
    pub allocator_walk_complete: bool,
    pub whole_volume_ownership_verified: bool,
    pub windows_mount_qualified: bool,
}

#[derive(Debug, Serialize)]
pub struct AllocatorStreamSummary {
    pub encoding: &'static str,
    pub leaf_rows: u64,
    pub pages_read: u64,
    pub covered_clusters: u64,
    pub leaf_rows_sha256: String,
    pub page_transcript_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct SmallAllocatorObservation {
    pub profile: &'static str,
    pub checkpoint_lcn: u64,
    pub checkpoint_clock: u64,
    pub root_physical_lcns: [u64; 4],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub child_pages: Vec<[u64; 4]>,
    pub rows: Vec<AllocatorRow>,
    pub managed_clusters: u64,
    pub free_clusters: u64,
    pub allocated_clusters: u64,
    pub allocated_ranges: Vec<AllocatedRange>,
    pub allocator_walk_complete: bool,
    pub whole_volume_ownership_verified: bool,
}

impl MediumAllocatorObservation {
    pub fn medium_allocated(&self, lcn: u64) -> bool {
        let offset = lcn.saturating_mul(CLUSTER);
        self.allocated_ranges
            .iter()
            .any(|range| range.offset <= offset && offset < range.offset + range.length)
    }
}

fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn u64le(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}

fn read_page(
    reader: &mut (impl Read + Seek),
    lcns: &[u64; 4],
    volume_bytes: u64,
) -> Result<[u8; PAGE]> {
    let mut page = [0u8; PAGE];
    for (index, &lcn) in lcns.iter().enumerate() {
        ensure!(
            lcn > 0 && !lcns[..index].contains(&lcn),
            "duplicate/zero allocator page cluster"
        );
        let at = lcn.checked_mul(CLUSTER).context("page offset overflow")?;
        ensure!(
            at.checked_add(CLUSTER)
                .is_some_and(|end| end <= volume_bytes),
            "page outside volume"
        );
        reader.seek(SeekFrom::Start(at))?;
        reader.read_exact(&mut page[index * 4096..(index + 1) * 4096])?;
    }
    Ok(page)
}

fn row_parts(row: &refs_node::NodeRowObservation) -> Result<(Vec<u8>, Vec<u8>)> {
    let bytes = hex::decode(&row.row_bytes_hex)?;
    ensure!(
        bytes.len() == row.size as usize,
        "allocator row length differs"
    );
    let key =
        usize::from(row.key_offset)..usize::from(row.key_offset) + usize::from(row.key_length);
    let value = usize::from(row.value_offset)
        ..usize::from(row.value_offset) + usize::from(row.value_length);
    Ok((
        bytes.get(key).context("allocator row key bounds")?.to_vec(),
        bytes
            .get(value)
            .context("allocator row value bounds")?
            .to_vec(),
    ))
}

fn translate(
    vlcn: u64,
    mappings: &crate::refs_containers::ContainerAddressView<'_>,
    volume_clusters: u64,
) -> Result<u64> {
    ensure!(
        vlcn & CPC == 0,
        "virtual allocator page uses forbidden container bit"
    );
    let id = vlcn >> 15;
    let offset = vlcn & (CPC - 1);
    let (start, _) = mappings
        .lookup(id)
        .context("allocator page container unmapped")?;
    let physical = start
        .checked_add(offset)
        .context("translated LCN overflow")?;
    ensure!(
        physical < volume_clusters,
        "translated allocator page outside volume"
    );
    Ok(physical)
}

fn append_allocated(ranges: &mut Vec<AllocatedRange>, lcn: u64, clusters: u64) -> Result<()> {
    if clusters == 0 {
        return Ok(());
    }
    let offset = lcn
        .checked_mul(CLUSTER)
        .context("allocated byte offset overflow")?;
    let length = clusters
        .checked_mul(CLUSTER)
        .context("allocated byte length overflow")?;
    if let Some(last) = ranges.last_mut()
        && last.offset + last.length == offset
    {
        last.length += length;
    } else {
        ensure!(ranges.len() < 65536, "allocator interval budget exhausted");
        ranges.push(AllocatedRange { offset, length });
    }
    Ok(())
}

fn decode_leaf(
    row: &refs_node::NodeRowObservation,
    volume_clusters: u64,
    allocated: &mut Vec<AllocatedRange>,
) -> Result<AllocatorRow> {
    let (key, value) = row_parts(row)?;
    ensure!(
        key.len() == 16 && value.len() >= 24 && key == value[..16],
        "allocator leaf key/value prefix differs"
    );
    let start = u64le(&value, 0);
    let count = u64le(&value, 8);
    let free_hint = u64::from(u16le(&value, 0x10));
    let flags = u16le(&value, 0x12);
    ensure!(
        count > 0
            && start
                .checked_add(count)
                .is_some_and(|end| end <= volume_clusters),
        "allocator row range outside volume"
    );
    let (free, bitmap_sha256) = if flags & 1 != 0 {
        let bitmap_at = usize::from(value[0x14]);
        ensure!(
            count <= CPC
                && bitmap_at >= 24
                && bitmap_at + count.div_ceil(8) as usize <= value.len(),
            "unsupported allocator bitmap row"
        );
        let bitmap = &value[bitmap_at..bitmap_at + count.div_ceil(8) as usize];
        let mut free = 0u64;
        let mut run_start = None;
        for bit in 0..count {
            let used = bitmap[(bit / 8) as usize] & (1 << (bit % 8)) != 0;
            if used {
                if run_start.is_none() {
                    run_start = Some(bit);
                }
            } else {
                free += 1;
                if let Some(first) = run_start.take() {
                    append_allocated(allocated, start + first, bit - first)?;
                }
            }
        }
        if let Some(first) = run_start {
            append_allocated(allocated, start + first, count - first)?;
        }
        ensure!(free == free_hint, "allocator bitmap free count differs");
        (free, Some(hex::encode(Sha256::digest(bitmap))))
    } else {
        ensure!(
            flags & 2 != 0 && value.len() == 24,
            "unsupported uniform allocator row"
        );
        let free = if free_hint == 0 {
            append_allocated(allocated, start, count)?;
            0
        } else {
            ensure!(
                free_hint == 65535 || free_hint == count,
                "uniform free-count marker differs"
            );
            count
        };
        (free, None)
    };
    Ok(AllocatorRow {
        start_lcn: start,
        clusters: count,
        flags,
        free_clusters: free,
        allocated_clusters: count - free,
        bitmap_sha256,
    })
}

/// Read the higher-clock checkpoint's Medium allocator root and its one level
/// of leaves. Unknown layouts fail closed; this does not establish that every
/// Medium-free cluster is safe from Small-allocator or metadata ownership.
pub fn inspect_medium(
    reader: &mut (impl Read + Seek),
    image_bytes: u64,
) -> Result<MediumAllocatorObservation> {
    inspect_medium_with_resource_profile(
        reader,
        image_bytes,
        crate::ntfs_admission::ResourceProfile::AlphaV1,
    )
}

pub fn inspect_medium_with_resource_profile(
    reader: &mut (impl Read + Seek),
    image_bytes: u64,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<MediumAllocatorObservation> {
    let refs = refs_inspect::inspect_with_resource_profile(reader, image_bytes, resources)?;
    let geometry = &refs.geometry;
    ensure!(
        geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_cluster == 4096
            && geometry.volume_bytes == image_bytes,
        "unsupported Medium allocator profile"
    );
    let bootstrap = refs.bootstrap.context("bootstrap observation absent")?;
    let valid_checkpoints: Vec<_> = bootstrap
        .checkpoints
        .iter()
        .filter(|c| c.rejection.is_none() && c.self_checksum.as_ref().is_some_and(|s| s.matches))
        .filter_map(|c| c.checkpoint.as_ref().map(|cp| (c.lcn, cp.virtual_clock)))
        .collect();
    let checkpoint = *valid_checkpoints
        .iter()
        .max_by_key(|&&(_, clock)| clock)
        .context("valid checkpoint absent")?;
    ensure!(
        valid_checkpoints
            .iter()
            .filter(|&&(_, clock)| clock == checkpoint.1)
            .count()
            == 1,
        "highest valid checkpoint clock is ambiguous"
    );
    let container = bootstrap
        .container_tables
        .as_ref()
        .context("container maps absent")?;
    let pair = container
        .failover_comparisons
        .iter()
        .find(|p| p.checkpoint_lcn == checkpoint.0)
        .context("checkpoint container pair absent")?;
    ensure!(
        pair.both_walks_finished
            && pair.both_root_counts_match
            && pair.mapping_entries_equal == Some(true)
            && pair.raw_values_equal == Some(true)
            && pair.rejection.is_none(),
        "container copies disagree or are incomplete"
    );
    let tree = container
        .trees
        .iter()
        .find(|t| t.checkpoint_lcn == checkpoint.0 && t.root_index == 7)
        .context("primary container table absent")?;
    let mappings = tree.address_view(image_bytes / CLUSTER)?;
    let roots = bootstrap
        .virtual_roots
        .as_ref()
        .context("virtual root observations absent")?;
    let medium = roots
        .roots
        .iter()
        .find(|r| r.checkpoint_lcn == checkpoint.0 && r.root_index == 1)
        .context("Medium allocator root absent")?;
    ensure!(
        medium.rejection.is_none()
            && medium.checksum_matches == Some(true)
            && medium.header_matches == Some(true)
            && medium.self_virtual_slots_match == Some(true)
            && medium.table_id_matches == Some(true),
        "Medium allocator root observation rejected"
    );
    let root_slots = medium
        .physical_lcn_slots
        .context("Medium root physical slots absent")?;
    let root_bytes = read_page(reader, &root_slots, image_bytes)?;
    ensure!(
        hex::encode(Sha256::digest(root_bytes)) == medium.sha256.as_deref().unwrap_or("")
            && crc64_nvme(&root_bytes)
                == u64::from_str_radix(
                    medium
                        .stored_crc64_nvme
                        .as_deref()
                        .context("root CRC absent")?,
                    16
                )?,
        "Medium allocator root hash or CRC differs"
    );
    let root = refs_node::inspect_root_node(&root_bytes)?;
    if resources != crate::ntfs_admission::ResourceProfile::AlphaV1 {
        return inspect_medium_multilevel(
            reader,
            image_bytes,
            checkpoint,
            root_slots,
            &root_bytes,
            root,
            &mappings,
        );
    }
    ensure!(
        root.table_id_low == 33 && root.node_level == 1,
        "unsupported Medium root shape"
    );
    let mut child_pages = Vec::new();
    let mut leaves = Vec::new();
    for row in &root.rows {
        let (_key, value) = row_parts(row)?;
        ensure!(
            value.len() == 48
                && u16le(&value, 0x20) == 0
                && value[0x22] == 2
                && value[0x23] == 8
                && u32le(&value, 0x24) == 8,
            "allocator child reference format differs"
        );
        let vlcns = [
            u64le(&value, 0),
            u64le(&value, 8),
            u64le(&value, 16),
            u64le(&value, 24),
        ];
        let mut physical = [0; 4];
        for (index, &vlcn) in vlcns.iter().enumerate() {
            physical[index] = translate(vlcn, &mappings, image_bytes / CLUSTER)?;
        }
        let page = read_page(reader, &physical, image_bytes)?;
        ensure!(
            crc64_nvme(&page) == u64le(&value, 0x28)
                && &page[..4] == b"MSB+"
                && u64le(&page, 0x48) == 33
                && (0..4).all(|i| u64le(&page, 0x20 + i * 8) == vlcns[i]),
            "Medium allocator child CRC, table or self-location differs"
        );
        let node = refs_node::inspect_child_node(&page)?;
        ensure!(
            node.node_level == 0,
            "Medium allocator has unsupported depth"
        );
        child_pages.push(physical);
        leaves.extend(node.rows);
    }
    ensure!(
        leaves.len() as u64 == root.whole_table_row_count && leaves.len() <= 4096,
        "Medium allocator leaf count differs"
    );
    let mut rows = Vec::new();
    let mut allocated_ranges = Vec::new();
    let mut covered = 0u64;
    let mut free = 0u64;
    for row in &leaves {
        let decoded = decode_leaf(row, image_bytes / CLUSTER, &mut allocated_ranges)?;
        ensure!(
            decoded.start_lcn == covered,
            "Medium allocator gap or row disorder"
        );
        covered += decoded.clusters;
        free += decoded.free_clusters;
        rows.push(decoded);
    }
    ensure!(
        covered == image_bytes / CLUSTER,
        "Medium allocator does not cover volume"
    );
    Ok(MediumAllocatorObservation {
        profile: "candidate ReFS 3.14 Medium allocator one-level walk",
        checkpoint_lcn: checkpoint.0,
        checkpoint_clock: checkpoint.1,
        root_physical_lcns: root_slots,
        child_pages,
        rows,
        free_clusters: free,
        allocated_clusters: covered - free,
        allocated_ranges,
        streamed: None,
        allocator_walk_complete: true,
        whole_volume_ownership_verified: false,
        windows_mount_qualified: false,
    })
}

struct PendingAllocatorPage {
    slots: [u64; 4],
    crc64: u64,
    expected_level: u8,
}

fn enqueue_allocator_children(
    rows: &[refs_node::NodeRowObservation],
    parent_level: u8,
    pending: &mut Vec<PendingAllocatorPage>,
    pages_read: usize,
    max_pages: usize,
) -> Result<()> {
    ensure!(
        parent_level > 0 && !rows.is_empty(),
        "empty or leaf allocator index node"
    );
    ensure!(
        pages_read + pending.len() + rows.len() <= max_pages,
        "allocator page budget exhausted before following children"
    );
    for row in rows.iter().rev() {
        let (_key, value) = row_parts(row)?;
        ensure!(
            value.len() == 48
                && u16le(&value, 0x20) == 0
                && value[0x22] == 2
                && value[0x23] == 8
                && u32le(&value, 0x24) == 8,
            "allocator child reference format differs"
        );
        pending.push(PendingAllocatorPage {
            slots: [
                u64le(&value, 0),
                u64le(&value, 8),
                u64le(&value, 16),
                u64le(&value, 24),
            ],
            crc64: u64le(&value, 0x28),
            expected_level: parent_level - 1,
        });
    }
    Ok(())
}

/// Only compact decoded allocator rows and intervals survive each page. The
/// authenticated container map remains independently required and bounded.
fn inspect_medium_multilevel(
    reader: &mut (impl Read + Seek),
    image_bytes: u64,
    checkpoint: (u64, u64),
    root_slots: [u64; 4],
    root_bytes: &[u8; PAGE],
    root: refs_node::RootNodeObservation,
    mappings: &crate::refs_containers::ContainerAddressView<'_>,
) -> Result<MediumAllocatorObservation> {
    const MAX_PAGES: usize = 1_048_576;
    const MAX_ROWS: u64 = 33_554_432;
    const RETAINED_CHILD_PAGES: usize = 32;
    const MAX_DEPTH: u8 = 8;
    ensure!(
        root.table_id_low == 33
            && root.node_level <= MAX_DEPTH
            && root.whole_table_row_count <= MAX_ROWS,
        "experimental Medium allocator root exceeds traversal profile"
    );
    let domain = image_bytes / CLUSTER;
    let volume_signature = u32le(root_bytes, 0xc);
    let mut pending = Vec::new();
    let mut seen: BTreeSet<u64> = root_slots.into_iter().collect();
    let mut child_pages = Vec::new();
    let mut pages_read = 1usize;
    let mut row_count = 0u64;
    let mut row_hash = Sha256::new();
    row_hash.update(b"refs-medium-leaf-row-sha256-v1");
    let mut page_hash = Sha256::new();
    page_hash.update(b"refs-medium-page-transcript-v1");
    for lcn in root_slots {
        page_hash.update(lcn.to_le_bytes());
    }
    page_hash.update([root.node_level]);
    page_hash.update(root_bytes);
    let mut allocated_ranges = Vec::new();
    let (mut covered, mut free) = (0u64, 0u64);
    let mut consume_leaf = |leaf: &[refs_node::NodeRowObservation]| -> Result<()> {
        ensure!(
            row_count
                .checked_add(leaf.len() as u64)
                .is_some_and(|count| count <= MAX_ROWS),
            "Medium allocator leaf-row budget exhausted"
        );
        for row in leaf {
            let decoded = decode_leaf(row, domain, &mut allocated_ranges)?;
            ensure!(
                decoded.start_lcn == covered,
                "Medium allocator gap or row disorder"
            );
            covered = covered
                .checked_add(decoded.clusters)
                .context("allocator coverage overflow")?;
            free = free
                .checked_add(decoded.free_clusters)
                .context("allocator free count overflow")?;
            let mut digest = [0; 32];
            hex::decode_to_slice(&row.row_sha256, &mut digest)
                .context("allocator row digest differs")?;
            row_hash.update(digest);
            row_count += 1;
        }
        Ok(())
    };
    if root.node_level == 0 {
        consume_leaf(&root.rows)?;
    } else {
        enqueue_allocator_children(&root.rows, root.node_level, &mut pending, 1, MAX_PAGES)?;
    }
    while let Some(next) = pending.pop() {
        ensure!(
            pages_read < MAX_PAGES,
            "Medium allocator page budget exhausted"
        );
        let mut physical = [0; 4];
        for (index, &vlcn) in next.slots.iter().enumerate() {
            physical[index] = translate(vlcn, mappings, domain)?;
            ensure!(
                seen.insert(physical[index]),
                "cyclic, shared or overlapping Medium allocator page"
            );
        }
        let bytes = read_page(reader, &physical, image_bytes)?;
        pages_read += 1;
        for lcn in physical {
            page_hash.update(lcn.to_le_bytes());
        }
        page_hash.update([next.expected_level]);
        page_hash.update(bytes);
        ensure!(
            crc64_nvme(&bytes) == next.crc64
                && &bytes[..4] == b"MSB+"
                && u32le(&bytes, 4) == 2
                && u32le(&bytes, 8) == 0
                && u32le(&bytes, 0xc) == volume_signature
                && u64le(&bytes, 0x40) == 0
                && u64le(&bytes, 0x48) == 33
                && (0..4).all(|i| u64le(&bytes, 0x20 + i * 8) == next.slots[i]),
            "Medium allocator child CRC, header, table or self-location differs"
        );
        let node = refs_node::inspect_child_node(&bytes)?;
        ensure!(
            node.node_level == next.expected_level,
            "Medium allocator child level differs from parent"
        );
        if child_pages.len() < RETAINED_CHILD_PAGES {
            child_pages.push(physical);
        }
        if node.node_level == 0 {
            consume_leaf(&node.rows)?;
        } else {
            enqueue_allocator_children(
                &node.rows,
                node.node_level,
                &mut pending,
                pages_read,
                MAX_PAGES,
            )?;
        }
    }
    ensure!(
        row_count == root.whole_table_row_count && covered == domain,
        "Medium allocator row count or full-volume coverage differs"
    );
    Ok(MediumAllocatorObservation {
        profile: "candidate ReFS 3.14 Medium allocator streamed multilevel walk",
        checkpoint_lcn: checkpoint.0,
        checkpoint_clock: checkpoint.1,
        root_physical_lcns: root_slots,
        child_pages,
        rows: Vec::new(),
        free_clusters: free,
        allocated_clusters: covered - free,
        allocated_ranges,
        streamed: Some(AllocatorStreamSummary {
            encoding: "refs-medium-streamed-rows-v1",
            leaf_rows: row_count,
            pages_read: pages_read as u64,
            covered_clusters: covered,
            leaf_rows_sha256: hex::encode(row_hash.finalize()),
            page_transcript_sha256: hex::encode(page_hash.finalize()),
        }),
        allocator_walk_complete: true,
        whole_volume_ownership_verified: false,
        windows_mount_qualified: false,
    })
}

/// Read the checkpoint-bound physical Small allocator root. Its disjoint
/// managed ranges do not cover the whole volume and may sit inside areas
/// reserved by the Medium tier.
pub fn inspect_small(
    reader: &mut (impl Read + Seek),
    image_bytes: u64,
) -> Result<SmallAllocatorObservation> {
    inspect_small_with_resource_profile(
        reader,
        image_bytes,
        crate::ntfs_admission::ResourceProfile::AlphaV1,
    )
}

pub fn inspect_small_with_resource_profile(
    reader: &mut (impl Read + Seek),
    image_bytes: u64,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<SmallAllocatorObservation> {
    let refs = if resources == crate::ntfs_admission::ResourceProfile::AlphaV1 {
        refs_inspect::inspect(reader, image_bytes)?
    } else {
        refs_inspect::inspect_physical_bootstrap(reader, image_bytes)?
    };
    let geometry = &refs.geometry;
    ensure!(
        geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_cluster == 4096
            && geometry.volume_bytes == image_bytes,
        "unsupported Small allocator profile"
    );
    let bootstrap = refs.bootstrap.context("bootstrap observation absent")?;
    let valid_checkpoints: Vec<_> = bootstrap
        .checkpoints
        .iter()
        .filter(|c| c.rejection.is_none() && c.self_checksum.as_ref().is_some_and(|s| s.matches))
        .filter_map(|c| c.checkpoint.as_ref().map(|cp| (c.lcn, cp.virtual_clock)))
        .collect();
    let checkpoint = *valid_checkpoints
        .iter()
        .max_by_key(|&&(_, clock)| clock)
        .context("valid checkpoint absent")?;
    ensure!(
        valid_checkpoints
            .iter()
            .filter(|&&(_, clock)| clock == checkpoint.1)
            .count()
            == 1,
        "highest valid checkpoint clock is ambiguous"
    );
    let reference = bootstrap
        .physical_root_references
        .iter()
        .find(|root| root.checkpoint_lcn == checkpoint.0 && root.root_index == 12)
        .context("Small allocator reference absent")?;
    ensure!(
        reference.rejection.is_none()
            && reference.checksum_matches == Some(true)
            && reference.header_matches == Some(true)
            && reference.table_id_matches == Some(true),
        "Small allocator root reference rejected"
    );
    let observed_page = bootstrap
        .physical_root_pages
        .get(
            reference
                .page_index
                .context("Small root page index absent")?,
        )
        .context("Small root page absent")?;
    let page = read_page(reader, &reference.lcn_slots, image_bytes)?;
    ensure!(
        observed_page.lcn_slots == reference.lcn_slots
            && observed_page.table_id_low == 34
            && hex::encode(Sha256::digest(page)) == observed_page.sha256
            && crc64_nvme(&page)
                == u64::from_str_radix(
                    reference
                        .stored_crc64_nvme
                        .as_deref()
                        .context("Small root CRC absent")?,
                    16,
                )?,
        "Small allocator root hash, table or CRC differs"
    );
    let root = refs_node::inspect_root_node(&page)?;
    if resources != crate::ntfs_admission::ResourceProfile::AlphaV1 {
        return inspect_small_multilevel(
            reader,
            image_bytes,
            checkpoint,
            reference.lcn_slots,
            &page,
            root,
        );
    }
    ensure!(
        root.table_id_low == 34
            && root.node_level == 0
            && root.rows.len() as u64 == root.whole_table_row_count,
        "unsupported Small allocator root shape"
    );
    let mut rows = Vec::new();
    let mut allocated_ranges = Vec::new();
    let mut previous_end = 0u64;
    let (mut managed, mut free) = (0u64, 0u64);
    for row in &root.rows {
        let decoded = decode_leaf(row, image_bytes / CLUSTER, &mut allocated_ranges)?;
        ensure!(
            decoded.start_lcn >= previous_end,
            "Small allocator rows overlap or are unsorted"
        );
        previous_end = decoded.start_lcn + decoded.clusters;
        managed += decoded.clusters;
        free += decoded.free_clusters;
        rows.push(decoded);
    }
    Ok(SmallAllocatorObservation {
        profile: "candidate ReFS 3.14 Small allocator root walk",
        checkpoint_lcn: checkpoint.0,
        checkpoint_clock: checkpoint.1,
        root_physical_lcns: reference.lcn_slots,
        child_pages: Vec::new(),
        rows,
        managed_clusters: managed,
        free_clusters: free,
        allocated_clusters: managed - free,
        allocated_ranges,
        allocator_walk_complete: true,
        whole_volume_ownership_verified: false,
    })
}

/// Small allocator table pages are physically addressed. Reusing the Medium
/// tier's virtual-container translation here would follow a different graph.
fn inspect_small_multilevel(
    reader: &mut (impl Read + Seek),
    image_bytes: u64,
    checkpoint: (u64, u64),
    root_slots: [u64; 4],
    root_bytes: &[u8; PAGE],
    root: refs_node::RootNodeObservation,
) -> Result<SmallAllocatorObservation> {
    const MAX_PAGES: usize = 4096;
    const MAX_ROWS: usize = 65536;
    const MAX_DEPTH: u8 = 8;
    ensure!(
        root.table_id_low == 34
            && root.node_level <= MAX_DEPTH
            && root.whole_table_row_count <= MAX_ROWS as u64,
        "experimental Small allocator root exceeds traversal profile"
    );
    let volume_signature = u32le(root_bytes, 0xc);
    let mut pending = Vec::new();
    let mut seen: BTreeSet<u64> = root_slots.into_iter().collect();
    let mut child_pages = Vec::new();
    let mut rows = Vec::new();
    let mut allocated_ranges = Vec::new();
    let (mut previous_end, mut managed, mut free) = (0u64, 0u64, 0u64);
    let mut consume_leaf = |leaf: &[refs_node::NodeRowObservation]| -> Result<()> {
        ensure!(
            rows.len() + leaf.len() <= MAX_ROWS,
            "Small allocator leaf-row budget exhausted"
        );
        for row in leaf {
            let decoded = decode_leaf(row, image_bytes / CLUSTER, &mut allocated_ranges)?;
            ensure!(
                decoded.start_lcn >= previous_end,
                "Small allocator rows overlap or are unsorted"
            );
            previous_end = decoded
                .start_lcn
                .checked_add(decoded.clusters)
                .context("Small allocator range overflow")?;
            managed = managed
                .checked_add(decoded.clusters)
                .context("Small managed count overflow")?;
            free = free
                .checked_add(decoded.free_clusters)
                .context("Small free count overflow")?;
            rows.push(decoded);
        }
        Ok(())
    };
    if root.node_level == 0 {
        consume_leaf(&root.rows)?;
    } else {
        enqueue_allocator_children(&root.rows, root.node_level, &mut pending, 1, MAX_PAGES)?;
    }
    while let Some(next) = pending.pop() {
        ensure!(
            child_pages.len() + 1 < MAX_PAGES,
            "Small allocator page budget exhausted"
        );
        for &lcn in &next.slots {
            ensure!(
                seen.insert(lcn),
                "cyclic, shared or overlapping Small allocator page"
            );
        }
        let bytes = read_page(reader, &next.slots, image_bytes)?;
        ensure!(
            crc64_nvme(&bytes) == next.crc64
                && &bytes[..4] == b"MSB+"
                && u32le(&bytes, 4) == 2
                && u32le(&bytes, 8) == 0
                && u32le(&bytes, 0xc) == volume_signature
                && u64le(&bytes, 0x40) == 0
                && u64le(&bytes, 0x48) == 34
                && (0..4).all(|i| u64le(&bytes, 0x20 + i * 8) == next.slots[i]),
            "Small allocator child CRC, header, table or physical self-location differs"
        );
        let node = refs_node::inspect_child_node(&bytes)?;
        ensure!(
            node.node_level == next.expected_level,
            "Small allocator child level differs from parent"
        );
        child_pages.push(next.slots);
        if node.node_level == 0 {
            consume_leaf(&node.rows)?;
        } else {
            enqueue_allocator_children(
                &node.rows,
                node.node_level,
                &mut pending,
                1 + child_pages.len(),
                MAX_PAGES,
            )?;
        }
    }
    ensure!(
        rows.len() as u64 == root.whole_table_row_count,
        "Small allocator leaf count differs from root descriptor"
    );
    Ok(SmallAllocatorObservation {
        profile: "candidate ReFS 3.14 Small allocator bounded physical multilevel walk",
        checkpoint_lcn: checkpoint.0,
        checkpoint_clock: checkpoint.1,
        root_physical_lcns: root_slots,
        child_pages,
        rows,
        managed_clusters: managed,
        free_clusters: free,
        allocated_clusters: managed - free,
        allocated_ranges,
        allocator_walk_complete: true,
        whole_volume_ownership_verified: false,
    })
}
