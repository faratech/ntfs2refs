//! Read-only union of independently authenticated checkpoint generations.
//! Cross-generation reuse is expected under COW and is not an ownership error.
use crate::{
    refs_bootstrap::{AnchorProbe, BootstrapProbe, RootReference, crc64_nvme},
    refs_containers::{self, ContainerLimits, ContainerRootTarget, ContainerTablesProbe},
    refs_inspect::RefsGeometry,
    refs_node,
    refs_virtual_roots::walk::{self, MetadataFootprint, WalkLimits},
    refs_write_set::ByteRange,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
};

const CLUSTER: u64 = 4096;
const PAGE: usize = 16384;
const MAX_RANGES: usize = 1_048_576;

#[derive(Serialize)]
pub struct GenerationUnion {
    pub profile: &'static str,
    pub max_page_reads: u32,
    pub bootstrap_physical_page_reads: u32,
    pub budget_pages_charged: u32,
    pub page_budget_scope: &'static str,
    pub generations: Vec<GenerationFootprint>,
    pub bootstrap_protected_lcns: BTreeSet<u64>,
    pub required_metadata_ranges: Vec<ByteRange>,
    pub observed_data_ranges: Vec<ByteRange>,
    pub observed_required_ranges: Vec<ByteRange>,
    pub cross_generation_overlap_policy: &'static str,
    pub scope: &'static str,
    pub complete_allocation_graph_verified: bool,
    pub selective_capture_executable: bool,
    pub conversion_authorized: bool,
}

#[derive(Serialize)]
pub struct GenerationFootprint {
    pub checkpoint_lcn: u64,
    pub checkpoint_clock: u64,
    pub checkpoint_sha256: String,
    pub physical_containers: ContainerTablesProbe,
    pub small_allocator_tree: PhysicalTreeFootprint,
    pub virtual_trees: MetadataFootprint,
    pub required_metadata_ranges: Vec<ByteRange>,
}

#[derive(Serialize)]
pub struct PhysicalTreeFootprint {
    pub root_index: usize,
    pub table_id: u64,
    pub pages_read: u32,
    pub leaf_rows: u64,
    pub expected_leaf_rows: u64,
    pub physical_ranges: Vec<ByteRange>,
    pub page_transcript_sha256: String,
    pub index_descendants_complete: bool,
    pub allocator_values_interpreted: bool,
    pub complete_allocation_graph_verified: bool,
}

struct PageBudget {
    limit: u32,
    used: u32,
}

impl PageBudget {
    fn remaining(&self) -> u32 {
        self.limit - self.used
    }

    fn charge(&mut self, pages: u32) -> Result<()> {
        self.used = self
            .used
            .checked_add(pages)
            .context("page accounting overflow")?;
        ensure!(
            self.used <= self.limit,
            "shared generation page budget exhausted"
        );
        Ok(())
    }
}

fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded page field"))
}

fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded page field"))
}

pub fn valid_checkpoint(checkpoint: &AnchorProbe) -> bool {
    checkpoint.kind == "CHKP"
        && checkpoint.rejection.is_none()
        && !checkpoint.referenced_by_superblock_lcns.is_empty()
        && checkpoint.self_checksum.as_ref().is_some_and(|s| s.matches)
        && checkpoint.header.as_ref().is_some_and(|h| {
            h.signature == "CHKP" && h.version == 2 && h.lcn_slots[0] == checkpoint.lcn
        })
        && checkpoint.checkpoint.as_ref().is_some_and(|c| {
            c.header_clock_matches
                && c.major_version == 3
                && c.minor_version == 14
                && c.reference_size == 48
                && c.roots.len() == 13
                && c.roots.iter().enumerate().all(|(i, r)| r.index == i)
        })
}

fn reference_crc(reference: &RootReference) -> Result<u64> {
    ensure!(
        reference.flags == 0
            && reference.checksum_type == 2
            && reference.checksum_data_offset == 8
            && reference.checksum_data_length == 8
            && reference.stored_checksum_bytes_hex.len() == 16,
        "unsupported physical-root CRC64 reference"
    );
    let bytes: [u8; 8] = hex::decode(&reference.stored_checksum_bytes_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("physical-root checksum length differs"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn coalesce(mut ranges: Vec<ByteRange>, volume_bytes: u64) -> Result<Vec<ByteRange>> {
    ensure!(
        ranges.len() <= MAX_RANGES,
        "generation union range budget exceeded"
    );
    for range in &ranges {
        ensure!(
            range.length > 0
                && range.offset.is_multiple_of(CLUSTER)
                && range.length.is_multiple_of(CLUSTER)
                && range
                    .offset
                    .checked_add(range.length)
                    .is_some_and(|end| end <= volume_bytes),
            "generation union range is unaligned or outside volume"
        );
    }
    ranges.sort_unstable_by_key(|range| range.offset);
    let mut merged: Vec<ByteRange> = Vec::new();
    for range in ranges {
        if let Some(last) = merged
            .last_mut()
            .filter(|last| last.offset + last.length >= range.offset)
        {
            last.length =
                (last.offset + last.length).max(range.offset + range.length) - last.offset;
        } else {
            merged.push(range);
        }
    }
    Ok(merged)
}

fn cluster_ranges(clusters: &BTreeSet<u64>, volume_bytes: u64) -> Result<Vec<ByteRange>> {
    let mut ranges: Vec<ByteRange> = Vec::new();
    for &lcn in clusters {
        let offset = lcn
            .checked_mul(CLUSTER)
            .context("physical range offset overflow")?;
        ensure!(
            offset
                .checked_add(CLUSTER)
                .is_some_and(|end| end <= volume_bytes),
            "physical range outside volume"
        );
        if let Some(last) = ranges
            .last_mut()
            .filter(|last| last.offset + last.length == offset)
        {
            last.length += CLUSTER;
        } else {
            ensure!(ranges.len() < MAX_RANGES, "physical range budget exceeded");
            ranges.push(ByteRange {
                offset,
                length: CLUSTER,
            });
        }
    }
    Ok(ranges)
}

fn anchors(geometry: &RefsGeometry, bootstrap: &BootstrapProbe) -> Result<BTreeSet<u64>> {
    let backup_probe_offset = geometry
        .volume_bytes
        .checked_sub(u64::from(geometry.bytes_per_sector))
        .context("backup header position underflow")?;
    let mut protected = BTreeSet::from([0, backup_probe_offset / CLUSTER]);
    for anchor in bootstrap.superblocks.iter().chain(&bootstrap.checkpoints) {
        let end = anchor
            .byte_offset
            .checked_add(anchor.bytes_read as u64)
            .context("anchor range overflow")?;
        ensure!(
            anchor.bytes_read > 0
                && anchor.byte_offset.is_multiple_of(CLUSTER)
                && end <= geometry.volume_bytes,
            "bootstrap anchor range outside volume"
        );
        protected.extend(anchor.byte_offset / CLUSTER..end.div_ceil(CLUSTER));
    }
    ensure!(
        protected.len() <= 64,
        "bootstrap anchor count exceeds bounded profile"
    );
    Ok(protected)
}

fn root_target(
    checkpoint: &AnchorProbe,
    bootstrap: &BootstrapProbe,
    index: usize,
) -> Result<ContainerRootTarget> {
    let fields = checkpoint
        .checkpoint
        .as_ref()
        .context("checkpoint fields absent")?;
    let descriptor = fields
        .roots
        .get(index)
        .context("physical root descriptor absent")?;
    let mut references = bootstrap
        .physical_root_references
        .iter()
        .filter(|r| r.checkpoint_lcn == checkpoint.lcn && r.root_index == index);
    let reference = references
        .next()
        .context("same-generation physical root observation absent")?;
    ensure!(
        references.next().is_none(),
        "same-generation physical root observation ambiguous"
    );
    ensure!(
        reference.rejection.is_none()
            && reference.checksum_matches == Some(true)
            && reference.header_matches == Some(true)
            && reference.table_id_matches == Some(true)
            && reference.lcn_slots == descriptor.lcn_slots,
        "same-generation physical root observation rejected or unbound"
    );
    let page = bootstrap
        .physical_root_pages
        .get(
            reference
                .page_index
                .context("physical root page index absent")?,
        )
        .context("physical root page absent")?;
    let signature = checkpoint
        .header
        .as_ref()
        .context("checkpoint header absent")?
        .volume_signature;
    let crc = reference_crc(descriptor)?;
    ensure!(
        page.lcn_slots == descriptor.lcn_slots
            && page.self_lcn_slots == descriptor.lcn_slots
            && page.signature_bytes_hex == "4d53422b"
            && page.header_version == 2
            && page.reserved_header == 0
            && page.volume_signature == signature
            && page.table_id_high == 0
            && page.node.is_some()
            && page.node_rejection.is_none()
            && reference.stored_crc64_nvme.as_deref() == Some(format!("{crc:016x}").as_str())
            && page.crc64_nvme == format!("{crc:016x}")
            && match index {
                7 | 8 => matches!(page.table_id_low, 11 | 12),
                12 => page.table_id_low == 34,
                _ => false,
            },
        "physical root identity, page profile or checkpoint CRC differs"
    );
    Ok(ContainerRootTarget {
        checkpoint_lcn: checkpoint.lcn,
        root_index: index,
        table_id: page.table_id_low,
        volume_signature: signature,
        lcn_slots: descriptor.lcn_slots,
        expected_crc64: crc,
        expected_sha256: page.sha256.clone(),
    })
}

struct PendingPhysical {
    slots: [u64; 4],
    crc: u64,
    expected_level: Option<u8>,
    depth: u8,
}

fn inspect_small<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    target: &ContainerRootTarget,
    blocked: &BTreeSet<u64>,
    budget: &mut PageBudget,
) -> Result<(PhysicalTreeFootprint, BTreeSet<u64>)> {
    let mut pending = vec![PendingPhysical {
        slots: target.lcn_slots,
        crc: target.expected_crc64,
        expected_level: None,
        depth: 0,
    }];
    let mut seen = BTreeSet::new();
    let mut transcript = Sha256::new();
    transcript.update(b"n2r-refs-physical-small-footprint-v1\0");
    transcript.update(target.checkpoint_lcn.to_le_bytes());
    let mut pages = 0u32;
    let mut leaves = 0u64;
    let mut expected_rows = None;
    while let Some(next) = pending.pop() {
        budget.charge(1)?;
        for (i, &lcn) in next.slots.iter().enumerate() {
            ensure!(
                lcn > 0
                    && lcn < geometry.volume_bytes / CLUSTER
                    && !next.slots[..i].contains(&lcn)
                    && !blocked.contains(&lcn)
                    && seen.insert(lcn),
                "Small page outside volume, cyclic, shared or overlaps same-generation bootstrap/container tree"
            );
        }
        let mut bytes = [0u8; PAGE];
        for (slot, lcn) in next.slots.iter().enumerate() {
            reader.seek(SeekFrom::Start(lcn * CLUSTER))?;
            reader.read_exact(&mut bytes[slot * 4096..(slot + 1) * 4096])?;
        }
        ensure!(
            crc64_nvme(&bytes) == next.crc
                && &bytes[..4] == b"MSB+"
                && u32le(&bytes, 4) == 2
                && u32le(&bytes, 8) == 0
                && u32le(&bytes, 12) == target.volume_signature
                && u64le(&bytes, 0x40) == 0
                && u64le(&bytes, 0x48) == 34
                && (0..4).all(|i| u64le(&bytes, 0x20 + i * 8) == next.slots[i]),
            "Small page CRC/header/table/physical self-location mismatch"
        );
        if next.depth == 0 {
            ensure!(
                hex::encode(Sha256::digest(bytes)) == target.expected_sha256,
                "Small root changed since bootstrap inspection"
            );
        }
        pages += 1;
        for lcn in next.slots {
            transcript.update(lcn.to_le_bytes());
        }
        transcript.update([next.depth]);
        transcript.update(bytes);
        let (level, index_node, rows) = if next.depth == 0 {
            let node = refs_node::inspect_root_node(&bytes)?;
            expected_rows = Some(node.whole_table_row_count);
            (node.node_level, node.index_node, node.rows)
        } else {
            let node = refs_node::inspect_child_node(&bytes)?;
            (node.node_level, node.index_node, node.rows)
        };
        ensure!(
            level <= 8
                && index_node == (level > 0)
                && next.expected_level.is_none_or(|expected| expected == level),
            "Small tree level or index form differs"
        );
        if index_node {
            ensure!(
                next.depth < 8
                    && !rows.is_empty()
                    && pending
                        .len()
                        .checked_add(rows.len())
                        .is_some_and(|count| count as u64 <= u64::from(budget.remaining())),
                "Small pending pages exceed shared page/depth budget"
            );
            for row in rows.iter().rev() {
                ensure!(
                    row.row_bytes_hex.len() <= PAGE * 2,
                    "Small index row exceeds page bound"
                );
                let row_bytes = hex::decode(&row.row_bytes_hex)?;
                ensure!(
                    row_bytes.len() == row.size as usize,
                    "Small index row length differs"
                );
                let start = usize::from(row.value_offset);
                let end = start
                    .checked_add(usize::from(row.value_length))
                    .context("Small child reference overflow")?;
                let value = row_bytes
                    .get(start..end)
                    .context("Small child reference outside row")?;
                ensure!(
                    value.len() == 48 && value[0x20..0x28] == [0, 0, 2, 8, 8, 0, 0, 0],
                    "unsupported Small child CRC64 reference"
                );
                pending.push(PendingPhysical {
                    slots: std::array::from_fn(|i| u64le(value, i * 8)),
                    crc: u64le(value, 0x28),
                    expected_level: Some(level - 1),
                    depth: next.depth + 1,
                });
            }
        } else {
            leaves = leaves
                .checked_add(rows.len() as u64)
                .context("Small leaf count overflow")?;
        }
    }
    let expected = expected_rows.context("Small root not visited")?;
    ensure!(
        leaves == expected,
        "Small leaf count differs from root descriptor"
    );
    let physical_ranges = cluster_ranges(&seen, geometry.volume_bytes)?;
    Ok((
        PhysicalTreeFootprint {
            root_index: 12,
            table_id: 34,
            pages_read: pages,
            leaf_rows: leaves,
            expected_leaf_rows: expected,
            physical_ranges,
            page_transcript_sha256: hex::encode(transcript.finalize()),
            index_descendants_complete: true,
            allocator_values_interpreted: false,
            complete_allocation_graph_verified: false,
        },
        seen,
    ))
}

/// Build a diagnostic union from bootstrap observations collected through this
/// same stable reader. Serialized reports grant no authority to skip reads or
/// write a device; all generation maps and referenced tree pages are freshly
/// checked below. Both generations consume one shared page budget.
pub fn inspect<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    bootstrap: &BootstrapProbe,
    max_pages: u32,
) -> Result<GenerationUnion> {
    ensure!(
        (10..=1_048_576).contains(&max_pages)
            && geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_cluster == 4096
            && geometry.volume_bytes.is_multiple_of(CLUSTER)
            && geometry.volume_bytes <= geometry.image_bytes
            && geometry.bytes_per_sector > 0
            && u64::from(geometry.bytes_per_sector) <= CLUSTER,
        "unsupported generation-union geometry/budget"
    );
    ensure!(
        bootstrap.vbr_checksum_matches && bootstrap.checkpoints.len() <= 2,
        "bootstrap checksum or checkpoint count differs"
    );
    let checksum_accepted: Vec<_> = bootstrap
        .checkpoints
        .iter()
        .filter(|cp| {
            cp.rejection.is_none()
                && !cp.referenced_by_superblock_lcns.is_empty()
                && cp.self_checksum.as_ref().is_some_and(|s| s.matches)
        })
        .collect();
    ensure!(
        !checksum_accepted.is_empty() && checksum_accepted.iter().all(|cp| valid_checkpoint(cp)),
        "no supported checkpoint or a checksum-accepted generation has an unsupported profile"
    );
    ensure!(
        bootstrap
            .physical_root_pages
            .iter()
            .all(|page| page.bytes_read == PAGE),
        "bootstrap physical-page read accounting differs"
    );
    let bootstrap_physical_page_reads = u32::try_from(bootstrap.physical_root_pages.len())
        .context("bootstrap page count overflow")?;
    let mut budget = PageBudget {
        limit: max_pages,
        used: 0,
    };
    budget.charge(bootstrap_physical_page_reads)?;
    let anchors = anchors(geometry, bootstrap)?;
    let anchor_ranges = cluster_ranges(&anchors, geometry.volume_bytes)?;
    let mut all_metadata = anchor_ranges.clone();
    let mut all_data = Vec::new();
    let mut generations = Vec::new();
    for checkpoint in checksum_accepted {
        let mut targets = Vec::new();
        let mut own_roots = BTreeSet::new();
        for index in [7, 8, 12] {
            let target = root_target(checkpoint, bootstrap, index)?;
            for &lcn in &target.lcn_slots {
                ensure!(
                    lcn > 0
                        && lcn < geometry.volume_bytes / CLUSTER
                        && !anchors.contains(&lcn)
                        && own_roots.insert(lcn),
                    "same-generation physical roots overlap or leave volume"
                );
            }
            targets.push(target);
        }
        let small_target = targets.pop().context("Small target absent")?;
        let mut container_protected = anchors.clone();
        container_protected.extend(own_roots);
        ensure!(
            budget.remaining() >= 2,
            "shared page budget cannot cover container roots"
        );
        let containers = refs_containers::inspect_container_tables(
            reader,
            geometry,
            &targets,
            &container_protected,
            ContainerLimits {
                max_pages_per_tree: budget.remaining().min(32),
                max_total_pages: budget.remaining().min(64),
                max_rows_per_tree: 4096,
                max_depth: 4,
            },
        )?;
        budget.charge(containers.pages_read)?;
        ensure!(
            containers.trees.len() == 2
                && containers
                    .trees
                    .iter()
                    .all(|tree| tree.checkpoint_lcn == checkpoint.lcn
                        && tree.walk_finished
                        && tree.rejection.is_none()
                        && tree.root_count_matches == Some(true)),
            "same-generation container traversal incomplete"
        );
        let mut physical = BTreeSet::new();
        for tree in &containers.trees {
            for page in &tree.pages {
                ensure!(
                    page.checksum_matches && page.header_matches && page.rejection.is_none(),
                    "container page authentication incomplete"
                );
                for lcn in page.lcn_slots {
                    ensure!(
                        !anchors.contains(&lcn)
                            && !small_target.lcn_slots.contains(&lcn)
                            && physical.insert(lcn),
                        "same-generation physical container pages overlap"
                    );
                }
            }
        }
        let mut small_blocked = anchors.clone();
        small_blocked.extend(physical.iter().copied());
        let (small, small_lcns) =
            inspect_small(reader, geometry, &small_target, &small_blocked, &mut budget)?;
        physical.extend(small_lcns);
        let mut virtual_protected = anchors.clone();
        virtual_protected.extend(physical.iter().copied());
        ensure!(
            budget.remaining() >= 10,
            "shared page budget cannot cover virtual system roots"
        );
        let virtual_trees = walk::inspect(
            reader,
            geometry,
            checkpoint,
            &containers,
            &virtual_protected,
            WalkLimits {
                max_pages: budget.remaining(),
                max_depth: 8,
            },
        )?;
        budget.charge(virtual_trees.budget_pages_charged)?;
        let mut metadata = cluster_ranges(&physical, geometry.volume_bytes)?;
        metadata.extend(virtual_trees.physical_ranges.iter().copied());
        // The circular log's storage is required even though only its control
        // blocks are read. A reached-page-only union would omit live log data.
        metadata.push(virtual_trees.log_storage.data_range);
        metadata.extend(virtual_trees.log_storage.control_ranges.iter().copied());
        let metadata = coalesce(metadata, geometry.volume_bytes)?;
        all_metadata.extend(metadata.iter().copied());
        all_data.extend(virtual_trees.data_storage.physical_ranges.iter().copied());
        generations.push(GenerationFootprint {
            checkpoint_lcn: checkpoint.lcn,
            checkpoint_clock: checkpoint
                .checkpoint
                .as_ref()
                .context("checkpoint fields absent")?
                .virtual_clock,
            checkpoint_sha256: checkpoint.sha256.clone(),
            physical_containers: containers,
            small_allocator_tree: small,
            virtual_trees,
            required_metadata_ranges: metadata,
        });
    }
    let required_metadata_ranges = coalesce(all_metadata, geometry.volume_bytes)?;
    let observed_data_ranges = coalesce(all_data, geometry.volume_bytes)?;
    let mut required = required_metadata_ranges.clone();
    required.extend(observed_data_ranges.iter().copied());
    let observed_required_ranges = coalesce(required, geometry.volume_bytes)?;
    Ok(GenerationUnion {
        profile: "refs-3.14-4k-crc64-per-generation-required-range-union-v1",
        max_page_reads: max_pages,
        bootstrap_physical_page_reads,
        budget_pages_charged: budget.used,
        page_budget_scope: "Shared across all generations: bootstrap physical pages, container/Small/virtual tree pages, and each charged MLog control read. Bootstrap anchor/header bytes are measured by the outer logical-read counter.",
        generations,
        bootstrap_protected_lcns: anchors,
        required_metadata_ranges,
        observed_data_ranges,
        observed_required_ranges,
        cross_generation_overlap_policy: "Authenticated generations have separate mappings and overlap checks; physical reuse between generations is coalesced without an ownership rejection.",
        scope: "Union of checked anchors, physical container/Small trees, virtual metadata and observed DATA extents only. Opaque leaf references, complete stream inventory and allocator/refcount ownership remain unproved. This is not a complete required-storage certificate.",
        complete_allocation_graph_verified: false,
        selective_capture_executable: false,
        conversion_authorized: false,
    })
}
