//! Bounded checkpoint-root translation, never an allocation certificate.
//!
//! Research formula: container = VLCN >> 15, offset = VLCN & 0x3fff;
//! bit 14 must be zero. Exact 3.14 / 4 KiB / CRC64 profile only.
//! https://xbpt.gitlab.io/forefst/structures/container_table/
//! https://xbpt.gitlab.io/forefst/structures/chkp/
use crate::{
    refs_bootstrap::{AnchorProbe, RootReference, crc64_nvme},
    refs_containers::{ContainerMapping, ContainerTablesProbe, ContainerTreeObservation},
    refs_inspect::RefsGeometry,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
};
const PAGE: usize = 16384;
const CLUSTER: u64 = 4096;
const CPC: u64 = 16384;
const ROOTS: [(usize, u64); 10] = [
    (0, 2),
    (1, 0x21),
    (2, 0x20),
    (3, 1),
    (4, 3),
    (5, 4),
    (6, 5),
    (9, 6),
    (10, 0xe),
    (11, 0xf),
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VirtualRootLimits {
    /// Hard maximum 20: ten roots per checkpoint, at most two checkpoints.
    pub max_page_reads: u32,
}
impl Default for VirtualRootLimits {
    fn default() -> Self {
        Self { max_page_reads: 20 }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualRootsProbe {
    pub profile: String,
    pub limits: VirtualRootLimits,
    pub pages_read: u32,
    pub bytes_read: u64,
    /// No page cache is used: each candidate gets its own bounded read.
    pub reused_page_reads: u32,
    /// Exact physical slot quadruples previously read for another checkpoint.
    pub repeated_physical_page_reads: u32,
    pub checkpoint_maps: Vec<VirtualMapBinding>,
    pub roots: Vec<VirtualRootObservation>,
    pub children_traversed: bool,
    pub authoritative_checkpoint_selected: bool,
    pub metadata_verified: bool,
    pub allocation_verified: bool,
    pub conversion_profile_qualified: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualMapBinding {
    pub checkpoint_lcn: u64,
    pub checkpoint_sha256: String,
    pub container_root_indices: [usize; 2],
    pub container_table_ids: Option<[u64; 2]>,
    pub mapping_rows: Option<usize>,
    /// SHA-256 of sorted ID/physical-start/CPC/raw-value bytes from both copies.
    pub common_mapping_sha256: Option<String>,
    pub both_complete_count_matching_maps_agree: bool,
    pub rejection: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualSlotTranslation {
    pub virtual_lcn: u64,
    pub container_id: u64,
    pub offset_in_container: u64,
    pub physical_lcn: u64,
    pub source_mapping_row_indices: [usize; 2],
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualRootObservation {
    pub checkpoint_lcn: u64,
    pub root_index: usize,
    pub expected_table_id: u64,
    pub descriptor_sha256: String,
    pub virtual_lcn_slots: [u64; 4],
    pub translations: Vec<VirtualSlotTranslation>,
    pub physical_lcn_slots: Option<[u64; 4]>,
    pub bytes_read: usize,
    pub repeated_physical_page_read: bool,
    pub sha256: Option<String>,
    pub stored_crc64_nvme: Option<String>,
    pub computed_crc64_nvme: Option<String>,
    pub checksum_matches: Option<bool>,
    pub header_matches: Option<bool>,
    pub self_virtual_slots_match: Option<bool>,
    pub table_id_matches: Option<bool>,
    pub observed_table_id: Option<[u64; 2]>,
    pub rejection: Option<String>,
}
fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded page field"))
}
fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded page field"))
}
fn reference_crc(reference: &RootReference) -> Result<u64> {
    ensure!(
        reference.flags == 0
            && reference.checksum_type == 2
            && reference.checksum_data_offset == 8
            && reference.checksum_data_length == 8,
        "unsupported virtual-root checksum descriptor"
    );
    ensure!(
        reference.stored_checksum_bytes_hex.len() == 16,
        "virtual-root checksum length differs"
    );
    let bytes: [u8; 8] = hex::decode(&reference.stored_checksum_bytes_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("CRC length differs"))?;
    Ok(u64::from_le_bytes(bytes))
}
fn validate_map(
    tree: &ContainerTreeObservation,
    checkpoint: &AnchorProbe,
    volume_clusters: u64,
) -> Result<()> {
    ensure!(
        tree.walk_finished && tree.rejection.is_none() && tree.root_count_matches == Some(true),
        "container walk or root count is not qualified for translation"
    );
    ensure!(
        !tree.mappings.is_empty()
            && tree.mappings.len() <= 4096
            && tree.expected_root_rows == Some(tree.mappings.len() as u64),
        "container row count differs or exceeds bound"
    );
    ensure!(
        !tree.pages.is_empty() && tree.pages.len() <= 32,
        "container page proof count exceeds bound"
    );
    ensure!(
        tree.pages
            .iter()
            .all(|p| p.checksum_matches && p.header_matches && p.rejection.is_none()),
        "container page has an unresolved checksum/header"
    );
    let reference = &checkpoint
        .checkpoint
        .as_ref()
        .context("missing checkpoint fields")?
        .roots[tree.root_index];
    ensure!(
        reference.lcn_slots == tree.root_lcn_slots
            && tree.pages[0].lcn_slots == tree.root_lcn_slots
            && tree.pages[0].depth == 0,
        "container root is not bound to this checkpoint descriptor"
    );
    let crc = format!("{:016x}", reference_crc(reference)?);
    ensure!(
        tree.pages[0].stored_crc64 == crc && tree.pages[0].computed_crc64 == crc,
        "container root CRC differs from checkpoint reference"
    );
    let mut previous_id = None;
    let mut physical = BTreeSet::new();
    for mapping in &tree.mappings {
        ensure!(
            mapping.container_id >= 2 && previous_id.is_none_or(|id| id < mapping.container_id),
            "container IDs are duplicated, unsorted or reserved"
        );
        previous_id = Some(mapping.container_id);
        ensure!(
            mapping.clusters_per_container == CPC as u32,
            "container cluster unit differs"
        );
        ensure!(
            mapping
                .physical_start_lcn
                .checked_add(CPC)
                .is_some_and(|end| end <= volume_clusters),
            "container physical range exceeds volume"
        );
        ensure!(
            mapping.value_bytes_hex.len() == 320
                && hex::decode(&mapping.value_bytes_hex)?.len() == 160,
            "container raw value length differs"
        );
        ensure!(
            physical.insert(mapping.physical_start_lcn),
            "duplicate container physical start"
        );
    }
    let mut previous_end = None;
    for start in physical {
        ensure!(
            previous_end.is_none_or(|end| end <= start),
            "container physical ranges overlap"
        );
        previous_end = Some(start + CPC);
    }
    Ok(())
}
type CommonMap<'a> = BTreeMap<u64, (&'a ContainerMapping, [usize; 2])>;
fn common_map<'a>(
    checkpoint: &AnchorProbe,
    containers: &'a ContainerTablesProbe,
    volume_clusters: u64,
    binding: &mut VirtualMapBinding,
) -> Result<CommonMap<'a>> {
    ensure!(
        checkpoint.kind == "CHKP"
            && checkpoint.rejection.is_none()
            && checkpoint.self_checksum.as_ref().is_some_and(|c| c.matches),
        "checkpoint candidate is not checksum/structure accepted"
    );
    let fields = checkpoint
        .checkpoint
        .as_ref()
        .context("missing checkpoint fields")?;
    let header = checkpoint
        .header
        .as_ref()
        .context("missing checkpoint header")?;
    ensure!(
        header.signature == "CHKP"
            && header.version == 2
            && header.lcn_slots[0] == checkpoint.lcn
            && fields.major_version == 3
            && fields.minor_version == 14
            && fields.reference_size == 48
            && fields.header_clock_matches,
        "unsupported checkpoint profile"
    );
    ensure!(
        fields.roots.len() == 13 && fields.roots.iter().enumerate().all(|(i, r)| r.index == i),
        "checkpoint root list is not thirteen distinct ordered descriptors"
    );
    let trees: Vec<_> = containers
        .trees
        .iter()
        .filter(|t| t.checkpoint_lcn == checkpoint.lcn)
        .collect();
    ensure!(
        trees.len() == 2,
        "checkpoint lacks exactly two container maps"
    );
    let first = trees
        .iter()
        .copied()
        .find(|t| t.root_index == 7)
        .context("missing root-seven container map")?;
    let second = trees
        .iter()
        .copied()
        .find(|t| t.root_index == 8)
        .context("missing root-eight container map")?;
    ensure!(
        [first.table_id, second.table_id]
            .into_iter()
            .collect::<BTreeSet<_>>()
            == BTreeSet::from([11, 12]),
        "container failover table identities differ"
    );
    validate_map(first, checkpoint, volume_clusters)?;
    validate_map(second, checkpoint, volume_clusters)?;
    ensure!(
        first.mappings.len() == second.mappings.len(),
        "container failover row counts differ"
    );
    let mut result = BTreeMap::new();
    let mut hash = Sha256::new();
    for (i, (a, b)) in first.mappings.iter().zip(&second.mappings).enumerate() {
        ensure!(
            a.container_id == b.container_id
                && a.physical_start_lcn == b.physical_start_lcn
                && a.clusters_per_container == b.clusters_per_container
                && a.value_bytes_hex == b.value_bytes_hex,
            "container failover mappings or raw values differ"
        );
        hash.update(a.container_id.to_le_bytes());
        hash.update(a.physical_start_lcn.to_le_bytes());
        hash.update(a.clusters_per_container.to_le_bytes());
        hash.update(hex::decode(&a.value_bytes_hex)?);
        result.insert(a.container_id, (a, [i, i]));
    }
    binding.container_table_ids = Some([first.table_id, second.table_id]);
    binding.mapping_rows = Some(result.len());
    binding.common_mapping_sha256 = Some(hex::encode(hash.finalize()));
    binding.both_complete_count_matching_maps_agree = true;
    Ok(result)
}
fn translate(
    reference: &RootReference,
    map: &CommonMap<'_>,
    volume_clusters: u64,
    protected: &BTreeSet<u64>,
    visited: &BTreeSet<u64>,
) -> Result<([u64; 4], Vec<VirtualSlotTranslation>)> {
    let mut physical = [0; 4];
    let mut translations = Vec::new();
    for (slot, virtual_lcn) in reference.lcn_slots.iter().copied().enumerate() {
        ensure!(
            virtual_lcn != 0
                && virtual_lcn & 0x4000 == 0
                && !reference.lcn_slots[..slot].contains(&virtual_lcn),
            "zero, duplicate or reserved-bit virtual address"
        );
        let id = virtual_lcn >> 15;
        let offset = virtual_lcn & 0x3fff;
        let (mapping, rows) = map
            .get(&id)
            .context("virtual root names an absent container")?;
        let lcn = mapping
            .physical_start_lcn
            .checked_add(offset)
            .context("translated address overflow")?;
        ensure!(lcn < volume_clusters, "translated root lies outside volume");
        ensure!(
            !physical[..slot].contains(&lcn) && !visited.contains(&lcn),
            "virtual root aliases or overlaps another root in this checkpoint"
        );
        ensure!(
            !protected.contains(&lcn),
            "virtual root overlaps bootstrap or container metadata"
        );
        physical[slot] = lcn;
        translations.push(VirtualSlotTranslation {
            virtual_lcn,
            container_id: id,
            offset_in_container: offset,
            physical_lcn: lcn,
            source_mapping_row_indices: *rows,
        });
    }
    Ok((physical, translations))
}
/// Inputs must be bootstrap/container observations from this same stable read-only
/// handle. Internal binding checks do not authenticate an external serialized
/// report. No descendants are followed and no checkpoint is selected.
pub fn inspect_virtual_roots<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    checkpoints: &[AnchorProbe],
    containers: &ContainerTablesProbe,
    protected_lcns: &BTreeSet<u64>,
    limits: VirtualRootLimits,
) -> Result<VirtualRootsProbe> {
    ensure!(
        geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_cluster == CLUSTER as u32
            && geometry.volume_bytes.is_multiple_of(CLUSTER)
            && geometry.volume_bytes <= geometry.image_bytes,
        "unsupported virtual-root geometry"
    );
    ensure!(
        (1..=20).contains(&limits.max_page_reads),
        "virtual-root page budget must be between one and twenty"
    );
    ensure!(
        checkpoints.len() <= 2
            && checkpoints
                .iter()
                .map(|c| c.lcn)
                .collect::<BTreeSet<_>>()
                .len()
                == checkpoints.len(),
        "ambiguous or excessive checkpoint candidates"
    );
    ensure!(
        containers.trees.len() <= 4
            && containers
                .trees
                .iter()
                .map(|t| t.pages.len())
                .sum::<usize>()
                <= 128,
        "container proof exceeds the reader profile"
    );
    let mut protected = protected_lcns.clone();
    for tree in &containers.trees {
        for page in &tree.pages {
            protected.extend(page.lcn_slots);
        }
    }
    let mut result = VirtualRootsProbe {
        profile: "candidate ReFS 3.14 / 4 KiB / CRC64 checkpoint virtual roots".into(),
        limits,
        pages_read: 0,
        bytes_read: 0,
        reused_page_reads: 0,
        repeated_physical_page_reads: 0,
        checkpoint_maps: Vec::new(),
        roots: Vec::new(),
        children_traversed: false,
        authoritative_checkpoint_selected: false,
        metadata_verified: false,
        allocation_verified: false,
        conversion_profile_qualified: false,
    };
    let mut previously_read = BTreeSet::new();
    for checkpoint in checkpoints {
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
        let map = match common_map(
            checkpoint,
            containers,
            geometry.volume_bytes / CLUSTER,
            &mut binding,
        ) {
            Ok(map) => map,
            Err(error) => {
                binding.rejection = Some(error.to_string());
                result.checkpoint_maps.push(binding);
                continue;
            }
        };
        result.checkpoint_maps.push(binding);
        let fields = checkpoint
            .checkpoint
            .as_ref()
            .expect("validated checkpoint");
        let header = checkpoint.header.as_ref().expect("validated header");
        let mut visited = BTreeSet::new();
        for (index, table) in ROOTS {
            let reference = &fields.roots[index];
            let mut observation = VirtualRootObservation {
                checkpoint_lcn: checkpoint.lcn,
                root_index: index,
                expected_table_id: table,
                descriptor_sha256: reference.descriptor_sha256.clone(),
                virtual_lcn_slots: reference.lcn_slots,
                translations: Vec::new(),
                physical_lcn_slots: None,
                bytes_read: 0,
                repeated_physical_page_read: false,
                sha256: None,
                stored_crc64_nvme: None,
                computed_crc64_nvme: None,
                checksum_matches: None,
                header_matches: None,
                self_virtual_slots_match: None,
                table_id_matches: None,
                observed_table_id: None,
                rejection: None,
            };
            let prepared = (|| -> Result<([u64; 4], u64)> {
                let expected = reference_crc(reference)?;
                observation.stored_crc64_nvme = Some(format!("{expected:016x}"));
                ensure!(
                    result.pages_read < limits.max_page_reads,
                    "virtual-root page-read budget exhausted"
                );
                let (physical, translations) = translate(
                    reference,
                    &map,
                    geometry.volume_bytes / CLUSTER,
                    &protected,
                    &visited,
                )?;
                observation.physical_lcn_slots = Some(physical);
                observation.translations = translations;
                Ok((physical, expected))
            })();
            let (physical, expected) = match prepared {
                Ok(value) => value,
                Err(error) => {
                    observation.rejection = Some(error.to_string());
                    result.roots.push(observation);
                    continue;
                }
            };
            visited.extend(physical);
            observation.repeated_physical_page_read = !previously_read.insert(physical);
            if observation.repeated_physical_page_read {
                result.repeated_physical_page_reads += 1;
            }
            let mut bytes = [0; PAGE];
            for (slot, lcn) in physical.iter().enumerate() {
                reader
                    .seek(SeekFrom::Start(lcn * CLUSTER))
                    .context("seek translated virtual-root cluster")?;
                reader
                    .read_exact(&mut bytes[slot * 4096..(slot + 1) * 4096])
                    .context("read translated virtual-root cluster")?;
            }
            result.pages_read += 1;
            result.bytes_read += PAGE as u64;
            observation.bytes_read = PAGE;
            observation.sha256 = Some(hex::encode(Sha256::digest(bytes)));
            let crc = crc64_nvme(&bytes);
            let ids = [u64le(&bytes, 0x40), u64le(&bytes, 0x48)];
            observation.computed_crc64_nvme = Some(format!("{crc:016x}"));
            observation.checksum_matches = Some(crc == expected);
            observation.header_matches = Some(
                &bytes[..4] == b"MSB+"
                    && u32le(&bytes, 4) == 2
                    && u32le(&bytes, 8) == 0
                    && u32le(&bytes, 12) == header.volume_signature,
            );
            observation.self_virtual_slots_match = Some(
                std::array::from_fn::<_, 4, _>(|slot| u64le(&bytes, 0x20 + slot * 8))
                    == reference.lcn_slots,
            );
            observation.table_id_matches = Some(ids == [0, table]);
            observation.observed_table_id = Some(ids);
            if observation.checksum_matches != Some(true)
                || observation.header_matches != Some(true)
                || observation.self_virtual_slots_match != Some(true)
                || observation.table_id_matches != Some(true)
            {
                observation.rejection = Some(
                    "translated root checksum/header/self-virtual-address/table mismatch".into(),
                );
            }
            result.roots.push(observation);
        }
    }
    Ok(result)
}
