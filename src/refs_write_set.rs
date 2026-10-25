//! Candidate write set for replacing NTFS metadata with a native ReFS shadow.
//! The complement preserves old source bytes in ReFS-free regions. A native
//! allocator bitmap plus observed anchors is evidence, not write authority.
use crate::{
    refs_bootstrap::AnchorProbe,
    refs_inspect::{BackupHeaderStatus, RefsInspection},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::bitmap_layout::{AllocatedRange, AllocationMap};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Serialize)]
pub struct WriteSetPlan {
    pub profile: &'static str,
    pub partition_bytes: u64,
    pub cluster_bytes: u64,
    pub metadata_bitmap_sha256: String,
    pub bitmap_allocated_clusters: u64,
    pub anchor_ranges_supplied: usize,
    pub target_owned_ranges: Vec<ByteRange>,
    pub preserve_source_ranges: Vec<ByteRange>,
    pub target_owned_bytes: u64,
    pub preserve_source_bytes: u64,
    pub executable: bool,
    pub pending: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct PayloadCoverage {
    pub supplied_ranges: usize,
    pub payload_bytes: u64,
    pub uncovered_bytes: u64,
    pub all_supplied_payloads_covered: bool,
    pub complete_payload_inventory_verified: bool,
    pub executable: bool,
}

/// Cross-check explicit, measured target retrieval extents against a candidate
/// write set. The caller cannot establish inventory completeness through this
/// range list, and a successful check grants no authority to omit other bytes.
pub fn payload_coverage(plan: &WriteSetPlan, payloads: &[ByteRange]) -> Result<PayloadCoverage> {
    ensure!(
        plan.cluster_bytes == 4096
            && plan.partition_bytes > 0
            && payloads.len() <= 65536
            && plan.target_owned_ranges.len() <= 65536,
        "target payload range geometry or budget differs"
    );
    let mut owned_end = 0u64;
    for owned in &plan.target_owned_ranges {
        let end = owned
            .offset
            .checked_add(owned.length)
            .context("owned range overflow")?;
        ensure!(
            owned.length > 0
                && owned.offset >= owned_end
                && owned.offset.is_multiple_of(plan.cluster_bytes)
                && owned.length.is_multiple_of(plan.cluster_bytes)
                && end <= plan.partition_bytes,
            "candidate owned ranges overlap, are unaligned or leave partition"
        );
        owned_end = end;
    }
    let mut sorted = payloads.to_vec();
    sorted.sort_by_key(|range| range.offset);
    let (mut previous, mut payload_bytes, mut covered_bytes) = (0u64, 0u64, 0u64);
    let mut owned_index = 0;
    for range in &sorted {
        let end = range
            .offset
            .checked_add(range.length)
            .context("target payload range overflow")?;
        ensure!(
            range.length > 0
                && range.offset >= previous
                && range.offset.is_multiple_of(plan.cluster_bytes)
                && range.length.is_multiple_of(plan.cluster_bytes)
                && end <= plan.partition_bytes,
            "target payloads overlap, are unaligned or leave partition"
        );
        previous = end;
        payload_bytes = payload_bytes
            .checked_add(range.length)
            .context("target payload bytes overflow")?;
        while owned_index < plan.target_owned_ranges.len()
            && plan.target_owned_ranges[owned_index].offset
                + plan.target_owned_ranges[owned_index].length
                <= range.offset
        {
            owned_index += 1;
        }
        for owned in &plan.target_owned_ranges[owned_index..] {
            if owned.offset >= end {
                break;
            }
            let owned_end = owned.offset + owned.length;
            let start = range.offset.max(owned.offset);
            let finish = end.min(owned_end);
            if start < finish {
                covered_bytes = covered_bytes
                    .checked_add(finish - start)
                    .context("target payload coverage overflow")?;
            }
        }
    }
    let uncovered_bytes = payload_bytes
        .checked_sub(covered_bytes)
        .context("candidate owned ranges overlap")?;
    Ok(PayloadCoverage {
        supplied_ranges: payloads.len(),
        payload_bytes,
        uncovered_bytes,
        all_supplied_payloads_covered: uncovered_bytes == 0,
        complete_payload_inventory_verified: false,
        executable: false,
    })
}

fn checked_anchor(anchor: &AnchorProbe, kind: &str, bytes: usize, volume: u64) -> Result<()> {
    ensure!(
        anchor.kind == kind
            && anchor.rejection.is_none()
            && anchor.bytes_read == bytes
            && anchor.lcn.checked_mul(4096) == Some(anchor.byte_offset)
            && anchor
                .byte_offset
                .checked_add(bytes as u64)
                .is_some_and(|end| end <= volume)
            && anchor.self_checksum.as_ref().is_some_and(|checksum| {
                checksum.matches
                    && checksum.stored == checksum.computed
                    && checksum.coverage_bytes == 4096
            })
            && anchor.header.as_ref().is_some_and(|header| {
                header.signature == kind && header.lcn_slots == [anchor.lcn, 0, 0, 0]
            }),
        "unverified, mislocated or incomplete ReFS {kind} anchor"
    );
    Ok(())
}

/// Known authenticated pages, rather than a complete reachable-metadata graph.
/// Rejected observations are errors: their locations cannot silently vanish
/// from a candidate copied set merely because their bytes failed validation.
pub fn observed_anchors(header: &RefsInspection) -> Result<Vec<ByteRange>> {
    let g = &header.geometry;
    ensure!(
        g.major_version == 3
            && g.minor_version == 14
            && g.bytes_per_sector == 512
            && g.bytes_per_cluster == 4096
            && g.volume_bytes >= 64 * 4096
            && g.volume_bytes.is_multiple_of(4096)
            && header.backup_header_status == BackupHeaderStatus::Matching,
        "unsupported ReFS anchor profile"
    );
    let bootstrap = header.bootstrap.as_ref().context("ReFS bootstrap absent")?;
    ensure!(
        bootstrap.vbr_checksum_matches
            && bootstrap.superblocks.len() == 3
            && bootstrap.checkpoints.len() == 2,
        "ReFS anchors incomplete or VBR checksum differs"
    );
    let cluster = u64::from(g.bytes_per_cluster);
    let mut anchors = vec![
        ByteRange {
            offset: 0,
            length: cluster,
        },
        ByteRange {
            offset: g.volume_bytes - cluster,
            length: cluster,
        },
    ];
    let expected_superblocks = BTreeSet::from([
        30,
        g.volume_bytes / cluster - 2,
        g.volume_bytes / cluster - 3,
    ]);
    ensure!(
        bootstrap
            .superblocks
            .iter()
            .map(|anchor| anchor.lcn)
            .collect::<BTreeSet<_>>()
            == expected_superblocks,
        "ReFS superblock locations differ from the bounded profile"
    );
    let checkpoints = bootstrap
        .checkpoints
        .iter()
        .map(|anchor| anchor.lcn)
        .collect::<BTreeSet<_>>();
    ensure!(checkpoints.len() == 2, "duplicate ReFS checkpoint location");
    for anchor in &bootstrap.superblocks {
        checked_anchor(anchor, "SUPB", 4096, g.volume_bytes)?;
        let fields = anchor
            .superblock
            .as_ref()
            .context("superblock fields absent")?;
        ensure!(
            fields.checkpoint_lcns.into_iter().collect::<BTreeSet<_>>() == checkpoints,
            "ReFS superblocks disagree on checkpoint locations"
        );
    }
    for anchor in &bootstrap.checkpoints {
        checked_anchor(anchor, "CHKP", 16384, g.volume_bytes)?;
        let fields = anchor
            .checkpoint
            .as_ref()
            .context("checkpoint fields absent")?;
        ensure!(
            fields.major_version == 3
                && fields.minor_version == 14
                && fields.reference_size == 48
                && fields.roots.len() == 13
                && fields.header_clock_matches,
            "ReFS checkpoint profile or clock differs"
        );
    }
    for anchor in bootstrap.superblocks.iter().chain(&bootstrap.checkpoints) {
        anchors.push(ByteRange {
            offset: anchor.byte_offset,
            length: u64::try_from(anchor.bytes_read)?,
        });
    }
    ensure!(
        bootstrap.physical_root_pages.len() <= 6
            && bootstrap.physical_root_references.len() <= 6
            && bootstrap.physical_root_references.iter().all(|reference| {
                checkpoints.contains(&reference.checkpoint_lcn)
                    && matches!(reference.root_index, 7 | 8 | 12)
                    && reference.rejection.is_none()
                    && reference.checksum_matches == Some(true)
                    && reference.header_matches == Some(true)
                    && reference.table_id_matches == Some(true)
                    && reference.page_index.is_some_and(|index| {
                        bootstrap
                            .physical_root_pages
                            .get(index)
                            .is_some_and(|page| page.lcn_slots == reference.lcn_slots)
                    })
            }),
        "physical-root page budget or reference validation differs"
    );
    for (index, page) in bootstrap.physical_root_pages.iter().enumerate() {
        ensure!(
            page.bytes_read == 16384
                && bootstrap.physical_root_references.iter().any(|reference| {
                    checkpoints.contains(&reference.checkpoint_lcn)
                        && reference.page_index == Some(index)
                        && reference.lcn_slots == page.lcn_slots
                        && reference.rejection.is_none()
                        && reference.checksum_matches == Some(true)
                        && reference.header_matches == Some(true)
                        && reference.table_id_matches == Some(true)
                })
                && page.byte_offsets == page.lcn_slots.map(|lcn| lcn.saturating_mul(cluster)),
            "physical-root page lacks a checked checkpoint reference"
        );
        for &offset in &page.byte_offsets {
            anchors.push(ByteRange {
                offset,
                length: cluster,
            });
        }
    }
    if let Some(containers) = &bootstrap.container_tables {
        ensure!(
            containers.trees.len() <= 4,
            "container-tree budget exceeded"
        );
        for tree in &containers.trees {
            ensure!(
                checkpoints.contains(&tree.checkpoint_lcn)
                    && tree.walk_finished
                    && tree.rejection.is_none()
                    && tree.root_count_matches == Some(true)
                    && tree.pages.len() <= 32,
                "container tree is incomplete or rejected"
            );
            for page in &tree.pages {
                ensure!(
                    page.checksum_matches && page.header_matches && page.rejection.is_none(),
                    "container page is rejected"
                );
                for lcn in page.lcn_slots {
                    anchors.push(ByteRange {
                        offset: lcn
                            .checked_mul(cluster)
                            .context("container page offset overflow")?,
                        length: cluster,
                    });
                }
            }
        }
    }
    if let Some(virtual_roots) = &bootstrap.virtual_roots {
        ensure!(
            virtual_roots.roots.len() <= 20,
            "virtual-root budget exceeded"
        );
        for root in &virtual_roots.roots {
            ensure!(
                checkpoints.contains(&root.checkpoint_lcn)
                    && root.bytes_read == 16384
                    && root.rejection.is_none()
                    && root.checksum_matches == Some(true)
                    && root.header_matches == Some(true)
                    && root.self_virtual_slots_match == Some(true)
                    && root.table_id_matches == Some(true),
                "virtual-root page is incomplete or rejected"
            );
            for lcn in root
                .physical_lcn_slots
                .context("virtual-root physical slots absent")?
            {
                anchors.push(ByteRange {
                    offset: lcn
                        .checked_mul(cluster)
                        .context("virtual-root offset overflow")?,
                    length: cluster,
                });
            }
        }
    }
    // Validate every collected page here, including noncontiguous page slots.
    for range in &anchors {
        ensure!(
            range.length > 0
                && range.offset.is_multiple_of(cluster)
                && range.length.is_multiple_of(cluster)
                && range
                    .offset
                    .checked_add(range.length)
                    .is_some_and(|end| end <= g.volume_bytes),
            "observed ReFS page lies outside the bounded partition"
        );
    }
    Ok(anchors)
}

pub fn plan(
    partition_bytes: u64,
    cluster_bytes: u64,
    allocation: &AllocationMap,
    anchors: &[ByteRange],
) -> Result<WriteSetPlan> {
    ensure!(
        cluster_bytes == 4096
            && partition_bytes >= 64 * cluster_bytes
            && partition_bytes.is_multiple_of(cluster_bytes)
            && allocation.cluster_count.checked_mul(cluster_bytes) == Some(partition_bytes),
        "unsupported write-set geometry or bitmap coverage"
    );
    let mut previous = 0u64;
    let mut bitmap_count = 0u64;
    let mut ranges = Vec::new();
    for AllocatedRange { offset, length } in &allocation.ranges {
        let end = offset
            .checked_add(*length)
            .context("bitmap interval overflow")?;
        ensure!(
            *length > 0
                && *offset >= previous
                && offset.is_multiple_of(cluster_bytes)
                && length.is_multiple_of(cluster_bytes)
                && end <= partition_bytes,
            "bitmap intervals overlap, are unaligned or leave volume"
        );
        bitmap_count += length / cluster_bytes;
        ranges.push(ByteRange {
            offset: *offset,
            length: *length,
        });
        previous = end;
    }
    ensure!(
        bitmap_count == allocation.allocated_clusters,
        "bitmap interval and allocated-count totals differ"
    );
    for anchor in anchors {
        let end = anchor
            .offset
            .checked_add(anchor.length)
            .context("anchor overflow")?;
        ensure!(
            anchor.length > 0
                && anchor.offset.is_multiple_of(cluster_bytes)
                && anchor.length.is_multiple_of(cluster_bytes)
                && end <= partition_bytes,
            "anchor range unaligned or outside partition"
        );
        ranges.push(*anchor);
    }
    ensure!(
        ranges.len() <= 131072,
        "candidate write-set range budget exceeded"
    );
    ranges.sort_by_key(|range| range.offset);
    let mut owned: Vec<ByteRange> = Vec::new();
    for range in ranges {
        let end = range.offset + range.length;
        if let Some(last) = owned.last_mut()
            && range.offset <= last.offset + last.length
        {
            last.length = end.max(last.offset + last.length) - last.offset;
        } else {
            owned.push(range);
        }
    }
    ensure!(
        owned.len() <= 65536,
        "coalesced write-set range budget exceeded"
    );
    let mut preserved = Vec::new();
    let mut cursor = 0u64;
    for range in &owned {
        if cursor < range.offset {
            preserved.push(ByteRange {
                offset: cursor,
                length: range.offset - cursor,
            });
        }
        cursor = range.offset + range.length;
    }
    if cursor < partition_bytes {
        preserved.push(ByteRange {
            offset: cursor,
            length: partition_bytes - cursor,
        });
    }
    let owned_bytes = owned.iter().try_fold(0u64, |sum, r| {
        sum.checked_add(r.length).context("owned bytes overflow")
    })?;
    let preserved_bytes = preserved.iter().try_fold(0u64, |sum, r| {
        sum.checked_add(r.length)
            .context("preserved bytes overflow")
    })?;
    ensure!(
        owned_bytes.checked_add(preserved_bytes) == Some(partition_bytes),
        "target write set does not partition volume"
    );
    Ok(WriteSetPlan {
        profile: "refs-metadata-inclusive-write-set-candidate-v1",
        partition_bytes,
        cluster_bytes,
        metadata_bitmap_sha256: allocation.bitmap_sha256.clone(),
        bitmap_allocated_clusters: allocation.allocated_clusters,
        anchor_ranges_supplied: anchors.len(),
        target_owned_ranges: owned,
        preserve_source_ranges: preserved,
        target_owned_bytes: owned_bytes,
        preserve_source_bytes: preserved_bytes,
        executable: false,
        pending: vec![
            "independent ReFS graph and allocator ownership proof",
            "proof every target-required bootstrap sector is in the write set",
            "journaled hybrid-image construction and native Windows mutation testing",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_extend_bitmap_and_free_complement_is_exact() {
        let map = AllocationMap {
            bitmap_sha256: "a".repeat(64),
            cluster_count: 64,
            allocated_clusters: 2,
            ranges: vec![AllocatedRange {
                offset: 20 * 4096,
                length: 2 * 4096,
            }],
        };
        let anchors = [
            ByteRange {
                offset: 0,
                length: 4096,
            },
            ByteRange {
                offset: 21 * 4096,
                length: 4096,
            },
            ByteRange {
                offset: 63 * 4096,
                length: 4096,
            },
        ];
        let p = plan(64 * 4096, 4096, &map, &anchors).unwrap();
        assert_eq!(p.target_owned_bytes, 4 * 4096);
        assert_eq!(p.preserve_source_bytes, 60 * 4096);
        assert_eq!(p.target_owned_ranges.len(), 3);
        assert_eq!(p.preserve_source_ranges.len(), 2);
    }

    #[test]
    fn incomplete_or_conflicting_bitmap_is_refused() {
        let map = AllocationMap {
            bitmap_sha256: "a".repeat(64),
            cluster_count: 64,
            allocated_clusters: 3,
            ranges: vec![AllocatedRange {
                offset: 20 * 4096,
                length: 2 * 4096,
            }],
        };
        assert!(plan(64 * 4096, 4096, &map, &[]).is_err());
        let map = AllocationMap {
            allocated_clusters: 2,
            ..map
        };
        assert!(plan(65 * 4096, 4096, &map, &[]).is_err());
    }
}
