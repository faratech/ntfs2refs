//! Candidate write set for replacing NTFS metadata with a native ReFS shadow.
//! The complement preserves old source bytes in ReFS-free regions. A native
//! allocator bitmap plus observed anchors is evidence, not write authority.
use crate::refs_inspect::{BackupHeaderStatus, RefsInspection};
use anyhow::{Context, Result, ensure};
use n2r_win32::bitmap_layout::{AllocatedRange, AllocationMap};
use serde::Serialize;

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

pub fn observed_anchors(header: &RefsInspection) -> Result<Vec<ByteRange>> {
    let g = &header.geometry;
    ensure!(
        g.major_version == 3
            && g.minor_version == 14
            && g.bytes_per_cluster == 4096
            && g.volume_bytes >= 64 * 4096
            && g.volume_bytes.is_multiple_of(4096)
            && header.backup_header_status == BackupHeaderStatus::Matching,
        "unsupported ReFS anchor profile"
    );
    let bootstrap = header.bootstrap.as_ref().context("ReFS bootstrap absent")?;
    ensure!(
        bootstrap.vbr_checksum_matches
            && bootstrap.superblocks.len() >= 3
            && bootstrap.checkpoints.len() >= 2,
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
    for anchor in bootstrap.superblocks.iter().chain(&bootstrap.checkpoints) {
        ensure!(
            anchor.rejection.is_none() && anchor.bytes_read > 0,
            "rejected or unread ReFS anchor"
        );
        anchors.push(ByteRange {
            offset: anchor.byte_offset,
            length: u64::try_from(anchor.bytes_read)?,
        });
    }
    for page in &bootstrap.physical_root_pages {
        for &offset in &page.byte_offsets {
            anchors.push(ByteRange {
                offset,
                length: cluster,
            });
        }
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
