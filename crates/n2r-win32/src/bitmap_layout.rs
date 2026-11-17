//! Bounded candidate occupancy in legacy or metadata-inclusive native bitmaps.
//! This is not a whole-volume ownership proof.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllocatedRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationMap {
    pub bitmap_sha256: String,
    pub cluster_count: u64,
    pub allocated_clusters: u64,
    pub ranges: Vec<AllocatedRange>,
}

/// Compress a complete metadata-inclusive bitmap into physical byte ranges.
/// This does not establish ownership of the set bits or authorize omission of
/// any ReFS bootstrap sector from a reconstruction write set.
pub fn allocated_ranges(bytes: &[u8], partition: u64) -> io::Result<AllocationMap> {
    allocated_ranges_with_profile(
        bytes,
        partition,
        crate::bitmap_paging::AssemblyProfile::Legacy,
    )
}

/// Inspect a complete map with the explicitly selected resource profile.
/// Like the legacy entry point, this is not an allocation-ownership proof.
pub fn allocated_ranges_with_profile(
    bytes: &[u8],
    partition: u64,
    profile: crate::bitmap_paging::AssemblyProfile,
) -> io::Result<AllocationMap> {
    let bad = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    let cluster = crate::target_cluster::bytes();
    if !partition.is_multiple_of(cluster)
        || bytes.len() < 16
        || bytes.len() > profile.max_complete_bytes()
        || bytes[..8] != [0; 8]
    {
        return Err(bad("invalid metadata-inclusive bitmap header or geometry"));
    }
    let bits = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if bits <= 0
        || bits as u64 != partition / cluster
        || bytes.len() - 16 < (bits as u64).div_ceil(8) as usize
    {
        return Err(bad("metadata-inclusive bitmap is incomplete"));
    }
    let mut ranges = Vec::new();
    let mut first = None;
    let mut allocated = 0u64;
    let clusters = bits as u64;
    // A full bitmap can cover tens of millions of clusters. Handle the common
    // completely free/allocated bytes at once, preserving run boundaries across
    // bytes; inspect individual bits only for mixed bytes and the final tail.
    let full_bytes = (clusters / 8) as usize;
    for (index, &value) in bytes[16..16 + full_bytes].iter().enumerate() {
        let start_cluster = index as u64 * 8;
        match value {
            0 => {
                if let Some(start) = first.take() {
                    push_range(&mut ranges, start, start_cluster)?;
                }
            }
            0xff => {
                allocated += 8;
                first.get_or_insert(start_cluster);
            }
            _ => {
                for bit in 0..8 {
                    let cluster = start_cluster + bit;
                    if value & (1 << bit) != 0 {
                        allocated += 1;
                        first.get_or_insert(cluster);
                    } else if let Some(start) = first.take() {
                        push_range(&mut ranges, start, cluster)?;
                    }
                }
            }
        }
    }
    if !clusters.is_multiple_of(8) {
        let value = bytes[16 + full_bytes];
        for bit in 0..clusters % 8 {
            let cluster = full_bytes as u64 * 8 + bit;
            if value & (1 << bit) != 0 {
                allocated += 1;
                first.get_or_insert(cluster);
            } else if let Some(start) = first.take() {
                push_range(&mut ranges, start, cluster)?;
            }
        }
    }
    if let Some(start) = first {
        push_range(&mut ranges, start, clusters)?;
    }
    Ok(AllocationMap {
        bitmap_sha256: hex::encode(Sha256::digest(bytes)),
        cluster_count: bits as u64,
        allocated_clusters: allocated,
        ranges,
    })
}

fn push_range(ranges: &mut Vec<AllocatedRange>, start: u64, end: u64) -> io::Result<()> {
    if ranges.len() >= 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata-inclusive allocation range budget exceeded",
        ));
    }
    let cluster = crate::target_cluster::bytes();
    ranges.push(AllocatedRange {
        offset: start * cluster,
        length: (end - start) * cluster,
    });
    Ok(())
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub start_lcn: u64,
    pub clusters: u64,
    pub declared_clusters: u64,
    pub allocated_clusters: u64,
    pub bitmap_sha256: String,
}
/// A validated immutable bitmap and its hash. Reusing this view for multiple
/// candidate extents avoids rehashing the complete map for every file. It is
/// still only an occupancy observation, not an ownership or exclusion proof.
pub(crate) struct BitmapView<'a> {
    bytes: &'a [u8],
    bits: u64,
    bitmap_sha256: String,
}

fn candidate_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "candidate is outside a complete bounded bitmap",
    )
}

impl<'a> BitmapView<'a> {
    pub(crate) fn new(bytes: &'a [u8], partition: u64) -> io::Result<Self> {
        Self::new_with_profile(
            bytes,
            partition,
            crate::bitmap_paging::AssemblyProfile::Legacy,
        )
    }

    pub(crate) fn new_with_profile(
        bytes: &'a [u8],
        partition: u64,
        profile: crate::bitmap_paging::AssemblyProfile,
    ) -> io::Result<Self> {
        if bytes.len() < 16 || bytes.len() > profile.max_complete_bytes() || bytes[..8] != [0; 8] {
            return Err(candidate_error());
        }
        let bits = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
        if bits <= 0
            || bits as u64 > partition / crate::target_cluster::bytes()
            || ((bytes.len() - 16) as u64) < (bits as u64).div_ceil(8)
        {
            return Err(candidate_error());
        }
        Ok(Self {
            bytes,
            bits: bits as u64,
            bitmap_sha256: hex::encode(Sha256::digest(bytes)),
        })
    }

    pub(crate) fn candidate(&self, offset: u64, length: u64) -> io::Result<Candidate> {
        let cluster = crate::target_cluster::bytes();
        if !offset.is_multiple_of(cluster) || length == 0 || !length.is_multiple_of(cluster) {
            return Err(candidate_error());
        }
        let start = offset / cluster;
        let clusters = length / cluster;
        let end = start.checked_add(clusters).ok_or_else(candidate_error)?;
        if end > self.bits {
            return Err(candidate_error());
        }
        let bitmap = &self.bytes[16..];
        let mut cursor = start;
        let mut allocated = 0u64;
        if !cursor.is_multiple_of(8) {
            let end_of_byte = (cursor / 8 * 8 + 8).min(end);
            let first_bit = (cursor % 8) as u32;
            let last_bit = (end_of_byte - cursor / 8 * 8) as u32;
            let mask = ((1u16 << last_bit) - 1) & !((1u16 << first_bit) - 1);
            allocated += u64::from((u16::from(bitmap[(cursor / 8) as usize]) & mask).count_ones());
            cursor = end_of_byte;
        }
        let full_end = (end / 8) as usize;
        let full = &bitmap[(cursor / 8) as usize..full_end];
        let mut words = full.chunks_exact(8);
        for word in &mut words {
            allocated += u64::from(u64::from_ne_bytes(word.try_into().unwrap()).count_ones());
        }
        for byte in words.remainder() {
            allocated += u64::from(byte.count_ones());
        }
        cursor = cursor.max(end / 8 * 8);
        if cursor < end {
            let mask = (1u16 << (end % 8)) - 1;
            allocated += u64::from((u16::from(bitmap[(end / 8) as usize]) & mask).count_ones());
        }
        Ok(Candidate {
            start_lcn: start,
            clusters,
            declared_clusters: self.bits,
            allocated_clusters: allocated,
            bitmap_sha256: self.bitmap_sha256.clone(),
        })
    }
}

pub fn candidate(bytes: &[u8], offset: u64, length: u64, partition: u64) -> io::Result<Candidate> {
    candidate_with_profile(
        bytes,
        offset,
        length,
        partition,
        crate::bitmap_paging::AssemblyProfile::Legacy,
    )
}

/// Evaluate an occupancy candidate with an explicit bitmap resource profile.
/// This does not authorize retention, allocation, or writes.
pub fn candidate_with_profile(
    bytes: &[u8],
    offset: u64,
    length: u64,
    partition: u64,
    profile: crate::bitmap_paging::AssemblyProfile,
) -> io::Result<Candidate> {
    // Reject invalid geometry before hashing a potentially multi-megabyte map.
    let cluster = crate::target_cluster::bytes();
    if !offset.is_multiple_of(cluster) || length == 0 || !length.is_multiple_of(cluster) {
        return Err(candidate_error());
    }
    BitmapView::new_with_profile(bytes, partition, profile)?.candidate(offset, length)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn bitmap() -> Vec<u8> {
        let mut b = vec![0; 18];
        b[8..16].copy_from_slice(&16u64.to_le_bytes());
        b
    }
    #[test]
    fn metadata_occupancy_is_independent_of_legacy_free_space() {
        let legacy = bitmap();
        let mut metadata = bitmap();
        metadata[16] = 0b11110000;
        assert_eq!(
            candidate(&legacy, 4 * 4096, 4 * 4096, 16 * 4096)
                .unwrap()
                .allocated_clusters,
            0
        );
        assert_eq!(
            candidate(&metadata, 4 * 4096, 4 * 4096, 16 * 4096)
                .unwrap()
                .allocated_clusters,
            4
        );
    }
    #[test]
    fn a_bit_is_one_cluster_of_the_target_unit() {
        let mut b = bitmap();
        b[16] = 0b0000_0110;
        crate::target_cluster::with(65536, || {
            let partition = 16 * 65536;
            assert_eq!(
                allocated_ranges(&b, partition).unwrap().ranges,
                [AllocatedRange {
                    offset: 65536,
                    length: 131_072
                }]
            );
            let found = candidate(&b, 65536, 196_608, partition).unwrap();
            assert_eq!(
                (found.start_lcn, found.clusters, found.allocated_clusters),
                (1, 3, 2)
            );
            // Sixteen bits do not cover sixteen 4 KiB clusters here, and a
            // 4 KiB range is not a whole number of clusters.
            assert!(allocated_ranges(&b, 16 * 4096).is_err());
            assert!(candidate(&b, 4096, 4096, partition).is_err());
        });
        assert_eq!(
            allocated_ranges(&b, 16 * 4096).unwrap().ranges,
            [AllocatedRange {
                offset: 4096,
                length: 8192
            }]
        );
    }
    #[test]
    fn partial_coverage_nonzero_base_overflow_and_alignment_fail() {
        assert!(candidate(&bitmap()[..17], 0, 4096, 65536).is_err());
        let mut b = bitmap();
        b[0] = 1;
        assert!(candidate(&b, 0, 4096, 65536).is_err());
        for (o, l) in [
            (1, 4096),
            (0, 0),
            (0, 1),
            (65536, 4096),
            (u64::MAX - 4095, 8192),
        ] {
            assert!(candidate(&bitmap(), o, l, 65536).is_err());
        }
    }
    #[test]
    fn compresses_complete_metadata_bitmap_without_losing_tail() {
        let mut b = bitmap();
        b[16] = 0b0001_0011;
        b[17] = 0b1000_0000;
        let map = allocated_ranges(&b, 16 * 4096).unwrap();
        assert_eq!(map.allocated_clusters, 4);
        assert_eq!(
            map.ranges,
            [
                AllocatedRange {
                    offset: 0,
                    length: 8192
                },
                AllocatedRange {
                    offset: 4 * 4096,
                    length: 4096
                },
                AllocatedRange {
                    offset: 15 * 4096,
                    length: 4096
                },
            ]
        );
        assert!(allocated_ranges(&b, 17 * 4096).is_err());
        assert!(allocated_ranges(&b[..17], 16 * 4096).is_err());
    }

    #[test]
    fn byte_scans_match_bitwise_reference_across_all_alignment_boundaries() {
        let mut seed = 0x3a46_1d9b_0012_ffe3u64;
        for clusters in (1u64..=137).chain([255, 256, 257, 511, 513]) {
            let mut bytes = vec![0u8; 16 + clusters.div_ceil(8) as usize + 2];
            bytes[8..16].copy_from_slice(&clusters.to_le_bytes());
            for byte in &mut bytes[16..] {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed as u8;
            }
            let partition = clusters * 4096;
            let is_set = |index: u64| bytes[16 + index as usize / 8] & (1 << (index % 8)) != 0;
            let view = BitmapView::new(&bytes, partition).unwrap();
            let expected_hash = hex::encode(Sha256::digest(&bytes));
            for start in 0..clusters {
                let remaining = clusters - start;
                for count in [1, 2, 7, 8, 9, 15, 16, 31, 64, remaining] {
                    if count > remaining {
                        continue;
                    }
                    let expected = (start..start + count).filter(|&i| is_set(i)).count() as u64;
                    let found = view.candidate(start * 4096, count * 4096).unwrap();
                    assert_eq!(
                        found.allocated_clusters, expected,
                        "clusters={clusters} start={start} count={count}"
                    );
                    assert_eq!(found.bitmap_sha256, expected_hash);
                    assert_eq!(found.start_lcn, start);
                    assert_eq!(found.clusters, count);
                    assert_eq!(found.declared_clusters, clusters);
                }
            }
            let actual = allocated_ranges(&bytes, partition).unwrap();
            let mut expected = Vec::new();
            let mut start = None;
            for cluster in 0..clusters {
                if is_set(cluster) {
                    start.get_or_insert(cluster);
                } else if let Some(first) = start.take() {
                    expected.push(AllocatedRange {
                        offset: first * 4096,
                        length: (cluster - first) * 4096,
                    });
                }
            }
            if let Some(first) = start {
                expected.push(AllocatedRange {
                    offset: first * 4096,
                    length: (clusters - first) * 4096,
                });
            }
            assert_eq!(actual.ranges, expected, "clusters={clusters}");
            assert_eq!(
                actual.allocated_clusters,
                (0..clusters).filter(|&i| is_set(i)).count() as u64
            );
            assert_eq!(actual.bitmap_sha256, expected_hash);
        }
    }

    #[test]
    fn range_budget_remains_exact_for_highly_fragmented_bitmap() {
        for range_count in [65536u64, 65537] {
            let clusters = range_count * 2 - 1;
            let mut bytes = vec![0x55; 16 + clusters.div_ceil(8) as usize];
            bytes[..8].fill(0);
            bytes[8..16].copy_from_slice(&clusters.to_le_bytes());
            let result = allocated_ranges(&bytes, clusters * 4096);
            if range_count == 65536 {
                let map = result.unwrap();
                assert_eq!(map.ranges.len(), 65536);
                assert_eq!(map.allocated_clusters, 65536);
                assert_eq!(map.ranges.last().unwrap().offset, (clusters - 1) * 4096);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn full_profile_bitmap_keeps_one_run_and_exact_candidate_counts() {
        let bitmap_bytes = crate::bitmap_paging::MAX_DATA_BYTES;
        let clusters = bitmap_bytes as u64 * 8;
        let mut bytes = vec![0xff; 16 + bitmap_bytes];
        bytes[..8].fill(0);
        bytes[8..16].copy_from_slice(&clusters.to_le_bytes());
        let partition = clusters * 4096;
        let map = allocated_ranges(&bytes, partition).unwrap();
        assert_eq!(map.allocated_clusters, clusters);
        assert_eq!(
            map.ranges,
            [AllocatedRange {
                offset: 0,
                length: partition
            }]
        );
        let view = BitmapView::new(&bytes, partition).unwrap();
        assert_eq!(
            view.candidate(4096, partition - 8192)
                .unwrap()
                .allocated_clusters,
            clusters - 2
        );
    }

    #[test]
    fn expanded_map_keeps_legacy_refusal_and_exact_tail_occupancy() {
        use crate::bitmap_paging::{AssemblyProfile, MAX_DATA_BYTES};

        let clusters = MAX_DATA_BYTES as u64 * 8 + 5;
        let mut bytes = vec![0; 16 + MAX_DATA_BYTES + 1];
        bytes[8..16].copy_from_slice(&clusters.to_le_bytes());
        bytes[16] = 0x80;
        bytes[17] = 0x01;
        // Only bit four is inside the declared final partial byte. Preserve
        // unused set bits in the hash but never treat them as allocated.
        bytes[16 + MAX_DATA_BYTES] = 0xf0;
        let partition = clusters * 4096;
        assert!(allocated_ranges(&bytes, partition).is_err());
        assert!(candidate(&bytes, 0, 4096, partition).is_err());

        let map =
            allocated_ranges_with_profile(&bytes, partition, AssemblyProfile::OneTiB).unwrap();
        assert_eq!(map.cluster_count, clusters);
        assert_eq!(map.allocated_clusters, 3);
        assert_eq!(
            map.ranges,
            vec![
                AllocatedRange {
                    offset: 7 * 4096,
                    length: 2 * 4096
                },
                AllocatedRange {
                    offset: (clusters - 1) * 4096,
                    length: 4096
                },
            ]
        );
        assert_eq!(map.bitmap_sha256, hex::encode(Sha256::digest(&bytes)));
        let tail = candidate_with_profile(
            &bytes,
            (clusters - 8) * 4096,
            8 * 4096,
            partition,
            AssemblyProfile::OneTiB,
        )
        .unwrap();
        assert_eq!(tail.allocated_clusters, 1);
        assert_eq!(tail.bitmap_sha256, map.bitmap_sha256);
        assert!(
            candidate_with_profile(
                &bytes,
                clusters * 4096,
                4096,
                partition,
                AssemblyProfile::OneTiB,
            )
            .is_err()
        );
    }
}
