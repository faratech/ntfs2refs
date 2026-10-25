//! Retained payload coverage against both ReFS 3.14 allocator families.
//! This does not prove unique ownership, refcounts or all metadata reachability.
use crate::{refs_allocator, retained_compare::RetainedCompareRequest};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::io::{Read, Seek};

const CLUSTER: u64 = 4096;
const MAX_RETAINED: u64 = 256 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct RangeCoverage {
    pub offset: u64,
    pub length: u64,
    pub medium_allocated_clusters: u64,
    pub small_allocated_clusters: u64,
    pub both_allocated_clusters: u64,
    pub unallocated_clusters: u64,
}

#[derive(Debug, Serialize)]
pub struct Coverage {
    pub schema_version: u32,
    pub profile: &'static str,
    pub checkpoint_lcn: u64,
    pub checkpoint_clock: u64,
    pub retained_bytes: u64,
    pub retained_clusters: u64,
    pub unallocated_clusters: u64,
    pub both_allocated_clusters: u64,
    pub ranges: Vec<RangeCoverage>,
    pub retained_allocator_coverage_verified: bool,
    pub whole_volume_ownership_verified: bool,
    pub conversion_qualified: bool,
}

fn merged(ranges: &[refs_allocator::AllocatedRange]) -> Result<Vec<(u64, u64)>> {
    let mut sorted = ranges
        .iter()
        .map(|range| {
            Ok((
                range.offset,
                range
                    .offset
                    .checked_add(range.length)
                    .ok_or_else(|| anyhow::anyhow!("allocator range overflow"))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    sorted.sort_unstable();
    let mut output: Vec<(u64, u64)> = Vec::new();
    for (start, end) in sorted {
        ensure!(start < end, "empty allocator range");
        if let Some(last) = output.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        output.push((start, end));
    }
    Ok(output)
}

fn contains(ranges: &[(u64, u64)], offset: u64) -> bool {
    let index = ranges.partition_point(|(start, _)| *start <= offset);
    index > 0 && offset < ranges[index - 1].1
}

pub fn inspect<R: Read + Seek>(
    reader: &mut R,
    image_bytes: u64,
    request: &RetainedCompareRequest,
) -> Result<Coverage> {
    crate::retained_compare::validate_request(request)?;
    ensure!(
        request.schema_version == 2
            && request.sector_size == CLUSTER as u32
            && request.expected_length == image_bytes,
        "retained allocator request geometry differs"
    );
    let retained_bytes = request
        .retained_ranges
        .iter()
        .try_fold(0u64, |sum, range| {
            sum.checked_add(range.length)
                .ok_or_else(|| anyhow::anyhow!("retained byte count overflow"))
        })?;
    ensure!(
        retained_bytes > 0 && retained_bytes <= MAX_RETAINED,
        "bounded nonempty retained payload required"
    );
    let medium = refs_allocator::inspect_medium(reader, image_bytes)?;
    let small = refs_allocator::inspect_small(reader, image_bytes)?;
    ensure!(
        medium.checkpoint_lcn == small.checkpoint_lcn
            && medium.checkpoint_clock == small.checkpoint_clock
            && medium.allocator_walk_complete
            && small.allocator_walk_complete,
        "ReFS allocator checkpoints or walks disagree"
    );
    let medium_ranges = merged(&medium.allocated_ranges)?;
    let small_ranges = merged(&small.allocated_ranges)?;
    let mut covered = Vec::new();
    let (mut missing_total, mut both_total) = (0u64, 0u64);
    for range in &request.retained_ranges {
        let (mut medium_count, mut small_count, mut both, mut missing) = (0, 0, 0, 0);
        for cluster in 0..range.length / CLUSTER {
            let offset = range.offset + cluster * CLUSTER;
            let in_medium = contains(&medium_ranges, offset);
            let in_small = contains(&small_ranges, offset);
            medium_count += u64::from(in_medium);
            small_count += u64::from(in_small);
            both += u64::from(in_medium && in_small);
            missing += u64::from(!in_medium && !in_small);
        }
        missing_total += missing;
        both_total += both;
        covered.push(RangeCoverage {
            offset: range.offset,
            length: range.length,
            medium_allocated_clusters: medium_count,
            small_allocated_clusters: small_count,
            both_allocated_clusters: both,
            unallocated_clusters: missing,
        });
    }
    Ok(Coverage {
        schema_version: 1,
        profile: "refs-3.14-retained-payload-allocator-coverage-v1",
        checkpoint_lcn: medium.checkpoint_lcn,
        checkpoint_clock: medium.checkpoint_clock,
        retained_bytes,
        retained_clusters: retained_bytes / CLUSTER,
        unallocated_clusters: missing_total,
        both_allocated_clusters: both_total,
        ranges: covered,
        retained_allocator_coverage_verified: missing_total == 0 && both_total == 0,
        whole_volume_ownership_verified: false,
        conversion_qualified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_intervals_cover_exact_cluster_boundaries() {
        let ranges = merged(&[
            refs_allocator::AllocatedRange {
                offset: 4096,
                length: 4096,
            },
            refs_allocator::AllocatedRange {
                offset: 0,
                length: 4096,
            },
            refs_allocator::AllocatedRange {
                offset: 16384,
                length: 4096,
            },
        ])
        .unwrap();
        assert_eq!(ranges, vec![(0, 8192), (16384, 20480)]);
        for offset in [0, 4095, 4096, 8191, 16384, 20479] {
            assert!(contains(&ranges, offset));
        }
        for offset in [8192, 12288, 20480] {
            assert!(!contains(&ranges, offset));
        }
    }
}
