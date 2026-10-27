//! Retained payload coverage against both ReFS 3.14 allocator families.
//! This does not prove unique ownership, refcounts or all metadata reachability.
use crate::{refs_allocator, retained_compare::RetainedCompareRequest};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::io::{Read, Seek};

const CLUSTER: u64 = 4096;

#[derive(Debug, PartialEq, Eq, Serialize)]
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
    /// Legacy output omits this field. A larger profile is explicit and does
    /// not itself authorize source admission or conversion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_profile: Option<crate::ntfs_admission::ResourceProfile>,
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

#[cfg(test)]
fn contains(ranges: &[(u64, u64)], offset: u64) -> bool {
    let index = ranges.partition_point(|(start, _)| *start <= offset);
    index > 0 && offset < ranges[index - 1].1
}

/// Convert byte intervals to the cluster-start positions they contain. This
/// preserves the old per-cluster interpretation even for an unaligned interval.
fn sampled_cluster_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges {
        let first = start.div_ceil(CLUSTER);
        let last = end.div_ceil(CLUSTER);
        if first == last {
            continue;
        }
        if let Some(previous) = out.last_mut()
            && first <= previous.1
        {
            previous.1 = previous.1.max(last);
        } else {
            out.push((first, last));
        }
    }
    out
}

/// Count coverage over interval boundaries instead of iterating every cluster.
/// Inputs are sorted, disjoint cluster ranges produced by `sampled_cluster_ranges`.
fn range_coverage(
    offset: u64,
    length: u64,
    medium: &[(u64, u64)],
    small: &[(u64, u64)],
) -> Result<RangeCoverage> {
    ensure!(
        offset.is_multiple_of(CLUSTER) && length > 0 && length.is_multiple_of(CLUSTER),
        "retained coverage must be nonempty and cluster aligned"
    );
    let mut cursor = offset / CLUSTER;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("retained range overflow"))?
        / CLUSTER;
    let mut medium_index = medium.partition_point(|&(_, end)| end <= cursor);
    let mut small_index = small.partition_point(|&(_, end)| end <= cursor);
    let (mut medium_count, mut small_count, mut both, mut missing) = (0, 0, 0, 0);
    while cursor < end {
        let in_medium = medium
            .get(medium_index)
            .is_some_and(|&(start, _)| start <= cursor);
        let in_small = small
            .get(small_index)
            .is_some_and(|&(start, _)| start <= cursor);
        let next_medium = medium
            .get(medium_index)
            .map_or(end, |&(start, stop)| if in_medium { stop } else { start });
        let next_small = small.get(small_index).map_or(
            end,
            |&(start, stop)| {
                if in_small { stop } else { start }
            },
        );
        let next = end.min(next_medium).min(next_small);
        ensure!(next > cursor, "allocator coverage did not advance");
        let count = next - cursor;
        if in_medium {
            medium_count += count;
        }
        if in_small {
            small_count += count;
        }
        if in_medium && in_small {
            both += count;
        }
        if !in_medium && !in_small {
            missing += count;
        }
        cursor = next;
        if in_medium && cursor == next_medium {
            medium_index += 1;
        }
        if in_small && cursor == next_small {
            small_index += 1;
        }
    }
    Ok(RangeCoverage {
        offset,
        length,
        medium_allocated_clusters: medium_count,
        small_allocated_clusters: small_count,
        both_allocated_clusters: both,
        unallocated_clusters: missing,
    })
}

pub fn inspect<R: Read + Seek>(
    reader: &mut R,
    image_bytes: u64,
    request: &RetainedCompareRequest,
) -> Result<Coverage> {
    inspect_with_resource_profile(
        reader,
        image_bytes,
        request,
        crate::ntfs_admission::ResourceProfile::AlphaV1,
    )
}

/// Inspect retained allocation with an explicit source-resource budget. This
/// is coverage evidence only; it cannot admit a source or authorize writes.
pub fn inspect_with_resource_profile<R: Read + Seek>(
    reader: &mut R,
    image_bytes: u64,
    request: &RetainedCompareRequest,
    resources: crate::ntfs_admission::ResourceProfile,
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
    validate_retained_budget(retained_bytes, resources)?;
    let medium = refs_allocator::inspect_medium(reader, image_bytes)?;
    let small = refs_allocator::inspect_small(reader, image_bytes)?;
    ensure!(
        medium.checkpoint_lcn == small.checkpoint_lcn
            && medium.checkpoint_clock == small.checkpoint_clock
            && medium.allocator_walk_complete
            && small.allocator_walk_complete,
        "ReFS allocator checkpoints or walks disagree"
    );
    let medium_ranges = sampled_cluster_ranges(&merged(&medium.allocated_ranges)?);
    let small_ranges = sampled_cluster_ranges(&merged(&small.allocated_ranges)?);
    let mut covered = Vec::new();
    let (mut missing_total, mut both_total) = (0u64, 0u64);
    for range in &request.retained_ranges {
        let observation =
            range_coverage(range.offset, range.length, &medium_ranges, &small_ranges)?;
        missing_total += observation.unallocated_clusters;
        both_total += observation.both_allocated_clusters;
        covered.push(observation);
    }
    Ok(Coverage {
        schema_version: 1,
        profile: "refs-3.14-retained-payload-allocator-coverage-v1",
        resource_profile: (resources != crate::ntfs_admission::ResourceProfile::AlphaV1)
            .then_some(resources),
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

fn validate_retained_budget(
    retained_bytes: u64,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<()> {
    ensure!(
        retained_bytes > 0 && retained_bytes <= resources.limits().maximum_logical_bytes,
        "bounded nonempty retained payload required"
    );
    Ok(())
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

    #[test]
    fn interval_coverage_matches_cluster_reference_for_mixed_and_unaligned_ranges() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..300 {
            let mut make_ranges = || {
                (0..12)
                    .map(|_| {
                        let start = next() % (128 * CLUSTER);
                        let length = next() % (12 * CLUSTER) + 1;
                        refs_allocator::AllocatedRange {
                            offset: start,
                            length,
                        }
                    })
                    .collect::<Vec<_>>()
            };
            let medium = merged(&make_ranges()).unwrap();
            let small = merged(&make_ranges()).unwrap();
            let start = next() % 128;
            let count = next() % 40 + 1;
            let actual = range_coverage(
                start * CLUSTER,
                count * CLUSTER,
                &sampled_cluster_ranges(&medium),
                &sampled_cluster_ranges(&small),
            )
            .unwrap();
            let (mut m, mut s, mut both, mut missing) = (0, 0, 0, 0);
            for cluster in start..start + count {
                let in_m = contains(&medium, cluster * CLUSTER);
                let in_s = contains(&small, cluster * CLUSTER);
                m += u64::from(in_m);
                s += u64::from(in_s);
                both += u64::from(in_m && in_s);
                missing += u64::from(!in_m && !in_s);
            }
            assert_eq!(actual.medium_allocated_clusters, m);
            assert_eq!(actual.small_allocated_clusters, s);
            assert_eq!(actual.both_allocated_clusters, both);
            assert_eq!(actual.unallocated_clusters, missing);
        }
    }

    #[test]
    fn large_coverage_counts_intersection_and_holes_without_cluster_walk() {
        let gib = 1u64 << 30;
        let medium = sampled_cluster_ranges(&[(0, 2 * gib)]);
        let small = sampled_cluster_ranges(&[(gib, 3 * gib)]);
        let report = range_coverage(0, 4 * gib, &medium, &small).unwrap();
        assert_eq!(report.medium_allocated_clusters, 2 * gib / CLUSTER);
        assert_eq!(report.small_allocated_clusters, 2 * gib / CLUSTER);
        assert_eq!(report.both_allocated_clusters, gib / CLUSTER);
        assert_eq!(report.unallocated_clusters, gib / CLUSTER);
        assert!(range_coverage(1, CLUSTER, &medium, &small).is_err());
        assert!(range_coverage(0, 0, &medium, &small).is_err());
        assert!(range_coverage(u64::MAX - (CLUSTER - 1), CLUSTER, &medium, &small).is_err());
    }

    #[test]
    fn retained_budget_requires_explicit_larger_profile_and_keeps_legacy_json() {
        use crate::ntfs_admission::ResourceProfile;
        let legacy = ResourceProfile::AlphaV1;
        let large = ResourceProfile::ExperimentalLargeTreeV1;
        assert!(validate_retained_budget(0, legacy).is_err());
        assert!(validate_retained_budget(256 << 20, legacy).is_ok());
        assert!(validate_retained_budget((256 << 20) + CLUSTER, legacy).is_err());
        assert!(validate_retained_budget(4u64 << 30, large).is_ok());
        assert!(validate_retained_budget((4u64 << 30) + CLUSTER, large).is_err());
        let mut report = Coverage {
            schema_version: 1,
            profile: "refs-3.14-retained-payload-allocator-coverage-v1",
            resource_profile: None,
            checkpoint_lcn: 42,
            checkpoint_clock: 3,
            retained_bytes: CLUSTER,
            retained_clusters: 1,
            unallocated_clusters: 0,
            both_allocated_clusters: 0,
            ranges: vec![],
            retained_allocator_coverage_verified: true,
            whole_volume_ownership_verified: false,
            conversion_qualified: false,
        };
        assert!(
            serde_json::to_value(&report)
                .unwrap()
                .get("resource_profile")
                .is_none()
        );
        report.resource_profile = Some(large);
        assert_eq!(
            serde_json::to_value(&report).unwrap()["resource_profile"],
            "experimental_large_tree_v1"
        );
        assert!(!report.conversion_qualified);
    }
}
