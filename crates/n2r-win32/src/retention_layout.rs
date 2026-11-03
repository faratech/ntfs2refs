//! Bounded free-subrun planning from two complete, same-domain ReFS bitmaps.
//! Candidates are not retained extents: the native mover must recheck occupancy
//! and measure the resulting file mapping before reporting actual retention.
use crate::bitmap_layout;
use serde::Serialize;
use std::io;

const CLUSTER: u64 = 4096;
/// Output-vector ceiling (48 B per subrun). Private-tree placement passes its
/// remaining native submissions as the budget, so this matches
/// private_tree::MAX_PLACEMENT_SUBMISSIONS; older callers pass their own.
pub const MAX_SUBRUNS: usize = 32_768;
// FSCTL_MOVE_FILE counts clusters in a DWORD. This bounds each submitted move,
// not the length of the original file or of a streamed bitmap interval.
pub(crate) const MAX_MOVE_BYTES: u64 = u32::MAX as u64 * CLUSTER;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SourceRun {
    pub logical_offset: u64,
    pub physical_offset: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FreeSubrun {
    pub logical_offset: u64,
    pub physical_offset: u64,
    pub length: u64,
    pub starting_vcn: u64,
    pub destination_lcn: u64,
    pub clusters: u32,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub source: SourceRun,
    pub legacy_bitmap_sha256: String,
    pub metadata_bitmap_sha256: String,
    pub free_bytes: u64,
    pub blocked_bytes: u64,
    pub subruns: Vec<FreeSubrun>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Equivalent free-space complement over complete streamed allocation ranges.
/// Merge the two ordered occupied views rather than visiting every cluster.
pub fn plan_free_subruns_streamed(
    legacy: &crate::bitmap_streaming::Summary,
    metadata: &crate::bitmap_streaming::Summary,
    run: SourceRun,
    partition: u64,
    max_subruns: usize,
) -> io::Result<Plan> {
    StreamedPlanner::new(legacy, metadata, partition)?.plan(run, max_subruns)
}

/// Immutable planning view over two completely validated phase snapshots.
/// This caches structural validation only. Every native move must still query
/// live occupancy and verify the actual resulting mapping independently.
pub struct StreamedPlanner<'a> {
    legacy: &'a crate::bitmap_streaming::Summary,
    metadata: &'a crate::bitmap_streaming::Summary,
    partition: u64,
    // Immutable union of both fully validated views, in cluster coordinates.
    // Compute overlaps once per phase rather than for every source extent.
    occupied: Vec<(u64, u64)>,
}

impl<'a> StreamedPlanner<'a> {
    pub fn new(
        legacy: &'a crate::bitmap_streaming::Summary,
        metadata: &'a crate::bitmap_streaming::Summary,
        partition: u64,
    ) -> io::Result<Self> {
        if partition == 0 || !partition.is_multiple_of(CLUSTER) {
            return Err(invalid("streamed retention partition geometry differs"));
        }
        let domain = partition / CLUSTER;
        Self::build(legacy, metadata, partition, crate::bitmap_streaming::source_limits(domain)?, None)
    }

    fn build(
        legacy: &'a crate::bitmap_streaming::Summary,
        metadata: &'a crate::bitmap_streaming::Summary,
        partition: u64,
        limits: crate::bitmap_streaming::Limits,
        resource_capacity: Option<usize>,
    ) -> io::Result<Self> {
        if partition == 0 || !partition.is_multiple_of(CLUSTER) {
            return Err(invalid("streamed retention partition geometry differs"));
        }
        let domain = partition / CLUSTER;
        for summary in [legacy, metadata] {
            summary.validate(domain, limits)?;
            if summary.declared_clusters != domain {
                return Err(invalid("streamed retention bitmap domain differs"));
            }
        }
        let mut left = legacy.allocated_ranges.iter().peekable();
        let mut right = metadata.allocated_ranges.iter().peekable();
        let mut occupied: Vec<(u64, u64)> = Vec::new();
        if let Some(capacity) = resource_capacity {
            occupied.try_reserve_exact(capacity).map_err(io::Error::other)?;
            if occupied.capacity() > capacity {
                return Err(invalid("retention union exceeded prepaid capacity"));
            }
        }
        loop {
            let next = match (left.peek(), right.peek()) {
                (Some(a), Some(b)) if a.starting_lcn <= b.starting_lcn => left.next(),
                (Some(_), Some(_)) => right.next(),
                (Some(_), None) => left.next(),
                (None, Some(_)) => right.next(),
                (None, None) => break,
            }
            .unwrap();
            let start = next.starting_lcn;
            let end = start + next.clusters;
            if let Some(last) = occupied.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                occupied.try_reserve(1).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "retention union allocation failed",
                    )
                })?;
                occupied.push((start, end));
            }
        }
        Ok(Self {
            legacy,
            metadata,
            partition,
            occupied,
        })
    }

    pub fn plan(&self, run: SourceRun, max_subruns: usize) -> io::Result<Plan> {
        self.plan_inner(run, max_subruns, false)
    }

    fn plan_inner(&self, run: SourceRun, max_subruns: usize, resource: bool) -> io::Result<Plan> {
        let (legacy, metadata, partition) = (self.legacy, self.metadata, self.partition);
        if max_subruns == 0 || (!resource && max_subruns > MAX_SUBRUNS)
            || partition == 0
            || !partition.is_multiple_of(CLUSTER)
            || run.length == 0
            || !run.length.is_multiple_of(CLUSTER)
            || !run.logical_offset.is_multiple_of(CLUSTER)
            || !run.physical_offset.is_multiple_of(CLUSTER)
            || run.logical_offset.checked_add(run.length).is_none()
            || run
                .physical_offset
                .checked_add(run.length)
                .is_none_or(|end| end > partition)
        {
            return Err(invalid("streamed retention run geometry or budget differs"));
        }
        let start = run.physical_offset / CLUSTER;
        let end = start + run.length / CLUSTER;
        let first = self.occupied.partition_point(|range| range.1 <= start);
        let mut cursor = start;
        let mut free_clusters = 0u64;
        let mut subruns = Vec::new();
        if resource {
            // A free complement gains at most one interval per occupied
            // interval, plus splits at the native DWORD cluster limit.
            let split = usize::try_from((run.length / CLUSTER).div_ceil(u64::from(u32::MAX)))
                .map_err(io::Error::other)?;
            let capacity = self.occupied.len().checked_add(split).and_then(|n| n.checked_add(1))
                .ok_or_else(|| invalid("retention output capacity overflow"))?.min(max_subruns);
            subruns.try_reserve_exact(capacity).map_err(io::Error::other)?;
            if subruns.capacity() > capacity { return Err(invalid("retention output exceeded prepaid capacity")); }
        }
        let mut push_free = |mut begin: u64, end: u64| -> io::Result<()> {
            while begin < end {
                if subruns.len() >= max_subruns {
                    return Err(invalid("retention free-subrun budget exceeded"));
                }
                let count = (end - begin).min(u64::from(u32::MAX)) as u32;
                let physical_offset = begin * CLUSTER;
                let logical_offset = run.logical_offset + (begin - start) * CLUSTER;
                subruns.push(FreeSubrun {
                    logical_offset,
                    physical_offset,
                    length: u64::from(count) * CLUSTER,
                    starting_vcn: logical_offset / CLUSTER,
                    destination_lcn: begin,
                    clusters: count,
                });
                free_clusters += u64::from(count);
                begin += u64::from(count);
            }
            Ok(())
        };
        for &(occupied_start, occupied_end) in self.occupied[first..]
            .iter()
            .take_while(|range| range.0 < end)
        {
            let occupied_end = occupied_end.min(end);
            if occupied_end <= cursor {
                continue;
            }
            let occupied_start = occupied_start.max(start);
            if occupied_start > cursor {
                push_free(cursor, occupied_start)?;
            }
            cursor = occupied_end;
        }
        if cursor < end {
            push_free(cursor, end)?;
        }
        Ok(Plan {
            source: run,
            legacy_bitmap_sha256: legacy.canonical_bitmap_sha256.clone(),
            metadata_bitmap_sha256: metadata.canonical_bitmap_sha256.clone(),
            free_bytes: free_clusters * CLUSTER,
            blocked_bytes: run.length - free_clusters * CLUSTER,
            subruns,
        })
    }
}

/// Actual bounded resource owner for complete bitmap union and per-run output.
#[cfg(windows)]
pub struct ResourcePlanner<'a> {
    planner: StreamedPlanner<'a>,
    max_subruns: usize,
    payer: &'a dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
    _lease: Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>,
}

#[cfg(windows)]
pub struct ResourcePlan {
    plan: Plan,
    _lease: Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>,
}
#[cfg(windows)]
impl std::ops::Deref for ResourcePlan {
    type Target = Plan;
    fn deref(&self) -> &Plan { &self.plan }
}

#[cfg(windows)]
impl<'a> StreamedPlanner<'a> {
    pub fn new_resource(
        legacy: &'a crate::bitmap_streaming::Summary,
        metadata: &'a crate::bitmap_streaming::Summary,
        partition: u64,
        limits: crate::bitmap_streaming::Limits,
        max_subruns: usize,
        payer: &'a dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
    ) -> io::Result<ResourcePlanner<'a>> {
        if max_subruns == 0 { return Err(invalid("resource retention subrun budget is empty")); }
        let capacity = legacy.allocated_ranges.len().checked_add(metadata.allocated_ranges.len())
            .ok_or_else(|| invalid("retention bitmap union count overflow"))?;
        let bytes = (capacity as u64).checked_mul(std::mem::size_of::<(u64,u64)>() as u64)
            .and_then(|n| n.checked_add(payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("retention union RAM overflow"))?;
        let lease = payer.reserve(bytes)?;
        let planner = Self::build(legacy, metadata, partition, limits, Some(capacity))?;
        Ok(ResourcePlanner { planner, max_subruns, payer, _lease: lease })
    }
}

#[cfg(windows)]
impl ResourcePlanner<'_> {
    pub fn plan(&self, run: SourceRun, remaining_subruns: usize) -> io::Result<ResourcePlan> {
        if remaining_subruns == 0 || remaining_subruns > self.max_subruns {
            return Err(invalid("resource retention remaining budget differs"));
        }
        let split = usize::try_from((run.length / CLUSTER).div_ceil(u64::from(u32::MAX)))
            .map_err(io::Error::other)?;
        let slots = self.planner.occupied.len().checked_add(split).and_then(|n| n.checked_add(1))
            .ok_or_else(|| invalid("retention output capacity overflow"))?.min(remaining_subruns);
        let bytes = (slots as u64).checked_mul(std::mem::size_of::<FreeSubrun>() as u64)
            .and_then(|n| n.checked_add((self.planner.legacy.canonical_bitmap_sha256.len() + self.planner.metadata.canonical_bitmap_sha256.len()) as u64 * 2))
            .and_then(|n| n.checked_add(self.payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("retention output RAM overflow"))?;
        let mut lease = self.payer.reserve(bytes)?;
        let plan = self.planner.plan_inner(run, remaining_subruns, true)?;
        let actual = (plan.subruns.capacity() as u64).checked_mul(std::mem::size_of::<FreeSubrun>() as u64)
            .and_then(|n| n.checked_add(plan.legacy_bitmap_sha256.capacity() as u64))
            .and_then(|n| n.checked_add(plan.metadata_bitmap_sha256.capacity() as u64))
            .and_then(|n| n.checked_add(self.payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("retention actual output RAM overflow"))?;
        lease.shrink_to(actual)?;
        Ok(ResourcePlan { plan, _lease: lease })
    }
}

/// Split an already eligible, fully initialized NTFS source run into maximal
/// intervals that are free in both native ReFS views. The two bitmaps must
/// cover exactly the same complete partition domain starting at cluster zero.
/// No partial plan is returned when geometry, coverage or budgets fail.
pub fn plan_free_subruns(
    legacy: &[u8],
    metadata: &[u8],
    run: SourceRun,
    partition: u64,
    max_subruns: usize,
) -> io::Result<Plan> {
    if !(1..=MAX_SUBRUNS).contains(&max_subruns)
        || partition == 0
        || !partition.is_multiple_of(CLUSTER)
        || run.length == 0
        || !run.length.is_multiple_of(CLUSTER)
        || !run.logical_offset.is_multiple_of(CLUSTER)
        || !run.physical_offset.is_multiple_of(CLUSTER)
    {
        return Err(invalid("retention run geometry or subrun budget differs"));
    }
    let clusters = run.length / CLUSTER;
    u32::try_from(clusters).map_err(|_| invalid("retention run exceeds u32 cluster count"))?;
    run.logical_offset
        .checked_add(run.length)
        .ok_or_else(|| invalid("retention logical range overflow"))?;
    if run
        .physical_offset
        .checked_add(run.length)
        .is_none_or(|end| end > partition)
    {
        return Err(invalid("retention physical range exceeds partition"));
    }
    // Reuse the existing bounded wire validator and exact response hashes.
    // Candidate alone permits a shorter declared domain; this planner does not.
    let legacy_candidate =
        bitmap_layout::candidate(legacy, run.physical_offset, run.length, partition)?;
    let metadata_candidate =
        bitmap_layout::candidate(metadata, run.physical_offset, run.length, partition)?;
    let domain = partition / CLUSTER;
    if legacy_candidate.declared_clusters != domain
        || metadata_candidate.declared_clusters != domain
    {
        return Err(invalid(
            "retention bitmaps do not cover the same complete partition domain",
        ));
    }
    let first = run.physical_offset / CLUSTER;
    let mut start = None;
    let mut free_clusters = 0u64;
    let mut subruns = Vec::new();
    for relative in 0..=clusters {
        let free = if relative == clusters {
            false // Flush a free interval ending exactly at the source-run tail.
        } else {
            let cluster = first + relative;
            let at = 16 + (cluster / 8) as usize;
            let mask = 1u8 << (cluster % 8);
            legacy[at] & mask == 0 && metadata[at] & mask == 0
        };
        if free {
            free_clusters += 1;
            start.get_or_insert(relative);
        } else if let Some(begin) = start.take() {
            if subruns.len() == max_subruns {
                return Err(invalid("retention free-subrun budget exceeded"));
            }
            let logical_offset = run.logical_offset + begin * CLUSTER;
            let physical_offset = run.physical_offset + begin * CLUSTER;
            let count = u32::try_from(relative - begin)
                .map_err(|_| invalid("retention subrun exceeds u32 cluster count"))?;
            subruns.push(FreeSubrun {
                logical_offset,
                physical_offset,
                length: u64::from(count) * CLUSTER,
                starting_vcn: logical_offset / CLUSTER,
                destination_lcn: physical_offset / CLUSTER,
                clusters: count,
            });
        }
    }
    Ok(Plan {
        source: run,
        legacy_bitmap_sha256: legacy_candidate.bitmap_sha256,
        metadata_bitmap_sha256: metadata_candidate.bitmap_sha256,
        free_bytes: free_clusters * CLUSTER,
        blocked_bytes: (clusters - free_clusters) * CLUSTER,
        subruns,
    })
}
