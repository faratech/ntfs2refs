//! Bounded free-subrun planning from two complete, same-domain ReFS bitmaps.
//! Candidates are not retained extents: the native mover must recheck occupancy
//! and measure the resulting file mapping before reporting actual retention.
use crate::bitmap_layout;
use serde::Serialize;
use std::io;

const CLUSTER: u64 = 4096;
pub const MAX_SUBRUNS: usize = 1024;

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
    if !(1..=MAX_SUBRUNS).contains(&max_subruns)
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
    let domain = partition / CLUSTER;
    for summary in [legacy, metadata] {
        summary.validate(domain, crate::bitmap_streaming::source_limits(domain)?)?;
        if summary.declared_clusters != domain {
            return Err(invalid("streamed retention bitmap domain differs"));
        }
    }
    u32::try_from(run.length / CLUSTER)
        .map_err(|_| invalid("retention run exceeds u32 cluster count"))?;
    let start = run.physical_offset / CLUSTER;
    let end = start + run.length / CLUSTER;
    let mut left = legacy.allocated_ranges.iter().peekable();
    let mut right = metadata.allocated_ranges.iter().peekable();
    let mut cursor = start;
    let mut free_clusters = 0u64;
    let mut subruns = Vec::new();
    let mut push_free = |begin: u64, end: u64| -> io::Result<()> {
        if begin == end {
            return Ok(());
        }
        if subruns.len() >= max_subruns {
            return Err(invalid("retention free-subrun budget exceeded"));
        }
        let count = u32::try_from(end - begin)
            .map_err(|_| invalid("retention subrun exceeds u32 cluster count"))?;
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
        Ok(())
    };
    loop {
        let next = match (left.peek(), right.peek()) {
            (Some(a), Some(b)) if a.starting_lcn <= b.starting_lcn => left.next(),
            (Some(_), Some(_)) => right.next(),
            (Some(_), None) => left.next(),
            (None, Some(_)) => right.next(),
            (None, None) => break,
        }
        .unwrap();
        if next.starting_lcn >= end {
            break;
        }
        let occupied_end = (next.starting_lcn + next.clusters).min(end);
        if occupied_end <= cursor {
            continue;
        }
        let occupied_start = next.starting_lcn.max(start);
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
