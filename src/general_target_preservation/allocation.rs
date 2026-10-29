//! Coverage diagnostics for a map queried inside the protected post-freeze
//! lease. Known ranges are not a complete ReFS metadata/allocator graph.
use crate::refs_write_set::ByteRange;
use anyhow::{Context, Result, ensure};
use n2r_win32::GeneralLiveRefsLayoutObservation;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProtectedAllocationCoverage {
    phase: &'static str,
    raw_shadow_sha256: String,
    metadata_bitmap_sha256: String,
    partition_bytes: u64,
    allocated_bytes: u64,
    observed_anchor_bytes: u64,
    observed_stream_extent_bytes: u64,
    anchor_observation_error: Option<String>,
    anchors_uncovered_by_bitmap: Vec<ByteRange>,
    streams_uncovered_by_bitmap: Vec<ByteRange>,
    unclassified_allocated_ranges: Vec<ByteRange>,
    complete_allocation_graph_verified: bool,
    selective_capture_executable: bool,
    source_admitted: bool,
    raw_write_authority: bool,
}

fn union(mut ranges: Vec<ByteRange>, length: u64) -> Result<Vec<ByteRange>> {
    ensure!(
        ranges.len() <= 131072,
        "allocation coverage range budget exceeded"
    );
    ranges.sort_by_key(|range| range.offset);
    let mut result: Vec<ByteRange> = Vec::new();
    for range in ranges {
        let end = range
            .offset
            .checked_add(range.length)
            .context("coverage range overflow")?;
        ensure!(
            range.length > 0
                && range.offset.is_multiple_of(4096)
                && range.length.is_multiple_of(4096)
                && end <= length,
            "coverage range escapes frozen partition"
        );
        if let Some(last) = result.last_mut()
            && range.offset <= last.offset + last.length
        {
            last.length = (last.offset + last.length).max(end) - last.offset;
        } else {
            result.push(range);
        }
    }
    Ok(result)
}

fn subtract(ranges: &[ByteRange], covered: &[ByteRange]) -> Result<Vec<ByteRange>> {
    let mut result = Vec::new();
    for range in ranges {
        let end = range.offset + range.length;
        let mut cursor = range.offset;
        let first = covered.partition_point(|item| item.offset + item.length <= cursor);
        for item in covered[first..].iter().take_while(|item| item.offset < end) {
            if cursor < item.offset {
                result.push(ByteRange {
                    offset: cursor,
                    length: item.offset - cursor,
                });
            }
            cursor = cursor.max((item.offset + item.length).min(end));
        }
        if cursor < end {
            result.push(ByteRange {
                offset: cursor,
                length: end - cursor,
            });
        }
        ensure!(
            result.len() <= 131072,
            "unclassified coverage range budget exceeded"
        );
    }
    Ok(result)
}

fn total(ranges: &[ByteRange]) -> Result<u64> {
    ranges.iter().try_fold(0u64, |sum, range| {
        sum.checked_add(range.length)
            .context("coverage byte total overflow")
    })
}

pub(super) fn reconcile(
    native: &GeneralLiveRefsLayoutObservation,
    anchors: std::result::Result<Vec<ByteRange>, String>,
    raw_shadow_sha256: &str,
    length: u64,
) -> Result<ProtectedAllocationCoverage> {
    let report = native.report().native();
    let map = report
        .metadata_allocation
        .as_ref()
        .context("protected layout metadata-inclusive allocation missing")?;
    let pages = report
        .metadata_allocation_page_proof
        .as_ref()
        .context("protected layout bitmap page proof missing")?;
    ensure!(
        map.cluster_count.checked_mul(4096) == Some(length)
            && pages.cluster_count == map.cluster_count
            && pages.canonical_bitmap_sha256 == map.bitmap_sha256,
        "protected bitmap/page receipt domain or digest differs"
    );
    let allocated = union(
        map.ranges
            .iter()
            .map(|range| ByteRange {
                offset: range.offset,
                length: range.length,
            })
            .collect(),
        length,
    )?;
    let (anchors, anchor_observation_error) = match anchors {
        Ok(ranges) => (union(ranges, length)?, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let mut streams = Vec::new();
    for object in &report.objects {
        if object.retrieval.is_empty() {
            continue;
        }
        for run in n2r_win32::stream_layout::parse_complete_retrieval(&object.retrieval)? {
            if let Some(lcn) = run.lcn {
                ensure!(
                    streams.len() < 65536,
                    "native stream coverage range budget exceeded"
                );
                streams.push(ByteRange {
                    offset: lcn
                        .checked_mul(4096)
                        .context("native extent offset overflow")?,
                    length: run
                        .clusters
                        .checked_mul(4096)
                        .context("native extent length overflow")?,
                });
            }
        }
    }
    let streams = union(streams, length)?;
    let known = union(anchors.iter().chain(&streams).copied().collect(), length)?;
    let allocated_bytes = total(&allocated)?;
    ensure!(
        map.allocated_clusters.checked_mul(4096) == Some(allocated_bytes),
        "allocation interval/count totals differ"
    );
    Ok(ProtectedAllocationCoverage {
        phase: "protected-post-freeze-readonly-native-bitmap",
        raw_shadow_sha256: raw_shadow_sha256.into(),
        metadata_bitmap_sha256: map.bitmap_sha256.clone(),
        partition_bytes: length,
        allocated_bytes,
        observed_anchor_bytes: total(&anchors)?,
        observed_stream_extent_bytes: total(&streams)?,
        anchor_observation_error,
        anchors_uncovered_by_bitmap: subtract(&anchors, &allocated)?,
        streams_uncovered_by_bitmap: subtract(&streams, &allocated)?,
        // These ranges may contain valid system trees, journals, reservations
        // and resident contents. Never infer "all metadata" by subtraction.
        unclassified_allocated_ranges: subtract(&allocated, &known)?,
        complete_allocation_graph_verified: false,
        selective_capture_executable: false,
        source_admitted: false,
        raw_write_authority: false,
    })
}
