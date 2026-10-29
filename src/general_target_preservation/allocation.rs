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

/// Retrospective size accounting over an already completed full capture.
/// Neither category proves that a changed byte is safe to omit.
#[derive(Debug, Serialize)]
pub struct CapturedDeltaAllocationDiagnostic {
    changed_bytes: u64,
    changed_in_observed_bitmap_or_known_ranges: u64,
    changed_outside_observed_bitmap_and_known_ranges: u64,
    hypothetical_packed_bytes_avoided: u64,
    hypothetical_journal_payload_bytes_avoided: u64,
    known_anchor_observation_complete: bool,
    allocation_graph_complete: bool,
    selective_capture_executable: bool,
    raw_write_authority: bool,
}

impl ProtectedAllocationCoverage {
    /// Compare actual full-capture ranges with the bitmap and known anchor and
    /// stream ranges already held by the protected layout. This performs no disk
    /// I/O and does not assert that bitmap-free bytes are unused by ReFS.
    pub(crate) fn classify_capture(
        &self,
        native: &GeneralLiveRefsLayoutObservation,
        layout: &crate::refs_hybrid::delta::DeltaLayout,
    ) -> Result<CapturedDeltaAllocationDiagnostic> {
        ensure!(
            layout.partition_bytes() == self.partition_bytes,
            "delta diagnostic partition binding differs"
        );
        let observed = self.observed_ranges(native)?;
        let changed = union(
            layout
                .intervals()
                .iter()
                .map(|range| ByteRange {
                    offset: range.offset,
                    length: range.length,
                })
                .collect(),
            self.partition_bytes,
        )?;
        let changed_bytes = total(&changed)?;
        ensure!(
            changed_bytes == layout.changed_bytes(),
            "delta byte total differs"
        );
        let outside = total(&subtract(&changed, &observed)?)?;
        Ok(CapturedDeltaAllocationDiagnostic {
            changed_bytes,
            changed_in_observed_bitmap_or_known_ranges: changed_bytes - outside,
            changed_outside_observed_bitmap_and_known_ranges: outside,
            hypothetical_packed_bytes_avoided: outside,
            hypothetical_journal_payload_bytes_avoided: outside
                .checked_mul(2)
                .context("hypothetical journal payload total overflow")?,
            known_anchor_observation_complete: self.anchor_observation_error.is_none(),
            allocation_graph_complete: false,
            selective_capture_executable: false,
            raw_write_authority: false,
        })
    }
}

impl ProtectedAllocationCoverage {
    /// The bitmap's allocated ranges plus known anchors and stream extents
    /// outside it, sorted and coalesced. Held from the protected observation;
    /// performs no disk I/O and is not a complete allocation graph.
    pub(crate) fn observed_ranges(
        &self,
        native: &GeneralLiveRefsLayoutObservation,
    ) -> Result<Vec<ByteRange>> {
        let map = native
            .report()
            .native()
            .metadata_allocation
            .as_ref()
            .context("protected allocation bitmap absent")?;
        ensure!(
            map.bitmap_sha256 == self.metadata_bitmap_sha256
                && map.cluster_count.checked_mul(4096) == Some(self.partition_bytes),
            "allocation diagnostic bitmap or partition binding differs"
        );
        let allocated = map.ranges.iter().map(|range| ByteRange {
            offset: range.offset,
            length: range.length,
        });
        // Known anchors and stream extents outside the bitmap remain included.
        union(
            allocated
                .chain(self.anchors_uncovered_by_bitmap.iter().copied())
                .chain(self.streams_uncovered_by_bitmap.iter().copied())
                .collect(),
            self.partition_bytes,
        )
    }
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
