//! Native occupancy views for shadow verification. No allocation ownership or
//! permission to omit filesystem structures is inferred from these bitmaps.
use crate::{
    bitmap_layout::{self, AllocationMap, Candidate},
    bitmap_paging::{self, Proof, StreamingProof},
    bitmap_streaming::{Limits, Summary},
};
use std::{fs::File, io};

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) enum Observation {
    Assembled(bitmap_paging::Capture),
    Streamed {
        proof: Proof,
        summary: Summary,
        limits: Limits,
        range_capacity_limit: Option<usize>,
    },
}

impl Observation {
    pub(crate) fn capture(
        volume: &File,
        template: &[u8],
        partition: u64,
        streaming: bool,
    ) -> io::Result<Self> {
        if partition == 0 || !partition.is_multiple_of(4096) {
            return Err(bad("target bitmap partition geometry differs"));
        }
        if streaming {
            Self::capture_with_limits(
                volume,
                template,
                partition,
                crate::bitmap_streaming::source_limits(partition / 4096)?,
            )
        } else {
            Ok(Self::Assembled(crate::stream_native::bitmap_capture(
                volume, template,
            )?))
        }
    }
    /// Keep the actual collection limits with the native result. Subsequent
    /// views must not silently reapply the legacy volume/range ceilings.
    pub(crate) fn capture_with_limits(
        volume: &File,
        template: &[u8],
        partition: u64,
        limits: Limits,
    ) -> io::Result<Self> {
        if partition == 0 || !partition.is_multiple_of(4096) {
            return Err(bad("target bitmap partition geometry differs"));
        }
        let collected = crate::stream_native::bitmap_streamed_with_limits(
            volume,
            partition / 4096,
            template,
            limits,
        )?;
        Self::from_collected(collected, partition, limits, None)
    }
    /// Requires the enclosing collector's actual prepaid range/query lease.
    /// Capacity checks detect excess owned allocation, not transient allocator
    /// over-allocation, so this remains an experimental accounting path.
    pub(crate) fn capture_with_bounded_ranges(
        volume: &File,
        template: &[u8],
        partition: u64,
        limits: Limits,
    ) -> io::Result<Self> {
        if partition == 0 || !partition.is_multiple_of(4096) {
            return Err(bad("target bitmap partition geometry differs"));
        }
        let capacity = limits
            .max_allocated_ranges
            .checked_mul(2)
            .ok_or_else(|| bad("target bitmap capacity envelope overflow"))?;
        let collected = crate::stream_native::bitmap_streamed_with_bounded_ranges(
            volume,
            partition / 4096,
            template,
            limits,
        )?;
        Self::from_collected(collected, partition, limits, Some(capacity))
    }
    fn from_collected(
        collected: crate::bitmap_streaming::CollectedBitmap,
        partition: u64,
        limits: Limits,
        range_capacity_limit: Option<usize>,
    ) -> io::Result<Self> {
        let (first_proof, summary) = collected.into_observation_parts();
        if summary.declared_clusters != partition / 4096 {
            return Err(bad("target bitmap domain differs from partition"));
        }
        let proof = Proof {
            encoding: summary.encoding.clone(),
            cluster_count: summary.cluster_count,
            canonical_bitmap_sha256: summary.canonical_bitmap_sha256.clone(),
            pages: vec![first_proof],
            assembly_profile: bitmap_paging::AssemblyProfile::Legacy,
            streaming: Some(StreamingProof {
                bitmap_data_sha256: summary.bitmap_data_sha256.clone(),
                page_transcript_sha256: summary.page_transcript_sha256.clone(),
                complete_page_count: summary.pages,
                returned_bytes: summary.returned_bytes,
            }),
        };
        Ok(Self::Streamed {
            proof,
            summary,
            limits,
            range_capacity_limit,
        })
    }
    pub(crate) fn view(&self, partition: u64) -> io::Result<View<'_>> {
        match self {
            Self::Assembled(capture) => Ok(View::Assembled(bitmap_layout::BitmapView::new(
                &capture.bitmap,
                partition,
            )?)),
            Self::Streamed {
                summary, limits, ..
            } => {
                summary.validate(partition / 4096, *limits)?;
                if !partition.is_multiple_of(4096) || summary.declared_clusters != partition / 4096
                {
                    return Err(bad("streamed target bitmap domain differs"));
                }
                Ok(View::Streamed(summary))
            }
        }
    }
    pub(crate) fn allocation_map(&self, partition: u64) -> io::Result<AllocationMap> {
        match self {
            Self::Assembled(capture) => bitmap_layout::allocated_ranges(&capture.bitmap, partition),
            Self::Streamed {
                summary,
                range_capacity_limit,
                ..
            } => {
                self.view(partition)?;
                let mut ranges = Vec::new();
                ranges
                    .try_reserve_exact(summary.allocated_ranges.len())
                    .map_err(|_| bad("allocation range storage unavailable"))?;
                if range_capacity_limit.is_some_and(|maximum| ranges.capacity() > maximum) {
                    return Err(bad(
                        "allocation map actual capacity exceeds prepaid envelope",
                    ));
                }
                for range in &summary.allocated_ranges {
                    ranges.push(bitmap_layout::AllocatedRange {
                        offset: range
                            .starting_lcn
                            .checked_mul(4096)
                            .ok_or_else(|| bad("allocation range offset overflow"))?,
                        length: range
                            .clusters
                            .checked_mul(4096)
                            .ok_or_else(|| bad("allocation range length overflow"))?,
                    });
                }
                Ok(AllocationMap {
                    bitmap_sha256: summary.canonical_bitmap_sha256.clone(),
                    cluster_count: summary.cluster_count,
                    allocated_clusters: summary.allocated_clusters,
                    ranges,
                })
            }
        }
    }
    pub(crate) fn proof(&self) -> Proof {
        match self {
            Self::Assembled(capture) => capture.proof.clone(),
            Self::Streamed { proof, .. } => proof.clone(),
        }
    }

    pub(crate) fn retention_planner<'a>(
        &'a self,
        metadata: &'a Self,
        partition: u64,
    ) -> io::Result<RetentionPlanner<'a>> {
        match (self, metadata) {
            (Self::Assembled(a), Self::Assembled(b)) => Ok(RetentionPlanner::Assembled {
                legacy: &a.bitmap,
                metadata: &b.bitmap,
                partition,
            }),
            (Self::Streamed { summary: a, .. }, Self::Streamed { summary: b, .. }) => {
                Ok(RetentionPlanner::Streamed(
                    crate::retention_layout::StreamedPlanner::new(a, b, partition)?,
                ))
            }
            _ => Err(bad("retention bitmap observation profiles differ")),
        }
    }

    pub(crate) fn plan_free_subruns(
        &self,
        metadata: &Self,
        run: crate::retention_layout::SourceRun,
        partition: u64,
        max_subruns: usize,
    ) -> io::Result<crate::retention_layout::Plan> {
        self.retention_planner(metadata, partition)?
            .plan(run, max_subruns)
    }
}

pub(crate) enum RetentionPlanner<'a> {
    Assembled {
        legacy: &'a [u8],
        metadata: &'a [u8],
        partition: u64,
    },
    Streamed(crate::retention_layout::StreamedPlanner<'a>),
}

impl RetentionPlanner<'_> {
    pub(crate) fn plan(
        &self,
        run: crate::retention_layout::SourceRun,
        max_subruns: usize,
    ) -> io::Result<crate::retention_layout::Plan> {
        match self {
            Self::Assembled {
                legacy,
                metadata,
                partition,
            } => crate::retention_layout::plan_free_subruns(
                legacy,
                metadata,
                run,
                *partition,
                max_subruns,
            ),
            Self::Streamed(planner) => planner.plan(run, max_subruns),
        }
    }
}

pub(crate) enum View<'a> {
    Assembled(bitmap_layout::BitmapView<'a>),
    Streamed(&'a Summary),
}
impl View<'_> {
    pub(crate) fn candidate(&self, offset: u64, length: u64) -> io::Result<Candidate> {
        match self {
            Self::Assembled(view) => view.candidate(offset, length),
            Self::Streamed(summary) => {
                if !offset.is_multiple_of(4096) || length == 0 || !length.is_multiple_of(4096) {
                    return Err(bad("target candidate geometry differs"));
                }
                let start = offset / 4096;
                let clusters = length / 4096;
                let end = start
                    .checked_add(clusters)
                    .filter(|end| *end <= summary.cluster_count)
                    .ok_or_else(|| bad("target candidate escapes bitmap"))?;
                let first = summary
                    .allocated_ranges
                    .partition_point(|range| range.starting_lcn + range.clusters <= start);
                let mut allocated = 0;
                for range in summary.allocated_ranges[first..]
                    .iter()
                    .take_while(|range| range.starting_lcn < end)
                {
                    allocated += (range.starting_lcn + range.clusters).min(end)
                        - range.starting_lcn.max(start);
                }
                Ok(Candidate {
                    start_lcn: start,
                    clusters,
                    declared_clusters: summary.declared_clusters,
                    allocated_clusters: allocated,
                    bitmap_sha256: summary.canonical_bitmap_sha256.clone(),
                })
            }
        }
    }
}
