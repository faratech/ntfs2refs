//! Native occupancy views for shadow verification. No allocation ownership or
//! permission to omit filesystem structures is inferred from these bitmaps.
use crate::{
    bitmap_layout::{self, AllocationMap, Candidate},
    bitmap_paging::{self, Proof, StreamingProof},
    bitmap_streaming::Summary,
};
use std::{fs::File, io};

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) enum Observation {
    Assembled(bitmap_paging::Capture),
    Streamed { proof: Proof, summary: Summary },
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
            let collected = crate::stream_native::bitmap_streamed_collected_with_input(
                volume,
                partition / 4096,
                template,
            )?;
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
            Ok(Self::Streamed { proof, summary })
        } else {
            Ok(Self::Assembled(crate::stream_native::bitmap_capture(
                volume, template,
            )?))
        }
    }
    pub(crate) fn view(&self, partition: u64) -> io::Result<View<'_>> {
        match self {
            Self::Assembled(capture) => Ok(View::Assembled(bitmap_layout::BitmapView::new(
                &capture.bitmap,
                partition,
            )?)),
            Self::Streamed { summary, .. } => {
                summary.validate(
                    partition / 4096,
                    crate::bitmap_streaming::source_limits(partition / 4096)?,
                )?;
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
            Self::Streamed { summary, .. } => {
                self.view(partition)?;
                let mut ranges = Vec::new();
                ranges
                    .try_reserve_exact(summary.allocated_ranges.len())
                    .map_err(|_| bad("allocation range storage unavailable"))?;
                for range in &summary.allocated_ranges {
                    ranges.push(bitmap_layout::AllocatedRange {
                        offset: range.starting_lcn * 4096,
                        length: range.clusters * 4096,
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
