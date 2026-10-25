//! Read-only source payload classification for a 4 KiB ReFS target. This is
//! not namespace admission or a target allocation/write plan.
use crate::ntfs_inspect::{Extent, LogicalHashStatus, MetadataRole, NtfsInspection};
use serde::Serialize;

const CLUSTER: u64 = 4096;
const MAX_MATERIALIZE: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    RetainCandidate,
    MaterializeCandidate,
    Reject,
}

#[derive(Debug, Serialize)]
pub struct StreamDecision {
    pub record_number: u64,
    pub sequence_number: u16,
    pub name_utf16: Vec<u16>,
    pub logical_bytes: u64,
    pub logical_sha256: Option<String>,
    pub source_offset: Option<u64>,
    /// Physical runs for a fully initialized ordinary stream with more than
    /// one NTFS run. Empty for single-run or materialized streams.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_extents: Vec<Extent>,
    pub disposition: Disposition,
    pub target_named_stream_support_pending: bool,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub profile: &'static str,
    pub streams: Vec<StreamDecision>,
    pub retained_candidate_bytes: u64,
    pub materialized_candidate_bytes: u64,
    pub rejected_streams: usize,
    pub source_admitted: bool,
    pub executable: bool,
}

pub fn classify(raw: &NtfsInspection) -> Plan {
    let mut plan = Plan {
        schema_version: 1,
        profile: "ntfs-4k-to-refs-4k-source-streams-v1",
        streams: Vec::new(),
        retained_candidate_bytes: 0,
        materialized_candidate_bytes: 0,
        rejected_streams: 0,
        source_admitted: false,
        executable: false,
    };
    for file in raw
        .files
        .iter()
        .filter(|f| !f.is_directory && f.metadata_role == MetadataRole::OutsideExtendCandidate)
    {
        for stream in &file.streams {
            let named = !stream.name_utf16.is_empty();
            let complete = stream.logical_hash_status == LogicalHashStatus::Complete
                && stream.logical_sha256.as_ref().is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                });
            let single = stream.extents.first().filter(|_| stream.extents.len() == 1);
            let physical = single.and_then(|e| e.physical_offset);
            let mut covered = 0u64;
            let physical_runs = !stream.extents.is_empty()
                && stream.extents.len() <= 1024
                && stream.extents.iter().all(|extent| {
                    let valid = extent.logical_offset == covered
                        && extent.length > 0
                        && extent.length.is_multiple_of(CLUSTER)
                        && extent.physical_offset.is_some_and(|offset| {
                            offset.is_multiple_of(CLUSTER)
                                && offset
                                    .checked_add(extent.length)
                                    .is_some_and(|end| end <= raw.geometry.volume_size)
                        });
                    covered = covered.saturating_add(extent.length);
                    valid
                })
                && covered == stream.logical_size;
            let retainable = !named
                && !stream.resident
                && stream.flags == 0
                && stream.logical_size > 0
                && stream.logical_size.is_multiple_of(CLUSTER)
                && stream.initialized_size == stream.logical_size
                && stream.allocated_size == stream.logical_size
                && physical_runs;
            let (disposition, reason) = if u64::from(raw.geometry.cluster_size) != CLUSTER
                || stream.flags != 0
                || !complete
                || stream.logical_size > MAX_MATERIALIZE
            {
                (
                    Disposition::Reject,
                    "source geometry, encoding, logical hash or bounded copy is unsupported",
                )
            } else if retainable {
                (
                    Disposition::RetainCandidate,
                    "initialized aligned physical runs may be adopted",
                )
            } else {
                (
                    Disposition::MaterializeCandidate,
                    "logical stream requires new ReFS allocation or inline data",
                )
            };
            match disposition {
                Disposition::RetainCandidate => {
                    plan.retained_candidate_bytes += stream.logical_size;
                }
                Disposition::MaterializeCandidate => {
                    plan.materialized_candidate_bytes += stream.logical_size;
                }
                Disposition::Reject => plan.rejected_streams += 1,
            }
            plan.streams.push(StreamDecision {
                record_number: file.record_number,
                sequence_number: file.sequence_number,
                name_utf16: stream.name_utf16.clone(),
                logical_bytes: stream.logical_size,
                logical_sha256: stream.logical_sha256.clone(),
                source_offset: if disposition == Disposition::RetainCandidate {
                    physical
                } else {
                    None
                },
                source_extents: if disposition == Disposition::RetainCandidate && single.is_none() {
                    stream.extents.clone()
                } else {
                    Vec::new()
                },
                disposition,
                target_named_stream_support_pending: named,
                reason,
            });
        }
    }
    plan
}
