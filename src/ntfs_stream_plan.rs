//! Read-only source payload classification for a 4 KiB ReFS target. This is
//! not namespace admission or a target allocation/write plan.
use crate::{
    ntfs_admission::ResourceProfile,
    ntfs_inspect::{Extent, LogicalHashStatus, MetadataRole, NtfsInspection},
};
use serde::{Deserialize, Serialize};

const CLUSTER: u64 = 4096;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    RetainCandidate,
    MixedCandidate,
    MaterializeCandidate,
    Reject,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamDecision {
    pub record_number: u64,
    pub sequence_number: u16,
    pub name_utf16: Vec<u16>,
    pub logical_bytes: u64,
    pub logical_sha256: Option<String>,
    pub source_offset: Option<u64>,
    /// Complete physical clusters before both EOF and valid-data length.
    /// Partial or uninitialized tail bytes must be materialized.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_extents: Vec<Extent>,
    pub disposition: Disposition,
    pub target_named_stream_support_pending: bool,
    pub reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub profile: String,
    pub streams: Vec<StreamDecision>,
    pub retained_candidate_bytes: u64,
    pub materialized_candidate_bytes: u64,
    pub rejected_streams: usize,
    pub source_admitted: bool,
    pub executable: bool,
}

pub fn classify(raw: &NtfsInspection) -> Plan {
    classify_with_resource_profile(raw, ResourceProfile::AlphaV1)
}

/// Explicit larger resource planning only; named/encoded semantics and actual
/// target ownership remain separate, and this report never authorizes writes.
pub fn classify_with_resource_profile(raw: &NtfsInspection, resources: ResourceProfile) -> Plan {
    let limits = resources.limits();
    let mut plan = Plan {
        schema_version: if resources == ResourceProfile::AlphaV1 {
            4
        } else {
            5
        },
        profile: if resources == ResourceProfile::AlphaV1 {
            "ntfs-4k-to-refs-4k-source-streams-v4"
        } else {
            "ntfs-aligned-to-refs-4k-large-source-streams-v1"
        }
        .into(),
        streams: Vec::new(),
        retained_candidate_bytes: 0,
        materialized_candidate_bytes: 0,
        rejected_streams: 0,
        source_admitted: false,
        executable: false,
    };
    for (file_index, file) in raw
        .files
        .iter()
        .filter(|f| !f.is_directory && f.metadata_role == MetadataRole::OutsideExtendCandidate)
        .enumerate()
    {
        for stream in &file.streams {
            let named = !stream.name_utf16.is_empty();
            let complete = stream.logical_hash_status == LogicalHashStatus::Complete
                && stream
                    .logical_sha256
                    .as_ref()
                    .is_some_and(|hash| n2r_win32::content_digest::is_hex(hash));
            let single = stream.extents.first().filter(|_| stream.extents.len() == 1);
            let physical = single.and_then(|e| e.physical_offset);
            let full_prefix = stream.initialized_size.min(stream.logical_size) / CLUSTER * CLUSTER;
            let rounded = stream.logical_size.checked_next_multiple_of(CLUSTER);
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
                    let Some(next) = covered.checked_add(extent.length) else {
                        return false;
                    };
                    covered = next;
                    valid
                })
                && covered == stream.allocated_size;
            let adoptable_prefix = !named
                && !stream.resident
                && stream.flags == 0
                && full_prefix > 0
                && stream.initialized_size <= stream.logical_size
                // NTFS may reserve clusters beyond logical EOF. Account for
                // the complete physical allocation, but retain only full
                // initialized logical clusters, never the unused reservation.
                && rounded.is_some_and(|minimum| {
                    stream.allocated_size >= minimum
                        && stream.allocated_size.is_multiple_of(CLUSTER)
                })
                && physical_runs;
            let (mut disposition, mut reason) = if !resources
                .supports_source_geometry(&raw.geometry)
                || stream.flags != 0
                || !complete
                || stream.logical_size > limits.maximum_stream_bytes
                || (resources != ResourceProfile::AlphaV1 && file_index >= limits.maximum_files)
            {
                (
                    Disposition::Reject,
                    "source geometry, encoding, logical hash or bounded copy is unsupported",
                )
            } else if adoptable_prefix && full_prefix == stream.logical_size {
                (
                    Disposition::RetainCandidate,
                    "initialized aligned physical runs may be adopted",
                )
            } else if adoptable_prefix {
                (
                    Disposition::MixedCandidate,
                    "complete initialized physical clusters may be retained; partial or uninitialized tail must be materialized",
                )
            } else {
                (
                    Disposition::MaterializeCandidate,
                    "logical stream requires new ReFS allocation or inline data",
                )
            };
            let increment = match disposition {
                Disposition::RetainCandidate => (stream.logical_size, 0),
                Disposition::MixedCandidate => (full_prefix, stream.logical_size - full_prefix),
                Disposition::MaterializeCandidate => (0, stream.logical_size),
                Disposition::Reject => (0, 0),
            };
            let next_totals = plan
                .retained_candidate_bytes
                .checked_add(increment.0)
                .zip(plan.materialized_candidate_bytes.checked_add(increment.1))
                .filter(|(retained, materialized)| {
                    retained.checked_add(*materialized).is_some_and(|total| {
                        resources == ResourceProfile::AlphaV1
                            || total <= limits.maximum_logical_bytes
                    })
                });
            if next_totals.is_none() {
                disposition = Disposition::Reject;
                reason = "candidate byte totals overflow or exceed the explicit resource profile";
            }
            if disposition == Disposition::Reject {
                plan.rejected_streams = plan.rejected_streams.saturating_add(1);
            } else if let Some((retained, materialized)) = next_totals {
                plan.retained_candidate_bytes = retained;
                plan.materialized_candidate_bytes = materialized;
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
                source_extents: if disposition == Disposition::MixedCandidate
                    || (disposition == Disposition::RetainCandidate && single.is_none())
                {
                    stream
                        .extents
                        .iter()
                        .filter_map(|extent| {
                            (extent.logical_offset < full_prefix).then(|| Extent {
                                logical_offset: extent.logical_offset,
                                physical_offset: extent.physical_offset,
                                length: extent.length.min(full_prefix - extent.logical_offset),
                            })
                        })
                        .collect()
                } else {
                    Vec::new()
                },
                disposition,
                target_named_stream_support_pending: named,
                reason: reason.into(),
            });
        }
    }
    plan
}
