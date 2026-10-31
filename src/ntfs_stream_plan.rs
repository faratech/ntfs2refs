//! Read-only source payload classification for a 4 KiB ReFS target. This is
//! not namespace admission or a target allocation/write plan.
use crate::{
    ntfs_admission::ResourceProfile,
    ntfs_inspect::{
        Extent, FileInventory, LogicalHashStatus, MetadataRole, NtfsInspection, StreamInventory,
    },
};
use anyhow::{Context, Result, ensure};
use n2r_win32::sparse_layout::{LogicalRange, SparseLayout};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse: Option<SparseLayout>,
    pub disposition: Disposition,
    pub target_named_stream_support_pending: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub target_sparse_support_pending: bool,
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
    #[serde(default, skip_serializing_if = "is_zero")]
    pub sparse_streams: usize,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    /// Allocated sparse clusters through rounded EOF, not the NTFS header's
    /// allocation field or any unused physical reservation beyond EOF.
    pub sparse_allocated_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sparse_zero_logical_bytes: u64,
    pub source_admitted: bool,
    pub executable: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}
fn is_zero(value: &usize) -> bool {
    *value == 0
}
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

struct SparseCandidate {
    layout: SparseLayout,
    initialized_extents: Vec<Extent>,
    retained: u64,
    materialized: u64,
    zero_logical: u64,
    allocated: u64,
}

fn sparse_candidate(
    raw: &NtfsInspection,
    file: &FileInventory,
    stream: &StreamInventory,
) -> Result<SparseCandidate> {
    ensure!(
        !stream.resident
            && stream.flags == 0x8000
            && stream.initialized_size <= stream.logical_size,
        "unsupported sparse source form"
    );
    let attributes: Vec<_> = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x80 && a.name_utf16 == stream.name_utf16)
        .collect();
    let [attribute] = attributes.as_slice() else {
        anyhow::bail!("sparse stream attribute is ambiguous or missing");
    };
    ensure!(
        attribute.flags == stream.flags
            && !attribute.resident
            && attribute.lowest_vcn == 0
            && matches!(attribute.compression_unit, 0 | 4)
            && attribute.extents == stream.extents
            && attribute.logical_size == stream.logical_size
            && attribute.initialized_size == stream.initialized_size
            && attribute.allocated_size == stream.allocated_size,
        "sparse stream inventory differs from its attribute"
    );
    let cluster = u64::from(raw.geometry.cluster_size);
    ensure!(
        cluster >= CLUSTER && cluster.is_multiple_of(CLUSTER),
        "sparse source geometry differs"
    );
    let rounded = stream
        .logical_size
        .checked_next_multiple_of(CLUSTER)
        .context("sparse EOF overflow")?;
    let initialized_end = stream.initialized_size / CLUSTER * CLUSTER;
    let mut coverage = 0u64;
    let mut physical_bytes = 0u64;
    let mut physical_ranges = Vec::new();
    let mut allocated = Vec::new();
    let mut initialized_extents = Vec::new();
    let mut initialized_data = 0u64;
    let mut retained = 0u64;
    for extent in &stream.extents {
        ensure!(
            extent.logical_offset == coverage
                && extent.length > 0
                && extent.length.is_multiple_of(cluster),
            "sparse source mapping has a gap or invalid run"
        );
        coverage = coverage
            .checked_add(extent.length)
            .context("sparse logical coverage overflow")?;
        if let Some(offset) = extent.physical_offset {
            ensure!(
                offset.is_multiple_of(cluster)
                    && offset
                        .checked_add(extent.length)
                        .is_some_and(|end| end <= raw.geometry.volume_size),
                "sparse physical run escapes the source"
            );
            physical_bytes = physical_bytes
                .checked_add(extent.length)
                .context("sparse physical byte overflow")?;
            physical_ranges.push((offset, extent.length));
            if extent.logical_offset < rounded {
                allocated.push(LogicalRange {
                    offset: extent.logical_offset,
                    length: extent.length.min(rounded - extent.logical_offset),
                });
            }
            let logical_end = coverage
                .min(stream.logical_size)
                .min(stream.initialized_size);
            if logical_end > extent.logical_offset {
                initialized_data = initialized_data
                    .checked_add(logical_end - extent.logical_offset)
                    .context("sparse initialized byte overflow")?;
            }
            let retained_end = coverage.min(initialized_end);
            if retained_end > extent.logical_offset {
                let length = retained_end - extent.logical_offset;
                initialized_extents.push(Extent {
                    logical_offset: extent.logical_offset,
                    physical_offset: Some(offset),
                    length,
                });
                retained = retained
                    .checked_add(length)
                    .context("sparse retained byte overflow")?;
            }
        }
    }
    ensure!(
        coverage >= stream.logical_size
            && stream.allocated_size.is_multiple_of(cluster)
            && physical_bytes <= stream.allocated_size
            && stream.allocated_size <= coverage,
        "sparse header allocation differs from physical and logical coverage"
    );
    physical_ranges.sort_unstable();
    ensure!(
        physical_ranges
            .windows(2)
            .all(|p| p[0].0.checked_add(p[0].1).is_some_and(|end| end <= p[1].0)),
        "sparse source physical runs overlap"
    );
    let layout =
        SparseLayout::from_allocated(stream.logical_size, stream.initialized_size, allocated)?;
    let allocated = layout.allocated_bytes()?;
    Ok(SparseCandidate {
        layout,
        initialized_extents,
        retained,
        materialized: initialized_data
            .checked_sub(retained)
            .context("sparse initialized accounting differs")?,
        zero_logical: stream
            .logical_size
            .checked_sub(initialized_data)
            .context("sparse zero accounting differs")?,
        allocated,
    })
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
        sparse_streams: 0,
        sparse_allocated_bytes: 0,
        sparse_zero_logical_bytes: 0,
        source_admitted: false,
        executable: false,
    };
    let mut accepted_logical_bytes = 0u64;
    for (file_index, file) in raw
        .files
        .iter()
        .filter(|f| !f.is_directory && f.metadata_role == MetadataRole::OutsideExtendCandidate)
        .enumerate()
    {
        for stream in &file.streams {
            let named = !stream.name_utf16.is_empty();
            let sparse_requested = stream.flags == 0x8000;
            let compressed = crate::ntfs_admission::compressed_stream_supported(raw, file, stream);
            let sparse = sparse_requested
                .then(|| sparse_candidate(raw, file, stream))
                .and_then(|value| value.ok());
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
            let adoptable_prefix = !stream.resident
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
                || (stream.flags != 0 && sparse.is_none() && !compressed)
                || (named && !crate::ntfs_admission::valid_named_stream_name(&stream.name_utf16))
                || plan.streams.len() >= crate::ntfs_admission::MAX_DATA_STREAMS
                || !complete
                || stream.logical_size > limits.maximum_stream_bytes
                || (resources != ResourceProfile::AlphaV1 && file_index >= limits.maximum_files)
            {
                (
                    Disposition::Reject,
                    "source geometry, encoding, logical hash or bounded copy is unsupported",
                )
            } else if compressed {
                (
                    Disposition::MaterializeCandidate,
                    "NTFS LZNT1 is decoded and rewritten as ordinary ReFS data; compressed physical bytes cannot be adopted",
                )
            } else if let Some(sparse) = &sparse {
                (
                    if sparse.retained == stream.logical_size {
                        Disposition::RetainCandidate
                    } else {
                        Disposition::MixedCandidate
                    },
                    "sparse physical islands may be retained; holes and VDL zeros remain logical absence",
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
            let increment = if let Some(sparse) = &sparse {
                (sparse.retained, sparse.materialized)
            } else {
                match disposition {
                    Disposition::RetainCandidate => (stream.logical_size, 0),
                    Disposition::MixedCandidate => (full_prefix, stream.logical_size - full_prefix),
                    Disposition::MaterializeCandidate => (0, stream.logical_size),
                    Disposition::Reject => (0, 0),
                }
            };
            let next_logical = accepted_logical_bytes
                .checked_add(stream.logical_size)
                .filter(|total| {
                    resources == ResourceProfile::AlphaV1 || *total <= limits.maximum_logical_bytes
                });
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
            let next_sparse = sparse.as_ref().map(|sparse| {
                plan.sparse_allocated_bytes
                    .checked_add(sparse.allocated)
                    .zip(
                        plan.sparse_zero_logical_bytes
                            .checked_add(sparse.zero_logical),
                    )
            });
            if next_totals.is_none()
                || next_logical.is_none()
                || next_sparse.is_some_and(|n| n.is_none())
            {
                disposition = Disposition::Reject;
                reason = "candidate byte totals overflow or exceed the explicit resource profile";
            }
            if disposition == Disposition::Reject {
                plan.rejected_streams = plan.rejected_streams.saturating_add(1);
            } else if let Some((retained, materialized)) = next_totals {
                accepted_logical_bytes = next_logical.unwrap();
                plan.retained_candidate_bytes = retained;
                plan.materialized_candidate_bytes = materialized;
                if let Some(Some((allocated, zeros))) = next_sparse {
                    plan.sparse_streams += 1;
                    plan.sparse_allocated_bytes = allocated;
                    plan.sparse_zero_logical_bytes = zeros;
                }
            }
            plan.streams.push(StreamDecision {
                record_number: file.record_number,
                sequence_number: file.sequence_number,
                name_utf16: stream.name_utf16.clone(),
                logical_bytes: stream.logical_size,
                logical_sha256: stream.logical_sha256.clone(),
                source_offset: if disposition == Disposition::RetainCandidate && sparse.is_none() {
                    physical
                } else {
                    None
                },
                source_extents: if disposition == Disposition::Reject {
                    Vec::new()
                } else if let Some(sparse) = &sparse {
                    sparse.initialized_extents.clone()
                } else if disposition == Disposition::MixedCandidate
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
                sparse: sparse.as_ref().map(|s| s.layout.clone()),
                disposition,
                target_named_stream_support_pending: false,
                target_sparse_support_pending: false,
                reason: reason.into(),
            });
        }
    }
    plan
}
