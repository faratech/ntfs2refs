//! One conservative source decision over existing independent reconciliations.
//! This report is not a certificate and cannot arm an executor. Frozen-device,
//! backup/log and target-preservation evidence must precede that capability.
use crate::{
    ntfs_attestation::Comparison,
    ntfs_inspect::{self as ntfs, AttributeInventory, FileInventory, MetadataRole},
    ntfs_namespace, ntfs_security,
};
#[cfg(windows)]
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
pub(crate) mod paged;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PROFILE: &str = "existing-data-tree-v1";
pub const ORDINARY_PROFILE: &str = "ordinary-data-tree-v2";
/// Source sparse metadata can be modeled before the native sparse graph is
/// connected; that does not make a sparse source eligible for conversion.

/// Conservative Win32 DATA-stream names, preserved as their exact UTF-16.
/// Device basenames are not relevant after the file's stream separator, but
/// path separators, stream separators, wildcards and normalization tails are.
pub fn valid_named_stream_name(name: &[u16]) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let Ok(text) = String::from_utf16(name) else {
        return false;
    };
    !text.ends_with([' ', '.'])
        && text
            .chars()
            .all(|c| !c.is_control() && !"<>:\"/\\|?*".contains(c))
}

/// Encoded bytes are never retained as ReFS payload. This recognizes only a
/// fully mapped NTFS stream whose logical reader can decode the source form.
pub(crate) fn compressed_stream_supported(
    raw: &ntfs::NtfsInspection,
    file: &FileInventory,
    stream: &ntfs::StreamInventory,
) -> bool {
    compressed_stream_supported_with_geometry(&raw.geometry, file, stream)
}

pub(crate) fn compressed_stream_supported_with_geometry(
    geometry: &ntfs::NtfsGeometry,
    file: &FileInventory,
    stream: &ntfs::StreamInventory,
) -> bool {
    if stream.flags != 1 {
        return false;
    }
    let mut attributes = file.attributes.iter().filter(|attribute| {
        attribute.type_code == 0x80 && attribute.name_utf16 == stream.name_utf16
    });
    let Some(attribute) = attributes.next() else {
        return false;
    };
    attributes.next().is_none()
        && attribute.resident == stream.resident
        && attribute.flags == stream.flags
        && attribute.logical_size == stream.logical_size
        && attribute.initialized_size == stream.initialized_size
        && attribute.allocated_size == stream.allocated_size
        && attribute.extents == stream.extents
        && crate::ntfs_compression::supported(attribute, geometry).is_ok()
}
pub const MAX_FILES: usize = 128;
pub const MAX_DIRECTORIES: usize = 32;
pub const MAX_LOGICAL_BYTES: u64 = 256 * 1024 * 1024;
/// Canonical default-plus-named DATA stream identities across the whole tree.
pub const MAX_DATA_STREAMS: usize = 16_384;

/// Explicit source/tree budgets, independent of journal format or capacity.
/// Selecting a larger profile supplies no native evidence or certificate.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProfile {
    #[default]
    AlphaV1,
    ExperimentalLargeTreeV1,
    ExperimentalStreamingTreeV2,
    ExperimentalObjectEnvelopeV3(Option<n2r_win32::tree_resources::CountAdmission>),
    ResourceBoundedV4(Option<n2r_win32::tree_resources::SourceResourceAdmission>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub maximum_files: usize,
    /// Includes the root directory.
    pub maximum_directories: usize,
    pub maximum_logical_bytes: u64,
    pub maximum_stream_bytes: u64,
}

impl ResourceProfile {
    /// Source allocation units are independent of the ReFS target's. A run
    /// that does not lie on the target's cluster boundaries cannot stay where
    /// it is: the stream plan copies such a stream instead of retaining it.
    pub fn supports_source_geometry(self, geometry: &ntfs::NtfsGeometry) -> bool {
        matches!(geometry.bytes_per_sector, 512 | 4096)
            && matches!(geometry.file_record_size, 1024 | 4096)
            && crate::ntfs_index::supports_index_record_size(geometry.index_record_size)
            && match self {
                Self::AlphaV1 => geometry.cluster_size == 4096,
                Self::ExperimentalLargeTreeV1
                | Self::ExperimentalStreamingTreeV2
                | Self::ExperimentalObjectEnvelopeV3(_)
                | Self::ResourceBoundedV4(_) => {
                    crate::ntfs_index::supports_cluster_size(geometry.cluster_size)
                }
            }
    }

    pub const fn native_profile(self) -> Option<n2r_win32::attestation::ResourceProfile> {
        match self {
            Self::AlphaV1 => None,
            Self::ExperimentalLargeTreeV1 => {
                Some(n2r_win32::attestation::ResourceProfile::ExperimentalLargeTreeV1)
            }
            Self::ExperimentalStreamingTreeV2 => {
                Some(n2r_win32::attestation::ResourceProfile::ExperimentalStreamingTreeV2)
            }
            Self::ExperimentalObjectEnvelopeV3(admission) => Some(
                n2r_win32::attestation::ResourceProfile::ExperimentalObjectEnvelopeV3(admission),
            ),
            Self::ResourceBoundedV4(admission) => Some(
                n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(admission),
            ),
        }
    }

    pub fn limits(self) -> ResourceLimits {
        match self {
            Self::AlphaV1 => ResourceLimits {
                maximum_files: MAX_FILES,
                maximum_directories: MAX_DIRECTORIES,
                maximum_logical_bytes: MAX_LOGICAL_BYTES,
                maximum_stream_bytes: MAX_LOGICAL_BYTES,
            },
            Self::ExperimentalLargeTreeV1 => ResourceLimits {
                maximum_files: 1024,
                maximum_directories: 256,
                maximum_logical_bytes: 4 * 1024 * 1024 * 1024,
                maximum_stream_bytes: 4 * 1024 * 1024 * 1024,
            },
            Self::ExperimentalStreamingTreeV2 => ResourceLimits {
                maximum_files: 1024,
                maximum_directories: 256,
                maximum_logical_bytes: n2r_win32::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES,
                maximum_stream_bytes: n2r_win32::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES,
            },
            Self::ExperimentalObjectEnvelopeV3(admission) => ResourceLimits {
                maximum_files: match admission {
                    Some(a) => a.files as usize,
                    None => n2r_win32::tree_resources::RAW_IDENTITIES,
                },
                maximum_directories: match admission {
                    Some(a) => a.directories as usize,
                    None => n2r_win32::tree_resources::RAW_IDENTITIES,
                },
                maximum_logical_bytes: n2r_win32::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES,
                maximum_stream_bytes: n2r_win32::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES,
            },
            Self::ResourceBoundedV4(admission) => {
                let Some(admission) = admission.filter(|value| value.validate().is_ok()) else {
                    return ResourceLimits {
                        maximum_files: 0,
                        maximum_directories: 0,
                        maximum_logical_bytes: 0,
                        maximum_stream_bytes: 0,
                    };
                };
                ResourceLimits {
                    maximum_files: usize::try_from(admission.files).unwrap_or(0),
                    maximum_directories: usize::try_from(admission.directories).unwrap_or(0),
                    maximum_logical_bytes: i64::MAX as u64,
                    maximum_stream_bytes: i64::MAX as u64,
                }
            }
        }
    }

    pub const fn ordinary_admission_profile(self) -> &'static str {
        match self {
            Self::AlphaV1 => ORDINARY_PROFILE,
            Self::ExperimentalLargeTreeV1 => "ordinary-data-tree-large-v1",
            Self::ExperimentalStreamingTreeV2 => "ordinary-data-tree-streaming-v2",
            Self::ExperimentalObjectEnvelopeV3(_) => "ordinary-data-tree-object-envelope-v3",
            Self::ResourceBoundedV4(_) => "ordinary-data-tree-resource-bounded-v4",
        }
    }

    pub const fn ordinary_shadow_profile(self) -> &'static str {
        match self {
            Self::AlphaV1 => "native-ordinary-tree-shadow-v2",
            Self::ExperimentalLargeTreeV1 => "native-ordinary-tree-shadow-large-v1",
            Self::ExperimentalStreamingTreeV2 => "native-ordinary-tree-shadow-streaming-v2",
            Self::ExperimentalObjectEnvelopeV3(_) => {
                "native-ordinary-tree-shadow-object-envelope-v3"
            }
            Self::ResourceBoundedV4(_) => "native-ordinary-tree-shadow-resource-bounded-v4",
        }
    }

    pub const fn is_streaming(self) -> bool {
        matches!(
            self,
            Self::ExperimentalStreamingTreeV2
                | Self::ExperimentalObjectEnvelopeV3(_)
                | Self::ResourceBoundedV4(_)
        )
    }
    pub const fn is_envelope(self) -> bool {
        matches!(self, Self::ExperimentalObjectEnvelopeV3(_))
    }
    pub fn maximum_objects(self) -> usize {
        match self {
            Self::ResourceBoundedV4(Some(admission)) if admission.validate().is_ok() => admission
                .objects()
                .ok()
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0),
            Self::ResourceBoundedV4(_) => 0,
            Self::ExperimentalObjectEnvelopeV3(Some(a)) if a.requires_paged_metadata() => {
                (a.object_slots as usize).min(n2r_win32::tree_resources::RAW_IDENTITIES)
            }
            Self::ExperimentalObjectEnvelopeV3(None) => n2r_win32::tree_resources::RAW_IDENTITIES,
            Self::ExperimentalObjectEnvelopeV3(Some(_)) => n2r_win32::tree_resources::OBJECT_SLOTS,
            _ => self.limits().maximum_files + self.limits().maximum_directories,
        }
    }
    pub fn count_admission(
        self,
    ) -> anyhow::Result<Option<n2r_win32::tree_resources::CountAdmission>> {
        Ok(self
            .native_profile()
            .map(n2r_win32::attestation::ResourceProfile::count_admission)
            .transpose()?
            .flatten())
    }
    /// Resource facts are not write authority. Fresh source admission also
    /// requires the actual complete raw/native page owners from the same lease.
    pub fn resource_admission(
        self,
    ) -> Result<Option<n2r_win32::tree_resources::SourceResourceAdmission>> {
        Ok(self
            .native_profile()
            .map(n2r_win32::attestation::ResourceProfile::resource_admission)
            .transpose()?
            .flatten())
    }
    /// Only complete reconciled frozen-source facts select the file/directory
    /// allocation of the existing object envelope. The descriptor is not authority.
    pub(crate) fn admit_inspection(
        self,
        raw: &ntfs::NtfsInspection,
        pin: &str,
    ) -> anyhow::Result<Self> {
        self.admit_inspection_mode(raw, pin, false)
    }

    /// Only the owning pipeline that actually constructs from authenticated
    /// pages may choose this version. It is not a deserializable authority flag.
    pub(crate) fn admit_inspection_paged(
        self,
        raw: &ntfs::NtfsInspection,
        pin: &str,
    ) -> anyhow::Result<Self> {
        self.admit_inspection_mode(raw, pin, true)
    }

    fn admit_inspection_mode(
        self,
        raw: &ntfs::NtfsInspection,
        pin: &str,
        paged: bool,
    ) -> anyhow::Result<Self> {
        if !self.is_envelope() {
            return Ok(self);
        }
        ntfs::validate_record_coverage(raw)?;
        anyhow::ensure!(
            raw.files.len() <= n2r_win32::tree_resources::RAW_IDENTITIES
                && has_unique_sorted_records(raw)
                && matches!(
                    raw.allocation_reconciliation.as_ref().map(|r| &r.status),
                    Some(ntfs::AllocationReconciliationStatus::ConsistentRawModel)
                )
                && matches!(
                    raw.namespace_reconciliation.as_ref().map(|r| &r.status),
                    Some(ntfs_namespace::Status::ConsistentRawModel)
                ),
            "tree counts require complete reconciled source facts"
        );
        anyhow::ensure!(
            raw.schema_version == 1
                && matches!(
                    raw.security_reconciliation.as_ref().map(|r| &r.status),
                    Some(ntfs_security::Status::ConsistentRawModel)
                ),
            "tree counts require complete source security reconciliation"
        );
        let mut files = 0usize;
        let mut dirs = 0usize;
        let mut streams = 0usize;
        for f in &raw.files {
            if internal_role(raw, f).is_some() {
                continue;
            }
            anyhow::ensure!(
                user_paths(raw, f).is_some(),
                "tree count source namespace is unresolved"
            );
            if f.is_directory {
                dirs += 1;
            } else {
                files += 1;
                streams = streams
                    .checked_add(f.streams.len())
                    .ok_or_else(|| anyhow::anyhow!("stream count overflow"))?;
            }
        }
        let bytes: [u8; 32] = hex::decode(pin)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("source inspection pin length differs"))?;
        let admitted = if let Self::ExperimentalObjectEnvelopeV3(Some(previous)) = self {
            previous.validate_tree(files, dirs, streams)?;
            anyhow::ensure!(
                previous.source_inspection_sha256 == bytes
                    && previous.raw_identities as usize == raw.files.len(),
                "supplied count admission differs from current complete source"
            );
            previous
        } else if paged {
            n2r_win32::tree_resources::CountAdmission::new_paged(
                bytes,
                raw.files.len(),
                files,
                dirs,
                streams,
            )?
        } else {
            n2r_win32::tree_resources::CountAdmission::new(
                bytes,
                raw.files.len(),
                files,
                dirs,
                streams,
            )?
        };
        admitted.validate_inspection_bytes(raw)?;
        Ok(Self::ExperimentalObjectEnvelopeV3(Some(admitted)))
    }
}

/// Windows-generated root transaction metadata is an internal replacement
/// obligation, not an ordinary user stream. Recognition alone never admits
/// its loss or proves an idle TxF resource manager.
pub(crate) fn recognized_root_txf(attribute: &AttributeInventory) -> bool {
    attribute.type_code == 0x100
        && attribute.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
        && attribute.resident
        && attribute.logical_size == 56
        && attribute.initialized_size == 56
        && attribute.allocated_size == 56
        && attribute.flags == 0
        && attribute.compression_unit == 0
        && attribute.lowest_vcn == 0
        && attribute.extents.is_empty()
}

fn accounted_internal_txf_blocker(
    raw: &ntfs::NtfsInspection,
    blocker: &ntfs::InspectionBlocker,
) -> bool {
    if blocker.code != "unsupported_attribute"
        || blocker.message != "Attribute type 0x100 needs a preservation policy"
    {
        return false;
    }
    let Some(record_number) = blocker.file_record_number else {
        return false;
    };
    let Some(file) = raw
        .files
        .iter()
        .find(|file| file.record_number == record_number)
    else {
        return false;
    };
    let role_matches = record_number == 5
        || internal_role(raw, file).as_deref() == Some("$Extend\\$RmMetadata\\$Txf");
    role_matches
        && file
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.type_code == 0x100
                    && attribute.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
            })
            .count()
            == 1
        && file
            .attributes
            .iter()
            .any(|attribute| recognized_root_txf(attribute))
        && file
            .attributes
            .iter()
            .filter(|attribute| attribute.type_code == 0x100)
            .all(recognized_root_txf)
}

fn accounted_empty_badclus_blocker(
    raw: &ntfs::NtfsInspection,
    blocker: &ntfs::InspectionBlocker,
) -> bool {
    if blocker.code != "logical_stream_hash_unavailable"
        || blocker.file_record_number != Some(8)
        || blocker.message
            != "DATA attribute 1 has no complete logical hash: UnsupportedBadClusterMetadata"
    {
        return false;
    }
    let Some(file) = raw.files.iter().find(|file| file.record_number == 8) else {
        return false;
    };
    if internal_role(raw, file).as_deref() != Some("$BadClus") || file.streams.len() != 2 {
        return false;
    }
    let Some(unnamed) = file
        .streams
        .iter()
        .find(|stream| stream.name_utf16.is_empty())
    else {
        return false;
    };
    let Some(bad) = file
        .streams
        .iter()
        .find(|stream| stream.name_utf16 == [36, 66, 97, 100])
    else {
        return false;
    };
    unnamed.resident
        && unnamed.logical_size == 0
        && unnamed.extents.is_empty()
        && unnamed.logical_hash_status == ntfs::LogicalHashStatus::Complete
        && !bad.resident
        && bad.flags == 0
        && raw
            .geometry
            .total_clusters
            .checked_mul(u64::from(raw.geometry.cluster_size))
            == Some(bad.logical_size)
        && bad.initialized_size == 0
        && bad.allocated_size == bad.logical_size
        && bad.logical_hash_status == ntfs::LogicalHashStatus::UnsupportedBadClusterMetadata
        && bad.extents.len() == 1
        && bad.extents[0].logical_offset == 0
        && bad.extents[0].physical_offset.is_none()
        && bad.extents[0].length == bad.logical_size
}

fn unresolved_codes(
    raw: &ntfs::NtfsInspection,
    backups: bool,
    clean_log: bool,
    short_name_policy: bool,
    volume_identity: Option<&crate::ntfs_internal::VerifiedIndexes>,
) -> Vec<String> {
    raw.blockers
        .iter()
        .filter(|blocker| {
            !matches!(
                blocker.code.as_str(),
                "security_descriptors_unresolved"
                    | "directory_indexes_unverified"
                    | "allocation_ownership_unverified"
            ) && !(blocker.code == "backup_boot_unverified" && backups)
                && !(blocker.code == "journal_state_unverified" && clean_log)
                && !(blocker.code == "volume_state_flags"
                    && short_name_policy
                    && raw.volume_flags == Some(0x80))
                && !accounted_internal_txf_blocker(raw, blocker)
                && !accounted_empty_badclus_blocker(raw, blocker)
                && !(blocker.code == "object_id"
                    && blocker.file_record_number == Some(3)
                    && volume_identity.is_some_and(|proof| proof.covers_volume_object_id(raw, 3)))
        })
        .map(|blocker| blocker.code.clone())
        .collect()
}

/// Bind a non-deserializable restart proof from actual source reads. This
/// clears only the restart-page diagnostic and its duplicate raw blocker;
/// full transaction replay and internal replacement remain separate gates.
pub(crate) fn bind_clean_log(
    assessment: &mut Assessment,
    raw: &ntfs::NtfsInspection,
    proof: &crate::ntfs_log::VerifiedRestart,
) -> bool {
    if !proof.binds(raw) || !proof.restart.candidate_clean_dismount {
        return false;
    }
    let policy_bound = raw.volume_flags == Some(0x80)
        && assessment
            .gates
            .iter()
            .any(|gate| gate.code == "volume_policy_flags" && gate.satisfied);
    let unresolved = unresolved_codes(
        raw,
        assessment.backup_evidence.is_some(),
        true,
        policy_bound,
        None,
    );
    for gate in &mut assessment.gates {
        if gate.code == "log_restart_pages" {
            gate.satisfied = true;
            gate.detail = "both clean-flagged NTFS restart copies passed structural checks on the frozen source; full log replay remains unproven".into();
        } else if gate.code == "remaining_inspection_refusals" {
            gate.satisfied = unresolved.is_empty();
            gate.detail = format!(
                "unresolved inspection checks after frozen log proof: {unresolved:?}; internal replacement obligations remain separate"
            );
        }
    }
    true
}

/// The controlled Windows 11 differential established 0x0080 as the
/// short-name-disable policy. Only an opaque live observer bound to the
/// unchanged frozen source can apply that interpretation to admission.
#[cfg(windows)]
pub(crate) fn bind_short_name_policy(
    assessment: &mut Assessment,
    raw: &ntfs::NtfsInspection,
    observed: &n2r_win32::GeneralLiveNtfsObservation,
) -> bool {
    let native = observed.report();
    let Some(policy) = observed.txf() else {
        return false;
    };
    let policy = &policy.observation;
    if raw.volume_flags != Some(0x80)
        || raw.dirty != Some(false)
        || raw.volume_version.as_deref() != Some("3.1")
        || native.request.source_inspection_sha256 != assessment.source_inspection_sha256
        || !assessment
            .source_view
            .as_ref()
            .is_some_and(|view| view.binds_live(&assessment.source_inspection_sha256))
        || !assessment
            .gates
            .iter()
            .any(|gate| gate.code == "frozen_device_basis" && gate.satisfied)
        || raw
            .files
            .iter()
            .any(|file| file.names.iter().any(|name| name.namespace == 2))
        || policy.schema_version != 2
        || !n2r_win32::windows_build::supported(policy.windows_version)
        || !policy.short_name_state_stable
        || !policy
            .persistent_state_before
            .as_ref()
            .zip(policy.persistent_state_after.as_ref())
            .is_some_and(|(before, after)| {
                [before, after].into_iter().all(|state| {
                    state.queried_flags_valid
                        && state.requested_flag_mask == 1
                        && state.requested_version == 1
                        && state.short_name_creation_disabled
                })
            })
    {
        return false;
    }
    let clean_log = assessment
        .gates
        .iter()
        .any(|gate| gate.code == "log_restart_pages" && gate.satisfied);
    let unresolved = unresolved_codes(
        raw,
        assessment.backup_evidence.is_some(),
        clean_log,
        true,
        None,
    );
    for gate in &mut assessment.gates {
        if gate.code == "volume_policy_flags" {
            gate.satisfied = true;
            gate.detail = "raw 0x0080 agrees with stable native disabled short-name policy on the bound frozen source; no DOS-only aliases are present; other volume-state bits remain refused".into();
        } else if gate.code == "remaining_inspection_refusals" {
            gate.satisfied = unresolved.is_empty();
            gate.detail = format!(
                "unresolved inspection checks after native short-name policy binding: {unresolved:?}; internal replacement obligations remain separate"
            );
        }
    }
    true
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    PreserveSupportedUserSemantics,
    RecognizedFilesystemInternal,
    Reject,
}
#[derive(Debug, Serialize)]
pub struct ObjectDecision {
    pub record_number: u64,
    pub sequence_number: u16,
    pub disposition: Disposition,
    pub role: String,
    pub issues: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Gate {
    pub code: String,
    pub satisfied: bool,
    pub detail: String,
}

/// What the `clean_volume` gate requires, as a refusal says it.
pub(crate) const CLEAN_VOLUME_REQUIREMENT: &str = "the volume is marked dirty, or is not NTFS version 3.1: run `chkdsk <drive>: /f`, let it finish, and convert then";

/// What the `volume_policy_flags` gate requires, as a refusal says it.
pub(crate) const VOLUME_FLAGS_REQUIREMENT: &str = "the volume carries state flags the converter does not take over (a pending chkdsk or upgrade), or 8.3 short-name creation is enabled on it: run `chkdsk <drive>: /f`, and turn short-name creation off with `fsutil 8dot3name set <drive>: 1`";

/// What a run says of directories that are marked case-sensitive and hold
/// no two names that differ only by case. `example` is one of them, and
/// `carry` whether this run sets the mark on the new volume, with the
/// reason where it does not.
pub(crate) fn case_mark_note(
    marked: u64,
    example: Option<&str>,
    carry: n2r_win32::directory_case::CaseMarkCarry,
) -> String {
    use n2r_win32::directory_case::CaseMarkCarry;
    let found = format!(
        "{marked} director{} marked case-sensitive{} (WSL and Git mark the directories they make). None holds two names that differ only by case",
        if marked == 1 { "y is" } else { "ies are" },
        example
            .map(|path| format!(", for example {path}"))
            .unwrap_or_default()
    );
    match carry {
        CaseMarkCarry::Carried => format!(
            "{found}. The converter sets the mark on the same directories of the new volume as it makes them, and reads it back; the directories are listed in the run's records."
        ),
        CaseMarkCarry::NotCarried(why) => format!(
            "{found}, so every name stays reachable. The converter does not set the mark on the new volume; the directories are listed in the run's records. {}",
            why.sentence()
        ),
    }
}

/// What the `native_directory_case_sensitivity` gate requires, as a refusal
/// says it: Windows has to answer for every directory, with flags the
/// converter knows.
pub(crate) fn case_answer_requirement(unanswered: u64, directories: u64) -> String {
    format!(
        "Windows did not say whether {unanswered} of {directories} directories are case-sensitive, or gave flags for them that the converter does not know (it knows 0, an ordinary directory, and 1, one marked case-sensitive)"
    )
}

/// Why one of NTFS's own indexes (`$Extend\$Quota`, `$ObjId`, `$Reparse`)
/// cannot be replaced by what ReFS keeps, as a refusal says it.
pub(crate) fn index_refusal_cause(role: &str) -> &'static str {
    if role.ends_with("$Quota") {
        "disk quotas are in use on the volume (enabled, or with entries for users): turn quota management off (`fsutil quota disable <drive>:`) and delete the quota entries, then convert"
    } else if role.ends_with("$ObjId") {
        "the volume's object-ID index is not in a form the converter takes over"
    } else {
        "the volume's reparse-point index does not match its reparse points: run `chkdsk <drive>: /f`"
    }
}

/// The objects the objects gate fails for: those the preservation policy does
/// not admit, and those that Windows does not show as the raw volume holds
/// them. Every one is written to the comparison pages with its reasons; the
/// first few of each kind are also kept here, so that the refusal itself can
/// say which objects it is about.
#[derive(Debug, Default)]
pub(crate) struct RefusedObjects {
    count: u64,
    first: Vec<String>,
    differing: u64,
    differing_first: Vec<String>,
}

impl RefusedObjects {
    /// How many objects of each kind a message spells out.
    const NAMED: usize = 12;

    fn named(record_number: u64, path: Option<&[String]>, reasons: &[String]) -> String {
        let place = match path {
            Some(components) => format!("\\{}", components.join("\\")),
            None => "(path not resolved)".to_owned(),
        };
        format!("MFT record {record_number} {place}: {}", reasons.join("; "))
    }

    pub(crate) fn note(&mut self, record_number: u64, path: Option<&[String]>, issues: &[String]) {
        self.count = self.count.saturating_add(1);
        if self.first.len() < Self::NAMED {
            self.first.push(Self::named(record_number, path, issues));
        }
    }

    /// An object that Windows does not show as the raw volume holds it:
    /// `differences` names each view that differs and what was found.
    pub(crate) fn note_difference(
        &mut self,
        record_number: u64,
        path: Option<&[String]>,
        differences: &[String],
    ) {
        self.differing = self.differing.saturating_add(1);
        if self.differing_first.len() < Self::NAMED {
            self.differing_first
                .push(Self::named(record_number, path, differences));
        }
    }

    /// The objects the preservation policy does not admit, as a sentence of
    /// its own: `None` when there are none. `rest` says where the ones that
    /// are not spelled out can be found.
    pub(crate) fn outside_policy(&self, rest: &str) -> Option<String> {
        if self.count == 0 {
            return None;
        }
        let mut text = format!(
            "{} object{} outside what this converter preserves: {}",
            self.count,
            if self.count == 1 { " is" } else { "s are" },
            self.first.join(" | ")
        );
        let unnamed = self.count - self.first.len() as u64;
        if unnamed > 0 {
            text.push_str(&format!(" | and {unnamed} more{rest}"));
        }
        Some(text)
    }

    /// The detail of the objects gate: what it requires and, when objects
    /// were refused, which and why.
    pub(crate) fn detail(&self, requirement: &str) -> String {
        const RECORDED: &str = "each recorded with its reasons in source-comparison.data.pages";
        let mut text = requirement.to_owned();
        if let Some(outside) = self.outside_policy(&format!(", {RECORDED}")) {
            text.push_str("; ");
            text.push_str(&outside);
        }
        if self.differing != 0 {
            text.push_str(&format!(
                "; Windows does not show {} object{} as the raw volume holds {}: {}",
                self.differing,
                if self.differing == 1 { "" } else { "s" },
                if self.differing == 1 { "it" } else { "them" },
                self.differing_first.join(" | ")
            ));
            let unnamed = self.differing - self.differing_first.len() as u64;
            if unnamed > 0 {
                text.push_str(&format!(" | and {unnamed} more, {RECORDED}"));
            }
        }
        text
    }
}

/// A source refusal: the gates that failed and, for each, what it requires
/// and found. A list of gate codes alone does not say what to change.
pub(crate) fn source_refusal<'a>(route: &str, failed: impl Iterator<Item = &'a Gate>) -> String {
    let failed: Vec<&Gate> = failed.collect();
    let codes: Vec<&str> = failed.iter().map(|gate| gate.code.as_str()).collect();
    let mut text = format!("{route} source evidence refused: {codes:?}");
    for gate in failed
        .iter()
        .filter(|gate| !only_a_consequence(&gate.code, &codes))
    {
        text.push_str(&format!("\n  {}: {}", gate.code, gate.detail));
    }
    text
}

/// Whether a failed gate is failed only because another one is. The
/// replacement of NTFS's internal files is admitted when every other
/// obligation has closed, and the directories' case flags are admitted with
/// it: beside a real cause, the two sentences only obscure it.
fn only_a_consequence(code: &str, failed: &[&str]) -> bool {
    const DEPENDENT: [&str; 2] = [
        "internal_replacement_state",
        "native_directory_case_sensitivity",
    ];
    DEPENDENT.contains(&code) && failed.iter().any(|other| !DEPENDENT.contains(other))
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[test]
    fn refused_file_attributes_are_named() {
        assert_eq!(file_attribute_names(0x100), "TEMPORARY");
        assert_eq!(file_attribute_names(0x1100), "TEMPORARY, OFFLINE");
        assert!(file_attribute_names(0x4000).starts_with("ENCRYPTED (decrypt"));
        // A bit without a name is still shown.
        assert_eq!(file_attribute_names(0x1000_0100), "TEMPORARY, 0x10000000");
        assert!(SHORT_NAME_REMEDY.contains("fsutil 8dot3name strip"));
    }

    #[test]
    fn a_refusal_names_the_refused_objects_and_their_reasons() {
        let requirement = "every transferred user object passes the preservation policy";
        let mut refused = RefusedObjects::default();
        assert_eq!(refused.detail(requirement), requirement);

        refused.note(
            39561,
            Some(&["shape".to_owned(), "folder".to_owned()]),
            &["directory data streams exceed the profile".to_owned()],
        );
        refused.note(7, None, &["first".to_owned(), "second".to_owned()]);
        let detail = refused.detail(requirement);
        assert!(detail.starts_with(requirement), "{detail}");
        assert!(detail.contains("2 objects are outside"), "{detail}");
        assert!(
            detail.contains(
                "MFT record 39561 \\shape\\folder: directory data streams exceed the profile"
            ),
            "{detail}"
        );
        assert!(
            detail.contains("MFT record 7 (path not resolved): first; second"),
            "{detail}"
        );

        // Only the first few are spelled out; the rest are counted.
        for record in 100..120 {
            refused.note(record, None, &["reason".to_owned()]);
        }
        let detail = refused.detail(requirement);
        assert!(detail.contains("22 objects are outside"), "{detail}");
        assert!(detail.contains("and 10 more"), "{detail}");
        assert!(!detail.contains("MFT record 119"), "{detail}");
    }

    #[test]
    fn the_case_mark_is_announced_and_an_unanswered_directory_is_refused() {
        use n2r_win32::directory_case::{CaseMarkCarry, WhyNotCarried};
        let windows_11 = CaseMarkCarry::NotCarried(WhyNotCarried::Windows {
            version: [10, 0, 26300],
            server: false,
        });
        let one = case_mark_note(1, Some("\\src\\linux"), windows_11);
        assert!(
            one.starts_with("1 directory is marked case-sensitive, for example \\src\\linux (WSL"),
            "{one}"
        );
        assert!(
            one.contains("does not set the mark")
                && one.contains("two names that differ only by case")
                && one.contains("listed in the run's records")
                // Why not, and where it is set.
                && one.contains("this is Windows 10.0.26300")
                && one.contains("Windows Server 2025 (build 26100)")
                // Not something to send a user to: see docs/feature-matrix.md.
                && !one.contains("fsutil"),
            "{one}"
        );
        let many = case_mark_note(2412, None, windows_11);
        assert!(
            many.starts_with("2412 directories are marked case-sensitive (WSL"),
            "{many}"
        );
        let on_windows = case_mark_note(
            1,
            None,
            CaseMarkCarry::NotCarried(WhyNotCarried::WindowsVolume),
        );
        assert!(
            on_windows.contains("does not set the mark")
                && on_windows.contains("data volumes only"),
            "{on_windows}"
        );
        // Where it is carried over, the note says so and gives no reason
        // for the opposite.
        let carried = case_mark_note(3, Some("\\src"), CaseMarkCarry::Carried);
        assert!(
            carried.starts_with("3 directories are marked case-sensitive, for example \\src (WSL")
                && carried.contains("sets the mark on the same directories of the new volume")
                && carried.contains("reads it back")
                && carried.contains("listed in the run's records")
                && !carried.contains("does not set")
                && !carried.contains("bugcheck"),
            "{carried}"
        );

        let unanswered = case_answer_requirement(3, 40);
        assert!(unanswered.contains("3 of 40 directories"), "{unanswered}");
        assert!(!unanswered.contains("setCaseSensitiveInfo"), "{unanswered}");
    }

    #[test]
    fn a_refusal_names_the_objects_windows_shows_differently() {
        let requirement = "Windows has to see it as the raw volume does";
        let mut refused = RefusedObjects::default();
        refused.note_difference(
            41,
            Some(&["tree".to_owned(), "sparse.bin".to_owned()]),
            &["contents: native allocated ranges differ".to_owned()],
        );
        let detail = refused.detail(requirement);
        assert_eq!(
            detail,
            "Windows has to see it as the raw volume does; Windows does not show 1 object as the raw volume holds it: MFT record 41 \\tree\\sparse.bin: contents: native allocated ranges differ"
        );

        // Both kinds are given, each with its own count.
        refused.note(7, None, &["reason".to_owned()]);
        for record in 100..114 {
            refused.note_difference(record, None, &["streams: differ".to_owned()]);
        }
        let detail = refused.detail(requirement);
        assert!(detail.contains("1 object is outside"), "{detail}");
        assert!(
            detail.contains("Windows does not show 15 objects as the raw volume holds them"),
            "{detail}"
        );
        assert!(detail.contains("and 3 more"), "{detail}");
        assert!(!detail.contains("MFT record 113"), "{detail}");
    }

    #[test]
    fn a_source_refusal_gives_each_failed_gate_with_its_detail() {
        let gates = [
            Gate {
                code: "objects".into(),
                satisfied: false,
                detail:
                    "1 object is outside what this converter preserves: MFT record 5 \\x: reason"
                        .into(),
            },
            Gate {
                code: "internal_replacement_state".into(),
                satisfied: false,
                detail: "only after all independent source obligations close".into(),
            },
        ];
        let text = source_refusal("resource", gates.iter());
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("resource source evidence refused: [\"objects\", \"internal_replacement_state\"]")
        );
        assert_eq!(
            lines.next(),
            Some(
                "  objects: 1 object is outside what this converter preserves: MFT record 5 \\x: reason"
            )
        );
        // The dependent gate is named in the list and not explained: it
        // failed because the other did.
        assert_eq!(lines.next(), None);
        let alone = source_refusal("resource", gates[1..].iter());
        let mut lines = alone.lines();
        lines.next();
        assert_eq!(
            lines.next(),
            Some(
                "  internal_replacement_state: only after all independent source obligations close"
            )
        );
        assert_eq!(lines.next(), None);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InternalReplacement {
    pub record_number: u64,
    pub sequence_number: u16,
    pub role: String,
    pub action: &'static str,
}

/// Created only after the independent internal-index, transaction-freeze and
/// source-state obligations have bound. The diagnostic replacement rows alone
/// cannot exclude an object from directory-case admission.
pub(crate) struct BoundInternalReplacements {
    inspection_sha256: String,
    replacements: Vec<InternalReplacement>,
}
impl BoundInternalReplacements {
    fn binds(&self, raw: &ntfs::NtfsInspection) -> bool {
        serde_json::to_vec(raw)
            .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
    }
    pub(crate) fn into_replacements(self) -> Vec<InternalReplacement> {
        self.replacements
    }
}

#[derive(Debug, Serialize)]
pub struct DirectoryCaseIdentity {
    pub record_number: u64,
    pub sequence_number: u16,
}

/// Admission scope is separate from the complete raw case-query diagnostics.
/// A transferred directory always requires actual stable zero flags. Only an
/// independently bound replacement can remove an internal directory from this
/// obligation; its Unknown/error observation remains in the comparison.
#[derive(Debug, Serialize)]
pub struct DirectoryCaseAdmission {
    pub raw_directories: usize,
    pub required_directories: Vec<DirectoryCaseIdentity>,
    pub matched_required_directories: usize,
    pub replaced_internal_directories: Vec<InternalReplacement>,
    pub internal_replacement_proof_bound: bool,
    pub all_required_directories_case_insensitive: bool,
    pub issues: Vec<String>,
}

fn directory_case_admission(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    replacements: Option<&BoundInternalReplacements>,
) -> Option<DirectoryCaseAdmission> {
    let evidence = comparison.directory_case_sensitivity.as_ref()?;
    let raw_ids: BTreeSet<_> = raw
        .files
        .iter()
        .filter(|file| file.is_directory)
        .map(|file| (file.record_number, file.sequence_number))
        .collect();
    let observed_ids: BTreeSet<_> = evidence
        .directories
        .iter()
        .map(|row| (row.record_number, row.sequence_number))
        .collect();
    let replacements = replacements.filter(|proof| {
        proof.binds(raw) && proof.inspection_sha256 == comparison.source_inspection_sha256
    });
    let mut scope = DirectoryCaseAdmission {
        raw_directories: raw_ids.len(),
        required_directories: Vec::new(),
        matched_required_directories: 0,
        replaced_internal_directories: Vec::new(),
        internal_replacement_proof_bound: replacements.is_some(),
        all_required_directories_case_insensitive: false,
        issues: Vec::new(),
    };
    if !has_unique_sorted_records(raw)
        || evidence.raw_directories != raw_ids.len()
        || evidence.directories.len() != raw_ids.len()
        || observed_ids.len() != evidence.directories.len()
        || observed_ids != raw_ids
    {
        scope
            .issues
            .push("complete uniquely identified raw directory-case coverage is missing".into());
    }
    for file in raw.files.iter().filter(|file| file.is_directory) {
        // This is the same exact internal-object recognition used by Tree
        // derivation, now additionally backed by the opaque replacement proof.
        let replacement = replacements.and_then(|proof| {
            proof.replacements.iter().find(|replacement| {
                replacement.record_number == file.record_number
                    && replacement.sequence_number == file.sequence_number
                    && internal_role(raw, file).as_deref() == Some(replacement.role.as_str())
            })
        });
        if let Some(replacement) = replacement {
            scope
                .replaced_internal_directories
                .push(replacement.clone());
            continue;
        }
        scope.required_directories.push(DirectoryCaseIdentity {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
        });
        let row = evidence.directories.iter().find(|row| {
            row.record_number == file.record_number && row.sequence_number == file.sequence_number
        });
        if row.is_some_and(|row| {
            row.matched
                && row.before_flags == Some(0)
                && row.after_flags == Some(0)
                && row.issues.is_empty()
        }) {
            scope.matched_required_directories += 1;
        } else {
            scope.issues.push(format!(
                "directory {}/{} requires successful same-identity before/after zero case flags: {:?}{}",
                file.record_number,
                file.sequence_number,
                row,
                if internal_role(raw, file).is_some() {
                    "; independently validated exact internal replacement proof is not bound"
                } else {
                    ""
                }
            ));
        }
    }
    scope.all_required_directories_case_insensitive = !scope.required_directories.is_empty()
        && scope.issues.is_empty()
        && scope.matched_required_directories == scope.required_directories.len();
    Some(scope)
}

pub(crate) fn bind_directory_case_admission(
    assessment: &mut Assessment,
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    replacements: Option<&BoundInternalReplacements>,
) {
    let scope = directory_case_admission(raw, comparison, replacements);
    for gate in &mut assessment.gates {
        if gate.code == "native_directory_case_sensitivity" {
            gate.satisfied = scope
                .as_ref()
                .is_some_and(|scope| scope.all_required_directories_case_insensitive);
            gate.detail = format!(
                "every transferred directory requires successful same-identity before/after FileCaseSensitiveInfo flags zero; exact proof-backed internal replacements alone are excluded; required={}, matched={}, replaced={}, replacement_proof_bound={}, issues={:?}; complete raw Unknown/error observations are retained",
                scope
                    .as_ref()
                    .map_or(0, |scope| scope.required_directories.len()),
                scope
                    .as_ref()
                    .map_or(0, |scope| scope.matched_required_directories),
                scope
                    .as_ref()
                    .map_or(0, |scope| scope.replaced_internal_directories.len()),
                scope
                    .as_ref()
                    .is_some_and(|scope| scope.internal_replacement_proof_bound),
                scope.as_ref().map(|scope| &scope.issues),
            );
        }
    }
    assessment.directory_case_admission = scope;
}

/// Account only for a reread, cross-indexed filesystem-internal volume ID.
/// User object IDs are never covered by this replacement policy.
pub(crate) fn bind_internal_volume_identity(
    assessment: &mut Assessment,
    raw: &ntfs::NtfsInspection,
    indexes: &crate::ntfs_internal::VerifiedIndexes,
) -> bool {
    if !indexes.covers_volume_object_id(raw, 3) {
        return false;
    }
    let clean_log = assessment
        .gates
        .iter()
        .any(|g| g.code == "log_restart_pages" && g.satisfied);
    let short_names = assessment
        .gates
        .iter()
        .any(|g| g.code == "volume_policy_flags" && g.satisfied);
    let unresolved = unresolved_codes(
        raw,
        assessment.backup_evidence.is_some(),
        clean_log,
        short_names,
        Some(indexes),
    );
    for gate in &mut assessment.gates {
        if gate.code == "remaining_inspection_refusals" {
            gate.satisfied = unresolved.is_empty();
            gate.detail = format!(
                "unresolved inspection checks: {unresolved:?}; sole reread $Volume identity is recorded for explicit filesystem-internal replacement; user object IDs remain refused"
            );
        }
    }
    true
}

/// Replace NTFS runtime structures with the native-created ReFS structures
/// only after their source-state obligations have actual bound evidence.
pub(crate) fn bind_internal_replacement(
    assessment: &mut Assessment,
    raw: &ntfs::NtfsInspection,
    indexes: &crate::ntfs_internal::VerifiedIndexes,
    transactions: &crate::ntfs_transactions::VerifiedTransactions,
) -> Option<BoundInternalReplacements> {
    let inspection_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(raw).ok()?));
    let required = [
        "clean_volume",
        "raw_allocation",
        "raw_namespace",
        "raw_mft_record_coverage",
        "raw_security",
        "objects",
        "native_identity_coverage",
        "native_volume_allocation",
        "source_backups",
        "log_restart_pages",
        "remaining_inspection_refusals",
        "frozen_device_basis",
    ];
    let missing_gates: Vec<_> = required
        .iter()
        .filter(|code| {
            !assessment
                .gates
                .iter()
                .any(|g| g.code == **code && g.satisfied)
        })
        .copied()
        .collect();
    if assessment.source_inspection_sha256 != inspection_sha256
        || !indexes.binds(raw)
        || !indexes.replacement_supported
        || !transactions.binds(raw)
        || !missing_gates.is_empty()
    {
        for gate in &mut assessment.gates {
            if gate.code == "internal_replacement_state" {
                gate.satisfied = false;
                gate.detail = format!(
                    "exact internal replacement proof is incomplete: inspection_pin_matches={}, indexes_bound={}, index_replacement_supported={}, transactions_bound={}, missing_source_gates={missing_gates:?}",
                    assessment.source_inspection_sha256 == inspection_sha256,
                    indexes.binds(raw),
                    indexes.replacement_supported,
                    transactions.binds(raw),
                );
            }
        }
        return None;
    }
    let mut replacements = Vec::new();
    for object in &assessment.objects {
        if object.disposition != Disposition::RecognizedFilesystemInternal {
            continue;
        }
        let file = raw.files.iter().find(|f| {
            f.record_number == object.record_number && f.sequence_number == object.sequence_number
        })?;
        if internal_role(raw, file).as_deref() != Some(object.role.as_str()) {
            return None;
        }
        let action = match object.role.as_str() {
            "$Volume" if indexes.covers_volume_object_id(raw, 3) => {
                "replace_filesystem_internal_volume_identity"
            }
            "$Extend\\$ObjId" if indexes.internal_volume_object_id().is_some() => {
                "replace_ntfs_internal_volume_identity_index"
            }
            "$LogFile" | "$Extend\\$UsnJrnl" => "start_new_filesystem_journal_epoch",
            "$Extend\\$RmMetadata\\$Repair" => "replace_ntfs_runtime_diagnostics",
            role if role.starts_with("$Extend\\$RmMetadata") || role == "$Extend\\$Deleted" => {
                "replace_idle_default_transaction_metadata"
            }
            _ => "replace_with_native_refs_structure",
        };
        replacements.push(InternalReplacement {
            record_number: object.record_number,
            sequence_number: object.sequence_number,
            role: object.role.clone(),
            action,
        });
    }
    for gate in &mut assessment.gates {
        if gate.code == "internal_replacement_state" {
            gate.satisfied = true;
            gate.detail = "frozen allocation/namespace/security, backup/restart copies, verified internal object/reparse index state, disabled default quotas and the observed default-RM freeze agree; a sole NTFS volume identity is recorded for explicit replacement and user object IDs remain refused".into();
        }
    }
    Some(BoundInternalReplacements {
        inspection_sha256,
        replacements,
    })
}
#[derive(Debug, Serialize)]
pub struct Assessment {
    pub schema_version: u32,
    pub profile: String,
    pub source_inspection_sha256: String,
    pub objects: Vec<ObjectDecision>,
    pub gates: Vec<Gate>,
    pub user_files: usize,
    pub user_directories: usize,
    pub user_logical_bytes: u64,
    pub source_admitted: bool,
    pub certificate_issued: bool,
    pub execution_authorized: bool,
    pub backup_evidence: Option<crate::ntfs_backup::VerifiedBackups>,
    pub source_view: Option<crate::ntfs_source_view::Analysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_case_admission: Option<DirectoryCaseAdmission>,
}
fn reference(f: &FileInventory) -> u64 {
    f.record_number | (u64::from(f.sequence_number) << 48)
}
/// The inspector emits this canonical order. Admission and tree derivation
/// check it once, rather than rebuilding a record map for each file name.
pub(crate) fn has_unique_sorted_records(raw: &ntfs::NtfsInspection) -> bool {
    raw.files.iter().all(|file| file.record_number < 1 << 48)
        && raw
            .files
            .windows(2)
            .all(|pair| pair[0].record_number < pair[1].record_number)
}

fn file_by_reference(raw: &ntfs::NtfsInspection, id: u64) -> Option<&FileInventory> {
    let number = id & 0x0000_ffff_ffff_ffff;
    let index = raw
        .files
        .binary_search_by_key(&number, |file| file.record_number)
        .ok()?;
    let file = &raw.files[index];
    // Full sequence identity remains mandatory. The adjacent checks also
    // refuse duplicate records locally; the callers' one-time order check
    // and physical-record coverage gate reject all other duplicate forms.
    if reference(file) != id
        || index
            .checked_sub(1)
            .is_some_and(|i| raw.files[i].record_number == number)
        || raw
            .files
            .get(index + 1)
            .is_some_and(|f| f.record_number == number)
    {
        return None;
    }
    Some(file)
}
pub(crate) fn path(raw: &ntfs::NtfsInspection, f: &FileInventory) -> Option<Vec<String>> {
    let mut cursor = f;
    let mut components = vec![];
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(reference(cursor)) || components.len() > 16 {
            return None;
        }
        if cursor.record_number == 5 {
            components.reverse();
            return Some(components);
        }
        if cursor.names.len() != 1 {
            return None;
        }
        let name = &cursor.names[0];
        if !matches!(name.namespace, 0 | 1 | 3) {
            return None;
        }
        components.push(String::from_utf16(&name.name_utf16).ok()?);
        cursor = file_by_reference(
            raw,
            name.parent_record_number | (u64::from(name.parent_sequence_number) << 48),
        )?;
        if !cursor.is_directory {
            return None;
        }
    }
}
/// Every addressable name of one ordinary source identity. Directories keep a
/// single parent; files may have multiple non-DOS links. The raw namespace must
/// already reconcile each name with its directory index, and callers must
/// have checked `has_unique_sorted_records` once. This resolves names, not
/// native target support or conversion authority.
pub(crate) fn user_paths(
    raw: &ntfs::NtfsInspection,
    f: &FileInventory,
) -> Option<Vec<Vec<String>>> {
    if !raw
        .namespace_reconciliation
        .as_ref()
        .is_some_and(|n| n.status == ntfs_namespace::Status::ConsistentRawModel)
        || f.names.is_empty()
        || usize::from(f.hard_link_count) != f.names.len()
        || f.names
            .iter()
            .any(|name| !matches!(name.namespace, 0 | 1 | 3))
        || (f.is_directory && f.names.len() != 1)
    {
        return None;
    }
    fn directory_path(raw: &ntfs::NtfsInspection, mut current: u64) -> Option<Vec<String>> {
        let mut components = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current) || components.len() > 16 {
                return None;
            }
            let directory = file_by_reference(raw, current)?;
            if !directory.is_directory
                || directory.hard_link_count != 1
                || directory.names.len() != 1
            {
                return None;
            }
            let name = &directory.names[0];
            if !matches!(name.namespace, 0 | 1 | 3) {
                return None;
            }
            let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
            if directory.record_number == 5 {
                if name.name_utf16 != [u16::from(b'.')] || parent != current {
                    return None;
                }
                components.reverse();
                return Some(components);
            }
            components.push(String::from_utf16(&name.name_utf16).ok()?);
            current = parent;
        }
    }
    if f.is_directory {
        return Some(vec![directory_path(raw, reference(f))?]);
    }
    let mut paths = Vec::with_capacity(f.names.len());
    for name in &f.names {
        let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
        let mut components = directory_path(raw, parent)?;
        components.push(String::from_utf16(&name.name_utf16).ok()?);
        if components.len() > 16 {
            return None;
        }
        paths.push(components);
    }
    // Prefer the shallowest name, then exact component order. One-name trees
    // keep the previous canonical path and serialization unchanged.
    paths.sort_by(|left, right| (left.len(), left).cmp(&(right.len(), right)));
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    Some(paths)
}
/// Exact role/name/ancestry recognition, never `is_metadata` as an exemption.
/// Recognition only identifies the replacement obligation; it does not prove
/// clean state, permit dropping allocations, or authorize replacement.
pub fn internal_role(raw: &ntfs::NtfsInspection, f: &FileInventory) -> Option<String> {
    internal_role_with_path(f, || path(raw, f))
}

/// Shared exact identity/attribute rules. Only path lookup differs between the
/// historical inline inventory and the complete paged source domain.
fn internal_role_with_path(
    f: &FileInventory,
    source_path: impl FnOnce() -> Option<Vec<String>>,
) -> Option<String> {
    if crate::ntfs_reparse::file_point(f).ok()?.is_some() {
        return None;
    }
    // Recognized NTFS internals are replaced, not recreated as user objects.
    // Their names/roles cannot authorize dropping otherwise valid EA metadata.
    if !crate::ntfs_extended_attributes::file_set(f)
        .ok()?
        .is_empty()
    {
        return None;
    }
    if f.base_file_reference != 0 || f.metadata_role_issue.is_some() {
        return None;
    }
    if (12..16).contains(&f.record_number) {
        return (f.metadata_role == MetadataRole::ReservedSystemRecord
            && f.names.is_empty()
            && f.streams.iter().all(|s| {
                s.name_utf16.is_empty()
                    && s.resident
                    && s.logical_size == 0
                    && s.initialized_size == 0
                    && s.allocated_size == 0
                    && s.extents.is_empty()
                    && s.flags == 0
            })
            && f.hard_link_count == 0
            && !f.is_directory
            && f.attributes.iter().all(|a| {
                matches!(a.type_code, 0x10 | 0x50 | 0x80)
                    && a.resident
                    && a.name_utf16.is_empty()
                    && a.flags == 0
            }))
        .then(|| "reserved_mft_slot".into());
    }
    let p = source_path()?;
    let canonical = match f.record_number {
        0 => "$MFT",
        1 => "$MFTMirr",
        2 => "$LogFile",
        3 => "$Volume",
        4 => "$AttrDef",
        6 => "$Bitmap",
        7 => "$Boot",
        8 => "$BadClus",
        9 => "$Secure",
        10 => "$UpCase",
        11 => "$Extend",
        _ => "",
    };
    if !canonical.is_empty() {
        return (f.metadata_role == MetadataRole::ReservedSystemRecord
            && p == [canonical]
            && f.is_directory == (f.record_number == 11))
            .then(|| canonical.into());
    }
    if f.metadata_role != MetadataRole::ExtendDescendantCandidate {
        return None;
    }
    let joined = p.join("\\");
    let directory = match joined.as_str() {
        "$Extend\\$Quota"
        | "$Extend\\$ObjId"
        | "$Extend\\$Reparse"
        | "$Extend\\$UsnJrnl"
        | "$Extend\\$RmMetadata\\$Repair"
        | "$Extend\\$RmMetadata\\$TxfLog\\$Tops"
        | "$Extend\\$RmMetadata\\$TxfLog\\$TxfLog.blf"
        | "$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000001"
        | "$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000002" => false,
        "$Extend\\$RmMetadata"
        | "$Extend\\$Deleted"
        | "$Extend\\$RmMetadata\\$TxfLog"
        | "$Extend\\$RmMetadata\\$Txf" => true,
        _ => return None,
    };
    (f.is_directory == directory).then_some(joined)
}
pub(crate) fn user_issues(raw: &ntfs::NtfsInspection, f: &FileInventory) -> Vec<String> {
    user_issues_profile(raw, f, false)
}
pub(crate) fn ordinary_user_issues(raw: &ntfs::NtfsInspection, f: &FileInventory) -> Vec<String> {
    user_issues_profile(raw, f, true)
}
fn user_issues_profile(
    raw: &ntfs::NtfsInspection,
    f: &FileInventory,
    ordinary: bool,
) -> Vec<String> {
    let paths = if ordinary
        || f.streams
            .iter()
            .any(|s| !s.name_utf16.is_empty() || s.flags == 0x8000)
    {
        user_paths(raw, f)
    } else {
        None
    };
    let names_supported = if ordinary {
        paths.is_some()
    } else {
        path(raw, f).is_some() && f.hard_link_count == 1
    };
    let system_volume_information = paths.as_ref().is_some_and(|paths| {
        paths.iter().any(|path| {
            path.first()
                .is_some_and(|name| name.eq_ignore_ascii_case("System Volume Information"))
        })
    });
    let descriptor = raw.security_reconciliation.as_ref().and_then(|s| {
        let binding = s.bindings.iter().find(|b| {
            b.record_number == f.record_number && b.sequence_number == f.sequence_number
        })?;
        s.descriptors
            .iter()
            .find(|d| d.descriptor.sha256 == binding.descriptor_sha256)
    });
    user_issues_with_context(
        f,
        ordinary,
        &raw.geometry,
        names_supported,
        system_volume_information,
        descriptor,
        None,
        n2r_win32::stream_layout::MAX_STREAMS,
        |stream| {
            crate::ntfs_attestation::source_stream_evidence_valid(raw, f, stream).unwrap_or(false)
        },
    )
}

/// Shared per-object preservation policy. The caller supplies already selected
/// path/security/source evidence; this function never invents an inventory or
/// grants admission from those diagnostic facts.
pub(crate) fn user_issues_with_context(
    f: &FileInventory,
    ordinary: bool,
    geometry: &ntfs::NtfsGeometry,
    names_supported: bool,
    system_volume_information: bool,
    descriptor: Option<&ntfs_security::DescriptorRecord>,
    descriptor_maximum: Option<u64>,
    maximum_streams: usize,
    source_evidence_valid: impl FnMut(&ntfs::StreamInventory) -> bool,
) -> Vec<String> {
    user_issues_with_context_alias_scope(
        f,
        ordinary,
        geometry,
        names_supported,
        system_volume_information,
        descriptor,
        descriptor_maximum,
        maximum_streams,
        false,
        false,
        false,
        false,
        source_evidence_valid,
    )
}

/// What to do about 8.3 short names on a data volume. ReFS has none, and
/// Windows has the tool that removes them.
pub const SHORT_NAME_REMEDY: &str = "remove the volume's short names with `fsutil 8dot3name strip /s /f <drive>:\\` and turn their creation off with `fsutil 8dot3name set <drive>: 1`, then convert (a program that stored a path in its short form will no longer find it). Or convert with `--short-names drop`, which leaves the short names behind and keeps a list of them";

/// The names of Win32 file-attribute bits, for a refusal.
pub fn file_attribute_names(bits: u32) -> String {
    const NAMES: [(u32, &str); 14] = [
        (0x40, "DEVICE"),
        (0x80, "NORMAL"),
        (0x100, "TEMPORARY"),
        (0x200, "SPARSE_FILE"),
        (0x400, "REPARSE_POINT"),
        (0x800, "COMPRESSED"),
        (0x1000, "OFFLINE"),
        (0x4000, "ENCRYPTED (decrypt the file with `cipher /d`)"),
        (0x8000, "INTEGRITY_STREAM"),
        (0x2_0000, "NO_SCRUB_DATA"),
        (0x4_0000, "RECALL_ON_OPEN"),
        (0x8_0000, "PINNED"),
        (0x10_0000, "UNPINNED"),
        (0x40_0000, "RECALL_ON_DATA_ACCESS"),
    ];
    let mut names: Vec<String> = NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect();
    let unnamed = NAMES.iter().fold(bits, |rest, (bit, _)| rest & !bit);
    if unnamed != 0 {
        names.push(format!("{unnamed:#x}"));
    }
    names.join(", ")
}

/// What an attribute the converter refuses is, where that says more than
/// its type number.
fn attribute_meaning(file: &FileInventory, attribute: &ntfs::AttributeInventory) -> &'static str {
    if attribute.flags & 0x4000 != 0 {
        " (the data is encrypted with EFS: decrypt the file with `cipher /d`, or move it off the volume)"
    } else if attribute.type_code == 0x40 {
        " (an object ID that the volume's object-ID index does not account for)"
    } else if attribute.type_code == 0x100 {
        " (a logged utility stream: EFS keys or transaction data)"
    } else if attribute.type_code == 0x80 && file.is_directory {
        " (a named data stream on a directory)"
    } else {
        ""
    }
}

/// The true alias scope is supplied only after a held WindowsAliasDomain has
/// conserved this record's DOS paths. Ordinary data callers use the wrapper.
pub(crate) fn user_issues_with_context_alias_scope(
    f: &FileInventory,
    ordinary: bool,
    geometry: &ntfs::NtfsGeometry,
    names_supported: bool,
    system_volume_information: bool,
    descriptor: Option<&ntfs_security::DescriptorRecord>,
    descriptor_maximum: Option<u64>,
    maximum_streams: usize,
    windows_alias_paths_preserved: bool,
    default_storage_hint_normalization: bool,
    verified_windows_txf_metadata: bool,
    verified_windows_object_id_disposition: bool,
    mut source_evidence_valid: impl FnMut(&ntfs::StreamInventory) -> bool,
) -> Vec<String> {
    let mut issues = vec![];
    if f.metadata_role_issue.is_some()
        || !matches!(
            f.metadata_role,
            MetadataRole::OutsideExtendCandidate | MetadataRole::ReservedSystemRecord
        )
        || (f.record_number < 16 && f.record_number != 5)
    {
        issues.push(
            "it is an NTFS-internal object in a state the converter does not take over".into(),
        );
    }
    let ea_supported = ordinary && crate::ntfs_extended_attributes::file_set(f).is_ok();
    let reparse = if ordinary {
        crate::ntfs_reparse::file_point(f).ok().flatten()
    } else {
        None
    };
    if let Some(point) = &reparse {
        if (point.tag() == 0xa0000003 && !f.is_directory)
            || (!f.is_directory && (f.streams.len() != 1 || f.streams[0].logical_size != 0))
            // Extended attributes beside a reparse point are what the
            // Windows Subsystem for Linux keeps owner and mode in; with any
            // other kind of point they are not something Windows makes.
            || (!n2r_win32::reparse_layout::is_wsl_tag(point.tag())
                && crate::ntfs_extended_attributes::file_set(f).is_ok_and(|ea| !ea.is_empty()))
        {
            issues.push(
                "its reparse point is of a kind the converter does not recreate, or comes with data or extended attributes".into(),
            );
        }
    }
    let short_name = f.names.iter().find(|n| n.namespace == 2);
    // A short name is no issue where it is dealt with: a Windows volume's
    // becomes a link, and a run asked to drop them lists it in its records.
    let short_names_accounted =
        windows_alias_paths_preserved || crate::short_name_disposition::dropped();
    if let (false, Some(name)) = (short_names_accounted, short_name) {
        issues.push(format!(
            "it has an 8.3 short name ({}), which ReFS does not have: {}",
            String::from_utf16_lossy(&name.name_utf16),
            SHORT_NAME_REMEDY
        ));
    } else if !names_supported {
        issues.push(
            "its name, or the set of names it has, is one the converter does not recreate (a name that is not valid UTF-16, or a directory with more than one name)"
                .into(),
        );
    }
    let unsupported_attribute = f.attributes.iter().find(|a| {
        let plain =
            matches!(a.type_code, 0x10 | 0x30 | 0x50) && a.name_utf16.is_empty() && a.resident;
        let data = !f.is_directory
            && a.type_code == 0x80
            && (a.name_utf16.is_empty() || (ordinary && valid_named_stream_name(&a.name_utf16)));
        let index = f.is_directory
            && matches!(a.type_code, 0x90 | 0xa0 | 0xb0)
            && ntfs_namespace::is_i30(&a.name_utf16);
        let root_txf = f.record_number == 5 && f.is_directory && recognized_root_txf(a);
        let windows_txf = windows_alias_paths_preserved
            && verified_windows_txf_metadata
            && recognized_root_txf(a);
        // An object ID that its route has accounted for and does not carry
        // over: a Windows volume's by what Windows answered for it, a data
        // volume's by its own index.
        let windows_object_id = verified_windows_object_id_disposition
            && a.type_code == 0x40
            && a.name_utf16.is_empty()
            && a.resident
            && a.flags == 0
            && a.logical_size == 16
            && a.initialized_size == 16
            && a.allocated_size == 16
            && a.lowest_vcn == 0
            && a.compression_unit == 0
            && a.extents.is_empty();
        #[cfg(windows)]
        let default_storage_hint = windows_alias_paths_preserved
            && default_storage_hint_normalization
            && crate::ntfs_storage_class::recognized_default(a);
        #[cfg(not(windows))]
        let default_storage_hint = {
            let _ = default_storage_hint_normalization;
            false
        };
        let ea = ea_supported && matches!(a.type_code, 0xd0 | 0xe0) && a.name_utf16.is_empty();
        let point = reparse.is_some() && a.type_code == 0xc0 && a.name_utf16.is_empty();
        let sparse_data = ordinary
            && data
            && !a.resident
            && a.flags == 0x8000
            && crate::ntfs_inspect::sparse_unit_supported(
                a.compression_unit,
                geometry.cluster_size,
            );
        let compressed_data = ordinary
            && data
            && a.flags == 1
            && crate::ntfs_compression::supported(a, geometry).is_ok();
        // Resident I30 compression is an inheritance policy marker; the
        // index value still passes the complete raw namespace parser.
        let compressed_directory_policy = ordinary
            && index
            && a.type_code == 0x90
            && a.resident
            && a.flags == 1
            && a.compression_unit == 0
            && a.extents.is_empty()
            && f.standard_information
                .as_ref()
                .is_some_and(|si| si.file_attributes & 0x800 != 0);
        !(plain
            || data
            || index
            || root_txf
            || windows_txf
            || windows_object_id
            || ea
            || point
            || default_storage_hint)
            || ((a.flags != 0 || a.compression_unit != 0)
                && !sparse_data
                && !compressed_data
                && !compressed_directory_policy)
            || a.lowest_vcn != 0
    });
    if f.base_file_reference != 0 {
        issues.push("unsupported or unassembled attribute semantics: an extension record".into());
    } else if let Some(a) = unsupported_attribute {
        issues.push(format!(
            "unsupported or unassembled attribute semantics: attribute type {:#x} {:?}, {}, flags {:#x}, compression unit {}, lowest VCN {}{}",
            a.type_code,
            String::from_utf16_lossy(&a.name_utf16),
            if a.resident { "resident" } else { "nonresident" },
            a.flags,
            a.compression_unit,
            a.lowest_vcn,
            attribute_meaning(f, a)
        ));
    }
    if f.record_number == 5
        && f.attributes
            .iter()
            .filter(|attribute| {
                attribute.type_code == 0x100
                    && attribute.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
            })
            .count()
            > 1
    {
        issues.push("duplicate root transaction metadata".into());
    }
    let has_sparse = f.streams.iter().any(|s| s.flags == 0x8000);
    let has_verified_eas = ordinary && crate::ntfs_attestation::has_verified_nonempty_eas(f);
    let carried_attributes = 0x2027
        | if reparse.is_some() { 0x400 } else { 0 }
        | if has_sparse && !f.is_directory {
            0x200
        } else {
            0
        }
        | if has_verified_eas { 0x40000 } else { 0 }
        | if ordinary { 0x800 } else { 0 };
    match crate::ntfs_file_attributes::project_user(f) {
        Ok(attributes) if attributes.source_attributes & !carried_attributes == 0 => {}
        Ok(attributes) => issues.push(format!(
            "it has file attributes the converter does not carry over: {}",
            file_attribute_names(attributes.source_attributes & !carried_attributes)
        )),
        Err(error) => issues.push(format!(
            "its standard information is not in a form the converter reads: {error:#}"
        )),
    }
    match descriptor {
        Some(record) if ordinary => {
            let validated = hex::decode(&record.descriptor.relative_hex)
                .ok()
                .and_then(|bytes| {
                    if let Some(maximum) = descriptor_maximum {
                        n2r_win32::security_descriptor::validate_with_limit(&bytes, maximum).ok()
                    } else {
                        n2r_win32::security_descriptor::validate(&bytes).ok()
                    }
                });
            if validated.is_none() {
                issues.push(
                    "its security descriptor cannot be set on the target as it is (larger than one object's working memory, or with an entry type Windows does not take back)"
                        .into(),
                );
            }
        }
        Some(record) if record.descriptor.sacl.state == ntfs_security::AclState::Absent => (),
        _ => issues.push("initial preservation profile requires verified SACL absence".into()),
    }
    if f.streams.iter().any(|stream| !stream.name_utf16.is_empty()) && system_volume_information {
        issues.push("named streams on System Volume Information objects require a separate system-payload implementation".into());
    }
    if has_sparse {
        if system_volume_information {
            issues.push(
                "sparse system-managed streams require a separate system-payload implementation"
                    .into(),
            );
        }
    }
    if f.is_directory {
        if !f.streams.is_empty() {
            issues.push(
                "it is a directory with a named data stream, which the converter does not carry over: remove the stream before converting"
                    .into(),
            );
        }
    } else {
        let mut exact_names = BTreeSet::new();
        let mut folded_names = BTreeSet::new();
        let stream_names_valid = !f.streams.is_empty()
            && f.streams.len() <= maximum_streams
            && f.streams.iter().filter(|s| s.name_utf16.is_empty()).count() == 1
            && f.streams.iter().all(|s| {
                (s.name_utf16.is_empty() || (ordinary && valid_named_stream_name(&s.name_utf16)))
                    && exact_names.insert(s.name_utf16.clone())
                    && String::from_utf16(&s.name_utf16)
                        .is_ok_and(|name| folded_names.insert(name.to_uppercase()))
            });
        if !stream_names_valid
            || (!ordinary && f.streams.len() != 1)
            || f.streams.iter().any(|s| {
                (!ordinary && !s.name_utf16.is_empty())
                    || (s.flags != 0
                        && !(ordinary && !s.resident && s.flags == 0x8000)
                        && !(ordinary && compressed_stream_supported_with_geometry(geometry, f, s)))
                    || s.initialized_size > s.logical_size
                    || (!ordinary
                        && (s.resident
                            || s.logical_size == 0
                            || !s.logical_size.is_multiple_of(65536)
                            || s.logical_size != s.initialized_size
                            || s.logical_size != s.allocated_size
                            || s.extents.len() != 1
                            || s.extents[0].logical_offset != 0
                            || s.extents[0].physical_offset.is_none()
                            || s.extents[0].length != s.logical_size))
                    || !source_evidence_valid(s)
            })
        {
            issues.push(
                "one of its data streams is stored in a form the converter does not read (encrypted, or compressed, sparse or named outside what it handles)"
                    .into(),
            );
        }
    }
    issues
}
/// Recompute this decision from pinned raw/native evidence. The CLI does not
/// deserialize a previously successful decision as authority.
pub fn assess(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
) -> Assessment {
    assess_with_backups(raw, comparison, native_schema, None)
}
pub fn assess_with_backups(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
) -> Assessment {
    assess_source_view(raw, comparison, native_schema, backups, None)
}
pub fn assess_ordinary_with_backups(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
) -> Assessment {
    assess_ordinary_with_resource_profile(
        raw,
        comparison,
        native_schema,
        backups,
        ResourceProfile::AlphaV1,
    )
}
/// Resource opt-in changes only bounded diagnostics. It does not supply the
/// matching complete native/target evidence needed for source admission.
pub fn assess_ordinary_with_resource_profile(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
    resources: ResourceProfile,
) -> Assessment {
    assess_source_view_profile(
        raw,
        comparison,
        native_schema,
        backups,
        None,
        true,
        resources,
    )
}
/// The opaque live observer is the only caller supplying a frozen-bound view.
/// Replay diagnostics cannot remove strict native object refusals.
pub(crate) fn assess_source_view(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
    source_view: Option<crate::ntfs_source_view::Analysis>,
) -> Assessment {
    assess_source_view_profile(
        raw,
        comparison,
        native_schema,
        backups,
        source_view,
        false,
        ResourceProfile::AlphaV1,
    )
}
pub(crate) fn assess_ordinary_source_view(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
    source_view: Option<crate::ntfs_source_view::Analysis>,
) -> Assessment {
    assess_ordinary_source_view_with_resources(
        raw,
        comparison,
        native_schema,
        backups,
        source_view,
        ResourceProfile::AlphaV1,
    )
}
pub(crate) fn assess_ordinary_source_view_with_resources(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
    source_view: Option<crate::ntfs_source_view::Analysis>,
    resources: ResourceProfile,
) -> Assessment {
    assess_source_view_profile(
        raw,
        comparison,
        native_schema,
        backups,
        source_view,
        true,
        resources,
    )
}
fn assess_source_view_profile(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
    source_view: Option<crate::ntfs_source_view::Analysis>,
    ordinary: bool,
    resources: ResourceProfile,
) -> Assessment {
    let limits = resources.limits();
    let path_index_valid = has_unique_sorted_records(raw);
    let backups = backups.filter(|b| b.binds(raw));
    let view_is_live = source_view
        .as_ref()
        .is_some_and(|v| v.binds_live(&comparison.source_inspection_sha256));
    let mut objects = vec![];
    let mut files = 0;
    let mut directories = 0;
    let mut bytes = 0u64;
    let mut data_streams = 0usize;
    for f in &raw.files {
        let internal = internal_role(raw, f);
        let (disposition, role, mut issues) = if let Some(role) = internal {
            (Disposition::RecognizedFilesystemInternal, role, vec![])
        } else if f.record_number == 5 || f.metadata_role == MetadataRole::OutsideExtendCandidate {
            if f.is_directory {
                directories += 1;
            } else {
                files += 1;
            }
            bytes = f
                .streams
                .iter()
                .try_fold(bytes, |sum, s| sum.checked_add(s.logical_size))
                .unwrap_or(u64::MAX);
            data_streams = data_streams
                .checked_add(f.streams.len())
                .unwrap_or(usize::MAX);
            let issues = if ordinary {
                ordinary_user_issues(raw, f)
            } else {
                user_issues(raw, f)
            };
            let disposition = if issues.is_empty() {
                Disposition::PreserveSupportedUserSemantics
            } else {
                Disposition::Reject
            };
            (disposition, "user_namespace".into(), issues)
        } else {
            (
                Disposition::Reject,
                "unresolved_internal_object".into(),
                vec!["no verified filesystem-internal role/replacement policy".into()],
            )
        };
        if disposition != Disposition::RecognizedFilesystemInternal {
            let view = source_view.as_ref().filter(|_| view_is_live).and_then(|v| {
                v.objects.iter().find(|o| {
                    o.record_number == f.record_number && o.sequence_number == f.sequence_number
                })
            });
            match comparison.files.iter().find(|o| {
                o.record_number == f.record_number && o.sequence_number == f.sequence_number
            }) {
                Some(o) if o.matched || view.is_some_and(|v| v.metadata.matched) => (),
                Some(o) => issues.extend(o.issues.iter().map(|s| format!("native metadata: {s}"))),
                None => issues.push("native metadata identity missing".into()),
            }
            if !comparison.native_logical_data.as_ref().is_some_and(|d| {
                d.audit.matched
                    && d.files.iter().any(|o| {
                        o.record_number == f.record_number
                            && o.sequence_number == f.sequence_number
                            && o.all_requested_stream_evidence_matched
                            && o.check.matched
                    })
            }) {
                issues.push("native logical-data evidence missing or mismatched".into());
            }
            if !comparison.native_streams.as_ref().is_some_and(|s| {
                s.files.iter().any(|o| {
                    o.record_number == f.record_number
                        && o.sequence_number == f.sequence_number
                        && o.check.matched
                })
            }) {
                issues.push("native stream ownership evidence missing or mismatched".into());
            }
            if f.is_directory
                && !comparison.native_namespace.as_ref().is_some_and(|n| {
                    n.directories.iter().any(|o| {
                        o.record_number == f.record_number
                            && o.sequence_number == f.sequence_number
                            && o.check.matched
                    })
                })
                && !view
                    .and_then(|v| v.directory.as_ref())
                    .is_some_and(|d| d.check.matched)
            {
                issues.push("native directory completeness is unresolved".into());
            }
        }
        objects.push(ObjectDecision {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            disposition: if !issues.is_empty()
                && disposition != Disposition::RecognizedFilesystemInternal
            {
                Disposition::Reject
            } else {
                disposition
            },
            role,
            issues,
        });
    }
    let directory_case_admission = directory_case_admission(raw, comparison, None);
    let mut gates = vec![];
    let mut gate = |code: &str, satisfied: bool, detail: &str| {
        gates.push(Gate {
            code: code.into(),
            satisfied,
            detail: detail.into(),
        })
    };
    let raw_ids: BTreeSet<_> = raw
        .files
        .iter()
        .map(|f| (f.record_number, f.sequence_number))
        .collect();
    let native_ids: BTreeSet<_> = comparison
        .files
        .iter()
        .map(|f| (f.record_number, f.sequence_number))
        .collect();
    gate(
        "native_identity_coverage",
        raw_ids.len() == raw.files.len()
            && native_ids.len() == comparison.files.len()
            && raw_ids == native_ids,
        "missing, duplicate or unexpected native file identities prevent admission",
    );
    gate(
        "geometry",
        resources.supports_source_geometry(&raw.geometry),
        "source geometry must match the selected resource profile; target allocation units remain 4 KiB",
    );
    gate(
        "clean_volume",
        raw.dirty == Some(false)
            && raw.volume_flags.is_some_and(|flags| flags & 1 == 0)
            && raw.volume_version.as_deref() == Some("3.1"),
        "require NTFS 3.1 and a clear on-disk $Volume dirty bit; independent native dirty-state observations are bound by the separate live transaction_freeze gate",
    );
    gate(
        "volume_policy_flags",
        raw.volume_flags == Some(0),
        "nonzero NTFS policy flags require independent native meaning and preservation evidence; 0x0080 is observed on clean Windows 11 lab volumes",
    );
    gate(
        "raw_allocation",
        raw.allocation_reconciliation
            .as_ref()
            .is_some_and(|a| a.status == ntfs::AllocationReconciliationStatus::ConsistentRawModel),
        "every supplied attribute interval and allocation bitmap must reconcile",
    );
    gate(
        "raw_mft_record_coverage",
        path_index_valid && ntfs::validate_record_coverage(raw).is_ok(),
        "canonical files must be uniquely ordered and every allocated physical record must be a canonical file or a uniquely bound extension",
    );
    gate(
        "raw_namespace",
        raw.namespace_reconciliation
            .as_ref()
            .is_some_and(|n| n.status == ntfs_namespace::Status::ConsistentRawModel),
        "all raw indexes, names, references and reachability must reconcile",
    );
    gate(
        "raw_security",
        raw.security_reconciliation
            .as_ref()
            .is_some_and(|s| s.status == ntfs_security::Status::ConsistentRawModel),
        "all stored security descriptors and object bindings must resolve",
    );
    gate(
        "native_profile",
        (matches!(native_schema, 5..=7)
            || (native_schema == 13 && resources.native_profile().is_none()))
            && comparison.native_namespace.is_some()
            && comparison.native_logical_data.is_some(),
        "older replay reports do not supply complete native namespace/logical-data evidence",
    );
    gate(
        "native_volume_allocation",
        comparison
            .native_streams
            .as_ref()
            .is_some_and(|s| s.bitmap.matched),
        "the full native bitmap must match; per-user stream checks also bind the physical retrieval base",
    );
    if matches!(native_schema, 13 | 14) {
        gate(
            "native_directory_case_sensitivity",
            directory_case_admission
                .as_ref()
                .is_some_and(|scope| scope.all_required_directories_case_insensitive),
            "every raw directory requires actual stable zero case flags until exact independently validated internal replacements are bound; role recognition alone cannot narrow the case obligation",
        );
    }
    gate(
        "objects",
        !objects.is_empty() && objects.iter().all(|o| o.disposition != Disposition::Reject),
        "every allocated object needs an explicit supported or recognized-internal disposition",
    );
    gate(
        "resource_limits",
        files > 0
            && files <= limits.maximum_files
            && directories <= limits.maximum_directories
            && files
                .checked_add(directories)
                .is_some_and(|n| n <= resources.maximum_objects())
            && data_streams <= MAX_DATA_STREAMS
            && bytes <= limits.maximum_logical_bytes,
        "limit ordinary files/directories, 16,384 total DATA streams and logical bytes; no automatic budget widening",
    );
    gate(
        "source_backups",
        backups.is_some(),
        "verify the backup boot sector and all four mirrored MFT records through actual source reads",
    );
    gate(
        "log_restart_pages",
        false,
        "read and reconcile both $LogFile restart pages from the frozen device; clean flags alone do not prove complete log recovery",
    );
    let unresolved = unresolved_codes(raw, backups.is_some(), false, false, None);
    let internal_txf_count = raw
        .blockers
        .iter()
        .filter(|blocker| accounted_internal_txf_blocker(raw, blocker))
        .count();
    let empty_badclus_count = raw
        .blockers
        .iter()
        .filter(|blocker| accounted_empty_badclus_blocker(raw, blocker))
        .count();
    gate(
        "remaining_inspection_refusals",
        unresolved.is_empty(),
        &format!(
            "unresolved inspection checks: {unresolved:?}; exact internal TxF replacements still pending: {internal_txf_count}; empty internal $BadClus streams accounted: {empty_badclus_count}"
        ),
    );
    gate(
        "internal_replacement_state",
        false,
        "role recognition is not clean log, backup, transaction, quota/object-id or replacement-state validation",
    );
    gate(
        "security_timestamp_preservation",
        false,
        "native security projections and persisted/cache timestamp views need a qualified target round trip",
    );
    gate(
        "frozen_device_basis",
        false,
        "capture and revalidate the actual device after lock/flush and persistent exclusion; a JSON flag is insufficient",
    );
    if resources != ResourceProfile::AlphaV1 {
        gate(
            "native_resource_profile_support",
            false,
            "matching complete live native attestation for this exact source profile is required; target preservation remains a separate gate",
        );
        gate(
            "target_resource_profile_support",
            false,
            "the same resource profile requires actual protected native target preservation before a certificate can issue",
        );
    }
    Assessment {
        schema_version: 1,
        profile: if ordinary {
            resources.ordinary_admission_profile()
        } else {
            PROFILE
        }
        .into(),
        source_inspection_sha256: comparison.source_inspection_sha256.clone(),
        objects,
        gates,
        user_files: files,
        user_directories: directories,
        user_logical_bytes: bytes,
        source_admitted: false,
        certificate_issued: false,
        execution_authorized: false,
        backup_evidence: backups.cloned(),
        source_view,
        directory_case_admission,
    }
}

/// Bind the expanded source profile only to an opaque native observation of
/// the excluded source. Recompute the comparison and projected source view
/// from the actual report and raw inventory; serialized success flags cannot
/// satisfy this gate. Target preservation remains independently required.
#[cfg(windows)]
pub(crate) fn bind_large_native_profile(
    assessment: &mut Assessment,
    raw: &ntfs::NtfsInspection,
    observed: &n2r_win32::GeneralLiveNtfsObservation,
    expected_source_sha256: &str,
    replacements: Option<&BoundInternalReplacements>,
) -> Result<()> {
    use n2r_win32::attestation::ResourceProfile as NativeProfile;

    let native = observed.report();
    let resources = match native.request.resource_profile {
        Some(NativeProfile::ExperimentalLargeTreeV1) => ResourceProfile::ExperimentalLargeTreeV1,
        Some(NativeProfile::ExperimentalStreamingTreeV2) => {
            ResourceProfile::ExperimentalStreamingTreeV2
        }
        Some(NativeProfile::ExperimentalObjectEnvelopeV3(admission)) => {
            ResourceProfile::ExperimentalObjectEnvelopeV3(admission)
        }
        Some(NativeProfile::ResourceBoundedV4(_)) => {
            anyhow::bail!(
                "resource-bounded source admission requires the actual paged native lease"
            )
        }
        None => anyhow::bail!("expanded source profile requires native resource evidence"),
    };
    let inspection = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    ensure!(
        assessment.profile == resources.ordinary_admission_profile()
            && assessment.source_inspection_sha256 == inspection
            && matches!(
                (native.schema_version, native.request.schema_version),
                (11, 3) | (12, 4) | (13, 5) | (14, 6)
            )
            && native.request.resource_profile == resources.native_profile()
            && native.request.source_inspection_sha256 == inspection
            && expected_source_sha256.len() == 64
            && expected_source_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && assessment
                .source_view
                .as_ref()
                .is_some_and(|view| view.binds_live_source(&inspection, expected_source_sha256))
            && assessment
                .gates
                .iter()
                .any(|gate| gate.code == "frozen_device_basis" && gate.satisfied),
        "large native resource profile is not bound to the current frozen source"
    );
    native.validate_resources()?;
    let comparison = crate::ntfs_attestation::compare(raw, &inspection, native)?;
    let mut view = crate::ntfs_source_view::diagnose(raw, &inspection, native)?;
    view.bind_frozen_source(expected_source_sha256);
    ensure!(
        serde_json::to_vec(&view)? == serde_json::to_vec(assessment.source_view.as_ref().unwrap())?,
        "large native source-view evidence differs from the live observation"
    );
    let mut fresh = assess_source_view_profile(
        raw,
        &comparison,
        native.schema_version,
        assessment.backup_evidence.as_ref(),
        Some(view),
        true,
        resources,
    );
    bind_directory_case_admission(&mut fresh, raw, &comparison, replacements);
    ensure!(
        serde_json::to_vec(&fresh.directory_case_admission)?
            == serde_json::to_vec(&assessment.directory_case_admission)?,
        "large native directory-case scope differs from the bound replacement proof and fresh raw observations"
    );
    let objects_match =
        serde_json::to_vec(&fresh.objects)? == serde_json::to_vec(&assessment.objects)?;
    let failed_gates: Vec<_> = [
        "native_identity_coverage",
        "native_volume_allocation",
        "native_directory_case_sensitivity",
        "objects",
        "resource_limits",
    ]
    .iter()
    .filter_map(
        |code| match fresh.gates.iter().find(|gate| gate.code == *code) {
            Some(gate) if gate.satisfied => None,
            Some(gate) => Some((*code, gate.detail.as_str())),
            None => Some((*code, "gate absent")),
        },
    )
    .collect();
    let rejected_objects: Vec<_> = fresh
        .objects
        .iter()
        .filter(|object| object.disposition == Disposition::Reject || !object.issues.is_empty())
        .collect();
    let logical_audit = comparison
        .native_logical_data
        .as_ref()
        .map(|data| &data.audit);
    ensure!(
        objects_match
            && failed_gates.is_empty()
            && comparison.native_namespace.is_some()
            && logical_audit.is_some_and(|audit| audit.matched),
        "large native resource evidence does not completely reconcile with source objects: objects_match={objects_match}; failed_gates={failed_gates:?}; namespace_present={}; logical_audit={logical_audit:?}; rejected_objects_total={}; first_rejected_objects={:?}",
        comparison.native_namespace.is_some(),
        rejected_objects.len(),
        &rejected_objects[..rejected_objects.len().min(24)]
    );
    ensure!(
        ["native_profile", "native_resource_profile_support"]
            .iter()
            .all(|code| assessment
                .gates
                .iter()
                .filter(|gate| gate.code == *code && !gate.satisfied)
                .count()
                == 1)
            && [
                "security_timestamp_preservation",
                "target_resource_profile_support"
            ]
            .iter()
            .all(|code| assessment
                .gates
                .iter()
                .filter(|gate| gate.code == *code && !gate.satisfied)
                .count()
                == 1),
        "large native or independent target-preservation gates differ"
    );
    let mut native_gate = false;
    let mut resource_gate = false;
    for gate in &mut assessment.gates {
        if gate.code == "native_profile" {
            gate.satisfied = true;
            gate.detail = format!(
                "schema-{} live native namespace and logical-data observations were independently reconciled against the frozen source",
                native.schema_version
            );
            native_gate = true;
        } else if gate.code == "native_resource_profile_support" {
            gate.satisfied = true;
            gate.detail = "the exact schema-3 large-resource request, schema-8 native evidence, resource accounting and user-object coverage match the bound frozen source; target preservation is still required".into();
            resource_gate = true;
        }
    }
    ensure!(
        native_gate && resource_gate,
        "large native assessment gates are absent"
    );
    Ok(())
}
