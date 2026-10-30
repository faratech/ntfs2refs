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
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PROFILE: &str = "existing-data-tree-v1";
pub const ORDINARY_PROFILE: &str = "ordinary-data-tree-v2";
/// A source-model candidate must not silently become public ADS conversion
/// support before the native stream graph and its verifier are connected.

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
    /// Source allocation units are independent of the fixed 4 KiB ReFS target.
    /// The expanded geometry remains explicitly experimental and still uses
    /// the same bounded tree, native-observation and journal requirements.
    pub fn supports_source_geometry(self, geometry: &ntfs::NtfsGeometry) -> bool {
        geometry.bytes_per_sector == 512
            && geometry.file_record_size == 1024
            && geometry.index_record_size == 4096
            && match self {
                Self::AlphaV1 => geometry.cluster_size == 4096,
                Self::ExperimentalLargeTreeV1 | Self::ExperimentalStreamingTreeV2 => {
                    geometry.cluster_size >= 4096
                        && crate::ntfs_index::supports_cluster_size(geometry.cluster_size)
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
        }
    }

    pub const fn limits(self) -> ResourceLimits {
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
        }
    }

    pub const fn ordinary_admission_profile(self) -> &'static str {
        match self {
            Self::AlphaV1 => ORDINARY_PROFILE,
            Self::ExperimentalLargeTreeV1 => "ordinary-data-tree-large-v1",
            Self::ExperimentalStreamingTreeV2 => "ordinary-data-tree-streaming-v2",
        }
    }

    pub const fn ordinary_shadow_profile(self) -> &'static str {
        match self {
            Self::AlphaV1 => "native-ordinary-tree-shadow-v2",
            Self::ExperimentalLargeTreeV1 => "native-ordinary-tree-shadow-large-v1",
            Self::ExperimentalStreamingTreeV2 => "native-ordinary-tree-shadow-streaming-v2",
        }
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
            .filter(|attribute| attribute.type_code == 0x100)
            .count()
            == 1
        && file
            .attributes
            .iter()
            .any(|attribute| recognized_root_txf(attribute))
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
        || policy.windows_version != [10, 0, 26300]
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

#[derive(Debug, Serialize)]
pub struct InternalReplacement {
    pub record_number: u64,
    pub role: String,
    pub action: &'static str,
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
) -> Option<Vec<InternalReplacement>> {
    let required = [
        "clean_volume",
        "raw_allocation",
        "raw_namespace",
        "raw_security",
        "objects",
        "native_volume_allocation",
        "source_backups",
        "log_restart_pages",
        "remaining_inspection_refusals",
        "frozen_device_basis",
    ];
    if !indexes.binds(raw)
        || !indexes.replacement_supported
        || !transactions.binds(raw)
        || required.iter().any(|code| {
            !assessment
                .gates
                .iter()
                .any(|g| g.code == *code && g.satisfied)
        })
    {
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
    Some(replacements)
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
    let p = path(raw, f)?;
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
    let mut issues = vec![];
    if f.metadata_role_issue.is_some()
        || !matches!(
            f.metadata_role,
            MetadataRole::OutsideExtendCandidate | MetadataRole::ReservedSystemRecord
        )
        || (f.record_number < 16 && f.record_number != 5)
    {
        issues.push("source object role is unresolved or unsupported".into());
    }
    let names_supported = if ordinary {
        user_paths(raw, f).is_some()
    } else {
        path(raw, f).is_some() && f.hard_link_count == 1
    };
    if !names_supported || f.names.iter().any(|n| n.namespace == 2) {
        issues
            .push("names, depth, short-name aliases or directory links exceed the profile".into());
    }
    if f.base_file_reference != 0
        || f.attributes.iter().any(|a| {
            let plain =
                matches!(a.type_code, 0x10 | 0x30 | 0x50) && a.name_utf16.is_empty() && a.resident;
            let data = !f.is_directory
                && a.type_code == 0x80
                && (a.name_utf16.is_empty()
                    || (ordinary && valid_named_stream_name(&a.name_utf16)));
            let index = f.is_directory
                && matches!(a.type_code, 0x90 | 0xa0 | 0xb0)
                && ntfs_namespace::is_i30(&a.name_utf16);
            let root_txf = f.record_number == 5 && f.is_directory && recognized_root_txf(a);
            !(plain || data || index || root_txf)
                || a.flags != 0
                || a.compression_unit != 0
                || a.lowest_vcn != 0
        })
    {
        issues.push("unsupported or unassembled attribute semantics".into());
    }
    if f.record_number == 5
        && f.attributes
            .iter()
            .filter(|attribute| attribute.type_code == 0x100)
            .count()
            > 1
    {
        issues.push("duplicate root transaction metadata".into());
    }
    if f.standard_information
        .as_ref()
        .is_none_or(|si| si.file_attributes & !0x2027 != 0)
    {
        issues.push("unsupported attributes or missing standard information".into());
    }
    let descriptor = raw.security_reconciliation.as_ref().and_then(|s| {
        let binding = s.bindings.iter().find(|b| {
            b.record_number == f.record_number && b.sequence_number == f.sequence_number
        })?;
        s.descriptors
            .iter()
            .find(|d| d.descriptor.sha256 == binding.descriptor_sha256)
    });
    if descriptor.is_none_or(|d| d.descriptor.sacl.state != ntfs_security::AclState::Absent) {
        issues.push("initial preservation profile requires verified SACL absence".into());
    }
    if f.streams.iter().any(|stream| !stream.name_utf16.is_empty())
        && user_paths(raw, f).is_some_and(|paths| {
            paths.iter().any(|path| {
                path.first()
                    .is_some_and(|name| name.eq_ignore_ascii_case("System Volume Information"))
            })
        })
    {
        issues.push("named streams on System Volume Information objects require a separate system-payload implementation".into());
    }
    if f.is_directory {
        if !f.streams.is_empty() {
            issues.push("directory data streams exceed the profile".into());
        }
    } else {
        let mut exact_names = BTreeSet::new();
        let mut folded_names = BTreeSet::new();
        let stream_names_valid = !f.streams.is_empty()
            && f.streams.len() <= n2r_win32::stream_layout::MAX_STREAMS
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
                    || s.flags != 0
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
                    || s.logical_hash_status != ntfs::LogicalHashStatus::Complete
            })
        {
            issues.push(
                "stream requires a later resident, sparse, fragmented, tail or encoded profile"
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
        matches!(native_schema, 5..=7)
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
) -> Result<()> {
    use n2r_win32::attestation::ResourceProfile as NativeProfile;

    let native = observed.report();
    let resources = match native.request.resource_profile {
        Some(NativeProfile::ExperimentalLargeTreeV1) => ResourceProfile::ExperimentalLargeTreeV1,
        Some(NativeProfile::ExperimentalStreamingTreeV2) => {
            ResourceProfile::ExperimentalStreamingTreeV2
        }
        None => anyhow::bail!("expanded source profile requires native resource evidence"),
    };
    let inspection = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    ensure!(
        assessment.profile == resources.ordinary_admission_profile()
            && assessment.source_inspection_sha256 == inspection
            && matches!(native.schema_version, 8 | 9)
            && native.request.schema_version == 3
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
    let fresh = assess_source_view_profile(
        raw,
        &comparison,
        native.schema_version,
        assessment.backup_evidence.as_ref(),
        Some(view),
        true,
        resources,
    );
    ensure!(
        serde_json::to_vec(&fresh.objects)? == serde_json::to_vec(&assessment.objects)?
            && [
                "native_identity_coverage",
                "native_volume_allocation",
                "objects",
                "resource_limits"
            ]
            .iter()
            .all(|code| fresh
                .gates
                .iter()
                .any(|gate| gate.code == *code && gate.satisfied))
            && comparison.native_namespace.is_some()
            && comparison
                .native_logical_data
                .as_ref()
                .is_some_and(|data| data.audit.matched),
        "large native resource evidence does not completely reconcile with source objects"
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
