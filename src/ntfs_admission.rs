//! One conservative source decision over existing independent reconciliations.
//! This report is not a certificate and cannot arm an executor. Frozen-device,
//! backup/log and target-preservation evidence must precede that capability.
use crate::{
    ntfs_attestation::Comparison,
    ntfs_inspect::{self as ntfs, AttributeInventory, FileInventory, MetadataRole},
    ntfs_namespace, ntfs_security,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "existing-data-tree-v1";
pub const ORDINARY_PROFILE: &str = "ordinary-data-tree-v2";
pub const MAX_FILES: usize = 128;
pub const MAX_DIRECTORIES: usize = 32;
pub const MAX_LOGICAL_BYTES: u64 = 256 * 1024 * 1024;

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
pub(crate) fn path(raw: &ntfs::NtfsInspection, f: &FileInventory) -> Option<Vec<String>> {
    let objects: BTreeMap<_, _> = raw.files.iter().map(|f| (reference(f), f)).collect();
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
        cursor = objects
            .get(&(name.parent_record_number | (u64::from(name.parent_sequence_number) << 48)))?;
        if !cursor.is_directory {
            return None;
        }
    }
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
    if path(raw, f).is_none() || f.hard_link_count != 1 || f.names.iter().any(|n| n.namespace == 2)
    {
        issues.push("names, depth, short-name aliases or hard links exceed the profile".into());
    }
    if f.base_file_reference != 0
        || f.attributes.iter().any(|a| {
            let plain =
                matches!(a.type_code, 0x10 | 0x30 | 0x50) && a.name_utf16.is_empty() && a.resident;
            let data = !f.is_directory && a.type_code == 0x80 && a.name_utf16.is_empty();
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
    if f.is_directory {
        if !f.streams.is_empty() {
            issues.push("directory data streams exceed the profile".into());
        }
    } else if f.streams.len() != 1
        || f.streams.iter().any(|s| {
            !s.name_utf16.is_empty()
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
            "stream requires a later resident, sparse, fragmented, tail or encoded profile".into(),
        );
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
    assess_source_view_profile(raw, comparison, native_schema, backups, None, true)
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
    assess_source_view_profile(raw, comparison, native_schema, backups, source_view, false)
}
pub(crate) fn assess_ordinary_source_view(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
    source_view: Option<crate::ntfs_source_view::Analysis>,
) -> Assessment {
    assess_source_view_profile(raw, comparison, native_schema, backups, source_view, true)
}
fn assess_source_view_profile(
    raw: &ntfs::NtfsInspection,
    comparison: &Comparison,
    native_schema: u32,
    backups: Option<&crate::ntfs_backup::VerifiedBackups>,
    source_view: Option<crate::ntfs_source_view::Analysis>,
    ordinary: bool,
) -> Assessment {
    let backups = backups.filter(|b| b.binds(raw));
    let view_is_live = source_view
        .as_ref()
        .is_some_and(|v| v.binds_live(&comparison.source_inspection_sha256));
    let mut objects = vec![];
    let mut files = 0;
    let mut directories = 0;
    let mut bytes = 0u64;
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
        raw.geometry.bytes_per_sector == 512
            && raw.geometry.cluster_size == 4096
            && raw.geometry.file_record_size == 1024,
        "initial source geometry is 512-byte sectors, 4 KiB clusters and 1 KiB MFT records",
    );
    gate(
        "clean_volume",
        raw.dirty == Some(false)
            && raw.volume_flags.is_some_and(|flags| flags & 1 == 0)
            && raw.volume_version.as_deref() == Some("3.1"),
        "require NTFS 3.1, clear native dirty state and clear on-disk dirty bit",
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
        native_schema == 5
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
            && files <= MAX_FILES
            && directories <= MAX_DIRECTORIES
            && bytes <= MAX_LOGICAL_BYTES,
        "limit ordinary files/directories/logical bytes; no automatic budget widening",
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
    let unresolved: Vec<_> = raw
        .blockers
        .iter()
        .filter(|b| {
            !matches!(
                b.code.as_str(),
                "security_descriptors_unresolved"
                    | "directory_indexes_unverified"
                    | "allocation_ownership_unverified"
            ) && !(b.code == "backup_boot_unverified" && backups.is_some())
                && !accounted_internal_txf_blocker(raw, b)
                && !accounted_empty_badclus_blocker(raw, b)
        })
        .map(|b| b.code.clone())
        .collect();
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
    Assessment {
        schema_version: 1,
        profile: if ordinary { ORDINARY_PROFILE } else { PROFILE }.into(),
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
