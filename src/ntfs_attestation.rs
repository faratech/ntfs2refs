//! Compare raw NTFS metadata with independently queried native file handles.
//! Diagnostic only: extent, namespace and preservation admission remain separate.
use crate::{
    ntfs_inspect::{FileInventory, NtfsInspection},
    ntfs_security::{self, Acl, Descriptor},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::attestation::{Report, Snapshot};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(windows)]
pub mod paged;

/// Generate an observer request in Rust so 64-bit identifiers stay exact.
/// Collection independently checks the native route and read-only protection.
pub fn request_for_inspection(
    inspection: &crate::planner::Inspection,
    inspection_sha256: &str,
    binding: &n2r_win32::layout::DiskBinding,
) -> Result<n2r_win32::attestation::Request> {
    binding.validate()?;
    let crate::planner::Filesystem::Ntfs(raw) = &inspection.filesystem else {
        anyhow::bail!("native NTFS observer requires an NTFS inspection");
    };
    ensure!(
        inspection.source.length == binding.identity.partition_bytes
            && (raw.geometry.volume_size == inspection.source.length
                || raw
                    .geometry
                    .volume_size
                    .checked_add(u64::from(raw.geometry.bytes_per_sector))
                    == Some(inspection.source.length)),
        "source inspection and native partition length differ"
    );
    let request = n2r_win32::attestation::Request {
        schema_version: 1,
        resource_profile: None,
        source_inspection_sha256: inspection_sha256.into(),
        volume: format!("{}\\", binding.volume_path()?),
        disk_number: binding.disk_number,
        partition_offset: binding.identity.partition_offset,
        partition_length: binding.identity.partition_bytes,
        ntfs_serial: raw.geometry.serial_number,
        files: raw
            .files
            .iter()
            .map(|f| n2r_win32::attestation::FileIdentity {
                record_number: f.record_number,
                sequence_number: f.sequence_number,
            })
            .collect(),
        extent_identity_streams: Vec::new(),
    };
    request.validate()?;
    Ok(request)
}

/// Generate the same native semantic inventory request for a dedicated data
/// disk. Schema 2 widens only route/geometry bounds; the collector still
/// verifies read-only NTFS identity through actual Windows handles.
pub fn request_for_general_inspection(
    raw: &NtfsInspection,
    inspection_sha256: &str,
    binding: &n2r_win32::general_layout::GeneralDiskBinding,
) -> Result<n2r_win32::attestation::Request> {
    binding.validate()?;
    ensure!(
        raw.geometry.volume_size == binding.identity.partition_bytes
            || raw
                .geometry
                .volume_size
                .checked_add(u64::from(raw.geometry.bytes_per_sector))
                == Some(binding.identity.partition_bytes),
        "general raw NTFS geometry differs from bound partition"
    );
    let request = n2r_win32::attestation::Request {
        schema_version: 2,
        resource_profile: None,
        source_inspection_sha256: inspection_sha256.into(),
        volume: format!("{}\\", binding.volume_path()?),
        disk_number: binding.disk_number,
        partition_offset: binding.identity.partition_offset,
        partition_length: binding.identity.partition_bytes,
        ntfs_serial: raw.geometry.serial_number,
        files: raw
            .files
            .iter()
            .map(|file| n2r_win32::attestation::FileIdentity {
                record_number: file.record_number,
                sequence_number: file.sequence_number,
            })
            .collect(),
        extent_identity_streams: Vec::new(),
    };
    request.validate()?;
    Ok(request)
}

/// Opt-in collection request only. Larger native evidence cannot grant source
/// admission or change the conversion profile by itself.
pub fn request_for_general_inspection_with_profile(
    raw: &NtfsInspection,
    inspection_sha256: &str,
    binding: &n2r_win32::general_layout::GeneralDiskBinding,
    profile: n2r_win32::attestation::ResourceProfile,
) -> Result<n2r_win32::attestation::Request> {
    // Construct without the legacy identity-count check, then validate the
    // explicitly selected profile. Geometry and route checks remain identical.
    binding.validate()?;
    ensure!(
        raw.geometry.volume_size == binding.identity.partition_bytes
            || raw
                .geometry
                .volume_size
                .checked_add(u64::from(raw.geometry.bytes_per_sector))
                == Some(binding.identity.partition_bytes),
        "general raw NTFS geometry differs from bound partition"
    );
    ensure!(
        !raw.files.is_empty() && raw.files.len() <= profile.limits().maximum_identities,
        "native resource profile identity budget exceeded"
    );
    let request = n2r_win32::attestation::Request {
        schema_version: 3,
        resource_profile: Some(profile),
        source_inspection_sha256: inspection_sha256.into(),
        volume: format!("{}\\", binding.volume_path()?),
        disk_number: binding.disk_number,
        partition_offset: binding.identity.partition_offset,
        partition_length: binding.identity.partition_bytes,
        ntfs_serial: raw.geometry.serial_number,
        files: raw
            .files
            .iter()
            .map(|f| n2r_win32::attestation::FileIdentity {
                record_number: f.record_number,
                sequence_number: f.sequence_number,
            })
            .collect(),
        extent_identity_streams: Vec::new(),
    };
    request.validate()?;
    Ok(request)
}

/// Shared structural eligibility/spec builder for explicit extent evidence.
/// No content hash is required or invented here. Native retrieval, allocation,
/// stable identity/EOF and the original frozen context remain separate gates.
pub fn extent_identity_stream_request(
    raw: &NtfsInspection,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>> {
    extent_identity_stream_request_with_paths(&raw.geometry, file, stream, || {
        Ok(crate::ntfs_admission::user_paths(raw, file))
    })
}

/// Paged-source counterpart. Complete allocation and namespace reconciliation
/// remain prerequisite observations, not write authority. The caller retains
/// the original source lease and the actual complete page owners separately.
#[cfg(windows)]
pub fn extent_identity_stream_request_domain(
    files: &impl crate::ntfs_inspect::RootFileDomain,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
    allocation_closed: bool,
    namespace_closed: bool,
) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>> {
    if !allocation_closed || !namespace_closed {
        return Ok(None);
    }
    extent_identity_stream_request_with_paths(&files.header().geometry, file, stream, || {
        Ok(Some(crate::ntfs_admission::paged::user_paths(files, file)?))
    })
}

/// Canonical native collection for the explicit offline-Windows layout.
/// This does not cover DOS path preservation or authorize target construction.
#[cfg(windows)]
pub(crate) fn extent_identity_stream_request_windows_domain(
    files: &impl crate::ntfs_inspect::RootFileDomain,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>> {
    extent_identity_stream_request_with_paths(&files.header().geometry, file, stream, || {
        Ok(Some(
            crate::ntfs_admission::paged::canonical_paths_for_alias_preparation(files, file)?,
        ))
    })
}

thread_local! {
    /// The inspections this process made, while their callers hold them
    /// ([`inspected_here`]): an identifier, the domain's address and type.
    static INSPECTED_HERE: std::cell::RefCell<Vec<(u64, usize, &'static str)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static NEXT_INSPECTED: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
}

/// While it lives, `files` is known on this thread as an inspection that
/// this process made itself (not one reopened from the source cache of an
/// earlier process): its stream evidence was decided here, by this build's
/// selector function ([`extent_identity_stream_request_observed`]). The
/// domain is borrowed while it lives, so that its address stands for it.
pub(crate) struct InspectedHere<'a> {
    id: u64,
    _files: std::marker::PhantomData<&'a ()>,
}
pub(crate) fn inspected_here<D>(files: &D) -> InspectedHere<'_> {
    let id = NEXT_INSPECTED.with(|next| {
        let id = next.get();
        next.set(id + 1);
        id
    });
    INSPECTED_HERE.with(|held| {
        held.borrow_mut().push((
            id,
            std::ptr::from_ref(files) as usize,
            std::any::type_name::<D>(),
        ))
    });
    InspectedHere {
        id,
        _files: std::marker::PhantomData,
    }
}
impl Drop for InspectedHere<'_> {
    fn drop(&mut self) {
        INSPECTED_HERE.with(|held| held.borrow_mut().retain(|(id, _, _)| *id != self.id));
    }
}
fn was_inspected_here<D>(files: &D) -> bool {
    let address = std::ptr::from_ref(files) as usize;
    let kind = std::any::type_name::<D>();
    INSPECTED_HERE.with(|held| {
        held.try_borrow()
            .is_ok_and(|held| held.iter().any(|(_, at, of)| *at == address && *of == kind))
    })
}

/// The extent-identity selector of `stream` for the observation of the frozen
/// source through Windows and its comparison with the raw reading:
/// [`extent_identity_stream_request_windows_domain`] where `windows_paths`,
/// otherwise [`extent_identity_stream_request_domain`] with both closures.
///
/// A stream the inspection marked `NotReadExtentIdentityV1` was found
/// eligible by that same function, its paths included, on the same held
/// source, when its stream evidence was decided (the inspection's step
/// "decide stream evidence"): the paths are derived from names and parents
/// that the step left as they were. In a run that verifies once they are
/// not derived again for it here, once for the observation's selector, once
/// for the comparison's and once more for each of the comparison's checks
/// of it; every other condition of the selector is checked again, and every
/// object's own paths are still derived by the admission of the comparison.
/// That holds only of an inspection this process made ([`inspected_here`]);
/// one reopened from the source cache had its statuses decided by an earlier
/// process, perhaps of another build, and derives them as before. So does
/// every other run, and every other stream.
#[cfg(windows)]
pub(crate) fn extent_identity_stream_request_observed<D: crate::ntfs_inspect::RootFileDomain>(
    files: &D,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
    windows_paths: bool,
) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>> {
    let decided = n2r_win32::verify_policy::verifies_once()
        && stream.logical_hash_status
            == crate::ntfs_inspect::LogicalHashStatus::NotReadExtentIdentityV1
        && was_inspected_here(files);
    if !decided {
        return if windows_paths {
            extent_identity_stream_request_windows_domain(files, file, stream)
        } else {
            extent_identity_stream_request_domain(files, file, stream, true, true)
        };
    }
    extent_identity_stream_request_checked(&files.header().geometry, file, stream, || Ok(true))
}

/// The extent-identity selector of `stream` for a caller that has just
/// derived the paths of `file` itself, from the same held source, with the
/// derivation the selector would make (the canonical paths of a Windows
/// volume, the user paths otherwise): `paths_eligible` is
/// [`extent_identity_paths_eligible`] of them. The paths are not derived
/// again; every other condition of the selector is checked as before.
pub(crate) fn extent_identity_stream_request_known_paths(
    geometry: &crate::ntfs_inspect::NtfsGeometry,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
    paths_eligible: bool,
) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>> {
    extent_identity_stream_request_checked(geometry, file, stream, || Ok(paths_eligible))
}

/// Whether an object at `paths` keeps extent evidence: it has a path and
/// none of them is under System Volume Information.
pub(crate) fn extent_identity_paths_eligible(paths: &[Vec<String>]) -> bool {
    // These streams use the bounded system-payload copier, whose complete
    // content baseline is still required. Ordinary data keeps extent evidence.
    !(paths.is_empty()
        || paths.iter().any(|path| {
            path.first()
                .is_some_and(|part| part.eq_ignore_ascii_case("System Volume Information"))
        }))
}

/// The ReFS allocation unit data must be aligned to in order to stay in place.
fn target_cluster() -> u64 {
    n2r_win32::target_cluster::bytes()
}

fn extent_identity_stream_request_with_paths(
    geometry: &crate::ntfs_inspect::NtfsGeometry,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
    source_paths: impl FnOnce() -> Result<Option<Vec<Vec<String>>>>,
) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>> {
    extent_identity_stream_request_checked(geometry, file, stream, || {
        let Some(paths) = source_paths()? else {
            return Ok(false);
        };
        Ok(extent_identity_paths_eligible(&paths))
    })
}

/// The selector of a stream whose paths `paths_eligible` says are those of
/// a stream that keeps extent evidence.
fn extent_identity_stream_request_checked(
    geometry: &crate::ntfs_inspect::NtfsGeometry,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
    paths_eligible: impl FnOnce() -> Result<bool>,
) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>> {
    use crate::ntfs_inspect::MetadataRole;
    let target = target_cluster();
    if !(512..=2 * 1024 * 1024).contains(&geometry.cluster_size)
        || !geometry.cluster_size.is_power_of_two()
        // Extent evidence is for a stream that stays where it is. On source
        // clusters smaller than the target's, a run can start or end inside
        // a target cluster; such a stream is copied, and so is hashed.
        || !stream.allocated_size.is_multiple_of(target)
        || stream.extents.iter().any(|e| {
            !e.logical_offset.is_multiple_of(target)
                || !e.length.is_multiple_of(target)
                || e.physical_offset
                    .is_some_and(|at| !at.is_multiple_of(target))
        })
        || file.is_directory
        || file.record_number < 16
        || file.base_file_reference != 0
        || file.metadata_role != MetadataRole::OutsideExtendCandidate
        || file.metadata_role_issue.is_some()
        || file.is_metadata
        || file.reparse.is_some()
        || file
            .standard_information
            .as_ref()
            .is_none_or(|s| s.file_attributes & 0x4e00 != 0)
        || stream.resident
        || stream.flags != 0
        // Source evidence binds the complete initialized stream/allocation,
        // including a partial final target cluster. Target preservation uses
        // a distinct materialized-tail contract; this is no content digest.
        || stream.logical_size < target
        || stream.initialized_size != stream.logical_size
        || stream.extents.is_empty()
        || stream.extents.iter().any(|e| e.physical_offset.is_none())
    {
        return Ok(None);
    }
    if !paths_eligible()? {
        return Ok(None);
    }
    ensure!(
        file.sequence_number != 0
            && file.record_number < 1 << 48
            && stream.name_utf16.len() <= 255
            && String::from_utf16(&stream.name_utf16).is_ok()
            && !stream
                .name_utf16
                .iter()
                .any(|n| matches!(*n, 0 | 0x2f | 0x5c | 0x3a)),
        "invalid extent-identity stream identity or name"
    );
    let attributes: Vec<_> = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x80 && a.name_utf16 == stream.name_utf16)
        .collect();
    ensure!(
        attributes.len() == 1,
        "extent-identity DATA attribute is ambiguous"
    );
    let a = attributes[0];
    ensure!(
        !a.resident
            && a.flags == 0
            && a.compression_unit == 0
            && a.total_allocated_size.is_none()
            && a.lowest_vcn == 0
            && a.logical_size == stream.logical_size
            && a.initialized_size == stream.initialized_size
            && a.allocated_size == stream.allocated_size
            && a.extents == stream.extents,
        "extent-identity DATA attribute differs from its stream"
    );
    crate::ntfs_inspect::validate_stream_mapping(a, geometry)?;
    ensure!(
        stream
            .allocated_size
            .is_multiple_of(u64::from(geometry.cluster_size))
            && stream.extents.iter().all(|e| e
                .length
                .is_multiple_of(u64::from(geometry.cluster_size))
                && e.physical_offset
                    .is_some_and(|at| at.is_multiple_of(u64::from(geometry.cluster_size)))),
        "extent-identity source allocation is not cluster aligned"
    );
    let mut extents: Vec<n2r_win32::attestation::ExtentIdentityExtent> = Vec::new();
    for e in &stream.extents {
        let physical = e.physical_offset.context("extent-identity source hole")?;
        if let Some(last) = extents.last_mut()
            && last.logical_offset.checked_add(last.length) == Some(e.logical_offset)
            && last.physical_offset.checked_add(last.length) == Some(physical)
        {
            last.length = last
                .length
                .checked_add(e.length)
                .context("extent-identity run overflow")?;
        } else {
            extents.push(n2r_win32::attestation::ExtentIdentityExtent {
                logical_offset: e.logical_offset,
                physical_offset: physical,
                length: e.length,
            });
        }
    }
    Ok(Some(n2r_win32::attestation::ExtentIdentityStream {
        identity: n2r_win32::attestation::FileIdentity {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
        },
        name_utf16: stream.name_utf16.clone(),
        cluster_bytes: geometry.cluster_size,
        logical_size: stream.logical_size,
        allocated_size: stream.allocated_size,
        extents,
    }))
}

/// A complete digest or an explicitly un-read, structurally eligible stream.
/// This is planner evidence only, never live source/write authority.
pub fn source_stream_evidence_valid(
    raw: &NtfsInspection,
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
) -> Result<bool> {
    use crate::ntfs_inspect::LogicalHashStatus;
    Ok(match stream.logical_hash_status {
        LogicalHashStatus::Complete => stream
            .logical_sha256
            .as_deref()
            .is_some_and(n2r_win32::content_digest::is_hex),
        LogicalHashStatus::NotReadExtentIdentityV1 => {
            stream.logical_sha256.is_none()
                && extent_identity_stream_request(raw, file, stream)?.is_some()
        }
        _ => false,
    })
}

pub fn request_for_general_inspection_with_policy(
    raw: &NtfsInspection,
    inspection_sha256: &str,
    binding: &n2r_win32::general_layout::GeneralDiskBinding,
    profile: n2r_win32::attestation::ResourceProfile,
    policy: crate::verification_policy::VerificationPolicy,
) -> Result<n2r_win32::attestation::Request> {
    let mut request =
        request_for_general_inspection_with_profile(raw, inspection_sha256, binding, profile)?;
    if policy.is_fast() {
        ensure!(
            profile.is_streaming(),
            "extent-identity native reads require the streaming source profile"
        );
        for file in &raw.files {
            for stream in &file.streams {
                if let Some(candidate) = extent_identity_stream_request(raw, file, stream)? {
                    request.extent_identity_streams.push(candidate);
                }
            }
        }
        request.schema_version = 4;
        request.validate()?;
    }
    Ok(request)
}

/// Fresh source admission additionally requires explicit per-directory native
/// case evidence. Historical request builders intentionally keep schemas2–4.
pub fn request_for_fresh_general_inspection(
    raw: &NtfsInspection,
    inspection_sha256: &str,
    binding: &n2r_win32::general_layout::GeneralDiskBinding,
    profile: Option<n2r_win32::attestation::ResourceProfile>,
    policy: crate::verification_policy::VerificationPolicy,
) -> Result<n2r_win32::attestation::Request> {
    let mut request = match profile {
        Some(profile) => request_for_general_inspection_with_policy(
            raw,
            inspection_sha256,
            binding,
            profile,
            policy,
        )?,
        None => {
            ensure!(
                policy.is_full_content(),
                "unprofiled fresh source cannot elide stream reads"
            );
            request_for_general_inspection(raw, inspection_sha256, binding)?
        }
    };
    request.schema_version = if request.uses_extent_identity() { 6 } else { 5 };
    request.validate()?;
    Ok(request)
}

#[derive(Debug, Serialize)]
pub struct FileComparison {
    pub record_number: u64,
    pub sequence_number: u16,
    pub matched: bool,
    pub issues: Vec<String>,
    pub raw_kernel_security_matched: Option<bool>,
    pub kernel_api_security_matched: Option<bool>,
}
#[derive(Debug, Serialize)]
pub struct Comparison {
    pub schema_version: u32,
    pub source_inspection_sha256: String,
    pub requested_files: usize,
    pub opened_files: usize,
    pub matched_files: usize,
    pub files: Vec<FileComparison>,
    pub all_requested_metadata_matched: bool,
    pub conversion_qualified: bool,
    pub native_streams: Option<crate::ntfs_stream_attestation::Reconciliation>,
    pub native_logical_data: Option<crate::ntfs_data_attestation::Reconciliation>,
    pub native_namespace: Option<crate::ntfs_namespace_attestation::Reconciliation>,
    /// None is historical Unknown, never an observation that flags were zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_case_sensitivity: Option<DirectoryCaseAssessment>,
}

#[derive(Debug, Serialize)]
pub struct DirectoryCaseAssessment {
    pub raw_directories: usize,
    pub matched_directories: usize,
    pub all_directories_case_insensitive: bool,
    pub directories: Vec<DirectoryCaseCheck>,
}
#[derive(Debug, Serialize)]
pub struct DirectoryCaseCheck {
    pub record_number: u64,
    pub sequence_number: u16,
    pub observation_path: &'static str,
    pub before_flags: Option<u32>,
    pub after_flags: Option<u32>,
    pub matched: bool,
    pub issues: Vec<String>,
}

fn directory_case_flags(
    raw: &NtfsInspection,
    file: &FileInventory,
    queries: &[n2r_win32::attestation::Query],
    case: Option<&n2r_win32::attestation::Query>,
) -> Result<u32> {
    directory_case_flags_with_serial(raw.geometry.serial_number, file, queries, case)
}

fn directory_case_flags_with_serial(
    serial: u64,
    file: &FileInventory,
    queries: &[n2r_win32::attestation::Query],
    case: Option<&n2r_win32::attestation::Query>,
) -> Result<u32> {
    let bytes = |class, length| -> Result<&[u8]> {
        let mut found = queries.iter().filter(|q| q.class == class);
        let query = found
            .next()
            .context("directory identity/type query missing")?;
        ensure!(
            found.next().is_none() && query.native_error.is_none() && query.bytes.len() == length,
            "directory identity/type query failed or malformed (class{class})"
        );
        Ok(&query.bytes)
    };
    let basic = bytes(0, 40)?;
    let standard = bytes(1, 24)?;
    let id = bytes(18, 24)?;
    ensure!(
        u32::from_le_bytes(basic[32..36].try_into()?) & 0x10 != 0
            && standard[21] == 1
            && standard[20] == 0,
        "directory case handle type/delete state differs"
    );
    ensure!(
        u64::from_le_bytes(id[..8].try_into()?) == serial
            && u64::from_le_bytes(id[8..16].try_into()?)
                == (file.record_number | (u64::from(file.sequence_number) << 48))
            && id[16..].iter().all(|byte| *byte == 0),
        "directory case handle serial/file reference differs from frozen raw identity"
    );
    let case = case.context("directory case sensitivity is Unknown (query missing)")?;
    ensure!(
        case.class == 23 && case.native_error.is_none() && case.bytes.len() == 4,
        "directory case query failed or malformed: class={}, error={:?}, bytes={}",
        case.class,
        case.native_error,
        case.bytes.len()
    );
    Ok(u32::from_le_bytes(case.bytes[..].try_into()?))
}

/// What Windows says of a directory's case sensitivity, asked twice:
/// whether the directory is marked case-sensitive. The converter sets the
/// mark on the target where `n2r_win32::directory_case::CaseMarkCarry` says
/// the running Windows was shown to hold such a directory, and says which
/// it did. (ReFS 3.14 takes the mark in the lab's controls, on Windows
/// Server 2025 and on Windows 11 build 26300; on the latter Windows then
/// stopped with a bugcheck when the volume was taken offline.) Two names
/// that differ only by case are a separate matter: such a pair is refused
/// where the directory's names are reconciled, whether the mark is carried
/// over or not.
/// Flags other than 0 and 1, and an answer that differs between the two
/// queries, are refused here.
#[cfg(windows)]
pub(crate) fn check_directory_case_observation(
    file: &FileInventory,
    serial: u64,
    observed: &n2r_win32::attestation::Observation,
) -> Result<bool> {
    ensure!(
        file.is_directory
            && observed.identity.record_number == file.record_number
            && observed.identity.sequence_number == file.sequence_number,
        "directory case observation identity differs"
    );
    let (before, before_case, after, after_case) = if observed.open_error.is_none() {
        ensure!(
            observed.case_only_fallback.is_none(),
            "successful directory open also carries fallback"
        );
        let a = observed
            .before
            .as_ref()
            .context("directory before snapshot absent")?;
        let b = observed
            .after
            .as_ref()
            .context("directory after snapshot absent")?;
        (
            &a.queries,
            a.directory_case_sensitivity.as_ref(),
            &b.queries,
            b.directory_case_sensitivity.as_ref(),
        )
    } else {
        ensure!(
            observed.before.is_none() && observed.after.is_none(),
            "failed broad directory open also carries metadata"
        );
        let fallback = observed
            .case_only_fallback
            .as_ref()
            .context("directory case fallback absent")?;
        ensure!(
            fallback.access_mask == 0x80 && fallback.open_error.is_none(),
            "directory case fallback refused"
        );
        let a = fallback
            .before
            .as_ref()
            .context("directory fallback before absent")?;
        let b = fallback
            .after
            .as_ref()
            .context("directory fallback after absent")?;
        (
            &a.queries,
            a.directory_case_sensitivity.as_ref(),
            &b.queries,
            b.directory_case_sensitivity.as_ref(),
        )
    };
    case_sensitive_mark(
        directory_case_flags_with_serial(serial, file, before, before_case)?,
        directory_case_flags_with_serial(serial, file, after, after_case)?,
    )
}

/// Whether a directory is marked case-sensitive, from the flags Windows
/// gave for it in two queries. FILE_CASE_SENSITIVE_INFO has one flag, 1.
pub(crate) fn case_sensitive_mark(first: u32, second: u32) -> Result<bool> {
    ensure!(
        first == second && first <= 1,
        "Windows reports case-sensitivity flags {first:#x} and then {second:#x} for the directory, where 0 (an ordinary directory) or 1 (one marked case-sensitive), twice the same, is what the converter knows"
    );
    Ok(first == 1)
}

#[cfg(test)]
mod case_mark_tests {
    use super::case_sensitive_mark;

    #[test]
    fn a_directory_is_ordinary_or_marked_and_anything_else_is_refused() {
        assert!(!case_sensitive_mark(0, 0).unwrap());
        assert!(case_sensitive_mark(1, 1).unwrap());
        // An answer that changed between the two queries.
        assert!(case_sensitive_mark(0, 1).is_err());
        assert!(case_sensitive_mark(1, 0).is_err());
        // Flags the converter does not know, even twice the same.
        let unknown = case_sensitive_mark(3, 3).unwrap_err().to_string();
        assert!(
            unknown.contains("0x3") && unknown.contains("what the converter knows"),
            "{unknown}"
        );
        assert!(case_sensitive_mark(2, 2).is_err());
    }
}

fn compare_directory_cases(raw: &NtfsInspection, native: &Report) -> DirectoryCaseAssessment {
    let mut directories = Vec::new();
    for file in raw.files.iter().filter(|file| file.is_directory) {
        let mut row = DirectoryCaseCheck {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            observation_path: "missing",
            before_flags: None,
            after_flags: None,
            matched: false,
            issues: Vec::new(),
        };
        let checked = (|| -> Result<()> {
            let mut matching = native.files.iter().filter(|item| {
                item.identity.record_number == file.record_number
                    && item.identity.sequence_number == file.sequence_number
            });
            let observed = matching
                .next()
                .context("source directory observation missing")?;
            ensure!(
                matching.next().is_none(),
                "source directory observation duplicated"
            );
            let (before_queries, before_case, after_queries, after_case) =
                if observed.open_error.is_none() {
                    row.observation_path = "canonical-snapshot";
                    ensure!(
                        observed.case_only_fallback.is_none(),
                        "successful metadata open also carries fallback"
                    );
                    let before = observed
                        .before
                        .as_ref()
                        .context("before directory snapshot missing")?;
                    let after = observed
                        .after
                        .as_ref()
                        .context("after directory snapshot missing")?;
                    (
                        before.queries.as_slice(),
                        before.directory_case_sensitivity.as_ref(),
                        after.queries.as_slice(),
                        after.directory_case_sensitivity.as_ref(),
                    )
                } else {
                    row.observation_path = "read-attributes-only-fallback";
                    ensure!(
                        observed.before.is_none() && observed.after.is_none(),
                        "failed broad open carries metadata snapshots"
                    );
                    let fallback = observed
                        .case_only_fallback
                        .as_ref()
                        .context("directory case fallback missing after broad-open failure")?;
                    ensure!(
                        fallback.access_mask == 0x80 && fallback.open_error.is_none(),
                        "directory read-attributes fallback failed: {:?}",
                        fallback.open_error
                    );
                    let before = fallback
                        .before
                        .as_ref()
                        .context("fallback before snapshot missing")?;
                    let after = fallback
                        .after
                        .as_ref()
                        .context("fallback after snapshot missing")?;
                    (
                        before.queries.as_slice(),
                        before.directory_case_sensitivity.as_ref(),
                        after.queries.as_slice(),
                        after.directory_case_sensitivity.as_ref(),
                    )
                };
            // Retain both actual query failures. A failed before query must
            // not hide the after observation or create synthetic zero flags.
            for (phase, queries, case) in [
                ("before", before_queries, before_case),
                ("after", after_queries, after_case),
            ] {
                match directory_case_flags(raw, file, queries, case) {
                    Ok(flags) if phase == "before" => row.before_flags = Some(flags),
                    Ok(flags) => row.after_flags = Some(flags),
                    Err(error) => row.issues.push(format!("{phase}: {error:#}")),
                }
            }
            if !row.issues.is_empty() {
                return Ok(());
            }
            ensure!(
                row.before_flags == Some(0) && row.after_flags == Some(0),
                "directory has unsupported nonzero/unstable case flags: before={:?}, after={:?}",
                row.before_flags,
                row.after_flags
            );
            Ok(())
        })();
        match checked {
            Ok(()) => row.matched = row.issues.is_empty(),
            Err(error) => row.issues.push(format!("{error:#}")),
        }
        directories.push(row);
    }
    let matched = directories.iter().filter(|row| row.matched).count();
    DirectoryCaseAssessment {
        raw_directories: directories.len(),
        matched_directories: matched,
        all_directories_case_insensitive: !directories.is_empty() && matched == directories.len(),
        directories,
    }
}
fn acl_bytes(d: &Descriptor, a: &Acl) -> Result<Vec<Vec<u8>>> {
    let b = hex::decode(&d.relative_hex)?;
    a.aces
        .iter()
        .map(|ace| {
            Ok(b.get(
                ace.offset
                    ..ace
                        .offset
                        .checked_add(ace.length)
                        .context("ACE range overflow")?,
            )
            .context("ACE outside descriptor")?
            .to_vec())
        })
        .collect()
}
fn acl_equal(a: &Descriptor, ac: &Acl, b: &Descriptor, bc: &Acl) -> Result<bool> {
    Ok(
        ac.state == bc.state
            && ac.revision == bc.revision
            && acl_bytes(a, ac)? == acl_bytes(b, bc)?,
    )
}
/// Ignore placement offsets and padding. Preserve control, SID values, ACL
/// presence/null state, revision, ACE order and every complete ACE byte.
pub fn same_security(a: &[u8], b: &[u8]) -> Result<bool> {
    same_security_with_limit(a, b, ntfs_security::MAX_DESCRIPTOR_BYTES as u64)
}

/// As `same_security`, except that a SACL marked present but null equals no
/// SACL at all: neither audits anything.
///
/// ReFS cannot clear the SACL-present flag once it is set, and its formatter
/// sets it (with a null SACL) on System Volume Information. Such an object can
/// therefore never be made bit-identical to an NTFS source with no SACL. Every
/// other field, including a real SACL, must still match exactly.
pub fn same_security_null_sacl_as_absent(a: &[u8], b: &[u8]) -> Result<bool> {
    const SE_SACL_PRESENT: u16 = 0x0010;
    let maximum = ntfs_security::MAX_DESCRIPTOR_BYTES as u64;
    remembered_comparison(1, a, b, maximum, || {
        let a = ntfs_security::parse_descriptor_with_limit(a, maximum)?;
        let b = ntfs_security::parse_descriptor_with_limit(b, maximum)?;
        let empty = |acl: &Acl| {
            matches!(
                acl.state,
                ntfs_security::AclState::Absent | ntfs_security::AclState::Null
            )
        };
        let (control_mask, sacl_same) = if empty(&a.sacl) && empty(&b.sacl) {
            (!SE_SACL_PRESENT, true)
        } else {
            (u16::MAX, acl_equal(&a, &a.sacl, &b, &b.sacl)?)
        };
        Ok(a.control & control_mask == b.control & control_mask
            && a.rm_control == b.rm_control
            && a.owner_sid == b.owner_sid
            && a.group_sid == b.group_sid
            && acl_equal(&a, &a.dacl, &b, &b.dacl)?
            && sacl_same)
    })
}
/// The resource profile changes the storage bound, never descriptor meaning.
/// SID/control/ACL states, ACE ordering and all complete ACE bytes still match.
pub fn same_security_with_limit(a: &[u8], b: &[u8], maximum: u64) -> Result<bool> {
    remembered_comparison(0, a, b, maximum, || {
        let a = ntfs_security::parse_descriptor_with_limit(a, maximum)?;
        let b = ntfs_security::parse_descriptor_with_limit(b, maximum)?;
        Ok(a.control == b.control
            && a.rm_control == b.rm_control
            && a.owner_sid == b.owner_sid
            && a.group_sid == b.group_sid
            && acl_equal(&a, &a.dacl, &b, &b.dacl)?
            && acl_equal(&a, &a.sacl, &b, &b.sacl)?)
    })
}

/// That `bytes` parse as a relative security descriptor of at most `maximum`
/// bytes ([`ntfs_security::parse_descriptor_with_limit`]), where the parsed
/// form is not needed. The answer is remembered by the descriptor's exact
/// bytes, as the comparisons are: most objects of a volume share a handful
/// of descriptors, and each was parsed again for each object and view. A
/// descriptor that does not parse is parsed again and refused the same way.
pub fn check_descriptor_with_limit(bytes: &[u8], maximum: u64) -> Result<()> {
    remembered_comparison(2, bytes, &[], maximum, || {
        ntfs_security::parse_descriptor_with_limit(bytes, maximum).map(|_| true)
    })
    .map(|_| ())
}

#[cfg(test)]
mod inspected_here_tests {
    use super::{inspected_here, was_inspected_here};

    #[test]
    fn only_an_inspection_held_as_made_here_is_known_as_one() {
        struct Store(#[allow(dead_code)] u64);
        // A domain whose first field is another domain at its address.
        struct Domain {
            store: Store,
        }
        let (made_here, reopened) = (Domain { store: Store(1) }, Domain { store: Store(2) });
        assert!(!was_inspected_here(&made_here));
        {
            let _held = inspected_here(&made_here);
            assert!(was_inspected_here(&made_here));
            assert!(!was_inspected_here(&reopened), "another domain");
            // The same address taken as another type is not it.
            assert_eq!(
                std::ptr::from_ref(&made_here.store) as usize,
                std::ptr::from_ref(&made_here) as usize
            );
            assert!(!was_inspected_here(&made_here.store));
            {
                let _also = inspected_here(&reopened);
                assert!(was_inspected_here(&reopened));
            }
            assert!(!was_inspected_here(&reopened), "no longer held");
            assert!(was_inspected_here(&made_here));
        }
        assert!(!was_inspected_here(&made_here), "no longer held");
    }
}

#[cfg(test)]
mod remembered_descriptor_tests {
    use super::{check_descriptor_with_limit, ntfs_security};

    #[test]
    fn a_remembered_descriptor_check_answers_as_the_parser_does() {
        // Revision 1, self-relative with a null DACL present: 20 bytes.
        let mut valid = vec![0u8; 20];
        valid[0] = 1;
        valid[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        let mut absolute = valid.clone();
        absolute[2..4].copy_from_slice(&0x0004u16.to_le_bytes());
        let short = vec![1u8; 12];
        for _ in 0..3 {
            for (bytes, maximum) in [
                (&valid, 4096),
                (&absolute, 4096),
                (&short, 4096),
                (&valid, 16),
            ] {
                let parsed = ntfs_security::parse_descriptor_with_limit(bytes, maximum);
                let checked = check_descriptor_with_limit(bytes, maximum);
                assert_eq!(parsed.is_ok(), checked.is_ok(), "{bytes:?} at {maximum}");
                if let (Err(parsed), Err(checked)) = (parsed, checked) {
                    assert_eq!(parsed.to_string(), checked.to_string());
                }
            }
        }
        assert!(check_descriptor_with_limit(&valid, 4096).is_ok());
        // The bound is part of what is remembered: the same bytes over it
        // are refused after they were admitted under a larger one.
        assert!(check_descriptor_with_limit(&valid, 16).is_err());
    }
}

/// The answer of a descriptor comparison for the same two byte strings.
///
/// A volume has hundreds of thousands of objects and a few hundred distinct
/// security descriptors, and each comparison parsed both descriptors again.
/// The comparison depends only on its inputs, so its answer is kept, keyed
/// by the exact bytes of both descriptors (a hash only finds the bucket).
/// Errors are not kept. At most `REMEMBERED_BYTES` of descriptors are held.
fn remembered_comparison(
    kind: u8,
    a: &[u8],
    b: &[u8],
    maximum: u64,
    compare: impl FnOnce() -> Result<bool>,
) -> Result<bool> {
    struct Known {
        kind: u8,
        maximum: u64,
        a: Vec<u8>,
        b: Vec<u8>,
        same: bool,
    }
    #[derive(Default)]
    struct Memory {
        buckets: std::collections::HashMap<u128, Vec<Known>>,
        bytes: usize,
    }
    const REMEMBERED_BYTES: usize = 32 * 1024 * 1024;
    thread_local! {
        static MEMORY: std::cell::RefCell<Memory> = std::cell::RefCell::new(Memory::default());
    }
    let mut hash = xxhash_rust::xxh3::Xxh3::new();
    hash.update(&[kind]);
    hash.update(&maximum.to_le_bytes());
    hash.update(&(a.len() as u64).to_le_bytes());
    hash.update(a);
    hash.update(b);
    let bucket = hash.digest128();
    let known = MEMORY.with(|memory| {
        memory.borrow().buckets.get(&bucket).and_then(|entries| {
            entries
                .iter()
                .find(|known| {
                    known.kind == kind && known.maximum == maximum && known.a == a && known.b == b
                })
                .map(|known| known.same)
        })
    });
    if let Some(same) = known {
        return Ok(same);
    }
    let same = compare()?;
    MEMORY.with(|memory| {
        let mut memory = memory.borrow_mut();
        let size = a.len() + b.len() + std::mem::size_of::<Known>();
        if memory.bytes + size <= REMEMBERED_BYTES {
            memory.bytes += size;
            memory.buckets.entry(bucket).or_default().push(Known {
                kind,
                maximum,
                a: a.to_vec(),
                b: b.to_vec(),
                same,
            });
        }
    });
    Ok(same)
}
fn buffer(s: &Snapshot, class: i32, length: usize) -> Result<&[u8]> {
    let q: Vec<_> = s.queries.iter().filter(|q| q.class == class).collect();
    ensure!(q.len() == 1, "native class {class} missing/duplicated");
    ensure!(
        q[0].native_error.is_none(),
        "native class {class}: error {:?}",
        q[0].native_error
    );
    ensure!(
        q[0].bytes.len() == length,
        "native class {class} length differs"
    );
    Ok(&q[0].bytes)
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn check_snapshot(file: &FileInventory, serial: u64, sd: &[u8], s: &Snapshot) -> Result<()> {
    let times = check_non_time_snapshot(file, serial, sd, s)?;
    let si = file
        .standard_information
        .as_ref()
        .context("missing raw standard information")?;
    ensure!(
        times
            == [
                si.creation_time,
                si.access_time,
                si.modification_time,
                si.mft_change_time
            ],
        "native timestamps differ"
    );
    Ok(())
}
/// Validate every other metadata field independently of timestamp comparison.
/// Returns the unchanged observed FILETIMEs. The strict comparator above still
/// requires all four to match; a separate frozen-source policy may explain only
/// cached access time and must record both observed and persisted values.
pub(crate) fn check_non_time_snapshot(
    file: &FileInventory,
    serial: u64,
    sd: &[u8],
    s: &Snapshot,
) -> Result<[u64; 4]> {
    let times = check_non_security_snapshot(file, serial, s)?;
    ensure!(
        s.security_error.is_none(),
        "native security query failed: {:?}",
        s.security_error
    );
    ensure!(
        same_security(sd, &s.security)?,
        "native security semantics differ"
    );
    Ok(times)
}

/// The frozen-source policy checks both descriptor views separately. Keep
/// identity/type/size/attribute validation independent of API SD projection.
/// Project FILE_ATTRIBUTE_SPARSE_FILE onto the opened default stream.
/// NTFS STANDARD_INFORMATION can retain this bit when a named stream is
/// sparse while the default stream is not. The internal NTFS EA marker is
/// omitted by Win32 for files and directories, but only validated nonempty EA
/// storage can identify that marker: the same numeric bit also names
/// RECALL_ON_OPEN. All other bits and the raw SI inventory remain unchanged.
pub(crate) fn has_verified_nonempty_eas(file: &FileInventory) -> bool {
    crate::ntfs_extended_attributes::file_set(file).is_ok_and(|set| !set.is_empty())
}

pub(crate) fn default_stream_attributes(file: &FileInventory, attributes: u32) -> Result<u32> {
    let attributes = if attributes & 0x40000 != 0 && has_verified_nonempty_eas(file) {
        attributes & !0x40000
    } else {
        attributes
    };
    if file.is_directory {
        return Ok(attributes);
    }
    let mut streams = file
        .streams
        .iter()
        .filter(|stream| stream.name_utf16.is_empty());
    let Some(default) = streams.next() else {
        return Ok(attributes);
    };
    ensure!(
        streams.next().is_none(),
        "default stream attribute projection is ambiguous"
    );
    Ok((attributes & !0x200)
        | if default.flags & 0x8000 != 0 {
            0x200
        } else {
            0
        })
}

pub(crate) fn check_non_security_snapshot(
    file: &FileInventory,
    serial: u64,
    s: &Snapshot,
) -> Result<[u64; 4]> {
    check_non_security_snapshot_scoped(file, serial, s, false)
}

/// The frozen Windows path retains the raw FILE link counter as a hint.
/// Complete MFT/I30 coverage remains a prerequisite, and native canonical
/// link counts are still checked against the complete FILE_NAME inventory.
pub(crate) fn check_non_security_snapshot_windows(
    file: &FileInventory,
    serial: u64,
    s: &Snapshot,
) -> Result<[u64; 4]> {
    check_non_security_snapshot_scoped(file, serial, s, true)
}

fn check_non_security_snapshot_scoped(
    file: &FileInventory,
    serial: u64,
    s: &Snapshot,
    windows_counter_hint: bool,
) -> Result<[u64; 4]> {
    check_reparse_snapshot(file, s)?;
    if file.extended_attributes.is_some()
        || s.extended_attributes.is_some()
        || s.extended_attributes_error.is_some()
    {
        let expected = crate::ntfs_extended_attributes::file_set(file)?;
        ensure!(
            s.extended_attributes_error.is_none(),
            "native EA query failed"
        );
        let observed = s
            .extended_attributes
            .as_ref()
            .context("native EA set missing")?;
        observed.validate()?;
        ensure!(
            expected.equivalent(observed),
            "raw/native EA semantics differ"
        );
    }
    ensure!(s.queries.len() == 4, "unexpected native query count");
    let id = buffer(s, 18, 24)?;
    ensure!(
        u64le(id, 0) == serial
            && u64le(id, 8) == (file.record_number | u64::from(file.sequence_number) << 48)
            && u64le(id, 16) == 0,
        "native file or volume identity differs"
    );
    let basic = buffer(s, 0, 40)?;
    let si = file
        .standard_information
        .as_ref()
        .context("missing raw standard information")?;
    // NTFS $STANDARD_INFORMATION omits the directory bit and carries internal
    // index/view flags in the high nibble, outside Win32 FILE_ATTRIBUTE_*.
    let projected = if file.record_number == 5
        || matches!(
            file.metadata_role,
            crate::ntfs_inspect::MetadataRole::OutsideExtendCandidate
        ) {
        crate::ntfs_file_attributes::project_user(file)?.win32_attributes
    } else {
        // Keep the existing observation behavior for recognized internal
        // indexes such as $Secure. Their replacement admission is separate.
        (si.file_attributes & 0x0fff_ffff) | if file.is_directory { 16 } else { 0 }
    };
    let mut attrs = default_stream_attributes(file, projected)?;
    if attrs == 0 {
        attrs = 128;
    }
    let tag = buffer(s, 9, 8)?;
    ensure!(
        u32le(basic, 32) == attrs && u32le(tag, 0) == attrs,
        "native attributes differ: expected {attrs:#x}, basic {:#x}, tag {:#x}",
        u32le(basic, 32),
        u32le(tag, 0)
    );
    let standard = buffer(s, 1, 24)?;
    ensure!(
        standard[20] == 0 && standard[21] == u8::from(file.is_directory),
        "native delete/directory state differs"
    );
    // The Windows profile preserves the raw FILE counter as a hint. Native
    // FILE_STANDARD_INFO must match canonical links in every profile; DOS
    // aliases retain their separate preservation obligation.
    let native_links = file.names.iter().filter(|name| name.namespace != 2).count();
    ensure!(
        (windows_counter_hint || usize::from(file.hard_link_count) == file.names.len())
            && usize::try_from(u32le(standard, 16))? == native_links,
        "native link count differs at FILE {}: native={}, canonical={}, raw={}, names={}",
        file.record_number,
        u32le(standard, 16),
        native_links,
        file.hard_link_count,
        file.names.len()
    );
    if let Some(stream) = file.streams.iter().find(|s| s.name_utf16.is_empty()) {
        ensure!(
            u64le(standard, 8) == stream.logical_size,
            "native unnamed stream EOF differs"
        );
    }
    Ok([
        u64le(basic, 0),
        u64le(basic, 8),
        u64le(basic, 16),
        u64le(basic, 24),
    ])
}

/// Source-link evidence belongs to the opened link itself. Matching only its
/// tag is insufficient: the full supported buffer must match the raw NTFS
/// attribute, including path strings, offsets and relative-link flags.
pub(crate) fn check_reparse_snapshot(file: &FileInventory, s: &Snapshot) -> Result<()> {
    let expected = crate::ntfs_reparse::file_point(file)?;
    let tag = buffer(s, 9, 8)?;
    let native_tag = u32le(tag, 4);
    let expected_tag = match &expected {
        Some(point) => u32::from_le_bytes(
            point
                .buffer
                .get(..4)
                .context("validated raw reparse tag missing")?
                .try_into()?,
        ),
        None => 0,
    };
    ensure!(
        native_tag == expected_tag && (u32le(tag, 0) & 0x400 != 0) == expected.is_some(),
        "native reparse tag/attribute differs from raw source"
    );
    s.validate_reparse(false)?;
    match &s.reparse {
        Some(observed) => {
            ensure!(observed.error.is_none(), "native reparse query failed");
            ensure!(
                observed.point == expected,
                "raw/native reparse buffers differ"
            );
        }
        None => ensure!(
            expected.is_none(),
            "legacy native report lacks full reparse evidence"
        ),
    }
    Ok(())
}

pub(crate) fn check_header_geometry(
    geometry: &crate::ntfs_inspect::NtfsGeometry,
    native: &Report,
) -> Result<()> {
    ensure!(
        native.request.ntfs_serial == geometry.serial_number,
        "source serial differs"
    );
    ensure!(
        native.privileges_restored
            && native.write_protect_error_before == 19
            && native.write_protect_error_after == 19,
        "native protection or privilege restoration incomplete"
    );
    ensure!(
        native.privilege_states.len() == 2,
        "native privilege audit incomplete"
    );
    for (p, name) in native
        .privilege_states
        .iter()
        .zip(["SeBackupPrivilege", "SeSecurityPrivilege"])
    {
        ensure!(
            p.name == name
                && p.enabled == p.before | 2
                && (p.restored & !0x8000_0000) == (p.before & !0x8000_0000),
            "native privilege audit differs"
        );
    }
    ensure!(
        native.volume_extents_before == native.volume_extents_after
            && native.disk_attributes_before == native.disk_attributes_after
            && native.ntfs_data_before == native.ntfs_data_after,
        "native volume state changed"
    );
    let ext = &native.volume_extents_before;
    ensure!(
        ext.len() == 32
            && u32le(ext, 0) == 1
            && u32le(ext, 8) == native.request.disk_number
            && u64le(ext, 16) == native.request.partition_offset
            && u64le(ext, 24) == native.request.partition_length,
        "native disk route differs"
    );
    let attrs = &native.disk_attributes_before;
    ensure!(
        attrs.len() == 16 && u32le(attrs, 0) == 16 && u64le(attrs, 8) & 3 == 2,
        "native read-only attributes differ"
    );
    let data = &native.ntfs_data_before;
    ensure!(
        (96..=128).contains(&data.len())
            && u64le(data, 0) == geometry.serial_number
            && u32le(data, 40) == u32::from(geometry.bytes_per_sector)
            && u32le(data, 44) == geometry.cluster_size
            && u32le(data, 48) == geometry.file_record_size
            && u64le(data, 8) == geometry.total_sectors
            && u64le(data, 16) == geometry.total_clusters
            && u64le(data, 64) == geometry.mft_lcn
            && u64le(data, 72) == geometry.mftmirr_lcn,
        "native NTFS geometry differs"
    );
    ensure!(
        native.request.partition_length == geometry.volume_size
            || native.request.partition_length
                == geometry
                    .volume_size
                    .checked_add(u64::from(geometry.bytes_per_sector))
                    .context("source length overflow")?,
        "native/source partition length differs"
    );
    Ok(())
}

#[cfg(windows)]
pub(crate) fn check_partition_header_geometry(
    geometry: &crate::ntfs_inspect::NtfsGeometry,
    observed: &n2r_win32::attestation_partition::PartitionPagedNtfsObservation,
) -> Result<()> {
    use n2r_win32::attestation::NativeObservationDomain;
    let native = observed.domain().header();
    ensure!(
        observed.before() == observed.after()
            && observed.before().partition_write_protect_error == 19
            && observed.before().physical_disk_is_writable_succeeded
            && observed.before().volume_extents == native.volume_extents_before
            && observed.before().ntfs_volume_data == native.ntfs_data_before
            && observed.before().actual_physical_disk_attributes == native.disk_attributes_before,
        "actual partition protection does not bind native header"
    );
    ensure!(
        native.request.ntfs_serial == geometry.serial_number,
        "source serial differs"
    );
    ensure!(
        native.privileges_restored
            && native.write_protect_error_before == 0
            && native.write_protect_error_after == 0,
        "native protection or privilege restoration incomplete"
    );
    ensure!(
        native.privilege_states.len() == 2,
        "native privilege audit incomplete"
    );
    for (p, name) in native
        .privilege_states
        .iter()
        .zip(["SeBackupPrivilege", "SeSecurityPrivilege"])
    {
        ensure!(
            p.name == name
                && p.enabled == p.before | 2
                && (p.restored & !0x8000_0000) == (p.before & !0x8000_0000),
            "native privilege audit differs"
        );
    }
    ensure!(
        native.volume_extents_before == native.volume_extents_after
            && native.disk_attributes_before == native.disk_attributes_after
            && native.ntfs_data_before == native.ntfs_data_after,
        "native volume state changed"
    );
    let ext = &native.volume_extents_before;
    ensure!(
        ext.len() == 32
            && u32le(ext, 0) == 1
            && u32le(ext, 8) == native.request.disk_number
            && u64le(ext, 16) == native.request.partition_offset
            && u64le(ext, 24) == native.request.partition_length,
        "native disk route differs"
    );
    let attrs = &native.disk_attributes_before;
    ensure!(
        attrs.len() == 16 && u32le(attrs, 0) == 16 && u64le(attrs, 8) == 0,
        "actual physical disk state differs from partition protection profile"
    );
    let data = &native.ntfs_data_before;
    ensure!(
        (96..=128).contains(&data.len())
            && u64le(data, 0) == geometry.serial_number
            && u32le(data, 40) == u32::from(geometry.bytes_per_sector)
            && u32le(data, 44) == geometry.cluster_size
            && u32le(data, 48) == geometry.file_record_size
            && u64le(data, 8) == geometry.total_sectors
            && u64le(data, 16) == geometry.total_clusters
            && u64le(data, 64) == geometry.mft_lcn
            && u64le(data, 72) == geometry.mftmirr_lcn,
        "native NTFS geometry differs"
    );
    ensure!(
        native.request.partition_length == geometry.volume_size
            || native.request.partition_length
                == geometry
                    .volume_size
                    .checked_add(u64::from(geometry.bytes_per_sector))
                    .context("source length overflow")?,
        "native/source partition length differs"
    );
    Ok(())
}

pub fn compare(
    raw: &NtfsInspection,
    inspection_sha256: &str,
    native: &Report,
) -> Result<Comparison> {
    if !raw.attribute_assemblies.is_empty() {
        crate::ntfs_inspect::validate_record_coverage(raw)?;
    }
    native.request.validate()?;
    ensure!(
        matches!(native.schema_version, 2..=14) && !native.conversion_qualified,
        "unexpected native report kind/claim"
    );
    crate::ntfs_stream_attestation::validate_paging_schema(native)?;
    ensure!(
        native.request.source_inspection_sha256 == inspection_sha256,
        "native/source report binding differs"
    );
    check_header_geometry(&raw.geometry, native)?;
    ensure!(
        raw.files.len() == native.request.files.len() && raw.files.len() == native.files.len(),
        "native inventory coverage differs"
    );
    let requested: BTreeSet<_> = native
        .request
        .files
        .iter()
        .map(|f| (f.record_number, f.sequence_number))
        .collect();
    let expected: BTreeSet<_> = raw
        .files
        .iter()
        .map(|f| (f.record_number, f.sequence_number))
        .collect();
    let observed: BTreeSet<_> = native
        .files
        .iter()
        .map(|f| (f.identity.record_number, f.identity.sequence_number))
        .collect();
    ensure!(
        requested == expected && observed == expected && observed.len() == native.files.len(),
        "missing, duplicate or unexpected file identity"
    );
    let security = raw
        .security_reconciliation
        .as_ref()
        .context("missing raw security reconciliation")?;
    ensure!(
        security.status == ntfs_security::Status::ConsistentRawModel,
        "raw security model inconsistent"
    );
    let bindings: BTreeMap<_, _> = security
        .bindings
        .iter()
        .map(|b| ((b.record_number, b.sequence_number), &b.descriptor_sha256))
        .collect();
    let descriptors: BTreeMap<_, _> = security
        .descriptors
        .iter()
        .map(|d| (&d.descriptor.sha256, &d.descriptor.relative_hex))
        .collect();
    let mut files = vec![];
    let mut opened = 0;
    for f in &raw.files {
        let obs = native
            .files
            .iter()
            .find(|o| {
                o.identity.record_number == f.record_number
                    && o.identity.sequence_number == f.sequence_number
            })
            .unwrap();
        let mut issues = vec![];
        let mut raw_kernel_security_matched = None;
        let mut kernel_api_security_matched = None;
        if let Some(e) = obs.open_error {
            ensure!(
                obs.before.is_none() && obs.after.is_none(),
                "failed open also carries snapshots"
            );
            issues.push(format!("OpenFileById refused with Windows error {e}"));
        } else {
            opened += 1;
            let before = obs
                .before
                .as_ref()
                .context("successful open missing before snapshot")?;
            let after = obs
                .after
                .as_ref()
                .context("successful open missing after snapshot")?;
            let hash = bindings
                .get(&(f.record_number, f.sequence_number))
                .context("missing descriptor binding")?;
            let sd = hex::decode(descriptors.get(hash).context("missing bound descriptor")?)?;
            match (&before.kernel_security, &after.kernel_security) {
                (Some(kb), Some(ka)) if kb.native_error.is_none() && ka.native_error.is_none() => {
                    raw_kernel_security_matched =
                        Some(same_security(&sd, &kb.bytes)? && same_security(&sd, &ka.bytes)?);
                    if raw_kernel_security_matched == Some(false) {
                        issues.push("raw/kernel security semantics differ".into());
                    }
                    if before.security_error.is_none() && after.security_error.is_none() {
                        kernel_api_security_matched = Some(
                            same_security(&before.security, &kb.bytes)?
                                && same_security(&after.security, &ka.bytes)?,
                        );
                    }
                }
                (Some(kb), Some(ka)) => issues.push(format!(
                    "kernel security query refused: before {:?}, after {:?}",
                    kb.native_error, ka.native_error
                )),
                _ => issues.push("kernel security query missing".into()),
            }
            for (name, snapshot) in [("before", before), ("after", after)] {
                if let Err(e) = check_snapshot(f, raw.geometry.serial_number, &sd, snapshot) {
                    issues.push(format!("{name}: {e:#}"));
                }
            }
            if before != after {
                issues.push("file metadata changed between native snapshots".into());
            }
        }
        files.push(FileComparison {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            matched: issues.is_empty(),
            issues,
            raw_kernel_security_matched,
            kernel_api_security_matched,
        });
    }
    let matched = files.iter().filter(|f| f.matched).count();
    let native_streams = if native.schema_version >= 3 {
        Some(crate::ntfs_stream_attestation::reconcile(raw, native)?)
    } else {
        None
    };
    let native_logical_data = if native.schema_version >= 4 {
        Some(crate::ntfs_data_attestation::reconcile(raw, native)?)
    } else {
        None
    };
    let native_namespace = if native.schema_version >= 5 {
        Some(crate::ntfs_namespace_attestation::reconcile(raw, native)?)
    } else {
        None
    };
    let directory_case_sensitivity = matches!(
        (native.schema_version, native.request.schema_version),
        (13, 5) | (14, 6)
    )
    .then(|| compare_directory_cases(raw, native));
    Ok(Comparison {
        schema_version: 1,
        source_inspection_sha256: inspection_sha256.into(),
        requested_files: files.len(),
        opened_files: opened,
        matched_files: matched,
        all_requested_metadata_matched: matched == files.len()
            && native_streams
                .as_ref()
                .is_none_or(|s| s.all_mappings_matched)
            && native_logical_data
                .as_ref()
                .is_none_or(|d| d.all_requested_stream_evidence_matched)
            && native_namespace
                .as_ref()
                .is_none_or(|n| n.all_visible_names_matched)
            && directory_case_sensitivity
                .as_ref()
                .is_none_or(|evidence| evidence.all_directories_case_insensitive),
        files,
        conversion_qualified: false,
        native_streams,
        native_logical_data,
        native_namespace,
        directory_case_sensitivity,
    })
}
