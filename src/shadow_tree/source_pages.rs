//! Source/native projection into immutable expected-object pages. This owns
//! construction metadata only, never a source certificate or write authority.
use super::*;
use crate::ntfs_inspect::{
    external_sort::ExternalSort,
    paged_storage::{SourceRamLease, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
};
use crate::{
    ntfs_inspect::{PagedInspection, RootFileDomain},
    ntfs_stream_plan::{self, Disposition},
};
use n2r_win32::{attestation::NativeObservationDomain, tree_resources::SourceResourceAdmission};
use serde::ser::{Error as _, SerializeSeq, SerializeStruct};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, path::Path};

#[derive(Serialize, Deserialize)]
struct NameRow {
    folded: String,
}
#[derive(Serialize, Deserialize)]
struct PhysicalRow {
    offset: u64,
    length: u64,
}
#[derive(Serialize, Deserialize)]
struct WindowsTxfDisposition {
    record_number: u64,
    sequence_number: u16,
    source_attribute: ntfs::AttributeInventory,
}

pub struct SourceExpectedDomain {
    objects: SortedRecordStore,
    windows_ea_normalizations: Option<SortedRecordStore>,
    windows_txf_dispositions: Option<SortedRecordStore>,
    windows_object_id_dispositions: Option<SortedRecordStore>,
    windows_object_id_owner: Option<std::sync::Arc<crate::boot_alias::WindowsObjectIdDomain>>,
    windows_ea_normalized_entries: u64,
    object_count: usize,
    admission: SourceResourceAdmission,
    profile: String,
    logical_bytes: u64,
    internal_replacement_pending: Vec<String>,
    source_inspection_sha256: String,
    files: u64,
    directories: u64,
    streams: u64,
    scratch: SourceScratch,
    _role_ram: Vec<SourceRamLease>,
    _row_ram: SourceRamLease,
}

/// Retains the real immutable projection files after their complete semantic
/// comparison. This owner deliberately cannot decode objects or serialize a
/// new projection, and grants no source-admission or conversion authority.
pub(crate) struct ProjectionRevalidationOwner {
    objects: SortedRecordStore,
    windows_ea_normalizations: Option<SortedRecordStore>,
    windows_txf_dispositions: Option<SortedRecordStore>,
    windows_object_id_dispositions: Option<SortedRecordStore>,
    windows_object_id_owner: Option<std::sync::Arc<crate::boot_alias::WindowsObjectIdDomain>>,
    _scratch: SourceScratch,
}

impl ProjectionRevalidationOwner {
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.objects.revalidate()?;
        if let Some(records) = &self.windows_ea_normalizations {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_txf_dispositions {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_object_id_dispositions {
            records.revalidate()?;
        }
        if let Some(owner) = &self.windows_object_id_owner {
            owner.revalidate()?;
        }
        Ok(())
    }
}
fn ordered_key(first: u64, second: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&first.to_be_bytes());
    key[8..].copy_from_slice(&second.to_be_bytes());
    key
}
/// What a projected object's key and the root's place are made of, read
/// from its row under [`Object`]'s own field names. Every other field is
/// passed over, and the path's components are counted, not kept.
#[derive(serde::Deserialize)]
struct ObjectHead {
    record_number: u64,
    path: PathDepth,
    directory: bool,
}
/// How many components a path has: a sequence of strings, none of them
/// kept.
struct PathDepth(u64);
impl<'de> serde::Deserialize<'de> for PathDepth {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Component;
        impl<'de> serde::Deserialize<'de> for Component {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                struct Text;
                impl serde::de::Visitor<'_> for Text {
                    type Value = Component;
                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("a path component")
                    }
                    fn visit_str<E: serde::de::Error>(
                        self,
                        _: &str,
                    ) -> std::result::Result<Component, E> {
                        Ok(Component)
                    }
                }
                deserializer.deserialize_str(Text)
            }
        }
        struct Components;
        impl<'de> serde::de::Visitor<'de> for Components {
            type Value = PathDepth;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("the components of a path")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<PathDepth, A::Error> {
                let mut depth = 0u64;
                while sequence.next_element::<Component>()?.is_some() {
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| serde::de::Error::custom("path depth overflow"))?;
                }
                Ok(PathDepth(depth))
            }
        }
        deserializer.deserialize_seq(Components)
    }
}
fn add_role(
    roles: &mut Vec<String>,
    leases: &mut Vec<SourceRamLease>,
    role: String,
    scratch: &SourceScratch,
) -> Result<()> {
    // The caller is exclusively the exact finite NTFS internal-role policy
    // (plus root TXF). No arbitrary source object can append a pending role.
    let bytes = (role.capacity() as u64)
        .checked_add(2 * std::mem::size_of::<String>() as u64)
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<SourceRamLease>() as u64))
        .context("replacement-role RAM overflow")?;
    let lease = scratch.lease_ram(bytes)?;
    roles.try_reserve(1)?;
    leases.try_reserve(1)?;
    roles.push(role);
    leases.push(lease);
    Ok(())
}
fn descriptor(
    source: &PagedInspection,
    file: &ntfs::FileInventory,
) -> Result<ntfs_security::Descriptor> {
    let binding = source
        .security()
        .find_binding(file.record_number)?
        .context("source descriptor binding absent")?;
    ensure!(
        binding.sequence_number == file.sequence_number,
        "source descriptor sequence differs"
    );
    let value = if let Some(id) = binding.security_id {
        source.security().find_id(id)?
    } else {
        source.security().find_legacy(file.record_number)?
    }
    .context("source descriptor bytes absent")?;
    ensure!(
        value.descriptor.sha256 == binding.descriptor_sha256,
        "source descriptor binding hash differs"
    );
    Ok(value.descriptor)
}
fn stream_evidence(
    source: &PagedInspection,
    file: &ntfs::FileInventory,
    stream: &ntfs::StreamInventory,
    aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
) -> Result<Option<SourceStreamEvidence>> {
    match stream.logical_hash_status {
        ntfs::LogicalHashStatus::Complete => {
            ensure!(
                stream
                    .logical_sha256
                    .as_deref()
                    .is_some_and(n2r_win32::content_digest::is_hex),
                "complete source stream digest absent"
            );
            Ok(None)
        }
        ntfs::LogicalHashStatus::NotReadExtentIdentityV1 => {
            ensure!(
                stream.logical_sha256.is_none()
                    && (if aliases.is_some() {
                        crate::ntfs_attestation::extent_identity_stream_request_windows_domain(
                            source, file, stream,
                        )?
                    } else {
                        crate::ntfs_attestation::extent_identity_stream_request_domain(
                            source, file, stream, true, true,
                        )?
                    })
                    .is_some(),
                "source extent-only stream is not eligible"
            );
            Ok(Some(
                if n2r_win32::target_cluster::aligned(stream.logical_size) {
                    SourceStreamEvidence::ExtentIdentityV1
                } else {
                    SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1
                },
            ))
        }
        _ => anyhow::bail!("source stream evidence is incomplete"),
    }
}
/// What the comparison of the raw and Windows views wrote of one object
/// (`source-comparison`, the admission's `ObjectRow` of a
/// `PagedFileComparison`), read under its own field names: the results a
/// run that verifies once takes from there instead of evaluating them again.
#[derive(Deserialize)]
struct ComparedObject {
    native: ComparedViews,
    user_issues: Vec<String>,
}
#[derive(Deserialize)]
struct ComparedViews {
    record_number: u64,
    sequence_number: u16,
    internal_replacement_role: Option<String>,
    metadata: ComparedCheck,
    directory_case: Option<ComparedCheck>,
    case_sensitive_mark: bool,
    timestamps: Option<ComparedTimestamps>,
    security: Option<SecurityFacts>,
}
#[derive(Deserialize)]
struct ComparedCheck {
    matched: bool,
    detail: String,
}
#[derive(Deserialize)]
struct ComparedTimestamps {
    stored: [u64; 4],
}
/// The parts of a [`crate::ntfs_source_view::SecurityView`] the projection
/// uses, evaluated here or taken from the comparison.
#[derive(Deserialize)]
struct SecurityFacts {
    stored_sha256: String,
    api_descriptor_hex: String,
    api_matches_stored: bool,
    api_stable: bool,
    target_must_reproduce_both_views: bool,
}
impl From<crate::ntfs_source_view::SecurityView> for SecurityFacts {
    fn from(view: crate::ntfs_source_view::SecurityView) -> Self {
        Self {
            stored_sha256: view.stored_sha256,
            api_descriptor_hex: view.api_descriptor_hex,
            api_matches_stored: view.api_matches_stored,
            api_stable: view.api_stable,
            target_must_reproduce_both_views: view.target_must_reproduce_both_views,
        }
    }
}
fn compared_key(record_number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&record_number.to_be_bytes());
    key
}

/// `compared` is the comparison's store of rows where the run verifies once
/// (`--verify fast`, owner's decision D2, #250): the object's user issues, its metadata and
/// security views and its directory's case mark are then those the
/// comparison evaluated for it from the same held source and Windows rows,
/// and the Windows row is not decoded again. Without it they are evaluated
/// here, as every thorough run does.
#[allow(clippy::too_many_arguments)]
fn build_object(
    source: &PagedInspection,
    native: &impl NativeObservationDomain,
    compared: Option<&SortedRecordStore>,
    ordinal: u64,
    file: &ntfs::FileInventory,
    admission: SourceResourceAdmission,
    aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
    object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
    carry_case_marks: bool,
) -> Result<(
    Object,
    Option<crate::ntfs_extended_attributes::WindowsKernelPurgeEaNormalization>,
)> {
    let compared = compared
        .map(|rows| -> Result<ComparedObject> {
            let row: ComparedObject = rows
                .find(compared_key(file.record_number))?
                .with_context(|| {
                    format!(
                        "the comparison of FILE {} with its Windows view is absent from source-comparison",
                        file.record_number
                    )
                })?;
            ensure!(
                row.native.record_number == file.record_number
                    && row.native.sequence_number == file.sequence_number
                    && row.native.internal_replacement_role.is_none(),
                "the comparison row of FILE {} differs from the canonical source object",
                file.record_number
            );
            Ok(row)
        })
        .transpose()?;
    let resources = ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission));
    let mut names = if let Some(aliases) = aliases {
        aliases.user_paths(source, file)?
    } else {
        ntfs_admission::paged::user_paths(source, file)?
    };
    ensure!(
        !names.is_empty() && (!file.is_directory || names.len() == 1),
        "missing names or unsupported directory links"
    );
    for name in &names {
        if let Some(part) = name
            .iter()
            .find(|part| !n2r_win32::shadow_names::valid_unicode_component(part))
        {
            anyhow::bail!(
                "\\{} has {}, which the converter does not carry over: rename it",
                name.join("\\"),
                n2r_win32::shadow_names::component_refusal(part)
            );
        }
        ensure!(
            expected_path_fits(name, true),
            "\\{} is a path too long or too deep for the converter to carry over",
            name.join("\\")
        );
    }
    ensure!(
        !file.streams.iter().any(|s| !s.name_utf16.is_empty())
            || names.iter().all(|path| path
                .first()
                .is_none_or(|p| !p.eq_ignore_ascii_case("System Volume Information"))),
        "named System Volume Information payload requires its separate system implementation"
    );
    let path = names.remove(0);
    if file.record_number == 5 {
        ensure!(
            path.is_empty() && file.is_directory && file.streams.is_empty(),
            "invalid source root"
        );
        ensure!(
            file.attributes.iter().all(|a| a.flags == 0
                && a.lowest_vcn == 0
                && ((matches!(a.type_code, 0x10 | 0x30 | 0x50)
                    && a.resident
                    && a.name_utf16.is_empty())
                    || (matches!(a.type_code, 0x90 | 0xa0 | 0xb0)
                        && crate::ntfs_namespace::is_i30(&a.name_utf16))
                    || ntfs_admission::recognized_root_txf(a)
                    || (aliases
                        .is_some_and(|aliases| aliases.storage_hint_normalization().is_some())
                        && crate::ntfs_storage_class::recognized_default(a)))),
            "unknown root attributes"
        );
    } else {
        let evaluated;
        let issues: &[String] = if let Some(row) = &compared {
            &row.user_issues
        } else {
            evaluated = if let Some(aliases) = aliases {
                ntfs_admission::paged::ordinary_user_issues_windows(
                    source, file, admission, aliases,
                )?
            } else {
                ntfs_admission::paged::ordinary_user_issues_data(
                    source, file, admission, object_ids,
                )?
            };
            &evaluated
        };
        ensure!(
            issues.is_empty(),
            "record {} exceeds shadow profile: {issues:?}",
            file.record_number
        );
    }
    let sd = descriptor(source, file)?;
    let stored = hex::decode(&sd.relative_hex)?;
    n2r_win32::security_descriptor::validate_with_limit(&stored, admission.budget.max_row_bytes)?;
    let case_mark_context = || {
        format!(
            "the case-sensitive mark of the directory at FILE {} ({})",
            file.record_number,
            ntfs_admission::paged::refused_object_path(source, file)
                .map(|path| format!("\\{}", path.join("\\")))
                .unwrap_or_else(|| "its path was not read".to_owned())
        )
    };
    if aliases.is_some() {
        ensure!(
            source.is_windows_conversion(),
            "Windows projection requires its actual inspection purpose"
        );
    }
    let (case_sensitive, timestamps, views) = if let Some(row) = compared {
        // The comparison opened the object (its metadata check refuses an
        // object Windows did not open) and evaluated these on the same
        // decoding of its Windows row; an evaluation that failed there is
        // this projection's failure, with what the comparison found.
        let row = row.native;
        let case_sensitive = if carry_case_marks && file.is_directory {
            let check = row
                .directory_case
                .context("the comparison of a directory holds no case-sensitivity check")?;
            if !check.matched {
                return Err(anyhow::anyhow!("{}", check.detail)).with_context(case_mark_context);
            }
            Some(row.case_sensitive_mark)
        } else {
            None
        };
        ensure!(row.metadata.matched, "{}", row.metadata.detail);
        (
            case_sensitive,
            row.timestamps
                .context("the comparison holds no timestamp view")?
                .stored,
            row.security
                .context("the comparison holds no security view")?,
        )
    } else {
        let native_row = native.row_view(usize::try_from(ordinal)?)?;
        let observed = native_row.observation();
        ensure!(
            observed.identity.record_number == file.record_number
                && observed.identity.sequence_number == file.sequence_number
                && observed.open_error.is_none(),
            "actual native row identity/open differs from canonical source"
        );
        let before = observed
            .before
            .as_ref()
            .context("source native before snapshot absent")?;
        let after = observed
            .after
            .as_ref()
            .context("source native after snapshot absent")?;
        // Where the mark is carried over, every directory states the source's:
        // the new directory is made with it, set or not, and held to it. The
        // flags are those the admission read, asked of Windows twice.
        let case_sensitive = if carry_case_marks && file.is_directory {
            Some(
                crate::ntfs_attestation::check_directory_case_observation(
                    file,
                    source.header().geometry.serial_number,
                    observed,
                )
                .with_context(case_mark_context)?,
            )
        } else {
            None
        };
        let check_metadata = if aliases.is_some() {
            crate::ntfs_source_view::check_metadata_windows_with_limit
        } else {
            crate::ntfs_source_view::check_metadata_with_limit
        };
        let timestamps = check_metadata(
            file,
            source.header().geometry.serial_number,
            &stored,
            before,
            after,
            admission.budget.max_row_bytes,
        )?;
        let views = crate::ntfs_source_view::check_security_views_with_limit(
            &stored,
            before,
            after,
            admission.budget.max_row_bytes,
        )?;
        (
            case_sensitive,
            timestamps.stored,
            SecurityFacts::from(views),
        )
    };
    ensure!(
        views.api_stable
            && views.target_must_reproduce_both_views
            && views.stored_sha256 == hex::encode(Sha256::digest(&stored)),
        "source security view differs"
    );
    let si = file
        .standard_information
        .as_ref()
        .context("stored timestamps absent")?;
    let times = [
        si.creation_time,
        si.access_time,
        si.modification_time,
        si.mft_change_time,
    ];
    ensure!(
        timestamps == times,
        "source persisted timestamp projection differs"
    );
    let eas = crate::ntfs_attestation::has_verified_nonempty_eas(file);
    let reparse = crate::ntfs_reparse::file_point(file)?;
    let normalized = si.file_attributes & 0x800 != 0 || file.streams.iter().any(|s| s.flags == 1);
    let projected = crate::ntfs_file_attributes::project_user(file)?;
    ensure!(
        times.iter().all(|t| *t > 0 && *t < i64::MAX as u64)
            && projected.source_attributes
                & !(0x2027
                    | if reparse.is_some() { 0x400 } else { 0 }
                    | if file.streams.iter().any(|s| s.flags == 0x8000) {
                        0x200
                    } else {
                        0
                    }
                    | if eas { 0x40000 } else { 0 }
                    | if normalized { 0x800 } else { 0 })
                == 0,
        "unsupported basic metadata"
    );
    let (source_offset, source_extents, length, sha256, source_evidence, sparse) =
        if let Some(stream) = file.streams.iter().find(|s| s.name_utf16.is_empty()) {
            let decision = if let Some(aliases) = aliases {
                ntfs_stream_plan::classify_stream_windows_domain(
                    source, file, stream, admission, aliases,
                )?
            } else {
                ntfs_stream_plan::classify_stream_domain(source, file, stream, admission)?
            };
            let (offset, extents) = planned_stream_source(Some(&decision), resources)?;
            (
                offset,
                extents,
                stream.logical_size,
                stream.logical_sha256.clone(),
                stream_evidence(source, file, stream, aliases)?,
                decision.sparse,
            )
        } else {
            (None, Vec::new(), 0, None, None, None)
        };
    let mut named_streams = Vec::new();
    for stream in file.streams.iter().filter(|s| !s.name_utf16.is_empty()) {
        ensure!(!file.is_directory, "named directory streams unsupported");
        let decision = if let Some(aliases) = aliases {
            ntfs_stream_plan::classify_stream_windows_domain(
                source, file, stream, admission, aliases,
            )?
        } else {
            ntfs_stream_plan::classify_stream_domain(source, file, stream, admission)?
        };
        ensure!(
            decision.disposition != Disposition::Reject,
            "named source stream candidate refused"
        );
        let (offset, extents) = planned_stream_source(Some(&decision), resources)?;
        named_streams.try_reserve(1)?;
        named_streams.push(NamedStream {
            name_utf16: stream.name_utf16.clone(),
            source_offset: offset,
            source_extents: extents,
            length: stream.logical_size,
            sha256: stream.logical_sha256.clone(),
            source_evidence: stream_evidence(source, file, stream, aliases)?,
            sparse: decision.sparse,
        });
    }
    named_streams.sort_by(|a, b| a.name_utf16.cmp(&b.name_utf16));
    let (extended_attributes, ea_normalization) = if aliases.is_some() {
        ensure!(
            source.is_windows_conversion(),
            "Windows EA projection requires its actual inspection purpose"
        );
        crate::ntfs_extended_attributes::windows_target_projection(file)?
    } else {
        (crate::ntfs_extended_attributes::file_set(file)?, None)
    };
    Ok((
        Object {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            path,
            additional_names: names,
            directory: file.is_directory,
            stored_times: times,
            attributes: crate::ntfs_attestation::default_stream_attributes(
                file,
                projected.win32_attributes,
            )? & !if normalized { 0x800 } else { 0 },
            ntfs_compression_normalized: normalized,
            security: stored,
            api_security: if views.api_matches_stored {
                None
            } else {
                Some(hex::decode(views.api_descriptor_hex)?)
            },
            extended_attributes: Some(extended_attributes),
            reparse,
            case_sensitive,
            source_offset,
            source_extents,
            length,
            sha256,
            source_evidence,
            named_streams,
            sparse,
        },
        ea_normalization,
    ))
}

impl SourceExpectedDomain {
    /// Linear current-code equality proof for an authenticated saved body.
    /// Native rows are visited in source ordinal order; no projection stores,
    /// sort runs or replacement expected file are produced.
    pub(crate) fn verify_cached_body(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        admission: SourceResourceAdmission,
        aliases: &crate::boot_alias::WindowsAliasDomain,
        expected: &crate::shadow_tree::PagedExpectedTree,
        scratch: &SourceScratch,
    ) -> Result<()> {
        aliases.require_source(source)?;
        source.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        ensure!(
            native.header().request.source_inspection_sha256 == source.canonical_sha256()?
                && native.header().request.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(admission)
                    ))
                && native.len() as u64 == source.file_count()
                && expected.len() as u64 == admission.objects()?
                && expected.profile()
                    == crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission))
                        .ordinary_shadow_profile(),
            "cached expected current projection profile/source coverage differs"
        );
        let index_bytes = (expected.len() as u64)
            .checked_mul(256)
            .and_then(|n| n.checked_add(65536))
            .context("cached expected equality index RAM overflow")?;
        let _index = scratch.lease_ram(index_bytes)?;
        let _row = scratch.lease_ram(
            admission
                .budget
                .max_row_bytes
                .checked_mul(16)
                .and_then(|n| n.checked_add(8 * 1024 * 1024))
                .context("cached expected equality row RAM overflow")?,
        )?;
        let mut hashes = std::collections::BTreeMap::new();
        for index in 0..expected.len() {
            let object = expected.object_leased(index)?;
            let hash: [u8; 32] = Sha256::digest(serde_json::to_vec(&*object)?).into();
            ensure!(
                hashes.insert(object.record_number, hash).is_none(),
                "cached expected repeats a source identity"
            );
        }
        let mut logical = 0u64;
        let mut roles = Vec::new();
        for ordinal in 0..source.file_count() {
            let file = source.file_shared(ordinal)?;
            if let Some(role) = ntfs_admission::paged::internal_role(source, &file)? {
                roles.push(role);
                continue;
            }
            let (object, _) = build_object(
                source,
                native,
                None,
                ordinal,
                &file,
                admission,
                Some(aliases),
                None,
                // A volume that holds a Windows carries no mark over.
                false,
            )?;
            let hash: [u8; 32] = Sha256::digest(serde_json::to_vec(&object)?).into();
            ensure!(
                hashes.remove(&object.record_number) == Some(hash),
                "cached expected differs from current typed projection at FILE {}",
                object.record_number
            );
            for stream in object.data_streams() {
                logical = logical
                    .checked_add(stream.length)
                    .context("cached expected logical total overflow")?;
            }
            if file.record_number == 5
                && file
                    .attributes
                    .iter()
                    .any(ntfs_admission::recognized_root_txf)
            {
                roles.push("root:$TXF_DATA (not yet admitted for replacement)".to_owned());
            }
        }
        ensure!(
            hashes.is_empty()
                && logical == expected.logical_bytes()
                && roles.as_slice() == expected.internal_replacement_pending(),
            "cached expected user coverage/logical total/roles differ"
        );
        source.revalidate()?;
        native.revalidate()?;
        expected.revalidate()?;
        Ok(())
    }
    pub fn derive(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        Self::derive_scoped(
            source, native, None, admission, output, scratch, None, None, false,
        )
    }
    /// The tree of a data volume whose object IDs, if it has any, have been
    /// matched and archived and are not carried over. With
    /// `carry_case_marks`, every directory of the tree states its
    /// case-sensitive mark, set or not: the run's decision, taken where the
    /// source has a marked directory and the running Windows is one the
    /// mark is carried on (`n2r_win32::directory_case::CaseMarkCarry`).
    /// `compared` as in [`build_object`].
    #[allow(clippy::too_many_arguments)]
    pub fn derive_data(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        compared: Option<&SortedRecordStore>,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
        carry_case_marks: bool,
    ) -> Result<Self> {
        Self::derive_scoped(
            source,
            native,
            compared,
            admission,
            output,
            scratch,
            None,
            object_ids,
            carry_case_marks,
        )
    }
    /// `compared` as in [`build_object`].
    pub fn derive_windows(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        compared: Option<&SortedRecordStore>,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        aliases: &crate::boot_alias::WindowsAliasDomain,
    ) -> Result<Self> {
        aliases.require_source(source)?;
        Self::derive_scoped(
            source,
            native,
            compared,
            admission,
            output,
            scratch,
            Some(aliases),
            None,
            false,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn derive_scoped(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        compared: Option<&SortedRecordStore>,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
        object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
        carry_case_marks: bool,
    ) -> Result<Self> {
        admission.validate()?;
        ensure!(
            !carry_case_marks || aliases.is_none(),
            "a volume that holds a Windows carries no case-sensitive mark over"
        );
        ensure!(
            aliases.is_none() || source.is_windows_conversion(),
            "Windows projection requires its actual inspection purpose"
        );
        source.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        native.revalidate()?;
        n2r_win32::attestation::validate_domain_resources(native)?;
        let source_pin = source.canonical_sha256()?;
        let source_hash: [u8; 32] = hex::decode(&source_pin)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("source inspection pin length differs"))?;
        let expected_budget =
            crate::ntfs_inspect::SourceMetadataBudget::from_resource_budget(admission.budget)?;
        let actual_budget = scratch.budget();
        ensure!(
            native.is_paged()
                && native.len() as u64 == source.file_count()
                && native.header().request.source_inspection_sha256 == source_pin
                && !native.header().conversion_qualified
                && native.header().request.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(admission)
                    ))
                && admission.source_inspection_sha256 == source_hash
                && scratch.budget().page_budget()? == admission.expected_page_budget()?
                && actual_budget.ram_bytes == expected_budget.ram_bytes
                && actual_budget.record_bytes == expected_budget.record_bytes
                && actual_budget.merge_fan_in == expected_budget.merge_fan_in,
            "actual source/native/resource projection ownership differs"
        );
        let row_working_bytes = admission
            .budget
            .max_row_bytes
            .checked_mul(8)
            .context("source object working RAM overflow")?;
        let row_ram = scratch.lease_ram(row_working_bytes)?;
        // The complete source counts size batches only; extra names or large
        // rows still spill and merge without dropping any source evidence.
        let mut objects = ExternalSort::with_shared_projection_hint(
            &output.join("source-objects"),
            *b"N2RSOBJ1",
            scratch,
            source.file_count(),
        )?;
        let mut names = ExternalSort::with_shared_projection_hint(
            &output.join("destination-names"),
            *b"N2RDNAM1",
            scratch,
            source.file_count(),
        )?;
        // Check physical source range non-overlap in spare RAM when available
        // (16 bytes per range; e.g. 200k ranges = 3.2 MiB), falling back to
        // on-disk ExternalSort if spare RAM is unavailable or capacity is exceeded.
        const PHYSICAL_MEM_CAP: usize = 512 * 1024;
        let physical_hint = usize::try_from(source.allocation().physical_intervals)
            .unwrap_or(PHYSICAL_MEM_CAP)
            .clamp(64, PHYSICAL_MEM_CAP);
        let physical_mem_bytes = (physical_hint as u64) * 16;
        let mut physical_mem: Option<(Vec<(u64, u64)>, SourceRamLease)> = scratch
            .lease_spare_ram(physical_mem_bytes)
            .ok()
            .map(|lease| (Vec::with_capacity(physical_hint), lease));
        let mut physical: Option<ExternalSort> = if physical_mem.is_none() {
            Some(ExternalSort::with_shared_projection_hint(
                &output.join("retained-source-ranges"),
                *b"N2RPHYS1",
                scratch,
                source.allocation().physical_intervals,
            )?)
        } else {
            None
        };
        let mut roles = Vec::new();
        let mut role_ram = Vec::new();
        let mut windows_ea_writer = aliases
            .map(|_| {
                SortedRecordWriter::new(
                    &output.join("windows-kernel-purge-ea-normalizations"),
                    *b"WINEAN01",
                    scratch,
                )
            })
            .transpose()?;
        let mut windows_ea_normalized_entries = 0u64;
        let mut windows_txf_writer = aliases
            .map(|_| {
                SortedRecordWriter::new(
                    &output.join("windows-nontransacted-txf-dispositions"),
                    *b"WINTXF01",
                    scratch,
                )
            })
            .transpose()?;
        let windows_object_id_owner = aliases.and_then(|owner| owner.windows_object_ids_owned());
        let mut windows_object_id_writer = windows_object_id_owner
            .as_ref()
            .map(|_| {
                SortedRecordWriter::new(
                    &output.join("windows-object-ID-dispositions"),
                    *b"WINOIDP1",
                    scratch,
                )
            })
            .transpose()?;
        let (
            mut files,
            mut directories,
            mut streams,
            mut logical_bytes,
            mut name_ordinal,
            mut physical_ordinal,
            mut pushed_roots,
        ) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        // Parallelize JSON serialization and case-folded NameRow generation in
        // spare-RAM batches of up to 256 objects, falling back to single-object
        // inline encoding if spare RAM is unavailable.
        const SERIALIZE_BATCH: usize = 256;
        const SERIALIZE_BATCH_SPARE_BYTES: u64 = 16 * 1024 * 1024;
        let _serialize_spare = scratch.lease_spare_ram(SERIALIZE_BATCH_SPARE_BYTES).ok();
        let serialize_batch_limit = if _serialize_spare.is_some() {
            SERIALIZE_BATCH
        } else {
            1
        };
        let serialize_workers = std::thread::available_parallelism()
            .map_or(2, |n| n.get())
            .clamp(2, 4);
        let record_limit = scratch.budget().record_bytes;
        struct EncodedObject {
            object_key: [u8; 16],
            object_json: Vec<u8>,
            names: Vec<(u64, Vec<u8>)>,
        }
        let encode_one = |(object_key, object): ([u8; 16], Object)| -> Result<EncodedObject> {
            let object_json = serde_json::to_vec(&object)?;
            ensure!(
                !object_json.is_empty() && (object_json.len() as u64) <= record_limit,
                "projected source object exceeds admitted working record bytes"
            );
            let mut folded_names = Vec::with_capacity(1 + object.additional_names.len());
            for path in std::iter::once(&object.path).chain(object.additional_names.iter()) {
                let folded = n2r_win32::shadow_names::conservative_path_key(path);
                let bucket = xxhash_rust::xxh3::xxh3_64(folded.as_bytes());
                let name_json = serde_json::to_vec(&NameRow { folded })?;
                folded_names.push((bucket, name_json));
            }
            Ok(EncodedObject {
                object_key,
                object_json,
                names: folded_names,
            })
        };
        let mut pending_objects: Vec<([u8; 16], Object)> =
            Vec::with_capacity(serialize_batch_limit);
        let flush_encoded = |pending: &mut Vec<([u8; 16], Object)>,
                             objects: &mut ExternalSort,
                             names: &mut ExternalSort,
                             name_ordinal: &mut u64|
         -> Result<()> {
            if pending.is_empty() {
                return Ok(());
            }
            let items = std::mem::take(pending);
            let encoded: Vec<Result<EncodedObject>> = if items.len() >= 16 && serialize_workers > 1
            {
                let chunk_size = items.len().div_ceil(serialize_workers);
                let mut iter = items.into_iter();
                let mut chunks: Vec<Vec<([u8; 16], Object)>> =
                    Vec::with_capacity(serialize_workers);
                loop {
                    let chunk: Vec<_> = iter.by_ref().take(chunk_size).collect();
                    if chunk.is_empty() {
                        break;
                    }
                    chunks.push(chunk);
                }
                std::thread::scope(|scope| {
                    let handles: Vec<_> = chunks
                        .into_iter()
                        .map(|chunk| {
                            scope.spawn(|| chunk.into_iter().map(&encode_one).collect::<Vec<_>>())
                        })
                        .collect();
                    let mut out = Vec::with_capacity(SERIALIZE_BATCH);
                    for handle in handles {
                        out.extend(handle.join().expect("source projection worker panicked"));
                    }
                    out
                })
            } else {
                items.into_iter().map(&encode_one).collect()
            };
            for row in encoded {
                let row = row?;
                for (bucket, name_json) in row.names {
                    names.push_json(ordered_key(bucket, *name_ordinal), name_json)?;
                    *name_ordinal = name_ordinal
                        .checked_add(1)
                        .context("namespace name count overflow")?;
                }
                objects.push_json(row.object_key, row.object_json)?;
            }
            Ok(())
        };
        for ordinal in 0..source.file_count() {
            let file = source.file_shared(ordinal)?;
            if let Some(role) = ntfs_admission::paged::internal_role(source, &file)? {
                add_role(&mut roles, &mut role_ram, role, scratch)?;
                continue;
            }
            let (object, ea_normalization) = build_object(
                source,
                native,
                compared,
                ordinal,
                &file,
                admission,
                aliases,
                object_ids,
                carry_case_marks,
            )?;
            if aliases
                .map(|owner| owner.windows_txf_accounted(source, &file))
                .transpose()?
                .unwrap_or(false)
            {
                let attribute = file
                    .attributes
                    .iter()
                    .find(|attribute| {
                        attribute.type_code == 0x100
                            && attribute.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
                    })
                    .context("verified Windows TxF source attribute disappeared")?;
                windows_txf_writer
                    .as_mut()
                    .context("Windows TxF disposition archive absent")?
                    .push(
                        ordered_key(ordinal, file.record_number),
                        &WindowsTxfDisposition {
                            record_number: file.record_number,
                            sequence_number: file.sequence_number,
                            source_attribute: attribute.clone(),
                        },
                    )?;
            }
            if let Some(owner) = &windows_object_id_owner {
                if let Some(disposition) = owner.disposition(source, &file)? {
                    windows_object_id_writer
                        .as_mut()
                        .context("Windows object-ID disposition archive absent")?
                        .push(ordered_key(ordinal, file.record_number), &disposition)?;
                }
            }
            if let Some(normalization) = ea_normalization {
                windows_ea_normalized_entries = windows_ea_normalized_entries
                    .checked_add(u64::try_from(normalization.omitted.entries.len())?)
                    .context("Windows kernel EA normalization count overflow")?;
                windows_ea_writer
                    .as_mut()
                    .context("Windows EA normalization archive absent")?
                    .push(ordered_key(ordinal, file.record_number), &normalization)?;
            }
            if object.directory {
                directories = directories
                    .checked_add(1)
                    .context("directory count overflow")?;
            } else {
                files = files.checked_add(1).context("file count overflow")?;
            }
            let mut ranges = Vec::new();
            for stream in object.data_streams() {
                streams = streams
                    .checked_add(1)
                    .context("DATA-stream count overflow")?;
                logical_bytes = logical_bytes
                    .checked_add(stream.length)
                    .context("logical byte total overflow")?;
                validate_stream_source(stream, &mut ranges)?;
            }
            for (offset, length) in ranges {
                ensure!(
                    offset
                        .checked_add(length)
                        .is_some_and(|end| end <= source.header().geometry.volume_size),
                    "retained source payload escapes the source"
                );
                if let Some((vec, _)) = physical_mem.as_mut() {
                    if vec.len() < vec.capacity() {
                        vec.push((offset, length));
                        continue;
                    }
                    let (spilled, lease) = physical_mem.take().unwrap();
                    drop(lease);
                    let mut sorter = ExternalSort::with_shared_projection_hint(
                        &output.join("retained-source-ranges"),
                        *b"N2RPHYS1",
                        scratch,
                        source.allocation().physical_intervals,
                    )?;
                    for (prev_offset, prev_length) in spilled {
                        sorter.push(
                            ordered_key(prev_offset, physical_ordinal),
                            &PhysicalRow {
                                offset: prev_offset,
                                length: prev_length,
                            },
                        )?;
                        physical_ordinal = physical_ordinal
                            .checked_add(1)
                            .context("physical source interval count overflow")?;
                    }
                    physical = Some(sorter);
                }
                physical
                    .as_mut()
                    .context("physical range sorter absent")?
                    .push(
                        ordered_key(offset, physical_ordinal),
                        &PhysicalRow { offset, length },
                    )?;
                physical_ordinal = physical_ordinal
                    .checked_add(1)
                    .context("physical source interval count overflow")?;
            }
            if file.record_number == 5
                && file
                    .attributes
                    .iter()
                    .any(ntfs_admission::recognized_root_txf)
            {
                add_role(
                    &mut roles,
                    &mut role_ram,
                    "root:$TXF_DATA (not yet admitted for replacement)".into(),
                    scratch,
                )?;
            }
            if object.path.is_empty() {
                ensure!(
                    object.directory && object.record_number == 5,
                    "invalid projected root"
                );
                pushed_roots += 1;
            }
            let object_key = ordered_key(u64::try_from(object.path.len())?, object.record_number);
            pending_objects.push((object_key, object));
            if pending_objects.len() >= serialize_batch_limit {
                flush_encoded(
                    &mut pending_objects,
                    &mut objects,
                    &mut names,
                    &mut name_ordinal,
                )?;
            }
        }
        flush_encoded(
            &mut pending_objects,
            &mut objects,
            &mut names,
            &mut name_ordinal,
        )?;
        drop(_serialize_spare);
        if let Some(aliases) = aliases {
            // Alias entries participate in the real destination collision
            // proof without becoming source objects or changing source counts.
            for ordinal in 0..aliases.len() {
                let alias = aliases.alias(ordinal)?;
                let folded = n2r_win32::shadow_names::conservative_path_key(&alias.path);
                let bucket = xxhash_rust::xxh3::xxh3_64(folded.as_bytes());
                names.push(ordered_key(bucket, name_ordinal), &NameRow { folded })?;
                name_ordinal = name_ordinal
                    .checked_add(1)
                    .context("Windows alias namespace count overflow")?;
            }
            aliases.require_source(source)?;
        }
        admission.validate_tree(files, directories, streams)?;
        // Object construction is complete. Return its transient parse/clone
        // allowance before opening merge heads and output verification rows.
        drop(row_ram);
        let name_pin = names.finish()?;
        let row_ram = scratch.lease_ram(row_working_bytes)?;
        let name_store = SortedRecordStore::open(&name_pin, scratch)?;
        // Hashes only select bounded on-disk comparison buckets. Equality is
        // ALWAYS the full folded string; distinct hash-colliding names remain
        // valid, and no bucket-size cap or resident whole-name set exists.
        //
        // The last name of a bucket (nearly every name is alone in its
        // bucket) is compared with no other. A run that verifies once does
        // not decode its row only to drop it: the rows are those this pass
        // has just serialized into the store, which its writer framed and
        // which is held. Every other run decodes every row, as before.
        let decode_every_row = !n2r_win32::verify_policy::verifies_once();
        let mut start = 0u64;
        while start < name_store.len() {
            let prefix: [u8; 8] = name_store.key(start)?[..8].try_into()?;
            let mut end = start + 1;
            while end < name_store.len() && name_store.key(end)?[..8] == prefix {
                end += 1;
            }
            for a in start..end {
                if a + 1 == end && !decode_every_row {
                    break;
                }
                let left: NameRow = name_store.get(a)?;
                for b in a + 1..end {
                    let right: NameRow = name_store.get(b)?;
                    ensure!(left.folded != right.folded, "colliding destination name");
                }
            }
            start = end;
        }
        drop(name_store);
        scratch.retire_created(&name_pin.data)?;
        scratch.retire_created(&name_pin.directory)?;
        drop(row_ram);
        if let Some((mut ranges, lease)) = physical_mem.take() {
            ranges.sort_unstable();
            let mut prior_end = 0u64;
            for (offset, length) in ranges {
                ensure!(
                    offset >= prior_end && length > 0,
                    "overlapping default or named source payloads"
                );
                prior_end = offset
                    .checked_add(length)
                    .context("physical source interval overflow")?;
            }
            drop(lease);
        } else if let Some(physical) = physical.take() {
            let physical_pin = physical.finish()?;
            let row_ram = scratch.lease_ram(row_working_bytes)?;
            let physical_store = SortedRecordStore::open(&physical_pin, scratch)?;
            let mut prior_end = 0u64;
            for ordinal in 0..physical_store.len() {
                let range: PhysicalRow = physical_store.get(ordinal)?;
                ensure!(
                    range.offset >= prior_end && range.length > 0,
                    "overlapping default or named source payloads"
                );
                prior_end = range
                    .offset
                    .checked_add(range.length)
                    .context("physical source interval overflow")?;
            }
            drop(physical_store);
            scratch.retire_created(&physical_pin.data)?;
            scratch.retire_created(&physical_pin.directory)?;
            drop(row_ram);
        }
        let object_pin = objects.finish()?;
        let row_ram = scratch.lease_ram(row_working_bytes)?;
        let objects = SortedRecordStore::open(&object_pin, scratch)?;
        ensure!(
            objects.len() == admission.objects()? && directories > 0,
            "complete projected object domain differs"
        );
        let object_count = usize::try_from(objects.len())?;
        let windows_ea_normalizations = windows_ea_writer
            .map(|writer| SortedRecordStore::open(&writer.finish()?, scratch))
            .transpose()?;
        let windows_txf_dispositions = windows_txf_writer
            .map(|writer| SortedRecordStore::open(&writer.finish()?, scratch))
            .transpose()?;
        let windows_object_id_dispositions = windows_object_id_writer
            .map(|writer| SortedRecordStore::open(&writer.finish()?, scratch))
            .transpose()?;
        if let Some(owner) = &windows_object_id_owner {
            owner.require_source(source)?;
            ensure!(
                windows_object_id_dispositions
                    .as_ref()
                    .is_some_and(|records| records.len() == owner.len()),
                "Windows object-ID projected disposition coverage differs"
            );
        }
        // Each row is held to its key and the root to its place. Under the
        // check-once policy, outside its gate, this pass just wrote every row
        // from a typed `Object` into `objects` with key `(path.len(), record_number)`
        // and verified the single root while pushing, and `SortedRecordStore::open`
        // verified the store's integrity and strictly ascending keys. Otherwise
        // the whole object is decoded here, as it always was.
        if !n2r_win32::verify_policy::full_unremembered() {
            ensure!(
                pushed_roots == 1,
                "exactly one projected source root required"
            );
        } else {
            let mut roots = 0u64;
            for ordinal in 0..objects.len() {
                let object: Object = objects.get(ordinal)?;
                let head = ObjectHead {
                    record_number: object.record_number,
                    path: PathDepth(u64::try_from(object.path.len())?),
                    directory: object.directory,
                };
                ensure!(
                    objects.key(ordinal)? == ordered_key(head.path.0, head.record_number),
                    "projected object key or ordering differs"
                );
                if head.path.0 == 0 {
                    ensure!(
                        head.directory && head.record_number == 5,
                        "invalid projected root"
                    );
                    roots += 1;
                }
            }
            ensure!(roots == 1, "exactly one projected source root required");
        }
        source.revalidate()?;
        native.revalidate()?;
        let value = Self {
            objects,
            windows_ea_normalizations,
            windows_txf_dispositions,
            windows_object_id_dispositions,
            windows_object_id_owner,
            windows_ea_normalized_entries,
            object_count,
            admission,
            profile: ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission))
                .ordinary_shadow_profile()
                .into(),
            logical_bytes,
            internal_replacement_pending: roles,
            source_inspection_sha256: source_pin,
            files,
            directories,
            streams,
            scratch: scratch.clone(),
            _role_ram: role_ram,
            _row_ram: row_ram,
        };
        value.revalidate_stores()?;
        Ok(value)
    }
    pub fn object_pin(&self) -> &RecordStorePin {
        self.objects.pin()
    }
    pub fn source_inspection_sha256(&self) -> &str {
        &self.source_inspection_sha256
    }

    fn revalidate_stores(&self) -> Result<()> {
        self.objects.revalidate()?;
        if let Some(records) = &self.windows_ea_normalizations {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_txf_dispositions {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_object_id_dispositions {
            records.revalidate()?;
        }
        if let Some(owner) = &self.windows_object_id_owner {
            owner.revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn windows_ea_normalization_report(&self) -> Result<Option<serde_json::Value>> {
        self.revalidate_stores()?;
        Ok(self.windows_ea_normalizations.as_ref().map(|records| serde_json::json!({
            "kind":"Windows-target-kernel-purge-EA-normalization-v1",
            "source_inspection_sha256":self.source_inspection_sha256,
            "records":records.pin(), "normalized_objects":records.len(),
            "omitted_kernel_purge_entries":self.windows_ea_normalized_entries,
            "policy":"target only: omit flags0 $Kernel.Purge.<nonempty> caches and the flags0 $Kernel.CFDoNotConvert hive mark; archive exact source EAs; preserve ordinary EAs",
            "ea_set_digest_format":"ntfs2refs-exact-EA-set-v1",
            "raw_source_evidence_changed":false,"source_native_comparison_changed":false,
            "grants_source_or_replay_authority":false,
        })))
    }
    pub(crate) fn windows_txf_disposition_report(&self) -> Result<Option<serde_json::Value>> {
        self.revalidate_stores()?;
        Ok(self.windows_txf_dispositions.as_ref().map(|records| serde_json::json!({
            "kind":"Windows-source-nontransacted-TxF-disposition-v1",
            "source_inspection_sha256":self.source_inspection_sha256,
            "records":records.pin(), "source_marker_objects":records.len(),
            "policy":"archive exact NTFS-only TxF marker bytes after live protected per-file nontransacted proof; target files preserve ordinary content and metadata",
            "target_transactional_continuity_preserved":false,
            "grants_source_or_replay_authority":false,
        })))
    }
    pub(crate) fn windows_object_id_disposition_report(&self) -> Result<Option<serde_json::Value>> {
        self.revalidate_stores()?;
        Ok(self.windows_object_id_dispositions.as_ref().map(|records|serde_json::json!({
            "kind":"Windows-target-object-ID-epoch-disposition-v1",
            "source_inspection_sha256":self.source_inspection_sha256,"records":records.pin(),
            "source_object_id_objects":records.len(),"source_owner":self.windows_object_id_owner.as_ref().map(|owner|owner.audit()),
            "policy":"retain exact source raw/index/native object-ID bytes in paid metadata; target starts a new object-ID epoch",
            "target_object_id_continuity_preserved":false,"raw_source_evidence_changed":false,
            "source_native_comparison_changed":false,"grants_source_or_replay_authority":false,
        })))
    }

    /// Drop decode-only workspace once the caller has completed its semantic
    /// comparison, without replacing the held file owners with serialized pins.
    pub(crate) fn into_revalidation_owner(self) -> Result<ProjectionRevalidationOwner> {
        self.revalidate_stores()?;
        let Self {
            objects,
            windows_ea_normalizations,
            windows_txf_dispositions,
            windows_object_id_dispositions,
            windows_object_id_owner,
            scratch,
            ..
        } = self;
        Ok(ProjectionRevalidationOwner {
            objects,
            windows_ea_normalizations,
            windows_txf_dispositions,
            windows_object_id_dispositions,
            windows_object_id_owner,
            _scratch: scratch,
        })
    }
}
impl ExpectedObjectDomain for SourceExpectedDomain {
    fn object_count(&self) -> usize {
        self.object_count
    }
    fn object(&self, index: usize) -> Result<Cow<'_, Object>> {
        self.objects.get(index as u64).map(Cow::Owned)
    }
    fn profile(&self) -> &str {
        &self.profile
    }
    fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    fn internal_replacement_pending(&self) -> &[String] {
        &self.internal_replacement_pending
    }
    fn revalidate_domain(&self) -> Result<()> {
        self.revalidate_stores()
    }
    fn require_paged_metadata(
        &self,
        budget: n2r_win32::metadata_pages::PageBudget,
        semantic: u64,
    ) -> Result<()> {
        ensure!(
            budget == self.admission.expected_page_budget()?
                && semantic == self.admission.semantic_byte_budget(),
            "actual projected page resources differ"
        );
        self.revalidate_stores()
    }
    fn require_resource_metadata(&self, admission: SourceResourceAdmission) -> Result<()> {
        ensure!(
            admission == self.admission && !self.scratch.is_poisoned(),
            "projected source admission differs"
        );
        admission.validate_tree(self.files, self.directories, self.streams)?;
        self.require_paged_metadata(
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
        )
    }
}
struct Objects<'a>(&'a SourceExpectedDomain);
impl Serialize for Objects<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let count = usize::try_from(self.0.objects.len()).map_err(S::Error::custom)?;
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for ordinal in 0..self.0.objects.len() {
            let object: Object = self.0.objects.get(ordinal).map_err(S::Error::custom)?;
            sequence.serialize_element(&object)?;
        }
        sequence.end()
    }
}
impl Serialize for SourceExpectedDomain {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("ExpectedTree", 4)?;
        value.serialize_field("profile", &self.profile)?;
        value.serialize_field("objects", &Objects(self))?;
        value.serialize_field("logical_bytes", &self.logical_bytes)?;
        value.serialize_field(
            "internal_replacement_pending",
            &self.internal_replacement_pending,
        )?;
        value.end()
    }
}
