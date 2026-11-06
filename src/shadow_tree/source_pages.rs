//! Source/native projection into immutable expected-object pages. This owns
//! construction metadata only, never a source certificate or write authority.
use super::*;
use crate::ntfs_inspect::{
    external_sort::ExternalSort,
    paged_storage::{SourceRamLease, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore},
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

pub struct SourceExpectedDomain {
    objects: SortedRecordStore,
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
    _scratch: SourceScratch,
}

impl ProjectionRevalidationOwner {
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.objects.revalidate()
    }
}
fn ordered_key(first: u64, second: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&first.to_be_bytes());
    key[8..].copy_from_slice(&second.to_be_bytes());
    key
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
                        crate::ntfs_attestation::extent_identity_stream_request_windows_domain(source, file, stream)?
                    } else {
                        crate::ntfs_attestation::extent_identity_stream_request_domain(source, file, stream, true, true)?
                    }).is_some(),
                "source extent-only stream is not eligible"
            );
            Ok(Some(if stream.logical_size.is_multiple_of(4096) {
                SourceStreamEvidence::ExtentIdentityV1
            } else {
                SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1
            }))
        }
        _ => anyhow::bail!("source stream evidence is incomplete"),
    }
}
fn build_object(
    source: &PagedInspection,
    native: &impl NativeObservationDomain,
    ordinal: u64,
    file: &ntfs::FileInventory,
    admission: SourceResourceAdmission,
    aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
) -> Result<Object> {
    let resources = ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission));
    let mut names = if let Some(aliases) = aliases { aliases.user_paths(source, file)? }
        else { ntfs_admission::paged::user_paths(source, file)? };
    ensure!(
        !names.is_empty() && (!file.is_directory || names.len() == 1),
        "missing names or unsupported directory links"
    );
    for name in &names {
        ensure!(
            expected_path_fits(name, true)
                && name
                    .iter()
                    .all(|part| n2r_win32::shadow_names::valid_unicode_component(part)),
            "unsupported Windows path"
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
                    || (aliases.is_some_and(|aliases| aliases.storage_hint_normalization().is_some())
                        && crate::ntfs_storage_class::recognized_default(a)))),
            "unknown root attributes"
        );
    } else {
        let issues = if let Some(aliases) = aliases {
            ntfs_admission::paged::ordinary_user_issues_windows(source, file, admission, aliases)?
        } else { ntfs_admission::paged::ordinary_user_issues(source, file, admission)? };
        ensure!(
            issues.is_empty(),
            "record {} exceeds shadow profile: {issues:?}",
            file.record_number
        );
    }
    let sd = descriptor(source, file)?;
    let stored = hex::decode(&sd.relative_hex)?;
    n2r_win32::security_descriptor::validate_with_limit(&stored, admission.budget.max_row_bytes)?;
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
    let timestamps = crate::ntfs_source_view::check_metadata_with_limit(
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
        timestamps.stored == times,
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
                ntfs_stream_plan::classify_stream_windows_domain(source, file, stream, admission, aliases)?
            } else { ntfs_stream_plan::classify_stream_domain(source, file, stream, admission)? };
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
            ntfs_stream_plan::classify_stream_windows_domain(source, file, stream, admission, aliases)?
        } else { ntfs_stream_plan::classify_stream_domain(source, file, stream, admission)? };
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
    Ok(Object {
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
        extended_attributes: Some(crate::ntfs_extended_attributes::file_set(file)?),
        reparse,
        source_offset,
        source_extents,
        length,
        sha256,
        source_evidence,
        named_streams,
        sparse,
    })
}

impl SourceExpectedDomain {
    pub fn derive(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        Self::derive_scoped(source, native, admission, output, scratch, None)
    }
    pub fn derive_windows(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        aliases: &crate::boot_alias::WindowsAliasDomain,
    ) -> Result<Self> {
        aliases.require_source(source)?;
        Self::derive_scoped(source, native, admission, output, scratch, Some(aliases))
    }
    fn derive_scoped(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
    ) -> Result<Self> {
        admission.validate()?;
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
        let row_ram = scratch.lease_ram(
            admission
                .budget
                .max_row_bytes
                .checked_mul(8)
                .context("source object working RAM overflow")?,
        )?;
        // The complete source counts size batches only; extra names or large
        // rows still spill and merge without dropping any source evidence.
        let mut objects = ExternalSort::with_record_hint(
            &output.join("source-objects"),
            *b"N2RSOBJ1",
            scratch,
            source.file_count(),
        )?;
        let mut names = ExternalSort::with_record_hint(
            &output.join("destination-names"),
            *b"N2RDNAM1",
            scratch,
            source.file_count(),
        )?;
        let mut physical = ExternalSort::with_record_hint(
            &output.join("retained-source-ranges"),
            *b"N2RPHYS1",
            scratch,
            source.allocation().physical_intervals,
        )?;
        let mut roles = Vec::new();
        let mut role_ram = Vec::new();
        let (
            mut files,
            mut directories,
            mut streams,
            mut logical_bytes,
            mut name_ordinal,
            mut physical_ordinal,
        ) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        for ordinal in 0..source.file_count() {
            let file = source.file(ordinal)?;
            if let Some(role) = ntfs_admission::paged::internal_role(source, &file)? {
                add_role(&mut roles, &mut role_ram, role, scratch)?;
                continue;
            }
            let object = build_object(source, native, ordinal, &file, admission, aliases)?;
            if object.directory {
                directories = directories
                    .checked_add(1)
                    .context("directory count overflow")?;
            } else {
                files = files.checked_add(1).context("file count overflow")?;
            }
            for path in std::iter::once(&object.path).chain(object.additional_names.iter()) {
                let folded = n2r_win32::shadow_names::conservative_path_key(path);
                let hash = Sha256::digest(folded.as_bytes());
                let bucket = u64::from_be_bytes(hash[..8].try_into()?);
                names.push(ordered_key(bucket, name_ordinal), &NameRow { folded })?;
                name_ordinal = name_ordinal
                    .checked_add(1)
                    .context("namespace name count overflow")?;
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
                physical.push(
                    ordered_key(offset, physical_ordinal),
                    &PhysicalRow { offset, length },
                )?;
                physical_ordinal = physical_ordinal
                    .checked_add(1)
                    .context("physical source interval count overflow")?;
            }
            if file.record_number == 5 && file.attributes.iter().any(ntfs_admission::recognized_root_txf) {
                add_role(
                    &mut roles,
                    &mut role_ram,
                    "root:$TXF_DATA (not yet admitted for replacement)".into(),
                    scratch,
                )?;
            }
            objects.push(
                ordered_key(u64::try_from(object.path.len())?, object.record_number),
                &object,
            )?;
        }
        if let Some(aliases) = aliases {
            // Alias entries participate in the real destination collision
            // proof without becoming source objects or changing source counts.
            for ordinal in 0..aliases.len() {
                let alias = aliases.alias(ordinal)?;
                let folded = n2r_win32::shadow_names::conservative_path_key(&alias.path);
                let hash = Sha256::digest(folded.as_bytes());
                let bucket = u64::from_be_bytes(hash[..8].try_into()?);
                names.push(ordered_key(bucket, name_ordinal), &NameRow { folded })?;
                name_ordinal = name_ordinal.checked_add(1).context("Windows alias namespace count overflow")?;
            }
            aliases.require_source(source)?;
        }
        admission.validate_tree(files, directories, streams)?;
        let name_pin = names.finish()?;
        let name_store = SortedRecordStore::open(&name_pin, scratch)?;
        // Hashes only select bounded on-disk comparison buckets. Equality is
        // ALWAYS the full folded string; distinct hash-colliding names remain
        // valid, and no bucket-size cap or resident whole-name set exists.
        let mut start = 0u64;
        while start < name_store.len() {
            let prefix: [u8; 8] = name_store.key(start)?[..8].try_into()?;
            let mut end = start + 1;
            while end < name_store.len() && name_store.key(end)?[..8] == prefix {
                end += 1;
            }
            for a in start..end {
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
        let physical_pin = physical.finish()?;
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
        let object_pin = objects.finish()?;
        let objects = SortedRecordStore::open(&object_pin, scratch)?;
        ensure!(
            objects.len() == admission.objects()? && directories > 0,
            "complete projected object domain differs"
        );
        let object_count = usize::try_from(objects.len())?;
        let mut roots = 0u64;
        for ordinal in 0..objects.len() {
            let object: Object = objects.get(ordinal)?;
            ensure!(
                objects.key(ordinal)?
                    == ordered_key(u64::try_from(object.path.len())?, object.record_number),
                "projected object key or ordering differs"
            );
            if object.path.is_empty() {
                ensure!(
                    object.directory && object.record_number == 5,
                    "invalid projected root"
                );
                roots += 1;
            }
        }
        ensure!(roots == 1, "exactly one projected source root required");
        source.revalidate()?;
        native.revalidate()?;
        let value = Self {
            objects,
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
        value.objects.revalidate()?;
        Ok(value)
    }
    pub fn object_pin(&self) -> &RecordStorePin {
        self.objects.pin()
    }
    pub fn source_inspection_sha256(&self) -> &str {
        &self.source_inspection_sha256
    }

    /// Drop decode-only workspace once the caller has completed its semantic
    /// comparison, without replacing the held file owners with serialized pins.
    pub(crate) fn into_revalidation_owner(self) -> Result<ProjectionRevalidationOwner> {
        self.objects.revalidate()?;
        let Self {
            objects, scratch, ..
        } = self;
        Ok(ProjectionRevalidationOwner {
            objects,
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
        self.objects.revalidate()
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
        self.objects.revalidate()
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
