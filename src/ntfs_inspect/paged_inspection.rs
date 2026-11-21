//! Active complete paged source inspection. Metadata facts alone are not a
//! source certificate; the caller still owns source exclusion and native proof.
use super::*;
use super::{
    allocation_domain::{PagedAllocationReconciliation, reconcile_allocation_domain},
    namespace_capture::{NamespacePagePins, PagedNamespaceCapture, PagedNamespaceDomain},
    paged_files::{PagedRawFiles, file_key},
    paged_storage::{SourcePagePin, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
    security_input::{PagedSecurityCapture, PagedSecurityInput, SecurityCapturePins},
};
use std::{fs, path::Path};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInspectionPin {
    schema_version: u32,
    header: SourceHeader,
    budget: SourceMetadataBudget,
    files: RecordStorePin,
    extensions: SourcePagePin,
    assemblies: assembled_io::PagedAssemblyEvidence,
    namespace: NamespacePagePins,
    namespace_entries: u64,
    security_capture: SecurityCapturePins,
    security: crate::ntfs_security::PagedReconciliationPin,
    allocation: PagedAllocationReconciliation,
    blockers: RecordStorePin,
    /// Omitted for the historical complete conversion inspector. A preparation
    /// pin records absent content evidence and never grants source admission.
    #[serde(default, skip_serializing_if = "is_false")]
    preparation_only: bool,
    serialized_facts_grant_source_admission: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum InspectionPurpose {
    Conversion,
    WindowsConversion,
    Preparation,
    CachedFacts,
}
struct ClosedSource;
pub struct PagedInspection {
    files: PagedRawFiles,
    directories: PagedNamespaceDomain,
    security_input: PagedSecurityInput,
    security: crate::ntfs_security::PagedReconciliation,
    allocation: PagedAllocationReconciliation,
    assemblies: [SortedRecordStore; 3],
    ownership: [SortedRecordStore; 2],
    blockers: SortedRecordStore,
    pin: SourceInspectionPin,
    scratch: SourceScratch,
    // Runtime provenance, independently of the serialized diagnostic pin.
    purpose: InspectionPurpose,
    _closed: ClosedSource,
    // Baseline readers retain the actual newly accounted immutable owners.
    _fact_artifacts: Vec<crate::artifact_arena::ArtifactLease>,
    _fact_artifact_ram: Option<paged_storage::SourceRamLease>,
    // `canonical_sha256` of the pin above, which never changes once built.
    canonical: std::cell::OnceCell<String>,
}
impl PagedInspection {
    /// Historical FACTS only. Every ordinary page must already have a real
    /// adopted lease in the caller's auxiliary group. No source continuity,
    /// conversion purpose, admission, native witness or writer is issued.
    pub(crate) fn open_cached_facts(
        pin: &SourceInspectionPin,
        inspection_sha256: &str,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        ensure!(
            inspection_sha256.len() == 64
                && inspection_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && pin.schema_version == 1
                && !pin.preparation_only
                && !pin.serialized_facts_grant_source_admission
                && pin.header.inventory_complete,
            "complete pinned cached baseline metadata required"
        );
        let work = scratch.lease_ram(
            scratch
                .budget()
                .record_bytes
                .checked_mul(8)
                .context("cached-fact working RAM overflow")?,
        )?;
        let mut pages = std::collections::BTreeMap::<std::path::PathBuf, SourcePagePin>::new();
        fn leaves(
            value: serde_json::Value,
            out: &mut std::collections::BTreeMap<std::path::PathBuf, SourcePagePin>,
        ) -> Result<()> {
            match value {
                serde_json::Value::Object(map) => {
                    if map.contains_key("file_sha256")
                        && map.contains_key("logical_sha256")
                        && map.contains_key("wire_bytes")
                        && map.contains_key("chunk_bytes")
                    {
                        let pin: SourcePagePin =
                            serde_json::from_value(serde_json::Value::Object(map))?;
                        if let Some(old) = out.get(&pin.path) {
                            ensure!(old == &pin, "conflicting cached-fact page pins");
                        } else {
                            out.insert(pin.path.clone(), pin);
                        }
                        return Ok(());
                    }
                    for (_, value) in map {
                        leaves(value, out)?;
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        leaves(value, out)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        leaves(serde_json::to_value(pin)?, &mut pages)?;
        let retained = pages.values().try_fold(4096u64, |sum, pin| {
            sum.checked_add(8192)
                .and_then(|n| {
                    n.checked_add(
                        (pin.path.as_os_str().as_encoded_bytes().len() as u64).checked_mul(8)?,
                    )
                })
                .context("cached-fact retained owner RAM overflow")
        })?;
        let owners_ram = scratch.lease_ram(retained)?;
        let mut owners = Vec::new();
        owners.try_reserve_exact(pages.len())?;
        for pin in pages.values() {
            let owner = group.arena().retained_artifact(&pin.path)?;
            ensure!(
                owner.same_group(group)
                    && owner.sha256() == pin.file_sha256
                    && owner.wire_bytes() == pin.wire_bytes,
                "cached-fact page lacks its exact accounted owner"
            );
            owners.push(owner);
        }
        let bitmap = paged_storage::PagedMetadataRange::open(&pin.assemblies.mft_bitmap, scratch)?;
        let files = PagedRawFiles::from_live_bitmap(
            pin.header.clone(),
            &pin.files,
            Box::new(bitmap),
            &pin.extensions,
            scratch,
        )?;
        let directories = PagedNamespaceDomain::open(&pin.namespace, scratch)?;
        ensure!(
            crate::ntfs_namespace::reconcile_windows_domains(&files, &directories)?
                == pin.namespace_entries,
            "cached-fact namespace coverage differs"
        );
        let value = Self {
            files,
            directories,
            security_input: PagedSecurityInput::open(&pin.security_capture, scratch)?,
            security: crate::ntfs_security::PagedReconciliation::open_cached(
                &pin.security,
                scratch,
            )?,
            allocation: pin.allocation.clone(),
            assemblies: [
                SortedRecordStore::open(&pin.assemblies.assemblies, scratch)?,
                SortedRecordStore::open(&pin.assemblies.consumed_extensions, scratch)?,
                SortedRecordStore::open(&pin.assemblies.physical_extensions, scratch)?,
            ],
            ownership: [
                SortedRecordStore::open(&pin.allocation.physical_ownership, scratch)?,
                SortedRecordStore::open(&pin.allocation.logical_ownership, scratch)?,
            ],
            blockers: SortedRecordStore::open(&pin.blockers, scratch)?,
            pin: pin.clone(),
            scratch: scratch.clone(),
            purpose: InspectionPurpose::CachedFacts,
            _closed: ClosedSource,
            _fact_artifacts: owners,
            _fact_artifact_ram: Some(owners_ram),
            canonical: std::cell::OnceCell::new(),
        };
        ensure!(
            value.canonical_sha256()? == inspection_sha256,
            "cached-fact canonical source pin differs"
        );
        value.revalidate()?;
        drop(work);
        Ok(value)
    }
    pub(crate) fn is_cached_facts(&self) -> bool {
        self.purpose == InspectionPurpose::CachedFacts
    }
    /// Cold metadata is promoted only by a NEW SDK byte-continuity proof bound
    /// to the actual fresh source FileObject. Saved inventory flags are not an
    /// issuer and this path does not deserialize any source/native admission.
    pub(crate) fn open_cached_exact(
        pin: &SourceInspectionPin,
        source: &n2r_win32::GeneralFrozenPartition,
        continuity: &n2r_win32::SourceCacheContinuity,
        origin: [u8; 32],
        scratch: &SourceScratch,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<Self> {
        continuity.require_source(source, continuity.inspection_sha256(), origin, events)?;
        let budget = scratch.budget();
        ensure!(
            pin.schema_version == 1
                && !pin.preparation_only
                && !pin.serialized_facts_grant_source_admission
                && pin.header.inventory_complete
                && pin.budget.ram_bytes == budget.ram_bytes
                && pin.budget.scratch_bytes == budget.scratch_bytes
                && pin.budget.page_bytes == budget.page_bytes
                && pin.budget.record_bytes == budget.record_bytes
                && source.binding().layout_profile
                    == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows,
            "cached raw source schema, purpose or original wire bounds differ"
        );
        let bitmap = paged_storage::PagedMetadataRange::open(&pin.assemblies.mft_bitmap, scratch)?;
        let files = PagedRawFiles::from_live_bitmap(
            pin.header.clone(),
            &pin.files,
            Box::new(bitmap),
            &pin.extensions,
            scratch,
        )?;
        let directories = PagedNamespaceDomain::open(&pin.namespace, scratch)?;
        ensure!(
            crate::ntfs_namespace::reconcile_windows_domains(&files, &directories)?
                == pin.namespace_entries,
            "cached raw namespace coverage differs"
        );
        let security_input = PagedSecurityInput::open(&pin.security_capture, scratch)?;
        let security =
            crate::ntfs_security::PagedReconciliation::open_cached(&pin.security, scratch)?;
        let value = Self {
            files,
            directories,
            security_input,
            security,
            allocation: pin.allocation.clone(),
            assemblies: [
                SortedRecordStore::open(&pin.assemblies.assemblies, scratch)?,
                SortedRecordStore::open(&pin.assemblies.consumed_extensions, scratch)?,
                SortedRecordStore::open(&pin.assemblies.physical_extensions, scratch)?,
            ],
            ownership: [
                SortedRecordStore::open(&pin.allocation.physical_ownership, scratch)?,
                SortedRecordStore::open(&pin.allocation.logical_ownership, scratch)?,
            ],
            blockers: SortedRecordStore::open(&pin.blockers, scratch)?,
            pin: pin.clone(),
            scratch: scratch.clone(),
            purpose: InspectionPurpose::WindowsConversion,
            _closed: ClosedSource,
            _fact_artifacts: Vec::new(),
            _fact_artifact_ram: None,
            canonical: std::cell::OnceCell::new(),
        };
        ensure!(
            value.canonical_sha256()? == hex::encode(continuity.inspection_sha256()),
            "cached raw canonical source pin differs from actual byte-continuity proof"
        );
        for ordinal in 0..value.file_count() {
            let file = value.file_shared(ordinal)?;
            if (12..16).contains(&file.record_number)
                && file.names.is_empty()
                && file.attributes.is_empty()
                && !file.is_directory
                && file.hard_link_count == 0
            {
                continue;
            }
            let binding = value
                .security
                .find_binding(file.record_number)?
                .context("cached raw file lacks its security binding")?;
            let id = file
                .standard_information
                .as_ref()
                .and_then(|si| si.security_id)
                .filter(|id| *id != 0);
            ensure!(
                binding.sequence_number == file.sequence_number && binding.security_id == id,
                "cached raw file/security binding differs"
            );
        }
        value.revalidate()?;
        continuity.require_source(source, continuity.inspection_sha256(), origin, events)?;
        Ok(value)
    }
    /// Complete planning metadata without separate logical DATA hashing. All
    /// source metadata, namespace, security and allocation joins still close.
    /// This runtime owner is explicitly excluded from source admission; the
    /// converter must collect a new frozen conversion inspection afterwards.
    pub(crate) fn inspect_preparation_with_scratch<R: Read + Seek>(
        reader: &mut R,
        length: u64,
        resources: n2r_win32::tree_resources::ResourceBudget,
        root: &Path,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        inspect_paged_internal(
            reader,
            length,
            resources,
            crate::verification_policy::VerificationPolicy::ExtentIdentityV1,
            root,
            scratch,
            InspectionPurpose::Preparation,
        )
    }
    pub fn pin(&self) -> &SourceInspectionPin {
        &self.pin
    }
    pub fn budget(&self) -> SourceMetadataBudget {
        self.scratch.budget()
    }
    pub(crate) fn release_inventory_resident_cache(&mut self) {
        self.files.release_inventory_resident_cache();
    }
    /// Whether this is the inspection made of a volume that is still in
    /// use: complete in its metadata, with nothing read of any stream's
    /// contents, and never a source a conversion is admitted from.
    pub(crate) fn is_preparation_only(&self) -> bool {
        self.pin.preparation_only
    }
    pub(crate) fn is_windows_conversion(&self) -> bool {
        self.purpose == InspectionPurpose::WindowsConversion
    }
    pub fn security(&self) -> &crate::ntfs_security::PagedReconciliation {
        &self.security
    }
    pub fn directories(&self) -> &impl RootDirectoryDomain {
        &self.directories
    }
    pub fn allocation(&self) -> &PagedAllocationReconciliation {
        &self.allocation
    }
    pub(crate) fn allocation_cursor(
        &self,
        partition_bytes: u64,
    ) -> Result<allocation_domain::AllocationCursor<'_>> {
        allocation_domain::AllocationCursor::new(
            &self.ownership[0],
            &self.header().geometry,
            &self.allocation,
            partition_bytes,
        )
    }
    pub fn allocated_bytes_in(
        &self,
        offset: u64,
        length: u64,
        partition_bytes: u64,
    ) -> Result<u64> {
        allocation_domain::allocated_bytes_in(
            &self.ownership[0],
            &self.header().geometry,
            &self.allocation,
            offset,
            length,
            partition_bytes,
        )
    }
    pub fn require_allocated_range(
        &self,
        offset: u64,
        length: u64,
        partition_bytes: u64,
    ) -> Result<()> {
        allocation_domain::require_allocated_range(
            &self.ownership[0],
            &self.header().geometry,
            &self.allocation,
            offset,
            length,
            partition_bytes,
        )
    }
    pub fn is_free_granule(&self, offset: u64, partition_bytes: u64) -> Result<bool> {
        allocation_domain::is_free_granule(
            &self.ownership[0],
            &self.header().geometry,
            &self.allocation,
            offset,
            partition_bytes,
        )
    }
    pub(crate) fn mft_bitmap_pin(&self) -> &SourcePagePin {
        &self.pin.assemblies.mft_bitmap
    }
    pub(crate) fn assembly_for_record(
        &self,
        record: u64,
    ) -> Result<Option<crate::ntfs_attribute_list::Assembly>> {
        self.assemblies[0].find(file_key(record))
    }
    /// Whether the record's attributes were assembled from an attribute
    /// list. Only the store's keys are searched; no assembly is decoded.
    pub(crate) fn has_attribute_list_assembly(&self, record: u64) -> Result<bool> {
        Ok(self.assemblies[0].find_ordinal(file_key(record))?.is_some())
    }
    /// Bounded directory metadata from the already authenticated stores. No
    /// row is decoded or allocated before its actual wire length is known.
    pub(crate) fn checked_record_wire_sizes(&self, record: u64) -> Result<(u64, Option<u64>)> {
        let file = self
            .files
            .record_wire_bytes(record)?
            .with_context(|| format!("source FILE {record} absent from complete domain"))?;
        let assembly = self.assemblies[0]
            .find_ordinal(file_key(record))?
            .map(|ordinal| self.assemblies[0].record_bytes(ordinal))
            .transpose()?;
        Ok((file, assembly))
    }
    /// The workspace for one decoded FILE record and what is made from it:
    /// thirty-two times the bytes its row, its attribute-list assembly and
    /// one file record take in the stores, and a megabyte. A caller that
    /// looks a record up (`find_record` hands it back decoded and pays for
    /// nothing) leases this for as long as it holds the record, instead of
    /// a workspace for the largest row the budget admits.
    pub(crate) fn record_workspace(&self, number: u64) -> Result<u64> {
        let (file, assembly) = self.checked_record_wire_sizes(number)?;
        file.checked_mul(32)
            .and_then(|n| n.checked_add(assembly.unwrap_or(0).checked_mul(32)?))
            .and_then(|n| {
                n.checked_add(u64::from(self.header().geometry.file_record_size).checked_mul(32)?)
            })
            .and_then(|n| n.checked_add(1024 * 1024))
            .with_context(|| format!("FILE {number} checked-row workspace overflow"))
    }
    #[track_caller]
    pub(crate) fn lease_working_ram(
        &self,
        bytes: u64,
    ) -> Result<super::paged_storage::SourceRamLease> {
        self.scratch.lease_ram(bytes)
    }
    pub(crate) fn metadata_scratch(&self) -> SourceScratch {
        self.scratch.clone()
    }
    pub fn blocker_count(&self) -> u64 {
        self.blockers.len()
    }
    pub fn blocker(&self, ordinal: u64) -> Result<InspectionBlocker> {
        self.blockers.get(ordinal)
    }
    /// The digest of this inspection's pinned summary. The summary is fixed
    /// when the inspection is built, and serializing it costs milliseconds;
    /// it is asked for on every stream opened and every object admitted, so
    /// it is computed once.
    pub fn canonical_sha256(&self) -> Result<String> {
        if let Some(known) = self.canonical.get() {
            return Ok(known.clone());
        }
        let computed = self.compute_canonical_sha256()?;
        Ok(self.canonical.get_or_init(|| computed).clone())
    }
    fn compute_canonical_sha256(&self) -> Result<String> {
        struct Hash {
            hash: Sha256,
            bytes: u64,
            maximum: u64,
        }
        impl Write for Hash {
            fn write(&mut self, input: &[u8]) -> io::Result<usize> {
                let n = self
                    .bytes
                    .checked_add(input.len() as u64)
                    .filter(|n| *n <= self.maximum)
                    .ok_or_else(|| {
                        io::Error::other("source root manifest exceeds semantic resources")
                    })?;
                self.hash.update(input);
                self.bytes = n;
                Ok(input.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut output = Hash {
            hash: Sha256::new(),
            bytes: 0,
            maximum: self.budget().scratch_bytes / 2,
        };
        output.hash.update(b"ntfs2refs-paged-raw-source-v1\0");
        serde_json::to_writer(&mut output, &self.pin)?;
        Ok(hex::encode(output.hash.finalize()))
    }
    pub fn require_paged_source(
        &self,
        expected: n2r_win32::tree_resources::MetadataPageBudget,
        semantic_bytes: u64,
    ) -> Result<()> {
        let actual = self.budget().page_budget()?;
        ensure!(
            matches!(
                self.purpose,
                InspectionPurpose::Conversion | InspectionPurpose::WindowsConversion
            ) && !self.pin.preparation_only
                && self.pin.schema_version == 1
                && self.files.header().inventory_complete
                && !self.pin.serialized_facts_grant_source_admission
                && !self.scratch.is_poisoned()
                && self.scratch.used_bytes() <= self.budget().scratch_bytes
                && semantic_bytes == self.budget().scratch_bytes / 2
                && actual.max_page_bytes == expected.max_page_bytes
                && actual.max_records_per_page == expected.max_records_per_page
                && actual.max_records == expected.max_records
                && actual.max_pages == expected.max_pages
                && actual.max_file_bytes == expected.max_file_bytes,
            "actual complete source owner differs from admitted resource pages"
        );
        self.revalidate()?;
        let _ = self.canonical_sha256()?;
        Ok(())
    }
}
impl RootFileDomain for PagedInspection {
    fn header(&self) -> &SourceHeader {
        self.files.header()
    }
    fn file_count(&self) -> u64 {
        self.files.file_count()
    }
    fn file(&self, ordinal: u64) -> Result<FileInventory> {
        self.files.file(ordinal)
    }
    fn with_file<T>(
        &self,
        ordinal: u64,
        read: impl FnOnce(&FileInventory) -> Result<T>,
    ) -> Result<T> {
        self.files.with_file(ordinal, read)
    }
    fn file_shared(&self, ordinal: u64) -> Result<std::sync::Arc<FileInventory>> {
        self.files.file_shared(ordinal)
    }
    fn find_record(&self, number: u64, sequence: Option<u16>) -> Result<Option<FileInventory>> {
        self.files.find_record(number, sequence)
    }
    fn find_record_shared(
        &self,
        number: u64,
        sequence: Option<u16>,
    ) -> Result<Option<std::sync::Arc<FileInventory>>> {
        self.files.find_record_shared(number, sequence)
    }
    fn with_record<T>(
        &self,
        number: u64,
        sequence: Option<u16>,
        read: impl FnOnce(&FileInventory) -> Result<T>,
    ) -> Result<Option<T>> {
        self.files.with_record(number, sequence, read)
    }
    fn allocated_record(&self, number: u64) -> Result<bool> {
        self.files.allocated_record(number)
    }
    fn extension_record(&self, number: u64) -> Result<bool> {
        self.files.extension_record(number)
    }
    fn revalidate(&self) -> Result<()> {
        self.files.revalidate()?;
        self.directories.revalidate()?;
        self.security_input.revalidate()?;
        self.security.revalidate()?;
        self.blockers.revalidate()?;
        for store in self.assemblies.iter().chain(self.ownership.iter()) {
            store.revalidate()?;
        }
        Ok(())
    }
}
fn blocker_key(ordinal: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&ordinal.to_be_bytes());
    key
}
fn emit_blocker(
    writer: &mut SortedRecordWriter,
    count: &mut u64,
    item: &InspectionBlocker,
) -> Result<()> {
    writer.push(blocker_key(*count), item)?;
    *count = count.checked_add(1).context("blocker count overflow")?;
    Ok(())
}
fn carrier(geometry: &NtfsGeometry, mft: u64, budget: SourceMetadataBudget) -> NtfsInspection {
    NtfsInspection {
        schema_version: 2,
        geometry: geometry.clone(),
        volume_version: None,
        volume_flags: None,
        dirty: None,
        mft_record_count: mft,
        records_scanned: 0,
        allocated_clusters: None,
        free_clusters: None,
        allocation_reconciliation: None,
        namespace_reconciliation: None,
        security_reconciliation: None,
        files: Vec::new(),
        attribute_assemblies: Vec::new(),
        blockers: Vec::new(),
        inventory_complete: false,
        inventory_memory_bytes: 0,
        inventory_memory_limit_bytes: budget.ram_bytes,
        stream_hash_bytes: 0,
        stream_hash_limit_bytes: u64::MAX,
    }
}
fn header(report: &NtfsInspection, complete: bool, hashed: u64) -> SourceHeader {
    SourceHeader {
        schema_version: 2,
        geometry: report.geometry.clone(),
        volume_version: report.volume_version.clone(),
        volume_flags: report.volume_flags,
        dirty: report.dirty,
        mft_record_count: report.mft_record_count,
        records_scanned: report.records_scanned,
        allocated_clusters: report.allocated_clusters,
        free_clusters: report.free_clusters,
        inventory_complete: complete,
        stream_hash_bytes: hashed,
    }
}

/// Preserve the normal inspector's metadata support diagnostics without
/// manufacturing a content digest or opening any logical DATA range.
fn validate_preparation_stream_metadata(
    file: &mut FileInventory,
    geometry: &NtfsGeometry,
    report: &mut NtfsInspection,
    budget: &mut ReportBudget,
) -> Result<()> {
    let has_attribute_list = file.attributes.iter().any(|a| a.type_code == 0x20);
    for stream in &mut file.streams {
        ensure!(
            stream.logical_hash_status == LogicalHashStatus::NotComputed
                && stream.logical_sha256.is_none(),
            "preparation stream unexpectedly contains logical-content evidence"
        );
        let attribute = file
            .attributes
            .iter()
            .find(|a| a.type_code == 0x80 && a.name_utf16 == stream.name_utf16)
            .context("preparation DATA attribute absent")?;
        if let Some(status) = logical_hash_metadata_status(
            attribute,
            geometry,
            has_attribute_list,
            file.base_file_reference != 0,
            file.record_number,
        ) {
            stream.logical_hash_status = status;
            blocker(
                report,
                budget,
                "logical_stream_hash_unavailable",
                format!(
                    "DATA attribute {} has no complete logical hash: {status:?}",
                    attribute.instance
                ),
                Some(file.record_number),
            )?;
        } else if attribute.resident {
            // The resident value was bounded and parsed inside its FILE
            // record. Its fingerprint is retained as metadata, never promoted
            // to a separately observed complete logical stream digest here.
            ensure!(
                attribute.initialized_size == attribute.logical_size,
                "resident DATA size is inconsistent"
            );
        } else {
            validate_stream_mapping(attribute, geometry)?;
        }
    }
    Ok(())
}

/// Every physical record and global join closes before a complete owner can be
/// returned. The legacy Vec inspector is never called or used as a fallback.
pub fn inspect_paged_with_policy<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    resources: n2r_win32::tree_resources::ResourceBudget,
    policy: crate::verification_policy::VerificationPolicy,
    root: &Path,
) -> Result<PagedInspection> {
    let budget = SourceMetadataBudget::from_resource_budget(resources)?;
    let scratch = SourceScratch::new(budget)?;
    inspect_paged_with_scratch(reader, length, resources, policy, root, &scratch)
}

/// The recorder, inspector and later source-range proofs share one aggregate
/// owner. The historical entry point simply creates this owner and delegates.
pub fn inspect_paged_with_scratch<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    resources: n2r_win32::tree_resources::ResourceBudget,
    policy: crate::verification_policy::VerificationPolicy,
    root: &Path,
    scratch: &SourceScratch,
) -> Result<PagedInspection> {
    inspect_paged_internal(
        reader,
        length,
        resources,
        policy,
        root,
        scratch,
        InspectionPurpose::Conversion,
    )
}

/// Observational path scope selected by the actual frozen source layout.
/// It does not cover target alias preservation or grant write authority.
pub(crate) fn inspect_paged_with_layout_scope<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    resources: n2r_win32::tree_resources::ResourceBudget,
    policy: crate::verification_policy::VerificationPolicy,
    root: &Path,
    scratch: &SourceScratch,
    layout: n2r_win32::general_layout::GeneralDiskLayoutProfile,
) -> Result<PagedInspection> {
    let purpose = if layout == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows {
        InspectionPurpose::WindowsConversion
    } else {
        InspectionPurpose::Conversion
    };
    inspect_paged_internal(reader, length, resources, policy, root, scratch, purpose)
}

/// The raw file rows of the MFT scan, serialized on a worker thread while
/// the scan reads and parses the records after them (#250): serializing
/// each row was about a quarter of the scan's single thread. Rows are
/// written to the store in record order, as the scan made them; a row the
/// memory for which (its inventory and its JSON, as spare working RAM)
/// cannot be had, and every row of a scan without the worker's own memory,
/// is written by the scan's thread after the rows before it, as before.
struct RowsAhead {
    jobs: Option<std::sync::mpsc::SyncSender<FileInventory>>,
    done: std::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    worker: Option<std::thread::JoinHandle<()>>,
    in_flight: std::collections::VecDeque<(u64, super::paged_storage::SourceRamLease)>,
    scratch: SourceScratch,
    row_bytes: u64,
    _workspace: Option<super::paged_storage::SourceRamLease>,
}
impl RowsAhead {
    /// Rows handed to the worker and not yet written, at most.
    const IN_FLIGHT: usize = 64;
    /// The worker's thread and its serializer's buffer, beside the rows.
    const WORKSPACE_BYTES: u64 = 2 * 1024 * 1024;
    fn new(scratch: &SourceScratch, row_bytes: u64) -> Self {
        let (jobs, received) = std::sync::mpsc::sync_channel::<FileInventory>(Self::IN_FLIGHT);
        let (finished, done) = std::sync::mpsc::channel();
        let workspace = scratch
            .lease_ram_if_room(Self::WORKSPACE_BYTES.saturating_add(row_bytes))
            .ok();
        let worker = workspace.as_ref().and_then(|_| {
            std::thread::Builder::new()
                .name("raw-file-rows".into())
                .spawn(move || {
                    let _sampled = n2r_win32::stack_sampler::helper();
                    for inventory in received {
                        let json = serde_json::to_vec(&inventory).map_err(|error| error.to_string());
                        drop(inventory);
                        if finished.send(json).is_err() {
                            break;
                        }
                    }
                })
                .ok()
        });
        Self {
            jobs: worker.as_ref().map(|_| jobs),
            done,
            worker,
            in_flight: std::collections::VecDeque::new(),
            scratch: scratch.clone(),
            row_bytes,
            _workspace: workspace,
        }
    }
    fn push(
        &mut self,
        writer: &mut SortedRecordWriter,
        number: u64,
        inventory: FileInventory,
    ) -> Result<()> {
        self.write_ready(writer, false)?;
        let lease = self.jobs.as_ref().and_then(|_| {
            file_heap_bytes(&inventory)
                .ok()
                .and_then(|heap| heap.checked_add(self.row_bytes))
                .and_then(|bytes| self.scratch.lease_ram_if_room(bytes).ok())
        });
        match (lease, &self.jobs) {
            (Some(lease), Some(jobs)) => {
                jobs.send(inventory)
                    .map_err(|_| anyhow::anyhow!("the raw file row worker stopped"))?;
                self.in_flight.push_back((number, lease));
                Ok(())
            }
            _ => {
                self.write_ready(writer, true)?;
                writer.push(file_key(number), &inventory)
            }
        }
    }
    /// Writes the rows the worker has finished, in order; with `wait`,
    /// every row handed to it.
    fn write_ready(&mut self, writer: &mut SortedRecordWriter, wait: bool) -> Result<()> {
        while let Some(&(number, _)) = self.in_flight.front() {
            let json = if wait {
                self.done
                    .recv()
                    .map_err(|_| anyhow::anyhow!("the raw file row worker stopped"))?
            } else {
                match self.done.try_recv() {
                    Ok(json) => json,
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        anyhow::bail!("the raw file row worker stopped")
                    }
                }
            };
            let json = json.map_err(anyhow::Error::msg)?;
            writer.push_serialized(file_key(number), &json)?;
            self.in_flight.pop_front();
        }
        Ok(())
    }
    fn finish(mut self, writer: &mut SortedRecordWriter) -> Result<()> {
        self.write_ready(writer, true)?;
        self.jobs.take();
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("the raw file row worker panicked"))?;
        }
        Ok(())
    }
}
impl Drop for RowsAhead {
    fn drop(&mut self) {
        // Ends the worker on every path, the scan's errors among them.
        self.jobs.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn inspect_paged_internal<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    resources: n2r_win32::tree_resources::ResourceBudget,
    policy: crate::verification_policy::VerificationPolicy,
    root: &Path,
    scratch: &SourceScratch,
    purpose: InspectionPurpose,
) -> Result<PagedInspection> {
    let preparation_only = purpose == InspectionPurpose::Preparation;
    let budget = SourceMetadataBudget::from_resource_budget(resources)?;
    let actual = scratch.budget();
    ensure!(
        actual.ram_bytes == budget.ram_bytes
            && actual.scratch_bytes == budget.scratch_bytes
            && actual.page_bytes == budget.page_bytes
            && actual.record_bytes == budget.record_bytes
            && actual.merge_fan_in == budget.merge_fan_in,
        "shared source scratch resource owner differs"
    );
    let scratch = scratch.clone();
    ensure!(
        !root.exists(),
        "fresh ordinary source-page directory required"
    );
    fs::create_dir(root)?;
    for name in ["mft", "namespace", "security", "allocation", "roles"] {
        fs::create_dir(root.join(name))?;
    }
    let mut boot = [0u8; 512];
    read_at(reader, 0, &mut boot, length)?;
    let geometry = inspect_boot_sector(&boot, length)?;
    let native_parser =
        ntfs::Ntfs::new(reader).context("independent NTFS geometry parser refused source")?;
    ensure!(
        native_parser.cluster_size() == geometry.cluster_size
            && native_parser.file_record_size() == geometry.file_record_size,
        "independent NTFS geometry interpretations disagree"
    );
    drop(native_parser);
    let mft_bootstrap::PagedBootstrap {
        record: bootstrap_record,
        data: mft_data,
        bitmap,
        record_count,
        base_raw_sha256,
        resolver: mut resolver,
    } = mft_bootstrap::read_paged(reader, &geometry, &root.join("mft"), &scratch)?;
    let mut bootstrap_record = Some(bootstrap_record);
    let mut report = carrier(&geometry, record_count, budget);
    let mut files_writer =
        SortedRecordWriter::new(&root.join("raw-files"), *b"N2RFILE1", &scratch)?;
    let mut blockers = SortedRecordWriter::new(&root.join("blockers"), *b"N2RBLKR1", &scratch)?;
    let mut blocker_count = 0u64;
    let mut extension_writer =
        scratch.writer(&root.join("physical-extension-bits.pages"), *b"N2REXTB1")?;
    let mut namespace = PagedNamespaceCapture::new(&root.join("namespace"), &scratch)?;
    let mut security = PagedSecurityCapture::new(&root.join("security"), &scratch)?;
    let mut hash_budget = HashBudget {
        limit: u64::MAX,
        used: 0,
    };
    n2r_win32::perf::step("NTFS: scan MFT records");
    let (mut root_seen, mut volume_bitmap, mut ext_byte) = (false, None, 0u8);
    let _working = scratch.lease_ram(
        budget
            .record_bytes
            .checked_mul(8)
            .and_then(|n| {
                n.checked_add(if preparation_only {
                    0
                } else {
                    LARGE_STREAM_HASH_BYTES as u64 + STREAM_HASH_BUFFER_BYTES as u64
                })
            })
            .context("raw current-row RAM overflow")?,
    )?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(geometry.file_record_size as usize)?;
    raw.resize(geometry.file_record_size as usize, 0);
    let mut bitmap_buf = [0u8; 4096];
    let mut bitmap_block = u64::MAX;
    let bitmap_len = bitmap.byte_len();
    let mut rows_ahead = RowsAhead::new(&scratch, budget.record_bytes);
    for number in 0..record_count {
        let byte_offset = number / 8;
        let block = byte_offset / bitmap_buf.len() as u64;
        if block != bitmap_block {
            let start = block * bitmap_buf.len() as u64;
            let len = (bitmap_len - start).min(bitmap_buf.len() as u64) as usize;
            bitmap.read_exact_at(start, &mut bitmap_buf[..len])?;
            bitmap_block = block;
        }
        let allocated_byte = bitmap_buf[(byte_offset % bitmap_buf.len() as u64) as usize];
        if allocated_byte & (1 << (number % 8)) != 0 {
            resolver.read_physical_record(reader, number, &mut raw)?;
            // Declared before the record so the assembly lease drops only
            // after the assembled record and its resident values are gone.
            let mut _assembly_ram = None;
            let mut record = parse_record(raw.clone(), &geometry)
                .with_context(|| format!("parsing MFT record {number}"))?;
            ensure!(
                record.flags & 1 != 0,
                "MFT bitmap marks an unallocated physical header"
            );
            report.records_scanned = report
                .records_scanned
                .checked_add(1)
                .context("physical MFT count overflow")?;
            if record.base != 0 {
                ext_byte |= 1 << (number % 8);
                resolver.observe_physical_extension(number, &raw, &record)?;
            } else {
                if number == 0 {
                    ensure!(
                        hex::encode(Sha256::digest(&raw)) == base_raw_sha256,
                        "MFT bootstrap changed before canonical scan"
                    );
                    record = bootstrap_record
                        .take()
                        .context("canonical MFT bootstrap reused")?;
                } else {
                    _assembly_ram = resolver.resolve(reader, number, &raw, &mut record)?;
                }
                let mut row_budget = ReportBudget {
                    limit: budget
                        .record_bytes
                        .checked_mul(8)
                        .context("record RAM overflow")?,
                    used: 0,
                };
                if number == 5 {
                    ensure!(record.flags & 2 != 0, "root record is not a directory");
                    root_seen = true;
                }
                if number == 3 {
                    let value =
                        read_small_attribute(reader, unnamed(&record, 0x70)?, &geometry, 1024)?;
                    ensure!(value.len() >= 12, "truncated volume information");
                    let flags = u16le(&value, 10)?;
                    report.volume_version = Some(format!("{}.{}", value[8], value[9]));
                    report.volume_flags = Some(flags);
                    report.dirty = Some(flags & 1 != 0);
                    if flags != 0 {
                        blocker(
                            &mut report,
                            &mut row_budget,
                            "volume_state_flags",
                            format!("Volume flags {flags:#06x} require native validation"),
                            Some(number),
                        )?;
                    }
                    if value[8] != 3 || value[9] != 1 {
                        blocker(
                            &mut report,
                            &mut row_budget,
                            "unsupported_ntfs_version",
                            "Only NTFS3.1 is supported",
                            Some(number),
                        )?;
                    }
                }
                if number == 6 {
                    let value = unnamed(&record, 0x80)?;
                    require_bitmap_bytes(&value.report, geometry.total_clusters.div_ceil(8))?;
                    volume_bitmap = Some(value.clone());
                }
                let mut inventory = inventory_record(
                    reader,
                    &geometry,
                    record,
                    number,
                    &mut report,
                    &mut row_budget,
                    &mut hash_budget,
                    policy,
                    preparation_only,
                    |reader, record| {
                        namespace.observe(reader, record, number, &geometry)?;
                        security.observe(reader, record, number, &geometry)?;
                        Ok(())
                    },
                )?;
                if preparation_only {
                    validate_preparation_stream_metadata(
                        &mut inventory,
                        &geometry,
                        &mut report,
                        &mut row_budget,
                    )?;
                }
                ensure!(
                    file_heap_bytes(&inventory)? <= row_budget.limit,
                    "current source row exceeds resource RAM"
                );
                rows_ahead.push(&mut files_writer, number, inventory)?;
                for item in report.blockers.drain(..) {
                    emit_blocker(&mut blockers, &mut blocker_count, &item)?;
                }
            }
        }
        if number % 8 == 7 || number + 1 == record_count {
            extension_writer.write_all(&[ext_byte])?;
            ext_byte = 0;
        }
    }
    rows_ahead.finish(&mut files_writer)?;
    drop(mft_data);
    drop(bootstrap_record);
    n2r_win32::perf::step("NTFS: finish raw file store");
    let extension_pin = extension_writer.finish()?;
    let file_pin = files_writer.finish()?;
    ensure!(
        root_seen && report.volume_flags.is_some(),
        "allocated root or volume information absent"
    );
    let volume_bitmap = volume_bitmap.context("allocated volume bitmap absent")?;
    let summary = {
        let mut bits = AttributeBitmapReader {
            reader,
            attribute: &volume_bitmap,
            geometry: &geometry,
            length: geometry.total_clusters.div_ceil(8),
            position: 0,
        };
        ntfs_allocation::summarize_stream(geometry.total_clusters, &mut bits)?
    };
    report.allocated_clusters = Some(summary.allocated_clusters);
    report.free_clusters = Some(summary.free_clusters);
    n2r_win32::perf::step("NTFS: open raw file store");
    let mut files = PagedRawFiles::from_live_bitmap(
        header(&report, false, hash_budget.used),
        &file_pin,
        bitmap,
        &extension_pin,
        &scratch,
    )?;
    n2r_win32::perf::step("NTFS: resolve attribute lists and classify roles");
    let assemblies = resolver.finish(&files)?;
    super::paged_roles::classify(
        &mut files,
        &root.join("roles"),
        &scratch,
        purpose == InspectionPurpose::WindowsConversion,
        |item| emit_blocker(&mut blockers, &mut blocker_count, &item),
    )?;
    n2r_win32::perf::step("NTFS: finish and reconcile namespace");
    let directories = namespace.finish()?;
    let namespace_entries = if purpose == InspectionPurpose::WindowsConversion {
        crate::ntfs_namespace::reconcile_windows_domains(&files, &directories)?
    } else {
        crate::ntfs_namespace::reconcile_domains(&files, &directories)?
    };
    n2r_win32::perf::step("NTFS: reconcile allocation");
    let allocation = {
        let mut bits = AttributeBitmapReader {
            reader,
            attribute: &volume_bitmap,
            geometry: &geometry,
            length: geometry.total_clusters.div_ceil(8),
            position: 0,
        };
        reconcile_allocation_domain(
            &files,
            &assemblies,
            &mut bits,
            &summary,
            &root.join("allocation"),
            &scratch,
        )?
    };
    ensure!(
        allocation.status == AllocationReconciliationStatus::ConsistentRawModel,
        "complete raw allocation closure absent"
    );
    n2r_win32::perf::step("NTFS: decide stream evidence and rewrite file store");
    if policy.is_fast() && !preparation_only {
        let mut output =
            SortedRecordWriter::new(&root.join("hashed-files"), *b"N2RFILE1", &scratch)?;
        for ordinal in 0..files.file_count() {
            let _working = scratch.lease_ram(
                budget
                    .record_bytes
                    .checked_mul(8)
                    .and_then(|n| {
                        n.checked_add(
                            LARGE_STREAM_HASH_BYTES as u64 + STREAM_HASH_BUFFER_BYTES as u64,
                        )
                    })
                    .context("raw hashing working memory overflow")?,
            )?;
            let mut file = files.file(ordinal)?;
            for index in 0..file.streams.len() {
                if file.streams[index].logical_hash_status != LogicalHashStatus::NotComputed {
                    continue;
                }
                let eligible = if purpose == InspectionPurpose::WindowsConversion {
                    crate::ntfs_attestation::extent_identity_stream_request_windows_domain(
                        &files,
                        &file,
                        &file.streams[index],
                    )?
                } else {
                    crate::ntfs_attestation::extent_identity_stream_request_domain(
                        &files,
                        &file,
                        &file.streams[index],
                        true,
                        true,
                    )?
                }
                .is_some();
                let (status, digest) = if eligible {
                    (LogicalHashStatus::NotReadExtentIdentityV1, None)
                } else {
                    let attribute = file
                        .attributes
                        .iter()
                        .find(|a| {
                            a.type_code == 0x80 && a.name_utf16 == file.streams[index].name_utf16
                        })
                        .context("deferred canonical DATA attribute absent")?
                        .clone();
                    hash_stream(
                        reader,
                        &Attribute {
                            report: attribute,
                            resident_value: None,
                        },
                        &geometry,
                        &mut hash_budget,
                        false,
                        false,
                        file.record_number,
                    )?
                };
                if !matches!(
                    status,
                    LogicalHashStatus::Complete | LogicalHashStatus::NotReadExtentIdentityV1
                ) {
                    emit_blocker(
                        &mut blockers,
                        &mut blocker_count,
                        &InspectionBlocker {
                            code: "logical_stream_hash_unavailable".into(),
                            message: format!(
                                "Deferred DATA has no supported source evidence: {status:?}"
                            ),
                            file_record_number: Some(file.record_number),
                        },
                    )?;
                }
                file.streams[index].logical_hash_status = status;
                file.streams[index].logical_sha256 = digest;
            }
            output.push(file_key(file.record_number), &file)?;
        }
        files.replace_files(&output.finish()?)?;
    }
    n2r_win32::perf::step("NTFS: reconcile security");
    let security_input = security.finish()?;
    let security = crate::ntfs_security::reconcile_paged(
        &security_input,
        &files,
        &root.join("security"),
        &scratch,
    )?;
    ensure!(
        !preparation_only || hash_budget.used == 0,
        "preparation inspection unexpectedly hashed logical DATA"
    );
    n2r_win32::perf::step("NTFS: close inspection");
    files.set_header(header(&report, true, hash_budget.used))?;
    for (code, message) in [
        (
            "security_descriptors_unresolved",
            "Raw security reconciliation does not replace native source security",
        ),
        (
            "directory_indexes_unverified",
            "Raw namespace reconciliation does not replace native enumeration",
        ),
        (
            "allocation_ownership_unverified",
            "Raw allocation reconciliation does not replace native allocation proof",
        ),
        (
            "journal_state_unverified",
            "LogFile restart and clean-shutdown validation remain separate",
        ),
        (
            "backup_boot_unverified",
            "Backup boot and MFTMirr validation remain separate",
        ),
    ] {
        emit_blocker(
            &mut blockers,
            &mut blocker_count,
            &InspectionBlocker {
                code: code.into(),
                message: message.into(),
                file_record_number: None,
            },
        )?;
    }
    if preparation_only {
        emit_blocker(
            &mut blockers,
            &mut blocker_count,
            &InspectionBlocker {
                code: "preparation_inventory_only".into(),
                message: "Metadata-only layout hints lack logical content evidence and cannot admit conversion".into(),
                file_record_number: None,
            },
        )?;
    }
    let blocker_pin = blockers.finish()?;
    let pin = SourceInspectionPin {
        schema_version: 1,
        header: files.header().clone(),
        budget,
        files: files.file_pin().clone(),
        extensions: extension_pin,
        assemblies: assemblies.clone(),
        namespace: directories.pins().clone(),
        namespace_entries,
        security_capture: security_input.pins().clone(),
        security: security.pin().clone(),
        allocation: allocation.clone(),
        blockers: blocker_pin.clone(),
        preparation_only,
        serialized_facts_grant_source_admission: false,
    };
    let value = PagedInspection {
        assemblies: [
            SortedRecordStore::open(&assemblies.assemblies, &scratch)?,
            SortedRecordStore::open(&assemblies.consumed_extensions, &scratch)?,
            SortedRecordStore::open(&assemblies.physical_extensions, &scratch)?,
        ],
        ownership: [
            SortedRecordStore::open(&allocation.physical_ownership, &scratch)?,
            SortedRecordStore::open(&allocation.logical_ownership, &scratch)?,
        ],
        blockers: SortedRecordStore::open(&blocker_pin, &scratch)?,
        files,
        directories,
        security_input,
        security,
        allocation,
        pin,
        scratch,
        purpose,
        _closed: ClosedSource,
        _fact_artifacts: Vec::new(),
        _fact_artifact_ram: None,
        canonical: std::cell::OnceCell::new(),
    };
    value.revalidate()?;
    let _ = value.canonical_sha256()?;
    Ok(value)
}
