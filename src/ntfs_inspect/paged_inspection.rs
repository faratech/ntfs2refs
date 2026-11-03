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
    serialized_facts_grant_source_admission: bool,
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
    _closed: ClosedSource,
}
impl PagedInspection {
    pub fn pin(&self) -> &SourceInspectionPin {
        &self.pin
    }
    pub fn budget(&self) -> SourceMetadataBudget {
        self.scratch.budget()
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
    pub fn blocker_count(&self) -> u64 {
        self.blockers.len()
    }
    pub fn blocker(&self, ordinal: u64) -> Result<InspectionBlocker> {
        self.blockers.get(ordinal)
    }
    pub fn canonical_sha256(&self) -> Result<String> {
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
            self.pin.schema_version == 1
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
    fn find_record(&self, number: u64, sequence: Option<u16>) -> Result<Option<FileInventory>> {
        self.files.find_record(number, sequence)
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
    let (mut root_seen, mut volume_bitmap, mut ext_byte) = (false, None, 0u8);
    for number in 0..record_count {
        let mut allocated = [0u8; 1];
        bitmap.read_exact_at(number / 8, &mut allocated)?;
        if allocated[0] & (1 << (number % 8)) != 0 {
            let _working = scratch.lease_ram(
                budget
                    .record_bytes
                    .checked_mul(8)
                    .and_then(|n| {
                        n.checked_add(
                            LARGE_STREAM_HASH_BYTES as u64 + STREAM_HASH_BUFFER_BYTES as u64,
                        )
                    })
                    .context("raw current-row RAM overflow")?,
            )?;
            let mut raw = Vec::new();
            raw.try_reserve_exact(geometry.file_record_size as usize)?;
            raw.resize(geometry.file_record_size as usize, 0);
            read_attribute_range(
                reader,
                &mft_data,
                number
                    .checked_mul(u64::from(geometry.file_record_size))
                    .context("MFT record byte address overflow")?,
                &mut raw,
                &geometry,
            )?;
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
                    resolver.resolve(reader, number, &raw, &mut record)?;
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
                let inventory = inventory_record(
                    reader,
                    &geometry,
                    record,
                    number,
                    &mut report,
                    &mut row_budget,
                    &mut hash_budget,
                    policy,
                    false,
                    |reader, record| {
                        namespace.observe(reader, record, number, &geometry)?;
                        security.observe(reader, record, number, &geometry)?;
                        Ok(())
                    },
                )?;
                ensure!(
                    file_heap_bytes(&inventory)? <= row_budget.limit,
                    "current source row exceeds resource RAM"
                );
                files_writer.push(file_key(number), &inventory)?;
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
    drop(mft_data);
    drop(bootstrap_record);
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
    let mut files = PagedRawFiles::from_live_bitmap(
        header(&report, false, hash_budget.used),
        &file_pin,
        bitmap,
        &extension_pin,
        &scratch,
    )?;
    let assemblies = resolver.finish(&files)?;
    super::paged_roles::classify(&mut files, &root.join("roles"), &scratch, |item| {
        emit_blocker(&mut blockers, &mut blocker_count, &item)
    })?;
    let directories = namespace.finish()?;
    let namespace_entries = crate::ntfs_namespace::reconcile_domains(&files, &directories)?;
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
    if policy.is_fast() {
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
                let eligible = crate::ntfs_attestation::extent_identity_stream_request_domain(
                    &files,
                    &file,
                    &file.streams[index],
                    true,
                    true,
                )?
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
    let security_input = security.finish()?;
    let security = crate::ntfs_security::reconcile_paged(
        &security_input,
        &files,
        &root.join("security"),
        &scratch,
    )?;
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
        _closed: ClosedSource,
    };
    value.revalidate()?;
    let _ = value.canonical_sha256()?;
    Ok(value)
}
