//! Legacy capture compatibility; paged capture uses an owning metadata domain.
use super::*;

/// Resource-bounded capture/reconciliation path. The input owner supplies
/// authenticated metadata ranges; this module never exposes raw write access.
#[cfg(windows)]
pub(super) fn reconcile_paged_capture(
    capture: &impl super::source_domain::RootSecurityCaptureDomain,
    files: &impl super::source_domain::RootFileDomain,
    output: &std::path::Path,
    scratch: &super::paged_storage::SourceScratch,
) -> Result<crate::ntfs_security::PagedReconciliation> {
    crate::ntfs_security::reconcile_paged(capture, files, output, scratch)
}

#[derive(Default)]
pub(super) struct SecurityCapture {
    pub(super) table: Option<crate::ntfs_security::Table>,
    pub(super) legacy: Vec<crate::ntfs_security::DescriptorRecord>,
    pub(super) bytes_read: usize,
    pub(super) descriptor_bytes: usize,
    pub(super) aces: usize,
    pub(super) sii_entries: usize,
    pub(super) sdh_entries: usize,
    pub(super) evidence: Sha256,
    pub(super) failure: Option<String>,
    pub(super) incomplete_attributes: bool,
    /// NTFS 1.2: no $Secure (record 9 is $Quota); every file's descriptor
    /// is its own $SECURITY_DESCRIPTOR attribute.
    pub(super) legacy_layout: bool,
}

impl SecurityCapture {
    pub(super) fn named<'a>(
        record: &'a Record,
        kind: u32,
        name: &str,
    ) -> Result<Option<&'a Attribute>> {
        let name: Vec<u16> = name.encode_utf16().collect();
        let mut found = record
            .attributes
            .iter()
            .filter(|a| a.report.type_code == kind && a.report.name_utf16 == name);
        let first = found.next();
        ensure!(found.next().is_none(), "duplicate security attribute");
        if let Some(a) = first {
            ensure!(
                a.report.lowest_vcn == 0,
                "unassembled security attribute VCN"
            );
        }
        Ok(first)
    }
    pub(super) fn bytes<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        a: &Attribute,
        geometry: &NtfsGeometry,
        role: &str,
        maximum: u64,
    ) -> Result<Vec<u8>> {
        use crate::ntfs_security as sec;
        ensure!(
            a.report.flags == 0
                && a.report.lowest_vcn == 0
                && a.report.initialized_size == a.report.logical_size,
            "security metadata must be fully initialized and unencoded"
        );
        if !a.report.resident {
            validate_stream_mapping(&a.report, geometry)?;
            ensure!(
                a.report.extents.iter().all(|e| e.physical_offset.is_some()),
                "sparse security metadata is unsupported"
            );
        }
        let total = (self.bytes_read as u64)
            .checked_add(a.report.logical_size)
            .context("security read budget overflow")?;
        ensure!(
            a.report.logical_size <= maximum && total <= sec::MAX_METADATA_BYTES as u64,
            "security metadata read budget exceeded"
        );
        self.bytes_read = total as usize;
        let value = read_small_attribute(reader, a, geometry, maximum)?;
        self.evidence.update((role.len() as u64).to_le_bytes());
        self.evidence.update(role.as_bytes());
        self.evidence.update((value.len() as u64).to_le_bytes());
        self.evidence.update(&value);
        Ok(value)
    }
    pub(super) fn index<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        record: &Record,
        geometry: &NtfsGeometry,
        name: &str,
        kind: crate::ntfs_security::IndexKind,
    ) -> Result<crate::ntfs_security::SecurityIndex> {
        let root = Self::named(record, 0x90, name)?.context("missing security INDEX_ROOT")?;
        ensure!(root.report.resident, "security INDEX_ROOT must be resident");
        let root = self.bytes(
            reader,
            root,
            geometry,
            &format!("{name}:root"),
            crate::ntfs_index::MAX_INDEX_ROOT_BYTES as u64,
        )?;
        let allocation_attr = Self::named(record, 0xa0, name)?;
        let bitmap_attr = Self::named(record, 0xb0, name)?;
        let (allocation, initialized) = if let Some(a) = allocation_attr {
            ensure!(
                !a.report.resident && bitmap_attr.is_some(),
                "security INDEX_ALLOCATION requires nonresident data and bitmap"
            );
            // Free trailing slots can be uninitialized; active-slot coverage is
            // independently enforced by the common index reader.
            ensure!(a.report.flags == 0, "encoded security index allocation");
            validate_stream_mapping(&a.report, geometry)?;
            ensure!(
                a.report.extents.iter().all(|e| e.physical_offset.is_some()),
                "sparse security index allocation"
            );
            let total = (self.bytes_read as u64)
                .checked_add(a.report.logical_size)
                .context("security index byte overflow")?;
            ensure!(
                total <= crate::ntfs_security::MAX_METADATA_BYTES as u64,
                "security index read budget exceeded"
            );
            self.bytes_read = total as usize;
            let bytes = read_small_attribute(
                reader,
                a,
                geometry,
                crate::ntfs_security::MAX_METADATA_BYTES as u64,
            )?;
            self.evidence.update(name.as_bytes());
            self.evidence.update((bytes.len() as u64).to_le_bytes());
            self.evidence.update(&bytes);
            (bytes, a.report.initialized_size)
        } else {
            (Vec::new(), 0)
        };
        let bitmap = if let Some(a) = bitmap_attr {
            self.bytes(reader, a, geometry, &format!("{name}:bitmap"), 4096)?
        } else {
            Vec::new()
        };
        crate::ntfs_security::parse_index_with_geometry(
            crate::ntfs_index::Input {
                root: &root,
                allocation: &allocation,
                initialized,
                bitmap: &bitmap,
            },
            kind,
            geometry.cluster_size,
            geometry.index_record_size,
        )
    }
    pub(super) fn charge_descriptors(
        &mut self,
        records: &[crate::ntfs_security::DescriptorRecord],
    ) -> Result<()> {
        use crate::ntfs_security as sec;
        for r in records {
            self.descriptor_bytes += r.descriptor.relative_hex.len() / 2;
            self.aces += r.descriptor.dacl.aces.len() + r.descriptor.sacl.aces.len();
        }
        ensure!(
            self.descriptor_bytes <= sec::MAX_TOTAL_DESCRIPTOR_BYTES
                && self.aces <= sec::MAX_TOTAL_ACES,
            "aggregate security descriptor/ACE budget exceeded"
        );
        Ok(())
    }
    pub(super) fn read<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        record: &Record,
        number: u64,
        geometry: &NtfsGeometry,
    ) -> Result<()> {
        use crate::ntfs_security as sec;
        if number == 9 && !self.legacy_layout {
            ensure!(
                crate::ntfs_index::supports_cluster_size(geometry.cluster_size)
                    && super::supports_record_geometry(geometry),
                "the security indexes cannot be read in this geometry: {}-byte sectors, {}-byte clusters, {}-byte index records",
                geometry.bytes_per_sector,
                geometry.cluster_size,
                geometry.index_record_size
            );
            let sds = Self::named(record, 0x80, "$SDS")?.context("$Secure lacks SDS data")?;
            let sds = self.bytes(reader, sds, geometry, "SDS", sec::MAX_METADATA_BYTES as u64)?;
            let sii = self.index(reader, record, geometry, "$SII", sec::IndexKind::Id)?;
            let sdh = self.index(reader, record, geometry, "$SDH", sec::IndexKind::Hash)?;
            self.sii_entries = sii.entries.len();
            self.sdh_entries = sdh.entries.len();
            let table = sec::reconcile_table(&sds, &sii, &sdh)?;
            self.charge_descriptors(&table.records)?;
            self.table = Some(table);
        }
        let mut legacy = record
            .attributes
            .iter()
            .filter(|a| a.report.type_code == 0x50);
        if let Some(a) = legacy.next() {
            ensure!(
                legacy.next().is_none() && a.report.name_utf16.is_empty(),
                "ambiguous/named legacy security descriptor"
            );
            ensure!(
                self.legacy.len() < sec::MAX_DESCRIPTORS,
                "legacy descriptor count limit exceeded"
            );
            let bytes = self.bytes(
                reader,
                a,
                geometry,
                &format!("legacy:{number}"),
                sec::MAX_DESCRIPTOR_BYTES as u64,
            )?;
            let descriptor = sec::DescriptorRecord {
                security_id: None,
                legacy_record: Some(number),
                sds_offset: None,
                ntfs_hash: None,
                descriptor: sec::parse_descriptor(&bytes)?,
            };
            self.charge_descriptors(std::slice::from_ref(&descriptor))?;
            self.legacy.push(descriptor);
        }
        Ok(())
    }
    pub(super) fn observe<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        record: &Record,
        number: u64,
        geometry: &NtfsGeometry,
    ) {
        if record.base != 0 || record.attributes.iter().any(|a| a.report.type_code == 0x20) {
            self.incomplete_attributes = true;
            return;
        }
        if self.failure.is_none()
            && let Err(error) = self.read(reader, record, number, geometry)
        {
            self.failure = Some(format!("MFT record {number}: {error:#}"));
        }
    }
    pub(super) fn finish(self, files: &[FileInventory]) -> crate::ntfs_security::Reconciliation {
        use crate::ntfs_security::{self as sec, Reconciliation, Status};
        let mut result = Reconciliation {
            status: Status::Rejected,
            metadata_bytes_read: self.bytes_read,
            central_descriptors: self.table.as_ref().map_or(0, |t| t.records.len()),
            legacy_descriptors: self.legacy.len(),
            sii_entries: self.sii_entries,
            sdh_entries: self.sdh_entries,
            index_blocks: self.table.as_ref().map_or(0, |t| t.index_blocks),
            bound_files: 0,
            evidence_sha256: hex::encode(self.evidence.finalize()),
            detail: String::new(),
            descriptors: Vec::new(),
            bindings: Vec::new(),
        };
        if self.incomplete_attributes {
            result.status = Status::IncompleteAttributeInventory;
            result.detail =
                "Attribute-list/extension records require assembly before security reconciliation"
                    .into();
        } else if let Some(error) = self.failure {
            result.detail = error;
        } else if let Some(mut table) = self.table.or_else(|| {
            self.legacy_layout
                .then(crate::ntfs_security::Table::default)
        }) {
            table.records.extend(self.legacy);
            match sec::bind_files(files, &table.records) {
                Ok(bindings) => {
                    result.status = Status::ConsistentRawModel;
                    result.bound_files = bindings.len();
                    result.bindings = bindings;
                    result.descriptors = table.records;
                    result.detail="SDS mirrors/hashes, SII/SDH entries and central/legacy file bindings reconcile; native security attestation remains unverified".into();
                }
                Err(error) => result.detail = format!("{error:#}"),
            }
        } else {
            result.detail = "No validated $Secure table was captured".into();
        }
        result
    }
}
