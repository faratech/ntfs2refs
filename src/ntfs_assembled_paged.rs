//! Complete physical MFT ownership with bounded per-base working state.
use super::*;
use crate::ntfs_inspect::{
    RootFileDomain, SourceMetadataRange,
    external_sort::ExternalSort,
    paged_storage::{PagedMetadataRange, SourcePagePin, SourceRamLease, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
};
use std::{path::Path, rc::Rc};

#[derive(Clone)]
pub(in crate::ntfs_inspect) struct SharedBitmap(pub(in crate::ntfs_inspect) Rc<PagedMetadataRange>);
impl SourceMetadataRange for SharedBitmap {
    fn byte_len(&self) -> u64 {
        self.0.byte_len()
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(offset, output)
    }
    fn revalidate(&self) -> Result<()> {
        self.0.revalidate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExtensionOwnership {
    record_number: u64,
    sequence_number: u16,
    base_file_reference: u64,
    raw_record_sha256: String,
}
impl ExtensionOwnership {
    fn of(number: u64, raw: &[u8], record: &Record) -> Self {
        Self {
            record_number: number,
            sequence_number: record.sequence,
            base_file_reference: record.base,
            raw_record_sha256: hex::encode(Sha256::digest(raw)),
        }
    }
    fn from_evidence(record: &RecordEvidence) -> Self {
        Self {
            record_number: record.record_number,
            sequence_number: record.sequence_number,
            base_file_reference: record.base_file_reference,
            raw_record_sha256: record.raw_record_sha256.clone(),
        }
    }
}
fn key(number: u64) -> [u8; 16] {
    let mut k = [0; 16];
    k[..8].copy_from_slice(&number.to_be_bytes());
    k
}

/// Pins locate complete ordinary metadata. They confer no source or write authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagedAssemblyEvidence {
    pub schema_version: u32,
    pub mft_bitmap: SourcePagePin,
    pub assemblies: RecordStorePin,
    pub consumed_extensions: RecordStorePin,
    pub physical_extensions: RecordStorePin,
    pub record_count: u64,
    pub canonical_records: u64,
    pub extension_records: u64,
    pub allocated_records: u64,
}

pub(in crate::ntfs_inspect) struct PagedMftResolver {
    data: Attribute,
    geometry: NtfsGeometry,
    bitmap: SharedBitmap,
    bitmap_pin: SourcePagePin,
    record_count: u64,
    scratch: SourceScratch,
    consumed: ExternalSort,
    physical: SortedRecordWriter,
    assemblies: SortedRecordWriter,
    _mapping_ram: SourceRamLease,
}
impl PagedMftResolver {
    pub(in crate::ntfs_inspect) fn new(
        data: &Attribute,
        geometry: &NtfsGeometry,
        bitmap: SharedBitmap,
        bitmap_pin: SourcePagePin,
        record_count: u64,
        root: &Path,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        let mapping = (data.report.extents.capacity() as u64)
            .checked_mul(std::mem::size_of::<Extent>() as u64)
            // The bootstrap record, sequential reader and resolver each own
            // a canonical DATA mapping until the source pass has closed.
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| n.checked_add(4096))
            .context("MFT mapping RAM overflow")?;
        let ram = scratch.lease_ram(mapping)?;
        Ok(Self {
            data: data.clone(),
            geometry: geometry.clone(),
            bitmap,
            bitmap_pin,
            record_count,
            scratch: scratch.clone(),
            consumed: ExternalSort::new(&root.join("mft-consumed"), *b"MFTCON01", scratch)?,
            physical: SortedRecordWriter::new(&root.join("mft-physical"), *b"MFTPHY01", scratch)?,
            assemblies: SortedRecordWriter::new(
                &root.join("mft-assemblies"),
                *b"MFTASM01",
                scratch,
            )?,
            _mapping_ram: ram,
        })
    }
    pub(in crate::ntfs_inspect) fn allocated(&self, number: u64) -> Result<bool> {
        if number >= self.record_count || number / 8 >= self.bitmap.byte_len() {
            return Ok(false);
        }
        let mut byte = [0];
        self.bitmap.read_exact_at(number / 8, &mut byte)?;
        Ok(byte[0] & (1 << (number % 8)) != 0)
    }
    pub(in crate::ntfs_inspect) fn retain_bootstrap(&mut self, assembly: Assembly) -> Result<()> {
        ensure!(
            assembly.base.record_number == 0 && assembly.schema_version == 7,
            "resource bootstrap ledger identity differs"
        );
        self.retain(assembly)
    }
    fn retain(&mut self, assembly: Assembly) -> Result<()> {
        for extension in &assembly.extensions {
            self.consumed.push(
                key(extension.record_number),
                &ExtensionOwnership::from_evidence(extension),
            )?;
        }
        self.assemblies
            .push(key(assembly.base.record_number), &assembly)
    }
    pub(in crate::ntfs_inspect) fn observe_physical_extension(
        &mut self,
        number: u64,
        raw: &[u8],
        record: &Record,
    ) -> Result<()> {
        ensure!(
            number >= 16
                && self.allocated(number)?
                && matches!(record.flags, 1 | 3 | 9)
                && record.sequence != 0
                && record.base != 0
                && (record.base >> 48) != 0,
            "physical MFT extension FILE {number} differs: flags={:#x}, links={}, sequence={}, base={:#x}",
            record.flags, record.links, record.sequence, record.base
        );
        self.physical
            .push(key(number), &ExtensionOwnership::of(number, raw, record))
    }
    pub(in crate::ntfs_inspect) fn resolve<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        number: u64,
        raw: &[u8],
        record: &mut Record,
    ) -> Result<Option<SourceRamLease>> {
        if !record.attributes.iter().any(|a| a.report.type_code == 0x20) {
            return Ok(None);
        }
        // MFT0 has already been independently bootstrapped. Unsupported list
        // semantics remain a refusal rather than an incompletely emitted file.
        ensure!(
            number > 0 && record.base == 0 && matches!(record.flags,1|3|9)
                && record.links>0 && record.attributes.iter().all(|a|a.report.flags==0&&a.report.compression_unit==0),
            "unsupported resource-bound attribute-list FILE {number}, flags={:#x}, attributes={:?}",record.flags,
            record.attributes.iter().map(|a|(a.report.type_code,a.report.flags,a.report.compression_unit)).collect::<Vec<_>>()
        );
        ensure!(
            self.allocated(number)?,
            "attribute-list base is not allocated"
        );
        let ordinary_base = stream_candidate(number, record);
        let working = self.scratch.budget().ram_bytes / 4;
        let limits =
            lists::AssemblyLimits::from_working_bytes(working, self.geometry.file_record_size)?;
        let list = unnamed(record, 0x20)?;
        lists::validate_list_resource(&list.report, &self.geometry, limits)?;
        // Pay for the actual list before it is read/decoded; original
        // AssemblyLimits still determine which NTFS forms are admitted.
        let list_bytes = list.report.logical_size;
        let list_work = list_bytes.checked_mul(32)
            .and_then(|n| n.checked_add(1024 * 1024))
            .with_context(|| format!("FILE {number} attribute-list workspace overflow"))?;
        let list_ram = self.scratch.lease_ram(list_work)
            .with_context(|| format!("FILE {number} attribute list requires {list_work} bytes"))?;
        let value = read_small_attribute(reader, list, &self.geometry, limits.list_bytes as u64)?;
        let entries = lists::parse_stream_entries_with_limit(&value, limits.list_bytes)?;
        let references: BTreeSet<_> = entries
            .iter()
            .filter(|e| e.record_number != number)
            .map(|e| (e.record_number, e.sequence_number))
            .collect();
        ensure!(
            references.len() <= limits.extension_records,
            "assembly exceeds admitted record RAM"
        );
        let record_work = u64::try_from(references.len())?.checked_add(1)
            .and_then(|n| n.checked_mul(u64::from(self.geometry.file_record_size)))
            .and_then(|n| n.checked_mul(32))
            .and_then(|n| n.checked_add(list_bytes.checked_mul(64)?))
            .and_then(|n| n.checked_add(1024 * 1024))
            .with_context(|| format!("FILE {number} extension assembly workspace overflow"))?;
        let record_ram = self.scratch.lease_ram(record_work)
            .with_context(|| format!("FILE {number} extensions require {record_work} bytes"))?;
        let mut extensions = Vec::new();
        let mut residents = BTreeMap::new();
        for attribute in &record.attributes {
            if let Some(bytes) = &attribute.resident_value {
                residents.insert(
                    (number, record.sequence, attribute.report.instance),
                    bytes.clone(),
                );
            }
        }
        let mut run_count = record
            .attributes
            .iter()
            .map(|a| a.report.extents.len())
            .sum::<usize>();
        for (extension, sequence) in references {
            ensure!(
                self.allocated(extension)?,
                "list references an unallocated/out-of-range extension"
            );
            let mut bytes = vec![0; self.geometry.file_record_size as usize];
            read_attribute_range(
                reader,
                &self.data,
                extension
                    .checked_mul(u64::from(self.geometry.file_record_size))
                    .context("extension record byte offset overflow")?,
                &mut bytes,
                &self.geometry,
            )?;
            let parsed = parse_record(bytes.clone(), &self.geometry)?;
            ensure!(
                (parsed.flags == 1 || !ordinary_base && matches!(parsed.flags,3|9)) && parsed.sequence == sequence,
                "referenced extension sequence or allocation header differs"
            );
            run_count = parsed
                .attributes
                .iter()
                .try_fold(run_count, |n, a| n.checked_add(a.report.extents.len()))
                .context("assembly run count overflow")?;
            ensure!(
                run_count <= limits.runs,
                "assembly exceeds admitted mapping RAM"
            );
            for attribute in &parsed.attributes {
                if let Some(value) = &attribute.resident_value {
                    ensure!(
                        residents
                            .insert(
                                (extension, sequence, attribute.report.instance),
                                value.clone()
                            )
                            .is_none(),
                        "duplicate resident physical attribute origin"
                    );
                }
            }
            extensions.push(evidence(extension, &bytes, &parsed));
        }
        // Extension headers can retain 0xffff in their noncanonical link-count
        // field. Their base reference, sequence, allocation and exact list
        // membership establish ownership; only the base supplies file links.
        let ordinary = ordinary_base && extensions.iter().all(|r|r.hard_link_count==0);
        let assemble = if ordinary { lists::assemble_streams_resource } else { lists::assemble_attributes_resource };
        let (canonical, assembly) = assemble(
            evidence(number, raw, record),
            extensions,
            &value,
            &self.geometry,
            limits,
        ).with_context(|| format!("assembling complete attributes of NTFS FILE {number}"))?;
        let origins = assembly
            .canonical_origins
            .as_ref()
            .context("canonical origins absent")?;
        ensure!(
            origins.len() == canonical.len(),
            "canonical origin coverage differs"
        );
        let mut output = Vec::new();
        output.try_reserve_exact(canonical.len())?;
        for (report, origin) in canonical.into_iter().zip(origins) {
            let resident_value = if report.resident {
                let bytes = residents
                    .get(&(
                        origin.record_number,
                        origin.sequence_number,
                        origin.instance,
                    ))
                    .context("canonical resident origin missing actual physical bytes")?;
                ensure!(
                    bytes.len() as u64 == report.logical_size
                        && report
                            .resident_sha256
                            .as_deref()
                            .is_some_and(|hash| lists::resident_digest_matches(hash, bytes)),
                    "canonical resident physical bytes differ"
                );
                Some(bytes.clone())
            } else {
                None
            };
            output.push(Attribute {
                report,
                resident_value,
            });
        }
        self.retain(assembly)?;
        record.attributes = output;
        drop(entries);
        drop(value);
        drop(list_ram);
        Ok(Some(record_ram))
    }
    pub(in crate::ntfs_inspect) fn finish(
        self,
        files: &PagedRawFiles,
    ) -> Result<PagedAssemblyEvidence> {
        files.revalidate()?;
        self.bitmap.revalidate()?;
        ensure!(
            files.header().mft_record_count == self.record_count,
            "canonical MFT record domain differs from bootstrap"
        );
        let consumed_pin = self.consumed.finish()?;
        let physical_pin = self.physical.finish()?;
        let assemblies_pin = self.assemblies.finish()?;
        let consumed = SortedRecordStore::open(&consumed_pin, &self.scratch)?;
        let physical = SortedRecordStore::open(&physical_pin, &self.scratch)?;
        let assemblies = SortedRecordStore::open(&assemblies_pin, &self.scratch)?;
        let working = self.scratch.budget().ram_bytes / 4;
        let limits =
            lists::AssemblyLimits::from_working_bytes(working, self.geometry.file_record_size)?;
        let bitmap_allocated = |number: u64| -> Result<bool> {
            if number >= self.record_count {
                return Ok(false);
            }
            let mut byte = [0];
            self.bitmap.read_exact_at(number / 8, &mut byte)?;
            Ok(byte[0] & (1 << (number % 8)) != 0)
        };
        ensure!(
            consumed.len() == physical.len(),
            "orphaned or multiply consumed MFT extension"
        );
        for ordinal in 0..physical.len() {
            let raw_bytes = physical.record_bytes(ordinal)?
                .checked_add(consumed.record_bytes(ordinal)?)
                .and_then(|n| n.checked_mul(32))
                .and_then(|n| n.checked_add(1024 * 1024))
                .with_context(|| format!("physical extension ordinal {ordinal} workspace overflow"))?;
            let _row_ram = self.scratch.lease_ram(raw_bytes)
                .with_context(|| format!("physical extension ordinal {ordinal} requires {raw_bytes} bytes"))?;
            let actual: ExtensionOwnership = physical.get(ordinal)?;
            let used: ExtensionOwnership = consumed.get(ordinal)?;
            ensure!(
                physical.key(ordinal)? == consumed.key(ordinal)? && actual == used,
                "physical extension differs from its exactly-one consuming base"
            );
            let base = actual.base_file_reference & 0x0000_ffff_ffff_ffff;
            let sequence = (actual.base_file_reference >> 48) as u16;
            let file_work = files.record_wire_bytes(base)?.unwrap_or(0)
                .checked_add(files.record_wire_bytes(actual.record_number)?.unwrap_or(0))
                .and_then(|n| n.checked_mul(32))
                .and_then(|n| n.checked_add(65536))
                .with_context(|| format!("physical extension ordinal {ordinal} file workspace overflow"))?;
            let _file_ram = self.scratch.lease_ram(file_work)
                .with_context(|| format!("physical extension ordinal {ordinal} file lookup requires {file_work} bytes"))?;
            ensure!(
                bitmap_allocated(actual.record_number)?
                    && files.allocated_record(actual.record_number)?
                    && files.extension_record(actual.record_number)?
                    && files.find_record(actual.record_number, None)?.is_none()
                    && files.find_record(base, Some(sequence))?.is_some(),
                "extension allocation/base ownership does not match canonical files"
            );
        }
        for ordinal in 0..assemblies.len() {
            let assembly_bytes = assemblies.record_bytes(ordinal)?;
            let decode_bytes = assembly_bytes.checked_mul(32).and_then(|n| n.checked_add(65536))
                .with_context(|| format!("assembly ordinal {ordinal} decode workspace overflow"))?;
            let _decode_ram = self.scratch.lease_ram(decode_bytes)
                .with_context(|| format!("assembly ordinal {ordinal} decode requires {decode_bytes} bytes"))?;
            let assembly: Assembly = assemblies.get(ordinal)?;
            let records = u64::try_from(assembly.extensions.len())?.checked_add(1)
                .context("assembly extension count overflow")?;
            let file_bytes = files.record_wire_bytes(assembly.base.record_number)?.unwrap_or(0);
            let replay_bytes = assembly_bytes.checked_mul(64)
                .and_then(|n| n.checked_add(file_bytes.checked_mul(32)?))
                .and_then(|n| n.checked_add(records.checked_mul(u64::from(self.geometry.file_record_size))?.checked_mul(16)?))
                .and_then(|n| n.checked_add((assembly.list_value_hex.len() as u64).checked_mul(8)?))
                .and_then(|n| n.checked_add(1024 * 1024))
                .with_context(|| format!("assembly ordinal {ordinal} replay workspace overflow"))?;
            let _replay_ram = self.scratch.lease_ram(replay_bytes)
                .with_context(|| format!("assembly ordinal {ordinal} replay requires {replay_bytes} bytes"))?;
            let file = files
                .find_record(
                    assembly.base.record_number,
                    Some(assembly.base.sequence_number),
                )?
                .context("assembled base absent from canonical source domain")?;
            ensure!(
                file.base_file_reference == 0,
                "assembled canonical record is an extension"
            );
            ensure!(
                assembly.list_value_hex.len()
                    <= limits
                        .list_bytes
                        .checked_mul(2)
                        .context("attribute-list replay byte overflow")?,
                "assembly replay exceeds admitted working RAM"
            );
            let value = hex::decode(&assembly.list_value_hex)?;
            let (canonical, replay) = if assembly.base.record_number == 0 {
                ensure!(
                    assembly.schema_version == 7 && assembly.mft_bitmap_hex.is_none(),
                    "paged MFT assembly cannot inherit a legacy bitmap authority field"
                );
                lists::assemble_mft_resource(
                    assembly.base.clone(),
                    assembly.extensions.clone(),
                    &value,
                    &self.bitmap,
                    &self.geometry,
                    limits,
                )?
            } else {
                ensure!(
                    matches!(assembly.schema_version, 5 | 6 | 8 | 9) && assembly.mft_bitmap_hex.is_none(),
                    "unknown resource ordinary assembly schema"
                );
                let assemble = if matches!(assembly.schema_version,8|9) { lists::assemble_attributes_resource }
                    else { lists::assemble_streams_resource };
                assemble(
                    assembly.base.clone(),
                    assembly.extensions.clone(),
                    &value,
                    &self.geometry,
                    limits,
                )?
            };
            ensure!(
                replay == assembly
                    && canonical == file.attributes
                    && assembly.base.hard_link_count == file.hard_link_count
                    && assembly.base.is_directory == file.is_directory,
                "complete physical assembly does not reproduce canonical source metadata"
            );
        }
        let mut allocated = 0u64;
        let mut at = 0u64;
        let mut window = [0u8; 4096];
        while at < self.bitmap.byte_len() {
            let n = usize::try_from((self.bitmap.byte_len() - at).min(window.len() as u64))?;
            self.bitmap.read_exact_at(at, &mut window[..n])?;
            for byte in &window[..n] {
                allocated = allocated
                    .checked_add(u64::from(byte.count_ones()))
                    .context("MFT allocated record count overflow")?;
            }
            at += n as u64;
        }
        ensure!(
            files.file_count().checked_add(physical.len()) == Some(allocated)
                && files.header().records_scanned == allocated,
            "allocated MFT records lack complete canonical/extension coverage"
        );
        for ordinal in 0..files.file_count() {
            let bytes = files.ordinal_wire_bytes(ordinal)?.checked_mul(32)
                .and_then(|n| n.checked_add(65536))
                .with_context(|| format!("canonical FILE ordinal {ordinal} workspace overflow"))?;
            let _ram = self.scratch.lease_ram(bytes)
                .with_context(|| format!("canonical FILE ordinal {ordinal} requires {bytes} bytes"))?;
            let file = files.file(ordinal)?;
            ensure!(
                file.base_file_reference == 0
                    && bitmap_allocated(file.record_number)?
                    && files.allocated_record(file.record_number)?
                    && !files.extension_record(file.record_number)?,
                "canonical record allocation/extension overlap"
            );
        }
        consumed.revalidate()?;
        physical.revalidate()?;
        assemblies.revalidate()?;
        self.bitmap.revalidate()?;
        files.revalidate()?;
        Ok(PagedAssemblyEvidence {
            schema_version: 1,
            mft_bitmap: self.bitmap_pin,
            assemblies: assemblies_pin,
            consumed_extensions: consumed_pin,
            physical_extensions: physical_pin,
            record_count: self.record_count,
            canonical_records: files.file_count(),
            extension_records: physical.len(),
            allocated_records: allocated,
        })
    }
}
