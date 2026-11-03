//! Actual source reads bound to the immutable complete paged inventory.
//! These checks are not filesystem exclusion or fresh write authority.
use super::*;
use crate::ntfs_attribute_list::{self as lists, Assembly};
use std::{cell::RefCell, collections::BTreeMap};

pub(crate) struct CheckedMftDomain {
    data: Attribute,
    root: Record,
    source_pin: String,
    _mapping_ram: paged_storage::SourceRamLease,
}
fn clone_record(record: &Record) -> Record {
    Record {
        sequence: record.sequence,
        links: record.links,
        flags: record.flags,
        base: record.base,
        attributes: record.attributes.clone(),
    }
}
fn same_identity(record: &Record, file: &FileInventory) -> Result<()> {
    ensure!(
        record.flags & 1 != 0
            && record.sequence == file.sequence_number
            && record.links == file.hard_link_count
            && record.base == file.base_file_reference
            && (record.flags & 2 != 0) == file.is_directory,
        "actual source FILE identity differs"
    );
    Ok(())
}

struct BitmapView<'a, R> {
    reader: RefCell<&'a mut R>,
    attribute: &'a Attribute,
    geometry: &'a NtfsGeometry,
    pin: &'a paged_storage::SourcePagePin,
}
impl<R: Read + Seek> SourceMetadataRange for BitmapView<'_, R> {
    fn byte_len(&self) -> u64 {
        self.attribute.report.logical_size
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        read_attribute_range(
            &mut **self.reader.borrow_mut(),
            self.attribute,
            offset,
            output,
            self.geometry,
        )
    }
    fn revalidate(&self) -> Result<()> {
        ensure!(
            self.byte_len() == self.pin.logical_bytes,
            "actual MFT bitmap length changed"
        );
        let mut digest = Sha256::new();
        let mut window = [0u8; 65536];
        let mut offset = 0;
        while offset < self.byte_len() {
            let n = (self.byte_len() - offset).min(window.len() as u64) as usize;
            self.read_exact_at(offset, &mut window[..n])?;
            digest.update(&window[..n]);
            offset += n as u64;
        }
        ensure!(
            hex::encode(digest.finalize()) == self.pin.logical_sha256,
            "actual MFT bitmap changed from the complete captured source"
        );
        Ok(())
    }
}

fn actual_assembly<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    data: &Attribute,
    number: u64,
    raw: &[u8],
    record: &mut Record,
    expected: Assembly,
) -> Result<()> {
    let geometry = &source.header().geometry;
    ensure!(
        expected.base.record_number == number
            && assembled_io::evidence(number, raw, record) == expected.base,
        "actual base record bytes/attributes differ from complete assembly ledger"
    );
    let working = source.budget().ram_bytes / 4;
    let limits = lists::AssemblyLimits::from_working_bytes(working, geometry.file_record_size)?;
    let list = unnamed(record, 0x20)?;
    lists::validate_list_resource(&list.report, geometry, limits)?;
    let value = read_small_attribute(reader, list, geometry, limits.list_bytes as u64)?;
    let mut residents = BTreeMap::new();
    for attribute in &record.attributes {
        if let Some(bytes) = &attribute.resident_value {
            residents.insert(
                (number, record.sequence, attribute.report.instance),
                bytes.clone(),
            );
        }
    }
    let mut extensions = Vec::new();
    extensions.try_reserve_exact(expected.extensions.len())?;
    for wanted in &expected.extensions {
        ensure!(
            source.allocated_record(wanted.record_number)?
                && source.extension_record(wanted.record_number)?,
            "actual extension allocation differs"
        );
        let mut bytes = vec![0; geometry.file_record_size as usize];
        read_attribute_range(
            reader,
            data,
            wanted
                .record_number
                .checked_mul(u64::from(geometry.file_record_size))
                .context("actual extension offset overflow")?,
            &mut bytes,
            geometry,
        )?;
        let parsed = parse_record(bytes.clone(), geometry)?;
        let actual = assembled_io::evidence(wanted.record_number, &bytes, &parsed);
        ensure!(
            actual == *wanted && parsed.flags == 1,
            "actual physical extension bytes differ from the complete captured assembly"
        );
        for attribute in &parsed.attributes {
            if let Some(value) = &attribute.resident_value {
                ensure!(
                    residents
                        .insert(
                            (
                                wanted.record_number,
                                parsed.sequence,
                                attribute.report.instance
                            ),
                            value.clone()
                        )
                        .is_none(),
                    "duplicate actual resident origin"
                );
            }
        }
        extensions.push(actual);
    }
    let (canonical, replay) = if number == 0 {
        ensure!(
            expected.schema_version == 7 && expected.mft_bitmap_hex.is_none(),
            "resource MFT assembly profile differs"
        );
        let bitmap = unnamed(record, 0xb0)?;
        let view = BitmapView {
            reader: RefCell::new(reader),
            attribute: bitmap,
            geometry,
            pin: source.mft_bitmap_pin(),
        };
        view.revalidate()?;
        let result = lists::assemble_mft_resource(
            expected.base.clone(),
            extensions,
            &value,
            &view,
            geometry,
            limits,
        )?;
        view.revalidate()?;
        result
    } else {
        ensure!(
            matches!(expected.schema_version, 5 | 6) && expected.mft_bitmap_hex.is_none(),
            "resource ordinary assembly profile differs"
        );
        lists::assemble_streams_resource(
            expected.base.clone(),
            extensions,
            &value,
            geometry,
            limits,
        )?
    };
    ensure!(
        replay == expected,
        "actual assembly changed its complete canonical replay"
    );
    let old = std::mem::take(&mut record.attributes);
    let mut output = Vec::new();
    output.try_reserve_exact(canonical.len())?;
    for (index, report) in canonical.into_iter().enumerate() {
        let resident_value = if report.resident {
            let bytes = if let Some(origins) = &expected.canonical_origins {
                let origin = origins
                    .get(index)
                    .context("canonical resident origin absent")?;
                residents.get(&(
                    origin.record_number,
                    origin.sequence_number,
                    origin.instance,
                ))
            } else {
                old.iter()
                    .find(|a| a.report.instance == report.instance)
                    .and_then(|a| a.resident_value.as_ref())
            }
            .context("actual canonical resident bytes absent")?;
            ensure!(
                bytes.len() as u64 == report.logical_size
                    && report
                        .resident_sha256
                        .as_deref()
                        .is_some_and(|hash| lists::resident_digest_matches(hash, bytes)),
                "actual canonical resident content differs"
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
    record.attributes = output;
    Ok(())
}

impl CheckedMftDomain {
    pub(crate) fn open<R: Read + Seek>(reader: &mut R, source: &PagedInspection) -> Result<Self> {
        ensure!(
            source.header().inventory_complete,
            "complete paged source is required"
        );
        let geometry = &source.header().geometry;
        let working = source.budget().ram_bytes / 4;
        let _working = source.lease_working_ram(working)?;
        let mut boot = [0; 512];
        read_at(reader, 0, &mut boot, geometry.volume_size)?;
        ensure!(
            inspect_boot_sector(&boot, geometry.volume_size)? == *geometry,
            "actual source geometry changed"
        );
        let file = source
            .find_record(0, None)?
            .context("canonical MFT absent")?;
        let expected = unnamed_inventory_data(&file, &[])?;
        let data = Attribute {
            report: expected.clone(),
            resident_value: None,
        };
        let mut raw = vec![0; geometry.file_record_size as usize];
        read_at(
            reader,
            geometry
                .mft_lcn
                .checked_mul(u64::from(geometry.cluster_size))
                .context("MFT bootstrap offset overflow")?,
            &mut raw,
            geometry.volume_size,
        )?;
        let mut record = parse_record(raw.clone(), geometry)?;
        same_identity(&record, &file)?;
        match source.assembly_for_record(0)? {
            Some(assembly) => {
                actual_assembly(reader, source, &data, 0, &raw, &mut record, assembly)?
            }
            None => ensure!(
                !record.attributes.iter().any(|a| a.report.type_code == 0x20),
                "actual MFT unexpectedly requires an assembly"
            ),
        }
        let attrs: Vec<_> = record.attributes.iter().map(|a| a.report.clone()).collect();
        ensure!(
            attrs == file.attributes,
            "actual canonical MFT mapping/metadata changed"
        );
        let bitmap = unnamed(&record, 0xb0)?;
        let view = BitmapView {
            reader: RefCell::new(reader),
            attribute: bitmap,
            geometry,
            pin: source.mft_bitmap_pin(),
        };
        view.revalidate()?;
        drop(view);
        let mapping = (expected.extents.capacity() as u64)
            .checked_mul(std::mem::size_of::<Extent>() as u64 * 2)
            .and_then(|n| n.checked_add(u64::from(geometry.file_record_size) * 16))
            .context("checked MFT mapping RAM overflow")?;
        let ram = source.lease_working_ram(mapping)?;
        Ok(Self {
            data,
            root: record,
            source_pin: source.canonical_sha256()?,
            _mapping_ram: ram,
        })
    }
    fn record<R: Read + Seek>(
        &self,
        reader: &mut R,
        source: &PagedInspection,
        number: u64,
    ) -> Result<Record> {
        ensure!(
            source.canonical_sha256()? == self.source_pin,
            "checked MFT owner changed"
        );
        if number == 0 {
            return Ok(clone_record(&self.root));
        }
        let file = source
            .find_record(number, None)?
            .context("source FILE absent from complete domain")?;
        ensure!(
            file.base_file_reference == 0
                && source.allocated_record(number)?
                && !source.extension_record(number)?,
            "source FILE allocation/base identity differs"
        );
        let _ram = source.lease_working_ram(source.budget().ram_bytes / 4)?;
        let geometry = &source.header().geometry;
        let mut raw = vec![0; geometry.file_record_size as usize];
        read_attribute_range(
            reader,
            &self.data,
            number
                .checked_mul(u64::from(geometry.file_record_size))
                .context("actual FILE offset overflow")?,
            &mut raw,
            geometry,
        )?;
        let mut record = parse_record(raw.clone(), geometry)?;
        same_identity(&record, &file)?;
        match source.assembly_for_record(number)? {
            Some(assembly) => actual_assembly(
                reader,
                source,
                &self.data,
                number,
                &raw,
                &mut record,
                assembly,
            )?,
            None => ensure!(
                !record.attributes.iter().any(|a| a.report.type_code == 0x20),
                "actual FILE unexpectedly requires an assembly"
            ),
        }
        let attrs: Vec<_> = record.attributes.iter().map(|a| a.report.clone()).collect();
        ensure!(
            attrs == file.attributes,
            "actual canonical FILE attributes changed"
        );
        Ok(record)
    }
    pub(crate) fn data<R: Read + Seek>(
        &self,
        reader: &mut R,
        source: &PagedInspection,
        number: u64,
        name: &[u16],
    ) -> Result<AttributeInventory> {
        let record = self.record(reader, source, number)?;
        let mut attrs = record
            .attributes
            .into_iter()
            .filter(|a| a.report.type_code == 0x80 && a.report.name_utf16 == name);
        let attribute = attrs.next().context("actual DATA attribute absent")?;
        ensure!(attrs.next().is_none(), "duplicate actual DATA attribute");
        Ok(attribute.report)
    }
    pub(crate) fn verify_record<R: Read + Seek>(
        &self,
        reader: &mut R,
        source: &PagedInspection,
        number: u64,
    ) -> Result<()> {
        let _ = self.record(reader, source, number)?;
        Ok(())
    }
    pub(crate) fn resident_attribute<R: Read + Seek>(
        &self,
        reader: &mut R,
        source: &PagedInspection,
        file: &FileInventory,
        wanted: &AttributeInventory,
    ) -> Result<Vec<u8>> {
        ensure!(
            wanted.resident && wanted.logical_size <= source.budget().record_bytes,
            "resident source attribute exceeds admitted row"
        );
        let record = self.record(reader, source, file.record_number)?;
        same_identity(&record, file)?;
        let mut attrs = record
            .attributes
            .into_iter()
            .filter(|a| a.report.instance == wanted.instance);
        let actual = attrs.next().context("actual resident attribute absent")?;
        ensure!(
            attrs.next().is_none() && actual.report == *wanted,
            "actual resident attribute changed"
        );
        actual
            .resident_value
            .context("actual resident bytes absent")
    }
}
fn unnamed_inventory_data<'a>(
    file: &'a FileInventory,
    name: &[u16],
) -> Result<&'a AttributeInventory> {
    let mut attrs = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x80 && a.name_utf16 == name);
    let value = attrs.next().context("canonical DATA attribute absent")?;
    ensure!(attrs.next().is_none(), "duplicate canonical DATA attribute");
    Ok(value)
}
pub(crate) fn read_resident_inventory_attribute_domain<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    file: &FileInventory,
    wanted: &AttributeInventory,
) -> Result<Vec<u8>> {
    ensure!(
        wanted.resident && wanted.logical_size <= source.budget().record_bytes,
        "resident source attribute exceeds admitted row"
    );
    let mapping = CheckedMftDomain::open(reader, source)?;
    mapping.resident_attribute(reader, source, file, wanted)
}

pub(super) fn checked_data_attribute_domain<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    number: u64,
    name: &[u16],
    max_bytes: u64,
    allow_sparse: bool,
) -> Result<(Attribute, Option<String>)> {
    let file = source
        .find_record(number, None)?
        .context("source file absent from complete inventory")?;
    ensure!(
        !file.is_directory && file.base_file_reference == 0,
        "plain standalone file required"
    );
    let stream = file
        .streams
        .iter()
        .find(|s| s.name_utf16 == name)
        .context("requested DATA stream absent")?;
    let expected = unnamed_inventory_data(&file, name)?;
    let geometry = &source.header().geometry;
    let compressed =
        stream.flags == 1 && crate::ntfs_compression::supported(expected, geometry).is_ok();
    let evidence = match stream.logical_hash_status {
        LogicalHashStatus::Complete => stream
            .logical_sha256
            .as_deref()
            .is_some_and(n2r_win32::content_digest::is_hex),
        LogicalHashStatus::NotReadExtentIdentityV1 => {
            stream.logical_sha256.is_none()
                && crate::ntfs_attestation::extent_identity_stream_request_domain(
                    source, &file, stream, true, true,
                )?
                .is_some()
        }
        _ => false,
    };
    ensure!(
        (stream.flags == 0 || (allow_sparse && stream.flags == 0x8000) || compressed)
            && evidence
            && stream.logical_size <= max_bytes,
        "unsupported stream or materialization budget"
    );
    let mapping = CheckedMftDomain::open(reader, source)?;
    let record = mapping.record(reader, source, number)?;
    same_identity(&record, &file)?;
    let mut attrs = record
        .attributes
        .into_iter()
        .filter(|a| a.report.type_code == 0x80 && a.report.name_utf16 == name);
    let data = attrs
        .next()
        .context("requested actual DATA attribute absent")?;
    ensure!(
        attrs.next().is_none()
            && data.report == *expected
            && ((data.report.flags == 0 && data.report.compression_unit == 0)
                || (allow_sparse
                    && data.report.flags == 0x8000
                    && !data.report.resident
                    && matches!(data.report.compression_unit, 0 | 4))
                || (compressed
                    && crate::ntfs_compression::supported(&data.report, geometry).is_ok()))
            && data.report.logical_size == stream.logical_size,
        "actual DATA attribute changed"
    );
    if allow_sparse
        || compressed
        || stream.logical_hash_status == LogicalHashStatus::NotReadExtentIdentityV1
    {
        ensure!(
            stream.flags == data.report.flags
                && stream.resident == data.report.resident
                && stream.initialized_size == data.report.initialized_size
                && stream.allocated_size == data.report.allocated_size
                && stream.extents == data.report.extents,
            "DATA stream inventory differs from actual attribute mapping"
        );
    }
    if !data.report.resident {
        validate_stream_mapping(&data.report, geometry)?;
    }
    Ok((data, stream.logical_sha256.clone()))
}
