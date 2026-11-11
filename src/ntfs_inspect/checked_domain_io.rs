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
    _assembly_ram: Option<paged_storage::SourceRamLease>,
}
struct CheckedRecord {
    record: Record,
    // The result can escape `record()`: keep all actual row/assembly leases
    // until its caller finishes using its attributes and resident values.
    _ram: paged_storage::SourceRamLease,
    _assembly_ram: Option<paged_storage::SourceRamLease>,
}
pub(crate) struct LeasedAttributeInventory {
    value: AttributeInventory,
    _ram: paged_storage::SourceRamLease,
    _assembly_ram: Option<paged_storage::SourceRamLease>,
}
impl std::ops::Deref for LeasedAttributeInventory {
    type Target = AttributeInventory;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
pub(crate) struct LeasedResidentBytes {
    value: Vec<u8>,
    _ram: paged_storage::SourceRamLease,
    _assembly_ram: Option<paged_storage::SourceRamLease>,
}
impl std::ops::Deref for LeasedResidentBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl AsRef<[u8]> for LeasedResidentBytes {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}
fn row_workspace(source: &PagedInspection, number: u64) -> Result<u64> {
    let (file, assembly) = source.checked_record_wire_sizes(number)?;
    file.checked_mul(32)
        .and_then(|n| n.checked_add(assembly.unwrap_or(0).checked_mul(32)?))
        .and_then(|n| {
            n.checked_add(u64::from(source.header().geometry.file_record_size).checked_mul(32)?)
        })
        .and_then(|n| n.checked_add(1024 * 1024))
        .with_context(|| format!("FILE {number} checked-row workspace overflow"))
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
) -> Result<paged_storage::SourceRamLease> {
    let geometry = &source.header().geometry;
    ensure!(
        expected.base.record_number == number
            && assembled_io::evidence(number, raw, record) == expected.base,
        "actual base record bytes/attributes differ from complete assembly ledger"
    );
    let working = source.budget().ram_bytes / 4;
    let limits = lists::AssemblyLimits::from_working_bytes(working, geometry.file_record_size)?;
    ensure!(
        expected.extensions.len() <= limits.extension_records
            && expected.list_value_hex.len()
                <= limits
                    .list_bytes
                    .checked_mul(2)
                    .context("actual assembly list limit overflow")?,
        "FILE {number} assembly exceeds its original admitted limits"
    );
    let extension_records = u64::try_from(expected.extensions.len())?
        .checked_add(1)
        .context("actual assembly record count overflow")?;
    let list_hex = u64::try_from(expected.list_value_hex.len())?;
    ensure!(
        list_hex.is_multiple_of(2),
        "actual assembly list encoding differs"
    );
    // Each extension can contribute resident bytes independently of its
    // serialized digest; include those actual record-size bounds as well as
    // replay/list decoding and cloned serialized evidence.
    let assembly_bytes = source
        .checked_record_wire_sizes(number)?
        .1
        .context("actual assembly wire size absent")?;
    let bytes = extension_records
        .checked_mul(u64::from(geometry.file_record_size))
        .and_then(|n| n.checked_mul(16))
        .and_then(|n| n.checked_add(assembly_bytes.checked_mul(64)?))
        .and_then(|n| n.checked_add(list_hex.checked_mul(8)?))
        .and_then(|n| n.checked_add(1024 * 1024))
        .with_context(|| format!("FILE {number} assembly workspace overflow"))?;
    let ram = source
        .lease_working_ram(bytes)
        .with_context(|| format!("FILE {number} actual assembly requires {bytes} bytes"))?;
    let list = unnamed(record, 0x20)?;
    lists::validate_list_resource(&list.report, geometry, limits)?;
    ensure!(
        list.report.logical_size == list_hex / 2,
        "actual attribute-list length differs from the captured assembly"
    );
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
            actual == *wanted
                && (parsed.flags == 1
                    || matches!(expected.schema_version, 8 | 9) && matches!(parsed.flags, 3 | 9)),
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
            matches!(expected.schema_version, 5 | 6 | 8 | 9) && expected.mft_bitmap_hex.is_none(),
            "resource ordinary assembly profile differs"
        );
        let assemble = if matches!(expected.schema_version, 8 | 9) {
            lists::assemble_attributes_resource
        } else {
            lists::assemble_streams_resource
        };
        assemble(expected.base.clone(), extensions, &value, geometry, limits)?
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
    Ok(ram)
}

/// Recently read stretches of the MFT. Every pass over the files reads each
/// file's record again, one uncached 4 KiB device read at a time: 124,000 of
/// them (77 s) for 26,000 objects. The source is frozen, so a stretch read
/// once is kept and its neighbours come with it. Not used inside the gate.
/// Bounded at 64 MiB; it holds no memory lease so that it cannot keep the
/// preparation arena alive.
const RECORD_WINDOW: u64 = 256 * 1024;
const RECORD_WINDOWS: usize = 256;
#[derive(Default)]
struct RecordWindows {
    source_pin: String,
    windows: BTreeMap<u64, Vec<u8>>,
    order: std::collections::VecDeque<u64>,
}
thread_local! {
    static RECORD_WINDOWS_CACHE: RefCell<RecordWindows> = RefCell::new(RecordWindows::default());
}

/// Reads one stretch of the MFT's data, through the window cache when the
/// policy allows and the stretch lies inside one window.
fn read_mft_bytes<R: Read + Seek>(
    reader: &mut R,
    data: &Attribute,
    source_pin: &str,
    offset: u64,
    output: &mut [u8],
    geometry: &NtfsGeometry,
) -> Result<()> {
    let window = offset / RECORD_WINDOW;
    let start = window * RECORD_WINDOW;
    let within = (offset - start) as usize;
    let available = data.report.initialized_size.min(data.report.logical_size);
    if !n2r_win32::verify_policy::may_reuse_frozen_reads()
        || within + output.len() > RECORD_WINDOW as usize
        || start >= available
    {
        RECORD_WINDOWS_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            cache.windows.clear();
            cache.order.clear();
        });
        return read_attribute_range(reader, data, offset, output, geometry);
    }
    let cached = RECORD_WINDOWS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.source_pin != source_pin {
            cache.source_pin = source_pin.to_owned();
            cache.windows.clear();
            cache.order.clear();
        }
        cache.windows.get(&window).and_then(|bytes| {
            bytes
                .get(within..within + output.len())
                .map(|bytes| output.copy_from_slice(bytes))
        })
    });
    if cached.is_some() {
        return Ok(());
    }
    let length = (available - start).min(RECORD_WINDOW) as usize;
    if within + output.len() > length {
        return read_attribute_range(reader, data, offset, output, geometry);
    }
    let mut bytes = vec![0; length];
    if read_attribute_range(reader, data, start, &mut bytes, geometry).is_err() {
        // Whatever stops the whole stretch being read must not stop the record.
        return read_attribute_range(reader, data, offset, output, geometry);
    }
    output.copy_from_slice(&bytes[within..within + output.len()]);
    RECORD_WINDOWS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.order.len() >= RECORD_WINDOWS {
            if let Some(oldest) = cache.order.pop_front() {
                cache.windows.remove(&oldest);
            }
        }
        cache.order.push_back(window);
        cache.windows.insert(window, bytes);
    });
    Ok(())
}

/// What opening the reader establishes about the MFT itself: where its data
/// lives and its own record. It holds no memory lease, so it can outlive the
/// reader that produced it.
struct VerifiedRoot {
    source_pin: String,
    data: Attribute,
    root: Record,
    assembly_bytes: Option<u64>,
}
thread_local! {
    static VERIFIED_ROOT: RefCell<Option<VerifiedRoot>> = const { RefCell::new(None) };
}
static ROOT_PACED: n2r_win32::verify_policy::Paced = n2r_win32::verify_policy::Paced::new();

impl CheckedMftDomain {
    pub(crate) fn open<R: Read + Seek>(reader: &mut R, source: &PagedInspection) -> Result<Self> {
        ensure!(
            source.header().inventory_complete,
            "complete paged source is required"
        );
        let geometry = &source.header().geometry;
        let working = row_workspace(source, 0)?;
        let ram = source
            .lease_working_ram(working)
            .with_context(|| format!("FILE 0 checked MFT open requires {working} bytes"))?;
        // Opening reads the boot sector, the MFT's own record and attribute
        // list, and hashes the whole MFT bitmap three times. It was done once
        // for every file, several times over. The source is frozen: keep what
        // one open established and repeat the open once a second, and always
        // inside the gate before the first source write.
        let source_pin = source.canonical_sha256()?;
        if !ROOT_PACED.due(1000) {
            let known = VERIFIED_ROOT.with(|cache| {
                cache
                    .borrow()
                    .as_ref()
                    .filter(|known| known.source_pin == source_pin)
                    .map(|known| {
                        (
                            known.data.clone(),
                            clone_record(&known.root),
                            known.assembly_bytes,
                        )
                    })
            });
            if let Some((data, root, assembly_bytes)) = known {
                let assembly_ram = assembly_bytes
                    .map(|bytes| source.lease_working_ram(bytes))
                    .transpose()
                    .context("FILE 0 checked MFT assembly memory")?;
                return Ok(Self {
                    data,
                    root,
                    source_pin,
                    _mapping_ram: ram,
                    _assembly_ram: assembly_ram,
                });
            }
        }
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::RecordReaderOpen);
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
        // Declare the optional assembly lease before the record so errors in
        // later validation drop the assembled record before its lease.
        let assembly_ram;
        let mut record = parse_record(raw.clone(), geometry)?;
        same_identity(&record, &file)?;
        assembly_ram = match source.assembly_for_record(0)? {
            Some(assembly) => Some(actual_assembly(
                reader,
                source,
                &data,
                0,
                &raw,
                &mut record,
                assembly,
            )?),
            None => {
                ensure!(
                    !record.attributes.iter().any(|a| a.report.type_code == 0x20),
                    "actual MFT unexpectedly requires an assembly"
                );
                None
            }
        };
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
        VERIFIED_ROOT.with(|cache| {
            *cache.borrow_mut() = Some(VerifiedRoot {
                source_pin: source_pin.clone(),
                data: data.clone(),
                root: clone_record(&record),
                assembly_bytes: assembly_ram.as_ref().map(|lease| lease.held_bytes()),
            });
        });
        ROOT_PACED.passed();
        Ok(Self {
            data,
            root: record,
            source_pin,
            _mapping_ram: ram,
            _assembly_ram: assembly_ram,
        })
    }
    fn record<R: Read + Seek>(
        &self,
        reader: &mut R,
        source: &PagedInspection,
        number: u64,
    ) -> Result<CheckedRecord> {
        ensure!(
            source.canonical_sha256()? == self.source_pin,
            "checked MFT owner changed"
        );
        let mut working = row_workspace(source, number)?;
        if number == 0 {
            for attribute in &self.root.attributes {
                working = working
                    .checked_add(
                        attribute
                            .resident_value
                            .as_ref()
                            .map_or(0, |v| v.capacity() as u64),
                    )
                    .context("root resident clone workspace overflow")?;
            }
        }
        let ram = source.lease_working_ram(working).with_context(|| {
            format!("FILE {number} checked-record operation requires {working} bytes")
        })?;
        if number == 0 {
            return Ok(CheckedRecord {
                record: clone_record(&self.root),
                _ram: ram,
                _assembly_ram: None,
            });
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
        let geometry = &source.header().geometry;
        let mut raw = vec![0; geometry.file_record_size as usize];
        read_mft_bytes(
            reader,
            &self.data,
            &self.source_pin,
            number
                .checked_mul(u64::from(geometry.file_record_size))
                .context("actual FILE offset overflow")?,
            &mut raw,
            geometry,
        )?;
        // The same ordering is required on all error paths after assembly.
        let assembly_ram;
        let mut record = parse_record(raw.clone(), geometry)?;
        same_identity(&record, &file)?;
        assembly_ram = match source.assembly_for_record(number)? {
            Some(assembly) => Some(actual_assembly(
                reader,
                source,
                &self.data,
                number,
                &raw,
                &mut record,
                assembly,
            )?),
            None => {
                ensure!(
                    !record.attributes.iter().any(|a| a.report.type_code == 0x20),
                    "actual FILE unexpectedly requires an assembly"
                );
                None
            }
        };
        let attrs: Vec<_> = record.attributes.iter().map(|a| a.report.clone()).collect();
        ensure!(
            attrs == file.attributes,
            "actual canonical FILE attributes changed"
        );
        Ok(CheckedRecord {
            record,
            _ram: ram,
            _assembly_ram: assembly_ram,
        })
    }
    pub(crate) fn data<R: Read + Seek>(
        &self,
        reader: &mut R,
        source: &PagedInspection,
        number: u64,
        name: &[u16],
    ) -> Result<LeasedAttributeInventory> {
        let CheckedRecord {
            record,
            _ram,
            _assembly_ram,
        } = self.record(reader, source, number)?;
        let mut attrs = record
            .attributes
            .into_iter()
            .filter(|a| a.report.type_code == 0x80 && a.report.name_utf16 == name);
        let attribute = attrs.next().context("actual DATA attribute absent")?;
        ensure!(attrs.next().is_none(), "duplicate actual DATA attribute");
        Ok(LeasedAttributeInventory {
            value: attribute.report,
            _ram,
            _assembly_ram,
        })
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
    ) -> Result<LeasedResidentBytes> {
        ensure!(
            wanted.resident && wanted.logical_size <= source.budget().record_bytes,
            "resident source attribute exceeds admitted row"
        );
        let CheckedRecord {
            record,
            _ram,
            _assembly_ram,
        } = self.record(reader, source, file.record_number)?;
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
        Ok(LeasedResidentBytes {
            value: actual
                .resident_value
                .context("actual resident bytes absent")?,
            _ram,
            _assembly_ram,
        })
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
) -> Result<LeasedResidentBytes> {
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
) -> Result<(
    Attribute,
    Option<String>,
    paged_storage::SourceRamLease,
    Option<paged_storage::SourceRamLease>,
)> {
    let file_workspace = row_workspace(source, number)?;
    let _file_ram = source.lease_working_ram(file_workspace).with_context(|| {
        format!("FILE {number} checked DATA inventory requires {file_workspace} bytes")
    })?;
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
                && (if source.is_windows_conversion() {
                    crate::ntfs_attestation::extent_identity_stream_request_windows_domain(
                        source, &file, stream,
                    )
                } else {
                    crate::ntfs_attestation::extent_identity_stream_request_domain(
                        source, &file, stream, true, true,
                    )
                })
                .with_context(|| {
                    format!("checked DATA extent selector at FILE {number} stream {name:?}",)
                })?
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
    let CheckedRecord {
        record,
        _ram,
        _assembly_ram,
    } = mapping.record(reader, source, number)?;
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
    Ok((data, stream.logical_sha256.clone(), _ram, _assembly_ram))
}
