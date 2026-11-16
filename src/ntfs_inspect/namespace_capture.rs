//! Legacy capture compatibility; paged capture uses an owning metadata domain.
use super::*;

#[cfg(windows)]
use {
    super::{
        paged_storage::{PagedMetadataRange, SourcePagePin, SourceScratch},
        record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
    },
    std::path::{Path, PathBuf},
};

/// Complete raw namespace facts in independent bounded metadata stores. A
/// successful capture is not namespace reconciliation or source admission.
#[cfg(windows)]
#[derive(Clone, Serialize, Deserialize)]
pub struct NamespacePagePins {
    pub schema_version: u32,
    pub directories: RecordStorePin,
    pub entries: RecordStorePin,
    pub upcase: SourcePagePin,
}

#[cfg(windows)]
pub struct PagedNamespaceDomain {
    directories: SortedRecordStore,
    entries: SortedRecordStore,
    upcase: PagedMetadataRange,
    pins: NamespacePagePins,
}
#[cfg(windows)]
impl PagedNamespaceDomain {
    pub fn open(pins: &NamespacePagePins, scratch: &SourceScratch) -> Result<Self> {
        ensure!(pins.schema_version == 1, "unknown paged namespace schema");
        let result = Self {
            directories: SortedRecordStore::open(&pins.directories, scratch)?,
            entries: SortedRecordStore::open(&pins.entries, scratch)?,
            upcase: PagedMetadataRange::open(&pins.upcase, scratch)?,
            pins: pins.clone(),
        };
        ensure!(
            result.upcase.byte_len() == 131_072,
            "complete paged $UpCase required"
        );
        let mut previous = None;
        let mut total_entries = 0u64;
        for ordinal in 0..result.directories.len() {
            let header: SourceDirectoryHeader = result.directories.get(ordinal)?;
            ensure!(
                previous.is_none_or(|number| number < header.record_number)
                    && header.record_number < 1 << 48
                    && header.sequence_number != 0
                    && result.directories.key(ordinal)? == namespace_key(header.record_number, 0),
                "namespace directory key/identity differs"
            );
            previous = Some(header.record_number);
            for entry in 0..header.entries {
                let link: crate::ntfs_namespace::Link = result.entries.get(total_entries)?;
                ensure!(
                    result.entries.key(total_entries)?
                        == namespace_key(header.record_number, entry)
                        && link.parent
                            == header.record_number | (u64::from(header.sequence_number) << 48),
                    "namespace entry ordinal/parent coverage differs"
                );
                total_entries = total_entries
                    .checked_add(1)
                    .context("namespace entry count overflow")?;
            }
        }
        ensure!(
            total_entries == result.entries.len(),
            "unclaimed namespace entries"
        );
        result.revalidate()?;
        Ok(result)
    }
    pub fn pins(&self) -> &NamespacePagePins {
        &self.pins
    }
    pub fn revalidate(&self) -> Result<()> {
        self.directories.revalidate()?;
        self.entries.revalidate()?;
        self.upcase.revalidate()
    }
}
#[cfg(windows)]
impl RootDirectoryDomain for PagedNamespaceDomain {
    fn directory_count(&self) -> u64 {
        self.directories.len()
    }
    fn directory(&self, ordinal: u64) -> Result<SourceDirectoryHeader> {
        self.directories.get(ordinal)
    }
    fn entry(&self, directory: u64, entry: u64) -> Result<crate::ntfs_namespace::Link> {
        let header: SourceDirectoryHeader = self.directories.get(directory)?;
        ensure!(
            entry < header.entries,
            "namespace entry outside complete directory"
        );
        self.entries
            .find(namespace_key(header.record_number, entry))?
            .context("complete namespace entry missing")
    }
    fn upcase(&self) -> &dyn SourceMetadataRange {
        &self.upcase
    }
    fn revalidate(&self) -> Result<()> {
        PagedNamespaceDomain::revalidate(self)
    }
}
#[cfg(windows)]
fn namespace_key(record: u64, entry: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&record.to_be_bytes());
    key[8..].copy_from_slice(&entry.to_be_bytes());
    key
}

/// The parser owns the output directory and source exclusion. This writer
/// retains only current index buffers and page windows, never all directories.
#[cfg(windows)]
pub(super) struct PagedNamespaceCapture {
    root: PathBuf,
    scratch: SourceScratch,
    directories: SortedRecordWriter,
    entries: SortedRecordWriter,
    upcase: Option<SourcePagePin>,
    previous_directory: Option<u64>,
    failed: bool,
}

/// One directory index attribute, held in memory while its index is walked.
#[cfg(windows)]
struct HeldAttribute {
    bytes: Vec<u8>,
    _ram: super::paged_storage::SourceRamLease,
}
#[cfg(windows)]
impl SourceMetadataRange for HeldAttribute {
    fn byte_len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(output.len())
            .filter(|end| *end <= self.bytes.len())
            .context("held index attribute read escapes its bytes")?;
        output.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
    fn revalidate(&self) -> Result<()> {
        Ok(())
    }
}
/// A directory's index is walked once and never read again. Writing its root,
/// allocation and bitmap to three scratch files, hashing each several times
/// and reopening them cost more than everything else in source inspection.
/// An index this small is held in memory instead; a larger one, or one the
/// memory ledger refuses, still goes through scratch files.
#[cfg(windows)]
const HELD_ATTRIBUTE_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(windows)]
pub(super) fn capture_attribute<R: Read + Seek>(
    reader: &mut R,
    attribute: &Attribute,
    geometry: &NtfsGeometry,
    path: &Path,
    purpose: [u8; 8],
    scratch: &SourceScratch,
    evidence: Option<&mut Sha256>,
) -> Result<SourcePagePin> {
    let mut input = attribute_input(reader, attribute, geometry, evidence)?;
    PagedMetadataRange::capture(
        path,
        purpose,
        &mut input,
        attribute.report.logical_size,
        scratch,
    )
}

/// The same bytes and the same evidence as [`capture_attribute`], in memory.
/// Returns None, having read nothing, when the attribute is too large to hold.
#[cfg(windows)]
fn hold_attribute<R: Read + Seek>(
    reader: &mut R,
    attribute: &Attribute,
    geometry: &NtfsGeometry,
    scratch: &SourceScratch,
    evidence: Option<&mut Sha256>,
) -> Result<Option<HeldAttribute>> {
    let length = attribute.report.logical_size;
    if length > HELD_ATTRIBUTE_BYTES {
        return Ok(None);
    }
    let Ok(ram) = scratch.lease_ram_if_room(length + 4096) else {
        return Ok(None);
    };
    let mut input = attribute_input(reader, attribute, geometry, evidence)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(length)?)?;
    bytes.resize(usize::try_from(length)?, 0);
    input.read_exact(&mut bytes)?;
    Ok(Some(HeldAttribute { bytes, _ram: ram }))
}

#[cfg(windows)]
struct AttributeInput<'a, R> {
    source: AttributeBitmapReader<'a, R>,
    evidence: Option<&'a mut Sha256>,
}
#[cfg(windows)]
impl<R: Read + Seek> Read for AttributeInput<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(output)?;
        if let Some(evidence) = &mut self.evidence {
            evidence.update(&output[..count]);
        }
        Ok(count)
    }
}

#[cfg(windows)]
fn attribute_input<'a, R: Read + Seek>(
    reader: &'a mut R,
    attribute: &'a Attribute,
    geometry: &'a NtfsGeometry,
    evidence: Option<&'a mut Sha256>,
) -> Result<AttributeInput<'a, R>> {
    let a = &attribute.report;
    ensure!(
        a.flags == 0 && a.compression_unit == 0 && a.lowest_vcn == 0,
        "metadata capture requires unencoded assembled attribute bytes"
    );
    if a.resident {
        let value = attribute
            .resident_value
            .as_deref()
            .context("resident metadata bytes absent")?;
        ensure!(
            a.extents.is_empty()
                && a.logical_size == value.len() as u64
                && a.initialized_size == a.logical_size
                && a.allocated_size == a.logical_size
                && a.resident_sha256.as_deref()
                    == Some(n2r_win32::content_digest::of(value).as_str()),
            "resident metadata length, digest or allocation differs (type {:#x}, name {:?})",
            a.type_code,
            a.name_utf16
        );
    } else {
        ensure!(
            attribute.resident_value.is_none(),
            "nonresident metadata carries resident bytes"
        );
        validate_stream_mapping(a, geometry)?;
    }
    ensure!(
        a.extents
            .iter()
            .all(|extent| extent.physical_offset.is_some()),
        "metadata capture cannot reinterpret sparse allocation"
    );
    Ok(AttributeInput {
        source: AttributeBitmapReader {
            reader,
            attribute,
            geometry,
            length: a.logical_size,
            position: 0,
        },
        evidence,
    })
}

#[cfg(windows)]
impl PagedNamespaceCapture {
    pub(super) fn new(root: &Path, scratch: &SourceScratch) -> Result<Self> {
        Ok(Self {
            root: root.to_path_buf(),
            scratch: scratch.clone(),
            directories: SortedRecordWriter::new(
                &root.join("namespace-directories"),
                *b"N2RNSD01",
                scratch,
            )?,
            entries: SortedRecordWriter::new(
                &root.join("namespace-entries"),
                *b"N2RNSE01",
                scratch,
            )?,
            upcase: None,
            previous_directory: None,
            failed: false,
        })
    }
    pub(super) fn observe<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        record: &Record,
        number: u64,
        geometry: &NtfsGeometry,
    ) -> Result<()> {
        ensure!(!self.failed, "paged namespace capture is poisoned");
        self.failed = true;
        self.read_record(reader, record, number, geometry)?;
        self.failed = false;
        Ok(())
    }
    fn read_record<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        record: &Record,
        number: u64,
        geometry: &NtfsGeometry,
    ) -> Result<()> {
        ensure!(
            record.base == 0 && !record.attributes.iter().any(|a| a.report.type_code == 0x20),
            "namespace requires fully assembled base records"
        );
        if number == 10 {
            ensure!(self.upcase.is_none(), "duplicate $UpCase capture");
            let table = unnamed(record, 0x80)?;
            ensure!(
                table.report.logical_size == 131_072,
                "complete $UpCase required"
            );
            require_bitmap_bytes(&table.report, 131_072)?;
            self.upcase = Some(capture_attribute(
                reader,
                table,
                geometry,
                &self.root.join("namespace-upcase.pages"),
                *b"N2RNSU01",
                &self.scratch,
                None,
            )?);
        }
        if record.flags & 2 == 0 {
            return Ok(());
        }
        ensure!(
            number < 1 << 48
                && record.sequence != 0
                && self
                    .previous_directory
                    .is_none_or(|previous| previous < number),
            "duplicate or unordered directory capture"
        );
        let mut attributes = std::collections::BTreeMap::new();
        for attribute in &record.attributes {
            if crate::ntfs_namespace::is_i30(&attribute.report.name_utf16)
                && [0x90, 0xa0, 0xb0].contains(&attribute.report.type_code)
            {
                ensure!(
                    attributes
                        .insert(attribute.report.type_code, attribute)
                        .is_none(),
                    "duplicate namespace attribute"
                );
            }
        }
        let root = attributes
            .get(&0x90)
            .context("directory lacks resident I30 root")?;
        ensure!(
            root.report.resident
                && (root.report.flags == 0 || directory_compression_root_policy(record, root)),
            "unsupported I30 root encoding"
        );
        let reference = number | (u64::from(record.sequence) << 48);
        let mut evidence = Sha256::new();
        evidence.update(b"ntfs2refs-I30-v1\0");
        evidence.update(reference.to_le_bytes());
        let root_bytes = root
            .resident_value
            .as_deref()
            .context("resident I30 bytes absent")?;
        evidence.update((root_bytes.len() as u64).to_le_bytes());
        evidence.update(root_bytes);
        // Each of the three ranges is held in memory when it can be, and
        // otherwise captured to a scratch file exactly as before. Either way
        // the same bytes are read in the same order into the same evidence.
        let scratch = self.scratch.clone();
        let held_root = scratch
            .lease_ram_if_room(root_bytes.len() as u64 + 4096)
            .ok()
            .map(|ram| HeldAttribute {
                bytes: root_bytes.to_vec(),
                _ram: ram,
            });
        let root_range = if held_root.is_some() {
            None
        } else {
            let pin = PagedMetadataRange::capture(
                &self.root.join(format!("i30-{number}-root.pages")),
                *b"N2RI30R1",
                &mut io::Cursor::new(root_bytes),
                root_bytes.len() as u64,
                &scratch,
            )?;
            Some(PagedMetadataRange::open(&pin, &scratch)?)
        };
        let allocation = attributes.get(&0xa0);
        let bitmap = attributes.get(&0xb0);
        ensure!(
            allocation.is_some() == bitmap.is_some(),
            "I30 allocation/bitmap pair incomplete"
        );
        let (held_allocation, allocation_range) = if let Some(attribute) = allocation {
            ensure!(
                !attribute.report.resident,
                "I30 allocation must be nonresident"
            );
            evidence.update(attribute.report.logical_size.to_le_bytes());
            match hold_attribute(reader, attribute, geometry, &scratch, Some(&mut evidence))? {
                Some(held) => (Some(held), None),
                None => {
                    let pin = capture_attribute(
                        reader,
                        attribute,
                        geometry,
                        &self.root.join(format!("i30-{number}-allocation.pages")),
                        *b"N2RI30A1",
                        &scratch,
                        Some(&mut evidence),
                    )?;
                    (None, Some(PagedMetadataRange::open(&pin, &scratch)?))
                }
            }
        } else {
            evidence.update(0u64.to_le_bytes());
            (None, None)
        };
        let (held_bitmap, bitmap_range) = if let Some(attribute) = bitmap {
            require_bitmap_bytes(&attribute.report, attribute.report.logical_size)?;
            evidence.update(attribute.report.logical_size.to_le_bytes());
            match hold_attribute(reader, attribute, geometry, &scratch, Some(&mut evidence))? {
                Some(held) => (Some(held), None),
                None => {
                    let pin = capture_attribute(
                        reader,
                        attribute,
                        geometry,
                        &self.root.join(format!("i30-{number}-bitmap.pages")),
                        *b"N2RI30B1",
                        &scratch,
                        Some(&mut evidence),
                    )?;
                    (None, Some(PagedMetadataRange::open(&pin, &scratch)?))
                }
            }
        } else {
            evidence.update(0u64.to_le_bytes());
            (None, None)
        };
        fn either<'a>(
            held: &'a Option<HeldAttribute>,
            paged: &'a Option<PagedMetadataRange>,
        ) -> Option<&'a dyn SourceMetadataRange> {
            match (held, paged) {
                (Some(held), _) => Some(held as &dyn SourceMetadataRange),
                (None, Some(paged)) => Some(paged as &dyn SourceMetadataRange),
                (None, None) => None,
            }
        }
        let mut ordinal = 0u64;
        let summary = crate::ntfs_index::paged::walk_ranges(
            SourceIndexRanges {
                root: either(&held_root, &root_range).context("directory index root absent")?,
                allocation: either(&held_allocation, &allocation_range),
                bitmap: either(&held_bitmap, &bitmap_range),
                initialized_allocation_bytes: allocation
                    .map_or(0, |attribute| attribute.report.initialized_size),
            },
            crate::ntfs_index::Profile::FILE_NAME,
            geometry.cluster_size,
            geometry.index_record_size,
            &scratch,
            &self.root.join(format!("i30-{number}-visited.bits")),
            |header, key, _| {
                ensure!(key.len() >= 68, "short FILE_NAME index key");
                let length = usize::from(key[64]);
                ensure!(
                    length > 0 && length <= 255 && key.len() == 66 + 2 * length && key[65] <= 3,
                    "invalid FILE_NAME index key"
                );
                let child = u64::from_le_bytes(
                    header
                        .get(..8)
                        .context("short index reference")?
                        .try_into()?,
                );
                let parent = u64::from_le_bytes(key[..8].try_into()?);
                let name: Vec<u16> = key[66..]
                    .chunks_exact(2)
                    .map(|word| u16::from_le_bytes([word[0], word[1]]))
                    .collect();
                ensure!(
                    child >> 48 != 0
                        && parent == reference
                        && !name.iter().any(|unit| [0, 47, 92].contains(unit))
                        && name != [46, 46]
                        && (name != [46] || number == 5 && child == parent),
                    "invalid namespace index name/reference"
                );
                self.entries.push(
                    namespace_key(number, ordinal),
                    &crate::ntfs_namespace::Link {
                        child,
                        parent,
                        namespace: key[65],
                        name,
                    },
                )?;
                ordinal = ordinal
                    .checked_add(1)
                    .context("namespace ordinal overflow")?;
                Ok(())
            },
        )?;
        ensure!(
            summary.entries == ordinal,
            "namespace entry capture incomplete"
        );
        self.directories.push(
            namespace_key(number, 0),
            &SourceDirectoryHeader {
                record_number: number,
                sequence_number: record.sequence,
                entries: ordinal,
                index_blocks: summary.index_blocks,
                evidence_sha256: hex::encode(evidence.finalize()),
            },
        )?;
        self.previous_directory = Some(number);
        Ok(())
    }
    pub(super) fn finish(self) -> Result<PagedNamespaceDomain> {
        ensure!(!self.failed, "cannot close partial namespace capture");
        let pins = NamespacePagePins {
            schema_version: 1,
            directories: self.directories.finish()?,
            entries: self.entries.finish()?,
            upcase: self.upcase.context("complete $UpCase not captured")?,
        };
        PagedNamespaceDomain::open(&pins, &self.scratch)
    }
}

#[derive(Default)]
pub(super) struct NamespaceCapture {
    pub(super) directories: Vec<crate::ntfs_namespace::Directory>,
    pub(super) upcase: Option<Vec<u16>>,
    pub(super) bytes_read: usize,
    pub(super) entries: usize,
    pub(super) name_units: usize,
    pub(super) failure: Option<String>,
    pub(super) incomplete_attributes: bool,
}

impl NamespaceCapture {
    pub(super) fn reserve(&mut self, bytes: u64) -> Result<()> {
        let total = (self.bytes_read as u64)
            .checked_add(bytes)
            .context("index byte budget overflow")?;
        ensure!(
            total <= crate::ntfs_namespace::MAX_INDEX_BYTES as u64,
            "global namespace read budget exceeded"
        );
        self.bytes_read = total as usize;
        Ok(())
    }

    pub(super) fn read<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        record: &Record,
        number: u64,
        geometry: &NtfsGeometry,
    ) -> Result<()> {
        use crate::ntfs_namespace as ns;
        ensure!(
            geometry.bytes_per_sector == 512
                && crate::ntfs_index::supports_cluster_size(geometry.cluster_size)
                && geometry.index_record_size == 4096,
            "raw namespace requires supported clusters, 512-byte sectors and 4 KiB index records"
        );
        if number == 10 {
            let table = unnamed(record, 0x80)?;
            ensure!(
                table.report.logical_size == 131_072,
                "complete 128 KiB $UpCase stream required"
            );
            require_bitmap_bytes(&table.report, 131_072)?;
            self.reserve(131_072)?;
            let bytes = read_small_attribute(reader, table, geometry, 131_072)?;
            self.upcase = Some(utf16(&bytes)?);
        }
        if record.flags & 2 == 0 {
            return Ok(());
        }
        ensure!(
            self.directories.len() < ns::MAX_DIRECTORIES,
            "directory count limit exceeded"
        );
        let mut attributes = std::collections::BTreeMap::new();
        for a in &record.attributes {
            if ns::is_i30(&a.report.name_utf16) && [0x90, 0xa0, 0xb0].contains(&a.report.type_code)
            {
                ensure!(
                    a.report.lowest_vcn == 0 && attributes.insert(a.report.type_code, a).is_none(),
                    "duplicate or unassembled I30 attribute"
                );
            }
        }
        let root = attributes
            .get(&0x90)
            .context("directory lacks $I30 INDEX_ROOT")?;
        ensure!(
            root.report.resident
                && (root.report.flags == 0 || directory_compression_root_policy(record, root)),
            "unsupported directory INDEX_ROOT encoding"
        );
        self.reserve(root.report.logical_size)?;
        let root_bytes = root
            .resident_value
            .as_deref()
            .context("missing resident INDEX_ROOT")?;
        let (allocation, initialized) = if let Some(a) = attributes.get(&0xa0) {
            ensure!(
                !a.report.resident && a.report.flags == 0,
                "unsupported INDEX_ALLOCATION encoding"
            );
            validate_stream_mapping(&a.report, geometry)?;
            ensure!(
                attributes.contains_key(&0xb0),
                "INDEX_ALLOCATION lacks its bitmap"
            );
            self.reserve(a.report.logical_size)?;
            (
                read_small_attribute(reader, a, geometry, ns::MAX_INDEX_BYTES as u64)?,
                a.report.initialized_size,
            )
        } else {
            (Vec::new(), 0)
        };
        let bitmap = if let Some(a) = attributes.get(&0xb0) {
            require_bitmap_bytes(&a.report, a.report.logical_size)?;
            self.reserve(a.report.logical_size)?;
            read_small_attribute(reader, a, geometry, 4096)?
        } else {
            Vec::new()
        };
        let directory = ns::parse_directory_with_cluster_size(
            number | (u64::from(record.sequence) << 48),
            root_bytes,
            &allocation,
            initialized,
            &bitmap,
            geometry.cluster_size,
        )?;
        self.entries = self
            .entries
            .checked_add(directory.entries.len())
            .context("global index entry overflow")?;
        self.name_units += directory
            .entries
            .iter()
            .map(|e| e.name.len())
            .sum::<usize>();
        ensure!(
            self.entries <= ns::MAX_ENTRIES && self.name_units <= ns::MAX_NAME_UNITS,
            "global namespace entry/name budget exceeded"
        );
        self.directories.push(directory);
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
            && (number == 10 || record.flags & 2 != 0)
            && let Err(error) = self.read(reader, record, number, geometry)
        {
            self.failure = Some(format!("MFT record {number}: {error:#}"));
        }
    }

    pub(super) fn finish(self, files: &[FileInventory]) -> crate::ntfs_namespace::Reconciliation {
        use crate::ntfs_namespace::{Reconciliation, Status};
        let mut hash = Sha256::new();
        hash.update(b"ntfs2refs-namespace-evidence-v1\0");
        if let Some(table) = &self.upcase {
            for unit in table {
                hash.update(unit.to_le_bytes());
            }
        }
        for dir in &self.directories {
            hash.update(dir.reference.to_le_bytes());
            hash.update(dir.evidence_sha256.as_bytes());
        }
        let mut result = Reconciliation {
            status: Status::Rejected,
            directories: self.directories.len(),
            index_blocks: self.directories.iter().map(|d| d.index_blocks).sum(),
            index_entries: self.entries,
            reachable_objects: 0,
            index_bytes_read: self.bytes_read,
            evidence_sha256: hex::encode(hash.finalize()),
            detail: String::new(),
        };
        if self.incomplete_attributes {
            result.status = Status::IncompleteAttributeInventory;
            result.detail = "Attribute-list or extension records require assembly before namespace reconciliation".into();
        } else if let Some(error) = self.failure {
            result.detail = error;
        } else if let Some(upcase) = self.upcase {
            match crate::ntfs_namespace::reconcile(files, &self.directories, &upcase) {
                Ok(reachable) => {
                    result.status = Status::ConsistentRawModel;
                    result.reachable_objects = reachable;
                    result.detail = "Allocated I30 nodes, key ordering, MFT names/references and root reachability reconcile; native enumeration remains unverified".into();
                }
                Err(error) => result.detail = format!("{error:#}"),
            }
        } else {
            result.detail = "No complete $UpCase table was captured".into();
        }
        result
    }
}
