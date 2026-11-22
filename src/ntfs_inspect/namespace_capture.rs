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
    fn find_directory_ordinal(&self, record_number: u64) -> Result<Option<u64>> {
        self.directories
            .find_ordinal(namespace_key(record_number, 0))
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
    fn entry_by_record(
        &self,
        _directory: u64,
        record_number: u64,
        entry: u64,
    ) -> Result<crate::ntfs_namespace::Link> {
        self.entries
            .find(namespace_key(record_number, entry))?
            .context("complete namespace entry missing")
    }
    fn entry_at(&self, global_ordinal: u64) -> Result<Option<crate::ntfs_namespace::Link>> {
        Ok(Some(self.entries.get(global_ordinal)?))
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
    // Where the evidence digests are made off the scan's thread, and the
    // directories whose rows wait for theirs, in order.
    ahead: Option<EvidenceAhead>,
    pending: std::collections::VecDeque<PendingDirectory>,
    // The index bytes handed to the worker and not yet hashed.
    in_flight: u64,
}

/// The SHA-256 evidence of the directories' indexes, made on a worker
/// thread while the scan goes on.
///
/// Each directory's evidence is a SHA-256 over its `$I30` root, allocation
/// and bitmap, and was made on the scan's thread as the index was read: a
/// second or more of the full Windows volume's scan, on a CPU without SHA
/// extensions. Where an index is held in memory, its bytes are hashed by
/// the worker once the index has been walked, from the digest of what came
/// before them; the directory's row waits, with every row after it, until
/// its digest is back, and the rows are written in their order. The bytes
/// handed over are paid as spare memory, within a small pool; where that
/// is refused, where an index is captured to a scratch file and where
/// there is no worker, the digest is made on the scan's thread, as before.
/// Either way it is the digest of the same bytes in the same order.
#[cfg(windows)]
struct EvidenceAhead {
    jobs: Option<std::sync::mpsc::SyncSender<(Sha256, Vec<EvidencePiece>)>>,
    done: std::sync::mpsc::Receiver<String>,
    worker: Option<std::thread::JoinHandle<()>>,
    _workspace: super::paged_storage::SourceRamLease,
}
#[cfg(windows)]
enum EvidencePiece {
    Length(u64),
    Bytes(Vec<u8>),
}
/// What follows the root in a directory's evidence while it is not hashed
/// yet: a length, or the bytes of the held allocation or bitmap.
#[cfg(windows)]
#[derive(Clone, Copy)]
enum EvidenceTail {
    Length(u64),
    Allocation,
    Bitmap,
}
/// A directory whose row is not written yet: its digest is being made, or
/// a directory before it waits for its own.
#[cfg(windows)]
struct PendingDirectory {
    header: SourceDirectoryHeader,
    waiting: bool,
    bytes: u64,
    _paid: Option<super::paged_storage::SourceRamLease>,
}
#[cfg(windows)]
impl EvidenceAhead {
    /// Directories whose digest the worker makes, at most at once.
    const IN_FLIGHT: usize = 256;
    /// The index bytes handed to it, at most at once.
    const POOL_BYTES: u64 = 64 * 1024 * 1024;
    /// The worker's thread.
    const WORKSPACE_BYTES: u64 = 2 * 1024 * 1024;
    fn start(scratch: &SourceScratch) -> Option<Self> {
        let workspace = scratch.lease_spare_ram(Self::WORKSPACE_BYTES).ok()?;
        let (jobs, received) =
            std::sync::mpsc::sync_channel::<(Sha256, Vec<EvidencePiece>)>(Self::IN_FLIGHT);
        let (finished, done) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("i30-evidence".into())
            .spawn(move || {
                let _sampled = n2r_win32::stack_sampler::helper();
                for (mut evidence, pieces) in received {
                    // Each piece's bytes are given up as they are hashed,
                    // before the digest goes back.
                    for piece in pieces {
                        match piece {
                            EvidencePiece::Length(length) => evidence.update(length.to_le_bytes()),
                            EvidencePiece::Bytes(bytes) => evidence.update(&bytes),
                        }
                    }
                    if finished.send(hex::encode(evidence.finalize())).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Self {
            jobs: Some(jobs),
            done,
            worker: Some(worker),
            _workspace: workspace,
        })
    }
}
#[cfg(windows)]
impl Drop for EvidenceAhead {
    fn drop(&mut self) {
        // Ends the worker on every path, errors among them.
        self.jobs.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
/// Hashes `tail` into `evidence`, in order, with the held bytes it names.
#[cfg(windows)]
fn hash_tail(
    evidence: &mut Sha256,
    tail: &[EvidenceTail],
    allocation: Option<&HeldAttribute>,
    bitmap: Option<&HeldAttribute>,
) -> Result<()> {
    for piece in tail {
        match piece {
            EvidenceTail::Length(length) => evidence.update(length.to_le_bytes()),
            EvidenceTail::Allocation => evidence.update(
                &allocation
                    .context("held I30 allocation absent from its evidence")?
                    .bytes,
            ),
            EvidenceTail::Bitmap => evidence.update(
                &bitmap
                    .context("held I30 bitmap absent from its evidence")?
                    .bytes,
            ),
        }
    }
    Ok(())
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
            ahead: EvidenceAhead::start(scratch),
            pending: std::collections::VecDeque::new(),
            in_flight: 0,
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
        // With the worker, what follows the root is hashed by it after the
        // walk, as long as every index is held; one that is captured to a
        // scratch file is hashed as it is read, after what came before it.
        let mut deferred = self.ahead.is_some();
        let mut tail = Vec::new();
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
            if deferred {
                tail.push(EvidenceTail::Length(attribute.report.logical_size));
            } else {
                evidence.update(attribute.report.logical_size.to_le_bytes());
            }
            match hold_attribute(
                reader,
                attribute,
                geometry,
                &scratch,
                (!deferred).then_some(&mut evidence),
            )? {
                Some(held) => {
                    if deferred {
                        tail.push(EvidenceTail::Allocation);
                    }
                    (Some(held), None)
                }
                None => {
                    if deferred {
                        hash_tail(&mut evidence, &tail, None, None)?;
                        tail.clear();
                        deferred = false;
                    }
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
            if deferred {
                tail.push(EvidenceTail::Length(0));
            } else {
                evidence.update(0u64.to_le_bytes());
            }
            (None, None)
        };
        let (held_bitmap, bitmap_range) = if let Some(attribute) = bitmap {
            require_bitmap_bytes(&attribute.report, attribute.report.logical_size)?;
            if deferred {
                tail.push(EvidenceTail::Length(attribute.report.logical_size));
            } else {
                evidence.update(attribute.report.logical_size.to_le_bytes());
            }
            match hold_attribute(
                reader,
                attribute,
                geometry,
                &scratch,
                (!deferred).then_some(&mut evidence),
            )? {
                Some(held) => {
                    if deferred {
                        tail.push(EvidenceTail::Bitmap);
                    }
                    (Some(held), None)
                }
                None => {
                    // What was put aside is hashed first: the bitmap is
                    // hashed as it is read, and nothing after it is left.
                    if deferred {
                        hash_tail(&mut evidence, &tail, held_allocation.as_ref(), None)?;
                        tail.clear();
                    }
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
            if deferred {
                tail.push(EvidenceTail::Length(0));
            } else {
                evidence.update(0u64.to_le_bytes());
            }
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
        self.queue_directory(
            SourceDirectoryHeader {
                record_number: number,
                sequence_number: record.sequence,
                entries: ordinal,
                index_blocks: summary.index_blocks,
                evidence_sha256: String::new(),
            },
            evidence,
            &tail,
            held_allocation,
            held_bitmap,
        )?;
        self.previous_directory = Some(number);
        Ok(())
    }
    /// Writes the directory's row once its evidence is made: here, or by
    /// the worker from `evidence` and the held bytes `tail` names, after
    /// every directory before it.
    fn queue_directory(
        &mut self,
        mut header: SourceDirectoryHeader,
        mut evidence: Sha256,
        tail: &[EvidenceTail],
        mut allocation: Option<HeldAttribute>,
        mut bitmap: Option<HeldAttribute>,
    ) -> Result<()> {
        let mut job = None;
        if !tail.is_empty() {
            let mut bytes = 0u64;
            for piece in tail {
                let held = match piece {
                    EvidenceTail::Length(_) => continue,
                    EvidenceTail::Allocation => allocation.as_ref(),
                    EvidenceTail::Bitmap => bitmap.as_ref(),
                };
                bytes = bytes
                    .checked_add(
                        held.context("held I30 bytes absent from their evidence")?
                            .bytes
                            .len() as u64,
                    )
                    .context("I30 evidence byte count overflow")?;
            }
            // Only indexes held in memory are worth the worker's while.
            if bytes > 0 && bytes <= EvidenceAhead::POOL_BYTES {
                // Room in the pool, and among the directories in flight, is
                // made by writing the oldest first.
                while (self.in_flight.saturating_add(bytes) > EvidenceAhead::POOL_BYTES
                    || self.pending.len() >= EvidenceAhead::IN_FLIGHT)
                    && self.write_next(true)?
                {}
                if let Ok(paid) = self.scratch.lease_spare_ram(bytes) {
                    let mut pieces = Vec::with_capacity(tail.len());
                    for piece in tail {
                        pieces.push(match piece {
                            EvidenceTail::Length(length) => EvidencePiece::Length(*length),
                            EvidenceTail::Allocation => EvidencePiece::Bytes(std::mem::take(
                                &mut allocation
                                    .as_mut()
                                    .context("held I30 allocation absent from its evidence")?
                                    .bytes,
                            )),
                            EvidenceTail::Bitmap => EvidencePiece::Bytes(std::mem::take(
                                &mut bitmap
                                    .as_mut()
                                    .context("held I30 bitmap absent from its evidence")?
                                    .bytes,
                            )),
                        });
                    }
                    job = Some((pieces, bytes, paid));
                }
            }
            if job.is_none() {
                hash_tail(&mut evidence, tail, allocation.as_ref(), bitmap.as_ref())?;
            }
        }
        // The bytes handed over are paid by the spare memory now; the held
        // attributes and what the ledger lent for them go.
        drop((allocation, bitmap));
        match job {
            Some((pieces, bytes, paid)) => {
                self.ahead
                    .as_ref()
                    .and_then(|ahead| ahead.jobs.as_ref())
                    .context("the I30 evidence worker is absent")?
                    .send((evidence, pieces))
                    .map_err(|_| anyhow::anyhow!("the I30 evidence worker stopped"))?;
                self.in_flight = self.in_flight.saturating_add(bytes);
                self.pending.push_back(PendingDirectory {
                    header,
                    waiting: true,
                    bytes,
                    _paid: Some(paid),
                });
            }
            None => {
                header.evidence_sha256 = hex::encode(evidence.finalize());
                if self.pending.is_empty() {
                    self.directories
                        .push(namespace_key(header.record_number, 0), &header)?;
                } else {
                    self.pending.push_back(PendingDirectory {
                        header,
                        waiting: false,
                        bytes: 0,
                        _paid: None,
                    });
                }
            }
        }
        self.write_ready(false)
    }
    /// Writes the oldest directory waiting once its digest is made; with
    /// `wait`, waits for it. False when there was none to write.
    fn write_next(&mut self, wait: bool) -> Result<bool> {
        let Some(front) = self.pending.front_mut() else {
            return Ok(false);
        };
        if front.waiting {
            let ahead = self
                .ahead
                .as_ref()
                .context("the I30 evidence worker is absent")?;
            let digest = if wait {
                ahead
                    .done
                    .recv()
                    .map_err(|_| anyhow::anyhow!("the I30 evidence worker stopped"))?
            } else {
                match ahead.done.try_recv() {
                    Ok(digest) => digest,
                    Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        anyhow::bail!("the I30 evidence worker stopped")
                    }
                }
            };
            front.header.evidence_sha256 = digest;
            front.waiting = false;
        }
        let written = self
            .pending
            .pop_front()
            .context("namespace directory in flight absent")?;
        self.directories.push(
            namespace_key(written.header.record_number, 0),
            &written.header,
        )?;
        self.in_flight = self.in_flight.saturating_sub(written.bytes);
        Ok(true)
    }
    /// Writes the directories whose digests are made, in order; with
    /// `wait`, every one.
    fn write_ready(&mut self, wait: bool) -> Result<()> {
        while self.write_next(wait)? {}
        Ok(())
    }
    pub(super) fn finish(mut self) -> Result<PagedNamespaceDomain> {
        ensure!(!self.failed, "cannot close partial namespace capture");
        self.write_ready(true)?;
        ensure!(
            self.pending.is_empty(),
            "namespace directories wait for their evidence"
        );
        drop(self.ahead.take());
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

#[cfg(all(test, windows))]
mod evidence_tests {
    use super::*;
    use crate::artifact_arena::{ArtifactArena, ArtifactGroup};

    const MIB: u64 = 1024 * 1024;

    /// A source scratch in a run's ledger, so that spare memory is had.
    fn scratch(directory: &Path) -> (ArtifactArena, SourceScratch) {
        let arena = ArtifactArena::new(
            &directory.join("arena"),
            n2r_win32::tree_resources::ResourceBudget {
                schema_version: 1,
                ram_bytes: 512 * MIB,
                scratch_bytes: 512 * MIB,
                page_bytes: 65536,
                max_row_bytes: 65536,
                retained_index_bytes: 32 * MIB,
                handle_slots: 1024,
            },
            &[],
        )
        .unwrap();
        let budget = SourceMetadataBudget {
            ram_bytes: 256 * MIB,
            scratch_bytes: 64 * MIB,
            page_bytes: 65536,
            record_bytes: 65536,
            merge_fan_in: 8,
        };
        let permit = arena
            .reserve_group(ArtifactGroup::Source, budget.scratch_bytes)
            .unwrap();
        let scratch = SourceScratch::new_in_arena(budget, permit).unwrap();
        (arena, scratch)
    }
    fn bytes(seed: u64, length: usize) -> Vec<u8> {
        (0..length as u64)
            .map(|n| (n.wrapping_mul(seed | 1) >> 3) as u8)
            .collect()
    }

    #[test]
    fn evidence_made_by_the_worker_is_the_evidence_made_in_order() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("arena")).unwrap();
        let (_arena, scratch) = scratch(directory.path());
        // The run's working files are under its ledger's directory.
        let namespace = directory.path().join("arena").join("namespace");
        std::fs::create_dir(&namespace).unwrap();
        let mut capture = PagedNamespaceCapture::new(&namespace, &scratch).unwrap();
        assert!(capture.ahead.is_some(), "the worker has its memory");
        let mut expected = Vec::new();
        // More directories than may be in flight at once, some without an
        // index allocation (hashed here), the others' handed to the worker.
        for number in 16..400u64 {
            let reference = number | 1 << 48;
            let root = bytes(number, 64 + number as usize % 50);
            let indexed = number % 3 != 0;
            let allocation = indexed.then(|| bytes(number * 7, 4096 * (1 + number as usize % 5)));
            let bitmap = indexed.then(|| bytes(number * 11, 8));
            let mut inline = Sha256::new();
            inline.update(b"ntfs2refs-I30-v1\0");
            inline.update(reference.to_le_bytes());
            inline.update((root.len() as u64).to_le_bytes());
            inline.update(&root);
            let mut evidence = inline.clone();
            let mut tail = Vec::new();
            for part in [&allocation, &bitmap] {
                let length = part.as_ref().map_or(0, Vec::len) as u64;
                inline.update(length.to_le_bytes());
                tail.push(EvidenceTail::Length(length));
                if let Some(part) = part {
                    inline.update(part);
                }
            }
            if indexed {
                tail.insert(1, EvidenceTail::Allocation);
                tail.push(EvidenceTail::Bitmap);
            }
            expected.push(hex::encode(inline.finalize()));
            let held = |bytes: Option<Vec<u8>>| {
                bytes.map(|bytes| HeldAttribute {
                    _ram: scratch.lease_ram(bytes.len() as u64 + 4096).unwrap(),
                    bytes,
                })
            };
            // Without the worker the tail is hashed here.
            if number == 100 {
                evidence = {
                    let mut here = evidence;
                    hash_tail(
                        &mut here,
                        &tail,
                        held(allocation.clone()).as_ref(),
                        held(bitmap.clone()).as_ref(),
                    )
                    .unwrap();
                    here
                };
                tail.clear();
            }
            capture
                .queue_directory(
                    SourceDirectoryHeader {
                        record_number: number,
                        sequence_number: 1,
                        entries: 0,
                        index_blocks: 0,
                        evidence_sha256: String::new(),
                    },
                    evidence,
                    &tail,
                    held(allocation),
                    held(bitmap),
                )
                .unwrap();
            assert!(capture.pending.len() <= EvidenceAhead::IN_FLIGHT);
            assert!(capture.in_flight <= EvidenceAhead::POOL_BYTES);
        }
        capture.write_ready(true).unwrap();
        assert!(capture.pending.is_empty() && capture.in_flight == 0);
        drop(capture.ahead.take());
        let store =
            SortedRecordStore::open(&capture.directories.finish().unwrap(), &scratch).unwrap();
        let written: Vec<String> = (0..store.len())
            .map(|ordinal| {
                let header: SourceDirectoryHeader = store.get(ordinal).unwrap();
                assert_eq!(header.record_number, 16 + ordinal);
                header.evidence_sha256
            })
            .collect();
        assert_eq!(written, expected);
    }
}
