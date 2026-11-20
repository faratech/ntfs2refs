//! Canonical raw files over a complete fixed-width disk index and bitmap facts.
use super::*;
use super::{
    paged_storage::{PagedMetadataRange, SourcePagePin, SourceRamLease, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore},
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    sync::Arc,
};

struct CachedDirectory {
    // Shared, so that a caller can be lent the row after the cache's borrow
    // has ended and may ask this domain for other rows meanwhile.
    file: Arc<FileInventory>,
    charged: u64,
    last_used: u64,
    // The retained row is dropped before its memory credit.
    _ram: SourceRamLease,
}
#[derive(Default)]
struct DirectoryRowCache {
    rows: BTreeMap<u64, CachedDirectory>,
    charged: u64,
    clock: u64,
}
impl DirectoryRowCache {
    fn clear(&mut self) {
        self.rows.clear();
        self.charged = 0;
        self.clock = 0;
    }
    /// Drops the least recently used quarter of the rows (at least one).
    /// Dropping only the single oldest meant a scan of the whole cache for
    /// every row added once it was full.
    fn evict_oldest(&mut self) -> bool {
        if self.rows.is_empty() {
            return false;
        }
        let mut used: Vec<u64> = self.rows.values().map(|row| row.last_used).collect();
        let cut = used.len() / 4;
        used.select_nth_unstable(cut);
        let threshold = used[cut];
        let mut freed = 0u64;
        self.rows.retain(|_, row| {
            if row.last_used <= threshold {
                freed += row.charged;
                false
            } else {
                true
            }
        });
        self.charged -= freed;
        true
    }
}

/// The row that was decoded last, of whatever kind.
///
/// The steps that go through a volume object by object ask for one object's
/// row several times over: for its identity, then for its transaction
/// marker, then for its object id, then for its streams; a stream's reader
/// asks for the row of the file it reads. Every one of those was a decode of
/// the whole row from its JSON, and together they were 106 s of a full
/// Windows conversion. The row decoded last is held, and whoever asks for
/// the same one next is given that.
struct LastRow {
    ordinal: u64,
    file: Arc<FileInventory>,
    // The retained row is dropped before its memory credit.
    _ram: SourceRamLease,
}

/// The rows of the file store decoded so far, by ordinal.
///
/// A conversion goes through the whole store some twenty-seven times, and
/// every pass decoded every row from its JSON again: between two and five
/// decodes an object in each phase, 340,000 to 680,000 of them a phase on
/// the full Windows volume. The store cannot change while it is open and its
/// pages are checked as they are loaded, so a row decoded once is kept and
/// handed out shared. The memory is optional
/// ([`SourceScratch::lease_optional_ram`]), paid for a block at a time and
/// charged by what each row holds; when a block is refused, what is kept
/// stays, the other rows are decoded as before (the row decoded last and the
/// directories are still held as they were), and a block is asked for again
/// a few thousand rows later. Inside the gate before the first write to the
/// source, and without the check-once policy, nothing is served from here
/// and nothing is added.
#[derive(Default)]
struct DecodedRows {
    // Declared before the blocks, so the rows are dropped before the
    // credit that pays for them.
    rows: Vec<Option<Arc<FileInventory>>>,
    leases: Vec<SourceRamLease>,
    unspent: u64,
    // Rows still to pass by before a block is asked for again.
    refused_for: u32,
}
/// The decoded rows as a cache of the run: given up, with the blocks that
/// pay for them, when memory is short ([`n2r_win32::evict`]).
struct DecodedRowCache {
    state: RefCell<DecodedRows>,
    last_used: Cell<u64>,
    // The record number and ordinal of the row served last from here: who
    // asks for that record next by its number needs no search for its place.
    last_served: Cell<Option<(u64, u64)>>,
}
impl DecodedRowCache {
    /// Gives up every row and block, for a store whose rows are replaced or
    /// whose memory is wanted back.
    fn clear(&self) {
        self.last_served.set(None);
        let taken = {
            let mut decoded = self.state.borrow_mut();
            decoded.unspent = 0;
            decoded.refused_for = 0;
            (
                std::mem::take(&mut decoded.rows),
                std::mem::take(&mut decoded.leases),
            )
        };
        // The rows before the blocks that paid for them.
        drop(taken);
    }
}
impl n2r_win32::evict::Evict for DecodedRowCache {
    fn last_used(&self) -> u64 {
        self.last_used.get()
    }
    fn evict(&self) -> bool {
        // Borrowed means in use at this moment: left alone. What is taken
        // is dropped after the borrow has ended, the rows before the blocks
        // that paid for them.
        let taken = match self.state.try_borrow_mut() {
            Ok(mut decoded) if !decoded.leases.is_empty() => {
                decoded.unspent = 0;
                // Memory was short: not asked for again at once.
                decoded.refused_for = DECODED_ROW_RETRY_ROWS;
                Some((
                    std::mem::take(&mut decoded.rows),
                    std::mem::take(&mut decoded.leases),
                ))
            }
            _ => None,
        };
        if taken.is_some() {
            self.last_served.set(None);
        }
        taken.is_some()
    }
}
const DECODED_ROW_BLOCK_BYTES: u64 = 16 * 1024 * 1024;
const DECODED_ROW_RETRY_ROWS: u32 = 4096;
/// Beside what a row holds on the heap: the row itself, the counts it is
/// shared by and what the allocator keeps for it.
const DECODED_ROW_OVERHEAD_BYTES: u64 = std::mem::size_of::<FileInventory>() as u64 + 64;

pub(super) fn file_key(number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key
}

pub struct PagedRawFiles {
    header: SourceHeader,
    files: SortedRecordStore,
    allocated: Box<dyn SourceMetadataRange>,
    extensions: PagedMetadataRange,
    extension_pin: SourcePagePin,
    scratch: SourceScratch,
    directory_rows: RefCell<DirectoryRowCache>,
    last_row: RefCell<Option<LastRow>>,
    // Rows already decoded from the store, while the run can spare the
    // memory.
    decoded: Rc<DecodedRowCache>,
}
impl PagedRawFiles {
    pub(super) fn from_live_bitmap(
        header: SourceHeader,
        files: &RecordStorePin,
        allocated: Box<dyn SourceMetadataRange>,
        extensions: &SourcePagePin,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        ensure!(
            header.schema_version == 2
                && header.mft_record_count > 6
                && header.mft_record_count <= 1 << 48
                && header.records_scanned <= header.mft_record_count,
            "paged source intrinsic MFT domain differs"
        );
        let value = Self {
            header,
            files: SortedRecordStore::open(files, scratch)?,
            allocated,
            extensions: PagedMetadataRange::open(extensions, scratch)?,
            extension_pin: extensions.clone(),
            scratch: scratch.clone(),
            directory_rows: RefCell::new(DirectoryRowCache::default()),
            last_row: RefCell::new(None),
            decoded: {
                let decoded = Rc::new(DecodedRowCache {
                    state: RefCell::new(DecodedRows::default()),
                    last_used: Cell::new(n2r_win32::evict::now()),
                    last_served: Cell::new(None),
                });
                n2r_win32::evict::register(&decoded);
                decoded
            },
        };
        value.validate_complete_files()?;
        Ok(value)
    }
    pub fn file_pin(&self) -> &RecordStorePin {
        self.files.pin()
    }
    pub fn extension_pin(&self) -> &SourcePagePin {
        &self.extension_pin
    }
    pub fn budget(&self) -> SourceMetadataBudget {
        self.scratch.budget()
    }
    pub(super) fn release_inventory_resident_cache(&mut self) {
        // Projection consumes file records sequentially, but it also walks
        // parents and security rows, and later stages look files up in every
        // order. Release the full file-data copy and its RAM credit only when
        // it is a large share of the budget.
        if self.files.pin().data.logical_bytes > self.scratch.budget().ram_bytes / 8 {
            self.files.clear_resident_cache();
        }
        self.last_row.get_mut().take();
        // The decoded rows are memory of the same kind: returned before the
        // projection pays for its rows and sorters, and kept again as its
        // passes decode them.
        self.decoded.clear();
    }
    pub(super) fn set_header(&mut self, header: SourceHeader) -> Result<()> {
        ensure!(
            header.schema_version == self.header.schema_version
                && header.geometry == self.header.geometry
                && header.mft_record_count == self.header.mft_record_count
                && header.records_scanned == self.header.records_scanned,
            "source summary cannot rebind its physical file domain"
        );
        self.header = header;
        Ok(())
    }
    pub(super) fn replace_files(&mut self, pin: &RecordStorePin) -> Result<()> {
        ensure!(
            pin.records == self.files.len() && pin.data.path != self.files.pin().data.path,
            "source row replacement cannot change its complete identity domain"
        );
        // Replacement changes roles or hash evidence. Never serve an old row,
        // and return optional cache credit before opening replacement pages.
        self.directory_rows.get_mut().clear();
        self.last_row.get_mut().take();
        self.decoded.clear();
        self.files.clear_resident_cache();
        let replacement = SortedRecordStore::open(pin, &self.scratch)?;
        for ordinal in 0..replacement.len() {
            ensure!(
                replacement.key(ordinal)? == self.files.key(ordinal)?,
                "source row replacement changed a canonical identity"
            );
        }
        let old = self.files.pin().clone();
        self.files = replacement;
        self.validate_complete_files()?;
        self.scratch.retire_created(&old.data)?;
        self.scratch.retire_created(&old.directory)?;
        Ok(())
    }
    pub(super) fn ordinal(&self, number: u64) -> Result<Option<u64>> {
        let key = file_key(number);
        let (mut low, mut high) = (0, self.files.len());
        while low < high {
            let mid = low + (high - low) / 2;
            match self.files.key(mid)?.cmp(&key) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
            }
        }
        Ok(None)
    }
    pub(super) fn record_wire_bytes(&self, number: u64) -> Result<Option<u64>> {
        self.ordinal(number)?
            .map(|ordinal| self.files.record_bytes(ordinal))
            .transpose()
    }
    pub(super) fn ordinal_wire_bytes(&self, ordinal: u64) -> Result<u64> {
        self.files.record_bytes(ordinal)
    }
    /// Whether decoded rows are kept and served again: under the check-once
    /// policy, outside its gate.
    fn serves_decoded(&self) -> bool {
        !n2r_win32::verify_policy::full_unremembered()
    }
    /// Keeps `file`, decoded from the row at `ordinal` and held to its key,
    /// to be served again. Returns whether it is kept: a refusal leaves the
    /// row to its caller as before.
    fn keep_decoded(&self, ordinal: u64, file: &Arc<FileInventory>) -> bool {
        if !self.serves_decoded() {
            return false;
        }
        let (Ok(index), Ok(count)) = (usize::try_from(ordinal), usize::try_from(self.files.len()))
        else {
            return false;
        };
        if index >= count {
            return false;
        }
        self.decoded.last_used.set(n2r_win32::evict::now());
        let mut decoded = self.decoded.state.borrow_mut();
        if decoded.rows.get(index).is_some_and(Option::is_some) {
            return true;
        }
        if decoded.refused_for > 0 {
            decoded.refused_for -= 1;
            return false;
        }
        let Some(mut bytes) = file_heap_bytes(file)
            .ok()
            .and_then(|heap| heap.checked_add(DECODED_ROW_OVERHEAD_BYTES))
        else {
            return false;
        };
        let slots = decoded.rows.is_empty();
        if slots {
            bytes = bytes.saturating_add(
                (count as u64)
                    .saturating_mul(std::mem::size_of::<Option<Arc<FileInventory>>>() as u64),
            );
        }
        if decoded.unspent < bytes {
            let block = DECODED_ROW_BLOCK_BYTES.max(bytes);
            // Optional cache pressure must not become a source admission
            // limit: a refusal is the ordinary answer of a full ledger.
            match self.scratch.lease_optional_ram(block) {
                Ok(lease) => {
                    decoded.leases.push(lease);
                    decoded.unspent += block;
                }
                Err(_) => {
                    decoded.refused_for = DECODED_ROW_RETRY_ROWS;
                    return false;
                }
            }
        }
        if slots {
            if decoded.rows.try_reserve_exact(count).is_err() {
                decoded.refused_for = DECODED_ROW_RETRY_ROWS;
                return false;
            }
            decoded.rows.resize_with(count, || None);
        }
        decoded.unspent -= bytes;
        decoded.rows[index] = Some(Arc::clone(file));
        self.decoded
            .last_served
            .set(Some((file.record_number, ordinal)));
        true
    }
    /// The row at `ordinal` if it is held, as one of the rows decoded
    /// before, as one of the directories or as the row decoded last, and the
    /// key that the row at `ordinal` must have.
    fn held_row(&self, ordinal: u64) -> Result<(Option<Arc<FileInventory>>, [u8; 16])> {
        // Ordinal callers (notably ancestry DFS parent visits) must share the
        // same bounded directory cache as record-number callers. The complete
        // held ordinal index still establishes the identity on every hit.
        let key = self.files.key(ordinal)?;
        let number = u64::from_be_bytes(key[..8].try_into()?);
        ensure!(
            key == file_key(number),
            "canonical ordinal key is not a file identity"
        );
        if self.serves_decoded() {
            let held = usize::try_from(ordinal).ok().and_then(|index| {
                self.decoded
                    .state
                    .borrow()
                    .rows
                    .get(index)
                    .and_then(Option::as_ref)
                    .map(Arc::clone)
            });
            if let Some(row) = held {
                ensure!(
                    row.record_number == number,
                    "decoded row differs from its canonical ordinal"
                );
                self.decoded.last_used.set(n2r_win32::evict::now());
                self.decoded.last_served.set(Some((number, ordinal)));
                return Ok((Some(row), key));
            }
        }
        {
            let mut cache = self.directory_rows.borrow_mut();
            cache.clock = cache.clock.saturating_add(1);
            let last_used = cache.clock;
            if let Some(row) = cache.rows.get_mut(&number) {
                ensure!(
                    row.file.record_number == number,
                    "cached directory differs from its canonical ordinal"
                );
                row.last_used = last_used;
                return Ok((Some(Arc::clone(&row.file)), key));
            }
        }
        if let Some(last) = self
            .last_row
            .borrow()
            .as_ref()
            .filter(|last| last.ordinal == ordinal)
        {
            ensure!(
                last.file.record_number == number,
                "held row differs from its canonical ordinal"
            );
            return Ok((Some(Arc::clone(&last.file)), key));
        }
        Ok((None, key))
    }
    /// Decodes the row at `ordinal`, which must carry `key`.
    fn decode_row(&self, ordinal: u64, key: [u8; 16]) -> Result<FileInventory> {
        let file: FileInventory = self.files.get(ordinal)?;
        ensure!(
            file_key(file.record_number) == key,
            "canonical ordinal row identity differs"
        );
        Ok(file)
    }
    /// The row at `ordinal`, shared: a held one, or the row decoded now,
    /// which is then held in its turn. For callers that are lent the row,
    /// for those that keep it shared and for those that look a record up by
    /// its number: all come back to the same row. A caller that wants a row
    /// of its own to change uses [`RootFileDomain::file`], which copies a
    /// held one for it.
    fn row(&self, ordinal: u64) -> Result<Arc<FileInventory>> {
        let (held, key) = self.held_row(ordinal)?;
        if let Some(row) = held {
            return Ok(row);
        }
        let file = Arc::new(self.decode_row(ordinal, key)?);
        self.retain_directory(ordinal, &file)?;
        // A row kept with the decoded rows is not held as the last one as
        // well: it is found there, and its place is remembered with it.
        if !self.keep_decoded(ordinal, &file) {
            self.retain_last(ordinal, &file)?;
        }
        Ok(file)
    }
    /// The ordinal of the row decoded or served last, if it is the record
    /// `number`: asking for that record again needs no search for its place.
    fn last_ordinal_of(&self, number: u64) -> Option<u64> {
        if let Some(ordinal) = self
            .last_row
            .borrow()
            .as_ref()
            .filter(|last| last.file.record_number == number)
            .map(|last| last.ordinal)
        {
            return Some(ordinal);
        }
        // The pair was read from the held index when the row was served, and
        // the row that is then asked for is held to that index again.
        self.decoded
            .last_served
            .get()
            .filter(|(served, _)| *served == number && self.serves_decoded())
            .map(|(_, ordinal)| ordinal)
    }
    /// Holds `file` as the row decoded last, in place of the one before. A
    /// directory is held with the directories and not here as well.
    fn retain_last(&self, ordinal: u64, file: &Arc<FileInventory>) -> Result<()> {
        if file.is_directory {
            return Ok(());
        }
        // The row before returns its credit before this one asks for its own.
        self.last_row.borrow_mut().take();
        let wire = self.files.record_bytes(ordinal)?;
        let slot = std::mem::size_of::<LastRow>() as u64 + 4096;
        let Some(charge) = wire
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(slot))
        else {
            return Ok(());
        };
        if charge > self.budget().ram_bytes / 32 {
            return Ok(());
        }
        let actual =
            file_heap_bytes(file)?.checked_add(std::mem::size_of::<FileInventory>() as u64);
        if actual.is_none_or(|bytes| bytes > charge - slot) {
            return Ok(());
        }
        // Holding a row is a saving, never a requirement of its own: a
        // refusal leaves the row to its caller as before.
        let Ok(ram) = self.scratch.lease_ram_if_room(charge) else {
            return Ok(());
        };
        *self.last_row.borrow_mut() = Some(LastRow {
            ordinal,
            file: Arc::clone(file),
            _ram: ram,
        });
        Ok(())
    }
    fn retain_directory(&self, ordinal: u64, file: &Arc<FileInventory>) -> Result<()> {
        if !file.is_directory {
            return Ok(());
        }
        let wire = self.files.record_bytes(ordinal)?;
        // Pay an oversized complete BTree node per row as well as the clone's
        // actual wire-derived bound. No file DATA contents live in this row.
        let node = (std::mem::size_of::<CachedDirectory>() as u64 + 8) * 16 + 4096;
        let Some(charge) = wire
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(node))
        else {
            return Ok(());
        };
        let limit = self.budget().ram_bytes / 32;
        if charge > limit {
            return Ok(());
        }
        let actual =
            file_heap_bytes(file)?.checked_add(std::mem::size_of::<FileInventory>() as u64);
        if actual.is_none_or(|bytes| bytes > charge - node) {
            return Ok(());
        }
        let mut cache = self.directory_rows.borrow_mut();
        if cache.rows.contains_key(&file.record_number) {
            return Ok(());
        }
        while cache.charged > limit - charge {
            if !cache.evict_oldest() {
                return Ok(());
            }
        }
        // Optional cache pressure must not become a source admission limit.
        // The ordinary read below already belongs to the caller's row budget.
        let Ok(ram) = self.scratch.lease_ram_if_room(charge) else {
            return Ok(());
        };
        let retained = Arc::clone(file);
        cache.clock = cache.clock.saturating_add(1);
        let last_used = cache.clock;
        cache.rows.insert(
            file.record_number,
            CachedDirectory {
                file: retained,
                charged: charge,
                last_used,
                _ram: ram,
            },
        );
        cache.charged += charge;
        Ok(())
    }
    fn bit(&self, range: &dyn SourceMetadataRange, number: u64) -> Result<bool> {
        ensure!(
            number < self.header.mft_record_count,
            "record-bit query escapes MFT"
        );
        let mut byte = [0];
        range.read_exact_at(number / 8, &mut byte)?;
        Ok(byte[0] & (1 << (number % 8)) != 0)
    }
    fn validate_complete_files(&self) -> Result<()> {
        self.revalidate()?;
        let bytes = self.header.mft_record_count.div_ceil(8);
        ensure!(
            self.allocated.byte_len() >= bytes && self.extensions.byte_len() == bytes,
            "complete physical record bitmap lengths differ"
        );
        let window = (u64::from(self.budget().page_bytes) / 4).clamp(1, 65536) as usize;
        let _ram = self.scratch.lease_ram(
            self.budget()
                .record_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(2 * window as u64))
                .context("file validation RAM overflow")?,
        )?;
        let mut allocated = Vec::new();
        allocated.try_reserve_exact(window)?;
        allocated.resize(window, 0);
        let mut extensions = Vec::new();
        extensions.try_reserve_exact(window)?;
        extensions.resize(window, 0);
        let (mut at, mut allocated_count, mut extension_count) = (0u64, 0u64, 0u64);
        while at < self.allocated.byte_len() {
            let n = (self.allocated.byte_len() - at).min(window as u64) as usize;
            self.allocated.read_exact_at(at, &mut allocated[..n])?;
            extensions[..n].fill(0);
            if at < bytes {
                let count = (bytes - at).min(n as u64) as usize;
                self.extensions
                    .read_exact_at(at, &mut extensions[..count])?;
            }
            for index in 0..n {
                let position = at + index as u64;
                let first = position
                    .checked_mul(8)
                    .context("record bitmap address overflow")?;
                let mask = if first >= self.header.mft_record_count {
                    0
                } else {
                    let bits = (self.header.mft_record_count - first).min(8) as u32;
                    ((1u16 << bits) - 1) as u8
                };
                ensure!(
                    allocated[index] & !mask == 0 && extensions[index] & !allocated[index] == 0,
                    "physical extension/free/tail bitmap conservation differs"
                );
                allocated_count += u64::from(allocated[index].count_ones());
                extension_count += u64::from(extensions[index].count_ones());
            }
            at += n as u64;
        }
        ensure!(
            allocated_count == self.header.records_scanned
                && self.files.len().checked_add(extension_count) == Some(allocated_count),
            "complete canonical and physical extension record counts differ"
        );
        let mut previous = None;
        for ordinal in 0..self.files.len() {
            let file: FileInventory = self.files.get(ordinal)?;
            ensure!(
                self.files.key(ordinal)? == file_key(file.record_number)
                    && previous.is_none_or(|n| n < file.record_number)
                    && file.base_file_reference == 0
                    && self.bit(self.allocated.as_ref(), file.record_number)?
                    && !self.bit(&self.extensions, file.record_number)?,
                "canonical source identity/key/allocation differs"
            );
            ensure!(
                file_heap_bytes(&file)?
                    .checked_add(std::mem::size_of::<FileInventory>() as u64)
                    .is_some_and(|n| n <= self.budget().record_bytes.saturating_mul(8)),
                "one source row exceeds its resource working window"
            );
            previous = Some(file.record_number);
            // Every row is decoded here and held to its key: the first pass
            // that asks for it need not decode it again.
            if self.serves_decoded() {
                self.keep_decoded(ordinal, &Arc::new(file));
            }
        }
        self.revalidate()
    }
}
impl RootFileDomain for PagedRawFiles {
    fn header(&self) -> &SourceHeader {
        &self.header
    }
    fn file_count(&self) -> u64 {
        self.files.len()
    }
    fn file(&self, ordinal: u64) -> Result<FileInventory> {
        // A held row is copied for a caller that wants one of its own. A row
        // that is not held is decoded; it is kept with the decoded rows
        // where they are kept, and a directory with the directories. A row
        // that nothing kept is handed over as it is, without a copy.
        let (held, key) = self.held_row(ordinal)?;
        if let Some(row) = held {
            return Ok(FileInventory::clone(&row));
        }
        let file = self.decode_row(ordinal, key)?;
        if !file.is_directory && !self.serves_decoded() {
            return Ok(file);
        }
        let file = Arc::new(file);
        self.retain_directory(ordinal, &file)?;
        self.keep_decoded(ordinal, &file);
        Ok(Arc::unwrap_or_clone(file))
    }
    /// The row the store holds decoded, not a copy of it: a pass that reads
    /// every row and changes none is handed the same row as the pass before
    /// it. Where decoded rows are not served (inside the gate, without the
    /// check-once policy) this is [`file`](Self::file), as it was.
    fn file_shared(&self, ordinal: u64) -> Result<Arc<FileInventory>> {
        if !self.serves_decoded() {
            return self.file(ordinal).map(Arc::new);
        }
        self.row(ordinal)
    }
    fn with_file<T>(
        &self,
        ordinal: u64,
        read: impl FnOnce(&FileInventory) -> Result<T>,
    ) -> Result<T> {
        read(&*self.row(ordinal)?)
    }
    fn find_record(&self, number: u64, sequence: Option<u16>) -> Result<Option<FileInventory>> {
        {
            let mut cache = self.directory_rows.borrow_mut();
            cache.clock = cache.clock.saturating_add(1);
            let last_used = cache.clock;
            if let Some(row) = cache.rows.get_mut(&number) {
                row.last_used = last_used;
                return Ok(
                    if sequence.is_none_or(|wanted| wanted == row.file.sequence_number) {
                        Some(FileInventory::clone(&row.file))
                    } else {
                        None
                    },
                );
            }
        }
        let ordinal = match self.last_ordinal_of(number) {
            Some(ordinal) => ordinal,
            None => match self.ordinal(number)? {
                Some(ordinal) => ordinal,
                None => return Ok(None),
            },
        };
        let file = self.row(ordinal)?;
        Ok(if sequence.is_none_or(|s| s == file.sequence_number) {
            Some(Arc::unwrap_or_clone(file))
        } else {
            None
        })
    }
    /// As [`find_record`](Self::find_record), handing out the row the store
    /// holds and not a copy of it. Where decoded rows are not served this is
    /// `find_record`, as it was.
    fn find_record_shared(
        &self,
        number: u64,
        sequence: Option<u16>,
    ) -> Result<Option<Arc<FileInventory>>> {
        if !self.serves_decoded() {
            return Ok(self.find_record(number, sequence)?.map(Arc::new));
        }
        let held = {
            let mut cache = self.directory_rows.borrow_mut();
            cache.clock = cache.clock.saturating_add(1);
            let last_used = cache.clock;
            cache.rows.get_mut(&number).map(|row| {
                row.last_used = last_used;
                Arc::clone(&row.file)
            })
        };
        let file = match held {
            Some(file) => file,
            None => {
                let ordinal = match self.last_ordinal_of(number) {
                    Some(ordinal) => ordinal,
                    None => match self.ordinal(number)? {
                        Some(ordinal) => ordinal,
                        None => return Ok(None),
                    },
                };
                self.row(ordinal)?
            }
        };
        Ok(sequence
            .is_none_or(|wanted| wanted == file.sequence_number)
            .then_some(file))
    }
    /// A directory row that is held is lent, not copied. Building one path
    /// asks for every directory above the object, and a copy of a row is a
    /// heap allocation for each of its names, streams and attributes: on the
    /// full Windows volume those copies were 28 s of the run.
    fn with_record<T>(
        &self,
        number: u64,
        sequence: Option<u16>,
        read: impl FnOnce(&FileInventory) -> Result<T>,
    ) -> Result<Option<T>> {
        let held = {
            let mut cache = self.directory_rows.borrow_mut();
            cache.clock = cache.clock.saturating_add(1);
            let last_used = cache.clock;
            cache.rows.get_mut(&number).map(|row| {
                row.last_used = last_used;
                Arc::clone(&row.file)
            })
        };
        let file = match held {
            Some(file) => file,
            None => {
                let ordinal = match self.last_ordinal_of(number) {
                    Some(ordinal) => ordinal,
                    None => match self.ordinal(number)? {
                        Some(ordinal) => ordinal,
                        None => return Ok(None),
                    },
                };
                self.row(ordinal)?
            }
        };
        if sequence.is_none_or(|wanted| wanted == file.sequence_number) {
            read(&file).map(Some)
        } else {
            Ok(None)
        }
    }
    fn allocated_record(&self, number: u64) -> Result<bool> {
        self.bit(self.allocated.as_ref(), number)
    }
    fn extension_record(&self, number: u64) -> Result<bool> {
        self.bit(&self.extensions, number)
    }
    fn revalidate(&self) -> Result<()> {
        self.files.revalidate()?;
        self.allocated.revalidate()?;
        self.extensions.revalidate()
    }
}
