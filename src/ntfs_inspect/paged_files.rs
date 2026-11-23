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
///
/// The optional memory of a run is one pool, a third of its budget, and
/// the expected tree's decoded objects are paid from it too, later in the
/// run. The rows are decoded first and would take all of it on a machine
/// with little memory, so they take no more than half of it
/// ([`DECODED_ROW_SHARE`]): the rows beyond that are decoded as before.
#[derive(Default)]
struct DecodedRows {
    // Declared before the blocks, so the rows are dropped before the
    // credit that pays for them.
    rows: Vec<Option<Arc<FileInventory>>>,
    // The rows of the store that replaces this one, by their ordinal there,
    // as this process serialized them ([`WrittenRows`]): not served until
    // that store is opened and they take the place of `rows`.
    written: Vec<Option<Arc<FileInventory>>>,
    leases: Vec<SourceRamLease>,
    // What the blocks hold together, and what of it no row has taken yet.
    leased: u64,
    unspent: u64,
    // Rows still to pass by before a block is asked for again.
    refused_for: u32,
}
impl DecodedRows {
    /// What holding `file` takes from the blocks.
    fn charge_of(file: &FileInventory) -> Option<u64> {
        file_heap_bytes(file)
            .ok()?
            .checked_add(DECODED_ROW_OVERHEAD_BYTES)
    }
    /// What the slots of `count` rows take from the blocks.
    fn slots_charge(count: usize) -> u64 {
        (count as u64).saturating_mul(std::mem::size_of::<Option<Arc<FileInventory>>>() as u64)
    }
    /// Gives `bytes` back to the blocks, no more than they hold.
    fn credit(&mut self, bytes: u64) {
        self.unspent = self.unspent.saturating_add(bytes).min(self.leased);
    }
    /// Holds `file` at `index` of the rows served (or, with `written`, of
    /// the rows written for the replacement), which have `count` slots. It
    /// is paid from the blocks; where they are spent another is asked for,
    /// within `share` bytes of blocks, as optional memory. False where it is
    /// not held: the row is then decoded where it is asked for, as before.
    fn hold(
        &mut self,
        written: bool,
        index: usize,
        count: usize,
        file: &Arc<FileInventory>,
        scratch: &SourceScratch,
        share: u64,
    ) -> bool {
        let slots = if written { &self.written } else { &self.rows };
        if slots.get(index).is_some_and(Option::is_some) {
            return true;
        }
        let first = slots.is_empty();
        if self.refused_for > 0 {
            self.refused_for -= 1;
            return false;
        }
        let Some(mut bytes) = Self::charge_of(file) else {
            return false;
        };
        if first {
            bytes = bytes.saturating_add(Self::slots_charge(count));
        }
        if self.unspent < bytes {
            let block = DECODED_ROW_BLOCK_BYTES.max(bytes);
            // The rows keep to their share of the optional memory, and
            // optional cache pressure must not become a source admission
            // limit: a refusal is the ordinary answer of a full ledger.
            let within_share = self
                .leased
                .checked_add(block)
                .is_some_and(|leased| leased <= share);
            match within_share
                .then(|| scratch.lease_optional_ram(block).ok())
                .flatten()
            {
                Some(lease) => {
                    self.leases.push(lease);
                    self.leased += block;
                    self.unspent += block;
                }
                None => {
                    self.refused_for = DECODED_ROW_RETRY_ROWS;
                    return false;
                }
            }
        }
        let slots = if written {
            &mut self.written
        } else {
            &mut self.rows
        };
        if first {
            if slots.try_reserve_exact(count).is_err() {
                self.refused_for = DECODED_ROW_RETRY_ROWS;
                return false;
            }
            slots.resize_with(count, || None);
        }
        let Some(slot) = slots.get_mut(index) else {
            return false;
        };
        *slot = Some(Arc::clone(file));
        self.unspent -= bytes;
        true
    }
    /// Takes the row at `index` out of the rows served, giving back to the
    /// blocks what it was paid with.
    fn take(&mut self, index: usize) -> Option<Arc<FileInventory>> {
        let row = self.rows.get_mut(index)?.take()?;
        if let Some(bytes) = Self::charge_of(&row) {
            self.credit(bytes);
        }
        Some(row)
    }
    /// Drops the rows written for a replacement, giving back what they were
    /// paid with.
    fn drop_written(&mut self) {
        let written = std::mem::take(&mut self.written);
        let mut freed = Self::slots_charge(written.len());
        for row in written.iter().flatten() {
            freed = freed.saturating_add(Self::charge_of(row).unwrap_or(0));
        }
        drop(written);
        self.credit(freed);
    }
    /// The rows written for the replacement, a store of `count` rows, become
    /// the rows served; the rows before them are dropped, and the blocks no
    /// row needs any more are given back.
    fn promote_written(&mut self, count: usize) {
        let old = std::mem::replace(&mut self.rows, std::mem::take(&mut self.written));
        let mut freed = Self::slots_charge(old.len());
        for row in old.iter().flatten() {
            freed = freed.saturating_add(Self::charge_of(row).unwrap_or(0));
        }
        drop(old);
        self.credit(freed);
        if self.rows.len() > count {
            // A writer may have had room for more rows than it wrote: the
            // slots beyond the store are given back.
            let beyond = self.rows.split_off(count);
            let mut freed = Self::slots_charge(beyond.len());
            for row in beyond.iter().flatten() {
                freed = freed.saturating_add(Self::charge_of(row).unwrap_or(0));
            }
            drop(beyond);
            self.rows.shrink_to_fit();
            self.credit(freed);
        } else if self.rows.len() < count && !self.rows.is_empty() {
            // Not a store of these rows: nothing of it is held.
            self.drop_rows();
        }
        while let Some(last) = self.leases.last() {
            let bytes = last.held_bytes();
            if bytes > self.unspent {
                break;
            }
            self.leases.pop();
            self.leased -= bytes;
            self.unspent -= bytes;
        }
    }
    /// Gives up every row and block.
    fn drop_rows(&mut self) {
        self.leased = 0;
        self.unspent = 0;
        let taken = (
            std::mem::take(&mut self.rows),
            std::mem::take(&mut self.written),
            std::mem::take(&mut self.leases),
        );
        // The rows before the blocks that paid for them.
        drop(taken);
    }
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
            decoded.leased = 0;
            decoded.unspent = 0;
            decoded.refused_for = 0;
            (
                std::mem::take(&mut decoded.rows),
                std::mem::take(&mut decoded.written),
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
                decoded.leased = 0;
                decoded.unspent = 0;
                // Memory was short: not asked for again at once.
                decoded.refused_for = DECODED_ROW_RETRY_ROWS;
                Some((
                    std::mem::take(&mut decoded.rows),
                    std::mem::take(&mut decoded.written),
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
/// The part of the RAM budget the decoded rows may hold: a sixth, which is
/// half of what all optional caches of a run may hold together.
const DECODED_ROW_SHARE: u64 = 6;
/// Beside what a row holds on the heap: the row itself, the counts it is
/// shared by and what the allocator keeps for it.
const DECODED_ROW_OVERHEAD_BYTES: u64 = std::mem::size_of::<FileInventory>() as u64 + 64;

pub(super) fn file_key(number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key
}

/// The rows of a file store as this process serialized them, kept for the
/// opening of that store: it takes them as its decoded rows instead of
/// decoding every row from its JSON again.
///
/// The inspection writes the file store three times (the MFT scan, the
/// roles and the stream evidence) and opened each by decoding all of its
/// rows: three decodes of every row of the volume, which the values the
/// writer had just serialized make unnecessary. The opening still holds
/// each kept row to the store's key at its ordinal, to the record bitmaps
/// and to its working window, as it holds a decoded one.
///
/// Rows are kept only where each thing is verified once (`--verify fast`)
/// and decoded rows are served (outside the gate): a run with `--verify
/// thorough`, without the check-once policy or inside the gate decodes
/// every row of the store it opens, as before. The memory is the decoded
/// rows' own: optional, in blocks, within their share, and given up with
/// them when memory is short; a row that is not kept is decoded, as before.
pub(super) struct WrittenRows {
    cache: Rc<DecodedRowCache>,
    scratch: SourceScratch,
    // The slots: the rows the store may have.
    count: usize,
}
impl WrittenRows {
    /// Whether rows written in this process are kept for their store.
    pub(super) fn keeps() -> bool {
        n2r_win32::verify_policy::verifies_once() && !n2r_win32::verify_policy::full_unremembered()
    }
    /// For a store of at most `count` rows, written while no store of
    /// these rows is open (the MFT scan): the rows are paid by blocks of
    /// their own, which the store takes with them when it is opened.
    pub(super) fn new(scratch: &SourceScratch, count: u64) -> Option<Self> {
        if !Self::keeps() {
            return None;
        }
        let count = usize::try_from(count).ok()?;
        let cache = Rc::new(DecodedRowCache {
            state: RefCell::new(DecodedRows::default()),
            last_used: Cell::new(n2r_win32::evict::now()),
            last_served: Cell::new(None),
        });
        n2r_win32::evict::register(&cache);
        Some(Self {
            cache,
            scratch: scratch.clone(),
            count,
        })
    }
    /// Keeps `file`, the row just written at `ordinal` of the store: as the
    /// writer serialized it. A row that cannot be paid for is dropped and
    /// decoded when the store is opened.
    pub(super) fn keep(&self, ordinal: u64, file: FileInventory) {
        let Ok(index) = usize::try_from(ordinal) else {
            return;
        };
        if index >= self.count {
            return;
        }
        self.cache.last_used.set(n2r_win32::evict::now());
        let share = self.scratch.budget().ram_bytes / DECODED_ROW_SHARE;
        // Borrowed means it is being given up at this moment.
        let Ok(mut state) = self.cache.state.try_borrow_mut() else {
            return;
        };
        state.hold(
            true,
            index,
            self.count,
            &Arc::new(file),
            &self.scratch,
            share,
        );
    }
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
    /// Opens the store `files`. `written` are its rows as this process
    /// wrote them ([`WrittenRows`]), where they were kept: those are held
    /// to the store as they are, the others decoded.
    pub(super) fn from_live_bitmap(
        header: SourceHeader,
        files: &RecordStorePin,
        allocated: Box<dyn SourceMetadataRange>,
        extensions: &SourcePagePin,
        scratch: &SourceScratch,
        written: Option<WrittenRows>,
    ) -> Result<Self> {
        ensure!(
            header.schema_version == 2
                && header.mft_record_count > 6
                && header.mft_record_count <= 1 << 48
                && header.records_scanned <= header.mft_record_count,
            "paged source intrinsic MFT domain differs"
        );
        let written = written.filter(|_| WrittenRows::keeps());
        let value = Self {
            header,
            files: SortedRecordStore::open(files, scratch)?,
            allocated,
            extensions: PagedMetadataRange::open(extensions, scratch)?,
            extension_pin: extensions.clone(),
            scratch: scratch.clone(),
            directory_rows: RefCell::new(DirectoryRowCache::default()),
            last_row: RefCell::new(None),
            decoded: match &written {
                Some(written) => Rc::clone(&written.cache),
                None => {
                    let decoded = Rc::new(DecodedRowCache {
                        state: RefCell::new(DecodedRows::default()),
                        last_used: Cell::new(n2r_win32::evict::now()),
                        last_served: Cell::new(None),
                    });
                    n2r_win32::evict::register(&decoded);
                    decoded
                }
            },
        };
        let promoted = written.is_some();
        drop(written);
        if promoted {
            value.promote_written()?;
        }
        value.validate_complete_files(promoted)?;
        Ok(value)
    }
    /// The rows written for this store take the place of the rows held.
    fn promote_written(&self) -> Result<()> {
        let count = usize::try_from(self.files.len())?;
        self.decoded.last_served.set(None);
        self.decoded.state.borrow_mut().promote_written(count);
        Ok(())
    }
    /// The rows of the store that is to replace this one, written in this
    /// process in its order: kept beside the rows of this one, paid from the
    /// same blocks, and served once it has replaced this one
    /// ([`Self::replace_files`]). None where rows are not kept.
    pub(super) fn written_rows(&self) -> Option<WrittenRows> {
        if !WrittenRows::keeps() {
            return None;
        }
        let count = usize::try_from(self.files.len()).ok()?;
        self.decoded.state.borrow_mut().drop_written();
        Some(WrittenRows {
            cache: Rc::clone(&self.decoded),
            scratch: self.scratch.clone(),
            count,
        })
    }
    /// The row at `ordinal` as a value of the caller's own, for a pass that
    /// rewrites every row, in order, into the store that replaces this one
    /// ([`Self::written_rows`]). A row that is no directory and is held
    /// with the decoded rows is handed over, not copied: it is held no
    /// more, and the memory it took pays for the rows written. Asked for
    /// again, it is decoded from the store. Directories, which the paths of
    /// other rows are built from, are copied as [`RootFileDomain::file`]
    /// copies them, and so is every row where rows written are not kept.
    ///
    /// The row is taken out of the decoded rows under one borrow, before
    /// anything else is read: reading the store's index may ask for memory
    /// that gives the decoded rows up. A row that is not held there (never
    /// kept, or given up) is decoded from the store, as [`Self::file`] does.
    pub(super) fn take_file(&self, ordinal: u64) -> Result<FileInventory> {
        let taken = if WrittenRows::keeps()
            && let Ok(index) = usize::try_from(ordinal)
            && let Ok(mut decoded) = self.decoded.state.try_borrow_mut()
            && decoded
                .rows
                .get(index)
                .and_then(Option::as_ref)
                .is_some_and(|row| !row.is_directory)
        {
            decoded.take(index)
        } else {
            None
        };
        let Some(row) = taken else {
            return self.file(ordinal);
        };
        self.decoded.last_used.set(n2r_win32::evict::now());
        // Held to the store's key at its ordinal, as a row served is.
        let key = self.files.key(ordinal)?;
        let number = u64::from_be_bytes(key[..8].try_into()?);
        ensure!(
            key == file_key(number),
            "canonical ordinal key is not a file identity"
        );
        ensure!(
            row.record_number == number,
            "the decoded row held for ordinal {ordinal} of the source file store is FILE {}, where the store's index has FILE {number}",
            row.record_number
        );
        Ok(Arc::unwrap_or_clone(row))
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
        self.release_inventory_resident_cache_keeping(|| false);
    }
    /// As [`Self::release_inventory_resident_cache`]; where `keep_decoded`,
    /// asked once the rest is released, says so, the decoded rows stay: the
    /// caller has found room for what it is about to reserve beside them.
    pub(super) fn release_inventory_resident_cache_keeping(
        &mut self,
        keep_decoded: impl FnOnce() -> bool,
    ) {
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
        // passes decode them. Where the ledger has room for those beside
        // the rows, they stay, and the projection does not decode every row
        // of the store again to keep them once more. They are still a cache
        // of the run, given up when memory is short.
        if !keep_decoded() {
            self.decoded.clear();
        }
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
    /// Replaces the store with `pin`, a store of the same records. `written`
    /// are its rows as this process wrote them ([`Self::written_rows`]),
    /// where they were kept: those are held to the store as they are, the
    /// others decoded.
    pub(super) fn replace_files(
        &mut self,
        pin: &RecordStorePin,
        written: Option<WrittenRows>,
    ) -> Result<()> {
        ensure!(
            pin.records == self.files.len() && pin.data.path != self.files.pin().data.path,
            "source row replacement cannot change its complete identity domain"
        );
        // Replacement changes roles or hash evidence. Never serve an old row,
        // and return optional cache credit before opening replacement pages.
        self.directory_rows.get_mut().clear();
        self.last_row.get_mut().take();
        let promoted = written.is_some_and(|written| {
            Rc::ptr_eq(&written.cache, &self.decoded)
                && u64::try_from(written.count) == Ok(pin.records)
        }) && WrittenRows::keeps();
        if promoted {
            self.promote_written()?;
        } else {
            self.decoded.clear();
        }
        self.files.clear_resident_cache();
        let result = (|| {
            let replacement = SortedRecordStore::open(pin, &self.scratch)?;
            for ordinal in 0..replacement.len() {
                ensure!(
                    replacement.key(ordinal)? == self.files.key(ordinal)?,
                    "source row replacement changed a canonical identity"
                );
            }
            let old = self.files.pin().clone();
            self.files = replacement;
            self.validate_complete_files(promoted)?;
            self.scratch.retire_created(&old.data)?;
            self.scratch.retire_created(&old.directory)?;
            Ok(())
        })();
        if result.is_err() && promoted {
            // The rows held may be of a store that was not taken.
            self.decoded.clear();
        }
        result
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
        if !decoded.hold(
            false,
            index,
            count,
            file,
            &self.scratch,
            self.budget().ram_bytes / DECODED_ROW_SHARE,
        ) {
            return false;
        }
        drop(decoded);
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
                    "the decoded row held for ordinal {ordinal} of the source file store is FILE {}, where the store's index has FILE {number}",
                    row.record_number
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
    /// The row of the record `number`, for a lookup by number that did not
    /// find it with the directories: its place is the remembered one or is
    /// searched for, and the row is the held one or is decoded.
    ///
    /// A directory that the decoded rows served is held with the directories
    /// from here on. Every path that is built asks for the directories above
    /// its object by their numbers, which the directories answer at once;
    /// the decoded rows are found by ordinal, after a search of the index,
    /// and once every row is decoded nothing else would put a directory
    /// there.
    fn searched_row(&self, number: u64) -> Result<Option<Arc<FileInventory>>> {
        let ordinal = match self.last_ordinal_of(number) {
            Some(ordinal) => ordinal,
            None => match self.ordinal(number)? {
                Some(ordinal) => ordinal,
                None => return Ok(None),
            },
        };
        let file = self.row(ordinal)?;
        if file.is_directory && self.serves_decoded() {
            self.retain_directory(ordinal, &file)?;
        }
        Ok(Some(file))
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
    /// Holds the complete store to the record bitmaps, row by row. With
    /// `written`, a row held as the writer serialized it ([`WrittenRows`])
    /// is held to them as it is; every other row is decoded from the store.
    fn validate_complete_files(&self, written: bool) -> Result<()> {
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
            let held = if written {
                usize::try_from(ordinal).ok().and_then(|index| {
                    self.decoded
                        .state
                        .borrow()
                        .rows
                        .get(index)
                        .and_then(Option::as_ref)
                        .map(Arc::clone)
                })
            } else {
                None
            };
            if let Some(file) = held {
                // Held to the same key, order, bitmaps and window as a
                // decoded row, and kept where it is. The row is lent for
                // that, not borrowed from the cache: reading the index may
                // give the decoded rows up, and the rows after it are then
                // decoded.
                self.decoded.last_used.set(n2r_win32::evict::now());
                self.check_complete_row(ordinal, &file, &mut previous)?;
                continue;
            }
            let file: FileInventory = self.files.get(ordinal)?;
            self.check_complete_row(ordinal, &file, &mut previous)?;
            // Every row is decoded here and held to its key: the first pass
            // that asks for it need not decode it again.
            if self.serves_decoded() {
                self.keep_decoded(ordinal, &Arc::new(file));
            }
        }
        self.revalidate()
    }
    /// Holds the row at `ordinal` to the store's key there, to the order of
    /// the rows before it, to the record bitmaps and to its working window.
    fn check_complete_row(
        &self,
        ordinal: u64,
        file: &FileInventory,
        previous: &mut Option<u64>,
    ) -> Result<()> {
        ensure!(
            self.files.key(ordinal)? == file_key(file.record_number)
                && previous.is_none_or(|n| n < file.record_number)
                && file.base_file_reference == 0
                && self.bit(self.allocated.as_ref(), file.record_number)?
                && !self.bit(&self.extensions, file.record_number)?,
            "canonical source identity/key/allocation differs"
        );
        ensure!(
            file_heap_bytes(file)?
                .checked_add(std::mem::size_of::<FileInventory>() as u64)
                .is_some_and(|n| n <= self.budget().record_bytes.saturating_mul(8)),
            "one source row exceeds its resource working window"
        );
        *previous = Some(file.record_number);
        Ok(())
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
        let Some(file) = self.searched_row(number)? else {
            return Ok(None);
        };
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
            None => match self.searched_row(number)? {
                Some(file) => file,
                None => return Ok(None),
            },
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
            None => match self.searched_row(number)? {
                Some(file) => file,
                None => return Ok(None),
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> SourceScratch {
        SourceScratch::new(SourceMetadataBudget {
            ram_bytes: 1024 * 1024 * 1024,
            scratch_bytes: 256 * 1024 * 1024,
            page_bytes: 4096,
            record_bytes: 64 * 1024,
            merge_fan_in: 8,
        })
        .unwrap()
    }
    fn row(number: u64, directory: bool) -> Arc<FileInventory> {
        // A name of some length, so that the rows take several blocks.
        let name = format!("{number:0>300}");
        Arc::new(FileInventory {
            record_number: number,
            sequence_number: 1,
            hard_link_count: 1,
            is_directory: directory,
            is_metadata: false,
            metadata_role: MetadataRole::NotClassified,
            metadata_role_issue: None,
            base_file_reference: 0,
            names: vec![NameInventory {
                name_utf16: name.encode_utf16().collect(),
                name,
                namespace: 1,
                parent_record_number: 5,
                parent_sequence_number: 5,
            }],
            standard_information: None,
            streams: Vec::new(),
            attributes: Vec::new(),
            extended_attributes: None,
            reparse: None,
        })
    }
    /// What the blocks have paid out: every row held, and the slots of
    /// each of the two vectors that has any.
    fn spent(rows: &DecodedRows) -> u64 {
        [&rows.rows, &rows.written]
            .into_iter()
            .map(|slots| {
                DecodedRows::slots_charge(slots.len())
                    + slots
                        .iter()
                        .flatten()
                        .map(|row| DecodedRows::charge_of(row).unwrap())
                        .sum::<u64>()
            })
            .sum()
    }

    #[test]
    fn rows_handed_over_pay_for_the_rows_written_and_spare_blocks_go_back() {
        let scratch = scratch();
        let share = scratch.budget().ram_bytes / DECODED_ROW_SHARE;
        let before = scratch.working_ram_bytes();
        let mut rows = DecodedRows::default();
        const COUNT: usize = 60_000;
        for index in 0..COUNT {
            assert!(rows.hold(
                false,
                index,
                COUNT,
                &row(index as u64 + 16, index % 7 == 0),
                &scratch,
                share
            ));
        }
        assert_eq!(rows.leased - rows.unspent, spent(&rows));
        let full = rows.leased;
        assert!(full > DECODED_ROW_BLOCK_BYTES, "more than one block");
        // A rewrite: each row that is no directory is taken over and its
        // replacement written.
        for index in 0..COUNT {
            let taken = if index % 7 == 0 {
                None
            } else {
                Some(rows.take(index).unwrap())
            };
            assert!(rows.rows[index].is_none() == taken.is_some());
            assert!(rows.hold(
                true,
                index,
                COUNT,
                &row(index as u64 + 16, index % 7 == 0),
                &scratch,
                share
            ));
            if index % 4999 == 0 {
                assert_eq!(rows.leased - rows.unspent, spent(&rows), "row {index}");
            }
        }
        assert_eq!(rows.leased - rows.unspent, spent(&rows));
        // The rows handed over paid for most of the rows written.
        assert!(rows.leased < full * 3 / 2, "{} of {full}", rows.leased);
        rows.promote_written(COUNT);
        assert!(rows.written.is_empty());
        assert!(rows.rows.iter().all(Option::is_some));
        assert_eq!(rows.leased - rows.unspent, spent(&rows));
        assert!(
            rows.unspent < DECODED_ROW_BLOCK_BYTES,
            "the blocks no row needs are given back"
        );
        assert_eq!(
            scratch.working_ram_bytes() - before,
            rows.leased,
            "the ledger holds what the blocks hold"
        );
        rows.drop_rows();
        assert_eq!(scratch.working_ram_bytes(), before);
    }

    #[test]
    fn rows_written_beyond_the_store_or_short_of_it_are_not_served() {
        let scratch = scratch();
        let share = scratch.budget().ram_bytes / DECODED_ROW_SHARE;
        let mut rows = DecodedRows::default();
        // A scan's writer has room for every record; the store has fewer.
        for index in 0..10 {
            assert!(rows.hold(true, index, 100, &row(index as u64, false), &scratch, share));
        }
        rows.promote_written(10);
        assert_eq!(rows.rows.len(), 10);
        assert_eq!(rows.leased - rows.unspent, spent(&rows));
        // Slots short of the store: nothing is held.
        for index in 0..5 {
            assert!(rows.hold(true, index, 5, &row(index as u64, false), &scratch, share));
        }
        rows.promote_written(10);
        assert!(rows.rows.is_empty() && rows.written.is_empty() && rows.leases.is_empty());
        assert_eq!((rows.leased, rows.unspent), (0, 0));
    }
}
