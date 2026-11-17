//! The rows of a native report: one [`ObjectReport`] for each object of the
//! volume walk, in the order of the walk. Nothing outside this module holds
//! the rows' storage: a row is lent to a closure and to nothing longer.
//!
//! Where the walk's payer offers working storage, the rows are kept in
//! blocks. They are held in memory, each row under the reservation it
//! came with, as rows always were, while the run has memory to spare
//! (what it cannot do without is under half of what it may hold). When
//! it has not, as a block is closed, the blocks go to a rows file and are
//! read back from it, two at a time, and the rows that follow go there at
//! once. They go there as well when a reservation the run cannot do
//! without finds no room after every cache was given up
//! ([`crate::evict::register_last_resort`]). A run that has the memory
//! makes no file and is not slowed. Where the payer has no working storage the
//! rows are one vector, as before.
use super::ObjectReport;
use super::report_memory::{
    ReportMemoryAccountant, ReportMemoryLease, SpillFile, SpillSource, row_bytes,
};
use crate::layout::invalid;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use std::cell::RefCell;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

mod file;

/// A block is closed at this many rows,
const BLOCK_ROWS: usize = 256;
/// or at this many bytes of rows, whichever comes first.
const BLOCK_BYTES: u64 = 2 * 1024 * 1024;
/// What paged rows reserve for themselves: two blocks read back from the
/// file, the file's page and chunk buffers, and the list of blocks.
const STORE_BYTES: u64 = 16 * 1024 * 1024;

pub struct Rows {
    store: Store,
}
enum Store {
    Held(Vec<ObjectReport>),
    Paged(Arc<Paged>),
}
impl fmt::Debug for Rows {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rows({})", self.len())
    }
}

type Lease = Box<dyn ReportMemoryLease>;
type BlockRows = Arc<Vec<ObjectReport>>;

struct Paged {
    state: Mutex<State>,
    // The thread that made the rows: the one whose caches are asked back.
    owner: std::thread::ThreadId,
    // When that thread last read a block, on its clock of cache uses.
    used: AtomicU64,
}
struct State {
    count: usize,
    // Closed blocks, in order.
    blocks: Vec<Block>,
    // Every row's native file identity (24 bytes), or none where the row
    // has none to give: asked for by index in no order (a link's parent
    // and target), which rows in the file could answer only by reading a
    // block back for each.
    identities: Vec<Option<[u8; 24]>>,
    // The block being filled, each row with the reservation it came with.
    tail: Vec<ObjectReport>,
    tail_leases: Vec<Lease>,
    tail_bytes: u64,
    // All rows are in: nothing is pushed any more.
    complete: bool,
    // Blocks read back from the file, the one read last at the end.
    window: Vec<(usize, BlockRows)>,
    // The largest block's bytes the window's reservation covers twice.
    window_block_bytes: u64,
    // Where the rows file is made, when the first block has to go to it.
    source: Box<dyn SpillSource>,
    file: OwnerOnly<FileState>,
    // The file is being written, and a file was made at all.
    writing: bool,
    made: bool,
    // The working storage refused the file, or more room for it: what is
    // not in the file stays in memory, paid for as it is.
    refused: bool,
    // Writing or reading the file failed: every later use says so.
    failed: Option<String>,
    // Dropped after the rows and buffers they pay for.
    _leases: Vec<Lease>,
}
struct Block {
    first: usize,
    rows: usize,
    bytes: u64,
    // In memory, with what pays for it.
    held: Option<(BlockRows, Vec<Lease>)>,
    // In the file.
    written: bool,
}
enum FileState {
    None,
    Writing {
        writer: Box<file::RowsFileWriter>,
        spill: Box<dyn SpillFile>,
        path: PathBuf,
        budget: crate::metadata_pages::PageBudget,
    },
    Reading(Box<file::RowsFileReader>),
    Closed,
}

/// Something only the thread that made it may use: the rows file's writer
/// and reader hold a hash handle and pages that belong to that thread. The
/// rows themselves are read on other threads too, from memory; a block
/// that would have to come from the file is refused there (a pass that
/// reads rows on helper threads pins them first, [`Rows::pin`]).
struct OwnerOnly<T> {
    value: std::mem::ManuallyDrop<T>,
    owner: std::thread::ThreadId,
}
// SAFETY: the value is reached only through `get`, which refuses every
// thread but the one that made it, and is dropped only on that thread.
unsafe impl<T> Send for OwnerOnly<T> {}
// SAFETY: as above; no shared reference to the value is ever handed out.
unsafe impl<T> Sync for OwnerOnly<T> {}
impl<T> OwnerOnly<T> {
    fn new(value: T) -> Self {
        Self {
            value: std::mem::ManuallyDrop::new(value),
            owner: std::thread::current().id(),
        }
    }
    fn get(&mut self) -> io::Result<&mut T> {
        if std::thread::current().id() != self.owner {
            return Err(failed(
                "a block can be written or read back only on the thread that made the rows",
            ));
        }
        Ok(&mut self.value)
    }
}
impl<T> Drop for OwnerOnly<T> {
    fn drop(&mut self) {
        if std::thread::current().id() == self.owner {
            // SAFETY: dropped once, here, on the owning thread.
            unsafe { std::mem::ManuallyDrop::drop(&mut self.value) };
        }
        // On another thread the value is left as it is: its handles belong
        // to the thread that made them.
    }
}

thread_local! {
    // The rows this thread made, as caches it can be asked to give up. The
    // registry of caches holds them weakly; this list is what keeps them.
    static EVICTORS: RefCell<Vec<Rc<Evictor>>> = const { RefCell::new(Vec::new()) };
}
struct Evictor(Weak<Paged>);
impl crate::evict::Evict for Evictor {
    fn evict(&self) -> bool {
        self.0.upgrade().is_some_and(|rows| rows.give_up())
    }
    fn last_used(&self) -> u64 {
        self.0
            .upgrade()
            .map_or(0, |rows| rows.used.load(Ordering::Relaxed))
    }
}

fn failed(error: impl fmt::Display) -> io::Error {
    io::Error::other(format!("the walk's rows file: {error}"))
}

impl State {
    fn check(&self) -> io::Result<()> {
        match &self.failed {
            Some(reason) => Err(failed(reason)),
            None => Ok(()),
        }
    }
    /// Writes every closed block that is in memory and not in the file, in
    /// order. A failure is kept: the rows cannot be used after it.
    fn write_held(&mut self) -> io::Result<()> {
        let State {
            file,
            blocks,
            refused,
            ..
        } = self;
        let result = (|| {
            let FileState::Writing { writer, spill, .. } = file.get()? else {
                return Err(io::Error::other("the file is not being written"));
            };
            for (number, block) in blocks.iter_mut().enumerate() {
                if block.written {
                    continue;
                }
                let Some((rows, _)) = &block.held else {
                    return Err(io::Error::other("a block is neither held nor written"));
                };
                // JSON of byte fields in hexadecimal pages: at most eight
                // times the rows' bytes, and the block's own records. Where
                // the storage has no more room for the file, this block
                // and those after it stay in memory.
                if spill
                    .extend(block.bytes.saturating_mul(8).saturating_add(65536))
                    .is_err()
                {
                    *refused = true;
                    break;
                }
                writer.write_block(number as u64, rows)?;
                block.written = true;
            }
            Ok(())
        })();
        if let Err(error) = &result {
            self.failed = Some(error.to_string());
        }
        result
    }
    /// Makes the rows file, if there is none yet. A refusal is not kept as
    /// a failure: the rows are where they were.
    fn make_file(&mut self) -> io::Result<()> {
        if self.made {
            return Ok(());
        }
        // Only the thread that made the rows writes their file.
        self.file.get()?;
        let made = (|| {
            let spill = self.source.create()?;
            let path = spill.path().to_owned();
            let budget = spill.page_budget();
            // A file that was reserved has to be closed: if its writer
            // cannot be made, the storage it is in is told so by the file
            // left open.
            let writer = Box::new(file::RowsFileWriter::new(&path, budget)?);
            Ok(FileState::Writing {
                writer,
                spill,
                path,
                budget,
            })
        })();
        match made {
            Ok(state) => *self.file.get()? = state,
            Err(error) => {
                self.refused = true;
                return Err(error);
            }
        }
        self.writing = true;
        self.made = true;
        Ok(())
    }
    /// Closes the file and opens it for reading. Every block is in it.
    fn finish_file(&mut self) -> io::Result<()> {
        let result = (|| {
            let file = self.file.get()?;
            let FileState::Writing {
                writer,
                spill,
                path,
                budget,
            } = std::mem::replace(file, FileState::Closed)
            else {
                return Err(io::Error::other("the file is not being written"));
            };
            self.writing = false;
            let summary = writer.finish()?;
            spill.close(&summary.sha256)?;
            *file = FileState::Reading(Box::new(file::RowsFileReader::open(
                &path,
                &summary.sha256,
                budget,
                summary.index,
            )?));
            Ok(())
        })();
        if let Err(error) = &result {
            self.failed = Some(error.to_string());
        }
        result
    }
    fn block_of(&self, index: usize) -> io::Result<usize> {
        if index >= self.count || !self.complete {
            return Err(absent(index, self.count));
        }
        Ok(self.blocks.partition_point(|block| block.first <= index) - 1)
    }
    /// The rows of a closed block: from memory, or read back.
    fn block(&mut self, number: usize) -> io::Result<BlockRows> {
        self.check()?;
        if let Some((rows, _)) = &self.blocks[number].held {
            return Ok(Arc::clone(rows));
        }
        if let Some(at) = self.window.iter().position(|(held, _)| *held == number) {
            let entry = self.window.remove(at);
            let rows = Arc::clone(&entry.1);
            self.window.push(entry);
            return Ok(rows);
        }
        // Not kept as a failure: on its own thread the same block is there.
        self.file.get()?;
        if self.writing {
            if !self.complete {
                return Err(failed("a block was asked for while rows were still added"));
            }
            self.write_held()?;
            self.finish_file()?;
        }
        if !self.blocks[number].written {
            return Err(failed("a block is in neither memory nor the file"));
        }
        let FileState::Reading(reader) = self.file.get()? else {
            return Err(failed("a block is in neither memory nor the file"));
        };
        let rows = match reader.read_block(number as u64) {
            Ok(rows) => rows,
            Err(error) => {
                self.failed = Some(error.to_string());
                return Err(failed(error));
            }
        };
        if rows.len() != self.blocks[number].rows {
            let reason = "a block came back with another number of rows";
            self.failed = Some(reason.to_owned());
            return Err(failed(reason));
        }
        let rows = Arc::new(rows);
        if self.window.len() >= 2 {
            self.window.remove(0);
        }
        self.window.push((number, Arc::clone(&rows)));
        Ok(rows)
    }
}

impl Paged {
    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| failed("its state was left by a thread that panicked"))
    }
    fn touch(&self) {
        if std::thread::current().id() == self.owner {
            self.used.store(crate::evict::now(), Ordering::Relaxed);
        }
    }
    /// A reservation the run needs found no room: the blocks in memory go
    /// to the file. Nothing is reserved here before their memory is back.
    /// After the walk the file is closed here as well, so that no file is
    /// left open when its storage is sealed.
    fn give_up(&self) -> bool {
        // Held by this thread: the rows are in use at this moment.
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.failed.is_some()
            || state.refused
            || (state.made && !state.writing)
            || !state.blocks.iter().any(|block| block.held.is_some())
        {
            return false;
        }
        if state.make_file().is_err() || state.write_held().is_err() {
            return false;
        }
        // The rows that are in the file first, then what paid for them.
        let held: Vec<_> = state
            .blocks
            .iter_mut()
            .filter(|block| block.written)
            .filter_map(|block| block.held.take())
            .collect();
        let any = !held.is_empty();
        drop(held);
        if state.complete {
            let _ = state.finish_file();
        }
        any
    }
    fn block(&self, number: usize) -> io::Result<BlockRows> {
        let rows = self.lock()?.block(number)?;
        self.touch();
        Ok(rows)
    }
    /// Closes the block that was being filled. Called with no lock held:
    /// the payer may ask this very store for memory back.
    fn close_block(
        &self,
        payer: &dyn ReportMemoryAccountant,
        rows: Vec<ObjectReport>,
        leases: Vec<Lease>,
        bytes: u64,
    ) -> io::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        // The rows' identities stay in memory: 25 bytes a row, and what the
        // vector of them grows by.
        let kept = payer.reserve((rows.len() as u64).saturating_mul(64))?;
        self.lock()?._leases.push(kept);
        // The window holds two blocks read back: it has to cover this one.
        let covered = self.lock()?.window_block_bytes;
        if bytes > covered {
            let more = payer.reserve((bytes - covered).saturating_mul(2))?;
            let mut state = self.lock()?;
            state._leases.push(more);
            state.window_block_bytes = bytes;
        }
        // Asked with no lock held, like everything of the payer's.
        let spare = payer.has_memory_to_spare();
        let mut state = self.lock()?;
        state.check()?;
        let first = state.blocks.last().map_or(0, |last| last.first + last.rows);
        let count = rows.len();
        state.blocks.push(Block {
            first,
            rows: count,
            bytes,
            held: Some((Arc::new(rows), leases)),
            written: false,
        });
        // No memory to spare: the blocks go to the file now, before the
        // run's caches are pressed for the room the rows take. A file the
        // storage refuses leaves them where they are.
        if !spare && !state.writing && !state.refused {
            let _ = state.make_file();
        }
        // Once blocks had to go to the file, memory is short: the blocks
        // that follow go there as they are closed.
        if state.writing {
            state.write_held()?;
            let written: Vec<_> = state
                .blocks
                .iter_mut()
                .filter(|block| block.written)
                .filter_map(|block| block.held.take())
                .collect();
            drop(state);
            drop(written);
        }
        Ok(())
    }
}
impl Drop for Paged {
    fn drop(&mut self) {
        // A working file has to be closed, whatever is in it: left open it
        // breaks the accounting of the storage it is in.
        let Ok(state) = self.state.get_mut() else {
            return;
        };
        if let Ok(file) = state.file.get()
            && let FileState::Writing { writer, spill, .. } =
                std::mem::replace(file, FileState::Closed)
            && let Ok(summary) = writer.finish()
        {
            let _ = spill.close(&summary.sha256);
        }
    }
}

impl Rows {
    /// No rows and no storage.
    pub(super) fn new() -> Self {
        Self {
            store: Store::Held(Vec::new()),
        }
    }

    /// Room for exactly the `count` rows a walk will push.
    pub(super) fn with_exact_capacity(count: usize) -> io::Result<Self> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(count).map_err(io::Error::other)?;
        Ok(Self {
            store: Store::Held(rows),
        })
    }

    /// The rows of a walk that observed all its objects at once, in its
    /// order. The allocation is kept as it is.
    pub(super) fn from_observed(rows: Vec<ObjectReport>) -> Self {
        Self {
            store: Store::Held(rows),
        }
    }

    /// Rows kept in blocks, with `source` for a file for the blocks that
    /// have no room in memory. Made on the thread that drives the run.
    pub(super) fn paged(
        payer: &dyn ReportMemoryAccountant,
        source: Box<dyn SpillSource>,
    ) -> io::Result<Self> {
        let own = payer.reserve(STORE_BYTES)?;
        let paged = Arc::new(Paged {
            state: Mutex::new(State {
                count: 0,
                blocks: Vec::new(),
                identities: Vec::new(),
                tail: Vec::new(),
                tail_leases: Vec::new(),
                tail_bytes: 0,
                complete: false,
                window: Vec::new(),
                window_block_bytes: BLOCK_BYTES,
                source,
                file: OwnerOnly::new(FileState::None),
                writing: false,
                made: false,
                refused: false,
                failed: None,
                _leases: vec![own],
            }),
            owner: std::thread::current().id(),
            used: AtomicU64::new(crate::evict::now()),
        });
        let evictor = Rc::new(Evictor(Arc::downgrade(&paged)));
        crate::evict::register_last_resort(&evictor);
        EVICTORS.with(|kept| {
            let mut kept = kept.borrow_mut();
            kept.retain(|evictor| evictor.0.strong_count() != 0);
            kept.push(evictor);
        });
        Ok(Self {
            store: Store::Paged(paged),
        })
    }

    /// Whether the rows are kept in blocks, each row added with its
    /// reservation ([`Self::push_paid`]).
    pub(super) fn in_blocks(&self) -> bool {
        matches!(self.store, Store::Paged(_))
    }

    /// Adds the row of the next index. The storage never grows beyond what
    /// was reserved for it: its memory was paid for at that size.
    pub(super) fn push(&mut self, row: ObjectReport) -> io::Result<()> {
        let Store::Held(rows) = &mut self.store else {
            return Err(invalid("rows in blocks are added with their reservation"));
        };
        if rows.len() == rows.capacity() {
            return Err(invalid(
                "native object slots exceeded their initial reservation",
            ));
        }
        rows.push(row);
        Ok(())
    }

    /// Adds the row of the next index to rows kept in blocks, with the
    /// reservation that pays for it, already shrunk to the row.
    pub(super) fn push_paid(
        &mut self,
        payer: &dyn ReportMemoryAccountant,
        row: ObjectReport,
        lease: Lease,
    ) -> io::Result<()> {
        let Store::Paged(paged) = &self.store else {
            return Err(invalid(
                "rows in one vector are added without a reservation",
            ));
        };
        let bytes = row_bytes(&row)?;
        let identity = identity_of(&row).ok();
        let closed = {
            let mut state = paged.lock()?;
            state.check()?;
            if state.complete {
                return Err(invalid("a row was added after the last"));
            }
            state.identities.try_reserve(1).map_err(io::Error::other)?;
            state.identities.push(identity);
            state.tail.push(row);
            state.tail_leases.push(lease);
            state.tail_bytes = state.tail_bytes.saturating_add(bytes);
            state.count += 1;
            (state.tail.len() >= BLOCK_ROWS || state.tail_bytes >= BLOCK_BYTES).then(|| {
                (
                    std::mem::take(&mut state.tail),
                    std::mem::take(&mut state.tail_leases),
                    std::mem::take(&mut state.tail_bytes),
                )
            })
        };
        match closed {
            Some((rows, leases, bytes)) => paged.close_block(payer, rows, leases, bytes),
            None => Ok(()),
        }
    }

    /// Every row is in. Rows in one vector need nothing done.
    pub(super) fn finish(&mut self, payer: Option<&dyn ReportMemoryAccountant>) -> io::Result<()> {
        let Store::Paged(paged) = &self.store else {
            return Ok(());
        };
        let payer = payer.ok_or_else(|| invalid("rows in blocks have a payer"))?;
        let (rows, leases, bytes) = {
            let mut state = paged.lock()?;
            (
                std::mem::take(&mut state.tail),
                std::mem::take(&mut state.tail_leases),
                std::mem::take(&mut state.tail_bytes),
            )
        };
        paged.close_block(payer, rows, leases, bytes)?;
        let mut state = paged.lock()?;
        state.complete = true;
        // A file that was begun is finished here, with every block that
        // can go to it, and closed before the storage it is in is sealed.
        if state.writing {
            state.write_held()?;
            let held: Vec<_> = state
                .blocks
                .iter_mut()
                .filter(|block| block.written)
                .filter_map(|block| block.held.take())
                .collect();
            drop(held);
            state.finish_file()?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        match &self.store {
            Store::Held(rows) => rows.len(),
            Store::Paged(paged) => paged.lock().map_or(0, |state| state.count),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of row slots held in one vector, which the report's
    /// memory is bound to; none where the rows are in blocks.
    pub(super) fn capacity(&self) -> usize {
        match &self.store {
            Store::Held(rows) => rows.capacity(),
            Store::Paged(_) => 0,
        }
    }

    /// Every row with its index, in ascending order of index. Stops at the
    /// first error and returns it.
    pub fn for_each(
        &self,
        visit: impl FnMut(usize, &ObjectReport) -> io::Result<()>,
    ) -> io::Result<()> {
        self.try_for_each(visit)
    }

    /// [`Self::for_each`] for a visitor with an error type of its own.
    pub fn try_for_each<E: From<io::Error>>(
        &self,
        mut visit: impl FnMut(usize, &ObjectReport) -> Result<(), E>,
    ) -> Result<(), E> {
        match &self.store {
            Store::Held(rows) => {
                for (index, row) in rows.iter().enumerate() {
                    visit(index, row)?;
                }
            }
            Store::Paged(paged) => {
                let blocks = {
                    let state = paged.lock()?;
                    if !state.complete {
                        return Err(failed("rows were read while they were still added").into());
                    }
                    state.blocks.len()
                };
                for number in 0..blocks {
                    // Lent with no lock held: the visitor may ask for rows.
                    let first = paged.lock()?.blocks[number].first;
                    let rows = paged.block(number)?;
                    for (offset, row) in rows.iter().enumerate() {
                        visit(first + offset, row)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// The row at `index`. An index beyond the rows is an error.
    pub fn with<T>(
        &self,
        index: usize,
        read: impl FnOnce(&ObjectReport) -> io::Result<T>,
    ) -> io::Result<T> {
        self.try_with(index, read)
    }

    /// [`Self::with`] for a reader with an error type of its own.
    pub fn try_with<T, E: From<io::Error>>(
        &self,
        index: usize,
        read: impl FnOnce(&ObjectReport) -> Result<T, E>,
    ) -> Result<T, E> {
        match &self.store {
            Store::Held(rows) => {
                let count = rows.len();
                read(rows.get(index).ok_or_else(|| absent(index, count))?)
            }
            Store::Paged(paged) => {
                let (number, first) = {
                    let state = paged.lock()?;
                    let number = state.block_of(index)?;
                    (number, state.blocks[number].first)
                };
                let rows = paged.block(number)?;
                read(&rows[index - first])
            }
        }
    }

    /// The native file identity of the row at `index`: 24 bytes of its
    /// first snapshot. Rows in blocks keep them in memory.
    pub(super) fn identity(&self, index: usize) -> io::Result<[u8; 24]> {
        if let Store::Paged(paged) = &self.store {
            let state = paged.lock()?;
            match state.identities.get(index) {
                Some(Some(identity)) if state.complete => return Ok(*identity),
                Some(_) => {}
                None => return Err(absent(index, state.count)),
            }
        }
        self.with(index, identity_of)
    }

    /// The row at `index`, kept at hand for as long as the result lives:
    /// for a pass that reads rows on helper threads, which pins what it
    /// will read while still on the thread that made the rows.
    pub(super) fn pin(&self, index: usize) -> io::Result<Pinned<'_>> {
        match &self.store {
            Store::Held(rows) => {
                let count = rows.len();
                Ok(Pinned::Held(
                    rows.get(index).ok_or_else(|| absent(index, count))?,
                ))
            }
            Store::Paged(paged) => {
                let (number, first) = {
                    let state = paged.lock()?;
                    let number = state.block_of(index)?;
                    (number, state.blocks[number].first)
                };
                Ok(Pinned::Block {
                    rows: paged.block(number)?,
                    at: index - first,
                    block: number,
                })
            }
        }
    }

    /// Records the digest of the default stream of the row at `index`.
    pub(super) fn set_logical_sha256(
        &mut self,
        index: usize,
        digest: Option<String>,
    ) -> io::Result<()> {
        self.change(index, |row| {
            row.logical_sha256 = digest;
            Ok(())
        })
    }

    /// Records the digest of the named stream at `stream`, in the order of
    /// the row's `named_streams`, of the row at `index`.
    pub(super) fn set_named_stream_logical_sha256(
        &mut self,
        index: usize,
        stream: usize,
        digest: Option<String>,
    ) -> io::Result<()> {
        self.change(index, |row| {
            row.named_streams
                .get_mut(stream)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("native report row {index} has no named stream {stream}"),
                    )
                })?
                .logical_sha256 = digest;
            Ok(())
        })
    }

    /// Changes a row in place. Rows in blocks are never changed: a block
    /// may be in working storage at any time.
    fn change(
        &mut self,
        index: usize,
        change: impl FnOnce(&mut ObjectReport) -> io::Result<()>,
    ) -> io::Result<()> {
        match &mut self.store {
            Store::Held(rows) => {
                let count = rows.len();
                change(rows.get_mut(index).ok_or_else(|| absent(index, count))?)
            }
            Store::Paged(_) => {
                let _ = (index, change);
                Err(failed("rows kept in blocks are not changed"))
            }
        }
    }
}

fn identity_of(row: &ObjectReport) -> io::Result<[u8; 24]> {
    super::query_bytes(&row.before, 18, 24)?
        .try_into()
        .map_err(|_| invalid("native file identity length differs"))
}

/// A row kept at hand ([`Rows::pin`]).
pub(super) enum Pinned<'a> {
    Held(&'a ObjectReport),
    Block {
        rows: BlockRows,
        at: usize,
        block: usize,
    },
}
impl Pinned<'_> {
    pub(super) fn row(&self) -> &ObjectReport {
        match self {
            Self::Held(row) => row,
            Self::Block { rows, at, .. } => &rows[*at],
        }
    }
    /// The block that is kept in memory for this row, where rows are in
    /// blocks: a pass pins rows of no more than two blocks at a time, which
    /// is what the rows reserved for blocks read back.
    pub(super) fn block(&self) -> Option<usize> {
        match self {
            Self::Held(_) => None,
            Self::Block { block, .. } => Some(*block),
        }
    }
}

fn absent(index: usize, count: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("native report row {index} was asked of {count} rows"),
    )
}

/// A JSON array of the rows, as the vector of them was.
impl Serialize for Rows {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.store {
            Store::Held(rows) => serializer.collect_seq(rows),
            Store::Paged(_) => {
                let mut sequence = serializer.serialize_seq(Some(self.len()))?;
                let mut inner = None;
                let walked = self.for_each(|_, row| {
                    if inner.is_none()
                        && let Err(error) = sequence.serialize_element(row)
                    {
                        inner = Some(error);
                    }
                    Ok(())
                });
                if let Some(error) = inner {
                    return Err(error);
                }
                walked.map_err(serde::ser::Error::custom)?;
                sequence.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Snapshot;

    fn snapshot() -> Snapshot {
        Snapshot {
            queries: vec![],
            security: vec![],
            security_error: None,
            kernel_security: None,
            extended_attributes: None,
            extended_attributes_error: None,
            reparse: None,
            directory_case_sensitivity: None,
        }
    }

    fn row(name: &str) -> ObjectReport {
        ObjectReport {
            components: vec![name.to_owned()],
            additional_names: vec![],
            named_streams: vec![],
            sparse: None,
            before: snapshot(),
            after: snapshot(),
            logical_sha256: None,
            retrieval: vec![1, 2, 3],
            retrieval_page_proof: None,
            resident_data: false,
            cached_validity: vec![],
            storage_validity: vec![],
            cached_validity_pages: None,
            storage_validity_pages: None,
            integrity: vec![],
            namespace: vec![],
            source_candidate: None,
            streams: vec![],
        }
    }

    #[test]
    fn rows_are_the_vector_they_replace() {
        let names = ["a", "b", "c"];
        let plain: Vec<ObjectReport> = names.iter().map(|name| row(name)).collect();
        let mut rows = Rows::with_exact_capacity(names.len()).unwrap();
        for name in names {
            rows.push(row(name)).unwrap();
        }
        assert_eq!((rows.len(), rows.is_empty()), (3, false));
        assert!(Rows::new().is_empty());
        // No row is taken beyond the slots that were reserved.
        if rows.len() == rows.capacity() {
            assert!(rows.push(row("d")).is_err());
        }

        assert_eq!(
            serde_json::to_vec(&rows).unwrap(),
            serde_json::to_vec(&plain).unwrap()
        );
        rows.set_logical_sha256(1, Some("digest".to_owned()))
            .unwrap();
        assert_eq!(
            serde_json::to_value(&rows).unwrap()[1]["logical_sha256"],
            "digest"
        );
        assert!(rows.set_logical_sha256(3, None).is_err());
        assert!(rows.set_named_stream_logical_sha256(0, 0, None).is_err());

        let mut seen = Vec::new();
        rows.for_each(|index, row| {
            seen.push((index, row.components[0].clone()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                (0, "a".to_owned()),
                (1, "b".to_owned()),
                (2, "c".to_owned())
            ]
        );
        // The first error ends the walk and is what the walk returns.
        let mut visited = 0;
        let stopped = rows.for_each(|index, _| {
            visited += 1;
            if index == 1 {
                Err(invalid("stop"))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            (visited, stopped.unwrap_err().to_string()),
            (2, "stop".to_owned())
        );

        assert_eq!(
            rows.with(2, |row| Ok(row.components[0].clone())).unwrap(),
            "c"
        );
        let refused = rows.with(3, |_| Ok(())).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    }

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// A payer that counts what is reserved and offers one working file in
    /// a directory.
    struct Payer {
        held: Arc<AtomicU64>,
        // Whether the run has memory to spare.
        spare: AtomicBool,
        directory: std::path::PathBuf,
        closed: Arc<AtomicBool>,
    }
    struct Counted(Arc<AtomicU64>, u64);
    impl ReportMemoryLease for Counted {
        fn shrink_to(&mut self, bytes: u64) -> io::Result<()> {
            assert!(bytes <= self.1);
            self.0.fetch_sub(self.1 - bytes, Ordering::SeqCst);
            self.1 = bytes;
            Ok(())
        }
    }
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::SeqCst);
        }
    }
    impl ReportMemoryAccountant for Payer {
        fn reserve(&self, bytes: u64) -> io::Result<Lease> {
            self.held.fetch_add(bytes, Ordering::SeqCst);
            Ok(Box::new(Counted(Arc::clone(&self.held), bytes)))
        }
        fn has_memory_to_spare(&self) -> bool {
            self.spare.load(Ordering::SeqCst)
        }
        fn spill_source(&self) -> Option<Box<dyn SpillSource>> {
            Some(Box::new(Source {
                path: self.directory.join("rows.pages"),
                closed: Arc::clone(&self.closed),
            }))
        }
        fn lease_heap_bytes(&self) -> u64 {
            16
        }
    }
    struct Source {
        path: std::path::PathBuf,
        closed: Arc<AtomicBool>,
    }
    impl SpillSource for Source {
        fn create(&self) -> io::Result<Box<dyn SpillFile>> {
            assert!(!self.path.exists(), "one file for the rows");
            Ok(Box::new(File {
                path: self.path.clone(),
                closed: Arc::clone(&self.closed),
            }))
        }
    }
    struct File {
        path: std::path::PathBuf,
        closed: Arc<AtomicBool>,
    }
    impl SpillFile for File {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
        fn page_budget(&self) -> crate::metadata_pages::PageBudget {
            crate::metadata_pages::PageBudget {
                max_page_bytes: 4096,
                max_records_per_page: 64,
                max_records: 1 << 20,
                max_pages: 1 << 20,
                max_file_bytes: 1 << 30,
            }
        }
        fn extend(&mut self, _bytes: u64) -> io::Result<()> {
            Ok(())
        }
        fn close(self: Box<Self>, sha256: &str) -> io::Result<()> {
            assert_eq!(sha256.len(), 64);
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn text(rows: &Rows) -> Vec<String> {
        let mut seen = Vec::new();
        rows.for_each(|index, row| {
            assert_eq!(index, seen.len());
            seen.push(serde_json::to_string(row).unwrap());
            Ok(())
        })
        .unwrap();
        seen
    }

    struct Walk {
        rows: Rows,
        payer: Payer,
        expected: Vec<String>,
        // What the rows' own reservations come to.
        paid: u64,
        _directory: tempfile::TempDir,
    }
    impl Walk {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let payer = Payer {
                held: Arc::new(AtomicU64::new(0)),
                spare: AtomicBool::new(true),
                directory: directory.path().to_owned(),
                closed: Arc::new(AtomicBool::new(false)),
            };
            let rows = Rows::paged(&payer, payer.spill_source().unwrap()).unwrap();
            assert!(rows.in_blocks());
            Self {
                rows,
                payer,
                expected: Vec::new(),
                paid: 0,
                _directory: directory,
            }
        }
        fn add(&mut self, count: usize) {
            for _ in 0..count {
                let row = row(&format!("object-{}", self.expected.len()));
                self.expected.push(serde_json::to_string(&row).unwrap());
                let bytes = row_bytes(&row).unwrap();
                self.paid += bytes;
                let lease = self.payer.reserve(bytes).unwrap();
                self.rows.push_paid(&self.payer, row, lease).unwrap();
            }
        }
        fn finish(&mut self) {
            self.rows.finish(Some(&self.payer)).unwrap();
            assert_eq!(self.rows.len(), self.expected.len());
        }
        fn inner(&self) -> Arc<Paged> {
            let Store::Paged(inner) = &self.rows.store else {
                panic!("rows in blocks")
            };
            Arc::clone(inner)
        }
        fn held(&self) -> u64 {
            self.payer.held.load(Ordering::SeqCst)
        }
        fn file(&self) -> bool {
            self.payer.directory.join("rows.pages").exists()
        }
        /// What the rows hold whatever becomes of the blocks.
        fn own(&self) -> u64 {
            STORE_BYTES + self.expected.len() as u64 * 64
        }
    }

    #[test]
    fn rows_in_blocks_stay_in_memory_and_make_no_file_while_nothing_asks() {
        let mut walk = Walk::new();
        walk.add(700);
        walk.finish();
        assert!(!walk.file());
        assert_eq!(walk.held(), walk.own() + walk.paid);
        assert_eq!(text(&walk.rows), walk.expected);
        assert_eq!(
            walk.rows
                .with(699, |row| Ok(row.components[0].clone()))
                .unwrap(),
            "object-699"
        );
        assert!(walk.rows.with(700, |_| Ok(())).is_err());
        assert_eq!(serde_json::to_string(&walk.rows).unwrap(), {
            format!("[{}]", walk.expected.join(","))
        });
    }

    #[test]
    fn rows_in_blocks_go_to_the_file_as_a_last_resort_after_the_walk() {
        let mut walk = Walk::new();
        walk.add(700);
        walk.finish();
        let inner = walk.inner();
        // No lock is held while a row is lent.
        walk.rows
            .with(5, |_| {
                assert!(inner.state.try_lock().is_ok());
                Ok(())
            })
            .unwrap();
        // A reservation the run needs found no room: every block goes to
        // the file, which is closed at once, and the rows read as before.
        assert!(inner.give_up());
        assert!(walk.file());
        assert!(walk.payer.closed.load(Ordering::SeqCst));
        assert_eq!(walk.held(), walk.own());
        assert!(!inner.give_up(), "nothing is left to give up");
        assert_eq!(text(&walk.rows), walk.expected);
        // Out of order, and from inside a walk over the rows.
        for index in [650, 3, 300, 699, 0] {
            let name = walk
                .rows
                .with(index, |row| Ok(row.components[0].clone()))
                .unwrap();
            assert_eq!(name, format!("object-{index}"));
        }
        walk.rows
            .for_each(|index, row| {
                let other = 699 - index;
                walk.rows.with(other, |far| {
                    assert_eq!(far.components[0], format!("object-{other}"));
                    Ok(())
                })?;
                assert_eq!(row.components[0], format!("object-{index}"));
                Ok(())
            })
            .unwrap();
        let pinned = walk.rows.pin(400).unwrap();
        assert_eq!(pinned.row().components[0], "object-400");
        assert!(pinned.block().is_some());
        drop(pinned);
        assert_eq!(walk.held(), walk.own());
        drop(inner);
        drop(walk.rows);
        assert_eq!(walk.payer.held.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn rows_in_blocks_go_to_the_file_as_a_last_resort_during_the_walk() {
        let mut walk = Walk::new();
        // Two blocks are closed and in memory, with rows of a third.
        walk.add(600);
        let inner = walk.inner();
        let before = walk.held();
        assert!(inner.give_up());
        assert!(walk.held() < before);
        assert!(walk.file());
        assert!(!inner.give_up(), "nothing is left to give up");
        // Memory is short: the blocks that follow go to the file as they
        // are closed, and at the end of the walk every row is in it.
        walk.add(400);
        assert!(!walk.payer.closed.load(Ordering::SeqCst));
        walk.finish();
        assert!(walk.payer.closed.load(Ordering::SeqCst));
        assert_eq!(walk.held(), walk.own());
        assert_eq!(text(&walk.rows), walk.expected);
    }

    #[test]
    fn rows_in_blocks_go_to_the_file_when_the_run_has_no_memory_to_spare() {
        let mut walk = Walk::new();
        // Two blocks close while there is memory to spare: no file.
        walk.add(600);
        assert!(!walk.file());
        // The run needs more than half of what it may hold: the next block
        // to close takes every block to the file, and so do those after.
        walk.payer.spare.store(false, Ordering::SeqCst);
        let before = walk.held();
        walk.add(300);
        assert!(walk.file());
        assert!(walk.held() < before);
        walk.payer.spare.store(true, Ordering::SeqCst);
        walk.add(300);
        walk.finish();
        assert!(walk.payer.closed.load(Ordering::SeqCst));
        assert_eq!(walk.held(), walk.own());
        assert_eq!(text(&walk.rows), walk.expected);
    }

    #[test]
    fn rows_in_blocks_are_not_changed() {
        let mut walk = Walk::new();
        walk.add(700);
        walk.finish();
        assert!(
            walk.rows
                .set_logical_sha256(300, Some("digest".to_owned()))
                .is_err()
        );
        assert!(
            walk.rows
                .set_named_stream_logical_sha256(300, 0, None)
                .is_err()
        );
    }

    #[test]
    fn rows_in_blocks_stay_in_memory_where_no_file_can_be_made() {
        struct NoFile;
        impl SpillSource for NoFile {
            fn create(&self) -> io::Result<Box<dyn SpillFile>> {
                Err(io::Error::other("the storage takes no new file"))
            }
        }
        let mut walk = Walk::new();
        walk.rows = Rows::paged(&walk.payer, Box::new(NoFile)).unwrap();
        walk.add(700);
        walk.finish();
        let inner = walk.inner();
        assert!(!inner.give_up());
        assert!(!walk.file());
        assert_eq!(text(&walk.rows), walk.expected);
        // The first rows made for `walk` reserved their own 16 MiB too.
        drop(inner);
        drop(walk.rows);
        assert_eq!(walk.payer.held.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_last_resort_is_asked_through_the_thread_s_registry() {
        let mut walk = Walk::new();
        walk.add(700);
        walk.finish();
        // Other tests' rows on this thread are gone; these are asked.
        assert!(crate::evict::give_up_last_resort());
        assert!(walk.file());
        assert_eq!(walk.held(), walk.own());
        assert_eq!(text(&walk.rows), walk.expected);
    }
}
