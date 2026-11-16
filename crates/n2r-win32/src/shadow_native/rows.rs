//! The rows of a native report: one [`ObjectReport`] for each object of the
//! volume walk, in the order of the walk. Nothing outside this module holds
//! the rows' storage: a row is lent to a closure and to nothing longer.
//!
//! Where the walk's payer offers working storage, the rows are kept in
//! blocks. A block stays in memory while the payer lends memory for it, as
//! memory it may ask back; when it does, or has none to lend, the block is
//! written to the rows file and read back from there, two blocks at a time.
//! A run with memory to spare writes nothing and reads nothing back. Where
//! the payer has no working storage the rows are one vector, each row paid
//! for until the report is dropped, as they always were.
use super::ObjectReport;
use super::report_memory::{ReportMemoryAccountant, ReportMemoryLease, SpillFile, row_bytes};
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
    file: OwnerOnly<FileState>,
    // The file is still being written, and whether a block is in it.
    writing: bool,
    any_written: bool,
    // A row was changed in place: the rows stay in memory from then on.
    pinned: bool,
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
            any_written,
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
                // times the rows' bytes, and the block's own records.
                spill.extend(block.bytes.saturating_mul(8).saturating_add(65536))?;
                writer.write_block(number as u64, rows)?;
                block.written = true;
                *any_written = true;
            }
            Ok(())
        })();
        if let Err(error) = &result {
            self.failed = Some(error.to_string());
        }
        result
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
    /// The payer wants memory back: the blocks in memory go to the file.
    /// Nothing is reserved here, and the file is not closed here (closing
    /// it hashes it under a reservation): the end of the walk does that.
    fn give_up(&self) -> bool {
        // Held by this thread: the rows are in use at this moment.
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.pinned
            || state.failed.is_some()
            || !state.writing
            || !state.blocks.iter().any(|block| block.held.is_some())
        {
            return false;
        }
        if state.write_held().is_err() {
            return false;
        }
        // The rows first, then what paid for them.
        let held: Vec<_> = state
            .blocks
            .iter_mut()
            .filter_map(|block| block.held.take())
            .collect();
        drop(state);
        drop(held);
        true
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
        // The window holds two blocks read back: it has to cover this one.
        let covered = self.lock()?.window_block_bytes;
        if bytes > covered {
            let more = payer.reserve((bytes - covered).saturating_mul(2))?;
            let mut state = self.lock()?;
            state._leases.push(more);
            state.window_block_bytes = bytes;
        }
        let cache = payer.reserve_cache(bytes.saturating_add(4096)).ok();
        let mut state = self.lock()?;
        state.check()?;
        let first = state.blocks.last().map_or(0, |last| last.first + last.rows);
        let count = rows.len();
        let rows = Arc::new(rows);
        match cache {
            Some(cache) => {
                // Paid for as memory that can be asked back: the rows' own
                // reservations go.
                drop(leases);
                state.blocks.push(Block {
                    first,
                    rows: count,
                    bytes,
                    held: Some((rows, vec![cache])),
                    written: false,
                });
            }
            None => {
                // No memory to lend: into the file, behind every block
                // before it, with the rows' own reservations held until it
                // is there.
                state.write_held()?;
                state.blocks.push(Block {
                    first,
                    rows: count,
                    bytes,
                    held: Some((rows, leases)),
                    written: false,
                });
                state.write_held()?;
                let written = state.blocks.last_mut().and_then(|block| block.held.take());
                drop(state);
                drop(written);
            }
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

    /// Rows kept in blocks, with `spill` for the blocks that have no room
    /// in memory. Made on the thread that drives the run.
    pub(super) fn paged(
        payer: &dyn ReportMemoryAccountant,
        spill: Box<dyn SpillFile>,
    ) -> io::Result<Self> {
        let own = payer.reserve(STORE_BYTES)?;
        let path = spill.path().to_owned();
        let budget = spill.page_budget();
        let writer = Box::new(file::RowsFileWriter::new(&path, budget)?);
        let paged = Arc::new(Paged {
            state: Mutex::new(State {
                count: 0,
                blocks: Vec::new(),
                tail: Vec::new(),
                tail_leases: Vec::new(),
                tail_bytes: 0,
                complete: false,
                window: Vec::new(),
                window_block_bytes: BLOCK_BYTES,
                file: OwnerOnly::new(FileState::Writing {
                    writer,
                    spill,
                    path,
                    budget,
                }),
                writing: true,
                any_written: false,
                pinned: false,
                failed: None,
                _leases: vec![own],
            }),
            owner: std::thread::current().id(),
            used: AtomicU64::new(crate::evict::now()),
        });
        let evictor = Rc::new(Evictor(Arc::downgrade(&paged)));
        crate::evict::register(&evictor);
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
        let closed = {
            let mut state = paged.lock()?;
            state.check()?;
            if state.complete {
                return Err(invalid("a row was added after the last"));
            }
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
        // The file is closed here, while its payer is at hand and before
        // the storage it is in is sealed. Once part of the rows is in it,
        // all of them go there. If none is, the rows stay in memory from
        // here on: there is no file left to give them up to.
        if state.writing {
            let any = state.any_written;
            if any {
                state.write_held()?;
            }
            state.finish_file()?;
            if any {
                let held: Vec<_> = state
                    .blocks
                    .iter_mut()
                    .filter_map(|block| block.held.take())
                    .collect();
                drop(state);
                drop(held);
            }
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

    /// Changes a row in place. Rows in blocks stay in memory from the first
    /// change on; rows that are in the file already cannot be changed.
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
            Store::Paged(paged) => {
                let mut state = paged.lock()?;
                state.check()?;
                if state.blocks.iter().any(|block| block.held.is_none()) {
                    return Err(failed(
                        "a row cannot be changed once rows are in working storage",
                    ));
                }
                state.pinned = true;
                let number = state.block_of(index)?;
                let block = &mut state.blocks[number];
                let first = block.first;
                let rows = block
                    .held
                    .as_mut()
                    .and_then(|(rows, _)| Arc::get_mut(rows))
                    .ok_or_else(|| failed("a row was changed while its block was being read"))?;
                change(&mut rows[index - first])
            }
        }
    }
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

    /// A payer that lends cache memory up to a limit and offers a working
    /// file in a directory; it counts what is reserved.
    struct Payer {
        held: Arc<AtomicU64>,
        cache_limit: u64,
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
    impl Payer {
        fn lease(&self, bytes: u64) -> Lease {
            self.held.fetch_add(bytes, Ordering::SeqCst);
            Box::new(Counted(Arc::clone(&self.held), bytes))
        }
    }
    impl ReportMemoryAccountant for Payer {
        fn reserve(&self, bytes: u64) -> io::Result<Lease> {
            Ok(self.lease(bytes))
        }
        fn reserve_cache(&self, bytes: u64) -> io::Result<Lease> {
            if self.held.load(Ordering::SeqCst) + bytes > self.cache_limit {
                return Err(io::Error::other("no memory to lend"));
            }
            Ok(self.lease(bytes))
        }
        fn spill_file(&self) -> io::Result<Option<Box<dyn SpillFile>>> {
            Ok(Some(Box::new(File {
                path: self.directory.join("rows.pages"),
                closed: Arc::clone(&self.closed),
            })))
        }
        fn lease_heap_bytes(&self) -> u64 {
            16
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

    /// 700 rows in blocks under a payer that lends `cache_limit` bytes.
    fn paged(cache_limit: u64) -> (Rows, Payer, Vec<String>, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let payer = Payer {
            held: Arc::new(AtomicU64::new(0)),
            cache_limit,
            directory: directory.path().to_owned(),
            closed: Arc::new(AtomicBool::new(false)),
        };
        let mut rows = Rows::paged(&payer, payer.spill_file().unwrap().unwrap()).unwrap();
        assert!(rows.in_blocks());
        let mut expected = Vec::new();
        for number in 0..700 {
            let row = row(&format!("object-{number}"));
            expected.push(serde_json::to_string(&row).unwrap());
            let lease = payer.reserve(row_bytes(&row).unwrap()).unwrap();
            rows.push_paid(&payer, row, lease).unwrap();
        }
        rows.finish(Some(&payer)).unwrap();
        assert_eq!(rows.len(), 700);
        (rows, payer, expected, directory)
    }

    #[test]
    fn rows_in_blocks_with_memory_to_spare_write_nothing() {
        let (rows, payer, expected, directory) = paged(u64::MAX / 2);
        assert_eq!(text(&rows), expected);
        assert_eq!(
            rows.with(699, |row| Ok(row.components[0].clone())).unwrap(),
            "object-699"
        );
        assert!(rows.with(700, |_| Ok(())).is_err());
        // The file was made and holds no block; it was closed when the
        // last row was in, and the rows stay in memory.
        assert!(payer.closed.load(Ordering::SeqCst));
        let Store::Paged(inner) = &rows.store else {
            panic!("rows in blocks")
        };
        assert!(!inner.lock().unwrap().any_written);
        assert!(!inner.give_up(), "no file is left to give the rows up to");
        assert_eq!(text(&rows), expected);
        drop(rows);
        assert_eq!(payer.held.load(Ordering::SeqCst), 0);
        drop(directory);
    }

    #[test]
    fn rows_in_blocks_with_no_memory_to_lend_are_read_back_from_the_file() {
        let (rows, payer, expected, _directory) = paged(0);
        // Every block is in the file, which is closed; what is held is the
        // rows' own reservation.
        assert!(payer.closed.load(Ordering::SeqCst));
        assert_eq!(payer.held.load(Ordering::SeqCst), STORE_BYTES);
        assert_eq!(text(&rows), expected);
        // Out of order, and from inside a walk over the rows.
        for index in [650, 3, 300, 699, 0] {
            let name = rows
                .with(index, |row| Ok(row.components[0].clone()))
                .unwrap();
            assert_eq!(name, format!("object-{index}"));
        }
        rows.for_each(|index, row| {
            let other = 699 - index;
            rows.with(other, |far| {
                assert_eq!(far.components[0], format!("object-{other}"));
                Ok(())
            })?;
            assert_eq!(row.components[0], format!("object-{index}"));
            Ok(())
        })
        .unwrap();
        assert_eq!(serde_json::to_string(&rows).unwrap(), {
            format!("[{}]", expected.join(","))
        });
        assert_eq!(payer.held.load(Ordering::SeqCst), STORE_BYTES);
    }

    #[test]
    fn rows_in_blocks_go_to_the_file_when_their_memory_is_asked_back() {
        let directory = tempfile::tempdir().unwrap();
        let payer = Payer {
            held: Arc::new(AtomicU64::new(0)),
            cache_limit: u64::MAX / 2,
            directory: directory.path().to_owned(),
            closed: Arc::new(AtomicBool::new(false)),
        };
        let mut rows = Rows::paged(&payer, payer.spill_file().unwrap().unwrap()).unwrap();
        let mut expected = Vec::new();
        let mut add = |rows: &mut Rows, from: usize, to: usize| {
            for number in from..to {
                let row = row(&format!("object-{number}"));
                expected.push(serde_json::to_string(&row).unwrap());
                let lease = payer.reserve(row_bytes(&row).unwrap()).unwrap();
                rows.push_paid(&payer, row, lease).unwrap();
            }
        };
        // Two blocks are closed and in memory, with rows of a third.
        add(&mut rows, 0, 600);
        let Store::Paged(inner) = &rows.store else {
            panic!("rows in blocks")
        };
        let inner = Arc::clone(inner);
        let before = payer.held.load(Ordering::SeqCst);
        // The payer asks for memory back while the walk goes on: the closed
        // blocks go to the file, and what paid for them is returned.
        assert!(inner.give_up());
        let after = payer.held.load(Ordering::SeqCst);
        assert!(after < before, "{after} of {before}");
        assert!(!inner.give_up(), "nothing is left to give up");
        // The walk goes on, and at its end every row is in the file.
        add(&mut rows, 600, 700);
        rows.finish(Some(&payer)).unwrap();
        assert!(payer.closed.load(Ordering::SeqCst));
        assert_eq!(payer.held.load(Ordering::SeqCst), STORE_BYTES);
        assert_eq!(text(&rows), expected);
        // No lock is held while a row is lent.
        rows.with(5, |_| {
            assert!(inner.state.try_lock().is_ok());
            Ok(())
        })
        .unwrap();
        let pinned = rows.pin(400).unwrap();
        assert_eq!(pinned.row().components[0], "object-400");
        assert!(pinned.block().is_some());
        drop(pinned);
        // Rows in the file cannot be changed.
        assert!(rows.set_logical_sha256(1, None).is_err());
    }

    #[test]
    fn rows_in_blocks_are_changed_in_place_and_then_stay_in_memory() {
        let (mut rows, _payer, _expected, _directory) = paged(u64::MAX / 2);
        rows.set_logical_sha256(300, Some("digest".to_owned()))
            .unwrap();
        assert_eq!(
            rows.with(300, |row| Ok(row.logical_sha256.clone()))
                .unwrap(),
            Some("digest".to_owned())
        );
        let Store::Paged(inner) = &rows.store else {
            panic!("rows in blocks")
        };
        assert!(!inner.give_up(), "changed rows are not in the file");
    }
}
