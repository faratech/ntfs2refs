//! The reads the raw inspection makes next, read ahead on read lanes of the
//! frozen source.
//!
//! The MFT scan made each of its reads by itself, at a queue depth of one:
//! on the full Windows volume 58,637 device reads of 193 µs each, most of
//! them one directory's index or one small stream's few clusters. When the
//! scan loads a window of the MFT, the records in it say which of those
//! reads it is about to make: [`window_reads`] finds them (a directory's
//! `$I30` allocation and bitmap, a stream below the target cluster, which is
//! hashed as it is found, extended attributes, a reparse point, an attribute
//! list) with the next window of the MFT, and [`LanePrefetch`] reads them on
//! read lanes, several at once, into memory.
//!
//! [`PrefetchedSource`] sits under the inspection's read recorder. The scan
//! asks for every byte as before and the recorder records every read as
//! before; a read is answered from what was read ahead where that holds all
//! of it, with exactly the count the source returns for it, and otherwise by
//! the source itself. The recorded reads, the read coverage and the source
//! fingerprint are those of a scan without it. A prediction that is wrong
//! costs a read of a lane and nothing else: a read is answered only from the
//! bytes at its own device offsets, read from the same frozen source.
//!
//! Only where each thing is verified once (`--verify fast`, outside the
//! gate): `--verify thorough` and every other route read as before. The
//! lanes and what they read are paid as spare memory, and what is read
//! ahead keeps within it; where the memory or the lanes cannot be had, the
//! source is read alone, as before.
use super::paged_storage::{SourceRamLease, SourceScratch};
use super::*;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

/// What is read ahead and not yet given up, at most: the reads of about two
/// windows of the MFT and the next window itself.
const CACHE_BYTES: u64 = 48 * 1024 * 1024;
/// The lanes: the depth at which small reads gain, as the fingerprint's.
const LANES: usize = crate::parallel_digest::SMALL_READ_DEPTH;
/// A gap between two reads that one read of a lane bridges.
const BRIDGE: u64 = 32 * 1024;
/// The most one read of a lane joins of several reads.
const JOINED_BYTES: u64 = 1024 * 1024;
/// The largest attribute read ahead; a larger one is read as it is asked for.
const ATTRIBUTE_BYTES: u64 = 4 * 1024 * 1024;
const GRANULE: u64 = 4096;

/// A read lane: a handle of its own on the source, for a thread of its own.
pub(crate) trait LaneRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> LaneRead for T {}
/// Read lanes, and the most one read of the source returns.
pub(crate) type Lanes = (Vec<Box<dyn LaneRead>>, usize);

/// A source the inspection can open read lanes on.
pub(crate) trait LaneSource {
    /// `count` read lanes of the source and the most one read of the source
    /// returns (from the start of the granule it starts in), or None where
    /// there are none to be had, or where a read of the source is not
    /// answered with the count [`PrefetchedSource`] gives. A lane whose
    /// route differs from the source's frozen state is an error.
    fn prefetch_lanes(&self, count: usize) -> io::Result<Option<Lanes>>;
    /// The bytes of the source: no read is answered past them.
    fn source_length(&self) -> u64;
}
impl LaneSource for n2r_win32::GeneralFrozenPartition {
    fn source_length(&self) -> u64 {
        self.byte_len()
    }
    fn prefetch_lanes(&self, count: usize) -> io::Result<Option<Lanes>> {
        // With read-ahead on, a read is answered with what its window holds.
        if self.reads_ahead() {
            return Ok(None);
        }
        let mut events = Vec::new();
        Ok(self
            .read_lanes_if_available(count, &mut events)?
            .map(|lanes| {
                (
                    lanes
                        .into_iter()
                        .map(|lane| Box::new(lane) as Box<dyn LaneRead>)
                        .collect(),
                    n2r_win32::GeneralFrozenPartition::MAX_READ_BYTES,
                )
            }))
    }
}
impl<T: LaneSource + ?Sized> LaneSource for &mut T {
    fn prefetch_lanes(&self, count: usize) -> io::Result<Option<Lanes>> {
        (**self).prefetch_lanes(count)
    }
    fn source_length(&self) -> u64 {
        (**self).source_length()
    }
}

enum State {
    /// Handed to a lane.
    Pending,
    Read(Vec<u8>),
    /// The lane could not read it: the source is asked.
    Failed,
    /// Given up while a lane still reads it; removed when it arrives.
    Abandoned,
}
struct Block {
    end: u64,
    /// The window of the MFT it was read ahead for.
    generation: u64,
    state: State,
}

struct Engine {
    jobs: Option<mpsc::Sender<(u64, usize)>>,
    results: mpsc::Receiver<(u64, io::Result<Vec<u8>>)>,
    cancel: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
    // Declared before the lease, so the bytes are dropped before the credit
    // that pays for them.
    blocks: BTreeMap<u64, Block>,
    /// The bytes of the blocks, read or still being read.
    held: u64,
    generation: u64,
    length: u64,
    max_read: usize,
    closed: bool,
    /// Reads answered from what was read ahead.
    served: u64,
    lease: Option<SourceRamLease>,
}
impl Engine {
    /// Takes what a lane has read; with `wait`, waits for it. False where
    /// nothing came, or where the lanes have stopped.
    fn receive(&mut self, wait: bool) -> bool {
        let message = if wait {
            self.results.recv().ok()
        } else {
            match self.results.try_recv() {
                Ok(message) => Some(message),
                Err(mpsc::TryRecvError::Empty) => return false,
                Err(mpsc::TryRecvError::Disconnected) => None,
            }
        };
        let Some((start, result)) = message else {
            self.close();
            return false;
        };
        if let Some(block) = self.blocks.get_mut(&start) {
            let length = block.end - start;
            match (&block.state, result) {
                (State::Abandoned, _) => {
                    self.blocks.remove(&start);
                    self.held -= length;
                }
                (State::Pending, Ok(bytes)) if bytes.len() as u64 == length => {
                    block.state = State::Read(bytes);
                }
                (State::Pending, _) => block.state = State::Failed,
                _ => {}
            }
        }
        true
    }
    fn read_ahead(&mut self, reads: &[(u64, u64)]) {
        if self.closed {
            return;
        }
        while self.receive(false) {}
        self.generation += 1;
        // What was read ahead for the windows before the one before is
        // given up: the scan has gone past their records.
        let stale = self.generation.saturating_sub(1);
        let mut freed = 0u64;
        self.blocks.retain(|start, block| {
            if block.generation >= stale {
                return true;
            }
            match block.state {
                State::Pending => {
                    block.state = State::Abandoned;
                    true
                }
                State::Abandoned => true,
                State::Read(_) | State::Failed => {
                    freed += block.end - *start;
                    false
                }
            }
        });
        self.held -= freed;
        // Each read as the source answers it: the first call up to its
        // bound from the read's start, each after it the bound.
        let mut chunks = Vec::new();
        if chunks.try_reserve(reads.len()).is_err() {
            return;
        }
        for (rank, &(start, length)) in reads.iter().enumerate() {
            let Some(end) = start.checked_add(length).filter(|end| *end <= self.length) else {
                continue;
            };
            let mut at = start;
            while at < end {
                let next = (self.max_read as u64 - at % GRANULE).min(end - at);
                chunks.push((at, at + next, rank));
                at += next;
            }
        }
        chunks.sort_unstable();
        // Reads that overlap, or lie close together, are read at once.
        let mut blocks: Vec<(u64, u64, usize)> = Vec::new();
        for (start, end, rank) in chunks {
            match blocks.last_mut() {
                Some(last)
                    if start < last.1
                        || (start - last.1 <= BRIDGE && end - last.0 <= JOINED_BYTES) =>
                {
                    last.1 = last.1.max(end);
                    last.2 = last.2.min(rank);
                }
                _ => blocks.push((start, end, rank)),
            }
        }
        // In the order the scan asks for them.
        blocks.sort_by_key(|block| block.2);
        for (start, end, _) in blocks {
            let length = end - start;
            if self.held + length > CACHE_BYTES
                || self
                    .blocks
                    .range(..end)
                    .next_back()
                    .is_some_and(|(_, block)| block.end > start)
            {
                continue;
            }
            let Ok(size) = usize::try_from(length) else {
                continue;
            };
            let sent = self
                .jobs
                .as_ref()
                .is_some_and(|jobs| jobs.send((start, size)).is_ok());
            if !sent {
                self.close();
                return;
            }
            self.blocks.insert(
                start,
                Block {
                    end,
                    generation: self.generation,
                    state: State::Pending,
                },
            );
            self.held += length;
        }
    }
    /// Fills `output` with the bytes at `position` where they were read
    /// ahead, waiting for a lane that is reading them. False where they were
    /// not: the source is asked.
    fn serve(&mut self, position: u64, output: &mut [u8]) -> bool {
        if self.closed || output.is_empty() {
            return false;
        }
        let Some(end) = position.checked_add(output.len() as u64) else {
            return false;
        };
        loop {
            let Some((&start, block)) = self.blocks.range(..=position).next_back() else {
                return false;
            };
            if block.end < end {
                return false;
            }
            match &block.state {
                State::Read(bytes) => {
                    let at = (position - start) as usize;
                    output.copy_from_slice(&bytes[at..at + output.len()]);
                    self.served += 1;
                    return true;
                }
                State::Pending => {
                    if !self.receive(true) {
                        return false;
                    }
                }
                State::Failed | State::Abandoned => return false,
            }
        }
    }
    /// Stops reading ahead: the lanes take no more reads and what was read
    /// is given up.
    fn close(&mut self) {
        self.closed = true;
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs = None;
        self.blocks.clear();
        self.held = 0;
    }
    /// Closes, ends the lanes' threads and gives the memory back.
    fn finish(&mut self) {
        self.close();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        self.lease = None;
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        // Ends the lanes on every path, errors among them, before the
        // memory that pays for what they read is given back.
        self.finish();
    }
}

/// Reads ahead on read lanes what the scan says it reads next.
#[derive(Clone)]
pub(crate) struct LanePrefetch(Rc<RefCell<Engine>>);
impl LanePrefetch {
    /// Lanes on `source`, a partition of `length` bytes, with the spare
    /// memory they and what they read ahead need. None where the run does
    /// not verify each thing once, or where the memory, the lanes or their
    /// threads cannot be had.
    pub(crate) fn open<S: LaneSource + ?Sized>(
        source: &S,
        length: u64,
        scratch: &SourceScratch,
    ) -> Result<Option<Self>> {
        if !n2r_win32::verify_policy::verifies_once()
            || n2r_win32::verify_policy::full_unremembered()
            || source.source_length() != length
        {
            return Ok(None);
        }
        // Each lane: its device buffer, its handle and its thread's stack.
        let lane =
            n2r_win32::GeneralFrozenPartition::read_buffer_memory_bytes() + 65536 + 2 * 1024 * 1024;
        let Ok(lease) = scratch.lease_spare_ram(LANES as u64 * lane + CACHE_BYTES) else {
            return Ok(None);
        };
        let Some(lanes) = source.prefetch_lanes(LANES).context(
            "source inspection: opening read lanes of the frozen source to read the MFT scan's reads ahead",
        )?
        else {
            return Ok(None);
        };
        Ok(Self::start(lanes, length, Some(lease)))
    }
    /// Reads ahead on `lanes`, a thread each, for a partition of `length`
    /// bytes, paid by `lease`. None where a thread cannot be had.
    fn start((lanes, max_read): Lanes, length: u64, lease: Option<SourceRamLease>) -> Option<Self> {
        if max_read < GRANULE as usize || !max_read.is_multiple_of(GRANULE as usize) {
            return None;
        }
        let (jobs, queue) = mpsc::channel::<(u64, usize)>();
        let queue = Arc::new(Mutex::new(queue));
        let (finished, results) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut engine = Engine {
            jobs: Some(jobs),
            results,
            cancel: Arc::clone(&cancel),
            workers: Vec::new(),
            blocks: BTreeMap::new(),
            held: 0,
            generation: 0,
            length,
            max_read,
            closed: false,
            served: 0,
            lease,
        };
        for mut lane in lanes {
            let (queue, finished, cancel) =
                (Arc::clone(&queue), finished.clone(), Arc::clone(&cancel));
            let spawned = std::thread::Builder::new()
                .name("inspection-read-lane".into())
                .spawn(move || {
                    let _sampled = n2r_win32::stack_sampler::helper();
                    loop {
                        let job = match queue.lock() {
                            Ok(queue) => queue.recv(),
                            Err(_) => break,
                        };
                        let Ok((start, length)) = job else {
                            break;
                        };
                        let result = if cancel.load(Ordering::Relaxed) {
                            Err(io::Error::other("read-ahead stopped"))
                        } else {
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                || -> io::Result<Vec<u8>> {
                                    let mut bytes = Vec::new();
                                    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
                                    bytes.resize(length, 0);
                                    lane.seek(SeekFrom::Start(start))?;
                                    lane.read_exact(&mut bytes)?;
                                    Ok(bytes)
                                },
                            ))
                            .unwrap_or_else(|_| Err(io::Error::other("read lane panicked")))
                        };
                        if finished.send((start, result)).is_err() {
                            break;
                        }
                    }
                });
            match spawned {
                Ok(worker) => engine.workers.push(worker),
                // Without its threads nothing is read ahead: the engine
                // ends those it has.
                Err(_) => return None,
            }
        }
        Some(Self(Rc::new(RefCell::new(engine))))
    }
    /// Reads ahead `reads` (device offset and length, in the order the scan
    /// makes them) for a window of the MFT just loaded, and gives up what
    /// was read ahead for the windows before the one before.
    pub(crate) fn read_ahead(&self, reads: &[(u64, u64)]) {
        self.0.borrow_mut().read_ahead(reads);
    }
    /// Ends reading ahead: the lanes are closed and the memory given back.
    pub(crate) fn finish(&self) {
        self.0.borrow_mut().finish();
    }
    fn serve(&self, position: u64, output: &mut [u8]) -> bool {
        self.0.borrow_mut().serve(position, output)
    }
}

/// The source under the inspection's read recorder: a read is answered
/// from what was read ahead where that holds all of it, with the count the
/// source returns, and otherwise by the source.
pub(crate) struct PrefetchedSource<R> {
    inner: R,
    position: u64,
    length: u64,
    /// Whether the source's own position is this one.
    synced: bool,
    prefetch: Option<LanePrefetch>,
    max_read: usize,
}
impl<R: Read + Seek> PrefetchedSource<R> {
    pub(crate) fn new(mut inner: R, length: u64, prefetch: Option<LanePrefetch>) -> Result<Self> {
        let position = inner.stream_position()?;
        let max_read = prefetch
            .as_ref()
            .map_or(GRANULE as usize, |prefetch| prefetch.0.borrow().max_read);
        Ok(Self {
            inner,
            position,
            length,
            synced: true,
            prefetch,
            max_read,
        })
    }
}
impl<R: Read + Seek> Read for PrefetchedSource<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(prefetch) = &self.prefetch
            && !output.is_empty()
            && self.position < self.length
        {
            // What the source returns for this read: no more than its
            // bound from the start of the granule, nor past the partition.
            let prefix = (self.position % GRANULE) as usize;
            let wanted = output
                .len()
                .min(self.max_read - prefix)
                .min((self.length - self.position) as usize);
            if prefetch.serve(self.position, &mut output[..wanted]) {
                // Counted as bytes a read was answered with, as those of
                // the source's own read-ahead are.
                n2r_win32::perf::add_bytes(n2r_win32::perf::Point::DeviceReadServed, wanted as u64);
                self.position += wanted as u64;
                self.synced = false;
                return Ok(wanted);
            }
        }
        if !self.synced {
            self.inner.seek(SeekFrom::Start(self.position))?;
            self.synced = true;
        }
        let count = self.inner.read(output)?;
        self.position += count as u64;
        Ok(count)
    }
}
impl<R: Read + Seek> Seek for PrefetchedSource<R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if !self.synced {
            self.inner.seek(SeekFrom::Start(self.position))?;
            self.synced = true;
        }
        self.position = self.inner.seek(from)?;
        Ok(self.position)
    }
}

/// The reads the scan makes for the records of a window of the MFT, the
/// records `first_record` on, in the order it makes them, onto `reads`.
/// Only allocated base records from 16 on are looked at, and of them only
/// what the scan reads in full as it goes: a directory's `$I30` allocation
/// and bitmap, a stream below the target cluster when `data` (streams are
/// hashed), extended attributes, a reparse point and an attribute list, each
/// of no more than [`ATTRIBUTE_BYTES`]. A record that does not parse is
/// passed by: the scan reads what it reads, and says what is wrong with it.
pub(super) fn window_reads(
    window: &[u8],
    first_record: u64,
    geometry: &NtfsGeometry,
    data: bool,
    allocated: impl Fn(u64) -> bool,
    reads: &mut Vec<(u64, u64)>,
) {
    let size = geometry.file_record_size as usize;
    if size < 48 {
        return;
    }
    let target = n2r_win32::target_cluster::bytes();
    let mut fixed = Vec::with_capacity(size);
    for (index, raw) in window.chunks_exact(size).enumerate() {
        let number = first_record + index as u64;
        if number < 16 || !allocated(number) {
            continue;
        }
        record_reads(raw, geometry, data, target, &mut fixed, reads);
    }
}

fn record_reads(
    raw: &[u8],
    geometry: &NtfsGeometry,
    data: bool,
    target: u64,
    fixed: &mut Vec<u8>,
    reads: &mut Vec<(u64, u64)>,
) {
    if &raw[..4] != b"FILE" {
        return;
    }
    fixed.clear();
    fixed.extend_from_slice(raw);
    let (Ok(usa), Ok(usa_count)) = (u16le(fixed, 4), u16le(fixed, 6)) else {
        return;
    };
    let (usa, usa_count) = (usize::from(usa), usize::from(usa_count));
    if usa_count != usa_entries(fixed.len())
        || usa < 0x2a
        || usa + usa_count * 2 > fixed.len().min(USA_STRIDE - 2)
    {
        return;
    }
    let sequence = [fixed[usa], fixed[usa + 1]];
    for index in 1..usa_count {
        let tail = index * USA_STRIDE - 2;
        if fixed[tail..tail + 2] != sequence {
            return;
        }
        let replacement = [fixed[usa + index * 2], fixed[usa + index * 2 + 1]];
        fixed[tail..tail + 2].copy_from_slice(&replacement);
    }
    let (Ok(flags), Ok(base), Ok(used), Ok(first)) = (
        u16le(fixed, 22),
        u64le(fixed, 32),
        u32le(fixed, 24),
        u16le(fixed, 20),
    ) else {
        return;
    };
    if flags & 1 == 0 || base != 0 {
        return;
    }
    let directory = flags & 2 != 0;
    let fixed: &[u8] = fixed;
    let used = (used as usize).min(fixed.len());
    let attributes = || {
        let mut at = usize::from(first);
        std::iter::from_fn(move || {
            let header = fixed.get(at..at + 8)?;
            let type_code = u32::from_le_bytes(header[..4].try_into().ok()?);
            let size = u32::from_le_bytes(header[4..].try_into().ok()?) as usize;
            if type_code == u32::MAX || size < 24 || size % 8 != 0 || at + size > used {
                return None;
            }
            let attribute = &fixed[at..at + size];
            at += size;
            Some((type_code, attribute))
        })
    };
    // With an attribute list, the record's streams are assembled from other
    // records and are not hashed as they are found.
    let listed = attributes().any(|(type_code, _)| type_code == 0x20);
    const I30: [u8; 8] = [0x24, 0, 0x49, 0, 0x33, 0, 0x30, 0];
    for (type_code, attribute) in attributes() {
        if attribute.len() < 64 || attribute[8] != 1 {
            continue;
        }
        let name_bytes = usize::from(attribute[9]) * 2;
        let (Ok(name_at), Ok(flags), Ok(lowest), Ok(highest), Ok(runs_at), Ok(unit)) = (
            u16le(attribute, 10),
            u16le(attribute, 12),
            u64le(attribute, 16),
            u64le(attribute, 24),
            u16le(attribute, 32),
            u16le(attribute, 34),
        ) else {
            continue;
        };
        let (Ok(logical), Ok(initialized)) = (u64le(attribute, 48), u64le(attribute, 56)) else {
            continue;
        };
        let Some(name) = attribute.get(usize::from(name_at)..usize::from(name_at) + name_bytes)
        else {
            continue;
        };
        let wanted = match type_code {
            0x20 | 0xc0 | 0xe0 => true,
            0xa0 | 0xb0 => directory && name == I30,
            0x80 => data && !directory && !listed && logical < target,
            _ => false,
        };
        if !wanted
            || lowest != 0
            || flags != 0
            || unit != 0
            || logical == 0
            || logical > ATTRIBUTE_BYTES
        {
            continue;
        }
        let Some(runs) = attribute.get(usize::from(runs_at)..) else {
            continue;
        };
        let Ok(extents) = parse_runs(runs, 0, highest, geometry) else {
            continue;
        };
        // As the scan reads the attribute: each run up to the end of its
        // initialized bytes.
        let limit = initialized.min(logical);
        for extent in extents {
            if extent.logical_offset >= limit {
                break;
            }
            if let Some(physical) = extent.physical_offset {
                reads.push((physical, extent.length.min(limit - extent.logical_offset)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A partition that answers reads as the frozen source does: no more
    /// than `max_read` bytes from the start of the granule a read starts in.
    struct Granular {
        bytes: Arc<Vec<u8>>,
        position: u64,
        max_read: usize,
    }
    impl Read for Granular {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let length = self.bytes.len() as u64;
            if output.is_empty() || self.position == length {
                return Ok(0);
            }
            let prefix = (self.position % GRANULE) as usize;
            let wanted = output
                .len()
                .min(self.max_read - prefix)
                .min((length - self.position) as usize);
            let at = self.position as usize;
            output[..wanted].copy_from_slice(&self.bytes[at..at + wanted]);
            self.position += wanted as u64;
            Ok(wanted)
        }
    }
    impl Seek for Granular {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            let length = self.bytes.len() as i128;
            let position = match from {
                SeekFrom::Start(value) => i128::from(value),
                SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
                SeekFrom::End(value) => length + i128::from(value),
            };
            if position < 0 || position > length {
                return Err(io::Error::other("seek escapes the partition"));
            }
            self.position = position as u64;
            Ok(self.position)
        }
    }
    const MAX_READ: usize = 64 * 1024;
    fn partition() -> Arc<Vec<u8>> {
        Arc::new(
            (0..8u32 * 1024 * 1024)
                .map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8)
                .collect(),
        )
    }
    fn source(bytes: &Arc<Vec<u8>>) -> Granular {
        Granular {
            bytes: Arc::clone(bytes),
            position: 0,
            max_read: MAX_READ,
        }
    }
    fn prefetch(bytes: &Arc<Vec<u8>>) -> LanePrefetch {
        let lanes = (0..4)
            .map(|_| Box::new(source(bytes)) as Box<dyn LaneRead>)
            .collect();
        LanePrefetch::start((lanes, MAX_READ), bytes.len() as u64, None).unwrap()
    }
    /// Every read call of `reader` for `reads`, as a recorder sees them:
    /// where, how many bytes, and which.
    fn transcript(
        reader: &mut (impl Read + Seek),
        reads: &[(u64, usize)],
    ) -> Vec<(u64, usize, Vec<u8>)> {
        let mut calls = Vec::new();
        for &(at, length) in reads {
            reader.seek(SeekFrom::Start(at)).unwrap();
            let mut buffer = vec![0u8; length];
            let mut done = 0;
            while done < length {
                let count = reader.read(&mut buffer[done..]).unwrap();
                assert!(count > 0);
                calls.push((at + done as u64, count, buffer[done..done + count].to_vec()));
                done += count;
            }
        }
        calls
    }

    #[test]
    fn reads_answered_from_the_lanes_are_the_reads_the_source_makes() {
        let bytes = partition();
        let prefetch = prefetch(&bytes);
        // Unaligned, past the bound of one read, overlapping, close
        // together, and one past the end of the partition.
        prefetch.read_ahead(&[
            (5000, 3000),
            (4096, 200_000),
            (300_000, 512),
            (301_000, 70_000),
            (8 * 1024 * 1024 - 100, 1000),
        ]);
        let reads = [
            (5000, 3000),
            (4096, 200_000),
            (300_000, 512),
            (301_000, 70_000),
            (310_000, 1000),
            (1_000_000, 5000),
            (100, 100),
            (8 * 1024 * 1024 - 100, 100),
        ];
        let expected = transcript(&mut source(&bytes), &reads);
        let mut layered =
            PrefetchedSource::new(source(&bytes), bytes.len() as u64, Some(prefetch.clone()))
                .unwrap();
        assert_eq!(transcript(&mut layered, &reads), expected);
        let served = prefetch.0.borrow().served;
        assert!(served >= 9, "{served} reads answered from the lanes");
        // Closed, it leaves every read to the source.
        prefetch.finish();
        assert_eq!(transcript(&mut layered, &reads), expected);
        assert_eq!(prefetch.0.borrow().served, served);
        // Without lanes it is the source.
        let mut plain = PrefetchedSource::new(source(&bytes), bytes.len() as u64, None).unwrap();
        assert_eq!(transcript(&mut plain, &reads), expected);
    }

    #[test]
    fn what_was_read_ahead_for_windows_long_past_is_given_up() {
        let bytes = partition();
        let prefetch = prefetch(&bytes);
        let mut buffer = [0u8; 4096];
        prefetch.read_ahead(&[(0, 4096)]);
        prefetch.read_ahead(&[(65536, 4096)]);
        assert!(prefetch.serve(0, &mut buffer));
        assert!(prefetch.serve(65536, &mut buffer));
        assert_eq!(prefetch.0.borrow().held, 8192);
        prefetch.read_ahead(&[(131072, 4096)]);
        assert!(!prefetch.serve(0, &mut buffer), "two windows back");
        assert!(prefetch.serve(65536, &mut buffer));
        assert!(prefetch.serve(131072, &mut buffer));
        assert_eq!(&buffer[..], &bytes[131072..131072 + 4096]);
        assert_eq!(prefetch.0.borrow().held, 8192);
    }

    /// A FILE record of 1 KiB with `attributes`, its update sequence
    /// applied as on disk.
    fn record(flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[..4].copy_from_slice(b"FILE");
        bytes[4..6].copy_from_slice(&48u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&3u16.to_le_bytes());
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
        bytes[20..22].copy_from_slice(&56u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&flags.to_le_bytes());
        bytes[28..32].copy_from_slice(&1024u32.to_le_bytes());
        let mut at = 56;
        for attribute in attributes {
            bytes[at..at + attribute.len()].copy_from_slice(attribute);
            at += attribute.len();
        }
        bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
        // The update sequence number at the end of each sector, the
        // original words in the array.
        bytes[48..50].copy_from_slice(&[7, 0]);
        for sector in 1..3 {
            let tail = sector * 512 - 2;
            let original = [bytes[tail], bytes[tail + 1]];
            bytes[48 + sector * 2..50 + sector * 2].copy_from_slice(&original);
            bytes[tail..tail + 2].copy_from_slice(&[7, 0]);
        }
        bytes
    }
    /// A nonresident attribute of one run of `clusters` at `lcn`.
    fn nonresident(type_code: u32, name: &str, logical: u64, lcn: u16, clusters: u8) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let runs_at = 64 + name.len();
        let size = (runs_at + 5).div_ceil(8) * 8;
        let mut bytes = vec![0u8; size];
        bytes[..4].copy_from_slice(&type_code.to_le_bytes());
        bytes[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        bytes[8] = 1;
        bytes[9] = (name.len() / 2) as u8;
        bytes[10..12].copy_from_slice(&64u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&(u64::from(clusters) - 1).to_le_bytes());
        bytes[32..34].copy_from_slice(&(runs_at as u16).to_le_bytes());
        bytes[40..48].copy_from_slice(&(u64::from(clusters) * 4096).to_le_bytes());
        bytes[48..56].copy_from_slice(&logical.to_le_bytes());
        bytes[56..64].copy_from_slice(&logical.to_le_bytes());
        bytes[64..runs_at].copy_from_slice(&name);
        bytes[runs_at..runs_at + 4].copy_from_slice(&[0x21, clusters, lcn as u8, (lcn >> 8) as u8]);
        bytes
    }
    fn geometry() -> NtfsGeometry {
        NtfsGeometry {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_size: 4096,
            total_sectors: 1 << 24,
            volume_size: 1 << 33,
            total_clusters: 1 << 21,
            mft_lcn: 4,
            mftmirr_lcn: 2,
            file_record_size: 1024,
            index_record_size: 4096,
            serial_number: 1,
        }
    }

    #[test]
    fn a_window_says_which_indexes_and_small_streams_the_scan_reads() {
        let directory = record(
            3,
            &[
                nonresident(0xa0, "$I30", 8192, 0x200, 2),
                nonresident(0xb0, "$I30", 8, 0x300, 1),
                // A directory's own stream is not hashed as it is found.
                nonresident(0x80, "", 100, 0x400, 1),
            ],
        );
        let file = record(
            1,
            &[
                nonresident(0x80, "", 1000, 0x100, 1),
                nonresident(0xe0, "", 300, 0x500, 1),
                // Another index than $I30 is not read by the scan.
                nonresident(0xa0, "$O", 4096, 0x600, 1),
            ],
        );
        let unallocated = record(1, &[nonresident(0x80, "", 1000, 0x700, 1)]);
        let window: Vec<u8> = [directory, file, unallocated].concat();
        let mut reads = Vec::new();
        window_reads(&window, 40, &geometry(), true, |n| n != 42, &mut reads);
        assert_eq!(
            reads,
            [
                (0x200 * 4096, 8192),
                (0x300 * 4096, 8),
                (0x100 * 4096, 1000),
                (0x500 * 4096, 300),
            ]
        );
        // Streams not hashed (a preparation), and system records.
        reads.clear();
        window_reads(&window, 40, &geometry(), false, |_| true, &mut reads);
        assert_eq!(
            reads,
            [(0x200 * 4096, 8192), (0x300 * 4096, 8), (0x500 * 4096, 300),]
        );
        reads.clear();
        window_reads(&window, 0, &geometry(), true, |_| true, &mut reads);
        assert!(reads.is_empty());
        // A torn record is passed by.
        let mut torn = window.clone();
        torn[510] ^= 1;
        reads.clear();
        window_reads(&torn[..1024], 40, &geometry(), true, |_| true, &mut reads);
        assert!(reads.is_empty());
    }
}
