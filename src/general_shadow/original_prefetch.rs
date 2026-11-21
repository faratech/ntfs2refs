//! Reads the chunks a comparison is about to ask for, through other handles
//! of the same frozen disk.
//!
//! A capture compares a frozen source with a frozen shadow one chunk of at
//! most 4 MiB after another, on one thread: it read one disk, then the other,
//! then hashed and compared the chunk. Neither disk had a read outstanding
//! while the other was read or the chunk was compared. Here helper threads
//! each own a read lane of one of the disks and the list of ranges the
//! comparison walks, and read the same chunks at the same places, ahead of
//! the comparison: the chunks are dealt to the lanes in turn (the first to
//! the first lane, the second to the second, and so on), so that as many
//! reads as there are lanes are outstanding at once. Each lane can hash its
//! chunks as it reads them, so that the comparing thread does not.
//!
//! The comparison takes the chunks in order (from the lanes in the same
//! turn) and says, for each, the place and the length it expects. A read
//! that failed is handed over when its chunk is asked for and not before:
//! every chunk before it is taken first, so the error a comparison reports
//! first is the one it reported first without the helpers. The helpers own
//! their lanes, the list and their buffers, and borrow nothing of the run.
//! They have ended, and their lanes are closed, when the owner of the
//! prefetch is finished or dropped.
use crate::refs_write_set::ByteRange;
use anyhow::{Context, Result, ensure};
use n2r_win32::GeneralFrozenPartition;
use std::{
    io::{self, Read, Seek, SeekFrom},
    sync::{Arc, mpsc},
};

/// The chunks one lane may have read that the comparison has not asked for,
/// where it is the only lane: two, as before.
const AHEAD_ALONE: usize = 2;
/// The same where there are several lanes: one each. Between them they are
/// still as many chunks ahead as there are lanes, and each lane holds two
/// buffers, the one it reads into and the one waiting to be taken.
const AHEAD_EACH: usize = 1;
/// The most lanes a prefetch opens on one disk.
const MOST_LANES: usize = 4;
/// A helper thread's stack.
const STACK_BYTES: u64 = 2 * 1024 * 1024;
/// What opening a lane asks Windows: one state query of the disk, whose
/// replies (at most 64 KiB of layout and small fixed buffers) are dropped
/// once the lane's route has been held to the frozen state.
const LANE_OPEN_BYTES: u64 = 1024 * 1024;

/// One chunk as a helper read it.
pub(crate) struct PrefetchedChunk {
    /// Where on the partition the chunk begins.
    pub(crate) offset: u64,
    pub(crate) bytes: Vec<u8>,
    /// The XXH3-128 of `bytes` (`parallel_digest::xxh3_128`), where the
    /// prefetch was started to hash.
    pub(crate) xxh3_128: Option<[u8; 16]>,
}

/// One lane's helper: the chunks it read, in its order, and the buffers it
/// may read into.
struct Lane {
    filled: mpsc::Receiver<io::Result<PrefetchedChunk>>,
    free: mpsc::SyncSender<Vec<u8>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

pub(crate) struct OriginalPrefetch {
    lanes: Vec<Lane>,
    // The lane the next chunk comes from, and the one the last came from
    // (whose buffer count the buffer handed back restores).
    next: usize,
    last: usize,
    // What pays for the buffers, the list, the lanes and the stacks:
    // returned once the helpers have ended and they are gone.
    _paid: Option<Box<dyn std::any::Any>>,
}

impl OriginalPrefetch {
    /// How many lanes to read one disk through, from the number of reads
    /// Windows says it takes at once (`IoProfile::queue_depth`): none on a
    /// device that takes one at a time, as before. A comparison's chunks are
    /// cut by the ranges it walks and are mostly far smaller than the
    /// requests that depth was measured with (on the full Windows volume
    /// 101,000 reads of 210 KiB on average, at one read outstanding), so
    /// such a device is given twice its depth, up to [`MOST_LANES`].
    pub(crate) fn lanes_for(queue_depth: usize) -> usize {
        if queue_depth < 2 {
            0
        } else {
            queue_depth.saturating_mul(2).min(MOST_LANES)
        }
    }

    fn ahead(lanes: usize) -> usize {
        if lanes > 1 { AHEAD_EACH } else { AHEAD_ALONE }
    }

    /// What a prefetch of `lanes` lanes holds: each lane's buffers, the lane
    /// (its own buffer and what opening it asks) and the stack of its
    /// helper, and the list of the `ranges` they walk. All of it only buys
    /// speed: it is asked for as spare memory, and a comparison that is
    /// refused it reads as it did.
    pub(crate) fn workspace_bytes(lanes: usize, chunk: usize, ranges: u64) -> Option<u64> {
        let buffers = (Self::ahead(lanes) as u64 + 1).checked_mul(chunk as u64)?;
        let lane = buffers
            .checked_add(GeneralFrozenPartition::read_buffer_memory_bytes())?
            .checked_add(LANE_OPEN_BYTES)?
            .checked_add(STACK_BYTES)?;
        (lanes as u64)
            .checked_mul(lane)?
            .checked_add(ranges.checked_mul(std::mem::size_of::<ByteRange>() as u64)?)
    }

    /// The most lanes, from `wanted` down to one, whose workspace `reserve`
    /// grants, with what it granted: `None` where not even one lane's is.
    pub(crate) fn reserve_lanes<P>(
        wanted: usize,
        chunk: usize,
        ranges: u64,
        reserve: impl Fn(u64) -> Option<P>,
    ) -> Option<(usize, P)> {
        (1..=wanted).rev().find_map(|lanes| {
            Self::workspace_bytes(lanes, chunk, ranges)
                .and_then(&reserve)
                .map(|paid| (lanes, paid))
        })
    }

    /// For a capture that holds the frozen source itself: a lane of it, when
    /// the device takes more than one outstanding read. The ranges are kept,
    /// not one descriptor for every chunk on the volume, so that the list is
    /// in proportion to the selection even for a complete capture of a very
    /// large volume. Nothing pays for this one: the capture that uses it has
    /// no ledger, and so it keeps the one lane it had, whose memory nothing
    /// grants.
    pub(crate) fn for_partition(
        source: &GeneralFrozenPartition,
        selection: &[ByteRange],
        chunk: usize,
    ) -> Result<Option<Self>> {
        if Self::lanes_for(source.io_profile().queue_depth) == 0 {
            return Ok(None);
        }
        let lanes = source.read_lanes(1, &mut Vec::new())?;
        if lanes.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::start(
            "n2r-original-prefetch",
            lanes,
            selection.to_vec(),
            chunk,
            false,
            None,
        )?))
    }

    /// Starts a helper for each lane. Together they read every range of
    /// `ranges` in order, each in chunks of at most `chunk` bytes from the
    /// range's start, as the comparison does: the n-th chunk is read by lane
    /// n modulo the number of lanes. Each hashes its chunks when `hash` is
    /// set. `paid` is whatever reserved [`Self::workspace_bytes`] for as
    /// many lanes; it is kept until the helpers have ended.
    ///
    /// An error is a helper that could not be started (no memory for a
    /// buffer, no thread). The helpers started are stopped, nothing is
    /// handed over and the lanes are closed: the caller reads as it did.
    pub(crate) fn start<L: Read + Seek + Send + 'static>(
        name: &'static str,
        lanes: Vec<L>,
        ranges: Vec<ByteRange>,
        chunk: usize,
        hash: bool,
        paid: Option<Box<dyn std::any::Any>>,
    ) -> io::Result<Self> {
        let count = lanes.len();
        if count == 0 {
            return Err(io::Error::other("a prefetch needs a lane"));
        }
        let ahead = Self::ahead(count);
        let ranges: Arc<[ByteRange]> = ranges.into();
        let mut started = Self {
            lanes: Vec::with_capacity(count),
            next: 0,
            last: 0,
            _paid: paid,
        };
        for (turn, mut lane) in lanes.into_iter().enumerate() {
            let (filled_tx, filled) = mpsc::sync_channel(ahead);
            let (free, free_rx) = mpsc::sync_channel::<Vec<u8>>(ahead + 1);
            for _ in 0..=ahead {
                let mut buffer = Vec::new();
                buffer.try_reserve_exact(chunk).map_err(|_| {
                    io::Error::new(io::ErrorKind::OutOfMemory, "no memory to read ahead")
                })?;
                buffer.resize(chunk, 0);
                let _ = free.send(buffer);
            }
            let ranges = Arc::clone(&ranges);
            let worker = std::thread::Builder::new()
                .name(name.into())
                .spawn(move || {
                    let _sampled = n2r_win32::stack_sampler::helper();
                    let mut ordinal = 0usize;
                    for range in ranges.iter() {
                        let mut done = 0;
                        while done < range.length {
                            let length = (range.length - done).min(chunk as u64);
                            let offset = range.offset + done;
                            done += length;
                            let mine = ordinal % count == turn;
                            ordinal += 1;
                            if !mine {
                                continue;
                            }
                            let Ok(mut buffer) = free_rx.recv() else {
                                return;
                            };
                            buffer.resize(length as usize, 0);
                            let result = lane
                                .seek(SeekFrom::Start(offset))
                                .and_then(|_| lane.read_exact(&mut buffer))
                                .map(|()| PrefetchedChunk {
                                    offset,
                                    xxh3_128: hash
                                        .then(|| crate::parallel_digest::xxh3_128(&buffer)),
                                    bytes: buffer,
                                });
                            let stop = result.is_err();
                            if filled_tx.send(result).is_err() || stop {
                                return;
                            }
                        }
                    }
                });
            // `started` stops the helpers already running if this one
            // cannot be.
            let worker = worker?;
            started.lanes.push(Lane {
                filled,
                free,
                worker: Some(worker),
            });
        }
        Ok(started)
    }

    /// The next chunk, which the comparison expects to be `count` bytes at
    /// `offset`. A read a helper failed is returned here, for its chunk.
    pub(crate) fn next(&mut self, offset: u64, count: usize) -> Result<PrefetchedChunk> {
        let turn = self.next;
        let lane = self.lanes.get(turn).context("prefetch has ended")?;
        let chunk = lane
            .filled
            .recv()
            .map_err(|_| anyhow::anyhow!("prefetch stopped early"))?
            .with_context(|| format!("reading {count} bytes at partition offset {offset} ahead"))?;
        self.last = turn;
        self.next = (turn + 1) % self.lanes.len();
        ensure!(
            chunk.offset == offset && chunk.bytes.len() == count,
            "prefetched chunk differs from the comparison's: {} bytes at {}, not {count} at {offset}",
            chunk.bytes.len(),
            chunk.offset
        );
        Ok(chunk)
    }

    /// Hands a buffer the comparison is done with back to the lane whose
    /// chunk was taken last: every lane keeps its number of buffers.
    pub(crate) fn recycle(&self, buffer: Vec<u8>) {
        if let Some(lane) = self.lanes.get(self.last) {
            let _ = lane.free.send(buffer);
        }
    }

    /// Ends the helpers and waits for them. Whatever each was blocked on (a
    /// free buffer, room for a chunk it read) is gone first, so it returns.
    fn stop(&mut self) -> Result<()> {
        let mut workers = Vec::with_capacity(self.lanes.len());
        for lane in self.lanes.drain(..) {
            let Lane {
                filled,
                free,
                worker,
            } = lane;
            drop(filled);
            drop(free);
            workers.extend(worker);
        }
        let mut ended = Ok(());
        for worker in workers {
            if worker.join().is_err() {
                ended = Err(anyhow::anyhow!("prefetch helper panicked"));
            }
        }
        ended
    }

    /// The comparison is over: the helpers must have read exactly its
    /// chunks.
    pub(crate) fn finish(mut self) -> Result<()> {
        let beyond = self
            .lanes
            .iter()
            .any(|lane| lane.filled.try_recv().is_ok());
        let ended = self.stop();
        ensure!(!beyond, "prefetch read beyond the comparison");
        ended
    }
}

impl Drop for OriginalPrefetch {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The most lanes [`LaneReads`] opens: the scheduler's deepest queue.
const MOST_SMALL_LANES: usize = n2r_win32::io_profile::MAX_QUEUE_DEPTH;
/// A [`LaneReads`] helper's stack: it reads into a buffer of its own.
const SMALL_STACK_BYTES: u64 = 256 * 1024;

/// Single reads of small ranges of a frozen disk, asked for ahead of the
/// caller and made on helper threads that each own a read lane of it.
///
/// The caller asks for ranges in the order it likes the disk to be read in
/// (its place on the disk), is given a ticket for each, and takes them back
/// by their tickets in the order it needs them: the order of the results is
/// restored by the tickets. A ticket's read may have failed; that is for the
/// caller to decide on, and it has the bytes read some other way then. The
/// helpers own their lanes and borrow nothing of the run; they have ended,
/// and their lanes are closed, when the owner is dropped.
pub(crate) struct LaneReads {
    asks: Option<mpsc::Sender<(u64, u64, usize)>>,
    results: mpsc::Receiver<(u64, io::Result<Vec<u8>>)>,
    arrived: std::collections::BTreeMap<u64, io::Result<Vec<u8>>>,
    issued: u64,
    stop: Arc<std::sync::atomic::AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
    _paid: Option<Box<dyn std::any::Any>>,
}

impl LaneReads {
    /// How many lanes to read small ranges through, from the number of
    /// reads Windows says the device takes at once: none on a device that
    /// takes one at a time. Each of these reads is a few KiB, far below the
    /// requests that depth was measured with, so the device is given four
    /// times its depth, up to the scheduler's deepest queue.
    pub(crate) fn lanes_for(queue_depth: usize) -> usize {
        if queue_depth < 2 {
            0
        } else {
            queue_depth.saturating_mul(4).min(MOST_SMALL_LANES)
        }
    }

    /// What `lanes` lanes hold beside the bytes read, which the caller pays
    /// for apart (they are its own once taken): each lane's buffer and what
    /// opening it asks, and a helper's stack.
    pub(crate) fn workspace_bytes(lanes: usize) -> Option<u64> {
        GeneralFrozenPartition::read_buffer_memory_bytes()
            .checked_add(LANE_OPEN_BYTES)?
            .checked_add(SMALL_STACK_BYTES)?
            .checked_mul(lanes as u64)
    }

    /// Starts a helper for each of `lanes`. An error is a helper that could
    /// not be started; those started are stopped and nothing was read.
    pub(crate) fn start<L: Read + Seek + Send + 'static>(
        name: &'static str,
        lanes: Vec<L>,
        paid: Option<Box<dyn std::any::Any>>,
    ) -> io::Result<Self> {
        if lanes.is_empty() {
            return Err(io::Error::other("lane reads need a lane"));
        }
        let (asks, asked) = mpsc::channel::<(u64, u64, usize)>();
        let asked = Arc::new(std::sync::Mutex::new(asked));
        let (results_tx, results) = mpsc::channel();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut started = Self {
            asks: Some(asks),
            results,
            arrived: std::collections::BTreeMap::new(),
            issued: 0,
            stop: Arc::clone(&stop),
            workers: Vec::with_capacity(lanes.len()),
            _paid: paid,
        };
        for mut lane in lanes {
            let asked = Arc::clone(&asked);
            let results = results_tx.clone();
            let stop = Arc::clone(&stop);
            let worker = std::thread::Builder::new()
                .name(name.into())
                .stack_size(SMALL_STACK_BYTES as usize)
                .spawn(move || {
                    let _sampled = n2r_win32::stack_sampler::helper();
                    loop {
                        let next = asked
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok((ticket, offset, length)) = next else {
                            return;
                        };
                        if stop.load(std::sync::atomic::Ordering::Acquire) {
                            return;
                        }
                        let mut buffer = Vec::new();
                        let result = match buffer.try_reserve_exact(length) {
                            Err(_) => Err(io::Error::new(
                                io::ErrorKind::OutOfMemory,
                                "no memory to read ahead",
                            )),
                            Ok(()) => {
                                buffer.resize(length, 0);
                                lane.seek(SeekFrom::Start(offset))
                                    .and_then(|_| lane.read_exact(&mut buffer))
                                    .map(|()| buffer)
                            }
                        };
                        if results.send((ticket, result)).is_err() {
                            return;
                        }
                    }
                })?;
            started.workers.push(worker);
        }
        Ok(started)
    }

    /// Asks for the `length` bytes at `offset`; the ticket takes them back.
    pub(crate) fn ask(&mut self, offset: u64, length: usize) -> u64 {
        let ticket = self.issued;
        self.issued += 1;
        let asked = self
            .asks
            .as_ref()
            .is_some_and(|asks| asks.send((ticket, offset, length)).is_ok());
        if !asked {
            self.arrived.insert(
                ticket,
                Err(io::Error::other("lane reads have ended")),
            );
        }
        ticket
    }

    /// The bytes asked for under `ticket`, or why they could not be read.
    /// Waits for them; the results of other tickets that arrive meanwhile
    /// are kept for theirs.
    pub(crate) fn take(&mut self, ticket: u64) -> io::Result<Vec<u8>> {
        loop {
            if let Some(result) = self.arrived.remove(&ticket) {
                return result;
            }
            match self.results.recv() {
                Ok((arrived, result)) => {
                    self.arrived.insert(arrived, result);
                }
                Err(_) => return Err(io::Error::other("lane reads stopped early")),
            }
        }
    }

    /// Ends the helpers and waits for them: what is still asked is not
    /// read.
    fn stop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.asks.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        self.arrived.clear();
    }
}

impl Drop for LaneReads {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disk of `length` bytes whose byte at `n` is `n` modulo 251.
    struct Disk {
        position: u64,
        length: u64,
        fail_at: Option<u64>,
    }
    impl Read for Disk {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.fail_at.is_some_and(|at| at == self.position) {
                return Err(io::Error::other("unreadable sector"));
            }
            let count = output.len().min((self.length - self.position) as usize);
            for (index, byte) in output[..count].iter_mut().enumerate() {
                *byte = ((self.position + index as u64) % 251) as u8;
            }
            self.position += count as u64;
            Ok(count)
        }
    }
    impl Seek for Disk {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            let SeekFrom::Start(at) = from else {
                unreachable!("lanes seek from the start");
            };
            self.position = at;
            Ok(at)
        }
    }
    fn disk(fail_at: Option<u64>) -> Disk {
        Disk {
            position: 0,
            length: 1 << 20,
            fail_at,
        }
    }
    fn chunks(ranges: &[ByteRange], chunk: u64) -> Vec<(u64, usize)> {
        let mut all = Vec::new();
        for range in ranges {
            let mut done = 0;
            while done < range.length {
                let count = (range.length - done).min(chunk);
                all.push((range.offset + done, count as usize));
                done += count;
            }
        }
        all
    }
    fn ranges() -> Vec<ByteRange> {
        [(0, 10_000), (12_288, 4096), (40_000, 1), (65_536, 33_333)]
            .into_iter()
            .map(|(offset, length)| ByteRange { offset, length })
            .collect()
    }

    /// However many lanes read ahead, the comparison takes every chunk in
    /// its order, with the bytes at its place and their digest, and the
    /// helpers read nothing beyond it.
    #[test]
    fn several_lanes_hand_over_the_chunks_in_the_comparisons_order() {
        for lanes in 1..=MOST_LANES {
            let mut prefetch = OriginalPrefetch::start(
                "test-prefetch",
                (0..lanes).map(|_| disk(None)).collect(),
                ranges(),
                4096,
                true,
                None,
            )
            .unwrap();
            let mut buffer = Vec::new();
            for (offset, count) in chunks(&ranges(), 4096) {
                let chunk = prefetch.next(offset, count).unwrap();
                let expected: Vec<u8> = (offset..offset + count as u64)
                    .map(|at| (at % 251) as u8)
                    .collect();
                assert_eq!(chunk.bytes, expected, "{lanes} lanes, chunk at {offset}");
                assert_eq!(
                    chunk.xxh3_128,
                    Some(crate::parallel_digest::xxh3_128(&expected))
                );
                prefetch.recycle(std::mem::replace(&mut buffer, chunk.bytes));
            }
            prefetch.finish().unwrap();
        }
    }

    /// A read that fails is reported for its own chunk, after every chunk
    /// before it was handed over, whichever lane read it.
    #[test]
    fn a_failed_read_is_reported_for_its_chunk_after_the_ones_before_it() {
        let all = chunks(&ranges(), 4096);
        let (failing, _) = all[5];
        for lanes in 1..=MOST_LANES {
            let mut prefetch = OriginalPrefetch::start(
                "test-prefetch",
                (0..lanes).map(|_| disk(Some(failing))).collect(),
                ranges(),
                4096,
                false,
                None,
            )
            .unwrap();
            for &(offset, count) in &all[..5] {
                let chunk = prefetch.next(offset, count).unwrap();
                prefetch.recycle(chunk.bytes);
            }
            let (offset, count) = all[5];
            let Err(error) = prefetch.next(offset, count) else {
                panic!("{lanes} lanes: the failed chunk was handed over");
            };
            assert!(
                format!("{error:#}").contains("unreadable sector"),
                "{lanes} lanes: {error:#}"
            );
        }
    }

    /// Ranges asked for in one order are taken back by their tickets in
    /// another, each with the bytes at its place; a read that failed is
    /// reported for its own ticket; and dropping the owner with reads still
    /// asked for ends the helpers.
    #[test]
    fn lane_reads_are_taken_back_by_their_tickets_in_any_order() {
        let failing = 300_000;
        let mut reads = LaneReads::start(
            "test-lane-reads",
            (0..3).map(|_| disk(Some(failing))).collect(),
            None,
        )
        .unwrap();
        let places = [70_000u64, 4096, 900_000, failing, 12, 65_536];
        let tickets: Vec<u64> = places.iter().map(|&at| reads.ask(at, 3000)).collect();
        for (&ticket, &at) in tickets.iter().zip(&places).rev() {
            match reads.take(ticket) {
                Ok(bytes) => {
                    assert_ne!(at, failing);
                    let expected: Vec<u8> = (at..at + 3000).map(|n| (n % 251) as u8).collect();
                    assert_eq!(bytes, expected, "read at {at}");
                }
                Err(error) => {
                    assert_eq!(at, failing);
                    assert!(error.to_string().contains("unreadable sector"));
                }
            }
        }
        for at in 0..64 {
            reads.ask(at * 4096, 4096);
        }
        drop(reads);
        assert_eq!(LaneReads::lanes_for(1), 0);
        assert_eq!(LaneReads::lanes_for(2), 8);
        assert_eq!(LaneReads::lanes_for(4), 8);
    }

    #[test]
    fn lanes_follow_the_devices_depth() {
        assert_eq!(OriginalPrefetch::lanes_for(1), 0);
        assert_eq!(OriginalPrefetch::lanes_for(2), 4);
        assert_eq!(OriginalPrefetch::lanes_for(4), 4);
        assert_eq!(OriginalPrefetch::lanes_for(8), 4);
        let granted = OriginalPrefetch::reserve_lanes(4, 4096, 10, |bytes| {
            (bytes <= OriginalPrefetch::workspace_bytes(2, 4096, 10).unwrap()).then_some(bytes)
        });
        assert_eq!(granted.map(|(lanes, _)| lanes), Some(2));
        assert!(OriginalPrefetch::reserve_lanes(4, 4096, 10, |_| None::<()>).is_none());
    }
}
