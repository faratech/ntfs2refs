//! Reads the chunks a comparison is about to ask for, through a second handle
//! of the same frozen disk.
//!
//! A capture compares a frozen source with a frozen shadow one chunk of at
//! most 4 MiB after another, on one thread: it read one disk, then the other,
//! then hashed and compared the chunk. Neither disk had a read outstanding
//! while the other was read or the chunk was compared. Here a helper thread
//! owns a read lane of one of the disks and the list of ranges the comparison
//! walks, and reads the same chunks at the same places, in the same order, up
//! to [`AHEAD`] of them ahead of the comparison. It can hash each chunk as it
//! reads it, so that the comparing thread does not.
//!
//! The comparison takes the chunks in order and says, for each, the place and
//! the length it expects. A read that failed is handed over when its chunk is
//! asked for and not before: the error a comparison reports first is the one
//! it reported first without the helper. The helper owns its lane, its list
//! and its buffers, and borrows nothing of the run. It has ended, and its lane
//! is closed, when the owner of the prefetch is finished or dropped.
use crate::refs_write_set::ByteRange;
use anyhow::{Context, Result, ensure};
use n2r_win32::GeneralFrozenPartition;
use std::{
    io::{self, Read, Seek, SeekFrom},
    sync::mpsc,
};

/// The chunks the helper may have read that the comparison has not asked for.
const AHEAD: usize = 2;
/// Those, and the one the helper is reading.
const BUFFERS: usize = AHEAD + 1;
/// The helper thread's stack.
const STACK_BYTES: u64 = 2 * 1024 * 1024;
/// What opening the lane asks Windows: one state query of the disk, whose
/// replies (at most 64 KiB of layout and small fixed buffers) are dropped
/// once the lane's route has been held to the frozen state.
const LANE_OPEN_BYTES: u64 = 1024 * 1024;

/// One chunk as the helper read it.
pub(crate) struct PrefetchedChunk {
    /// Where on the partition the chunk begins.
    pub(crate) offset: u64,
    pub(crate) bytes: Vec<u8>,
    /// The XXH3-128 of `bytes` (`parallel_digest::xxh3_128`), where the
    /// prefetch was started to hash.
    pub(crate) xxh3_128: Option<[u8; 16]>,
}

pub(crate) struct OriginalPrefetch {
    filled: Option<mpsc::Receiver<io::Result<PrefetchedChunk>>>,
    free: Option<mpsc::SyncSender<Vec<u8>>>,
    worker: Option<std::thread::JoinHandle<()>>,
    // What pays for the buffers, the list, the lane and the stack: returned
    // once the helper has ended and they are gone.
    _paid: Option<Box<dyn std::any::Any>>,
}

impl OriginalPrefetch {
    /// What a prefetch holds: its buffers, its lane (the lane's own buffer
    /// and what opening it asks), the stack of its helper and the list of
    /// the `ranges` it walks. All of it only buys speed: it is asked for as
    /// spare memory, and a comparison that is refused it reads as it did.
    pub(crate) fn workspace_bytes(chunk: usize, ranges: u64) -> Option<u64> {
        (BUFFERS as u64)
            .checked_mul(chunk as u64)?
            .checked_add(GeneralFrozenPartition::read_buffer_memory_bytes())?
            .checked_add(LANE_OPEN_BYTES)?
            .checked_add(STACK_BYTES)?
            .checked_add(ranges.checked_mul(std::mem::size_of::<ByteRange>() as u64)?)
    }

    /// For a capture that holds the frozen source itself: a lane of it, when
    /// the device takes more than one outstanding read. The ranges are kept,
    /// not one descriptor for every chunk on the volume, so that the list is
    /// in proportion to the selection even for a complete capture of a very
    /// large volume. Nothing pays for this one: the capture that uses it has
    /// no ledger.
    pub(crate) fn for_partition(
        source: &GeneralFrozenPartition,
        selection: &[ByteRange],
        chunk: usize,
    ) -> Result<Option<Self>> {
        if source.io_profile().queue_depth < 2 {
            return Ok(None);
        }
        let Some(lane) = source.read_lanes(1, &mut Vec::new())?.pop() else {
            return Ok(None);
        };
        Ok(Some(Self::start(
            "n2r-original-prefetch",
            lane,
            selection.to_vec(),
            chunk,
            false,
            None,
        )?))
    }

    /// Starts the helper. It reads every range of `ranges` in order, each in
    /// chunks of at most `chunk` bytes from the range's start, as the
    /// comparison does, and hashes each chunk when `hash` is set. `paid` is
    /// whatever reserved [`Self::workspace_bytes`]; it is kept until the
    /// helper has ended.
    ///
    /// An error is a helper that could not be started (no memory for a
    /// buffer, no thread). Nothing was read: the caller reads as it did.
    pub(crate) fn start<L: Read + Seek + Send + 'static>(
        name: &'static str,
        mut lane: L,
        ranges: Vec<ByteRange>,
        chunk: usize,
        hash: bool,
        paid: Option<Box<dyn std::any::Any>>,
    ) -> io::Result<Self> {
        let (filled_tx, filled) = mpsc::sync_channel(AHEAD);
        let (free, free_rx) = mpsc::sync_channel::<Vec<u8>>(BUFFERS);
        for _ in 0..BUFFERS {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(chunk).map_err(|_| {
                io::Error::new(io::ErrorKind::OutOfMemory, "no memory to read ahead")
            })?;
            buffer.resize(chunk, 0);
            let _ = free.send(buffer);
        }
        let worker = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let _sampled = n2r_win32::stack_sampler::helper();
                for range in ranges {
                    let mut done = 0;
                    while done < range.length {
                        let count = (range.length - done).min(chunk as u64);
                        let Ok(mut buffer) = free_rx.recv() else {
                            return;
                        };
                        buffer.resize(count as usize, 0);
                        let offset = range.offset + done;
                        let result = lane
                            .seek(SeekFrom::Start(offset))
                            .and_then(|_| lane.read_exact(&mut buffer))
                            .map(|()| PrefetchedChunk {
                                offset,
                                xxh3_128: hash.then(|| crate::parallel_digest::xxh3_128(&buffer)),
                                bytes: buffer,
                            });
                        let stop = result.is_err();
                        if filled_tx.send(result).is_err() || stop {
                            return;
                        }
                        done += count;
                    }
                }
            })?;
        Ok(Self {
            filled: Some(filled),
            free: Some(free),
            worker: Some(worker),
            _paid: paid,
        })
    }

    /// The next chunk, which the comparison expects to be `count` bytes at
    /// `offset`. A read the helper failed is returned here, for its chunk.
    pub(crate) fn next(&mut self, offset: u64, count: usize) -> Result<PrefetchedChunk> {
        let chunk = self
            .filled
            .as_ref()
            .context("prefetch has ended")?
            .recv()
            .map_err(|_| anyhow::anyhow!("prefetch stopped early"))?
            .with_context(|| format!("reading {count} bytes at partition offset {offset} ahead"))?;
        ensure!(
            chunk.offset == offset && chunk.bytes.len() == count,
            "prefetched chunk differs from the comparison's: {} bytes at {}, not {count} at {offset}",
            chunk.bytes.len(),
            chunk.offset
        );
        Ok(chunk)
    }

    /// Hands a buffer the comparison is done with back to the helper.
    pub(crate) fn recycle(&self, buffer: Vec<u8>) {
        if let Some(free) = &self.free {
            let _ = free.send(buffer);
        }
    }

    /// Ends the helper and waits for it. Whatever it was blocked on (a free
    /// buffer, room for a chunk it read) is gone first, so it returns.
    fn stop(&mut self) -> Result<()> {
        self.filled.take();
        self.free.take();
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| anyhow::anyhow!("prefetch helper panicked")),
            None => Ok(()),
        }
    }

    /// The comparison is over: the helper must have read exactly its chunks.
    pub(crate) fn finish(mut self) -> Result<()> {
        let beyond = self
            .filled
            .as_ref()
            .is_some_and(|filled| filled.try_recv().is_ok());
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
