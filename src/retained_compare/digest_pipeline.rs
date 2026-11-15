//! One in-flight chunk, one chunk being filled and one SHA-256 worker. The
//! caller still reads and compares every byte; this only overlaps independent
//! digests.
//!
//! Updates are gathered into the chunk being filled and handed to the worker
//! when it is a quarter of a megabyte or would overflow. A journal row
//! brings a sixteen-byte frame, a descriptor of a hundred bytes and its
//! data: handing each of those over by itself woke the worker, and waited for
//! it, three times a row for each of four digests, which on the full Windows
//! volume was a third of the time the journal took to write.
use super::stream_digest::StreamDigest;
use anyhow::{Context, Result, anyhow};
use std::{
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread::{self, JoinHandle},
};

pub(crate) struct Pipeline {
    input: Option<SyncSender<Vec<u8>>>,
    recycled: Option<Receiver<Vec<u8>>>,
    // Bytes accepted and not yet handed to the worker.
    filling: Option<Vec<u8>>,
    // How many more buffers may be made: all but the first exist only once
    // the worker has fallen that far behind.
    spare: usize,
    worker: Option<JoinHandle<Result<[u8; 32]>>>,
    chunk_bytes: usize,
}

/// A chunk this full goes to the worker without waiting for more.
const HAND_OVER_BYTES: usize = 256 * 1024;

impl Pipeline {
    pub(crate) fn with_native_backend(chunk_bytes: usize, native: bool) -> Result<Self> {
        Self::with_native_backend_and_prefix(chunk_bytes, native, None)
    }

    /// The fixed optional prefix is hashed once before submitted data chunks.
    /// It is copied into the worker; native hash handles stay on that worker.
    pub(crate) fn with_native_backend_and_prefix(
        chunk_bytes: usize,
        native: bool,
        prefix: Option<[u8; 16]>,
    ) -> Result<Self> {
        Self::with_buffers(chunk_bytes, native, prefix, 2)
    }

    /// A pipeline that lets its caller get `buffers` chunks ahead of the
    /// worker before it has to wait. Two is enough where the caller's reads
    /// and the worker's hashing take turns; a caller that hands over a burst
    /// and then turns to something else gives the burst's size, and pays for
    /// that many chunks.
    pub(crate) fn with_buffers(
        chunk_bytes: usize,
        native: bool,
        prefix: Option<[u8; 16]>,
        buffers: usize,
    ) -> Result<Self> {
        // The recycled buffers bound the worker's memory; 4 MiB matches the
        // largest native device request.
        anyhow::ensure!(
            (1..=4 * 1024 * 1024).contains(&chunk_bytes),
            "digest buffer must be between one byte and 4MiB"
        );
        anyhow::ensure!(
            (2..=64).contains(&buffers),
            "a digest pipeline has between two and sixty-four buffers"
        );
        let spare = buffers - 1;
        // One chunk is with the worker and the others can queue behind it;
        // every chunk can be on its way back at once.
        let (input, chunks) = sync_channel::<Vec<u8>>(buffers - 1);
        let (buffers, recycled) = sync_channel(buffers);
        let worker = thread::Builder::new()
            .name("n2r-shadow-digest".into())
            .spawn(move || {
                let _sampled = n2r_win32::stack_sampler::helper();
                // Construct CNG handles on this worker; none crosses threads.
                let mut hash = StreamDigest::new(native)?;
                if let Some(prefix) = prefix {
                    hash.update(&prefix)?;
                }
                // Every chunk handed over is hashed, also after the caller
                // has stopped taking buffers back: chunks can still be queued
                // here when the caller finishes.
                while let Ok(buffer) = chunks.recv() {
                    hash.update(&buffer)?;
                    let _ = buffers.send(buffer);
                }
                hash.finish()
            })
            .context("start bounded shadow digest worker")?;
        Ok(Self {
            input: Some(input),
            recycled: Some(recycled),
            filling: Some(Vec::with_capacity(chunk_bytes)),
            spare,
            worker: Some(worker),
            chunk_bytes,
        })
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(
            bytes.len() <= self.chunk_bytes,
            "digest chunk exceeds bound"
        );
        if self
            .filling
            .as_ref()
            .is_some_and(|filling| filling.len() + bytes.len() > self.chunk_bytes)
        {
            self.hand_over()?;
        }
        let mut filling = match self.filling.take() {
            Some(filling) => filling,
            None => self.empty_buffer()?,
        };
        filling.extend_from_slice(bytes);
        let full = filling.len() >= HAND_OVER_BYTES.min(self.chunk_bytes);
        self.filling = Some(filling);
        if full {
            self.hand_over()?;
        }
        Ok(())
    }

    /// A buffer to fill: one the worker has returned, else a new one while
    /// there are buffers still to be made, else the next the worker returns.
    fn empty_buffer(&mut self) -> Result<Vec<u8>> {
        use std::sync::mpsc::TryRecvError;
        let recycled = self
            .recycled
            .as_ref()
            .context("closed digest buffer channel")?;
        let mut buffer = match recycled.try_recv() {
            Ok(buffer) => buffer,
            Err(TryRecvError::Empty) if self.spare > 0 => {
                self.spare -= 1;
                Vec::with_capacity(self.chunk_bytes)
            }
            Err(TryRecvError::Empty) => match recycled.recv() {
                Ok(buffer) => buffer,
                Err(_) => {
                    return Err(self.worker_stopped("digest worker stopped before recycling"));
                }
            },
            Err(TryRecvError::Disconnected) => {
                return Err(self.worker_stopped("digest worker stopped before recycling"));
            }
        };
        buffer.clear();
        Ok(buffer)
    }

    /// Gives the worker what has been gathered so far, if anything.
    fn hand_over(&mut self) -> Result<()> {
        let Some(filling) = self.filling.take() else {
            return Ok(());
        };
        if filling.is_empty() {
            self.filling = Some(filling);
            return Ok(());
        }
        if self
            .input
            .as_ref()
            .context("closed digest input channel")?
            .send(filling)
            .is_err()
        {
            return Err(self.worker_stopped("digest worker stopped before accepting input"));
        }
        Ok(())
    }

    fn worker_stopped(&mut self, operation: &'static str) -> anyhow::Error {
        self.input.take();
        self.recycled.take();
        match self.worker.take().map(JoinHandle::join) {
            Some(Ok(Err(error))) => error.context(operation),
            Some(Err(_)) => anyhow!("{operation}: digest worker panicked"),
            Some(Ok(Ok(_))) => anyhow!("{operation}: digest worker ended before all input"),
            None => anyhow!("{operation}: digest worker is unavailable"),
        }
    }

    pub(crate) fn finish(mut self) -> Result<[u8; 32]> {
        self.hand_over()?;
        // No more input can follow. Closing the recycle receiver releases a
        // worker returning a chunk; the worker hashes whatever is still
        // queued for it before it ends.
        self.input.take();
        self.recycled.take();
        self.worker
            .take()
            .context("missing shadow digest worker")?
            .join()
            .map_err(|_| anyhow!("shadow digest worker panicked"))?
    }
}

/// A native SHA-256 that hashes on a worker when a spare core exists, so the
/// caller's reads overlap hashing; one-core machines hash on the caller. Both
/// see exactly the same ordered bytes and produce the same digest.
pub(crate) enum Overlapped {
    Serial(StreamDigest),
    Worker(Pipeline),
}

impl Overlapped {
    pub(crate) fn new(chunk_bytes: usize) -> Result<Self> {
        let native = cfg!(windows);
        if std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 2) {
            Ok(Self::Worker(Pipeline::with_native_backend(
                chunk_bytes,
                native,
            )?))
        } else {
            Ok(Self::Serial(StreamDigest::new(native)?))
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Serial(hash) => hash.update(bytes),
            Self::Worker(hash) => hash.update(bytes),
        }
    }

    pub(crate) fn finish(self) -> Result<[u8; 32]> {
        match self {
            Self::Serial(hash) => hash.finish(),
            Self::Worker(hash) => hash.finish(),
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        // Error exits must close both channels before joining, including when
        // the worker is blocked returning a buffer and the caller stopped early.
        self.input.take();
        self.recycled.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// One SHA-256 worker for a sequence of records, each with a digest of its
/// own: a journal's rows.
///
/// A row of the journal carries the SHA-256 of its payload, and the thread
/// that writes the journal computed it between one read and the next: on the
/// full Windows volume that was 58 of the 128 s the journal took, while the
/// workers of the file-wide digests waited four fifths of the time. The
/// caller hands the bytes over here and reads on; the digests come back in
/// the order the records ended.
///
/// Bytes and the places where records end travel together, gathered like a
/// [`Pipeline`]'s updates, so a run of small rows costs one hand-over and
/// not one a row. Two recycled chunks bound the worker's memory. The digests
/// that are owed wait in a queue of thirty-two bytes each: the caller takes
/// them before it ends many more records.
pub(crate) struct RecordDigests {
    input: Option<SyncSender<RecordChunk>>,
    recycled: Option<Receiver<RecordChunk>>,
    digests: Option<Receiver<[u8; 32]>>,
    // Bytes and ends accepted and not yet handed to the worker.
    filling: Option<RecordChunk>,
    // Whether the second of the two chunks exists yet.
    second: bool,
    worker: Option<JoinHandle<Result<()>>>,
    chunk_bytes: usize,
    // Records ended whose digest has not been taken.
    owed: u64,
    // Whether bytes of a record that has not ended were accepted.
    open: bool,
}

struct RecordChunk {
    bytes: Vec<u8>,
    // Where in `bytes` a record ends, ascending. A record that ended with
    // the chunk before ends at zero.
    ends: Vec<usize>,
}

/// A chunk with this many ends goes to the worker, however few bytes it has.
const MOST_ENDS: usize = 1024;

impl RecordChunk {
    fn new(chunk_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(chunk_bytes),
            ends: Vec::with_capacity(MOST_ENDS),
        }
    }
}

impl RecordDigests {
    pub(crate) fn with_native_backend(chunk_bytes: usize, native: bool) -> Result<Self> {
        anyhow::ensure!(
            (1..=4 * 1024 * 1024).contains(&chunk_bytes),
            "record digest buffer must be between one byte and 4MiB"
        );
        let (input, chunks) = sync_channel::<RecordChunk>(1);
        let (buffers, recycled) = sync_channel(1);
        let (results, digests) = std::sync::mpsc::channel();
        let worker = thread::Builder::new()
            .name("n2r-record-digest".into())
            .spawn(move || {
                let _sampled = n2r_win32::stack_sampler::helper();
                // Construct CNG handles on this worker; none crosses threads.
                let mut hash = StreamDigest::new(native)?;
                while let Ok(chunk) = chunks.recv() {
                    let mut from = 0;
                    for &end in &chunk.ends {
                        if end > from {
                            hash.update(&chunk.bytes[from..end])?;
                        }
                        from = end;
                        let ended = std::mem::replace(&mut hash, StreamDigest::new(native)?);
                        if results.send(ended.finish()?).is_err() {
                            // The caller is gone and wants no more digests.
                            return Ok(());
                        }
                    }
                    if chunk.bytes.len() > from {
                        hash.update(&chunk.bytes[from..])?;
                    }
                    let _ = buffers.send(chunk);
                }
                Ok(())
            })
            .context("start record digest worker")?;
        Ok(Self {
            input: Some(input),
            recycled: Some(recycled),
            digests: Some(digests),
            filling: Some(RecordChunk::new(chunk_bytes)),
            second: false,
            worker: Some(worker),
            chunk_bytes,
            owed: 0,
            open: false,
        })
    }

    /// More bytes of the record that has not ended.
    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(
            bytes.len() <= self.chunk_bytes,
            "record digest chunk exceeds bound"
        );
        if self
            .filling
            .as_ref()
            .is_some_and(|filling| filling.bytes.len() + bytes.len() > self.chunk_bytes)
        {
            self.hand_over()?;
        }
        let mut filling = match self.filling.take() {
            Some(filling) => filling,
            None => self.empty_chunk()?,
        };
        filling.bytes.extend_from_slice(bytes);
        let full = filling.bytes.len() >= HAND_OVER_BYTES.min(self.chunk_bytes);
        self.filling = Some(filling);
        self.open = true;
        if full {
            self.hand_over()?;
        }
        Ok(())
    }

    /// The record ends here, and the next begins. Its digest is owed: the
    /// next [`take`](Self::take) not yet matched by an earlier end gives it.
    pub(crate) fn end_record(&mut self) -> Result<()> {
        let mut filling = match self.filling.take() {
            Some(filling) => filling,
            None => self.empty_chunk()?,
        };
        filling.ends.push(filling.bytes.len());
        let full = filling.ends.len() >= MOST_ENDS;
        self.filling = Some(filling);
        self.owed += 1;
        self.open = false;
        if full {
            self.hand_over()?;
        }
        Ok(())
    }

    /// The digest of the earliest record that ended and has not been taken.
    /// Waits for the worker if it has not come to that record's end yet.
    pub(crate) fn take(&mut self) -> Result<[u8; 32]> {
        use std::sync::mpsc::TryRecvError;
        anyhow::ensure!(self.owed != 0, "no record digest is owed");
        let waiting = self
            .digests
            .as_ref()
            .context("closed record digest channel")?
            .try_recv();
        let digest = match waiting {
            Ok(digest) => digest,
            Err(TryRecvError::Empty) => {
                // The record's end may still be gathered here.
                self.hand_over()?;
                let received = self
                    .digests
                    .as_ref()
                    .context("closed record digest channel")?
                    .recv();
                match received {
                    Ok(digest) => digest,
                    Err(_) => {
                        return Err(
                            self.worker_stopped("record digest worker stopped before a digest")
                        );
                    }
                }
            }
            Err(TryRecvError::Disconnected) => {
                return Err(self.worker_stopped("record digest worker stopped before a digest"));
            }
        };
        self.owed -= 1;
        Ok(digest)
    }

    /// A chunk to fill: one the worker has returned, else the second chunk
    /// the first time none has come back, else the next the worker returns.
    fn empty_chunk(&mut self) -> Result<RecordChunk> {
        use std::sync::mpsc::TryRecvError;
        let recycled = self
            .recycled
            .as_ref()
            .context("closed record digest buffer channel")?;
        let mut chunk = match recycled.try_recv() {
            Ok(chunk) => chunk,
            Err(TryRecvError::Empty) if !self.second => {
                self.second = true;
                RecordChunk::new(self.chunk_bytes)
            }
            Err(TryRecvError::Empty) => match recycled.recv() {
                Ok(chunk) => chunk,
                Err(_) => {
                    return Err(
                        self.worker_stopped("record digest worker stopped before recycling")
                    );
                }
            },
            Err(TryRecvError::Disconnected) => {
                return Err(self.worker_stopped("record digest worker stopped before recycling"));
            }
        };
        chunk.bytes.clear();
        chunk.ends.clear();
        Ok(chunk)
    }

    /// Gives the worker what has been gathered so far, if anything.
    fn hand_over(&mut self) -> Result<()> {
        let Some(filling) = self.filling.take() else {
            return Ok(());
        };
        if filling.bytes.is_empty() && filling.ends.is_empty() {
            self.filling = Some(filling);
            return Ok(());
        }
        if self
            .input
            .as_ref()
            .context("closed record digest input channel")?
            .send(filling)
            .is_err()
        {
            return Err(self.worker_stopped("record digest worker stopped before accepting input"));
        }
        Ok(())
    }

    fn worker_stopped(&mut self, operation: &'static str) -> anyhow::Error {
        self.input.take();
        self.recycled.take();
        self.digests.take();
        match self.worker.take().map(JoinHandle::join) {
            Some(Ok(Err(error))) => error.context(operation),
            Some(Err(_)) => anyhow!("{operation}: record digest worker panicked"),
            Some(Ok(Ok(()))) => anyhow!("{operation}: record digest worker ended before all input"),
            None => anyhow!("{operation}: record digest worker is unavailable"),
        }
    }

    /// Ends the worker. Every record must have ended and every digest must
    /// have been taken: a digest left behind is a row without its digest.
    pub(crate) fn finish(mut self) -> Result<()> {
        anyhow::ensure!(
            self.owed == 0 && !self.open,
            "record digests are left untaken or a record has not ended"
        );
        self.input.take();
        self.recycled.take();
        self.digests.take();
        self.worker
            .take()
            .context("missing record digest worker")?
            .join()
            .map_err(|_| anyhow!("record digest worker panicked"))?
    }
}

impl Drop for RecordDigests {
    fn drop(&mut self) {
        // As for a Pipeline: close every channel, then join, so that a worker
        // returning a chunk or a digest to a caller that stopped early ends.
        self.input.take();
        self.recycled.take();
        self.digests.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn bytes(count: usize, seed: u8) -> Vec<u8> {
        (0..count)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn gathered_updates_hash_as_the_same_bytes_in_order() {
        for native in [false, cfg!(windows)] {
            let chunk = 1024 * 1024;
            let mut pipeline = Pipeline::with_native_backend(chunk, native).unwrap();
            let mut serial = Sha256::new();
            // A journal's shape: a frame, a descriptor and data of every size,
            // from nothing to a whole chunk, many times over.
            for round in 0..40usize {
                let parts = [
                    bytes(16, round as u8),
                    bytes(100, 3),
                    bytes(
                        [0, 1, 4095, 70_000, 300_000, chunk - 1, chunk][round % 7],
                        7,
                    ),
                ];
                for part in &parts {
                    pipeline.update(part).unwrap();
                    serial.update(part);
                }
            }
            let expected: [u8; 32] = serial.finalize().into();
            assert_eq!(pipeline.finish().unwrap(), expected, "native {native}");
        }
    }

    #[test]
    fn a_pipeline_with_many_buffers_hashes_the_same_bytes_in_order() {
        for native in [false, cfg!(windows)] {
            for buffers in [2usize, 3, 16, 64] {
                let chunk = 64 * 1024;
                let mut pipeline = Pipeline::with_buffers(chunk, native, None, buffers).unwrap();
                let mut serial = Sha256::new();
                // A burst several times the buffers, then small updates,
                // then another burst, finished while chunks are queued.
                for round in 0..3 * buffers {
                    let part = bytes(chunk, round as u8);
                    pipeline.update(&part).unwrap();
                    serial.update(&part);
                }
                for round in 0..200usize {
                    let part = bytes(1 + round % 300, round as u8);
                    pipeline.update(&part).unwrap();
                    serial.update(&part);
                }
                for round in 0..buffers {
                    let part = bytes(chunk - round, 7);
                    pipeline.update(&part).unwrap();
                    serial.update(&part);
                }
                let expected: [u8; 32] = serial.finalize().into();
                assert_eq!(
                    pipeline.finish().unwrap(),
                    expected,
                    "native {native}, {buffers} buffers"
                );
            }
        }
        assert!(Pipeline::with_buffers(4096, false, None, 1).is_err());
        assert!(Pipeline::with_buffers(4096, false, None, 65).is_err());
    }

    #[test]
    fn what_is_still_queued_when_the_caller_finishes_is_hashed() {
        // Two full chunks handed over back to back and finished at once: the
        // second is still queued, or being filled, when the channels close.
        for _ in 0..50 {
            let chunk = 512 * 1024;
            let mut pipeline = Pipeline::with_native_backend(chunk, false).unwrap();
            let mut serial = Sha256::new();
            for seed in 0..3u8 {
                let part = bytes(chunk, seed);
                pipeline.update(&part).unwrap();
                serial.update(&part);
            }
            let tail = bytes(5, 9);
            pipeline.update(&tail).unwrap();
            serial.update(&tail);
            let expected: [u8; 32] = serial.finalize().into();
            assert_eq!(pipeline.finish().unwrap(), expected);
        }
    }

    /// Feeds `lengths` as records, a megabyte or less at a time, and takes
    /// the digests after every `take_every` records and at the end.
    fn record_digests(
        chunk: usize,
        native: bool,
        lengths: &[usize],
        take_every: usize,
    ) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let mut records = RecordDigests::with_native_backend(chunk, native).unwrap();
        let (mut expected, mut taken) = (Vec::new(), Vec::new());
        for (index, &length) in lengths.iter().enumerate() {
            let record = bytes(length, index as u8);
            for part in record.chunks(chunk.min(1024 * 1024)) {
                records.update(part).unwrap();
            }
            records.end_record().unwrap();
            expected.push(<[u8; 32]>::from(Sha256::digest(&record)));
            if (index + 1) % take_every == 0 {
                while taken.len() < expected.len() {
                    taken.push(records.take().unwrap());
                }
            }
        }
        while taken.len() < expected.len() {
            taken.push(records.take().unwrap());
        }
        records.finish().unwrap();
        (expected, taken)
    }

    #[test]
    fn each_record_has_the_digest_of_its_own_bytes_in_the_order_it_ended() {
        for native in [false, cfg!(windows)] {
            for chunk in [4096usize, 64 * 1024, 1024 * 1024] {
                // Nothing, a byte, a cluster, one short of a chunk, a chunk,
                // one more, the size at which a chunk is handed over, and
                // several chunks: twice over, so that each also follows
                // every other.
                let shapes = [
                    0,
                    1,
                    4096,
                    chunk - 1,
                    chunk,
                    chunk + 1,
                    HAND_OVER_BYTES,
                    3 * chunk + 17,
                    0,
                    0,
                    300,
                ];
                let lengths: Vec<usize> =
                    shapes.iter().chain(shapes.iter().rev()).copied().collect();
                // Taken at once, a few rows late, and only at the end.
                for take_every in [1usize, 3, usize::MAX] {
                    let (expected, taken) = record_digests(chunk, native, &lengths, take_every);
                    assert_eq!(
                        taken, expected,
                        "native {native}, chunk {chunk}, taken every {take_every}"
                    );
                }
            }
        }
    }

    #[test]
    fn more_records_than_a_chunk_has_ends_for_are_all_given() {
        // Small rows in their thousands, and empty ones, which add an end
        // and no byte: neither may wait for a chunk to fill.
        let lengths: Vec<usize> = (0..3 * MOST_ENDS + 5).map(|index| index % 3).collect();
        let (expected, taken) = record_digests(1024 * 1024, false, &lengths, usize::MAX);
        assert_eq!(taken, expected);
        let (expected, taken) = record_digests(1024 * 1024, false, &lengths, 7);
        assert_eq!(taken, expected);
    }

    #[test]
    fn a_digest_not_owed_is_refused_and_one_left_behind_is_an_error() {
        let mut records = RecordDigests::with_native_backend(4096, false).unwrap();
        assert!(records.take().is_err(), "nothing has ended yet");
        assert!(records.update(&[0u8; 4097]).is_err(), "larger than a chunk");
        records.update(&[1, 2, 3]).unwrap();
        records.end_record().unwrap();
        assert_eq!(
            records.take().unwrap(),
            <[u8; 32]>::from(Sha256::digest([1, 2, 3]))
        );
        assert!(records.take().is_err(), "taken already");
        records.finish().unwrap();

        let mut owed = RecordDigests::with_native_backend(4096, false).unwrap();
        owed.update(&[9]).unwrap();
        owed.end_record().unwrap();
        assert!(owed.finish().is_err(), "a digest is owed");

        let mut open = RecordDigests::with_native_backend(4096, false).unwrap();
        open.update(&[9]).unwrap();
        assert!(open.finish().is_err(), "a record has not ended");
    }

    #[test]
    fn a_caller_that_stops_in_the_middle_does_not_wait_for_the_worker() {
        // Chunks in flight, digests untaken, a record half given: dropping
        // must end the worker whichever of its three channels it is at.
        for records_before in [0usize, 1, 40] {
            let chunk = 64 * 1024;
            let mut records = RecordDigests::with_native_backend(chunk, false).unwrap();
            for index in 0..records_before {
                records.update(&bytes(chunk, index as u8)).unwrap();
                records.end_record().unwrap();
            }
            records.update(&bytes(chunk, 3)).unwrap();
            records.update(&bytes(chunk / 2, 4)).unwrap();
            drop(records);
        }
    }

    #[test]
    fn an_update_larger_than_a_chunk_is_refused_and_nothing_is_an_empty_digest() {
        let mut pipeline = Pipeline::with_native_backend(4096, false).unwrap();
        assert!(pipeline.update(&[0u8; 4097]).is_err());
        let empty = Pipeline::with_native_backend(4096, false).unwrap();
        let expected: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(empty.finish().unwrap(), expected);
    }
}
