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
    // Whether the second of the two buffers exists yet.
    second: bool,
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
        // Two recycled buffers bound the worker's memory; 4 MiB matches the
        // largest native device request.
        anyhow::ensure!(
            (1..=4 * 1024 * 1024).contains(&chunk_bytes),
            "digest buffer must be between one byte and 4MiB"
        );
        let (input, chunks) = sync_channel::<Vec<u8>>(1);
        let (buffers, recycled) = sync_channel(1);
        let worker = thread::Builder::new()
            .name("n2r-shadow-digest".into())
            .spawn(move || {
                // Construct CNG handles on this worker; none crosses threads.
                let mut hash = StreamDigest::new(native)?;
                if let Some(prefix) = prefix {
                    hash.update(&prefix)?;
                }
                // Every chunk handed over is hashed, also after the caller
                // has stopped taking buffers back: with two buffers, one can
                // still be queued here when the caller finishes.
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
            second: false,
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

    /// A buffer to fill: one the worker has returned, else the second buffer
    /// the first time none has come back, else the next the worker returns.
    fn empty_buffer(&mut self) -> Result<Vec<u8>> {
        use std::sync::mpsc::TryRecvError;
        let recycled = self
            .recycled
            .as_ref()
            .context("closed digest buffer channel")?;
        let mut buffer = match recycled.try_recv() {
            Ok(buffer) => buffer,
            Err(TryRecvError::Empty) if !self.second => {
                self.second = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn bytes(count: usize, seed: u8) -> Vec<u8> {
        (0..count).map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed)).collect()
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
                    bytes([0, 1, 4095, 70_000, 300_000, chunk - 1, chunk][round % 7], 7),
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

    #[test]
    fn an_update_larger_than_a_chunk_is_refused_and_nothing_is_an_empty_digest() {
        let mut pipeline = Pipeline::with_native_backend(4096, false).unwrap();
        assert!(pipeline.update(&[0u8; 4097]).is_err());
        let empty = Pipeline::with_native_backend(4096, false).unwrap();
        let expected: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(empty.finish().unwrap(), expected);
    }
}
