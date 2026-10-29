//! One in-flight chunk, one reusable chunk and one SHA-256 worker. The caller
//! still reads and compares every byte; this only overlaps independent digests.
use super::stream_digest::StreamDigest;
use anyhow::{Context, Result, anyhow};
use std::{
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread::{self, JoinHandle},
};

pub(crate) struct Pipeline {
    input: Option<SyncSender<Vec<u8>>>,
    recycled: Option<Receiver<Vec<u8>>>,
    spare: Option<Vec<u8>>,
    worker: Option<JoinHandle<Result<[u8; 32]>>>,
    chunk_bytes: usize,
}

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
                while let Ok(buffer) = chunks.recv() {
                    hash.update(&buffer)?;
                    if buffers.send(buffer).is_err() {
                        break;
                    }
                }
                hash.finish()
            })
            .context("start bounded shadow digest worker")?;
        Ok(Self {
            input: Some(input),
            recycled: Some(recycled),
            spare: Some(Vec::with_capacity(chunk_bytes)),
            worker: Some(worker),
            chunk_bytes,
        })
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(
            bytes.len() <= self.chunk_bytes,
            "digest chunk exceeds bound"
        );
        let mut buffer = match self.spare.take() {
            Some(buffer) => buffer,
            None => match self
                .recycled
                .as_ref()
                .context("closed digest buffer channel")?
                .recv()
            {
                Ok(buffer) => buffer,
                Err(_) => {
                    return Err(self.worker_stopped("digest worker stopped before recycling"));
                }
            },
        };
        buffer.clear();
        buffer.extend_from_slice(bytes);
        if self
            .input
            .as_ref()
            .context("closed digest input channel")?
            .send(buffer)
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
        // No more input can follow. Closing the recycle receiver releases a
        // worker returning its final chunk; that chunk was hashed before send.
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
