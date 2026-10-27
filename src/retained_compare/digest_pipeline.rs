//! One in-flight chunk, one reusable chunk and one SHA-256 worker. The caller
//! still reads and compares every byte; this only overlaps independent digests.
use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use std::{
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread::{self, JoinHandle},
};

pub(crate) struct Pipeline {
    input: Option<SyncSender<Vec<u8>>>,
    recycled: Option<Receiver<Vec<u8>>>,
    spare: Option<Vec<u8>>,
    worker: Option<JoinHandle<[u8; 32]>>,
    chunk_bytes: usize,
}

impl Pipeline {
    pub(crate) fn new(chunk_bytes: usize) -> Result<Self> {
        let (input, chunks) = sync_channel::<Vec<u8>>(1);
        let (buffers, recycled) = sync_channel(1);
        let worker = thread::Builder::new()
            .name("n2r-shadow-digest".into())
            .spawn(move || {
                let mut hash = Sha256::new();
                while let Ok(buffer) = chunks.recv() {
                    hash.update(&buffer);
                    if buffers.send(buffer).is_err() {
                        break;
                    }
                }
                hash.finalize().into()
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
            None => self
                .recycled
                .as_ref()
                .context("closed digest buffer channel")?
                .recv()
                .map_err(|_| anyhow!("shadow digest worker stopped before recycling"))?,
        };
        buffer.clear();
        buffer.extend_from_slice(bytes);
        self.input
            .as_ref()
            .context("closed digest input channel")?
            .send(buffer)
            .map_err(|_| anyhow!("shadow digest worker stopped before accepting input"))
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
            .map_err(|_| anyhow!("shadow digest worker panicked"))
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
