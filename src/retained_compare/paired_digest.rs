//! Four exact SHA-256 streams over caller-supplied source/candidate bytes.
//! This accumulator opens no files or devices and grants no I/O authority.
//! The caller must retain every source/backing identity and exclusion check.
#![cfg(windows)]

use super::{digest_pipeline::Pipeline, stream_digest::StreamDigest};
use anyhow::{Context, Result, ensure};

pub(crate) const MAX_CHUNK_BYTES: usize = 1024 * 1024;

pub(crate) struct PairDigests {
    pub(crate) source_raw: [u8; 32],
    pub(crate) source_framed: [u8; 32],
    pub(crate) candidate_raw: [u8; 32],
    pub(crate) candidate_framed: [u8; 32],
}

enum FramedDigest {
    Serial(StreamDigest),
    Worker(Pipeline),
}

impl FramedDigest {
    fn new(prefix: [u8; 16], parallel: bool) -> Result<Self> {
        if parallel {
            Ok(Self::Worker(Pipeline::with_native_backend_and_prefix(
                MAX_CHUNK_BYTES,
                true,
                Some(prefix),
            )?))
        } else {
            let mut hash = StreamDigest::new(true)?;
            hash.update(&prefix)?;
            Ok(Self::Serial(hash))
        }
    }

    fn update(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Serial(hash) => hash.update(bytes),
            Self::Worker(worker) => worker.update(bytes),
        }
    }

    fn finish(self) -> Result<[u8; 32]> {
        match self {
            Self::Serial(hash) => hash.finish(),
            Self::Worker(worker) => worker.finish(),
        }
    }
}

/// Raw digests stay on the owning caller. With at least two available CPUs,
/// independent source/candidate framed digests each use one bounded worker.
/// Otherwise all four CNG digests run serially. There are no additional reads.
pub(crate) struct PairHasher {
    expected_length: u64,
    consumed: u64,
    failed: bool,
    source_raw: StreamDigest,
    candidate_raw: StreamDigest,
    source_framed: FramedDigest,
    candidate_framed: FramedDigest,
}

impl PairHasher {
    pub(crate) fn new(expected_length: u64) -> Result<Self> {
        let parallel = std::thread::available_parallelism().is_ok_and(|count| count.get() >= 2);
        let mut prefix = [0u8; 16];
        prefix[..8].copy_from_slice(&0u64.to_le_bytes());
        prefix[8..].copy_from_slice(&expected_length.to_le_bytes());
        Ok(Self {
            expected_length,
            consumed: 0,
            failed: false,
            source_raw: StreamDigest::new(true).context("create source raw digest")?,
            candidate_raw: StreamDigest::new(true).context("create candidate raw digest")?,
            source_framed: FramedDigest::new(prefix, parallel)
                .context("create source framed digest")?,
            candidate_framed: FramedDigest::new(prefix, parallel)
                .context("create candidate framed digest")?,
        })
    }

    pub(crate) fn update_pair(&mut self, source: &[u8], candidate: &[u8]) -> Result<()> {
        ensure!(
            !self.failed,
            "paired digest is unusable after an earlier error"
        );
        let result = (|| -> Result<()> {
            ensure!(
                !source.is_empty()
                    && source.len() == candidate.len()
                    && source.len() <= MAX_CHUNK_BYTES,
                "paired digest needs equal nonempty chunks of at most 1MiB"
            );
            let next = self
                .consumed
                .checked_add(u64::try_from(source.len())?)
                .context("paired digest byte count overflow")?;
            ensure!(
                next <= self.expected_length,
                "paired digest exceeds its exact length"
            );
            // Each pipeline copies at most one 1MiB chunk. It is safe for the
            // caller to reuse its buffers after this method returns. CNG hash
            // construction, ordered updates and destruction stay on workers.
            self.source_framed
                .update(source)
                .context("update source framed digest")?;
            self.candidate_framed
                .update(candidate)
                .context("update candidate framed digest")?;
            self.source_raw
                .update(source)
                .context("update source raw digest")?;
            self.candidate_raw
                .update(candidate)
                .context("update candidate raw digest")?;
            self.consumed = next;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(crate) fn finish(self) -> Result<PairDigests> {
        ensure!(!self.failed, "cannot finish a failed paired digest");
        ensure!(
            self.consumed == self.expected_length,
            "paired digest did not consume the complete exact length"
        );
        // Finish both workers even when a different digest has failed. Error
        // paths also close channels and join through Pipeline's existing Drop.
        let source_raw = self.source_raw.finish().context("finish source raw digest");
        let candidate_raw = self
            .candidate_raw
            .finish()
            .context("finish candidate raw digest");
        let source_framed = self
            .source_framed
            .finish()
            .context("finish source framed digest");
        let candidate_framed = self
            .candidate_framed
            .finish()
            .context("finish candidate framed digest");
        Ok(PairDigests {
            source_raw: source_raw?,
            source_framed: source_framed?,
            candidate_raw: candidate_raw?,
            candidate_framed: candidate_framed?,
        })
    }
}
