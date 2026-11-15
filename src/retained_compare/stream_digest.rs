//! Failable SHA-256 backend for complete streaming image hashes. Metadata,
//! patch and retained-range digests keep their independent existing paths.
use anyhow::Result;
use sha2::{Digest, Sha256};

pub(crate) enum StreamDigest {
    Rust(Sha256),
    #[cfg(windows)]
    Native(n2r_win32::sha256_native::Sha256),
    Worker(super::digest_pipeline::Pipeline),
}

impl StreamDigest {
    pub(crate) fn new(native: bool) -> Result<Self> {
        #[cfg(windows)]
        if native {
            return Ok(Self::Native(n2r_win32::sha256_native::Sha256::new()?));
        }
        let _ = native;
        Ok(Self::Rust(Sha256::new()))
    }

    /// Overlap this aggregate with the caller's independent per-record hash.
    /// The existing pipeline owns one bounded recycled buffer and constructs
    /// its serial hash on the worker. Reserve a core for I/O and record checks;
    /// small machines retain the serial backend and identical ordered bytes.
    pub(crate) fn alongside_record_hash(chunk_bytes: usize, native: bool) -> Result<Self> {
        if std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 3) {
            Ok(Self::Worker(
                super::digest_pipeline::Pipeline::with_native_backend(chunk_bytes, native)?,
            ))
        } else {
            Self::new(native)
        }
    }
    /// [`Self::alongside_record_hash`] for a caller that hands over a burst
    /// of `buffers` chunks and then turns to something else while the worker
    /// hashes them: a journal's rows, read back a few megabytes at a time.
    pub(crate) fn alongside_a_burst(
        chunk_bytes: usize,
        native: bool,
        buffers: usize,
    ) -> Result<Self> {
        if std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 3) {
            Ok(Self::Worker(
                super::digest_pipeline::Pipeline::with_buffers(chunk_bytes, native, None, buffers)?,
            ))
        } else {
            Self::new(native)
        }
    }
    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Rust(hash) => hash.update(bytes),
            #[cfg(windows)]
            Self::Native(hash) => hash.update(bytes)?,
            Self::Worker(hash) => hash.update(bytes)?,
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<[u8; 32]> {
        match self {
            Self::Rust(hash) => Ok(hash.finalize().into()),
            #[cfg(windows)]
            Self::Native(hash) => Ok(hash.finish()?),
            Self::Worker(hash) => hash.finish(),
        }
    }
}
