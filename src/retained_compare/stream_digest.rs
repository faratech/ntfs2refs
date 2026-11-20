//! Failable streaming digest for complete images and journals: SHA-256, or
//! BLAKE3 for a journal this build writes (`n2r_win32::bulk_digest`).
//! Metadata, patch and retained-range digests keep their independent existing
//! paths.
use anyhow::Result;
use n2r_win32::bulk_digest::Algorithm;
use sha2::{Digest, Sha256};

/// What a [`StreamDigest`] computes, and through which code. A plain `bool`
/// is SHA-256, through Windows' implementation where it is true: what every
/// caller passed before there was a choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    Sha256 {
        native: bool,
    },
    /// BLAKE3, a buffer large enough to divide hashed on the pool's threads.
    Blake3,
}

impl From<bool> for Backend {
    fn from(native: bool) -> Self {
        Self::Sha256 { native }
    }
}

impl Backend {
    /// The backend of a digest of `algorithm`; SHA-256 through Windows'
    /// implementation on Windows.
    pub(crate) fn of(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha256 => Self::Sha256 {
                native: cfg!(windows),
            },
            Algorithm::Blake3 => Self::Blake3,
        }
    }

    pub(crate) fn algorithm(self) -> Algorithm {
        match self {
            Self::Sha256 { .. } => Algorithm::Sha256,
            Self::Blake3 => Algorithm::Blake3,
        }
    }
}

pub(crate) enum StreamDigest {
    Rust(Sha256),
    #[cfg(windows)]
    Native(n2r_win32::sha256_native::Sha256),
    Blake3(n2r_win32::bulk_digest::Hasher),
    Worker(super::digest_pipeline::Pipeline),
}

impl StreamDigest {
    pub(crate) fn new(backend: impl Into<Backend>) -> Result<Self> {
        match backend.into() {
            Backend::Sha256 { native } => {
                #[cfg(windows)]
                if native {
                    return Ok(Self::Native(n2r_win32::sha256_native::Sha256::new()?));
                }
                let _ = native;
                Ok(Self::Rust(Sha256::new()))
            }
            Backend::Blake3 => Ok(Self::Blake3(n2r_win32::bulk_digest::Hasher::new(
                Algorithm::Blake3,
            )?)),
        }
    }

    /// Overlap this aggregate with the caller's independent per-record hash.
    /// The existing pipeline owns one bounded recycled buffer and constructs
    /// its serial hash on the worker. Reserve a core for I/O and record checks;
    /// small machines retain the serial backend and identical ordered bytes.
    pub(crate) fn alongside_record_hash(
        chunk_bytes: usize,
        backend: impl Into<Backend>,
    ) -> Result<Self> {
        let backend = backend.into();
        if std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 3) {
            Ok(Self::Worker(
                super::digest_pipeline::Pipeline::with_native_backend(chunk_bytes, backend)?,
            ))
        } else {
            Self::new(backend)
        }
    }
    /// [`Self::alongside_record_hash`] for a caller that hands over a burst
    /// of `buffers` chunks and then turns to something else while the worker
    /// hashes them: a journal's rows, read back a few megabytes at a time.
    pub(crate) fn alongside_a_burst(
        chunk_bytes: usize,
        backend: impl Into<Backend>,
        buffers: usize,
    ) -> Result<Self> {
        let backend = backend.into();
        if std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 3) {
            Ok(Self::Worker(
                super::digest_pipeline::Pipeline::with_buffers(
                    chunk_bytes,
                    backend,
                    None,
                    buffers,
                )?,
            ))
        } else {
            Self::new(backend)
        }
    }
    /// The algorithm of the digest this computes.
    pub(crate) fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rust(_) => Algorithm::Sha256,
            #[cfg(windows)]
            Self::Native(_) => Algorithm::Sha256,
            Self::Blake3(_) => Algorithm::Blake3,
            Self::Worker(hash) => hash.algorithm(),
        }
    }
    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Rust(hash) => hash.update(bytes),
            #[cfg(windows)]
            Self::Native(hash) => hash.update(bytes)?,
            Self::Blake3(hash) => hash.update(bytes)?,
            Self::Worker(hash) => hash.update(bytes)?,
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<[u8; 32]> {
        match self {
            Self::Rust(hash) => Ok(hash.finalize().into()),
            #[cfg(windows)]
            Self::Native(hash) => Ok(hash.finish()?),
            Self::Blake3(hash) => Ok(hash.finish()?),
            Self::Worker(hash) => hash.finish(),
        }
    }
}
