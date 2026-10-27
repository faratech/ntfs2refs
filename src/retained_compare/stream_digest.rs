//! Failable SHA-256 backend for complete streaming image hashes. Metadata,
//! patch and retained-range digests keep their independent existing paths.
use anyhow::Result;
use sha2::{Digest, Sha256};

pub(super) enum StreamDigest {
    Rust(Sha256),
    #[cfg(windows)]
    Native(n2r_win32::sha256_native::Sha256),
}

impl StreamDigest {
    pub(super) fn new(native: bool) -> Result<Self> {
        #[cfg(windows)]
        if native {
            return Ok(Self::Native(n2r_win32::sha256_native::Sha256::new()?));
        }
        let _ = native;
        Ok(Self::Rust(Sha256::new()))
    }
    pub(super) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Rust(hash) => hash.update(bytes),
            #[cfg(windows)]
            Self::Native(hash) => hash.update(bytes)?,
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<[u8; 32]> {
        match self {
            Self::Rust(hash) => Ok(hash.finalize().into()),
            #[cfg(windows)]
            Self::Native(hash) => Ok(hash.finish()?),
        }
    }
}
