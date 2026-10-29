//! SHA-256 through Windows' Microsoft Primitive Provider. This module opens
//! no files/devices and grants no I/O authority. The caller owns its reader.
//! See https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash.
use std::{
    io::{self, Read, Seek, SeekFrom},
    ptr,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_HASH_REUSABLE_FLAG, BCRYPT_SHA256_ALGORITHM,
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, MS_PRIMITIVE_PROVIDER,
};

fn check(status: i32, operation: &str) -> io::Result<()> {
    if status < 0 {
        Err(io::Error::other(format!(
            "{operation}: CNG NTSTATUS 0x{:08x}",
            status as u32
        )))
    } else {
        Ok(())
    }
}

/// A single-use hash. Construct on its consuming thread; native handles are
/// never shared with another thread or reused after finishing.
pub struct Sha256 {
    algorithm: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
}

impl Sha256 {
    pub fn new() -> io::Result<Self> {
        let mut value = Self {
            algorithm: ptr::null_mut(),
            hash: ptr::null_mut(),
        };
        // SAFETY: live output handle storage and static, NUL-terminated strings.
        check(
            unsafe {
                BCryptOpenAlgorithmProvider(
                    &mut value.algorithm,
                    BCRYPT_SHA256_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER,
                    0,
                )
            },
            "open SHA-256 provider",
        )?;
        // SAFETY: live provider/output handle; Windows allocates the hash object
        // when the object buffer is NULL/zero (supported since Windows 7).
        check(
            unsafe {
                BCryptCreateHash(
                    value.algorithm,
                    &mut value.hash,
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                    0,
                    0,
                )
            },
            "create SHA-256 hash",
        )?;
        Ok(value)
    }

    pub fn update(&mut self, bytes: &[u8]) -> io::Result<()> {
        for chunk in bytes.chunks(u32::MAX as usize) {
            // SAFETY: the owned live hash and immutable slice remain valid
            // throughout the synchronous call; BCryptHashData never edits input.
            check(
                unsafe { BCryptHashData(self.hash, chunk.as_ptr(), chunk.len() as u32, 0) },
                "update SHA-256 hash",
            )?;
        }
        Ok(())
    }

    pub fn finish(self) -> io::Result<[u8; 32]> {
        let mut digest = [0; 32];
        // SAFETY: owned live hash and exactly the fixed SHA-256 output size.
        check(
            unsafe { BCryptFinishHash(self.hash, digest.as_mut_ptr(), 32, 0) },
            "finish SHA-256 hash",
        )?;
        Ok(digest)
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // SAFETY: each non-null handle is uniquely owned here. Destroy the hash
        // (including its CNG-owned buffer) before closing its provider.
        unsafe {
            if !self.hash.is_null() {
                BCryptDestroyHash(self.hash);
            }
            if !self.algorithm.is_null() {
                BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }
}

/// Many independent short digests on one thread: one provider and one reusable
/// hash object (`BCRYPT_HASH_REUSABLE_FLAG`), finished once per digest. Construct
/// on its consuming thread; handles are never shared with another thread.
pub struct Sha256Reusable {
    algorithm: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
}

impl Sha256Reusable {
    pub fn new() -> io::Result<Self> {
        let mut value = Self {
            algorithm: ptr::null_mut(),
            hash: ptr::null_mut(),
        };
        // SAFETY: live output handle storage and static, NUL-terminated strings.
        check(
            unsafe {
                BCryptOpenAlgorithmProvider(
                    &mut value.algorithm,
                    BCRYPT_SHA256_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER,
                    0,
                )
            },
            "open SHA-256 provider",
        )?;
        // SAFETY: live provider/output handle; Windows allocates the object, and
        // the reusable flag (Windows 8+) resets the state after each finish.
        check(
            unsafe {
                BCryptCreateHash(
                    value.algorithm,
                    &mut value.hash,
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                    0,
                    BCRYPT_HASH_REUSABLE_FLAG,
                )
            },
            "create reusable SHA-256 hash",
        )?;
        Ok(value)
    }

    /// The SHA-256 of exactly `bytes`; the object is ready for the next digest.
    pub fn digest(&mut self, bytes: &[u8]) -> io::Result<[u8; 32]> {
        for chunk in bytes.chunks(u32::MAX as usize) {
            // SAFETY: the owned live hash and immutable slice remain valid
            // throughout the synchronous call; BCryptHashData never edits input.
            check(
                unsafe { BCryptHashData(self.hash, chunk.as_ptr(), chunk.len() as u32, 0) },
                "update reusable SHA-256 hash",
            )?;
        }
        let mut digest = [0; 32];
        // SAFETY: owned live reusable hash and exactly the SHA-256 output size.
        check(
            unsafe { BCryptFinishHash(self.hash, digest.as_mut_ptr(), 32, 0) },
            "finish reusable SHA-256 hash",
        )?;
        Ok(digest)
    }
}

impl Drop for Sha256Reusable {
    fn drop(&mut self) {
        // SAFETY: each non-null handle is uniquely owned here. Destroy the hash
        // before closing its provider.
        unsafe {
            if !self.hash.is_null() {
                BCryptDestroyHash(self.hash);
            }
            if !self.algorithm.is_null() {
                BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }
}

/// Hash every requested byte, with a fixed 4 MiB buffer and exact reads. No
/// sampling, skipped zero ranges, alternate digest or source mutation.
pub fn hash_range(
    reader: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
) -> io::Result<[u8; 32]> {
    offset
        .checked_add(length)
        .ok_or_else(|| io::Error::other("SHA-256 range overflow"))?;
    reader.seek(SeekFrom::Start(offset))?;
    let mut hash = Sha256::new()?;
    let mut buffer = vec![0; length.min(4 * 1024 * 1024) as usize];
    let mut left = length;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count])?;
        left -= count as u64;
    }
    hash.finish()
}
