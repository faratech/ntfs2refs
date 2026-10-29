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

/// One stream's SHA-256, computed by CNG on a worker thread while the caller
/// reads its next buffer. One buffer of at most `chunk_bytes` is in flight; the
/// digest equals a serial SHA-256 of the same ordered bytes.
pub struct Overlapped {
    input: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    recycled: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    spare: Option<Vec<u8>>,
    worker: Option<std::thread::JoinHandle<io::Result<[u8; 32]>>>,
    chunk_bytes: usize,
}

impl Overlapped {
    pub fn new(chunk_bytes: usize) -> io::Result<Self> {
        let (input, chunks) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        let (buffers, recycled) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("n2r-stream-digest".into())
            .spawn(move || {
                // The CNG object lives only on this worker.
                let mut hash = Sha256::new()?;
                while let Ok(buffer) = chunks.recv() {
                    hash.update(&buffer)?;
                    if buffers.send(buffer).is_err() {
                        break;
                    }
                }
                hash.finish()
            })?;
        Ok(Self {
            input: Some(input),
            recycled: Some(recycled),
            spare: Some(Vec::with_capacity(chunk_bytes)),
            worker: Some(worker),
            chunk_bytes,
        })
    }

    pub fn update(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > self.chunk_bytes {
            return Err(io::Error::other("overlapped digest chunk exceeds bound"));
        }
        let buffer = match self.spare.take() {
            Some(buffer) => Some(buffer),
            None => self.recycled.as_ref().and_then(|r| r.recv().ok()),
        };
        let Some(mut buffer) = buffer else {
            return Err(self.stopped());
        };
        buffer.clear();
        buffer.extend_from_slice(bytes);
        let sent = self.input.as_ref().is_some_and(|i| i.send(buffer).is_ok());
        if !sent {
            return Err(self.stopped());
        }
        Ok(())
    }

    fn stopped(&mut self) -> io::Error {
        self.input.take();
        self.recycled.take();
        match self.worker.take().map(std::thread::JoinHandle::join) {
            Some(Ok(Err(error))) => error,
            Some(Err(_)) => io::Error::other("overlapped digest worker panicked"),
            _ => io::Error::other("overlapped digest worker stopped before all input"),
        }
    }

    pub fn finish(mut self) -> io::Result<[u8; 32]> {
        // Only one buffer exists, so nothing is queued behind the final chunk;
        // closing the recycle receiver releases the worker after hashing it.
        self.input.take();
        self.recycled.take();
        self.worker
            .take()
            .ok_or_else(|| io::Error::other("missing overlapped digest worker"))?
            .join()
            .map_err(|_| io::Error::other("overlapped digest worker panicked"))?
    }
}

impl Drop for Overlapped {
    fn drop(&mut self) {
        self.input.take();
        self.recycled.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
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
