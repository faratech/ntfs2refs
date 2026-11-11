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

/// The SHA-256 algorithm provider, opened once and kept for the life of the
/// process. Finding, loading and initializing a provider is slow (Windows'
/// documentation says to keep the handle for that reason): opened for every
/// hash, it cost 16 s while the full Windows journal was written, three
/// hashes to a row. A provider handle may create hash objects on any thread;
/// each hash object still belongs to one thread.
fn provider() -> io::Result<BCRYPT_ALG_HANDLE> {
    static PROVIDER: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if let Some(handle) = PROVIDER.get() {
        return Ok(*handle as BCRYPT_ALG_HANDLE);
    }
    let mut handle: BCRYPT_ALG_HANDLE = ptr::null_mut();
    // SAFETY: live output handle storage and static, NUL-terminated strings.
    check(
        unsafe {
            BCryptOpenAlgorithmProvider(
                &mut handle,
                BCRYPT_SHA256_ALGORITHM,
                MS_PRIMITIVE_PROVIDER,
                0,
            )
        },
        "open SHA-256 provider",
    )?;
    if PROVIDER.set(handle as usize).is_err() {
        // Another thread opened it first; this one is not needed.
        // SAFETY: a provider handle this call opened and nothing else uses.
        unsafe { BCryptCloseAlgorithmProvider(handle, 0) };
    }
    Ok(*PROVIDER.get().expect("provider stored above") as BCRYPT_ALG_HANDLE)
}

/// A single-use hash. Construct on its consuming thread; the hash object is
/// never shared with another thread or reused after finishing.
pub struct Sha256 {
    hash: BCRYPT_HASH_HANDLE,
}

impl Sha256 {
    pub fn new() -> io::Result<Self> {
        let algorithm = provider()?;
        let mut value = Self {
            hash: ptr::null_mut(),
        };
        // SAFETY: live provider/output handle; Windows allocates the hash object
        // when the object buffer is NULL/zero (supported since Windows 7).
        check(
            unsafe {
                BCryptCreateHash(
                    algorithm,
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
        // SAFETY: the hash object (and its CNG-owned buffer) is uniquely
        // owned here; the provider it came from stays open for the process.
        unsafe {
            if !self.hash.is_null() {
                BCryptDestroyHash(self.hash);
            }
        }
    }
}

/// Many independent short digests on one thread: one reusable hash object
/// (`BCRYPT_HASH_REUSABLE_FLAG`), finished once per digest. Construct on its
/// consuming thread; the hash object is never shared with another thread.
pub struct Sha256Reusable {
    hash: BCRYPT_HASH_HANDLE,
}

impl Sha256Reusable {
    pub fn new() -> io::Result<Self> {
        let algorithm = provider()?;
        let mut value = Self {
            hash: ptr::null_mut(),
        };
        // SAFETY: live provider/output handle; Windows allocates the object, and
        // the reusable flag (Windows 8+) resets the state after each finish.
        check(
            unsafe {
                BCryptCreateHash(
                    algorithm,
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
        // SAFETY: the hash object is uniquely owned here; the provider it
        // came from stays open for the process.
        unsafe {
            if !self.hash.is_null() {
                BCryptDestroyHash(self.hash);
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
        self.update_parts(&[bytes])
    }

    /// As [`Self::update`] for `parts` one after another, handed to the worker
    /// together; their total length is bounded like a single chunk's.
    pub fn update_parts(&mut self, parts: &[&[u8]]) -> io::Result<()> {
        let total = parts
            .iter()
            .try_fold(0usize, |total, part| total.checked_add(part.len()));
        if total.is_none_or(|total| total > self.chunk_bytes) {
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
        for part in parts {
            buffer.extend_from_slice(part);
        }
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
type VerifiedBody = ([u8; 32], u64, u64);
static VERIFIED_JOURNAL_BODIES: std::sync::Mutex<Vec<VerifiedBody>> =
    std::sync::Mutex::new(Vec::new());
static JOURNAL_BODY_LAST_FULL: crate::verify_policy::LastFull =
    crate::verify_policy::LastFull::new();

/// Records that a recovery journal body with this digest was read in full and
/// matched, in this process.
pub fn note_journal_body_verified(expected: &[u8; 32], offset: u64, length: u64) {
    let mut verified = VERIFIED_JOURNAL_BODIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !verified.contains(&(*expected, offset, length)) {
        verified.push((*expected, offset, length));
    }
}

/// Whether a full read of this journal body can be skipped: it already
/// matched in this process, the route checks once, and the single full read
/// due inside the gate before the first source write has been made (or no
/// gate is open). The body never changes once written; only the marker area
/// in front of it does.
pub fn journal_body_already_verified(expected: &[u8; 32], offset: u64, length: u64) -> bool {
    if !crate::verify_policy::checks_once() {
        return false;
    }
    let known = VERIFIED_JOURNAL_BODIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(&(*expected, offset, length));
    known && !crate::verify_policy::full(&JOURNAL_BODY_LAST_FULL)
}

/// SHA-256 of a held recovery journal's immutable body, to compare with
/// `expected`. Gigabytes long and compared at every step of apply and
/// finalization; see [`journal_body_already_verified`] for when the read is
/// skipped and `expected` returned.
pub fn journal_body(
    reader: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
    expected: &[u8; 32],
) -> io::Result<[u8; 32]> {
    if journal_body_already_verified(expected, offset, length) {
        return Ok(*expected);
    }
    let actual = hash_range(reader, offset, length)?;
    if actual == *expected {
        note_journal_body_verified(expected, offset, length);
    }
    Ok(actual)
}

pub fn hash_range(
    reader: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
) -> io::Result<[u8; 32]> {
    offset
        .checked_add(length)
        .ok_or_else(|| io::Error::other("SHA-256 range overflow"))?;
    let _timed = crate::perf::scope(crate::perf::Point::FileHash);
    crate::perf::add_bytes(crate::perf::Point::FileHash, length);
    reader.seek(SeekFrom::Start(offset))?;
    hash_next(reader, length)
}

/// SHA-256 of the next `length` bytes of `reader`, all of them read.
///
/// A long range is hashed on a second thread while this one reads the next
/// megabyte: the gate before the first write to the source reads every
/// working file again (16 GB on the full Windows volume), and reading and
/// hashing took turns on one thread. The two megabyte buffers of that path
/// are less than the four-megabyte buffer of the serial one, which callers
/// pay for; the digest is the same.
pub fn hash_next(reader: &mut impl Read, length: u64) -> io::Result<[u8; 32]> {
    const OVERLAP_FROM: u64 = 32 * 1024 * 1024;
    const OVERLAP_CHUNK: usize = 1024 * 1024;
    let mut left = length;
    if length >= OVERLAP_FROM
        && std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 2)
    {
        let mut hash = Overlapped::new(OVERLAP_CHUNK)?;
        let mut buffer = vec![0; OVERLAP_CHUNK];
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count])?;
            left -= count as u64;
        }
        return hash.finish();
    }
    let mut hash = Sha256::new()?;
    let mut buffer = vec![0; length.min(4 * 1024 * 1024) as usize];
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count])?;
        left -= count as u64;
    }
    hash.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    struct CountingReader {
        inner: io::Cursor<Vec<u8>>,
        reads: usize,
    }
    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            self.inner.read(buffer)
        }
    }
    impl Seek for CountingReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    // The process-wide "check once" switch is off in tests, as it is for
    // every route that does not run a gate before its first source write.
    #[test]
    fn a_journal_body_is_read_every_time_unless_the_route_checks_once() {
        let data: Vec<u8> = (0..8192u32).map(|value| value as u8).collect();
        let expected: [u8; 32] = sha2::Sha256::digest(&data[1024..]).into();
        let mut reader = CountingReader {
            inner: io::Cursor::new(data),
            reads: 0,
        };
        assert_eq!(
            journal_body(&mut reader, 1024, 7168, &expected).unwrap(),
            expected
        );
        let first = reader.reads;
        assert!(first > 0);
        assert!(!journal_body_already_verified(&expected, 1024, 7168));
        assert_eq!(
            journal_body(&mut reader, 1024, 7168, &expected).unwrap(),
            expected
        );
        assert!(
            reader.reads > first,
            "the second comparison must read the body again"
        );
    }

    #[test]
    fn parts_handed_to_the_digest_thread_hash_as_the_bytes_in_order() {
        let frame = 7u64.to_le_bytes();
        let body: Vec<u8> = (0..5000u32).map(|value| (value * 7) as u8).collect();
        let mut overlapped = Overlapped::new(body.len() + 16).unwrap();
        let mut serial = sha2::Sha256::new();
        overlapped.update(b"head").unwrap();
        serial.update(b"head");
        for round in 0..5u64 {
            let at = round.to_le_bytes();
            overlapped.update_parts(&[&at, &frame, &body]).unwrap();
            serial.update(at);
            serial.update(frame);
            serial.update(&body);
        }
        overlapped.update_parts(&[]).unwrap();
        // One byte more than the bound, split over parts, is refused whole.
        assert!(
            overlapped
                .update_parts(&[&body, &frame, &frame, &[0]])
                .is_err()
        );
        let expected: [u8; 32] = serial.finalize().into();
        assert_eq!(overlapped.finish().unwrap(), expected);
    }

    #[test]
    fn a_long_range_hashed_on_two_threads_has_the_digest_of_its_bytes() {
        // Forty megabytes and a ragged tail: past the size from which the
        // range is hashed while the next megabyte is read.
        let data: Vec<u8> = (0..40 * 1024 * 1024 + 12_345u32)
            .map(|value| (value ^ (value >> 11)) as u8)
            .collect();
        for (offset, length) in [
            (0u64, data.len() as u64),
            (4097, 33 * 1024 * 1024),
            (100, 5000),
        ] {
            let expected: [u8; 32] =
                sha2::Sha256::digest(&data[offset as usize..(offset + length) as usize]).into();
            let mut reader = io::Cursor::new(&data);
            assert_eq!(hash_range(&mut reader, offset, length).unwrap(), expected);
            assert_eq!(
                reader.position(),
                offset + length,
                "exactly the range is read"
            );
        }
        // A range that ends before its length is an error, not a short digest.
        let mut reader = io::Cursor::new(&data);
        assert!(hash_range(&mut reader, 1024, data.len() as u64).is_err());
    }

    #[test]
    fn a_changed_journal_body_is_reported_as_different() {
        let mut data = vec![3u8; 4096];
        let expected: [u8; 32] = sha2::Sha256::digest(&data[..]).into();
        data[100] ^= 1;
        let mut reader = io::Cursor::new(data);
        assert_ne!(
            journal_body(&mut reader, 0, 4096, &expected).unwrap(),
            expected
        );
        assert!(!journal_body_already_verified(&expected, 0, 4096));
    }
}
