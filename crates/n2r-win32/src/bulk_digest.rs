//! The digest of something large: a working file, a recovery journal's body,
//! the ranges a journal changes. BLAKE3 for what this build writes, SHA-256
//! for what a build before it wrote.
//!
//! On a processor without SHA instructions SHA-256 is one stream of about a
//! quarter of a gigabyte a second, and a conversion of the Windows volume
//! hashed tens of gigabytes that way: every working file at the gate before
//! the first write to the source, the journal as it is written and again
//! wherever it is checked, every changed range before and after it is
//! applied. BLAKE3 is a cryptographic hash as well, several gigabytes a
//! second with AVX2, and one input is hashed on every processor at once. The
//! checks are the same checks, made as often.
//!
//! Both digests are thirty-two bytes, so nothing but its label tells one from
//! the other. Whatever pins a large digest therefore names its algorithm: a
//! record store in the magic of its header, a journal in its magic, a ticket
//! in its `digest` field (absent in a ticket of an older build, which is
//! SHA-256). The functions here take the [`Algorithm`] so read; a digest of
//! one is never compared with a pin of the other, and the memories of
//! digests already computed are kept by algorithm.
//!
//! Small records (envelopes, markers, intents, boot data, the page index of
//! a store) keep SHA-256 through `sha256_native` and `sha2`.
//!
//! This module opens no files and grants no I/O authority. BLAKE3's threads
//! are the process's Rayon pool, which has one thread for each processor the
//! process may use; a buffer is hashed there only when it is long enough to
//! be worth dividing.
use std::io::{self, Read, Seek, SeekFrom};

/// Which hash a large digest is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// What builds through 0.0.1 wrote. Read, never written.
    Sha256,
    /// What this build writes.
    Blake3,
}

impl Algorithm {
    /// The algorithm of everything this build writes.
    pub const WRITTEN: Self = Self::Blake3;

    /// The name a record gives it.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
        }
    }

    /// The algorithm a record's label names. A record without one was
    /// written before there was a choice: its caller passes `None`.
    pub fn from_label(label: Option<&str>) -> io::Result<Self> {
        match label {
            None | Some("sha256") => Ok(Self::Sha256),
            Some("blake3") => Ok(Self::Blake3),
            Some(other) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "a record names the digest algorithm {other:?}, which this build does not know"
                ),
            )),
        }
    }

    /// The name for a message.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Blake3 => "BLAKE3",
        }
    }
}

/// A buffer at least this long is hashed on the pool's threads. Below it the
/// division costs more than it saves.
const PARALLEL_FROM: usize = 256 * 1024;

/// The read buffer of a range hashed with BLAKE3: what the serial SHA-256
/// path has always used, and what its callers pay the ledger for.
const BLAKE3_BUFFER: usize = 4 * 1024 * 1024;

/// A streaming digest of exactly the bytes passed to `update`, in order.
/// Construct on its consuming thread: a SHA-256 hash object belongs to one.
pub enum Hasher {
    Sha256(crate::sha256_native::Sha256),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    pub fn new(algorithm: Algorithm) -> io::Result<Self> {
        Ok(match algorithm {
            Algorithm::Sha256 => Self::Sha256(crate::sha256_native::Sha256::new()?),
            Algorithm::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
        })
    }

    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Sha256(_) => Algorithm::Sha256,
            Self::Blake3(_) => Algorithm::Blake3,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Sha256(hash) => hash.update(bytes),
            Self::Blake3(hash) => {
                if bytes.len() >= PARALLEL_FROM {
                    hash.update_rayon(bytes);
                } else {
                    hash.update(bytes);
                }
                Ok(())
            }
        }
    }

    pub fn finish(self) -> io::Result<[u8; 32]> {
        match self {
            Self::Sha256(hash) => hash.finish(),
            Self::Blake3(hash) => Ok(*hash.finalize().as_bytes()),
        }
    }
}

/// The digest of `bytes`, held in memory.
pub fn digest(algorithm: Algorithm, bytes: &[u8]) -> io::Result<[u8; 32]> {
    let mut hash = Hasher::new(algorithm)?;
    hash.update(bytes)?;
    hash.finish()
}

/// The digest of the `length` bytes of `reader` from `offset`, all of them
/// read. No sampling, no skipped zero ranges.
pub fn hash_range(
    algorithm: Algorithm,
    reader: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
) -> io::Result<[u8; 32]> {
    if algorithm == Algorithm::Sha256 {
        return crate::sha256_native::hash_range(reader, offset, length);
    }
    offset
        .checked_add(length)
        .ok_or_else(|| io::Error::other("BLAKE3 range overflow"))?;
    let _timed = crate::perf::scope(crate::perf::Point::FileHash);
    crate::perf::add_bytes(crate::perf::Point::FileHash, length);
    reader.seek(SeekFrom::Start(offset))?;
    hash_next(algorithm, reader, length)
}

/// The digest of the next `length` bytes of `reader`, all of them read.
///
/// BLAKE3 hashes each buffer on the pool's threads while this thread waits:
/// four megabytes take about a millisecond, so there is nothing to gain from
/// reading the next buffer meanwhile, and one buffer is all it holds.
pub fn hash_next(
    algorithm: Algorithm,
    reader: &mut impl Read,
    length: u64,
) -> io::Result<[u8; 32]> {
    if algorithm == Algorithm::Sha256 {
        return crate::sha256_native::hash_next(reader, length);
    }
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0; length.min(BLAKE3_BUFFER as u64) as usize];
    let mut left = length;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        if count >= PARALLEL_FROM {
            hash.update_rayon(&buffer[..count]);
        } else {
            hash.update(&buffer[..count]);
        }
        left -= count as u64;
    }
    Ok(*hash.finalize().as_bytes())
}

/// The SHA-256 and the BLAKE3 of the same `bytes` bytes of `file` from its
/// start, from one read of them.
///
/// For a working file whose writer pinned it by SHA-256: whoever holds it
/// compares the SHA-256 with that pin and keeps the BLAKE3, and every later
/// full re-read of the held file is compared with the BLAKE3. Both digests
/// are of the very bytes this call read, so the later comparison says what
/// the SHA-256 would. The file is left positioned at `bytes`.
pub fn sha256_and_blake3(file: &mut (impl Read + Seek), bytes: u64) -> io::Result<Both> {
    // A megabyte in hand and the SHA-256 worker's two: less than the four
    // megabytes callers pay for.
    const CHUNK: usize = 1024 * 1024;
    const OVERLAP_FROM: u64 = 32 * 1024 * 1024;
    let _timed = crate::perf::scope(crate::perf::Point::FileHash);
    crate::perf::add_bytes(crate::perf::Point::FileHash, bytes);
    file.seek(SeekFrom::Start(0))?;
    let mut blake3 = blake3::Hasher::new();
    let mut buffer = vec![0; bytes.min(CHUNK as u64) as usize];
    let mut left = bytes;
    let overlapped = bytes >= OVERLAP_FROM
        && std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 2);
    let sha256 = if overlapped {
        let mut sha256 = crate::sha256_native::Overlapped::new(CHUNK)?;
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            sha256.update(&buffer[..count])?;
            blake3.update(&buffer[..count]);
            left -= count as u64;
        }
        sha256.finish()?
    } else {
        let mut sha256 = crate::sha256_native::Sha256::new()?;
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            sha256.update(&buffer[..count])?;
            blake3.update(&buffer[..count]);
            left -= count as u64;
        }
        sha256.finish()?
    };
    Ok(Both {
        sha256,
        blake3: *blake3.finalize().as_bytes(),
    })
}

/// See [`sha256_and_blake3`].
pub struct Both {
    pub sha256: [u8; 32],
    pub blake3: [u8; 32],
}

/// A complete digest computed inside the gate that is open: the gate, the
/// algorithm, the file's identity (volume and file id), its length and its
/// timestamp.
type GateDigest = (
    u64,
    Algorithm,
    String,
    u64,
    std::time::SystemTime,
    [u8; 32],
);
static GATE_DIGESTS: std::sync::Mutex<Vec<GateDigest>> = std::sync::Mutex::new(Vec::new());

/// The digest of all `bytes` bytes of a held working file, for an owner to
/// compare with the digest it pinned.
///
/// The gate before the first write to the source reads every working file
/// again, once for each owner that holds it, and a record store has two: the
/// arena's pin and the reader that looks records up in it. Each hashed the
/// whole file, one after the other. Inside one gate under the check-once
/// policy the digest computed for a file stands for the next owner of that
/// same file that asks for the same algorithm (same volume and file id,
/// length and timestamp, each read from the caller's own handle); every
/// owner still compares it with its own pin and makes its own identity
/// checks. Outside a gate, and always with `--recheck-everything`, the file
/// is read every time. The file is left positioned at `bytes`, as after a
/// read.
pub fn held_file(
    algorithm: Algorithm,
    file: &mut std::fs::File,
    bytes: u64,
) -> io::Result<[u8; 32]> {
    let key = match crate::verify_policy::open_gate() {
        Some(gate) => {
            let metadata = file.metadata()?;
            (metadata.len() == bytes)
                .then(|| -> io::Result<_> {
                    Ok((
                        gate,
                        crate::file_storage::file_id_info(file)?,
                        metadata.modified()?,
                    ))
                })
                .transpose()?
        }
        None => None,
    };
    if let Some((gate, id, modified)) = &key {
        let known = GATE_DIGESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .find(|(of, with, file_id, length, at, _)| {
                of == gate
                    && *with == algorithm
                    && file_id == id
                    && *length == bytes
                    && at == modified
            })
            .map(|known| known.5);
        if let Some(digest) = known {
            file.seek(SeekFrom::Start(bytes))?;
            return Ok(digest);
        }
    }
    let digest = hash_range(algorithm, file, 0, bytes)?;
    if let Some((gate, id, modified)) = key {
        // Only for a file that is, after the read, what it was before it.
        let metadata = file.metadata()?;
        if metadata.len() == bytes && metadata.modified()? == modified {
            let mut known = GATE_DIGESTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Digests of gates that have closed are of no use to anyone.
            known.retain(|(of, ..)| *of == gate);
            known.push((gate, algorithm, id, bytes, modified, digest));
        }
    }
    Ok(digest)
}

type VerifiedBody = (Algorithm, [u8; 32], u64, u64);
static VERIFIED_JOURNAL_BODIES: std::sync::Mutex<Vec<VerifiedBody>> =
    std::sync::Mutex::new(Vec::new());
static JOURNAL_BODY_LAST_FULL: crate::verify_policy::LastFull =
    crate::verify_policy::LastFull::new();

/// Records that a recovery journal body with this digest was read in full and
/// matched, in this process.
pub fn note_journal_body_verified(
    algorithm: Algorithm,
    expected: &[u8; 32],
    offset: u64,
    length: u64,
) {
    let mut verified = VERIFIED_JOURNAL_BODIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !verified.contains(&(algorithm, *expected, offset, length)) {
        verified.push((algorithm, *expected, offset, length));
    }
}

/// Whether a full read of this journal body can be skipped: it already
/// matched in this process under this algorithm, the route checks once, and
/// the single full read due inside the gate before the first source write
/// has been made (or no gate is open). The body never changes once written;
/// only the marker area in front of it does.
pub fn journal_body_already_verified(
    algorithm: Algorithm,
    expected: &[u8; 32],
    offset: u64,
    length: u64,
) -> bool {
    if !crate::verify_policy::checks_once() {
        return false;
    }
    let known = VERIFIED_JOURNAL_BODIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(&(algorithm, *expected, offset, length));
    known && !crate::verify_policy::full(&JOURNAL_BODY_LAST_FULL)
}

/// The digest of a held recovery journal's immutable body, to compare with
/// `expected`. Gigabytes long and compared at every step of apply and
/// finalization; see [`journal_body_already_verified`] for when the read is
/// skipped and `expected` returned.
pub fn journal_body(
    algorithm: Algorithm,
    reader: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
    expected: &[u8; 32],
) -> io::Result<[u8; 32]> {
    if journal_body_already_verified(algorithm, expected, offset, length) {
        return Ok(*expected);
    }
    let actual = hash_range(algorithm, reader, offset, length)?;
    if actual == *expected {
        note_journal_body_verified(algorithm, expected, offset, length);
    }
    Ok(actual)
}
