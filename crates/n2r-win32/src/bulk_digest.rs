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
//! record store in the magic of its header, a journal's ticket in its
//! `digest` field (absent in a ticket of an older build, which is SHA-256),
//! the capture's literal file in its pin. The functions here take the
//! [`Algorithm`] so read; a digest of one is never compared with a pin of
//! the other, and the memories of digests already computed are kept by
//! algorithm.
//!
//! Small records (envelopes, markers, intents, boot data, the page index of
//! a store) keep SHA-256 through `sha256_native` and `sha2`.
//!
//! This module opens no files and grants no I/O authority. BLAKE3's threads
//! are the process's Rayon pool, which has one thread for each processor the
//! process may use; a buffer is hashed there only when it is long enough to
//! be worth dividing.
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Seek, SeekFrom};

/// Which hash a large digest is. Serialized as its label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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

#[cfg(windows)]
type Sha256Stream = crate::sha256_native::Sha256;
#[cfg(not(windows))]
struct Sha256Stream(sha2::Sha256);
#[cfg(not(windows))]
impl Sha256Stream {
    fn new() -> io::Result<Self> {
        Ok(Self(<sha2::Sha256 as sha2::Digest>::new()))
    }
    fn update(&mut self, bytes: &[u8]) -> io::Result<()> {
        sha2::Digest::update(&mut self.0, bytes);
        Ok(())
    }
    fn finish(self) -> io::Result<[u8; 32]> {
        Ok(sha2::Digest::finalize(self.0).into())
    }
}

fn blake3_update(hash: &mut blake3::Hasher, bytes: &[u8]) {
    if bytes.len() >= PARALLEL_FROM {
        hash.update_rayon(bytes);
    } else {
        hash.update(bytes);
    }
}

/// A streaming digest of exactly the bytes passed to `update`, in order.
/// Construct on its consuming thread: a SHA-256 hash object belongs to one.
pub struct Hasher(Inner);

enum Inner {
    Sha256(Sha256Stream),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    pub fn new(algorithm: Algorithm) -> io::Result<Self> {
        Ok(Self(match algorithm {
            Algorithm::Sha256 => Inner::Sha256(Sha256Stream::new()?),
            Algorithm::Blake3 => Inner::Blake3(Box::new(blake3::Hasher::new())),
        }))
    }

    pub fn algorithm(&self) -> Algorithm {
        match &self.0 {
            Inner::Sha256(_) => Algorithm::Sha256,
            Inner::Blake3(_) => Algorithm::Blake3,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> io::Result<()> {
        match &mut self.0 {
            Inner::Sha256(hash) => hash.update(bytes),
            Inner::Blake3(hash) => {
                blake3_update(hash, bytes);
                Ok(())
            }
        }
    }

    pub fn finish(self) -> io::Result<[u8; 32]> {
        match self.0 {
            Inner::Sha256(hash) => hash.finish(),
            Inner::Blake3(hash) => Ok(*hash.finalize().as_bytes()),
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
    #[cfg(windows)]
    if algorithm == Algorithm::Sha256 {
        return crate::sha256_native::hash_range(reader, offset, length);
    }
    offset
        .checked_add(length)
        .ok_or_else(|| io::Error::other(format!("{} range overflow", algorithm.name())))?;
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
    #[cfg(windows)]
    if algorithm == Algorithm::Sha256 {
        return crate::sha256_native::hash_next(reader, length);
    }
    let mut hash = Hasher::new(algorithm)?;
    let mut buffer = vec![0; length.min(BLAKE3_BUFFER as u64) as usize];
    let mut left = length;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count])?;
        left -= count as u64;
    }
    hash.finish()
}

/// The SHA-256 and the BLAKE3 of the same `bytes` bytes of `file` from its
/// start, from one read of them.
///
/// For a working file whose writer pinned it by SHA-256: whoever holds it
/// compares the SHA-256 with that pin and keeps the BLAKE3, and every later
/// full re-read of the held file is compared with the BLAKE3. Both digests
/// are of the very bytes this call read, so the later comparison says what
/// the SHA-256 would. The file is left positioned at `bytes`.
#[cfg(windows)]
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
            blake3_update(&mut blake3, &buffer[..count]);
            left -= count as u64;
        }
        sha256.finish()?
    } else {
        let mut sha256 = crate::sha256_native::Sha256::new()?;
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            sha256.update(&buffer[..count])?;
            blake3_update(&mut blake3, &buffer[..count]);
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
#[cfg(windows)]
pub struct Both {
    pub sha256: [u8; 32],
    pub blake3: [u8; 32],
}

/// A complete digest computed inside the gate that is open: the gate, the
/// algorithm, the file's identity (volume and file id), its length and its
/// timestamp.
#[cfg(windows)]
type GateDigest = (u64, Algorithm, String, u64, std::time::SystemTime, [u8; 32]);
#[cfg(windows)]
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
#[cfg(windows)]
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

/// A journal body: the algorithm and digest that pin it, where it begins in
/// its journal and how long it is.
pub(crate) type VerifiedBody = (Algorithm, [u8; 32], u64, u64);
static VERIFIED_JOURNAL_BODIES: std::sync::Mutex<Vec<VerifiedBody>> =
    std::sync::Mutex::new(Vec::new());
static JOURNAL_BODY_LAST_FULL: crate::verify_policy::LastFull =
    crate::verify_policy::LastFull::new();

/// One hold of a journal: its number, the body it pins, and whether that body
/// was read in full and matched while the hold lasted.
type HeldBody = (u64, VerifiedBody, bool);
static HELD_JOURNAL_BODIES: std::sync::Mutex<Vec<HeldBody>> = std::sync::Mutex::new(Vec::new());
static NEXT_JOURNAL_BODY_HOLD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Says, for as long as it lives, that this process holds a recovery journal
/// open so that nothing else can write to it (share-zero), and writes only
/// to the marker area in front of its body itself.
///
/// A recovery has no gate (`verify_policy`), so what it read in full it used
/// to read in full again at every step: six times over a rollback. Under
/// [`crate::verify_policy::repeat_once`] a body that was read in full and
/// matched *while this hold lasted* is not read again until the hold ends.
/// What was read before the hold began, through another owner of the journal
/// or by the conversion being recovered, does not count; and when the owner
/// of the journal is dropped, so is this, and nothing it verified stands for
/// an owner that opens the journal again. Whoever opens the journal keeps
/// this beside it and drops it no later.
///
/// The hold decides only while the process does not check once. From where
/// a resumed recovery selects `check_once`, for its finalizer, that policy's
/// own rule decides, as it did before there were holds: a body that matched
/// in this process is not read again outside a gate, by the finalizer's
/// reopening of the journal either.
pub struct JournalBodyHold(u64);

impl JournalBodyHold {
    pub fn begin(algorithm: Algorithm, expected: &[u8; 32], offset: u64, length: u64) -> Self {
        let hold = NEXT_JOURNAL_BODY_HOLD.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        HELD_JOURNAL_BODIES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((hold, (algorithm, *expected, offset, length), false));
        Self(hold)
    }
}

impl Drop for JournalBodyHold {
    fn drop(&mut self) {
        HELD_JOURNAL_BODIES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(hold, ..)| *hold != self.0);
    }
}

/// Whether a [`JournalBodyHold`] of this body is alive and the body was read
/// in full and matched since it began.
pub(crate) fn journal_body_verified_while_held(body: &VerifiedBody) -> bool {
    HELD_JOURNAL_BODIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .any(|(_, held, verified)| held == body && *verified)
}

/// Records that a recovery journal body with this digest was read in full and
/// matched, in this process.
pub fn note_journal_body_verified(
    algorithm: Algorithm,
    expected: &[u8; 32],
    offset: u64,
    length: u64,
) {
    let body = (algorithm, *expected, offset, length);
    {
        let mut verified = VERIFIED_JOURNAL_BODIES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !verified.contains(&body) {
            verified.push(body);
        }
    }
    for (_, held, verified) in HELD_JOURNAL_BODIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter_mut()
    {
        *verified |= *held == body;
    }
}

/// The rule of [`journal_body_already_verified`], apart from the switches and
/// the memories it reads. A route that checks once is decided by its gate
/// alone, as it always was; `known_and_no_full_read_due` is asked only then.
pub(crate) fn journal_body_read_is_left_out(
    checks_once: bool,
    repeats_once: bool,
    verified_while_held: impl FnOnce() -> bool,
    known_and_no_full_read_due: impl FnOnce() -> bool,
) -> bool {
    if checks_once {
        known_and_no_full_read_due()
    } else {
        repeats_once && verified_while_held()
    }
}

/// Whether a full read of this journal body can be skipped. The body never
/// changes once written; only the marker area in front of it does.
///
/// On a route that checks once: it already matched in this process under
/// this algorithm, and the single full read due inside the gate before the
/// first source write has been made (or no gate is open).
///
/// In a recovery, which has no gate and does not check once until its replay
/// is over (`verify_policy::repeat_once`): this process read it in full, and
/// it matched, while it held the journal, and it has held the journal since
/// ([`JournalBodyHold`]). The first read of the journal by the recovery that
/// opens it is therefore always complete. (Its finalizer checks once and is
/// decided by the rule above, as before.)
///
/// Otherwise (`--recheck-everything`, and every route with neither switch)
/// it is read every time.
pub fn journal_body_already_verified(
    algorithm: Algorithm,
    expected: &[u8; 32],
    offset: u64,
    length: u64,
) -> bool {
    let body = (algorithm, *expected, offset, length);
    journal_body_read_is_left_out(
        crate::verify_policy::checks_once(),
        crate::verify_policy::repeats_once(),
        || journal_body_verified_while_held(&body),
        || {
            let known = VERIFIED_JOURNAL_BODIES
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains(&body);
            known && !crate::verify_policy::full(&JOURNAL_BODY_LAST_FULL)
        },
    )
}

/// The digest of a held recovery journal's immutable body, to compare with
/// `expected`, which the journal's ticket pins by `algorithm`. Gigabytes
/// long and compared at every step of apply, recovery and finalization; see
/// [`journal_body_already_verified`] for when the read is skipped and
/// `expected` returned.
pub fn journal_body(
    algorithm: Algorithm,
    reader: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
    expected: &[u8; 32],
) -> io::Result<[u8; 32]> {
    journal_body_reading(algorithm, reader, offset, length, expected).map(|(digest, _)| digest)
}

/// [`journal_body`], and whether the body was read in full this time:
/// `false` where the read was left out and `expected` returned. A check of
/// the journal's descriptors that follows the hash, which lie in the body,
/// is left out on the same ground (see `paged_recovery`).
pub fn journal_body_reading(
    algorithm: Algorithm,
    reader: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
    expected: &[u8; 32],
) -> io::Result<([u8; 32], bool)> {
    if journal_body_already_verified(algorithm, expected, offset, length) {
        return Ok((*expected, false));
    }
    let actual = hash_range(algorithm, reader, offset, length)?;
    if actual == *expected {
        note_journal_body_verified(algorithm, expected, offset, length);
    }
    Ok((actual, true))
}
