//! Bounded, authenticated metadata records in one ordinary file. This is not
//! source, journal or execution authority. No raw handle or partial validation
//! result is exposed. Keys and JSON records are supplied by the typed caller.
//! Callers must separately exclude raw/admin aliases and surviving writable
//! mappings: ordinary file sharing alone cannot prove those writers absent.
use crate::bulk_digest::{self, Algorithm};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, Prefix},
    time::SystemTime,
};

/// The format this build writes. Its magic says which digest the file is
/// pinned by and which one its page index carries: BLAKE3
/// (`bulk_digest`). The magic is the first thing the complete-file digest
/// covers, so a file cannot name one algorithm and be pinned by the other.
pub const MAGIC: [u8; 8] = *b"N2RMPG02";
/// The format of builds through 0.0.1, the same in every other respect:
/// pinned and indexed by SHA-256. Read, never written.
const MAGIC_SHA256: [u8; 8] = *b"N2RMPG01";
fn magic_of(algorithm: Algorithm) -> [u8; 8] {
    match algorithm {
        Algorithm::Blake3 => MAGIC,
        Algorithm::Sha256 => MAGIC_SHA256,
    }
}
fn algorithm_of(magic: &[u8]) -> Option<Algorithm> {
    if magic == MAGIC {
        Some(Algorithm::Blake3)
    } else if magic == MAGIC_SHA256 {
        Some(Algorithm::Sha256)
    } else {
        None
    }
}
const PAGE_MAGIC: [u8; 8] = *b"N2RPG001";
const END_MAGIC: [u8; 8] = *b"N2RMEND1";
const HEADER: u64 = 64;
const FRAME: u64 = 64;
const INDEX: u64 = 64;
const FOOTER: u64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageBudget {
    /// Complete encoded page, including its 64-byte frame.
    pub max_page_bytes: u32,
    pub max_records_per_page: u32,
    pub max_records: u64,
    pub max_pages: u64,
    pub max_file_bytes: u64,
}
impl PageBudget {
    pub fn validate(self) -> io::Result<()> {
        require(
            (80..=4 * 1024 * 1024).contains(&self.max_page_bytes)
                && self.max_records_per_page > 0
                && self.max_records > 0
                && self.max_pages > 0
                && (HEADER + FOOTER..=i64::MAX as u64).contains(&self.max_file_bytes)
                && self.max_pages.checked_mul(INDEX).is_some(),
            "invalid metadata page budget",
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    /// The digest of the complete file, in hex. The field keeps its
    /// historical name; the algorithm is the one the file's magic names,
    /// BLAKE3 for every file this build writes.
    pub sha256: String,
    pub records: u64,
    pub pages: u64,
    pub bytes: u64,
}
#[derive(Debug)]
pub struct Record {
    pub key: Vec<u8>,
    pub payload: Vec<u8>,
}

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "metadata size overflow"))
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn read_at(file: &mut File, at: u64, bytes: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(at))?;
    file.read_exact(bytes)
}
fn valid_json(bytes: &[u8]) -> io::Result<()> {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    serde::de::IgnoredAny::deserialize(&mut parser).map_err(io::Error::other)?;
    parser.end().map_err(io::Error::other)
}
fn header(algorithm: Algorithm, purpose: [u8; 8], b: PageBudget) -> [u8; 64] {
    let mut out = [0; 64];
    out[..8].copy_from_slice(&magic_of(algorithm));
    out[8..16].copy_from_slice(&purpose);
    out[16..20].copy_from_slice(&b.max_page_bytes.to_le_bytes());
    out[20..24].copy_from_slice(&b.max_records_per_page.to_le_bytes());
    out[24..32].copy_from_slice(&b.max_records.to_le_bytes());
    out[32..40].copy_from_slice(&b.max_pages.to_le_bytes());
    out[40..48].copy_from_slice(&b.max_file_bytes.to_le_bytes());
    out
}
fn ordinary(path: &Path) -> io::Result<()> {
    require(
        path.is_absolute(),
        "absolute ordinary metadata path required",
    )?;
    for part in path.components() {
        match part {
            Component::Prefix(p) => {
                let local = match p.kind() {
                    Prefix::Disk(_) => true,
                    // Authenticated recovery pins use the actual volume-GUID
                    // route saved by the held file. Accept only that exact
                    // filesystem prefix, never device/GLOBALROOT/UNC aliases.
                    Prefix::Verbatim(name) => name
                        .to_str()
                        .and_then(|s| s.strip_prefix("Volume{"))
                        .and_then(|s| s.strip_suffix('}'))
                        .is_some_and(|guid| {
                            guid.len() == 36
                                && crate::layout::guid_bytes(guid).is_ok_and(|v| v != [0; 16])
                        }),
                    _ => false,
                };
                require(local, "local ordinary metadata path required")?;
            }
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| io::Error::other("metadata path must be Unicode"))?;
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                require(
                    !name.is_empty()
                        && !name.ends_with([' ', '.'])
                        && !name.chars().any(|c| {
                            c.is_control()
                                || matches!(c, ':' | '/' | '\\' | '"' | '<' | '>' | '|' | '?' | '*')
                        })
                        && !matches!(
                            stem.as_str(),
                            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                        )
                        && !(stem.len() == 4
                            && (stem.starts_with("COM") || stem.starts_with("LPT"))
                            && stem.as_bytes()[3].is_ascii_digit()),
                    "ambiguous metadata path",
                )?;
            }
            _ => return Err(io::Error::other("metadata path traversal refused")),
        }
    }
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let m = fs::symlink_metadata(parent)?;
        require(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "metadata ancestry is not ordinary",
        )?;
    }
    Ok(())
}
#[derive(PartialEq, Eq)]
struct Snapshot {
    id: String,
    final_path: String,
    bytes: u64,
    modified: SystemTime,
    attributes: u32,
}
impl Snapshot {
    fn observe(file: &File) -> io::Result<Self> {
        let m = file.metadata()?;
        require(
            m.is_file() && m.file_attributes() & (0x10 | 0x40 | 0x400 | 0x1000) == 0,
            "metadata handle is not an ordinary file",
        )?;
        let mut path = vec![0u16; 32768];
        // SAFETY: the borrowed held file handle and initialized WCHAR buffer
        // remain valid throughout this synchronous metadata-only query.
        let count = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_GUID,
            )
        } as usize;
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        require(
            count < path.len() && path[count] == 0,
            "metadata final path exceeds Windows bound",
        )?;
        let final_path = String::from_utf16(&path[..count]).map_err(io::Error::other)?;
        let (volume, name) = final_path
            .strip_prefix("\\\\?\\Volume{")
            .and_then(|p| p.split_once("}\\"))
            .ok_or_else(|| io::Error::other("metadata final path has no actual volume GUID"))?;
        require(
            crate::layout::guid_bytes(volume)? != [0; 16]
                && !name.is_empty()
                && !name.contains(':'),
            "metadata final route is not an ordinary volume file",
        )?;
        Ok(Self {
            id: crate::file_storage::file_id_info(file)?,
            final_path,
            bytes: m.len(),
            modified: m.modified()?,
            attributes: m.file_attributes(),
        })
    }
}
/// The digest of a page's body, as the file's format has it in its index.
/// The small fixed-size records below keep the portable SHA-256.
fn page_digest(algorithm: Algorithm, bytes: &[u8]) -> io::Result<[u8; 32]> {
    bulk_digest::digest(algorithm, bytes)
}
/// A page this large is hashed on a second thread while the writer's own
/// thread brings the file hash up to date with the page before it.
const OVERLAP_PAGE_BYTES: usize = 256 * 1024;
fn file_hash(algorithm: Algorithm, file: &mut File, bytes: u64) -> io::Result<[u8; 32]> {
    bulk_digest::held_file(algorithm, file, bytes)
}
/// The algorithm of the digest that pins a working file: BLAKE3 when it is a
/// complete record store of this module in the current format, SHA-256 for
/// any other file.
///
/// A store is told by more than its magic, so that a file of other content
/// that happens to begin with those eight bytes is not taken for one: its
/// footer has the end magic, the same purpose, the file's own length and the
/// SHA-256 of its header, as every store a [`Writer`] finished has.
/// Classification only: the digest covers every byte looked at here, and a
/// store that is damaged in any of them fails its pin under either
/// algorithm. The file's position is left at its start.
pub fn file_digest_algorithm(file: &mut File) -> io::Result<Algorithm> {
    let bytes = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    if bytes < HEADER + FOOTER {
        return Ok(Algorithm::Sha256);
    }
    let mut header = [0; HEADER as usize];
    file.read_exact(&mut header)?;
    let mut current = false;
    if header[..8] == MAGIC {
        let mut footer = [0; FOOTER as usize];
        read_at(file, bytes - FOOTER, &mut footer)?;
        current = footer[..8] == END_MAGIC
            && footer[8..16] == header[8..16]
            && u64_at(&footer, 40) == bytes
            && &footer[80..112] == Sha256::digest(header).as_slice();
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(if current {
        Algorithm::Blake3
    } else {
        Algorithm::Sha256
    })
}
/// The digest that pins a working file of `bytes` bytes, every byte read:
/// by the algorithm [`file_digest_algorithm`] gives for it. For an owner
/// that holds a working file to a digest a record names without knowing
/// whether the file is a store. The file is left positioned at `bytes`.
pub fn pinning_digest(file: &mut File, bytes: u64) -> io::Result<[u8; 32]> {
    let algorithm = file_digest_algorithm(file)?;
    bulk_digest::hash_range(algorithm, file, 0, bytes)
}
/// A file this process has seen every byte and every record of: one a
/// [`Writer`] here finished, or one a [`Reader`] here read completely (the
/// whole file hashed and held to its pin, every page held to its digest in
/// the index and every record parsed).
struct Known {
    bytes: u64,
    modified: SystemTime,
    // The algorithm of `digest`: the one this build writes for a file
    // written here, the one the file's magic names for a file read here.
    algorithm: Algorithm,
    // The complete file's digest.
    digest: [u8; 32],
    // XXH3-64 of each page body, in page order.
    page_sums: std::sync::Arc<Vec<u64>>,
    // A writer of this process produced it; otherwise a reader checked it.
    written: bool,
}
/// By file identity and final path.
type KnownFiles = std::collections::HashMap<(String, String), Known>;
static KNOWN: std::sync::Mutex<Option<KnownFiles>> = std::sync::Mutex::new(None);

fn note_written(snapshot: &Snapshot, digest: [u8; 32], page_sums: Vec<u64>) {
    KNOWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(KnownFiles::new)
        .insert(
            (snapshot.id.clone(), snapshot.final_path.clone()),
            Known {
                bytes: snapshot.bytes,
                modified: snapshot.modified,
                algorithm: Algorithm::WRITTEN,
                digest,
                page_sums: std::sync::Arc::new(page_sums),
                written: true,
            },
        );
}

/// Records what a reader's complete validation of exactly this file found:
/// `page_sums` are of the page bodies it had just held to their digests.
/// What is already known of the same file in the same state is kept: a file
/// written here stays one written here. Returns the checksums on record.
fn note_read(
    snapshot: &Snapshot,
    algorithm: Algorithm,
    digest: [u8; 32],
    page_sums: Vec<u64>,
) -> std::sync::Arc<Vec<u64>> {
    let mut known = KNOWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let files = known.get_or_insert_with(KnownFiles::new);
    let key = (snapshot.id.clone(), snapshot.final_path.clone());
    if let Some(same) = files.get(&key).filter(|known| {
        known.bytes == snapshot.bytes
            && known.modified == snapshot.modified
            && known.algorithm == algorithm
            && known.digest == digest
    }) {
        return std::sync::Arc::clone(&same.page_sums);
    }
    let page_sums = std::sync::Arc::new(page_sums);
    files.insert(
        key,
        Known {
            bytes: snapshot.bytes,
            modified: snapshot.modified,
            algorithm,
            digest,
            page_sums: std::sync::Arc::clone(&page_sums),
            written: false,
        },
    );
    page_sums
}

/// The checksum of each page of a file this process knows, and whether a
/// writer here produced the file.
struct KnownPages {
    page_sums: std::sync::Arc<Vec<u64>>,
    written: bool,
}

/// Whether this process wrote exactly this file, or read it completely,
/// unchanged since, with this digest of this algorithm. Its writer refused
/// any record that was not valid JSON under a strictly increasing key and
/// hashed every byte, and a reader that read it completely held every byte
/// to the pin and every record to the same rules, so under the check-once
/// policy a reader need not hash and parse the whole file again to open it.
/// Each page is still checked whenever it is loaded: against the checksum
/// kept in memory (returned here), which costs a few percent of the digest
/// in the page index and catches the same damage to a file nobody else can
/// have written.
///
/// What is known is used only where `verify_policy::full_unremembered` is
/// false, which the callers ask: inside the gate before the first write to
/// the source a known file is read completely and its pages are checked by
/// their digest. Without the check-once policy nothing is known at all.
fn known_file(snapshot: &Snapshot, algorithm: Algorithm, digest: &[u8; 32]) -> Option<KnownPages> {
    if !crate::verify_policy::checks_once() {
        return None;
    }
    KNOWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .and_then(|known| known.get(&(snapshot.id.clone(), snapshot.final_path.clone())))
        .filter(|known| {
            known.bytes == snapshot.bytes
                && known.modified == snapshot.modified
                && known.algorithm == algorithm
                && known.digest == *digest
        })
        .map(|known| KnownPages {
            page_sums: std::sync::Arc::clone(&known.page_sums),
            written: known.written,
        })
}

/// The digest a [`Writer`] in this process computed for exactly this file
/// (same identity, final path, length and timestamp), when the check-once
/// policy lets it stand for hashing the file again: outside a gate only. An
/// owner that pins a freshly written store by its digest can use it instead
/// of reading the whole file back. It is the BLAKE3 of the file: what
/// [`file_digest_algorithm`] says of every file a writer here finished.
pub fn digest_if_written_here(file: &File) -> Option<[u8; 32]> {
    if crate::verify_policy::full_unremembered() {
        return None;
    }
    let snapshot = Snapshot::observe(file).ok()?;
    KNOWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .and_then(|known| known.get(&(snapshot.id.clone(), snapshot.final_path.clone())))
        .filter(|known| {
            known.written && known.bytes == snapshot.bytes && known.modified == snapshot.modified
        })
        .map(|known| known.digest)
}

/// One start offset for every this many records of a page.
const START_STRIDE: u64 = 16;

/// The start offset of every [`START_STRIDE`]th record of a page, so a record
/// is found by scanning at most that many, not the whole page before it.
fn sparse_starts(body: &[u8], count: u32, starts: &mut Vec<u32>) -> io::Result<()> {
    starts.clear();
    let mut at = 0usize;
    for record in 0..u64::from(count) {
        if record % START_STRIDE == 0 {
            starts.push(u32::try_from(at).map_err(io::Error::other)?);
        }
        at = record_at(body, at)?.0;
    }
    Ok(())
}

fn projected(data_end: u64, pages: u64, budget: PageBudget) -> io::Result<u64> {
    let bytes = add(
        add(
            data_end,
            pages
                .checked_mul(INDEX)
                .ok_or_else(|| io::Error::other("metadata index overflow"))?,
        )?,
        FOOTER,
    )?;
    require(
        pages <= budget.max_pages && bytes <= budget.max_file_bytes,
        "metadata file/page budget exhausted",
    )?;
    Ok(bytes)
}

pub struct Writer {
    file: File,
    purpose: [u8; 8],
    budget: PageBudget,
    body: Vec<u8>,
    pending: u32,
    records: u64,
    pages: u64,
    data_end: u64,
    last_key: Option<Vec<u8>>,
    poisoned: bool,
    // Every byte in file order as it is written: the complete-file digest.
    // It runs one page behind (`lagging`), so that a page's own hash and the
    // file hash of the page before it can be computed at the same time.
    hash: Option<bulk_digest::Hasher>,
    lagging: Option<([u8; 64], Vec<u8>)>,
    // XXH3-64 of each page body written, for this process's own readers.
    page_sums: Vec<u64>,
}
impl Writer {
    pub fn new(path: &Path, purpose: [u8; 8], budget: PageBudget) -> io::Result<Self> {
        budget.validate()?;
        require(purpose != [0; 8], "typed metadata purpose required")?;
        ordinary(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        require(
            Snapshot::observe(&file)?.bytes == 0,
            "new empty metadata file required",
        )?;
        file.write_all(&header(Algorithm::WRITTEN, purpose, budget))?;
        let mut hash = bulk_digest::Hasher::new(Algorithm::WRITTEN)?;
        hash.update(&header(Algorithm::WRITTEN, purpose, budget))?;
        Ok(Self {
            file,
            purpose,
            budget,
            body: Vec::with_capacity(budget.max_page_bytes as usize - FRAME as usize),
            pending: 0,
            records: 0,
            pages: 0,
            data_end: HEADER,
            last_key: None,
            poisoned: false,
            hash: Some(hash),
            lagging: None,
            page_sums: Vec::new(),
        })
    }
    /// Keys are strictly increasing binary strings; only the first may be empty.
    /// A refused record poisons the writer, so finish cannot certify a prefix.
    pub fn push(&mut self, key: &[u8], payload: &[u8]) -> io::Result<()> {
        let result = self.push_inner(key, payload);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn push_inner(&mut self, key: &[u8], payload: &[u8]) -> io::Result<()> {
        require(!self.poisoned, "metadata writer is poisoned")?;
        let bytes = add(add(8, key.len() as u64)?, payload.len() as u64)?;
        require(
            bytes <= self.budget.max_page_bytes as u64 - FRAME
                && self.records < self.budget.max_records
                && self
                    .last_key
                    .as_ref()
                    .is_none_or(|last| last.as_slice() < key),
            "metadata record size/count/key order refused",
        )?;
        valid_json(payload)?;
        if self.pending > 0
            && (self.pending == self.budget.max_records_per_page
                || self.body.len() as u64 + bytes + FRAME > self.budget.max_page_bytes as u64)
        {
            self.flush_page()?;
        }
        projected(
            add(
                add(self.data_end, FRAME)?,
                add(self.body.len() as u64, bytes)?,
            )?,
            add(self.pages, 1)?,
            self.budget,
        )?;
        self.body
            .extend_from_slice(&(key.len() as u32).to_le_bytes());
        self.body
            .extend_from_slice(&(payload.len() as u32).to_le_bytes());
        self.body.extend_from_slice(key);
        self.body.extend_from_slice(payload);
        self.pending += 1;
        self.records += 1;
        self.last_key = Some(key.to_vec());
        Ok(())
    }
    fn flush_page(&mut self) -> io::Result<()> {
        if self.pending == 0 {
            return Ok(());
        }
        let next = add(add(self.data_end, FRAME)?, self.body.len() as u64)?;
        projected(next, add(self.pages, 1)?, self.budget)?;
        let mut frame = [0; 64];
        frame[..8].copy_from_slice(&PAGE_MAGIC);
        frame[8..12].copy_from_slice(&(self.body.len() as u32).to_le_bytes());
        frame[12..16].copy_from_slice(&self.pending.to_le_bytes());
        frame[16..24].copy_from_slice(&(self.records - self.pending as u64).to_le_bytes());
        let previous = self.lagging.take();
        let file_hash = self
            .hash
            .as_mut()
            .ok_or_else(|| io::Error::other("metadata writer hash absent"))?;
        let mut catch_up = || -> io::Result<()> {
            if let Some((frame, body)) = &previous {
                file_hash.update(frame)?;
                file_hash.update(body)?;
            }
            Ok(())
        };
        let body = &self.body;
        let page = if body.len() >= OVERLAP_PAGE_BYTES && previous.is_some() {
            let (page, caught_up) = std::thread::scope(|scope| {
                let page = scope.spawn(move || page_digest(Algorithm::WRITTEN, body));
                let caught_up = catch_up();
                (page.join(), caught_up)
            });
            caught_up?;
            page.map_err(|_| io::Error::other("metadata page hashing thread panicked"))??
        } else {
            catch_up()?;
            page_digest(Algorithm::WRITTEN, body)?
        };
        frame[32..].copy_from_slice(&page);
        self.file.seek(SeekFrom::Start(self.data_end))?;
        self.file.write_all(&frame)?;
        self.file.write_all(&self.body)?;
        self.page_sums.push(xxhash_rust::xxh3::xxh3_64(&self.body));
        self.data_end = next;
        self.pages += 1;
        self.pending = 0;
        // This page waits for the file hash; the page before it gives up its
        // buffer for the records that come next.
        let mut spare = previous.map(|(_, buffer)| buffer).unwrap_or_default();
        spare.clear();
        if spare.capacity() == 0 {
            spare
                .try_reserve_exact(self.body.capacity())
                .map_err(io::Error::other)?;
        }
        let written = std::mem::replace(&mut self.body, spare);
        self.lagging = Some((frame, written));
        Ok(())
    }
    pub fn finish(mut self) -> io::Result<Summary> {
        require(!self.poisoned, "metadata writer is poisoned")?;
        self.flush_page()?;
        let bytes = projected(self.data_end, self.pages, self.budget)?;
        let mut running = self
            .hash
            .take()
            .ok_or_else(|| io::Error::other("metadata writer hash absent"))?;
        if let Some((frame, body)) = self.lagging.take() {
            running.update(&frame)?;
            running.update(&body)?;
        }
        let mut at = HEADER;
        let mut first = 0;
        let mut index_hash = Sha256::new();
        // Build the index in the same file without retaining page descriptors.
        for page in 0..self.pages {
            let mut frame = [0; 64];
            read_at(&mut self.file, at, &mut frame)?;
            require(
                frame[..8] == PAGE_MAGIC && u64_at(&frame, 16) == first,
                "written metadata page changed",
            )?;
            let encoded = add(FRAME, u32_at(&frame, 8) as u64)?;
            first = add(first, u32_at(&frame, 12) as u64)?;
            frame[..8].copy_from_slice(&at.to_le_bytes());
            frame[8..12].copy_from_slice(&(encoded as u32).to_le_bytes());
            self.file
                .seek(SeekFrom::Start(add(self.data_end, page * INDEX)?))?;
            self.file.write_all(&frame)?;
            index_hash.update(frame);
            running.update(&frame)?;
            at = add(at, encoded)?;
        }
        require(
            at == self.data_end && first == self.records,
            "metadata index does not cover all records",
        )?;
        let mut footer = [0; 128];
        footer[..8].copy_from_slice(&END_MAGIC);
        footer[8..16].copy_from_slice(&self.purpose);
        for (position, value) in [
            (16, self.records),
            (24, self.pages),
            (32, self.data_end),
            (40, bytes),
        ] {
            footer[position..position + 8].copy_from_slice(&value.to_le_bytes());
        }
        footer[48..80].copy_from_slice(&index_hash.finalize());
        footer[80..112].copy_from_slice(&Sha256::digest(header(
            Algorithm::WRITTEN,
            self.purpose,
            self.budget,
        )));
        self.file.seek(SeekFrom::Start(bytes - FOOTER))?;
        self.file.write_all(&footer)?;
        running.update(&footer)?;
        self.file.flush()?;
        crate::verify_policy::flush_working_file(&self.file)?;
        let before = Snapshot::observe(&self.file)?;
        require(
            before.bytes == bytes,
            "metadata completed file length differs",
        )?;
        // The file is written front to back, so its digest is known from the
        // bytes handed to it. Reading it all back to hash it again is left out
        // under the check-once policy.
        let written: [u8; 32] = running.finish()?;
        if !crate::verify_policy::checks_once() {
            require(
                file_hash(Algorithm::WRITTEN, &mut self.file, bytes)? == written,
                "metadata file differs from the bytes written to it",
            )?;
        }
        require(
            Snapshot::observe(&self.file)? == before,
            "metadata file changed while finishing",
        )?;
        note_written(&before, written, std::mem::take(&mut self.page_sums));
        let sha256 = hex::encode(written);
        Ok(Summary {
            sha256,
            records: self.records,
            pages: self.pages,
            bytes,
        })
    }
}

/// The checksum this process keeps of one page body, and whose it is: the
/// writer's, or a reader's that had just held the page to its digest.
#[derive(Clone, Copy)]
struct PageSum {
    sum: u64,
    written: bool,
}

#[derive(Clone, Copy)]
struct Entry {
    offset: u64,
    bytes: u32,
    count: u32,
    first: u64,
    sha: [u8; 32],
}
fn entry(file: &mut File, index: u64, page: u64) -> io::Result<Entry> {
    let mut raw = [0; 64];
    read_at(
        file,
        add(
            index,
            page.checked_mul(INDEX)
                .ok_or_else(|| io::Error::other("metadata index overflow"))?,
        )?,
        &mut raw,
    )?;
    require(
        raw[24..32] == [0; 8],
        "metadata index reserved bytes differ",
    )?;
    Ok(Entry {
        offset: u64_at(&raw, 0),
        bytes: u32_at(&raw, 8),
        count: u32_at(&raw, 12),
        first: u64_at(&raw, 16),
        sha: raw[32..].try_into().unwrap(),
    })
}
fn load_page(
    file: &mut File,
    e: Entry,
    budget: PageBudget,
    data_end: u64,
    body_limit: usize,
    body: &mut Vec<u8>,
    statistics: &mut PageCacheStatistics,
    // This process's in-memory checksum of this page, when the file is one
    // it wrote or read completely: checked in place of the page's digest.
    known_sum: Option<PageSum>,
    // The digest the file's index carries for its pages.
    algorithm: Algorithm,
) -> io::Result<()> {
    require(
        e.bytes as u64 > FRAME
            && e.bytes <= budget.max_page_bytes
            && (e.bytes as u64 - FRAME) <= body_limit as u64
            && e.offset >= HEADER
            && add(e.offset, e.bytes as u64)? <= data_end
            && e.count > 0
            && e.count <= budget.max_records_per_page,
        "metadata page budget/count differs",
    )?;
    let _timed = crate::perf::scope(crate::perf::Point::PageLoad);
    crate::perf::add_bytes(crate::perf::Point::PageLoad, e.bytes as u64);
    let mut frame = [0; 64];
    read_at(file, e.offset, &mut frame)?;
    require(
        frame[..8] == PAGE_MAGIC
            && u32_at(&frame, 8) as u64 == e.bytes as u64 - FRAME
            && u32_at(&frame, 12) == e.count
            && u64_at(&frame, 16) == e.first
            && frame[24..32] == [0; 8]
            && frame[32..] == e.sha,
        "metadata page/index association differs",
    )?;
    body.resize(e.bytes as usize - FRAME as usize, 0);
    file.read_exact(body)?;
    statistics.page_loads = statistics.page_loads.saturating_add(1);
    if let Some(known) = known_sum {
        return require(
            xxhash_rust::xxh3::xxh3_64(body) == known.sum,
            if known.written {
                "metadata page differs from the page this process wrote"
            } else {
                "metadata page differs from the page this process read and held to its digest"
            },
        );
    }
    statistics.page_hash_bytes = statistics.page_hash_bytes.saturating_add(body.len() as u64);
    require(
        page_digest(algorithm, body)? == e.sha,
        "metadata page digest differs",
    )
}
fn record_at(body: &[u8], at: usize) -> io::Result<(usize, &[u8], &[u8])> {
    require(
        at.checked_add(8).is_some_and(|end| end <= body.len()),
        "metadata record frame truncated",
    )?;
    let key = u32_at(body, at) as usize;
    let payload = u32_at(body, at + 4) as usize;
    let split = (at + 8)
        .checked_add(key)
        .ok_or_else(|| io::Error::other("metadata key overflow"))?;
    let end = split
        .checked_add(payload)
        .ok_or_else(|| io::Error::other("metadata record overflow"))?;
    require(
        end <= body.len() && payload > 0,
        "metadata record escapes its page",
    )?;
    Ok((end, &body[at + 8..split], &body[split..end]))
}

/// Classification only. A true result grants nothing; open still requires the
/// expected complete-file SHA, purpose, exact budget and full validation.
pub fn has_magic(path: &Path) -> io::Result<bool> {
    ordinary(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let snapshot = Snapshot::observe(&file)?;
    if snapshot.bytes < 8 {
        return Ok(false);
    }
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    Ok(algorithm_of(&magic).is_some())
}

/// Bounded diagnostic counters, never validation or recovery authority. Page
/// loads/hash bytes include complete opening validation and failed page hashes;
/// hits/misses describe subsequent record requests. Overflow saturates rather
/// than changing the outcome of an otherwise valid metadata operation.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PageCacheStatistics {
    pub hits: u64,
    pub misses: u64,
    pub page_loads: u64,
    pub page_hash_bytes: u64,
}

struct CachedPage {
    entry: Option<Entry>,
    record: Option<(u64, usize, usize)>,
    body: Vec<u8>,
    starts: Vec<u32>,
}

/// The largest file a reader will decide by itself to hold in memory.
const AUTO_RESIDENT_FILE_BYTES: u64 = 1024 * 1024 * 1024;

pub struct Reader {
    file: File,
    snapshot: Snapshot,
    // The digest of the complete file, and of each page in its index, is of
    // the algorithm the file's magic names.
    algorithm: Algorithm,
    sha256: [u8; 32],
    last_full: crate::verify_policy::LastFull,
    budget: PageBudget,
    records: u64,
    pages: u64,
    index: u64,
    cached: Option<Entry>,
    // Ordinal, start and end of the last record decoded in the cached page.
    // Sequential access can continue from that frame instead of rescanning
    // every earlier record in the page for each lookup.
    cached_record: Option<(u64, usize, usize)>,
    body: Vec<u8>,
    // Sparse record offsets of the cached page; empty when it has none.
    starts: Vec<u32>,
    // Opened as a file this process wrote, without reading all of it again.
    written_here: bool,
    // This process's checksum of each page, when there is one per page: that
    // writer's, or the one taken as a reader here (this one, or one before
    // it) held every page of the file to its digest.
    page_sums: Option<std::sync::Arc<Vec<u64>>>,
    // Whose they are: the writer's, or a reader's.
    page_sums_written: bool,
    body_limit: usize,
    // Optional second authenticated page, supplied by an explicitly prepaid
    // caller. The primary slot is most recently used; swaps retain each page's
    // own record cursor and never share buffers across Reader/file ownership.
    secondary: Option<CachedPage>,
    // Every authenticated page, with each record's start offset. When present,
    // lookups do no file I/O, no re-hash and no in-page scan.
    // Every page, held in memory while the run's ledger has room for it:
    // given up when memory is short, and done without from then on.
    resident: Option<crate::evict::Evictable<ResidentPages>>,
    // The misses after which the reader asks again to hold its file, once
    // the ledger had no room for it.
    resident_asked_again_after: u64,
    // Never holds its file by itself: its owner keeps what it reads.
    page_by_page: bool,
    statistics: PageCacheStatistics,
}

struct ResidentPage {
    first: u64,
    starts: Vec<u32>,
    body: Vec<u8>,
}
/// Every page of a file, and what pays for holding them: the pages are
/// freed before the payment is returned.
struct ResidentPages {
    pages: Vec<ResidentPage>,
    _paid: Option<Box<dyn std::any::Any>>,
}

thread_local! {
    // The files whose pages a reader of this thread holds in memory, by the
    // digest (and its algorithm) and length of the complete file: a second reader of the same
    // file shares them. (The expected tree is opened more than once in a
    // run; each reader read and held all of it, and where the ledger had no
    // room for the second copy that reader re-read a page for nearly every
    // lookup: 280 s of one step on a volume of 500,000 files.)
    static RESIDENT: std::cell::RefCell<
        std::collections::HashMap<
            (Algorithm, [u8; 32], u64),
            crate::evict::WeakEvictable<ResidentPages>,
        >,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}
impl Reader {
    /// Pre-allocation body bound for an actual held ordinary file length.
    /// This is sizing only; open still authenticates the exact file, format,
    /// purpose, pinned budget and complete SHA before returning any record.
    pub fn body_capacity_for_file(budget: PageBudget, actual_file_bytes: u64) -> io::Result<usize> {
        budget.validate()?;
        require(
            (HEADER + FOOTER..=budget.max_file_bytes).contains(&actual_file_bytes),
            "metadata file size exceeds pinned budget",
        )?;
        usize::try_from((u64::from(budget.max_page_bytes) - FRAME).min(actual_file_bytes))
            .map_err(io::Error::other)
    }

    pub fn open(
        path: &Path,
        expected_sha256: &str,
        purpose: [u8; 8],
        budget: PageBudget,
    ) -> io::Result<Self> {
        budget.validate()?;
        ordinary(path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        Self::open_held(file, expected_sha256, purpose, budget)
    }

    /// Authenticate the caller's actual preopened readonly file. This lets
    /// the caller reserve its body bound from that same held file's length
    /// before Reader allocates; no saved length or path supplies authority.
    pub fn open_held(
        mut file: File,
        expected_sha256: &str,
        purpose: [u8; 8],
        budget: PageBudget,
    ) -> io::Result<Self> {
        budget.validate()?;
        crate::file_storage::require_readonly_access(&file)?;
        require(
            purpose != [0; 8]
                && expected_sha256.len() == 64
                && expected_sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "canonical metadata purpose/SHA required",
        )?;
        let sha256: [u8; 32] = hex::decode(expected_sha256)
            .map_err(io::Error::other)?
            .try_into()
            .map_err(|_| io::Error::other("metadata SHA length differs"))?;
        let snapshot = Snapshot::observe(&file)?;
        ordinary(Path::new(&snapshot.final_path))?;
        let body_limit = Self::body_capacity_for_file(budget, snapshot.bytes)?;
        // The file says which digest pins it; the digest covers that too.
        let mut actual_header = [0; 64];
        read_at(&mut file, 0, &mut actual_header)?;
        // (A file that is no store fails its pin or, below, its header, as
        // it always has.)
        let algorithm = algorithm_of(&actual_header[..8]).unwrap_or(Algorithm::Sha256);
        let known = known_file(&snapshot, algorithm, &sha256);
        // Written here or read completely here: neither is read completely
        // again to be opened, except inside the gate.
        let known_here = known.is_some() && !crate::verify_policy::full_unremembered();
        // A file written here: what the owners of a store are told, who then
        // leave out checks of their own that only its writer answers for.
        let written_here = known_here && known.as_ref().is_some_and(|known| known.written);
        if !known_here {
            require(
                file_hash(algorithm, &mut file, snapshot.bytes)? == sha256,
                "metadata complete-file digest differs",
            )?;
        }
        // The checksum of each page as this complete read holds it to its
        // digest, for the page loads and the readers that follow. Taken only
        // where it may be used, under the check-once policy (inside its gate
        // too, for when it has closed), and only for a file that is not
        // known already.
        let mut read_sums = (known.is_none() && crate::verify_policy::checks_once()).then(Vec::new);
        read_at(&mut file, 0, &mut actual_header)?;
        require(
            actual_header == header(algorithm, purpose, budget),
            "metadata purpose or pinned budget differs",
        )?;
        let mut footer = [0; 128];
        read_at(&mut file, snapshot.bytes - FOOTER, &mut footer)?;
        let records = u64_at(&footer, 16);
        let pages = u64_at(&footer, 24);
        let index = u64_at(&footer, 32);
        require(
            footer[..8] == END_MAGIC
                && footer[8..16] == purpose
                && footer[112..] == [0; 16]
                && records <= budget.max_records
                && pages <= budget.max_pages
                && (records == 0) == (pages == 0)
                && u64_at(&footer, 40) == snapshot.bytes
                && index >= HEADER
                && projected(index, pages, budget)? == snapshot.bytes
                && &footer[80..112] == Sha256::digest(actual_header).as_slice(),
            "metadata footer/index/counts incomplete",
        )?;
        let mut index_hash = Sha256::new();
        let mut raw = [0; 64];
        for page in 0..pages {
            read_at(&mut file, add(index, page * INDEX)?, &mut raw)?;
            index_hash.update(raw);
        }
        require(
            &footer[48..80] == index_hash.finalize().as_slice(),
            "metadata complete index SHA differs",
        )?;
        let mut body = Vec::with_capacity(body_limit);
        require(
            body.capacity() <= body_limit,
            "metadata body allocation exceeds its actual-file bound",
        )?;
        let mut cursor = HEADER;
        let mut count = 0;
        let mut previous: Option<Vec<u8>> = None;
        let mut cached = None;
        let mut statistics = PageCacheStatistics::default();
        for page in 0..pages {
            let e = entry(&mut file, index, page)?;
            require(
                e.offset == cursor && e.first == count && add(cursor, e.bytes as u64)? <= index,
                "metadata page index has a gap/overlap or missing records",
            )?;
            if known_here {
                // The index, checked against the footer above, is walked for
                // gaps; the pages it names are checked when they are loaded.
                cursor = add(cursor, e.bytes as u64)?;
                count = add(count, e.count as u64)?;
                require(count <= records, "metadata page records exceed footer")?;
                continue;
            }
            load_page(
                &mut file,
                e,
                budget,
                index,
                body_limit,
                &mut body,
                &mut statistics,
                None,
                algorithm,
            )?;
            let mut at = 0;
            for _ in 0..e.count {
                let (end, key, payload) = record_at(&body, at)?;
                require(
                    previous.as_ref().is_none_or(|last| last.as_slice() < key),
                    "metadata binary keys are not strictly ordered and unique",
                )?;
                valid_json(payload)?;
                previous = Some(key.to_vec());
                at = end;
            }
            require(
                at == body.len(),
                "metadata page has unindexed trailing records/bytes",
            )?;
            // Of the bytes that have just passed their digest and parsed.
            if let Some(sums) = &mut read_sums {
                sums.push(xxhash_rust::xxh3::xxh3_64(&body));
            }
            cursor = add(cursor, e.bytes as u64)?;
            count = add(count, e.count as u64)?;
            require(count <= records, "metadata page records exceed footer")?;
            cached = Some(e);
        }
        require(
            cursor == index && count == records && Snapshot::observe(&file)? == snapshot,
            "metadata full validation did not cover the immutable file",
        )?;
        // Only now, with every byte and every record of the unchanged file
        // seen, is the file one this process knows.
        let (page_sums, page_sums_written) = match (read_sums, known) {
            (Some(sums), _) => (Some(note_read(&snapshot, algorithm, sha256, sums)), false),
            (None, Some(known)) => (Some(known.page_sums), known.written),
            (None, None) => (None, false),
        };
        Ok(Self {
            file,
            snapshot,
            algorithm,
            sha256,
            last_full: crate::verify_policy::LastFull::new(),
            budget,
            records,
            pages,
            index,
            cached,
            cached_record: None,
            body,
            starts: Vec::new(),
            written_here,
            page_sums: page_sums.filter(|sums| sums.len() as u64 == pages),
            page_sums_written,
            body_limit,
            secondary: None,
            resident: None,
            resident_asked_again_after: 0,
            page_by_page: false,
            statistics,
        })
    }
    /// Upper bound of what `install_resident_pages` retains: every page body,
    /// one offset per record, and the per-page bookkeeping.
    pub fn resident_page_bytes(&self) -> io::Result<u64> {
        let offsets = self
            .records
            .checked_mul(4)
            .ok_or_else(|| io::Error::other("resident metadata offsets overflow"))?;
        let pages = self
            .pages
            .checked_mul(std::mem::size_of::<ResidentPage>() as u64)
            .ok_or_else(|| io::Error::other("resident metadata pages overflow"))?;
        add(add(self.index - HEADER, offsets)?, pages)
    }
    /// Keep every page in memory. Each page is read and SHA-checked once more
    /// against the already authenticated index, so a random lookup afterwards
    /// costs a binary search over pages instead of a 4 MiB read and hash. The
    /// caller reserves `resident_page_bytes` first and holds that payment
    /// until this Reader has dropped.
    pub fn install_resident_pages(&mut self) -> io::Result<()> {
        self.install_resident(None)
    }
    /// Use the pages another reader of this thread already holds in memory
    /// for the same file (the same SHA-256 and length, which both readers
    /// authenticated), if there is one. Nothing is read and nothing more is
    /// reserved; the pages are given up for both readers at once. Returns
    /// whether the pages are in memory now. Never under the policy that
    /// reads everything again.
    pub fn share_resident_pages(&mut self) -> bool {
        if self.pages_resident() {
            return true;
        }
        if crate::verify_policy::full_unremembered() {
            return false;
        }
        let key = (self.algorithm, self.sha256, self.snapshot.bytes);
        let shared = RESIDENT.with(|resident| {
            let mut resident = resident.borrow_mut();
            let shared = resident.get(&key).and_then(|held| held.upgrade());
            if shared.is_none() {
                resident.remove(&key);
            }
            shared
        });
        match shared {
            Some(shared) => {
                self.resident = Some(shared);
                true
            }
            None => false,
        }
    }
    /// As [`Self::install_resident_pages`], with the reservation that pays
    /// for the pages. They are a cache: when the run's memory is short they
    /// are given up, `paid` with them ([`crate::evict`]), and the reader
    /// reads from its file again.
    pub fn install_resident_pages_paid(&mut self, paid: Box<dyn std::any::Any>) -> io::Result<()> {
        self.install_resident(Some(paid))
    }
    fn install_resident(&mut self, paid: Option<Box<dyn std::any::Any>>) -> io::Result<()> {
        require(
            !self.pages_resident(),
            "metadata pages are already resident",
        )?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(usize::try_from(self.pages).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        for page in 0..self.pages {
            let e = entry(&mut self.file, self.index, page)?;
            let mut body = Vec::new();
            body.try_reserve_exact(e.bytes as usize - FRAME as usize)
                .map_err(io::Error::other)?;
            let known_sum = self.known_sum(page);
            load_page(
                &mut self.file,
                e,
                self.budget,
                self.index,
                self.body_limit,
                &mut body,
                &mut self.statistics,
                known_sum,
                self.algorithm,
            )?;
            let mut starts = Vec::new();
            starts
                .try_reserve_exact(e.count as usize)
                .map_err(io::Error::other)?;
            let mut at = 0;
            for _ in 0..e.count {
                starts.push(u32::try_from(at).map_err(io::Error::other)?);
                at = record_at(&body, at)?.0;
            }
            require(at == body.len(), "resident metadata page length differs")?;
            pages.push(ResidentPage {
                first: e.first,
                starts,
                body,
            });
        }
        require(
            Snapshot::observe(&self.file)? == self.snapshot,
            "metadata file changed while its pages became resident",
        )?;
        let resident = crate::evict::Evictable::new(ResidentPages { pages, _paid: paid });
        RESIDENT.with(|shared| {
            let mut shared = shared.borrow_mut();
            // Entries whose pages are gone are dropped as the map doubles.
            if shared.len() >= 16 && shared.len().is_power_of_two() {
                shared.retain(|_, held| held.upgrade().is_some());
            }
            shared.insert(
                (self.algorithm, self.sha256, self.snapshot.bytes),
                resident.downgrade(),
            );
        });
        self.resident = Some(resident);
        Ok(())
    }
    /// This reader does not decide by itself to hold its whole file in
    /// memory, however it is read. For a file whose owner keeps what it
    /// reads from it: the walk's rows file, read back a block at a time,
    /// is several hundred megabytes for 100,000 objects, and held whole it
    /// took the memory of the stores the next steps look things up in (a
    /// volume of 100,000 files held to 1,240 MiB: 950 s where it takes
    /// 480 s) or, given up and held again in turns, was read over and
    /// over (800 GB of page loads in one run).
    pub fn read_page_by_page(&mut self) {
        self.page_by_page = true;
    }
    /// Whether this reader accepted the file as one this process wrote
    /// (check-once policy) instead of hashing and parsing all of it. A
    /// caller with a whole-content check of its own may then leave it out.
    /// Only a file a writer of this process produced: one this process has
    /// read completely before opens without being read again as well, but
    /// this is false for it, and its owner's own checks of its content are
    /// made.
    pub fn written_by_this_process(&self) -> bool {
        self.written_here
    }
    /// The checksum to check page `page` by, in place of its digest: only for
    /// a file this process wrote or read completely, and never inside a gate.
    fn known_sum(&self, page: u64) -> Option<PageSum> {
        if crate::verify_policy::full_unremembered() {
            return None;
        }
        let sum = *self.page_sums.as_ref()?.get(usize::try_from(page).ok()?)?;
        Some(PageSum {
            sum,
            written: self.page_sums_written,
        })
    }
    pub fn pages_resident(&self) -> bool {
        self.resident
            .as_ref()
            .is_some_and(crate::evict::Evictable::is_held)
    }
    pub fn len(&self) -> u64 {
        self.records
    }
    pub fn is_empty(&self) -> bool {
        self.records == 0
    }
    pub fn page_count(&self) -> u64 {
        self.pages
    }
    pub fn byte_len(&self) -> u64 {
        self.snapshot.bytes
    }
    /// Actual retained allocation, for the caller's prepaid bound check.
    pub fn body_capacity(&self) -> usize {
        self.body.capacity()
            + self
                .secondary
                .as_ref()
                .map_or(0, |page| page.body.capacity())
    }
    /// Opt in without allocating inside this generic reader. The caller must
    /// reserve the actual additional capacity before allocating this empty
    /// buffer, and retain that payment until this Reader has dropped. Ordinary
    /// open/open_held callers continue to retain exactly one page buffer.
    pub fn install_second_page_cache(&mut self, body: Vec<u8>) -> io::Result<()> {
        require(
            self.secondary.is_none() && body.is_empty() && body.capacity() == self.body_limit,
            "second metadata cache must be fresh and exactly bounded by the held file",
        )?;
        self.secondary = Some(CachedPage {
            entry: None,
            record: None,
            body,
            starts: Vec::new(),
        });
        Ok(())
    }
    pub fn page_cache_statistics(&self) -> PageCacheStatistics {
        self.statistics
    }
    /// Actual retained-handle route, for the caller's independent-volume gate.
    pub fn final_path(&self) -> &str {
        &self.snapshot.final_path
    }
    /// Compare complete native file identity and immutable metadata against an
    /// independently retained handle. No path or serialized pin is authority.
    pub fn same_file_as(&self, file: &File) -> io::Result<bool> {
        Ok(Snapshot::observe(file)? == self.snapshot)
    }
    pub fn get(&mut self, ordinal: u64) -> io::Result<Record> {
        self.with_record(ordinal, |key, payload| {
            Ok(Record {
                key: key.to_vec(),
                payload: payload.to_vec(),
            })
        })
    }
    /// Borrow one completely authenticated page record without allocating
    /// owned key/payload copies. The callback cannot retain page references
    /// beyond this mutable Reader borrow or bypass its index/cache checks.
    pub fn with_record<T>(
        &mut self,
        ordinal: u64,
        callback: impl FnOnce(&[u8], &[u8]) -> io::Result<T>,
    ) -> io::Result<T> {
        require(ordinal < self.records, "metadata ordinal is out of bounds")?;
        // Borrowed for the callback: the pages cannot be given up under it.
        if let Some(resident) = self.resident.as_ref().and_then(|resident| resident.get()) {
            let pages = &resident.pages;
            self.statistics.hits = self.statistics.hits.saturating_add(1);
            let page = pages
                .partition_point(|page| page.first <= ordinal)
                .checked_sub(1)
                .map(|index| &pages[index])
                .ok_or_else(|| io::Error::other("metadata indexed ordinal absent"))?;
            let start = usize::try_from(ordinal - page.first)
                .ok()
                .and_then(|record| page.starts.get(record))
                .ok_or_else(|| io::Error::other("metadata indexed ordinal has a gap"))?;
            let (_, key, payload) = record_at(&page.body, *start as usize)?;
            return callback(key, payload);
        }
        if self
            .cached
            .is_some_and(|e| ordinal >= e.first && ordinal - e.first < e.count as u64)
        {
            self.statistics.hits = self.statistics.hits.saturating_add(1);
        } else if self
            .secondary
            .as_ref()
            .and_then(|page| page.entry)
            .is_some_and(|e| ordinal >= e.first && ordinal - e.first < e.count as u64)
        {
            let secondary = self.secondary.as_mut().unwrap();
            std::mem::swap(&mut self.cached, &mut secondary.entry);
            std::mem::swap(&mut self.cached_record, &mut secondary.record);
            std::mem::swap(&mut self.body, &mut secondary.body);
            std::mem::swap(&mut self.starts, &mut secondary.starts);
            self.statistics.hits = self.statistics.hits.saturating_add(1);
        } else {
            self.statistics.misses = self.statistics.misses.saturating_add(1);
            // A reader that has had to load twice as many pages as its file
            // holds is being read in several passes or at random, and every
            // further miss costs a 4 MiB read and hash. Hold the whole file
            // from here on: one more pass over it, then no I/O at all.
            if crate::verify_policy::checks_once()
                && !self.page_by_page
                && self.snapshot.bytes <= AUTO_RESIDENT_FILE_BYTES
                && self.statistics.misses > self.pages.saturating_mul(2).max(8)
                && self.statistics.misses >= self.resident_asked_again_after
            {
                if self.share_resident_pages() {
                    return self.with_record(ordinal, callback);
                }
                // The run's ledger pays for it, and gets it back when memory
                // is short. A ledger with no room is asked again only after
                // as many misses again.
                match crate::evict::pay_for_cache(self.resident_page_bytes()?) {
                    crate::evict::CachePayment::Refused => {
                        self.resident_asked_again_after = self.statistics.misses.saturating_mul(2);
                    }
                    payment => {
                        self.install_resident(match payment {
                            crate::evict::CachePayment::Paid(paid) => Some(paid),
                            _ => None,
                        })?;
                        return self.with_record(ordinal, callback);
                    }
                }
            }
            let (mut low, mut high) = (0, self.pages);
            while low < high {
                let mid = low + (high - low) / 2;
                let e = entry(&mut self.file, self.index, mid)?;
                if e.first <= ordinal {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }
            require(low > 0, "metadata indexed ordinal absent")?;
            let e = entry(&mut self.file, self.index, low - 1)?;
            require(
                ordinal >= e.first && ordinal - e.first < e.count as u64,
                "metadata indexed ordinal has a gap",
            )?;
            // Evict the less recently used slot. Clear its advertised entry
            // before I/O so a failed load/hash can never expose overwritten
            // bytes under the previous page identity on a later request.
            if let Some(secondary) = &mut self.secondary {
                std::mem::swap(&mut self.cached, &mut secondary.entry);
                std::mem::swap(&mut self.cached_record, &mut secondary.record);
                std::mem::swap(&mut self.body, &mut secondary.body);
                std::mem::swap(&mut self.starts, &mut secondary.starts);
            }
            self.cached = None;
            self.cached_record = None;
            self.starts.clear();
            let known_sum = self.known_sum(low - 1);
            load_page(
                &mut self.file,
                e,
                self.budget,
                self.index,
                self.body_limit,
                &mut self.body,
                &mut self.statistics,
                known_sum,
                self.algorithm,
            )?;
            // Without its offsets the page is still read correctly, by
            // scanning; a malformed page is reported by that scan as before.
            if sparse_starts(&self.body, e.count, &mut self.starts).is_err() {
                self.starts.clear();
            }
            self.cached = Some(e);
            self.cached_record = None;
        }
        let e = self
            .cached
            .ok_or_else(|| io::Error::other("metadata page cache absent"))?;
        // Start from whichever known record is nearest before the one asked
        // for: the last one decoded, or the page's sparse offsets.
        let cursor = match self.cached_record {
            Some((previous, start, _)) if ordinal == previous => Some((previous, start)),
            Some((previous, _, end)) if ordinal > previous => Some((previous + 1, end)),
            _ => None,
        };
        let slot = (ordinal - e.first) / START_STRIDE;
        let indexed = usize::try_from(slot)
            .ok()
            .and_then(|slot| self.starts.get(slot))
            .map(|start| (e.first + slot * START_STRIDE, *start as usize));
        let (first, mut at) = match (cursor, indexed) {
            (Some(cursor), Some(indexed)) if cursor.0 >= indexed.0 => cursor,
            (_, Some(indexed)) => indexed,
            (Some(cursor), None) => cursor,
            (None, None) => (e.first, 0),
        };
        for current in first..=ordinal {
            let (end, key, payload) = record_at(&self.body, at)?;
            if current == ordinal {
                self.cached_record = Some((current, at, end));
                return callback(key, payload);
            }
            at = end;
        }
        Err(io::Error::other("metadata indexed record absent"))
    }
    pub fn revalidate(&mut self) -> io::Result<()> {
        // The whole file was hashed when this reader opened it, and every page
        // is hashed again as it is loaded. Unless a full check is due, confirm
        // that the held file still has the same identity, size and timestamp.
        if !crate::verify_policy::full(&self.last_full) {
            return require(
                Snapshot::observe(&self.file)? == self.snapshot,
                "held metadata identity changed",
            );
        }
        require(
            Snapshot::observe(&self.file)? == self.snapshot
                && file_hash(self.algorithm, &mut self.file, self.snapshot.bytes)? == self.sha256
                && Snapshot::observe(&self.file)? == self.snapshot,
            "held metadata identity or complete-file digest changed",
        )
    }
    pub fn copy_to(&mut self, destination: &Path) -> io::Result<()> {
        self.revalidate()?;
        ordinary(destination)?;
        let mut output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(destination)?;
        require(
            Snapshot::observe(&output)?.bytes == 0,
            "new empty metadata copy required",
        )?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut left = self.snapshot.bytes;
        let mut buffer = [0; 65536];
        let mut hash = bulk_digest::Hasher::new(self.algorithm)?;
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            self.file.read_exact(&mut buffer[..count])?;
            output.write_all(&buffer[..count])?;
            hash.update(&buffer[..count])?;
            left -= count as u64;
        }
        output.flush()?;
        output.sync_all()?;
        require(
            hash.finish()? == self.sha256
                && output.metadata()?.len() == self.snapshot.bytes
                && file_hash(self.algorithm, &mut output, self.snapshot.bytes)? == self.sha256
                && Snapshot::observe(&self.file)? == self.snapshot,
            "metadata copy/root pin differs",
        )
    }
}
