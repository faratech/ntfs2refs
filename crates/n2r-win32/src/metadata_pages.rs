//! Bounded, authenticated metadata records in one ordinary file. This is not
//! source, journal or execution authority. No raw handle or partial validation
//! result is exposed. Keys and JSON records are supplied by the typed caller.
//! Callers must separately exclude raw/admin aliases and surviving writable
//! mappings: ordinary file sharing alone cannot prove those writers absent.
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

pub const MAGIC: [u8; 8] = *b"N2RMPG01";
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
fn header(purpose: [u8; 8], b: PageBudget) -> [u8; 64] {
    let mut out = [0; 64];
    out[..8].copy_from_slice(&MAGIC);
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
fn file_hash(file: &mut File, bytes: u64) -> io::Result<[u8; 32]> {
    let _timed = crate::perf::scope(crate::perf::Point::FileHash);
    crate::perf::add_bytes(crate::perf::Point::FileHash, bytes);
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut left = bytes;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        left -= count as u64;
    }
    Ok(hash.finalize().into())
}
/// Files a [`Writer`] in this process finished: identity and final path, then
/// length, timestamp and the SHA-256 it computed.
type WrittenFiles = std::collections::HashMap<(String, String), (u64, SystemTime, [u8; 32])>;
static WRITTEN: std::sync::Mutex<Option<WrittenFiles>> = std::sync::Mutex::new(None);

fn note_written(snapshot: &Snapshot, sha256: [u8; 32]) {
    WRITTEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(WrittenFiles::new)
        .insert(
            (snapshot.id.clone(), snapshot.final_path.clone()),
            (snapshot.bytes, snapshot.modified, sha256),
        );
}

/// Whether this process wrote exactly this file, unchanged since, with this
/// SHA-256. Its writer refused any record that was not valid JSON under a
/// strictly increasing key and hashed every byte, so under the check-once
/// policy a reader need not hash and parse the whole file again to open it.
/// Each page is still hashed against the index whenever it is loaded. Inside
/// the gate before the first write to the source this is never true.
fn written_here(snapshot: &Snapshot, sha256: &[u8; 32]) -> bool {
    if crate::verify_policy::full_unremembered() {
        return false;
    }
    WRITTEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .and_then(|written| written.get(&(snapshot.id.clone(), snapshot.final_path.clone())))
        .is_some_and(|(bytes, modified, known)| {
            *bytes == snapshot.bytes && *modified == snapshot.modified && known == sha256
        })
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
    // Every byte in file order as it is written: the complete-file SHA-256.
    hash: Sha256,
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
        file.write_all(&header(purpose, budget))?;
        let mut hash = Sha256::new();
        hash.update(header(purpose, budget));
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
            hash,
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
        frame[32..].copy_from_slice(&Sha256::digest(&self.body));
        self.file.seek(SeekFrom::Start(self.data_end))?;
        self.file.write_all(&frame)?;
        self.file.write_all(&self.body)?;
        self.hash.update(frame);
        self.hash.update(&self.body);
        self.data_end = next;
        self.pages += 1;
        self.pending = 0;
        self.body.clear();
        Ok(())
    }
    pub fn finish(mut self) -> io::Result<Summary> {
        require(!self.poisoned, "metadata writer is poisoned")?;
        self.flush_page()?;
        let bytes = projected(self.data_end, self.pages, self.budget)?;
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
            self.hash.update(frame);
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
        footer[80..112].copy_from_slice(&Sha256::digest(header(self.purpose, self.budget)));
        self.file.seek(SeekFrom::Start(bytes - FOOTER))?;
        self.file.write_all(&footer)?;
        self.hash.update(footer);
        self.file.flush()?;
        crate::verify_policy::flush_working_file(&self.file)?;
        let before = Snapshot::observe(&self.file)?;
        require(
            before.bytes == bytes,
            "metadata completed file length differs",
        )?;
        // The file is written front to back, so its SHA-256 is known from the
        // bytes handed to it. Reading it all back to hash it again is left out
        // under the check-once policy.
        let written: [u8; 32] = std::mem::take(&mut self.hash).finalize().into();
        if !crate::verify_policy::checks_once() {
            require(
                file_hash(&mut self.file, bytes)? == written,
                "metadata file differs from the bytes written to it",
            )?;
        }
        require(
            Snapshot::observe(&self.file)? == before,
            "metadata file changed while finishing",
        )?;
        note_written(&before, written);
        let sha256 = hex::encode(written);
        Ok(Summary {
            sha256,
            records: self.records,
            pages: self.pages,
            bytes,
        })
    }
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
    statistics.page_hash_bytes = statistics.page_hash_bytes.saturating_add(body.len() as u64);
    require(
        Sha256::digest(&*body).as_slice() == e.sha,
        "metadata page SHA differs",
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
    Ok(magic == MAGIC)
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
    body_limit: usize,
    // Optional second authenticated page, supplied by an explicitly prepaid
    // caller. The primary slot is most recently used; swaps retain each page's
    // own record cursor and never share buffers across Reader/file ownership.
    secondary: Option<CachedPage>,
    // Every authenticated page, with each record's start offset. When present,
    // lookups do no file I/O, no re-hash and no in-page scan.
    resident: Option<Vec<ResidentPage>>,
    statistics: PageCacheStatistics,
}

struct ResidentPage {
    first: u64,
    starts: Vec<u32>,
    body: Vec<u8>,
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
        let written_here = written_here(&snapshot, &sha256);
        if !written_here {
            require(
                file_hash(&mut file, snapshot.bytes)? == sha256,
                "metadata complete-file SHA differs",
            )?;
        }
        let mut actual_header = [0; 64];
        read_at(&mut file, 0, &mut actual_header)?;
        require(
            actual_header == header(purpose, budget),
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
            if written_here {
                // The index, checked against the footer above, is walked for
                // gaps; the pages it names are hashed when they are loaded.
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
            cursor = add(cursor, e.bytes as u64)?;
            count = add(count, e.count as u64)?;
            require(count <= records, "metadata page records exceed footer")?;
            cached = Some(e);
        }
        require(
            cursor == index && count == records && Snapshot::observe(&file)? == snapshot,
            "metadata full validation did not cover the immutable file",
        )?;
        Ok(Self {
            file,
            snapshot,
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
            body_limit,
            secondary: None,
            resident: None,
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
        require(self.resident.is_none(), "metadata pages are already resident")?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(usize::try_from(self.pages).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        for page in 0..self.pages {
            let e = entry(&mut self.file, self.index, page)?;
            let mut body = Vec::new();
            body.try_reserve_exact(e.bytes as usize - FRAME as usize)
                .map_err(io::Error::other)?;
            load_page(
                &mut self.file,
                e,
                self.budget,
                self.index,
                self.body_limit,
                &mut body,
                &mut self.statistics,
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
        self.resident = Some(pages);
        Ok(())
    }
    pub fn pages_resident(&self) -> bool {
        self.resident.is_some()
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
            + self.secondary.as_ref().map_or(0, |page| page.body.capacity())
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
        if let Some(pages) = &self.resident {
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
                && self.snapshot.bytes <= AUTO_RESIDENT_FILE_BYTES
                && self.statistics.misses > self.pages.saturating_mul(2).max(8)
            {
                self.install_resident_pages()?;
                return self.with_record(ordinal, callback);
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
            load_page(
                &mut self.file,
                e,
                self.budget,
                self.index,
                self.body_limit,
                &mut self.body,
                &mut self.statistics,
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
                && file_hash(&mut self.file, self.snapshot.bytes)? == self.sha256
                && Snapshot::observe(&self.file)? == self.snapshot,
            "held metadata identity or complete-file SHA changed",
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
        let mut hash = Sha256::new();
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            self.file.read_exact(&mut buffer[..count])?;
            output.write_all(&buffer[..count])?;
            hash.update(&buffer[..count]);
            left -= count as u64;
        }
        output.flush()?;
        output.sync_all()?;
        require(
            hash.finalize().as_slice() == self.sha256
                && output.metadata()?.len() == self.snapshot.bytes
                && file_hash(&mut output, self.snapshot.bytes)? == self.sha256
                && Snapshot::observe(&self.file)? == self.snapshot,
            "metadata copy/root pin differs",
        )
    }
}
