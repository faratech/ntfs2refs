//! Immutable authenticated pages for the legacy ExpectedTree semantic domain.
//! File and semantic pins are facts, never source, journal or replay authority.
use super::{ExpectedObjectDomain, ExpectedTree, Object};
use anyhow::{Context, Result, ensure};
use n2r_win32::metadata_pages::{PageBudget, Reader, Writer};
use serde::{
    Deserialize, Serialize, Serializer,
    ser::{Error as _, SerializeSeq, SerializeStruct},
};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

const PURPOSE: [u8; 8] = *b"N2REXP01";

/// Authenticated data binding only. It cannot recreate the live source proof
/// which authorized its producer, or issue source/journal/write authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedBindingFacts {
    pub schema_version: u32,
    pub verification_kind: String,
    pub body_file_sha256: String,
    pub body_semantic_sha256: String,
    pub original_admission: n2r_win32::tree_resources::SourceResourceAdmission,
    pub effective_admission: n2r_win32::tree_resources::SourceResourceAdmission,
    pub profile: String,
    pub logical_bytes: u64,
    pub objects: u64,
    pub pending_roles: Vec<String>,
    pub native_file_sha256: String,
    pub user_join_sha256: String,
}
impl ExpectedBindingFacts {
    pub(crate) fn validate(
        &self,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        file_sha: &str,
        semantic_sha: &str,
    ) -> Result<()> {
        self.original_admission.validate()?;
        admission.validate()?;
        let mut rebound = self.original_admission;
        rebound.source_inspection_sha256 = admission.source_inspection_sha256;
        ensure!(
            self.schema_version == 1
                && matches!(
                    self.verification_kind.as_str(),
                    "strict-user-refresh-and-current-projection-v1"
                        | "exact-current-source-and-current-projection-v1"
                )
                && self.original_admission.schema_version == 2
                && rebound == admission
                && self.effective_admission == admission
                && self.body_file_sha256 == file_sha
                && self.body_semantic_sha256 == semantic_sha
                && canonical_sha(file_sha)
                && canonical_sha(semantic_sha)
                && canonical_sha(&self.native_file_sha256)
                && canonical_sha(&self.user_join_sha256)
                && self.profile == "native-ordinary-tree-shadow-resource-bounded-v4"
                && self.objects == admission.objects()?
                && serde_json::to_vec(self)?.len() <= 65536,
            "cached expected body binding differs from its exact data/resource contract"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedBindingPin {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub facts: ExpectedBindingFacts,
}

/// Record zero contains only the non-object fields and the complete domain size.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedTreePageHeader {
    pub schema_version: u32,
    pub profile: String,
    pub logical_bytes: u64,
    pub internal_replacement_pending: Vec<String>,
    pub total_objects: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
}

#[derive(Serialize)]
struct HeaderRef<'a> {
    schema_version: u32,
    profile: &'a str,
    logical_bytes: u64,
    internal_replacement_pending: &'a [String],
    total_objects: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ExpectedTreePageCounts {
    pub objects: u64,
    pub files: u64,
    pub directories: u64,
    pub data_streams: u64,
}

impl ExpectedTreePageCounts {
    fn include(&mut self, object: &Object) -> Result<()> {
        self.objects = self
            .objects
            .checked_add(1)
            .context("paged object count overflow")?;
        let target = if object.directory {
            &mut self.directories
        } else {
            &mut self.files
        };
        *target = target
            .checked_add(1)
            .context("paged file/directory count overflow")?;
        self.data_streams = self
            .data_streams
            .checked_add(u64::try_from(object.data_streams().count())?)
            .context("paged DATA-stream count overflow")?;
        Ok(())
    }
}

/// This receipt is descriptive. Opening still requires independently pinned
/// file and legacy-semantic hashes and complete validation of the actual
/// file, except the opening of the pages this process has just written in
/// a run that verifies once, which takes what their creation derived and
/// checked of them instead of the pass over every object (see
/// [`CreatedHere`]).
#[derive(Clone, Debug, Serialize)]
pub struct ExpectedTreePageReceipt {
    pub schema_version: u32,
    pub path: PathBuf,
    pub file_sha256: String,
    pub semantic_sha256: String,
    pub objects: u64,
    pub records: u64,
    pub pages: u64,
    pub bytes: u64,
    pub page_budget: PageBudget,
    pub semantic_byte_budget: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    // What the creation computed of the pages, in memory only: never
    // serialized, and made by nothing but the creation itself.
    #[serde(skip)]
    created: Option<CreatedHere>,
}

/// What this process's creation of a tree's pages derived and checked of
/// them, while it wrote them: the digest of the tree's legacy JSON and the
/// counts of its objects, of the file it wrote, under the budgets it wrote
/// it to, and whether it decoded every object back from the chunks it had
/// just written ([`DecodeBack`]).
///
/// The opening of a tree's pages checks, of every object: that its chunks
/// are complete, ordered and within the budgets (the directory it builds,
/// always), that they decode to an object within the row budget, and that
/// the objects reproduce the pinned legacy JSON's digest and counts (its
/// pass over every object).
///
/// Opening that file again in a run that verifies once
/// ([`n2r_win32::verify_policy::verifies_once`]) leaves its pass over every
/// object out, and takes the digest and the counts from here, only where
/// the creation decoded every object back: the decoding was then made at
/// the creation, with the opening's decoder, and each object held equal to
/// the one written, which is the one the digest and the counts are of. The
/// reader accepts the file only as the one this process's writer produced
/// ([`n2r_win32::metadata_pages::Reader::written_by_this_process`]), held
/// since and checked page by page as it is read, so those were the same
/// bytes. The directory is still built and checked by the opening. Every
/// other opening (a thorough run, a cached body, a rebind, a recovery, a
/// resume, any file this process did not write or did not decode back)
/// makes its pass over every object, as it always has.
#[derive(Clone, Debug)]
struct CreatedHere {
    file_sha256: String,
    semantic_sha256: String,
    counts: ExpectedTreePageCounts,
    budget: PageBudget,
    semantic_byte_budget: u64,
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    decoded_back: bool,
}

pub struct PagedExpectedTree {
    reader: RefCell<Reader>,
    alias_projection: RefCell<Option<AliasProjection>>,
    alias_projection_lookups: Cell<u64>,
    // The digest of every object's native input; this tree never changes.
    input_digest: n2r_win32::shadow_native::input_domain::InputDigestMemo,
    // Objects already decoded from it, while the arena can spare the memory.
    decoded: std::rc::Rc<DecodedCache>,
    header: ExpectedTreePageHeader,
    counts: ExpectedTreePageCounts,
    file_sha256: String,
    semantic_sha256: String,
    budget: PageBudget,
    semantic_byte_budget: u64,
    directory: Vec<ObjectEntry>,
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    binding: Option<ExpectedBindingPin>,
    _binding_artifact: Option<crate::artifact_arena::ArtifactLease>,
    live_rebind_source: Option<usize>,
    cached_body_pending: bool,
    _binding_ram: Option<crate::artifact_arena::ArenaRamLease>,
    arena: Option<crate::artifact_arena::ArtifactArena>,
    _artifact: Option<crate::artifact_arena::ArtifactLease>,
    // A reopened expected domain retains the already authenticated read-only
    // file, but never gains a fresh-created ArtifactLease/source authority.
    _reopened_file: Option<File>,
    _reopened_binding: Option<(
        File,
        n2r_win32::reference_file::ReferenceFileSnapshot,
        std::time::SystemTime,
    )>,
    _reader_ram: Option<crate::artifact_arena::ArenaRamLease>,
    // This separate payment is acquired before allocating the optional second
    // authenticated page and outlives the Reader that retains its buffer.
    _second_page_ram: Option<crate::artifact_arena::ArenaRamLease>,
    _directory_ram: Option<crate::artifact_arena::ArenaRamLease>,
    _header_ram: Option<crate::artifact_arena::ArenaRamLease>,
}

/// The objects a tree has decoded so far, by ordinal.
///
/// Every pass over the volume asks the tree for every object, and each
/// answer was read from its page, taken out of base64 and parsed from JSON
/// again: about 0.2 ms an object, 28 s a pass on the full Windows volume and
/// a hundred seconds before the journal was even started. The tree cannot
/// change while it is open and its pages are checked as they are loaded, so
/// an object decoded once is kept and handed out as a copy. The memory is
/// optional (see `ArtifactArena::reserve_optional_ram`), paid for a block at
/// a time; when the arena refuses a block, what is kept stays, the rest are
/// decoded as before, and a block is asked for again a few thousand objects
/// later, when a stage's own reservations may have been returned. Inside the
/// gate before the first write to the source, and without the check-once
/// policy, nothing is served from here.
#[derive(Default)]
struct DecodedObjects {
    rows: Vec<Option<Arc<Object>>>,
    leases: Vec<crate::artifact_arena::ArenaRamLease>,
    unspent: u64,
    // Objects still to pass by before the arena is asked again.
    refused_for: u32,
}
/// The decoded objects as a cache of the run: given up, with the blocks
/// that pay for them, when memory is short ([`n2r_win32::evict`]).
struct DecodedCache(RefCell<DecodedObjects>, std::cell::Cell<u64>);
impl n2r_win32::evict::Evict for DecodedCache {
    fn last_used(&self) -> u64 {
        self.1.get()
    }
    fn evict(&self) -> bool {
        // Borrowed means in use at this moment: left alone. What is taken
        // is dropped after the borrow has ended, the objects before the
        // blocks that paid for them.
        let taken = match self.0.try_borrow_mut() {
            Ok(mut decoded) if !decoded.leases.is_empty() => {
                decoded.unspent = 0;
                // Memory was short: not asked for again at once.
                decoded.refused_for = DECODED_RETRY_OBJECTS;
                Some((
                    std::mem::take(&mut decoded.rows),
                    std::mem::take(&mut decoded.leases),
                ))
            }
            _ => None,
        };
        taken.is_some()
    }
}
impl DecodedCache {
    /// An empty cache, registered as a cache of this thread.
    fn registered() -> std::rc::Rc<Self> {
        let decoded = std::rc::Rc::new(Self(
            RefCell::new(DecodedObjects::default()),
            std::cell::Cell::new(n2r_win32::evict::now()),
        ));
        n2r_win32::evict::register(&decoded);
        decoded
    }
    /// Keeps `object`, object `index` of a tree of `len` objects, where the
    /// arena can spare the memory for it (see [`DecodedObjects`]).
    fn keep(
        &self,
        arena: &crate::artifact_arena::ArtifactArena,
        row_limit: u64,
        len: usize,
        index: usize,
        object: &Arc<Object>,
    ) {
        self.1.set(n2r_win32::evict::now());
        let mut decoded = self.0.borrow_mut();
        if decoded.rows.get(index).is_some_and(Option::is_some) {
            return;
        }
        if decoded.refused_for > 0 {
            decoded.refused_for -= 1;
            return;
        }
        let Ok(mut bytes) = object_memory_bytes(object, 0, row_limit) else {
            return;
        };
        let slots = decoded.rows.is_empty();
        if slots {
            bytes = bytes.saturating_add((len * std::mem::size_of::<Option<Arc<Object>>>()) as u64);
        }
        if decoded.unspent < bytes {
            let block = DECODED_BLOCK_BYTES.max(bytes);
            match arena.reserve_optional_ram(block) {
                Ok(lease) => {
                    decoded.leases.push(lease);
                    decoded.unspent += block;
                }
                Err(_) => {
                    decoded.refused_for = DECODED_RETRY_OBJECTS;
                    return;
                }
            }
        }
        if slots {
            if decoded.rows.try_reserve_exact(len).is_err() {
                decoded.refused_for = DECODED_RETRY_OBJECTS;
                return;
            }
            decoded.rows.resize_with(len, || None);
        }
        decoded.unspent -= bytes;
        decoded.rows[index] = Some(Arc::clone(object));
    }
}
const DECODED_BLOCK_BYTES: u64 = 16 * 1024 * 1024;
const DECODED_RETRY_OBJECTS: u32 = 4096;

struct ExpectedMemoryOwner {
    arena: crate::artifact_arena::ArtifactArena,
    artifact: Option<crate::artifact_arena::ArtifactLease>,
    reopened: Option<File>,
}

/// Beside eight times an object's compact bytes: what the decoded structure
/// of the smallest object takes, three times over (see `object_leased`).
const DECODED_OBJECT_ALLOWANCE: u64 = 64 * 1024;

/// One decoded object keeps its actual shared-memory lease through all native
/// views/caches. It has no Clone or Deserialize implementation.
pub struct LeasedExpectedObject {
    object: Arc<Object>,
    _ram: crate::artifact_arena::ArenaRamLease,
    // What the object holds beyond what was reserved to decode it.
    _more: Option<crate::artifact_arena::ArenaRamLease>,
}
impl std::ops::Deref for LeasedExpectedObject {
    type Target = Object;
    fn deref(&self) -> &Object {
        &self.object
    }
}

#[derive(Clone, Copy)]
struct ObjectEntry {
    start: u64,
    chunks: u64,
    bytes: u64,
}

/// Private runtime projection of this exact held Expected owner. Paths use
/// compact length framing instead of retaining a Vec/String allocation for
/// every component. No serialized receipt can construct this projection.
struct AliasProjectionRow {
    paths: Vec<u8>,
    directory: bool,
    is_reparse: bool,
    _ram: crate::artifact_arena::ArenaRamLease,
}
struct AliasProjection {
    rows: Vec<AliasProjectionRow>,
    path_bytes: u64,
    _ram: crate::artifact_arena::ArenaRamLease,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct AliasProjectionStatistics {
    pub objects: u64,
    pub encoded_path_bytes: u64,
    pub lookups: u64,
}

fn alias_path_bytes(object: &Object) -> Result<usize> {
    std::iter::once(&object.path)
        .chain(&object.additional_names)
        .try_fold(8usize, |bytes, path| {
            path.iter().try_fold(
                bytes
                    .checked_add(8)
                    .context("alias path framing overflow")?,
                |bytes, part| {
                    bytes
                        .checked_add(8)
                        .and_then(|n| n.checked_add(part.len()))
                        .context("alias component framing overflow")
                },
            )
        })
}
fn alias_take<'a>(bytes: &mut &'a [u8], length: usize) -> io::Result<&'a [u8]> {
    if length > bytes.len() {
        return Err(io::Error::other("held alias projection frame differs"));
    }
    let (value, rest) = bytes.split_at(length);
    *bytes = rest;
    Ok(value)
}
fn alias_number(bytes: &mut &[u8]) -> io::Result<usize> {
    let raw: [u8; 8] = alias_take(bytes, 8)?.try_into().map_err(io::Error::other)?;
    usize::try_from(u64::from_le_bytes(raw)).map_err(io::Error::other)
}
fn alias_path_matches(bytes: &mut &[u8], expected: &[String]) -> io::Result<bool> {
    let parts = alias_number(bytes)?;
    if parts > bytes.len() / 8 {
        return Err(io::Error::other("held alias component count differs"));
    }
    let mut matched = parts == expected.len();
    for ordinal in 0..parts {
        let length = alias_number(bytes)?;
        let part = alias_take(bytes, length)?;
        matched &= expected
            .get(ordinal)
            .is_some_and(|wanted| wanted.as_bytes() == part);
    }
    Ok(matched)
}
impl n2r_win32::shadow_native::input_domain::AliasObjectShape for AliasProjectionRow {
    fn directory(&self) -> bool {
        self.directory
    }
    fn is_reparse(&self) -> bool {
        self.is_reparse
    }
    fn primary_path_matches(&self, path: &[String]) -> io::Result<bool> {
        let mut bytes = self.paths.as_slice();
        if alias_number(&mut bytes)? == 0 {
            return Err(io::Error::other("held alias primary path absent"));
        }
        alias_path_matches(&mut bytes, path)
    }
    fn contains_path(&self, path: &[String]) -> io::Result<bool> {
        let mut bytes = self.paths.as_slice();
        let paths = alias_number(&mut bytes)?;
        if paths == 0 || paths > bytes.len() / 8 {
            return Err(io::Error::other("held alias path count differs"));
        }
        let mut found = false;
        for _ in 0..paths {
            found |= alias_path_matches(&mut bytes, path)?;
        }
        if !bytes.is_empty() {
            return Err(io::Error::other("held alias projection has trailing bytes"));
        }
        Ok(found)
    }
}

fn chunk_bytes(budget: PageBudget) -> Result<usize> {
    budget.validate()?;
    let available = budget
        .max_page_bytes
        .checked_sub(90)
        .context("expected page cannot contain a chunk")?;
    let maximum = ((available / 4) * 3).min(768 * 1024) as usize;
    ensure!(maximum != 0, "expected page cannot contain a chunk");
    Ok(maximum)
}

/// The caller's file ceiling remains the exact legacy semantic JSON ceiling.
/// Wire framing/base64 are separately derived and do not consume that budget.
fn wire_budget(budget: PageBudget) -> Result<PageBudget> {
    let chunk = chunk_bytes(budget)? as u64;
    let extra = budget
        .max_file_bytes
        .checked_div(chunk)
        .and_then(|n| n.checked_add(1))
        .context("chunk count overflow")?;
    let records = budget
        .max_records
        .checked_add(extra)
        .context("wire record budget overflow")?;
    let pages = budget
        .max_pages
        .checked_add(extra)
        .context("wire page budget overflow")?;
    let bytes = budget
        .max_file_bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .map(|n| n / 3)
        .and_then(|n| records.checked_mul(32).and_then(|r| n.checked_add(r)))
        .and_then(|n| pages.checked_mul(128).and_then(|r| n.checked_add(r)))
        .and_then(|n| n.checked_add(u64::from(budget.max_page_bytes)))
        .and_then(|n| n.checked_add(192))
        .context("wire byte budget overflow")?;
    let wire = PageBudget {
        max_records: records,
        max_pages: pages,
        max_file_bytes: bytes,
        ..budget
    };
    wire.validate()?;
    Ok(wire)
}

fn decode_chunk(value: &[u8], maximum: usize) -> Result<Vec<u8>> {
    if let Some((&0u8, raw)) = value.split_first() {
        ensure!(
            !raw.is_empty() && raw.len() <= maximum,
            "decoded object chunk exceeds bound"
        );
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(raw.len())?;
        bytes.extend_from_slice(raw);
        return Ok(bytes);
    }
    let value: &str = serde_json::from_slice(value)?;
    let input = value.as_bytes();
    ensure!(input.len().is_multiple_of(4), "chunk base64 length differs");
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    ensure!(padding <= 2, "chunk base64 padding differs");
    let length = input
        .len()
        .checked_div(4)
        .and_then(|n| n.checked_mul(3))
        .and_then(|n| n.checked_sub(padding))
        .context("chunk length overflow")?;
    ensure!(
        length > 0 && length <= maximum,
        "decoded object chunk exceeds bound"
    );
    let digit = |b: u8| -> Result<u8> {
        Ok(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => anyhow::bail!("noncanonical chunk base64 alphabet"),
        })
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    // Every group but the last is four alphabet characters; only the last
    // may be padded and takes the checked path below.
    let complete = input.len() / 4 - 1;
    ensure!(
        crate::ntfs_inspect::paged_storage::decode_base64_groups(
            &input[..complete * 4],
            &mut bytes
        ),
        "noncanonical chunk base64 alphabet"
    );
    for (index, c) in input.chunks_exact(4).enumerate().skip(complete) {
        let last = index + 1 == input.len() / 4;
        let a = digit(c[0])?;
        let b = digit(c[1])?;
        bytes.push((a << 2) | (b >> 4));
        if c[2] == b'=' {
            ensure!(
                last && c[3] == b'=' && b & 15 == 0,
                "noncanonical chunk padding bits"
            );
        } else {
            let d = digit(c[2])?;
            bytes.push((b << 4) | (d >> 2));
            if c[3] == b'=' {
                ensure!(last && d & 3 == 0, "noncanonical chunk padding bits");
            } else {
                bytes.push((d << 6) | digit(c[3])?);
            }
        }
    }
    ensure!(bytes.len() == length, "decoded chunk length differs");
    Ok(bytes)
}
fn object_key(object: u64, chunk: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&object.to_be_bytes());
    key[8..].copy_from_slice(&chunk.to_be_bytes());
    key
}

struct ChunkWriter<'a> {
    writer: &'a mut Writer,
    object: u64,
    chunks: u64,
    bytes: u64,
    maximum: u64,
    buffer: Vec<u8>,
    chunk_bytes: usize,
    // The payloads written, where the object is decoded back from them.
    kept: Option<Vec<Vec<u8>>>,
}
impl ChunkWriter<'_> {
    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let payload = crate::ntfs_inspect::paged_storage::encode_raw_chunk(&self.buffer)
            .map_err(io::Error::other)?;
        self.writer
            .push(&object_key(self.object, self.chunks), &payload)?;
        if let Some(kept) = &mut self.kept {
            kept.try_reserve(1).map_err(io::Error::other)?;
            kept.push(payload);
        }
        self.chunks = self
            .chunks
            .checked_add(1)
            .ok_or_else(|| io::Error::other("object chunk ordinal overflow"))?;
        self.buffer.clear();
        Ok(())
    }
    /// The payloads written, where they were kept.
    fn finish(mut self) -> io::Result<Option<Vec<Vec<u8>>>> {
        self.flush_chunk()?;
        if self.chunks == 0 {
            return Err(io::Error::other("empty object JSON"));
        }
        Ok(self.kept.take())
    }
}
impl Write for ChunkWriter<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len();
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("object JSON exceeds legacy semantic budget"))?;
        while !bytes.is_empty() {
            let n = bytes.len().min(self.chunk_bytes - self.buffer.len());
            let required = self.buffer.len() + n;
            if required > self.buffer.capacity() {
                let capacity = self
                    .buffer
                    .capacity()
                    .max(128)
                    .saturating_mul(2)
                    .min(self.chunk_bytes)
                    .max(required);
                self.buffer
                    .try_reserve_exact(capacity - self.buffer.len())
                    .map_err(io::Error::other)?;
            }
            self.buffer.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.buffer.len() == self.chunk_bytes {
                self.flush_chunk()?;
            }
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct ChunkReader<'a> {
    tree: &'a PagedExpectedTree,
    object: u64,
    entry: ObjectEntry,
    next: u64,
    loaded: u64,
    buffer: Vec<u8>,
    position: usize,
}
impl Read for ChunkReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.position == self.buffer.len() {
            if self.next == self.entry.chunks {
                if self.loaded != self.entry.bytes {
                    return Err(io::Error::other("complete object chunk byte count differs"));
                }
                return Ok(0);
            }
            let entry = self
                .tree
                .reader
                .borrow_mut()
                .get(self.entry.start + self.next)?;
            if entry.key.as_slice() != object_key(self.object, self.next) {
                return Err(io::Error::other("object chunk ordinal key differs"));
            }
            self.buffer = decode_chunk(
                &entry.payload,
                chunk_bytes(self.tree.budget).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            self.loaded = self
                .loaded
                .checked_add(self.buffer.len() as u64)
                .filter(|n| *n <= self.entry.bytes)
                .ok_or_else(|| io::Error::other("object chunk bytes exceed directory"))?;
            self.position = 0;
            self.next += 1;
        }
        let n = output.len().min(self.buffer.len() - self.position);
        output[..n].copy_from_slice(&self.buffer[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}

struct BoundedRecord {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for BoundedRecord {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("expected-tree record exceeds page budget"))?;
        if required > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .max(128)
                .saturating_mul(2)
                .min(self.maximum)
                .max(required);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn record(value: &impl Serialize, budget: PageBudget) -> Result<Vec<u8>> {
    // The writer separately enforces framing/key overhead. This bounds the
    // temporary serialization before allocating or handing it to the writer.
    let mut output = BoundedRecord {
        bytes: Vec::new(),
        maximum: budget.max_page_bytes as usize,
    };
    serde_json::to_writer(&mut output, value)?;
    Ok(output.bytes)
}

/// The digest of the expected tree's legacy JSON. The JSON writer hands it
/// over a token at a time; blocks of 64 KiB are hashed on a background worker
/// thread (overlapping the 1.5 GB SHA-256 with JSON formatting and page writes).
struct SemanticHash {
    sender: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    recycle: std::sync::mpsc::Receiver<Vec<u8>>,
    worker: Option<std::thread::JoinHandle<Result<[u8; 32]>>>,
    pending: Vec<u8>,
    bytes: u64,
    maximum: u64,
}
impl SemanticHash {
    const BLOCK: usize = 64 * 1024;
    const SLOTS: usize = 8;
    fn new(maximum: u64) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(Self::SLOTS);
        let (rtx, rrx) = std::sync::mpsc::sync_channel::<Vec<u8>>(Self::SLOTS);
        for _ in 0..Self::SLOTS {
            let mut buf = Vec::new();
            buf.try_reserve_exact(Self::BLOCK)?;
            let _ = rtx.send(buf);
        }
        let worker = std::thread::Builder::new()
            .name("expected-semantic-sha256".into())
            .spawn(move || -> Result<[u8; 32]> {
                let mut sha256 =
                    crate::retained_compare::stream_digest::StreamDigest::new(cfg!(windows))?;
                for mut block in rx {
                    sha256.update(&block)?;
                    block.clear();
                    let _ = rtx.send(block);
                }
                sha256.finish()
            })
            .context("spawning expected-tree semantic SHA-256 worker")?;
        let mut pending = Vec::new();
        pending.try_reserve_exact(Self::BLOCK)?;
        Ok(Self {
            sender: Some(tx),
            recycle: rrx,
            worker: Some(worker),
            pending,
            bytes: 0,
            maximum,
        })
    }
    fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let next_buf = self
            .recycle
            .recv()
            .map_err(|_| io::Error::other("expected-tree semantic SHA-256 worker stopped"))?;
        let full = std::mem::replace(&mut self.pending, next_buf);
        self.sender
            .as_ref()
            .ok_or_else(|| io::Error::other("expected-tree semantic SHA-256 channel closed"))?
            .send(full)
            .map_err(|_| io::Error::other("expected-tree semantic SHA-256 worker stopped"))
    }
    fn finish(mut self) -> Result<String> {
        self.flush_pending()?;
        self.sender.take();
        let digest = self
            .worker
            .take()
            .context("expected-tree semantic SHA-256 worker absent")?
            .join()
            .map_err(|_| anyhow::anyhow!("expected-tree semantic SHA-256 worker panicked"))??;
        Ok(hex::encode(digest))
    }
}
impl Drop for SemanticHash {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Write for SemanticHash {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let total = bytes.len();
        let next = self
            .bytes
            .checked_add(total as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| {
                io::Error::other("legacy expected-tree JSON exceeds pinned byte budget")
            })?;
        while !bytes.is_empty() {
            let room = Self::BLOCK - self.pending.len();
            if room == 0 {
                self.flush_pending()?;
                continue;
            }
            let take = bytes.len().min(room);
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        self.bytes = next;
        Ok(total)
    }
    // The JSON writer hands its text over in pieces of a few bytes, several
    // for each element of a byte array. A piece that fits in the pending
    // block, within the budget, is copied there at once; any other goes
    // through `write`, which takes all of it or refuses it.
    #[inline]
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() <= Self::BLOCK - self.pending.len()
            && let Some(next) = self
                .bytes
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= self.maximum)
        {
            self.pending.extend_from_slice(bytes);
            self.bytes = next;
            return Ok(());
        }
        self.write(bytes).map(|_| ())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The legacy JSON of `value`, as `serde_json::to_writer_pretty` writes it,
/// into `output`.
fn write_legacy_json(
    output: impl io::Write,
    value: &(impl Serialize + ?Sized),
) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        output,
        LegacyPretty::default(),
    ))
}

/// serde_json's `PrettyFormatter` with its two-space indentation, method for
/// method, writing each line break together with the indentation that
/// follows it, instead of the break and then each level's two spaces by
/// itself. The bytes are the same; the legacy JSON of an expected tree is
/// mostly byte arrays, one element a line, and this is a third of the
/// pieces handed to its digest.
#[derive(Default)]
struct LegacyPretty {
    current_indent: usize,
    has_value: bool,
}
impl LegacyPretty {
    /// Levels whose indentation is written in one piece with the break;
    /// deeper ones (an expected tree has fewer than ten) a level at a time.
    const LEVELS: usize = 32;
    /// A comma, a line break, and the indentation of `LEVELS` levels.
    const BREAKS: [u8; 2 + 2 * Self::LEVELS] = {
        let mut breaks = [b' '; 2 + 2 * Self::LEVELS];
        breaks[0] = b',';
        breaks[1] = b'\n';
        breaks
    };
    fn line<W: ?Sized + io::Write>(&self, writer: &mut W, comma: bool) -> io::Result<()> {
        let from = usize::from(!comma);
        let levels = self.current_indent.min(Self::LEVELS);
        writer.write_all(&Self::BREAKS[from..2 + 2 * levels])?;
        for _ in levels..self.current_indent {
            writer.write_all(b"  ")?;
        }
        Ok(())
    }
}
impl serde_json::ser::Formatter for LegacyPretty {
    #[inline]
    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.current_indent += 1;
        self.has_value = false;
        writer.write_all(b"[")
    }
    #[inline]
    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.current_indent -= 1;
        if self.has_value {
            self.line(writer, false)?;
        }
        writer.write_all(b"]")
    }
    #[inline]
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.line(writer, !first)
    }
    #[inline]
    fn end_array_value<W: ?Sized + io::Write>(&mut self, _writer: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }
    #[inline]
    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.current_indent += 1;
        self.has_value = false;
        writer.write_all(b"{")
    }
    #[inline]
    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.current_indent -= 1;
        if self.has_value {
            self.line(writer, false)?;
        }
        writer.write_all(b"}")
    }
    #[inline]
    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.line(writer, !first)
    }
    #[inline]
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }
    #[inline]
    fn end_object_value<W: ?Sized + io::Write>(&mut self, _writer: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }
}

fn canonical_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Schema-aware allocation preflight. It consumes JSON tokens and counters,
// never a JSON Value or an Object. Vec growth and owned strings are charged
// conservatively before the typed deserializer may allocate them.
#[derive(Clone, Copy)]
enum MemoryKind {
    Object,
    Named,
    Extent,
    Sparse,
    Range,
    EaSet,
    Ea,
    Point,
    Text,
    Scalar,
    Path,
    Paths,
    Bytes,
    Units,
    Extents,
    Ranges,
    Names,
    Eas,
    Fixed,
}
#[derive(Clone, Copy)]
struct MemorySeed<'a> {
    kind: MemoryKind,
    used: &'a Cell<u64>,
    limit: u64,
}
impl MemorySeed<'_> {
    fn charge<E: serde::de::Error>(&self, bytes: u64) -> std::result::Result<(), E> {
        let next = self
            .used
            .get()
            .checked_add(bytes)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| {
                E::custom("object compact/decoded allocation exceeds resource row budget")
            })?;
        self.used.set(next);
        Ok(())
    }
    fn field(self, name: &str) -> Option<MemoryKind> {
        use MemoryKind::*;
        Some(match (self.kind, name) {
            (Object, "path") => Path,
            (Object, "additional_names") => Paths,
            (Object, "security" | "api_security") => Bytes,
            (Object, "extended_attributes") => EaSet,
            (Object, "reparse") => Point,
            (Object, "named_streams") => Names,
            (Object | Named, "source_extents") => Extents,
            (Object | Named, "sparse") => Sparse,
            (Object | Named, "sha256") => Text,
            (Object, "stored_times") => Fixed,
            (
                Object,
                "record_number"
                | "sequence_number"
                | "directory"
                | "attributes"
                | "ntfs_compression_normalized"
                | "case_sensitive",
            ) => Scalar,
            (Object | Named, "source_offset" | "length" | "source_evidence") => Scalar,
            (Named, "name_utf16") => Units,
            (Extent, "logical_offset" | "physical_offset" | "length") => Scalar,
            (Sparse, "initialized_length") => Scalar,
            (Sparse, "allocated" | "holes") => Ranges,
            (Range, "offset" | "length") => Scalar,
            (EaSet, "entries") => Eas,
            (Ea, "flags") => Scalar,
            (Ea, "name" | "value") => Bytes,
            (Point, "buffer") => Bytes,
            _ => return None,
        })
    }
}
impl<'de> serde::de::DeserializeSeed<'de> for MemorySeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for MemorySeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded expected object JSON")
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, text: &str) -> std::result::Result<(), E> {
        if matches!(self.kind, MemoryKind::Text) {
            self.charge(
                (text.len() as u64)
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(8))
                    .ok_or_else(|| E::custom("object string size overflow"))?,
            )?;
        }
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, text: String) -> std::result::Result<(), E> {
        self.visit_str(&text)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<(), A::Error> {
        use MemoryKind::*;
        let (kind, size) = match self.kind {
            Path => (Text, std::mem::size_of::<String>()),
            Paths => (Path, std::mem::size_of::<Vec<String>>()),
            Bytes => (Scalar, 1),
            Units => (Scalar, 2),
            Extents => (Extent, std::mem::size_of::<crate::ntfs_inspect::Extent>()),
            Ranges => (Range, std::mem::size_of::<super::LogicalRange>()),
            Names => (Named, std::mem::size_of::<super::NamedStream>()),
            Eas => (
                Ea,
                std::mem::size_of::<n2r_win32::extended_attributes::Entry>(),
            ),
            Fixed => (Scalar, 0),
            _ => {
                return Err(<A::Error as serde::de::Error>::custom(
                    "unexpected object allocation sequence",
                ));
            }
        };
        let mut count = 0u64;
        while seq
            .next_element_seed(MemorySeed {
                kind,
                used: self.used,
                limit: self.limit,
            })?
            .is_some()
        {
            count = count.checked_add(1).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom("object allocation count overflow")
            })?;
        }
        if count > 0 && size > 0 {
            let capacity = count
                .checked_next_power_of_two()
                .map(|n| n.max(8))
                .ok_or_else(|| {
                    <A::Error as serde::de::Error>::custom("object vector capacity overflow")
                })?;
            self.charge(capacity.checked_mul(size as u64).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom("object vector allocation overflow")
            })?)?;
        }
        Ok(())
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<(), A::Error> {
        while let Some(field) = map.next_key::<String>()? {
            let kind = self.field(&field).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom("unknown typed object allocation field")
            })?;
            map.next_value_seed(MemorySeed {
                kind,
                used: self.used,
                limit: self.limit,
            })?;
        }
        self.charge(0)
    }
}
fn object_memory_bytes(object: &Object, compact: u64, maximum: u64) -> Result<u64> {
    let mut bytes = compact
        .checked_add(std::mem::size_of::<Object>() as u64)
        .context("object memory overflow")?;
    let mut charge = |n: usize| -> Result<()> {
        bytes = bytes
            .checked_add(n as u64)
            .filter(|n| *n <= maximum)
            .context("actual decoded object exceeds resource row budget")?;
        Ok(())
    };
    let path = |v: &Vec<String>| -> Result<usize> {
        v.iter().try_fold(
            v.capacity()
                .checked_mul(std::mem::size_of::<String>())
                .context("path memory overflow")?,
            |n, s| n.checked_add(s.capacity()).context("path memory overflow"),
        )
    };
    let sparse = |s: &super::SparseLayout| -> Result<usize> {
        s.allocated
            .capacity()
            .checked_add(s.holes.capacity())
            .and_then(|n| n.checked_mul(std::mem::size_of::<super::LogicalRange>()))
            .context("sparse memory overflow")
    };
    charge(path(&object.path)?)?;
    charge(
        object
            .additional_names
            .capacity()
            .checked_mul(std::mem::size_of::<Vec<String>>())
            .context("alias memory overflow")?,
    )?;
    for alias in &object.additional_names {
        charge(path(alias)?)?;
    }
    charge(object.security.capacity())?;
    if let Some(api) = &object.api_security {
        charge(api.capacity())?;
    }
    if let Some(ea) = &object.extended_attributes {
        charge(
            ea.entries
                .capacity()
                .checked_mul(std::mem::size_of::<n2r_win32::extended_attributes::Entry>())
                .context("EA memory overflow")?,
        )?;
        for entry in &ea.entries {
            charge(entry.name.capacity())?;
            charge(entry.value.capacity())?;
        }
    }
    if let Some(point) = &object.reparse {
        charge(point.buffer.capacity())?;
    }
    charge(
        object
            .source_extents
            .capacity()
            .checked_mul(std::mem::size_of::<crate::ntfs_inspect::Extent>())
            .context("extent memory overflow")?,
    )?;
    if let Some(digest) = &object.sha256 {
        charge(digest.capacity())?;
    }
    if let Some(layout) = &object.sparse {
        charge(sparse(layout)?)?;
    }
    charge(
        object
            .named_streams
            .capacity()
            .checked_mul(std::mem::size_of::<super::NamedStream>())
            .context("stream memory overflow")?,
    )?;
    for stream in &object.named_streams {
        charge(
            stream
                .name_utf16
                .capacity()
                .checked_mul(2)
                .context("stream name memory overflow")?,
        )?;
        charge(
            stream
                .source_extents
                .capacity()
                .checked_mul(std::mem::size_of::<crate::ntfs_inspect::Extent>())
                .context("stream extent memory overflow")?,
        )?;
        if let Some(digest) = &stream.sha256 {
            charge(digest.capacity())?;
        }
        if let Some(layout) = &stream.sparse {
            charge(sparse(layout)?)?;
        }
    }
    charge(0)?;
    Ok(bytes)
}
fn check_object_memory(object: &Object, compact: u64, maximum: u64) -> Result<()> {
    object_memory_bytes(object, compact, maximum).map(|_| ())
}

/// Whether a row of `compact` bytes cannot decode to more than `limit`.
///
/// The counting pass of [`decode_compact_object`] refuses a row whose
/// decoded form would pass the row budget before anything is allocated for
/// it. Decoding takes at most a small multiple of the JSON's size (an empty
/// string or list costs 24 bytes for 2 of text, a first list element four
/// elements' room); `DECODE_GROWTH` is far above that. A row that cannot
/// reach the budget even so is parsed once, not twice, and its actual
/// memory is still checked after decoding.
fn decoded_cannot_exceed(compact: u64, limit: u64) -> bool {
    const DECODE_GROWTH: u64 = 1024;
    compact
        .checked_mul(DECODE_GROWTH)
        .and_then(|n| n.checked_add(std::mem::size_of::<Object>() as u64))
        .is_some_and(|n| n <= limit)
}

/// One object decoded from the complete compact JSON its chunks hold, as
/// an opening that owns its memory decodes it from its pages: the
/// allocation pre-check against the row budget (`row_limit`, a resource
/// admission's) where the row could reach it, the typed decoding, and the
/// decoded object's actual memory held to the budget. The creation of a
/// tree that verifies once decodes every object it writes with this too
/// (see `DecodeBack`).
fn decode_compact_object(bytes: &[u8], row_limit: Option<u64>) -> Result<Object> {
    let compact = bytes.len() as u64;
    if let Some(limit) = row_limit.filter(|limit| !decoded_cannot_exceed(compact, *limit)) {
        let used = Cell::new(
            compact
                .checked_add(std::mem::size_of::<Object>() as u64)
                .context("object memory counter overflow")?,
        );
        let seed = MemorySeed {
            kind: MemoryKind::Object,
            used: &used,
            limit,
        };
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        serde::de::DeserializeSeed::deserialize(seed, &mut decoder)?;
        decoder.end()?;
    }
    let object: Object =
        serde_json::from_slice(bytes).context("decode complete expected-tree object chunks")?;
    if let Some(limit) = row_limit {
        check_object_memory(&object, compact, limit)?;
    }
    Ok(object)
}

/// Where a creation that verifies once keeps what it decodes back (see
/// [`DecodeBack`]): the cache of the tree that opens its pages next, the
/// arena that pays for the decoding and for what is kept, and the number
/// of objects of the tree.
#[derive(Clone, Copy)]
struct DecodeBackTo<'c> {
    cache: &'c DecodedCache,
    arena: &'c crate::artifact_arena::ArtifactArena,
    len: usize,
}

/// Every object a creation that verifies once writes, decoded back from the
/// chunks it was just written as, with the decoder an opening uses
/// ([`decode_chunk`] for each chunk's payload, then
/// [`decode_compact_object`]), and held equal to the object written.
///
/// The opening of those pages in the same run leaves out its own pass over
/// every object (see [`CreatedHere`]), and the objects decoded here are the
/// ones it is then handed (its decoded-object cache), so this is the check,
/// before the first write to the source, that the pages decode to the tree:
/// the chunk framing, the typed decoding, the allocation pre-check (a row
/// it refuses is refused here, not at its first use after the apply) and
/// the decoded object's memory.
///
/// Objects are decoded a batch at a time on helper threads, each object's
/// workspace (eight times its compact bytes, as an opening reserves to
/// decode it, and the object held until then) leased from spare memory;
/// where the arena has none to spare, what is pending is decoded and the
/// object is decoded by itself, its workspace reserved as an opening
/// reserves it. Results are taken in the order the objects were written,
/// so the refusal reported is that of the first object refused.
struct DecodeBack<'c> {
    to: DecodeBackTo<'c>,
    pending: Vec<WrittenObject>,
    leases: Vec<crate::artifact_arena::ArenaRamLease>,
    leased: u64,
    workers: usize,
}
/// One object as written: the object, its chunks' payloads and the compact
/// bytes they hold.
struct WrittenObject {
    ordinal: usize,
    object: Arc<Object>,
    payloads: Vec<Vec<u8>>,
    bytes: u64,
}
impl WrittenObject {
    fn decode(&self, maximum_chunk: usize, row_limit: Option<u64>) -> Result<Object> {
        (|| -> Result<Object> {
            let length =
                usize::try_from(self.bytes).context("compact object exceeds address space")?;
            let mut compact = Vec::new();
            compact.try_reserve_exact(length)?;
            for payload in &self.payloads {
                let raw = decode_chunk(payload, maximum_chunk)?;
                ensure!(
                    compact.len() + raw.len() <= length,
                    "object chunk bytes exceed directory"
                );
                compact.extend_from_slice(&raw);
            }
            ensure!(
                compact.len() == length,
                "complete object chunk byte count differs"
            );
            let decoded = decode_compact_object(&compact, row_limit)?;
            ensure!(
                decoded == *self.object,
                "the object decoded from its chunks differs from the object written"
            );
            Ok(decoded)
        })()
        .with_context(|| {
            format!(
                "expected-tree object {} (FILE {}) decoded back from the pages just written",
                self.ordinal, self.object.record_number
            )
        })
    }
}
impl<'c> DecodeBack<'c> {
    /// Objects decoded at once on helper threads, and the workspace leased
    /// for them, at most.
    const BATCH_OBJECTS: usize = 1024;
    const BATCH_BYTES: u64 = 64 * 1024 * 1024;
    fn new(to: DecodeBackTo<'c>) -> Self {
        Self {
            to,
            pending: Vec::new(),
            leases: Vec::new(),
            leased: 0,
            workers: std::thread::available_parallelism()
                .map_or(2, |n| n.get())
                .clamp(2, 4),
        }
    }
    /// The workspace to decode `written` back: what an opening reserves
    /// to decode it from its pages, less the page buffers it reads them
    /// through, and the object, held until it is decoded.
    fn workspace(written: &WrittenObject, row_limit: Option<u64>) -> Result<u64> {
        written
            .bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(DECODED_OBJECT_ALLOWANCE))
            .and_then(|n| {
                n.checked_add(
                    object_memory_bytes(&written.object, 0, row_limit.unwrap_or(u64::MAX)).ok()?,
                )
            })
            .context("expected decode-back workspace overflow")
    }
    /// Takes `written` to be decoded back, now or with its batch.
    fn push(
        &mut self,
        written: WrittenObject,
        maximum_chunk: usize,
        row_limit: Option<u64>,
    ) -> Result<()> {
        let queued = (|| -> Result<_> {
            let workspace = Self::workspace(&written, row_limit)?;
            self.pending.try_reserve(1)?;
            self.leases.try_reserve(1)?;
            Ok((workspace, self.to.arena.reserve_spare_ram(workspace).ok()))
        })();
        match queued {
            Ok((workspace, Some(lease))) => {
                self.pending.push(written);
                self.leases.push(lease);
                self.leased = self.leased.saturating_add(workspace);
                if self.pending.len() >= Self::BATCH_OBJECTS || self.leased >= Self::BATCH_BYTES {
                    self.flush(maximum_chunk, row_limit)?;
                }
                Ok(())
            }
            Ok((workspace, None)) => {
                // No memory to spare: in order, what is pending, and then
                // this one by itself in the memory the run needs for it.
                self.flush(maximum_chunk, row_limit)?;
                let _workspace = self.to.arena.reserve_ram(workspace)?;
                let decoded = written.decode(maximum_chunk, row_limit)?;
                self.keep(written.ordinal, row_limit, decoded);
                Ok(())
            }
            Err(error) => {
                // This object's refusal comes after those of the objects
                // written before it.
                self.flush(maximum_chunk, row_limit)?;
                Err(error)
            }
        }
    }
    /// Decodes back what is pending, in the order it was written: the
    /// first object refused is the refusal returned.
    fn flush(&mut self, maximum_chunk: usize, row_limit: Option<u64>) -> Result<()> {
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            return Ok(());
        }
        let decoded: Vec<Result<Object>> = if pending.len() >= 16 && self.workers > 1 {
            let part = pending.len().div_ceil(self.workers);
            std::thread::scope(|scope| -> Result<Vec<Result<Object>>> {
                let handles: Vec<_> = pending
                    .chunks(part)
                    .map(|objects| {
                        scope.spawn(move || {
                            objects
                                .iter()
                                .map(|written| written.decode(maximum_chunk, row_limit))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                let mut decoded = Vec::new();
                decoded.try_reserve_exact(pending.len())?;
                for handle in handles {
                    decoded.extend(handle.join().map_err(|_| {
                        anyhow::anyhow!("expected-tree decode-back worker panicked")
                    })?);
                }
                Ok(decoded)
            })?
        } else {
            pending
                .iter()
                .map(|written| written.decode(maximum_chunk, row_limit))
                .collect()
        };
        let result = pending
            .iter()
            .zip(decoded)
            .try_for_each(|(written, decoded)| {
                self.keep(written.ordinal, row_limit, decoded?);
                Ok(())
            });
        drop(pending);
        self.leases.clear();
        self.leased = 0;
        result
    }
    fn keep(&self, ordinal: usize, row_limit: Option<u64>, decoded: Object) {
        if let Some(limit) = row_limit {
            self.to.cache.keep(
                self.to.arena,
                limit,
                self.to.len,
                ordinal,
                &Arc::new(decoded),
            );
        }
    }
}

/// The pages of a tree that is being created: the writer, past the header
/// record, and what was counted of the objects written so far.
struct CompactObjects<'c> {
    writer: Writer,
    counts: ExpectedTreePageCounts,
    maximum_chunk: usize,
    // The most compact bytes one object may take.
    maximum_bytes: u64,
    // The row budget of a resource admission: the decoded object is held
    // to it as well.
    row_limit: Option<u64>,
    // Every object written decoded back from its chunks (see `DecodeBack`).
    decode_back: Option<DecodeBack<'c>>,
}
impl<'c> CompactObjects<'c> {
    fn begin(
        path: &Path,
        budget: PageBudget,
        header: &HeaderRef<'_>,
        semantic_byte_budget: u64,
        row_limit: Option<u64>,
        decode_back: Option<DecodeBackTo<'c>>,
    ) -> Result<Self> {
        let maximum_chunk = chunk_bytes(budget)?;
        let mut writer = Writer::new(path, PURPOSE, budget)?;
        writer.push(&[], &record(header, budget)?)?;
        Ok(Self {
            writer,
            counts: ExpectedTreePageCounts::default(),
            maximum_chunk,
            maximum_bytes: row_limit.unwrap_or(semantic_byte_budget),
            row_limit,
            decode_back: decode_back.map(DecodeBack::new),
        })
    }
    /// Counts `object` and writes it as the chunks of object `ordinal`.
    ///
    /// Where objects are decoded back, a refusal of this object's writing
    /// is returned only once every object written before it has been
    /// decoded back without one: the first refusal is still the first.
    fn write(&mut self, ordinal: usize, object: Cow<'_, Object>) -> Result<()> {
        let written = self.write_chunks(ordinal, &object);
        let Some(decode_back) = self.decode_back.as_mut() else {
            return written.map(|_| ());
        };
        let (payloads, bytes) = match written {
            Ok(kept) => kept.context("the chunks to decode back are absent")?,
            Err(error) => {
                decode_back.flush(self.maximum_chunk, self.row_limit)?;
                return Err(error);
            }
        };
        decode_back.push(
            WrittenObject {
                ordinal,
                object: Arc::new(object.into_owned()),
                payloads,
                bytes,
            },
            self.maximum_chunk,
            self.row_limit,
        )
    }
    /// The chunks of object `ordinal`; their payloads and compact bytes
    /// where the object is to be decoded back from them.
    fn write_chunks(
        &mut self,
        ordinal: usize,
        object: &Object,
    ) -> Result<Option<(Vec<Vec<u8>>, u64)>> {
        self.counts.include(object)?;
        if let Some(limit) = self.row_limit {
            check_object_memory(object, 0, limit)?;
        }
        let mut chunks = ChunkWriter {
            writer: &mut self.writer,
            object: u64::try_from(ordinal)?,
            chunks: 0,
            bytes: 0,
            maximum: self.maximum_bytes,
            buffer: Vec::new(),
            chunk_bytes: self.maximum_chunk,
            kept: self.decode_back.is_some().then(Vec::new),
        };
        serde_json::to_writer(&mut chunks, object)?;
        if let Some(limit) = self.row_limit {
            check_object_memory(object, chunks.bytes, limit)?;
        }
        let bytes = chunks.bytes;
        Ok(chunks.finish()?.map(|payloads| (payloads, bytes)))
    }
    /// Decodes back what is still pending (see `DecodeBack`).
    fn finish_decoding_back(&mut self) -> Result<()> {
        match self.decode_back.as_mut() {
            Some(decode_back) => decode_back.flush(self.maximum_chunk, self.row_limit),
            None => Ok(()),
        }
    }
}

/// A tree's legacy JSON, written as its own serializer writes it (the four
/// fields of [`ExpectedTree`] in their order, the objects in theirs: see
/// [`LegacyView`]), with every object also written to the tree's pages as
/// it goes by.
///
/// Creating the pages went through the tree twice, once for the digest of
/// this JSON and once for the pages, and a tree that is a projection store
/// decodes an object from its row each time it is asked for one. Here each
/// object is asked for once.
///
/// The JSON used to be complete before the first page was written, so
/// whatever it refused was refused before anything of the pages was. That
/// order is kept: the first failure of the pages is put aside, nothing
/// more is written to them, and the JSON goes on to its end. Its refusal,
/// if it has one, is the one reported; otherwise the pages' is.
struct CreationView<'a, 'c, T: ExpectedObjectDomain> {
    tree: &'a T,
    compact: &'a RefCell<Result<CompactObjects<'c>>>,
}
impl<T: ExpectedObjectDomain> Serialize for CreationView<'_, '_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("ExpectedTree", 4)?;
        fields.serialize_field("profile", self.tree.profile())?;
        fields.serialize_field(
            "objects",
            &CreationObjects {
                tree: self.tree,
                compact: self.compact,
            },
        )?;
        fields.serialize_field("logical_bytes", &self.tree.logical_bytes())?;
        fields.serialize_field(
            "internal_replacement_pending",
            self.tree.internal_replacement_pending(),
        )?;
        fields.end()
    }
}
struct CreationObjects<'a, 'c, T: ExpectedObjectDomain> {
    tree: &'a T,
    compact: &'a RefCell<Result<CompactObjects<'c>>>,
}
impl<T: ExpectedObjectDomain> Serialize for CreationObjects<'_, '_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let count = self.tree.object_count();
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for index in 0..count {
            let object = self.tree.object(index).map_err(S::Error::custom)?;
            // The JSON's refusal of this object, if it has one, is the one
            // reported, whatever its pages would refuse: it goes first, and
            // the object then goes to the pages.
            sequence.serialize_element(object.as_ref())?;
            let mut compact = self.compact.borrow_mut();
            let written = match compact.as_mut() {
                Ok(pages) => pages.write(index, object),
                // Already put aside: the JSON alone goes on.
                Err(_) => Ok(()),
            };
            if let Err(error) = written {
                // The writer goes with it: nothing certifies a prefix.
                *compact = Err(error);
            }
        }
        sequence.end()
    }
}

impl PagedExpectedTree {
    pub fn create_with_resources_in_group(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
    ) -> Result<(
        ExpectedTreePageReceipt,
        crate::artifact_arena::ArtifactLease,
    )> {
        Self::create_in_group(tree, path, admission, group, None)
    }
    /// [`Self::create_with_resources_in_group`] and then
    /// [`Self::open_created_with_resources_in_group`] of what it wrote.
    ///
    /// In a run that verifies once, the creation decodes every object back
    /// from the chunks it has just written, with the opening's decoder,
    /// and holds it equal to the object written ([`DecodeBack`]); the
    /// opening then makes no pass over the objects of its own. The objects
    /// decoded back are kept for the opened tree as its decoded objects, as
    /// the opening's own pass over them used to keep them (the same
    /// optional memory, the same cache, given up the same way when memory
    /// is short). Where the opening makes its pass, it starts from an
    /// empty cache, as always.
    pub fn create_and_open_with_resources_in_group(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
    ) -> Result<Self> {
        let decoded = n2r_win32::verify_policy::verifies_once().then(DecodedCache::registered);
        let (receipt, artifact) =
            Self::create_in_group(tree, path, admission, group, decoded.as_deref())?;
        Self::open_created_in_group(path, &receipt, admission, group, artifact, decoded)
    }
    fn create_in_group(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        decoded: Option<&DecodedCache>,
    ) -> Result<(
        ExpectedTreePageReceipt,
        crate::artifact_arena::ArtifactLease,
    )> {
        ensure!(
            group.group() == crate::artifact_arena::ArtifactGroup::Expected
                && group.arena().budget() == admission.budget,
            "actual expected arena group differs"
        );
        let page = u64::from(admission.expected_page_budget()?.max_page_bytes);
        let working = page
            .checked_mul(4)
            .and_then(|n| {
                admission
                    .budget
                    .max_row_bytes
                    .checked_mul(8)
                    .and_then(|row| n.checked_add(row))
            })
            .context("expected writer RAM overflow")?;
        let _ram = group.arena().reserve_ram(working)?;
        let permit = group.reserve_file(path, admission.expected_page_budget()?.max_file_bytes)?;
        let decode_back = decoded.map(|cache| DecodeBackTo {
            cache,
            arena: group.arena(),
            len: tree.object_count(),
        });
        let receipt =
            Self::create_with_resources_decoded_back(tree, permit.path(), admission, decode_back)?;
        let artifact = permit.verify_closed(&receipt.file_sha256)?;
        Ok((receipt, artifact))
    }
    /// Create a separate paged projection; the original expectation.json and
    /// its exact pretty-JSON SHA remain unchanged. The same pinned max_file_bytes
    /// also bounds the streamed legacy semantic JSON representation.
    pub fn create(
        tree: &ExpectedTree,
        path: &Path,
        budget: PageBudget,
    ) -> Result<ExpectedTreePageReceipt> {
        Self::create_with_limits(tree, path, wire_budget(budget)?, budget.max_file_bytes)
    }

    /// Explicit independent physical-page and legacy-semantic budgets. Wire
    /// expansion must never reduce the admitted legacy metadata domain.
    pub fn create_with_limits(
        tree: &ExpectedTree,
        path: &Path,
        budget: PageBudget,
        semantic_byte_budget: u64,
    ) -> Result<ExpectedTreePageReceipt> {
        Self::create_domain(tree, path, budget, semantic_byte_budget, None, None)
    }
    pub fn create_with_resources(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<ExpectedTreePageReceipt> {
        Self::create_with_resources_decoded_back(tree, path, admission, None)
    }
    fn create_with_resources_decoded_back(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        decode_back: Option<DecodeBackTo<'_>>,
    ) -> Result<ExpectedTreePageReceipt> {
        admission.validate()?;
        ensure!(
            tree.object_count() as u64 == admission.objects()?,
            "resource expected object count differs"
        );
        ensure!(
            (tree.object_count() as u64)
                .checked_mul(24)
                .is_some_and(|n| n <= admission.budget.retained_index_bytes),
            "resource expected index exceeds budget"
        );
        Self::create_domain(
            tree,
            path,
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
            Some(admission),
            decode_back,
        )
    }
    fn create_domain(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        budget: PageBudget,
        semantic_byte_budget: u64,
        resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
        decode_back: Option<DecodeBackTo<'_>>,
    ) -> Result<ExpectedTreePageReceipt> {
        budget.validate()?;
        ensure!(
            (1..=i64::MAX as u64).contains(&semantic_byte_budget),
            "invalid expected semantic byte budget"
        );
        let objects = u64::try_from(tree.object_count())?;
        let records = objects
            .checked_add(1)
            .context("paged expected-tree record count overflow")?;
        ensure!(
            records <= budget.max_records,
            "expected-tree object domain exceeds record budget"
        );
        let mut semantic = SemanticHash::new(semantic_byte_budget)?;
        let header = HeaderRef {
            schema_version: if resource_admission.is_some() { 3 } else { 2 },
            profile: tree.profile(),
            logical_bytes: tree.logical_bytes(),
            internal_replacement_pending: tree.internal_replacement_pending(),
            total_objects: objects,
            resource_admission,
        };
        let row_limit = resource_admission.map(|admission| admission.budget.max_row_bytes);
        // Whether every object written was decoded back from its chunks.
        let mut decoded_back = false;
        let (semantic_sha256, compact) = if n2r_win32::verify_policy::full_unremembered() {
            // Two passes over the tree, as it always was: its legacy JSON
            // first, then its pages. (Their opening derives everything from
            // them again: nothing is decoded back here.)
            write_legacy_json(&mut semantic, tree)?;
            let semantic_sha256 = semantic.finish()?;
            let mut compact = CompactObjects::begin(
                path,
                budget,
                &header,
                semantic_byte_budget,
                row_limit,
                None,
            )?;
            for ordinal in 0..tree.object_count() {
                let object = tree.object(ordinal)?;
                compact.write(ordinal, object)?;
            }
            (semantic_sha256, compact)
        } else {
            // One pass (check-once, outside its gate): each object is
            // decoded once, for its pages and for the legacy JSON. What
            // the pages refuse is kept until the JSON is complete, so the
            // refusal that comes first is the one that came first. The
            // objects decoded back from the pages are of the pages too:
            // their refusal comes after the JSON's.
            let compact = RefCell::new(CompactObjects::begin(
                path,
                budget,
                &header,
                semantic_byte_budget,
                row_limit,
                decode_back,
            ));
            write_legacy_json(
                &mut semantic,
                &CreationView {
                    tree,
                    compact: &compact,
                },
            )?;
            let semantic_sha256 = semantic.finish()?;
            let mut compact = compact.into_inner()?;
            compact.finish_decoding_back()?;
            decoded_back = compact.decode_back.is_some();
            (semantic_sha256, compact)
        };
        let CompactObjects { writer, counts, .. } = compact;
        if let Some(admission) = resource_admission {
            admission.validate_tree(counts.files, counts.directories, counts.data_streams)?;
        }
        let summary = writer.finish()?;
        ensure!(
            summary.records >= records,
            "written expected-tree record domain differs"
        );
        let created = CreatedHere {
            file_sha256: summary.sha256.clone(),
            semantic_sha256: semantic_sha256.clone(),
            counts,
            budget,
            semantic_byte_budget,
            resource_admission,
            decoded_back,
        };
        Ok(ExpectedTreePageReceipt {
            schema_version: if resource_admission.is_some() { 3 } else { 2 },
            path: path.to_owned(),
            file_sha256: summary.sha256,
            semantic_sha256,
            objects,
            records: summary.records,
            pages: summary.pages,
            bytes: summary.bytes,
            page_budget: budget,
            semantic_byte_budget,
            resource_admission,
            created: Some(created),
        })
    }

    /// The held-file/page reader authenticates the entire file and page/index
    /// domain first. This layer then checks every ordinal key, typed object and
    /// scalar count while reconstructing the exact legacy pretty JSON pin.
    pub fn open(
        path: &Path,
        file_sha256: &str,
        legacy_semantic_sha256: &str,
        budget: PageBudget,
    ) -> Result<Self> {
        Self::open_with_limits(
            path,
            file_sha256,
            legacy_semantic_sha256,
            wire_budget(budget)?,
            budget.max_file_bytes,
        )
    }

    pub fn open_with_limits(
        path: &Path,
        file_sha256: &str,
        legacy_semantic_sha256: &str,
        budget: PageBudget,
        semantic_byte_budget: u64,
    ) -> Result<Self> {
        Self::open_domain(
            path,
            file_sha256,
            legacy_semantic_sha256,
            budget,
            semantic_byte_budget,
            None,
            None,
        )
    }
    pub fn open_with_resources(
        path: &Path,
        file_sha256: &str,
        legacy_semantic_sha256: &str,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<Self> {
        admission.validate()?;
        Self::open_domain(
            path,
            file_sha256,
            legacy_semantic_sha256,
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
            Some(admission),
            None,
        )
    }
    pub fn open_with_resources_in_group(
        path: &Path,
        file_sha256: &str,
        legacy_semantic_sha256: &str,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        artifact: crate::artifact_arena::ArtifactLease,
    ) -> Result<Self> {
        admission.validate()?;
        ensure!(
            group.group() == crate::artifact_arena::ArtifactGroup::Expected
                && group.arena().budget() == admission.budget
                && artifact.same_group(group)
                && artifact.sha256() == file_sha256,
            "expected page file/arena owner differs"
        );
        Self::open_domain(
            path,
            file_sha256,
            legacy_semantic_sha256,
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
            Some(admission),
            Some((group.arena().clone(), artifact)),
        )
    }
    /// [`Self::open_with_resources_in_group`] for the pages that
    /// [`Self::create_with_resources_in_group`] has just written, pinned by
    /// the receipt it returned. In a run that verifies once, the legacy
    /// JSON's digest and the object counts are those the creation derived
    /// (see [`CreatedHere`]); otherwise, and for a receipt that does not
    /// describe this file, the opening derives them again as every other
    /// opening does.
    pub fn open_created_with_resources_in_group(
        path: &Path,
        receipt: &ExpectedTreePageReceipt,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        artifact: crate::artifact_arena::ArtifactLease,
    ) -> Result<Self> {
        Self::open_created_in_group(path, receipt, admission, group, artifact, None)
    }
    fn open_created_in_group(
        path: &Path,
        receipt: &ExpectedTreePageReceipt,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        artifact: crate::artifact_arena::ArtifactLease,
        decoded: Option<std::rc::Rc<DecodedCache>>,
    ) -> Result<Self> {
        admission.validate()?;
        ensure!(
            group.group() == crate::artifact_arena::ArtifactGroup::Expected
                && group.arena().budget() == admission.budget
                && artifact.same_group(group)
                && artifact.sha256() == receipt.file_sha256,
            "expected page file/arena owner differs"
        );
        Self::open_owned_domain(
            path,
            &receipt.file_sha256,
            Some(&receipt.semantic_sha256),
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
            Some(admission),
            false,
            Some(ExpectedMemoryOwner {
                arena: group.arena().clone(),
                artifact: Some(artifact),
                reopened: None,
            }),
            receipt.created.as_ref().map(|created| (created, decoded)),
        )
    }
    fn open_domain(
        path: &Path,
        file_sha256: &str,
        legacy_semantic_sha256: &str,
        budget: PageBudget,
        semantic_byte_budget: u64,
        resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
        memory: Option<(
            crate::artifact_arena::ArtifactArena,
            crate::artifact_arena::ArtifactLease,
        )>,
    ) -> Result<Self> {
        Self::open_owned_domain(
            path,
            file_sha256,
            Some(legacy_semantic_sha256),
            budget,
            semantic_byte_budget,
            resource_admission,
            false,
            memory.map(|(arena, artifact)| ExpectedMemoryOwner {
                arena,
                artifact: Some(artifact),
                reopened: None,
            }),
            None,
        )
    }

    /// Revalidate an independently pinned legacy file whose semantic receipt
    /// was never persisted. The complete typed domain derives that fact anew;
    /// this does not issue source admission or recover an old runtime owner.
    pub(crate) fn open_revalidated_with_resources_in_group(
        path: &Path,
        file_sha256: &str,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        artifact: crate::artifact_arena::ArtifactLease,
    ) -> Result<Self> {
        admission.validate()?;
        ensure!(
            group.group() == crate::artifact_arena::ArtifactGroup::Expected
                && group.arena().budget() == admission.budget
                && artifact.same_group(group)
                && artifact.sha256() == file_sha256,
            "revalidated expected file/arena owner differs"
        );
        Self::open_owned_domain(
            path,
            file_sha256,
            None,
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
            Some(admission),
            false,
            Some(ExpectedMemoryOwner {
                arena: group.arena().clone(),
                artifact: Some(artifact),
                reopened: None,
            }),
            None,
        )
    }

    pub(crate) fn open_cached_body_in_group(
        path: &Path,
        file_sha: &str,
        current: n2r_win32::tree_resources::SourceResourceAdmission,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        artifact: crate::artifact_arena::ArtifactLease,
    ) -> Result<Self> {
        current.validate()?;
        ensure!(
            group.group() == crate::artifact_arena::ArtifactGroup::Expected
                && group.arena().budget() == current.budget
                && artifact.same_group(group)
                && artifact.sha256() == file_sha,
            "cached expected actual file/group differs"
        );
        let mut tree = Self::open_owned_domain(
            path,
            file_sha,
            None,
            current.expected_page_budget()?,
            current.semantic_byte_budget(),
            Some(current),
            true,
            Some(ExpectedMemoryOwner {
                arena: group.arena().clone(),
                artifact: Some(artifact),
                reopened: None,
            }),
            None,
        )?;
        tree.cached_body_pending = true;
        Ok(tree)
    }
    pub(crate) fn binding_pin(&self) -> Option<&ExpectedBindingPin> {
        self.binding.as_ref()
    }
    pub(crate) fn require_rebind_source(&self, source_owner: usize) -> Result<()> {
        ensure!(
            !self.cached_body_pending
                && (self.binding.is_none()
                    || (self._binding_artifact.is_some()
                        && self.live_rebind_source == Some(source_owner))),
            "cached expected lacks this actual fresh source's live rebind proof"
        );
        Ok(())
    }
    fn apply_binding(
        &mut self,
        pin: &ExpectedBindingPin,
        current: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<()> {
        pin.facts
            .validate(current, &self.file_sha256, &self.semantic_sha256)?;
        ensure!(
            pin.bytes > 0
                && pin.bytes <= 65536
                && canonical_sha(&pin.sha256)
                && self.header.resource_admission == Some(pin.facts.original_admission)
                && self.profile() == pin.facts.profile.as_str()
                && self.logical_bytes() == pin.facts.logical_bytes
                && self.len() as u64 == pin.facts.objects
                && self.internal_replacement_pending() == pin.facts.pending_roles.as_slice(),
            "cached expected binding does not describe the complete typed body"
        );
        let bytes = serde_json::to_vec(&pin.facts)?;
        ensure!(
            bytes.len() as u64 == pin.bytes && hex::encode(Sha256::digest(&bytes)) == pin.sha256,
            "cached expected binding canonical pin differs"
        );
        let ram = self
            .arena
            .as_ref()
            .context("bound expected arena absent")?
            .reserve_ram(
                pin.bytes
                    .checked_mul(32)
                    .and_then(|n| n.checked_add(65536))
                    .context("expected binding RAM overflow")?,
            )?;
        self.binding = Some(pin.clone());
        self._binding_ram = Some(ram);
        self.resource_admission = Some(current);
        self.header.resource_admission = Some(current);
        self.cached_body_pending = false;
        Ok(())
    }
    pub(crate) fn rebind_cached_body(
        &mut self,
        proof: crate::general_source_admission::resource::CachedExpectedRebind,
        group: &crate::artifact_arena::ArtifactGroupPermit,
        path: &Path,
    ) -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        ensure!(
            self.cached_body_pending
                && group.group() == crate::artifact_arena::ArtifactGroup::Expected
                && self._artifact.as_ref().is_some_and(|a| a.same_group(group)),
            "cached expected rebind lacks its actual paid body owner"
        );
        let (facts, source_owner) = proof.into_parts(self)?;
        let _work = group.arena().reserve_ram(2 * 1024 * 1024 + 65536)?;
        let bytes = serde_json::to_vec(&facts)?;
        ensure!(bytes.len() <= 65536, "expected source binding exceeds64KiB");
        let permit = group.reserve_file(path, bytes.len() as u64)?;
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x00200000)
            .open(permit.path())?;
        writer.write_all(&bytes)?;
        writer.sync_all()?;
        drop(writer);
        let sha = hex::encode(Sha256::digest(&bytes));
        let artifact = permit.verify_closed(&sha)?;
        let pin = ExpectedBindingPin {
            path: artifact.path().to_path_buf(),
            sha256: sha,
            bytes: bytes.len() as u64,
            facts,
        };
        self.apply_binding(&pin, pin.facts.effective_admission)?;
        self._binding_artifact = Some(artifact);
        self.live_rebind_source = Some(source_owner);
        Ok(())
    }

    pub(crate) fn open_recovery_with_binding(
        file: &File,
        snapshot: &n2r_win32::reference_file::ReferenceFileSnapshot,
        file_sha: &str,
        semantic_sha: &str,
        current: n2r_win32::tree_resources::SourceResourceAdmission,
        arena: &crate::artifact_arena::ArtifactArena,
        binding: Option<&ExpectedBindingPin>,
    ) -> Result<Self> {
        let Some(pin) = binding else {
            return Self::open_recovery_with_resources(
                file,
                snapshot,
                file_sha,
                semantic_sha,
                current,
                arena,
            );
        };
        pin.facts.validate(current, file_sha, semantic_sha)?;
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                file,
                current.expected_page_budget()?.max_file_bytes
            )? == *snapshot,
            "rebound recovery expected actual file differs"
        );
        let mut tree = Self::open_owned_domain(
            Path::new(&snapshot.final_path),
            file_sha,
            Some(semantic_sha),
            current.expected_page_budget()?,
            current.semantic_byte_budget(),
            Some(current),
            true,
            Some(ExpectedMemoryOwner {
                arena: arena.clone(),
                artifact: None,
                reopened: Some(file.try_clone()?),
            }),
            None,
        )?;
        tree.apply_binding(pin, current)?;
        use std::os::windows::fs::OpenOptionsExt;
        let mut binding_file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&pin.path)?;
        let binding_snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &binding_file,
            65536,
        )?;
        let modified = binding_file.metadata()?.modified()?;
        ensure!(
            binding_snapshot.file_bytes == pin.bytes
                && binding_snapshot.number_of_links == 1
                && hex::encode(n2r_win32::metadata_pages::pinning_digest(
                    &mut binding_file,
                    pin.bytes
                )?) == pin.sha256,
            "rebound expected sidecar actual identity/complete hash differs"
        );
        tree._reopened_binding = Some((binding_file, binding_snapshot, modified));
        tree.require_recovery_memory(arena)?;
        Ok(tree)
    }

    /// Reopen the exact held recovery artifact with live runtime accounting.
    /// This owner cannot satisfy the fresh-source artifact requirement.
    pub(crate) fn open_recovery_with_resources(
        file: &File,
        snapshot: &n2r_win32::reference_file::ReferenceFileSnapshot,
        file_sha256: &str,
        semantic_sha256: &str,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        arena: &crate::artifact_arena::ArtifactArena,
    ) -> Result<Self> {
        admission.validate()?;
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                file,
                admission.expected_page_budget()?.max_file_bytes,
            )? == *snapshot,
            "reopened expected artifact identity changed"
        );
        let tree = Self::open_owned_domain(
            Path::new(&snapshot.final_path),
            file_sha256,
            Some(semantic_sha256),
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
            Some(admission),
            false,
            Some(ExpectedMemoryOwner {
                arena: arena.clone(),
                artifact: None,
                reopened: Some(file.try_clone()?),
            }),
            None,
        )?;
        tree.require_recovery_memory(arena)?;
        Ok(tree)
    }

    #[allow(clippy::too_many_arguments)]
    fn open_owned_domain(
        path: &Path,
        file_sha256: &str,
        legacy_semantic_sha256: Option<&str>,
        budget: PageBudget,
        semantic_byte_budget: u64,
        resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
        allow_original_source_header: bool,
        mut memory: Option<ExpectedMemoryOwner>,
        // What the creation of this file derived of it, and the objects it
        // decoded, kept for this tree where those facts are taken.
        created: Option<(&CreatedHere, Option<std::rc::Rc<DecodedCache>>)>,
    ) -> Result<Self> {
        ensure!(
            (1..=i64::MAX as u64).contains(&semantic_byte_budget),
            "invalid expected semantic byte budget"
        );
        ensure!(
            canonical_sha(file_sha256) && legacy_semantic_sha256.is_none_or(canonical_sha),
            "canonical file and legacy expectation SHA-256 pins required"
        );
        // Pay the page cache, immutable path/snapshot state and read/hash
        // workspace BEFORE opening/validating any page. Cache Vec growth is
        // bounded by twice the largest admitted page.
        let arena = memory.as_ref().map(|owner| owner.arena.clone());
        let reader_bytes = u64::from(budget.max_page_bytes)
            .checked_mul(3)
            .and_then(|n| n.checked_add(65536 + 4096))
            .and_then(|n| {
                n.checked_add(memory.as_ref().map_or(0, |owner| {
                    owner.artifact.as_ref().map_or(262144, |file| {
                        file.snapshot().final_path.capacity() as u64 * 8
                    })
                }))
            })
            .context("expected reader RAM overflow")?;
        let reader_ram = arena
            .as_ref()
            .map(|a| a.reserve_ram(reader_bytes))
            .transpose()?;
        let directory_bound = resource_admission
            .map(|a| a.objects())
            .transpose()?
            .map(|n| {
                n.checked_mul(48)
                    .and_then(|n| n.checked_add(256))
                    .context("expected directory RAM overflow")
            })
            .transpose()?;
        let mut directory_ram = match (&arena, directory_bound) {
            (Some(a), Some(bytes)) => Some(a.reserve_ram(bytes)?),
            _ => None,
        };
        // Declare before Reader so its additional buffer also drops before
        // this payment on every later opening/validation error path.
        let mut second_page_ram = None;
        let mut reader = Reader::open(path, file_sha256, PURPOSE, budget)?;
        if let Some(owner) = &memory {
            if let Some(artifact) = &owner.artifact {
                ensure!(
                    reader.final_path() == artifact.snapshot().final_path
                        && reader.byte_len() == artifact.wire_bytes(),
                    "expected reader changed actual arena file identity"
                );
            }
            if let Some(file) = &owner.reopened {
                ensure!(
                    reader.same_file_as(file)?,
                    "expected reader differs from held recovery file"
                );
            }
        }
        // Only resource-owned Expected readers opt in. Keep legacy/general
        // metadata readers at one page, and avoid paying for a second buffer
        // when the actual authenticated file contains only one page.
        // Prefer every page resident: completion looks objects up in canonical
        // order across all pages, and a two-slot cache then re-reads and
        // re-hashes a page on almost every lookup. Fall back to the second
        // slot only when the arena cannot pay for the whole body.
        if let Some(arena) = &arena {
            if reader.page_count() > 1 {
                // Another reader of the same file may hold them already.
                if !reader.share_resident_pages()
                    && let Ok(lease) = arena.reserve_cache_ram(reader.resident_page_bytes()?)
                {
                    // A cache: given up, with its reservation, when the
                    // run's memory is short.
                    reader.install_resident_pages_paid(Box::new(lease))?;
                }
            }
        }
        if let Some(arena) = &arena {
            if reader.page_count() > 1 && !reader.pages_resident() {
                let capacity = Reader::body_capacity_for_file(budget, reader.byte_len())?;
                let lease = arena.reserve_ram(capacity as u64)?;
                let mut body = Vec::new();
                body.try_reserve_exact(capacity)?;
                ensure!(
                    body.capacity() == capacity,
                    "second Expected cache allocation differs from its prepaid bound"
                );
                reader.install_second_page_cache(body)?;
                second_page_ram = Some(lease);
            }
        }
        ensure!(
            !reader.is_empty(),
            "paged expected tree lacks its scalar header"
        );
        let first = reader.get(0)?;
        ensure!(
            first.key.is_empty(),
            "expected-tree scalar header key differs"
        );
        // Strings and the role-vector can amplify compact JSON. This is an
        // allocation bound from the actual encoded header, not a role count cap.
        let mut header_ram = arena
            .as_ref()
            .map(|a| {
                a.reserve_ram(
                    (first.payload.len() as u64)
                        .checked_mul(32)
                        .and_then(|n| {
                            n.checked_add(std::mem::size_of::<ExpectedTreePageHeader>() as u64)
                        })
                        .context("expected header RAM overflow")?,
                )
            })
            .transpose()?;
        let header: ExpectedTreePageHeader = serde_json::from_slice(&first.payload)?;
        let resource_admission = if allow_original_source_header {
            let current = resource_admission.context("cached expected current limits absent")?;
            let original = header
                .resource_admission
                .context("cached expected original admission absent")?;
            original.validate()?;
            let mut rebound = original;
            rebound.source_inspection_sha256 = current.source_inspection_sha256;
            ensure!(
                original.schema_version == 2 && rebound == current,
                "cached expected original/current shape or wire bounds differ"
            );
            Some(original)
        } else {
            resource_admission
        };
        if let Some(lease) = &mut header_ram {
            let actual = header.internal_replacement_pending.iter().try_fold(
                (std::mem::size_of::<ExpectedTreePageHeader>()
                    + header.profile.capacity()
                    + header.internal_replacement_pending.capacity()
                        * std::mem::size_of::<String>()) as u64,
                |n, s| {
                    n.checked_add(s.capacity() as u64)
                        .context("expected header RAM overflow")
                },
            )?;
            lease.shrink_to(actual)?;
        }
        drop(first);
        ensure!(
            header.schema_version == (if resource_admission.is_some() { 3 } else { 2 })
                && header.resource_admission == resource_admission
                && header
                    .total_objects
                    .checked_add(1)
                    .is_some_and(|n| n <= budget.max_records && n <= reader.len()),
            "expected-tree header/version/complete object count differs"
        );
        usize::try_from(header.total_objects)
            .context("expected-tree object domain exceeds addressable ordinals")?;
        if let Some(admission) = resource_admission {
            ensure!(
                header.total_objects == admission.objects()?
                    && header
                        .total_objects
                        .checked_mul(24)
                        .is_some_and(|n| n <= admission.budget.retained_index_bytes),
                "resource expected index/count exceeds budget"
            );
        }
        let maximum_chunk = chunk_bytes(budget)?;
        let mut directory = Vec::new();
        directory.try_reserve_exact(usize::try_from(header.total_objects)?)?;
        if let Some(lease) = &mut directory_ram {
            lease.shrink_to(
                (directory.capacity() as u64)
                    .checked_mul(std::mem::size_of::<ObjectEntry>() as u64)
                    .context("expected directory capacity overflow")?,
            )?;
        }
        if let Some(admission) = resource_admission {
            ensure!(
                (directory.capacity() as u64)
                    .checked_mul(24)
                    .is_some_and(|n| n <= admission.budget.retained_index_bytes),
                "actual expected index allocation exceeds resource budget"
            );
        }
        let mut cursor = 1u64;
        let mut total_compact = 0u64;
        for ordinal in 0..header.total_objects {
            let start = cursor;
            let mut chunks = 0u64;
            let mut bytes = 0u64;
            let mut previous = maximum_chunk;
            while cursor < reader.len() {
                let entry = reader.get(cursor)?;
                ensure!(entry.key.len() == 16, "object chunk key length differs");
                let actual = u64::from_be_bytes(entry.key[..8].try_into()?);
                if actual != ordinal {
                    ensure!(
                        chunks > 0 && actual == ordinal + 1,
                        "object chunk domain is incomplete or unordered"
                    );
                    break;
                }
                ensure!(
                    entry.key.as_slice() == object_key(ordinal, chunks)
                        && previous == maximum_chunk,
                    "object chunk key or nonfinal size differs"
                );
                let raw = decode_chunk(&entry.payload, maximum_chunk)?;
                previous = raw.len();
                bytes = bytes
                    .checked_add(raw.len() as u64)
                    .filter(|n| {
                        *n <= semantic_byte_budget
                            && resource_admission.is_none_or(|a| *n <= a.budget.max_row_bytes)
                    })
                    .context("object exceeds semantic/decoded resource budget")?;
                chunks = chunks
                    .checked_add(1)
                    .context("object chunk count overflow")?;
                cursor += 1;
            }
            ensure!(chunks > 0, "object has no complete JSON chunks");
            total_compact = total_compact
                .checked_add(bytes)
                .filter(|n| *n <= semantic_byte_budget)
                .context("object domain exceeds legacy semantic budget")?;
            directory.push(ObjectEntry {
                start,
                chunks,
                bytes,
            });
        }
        ensure!(
            cursor == reader.len(),
            "extra objects or chunks outside expected domain"
        );
        let mut view = Self {
            reader: RefCell::new(reader),
            alias_projection: RefCell::new(None),
            alias_projection_lookups: Cell::new(0),
            input_digest: n2r_win32::shadow_native::input_domain::InputDigestMemo::new(),
            decoded: DecodedCache::registered(),
            header,
            counts: ExpectedTreePageCounts::default(),
            file_sha256: file_sha256.into(),
            semantic_sha256: legacy_semantic_sha256.unwrap_or_default().into(),
            budget,
            semantic_byte_budget,
            directory,
            resource_admission,
            binding: None,
            _binding_artifact: None,
            live_rebind_source: None,
            cached_body_pending: false,
            _binding_ram: None,
            arena,
            _artifact: memory.as_mut().and_then(|owner| owner.artifact.take()),
            _reopened_file: memory.and_then(|owner| owner.reopened),
            _reopened_binding: None,
            _reader_ram: reader_ram,
            _second_page_ram: second_page_ram,
            _directory_ram: directory_ram,
            _header_ram: header_ram,
        };
        // The file this process's creation has just written, pinned by what
        // that creation derived of it: in a run that verifies once, those
        // stand for deriving them again (see `CreatedHere`).
        // Where they are not taken, the objects the creation decoded are
        // given up here, before the opening decodes them again.
        let created = created.filter(|(created, _)| {
            n2r_win32::verify_policy::verifies_once()
                && created.decoded_back
                && !allow_original_source_header
                && view.reader.borrow().written_by_this_process()
                && created.file_sha256 == file_sha256
                && legacy_semantic_sha256 == Some(created.semantic_sha256.as_str())
                && created.budget == budget
                && created.semantic_byte_budget == semantic_byte_budget
                && created.resource_admission == view.resource_admission
                && created.counts.objects == view.header.total_objects
        });
        if let Some((created, decoded)) = created {
            view.semantic_sha256 = created.semantic_sha256.clone();
            view.counts = created.counts;
            if let Some(decoded) = decoded {
                view.decoded = decoded;
            }
        } else {
            let counts = Cell::new(ExpectedTreePageCounts::default());
            let mut semantic = SemanticHash::new(semantic_byte_budget)?;
            write_legacy_json(
                &mut semantic,
                &LegacyView {
                    tree: &view,
                    counts: Some(&counts),
                },
            )?;
            let derived_semantic_sha256 = semantic.finish()?;
            ensure!(
                legacy_semantic_sha256.is_none_or(|expected| derived_semantic_sha256 == expected),
                "paged objects do not reproduce the pinned legacy expectation JSON"
            );
            view.semantic_sha256 = derived_semantic_sha256;
            view.counts = counts.get();
        }
        ensure!(
            view.counts.objects == view.header.total_objects,
            "typed object count differs from the complete header domain"
        );
        if let Some(admission) = resource_admission {
            admission.validate_tree(
                view.counts.files,
                view.counts.directories,
                view.counts.data_streams,
            )?;
        }
        Ok(view)
    }

    pub fn header(&self) -> &ExpectedTreePageHeader {
        &self.header
    }
    pub fn counts(&self) -> ExpectedTreePageCounts {
        self.counts
    }
    pub fn len(&self) -> usize {
        self.header.total_objects as usize
    }
    pub fn is_empty(&self) -> bool {
        self.header.total_objects == 0
    }
    pub fn profile(&self) -> &str {
        &self.header.profile
    }
    pub fn logical_bytes(&self) -> u64 {
        self.header.logical_bytes
    }
    pub fn internal_replacement_pending(&self) -> &[String] {
        &self.header.internal_replacement_pending
    }
    pub fn file_sha256(&self) -> &str {
        &self.file_sha256
    }
    /// The actual constructor-held file owner, never a serialized page pin.
    pub(crate) fn artifact_lease(&self) -> Option<&crate::artifact_arena::ArtifactLease> {
        self._artifact.as_ref()
    }
    pub fn semantic_sha256(&self) -> &str {
        &self.semantic_sha256
    }
    pub fn budget(&self) -> PageBudget {
        self.budget
    }
    pub fn semantic_byte_budget(&self) -> u64 {
        self.semantic_byte_budget
    }
    pub fn byte_len(&self) -> u64 {
        self.reader.borrow().byte_len()
    }
    pub fn final_path(&self) -> String {
        self.reader.borrow().final_path().to_owned()
    }
    pub fn page_count(&self) -> u64 {
        self.reader.borrow().page_count()
    }

    pub fn object(&self, index: usize) -> Result<Object> {
        let _working = self.reserve_decode_ram(index)?;
        Ok((*self.decode_object(index)?).clone())
    }
    /// The workspace for decoding object `index`.
    ///
    /// Its size follows the object: eight times the compact bytes its
    /// directory entry states (the compact buffer, the preflight and the
    /// typed decoder; object_memory_bytes and MemorySeed charge compact bytes
    /// before they accept a decoded allocation), three pages for the chunks
    /// it is read through, and a fixed allowance for the decoded object's own
    /// structure. It used to be eight times the largest row the budget
    /// admits, which is a sixty-fourth of the run's memory: every decoding
    /// reserved an eighth of the whole ledger, 566 MB on a machine with 9 GB
    /// and 1.8 GB on one with 24, for an object of a few hundred bytes. That
    /// was the reservation a batch's workspaces starved (#150), and the
    /// largest part of what a run needed whatever its volume held (#129).
    fn reserve_decode_ram(
        &self,
        index: usize,
    ) -> Result<Option<crate::artifact_arena::ArenaRamLease>> {
        let Some(arena) = &self.arena else {
            return Ok(None);
        };
        let admission = self
            .resource_admission
            .context("expected arena row lacks admission")?;
        ensure!(
            index < self.len(),
            "expected-tree ordinal outside complete object domain"
        );
        let compact = self.directory[index].bytes;
        ensure!(
            compact <= admission.budget.max_row_bytes,
            "resource object compact bytes exceed budget"
        );
        let bytes = compact
            .checked_mul(8)
            .and_then(|n| n.checked_add(u64::from(self.budget.max_page_bytes) * 3))
            .and_then(|n| n.checked_add(DECODED_OBJECT_ALLOWANCE))
            .context("expected row decode RAM overflow")?;
        Ok(Some(arena.reserve_ram(bytes)?))
    }
    pub fn object_leased(&self, index: usize) -> Result<LeasedExpectedObject> {
        let mut ram = self
            .reserve_decode_ram(index)?
            .context("actual shared expected memory owner required")?;
        let object = self.decode_object(index)?;
        let bytes = object_memory_bytes(
            &object,
            0,
            self.resource_admission
                .context("expected admission absent")?
                .budget
                .max_row_bytes,
        )?;
        // Keep room for the two native source-run/name views made from this
        // object while its lease is alive, as well as its own exact capacities.
        let keep = bytes
            .checked_mul(3)
            .context("expected leased native-view RAM overflow")?;
        // A decoded object can hold more than its compact bytes suggest (a
        // deep path of one-letter names costs a String a component): what
        // it holds beyond the decoding workspace is reserved now.
        let more = match keep.checked_sub(ram.bytes()) {
            Some(more) if more > 0 => Some(
                self.arena
                    .as_ref()
                    .context("actual shared expected memory owner required")?
                    .reserve_ram(more)?,
            ),
            _ => {
                ram.shrink_to(keep)?;
                None
            }
        };
        Ok(LeasedExpectedObject {
            object,
            _ram: ram,
            _more: more,
        })
    }
    /// Object `first` and the objects after it, for a pass that hands a batch
    /// of objects to helper threads and takes them in order afterwards.
    ///
    /// The first is leased as [`Self::object_leased`] leases it, and what
    /// that fails with is the caller's error. Every further object is
    /// decoded the same way, with the same workspace and the same lease on
    /// what it keeps, but from memory the pass can do without
    /// (`ArtifactArena::reserve_spare_ram`): the batch ends before an object
    /// the ledger has no spare room for, and before one that does not
    /// decode, which the caller then asks for again as the first of its next
    /// batch and is told about there. `more` is asked, with the object just
    /// gathered, whether the caller wants another.
    pub fn objects_leased_at_once(
        &self,
        first: usize,
        mut more: impl FnMut(&Object) -> bool,
    ) -> Result<Vec<LeasedExpectedObject>> {
        let mut objects = vec![self.object_leased(first)?];
        let (Some(arena), Some(admission)) = (&self.arena, self.resource_admission) else {
            return Ok(objects);
        };
        let row = admission.budget.max_row_bytes;
        for index in first + 1..self.len() {
            if !objects.last().is_some_and(|object| more(object)) {
                break;
            }
            // The workspace of `reserve_decode_ram`, and then what
            // `object_leased` keeps of it.
            let compact = self.directory[index].bytes;
            let Some(workspace) = compact
                .checked_mul(8)
                .and_then(|n| n.checked_add(u64::from(self.budget.max_page_bytes) * 3))
                .and_then(|n| n.checked_add(DECODED_OBJECT_ALLOWANCE))
                .filter(|_| compact <= row)
            else {
                break;
            };
            let Ok(mut ram) = arena.reserve_spare_ram(workspace) else {
                break;
            };
            let Ok(object) = self.decode_object(index) else {
                break;
            };
            let Some(keep) = object_memory_bytes(&object, 0, row)
                .ok()
                .and_then(|bytes| bytes.checked_mul(3))
            else {
                break;
            };
            let more_ram = match keep.checked_sub(ram.bytes()) {
                Some(beyond) if beyond > 0 => match arena.reserve_spare_ram(beyond) {
                    Ok(lease) => Some(lease),
                    Err(_) => break,
                },
                _ => {
                    if ram.shrink_to(keep).is_err() {
                        break;
                    }
                    None
                }
            };
            objects.push(LeasedExpectedObject {
                object,
                _ram: ram,
                _more: more_ram,
            });
        }
        Ok(objects)
    }
    /// Snapshot only: no file reads, allocations or per-record logging. These
    /// counters are diagnostic and never replace authentication/owner checks.
    pub fn page_cache_statistics(&self) -> n2r_win32::metadata_pages::PageCacheStatistics {
        self.reader.borrow().page_cache_statistics()
    }
    pub fn alias_projection_statistics(&self) -> AliasProjectionStatistics {
        let projection = self.alias_projection.borrow();
        AliasProjectionStatistics {
            objects: projection
                .as_ref()
                .map_or(0, |value| value.rows.len() as u64),
            encoded_path_bytes: projection.as_ref().map_or(0, |value| value.path_bytes),
            lookups: self.alias_projection_lookups.get(),
        }
    }
    fn build_alias_projection(&self) -> Result<AliasProjection> {
        let admission = self
            .resource_admission
            .context("alias projection resource owner absent")?;
        let arena = self
            .arena
            .as_ref()
            .context("alias projection shared payer absent")?;
        self.require_resource_owner(admission)?;
        // Pay only the actual ordinal table and then each observed encoded
        // path size. There is no maximum-row-times-object-count allocation.
        let row_bytes = self
            .len()
            .checked_mul(std::mem::size_of::<AliasProjectionRow>())
            .and_then(|n| n.checked_add(std::mem::size_of::<AliasProjection>()))
            .context("alias ordinal projection RAM overflow")?;
        let ram = arena.reserve_ram(row_bytes as u64)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.len())?;
        ensure!(
            rows.capacity()
                .checked_mul(std::mem::size_of::<AliasProjectionRow>())
                .and_then(|n| n.checked_add(std::mem::size_of::<AliasProjection>()))
                .is_some_and(|n| n <= row_bytes),
            "alias ordinal allocation exceeds its payment"
        );
        let mut path_bytes = 0u64;
        for index in 0..self.len() {
            let object = self.object_leased(index)?;
            let length = alias_path_bytes(&object)?;
            let row_ram = arena.reserve_ram(length as u64)?;
            let mut paths = Vec::new();
            paths.try_reserve_exact(length)?;
            ensure!(
                paths.capacity() == length,
                "alias path allocation exceeds its exact payment"
            );
            let count = object
                .additional_names
                .len()
                .checked_add(1)
                .context("alias name count overflow")?;
            paths.extend_from_slice(&(count as u64).to_le_bytes());
            for path in std::iter::once(&object.path).chain(&object.additional_names) {
                paths.extend_from_slice(&(path.len() as u64).to_le_bytes());
                for part in path {
                    paths.extend_from_slice(&(part.len() as u64).to_le_bytes());
                    paths.extend_from_slice(part.as_bytes());
                }
            }
            ensure!(
                paths.len() == length,
                "alias path projection size changed after admission"
            );
            path_bytes = path_bytes
                .checked_add(length as u64)
                .context("alias path total overflow")?;
            rows.push(AliasProjectionRow {
                paths,
                directory: object.directory,
                is_reparse: object.reparse.is_some(),
                _ram: row_ram,
            });
        }
        self.require_resource_owner(admission)?;
        Ok(AliasProjection {
            rows,
            path_bytes,
            _ram: ram,
        })
    }
    pub(crate) fn with_alias_shape<T>(
        &self,
        index: usize,
        visit: impl FnOnce(
            &dyn n2r_win32::shadow_native::input_domain::AliasObjectShape,
        ) -> io::Result<T>,
    ) -> io::Result<T> {
        if index >= self.len() || self.cached_body_pending {
            return Err(io::Error::other(
                "alias lookup requires a complete bound Expected ordinal",
            ));
        }
        if self.arena.is_none() {
            let object = self.object(index).map_err(io::Error::other)?;
            return visit(
                &n2r_win32::shadow_native::input_domain::AliasObjectShapeRef {
                    components: &object.path,
                    additional_names: &object.additional_names,
                    directory: object.directory,
                    is_reparse: object.reparse.is_some(),
                },
            );
        }
        let needs_projection = self.alias_projection.borrow().is_none();
        if needs_projection {
            let projection = self.build_alias_projection().map_err(io::Error::other)?;
            *self.alias_projection.borrow_mut() = Some(projection);
        }
        let projection = self.alias_projection.borrow();
        let row = projection
            .as_ref()
            .and_then(|value| value.rows.get(index))
            .ok_or_else(|| io::Error::other("held alias projection ordinal absent"))?;
        self.alias_projection_lookups
            .set(self.alias_projection_lookups.get().saturating_add(1));
        visit(row)
    }
    pub(crate) fn require_shared_memory(
        &self,
        arena: &crate::artifact_arena::ArtifactArena,
    ) -> Result<()> {
        ensure!(
            !self.cached_body_pending
                && self
                    .arena
                    .as_ref()
                    .is_some_and(|owned| owned.same_arena(arena))
                && self._artifact.is_some()
                && self._reader_ram.is_some()
                && self._directory_ram.is_some()
                && self._header_ram.is_some(),
            "expected pages lack actual shared arena/index/cache memory ownership"
        );
        Ok(())
    }
    /// Whether decoded objects are kept and served again: on the arena-owned
    /// resource route, under the check-once policy, outside its gate.
    fn keeps_decoded(&self) -> bool {
        self.arena.is_some()
            && self.resource_admission.is_some()
            && !self.cached_body_pending
            && !n2r_win32::verify_policy::full_unremembered()
    }
    fn keep_decoded(&self, index: usize, object: &Arc<Object>) {
        let (Some(arena), Some(admission)) = (&self.arena, self.resource_admission) else {
            return;
        };
        self.decoded.keep(
            arena,
            admission.budget.max_row_bytes,
            self.len(),
            index,
            object,
        );
    }
    fn decode_object(&self, index: usize) -> Result<Arc<Object>> {
        ensure!(
            index < self.len(),
            "expected-tree ordinal outside complete object domain"
        );
        let keeps = self.keeps_decoded();
        if keeps
            && let Some(object) = self
                .decoded
                .0
                .borrow()
                .rows
                .get(index)
                .and_then(Option::as_ref)
        {
            self.decoded.1.set(n2r_win32::evict::now());
            return Ok(Arc::clone(object));
        }
        let object = Arc::new(self.decode_object_from_pages(index)?);
        if keeps {
            self.keep_decoded(index, &object);
        }
        Ok(object)
    }
    fn decode_object_from_pages(&self, index: usize) -> Result<Object> {
        let entry = self.directory[index];
        let chunks = || ChunkReader {
            tree: self,
            object: index as u64,
            entry,
            next: 0,
            loaded: 0,
            buffer: Vec::new(),
            position: 0,
        };
        if let Some(admission) = self.resource_admission {
            ensure!(
                entry.bytes <= admission.budget.max_row_bytes,
                "resource object compact bytes exceed budget"
            );
        }
        // Both callers prepay reserve_decode_ram before entering this private
        // decoder. For an actual arena-owned row, retain exactly its admitted
        // compact bytes so the two validation passes need only one authenticated
        // chunk/base64 read. Legacy and non-arena owners keep the streaming path.
        let compact = if self.arena.is_some() && self.resource_admission.is_some() {
            let length =
                usize::try_from(entry.bytes).context("compact object exceeds address space")?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length)?;
            ensure!(
                bytes.capacity() == length,
                "compact object allocation exceeds its paid byte count"
            );
            bytes.resize(length, 0);
            {
                let mut source = chunks();
                source
                    .read_exact(&mut bytes)
                    .context("read complete bounded expected-object chunks")?;
                // Exercise ChunkReader's complete chunk-count/byte-count gate,
                // including a malformed extra chunk after the declared bytes.
                let mut extra = [0u8; 1];
                ensure!(
                    source.read(&mut extra)? == 0,
                    "expected object has bytes beyond its authenticated directory row"
                );
            }
            Some(bytes)
        } else {
            None
        };
        if let Some(bytes) = compact {
            return decode_compact_object(
                &bytes,
                self.resource_admission
                    .map(|admission| admission.budget.max_row_bytes),
            );
        }
        // Legacy and non-arena owners decode while they read the chunks,
        // with the same pre-check (see `decode_compact_object`).
        if let Some(admission) = self
            .resource_admission
            .filter(|admission| !decoded_cannot_exceed(entry.bytes, admission.budget.max_row_bytes))
        {
            let used = Cell::new(
                entry
                    .bytes
                    .checked_add(std::mem::size_of::<Object>() as u64)
                    .context("object memory counter overflow")?,
            );
            let seed = MemorySeed {
                kind: MemoryKind::Object,
                used: &used,
                limit: admission.budget.max_row_bytes,
            };
            let mut decoder = serde_json::Deserializer::from_reader(chunks());
            serde::de::DeserializeSeed::deserialize(seed, &mut decoder)?;
            decoder.end()?;
        }
        let object: Object = serde_json::from_reader(chunks())
            .context("decode complete expected-tree object chunks")?;
        if let Some(admission) = self.resource_admission {
            check_object_memory(&object, entry.bytes, admission.budget.max_row_bytes)?;
        }
        Ok(object)
    }

    pub fn require_resource_owner(
        &self,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<()> {
        admission.validate()?;
        ensure!(
            !self.cached_body_pending
                && self.resource_admission == Some(admission)
                && self.budget == admission.expected_page_budget()?
                && self.semantic_byte_budget == admission.semantic_byte_budget(),
            "expected resource page owner differs from admission"
        );
        admission.validate_tree(
            self.counts.files,
            self.counts.directories,
            self.counts.data_streams,
        )?;
        self.revalidate()
    }

    pub fn revalidate(&self) -> Result<()> {
        if let Some(binding) = &self._binding_artifact {
            binding.revalidate()?;
        }
        if let Some((file, snapshot, modified)) = &self._reopened_binding {
            let pin = self
                .binding
                .as_ref()
                .context("reopened expected binding pin absent")?;
            ensure!(
                n2r_win32::reference_file::observe_reference_file_handle_with_limit(file, 65536)?
                    == *snapshot
                    && file.metadata()?.modified()? == *modified,
                "reopened expected binding identity/time changed"
            );
            let mut duplicate = file.try_clone()?;
            ensure!(
                hex::encode(n2r_win32::metadata_pages::pinning_digest(
                    &mut duplicate,
                    pin.bytes
                )?) == pin.sha256,
                "reopened expected binding complete hash changed"
            );
        }
        let mut reader = self.reader.borrow_mut();
        reader.revalidate()?;
        if let Some(file) = &self._reopened_file {
            ensure!(
                reader.same_file_as(file)?,
                "held recovered expected file changed"
            );
        }
        Ok(())
    }
    pub(crate) fn require_recovery_memory(
        &self,
        arena: &crate::artifact_arena::ArtifactArena,
    ) -> Result<()> {
        ensure!(
            self._artifact.is_none()
                && self._reopened_file.is_some()
                && self.arena.as_ref().is_some_and(|a| a.same_arena(arena))
                && self._reader_ram.is_some()
                && self._directory_ram.is_some()
                && self._header_ram.is_some(),
            "recovered expected pages lack live reader/index/header accounting"
        );
        self.revalidate()
    }
    pub fn copy_to(&self, path: &Path) -> Result<()> {
        self.reader.borrow_mut().copy_to(path)?;
        Ok(())
    }
    pub fn validate_with_resource_profile(
        &self,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<()> {
        super::validate_expected_domain(self, resources)
    }
}

impl PagedExpectedTree {
    pub(crate) fn input_digest_memo(
        &self,
    ) -> &n2r_win32::shadow_native::input_domain::InputDigestMemo {
        &self.input_digest
    }
}
impl ExpectedObjectDomain for PagedExpectedTree {
    fn object_count(&self) -> usize {
        self.len()
    }
    fn object(&self, index: usize) -> Result<Cow<'_, Object>> {
        PagedExpectedTree::object(self, index).map(Cow::Owned)
    }
    fn profile(&self) -> &str {
        PagedExpectedTree::profile(self)
    }
    fn logical_bytes(&self) -> u64 {
        PagedExpectedTree::logical_bytes(self)
    }
    fn internal_replacement_pending(&self) -> &[String] {
        PagedExpectedTree::internal_replacement_pending(self)
    }
    fn require_resource_metadata(
        &self,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<()> {
        self.require_resource_owner(admission)
    }
    fn revalidate_domain(&self) -> Result<()> {
        self.revalidate()
    }
    fn require_paged_metadata(&self, budget: PageBudget, semantic: u64) -> Result<()> {
        ensure!(
            self.budget == budget && self.semantic_byte_budget == semantic,
            "paged expected metadata owner differs from source resource admission"
        );
        self.revalidate()
    }
}

/// Borrow the live inline or paged owner without materializing a new tree.
pub(crate) enum ExpectedTreeView<'a> {
    Inline(&'a ExpectedTree),
    Paged(&'a PagedExpectedTree),
}
impl Serialize for ExpectedTreeView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Inline(tree) => tree.serialize(serializer),
            Self::Paged(tree) => tree.serialize(serializer),
        }
    }
}
impl ExpectedObjectDomain for ExpectedTreeView<'_> {
    fn object_count(&self) -> usize {
        match self {
            Self::Inline(tree) => tree.objects.len(),
            Self::Paged(tree) => tree.len(),
        }
    }
    fn object(&self, index: usize) -> Result<Cow<'_, Object>> {
        match self {
            Self::Inline(tree) => tree
                .objects
                .get(index)
                .map(Cow::Borrowed)
                .context("inline expected object ordinal absent"),
            Self::Paged(tree) => tree.object(index).map(Cow::Owned),
        }
    }
    fn profile(&self) -> &str {
        match self {
            Self::Inline(tree) => &tree.profile,
            Self::Paged(tree) => tree.profile(),
        }
    }
    fn logical_bytes(&self) -> u64 {
        match self {
            Self::Inline(tree) => tree.logical_bytes,
            Self::Paged(tree) => tree.logical_bytes(),
        }
    }
    fn internal_replacement_pending(&self) -> &[String] {
        match self {
            Self::Inline(tree) => &tree.internal_replacement_pending,
            Self::Paged(tree) => tree.internal_replacement_pending(),
        }
    }
    fn require_resource_metadata(
        &self,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<()> {
        match self {
            Self::Inline(tree) => tree.require_resource_metadata(admission),
            Self::Paged(tree) => tree.require_resource_owner(admission),
        }
    }
    fn revalidate_domain(&self) -> Result<()> {
        match self {
            Self::Inline(_) => Ok(()),
            Self::Paged(tree) => tree.revalidate(),
        }
    }
    fn require_paged_metadata(&self, budget: PageBudget, semantic: u64) -> Result<()> {
        match self {
            Self::Inline(tree) => tree.require_paged_metadata(budget, semantic),
            Self::Paged(tree) => {
                ExpectedObjectDomain::require_paged_metadata(*tree, budget, semantic)
            }
        }
    }
}

/// Field order and value representation deliberately match ExpectedTree's
/// derived serializer; object pages are streamed in the original Vec order.
struct LegacyView<'a> {
    tree: &'a PagedExpectedTree,
    counts: Option<&'a Cell<ExpectedTreePageCounts>>,
}

impl Serialize for LegacyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("ExpectedTree", 4)?;
        fields.serialize_field("profile", self.tree.profile())?;
        fields.serialize_field(
            "objects",
            &ObjectSequence {
                tree: self.tree,
                counts: self.counts,
            },
        )?;
        fields.serialize_field("logical_bytes", &self.tree.header.logical_bytes)?;
        fields.serialize_field(
            "internal_replacement_pending",
            &self.tree.header.internal_replacement_pending,
        )?;
        fields.end()
    }
}

struct ObjectSequence<'a> {
    tree: &'a PagedExpectedTree,
    counts: Option<&'a Cell<ExpectedTreePageCounts>>,
}
impl Serialize for ObjectSequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.tree.len()))?;
        let mut counts = ExpectedTreePageCounts::default();
        for index in 0..self.tree.len() {
            let object = self.tree.object(index).map_err(S::Error::custom)?;
            if self.counts.is_some() {
                counts.include(&object).map_err(S::Error::custom)?;
            }
            sequence.serialize_element(&object)?;
        }
        let result = sequence.end()?;
        if let Some(output) = self.counts {
            output.set(counts);
        }
        Ok(result)
    }
}

impl Serialize for PagedExpectedTree {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        LegacyView {
            tree: self,
            counts: None,
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod created_tests {
    use super::*;

    fn object(record_number: u64, path: &[&str], directory: bool) -> Object {
        Object {
            record_number,
            sequence_number: 1,
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            additional_names: Vec::new(),
            directory,
            stored_times: [1, 2, 3, 4],
            attributes: if directory { 16 } else { 32 },
            ntfs_compression_normalized: false,
            security: (0..=255).collect(),
            api_security: None,
            extended_attributes: None,
            reparse: None,
            case_sensitive: None,
            source_offset: None,
            source_extents: Vec::new(),
            length: if directory { 0 } else { 5 },
            sha256: (!directory).then(|| "ab".repeat(16)),
            source_evidence: None,
            named_streams: Vec::new(),
            sparse: None,
        }
    }

    /// The legacy JSON is byte for byte what serde_json's pretty writer
    /// writes: empty and nested arrays and objects, deeper than the levels
    /// written in one piece, and an expected tree.
    #[test]
    fn the_legacy_formatter_writes_what_the_pretty_writer_writes() {
        use serde_json::json;
        let mut deep = json!(1);
        for level in 0..40 {
            deep = if level % 2 == 0 {
                json!([deep, [], {}, [[]], [{}], 7])
            } else {
                json!({"k": deep, "e": [], "o": {}, "s": "x\n\"y\"", "n": null, "t": true})
            };
        }
        let values = [
            json!(null),
            json!(-3),
            json!("text"),
            json!([]),
            json!({}),
            json!([[]]),
            json!([{}]),
            json!({"a": []}),
            json!({"a": {}}),
            json!([1, [2, []], {"b": [3, {}], "c": {"d": []}}]),
            deep,
        ];
        for value in &values {
            let mut ours = Vec::new();
            write_legacy_json(&mut ours, value).unwrap();
            assert_eq!(
                String::from_utf8(ours).unwrap(),
                serde_json::to_string_pretty(value).unwrap()
            );
        }
        let mut objects = vec![object(5, &[], true), object(40, &["a"], true)];
        let mut file = object(64, &["a", "f"], false);
        file.additional_names = vec![vec!["a".into(), "F~1".into()]];
        file.extended_attributes = Some(Default::default());
        file.source_extents = vec![crate::ntfs_inspect::Extent {
            logical_offset: 0,
            physical_offset: Some(4096),
            length: 8192,
        }];
        objects.push(file);
        let tree = ExpectedTree {
            profile: "test-profile".into(),
            logical_bytes: 5,
            internal_replacement_pending: vec!["root:$TXF_DATA".into()],
            objects,
        };
        let mut ours = Vec::new();
        write_legacy_json(&mut ours, &tree).unwrap();
        assert!(ours == serde_json::to_vec_pretty(&tree).unwrap());
    }

    /// Pieces of any size, across the digest's blocks, give the digest of
    /// the whole, and a piece past the budget is refused as it always was.
    #[test]
    fn the_semantic_digest_takes_pieces_and_refuses_past_its_budget() {
        let text: Vec<u8> = (0..200_000u32).map(|n| b'a' + (n % 26) as u8).collect();
        let mut whole = SemanticHash::new(1 << 20).unwrap();
        for piece in text.chunks(7) {
            whole.write_all(piece).unwrap();
        }
        assert_eq!(whole.finish().unwrap(), hex::encode(Sha256::digest(&text)));
        let mut small = SemanticHash::new(10).unwrap();
        small.write_all(b"0123456789").unwrap();
        let refused = small.write_all(b"x").unwrap_err();
        assert_eq!(
            refused.to_string(),
            "legacy expected-tree JSON exceeds pinned byte budget"
        );
    }

    /// What a creation keeps of its pages for an opening in a run that
    /// verifies once is what an opening derives from them again, and never
    /// part of the receipt's serialized form.
    #[test]
    fn a_creation_derives_what_its_opening_would_derive_again() {
        let directory = tempfile::tempdir().unwrap();
        let mut objects = vec![object(5, &[], true), object(40, &["a"], true)];
        for record in 0..300u64 {
            objects.push(object(64 + record, &["a", &format!("f{record}")], false));
        }
        let tree = ExpectedTree {
            profile: "test-profile".into(),
            logical_bytes: 1500,
            internal_replacement_pending: vec!["root:$TXF_DATA".into()],
            objects,
        };
        let budget = PageBudget {
            max_page_bytes: 64 * 1024,
            max_records_per_page: 1024,
            max_records: 4096,
            max_pages: 1024,
            max_file_bytes: 64 * 1024 * 1024,
        };
        let path = directory.path().join("expected.pages");
        let receipt = PagedExpectedTree::create(&tree, &path, budget).unwrap();
        let created = receipt.created.clone().unwrap();
        assert_eq!(created.file_sha256, receipt.file_sha256);
        assert_eq!(created.semantic_sha256, receipt.semantic_sha256);
        assert_eq!(
            created.semantic_sha256,
            hex::encode(Sha256::digest(serde_json::to_vec_pretty(&tree).unwrap()))
        );
        assert_eq!(
            created.counts,
            ExpectedTreePageCounts {
                objects: 302,
                files: 300,
                directories: 2,
                data_streams: 300,
            }
        );

        let opened = PagedExpectedTree::open(
            &path,
            &receipt.file_sha256,
            &receipt.semantic_sha256,
            budget,
        )
        .unwrap();
        assert_eq!(opened.counts(), created.counts);
        assert_eq!(opened.semantic_sha256(), created.semantic_sha256);

        let written = serde_json::to_value(&receipt).unwrap();
        assert!(!written.as_object().unwrap().contains_key("created"));
    }

    /// A ledger of 256 MiB in `directory`.
    fn arena(directory: &Path) -> crate::artifact_arena::ArtifactArena {
        let ledger = directory.join("ledger");
        std::fs::create_dir(&ledger).unwrap();
        crate::artifact_arena::ArtifactArena::new(
            &ledger,
            n2r_win32::tree_resources::ResourceBudget {
                schema_version: 1,
                ram_bytes: 256 * 1024 * 1024,
                scratch_bytes: 256 * 1024 * 1024,
                page_bytes: 65536,
                max_row_bytes: 65536,
                retained_index_bytes: 16 * 1024 * 1024,
                handle_slots: 1024,
            },
            &[],
        )
        .unwrap()
    }

    /// `object` as written: its compact JSON as the payloads of chunks of
    /// at most `chunk` bytes.
    fn written(ordinal: usize, object: Object, chunk: usize) -> WrittenObject {
        let compact = serde_json::to_vec(&object).unwrap();
        WrittenObject {
            ordinal,
            payloads: compact
                .chunks(chunk)
                .map(|part| crate::ntfs_inspect::paged_storage::encode_raw_chunk(part).unwrap())
                .collect(),
            bytes: compact.len() as u64,
            object: Arc::new(object),
        }
    }

    /// Decoding back refuses, naming the object, what an opening's decoding
    /// would refuse or would not give back as written: chunks that do not
    /// hold the object's bytes, an object that decodes to another, and a
    /// row the allocation pre-check refuses although the object written
    /// was within the row budget.
    #[test]
    fn decoding_back_refuses_what_the_opening_would_not_decode_as_written() {
        let file = object(64, &["a", "f"], false);
        let good = written(7, file.clone(), 100);
        assert!(good.payloads.len() > 1);
        assert_eq!(good.decode(100, Some(65536)).unwrap(), file);

        let mut short = written(7, file.clone(), 100);
        short.payloads.pop();
        let refused = format!("{:#}", short.decode(100, Some(65536)).unwrap_err());
        assert!(
            refused.contains("object 7 (FILE 64)")
                && refused.contains("complete object chunk byte count differs"),
            "{refused}"
        );

        let mut other = written(7, file.clone(), 100);
        other.object = Arc::new(object(65, &["a", "g"], false));
        let refused = format!("{:#}", other.decode(100, Some(65536)).unwrap_err());
        assert!(
            refused.contains("differs from the object written"),
            "{refused}"
        );

        // 1,025 one-letter components: within the budget as held, past it
        // as the pre-check charges a row before decoding it.
        let parts: Vec<String> = (0..1025).map(|_| "a".to_owned()).collect();
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        let deep = object(66, &parts, false);
        let held = serde_json::to_vec(&deep).unwrap().len() as u64;
        check_object_memory(&deep, held, 40_000).unwrap();
        let refused = format!(
            "{:#}",
            written(9, deep, 768 * 1024)
                .decode(768 * 1024, Some(40_000))
                .unwrap_err()
        );
        assert!(
            refused.contains("object 9 (FILE 66)")
                && refused.contains("exceeds resource row budget"),
            "{refused}"
        );
    }

    /// The objects a creation decodes back and keeps for the tree that
    /// opens its pages are what decoding those pages gives, ordinal by
    /// ordinal, on helper threads and by themselves alike, and decoding
    /// them changes nothing of the legacy JSON or of the pages written.
    #[test]
    fn the_objects_a_creation_keeps_are_those_its_pages_decode_to() {
        let directory = tempfile::tempdir().unwrap();
        let mut objects = vec![object(5, &[], true), object(40, &["a"], true)];
        for record in 0..200u64 {
            objects.push(object(64 + record, &["a", &format!("f{record}")], false));
        }
        let tree = ExpectedTree {
            profile: "test-profile".into(),
            logical_bytes: 1000,
            internal_replacement_pending: Vec::new(),
            objects,
        };
        let budget = PageBudget {
            max_page_bytes: 64 * 1024,
            max_records_per_page: 1024,
            max_records: 4096,
            max_pages: 1024,
            max_file_bytes: 64 * 1024 * 1024,
        };
        let first = directory.path().join("first.pages");
        let receipt = PagedExpectedTree::create(&tree, &first, budget).unwrap();
        // A tree that hands out objects of its own, as a projection does.
        let source = PagedExpectedTree::open(
            &first,
            &receipt.file_sha256,
            &receipt.semantic_sha256,
            budget,
        )
        .unwrap();
        let arena = arena(directory.path());
        let wire = wire_budget(budget).unwrap();
        let header = HeaderRef {
            schema_version: 2,
            profile: source.profile(),
            logical_bytes: source.logical_bytes(),
            internal_replacement_pending: source.internal_replacement_pending(),
            total_objects: source.len() as u64,
            resource_admission: None,
        };
        // On helper threads, and on the creation's own thread.
        for (name, workers) in [("threads.pages", 4), ("serial.pages", 1)] {
            let cache = DecodedCache::registered();
            let second = directory.path().join(name);
            let mut pages = CompactObjects::begin(
                &second,
                wire,
                &header,
                budget.max_file_bytes,
                Some(65536),
                Some(DecodeBackTo {
                    cache: &cache,
                    arena: &arena,
                    len: source.len(),
                }),
            )
            .unwrap();
            pages.decode_back.as_mut().unwrap().workers = workers;
            let compact = RefCell::new(Ok(pages));
            let mut json = Vec::new();
            serde_json::to_writer_pretty(
                &mut json,
                &CreationView {
                    tree: &source,
                    compact: &compact,
                },
            )
            .unwrap();
            assert_eq!(json, serde_json::to_vec_pretty(&tree).unwrap());
            let mut compact = compact.into_inner().unwrap();
            compact.finish_decoding_back().unwrap();
            let CompactObjects { writer, counts, .. } = compact;
            assert_eq!(counts, receipt.created.as_ref().unwrap().counts);
            let summary = writer.finish().unwrap();
            let reopened = PagedExpectedTree::open_with_limits(
                &second,
                &summary.sha256,
                &receipt.semantic_sha256,
                wire,
                budget.max_file_bytes,
            )
            .unwrap();
            let kept = cache.0.borrow();
            assert_eq!(kept.rows.len(), tree.objects.len());
            for (index, expected) in tree.objects.iter().enumerate() {
                let held = kept.rows[index].as_deref().expect("every object kept");
                assert_eq!(held, expected);
                assert_eq!(*held, reopened.object(index).unwrap());
            }
        }
    }
}

#[cfg(test)]
mod case_mark_tests {
    use super::*;

    fn directory(case_sensitive: Option<bool>) -> Object {
        Object {
            record_number: 40,
            sequence_number: 2,
            path: vec!["src".into(), "linux".into()],
            additional_names: Vec::new(),
            directory: true,
            stored_times: [1, 2, 3, 4],
            attributes: 16,
            ntfs_compression_normalized: false,
            security: vec![1, 0, 4, 128],
            api_security: None,
            extended_attributes: None,
            reparse: None,
            case_sensitive,
            source_offset: None,
            source_extents: Vec::new(),
            length: 0,
            sha256: None,
            source_evidence: None,
            named_streams: Vec::new(),
            sparse: None,
        }
    }

    /// The decoder that charges a large row's memory refuses a field it
    /// does not know: the mark has to pass it, stated either way.
    fn charged(object: &Object) -> std::result::Result<(), serde_json::Error> {
        let bytes = serde_json::to_vec(object).unwrap();
        let used = Cell::new(0);
        let mut decoder = serde_json::Deserializer::from_slice(&bytes);
        serde::de::DeserializeSeed::deserialize(
            MemorySeed {
                kind: MemoryKind::Object,
                used: &used,
                limit: 1 << 20,
            },
            &mut decoder,
        )?;
        decoder.end()
    }

    #[test]
    fn a_directory_states_its_case_mark_only_where_it_is_carried_over() {
        // A tree that carries no mark is written as it always was, so what
        // was saved before the field existed is the same tree.
        let silent = directory(None);
        let text = serde_json::to_string(&silent).unwrap();
        assert!(!text.contains("case_sensitive"), "{text}");
        assert_eq!(serde_json::from_str::<Object>(&text).unwrap(), silent);
        charged(&silent).unwrap();

        for marked in [true, false] {
            let stated = directory(Some(marked));
            let text = serde_json::to_string(&stated).unwrap();
            assert!(
                text.contains(&format!("\"case_sensitive\":{marked}")),
                "{text}"
            );
            assert_eq!(serde_json::from_str::<Object>(&text).unwrap(), stated);
            assert_ne!(stated, silent);
            charged(&stated).unwrap();
        }
    }

    #[test]
    fn the_new_volume_is_asked_for_the_mark_of_directories_only() {
        use n2r_win32::shadow_native::input_domain::ObjectInput;
        for stated in [None, Some(true), Some(false)] {
            let object = directory(stated);
            assert_eq!(object.input().case_sensitive, stated);
            // A file never states one, whatever its record says.
            let file = Object {
                directory: false,
                attributes: 32,
                ..object
            };
            assert_eq!(file.input().case_sensitive, None);
        }
    }
}
