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
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const PURPOSE: [u8; 8] = *b"N2REXP01";

/// Record zero contains only the non-object fields and the complete domain size.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedTreePageHeader {
    pub schema_version: u32,
    pub profile: String,
    pub logical_bytes: u64,
    pub internal_replacement_pending: Vec<String>,
    pub total_objects: u64,
}

#[derive(Serialize)]
struct HeaderRef<'a> {
    schema_version: u32,
    profile: &'a str,
    logical_bytes: u64,
    internal_replacement_pending: &'a [String],
    total_objects: u64,
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
/// file and legacy-semantic hashes and complete validation of the actual file.
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
}

pub struct PagedExpectedTree {
    reader: RefCell<Reader>,
    header: ExpectedTreePageHeader,
    counts: ExpectedTreePageCounts,
    file_sha256: String,
    semantic_sha256: String,
    budget: PageBudget,
    semantic_byte_budget: u64,
    directory: Vec<ObjectEntry>,
}

#[derive(Clone, Copy)]
struct ObjectEntry {
    start: u64,
    chunks: u64,
    bytes: u64,
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

struct Base64Bytes<'a>(&'a [u8]);
impl std::fmt::Display for Base64Bytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for value in self.0.chunks(3) {
            let a = value[0];
            let b = value.get(1).copied();
            let c = value.get(2).copied();
            let encoded = [
                ABC[(a >> 2) as usize],
                ABC[(((a & 3) << 4) | (b.unwrap_or(0) >> 4)) as usize],
                b.map_or(b'=', |b| {
                    ABC[(((b & 15) << 2) | (c.unwrap_or(0) >> 6)) as usize]
                }),
                c.map_or(b'=', |c| ABC[(c & 63) as usize]),
            ];
            f.write_str(std::str::from_utf8(&encoded).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for Base64Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
fn decode_chunk(value: &[u8], maximum: usize) -> Result<Vec<u8>> {
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
    for (index, c) in input.chunks_exact(4).enumerate() {
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
}
impl ChunkWriter<'_> {
    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let payload = serde_json::to_vec(&Base64Bytes(&self.buffer)).map_err(io::Error::other)?;
        self.writer
            .push(&object_key(self.object, self.chunks), &payload)?;
        self.chunks = self
            .chunks
            .checked_add(1)
            .ok_or_else(|| io::Error::other("object chunk ordinal overflow"))?;
        self.buffer.clear();
        Ok(())
    }
    fn finish(mut self) -> io::Result<()> {
        self.flush_chunk()?;
        if self.chunks == 0 {
            return Err(io::Error::other("empty object JSON"));
        }
        Ok(())
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

struct SemanticHash {
    sha256: Sha256,
    bytes: u64,
    maximum: u64,
}
impl SemanticHash {
    fn new(maximum: u64) -> Self {
        Self {
            sha256: Sha256::new(),
            bytes: 0,
            maximum,
        }
    }
    fn finish(self) -> String {
        hex::encode(self.sha256.finalize())
    }
}
impl Write for SemanticHash {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| {
                io::Error::other("legacy expected-tree JSON exceeds pinned byte budget")
            })?;
        self.sha256.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl PagedExpectedTree {
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
        budget.validate()?;
        ensure!(
            (1..=i64::MAX as u64).contains(&semantic_byte_budget),
            "invalid expected semantic byte budget"
        );
        let objects = u64::try_from(tree.objects.len())?;
        let records = objects
            .checked_add(1)
            .context("paged expected-tree record count overflow")?;
        ensure!(
            records <= budget.max_records,
            "expected-tree object domain exceeds record budget"
        );
        let mut semantic = SemanticHash::new(semantic_byte_budget);
        serde_json::to_writer_pretty(&mut semantic, tree)?;
        let semantic_sha256 = semantic.finish();
        let header = HeaderRef {
            schema_version: 2,
            profile: &tree.profile,
            logical_bytes: tree.logical_bytes,
            internal_replacement_pending: &tree.internal_replacement_pending,
            total_objects: objects,
        };
        let maximum_chunk = chunk_bytes(budget)?;
        let mut writer = Writer::new(path, PURPOSE, budget)?;
        writer.push(&[], &record(&header, budget)?)?;
        for (ordinal, object) in tree.objects.iter().enumerate() {
            let mut chunks = ChunkWriter {
                writer: &mut writer,
                object: u64::try_from(ordinal)?,
                chunks: 0,
                bytes: 0,
                maximum: semantic_byte_budget,
                buffer: Vec::new(),
                chunk_bytes: maximum_chunk,
            };
            serde_json::to_writer(&mut chunks, object)?;
            chunks.finish()?;
        }
        let summary = writer.finish()?;
        ensure!(
            summary.records >= records,
            "written expected-tree record domain differs"
        );
        Ok(ExpectedTreePageReceipt {
            schema_version: 2,
            path: path.to_owned(),
            file_sha256: summary.sha256,
            semantic_sha256,
            objects,
            records: summary.records,
            pages: summary.pages,
            bytes: summary.bytes,
            page_budget: budget,
            semantic_byte_budget,
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
        ensure!(
            (1..=i64::MAX as u64).contains(&semantic_byte_budget),
            "invalid expected semantic byte budget"
        );
        ensure!(
            canonical_sha(file_sha256) && canonical_sha(legacy_semantic_sha256),
            "canonical file and legacy expectation SHA-256 pins required"
        );
        let mut reader = Reader::open(path, file_sha256, PURPOSE, budget)?;
        ensure!(
            !reader.is_empty(),
            "paged expected tree lacks its scalar header"
        );
        let first = reader.get(0)?;
        ensure!(
            first.key.is_empty(),
            "expected-tree scalar header key differs"
        );
        let header: ExpectedTreePageHeader = serde_json::from_slice(&first.payload)?;
        drop(first);
        ensure!(
            header.schema_version == 2
                && header
                    .total_objects
                    .checked_add(1)
                    .is_some_and(|n| n <= budget.max_records && n <= reader.len()),
            "expected-tree header/version/complete object count differs"
        );
        usize::try_from(header.total_objects)
            .context("expected-tree object domain exceeds addressable ordinals")?;
        let maximum_chunk = chunk_bytes(budget)?;
        let mut directory = Vec::new();
        directory.try_reserve_exact(usize::try_from(header.total_objects)?)?;
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
                    .filter(|n| *n <= semantic_byte_budget)
                    .context("object exceeds legacy semantic budget")?;
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
            header,
            counts: ExpectedTreePageCounts::default(),
            file_sha256: file_sha256.into(),
            semantic_sha256: legacy_semantic_sha256.into(),
            budget,
            semantic_byte_budget,
            directory,
        };
        let counts = Cell::new(ExpectedTreePageCounts::default());
        let mut semantic = SemanticHash::new(semantic_byte_budget);
        serde_json::to_writer_pretty(
            &mut semantic,
            &LegacyView {
                tree: &view,
                counts: Some(&counts),
            },
        )?;
        ensure!(
            semantic.finish() == legacy_semantic_sha256,
            "paged objects do not reproduce the pinned legacy expectation JSON"
        );
        view.counts = counts.get();
        ensure!(
            view.counts.objects == view.header.total_objects,
            "typed object count differs from the complete header domain"
        );
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
        ensure!(
            index < self.len(),
            "expected-tree ordinal outside complete object domain"
        );
        let entry = self.directory[index];
        let chunks = ChunkReader {
            tree: self,
            object: u64::try_from(index)?,
            entry,
            next: 0,
            loaded: 0,
            buffer: Vec::new(),
            position: 0,
        };
        serde_json::from_reader(chunks).context("decode complete expected-tree object chunks")
    }

    pub fn revalidate(&self) -> Result<()> {
        self.reader.borrow_mut().revalidate()?;
        Ok(())
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
