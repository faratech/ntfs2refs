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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
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
    resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
    arena: Option<crate::artifact_arena::ArtifactArena>,
    _artifact: Option<crate::artifact_arena::ArtifactLease>,
    // A reopened expected domain retains the already authenticated read-only
    // file, but never gains a fresh-created ArtifactLease/source authority.
    _reopened_file: Option<File>,
    _reader_ram: Option<crate::artifact_arena::ArenaRamLease>,
    _directory_ram: Option<crate::artifact_arena::ArenaRamLease>,
    _header_ram: Option<crate::artifact_arena::ArenaRamLease>,
}

struct ExpectedMemoryOwner {
    arena: crate::artifact_arena::ArtifactArena,
    artifact: Option<crate::artifact_arena::ArtifactLease>,
    reopened: Option<File>,
}

/// One decoded object keeps its actual shared-memory lease through all native
/// views/caches. It has no Clone or Deserialize implementation.
pub struct LeasedExpectedObject {
    object: Object,
    _ram: crate::artifact_arena::ArenaRamLease,
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
                | "ntfs_compression_normalized",
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
        let receipt = Self::create_with_resources(tree, permit.path(), admission)?;
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
        Self::create_domain(tree, path, budget, semantic_byte_budget, None)
    }
    pub fn create_with_resources(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
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
        )
    }
    fn create_domain(
        tree: &impl ExpectedObjectDomain,
        path: &Path,
        budget: PageBudget,
        semantic_byte_budget: u64,
        resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
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
        let mut semantic = SemanticHash::new(semantic_byte_budget);
        serde_json::to_writer_pretty(&mut semantic, tree)?;
        let semantic_sha256 = semantic.finish();
        let header = HeaderRef {
            schema_version: if resource_admission.is_some() { 3 } else { 2 },
            profile: tree.profile(),
            logical_bytes: tree.logical_bytes(),
            internal_replacement_pending: tree.internal_replacement_pending(),
            total_objects: objects,
            resource_admission,
        };
        let maximum_chunk = chunk_bytes(budget)?;
        let mut writer = Writer::new(path, PURPOSE, budget)?;
        writer.push(&[], &record(&header, budget)?)?;
        let mut counts = ExpectedTreePageCounts::default();
        for ordinal in 0..tree.object_count() {
            let object = tree.object(ordinal)?;
            counts.include(&object)?;
            if let Some(admission) = resource_admission {
                check_object_memory(&object, 0, admission.budget.max_row_bytes)?;
            }
            let mut chunks = ChunkWriter {
                writer: &mut writer,
                object: u64::try_from(ordinal)?,
                chunks: 0,
                bytes: 0,
                maximum: resource_admission
                    .map_or(semantic_byte_budget, |a| a.budget.max_row_bytes),
                buffer: Vec::new(),
                chunk_bytes: maximum_chunk,
            };
            serde_json::to_writer(&mut chunks, object.as_ref())?;
            if let Some(admission) = resource_admission {
                check_object_memory(&object, chunks.bytes, admission.budget.max_row_bytes)?;
            }
            chunks.finish()?;
        }
        if let Some(admission) = resource_admission {
            admission.validate_tree(counts.files, counts.directories, counts.data_streams)?;
        }
        let summary = writer.finish()?;
        ensure!(
            summary.records >= records,
            "written expected-tree record domain differs"
        );
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
            legacy_semantic_sha256,
            budget,
            semantic_byte_budget,
            resource_admission,
            memory.map(|(arena, artifact)| ExpectedMemoryOwner {
                arena,
                artifact: Some(artifact),
                reopened: None,
            }),
        )
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
            semantic_sha256,
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
            Some(admission),
            Some(ExpectedMemoryOwner {
                arena: arena.clone(),
                artifact: None,
                reopened: Some(file.try_clone()?),
            }),
        )?;
        tree.require_recovery_memory(arena)?;
        Ok(tree)
    }

    fn open_owned_domain(
        path: &Path,
        file_sha256: &str,
        legacy_semantic_sha256: &str,
        budget: PageBudget,
        semantic_byte_budget: u64,
        resource_admission: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
        mut memory: Option<ExpectedMemoryOwner>,
    ) -> Result<Self> {
        ensure!(
            (1..=i64::MAX as u64).contains(&semantic_byte_budget),
            "invalid expected semantic byte budget"
        );
        ensure!(
            canonical_sha(file_sha256) && canonical_sha(legacy_semantic_sha256),
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
            header,
            counts: ExpectedTreePageCounts::default(),
            file_sha256: file_sha256.into(),
            semantic_sha256: legacy_semantic_sha256.into(),
            budget,
            semantic_byte_budget,
            directory,
            resource_admission,
            arena,
            _artifact: memory.as_mut().and_then(|owner| owner.artifact.take()),
            _reopened_file: memory.and_then(|owner| owner.reopened),
            _reader_ram: reader_ram,
            _directory_ram: directory_ram,
            _header_ram: header_ram,
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
        let _working = self.reserve_decode_ram()?;
        self.decode_object(index)
    }
    fn reserve_decode_ram(&self) -> Result<Option<crate::artifact_arena::ArenaRamLease>> {
        let Some(arena) = &self.arena else {
            return Ok(None);
        };
        let admission = self
            .resource_admission
            .context("expected arena row lacks admission")?;
        let bytes = admission
            .budget
            .max_row_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(u64::from(self.budget.max_page_bytes) * 3))
            .context("expected row decode RAM overflow")?;
        Ok(Some(arena.reserve_ram(bytes)?))
    }
    pub fn object_leased(&self, index: usize) -> Result<LeasedExpectedObject> {
        let mut ram = self
            .reserve_decode_ram()?
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
        ram.shrink_to(
            bytes
                .checked_mul(3)
                .context("expected leased native-view RAM overflow")?,
        )?;
        Ok(LeasedExpectedObject { object, _ram: ram })
    }
    pub(crate) fn require_shared_memory(
        &self,
        arena: &crate::artifact_arena::ArtifactArena,
    ) -> Result<()> {
        ensure!(
            self.arena
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
    fn decode_object(&self, index: usize) -> Result<Object> {
        ensure!(
            index < self.len(),
            "expected-tree ordinal outside complete object domain"
        );
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
            let used = Cell::new(
                entry
                    .bytes
                    .checked_add(std::mem::size_of::<Object>() as u64)
                    .context("object memory counter overflow")?,
            );
            let mut decoder = serde_json::Deserializer::from_reader(chunks());
            serde::de::DeserializeSeed::deserialize(
                MemorySeed {
                    kind: MemoryKind::Object,
                    used: &used,
                    limit: admission.budget.max_row_bytes,
                },
                &mut decoder,
            )?;
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
            self.resource_admission == Some(admission)
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
