//! Blocks of walk rows in one authenticated file of this process's own:
//! written a block at a time in ascending order of block number, and read
//! back a block at a time in any order once the file is finished. Nothing
//! but the handle that wrote a file may name it to a reader: the reader is
//! given the SHA-256 and the index the writer returned, never a path or a
//! digest from outside.
//!
//! A block is the JSON array of its rows, cut into chunks that fit a page of
//! [`crate::metadata_pages`]. Each chunk is one record, keyed by the block
//! number and the chunk number (both big-endian, so the records of a block
//! follow one another in the file), whose payload is the chunk in lowercase
//! hexadecimal as a JSON string. The record after a block's last chunk is
//! its end: the same block number with chunk number `u32::MAX`, and the
//! counts of the block's chunks, bytes and rows.
use super::super::ObjectReport;
use crate::metadata_pages::{PageBudget, Reader, Writer};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    path::Path,
};

const PURPOSE: [u8; 8] = *b"N2RROW01";
/// The chunk number of the record that ends a block.
const END: u32 = u32::MAX;
const KEY_BYTES: usize = 12;
/// What a chunk's record takes of its page besides the chunk in hexadecimal:
/// the page's frame, the record's two lengths, its key and two quotes.
const CHUNK_OVERHEAD: u32 = 64 + 8 + KEY_BYTES as u32 + 2;
/// The smallest page that holds the longest end record and its key.
const MIN_PAGE_BYTES: u32 = 256;

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(ok: bool, message: impl FnOnce() -> String) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message())) }
}
/// The bytes of a block's JSON in each of its chunks but the last.
fn chunk_bytes(budget: PageBudget) -> io::Result<usize> {
    budget.validate()?;
    require(budget.max_page_bytes >= MIN_PAGE_BYTES, || {
        format!(
            "a rows file needs pages of {MIN_PAGE_BYTES} bytes or more, not {}",
            budget.max_page_bytes
        )
    })?;
    Ok(((budget.max_page_bytes - CHUNK_OVERHEAD) / 2) as usize)
}
fn key(block: u64, chunk: u32) -> [u8; KEY_BYTES] {
    let mut key = [0; KEY_BYTES];
    key[..8].copy_from_slice(&block.to_be_bytes());
    key[8..].copy_from_slice(&chunk.to_be_bytes());
    key
}
fn decode_key(key: &[u8]) -> Option<(u64, u32)> {
    let key: &[u8; KEY_BYTES] = key.try_into().ok()?;
    Some((
        u64::from_be_bytes(key[..8].try_into().unwrap()),
        u32::from_be_bytes(key[8..].try_into().unwrap()),
    ))
}

/// The record that ends a block.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockEnd {
    chunks: u32,
    bytes: u64,
    rows: u64,
}

/// Where each block of a rows file begins: the ordinal of its first record,
/// in ascending order of block number. Sixteen bytes a block, kept in memory
/// by the owner of the file from its writer to its reader.
#[derive(Clone, Debug, Default)]
pub(super) struct RowsFileIndex {
    blocks: Vec<BlockStart>,
}
#[derive(Clone, Copy, Debug)]
struct BlockStart {
    block: u64,
    first_record: u64,
}
impl RowsFileIndex {
    fn first_record(&self, block: u64) -> Option<u64> {
        self.blocks
            .binary_search_by_key(&block, |start| start.block)
            .ok()
            .map(|at| self.blocks[at].first_record)
    }
}

/// A finished rows file: what its reader is opened with.
#[derive(Clone, Debug)]
pub(super) struct RowsFileSummary {
    /// SHA-256 of the complete file, as [`Writer::finish`] returns it.
    pub(super) sha256: String,
    pub(super) blocks: u64,
    pub(super) rows: u64,
    /// The length of the file.
    pub(super) bytes: u64,
    /// The bytes of the blocks' JSON, before they were cut into records.
    pub(super) row_bytes: u64,
    pub(super) records: u64,
    pub(super) index: RowsFileIndex,
}

pub(super) struct RowsFileWriter {
    writer: Writer,
    chunk_bytes: usize,
    // One chunk of a block's JSON and its record's payload, made once and
    // used for every chunk: writing a block allocates only what serde does
    // for a row and, for every block, one entry of the index.
    chunk: Vec<u8>,
    payload: Vec<u8>,
    index: RowsFileIndex,
    rows: u64,
    row_bytes: u64,
    records: u64,
    // A block that was not written to its end leaves records of a part of
    // it: the file can no longer be finished.
    poisoned: bool,
}
impl RowsFileWriter {
    /// A new file at `path`, which must not exist.
    pub(super) fn new(path: &Path, budget: PageBudget) -> io::Result<Self> {
        let chunk_bytes = chunk_bytes(budget)?;
        let mut chunk = Vec::new();
        chunk
            .try_reserve_exact(chunk_bytes)
            .map_err(io::Error::other)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(2 * chunk_bytes + 2)
            .map_err(io::Error::other)?;
        Ok(Self {
            writer: Writer::new(path, PURPOSE, budget)?,
            chunk_bytes,
            chunk,
            payload,
            index: RowsFileIndex::default(),
            rows: 0,
            row_bytes: 0,
            records: 0,
            poisoned: false,
        })
    }

    /// Writes the rows of `block`, which may be none. A block number that is
    /// not greater than every one written before is refused, and leaves the
    /// file as it was.
    pub(super) fn write_block(&mut self, block: u64, rows: &[ObjectReport]) -> io::Result<()> {
        require(!self.poisoned, || {
            format!("the rows file is incomplete: block {block} cannot be added to it")
        })?;
        if let Some(last) = self.index.blocks.last() {
            require(last.block < block, || {
                format!(
                    "block {block} of the rows file was written after block {}",
                    last.block
                )
            })?;
        }
        self.index.blocks.try_reserve(1).map_err(io::Error::other)?;
        self.poisoned = true;
        let first_record = self.records;
        let mut sink = ChunkSink {
            writer: &mut self.writer,
            chunk_bytes: self.chunk_bytes,
            chunk: &mut self.chunk,
            payload: &mut self.payload,
            block,
            chunks: 0,
            bytes: 0,
        };
        sink.chunk.clear();
        serde_json::to_writer(&mut sink, rows).map_err(|error| {
            let error = io::Error::from(error);
            io::Error::new(
                error.kind(),
                format!("block {block} of the rows file could not be written: {error}"),
            )
        })?;
        if !sink.chunk.is_empty() {
            sink.emit()?;
        }
        let end = BlockEnd {
            chunks: sink.chunks,
            bytes: sink.bytes,
            rows: rows.len() as u64,
        };
        self.writer.push(
            &key(block, END),
            &serde_json::to_vec(&end).map_err(io::Error::other)?,
        )?;
        self.records = add(self.records, u64::from(end.chunks) + 1)?;
        self.rows = add(self.rows, end.rows)?;
        self.row_bytes = add(self.row_bytes, end.bytes)?;
        self.index.blocks.push(BlockStart {
            block,
            first_record,
        });
        self.poisoned = false;
        Ok(())
    }

    /// Closes the file. It can be read from here on, and only with what this
    /// returns.
    pub(super) fn finish(self) -> io::Result<RowsFileSummary> {
        require(!self.poisoned, || {
            "the rows file is incomplete: it cannot be finished".to_owned()
        })?;
        let summary = self.writer.finish()?;
        require(summary.records == self.records, || {
            format!(
                "the rows file holds {} records where {} were written",
                summary.records, self.records
            )
        })?;
        Ok(RowsFileSummary {
            sha256: summary.sha256,
            blocks: self.index.blocks.len() as u64,
            rows: self.rows,
            bytes: summary.bytes,
            row_bytes: self.row_bytes,
            records: self.records,
            index: self.index,
        })
    }
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| io::Error::other("rows file count overflow"))
}

/// Cuts what serde writes of one block into chunk records.
struct ChunkSink<'a> {
    writer: &'a mut Writer,
    chunk_bytes: usize,
    chunk: &'a mut Vec<u8>,
    payload: &'a mut Vec<u8>,
    block: u64,
    chunks: u32,
    bytes: u64,
}
impl ChunkSink<'_> {
    fn emit(&mut self) -> io::Result<()> {
        require(self.chunks < END, || {
            format!(
                "block {} of the rows file has more than {END} chunks",
                self.block
            )
        })?;
        self.payload.clear();
        self.payload.resize(2 * self.chunk.len() + 2, b'"');
        let hex_end = self.payload.len() - 1;
        hex::encode_to_slice(&*self.chunk, &mut self.payload[1..hex_end])
            .map_err(io::Error::other)?;
        self.writer
            .push(&key(self.block, self.chunks), &self.payload[..])?;
        self.chunks += 1;
        self.chunk.clear();
        Ok(())
    }
}
impl Write for ChunkSink<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        self.bytes = add(self.bytes, length as u64)?;
        while !bytes.is_empty() {
            let count = bytes.len().min(self.chunk_bytes - self.chunk.len());
            self.chunk.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.chunk.len() == self.chunk_bytes {
                self.emit()?;
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct RowsFileReader {
    reader: Reader,
    chunk_bytes: usize,
    index: RowsFileIndex,
    // The JSON of the block being read; kept from one block to the next.
    text: Vec<u8>,
}
impl RowsFileReader {
    /// The file at `path` that a writer finished with this `sha256` and
    /// `index`, under the budget it was written with. Any other file is
    /// refused: the whole of it is checked against the SHA-256.
    pub(super) fn open(
        path: &Path,
        sha256: &str,
        budget: PageBudget,
        index: RowsFileIndex,
    ) -> io::Result<Self> {
        let chunk_bytes = chunk_bytes(budget)?;
        let reader = Reader::open(path, sha256, PURPOSE, budget)?;
        // Every block is one chunk or more and its end, in the writer's
        // order from the first record. Where exactly a block begins is
        // checked by the keys of its records when it is read.
        let mut previous = None;
        let mut next = 0u64;
        for start in &index.blocks {
            require(
                previous.is_none_or(|block| block < start.block)
                    && (start.first_record == 0) == previous.is_none()
                    && start.first_record >= next
                    && start
                        .first_record
                        .checked_add(2)
                        .is_some_and(|end| end <= reader.len()),
                || {
                    format!(
                        "the index of the rows file is not of this file at block {}",
                        start.block
                    )
                },
            )?;
            previous = Some(start.block);
            next = start.first_record + 2;
        }
        require(index.blocks.is_empty() == reader.is_empty(), || {
            "the index of the rows file is not of this file".to_owned()
        })?;
        Ok(Self {
            reader,
            chunk_bytes,
            index,
            text: Vec::new(),
        })
    }

    /// The rows of `block`, as they were written and in that order. A block
    /// that was never written is an error.
    pub(super) fn read_block(&mut self, block: u64) -> io::Result<Vec<ObjectReport>> {
        let first = self
            .index
            .first_record(block)
            .ok_or_else(|| invalid(format!("block {block} was never written to the rows file")))?;
        let differs = |what: &str| invalid(format!("block {block} of the rows file {what}"));
        let Self {
            reader,
            chunk_bytes,
            text,
            ..
        } = self;
        text.clear();
        let mut chunks = 0u32;
        // Every chunk but the last is full.
        let mut last_full = true;
        let end = loop {
            let ordinal = add(first, u64::from(chunks))?;
            let end = reader.with_record(ordinal, |key, payload| {
                let (of_block, chunk) =
                    decode_key(key).ok_or_else(|| differs("has a record without its key"))?;
                if of_block != block {
                    return Err(differs("is not where the index has it"));
                }
                if chunk == END {
                    return serde_json::from_slice::<BlockEnd>(payload)
                        .map(Some)
                        .map_err(|error| differs(&format!("has no readable end: {error}")));
                }
                let hex = payload
                    .strip_prefix(b"\"")
                    .and_then(|rest| rest.strip_suffix(b"\""))
                    .filter(|hex| {
                        chunk == chunks
                            && last_full
                            && !hex.is_empty()
                            && hex.len() % 2 == 0
                            && hex.len() / 2 <= *chunk_bytes
                            && hex
                                .iter()
                                .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
                    })
                    .ok_or_else(|| differs(&format!("has a chunk {chunk} that was not written")))?;
                let at = text.len();
                text.try_reserve(hex.len() / 2).map_err(io::Error::other)?;
                text.resize(at + hex.len() / 2, 0);
                hex::decode_to_slice(hex, &mut text[at..]).map_err(io::Error::other)?;
                last_full = hex.len() / 2 == *chunk_bytes;
                Ok(None)
            })?;
            match end {
                Some(end) => break end,
                None => chunks += 1,
            }
        };
        if end.chunks != chunks || chunks == 0 || end.bytes != text.len() as u64 {
            return Err(differs("is not of the length its end records"));
        }
        let rows: Vec<ObjectReport> = serde_json::from_slice(text)
            .map_err(|error| differs(&format!("cannot be read back as rows: {error}")))?;
        if rows.len() as u64 != end.rows {
            return Err(differs("has another number of rows than its end records"));
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        CandidateReport, HardLinkObservation, InitializedRegionPages, NamedStreamReport,
        ObjectReport, sparse_stream,
    };
    use super::*;
    use crate::{
        attestation::{IoctlQuery, Query, SecurityQuery, Snapshot},
        namespace_layout,
        sparse_layout::{LogicalRange, SparseLayout},
    };

    fn snapshot(seed: u8, full: bool) -> Snapshot {
        Snapshot {
            queries: vec![
                Query {
                    class: 18,
                    bytes: vec![seed; 24],
                    native_error: None,
                },
                Query {
                    class: 48,
                    bytes: vec![],
                    native_error: Some(87),
                },
            ],
            security: vec![1, 0, 4, seed],
            security_error: None,
            kernel_security: full.then(|| SecurityQuery {
                bytes: vec![seed, 2],
                native_error: None,
            }),
            extended_attributes: None,
            extended_attributes_error: full.then(|| "no extended attributes".to_owned()),
            reparse: None,
            directory_case_sensitivity: full.then(|| Query {
                class: 23,
                bytes: vec![0; 4],
                native_error: None,
            }),
        }
    }

    fn ioctl(seed: u8, bytes: usize) -> IoctlQuery {
        IoctlQuery {
            code: 0x0009_0284,
            input: vec![seed; 16],
            bytes: (0..bytes).map(|at| (at as u8).wrapping_add(seed)).collect(),
            native_error: (bytes == 0).then_some(38),
        }
    }

    fn retrieval_proof(seed: u8) -> crate::retrieval_paging::Proof {
        crate::retrieval_paging::Proof {
            encoding: crate::retrieval_paging::ENCODING.to_owned(),
            canonical_sha256: "a".repeat(64),
            extent_count: 2,
            virtual_clusters: 9,
            pages: vec![crate::retrieval_paging::PageProof {
                input: vec![0; 8],
                response_header: [seed; 16],
                response_bytes: 48,
                native_error: None,
                response_sha256: "b".repeat(64),
            }],
        }
    }

    fn bitmap_proof(
        seed: u8,
        profile: crate::bitmap_paging::AssemblyProfile,
    ) -> crate::bitmap_paging::Proof {
        crate::bitmap_paging::Proof {
            encoding: "bitmap".to_owned(),
            cluster_count: 64,
            canonical_bitmap_sha256: "d".repeat(64),
            pages: vec![crate::bitmap_paging::PageProof {
                input: vec![0; 16],
                response_header: [seed; 16],
                response_bytes: 24,
                native_error: Some(234),
                response_sha256: "e".repeat(64),
            }],
            assembly_profile: profile,
            streaming: (profile != crate::bitmap_paging::AssemblyProfile::Legacy).then(|| {
                crate::bitmap_paging::StreamingProof {
                    bitmap_data_sha256: "f".repeat(64),
                    page_transcript_sha256: "0".repeat(64),
                    complete_page_count: 1,
                    returned_bytes: 24,
                }
            }),
        }
    }

    fn candidate(seed: u8) -> crate::bitmap_layout::Candidate {
        crate::bitmap_layout::Candidate {
            start_lcn: u64::from(seed) * 8,
            clusters: 3,
            declared_clusters: 3,
            allocated_clusters: 2,
            bitmap_sha256: "1".repeat(64),
        }
    }

    fn sparse(seed: u8) -> sparse_stream::Observation {
        let range = |offset| LogicalRange {
            offset,
            length: 4096,
        };
        sparse_stream::Observation {
            expected: SparseLayout {
                initialized_length: 4096,
                allocated: vec![range(0), range(8192)],
                holes: vec![range(4096)],
            },
            source_initialized_length: 4096,
            numeric_vdl_preservation_claimed: false,
            logical_zero_policy: "source_uninitialized_allocated_bytes_are_normalized_from_logical_zero_reads; final_full_stream_digest_required",
            layout_observation_verifies_logical_zero_bytes: false,
            actual_allocated: vec![range(0), range(8192)],
            allocation_matches: true,
            cached_regions: vec![ioctl(seed, 24)],
            storage_regions: vec![ioctl(seed, 24), ioctl(seed, 0)],
            data_storage_valid: true,
        }
    }

    /// A row with nothing optional in it and `bytes` bytes in each of its
    /// byte fields.
    fn plain_row(name: &str, seed: u8, bytes: usize) -> ObjectReport {
        let blob = |salt: u8| -> Vec<u8> {
            (0..bytes)
                .map(|at| (at as u8).wrapping_mul(31).wrapping_add(seed ^ salt))
                .collect()
        };
        ObjectReport {
            components: vec!["Users".to_owned(), name.to_owned()],
            additional_names: vec![],
            named_streams: vec![],
            sparse: None,
            before: snapshot(seed, false),
            after: snapshot(seed, false),
            logical_sha256: None,
            retrieval: blob(1),
            retrieval_page_proof: None,
            resident_data: false,
            cached_validity: blob(2),
            storage_validity: blob(3),
            cached_validity_pages: None,
            storage_validity_pages: None,
            integrity: blob(4),
            namespace: vec![],
            source_candidate: None,
            streams: blob(5),
        }
    }

    /// A row with every optional and repeated field filled.
    fn full_row(name: &str, seed: u8, bytes: usize) -> ObjectReport {
        let plain = plain_row(name, seed, bytes);
        ObjectReport {
            additional_names: vec![HardLinkObservation {
                components: vec!["Users".to_owned(), format!("{name}~1")],
                before: snapshot(seed, true),
                after: snapshot(seed, false),
                same_file_id: true,
                expected_link_count: 2,
                link_count_matches: true,
            }],
            named_streams: vec![
                NamedStreamReport {
                    name_utf16: "Zone.Identifier".encode_utf16().collect(),
                    expected_sha256: Some("2".repeat(64)),
                    before: snapshot(seed, false),
                    after: snapshot(seed, false),
                    logical_sha256: Some("2".repeat(64)),
                    retrieval: vec![seed; 5],
                    retrieval_page_proof: Some(retrieval_proof(seed)),
                    resident_data: false,
                    cached_validity: vec![1, 2],
                    storage_validity: vec![3],
                    cached_validity_pages: Some(InitializedRegionPages::for_test(
                        8192,
                        1,
                        vec![ioctl(seed, 40)],
                    )),
                    storage_validity_pages: Some(InitializedRegionPages::for_test(
                        8192,
                        2,
                        vec![ioctl(seed, 40), ioctl(seed, 0)],
                    )),
                    integrity: vec![0; 3],
                    sparse: Some(sparse(seed)),
                },
                NamedStreamReport {
                    name_utf16: vec![0xd800, 0x41],
                    expected_sha256: None,
                    before: snapshot(seed, false),
                    after: snapshot(seed, false),
                    logical_sha256: None,
                    retrieval: vec![],
                    retrieval_page_proof: None,
                    resident_data: true,
                    cached_validity: vec![],
                    storage_validity: vec![],
                    cached_validity_pages: None,
                    storage_validity_pages: None,
                    integrity: vec![],
                    sparse: None,
                },
            ],
            sparse: Some(sparse(seed.wrapping_add(1))),
            before: snapshot(seed, true),
            after: snapshot(seed, true),
            logical_sha256: Some("3".repeat(64)),
            retrieval_page_proof: Some(retrieval_proof(seed)),
            resident_data: true,
            cached_validity_pages: Some(InitializedRegionPages::for_test(
                4096,
                1,
                vec![ioctl(seed, 16)],
            )),
            storage_validity_pages: Some(InitializedRegionPages::for_test(
                4096,
                2,
                vec![ioctl(seed, 16)],
            )),
            namespace: vec![
                namespace_layout::Entry {
                    file_id: [seed; 16],
                    name_utf16: "child.txt".encode_utf16().collect(),
                    attributes: 0x20,
                },
                namespace_layout::Entry {
                    file_id: [seed.wrapping_add(1); 16],
                    name_utf16: vec![0xdc00],
                    attributes: 0x10,
                },
            ],
            source_candidate: Some(CandidateReport {
                legacy: candidate(seed),
                metadata_inclusive: candidate(seed.wrapping_add(1)),
                legacy_page_proof: bitmap_proof(
                    seed,
                    crate::bitmap_paging::AssemblyProfile::Legacy,
                ),
                metadata_page_proof: bitmap_proof(
                    seed,
                    crate::bitmap_paging::AssemblyProfile::OneTiB,
                ),
            }),
            ..plain
        }
    }

    /// Pages far smaller than a long row, so that a block is many records.
    const BUDGET: PageBudget = PageBudget {
        max_page_bytes: 4096,
        max_records_per_page: 64,
        max_records: 1 << 20,
        max_pages: 1 << 16,
        max_file_bytes: 1 << 30,
    };

    fn json(rows: &[ObjectReport]) -> Vec<u8> {
        serde_json::to_vec(rows).unwrap()
    }

    /// The blocks of the tests' file, by block number: several rows, no
    /// row, one row longer than many pages, and a gap in the numbers.
    fn blocks() -> Vec<(u64, Vec<ObjectReport>)> {
        vec![
            (
                0,
                vec![
                    full_row("a.txt", 7, 3),
                    plain_row("b", 9, 0),
                    full_row("c.bin", 200, 300),
                ],
            ),
            (1, vec![]),
            (5, vec![plain_row("long", 3, 20_000)]),
            (6, vec![full_row("last", 1, 40), plain_row("z", 2, 16)]),
        ]
    }

    fn write(path: &Path, blocks: &[(u64, Vec<ObjectReport>)]) -> io::Result<RowsFileSummary> {
        let mut writer = RowsFileWriter::new(path, BUDGET)?;
        for (block, rows) in blocks {
            writer.write_block(*block, rows)?;
        }
        writer.finish()
    }

    fn open(path: &Path, summary: &RowsFileSummary) -> io::Result<RowsFileReader> {
        RowsFileReader::open(path, &summary.sha256, BUDGET, summary.index.clone())
    }

    #[test]
    fn a_row_serializes_as_it_did_before_it_could_be_read_back() {
        let json = serde_json::to_string(&[full_row("a.txt", 7, 3), plain_row("b", 9, 0)]).unwrap();
        assert_eq!(json, include_str!("pinned_rows.json").trim_end());
        // And what is read back from that text is written as the same text.
        let rows: Vec<ObjectReport> = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&rows).unwrap(), json);
    }

    #[test]
    fn a_row_with_a_constant_it_was_not_written_with_is_refused() {
        let json = serde_json::to_string(&full_row("a.txt", 7, 3)).unwrap();
        serde_json::from_str::<ObjectReport>(&json).unwrap();
        for known in [
            "native-initialized-region-pages-v1",
            "final_full_stream_digest_required",
        ] {
            assert!(json.contains(known));
            let other = json.replace(known, &format!("{known}x"));
            assert!(serde_json::from_str::<ObjectReport>(&other).is_err());
        }
    }

    #[test]
    fn blocks_are_read_back_as_they_were_written_in_any_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rows.pages");
        let blocks = blocks();
        let summary = write(&path, &blocks).unwrap();
        let rows: u64 = blocks.iter().map(|(_, rows)| rows.len() as u64).sum();
        let row_bytes: u64 = blocks.iter().map(|(_, rows)| json(rows).len() as u64).sum();
        assert_eq!(
            (
                summary.blocks,
                summary.rows,
                summary.row_bytes,
                summary.bytes
            ),
            (4, rows, row_bytes, std::fs::metadata(&path).unwrap().len())
        );
        // The long row is many pages, so its block is many chunk records.
        let long = json(&blocks[2].1).len();
        assert!(long > 20 * BUDGET.max_page_bytes as usize);
        assert!(summary.records > (long / (BUDGET.max_page_bytes as usize / 2)) as u64);
        println!(
            "ROW-SIZES: full row {} bytes of JSON, plain row {} bytes, row with five 20,000-byte fields {} bytes; file {} bytes for {} bytes of JSON",
            json(&[full_row("a.txt", 7, 3)]).len() - 2,
            json(&[plain_row("b", 9, 0)]).len() - 2,
            long - 2,
            summary.bytes,
            summary.row_bytes,
        );

        let mut reader = open(&path, &summary).unwrap();
        // Out of order, and each of them twice.
        for at in [2, 0, 3, 1, 0, 2, 1, 3] {
            let (block, written) = &blocks[at];
            let read = reader.read_block(*block).unwrap();
            assert_eq!(read.len(), written.len());
            assert_eq!(json(&read), json(written), "block {block}");
        }
    }

    #[test]
    fn a_block_that_was_never_written_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rows.pages");
        let summary = write(&path, &blocks()).unwrap();
        let mut reader = open(&path, &summary).unwrap();
        for absent in [2, 4, 7, u64::MAX] {
            let refused = reader.read_block(absent).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
            assert!(refused.to_string().contains("never written"), "{refused}");
        }
        // The reader is as good as it was.
        assert_eq!(reader.read_block(6).unwrap().len(), 2);

        // A file of no block at all is a file, with nothing to read.
        let path = directory.path().join("empty.pages");
        let summary = write(&path, &[]).unwrap();
        assert_eq!((summary.blocks, summary.rows, summary.records), (0, 0, 0));
        let refused = open(&path, &summary).unwrap().read_block(0).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn blocks_are_written_in_ascending_order_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rows.pages");
        let mut writer = RowsFileWriter::new(&path, BUDGET).unwrap();
        let three = vec![plain_row("three", 3, 8)];
        let four = vec![full_row("four", 4, 8)];
        writer.write_block(3, &three).unwrap();
        for late in [3, 2, 0] {
            let refused = writer.write_block(late, &four).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        }
        // A refused block leaves nothing of itself in the file.
        writer.write_block(4, &four).unwrap();
        let summary = writer.finish().unwrap();
        assert_eq!((summary.blocks, summary.rows), (2, 2));
        let mut reader = open(&path, &summary).unwrap();
        assert_eq!(json(&reader.read_block(4).unwrap()), json(&four));
        assert_eq!(json(&reader.read_block(3).unwrap()), json(&three));
        assert!(reader.read_block(2).is_err());
    }

    #[test]
    fn a_file_is_read_only_with_what_its_writer_returned() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rows.pages");
        let summary = write(&path, &blocks()).unwrap();

        // Another SHA-256.
        let mut other = summary.sha256.clone().into_bytes();
        other[0] = if other[0] == b'0' { b'1' } else { b'0' };
        let other = String::from_utf8(other).unwrap();
        let refused = RowsFileReader::open(&path, &other, BUDGET, summary.index.clone());
        assert_eq!(refused.err().unwrap().kind(), io::ErrorKind::InvalidData);

        // Another budget than it was written with.
        let mut budget = BUDGET;
        budget.max_records += 1;
        assert!(
            RowsFileReader::open(&path, &summary.sha256, budget, summary.index.clone()).is_err()
        );

        // The index of another file: one that fits no file of these records,
        // and one that does but has a block where this file has none.
        let other_path = directory.path().join("other.pages");
        let other = write(&other_path, &[(0, vec![]), (1, vec![]), (9, vec![])]).unwrap();
        assert!(
            RowsFileReader::open(&path, &summary.sha256, BUDGET, RowsFileIndex::default()).is_err()
        );
        let mut reader =
            RowsFileReader::open(&path, &summary.sha256, BUDGET, other.index.clone()).unwrap();
        assert_eq!(json(&reader.read_block(0).unwrap()), json(&blocks()[0].1));
        for misplaced in [1, 9] {
            let refused = reader.read_block(misplaced).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        }
        assert!(open(&other_path, &summary).is_err());
    }
}
