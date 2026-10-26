//! Bounded, read-only retrieval-pointer transcript assembly. File identity,
//! volume bounds, VDL and storage initialization remain independent checks.
use crate::{
    attestation::IoctlQuery,
    stream_layout::{self, Run},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
pub use stream_layout::MAX_COMPLETE_EXTENTS;
pub const PAGE_CAPACITY: usize = stream_layout::RETRIEVAL_CAPACITY;
pub const MAX_PAGES: usize = 128;
pub const MAX_RETURNED_BYTES: usize =
    2 * stream_layout::COMPLETE_RETRIEVAL_CAPACITY + 16 * MAX_PAGES;
pub const MORE_DATA: i32 = 234;
pub const ENCODING: &str = "assembled-zero-vcn-retrieval-v1";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PageProof {
    pub input: Vec<u8>,
    pub response_header: [u8; 16],
    pub response_bytes: usize,
    pub native_error: Option<i32>,
    pub response_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
    pub encoding: String,
    pub canonical_sha256: String,
    pub extent_count: usize,
    pub virtual_clusters: u64,
    pub pages: Vec<PageProof>,
}
#[derive(Debug)]
pub struct Capture {
    pub canonical: Vec<u8>,
    pub runs: Vec<Run>,
    pub proof: Proof,
}
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn end(run: &Run) -> u64 {
    run.vcn + run.clusters
}
fn physical_at(run: &Run, vcn: u64) -> io::Result<Option<u64>> {
    run.lcn
        .map(|lcn| {
            lcn.checked_add(vcn - run.vcn)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or_else(|| bad("retrieval physical mapping overflow"))
        })
        .transpose()
}
fn parse_page(bytes: &[u8]) -> io::Result<Vec<Run>> {
    if !(32..=PAGE_CAPACITY).contains(&bytes.len()) {
        return Err(bad("retrieval page length differs"));
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut vcn = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if count == 0 || count > stream_layout::MAX_EXTENTS || bytes.len() != 16 + 16 * count || vcn < 0
    {
        return Err(bad("retrieval page count/start differs"));
    }
    let mut runs = Vec::with_capacity(count);
    for entry in bytes[16..].as_chunks::<16>().0 {
        let next = i64::from_le_bytes(entry[..8].try_into().unwrap());
        let lcn = i64::from_le_bytes(entry[8..].try_into().unwrap());
        if next <= vcn || lcn < -1 {
            return Err(bad("invalid retrieval page extent"));
        }
        runs.push(Run {
            vcn: vcn as u64,
            lcn: (lcn >= 0).then_some(lcn as u64),
            clusters: (next - vcn) as u64,
        });
        vcn = next;
    }
    Ok(runs)
}
#[derive(Default)]
pub struct Assembler {
    runs: Vec<Run>,
    covered: u64,
    pages: Vec<PageProof>,
    returned: usize,
    complete: bool,
    poisoned: bool,
}
impl Assembler {
    pub fn next_vcn(&self) -> u64 {
        self.covered
    }
    pub fn response_capacity(&self) -> usize {
        if self.complete || self.poisoned || self.pages.len() >= MAX_PAGES {
            return 0;
        }
        let n = (MAX_RETURNED_BYTES - self.returned).min(PAGE_CAPACITY);
        if n < 32 { 0 } else { 16 + (n - 16) / 16 * 16 }
    }
    pub fn push(&mut self, query: &IoctlQuery) -> io::Result<bool> {
        if self.poisoned {
            return Err(bad("retrieval assembler is poisoned"));
        }
        let result = self.push_page(query);
        if result.is_err() {
            self.poisoned = true
        };
        result
    }
    fn push_page(&mut self, query: &IoctlQuery) -> io::Result<bool> {
        if self.complete
            || self.pages.len() >= MAX_PAGES
            || query.code != stream_layout::GET_RETRIEVAL
            || query.input != self.covered.to_le_bytes()
            || self
                .returned
                .checked_add(query.bytes.len())
                .is_none_or(|n| n > MAX_RETURNED_BYTES)
            || query.native_error.is_some_and(|e| e != MORE_DATA)
        {
            return Err(bad("retrieval continuation, status or budget differs"));
        }
        let page = parse_page(&query.bytes)?;
        let page_start = page[0].vcn;
        let page_end = end(page.last().unwrap());
        if page_start > self.covered || page_end <= self.covered {
            return Err(bad("gapped or nonprogressing retrieval response"));
        }
        let original_end = self.covered;
        let mut old_index = self.runs.partition_point(|r| end(r) <= page_start);
        for run in &page {
            let mut overlap = run.vcn;
            let overlap_end = end(run).min(original_end);
            while overlap < overlap_end {
                let old = self
                    .runs
                    .get(old_index)
                    .ok_or_else(|| bad("retrieval overlap has no prior mapping"))?;
                if old.vcn > overlap
                    || end(old) <= overlap
                    || physical_at(old, overlap)? != physical_at(run, overlap)?
                {
                    return Err(bad("retrieval overlap mapping changed"));
                }
                overlap = end(old).min(overlap_end);
                if overlap == end(old) {
                    old_index += 1
                };
            }
            if end(run) > original_end {
                let start = run.vcn.max(original_end);
                let appended = Run {
                    vcn: start,
                    lcn: physical_at(run, start)?,
                    clusters: end(run) - start,
                };
                let merge = self.runs.last().is_some_and(|old| {
                    end(old) == appended.vcn
                        && match (old.lcn, appended.lcn) {
                            (None, None) => true,
                            (Some(a), Some(b)) => a.checked_add(old.clusters) == Some(b),
                            _ => false,
                        }
                });
                if merge {
                    self.runs.last_mut().unwrap().clusters += appended.clusters;
                } else {
                    if self.runs.len() >= MAX_COMPLETE_EXTENTS {
                        return Err(bad("complete retrieval extent budget exceeded"));
                    };
                    self.runs.push(appended);
                }
            }
        }
        self.covered = page_end;
        self.returned += query.bytes.len();
        self.complete = query.native_error.is_none();
        self.pages.push(PageProof {
            input: query.input.clone(),
            response_header: query.bytes[..16].try_into().unwrap(),
            response_bytes: query.bytes.len(),
            native_error: query.native_error,
            response_sha256: hex::encode(Sha256::digest(&query.bytes)),
        });
        Ok(self.complete)
    }
    pub fn finish(self) -> io::Result<Capture> {
        if self.poisoned || !self.complete || self.runs.is_empty() {
            return Err(bad("retrieval capture is incomplete"));
        }
        let mut canonical = Vec::with_capacity(16 + self.runs.len() * 16);
        canonical.extend_from_slice(&(self.runs.len() as u32).to_le_bytes());
        canonical.extend_from_slice(&[0; 12]);
        for run in &self.runs {
            canonical.extend_from_slice(&end(run).to_le_bytes());
            canonical.extend_from_slice(&run.lcn.map_or(-1, |n| n as i64).to_le_bytes());
        }
        let proof = Proof {
            encoding: ENCODING.into(),
            canonical_sha256: hex::encode(Sha256::digest(&canonical)),
            extent_count: self.runs.len(),
            virtual_clusters: self.covered,
            pages: self.pages,
        };
        Ok(Capture {
            canonical,
            runs: self.runs,
            proof,
        })
    }
}
pub fn assemble_queries(first: &IoctlQuery, continuation: &[IoctlQuery]) -> io::Result<Capture> {
    let mut assembler = Assembler::default();
    for query in std::iter::once(first).chain(continuation) {
        assembler.push(query)?;
    }
    assembler.finish()
}
