//! Bounded, read-only retrieval-pointer transcript assembly. File identity,
//! volume bounds, VDL and storage initialization remain independent checks.
use crate::{
    attestation::IoctlQuery,
    stream_layout::{self, Run},
};
use serde::{Deserialize, Serialize};
use std::io;
pub use stream_layout::MAX_COMPLETE_EXTENTS;
pub const PAGE_CAPACITY: usize = stream_layout::RETRIEVAL_CAPACITY;
pub const MAX_PAGES: usize = 128;
pub const MAX_RETURNED_BYTES: usize =
    2 * stream_layout::COMPLETE_RETRIEVAL_CAPACITY + 16 * MAX_PAGES;
/// Pages one complete mapping may take in this process: two for every
/// response's worth of extents, as the fixed 128 are for 65,536.
pub fn max_pages() -> usize {
    (stream_layout::complete_extent_limit() / stream_layout::MAX_EXTENTS * 2).max(MAX_PAGES)
}
/// Bytes one complete mapping's pages and assembled form may take.
pub fn max_returned_bytes() -> usize {
    2 * stream_layout::complete_retrieval_capacity() + 16 * max_pages()
}
/// Bytes the pages and assembled form of one stream's mapping can take, for
/// a stream of `stream_bytes`. A stream cannot be in more extents than it
/// has clusters; the allowance is twice that and one response's worth more,
/// for allocation beyond its end, and never more than the process's limit.
/// A file with hundreds of small named streams is then charged for what
/// those streams can need, not for hundreds of the largest mapping there is.
pub fn returned_bytes_for_stream(stream_bytes: u64) -> usize {
    let clusters = stream_bytes.div_ceil(crate::target_cluster::bytes());
    let extents = usize::try_from(
        clusters
            .saturating_mul(2)
            .saturating_add(stream_layout::MAX_EXTENTS as u64),
    )
    .unwrap_or(usize::MAX)
    .min(stream_layout::complete_extent_limit());
    let pages = (extents / stream_layout::MAX_EXTENTS * 2).max(2);
    2 * (16 + 16 * extents) + 16 * pages
}
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
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_returned_bytes: usize,
    pub max_extents: usize,
    pub max_pages: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_returned_bytes: max_returned_bytes(),
            max_extents: stream_layout::complete_extent_limit(),
            max_pages: max_pages(),
        }
    }
}
impl Limits {
    pub fn for_resource_bytes(bytes: usize) -> io::Result<Self> {
        let per_page = std::mem::size_of::<PageProof>()
            .checked_add(std::mem::size_of::<IoctlQuery>())
            .and_then(|n| n.checked_add(8 + 8 + 64))
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(|| bad("retrieval page resource accounting overflow"))?;
        if bytes / 4 < 32 || bytes / per_page == 0 || bytes / (4 * std::mem::size_of::<Run>()) == 0
        {
            return Err(bad("retrieval resource row has no complete response space"));
        }
        Ok(Self {
            max_returned_bytes: bytes / 4,
            max_extents: (bytes / (4 * std::mem::size_of::<Run>())).min(u32::MAX as usize),
            max_pages: bytes / per_page,
        })
    }
}
#[cfg(test)]
mod limit_tests {
    use super::*;

    /// With no memory budget stated, the limits are the fixed ones the older
    /// profiles have always had. (A route that states a budget raises the
    /// extent count for its process; no test here does.)
    #[test]
    fn a_stream_is_charged_for_the_extents_it_has_room_for() {
        // A stream of a few bytes: one response's worth of extents.
        let small = returned_bytes_for_stream(100);
        assert_eq!(small, 2 * (16 + 16 * 1026) + 16 * 2);
        // A stream too large for the limit to matter is charged the limit.
        assert_eq!(returned_bytes_for_stream(u64::MAX), max_returned_bytes());
        assert_eq!(returned_bytes_for_stream(1 << 40), max_returned_bytes());
        // In between it grows with the stream, and with the cluster size it
        // shrinks: the same bytes are fewer 64 KiB clusters.
        let megabyte = returned_bytes_for_stream(1 << 20);
        assert!(small < megabyte && megabyte < max_returned_bytes());
        crate::target_cluster::with(65536, || {
            assert!(returned_bytes_for_stream(1 << 20) < megabyte);
        });
    }

    #[test]
    fn without_a_budget_the_limits_are_the_fixed_ones() {
        assert_eq!(stream_layout::complete_extent_limit(), MAX_COMPLETE_EXTENTS);
        assert_eq!(max_pages(), MAX_PAGES);
        assert_eq!(max_returned_bytes(), MAX_RETURNED_BYTES);
        let limits = Limits::default();
        assert_eq!(
            (
                limits.max_extents,
                limits.max_pages,
                limits.max_returned_bytes
            ),
            (MAX_COMPLETE_EXTENTS, MAX_PAGES, MAX_RETURNED_BYTES)
        );
    }
}

pub struct Assembler {
    runs: Vec<Run>,
    covered: u64,
    pages: Vec<PageProof>,
    returned: usize,
    complete: bool,
    poisoned: bool,
    limits: Limits,
}
impl Default for Assembler {
    fn default() -> Self {
        Self::with_limits(Limits::default()).expect("fixed retrieval limits")
    }
}
impl Assembler {
    pub fn with_limits(limits: Limits) -> io::Result<Self> {
        if limits.max_returned_bytes < 32
            || limits.max_extents == 0
            || limits.max_extents > u32::MAX as usize
            || limits.max_pages == 0
        {
            return Err(bad("invalid retrieval resource budgets"));
        }
        Ok(Self {
            runs: Vec::new(),
            covered: 0,
            pages: Vec::new(),
            returned: 0,
            complete: false,
            poisoned: false,
            limits,
        })
    }
    pub fn next_vcn(&self) -> u64 {
        self.covered
    }
    pub fn response_capacity(&self) -> usize {
        if self.complete || self.poisoned || self.pages.len() >= self.limits.max_pages {
            return 0;
        }
        let n = (self.limits.max_returned_bytes - self.returned).min(PAGE_CAPACITY);
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
            || self.pages.len() >= self.limits.max_pages
            || query.code != stream_layout::GET_RETRIEVAL
            || query.input != self.covered.to_le_bytes()
            || self
                .returned
                .checked_add(query.bytes.len())
                .is_none_or(|n| n > self.limits.max_returned_bytes)
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
                    if self.runs.len() >= self.limits.max_extents {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "a stream is in more than {} separate extents, the most this run's memory budget allows for one stream's mapping",
                                self.limits.max_extents
                            ),
                        ));
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
            response_sha256: hex::encode(crate::content_digest::sha256(&query.bytes)?),
        });
        Ok(self.complete)
    }
    pub fn finish(self) -> io::Result<Capture> {
        if self.poisoned || !self.complete || self.runs.is_empty() {
            return Err(bad("retrieval capture is incomplete"));
        }
        let count = u32::try_from(self.runs.len()).map_err(io::Error::other)?;
        let bytes = self
            .runs
            .len()
            .checked_mul(16)
            .and_then(|n| n.checked_add(16))
            .ok_or_else(|| bad("canonical retrieval size overflow"))?;
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(bytes)
            .map_err(io::Error::other)?;
        canonical.extend_from_slice(&count.to_le_bytes());
        canonical.extend_from_slice(&[0; 12]);
        for run in &self.runs {
            canonical.extend_from_slice(&end(run).to_le_bytes());
            canonical.extend_from_slice(&run.lcn.map_or(-1, |n| n as i64).to_le_bytes());
        }
        let proof = Proof {
            encoding: ENCODING.into(),
            canonical_sha256: hex::encode(crate::content_digest::sha256(&canonical)?),
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
    assemble_queries_with_limits(first, continuation, Limits::default())
}
pub fn assemble_queries_with_limits(
    first: &IoctlQuery,
    continuation: &[IoctlQuery],
    limits: Limits,
) -> io::Result<Capture> {
    let mut assembler = Assembler::with_limits(limits)?;
    for query in std::iter::once(first).chain(continuation) {
        assembler.push(query)?;
    }
    assembler.finish()
}
