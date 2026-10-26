//! Complete, bounded assembly of native volume-bitmap responses.
//! Raw responses stay separate from the explicitly normalized bitmap view.
use crate::{attestation::IoctlQuery, stream_layout::GET_BITMAP};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub const PAGE_BYTES: usize = 16 + crate::stream_layout::MAX_BITMAP_BYTES;
/// Covers the existing 128 GiB partition profile with 4 KiB clusters.
pub const MAX_DATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMPLETE_BYTES: usize = 16 + MAX_DATA_BYTES;
pub const MAX_PAGES: usize = 8;
pub const MAX_RETURNED_BYTES: usize = 2 * MAX_DATA_BYTES + 16 * MAX_PAGES;
pub const MORE_DATA: i32 = 234;
pub const ENCODING: &str = "assembled-zero-lcn-bitmap-v1";

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
    pub cluster_count: u64,
    pub canonical_bitmap_sha256: String,
    pub pages: Vec<PageProof>,
}
#[derive(Debug)]
pub struct Capture {
    pub bitmap: Vec<u8>,
    pub proof: Proof,
}
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Preserve the legacy/extended input and its metadata flag on every page.
pub fn page_input(template: &[u8], starting_lcn: u64) -> io::Result<Vec<u8>> {
    if !matches!(template.len(), 8 | 16)
        || template[..8] != [0; 8]
        || (template.len() == 16
            && (template[8..12] != [0; 4] && template[8..12] != [1, 0, 0, 0]
                || template[12..] != [0; 4]))
        || starting_lcn > i64::MAX as u64
        || !starting_lcn.is_multiple_of(8)
    {
        return Err(bad("invalid bitmap input template or continuation LCN"));
    }
    let mut input = template.to_vec();
    input[..8].copy_from_slice(&starting_lcn.to_le_bytes());
    Ok(input)
}

#[derive(Default)]
pub struct Assembler {
    bitmap: Vec<u8>,
    cluster_count: Option<u64>,
    covered_clusters: u64,
    pages: Vec<PageProof>,
    returned_bytes: usize,
    complete: bool,
    poisoned: bool,
}
impl Assembler {
    pub fn next_lcn(&self) -> u64 {
        self.covered_clusters
    }
    pub fn response_capacity(&self) -> usize {
        if self.complete || self.poisoned || self.pages.len() >= MAX_PAGES {
            return 0;
        }
        let remaining = MAX_RETURNED_BYTES - self.returned_bytes;
        if remaining < 17 {
            0
        } else {
            remaining.min(PAGE_BYTES)
        }
    }
    /// A rounded-down overlap is accepted only if every repeated bitmap byte
    /// agrees. Gaps, changed domains, nonprogress and successful truncation fail.
    pub fn push(&mut self, query: &IoctlQuery, template: &[u8]) -> io::Result<bool> {
        if self.poisoned {
            return Err(bad("bitmap assembler was poisoned by a failed page"));
        }
        let result = self.push_page(query, template);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn push_page(&mut self, query: &IoctlQuery, template: &[u8]) -> io::Result<bool> {
        if self.complete
            || self.pages.len() >= MAX_PAGES
            || query.code != GET_BITMAP
            || query.input != page_input(template, self.next_lcn())?
            || !(17..=PAGE_BYTES).contains(&query.bytes.len())
            || self
                .returned_bytes
                .checked_add(query.bytes.len())
                .is_none_or(|n| n > MAX_RETURNED_BYTES)
        {
            return Err(bad(
                "bitmap page sequence, response or query budget differs",
            ));
        }
        if query.native_error.is_some_and(|e| e != MORE_DATA) {
            return Err(bad("native bitmap page query failed"));
        }
        let start = i64::from_le_bytes(query.bytes[..8].try_into().unwrap());
        let remaining = i64::from_le_bytes(query.bytes[8..16].try_into().unwrap());
        if start < 0
            || remaining <= 0
            || !(start as u64).is_multiple_of(8)
            || start as u64 > self.next_lcn()
        {
            return Err(bad("invalid or gapped bitmap page header"));
        }
        let start = start as u64;
        let end = start
            .checked_add(remaining as u64)
            .ok_or_else(|| bad("bitmap domain overflow"))?;
        if end > MAX_DATA_BYTES as u64 * 8 || self.cluster_count.is_some_and(|n| n != end) {
            return Err(bad("bitmap declared domain changed or exceeds bound"));
        }
        let covered_end = start
            .checked_add((query.bytes.len() - 16) as u64 * 8)
            .ok_or_else(|| bad("bitmap response range overflow"))?
            .min(end);
        if covered_end <= self.covered_clusters
            || (query.native_error.is_none() && covered_end != end)
            || (query.native_error == Some(MORE_DATA) && covered_end == end)
        {
            return Err(bad(
                "bitmap page made no progress or native completion is inconsistent",
            ));
        }
        if self.cluster_count.is_none() {
            let length = 16 + end.div_ceil(8) as usize;
            self.bitmap
                .try_reserve_exact(length)
                .map_err(|_| bad("bitmap allocation failed"))?;
            self.bitmap.resize(length, 0);
            self.bitmap[8..16].copy_from_slice(&end.to_le_bytes());
            self.cluster_count = Some(end);
        }
        let first = start as usize / 8;
        let overlap = self.covered_clusters as usize / 8 - first;
        if self.bitmap[16 + first..16 + first + overlap] != query.bytes[16..16 + overlap] {
            return Err(bad("rounded bitmap overlap changed"));
        }
        let count = covered_end.div_ceil(8) as usize - first;
        // Retain the final byte's unused bits; raw NTFS bitmap hashes include it.
        self.bitmap[16 + first..16 + first + count].copy_from_slice(&query.bytes[16..16 + count]);
        self.pages.push(PageProof {
            input: query.input.clone(),
            response_header: query.bytes[..16].try_into().unwrap(),
            response_bytes: query.bytes.len(),
            native_error: query.native_error,
            response_sha256: hex::encode(Sha256::digest(&query.bytes)),
        });
        self.returned_bytes += query.bytes.len();
        self.covered_clusters = covered_end;
        self.complete = covered_end == end;
        Ok(self.complete)
    }
    pub fn finish(self) -> io::Result<Capture> {
        if self.poisoned || !self.complete || self.pages.is_empty() {
            return Err(bad("bitmap capture ended before complete coverage"));
        }
        let proof = Proof {
            encoding: ENCODING.into(),
            cluster_count: self.cluster_count.unwrap(),
            canonical_bitmap_sha256: hex::encode(Sha256::digest(&self.bitmap)),
            pages: self.pages,
        };
        Ok(Capture {
            bitmap: self.bitmap,
            proof,
        })
    }
}

/// Replay exact recorded native calls; a precomputed map or success flag is
/// never substituted for complete, correctly addressed response coverage.
pub fn assemble_queries(
    first: &IoctlQuery,
    continuation: &[IoctlQuery],
    template: &[u8],
) -> io::Result<Capture> {
    let mut assembler = Assembler::default();
    for query in std::iter::once(first).chain(continuation) {
        assembler.push(query, template)?;
    }
    assembler.finish()
}
