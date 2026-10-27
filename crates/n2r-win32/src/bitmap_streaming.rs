//! Streaming native bitmap observations. No mount exclusion or write authority.
//! Raw pages can be exported by the caller; only a bounded overlap window,
//! transcript digest and bounded allocation intervals remain in memory.
use crate::{
    attestation::IoctlQuery,
    bitmap_paging::{MORE_DATA, PageProof, page_input},
    stream_layout::GET_BITMAP,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub const PAGE_DATA_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bitmap_bytes: u64,
    pub max_pages: u64,
    pub max_returned_bytes: u64,
    pub max_allocated_ranges: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRange {
    pub starting_lcn: u64,
    pub clusters: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub encoding: String,
    pub cluster_count: u64,
    pub declared_clusters: u64,
    pub bitmap_bytes: u64,
    pub bitmap_data_sha256: String,
    pub canonical_bitmap_sha256: String,
    pub page_transcript_sha256: String,
    pub pages: u64,
    pub returned_bytes: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    pub padding_bits_set: u32,
    pub allocated_ranges: Vec<ClusterRange>,
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub struct Collector {
    expected: u64,
    declared: Option<u64>,
    covered: u64,
    limits: Limits,
    previous_start: u64,
    previous: Vec<u8>,
    data_hash: Sha256,
    canonical_hash: Sha256,
    transcript: Sha256,
    pages: u64,
    returned: u64,
    allocated: u64,
    padding: u32,
    ranges: Vec<ClusterRange>,
    complete: bool,
    poisoned: bool,
}

impl Collector {
    pub fn new(expected_clusters: u64, limits: Limits) -> io::Result<Self> {
        if expected_clusters == 0
            || expected_clusters > i64::MAX as u64
            || expected_clusters.div_ceil(8) > limits.max_bitmap_bytes
            || limits.max_pages == 0
            || limits.max_returned_bytes < 17
            || limits.max_allocated_ranges == 0
        {
            return Err(bad("invalid streaming bitmap domain or budgets"));
        }
        Ok(Self {
            expected: expected_clusters,
            declared: None,
            covered: 0,
            limits,
            previous_start: 0,
            previous: Vec::new(),
            data_hash: Sha256::new(),
            canonical_hash: Sha256::new(),
            transcript: Sha256::new(),
            pages: 0,
            returned: 0,
            allocated: 0,
            padding: 0,
            ranges: Vec::new(),
            complete: false,
            poisoned: false,
        })
    }
    pub fn next_lcn(&self) -> u64 {
        self.covered
    }
    pub fn response_capacity(&self) -> usize {
        if self.poisoned || self.complete || self.pages >= self.limits.max_pages {
            return 0;
        }
        let remaining = self.limits.max_returned_bytes - self.returned;
        if remaining < 17 {
            0
        } else {
            remaining.min((16 + PAGE_DATA_BYTES) as u64) as usize
        }
    }
    pub fn push(
        &mut self,
        query: &IoctlQuery,
        template: &[u8],
        on_page: &mut impl FnMut(&PageProof) -> io::Result<()>,
    ) -> io::Result<bool> {
        if self.poisoned {
            return Err(bad("streaming bitmap collector is poisoned"));
        }
        let result = self.push_page(query, template, on_page);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn add_range(&mut self, starting_lcn: u64, clusters: u64) -> io::Result<()> {
        if let Some(last) = self.ranges.last_mut()
            && last.starting_lcn + last.clusters == starting_lcn
        {
            last.clusters += clusters;
        } else {
            if self.ranges.len() >= self.limits.max_allocated_ranges {
                return Err(bad("streaming bitmap allocation-range budget exhausted"));
            }
            self.ranges
                .try_reserve(1)
                .map_err(|_| bad("bitmap interval allocation failed"))?;
            self.ranges.push(ClusterRange {
                starting_lcn,
                clusters,
            });
        }
        self.allocated += clusters;
        Ok(())
    }
    fn consume_bits(&mut self, bytes: &[u8], first_lcn: u64) -> io::Result<()> {
        for (index, chunk) in bytes.chunks(8).enumerate() {
            let start = first_lcn + index as u64 * 64;
            let mut encoded = [0; 8];
            encoded[..chunk.len()].copy_from_slice(chunk);
            let raw = u64::from_le_bytes(encoded);
            let valid = self
                .expected
                .saturating_sub(start)
                .min(chunk.len() as u64 * 8) as u32;
            let mask = if valid == 64 {
                u64::MAX
            } else {
                (1u64 << valid) - 1
            };
            self.padding += (raw & !mask).count_ones();
            let mut bits = raw & mask;
            let mut cursor = start;
            while bits != 0 {
                let skip = bits.trailing_zeros();
                cursor += u64::from(skip);
                bits >>= skip;
                let run = bits.trailing_ones();
                self.add_range(cursor, u64::from(run))?;
                if run == 64 {
                    break;
                }
                bits >>= run;
                cursor += u64::from(run);
            }
        }
        Ok(())
    }
    fn push_page(
        &mut self,
        query: &IoctlQuery,
        template: &[u8],
        on_page: &mut impl FnMut(&PageProof) -> io::Result<()>,
    ) -> io::Result<bool> {
        if self.response_capacity() == 0
            || query.code != GET_BITMAP
            || query.input != page_input(template, self.covered)?
            || !(17..=self.response_capacity()).contains(&query.bytes.len())
            || query.native_error.is_some_and(|error| error != MORE_DATA)
        {
            return Err(bad(
                "invalid streaming bitmap page or exhausted query budget",
            ));
        }
        let start = i64::from_le_bytes(query.bytes[..8].try_into().unwrap());
        let remaining = i64::from_le_bytes(query.bytes[8..16].try_into().unwrap());
        if start < 0
            || remaining <= 0
            || !(start as u64).is_multiple_of(8)
            || start as u64 > self.covered
        {
            return Err(bad("invalid streaming bitmap header"));
        }
        let start = start as u64;
        let end = start
            .checked_add(remaining as u64)
            .ok_or_else(|| bad("bitmap domain overflow"))?;
        if end < self.expected
            || end > self.expected.div_ceil(8) * 8
            || self.declared.is_some_and(|prior| prior != end)
        {
            return Err(bad("streaming bitmap declared domain changed or differs"));
        }
        let covered_end = start
            .checked_add((query.bytes.len() - 16) as u64 * 8)
            .ok_or_else(|| bad("bitmap page overflow"))?
            .min(end);
        if covered_end <= self.covered || query.native_error.is_none() != (covered_end == end) {
            return Err(bad(
                "streaming bitmap made no progress or completion differs",
            ));
        }
        let first_byte = start / 8;
        let old_bytes = self.covered / 8;
        if first_byte < self.previous_start || old_bytes < first_byte {
            return Err(bad("bitmap overlap exceeds retained observation window"));
        }
        let overlap =
            usize::try_from(old_bytes - first_byte).map_err(|_| bad("bitmap overlap overflow"))?;
        let prior_at = usize::try_from(first_byte - self.previous_start)
            .map_err(|_| bad("bitmap overlap offset overflow"))?;
        if overlap > 0
            && self.previous.get(prior_at..prior_at + overlap) != query.bytes.get(16..16 + overlap)
        {
            return Err(bad("streaming bitmap overlap changed"));
        }
        let count = usize::try_from(covered_end.div_ceil(8) - first_byte)
            .map_err(|_| bad("bitmap page length overflow"))?;
        let new_bytes = query
            .bytes
            .get(16 + overlap..16 + count)
            .ok_or_else(|| bad("truncated bitmap coverage"))?;
        if self.declared.is_none() {
            self.canonical_hash.update([0; 8]);
            self.canonical_hash.update(end.to_le_bytes());
            self.declared = Some(end);
        }
        self.data_hash.update(new_bytes);
        self.canonical_hash.update(new_bytes);
        self.consume_bits(new_bytes, self.covered)?;
        let proof = PageProof {
            input: query.input.clone(),
            response_header: query.bytes[..16].try_into().unwrap(),
            response_bytes: query.bytes.len(),
            native_error: query.native_error,
            response_sha256: hex::encode(Sha256::digest(&query.bytes)),
        };
        // Fixed binary framing of actual request/response observations.
        self.transcript
            .update((query.input.len() as u64).to_le_bytes());
        self.transcript.update(&query.input);
        self.transcript
            .update((query.bytes.len() as u64).to_le_bytes());
        self.transcript
            .update(query.native_error.unwrap_or(0).to_le_bytes());
        self.transcript.update(&query.bytes);
        on_page(&proof)?;
        self.previous.clear();
        self.previous
            .extend_from_slice(&query.bytes[16..16 + count]);
        self.previous_start = first_byte;
        self.covered = covered_end;
        self.returned += query.bytes.len() as u64;
        self.pages += 1;
        self.complete = covered_end == end;
        Ok(self.complete)
    }
    pub fn finish(self) -> io::Result<Summary> {
        if self.poisoned || !self.complete || self.pages == 0 {
            return Err(bad("streaming bitmap observation is incomplete"));
        }
        Ok(Summary {
            encoding: "streamed-volume-bitmap-v1".into(),
            cluster_count: self.expected,
            declared_clusters: self.declared.unwrap(),
            bitmap_bytes: self.expected.div_ceil(8),
            bitmap_data_sha256: hex::encode(self.data_hash.finalize()),
            canonical_bitmap_sha256: hex::encode(self.canonical_hash.finalize()),
            page_transcript_sha256: hex::encode(self.transcript.finalize()),
            pages: self.pages,
            returned_bytes: self.returned,
            allocated_clusters: self.allocated,
            free_clusters: self.expected - self.allocated,
            padding_bits_set: self.padding,
            allocated_ranges: self.ranges,
        })
    }
}

/// Actual native queries against a borrowed volume handle. The caller owns
/// identity, exclusion and lifetime checks. A summary is never write authority.
#[cfg(windows)]
pub fn capture(
    volume: &std::fs::File,
    expected_clusters: u64,
    template: &[u8],
    limits: Limits,
    mut on_page: impl FnMut(&PageProof) -> io::Result<()>,
) -> io::Result<Summary> {
    page_input(template, 0)?;
    let mut collector = Collector::new(expected_clusters, limits)?;
    while collector.response_capacity() != 0 {
        let input = page_input(template, collector.next_lcn())?;
        let query =
            crate::stream_native::ioctl(volume, GET_BITMAP, &input, collector.response_capacity());
        if collector.push(&query, template, &mut on_page)? {
            break;
        }
    }
    collector.finish()
}

/// Read-only observation of an actually routed dedicated data volume. Route
/// checks surround the same held volume handle. This neither freezes the
/// filesystem nor claims its allocations were unchanged during the scan.
#[cfg(windows)]
pub fn capture_general(
    binding: crate::general_layout::GeneralDiskBinding,
    expected_clusters: u64,
    template: &[u8],
    limits: Limits,
    events: &mut Vec<crate::NativeEvent>,
    on_page: impl FnMut(&PageProof) -> io::Result<()>,
) -> io::Result<Summary> {
    let reader = crate::GeneralPartitionReader::open(binding.clone(), events)?;
    let volume = crate::native::device_file(&binding.volume_path()?, false, false)?;
    let before = crate::stream_native::ioctl(&volume, 0x00560000, &[], 1024);
    if before.native_error.is_some() {
        return Err(bad("streaming bitmap volume route query failed"));
    }
    binding.validate_volume_extent(&before.bytes)?;
    let summary = capture(&volume, expected_clusters, template, limits, on_page)?;
    let after = crate::stream_native::ioctl(&volume, 0x00560000, &[], 1024);
    if after.native_error.is_some() || before.bytes != after.bytes {
        return Err(bad("streaming bitmap held volume route changed"));
    }
    binding.validate_volume_extent(&after.bytes)?;
    reader.revalidate_route(events)?;
    Ok(summary)
}
