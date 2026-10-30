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
pub const MAX_STREAM_BITMAP_BYTES: u64 = 64 * 1024 * 1024 * 1024;

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

/// First-page evidence and the completed summary from one collector lifetime.
/// No deserializer or public field can pair unrelated response bytes, digest
/// proofs and summaries. This establishes collection consistency, not device
/// identity, mount exclusion, allocation ownership or write authority.
pub(crate) struct CollectedBitmap {
    first: IoctlQuery,
    first_proof: PageProof,
    summary: Summary,
}
impl CollectedBitmap {
    pub(crate) fn into_legacy_parts(self) -> (IoctlQuery, Summary) {
        (self.first, self.summary)
    }

    pub(crate) fn into_observation_parts(self) -> (PageProof, Summary) {
        (self.first_proof, self.summary)
    }
}

struct CollectedFirstPage {
    query: IoctlQuery,
    proof: PageProof,
    covered: u64,
    declared: u64,
    ranges: Vec<ClusterRange>,
    complete_summary: Option<Summary>,
}

impl Summary {
    /// Replay the retained actual first query and cross-check its allocation
    /// prefix. Later-page acquisition is represented by the native transcript;
    /// this method does not recreate missing pages or a native acquisition.
    pub fn validate_source_first(&self, first: &IoctlQuery) -> io::Result<()> {
        self.validate_first_page(first, &[0; 8])
    }

    pub fn validate_first_page(&self, first: &IoctlQuery, template: &[u8]) -> io::Result<()> {
        let limits = source_limits(self.cluster_count)?;
        self.validate(self.cluster_count, limits)?;
        let mut collector = Collector::new(self.cluster_count, limits)?;
        let complete = collector.push(first, template, &mut |_| Ok(()))?;
        if complete {
            if collector.finish()? != *self {
                return Err(bad(
                    "single-page bitmap summary differs from its actual response",
                ));
            }
        } else {
            if self.pages < 2
                || self.returned_bytes <= first.bytes.len() as u64
                || self.declared_clusters != collector.declared.unwrap()
            {
                return Err(bad("streamed bitmap summary disagrees with first page"));
            }
            let expected_prefix = self
                .allocated_ranges
                .iter()
                .take_while(|range| range.starting_lcn < collector.covered)
                .map(|range| {
                    (
                        range.starting_lcn,
                        range.clusters.min(collector.covered - range.starting_lcn),
                    )
                });
            let observed_prefix = collector
                .ranges
                .iter()
                .map(|range| (range.starting_lcn, range.clusters));
            if !expected_prefix.eq(observed_prefix) {
                return Err(bad("streamed bitmap first-page allocation prefix differs"));
            }
        }
        Ok(())
    }

    /// Structural accounting only. Actual native acquisition and comparison
    /// with the frozen source remain separate from deserializable summaries.
    pub fn validate(&self, expected: u64, limits: Limits) -> io::Result<()> {
        Collector::new(expected, limits)?;
        let hash = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.encoding != "streamed-volume-bitmap-v1"
            || self.cluster_count != expected
            || self.declared_clusters < expected
            || self.declared_clusters > expected.div_ceil(8) * 8
            || self.bitmap_bytes != expected.div_ceil(8)
            || !hash(&self.bitmap_data_sha256)
            || !hash(&self.canonical_bitmap_sha256)
            || !hash(&self.page_transcript_sha256)
            || self.pages == 0
            || self.pages > limits.max_pages
            || self.returned_bytes > limits.max_returned_bytes
            || self
                .pages
                .checked_mul(17)
                .is_none_or(|n| self.returned_bytes < n)
            || self
                .pages
                .checked_mul(16)
                .and_then(|n| n.checked_add(self.bitmap_bytes))
                .is_none_or(|n| self.returned_bytes < n)
            || self
                .pages
                .checked_mul((16 + PAGE_DATA_BYTES) as u64)
                .is_none_or(|n| self.returned_bytes > n)
            || self.allocated_clusters > expected
            || self.free_clusters != expected - self.allocated_clusters
            || self.padding_bits_set > ((8 - expected % 8) % 8) as u32
            || self.allocated_ranges.len() > limits.max_allocated_ranges
        {
            return Err(bad("streamed bitmap summary accounting differs"));
        }
        let mut end = None;
        let mut allocated = 0u64;
        for range in &self.allocated_ranges {
            let next = range
                .starting_lcn
                .checked_add(range.clusters)
                .filter(|next| *next <= expected)
                .ok_or_else(|| bad("streamed bitmap allocation range escapes domain"))?;
            if range.clusters == 0 || end.is_some_and(|prior| range.starting_lcn <= prior) {
                return Err(bad(
                    "streamed bitmap allocation ranges overlap or are not maximal",
                ));
            }
            allocated = allocated
                .checked_add(range.clusters)
                .ok_or_else(|| bad("bitmap allocation count overflow"))?;
            end = Some(next);
        }
        if allocated != self.allocated_clusters {
            return Err(bad("streamed bitmap allocated count differs from ranges"));
        }
        Ok(())
    }
}

/// Source evidence limits are independent of the number of file identities.
/// The complete map is never retained, and these bounds grant no write access.
pub fn source_limits(expected_clusters: u64) -> io::Result<Limits> {
    let max_pages = 131_072;
    let max_returned_bytes = expected_clusters
        .div_ceil(8)
        .checked_mul(2)
        .and_then(|n| n.checked_add(16 * max_pages))
        .ok_or_else(|| bad("source bitmap read budget overflow"))?;
    Ok(Limits {
        max_bitmap_bytes: MAX_STREAM_BITMAP_BYTES,
        max_pages,
        max_returned_bytes,
        max_allocated_ranges: 65_536,
    })
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
    first_page: Option<CollectedFirstPage>,
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
            first_page: None,
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

    /// Consume the actual first response when a native caller needs retained
    /// first-page evidence. The ordinary replay API continues to use `push`.
    /// Capture its proof and prefix from this original processing pass; do not
    /// reconstruct a collector or hash the response a second time afterward.
    pub(crate) fn push_first_owned(
        &mut self,
        query: IoctlQuery,
        template: &[u8],
    ) -> io::Result<bool> {
        if self.pages != 0 || self.first_page.is_some() || self.poisoned || self.complete {
            self.poisoned = true;
            return Err(bad(
                "retained first bitmap page must precede every other page",
            ));
        }
        let mut proof = None;
        let complete = self.push(&query, template, &mut |page| {
            if proof.replace(page.clone()).is_some() {
                return Err(bad("first bitmap response produced duplicate page proofs"));
            }
            Ok(())
        })?;
        let proof = proof.ok_or_else(|| bad("first bitmap response has no page proof"))?;
        let declared = self
            .declared
            .ok_or_else(|| bad("first bitmap page has no declared domain"))?;
        let complete_summary = if complete {
            Some(self.completed_summary_snapshot()?)
        } else {
            None
        };
        let ranges = if complete {
            Vec::new()
        } else {
            self.ranges.clone()
        };
        self.first_page = Some(CollectedFirstPage {
            query,
            proof,
            covered: self.covered,
            declared,
            ranges,
            complete_summary,
        });
        Ok(complete)
    }

    // Only used for a complete first response. Cloning/finalizing digest state
    // does not reread or rehash response data, and retains the old equality
    // check between complete first-page and complete collection summaries.
    fn completed_summary_snapshot(&self) -> io::Result<Summary> {
        if self.poisoned || !self.complete || self.pages == 0 {
            return Err(bad("streaming bitmap observation is incomplete"));
        }
        Ok(Summary {
            encoding: "streamed-volume-bitmap-v1".into(),
            cluster_count: self.expected,
            declared_clusters: self.declared.ok_or_else(|| bad("bitmap domain absent"))?,
            bitmap_bytes: self.expected.div_ceil(8),
            bitmap_data_sha256: hex::encode(self.data_hash.clone().finalize()),
            canonical_bitmap_sha256: hex::encode(self.canonical_hash.clone().finalize()),
            page_transcript_sha256: hex::encode(self.transcript.clone().finalize()),
            pages: self.pages,
            returned_bytes: self.returned,
            allocated_clusters: self.allocated,
            free_clusters: self.expected - self.allocated,
            padding_bits_set: self.padding,
            allocated_ranges: self.ranges.clone(),
        })
    }

    /// Finish the same collector that consumed the owned first response. Keep
    /// all structural/domain and complete/prefix comparisons of replay, using
    /// the immutable first-page state that was already derived from its bytes.
    pub(crate) fn finish_collected(mut self) -> io::Result<CollectedBitmap> {
        let first = self
            .first_page
            .take()
            .ok_or_else(|| bad("owned first bitmap page absent"))?;
        let expected = self.expected;
        let summary = self.finish()?;
        summary.validate(expected, source_limits(expected)?)?;
        if let Some(single) = first.complete_summary {
            if single != summary {
                return Err(bad(
                    "single-page bitmap summary differs from its actual response",
                ));
            }
        } else {
            if summary.pages < 2
                || summary.returned_bytes <= first.query.bytes.len() as u64
                || summary.declared_clusters != first.declared
            {
                return Err(bad("streamed bitmap summary disagrees with first page"));
            }
            let expected_prefix = summary
                .allocated_ranges
                .iter()
                .take_while(|range| range.starting_lcn < first.covered)
                .map(|range| {
                    (
                        range.starting_lcn,
                        range.clusters.min(first.covered - range.starting_lcn),
                    )
                });
            let observed_prefix = first
                .ranges
                .iter()
                .map(|range| (range.starting_lcn, range.clusters));
            if !expected_prefix.eq(observed_prefix) {
                return Err(bad("streamed bitmap first-page allocation prefix differs"));
            }
        }
        Ok(CollectedBitmap {
            first: first.query,
            first_proof: first.proof,
            summary,
        })
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
        if let Some(error) = query.native_error.filter(|error| *error != MORE_DATA) {
            return Err(io::Error::from_raw_os_error(error));
        }
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
