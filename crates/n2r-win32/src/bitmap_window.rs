//! Bounded observations of a requested cluster window, not a full volume map.
//! No device is opened here. Saved proofs are untrusted until replayed, and
//! even a replayed observation grants no allocation or conversion authority.
use crate::{
    attestation::IoctlQuery,
    bitmap_paging::{MORE_DATA, PAGE_BYTES, page_input},
    stream_layout::GET_BITMAP,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub const ENCODING: &str = "native-bitmap-window-v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub volume_clusters: u64,
    pub starting_lcn: u64,
    pub clusters: u64,
}
impl Request {
    fn end(self) -> io::Result<u64> {
        if self.volume_clusters == 0
            || self.volume_clusters > i64::MAX as u64
            || self.clusters == 0
            || self.starting_lcn > i64::MAX as u64
        {
            return Err(bad("invalid bitmap-window domain or requested range"));
        }
        self.starting_lcn
            .checked_add(self.clusters)
            .filter(|end| *end <= self.volume_clusters)
            .ok_or_else(|| bad("bitmap window escapes volume domain"))
    }
}

/// Explicit independent limits. `page_bytes` includes the 16-byte native
/// header and is a ceiling, not an allocation proportional to volume size.
/// A collector initially requests at most 4096 bytes and grows only after an
/// observed rounded-down reply cannot reach the requested cursor.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_window_bytes: usize,
    pub max_pages: usize,
    pub max_returned_bytes: usize,
    pub page_bytes: usize,
}

/// Serialization is an evidence transport only. Call `replay` before using
/// any fields, including counts, hashes, booleans and canonical window bits.
/// `window_bits` is packed LSB first relative to Request.starting_lcn; unused
/// high bits of the final byte are zero. Its hash has a separate window domain
/// and MUST NOT be used as a full-volume bitmap/Candidate hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub schema_version: u32,
    pub encoding: String,
    pub request: Request,
    pub template: Vec<u8>,
    pub declared_volume_clusters: u64,
    pub window_bits: Vec<u8>,
    pub allocated_clusters: u64,
    pub window_sha256: String,
    pub returned_bytes: usize,
    pub whole_volume_complete: bool,
    pub queries: Vec<IoctlQuery>,
}

/// An internally consistent observation. This is deliberately unrelated to
/// bitmap_layout::Candidate and does not represent a full allocation map.
pub struct Observation {
    proof: Proof,
}
impl Observation {
    pub fn request(&self) -> Request {
        self.proof.request
    }
    pub fn window_bits(&self) -> &[u8] {
        &self.proof.window_bits
    }
    pub fn allocated_clusters(&self) -> u64 {
        self.proof.allocated_clusters
    }
    pub fn window_sha256(&self) -> &str {
        &self.proof.window_sha256
    }
    pub fn proof(&self) -> &Proof {
        &self.proof
    }
    pub fn into_proof(self) -> Proof {
        self.proof
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    NeedMore,
    Complete,
    /// This actual response ended before the wanted cursor. The collector
    /// retains it and raises page_capacity() within the original limits;
    /// request_lcn() remains unchanged. No rounding constant is assumed.
    NeedLargerBuffer {
        required_bytes: usize,
    },
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// State and all allocated memory are bounded by the requested window and
/// explicit query budgets, independently of the declared volume capacity.
pub struct Collector {
    request: Request,
    end: u64,
    cursor: u64,
    template: Vec<u8>,
    limits: Limits,
    current_page_bytes: usize,
    declared: Option<u64>,
    bits: Vec<u8>,
    queries: Vec<IoctlQuery>,
    returned_bytes: usize,
    poisoned: bool,
}
impl Collector {
    pub fn new(request: Request, template: &[u8], limits: Limits) -> io::Result<Self> {
        let end = request.end()?;
        page_input(template, request.starting_lcn / 8 * 8)?;
        let bytes = usize::try_from(request.clusters.div_ceil(8))
            .map_err(|_| bad("bitmap-window allocation does not fit address space"))?;
        if bytes > limits.max_window_bytes
            || limits.max_pages == 0
            || limits.max_returned_bytes < 17
            || !(17..=PAGE_BYTES).contains(&limits.page_bytes)
        {
            return Err(bad("invalid bitmap-window resource limits"));
        }
        let mut bits = Vec::new();
        bits.try_reserve_exact(bytes)
            .map_err(|_| bad("bitmap-window storage unavailable"))?;
        bits.resize(bytes, 0);
        Ok(Self {
            request,
            end,
            cursor: request.starting_lcn,
            template: template.to_vec(),
            limits,
            current_page_bytes: 4096.min(limits.page_bytes),
            declared: None,
            bits,
            queries: Vec::new(),
            returned_bytes: 0,
            poisoned: false,
        })
    }
    /// STARTING_LCN_INPUT_BUFFER uses an integral multiple of eight. The
    /// canonical requested window itself may begin at any cluster.
    pub fn request_lcn(&self) -> u64 {
        self.cursor / 8 * 8
    }
    pub fn page_capacity(&self) -> usize {
        if self.poisoned || self.cursor == self.end || self.queries.len() >= self.limits.max_pages {
            return 0;
        }
        let remaining = self.limits.max_returned_bytes - self.returned_bytes;
        if remaining < 17 {
            0
        } else {
            remaining.min(self.current_page_bytes)
        }
    }
    pub fn push(&mut self, query: IoctlQuery) -> io::Result<PushOutcome> {
        if self.poisoned {
            return Err(bad("bitmap-window collector is poisoned"));
        }
        let result = self.push_page(query);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn push_page(&mut self, query: IoctlQuery) -> io::Result<PushOutcome> {
        let capacity = self.page_capacity();
        let requested_lcn = self.request_lcn();
        if capacity == 0
            || query.code != GET_BITMAP
            || query.input != page_input(&self.template, requested_lcn)?
            || !(17..=capacity).contains(&query.bytes.len())
            || query.native_error.is_some_and(|error| error != MORE_DATA)
        {
            return Err(bad(
                "invalid bitmap-window request, status or response size",
            ));
        }
        let start = i64::from_le_bytes(query.bytes[..8].try_into().unwrap());
        let remaining = i64::from_le_bytes(query.bytes[8..16].try_into().unwrap());
        if start < 0
            || remaining <= 0
            || !(start as u64).is_multiple_of(8)
            || start as u64 > requested_lcn
        {
            return Err(bad("invalid rounded bitmap-window response header"));
        }
        let start = start as u64;
        let declared = start
            .checked_add(remaining as u64)
            .ok_or_else(|| bad("bitmap-window declared domain overflow"))?;
        if declared < self.request.volume_clusters
            || declared > self.request.volume_clusters.div_ceil(8) * 8
            || self.declared.is_some_and(|prior| prior != declared)
        {
            return Err(bad("bitmap-window response domain changed or differs"));
        }
        let returned_end = start
            .checked_add((query.bytes.len() - 16) as u64 * 8)
            .ok_or_else(|| bad("bitmap-window page coverage overflow"))?
            .min(declared);
        // The driver status describes its whole returned domain, not whether
        // our smaller requested window is now complete.
        if query.native_error.is_none() != (returned_end == declared) {
            return Err(bad("bitmap-window native completion status differs"));
        }
        let overlap_start = start.max(self.request.starting_lcn);
        let overlap_end = returned_end.min(self.cursor);
        if overlap_start < overlap_end {
            compare_bits(
                &self.bits,
                overlap_start - self.request.starting_lcn,
                &query.bytes[16..],
                overlap_start - start,
                overlap_end - overlap_start,
            )?;
        }
        let next_cursor = returned_end.min(self.end).max(self.cursor);
        let next_returned = self
            .returned_bytes
            .checked_add(query.bytes.len())
            .filter(|bytes| *bytes <= self.limits.max_returned_bytes)
            .ok_or_else(|| bad("bitmap-window returned-byte budget exceeded"))?;
        let outcome = if next_cursor == self.cursor {
            // The response rounded back farther than the supplied buffer can
            // bridge. Account for the actual observed offset, not a guessed
            // filesystem rounding unit. At least one byte at cursor is needed.
            let required = usize::try_from((requested_lcn - start) / 8)
                .ok()
                .and_then(|bytes| bytes.checked_add(17))
                .ok_or_else(|| bad("bitmap-window larger-buffer requirement overflow"))?;
            let remaining_budget = self.limits.max_returned_bytes - next_returned;
            if required <= capacity
                || required > self.limits.page_bytes
                || required > remaining_budget
                || self.queries.len() + 1 >= self.limits.max_pages
            {
                return Err(bad(
                    "rounded bitmap-window response cannot progress within resource limits",
                ));
            }
            self.current_page_bytes = required
                .max(capacity.saturating_mul(2))
                .min(self.limits.page_bytes)
                .min(remaining_budget);
            PushOutcome::NeedLargerBuffer {
                required_bytes: required,
            }
        } else {
            copy_bits(
                &mut self.bits,
                self.cursor - self.request.starting_lcn,
                &query.bytes[16..],
                self.cursor - start,
                next_cursor - self.cursor,
            )?;
            if next_cursor == self.end {
                PushOutcome::Complete
            } else {
                PushOutcome::NeedMore
            }
        };
        self.queries
            .try_reserve(1)
            .map_err(|_| bad("bitmap-window query storage unavailable"))?;
        self.queries.push(query);
        self.returned_bytes = next_returned;
        self.declared = Some(declared);
        self.cursor = next_cursor;
        Ok(outcome)
    }
    pub fn finish(self) -> io::Result<Observation> {
        if self.poisoned || self.cursor != self.end || self.queries.is_empty() {
            return Err(bad("bitmap-window observation is incomplete"));
        }
        let declared = self
            .declared
            .ok_or_else(|| bad("bitmap-window declared domain absent"))?;
        let allocated = self
            .bits
            .iter()
            .map(|byte| u64::from(byte.count_ones()))
            .sum();
        let window_sha256 = window_digest(self.request, declared, &self.template, &self.bits);
        Ok(Observation {
            proof: Proof {
                schema_version: 1,
                encoding: ENCODING.into(),
                request: self.request,
                template: self.template,
                declared_volume_clusters: declared,
                window_bits: self.bits,
                allocated_clusters: allocated,
                window_sha256,
                returned_bytes: self.returned_bytes,
                // A window proof never claims whole-volume acquisition, including
                // when a final native response itself has a success status.
                whole_volume_complete: false,
                queries: self.queries,
            },
        })
    }
}

/// Reprocess every native request/response under caller-supplied limits. No
/// serialized count, digest, canonical bits or boolean is taken as authority.
pub fn replay(proof: &Proof, limits: Limits) -> io::Result<Observation> {
    if proof.schema_version != 1
        || proof.encoding != ENCODING
        || proof.whole_volume_complete
        || proof.queries.len() > limits.max_pages
        || proof.window_bits.len() > limits.max_window_bytes
    {
        return Err(bad("invalid bitmap-window proof schema or replay limits"));
    }
    let mut returned = 0usize;
    for query in &proof.queries {
        if !(17..=limits.page_bytes.min(PAGE_BYTES)).contains(&query.bytes.len())
            || !matches!(query.input.len(), 8 | 16)
        {
            return Err(bad("bitmap-window replay query exceeds bounds"));
        }
        returned = returned
            .checked_add(query.bytes.len())
            .filter(|bytes| *bytes <= limits.max_returned_bytes)
            .ok_or_else(|| bad("bitmap-window replay byte budget exceeded"))?;
    }
    let mut collector = Collector::new(proof.request, &proof.template, limits)?;
    for query in &proof.queries {
        collector.push(query.clone())?;
    }
    let observation = collector.finish()?;
    if observation.proof != *proof {
        return Err(bad("bitmap-window replay differs from claimed evidence"));
    }
    Ok(observation)
}

fn window_digest(request: Request, declared: u64, template: &[u8], bits: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update((ENCODING.len() as u64).to_le_bytes());
    hash.update(ENCODING.as_bytes());
    hash.update((template.len() as u64).to_le_bytes());
    hash.update(template);
    hash.update(request.volume_clusters.to_le_bytes());
    hash.update(declared.to_le_bytes());
    hash.update(request.starting_lcn.to_le_bytes());
    hash.update(request.clusters.to_le_bytes());
    hash.update((bits.len() as u64).to_le_bytes());
    hash.update(bits);
    hex::encode(hash.finalize())
}

fn read_bits(bytes: &[u8], bit: u64, count: u32) -> io::Result<u8> {
    if !(1..=8).contains(&count) {
        return Err(bad("bitmap-window bit-width differs"));
    }
    let index = usize::try_from(bit / 8).map_err(|_| bad("bitmap-window bit offset overflow"))?;
    let shift = (bit % 8) as u32;
    let mut value = u16::from(
        *bytes
            .get(index)
            .ok_or_else(|| bad("bitmap-window bit outside buffer"))?,
    );
    if shift + count > 8 {
        value |= u16::from(
            *bytes
                .get(index + 1)
                .ok_or_else(|| bad("bitmap-window split byte outside buffer"))?,
        ) << 8;
    }
    Ok(((value >> shift) & ((1u16 << count) - 1)) as u8)
}
fn compare_bits(
    target: &[u8],
    target_bit: u64,
    source: &[u8],
    source_bit: u64,
    count: u64,
) -> io::Result<()> {
    let mut at = 0;
    while at < count {
        let width = (count - at).min(8 - (target_bit + at) % 8) as u32;
        if read_bits(target, target_bit + at, width)? != read_bits(source, source_bit + at, width)?
        {
            return Err(bad("overlapping bitmap-window bits changed"));
        }
        at += u64::from(width);
    }
    Ok(())
}
fn copy_bits(
    target: &mut [u8],
    target_bit: u64,
    source: &[u8],
    source_bit: u64,
    count: u64,
) -> io::Result<()> {
    let mut at = 0;
    while at < count {
        let bit = target_bit + at;
        let width = (count - at).min(8 - bit % 8) as u32;
        let value = read_bits(source, source_bit + at, width)?;
        let shift = (bit % 8) as u32;
        let mask = (((1u16 << width) - 1) << shift) as u8;
        let index =
            usize::try_from(bit / 8).map_err(|_| bad("bitmap-window copy offset overflow"))?;
        let byte = target
            .get_mut(index)
            .ok_or_else(|| bad("bitmap-window copy outside window"))?;
        *byte = (*byte & !mask) | (value << shift);
        at += u64::from(width);
    }
    Ok(())
}
