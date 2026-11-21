//! Selected-range reconstruction journal. This module opens no devices and
//! does not authenticate the selection, establish exclusion or certify a
//! filesystem. The caller owns those obligations and the trusted ticket.
//!
//! Empty `new_zero_ranges` preserves the original N2RSEL01 byte layout.
//! N2RZERO1 stores every old byte but represents selected all-zero new ranges
//! without payload. Both formats use the same selected-byte digests and replay
//! barriers; zero encoding changes storage, not the target write set.
//! N2RCPY01 additionally resolves new bytes from the journal's immutable old
//! payloads. It never needs a source device when replaying a copy.
//! N2ROLD01 additionally omits old ranges independently verified as zero.
//! Recovery synthesizes their original bytes, including old-copy sources.
//! N2RFRE01 stores only 4 KiB digests for admitted source-free old ranges.
//! Their actual old bytes remain part of the fresh target pin, but rollback
//! leaves these free destinations unchanged and restores only the other ranges.
//! Explicit N2RFRE02 preparation adds write-once duplicated lifecycle markers.
//! Distinct file offsets alone do not certify physical failure independence or
//! uncached durable readback; native callers remain on the legacy preparation.
use crate::interrupted_marker::{Marker, MarkerWrite, SettledMarker};
use crate::lab_reconstruct::{DurableIo, ReadSeek};
use anyhow::{Context, Result, ensure};
use n2r_win32::bulk_digest::Algorithm;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

#[cfg(windows)]
pub(crate) mod resource_domain;

const GRANULE: u64 = 4096;
const BODY: u64 = 8192;
const REDUNDANT_BODY: u64 = 8 * GRANULE;
const HEADER: usize = 80;
const RECORD: usize = 80;
const ZERO_RECORD: usize = 88;
const COPY_RECORD: usize = 96;
const OLD_ZERO_RECORD: usize = 104;
const FOOTER: usize = 80;
const BUFFER: usize = 1024 * 1024;
const MAX_RANGES: usize = 65_536;
const FORMAT: u32 = 1;
const ZERO_FORMAT: u32 = 2;
const COPY_FORMAT: u32 = 3;
const OLD_ZERO_FORMAT: u32 = 4;
const SOURCE_FREE_FORMAT: u32 = 5;
const REDUNDANT_SOURCE_FREE_FORMAT: u32 = 6;
const FREE_DIGEST: u64 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedCopyRange {
    pub offset: u64,
    pub length: u64,
    pub source_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedPlan {
    pub image_length: u64,
    pub ranges: Vec<SelectedRange>,
    pub max_selected_bytes: u64,
    pub max_journal_bytes: u64,
    /// A sorted subset of `ranges` whose new contents are exactly zero. Every
    /// entry must equal a complete selected range. Preparation checks the
    /// actual candidate; this declaration alone never authenticates bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_zero_ranges: Vec<SelectedRange>,
    /// New bytes reproduced from original bytes of selected ranges. The
    /// entire source interval must be covered by the journal's old payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_copy_ranges: Vec<SelectedCopyRange>,
    /// A sorted unique whole-range subset whose actual original source bytes
    /// are rechecked as zero during preparation. This never omits a target
    /// check or write, and the declaration alone authenticates no source byte.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub old_zero_ranges: Vec<SelectedRange>,
    /// Exact whole-range subset independently proved source-free by the caller.
    /// Preparation records actual old 4 KiB digests, never allocation authority.
    /// Rollback may leave these destinations changed. Discovery and immutable
    /// old-copy source bytes must never belong to this subset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_free_ranges: Vec<SelectedRange>,
}

/// Explicit format selection, never inferred from file size or damaged markers.
/// Native use also needs a backend proving separate failure granules and durable
/// uncached marker readback; `DurableIo` alone makes neither claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedMarkerProfile {
    RedundantSourceFreeV1,
}

/// Trusted only when held independently by the caller. This format and its
/// magic are separate from full-image reconstruction journal versions 1/2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTicket {
    pub image_length: u64,
    pub selected_bytes: u64,
    pub range_count: u32,
    pub journal_length: u64,
    pub immutable_sha256: [u8; 32],
    /// Absent preserves selected formats one through five exactly. Format six
    /// binds this explicit selection into its immutable header and trusted pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker_profile: Option<SelectedMarkerProfile>,
    pub old_selected_sha256: [u8; 32],
    /// Format-five/six rollback pin over framed restore-required ranges only.
    /// The complete original selected pin above is retained for fresh apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_restored_selected_sha256: Option<[u8; 32]>,
    pub new_selected_sha256: [u8; 32],
    pub whole_image_verified: bool,
    /// The algorithm of every digest above and of the digests the journal
    /// carries for its rows: BLAKE3 in a ticket this build writes. Absent in
    /// a ticket of a build before it, whose digests are SHA-256; absent is
    /// never written, so such a ticket reads and serializes as it always did.
    /// The field names keep their historical `sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Algorithm>,
}

impl SelectedTicket {
    fn body_offset(&self) -> u64 {
        marker_body(self.marker_profile)
    }

    /// The algorithm of the ticket's digests and its journal's.
    pub(crate) fn digest_algorithm(&self) -> Algorithm {
        self.digest.unwrap_or(Algorithm::Sha256)
    }
}

fn marker_body(profile: Option<SelectedMarkerProfile>) -> u64 {
    match profile {
        None => BODY,
        Some(SelectedMarkerProfile::RedundantSourceFreeV1) => REDUNDANT_BODY,
    }
}

#[derive(Debug, Serialize)]
pub struct SelectedResult {
    pub selected_sha256: [u8; 32],
    pub selected_bytes: u64,
    pub range_count: u32,
    pub replay_closed: bool,
    pub whole_image_verified: bool,
    pub conversion_qualified: bool,
    /// Present only when selected_sha256 describes restore-required ranges;
    /// selected_bytes still records the complete checked selected address set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_restoration_bytes: Option<u64>,
}

#[derive(Debug)]
struct JournalRecord {
    range: SelectedRange,
    before: OldBytes,
    after: NewBytes,
    new_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
enum OldBytes {
    Payload(u64),
    Zero,
    /// Offset of the authenticated 16-byte-per-granule old-digest table.
    SourceFree(u64),
}

#[derive(Debug, Clone, Copy)]
enum NewBytes {
    Payload(u64),
    Zero,
    OldReference(u64),
}

fn at<R: Read + Seek>(io: &mut R, offset: u64, bytes: &mut [u8]) -> Result<()> {
    io.seek(SeekFrom::Start(offset))?;
    io.read_exact(bytes)?;
    Ok(())
}

/// A journal read in the order of its bytes, through a window.
///
/// A pass over a journal's rows read each descriptor (a hundred bytes) and
/// each stored payload (a few tens of kilobytes on average) with a request
/// of its own to the file, and asked the file for its position after every
/// payload: five requests a row or more. On the full Windows volume that
/// is 284,000 rows over 13 GB, and a recovery's scan of them read 100 MB a
/// second where hashing the same bytes four megabytes at a time takes under
/// twenty seconds. Through this the file is asked for a window at a time and
/// the rows are handed out of the window; the position is counted here.
///
/// Only the size of a request changes. Every byte handed out is the byte of
/// the file at its offset: each request names its offset, as [`at`] does, so
/// the file's own position is never relied on and other reads of the same
/// file may come between two of these. Nothing beyond `limit` (the
/// journal's length) is asked for ahead of its use. A request for a window
/// that fails is forgotten, and from there on only what is asked for is
/// read, by itself, as before there was a window: an error is raised by
/// the read that would have raised it, and after everything that read used
/// to follow.
///
/// A pass may leave bytes out ([`Self::seek_to`]): the payloads, in a pass
/// over the descriptors alone. A window is asked for only where no more
/// than an eighth of one was passed over to reach the bytes that are
/// wanted; after a longer jump those bytes are read alone, as before. Rows
/// that store little or nothing follow each other closely and come many to
/// a request, with what lies between them; a row behind a long payload
/// comes with a request of its own. Such a pass reads bytes it has no use
/// for, which it did not before: at most one window of them for each read
/// it makes, and, going forward, never a byte of the file twice.
///
/// It holds no reference to the file, which each call is given, so that the
/// file's owner can read elsewhere in it between two calls.
pub(crate) struct InOrder {
    // What one request may read; empty where each read is its own request.
    window: Vec<u8>,
    // The bytes of the window not handed out yet.
    from: usize,
    to: usize,
    // Where in the file the next byte handed out lies.
    position: u64,
    limit: u64,
    // The bytes passed over since a byte was last handed out.
    gap: u64,
    // The bytes the file was asked for.
    read: u64,
}

impl InOrder {
    /// A reader at `position` of a file of `limit` bytes. With an empty
    /// window every read is a request for exactly its bytes, as it was
    /// before there were windows.
    pub(crate) fn through(window: Vec<u8>, position: u64, limit: u64) -> Self {
        Self {
            window,
            from: 0,
            to: 0,
            position,
            limit,
            gap: 0,
            read: 0,
        }
    }

    /// Where in the file the next byte handed out lies.
    pub(crate) fn position(&self) -> u64 {
        self.position
    }

    /// How many bytes the file was asked for.
    pub(crate) fn bytes_read(&self) -> u64 {
        self.read
    }

    /// The next byte handed out is the one at `offset`. Costs nothing: what
    /// the window already holds of it is kept.
    pub(crate) fn seek_to(&mut self, offset: u64) {
        match offset.checked_sub(self.position) {
            Some(forward) if forward <= (self.to - self.from) as u64 => {
                self.from += forward as usize;
            }
            _ => (self.from, self.to) = (0, 0),
        }
        self.gap = self.gap.saturating_add(offset.abs_diff(self.position));
        self.position = offset;
    }

    /// The next `bytes.len()` bytes of the file.
    pub(crate) fn read_exact<R: Read + Seek>(
        &mut self,
        io: &mut R,
        bytes: &mut [u8],
    ) -> Result<()> {
        let mut done = 0;
        while done < bytes.len() {
            if self.from == self.to && !self.fill(io, bytes.len() - done) {
                at(io, self.position, &mut bytes[done..])?;
                self.handed_out_from_the_file(bytes.len() - done);
                return Ok(());
            }
            let count = (self.to - self.from).min(bytes.len() - done);
            bytes[done..done + count].copy_from_slice(&self.window[self.from..self.from + count]);
            self.handed_out_from_the_window(count);
            done += count;
        }
        Ok(())
    }

    /// The next bytes of the file, at most `scratch.len()` of them and at
    /// least one: out of the window where it holds any, and otherwise read
    /// into `scratch`, all of it.
    pub(crate) fn next<'a, R: Read + Seek>(
        &'a mut self,
        io: &mut R,
        scratch: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        if scratch.is_empty() {
            return Ok(scratch);
        }
        if self.from == self.to && !self.fill(io, scratch.len()) {
            at(io, self.position, scratch)?;
            self.handed_out_from_the_file(scratch.len());
            return Ok(scratch);
        }
        let from = self.from;
        let count = (self.to - from).min(scratch.len());
        self.handed_out_from_the_window(count);
        Ok(&self.window[from..from + count])
    }

    fn handed_out_from_the_window(&mut self, count: usize) {
        self.from += count;
        self.position += count as u64;
        self.gap = 0;
    }

    fn handed_out_from_the_file(&mut self, count: usize) {
        self.position += count as u64;
        self.read += count as u64;
        self.gap = 0;
    }

    /// Asks the file for a window at the position, where the window holds
    /// nothing, would then hold more than the `asked` bytes that are
    /// wanted, and no long stretch was passed over to come here. False
    /// where it does not: the caller reads those bytes alone.
    fn fill<R: Read + Seek>(&mut self, io: &mut R, asked: usize) -> bool {
        if self.gap > (self.window.len() / 8) as u64 {
            return false;
        }
        let left = self.limit.saturating_sub(self.position);
        let count = self
            .window
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        if count <= asked {
            return false;
        }
        if at(io, self.position, &mut self.window[..count]).is_err() {
            // Whatever failed lies somewhere in the window, perhaps beyond
            // everything this pass will come to use before it stops for
            // another reason. The read of the bytes that are asked for
            // decides, now and from here on.
            self.window = Vec::new();
            (self.from, self.to) = (0, 0);
            return false;
        }
        (self.from, self.to) = (0, count);
        self.read += count as u64;
        true
    }
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed field"))
}
fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed field"))
}
/// The journal's pins, of the ticket's algorithm: BLAKE3 for a journal this
/// build writes; SHA-256 for one of an older build, through CNG on Windows
/// (faster on CPUs without SHA instructions) and the sha2 crate elsewhere.
type PinHash = crate::retained_compare::stream_digest::StreamDigest;
fn backend(algorithm: Algorithm) -> crate::retained_compare::stream_digest::Backend {
    crate::retained_compare::stream_digest::Backend::of(algorithm)
}
fn pin_hash(algorithm: Algorithm) -> Result<PinHash> {
    PinHash::new(backend(algorithm))
}
fn aggregate_pin_hash(algorithm: Algorithm) -> Result<PinHash> {
    PinHash::alongside_record_hash(BUFFER, backend(algorithm))
}
/// A file-wide digest whose caller hands it `buffers` megabytes in a burst.
fn burst_pin_hash(algorithm: Algorithm, buffers: usize) -> Result<PinHash> {
    PinHash::alongside_a_burst(BUFFER, backend(algorithm), buffers)
}
fn finish(hash: PinHash) -> Result<[u8; 32]> {
    hash.finish()
}

/// The digest of one row's payload: known, or owed by the worker that is
/// still hashing it.
#[must_use]
enum RowDigest {
    Known([u8; 32]),
    /// The next digest the worker gives that an earlier row is not owed.
    /// `zero_length` is the payload's length where every byte of it was
    /// checked to be zero.
    Owed {
        zero_length: Option<u64>,
    },
}

/// Where the digests of the rows' payloads are computed: on this thread,
/// between one read and the next, or on a worker while this thread reads on.
/// Either way a payload's digest is the digest (of the journal's algorithm)
/// of exactly the bytes that were read for it, in order.
struct RecordHashes {
    algorithm: Algorithm,
    worker: Option<crate::retained_compare::digest_pipeline::RecordDigests>,
}

impl RecordHashes {
    /// Every digest is computed on the calling thread and known at once.
    fn here(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            worker: None,
        }
    }

    /// A worker of its own where the machine has a core for it beside the
    /// reading thread and the workers of the file-wide digests.
    fn overlapped(algorithm: Algorithm) -> Result<Self> {
        if std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 4) {
            Self::on_a_worker(algorithm)
        } else {
            Ok(Self::here(algorithm))
        }
    }

    fn on_a_worker(algorithm: Algorithm) -> Result<Self> {
        Ok(Self {
            algorithm,
            worker: Some(
                crate::retained_compare::digest_pipeline::RecordDigests::with_native_backend(
                    BUFFER,
                    backend(algorithm),
                )?,
            ),
        })
    }

    fn begin(&mut self) -> Result<RecordHash<'_>> {
        Ok(match self.worker.as_mut() {
            Some(worker) => RecordHash::There(worker),
            None => RecordHash::Here(pin_hash(self.algorithm)?),
        })
    }

    /// The digest itself. Digests that are owed must be settled in the order
    /// their payloads were read. A payload that was checked to be zero is
    /// remembered here, as it is when its digest is known at once.
    fn settle(&mut self, digest: RowDigest, zero_digests: &mut ZeroDigests) -> Result<[u8; 32]> {
        match digest {
            RowDigest::Known(digest) => Ok(digest),
            RowDigest::Owed { zero_length } => {
                let digest = self
                    .worker
                    .as_mut()
                    .context("a row's digest is owed and there is no worker")?
                    .take()?;
                if let Some(length) = zero_length {
                    zero_digests.remember_verified(length, digest);
                }
                Ok(digest)
            }
        }
    }

    /// Ends the worker; an error if it failed or a digest was left with it.
    fn finish(self) -> Result<()> {
        match self.worker {
            Some(worker) => worker.finish(),
            None => Ok(()),
        }
    }
}

enum RecordHash<'a> {
    Here(PinHash),
    There(&'a mut crate::retained_compare::digest_pipeline::RecordDigests),
}

impl RecordHash<'_> {
    fn update(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Here(hash) => hash.update(bytes),
            Self::There(worker) => worker.update(bytes),
        }
    }

    fn finish(self, zero_length: Option<u64>) -> Result<RowDigest> {
        match self {
            Self::Here(hash) => Ok(RowDigest::Known(finish(hash)?)),
            Self::There(worker) => {
                worker.end_record()?;
                Ok(RowDigest::Owed { zero_length })
            }
        }
    }
}

/// Operation-local SHA256(0^length) values. Only actual fully checked zero
/// candidates or freshly generated canonical zeros may populate this cache.
/// Keep the largest lengths: they also recur across the descriptor/resolved
/// readback passes, whereas a plain LRU would evict a large unique range.
struct ZeroDigests {
    entries: [(u64, [u8; 32]); 64],
    used: usize,
}
impl ZeroDigests {
    fn new() -> Self {
        Self {
            entries: [(0, [0; 32]); 64],
            used: 0,
        }
    }
    fn get(&self, length: u64) -> Option<[u8; 32]> {
        self.entries[..self.used]
            .iter()
            .find(|entry| entry.0 == length)
            .map(|entry| entry.1)
    }
    fn remember_verified(&mut self, length: u64, digest: [u8; 32]) {
        if self.get(length).is_some() {
            return;
        }
        if self.used < self.entries.len() {
            self.entries[self.used] = (length, digest);
            self.used += 1;
        } else if let Some((index, entry)) = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.0)
            && length > entry.0
        {
            self.entries[index] = (length, digest);
        }
    }
}
fn frame(hash: &mut PinHash, range: &SelectedRange) -> Result<()> {
    hash.update(&range.offset.to_le_bytes())?;
    hash.update(&range.length.to_le_bytes())
}

impl SelectedPlan {
    pub fn source_free_bytes(&self) -> Result<u64> {
        if self.source_free_ranges.is_empty() {
            return Ok(0);
        }
        let backup_granule = self
            .image_length
            .checked_sub(GRANULE)
            .context("source-free image lacks a backup boot granule")?;
        // COPY destinations are ordered, but their source addresses need not
        // be. Merge their source union once rather than scanning C for each F.
        let mut protected = self
            .new_copy_ranges
            .iter()
            .map(|copy| {
                Ok((
                    copy.source_offset,
                    copy.source_offset
                        .checked_add(copy.length)
                        .context("copy source overflow")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        protected.sort_unstable();
        let mut used = 0usize;
        for position in 0..protected.len() {
            let current = protected[position];
            if used != 0 && current.0 <= protected[used - 1].1 {
                protected[used - 1].1 = protected[used - 1].1.max(current.1);
            } else {
                protected[used] = current;
                used += 1;
            }
        }
        protected.truncate(used);
        let mut index = 0usize;
        let mut bytes = 0u64;
        for free in &self.source_free_ranges {
            while index < self.ranges.len() && self.ranges[index].offset < free.offset {
                index += 1;
            }
            ensure!(
                self.ranges.get(index) == Some(free),
                "source-free ranges must be a sorted unique exact subset of selected ranges"
            );
            ensure!(
                free.offset >= GRANULE,
                "source-free range covers discovery bytes"
            );
            ensure!(
                self.old_zero_ranges
                    .binary_search_by_key(&free.offset, |r| r.offset)
                    .is_err(),
                "source-free and old-zero ranges overlap"
            );
            let end = free
                .offset
                .checked_add(free.length)
                .context("source-free range overflow")?;
            ensure!(
                end <= backup_granule,
                "source-free range covers the reserved backup boot granule"
            );
            let first = protected.partition_point(|&(_, source_end)| source_end <= free.offset);
            ensure!(
                protected.get(first).is_none_or(|&(start, _)| start >= end),
                "source-free range omits immutable copy-source bytes"
            );
            bytes = bytes
                .checked_add(free.length)
                .context("source-free byte total overflow")?;
            index += 1;
        }
        Ok(bytes)
    }

    pub fn old_restored_bytes(&self) -> Result<u64> {
        let total = self.ranges.iter().try_fold(0u64, |sum, r| {
            sum.checked_add(r.length)
                .context("selected byte total overflow")
        })?;
        total
            .checked_sub(self.source_free_bytes()?)
            .context("source-free bytes exceed selection")
    }

    pub fn old_zero_bytes(&self) -> Result<u64> {
        let mut index = 0usize;
        let mut bytes = 0u64;
        for zero in &self.old_zero_ranges {
            while index < self.ranges.len() && self.ranges[index].offset < zero.offset {
                index += 1;
            }
            ensure!(
                self.ranges.get(index) == Some(zero),
                "old-zero ranges must be a sorted unique exact subset of selected ranges"
            );
            bytes = bytes
                .checked_add(zero.length)
                .context("old-zero byte total overflow")?;
            index += 1;
        }
        Ok(bytes)
    }

    pub fn new_copy_bytes(&self) -> Result<u64> {
        self.new_zero_bytes()?;
        let mut index = 0usize;
        let mut bytes = 0u64;
        for copy in &self.new_copy_ranges {
            while index < self.ranges.len() && self.ranges[index].offset < copy.offset {
                index += 1;
            }
            ensure!(
                self.ranges
                    .get(index)
                    .is_some_and(|r| r.offset == copy.offset && r.length == copy.length),
                "copy ranges must be a sorted unique exact subset of selected ranges"
            );
            ensure!(
                self.new_zero_ranges
                    .binary_search_by_key(&copy.offset, |r| r.offset)
                    .is_err(),
                "copy and zero destination ranges overlap"
            );
            let end = copy
                .source_offset
                .checked_add(copy.length)
                .context("copy source overflow")?;
            ensure!(
                copy.source_offset.is_multiple_of(GRANULE)
                    && copy.length > 0
                    && copy.length.is_multiple_of(GRANULE)
                    && end <= self.image_length,
                "copy source is unaligned or escapes the image"
            );
            let mut source_index = self.ranges.partition_point(|r| {
                r.offset
                    .checked_add(r.length)
                    .is_some_and(|end| end <= copy.source_offset)
            });
            let mut cursor = copy.source_offset;
            while cursor < end {
                let range = self
                    .ranges
                    .get(source_index)
                    .context("copy source leaves selected old payload")?;
                let range_end = range
                    .offset
                    .checked_add(range.length)
                    .context("selected old range overflow")?;
                ensure!(
                    range.offset <= cursor && cursor < range_end,
                    "copy source crosses an unjournaled gap"
                );
                cursor = end.min(range_end);
                source_index += 1;
            }
            bytes = bytes
                .checked_add(copy.length)
                .context("copy byte total overflow")?;
            index += 1;
        }
        Ok(bytes)
    }

    pub fn new_zero_bytes(&self) -> Result<u64> {
        let mut index = 0usize;
        let mut bytes = 0u64;
        for zero in &self.new_zero_ranges {
            while index < self.ranges.len() && self.ranges[index].offset < zero.offset {
                index += 1;
            }
            ensure!(
                self.ranges.get(index) == Some(zero),
                "zero ranges must be a sorted unique exact subset of selected ranges"
            );
            bytes = bytes
                .checked_add(zero.length)
                .context("zero byte total overflow")?;
            index += 1;
        }
        Ok(bytes)
    }

    fn zero_encoded(&self) -> bool {
        !self.new_zero_ranges.is_empty()
    }

    fn copy_encoded(&self) -> bool {
        !self.new_copy_ranges.is_empty()
    }

    fn old_zero_encoded(&self) -> bool {
        !self.old_zero_ranges.is_empty()
    }

    fn source_free_encoded(&self) -> bool {
        !self.source_free_ranges.is_empty()
    }

    /// The default encoding; explicit redundant preparation selects format six.
    /// Empty old-zero lists retain legacy names.
    pub fn encoding_name(&self) -> &'static str {
        std::str::from_utf8(self.magic()).expect("selected journal ASCII magic")
    }

    pub fn encoding_version(&self) -> u32 {
        self.format()
    }

    /// Exact opt-in format-six size, including all eight marker slots. This
    /// changes no source-free admission or selected-byte verification rule.
    pub fn validate_redundant_source_free(&self) -> Result<(u64, u64)> {
        self.validate_marker_profile(Some(SelectedMarkerProfile::RedundantSourceFreeV1))
    }

    pub(crate) fn validate_marker_profile(
        &self,
        profile: Option<SelectedMarkerProfile>,
    ) -> Result<(u64, u64)> {
        let (changed, legacy_length) = self.validate()?;
        if profile.is_none() {
            return Ok((changed, legacy_length));
        }
        ensure!(
            self.source_free_encoded(),
            "redundant marker profile requires a source-free plan"
        );
        let journal_length = legacy_length
            .checked_add(REDUNDANT_BODY - BODY)
            .context("redundant selected journal length overflow")?;
        ensure!(
            journal_length <= self.max_journal_bytes,
            "redundant selected journal exceeds caller budget"
        );
        Ok((changed, journal_length))
    }

    fn format_with_markers(&self, profile: Option<SelectedMarkerProfile>) -> u32 {
        match profile {
            None => self.format(),
            Some(SelectedMarkerProfile::RedundantSourceFreeV1) => REDUNDANT_SOURCE_FREE_FORMAT,
        }
    }

    fn magic_with_markers(&self, profile: Option<SelectedMarkerProfile>) -> &'static [u8; 8] {
        match profile {
            None => self.magic(),
            Some(SelectedMarkerProfile::RedundantSourceFreeV1) => b"N2RFRE02",
        }
    }

    fn footer_magic_with_markers(
        &self,
        profile: Option<SelectedMarkerProfile>,
    ) -> &'static [u8; 8] {
        match profile {
            None => self.footer_magic(),
            Some(SelectedMarkerProfile::RedundantSourceFreeV1) => b"N2RFEND2",
        }
    }

    fn copy_source(&self, range: &SelectedRange) -> Option<u64> {
        self.new_copy_ranges
            .binary_search_by_key(&range.offset, |r| r.offset)
            .ok()
            .map(|i| self.new_copy_ranges[i].source_offset)
    }

    fn format(&self) -> u32 {
        if self.source_free_encoded() {
            SOURCE_FREE_FORMAT
        } else if self.old_zero_encoded() {
            OLD_ZERO_FORMAT
        } else if self.copy_encoded() {
            COPY_FORMAT
        } else if self.zero_encoded() {
            ZERO_FORMAT
        } else {
            FORMAT
        }
    }

    fn magic(&self) -> &'static [u8; 8] {
        if self.source_free_encoded() {
            b"N2RFRE01"
        } else if self.old_zero_encoded() {
            b"N2ROLD01"
        } else if self.copy_encoded() {
            b"N2RCPY01"
        } else if self.zero_encoded() {
            b"N2RZERO1"
        } else {
            b"N2RSEL01"
        }
    }

    fn footer_magic(&self) -> &'static [u8; 8] {
        if self.source_free_encoded() {
            b"N2RFEND1"
        } else if self.old_zero_encoded() {
            b"N2ROEND1"
        } else if self.copy_encoded() {
            b"N2RCEND1"
        } else if self.zero_encoded() {
            b"N2RZEND1"
        } else {
            b"N2RSEND1"
        }
    }

    fn is_new_zero(&self, range: &SelectedRange) -> bool {
        self.new_zero_ranges
            .binary_search_by_key(&range.offset, |r| r.offset)
            .is_ok()
    }

    fn is_old_zero(&self, range: &SelectedRange) -> bool {
        self.old_zero_ranges
            .binary_search_by_key(&range.offset, |r| r.offset)
            .is_ok()
    }

    fn is_source_free(&self, range: &SelectedRange) -> bool {
        self.source_free_ranges
            .binary_search_by_key(&range.offset, |r| r.offset)
            .is_ok()
    }

    fn record_size(&self) -> usize {
        if self.source_free_encoded() || self.old_zero_encoded() {
            OLD_ZERO_RECORD
        } else if self.copy_encoded() {
            COPY_RECORD
        } else if self.zero_encoded() {
            ZERO_RECORD
        } else {
            RECORD
        }
    }

    /// Computes exact journal size with checked arithmetic and bounded range
    /// memory. No filesystem or write-set correctness is implied.
    pub fn validate(&self) -> Result<(u64, u64)> {
        ensure!(
            self.image_length >= GRANULE
                && self.image_length.is_multiple_of(GRANULE)
                && !self.ranges.is_empty()
                && self.ranges.len() <= MAX_RANGES
                && self.max_selected_bytes <= self.image_length,
            "selected journal geometry or range budget invalid"
        );
        let mut previous_end = 0u64;
        let mut changed = 0u64;
        for range in &self.ranges {
            let end = range
                .offset
                .checked_add(range.length)
                .context("selected range overflow")?;
            ensure!(
                range.length != 0
                    && range.offset.is_multiple_of(GRANULE)
                    && range.length.is_multiple_of(GRANULE)
                    && range.offset >= previous_end
                    && end <= self.image_length,
                "selected ranges overlap, are unaligned or escape the image"
            );
            previous_end = end;
            changed = changed
                .checked_add(range.length)
                .context("selected byte total overflow")?;
        }
        ensure!(
            changed <= self.max_selected_bytes,
            "selected bytes exceed caller budget"
        );
        let zero_bytes = self.new_zero_bytes()?;
        let copy_bytes = self.new_copy_bytes()?;
        let old_zero_bytes = self.old_zero_bytes()?;
        let source_free_bytes = self.source_free_bytes()?;
        let journal_length = BODY
            .checked_add(HEADER as u64)
            .and_then(|n| {
                n.checked_add((self.ranges.len() as u64).checked_mul(self.record_size() as u64)?)
            })
            .and_then(|n| {
                n.checked_add(
                    changed
                        .checked_mul(2)?
                        .checked_sub(zero_bytes)?
                        .checked_sub(copy_bytes)?
                        .checked_sub(old_zero_bytes)?
                        .checked_sub(source_free_bytes)?
                        .checked_add((source_free_bytes / GRANULE).checked_mul(FREE_DIGEST)?)?,
                )
            })
            .and_then(|n| n.checked_add(FOOTER as u64))
            .context("selected journal length overflow")?;
        ensure!(
            journal_length <= self.max_journal_bytes,
            "selected journal exceeds caller budget"
        );
        Ok((changed, journal_length))
    }
}

fn extend(runs: &mut Vec<SelectedRange>, offset: u64, length: u64) -> Result<()> {
    if let Some(last) = runs.last_mut()
        && last.offset + last.length == offset
    {
        last.length += length;
        return Ok(());
    }
    ensure!(
        runs.len() < MAX_RANGES,
        "differing granule runs exceed the selected journal range limit"
    );
    runs.push(SelectedRange { offset, length });
    Ok(())
}

/// Narrow a coarse selection to the 4 KiB granules in which `source` and
/// `candidate` differ, so equal bytes are neither journaled nor written. Both
/// inputs are read once over the coarse ranges and nowhere else. The coarse
/// selection is validated with the plan geometry rules but not authenticated,
/// and the result holds only while both inputs stay unchanged under the
/// caller's exclusion until the apply completes. It certifies nothing about
/// bytes outside the coarse selection.
pub fn changed_plan<R: ReadSeek, S: ReadSeek>(
    source: &mut R,
    candidate: &mut S,
    image_length: u64,
    coarse: &[SelectedRange],
    max_selected_bytes: u64,
    max_journal_bytes: u64,
) -> Result<SelectedPlan> {
    validate_coarse(image_length, coarse)?;
    ensure!(
        source.byte_len()? == image_length && candidate.byte_len()? == image_length,
        "planning inputs differ in length from the image"
    );
    let mut before = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let mut runs = Vec::new();
    for range in coarse {
        let mut done = 0u64;
        while done < range.length {
            let count = usize::try_from((range.length - done).min(BUFFER as u64))?;
            let base = range.offset + done;
            at(source, base, &mut before[..count])?;
            at(candidate, base, &mut after[..count])?;
            record_differing_granules(&mut runs, base, &before[..count], &after[..count])?;
            done += count as u64;
        }
    }
    finish_changed_plan(image_length, runs, max_selected_bytes, max_journal_bytes)
}

/// Geometry check for a coarse planning selection; budgets apply to the result.
pub(crate) fn validate_coarse(image_length: u64, coarse: &[SelectedRange]) -> Result<()> {
    SelectedPlan {
        image_length,
        ranges: coarse.to_vec(),
        max_selected_bytes: image_length,
        max_journal_bytes: u64::MAX,
        new_zero_ranges: Vec::new(),
        new_copy_ranges: Vec::new(),
        old_zero_ranges: Vec::new(),
        source_free_ranges: Vec::new(),
    }
    .validate()?;
    Ok(())
}

/// Append the differing 4 KiB granules of one paired chunk read at `base`.
/// Shared by readers that cannot lend two independent handles to `changed_plan`.
pub(crate) fn record_differing_granules(
    runs: &mut Vec<SelectedRange>,
    base: u64,
    before: &[u8],
    after: &[u8],
) -> Result<()> {
    ensure!(
        before.len() == after.len() && before.len().is_multiple_of(GRANULE as usize),
        "paired planning chunks differ or are not granule aligned"
    );
    let granules = before
        .chunks(GRANULE as usize)
        .zip(after.chunks(GRANULE as usize));
    for (index, (old, new)) in granules.enumerate() {
        if old != new {
            extend(runs, base + index as u64 * GRANULE, GRANULE)?;
        }
    }
    Ok(())
}

pub(crate) fn finish_changed_plan(
    image_length: u64,
    runs: Vec<SelectedRange>,
    max_selected_bytes: u64,
    max_journal_bytes: u64,
) -> Result<SelectedPlan> {
    ensure!(
        !runs.is_empty(),
        "coarse selection contains no differing granule"
    );
    let plan = SelectedPlan {
        image_length,
        ranges: runs,
        max_selected_bytes,
        max_journal_bytes,
        new_zero_ranges: Vec::new(),
        new_copy_ranges: Vec::new(),
        old_zero_ranges: Vec::new(),
        source_free_ranges: Vec::new(),
    };
    plan.validate()?;
    Ok(plan)
}

fn hash_range<R: Read + Seek>(
    io: &mut R,
    algorithm: Algorithm,
    offset: u64,
    length: u64,
) -> Result<[u8; 32]> {
    io.seek(SeekFrom::Start(offset))?;
    let mut hash = pin_hash(algorithm)?;
    let mut buffer = vec![0; BUFFER];
    let mut remaining = length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        io.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count])?;
        remaining -= count as u64;
    }
    finish(hash)
}

fn copy_selected<R: Read + Seek, J: Write>(
    input: &mut R,
    range: &SelectedRange,
    journal: &mut J,
    selected: &mut PinHash,
    buffer: &mut [u8],
    restored: Option<&mut PinHash>,
) -> Result<[u8; 32]> {
    let mut here = RecordHashes::here(selected.algorithm());
    let digest = copy_selected_with(input, range, journal, selected, buffer, restored, &mut here)?;
    here.settle(digest, &mut ZeroDigests::new())
}

/// [`copy_selected`] with the payload's own digest computed where `records`
/// computes it. The bytes read, written and given to the aggregates are the
/// same, in the same order.
fn copy_selected_with<R: Read + Seek, J: Write>(
    input: &mut R,
    range: &SelectedRange,
    journal: &mut J,
    selected: &mut PinHash,
    buffer: &mut [u8],
    mut restored: Option<&mut PinHash>,
    records: &mut RecordHashes,
) -> Result<RowDigest> {
    input.seek(SeekFrom::Start(range.offset))?;
    frame(selected, range)?;
    if let Some(restored) = restored.as_deref_mut() {
        frame(restored, range)?;
    }
    let mut hash = records.begin()?;
    let mut remaining = range.length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        input.read_exact(&mut buffer[..count])?;
        journal.write_all(&buffer[..count])?;
        selected.update(&buffer[..count])?;
        if let Some(restored) = restored.as_deref_mut() {
            restored.update(&buffer[..count])?;
        }
        hash.update(&buffer[..count])?;
        remaining -= count as u64;
    }
    hash.finish(None)
}

fn verify_zero_selected<R: Read + Seek>(
    input: &mut R,
    range: &SelectedRange,
    selected: &mut PinHash,
    buffer: &mut [u8],
    zero_digests: &mut ZeroDigests,
    mismatch: &'static str,
    restored: Option<&mut PinHash>,
) -> Result<[u8; 32]> {
    let mut here = RecordHashes::here(selected.algorithm());
    let digest = verify_zero_selected_with(
        input,
        range,
        selected,
        buffer,
        zero_digests,
        mismatch,
        restored,
        &mut here,
    )?;
    here.settle(digest, zero_digests)
}

/// [`verify_zero_selected`] with the payload's own digest computed where
/// `records` computes it. Every byte is still read, checked to be zero and
/// given to the aggregates on this thread; a digest that is owed is
/// remembered for its length when it is settled, not before.
fn verify_zero_selected_with<R: Read + Seek>(
    input: &mut R,
    range: &SelectedRange,
    selected: &mut PinHash,
    buffer: &mut [u8],
    zero_digests: &mut ZeroDigests,
    mismatch: &'static str,
    mut restored: Option<&mut PinHash>,
    records: &mut RecordHashes,
) -> Result<RowDigest> {
    input.seek(SeekFrom::Start(range.offset))?;
    frame(selected, range)?;
    if let Some(restored) = restored.as_deref_mut() {
        frame(restored, range)?;
    }
    let cached = zero_digests.get(range.length);
    let mut hash = if cached.is_some() {
        None
    } else {
        Some(records.begin()?)
    };
    let mut remaining = range.length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        input.read_exact(&mut buffer[..count])?;
        ensure!(buffer[..count].iter().all(|&byte| byte == 0), mismatch);
        selected.update(&buffer[..count])?;
        if let Some(restored) = restored.as_deref_mut() {
            restored.update(&buffer[..count])?;
        }
        if let Some(hash) = hash.as_mut() {
            hash.update(&buffer[..count])?;
        }
        remaining -= count as u64;
    }
    let digest = match hash {
        Some(hash) => hash.finish(Some(range.length))?,
        None => RowDigest::Known(cached.context("verified zero digest absent")?),
    };
    // No hit can bypass even one actual input byte or its aggregate update.
    if let RowDigest::Known(digest) = &digest {
        zero_digests.remember_verified(range.length, *digest);
    }
    Ok(digest)
}

fn capture_free_selected<R: Read + Seek, J: Write>(
    source: &mut R,
    range: &SelectedRange,
    journal: &mut J,
    selected: &mut PinHash,
    buffer: &mut [u8],
) -> Result<[u8; 32]> {
    source.seek(SeekFrom::Start(range.offset))?;
    frame(selected, range)?;
    let mut table_hash = pin_hash(selected.algorithm())?;
    // The binary table is streamed; it never expands the JSON plan or the
    // retained record vector by one entry per source-free cluster.
    let mut table = vec![0u8; buffer.len() / GRANULE as usize * FREE_DIGEST as usize];
    let mut remaining = range.length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))?;
        source.read_exact(&mut buffer[..count])?;
        selected.update(&buffer[..count])?;
        let table_count = count / GRANULE as usize * FREE_DIGEST as usize;
        for (granule, digest) in buffer[..count]
            .chunks_exact(GRANULE as usize)
            .zip(table[..table_count].chunks_exact_mut(FREE_DIGEST as usize))
        {
            digest.copy_from_slice(&xxhash_rust::xxh3::xxh3_128(granule).to_le_bytes());
        }
        journal.write_all(&table[..table_count])?;
        table_hash.update(&table[..table_count])?;
        remaining -= count as u64;
    }
    finish(table_hash)
}

fn verify_copy_selected<R: Read + Seek, S: Read + Seek>(
    source: &mut R,
    candidate: &mut S,
    ranges: &[SelectedRange],
    range: &SelectedRange,
    source_offset: u64,
    selected: &mut PinHash,
    before: &mut [u8],
    after: &mut [u8],
    same_native_source: bool,
) -> Result<[u8; 32]> {
    frame(selected, range)?;
    let mut hash = pin_hash(selected.algorithm())?;
    let mut done = 0u64;
    while done < range.length {
        let count = usize::try_from((range.length - done).min(BUFFER as u64))?;
        at(candidate, range.offset + done, &mut after[..count])?;
        if same_native_source {
            // The typed entry checked both real frozen readers and every
            // reference against DifferenceImage's actual raw-source branch.
            // This candidate read already read these exact physical bytes.
            // Complete resolved J readback still independently authenticates
            // their equality to the saved old COPY source before ticket issue.
            selected.update(&after[..count])?;
            hash.update(&after[..count])?;
            done += count as u64;
            continue;
        }
        let mut cursor = source_offset + done;
        let mut filled = 0usize;
        while filled < count {
            let index = ranges.partition_point(|r| r.offset + r.length <= cursor);
            let old = ranges
                .get(index)
                .context("copy source leaves selected old ranges")?;
            ensure!(
                old.offset <= cursor,
                "copy source crosses an unjournaled gap"
            );
            let n =
                usize::try_from((old.offset + old.length - cursor).min((count - filled) as u64))?;
            at(source, cursor, &mut before[filled..filled + n])?;
            cursor += n as u64;
            filled += n;
        }
        ensure!(
            before[..count] == after[..count],
            "selected copy differs from original source bytes"
        );
        selected.update(&after[..count])?;
        hash.update(&after[..count])?;
        done += count as u64;
    }
    finish(hash)
}

/// Create and durably verify a new external journal. Only selected ranges are
/// read from the two images. Ticket issuance follows an independent readback.
#[cfg(test)]
pub fn prepare<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
) -> Result<SelectedTicket> {
    prepare_inner(source, candidate, journal, plan, false, false, None)
}

/// Explicit opt-in to N2RFRE02's redundant write-once lifecycle layout. All
/// source/candidate reads and pins are the format-five checks. This API does
/// not establish physical sector independence or strengthen the backend's
/// flush/readback contract; no native conversion caller opts in yet.
pub fn prepare_redundant_source_free<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
) -> Result<SelectedTicket> {
    prepare_inner(
        source,
        candidate,
        journal,
        plan,
        false,
        false,
        Some(SelectedMarkerProfile::RedundantSourceFreeV1),
    )
}

/// Prepare under continuous exclusive ownership of the new journal. The
/// caller must exclude writer/delete aliases, including hidden handles in the
/// source/candidate readers. Windows callers use a newly created share-zero
/// file and retain that owner throughout this call.
///
/// The complete post-flush validating readback computes the immutable pin
/// while checking descriptors, all payloads and source/candidate selected
/// digests. No preliminary hash-only scan is needed to issue the same pin.
/// Legacy preparation and every fresh recovery entry retain their checks.
#[allow(
    dead_code,
    reason = "retain the independently validating ticket-only exclusive entry point"
)]
pub(crate) fn prepare_exclusive<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
) -> Result<SelectedTicket> {
    prepare_inner(source, candidate, journal, plan, true, false, None)
}

fn prepare_inner<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
    exclusive_readback: bool,
    same_native_source: bool,
    marker_profile: Option<SelectedMarkerProfile>,
) -> Result<SelectedTicket> {
    ensure!(
        !same_native_source || exclusive_readback,
        "same-source construction proof requires the complete exclusive readback"
    );
    let (changed, journal_length) = plan.validate_marker_profile(marker_profile)?;
    let body = marker_body(marker_profile);
    ensure!(
        source.byte_len()? == plan.image_length
            && candidate.byte_len()? == plan.image_length
            && journal.byte_len()? == 0,
        "selected inputs differ in length or journal is not empty"
    );
    let mut header = [0u8; HEADER];
    let zero_encoded = plan.zero_encoded();
    let copy_encoded = plan.copy_encoded();
    let source_free_encoded = plan.source_free_encoded();
    let old_zero_encoded = plan.old_zero_encoded() || source_free_encoded;
    header[..8].copy_from_slice(plan.magic_with_markers(marker_profile));
    put_u32(&mut header, 8, plan.format_with_markers(marker_profile));
    put_u32(&mut header, 12, u32::try_from(plan.ranges.len())?);
    put_u64(&mut header, 16, plan.image_length);
    put_u64(&mut header, 24, changed);
    put_u64(&mut header, 32, journal_length);
    journal.seek(SeekFrom::Start(0))?;
    journal.write_all(&vec![0; body as usize])?;
    journal.write_all(&header)?;
    // Every digest of a journal this build writes, and its ticket's, is BLAKE3.
    let algorithm = Algorithm::WRITTEN;
    let mut old_selected = aggregate_pin_hash(algorithm)?;
    let mut old_restored = source_free_encoded
        .then(|| aggregate_pin_hash(algorithm))
        .transpose()?;
    let mut new_selected = aggregate_pin_hash(algorithm)?;
    // Fixed memory for the whole preparation; small fragmented ranges do not
    // repeatedly allocate/zero MiB-sized vectors. Each slice used below is
    // completely filled by its current read before hashing or comparison.
    let mut data_buffer = vec![0; BUFFER];
    let mut copy_buffer = vec![0; BUFFER];
    let mut zero_digests = ZeroDigests::new();
    for range in &plan.ranges {
        let record_at = journal.stream_position()?;
        let mut record = [0u8; OLD_ZERO_RECORD];
        journal.write_all(&record[..plan.record_size()])?;
        let old_is_zero = plan.is_old_zero(range);
        let old_is_free = plan.is_source_free(range);
        let old_hash = if old_is_free {
            capture_free_selected(source, range, journal, &mut old_selected, &mut data_buffer)?
        } else if old_is_zero {
            verify_zero_selected(
                source,
                range,
                &mut old_selected,
                &mut data_buffer,
                &mut zero_digests,
                "selected old-zero range contains nonzero source bytes",
                old_restored.as_mut(),
            )?
        } else {
            copy_selected(
                source,
                range,
                journal,
                &mut old_selected,
                &mut data_buffer,
                old_restored.as_mut(),
            )?
        };
        let is_zero = plan.is_new_zero(range);
        let copy_source = plan.copy_source(range);
        let new_hash = if is_zero {
            verify_zero_selected(
                candidate,
                range,
                &mut new_selected,
                &mut data_buffer,
                &mut zero_digests,
                "selected zero range contains nonzero candidate bytes",
                None,
            )?
        } else if let Some(source_offset) = copy_source {
            verify_copy_selected(
                source,
                candidate,
                &plan.ranges,
                range,
                source_offset,
                &mut new_selected,
                &mut data_buffer,
                &mut copy_buffer,
                same_native_source,
            )?
        } else {
            copy_selected(
                candidate,
                range,
                journal,
                &mut new_selected,
                &mut data_buffer,
                None,
            )?
        };
        let next = journal.stream_position()?;
        put_u64(&mut record, 0, range.offset);
        put_u64(&mut record, 8, range.length);
        let hashes = if old_zero_encoded || copy_encoded {
            put_u64(
                &mut record,
                16,
                if is_zero {
                    1
                } else if copy_source.is_some() {
                    2
                } else {
                    0
                },
            );
            put_u64(&mut record, 24, copy_source.unwrap_or(0));
            if old_zero_encoded {
                put_u64(
                    &mut record,
                    32,
                    if old_is_free {
                        2
                    } else {
                        u64::from(old_is_zero)
                    },
                );
                40
            } else {
                32
            }
        } else if zero_encoded {
            put_u64(&mut record, 16, u64::from(is_zero));
            24
        } else {
            16
        };
        record[hashes..hashes + 32].copy_from_slice(&old_hash);
        record[hashes + 32..hashes + 64].copy_from_slice(&new_hash);
        journal.seek(SeekFrom::Start(record_at))?;
        journal.write_all(&record[..plan.record_size()])?;
        journal.seek(SeekFrom::Start(next))?;
    }
    let old_selected_sha256 = finish(old_selected)?;
    let old_restored_selected_sha256 = old_restored.map(finish).transpose()?;
    let new_selected_sha256 = finish(new_selected)?;
    drop(data_buffer);
    drop(copy_buffer);
    let mut footer = [0u8; FOOTER];
    footer[..8].copy_from_slice(plan.footer_magic_with_markers(marker_profile));
    footer[8..40].copy_from_slice(&old_selected_sha256);
    footer[40..72].copy_from_slice(&new_selected_sha256);
    put_u64(&mut footer, 72, journal_length);
    journal.write_all(&footer)?;
    if let Some(restored) = old_restored_selected_sha256 {
        header[40..72].copy_from_slice(&restored);
        put_u64(&mut header, 72, plan.source_free_bytes()?);
        journal.seek(SeekFrom::Start(body))?;
        journal.write_all(&header)?;
        journal.seek(SeekFrom::Start(journal_length))?;
    }
    ensure!(
        journal.byte_len()? == journal_length
            && source.byte_len()? == plan.image_length
            && candidate.byte_len()? == plan.image_length,
        "selected preparation input or journal length changed"
    );
    journal.sync_all()?;
    let mut ticket = SelectedTicket {
        image_length: plan.image_length,
        selected_bytes: changed,
        range_count: u32::try_from(plan.ranges.len())?,
        journal_length,
        // This internal value is never returned or persisted before the
        // validating readback supplies the actual digest below.
        immutable_sha256: [0; 32],
        marker_profile,
        old_selected_sha256,
        old_restored_selected_sha256,
        new_selected_sha256,
        whole_image_verified: false,
        digest: Some(algorithm),
    };
    // Only this complete post-flush validation lets the ticket out.
    if exclusive_readback {
        let (_, immutable_sha256) = validate_body(journal, plan, &ticket, None, &mut zero_digests)?;
        ticket.immutable_sha256 = immutable_sha256;
    } else {
        ticket.immutable_sha256 = hash_range(journal, algorithm, body, journal_length - body)?;
        validate_body(
            journal,
            plan,
            &ticket,
            Some(&ticket.immutable_sha256),
            &mut zero_digests,
        )?;
    }
    let mut markers = vec![0u8; body as usize];
    at(journal, 0, &mut markers)?;
    ensure!(
        markers.iter().all(|&b| b == 0),
        "selected journal markers are not clear"
    );
    Ok(ticket)
}

/// Recheck the pinned complete immutable journal and each payload in one
/// sequential read pass. Synthetic zero bytes participate in the selected
/// digests, never the immutable journal digest. No record is returned before
/// the complete immutable pin and all payload/footer checks have passed.
/// Even a valid serialized ticket must be trusted independently by the caller.
fn load<J: ReadSeek>(
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<Vec<JournalRecord>> {
    let mut zero_digests = ZeroDigests::new();
    Ok(validate_body(
        journal,
        plan,
        ticket,
        Some(&ticket.immutable_sha256),
        &mut zero_digests,
    )?
    .0)
}

/// No pin is issued, nor record returned, until the whole independent readback
/// and every selected/payload check succeeds. Only new-journal preparation may
/// create a pin; all journal consumers require the independently trusted pin.
fn validate_body<J: ReadSeek>(
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    expected_immutable: Option<&[u8; 32]>,
    zero_digests: &mut ZeroDigests,
) -> Result<(Vec<JournalRecord>, [u8; 32])> {
    let (changed, journal_length) = plan.validate_marker_profile(ticket.marker_profile)?;
    let body = ticket.body_offset();
    ensure!(
        !ticket.whole_image_verified
            && ticket.old_restored_selected_sha256.is_some() == plan.source_free_encoded()
            && ticket.image_length == plan.image_length
            && ticket.selected_bytes == changed
            && ticket.range_count as usize == plan.ranges.len()
            && ticket.journal_length == journal_length
            && journal.byte_len()? == journal_length,
        "selected ticket, plan or journal length differs"
    );
    let algorithm = ticket.digest_algorithm();
    let mut immutable = aggregate_pin_hash(algorithm)?;
    let mut header = [0u8; HEADER];
    at(journal, body, &mut header)?;
    immutable.update(&header)?;
    let zero_encoded = plan.zero_encoded();
    let copy_encoded = plan.copy_encoded();
    let source_free_encoded = plan.source_free_encoded();
    let old_zero_encoded = plan.old_zero_encoded() || source_free_encoded;
    ensure!(
        &header[..8] == plan.magic_with_markers(ticket.marker_profile)
            && get_u32(&header, 8) == plan.format_with_markers(ticket.marker_profile)
            && get_u32(&header, 12) == ticket.range_count
            && get_u64(&header, 16) == plan.image_length
            && get_u64(&header, 24) == changed
            && get_u64(&header, 32) == journal_length
            && if let Some(restored) = ticket.old_restored_selected_sha256 {
                header[40..72] == restored && get_u64(&header, 72) == plan.source_free_bytes()?
            } else {
                header[40..].iter().all(|&b| b == 0)
            },
        "selected journal header differs"
    );
    let mut records = Vec::with_capacity(plan.ranges.len());
    let mut old_selected = aggregate_pin_hash(algorithm)?;
    // Copy-format new selected bytes are authenticated in the resolved pass
    // below. Do not start an unused worker for this first descriptor pass.
    let mut new_selected = if copy_encoded {
        pin_hash(algorithm)?
    } else {
        aggregate_pin_hash(algorithm)?
    };
    let mut buffer = vec![0; BUFFER];
    for range in &plan.ranges {
        let mut record = [0u8; OLD_ZERO_RECORD];
        journal.read_exact(&mut record[..plan.record_size()])?;
        immutable.update(&record[..plan.record_size()])?;
        ensure!(
            get_u64(&record, 0) == range.offset && get_u64(&record, 8) == range.length,
            "selected journal range differs"
        );
        let before_at = journal.stream_position()?;
        let old_is_zero = plan.is_old_zero(range);
        let old_is_free = plan.is_source_free(range);
        let after_at = before_at
            .checked_add(if old_is_zero {
                0
            } else if old_is_free {
                range.length / GRANULE * FREE_DIGEST
            } else {
                range.length
            })
            .context("selected journal offset overflow")?;
        let is_zero = plan.is_new_zero(range);
        let copy_source = plan.copy_source(range);
        let hashes = if old_zero_encoded || copy_encoded {
            let kind = if is_zero {
                1
            } else if copy_source.is_some() {
                2
            } else {
                0
            };
            ensure!(
                get_u64(&record, 16) == kind && get_u64(&record, 24) == copy_source.unwrap_or(0),
                "selected journal copy descriptor differs from the pinned plan"
            );
            if old_zero_encoded {
                ensure!(
                    get_u64(&record, 32)
                        == if old_is_free {
                            2
                        } else {
                            u64::from(old_is_zero)
                        },
                    "selected journal old-zero descriptor differs from the pinned plan"
                );
                40
            } else {
                32
            }
        } else if zero_encoded {
            ensure!(
                get_u64(&record, 16) == u64::from(is_zero),
                "selected journal zero flag differs from the pinned plan"
            );
            24
        } else {
            16
        };
        let next = after_at
            .checked_add(if is_zero || copy_source.is_some() {
                0
            } else {
                range.length
            })
            .context("selected journal offset overflow")?;
        ensure!(
            next <= journal_length - FOOTER as u64,
            "selected journal payload truncated"
        );
        for old in [true, false] {
            if !old && copy_source.is_some() {
                continue; // The complete old-payload table is needed first.
            }
            if old && old_is_free {
                // The original free bytes deliberately do not exist in J.
                // Authenticate the entire digest table and its independent
                // immutable pin. Its truth is established from actual bytes
                // during preparation and the complete fresh target gate.
                let mut hash = pin_hash(algorithm)?;
                let mut remaining = range.length / GRANULE * FREE_DIGEST;
                while remaining != 0 {
                    let count = usize::try_from(remaining.min(BUFFER as u64))?;
                    journal.read_exact(&mut buffer[..count])?;
                    immutable.update(&buffer[..count])?;
                    hash.update(&buffer[..count])?;
                    remaining -= count as u64;
                }
                ensure!(
                    finish(hash)?.as_slice() == &record[hashes..hashes + 32],
                    "source-free old digest table differs"
                );
                continue;
            }
            let offset = if old {
                (!old_is_zero).then_some(before_at)
            } else {
                (!is_zero).then_some(after_at)
            };
            let expected = if old {
                &record[hashes..hashes + 32]
            } else {
                &record[hashes + 32..hashes + 64]
            };
            let mut selected = if old {
                Some(&mut old_selected)
            } else if !copy_encoded {
                Some(&mut new_selected)
            } else {
                None
            };
            if let Some(offset) = offset {
                ensure!(
                    journal.stream_position()? == offset,
                    "selected journal sequential payload position differs"
                );
            }
            if let Some(selected) = selected.as_deref_mut() {
                frame(selected, range)?;
            }
            // None is exclusively a canonical generated old/new zero side.
            // Actual old/literal payloads always keep their complete hashes.
            let cached = if offset.is_none() {
                zero_digests.get(range.length)
            } else {
                None
            };
            // A copy-format descriptor pass does not compute the new aggregate;
            // the resolved pass below does. If a canonical zero digest is
            // already known, no stored byte or aggregate update remains here.
            // Keep the descriptor check without repeatedly filling MiB buffers.
            if selected.is_none()
                && let Some(actual) = cached
            {
                ensure!(
                    actual.as_slice() == expected,
                    "selected zero digest differs"
                );
                continue;
            }
            let mut hash = if cached.is_some() {
                None
            } else {
                Some(pin_hash(algorithm)?)
            };
            let mut remaining = range.length;
            while remaining > 0 {
                let count = usize::try_from(remaining.min(BUFFER as u64))?;
                if offset.is_some() {
                    journal.read_exact(&mut buffer[..count])?;
                    immutable.update(&buffer[..count])?;
                } else {
                    buffer[..count].fill(0);
                }
                if let Some(selected) = selected.as_deref_mut() {
                    selected.update(&buffer[..count])?;
                }
                if let Some(hash) = hash.as_mut() {
                    hash.update(&buffer[..count])?;
                }
                remaining -= count as u64;
            }
            let actual = match hash {
                Some(hash) => finish(hash)?,
                None => cached.context("canonical zero digest absent")?,
            };
            ensure!(
                actual.as_slice() == expected,
                "selected journal payload hash differs"
            );
            if offset.is_none() {
                zero_digests.remember_verified(range.length, actual);
            }
        }
        records.push(JournalRecord {
            range: range.clone(),
            before: if old_is_free {
                OldBytes::SourceFree(before_at)
            } else if old_is_zero {
                OldBytes::Zero
            } else {
                OldBytes::Payload(before_at)
            },
            after: if is_zero {
                NewBytes::Zero
            } else if let Some(source) = copy_source {
                NewBytes::OldReference(source)
            } else {
                NewBytes::Payload(after_at)
            },
            new_sha256: record[hashes + 32..hashes + 64]
                .try_into()
                .expect("fixed digest"),
        });
        ensure!(
            journal.stream_position()? == next,
            "selected journal sequential record position differs"
        );
    }
    let mut footer = [0u8; FOOTER];
    journal.read_exact(&mut footer)?;
    immutable.update(&footer)?;
    ensure!(
        &footer[..8] == plan.footer_magic_with_markers(ticket.marker_profile)
            && footer[8..40] == ticket.old_selected_sha256
            && footer[40..72] == ticket.new_selected_sha256
            && get_u64(&footer, 72) == journal_length
            && finish(old_selected)?
                == ticket
                    .old_restored_selected_sha256
                    .unwrap_or(ticket.old_selected_sha256)
            && (copy_encoded || finish(new_selected)? == ticket.new_selected_sha256)
            && journal.stream_position()? == journal_length,
        "selected journal footer or selected digest differs"
    );
    let immutable_sha256 = finish(immutable)?;
    if let Some(expected) = expected_immutable {
        ensure!(
            &immutable_sha256 == expected,
            "selected immutable journal differs from trusted ticket"
        );
    }
    if copy_encoded {
        // All old payloads and descriptors are authenticated before any
        // reference is followed. References resolve only to those old bytes,
        // so overlap, forward references and reference cycles are harmless.
        let mut new_selected = aggregate_pin_hash(algorithm)?;
        for record in &records {
            frame(&mut new_selected, &record.range)?;
            let is_zero = matches!(record.after, NewBytes::Zero);
            let cached = if is_zero {
                zero_digests.get(record.range.length)
            } else {
                None
            };
            let mut hash = if cached.is_some() {
                None
            } else {
                Some(pin_hash(algorithm)?)
            };
            let mut done = 0u64;
            while done < record.range.length {
                let count = usize::try_from((record.range.length - done).min(BUFFER as u64))?;
                read_after(journal, &records, record, done, &mut buffer[..count])?;
                if let Some(hash) = hash.as_mut() {
                    hash.update(&buffer[..count])?;
                }
                new_selected.update(&buffer[..count])?;
                done += count as u64;
            }
            let actual = match hash {
                Some(hash) => finish(hash)?,
                None => cached.context("resolved zero digest absent")?,
            };
            ensure!(
                actual == record.new_sha256,
                "selected resolved copy hash differs"
            );
            if is_zero {
                zero_digests.remember_verified(record.range.length, actual);
            }
        }
        ensure!(
            finish(new_selected)? == ticket.new_selected_sha256,
            "selected resolved new digest differs"
        );
    }
    Ok((records, immutable_sha256))
}

fn marker(kind: &[u8; 8], ticket: &SelectedTicket, digest: &[u8; 32]) -> [u8; GRANULE as usize] {
    let mut marker = [0u8; GRANULE as usize];
    marker[..8].copy_from_slice(kind);
    marker[8..40].copy_from_slice(&ticket.immutable_sha256);
    marker[40..72].copy_from_slice(digest);
    let hash: [u8; 32] = Sha256::digest(&marker[..GRANULE as usize - 32]).into();
    marker[GRANULE as usize - 32..].copy_from_slice(&hash);
    marker
}

#[derive(Clone, Copy)]
enum MarkerKind {
    Apply,
    Rollback,
    Handoff,
    Aborted,
}

impl MarkerKind {
    fn first_slot(self) -> u64 {
        match self {
            Self::Apply => 0,
            Self::Rollback => 2,
            Self::Handoff => 4,
            Self::Aborted => 6,
        }
    }

    fn magic(self, redundant: bool) -> &'static [u8; 8] {
        match (self, redundant) {
            (Self::Apply, false) => b"N2RSAP01",
            (Self::Rollback, false) => b"N2RSRB01",
            (Self::Handoff, false) => b"N2RSHN01",
            (Self::Aborted, false) => b"N2RSAB01",
            (Self::Apply, true) => b"N2RSAP02",
            (Self::Rollback, true) => b"N2RSRB02",
            (Self::Handoff, true) => b"N2RSHN02",
            (Self::Aborted, true) => b"N2RSAB02",
        }
    }

    fn digest(self, ticket: &SelectedTicket) -> &[u8; 32] {
        match self {
            Self::Apply | Self::Handoff => &ticket.new_selected_sha256,
            Self::Rollback | Self::Aborted => &ticket.old_selected_sha256,
        }
    }
}

fn redundant_marker(
    kind: MarkerKind,
    copy: u32,
    ticket: &SelectedTicket,
) -> [u8; GRANULE as usize] {
    let mut value = [0u8; GRANULE as usize];
    value[..8].copy_from_slice(kind.magic(true));
    put_u32(&mut value, 8, REDUNDANT_SOURCE_FREE_FORMAT);
    put_u32(&mut value, 12, copy);
    value[16..48].copy_from_slice(&ticket.immutable_sha256);
    // The original complete old identity is retained even when ABT verifies
    // only restore-required bytes. Neither that subset nor its hash replaces it.
    value[48..80].copy_from_slice(&ticket.old_selected_sha256);
    value[80..112].copy_from_slice(&ticket.new_selected_sha256);
    put_u64(&mut value, 112, ticket.journal_length);
    put_u64(&mut value, 120, ticket.image_length);
    put_u64(&mut value, 128, ticket.selected_bytes);
    put_u32(&mut value, 136, ticket.range_count);
    let hash: [u8; 32] = Sha256::digest(&value[..GRANULE as usize - 32]).into();
    value[GRANULE as usize - 32..].copy_from_slice(&hash);
    value
}

fn marker_self_hash_valid(value: &[u8; GRANULE as usize]) -> bool {
    let hash: [u8; 32] = Sha256::digest(&value[..GRANULE as usize - 32]).into();
    value[GRANULE as usize - 32..] == hash
}

/// Fixed lab-only codec images for an inactive second marker copy. These are
/// not journal authority: recovery must still authenticate the actual journal,
/// and the native owner must verify the intact first copy and zero peer before
/// using them. No caller-supplied byte mutation or offset is accepted.
pub(crate) fn lab_fault_peer_images(
    ticket: &SelectedTicket,
    peer_label: &str,
) -> Result<(
    [u8; GRANULE as usize],
    [u8; GRANULE as usize],
    [u8; GRANULE as usize],
)> {
    ensure!(
        ticket.marker_profile == Some(SelectedMarkerProfile::RedundantSourceFreeV1),
        "lab marker fault requires the format-six codec"
    );
    let kind = match peer_label {
        "AP2" => MarkerKind::Apply,
        "RB2" => MarkerKind::Rollback,
        "HND2" => MarkerKind::Handoff,
        "ABT2" => MarkerKind::Aborted,
        _ => anyhow::bail!("lab marker fault permits only an inactive second copy"),
    };
    let first = redundant_marker(kind, 1, ticket);
    let peer = redundant_marker(kind, 2, ticket);
    let mut corrupt = peer;
    corrupt[GRANULE as usize - 1] ^= 1;
    ensure!(
        !marker_self_hash_valid(&corrupt),
        "lab marker fault codec did not damage the self hash"
    );
    Ok((first, peer, corrupt))
}

/// A positive exact copy can recover a peer with a damaged self hash. A valid
/// foreign identity/copy/kind is a conflict, never something to outvote. Zero
/// plus damage supplies no authenticated state and conservatively refuses.
fn read_marker_pair<J: Read + Seek>(
    journal: &mut J,
    ticket: &SelectedTicket,
    kind: MarkerKind,
) -> Result<bool> {
    let mut valid = false;
    let mut damaged = false;
    for copy in 1..=2 {
        let mut observed = [0u8; GRANULE as usize];
        at(
            journal,
            (kind.first_slot() + u64::from(copy - 1)) * GRANULE,
            &mut observed,
        )?;
        if observed == redundant_marker(kind, copy, ticket) {
            valid = true;
        } else if observed.iter().any(|&byte| byte != 0) {
            ensure!(
                !marker_self_hash_valid(&observed),
                "redundant selected marker has a valid conflicting identity or kind"
            );
            damaged = true;
        }
    }
    ensure!(
        valid || !damaged,
        "redundant selected marker has no authenticated intact copy"
    );
    Ok(valid)
}

fn classify_redundant<J: Read + Seek>(
    journal: &mut J,
    ticket: &SelectedTicket,
) -> Result<SelectedLifecycle> {
    // Read every pair before choosing a terminal state. HND/ABT never hide
    // damage or a conflicting state elsewhere in the marker body.
    let apply = read_marker_pair(journal, ticket, MarkerKind::Apply)?;
    let rollback = read_marker_pair(journal, ticket, MarkerKind::Rollback)?;
    let handoff = read_marker_pair(journal, ticket, MarkerKind::Handoff)?;
    let aborted = read_marker_pair(journal, ticket, MarkerKind::Aborted)?;
    match (apply, rollback, handoff, aborted) {
        (false, false, false, false) => Ok(SelectedLifecycle::PreparedClear),
        (true, false, false, false) => Ok(SelectedLifecycle::ApplyIntent),
        (true, true, false, false) => Ok(SelectedLifecycle::RollbackIntent),
        (true, false, true, false) => Ok(SelectedLifecycle::Handoff),
        (false, false, false, true) | (true, true, false, true) => Ok(SelectedLifecycle::Aborted),
        _ => anyhow::bail!("redundant selected lifecycle markers conflict"),
    }
}

fn read_markers<J: Read + Seek>(journal: &mut J, ticket: &SelectedTicket) -> Result<(bool, bool)> {
    if ticket.marker_profile.is_some() {
        return match classify_redundant(journal, ticket)? {
            SelectedLifecycle::PreparedClear => Ok((false, false)),
            SelectedLifecycle::ApplyIntent => Ok((true, false)),
            SelectedLifecycle::RollbackIntent => Ok((true, true)),
            SelectedLifecycle::Handoff | SelectedLifecycle::Aborted => {
                anyhow::bail!("selected replay is closed")
            }
        };
    }
    let mut completed = [0u8; GRANULE as usize];
    let mut intent = [0u8; GRANULE as usize];
    at(journal, 0, &mut completed)?;
    at(journal, GRANULE, &mut intent)?;
    ensure!(
        completed.iter().all(|&b| b == 0),
        "selected replay is closed or completion marker is foreign/torn"
    );
    let zero = [0u8; GRANULE as usize];
    let apply = marker(b"N2RSAP01", ticket, &ticket.new_selected_sha256);
    let rollback = marker(b"N2RSRB01", ticket, &ticket.old_selected_sha256);
    ensure!(
        intent == zero || intent == apply || intent == rollback,
        "selected intent marker is foreign or torn"
    );
    Ok((intent == apply, intent == rollback))
}

fn write_marker<J: DurableIo>(
    journal: &mut J,
    offset: u64,
    value: &[u8; GRANULE as usize],
) -> Result<()> {
    journal.seek(SeekFrom::Start(offset))?;
    journal
        .write_all(value)
        .context("short selected marker write")?;
    journal.sync_all()?;
    let mut observed = [0u8; GRANULE as usize];
    at(journal, offset, &mut observed)?;
    ensure!(&observed == value, "selected marker readback differs");
    Ok(())
}

fn write_lifecycle_marker<J: DurableIo>(
    journal: &mut J,
    ticket: &SelectedTicket,
    kind: MarkerKind,
) -> Result<()> {
    if ticket.marker_profile.is_none() {
        let offset = match kind {
            MarkerKind::Apply | MarkerKind::Rollback => GRANULE,
            MarkerKind::Handoff | MarkerKind::Aborted => 0,
        };
        return write_marker(
            journal,
            offset,
            &marker(kind.magic(false), ticket, kind.digest(ticket)),
        );
    }
    // The caller has already classified the full lifecycle and checked the
    // complete required target bytes. Slots are write-once by kind: RB can
    // never tear or replace AP. An authenticated peer permits repair only
    // with these same bytes. No target write/online may pass the two barriers.
    read_marker_pair(journal, ticket, kind)?;
    for copy in 1..=2 {
        let value = redundant_marker(kind, copy, ticket);
        let offset = (kind.first_slot() + u64::from(copy - 1)) * GRANULE;
        let mut observed = [0u8; GRANULE as usize];
        at(journal, offset, &mut observed)?;
        if observed == value {
            // Never put the sole intact copy at risk while repairing its peer.
            journal.sync_all()?;
            at(journal, offset, &mut observed)?;
            ensure!(observed == value, "selected marker readback differs");
        } else {
            write_marker(journal, offset, &value)?;
        }
    }
    Ok(())
}

/// Classification closes replay with one intact terminal peer. Native online
/// exposure is stricter: both closing copies must survive independent flush
/// and actual readback. A degraded terminal pair stays closed and offline;
/// this read-only check does not repair it or recreate replay authority.
pub(crate) fn require_redundant_terminal_barriers<J: DurableIo>(
    journal: &mut J,
    ticket: &SelectedTicket,
) -> Result<()> {
    ensure!(
        ticket.marker_profile.is_some(),
        "redundant terminal profile required"
    );
    let state = classify(journal, ticket)?;
    let kind = match state {
        SelectedLifecycle::Handoff => MarkerKind::Handoff,
        SelectedLifecycle::Aborted => MarkerKind::Aborted,
        _ => anyhow::bail!("native mount requires a closed selected journal"),
    };
    for copy in 1..=2 {
        journal.sync_all()?;
        let mut observed = [0u8; GRANULE as usize];
        at(
            journal,
            (kind.first_slot() + u64::from(copy - 1)) * GRANULE,
            &mut observed,
        )?;
        ensure!(
            observed == redundant_marker(kind, copy, ticket),
            "closed selected journal lacks both durable terminal copies; replay stays closed and target offline"
        );
    }
    ensure!(
        classify(journal, ticket)? == state,
        "selected terminal lifecycle changed"
    );
    Ok(())
}

/// Resolve original bytes only from the authenticated old representation.
/// Recovery never needs the source device or an already modified target.
fn read_before<J: Read + Seek>(
    journal: &mut J,
    record: &JournalRecord,
    within: u64,
    bytes: &mut [u8],
) -> Result<()> {
    ensure!(
        within
            .checked_add(bytes.len() as u64)
            .is_some_and(|end| end <= record.range.length),
        "old read escapes its authenticated range"
    );
    match record.before {
        OldBytes::Payload(offset) => at(
            journal,
            offset
                .checked_add(within)
                .context("old payload offset overflow")?,
            bytes,
        ),
        OldBytes::Zero => {
            bytes.fill(0);
            Ok(())
        }
        OldBytes::SourceFree(_) => {
            anyhow::bail!("source-free old bytes are hash-only and cannot resolve a copy")
        }
    }
}

/// Compare actual whole granules to their authenticated original digests and,
/// when supplied, their authenticated new bytes. This format deliberately
/// refuses torn/foreign 4 KiB granules instead of the legacy per-byte rule.
fn check_free_granules<J: Read + Seek>(
    journal: &mut J,
    record: &JournalRecord,
    within: u64,
    current: &[u8],
    after: Option<&[u8]>,
) -> Result<()> {
    let OldBytes::SourceFree(table_at) = record.before else {
        anyhow::bail!("source-free check requires a hash-only old record");
    };
    ensure!(
        within.is_multiple_of(GRANULE)
            && current.len().is_multiple_of(GRANULE as usize)
            && current.len() <= BUFFER
            && within
                .checked_add(current.len() as u64)
                .is_some_and(|end| end <= record.range.length)
            && after.is_none_or(|bytes| bytes.len() == current.len()),
        "source-free granule check escapes its authenticated range"
    );
    let mut table = [0u8; BUFFER / GRANULE as usize * FREE_DIGEST as usize];
    let count = current.len() / GRANULE as usize * FREE_DIGEST as usize;
    let offset = table_at
        .checked_add(within / GRANULE * FREE_DIGEST)
        .context("source-free digest offset overflow")?;
    at(journal, offset, &mut table[..count])?;
    for (index, (actual, old)) in current
        .chunks_exact(GRANULE as usize)
        .zip(table[..count].chunks_exact(FREE_DIGEST as usize))
        .enumerate()
    {
        let is_new = after.is_some_and(|bytes| {
            actual == &bytes[index * GRANULE as usize..(index + 1) * GRANULE as usize]
        });
        ensure!(
            is_new || xxhash_rust::xxh3::xxh3_128(actual).to_le_bytes().as_slice() == old,
            "source-free target granule is neither original nor new"
        );
    }
    Ok(())
}

fn read_after<J: Read + Seek>(
    journal: &mut J,
    records: &[JournalRecord],
    record: &JournalRecord,
    within: u64,
    bytes: &mut [u8],
) -> Result<()> {
    match record.after {
        NewBytes::Payload(offset) => at(journal, offset + within, bytes),
        NewBytes::Zero => {
            bytes.fill(0);
            Ok(())
        }
        NewBytes::OldReference(source) => {
            let mut cursor = source + within;
            let mut filled = 0usize;
            while filled < bytes.len() {
                let index = records.partition_point(|r| r.range.offset + r.range.length <= cursor);
                let original = records
                    .get(index)
                    .context("copy leaves immutable old records")?;
                ensure!(
                    original.range.offset <= cursor,
                    "copy crosses an unjournaled old gap"
                );
                let count = usize::try_from(
                    (original.range.offset + original.range.length - cursor)
                        .min((bytes.len() - filled) as u64),
                )?;
                read_before(
                    journal,
                    original,
                    cursor - original.range.offset,
                    &mut bytes[filled..filled + count],
                )?;
                cursor += count as u64;
                filled += count;
            }
            Ok(())
        }
    }
}

/// Whole old/new buffers use slice equality; interrupted mixed buffers retain
/// the exact per-byte rule. Equal lengths are required before zipped fallback.
fn bytes_are_old_or_new(current: &[u8], before: &[u8], after: &[u8]) -> bool {
    current.len() == before.len()
        && current.len() == after.len()
        && (current == before
            || current == after
            || current
                .iter()
                .zip(before)
                .zip(after)
                .all(|((&actual, &old), &new)| actual == old || actual == new))
}

/// Verify every selected actual byte is either its recorded old or new byte;
/// optionally require the complete framed selected target digest to match.
fn check_target<T: ReadSeek, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    records: &[JournalRecord],
    algorithm: Algorithm,
    expected: Option<&[u8; 32]>,
    fresh_old: bool,
) -> Result<[u8; 32]> {
    ensure!(
        target.byte_len()? == plan.image_length,
        "selected target length differs"
    );
    if let Some(expected) = expected {
        // Exact old/new states have an independently trusted framed digest.
        // Hash every actual selected target byte with the same framing. A
        // complete match proves the chosen side without rereading both journal
        // payloads merely to repeat their old-or-new membership comparison.
        // Mixed recovery states (None) keep every original byte check below.
        let mut current = vec![0; BUFFER];
        let mut digest = pin_hash(algorithm)?;
        for record in records {
            frame(&mut digest, &record.range)?;
            let mut done = 0u64;
            while done < record.range.length {
                let count = usize::try_from((record.range.length - done).min(BUFFER as u64))?;
                at(target, record.range.offset + done, &mut current[..count])?;
                if fresh_old && matches!(record.before, OldBytes::SourceFree(_)) {
                    check_free_granules(journal, record, done, &current[..count], None)?;
                }
                digest.update(&current[..count])?;
                done += count as u64;
            }
        }
        let digest = finish(digest)?;
        ensure!(&digest == expected, "selected target digest differs");
        return Ok(digest);
    }
    let mut current = vec![0; BUFFER];
    let mut before = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let mut digest = pin_hash(algorithm)?;
    for record in records {
        frame(&mut digest, &record.range)?;
        let mut done = 0u64;
        while done < record.range.length {
            let count = usize::try_from((record.range.length - done).min(BUFFER as u64))?;
            at(target, record.range.offset + done, &mut current[..count])?;
            read_after(journal, records, record, done, &mut after[..count])?;
            if matches!(record.before, OldBytes::SourceFree(_)) {
                check_free_granules(
                    journal,
                    record,
                    done,
                    &current[..count],
                    Some(&after[..count]),
                )?;
            } else {
                read_before(journal, record, done, &mut before[..count])?;
                ensure!(
                    bytes_are_old_or_new(&current[..count], &before[..count], &after[..count]),
                    "selected target contains a foreign byte"
                );
            }
            digest.update(&current[..count])?;
            done += count as u64;
        }
    }
    let digest = finish(digest)?;
    ensure!(
        expected.is_none_or(|expected| *expected == digest),
        "selected target digest differs"
    );
    Ok(digest)
}

/// Verify the rollback result without claiming restoration of formerly free
/// contents. Every free granule still undergoes its old/new membership check.
fn check_restored_target<T: ReadSeek, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    records: &[JournalRecord],
    ticket: &SelectedTicket,
) -> Result<[u8; 32]> {
    let Some(expected) = ticket.old_restored_selected_sha256 else {
        return check_target(
            target,
            journal,
            plan,
            records,
            ticket.digest_algorithm(),
            Some(&ticket.old_selected_sha256),
            false,
        );
    };
    ensure!(
        target.byte_len()? == plan.image_length,
        "selected target length differs"
    );
    let mut current = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let mut restored = pin_hash(ticket.digest_algorithm())?;
    for record in records {
        let free = matches!(record.before, OldBytes::SourceFree(_));
        if !free {
            frame(&mut restored, &record.range)?;
        }
        let mut done = 0u64;
        while done < record.range.length {
            let count = usize::try_from((record.range.length - done).min(BUFFER as u64))?;
            at(target, record.range.offset + done, &mut current[..count])?;
            if free {
                read_after(journal, records, record, done, &mut after[..count])?;
                check_free_granules(
                    journal,
                    record,
                    done,
                    &current[..count],
                    Some(&after[..count]),
                )?;
            } else {
                restored.update(&current[..count])?;
            }
            done += count as u64;
        }
    }
    let actual = finish(restored)?;
    ensure!(
        actual == expected,
        "restore-required selected target digest differs"
    );
    Ok(actual)
}

/// One fixed working set for the entire replay. Every compared/written byte
/// is filled by the current IO before use; no previous span contents are used.
struct ReplayBuffers {
    current: Vec<u8>,
    before: Vec<u8>,
    after: Vec<u8>,
}

impl ReplayBuffers {
    fn new() -> Self {
        Self {
            current: vec![0; BUFFER],
            before: vec![0; BUFFER],
            after: vec![0; BUFFER],
        }
    }
}

fn write_span<T: DurableIo, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    records: &[JournalRecord],
    record: &JournalRecord,
    start: u64,
    length: u64,
    forward: bool,
    buffers: &mut ReplayBuffers,
) -> Result<()> {
    let ReplayBuffers {
        current,
        before,
        after,
    } = buffers;
    let mut done = 0u64;
    while done < length {
        let count = usize::try_from((length - done).min(BUFFER as u64))?;
        let within = start + done;
        let offset = record.range.offset + within;
        at(target, offset, &mut current[..count])?;
        read_after(journal, records, record, within, &mut after[..count])?;
        if matches!(record.before, OldBytes::SourceFree(_)) {
            check_free_granules(
                journal,
                record,
                within,
                &current[..count],
                Some(&after[..count]),
            )?;
            if !forward {
                // Original source-free bytes are deliberately unavailable.
                // Check membership but never overwrite their current state.
                done += count as u64;
                continue;
            }
        } else {
            read_before(journal, record, within, &mut before[..count])?;
            ensure!(
                bytes_are_old_or_new(&current[..count], &before[..count], &after[..count]),
                "selected target changed before write"
            );
        }
        let desired = if forward {
            &after[..count]
        } else {
            &before[..count]
        };
        if &current[..count] == desired {
            done += count as u64;
            continue;
        }
        // No flush or readback per chunk: replay accepts old or new bytes, the
        // caller flushes every span before the first granule and again after
        // it, and check_target then rereads every selected byte.
        target.seek(SeekFrom::Start(offset))?;
        ensure!(
            target.write(desired)? == count,
            "short selected target write"
        );
        done += count as u64;
    }
    Ok(())
}

fn execute<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    forward: bool,
    fresh: bool,
) -> Result<SelectedResult> {
    let records = load(journal, plan, ticket)?;
    execute_loaded(
        target, journal, plan, ticket, &records, forward, fresh, true,
    )
}

/// Every caller retains all target membership/digest checks. Legacy execution
/// rehashes the immutable body afterward; only a live exclusive journal owner
/// may retain its completed authentication through its own marker writes.
#[allow(clippy::too_many_arguments)]
fn execute_loaded<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    records: &[JournalRecord],
    forward: bool,
    fresh: bool,
    recheck_immutable: bool,
) -> Result<SelectedResult> {
    let (apply_intent, rollback_intent) = read_markers(journal, ticket)?;
    ensure!(
        !fresh || (!apply_intent && !rollback_intent),
        "fresh selected apply requires clear intent"
    );
    ensure!(
        fresh || !forward || apply_intent,
        "selected resume requires a durable apply intent"
    );
    ensure!(
        forward || apply_intent || rollback_intent,
        "selected rollback requires an existing durable operation intent"
    );
    ensure!(
        !forward || !rollback_intent,
        "selected rollback intent closes forward replay"
    );
    target.sync_all()?;
    check_target(
        target,
        journal,
        plan,
        records,
        ticket.digest_algorithm(),
        fresh.then_some(&ticket.old_selected_sha256),
        fresh,
    )?;
    if !forward && ticket.marker_profile.is_some() {
        // A redundant rollback already requires an authenticated AP. Restore
        // its missing peer before RB or target writes without creating an
        // intent for a PreparedClear journal or reopening forward replay.
        ensure!(
            apply_intent && read_marker_pair(journal, ticket, MarkerKind::Apply)?,
            "redundant rollback cannot repair an absent apply intent"
        );
        write_lifecycle_marker(journal, ticket, MarkerKind::Apply)?;
        ensure!(
            read_markers(journal, ticket)? == (apply_intent, rollback_intent),
            "selected lifecycle changed during apply peer repair"
        );
    }
    write_lifecycle_marker(
        journal,
        ticket,
        if forward {
            MarkerKind::Apply
        } else {
            MarkerKind::Rollback
        },
    )?;
    let mut replay_buffers = ReplayBuffers::new();
    for record in records {
        let skip = if record.range.offset == 0 { GRANULE } else { 0 };
        write_span(
            target,
            journal,
            records,
            record,
            skip,
            record.range.length - skip,
            forward,
            &mut replay_buffers,
        )?;
    }
    target.sync_all()?;
    if let Some(first) = records.first().filter(|r| r.range.offset == 0) {
        write_span(
            target,
            journal,
            records,
            first,
            0,
            GRANULE,
            forward,
            &mut replay_buffers,
        )?;
    }
    // The subsequent complete target check has its own fixed buffers. Release
    // replay scratch first so reuse does not double that phase's working set.
    drop(replay_buffers);
    target.sync_all()?;
    let expected = if forward {
        &ticket.new_selected_sha256
    } else {
        &ticket.old_selected_sha256
    };
    let selected_sha256 = if forward {
        check_target(
            target,
            journal,
            plan,
            records,
            ticket.digest_algorithm(),
            Some(expected),
            false,
        )?
    } else {
        check_restored_target(target, journal, plan, records, ticket)?
    };
    if recheck_immutable {
        ensure!(
            hash_range(
                journal,
                ticket.digest_algorithm(),
                ticket.body_offset(),
                ticket.journal_length - ticket.body_offset()
            )? == ticket.immutable_sha256,
            "selected journal changed during target writes"
        );
    }
    if !forward {
        write_lifecycle_marker(journal, ticket, MarkerKind::Aborted)?;
    }
    Ok(SelectedResult {
        selected_sha256,
        selected_bytes: ticket.selected_bytes,
        range_count: ticket.range_count,
        replay_closed: !forward,
        whole_image_verified: false,
        conversion_qualified: false,
        old_restoration_bytes: if !forward && plan.source_free_encoded() {
            Some(plan.old_restored_bytes()?)
        } else {
            None
        },
    })
}

#[cfg(test)]
pub fn apply<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    execute(target, journal, plan, ticket, true, true)
}

pub fn resume<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    execute(target, journal, plan, ticket, true, false)
}
pub fn rollback<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    execute(target, journal, plan, ticket, false, false)
}

/// Durable journal state, read after the complete immutable journal checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedLifecycle {
    PreparedClear,
    ApplyIntent,
    RollbackIntent,
    Handoff,
    Aborted,
}

/// One-shot ownership of a journal authenticated in this process. Exclusivity
/// concerns the JOURNAL only: the target retains every mixed-byte, per-span and
/// exact-digest check and requires no new global target-exclusion assumption.
/// The caller must keep the journal free of writer/delete aliases; native
/// recovery opens its exact file with share mode zero. No serialized state,
/// mutable stream accessor or clone can recreate this completed load.
pub(crate) struct ExclusiveRecoveryJournal<'a, J: DurableIo> {
    journal: &'a mut J,
    plan: &'a SelectedPlan,
    ticket: &'a SelectedTicket,
    records: Vec<JournalRecord>,
    state: SelectedLifecycle,
}

pub(crate) fn authenticate_recovery_exclusive<'a, J: DurableIo>(
    journal: &'a mut J,
    plan: &'a SelectedPlan,
    ticket: &'a SelectedTicket,
) -> Result<ExclusiveRecoveryJournal<'a, J>> {
    let records = load(journal, plan, ticket)?;
    let state = classify(journal, ticket)?;
    Ok(ExclusiveRecoveryJournal {
        journal,
        plan,
        ticket,
        records,
        state,
    })
}

impl<J: DurableIo> ExclusiveRecoveryJournal<'_, J> {
    /// The state comes from actual authenticated journal bytes, not a report.
    pub(crate) fn lifecycle(&self) -> SelectedLifecycle {
        self.state
    }

    pub(crate) fn resume_and_handoff<T: DurableIo, F: FnOnce(&SelectedResult) -> Result<()>>(
        self,
        target: &mut T,
        after_resume: F,
    ) -> Result<(SelectedResult, SelectedResult)> {
        ensure!(
            self.state == SelectedLifecycle::ApplyIntent,
            "exclusive journal resume requires an observed durable apply intent"
        );
        let resumed = execute_loaded(
            target,
            self.journal,
            self.plan,
            self.ticket,
            &self.records,
            true,
            false,
            false,
        )?;
        after_resume(&resumed)?;
        // Keep handoff's actual marker rereads, target flush and complete
        // exact-new target check. Only repeated journal-body authentication
        // is redundant under the continuously held journal borrow.
        let handed_off = handoff_loaded(
            target,
            self.journal,
            self.plan,
            self.ticket,
            &self.records,
            false,
        )?;
        Ok((resumed, handed_off))
    }

    pub(crate) fn rollback<T: DurableIo>(self, target: &mut T) -> Result<SelectedResult> {
        ensure!(
            matches!(
                self.state,
                SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
            ),
            "exclusive journal rollback requires an observed durable operation intent"
        );
        execute_loaded(
            target,
            self.journal,
            self.plan,
            self.ticket,
            &self.records,
            false,
            false,
            false,
        )
    }

    pub(crate) fn abandon<T: DurableIo>(self, target: &mut T) -> Result<SelectedResult> {
        ensure!(
            self.state == SelectedLifecycle::PreparedClear,
            "exclusive journal abandon requires observed clear intent"
        );
        abandon_loaded(target, self.journal, self.plan, self.ticket, &self.records)
    }

    /// Verify the committed target before repairing a redundant terminal peer,
    /// then verify the complete committed target again. Target access remains
    /// read-only: a closed lifecycle never re-enters raw target replay. Legacy
    /// formats retain the original verification-only behavior.
    pub(crate) fn verify_closed_and_repair<T: ReadSeek>(
        self,
        target: &mut T,
    ) -> Result<(SelectedLifecycle, SelectedResult)> {
        ensure!(
            matches!(
                self.state,
                SelectedLifecycle::Handoff | SelectedLifecycle::Aborted
            ),
            "exclusive journal verification requires an observed closed lifecycle"
        );
        let result =
            verify_closed_loaded(target, self.journal, self.plan, self.ticket, &self.records)?;
        ensure!(
            result.0 == self.state,
            "exclusive journal closed lifecycle changed"
        );
        if self.ticket.marker_profile.is_some() {
            ensure!(
                classify(self.journal, self.ticket)? == self.state,
                "exclusive journal closed lifecycle changed after target verification"
            );
            write_lifecycle_marker(
                self.journal,
                self.ticket,
                match self.state {
                    SelectedLifecycle::Handoff => MarkerKind::Handoff,
                    SelectedLifecycle::Aborted => MarkerKind::Aborted,
                    _ => unreachable!("closed lifecycle checked above"),
                },
            )?;
            let rechecked =
                verify_closed_loaded(target, self.journal, self.plan, self.ticket, &self.records)?;
            ensure!(
                rechecked.0 == self.state
                    && rechecked.1.selected_sha256 == result.1.selected_sha256
                    && classify(self.journal, self.ticket)? == self.state,
                "committed target or closed lifecycle changed during terminal peer repair"
            );
            return Ok(rechecked);
        }
        Ok(result)
    }
}

/// Classify the markers of a fully verified journal. Legacy torn markers refuse;
/// the redundant profile requires an authenticated intact peer. This never writes.
pub fn lifecycle<J: ReadSeek>(
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedLifecycle> {
    load(journal, plan, ticket)?;
    classify(journal, ticket)
}

/// Internal marker classification only. Callers must independently bind and
/// authenticate the actual held journal and ticket; this never grants replay.
pub(crate) fn classify<J: Read + Seek>(
    journal: &mut J,
    ticket: &SelectedTicket,
) -> Result<SelectedLifecycle> {
    if ticket.marker_profile.is_some() {
        return classify_redundant(journal, ticket);
    }
    let mut completed = [0u8; GRANULE as usize];
    let mut intent = [0u8; GRANULE as usize];
    at(journal, 0, &mut completed)?;
    at(journal, GRANULE, &mut intent)?;
    let zero = [0u8; GRANULE as usize];
    let apply = marker(b"N2RSAP01", ticket, &ticket.new_selected_sha256);
    let rollback = marker(b"N2RSRB01", ticket, &ticket.old_selected_sha256);
    if completed == marker(b"N2RSHN01", ticket, &ticket.new_selected_sha256) {
        ensure!(
            intent == apply,
            "selected handoff marker conflicts with intent marker"
        );
        return Ok(SelectedLifecycle::Handoff);
    }
    if completed == marker(b"N2RSAB01", ticket, &ticket.old_selected_sha256) {
        ensure!(
            intent == zero || intent == rollback,
            "selected abort marker conflicts with intent marker"
        );
        return Ok(SelectedLifecycle::Aborted);
    }
    ensure!(
        completed == zero,
        "selected completion marker is foreign or torn"
    );
    if intent == zero {
        Ok(SelectedLifecycle::PreparedClear)
    } else if intent == apply {
        Ok(SelectedLifecycle::ApplyIntent)
    } else if intent == rollback {
        Ok(SelectedLifecycle::RollbackIntent)
    } else {
        anyhow::bail!("selected intent marker is foreign or torn")
    }
}

/// The marker writes of a single-granule journal that can be found
/// interrupted (see `interrupted_marker`). Each is settled by putting its
/// granule back to what it held before the write.
///
/// The intent granule goes from clear to the apply intent, and from the apply
/// intent to the rollback intent, both beside a clear completion granule. The
/// completion granule goes from clear to the handoff marker beside the apply
/// intent, or to the abort marker beside the rollback intent, or beside a
/// clear intent when a run that never wrote one is abandoned.
fn interrupted_marker_writes(ticket: &SelectedTicket) -> Vec<MarkerWrite> {
    let exact = |kind: MarkerKind| marker(kind.magic(false), ticket, kind.digest(ticket));
    let clear = [0u8; GRANULE as usize];
    let apply = exact(MarkerKind::Apply);
    let rollback = exact(MarkerKind::Rollback);
    let aborted = exact(MarkerKind::Aborted);
    let write = |marker, name, offset, before, after, beside_at, beside| MarkerWrite {
        marker,
        name,
        offset,
        before,
        after,
        settled: before,
        settled_as: "not written",
        beside: (beside_at, vec![beside]),
    };
    vec![
        write(
            Marker::ApplyIntent,
            "apply intent",
            GRANULE,
            clear,
            apply,
            0,
            clear,
        ),
        write(
            Marker::RollbackIntent,
            "rollback intent",
            GRANULE,
            apply,
            rollback,
            0,
            clear,
        ),
        write(
            Marker::Handoff,
            "handoff",
            0,
            clear,
            exact(MarkerKind::Handoff),
            GRANULE,
            apply,
        ),
        write(
            Marker::AbortAfterRollback,
            "abort",
            0,
            clear,
            aborted,
            GRANULE,
            rollback,
        ),
        write(
            Marker::AbortAfterAbandon,
            "abort",
            0,
            clear,
            aborted,
            GRANULE,
            clear,
        ),
    ]
}

/// The marker whose write this journal shows was interrupted, if any. Reads
/// two granules and writes nothing. The redundant format keeps two copies of
/// each marker and has its own rules; nothing is looked for there.
pub(crate) fn find_interrupted_marker<J: Read + Seek>(
    journal: &mut J,
    ticket: &SelectedTicket,
) -> Result<Option<crate::interrupted_marker::Found>> {
    if ticket.marker_profile.is_some() {
        return Ok(None);
    }
    crate::interrupted_marker::found(journal, &interrupted_marker_writes(ticket))
}

/// Settles the interrupted marker write `find_interrupted_marker` reports,
/// before a recovery reads the lifecycle. The caller holds the journal
/// exclusively and has seen the source in the state that marker is written
/// in. The journal's whole body is held to its ticket first: a journal that
/// is not this conversion's is not written to. Returns `None`, having written
/// nothing, when the markers are exact (or are not this journal's: those are
/// refused by `classify`, as before).
pub(crate) fn settle_interrupted_marker<J: DurableIo>(
    journal: &mut J,
    ticket: &SelectedTicket,
) -> Result<Option<SettledMarker>> {
    if ticket.marker_profile.is_some() {
        return Ok(None);
    }
    let writes = interrupted_marker_writes(ticket);
    if crate::interrupted_marker::find(journal, &writes)?.is_none() {
        return Ok(None);
    }
    ensure!(
        journal.byte_len()? == ticket.journal_length
            && hash_range(
                journal,
                ticket.digest_algorithm(),
                ticket.body_offset(),
                ticket.journal_length - ticket.body_offset()
            )? == ticket.immutable_sha256,
        "the journal's length or body differs from its ticket; the partly written marker in \
         it is left as it is"
    );
    crate::interrupted_marker::settle(journal, &writes)
}

#[cfg(test)]
mod interrupted_marker_tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Clone)]
    struct Memory(Cursor<Vec<u8>>);
    impl Read for Memory {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(bytes)
        }
    }
    impl Write for Memory {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Seek for Memory {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(from)
        }
    }
    impl ReadSeek for Memory {
        fn byte_len(&mut self) -> std::io::Result<u64> {
            Ok(self.0.get_ref().len() as u64)
        }
    }
    impl DurableIo for Memory {
        fn sync_all(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn memory(bytes: &[u8]) -> Memory {
        Memory(Cursor::new(bytes.to_vec()))
    }

    const SECTOR: usize = 512;
    const INTENT: usize = GRANULE as usize;
    const COMPLETION: usize = 0;

    struct Run {
        old: Vec<u8>,
        new: Vec<u8>,
        /// Partly applied: the first range new, the second still old.
        mixed: Vec<u8>,
        plan: SelectedPlan,
        ticket: SelectedTicket,
        /// The journal as prepared, after the apply, after the handoff, and
        /// after a rollback of the apply.
        prepared: Vec<u8>,
        applied: Vec<u8>,
        handed_off: Vec<u8>,
        rolled_back: Vec<u8>,
    }

    fn run() -> Run {
        let old: Vec<u8> = (0..16 * GRANULE as usize)
            .map(|index| (index % 251) as u8)
            .collect();
        let mut new = old.clone();
        new[..2 * GRANULE as usize].fill(0x72);
        new[4 * GRANULE as usize..5 * GRANULE as usize].fill(0x52);
        let mut mixed = old.clone();
        mixed[..2 * GRANULE as usize].copy_from_slice(&new[..2 * GRANULE as usize]);
        let plan = SelectedPlan {
            image_length: old.len() as u64,
            ranges: vec![
                SelectedRange {
                    offset: 0,
                    length: 2 * GRANULE,
                },
                SelectedRange {
                    offset: 4 * GRANULE,
                    length: GRANULE,
                },
            ],
            max_selected_bytes: old.len() as u64,
            max_journal_bytes: 1 << 24,
            new_zero_ranges: vec![],
            new_copy_ranges: vec![],
            old_zero_ranges: vec![],
            source_free_ranges: vec![],
        };
        let mut journal = memory(&[]);
        let ticket = prepare(&mut memory(&old), &mut memory(&new), &mut journal, &plan).unwrap();
        let prepared = journal.0.get_ref().clone();
        let mut target = memory(&old);
        apply(&mut target, &mut journal, &plan, &ticket).unwrap();
        assert_eq!(target.0.get_ref(), &new);
        let applied = journal.0.get_ref().clone();
        handoff(&mut target, &mut journal, &plan, &ticket).unwrap();
        let handed_off = journal.0.get_ref().clone();
        let mut undone = memory(&applied);
        rollback(&mut target, &mut undone, &plan, &ticket).unwrap();
        assert_eq!(target.0.get_ref(), &old);
        let rolled_back = undone.0.get_ref().clone();
        Run {
            old,
            new,
            mixed,
            plan,
            ticket,
            prepared,
            applied,
            handed_off,
            rolled_back,
        }
    }

    /// `journal` with the marker granule at `at` as a write of `after`'s
    /// granule leaves it when it stops after the given sectors.
    fn stopped(journal: &[u8], after: &[u8], at: usize, sectors: &[usize]) -> Vec<u8> {
        let mut bytes = journal.to_vec();
        for &sector in sectors {
            let range = at + sector * SECTOR..at + (sector + 1) * SECTOR;
            bytes[range.clone()].copy_from_slice(&after[range]);
        }
        bytes
    }

    fn state(run: &Run, journal: &mut Memory) -> Result<SelectedLifecycle> {
        lifecycle(journal, &run.plan, &run.ticket)
    }

    /// Finds and settles; the journal must not be readable before, and must
    /// hold nothing partly written after. Returns what was found.
    fn settled(run: &Run, journal: &mut Memory) -> Marker {
        assert!(format!("{:#}", state(run, journal).unwrap_err()).contains("foreign or torn"));
        let found = find_interrupted_marker(journal, &run.ticket)
            .unwrap()
            .unwrap();
        let settled = settle_interrupted_marker(journal, &run.ticket)
            .unwrap()
            .unwrap();
        assert_eq!(settled.marker, found.name);
        assert_eq!(settled.settled_as, "not written");
        assert_eq!(find_interrupted_marker(journal, &run.ticket).unwrap(), None);
        found.marker
    }

    #[test]
    fn an_interrupted_handoff_is_not_written_and_the_apply_is_proved_again() {
        let run = run();
        // First or last sector of the marker on the disk: both stop every
        // direction until they are settled.
        for sectors in [&[0][..], &[7][..]] {
            let mut journal = memory(&stopped(&run.applied, &run.handed_off, COMPLETION, sectors));
            assert_eq!(settled(&run, &mut journal), Marker::Handoff);
            assert_eq!(journal.0.get_ref(), &run.applied);
            assert_eq!(
                state(&run, &mut journal).unwrap(),
                SelectedLifecycle::ApplyIntent
            );
            // The ordinary resume and handoff run from there, with every check.
            let mut target = memory(&run.new);
            resume(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
            handoff(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
            assert_eq!(journal.0.get_ref(), &run.handed_off);
            assert_eq!(target.0.get_ref(), &run.new);
        }
        // The same journal can instead be rolled back: the handoff was never
        // recorded.
        let mut journal = memory(&stopped(&run.applied, &run.handed_off, COMPLETION, &[0]));
        settled(&run, &mut journal);
        let mut target = memory(&run.new);
        rollback(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
        assert_eq!(target.0.get_ref(), &run.old);
        assert_eq!(
            state(&run, &mut journal).unwrap(),
            SelectedLifecycle::Aborted
        );
        // A source that holds a byte of neither image is refused by the
        // resume, as it always was: settling proves nothing about the source.
        let mut journal = memory(&stopped(&run.applied, &run.handed_off, COMPLETION, &[0]));
        settled(&run, &mut journal);
        let mut foreign = run.new.clone();
        foreign[5] ^= 0x40;
        assert!(resume(&mut memory(&foreign), &mut journal, &run.plan, &run.ticket).is_err());
        assert_eq!(journal.0.get_ref(), &run.applied);
    }

    #[test]
    fn an_interrupted_apply_intent_is_not_written_and_the_source_must_be_the_old_one() {
        let run = run();
        for sectors in [&[0][..], &[7][..]] {
            let mut journal = memory(&stopped(&run.prepared, &run.applied, INTENT, sectors));
            assert_eq!(settled(&run, &mut journal), Marker::ApplyIntent);
            assert_eq!(journal.0.get_ref(), &run.prepared);
            assert_eq!(
                state(&run, &mut journal).unwrap(),
                SelectedLifecycle::PreparedClear
            );
            // A source that was written to after all is not abandoned: the
            // whole old digest is required, and the journal stays clear.
            assert!(
                abandon(
                    &mut memory(&run.mixed),
                    &mut journal,
                    &run.plan,
                    &run.ticket
                )
                .is_err()
            );
            assert!(resume(&mut memory(&run.old), &mut journal, &run.plan, &run.ticket).is_err());
            assert_eq!(journal.0.get_ref(), &run.prepared);
            // Abandoning proves the whole source is still the old one.
            let mut target = memory(&run.old);
            abandon(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
            assert_eq!(target.0.get_ref(), &run.old);
            assert_eq!(
                state(&run, &mut journal).unwrap(),
                SelectedLifecycle::Aborted
            );
        }
    }

    #[test]
    fn an_interrupted_rollback_intent_is_not_written_and_both_directions_stay_open() {
        let run = run();
        for sectors in [&[0][..], &[7][..]] {
            let torn = stopped(&run.applied, &run.rolled_back, INTENT, sectors);
            // Rolled back from a partly applied source.
            let mut journal = memory(&torn);
            assert_eq!(settled(&run, &mut journal), Marker::RollbackIntent);
            assert_eq!(journal.0.get_ref(), &run.applied);
            assert_eq!(
                state(&run, &mut journal).unwrap(),
                SelectedLifecycle::ApplyIntent
            );
            let mut target = memory(&run.mixed);
            rollback(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
            assert_eq!(target.0.get_ref(), &run.old);
            assert_eq!(journal.0.get_ref(), &run.rolled_back);
            // Or resumed: the apply intent is the durable one.
            let mut journal = memory(&torn);
            settled(&run, &mut journal);
            let mut target = memory(&run.mixed);
            resume(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
            handoff(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
            assert_eq!(target.0.get_ref(), &run.new);
            assert_eq!(journal.0.get_ref(), &run.handed_off);
        }
    }

    #[test]
    fn an_interrupted_abort_is_not_written_and_the_rollback_is_proved_again() {
        let run = run();
        // After a rollback: the abort marker beside the rollback intent.
        let mut before_abort = run.rolled_back.clone();
        before_abort[..GRANULE as usize].fill(0);
        let mut journal = memory(&stopped(&before_abort, &run.rolled_back, COMPLETION, &[7]));
        assert_eq!(settled(&run, &mut journal), Marker::AbortAfterRollback);
        assert_eq!(journal.0.get_ref(), &before_abort);
        assert_eq!(
            state(&run, &mut journal).unwrap(),
            SelectedLifecycle::RollbackIntent
        );
        // A resume is closed; the rollback runs again and requires old bytes.
        assert!(resume(&mut memory(&run.new), &mut journal, &run.plan, &run.ticket).is_err());
        let mut target = memory(&run.old);
        rollback(&mut target, &mut journal, &run.plan, &run.ticket).unwrap();
        assert_eq!(journal.0.get_ref(), &run.rolled_back);
        // After an abandoned run: the abort marker beside a clear intent.
        let mut abandoned = memory(&run.prepared);
        abandon(
            &mut memory(&run.old),
            &mut abandoned,
            &run.plan,
            &run.ticket,
        )
        .unwrap();
        let abandoned = abandoned.0.get_ref().clone();
        let mut journal = memory(&stopped(&run.prepared, &abandoned, COMPLETION, &[0]));
        assert_eq!(settled(&run, &mut journal), Marker::AbortAfterAbandon);
        assert_eq!(journal.0.get_ref(), &run.prepared);
    }

    #[test]
    fn markers_that_are_not_an_interrupted_write_are_refused_as_before() {
        let run = run();
        let untouched = |bytes: Vec<u8>| {
            let mut journal = memory(&bytes);
            assert_eq!(
                find_interrupted_marker(&mut journal, &run.ticket).unwrap(),
                None
            );
            assert_eq!(
                settle_interrupted_marker(&mut journal, &run.ticket).unwrap(),
                None
            );
            assert_eq!(journal.0.get_ref(), &bytes);
            journal
        };
        // Every exact lifecycle: nothing to settle.
        for exact in [
            &run.prepared,
            &run.applied,
            &run.handed_off,
            &run.rolled_back,
        ] {
            assert!(state(&run, &mut untouched(exact.clone())).is_ok());
        }
        // One changed byte in a marker.
        for (journal, at) in [
            (&run.handed_off, COMPLETION + 3),
            (&run.handed_off, COMPLETION + GRANULE as usize - 1),
            (&run.applied, INTENT + 9),
        ] {
            let mut bytes = journal.clone();
            bytes[at] ^= 1;
            assert!(state(&run, &mut untouched(bytes)).is_err());
        }
        // A completion stopped part-way beside an intent it is never written
        // beside: a handoff beside a clear or a rollback intent, an abort
        // beside the apply intent.
        let mut before_abort = run.rolled_back.clone();
        before_abort[..GRANULE as usize].fill(0);
        for (journal, completion) in [
            (&run.prepared, &run.handed_off),
            (&before_abort, &run.handed_off),
            (&run.applied, &run.rolled_back),
        ] {
            let bytes = stopped(journal, completion, COMPLETION, &[0]);
            assert!(state(&run, &mut untouched(bytes)).is_err());
        }
        // An intent stopped part-way beside a completion that is not clear.
        untouched(stopped(&run.handed_off, &run.rolled_back, INTENT, &[0]));
        // Both granules partly written.
        let both = stopped(
            &stopped(&run.prepared, &run.applied, INTENT, &[0]),
            &run.handed_off,
            COMPLETION,
            &[0],
        );
        assert!(state(&run, &mut untouched(both)).is_err());
        // Another journal's marker: its digests differ.
        let mut other = run.ticket.clone();
        other.immutable_sha256[0] ^= 1;
        let foreign = marker(b"N2RSHN01", &other, &other.new_selected_sha256);
        let mut bytes = run.applied.clone();
        bytes[..SECTOR].copy_from_slice(&foreign[..SECTOR]);
        assert!(state(&run, &mut untouched(bytes)).is_err());
        // The redundant format keeps two copies of each marker and its own
        // rules: nothing is looked for, and nothing is written.
        let mut redundant = run.ticket.clone();
        redundant.marker_profile = Some(SelectedMarkerProfile::RedundantSourceFreeV1);
        let mut journal = memory(&stopped(&run.applied, &run.handed_off, COMPLETION, &[0]));
        assert_eq!(
            find_interrupted_marker(&mut journal, &redundant).unwrap(),
            None
        );
        assert_eq!(
            settle_interrupted_marker(&mut journal, &redundant).unwrap(),
            None
        );
    }

    #[test]
    fn a_journal_whose_body_is_not_its_tickets_is_not_written_to() {
        let run = run();
        let mut bytes = stopped(&run.applied, &run.handed_off, COMPLETION, &[0]);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let mut journal = memory(&bytes);
        // The marker itself is this journal's and is found; the body is not.
        assert_eq!(
            find_interrupted_marker(&mut journal, &run.ticket)
                .unwrap()
                .map(|found| found.marker),
            Some(Marker::Handoff)
        );
        let refusal = format!(
            "{:#}",
            settle_interrupted_marker(&mut journal, &run.ticket).unwrap_err()
        );
        assert!(refusal.contains("left as it is"), "{refusal}");
        assert_eq!(journal.0.get_ref(), &bytes);
        // A journal of another length is refused the same way.
        let mut longer = stopped(&run.applied, &run.handed_off, COMPLETION, &[0]);
        longer.push(0);
        let mut journal = memory(&longer);
        assert!(settle_interrupted_marker(&mut journal, &run.ticket).is_err());
        assert_eq!(journal.0.get_ref(), &longer);
    }
}

/// Close replay for an apply that never wrote its intent: no target write can
/// have happened, and the complete selected old digest must still hold.
#[cfg(test)]
pub fn abandon<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    let records = load(journal, plan, ticket)?;
    abandon_loaded(target, journal, plan, ticket, &records)
}

fn abandon_loaded<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    records: &[JournalRecord],
) -> Result<SelectedResult> {
    let (apply_intent, rollback_intent) = read_markers(journal, ticket)?;
    ensure!(
        !apply_intent && !rollback_intent,
        "selected abandon requires a journal with no operation intent"
    );
    target.sync_all()?;
    let selected_sha256 = check_target(
        target,
        journal,
        plan,
        records,
        ticket.digest_algorithm(),
        Some(&ticket.old_selected_sha256),
        true,
    )?;
    write_lifecycle_marker(journal, ticket, MarkerKind::Aborted)?;
    Ok(SelectedResult {
        selected_sha256: ticket
            .old_restored_selected_sha256
            .unwrap_or(selected_sha256),
        selected_bytes: ticket.selected_bytes,
        range_count: ticket.range_count,
        replay_closed: true,
        whole_image_verified: false,
        conversion_qualified: false,
        old_restoration_bytes: plan
            .source_free_encoded()
            .then(|| plan.old_restored_bytes())
            .transpose()?,
    })
}

/// Recheck a journal already closed by HND or ABT: the complete selected digest
/// must be the committed side. This writes nothing.
pub fn verify_closed<T: ReadSeek, J: ReadSeek>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<(SelectedLifecycle, SelectedResult)> {
    let records = load(journal, plan, ticket)?;
    verify_closed_loaded(target, journal, plan, ticket, &records)
}

fn verify_closed_loaded<T: ReadSeek, J: ReadSeek>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    records: &[JournalRecord],
) -> Result<(SelectedLifecycle, SelectedResult)> {
    let state = classify(journal, ticket)?;
    let expected = match state {
        SelectedLifecycle::Handoff => &ticket.new_selected_sha256,
        SelectedLifecycle::Aborted => &ticket.old_selected_sha256,
        _ => anyhow::bail!("selected journal is not closed by HND or ABT"),
    };
    let selected_sha256 = if state == SelectedLifecycle::Aborted {
        check_restored_target(target, journal, plan, records, ticket)?
    } else {
        check_target(
            target,
            journal,
            plan,
            records,
            ticket.digest_algorithm(),
            Some(expected),
            false,
        )?
    };
    Ok((
        state,
        SelectedResult {
            selected_sha256,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: if state == SelectedLifecycle::Aborted
                && plan.source_free_encoded()
            {
                Some(plan.old_restored_bytes()?)
            } else {
                None
            },
        },
    ))
}

/// Permanently close raw replay before the caller permits a native mount.
pub fn handoff<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    let records = load(journal, plan, ticket)?;
    handoff_loaded(target, journal, plan, ticket, &records, true)
}

fn handoff_loaded<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    records: &[JournalRecord],
    recheck_immutable: bool,
) -> Result<SelectedResult> {
    let (apply_intent, rollback_intent) = read_markers(journal, ticket)?;
    ensure!(
        apply_intent && !rollback_intent,
        "selected handoff requires completed forward intent"
    );
    target.sync_all()?;
    let selected_sha256 = check_target(
        target,
        journal,
        plan,
        records,
        ticket.digest_algorithm(),
        Some(&ticket.new_selected_sha256),
        false,
    )?;
    if recheck_immutable {
        ensure!(
            hash_range(
                journal,
                ticket.digest_algorithm(),
                ticket.body_offset(),
                ticket.journal_length - ticket.body_offset()
            )? == ticket.immutable_sha256,
            "selected journal changed during handoff verification"
        );
    }
    write_lifecycle_marker(journal, ticket, MarkerKind::Handoff)?;
    Ok(SelectedResult {
        selected_sha256,
        selected_bytes: ticket.selected_bytes,
        range_count: ticket.range_count,
        replay_closed: true,
        whole_image_verified: false,
        conversion_qualified: false,
        old_restoration_bytes: None,
    })
}

#[cfg(test)]
mod record_hash_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn image(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8 | 1).collect()
    }

    /// The rows of a journal: copied, checked to be zero, short and several
    /// buffers long.
    fn rows() -> Vec<(SelectedRange, bool)> {
        let granule = GRANULE;
        let buffer = BUFFER as u64;
        vec![
            (
                SelectedRange {
                    offset: 0,
                    length: granule,
                },
                false,
            ),
            (
                SelectedRange {
                    offset: granule,
                    length: 3 * granule,
                },
                true,
            ),
            (
                SelectedRange {
                    offset: 8 * granule,
                    length: 2 * buffer + granule,
                },
                false,
            ),
            (
                SelectedRange {
                    offset: 8 * granule + 3 * buffer,
                    length: buffer + granule,
                },
                true,
            ),
            (
                SelectedRange {
                    offset: 8 * granule + 5 * buffer,
                    length: 3 * granule,
                },
                true,
            ),
            (
                SelectedRange {
                    offset: 8 * granule + 6 * buffer,
                    length: granule,
                },
                false,
            ),
        ]
    }

    /// Runs the rows with `records`, settling every row's digest only after
    /// `late` more rows were read. Returns the digests, the journal's bytes
    /// and the aggregate's digest.
    fn run(mut records: RecordHashes, late: usize) -> (Vec<[u8; 32]>, Vec<u8>, [u8; 32]) {
        let rows = rows();
        let end = rows
            .iter()
            .map(|(range, _)| range.offset + range.length)
            .max()
            .unwrap();
        let mut source = image(end as usize);
        for (range, zero) in &rows {
            if *zero {
                source[range.offset as usize..(range.offset + range.length) as usize].fill(0);
            }
        }
        let mut input = Cursor::new(source);
        let mut journal = Vec::new();
        let mut selected = pin_hash(Algorithm::Sha256).unwrap();
        let mut buffer = vec![0u8; BUFFER];
        let mut zeros = ZeroDigests::new();
        let mut owed = std::collections::VecDeque::new();
        let mut digests = Vec::new();
        for (range, zero) in &rows {
            let digest = if *zero {
                verify_zero_selected_with(
                    &mut input,
                    range,
                    &mut selected,
                    &mut buffer,
                    &mut zeros,
                    "row is not zero",
                    None,
                    &mut records,
                )
                .unwrap()
            } else {
                copy_selected_with(
                    &mut input,
                    range,
                    &mut journal,
                    &mut selected,
                    &mut buffer,
                    None,
                    &mut records,
                )
                .unwrap()
            };
            owed.push_back(digest);
            while owed.len() > late {
                let digest = owed.pop_front().unwrap();
                digests.push(records.settle(digest, &mut zeros).unwrap());
            }
        }
        for digest in owed {
            digests.push(records.settle(digest, &mut zeros).unwrap());
        }
        records.finish().unwrap();
        // Every zero row's digest is remembered for its length by the end.
        for (range, zero) in &rows {
            if *zero {
                assert_eq!(
                    zeros.get(range.length),
                    Some(sha(&vec![0u8; range.length as usize]))
                );
            }
        }
        (digests, journal, finish(selected).unwrap())
    }

    #[test]
    fn a_worker_gives_every_row_the_digest_this_thread_would_have_given() {
        let source = {
            let rows = rows();
            let end = rows
                .iter()
                .map(|(range, _)| range.offset + range.length)
                .max()
                .unwrap();
            let mut source = image(end as usize);
            for (range, zero) in &rows {
                if *zero {
                    source[range.offset as usize..(range.offset + range.length) as usize].fill(0);
                }
            }
            source
        };
        let expected: Vec<[u8; 32]> = rows()
            .iter()
            .map(|(range, _)| {
                sha(&source[range.offset as usize..(range.offset + range.length) as usize])
            })
            .collect();
        let here = run(RecordHashes::here(Algorithm::Sha256), 0);
        assert_eq!(here.0, expected);
        // Settled at once, a row late, and only when every row was read.
        for late in [0usize, 1, 64] {
            let there = run(RecordHashes::on_a_worker(Algorithm::Sha256).unwrap(), late);
            assert_eq!(there.0, expected, "settled {late} rows late");
            assert_eq!(
                there.1, here.1,
                "the journal's bytes, settled {late} rows late"
            );
            assert_eq!(there.2, here.2, "the aggregate, settled {late} rows late");
        }
    }

    #[test]
    fn a_zero_row_is_remembered_when_its_digest_is_settled_and_not_before() {
        let length = 3 * GRANULE;
        let range = SelectedRange { offset: 0, length };
        let mut input = Cursor::new(vec![0u8; length as usize]);
        let mut records = RecordHashes::on_a_worker(Algorithm::Sha256).unwrap();
        let mut zeros = ZeroDigests::new();
        let mut buffer = vec![0u8; BUFFER];
        let mut selected = pin_hash(Algorithm::Sha256).unwrap();
        let mut zero = |zeros: &mut ZeroDigests, records: &mut RecordHashes| {
            verify_zero_selected_with(
                &mut input,
                &range,
                &mut selected,
                &mut buffer,
                zeros,
                "row is not zero",
                None,
                records,
            )
            .unwrap()
        };
        let first = zero(&mut zeros, &mut records);
        assert!(matches!(first, RowDigest::Owed { zero_length: Some(l) } if l == length));
        assert_eq!(zeros.get(length), None, "not remembered while it is owed");
        // A second row of that length before the first is settled is hashed
        // as well; both give the digest of that many zero bytes.
        let second = zero(&mut zeros, &mut records);
        assert!(matches!(second, RowDigest::Owed { .. }));
        let expected = sha(&vec![0u8; length as usize]);
        assert_eq!(records.settle(first, &mut zeros).unwrap(), expected);
        assert_eq!(zeros.get(length), Some(expected));
        assert_eq!(records.settle(second, &mut zeros).unwrap(), expected);
        // Once remembered, a row of that length is known at once.
        let third = zero(&mut zeros, &mut records);
        assert!(matches!(third, RowDigest::Known(digest) if digest == expected));
        records.finish().unwrap();
    }

    #[test]
    fn a_row_that_is_not_zero_fails_on_a_worker_as_it_does_here() {
        for worker in [false, true] {
            let range = SelectedRange {
                offset: 0,
                length: 2 * GRANULE,
            };
            let mut bytes = vec![0u8; 2 * GRANULE as usize];
            bytes[GRANULE as usize + 7] = 1;
            let mut records = if worker {
                RecordHashes::on_a_worker(Algorithm::Sha256).unwrap()
            } else {
                RecordHashes::here(Algorithm::Sha256)
            };
            let error = verify_zero_selected_with(
                &mut Cursor::new(bytes),
                &range,
                &mut pin_hash(Algorithm::Sha256).unwrap(),
                &mut vec![0u8; BUFFER],
                &mut ZeroDigests::new(),
                "row is not zero",
                None,
                &mut records,
            )
            .err()
            .expect("a nonzero byte is refused");
            assert!(format!("{error:#}").contains("row is not zero"));
        }
    }

    #[test]
    fn classify_rejects_conflicting_intent_beside_terminal_markers() {
        let ticket = SelectedTicket {
            image_length: 8192,
            selected_bytes: 4096,
            range_count: 1,
            journal_length: 16384,
            immutable_sha256: [1u8; 32],
            marker_profile: None,
            old_selected_sha256: [2u8; 32],
            old_restored_selected_sha256: None,
            new_selected_sha256: [3u8; 32],
            whole_image_verified: true,
            digest: None,
        };
        let zero = [0u8; GRANULE as usize];
        let apply = marker(b"N2RSAP01", &ticket, &ticket.new_selected_sha256);
        let rollback = marker(b"N2RSRB01", &ticket, &ticket.old_selected_sha256);
        let handoff = marker(b"N2RSHN01", &ticket, &ticket.new_selected_sha256);
        let aborted = marker(b"N2RSAB01", &ticket, &ticket.old_selected_sha256);
        let pair = |a: &[u8], b: &[u8]| {
            let mut v = Vec::with_capacity(2 * GRANULE as usize);
            v.extend_from_slice(a);
            v.extend_from_slice(b);
            Cursor::new(v)
        };
        // Valid terminal states.
        assert_eq!(
            classify(&mut pair(&handoff, &apply), &ticket).unwrap(),
            SelectedLifecycle::Handoff
        );
        assert_eq!(
            classify(&mut pair(&aborted, &zero), &ticket).unwrap(),
            SelectedLifecycle::Aborted
        );
        assert_eq!(
            classify(&mut pair(&aborted, &rollback), &ticket).unwrap(),
            SelectedLifecycle::Aborted
        );
        // Conflicting or torn intent alongside Handoff/Aborted must be rejected.
        assert!(classify(&mut pair(&handoff, &zero), &ticket).is_err());
        assert!(classify(&mut pair(&handoff, &rollback), &ticket).is_err());
        assert!(classify(&mut pair(&aborted, &apply), &ticket).is_err());
        let mut torn = apply;
        torn[0] ^= 0xff;
        assert!(classify(&mut pair(&handoff, &torn), &ticket).is_err());
        assert!(classify(&mut pair(&aborted, &torn), &ticket).is_err());
    }
}
