//! Read-only candidate for compact capture: metadata/tails come from a frozen
//! shadow, full-cluster payload comes from logical NTFS reads at measured ReFS
//! destinations. No payload-sized image or raw source writer is constructed.
//! Frozen metadata-graph reconciliation is still required before cutover.
use crate::selected_capacity::SelectedCapacityPolicy;
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition,
    shadow_native::private_tree::{PayloadRoute, SourceBackedRoutes},
};
use serde::Serialize;
use std::io::{self, Read, Seek, SeekFrom};

// Match the native partition reader's bounded aligned batch. Logical NTFS
// session reads use the same bound, so payload routes are not split into
// 64 KiB device requests.
const NATIVE_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const LOGICAL_SOURCE_READ_BYTES: usize = crate::ntfs_inspect::SESSION_READ_BYTES;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ReadCounts {
    pub source_logical_bytes: u64,
    pub shadow_bytes: u64,
    /// Actual closing-bracket bytes supplied again from its immutable read buffer.
    /// The closing bracket still reads and authenticates all of these bytes.
    #[serde(skip_serializing_if = "is_zero")]
    pub shadow_bytes_reused_from_closing: u64,
    /// Raw equality checks proving an omitted reference, separate from the
    /// logical candidate reads and their stream-transfer budget.
    #[serde(skip_serializing_if = "is_zero")]
    pub source_reference_bytes: u64,
    /// COPY bytes whose exact source mapping and immutable candidate slice
    /// were already observed during this same chunk read. Not extra disk IO.
    #[serde(skip_serializing_if = "is_zero")]
    pub source_reference_bytes_reused: u64,
}

struct CandidateReadSpan {
    output_offset: usize,
    source_offset: u64,
    length: usize,
}

/// Both growable span vectors can overlap while a direct-read receipt is
/// appended. Pay old plus new Vec allocations during growth; this stays
/// bounded by the explicit per-read span limit and is independent of row size.
pub(super) fn candidate_span_workspace_bytes() -> Result<u64> {
    let item_bytes = std::mem::size_of::<CandidateReadSpan>()
        .checked_add(std::mem::size_of::<crate::ntfs_inspect::DirectReadSpan>())
        .context("candidate span item size overflow")?;
    (crate::ntfs_inspect::MAX_DIRECT_READ_SPANS as u64)
        .checked_mul(item_bytes as u64)
        .and_then(|n| n.checked_mul(3))
        .and_then(|n| n.checked_add(64 * 1024))
        .context("candidate span workspace overflow")
}

impl<'buf> CandidateChunk<'buf> {
    pub(super) fn from_actual_reads(bytes: &'buf [u8], reads: CandidateReadSpans) -> Self {
        Self { bytes, reads }
    }
}

pub(super) struct CandidateReadSpans {
    spans: Vec<CandidateReadSpan>,
    available: bool,
}

impl CandidateReadSpans {
    pub(super) fn new() -> Self {
        Self {
            spans: Vec::new(),
            available: true,
        }
    }

    fn unavailable(&mut self) {
        self.available = false;
        self.spans.clear();
    }

    pub(super) fn append(
        &mut self,
        base: usize,
        count: usize,
        receipt: &crate::ntfs_inspect::DirectReadReceipt,
    ) {
        if !self.available {
            return;
        }
        let Some(spans) = receipt.spans() else {
            self.unavailable();
            return;
        };
        for span in spans {
            if !span
                .output_offset()
                .checked_add(span.length())
                .is_some_and(|end| end <= count)
            {
                self.unavailable();
                return;
            }
            let Some(output_offset) = base.checked_add(span.output_offset()) else {
                self.unavailable();
                return;
            };
            if let Some(last) = self.spans.last_mut() {
                if last.output_offset.checked_add(last.length) == Some(output_offset)
                    && last.source_offset.checked_add(last.length as u64)
                        == Some(span.source_offset())
                {
                    if let Some(length) = last.length.checked_add(span.length()) {
                        last.length = length;
                        continue;
                    }
                    self.unavailable();
                    return;
                }
            }
            if self.spans.len() == crate::ntfs_inspect::MAX_DIRECT_READ_SPANS
                || self.spans.try_reserve(1).is_err()
            {
                self.unavailable();
                return;
            }
            self.spans.push(CandidateReadSpan {
                output_offset,
                source_offset: span.source_offset(),
                length: span.length(),
            });
        }
    }
}

/// The receipt cannot outlive or be detached from these immutable actual
/// candidate bytes. Neither it nor the session receipt is serializable.
pub(super) struct CandidateChunk<'buf> {
    bytes: &'buf [u8],
    reads: CandidateReadSpans,
}

impl CandidateChunk<'_> {
    pub(super) fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub(super) fn copy_source(&self, offset: usize, length: usize) -> Option<u64> {
        let span = self.reads.spans.iter().find(|span| {
            span.output_offset <= offset
                && span
                    .output_offset
                    .checked_add(span.length)
                    .is_some_and(|end| offset < end)
        })?;
        let source = span
            .source_offset
            .checked_add((offset - span.output_offset) as u64)?;
        self.covers_copy(offset, source, length).then_some(source)
    }

    pub(super) fn covers_copy(
        &self,
        output_offset: usize,
        source_offset: u64,
        length: usize,
    ) -> bool {
        if !self.reads.available || length == 0 {
            return false;
        }
        let Some(finish) = output_offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
        else {
            return false;
        };
        if source_offset.checked_add(length as u64).is_none() {
            return false;
        }
        let mut cursor = output_offset;
        let mut index = self
            .reads
            .spans
            .partition_point(|r| r.output_offset + r.length <= cursor);
        while cursor < finish {
            let Some(span) = self.reads.spans.get(index) else {
                return false;
            };
            if span.output_offset > cursor
                || span
                    .source_offset
                    .checked_add((cursor - span.output_offset) as u64)
                    != source_offset.checked_add((cursor - output_offset) as u64)
            {
                return false;
            }
            cursor = finish.min(span.output_offset + span.length);
            index += 1;
        }
        true
    }
}

fn is_zero(bytes: &u64) -> bool {
    *bytes == 0
}

/// Independent upper bounds for encoded selected capture. These resource
/// ceilings do not reserve filesystem space or authorize source writes.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct CaptureBudget {
    pub max_changed_bytes: u64,
    pub max_journal_bytes: u64,
    pub max_literal_backing_bytes: u64,
    pub max_combined_backing_and_journal_bytes: u64,
    pub minimum_free_bytes: u64,
    #[serde(
        default,
        skip_serializing_if = "SelectedCapacityPolicy::is_conservative"
    )]
    pub selected_capacity_policy: SelectedCapacityPolicy,
}

/// State immediately before accepting a changed run. `changed_bytes` and
/// `range_count` include that run; `literal_backing_bytes` is already written,
/// and `next_append_bytes` is the additional literal allocation about to occur.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct CaptureProgress {
    pub changed_bytes: u64,
    pub literal_backing_bytes: u64,
    pub next_append_bytes: u64,
    pub range_count: usize,
    pub projected_journal_bytes: u64,
    pub projected_combined_bytes: u64,
    pub minimum_free_bytes: u64,
    #[serde(skip_serializing_if = "SelectedCapacityPolicy::is_conservative")]
    pub selected_capacity_policy: SelectedCapacityPolicy,
    /// Proposed whole-range old-zero bytes. New policy reports Some(0)
    /// explicitly; historical conservative progress keeps its original shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_zero_bytes: Option<u64>,
    /// Actual nonzero old destinations proved free by the frozen NTFS map.
    /// Their old granule hashes, rather than old payload, consume journal space.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_free_bytes: Option<u64>,
}
impl CaptureProgress {
    /// Already written backing is reflected in current filesystem free space;
    /// charge only the pending append, future journal and working reserve.
    pub fn required_available_bytes(&self) -> Result<u64> {
        self.projected_journal_bytes
            .checked_add(self.next_append_bytes)
            .and_then(|n| n.checked_add(self.minimum_free_bytes))
            .context("capture free-space requirement overflow")
    }
}
impl CaptureBudget {
    pub fn validate(&self, image_bytes: u64) -> Result<()> {
        let overhead = n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE;
        ensure!(
            self.max_changed_bytes != 0
                && self.max_changed_bytes.is_multiple_of(4096)
                && self.max_changed_bytes <= image_bytes
                && self
                    .max_journal_bytes
                    .checked_sub(overhead)
                    .is_some_and(|n| {
                        !self.selected_capacity_policy.is_conservative()
                            || self.max_changed_bytes <= n
                    })
                && self.max_literal_backing_bytes
                    <= n2r_win32::reference_file::MAX_REFERENCE_FILE_BYTES
                && self.max_combined_backing_and_journal_bytes >= overhead + 4096,
            "encoded capture capacity bounds differ"
        );
        Ok(())
    }

    fn assess(
        &self,
        changed: u64,
        old_zero: u64,
        source_free: u64,
        literal: u64,
        append: u64,
        ranges: usize,
    ) -> Result<CaptureProgress> {
        // The widest selected encoding has 104-byte records. The established
        // 16 MiB reserve also covers headers, footer and bounded metadata; the
        // exact plan is independently validated after the capture completes.
        let metadata = 8192u64
            .checked_add(80 + 80)
            .and_then(|n| {
                (ranges as u64)
                    .checked_mul(104)
                    .and_then(|r| n.checked_add(r))
            })
            .context("capture journal metadata overflow")?;
        let overhead = n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE;
        ensure!(
            metadata <= overhead,
            "capture journal metadata exceeds its reserve"
        );
        let projected_literal = literal
            .checked_add(append)
            .context("capture literal backing overflow")?;
        let stored_old = match self.selected_capacity_policy {
            SelectedCapacityPolicy::ConservativeV1 => changed,
            SelectedCapacityPolicy::OldZeroActualBytesV1
            | SelectedCapacityPolicy::SourceFreeActualBytesV1 => {
                ensure!(
                    old_zero.is_multiple_of(4096)
                        && source_free.is_multiple_of(4096)
                        && (self.selected_capacity_policy.allows_source_free() || source_free == 0),
                    "capture omitted old bytes differ from the explicit policy"
                );
                changed
                    .checked_sub(old_zero)
                    .and_then(|bytes| bytes.checked_sub(source_free))
                    .context("capture omitted old bytes exceed changed bytes")?
            }
        };
        let journal = stored_old
            .checked_add(projected_literal)
            .and_then(|bytes| bytes.checked_add(source_free / 256))
            .and_then(|n| n.checked_add(overhead))
            .context("capture journal capacity overflow")?;
        let combined = journal
            .checked_add(projected_literal)
            .context("capture combined capacity overflow")?;
        ensure!(
            changed <= self.max_changed_bytes,
            "capture changed bytes exceed their capacity bound"
        );
        ensure!(
            projected_literal <= self.max_literal_backing_bytes,
            "capture literal backing exceeds its capacity bound"
        );
        ensure!(
            journal <= self.max_journal_bytes,
            "capture encoded journal exceeds its capacity bound"
        );
        ensure!(
            combined <= self.max_combined_backing_and_journal_bytes,
            "capture backing plus journal exceeds its capacity bound"
        );
        Ok(CaptureProgress {
            changed_bytes: changed,
            literal_backing_bytes: literal,
            next_append_bytes: append,
            range_count: ranges,
            projected_journal_bytes: journal,
            projected_combined_bytes: combined,
            minimum_free_bytes: self.minimum_free_bytes,
            selected_capacity_policy: self.selected_capacity_policy,
            old_zero_bytes: (!self.selected_capacity_policy.is_conservative()).then_some(old_zero),
            source_free_bytes: self
                .selected_capacity_policy
                .allows_source_free()
                .then_some(source_free),
        })
    }
}

struct CaptureCapacity<'g> {
    budget: CaptureBudget,
    guard: &'g mut dyn FnMut(CaptureProgress) -> Result<()>,
}

const SELECTED_CHUNK_DIGEST: &str = "sha256-over-frames-and-xxh3-128-per-compared-chunk";

/// A comparison's chunks read ahead of it through a second handle of the
/// same frozen disk.
#[path = "original_prefetch.rs"]
pub(crate) mod original_prefetch;
use original_prefetch::{LaneReads, OriginalPrefetch};

/// Framed digest of the bytes one side of a capture compared. `Stream` and
/// `Overlapped` are a SHA-256 of the framed byte stream (recomputed by the
/// complete path). `Chunks` is a SHA-256 over the same frames and the
/// XXH3-128 of each compared chunk (at most 4 MiB, range-relative), for the
/// allocation-bounded capture whose digests bind evidence only.
enum SelectedDigest {
    Stream(crate::retained_compare::stream_digest::StreamDigest),
    Overlapped(crate::retained_compare::digest_pipeline::Overlapped),
    Chunks(sha2::Sha256),
}

impl SelectedDigest {
    fn chunks() -> Self {
        use sha2::Digest;
        Self::Chunks(sha2::Sha256::new())
    }

    fn frame(&mut self, bytes: &[u8]) -> Result<()> {
        use sha2::Digest;
        match self {
            Self::Stream(hash) => hash.update(bytes),
            Self::Overlapped(hash) => hash.update(bytes),
            Self::Chunks(hash) => {
                hash.update(bytes);
                Ok(())
            }
        }
    }

    fn chunk(&mut self, bytes: &[u8]) -> Result<()> {
        use sha2::Digest;
        match self {
            Self::Chunks(hash) => {
                hash.update(crate::parallel_digest::xxh3_128(bytes));
                Ok(())
            }
            other => other.frame(bytes),
        }
    }

    fn finish(self) -> Result<[u8; 32]> {
        use sha2::Digest;
        match self {
            Self::Stream(hash) => hash.finish(),
            Self::Overlapped(hash) => hash.finish(),
            Self::Chunks(hash) => Ok(hash.finalize().into()),
        }
    }
}

#[derive(Serialize)]
pub struct DifferenceCapture {
    pub layout: crate::refs_hybrid::delta::DeltaLayout,
    pub selected_bytes_compared: u64,
    pub equal_selected_bytes: u64,
    pub read_counts: ReadCounts,
    /// How `source_selected_sha256` and `candidate_selected_sha256` are formed.
    pub selected_digest: &'static str,
    pub source_selected_sha256: String,
    pub candidate_selected_sha256: String,
    pub packed_sha256: String,
    pub input_plan_sha256: String,
    pub conversion_qualified: bool,
    /// Non-gating destination split of the changed granules; present only
    /// for a listed capture that asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_classes: Option<ChangedClassCounters>,
    // Only a fresh, complete source scan can issue this digest. Keep the
    // sidecar out of strict historical capture reports and recovery inputs.
    #[serde(skip)]
    source_raw_sha256: Option<String>,
}
impl DifferenceCapture {
    pub(crate) fn source_raw_sha256(&self) -> Option<&str> {
        self.source_raw_sha256.as_deref()
    }
}

/// Non-gating measurement: every changed 4 KiB granule of a listed capture,
/// split by its destination (NTFS-allocated or free at that offset; inside a
/// relocated payload route or not; below the first route destination) and by
/// whether either side's granule is all zero. It changes no output, digest,
/// range, budget or refusal. `changed_ranges` counts maximal contiguous
/// changed runs as the packed layout does. Without the NTFS allocation model
/// the two NTFS counters stay zero and `ntfs_allocation_available` is false.
/// With no routes, every byte counts as below the first route destination.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ChangedClassCounters {
    pub changed_bytes_total: u64,
    pub changed_bytes_ntfs_free_destination: u64,
    pub changed_bytes_ntfs_allocated_destination: u64,
    pub changed_bytes_in_payload_route: u64,
    pub changed_bytes_outside_routes: u64,
    pub changed_bytes_below_first_route_destination: u64,
    pub changed_bytes_new_is_zero: u64,
    pub changed_bytes_old_is_zero: u64,
    pub changed_ranges: u64,
    pub first_route_destination_offset: Option<u64>,
    pub ntfs_allocation_available: bool,
}

/// Destination context for [`ChangedClassCounters`]. Payload routes come from
/// the capturing view itself.
#[derive(Clone, Copy)]
pub struct ChangeClassSplit<'b> {
    /// Sorted, merged NTFS-allocated `(offset, length)` ranges, or `None` when
    /// the reconciled raw allocation model is unavailable.
    pub ntfs_allocated: Option<&'b [(u64, u64)]>,
}

/// Accumulates [`ChangedClassCounters`]. Arithmetic saturates so the
/// diagnostic can never fail or panic a capture.
struct ChangeClassifier<'b> {
    counters: ChangedClassCounters,
    allocated: &'b [(u64, u64)],
    routes: &'b [PayloadRoute],
    last_end: Option<u64>,
}

impl<'b> ChangeClassifier<'b> {
    fn new(split: ChangeClassSplit<'b>, routes: &'b [PayloadRoute]) -> Self {
        Self {
            counters: ChangedClassCounters {
                first_route_destination_offset: routes.first().map(|r| r.target_physical_offset),
                ntfs_allocation_available: split.ntfs_allocated.is_some(),
                ..ChangedClassCounters::default()
            },
            allocated: split.ntfs_allocated.unwrap_or(&[]),
            routes,
            last_end: None,
        }
    }

    /// Record one run of changed whole granules destined for `address`.
    fn record(&mut self, address: u64, original: &[u8], candidate: &[u8]) {
        let bytes = candidate.len() as u64;
        let end = address.saturating_add(bytes);
        let counters = &mut self.counters;
        if self.last_end != Some(address) {
            counters.changed_ranges = counters.changed_ranges.saturating_add(1);
        }
        self.last_end = Some(end);
        counters.changed_bytes_total = counters.changed_bytes_total.saturating_add(bytes);
        if counters.ntfs_allocation_available {
            let allocated = covered_bytes(self.allocated, |&span| span, address, end);
            counters.changed_bytes_ntfs_allocated_destination = counters
                .changed_bytes_ntfs_allocated_destination
                .saturating_add(allocated);
            counters.changed_bytes_ntfs_free_destination = counters
                .changed_bytes_ntfs_free_destination
                .saturating_add(bytes.saturating_sub(allocated));
        }
        let routed = covered_bytes(
            self.routes,
            |r| (r.target_physical_offset, r.length),
            address,
            end,
        );
        counters.changed_bytes_in_payload_route = counters
            .changed_bytes_in_payload_route
            .saturating_add(routed);
        counters.changed_bytes_outside_routes = counters
            .changed_bytes_outside_routes
            .saturating_add(bytes.saturating_sub(routed));
        let below = counters
            .first_route_destination_offset
            .map_or(bytes, |first| first.min(end).saturating_sub(address));
        counters.changed_bytes_below_first_route_destination = counters
            .changed_bytes_below_first_route_destination
            .saturating_add(below);
        for granule in candidate.chunks_exact(4096) {
            if granule.iter().all(|&b| b == 0) {
                counters.changed_bytes_new_is_zero =
                    counters.changed_bytes_new_is_zero.saturating_add(4096);
            }
        }
        for granule in original.chunks_exact(4096) {
            if granule.iter().all(|&b| b == 0) {
                counters.changed_bytes_old_is_zero =
                    counters.changed_bytes_old_is_zero.saturating_add(4096);
            }
        }
    }
}

/// Bytes of `[start, end)` inside sorted, disjoint `(offset, length)` spans.
fn covered_bytes<T>(items: &[T], span: impl Fn(&T) -> (u64, u64), start: u64, end: u64) -> u64 {
    let first = items.partition_point(|item| {
        let (offset, length) = span(item);
        offset.saturating_add(length) <= start
    });
    let mut bytes = 0u64;
    for item in &items[first..] {
        let (offset, length) = span(item);
        if offset >= end {
            break;
        }
        bytes = bytes.saturating_add(
            offset
                .saturating_add(length)
                .min(end)
                .saturating_sub(offset.max(start)),
        );
    }
    bytes
}

/// Admit one whole granule only when its source is already part of the
/// captured write set. Journal preparation can then resolve it solely from
/// immutable OLD payloads, including when that earlier range is itself a
/// zero or copy replacement. This never follows the earlier range's NEW data.
fn captured_copy_source(
    copies: &[crate::payload_copy_plan::CopySpan],
    captured: &[crate::refs_hybrid::delta::ChangedRange],
    destination: u64,
) -> Option<u64> {
    let copy = copies
        .get(copies.partition_point(|copy| copy.destination_offset + copy.length <= destination))?;
    let destination_end = destination.checked_add(4096)?;
    if copy.destination_offset > destination
        || destination_end > copy.destination_offset.checked_add(copy.length)?
    {
        return None;
    }
    let source = copy
        .source_offset
        .checked_add(destination - copy.destination_offset)?;
    let source_end = source.checked_add(4096)?;
    if source_end > destination {
        return None;
    }
    let first = captured.partition_point(|range| range.offset + range.length <= source);
    let mut cursor = source;
    for range in &captured[first..] {
        if range.offset > cursor {
            return None;
        }
        cursor = source_end.min(range.offset + range.length);
        if cursor == source_end {
            return Some(source);
        }
    }
    None
}

/// What the changed-byte budget met when a capture refused. The run stops
/// at the current 4 MiB comparison chunk; `compared_bytes_through_refused_run`
/// counts every selected byte compared up to the end of that run.
#[derive(Serialize)]
struct BudgetRefusal {
    max_changed_bytes: u64,
    changed_bytes_written: u64,
    refused_run_bytes: u64,
    compared_bytes_through_refused_run: u64,
    selected_bytes: u64,
}

/// The unchanged budget refusal, stating the budget against the selection. A
/// class split so far is appended and, when possible, left in a new
/// `<output>.class-split.json` beside the partial artifact. Neither can turn
/// the refusal into another error.
fn budget_refusal(
    output: &std::path::Path,
    refusal: &BudgetRefusal,
    classes: Option<&ChangedClassCounters>,
) -> anyhow::Error {
    use std::io::Write;
    let mut message = format!(
        "delta capture budget exhausted before next output write; preserve partial artifact \
         (max_changed_bytes {}, changed_bytes_written {}, refused_run_bytes {}, \
         compared_bytes_through_refused_run {}, selected_bytes {})",
        refusal.max_changed_bytes,
        refusal.changed_bytes_written,
        refusal.refused_run_bytes,
        refusal.compared_bytes_through_refused_run,
        refusal.selected_bytes
    );
    if let Some(classes) = classes {
        if let Ok(json) = serde_json::to_string(classes) {
            message.push_str("; class split so far: ");
            message.push_str(&json);
        }
        let mut path = output.as_os_str().to_owned();
        path.push(".class-split.json");
        if let Ok(bytes) = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":1,"kind":"listed-capture-changed-class-split",
            "complete":false,"budget_refusal":refusal,"changed_classes":classes}))
        {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(std::path::PathBuf::from(path))
                .and_then(|mut file| {
                    file.write_all(&bytes)?;
                    file.sync_all()
                });
        }
    }
    anyhow::anyhow!(message)
}

/// Internal byte supply for the fused closing pass. It receives the same held
/// frozen target, and may reuse only its actual immutable closing-read bytes.
/// Returning zero retains the ordinary actual-read fallback accounting.
pub(crate) trait ClosingShadowBytes {
    fn read_shadow_exact(
        &mut self,
        target: &mut GeneralFrozenPartition,
        offset: u64,
        output: &mut [u8],
    ) -> Result<u64>;
}

/// Observe only the immutable original bytes already read by this capture,
/// before its prefetch buffer is recycled. The supplied owner is the same
/// frozen source that created those read lanes; it has no Write implementation
/// or online/attribute setter. Consumers may read missing coverage through it.
pub(crate) trait ClosingSourceBytes {
    fn observe_original(
        &mut self,
        source: &mut GeneralFrozenPartition,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()>;
}

/// A borrowed expected-stream identity, never a source or write capability.
/// The checked paged source and actual record reread must independently agree.
pub struct PagedStreamIdentity<'a> {
    pub record_number: u64,
    pub sequence_number: u16,
    pub name_utf16: &'a [u16],
    pub length: u64,
    pub sha256: Option<&'a str>,
    pub allow_sparse: bool,
}

/// Logical bytes from the original protected source, using one checked DATA
/// session. The legacy candidate and its Tree/NtfsInspection path stay intact.
#[path = "partition_source_bytes.rs"]
mod partition_source_bytes;
use partition_source_bytes::BorrowedPagedSource;

// Preserve the established one-lifetime dedicated/partition interface.
pub type PagedSourceByteAdapter<'a> = PagedSourceByteAdapterWithScope<'a, 'a>;

/// What the adapter holds beside its stream session: the two 64 KiB unit
/// buffers of a compressed stream's decoder, and as much again for its own
/// state. The session pays for the record it holds
/// (`PlainStreamRangeSession::open_domain_policy`), and a record looked up
/// to open one is paid for while it is held (`prepare`). This used to be
/// eight of the largest row the budget admits, an eighth of the ledger for
/// as long as the adapter lived: 1.1 GB on a machine with 16 GB, through
/// supply, verification and capture.
pub(super) const SESSION_WORKSPACE: u64 = 4 * 16 * 4096;

pub struct PagedSourceByteAdapterWithScope<'a, 'scope> {
    source: BorrowedPagedSource<'a, 'scope>,
    raw: &'a crate::ntfs_inspect::PagedInspection,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
    before: Option<n2r_win32::GeneralDiskState>,
    budget: crate::ntfs_inspect::StreamTransferBudget,
    session: Option<crate::ntfs_inspect::PlainStreamRangeSession>,
    sequence: Option<u16>,
    allow_sparse: Option<bool>,
    logical_bytes: u64,
    poisoned: bool,
    /// Bytes of the source a read lane has just read, at their place on the
    /// partition, which a stream's reads take where they lie wholly inside
    /// them ([`AheadReader`]); empty but where a caller offered them.
    read_ahead: Vec<(u64, Vec<u8>)>,
    /// True only when every entry in `read_ahead` was read by a read lane of
    /// `self.source` inside the same frozen scope, allowing `AheadReader` to
    /// satisfy `read_with_direct_receipts` (`direct == true`) as well.
    read_ahead_from_source_lanes: bool,
    /// Bounded, evictable 1 MiB aligned page cache for small MFT record reads
    /// during `prepare()` under `checks_once()`. Paid from `reserve_cache_ram`.
    mft_cache: Option<n2r_win32::evict::Evictable<MftPageCache>>,
    _session_ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
}

impl<'a, 'scope> PagedSourceByteAdapterWithScope<'a, 'scope> {
    pub fn new(
        source: &'a mut GeneralFrozenPartition,
        raw: &'a crate::ntfs_inspect::PagedInspection,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        maximum_logical_reads: u64,
    ) -> Result<Self> {
        use crate::ntfs_inspect::RootFileDomain;
        admission.validate()?;
        raw.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        let pin: [u8; 32] = hex::decode(raw.canonical_sha256()?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("source pin length differs"))?;
        ensure!(
            pin == admission.source_inspection_sha256
                && raw.file_count() == admission.raw_identities
                && raw.header().mft_record_count == admission.mft_records
                && (raw.header().geometry.volume_size == source.byte_len()
                    || raw
                        .header()
                        .geometry
                        .volume_size
                        .checked_add(u64::from(raw.header().geometry.bytes_per_sector,))
                        == Some(source.byte_len())),
            "paged source byte owner differs from the admitted partition",
        );
        let mut events = Vec::new();
        let before = source.state(&mut events)?;
        ensure!(
            before.disk_attributes == 3,
            "original source must remain excluded read-only"
        );
        let session_ram = raw.lease_working_ram(SESSION_WORKSPACE)?;
        Ok(Self {
            source: BorrowedPagedSource::Dedicated(source),
            raw,
            admission,
            before: Some(before),
            // Individual NTFS logical lengths have the native signed-width
            // bound. Aggregate actual reads retain the caller's explicit budget.
            budget: crate::ntfs_inspect::StreamTransferBudget::new(
                i64::MAX as u64,
                maximum_logical_reads,
            )?,
            session: None,
            sequence: None,
            allow_sparse: None,
            logical_bytes: 0,
            poisoned: false,
            read_ahead: Vec::new(),
            read_ahead_from_source_lanes: false,
            mft_cache: None,
            _session_ram: session_ram,
        })
    }

    /// The actual SDK scope supplies source identity/exclusion checks; its
    /// issuer performs full role fences before and after this adapter lives.
    pub(crate) fn new_scoped(
        source: &'a mut n2r_win32::GeneralFrozenSourceReadScope<'scope>,
        raw: &'a crate::ntfs_inspect::PagedInspection,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        maximum_logical_reads: u64,
    ) -> Result<Self> {
        use crate::ntfs_inspect::RootFileDomain;
        admission.validate()?;
        raw.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        let pin: [u8; 32] = hex::decode(raw.canonical_sha256()?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("source pin length differs"))?;
        ensure!(
            pin == admission.source_inspection_sha256
                && raw.file_count() == admission.raw_identities
                && raw.header().mft_record_count == admission.mft_records
                && (raw.header().geometry.volume_size == source.byte_len()
                    || raw
                        .header()
                        .geometry
                        .volume_size
                        .checked_add(u64::from(raw.header().geometry.bytes_per_sector,))
                        == Some(source.byte_len())),
            "paged source byte owner differs from the admitted partition",
        );
        let mut events = Vec::new();
        let before = source.state(&mut events)?;
        ensure!(
            before.disk_attributes == 3,
            "original source must remain excluded read-only"
        );
        let session_ram = raw.lease_working_ram(SESSION_WORKSPACE)?;
        Ok(Self {
            source: BorrowedPagedSource::DedicatedScoped(source),
            raw,
            admission,
            before: Some(before),
            // Individual NTFS logical lengths have the native signed-width
            // bound. Aggregate actual reads retain the caller's explicit budget.
            budget: crate::ntfs_inspect::StreamTransferBudget::new(
                i64::MAX as u64,
                maximum_logical_reads,
            )?,
            session: None,
            sequence: None,
            allow_sparse: None,
            logical_bytes: 0,
            poisoned: false,
            read_ahead: Vec::new(),
            read_ahead_from_source_lanes: false,
            mft_cache: None,
            _session_ram: session_ram,
        })
    }

    fn prepare(&mut self, identity: &PagedStreamIdentity<'_>) -> Result<()> {
        use crate::ntfs_inspect::RootFileDomain;
        ensure!(
            !self.poisoned,
            "failed paged source byte adapter cannot continue"
        );
        let matches = self.session.as_ref().is_some_and(|session| {
            session.matches_stream(identity.record_number, identity.name_utf16)
                && self.sequence == Some(identity.sequence_number)
                && self.allow_sparse == Some(identity.allow_sparse)
        });
        if !matches {
            if let Some(session) = self.session.take() {
                session.finish_domain(&mut self.source, self.raw)?;
            }
            // The record is held, decoded, until the session is open.
            let _record_ram = self
                .raw
                .lease_working_ram(self.raw.record_workspace(identity.record_number)?)?;
            let file = self
                .raw
                .find_record(identity.record_number, Some(identity.sequence_number))?
                .context("paged source byte identity is missing or stale")?;
            ensure!(!file.is_directory, "directory cannot supply DATA payload");
            let mut streams = file
                .streams
                .iter()
                .filter(|s| s.name_utf16 == identity.name_utf16);
            let stream = streams.next().context("paged source DATA stream absent")?;
            ensure!(
                streams.next().is_none()
                    && stream.logical_size == identity.length
                    && stream.logical_sha256.as_deref() == identity.sha256,
                "expected stream differs from the complete paged source",
            );
            let use_mft_cache = n2r_win32::verify_policy::checks_once()
                && n2r_win32::verify_policy::open_gate().is_none()
                && !matches!(self.source, BorrowedPagedSource::Partition { .. });
            let session = if use_mft_cache {
                let scratch = self.raw.metadata_scratch();
                let byte_len = self.source.byte_len();
                let mut reader = CachedMftReader::new(
                    &mut self.source,
                    &mut self.mft_cache,
                    &scratch,
                    byte_len,
                )?;
                if identity.allow_sparse {
                    crate::ntfs_inspect::PlainStreamRangeSession::open_sparse_named_domain(
                        &mut reader,
                        self.raw,
                        identity.record_number,
                        identity.name_utf16,
                        identity.length,
                    )?
                } else {
                    crate::ntfs_inspect::PlainStreamRangeSession::open_named_domain(
                        &mut reader,
                        self.raw,
                        identity.record_number,
                        identity.name_utf16,
                        identity.length,
                    )?
                }
            } else if identity.allow_sparse {
                crate::ntfs_inspect::PlainStreamRangeSession::open_sparse_named_domain(
                    &mut self.source,
                    self.raw,
                    identity.record_number,
                    identity.name_utf16,
                    identity.length,
                )?
            } else {
                crate::ntfs_inspect::PlainStreamRangeSession::open_named_domain(
                    &mut self.source,
                    self.raw,
                    identity.record_number,
                    identity.name_utf16,
                    identity.length,
                )?
            };
            self.session = Some(session);
            self.sequence = Some(identity.sequence_number);
            self.allow_sparse = Some(identity.allow_sparse);
        }
        let session = self.session.as_ref().context("paged DATA session absent")?;
        ensure!(
            session.stream_length() == identity.length
                && session.expected_sha256() == identity.sha256,
            "checked DATA session differs from expected stream length or evidence",
        );
        Ok(())
    }

    pub fn read_into(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        self.read_observed(identity, offset, output, false)
            .map(|_| ())
    }

    pub(crate) fn read_with_direct_receipts(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        output: &mut [u8],
    ) -> Result<crate::ntfs_inspect::DirectReadReceipt> {
        self.read_observed(identity, offset, output, true)?
            .context("actual direct-read receipt absent")
    }

    fn read_observed(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        output: &mut [u8],
        direct: bool,
    ) -> Result<Option<crate::ntfs_inspect::DirectReadReceipt>> {
        let prepared = self.prepare(identity);
        if prepared.is_err() {
            self.poisoned = true;
        }
        prepared?;
        self.poisoned = true;
        let session = self.session.as_mut().context("paged DATA session absent")?;
        // A direct read's receipt says the frozen source itself supplied the
        // bytes: only buffers read from `self.source`'s own read lanes within
        // the same scope may satisfy `direct == true`.
        let use_ahead =
            !self.read_ahead.is_empty() && (!direct || self.read_ahead_from_source_lanes);
        let receipt = if !use_ahead {
            read_session(
                session,
                &mut self.source,
                self.raw,
                offset,
                output,
                &mut self.budget,
                direct,
            )?
        } else {
            let mut reader = AheadReader::new(&mut self.source, &self.read_ahead)?;
            read_session(
                session,
                &mut reader,
                self.raw,
                offset,
                output,
                &mut self.budget,
                direct,
            )?
        };
        self.logical_bytes = self
            .logical_bytes
            .checked_add(output.len() as u64)
            .context("paged source logical-read accounting overflow")?;
        self.poisoned = false;
        Ok(receipt)
    }

    pub fn logical_bytes_read(&self) -> u64 {
        self.logical_bytes
    }

    /// Offers `bytes`, which a read lane of this source has just read at
    /// `offset` on the partition, to the reads of the stream read next:
    /// where one of them lies wholly inside them it takes them instead of
    /// asking the device again ([`AheadReader`]). Which bytes a stream reads
    /// is still decided by its session, from the source's own record; bytes
    /// no read asks for are not used. The caller takes them back
    /// ([`Self::withdraw_read_ahead`]) once that stream's range is read.
    pub(crate) fn offer_read_ahead(&mut self, offset: u64, bytes: Vec<u8>) {
        self.read_ahead_from_source_lanes = false;
        self.read_ahead.push((offset, bytes));
    }

    /// Offers `bytes` read by a read lane of `self.source` inside the same
    /// frozen scope, enabling `AheadReader` to satisfy `read_with_direct_receipts`
    /// as well as ordinary reads.
    pub(crate) fn offer_source_lane_read_ahead(&mut self, offset: u64, bytes: Vec<u8>) {
        if self.read_ahead.is_empty() {
            self.read_ahead_from_source_lanes = true;
        }
        self.read_ahead.push((offset, bytes));
    }

    /// Takes back every offer, handing each buffer to `give_back`.
    pub(crate) fn withdraw_read_ahead(&mut self, give_back: impl FnMut(Vec<u8>)) {
        self.read_ahead_from_source_lanes = false;
        self.read_ahead
            .drain(..)
            .map(|(_, bytes)| bytes)
            .for_each(give_back);
    }

    /// How many reads the source's device takes at once where the source
    /// may be read through lanes of its own (a dedicated source inside its
    /// read scope); zero where it may not.
    pub(crate) fn read_lane_depth(&self) -> usize {
        self.source.read_lane_depth()
    }

    /// `count` read lanes of the source, where [`Self::read_lane_depth`] is
    /// not zero; none otherwise. They are to be dropped before the adapter.
    pub(crate) fn read_lanes(
        &mut self,
        count: usize,
    ) -> io::Result<Vec<n2r_win32::GeneralFrozenLane>> {
        self.source.read_lanes(count)
    }

    pub fn source_binding(&self) -> &n2r_win32::general_layout::GeneralDiskBinding {
        self.source.binding()
    }

    pub(crate) fn metadata_scratch(&self) -> crate::ntfs_inspect::paged_storage::SourceScratch {
        self.raw.metadata_scratch()
    }

    pub(super) fn raw_source(&self) -> &crate::ntfs_inspect::PagedInspection {
        self.raw
    }
    pub(super) fn allocation_cursor(
        &self,
        partition_bytes: u64,
    ) -> Result<crate::ntfs_inspect::allocation_domain::AllocationCursor<'a>> {
        self.raw.allocation_cursor(partition_bytes)
    }

    pub(crate) fn source_physical_for(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        length: u64,
    ) -> Result<Option<u64>> {
        let result = (|| {
            self.prepare(identity)?;
            self.session
                .as_ref()
                .context("checked COPY session absent")?
                .contiguous_physical_range(offset, length)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(super) fn original_owner(&mut self) -> &mut BorrowedPagedSource<'a, 'scope> {
        &mut self.source
    }

    pub(super) fn original_owner_id(&self) -> usize {
        self.source.owner_identity()
    }

    #[track_caller]
    pub(crate) fn lease_working_ram(
        &self,
        bytes: u64,
    ) -> Result<crate::ntfs_inspect::paged_storage::SourceRamLease> {
        self.raw.lease_working_ram(bytes)
    }

    pub(crate) fn require_admission(
        &mut self,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<()> {
        ensure!(self.admission == admission, "source byte admission differs");
        self.validate_protection()?;
        self.raw
            .require_paged_source(admission.source_pages, admission.semantic_byte_budget())
    }

    pub(crate) fn validate_protection(&mut self) -> Result<()> {
        ensure!(!self.poisoned, "failed source adapter cannot validate");
        let result = self.source.validate(self.before.as_ref());
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn finish_stream(&mut self) -> Result<()> {
        ensure!(!self.poisoned, "failed source adapter cannot close stream");
        self.poisoned = true;
        if let Some(session) = self.session.take() {
            session.finish_domain(&mut self.source, self.raw)?;
        }
        self.sequence = None;
        self.allow_sparse = None;
        self.poisoned = false;
        self.validate_protection()
    }

    pub(crate) fn require_reference(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        physical: u64,
        length: u64,
    ) -> Result<()> {
        let result = (|| {
            self.prepare(identity)?;
            self.session
                .as_ref()
                .context("checked reference session absent")?
                .require_physical_mapping(offset, physical, length).with_context(||format!(
                    "source reference record={}, sequence={}, stream={:?}, logical_offset={offset}, physical_offset={physical}, length={length}",
                    identity.record_number,identity.sequence_number,identity.name_utf16))?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn check_stream(&mut self, identity: &PagedStreamIdentity<'_>) -> Result<()> {
        let result = self.prepare(identity);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn require_hole(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        length: u64,
    ) -> Result<()> {
        let result = (|| {
            self.prepare(identity)?;
            self.session
                .as_ref()
                .context("checked hole session absent")?
                .require_zero_mapping(offset, length)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Actual checked range bytes. The mapping is revalidated when the session
    /// of the stream closes. Whole-stream content is claimed only when read.
    pub(crate) fn read_range_proof(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        output: &mut [u8],
    ) -> Result<crate::ntfs_inspect::StreamRangeReadProof> {
        let allocation = self.read_range(identity, offset, output)?;
        let whole = offset == 0 && output.len() as u64 == identity.length;
        let sha256 = hex::encode(n2r_win32::content_digest::sha256(output)?);
        self.end_range()?;
        Ok(crate::ntfs_inspect::StreamRangeReadProof {
            record_number: identity.record_number,
            stream_name_utf16: identity.name_utf16.to_vec(),
            logical_offset: offset,
            logical_bytes: output.len() as u64,
            stream_logical_bytes: identity.length,
            expected_stream_sha256: identity.sha256.map(str::to_owned),
            sha256,
            whole_stream_hash_matched: whole && identity.sha256.is_some(),
            allocation,
        })
    }

    /// [`Self::read_range_proof`] for a caller that keeps no proof of the
    /// range: every check is made as there, and only the digest of the
    /// range, which nothing but the proof carries, is not computed.
    pub(crate) fn read_range_checked(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        self.read_range(identity, offset, output)?;
        self.end_range()
    }

    /// The protection checked, the bytes read, a sparse stream's allocation
    /// evidence taken and a whole stream held to its expected content.
    fn read_range(
        &mut self,
        identity: &PagedStreamIdentity<'_>,
        offset: u64,
        output: &mut [u8],
    ) -> Result<Option<crate::ntfs_inspect::StreamAllocationEvidence>> {
        self.validate_protection()?;
        self.read_into(identity, offset, output)?;
        let allocation = if identity.allow_sparse {
            Some(
                self.session
                    .as_ref()
                    .context("range DATA session absent")?
                    .allocation_evidence()?,
            )
        } else {
            None
        };
        let whole = offset == 0 && output.len() as u64 == identity.length;
        if whole && let Some(expected) = identity.sha256 {
            if n2r_win32::content_digest::of(output) != expected {
                self.poisoned = true;
                anyhow::bail!("checked full source stream differs from expected content");
            }
        }
        Ok(allocation)
    }

    fn end_range(&mut self) -> Result<()> {
        // Closing the stream's session reads its file record again (all of
        // them, for a stream with an attribute list) and checks the mapping.
        // Where everything is re-read at each step that happens after every
        // range. Otherwise it happens once, when the caller finishes the
        // stream or moves to another: a stream copied in many pieces (a
        // sparse file with thousands of islands) would otherwise be opened
        // and closed once per piece, which is quadratic in its runs.
        if n2r_win32::verify_policy::full_unremembered() {
            self.finish_stream()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<u64> {
        ensure!(
            !self.poisoned,
            "failed paged source byte adapter cannot finish"
        );
        if let Some(session) = self.session.take() {
            session.finish_domain(&mut self.source, self.raw)?;
        }
        self.raw.require_paged_source(
            self.admission.source_pages,
            self.admission.semantic_byte_budget(),
        )?;
        self.source.validate(self.before.as_ref())?;
        Ok(self.logical_bytes)
    }
}

/// The most tails one batch of a pass that reads tails ahead has asked
/// for, and the most objects it holds.
pub(crate) const TAIL_BATCH: usize = 8192;
/// The most bytes of tails one batch has read ahead and holds.
pub(crate) const TAIL_BATCH_BYTES: u64 = 16 * 1024 * 1024;
/// What a batch's lists hold for each tail read ahead: its ticket, its
/// place and length, and its slot.
const TAIL_ASK_BYTES: u64 = 64;

/// Where on the partition `count` bytes of `stream` at `offset` lie, where
/// the stream's expected run list puts all of them in one run: the place the
/// tail is read ahead from. Only a hint for the read ahead: what the tail's
/// read takes is decided by the session, from the source's own record, and
/// bytes read from another place are not used.
pub(crate) fn tail_place(
    stream: &crate::shadow_tree::StreamRef<'_>,
    offset: u64,
    count: u64,
) -> Option<u64> {
    if stream.sparse.is_some() {
        return None;
    }
    let end = offset.checked_add(count)?;
    if let Some(base) = stream.source_offset {
        return base.checked_add(offset);
    }
    let run = stream.source_extents.iter().find(|run| {
        run.logical_offset <= offset
            && run
                .logical_offset
                .checked_add(run.length)
                .is_some_and(|stop| end <= stop)
    })?;
    run.physical_offset?
        .checked_add(offset - run.logical_offset)
}

/// Whether opening read lanes failed for want of a resource (memory,
/// handles, a share another holder refuses), which leaves reading without
/// lanes, rather than for something that may mean the source is no longer
/// what it was frozen as (a lane's route that differs from the frozen state,
/// a failed state query, a scope that failed, access refused), which is the
/// run's failure.
fn lane_open_wants_resource(error: &io::Error) -> bool {
    // ERROR_TOO_MANY_OPEN_FILES, ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY,
    // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_NO_SYSTEM_RESOURCES,
    // ERROR_WORKING_SET_QUOTA, ERROR_COMMITMENT_LIMIT.
    error.kind() == io::ErrorKind::OutOfMemory
        || matches!(
            error.raw_os_error(),
            Some(4 | 8 | 14 | 32 | 33 | 1450 | 1453 | 1455)
        )
}

/// Lanes of the source for reading tails ahead: as many as its device
/// asks for and the ledger grants as spare memory (their buffers and
/// stacks, and a batch's bytes and lists), down to one. None where the
/// source is not read through lanes of its own, where there is no ledger,
/// where nothing is granted, or where the lanes cannot be opened or started
/// for want of a resource; then every tail is read as before. A lane that
/// cannot be opened for any other reason (its route differs from the frozen
/// state, among them) is an error, as the source's other reads would be.
pub(crate) fn tails_ahead(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    group: Option<crate::artifact_arena::ArtifactGroupPermit>,
    name: &'static str,
) -> Result<Option<LaneReads>> {
    let wanted = LaneReads::lanes_for(bytes.read_lane_depth());
    let Some(group) = group else {
        return Ok(None);
    };
    let Some((lanes, paid)) = (1..=wanted).rev().find_map(|lanes| {
        let workspace = LaneReads::workspace_bytes(lanes)?
            .checked_add(TAIL_BATCH_BYTES)?
            .checked_add((TAIL_BATCH as u64).checked_mul(TAIL_ASK_BYTES)?)?;
        group
            .arena()
            .reserve_spare_ram(workspace)
            .ok()
            .map(|paid| (lanes, paid))
    }) else {
        return Ok(None);
    };
    let lanes = match bytes.read_lanes(lanes) {
        Ok(lanes) if !lanes.is_empty() => lanes,
        Ok(_) => return Ok(None),
        Err(error) if lane_open_wants_resource(&error) => return Ok(None),
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!(
                "opening {lanes} read lanes of the source to read stream tails ahead"
            )));
        }
    };
    // Helpers that cannot be started read nothing; their lanes are closed.
    Ok(LaneReads::start(name, lanes, Some(Box::new(paid))).ok())
}

/// One read of a stream's session, through `reader`.
fn read_session<R: Read + Seek>(
    session: &mut crate::ntfs_inspect::PlainStreamRangeSession,
    reader: &mut R,
    raw: &crate::ntfs_inspect::PagedInspection,
    offset: u64,
    output: &mut [u8],
    budget: &mut crate::ntfs_inspect::StreamTransferBudget,
    direct: bool,
) -> Result<Option<crate::ntfs_inspect::DirectReadReceipt>> {
    if direct {
        Ok(Some(session.read_with_direct_receipts_domain(
            reader, raw, offset, output, budget,
        )?))
    } else {
        session.read_domain(reader, raw, offset, output, budget)?;
        Ok(None)
    }
}

/// The source as a stream's session reads it where bytes of it were read
/// ahead on a lane ([`PagedSourceByteAdapterWithScope::offer_read_ahead`]):
/// a read that lies wholly inside such bytes takes them, and every other
/// read is made by the source itself, at the same place, as before.
struct AheadReader<'r, R: Read + Seek> {
    inner: &'r mut R,
    blocks: &'r [(u64, Vec<u8>)],
    position: u64,
    // Whether `inner` stands at `position`.
    synced: bool,
}
impl<'r, R: Read + Seek> AheadReader<'r, R> {
    fn new(inner: &'r mut R, blocks: &'r [(u64, Vec<u8>)]) -> io::Result<Self> {
        let position = inner.stream_position()?;
        Ok(Self {
            inner,
            blocks,
            position,
            synced: true,
        })
    }
}
impl<R: Read + Seek> Read for AheadReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let at = self.position;
        let end = at.checked_add(output.len() as u64);
        let inside = self.blocks.iter().find(|(start, bytes)| {
            *start <= at
                && end.is_some_and(|end| {
                    start
                        .checked_add(bytes.len() as u64)
                        .is_some_and(|stop| end <= stop)
                })
        });
        if let Some((start, bytes)) = inside {
            let local = (at - start) as usize;
            output.copy_from_slice(&bytes[local..local + output.len()]);
            self.position = end.unwrap_or(at);
            self.synced = false;
            return Ok(output.len());
        }
        if !self.synced {
            self.inner.seek(SeekFrom::Start(at))?;
            self.synced = true;
        }
        let read = self.inner.read(output)?;
        self.position = at + read as u64;
        Ok(read)
    }
}
impl<R: Read + Seek> Seek for AheadReader<'_, R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if let SeekFrom::Start(at) = from {
            self.position = at;
            self.synced = false;
            return Ok(at);
        }
        if !self.synced {
            self.inner.seek(SeekFrom::Start(self.position))?;
        }
        self.position = self.inner.seek(from)?;
        self.synced = true;
        Ok(self.position)
    }
}
impl<R: Read + Seek> Drop for AheadReader<'_, R> {
    fn drop(&mut self) {
        // The source stands where the session's last read ended, as it
        // would had every read been its own.
        if !self.synced {
            let _ = self.inner.seek(SeekFrom::Start(self.position));
        }
    }
}

/// 1 MiB aligned page size for caching small MFT record reads on a frozen
/// dedicated source under `checks_once()`.
const MFT_PAGE_BYTES: u64 = 1024 * 1024;
/// Maximum cached 1 MiB pages (128 MiB cap; evicted LRU on miss or wholly via
/// `n2r_win32::evict::Evictable` when the ledger needs memory).
const MFT_CACHE_MAX_PAGES: usize = 128;
/// Only cache small metadata/MFT reads (1 KiB–4 KiB records and small headers).
const MFT_CACHE_MAX_READ: usize = 16 * 1024;

struct MftPageCache {
    // Declared before `leases` so buffers drop before their RAM leases return.
    pages: std::collections::HashMap<u64, (u64, Vec<u8>)>,
    tick: u64,
    leases: Vec<crate::ntfs_inspect::paged_storage::SourceRamLease>,
}

impl MftPageCache {
    fn new() -> Self {
        Self {
            pages: std::collections::HashMap::new(),
            tick: 0,
            leases: Vec::new(),
        }
    }
    fn get_slice(&mut self, page_start: u64, offset_in_page: usize, out: &mut [u8]) -> bool {
        if let Some((used, bytes)) = self.pages.get_mut(&page_start)
            && offset_in_page + out.len() <= bytes.len()
        {
            self.tick += 1;
            *used = self.tick;
            out.copy_from_slice(&bytes[offset_in_page..offset_in_page + out.len()]);
            return true;
        }
        false
    }
    fn take_lru_buffer(&mut self) -> Option<Vec<u8>> {
        if self.pages.len() < MFT_CACHE_MAX_PAGES {
            return None;
        }
        let (&oldest_key, _) = self.pages.iter().min_by_key(|(_, (used, _))| *used)?;
        self.pages.remove(&oldest_key).map(|(_, buf)| buf)
    }
    fn insert(
        &mut self,
        page_start: u64,
        bytes: Vec<u8>,
        lease: Option<crate::ntfs_inspect::paged_storage::SourceRamLease>,
    ) {
        self.tick += 1;
        let tick = self.tick;
        self.pages.insert(page_start, (tick, bytes));
        if let Some(lease) = lease {
            self.leases.push(lease);
        }
    }
}

struct CachedMftReader<'r, R: Read + Seek> {
    inner: &'r mut R,
    cache: &'r mut Option<n2r_win32::evict::Evictable<MftPageCache>>,
    scratch: &'r crate::ntfs_inspect::paged_storage::SourceScratch,
    byte_len: u64,
    position: u64,
    synced: bool,
}

impl<'r, R: Read + Seek> CachedMftReader<'r, R> {
    fn new(
        inner: &'r mut R,
        cache: &'r mut Option<n2r_win32::evict::Evictable<MftPageCache>>,
        scratch: &'r crate::ntfs_inspect::paged_storage::SourceScratch,
        byte_len: u64,
    ) -> io::Result<Self> {
        let position = inner.stream_position()?;
        Ok(Self {
            inner,
            cache,
            scratch,
            byte_len,
            position,
            synced: true,
        })
    }
}

impl<R: Read + Seek> Read for CachedMftReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let at = self.position;
        if !output.is_empty() && output.len() <= MFT_CACHE_MAX_READ && at < self.byte_len {
            let page_start = at / MFT_PAGE_BYTES * MFT_PAGE_BYTES;
            let page_end = page_start.saturating_add(MFT_PAGE_BYTES).min(self.byte_len);
            let read_end = at.saturating_add(output.len() as u64);
            if read_end <= page_end {
                let offset_in_page = (at - page_start) as usize;
                // 1. Fast path: cache hit.
                if let Some(evictable) = self.cache.as_ref()
                    && let Some(mut guard) = evictable.get_mut()
                    && guard.get_slice(page_start, offset_in_page, output)
                {
                    self.position = read_end;
                    self.synced = false;
                    return Ok(output.len());
                }
                // 2. Miss: try to reuse an LRU buffer if full, else lease cache RAM
                //    outside any RefCell borrow so eviction can run safely.
                let page_len = (page_end - page_start) as usize;
                let reused_buf = self
                    .cache
                    .as_ref()
                    .and_then(|ev| ev.get_mut().and_then(|mut g| g.take_lru_buffer()));
                let (mut buf, new_lease) = if let Some(mut buf) = reused_buf {
                    buf.resize(page_len, 0);
                    (buf, None)
                } else if let Ok(lease) = self.scratch.lease_cache_ram(MFT_PAGE_BYTES) {
                    let mut buf = Vec::new();
                    if buf.try_reserve_exact(page_len).is_ok() {
                        buf.resize(page_len, 0);
                        (buf, Some(lease))
                    } else {
                        (Vec::new(), None)
                    }
                } else {
                    (Vec::new(), None)
                };
                if !buf.is_empty() {
                    self.inner.seek(SeekFrom::Start(page_start))?;
                    self.inner.read_exact(&mut buf)?;
                    self.synced = false;
                    output.copy_from_slice(&buf[offset_in_page..offset_in_page + output.len()]);
                    self.position = read_end;
                    let held = self.cache.as_ref().is_some_and(|ev| ev.is_held());
                    if !held {
                        let mut fresh = MftPageCache::new();
                        fresh.insert(page_start, buf, new_lease);
                        *self.cache = Some(n2r_win32::evict::Evictable::new(fresh));
                    } else if let Some(evictable) = self.cache.as_ref()
                        && let Some(mut guard) = evictable.get_mut()
                    {
                        guard.insert(page_start, buf, new_lease);
                    }
                    return Ok(output.len());
                }
            }
        }
        if !self.synced {
            self.inner.seek(SeekFrom::Start(at))?;
            self.synced = true;
        }
        let read = self.inner.read(output)?;
        self.position = at + read as u64;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for CachedMftReader<'_, R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if let SeekFrom::Start(at) = from {
            self.position = at;
            self.synced = false;
            return Ok(at);
        }
        if !self.synced {
            self.inner.seek(SeekFrom::Start(self.position))?;
        }
        self.position = self.inner.seek(from)?;
        self.synced = true;
        Ok(self.position)
    }
}

impl<R: Read + Seek> Drop for CachedMftReader<'_, R> {
    fn drop(&mut self) {
        if !self.synced {
            let _ = self.inner.seek(SeekFrom::Start(self.position));
        }
    }
}

pub struct SourceBackedShadow<'a> {
    source: &'a mut GeneralFrozenPartition,
    shadow: &'a mut GeneralFrozenPartition,
    closing_bytes: Option<&'a mut dyn ClosingShadowBytes>,
    closing_source_bytes: Option<&'a mut dyn ClosingSourceBytes>,
    raw: &'a crate::ntfs_inspect::NtfsInspection,
    tree: &'a crate::shadow_tree::Tree,
    routes: &'a SourceBackedRoutes,
    source_before: n2r_win32::GeneralDiskState,
    shadow_before: n2r_win32::GeneralDiskState,
    budget: crate::ntfs_inspect::StreamTransferBudget,
    length: u64,
    position: u64,
    counts: ReadCounts,
    poisoned: bool,
    session: Option<crate::ntfs_inspect::PlainStreamRangeSession>,
}

impl<'a> SourceBackedShadow<'a> {
    pub fn new(
        source: &'a mut GeneralFrozenPartition,
        shadow: &'a mut GeneralFrozenPartition,
        raw: &'a crate::ntfs_inspect::NtfsInspection,
        tree: &'a crate::shadow_tree::Tree,
        routes: &'a SourceBackedRoutes,
        max_source_logical_reads: u64,
    ) -> Result<Self> {
        ensure!(
            source.binding() == &routes.pair().source
                && shadow.binding() == &routes.pair().shadow
                && source.byte_len() == shadow.byte_len(),
            "source-backed device bindings differ"
        );
        let mut events = Vec::new();
        let source_before = source.state(&mut events)?;
        let shadow_before = shadow.state(&mut events)?;
        ensure!(
            source_before.disk_attributes == 3 && shadow_before.disk_attributes == 3,
            "source-backed candidate requires both disks frozen read-only/offline"
        );
        let max_stream = tree
            .objects
            .iter()
            .flat_map(|object| object.data_streams())
            .map(|stream| stream.length)
            .max()
            .unwrap_or(1)
            .max(1);
        // A stream may have many destination routes. Resolve raw record
        // uniqueness once instead of rescanning the complete MFT inventory
        // and allocating a matches vector for every fragment of that stream.
        // Duplicates remain explicit, including duplicate records with the
        // same sequence number; only referenced records are gated below, as
        // in the original per-route reconciliation.
        let mut identities = std::collections::BTreeMap::new();
        for file in &raw.files {
            identities
                .entry(file.record_number)
                .and_modify(|identity: &mut Option<u16>| *identity = None)
                .or_insert(Some(file.sequence_number));
        }
        for route in routes.entries() {
            let object = tree
                .objects
                .get(route.object_index)
                .context("payload object absent")?;
            let stream = object
                .stream(&route.stream_name_utf16)
                .context("payload stream absent from canonical object")?;
            ensure!(
                !object.directory
                    && object.path == route.components
                    && stream.length == route.stream_length
                    && stream.sha256 == route.expected_sha256.as_deref()
                    && identities.get(&object.record_number) == Some(&Some(object.sequence_number)),
                "source-backed canonical stream identity differs"
            );
        }
        let length = shadow.byte_len();
        Ok(Self {
            source,
            shadow,
            closing_bytes: None,
            closing_source_bytes: None,
            raw,
            tree,
            routes,
            source_before,
            shadow_before,
            budget: crate::ntfs_inspect::StreamTransferBudget::new(
                max_stream,
                max_source_logical_reads,
            )?,
            length,
            position: 0,
            counts: ReadCounts::default(),
            poisoned: false,
            session: None,
        })
    }

    pub(crate) fn with_closing_bytes(mut self, bytes: &'a mut dyn ClosingShadowBytes) -> Self {
        self.closing_bytes = Some(bytes);
        self
    }

    pub(crate) fn with_closing_source_bytes(
        mut self,
        bytes: &'a mut dyn ClosingSourceBytes,
    ) -> Self {
        self.closing_source_bytes = Some(bytes);
        self
    }

    pub fn read_counts(&self) -> ReadCounts {
        self.counts
    }

    /// Compare the complete conservative selected set, storing only differing
    /// clusters. This avoids filling both a shadow and its unused reservations.
    /// Equal bytes are proved by comparison, never by guessing their purpose.
    pub fn capture_differences_to_new_file(
        self,
        plan: &crate::refs_write_set::WriteSetPlan,
        output: &std::path::Path,
        max_changed_bytes: u64,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        ensure!(
            plan.partition_bytes == self.length,
            "delta capture geometry differs"
        );
        let selected_bytes = crate::refs_hybrid::packed::required_bytes(plan, &[])?;
        let payload: Vec<_> = self
            .routes
            .entries()
            .iter()
            .map(|r| crate::refs_write_set::ByteRange {
                offset: r.target_physical_offset,
                length: r.length,
            })
            .collect();
        ensure!(
            crate::refs_write_set::payload_coverage(plan, &payload)?.all_supplied_payloads_covered,
            "delta set omits measured user payload"
        );
        let input_plan_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(plan)?));
        self.capture_difference_ranges(
            &plan.target_owned_ranges,
            selected_bytes,
            input_plan_sha256,
            output,
            max_changed_bytes,
        )
    }

    /// Complete native address-space comparison avoids relying on a metadata
    /// bitmap to prove required-byte completeness. Dirty free space can enlarge
    /// the delta; every output byte still faces the caller's hard budget.
    pub fn capture_complete_differences_to_new_file(
        self,
        output: &std::path::Path,
        max_changed_bytes: u64,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        let length = self.length;
        let selection = [crate::refs_write_set::ByteRange { offset: 0, length }];
        let identity = hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "profile":"complete-native-address-space-source-backed-v1","partition_bytes":length,"granule_bytes":4096}))?));
        self.capture_difference_ranges(&selection, length, identity, output, max_changed_bytes)
    }

    /// Compare only the listed sorted, disjoint ranges and store their differing
    /// clusters. The caller owns the claim that unlisted bytes need not match;
    /// this capture records nothing about them. `class_split` adds the
    /// non-gating [`ChangedClassCounters`] and changes nothing else.
    pub fn capture_listed_differences_to_new_file(
        self,
        selection: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        max_changed_bytes: u64,
        class_split: Option<ChangeClassSplit<'_>>,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        let mut selected_bytes = 0u64;
        for range in selection {
            selected_bytes = selected_bytes
                .checked_add(range.length)
                .context("listed selection overflow")?;
        }
        let identity = hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "profile":"listed-ranges-source-backed-v1","partition_bytes":self.length,
            "granule_bytes":4096,"ranges":selection}))?));
        self.capture_difference_ranges_with(
            selection,
            selected_bytes,
            identity,
            output,
            max_changed_bytes,
            true,
            false,
            class_split,
            None,
            None,
        )
    }

    /// Allocation-only capture with an explicitly versioned zero-eliding
    /// backing. Every changed zero granule remains in the authenticated layout
    /// and write set, but contributes no bytes to the packed file.
    pub fn capture_listed_zero_aware_differences_to_new_file(
        self,
        selection: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        max_changed_bytes: u64,
        class_split: Option<ChangeClassSplit<'_>>,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        let selected_bytes = selection.iter().try_fold(0u64, |total, range| {
            total
                .checked_add(range.length)
                .context("listed selection overflow")
        })?;
        let identity = hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "profile":"listed-ranges-source-backed-zero-v2","partition_bytes":self.length,
            "granule_bytes":4096,"ranges":selection}))?));
        self.capture_difference_ranges_with(
            selection,
            selected_bytes,
            identity,
            output,
            max_changed_bytes,
            true,
            true,
            class_split,
            None,
            None,
        )
    }

    /// Encode selected relocated payload as references to old bytes that the
    /// journal will already own. Every referenced source granule must be in an
    /// earlier captured changed range; retained or future source bytes remain
    /// literal. Raw frozen source bytes are compared with the logical candidate
    /// before any reference is emitted. Zero replacements retain precedence.
    pub fn capture_listed_source_references_to_new_file(
        self,
        selection: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        max_changed_bytes: u64,
        class_split: Option<ChangeClassSplit<'_>>,
        copies: &[crate::payload_copy_plan::CopySpan],
    ) -> Result<DifferenceCapture> {
        self.capture_listed_source_references(
            selection,
            output,
            max_changed_bytes,
            class_split,
            copies,
            None,
        )
    }

    /// Capacity-pinned selected capture. The caller's live guard rechecks the
    /// exact backing volume's available space before every changed run,
    /// including zero/copy runs that enlarge only the future journal.
    pub fn capture_listed_source_references_to_new_file_with_budget(
        self,
        selection: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        budget: CaptureBudget,
        class_split: Option<ChangeClassSplit<'_>>,
        copies: &[crate::payload_copy_plan::CopySpan],
        guard: &mut dyn FnMut(CaptureProgress) -> Result<()>,
    ) -> Result<DifferenceCapture> {
        budget.validate(self.length)?;
        self.capture_listed_source_references(
            selection,
            output,
            budget.max_changed_bytes,
            class_split,
            copies,
            Some(CaptureCapacity { budget, guard }),
        )
    }

    fn capture_listed_source_references(
        self,
        selection: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        max_changed_bytes: u64,
        class_split: Option<ChangeClassSplit<'_>>,
        copies: &[crate::payload_copy_plan::CopySpan],
        capacity: Option<CaptureCapacity<'_>>,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        let mut selected_bytes = 0u64;
        let mut prior_end = 0u64;
        for range in selection {
            let end = range
                .offset
                .checked_add(range.length)
                .context("source-reference selection overflow")?;
            ensure!(
                range.length > 0
                    && range.length.is_multiple_of(4096)
                    && range.offset.is_multiple_of(4096)
                    && range.offset >= prior_end
                    && end <= self.length,
                "invalid source-reference selection"
            );
            prior_end = end;
            selected_bytes = selected_bytes
                .checked_add(range.length)
                .context("listed selection overflow")?;
        }
        let mut prior_end = 0u64;
        for copy in copies {
            let destination_end = copy
                .destination_offset
                .checked_add(copy.length)
                .context("copy destination overflow")?;
            let source_end = copy
                .source_offset
                .checked_add(copy.length)
                .context("copy source overflow")?;
            ensure!(
                copy.length > 0
                    && copy.length.is_multiple_of(4096)
                    && copy.destination_offset.is_multiple_of(4096)
                    && copy.source_offset.is_multiple_of(4096)
                    && copy.destination_offset >= prior_end
                    && destination_end <= self.length
                    && source_end <= self.length,
                "invalid source-reference copy spans"
            );
            prior_end = destination_end;
        }
        let identity = hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "profile":"listed-ranges-source-backed-copy-v3","partition_bytes":self.length,
            "granule_bytes":4096,"ranges":selection,
            "copies":copies.iter().map(|copy| (copy.destination_offset, copy.source_offset, copy.length)).collect::<Vec<_>>()
        }))?));
        self.capture_difference_ranges_with(
            selection,
            selected_bytes,
            identity,
            output,
            max_changed_bytes,
            true,
            true,
            class_split,
            Some(copies),
            capacity,
        )
    }

    /// Retrospective planning over a coarse selection: compare the original
    /// bytes with this candidate view only inside `coarse` and return the
    /// differing granules as a selected plan, with the view's read counts and
    /// the original bytes read. Nothing outside `coarse` is read. This grants
    /// nothing and does not replace the complete capture.
    pub fn plan_changed_granules(
        mut self,
        coarse: &[crate::selected_journal::SelectedRange],
        max_selected_bytes: u64,
        max_journal_bytes: u64,
    ) -> Result<(crate::selected_journal::SelectedPlan, ReadCounts, u64)> {
        use crate::selected_journal as sj;
        let length = self.length;
        sj::validate_coarse(length, coarse)?;
        let mut original = vec![0u8; NATIVE_CAPTURE_BYTES];
        let mut candidate = vec![0u8; NATIVE_CAPTURE_BYTES];
        let mut runs = Vec::new();
        let mut original_bytes = 0u64;
        for range in coarse {
            let mut done = 0;
            while done < range.length {
                let count = (range.length - done).min(original.len() as u64) as usize;
                let at = range.offset + done;
                self.seek(SeekFrom::Start(at))?;
                self.read_exact(&mut candidate[..count])?;
                self.source.seek(SeekFrom::Start(at))?;
                self.source.read_exact(&mut original[..count])?;
                sj::record_differing_granules(
                    &mut runs,
                    at,
                    &original[..count],
                    &candidate[..count],
                )?;
                original_bytes += count as u64;
                done += count as u64;
            }
        }
        let counts = self.finish()?;
        let plan = sj::finish_changed_plan(length, runs, max_selected_bytes, max_journal_bytes)?;
        Ok((plan, counts, original_bytes))
    }

    fn capture_difference_ranges(
        self,
        selection: &[crate::refs_write_set::ByteRange],
        selected_bytes: u64,
        input_plan_sha256: String,
        output: &std::path::Path,
        max_changed_bytes: u64,
    ) -> Result<DifferenceCapture> {
        self.capture_difference_ranges_with(
            selection,
            selected_bytes,
            input_plan_sha256,
            output,
            max_changed_bytes,
            false,
            false,
            None,
            None,
            None,
        )
    }

    /// `chunk_digests` selects the cheap selected-digest construction (see
    /// [`SelectedDigest`]); captures whose digests are recomputed later keep
    /// the framed SHA-256 stream.
    #[allow(clippy::too_many_arguments)]
    fn capture_difference_ranges_with(
        mut self,
        selection: &[crate::refs_write_set::ByteRange],
        selected_bytes: u64,
        input_plan_sha256: String,
        output: &std::path::Path,
        max_changed_bytes: u64,
        chunk_digests: bool,
        zero_payloads: bool,
        class_split: Option<ChangeClassSplit<'_>>,
        copies: Option<&[crate::payload_copy_plan::CopySpan]>,
        mut capacity: Option<CaptureCapacity<'_>>,
    ) -> Result<DifferenceCapture> {
        use crate::refs_hybrid::delta::{ChangedRange, DeltaLayout};
        use sha2::{Digest, Sha256};
        use std::io::Write;
        let source_free_mode = capacity.as_ref().is_some_and(|capacity| {
            capacity
                .budget
                .selected_capacity_policy
                .allows_source_free()
        });
        let allocated = if source_free_mode {
            let allocated = class_split.and_then(|split| split.ntfs_allocated).context(
                "source-free capture requires a complete reconciled NTFS allocation map",
            )?;
            let mut prior_end = 0;
            for &(offset, length) in allocated {
                let end = offset
                    .checked_add(length)
                    .context("NTFS allocation overflow")?;
                ensure!(
                    length > 0 && offset >= prior_end && end <= self.length,
                    "source-free allocation map overlaps or escapes its partition"
                );
                prior_end = end;
            }
            for copy in
                copies.context("source-free capture requires reference-aware construction")?
            {
                let end = copy
                    .source_offset
                    .checked_add(copy.length)
                    .context("COPY source overflow")?;
                let mut cursor = copy.source_offset;
                let mut index =
                    allocated.partition_point(|&(offset, length)| offset + length <= cursor);
                while cursor < end {
                    let &(offset, length) = allocated
                        .get(index)
                        .context("COPY source is outside reconciled NTFS allocations")?;
                    ensure!(
                        offset <= cursor && cursor < offset + length,
                        "COPY source crosses a source-free allocation gap"
                    );
                    cursor = end.min(offset + length);
                    index += 1;
                }
            }
            Some(allocated)
        } else {
            None
        };
        let is_source_free = |offset: u64| {
            allocated.is_some_and(|allocated| {
                if offset < 4096 {
                    return false;
                }
                let index = allocated.partition_point(|&(start, length)| start + length <= offset);
                allocated
                    .get(index)
                    .is_none_or(|&(start, _)| start >= offset + 4096)
            })
        };
        if let Some(capacity) = &mut capacity {
            ensure!(
                capacity.budget.selected_capacity_policy.is_conservative()
                    || (copies.is_some()
                        && zero_payloads
                        && chunk_digests
                        && capacity.budget.max_changed_bytes == max_changed_bytes),
                "actual-old-zero capacity requires the complete reference-aware capture"
            );
            (capacity.guard)(capacity.budget.assess(0, 0, 0, 0, 0, 0)?)
                .context("capture capacity guard refused before backing creation")?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() == 0,
            "delta output must be a new ordinary file"
        );
        // One native read can satisfy each full image chunk instead of sixteen
        // 64 KiB requests. Keep these fixed-size buffers off the thread stack;
        // the exact 4 KiB comparison, budget and output loop is unchanged.
        let mut original = vec![0u8; NATIVE_CAPTURE_BYTES];
        let mut candidate = vec![0u8; NATIVE_CAPTURE_BYTES];
        // Allocate the fallback comparison buffer only if observed direct-read
        // coverage is missing. Its original full comparison remains unchanged.
        let mut copy_check: Option<Vec<u8>> = None;
        let mut source_digest = if chunk_digests {
            SelectedDigest::chunks()
        } else {
            SelectedDigest::Stream(crate::retained_compare::stream_digest::StreamDigest::new(
                true,
            )?)
        };
        let mut source_raw = if selection.len() == 1
            && selection[0].offset == 0
            && selection[0].length == self.length
            && selected_bytes == self.length
        {
            Some(n2r_win32::sha256_native::Sha256::new()?)
        } else {
            None
        };
        // Hash the candidate in parallel with source comparison on machines
        // with spare CPUs; the worker receives precisely the same framed bytes.
        let mut candidate_digest = if chunk_digests {
            SelectedDigest::chunks()
        } else {
            SelectedDigest::Overlapped(crate::retained_compare::digest_pipeline::Overlapped::new(
                NATIVE_CAPTURE_BYTES,
            )?)
        };
        let mut packed_digest = Sha256::new();
        let mut changed = 0u64;
        // Whole-record credit, updated only after an accepted run. Extending
        // a zero record with nonzero bytes revokes its entire prior credit;
        // there is no per-run scan of the accumulated interval table.
        let mut old_zero_bytes = 0u64;
        let mut source_free_bytes = 0u64;
        let mut previous_source_free = false;
        let mut packed = 0u64;
        let mut compared = 0u64;
        let mut ranges: Vec<ChangedRange> = Vec::new();
        let routes = self.routes;
        let mut classes = class_split.map(|split| ChangeClassifier::new(split, routes.entries()));
        let mut prefetch =
            OriginalPrefetch::for_partition(self.source, selection, NATIVE_CAPTURE_BYTES)?;
        for range in selection {
            let offset = range.offset.to_le_bytes();
            let length = range.length.to_le_bytes();
            source_digest.frame(&offset)?;
            source_digest.frame(&length)?;
            candidate_digest.frame(&offset)?;
            candidate_digest.frame(&length)?;
            let mut done = 0;
            while done < range.length {
                let count = (range.length - done).min(original.len() as u64) as usize;
                let at = range.offset + done;
                let candidate_chunk = self.read_capture_chunk(
                    at,
                    &mut candidate[..count],
                    copies.is_some_and(|copies| !copies.is_empty()),
                )?;
                let candidate = candidate_chunk.bytes();
                let prefetched = match &mut prefetch {
                    Some(prefetch) => Some(prefetch.next(at, count)?.bytes),
                    None => {
                        self.source.seek(SeekFrom::Start(at))?;
                        self.source.read_exact(&mut original[..count])?;
                        None
                    }
                };
                let original: &[u8] = prefetched.as_deref().unwrap_or(&original[..count]);
                if let Some(observer) = &mut self.closing_source_bytes {
                    observer.observe_original(self.source, at, original)?;
                }
                source_digest.chunk(original)?;
                if let Some(digest) = &mut source_raw {
                    digest.update(original)?;
                }
                candidate_digest.chunk(&candidate[..count])?;
                let mut offset = 0;
                while offset < count {
                    if original[offset..offset + 4096] == candidate[offset..offset + 4096] {
                        offset += 4096;
                        continue;
                    }
                    // Pack consecutive changed clusters in one write. Keep
                    // the budget boundary at a cluster: if only part of a
                    // run fits, write that prefix and refuse the next cluster
                    // exactly as the original per-cluster loop did.
                    let new_is_zero = zero_payloads
                        && candidate[offset..offset + 4096]
                            .iter()
                            .all(|&byte| byte == 0);
                    let copy_source_offset = if new_is_zero {
                        None
                    } else {
                        copies.and_then(|copies| {
                            captured_copy_source(copies, &ranges, at + offset as u64)
                        })
                    };
                    let free_destination = is_source_free(at + offset as u64);
                    let old_granule_zero = source_free_mode
                        && original[offset..offset + 4096]
                            .iter()
                            .all(|&byte| byte == 0);
                    let mut end = offset + 4096;
                    while end < count
                        && original[end..end + 4096] != candidate[end..end + 4096]
                        && (!source_free_mode
                            || (is_source_free(at + end as u64) == free_destination
                                && original[end..end + 4096].iter().all(|&byte| byte == 0)
                                    == old_granule_zero))
                        && (!zero_payloads
                            || candidate[end..end + 4096].iter().all(|&byte| byte == 0)
                                == new_is_zero)
                        && (if new_is_zero {
                            None
                        } else {
                            copies.and_then(|copies| {
                                captured_copy_source(copies, &ranges, at + end as u64)
                            })
                        }) == copy_source_offset.map(|source| source + (end - offset) as u64)
                    {
                        end += 4096;
                    }
                    let allowed = max_changed_bytes.saturating_sub(changed) / 4096;
                    if allowed == 0 {
                        // Same refusal; the refused run joins the class split
                        // first so the split covers every granule examined.
                        if let Some(classes) = &mut classes {
                            classes.record(
                                at + offset as u64,
                                &original[offset..end],
                                &candidate[offset..end],
                            );
                        }
                        let refusal = BudgetRefusal {
                            max_changed_bytes,
                            changed_bytes_written: changed,
                            refused_run_bytes: (end - offset) as u64,
                            compared_bytes_through_refused_run: compared.saturating_add(end as u64),
                            selected_bytes,
                        };
                        return Err(budget_refusal(
                            output,
                            &refusal,
                            classes.as_ref().map(|c| &c.counters),
                        ));
                    }
                    let clusters =
                        usize::try_from(u64::try_from((end - offset) / 4096)?.min(allowed))?;
                    let bytes = clusters * 4096;
                    // Only allocation reference-aware captures classify actual
                    // old bytes. Keep existing boundaries; the whole range is
                    // eligible only if every accepted byte is observed zero.
                    let old_is_zero = copies.is_some()
                        && original[offset..offset + bytes]
                            .iter()
                            .all(|&byte| byte == 0);
                    let next = changed
                        .checked_add(bytes as u64)
                        .context("delta byte count overflow")?;
                    let address = at + offset as u64;
                    let extends_previous = ranges.last().is_some_and(|r| {
                        r.offset + r.length == address
                            && (!source_free_mode
                                || (previous_source_free == free_destination
                                    && r.old_is_zero == old_is_zero))
                            && r.new_is_zero == new_is_zero
                            && match (r.copy_source_offset, copy_source_offset) {
                                (None, None) => true,
                                (Some(previous), Some(current)) => previous + r.length == current,
                                _ => false,
                            }
                    });
                    let previous_length = if extends_previous {
                        ranges
                            .last()
                            .context("extended capture range absent")?
                            .length
                    } else {
                        0
                    };
                    let next_range_length = previous_length
                        .checked_add(bytes as u64)
                        .context("capture coalesced range length overflow")?;
                    let next_old_zero_bytes = if extends_previous {
                        let previous = ranges.last().context("extended capture range absent")?;
                        if previous.old_is_zero {
                            if old_is_zero {
                                old_zero_bytes
                                    .checked_add(bytes as u64)
                                    .context("capture old-zero total overflow")?
                            } else {
                                old_zero_bytes
                                    .checked_sub(previous.length)
                                    .context("capture old-zero revoked credit underflow")?
                            }
                        } else {
                            old_zero_bytes
                        }
                    } else if old_is_zero {
                        old_zero_bytes
                            .checked_add(bytes as u64)
                            .context("capture old-zero total overflow")?
                    } else {
                        old_zero_bytes
                    };
                    let next_source_free_bytes = if free_destination && !old_is_zero {
                        source_free_bytes
                            .checked_add(bytes as u64)
                            .context("capture source-free byte total overflow")?
                    } else {
                        source_free_bytes
                    };
                    if let Some(capacity) = &mut capacity {
                        let range_count = ranges
                            .len()
                            .checked_add(usize::from(!extends_previous))
                            .context("capture range count overflow")?;
                        let append = if !new_is_zero && copy_source_offset.is_none() {
                            bytes as u64
                        } else {
                            0
                        };
                        let progress = capacity.budget.assess(
                            next,
                            next_old_zero_bytes,
                            next_source_free_bytes,
                            packed,
                            append,
                            range_count,
                        )?;
                        (capacity.guard)(progress).context(
                            "capture capacity guard refused before accepting changed bytes",
                        )?;
                    }
                    if !extends_previous {
                        ensure!(
                            ranges.len() < 65536,
                            "delta range budget exhausted before output write"
                        );
                    }
                    if let Some(source_offset) = copy_source_offset {
                        if candidate_chunk.covers_copy(offset, source_offset, bytes) {
                            self.counts.source_reference_bytes_reused = self
                                .counts
                                .source_reference_bytes_reused
                                .checked_add(bytes as u64)
                                .context("reused source reference accounting overflow")?;
                        } else {
                            let check =
                                copy_check.get_or_insert_with(|| vec![0u8; NATIVE_CAPTURE_BYTES]);
                            self.source.seek(SeekFrom::Start(source_offset))?;
                            self.source.read_exact(&mut check[..bytes])?;
                            self.counts.source_reference_bytes = self
                                .counts
                                .source_reference_bytes
                                .checked_add(bytes as u64)
                                .context("source reference read accounting overflow")?;
                            ensure!(
                                check[..bytes] == candidate[offset..offset + bytes],
                                "raw source reference differs from logical candidate"
                            );
                        }
                    }
                    if let Some(classes) = &mut classes {
                        classes.record(
                            address,
                            &original[offset..offset + bytes],
                            &candidate[offset..offset + bytes],
                        );
                    }
                    let range_packed_offset = packed;
                    if !new_is_zero && copy_source_offset.is_none() {
                        file.write_all(&candidate[offset..offset + bytes])?;
                        packed_digest.update(&candidate[offset..offset + bytes]);
                        packed = packed
                            .checked_add(bytes as u64)
                            .context("delta packed byte count overflow")?;
                    }
                    if extends_previous {
                        let previous =
                            ranges.last_mut().context("extended capture range absent")?;
                        previous.old_is_zero &= old_is_zero;
                        previous.length = next_range_length;
                    } else {
                        ranges.push(ChangedRange {
                            offset: address,
                            length: bytes as u64,
                            packed_offset: range_packed_offset,
                            new_is_zero,
                            old_is_zero,
                            copy_source_offset,
                        });
                    }
                    changed = next;
                    old_zero_bytes = next_old_zero_bytes;
                    source_free_bytes = next_source_free_bytes;
                    previous_source_free = free_destination;
                    offset += bytes;
                }
                if let (Some(prefetch), Some(buffer)) = (&prefetch, prefetched) {
                    prefetch.recycle(buffer);
                }
                done += count as u64;
                compared = compared
                    .checked_add(count as u64)
                    .context("delta comparison overflow")?;
            }
        }
        if let Some(prefetch) = prefetch {
            prefetch.finish()?;
        }
        file.sync_all()?;
        ensure!(
            compared == selected_bytes && file.metadata()?.len() == packed,
            "delta comparison/output accounting differs"
        );
        let layout = if copies.is_some() {
            DeltaLayout::new_reference_aware(self.length, changed, packed, ranges)?
        } else if zero_payloads {
            DeltaLayout::new_zero_aware(self.length, changed, packed, ranges)?
        } else {
            DeltaLayout::new(self.length, changed, ranges)?
        };
        let read_counts = self.finish()?;
        let source_raw_sha256 = match source_raw {
            Some(digest) => Some(hex::encode(digest.finish()?)),
            None => None,
        };
        Ok(DifferenceCapture {
            layout,
            selected_bytes_compared: compared,
            equal_selected_bytes: compared - changed,
            read_counts,
            selected_digest: if chunk_digests {
                SELECTED_CHUNK_DIGEST
            } else {
                "sha256-framed-stream"
            },
            source_selected_sha256: hex::encode(source_digest.finish()?),
            candidate_selected_sha256: hex::encode(candidate_digest.finish()?),
            packed_sha256: hex::encode(packed_digest.finalize()),
            input_plan_sha256,
            conversion_qualified: false,
            changed_classes: classes.map(|c| c.counters),
            source_raw_sha256,
        })
    }

    /// Capture selected bytes directly from this source-backed view. Retained
    /// payload is compared against the actual original physical bytes before
    /// it is omitted. The output is a fresh ordinary file, never a device.
    /// A failed capture remains incomplete and returns no completion receipt.
    pub fn capture_to_new_file(
        mut self,
        plan: &crate::refs_write_set::WriteSetPlan,
        retained: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        max_packed_bytes: u64,
    ) -> Result<serde_json::Value> {
        use sha2::{Digest, Sha256};
        ensure!(
            plan.partition_bytes == self.length,
            "candidate capture geometry differs"
        );
        let required = crate::refs_hybrid::packed::required_bytes(plan, retained)?;
        ensure!(
            required <= max_packed_bytes,
            "compact capture exceeds explicit output budget"
        );
        // Every routed full-cluster user allocation must belong to the proposed
        // target write set, even if a later proof will allow omitting its bytes.
        let payload: Vec<_> = self
            .routes
            .entries()
            .iter()
            .map(|r| crate::refs_write_set::ByteRange {
                offset: r.target_physical_offset,
                length: r.length,
            })
            .collect();
        let coverage = crate::refs_write_set::payload_coverage(plan, &payload)?;
        ensure!(
            coverage.all_supplied_payloads_covered,
            "write set omits measured payload allocation"
        );
        let mut expected = [0u8; 65536];
        let mut original = [0u8; 65536];
        let mut compared = 0u64;
        let mut retained_digest = Sha256::new();
        retained_digest.update(b"n2r-source-backed-retained-comparison-v1\0");
        for range in retained {
            retained_digest.update(range.offset.to_le_bytes());
            retained_digest.update(range.length.to_le_bytes());
            let mut done = 0;
            while done < range.length {
                let position = range.offset + done;
                let index = self
                    .routes
                    .entries()
                    .partition_point(|r| r.target_physical_offset + r.length <= position);
                let route = self
                    .routes
                    .entries()
                    .get(index)
                    .context("retained payload route absent")?;
                ensure!(
                    route.target_physical_offset <= position,
                    "retained range crosses nonpayload bytes"
                );
                let count = (range.length - done)
                    .min(route.target_physical_offset + route.length - position)
                    .min(expected.len() as u64) as usize;
                self.seek(SeekFrom::Start(position))?;
                self.read_exact(&mut expected[..count])?;
                self.source.seek(SeekFrom::Start(position))?;
                self.source.read_exact(&mut original[..count])?;
                ensure!(
                    expected[..count] == original[..count],
                    "retained physical bytes differ from logical NTFS payload"
                );
                retained_digest.update(&expected[..count]);
                compared = compared
                    .checked_add(count as u64)
                    .context("retained comparison count overflow")?;
                done += count as u64;
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() == 0,
            "compact output must be a fresh ordinary file"
        );
        let packed =
            crate::refs_hybrid::packed::pack_with_retained(&mut self, &mut file, plan, retained)?;
        file.sync_all()?;
        ensure!(
            file.metadata()?.len() == required && packed.packed_bytes == required,
            "durable compact output length differs"
        );
        let counts = self.finish()?;
        Ok(
            serde_json::json!({"kind":"source-backed-compact-candidate","packed":packed,
            "read_counts":counts,"retained_physical_bytes_compared":compared,
            "retained_comparison_sha256":hex::encode(retained_digest.finalize()),
            "payload_shadow_initialization_bytes":0,"source_payload_writes":0,
            "frozen_required_byte_graph_verified":false,"conversion_qualified":false}),
        )
    }

    /// A consumer must require this bracket after capture. It does not prove
    /// required-byte graph completeness or authenticate a new filesystem.
    pub fn finish(mut self) -> Result<ReadCounts> {
        ensure!(!self.poisoned, "failed source-backed reader cannot finish");
        if let Some(session) = self.session.take() {
            session.finish(self.source, self.raw)?;
        }
        let mut events = Vec::new();
        ensure!(
            self.source.state(&mut events)? == self.source_before
                && self.shadow.state(&mut events)? == self.shadow_before,
            "source-backed disk state changed around capture"
        );
        ensure!(
            self.budget.reserved_bytes() == self.counts.source_logical_bytes,
            "source-backed read accounting differs"
        );
        Ok(self.counts)
    }

    fn read_capture_chunk<'buf>(
        &mut self,
        at: u64,
        output: &'buf mut [u8],
        observe_direct: bool,
    ) -> Result<CandidateChunk<'buf>> {
        ensure!(
            !self.poisoned && output.len() <= NATIVE_CAPTURE_BYTES,
            "candidate capture chunk is poisoned or exceeds its bound"
        );
        self.seek(SeekFrom::Start(at))?;
        let mut done = 0usize;
        let mut reads = CandidateReadSpans::new();
        while done < output.len() {
            let read = self.read_inner_observed(&mut output[done..], observe_direct);
            let (count, receipt) = match read {
                Ok(read) => read,
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            };
            if count == 0 {
                self.poisoned = true;
                anyhow::bail!("candidate capture chunk ended before its requested bytes");
            }
            if let Some(receipt) = receipt {
                reads.append(done, count, &receipt);
            }
            done = done
                .checked_add(count)
                .context("candidate chunk byte total overflow")?;
        }
        Ok(CandidateChunk {
            bytes: output,
            reads,
        })
    }

    fn read_inner(&mut self, output: &mut [u8]) -> Result<usize> {
        Ok(self.read_inner_observed(output, false)?.0)
    }

    fn read_inner_observed(
        &mut self,
        output: &mut [u8],
        observe_direct: bool,
    ) -> Result<(usize, Option<crate::ntfs_inspect::DirectReadReceipt>)> {
        if output.is_empty() || self.position == self.length {
            return Ok((0, None));
        }
        let index = self
            .routes
            .entries()
            .partition_point(|r| r.target_physical_offset + r.length <= self.position);
        let route = self.routes.entries().get(index);
        let in_payload = route.is_some_and(|r| r.target_physical_offset <= self.position);
        let boundary = match route {
            Some(r) if in_payload => r.target_physical_offset + r.length,
            Some(r) => r.target_physical_offset,
            None => self.length,
        };
        // A logical source read must stay inside the NTFS session's read
        // bound; native shadow bytes use the aligned adapter batch. Both stop
        // at the next payload boundary and logical EOF.
        let limit = if in_payload {
            LOGICAL_SOURCE_READ_BYTES
        } else {
            NATIVE_CAPTURE_BYTES
        };
        let count = (boundary - self.position)
            .min(output.len() as u64)
            .min(limit as u64) as usize;
        let receipt =
            if in_payload {
                let route = route.unwrap();
                let object = &self.tree.objects[route.object_index];
                let stream = object
                    .stream(&route.stream_name_utf16)
                    .context("source-backed sparse stream absent")?;
                let logical = route.logical_offset + self.position - route.target_physical_offset;
                if self.session.as_ref().is_none_or(|s| {
                    !s.matches_stream(object.record_number, &route.stream_name_utf16)
                }) {
                    if let Some(old) = self.session.take() {
                        old.finish(self.source, self.raw)?;
                    }
                    self.session = Some(if stream.sparse.is_some() {
                        crate::ntfs_inspect::PlainStreamRangeSession::open_sparse_named(
                            self.source,
                            self.raw,
                            object.record_number,
                            &route.stream_name_utf16,
                            route.stream_length,
                        )?
                    } else {
                        crate::ntfs_inspect::PlainStreamRangeSession::open_named(
                            self.source,
                            self.raw,
                            object.record_number,
                            &route.stream_name_utf16,
                            route.stream_length,
                        )?
                    });
                }
                let session = self.session.as_mut().unwrap();
                ensure!(
                    session.stream_length() == route.stream_length
                        && session.expected_sha256() == route.expected_sha256.as_deref(),
                    "source-backed read differs from bound stream"
                );
                let receipt = if observe_direct {
                    Some(session.read_with_direct_receipts(
                        self.source,
                        self.raw,
                        logical,
                        &mut output[..count],
                        &mut self.budget,
                    )?)
                } else {
                    session.read(
                        self.source,
                        self.raw,
                        logical,
                        &mut output[..count],
                        &mut self.budget,
                    )?;
                    None
                };
                self.counts.source_logical_bytes = self
                    .counts
                    .source_logical_bytes
                    .checked_add(count as u64)
                    .context("source-backed source accounting overflow")?;
                receipt
            } else {
                let reused = match &mut self.closing_bytes {
                    Some(bytes) => {
                        bytes.read_shadow_exact(self.shadow, self.position, &mut output[..count])?
                    }
                    None => {
                        self.shadow.seek(SeekFrom::Start(self.position))?;
                        self.shadow.read_exact(&mut output[..count])?;
                        0
                    }
                };
                ensure!(
                    reused <= count as u64,
                    "closing shadow reuse exceeds actual supply"
                );
                self.counts.shadow_bytes = self
                    .counts
                    .shadow_bytes
                    .checked_add(count as u64 - reused)
                    .context("source-backed shadow accounting overflow")?;
                self.counts.shadow_bytes_reused_from_closing = self
                    .counts
                    .shadow_bytes_reused_from_closing
                    .checked_add(reused)
                    .context("closing shadow reuse accounting overflow")?;
                None
            };
        self.position += count as u64;
        Ok((count, receipt))
    }
}

impl Read for SourceBackedShadow<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(io::Error::other("poisoned source-backed candidate"));
        }
        match self.read_inner(output) {
            Ok(count) => Ok(count),
            Err(error) => {
                self.poisoned = true;
                Err(io::Error::other(error))
            }
        }
    }
}

impl Seek for SourceBackedShadow<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if self.poisoned {
            return Err(io::Error::other("poisoned source-backed candidate"));
        }
        let next = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.length) + i128::from(v),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source-backed seek escapes partition",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod ahead_reader_tests {
    use super::*;

    /// Only a lane that could not be had for want of a resource leaves the
    /// tails read without lanes; a lane whose route differs from the frozen
    /// state, or any other failure, is the run's.
    #[test]
    fn only_a_resource_failure_leaves_reading_without_lanes() {
        let memory = io::Error::new(io::ErrorKind::OutOfMemory, "aligned allocation failed");
        assert!(lane_open_wants_resource(&memory));
        assert!(lane_open_wants_resource(&io::Error::from_raw_os_error(32)));
        assert!(lane_open_wants_resource(&io::Error::from_raw_os_error(
            1450
        )));
        let route = io::Error::new(io::ErrorKind::InvalidData, "frozen read lane route differs");
        assert!(!lane_open_wants_resource(&route));
        assert!(!lane_open_wants_resource(&io::Error::from_raw_os_error(5)));
        assert!(!lane_open_wants_resource(&io::Error::other(
            "failed frozen source read scope cannot open read lanes"
        )));
    }

    /// A read that lies wholly inside bytes read ahead takes them; any other
    /// is made by the source itself at the same place, and the source is
    /// left where the last read ended.
    #[test]
    fn only_a_read_wholly_inside_bytes_read_ahead_takes_them() {
        let disk: Vec<u8> = (0..65_536u32).map(|n| (n % 251) as u8).collect();
        let mut source = io::Cursor::new(disk.clone());
        // What a lane read at 8192, marked so that it can be told apart.
        let blocks = vec![(8192u64, vec![0xAA; 4096])];
        let mut reader = AheadReader::new(&mut source, &blocks).unwrap();
        let mut output = [0u8; 1024];
        reader.seek(SeekFrom::Start(9000)).unwrap();
        reader.read_exact(&mut output).unwrap();
        assert_eq!(output, [0xAA; 1024], "inside: taken from the read ahead");
        reader.seek(SeekFrom::Start(12_000)).unwrap();
        reader.read_exact(&mut output).unwrap();
        assert_eq!(
            &output[..],
            &disk[12_000..13_024],
            "across its end: the source"
        );
        reader.seek(SeekFrom::Start(100)).unwrap();
        reader.read_exact(&mut output).unwrap();
        assert_eq!(&output[..], &disk[100..1124], "outside: the source");
        reader.seek(SeekFrom::Start(8192)).unwrap();
        reader.read_exact(&mut output).unwrap();
        drop(reader);
        assert_eq!(source.position(), 8192 + 1024);
    }
}
