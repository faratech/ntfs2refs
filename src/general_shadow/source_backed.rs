//! Read-only candidate for compact capture: metadata/tails come from a frozen
//! shadow, full-cluster payload comes from logical NTFS reads at measured ReFS
//! destinations. No payload-sized image or raw source writer is constructed.
//! Frozen metadata-graph reconciliation is still required before cutover.
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
    /// Raw equality checks proving an omitted reference, separate from the
    /// logical candidate reads and their stream-transfer budget.
    #[serde(skip_serializing_if = "is_zero")]
    pub source_reference_bytes: u64,
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
                    .is_some_and(|n| self.max_changed_bytes <= n)
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
        let journal = changed
            .checked_add(projected_literal)
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
        })
    }
}

struct CaptureCapacity<'g> {
    budget: CaptureBudget,
    guard: &'g mut dyn FnMut(CaptureProgress) -> Result<()>,
}

const SELECTED_CHUNK_DIGEST: &str = "sha256-over-frames-and-xxh3-128-per-compared-chunk";

/// Reads a capture's original (source) chunks through a second frozen-source
/// handle, one chunk ahead of the comparison, when the device takes more than
/// one outstanding read. The chunk sequence equals the comparison loop's.
struct OriginalPrefetch {
    filled: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    free: std::sync::mpsc::SyncSender<Vec<u8>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl OriginalPrefetch {
    fn start(
        source: &GeneralFrozenPartition,
        selection: &[crate::refs_write_set::ByteRange],
    ) -> Result<Option<Self>> {
        if source.io_profile().queue_depth < 2 {
            return Ok(None);
        }
        let Some(mut lane) = source.read_lanes(1, &mut Vec::new())?.pop() else {
            return Ok(None);
        };
        // Retain the selection, not one descriptor for every 4 MiB on the
        // volume. The worker expands each range in exactly the comparison's
        // order, keeping schedule memory proportional to range count even for
        // a complete-address-space capture on a very large volume.
        let selection = selection.to_vec();
        let (filled_tx, filled) = std::sync::mpsc::sync_channel(2);
        let (free, free_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(3);
        for _ in 0..3 {
            let _ = free.send(vec![0u8; NATIVE_CAPTURE_BYTES]);
        }
        let worker = std::thread::Builder::new()
            .name("n2r-original-prefetch".into())
            .spawn(move || {
                for range in selection {
                    let mut done = 0;
                    while done < range.length {
                        let count = (range.length - done).min(NATIVE_CAPTURE_BYTES as u64);
                        let Ok(mut buffer) = free_rx.recv() else {
                            return;
                        };
                        buffer.resize(count as usize, 0);
                        let result = lane
                            .seek(SeekFrom::Start(range.offset + done))
                            .and_then(|_| lane.read_exact(&mut buffer))
                            .map(|_| buffer);
                        let stop = result.is_err();
                        if filled_tx.send(result).is_err() || stop {
                            return;
                        }
                        done += count;
                    }
                }
            })?;
        Ok(Some(Self {
            filled,
            free,
            worker: Some(worker),
        }))
    }

    fn next(&mut self, count: usize) -> Result<Vec<u8>> {
        let buffer = self
            .filled
            .recv()
            .map_err(|_| anyhow::anyhow!("original prefetch stopped early"))??;
        ensure!(buffer.len() == count, "original prefetch chunk differs");
        Ok(buffer)
    }

    fn recycle(&self, buffer: Vec<u8>) {
        let _ = self.free.send(buffer);
    }

    fn finish(mut self) -> Result<()> {
        ensure!(
            self.filled.try_recv().is_err(),
            "original prefetch read beyond the comparison"
        );
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("original prefetch panicked"))?;
        }
        Ok(())
    }
}

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

pub struct SourceBackedShadow<'a> {
    source: &'a mut GeneralFrozenPartition,
    shadow: &'a mut GeneralFrozenPartition,
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
        if let Some(capacity) = &mut capacity {
            (capacity.guard)(capacity.budget.assess(0, 0, 0, 0)?)
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
        let mut copy_check = copies.map(|_| vec![0u8; NATIVE_CAPTURE_BYTES]);
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
        let mut packed = 0u64;
        let mut compared = 0u64;
        let mut ranges: Vec<ChangedRange> = Vec::new();
        let routes = self.routes;
        let mut classes = class_split.map(|split| ChangeClassifier::new(split, routes.entries()));
        let mut prefetch = OriginalPrefetch::start(self.source, selection)?;
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
                self.seek(SeekFrom::Start(at))?;
                self.read_exact(&mut candidate[..count])?;
                let prefetched = match &mut prefetch {
                    Some(prefetch) => Some(prefetch.next(count)?),
                    None => {
                        self.source.seek(SeekFrom::Start(at))?;
                        self.source.read_exact(&mut original[..count])?;
                        None
                    }
                };
                let original: &[u8] = prefetched.as_deref().unwrap_or(&original[..count]);
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
                    let mut end = offset + 4096;
                    while end < count
                        && original[end..end + 4096] != candidate[end..end + 4096]
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
                            && r.new_is_zero == new_is_zero
                            && match (r.copy_source_offset, copy_source_offset) {
                                (None, None) => true,
                                (Some(previous), Some(current)) => previous + r.length == current,
                                _ => false,
                            }
                    });
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
                        let progress = capacity.budget.assess(next, packed, append, range_count)?;
                        (capacity.guard)(progress).context(
                            "capture capacity guard refused before accepting changed bytes",
                        )?;
                    }
                    if let Some(source_offset) = copy_source_offset {
                        let check = copy_check
                            .as_mut()
                            .context("source-reference buffer absent")?;
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
                    if let Some(classes) = &mut classes {
                        classes.record(
                            address,
                            &original[offset..offset + bytes],
                            &candidate[offset..offset + bytes],
                        );
                    }
                    if extends_previous {
                        let previous =
                            ranges.last_mut().context("extended capture range absent")?;
                        previous.old_is_zero &= old_is_zero;
                        previous.length += bytes as u64;
                    } else {
                        ensure!(
                            ranges.len() < 65536,
                            "delta range budget exhausted before output write"
                        );
                        ranges.push(ChangedRange {
                            offset: address,
                            length: bytes as u64,
                            packed_offset: packed,
                            new_is_zero,
                            old_is_zero,
                            copy_source_offset,
                        });
                    }
                    if !new_is_zero && copy_source_offset.is_none() {
                        file.write_all(&candidate[offset..offset + bytes])?;
                        packed_digest.update(&candidate[offset..offset + bytes]);
                        packed = packed
                            .checked_add(bytes as u64)
                            .context("delta packed byte count overflow")?;
                    }
                    changed = next;
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

    fn read_inner(&mut self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() || self.position == self.length {
            return Ok(0);
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
        if in_payload {
            let route = route.unwrap();
            let object = &self.tree.objects[route.object_index];
            let stream = object
                .stream(&route.stream_name_utf16)
                .context("source-backed sparse stream absent")?;
            let logical = route.logical_offset + self.position - route.target_physical_offset;
            if self
                .session
                .as_ref()
                .is_none_or(|s| !s.matches_stream(object.record_number, &route.stream_name_utf16))
            {
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
            session.read(
                self.source,
                self.raw,
                logical,
                &mut output[..count],
                &mut self.budget,
            )?;
            self.counts.source_logical_bytes = self
                .counts
                .source_logical_bytes
                .checked_add(count as u64)
                .context("source-backed source accounting overflow")?;
        } else {
            self.shadow.seek(SeekFrom::Start(self.position))?;
            self.shadow.read_exact(&mut output[..count])?;
            self.counts.shadow_bytes = self
                .counts
                .shadow_bytes
                .checked_add(count as u64)
                .context("source-backed shadow accounting overflow")?;
        }
        self.position += count as u64;
        Ok(count)
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
