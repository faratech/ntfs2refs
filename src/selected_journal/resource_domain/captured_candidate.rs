//! Read only the selected changed bytes from a real protected capture.
//! ZERO comes from its verified classification, literals from its held file,
//! and COPY from a separately reopened frozen source lane. This is not a
//! source-admission certificate, journal ticket or target-write capability.
use super::{ResourceJournalDomain, add};
use crate::{
    general_composite_target::paged::ProtectedPagedTargetSelection,
    general_shadow::capture_index::CaptureIndexRange,
    general_source_admission::resource::{
        ResourceSourceContext, source_owner::ResourceSourceReadLane,
    },
    lab_reconstruct::ReadSeek,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{GeneralDiskState, GeneralFrozenLane, GeneralFrozenPartition, NativeEvent};
use std::{
    collections::VecDeque,
    io::{self, Read, Seek, SeekFrom},
};

/// Multi-lane sorted, coalesced prefetcher for non-monotonic COPY source reads
/// during journal preparation. Opened with spare RAM; on refusal or read error
/// the caller falls back cleanly to `source_lane`.
///
/// The preparing thread waited for each batch while the lanes read it. Where
/// a second batch's memory is granted (spare RAM), the batch that follows is
/// read on a thread of its own, through the same lanes, while the preparing
/// thread uses the one it has: the batch a refill at its first row would read
/// (the same rows, from the same offsets), which the refill then takes
/// without waiting for the lanes. Where that memory is not granted, or the
/// batch read ahead is not the one asked for, a batch is read when it is
/// asked for, as before. Where the thread cannot be started, the lanes stay
/// here, a line says so, and from then on every batch is read when it is
/// asked for. A panic of that thread is the error of the read that takes its
/// batch, as a lane's panic was of the read that waited for it.
struct CopyPrefetch {
    /// `None` only while the thread reading ahead has them.
    lanes: Option<Vec<GeneralFrozenLane>>,
    cache: VecDeque<(u64, Vec<u8>)>,
    /// The batch being read ahead. Its thread gives the lanes back, with the
    /// batch, or none where a lane failed to read.
    ahead: Option<std::thread::JoinHandle<(Vec<GeneralFrozenLane>, Option<CopyBatch>)>>,
    /// Where the scan for the batch after the cached one begins.
    next_scan: Option<u64>,
    /// The second batch's memory: without it nothing is read ahead.
    ahead_ram: Option<crate::artifact_arena::ArenaRamLease>,
    _ram: crate::artifact_arena::ArenaRamLease,
}

/// A batch of COPY rows' source bytes, by row ordinal, in ordinal order.
type CopyBatch = Vec<(u64, Vec<u8>)>;

impl Drop for CopyPrefetch {
    /// The batch being read ahead ends before the lanes and the memory go;
    /// a panic of its thread goes on from here, as a lane's did from the
    /// read that waited for it.
    fn drop(&mut self) {
        if let Some(ahead) = self.ahead.take()
            && let Err(panic) = ahead.join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(panic);
        }
    }
}

const COPY_PREFETCH_MAX_LANES: usize = 4;
const COPY_PREFETCH_MAX_ROWS: usize = 256;
const COPY_PREFETCH_MAX_SCAN: u64 = 1024;
const COPY_PREFETCH_MAX_BATCH_BYTES: u64 = 16 * 1024 * 1024;
const COPY_PREFETCH_MAX_GAP: u64 = 64 * 1024;
const COPY_PREFETCH_MAX_SPAN: u64 = 4 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct CopySpan {
    start: u64,
    length: usize,
    members: Vec<(u64, usize, usize)>,
}

fn coalesce_copy_spans(mut items: Vec<(u64, u64, u64)>) -> Vec<CopySpan> {
    // items: (copy_source_offset, length, row_ordinal)
    items.sort_unstable_by_key(|&(offset, _, ordinal)| (offset, ordinal));
    let mut spans: Vec<CopySpan> = Vec::new();
    for (offset, length, ordinal) in items {
        let Ok(len) = usize::try_from(length) else {
            continue;
        };
        if len == 0 || len as u64 > COPY_PREFETCH_MAX_SPAN {
            continue;
        }
        if let Some(last) = spans.last_mut() {
            let last_end = last.start + last.length as u64;
            if offset >= last.start {
                let new_end = (offset + length).max(last_end);
                let gap = offset.saturating_sub(last_end);
                if gap <= COPY_PREFETCH_MAX_GAP && new_end - last.start <= COPY_PREFETCH_MAX_SPAN {
                    let within = (offset - last.start) as usize;
                    last.length = (new_end - last.start) as usize;
                    last.members.push((ordinal, within, len));
                    continue;
                }
            }
        }
        spans.push(CopySpan {
            start: offset,
            length: len,
            members: vec![(ordinal, 0, len)],
        });
    }
    spans
}

impl CopyPrefetch {
    fn open(
        source: &GeneralFrozenPartition,
        arena: &crate::artifact_arena::ArtifactArena,
        events: &mut Vec<NativeEvent>,
    ) -> Option<Self> {
        let depth = source.io_profile().queue_depth;
        if depth < 2 {
            return None;
        }
        let wanted = depth.min(COPY_PREFETCH_MAX_LANES);
        let per_lane = GeneralFrozenPartition::read_buffer_memory_bytes()
            .saturating_add(COPY_PREFETCH_MAX_SPAN)
            .saturating_add(2 * 1024 * 1024);
        let (lanes_count, ram) = (2..=wanted).rev().find_map(|n| {
            let bytes = (n as u64)
                .checked_mul(per_lane)?
                .checked_add(COPY_PREFETCH_MAX_BATCH_BYTES)?;
            arena.reserve_spare_ram(bytes).ok().map(|lease| (n, lease))
        })?;
        let lanes = source.read_lanes(lanes_count, events).ok()?;
        if lanes.len() < 2 {
            return None;
        }
        let ahead_ram = arena.reserve_spare_ram(COPY_PREFETCH_MAX_BATCH_BYTES).ok();
        Some(Self {
            lanes: Some(lanes),
            cache: VecDeque::new(),
            ahead: None,
            next_scan: None,
            ahead_ram,
            _ram: ram,
        })
    }

    /// Fills the cache with the batch that begins with the COPY row
    /// `start_ordinal`: the one read ahead where it holds that row, and
    /// otherwise read now. Then starts reading the batch after it.
    fn refill(
        &mut self,
        index: &crate::general_shadow::capture_index::ClosedCaptureIndex,
        start_ordinal: u64,
    ) -> io::Result<()> {
        self.cache.clear();
        if let Some(batch) = self.take_ahead()?
            && batch.iter().any(|(ordinal, _)| *ordinal == start_ordinal)
        {
            self.cache.extend(batch);
            self.read_ahead(index);
            return Ok(());
        }
        self.next_scan = None;
        let Some((spans, stopped)) =
            plan_copy_batch(index.len(), |ordinal| index.range(ordinal), start_ordinal)
        else {
            return Ok(());
        };
        let Some(lanes) = self.lanes.as_mut() else {
            return Ok(());
        };
        let Some(batch) = read_copy_spans(lanes, &spans) else {
            return Ok(());
        };
        self.cache.extend(batch);
        self.next_scan = Some(stopped);
        self.read_ahead(index);
        Ok(())
    }

    /// The batch read ahead, once its thread is done, and the lanes back. A
    /// panic of that thread is an error: the lanes went with it.
    fn take_ahead(&mut self) -> io::Result<Option<CopyBatch>> {
        let Some(ahead) = self.ahead.take() else {
            return Ok(None);
        };
        let (lanes, batch) = ahead.join().map_err(|_| {
            io::Error::other(
                "journal preparation: the thread reading COPY rows' source bytes ahead, through read lanes of the frozen source, panicked",
            )
        })?;
        self.lanes = Some(lanes);
        Ok(batch)
    }

    /// Starts reading, on a thread of its own, the batch a refill at the
    /// first COPY row from `next_scan` on would read, where the memory for a
    /// second batch is held.
    fn read_ahead(&mut self, index: &crate::general_shadow::capture_index::ClosedCaptureIndex) {
        if self.ahead_ram.is_none() || self.ahead.is_some() || self.lanes.is_none() {
            return;
        }
        let Some(from) = self.next_scan.take() else {
            return;
        };
        let range = |ordinal| index.range(ordinal);
        let Some(first) = first_copy_row(index.len(), range, from) else {
            return;
        };
        let Some((spans, stopped)) = plan_copy_batch(index.len(), range, first) else {
            return;
        };
        // The thread is started first and handed the lanes once it runs, so
        // that a thread that cannot be started leaves them here.
        let (hand_over, handed) =
            std::sync::mpsc::sync_channel::<(Vec<GeneralFrozenLane>, Vec<CopySpan>)>(1);
        let started = std::thread::Builder::new()
            .name("n2r-copy-read-ahead".into())
            .spawn(move || {
                let _sampled = n2r_win32::stack_sampler::helper();
                let (mut lanes, spans) = handed
                    .recv()
                    .expect("the COPY read-ahead thread is handed its lanes once it runs");
                let batch = read_copy_spans(&mut lanes, &spans);
                (lanes, batch)
            });
        let ahead = match started {
            Ok(ahead) => ahead,
            Err(error) => {
                eprintln!(
                    "journal preparation: COPY rows' source bytes are read when they are asked for from here on, not ahead: the thread to read them ahead could not be started: {error}"
                );
                self.ahead_ram = None;
                return;
            }
        };
        let lanes = self
            .lanes
            .take()
            .expect("the lanes are here: checked above");
        match hand_over.send((lanes, spans)) {
            Ok(()) => {
                self.ahead = Some(ahead);
                self.next_scan = Some(stopped);
            }
            // The thread ended before it took them: its panic is taken with
            // the next batch, and the lanes stay here.
            Err(std::sync::mpsc::SendError((lanes, _))) => {
                self.lanes = Some(lanes);
                self.ahead = Some(ahead);
            }
        }
    }
}

/// The first COPY row from `from` on, within the rows a batch scans.
fn first_copy_row(
    len: u64,
    range: impl Fn(u64) -> Result<CaptureIndexRange>,
    from: u64,
) -> Option<u64> {
    let scan_end = from.saturating_add(COPY_PREFETCH_MAX_SCAN).min(len);
    (from..scan_end)
        .map_while(|ordinal| range(ordinal).ok().map(|row| (ordinal, row)))
        .find(|(_, row)| row.copy_source_offset.is_some())
        .map(|(ordinal, _)| ordinal)
}

/// The coalesced spans of the batch of COPY rows a refill at
/// `start_ordinal` reads, and the ordinal its scan stopped at, where the next
/// batch's scan begins. `None` where there are fewer than two such rows or
/// the first is too long to prefetch.
fn plan_copy_batch(
    len: u64,
    range: impl Fn(u64) -> Result<CaptureIndexRange>,
    start_ordinal: u64,
) -> Option<(Vec<CopySpan>, u64)> {
    let mut items: Vec<(u64, u64, u64)> = Vec::new();
    let mut total_bytes = 0u64;
    let scan_end = start_ordinal
        .saturating_add(COPY_PREFETCH_MAX_SCAN)
        .min(len);
    let mut stopped = scan_end;
    for ordinal in start_ordinal..scan_end {
        let Ok(row) = range(ordinal) else {
            stopped = ordinal;
            break;
        };
        if let Some(source_offset) = row.copy_source_offset {
            if row.length > COPY_PREFETCH_MAX_SPAN {
                if items.is_empty() {
                    return None;
                }
                stopped = ordinal;
                break;
            }
            if total_bytes.saturating_add(row.length) > COPY_PREFETCH_MAX_BATCH_BYTES
                && !items.is_empty()
            {
                stopped = ordinal;
                break;
            }
            total_bytes = total_bytes.saturating_add(row.length);
            items.push((source_offset, row.length, ordinal));
            if items.len() >= COPY_PREFETCH_MAX_ROWS {
                stopped = ordinal + 1;
                break;
            }
        }
    }
    if items.len() < 2 {
        return None;
    }
    let spans = coalesce_copy_spans(items);
    if spans.is_empty() {
        return None;
    }
    Some((spans, stopped))
}

/// Reads `spans` across `lanes`, in parallel, into each member row's bytes,
/// in ordinal order. `None` where a lane fails to read.
fn read_copy_spans(lanes: &mut [GeneralFrozenLane], spans: &[CopySpan]) -> Option<CopyBatch> {
    if lanes.is_empty() {
        return None;
    }
    {
        let lane_count = lanes.len();
        let mut results: Vec<io::Result<Vec<(u64, Vec<u8>)>>> =
            (0..lane_count).map(|_| Ok(Vec::new())).collect();
        std::thread::scope(|scope| {
            for ((lane_idx, lane), slot) in lanes.iter_mut().enumerate().zip(results.iter_mut()) {
                let spans = &spans;
                scope.spawn(move || {
                    let mut buf = Vec::new();
                    let mut out = Vec::new();
                    for (span_idx, span) in spans.iter().enumerate() {
                        if span_idx % lane_count != lane_idx {
                            continue;
                        }
                        buf.resize(span.length, 0);
                        if let Err(err) = lane
                            .seek(SeekFrom::Start(span.start))
                            .and_then(|_| lane.read_exact(&mut buf))
                        {
                            *slot = Err(err);
                            return;
                        }
                        for &(ordinal, within, len) in &span.members {
                            out.push((ordinal, buf[within..within + len].to_vec()));
                        }
                    }
                    *slot = Ok(out);
                });
            }
        });
        let mut combined = Vec::new();
        for res in results {
            match res {
                Ok(mut part) => combined.append(&mut part),
                Err(_) => return None,
            }
        }
        combined.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        Some(combined)
    }
}

pub(crate) struct ProtectedCapturedCandidate<'a> {
    proof: &'a ProtectedPagedTargetSelection,
    copy_prefetch: Option<CopyPrefetch>,
    source_lane: ResourceSourceReadLane,
    source_before: Option<GeneralDiskState>,
    partition_owner: Option<n2r_win32::PartitionOwnerToken>,
    shadow_before: GeneralDiskState,
    image_length: u64,
    position: u64,
    cached: Option<(u64, CaptureIndexRange)>,
    _lane_memory: crate::artifact_arena::ArenaRamLease,
}

impl<'a> ProtectedCapturedCandidate<'a> {
    /// The actual still-borrowed protected target; never reconstructed from
    /// the capture summary or a persisted route pin.
    pub(crate) fn protected_proof(&self) -> &'a ProtectedPagedTargetSelection {
        self.proof
    }

    pub(crate) fn open(
        proof: &'a ProtectedPagedTargetSelection,
        domain: &ResourceJournalDomain<'_>,
        context: &mut ResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        ensure!(
            std::ptr::eq(domain.capture(), proof.captured()),
            "journal domain does not borrow the exact protected capture owner"
        );
        context.require_source_evidence()?;
        context.recheck_source(events)?;
        proof.scope().revalidate()?;
        proof.captured().revalidate()?;
        ensure!(
            proof.scope().source_inspection_sha256() == context.inspection_sha256(),
            "protected capture source inventory differs from its actual context"
        );
        // GeneralFrozenPartition owns a 4 MiB aligned native I/O buffer. The
        // lease is acquired before opening that second lane and remains held
        // until after the lane itself has been dropped.
        let lane_ram = GeneralFrozenPartition::read_buffer_memory_bytes()
            .checked_add(64 * 1024)
            .context("source lane RAM overflow")?;
        let arena = context
            .arena()
            .context("source lane needs the actual shared arena")?
            .clone();
        let lane_memory = arena.reserve_ram(lane_ram)?;
        let (source, _) = context.scoped_source_and_inspection();
        ensure!(
            source.binding() == &proof.scope().pair().source
                && shadow.binding() == &proof.scope().pair().shadow,
            "protected capture source/shadow route differs"
        );
        let source_before = source.state(events)?;
        let shadow_before = shadow.state(events)?;
        ensure!(
            source_before.disk_attributes == 3
                && shadow_before.disk_attributes == 3
                && proof.native().before() == &shadow_before
                && proof.native().after() == &shadow_before,
            "protected capture requires the original excluded source and shadow"
        );
        let mut source_lane = ResourceSourceReadLane::open(source, events)?;
        ensure!(
            source_lane.dedicated_state(events)? == source_before,
            "captured-candidate source lane differs from the real frozen source"
        );
        source_lane.set_read_ahead(true);
        let copy_prefetch = source
            .require_dedicated()
            .ok()
            .and_then(|dedicated| CopyPrefetch::open(dedicated, &arena, events));
        let image_length = domain.facts().image_length;
        ensure!(
            source.byte_len() == image_length
                && GeneralFrozenPartition::byte_len(shadow) == image_length
                && source_lane.byte_len() == image_length,
            "captured-candidate image geometry differs"
        );
        Ok(Self {
            proof,
            copy_prefetch,
            source_lane,
            _lane_memory: lane_memory,
            source_before: Some(source_before),
            partition_owner: None,
            shadow_before,
            image_length,
            position: 0,
            cached: None,
        })
    }

    pub(crate) fn require_domain(&self, domain: &ResourceJournalDomain<'_>) -> Result<()> {
        ensure!(
            std::ptr::eq(domain.capture(), self.proof.captured()),
            "journal domain and captured-candidate proof are not the same owner"
        );
        Ok(())
    }

    /// Recheck the original source fingerprint/owners and the actual target
    /// after preparation. The target proof still does not grant activation.
    pub(crate) fn revalidate(
        &mut self,
        context: &mut ResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        let proof = self.protected_proof();
        proof.captured().with_revalidation(|witness| {
            self.revalidate_with_capture_witness(context, shadow, events, witness)
        })?;
        // Keep a complete end check for this standalone boundary too; the
        // scoped witness does not exclude raw writes during the callback.
        proof.captured().revalidate()
    }

    pub(crate) fn revalidate_with_capture_witness(
        &mut self,
        context: &mut ResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
        witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    ) -> Result<()> {
        witness.require_capture(self.proof.captured())?;
        self.proof.scope().revalidate()?;
        context.recheck_source(events)?;
        ensure!(
            self.proof.scope().source_inspection_sha256() == context.inspection_sha256(),
            "captured-candidate source inventory changed"
        );
        let (source, _) = context.scoped_source_and_inspection();
        ensure!(
            source.binding() == &self.proof.scope().pair().source
                && shadow.binding() == &self.proof.scope().pair().shadow
                && Some(source.state(events)?) == self.source_before
                && Some(self.source_lane.dedicated_state(events)?) == self.source_before
                && shadow.state(events)? == self.shadow_before,
            "captured-candidate frozen route or exclusion changed"
        );
        self.proof
            .recheck_frozen_target_with_capture_witness(shadow, events, witness)?;
        Ok(())
    }

    fn find_row(&mut self, offset: u64) -> Result<CaptureIndexRange> {
        let index = self.proof.captured().index();
        if let Some((_, row)) = self.cached {
            if row.offset <= offset && offset < add(row.offset, row.length)? {
                return Ok(row);
            }
        }
        let (mut low, mut high) = (0u64, index.len());
        while low < high {
            let mid = low + (high - low) / 2;
            let row = index.range(mid)?;
            if add(row.offset, row.length)? <= offset {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        ensure!(
            low < index.len(),
            "captured-candidate read escapes selected rows"
        );
        let row = index.range(low)?;
        ensure!(
            row.offset <= offset && offset < add(row.offset, row.length)?,
            "captured-candidate read enters an unselected gap"
        );
        self.cached = Some((low, row));
        Ok(row)
    }
}

impl Read for ProtectedCapturedCandidate<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.image_length {
            return Ok(0);
        }
        let row = self
            .find_row(self.position)
            .map_err(|e| io::Error::other(format!("{e:#}")))?;
        let within = self.position - row.offset;
        let count = usize::try_from((row.length - within).min(output.len() as u64))
            .map_err(io::Error::other)?;
        if row.new_is_zero {
            output[..count].fill(0);
        } else if let Some(source) = row.copy_source_offset {
            let current_ordinal = self.cached.map(|(ord, _)| ord);
            let mut served = false;
            if let (Some(ordinal), Some(prefetch)) = (current_ordinal, self.copy_prefetch.as_mut())
            {
                while prefetch
                    .cache
                    .front()
                    .is_some_and(|(ord, _)| *ord < ordinal)
                {
                    prefetch.cache.pop_front();
                }
                if prefetch
                    .cache
                    .front()
                    .is_none_or(|(ord, _)| *ord != ordinal)
                    && within == 0
                {
                    prefetch.refill(self.proof.captured().index(), ordinal)?;
                }
                if let Some((ord, bytes)) = prefetch.cache.front()
                    && *ord == ordinal
                    && let Some(slice) = bytes.get(within as usize..within as usize + count)
                {
                    output[..count].copy_from_slice(slice);
                    if within as usize + count == bytes.len() {
                        prefetch.cache.pop_front();
                    }
                    served = true;
                }
            }
            if !served {
                let offset = source
                    .checked_add(within)
                    .ok_or_else(|| io::Error::other("captured COPY offset overflow"))?;
                self.source_lane.seek(SeekFrom::Start(offset))?;
                self.source_lane.read_exact(&mut output[..count])?;
            }
        } else {
            let offset = row
                .packed_offset
                .checked_add(within)
                .ok_or_else(|| io::Error::other("captured literal offset overflow"))?;
            self.proof
                .captured()
                .literal()
                .read_exact_at(offset, &mut output[..count])
                .map_err(|e| io::Error::other(format!("{e:#}")))?;
        }
        self.position = self
            .position
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("captured-candidate cursor overflow"))?;
        Ok(count)
    }
}

impl Seek for ProtectedCapturedCandidate<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.image_length) + i128::from(v),
        };
        if position < 0 || position > i128::from(self.image_length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "captured-candidate seek escapes image",
            ));
        }
        self.position = u64::try_from(position).map_err(io::Error::other)?;
        Ok(self.position)
    }
}

impl ReadSeek for ProtectedCapturedCandidate<'_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.image_length)
    }
}

impl<'a> ProtectedCapturedCandidate<'a> {
    pub(crate) fn open_partition(
        proof: &'a ProtectedPagedTargetSelection,
        domain: &ResourceJournalDomain<'_>,
        context:&mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        ensure!(
            std::ptr::eq(domain.capture(), proof.captured()),
            "partition journal does not borrow exact protected capture"
        );
        context.require_source_evidence()?;
        context.recheck_source(events)?;
        proof.scope().revalidate()?;
        proof.captured().revalidate()?;
        let token = context.owner_token();
        proof.native().require_partition_source_owner(&token)?;
        ensure!(
            proof
                .scope()
                .matches_source_owner(context.source_owner_identity())
                && proof.scope().source_inspection_sha256() == context.inspection_sha256(),
            "partition capture source owner/inventory differs"
        );
        let lane_ram =
            n2r_win32::partition_lifecycle::PartitionReadLane::read_buffer_memory_bytes()
                .checked_add(64 * 1024)
                .context("partition source lane RAM overflow")?;
        let lane_memory = context.arena().reserve_ram(lane_ram)?;
        let (owner, admission, _) = context.source_admission_and_inspection();
        n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(owner, admission)?;
        ensure!(
            owner.binding().storage == proof.scope().pair().source
                && shadow.binding() == &proof.scope().pair().shadow,
            "partition source/shadow route differs"
        );
        owner.revalidate(events)?;
        let shadow_before = shadow.state(events)?;
        ensure!(
            shadow_before.disk_attributes == 3
                && proof.native().before() == &shadow_before
                && proof.native().after() == &shadow_before,
            "protected partition target lost actual shadow exclusion"
        );
        let lane = n2r_win32::partition_lifecycle::PartitionReadLane::from_owner(owner, events)?;
        let source_lane = ResourceSourceReadLane::Partition(lane);
        let image_length = domain.facts().image_length;
        ensure!(
            n2r_win32::PartitionScopedOwner::byte_len(owner) == image_length
                && n2r_win32::GeneralFrozenPartition::byte_len(shadow) == image_length
                && source_lane.byte_len() == image_length,
            "partition capture/journal image geometry differs"
        );
        Ok(Self {
            proof,
            copy_prefetch: None,
            source_lane,
            source_before: None,
            partition_owner: Some(token),
            shadow_before,
            image_length,
            position: 0,
            cached: None,
            _lane_memory: lane_memory,
        })
    }
    pub(crate) fn revalidate_partition(
        &mut self,
        context:&mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        let proof = self.proof;
        proof.captured().with_revalidation(|witness| {
            self.revalidate_partition_with_capture_witness(context, shadow, events, witness)
        })?;
        proof.captured().revalidate()
    }
    pub(crate) fn revalidate_partition_with_capture_witness(
        &mut self,
        context:&mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
        witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    ) -> Result<()> {
        witness.require_capture(self.proof.captured())?;
        self.proof.scope().revalidate()?;
        context.recheck_source(events)?;
        let token = context.owner_token();
        ensure!(
            self.source_before.is_none()
                && self
                    .partition_owner
                    .as_ref()
                    .is_some_and(|p| p.same_owner(&token))
                && self
                    .proof
                    .scope()
                    .matches_source_owner(context.source_owner_identity())
                && self.proof.scope().source_inspection_sha256() == context.inspection_sha256(),
            "partition candidate lost actual original context/token"
        );
        self.proof.native().require_partition_source_owner(&token)?;
        let (owner, admission, _) = context.source_admission_and_inspection();
        n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(owner, admission)?;
        owner.revalidate(events)?;
        ensure!(
            owner.binding().storage == self.proof.scope().pair().source
                && shadow.binding() == &self.proof.scope().pair().shadow
                && shadow.state(events)? == self.shadow_before,
            "partition candidate source/target binding or shadow state changed"
        );
        match &mut self.source_lane {
            ResourceSourceReadLane::Partition(lane) => lane.revalidate(owner, events)?,
            ResourceSourceReadLane::Dedicated(_) => {
                anyhow::bail!("partition candidate acquired dedicated source lane")
            }
        }
        self.proof
            .recheck_frozen_target_with_capture_witness(shadow, events, witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rows one after another from offset 1 MiB on; `Some(source)` makes a
    /// COPY row.
    fn rows(spec: &[(u64, Option<u64>)]) -> Vec<CaptureIndexRange> {
        let mut offset = 1 << 20;
        spec.iter()
            .map(|&(length, copy_source_offset)| {
                let row = CaptureIndexRange {
                    offset,
                    length,
                    packed_offset: 0,
                    new_is_zero: false,
                    old_is_zero: false,
                    old_is_source_free: false,
                    copy_source_offset,
                };
                offset += length;
                row
            })
            .collect()
    }

    fn members(spans: &[CopySpan]) -> Vec<u64> {
        let mut members: Vec<u64> = spans
            .iter()
            .flat_map(|span| span.members.iter().map(|member| member.0))
            .collect();
        members.sort_unstable();
        members
    }

    #[test]
    fn batches_follow_one_another_and_stop_where_a_refill_stops() {
        const MIB: u64 = 1024 * 1024;
        let table = rows(&[
            (4096, None),
            (4096, Some(0)),
            (8192, None),
            (8192, Some(64 * 1024)),
            (5 * MIB, Some(128 * 1024)),
            (4096, Some(0)),
            (4096, Some(4096)),
        ]);
        let len = table.len() as u64;
        let range = |ordinal: u64| Ok(table[usize::try_from(ordinal).unwrap()]);
        assert_eq!(first_copy_row(len, range, 0), Some(1));
        let (spans, stopped) = plan_copy_batch(len, range, 1).unwrap();
        assert_eq!(members(&spans), vec![1, 3]);
        assert_eq!(stopped, 4, "a COPY row too long to prefetch ends the batch");
        assert_eq!(first_copy_row(len, range, stopped), Some(4));
        assert!(
            plan_copy_batch(len, range, 4).is_none(),
            "and is read through the source lane"
        );
        let (spans, stopped) = plan_copy_batch(len, range, 5).unwrap();
        assert_eq!(members(&spans), vec![5, 6]);
        assert_eq!(stopped, len);
        assert_eq!(first_copy_row(len, range, stopped), None);

        // A batch holds at most COPY_PREFETCH_MAX_ROWS rows and about
        // COPY_PREFETCH_MAX_BATCH_BYTES bytes; the next begins where it ends.
        let many = rows(&vec![(4096, Some(0)); 300]);
        let range = |ordinal: u64| Ok(many[usize::try_from(ordinal).unwrap()]);
        let (spans, stopped) = plan_copy_batch(300, range, 0).unwrap();
        assert_eq!(members(&spans), (0..256).collect::<Vec<_>>());
        assert_eq!(stopped, 256);
        let (spans, _) = plan_copy_batch(300, range, stopped).unwrap();
        assert_eq!(members(&spans), (256..300).collect::<Vec<_>>());
        let large = rows(&vec![(4 * MIB, Some(0)); 6]);
        let range = |ordinal: u64| Ok(large[usize::try_from(ordinal).unwrap()]);
        let (spans, stopped) = plan_copy_batch(6, range, 0).unwrap();
        assert_eq!(members(&spans), vec![0, 1, 2, 3]);
        assert_eq!(stopped, 4);

        // A lone COPY row is not prefetched.
        let lone = rows(&[(4096, Some(0)), (4096, None)]);
        let range = |ordinal: u64| Ok(lone[usize::try_from(ordinal).unwrap()]);
        assert!(plan_copy_batch(2, range, 0).is_none());
    }

    #[test]
    fn copy_span_coalescing_sorts_bridges_small_gaps_and_respects_span_cap() {
        let items = vec![
            // Out of physical order, with a 16 KiB gap that should bridge.
            (100 * 1024, 8 * 1024, 5),
            (64 * 1024, 20 * 1024, 2),
            // Far away (> 64 KiB gap): separate span.
            (512 * 1024, 4 * 1024, 9),
            // Adjacent to the 512 KiB entry: bridges into the same span.
            (516 * 1024, 12 * 1024, 1),
        ];
        let spans = coalesce_copy_spans(items);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start, 64 * 1024);
        assert_eq!(spans[0].length, 44 * 1024);
        assert_eq!(
            spans[0].members,
            vec![(2, 0, 20 * 1024), (5, 36 * 1024, 8 * 1024)]
        );
        assert_eq!(spans[1].start, 512 * 1024);
        assert_eq!(spans[1].length, 16 * 1024);
        assert_eq!(
            spans[1].members,
            vec![(9, 0, 4 * 1024), (1, 4 * 1024, 12 * 1024)]
        );
    }
}
