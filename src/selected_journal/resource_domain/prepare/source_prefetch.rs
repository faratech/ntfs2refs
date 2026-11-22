//! Multi-lane ascending prefetch of the frozen source during native journal
//! preparation.
//!
//! `native-journal-preparation` reads every changed range of the source in
//! ascending order. Reading them one at a time on a single unbuffered handle
//! (`with_read_ahead`) left the disk at queue depth 1 across tens of thousands
//! of reads. Here 2–4 `GeneralFrozenLane` handles read grouped ≤4 MiB spans
//! (bridging gaps ≤64 KiB) ahead of `prepare_inner`, paid for as spare memory.
//! Any out-of-order read (e.g. a backward COPY reference) falls back directly
//! to the primary handle, and if lanes or spare memory are unavailable the
//! caller falls back to `source.with_read_ahead`. A run that verifies each
//! thing once does not read the OLD-zero ranges here (`old_zero_unread` in
//! `prepare_inner`), and they are not read ahead.
use super::*;
use std::{
    collections::VecDeque,
    io::{self, Read, Seek, SeekFrom},
    sync::mpsc,
};

const SPAN: usize = 4 * BUFFER;
const BRIDGE: u64 = 64 * 1024;
const AHEAD_PER_LANE: usize = 2;

struct LaneHandle {
    jobs: mpsc::SyncSender<(u64, usize)>,
    results: mpsc::Receiver<io::Result<Vec<u8>>>,
    free: mpsc::SyncSender<Vec<u8>>,
}

struct PendingSpan {
    start: u64,
    length: usize,
    lane: usize,
}

struct ActiveSpan {
    start: u64,
    length: usize,
    lane: usize,
    buffer: Vec<u8>,
}

struct PrefetchedSource<'a, R: ReadSeek> {
    fallback: &'a mut R,
    image_length: u64,
    domain: &'a ResourceJournalDomain<'a>,
    range_count: u64,
    /// The OLD-zero ranges are not read by the preparation
    /// (`old_zero_unread` in `prepare_inner`): none is read ahead either.
    old_zero_unread: bool,
    next_ordinal: u64,
    /// Unqueued tail `(start, end)` of a range larger than `SPAN`.
    remainder: Option<(u64, u64)>,
    next_lane: usize,
    lanes: Vec<LaneHandle>,
    pending: VecDeque<PendingSpan>,
    current: Option<ActiveSpan>,
    position: u64,
}

impl<'a, R: ReadSeek> PrefetchedSource<'a, R> {
    fn new(
        fallback: &'a mut R,
        image_length: u64,
        domain: &'a ResourceJournalDomain<'a>,
        range_count: u64,
        old_zero_unread: bool,
        lanes: Vec<LaneHandle>,
    ) -> Self {
        let mut this = Self {
            fallback,
            image_length,
            domain,
            range_count,
            old_zero_unread,
            next_ordinal: 0,
            remainder: None,
            next_lane: 0,
            lanes,
            pending: VecDeque::new(),
            current: None,
            position: 0,
        };
        this.pump();
        this
    }

    /// Groups upcoming ranges into ≤4 MiB spans (bridging gaps ≤64 KiB) and
    /// submits them round-robin to the lane threads up to `lanes * AHEAD_PER_LANE`.
    /// Where the OLD-zero ranges are not read, they are passed over: a gap.
    fn pump(&mut self) {
        let limit = self.lanes.len() * AHEAD_PER_LANE;
        let index = self.domain.capture().index();
        while self.pending.len() < limit {
            let (mut start, mut end) = if let Some((rem_start, rem_end)) = self.remainder.take() {
                (rem_start, rem_end)
            } else {
                let first = loop {
                    if self.next_ordinal >= self.range_count {
                        break None;
                    }
                    let Ok(first) = index.range(self.next_ordinal) else {
                        break None;
                    };
                    self.next_ordinal += 1;
                    if !(self.old_zero_unread && first.old_is_zero) {
                        break Some(first);
                    }
                };
                let Some(first) = first else {
                    break;
                };
                (first.offset, first.offset.saturating_add(first.length))
            };
            if end - start > SPAN as u64 {
                if !self.submit_span(start, SPAN) {
                    return;
                }
                start += SPAN as u64;
                if start < end {
                    self.remainder = Some((start, end));
                }
                continue;
            }
            while self.next_ordinal < self.range_count {
                let Ok(next) = index.range(self.next_ordinal) else {
                    break;
                };
                if self.old_zero_unread && next.old_is_zero {
                    self.next_ordinal += 1;
                    continue;
                }
                if next.offset < end || next.offset - end > BRIDGE {
                    break;
                }
                let next_end = next.offset.saturating_add(next.length);
                if next_end - start > SPAN as u64 {
                    break;
                }
                end = next_end;
                self.next_ordinal += 1;
            }
            let length = (end - start) as usize;
            if length > 0 && !self.submit_span(start, length) {
                return;
            }
        }
    }

    fn submit_span(&mut self, start: u64, length: usize) -> bool {
        let lane = self.next_lane % self.lanes.len();
        self.next_lane = self.next_lane.wrapping_add(1);
        if self.lanes[lane].jobs.send((start, length)).is_err() {
            return false;
        }
        self.pending.push_back(PendingSpan {
            start,
            length,
            lane,
        });
        true
    }

    fn recycle_current(&mut self) {
        if let Some(active) = self.current.take() {
            let _ = self.lanes[active.lane].free.send(active.buffer);
        }
    }

    fn advance_to(&mut self, offset: u64) -> io::Result<bool> {
        if let Some(active) = &self.current {
            if offset >= active.start && offset < active.start + active.length as u64 {
                return Ok(true);
            }
            if offset < active.start {
                return Ok(false);
            }
        }
        // Only consume pending spans if the front span is at or before `offset`.
        while let Some(front) = self.pending.front() {
            if offset < front.start {
                return Ok(false);
            }
            let span = self.pending.pop_front().unwrap();
            self.recycle_current();
            let buffer = self.lanes[span.lane]
                .results
                .recv()
                .map_err(|_| io::Error::other("journal source prefetch lane stopped"))??;
            self.current = Some(ActiveSpan {
                start: span.start,
                length: span.length,
                lane: span.lane,
                buffer,
            });
            self.pump();
            if offset < span.start + span.length as u64 {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl<R: ReadSeek> Drop for PrefetchedSource<'_, R> {
    fn drop(&mut self) {
        self.recycle_current();
        self.lanes.clear();
    }
}

impl<R: ReadSeek> Read for PrefetchedSource<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.position >= self.image_length {
            return Ok(0);
        }
        if self.advance_to(self.position)? {
            let active = self.current.as_ref().unwrap();
            let from = (self.position - active.start) as usize;
            let available = active.length - from;
            let count = out.len().min(available);
            out[..count].copy_from_slice(&active.buffer[from..from + count]);
            self.position += count as u64;
            return Ok(count);
        }
        self.fallback.seek(SeekFrom::Start(self.position))?;
        let n = self.fallback.read(out)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: ReadSeek> Seek for PrefetchedSource<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => self
                .position
                .checked_add_signed(delta)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek underflow"))?,
            SeekFrom::End(delta) => self
                .image_length
                .checked_add_signed(delta)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek underflow"))?,
        };
        self.position = next;
        Ok(next)
    }
}

impl<R: ReadSeek> ReadSeek for PrefetchedSource<'_, R> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.image_length)
    }
}

fn allocate_lane_buffers(lanes: usize) -> Option<Vec<Vec<Vec<u8>>>> {
    let mut all = Vec::with_capacity(lanes);
    for _ in 0..lanes {
        let mut group = Vec::with_capacity(AHEAD_PER_LANE);
        for _ in 0..AHEAD_PER_LANE {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(SPAN).ok()?;
            buffer.resize(SPAN, 0);
            group.push(buffer);
        }
        all.push(group);
    }
    Some(all)
}

fn lane_loop<L: Read + Seek>(
    mut reader: L,
    jobs: mpsc::Receiver<(u64, usize)>,
    results: mpsc::SyncSender<io::Result<Vec<u8>>>,
    free: mpsc::Receiver<Vec<u8>>,
) {
    let _sampled = n2r_win32::stack_sampler::helper();
    while let Ok((offset, length)) = jobs.recv() {
        let Ok(mut buffer) = free.recv() else {
            return;
        };
        let res = reader
            .seek(SeekFrom::Start(offset))
            .and_then(|_| reader.read_exact(&mut buffer[..length]))
            .map(|()| buffer);
        let failed = res.is_err();
        if results.send(res).is_err() || failed {
            return;
        }
    }
}

pub(super) enum SourceReader<'a> {
    Prefetched(PrefetchedSource<'a, n2r_win32::GeneralFrozenPartition>),
    Direct(&'a mut n2r_win32::GeneralFrozenPartition),
}

impl SourceReader<'_> {
    pub(super) fn set_read_ahead_reach(&mut self, end: u64) {
        if let Self::Direct(source) = self {
            source.set_read_ahead_reach(end);
        }
    }
}

impl Read for SourceReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Prefetched(source) => source.read(out),
            Self::Direct(source) => source.read(out),
        }
    }
}

impl Seek for SourceReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Prefetched(source) => source.seek(pos),
            Self::Direct(source) => source.seek(pos),
        }
    }
}

impl ReadSeek for SourceReader<'_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        match self {
            Self::Prefetched(source) => source.byte_len(),
            Self::Direct(source) => source.byte_len(),
        }
    }
}

/// Runs `operation` with a multi-lane prefetched source if the disk supports
/// concurrent reads and spare memory / read lanes are available; otherwise
/// falls back to `source.with_read_ahead`. With `old_zero_unread`, the
/// OLD-zero ranges, which the preparation does not read, are not read ahead.
pub(super) fn with_prefetched_source<T>(
    source: &mut n2r_win32::GeneralFrozenPartition,
    domain: &ResourceJournalDomain<'_>,
    arena: &crate::artifact_arena::ArtifactArena,
    old_zero_unread: bool,
    events: &mut Vec<n2r_win32::NativeEvent>,
    mut operation: impl FnMut(&mut SourceReader<'_>) -> Result<T>,
) -> Result<T> {
    let depth = source.io_profile().queue_depth;
    let lane_count = depth.clamp(2, 4);
    let range_count = u64::from(domain.facts.range_count);
    if depth < 2 || range_count < 4 {
        return source.with_read_ahead(|source| operation(&mut SourceReader::Direct(source)));
    }
    // Each lane holds AHEAD_PER_LANE * 4 MiB buffers plus its own 4 MiB aligned buffer.
    let workspace = (lane_count * (AHEAD_PER_LANE + 1) * SPAN) as u64;
    let Ok(lease) = arena.reserve_spare_ram(workspace) else {
        return source.with_read_ahead(|source| operation(&mut SourceReader::Direct(source)));
    };
    let Some(buffers) = allocate_lane_buffers(lane_count) else {
        drop(lease);
        return source.with_read_ahead(|source| operation(&mut SourceReader::Direct(source)));
    };
    let Some(lanes) = source.read_lanes_if_available(lane_count, events)? else {
        drop(buffers);
        drop(lease);
        return source.with_read_ahead(|source| operation(&mut SourceReader::Direct(source)));
    };
    let image_length = domain.facts.image_length;
    let result = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(lanes.len());
        for (lane, lane_buffers) in lanes.into_iter().zip(buffers) {
            let (jobs_tx, jobs_rx) = mpsc::sync_channel::<(u64, usize)>(AHEAD_PER_LANE);
            let (results_tx, results_rx) =
                mpsc::sync_channel::<io::Result<Vec<u8>>>(AHEAD_PER_LANE);
            let (free_tx, free_rx) = mpsc::sync_channel::<Vec<u8>>(AHEAD_PER_LANE);
            for buffer in lane_buffers {
                let _ = free_tx.send(buffer);
            }
            scope.spawn(move || lane_loop(lane, jobs_rx, results_tx, free_rx));
            handles.push(LaneHandle {
                jobs: jobs_tx,
                results: results_rx,
                free: free_tx,
            });
        }
        let mut reader = SourceReader::Prefetched(PrefetchedSource::new(
            source,
            image_length,
            domain,
            range_count,
            old_zero_unread,
            handles,
        ));
        operation(&mut reader)
    });
    drop(lease);
    result
}
