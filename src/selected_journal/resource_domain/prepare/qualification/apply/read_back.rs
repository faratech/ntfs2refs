//! The read-back of the changed ranges after a fresh apply, with two reads
//! outstanding (#249).
//!
//! After its flush the apply reads every changed range back and holds the
//! framed digest of them to the journal's NEW digest
//! (`check_selected_reaching`): one read at a time through the writer's
//! handle, 41 s on the full Windows volume. The lab's disks (and most that
//! report no seek penalty) deliver about twice as much with two reads
//! outstanding (`io_profile`). Here the ranges are gathered into spans of up
//! to 4 MiB (ranges with no more than [`BRIDGE`] between them, as read-ahead
//! groups them), and the spans are read alternately through the writer's
//! handle and through one more read-only handle on the same disk
//! (`BorrowedPagedWriter::read_lanes`, which proves it reaches the same disk
//! in the same state), each on its own thread. This thread hashes them, in
//! the order of the spans: each range's frame, then its bytes, exactly as
//! `check_selected_reaching` hashes them, so the digest is the same. The
//! bytes between ranges that a span reads are not hashed.
//!
//! Both handles are unbuffered: every byte comes from the device, after the
//! flush, as through read-ahead off. The pass writes nothing.
use super::*;
use std::{collections::VecDeque, sync::mpsc};

/// A gap between two ranges that one read bridges, as read-ahead bridges it
/// (`AscendingRanges`).
const BRIDGE: u64 = 64 * 1024;

/// The longest span: one native request.
const SPAN: usize = n2r_win32::BorrowedPagedWriter::MAX_WRITE;

/// Spans each reader may hold, read or being read, beside those hashed.
const AHEAD: usize = 2;

/// Maximum concurrent unbuffered readers during read-back (writer + up to 3
/// extra read lanes, matching the 4-lane NVMe/virtual-SCSI sweet spot).
const MAX_READERS: usize = 4;

/// The memory the pass holds beyond the caller's for `readers` concurrent
/// handles: each reader's `AHEAD` buffers, each extra handle's aligned buffer,
/// and the digest worker's two buffers.
const fn workspace_for(readers: usize) -> u64 {
    ((readers * AHEAD + (readers - 1) + 2) * SPAN) as u64
}

/// What a multi-handle read-back holds: the spare memory that pays for it,
/// every reader's buffers, and the extra read handles.
pub(super) struct TwoHandles {
    _lease: crate::artifact_arena::ArenaRamLease,
    buffers: Vec<Vec<u8>>,
    lanes: Vec<n2r_win32::GeneralFrozenLane>,
}

/// Why the read-back reads through the writer's handle alone, with the OS
/// error where one said why, for the native event that records it.
#[derive(Debug)]
pub(super) struct OneHandle {
    reason: String,
    native_error: Option<i32>,
}

impl OneHandle {
    fn because(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            native_error: None,
        }
    }

    /// The native event that records that the read-back reads through the
    /// writer's handle alone, and why.
    pub(super) fn event(&self) -> n2r_win32::NativeEvent {
        n2r_win32::NativeEvent {
            operation: "apply-read-back-on-one-handle".into(),
            control_code: 0,
            input: vec![],
            succeeded: true,
            native_error: self.native_error,
            output: self.reason.clone().into_bytes(),
        }
    }
}

/// Buffers for `readers` concurrent readers, or `None` where Windows has no
/// memory for them.
fn reader_buffers_for(readers: usize) -> Option<Vec<Vec<u8>>> {
    let mut buffers = Vec::with_capacity(readers * AHEAD);
    for _ in 0..readers * AHEAD {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(SPAN).ok()?;
        buffer.resize(SPAN, 0);
        buffers.push(buffer);
    }
    Some(buffers)
}

#[cfg(test)]
fn reader_buffers() -> Option<Vec<Vec<u8>>> {
    reader_buffers_for(2)
}

/// Everything a multi-handle read-back needs, or why it reads through the
/// writer's handle alone: a disk that serves one read at a time
/// (`io_profile`), spare memory or Windows memory refused, or extra handles
/// that could not be opened or did not reach the same disk in the same state.
/// Scales up to [`MAX_READERS`] (4) handles when queue depth and spare RAM
/// admit them, falling back to 2 handles before falling back to 1.
pub(super) fn prepare(
    target: &n2r_win32::BorrowedPagedWriter<'_>,
    arena: &crate::artifact_arena::ArtifactArena,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<TwoHandles, OneHandle> {
    let depth = target.io_profile().queue_depth;
    if depth < 2 {
        return Err(OneHandle::because(format!(
            "the disk serves one read at a time (queue depth {depth})"
        )));
    }
    let desired = depth.min(MAX_READERS);
    let (readers, lease) = match arena.reserve_spare_ram(workspace_for(desired)) {
        Ok(lease) => (desired, lease),
        Err(error) if desired > 2 => match arena.reserve_spare_ram(workspace_for(2)) {
            Ok(lease) => (2, lease),
            Err(_) => {
                return Err(OneHandle::because(format!(
                    "no spare memory for its buffers: {error:#}"
                )));
            }
        },
        Err(error) => {
            return Err(OneHandle::because(format!(
                "no spare memory for its buffers: {error:#}"
            )));
        }
    };
    let buffers = reader_buffers_for(readers)
        .ok_or_else(|| OneHandle::because("Windows has no memory for its buffers"))?;
    let extra = readers - 1;
    let lanes = match target.read_lanes(extra, events) {
        Ok(lanes) if lanes.len() == extra => lanes,
        Ok(_) => {
            return Err(OneHandle::because("fewer extra read handles were opened"));
        }
        Err(error) => {
            return Err(OneHandle {
                reason: format!("extra read handles could not be opened: {error}"),
                native_error: error.raw_os_error(),
            });
        }
    };
    Ok(TwoHandles {
        _lease: lease,
        buffers,
        lanes,
    })
}

/// Part of a range, `length` bytes at `offset` of the source; `frame` where
/// it begins its range (the range's offset and length), whose frame is
/// hashed in front of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Piece {
    offset: u64,
    length: u64,
    frame: Option<(u64, u64)>,
}

/// What one read covers: from the first piece's offset to the last one's
/// end, at most [`SPAN`] bytes.
#[derive(Debug, Default, PartialEq, Eq)]
struct Span {
    pieces: Vec<Piece>,
}

impl Span {
    fn start(&self) -> u64 {
        self.pieces.first().map_or(0, |piece| piece.offset)
    }
    fn end(&self) -> u64 {
        self.pieces
            .last()
            .map_or(0, |piece| piece.offset + piece.length)
    }
    fn length(&self) -> usize {
        (self.end() - self.start()) as usize
    }
}

/// Gathers the ranges, taken in ascending order, into spans.
struct Spans {
    open: Span,
}

impl Spans {
    fn new() -> Self {
        Self {
            open: Span::default(),
        }
    }

    /// Adds the range `length` bytes at `offset`; `done` is given each span
    /// that is complete.
    fn add(
        &mut self,
        offset: u64,
        length: u64,
        done: &mut impl FnMut(Span) -> Result<()>,
    ) -> Result<()> {
        let end = offset
            .checked_add(length)
            .context("read-back range overflow")?;
        let mut at = offset;
        while at < end {
            let room = if self.open.pieces.is_empty() {
                SPAN as u64
            } else {
                let (start, open_end) = (self.open.start(), self.open.end());
                if at < open_end || at - open_end > BRIDGE || at - start >= SPAN as u64 {
                    0
                } else {
                    SPAN as u64 - (at - start)
                }
            };
            if room == 0 {
                done(std::mem::take(&mut self.open))?;
                continue;
            }
            let count = (end - at).min(room);
            self.open.pieces.push(Piece {
                offset: at,
                length: count,
                frame: (at == offset).then_some((offset, length)),
            });
            at += count;
        }
        Ok(())
    }

    /// The last span, if any.
    fn finish(&mut self) -> Option<Span> {
        (!self.open.pieces.is_empty()).then(|| std::mem::take(&mut self.open))
    }
}

/// One reader's side: spans to read, buffers to read them into, what it
/// read.
struct Lane {
    jobs: mpsc::SyncSender<(u64, usize)>,
    results: mpsc::Receiver<Result<Vec<u8>>>,
    free: mpsc::Sender<Vec<u8>>,
}

/// Reads each span it is given, in order, into a buffer of its own.
fn read_spans<R: Read + Seek>(
    reader: &mut R,
    handle: &'static str,
    jobs: mpsc::Receiver<(u64, usize)>,
    results: mpsc::SyncSender<Result<Vec<u8>>>,
    free: mpsc::Receiver<Vec<u8>>,
) {
    let _sampled = n2r_win32::stack_sampler::helper();
    for (offset, length) in jobs {
        let Ok(mut buffer) = free.recv() else {
            return;
        };
        let read = reader
            .seek(SeekFrom::Start(offset))
            .and_then(|_| reader.read_exact(&mut buffer[..length]))
            .with_context(|| {
                format!(
                    "apply read-back: reading {length} bytes at source offset {offset} through the {handle}"
                )
            })
            .map(|()| buffer);
        let failed = read.is_err();
        if results.send(read).is_err() || failed {
            return;
        }
    }
}

/// Hashes the oldest span outstanding, when its reader has read it: each
/// range's frame where the range begins, then the range's bytes.
fn hash_next(
    aggregate: &mut n2r_win32::bulk_digest::HashedBehind,
    lanes: &[Lane],
    pending: &mut VecDeque<Span>,
    consumed: &mut u64,
) -> Result<()> {
    let span = pending
        .pop_front()
        .context("apply read-back: no span is outstanding")?;
    let side = (*consumed as usize) % lanes.len();
    let buffer = lanes[side]
        .results
        .recv()
        .map_err(|_| anyhow::anyhow!("apply read-back: a reading thread stopped"))??;
    let start = span.start();
    for piece in &span.pieces {
        if let Some((offset, length)) = piece.frame {
            aggregate.update(&offset.to_le_bytes())?;
            aggregate.update(&length.to_le_bytes())?;
        }
        let from = usize::try_from(piece.offset - start)?;
        aggregate.update(&buffer[from..from + usize::try_from(piece.length)?])?;
    }
    // A reader that stopped needs no buffer back.
    let _ = lanes[side].free.send(buffer);
    *consumed += 1;
    Ok(())
}

/// The framed digest of every changed range of `domain`, read back through
/// `target` and the extra handles of `two` with reads outstanding on each,
/// held to `expected` as `check_selected_reaching` holds it. `Ok(Err(_))`
/// where its reading threads could not be started: nothing was read or
/// hashed, and the caller reads back through `target` alone. A read that
/// fails on any handle, and a digest that differs, end the pass.
pub(super) fn check_selected_two_handles(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    two: TwoHandles,
    domain: &ResourceJournalDomain<'_>,
    algorithm: n2r_win32::bulk_digest::Algorithm,
    expected: [u8; 32],
) -> Result<Result<[u8; 32], OneHandle>> {
    let TwoHandles {
        _lease,
        buffers,
        mut lanes,
    } = two;
    let mut aggregate = n2r_win32::bulk_digest::HashedBehind::new(algorithm, SPAN)?;
    if let Some(one) = hash_multi_readers(
        (target, "writer's handle"),
        &mut lanes,
        u64::from(domain.facts.range_count),
        |ordinal| {
            domain
                .capture()
                .index()
                .range(ordinal)
                .map(|range| (range.offset, range.length))
        },
        buffers,
        &mut aggregate,
    )? {
        return Ok(Err(one));
    }
    let digest = aggregate.finish()?;
    ensure!(
        digest == expected,
        "fresh apply actual selected target digest differs"
    );
    Ok(Ok(digest))
}

#[cfg(test)]
fn hash_two_readers<A: Read + Seek + Send, B: Read + Seek + Send>(
    first: (&mut A, &'static str),
    second: (&mut B, &'static str),
    range_count: u64,
    range: impl FnMut(u64) -> Result<(u64, u64)>,
    buffers: Vec<Vec<u8>>,
    aggregate: &mut n2r_win32::bulk_digest::HashedBehind,
) -> Result<Option<OneHandle>> {
    let mut extras = [second.0];
    hash_multi_readers_named(
        first,
        &mut extras,
        second.1,
        range_count,
        range,
        buffers,
        aggregate,
    )
}

fn hash_multi_readers<A: Read + Seek + Send, B: Read + Seek + Send>(
    first: (&mut A, &'static str),
    extras: &mut [B],
    range_count: u64,
    range: impl FnMut(u64) -> Result<(u64, u64)>,
    buffers: Vec<Vec<u8>>,
    aggregate: &mut n2r_win32::bulk_digest::HashedBehind,
) -> Result<Option<OneHandle>> {
    let mut refs: Vec<&mut B> = extras.iter_mut().collect();
    hash_multi_readers_named(
        first,
        &mut refs,
        "extra read handle",
        range_count,
        range,
        buffers,
        aggregate,
    )
}

fn hash_multi_readers_named<A: Read + Seek + Send, B: Read + Seek + Send>(
    first: (&mut A, &'static str),
    extras: &mut [&mut B],
    extra_name: &'static str,
    range_count: u64,
    mut range: impl FnMut(u64) -> Result<(u64, u64)>,
    buffers: Vec<Vec<u8>>,
    aggregate: &mut n2r_win32::bulk_digest::HashedBehind,
) -> Result<Option<OneHandle>> {
    let reader_count = 1 + extras.len();
    if buffers.len() != reader_count * AHEAD || buffers.iter().any(|buffer| buffer.len() < SPAN) {
        return Ok(Some(OneHandle::because(
            "the read buffers are not those of the configured readers",
        )));
    }
    let mut buffers = buffers.into_iter();
    let mut lanes = Vec::with_capacity(reader_count);
    let mut readers = Vec::with_capacity(reader_count);
    for _ in 0..reader_count {
        let (jobs, queue) = mpsc::sync_channel::<(u64, usize)>(AHEAD);
        let (results, read) = mpsc::sync_channel::<Result<Vec<u8>>>(AHEAD);
        let (free, held) = mpsc::channel::<Vec<u8>>();
        // Its receiver is alive here: the send cannot fail.
        for buffer in buffers.by_ref().take(AHEAD) {
            let _ = free.send(buffer);
        }
        lanes.push(Lane {
            jobs,
            results: read,
            free,
        });
        readers.push((queue, results, held));
    }
    let not_started = |error: std::io::Error| OneHandle {
        reason: format!("a reading thread could not be started: {error}"),
        native_error: error.raw_os_error(),
    };
    std::thread::scope(|scope| -> Result<Option<OneHandle>> {
        let mut readers = readers.into_iter();
        let mut handles = Vec::with_capacity(reader_count);
        let (queue, results, held) = readers.next().context("apply read-back: no reader")?;
        let (reader, name) = first;
        match std::thread::Builder::new()
            .name("n2r-read-back".into())
            .spawn_scoped(scope, move || {
                read_spans(reader, name, queue, results, held);
            }) {
            Ok(h) => handles.push(h),
            Err(error) => return Ok(Some(not_started(error))),
        }
        for extra in extras.iter_mut() {
            let (queue, results, held) = readers.next().context("apply read-back: no reader")?;
            match std::thread::Builder::new()
                .name("n2r-read-back".into())
                .spawn_scoped(scope, move || {
                    read_spans(*extra, extra_name, queue, results, held);
                }) {
                Ok(h) => handles.push(h),
                Err(error) => {
                    drop(lanes);
                    for h in handles {
                        let _ = h.join();
                    }
                    return Ok(Some(not_started(error)));
                }
            }
        }
        let max_in_flight = (reader_count * AHEAD) as u64;
        let hashed = (|| -> Result<()> {
            let mut spans = Spans::new();
            let mut ready: VecDeque<Span> = VecDeque::new();
            let mut pending: VecDeque<Span> = VecDeque::new();
            let (mut dispatched, mut consumed) = (0u64, 0u64);
            let mut rows = 0..range_count;
            loop {
                let Some(span) = ready.pop_front() else {
                    match rows.next() {
                        Some(ordinal) => {
                            let (offset, length) = range(ordinal)?;
                            spans.add(offset, length, &mut |span| {
                                ready.push_back(span);
                                Ok(())
                            })?;
                        }
                        None => match spans.finish() {
                            Some(span) => ready.push_back(span),
                            None => break,
                        },
                    }
                    continue;
                };
                if dispatched - consumed == max_in_flight {
                    hash_next(aggregate, &lanes, &mut pending, &mut consumed)?;
                }
                let side = (dispatched as usize) % reader_count;
                if lanes[side]
                    .jobs
                    .send((span.start(), span.length()))
                    .is_err()
                {
                    // The reader stopped: its own error is among the results
                    // of the spans it was given before this one.
                    while consumed < dispatched {
                        hash_next(aggregate, &lanes, &mut pending, &mut consumed)?;
                    }
                    anyhow::bail!(
                        "apply read-back: a reading thread stopped before every range was read"
                    );
                }
                pending.push_back(span);
                dispatched += 1;
            }
            while consumed < dispatched {
                hash_next(aggregate, &lanes, &mut pending, &mut consumed)?;
            }
            Ok(())
        })();
        // Ends all readers: no more spans, and no buffers back.
        drop(lanes);
        let mut panicked = false;
        for h in handles {
            if h.join().is_err() {
                panicked = true;
            }
        }
        if panicked {
            anyhow::bail!("apply read-back: a reading thread panicked");
        }
        hashed.map(|()| None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(ranges: &[(u64, u64)]) -> Vec<Vec<Piece>> {
        let mut out = Vec::new();
        let mut spans = Spans::new();
        for &(offset, length) in ranges {
            spans
                .add(offset, length, &mut |span: Span| {
                    out.push(span.pieces);
                    Ok(())
                })
                .unwrap();
        }
        if let Some(span) = spans.finish() {
            out.push(span.pieces);
        }
        assert!(spans.finish().is_none());
        out
    }

    const MIB: u64 = 1024 * 1024;

    /// The framed digest of `ranges` of `image`, as `check_selected_reaching`
    /// computes it: one range after another, a megabyte at a time.
    fn serial(image: &[u8], ranges: &[(u64, u64)]) -> [u8; 32] {
        let mut hash = aggregate_pin_hash(n2r_win32::bulk_digest::Algorithm::WRITTEN).unwrap();
        for &(offset, length) in ranges {
            frame(&mut hash, &SelectedRange { offset, length }).unwrap();
            for bytes in image[offset as usize..(offset + length) as usize].chunks(BUFFER) {
                hash.update(bytes).unwrap();
            }
        }
        finish(hash).unwrap()
    }

    #[test]
    fn two_readers_give_the_digest_one_gives() {
        let image: Vec<u8> = (0..48 * MIB as usize)
            .map(|index| (index.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let mut ranges = Vec::new();
        let mut at = 0u64;
        for index in 0..900u64 {
            let length =
                4096 * (1 + (index * 7919) % 50) + if index % 97 == 0 { 5 * MIB } else { 0 };
            if at + length > image.len() as u64 {
                break;
            }
            ranges.push((at, length));
            at += length + 4096 * ((index * 104_729) % 24);
        }
        let mut first = std::io::Cursor::new(image.clone());
        let mut second = std::io::Cursor::new(image.clone());
        let mut hash = n2r_win32::bulk_digest::HashedBehind::new(
            n2r_win32::bulk_digest::Algorithm::WRITTEN,
            SPAN,
        )
        .unwrap();
        let started = hash_two_readers(
            (&mut first, "first"),
            (&mut second, "second"),
            ranges.len() as u64,
            |ordinal| Ok(ranges[ordinal as usize]),
            reader_buffers().unwrap(),
            &mut hash,
        )
        .unwrap();
        assert!(started.is_none(), "both readers started");
        assert_eq!(hash.finish().unwrap(), serial(&image, &ranges));
    }

    #[test]
    fn a_read_that_fails_is_the_error_of_the_pass() {
        let image = vec![7u8; 2 * MIB as usize];
        let ranges = [(0, 4096), (8 * MIB, 4096), (4096 * 3, 4096)];
        let mut first = std::io::Cursor::new(image.clone());
        let mut second = std::io::Cursor::new(image);
        let mut hash = n2r_win32::bulk_digest::HashedBehind::new(
            n2r_win32::bulk_digest::Algorithm::WRITTEN,
            SPAN,
        )
        .unwrap();
        let error = hash_two_readers(
            (&mut first, "first"),
            (&mut second, "second"),
            ranges.len() as u64,
            |ordinal| Ok(ranges[ordinal as usize]),
            reader_buffers().unwrap(),
            &mut hash,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("at source offset {}", 8 * MIB)),
            "{error:#}"
        );
    }

    #[test]
    fn ranges_close_together_share_a_span_and_far_ones_do_not() {
        let found = spans(&[(0, 4096), (8192, 4096), (8192 + 4096 + BRIDGE + 4096, 4096)]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].len(), 2, "a short gap is bridged");
        assert_eq!(found[1].len(), 1, "a gap beyond the bridge starts a span");
    }

    #[test]
    fn a_long_range_is_cut_into_spans_and_framed_once() {
        let found = spans(&[(4096, 9 * MIB)]);
        let pieces: Vec<Piece> = found.iter().flatten().copied().collect();
        assert_eq!(pieces.len(), 3);
        assert!(
            found
                .iter()
                .all(|span| span.iter().map(|p| p.length).sum::<u64>() <= SPAN as u64)
        );
        assert_eq!(pieces[0].frame, Some((4096, 9 * MIB)));
        assert!(pieces[1..].iter().all(|piece| piece.frame.is_none()));
        assert_eq!(pieces.iter().map(|p| p.length).sum::<u64>(), 9 * MIB);
    }

    #[test]
    fn every_range_is_covered_once_in_order_and_framed_once() {
        let mut ranges = Vec::new();
        let mut at = 0u64;
        for index in 0..2000u64 {
            let length = 4096 * (1 + (index * 7919) % 300);
            ranges.push((at, length));
            at += length + 4096 * ((index * 104_729) % 40);
        }
        let found = spans(&ranges);
        for span in &found {
            let start = span[0].offset;
            let last = span.last().unwrap();
            assert!(last.offset + last.length - start <= SPAN as u64);
        }
        let pieces: Vec<Piece> = found.into_iter().flatten().collect();
        let mut rebuilt: Vec<(u64, u64)> = Vec::new();
        for piece in &pieces {
            match piece.frame {
                Some(frame) => {
                    assert_eq!(frame.0, piece.offset);
                    rebuilt.push((piece.offset, piece.length));
                }
                None => {
                    let last = rebuilt.last_mut().unwrap();
                    assert_eq!(last.0 + last.1, piece.offset, "a piece continues its range");
                    last.1 += piece.length;
                }
            }
        }
        assert_eq!(rebuilt, ranges);
    }
}
