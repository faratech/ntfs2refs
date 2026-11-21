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

/// The memory the pass holds beyond the caller's: each reader's buffers and
/// the extra handle's own aligned buffer.
pub(super) const WORKSPACE: u64 = ((2 * AHEAD + 1) * SPAN) as u64;

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
    aggregate: &mut crate::selected_journal::PinHash,
    lanes: &[Lane],
    pending: &mut VecDeque<Span>,
    consumed: &mut u64,
) -> Result<()> {
    let span = pending
        .pop_front()
        .context("apply read-back: no span is outstanding")?;
    let side = usize::from(*consumed % 2 == 1);
    let buffer = lanes[side]
        .results
        .recv()
        .map_err(|_| anyhow::anyhow!("apply read-back: a reading thread stopped"))??;
    let start = span.start();
    for piece in &span.pieces {
        if let Some((offset, length)) = piece.frame {
            frame(aggregate, &SelectedRange { offset, length })?;
        }
        let from = usize::try_from(piece.offset - start)?;
        // A megabyte at a time, as the aggregate takes them.
        for bytes in buffer[from..from + usize::try_from(piece.length)?].chunks(BUFFER) {
            aggregate.update(bytes)?;
        }
    }
    // A reader that stopped needs no buffer back.
    let _ = lanes[side].free.send(buffer);
    *consumed += 1;
    Ok(())
}

/// The framed digest of every changed range of `domain`, read back through
/// `target` and `lane` with a read outstanding on each, held to `expected`
/// as `check_selected_reaching` holds it.
pub(super) fn check_selected_two_handles(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    mut lane: n2r_win32::GeneralFrozenLane,
    domain: &ResourceJournalDomain<'_>,
    algorithm: n2r_win32::bulk_digest::Algorithm,
    expected: [u8; 32],
) -> Result<[u8; 32]> {
    let mut aggregate = aggregate_pin_hash(algorithm)?;
    hash_two_readers(
        (target, "writer's handle"),
        (&mut lane, "second read handle"),
        u64::from(domain.facts.range_count),
        |ordinal| {
            domain
                .row(ordinal)
                .map(|row| (row.capture.offset, row.capture.length))
        },
        &mut aggregate,
    )?;
    let digest = finish(aggregate)?;
    ensure!(
        digest == expected,
        "fresh apply actual selected target digest differs"
    );
    Ok(digest)
}

/// Frames and hashes into `aggregate` the `range_count` ranges `range`
/// gives (offset and length, ascending), read in spans alternately through
/// `first` and `second`, each on a thread of its own.
fn hash_two_readers<A: Read + Seek + Send, B: Read + Seek + Send>(
    first: (&mut A, &'static str),
    second: (&mut B, &'static str),
    range_count: u64,
    mut range: impl FnMut(u64) -> Result<(u64, u64)>,
    aggregate: &mut crate::selected_journal::PinHash,
) -> Result<()> {
    let mut lanes = Vec::with_capacity(2);
    let mut readers = Vec::with_capacity(2);
    for _ in 0..2 {
        let (jobs, queue) = mpsc::sync_channel::<(u64, usize)>(AHEAD);
        let (results, read) = mpsc::sync_channel::<Result<Vec<u8>>>(AHEAD);
        let (free, buffers) = mpsc::channel::<Vec<u8>>();
        for _ in 0..AHEAD {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(SPAN)
                .map_err(|_| anyhow::anyhow!("apply read-back: no memory for a read buffer"))?;
            buffer.resize(SPAN, 0);
            free.send(buffer).map_err(|_| {
                anyhow::anyhow!("apply read-back: a read buffer could not be queued")
            })?;
        }
        lanes.push(Lane {
            jobs,
            results: read,
            free,
        });
        readers.push((queue, results, buffers));
    }
    std::thread::scope(|scope| -> Result<()> {
        let mut readers = readers.into_iter();
        let (queue, results, buffers) = readers.next().context("apply read-back: no reader")?;
        let (reader, name) = first;
        let first = scope.spawn(move || {
            read_spans(reader, name, queue, results, buffers);
        });
        let (queue, results, buffers) = readers.next().context("apply read-back: no reader")?;
        let (reader, name) = second;
        let second = scope.spawn(move || {
            read_spans(reader, name, queue, results, buffers);
        });
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
                if dispatched - consumed == 2 * AHEAD as u64 {
                    hash_next(aggregate, &lanes, &mut pending, &mut consumed)?;
                }
                let side = usize::from(dispatched % 2 == 1);
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
        // Ends both readers: no more spans, and no buffers back.
        drop(lanes);
        let first = first.join();
        let second = second.join();
        if first.is_err() || second.is_err() {
            anyhow::bail!("apply read-back: a reading thread panicked");
        }
        hashed
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
        let mut hash = aggregate_pin_hash(n2r_win32::bulk_digest::Algorithm::WRITTEN).unwrap();
        hash_two_readers(
            (&mut first, "first"),
            (&mut second, "second"),
            ranges.len() as u64,
            |ordinal| Ok(ranges[ordinal as usize]),
            &mut hash,
        )
        .unwrap();
        assert_eq!(finish(hash).unwrap(), serial(&image, &ranges));
    }

    #[test]
    fn a_read_that_fails_is_the_error_of_the_pass() {
        let image = vec![7u8; 2 * MIB as usize];
        let ranges = [(0, 4096), (8 * MIB, 4096), (4096 * 3, 4096)];
        let mut first = std::io::Cursor::new(image.clone());
        let mut second = std::io::Cursor::new(image);
        let mut hash = aggregate_pin_hash(n2r_win32::bulk_digest::Algorithm::WRITTEN).unwrap();
        let error = hash_two_readers(
            (&mut first, "first"),
            (&mut second, "second"),
            ranges.len() as u64,
            |ordinal| Ok(ranges[ordinal as usize]),
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
