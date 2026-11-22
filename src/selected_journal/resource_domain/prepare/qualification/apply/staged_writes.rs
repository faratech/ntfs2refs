//! The write pass of a fresh apply that verifies each thing once, on two
//! threads (#249).
//!
//! Under `--verify fast` the pass reads nothing of the source: for each
//! changed range it holds the journal's descriptor to the capture domain
//! (`record`), reads the range's NEW bytes from the journal (`read_new`) and
//! writes them. Done in turn on one thread, the journal reads and the device
//! writes never overlapped: 106 s on the full Windows volume, of which the
//! device writes were 50 s. Here this thread reads the journal into a few
//! buffers, in the order of the ranges, and a second thread writes them in
//! that same order, each through the same writer and its `permits()`.
//!
//! The ranges are runs of changed 4 KiB blocks, cut where the kind of their
//! bytes changes, so many follow one another directly. Those are written
//! together ([`Cuts`]): one write of up to 4 MiB, the writer's limit, where
//! the serial pass made one for each range, a megabyte at a time. The policy
//! (`permits`) accepts a write that spans adjacent ranges; a gap between two
//! ranges always ends a write. The bytes written and their order are the
//! same.
//!
//! What is written, in what order, and where the `apply-mid-ranges` hold
//! falls are the serial pass's: the hold is reached on the writing thread
//! after every range before ordinal `range_count / 2` was written and before
//! any range from it on is, and no write spans it. The boot granule is not
//! written here; the caller writes it last, after its flush, as before. The
//! pass that reads each range before it writes it (`--verify thorough`,
//! `--recheck-everything`, the fault-injection path) stays on one thread,
//! range by range (`write_span`).
use super::*;
use std::sync::mpsc;

/// Buffers in flight: one this thread fills, one queued, one being written.
const BUFFERS: usize = 3;

/// Overlapped async write queue depth (4 KiB-aligned `WRITE` buffers) when
/// spare memory allows.
const OVERLAPPED_DEPTH: usize = 4;

/// The longest write: the writer's limit, one native request.
const WRITE: usize = n2r_win32::BorrowedPagedWriter::MAX_WRITE;

pub(super) struct StagedBuffers {
    buffers: Vec<Vec<u8>>,
    overlapped_depth: usize,
}

/// Cuts the changed ranges, taken in ascending order, into writes of up to
/// `limit` bytes: a part of a range that begins where the write being
/// staged ends joins it while it has room, and anything else begins a new
/// one.
struct Cuts {
    limit: usize,
    /// Where the write being staged begins and how long it is.
    open: Option<(u64, usize)>,
}

impl Cuts {
    fn new(limit: usize) -> Self {
        Self { limit, open: None }
    }

    /// The next `wanted` bytes of a range, at `offset`: how many of them go
    /// into one write, and whether that is the write being staged (`true`)
    /// or a new one that begins at `offset` (`false`), which ends the one
    /// being staged.
    fn next(&mut self, offset: u64, wanted: u64) -> (bool, usize) {
        let room = |length: usize| {
            usize::try_from(wanted).map_or(self.limit - length, |wanted| {
                wanted.min(self.limit - length)
            })
        };
        match self.open {
            Some((start, length))
                if length < self.limit && start.checked_add(length as u64) == Some(offset) =>
            {
                let count = room(length);
                self.open = Some((start, length + count));
                (true, count)
            }
            _ => {
                let count = room(0);
                self.open = Some((offset, count));
                (false, count)
            }
        }
    }

    /// The write being staged is complete: nothing joins it any more.
    fn close(&mut self) {
        self.open = None;
    }
}

/// One write staged for the writing thread, or the hold, in the order the
/// serial pass made them.
enum Staged {
    Write(Stage),
    Hold,
}

/// `length` bytes of `bytes` for `offset` of the source, from the changed
/// ranges `first..=last`.
struct Stage {
    offset: u64,
    length: usize,
    bytes: Vec<u8>,
    first: u64,
    last: u64,
}

/// What the pass wrote, for the line it prints: `serial` is the number of
/// writes the serial pass makes of the same ranges, a megabyte at a time.
pub(super) struct Written {
    pub(super) ranges: u64,
    pub(super) bytes: u64,
    pub(super) writes: u64,
    pub(super) serial: u64,
}

/// What the reading thread staged.
struct Read {
    ranges: u64,
    bytes: u64,
    serial: u64,
}

/// The writing thread stopped; what stopped it is its own error.
#[derive(Debug)]
struct WriterStopped;
impl std::fmt::Display for WriterStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("apply: the thread writing the changed ranges stopped")
    }
}
impl std::error::Error for WriterStopped {}

/// The buffers of the pass and the spare memory that pays for them, or
/// `None` where the ledger has none to spare or Windows no memory. They
/// only buy speed: the caller then writes range by range on its own thread,
/// as before.
pub(super) fn reserve(
    arena: &crate::artifact_arena::ArtifactArena,
) -> Option<(crate::artifact_arena::ArenaRamLease, StagedBuffers)> {
    // Prefer reserving both the staging buffers and the overlapped write
    // queue's aligned slots; fall back to staging buffers alone if tight.
    let (lease, overlapped_depth) = arena
        .reserve_spare_ram(u64::try_from((BUFFERS + OVERLAPPED_DEPTH) * WRITE).ok()?)
        .ok()
        .map(|lease| (lease, OVERLAPPED_DEPTH))
        .or_else(|| {
            arena
                .reserve_spare_ram(u64::try_from(BUFFERS * WRITE).ok()?)
                .ok()
                .map(|lease| (lease, 0))
        })?;
    let mut buffers = Vec::with_capacity(BUFFERS);
    for _ in 0..BUFFERS {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(WRITE).ok()?;
        buffer.resize(WRITE, 0);
        buffers.push(buffer);
    }
    Some((
        lease,
        StagedBuffers {
            buffers,
            overlapped_depth,
        },
    ))
}

/// Writes the `range_count` changed ranges of `domain` (the ticket's count,
/// as the serial pass takes it) except the boot granule of a range at
/// offset 0, in ascending order, through `target`, reading their NEW bytes
/// from `journal` meanwhile.
pub(super) fn write_ranges(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    journal: &mut NativeSelectedJournal,
    domain: &ResourceJournalDomain<'_>,
    range_count: u64,
    staged_buffers: StagedBuffers,
    journal_path: &Path,
) -> Result<Written> {
    let StagedBuffers {
        buffers,
        overlapped_depth,
    } = staged_buffers;
    let (recycle, free) = mpsc::channel::<Vec<u8>>();
    for buffer in buffers {
        recycle
            .send(buffer)
            .map_err(|_| anyhow::anyhow!("apply: write buffers could not be queued"))?;
    }
    let (stage, staged) = mpsc::sync_channel::<Staged>(BUFFERS);
    let (read, written) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || write_staged(target, staged, recycle, overlapped_depth));
        let read = read_staged(journal, domain, range_count, &free, stage, journal_path);
        (read, writer.join())
    });
    // The writer's error, if it has one, is about ranges before any the
    // reading thread came to: the serial pass would have stopped there.
    let writes = match written {
        Err(_) => anyhow::bail!("apply: the thread writing the changed ranges panicked"),
        Ok(written) => written?,
    };
    let read = read?;
    Ok(Written {
        ranges: read.ranges,
        bytes: read.bytes,
        writes,
        serial: read.serial,
    })
}

/// The reading thread: every range's descriptor and NEW bytes, staged in
/// order, ranges that follow one another directly in one write.
fn read_staged(
    journal: &mut NativeSelectedJournal,
    domain: &ResourceJournalDomain<'_>,
    range_count: u64,
    free: &mpsc::Receiver<Vec<u8>>,
    stage: mpsc::SyncSender<Staged>,
    journal_path: &Path,
) -> Result<Read> {
    let send = |item: Staged| stage.send(item).map_err(|_| WriterStopped);
    let mut cuts = Cuts::new(WRITE);
    let mut staging: Option<Stage> = None;
    let mut staged_bytes = 0u64;
    let mut serial = 0u64;
    for ordinal in 0..range_count {
        if ordinal == range_count / 2 {
            // Everything before the hold is written before it, and no write
            // spans it.
            if let Some(complete) = staging.take() {
                send(Staged::Write(complete))?;
            }
            cuts.close();
            send(Staged::Hold)?;
        }
        let row = domain
            .row(ordinal)
            .with_context(|| format!("apply: changed range {ordinal} of the capture domain"))?;
        let skip = if row.capture.offset == 0 { GRANULE } else { 0 };
        // The boot granule of a range at offset 0 is written last, on its
        // own. A range there shorter than one granule cannot be split.
        let length = row.capture.length.checked_sub(skip).with_context(|| {
            format!(
                "apply: changed range {ordinal} at source offset 0 is {} bytes, shorter than the {GRANULE}-byte boot granule",
                row.capture.length
            )
        })?;
        let context = || {
            format!(
                "apply: changed range {ordinal} (source offset {}, {} bytes) in journal {}",
                row.capture.offset,
                row.capture.length,
                journal_path.display()
            )
        };
        // As `write_span`: the journal's descriptor is the held domain's.
        record(row, domain, journal).with_context(context)?;
        let mut done = 0u64;
        while done < length {
            let within = add(skip, done)?;
            let offset = add(row.capture.offset, within)?;
            let (joins, count) = cuts.next(offset, length - done);
            if !joins {
                if let Some(complete) = staging.take() {
                    send(Staged::Write(complete))?;
                }
                staging = Some(Stage {
                    offset,
                    length: 0,
                    bytes: free.recv().map_err(|_| WriterStopped)?,
                    first: ordinal,
                    last: ordinal,
                });
            }
            let open = staging
                .as_mut()
                .context("apply: no write is staged for the next changed bytes")?;
            ensure!(
                open.offset.checked_add(open.length as u64) == Some(offset)
                    && open.length + count <= open.bytes.len(),
                "apply: changed range {ordinal} at source offset {offset} does not continue its staged write"
            );
            read_new(
                domain,
                journal,
                row,
                ordinal,
                within,
                &mut open.bytes[open.length..open.length + count],
            )
            .with_context(context)?;
            open.length += count;
            open.last = ordinal;
            done = add(done, count as u64)?;
        }
        staged_bytes = add(staged_bytes, length)?;
        serial = add(serial, length.div_ceil(BUFFER as u64))?;
    }
    if let Some(complete) = staging.take() {
        send(Staged::Write(complete))?;
    }
    Ok(Read {
        ranges: range_count,
        bytes: staged_bytes,
        serial,
    })
}

/// The writing thread: each staged write in order, and the hold where it
/// falls. Returns the writes made.
fn write_staged(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    staged: mpsc::Receiver<Staged>,
    recycle: mpsc::Sender<Vec<u8>>,
    overlapped_depth: usize,
) -> Result<u64> {
    let _sampled = n2r_win32::stack_sampler::helper();
    if overlapped_depth >= 2 && target.io_profile().queue_depth >= 2 {
        if let Ok(mut queue) = target.open_overlapped_writer(overlapped_depth) {
            let mut writes = 0u64;
            for item in staged {
                let Stage {
                    offset,
                    length,
                    bytes,
                    first,
                    last,
                } = match item {
                    Staged::Hold => {
                        queue
                            .drain()
                            .context("apply: draining overlapped writes before lab hold")?;
                        n2r_win32::lab_hold::reached("apply-mid-ranges");
                        continue;
                    }
                    Staged::Write(stage) => stage,
                };
                let context = || {
                    format!(
                        "apply: writing {length} bytes at source offset {offset} (changed ranges {first} to {last})"
                    )
                };
                queue
                    .submit(offset, &bytes[..length])
                    .with_context(context)?;
                writes += 1;
                let _ = recycle.send(bytes);
            }
            queue
                .drain()
                .context("apply: draining overlapped writes at end of pass")?;
            return Ok(writes);
        }
    }
    let mut writes = 0u64;
    for item in staged {
        let Stage {
            offset,
            length,
            bytes,
            first,
            last,
        } = match item {
            Staged::Hold => {
                n2r_win32::lab_hold::reached("apply-mid-ranges");
                continue;
            }
            Staged::Write(stage) => stage,
        };
        let context = || {
            format!(
                "apply: writing {length} bytes at source offset {offset} (changed ranges {first} to {last})"
            )
        };
        target.seek(SeekFrom::Start(offset)).with_context(context)?;
        let written = target.write(&bytes[..length]).with_context(context)?;
        ensure!(
            written == length,
            "short fresh selected target write: {written} of {length} bytes at source offset {offset} (changed ranges {first} to {last})"
        );
        writes += 1;
        // Where the reading thread has stopped, the buffer is dropped here.
        let _ = recycle.send(bytes);
    }
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;

    /// The writes `read_staged` makes of `ranges` (offset, length), cut
    /// as it cuts them, with a hold before range `hold`: each write's offset
    /// and length, or `None` for the hold.
    fn writes(ranges: &[(u64, u64)], limit: usize, hold: usize) -> Vec<Option<(u64, u64)>> {
        let mut cuts = Cuts::new(limit);
        let mut out: Vec<Option<(u64, u64)>> = Vec::new();
        for (ordinal, &(offset, length)) in ranges.iter().enumerate() {
            if ordinal == hold {
                cuts.close();
                out.push(None);
            }
            let mut done = 0;
            while done < length {
                let (joins, count) = cuts.next(offset + done, length - done);
                match out.last_mut() {
                    Some(Some((_, staged))) if joins => *staged += count as u64,
                    _ => {
                        assert!(!joins, "a write joined at {}", offset + done);
                        out.push(Some((offset + done, count as u64)));
                    }
                }
                done += count as u64;
            }
        }
        out
    }

    #[test]
    fn ranges_that_follow_one_another_are_written_together_up_to_the_limit() {
        let ranges = [
            (4 * KIB, 8 * KIB),
            (12 * KIB, 4 * KIB),
            (16 * KIB, 12 * KIB),
            (40 * KIB, 4 * KIB),
        ];
        assert_eq!(
            writes(&ranges, 16 * KIB as usize, usize::MAX),
            [
                Some((4 * KIB, 16 * KIB)),
                Some((20 * KIB, 8 * KIB)),
                Some((40 * KIB, 4 * KIB)),
            ],
            "a gap ends a write, and a full one is followed by a new one"
        );
    }

    #[test]
    fn a_long_range_is_cut_at_the_limit_and_the_next_one_continues_its_last_write() {
        let ranges = [(0, 40 * KIB), (40 * KIB, 4 * KIB)];
        assert_eq!(
            writes(&ranges, 16 * KIB as usize, usize::MAX),
            [
                Some((0, 16 * KIB)),
                Some((16 * KIB, 16 * KIB)),
                Some((32 * KIB, 12 * KIB)),
            ]
        );
    }

    #[test]
    fn no_write_spans_the_hold() {
        let ranges = [(0, 4 * KIB), (4 * KIB, 4 * KIB), (8 * KIB, 4 * KIB)];
        assert_eq!(
            writes(&ranges, 16 * KIB as usize, 1),
            [Some((0, 4 * KIB)), None, Some((4 * KIB, 8 * KIB))]
        );
    }

    #[test]
    fn the_bytes_and_their_order_are_those_of_the_ranges() {
        // Ranges of granules with gaps between some, cut at the writer's
        // limit: the writes cover exactly the ranges, in order, each within
        // the limit and on whole granules.
        let mut ranges = Vec::new();
        let mut at = GRANULE;
        for index in 0..500u64 {
            let length = GRANULE * (1 + (index * 7919) % 700);
            ranges.push((at, length));
            at += length + if index % 3 == 0 { GRANULE } else { 0 };
        }
        let cut = writes(&ranges, WRITE, 250);
        let mut covered = Vec::new();
        for (offset, length) in cut.iter().flatten() {
            assert!(*length as usize <= WRITE && *length > 0);
            assert!(offset.is_multiple_of(GRANULE) && length.is_multiple_of(GRANULE));
            covered.push((*offset, *length));
        }
        let merge = |list: &[(u64, u64)]| {
            let mut merged: Vec<(u64, u64)> = Vec::new();
            for &(offset, length) in list {
                match merged.last_mut() {
                    Some((start, staged)) if *start + *staged == offset => *staged += length,
                    _ => merged.push((offset, length)),
                }
            }
            merged
        };
        assert_eq!(merge(&covered), merge(&ranges));
        assert!(covered.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0));
        assert!(cut.len() - 1 < ranges.len(), "adjacent ranges were merged");
    }
}
