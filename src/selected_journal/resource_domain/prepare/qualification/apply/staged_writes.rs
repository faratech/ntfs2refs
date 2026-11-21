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
//! What is written, in what order, and where the `apply-mid-ranges` hold
//! falls are the serial pass's: the hold is reached on the writing thread
//! after every range before ordinal `range_count / 2` was written and before
//! any range from it on is. The boot granule is not written here; the caller
//! writes it last, after its flush, as before. The pass that reads each
//! range before it writes it (`--verify thorough`, `--recheck-everything`,
//! the fault-injection path) stays on one thread (`write_span`).
use super::*;
use std::sync::mpsc;

/// Buffers in flight: one this thread fills, one queued, one being written.
const BUFFERS: usize = 3;

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

/// What the pass wrote, for the line it prints.
pub(super) struct Written {
    pub(super) ranges: u64,
    pub(super) bytes: u64,
    pub(super) writes: u64,
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
) -> Option<(crate::artifact_arena::ArenaRamLease, Vec<Vec<u8>>)> {
    let lease = arena
        .reserve_spare_ram(u64::try_from(BUFFERS * BUFFER).ok()?)
        .ok()?;
    let mut buffers = Vec::with_capacity(BUFFERS);
    for _ in 0..BUFFERS {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(BUFFER).ok()?;
        buffer.resize(BUFFER, 0);
        buffers.push(buffer);
    }
    Some((lease, buffers))
}

/// Writes every changed range of `domain` except the boot granule of a range
/// at offset 0, in ascending order, through `target`, reading their NEW
/// bytes from `journal` meanwhile.
pub(super) fn write_ranges(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    journal: &mut NativeSelectedJournal,
    domain: &ResourceJournalDomain<'_>,
    buffers: Vec<Vec<u8>>,
    journal_path: &Path,
) -> Result<Written> {
    let (recycle, free) = mpsc::channel::<Vec<u8>>();
    for buffer in buffers {
        recycle
            .send(buffer)
            .map_err(|_| anyhow::anyhow!("apply: write buffers could not be queued"))?;
    }
    let (stage, staged) = mpsc::sync_channel::<Staged>(BUFFERS);
    let (read, written) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || write_staged(target, staged, recycle));
        let read = read_staged(journal, domain, &free, stage, journal_path);
        (read, writer.join())
    });
    // The writer's error, if it has one, is about ranges before any the
    // reading thread came to: the serial pass would have stopped there.
    let writes = match written {
        Err(_) => anyhow::bail!("apply: the thread writing the changed ranges panicked"),
        Ok(written) => written?,
    };
    let (ranges, bytes) = read?;
    Ok(Written {
        ranges,
        bytes,
        writes,
    })
}

/// The reading thread: every range's descriptor and NEW bytes, staged in
/// order. Returns the ranges and the bytes staged.
fn read_staged(
    journal: &mut NativeSelectedJournal,
    domain: &ResourceJournalDomain<'_>,
    free: &mpsc::Receiver<Vec<u8>>,
    stage: mpsc::SyncSender<Staged>,
    journal_path: &Path,
) -> Result<(u64, u64)> {
    let range_count = u64::from(domain.facts().range_count);
    let send = |item: Staged| stage.send(item).map_err(|_| WriterStopped);
    let mut staged_bytes = 0u64;
    for ordinal in 0..range_count {
        if ordinal == range_count / 2 {
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
            let mut bytes = free.recv().map_err(|_| WriterStopped)?;
            let count = usize::try_from((length - done).min(bytes.len() as u64))?;
            let within = add(skip, done)?;
            read_new(domain, journal, row, ordinal, within, &mut bytes[..count])
                .with_context(context)?;
            send(Staged::Write(Stage {
                offset: add(row.capture.offset, within)?,
                length: count,
                bytes,
                first: ordinal,
                last: ordinal,
            }))?;
            done = add(done, count as u64)?;
        }
        staged_bytes = add(staged_bytes, length)?;
    }
    Ok((range_count, staged_bytes))
}

/// The writing thread: each staged write in order, and the hold where it
/// falls. Returns the writes made.
fn write_staged(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    staged: mpsc::Receiver<Staged>,
    recycle: mpsc::Sender<Vec<u8>>,
) -> Result<u64> {
    let _sampled = n2r_win32::stack_sampler::helper();
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
        target
            .seek(SeekFrom::Start(offset))
            .with_context(context)?;
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
