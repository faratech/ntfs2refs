//! A lifecycle marker whose write was interrupted.
//!
//! A journal records its lifecycle in single 4,096-byte marker granules and
//! reads them back exactly: a granule is clear, or it is one of the journal's
//! own markers, or the journal is refused. A power loss or host crash in the
//! middle of a marker write can leave the granule partly written. Recovery
//! used to refuse that for good, in both directions, with the disk offline and
//! every journaled byte intact.
//!
//! A marker is written, flushed and read back before the run does anything
//! that depends on it. A granule found partly written was therefore never
//! relied on: the run stopped inside that write. This module recognises that
//! and nothing else:
//!
//! - the granule is made only of whole 512-byte sectors of what it held
//!   before and of the marker that was being written (a disk replaces a
//!   sector as a whole), and is neither of the two;
//! - the journal's other marker granule holds exactly what it holds while
//!   that marker is written;
//! - the marker is this journal's own: it carries the journal's digests;
//! - the caller has seen the source in the state that marker is written in.
//!
//! A byte that fits none of this is still refused, as before.
//!
//! What is found is settled by writing that one granule, before a recovery
//! command reads the lifecycle: the granule is put back to what it held
//! before the write, so the journal is where it was. (One journal cannot say
//! which of two intents was being written over the other; see
//! `lab_reconstruct::interrupted_marker_writes`.) Recovery then runs as it
//! always does, from exact markers, and repeats every check of the source
//! before it writes a byte or records a completion. No check is changed, and
//! the journal format is the same. Commands that only inspect or finalize do
//! not settle anything: they refuse such a journal as before.
use crate::lab_reconstruct::DurableIo;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

pub(crate) const GRANULE: usize = 4096;
/// The smallest unit a disk replaces as a whole.
const SECTOR: usize = 512;
pub(crate) type Granule = [u8; GRANULE];

/// Whether `observed` is what an interrupted write of `after` over `before`
/// leaves: every sector is one or the other, and the granule as a whole is
/// neither.
pub(crate) fn is_interrupted_write(observed: &Granule, before: &Granule, after: &Granule) -> bool {
    observed != before
        && observed != after
        && (0..GRANULE).step_by(SECTOR).all(|at| {
            let sector = &observed[at..at + SECTOR];
            sector == &before[at..at + SECTOR] || sector == &after[at..at + SECTOR]
        })
}

/// Whether a granule could be a partly written marker at all: it is not
/// clear, and its closing digest does not cover it. Every marker of every
/// journal ends in the SHA-256 of the bytes before it, so a whole marker
/// never passes this. Used where the exact markers are costly to derive.
pub(crate) fn may_be_partly_written(observed: &Granule) -> bool {
    observed.iter().any(|&byte| byte != 0)
        && observed[GRANULE - 32..] != Sha256::digest(&observed[..GRANULE - 32])[..]
}

/// The marker write that was cut short. A route uses this to say which state
/// of the source that marker is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Marker {
    ApplyIntent,
    RollbackIntent,
    Handoff,
    /// The completion of a rollback, beside its rollback intent.
    AbortAfterRollback,
    /// The completion of an abandoned run, beside a clear intent.
    AbortAfterAbandon,
}

/// One marker write, and how it is settled when it is found interrupted.
pub(crate) struct MarkerWrite {
    pub marker: Marker,
    /// What the journal calls it, for the message.
    pub name: &'static str,
    /// Where its granule is in the journal.
    pub offset: u64,
    pub before: Granule,
    pub after: Granule,
    /// What the granule is set to.
    pub settled: Granule,
    /// How that reads: "not written" or "written".
    pub settled_as: &'static str,
    /// The journal's other marker granule: where it is, and what it may hold
    /// while this marker is written.
    pub beside: (u64, Vec<Granule>),
}

/// A marker write found interrupted. Nothing has been written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Found {
    pub marker: Marker,
    pub name: &'static str,
}

/// What was found and done, for the run's records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SettledMarker {
    pub marker: &'static str,
    pub settled_as: &'static str,
    pub journal_offset: u64,
    /// SHA-256 of the granule as it was found.
    pub found_sha256: String,
}

fn granule_at<J: Read + Seek>(journal: &mut J, offset: u64) -> Result<Granule> {
    let mut granule = [0u8; GRANULE];
    journal.seek(SeekFrom::Start(offset))?;
    journal
        .read_exact(&mut granule)
        .with_context(|| format!("reading the journal's marker granule at offset {offset}"))?;
    Ok(granule)
}

/// The one write in `writes` that the journal's marker granules show was
/// interrupted, if any. Reads only.
pub(crate) fn find<J: Read + Seek>(
    journal: &mut J,
    writes: &[MarkerWrite],
) -> Result<Option<usize>> {
    let mut found = None;
    for (index, write) in writes.iter().enumerate() {
        let observed = granule_at(journal, write.offset)?;
        if !is_interrupted_write(&observed, &write.before, &write.after) {
            continue;
        }
        let beside = granule_at(journal, write.beside.0)?;
        if !write.beside.1.contains(&beside) {
            continue;
        }
        ensure!(
            found.is_none(),
            "the journal's marker granules fit more than one interrupted marker write"
        );
        found = Some(index);
    }
    Ok(found)
}

/// `find`, as the marker a caller checks the source's state against.
pub(crate) fn found<J: Read + Seek>(
    journal: &mut J,
    writes: &[MarkerWrite],
) -> Result<Option<Found>> {
    Ok(find(journal, writes)?.map(|index| Found {
        marker: writes[index].marker,
        name: writes[index].name,
    }))
}

/// Settles the interrupted write `find` reports: writes its settled granule,
/// flushes, reads it back, and requires that nothing partly written is left.
/// Returns `None`, having written nothing, when there is none.
pub(crate) fn settle<J: DurableIo>(
    journal: &mut J,
    writes: &[MarkerWrite],
) -> Result<Option<SettledMarker>> {
    let Some(index) = find(journal, writes)? else {
        return Ok(None);
    };
    let write = &writes[index];
    let observed = granule_at(journal, write.offset)?;
    journal.seek(SeekFrom::Start(write.offset))?;
    journal
        .write_all(&write.settled)
        .with_context(|| format!("settling the partly written {} marker", write.name))?;
    journal.sync_all()?;
    ensure!(
        granule_at(journal, write.offset)? == write.settled,
        "the settled {} marker did not read back as written",
        write.name
    );
    ensure!(
        find(journal, writes)
            .context("reading the journal's markers after one was settled")?
            .is_none(),
        "the journal still holds a partly written marker after the {} marker was settled",
        write.name
    );
    Ok(Some(SettledMarker {
        marker: write.name,
        settled_as: write.settled_as,
        journal_offset: write.offset,
        found_sha256: hex::encode(Sha256::digest(observed)),
    }))
}

/// Refuses, having changed nothing, when the source disk is not in a state
/// the route writes that marker in. A marker is only written while the disk
/// is offline: with the read-only attribute still set (3) or cleared (1),
/// depending on the marker and the route. A partly written marker beside a
/// disk in any other state is not an interrupted write.
pub(crate) fn require_source_state(
    found: Found,
    journal: &std::path::Path,
    disk_number: impl std::fmt::Display,
    disk_attributes: u64,
    written_in: &[u64],
) -> Result<()> {
    ensure!(
        written_in.contains(&disk_attributes),
        "the recovery journal {} holds a partly written {} marker, but disk {disk_number} has \
         attributes {disk_attributes} and that marker is written only with {written_in:?} \
         (1 offline, 3 offline and read-only): this is not a marker write that was cut short, \
         and nothing was changed",
        journal.display(),
        found.name
    );
    Ok(())
}

/// Tells the operator what was found and done.
pub(crate) fn announce(settled: &SettledMarker, journal: &std::path::Path) {
    eprintln!(
        "The recovery journal {} held a partly written {} marker: the run stopped while writing \
         it. It is settled as {}, and recovery continues from there; every check of the source is \
         repeated before anything is written.",
        journal.display(),
        settled.marker,
        settled.settled_as
    );
}

#[cfg(test)]
mod tests {
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
    impl crate::lab_reconstruct::ReadSeek for Memory {
        fn byte_len(&mut self) -> std::io::Result<u64> {
            Ok(self.0.get_ref().len() as u64)
        }
    }
    impl DurableIo for Memory {
        fn sync_all(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A marker shaped like the journals' own: content in the first sector,
    /// the closing digest in the last.
    fn marker(tag: u8) -> Granule {
        let mut value = [0u8; GRANULE];
        value[..72].fill(tag);
        let hash = Sha256::digest(&value[..GRANULE - 32]);
        value[GRANULE - 32..].copy_from_slice(&hash);
        value
    }

    /// `after` written over `before`, stopped after the given sectors.
    fn stopped(before: &Granule, after: &Granule, written: &[usize]) -> Granule {
        let mut value = *before;
        for &sector in written {
            let at = sector * SECTOR;
            value[at..at + SECTOR].copy_from_slice(&after[at..at + SECTOR]);
        }
        value
    }

    #[test]
    fn only_whole_sectors_of_the_two_images_are_an_interrupted_write() {
        let zero = [0u8; GRANULE];
        let a = marker(1);
        let b = marker(2);
        // Neither the image before nor the image after is interrupted.
        assert!(!is_interrupted_write(&zero, &zero, &a));
        assert!(!is_interrupted_write(&a, &zero, &a));
        // Either end written first, over a clear granule or another marker.
        for (before, after) in [(&zero, &a), (&a, &b)] {
            assert!(is_interrupted_write(
                &stopped(before, after, &[0]),
                before,
                after
            ));
            assert!(is_interrupted_write(
                &stopped(before, after, &[7]),
                before,
                after
            ));
            assert!(is_interrupted_write(
                &stopped(before, after, &[0, 1, 2, 3]),
                before,
                after
            ));
        }
        // A sector that is neither image: one changed byte, a sector written
        // in part, a third marker's sector.
        let mut flipped = stopped(&zero, &a, &[0]);
        flipped[5] ^= 1;
        assert!(!is_interrupted_write(&flipped, &zero, &a));
        let mut partial = zero;
        partial[..40].copy_from_slice(&a[..40]);
        assert!(!is_interrupted_write(&partial, &zero, &a));
        assert!(!is_interrupted_write(&stopped(&zero, &b, &[0]), &zero, &a));
        let mut last_byte = a;
        last_byte[GRANULE - 1] ^= 1;
        assert!(!is_interrupted_write(&last_byte, &zero, &a));
    }

    #[test]
    fn a_whole_marker_and_a_clear_granule_are_never_partly_written() {
        let zero = [0u8; GRANULE];
        let a = marker(1);
        assert!(!may_be_partly_written(&zero));
        assert!(!may_be_partly_written(&a));
        assert!(may_be_partly_written(&stopped(&zero, &a, &[0])));
        assert!(may_be_partly_written(&stopped(&zero, &a, &[7])));
        assert!(may_be_partly_written(&stopped(&a, &marker(2), &[7])));
    }

    fn journal(first: &Granule, second: &Granule) -> Memory {
        let mut bytes = first.to_vec();
        bytes.extend_from_slice(second);
        bytes.extend_from_slice(&[0x5a; 64]);
        Memory(Cursor::new(bytes))
    }

    fn writes(intent: Granule, done: Granule) -> Vec<MarkerWrite> {
        let zero = [0u8; GRANULE];
        vec![
            MarkerWrite {
                marker: Marker::ApplyIntent,
                name: "intent",
                offset: GRANULE as u64,
                before: zero,
                after: intent,
                settled: zero,
                settled_as: "not written",
                beside: (0, vec![zero]),
            },
            MarkerWrite {
                marker: Marker::Handoff,
                name: "completion",
                offset: 0,
                before: zero,
                after: done,
                settled: zero,
                settled_as: "not written",
                beside: (GRANULE as u64, vec![intent]),
            },
        ]
    }

    #[test]
    fn settling_writes_one_granule_and_only_for_the_write_that_fits() {
        let zero = [0u8; GRANULE];
        let intent = marker(1);
        let done = marker(3);
        let writes = writes(intent, done);
        // Exact states: nothing found, nothing written.
        for (first, second) in [(&zero, &zero), (&zero, &intent), (&done, &intent)] {
            let mut exact = journal(first, second);
            let before = exact.0.get_ref().clone();
            assert_eq!(found(&mut exact, &writes).unwrap(), None);
            assert_eq!(settle(&mut exact, &writes).unwrap(), None);
            assert_eq!(exact.0.get_ref(), &before);
        }
        // A completion stopped part-way, beside the intent it needs.
        let torn = stopped(&zero, &done, &[0]);
        let mut interrupted = journal(&torn, &intent);
        assert_eq!(
            found(&mut interrupted, &writes).unwrap(),
            Some(Found {
                marker: Marker::Handoff,
                name: "completion"
            })
        );
        let settled = settle(&mut interrupted, &writes).unwrap().unwrap();
        assert_eq!(settled.marker, "completion");
        assert_eq!(settled.settled_as, "not written");
        assert_eq!(settled.found_sha256, hex::encode(Sha256::digest(torn)));
        assert_eq!(interrupted.0.get_ref(), journal(&zero, &intent).0.get_ref());
        // Settling again finds nothing.
        assert_eq!(settle(&mut interrupted, &writes).unwrap(), None);
        // The same granule beside anything else is not that write: untouched.
        let mut elsewhere = journal(&torn, &zero);
        let before = elsewhere.0.get_ref().clone();
        assert_eq!(settle(&mut elsewhere, &writes).unwrap(), None);
        assert_eq!(elsewhere.0.get_ref(), &before);
        // Two granules partly written at once fit no single write.
        let mut both = journal(&torn, &stopped(&zero, &intent, &[7]));
        let before = both.0.get_ref().clone();
        assert_eq!(settle(&mut both, &writes).unwrap(), None);
        assert_eq!(both.0.get_ref(), &before);
    }

    #[test]
    fn granules_that_fit_two_writes_are_refused_and_left_alone() {
        let zero = [0u8; GRANULE];
        let intent = marker(1);
        let done = marker(3);
        // A table that lists the same write twice: a mistake in a table must
        // stop the settle, not pick one.
        let mut ambiguous = writes(intent, done);
        ambiguous.extend(writes(intent, done));
        let mut interrupted = journal(&stopped(&zero, &done, &[0]), &intent);
        let before = interrupted.0.get_ref().clone();
        let refusal = format!("{:#}", settle(&mut interrupted, &ambiguous).unwrap_err());
        assert!(refusal.contains("more than one"), "{refusal}");
        assert_eq!(interrupted.0.get_ref(), &before);
    }

    #[test]
    fn a_marker_is_settled_only_beside_the_source_state_it_is_written_in() {
        let path = std::path::Path::new("journal.n2r");
        let handoff = Found {
            marker: Marker::Handoff,
            name: "handoff",
        };
        require_source_state(handoff, path, 4, 1, &[1]).unwrap();
        require_source_state(handoff, path, 4, 3, &[1, 3]).unwrap();
        for (attributes, written_in) in [(0, &[1][..]), (2, &[1, 3]), (3, &[1]), (1, &[3])] {
            let refusal = format!(
                "{:#}",
                require_source_state(handoff, path, 4, attributes, written_in).unwrap_err()
            );
            assert!(
                refusal.contains(&format!("disk 4 has attributes {attributes}")),
                "{refusal}"
            );
            assert!(refusal.contains("journal.n2r"), "{refusal}");
            assert!(refusal.contains("nothing was changed"), "{refusal}");
        }
    }
}
