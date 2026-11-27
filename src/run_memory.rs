//! The memory a run needs for a volume.
//!
//! Asked in two places, which must agree: by the check of a data volume
//! while it is online, and of the frozen source of a Windows volume, which
//! has no such check before it. A volume the machine cannot convert is
//! refused there, with the figure, before anything is built; it was found
//! out minutes or half an hour in, at whichever reservation came short.
use crate::{
    ntfs_admission,
    ntfs_inspect::{PagedInspection, RootFileDomain},
};
use anyhow::{Result, bail};

/// The free memory that leaves a run `ram` bytes: a run takes two thirds of
/// what is free (`drive_resource::budget`).
pub(crate) fn free_memory_for(ram: u64) -> u64 {
    ram.saturating_add(ram / 2)
}

/// The memory a run needs for a volume of this many objects.
///
/// Two things decide it. What a run is admitted with: its indexes, which
/// are held in memory, may take a quarter of the run's memory, and its
/// handles a 1024th (`SourceResourceAdmission::validate`). And what its
/// ledger of reservations then holds while it builds the new volume, which
/// is the larger for every volume the lab has run. What is held for every
/// file and directory was read from each step of runs of 100,000 and
/// 500,000 files (`memory-steps`): the new volume's record of the object
/// with its open handle, 3.4 KiB; the walks' row for it, 3.1 KiB; never
/// both in full at once, and 8 KiB are counted. A stream counts 1 KiB
/// more: its slot and runs in the placement indexes and the coordinates
/// kept from them. A tenth is counted beside those for what a step holds
/// of its own. (It was 0.35 while workspaces were sized by the largest row
/// the ledger admits; those follow the object now, and the sorts' batches
/// are fractions of the ledger that shrink with it.) Runs of 100,000 files
/// held to a limit bear it out: the estimate asks a limit of 977 MiB; the
/// run converts with 1,000 and with 850, where it could not do without 737,
/// and with 700 it stops with the source unchanged, at the walk of the new
/// volume in that build. Both current walk reports spill their rows to
/// working storage. Identity directories, validation indexes and
/// constructor handles still account for memory as object counts grow.
///
/// And 256 MiB whatever the volume holds: the observation of the source
/// through Windows keeps a window of 117 MiB and pays thirty-two times its
/// longest row (a directory of 20,000 entries is a row of 4 MiB), so a
/// volume of 20,000 files converts held to 506 MiB, where it could not do
/// without 283, and stops in that observation held to 256.
///
/// (Until reservations followed the volume the figure was four times this:
/// the placement index alone prepaid 8 KiB a stream, and a volume of
/// 500,000 files was refused with 15.6 GiB free.)
pub(crate) fn memory_needed(
    raw_identities: u64,
    files: u64,
    directories: u64,
    streams: u64,
) -> u64 {
    free_memory_for(ledger_needed(raw_identities, files, directories, streams))
}

/// What a run's ledger must be allowed to hold for such a volume: two
/// thirds of the free memory `memory_needed` asks.
///
/// A Windows volume's short names, which become links, are within what is
/// counted for an object: the lab's Windows volume (143,552 files and
/// directories, 107,606 streams, 112,609 such links) is asked 1,619 MiB by
/// this, and converted and started on a machine with 4 GB of RAM, whose
/// run was given 1,725 MiB and could not do without 1,195.
pub(crate) fn ledger_needed(
    raw_identities: u64,
    files: u64,
    directories: u64,
    streams: u64,
) -> u64 {
    let objects = files.saturating_add(directories);
    let indexes = raw_identities
        .saturating_mul(256)
        .saturating_add(objects.saturating_add(streams).saturating_mul(64));
    let handles = streams
        .saturating_mul(2)
        .saturating_add(objects)
        .saturating_add(8);
    let admitted = indexes.saturating_mul(4).max(handles.saturating_mul(1024));
    let ledger = streams
        .saturating_mul(LEDGER_BYTES_A_STREAM)
        .saturating_add(objects.saturating_mul(LEDGER_BYTES_AN_OBJECT))
        / (100 - LEDGER_FIXED_PERCENT)
        * 100;
    admitted.max(ledger).saturating_add(LEDGER_FIXED_BYTES)
}
/// What the ledger holds for a stream beside its file: the placement
/// indexes and the coordinates kept from them.
const LEDGER_BYTES_A_STREAM: u64 = 1024;
/// What the ledger holds for a file or directory, at the most.
const LEDGER_BYTES_AN_OBJECT: u64 = 8192;
/// The share of the ledger that reservations sized by the ledger take.
const LEDGER_FIXED_PERCENT: u64 = 10;
/// What a run holds whatever the volume holds.
const LEDGER_FIXED_BYTES: u64 = 256 << 20;

/// What a volume that needs more memory than there is, is refused with:
/// what it needs free, what is free, and, where the user set a limit that
/// is the smaller of the two, that it is the limit and what it would have
/// to be.
pub(crate) fn memory_refusal(needed: u64, free: u64, limit: Option<u64>) -> String {
    match limit {
        // A run uses two thirds of what is free: the limit it needs is two
        // thirds of the free memory it needs.
        Some(limit) if free_memory_for(limit) <= free => format!(
            "a conversion of this volume needs a memory limit of about {} MiB, and --memory-limit gives it {} MiB. Give it more, or leave the limit out",
            // Rounded up: a limit of the figure given has to be enough.
            (needed / 3 * 2).div_ceil(1 << 20),
            limit >> 20
        ),
        _ => format!(
            "a conversion of this volume needs about {} MiB of free memory, and {} MiB are free. Close other programs, or convert on a machine with more memory",
            needed >> 20,
            free >> 20
        ),
    }
}

/// What a volume that needs more memory than is free comes to.
pub(crate) enum Short {
    /// The run goes ahead, slower: said before it starts.
    GoesOn(String),
    /// It is refused, with the figures.
    Refused(String),
}

/// A volume needs `needed` bytes of free memory and `free` are free.
///
/// A run whose user set a limit is held to it and refused. A run without
/// one fits itself to the machine: the figure is advice. It goes ahead,
/// takes what is beyond its share of the free memory from the page file,
/// and is told that it will be slower. It stops for memory only where
/// Windows has none left to commit, which the ledger finds out when it
/// asks, not this estimate beforehand.
pub(crate) fn short_of_memory(needed: u64, free: u64) -> Short {
    let limit = n2r_win32::resource_native::memory_limit();
    if n2r_win32::resource_native::memory_fits_the_machine() {
        Short::GoesOn(format!(
            "this volume wants about {} MiB of free memory, and {} MiB are free. The conversion goes ahead and takes the rest from the page file, which makes it slower; closing other programs first makes it faster.",
            needed >> 20,
            free >> 20
        ))
    } else {
        Short::Refused(memory_refusal(needed, free, limit))
    }
}

/// Refuse the frozen source of a run that may hold `ram_bytes`, where its
/// volume needs more. Nothing was changed by then.
pub(crate) fn refuse_frozen_source(raw: &PagedInspection, ram_bytes: u64) -> Result<()> {
    let mut counts = ntfs_admission::TreeCounts::default();
    for ordinal in 0..raw.file_count() {
        let file = raw.file_shared(ordinal)?;
        if ntfs_admission::paged::internal_role(raw, &file)?.is_some() {
            continue;
        }
        counts.add(&file)?;
    }
    let ntfs_admission::TreeCounts {
        files,
        directories,
        streams,
        ..
    } = counts;
    let needed = ledger_needed(raw.file_count(), files, directories, streams);
    // A run held to a limit is measured against the limit, which is what
    // the estimate asks for: the ledger's own budget is the limit less what
    // the run's records take, and a run given exactly the limit it was
    // told to have was refused for that difference (1,517 MiB of a limit
    // of 1,619, the lab's Windows volume).
    let have =
        n2r_win32::resource_native::memory_limit().map_or(ram_bytes, |limit| limit.max(ram_bytes));
    if needed > have {
        match short_of_memory(free_memory_for(needed), free_memory_for(have)) {
            Short::GoesOn(note) => println!("Note: {note}"),
            Short::Refused(refusal) => bail!(
                "the volume has {files} file(s), {directories} directories and {streams} data stream(s): {refusal}. Nothing on it was changed"
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lab_windows_volume_fits_a_machine_with_four_gigabytes() {
        // Its run there was given 1,725 MiB and could not do without 1,195.
        let needed = ledger_needed(191_101, 107_000, 36_552, 107_606) >> 20;
        assert!((1_300..1_700).contains(&needed), "{needed}");
        // The check of a data volume asks the free memory that leaves a
        // run as much: half as much again.
        assert_eq!(
            memory_needed(191_101, 107_000, 36_552, 107_606),
            free_memory_for(ledger_needed(191_101, 107_000, 36_552, 107_606))
        );
    }
}
