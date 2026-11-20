//! Verify once (owner, 2026-11-19; #148 phase 2, #110): in `--verify fast` a
//! run checks each thing once, and its handoff follows the one verification
//! of the converted volume instead of preceding it.
//!
//! Such a run writes every new byte, flushes it and reads it back as any
//! conversion does, then seals its source again (offline, read-only) under
//! the apply marker alone. The finalizer verifies the converted volume in
//! that state (the volume mounted read-only meanwhile) and writes the
//! handoff marker only when everything passed. Until then `--recover
//! --rollback` puts the NTFS volume back. A verification that fails leaves
//! the volume sealed and says how to try again and how to go back; nothing
//! is rolled back by itself.
//!
//! What such a run may do that another may not is decided by its recovery
//! publication alone (`verify_before_handoff`), which is pinned by the
//! checksum the run printed before it wrote anything. A `--verify thorough`
//! run, and a run of a build before this, records nothing and keeps the
//! flow it had: the handoff in the apply step, before anything is mounted.
//!
//! The seal is recorded in `verification-seal.json` beside the publication.
//! A recovery environment starts every disk offline and read-only, so there
//! the disk's attributes do not say whether the run was still writing or had
//! sealed its source; this record does. It is only ever a reason to leave
//! the disk sealed: without it recovery makes the disk writable and replays,
//! which is right for a source that holds every new byte as well.
use crate::selected_journal::SelectedLifecycle;
use anyhow::{Context, Result, ensure};
use n2r_win32::general_layout::GeneralDiskBinding;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

static CHOSEN: AtomicBool = AtomicBool::new(false);

/// Chooses, for the conversion of this process, the handoff after the
/// verification. Called once, before the recovery publication is written.
pub(crate) fn choose() {
    CHOSEN.store(true, Ordering::SeqCst);
}

/// Whether this process converts with its handoff after the verification.
pub(crate) fn chosen() -> bool {
    CHOSEN.load(Ordering::SeqCst)
}

/// What a publication records: nothing for a run that hands off in its apply
/// step, so that the records of every such run are byte for byte what they
/// were.
pub(crate) fn recorded() -> Option<bool> {
    chosen().then_some(true)
}

/// The name of the record of the seal, beside the recovery publication.
pub(crate) const RECORD_NAME: &str = "verification-seal.json";
const RECORD_KIND: &str = "ntfs2refs-verification-seal-v1";

/// What is recorded once the source is sealed offline and read-only again
/// under the apply marker alone, with every new byte written and read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    schema_version: u32,
    kind: String,
    /// The SHA-256 of the run's recovery publication.
    publication_sha256: String,
    source: GeneralDiskBinding,
    new_selected_sha256: String,
    grants_authority: bool,
}

impl Seal {
    fn new(
        publication_sha256: [u8; 32],
        source: &GeneralDiskBinding,
        new_selected_sha256: [u8; 32],
    ) -> Self {
        Self {
            schema_version: 1,
            kind: RECORD_KIND.into(),
            publication_sha256: hex::encode(publication_sha256),
            source: source.clone(),
            new_selected_sha256: hex::encode(new_selected_sha256),
            grants_authority: false,
        }
    }
}

pub(crate) fn record_path(publication: &Path) -> Result<PathBuf> {
    Ok(publication
        .parent()
        .context("the recovery publication has no directory")?
        .join(RECORD_NAME))
}

/// Whether the seal of this run is recorded. A record that is absent, empty
/// (withdrawn) or cut short is no record; one of another run is refused.
pub(crate) fn sealed(
    path: &Path,
    publication_sha256: [u8; 32],
    source: &GeneralDiskBinding,
    new_selected_sha256: [u8; 32],
) -> Result<bool> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "recovery: reading the record of the seal {}",
                    path.display()
                )
            });
        }
    };
    let Ok(record) = serde_json::from_slice::<Seal>(&bytes) else {
        // Withdrawn, or a write that a power cut ended: the source is then
        // treated as one that may still have been written to.
        return Ok(false);
    };
    ensure!(
        record == Seal::new(publication_sha256, source, new_selected_sha256),
        "the record of the seal {} belongs to another run, source or journal",
        path.display()
    );
    Ok(true)
}

/// Records the seal, flushed and read back. It is written whole under a
/// temporary name and renamed, so that a power cut leaves no record or a
/// whole one. A record of this run that is there already is kept: a recovery
/// that verifies again passes here again.
pub(crate) fn record_seal(
    path: &Path,
    publication_sha256: [u8; 32],
    source: &GeneralDiskBinding,
    new_selected_sha256: [u8; 32],
) -> Result<()> {
    if sealed(path, publication_sha256, source, new_selected_sha256)? {
        return Ok(());
    }
    let record = Seal::new(publication_sha256, source, new_selected_sha256);
    let bytes = serde_json::to_vec_pretty(&record)?;
    let written = (|| -> Result<()> {
        let partial = path.with_extension("json.partial");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&partial)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // Over a withdrawn record, if one is there.
        std::fs::rename(&partial, path)?;
        // Flushing the renamed file commits the file system's log, the
        // rename with it.
        OpenOptions::new().write(true).open(path)?.sync_all()?;
        let mut back = Vec::new();
        File::open(path)?.read_to_end(&mut back)?;
        ensure!(
            back == bytes,
            "the record read back differs from what was written"
        );
        Ok(())
    })();
    written.with_context(|| {
        format!(
            "verification before the handoff: recording the seal in {}",
            path.display()
        )
    })
}

/// Withdraws the record before the source is made writable again: emptied
/// and flushed first, so that a power cut cannot bring a whole record back,
/// then removed.
pub(crate) fn withdraw_seal(path: &Path) -> Result<()> {
    let withdrawn = (|| -> std::io::Result<()> {
        let file = match OpenOptions::new().write(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        file.set_len(0)?;
        file.sync_all()?;
        drop(file);
        std::fs::remove_file(path)
    })();
    withdrawn.with_context(|| {
        format!(
            "recovery: withdrawing the record of the seal {} before the source is made writable",
            path.display()
        )
    })
}

/// Whether a recovery environment leaves the source sealed: only a run with
/// the handoff after its verification, under the apply intent alone, whose
/// seal is recorded. Everything else is made writable there as before.
pub(crate) fn stays_sealed_in_recovery_environment(
    verify_before_handoff: bool,
    lifecycle: SelectedLifecycle,
    sealed: bool,
) -> bool {
    verify_before_handoff && lifecycle == SelectedLifecycle::ApplyIntent && sealed
}

/// Whether a source found online and read-only is one an interrupted
/// verification before the handoff left: such a run's apply intent alone,
/// with its seal recorded. Nothing was written to a read-only disk, so
/// sealing it again is what the verification would have done on its way out.
pub(crate) fn interrupted_verification_left_source_online(
    verify_before_handoff: bool,
    lifecycle: SelectedLifecycle,
    disk_attributes: u64,
    sealed: bool,
) -> bool {
    verify_before_handoff
        && lifecycle == SelectedLifecycle::ApplyIntent
        && disk_attributes == 2
        && sealed
}

/// Whether a rollback holds the restored NTFS volume to the fingerprint of
/// the run's frozen source before it is put online, as a review's rollback
/// does: every rollback of such a run that had written to its source. A run
/// whose journal does not restore what the source had free (`source_free`,
/// `--minimize-scratch`) is not held to it: that those sectors lie outside
/// the fingerprint has not been shown, and a false alarm would leave a
/// restored volume offline.
pub(crate) fn check_restored_source(
    verify_before_handoff: bool,
    found: SelectedLifecycle,
    source_free: bool,
) -> bool {
    verify_before_handoff
        && !source_free
        && matches!(
            found,
            SelectedLifecycle::ApplyIntent
                | SelectedLifecycle::RollbackIntent
                | SelectedLifecycle::Aborted
        )
}

/// What is said when the verification before the handoff did not pass: what
/// stopped it, on the first line (the one a log filter that keeps the
/// `error:` line keeps), then that nothing is committed and the two ways on.
/// It goes to the error stream with the failure.
pub(crate) fn failed_before_handoff(
    directory: &Path,
    sha256: &str,
    cause: &anyhow::Error,
) -> String {
    format!(
        "the converted volume did not pass its verification, or the verification could not be \
         completed: {cause:#}\n  \
         Nothing is committed: the handoff is not written and the converted volume was never \
         mounted writable, so the NTFS volume can still be put back. Nothing was rolled back.\n  \
         To verify again and finish: ntfs2refs --recover \"{dir}\" --recovery-sha256 {sha256}\n  \
         To put NTFS back:           ntfs2refs --recover \"{dir}\" --recovery-sha256 {sha256} --rollback",
        dir = directory.display()
    )
}
