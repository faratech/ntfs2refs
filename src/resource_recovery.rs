//! Explicit restart of the resource-profile conversion on its original owner.
//! Every decision comes from the actual held journal and offline device.
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    resource_preparation::{EventLog, PreparationObserver, create_external_output},
    selected_journal::{
        SelectedLifecycle, resource_domain::reopen::envelope::ReopenedResourceRecovery,
    },
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    PagedRecoveryDirection, general_layout::GeneralSourceShadowBinding,
    journal_file::GeneralJournalStorageBinding, tree_resources::ResourceBudget,
};
use std::{collections::BTreeSet, path::Path};

pub(crate) fn recover_resource_allocation_with_observer<O: PreparationObserver>(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    publication: &Path,
    publication_sha256: [u8; 32],
    mut resources: ResourceBudget,
    output: &Path,
    rollback: bool,
    observer: &mut O,
) -> Result<serde_json::Value> {
    resources.validate()?;
    ensure!(
        output.is_absolute() && !output.exists(),
        "fresh recovery output required"
    );
    let available = n2r_win32::resource_native::observe_available_resources(
        output.parent().context("recovery parent absent")?,
    )?;
    resources.scratch_bytes = resources
        .scratch_bytes
        .min(available.scratch_available_bytes / 2);
    available.validate_budget(resources)?;
    let _ancestry = create_external_output(output, &journal)?;
    let arena = ArtifactArena::new(
        output,
        resources,
        &[pair.source.clone(), pair.shadow.clone()],
    )?;
    let budget = SourceMetadataBudget::from_resource_budget(resources)?;
    let group = arena.reserve_group(ArtifactGroup::RecoveryCopy, budget.scratch_bytes)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(budget, group.clone())?;
    let mut events = EventLog::new(observer);
    events.phase("resource-recovery-reopen");
    let mut recovery = ReopenedResourceRecovery::open_observed_or_online_terminal(
        publication,
        publication_sha256,
        budget.record_bytes,
        &pair,
        &journal,
        &group,
        &scratch,
        &output.join("reopened-journal.index"),
        budget.scratch_bytes,
        &mut events,
    )?;
    let initial = recovery.observed_lifecycle();
    events.checkpoint()?;
    if recovery.mounted_source().is_some() {
        ensure!(
            matches!(
                (rollback, initial),
                (false, SelectedLifecycle::Handoff) | (true, SelectedLifecycle::Aborted)
            ),
            "requested direction conflicts with the actual online terminal journal"
        );
        let reconciliation =
            crate::resource_finalize::reconcile_online_terminal(&mut recovery, &mut events)?;
        return Ok(serde_json::json!({
            "kind":"resource-allocation-recovery-v1",
            "direction":if rollback { "rollback" } else { "resume" },
            "initial_lifecycle":initial,"already_online_terminal":true,
            "raw_replay_performed":false,"conversion_time_content_reverified":false,
            "reconciliation":reconciliation
        }));
    }
    // A run that stopped for review (#110): before either direction, the
    // whole partition must still be what it was at the stop. Nothing else
    // of the recovery differs for it until its rollback is checked below.
    let review = recovery.review_before_handoff();
    if review {
        let record_path = crate::review::record_path(publication)?;
        let record = crate::review::read_record(
            &record_path,
            publication_sha256,
            recovery.source(),
            recovery.ticket().new_selected_sha256,
        )?;
        if let Some(record) = record
            .as_ref()
            .filter(|_| crate::review::compare_before_direction(review, initial, true))
        {
            events.phase("resource-review-fingerprint-check");
            println!("Checking that the reviewed volume was not changed since the review stop.");
            let actual = recovery
                .whole_source_fingerprint(&mut events)
                .context("recovery of a review: fingerprinting the converted partition")?;
            if actual != record.volume_fingerprint {
                return Err(crate::review::changed_since_stop(&record_path));
            }
            events.checkpoint()?;
        }
    }
    let mut replayed = None;
    // A run cut off after it printed its "To recover:" line but before its
    // apply intent was durable wrote nothing to the source: the only way it
    // can end is with the NTFS volume back as it was, which is what the
    // printed command then does (the soak found the window, #177).
    let rollback = if !rollback && initial == SelectedLifecycle::PreparedClear {
        eprintln!(
            "Note: the conversion stopped before it wrote anything to the volume; there is nothing \
             to resume, so the NTFS volume is given back as it was."
        );
        true
    } else {
        rollback
    };
    // A rollback of a review run that wrote to its source is held to the
    // fingerprint of its frozen source before NTFS is put online. The
    // fingerprint is reopened here, before anything is written, so that a
    // run whose records cannot be checked is refused with nothing changed.
    let restored_source_check = if rollback && crate::review::check_restored_source(review, initial)
    {
        Some(
            crate::review::reopen_source_fingerprint(
                publication
                    .parent()
                    .context("the recovery publication has no directory")?,
                recovery.source_sha256(),
                recovery.source_inspection_sha256(),
                recovery.runtime_scratch(),
            )
            .context("rollback of a review: nothing was written")?,
        )
    } else {
        None
    };
    match (rollback, initial) {
        (true, SelectedLifecycle::PreparedClear) => {
            events.phase("resource-abandon-clear");
            recovery.abandon_clear(
                &group,
                &output.join("abandon-journal.index"),
                budget.scratch_bytes,
                &mut events,
            )?;
            events.checkpoint()?;
        }
        (false, SelectedLifecycle::ApplyIntent)
        | (true, SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent) => {
            events.phase("resource-recovery-replay");
            let direction = if rollback {
                PagedRecoveryDirection::Rollback
            } else {
                PagedRecoveryDirection::Resume
            };
            let outcome = recovery.replay_markerless(
                &group,
                &output.join("replay-journal.index"),
                budget.scratch_bytes,
                direction,
                |_| Ok(()),
                &mut events,
            )?;
            replayed = Some(outcome.selected);
            events.checkpoint()?;
        }
        (false, SelectedLifecycle::Handoff) | (true, SelectedLifecycle::Aborted) => (),
        (false, SelectedLifecycle::PreparedClear) => anyhow::bail!(
            "the conversion stopped before its apply intent was recorded: nothing was written \
             to the source and there is nothing to resume. Run the same recovery command with \
             --rollback to close the journal and return the NTFS volume"
        ),
        (false, SelectedLifecycle::RollbackIntent | SelectedLifecycle::Aborted) => anyhow::bail!(
            "a rollback is recorded in the journal ({initial:?}); a resume is closed. Run the \
             same recovery command with --rollback to finish it"
        ),
        (true, SelectedLifecycle::Handoff) => anyhow::bail!(
            "the ReFS handoff is recorded in the journal; a rollback is closed. Run the \
             recovery command without --rollback to finish the conversion"
        ),
    }
    if rollback {
        if let Some(fingerprint) = &restored_source_check {
            // Today nothing checks the bytes outside the journaled ranges
            // after a rollback; for a review run, whose converted volume was
            // mounted, the restored NTFS volume is held to the fingerprint
            // of the frozen source before it is put online.
            events.phase("resource-review-restored-source-check");
            println!("Checking the restored NTFS volume against the source as it was frozen.");
            ensure!(
                recovery.observed_lifecycle() == SelectedLifecycle::Aborted,
                "rollback of a review: the journal does not record the rollback as done"
            );
            ensure!(
                recovery.source_matches_frozen_fingerprint(fingerprint, &mut events)?,
                "rollback of a review: the restored NTFS volume differs from the fingerprint of \
                 its source as it was frozen before the conversion. It is left offline; the \
                 journal records the rollback. Nothing more is done: restore the volume from a \
                 backup"
            );
            events.checkpoint()?;
        }
        events.phase("resource-rollback-finalization");
        let mounted = recovery.restore_aborted(
            &group,
            &output.join("abort-journal.index"),
            budget.scratch_bytes,
            &mut events,
        )?;
        events.checkpoint()?;
        let expected: BTreeSet<_> = recovery
            .expected_mount_paths()
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        let first = n2r_win32::capture_mount_paths_general(mounted.clone(), &mut events)?;
        let before: BTreeSet<_> = first.paths.iter().map(|s| s.to_lowercase()).collect();
        // Windows gives the volume its letters back by itself where automatic
        // mounting is on; where it is off (`mountvol /N`) the NTFS volume is
        // back without them. Each original drive letter still missing is
        // given back, never taken from another volume. The volume is NTFS and
        // whole either way, so a letter that cannot be given back is reported,
        // not made the rollback's failure.
        let mut restored_letters = Vec::new();
        let mut letter_errors = Vec::new();
        for missing in expected.difference(&before) {
            if !crate::resource_finalize::is_drive_letter_root(missing) {
                continue;
            }
            events.checkpoint()?;
            match n2r_win32::restore_drive_letter_general_on(
                mounted.clone(),
                missing,
                "NTFS",
                &mut events,
            ) {
                Ok(_) => restored_letters.push(missing.clone()),
                Err(error) => letter_errors.push(format!("{}: {error}", missing.to_uppercase())),
            }
        }
        let paths = n2r_win32::capture_mount_paths_general(mounted.clone(), &mut events)?;
        let actual: BTreeSet<_> = paths.paths.iter().map(|s| s.to_lowercase()).collect();
        for error in &letter_errors {
            eprintln!(
                "Note: the NTFS volume is back, but its drive letter {error}. Give it a letter in \
                 Disk Management (or with mountvol)."
            );
        }
        events.checkpoint()?;
        return Ok(serde_json::json!({
            "kind":"resource-allocation-recovery-v1", "direction":"rollback",
            "initial_lifecycle":initial, "ntfs_mounted":true,
            "source":mounted, "selected_replay":replayed,
            "restore_required_selected_bytes_verified":true,
            "free_space_restored_byte_for_byte":false,
            "source_fingerprint_verified":restored_source_check.is_some(),
            "mount_paths_preserved": expected == actual,
            "expected_mount_paths": expected, "actual_mount_paths": actual,
            "restored_drive_letters": restored_letters,
            "drive_letter_restore_errors": letter_errors,
            "journal_aborted":true
        }));
    }
    // HND is terminal. Release the original source/journal owners before the
    // common finalizer reopens and independently authenticates those same
    // pinned artifacts; no opposite-direction replay is attempted.
    drop(recovery);
    drop(events);
    drop(scratch);
    drop(group);
    drop(arena);
    // From here on nothing is written to the source from the journal. Each
    // recovery file is hashed as it is reopened and then held; it need not be
    // hashed again at every later step of the finalizer.
    n2r_win32::verify_policy::check_once();
    let finalized = crate::resource_finalize::finalize_resource_handoff_with_observer(
        pair,
        journal,
        publication,
        publication_sha256,
        resources,
        &output.join("finalization"),
        observer,
    )?;
    Ok(serde_json::json!({
        "kind":"resource-allocation-recovery-v1", "direction":"resume",
        "initial_lifecycle":initial, "selected_replay":replayed,
        "finalization":finalized
    }))
}
