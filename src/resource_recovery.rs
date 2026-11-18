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
    let mut replayed = None;
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
