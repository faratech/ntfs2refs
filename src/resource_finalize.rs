//! Complete a real resource-profile HND through a protected native observer.
//! No source admission or replay authority is recreated during finalization.
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
    general_composite_target::paged_memory::ArenaReportMemory,
    general_reconstruct::fast_verification::v4_maps::reopened::ReopenedVerificationMetadata,
    general_shadow::PagedInputs,
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    resource_preparation::{EventLog, PreparationObserver, StdoutObserver, create_external_output},
    selected_journal::resource_domain::reopen::envelope::ReopenedResourceRecovery,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::GeneralSourceShadowBinding, journal_file::GeneralJournalStorageBinding,
    tree_resources::ResourceBudget,
};
use std::{collections::BTreeSet, path::Path};

/// Reconcile an already-online terminal state without replaying any bytes or
/// claiming that its current contents equal the conversion-time snapshot.
/// Applications may have used the volume since the original terminal mount.
pub(crate) fn reconcile_online_terminal<O: PreparationObserver>(
    recovery: &mut ReopenedResourceRecovery,
    events: &mut EventLog<'_, O>,
) -> Result<serde_json::Value> {
    use crate::selected_journal::SelectedLifecycle;
    let lifecycle = recovery.observed_lifecycle();
    ensure!(matches!(lifecycle, SelectedLifecycle::Handoff | SelectedLifecycle::Aborted),
        "online reconciliation requires a durable terminal lifecycle");
    events.phase("resource-online-terminal-reconcile");
    let mounted = recovery.revalidate_online_terminal(events)?;
    events.checkpoint()?;
    let filesystem = if lifecycle == SelectedLifecycle::Handoff { "ReFS" } else { "NTFS" };
    let desired = recovery.expected_source_label().clone();
    let initial = n2r_win32::volume_label::observe_label(mounted.clone(), filesystem)?;
    let mut label_action = "already-original";
    if initial.label != desired {
        let enrollment = n2r_win32::volume_label::VolumeLabel::from_text("n2r-retained-shadow")?;
        if lifecycle == SelectedLifecycle::Handoff && initial.label == enrollment {
            let restored = n2r_win32::volume_label::restore_verified_label(
                recovery.source(), &desired, mounted.clone(), &enrollment,
            )?;
            ensure!(restored.success, "terminal volume label restoration did not complete");
            label_action = "restored-enrollment-label";
        } else {
            // A later application/user may have deliberately changed it.
            label_action = "different-current-label-preserved";
        }
    }
    let expected: BTreeSet<_> = recovery.expected_mount_paths().iter()
        .map(|s| s.to_lowercase()).collect();
    let first = n2r_win32::capture_mount_paths_general(mounted.clone(), events)?;
    let actual_before: BTreeSet<_> = first.paths.iter().map(|s| s.to_lowercase()).collect();
    let mut attempted = Vec::new();
    for missing in expected.difference(&actual_before) {
        let bytes = missing.as_bytes();
        let letter = bytes.len() == 3 && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':' && bytes[2] == b'\\';
        if lifecycle == SelectedLifecycle::Handoff && letter {
            events.checkpoint()?;
            n2r_win32::restore_drive_letter_general(mounted.clone(), missing, events)
                .context("terminal drive letter is unavailable or could not be safely restored")?;
            attempted.push(missing.clone());
        }
    }
    let paths = n2r_win32::capture_mount_paths_general(mounted.clone(), events)?;
    let actual: BTreeSet<_> = paths.paths.iter().map(|s| s.to_lowercase()).collect();
    let missing: Vec<_> = expected.difference(&actual).cloned().collect();
    let current = n2r_win32::volume_label::observe_label(mounted.clone(), filesystem)?;
    recovery.revalidate_online_terminal(events)?;
    events.checkpoint()?;
    Ok(serde_json::json!({
        "kind":"resource-online-terminal-reconciliation-v1",
        "terminal_lifecycle":lifecycle,"source":mounted,"filesystem":filesystem,
        "reconciliation_complete":missing.is_empty() && current.label == desired,
        "label_action":label_action,"label_matches_original":current.label == desired,
        "restored_drive_letters":attempted,"missing_original_mount_paths":missing,
        "additional_current_mount_paths_preserved":actual.difference(&expected).cloned().collect::<Vec<_>>(),
        "journal_terminal_verified":true,"raw_replay_performed":false,
        "conversion_time_content_reverified":false,
        "selected_bytes_compared_to_old_or_new":false
    }))
}

#[derive(Debug)]
pub(crate) struct CommittedFinalizationError {
    cause: anyhow::Error,
}
impl std::fmt::Display for CommittedFinalizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReFS conversion is committed and online; finalization is incomplete: {:#}",
            self.cause
        )
    }
}
impl std::error::Error for CommittedFinalizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

pub(crate) fn finalize_resource_handoff(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    publication: &Path,
    publication_sha256: [u8; 32],
    resources: ResourceBudget,
    output: &Path,
) -> Result<serde_json::Value> {
    let mut observer = StdoutObserver;
    finalize_resource_handoff_with_observer(
        pair,
        journal,
        publication,
        publication_sha256,
        resources,
        output,
        &mut observer,
    )
}

pub(crate) fn finalize_resource_handoff_with_observer<O: PreparationObserver>(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    publication: &Path,
    publication_sha256: [u8; 32],
    mut resources: ResourceBudget,
    output: &Path,
    observer: &mut O,
) -> Result<serde_json::Value> {
    resources.validate()?;
    ensure!(
        output.is_absolute() && !output.exists(),
        "fresh finalization output required"
    );
    let available = n2r_win32::resource_native::observe_available_resources(
        output.parent().context("finalization parent absent")?,
    )?;
    // This new transient index arena does not reserve the original preparation
    // ceiling again. Existing authenticated artifacts retain their original
    // format bounds; leave half the current free space outside this arena.
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
    events.phase("resource-finalization-reopen");
    let mut recovery = ReopenedResourceRecovery::open_observed(
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
    events.checkpoint()?;
    events.phase("resource-handoff-authentication");
    let handoff = recovery.verify_handoff(
        &group,
        &output.join("verified-handoff.index"),
        budget.scratch_bytes,
        &mut events,
    )?;
    let metadata = ReopenedVerificationMetadata::open(&handoff)?;
    events.checkpoint()?;
    events.phase("resource-protected-verification");
    let mut protected = handoff.seal_for_protected_verification(
        &group,
        &output.join("protected-handoff.index"),
        budget.scratch_bytes,
        &mut events,
    )?;
    events.checkpoint()?;
    // The two GUID strings and expected-label copy remain paid through the
    // native callback; the decoded tree and report carry their own leases.
    let _small = arena.reserve_ram(1024 * 1024)?;
    let desired_label = protected.recovery().expected_source_label().clone();
    let native_pair = GeneralSourceShadowBinding {
        source: protected.recovery().source().clone(),
        shadow: protected.recovery().shadow().clone(),
    };
    let input = PagedInputs(metadata.expected());
    let payer = ArenaReportMemory(arena.clone());
    let admission = protected.recovery().resource_admission();
    let native = protected
        .source_mut()?
        .observe_converted_protected_with_memory(
            native_pair,
            &input,
            Some(&desired_label),
            |a, b| crate::ntfs_attestation::same_security(a, b).map_err(std::io::Error::other),
            n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(admission)),
            &payer,
            &mut events,
        )?;
    events.checkpoint()?;
    let maps = metadata.compare_protected(&protected, &native)?;
    let matching_bindings = maps.bindings();
    events.phase("resource-verified-handoff-online");
    let mounted = protected.bring_online_after_verified_observation(
        &native,
        &maps,
        &group,
        &output.join("online-handoff.index"),
        budget.scratch_bytes,
        &mut events,
    )?;
    let finish_online = (|| -> Result<serde_json::Value> {
        events.checkpoint()?;
        let converted = mounted.revalidate_handoff_artifacts_after_mount(&mut events)?;
        let current_label = n2r_win32::volume_label::observe_label(converted.clone(), "ReFS")?;
        let restored = n2r_win32::volume_label::restore_verified_label(
            mounted.source(),
            mounted.expected_source_label(),
            converted.clone(),
            &current_label.label,
        )?;
        ensure!(restored.success, "original volume label restoration failed");
        let mut paths = n2r_win32::capture_mount_paths_general(converted.clone(), &mut events)?;
        let expected_paths: BTreeSet<_> = mounted
            .expected_mount_paths()
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        let initial_paths: BTreeSet<_> = paths.paths.iter().map(|s| s.to_lowercase()).collect();
        for missing in expected_paths.difference(&initial_paths) {
            let bytes = missing.as_bytes();
            ensure!(
                bytes.len() == 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && bytes[2] == b'\\',
                "HND is closed; missing folder mount requires explicit rebinding: {missing}"
            );
            events.checkpoint()?;
            n2r_win32::restore_drive_letter_general(converted.clone(), missing, &mut events)
            .context("HND is closed; original drive letter could not be restored without reassigning another volume")?;
        }
        if !expected_paths.is_subset(&initial_paths) {
            paths = n2r_win32::capture_mount_paths_general(converted.clone(), &mut events)?;
        }
        let actual_paths: BTreeSet<_> = paths.paths.iter().map(|s| s.to_lowercase()).collect();
        ensure!(
            expected_paths == actual_paths,
            "original volume mount paths were not preserved"
        );
        mounted.revalidate_handoff_artifacts_after_mount(&mut events)?;
        events.checkpoint()?;
        let known = native
            .report()
            .content_observation
            .as_ref()
            .and_then(|o| o.known_content.as_ref())
            .context("known-content verification receipt absent")?;
        Ok(
            serde_json::json!({"kind":"resource-native-finalization-v1","success":true,
        "publication_sha256":hex::encode(publication_sha256),"matching_map_bindings":matching_bindings,
        "known_streams_hashed":known.streams_hashed,"known_payload_bytes_read":known.payload_bytes_read,
        "extent_only_streams":known.streams_without_content_baseline,"source":converted,
        "label_restored":true,"mount_paths_preserved":true,"journal_handoff_closed":true}),
        )
    })();
    finish_online.map_err(|cause| CommittedFinalizationError { cause }.into())
}
