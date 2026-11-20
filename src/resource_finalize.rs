//! Complete a real resource-profile HND through a protected native observer.
//! No source admission or replay authority is recreated during finalization.
//!
//! A run whose handoff follows its verification (#148, `verify_first`) comes
//! here beside its apply intent alone: the same steps authenticate the new
//! bytes, seal the source and verify the converted volume mounted read-only,
//! and only then is the handoff written, with the source still sealed. A
//! failure before that leaves rollback open and is returned as an
//! `UncommittedVerificationError`.
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
    ensure!(
        matches!(
            lifecycle,
            SelectedLifecycle::Handoff | SelectedLifecycle::Aborted
        ),
        "online reconciliation requires a durable terminal lifecycle"
    );
    events.phase("resource-online-terminal-reconcile");
    let mounted = recovery.revalidate_online_terminal(events)?;
    events.checkpoint()?;
    let filesystem = if lifecycle == SelectedLifecycle::Handoff {
        "ReFS"
    } else {
        "NTFS"
    };
    let desired = recovery.expected_source_label().clone();
    let initial = n2r_win32::volume_label::observe_label(mounted.clone(), filesystem)?;
    let mut label_action = "already-original";
    if initial.label != desired {
        let enrollment = n2r_win32::volume_label::VolumeLabel::from_text("n2r-retained-shadow")?;
        if lifecycle == SelectedLifecycle::Handoff && initial.label == enrollment {
            let restored = n2r_win32::volume_label::restore_verified_label(
                recovery.source(),
                &desired,
                mounted.clone(),
                &enrollment,
            )?;
            ensure!(
                restored.success,
                "terminal volume label restoration did not complete"
            );
            label_action = "restored-enrollment-label";
        } else {
            // A later application/user may have deliberately changed it.
            label_action = "different-current-label-preserved";
        }
    }
    let expected: BTreeSet<_> = recovery
        .expected_mount_paths()
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let first = n2r_win32::capture_mount_paths_general(mounted.clone(), events)?;
    let actual_before: BTreeSet<_> = first.paths.iter().map(|s| s.to_lowercase()).collect();
    let mut attempted = Vec::new();
    for missing in expected.difference(&actual_before) {
        // The converted volume's letter after a handoff, and the NTFS
        // volume's after a rollback: Windows does not give them back where
        // automatic mounting of volumes is off.
        if is_drive_letter_root(missing) {
            events.checkpoint()?;
            n2r_win32::restore_drive_letter_general_on(
                mounted.clone(),
                missing,
                filesystem,
                events,
            )
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

/// The verification of a run whose handoff follows it (#148) did not pass,
/// or could not be made: the handoff is not written, the converted volume
/// was never mounted writable and rollback is open. Nothing is rolled back
/// here; the message names the two ways on.
#[derive(Debug)]
pub(crate) struct UncommittedVerificationError {
    directory: std::path::PathBuf,
    publication_sha256: [u8; 32],
    cause: anyhow::Error,
}
impl std::fmt::Display for UncommittedVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\n  What stopped it: {:#}",
            crate::verify_first::failed_before_handoff(
                &self.directory,
                &hex::encode(self.publication_sha256)
            ),
            self.cause
        )
    }
}
impl std::error::Error for UncommittedVerificationError {
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
    resources: ResourceBudget,
    output: &Path,
    observer: &mut O,
) -> Result<serde_json::Value> {
    finalize_resource_handoff_with_windows_aliases_observer(
        pair,
        journal,
        publication,
        publication_sha256,
        resources,
        output,
        observer,
        None,
    )
}

pub(crate) fn finalize_resource_handoff_with_windows_aliases_observer<O: PreparationObserver>(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    publication: &Path,
    publication_sha256: [u8; 32],
    resources: ResourceBudget,
    output: &Path,
    observer: &mut O,
    windows_aliases: Option<
        std::sync::Arc<n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>,
    >,
) -> Result<serde_json::Value> {
    // Whether the run is still before its handoff: from the start for the
    // conversion of this process if it chose the handoff after the
    // verification (its apply step wrote no handoff), else once the records
    // are reopened. Cleared just before the handoff is written.
    let before_handoff = std::cell::Cell::new(crate::verify_first::chosen());
    let finalized = finalize_reopened(
        pair,
        journal,
        publication,
        publication_sha256,
        resources,
        output,
        observer,
        windows_aliases,
        &before_handoff,
    );
    // The hold points of a verification before the handoff carry their own
    // names only while this call verifies one.
    n2r_win32::lab_hold::verifying_before_handoff(false);
    match finalized {
        Err(cause) if before_handoff.get() => Err(UncommittedVerificationError {
            directory: publication.parent().unwrap_or(publication).to_path_buf(),
            publication_sha256,
            cause,
        }
        .into()),
        other => other,
    }
}

fn finalize_reopened<O: PreparationObserver>(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    publication: &Path,
    publication_sha256: [u8; 32],
    mut resources: ResourceBudget,
    output: &Path,
    observer: &mut O,
    windows_aliases: Option<
        std::sync::Arc<n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>,
    >,
    before_handoff: &std::cell::Cell<bool>,
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
    let _ancestry = create_external_output(output, &journal)
        .context("finalization: creating its output directory")?;
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
    n2r_win32::perf::step("reopen recovery records");
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
    )
    .context("finalization: reopening the published recovery records")?;
    events.checkpoint()?;
    // A run whose handoff follows its verification (#148): everything up to
    // the handoff below is made beside the apply intent alone, and a failure
    // there leaves rollback open.
    let verifies_first = recovery.verifying_before_handoff();
    before_handoff.set(verifies_first);
    n2r_win32::lab_hold::verifying_before_handoff(verifies_first);
    events.phase("resource-handoff-authentication");
    n2r_win32::perf::step(if verifies_first {
        "authenticate new bytes before handoff"
    } else {
        "authenticate handoff"
    });
    let handoff = recovery
        .verify_handoff(
            &group,
            &output.join("verified-handoff.index"),
            budget.scratch_bytes,
            &mut events,
        )
        .context(if verifies_first {
            "finalization: authenticating the apply intent and the new bytes before the handoff"
        } else {
            "finalization: authenticating the handoff"
        })?;
    n2r_win32::lab_hold::reached(if verifies_first {
        "verify-authenticated"
    } else {
        "finalize-authenticated"
    });
    n2r_win32::perf::step("reopen verification metadata");
    let metadata = ReopenedVerificationMetadata::open(&handoff)
        .context("finalization: reopening verification metadata")?;
    events.checkpoint()?;
    events.phase("resource-protected-verification");
    n2r_win32::perf::step("seal for protected verification");
    let mut protected = handoff
        .seal_for_protected_verification(
            &group,
            &output.join("protected-handoff.index"),
            budget.scratch_bytes,
            &mut events,
        )
        .context("finalization: sealing for protected verification")?;
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
    // The walk of the converted volume keeps its rows in blocks, which go
    // to a file of this group when memory is short. The files are kept
    // for as long as the group; declared here, they outlive the report.
    let spilled_rows = crate::general_composite_target::paged_memory::SpilledFiles::default();
    let payer = crate::general_composite_target::paged_memory::ArenaReportStorage::new(
        ArenaReportMemory(arena.clone()),
        group.clone(),
        output,
        std::sync::Arc::clone(&spilled_rows),
    );
    // The old preparation's Arc remains a real owner. Charge its retained
    // ledger in this new arena as well before native queries/union indexes.
    let _external_alias_memory = windows_aliases
        .as_deref()
        .map(|aliases| aliases.reserve_external_retained_memory(&payer))
        .transpose()?;
    let admission = protected.recovery().resource_admission();
    // A restarted process cannot carry the constructor's live witness. Open
    // only the alias expectations authenticated by this actual HND/publication;
    // the protected native observer below must issue a fresh observed witness.
    n2r_win32::perf::step("reopen alias records");
    let reopened_windows_aliases = if native_pair.source.layout_profile
        == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        && windows_aliases.is_none()
    {
        Some(
            protected
                .recovery()
                .reopen_windows_alias_expectations(
                    metadata.expected(),
                    &scratch,
                    &output.join("reopened-windows-aliases"),
                )?
                .context("Windows restart finalization lacks authenticated alias expectations")?,
        )
    } else {
        None
    };
    n2r_win32::perf::step("observe converted volume");
    let (native, observed_windows_aliases) = if let Some(aliases) = windows_aliases.as_deref() {
        aliases.require_scope(
            &native_pair,
            admission.source_inspection_sha256,
            aliases.plan_digest(),
        )?;
        aliases.require_canonical_input(&input)?;
        let (native, observed) = protected
            .source_mut()?
            .observe_converted_protected_with_memory_windows_aliases(
                native_pair.clone(),
                &input,
                Some(&desired_label),
                |a, b| {
                    crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b)
                        .map_err(std::io::Error::other)
                },
                n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(admission)),
                &payer,
                aliases,
                &mut events,
            )?;
        observed.require_converted_scope(
            &native_pair,
            admission.source_inspection_sha256,
            aliases.plan_digest(),
        )?;
        observed.require_input(&input)?;
        ensure!(
            observed.len() == aliases.len(),
            "converted Windows alias coverage differs"
        );
        (native, Some(observed))
    } else if let Some(aliases) = reopened_windows_aliases.as_ref() {
        use n2r_win32::shadow_native::windows_aliases::WindowsAliasInputDomain;
        let plan_digest = aliases.semantic_sha256()?;
        let (native, observed) = protected
            .source_mut()?
            .observe_converted_protected_with_memory_windows_alias_expectations(
                native_pair.clone(),
                &input,
                Some(&desired_label),
                |a, b| {
                    crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b)
                        .map_err(std::io::Error::other)
                },
                n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(admission)),
                &payer,
                aliases,
                &mut events,
            )?;
        observed.require_converted_scope(
            &native_pair,
            admission.source_inspection_sha256,
            plan_digest,
        )?;
        observed.require_input(&input)?;
        ensure!(
            observed.len() == aliases.len(),
            "reopened Windows alias coverage differs"
        );
        (native, Some(observed))
    } else {
        (
            protected
                .source_mut()?
                .observe_converted_protected_with_memory(
                    native_pair,
                    &input,
                    Some(&desired_label),
                    |a, b| {
                        crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b)
                            .map_err(std::io::Error::other)
                    },
                    n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(admission)),
                    &payer,
                    &mut events,
                )?,
            None,
        )
    };
    events.checkpoint()?;
    n2r_win32::perf::step("compare maps");
    let maps = metadata.compare_protected(&protected, &native)?;
    let matching_bindings = maps.bindings();
    if protected.before_handoff() {
        // The one verification of the converted volume has passed. Only now
        // is the handoff written: rollback closes here and nowhere earlier.
        events.checkpoint()?;
        events.phase("resource-handoff-after-verification");
        n2r_win32::lab_hold::reached("verify-passed");
        n2r_win32::perf::step("write handoff marker");
        println!("Converted volume verified; recording handoff.");
        // A failure from here on may come after the marker is durable, so it
        // is no longer reported as one that leaves rollback open; the
        // recovery command reads the journal and goes the way it allows.
        before_handoff.set(false);
        n2r_win32::lab_hold::verifying_before_handoff(false);
        protected
            .write_handoff_after_verified_observation(
                &native,
                &maps,
                &group,
                &output.join("handoff-after-verification.index"),
                budget.scratch_bytes,
                &mut events,
            )
            .context(
                "finalization: writing the handoff after the converted volume passed its \
                 verification; the handoff may or may not be durable. Run the recovery command \
                 this run printed: it finishes the conversion, and while no handoff is written \
                 the same command with --rollback still puts NTFS back",
            )?;
        events.checkpoint()?;
        // The same state as a handoff written in the apply step and sealed.
        n2r_win32::lab_hold::reached("handoff-sealed");
    }
    events.phase("resource-verified-handoff-online");
    n2r_win32::lab_hold::reached("finalize-before-online");
    n2r_win32::perf::step("bring online");
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
        n2r_win32::lab_hold::reached("finalize-online");
        n2r_win32::perf::step("revalidate after mount");
        let converted = mounted.revalidate_handoff_artifacts_after_mount(&mut events)?;
        n2r_win32::perf::step("restore label and mount paths");
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
        n2r_win32::perf::step("revalidate after mount, again");
        mounted.revalidate_handoff_artifacts_after_mount(&mut events)?;
        events.checkpoint()?;
        let known = native
            .report()
            .content_observation
            .as_ref()
            .and_then(|o| o.known_content.as_ref())
            .context("known-content verification receipt absent")?;
        let mut receipt = serde_json::json!({"kind":"resource-native-finalization-v1","success":true,
        "publication_sha256":hex::encode(publication_sha256),"matching_map_bindings":matching_bindings,
        "known_streams_hashed":known.streams_hashed,"known_payload_bytes_read":known.payload_bytes_read,
        "extent_only_streams":known.streams_without_content_baseline,"source":converted,
        "label_restored":true,"mount_paths_preserved":true,"journal_handoff_closed":true});
        if let Some(aliases) = observed_windows_aliases.as_ref() {
            receipt["derived_windows_aliases_verified"] = true.into();
            receipt["derived_windows_alias_count"] = aliases.len().into();
            receipt["windows_alias_expectations_reopened"] =
                reopened_windows_aliases.is_some().into();
            receipt["windows_alias_restart_recovery_qualified"] = false.into();
        }
        Ok(receipt)
    })();
    finish_online.map_err(|cause| CommittedFinalizationError { cause }.into())
}

/// Whether a mount path is a drive-letter root such as `v:\`.
pub(crate) fn is_drive_letter_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}
