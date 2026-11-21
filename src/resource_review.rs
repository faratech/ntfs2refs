//! The review stop of `--review` (#110): in place of the finalizer, a
//! review run reopens its published records, re-authenticates the apply
//! intent alone and every new byte, fingerprints the whole converted
//! partition, records that in `review-stop.json` and puts the disk online
//! read-only. The handoff is not written; `--recover` decides.
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    resource_preparation::{EventLog, PreparationObserver, create_external_output},
    selected_journal::resource_domain::reopen::envelope::ReopenedResourceRecovery,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::GeneralSourceShadowBinding, journal_file::GeneralJournalStorageBinding,
    tree_resources::ResourceBudget,
};
use std::{collections::BTreeSet, path::Path};

/// What a review stop left: where the converted volume is mounted
/// write-protected, and where its record is.
pub(crate) struct ReviewPresented {
    pub mount_paths: Vec<String>,
    pub record: std::path::PathBuf,
    pub receipt: serde_json::Value,
}

pub(crate) fn present_review_stop<O: PreparationObserver>(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    publication: &Path,
    publication_sha256: [u8; 32],
    mut resources: ResourceBudget,
    output: &Path,
    observer: &mut O,
) -> Result<ReviewPresented> {
    resources.validate()?;
    ensure!(
        output.is_absolute() && !output.exists(),
        "review stop: a fresh output directory is required"
    );
    let available = n2r_win32::resource_native::observe_available_resources(
        output
            .parent()
            .context("review stop: output parent absent")?,
    )?;
    resources.scratch_bytes = resources
        .scratch_bytes
        .min(available.scratch_available_bytes / 2);
    available.validate_budget(resources)?;
    let _ancestry = create_external_output(output, &journal)
        .context("review stop: creating its output directory")?;
    let arena = ArtifactArena::new(
        output,
        resources,
        &[pair.source.clone(), pair.shadow.clone()],
    )?;
    let budget = SourceMetadataBudget::from_resource_budget(resources)?;
    let group = arena.reserve_group(ArtifactGroup::RecoveryCopy, budget.scratch_bytes)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(budget, group.clone())?;
    let mut events = EventLog::new(observer);
    events.phase("resource-review-reopen");
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
    .context("review stop: reopening the published recovery records")?;
    ensure!(
        recovery.review_before_handoff(),
        "review stop: the recovery publication {} does not record a review",
        publication.display()
    );
    events.checkpoint()?;
    events.phase("resource-review-verification");
    n2r_win32::perf::step("authenticate review stop");
    let new_selected = recovery
        .verify_review_stop(
            &group,
            &output.join("review-stop.index"),
            budget.scratch_bytes,
            &mut events,
        )
        .context("review stop: authenticating the apply intent and the new bytes")?;
    events.checkpoint()?;
    events.phase("resource-review-fingerprint");
    n2r_win32::perf::step("fingerprint converted partition");
    let fingerprint = recovery
        .whole_source_fingerprint(&mut events)
        .context("review stop: fingerprinting the converted partition")?;
    let record_path = crate::review::record_path(publication)?;
    let record = crate::review::ReviewStop::new(
        publication_sha256,
        recovery.source(),
        new_selected,
        fingerprint,
    );
    crate::review::write_record(&record_path, &record)?;
    n2r_win32::lab_hold::reached("review-recorded");
    events.checkpoint()?;
    events.phase("resource-review-online-readonly");
    n2r_win32::perf::step("put review online read-only");
    // From here the disk is online and read-only, which is what a review
    // stop leaves: the probes, rediscoveries and mount-path reads below
    // accept that state, and nothing else besides writable (#252). Every
    // probe elsewhere still requires a writable disk.
    let _read_only_disk = n2r_win32::allow_read_only_disk();
    let mounted = recovery
        .present_review_readonly(
            &group,
            &output.join("review-online.index"),
            budget.scratch_bytes,
            &mut events,
        )
        .context("review stop: putting the converted volume online read-only")?;
    events.checkpoint()?;
    // Windows gives the volume its letter back by itself where automatic
    // mounting is on. A letter is a mount-manager entry, not a write to the
    // volume; one that cannot be given back is reported, not made the stop's
    // failure: the volume is still reachable by its volume path.
    let expected: BTreeSet<_> = recovery
        .expected_mount_paths()
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let first = n2r_win32::capture_mount_paths_general(mounted.clone(), &mut events)?;
    let before: BTreeSet<_> = first.paths.iter().map(|s| s.to_lowercase()).collect();
    let mut letter_errors = Vec::new();
    for missing in expected.difference(&before) {
        if !crate::resource_finalize::is_drive_letter_root(missing) {
            continue;
        }
        if let Err(error) = n2r_win32::restore_drive_letter_general_on(
            mounted.clone(),
            missing,
            "ReFS",
            &mut events,
        ) {
            letter_errors.push(format!("{}: {error}", missing.to_uppercase()));
        }
    }
    let paths = n2r_win32::capture_mount_paths_general(mounted.clone(), &mut events)?;
    events.checkpoint()?;
    for error in &letter_errors {
        eprintln!(
            "Note: the converted volume is mounted read-only, but its drive letter {error}. It is \
             reachable as {}",
            mounted.volume_path().unwrap_or_default()
        );
    }
    let receipt = serde_json::json!({
        "kind":"resource-review-stop-v1","publication_sha256":hex::encode(publication_sha256),
        "source":mounted,"record":record_path,"record_contents":record,
        "mount_paths":paths.paths,"drive_letter_restore_errors":letter_errors,
        "handoff_written":false,"rollback_open":true,"disk_read_only":true,
        "native_refs_namespace_verified":false
    });
    Ok(ReviewPresented {
        mount_paths: paths.paths,
        record: record_path,
        receipt,
    })
}
