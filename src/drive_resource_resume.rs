//! Continue an authenticated, closed preparation without source recollection,
//! shadow formatting, constructor allocation, or replaying historical moves.
use super::*;
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    resource_preparation::{
        ResumePreparation,
        resume_origin::{LegacyResumeOrigin, peek_parent_resources},
        resume_session_inputs::{
            ResumeSessionInputs, peek_saved_resume_request, probe_resume_session,
        },
    },
};
use n2r_win32::shadow_native::private_tree::recovery::{
    ExternalOriginPins, PartialPlacementSpend, RecoveryLimits,
};

fn launch_root(directory: &Path) -> Result<PathBuf> {
    let candidates: Vec<_> = directory
        .ancestors()
        .take(6)
        .filter(|p| {
            p.join("native-process.json").is_file() && p.join("native-terminal.json").is_file()
        })
        .collect();
    ensure!(
        candidates.len() == 1,
        "closed legacy launch root is absent or ambiguous"
    );
    Ok(candidates[0].to_path_buf())
}

pub(super) fn resume_preparation(directory: &Path, old_sha: [u8; 32]) -> Result<u8> {
    if directory.join("resume-intent.json").try_exists()? {
        return resume_session(directory, old_sha);
    }
    let routes = crate::resource_preparation::early_guard::inspect_routes(
        &directory.join("preparation-intent.json"),
        old_sha,
        recovery_metadata_limit()?,
    )?;
    ensure!(
        routes.phase == "Cancelled" && routes.delegated.is_none(),
        "legacy resume requires its actual closed nondelegated Cancelled origin"
    );
    let parent = peek_parent_resources(directory)?;
    let main =
        crate::refs_security_integration::TrustRepairAllocation::split(parent.resources)?.main;
    let root = launch_root(directory)?;
    let arena =
        ArtifactArena::new_resuming(&root, main, &[routes.source.clone(), routes.shadow.clone()])?;
    arena.use_windows_native_allocation(&routes.source)?;
    let locator = arena.reserve_group(
        ArtifactGroup::RecoveryCopy,
        parent.resources.scratch_bytes / 16,
    )?;
    let bootstrap = SourceScratch::new_auxiliary_in_arena(
        SourceMetadataBudget::from_resource_budget(main)?,
        locator.clone(),
    )?;
    let origin = LegacyResumeOrigin::open(directory, old_sha, &bootstrap)?;
    ensure!(
        origin.arena_root == root
            && origin.old_main_resources == main
            && origin.parent_resources.resources == parent.resources,
        "legacy budget/root changed during resume discovery"
    );
    println!(
        "Resume saved preparation: disk {}, partition {}.\nReusing source evidence, expected tree and existing private ReFS shadow.\nThe remaining placement is planned from current native mappings.",
        origin.pair.source.disk_number, origin.pair.source.identity.partition_number
    );
    print!("Resume this conversion? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(65).read_line(&mut answer)?;
    if answer.len() >= 65 || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("Cancelled.");
        return Ok(0);
    }
    let mut hash = Sha256::new();
    hash.update(old_sha);
    hash.update(std::process::id().to_le_bytes());
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
            .to_le_bytes(),
    );
    let digest: [u8; 32] = hash.finalize().into();
    let mut epoch = [0u8; 16];
    epoch.copy_from_slice(&digest[..16]);
    let run = root.join(format!("resume-{}", hex::encode(epoch)));
    let _run_ancestry = crate::resource_preparation::create_external_output(&run, &origin.journal)?;
    let available = n2r_win32::resource_native::observe_available_resources(&run)?;
    let keep = reserve(available.scratch_available_bytes);
    let log = run.join("native-events.log");
    let log_ram = FilePreparationObserver::required_ram(&log)?;
    let ceiling = aligned(
        available
            .scratch_available_bytes
            .checked_sub(keep)
            .context("resume cannot preserve working reserve")?
            / 64,
    );
    let mut observer = FilePreparationObserver::create(
        &log,
        &origin.pair,
        &origin.journal,
        ceiling,
        log_ram,
        keep,
    )?;
    let source_bytes = origin.pair.source.identity.partition_bytes;
    let new_work = source_bytes
        .checked_mul(4)
        .context("resume work allowance overflow")?;
    let prior = origin.conservative_spend.old_work_upper_bytes;
    let uncertain = origin.conservative_spend.uncertain_operation_upper_bytes;
    let prior_ops = usize::try_from(origin.conservative_spend.old_submission_upper)?;
    let new_ops = usize::try_from(new_work / 4096)?;
    let saved = ResumePreparation {
        arena_root: root,
        arena,
        locator_group: locator,
        source: origin.origin.clone(),
        source_origin_sha256: origin.origin_sha256,
        expected: origin.expected.clone(),
        legacy_terminal: Some(origin.terminal.clone()),
        prior_resume_intent: None,
        parent_resources: origin.parent_resources.clone(),
        shadow_origin: ExternalOriginPins {
            prior_preparation_sha256: old_sha,
            expected_pages_sha256: parse_sha(&origin.expected.sha256)?,
            authenticated_checkpoint_sha256: origin.origin_sha256,
            new_epoch: epoch,
        },
        prior_spend: PartialPlacementSpend {
            prior_submissions_upper: prior_ops,
            prior_move_bytes_upper: prior,
            uncertain_tail_submissions: 1,
            uncertain_tail_move_bytes: uncertain,
        },
        placement_limits: RecoveryLimits {
            cumulative_maximum_move_bytes: prior
                .checked_add(uncertain)
                .and_then(|n| n.checked_add(new_work))
                .context("cumulative resume work overflow")?,
            cumulative_maximum_submissions: prior_ops
                .checked_add(1)
                .and_then(|n| n.checked_add(new_ops))
                .context("cumulative resume submissions overflow")?,
        },
    };
    observer.note(&serde_json::json!({"kind":"preparation-resume-import-v1","origin_sha256":hex::encode(origin.origin_sha256),
        "old_preparation_sha256":hex::encode(old_sha),"historical_spend":origin.conservative_spend,
        "new_remaining_work_allowance_bytes":new_work,"source_collection_requested":false,
        "shadow_creation_requested":false,"source_write_authority":false}))?;
    let request = ResourcePreparationRequest {
        pair: origin.pair.clone(),
        journal: origin.journal.clone(),
        resources: parent.resources,
        verification_policy: origin.origin.policy,
        selected_capacity_policy: SelectedCapacityPolicy::ConservativeV1,
        maximum_placement_bytes: new_work,
        maximum_placement_submissions: new_ops,
        maximum_materialized_bytes: parent.capture_bytes,
        maximum_source_read_bytes: None,
        capture_arena_bytes: parent.capture_bytes,
        locator_arena_bytes: parent.resources.scratch_bytes / 16,
        max_journal_bytes: parent.maximum_journal_bytes,
        max_literal_backing_bytes: parent.capture_bytes,
        max_combined_backing_and_journal_bytes: parent.maximum_combined_bytes,
        minimum_free_bytes: keep,
        marker_profile: None,
        marker_use: MarkerStorageUse::QualifiedProduction,
    };
    origin.revalidate()?;
    execute_resume(request, &run, &mut observer, &saved, keep)
}

fn execute_resume(
    request: ResourcePreparationRequest,
    run: &Path,
    observer: &mut FilePreparationObserver,
    saved: &ResumePreparation,
    keep: u64,
) -> Result<u8> {
    let pair = request.pair.clone();
    let journal = request.journal.clone();
    let cancellation_pair=pair.clone();
    let cancellation_journal=journal.clone();
    observer.enable_durable_preparation_cancellation()?;
    let result = (|| -> Result<()> {
        let mut aliases = None;
        let (publication, sha) = crate::resource_preparation::resume_with(
            request,
            &run.join("conversion"),
            observer,
            saved,
            |prepared, events, observer| {
                let path = prepared.publication_path().to_path_buf();
                let sha = parse_sha(prepared.publication_sha256())?;
                let fresh = prepared.into_fresh_apply(events, |batch| {
                    observer.native_events("source-activation", batch)
                })?;
                let mut applied = fresh.apply_and_handoff(
                    events,
                    |batch| observer.native_events("source-apply-and-handoff", batch),
                    |_| {
                        println!("Source changes verified; recording handoff.");
                        io::stdout().flush()?;
                        Ok(())
                    },
                )?;
                applied.seal_handoff_readonly(events, |batch| {
                    observer.native_events("source-handoff-readonly", batch)
                })?;
                ensure!(
                    applied.source() == &pair.source,
                    "resumed apply source identity differs"
                );
                aliases = applied.windows_aliases().cloned();
                drop(applied);
                Ok((path, sha))
            },
        )?;
        let current = n2r_win32::resource_native::observe_available_resources(&run)?;
        let remaining = current
            .scratch_available_bytes
            .checked_sub(keep)
            .and_then(|n| n.checked_sub(observer.remaining_reservation_bytes()))
            .context("resume finalization cannot preserve reserve")?;
        let resources = budget(current, aligned(remaining / 2), observer.ram_bytes())?;
        let receipt =
            crate::resource_finalize::finalize_resource_handoff_with_windows_aliases_observer(
                pair,
                journal,
                &publication,
                sha,
                resources,
                &run.join("finalization"),
                observer,
                aliases,
            )?;
        observer.note(&receipt)?;
        save(&run.join("resource-completion.json"), &receipt)?;
        Ok(())
    })();
    let result=match result {
        Ok(())=>Ok(()),
        Err(error)=>match cancel_unpublished_resume(run,observer,&cancellation_pair,
            &cancellation_journal,saved.arena.budget()) {
            Ok(Some(receipt))=>{
                let _=save(&run.join("preparation-cancelled.json"),&receipt);
                Err(error.context("prepublication preparation cancelled through its authenticated native guard; NTFS access restored"))
            }
            Ok(None)=>Err(error),
            Err(cleanup)=>Err(error.context(format!("preparation guard cancellation did not close; preserve records and inspect actual source availability: {cleanup:#}"))),
        }
    };
    if let Ok(receipt) = observer.finish() {
        save(&run.join("native-events-summary.json"), &receipt)?;
    }
    result?;
    Ok(0)
}

fn cancel_unpublished_resume(run:&Path,observer:&mut FilePreparationObserver,
    pair:&GeneralSourceShadowBinding,journal:&GeneralJournalStorageBinding,
    resources:ResourceBudget)->Result<Option<serde_json::Value>> {
    let Some(pin)=observer.preparation_pin() else{return Ok(None)};
    if run.join("conversion/recovery-envelope.json").try_exists()?{return Ok(None)}
    let sha=parse_sha(&pin.sha256)?;
    let routes=crate::resource_preparation::early_guard::inspect_routes(&pin.path,sha,pin.bytes)?;
    ensure!(routes.source==pair.source&&routes.shadow==pair.shadow&&routes.journal==*journal,
        "actual cancellation guard differs from this invocation's source/shadow/journal");
    if routes.delegated.is_some()||routes.phase=="Delegated"{return Ok(None)}
    let mut events=Vec::new();
    let cancelled=crate::resource_preparation::early_guard::cancel_preparation(&pin.path,sha,resources,&mut events);
    let recorded=observer.native_events("resume-prepublication-guard-cancellation",&mut events);
    let receipt=cancelled?;recorded?;
    observer.note(&serde_json::json!({"kind":"resume-prepublication-native-guard-cancelled",
        "preparation_sha256":pin.sha256,"receipt":receipt,
        "whole_partition_hash_passes_requested":0,"source_byte_replay_requested":false}))?;
    Ok(Some(receipt))
}

/// Restart an epoch from durable checkpoint facts. Every native owner is newly
/// issued; a saved phase or a JSON request can never recreate a volume lock.
fn resume_session(directory: &Path, intent_sha: [u8; 32]) -> Result<u8> {
    let maximum = recovery_metadata_limit()?.min(8 << 20);
    let probe = probe_resume_session(directory, intent_sha, maximum)?;
    // Publication can have completed before the last preparation checkpoint.
    // Follow the real guard first, even when the saved stage still says Placing.
    if let Some(publication) = &probe.delegated_publication {
        ensure!(
            publication
                .path
                .file_name()
                .is_some_and(|name| name == "recovery-envelope.json"),
            "delegated publication filename differs; preserve preparation"
        );
        return super::recover(
            publication
                .path
                .parent()
                .context("publication parent absent")?,
            &publication.sha256,
            false,
        );
    }
    ensure!(
        !probe.requires_publication_route(),
        "publication file exists without authenticated delegation; preserve it and recover its independent publication pin"
    );
    let bootstrap = peek_saved_resume_request(directory, intent_sha, maximum)?;
    let main = crate::refs_security_integration::TrustRepairAllocation::split(
        bootstrap.parent_resources.resources,
    )?
    .main;
    let pair = bootstrap.request.pair.clone();
    let arena = ArtifactArena::new_resuming(
        &bootstrap.arena_root,
        main,
        &[pair.source.clone(), pair.shadow.clone()],
    )?;
    arena.use_windows_native_allocation(&pair.source)?;
    let locator = arena.reserve_group(
        ArtifactGroup::RecoveryCopy,
        bootstrap.request.locator_arena_bytes,
    )?;
    let session = ResumeSessionInputs::open(directory, intent_sha, &locator)?;
    ensure!(
        session.saved.arena_root == bootstrap.arena_root
            && session.saved.parent_resources.resources == bootstrap.parent_resources.resources,
        "saved session bootstrap changed before paid adoption"
    );
    println!(
        "Resume checkpoint: {}\nSource: disk {}, partition {}.\nCompleted shadow placement will be reused; source collection and shadow creation are disabled.",
        directory.display(),
        pair.source.disk_number,
        pair.source.identity.partition_number
    );
    print!("Resume this conversion? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(65).read_line(&mut answer)?;
    if answer.len() >= 65 || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("Cancelled.");
        return Ok(0);
    }
    session.revalidate()?;
    let mut hash = Sha256::new();
    hash.update(intent_sha);
    hash.update(std::process::id().to_le_bytes());
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
            .to_le_bytes(),
    );
    let id: [u8; 32] = hash.finalize().into();
    let mut epoch = [0u8; 16];
    epoch.copy_from_slice(&id[..16]);
    let run = session
        .saved
        .arena_root
        .join(format!("resume-{}", hex::encode(epoch)));
    let _ancestry =
        crate::resource_preparation::create_external_output(&run, &session.saved.request.journal)?;
    let available = n2r_win32::resource_native::observe_available_resources(&run)?;
    let keep = reserve(available.scratch_available_bytes);
    let log = run.join("native-events.log");
    let log_ram = FilePreparationObserver::required_ram(&log)?;
    let ceiling = aligned(
        available
            .scratch_available_bytes
            .checked_sub(keep)
            .context("restart cannot preserve working reserve")?
            / 64,
    );
    let mut observer = FilePreparationObserver::create(
        &log,
        &pair,
        &session.saved.request.journal,
        ceiling,
        log_ram,
        keep,
    )?;
    // A dead process's old guard must perform its real cancellation protocol.
    // Do this before asking the fresh guard to isolate the original partition.
    let mut execution_started = false;
    let result = (|| -> Result<u8> {
        let guard = &session.new_preparation_intent;
        let mut events = Vec::new();
        let cancelled = crate::resource_preparation::early_guard::cancel_preparation(
            &guard.path,
            parse_sha(&guard.sha256)?,
            main,
            &mut events,
        );
        let recorded = observer.native_events("resume-prior-guard-cancellation", &mut events);
        cancelled?;
        recorded?;
        let routes = crate::resource_preparation::early_guard::inspect_routes(
            &guard.path,
            parse_sha(&guard.sha256)?,
            maximum,
        )?;
        ensure!(
            routes.delegated.is_none()
                && matches!(routes.phase.as_str(), "Cancelled" | "UnstartedCancelled")
                && routes.source == pair.source
                && routes.shadow == pair.shadow,
            "prior guard did not reach actual cancelled state"
        );
        session.revalidate()?;
        let mut request = session.saved.request.clone().into_actual()?;
        let mut spend = session.saved.prior_spend.into_actual()?;
        // A crash can leave any submitted move in flight. Charge the complete
        // prior attempt's admitted work rather than inventing zero old spend.
        spend.prior_move_bytes_upper = spend
            .prior_move_bytes_upper
            .checked_add(request.maximum_placement_bytes)
            .context("restart historical work overflow")?;
        spend.prior_submissions_upper = spend
            .prior_submissions_upper
            .checked_add(request.maximum_placement_submissions)
            .context("restart historical submissions overflow")?;
        let new_work = pair
            .source
            .identity
            .partition_bytes
            .checked_mul(4)
            .context("restart allowance overflow")?;
        let new_ops = usize::try_from(new_work / 4096)?;
        let limits = RecoveryLimits {
            cumulative_maximum_move_bytes: spend
                .prior_move_bytes_upper
                .checked_add(spend.uncertain_tail_move_bytes)
                .and_then(|n| n.checked_add(new_work))
                .context("restart cumulative work overflow")?,
            cumulative_maximum_submissions: spend
                .prior_submissions_upper
                .checked_add(spend.uncertain_tail_submissions)
                .and_then(|n| n.checked_add(new_ops))
                .context("restart cumulative submissions overflow")?,
        };
        request.maximum_placement_bytes = new_work;
        request.maximum_placement_submissions = new_ops;
        request.minimum_free_bytes = keep;
        let saved = ResumePreparation {
            arena_root: session.saved.arena_root.clone(),
            arena,
            locator_group: locator,
            source: session.source.clone(),
            source_origin_sha256: session.source_origin_sha256,
            expected: session.saved.expected.clone(),
            legacy_terminal: session.saved.legacy_terminal.clone(),
            prior_resume_intent: Some(session.journal.intent_pin().clone()),
            parent_resources: session.saved.parent_resources.clone(),
            prior_spend: spend,
            placement_limits: limits,
            shadow_origin: ExternalOriginPins {
                prior_preparation_sha256: parse_sha(&guard.sha256)?,
                expected_pages_sha256: parse_sha(&session.saved.expected.sha256)?,
                authenticated_checkpoint_sha256: intent_sha,
                new_epoch: epoch,
            },
        };
        observer.note(&serde_json::json!({"kind":"preparation-resume-checkpoint-import-v1",
            "previous_intent_sha256":hex::encode(intent_sha),"previous_stage":session.journal.stage(),
            "pending_batch":session.journal.pending_batch(),"prior_actual_guard_phase":session.actual_guard_phase,
            "source_collection_requested":false,"shadow_creation_requested":false,
            "historical_spend":session.saved.prior_spend,"new_remaining_work_allowance_bytes":new_work}))?;
        execution_started = true;
        execute_resume(request, &run, &mut observer, &saved, keep)
    })();
    // execute_resume closes its observer. Only close here on failures that
    // occurred before execution, preserving the original native failure.
    if result.is_err() && !execution_started {
        if let Ok(receipt) = observer.finish() {
            let _ = save(&run.join("native-events-summary.json"), &receipt);
        }
    }
    result
}
