//! RAM-started consumer of the original Windows preparation and journal.
//! J is enrolled from current boot-bound RAM routing before any file on J is read.
use super::*;
use crate::{
    artifact_arena::ArtifactGroup,
    general_reconstruct::selected_native_journal::BoundNativeRecoveryJournal,
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    resource_prepared_bundle::HeldWindowsPreparedBundle,
    resource_prepared_offline_apply::{self, PreparedOfflineBootRequest},
};
use n2r_win32::{
    PagedRecoveryDirection,
    journal_file::{JournalProfile, MarkerStorageUse},
    offline_environment::{OfflineOwningEnvironment, OfflinePreparedSource},
    recovery_boot::RecoveryBootBudget,
};

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedOfflineAction {
    #[default]
    AutoResume,
    Rollback,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOfflineRequest {
    pub schema_version: u32,
    pub source: PartitionSourceBinding,
    pub journal: GeneralJournalStorageBinding,
    pub prepared_bundle: PathBuf,
    pub prepared_bundle_sha256: String,
    pub maximum_bundle_bytes: u64,
    pub output_parent: PathBuf,
    pub observation_budget: PartitionObservationBudget,
    pub total_ram_bytes: u64,
    pub arena_scratch_bytes: u64,
    pub maximum_evidence_bytes: u64,
    pub minimum_free_bytes: u64,
    pub boot_intent: PathBuf,
    pub boot_budget: RecoveryBootBudget,
    #[serde(default)]
    pub action: PreparedOfflineAction,
    /// Qualification-only pause; normal public conversion leaves this absent.
    #[serde(default)]
    pub controlled_pause_nonce: Option<String>,
}

pub fn run_prepared_offline(
    request: PreparedOfflineRequest,
    mut held_ram_bootstrap: File,
    acknowledge: bool,
) -> Result<()> {
    run_prepared_offline_mode(request,held_ram_bootstrap,acknowledge,false)
}
/// Metadata-only continuation of an authenticated HND/ABT. This route cannot
/// admit PreparedClear/AP/RB or obtain a source payload writer.
pub fn finalize_closed_boot_only(request:PreparedOfflineRequest,held_ram_bootstrap:File,
    acknowledge:bool) -> Result<()> {
    run_prepared_offline_mode(request,held_ram_bootstrap,acknowledge,true)
}
fn run_prepared_offline_mode(
    request:PreparedOfflineRequest,mut held_ram_bootstrap:File,acknowledge:bool,
    closed_only_boot_repair:bool,
) -> Result<()> {
    ensure!(
        acknowledge && request.schema_version == 1,
        "explicit owning-machine offline execution required"
    );
    request.source.validate()?;
    request.journal.validate()?;
    request.observation_budget.validate()?;
    let pause_ram = if let Some(nonce) = &request.controlled_pause_nonce {
        super::controlled_pause::require_nonce(nonce)?;
        512 * 1024
    } else {
        0
    };
    let pause_evidence = if pause_ram > 0 { 1024 * 1024 } else { 0 };
    ensure!(
        request.maximum_evidence_bytes > 0 && request.minimum_free_bytes > 0,
        "independent offline evidence and free-space reserves required"
    );
    let sdk_ram = request
        .observation_budget
        .ram_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(request.boot_budget.ram_bytes))
        .context("offline native/boot memory overflow")?;
    let arena_ram = request
        .total_ram_bytes
        .checked_sub(sdk_ram)
        .and_then(|n| n.checked_sub(pause_ram))
        .and_then(|n| n.checked_sub(request.maximum_evidence_bytes))
        .and_then(|n| n.checked_sub(EXECUTION_STACK_RESERVE_BYTES + 5 * 1024 * 1024))
        .context("offline memory cannot cover native, boot, stacks and evidence")?;
    let resources = derive_budget(arena_ram, request.arena_scratch_bytes)?;
    ensure!(
        request.total_ram_bytes <= n2r_win32::offline_environment::available_ram_bytes()?,
        "offline request exceeds currently available RAM"
    );
    // Early SAN3 means independent J is deliberately unavailable. The first
    // evidence sink is on current RAM and contains only bounded native facts.
    let ram_directory = std::env::current_exe()?
        .parent()
        .context("RAM runner parent absent")?
        .to_path_buf();
    let ram_log = ram_directory.join(format!("n2r-bootstrap-{}.jsonl", std::process::id()));
    let observer = Observer(Arc::new(Mutex::new(Ledger {
        file: OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .share_mode(1)
            .open(ram_log)?,
        bytes: 0,
        event_encoder: Default::default(),
        maximum: request.maximum_evidence_bytes,
        poisoned: false,
        meter: None,
        stage_maximum: 0,
        minimum_free: 0,
        run: ram_directory,
    })));
    let mut events = Vec::new();
    let observed_environment = OfflineOwningEnvironment::observe_and_require(
        request.source.clone(),
        request.observation_budget,
        &mut events,
    );
    let mut environment = match observed_environment {
        Ok(value) => value,
        Err(error) => {
            // Preserve actual constructor events on RAM even when the first
            // positive-owner checkpoint was never reached. No source/J writer
            // has been issued; this does not turn a failure into admission.
            let closing = observer.checkpoint("offline-RAM-environment-observation-failed", &mut events);
            return match closing {
                Ok(()) => Err(error).context("observe actual RAM-Windows/source environment"),
                Err(close) => Err(anyhow::Error::from(error).context(format!("environment observation failed; RAM event preservation also failed: {close}"))),
            };
        }
    };
    observer.checkpoint("offline-positive-RAM-source-environment", &mut events)?;
    let mut bootstrap_observer = observer.clone();
    let volume = environment.open_independent_journal_for_recovery(
        &request.journal,
        &mut held_ram_bootstrap,
        &mut bootstrap_observer,
        &mut events,
    )?;
    observer.checkpoint("offline-independent-J-enrollment", &mut events)?;
    let _parents = ordinary_directory(&request.output_parent)?;
    let prefix = format!(
        "{}\\",
        request.journal.disk.volume_path()?.trim_end_matches('\\')
    );
    ensure!(
        n2r_win32::file_storage::final_path_guid(
            _parents.first().context("offline output parent absent")?
        )?
        .get(..prefix.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(&prefix)),
        "offline output parent is not the actual independently enrolled J"
    );
    let ordinary_output_parent = environment.ordinary_journal_directory(
        &request.journal, &volume,
        _parents.first().context("held J output parent absent")?, &mut events,
    )?;
    // Retain every ordinary ancestor on the same native directory before any
    // arena/index output is admitted. Sealed bundle/J/bootstrap paths stay GUID.
    let _ordinary_output_parents = ordinary_directory(&ordinary_output_parent)?;
    observer.checkpoint("offline-current-J-ordinary-output-route", &mut events)?;
    let available =
        n2r_win32::resource_native::observe_available_resources(&request.output_parent)?;
    let evidence_bytes = request
        .maximum_evidence_bytes
        .checked_mul(2)
        .context("offline evidence reservation overflow")?;
    let required = request
        .arena_scratch_bytes
        .checked_add(pause_evidence)
        .and_then(|n| n.checked_add(evidence_bytes))
        .and_then(|n| n.checked_add(request.minimum_free_bytes))
        .context("offline storage reservation overflow")?;
    ensure!(
        available.scratch_available_bytes >= required,
        "actual independent J lacks offline arena/evidence/reserve"
    );
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let output = ordinary_output_parent
        .join(format!("offline-{stamp}-{}", std::process::id()));
    fs::create_dir(&output)?;
    let _output = ordinary_directory(&output)?;
    fs::create_dir(output.join("arena"))?;
    // Transfer the same durable observer to actual J only after enrollment.
    let old_ram_log = {
        let mut ledger = observer.lock()?;
        let new_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .share_mode(1)
            .open(output.join("native-events.jsonl"))?;
        let mut new_file = new_file;
        use std::io::{Seek, SeekFrom};
        ledger.file.seek(SeekFrom::Start(0))?;
        ensure!(
            io::copy(&mut ledger.file, &mut new_file)? == ledger.bytes,
            "RAM bootstrap native evidence transfer length differs"
        );
        new_file.sync_all()?;
        ledger.run = output.clone();
        ledger.minimum_free = request.minimum_free_bytes;
        std::mem::replace(&mut ledger.file, new_file)
    };
    drop(old_ram_log);
    observer.lock()?.record(
        &serde_json::json!({"kind":"cold-prepared-resource-admission-v1",
        "request":request,"available":available,"arena":resources,"native_and_boot_ram":sdk_ram,
        "capacity_including_reserve":required,"request_grants_source_authority":false}),
    )?;
    let arena = ArtifactArena::new(
        &output.join("arena"),
        resources,
        &[request.source.storage.clone()],
    )?;
    let budget = SourceMetadataBudget::from_resource_budget(resources)?;
    let group = arena.reserve_group(ArtifactGroup::RecoveryCopy, budget.scratch_bytes)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(budget, group.clone())?;
    let bundle = HeldWindowsPreparedBundle::open(
        &request.prepared_bundle,
        &request.prepared_bundle_sha256,
        request.maximum_bundle_bytes,
        &mut environment,
        &volume,
        &scratch,
        &mut events,
    )?;
    ensure!(
        bundle.core().source == request.source.storage
            && bundle.core().journal_binding == request.journal,
        "boot request differs from actual held Windows preparation"
    );
    observer.checkpoint("cold-prepared-bundle-authenticated", &mut events)?;
    let gpt: [u8; 32] = hex::decode(&bundle.core().source_readonly_gpt_sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("prepared GPT hash width"))?;
    let excluded = OfflinePreparedSource::exclude(
        environment,
        gpt,
        &request.journal,
        &volume,
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .share_mode(1)
            .open(output.join("exclusion.intent"))?,
        Box::new(observer.clone()),
        &mut events,
    );
    let source = match excluded {
        Ok(source) => source,
        Err(error) => {
            // Retain the actual failed inventory/lock controls before returning
            // to the recovery console. These diagnostics grant no authority.
            let closing = observer.checkpoint("cold-prepared-source-exclusion-failed", &mut events);
            return match closing {
                Ok(()) => Err(error).context("exclude actual prepared source in recovery Windows"),
                Err(close) => Err(anyhow::Error::from(error).context(format!(
                    "prepared source exclusion failed; preserving native evidence also failed: {close}"
                ))),
            };
        }
    };
    let profile = JournalProfile::from_schema_and_capacity(
        bundle.core().journal_profile_version,
        Some(bundle.core().journal_profile_max_bytes),
    )?;
    let (mut journal, observed_journal) = BoundNativeRecoveryJournal::open(
        &bundle.core().journal_path,
        &request.journal,
        profile,
        &bundle.core().ticket,
        None,
        MarkerStorageUse::QualifiedProduction,
    )?;
    observer.lock()?.record(
        &serde_json::json!({"kind":"actual-exclusive-cold-J-open","observed":observed_journal}),
    )?;
    let boot = PreparedOfflineBootRequest {
        closed_only_boot_repair,
        intent_path: request.boot_intent.clone(),
        intent_sha256: n2r_win32::recovery_boot::current_recovery_intent_sha256()?,
        output: output.join("boot-proof"),
        budget: request.boot_budget,
        postflush_pause_nonce: request.controlled_pause_nonce.clone(),
    };
    let lifecycle = {
        let (native, _) = journal.split_for_observation()?;
        crate::selected_journal::classify(native, &bundle.core().ticket)?
    };
    use crate::selected_journal::SelectedLifecycle;
    if closed_only_boot_repair {
        ensure!(matches!(lifecycle,SelectedLifecycle::Handoff|SelectedLifecycle::Aborted)
            &&request.controlled_pause_nonce.is_none(),
            "closed-only boot repair rejects unactivated/AP/RB journals and pause hooks; no payload writer admitted");
        observer.lock()?.record(&serde_json::json!({"kind":"closed-only-boot-repair-authenticated-entry",
            "source_payload_writer_allowed":false,"already_closed_lifecycle":true,
            "uses_original_boot_bound_request":true}))?;
    }
    let operation = match (lifecycle, request.action) {
        (SelectedLifecycle::PreparedClear, PreparedOfflineAction::AutoResume) => {
            resource_prepared_offline_apply::apply_prepared(
                bundle,
                source,
                journal,
                &group,
                &scratch,
                &output.join("arena/cold-write.index"),
                budget.scratch_bytes,
                &boot,
                &mut events,
                |events| Ok(observer.checkpoint("cold-prepared-operation", events)?),
            )
        }
        (SelectedLifecycle::ApplyIntent, _) | (SelectedLifecycle::RollbackIntent, _) => {
            let direction = match (lifecycle, request.action) {
                (_, PreparedOfflineAction::Rollback) | (SelectedLifecycle::RollbackIntent, _) => {
                    PagedRecoveryDirection::Rollback
                }
                _ => choose_recovery_direction()?,
            };
            resource_prepared_offline_apply::recover_prepared(
                bundle,
                source,
                journal,
                &group,
                &scratch,
                &output.join("arena/cold-write.index"),
                budget.scratch_bytes,
                direction,
                &boot,
                &mut events,
                |events| Ok(observer.checkpoint("cold-prepared-restart-recovery", events)?),
            )
        }
        (SelectedLifecycle::Handoff, PreparedOfflineAction::Rollback) => anyhow::bail!(
            "handoff permanently closed NTFS rollback; no raw replay or metadata change was attempted"
        ),
        (SelectedLifecycle::Handoff, PreparedOfflineAction::AutoResume)
        | (SelectedLifecycle::Aborted, _) => {
            resource_prepared_offline_apply::finalize_prepared_closed(
                bundle,
                source,
                journal,
                &group,
                &scratch,
                &output.join("arena/cold-write.index"),
                budget.scratch_bytes,
                &boot,
                &mut events,
                |events| Ok(observer.checkpoint("cold-prepared-closed-reconciliation", events)?),
            )
        }
        _ => anyhow::bail!(
            "an unactivated journal cannot be rolled back through the replay path; no raw replay was attempted"
        ),
    };
    match operation {
        Ok(terminal) => {
            observer.lock()?.record(
                &serde_json::json!({"kind":"cold-prepared-closed-HND-before-native-finalization",
                "selected":terminal.selected,"native_bytes_written":terminal.native_bytes_written,
                "normal_boot_restored":false,"native_finalization_complete":false}),
            )?;
            let mut restoration = observer.clone();
            let result = crate::resource_prepared_terminal::finalize_prepared_offline(
                terminal,
                &scratch,
                &output.join("terminal"),
                request.observation_budget,
                &mut restoration,
                &mut events,
            );
            let drained = observer.checkpoint("cold-prepared-native-terminal-closed", &mut events);
            let receipt = match (result, drained) {
                (Ok(v), Ok(())) => v,
                (Err(e), Err(close)) => {
                    return Err(e.context(format!("terminal evidence also failed: {close}")));
                }
                (Err(e), _) => return Err(e),
                (_, Err(e)) => return Err(e.into()),
            };
            save(
                &output.join("conversion-terminal-result.json"),
                &receipt,
                request.maximum_evidence_bytes,
            )?;
            observer.lock()?.record(&receipt)?;
            println!("Conversion/recovery finalized; normal Windows boot restored.");
            io::stdout().flush()?;
            Ok(())
        }
        Err(error) => {
            let closing =
                observer.checkpoint("cold-prepared-failed-preserve-recovery", &mut events);
            match closing {
                Ok(()) => Err(error),
                Err(close) => Err(error.context(format!("closing evidence failed: {close}"))),
            }
        }
    }
}

fn choose_recovery_direction() -> Result<PagedRecoveryDirection> {
    use std::io::{BufRead, Read};
    println!(
        "An interrupted conversion is protected. Enter R to resume conversion or B to restore NTFS:"
    );
    io::stdout().flush()?;
    let stdin = io::stdin();
    let mut reader = stdin.lock().take(16);
    let mut answer = String::new();
    reader.read_line(&mut answer)?;
    ensure!(
        answer.len() < 16 && answer.ends_with('\n'),
        "bounded recovery choice required; source remains excluded"
    );
    match answer.trim().to_ascii_uppercase().as_str() {
        "R" => Ok(PagedRecoveryDirection::Resume),
        "B" => Ok(PagedRecoveryDirection::Rollback),
        _ => anyhow::bail!("recovery choice was not R or B; source remains excluded"),
    }
}
