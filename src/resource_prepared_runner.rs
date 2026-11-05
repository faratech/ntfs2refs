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
}

pub fn run_prepared_offline(
    request: PreparedOfflineRequest,
    mut held_ram_bootstrap: File,
    acknowledge: bool,
) -> Result<()> {
    ensure!(
        acknowledge && request.schema_version == 1,
        "explicit owning-machine offline execution required"
    );
    request.source.validate()?;
    request.journal.validate()?;
    request.observation_budget.validate()?;
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
        maximum: request.maximum_evidence_bytes,
        poisoned: false,
        meter: None,
        stage_maximum: 0,
        minimum_free: 0,
        run: ram_directory,
    })));
    let mut events = Vec::new();
    let mut environment = OfflineOwningEnvironment::observe_and_require(
        request.source.clone(),
        request.observation_budget,
        &mut events,
    )?;
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
    let available =
        n2r_win32::resource_native::observe_available_resources(&request.output_parent)?;
    let required = request
        .arena_scratch_bytes
        .checked_add(
            request
                .maximum_evidence_bytes
                .checked_mul(2)
                .context("offline evidence reservation overflow")?,
        )
        .and_then(|n| n.checked_add(request.minimum_free_bytes))
        .context("offline storage reservation overflow")?;
    ensure!(
        available.scratch_available_bytes >= required,
        "actual independent J lacks offline arena/evidence/reserve"
    );
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let output = request
        .output_parent
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
    let source = OfflinePreparedSource::exclude(
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
    )?;
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
        intent_path: request.boot_intent.clone(),
        intent_sha256: n2r_win32::recovery_boot::current_recovery_intent_sha256()?,
        output: output.join("boot-proof"),
        budget: request.boot_budget,
    };
    let lifecycle = {
        let (native, _) = journal.split_for_observation()?;
        crate::selected_journal::classify(native, &bundle.core().ticket)?
    };
    use crate::selected_journal::SelectedLifecycle;
    let operation = match (lifecycle, request.action) {
        (SelectedLifecycle::PreparedClear, PreparedOfflineAction::AutoResume) =>
            resource_prepared_offline_apply::apply_prepared(bundle, source, journal,
                &group, &scratch, &output.join("arena/cold-write.index"), budget.scratch_bytes,
                &boot, &mut events, |events| Ok(observer.checkpoint("cold-prepared-operation", events)?)),
        (SelectedLifecycle::ApplyIntent, _) | (SelectedLifecycle::RollbackIntent, _) => {
            let direction = match (lifecycle, request.action) {
                (_, PreparedOfflineAction::Rollback) | (SelectedLifecycle::RollbackIntent, _) => PagedRecoveryDirection::Rollback,
                _ => PagedRecoveryDirection::Resume,
            };
            resource_prepared_offline_apply::recover_prepared(bundle, source, journal,
                &group, &scratch, &output.join("arena/cold-write.index"), budget.scratch_bytes,
                direction, &boot, &mut events,
                |events| Ok(observer.checkpoint("cold-prepared-restart-recovery", events)?))
        }
        _ => anyhow::bail!("current closed/unactivated J requires terminal reconciliation; no raw replay was attempted"),
    };
    match operation {
        Ok(terminal) => {
            observer.lock()?.record(
                &serde_json::json!({"kind":"cold-prepared-closed-HND-before-native-finalization",
                "selected":terminal.selected,"native_bytes_written":terminal.native_bytes_written,
                "normal_boot_restored":false,"native_finalization_complete":false}),
            )?;
            // A closed journal is not a successful mounted conversion. Retain
            // recovery boot protection until native target verification and
            // the consuming closed-owner restoration are connected.
            anyhow::bail!(
                "raw conversion reached closed HND; recovery boot remains selected pending native finalization"
            )
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
