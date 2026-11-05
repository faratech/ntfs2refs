//! Owning-machine AP/RB partition recovery. Requests route actual artifacts;
//! only current private/source/J/origin gates issue bounded replay authority.
use super::{Ledger, Observer, derive_budget, ordinary_directory, save};
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    selected_journal::resource_domain::reopen::envelope::ReopenedPartitionResourceRecovery,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent, PagedRecoveryDirection, PartitionScopedOwner,
    general_layout::GeneralDiskBinding,
    journal_file::GeneralJournalStorageBinding,
    partition_isolation::{PartitionObservationBudget, PartitionSourceBinding},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
pub const PARTITION_RECOVERY_WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;
const RECOVERY_THREAD_STACK_RESERVATION: u64 = 9 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRecoveryDirection {
    Resume,
    Rollback,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionRecoveryRequest {
    pub schema_version: u32,
    pub source: PartitionSourceBinding,
    pub shadow: GeneralDiskBinding,
    pub journal: GeneralJournalStorageBinding,
    pub publication: PathBuf,
    pub publication_sha256: String,
    pub observation_budget: PartitionObservationBudget,
    pub total_ram_bytes: u64,
    pub arena_scratch_bytes: u64,
    pub maximum_evidence_bytes: u64,
    pub minimum_free_bytes: u64,
    pub direction: PartitionRecoveryDirection,
}
fn digest(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "independently supplied canonical publication SHA256 required"
    );
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("publication checksum width differs"))
}
/// AP/RB only. PreparedClear/no-publication/process-death cancellation is not
/// inferred from absent files, an intent flag or the original primary sector.
pub fn run_recovery(
    request: PartitionRecoveryRequest,
    output: &Path,
    acknowledge: bool,
) -> Result<()> {
    ensure!(
        acknowledge && request.schema_version == 1,
        "explicit disposable partition recovery acknowledgement required"
    );
    request.source.validate()?;
    request.shadow.validate()?;
    request.journal.validate()?;
    request.observation_budget.validate()?;
    let publication_sha = digest(&request.publication_sha256)?;
    ensure!(
        request.minimum_free_bytes > 0
            && request.maximum_evidence_bytes > 0
            && request.arena_scratch_bytes > 0,
        "explicit independent recovery resource/evidence reserves required"
    );
    ensure!(
        output.is_absolute() && !output.exists(),
        "fresh absolute recovery output required"
    );
    let parent = output.parent().context("recovery parent absent")?;
    let _parent = ordinary_directory(parent)?;
    ensure!(
        output
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| !s.is_empty()
                && !s.ends_with([' ', '.'])
                && !s.chars().any(|c| c.is_control()
                    || matches!(c, ':' | '/' | '\\' | '"' | '<' | '>' | '|' | '?' | '*'))),
        "ordinary recovery output leaf required"
    );
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    let evidence = request
        .maximum_evidence_bytes
        .checked_mul(2)
        .context("recovery evidence reserve overflow")?;
    let required = request
        .arena_scratch_bytes
        .checked_add(evidence)
        .and_then(|n| n.checked_add(request.minimum_free_bytes))
        .context("recovery free reserve overflow")?;
    ensure!(
        available.scratch_available_bytes >= required
            && request.total_ram_bytes <= available.available_physical_bytes,
        "actual RAM/storage cannot cover independent recovery reservations"
    );
    let sdk_ram = request
        .observation_budget
        .ram_bytes
        .checked_mul(2)
        .context("recovery SDK RAM overflow")?;
    let ledger_ram = 5 * 1024 * 1024;
    let arena_ram = request
        .total_ram_bytes
        .checked_sub(sdk_ram)
        .and_then(|n| n.checked_sub(ledger_ram))
        .and_then(|n| n.checked_sub(RECOVERY_THREAD_STACK_RESERVATION))
        .context("recovery RAM cannot cover SDK+ledger")?;
    let resources = derive_budget(arena_ram, request.arena_scratch_bytes / 4096 * 4096)?;
    fs::create_dir(output)?;
    let _output = ordinary_directory(output)?;
    fs::create_dir(output.join("control"))?;
    fs::create_dir(output.join("arena"))?;
    let _control = ordinary_directory(&output.join("control"))?;
    let _arena_directory = ordinary_directory(&output.join("arena"))?;
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(1)
        .open(output.join("control/native-events.jsonl"))?;
    let observer = Observer(Arc::new(Mutex::new(Ledger {
        file,
        bytes: 0,
        maximum: request.maximum_evidence_bytes,
        poisoned: false,
        meter: None,
        stage_maximum: 0,
        minimum_free: request.minimum_free_bytes,
        run: output.to_path_buf(),
    })));
    observer.lock()?.record(&serde_json::json!({"kind":"partition-recovery-admitted-resources","request":request,
  "actual_available":available,"runtime_arena":resources,"independently_reserved_sdk_ram_bytes":sdk_ram,
  "ledger_ram_bytes":ledger_ram,"thread_stack_reservation_bytes":RECOVERY_THREAD_STACK_RESERVATION,
  "pre_ap_restart_cancel_supported":false,"request_grants_authority":false}))?;
    let mut events = Vec::<NativeEvent>::new();
    let operation = (|| -> Result<serde_json::Value> {
        let owner = PartitionScopedOwner::open_private(
            request.source.clone(),
            request.observation_budget,
            &mut events,
        ).context("partition recovery currently supports an actual PRIVATE source only; BasicRO/operational Basic0 terminal reconciliation is not implemented; no fallback/replay was attempted")?;
        let mut owner = owner.attach_recovery_observer(Box::new(observer.clone()), &mut events)?;
        ensure!(
            owner.binding().storage.disk_number
                == owner.state().partition.windows_volume.disk_number,
            "this explicit partition recovery route requires the same running Windows disk"
        );
        let destination = n2r_win32::partition_isolation::metadata_destination_outside_source(
            &request.source,
            parent,
            &mut events,
        )?;
        let windows = &owner.state().partition.windows_volume;
        ensure!(
            destination.disk_number == windows.disk_number
                && destination.offset == windows.offset
                && destination.length == windows.length,
            "recovery controls must be on actual Windows volume outside selected partition"
        );
        observer.checkpoint("partition-recovery-original-private-owner", &mut events)?;
        let arena = ArtifactArena::new(
            &output.join("arena"),
            resources,
            &[request.source.storage.clone(), request.shadow.clone()],
        )?;
        let budget = SourceMetadataBudget::from_resource_budget(resources)?;
        let group = arena.reserve_group(ArtifactGroup::RecoveryCopy, budget.scratch_bytes)?;
        let scratch = SourceScratch::new_auxiliary_in_arena(budget, group.clone())?;
        let stable = owner.owner_token();
        let observed = ReopenedPartitionResourceRecovery::open_observed_restarted(
            &request.publication,
            publication_sha,
            budget.record_bytes,
            &mut owner,
            &stable,
            request.observation_budget,
            &request.shadow,
            &request.journal,
            &group,
            &scratch,
            &output.join("arena/open-journal.index"),
            budget.scratch_bytes,
            &mut events,
        )?;
        observer.checkpoint(
            "partition-recovery-authenticated-original-artifacts",
            &mut events,
        )?;
        let mut recovery=match observed{
            crate::selected_journal::resource_domain::reopen::envelope::ReopenedPartitionRestart::Closed(terminal)=>{
                let expected=match request.direction{
                    PartitionRecoveryDirection::Resume=>n2r_win32::PartitionTerminalKind::Handoff,
                    PartitionRecoveryDirection::Rollback=>n2r_win32::PartitionTerminalKind::Aborted,
                };
                ensure!(terminal.kind()==expected,"requested direction conflicts with actual closed HND/ABT; opposite replay remains closed");
                let mut restoration=observer.clone();
                return terminal.finalize(owner,&mut restoration,&mut events,|phase,events|
                    observer.checkpoint(phase,events).map_err(anyhow::Error::from));
            }
            crate::selected_journal::resource_domain::reopen::envelope::ReopenedPartitionRestart::Replay(recovery)=>recovery,
        };
        let direction = match request.direction {
            PartitionRecoveryDirection::Resume => PagedRecoveryDirection::Resume,
            PartitionRecoveryDirection::Rollback => PagedRecoveryDirection::Rollback,
        };
        let replay = recovery.replay_restarted(
            &mut owner,
            &stable,
            direction,
            &group,
            &output.join("arena/replay-journal.index"),
            budget.scratch_bytes,
            &mut events,
            |events| {
                observer
                    .checkpoint("partition-recovery-actual-mixed-replay", events)
                    .map_err(anyhow::Error::from)
            },
        )?;
        observer.checkpoint("partition-recovery-actual-terminal-marker", &mut events)?;
        let mut restoration = observer.clone();
        recovery.finalize_replayed_partition(
            owner,
            replay,
            &group,
            &output.join("arena/terminal-journal.index"),
            budget.scratch_bytes,
            &mut restoration,
            &mut events,
            |phase, events| {
                observer
                    .checkpoint(phase, events)
                    .map_err(anyhow::Error::from)
            },
        )
    })();
    match operation {
        Ok(result) => {
            observer.checkpoint("partition-recovery-completed", &mut events)?;
            observer.lock()?.record(&result)?;
            save(
                &output.join("control/result.json"),
                &result,
                request.maximum_evidence_bytes,
            )?;
            Ok(())
        }
        Err(error) => {
            let drained =
                observer.checkpoint("partition-recovery-stopped-preserve-state", &mut events);
            let message = format!("{error:#}");
            let _=observer.lock().and_then(|mut l|l.record(&serde_json::json!({
    "kind":"partition-recovery-actual-error","error":message,"success":false,"automatic_restore_retry":false,
    "pre_ap_restart_cancel_supported":false,"actual_source_J_origin_state_must_be_preserved":true})));
            match drained{Ok(())=>Err(error.context("partition recovery stopped; preserve actual source and original recovery files")),
    Err(checkpoint)=>Err(error.context(format!("partition recovery stopped; durable event checkpoint also failed: {checkpoint}")))}
        }
    }
}
