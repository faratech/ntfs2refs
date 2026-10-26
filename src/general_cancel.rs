//! Public preactivation cancel using the public qualification artifact schema.
use crate::{general_operation_state as state, general_qualification as artifacts};
use anyhow::{Result, ensure};
use n2r_win32::{NativeEvent, source_cancel::UnchangedSourceLease};
pub use state::Inputs;
use std::path::Path;

pub fn cancel(inputs: &Inputs, output: &Path) -> Result<()> {
    let run = state::load(inputs)?;
    let frozen = run
        .frozen
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("cancel needs pinned qualification/source-frozen.json"))?;
    let mounts = run.mount_paths.as_ref().ok_or_else(|| {
        anyhow::anyhow!("cancel needs pinned qualification/source-mount-paths.json")
    })?;
    ensure!(
        run.blocking_artifacts.is_empty(),
        "postactivation artifacts prevent cancellation"
    );
    let mut events = Vec::<NativeEvent>::new();
    let before =
        n2r_win32::observe_general_disk_state_readonly(frozen.binding.clone(), &mut events)?;
    ensure!(
        before == frozen.state && before.disk_attributes == 3,
        "actual source differs from public frozen identity/state"
    );
    let mut journal = state::open_journal(&run)?;
    state::require_no_activation(&run, &journal)?;
    n2r_win32::source_cancel::preflight_mount_paths(&frozen.binding, &mounts.paths)?;
    artifacts::create_output(output)?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({"schema_version":1,"kind":"public-preactivation-cancel-intent","run_directory":inputs.run_directory,"conversion_intent_sha256":inputs.intent_sha256,"frozen_source_sha256":inputs.frozen_source_sha256,"mount_paths_sha256":inputs.mount_paths_sha256,"request_sha256":inputs.request_sha256,"ticket_sha256":inputs.ticket_sha256,"source_sha256":frozen.source_sha256,"journal":journal.observation,"source_payload_writes":0,"raw_reconstruction_authorized":false,"automatic_rollback_authorized":false}),
    )?;
    let mut phase = "exclusive-source-and-full-hash";
    let mut native_transition_returned = false;
    let attempted = (|| -> Result<()> {
        let source = UnchangedSourceLease::prove(
            frozen.binding.clone(),
            &frozen.state,
            &frozen.source_sha256,
            &mut events,
        )?;
        state::recheck_journal(&run, &mut journal)?;
        artifacts::save(
            output,
            "source-unchanged.json",
            &serde_json::json!({"schema_version":1,"kind":"live-exclusive-unchanged-ntfs-source","source_sha256":source.source_sha256(),"binding":frozen.binding,"expected_state":frozen.state,"raw_reconstruction_authorized":false}),
        )?;
        artifacts::save(
            output,
            "availability-intent.json",
            &serde_json::json!({"schema_version":1,"kind":"restore-unchanged-original-ntfs-availability","source_sha256":frozen.source_sha256,"expected_mount_paths":mounts.paths,"expected_disk_attributes":0,"journal_mutations_authorized":false}),
        )?;
        phase = "original-ntfs-online";
        let restored = source.restore_original_online(&mut events)?;
        native_transition_returned = true;
        artifacts::save(output, "source-restored.json", &restored)?;
        phase = "original-mount-paths";
        let paths = n2r_win32::source_cancel::restore_ntfs_mount_paths(
            frozen.binding.clone(),
            &mounts.paths,
            &mut events,
        )?;
        artifacts::save(output, "mount-paths.json", &paths)?;
        state::recheck_journal(&run, &mut journal)?;
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({"schema_version":1,"kind":"public-preactivation-cancel","success":true,"source_sha256":frozen.source_sha256,"source_hash_scope":"complete partition before original NTFS writable mount","source_original_online":true,"source_filesystem":"NTFS","original_mount_paths_preserved":true,"exclusive_source_lease":true,"journal_mutations":0,"source_payload_writes":0,"shadow_access_required":false,"raw_reconstruction_authorized":false,"events":events}),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        let observed =
            n2r_win32::observe_general_disk_state_readonly(frozen.binding.clone(), &mut events);
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({"schema_version":1,"kind":"public-preactivation-cancel-failure","phase":phase,"error":format!("{error:#}"),"native_transition_returned":native_transition_returned,"source_state_after_failure":observed.as_ref().ok(),"state_observation_error":observed.as_ref().err().map(ToString::to_string),"automatic_rollback_attempted":false,"automatic_online_retry_attempted":false,"source_payload_writes":0,"events":events}),
        )?;
        return Err(error);
    }
    Ok(())
}
