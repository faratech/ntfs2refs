//! Optional NTFS-owned prealignment before the final source is frozen.
//! The closed plan and receipts are evidence, never conversion authority.
use crate::{
    artifact_arena::ArtifactArena,
    ntfs_preparation::resource::{self, PreparationExecutionOutcome},
    resource_preparation::{PreparationObserver, create_external_output},
};
use anyhow::{Context, Result, bail, ensure};
use n2r_win32::{
    general_layout::GeneralSourceShadowBinding,
    journal_file::GeneralJournalStorageBinding,
    ntfs_preparation::resource::{MoveBudget, maximum_clusters_per_move},
    tree_resources::ResourceBudget,
};
use std::path::Path;

fn aligned(bytes: u64) -> u64 {
    bytes / 4096 * 4096
}

/// All native owners from this pass are dropped before returning. The caller
/// must sample resources again and obtain a fresh frozen source certificate.
pub(super) fn run(
    pair: &GeneralSourceShadowBinding,
    journal: &GeneralJournalStorageBinding,
    run: &Path,
    resources: ResourceBudget,
    free_reserve: u64,
    evidence_remaining: u64,
    observer: &mut impl PreparationObserver,
) -> Result<()> {
    let root = run.join("ntfs-prealignment");
    let _ancestry = create_external_output(&root, journal)?;
    let arena = ArtifactArena::new(
        &root,
        resources,
        &[pair.source.clone(), pair.shadow.clone()],
    )?;
    ensure!(
        arena
            .volume_guid_path()?
            .eq_ignore_ascii_case(&journal.disk.volume_path()?),
        "prealignment arena is not on the enrolled journal volume"
    );
    let planning_bytes = aligned(resources.scratch_bytes / 2);
    let receipt_bytes = aligned(resources.scratch_bytes / 4);
    ensure!(
        planning_bytes > 0 && receipt_bytes > 0,
        "insufficient prealignment workspace"
    );

    let mut events = Vec::new();
    let planned = resource::collect_and_plan(
        pair.source.clone(),
        pair.shadow.clone(),
        resources,
        planning_bytes,
        &root,
        &arena,
        &mut events,
    );
    let logged = observer.native_events("ntfs-prealignment-plan", &mut events);
    let plan = planned?;
    logged?;
    // Reserve transient JSON/observer copies before reading the bounded row.
    {
        let _ram = arena.reserve_ram(
            resources
                .max_row_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(1024 * 1024))
                .context("prealignment summary RAM overflow")?,
        )?;
        observer.note(&serde_json::json!({"phase":"ntfs-prealignment-plan",
            "plan":plan.summary()?, "source_admission":false,
            "logical_payload_reads_may_have_occurred":true}))?;
    }
    let free = n2r_win32::resource_native::observe_available_resources(&root)?;
    ensure!(
        free.scratch_available_bytes
            >= free_reserve
                .checked_add(evidence_remaining)
                .context("prealignment reserve overflow")?,
        "prealignment cannot preserve free-space and evidence reserves"
    );
    let cluster = plan.cluster_bytes();
    let max_clusters = maximum_clusters_per_move(resources, u32::try_from(cluster)?)?;
    let limits = MoveBudget {
        maximum_moves: pair.source.identity.partition_bytes / cluster,
        maximum_move_bytes: u64::from(max_clusters)
            .checked_mul(cluster)
            .context("move size overflow")?,
        maximum_total_move_bytes: pair.source.identity.partition_bytes,
    };
    let minimum_free = free_reserve
        .checked_add(evidence_remaining)
        .context("prealignment reserve overflow")?;
    let executed = resource::execute_plan(
        &plan,
        resources,
        limits,
        receipt_bytes,
        minimum_free,
        &root.join("execution"),
        &arena,
        &mut events,
    );
    let logged = observer.native_events("ntfs-prealignment-execution", &mut events);
    let outcome = executed.context("NTFS prealignment could not complete its receipt archive; some NTFS moves may already have occurred and were not retried or undone")?;
    logged?;
    outcome.execution().revalidate()?;
    {
        let _ram = arena.reserve_ram(
            resources
                .max_row_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(1024 * 1024))
                .context("prealignment summary RAM overflow")?,
        )?;
        observer.note(&serde_json::json!({"phase":"ntfs-prealignment-execution",
            "execution":outcome.execution().summary(), "source_admission":false}))?;
    }
    if matches!(outcome, PreparationExecutionOutcome::Stopped(_)) {
        bail!(
            "NTFS prealignment stopped; consult its retained receipts. No conversion was started and submitted moves were not retried or undone"
        );
    }
    let free = n2r_win32::resource_native::observe_available_resources(&root)?;
    ensure!(
        free.scratch_available_bytes
            >= free_reserve
                .checked_add(evidence_remaining)
                .context("prealignment reserve overflow")?,
        "prealignment consumed the free-space or evidence reserve; conversion was not started"
    );
    drop(outcome);
    drop(plan);
    drop(arena);
    Ok(())
}
