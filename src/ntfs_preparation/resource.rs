//! Resource-paged hints for optional NTFS-driver-owned prealignment.
//! This prepass cannot issue admission or raw conversion authority. The
//! converter must discard its hints and collect a fresh frozen source later.
mod executor;
mod inventory;
mod planner;

pub(crate) use executor::{PreparationExecution, PreparationExecutionOutcome, execute_plan};
pub(crate) use inventory::PreparationInventory;
pub(crate) use planner::{PreparationPlan, TargetHintBuilder, TargetHints};

use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
};
use anyhow::{Result, ensure};
use n2r_win32::{NativeEvent, general_layout::GeneralDiskBinding, tree_resources::ResourceBudget};
use std::path::Path;

fn create_child(arena: &ArtifactArena, path: &Path) -> Result<std::fs::File> {
    use anyhow::Context;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let parent = path
        .parent()
        .context("prealignment artifact parent absent")?;
    let held = std::fs::OpenOptions::new()
        .access_mode(0x80)
        .share_mode(1)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(parent)?;
    arena.require_root_directory(&held)?;
    ensure!(
        !path.exists(),
        "fresh direct-child prealignment directory required"
    );
    std::fs::create_dir(path)?;
    let child = std::fs::OpenOptions::new()
        .access_mode(0x80)
        .share_mode(1)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(path)?;
    ensure!(
        child.metadata()?.is_dir() && child.metadata()?.file_attributes() & 0x400 == 0,
        "prealignment directory is not an actual ordinary child"
    );
    let parent_route = n2r_win32::file_storage::final_path_guid(&held)?;
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("Unicode prealignment directory name required")?;
    ensure!(
        n2r_win32::file_storage::final_path_guid(&child)?.eq_ignore_ascii_case(&format!(
            "{}\\{}",
            parent_route.trim_end_matches('\\'),
            leaf
        )),
        "prealignment child route changed during creation"
    );
    Ok(child)
}

/// Collect complete planning evidence and close every decision/move store.
/// No source freeze, source mutation, native move, or CLI selection occurs.
pub(crate) fn collect_and_plan(
    source: GeneralDiskBinding,
    shadow: GeneralDiskBinding,
    resources: ResourceBudget,
    maximum_planning_wire_bytes: u64,
    root: &Path,
    arena: &ArtifactArena,
    events: &mut Vec<NativeEvent>,
) -> Result<PreparationPlan> {
    resources.validate()?;
    ensure!(
        maximum_planning_wire_bytes > 0 && maximum_planning_wire_bytes <= resources.scratch_bytes,
        "explicit preparation planning wire budget differs"
    );
    let inventory =
        PreparationInventory::collect(source, resources, &root.join("inventory"), arena, events)?;
    let group = arena.reserve_group(ArtifactGroup::Capture, maximum_planning_wire_bytes)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(
        SourceMetadataBudget::from_resource_budget(resources)?,
        group,
    )?;
    let hints = TargetHints::collect(
        shadow,
        resources,
        &root.join("target-hints"),
        arena,
        &scratch,
    )?;
    let plan = PreparationPlan::build(&inventory, hints, &root.join("plan"), &scratch, events)?;
    drop(inventory);
    Ok(plan)
}
