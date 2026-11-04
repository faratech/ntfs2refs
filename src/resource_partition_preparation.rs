//! Owning preparation for a selected data partition. Every source, expected
//! tree and shadow proof below comes from the actual native owners.
use super::*;
use crate::general_source_admission::resource::partition::{
    PartitionAuxiliaryDirectory, PartitionResourceSourceContext,
};
use n2r_win32::{
    partition_isolation::{PartitionObservationBudget, PartitionSourceBinding},
    partition_lifecycle::PartitionPreparationGuard,
};

pub(crate) struct PartitionPreparationRequest {
    pub binding: PartitionSourceBinding,
    pub observation_budget: PartitionObservationBudget,
    pub resources: ResourceBudget,
    pub verification_policy: VerificationPolicy,
    pub target: partition_target::PartitionTargetRequest,
}

/// Actual owners stay together until the later journal/publication/apply scope
/// consumes them. No field is a serializable conversion authorization.
pub(crate) struct PartitionPreparedResources {
    pub context: PartitionResourceSourceContext,
    pub expected: PagedExpectedTree,
    pub target: partition_target::PartitionPreparedTargetCapture,
    _projection_seal: crate::artifact_arena::ArtifactGroupSeal,
    _expected_seal: crate::artifact_arena::ArtifactGroupSeal,
    _projection_directory: PartitionAuxiliaryDirectory,
}

/// The arena already owns its ordinary external root. Source collection,
/// expected projection and target construction all use children of that same
/// root, preserving the actual native disjoint-volume checks and quotas.
pub(crate) fn prepare_partition_resources(
    request: PartitionPreparationRequest,
    arena_root: &Path,
    arena: &ArtifactArena,
    guard: PartitionPreparationGuard,
    events: &mut Vec<NativeEvent>,
    mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
) -> Result<PartitionPreparedResources> {
    request.binding.validate()?;
    request.observation_budget.validate()?;
    request.resources.validate()?;
    ensure!(
        request.binding.storage == request.target.pair.source
            && arena.budget() == request.resources,
        "partition preparation source/profile/arena differs"
    );
    // Check the actual root before any source protection transition.
    let root = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(arena_root)?;
    arena.require_root_directory(&root)?;
    checkpoint("partition-source-preparation", events)?;
    let mut context = ResourceSourceContext::prepare_partition(
        request.binding,
        request.observation_budget,
        request.resources,
        request.verification_policy,
        &arena_root.join("source-evidence"),
        arena,
        guard,
        events,
    )?;
    context.require_source_evidence()?;
    context.recheck_source(events)?;
    checkpoint("partition-expected-projection", events)?;
    let admission = context.resource_admission();
    let source_budget = SourceMetadataBudget::from_resource_budget(request.resources)?;
    let auxiliary = arena.reserve_group(ArtifactGroup::Auxiliary, source_budget.scratch_bytes)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(source_budget, auxiliary)?;
    let projection_path = arena_root.join("projection");
    let projection_directory = context.create_auxiliary_directory(&projection_path, events)?;
    let projection = SourceExpectedDomain::derive(
        context.inspection(),
        context.native().domain(),
        admission,
        &projection_path,
        &scratch,
    )?;
    let expected_group = arena.reserve_group(
        ArtifactGroup::Expected,
        admission.expected_page_budget()?.max_file_bytes,
    )?;
    let expected_path = arena_root.join("expected.pages");
    let (receipt, artifact) = PagedExpectedTree::create_with_resources_in_group(
        &projection,
        &expected_path,
        admission,
        &expected_group,
    )?;
    let expected = PagedExpectedTree::open_with_resources_in_group(
        &expected_path,
        &receipt.file_sha256,
        &receipt.semantic_sha256,
        admission,
        &expected_group,
        artifact,
    )?;
    let expected_seal = expected_group.seal()?;
    expected.require_resource_owner(admission)?;
    expected.require_shared_memory(arena)?;
    // The independently reopened expected tree owns its bytes. Release the
    // projection decoding workspace before native allocation starts.
    drop(projection);
    let projection_seal = scratch.seal()?;
    projection_directory.revalidate(&mut context, events)?;
    checkpoint("partition-expected-closed", events)?;
    let target = partition_target::prepare_partition_target_capture(
        &mut context,
        &expected,
        &request.target,
        &arena_root.join("target-construction"),
        events,
        &mut checkpoint,
    )?;
    context.recheck_source(events)?;
    expected_seal.revalidate()?;
    projection_directory.revalidate(&mut context, events)?;
    checkpoint("partition-source-and-shadow-prepared", events)?;
    Ok(PartitionPreparedResources {
        context,
        expected,
        target,
        _projection_seal: projection_seal,
        _expected_seal: expected_seal,
        _projection_directory: projection_directory,
    })
}
