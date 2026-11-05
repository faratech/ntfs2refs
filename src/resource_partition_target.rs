//! Real partition source -> native shadow construction -> protected V4 capture.
//! This entry creates no source writer, publication authority or CLI bypass.
use super::*;
use crate::{
    general_composite_target::paged::{
        ProtectedPagedTargetSelection, observe_and_select_partition_paged,
    },
    general_source_admission::resource::partition::{
        PartitionAuxiliaryDirectory, PartitionResourceSourceContext,
    },
};

pub(crate) struct PartitionTargetRequest {
    pub pair: GeneralSourceShadowBinding,
    pub maximum_placement_bytes: u64,
    pub maximum_placement_submissions: usize,
    pub maximum_materialized_bytes: u64,
    pub maximum_source_read_bytes: u64,
    pub capture_arena_bytes: u64,
    pub capture_budget: CaptureBudget,
}
pub(crate) struct PartitionPreparedTargetCapture {
    shadow: GeneralFrozenPartition,
    proof: ProtectedPagedTargetSelection,
    capture_group: crate::artifact_arena::ArtifactGroupPermit,
    capture_scratch: SourceScratch,
    _output_directory: PartitionAuxiliaryDirectory,
    _shadow_ram: crate::artifact_arena::ArenaRamLease,
}
impl PartitionPreparedTargetCapture {
    pub(crate) fn proof(&self) -> &ProtectedPagedTargetSelection {
        &self.proof
    }
    pub(crate) fn shadow(&mut self) -> &mut GeneralFrozenPartition {
        &mut self.shadow
    }
    pub(crate) fn capture_group(&self) -> &crate::artifact_arena::ArtifactGroupPermit {
        &self.capture_group
    }
    /// Actual journal-domain/index preparation borrows the still-held capture.
    /// The callback can persist/authenticate a new external journal, never apply.
    pub(crate) fn with_journal_domain<T>(
        &mut self,
        context: &mut PartitionResourceSourceContext,
        budget: ResourceJournalBudget,
        layout_index: &std::path::Path,
        events: &mut Vec<NativeEvent>,
        action: impl FnOnce(
            &ResourceJournalDomain<'_>,
            &mut PartitionResourceSourceContext,
            &mut GeneralFrozenPartition,
            &mut ProtectedCapturedCandidate<'_>,
            &mut Vec<NativeEvent>,
        ) -> Result<T>,
    ) -> Result<T> {
        self._output_directory.revalidate(context, events)?;
        context.recheck_source(events)?;
        self.proof.recheck_frozen_target(&mut self.shadow, events)?;
        let domain = ResourceJournalDomain::from_capture(
            self.proof.captured(),
            budget,
            &self.capture_group,
            &self.capture_scratch,
            layout_index,
        )?;
        let mut candidate = ProtectedCapturedCandidate::open_partition(
            &self.proof,
            &domain,
            context,
            &mut self.shadow,
            events,
        )?;
        let result = action(&domain, context, &mut self.shadow, &mut candidate, events);
        let closing = candidate.revalidate_partition(context, &mut self.shadow, events);
        match (result, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    /// Execution consumes the real prepared certificate inside the callback.
    /// A completed HND closes against NEW bytes; an interrupted execution keeps
    /// private exclusion and its recovery files. Neither case reuses OLD proof.
    pub(crate) fn with_execution_domain(
        &mut self,
        context: &mut PartitionResourceSourceContext,
        budget: ResourceJournalBudget,
        layout_index: &std::path::Path,
        events: &mut Vec<NativeEvent>,
        action: impl FnOnce(
            &ResourceJournalDomain<'_>,
            &mut PartitionResourceSourceContext,
            &mut GeneralFrozenPartition,
            &mut ProtectedCapturedCandidate<'_>,
            &mut Vec<NativeEvent>,
        ) -> Result<crate::selected_journal::resource_domain::prepare::PartitionExecutionOutcome>,
    ) -> Result<crate::selected_journal::resource_domain::prepare::PartitionApplyOutcome> {
        use crate::selected_journal::resource_domain::prepare::PartitionExecutionOutcome;
        self._output_directory.revalidate(context, events)?;
        context.recheck_source(events)?;
        self.proof.recheck_frozen_target(&mut self.shadow, events)?;
        let domain = ResourceJournalDomain::from_capture(
            self.proof.captured(), budget, &self.capture_group,
            &self.capture_scratch, layout_index,
        )?;
        let mut candidate = ProtectedCapturedCandidate::open_partition(
            &self.proof, &domain, context, &mut self.shadow, events,
        )?;
        match action(&domain, context, &mut self.shadow, &mut candidate, events) {
            Ok(PartitionExecutionOutcome::Handoff(mut outcome)) => {
                outcome.require_terminal(context, &mut self.shadow, &self.proof, events)?;
                self._output_directory.revalidate(context, events)?;
                Ok(outcome)
            }
            Ok(PartitionExecutionOutcome::Interrupted(failure)) => {
                failure.require_owner_scope(context, &self.proof)?;
                anyhow::bail!("Partition execution interrupted; preserve the private partition and recovery files: {:#}", failure.error())
            }
            Err(error) => {
                // An error cannot restore or grant replay. In particular, do
                // not assume OLD merely because the callback did not return.
                Err(error.context("Partition execution stopped; private exclusion and recovery files are preserved"))
            }
        }
    }
}

/// `pair.shadow` must be the fresh owned native provider enrolled by the SDK;
/// actual source/admission and native formatter/profile checks remain required.
pub(crate) fn prepare_partition_target_capture(
    context: &mut PartitionResourceSourceContext,
    expected: &PagedExpectedTree,
    request: &PartitionTargetRequest,
    output: &std::path::Path,
    events: &mut Vec<NativeEvent>,
    mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
) -> Result<PartitionPreparedTargetCapture> {
    // This phase writes ONLY the separately enrolled shadow. Full current
    // source GPT/C/page/dump/StorageWMI and original fingerprint bracket BOTH
    // result paths; the typed native lease narrows only per-shadow-op checks.
    context.recheck_source(events)?;
    checkpoint("partition-shadow-source-phase-opening",events)?;
    let result=prepare_partition_target_capture_inner(context,expected,request,output,events,&mut checkpoint);
    let closing=context.recheck_source(events);
    let drained=checkpoint("partition-shadow-source-phase-closing",events);
    match(result,closing,drained){
        (Ok(value),Ok(()),Ok(()))=>Ok(value),
        (Err(error),Err(closing),Err(checkpoint))=>Err(error.context(format!("full source closing check also failed: {closing:#}; source phase event checkpoint also failed: {checkpoint:#}"))),
        (Ok(_),Err(closing),Err(checkpoint))=>Err(closing.context(format!("source phase event checkpoint also failed: {checkpoint:#}"))),
        (Err(error),Err(closing),_)=>Err(error.context(format!("full source closing check also failed: {closing:#}"))),
        (Err(error),_,Err(checkpoint))=>Err(error.context(format!("source phase event checkpoint also failed: {checkpoint:#}"))),
        (Err(error),_,_)|(_,Err(error),_)|(_,_,Err(error))=>Err(error),
    }
}
fn prepare_partition_target_capture_inner(
    context:&mut PartitionResourceSourceContext,
    expected:&PagedExpectedTree,
    request:&PartitionTargetRequest,
    output:&std::path::Path,
    events:&mut Vec<NativeEvent>,
    mut checkpoint:impl FnMut(&'static str,&mut Vec<NativeEvent>)->Result<()>,
)->Result<PartitionPreparedTargetCapture>{
    let admission = context.resource_admission();
    let arena = context.arena().clone();
    let policy = context.verification_policy();
    let scratch_root = format!("{}\\", arena.volume_guid_path()?.trim_end_matches('\\'));
    let profile = crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission));
    request
        .pair
        .validate_with_resource_profile(profile.native_profile())?;
    ensure!(
        context.binding().storage == request.pair.source
            && request.maximum_source_read_bytes > 0
            && request.maximum_materialized_bytes > 0
            && request.capture_arena_bytes > 0,
        "actual partition target request/limits differ"
    );
    n2r_win32::shadow_native::private_tree::validate_placement_limits(request.maximum_placement_bytes,request.maximum_placement_submissions)?;
    request
        .capture_budget
        .validate(request.pair.source.identity.partition_bytes)?;
    expected.require_resource_owner(admission)?;
    expected.require_shared_memory(&arena)?;
    context.require_source_evidence()?;
    context.recheck_source(events)?;
    let output_directory = context.create_auxiliary_directory(output, events)?;
    let capture_group = arena.reserve_group(ArtifactGroup::Capture, request.capture_arena_bytes)?;
    let source_budget = SourceMetadataBudget::from_resource_budget(admission.budget)?;
    let placement_directory = output.join("placement");
    std::fs::create_dir(&placement_directory)?;
    let placement_scratch =
        SourceScratch::new_bounded_auxiliary_in_arena(source_budget, capture_group.clone())?;
    let mut placement_evidence = placement_evidence::PagedPlacementEvidence::create(
        &placement_directory.join("evidence"),
        placement_scratch,
    )?;
    let inputs = PagedInputs(expected);
    checkpoint("partition-shadow-allocation", events)?;
    let native_profile = profile
        .native_profile()
        .context("partition native resource profile absent")?;
    let mut private = {
        let (source, native_admission, _) = context.source_admission_and_inspection();
        let enrollment =
            n2r_win32::shadow_native::private_tree::enroll_partition_with_resource_profile(
                source,
                native_admission,
                &request.pair,
                native_profile,
            )?;
        n2r_win32::shadow_native::private_tree::allocate_enrolled_partition_domain_with_memory(
            enrollment,
            &inputs,
            native_profile,
            Arc::new(ArenaReportMemory(arena.clone())),
        )?
    };
    ensure!(
        private.allocation_ram_accounted(),
        "actual partition shadow allocation RAM lease absent"
    );
    let placement = private.place_source_prefixes_resource_domain(
        &inputs,
        request.maximum_placement_bytes,
        request.maximum_placement_submissions,
        &mut placement_evidence,
    )?;
    drop(placement);
    private.prepare_source_backed_prefixes()?;
    checkpoint("partition-source-backed-supply", events)?;
    {
        let mut bytes = PagedSourceByteAdapter::new_partition(
            context,
            admission,
            request.maximum_source_read_bytes,
        )?;
        let mut routed = general_shadow::paged_supply::routed::prepare(
            &mut bytes,
            expected,
            &mut private,
            request.maximum_materialized_bytes,
            policy,
        )?;
        let (_system, indexer) = routed.materialize_system_payloads()?;
        drop(indexer);
        let receipt = routed.verify()?;
        drop(receipt);
        bytes.finish()?;
    }
    private.complete_source_metadata_domain(&inputs, |a, b| {
        crate::ntfs_attestation::same_security(a, b).map_err(std::io::Error::other)
    })?;
    checkpoint("partition-source-after-shadow", events)?;
    context.recheck_source(events)?;
    let shadow_ram = arena.reserve_ram(
        GeneralFrozenPartition::read_buffer_memory_bytes()
            .checked_add(64 * 1024)
            .context("partition shadow native RAM overflow")?,
    )?;
    let mut shadow = GeneralFrozenPartition::isolate(request.pair.shadow.clone(), events)?;
    let capture_dir = output.join("capture");
    std::fs::create_dir(&capture_dir)?;
    checkpoint("partition-protected-target-capture", events)?;
    let proof = observe_and_select_partition_paged(
        context,
        &mut shadow,
        request.pair.clone(),
        expected,
        &capture_group,
        &output.join("target"),
        events,
        |context, target, expected, native, scope, closing| {
            let mut bytes = PagedSourceByteAdapter::new_partition(
                context,
                admission,
                request.maximum_source_read_bytes,
            )?;
            let routes = PagedPayloadRoutes::capture(
                native,
                expected,
                &mut bytes,
                &capture_dir.join("routes"),
                &capture_group,
            )?;
            let candidate = PagedSourceBackedCandidate::new(bytes, target, expected, routes)?
                .with_closing_bytes(closing);
            let mut capacity = |progress: CaptureProgress| -> Result<()> {
                let available = n2r_win32::discovery::observe_volume_space(&scratch_root)?;
                ensure!(
                    available.available_bytes_to_caller >= progress.required_available_bytes()?,
                    "partition capture lacks remaining journal/reserve capacity"
                );
                Ok(())
            };
            capture_target_selected(
                candidate,
                scope,
                &capture_dir.join("literal.bin"),
                &capture_dir.join("capture.index"),
                request.capture_budget,
                &mut capacity,
            )
        },
    )?;
    checkpoint("partition-capture-closed", events)?;
    output_directory.revalidate(context, events)?;
    let capture_scratch =
        SourceScratch::new_auxiliary_in_arena(source_budget, capture_group.clone())?;
    Ok(PartitionPreparedTargetCapture {
        shadow,
        proof,
        capture_group,
        capture_scratch,
        _output_directory: output_directory,
        _shadow_ram: shadow_ram,
    })
}
