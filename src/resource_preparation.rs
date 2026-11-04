//! Generic owning-machine V4 preparation. Hardware budgets and native
//! bindings are supplied by the caller; no fixture identity, job or count can
//! qualify a source. The live prepared owner never escapes this function.
use crate::{
    artifact_arena::{ArenaUsage, ArtifactArena, ArtifactGroup},
    general_composite_target::{paged::observe_and_select_paged, paged_memory::ArenaReportMemory},
    general_reconstruct::selected_native_journal::BoundNativeCreationJournal,
    general_shadow::{
        self, PagedInputs,
        paged_candidate::{PagedPayloadRoutes, PagedSourceBackedCandidate},
        paged_capture::capture_target_selected,
        source_backed::{CaptureBudget, CaptureProgress, PagedSourceByteAdapter},
    },
    general_source_admission::resource::ResourceSourceContext,
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    selected_capacity::SelectedCapacityPolicy,
    selected_journal::{
        SelectedMarkerProfile,
        resource_domain::{
            ResourceJournalBudget, ResourceJournalDomain,
            captured_candidate::ProtectedCapturedCandidate,
            prepare::{ResourcePreparedConversion, prepare_native_from_protected_capture},
        },
    },
    shadow_tree::{PagedExpectedTree, source_pages::SourceExpectedDomain},
    verification_policy::VerificationPolicy,
};

#[path = "resource_placement.rs"]
mod placement_evidence;

pub(crate) mod abort;
pub(crate) mod early_guard;
pub(crate) mod file_observer;
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent,
    general_layout::GeneralSourceShadowBinding,
    journal_file::{GeneralJournalStorageBinding, JournalProfile, MarkerStorageUse},
    tree_resources::{ResourceBudget, SourceResourceAdmission},
};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    ops::{Deref, DerefMut},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

pub(crate) struct ResourcePreparationRequest {
    pub pair: GeneralSourceShadowBinding,
    pub journal: GeneralJournalStorageBinding,
    pub resources: ResourceBudget,
    pub verification_policy: VerificationPolicy,
    pub selected_capacity_policy: SelectedCapacityPolicy,
    pub maximum_placement_bytes: u64,
    pub maximum_placement_submissions: usize,
    pub maximum_materialized_bytes: u64,
    pub maximum_source_read_bytes: Option<u64>,
    pub capture_arena_bytes: u64,
    pub locator_arena_bytes: u64,
    pub max_journal_bytes: u64,
    pub max_literal_backing_bytes: u64,
    pub max_combined_backing_and_journal_bytes: u64,
    pub minimum_free_bytes: u64,
    pub marker_profile: Option<SelectedMarkerProfile>,
    pub marker_use: MarkerStorageUse,
}
impl ResourcePreparationRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        self.resources.validate()?;
        self.pair.source.validate()?;
        self.pair.shadow.validate()?;
        self.journal.validate()?;
        let a = &self.pair.source;
        let b = &self.pair.shadow;
        ensure!(
            a.disk_number != b.disk_number
                && n2r_win32::layout::guid_bytes(&a.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&b.identity.disk_guid)?
                && n2r_win32::layout::guid_bytes(&a.identity.partition_guid)?
                    != n2r_win32::layout::guid_bytes(&b.identity.partition_guid)?
                && n2r_win32::layout::guid_bytes(&a.volume_guid)?
                    != n2r_win32::layout::guid_bytes(&b.volume_guid)?
                && a.identity.partition_bytes == b.identity.partition_bytes
                && a.identity.logical_sector_bytes == b.identity.logical_sector_bytes
                && a.identity.physical_sector_bytes == b.identity.physical_sector_bytes,
            "resource preparation source/shadow identity or geometry differs"
        );
        for disk in [a, b] {
            ensure!(
                disk.disk_number != self.journal.disk.disk_number
                    && n2r_win32::layout::guid_bytes(&disk.identity.disk_guid)?
                        != n2r_win32::layout::guid_bytes(&self.journal.disk.identity.disk_guid)?,
                "resource journal must be independent of both data disks"
            );
        }
        let profile = JournalProfile::from_schema_and_capacity(3, Some(self.max_journal_bytes))?;
        ensure!(
            profile.max_journal_bytes() == self.max_journal_bytes
                && self.maximum_placement_bytes > 0
                && self.maximum_placement_submissions > 0
                && self.maximum_materialized_bytes > 0
                && self.maximum_source_read_bytes.is_none_or(|b| b > 0)
                && self.capture_arena_bytes > 0
                && self.locator_arena_bytes > 0
                && self.max_literal_backing_bytes > 0
                && self.max_combined_backing_and_journal_bytes >= self.max_journal_bytes
                && self.minimum_free_bytes > 0,
            "resource preparation capacity differs"
        );
        Ok(())
    }
    fn source_read_budget(
        &self,
        expected: &PagedExpectedTree,
        admission: SourceResourceAdmission,
    ) -> Result<u64> {
        if let Some(bytes) = self.maximum_source_read_bytes {
            return Ok(bytes);
        }
        // Dataset-derived allowance for construction and ordered verification,
        // plus complete source/stream metadata revalidation. No file-count or
        // fixed-volume ceiling substitutes for the actual admitted domain.
        expected
            .logical_bytes()
            .checked_mul(4)
            .and_then(|n| n.checked_add(self.pair.source.identity.partition_bytes))
            .and_then(|n| {
                admission
                    .data_streams
                    .checked_mul(admission.budget.max_row_bytes)
                    .and_then(|m| n.checked_add(m))
            })
            .context("actual source read-work budget overflow")
    }
}

pub(crate) struct PreShadow<'a> {
    pub context: &'a ResourceSourceContext,
    pub expected: &'a PagedExpectedTree,
    pub arena: &'a ArtifactArena,
    pub projection_memory_before: ArenaUsage,
    pub projection_memory_after: ArenaUsage,
    pub projection_wire_bytes: u64,
}
pub(crate) trait PreparationObserver {
    /// Cleanup policy only. Actual unchanged-source or ABT proofs must still
    /// be issued by the live owning context; this flag grants no device access.
    fn restore_source_on_pre_ap_failure(&self) -> bool {
        false
    }
    fn native_events(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> Result<()>;
    fn source_prepared(&mut self, _context: &ResourceSourceContext) -> Result<()> {
        Ok(())
    }
    fn expected_prepared(
        &mut self,
        _context: &ResourceSourceContext,
        _expected: &PagedExpectedTree,
    ) -> Result<()> {
        Ok(())
    }
    fn before_shadow(&mut self, _observation: PreShadow<'_>) -> Result<()> {
        Ok(())
    }
    fn published(&mut self, _path: &Path, _sha: &str, _locator_sha: [u8; 32]) -> Result<()> {
        Ok(())
    }
    fn note(&mut self, value: &serde_json::Value) -> Result<()> {
        let mut out = std::io::stdout().lock();
        serde_json::to_writer(&mut out, value)?;
        out.write_all(b"\n")?;
        out.flush()?;
        Ok(())
    }
    fn incomplete_events(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) {
        let mut out = std::io::stderr().lock();
        let written = serde_json::to_writer(&mut out, &serde_json::json!({
            "kind":"resource-preparation-incomplete-native-events", "phase":phase,"events":events
        })).and_then(|_| out.write_all(b"\n").map_err(serde_json::Error::io))
            .and_then(|_| out.flush().map_err(serde_json::Error::io));
        if written.is_ok() {
            events.clear();
        }
    }
}
pub(crate) struct StdoutObserver;
impl PreparationObserver for StdoutObserver {
    fn native_events(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> Result<()> {
        let mut out = std::io::stdout().lock();
        serde_json::to_writer(
            &mut out,
            &serde_json::json!({"kind":"resource-native-events","phase":phase,"events":events}),
        )?;
        out.write_all(b"\n")?;
        out.flush()?;
        events.clear();
        Ok(())
    }
}
pub(crate) struct EventLog<'a, O: PreparationObserver> {
    phase: &'static str,
    events: Vec<NativeEvent>,
    observer: &'a mut O,
}
impl<'a, O: PreparationObserver> EventLog<'a, O> {
    pub(crate) fn new(observer: &'a mut O) -> Self {
        Self {
            phase: "initial",
            events: Vec::new(),
            observer,
        }
    }
    pub(crate) fn phase(&mut self, phase: &'static str) {
        self.phase = phase;
    }
    pub(crate) fn checkpoint(&mut self) -> Result<()> {
        self.observer.native_events(self.phase, &mut self.events)?;
        ensure!(
            self.events.is_empty(),
            "native event observer did not drain its completed batch"
        );
        Ok(())
    }
}
impl<O: PreparationObserver> Deref for EventLog<'_, O> {
    type Target = Vec<NativeEvent>;
    fn deref(&self) -> &Self::Target {
        &self.events
    }
}
impl<O: PreparationObserver> DerefMut for EventLog<'_, O> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.events
    }
}
impl<O: PreparationObserver> Drop for EventLog<'_, O> {
    fn drop(&mut self) {
        if !self.events.is_empty() {
            self.observer
                .incomplete_events(self.phase, &mut self.events);
        }
    }
}

pub(crate) fn create_external_output(
    output: &Path,
    journal: &GeneralJournalStorageBinding,
) -> Result<Vec<File>> {
    let parent = output.parent().context("diagnostic output parent absent")?;
    let leaf = output
        .file_name()
        .and_then(|v| v.to_str())
        .context("ordinary output name required")?;
    ensure!(
        !leaf.is_empty()
            && !leaf.ends_with([' ', '.'])
            && !leaf.chars().any(|c| c.is_control()
                || matches!(c, ':' | '/' | '\\' | '"' | '<' | '>' | '|' | '?' | '*')),
        "ambiguous diagnostic output name refused"
    );
    let mut held = Vec::new();
    for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let meta = std::fs::symlink_metadata(ancestor)?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "output ancestry must be ordinary directories"
        );
        let handle = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(ancestor)?;
        let actual = handle.metadata()?;
        ensure!(
            actual.is_dir() && actual.file_attributes() & 0x400 == 0,
            "held output ancestry is not ordinary"
        );
        held.push(handle);
    }
    let first = held
        .first()
        .context("held diagnostic output parent missing")?;
    let first_id = n2r_win32::file_storage::file_id_info(first)?;
    let route = n2r_win32::file_storage::final_path_guid(first)?;
    let end = route
        .find("}\\")
        .context("output parent has no volume GUID root")?
        + 1;
    ensure!(
        route[..end].eq_ignore_ascii_case(&journal.disk.volume_path()?),
        "diagnostic output must be on the actual external journal volume"
    );
    let checked = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(parent)?;
    ensure!(
        n2r_win32::file_storage::file_id_info(&checked)? == first_id
            && n2r_win32::file_storage::final_path_guid(&checked)?.eq_ignore_ascii_case(&route),
        "output parent route changed before creation"
    );
    held.push(checked);
    std::fs::create_dir(output)?;
    let created = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(output)?;
    let created_meta = created.metadata()?;
    let created_route = n2r_win32::file_storage::final_path_guid(&created)?;
    ensure!(
        created_meta.is_dir()
            && created_meta.file_attributes() & 0x400 == 0
            && created_route
                .to_ascii_lowercase()
                .starts_with(&(route.trim_end_matches('\\').to_ascii_lowercase() + "\\")),
        "created diagnostic output differs from held parent"
    );
    held.push(created);
    Ok(held)
}

pub(crate) fn prepare_with<T, O, F>(
    request: ResourcePreparationRequest,
    output: &Path,
    observer: &mut O,
    consume: F,
) -> Result<T>
where
    O: PreparationObserver,
    F: for<'journal, 'domain, 'capture, 'proof, 'scope, 'expected> FnOnce(
        ResourcePreparedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>,
        &mut Vec<NativeEvent>,
        &mut O,
    ) -> Result<T>,
{
    request.validate()?;
    let parent = output.parent().context("diagnostic output parent absent")?;
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    available.validate_budget(request.resources)?;
    let _output_ancestry = create_external_output(output, &request.journal)?;
    let arena = ArtifactArena::new(
        output,
        request.resources,
        &[request.pair.source.clone(), request.pair.shadow.clone()],
    )?;
    ensure!(
        arena
            .volume_guid_path()?
            .eq_ignore_ascii_case(&request.journal.disk.volume_path()?),
        "diagnostic arena must use the actual external journal volume"
    );
    let mut events = EventLog::new(observer);
    let locator_group =
        arena.reserve_group(ArtifactGroup::RecoveryCopy, request.locator_arena_bytes)?;
    events.phase("early-preparation-guard");
    let early_guard = early_guard::EarlyPreparationGuard::create(
        &request.pair,
        &request.journal,
        request.resources,
        output,
        &arena,
        &locator_group,
        &mut events,
    )?;
    events.observer.note(
        &serde_json::json!({"kind":"resource-preparation-cancellation-anchor",
        "intent":early_guard.pin(),"source_payload_writes_authorized":false}),
    )?;
    {
        let pin = early_guard.pin();
        println!(
            "Preparation recovery: {}\nPreparation SHA-256: {}",
            pin.path.display(),
            pin.sha256
        );
        std::io::stdout().flush()?;
    }
    events.checkpoint()?;
    events.phase("source-preparation");
    let mut phase = "source-start";
    let restore_on_failure = events.observer.restore_source_on_pre_ap_failure();
    let source_result = ResourceSourceContext::prepare_with_guard(
        request.pair.source.clone(),
        request.resources,
        request.verification_policy,
        &output.join("source"),
        &arena,
        &mut events,
        &mut phase,
        restore_on_failure,
        Some(early_guard),
    );
    events.phase(phase);
    let mut context = source_result?;
    let mut published: Option<(PathBuf, [u8; 32])> = None;
    let result = (|| -> Result<T> {
        events.checkpoint()?;
        events.phase("source-recheck");
        context.require_source_evidence()?;
        context.recheck_source(&mut events)?;
        events.checkpoint()?;
        events.observer.source_prepared(&context)?;
        let admission = context.resource_admission();
        let profile = crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission));
        request
            .pair
            .validate_with_resource_profile(profile.native_profile())?;
        let source_budget = SourceMetadataBudget::from_resource_budget(request.resources)?;
        let aux_group =
            arena.reserve_group(ArtifactGroup::Auxiliary, source_budget.scratch_bytes)?;
        let aux_scratch = SourceScratch::new_auxiliary_in_arena(source_budget, aux_group)?;
        let projection_dir = output.join("projection");
        std::fs::create_dir(&projection_dir)?;
        let projection = SourceExpectedDomain::derive(
            context.inspection(),
            context.native().domain(),
            admission,
            &projection_dir,
            &aux_scratch,
        )?;
        let expected_group = arena.reserve_group(
            ArtifactGroup::Expected,
            admission.expected_page_budget()?.max_file_bytes,
        )?;
        let expected_path = output.join("expected.pages");
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
        let _expected_seal = expected_group.seal()?;
        expected.require_shared_memory(&arena)?;
        expected.require_resource_owner(admission)?;
        events.observer.expected_prepared(&context, &expected)?;
        // The complete independently held expected pages are now reopened,
        // authenticated and resource-bound. Their producer is no longer used:
        // release its 8-row workspace before native shadow construction. The
        // original source/native owners and expected page lease stay alive.
        let memory_before_projection_drop = arena.usage()?;
        drop(projection);
        // The expected tree now owns its independent authenticated pages. No
        // subsequent phase writes through this projection scratch. Seal its
        // retained real file owners so only actual wire bytes remain reserved.
        let projection_seal = aux_scratch.seal()?;
        let memory_after_projection_drop = arena.usage()?;
        events.observer.before_shadow(PreShadow {
            context: &context,
            expected: &expected,
            arena: &arena,
            projection_memory_before: memory_before_projection_drop,
            projection_memory_after: memory_after_projection_drop,
            projection_wire_bytes: projection_seal.wire_bytes(),
        })?;
        let maximum_source_read_bytes = request.source_read_budget(&expected, admission)?;
        let inputs = PagedInputs(&expected);

        // Placement and later target capture share one actual quota. Keep
        // every complete placement proof in its constructor-owned page files.
        let capture_group =
            arena.reserve_group(ArtifactGroup::Capture, request.capture_arena_bytes)?;
        let placement_directory = output.join("placement");
        std::fs::create_dir(&placement_directory)?;
        let placement_scratch =
            SourceScratch::new_bounded_auxiliary_in_arena(source_budget, capture_group.clone())?;
        let mut placement_evidence = placement_evidence::PagedPlacementEvidence::create(
            &placement_directory.join("evidence"),
            placement_scratch,
        )?;

        // Every native allocation uses this actual shared arena accountant.
        let mut private = {
            let (source, _) = context.source_and_inspection();
            let native_profile = profile
                .native_profile()
                .context("native resource profile absent")?;
            let enrollment = n2r_win32::shadow_native::private_tree::enroll_with_resource_profile(
                source,
                &request.pair,
                native_profile,
            )?;
            n2r_win32::shadow_native::private_tree::allocate_enrolled_domain_with_memory(
                enrollment,
                &inputs,
                native_profile,
                Arc::new(ArenaReportMemory(arena.clone())),
            )?
        };
        ensure!(
            private.allocation_ram_accounted(),
            "native private-tree allocation lease is absent"
        );
        let placement = match private.place_source_prefixes_resource_domain(
            &inputs,
            request.maximum_placement_bytes,
            request.maximum_placement_submissions,
            &mut placement_evidence,
        ) {
            Ok(report) => report,
            Err(error) => {
                let progress = private.placement_progress();
                events.observer.note(&serde_json::json!({
                    "kind":"resource-placement-refusal", "phase":progress.get("phase"),
                    "counters":progress.get("counters"), "refusal":progress.get("refusal"),
                    "source_payload_writes":0, "conversion_authorized":false,
                }))?;
                return Err(error.into());
            }
        };
        events.observer.note(&serde_json::json!({
            "kind":"resource-placement-summary",
            "original_coordinate_bytes":placement.get("original_coordinate_bytes"),
            "move_bytes_submitted":placement.get("move_bytes_submitted"),
            "counters":placement.get("counters"), "source_payload_writes":0,
            "conversion_authorized":false,
        }))?;
        drop(placement);
        private.prepare_source_backed_prefixes()?;
        {
            let (source, raw) = context.source_and_inspection();
            let mut bytes =
                PagedSourceByteAdapter::new(source, raw, admission, maximum_source_read_bytes)?;
            let mut routed = general_shadow::paged_supply::routed::prepare(
                &mut bytes,
                &expected,
                &mut private,
                request.maximum_materialized_bytes,
                request.verification_policy,
            )?;
            let (_system, indexer) = routed.materialize_system_payloads()?;
            drop(indexer);
            let supply_receipt = routed.verify()?;
            events
                .observer
                .note(&serde_json::to_value(&supply_receipt)?)?;
            bytes.finish()?;
        }
        private.complete_source_metadata_domain(&inputs, |a, b| {
            crate::ntfs_attestation::same_security(a, b).map_err(std::io::Error::other)
        })?;
        events.phase("source-after-shadow-construction");
        context.recheck_source(&mut events)?;
        events.checkpoint()?;
        let shadow_ram = arena.reserve_ram(
            GeneralFrozenPartition::read_buffer_memory_bytes()
                .checked_add(64 * 1024)
                .context("shadow native RAM overflow")?,
        )?;
        events.phase("shadow-freeze");
        let mut shadow = GeneralFrozenPartition::isolate(request.pair.shadow.clone(), &mut events)?;
        events.checkpoint()?;
        let capture_dir = output.join("capture");
        std::fs::create_dir(&capture_dir)?;
        let capture_budget = CaptureBudget {
            max_changed_bytes: request.pair.source.identity.partition_bytes / 4096 * 4096,
            max_journal_bytes: request.max_journal_bytes,
            max_literal_backing_bytes: request.max_literal_backing_bytes,
            max_combined_backing_and_journal_bytes: request.max_combined_backing_and_journal_bytes,
            minimum_free_bytes: request.minimum_free_bytes,
            selected_capacity_policy: request.selected_capacity_policy,
        };
        let journal_root = format!("{}\\", request.journal.disk.volume_path()?);
        events.phase("protected-target-capture");
        let proof = observe_and_select_paged(
            &mut context,
            &mut shadow,
            request.pair.clone(),
            &expected,
            &capture_group,
            &output.join("target"),
            &mut events,
            |context, target, expected, native, scope, closing| {
                let (source, raw) = context.source_and_inspection();
                let mut bytes =
                    PagedSourceByteAdapter::new(source, raw, admission, maximum_source_read_bytes)?;
                let routes = PagedPayloadRoutes::capture(
                    native,
                    expected,
                    &mut bytes,
                    &capture_dir.join("routes"),
                    &capture_group,
                )?;
                let candidate = PagedSourceBackedCandidate::new(bytes, target, expected, routes)?
                    .with_closing_bytes(closing);
                let mut guard = |p: CaptureProgress| -> Result<()> {
                    let space = n2r_win32::discovery::observe_volume_space(&journal_root)?;
                    ensure!(
                        space.available_bytes_to_caller >= p.required_available_bytes()?,
                        "capture does not have its remaining journal and reserve capacity"
                    );
                    Ok(())
                };
                capture_target_selected(
                    candidate,
                    scope,
                    &capture_dir.join("literal.bin"),
                    &capture_dir.join("capture.index"),
                    capture_budget,
                    &mut guard,
                )
            },
        )?;
        events.checkpoint()?;
        let capture_scratch =
            SourceScratch::new_auxiliary_in_arena(source_budget, capture_group.clone())?;
        let domain = ResourceJournalDomain::from_capture(
            proof.captured(),
            ResourceJournalBudget {
                max_selected_bytes: capture_budget.max_changed_bytes,
                max_journal_bytes: request.max_journal_bytes,
                marker_profile: request.marker_profile,
            },
            &capture_group,
            &capture_scratch,
            &output.join("journal-layout.index"),
        )?;
        events.phase("captured-candidate-open");
        let mut candidate = ProtectedCapturedCandidate::open(
            &proof,
            &domain,
            &mut context,
            &mut shadow,
            &mut events,
        )?;
        events.checkpoint()?;
        events.phase("native-journal-create");
        let mut creation = {
            let (source, _) = context.source_and_inspection();
            BoundNativeCreationJournal::create_new(
                source,
                &mut shadow,
                &arena,
                domain.facts().journal_length,
                &output.join("selected.journal"),
                &request.journal,
                JournalProfile::from_schema_and_capacity(3, Some(request.max_journal_bytes))?,
                domain.facts().marker_profile,
                request.marker_use,
                &mut events,
            )?
        };
        events.checkpoint()?;
        events.phase("native-journal-preparation");
        let mut prepared = prepare_native_from_protected_capture(
            &domain,
            &mut context,
            &mut shadow,
            &mut candidate,
            &mut creation,
            &mut events,
        )?;
        events.checkpoint()?;
        // No capture producer remains after native preparation. Seal its actual
        // closed files before reserving the separate map group, so unused promised
        // capture capacity is not mistaken for a second simultaneous allocation.
        let _capture_seal = capture_group.seal()?;
        // Observational post-alpha accounting at the existing closed-capture /
        // prepared-journal boundary. No payload read, new authority or quota.
        let literal = proof.captured().literal().pin();
        let index = proof.captured().index().pin();
        let index_allocation = proof.captured().index().observe_allocation_bytes();
        let capture_reads = proof.captured().summary().get("read_counts");
        let journal = domain.facts();
        let usage = arena.usage();
        let mut accounting = serde_json::json!({
            "kind":"pre-ap-resource-accounting-v1","phase":"native-journal-prepared-before-publication",
            "admitted_resource_ram_bytes":request.resources.ram_bytes,
            "capture_literal_file_bytes":literal.snapshot.file_bytes,
            "capture_literal_recorded_allocation_bytes":literal.snapshot.allocation_bytes,
            "capture_literal_allocation_basis":"closed held capture pin; not a peak measurement",
            "capture_index_wire_bytes":index.bytes,
            "capture_index_physical_allocation_bytes":index_allocation.as_ref().ok().copied(),
            "capture_index_length_is_not_physical_allocation":true,
            "encoded_journal_bytes":journal.journal_length,
            "encoded_journal_length_is_not_physical_allocation":true,
            "selected_bytes":journal.selected_bytes,"old_zero_bytes":journal.old_zero_bytes,
            "source_free_bytes":journal.source_free_bytes,"new_zero_bytes":journal.new_zero_bytes,
            "copy_bytes":journal.copy_bytes,"literal_bytes":journal.literal_bytes,
            "journal_classifications_are_not_source_device_IO_counters":true,
            "source_payload_bytes_read":Option::<u64>::None,
            "source_payload_bytes_written":Option::<u64>::None,
            "source_payload_counter_basis":"not available in this metadata sample",
            "capture_source_logical_bytes":capture_reads.and_then(|v|v.get("source_logical_bytes")).and_then(serde_json::Value::as_u64),
            "capture_shadow_bytes":capture_reads.and_then(|v|v.get("shadow_bytes")).and_then(serde_json::Value::as_u64),
            "capture_source_reference_bytes":capture_reads.and_then(|v|v.get("source_reference_bytes")).and_then(serde_json::Value::as_u64),
            "capture_source_reference_bytes_reused":capture_reads.and_then(|v|v.get("source_reference_bytes_reused")).and_then(serde_json::Value::as_u64),
            "capture_counters_are_one_stage_not_total_device_traffic":true,
            "arena_observed_wire_bytes":usage.as_ref().ok().map(|v|v.actual_wire_bytes),
            "arena_observed_allocation_bytes":usage.as_ref().ok().map(|v|v.actual_allocated_bytes),
            "arena_promised_bytes":usage.as_ref().ok().map(|v|v.promised_bytes),
            "arena_leased_ram_bytes":usage.as_ref().ok().map(|v|v.leased_ram_bytes),
            "arena_registry_ram_bytes":usage.as_ref().ok().map(|v|v.registry_ram_bytes),
            "arena_observation_error":usage.as_ref().err().map(ToString::to_string),
            "capture_arena_ceiling_bytes":request.capture_arena_bytes,
            "literal_backing_ceiling_bytes":request.max_literal_backing_bytes,
            "journal_ceiling_bytes":request.max_journal_bytes,
            "combined_backing_journal_ceiling_bytes":request.max_combined_backing_and_journal_bytes,
            "observed_allocation_and_reserved_ceilings_are_distinct":true,
            "metadata_queries_only":true,"peak_or_physical_usage_measured":false,
            "AP_or_source_write_authority_granted":false
        });
        accounting["capture_index_allocation_observation_error"] =
            serde_json::json!(index_allocation.as_ref().err().map(ToString::to_string));
        accounting["capture_index_allocation_basis"] =
            serde_json::json!("current retained readonly file metadata; telemetry only");
        events.observer.note(&accounting)?;
        events.phase("recovery-map-publication");
        let map_group = if prepared.recovery_maps_required(&expected)? {
            Some(arena.reserve_group(
                ArtifactGroup::Map,
                admission.map_page_budget()?.max_file_bytes,
            )?)
        } else {
            None
        };
        let locator_scratch =
            SourceScratch::new_auxiliary_in_arena(source_budget, locator_group.clone())?;
        let (recovery_maps, locator) = {
            let EventLog {
                observer,
                events: native_events,
                ..
            } = &mut events;
            prepared.create_recovery_metadata(
                &expected,
                map_group.as_ref(),
                &capture_scratch,
                &output.join("recovery-maps.pages"),
                &locator_group,
                &locator_scratch,
                &output.join("recovery.locator"),
                native_events,
                |phase, batch| observer.native_events(phase, batch),
            )?
        };
        events.checkpoint()?;
        events.phase("prepared-conversion-publication");
        let prepared_conversion = {
            let EventLog {
                observer,
                events: native_events,
                ..
            } = &mut events;
            ResourcePreparedConversion::publish(
                prepared,
                &expected,
                recovery_maps,
                locator,
                &locator_group,
                &locator_scratch,
                &output.join("recovery-envelope.json"),
                native_events,
                |batch| observer.native_events("prepared-conversion-publication", batch),
            )?
        };
        let publication_digest: [u8; 32] = hex::decode(prepared_conversion.publication_sha256())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("published recovery checksum length differs"))?;
        published = Some((
            prepared_conversion.publication_path().to_path_buf(),
            publication_digest,
        ));
        events.checkpoint()?;
        events.observer.published(
            prepared_conversion.publication_path(),
            prepared_conversion.publication_sha256(),
            prepared_conversion.locator_sha256(),
        )?;
        // Consume only inside this lexical scope. A callback cannot return any
        // borrowed prepared/source/journal owner as its lifetime-independent T.
        let result = {
            let EventLog {
                observer,
                events: native_events,
                ..
            } = &mut events;
            consume(prepared_conversion, native_events, *observer)?
        };
        events.checkpoint()?;
        drop(creation);
        drop(candidate);
        drop(domain);
        drop(proof);
        drop(shadow);
        drop(shadow_ram);
        Ok(result)
    })();
    match result {
        Ok(value) => Ok(value),
        Err(original) => {
            if !events.observer.restore_source_on_pre_ap_failure() {
                return Err(original
                    .context("diagnostic observer did not request automatic source restoration"));
            }
            // A cleared witness means an AP write was attempted, even if the
            // call failed before the disk attributes changed. Never infer a
            // safe cancellation from marker absence in that state.
            if !context.has_original_freeze_witness() {
                return Err(original.context(
                    "apply intent was attempted; preserve and classify the recovery journal",
                ));
            }
            if let Some((path, sha)) = published {
                // Recheck the actual still-held pre-AP source before releasing
                // it. The reopened recovery path independently authenticates
                // the publication and writes durable ABT before NTFS online.
                events.phase("pre-ap-published-cancellation-check");
                let checked = context
                    .recheck_source(&mut events)
                    .and_then(|()| events.checkpoint());
                if let Err(cleanup) = checked {
                    return Err(original.context(format!("pre-AP cancellation source recheck failed; disk remains excluded: {cleanup:#}")));
                }
                drop(context);
                drop(events);
                drop(arena);
                let cancelled = crate::resource_recovery::recover_resource_allocation_with_observer(
                    request.pair.clone(),
                    request.journal.clone(),
                    &path,
                    sha,
                    request.resources,
                    &output.join("pre-ap-cancellation"),
                    true,
                    observer,
                );
                match cancelled {
                    Ok(receipt) => Err(original.context(format!("conversion failed before AP; original NTFS restored through durable cancellation: {receipt}"))),
                    Err(cleanup) => Err(original.context(format!("conversion failed before AP; durable cancellation did not complete and source may remain excluded or already be online: {cleanup:#}"))),
                }
            } else {
                if context.early_preparation_delegated()? {
                    return Err(original.context("preparation delegated to its durable final publication; preserve it and the excluded source for explicit authenticated recovery"));
                }
                if output.join("recovery-envelope.json").exists() {
                    return Err(original.context("publication may be partial; preserve it and the excluded source for explicit recovery"));
                }
                match abort::restore_live_source(context, &mut events) {
                    Ok(mounted) => Err(original.context(format!("conversion failed before publication; unchanged original NTFS restored on disk {}", mounted.disk_number))),
                    Err(cleanup) => Err(original.context(format!("conversion failed before publication; original NTFS cleanup did not complete and source may remain excluded or already be online: {cleanup:#}"))),
                }
            }
        }
    }
}
