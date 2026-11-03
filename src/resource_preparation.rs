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
            durable_anchor::DurableRecoveryLocator,
            prepare::{ResourcePreparedConversion, prepare_native_from_protected_capture},
        },
    },
    shadow_tree::{PagedExpectedTree, source_pages::SourceExpectedDomain},
    verification_policy::VerificationPolicy,
};
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
    path::{Component, Path},
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
            let mut out = std::io::stderr().lock();
            let _ = serde_json::to_writer(
                &mut out,
                &serde_json::json!({"kind":"resource-preparation-incomplete-native-events","phase":self.phase,"events":self.events}),
            );
            let _ = out.write_all(b"\n");
            let _ = out.flush();
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
    events.phase("source-preparation");
    let mut phase = "source-start";
    let source_result = ResourceSourceContext::prepare(
        request.pair.source.clone(),
        request.resources,
        request.verification_policy,
        &output.join("source"),
        &arena,
        &mut events,
        &mut phase,
    );
    events.phase(phase);
    let mut context = source_result?;
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
    let aux_group = arena.reserve_group(ArtifactGroup::Auxiliary, source_budget.scratch_bytes)?;
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
    let placement = match private.place_source_prefixes_domain(
        &inputs,
        request.maximum_placement_bytes,
        request.maximum_placement_submissions,
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
    let capture_group = arena.reserve_group(ArtifactGroup::Capture, request.capture_arena_bytes)?;
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
    let mut candidate =
        ProtectedCapturedCandidate::open(&proof, &domain, &mut context, &mut shadow, &mut events)?;
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
    events.phase("recovery-map-publication");
    let recovery_maps = if prepared.recovery_maps_required(&expected)? {
        let map_group = arena.reserve_group(
            ArtifactGroup::Map,
            admission.map_page_budget()?.max_file_bytes,
        )?;
        let maps = prepared.create_recovery_maps(
            &expected,
            &map_group,
            &capture_scratch,
            &output.join("recovery-maps.pages"),
            &mut events,
        )?;
        let _map_seal = map_group.seal()?;
        Some(maps)
    } else {
        None
    };
    events.checkpoint()?;
    let locator_group =
        arena.reserve_group(ArtifactGroup::RecoveryCopy, request.locator_arena_bytes)?;
    let locator_scratch =
        SourceScratch::new_auxiliary_in_arena(source_budget, locator_group.clone())?;
    events.phase("durable-locator");
    let locator = DurableRecoveryLocator::create_from_protected_preparation(
        &mut prepared,
        &locator_group,
        &locator_scratch,
        &output.join("recovery.locator"),
        &mut events,
    )?;
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
}
