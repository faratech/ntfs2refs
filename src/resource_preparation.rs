//! Generic owning-machine V4 preparation. Hardware budgets and native
//! bindings are supplied by the caller; no fixture identity, job or count can
//! qualify a source. The live prepared owner never escapes this function.
use crate::{
    artifact_arena::{ArenaUsage, ArtifactArena, ArtifactGroup},
    general_composite_target::paged_memory::ArenaReportMemory,
    general_reconstruct::selected_native_journal::BoundNativeCreationJournal,
    general_shadow::{
        self, PagedInputs,
        paged_candidate::{PagedPayloadRoutes, PagedSourceBackedCandidateWithScope},
        paged_capture::capture_target_selected,
        source_backed::{CaptureBudget, CaptureProgress, PagedSourceByteAdapter, PagedSourceByteAdapterWithScope},
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
#[path = "resource_partition_preparation.rs"]
pub(crate) mod partition_preparation;
#[path = "resource_partition_target.rs"]
pub(crate) mod partition_target;
mod resume_checkpoint;
pub(crate) mod resume_origin;
pub(crate) mod resume_session_inputs;
pub(crate) mod resume_workspace;
/// Process-wide diagnose switch, set once by the command line before
/// preparation starts. In diagnose mode preparation collects per-object
use anyhow::{Context, Result, ensure};

/// Process-wide diagnose switch, set once by the command line before
/// preparation starts. In diagnose mode preparation collects per-object
/// failures and always stops before publication.
static DIAGNOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn set_diagnose() {
    DIAGNOSE.store(true, std::sync::atomic::Ordering::SeqCst);
}
fn diagnose() -> bool {
    DIAGNOSE.load(std::sync::atomic::Ordering::SeqCst)
}

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

/// Immutable cached inputs describe facts. Fresh source continuity and native
/// cold-shadow adoption below must issue this invocation's actual owners.
#[derive(Clone)]
pub(crate) struct ResumePreparation {
    pub arena_root: PathBuf,
    pub arena: ArtifactArena,
    pub locator_group: crate::artifact_arena::ArtifactGroupPermit,
    pub source: crate::general_source_admission::resource::SourceCacheOriginPins,
    pub source_origin_sha256: [u8; 32],
    pub expected: crate::general_source_admission::resource::SourceCacheFilePin,
    pub expected_binding: Option<crate::shadow_tree::ExpectedBindingPin>,
    pub completed_placement: Option<resume_session_inputs::HeldCompletedPlacement>,
    pub completed_payloads: Option<resume_session_inputs::HeldCompletedPayloads>,
    pub shadow_start: resume_session_inputs::ShadowStart,
    pub shadow_origin: n2r_win32::shadow_native::private_tree::recovery::ExternalOriginPins,
    pub prior_spend: n2r_win32::shadow_native::private_tree::recovery::PartialPlacementSpend,
    pub placement_limits: n2r_win32::shadow_native::private_tree::recovery::RecoveryLimits,
    pub legacy_terminal: Option<crate::general_source_admission::resource::SourceCacheFilePin>,
    pub prior_resume_intent: Option<crate::preparation_resume::ArtifactPin>,
    pub workspace_origin: Option<(PathBuf, GeneralJournalStorageBinding)>,
    pub parent_resources: resume_origin::ParentPublicResources,
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
    fn prefer_durable_preparation_cancellation(&self) -> bool {
        false
    }
    fn remaining_scratch_reservation_bytes(&self) -> u64 {
        0
    }
    /// Actual provider/backing owner, not a serialized capacity claim. Long
    /// native loops must consult this before their bounded allocating work.
    fn backing_resource_guard(
        &self,
    ) -> Option<std::sync::Arc<n2r_win32::managed_shadow::BackingResourceGuard>> {
        None
    }
    fn progress_reporter(&self) -> n2r_win32::progress::Reporter {
        n2r_win32::progress::Reporter::default()
    }
    fn parent_public_resources(&self) -> Option<&resume_origin::ParentPublicResources> {
        None
    }
    fn preparation_created(&mut self, _pin: &early_guard::GuardPin) -> Result<()> {
        Ok(())
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
        n2r_win32::perf::phase(phase);
        use n2r_win32::progress::{Phase,Unit,Update};
        let typed=match phase {
            "source-preparation"|"source-recheck"=>Some(Phase::SourceEvidence),
            "expected-preparation"=>Some(Phase::ExpectedPreparation),
            "shadow-allocation"=>Some(Phase::ShadowAllocation),
            "shadow-placement"=>Some(Phase::Placement),
            "metadata-recovery-verification"=>Some(Phase::PayloadVerification),
            "protected-target-capture"=>Some(Phase::TargetCapture),
            "native-journal-preparation"=>Some(Phase::RecoveryJournal),
            _=>None,
        };
        if let Some(phase)=typed {
            self.observer.progress_reporter().report(Update::new(phase,Unit::Operations,0,None));
        }
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
        // Attribute-only handles used to pin the route. Share everything,
        // including delete: another holder with delete access on a working
        // directory must not turn this into a sharing violation.
        let handle = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(7)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(ancestor)
            .with_context(|| format!("holding output ancestor {}", ancestor.display()))?;
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
        .share_mode(7)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(parent)
        .with_context(|| format!("rechecking output parent {}", parent.display()))?;
    ensure!(
        n2r_win32::file_storage::file_id_info(&checked)? == first_id
            && n2r_win32::file_storage::final_path_guid(&checked)?.eq_ignore_ascii_case(&route),
        "output parent route changed before creation"
    );
    held.push(checked);
    std::fs::create_dir(output).with_context(|| format!("creating output {}", output.display()))?;
    let created = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(7)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(output)
        .with_context(|| format!("holding created output {}", output.display()))?;
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
    prepare_with_mode(request, output, observer, consume, None)
}

pub(crate) fn resume_with<T, O, F>(
    request: ResourcePreparationRequest,
    output: &Path,
    observer: &mut O,
    resume: &ResumePreparation,
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
    prepare_with_mode(request, output, observer, consume, Some(resume))
}

fn prepare_with_mode<T, O, F>(
    mut request: ResourcePreparationRequest,
    output: &Path,
    observer: &mut O,
    consume: F,
    resume: Option<&ResumePreparation>,
) -> Result<T>
where
    O: PreparationObserver,
    F: for<'journal, 'domain, 'capture, 'proof, 'scope, 'expected> FnOnce(
        ResourcePreparedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>,
        &mut Vec<NativeEvent>,
        &mut O,
    ) -> Result<T>,
{
    let original_resources = request.resources;
    let trust_repair_allocation = if request.pair.source.layout_profile
        == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
    {
        let allocation =
            crate::refs_security_integration::TrustRepairAllocation::split(original_resources)?;
        request.resources = allocation.main;
        Some(allocation)
    } else {
        None
    };
    request.validate()?;
    let parent = output.parent().context("diagnostic output parent absent")?;
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    if let Some(saved) = resume {
        ensure!(
            saved.source.source == request.pair.source
                && saved.source.resource_admission.budget == request.resources
                && saved.source.policy == request.verification_policy
                && original_resources.ram_bytes <= available.available_physical_bytes,
            "resume source/wire profile or actual RAM differs"
        );
    } else {
        available.validate_budget(original_resources)?;
    }
    let _output_ancestry = create_external_output(output, &request.journal)?;
    let excluded = [request.pair.source.clone(), request.pair.shadow.clone()];
    let arena = if let Some(saved) = resume {
        ensure!(
            saved.arena.budget() == request.resources,
            "resume inputs lost the actual newly admitted arena"
        );
        saved.arena.clone()
    } else {
        ArtifactArena::new(output, request.resources, &excluded)?
    };
    if request.pair.source.layout_profile
        == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
    {
        if let Some(saved) = resume {
            arena.require_native_allocation(saved.source.resource_admission)?;
        } else {
            arena.use_windows_native_allocation(&request.pair.source)?;
        }
    }
    ensure!(
        arena
            .volume_guid_path()?
            .eq_ignore_ascii_case(&request.journal.disk.volume_path()?),
        "diagnostic arena must use the actual external journal volume"
    );
    let mut events = EventLog::new(observer);
    if let Some(allocation) = trust_repair_allocation {
        events.observer.note(&serde_json::json!({
            "kind":"Windows-constructor-security-repair-resource-split-v1",
            "allocation":allocation,"combined_budget_unchanged":true,
            "source_security_expectations_changed":false,
        }))?;
    }
    let locator_group = if let Some(saved) = resume {
        ensure!(
            saved.locator_group.group() == ArtifactGroup::RecoveryCopy
                && saved.locator_group.arena().same_arena(&arena),
            "resume locator group differs from actual arena"
        );
        saved.locator_group.clone()
    } else {
        arena.reserve_group(ArtifactGroup::RecoveryCopy, request.locator_arena_bytes)?
    };
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
    events.observer.preparation_created(&early_guard.pin())?;
    if resume.is_some() {
        // Exercise the exact checkpoint owner/path conversion before any
        // expensive source revalidation or source exclusion begins.
        resume_checkpoint::preflight_new_guard(&early_guard, &locator_group)?;
    }
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
    let restore_on_failure = events.observer.restore_source_on_pre_ap_failure()
        && !events.observer.prefer_durable_preparation_cancellation();
    let source_result = if let Some(saved) = resume {
        ResourceSourceContext::prepare_cached_exact_with_guard(
            request.pair.source.clone(),
            request.resources,
            request.verification_policy,
            &output.join("source"),
            &arena,
            &mut events,
            &mut phase,
            restore_on_failure,
            early_guard,
            &saved.source,
            saved.source_origin_sha256,
        )
    } else {
        ResourceSourceContext::prepare_with_guard(
            request.pair.source.clone(),
            request.resources,
            request.verification_policy,
            &output.join("source"),
            &arena,
            &mut events,
            &mut phase,
            restore_on_failure,
            Some(early_guard),
        )
    };
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
        events.phase("expected-preparation");
        let profile = crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission));
        request
            .pair
            .validate_with_resource_profile(profile.native_profile())?;
        let source_budget = SourceMetadataBudget::from_resource_budget(request.resources)?;
        let aux_group = if let Some(group) = context.cached_auxiliary_group() {
            ensure!(
                group.arena().same_arena(&arena),
                "cached auxiliary owner differs"
            );
            arena.retained_group(ArtifactGroup::Auxiliary, source_budget.scratch_bytes)?
        } else {
            arena.reserve_group(ArtifactGroup::Auxiliary, source_budget.scratch_bytes)?
        };
        let aux_scratch = SourceScratch::new_auxiliary_in_arena(source_budget, aux_group)?;
        let projection_dir = output.join("projection");
        std::fs::create_dir(&projection_dir)?;
        let projection = if resume.is_none() {
            Some(context.derive_projection(admission, &projection_dir, &aux_scratch)?)
        } else {
            None
        };
        if let Some(projection) = projection.as_ref() {
            if let Some(report) = projection.windows_ea_normalization_report()? {
                events.observer.note(&report)?;
            }
            if let Some(report) = projection.windows_txf_disposition_report()? {
                events.observer.note(&report)?;
            }
            if let Some(report) = projection.windows_object_id_disposition_report()? {
                events.observer.note(&report)?;
            }
        }
        let expected_group = arena.reserve_group(
            ArtifactGroup::Expected,
            admission.expected_page_budget()?.max_file_bytes,
        )?;
        let expected = if let Some(saved) = resume {
            ensure!(
                saved.expected.sha256 == hex::encode(saved.shadow_origin.expected_pages_sha256),
                "cached expected and recovered shadow origin differ"
            );
            let (expected_path, artifact) = if saved.workspace_origin.is_some()
                && !saved.expected.path.starts_with(&saved.arena_root)
            {
                let source = OpenOptions::new()
                    .read(true)
                    .share_mode(1)
                    .custom_flags(0x00200000)
                    .open(&saved.expected.path)?;
                let before = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &source,
                    saved.expected.bytes,
                )?;
                ensure!(
                    before.file_bytes == saved.expected.bytes,
                    "migrated expected length differs"
                );
                let path = output.join("expected.pages");
                let permit = expected_group.reserve_file(&path, saved.expected.bytes)?;
                let mut target = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(permit.path())?;
                let _ram = arena.reserve_ram(65536)?;
                let mut source = source;
                let mut buffer = [0u8; 65536];
                let mut remaining = saved.expected.bytes;
                while remaining > 0 {
                    let n = remaining.min(buffer.len() as u64) as usize;
                    std::io::Read::read_exact(&mut source, &mut buffer[..n])?;
                    target.write_all(&buffer[..n])?;
                    remaining -= n as u64;
                }
                target.sync_all()?;
                drop(target);
                ensure!(
                    n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                        &source,
                        saved.expected.bytes
                    )? == before,
                    "migrated expected source changed while copied"
                );
                let lease = permit.verify_closed(&saved.expected.sha256)?;
                (path, lease)
            } else {
                (
                    saved.expected.path.clone(),
                    expected_group.adopt_existing(
                        &saved.expected.path,
                        &saved.expected.sha256,
                        saved.expected.bytes,
                    )?,
                )
            };
            let expected = if context.cache_metadata_refreshed() {
                let mut body = PagedExpectedTree::open_cached_body_in_group(
                    &expected_path,
                    &saved.expected.sha256,
                    admission,
                    &expected_group,
                    artifact,
                )?;
                let proof = context.authorize_cached_expected_rebind(&body)?;
                body.rebind_cached_body(
                    proof,
                    &expected_group,
                    &output.join("expected-source-binding.json"),
                )?;
                body
            } else if let Some(binding) = saved.expected_binding.as_ref() {
                // Exact source continuity still needs this invocation's source
                // relation; a saved binding cannot issue a live rebind witness.
                // The current semantic verifier remains required after refresh.
                let mut body = PagedExpectedTree::open_cached_body_in_group(
                    &expected_path,
                    &saved.expected.sha256,
                    admission,
                    &expected_group,
                    artifact,
                )?;
                binding.facts.validate(
                    binding.facts.effective_admission,
                    &saved.expected.sha256,
                    &binding.facts.body_semantic_sha256,
                )?;
                let proof = context.authorize_cached_expected_exact_rebind(&body)?;
                body.rebind_cached_body(
                    proof,
                    &expected_group,
                    &output.join("expected-source-binding.json"),
                )?;
                body
            } else {
                PagedExpectedTree::open_revalidated_with_resources_in_group(
                    &expected_path,
                    &saved.expected.sha256,
                    admission,
                    &expected_group,
                    artifact,
                )?
            };
            events.observer.note(&serde_json::json!({
                "kind":"preparation-resume-expected-reused-v1",
                "file_sha256":expected.file_sha256(),
                "semantic_sha256":expected.semantic_sha256(),
                "objects":expected.len(),"expected_recreated":false,
                "source_write_authority":false,
            }))?;
            expected
        } else {
            let expected_path = output.join("expected.pages");
            let (receipt, artifact) = PagedExpectedTree::create_with_resources_in_group(
                projection
                    .as_ref()
                    .context("fresh source projection absent")?,
                &expected_path,
                admission,
                &expected_group,
            )?;
            PagedExpectedTree::open_with_resources_in_group(
                &expected_path,
                &receipt.file_sha256,
                &receipt.semantic_sha256,
                admission,
                &expected_group,
                artifact,
            )?
        };
        let _expected_seal = expected_group.seal()?;
        expected.require_shared_memory(&arena)?;
        expected.require_resource_owner(admission)?;
        // A refresh changes the source-bound expected header, never the
        // admitted user tree. Carry the new metadata artifact into this epoch
        // while the original partial shadow is adopted rather than recreated.
        let effective_resume = resume
            .map(|saved| -> Result<ResumePreparation> {
                let mut current = saved.clone();
                let artifact = expected
                    .artifact_lease()
                    .context("resumed expected actual owner absent")?;
                current.expected = crate::general_source_admission::resource::SourceCacheFilePin {
                    path: artifact.path().to_path_buf(),
                    sha256: expected.file_sha256().to_owned(),
                    bytes: expected.byte_len(),
                };
                current.expected_binding = expected.binding_pin().cloned();
                current.shadow_origin.expected_pages_sha256 = hex::decode(expected.file_sha256())?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("expected digest width differs"))?;
                Ok(current)
            })
            .transpose()?;
        let alias_inputs = context
            .windows_aliases()
            .map(|owner| {
                crate::boot_alias::WindowsAliasNativeDomain::new(
                    owner,
                    &expected,
                    admission,
                    &projection_dir.join("windows-alias-indices"),
                    &aux_scratch,
                )
            })
            .transpose()?;
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
        let backing_guard = events.observer.backing_resource_guard();
        let diagnose_failures = diagnose().then(general_shadow::DeferredFailures::default);
        let inputs = general_shadow::GuardedInputs::new(
            PagedInputs(&expected), backing_guard.clone(), &request.pair.shadow,
        )?.with_progress(events.observer.progress_reporter())
            .with_deferred_failures(diagnose_failures.clone());
        let trust_recipes = if trust_repair_allocation.is_some() {
            Some(crate::refs_security_integration::collect_recipes(
                &inputs, &arena,
            )?)
        } else {
            None
        };
        let mut resume_checkpoints = if let Some(saved) = effective_resume.as_ref() {
            Some(resume_checkpoint::Checkpoints::create(
                    saved,
                    &context,
                    &expected,
                    &request,
                    &locator_group,
                    output,
                )?)
        } else if request.pair.source.layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            && request.verification_policy == VerificationPolicy::ExtentIdentityV1
            && request.marker_use == MarkerStorageUse::QualifiedProduction
        {
            events.observer.parent_public_resources().map(|parent| {
                resume_checkpoint::Checkpoints::create_fresh(
                    &context, &expected, &request, parent, &locator_group, output,
                )
            }).transpose()?
        } else {
            None
        };

        // Placement and later target capture share one actual quota. Keep
        // every complete placement proof in its constructor-owned page files.
        let recovery_ceiling = locator_group.maximum_bytes()?;
        if resume.is_some() {
            // Only checkpoint facts are written before capture closes. Do not
            // promise the later locator's whole share simultaneously with
            // placement. Retain every actual owner and room for the remaining
            // bounded phase records (each checkpoint has two durable copies).
            let facts = crate::preparation_resume::Limits::from_budget(request.resources)?;
            let headroom = facts
                .max_checkpoint_bytes
                .checked_mul(32)
                .context("resume phase fact allowance overflow")?;
            let held = locator_group.held_bytes()?;
            locator_group.resize_reservation(
                recovery_ceiling.min(
                    held.checked_add(headroom)
                        .context("resume recovery phase reservation overflow")?,
                ),
            )?;
            let usage = arena.usage()?;
            let pending = usage
                .promised_bytes
                .saturating_sub(usage.local_allocation_credit_bytes);
            let available = n2r_win32::resource_native::observe_available_resources(output)?;
            let reserve = request
                .minimum_free_bytes
                .checked_add(events.observer.remaining_scratch_reservation_bytes())
                .context("resume working reserve overflow")?;
            let current = available
                .scratch_available_bytes
                .checked_sub(pending)
                .and_then(|n| n.checked_sub(reserve))
                .context("resume cannot retain working reserve for capture")?
                / 4096
                * 4096;
            let ceiling = request.capture_arena_bytes.min(current);
            ensure!(
                ceiling >= source_budget.scratch_bytes,
                "current capture capacity is below the canonical metadata workspace"
            );
            events.observer.note(&serde_json::json!({"kind":"resume-current-phase-capacity-v1",
                "prior_capture_ceiling":request.capture_arena_bytes,"capture_ceiling":ceiling,
                "recovery_later_ceiling":recovery_ceiling,"recovery_current_ceiling":locator_group.maximum_bytes()?,
                "physical_free_bytes":available.scratch_available_bytes,"other_pending_bytes":pending,
                "working_reserve_bytes":reserve,"checks_unchanged":true}))?;
            request.capture_arena_bytes = ceiling;
        }
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

        let completed_payloads = effective_resume
            .as_ref()
            .and_then(|saved| saved.completed_payloads.as_ref());
        if let Some(proof) = completed_payloads {
            proof.require_arena(&arena)?;
            proof.require_expected(expected.file_sha256())?;
            events.observer.note(&serde_json::json!({
                "kind":"completed-payload-recovery-selected-v1",
                "payload_receipt":proof.pin(),"selection_only":true,
                "fresh_native_payload_verification_required":true,
                "payload_rematerialization_requested":false,
            }))?;
        }

        let pending_metadata = if completed_payloads.is_some() {
            if let (Some(saved),Some(aliases))=(effective_resume.as_ref(),alias_inputs.as_ref()) {
                let (source,_) = context.source_and_inspection()?;
                let native_profile=profile.native_profile().context("native metadata profile absent")?;
                let mut enrollment=n2r_win32::shadow_native::private_tree::enroll_with_resource_profile(
                    source,&request.pair,native_profile)?;
                let memory=Arc::new(ArenaReportMemory(arena.clone()));
                use n2r_win32::shadow_native::private_tree::recovery::metadata_transition::{
                    self,PayloadsShape,
                };
                match metadata_transition::classify_payloads_domain(&mut enrollment,&inputs,memory.as_ref())? {
                    PayloadsShape::PrivatePayloads=>None,
                    PayloadsShape::FinalTargets=>Some(metadata_transition::adopt_domain(
                        enrollment,&inputs,aliases,native_profile,memory,saved.shadow_origin.clone(),
                    ).context("fresh native final-target metadata adoption")?),
                }
            }else{None}
        }else{None};
        let verified_aliases = if let Some(pending) = pending_metadata {
            let aliases=alias_inputs.as_ref().context("metadata recovery aliases absent")?;
            events.phase("metadata-recovery-verification");
            let verified={
                let (source,raw)=context.source_and_inspection()?;
                let memory=ArenaReportMemory(arena.clone());
                source.with_readonly_source_bytes(&memory,&mut events,|scope| {
                    (||->Result<_>{
                        let mut bytes=PagedSourceByteAdapterWithScope::new_scoped(
                            scope,raw,admission,maximum_source_read_bytes)?;
                        general_shadow::paged_supply::routed::preflight_source_references(&bytes,&expected)?;
                        let body=pending.verify_payloads(&inputs,aliases,|index,name,offset,physical,output| {
                            (||->Result<()>{
                                let object=expected.object_leased(index)?;
                                let stream=object.data_streams().find(|stream|stream.name_utf16==name)
                                    .context("metadata recovery source stream absent")?;
                                let id=general_shadow::source_backed::PagedStreamIdentity {
                                    record_number:object.record_number,sequence_number:object.sequence_number,
                                    name_utf16:stream.name_utf16,length:stream.length,sha256:stream.sha256,
                                    allow_sparse:stream.sparse.is_some(),
                                };
                                if let Some(physical)=physical {
                                    bytes.require_reference(&id,offset,physical,output.len() as u64)?;
                                }
                                bytes.read_into(&id,offset,output)?;
                                // The adapter closes the previous session on
                                // identity change and its last session at the
                                // enclosing finish; keep one per stream here.
                                Ok(())
                            })().map_err(std::io::Error::other)
                        });
                        let closing=bytes.finish();
                        match (body,closing) {
                            (Ok(value),Ok(_))=>Ok(value),
                            (Err(error),Ok(_))=>Err(error.into()),
                            (Ok(_),Err(error))=>Err(error),
                            (Err(error),Err(closing))=>Err(closing.context(format!("metadata payload verification also failed: {error}"))),
                        }
                    })().map_err(std::io::Error::other)
                }).context("metadata recovery source-byte closing")?
            };
            let observed=verified.observation();
            events.observer.note(&observed)?;
            if let Some(state)=resume_checkpoints.as_mut(){state.metadata_adopted(&observed)?;}
            let batch=resume_checkpoints.as_mut().map(resume_checkpoint::Checkpoints::begin_metadata).transpose()?;
            let placeholders=trust_recipes.as_ref().is_some_and(|recipes|!recipes.is_empty());
            let (report,aliases)=verified.complete(&inputs,aliases,placeholders,|a,b| {
                crate::ntfs_attestation::same_security_null_sacl_as_absent(a,b).map_err(std::io::Error::other)
            }).context("reconcile existing final-target metadata")?;
            events.observer.note(&serde_json::json!({"kind":"Windows-recovered-metadata-completion",
                "report":report,"original_security_native_verification_pending":true}))?;
            if let (Some(state),Some(batch))=(resume_checkpoints.as_mut(),batch) {
                state.metadata_completed(batch,&serde_json::json!({"kind":"metadata-reconciliation-completed-v1",
                    "expected_sha256":expected.file_sha256(),"objects":expected.len(),"aliases":aliases.len(),
                    "original_security_native_verification_pending":true,"protected_target_capture_required":true}))?;
            }
            Some(Arc::new(aliases))
        } else {
        // Recovery acquires fresh native ownership of the existing tree. It
        // never calls the allocator or recreates the shadow's files.
        let (mut private, placement) = if let Some(saved) = effective_resume.as_ref()
            .filter(|saved| saved.shadow_start == resume_session_inputs::ShadowStart::AdoptExisting) {
            let (source, _) = context.source_and_inspection()?;
            let native_profile = profile
                .native_profile()
                .context("native resource profile absent")?;
            let enrollment = n2r_win32::shadow_native::private_tree::enroll_with_resource_profile(
                source,
                &request.pair,
                native_profile,
            )?;
            let placed_ready = saved.completed_placement.as_ref();
            if let Some(proof) = placed_ready {
                proof.require_arena(&arena)?;
                events.observer.note(
                    &serde_json::json!({"kind":"placed-shadow-recovery-selected-v1",
                    "closed_placement_report":proof.pin(),"selection_only":true,
                    "requires_fresh_native_placed_audit":true,"placement_moves_requested":false}),
                )?;
            }
            let mut recovered = if completed_payloads.is_some() {
                ensure!(placed_ready.is_some(), "completed payloads require held placement evidence");
                n2r_win32::shadow_native::private_tree::recovery::adopt_payloads_domain(
                    enrollment,
                    &inputs,
                    native_profile,
                    Arc::new(ArenaReportMemory(arena.clone())),
                    saved.prior_spend,
                    saved.placement_limits,
                    saved.shadow_origin.clone(),
                )
                .context("fresh native completed-payload shadow adoption")?
            } else if placed_ready.is_some() {
                n2r_win32::shadow_native::private_tree::recovery::adopt_placed_domain(
                    enrollment,
                    &inputs,
                    native_profile,
                    Arc::new(ArenaReportMemory(arena.clone())),
                    saved.prior_spend,
                    saved.placement_limits,
                    saved.shadow_origin.clone(),
                )
                .context("fresh native placed-shadow adoption")?
            } else {
                n2r_win32::shadow_native::private_tree::recovery::adopt_unwritten_domain(
                    enrollment,
                    &inputs,
                    native_profile,
                    Arc::new(ArenaReportMemory(arena.clone())),
                    saved.prior_spend,
                    saved.placement_limits,
                    saved.shadow_origin.clone(),
                )
                .context("fresh native unwritten-shadow adoption")?
            };
            if let Some(guard) = &backing_guard {
                recovered.attach_backing_resource_guard(Arc::clone(guard))?;
            }
            let observation = recovered.origin_observation();
            events.observer.note(&observation)?;
            let batch = resume_checkpoints
                .as_mut()
                .map(|state| state.adopted(&observation))
                .transpose()?;
            events.phase("shadow-placement");
            let placement_result = if placed_ready.is_some() {
                recovered.rehydrate_placed_domain(&inputs, &mut placement_evidence)
            } else {
                recovered.place_remaining_domain(&inputs, &mut placement_evidence)
            };
            let placement = match placement_result {
                Ok(report) => report,
                Err(error) => {
                    let progress = recovered.placement_progress();
                    events.observer.note(&serde_json::json!({
                        "kind":"resource-placement-refusal","resumed":true,
                        "phase":progress.get("phase"),"counters":progress.get("counters"),
                        "move_bytes_submitted":progress.get("move_bytes_submitted"),
                        "refusal":progress.get("refusal"),
                        "source_payload_writes":0,"conversion_authorized":false,
                    }))?;
                    return Err(error.into());
                }
            };
            if let (Some(state), Some(batch)) = (resume_checkpoints.as_mut(), batch) {
                state.placed(batch, &placement)?;
            }
            (recovered.into_placed_tree()?, placement)
        } else {
            ensure!(completed_payloads.is_none(), "empty allocation cannot reuse completed payloads");
            events.phase("shadow-allocation");
            let allocation_batch = resume_checkpoints.as_mut()
                .map(resume_checkpoint::Checkpoints::begin_allocation).transpose()?;
            // Every native allocation uses this actual shared arena accountant.
            let mut private = {
                let (source, _) = context.source_and_inspection()?;
                let native_profile = profile
                    .native_profile()
                    .context("native resource profile absent")?;
                let enrollment =
                    n2r_win32::shadow_native::private_tree::enroll_with_resource_profile(
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
            if let Some(guard) = &backing_guard {
                private.attach_backing_resource_guard(Arc::clone(guard))?;
            }
            let placement_batch = if let (Some(state), Some(batch)) =
                (resume_checkpoints.as_mut(), allocation_batch) {
                Some(state.allocated(batch, &private.allocation_observation()?)?)
            } else { None };
            events.phase("shadow-placement");
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
                        "move_bytes_submitted":progress.get("move_bytes_submitted"),
                        "source_payload_writes":0, "conversion_authorized":false,
                    }))?;
                    return Err(error.into());
                }
            };
            if let (Some(state), Some(batch)) = (resume_checkpoints.as_mut(), placement_batch) {
                state.placed(batch, &placement)?;
            }
            (private, placement)
        };
        events.observer.note(&serde_json::json!({
            "kind":"resource-placement-summary",
            "original_coordinate_bytes":placement.get("original_coordinate_bytes"),
            "move_bytes_submitted":placement.get("move_bytes_submitted"),
            "counters":placement.get("counters"), "source_payload_writes":0,
            "conversion_authorized":false,
        }))?;
        drop(placement);
        if completed_payloads.is_none() {
            private
                .prepare_source_backed_prefixes()
                .context("prepare source-backed shadow prefixes")?;
        }
        {
            let supply_progress=events.observer.progress_reporter();
            let (source, raw) = context.source_and_inspection()?;
            let scope_memory = ArenaReportMemory(arena.clone());
            let supply_receipt = source.with_readonly_source_bytes(
                &scope_memory, &mut events, |scope| {
                    (|| -> Result<serde_json::Value> {
                        let mut bytes = PagedSourceByteAdapterWithScope::new_scoped(
                            scope, raw, admission, maximum_source_read_bytes,
                        )?;
                        let routed = if let Some(proof) = completed_payloads {
                            general_shadow::paged_supply::routed::prepare_recovered(
                                &mut bytes, &expected, &mut private,
                                request.maximum_materialized_bytes, request.verification_policy,
                                proof.routed_plan_sha256(),
                                &supply_progress,
                            ).context("revalidate completed routed payload supply")?
                        } else {
                            let mut routed = general_shadow::paged_supply::routed::prepare(
                                &mut bytes, &expected, &mut private,
                                request.maximum_materialized_bytes, request.verification_policy,
                                &supply_progress,
                            ).context("prepare routed shadow payload materialization")?;
                            let (_system, indexer) = routed.materialize_system_payloads()
                                .context("materialize routed system payloads")?;
                            drop(indexer);
                            routed
                        };
                        let receipt = routed.verify()
                            .context("verify routed shadow payload supply")?;
                        bytes.finish()?;
                        Ok(receipt)
                    })().map_err(std::io::Error::other)
                },
            ).context("routed source-byte scope full closing validation")?;
            events.observer.note(&serde_json::to_value(&supply_receipt)?)?;
            if let Some(state) = resume_checkpoints.as_mut() {
                state.stage(
                    crate::preparation_resume::Stage::Payloads,
                    "payloads-ready",
                    &supply_receipt,
                )?;
            }
        }
        let metadata_batch=resume_checkpoints.as_mut()
            .map(resume_checkpoint::Checkpoints::begin_metadata).transpose()?;
        let verified_aliases = if let Some(aliases) = &alias_inputs {
            let compare = |a: &[u8], b: &[u8]| {
                crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b).map_err(std::io::Error::other)
            };
            let (report, verified) = if trust_recipes
                .as_ref()
                .is_some_and(|recipes| !recipes.is_empty())
            {
                private.complete_source_metadata_windows_aliases_domain_with_security_placeholders(
                    &inputs, aliases, compare,
                )
                .context("shadow metadata completion with Windows aliases and security placeholders")?
            } else {
                private
                    .complete_source_metadata_windows_aliases_domain(&inputs, aliases, compare)
                    .context("shadow metadata completion with Windows aliases")?
            };
            events.observer.note(&serde_json::json!({"kind":"Windows-constructor-metadata-completion",
                "trust_label_descriptors_requiring_raw_repair":trust_recipes.as_ref().map_or(0,|recipes|recipes.len()),
                "report":report,"original_security_native_verification_pending":true}))?;
            Some(std::sync::Arc::new(verified))
        } else {
            private
                .complete_source_metadata_domain(&inputs, |a, b| {
                    crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b).map_err(std::io::Error::other)
                })
                .context("shadow metadata completion")?;
            None
        };
        if let (Some(state),Some(batch))=(resume_checkpoints.as_mut(),metadata_batch) {
            state.metadata_completed(batch,&serde_json::json!({"kind":"metadata-completion-v1",
                "expected_sha256":expected.file_sha256(),"objects":expected.len(),
                "aliases":verified_aliases.as_ref().map_or(0,|aliases|aliases.len()),
                "original_security_native_verification_pending":true,"protected_target_capture_required":true}))?;
        }
        verified_aliases
        };
        events.observer.note(&serde_json::json!({"kind":"expected-metadata-work-counters-v1",
            "phase":"metadata-completed","page_cache":expected.page_cache_statistics(),
            "alias_projection":expected.alias_projection_statistics(),"diagnostic_only":true}))?;
        // Diagnose gate. Nothing has been published or written to the source
        // yet; returning an error here takes the ordinary cancellation path,
        // which restores NTFS access.
        if let Some(sink) = &diagnose_failures {
            let failures = sink.take();
            anyhow::bail!("diagnose complete: {} per-object failures; nothing was published or written to the source", failures.len());
        }
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
        let _trust_repair_owner = if let Some(recipes) =
            trust_recipes.as_ref().filter(|recipes| !recipes.is_empty())
        {
            events.phase("shadow-original-trust-label-repair");
            let (repaired, owner) = crate::refs_security_integration::repair_constructor_shadow(
                &mut context,
                shadow,
                recipes,
                trust_repair_allocation.context("Windows security-repair allocation absent")?,
                &arena,
                &request.journal,
                &output.join("shadow-security-repair"),
                &mut events,
            )?;
            shadow = repaired;
            events
                .observer
                .note(&serde_json::to_value(owner.receipt())?)?;
            Some(owner)
        } else {
            None
        };
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
        let capture_progress=events.observer.progress_reporter();
        let proof = crate::general_composite_target::paged::observe_and_select_paged_optional_windows_aliases(
            &mut context,
            &mut shadow,
            request.pair.clone(),
            &expected,
            &capture_group,
            &output.join("target"),
            &mut events,
            verified_aliases.as_ref().zip(alias_inputs.as_ref()),
            |context, target, expected, routes, scope, closing, native_events| {
                let (source, raw) = context.source_and_inspection()?;
                let memory = ArenaReportMemory(arena.clone());
                source.with_readonly_source_bytes(&memory, native_events, |source_scope| {
                    (|| -> Result<_> {
                        let bytes = PagedSourceByteAdapterWithScope::new_scoped(
                            source_scope, raw, admission, maximum_source_read_bytes,
                        )?;
                        let candidate = PagedSourceBackedCandidateWithScope::new(
                            bytes, target, expected, routes,
                        )?.with_closing_bytes(closing);
                        let mut guard = |p: CaptureProgress| -> Result<()> {
                            let space = n2r_win32::discovery::observe_volume_space(&journal_root)?;
                            ensure!(
                                space.available_bytes_to_caller >= p.required_available_bytes()?,
                                "capture does not have its remaining journal and reserve capacity"
                            );
                            capture_progress.report(n2r_win32::progress::Update::new(
                                n2r_win32::progress::Phase::TargetCapture,
                                n2r_win32::progress::Unit::Bytes,p.literal_backing_bytes,None,
                            ).with_counters(n2r_win32::progress::Counters {
                                payload_bytes_written:Some(p.literal_backing_bytes),
                                ..Default::default()
                            }));
                            Ok(())
                        };
                        capture_target_selected(
                            candidate, scope, &capture_dir.join("literal.bin"),
                            &capture_dir.join("capture.index"), capture_budget, &mut guard,
                        )
                    })().map_err(std::io::Error::other)
                }).context("capture source-byte scope full closing validation")
            },
        )?;
        events.checkpoint()?;
        if let Some(state) = resume_checkpoints.as_mut() {
            state.stage(crate::preparation_resume::Stage::Metadata, "protected-native-metadata-verified",
                &serde_json::json!({"kind":"protected-native-target-capture-returned-v1",
                    "expected_sha256":expected.file_sha256(),"source_inspection_sha256":context.inspection_sha256(),
                    "shadow":request.pair.shadow,"source_write_authority":false}))?;
            state.stage(
                crate::preparation_resume::Stage::Captured,
                "capture-ready",
                &proof.captured().summary(),
            )?;
        }
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
            let (source, _) = context.source_and_inspection()?;
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
        if resume.is_some() {
            // Later locator/publication work regains its original ceiling only
            // after unused capture promises are released, against actual free
            // space again. No saved quota or serialized flag supplies credit.
            locator_group.resize_reservation(recovery_ceiling)?;
        }
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
            ResourcePreparedConversion::publish_with_windows_aliases(
                prepared,
                &expected,
                recovery_maps,
                locator,
                &locator_group,
                &locator_scratch,
                &output.join("recovery-envelope.json"),
                native_events,
                |batch| observer.native_events("prepared-conversion-publication", batch),
                verified_aliases.clone(),
            )?
        };
        let publication_digest: [u8; 32] = hex::decode(prepared_conversion.publication_sha256())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("published recovery checksum length differs"))?;
        published = Some((
            prepared_conversion.publication_path().to_path_buf(),
            publication_digest,
        ));
        // Publication seals this arena. Its already-durable native guard
        // delegation and the independent observer log route subsequent
        // recovery; never allocate another checkpoint in the sealed arena.
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
                if events.observer.prefer_durable_preparation_cancellation() {
                    // Drop every source/shadow owner before the outer resume
                    // driver reopens the actual durable guard. A later AP or
                    // delegated publication still uses journal recovery above.
                    drop(context);
                    return Err(original.context("prepublication source remains protected for authenticated guard cancellation"));
                }
                match abort::restore_live_source(context, &mut events) {
                    Ok(mounted) => Err(original.context(format!("conversion failed before publication; unchanged original NTFS restored on disk {}", mounted.disk_number))),
                    Err(cleanup) => Err(original.context(format!("conversion failed before publication; original NTFS cleanup did not complete and source may remain excluded or already be online: {cleanup:#}"))),
                }
            }
        }
    }
}
