//! Owning-guest V4 orchestration for the explicitly enrolled, Job-bounded
//! disposable fixture. Preparation remains the default; the explicit apply
//! operation requires the real live issuer, durable journal and native finish.
//! This does not qualify the general V4 resource contract.
mod first_write_signal;
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent,
    general_layout::GeneralSourceShadowBinding,
    journal_file::{GeneralJournalStorageBinding, JournalProfile, MarkerStorageUse},
    tree_resources::ResourceBudget,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    ops::{Deref, DerefMut},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
    sync::Arc,
};

/// Hold the complete ordinary directory ancestry and prove the output parent
/// is on the exact external journal volume before creating any directory.
fn create_external_output(
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

#[derive(Serialize)]
struct EventBatch<'a> {
    kind: &'static str,
    phase: &'static str,
    events: &'a [NativeEvent],
}

fn stream_native_events(phase: &'static str, events: &mut Vec<NativeEvent>) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(
        &mut out,
        &EventBatch {
            kind: "resource-diagnostic-native-events",
            phase,
            events: events.as_slice(),
        },
    )?;
    out.write_all(b"\n")?;
    out.flush()?;
    // Only clear after the full batch has been handed to the output stream.
    // A flush here is not a durable recovery record or write authority.
    events.clear();
    Ok(())
}

/// Each native phase has a bounded event Vec. Write the actual events to the
/// worker's captured stream before clearing it, including on early failure.
struct EventLog {
    phase: &'static str,
    events: Vec<NativeEvent>,
}
impl EventLog {
    fn new() -> Self {
        Self {
            phase: "initial",
            events: Vec::new(),
        }
    }
    fn phase(&mut self, phase: &'static str) {
        self.phase = phase;
    }
    fn checkpoint(&mut self) -> Result<()> {
        stream_native_events(self.phase, &mut self.events)
    }
}
impl Deref for EventLog {
    type Target = Vec<NativeEvent>;
    fn deref(&self) -> &Self::Target {
        &self.events
    }
}
impl DerefMut for EventLog {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.events
    }
}
impl Drop for EventLog {
    fn drop(&mut self) {
        if !self.events.is_empty() {
            let mut out = std::io::stderr().lock();
            let _ = serde_json::to_writer(
                &mut out,
                &EventBatch {
                    kind: "resource-diagnostic-incomplete-phase-events",
                    phase: self.phase,
                    events: &self.events,
                },
            );
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }
}

use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
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

/// Explicit hardware and disposable-shadow budgets for one diagnostic run.
/// These values are not source admission or conversion authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDiagnosticRequest {
    pub pair: GeneralSourceShadowBinding,
    pub journal: GeneralJournalStorageBinding,
    pub resources: ResourceBudget,
    pub verification_policy: VerificationPolicy,
    pub selected_capacity_policy: SelectedCapacityPolicy,
    pub maximum_placement_bytes: u64,
    pub maximum_placement_submissions: usize,
    pub maximum_materialized_bytes: u64,
    pub maximum_source_read_bytes: u64,
    pub capture_arena_bytes: u64,
    pub locator_arena_bytes: u64,
    pub max_journal_bytes: u64,
    pub max_literal_backing_bytes: u64,
    pub max_combined_backing_and_journal_bytes: u64,
    pub minimum_free_bytes: u64,
    pub use_enrolled_lab_native_markers: bool,
    /// Guest-process/job commit cap for this one disposable fixture only.
    pub lab_process_memory_limit_bytes: u64,
    /// Host launcher independently verifies this actual checkpoint before
    /// boot; the string alone never authorizes disk writes.
    pub host_verified_ready_checkpoint: String,
}

impl ResourceDiagnosticRequest {
    fn validate(&self) -> Result<()> {
        self.resources.validate()?;
        // This exact 52 GiB lab fixture fits the ordinary structural bound.
        // The real V4 admission does not exist until the source is scanned;
        // validate that actual descriptor separately after preparation.
        self.pair.validate()?;
        self.journal.validate()?;
        let profile = JournalProfile::from_schema_and_capacity(3, Some(self.max_journal_bytes))?;
        ensure!(
            self.max_journal_bytes == profile.max_journal_bytes()
                && self.maximum_placement_bytes > 0
                && self.maximum_placement_submissions > 0
                && self.maximum_source_read_bytes > 0
                && self.capture_arena_bytes > 0
                && self.locator_arena_bytes > 0
                && self.max_literal_backing_bytes > 0
                && self.max_combined_backing_and_journal_bytes >= self.max_journal_bytes
                && self.minimum_free_bytes > 0,
            "resource diagnostic capacity differs"
        );
        for disk in [&self.pair.source, &self.pair.shadow] {
            ensure!(
                disk.disk_number != self.journal.disk.disk_number
                    && n2r_win32::layout::guid_bytes(&disk.identity.disk_guid)?
                        != n2r_win32::layout::guid_bytes(&self.journal.disk.identity.disk_guid)?,
                "diagnostic journal must be on a separate disk"
            );
        }
        Ok(())
    }
}

const FIXTURE_CHECKPOINT: &str = "3343f2a4-cf81-4fa9-a504-030425a8011e";
// Independently pinned from the archived successful d79 source observation.
// These are path-independent allocation/ownership facts, not a full-payload
// fingerprint or a substitute for the current live source evidence.
const FIXTURE_OWNERSHIP_SHA256: &str =
    "f4a3befab5ea46c4aa82b01956a08487a71840e6fd0dec8c3e7507c957b11716";
const FIXTURE_BITMAP_SHA256: &str =
    "a306fbb23fa7a9150e52b0d64dfa8ebdd7562b7a948bbb8e86431e9d487836f6";

/// These hard bounds identify ONE enrolled laboratory fixture, not supported
/// filesystem geometry or a production conversion limit.
fn require_enrolled_fixture(request: &ResourceDiagnosticRequest) -> Result<()> {
    let source = &request.pair.source;
    let journal = &request.journal.disk;
    ensure!(
        request
            .host_verified_ready_checkpoint
            .eq_ignore_ascii_case(FIXTURE_CHECKPOINT)
            && source.disk_number == 1
            && source
                .volume_guid
                .eq_ignore_ascii_case("f06075a8-67a2-46b9-8fac-4af4da809617")
            && source
                .identity
                .disk_guid
                .eq_ignore_ascii_case("1b191872-c372-41ee-a416-e18863996f54")
            && source
                .identity
                .partition_guid
                .eq_ignore_ascii_case("f06075a8-67a2-46b9-8fac-4af4da809617")
            && source.identity.partition_number == 2
            && source.identity.disk_bytes == 68_719_476_736
            && source.identity.partition_offset == 16_777_216
            && source.identity.partition_bytes == 55_834_574_848
            && source.identity.logical_sector_bytes == 512
            && source.identity.physical_sector_bytes == 4096,
        "request does not name the exact enrolled lab source"
    );
    ensure!(
        journal.disk_number == 7
            && journal
                .volume_guid
                .eq_ignore_ascii_case("6b2c8755-e6a4-40a9-b804-ccd32d9c0d6f")
            && journal
                .identity
                .disk_guid
                .eq_ignore_ascii_case("b1209612-0971-4230-afc8-142134dc3d19")
            && journal
                .identity
                .partition_guid
                .eq_ignore_ascii_case("6b2c8755-e6a4-40a9-b804-ccd32d9c0d6f")
            && journal.identity.partition_number == 2
            && journal.identity.disk_bytes == 34_359_738_368
            && journal.identity.partition_offset == 16_777_216
            && journal.identity.partition_bytes == 33_285_996_544
            && journal.identity.logical_sector_bytes == 512
            && journal.identity.physical_sector_bytes == 4096
            && request.journal.externally_enrolled_disk_unique_id
                == "gpt-b1209612-0971-4230-afc8-142134dc3d19"
            && !request.journal.allow_additional_partitions,
        "request does not name the exact enrolled external lab journal"
    );
    ensure!(
        matches!(request.resources.ram_bytes, 1_456_427_008 | 1_489_981_440)
            && request.resources
                == (ResourceBudget {
                    schema_version: 1,
                    ram_bytes: request.resources.ram_bytes,
                    scratch_bytes: 25_769_803_776,
                    page_bytes: 4_194_304,
                    max_row_bytes: 22_756_672,
                    retained_index_bytes: 364_106_752,
                    handle_slots: 1_422_292
                })
            && request.verification_policy == VerificationPolicy::ExtentIdentityV1,
        "fixture source-evidence budget or verification profile differs"
    );
    let shadow = &request.pair.shadow;
    ensure!(
        shadow.disk_number == 6
            && shadow
                .volume_guid
                .eq_ignore_ascii_case("ad0e87c4-487a-49bd-94bd-519d054dcc5b")
            && shadow
                .identity
                .disk_guid
                .eq_ignore_ascii_case("f88939b6-dbc6-4089-b947-7914d2f92180")
            && shadow
                .identity
                .partition_guid
                .eq_ignore_ascii_case("ad0e87c4-487a-49bd-94bd-519d054dcc5b")
            && shadow.identity.partition_number == 2
            && shadow.identity.disk_bytes == 55_901_683_712
            && shadow.identity.partition_offset == 33_554_432
            && shadow.identity.partition_bytes == 55_834_574_848
            && shadow.identity.logical_sector_bytes == 512
            && shadow.identity.physical_sector_bytes == 4096,
        "request does not name the freshly enrolled disposable lab shadow"
    );
    Ok(())
}

/// The fixture route is separate from all production V4/activation gates.
/// It requires the real job cap and exact enrolled lab identities.
pub fn run_guest_diagnostic(
    request: ResourceDiagnosticRequest,
    output: &Path,
    acknowledge_disposable_shadow: bool,
) -> Result<()> {
    run_guest_diagnostic_with_operation(
        request,
        output,
        acknowledge_disposable_shadow,
        ResourceDiagnosticOperation::PrepareOnly,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceDiagnosticOperation {
    PrepareOnly,
    ApplyAndVerify,
    InterruptAfterFirstFlushedWrite,
}

/// The operation is an explicit invocation choice, not source admission or a
/// serialized request flag. Every fixture, Job and runtime proof remains.
pub fn run_guest_diagnostic_with_operation(
    request: ResourceDiagnosticRequest,
    output: &Path,
    acknowledge_disposable_shadow: bool,
    operation: ResourceDiagnosticOperation,
) -> Result<()> {
    ensure!(
        acknowledge_disposable_shadow,
        "explicit disposable shadow acknowledgment required"
    );
    request.validate()?;
    ensure!(
        operation == ResourceDiagnosticOperation::PrepareOnly
            || !request.use_enrolled_lab_native_markers,
        "actual fixture apply currently requires the markerless native journal"
    );
    ensure!(
        output.is_absolute()
            && !output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            && !output.exists(),
        "fresh absolute diagnostic output required"
    );
    require_enrolled_fixture(&request)?;
    let parent = output.parent().context("diagnostic output parent absent")?;
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    available.validate_budget(request.resources)?;
    let guard = n2r_win32::lab_job::FixtureJobGuard::assign_current(
        request.lab_process_memory_limit_bytes,
        request.resources.ram_bytes,
        available,
    )?;
    run_with_fixture_job(request, output, guard, operation)
}

struct FixturePreparationObserver {
    job: n2r_win32::lab_job::FixtureJobGuard,
    parent: std::path::PathBuf,
}
impl crate::resource_preparation::PreparationObserver for FixturePreparationObserver {
    fn native_events(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> Result<()> {
        stream_native_events(phase, events)
    }
    fn source_prepared(&mut self, context: &ResourceSourceContext) -> Result<()> {
        let admission = context.resource_admission();
        ensure!(
            context
                .inspection()
                .allocation()
                .physical_ownership
                .data
                .logical_sha256
                == FIXTURE_OWNERSHIP_SHA256
                && context.inspection().allocation().physical_ownership.records == 921
                && context.inspection().allocation().physical_intervals == 921
                && context.inspection().allocation().bitmap_sha256 == FIXTURE_BITMAP_SHA256
                && admission.mft_records == 2816
                && admission.raw_identities == 2585
                && admission.files == 811
                && admission.directories == 1747
                && admission.data_streams == 811,
            "actual frozen lab allocation/ownership pins or object/stream counts differ; no shadow writes were attempted"
        );
        Ok(())
    }
    fn expected_prepared(
        &mut self,
        _context: &ResourceSourceContext,
        expected: &PagedExpectedTree,
    ) -> Result<()> {
        ensure!(
            expected.len() == 2558,
            "actual expected lab object count differs"
        );
        Ok(())
    }
    fn before_shadow(
        &mut self,
        observation: crate::resource_preparation::PreShadow<'_>,
    ) -> Result<()> {
        let available = n2r_win32::resource_native::observe_available_resources(&self.parent)?;
        ensure!(
            available.available_physical_bytes >= 512 * 1024 * 1024,
            "fixture guest has insufficient physical RAM headroom; no shadow writes were attempted"
        );
        let admission = observation.context.resource_admission();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "kind":"fixture-source-pre-shadow","current_run_source_sha256":observation.context.source_sha256(),
                "fixture_ownership_sha256":FIXTURE_OWNERSHIP_SHA256,"fixture_bitmap_sha256":FIXTURE_BITMAP_SHA256,
                "fixture_pin_scope":"allocation-and-ownership-not-full-payload",
                "raw_identities":admission.raw_identities,"files":admission.files,"directories":admission.directories,"streams":admission.data_streams,
                "arena_ram_before_projection_drop":observation.projection_memory_before.leased_ram_bytes,
                "arena_ram_after_projection_drop":observation.projection_memory_after.leased_ram_bytes,
                "projection_scratch_wire_bytes":observation.projection_wire_bytes,
                "arena_registry_ram":observation.projection_memory_after.registry_ram_bytes,
                "job":self.job.verify()?,"general_resource_qualified":false,"source_writes_authorized":false,
            }))?
        );
        Ok(())
    }
}
fn run_with_fixture_job(
    request: ResourceDiagnosticRequest,
    output: &Path,
    mut job: n2r_win32::lab_job::FixtureJobGuard,
    operation: ResourceDiagnosticOperation,
) -> Result<()> {
    request.validate()?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "kind":"fixture-job-limit","actual":job.verify()?,
            "general_resource_qualified":false,"conversion_authorized":false,
            "apply_and_verify_requested":operation != ResourceDiagnosticOperation::PrepareOnly,
            "first_flushed_write_interruption_requested":operation == ResourceDiagnosticOperation::InterruptAfterFirstFlushedWrite,
        }))?
    );
    let parent = output
        .parent()
        .context("diagnostic output parent absent")?
        .to_path_buf();
    let final_pair = request.pair.clone();
    let final_journal = request.journal.clone();
    let final_resources = request.resources;
    let mut signal = if operation == ResourceDiagnosticOperation::InterruptAfterFirstFlushedWrite {
        ensure!(request.lab_process_memory_limit_bytes >= request.resources.ram_bytes
            .checked_add(first_write_signal::RAM_RESERVE).context("signal RAM reserve overflow")?,
            "fixture Job has no prepaid diagnostic signal RAM headroom");
        Some(first_write_signal::FirstWriteSignal::create(output, &request.journal, request.minimum_free_bytes)?)
    } else { None };
    let generic = crate::resource_preparation::ResourcePreparationRequest {
        pair: request.pair,
        journal: request.journal,
        resources: request.resources,
        verification_policy: request.verification_policy,
        selected_capacity_policy: request.selected_capacity_policy,
        maximum_placement_bytes: request.maximum_placement_bytes,
        maximum_placement_submissions: request.maximum_placement_submissions,
        maximum_materialized_bytes: request.maximum_materialized_bytes,
        maximum_source_read_bytes: Some(request.maximum_source_read_bytes),
        capture_arena_bytes: request.capture_arena_bytes,
        locator_arena_bytes: request.locator_arena_bytes,
        max_journal_bytes: request.max_journal_bytes,
        max_literal_backing_bytes: request.max_literal_backing_bytes,
        max_combined_backing_and_journal_bytes: request.max_combined_backing_and_journal_bytes,
        minimum_free_bytes: request.minimum_free_bytes,
        marker_profile: request
            .use_enrolled_lab_native_markers
            .then_some(SelectedMarkerProfile::RedundantSourceFreeV1),
        marker_use: if request.use_enrolled_lab_native_markers {
            MarkerStorageUse::EnrolledUnqualifiedLab
        } else {
            MarkerStorageUse::QualifiedProduction
        },
    };
    let mut observer = FixturePreparationObserver { job, parent };
    let publication = crate::resource_preparation::prepare_with(
        generic,
        output,
        &mut observer,
        |prepared, events, observer| {
            if operation != ResourceDiagnosticOperation::PrepareOnly {
                observer.job.verify()?;
                let publication_path = prepared.publication_path().to_path_buf();
                let publication_sha = prepared.publication_sha256().to_owned();
                let fresh = prepared.into_fresh_apply(events, |batch| {
                    stream_native_events("fixture-fresh-admission", batch)
                })?;
                let mut callback = |observed: &crate::selected_journal::resource_domain::prepare::FirstFlushedWrite| {
                    signal.as_mut().context("preallocated actual signal owner absent")?
                        .commit(observed, &publication_path, &publication_sha)
                };
                let fault = if operation == ResourceDiagnosticOperation::InterruptAfterFirstFlushedWrite {
                    Some(&mut callback as &mut dyn FnMut(&crate::selected_journal::resource_domain::prepare::FirstFlushedWrite) -> Result<()>)
                } else { None };
                let mut applied = fresh.apply_and_handoff_with_first_write_fault(
                    events,
                    |batch| stream_native_events("fixture-selected-apply", batch),
                    |selected| {
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::json!({
                                "kind":"resource-fixture-selected-applied","actual":selected,
                                "mounted":false,"conversion_qualified":false,
                            }))?
                        );
                        std::io::stdout().flush()?;
                        Ok(())
                    },
                    fault,
                )?;
                applied.seal_handoff_readonly(events, |batch| {
                    stream_native_events("fixture-handoff-readonly", batch)
                })?;
                ensure!(
                    applied.source() == &final_pair.source,
                    "actual fixture handoff source differs from enrolled request"
                );
                let path = applied.publication_path().to_path_buf();
                let sha256: [u8; 32] = hex::decode(applied.publication_sha256())?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("complete publication SHA-256 required"))?;
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "kind":"resource-fixture-handoff-excluded","applied":applied.applied(),
                        "handoff":applied.handoff(),"native_bytes_written":applied.native_bytes_written(),
                        "source_disk_attributes":3,"mounted":false,"fixture_job":observer.job.verify()?,
                        "recovery_envelope_path":path,"recovery_envelope_sha256":hex::encode(sha256),
                        "conversion_qualified":false,
                    }))?
                );
                std::io::stdout().flush()?;
                // The callback's actual owners (including the share-zero
                // journal) drop before the independent reopening finalizer.
                drop(applied);
                return Ok(Some((path, sha256)));
            }
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "kind":"resource-guest-diagnostic","locator_sha256":hex::encode(prepared.locator_sha256()),
                    "recovery_envelope_path":prepared.publication_path(),"recovery_envelope_sha256":prepared.publication_sha256(),
                    "held_prepared_conversion_qualified":true,"fixture_job":observer.job.verify()?,
                    "source_payload_writes":0,"source_admitted":false,"execution_authorized":false,
                    "conversion_qualified":false,"locator_grants_authority":false,
                }))?
            );
            drop(prepared);
            Ok(None)
        },
    )?;
    if let Some((path, sha256)) = publication {
        observer.job.verify()?;
        let finalization = crate::resource_finalize::finalize_resource_handoff_with_observer(
            final_pair,
            final_journal,
            &path,
            sha256,
            final_resources,
            &output.join("finalization"),
            &mut observer,
        )?;
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "kind":"resource-fixture-apply-and-verify-complete","actual":finalization,
                "fixture_job":observer.job.verify()?,"general_release_qualified":false,
            }))?
        );
        std::io::stdout().flush()?;
    }
    Ok(())
}

/// Reopen only the independently enrolled disposable fixture after a guest
/// restart. This inspects the real publication, journal and excluded source;
/// it never activates a target or issues recovery/write authority.
pub fn run_guest_recovery_observation(
    request: ResourceDiagnosticRequest,
    publication: &Path,
    publication_sha256: [u8; 32],
    output: &Path,
    recovery_resources: ResourceBudget,
    acknowledge_disposable_fixture: bool,
) -> Result<serde_json::Value> {
    use crate::selected_journal::resource_domain::reopen::envelope::ReopenedResourceRecovery;

    ensure!(
        acknowledge_disposable_fixture,
        "explicit disposable fixture acknowledgment required"
    );
    request.validate()?;
    require_enrolled_fixture(&request)?;
    recovery_resources.validate()?;
    ensure!(
        output.is_absolute()
            && !output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            && !output.exists(),
        "fresh absolute recovery observation output required"
    );
    let parent = output
        .parent()
        .context("recovery observation output parent absent")?;
    n2r_win32::resource_native::observe_available_resources(parent)?
        .validate_budget(recovery_resources)?;
    let _output_ancestry = create_external_output(output, &request.journal)?;
    let arena = ArtifactArena::new(
        output,
        recovery_resources,
        &[request.pair.source.clone(), request.pair.shadow.clone()],
    )?;
    ensure!(
        arena
            .volume_guid_path()?
            .eq_ignore_ascii_case(&request.journal.disk.volume_path()?),
        "recovery observation arena differs from external journal volume"
    );
    let source_budget = SourceMetadataBudget::from_resource_budget(recovery_resources)?;
    let group = arena.reserve_group(ArtifactGroup::RecoveryCopy, source_budget.scratch_bytes)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(source_budget, group.clone())?;
    let mut events = EventLog::new();
    events.phase("reopen-resource-recovery");
    let recovered = ReopenedResourceRecovery::open_observed(
        publication,
        publication_sha256,
        source_budget.record_bytes,
        &request.pair,
        &request.journal,
        &group,
        &scratch,
        &output.join("journal-recovery.index"),
        source_budget.scratch_bytes,
        &mut events,
    )?;
    events.checkpoint()?;
    Ok(serde_json::json!({
        "kind":"resource-recovery-reopen-observation-v1",
        "publication_path":recovered.publication_path(),
        "publication_sha256":hex::encode(publication_sha256),
        "source":recovered.source(),
        "source_disk_attributes":recovered.source_disk_attributes(),
        "source_route_exclusive":recovered.source_route_exclusive(),
        "initial_journal_lifecycle":recovered.observed_lifecycle(),
        "journal_immutable_body_scanned":true,
        "source_write_authorized":false,
        "replay_authorized":false,
        "conversion_qualified":false
    }))
}
