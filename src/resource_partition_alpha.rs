//! Explicit experimental owning-machine runner. Inputs route/budget work;
//! only actual native owners can authorize conversion of the selected source.
#[path = "resource_partition_prepare_only.rs"]
mod prepare_only;
use crate::{
    artifact_arena::ArtifactArena,
    general_shadow::source_backed::CaptureBudget,
    resource_preparation::{
        partition_preparation::{
            PartitionExecutionRequest, PartitionPreparationRequest, finalize_partition_handoff,
            prepare_partition_resources, prepare_partition_resources_readonly_physical,
        },
        partition_target::PartitionTargetRequest,
    },
    selected_capacity::SelectedCapacityPolicy,
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent, PartitionTerminalKind,
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    journal_file::GeneralJournalStorageBinding,
    managed_shadow::{self, StagingAllocationMeter, TargetFormatProfile},
    partition_isolation::{
        PartitionObservationBudget, PartitionScopedReader, PartitionSourceBinding,
    },
    partition_lifecycle::{
        PartitionIntentReceipt, PartitionPreparationGuard, PartitionPreparationObserver,
    },
    partition_restoration::PartitionRestorationObserver,
    tree_resources::ResourceBudget,
};
use prepare_only::RunPurpose;
pub use prepare_only::{WindowsPreparedOfflineApplyReceipt, prepare_for_offline_apply};
#[path = "resource_prepared_boot.rs"]
mod prepared_boot;
pub use prepared_boot::{
    PreparedBootRequest, arm_existing_prepared_boot, arm_prepared_boot,
    prepare_and_arm_shared_conversion,
};
#[path = "resource_prepared_runner.rs"]
mod prepared_runner;
pub use prepared_runner::{PreparedOfflineAction, PreparedOfflineRequest, run_prepared_offline};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Fixed reservation for the experimental owning-machine worker. This is a
/// stack address-space bound, not a claim about peak resident memory.
pub const WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;
const EXECUTION_STACK_RESERVE_BYTES: u64 = WORKER_STACK_BYTES as u64 + 1024 * 1024;
#[path = "resource_partition_pause.rs"]
mod controlled_pause;
#[path = "resource_native_event_log.rs"]
mod native_event_log;
// Public dispatch reserves this SAME existing independent evidence allowance;
// the Alpha still owns the actual control-file/RAM accounting and validation.
pub(crate) const CONTROLLED_POST_FLUSH_EVIDENCE_RESERVE_BYTES: u64 =
    controlled_pause::EVIDENCE_RESERVE_BYTES;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionAlphaRequest {
    pub schema_version: u32,
    pub source_root: String,
    pub expected_source: GeneralDiskBinding,
    pub observation_budget: PartitionObservationBudget,
    pub total_ram_bytes: u64,
    pub arena_scratch_bytes: u64,
    pub maximum_staging_allocation_bytes: u64,
    pub maximum_evidence_bytes: u64,
    pub minimum_free_bytes: u64,
    pub verification_policy: VerificationPolicy,
    #[serde(default)]
    pub target_format: TargetFormatProfile,
    // Preserve historical lab requests; public callers choose explicitly.
    #[serde(default = "legacy_partition_capacity_policy")]
    pub selected_capacity_policy: SelectedCapacityPolicy,
}
fn legacy_partition_capacity_policy() -> SelectedCapacityPolicy {
    SelectedCapacityPolicy::SourceFreeActualBytesV1
}
struct Ledger {
    file: File,
    bytes: u64,
    event_encoder: native_event_log::NativeEventEncoder,
    maximum: u64,
    poisoned: bool,
    meter: Option<StagingAllocationMeter>,
    stage_maximum: u64,
    minimum_free: u64,
    run: PathBuf,
}
#[derive(Serialize)]
struct Batch<'a> {
    kind: &'static str,
    native_buffer_encoding: &'static str,
    phase: &'static str,
    observed_unix_ms: Option<u64>,
    events: &'a [native_event_log::EncodedNativeEvent<'a>],
}
struct Count(u64);
impl Write for Count {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(b.len() as u64)
            .ok_or_else(|| io::Error::other("evidence counter overflow"))?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Ledger {
    fn record(&mut self, value: &impl Serialize) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other("partition alpha ledger poisoned"));
        }
        let mut n = Count(0);
        serde_json::to_writer(&mut n, value).map_err(io::Error::other)?;
        let end = self
            .bytes
            .checked_add(n.0)
            .and_then(|n| n.checked_add(1))
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("partition alpha evidence budget exhausted"))?;
        self.poisoned = true;
        {
            let mut writer = io::BufWriter::with_capacity(65536, &mut self.file);
            serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        self.file.sync_all()?;
        if self.file.metadata()?.len() != end {
            return Err(io::Error::other("ledger EOF differs"));
        }
        self.bytes = end;
        self.poisoned = false;
        Ok(())
    }
    fn checkpoint(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        // References may point only into this successfully persisted stream.
        // A budget/write/flush/readback failure must not publish cache state.
        let mut next_encoder = self.event_encoder.clone();
        let encoded = next_encoder.encode(events)?;
        self.record(&Batch {
            kind: "actual-native-event-batch-v2",
            native_buffer_encoding: native_event_log::ENCODING,
            phase,
            observed_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
            events: &encoded,
        })?;
        self.event_encoder = next_encoder;
        events.clear();
        if let Some(meter) = &self.meter {
            let observed = meter.observe()?;
            if observed.backing_file.allocation_bytes > self.stage_maximum {
                return Err(io::Error::other(
                    "observed owned staging backing exceeds admitted allocation budget",
                ));
            }
            self.record(&serde_json::json!({"kind":"owned-staging-allocation-sample","phase":phase,"observed":observed,
                "maximum_admitted_bytes":self.stage_maximum,"is_kernel_quota":false,"is_peak":false}))?;
        }
        if n2r_win32::resource_native::observe_available_resources(&self.run)?
            .scratch_available_bytes
            < self.minimum_free
        {
            return Err(io::Error::other(
                "partition alpha reached the admitted free-space reserve",
            ));
        }
        println!("{phase}");
        io::stdout().flush()
    }
}
#[derive(Clone)]
struct Observer(Arc<Mutex<Ledger>>);
impl Observer {
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Ledger>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("ledger lock poisoned"))
    }
    fn checkpoint(&self, phase: &'static str, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.lock()?.checkpoint(phase, events)
    }
}
impl PartitionPreparationObserver for Observer {
    fn checkpoint(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        Observer::checkpoint(self, phase, events)
    }
    fn durable_intent(&mut self, receipt: &PartitionIntentReceipt) -> io::Result<()> {
        self.lock()?.record(
            &serde_json::json!({"kind":"actual-durable-before-setter-intent","receipt":receipt}),
        )
    }
}
impl PartitionRestorationObserver for Observer {
    fn checkpoint_native_events(
        &mut self,
        phase: &'static str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        Observer::checkpoint(self, phase, events)
    }
    fn before_partition_change(
        &mut self,
        kind: PartitionTerminalKind,
        current: &[u8],
        desired: &[u8],
    ) -> io::Result<()> {
        let terminal = match kind {
            PartitionTerminalKind::Handoff => "handoff",
            PartitionTerminalKind::Aborted => "aborted",
        };
        self.lock()?.record(
            &serde_json::json!({"kind":"actual-before-terminal-partition-change","terminal":terminal,
            "current_partition_info":current,"desired_partition_info":desired}),
        )
    }
}
fn ordinary_directory(path: &Path) -> Result<Vec<File>> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "ordinary absolute directory required"
    );
    let mut held = Vec::new();
    for parent in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "ordinary directory ancestry required"
        );
        let f = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(parent)?;
        ensure!(
            f.metadata()?.is_dir() && f.metadata()?.file_attributes() & 0x400 == 0,
            "held directory ancestry changed"
        );
        held.push(f);
    }
    Ok(held)
}
fn save(path: &Path, value: &impl Serialize, maximum: u64) -> Result<()> {
    let mut counted = Count(0);
    serde_json::to_writer_pretty(&mut counted, value)?;
    ensure!(
        counted.0.checked_add(1).is_some_and(|n| n <= maximum),
        "bounded alpha result exceeds its separate evidence reservation"
    );
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}
fn align(n: u64) -> u64 {
    n / 4096 * 4096
}
fn derive_budget(ram: u64, scratch: u64) -> Result<ResourceBudget> {
    let result = ResourceBudget {
        schema_version: 1,
        ram_bytes: ram,
        scratch_bytes: scratch,
        page_bytes: (ram / 512).clamp(256, n2r_win32::tree_resources::METADATA_PAGE_BYTES as u64)
            as u32,
        max_row_bytes: (ram / 64).min(scratch / 16),
        retained_index_bytes: ram / 4,
        handle_slots: ram / 1024,
    };
    result.validate()?;
    Ok(result)
}
/// Execute only inside the machine owning the actual source. Request fields
/// are routing/resources; acknowledgements never replace native admission.
pub fn run(
    request: PartitionAlphaRequest,
    output: &Path,
    acknowledge_source_conversion: bool,
) -> Result<()> {
    run_inner(
        request,
        output,
        acknowledge_source_conversion,
        None,
        false,
        RunPurpose::Convert,
    )
}
/// Exercise the real mounted-BasicRO cancellation path without creating a
/// shadow, source admission or payload writer. The guard closes before return.
#[doc(hidden)]
pub fn run_cancel_before_private(
    request: PartitionAlphaRequest,
    output: &Path,
    acknowledge_source_conversion: bool,
) -> Result<()> {
    run_inner(
        request,
        output,
        acknowledge_source_conversion,
        None,
        true,
        RunPurpose::Convert,
    )
}
/// Explicit hidden-lab fault control. The nonce/command never authorizes I/O.
#[doc(hidden)]
pub fn run_with_controlled_post_flush_pause(
    request: PartitionAlphaRequest,
    output: &Path,
    acknowledge_source_conversion: bool,
    nonce: String,
    acknowledge_controlled_pause: bool,
) -> Result<()> {
    ensure!(
        acknowledge_controlled_pause,
        "separate controlled post-flush pause acknowledgement required"
    );
    controlled_pause::require_nonce(&nonce)?;
    run_inner(
        request,
        output,
        acknowledge_source_conversion,
        Some(nonce),
        false,
        RunPurpose::Convert,
    )
}
fn run_inner(
    request: PartitionAlphaRequest,
    output: &Path,
    acknowledge_source_conversion: bool,
    pause_nonce: Option<String>,
    cancel_readonly: bool,
    mut purpose: RunPurpose<'_>,
) -> Result<()> {
    let prepare_only = matches!(&purpose, RunPurpose::Prepare(_));
    ensure!(
        !prepare_only || (pause_nonce.is_none() && !cancel_readonly),
        "prepare-only cannot enable pause/cancel/execution controls"
    );
    ensure!(
        acknowledge_source_conversion && request.schema_version == 1,
        "explicit disposable source conversion acknowledgement required"
    );
    request.expected_source.validate()?;
    request.observation_budget.validate()?;
    ensure!(
        request.minimum_free_bytes > 0
            && request.maximum_staging_allocation_bytes > 0
            && request.maximum_evidence_bytes > 0
            && request.arena_scratch_bytes > 0,
        "explicit nonzero resource reserves required"
    );
    let route = n2r_win32::discovery::discover(
        &request.source_root,
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        route.binding == request.expected_source
            && route.filesystem == "NTFS"
            && route.read_only
            && route.observed_twice_unchanged
            && route.source_write_requests == 0,
        "actual readonly source route differs from supplied routing pin"
    );
    let binding = PartitionSourceBinding {
        storage: route.binding,
    };
    let mut events = Vec::new();
    let reader =
        PartitionScopedReader::open(binding.clone(), request.observation_budget, &mut events)?;
    let windows = reader.observation().windows_volume.clone();
    let parent = output.parent().context("alpha output parent absent")?;
    let _parent_owners = ordinary_directory(parent)?;
    ensure!(
        !output.exists()
            && output
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| !s.is_empty()
                    && !s.ends_with([' ', '.'])
                    && !s.chars().any(|c| c.is_control()
                        || matches!(c, ':' | '/' | '\\' | '"' | '<' | '>' | '|' | '?' | '*'))),
        "fresh ordinary alpha output required"
    );
    let destination = n2r_win32::partition_isolation::metadata_destination_outside_source(
        &binding,
        parent,
        &mut events,
    )?;
    if prepare_only {
        ensure!(
            destination.disk_number != binding.storage.disk_number,
            "offline apply bundle/control/intent/J must use another physical disk"
        );
        let parent_guid = n2r_win32::file_storage::final_path_guid(
            _parent_owners
                .first()
                .context("held external parent absent")?,
        )?;
        let end = parent_guid
            .find('}')
            .context("external parent has no volume GUID")?
            + 1;
        let external = n2r_win32::discovery::discover(
            &format!("{}\\", &parent_guid[..end]),
            n2r_win32::discovery::Role::Journal {
                allow_additional_partitions: true,
            },
        )?;
        ensure!(
            external.read_only
                && external.observed_twice_unchanged
                && external.source_write_requests == 0
                && external.binding.disk_number != binding.storage.disk_number
                && n2r_win32::layout::guid_bytes(&external.binding.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&binding.storage.identity.disk_guid)?,
            "actual external preparation parent aliases source disk"
        );
    } else {
        ensure!(
            destination.disk_number == windows.disk_number
                && destination.offset == windows.offset
                && destination.length == windows.length,
            "alpha controls/intent must be on the actual Windows volume outside selected source"
        );
    }
    drop(reader);
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    ensure!(
        request.total_ram_bytes <= available.available_physical_bytes,
        "total admitted RAM exceeds current physical availability"
    );
    let parent_owner = _parent_owners.first().context("held parent missing")?;
    let slack = n2r_win32::file_storage::artifact_allocation_slack(parent_owner)?;
    let intent_quota = PartitionPreparationGuard::maximum_intent_file_bytes()
        .checked_add(slack)
        .context("intent reservation overflow")?;
    let pause_ram = if pause_nonce.is_some() {
        controlled_pause::RAM_RESERVE_BYTES
    } else {
        0
    };
    let pause_evidence = if pause_nonce.is_some() {
        controlled_pause::EVIDENCE_RESERVE_BYTES
    } else {
        0
    };
    let control_quota = request
        .maximum_evidence_bytes
        .checked_mul(if prepare_only { 3 } else { 2 })
        .and_then(|n| n.checked_add(intent_quota))
        .and_then(|n| n.checked_add(pause_evidence))
        .context("control reservation overflow")?;
    let independent = request
        .minimum_free_bytes
        .checked_add(request.maximum_staging_allocation_bytes)
        .and_then(|n| n.checked_add(control_quota))
        .context("independent storage reservation overflow")?;
    ensure!(
        available
            .scratch_available_bytes
            .checked_sub(independent)
            .is_some_and(|n| n >= request.arena_scratch_bytes),
        "actual working storage cannot cover staging, intent/evidence, arena and free reserve"
    );
    let ledger_ram = 5 * 1024 * 1024u64;
    let sdk_ram = request
        .observation_budget
        .ram_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(PartitionPreparationGuard::intent_working_memory_bytes()))
        .context("SDK RAM reserve overflow")?;
    let arena_ram = request
        .total_ram_bytes
        .checked_sub(EXECUTION_STACK_RESERVE_BYTES)
        .and_then(|n| n.checked_sub(pause_ram))
        .and_then(|n| n.checked_sub(sdk_ram))
        .and_then(|n| n.checked_sub(ledger_ram))
        .context("total RAM cannot cover execution stacks and independent SDK lifecycle/owner/intent/evidence")?;
    let resources = derive_budget(arena_ram, align(request.arena_scratch_bytes))?;
    let capture = align(resources.scratch_bytes / 3);
    let journal_bytes = align(resources.scratch_bytes - resources.scratch_bytes / 3);
    let combined = align(resources.scratch_bytes - resources.scratch_bytes / 6);
    let partition_bytes = align(binding.storage.identity.partition_bytes);
    let max_changed_bytes = if request.selected_capacity_policy.is_conservative() {
        align(
            partition_bytes.min(
                journal_bytes
                    .checked_sub(n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE)
                    .context("selected journal cannot reserve its metadata")?,
            ),
        )
    } else {
        partition_bytes
    };
    let mut capture_budget = CaptureBudget {
        max_changed_bytes,
        max_journal_bytes: journal_bytes,
        max_literal_backing_bytes: capture,
        max_combined_backing_and_journal_bytes: combined,
        minimum_free_bytes: request.minimum_free_bytes,
        selected_capacity_policy: request.selected_capacity_policy,
    };
    // Bound changed bytes by admitted journal capacity, not by volume size.
    // Reject inconsistent budgets before acquiring source protection or staging.
    capture_budget.validate(binding.storage.identity.partition_bytes)?;
    fs::create_dir(output)?;
    let _run_owners = ordinary_directory(output)?;
    for name in ["control", "provider", "arena"] {
        fs::create_dir(output.join(name))?;
    }
    let _control_owners = ordinary_directory(&output.join("control"))?;
    let _provider_owners = ordinary_directory(&output.join("provider"))?;
    let _arena_owners = ordinary_directory(&output.join("arena"))?;
    let ledger_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(1)
        .open(output.join("control/native-events.jsonl"))?;
    let observer = Observer(Arc::new(Mutex::new(Ledger {
        file: ledger_file,
        bytes: 0,
        event_encoder: Default::default(),
        maximum: request.maximum_evidence_bytes,
        poisoned: false,
        meter: None,
        stage_maximum: request.maximum_staging_allocation_bytes,
        minimum_free: request.minimum_free_bytes,
        run: output.to_path_buf(),
    })));
    observer.lock()?.record(
        &serde_json::json!({"kind":"partition-alpha-admitted-resources","request":request,
        "actual_source":binding,"arena":resources,"intent_maximum_including_slack":intent_quota,
        "cancel_before_private_requested":cancel_readonly,"windows_prepare_for_offline_apply":prepare_only,
        "intent_outside_arena":true,"evidence_outside_arena":true,"provider_outside_arena":true,
        "independently_reserved_sdk_ram_bytes":sdk_ram,"ledger_ram_bytes":ledger_ram,
        "worker_stack_reservation_bytes":WORKER_STACK_BYTES,
        "execution_stacks_reservation_bytes":EXECUTION_STACK_RESERVE_BYTES,
        "controlled_pause_enabled":pause_nonce.is_some(),
        "controlled_pause_reader_stack_reservation_bytes":if pause_nonce.is_some(){controlled_pause::READER_STACK_BYTES}else{0},
        "controlled_pause_ram_reservation_bytes":pause_ram,
        "controlled_pause_extra_control_evidence_reservation_bytes":pause_evidence,
        "stack_reservation_is_not_peak_resident_memory":true,
        "maximum_staging_is_observed_phase_budget_not_kernel_quota":true}),
    )?;
    observer.checkpoint("readonly-source-route-and-resource-admission", &mut events)?;
    if cancel_readonly {
        let cancellation = (|| -> Result<serde_json::Value> {
            let intent = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(output.join("control/partition.intent"))?;
            let mut guard = PartitionPreparationGuard::begin(
                binding.clone(),
                request.observation_budget,
                intent,
                Box::new(observer.clone()),
                &mut events,
            )?;
            guard.protect_basic_readonly(&mut events)?;
            observer.checkpoint("partition-cancel-actual-mounted-readonly", &mut events)?;
            guard.cancel_before_private(&mut events)?;
            let stage = guard.stage();
            // Closing the actual locking FileObject releases the lock before
            // an independent observer or subsequent conversion can open NTFS.
            drop(guard);
            ensure!(
                stage == n2r_win32::partition_lifecycle::PartitionPreparationStage::Cancelled,
                "actual live cancellation did not reach Cancelled"
            );
            Ok(
                serde_json::json!({"kind":"partition-alpha-live-readonly-cancellation-result-v1",
                "success":true,"actual_guard_stage":stage,"locking_guard_closed":true,
                "payload_apply_attempted":false,"shadow_created":false,
                "independent_file_preservation_verification_required":true}),
            )
        })();
        let drained = observer.checkpoint("partition-cancel-guard-closed", &mut events);
        return match (cancellation, drained) {
            (Ok(value), Ok(())) => {
                observer.lock()?.record(&value)?;
                save(
                    &output.join("control/result.json"),
                    &value,
                    request.maximum_evidence_bytes,
                )?;
                Ok(())
            }
            (Err(error), Ok(())) => {
                let _ = observer.lock().and_then(|mut log| {
                    log.record(&serde_json::json!({
                    "kind":"partition-alpha-live-cancellation-error", "error":format!("{error:#}"),
                    "automatic_retry":false,"preserve_actual_source_and_intent":true}))
                });
                Err(error.context(
                    "live cancellation stopped; preserve actual source protection and intent",
                ))
            }
            (Ok(_), Err(error)) => Err(error.into()),
            (Err(error), Err(checkpoint)) => Err(error.context(format!(
                "live cancellation and durable event checkpoint failed: {checkpoint}"
            ))),
        };
    }
    let shadow = managed_shadow::create_with_profile(
        &output.join("provider/shadow.vhdx"),
        binding.storage.identity.partition_bytes,
        binding.storage.identity.logical_sector_bytes,
        binding.storage.identity.physical_sector_bytes,
        request.target_format,
    )?;
    observer.lock()?.meter = Some(shadow.staging_allocation_meter()?);
    observer.checkpoint(
        if request.target_format.is_dev_drive() {
            "fresh-owned-devdrive-shadow-formatted"
        } else {
            "fresh-owned-standard-shadow-formatted"
        },
        &mut events,
    )?;
    let run_guid =
        n2r_win32::file_storage::final_path_guid(_run_owners.first().context("held run absent")?)?;
    let root_end = run_guid.find('}').context("run has no volume GUID")? + 1;
    let journal_route = n2r_win32::discovery::discover(
        &format!("{}\\", &run_guid[..root_end]),
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    let journal = GeneralJournalStorageBinding {
        externally_enrolled_disk_unique_id: format!(
            "partition-alpha-{}",
            journal_route.binding.identity.disk_guid
        ),
        disk: journal_route.binding,
        allow_additional_partitions: true,
    };
    journal.validate()?;
    let actual = n2r_win32::resource_native::observe_available_resources(output)?;
    let staging_now = observer
        .lock()?
        .meter
        .as_ref()
        .context("actual staging meter absent")?
        .observe()?
        .backing_file
        .allocation_bytes;
    let remaining_staging = request
        .maximum_staging_allocation_bytes
        .checked_sub(staging_now)
        .context("staging exceeds admitted sampled budget")?;
    let remaining_independent = request
        .minimum_free_bytes
        .checked_add(remaining_staging)
        .and_then(|n| n.checked_add(control_quota))
        .context("remaining reserve overflow")?;
    ensure!(
        actual
            .scratch_available_bytes
            .checked_sub(remaining_independent)
            .is_some_and(|n| n >= resources.scratch_bytes),
        "formatting consumed reserved working-volume conversion capacity"
    );
    let intent = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(output.join("control/partition.intent"))?;
    ensure!(
        intent.metadata()?.len() == 0,
        "fresh empty external intent required"
    );
    // Full native intent quota and lifecycle/owner RAM were subtracted ABOVE.
    // Mutable intent/log/provider files are deliberately outside this root.
    let arena_root = output.join("arena");
    let arena = ArtifactArena::new(
        &arena_root,
        resources,
        &[binding.storage.clone(), shadow.binding.clone()],
    )?;
    let pair = GeneralSourceShadowBinding {
        source: binding.storage.clone(),
        shadow: shadow.binding.clone(),
    };
    capture_budget.minimum_free_bytes = remaining_independent;
    let guard = if prepare_only {
        PartitionPreparationGuard::begin_external_journal(
            binding.clone(),
            request.observation_budget,
            intent,
            &journal,
            Box::new(observer.clone()),
            &mut events,
        )?
    } else {
        PartitionPreparationGuard::begin(
            binding.clone(),
            request.observation_budget,
            intent,
            Box::new(observer.clone()),
            &mut events,
        )?
    };
    let placement = binding
        .storage
        .identity
        .partition_bytes
        .checked_mul(4)
        .context("placement work overflow")?;
    let target = PartitionTargetRequest {
        pair,
        maximum_placement_bytes: placement,
        maximum_placement_submissions: usize::try_from(placement / 4096)?
            .min(n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS),
        maximum_materialized_bytes: capture,
        maximum_source_read_bytes: i64::MAX as u64,
        capture_arena_bytes: capture,
        capture_budget,
    };
    let prepared = PartitionPreparationRequest {
        binding,
        observation_budget: request.observation_budget,
        resources,
        verification_policy: request.verification_policy,
        target,
    };
    let result = (|| -> Result<serde_json::Value> {
        let prepared_result = if prepare_only {
            prepare_partition_resources_readonly_physical(
                prepared,
                &arena_root,
                &arena,
                guard,
                &mut events,
                |phase, events| {
                    observer
                        .checkpoint(phase, events)
                        .map_err(anyhow::Error::from)
                },
            )
        } else {
            prepare_partition_resources(
                prepared,
                &arena_root,
                &arena,
                guard,
                &mut events,
                |phase, events| {
                    observer
                        .checkpoint(phase, events)
                        .map_err(anyhow::Error::from)
                },
            )
        };
        let mut owned = match prepared_result {
            Ok(owned) => owned,
            Err(failure) => {
                if prepare_only {
                    return Err(anyhow::anyhow!(format!("{:#}",failure.cause())).context(
                    "Windows prepare-only refused; preserve actual source protection and all artifacts"));
                }
                let original = anyhow::anyhow!(format!("{:#}", failure.cause()));
                let mut cancellation_observer = observer.clone();
                let cancelled = failure.cancel_if_live(&mut cancellation_observer, &mut events);
                return Err(live_private_cancellation_error(
                    original,
                    cancelled,
                    &observer,
                    &mut events,
                ));
            }
        };
        let execution = PartitionExecutionRequest {
            journal,
            maximum_journal_bytes: journal_bytes,
            maximum_selected_bytes: request.expected_source.identity.partition_bytes,
            maximum_index_bytes: resources.scratch_bytes / 16,
            recovery_arena_bytes: resources.scratch_bytes / 16,
        };
        if prepare_only {
            let core = owned.prepare_for_offline_apply(
                &execution,
                &arena_root,
                &mut events,
                |phase, events| {
                    observer
                        .checkpoint(phase, events)
                        .map_err(anyhow::Error::from)
                },
            )?;
            // The arena owns a SAME-FILE_OBJECT readonly J allocation witness.
            // Close the LAST arena clone before any ordinary J reopen/readback.
            drop(arena);
            let receipt =
                prepare_only::finish_prepared(core, output, &request, &observer, &mut events)?;
            let result = serde_json::to_value(&receipt)?;
            if let RunPurpose::Prepare(slot) = &mut purpose {
                **slot = Some(receipt);
            } else {
                anyhow::bail!("prepare-only result has no owning return slot");
            }
            return Ok(result);
        }
        let mut pause_publication = None;
        let pending_result =
            owned.execute_and_handoff(&execution, &arena_root, &mut events, |phase, events| {
                observer
                    .checkpoint(phase, events)
                    .map_err(anyhow::Error::from)
            }, Some(|progress: crate::resource_preparation::partition_preparation::PartitionExecutionProgress<'_>,
                events: &mut Vec<NativeEvent>| {
                use crate::resource_preparation::partition_preparation::PartitionExecutionProgress;
                match progress {
                    PartitionExecutionProgress::Accounting(preparation) => {
                        // Paid by the existing independent bounded ledger RAM
                        // allowance. Same-held outer metadata only; failures
                        // remain unknown observations, never capacity truth.
                        let mut ledger=observer.lock()?;
                        let observed=ledger.meter.as_ref().map(|meter|meter.observe());
                        let sample=observed.as_ref().and_then(|v|v.as_ref().ok());
                        let error=observed.as_ref().and_then(|v|v.as_ref().err()).map(ToString::to_string);
                        let report=serde_json::json!({"kind":"pre-ap-resource-accounting-v1","source_scope":"selected_partition",
                            "preparation":preparation,"staging_backing":sample,"staging_observation_error":error,
                            "staging_meter_present":ledger.meter.is_some(),"admitted_total_ram_bytes":request.total_ram_bytes,
                            "independent_sdk_ram_reservation_bytes":sdk_ram,"ledger_ram_reservation_bytes":ledger_ram,
                            "execution_stack_reservation_bytes":EXECUTION_STACK_RESERVE_BYTES,
                            "controlled_pause_ram_reservation_bytes":pause_ram,
                            "admitted_RAM_is_not_working_set_or_peak":true,
                            "current_backing_allocation_is_not_virtual_capacity_or_peak":true,
                            "measurement_grants_authority":false});
                        ledger.record(&report)?;
                        let text=|v:Option<u64>|v.map(|n|n.to_string()).unwrap_or_else(||"unknown".into());
                        let allocated=sample.map(|s|s.backing_file.allocation_bytes);
                        use std::io::Write as _;
                        let _=writeln!(std::io::stdout().lock(),
                            "Before apply: backing allocation {} bytes; capture literal {} bytes, index {} bytes; encoded journal {} bytes (allocation {}); admitted RAM {} bytes.",
                            text(allocated),text(preparation["capture_literal_file_bytes"].as_u64()),
                            text(preparation["capture_index_wire_bytes"].as_u64()),text(preparation["encoded_journal_bytes"].as_u64()),
                            text(preparation["journal_current_allocation_bytes"].as_u64()),request.total_ram_bytes);
                    }
                    PartitionExecutionProgress::Published(receipt) => {
                        observer.lock()?.record(receipt)?;
                        observer.checkpoint("partition-actual-publisher-before-AP", events)?;
                        if pause_nonce.is_some() {
                            save(&output.join("control/publication-before-AP.json"), receipt, 512 * 1024)?;
                            pause_publication = Some(receipt.clone());
                        }
                    }
                    PartitionExecutionProgress::PostFlush(receipt) => {
                        observer.lock()?.record(receipt)?;
                        observer.checkpoint("partition-nondiscovery-writes-flushed", events)?;
                        if let Some(nonce) = pause_nonce.as_deref() {
                            controlled_pause::wait(&observer, output, nonce,
                                pause_publication.as_ref().context("actual pre-AP publisher receipt absent")?, receipt)?;
                        }
                    }
                }
                Ok(())
            }));
        let pending = match pending_result {
            Ok(pending) => pending,
            Err(cause) => {
                // The consumed SDK source-gate/held-J history decides whether
                // this is still a cancellable original NTFS preparation.
                // An AP/RB attempt cannot enter cancellation or replay here.
                let mut cancellation_observer = observer.clone();
                let cancelled = owned.cancel_unactivated(&mut cancellation_observer, &mut events);
                return Err(live_private_cancellation_error(
                    cause,
                    cancelled,
                    &observer,
                    &mut events,
                ));
            }
        };
        let trusted = hex::encode(pending.trusted_publication_sha256());
        println!("Trusted recovery publication SHA256: {trusted}");
        io::stdout().flush()?;
        let mut restoration = observer.clone();
        let finalization = finalize_partition_handoff(
            owned,
            pending,
            &mut restoration,
            &mut events,
            |phase, events| {
                observer
                    .checkpoint(phase, events)
                    .map_err(anyhow::Error::from)
            },
        )?;
        observer.checkpoint("partition-alpha-native-finalization-complete", &mut events)?;
        drop(observer.lock()?.meter.take());
        let retirement = shadow.retire_after_successful_v4();
        Ok(
            serde_json::json!({"kind":"partition-alpha-actual-normal-result","success":true,
            "finalization":finalization,"owned_shadow_retirement":retirement,"trusted_publication_sha256":trusted,
            "hardware_wide_qualification":false,"stable_release_qualification":false}),
        )
    })();
    match result {
        Ok(value) => {
            observer.lock()?.record(&value)?;
            save(
                &output.join("control/result.json"),
                &value,
                request.maximum_evidence_bytes,
            )?;
            Ok(())
        }
        Err(error) => {
            let message = format!("{error:#}");
            let _=observer.lock().and_then(|mut l|l.record(
            &serde_json::json!({"kind":"partition-alpha-actual-error","success":false,"error":message})));
            Err(error
                .context("conversion stopped; preserve this run and actual source/recovery state"))
        }
    }
}

/// Preserve the original preparation error together with the actual consuming
/// cancellation result. A refusal never requests opposite-direction replay,
/// a setter retry or a state reconstruction from the saved receipts.
fn live_private_cancellation_error(
    cause: anyhow::Error,
    cancellation: Result<serde_json::Value>,
    observer: &Observer,
    events: &mut Vec<NativeEvent>,
) -> anyhow::Error {
    let original = format!("{cause:#}");
    let (receipt, cancel_error) = match cancellation {
        Ok(receipt) => (Some(receipt), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let drained = observer.checkpoint("partition-live-private-cancellation-closed", events);
    let recorded = observer.lock().and_then(|mut log| {
        log.record(&serde_json::json!({
            "kind":"partition-alpha-actual-live-private-cancellation",
            "preparation_error":original,"cancellation":receipt,"cancellation_error":cancel_error,
            "automatic_retry":false,"automatic_replay":false,"saved_receipt_grants_authority":false,
        }))
    });
    let mut error = if let Some(cancel) = cancel_error {
        cause.context(format!(
            "actual live private cancellation refused; preserve source/J/origin: {cancel}"
        ))
    } else {
        cause.context("preparation failed; actual live unactivated source cancellation completed")
    };
    if let Err(checkpoint) = drained {
        error = error.context(format!(
            "durable cancellation event checkpoint also failed: {checkpoint}"
        ));
    }
    if let Err(record) = recorded {
        error = error.context(format!("cancellation result record also failed: {record}"));
    }
    error
}

#[path = "resource_partition_recovery.rs"]
mod recovery;
pub use recovery::{
    PARTITION_RECOVERY_WORKER_STACK_BYTES, PartitionRecoveryDirection, PartitionRecoveryRequest,
    run_recovery,
};
