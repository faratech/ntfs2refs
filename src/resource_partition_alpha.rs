//! Explicit experimental owning-machine runner. Inputs route/budget work;
//! only actual native owners can authorize conversion of the selected source.
use crate::{
    artifact_arena::ArtifactArena,
    general_shadow::source_backed::CaptureBudget,
    resource_preparation::{
        partition_preparation::{
            PartitionExecutionRequest, PartitionPreparationRequest, finalize_partition_handoff,
            prepare_partition_resources,
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
}
struct Ledger {
    file: File,
    bytes: u64,
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
    phase: &'static str,
    events: &'a [NativeEvent],
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
        self.record(&Batch {
            kind: "actual-native-event-batch",
            phase,
            events,
        })?;
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
    ensure!(
        destination.disk_number == windows.disk_number
            && destination.offset == windows.offset
            && destination.length == windows.length,
        "alpha controls/intent must be on the actual Windows volume outside selected source"
    );
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
    let control_quota = request
        .maximum_evidence_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(intent_quota))
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
        "actual C storage cannot cover staging, intent/evidence, arena and free reserve"
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
        .and_then(|n| n.checked_sub(sdk_ram))
        .and_then(|n| n.checked_sub(ledger_ram))
        .context("total RAM cannot cover execution stacks and independent SDK lifecycle/owner/intent/evidence")?;
    let resources = derive_budget(arena_ram, align(request.arena_scratch_bytes))?;
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
        "intent_outside_arena":true,"evidence_outside_arena":true,"provider_outside_arena":true,
        "independently_reserved_sdk_ram_bytes":sdk_ram,"ledger_ram_bytes":ledger_ram,
        "worker_stack_reservation_bytes":WORKER_STACK_BYTES,
        "execution_stacks_reservation_bytes":EXECUTION_STACK_RESERVE_BYTES,
        "stack_reservation_is_not_peak_resident_memory":true,
        "maximum_staging_is_observed_phase_budget_not_kernel_quota":true}),
    )?;
    observer.checkpoint("readonly-source-route-and-resource-admission", &mut events)?;
    let shadow = managed_shadow::create_with_profile(
        &output.join("provider/shadow.vhdx"),
        binding.storage.identity.partition_bytes,
        binding.storage.identity.logical_sector_bytes,
        binding.storage.identity.physical_sector_bytes,
        TargetFormatProfile::DevDrive,
    )?;
    observer.lock()?.meter = Some(shadow.staging_allocation_meter()?);
    observer.checkpoint("fresh-owned-devdrive-shadow-formatted", &mut events)?;
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
        "formatting consumed reserved C conversion capacity"
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
    let guard = PartitionPreparationGuard::begin(
        binding.clone(),
        request.observation_budget,
        intent,
        Box::new(observer.clone()),
        &mut events,
    )?;
    let capture = align(resources.scratch_bytes / 3);
    let journal_bytes = align(resources.scratch_bytes - resources.scratch_bytes / 3);
    let combined = align(resources.scratch_bytes - resources.scratch_bytes / 6);
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
        capture_budget: CaptureBudget {
            max_changed_bytes: binding.storage.identity.partition_bytes,
            max_journal_bytes: journal_bytes,
            max_literal_backing_bytes: capture,
            max_combined_backing_and_journal_bytes: combined,
            minimum_free_bytes: remaining_independent,
            selected_capacity_policy: SelectedCapacityPolicy::SourceFreeActualBytesV1,
        },
    };
    let prepared = PartitionPreparationRequest {
        binding,
        observation_budget: request.observation_budget,
        resources,
        verification_policy: request.verification_policy,
        target,
    };
    let result = (|| -> Result<serde_json::Value> {
        let mut owned = prepare_partition_resources(
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
        )?;
        let execution = PartitionExecutionRequest {
            journal,
            maximum_journal_bytes: journal_bytes,
            maximum_selected_bytes: request.expected_source.identity.partition_bytes,
            maximum_index_bytes: resources.scratch_bytes / 16,
            recovery_arena_bytes: resources.scratch_bytes / 16,
        };
        let pending =
            owned.execute_and_handoff(&execution, &arena_root, &mut events, |phase, events| {
                observer
                    .checkpoint(phase, events)
                    .map_err(anyhow::Error::from)
            })?;
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
                .context("conversion stopped; preserve this run and actual private/recovery state"))
        }
    }
}

#[path = "resource_partition_recovery.rs"]
mod recovery;
pub use recovery::{
    PARTITION_RECOVERY_WORKER_STACK_BYTES, PartitionRecoveryDirection, PartitionRecoveryRequest,
    run_recovery,
};
