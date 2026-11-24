//! Windows-side boot handoff around the original native preparation.
//! This owner can install recovery selection, never issue a source writer.
use super::*;
use crate::{
    ntfs_inspect::{paged_storage::SourceScratch, source_domain::SourceMetadataBudget},
    resource_prepared_bundle::HeldWindowsPreparedBundle,
};
use n2r_win32::{
    recovery_boot::{OwnedRecoveryBoot, RecoveryBootBudget, RecoveryBootReceipt},
    recovery_image::{self, RecoveryImageRequest},
};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedBootRequest {
    pub schema_version: u32,
    pub prepared_bundle: PathBuf,
    pub prepared_bundle_sha256: String,
    pub source: GeneralDiskBinding,
    pub journal: GeneralJournalStorageBinding,
    pub maximum_bundle_bytes: u64,
    pub metadata_budget: SourceMetadataBudget,
    pub total_ram_bytes: u64,
    pub maximum_evidence_bytes: u64,
    pub minimum_free_bytes: u64,
    pub image: RecoveryImageRequest,
    pub boot: RecoveryBootBudget,
}

fn gpt_digest(gpt: &n2r_win32::partition_isolation::PartitionGptObservation) -> String {
    let mut h = Sha256::new();
    h.update(&gpt.primary_header);
    h.update(&gpt.entries);
    h.update(&gpt.backup_header);
    h.update(&gpt.native_layout);
    hex::encode(h.finalize())
}

/// Build only the independently owned recovery image and persistent selection.
/// No restart is issued here: the owning public dispatcher can flush its output
/// and request a normal restart after this exact receipt has been persisted.
pub fn arm_prepared_boot(
    request: PreparedBootRequest,
    output: &Path,
    acknowledge_persistent_recovery_boot: bool,
) -> Result<RecoveryBootReceipt> {
    arm_prepared_boot_inner(request, output, acknowledge_persistent_recovery_boot, None)
}

/// Reopen the exact completed image after a failed pre-install operation.
/// This authenticates current bytes; it recreates no source write capability.
pub fn arm_existing_prepared_boot(
    request: PreparedBootRequest,
    output: &Path,
    acknowledge_persistent_recovery_boot: bool,
    completed_image_record_sha256: [u8; 32],
) -> Result<RecoveryBootReceipt> {
    arm_prepared_boot_inner(
        request,
        output,
        acknowledge_persistent_recovery_boot,
        Some(completed_image_record_sha256),
    )
}

fn arm_prepared_boot_inner(
    request: PreparedBootRequest,
    output: &Path,
    acknowledge_persistent_recovery_boot: bool,
    completed_image_record_sha256: Option<[u8; 32]>,
) -> Result<RecoveryBootReceipt> {
    ensure!(
        acknowledge_persistent_recovery_boot,
        "explicit recovery boot acknowledgement required"
    );
    ensure!(request.schema_version == 1, "unknown prepared boot request");
    request.source.validate()?;
    request.journal.validate()?;
    request.metadata_budget.validate()?;
    request.image.observation.validate()?;
    ensure!(
        request.maximum_evidence_bytes > 0
            && request.maximum_evidence_bytes <= request.total_ram_bytes / 8,
        "bounded independent boot evidence required"
    );
    ensure!(
        request.image.prepared_bundle_sha256 == decode_sha(&request.prepared_bundle_sha256)?,
        "boot image does not bind the selected preparation bundle"
    );
    let parent = output.parent().context("boot output parent absent")?;
    let _parents = ordinary_directory(parent)?;
    ensure!(!output.exists(), "fresh boot output required");
    let observed = n2r_win32::resource_native::observe_available_resources(parent)?;
    let ram = request
        .metadata_budget
        .ram_bytes
        .checked_add(request.image.budget.ram_bytes)
        .and_then(|n| n.checked_add(request.boot.ram_bytes))
        .and_then(|n| n.checked_add(request.image.observation.ram_bytes.checked_mul(2)?))
        .and_then(|n| n.checked_add(EXECUTION_STACK_RESERVE_BYTES + 5 * 1024 * 1024))
        .context("aggregate boot memory overflow")?;
    let image_working = if completed_image_record_sha256.is_some() {
        0
    } else {
        request.image.budget.admitted_working_bytes
    };
    let disk = image_working
        .checked_add(
            request
                .maximum_evidence_bytes
                .checked_mul(3)
                .context("boot evidence overflow")?,
        )
        .and_then(|n| n.checked_add(request.minimum_free_bytes))
        .context("aggregate boot storage overflow")?;
    ensure!(
        ram <= request.total_ram_bytes
            && request.total_ram_bytes <= observed.available_physical_bytes,
        "boot image, metadata, native and stack memory exceed admitted available RAM"
    );
    ensure!(
        observed.scratch_available_bytes >= disk,
        "boot image/evidence/reserve exceed actual independent capacity"
    );
    let parent_handle = _parents.first().context("held boot parent absent")?;
    let parent_route = n2r_win32::file_storage::final_path_guid(parent_handle)?;
    let prefix = format!(
        "{}\\",
        request.journal.disk.volume_path()?.trim_end_matches('\\')
    );
    ensure!(
        parent_route
            .get(..prefix.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(&prefix)),
        "boot output parent is not the actual independent recovery volume"
    );
    fs::create_dir(output)?;
    let _output = ordinary_directory(output)?;
    let observer = Observer(Arc::new(Mutex::new(Ledger {
        file: OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .share_mode(1)
            .open(output.join("native-events.jsonl"))?,
        bytes: 0,
        event_encoder: Default::default(),
        maximum: request.maximum_evidence_bytes,
        poisoned: false,
        meter: None,
        stage_maximum: 0,
        minimum_free: request.minimum_free_bytes,
        run: output.to_path_buf(),
    })));
    observer.lock()?.record(
        &serde_json::json!({"kind":"prepared-recovery-boot-resource-admission-v1",
        "request":request,"actual_available":observed,"aggregate_ram_required":ram,
        "independent_capacity_including_reserve":disk,"source_write_authority":false}),
    )?;
    let mut events = Vec::new();
    let result = (|| -> Result<RecoveryBootReceipt> {
        let volume = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(request.journal.disk.volume_path()?)?;
        let scratch = SourceScratch::new(request.metadata_budget)?;
        let bundle = HeldWindowsPreparedBundle::open_metadata_on_journal(
            &request.prepared_bundle,
            &request.prepared_bundle_sha256,
            request.maximum_bundle_bytes,
            &request.journal,
            &volume,
            &scratch,
            &mut events,
        )?;
        bundle.require_ready_artifacts()?;
        ensure!(
            bundle.core().source == request.source
                && bundle.core().journal_binding == request.journal,
            "actual held bundle source/recovery volume differs from selected boot request"
        );
        let mut restoration = observer.clone();
        let mut source = n2r_win32::partition_restoration::PartitionBasicReadonlyTerminal::open_if_actual_basic_ro(
            PartitionSourceBinding { storage: request.source.clone() }, request.image.observation,
            &mut restoration, &mut events,
        )?.context("prepared source is not actual BASIC+READONLY")?;
        ensure!(
            source.filesystem() == "NTFS",
            "unapplied prepared source must remain NTFS"
        );
        source.revalidate(&mut restoration, &mut events)?;
        let mut reader = PartitionScopedReader::open(
            PartitionSourceBinding {
                storage: request.source.clone(),
            },
            request.image.observation,
            &mut events,
        )?;
        ensure!(
            gpt_digest(&reader.observation().gpt) == bundle.core().source_readonly_gpt_sha256,
            "source full GPT/siblings differ before recovery boot installation"
        );
        let mut primary = [0u8; 512];
        reader.read_exact(&mut primary)?;
        ensure!(
            hex::encode(Sha256::digest(primary))
                == bundle.core().source_preparation.ntfs_primary_sha256,
            "prepared original NTFS discovery identity changed"
        );
        drop(reader);
        let profile = n2r_win32::journal_file::JournalProfile::from_schema_and_capacity(
            bundle.core().journal_profile_version,
            Some(bundle.core().journal_profile_max_bytes),
        )?;
        let mut j = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&bundle.core().journal_path)?;
        let before = n2r_win32::journal_file::observe_general_journal_file_with_profile(
            &j,
            &request.journal,
            profile,
        )?;
        ensure!(
            before.identity == bundle.core().journal_identity
                && before.file_bytes == bundle.core().ticket.journal_length,
            "actual prepared J identity or EOF changed before boot installation"
        );
        let mut clear = [0u8; 8192];
        j.seek(SeekFrom::Start(0))?;
        j.read_exact(&mut clear)?;
        ensure!(
            clear == [0u8; 8192],
            "prepared J already has intent/completion or foreign lifecycle bytes"
        );
        let after = n2r_win32::journal_file::observe_general_journal_file_with_profile(
            &j,
            &request.journal,
            profile,
        )?;
        ensure!(
            after.identity == before.identity
                && after.file_bytes == before.file_bytes
                && after.allocation_bytes == before.allocation_bytes
                && after.final_path == before.final_path
                && after.file_attributes == before.file_attributes
                && after.number_of_links == before.number_of_links,
            "prepared J changed during boot handoff check"
        );
        observer.checkpoint("prepared-boot-source-J-ready-before-image", &mut events)?;
        let image_source = PartitionSourceBinding {
            storage: request.source.clone(),
        };
        let image = if let Some(expected_record) = completed_image_record_sha256 {
            recovery_image::reopen_completed(
                &image_source,
                &request.journal,
                &volume,
                &request.image,
                expected_record,
                &mut events,
            )?
        } else {
            recovery_image::build(
                &image_source,
                &request.journal,
                &volume,
                &request.image,
                &mut events,
            )?
        };
        observer.checkpoint("prepared-boot-owned-image-complete", &mut events)?;
        // Laboratory only; a no-op unless the hidden switch armed it.
        n2r_win32::lab_fail::reached(n2r_win32::lab_fail::RESTART_AFTER_IMAGE)?;
        bundle.revalidate()?;
        source.revalidate(&mut restoration, &mut events)?;
        let boot = OwnedRecoveryBoot::install(
            image,
            &output.join("selection"),
            request.boot,
            request.image.observation,
            &mut events,
        )?;
        observer.checkpoint("prepared-boot-persistent-selection-installed", &mut events)?;
        boot.revalidate(&mut events)?;
        source.revalidate(&mut restoration, &mut events)?;
        bundle.revalidate()?;
        let receipt = boot.receipt().clone();
        save(
            &output.join("armed-recovery-boot.json"),
            &receipt,
            request.maximum_evidence_bytes,
        )?;
        observer.checkpoint(
            "prepared-boot-receipt-durable-no-restart-issued",
            &mut events,
        )?;
        // Laboratory only; a no-op unless the hidden switch armed it.
        n2r_win32::lab_fail::reached(n2r_win32::lab_fail::RESTART_AFTER_ARM)?;
        Ok(receipt)
    })();
    let drained = observer.checkpoint("prepared-boot-owner-closing", &mut events);
    match (result, drained) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), Err(close)) => {
            Err(e.context(format!("boot owner closing evidence also failed: {close}")))
        }
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e.into()),
    }
}
fn decode_sha(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical independent bundle SHA256 required"
    );
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA256 width"))
}

/// One owning-machine preparation and boot handoff. All recovery resources
/// are reserved before NTFS preparation; the image builder receives the exact
/// bundle returned by that same preparation, never a caller's READY boolean.
pub fn prepare_and_arm_shared_conversion(
    request: PartitionAlphaRequest,
    output: &Path,
    image: RecoveryImageRequest,
    boot_budget: RecoveryBootBudget,
    acknowledge: bool,
) -> Result<RecoveryBootReceipt> {
    prepare_and_arm_shared_conversion_with_pause(
        request,
        output,
        image,
        boot_budget,
        acknowledge,
        None,
    )
}

pub(crate) fn prepare_and_arm_shared_conversion_with_pause(
    mut request: PartitionAlphaRequest,
    output: &Path,
    image: RecoveryImageRequest,
    boot_budget: RecoveryBootBudget,
    acknowledge: bool,
    controlled_pause_nonce: Option<String>,
) -> Result<RecoveryBootReceipt> {
    ensure!(
        acknowledge,
        "shared conversion and persistent recovery boot require confirmation"
    );
    if let Some(nonce) = &controlled_pause_nonce {
        super::controlled_pause::require_nonce(nonce)?;
    }
    ensure!(
        request.schema_version == 1 && output.is_absolute() && !output.exists(),
        "fresh shared conversion namespace required"
    );
    let parent = output.parent().context("shared conversion parent absent")?;
    let _parent = ordinary_directory(parent)?;
    let parent_guid = n2r_win32::file_storage::final_path_guid(
        _parent.first().context("held shared parent absent")?,
    )?;
    let end = parent_guid
        .find('}')
        .context("shared parent has no native volume GUID")?
        + 1;
    let journal_route = n2r_win32::discovery::discover(
        &format!("{}\\", &parent_guid[..end]),
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        journal_route.read_only
            && journal_route.observed_twice_unchanged
            && journal_route.source_write_requests == 0
            && journal_route.binding.disk_number != request.expected_source.disk_number
            && n2r_win32::layout::guid_bytes(&journal_route.binding.identity.disk_guid)?
                != n2r_win32::layout::guid_bytes(&request.expected_source.identity.disk_guid)?,
        "whole workflow must use an actually observed independent recovery disk"
    );
    let actual = n2r_win32::resource_native::observe_available_resources(parent)?;
    let additional = image
        .budget
        .admitted_working_bytes
        .checked_add(
            request
                .maximum_evidence_bytes
                .checked_mul(3)
                .context("boot evidence overflow")?,
        )
        .context("shared image reservation overflow")?;
    request.minimum_free_bytes = request
        .minimum_free_bytes
        .checked_add(additional)
        .context("shared image free reserve overflow")?;
    let required = request
        .arena_scratch_bytes
        .checked_add(request.maximum_staging_allocation_bytes)
        .and_then(|n| n.checked_add(request.maximum_evidence_bytes.checked_mul(3)?))
        .and_then(|n| n.checked_add(request.minimum_free_bytes))
        .and_then(|n| n.checked_add(PartitionPreparationGuard::maximum_intent_file_bytes()))
        .context("whole shared workflow admission overflow")?;
    ensure!(
        actual.scratch_available_bytes >= required,
        "independent storage cannot cover preparation, image, boot evidence and free reserve together"
    );
    ensure!(
        request.total_ram_bytes <= actual.available_physical_bytes,
        "whole shared workflow RAM exceeds actual availability"
    );
    fs::create_dir(output)?;
    let _output = ordinary_directory(output)?;
    let output_guid = PathBuf::from(n2r_win32::file_storage::final_path_guid(
        _output
            .first()
            .context("held shared workflow directory absent")?,
    )?);
    save(
        &output.join("workflow-admission.json"),
        &serde_json::json!({
            "kind":"shared-native-shadow-offline-workflow-admission-v1", "preparation":request,
            "recovery_image":image, "boot_budget":boot_budget, "required_independent_capacity":required,
            "actual_available":actual, "source_payload_write_authority":false,
            "controlled_postflush_pause":controlled_pause_nonce.is_some()
        }),
        request.maximum_evidence_bytes,
    )?;
    // Before anything is changed: the boot configuration can be read the
    // way the installation of the boot selection, and every way back, will
    // have to read it. (`bcdedit` answers in the display language of
    // Windows; the installation found that out only after the long
    // preparation, with the source already read-only.)
    n2r_win32::recovery_boot::require_readable_boot_configuration(
        &output.join("boot-readable"),
        boot_budget,
    )?;
    // From here on the run has a folder and its admission record, and a
    // failure is not left as it falls: whatever the run did to the source
    // and to the boot selection is taken back from its own records, and the
    // error says what became of the volume (`way_back`).
    prepare_and_arm_admitted(
        request,
        output,
        output_guid,
        image,
        boot_budget,
        additional,
        controlled_pause_nonce,
    )
    .map_err(|cause| way_back::after_failure_in_windows(output, cause))
}

fn prepare_and_arm_admitted(
    request: PartitionAlphaRequest,
    output: &Path,
    output_guid: PathBuf,
    mut image: RecoveryImageRequest,
    boot_budget: RecoveryBootBudget,
    additional: u64,
    controlled_pause_nonce: Option<String>,
) -> Result<RecoveryBootReceipt> {
    let source = request.expected_source.clone();
    let total_ram = request.total_ram_bytes;
    let evidence = request.maximum_evidence_bytes;
    let minimum_free = request.minimum_free_bytes - additional;
    let observation = request.observation_budget;
    let prepared = prepare_for_offline_apply(request, &output.join("prepared"), true)?;
    let available_after = n2r_win32::resource_native::observe_available_resources(output)?;
    let metadata = SourceMetadataBudget::from_resource_budget(derive_budget(
        total_ram / 4,
        align(available_after.scratch_available_bytes / 16),
    )?)?;
    let bundle_pin = decode_sha(&prepared.bundle_manifest_sha256)?;
    let bootstrap = output.join("offline-request.json");
    let offline_request = PreparedOfflineRequest {
        schema_version: 1,
        source: PartitionSourceBinding {
            storage: source.clone(),
        },
        journal: prepared.journal_binding.clone(),
        prepared_bundle: {
            let held = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(&prepared.bundle_manifest_path)?;
            PathBuf::from(n2r_win32::file_storage::final_path_guid(&held)?)
        },
        prepared_bundle_sha256: prepared.bundle_manifest_sha256.clone(),
        maximum_bundle_bytes: evidence,
        output_parent: output_guid.clone(),
        observation_budget: observation,
        total_ram_bytes: total_ram,
        // Reopened index/maps are metadata. Do not reserve the former shadow
        // or journal a second time; their actual storage remains occupied.
        arena_scratch_bytes: align(available_after.scratch_available_bytes / 8),
        maximum_evidence_bytes: evidence,
        minimum_free_bytes: minimum_free,
        boot_intent: output_guid.join("boot/selection/recovery-boot-guard-intent.json"),
        boot_budget,
        action: PreparedOfflineAction::AutoResume,
        controlled_pause_nonce,
        // Present only when the hidden laboratory switch armed the point of
        // the recovery environment.
        lab_fail_at: n2r_win32::lab_fail::armed()
            .filter(|point| *point == n2r_win32::lab_fail::WINPE_BEFORE_APPLY)
            .map(str::to_owned),
    };
    save(&bootstrap, &offline_request, evidence)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&bootstrap)?;
    let bytes = file.metadata()?.len();
    let bootstrap_hash = n2r_win32::sha256_native::hash_range(&mut file, 0, bytes)?;
    image.root = output.join("recovery-image");
    image.prepared_bundle_sha256 = bundle_pin;
    image.bootstrap = n2r_win32::recovery_image::RecoveryImageInput {
        path: bootstrap,
        bytes,
        sha256: bootstrap_hash,
    };
    image.startup_args = vec![
        "--request-sha256".into(),
        hex::encode(bootstrap_hash),
        "--bundle-sha256".into(),
        prepared.bundle_manifest_sha256.clone(),
        "--acknowledge-offline-conversion".into(),
    ];
    arm_prepared_boot(
        PreparedBootRequest {
            schema_version: 1,
            prepared_bundle: prepared.bundle_manifest_path,
            prepared_bundle_sha256: prepared.bundle_manifest_sha256,
            source,
            journal: prepared.journal_binding,
            maximum_bundle_bytes: evidence,
            metadata_budget: metadata,
            total_ram_bytes: total_ram,
            maximum_evidence_bytes: evidence,
            minimum_free_bytes: minimum_free,
            image,
            boot: boot_budget,
        },
        &output.join("boot"),
        true,
    )
}
