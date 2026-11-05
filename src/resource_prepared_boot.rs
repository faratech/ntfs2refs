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
    let disk = request
        .image
        .budget
        .admitted_working_bytes
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
        let image = recovery_image::build(
            &PartitionSourceBinding {
                storage: request.source.clone(),
            },
            &request.journal,
            &volume,
            &request.image,
            &mut events,
        )?;
        observer.checkpoint("prepared-boot-owned-image-complete", &mut events)?;
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
