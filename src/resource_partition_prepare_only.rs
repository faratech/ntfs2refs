//! Explicit Windows prepare-only entry. This does not dispatch apply/recovery
//! and its serializable receipt cannot recreate a writer or root certificate.
use super::*;
use crate::selected_journal::resource_domain::prepare::WindowsPreparedBundleCore;
use sha2::Digest;
#[derive(Clone, Serialize)]
pub struct WindowsPreparedOfflineApplyReceipt {
    pub schema_version: u32,
    pub kind: &'static str,
    pub bundle_manifest_path: PathBuf,
    pub bundle_manifest_sha256: String,
    pub publication_path: PathBuf,
    pub publication_sha256: String,
    pub source: GeneralDiskBinding,
    pub journal_binding: GeneralJournalStorageBinding,
    pub journal_path: PathBuf,
    pub journal_file_id_128: [u8; 16],
    pub journal_bytes: u64,
    pub source_readonly_after_all_producer_handles_closed: bool,
    pub source_payload_write_calls: u64,
    pub source_apply_intent_attempted: bool,
    pub source_write_or_replay_authority: bool,
}
pub(super) enum RunPurpose<'a> {
    Convert,
    Prepare(&'a mut Option<WindowsPreparedOfflineApplyReceipt>),
}
pub fn prepare_for_offline_apply(
    request: PartitionAlphaRequest,
    output: &Path,
    acknowledge_preparation: bool,
) -> Result<WindowsPreparedOfflineApplyReceipt> {
    let mut receipt = None;
    run_inner(
        request,
        output,
        acknowledge_preparation,
        None,
        false,
        RunPurpose::Prepare(&mut receipt),
    )?;
    receipt.context("prepare-only did not return the actual sealed bundle")
}
fn full_gpt_hash(gpt: &n2r_win32::partition_isolation::PartitionGptObservation) -> String {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(&gpt.primary_header);
    hash.update(&gpt.entries);
    hash.update(&gpt.backup_header);
    hash.update(&gpt.native_layout);
    hex::encode(hash.finalize())
}
pub(super) fn finish_prepared(
    core: WindowsPreparedBundleCore,
    output: &Path,
    request: &PartitionAlphaRequest,
    observer: &Observer,
    events: &mut Vec<NativeEvent>,
) -> Result<WindowsPreparedOfflineApplyReceipt> {
    ensure!(
        core.source == request.expected_source
            && core.journal_prepared_clear
            && core.native_journal_body_sealed
            && !core.source_apply_intent_attempted
            && core.source_certificate_issued
            && core.source_semantic_readiness_qualified
            && !core.source_write_gate_issued
            && core.source_payload_write_calls == 0,
        "actual prepared source/publication summary is inconsistent"
    );
    let mut restoration = observer.clone();
    let mut source =
        n2r_win32::partition_restoration::PartitionBasicReadonlyTerminal::open_if_actual_basic_ro(
            PartitionSourceBinding {
                storage: core.source.clone(),
            },
            request.observation_budget,
            &mut restoration,
            events,
        )?
        .context("producer handles closed without actual BASIC+RO source")?;
    ensure!(
        source.filesystem() == "NTFS" && source.binding().storage.identity == core.source.identity,
        "post-close protected source is not the same original NTFS epoch"
    );
    source.revalidate(&mut restoration, events)?;
    let mut reader = PartitionScopedReader::open(
        PartitionSourceBinding {
            storage: core.source.clone(),
        },
        request.observation_budget,
        events,
    )?;
    ensure!(
        reader.observation().gpt.target_attributes == 0x1000_0000_0000_0000
            && full_gpt_hash(&reader.observation().gpt) == core.source_readonly_gpt_sha256,
        "post-close full source GPT/siblings/protection differs"
    );
    let mut primary = [0u8; 512];
    std::io::Read::read_exact(&mut reader, &mut primary)?;
    ensure!(
        hex::encode(sha2::Sha256::digest(primary)) == core.source_preparation.ntfs_primary_sha256,
        "post-close original NTFS discovery identity differs"
    );
    drop(reader);
    source.revalidate(&mut restoration, events)?;
    drop(source);
    observer.checkpoint(
        "windows-prepared-source-handles-closed-positive-readonly",
        events,
    )?;
    let profile = n2r_win32::journal_file::JournalProfile::from_schema_and_capacity(
        core.journal_profile_version,
        Some(core.journal_profile_max_bytes),
    )?;
    let mut journal = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&core.journal_path)?;
    n2r_win32::file_storage::require_readonly_access(&journal)?;
    let before = n2r_win32::journal_file::observe_general_journal_file_with_profile(
        &journal,
        &core.journal_binding,
        profile,
    )?;
    ensure!(
        before.identity == core.journal_identity && before.file_bytes == core.ticket.journal_length,
        "post-close actual J identity/EOF differs"
    );
    use std::io::{Read, Seek, SeekFrom};
    let mut prefix = [0u8; 8192];
    journal.seek(SeekFrom::Start(0))?;
    journal.read_exact(&mut prefix)?;
    ensure!(
        prefix.iter().all(|v| *v == 0),
        "post-close J is not actual PreparedClear; no offline bundle is issued"
    );
    let after = n2r_win32::journal_file::observe_general_journal_file_with_profile(
        &journal,
        &core.journal_binding,
        profile,
    )?;
    ensure!(
        before.identity == after.identity && before.file_bytes == after.file_bytes,
        "post-close J changed while proving clear lifecycle"
    );
    let manifest = output.join("control/windows-prepared-offline-apply-bundle.json");
    let proof = serde_json::json!({"schema_version":1,"kind":"windows-prepared-offline-apply-bundle-v1",
        "core":&core,"producer_handles_closed":true,"postclose_source_BasicReadonly_native19_verified":true,
        "postclose_source_ntfs_primary_sha256":hex::encode(sha2::Sha256::digest(primary)),
        "postclose_prepared_journal_prefix_bytes":8192,"postclose_prepared_journal_prefix_sha256":hex::encode(sha2::Sha256::digest(prefix)),
        "full_journal_body_not_rescanned_at_close":true,"historical_run_artifacts_preserved":true,
        "source_payload_write_calls":0,"source_apply_intent_attempted":false,"source_write_or_replay_authority":false,
        "requires_new_PE_guarded_prepared_consumer":true,"legacy_C_only_Origin_route_allowed":false});
    save(&manifest, &proof, request.maximum_evidence_bytes)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&manifest)?;
    let pin = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
        &file,
        request.maximum_evidence_bytes,
    )?;
    let mut readback = file;
    let digest = n2r_win32::sha256_native::hash_range(&mut readback, 0, pin.file_bytes)?;
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &readback,
            request.maximum_evidence_bytes
        )? == pin,
        "prepared bundle identity changed during independent readback"
    );
    let receipt = WindowsPreparedOfflineApplyReceipt {
        schema_version: 1,
        kind: "windows-native-prepare-only-completed-v1",
        bundle_manifest_path: manifest,
        bundle_manifest_sha256: hex::encode(digest),
        publication_path: core.publication_path,
        publication_sha256: core.publication_sha256,
        source: core.source,
        journal_binding: core.journal_binding,
        journal_path: core.journal_path,
        journal_file_id_128: core.journal_identity.file_id_128,
        journal_bytes: core.ticket.journal_length,
        source_readonly_after_all_producer_handles_closed: true,
        source_payload_write_calls: 0,
        source_apply_intent_attempted: false,
        source_write_or_replay_authority: false,
    };
    observer.lock()?.record(&receipt)?;
    observer.checkpoint("windows-prepared-offline-bundle-durable", events)?;
    Ok(receipt)
}
