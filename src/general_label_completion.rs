//! Native-only metadata completion after irreversible ReFS handoff. The old
//! journal is a receipt, never replayed over the mounted filesystem.
use crate::{
    general_qualification as artifacts,
    general_reconstruct::Request,
    general_shadow,
    lab_native_reconstruct::{identity_hash, partition_hash},
    lab_reconstruct::{self, JournalBinding, JournalTicket},
    ntfs_attestation, shadow_tree,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent,
    journal_file::{JournalProfile, observe_general_journal_file_with_profile},
    shadow_native,
    volume_label::{self, VolumeLabel},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Inputs {
    pub request: PathBuf,
    pub request_sha256: String,
    pub ticket: PathBuf,
    pub ticket_sha256: String,
    pub journal: PathBuf,
    pub expectation: PathBuf,
    pub expectation_sha256: String,
}
fn canonical(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pinned(path: &Path, pin: &str, limit: u64) -> Result<Vec<u8>> {
    ensure!(canonical(pin), "canonical input SHA-256 required");
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && meta.file_attributes() & 0x400 == 0 && meta.len() <= limit,
        "bounded ordinary completion input required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.file_attributes() & 0x400 == 0 && meta.len() <= limit,
        "opened completion input differs"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit && hex::encode(Sha256::digest(&bytes)) == pin,
        "completion input SHA-256 differs"
    );
    Ok(bytes)
}
fn save_bytes(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "completion input copy exceeds bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
impl Inputs {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            canonical(&self.request_sha256)
                && canonical(&self.ticket_sha256)
                && canonical(&self.expectation_sha256),
            "request, ticket and expectation each require canonical SHA-256 pins"
        );
        Ok(())
    }
}

pub fn complete(inputs: &Inputs, output: &Path) -> Result<()> {
    inputs.validate()?;
    let request_bytes = pinned(&inputs.request, &inputs.request_sha256, 131072)?;
    let request: Request = serde_json::from_slice(&request_bytes)?;
    request.validate()?;
    let desired = request
        .expected_source_label
        .as_ref()
        .context("label completion requires expected_source_label in the pinned request")?;
    desired.validate()?;
    let ticket_bytes = pinned(&inputs.ticket, &inputs.ticket_sha256, 65536)?;
    let ticket: JournalTicket = serde_json::from_slice(&ticket_bytes)?;
    ensure!(
        inputs.expectation_sha256 == request.expected_tree_sha256,
        "expectation pin differs from request"
    );
    let expected_bytes = pinned(
        &inputs.expectation,
        &inputs.expectation_sha256,
        16 * 1024 * 1024,
    )?;
    let expected: shadow_tree::ExpectedTree = serde_json::from_slice(&expected_bytes)?;
    expected.validate()?;
    artifacts::create_output(output)?;
    save_bytes(output, "request.json", &request_bytes)?;
    save_bytes(output, "ticket.json", &ticket_bytes)?;
    save_bytes(output, "expectation.json", &expected_bytes)?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({"schema_version":1,"kind":"native-only-post-handoff-label-intent",
        "request_sha256":inputs.request_sha256,"ticket_sha256":inputs.ticket_sha256,"expectation_sha256":inputs.expectation_sha256,
        "journal":inputs.journal,"raw_replay_authorized":false,"disk_attribute_changes_authorized":false,"shadow_access_required":false}),
    )?;
    let mut phase = "journal-receipt";
    let attempted = (|| -> Result<()> {
        let meta = fs::symlink_metadata(&inputs.journal)?;
        ensure!(
            meta.is_file()
                && meta.file_attributes() & 0x400 == 0
                && meta.len() == ticket.journal_length
                && meta.len() <= request.max_journal_bytes,
            "journal differs from pinned bounded file"
        );
        // Read-only and exclusive: cannot update intent/progress or markers.
        let mut journal = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&inputs.journal)?;
        let observed = observe_general_journal_file_with_profile(
            &journal,
            &request.journal,
            JournalProfile::from_schema(request.schema_version)?,
        )?;
        artifacts::save(output, "journal-identity.json", &observed)?;
        let binding = JournalBinding {
            experiment_id: request.experiment_id.clone(),
            target_identity_sha256: partition_hash(&request.pair.source.identity)?,
            shadow_identity_sha256: partition_hash(&request.pair.shadow.identity)?,
            journal_identity_sha256: identity_hash(
                b"ntfs2refs/general/journal-file-identity/v1",
                &observed.identity,
            )?,
        };
        ensure!(
            ticket.schema_version == request.schema_version
                && ticket.binding == binding
                && ticket.journal_length == observed.file_bytes
                && ticket.immutable_length.checked_add(8192) == Some(ticket.journal_length),
            "journal ticket/identity differs"
        );
        let receipt =
            lab_reconstruct::verify_refs_handoff_receipt(&mut journal, &ticket, &binding)?;
        ensure!(
            serde_json::to_vec(receipt.comparison())? == serde_json::to_vec(&request.comparison)?,
            "journal comparison differs from pinned request"
        );
        artifacts::save(output, "handoff-receipt.json", &receipt)?;
        phase = "mounted-source-preflight";
        let mut events = Vec::<NativeEvent>::new();
        let source =
            n2r_win32::rediscover_general_volume(request.pair.source.clone(), &mut events)?;
        volume_label::validate_original_partition(&request.pair.source, &source)?;
        let before = volume_label::observe_label(source.clone(), "ReFS")?;
        let enrollment = VolumeLabel::from_text("n2r-retained-shadow")?;
        volume_label::require_expected_current(&before.label, &enrollment, desired)?;
        artifacts::save(output, "label-before.json", &before)?;
        let mut pair = request.pair.clone();
        pair.source = source.clone();
        let tree = shadow_tree::Tree {
            profile: "native-ordinary-tree-shadow-v2",
            objects: expected.objects,
            logical_bytes: expected.logical_bytes,
            internal_replacement_pending: expected.internal_replacement_pending,
        };
        let native_inputs = general_shadow::native_inputs(&tree);
        let same = |a: &[u8], b: &[u8]| {
            ntfs_attestation::same_security(a, b).map_err(std::io::Error::other)
        };
        phase = "strict-native-tree-before";
        let native_before = shadow_native::verify_general_converted_ordinary_with_label(
            pair.clone(),
            &native_inputs,
            &before.label,
            &same,
        )?;
        artifacts::save(output, "native-before.json", &native_before)?;
        phase = "label-restoration";
        let restored = volume_label::restore_verified_label(
            &request.pair.source,
            desired,
            source,
            &enrollment,
        )?;
        let restored_ok = restored.success;
        artifacts::save(output, "label-restoration.json", &restored)?;
        ensure!(
            restored_ok,
            "native source label restoration failed: {:?}",
            restored.error
        );
        phase = "strict-native-tree-after";
        let native_after = shadow_native::verify_general_converted_ordinary_with_label(
            pair,
            &native_inputs,
            desired,
            &same,
        )?;
        artifacts::save(output, "native-after.json", &native_after)?;
        let journal_after = observe_general_journal_file_with_profile(
            &journal,
            &request.journal,
            JournalProfile::from_schema(request.schema_version)?,
        )?;
        ensure!(
            journal_after.identity == observed.identity
                && journal_after.file_bytes == observed.file_bytes,
            "journal changed during native label completion"
        );
        lab_reconstruct::verify_refs_handoff_receipt(&mut journal, &ticket, &binding)?;
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({"schema_version":1,"kind":"native-only-post-handoff-label-completion",
            "success":true,"raw_replay_authorized":false,"raw_source_writes_issued":0,"disk_attributes_changed":false,
            "shadow_access_required":false,"desired_label":desired,"setter_called":restored.setter_called,
            "flushed":restored.flushed,"readback_matches":restored.readback_matches,"objects":tree.objects.len(),"events":events}),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({"schema_version":1,
        "kind":"native-only-label-completion-failure","phase":phase,"error":format!("{error:#}"),
        "raw_replay_authorized":false,"automatic_rollback_attempted":false}),
        )?;
        return Err(error);
    }
    Ok(())
}
