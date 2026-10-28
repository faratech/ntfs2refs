//! Recovery for an already activated conversion on the machine owning its disks.
use crate::{
    general_qualification as artifacts, general_reconstruct as protocol,
    lab_reconstruct::JournalTicket,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, GeneralJournaledPartition, NativeEvent,
    journal_file::{JournalProfile, observe_general_journal_file_with_profile},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[allow(
    dead_code,
    reason = "experimental composite restart entry awaits native qualification"
)]
mod compact;
#[allow(
    unused_imports,
    reason = "typed restart entry retained for owning-guest qualification"
)]
pub(crate) use compact::{
    ExperimentalCompactInputs, ExperimentalCompactOperation, recover_compact_experimental,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Resume,
    Rollback,
    RollbackAfterMarker,
    RollbackWithoutShadow,
    RollbackAfterMarkerWithoutShadow,
    Finalize,
    FinalizeAfterMarker,
}
impl Operation {
    /// Shadowless authority is deliberately limited to the NTFS rollback
    /// direction. Missing shadow storage never changes another operation.
    pub fn requires_shadow(self) -> bool {
        !matches!(
            self,
            Self::RollbackWithoutShadow | Self::RollbackAfterMarkerWithoutShadow
        )
    }
    fn needs_expectation(self) -> bool {
        matches!(self, Self::Finalize | Self::FinalizeAfterMarker)
    }
}
#[derive(Clone, Debug)]
pub struct Inputs {
    pub request: PathBuf,
    pub request_sha256: String,
    pub ticket: PathBuf,
    pub ticket_sha256: String,
    pub journal: PathBuf,
    pub expectation: Option<PathBuf>,
    pub expectation_sha256: Option<String>,
}
impl Inputs {
    pub fn validate(&self, operation: Operation) -> Result<()> {
        ensure!(
            canonical_pin(&self.request_sha256) && canonical_pin(&self.ticket_sha256),
            "request and ticket require canonical SHA-256 pins"
        );
        ensure!(
            self.expectation.is_some() == operation.needs_expectation()
                && self.expectation_sha256.is_some() == operation.needs_expectation(),
            "only finalize operations require the expectation and its pin"
        );
        if let Some(pin) = &self.expectation_sha256 {
            ensure!(canonical_pin(pin), "expectation SHA-256 pin is invalid");
        }
        Ok(())
    }
}
fn canonical_pin(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn pinned(path: &Path, expected: &str, limit: u64) -> Result<Vec<u8>> {
    ensure!(canonical_pin(expected), "invalid recovery input pin");
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && meta.file_attributes() & 0x400 == 0 && meta.len() <= limit,
        "recovery input is not a bounded ordinary file"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.file_attributes() & 0x400 == 0 && meta.len() <= limit,
        "opened recovery input differs"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit && hex::encode(Sha256::digest(&bytes)) == expected,
        "recovery input SHA-256 differs"
    );
    Ok(bytes)
}
fn save_bytes(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "recovery input copy exceeds bound"
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

/// Resume leaves the verified postimage offline. Rollback also completes the
/// exact NTFS restoration. Finalize closes rollback before the first ReFS mount.
pub fn recover(operation: Operation, inputs: &Inputs, output: &Path) -> Result<()> {
    inputs.validate(operation)?;
    let request_bytes = pinned(&inputs.request, &inputs.request_sha256, 131072)?;
    let request: protocol::Request = serde_json::from_slice(&request_bytes)?;
    request.validate()?;
    let ticket_bytes = pinned(&inputs.ticket, &inputs.ticket_sha256, 65536)?;
    let ticket: JournalTicket = serde_json::from_slice(&ticket_bytes)?;
    ensure!(
        ticket.schema_version == request.schema_version
            && ticket.binding.source_resource_profile == request.source_resource_profile,
        "recovery ticket and request journal profiles differ"
    );
    let expectation = match (&inputs.expectation, &inputs.expectation_sha256) {
        (Some(path), Some(pin)) => {
            ensure!(
                pin == &request.expected_tree_sha256,
                "expectation pin differs from request"
            );
            let bytes = pinned(path, pin, 16 * 1024 * 1024)?;
            let value: crate::shadow_tree::ExpectedTree = serde_json::from_slice(&bytes)?;
            value.validate_with_resource_profile(
                request.source_resource_profile.unwrap_or_default(),
            )?;
            Some(bytes)
        }
        (None, None) => None,
        _ => unreachable!(),
    };
    artifacts::create_output(output)?;
    save_bytes(output, "request.json", &request_bytes)?;
    save_bytes(output, "ticket.json", &ticket_bytes)?;
    if let Some(bytes) = &expectation {
        save_bytes(output, "expectation.json", bytes)?;
    }
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({"schema_version":1,"kind":"general-recovery-intent",
        "operation":operation,"request_sha256":inputs.request_sha256,"ticket_sha256":inputs.ticket_sha256,
        "expectation_sha256":inputs.expectation_sha256,"journal":inputs.journal,"shadow_access_required":operation.requires_shadow(),"fresh_apply_authorized":false}),
    )?;
    run(
        operation,
        inputs,
        output,
        &request,
        &ticket,
        expectation.as_deref(),
    )
}

fn run(
    operation: Operation,
    inputs: &Inputs,
    output: &Path,
    request: &protocol::Request,
    ticket: &JournalTicket,
    expectation: Option<&[u8]>,
) -> Result<()> {
    let mut phase = "journal-preflight";
    let attempted = (|| -> Result<()> {
        let meta = fs::symlink_metadata(&inputs.journal)?;
        ensure!(
            meta.is_file()
                && meta.file_attributes() & 0x400 == 0
                && meta.len() == ticket.journal_length
                && meta.len() <= request.max_journal_bytes,
            "journal is not the expected bounded ordinary file"
        );
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&inputs.journal)?;
        let identity = observe_general_journal_file_with_profile(
            &journal,
            &request.journal,
            JournalProfile::from_schema(request.schema_version)?,
        )?;
        artifacts::save(output, "journal-identity.json", &identity)?;
        phase = "reopen-excluded-disks";
        let mut events = Vec::<NativeEvent>::new();
        let mut target =
            GeneralJournaledPartition::reopen(request.pair.source.clone(), &mut events)?;
        ensure!(
            target.state(&mut events)?.disk_attributes == 1,
            "recovery requires an already activated offline target"
        );
        let mut shadow = if operation.requires_shadow() {
            let shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
            ensure!(
                shadow.state(&mut events)?.disk_attributes == 3,
                "recovery requires an excluded read-only shadow"
            );
            Some(shadow)
        } else {
            None
        };
        artifacts::save(output, "preflight-events.json", &events)?;
        events.clear();
        match operation {
            Operation::Resume | Operation::Rollback => {
                let shadow = shadow.as_mut().context("required shadow unavailable")?;
                phase = "journal-recovery";
                let mode = if operation == Operation::Resume {
                    protocol::RecoveryOperation::Resume
                } else {
                    protocol::RecoveryOperation::Rollback
                };
                let execution = protocol::recover(
                    mode,
                    request,
                    &mut target,
                    shadow,
                    &mut journal,
                    ticket,
                    &mut events,
                )?;
                artifacts::save(output, "execution.json", &execution)?;
                artifacts::save(output, "execution-events.json", &events)?;
                events.clear();
                ensure!(
                    execution.result.target_sha256 == execution.expected_target_sha256
                        && target.state(&mut events)?.disk_attributes == 1
                        && shadow.state(&mut events)?.disk_attributes == 3,
                    "recovery did not prove the expected complete excluded image"
                );
                if operation == Operation::Rollback {
                    phase = "rollback-completion";
                    let completed = protocol::complete_rollback(
                        request,
                        target,
                        shadow,
                        &mut journal,
                        ticket,
                        events,
                    )?;
                    artifacts::save(output, "completion.json", &completed)?;
                    ensure!(
                        completed.success
                            && completed.replay_closed
                            && completed.mounted_filesystem.as_deref() == Some("NTFS"),
                        "NTFS rollback completion refused: {:?}",
                        completed.error
                    );
                } else {
                    artifacts::save(output, "completion-events.json", &events)?;
                }
            }
            Operation::RollbackAfterMarker => {
                let shadow = shadow.as_mut().context("required shadow unavailable")?;
                phase = "rollback-after-marker";
                let completed = protocol::resume_completed_rollback(
                    request,
                    target,
                    shadow,
                    &mut journal,
                    ticket,
                    events,
                )?;
                artifacts::save(output, "completion.json", &completed)?;
                ensure!(
                    completed.success
                        && completed.replay_closed
                        && completed.mounted_filesystem.as_deref() == Some("NTFS"),
                    "completed rollback marker could not be finalized: {:?}",
                    completed.error
                );
            }
            Operation::Finalize | Operation::FinalizeAfterMarker => {
                let shadow = shadow.as_mut().context("required shadow unavailable")?;
                phase = "refs-handoff";
                let expected = expectation.context("finalize expectation absent")?;
                let mut completed = if operation == Operation::Finalize {
                    protocol::finalize(request, target, shadow, &mut journal, ticket, expected)?
                } else {
                    protocol::finalize_after_marker(
                        request,
                        target,
                        shadow,
                        &mut journal,
                        ticket,
                        expected,
                    )?
                };
                completed.events.splice(0..0, events);
                artifacts::save(output, "completion.json", &completed)?;
                ensure!(
                    completed.success && completed.rollback_closed && completed.native.is_some(),
                    "ReFS handoff verification refused; do not reopen rollback: {:?}",
                    completed.error
                );
            }
            Operation::RollbackWithoutShadow => {
                phase = "journal-only-rollback";
                let execution = protocol::rollback_without_shadow(
                    request,
                    &mut target,
                    &mut journal,
                    ticket,
                    &mut events,
                )?;
                artifacts::save(output, "execution.json", &execution)?;
                artifacts::save(output, "execution-events.json", &events)?;
                events.clear();
                ensure!(
                    execution.result.target_sha256 == execution.expected_target_sha256
                        && execution.expected_target_sha256 == request.comparison.source_sha256
                        && !execution.shadow_available
                        && target.state(&mut events)?.disk_attributes == 1,
                    "shadowless rollback did not prove the complete excluded NTFS image"
                );
                phase = "journal-only-rollback-completion";
                let completed = protocol::complete_rollback_without_shadow(
                    request,
                    target,
                    &mut journal,
                    ticket,
                    events,
                )?;
                artifacts::save(output, "completion.json", &completed)?;
                ensure!(
                    completed.success
                        && completed.replay_closed
                        && !completed.shadow_available
                        && completed.mounted_filesystem.as_deref() == Some("NTFS"),
                    "shadowless NTFS rollback completion refused: {:?}",
                    completed.error
                );
            }
            Operation::RollbackAfterMarkerWithoutShadow => {
                phase = "journal-only-rollback-after-marker";
                let completed = protocol::resume_completed_rollback_without_shadow(
                    request,
                    target,
                    &mut journal,
                    ticket,
                    events,
                )?;
                artifacts::save(output, "completion.json", &completed)?;
                ensure!(
                    completed.success
                        && completed.replay_closed
                        && !completed.shadow_available
                        && completed.mounted_filesystem.as_deref() == Some("NTFS"),
                    "shadowless completed rollback marker could not be finalized: {:?}",
                    completed.error
                );
            }
        }
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({"schema_version":1,"kind":"general-recovery",
            "success":true,"operation":operation,"fresh_apply_authorized":false,
            "shadow_access_required":operation.requires_shadow(),
            "target_remains_offline":operation == Operation::Resume,
            "rollback_closed":matches!(operation,Operation::Finalize|Operation::FinalizeAfterMarker),
            "ntfs_rollback_completed":matches!(operation,Operation::Rollback|Operation::RollbackAfterMarker|Operation::RollbackWithoutShadow|Operation::RollbackAfterMarkerWithoutShadow)}),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({"schema_version":1,"kind":"general-recovery-failure",
            "operation":operation,"phase":phase,"error":format!("{error:#}"),"shadow_access_required":operation.requires_shadow(),"automatic_fallback_attempted":false}),
        )?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inputs() -> Inputs {
        Inputs {
            request: "request.json".into(),
            request_sha256: "a".repeat(64),
            ticket: "ticket.json".into(),
            ticket_sha256: "b".repeat(64),
            journal: "journal.bin".into(),
            expectation: None,
            expectation_sha256: None,
        }
    }
    #[test]
    fn finalize_requires_both_expectation_and_canonical_pin() {
        let mut value = inputs();
        value.validate(Operation::Resume).unwrap();
        value.validate(Operation::Rollback).unwrap();
        value.validate(Operation::RollbackAfterMarker).unwrap();
        assert!(value.validate(Operation::Finalize).is_err());
        value.expectation = Some("tree.json".into());
        assert!(value.validate(Operation::Finalize).is_err());
        value.expectation_sha256 = Some("c".repeat(64));
        value.validate(Operation::Finalize).unwrap();
        value.validate(Operation::FinalizeAfterMarker).unwrap();
        assert!(value.validate(Operation::Resume).is_err());
        value.expectation_sha256 = Some("C".repeat(64));
        assert!(value.validate(Operation::Finalize).is_err());
    }
    #[test]
    fn shadowless_authority_is_explicit_and_cannot_supply_forward_expectations() {
        for operation in [
            Operation::Resume,
            Operation::Rollback,
            Operation::RollbackAfterMarker,
            Operation::Finalize,
            Operation::FinalizeAfterMarker,
        ] {
            assert!(operation.requires_shadow());
        }
        for operation in [
            Operation::RollbackWithoutShadow,
            Operation::RollbackAfterMarkerWithoutShadow,
        ] {
            assert!(!operation.requires_shadow());
            let mut value = inputs();
            value.validate(operation).unwrap();
            value.expectation = Some("tree.json".into());
            value.expectation_sha256 = Some("c".repeat(64));
            assert!(value.validate(operation).is_err());
        }
        assert_eq!(
            serde_json::to_value(Operation::RollbackWithoutShadow).unwrap(),
            "rollback_without_shadow"
        );
        assert_eq!(
            serde_json::to_value(Operation::RollbackAfterMarkerWithoutShadow).unwrap(),
            "rollback_after_marker_without_shadow"
        );
    }
    #[test]
    fn pinned_inputs_refuse_changed_bytes_size_and_noncanonical_pins() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        fs::write(&path, b"payload").unwrap();
        let pin = hex::encode(Sha256::digest(b"payload"));
        assert_eq!(pinned(&path, &pin, 7).unwrap(), b"payload");
        assert!(pinned(&path, &pin, 6).is_err());
        assert!(pinned(&path, &pin.to_uppercase(), 7).is_err());
        fs::write(&path, b"changed").unwrap();
        assert!(pinned(&path, &pin, 7).is_err());
        assert!(pinned(directory.path(), &pin, 7).is_err());
    }
    #[test]
    fn invalid_inputs_never_create_output_or_open_a_device() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output");
        let mut value = inputs();
        value.request_sha256 = "invalid".into();
        for operation in [
            Operation::Resume,
            Operation::RollbackWithoutShadow,
            Operation::RollbackAfterMarkerWithoutShadow,
        ] {
            assert!(recover(operation, &value, &output).is_err());
            assert!(!output.exists());
        }
    }
    #[test]
    fn mismatched_expectation_is_refused_before_output_or_native_access() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let disk = |number: u32, id: &str, volume: &str, bytes: u64| {
            serde_json::json!({"disk_number":number,"volume_guid":volume,
            "identity":{"disk_guid":id,"partition_guid":volume,"partition_number":2,"disk_bytes":bytes,
                "partition_offset":16u64<<20,"partition_bytes":if number==2 {bytes-(32<<20)}else{52u64<<30},
                "logical_sector_bytes":512,"physical_sector_bytes":4096}})
        };
        let request = serde_json::json!({"schema_version":1,"experiment_id":"a".repeat(32),"expected_tree_sha256":"c".repeat(64),
            "pair":{"source":disk(1,"11111111-1111-1111-1111-111111111111","12121212-1212-1212-1212-121212121212",64<<30),
                "shadow":disk(3,"33333333-3333-3333-3333-333333333333","34343434-3434-3434-3434-343434343434",64<<30)},
            "comparison":{"schema_version":2,"sector_size":4096,"expected_length":52u64<<30,"source_sha256":"a".repeat(64),
                "shadow_sha256":"b".repeat(64),"retained_ranges":[],"max_change_bytes":4096,"max_ranges":65536},
            "journal":{"disk":disk(2,"22222222-2222-2222-2222-222222222222","23232323-2323-2323-2323-232323232323",8<<30),
                "externally_enrolled_disk_unique_id":"test-journal","allow_additional_partitions":false},"max_journal_bytes":768u64<<20});
        let ticket = serde_json::json!({"schema_version":1,"binding":{"experiment_id":"a".repeat(32),
            "target_identity_sha256":"a".repeat(64),"shadow_identity_sha256":"b".repeat(64),"journal_identity_sha256":"d".repeat(64)},
            "immutable_sha256":"e".repeat(64),"immutable_length":4096,"journal_length":12288});
        let request_bytes = serde_json::to_vec(&request).unwrap();
        let ticket_bytes = serde_json::to_vec(&ticket).unwrap();
        fs::write(root.join("request.json"), &request_bytes).unwrap();
        fs::write(root.join("ticket.json"), &ticket_bytes).unwrap();
        let inputs = Inputs {
            request: root.join("request.json"),
            request_sha256: hex::encode(Sha256::digest(&request_bytes)),
            ticket: root.join("ticket.json"),
            ticket_sha256: hex::encode(Sha256::digest(&ticket_bytes)),
            journal: root.join("absent-journal"),
            expectation: Some(root.join("absent-expectation")),
            expectation_sha256: Some("f".repeat(64)),
        };
        let output = root.join("output");
        let error = recover(Operation::Finalize, &inputs, &output).unwrap_err();
        assert!(
            error.to_string().contains("expectation pin differs"),
            "{error:#}"
        );
        assert!(!output.exists());
    }
}
