//! Experimental recovery of an already activated compact conversion. No
//! operation can activate a frozen source, apply a new plan, manufacture a
//! SourceCertificate or promote a capture report into source admission.
use super::*;
use crate::refs_hybrid::delta::VerifiedDeltaArtifact;
use n2r_win32::reference_file::{self, ReferenceFileSnapshot};
use std::{fs::File, path::Component, time::SystemTime};

fn announce_recovery_phase(operation: ExperimentalCompactOperation, message: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "Recovery {operation:?}: {message}");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentalCompactOperation {
    /// Finish journal writes, leaving the exact ReFS image offline and unmounted.
    Resume,
    /// Restore the complete original, close replay with ABT, then verify NTFS.
    Rollback,
    /// Verify a complete unmarked ReFS result, write HND, then mount and verify.
    Finalize,
    /// Recheck an existing complete HND and its durability before native mount.
    FinalizeAfterMarker,
    /// Recheck an existing complete ABT and its durability before NTFS mount.
    FinalizeRollback,
}

#[derive(Clone, Debug)]
pub struct ExperimentalCompactInputs {
    pub request: PathBuf,
    pub request_sha256: String,
    pub ticket: PathBuf,
    pub ticket_sha256: String,
    pub journal: PathBuf,
    pub capture: PathBuf,
    pub capture_sha256: String,
    pub packed: PathBuf,
    pub packed_sha256: String,
    pub expectation: PathBuf,
    pub expectation_sha256: String,
}
impl ExperimentalCompactInputs {
    /// Public CLI routing from an actual journal, while the engine retains its
    /// exclusive handle. A committed marker can select completion only.
    pub(crate) fn recover_offline_by_lifecycle(
        &self,
        rollback: bool,
        output: &Path,
    ) -> Result<ExperimentalCompactOperation> {
        let requested = if rollback {
            ExperimentalCompactOperation::Rollback
        } else {
            ExperimentalCompactOperation::Resume
        };
        recover_compact_impl(requested, self, output, true)
    }

    /// A successful Resume left an unmarked offline image. Recheck lifecycle
    /// under the next exclusive journal lease before writing its first HND.
    pub(crate) fn finalize_offline_after_resume(&self, output: &Path) -> Result<()> {
        recover_compact_impl(ExperimentalCompactOperation::Finalize, self, output, true).map(|_| ())
    }

    fn validate(&self) -> Result<()> {
        for pin in [
            &self.request_sha256,
            &self.ticket_sha256,
            &self.capture_sha256,
            &self.packed_sha256,
            &self.expectation_sha256,
        ] {
            ensure!(
                canonical_pin(pin),
                "compact recovery requires canonical input SHA-256 pins"
            );
        }
        for path in [
            &self.request,
            &self.ticket,
            &self.journal,
            &self.capture,
            &self.packed,
            &self.expectation,
        ] {
            ensure!(
                path.is_absolute()
                    && !path
                        .components()
                        .any(|part| matches!(part, Component::ParentDir)),
                "compact recovery requires absolute paths without parent traversal"
            );
        }
        Ok(())
    }
}

/// The exact input handles stay open throughout recovery. A path, JSON flag or
/// hash of a different reopened file does not replace these held-file pins.
struct HeldInput {
    file: File,
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    bytes: Vec<u8>,
    sha256: String,
}
impl HeldInput {
    fn open(path: &Path, expected: &str, limit: u64) -> Result<Self> {
        ensure!(
            canonical_pin(expected),
            "invalid compact recovery input pin"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let snapshot = reference_file::observe_reference_file_handle(&file)?;
        ensure!(
            snapshot.file_bytes <= limit && snapshot.number_of_links == 1,
            "compact recovery input exceeds its bound or has additional links"
        );
        let modified = file.metadata()?.modified()?;
        let mut bytes = Vec::new();
        (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == snapshot.file_bytes
                && bytes.len() as u64 <= limit
                && hex::encode(Sha256::digest(&bytes)) == expected,
            "held compact recovery input length or SHA-256 differs"
        );
        let mut held = Self {
            file,
            snapshot,
            modified,
            bytes,
            sha256: expected.into(),
        };
        held.revalidate()?;
        Ok(held)
    }
    fn revalidate(&mut self) -> Result<()> {
        ensure!(
            reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "held compact recovery input identity or metadata changed"
        );
        let hash = hex::encode(n2r_win32::sha256_native::hash_range(
            &mut self.file,
            0,
            self.snapshot.file_bytes,
        )?);
        ensure!(
            hash == self.sha256
                && reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "held compact recovery input changed during rehash"
        );
        Ok(())
    }
}

/// Resume/rollback are authorized by the trusted ticket, actual enrolled
/// journal identity and already activated device state. Existing compact
/// protocol gates independently recheck complete immutable contents, exact
/// delta coverage, normalized original bytes and candidate image hashes before
/// writing. Serialized source-admitted/success booleans are never authority.
pub fn recover_compact_experimental(
    operation: ExperimentalCompactOperation,
    inputs: &ExperimentalCompactInputs,
    output: &Path,
) -> Result<()> {
    recover_compact_impl(operation, inputs, output, false).map(|_| ())
}

fn recover_compact_impl(
    operation: ExperimentalCompactOperation,
    inputs: &ExperimentalCompactInputs,
    output: &Path,
    select_lifecycle: bool,
) -> Result<ExperimentalCompactOperation> {
    inputs.validate()?;
    announce_recovery_phase(operation, "checking original input and backing hashes");
    let mut request_input = HeldInput::open(&inputs.request, &inputs.request_sha256, 131072)?;
    let request: protocol::Request = serde_json::from_slice(&request_input.bytes)?;
    request.validate()?;
    let mut ticket_input = HeldInput::open(&inputs.ticket, &inputs.ticket_sha256, 65536)?;
    let ticket: JournalTicket = serde_json::from_slice(&ticket_input.bytes)?;
    ensure!(
        ticket.schema_version == request.schema_version
            && ticket.binding.source_resource_profile == request.source_resource_profile,
        "compact recovery request and ticket profiles differ"
    );
    ensure!(
        inputs.expectation_sha256 == request.expected_tree_sha256,
        "compact recovery expectation pin differs from request"
    );
    let mut expectation_input = HeldInput::open(
        &inputs.expectation,
        &inputs.expectation_sha256,
        16 * 1024 * 1024,
    )?;
    let expectation: crate::shadow_tree::ExpectedTree =
        serde_json::from_slice(&expectation_input.bytes)?;
    expectation
        .validate_with_resource_profile(request.source_resource_profile.unwrap_or_default())?;
    let mut artifact = VerifiedDeltaArtifact::open(
        &inputs.capture,
        &inputs.capture_sha256,
        &inputs.packed,
        request.comparison.expected_length,
        request.comparison.max_change_bytes,
    )?;
    ensure!(
        artifact.pins().packed_sha256 == inputs.packed_sha256,
        "compact recovery packed hash differs from the independent input pin"
    );
    let captured: serde_json::Value = serde_json::from_slice(artifact.report_bytes())?;
    ensure!(
        captured["kind"] == "frozen-composite-target-capture"
            && captured["pair"] == serde_json::to_value(&request.pair)?
            && captured["source_sha256"] == request.comparison.source_sha256
            && captured["composite_target_sha256"] == request.comparison.shadow_sha256
            && captured["expected_tree_sha256"] == request.expected_tree_sha256
            && captured["source_resource_profile"]
                == serde_json::to_value(request.source_resource_profile.unwrap_or_default())?
            && artifact.pins().selected_bytes_compared == request.comparison.expected_length,
        "compact recovery capture does not bind the complete requested source-backed image"
    );
    drop(captured);
    // Source/target volumes cannot supply recovery metadata that must remain
    // available while the source stays excluded or transitions to a native mount.
    for held in [&request_input, &ticket_input, &expectation_input] {
        for binding in [&request.pair.source, &request.pair.shadow] {
            ensure!(
                !held
                    .snapshot
                    .final_path
                    .to_ascii_lowercase()
                    .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
                "compact recovery inputs must be outside the two data volumes"
            );
        }
    }
    let artifact_identity = artifact.identity_sha256()?;
    artifacts::create_output(output)?;
    save_bytes(output, "request.json", &request_input.bytes)?;
    save_bytes(output, "ticket.json", &ticket_input.bytes)?;
    save_bytes(output, "expectation.json", &expectation_input.bytes)?;
    artifacts::save(
        output,
        "input-identities.json",
        &serde_json::json!({
            "request":request_input.snapshot,"ticket":ticket_input.snapshot,
            "expectation":expectation_input.snapshot,"compact_artifact":artifact.pins(),
            "artifact_identity_sha256":artifact_identity,
        }),
    )?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({
            "schema_version":1,"kind":"experimental-compact-recovery-intent",
            "operation":operation,"request_sha256":inputs.request_sha256,
            "ticket_sha256":inputs.ticket_sha256,"capture":inputs.capture,
            "capture_sha256":inputs.capture_sha256,"packed":inputs.packed,
            "packed_sha256":inputs.packed_sha256,"expectation_sha256":inputs.expectation_sha256,
            "journal":inputs.journal,"fresh_apply_authorized":false,
            "source_admitted":false,"general_conversion_qualified":false,
        }),
    )?;
    let mut phase = "compact-journal-preflight";
    let mut effective_operation = operation;
    let attempted = (|| -> Result<()> {
        announce_recovery_phase(
            operation,
            "checking journal identity and frozen device state",
        );
        let metadata = fs::symlink_metadata(&inputs.journal)?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() == ticket.journal_length
                && metadata.len() <= request.max_journal_bytes,
            "compact journal is not the expected bounded ordinary file"
        );
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&inputs.journal)?;
        let observed = observe_general_journal_file_with_profile(
            &journal,
            &request.journal,
            JournalProfile::from_schema(request.schema_version)?,
        )?;
        ensure!(
            observed.file_bytes == ticket.journal_length,
            "opened compact journal length differs from pinned ticket"
        );
        artifacts::save(output, "journal-identity.json", &observed)?;
        // Public automatic routing observes the same journal held exclusively
        // below. Explicit experimental operations keep their existing path.
        let operation = if select_lifecycle {
            use crate::lab_reconstruct::{JournalLifecycle, inspect_journal_lifecycle};
            phase = "compact-journal-lifecycle";
            // Use the same binding implementation as preparation/execution:
            // native shadow AND held compact artifact identity are mandatory.
            let bound =
                protocol::compact_binding(&request, &observed.identity, &artifact_identity)?;
            let (lifecycle, descriptor) =
                inspect_journal_lifecycle(&mut journal, &ticket, &bound, &request.comparison)?;
            let ranges: Vec<_> = descriptor
                .patches
                .iter()
                .map(|p| (p.offset, p.length))
                .collect();
            artifact.layout().require_exact_write_ranges(&ranges)?;
            let selected = match lifecycle {
                JournalLifecycle::PreparedClear
                | JournalLifecycle::ApplyIntent
                | JournalLifecycle::RollbackIntent => operation,
                JournalLifecycle::RefsHandoff => {
                    ensure!(
                        operation == ExperimentalCompactOperation::Resume,
                        "ReFS handoff is committed; raw replay, rollback and a new handoff are closed"
                    );
                    ExperimentalCompactOperation::FinalizeAfterMarker
                }
                JournalLifecycle::NtfsRollback => {
                    ensure!(
                        operation == ExperimentalCompactOperation::Rollback,
                        "NTFS rollback is committed; ReFS resume is closed; use --rollback to finalize NTFS"
                    );
                    ExperimentalCompactOperation::FinalizeRollback
                }
            };
            artifacts::save(
                output,
                "lifecycle-selection.json",
                &serde_json::json!({
                    "requested_operation":operation,"observed_lifecycle":lifecycle,
                    "selected_operation":selected,"journal_handle_held_exclusively":true,
                    "serialized_selection_grants_authority":false,
                }),
            )?;
            selected
        } else {
            operation
        };
        effective_operation = operation;
        phase = "reopen-activated-compact-disks";
        let mut events = Vec::<NativeEvent>::new();
        let mut target =
            GeneralJournaledPartition::reopen(request.pair.source.clone(), &mut events)?;
        let shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
        ensure!(
            target.state(&mut events)?.disk_attributes == 1
                && shadow.state(&mut events)?.disk_attributes == 3,
            "compact recovery requires an already activated offline target and frozen native shadow"
        );
        artifacts::save(output, "preflight-events.json", &events)?;
        events.clear();
        request_input.revalidate()?;
        ticket_input.revalidate()?;
        expectation_input.revalidate()?;
        artifact.revalidate()?;
        match operation {
            ExperimentalCompactOperation::Resume | ExperimentalCompactOperation::Rollback => {
                phase = "compact-journal-recovery";
                announce_recovery_phase(
                    operation,
                    "scanning complete images and applying journaled recovery patches",
                );
                let mode = if operation == ExperimentalCompactOperation::Resume {
                    protocol::RecoveryOperation::Resume
                } else {
                    protocol::RecoveryOperation::Rollback
                };
                let execution = protocol::compact::execute(
                    mode,
                    &request,
                    &mut target,
                    &shadow,
                    &mut artifact,
                    &mut journal,
                    &ticket,
                    &mut events,
                    None,
                )?;
                artifacts::save(output, "execution.json", &execution)?;
                artifacts::save(output, "execution-events.json", &events)?;
                events.clear();
                ensure!(
                    execution.result.target_sha256 == execution.expected_target_sha256
                        && target.state(&mut events)?.disk_attributes == 1
                        && shadow.state(&mut events)?.disk_attributes == 3,
                    "compact recovery did not prove the complete excluded result"
                );
                if operation == ExperimentalCompactOperation::Rollback {
                    phase = "compact-rollback-completion";
                    announce_recovery_phase(
                        operation,
                        "closing replay and checking the restored NTFS filesystem",
                    );
                    let completed = protocol::compact_finalize::complete_rollback(
                        &request,
                        target,
                        &shadow,
                        &mut artifact,
                        &mut journal,
                        &ticket,
                        events,
                    )?;
                    artifacts::save(output, "completion.json", &completed)?;
                    ensure!(
                        completed.success
                            && completed.replay_closed
                            && completed.mounted_filesystem.as_deref() == Some("NTFS"),
                        "compact NTFS rollback completion refused: {:?}",
                        completed.error
                    );
                } else {
                    artifacts::save(output, "completion-events.json", &events)?;
                }
            }
            ExperimentalCompactOperation::Finalize
            | ExperimentalCompactOperation::FinalizeAfterMarker => {
                phase = "compact-refs-handoff";
                announce_recovery_phase(
                    operation,
                    "verifying ReFS handoff and mounted file contents",
                );
                let mut completed = if operation == ExperimentalCompactOperation::Finalize {
                    protocol::compact_finalize::finalize(
                        &request,
                        target,
                        &shadow,
                        &mut artifact,
                        &mut journal,
                        &ticket,
                        &expectation_input.bytes,
                    )?
                } else {
                    protocol::compact_finalize::finalize_after_marker(
                        &request,
                        target,
                        &shadow,
                        &mut artifact,
                        &mut journal,
                        &ticket,
                        &expectation_input.bytes,
                    )?
                };
                completed.events.splice(0..0, events);
                artifacts::save(output, "completion.json", &completed)?;
                ensure!(
                    completed.success && completed.rollback_closed && completed.native.is_some(),
                    "compact ReFS handoff refused; rollback must stay closed: {:?}",
                    completed.error
                );
            }
            ExperimentalCompactOperation::FinalizeRollback => {
                phase = "compact-rollback-after-marker";
                announce_recovery_phase(operation, "checking the completed NTFS rollback");
                let completed = protocol::compact_finalize::resume_completed_rollback(
                    &request,
                    target,
                    &shadow,
                    &mut artifact,
                    &mut journal,
                    &ticket,
                    events,
                )?;
                artifacts::save(output, "completion.json", &completed)?;
                ensure!(
                    completed.success
                        && completed.replay_closed
                        && completed.mounted_filesystem.as_deref() == Some("NTFS"),
                    "completed compact rollback could not be finalized: {:?}",
                    completed.error
                );
            }
        }
        request_input.revalidate()?;
        ticket_input.revalidate()?;
        expectation_input.revalidate()?;
        artifact.revalidate()?;
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({
                "schema_version":1,"kind":"experimental-compact-recovery","success":true,
                "operation":operation,"fresh_apply_authorized":false,"source_admitted":false,
                "target_remains_offline":operation==ExperimentalCompactOperation::Resume,
                "rollback_closed":matches!(operation,ExperimentalCompactOperation::Finalize
                    |ExperimentalCompactOperation::FinalizeAfterMarker),
                "ntfs_rollback_completed":matches!(operation,ExperimentalCompactOperation::Rollback
                    |ExperimentalCompactOperation::FinalizeRollback),
                "artifact_identity_sha256":artifact_identity,"general_conversion_qualified":false,
            }),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({
                "schema_version":1,"kind":"experimental-compact-recovery-failure",
                "operation":operation,"phase":phase,"error":format!("{error:#}"),
                "automatic_fallback_attempted":false,"fresh_apply_authorized":false,
                "completion_state_must_be_inspected":true,
            }),
        )?;
        return Err(error);
    }
    Ok(effective_operation)
}
