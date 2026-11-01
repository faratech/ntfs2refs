//! Recovery of an interrupted allocation-bounded conversion from its pinned
//! bundle and self-contained selected-range journal. The bundle locates inputs
//! only; the journal lifecycle, its complete immutable checks and the activated
//! device state authorize recovery. No fresh apply or certificate is possible.
use super::{compact::HeldInput, *};
use crate::selected_journal::{self as sj, SelectedLifecycle, SelectedPlan, SelectedTicket};
use n2r_win32::{
    WritePolicy, general_layout::GeneralDiskBinding, mounted_filesystem_general,
    rediscover_general_volume_wait, volume_label::VolumeLabel,
};
use serde::Deserialize;
use std::path::Component;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: u32,
    kind: String,
    request: Pin,
    plan: Pin,
    ticket: Pin,
    expectation: Pin,
    verification: Pin,
    #[serde(default)]
    recovery_payload_manifest: Option<Pin>,
    journal: PathBuf,
    source: GeneralDiskBinding,
    serialized_bundle_grants_recovery_authority: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verification {
    expected_mount_paths: Vec<String>,
    expected_source_label: VolumeLabel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationRecoveryOutcome {
    RefsCompleted,
    NtfsRestored,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Resume,
    VerifyHandoff,
    Rollback,
    Abandon,
    VerifyAborted,
}

fn ordinary_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
}

fn open_bundle(bundle_path: &Path, bundle_sha256: &str) -> Result<(HeldInput, Bundle)> {
    ensure!(
        ordinary_absolute(bundle_path),
        "allocation recovery bundle path must be absolute without traversal"
    );
    let held = HeldInput::open(bundle_path, bundle_sha256, 65536)?;
    let bundle: Bundle = serde_json::from_slice(&held.bytes)?;
    ensure!(
        bundle.schema_version == 1
            && bundle.kind == "allocation-bounded-recovery-bundle"
            && !bundle.serialized_bundle_grants_recovery_authority,
        "not an allocation-bounded recovery bundle"
    );
    for path in [
        &bundle.request.path,
        &bundle.plan.path,
        &bundle.ticket.path,
        &bundle.expectation.path,
        &bundle.verification.path,
        &bundle.journal,
    ]
    .into_iter()
    .chain(bundle.recovery_payload_manifest.iter().map(|pin| &pin.path))
    {
        ensure!(
            ordinary_absolute(path),
            "allocation recovery inputs need absolute paths without traversal"
        );
    }
    Ok((held, bundle))
}

/// The pinned source route, for display before the operator confirms. Recovery
/// itself reopens and rechecks every input.
pub fn preview_allocation(bundle_path: &Path, bundle_sha256: &str) -> Result<GeneralDiskBinding> {
    Ok(open_bundle(bundle_path, bundle_sha256)?.1.source)
}

pub fn recover_allocation(
    bundle_path: &Path,
    bundle_sha256: &str,
    rollback: bool,
    output: &Path,
) -> Result<AllocationRecoveryOutcome> {
    let (mut bundle_input, bundle) = open_bundle(bundle_path, bundle_sha256)?;
    let mut request_input = HeldInput::open(&bundle.request.path, &bundle.request.sha256, 131072)?;
    let request: crate::general_conversion::Request = serde_json::from_slice(&request_input.bytes)?;
    request.validate()?;
    request
        .source_resource_profile
        .unwrap_or_default()
        .count_admission()?;
    ensure!(
        request.pair.source == bundle.source,
        "bundle source differs from its pinned request"
    );
    let mut plan_input = HeldInput::open(&bundle.plan.path, &bundle.plan.sha256, 16 * 1024 * 1024)?;
    let plan: SelectedPlan = serde_json::from_slice(&plan_input.bytes)?;
    let (selected_bytes, journal_bytes) = plan.validate()?;
    request.validate_selected_capacity(&plan)?;
    let old_zero_bytes = plan.old_zero_bytes()?;
    let source_free_bytes = plan.source_free_bytes()?;
    let mut ticket_input = HeldInput::open(&bundle.ticket.path, &bundle.ticket.sha256, 65536)?;
    let ticket: SelectedTicket = serde_json::from_slice(&ticket_input.bytes)?;
    ensure!(
        ticket.selected_bytes == selected_bytes
            && ticket.journal_length == journal_bytes
            && journal_bytes <= request.max_journal_bytes
            && plan.max_journal_bytes == request.max_journal_bytes
            && plan.image_length == request.pair.source.identity.partition_bytes
            && !ticket.whole_image_verified,
        "allocation recovery ticket, plan and request differ"
    );
    let mut expectation_input = HeldInput::open(
        &bundle.expectation.path,
        &bundle.expectation.sha256,
        16 * 1024 * 1024,
    )?;
    let expectation: crate::shadow_tree::ExpectedTree =
        serde_json::from_slice(&expectation_input.bytes)?;
    expectation
        .validate_with_resource_profile(request.source_resource_profile.unwrap_or_default())?;
    ensure!(
        !expectation.has_extent_only_streams() || request.verification_policy.is_fast(),
        "hash-free recovery expectation requires the explicit fast verification policy"
    );
    let needs_payload_manifest =
        request.verification_policy.is_fast() && expectation.has_extent_only_streams();
    ensure!(
        bundle.recovery_payload_manifest.is_some() == needs_payload_manifest,
        "recovery payload manifest must match the fast hash-free expectation profile"
    );
    let mut recovery_payload_input = bundle
        .recovery_payload_manifest
        .as_ref()
        .map(|pin| HeldInput::open(&pin.path, &pin.sha256, 64 * 1024 * 1024))
        .transpose()?;
    let recovery_payload_proof = recovery_payload_input
        .as_ref()
        .map(|held| {
            protocol::fast_verification::RecoveryPayloadProof::from_pinned_manifest(
                &held.bytes,
                &request.pair.source,
                &expectation,
                &plan,
                &ticket,
                request.source_resource_profile.unwrap_or_default(),
            )
        })
        .transpose()?;
    let mut verification_input = HeldInput::open(
        &bundle.verification.path,
        &bundle.verification.sha256,
        65536,
    )?;
    let verification: Verification = serde_json::from_slice(&verification_input.bytes)?;
    // Recovery metadata cannot live on a volume that must stay excluded or that
    // transitions to a native mount during recovery.
    for held in [
        &bundle_input,
        &request_input,
        &plan_input,
        &ticket_input,
        &expectation_input,
        &verification_input,
    ]
    .into_iter()
    .chain(recovery_payload_input.iter())
    {
        for binding in [&request.pair.source, &request.pair.shadow] {
            ensure!(
                !held
                    .snapshot
                    .final_path
                    .to_ascii_lowercase()
                    .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
                "allocation recovery inputs must be outside the two data volumes"
            );
        }
    }
    artifacts::create_output(output)?;
    save_bytes(output, "bundle.json", &bundle_input.bytes)?;
    save_bytes(output, "request.json", &request_input.bytes)?;
    save_bytes(output, "selected-plan.json", &plan_input.bytes)?;
    save_bytes(output, "selected-ticket.json", &ticket_input.bytes)?;
    if let Some(held) = &recovery_payload_input {
        save_bytes(output, "recovery-payload-manifest.json", &held.bytes)?;
    }
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({
            "schema_version":1,"kind":"allocation-bounded-recovery-intent",
            "rollback_requested":rollback,"bundle":bundle_path,"bundle_sha256":bundle_sha256,
            "journal":bundle.journal,"fresh_apply_authorized":false,"source_admitted":false,
            "general_conversion_qualified":false,
        }),
    )?;
    let mut phase = "selected-journal-preflight";
    let attempted = (|| -> Result<AllocationRecoveryOutcome> {
        let metadata = fs::symlink_metadata(&bundle.journal)?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() == ticket.journal_length,
            "selected journal is not the expected bounded ordinary file"
        );
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&bundle.journal)?;
        let profile = request.journal_profile()?;
        let observed =
            observe_general_journal_file_with_profile(&journal, &request.journal, profile)?;
        ensure!(
            observed.file_bytes == ticket.journal_length,
            "opened selected journal length differs from the pinned ticket"
        );
        artifacts::save(output, "journal-identity.json", &observed)?;
        phase = "selected-journal-lifecycle";
        // Authenticate the actual share-zero journal once before reopening the
        // target. The opaque owner keeps this exact mutable journal borrow
        // through action selection, pin revalidation and replay completion.
        // It supplies no exclusion claim about the independently reopened target.
        let recovery_journal = sj::authenticate_recovery_exclusive(&mut journal, &plan, &ticket)?;
        let state = recovery_journal.lifecycle();
        let action = match (state, rollback) {
            (SelectedLifecycle::ApplyIntent, false) => Action::Resume,
            (SelectedLifecycle::Handoff, false) => Action::VerifyHandoff,
            (SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent, true) => {
                Action::Rollback
            }
            (SelectedLifecycle::PreparedClear, true) => Action::Abandon,
            (SelectedLifecycle::Aborted, true) => Action::VerifyAborted,
            (SelectedLifecycle::PreparedClear, false) => anyhow::bail!(
                "the interrupted apply never recorded its intent; resuming would be a fresh apply that needs the original live certificate. Use --rollback to close it"
            ),
            (SelectedLifecycle::RollbackIntent | SelectedLifecycle::Aborted, false) => {
                anyhow::bail!(
                    "NTFS rollback is in progress or committed; ReFS resume is closed. Use --rollback"
                )
            }
            (SelectedLifecycle::Handoff, true) => {
                anyhow::bail!("ReFS handoff is committed; raw replay and rollback are closed")
            }
        };
        artifacts::save(
            output,
            "lifecycle-selection.json",
            &serde_json::json!({
                "observed_lifecycle":state,"rollback_requested":rollback,"selected_action":action,
                "journal_handle_held_exclusively":true,
                "serialized_selection_grants_authority":false,
            }),
        )?;
        phase = "reopen-activated-source";
        let mut events = Vec::<NativeEvent>::new();
        let mut target =
            GeneralJournaledPartition::reopen(request.pair.source.clone(), &mut events)?;
        ensure!(
            target.state(&mut events)?.disk_attributes == 1,
            "allocation recovery requires the already activated offline source"
        );
        for held in [
            &mut bundle_input,
            &mut request_input,
            &mut plan_input,
            &mut ticket_input,
            &mut expectation_input,
            &mut verification_input,
        ]
        .into_iter()
        .chain(recovery_payload_input.iter_mut())
        {
            held.revalidate()?;
        }
        let policy = WritePolicy {
            allowed: plan.ranges.iter().map(|r| (r.offset, r.length)).collect(),
            retained: Vec::new(),
            maximum_bytes: selected_bytes,
            journal_profile: profile,
        };
        phase = "selected-journal-recovery";
        // A parsed manifest supplies bounded facts only. Native extent
        // verification below also requires the real HND/closed-journal result
        // returned by this recovery's unchanged complete journal checks.
        let mut verified_refs_closed = None;
        let outcome = match action {
            Action::Resume => {
                if source_free_bytes != 0 {
                    ensure!(
                        request.selected_capacity_policy.allows_source_free()
                            && plan.encoding_version() == 5,
                        "source-free recovery requires format five policy"
                    );
                    target.arm_source_free_actual_bytes_v3_writes(
                        policy,
                        journal_bytes,
                        old_zero_bytes,
                        source_free_bytes,
                        request.max_journal_bytes,
                        &mut events,
                    )?;
                } else if old_zero_bytes != 0 && !request.selected_capacity_policy.is_conservative()
                {
                    ensure!(
                        plan.encoding_version() == 4,
                        "actual-byte recovery requires format four"
                    );
                    target.arm_old_zero_actual_bytes_v3_writes(
                        policy,
                        journal_bytes,
                        old_zero_bytes,
                        request.max_journal_bytes,
                        &mut events,
                    )?;
                } else if old_zero_bytes != 0 {
                    target.arm_old_zero_selected_writes(
                        policy,
                        journal_bytes,
                        old_zero_bytes,
                        &mut events,
                    )?;
                } else if plan.new_zero_ranges.is_empty() && plan.new_copy_ranges.is_empty() {
                    target.arm_writes(policy, &mut events)?;
                } else {
                    target.arm_encoded_selected_writes(policy, journal_bytes, &mut events)?;
                }
                let (_, handoff) = recovery_journal.resume_and_handoff(&mut target, |resumed| {
                    artifacts::save(output, "resume.json", resumed)?;
                    Ok(())
                })?;
                artifacts::save(output, "handoff.json", &handoff)?;
                verified_refs_closed = Some(handoff);
                AllocationRecoveryOutcome::RefsCompleted
            }
            Action::VerifyHandoff => {
                let (closed_state, verified) = recovery_journal.verify_closed(&mut target)?;
                ensure!(
                    closed_state == SelectedLifecycle::Handoff,
                    "ReFS verification requires the actual closed HND lifecycle"
                );
                artifacts::save(output, "verified-handoff.json", &verified)?;
                verified_refs_closed = Some(verified);
                AllocationRecoveryOutcome::RefsCompleted
            }
            Action::Rollback => {
                if source_free_bytes != 0 {
                    ensure!(
                        request.selected_capacity_policy.allows_source_free()
                            && plan.encoding_version() == 5,
                        "source-free recovery requires format five policy"
                    );
                    target.arm_source_free_actual_bytes_v3_writes(
                        policy,
                        journal_bytes,
                        old_zero_bytes,
                        source_free_bytes,
                        request.max_journal_bytes,
                        &mut events,
                    )?;
                } else if old_zero_bytes != 0 && !request.selected_capacity_policy.is_conservative()
                {
                    ensure!(
                        plan.encoding_version() == 4,
                        "actual-byte recovery requires format four"
                    );
                    target.arm_old_zero_actual_bytes_v3_writes(
                        policy,
                        journal_bytes,
                        old_zero_bytes,
                        request.max_journal_bytes,
                        &mut events,
                    )?;
                } else if old_zero_bytes != 0 {
                    target.arm_old_zero_selected_writes(
                        policy,
                        journal_bytes,
                        old_zero_bytes,
                        &mut events,
                    )?;
                } else if plan.new_zero_ranges.is_empty() && plan.new_copy_ranges.is_empty() {
                    target.arm_writes(policy, &mut events)?;
                } else {
                    target.arm_encoded_selected_writes(policy, journal_bytes, &mut events)?;
                }
                let rolled = recovery_journal.rollback(&mut target)?;
                artifacts::save(output, "rollback.json", &rolled)?;
                AllocationRecoveryOutcome::NtfsRestored
            }
            Action::Abandon => {
                let closed = recovery_journal.abandon(&mut target)?;
                artifacts::save(output, "abandon.json", &closed)?;
                AllocationRecoveryOutcome::NtfsRestored
            }
            Action::VerifyAborted => {
                let (_, verified) = recovery_journal.verify_closed(&mut target)?;
                artifacts::save(output, "verified-rollback.json", &verified)?;
                AllocationRecoveryOutcome::NtfsRestored
            }
        };
        artifacts::save(output, "recovery-events.json", &events)?;
        for held in [
            &mut bundle_input,
            &mut request_input,
            &mut plan_input,
            &mut ticket_input,
            &mut expectation_input,
            &mut verification_input,
        ]
        .into_iter()
        .chain(recovery_payload_input.iter_mut())
        {
            held.revalidate()?;
        }
        phase = "native-mount";
        let mut extent_verification_receipt = None;
        match outcome {
            AllocationRecoveryOutcome::RefsCompleted => {
                let mut finalization = protocol::Finalization {
                    success: false,
                    rollback_closed: true,
                    handoff: None,
                    completed_marker_proof: None,
                    native: None,
                    label_restoration: None,
                    mount_paths_after: None,
                    mount_paths_preserved: None,
                    mount_paths_error: None,
                    error: None,
                    events: Vec::new(),
                    general_conversion_qualified: false,
                };
                match target.bring_online(&mut finalization.events) {
                    Ok(()) => {
                        // A previous process may have restored the label after
                        // its own handoff; verify against the label it left.
                        let restored_label = matches!(action, Action::VerifyHandoff)
                            && rediscover_general_volume_wait(
                                request.pair.source.clone(),
                                &mut finalization.events,
                            )
                            .and_then(|binding| {
                                n2r_win32::volume_label::observe_label(binding, "ReFS")
                            })
                            .is_ok_and(|observed| {
                                observed.label == verification.expected_source_label
                            });
                        let scope = protocol::NativeVerificationScope {
                            pair: &request.pair,
                            source_resource_profile: request.source_resource_profile,
                            expected_mount_paths: Some(
                                verification.expected_mount_paths.as_slice(),
                            ),
                            expected_source_label: Some(&verification.expected_source_label),
                        };
                        if let Some(proof) = &recovery_payload_proof {
                            let closed = verified_refs_closed.as_ref().context(
                                "extent recovery lacks an actual verified closed-journal result",
                            )?;
                            match protocol::fast_verification::verify_native_recovery_extents_scoped(
                                &scope,
                                &expectation,
                                &mut finalization,
                                proof,
                                closed,
                                restored_label,
                            ) {
                                Ok(receipt) => {
                                    artifacts::save(
                                        output,
                                        "recovery-extent-verification.json",
                                        &receipt,
                                    )?;
                                    extent_verification_receipt = Some(receipt);
                                }
                                Err(error) => finalization.error = Some(format!("{error:#}")),
                            }
                        } else {
                            protocol::verify_native_scoped(
                                &scope,
                                &expectation,
                                &mut finalization,
                                restored_label,
                            );
                        }
                    }
                    Err(error) => finalization.error = Some(error.to_string()),
                }
                artifacts::save(output, "completion.json", &finalization)?;
                ensure!(
                    finalization.success,
                    "allocation ReFS recovery verification refused; rollback stays closed: {:?}",
                    finalization.error
                );
            }
            AllocationRecoveryOutcome::NtfsRestored => {
                let mut mount_events = Vec::new();
                target.bring_online(&mut mount_events)?;
                let mounted =
                    rediscover_general_volume_wait(request.pair.source.clone(), &mut mount_events)
                        .and_then(|binding| mounted_filesystem_general(binding, &mut mount_events));
                artifacts::save(
                    output,
                    "completion.json",
                    &serde_json::json!({
                        "mounted_filesystem":mounted.as_ref().ok(),
                        "error":mounted.as_ref().err().map(|error| error.to_string()),
                        "events":mount_events,
                    }),
                )?;
                ensure!(
                    matches!(&mounted, Ok(name) if name == "NTFS"),
                    "restored original did not mount as NTFS: {mounted:?}"
                );
            }
        }
        let mut result = serde_json::json!({
            "schema_version":1,"kind":"allocation-bounded-recovery","success":true,
            "observed_lifecycle":state,"action":action,"outcome":outcome,
            // Every successful action above consumed the authenticated owner.
            // This records that code path; it grants no replay authority.
            "exclusive_recovery_journal_used":true,
            "journal_format":plan.encoding_name(),
            "journal_bytes":journal_bytes,"selected_bytes":selected_bytes,
            "old_zero_bytes":old_zero_bytes,
            "old_zero_payload_storage_elided":old_zero_bytes > 0,
            "source_free_old_payload_storage_elided":source_free_bytes > 0,
            "source_free_bytes":source_free_bytes,
            "source_free_hash_table_bytes":source_free_bytes / 256,
            "rollback_preserves_free_space_contents":source_free_bytes == 0,
            "fresh_apply_authorized":false,"source_admitted":false,
            "general_conversion_qualified":false,
        });
        if !request.selected_capacity_policy.is_conservative() {
            result["selected_capacity_policy"] =
                serde_json::to_value(request.selected_capacity_policy)?;
        }
        if let Some(receipt) = extent_verification_receipt {
            result["actual_verification_scope"] = "pinned_extent_identity_v1".into();
            result["full_content_hashes_compared"] = false.into();
            result["original_unread_content_digest_reconstructed"] = false.into();
            result["extent_verification"] = receipt;
        }
        artifacts::save(output, "result.json", &result)?;
        Ok(outcome)
    })();
    match attempted {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            artifacts::save(
                output,
                "failed.json",
                &serde_json::json!({
                    "schema_version":1,"kind":"allocation-bounded-recovery-failure",
                    "phase":phase,"error":format!("{error:#}"),
                    "automatic_fallback_attempted":false,"fresh_apply_authorized":false,
                    "completion_state_must_be_inspected":true,
                }),
            )?;
            Err(error)
        }
    }
}
