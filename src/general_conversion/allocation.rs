//! Experimental allocation-bounded conversion under the ntfs2btrfs-style
//! guarantee: only ranges the protected frozen shadow's native allocator reports
//! allocated are compared, journaled and written. The original live certificate
//! is still required. An interrupted run is recovered from its published
//! allocation recovery bundle by `general_recovery::allocation`.
use super::*;
use crate::selected_journal as sj;
use anyhow::Context;
use n2r_win32::{GeneralFrozenPartition, WritePolicy};

fn announce_conversion_phase(message: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "Conversion: {message}");
}

/// Advisory phase counters; these do not describe physical storage traffic or
/// provide any source, target or recovery authority.
fn record_process_io(output: &Path, phase: &str) -> Result<()> {
    let counters = n2r_win32::process_io::snapshot();
    qualification::save(
        output,
        &format!("process-io-{phase}.json"),
        &serde_json::json!({
            "schema_version":1,"phase":phase,
            "counters":counters.as_ref().ok(),
            "native_error":counters.as_ref().err().map(ToString::to_string),
            "advisory_only":true,"execution_authorized":false,
        }),
    )?;
    Ok(())
}

pub(super) fn convert_allocation_selected(
    request: &Request,
    construction: qualification::CompactConstructionBudget,
    output: &Path,
    interrupt_after_writes: Option<u32>,
    interrupt_after_first_copy_write: bool,
    fresh_exclusive_v3_first_write_fault: bool,
) -> Result<()> {
    request.validate()?;
    ensure!(
        !fresh_exclusive_v3_first_write_fault
            || (interrupt_after_writes == Some(1)
                && !interrupt_after_first_copy_write
                && request.schema_version == 3
                && request.verification_policy.is_fast()
                && request.source_resource_profile
                    == Some(
                        crate::ntfs_admission::ResourceProfile::ExperimentalObjectEnvelopeV3(None)
                    )
                && !request.verify_existing_shadow),
        "exclusive first-write fault requires the explicit fresh V3 planning input"
    );
    ensure!(
        interrupt_after_writes.is_none_or(|writes| (1..=4096).contains(&writes)),
        "allocation-bounded interruption count must be 1..=4096"
    );
    ensure!(
        !interrupt_after_first_copy_write || interrupt_after_writes.is_none(),
        "copy-write and numeric interruptions are mutually exclusive"
    );
    announce_conversion_phase("checking request and device identities");
    let preflight = composite::selected_device_preflight(request)?;
    qualification::create_output(output)?;
    qualification::save(output, "selected-device-preflight.json", &preflight)?;
    qualification::save(
        output,
        "conversion-intent.json",
        &serde_json::json!({
            "schema_version":1,"kind":"experimental-allocation-bounded-conversion-intent",
            "request":request,"construction_budget":construction,
            "verification_policy":request.verification_policy,
            "planned_source_verification_policy":request.verification_policy,
            "planned_target_verification_policy":request.verification_policy,
            "full_file_hashes_requested":request.verification_policy.is_full_content(),
            "raw_source_logical_hashes_requested":request.verification_policy.is_full_content(),
            "raw_source_extent_identity_requested":request.verification_policy.is_fast(),
            "interrupt_after_writes":interrupt_after_writes,
            "interrupt_after_first_copy_write":interrupt_after_first_copy_write,
            "requires_original_live_source_certificate":true,
            "free_space_contents_compared":false,"recovery_bundle_published_before_activation":true,
            "source_admitted":false,"execution_authorized":false,
            "general_conversion_qualified":false,
        }),
    )?;
    let mut phase = "allocation-bounded-qualification";
    let attempted = (|| -> Result<()> {
        record_process_io(output, "start")?;
        let profile = request.journal_profile()?;
        // Every old byte remains in the encoded journal. New zero bytes need
        // no stored copy; the exact D + literal-new + metadata size is checked
        // by the live plan before preparing the journal or activating source.
        let maximum = request
            .max_journal_bytes
            .checked_sub(n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE)
            .context("selected journal cannot reserve its metadata")?
            .min(request.pair.source.identity.partition_bytes)
            / 4096
            * 4096;
        let qualification_root = output.join("qualification");
        let packed_path = qualification_root.join("changed-clusters.bin");
        let capture_budget = request.max_literal_backing_bytes.map(|literal| {
            crate::general_shadow::source_backed::CaptureBudget {
                max_changed_bytes: maximum,
                max_journal_bytes: request.max_journal_bytes,
                max_literal_backing_bytes: literal,
                max_combined_backing_and_journal_bytes: request.max_combined_scratch_bytes.unwrap(),
                minimum_free_bytes: 1024 * 1024 * 1024,
            }
        });
        let journal_root = request.journal.disk.volume_path()? + "\\";
        let mut capacity_observations = Vec::new();
        let mut observed_capacity: Option<(u64, u64, u64)> = None;
        let mut guard =
            |progress: crate::general_shadow::source_backed::CaptureProgress| -> Result<()> {
                let required = progress.required_available_bytes()?;
                let cached_available = observed_capacity.and_then(|(_, literal, available)| {
                    progress
                        .literal_backing_bytes
                        .checked_sub(literal)
                        .and_then(|written| available.checked_sub(written))
                });
                let refresh = observed_capacity.is_none_or(|(changed, _, _)| {
                    progress.changed_bytes.saturating_sub(changed) >= 4 * 1024 * 1024
                }) || cached_available.is_none_or(|available| available < required);
                if refresh {
                    if observed_capacity.is_none() {
                        // The combined budget belongs to one real storage pool.
                        // Public runs put both files on the selected OS volume.
                        let capture_root = match output.components().next() {
                            Some(std::path::Component::Prefix(prefix)) => match prefix.kind() {
                                std::path::Prefix::Disk(letter) => {
                                    format!("{}:\\", char::from(letter))
                                }
                                _ => anyhow::bail!(
                                    "capacity capture requires an ordinary drive path"
                                ),
                            },
                            _ => anyhow::bail!("capacity capture requires an absolute drive path"),
                        };
                        let actual = n2r_win32::discovery::discover(
                            &capture_root,
                            n2r_win32::discovery::Role::Journal {
                                allow_additional_partitions: request
                                    .journal
                                    .allow_additional_partitions,
                            },
                        )?;
                        ensure!(
                            actual.binding == request.journal.disk,
                            "literal backing and journal do not share the pinned storage volume"
                        );
                    }
                    let space = n2r_win32::discovery::observe_volume_space(&journal_root)?;
                    observed_capacity = Some((
                        progress.changed_bytes,
                        progress.literal_backing_bytes,
                        space.available_bytes_to_caller,
                    ));
                    capacity_observations
                        .try_reserve(1)
                        .context("capture capacity observation allocation failed")?;
                    capacity_observations.push(serde_json::json!({
                        "changed_bytes":progress.changed_bytes,
                        "literal_backing_bytes":progress.literal_backing_bytes,
                        "next_append_bytes":progress.next_append_bytes,
                        "required_available_bytes":required,"space":space,
                    }));
                }
                let (_, literal, available) =
                    observed_capacity.context("capture capacity not observed")?;
                let remaining = available
                    .checked_sub(
                        progress
                            .literal_backing_bytes
                            .checked_sub(literal)
                            .context("literal backing progress moved backwards")?,
                    )
                    .context("literal backing consumed the observed storage capacity")?;
                ensure!(
                    remaining >= required,
                    "capture storage cannot cover the projected journal, next append and reserve"
                );
                Ok(())
            };
        announce_conversion_phase(
            "inspecting NTFS, building the ReFS shadow and comparing its allocated ranges",
        );
        let qualified = qualification::prepare_allocation_fresh_selected(
            request.pair.clone(),
            &qualification_root,
            &packed_path,
            maximum,
            profile,
            request.source_resource_profile.unwrap_or_default(),
            construction,
            capture_budget,
            request
                .max_literal_backing_bytes
                .map(|_| &mut guard as &mut dyn FnMut(_) -> Result<()>),
            request.verification_policy,
        );
        drop(guard);
        if capture_budget.is_some() {
            qualification::save(
                output,
                "capture-capacity.json",
                &serde_json::json!({
                    "schema_version":1,"budget":capture_budget,"observations":capacity_observations,
                    "refresh_changed_bytes":4 * 1024 * 1024,"source_writes_started":false,
                    "capacity_is_advisory":true,"execution_authorized":false,
                }),
            )?;
        }
        let qualification::QualifiedAllocationTree {
            resources,
            mut source,
            native_target,
            mut proof,
            certificate,
            expected,
            mount_paths,
            source_label,
        } = qualified?;
        // Only the complete frozen-source admission is persisted for recovery.
        // Planning an envelope did not issue a certificate or widen any budget.
        let mut admitted_request = request.clone();
        if resources.is_envelope() {
            resources.count_admission()?;
            admitted_request.source_resource_profile = Some(resources);
        }
        let request = &admitted_request;
        record_process_io(output, "qualified")?;
        let expected_tree_sha256 = hex::encode(Sha256::digest(&expected));
        ensure!(
            certificate.binds(&proof) && certificate.expected_tree_sha256() == expected_tree_sha256,
            "allocation-bounded certificate does not bind the live proof"
        );
        let expectation: crate::shadow_tree::ExpectedTree = serde_json::from_slice(&expected)?;
        let expectation_pin = qualification::save(output, "expectation.json", &expectation)?;
        ensure!(
            expectation_pin == expected_tree_sha256,
            "saved expectation differs from the admitted target"
        );
        let plan = proof.plan(request.max_journal_bytes)?;
        let (selected_bytes, journal_bytes) = plan.validate()?;
        let new_zero_bytes = plan.new_zero_bytes()?;
        let new_copy_bytes = plan.new_copy_bytes()?;
        let packed_bytes = proof.capture().layout.packed_bytes();
        let plan_pin = qualification::save(output, "selected-plan.json", &plan)?;
        let copy_interruption_target = if interrupt_after_first_copy_write {
            let copy = plan.new_copy_ranges.first().context(
                "first-copy interruption requires a qualified old-payload reference; source writes have not started",
            )?.clone();
            qualification::save(
                output,
                "copy-interruption-target.json",
                &serde_json::json!({
                    "kind":"first-copy-write-interruption-target",
                    "offset":copy.offset,"length":copy.length,
                    "source_offset":copy.source_offset,"actual_plan_bound":true,
                    "plan_sha256":plan_pin,"expected_exit_code":86,
                    "write_executed":false,
                }),
            )?;
            Some(copy)
        } else {
            None
        };

        let journal_volume_root = request.journal.disk.volume_path()? + "\\";
        let space = n2r_win32::discovery::observe_volume_space(&journal_volume_root)?;
        let reserve = 1024_u64 * 1024 * 1024;
        ensure!(
            space.available_bytes_to_caller >= journal_bytes.saturating_add(reserve),
            "exact selected journal needs {journal_bytes} bytes plus the working-space reserve"
        );
        qualification::save(
            output,
            "journal-capacity.json",
            &serde_json::json!({
                "journal_bytes":journal_bytes,"packed_bytes":packed_bytes,
                "selected_bytes":selected_bytes,"new_zero_bytes":new_zero_bytes,
                "new_copy_bytes":new_copy_bytes,
                "available_after_shadow_and_backing":space.available_bytes_to_caller,
                "reserve_bytes":reserve,"source_writes_started":false,
            }),
        )?;

        phase = "selected-journal-preparation";
        announce_conversion_phase("preparing the selected-range recovery journal");
        let parent = std::path::PathBuf::from(format!(
            "{}\\ntfs2refs-shadow",
            request.journal.disk.volume_path()?,
        ));
        if !parent.exists() {
            fs::create_dir(&parent)?;
        }
        let metadata = fs::symlink_metadata(&parent)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "ordinary selected journal parent required"
        );
        let directory = parent.join(&request.experiment_id);
        ensure!(
            !directory.exists(),
            "fresh selected journal experiment required"
        );
        fs::create_dir(&directory)?;
        let journal_path = directory.join("selected.journal");
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&journal_path)?;
        let observed =
            observe_general_journal_file_with_profile(&journal, &request.journal, profile)?;
        ensure!(
            observed.file_bytes == 0,
            "fresh empty selected journal required"
        );
        qualification::save(
            output,
            "journal-location.json",
            &serde_json::json!({
                "path":journal_path,"identity":observed.identity,
                "format":if new_copy_bytes != 0 {"N2RCPY01"} else if new_zero_bytes != 0 {"N2RZERO1"} else {"N2RSEL01"},
            }),
        )?;
        let mut preparation_events = Vec::new();
        // The second read-only handle supplies the candidate's unchanged bytes;
        // the original source handle keeps the admission/freeze context.
        let mut complement =
            GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut preparation_events)?;
        let complement_before = complement.state(&mut preparation_events)?;
        let source_before = source.state(&mut preparation_events)?;
        ensure!(
            complement_before == source_before && complement_before.disk_attributes == 3,
            "selected preparation complement differs from the admitted source"
        );
        let ticket = {
            let mut image = proof.image(&mut complement)?;
            if request.verification_policy.is_fast()
                && ((interrupt_after_writes.is_none() && !interrupt_after_first_copy_write)
                    || fresh_exclusive_v3_first_write_fault)
            {
                sj::prepare_exclusive(&mut source, &mut image, &mut journal, &plan)?
            } else {
                sj::prepare(&mut source, &mut image, &mut journal, &plan)?
            }
        };
        ensure!(
            complement.state(&mut preparation_events)? == complement_before
                && source.state(&mut preparation_events)? == source_before,
            "source or complement changed during selected journal preparation"
        );
        drop(complement);
        proof.revalidate_backing()?;
        ensure!(
            ticket.selected_bytes == selected_bytes
                && ticket.journal_length == journal_bytes
                && ticket.new_selected_sha256 != ticket.old_selected_sha256,
            "selected ticket differs from the admitted plan"
        );
        qualification::save(output, "preparation-events.json", &preparation_events)?;
        let ticket_pin = qualification::save(output, "selected-ticket.json", &ticket)?;
        let fresh_payload_proof = request
            .verification_policy
            .is_fast()
            .then(|| {
                reconstruct::fast_verification::FreshPayloadProof::new(
                    &proof,
                    &certificate,
                    &expectation,
                    &plan,
                    &ticket,
                )
            })
            .transpose()?;
        let recovery_payload_manifest = if expectation.has_extent_only_streams() {
            let manifest = fresh_payload_proof
                .as_ref()
                .context("hash-free source requires the original fresh payload proof")?
                .recovery_manifest()?;
            let path = output.join("recovery-payload-manifest.json");
            let sha256 = qualification::save(output, "recovery-payload-manifest.json", &manifest)?;
            Some(serde_json::json!({"path":path,"sha256":sha256}))
        } else {
            None
        };
        // Publish one checksummed locator before activation. It carries pins
        // only; the recovery engine rechecks the journal and device itself.
        let request_pin = qualification::save(output, "request.json", request)?;
        let verification_pin = qualification::save(
            output,
            "verification.json",
            &serde_json::json!({
                "expected_mount_paths":mount_paths.paths,
                "expected_source_label":source_label.label(),
            }),
        )?;
        let mut recovery_bundle = serde_json::json!({
            "schema_version":1,"kind":"allocation-bounded-recovery-bundle",
            "request":{"path":output.join("request.json"),"sha256":request_pin},
            "plan":{"path":output.join("selected-plan.json"),"sha256":plan_pin},
            "ticket":{"path":output.join("selected-ticket.json"),"sha256":ticket_pin},
            "expectation":{"path":output.join("expectation.json"),"sha256":expectation_pin},
            "verification":{"path":output.join("verification.json"),"sha256":verification_pin},
            "journal":journal_path,"source":request.pair.source,
            "serialized_bundle_grants_recovery_authority":false,
        });
        if let Some(manifest) = recovery_payload_manifest {
            recovery_bundle["recovery_payload_manifest"] = manifest;
        }
        let recovery_pin =
            qualification::save(output, "allocation-recovery-bundle.json", &recovery_bundle)?;
        if fresh_exclusive_v3_first_write_fault {
            request
                .source_resource_profile
                .unwrap_or_default()
                .count_admission()?;
            qualification::save(
                output,
                "fresh-exclusive-fault-path.json",
                &serde_json::json!({
                    "schema_version":1,"kind":"lab-fresh-exclusive-v3-first-write-path",
                    "source_resource_profile":request.source_resource_profile,
                    "preparation_completed":"prepare_exclusive",
                    "apply_entrypoint_requested":"apply_and_handoff_exclusive",
                    "requested_flushed_payload_writes":1,"controlled_exit_code":86,
                    "hnd_allowed_if_interruption_not_reached":false,"source_writes_started":false,
                    "diagnostic_only":true,"execution_authorized":false,"replay_authorized":false,
                    "recovery_bundle_sha256":recovery_pin,
                }),
            )?;
        }
        println!("Recovery directory: {}", output.display());
        println!("Recovery checksum: {recovery_pin}");

        phase = "selected-activation";
        record_process_io(output, "journal-prepared")?;
        if capture_budget.is_some() {
            // Existing journal/backing allocations have already reduced free
            // space. Require the remaining reserve without charging them twice.
            let remaining = n2r_win32::discovery::observe_volume_space(&journal_root)?;
            ensure!(
                remaining.available_bytes_to_caller >= 1024 * 1024 * 1024,
                "working-space reserve was consumed before source activation"
            );
            qualification::save(
                output,
                "activation-capacity.json",
                &serde_json::json!({
                    "schema_version":1,"space":remaining,"minimum_free_bytes":1024_u64 * 1024 * 1024,
                    "journal_already_allocated":true,"source_writes_started":false,
                }),
            )?;
        }
        announce_conversion_phase("activating the frozen source for selected writes");
        ensure!(
            certificate.binds(&proof),
            "original live certificate no longer binds the allocation-bounded proof"
        );
        let mut events = Vec::<NativeEvent>::new();
        let shadow_before = native_target.state(&mut events)?;
        let activation = if request.verification_policy.is_fast() {
            source.activate_for_journal_exclusive(&mut events)
        } else {
            source.activate_for_journal(&mut events)
        };
        let mut target = match activation {
            Ok(target) => target,
            Err(error) => {
                qualification::save(output, "activation-events.json", &events)?;
                return Err(error.into());
            }
        };
        ensure!(
            target.state(&mut events)?.disk_attributes == 1
                && native_target.state(&mut events)? == shadow_before,
            "selected activation lost exclusion"
        );
        let policy = WritePolicy {
            allowed: plan.ranges.iter().map(|r| (r.offset, r.length)).collect(),
            retained: Vec::new(),
            maximum_bytes: selected_bytes,
            journal_profile: profile,
        };
        if new_zero_bytes == 0 && new_copy_bytes == 0 {
            target.arm_writes(policy, &mut events)?;
        } else {
            target.arm_encoded_selected_writes(policy, journal_bytes, &mut events)?;
        }
        qualification::save(output, "activation-events.json", &events)?;
        events.clear();

        phase = "selected-apply";
        announce_conversion_phase("applying the selected ranges");
        let (applied, exclusive_handoff) = match (
            interrupt_after_writes,
            copy_interruption_target.as_ref(),
        ) {
            (Some(remaining), _) if fresh_exclusive_v3_first_write_fault => {
                let mut interrupted =
                    reconstruct::InterruptingGeneralTarget::new(&mut target, remaining);
                let _ = sj::apply_and_handoff_exclusive(
                    &mut interrupted,
                    &mut journal,
                    &plan,
                    &ticket,
                    |_| {
                        anyhow::bail!(
                            "exclusive first-write interruption was not reached; refusing HND"
                        )
                    },
                )?;
                anyhow::bail!("exclusive first-write interruption unexpectedly returned; no retry")
            }
            (Some(remaining), _) => {
                // Lab fault: the wrapper flushes then exits the process with 86.
                let mut interrupted =
                    reconstruct::InterruptingGeneralTarget::new(&mut target, remaining);
                let result = sj::apply(&mut interrupted, &mut journal, &plan, &ticket)?;
                anyhow::bail!(
                    "allocation-bounded interruption not reached: {} ranges written",
                    result.range_count
                )
            }
            (None, Some(copy)) => {
                let mut interrupted = reconstruct::FirstCopyInterruptingGeneralTarget::new(
                    &mut target,
                    copy.offset,
                    copy.length,
                )?;
                let result = sj::apply(&mut interrupted, &mut journal, &plan, &ticket)?;
                anyhow::bail!(
                    "first-copy interruption not reached: qualified copy at {} for {} bytes; {} ranges applied",
                    copy.offset,
                    copy.length,
                    result.range_count
                )
            }
            (None, None) if request.verification_policy.is_fast() => {
                // Preserve exclusive ownership through the validated Apply
                // and durable HND. Only this fresh path can later consume the
                // live payload proof for mounted extent verification.
                let (applied, handoff) = sj::apply_and_handoff_exclusive(
                    &mut target,
                    &mut journal,
                    &plan,
                    &ticket,
                    |applied| {
                        qualification::save(output, "apply.json", applied)?;
                        record_process_io(output, "applied")?;
                        phase = "selected-handoff";
                        announce_conversion_phase(
                            "completing ReFS handoff and verifying mounted file contents",
                        );
                        Ok(())
                    },
                )?;
                (applied, Some(handoff))
            }
            (None, None) => (sj::apply(&mut target, &mut journal, &plan, &ticket)?, None),
        };
        let handoff = if let Some(handoff) = exclusive_handoff {
            handoff
        } else {
            qualification::save(output, "apply.json", &applied)?;
            record_process_io(output, "applied")?;
            phase = "selected-handoff";
            announce_conversion_phase(
                "completing ReFS handoff and verifying mounted file contents",
            );
            sj::handoff(&mut target, &mut journal, &plan, &ticket)?
        };
        qualification::save(output, "handoff.json", &handoff)?;
        record_process_io(output, "handoff")?;
        proof.revalidate_backing()?;
        ensure!(
            native_target.state(&mut events)? == shadow_before,
            "native shadow route changed during selected handoff"
        );
        let mut finalization = reconstruct::Finalization {
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
            events,
            general_conversion_qualified: false,
        };
        match target.bring_online(&mut finalization.events) {
            Ok(()) => {
                let scope = reconstruct::NativeVerificationScope {
                    pair: &request.pair,
                    source_resource_profile: request.source_resource_profile,
                    expected_mount_paths: Some(mount_paths.paths.as_slice()),
                    expected_source_label: Some(source_label.label()),
                };
                if let Some(fresh) = &fresh_payload_proof {
                    match reconstruct::fast_verification::verify_native_extents_scoped(
                        &scope,
                        &expectation,
                        &mut finalization,
                        fresh,
                        &applied,
                        &handoff,
                    ) {
                        Ok(receipt) => {
                            qualification::save(output, "extent-verification.json", &receipt)?;
                        }
                        Err(error) => {
                            finalization.error = Some(format!("{error:#}"));
                        }
                    }
                } else {
                    reconstruct::verify_native_scoped(
                        &scope,
                        &expectation,
                        &mut finalization,
                        false,
                    );
                }
            }
            Err(error) => finalization.error = Some(error.to_string()),
        }
        qualification::save(output, "finalization.json", &finalization)?;
        record_process_io(output, "native-verified")?;
        ensure!(
            finalization.success,
            "allocation-bounded native handoff failed: {:?}",
            finalization.error
        );
        qualification::save(
            output,
            "result.json",
            &serde_json::json!({
                "schema_version":1,"kind":"experimental-allocation-bounded-conversion",
                "success":true,"source_admitted":true,"rollback_closed":true,
                "verification_policy":request.verification_policy,
                "actual_source_verification_policy":request.verification_policy,
                "raw_source_logical_hashes":!expectation.has_extent_only_streams(),
                "raw_source_extent_only_streams":expectation.objects.iter()
                    .flat_map(|o|o.data_streams()).filter(|s|s.source_evidence.is_some()).count(),
                "raw_source_extent_only_partial_streams":expectation.objects.iter()
                    .flat_map(|o|o.data_streams()).filter(|s|s.source_evidence==Some(crate::shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)).count(),
                "actual_target_verification_policy":request.verification_policy,
                "actual_full_file_hashes":request.verification_policy.is_full_content(),
                "exclusive_apply_handoff_used":request.verification_policy.is_fast(),
                "exclusive_preparation_readback_used":request.verification_policy.is_fast()
                    && interrupt_after_writes.is_none() && !interrupt_after_first_copy_write,
                "journal_path":journal_path,"ticket_sha256":ticket_pin,"plan_sha256":plan_pin,
                "expected_tree_sha256":expected_tree_sha256,
                "selected_ranges":plan.ranges.len(),"selected_bytes":selected_bytes,
                "journal_bytes":journal_bytes,"selection_sha256":proof.selection_sha256(),
                "packed_bytes":packed_bytes,"new_zero_bytes":new_zero_bytes,
                "new_copy_bytes":new_copy_bytes,
                "zero_payload_storage_elided":new_zero_bytes > 0,
                "free_space_contents_compared":false,"recovery_bundle_sha256":recovery_pin,
                "general_conversion_qualified":false,
            }),
        )?;
        drop(proof);
        Ok(())
    })();
    if let Err(error) = attempted {
        qualification::save(
            output,
            "failed.json",
            &serde_json::json!({
                "phase":phase,"error":format!("{error:#}"),"recovery_materials":output,
                "automatic_rollback_attempted":false,
                "recover_with_published_bundle_if_present":"allocation-recovery-bundle.json",
                "general_conversion_qualified":false,
            }),
        )?;
        return Err(error);
    }
    Ok(())
}
