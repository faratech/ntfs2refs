//! Experimental allocation-bounded conversion under the ntfs2btrfs-style
//! guarantee: only ranges the protected frozen shadow's native allocator reports
//! allocated are compared, journaled and written. The original live certificate
//! is still required. An interrupted run is recovered from its published
//! allocation recovery bundle by `general_recovery::allocation`.
use super::*;
use crate::selected_journal as sj;
use anyhow::Context;
use n2r_win32::{GeneralFrozenPartition, WritePolicy, journal_file::MarkerStorageUse};
use reconstruct::selected_artifacts::Artifact;
use reconstruct::selected_native_journal::NativeSelectedJournal;

/// The fresh alternative exposes no mutable journal between completed
/// preparation and handoff. Legacy execution retains its original stream APIs.
enum PreparedJournal<'a> {
    Exclusive(sj::PreparedExclusiveJournal<'a, NativeSelectedJournal>),
    Legacy {
        journal: &'a mut NativeSelectedJournal,
        ticket: sj::SelectedTicket,
    },
}

impl PreparedJournal<'_> {
    fn ticket(&self) -> &sj::SelectedTicket {
        match self {
            Self::Exclusive(prepared) => prepared.ticket(),
            Self::Legacy { ticket, .. } => ticket,
        }
    }
}

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
    production_markers: bool,
) -> Result<()> {
    convert_allocation_selected_inner(
        request,
        construction,
        output,
        interrupt_after_writes,
        interrupt_after_first_copy_write,
        fresh_exclusive_v3_first_write_fault,
        None,
        production_markers,
        None,
    )
}

/// Explicit enrolled-lab entry; its marker profile remains independent of the
/// production qualification gate.
pub(crate) fn convert_allocation_redundant_for_lab(
    request: &Request,
    construction: qualification::CompactConstructionBudget,
    output: &Path,
    first_write_fault: bool,
    pause: Option<n2r_win32::journal_file::LabMarkerPauseRequest>,
) -> Result<()> {
    ensure!(
        request.schema_version == 3
            && request.verification_policy.is_fast()
            && request.source_resource_profile
                == Some(crate::ntfs_admission::ResourceProfile::ExperimentalObjectEnvelopeV3(None))
            && request.selected_capacity_policy.allows_source_free()
            && !request.verify_existing_shadow,
        "native redundant marker lab conversion requires fresh schema3 fast source-free planning None"
    );
    construction.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        pause.is_none() || !first_write_fault,
        "marker pause and first-write exit fault are mutually exclusive"
    );
    convert_allocation_selected_inner(
        request,
        construction,
        output,
        first_write_fault.then_some(1),
        false,
        first_write_fault,
        Some(sj::SelectedMarkerProfile::RedundantSourceFreeV1),
        false,
        pause,
    )
}

fn convert_allocation_selected_inner(
    request: &Request,
    construction: qualification::CompactConstructionBudget,
    output: &Path,
    interrupt_after_writes: Option<u32>,
    interrupt_after_first_copy_write: bool,
    fresh_exclusive_v3_first_write_fault: bool,
    marker_profile: Option<sj::SelectedMarkerProfile>,
    production_markers: bool,
    pause: Option<n2r_win32::journal_file::LabMarkerPauseRequest>,
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
    ensure!(
        pause.is_none() || marker_profile == Some(sj::SelectedMarkerProfile::RedundantSourceFreeV1),
        "marker pause requires the explicit native format-six lab route"
    );
    let lab_pause = if let Some(pause) = pause {
        Some(pause.reserve(
            output,
            &request.journal,
            &request.pair.source,
            &request.pair.shadow,
            request.journal_profile()?,
        )?)
    } else {
        None
    };
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
        // Only the explicit actual-byte policy may capture a larger changed
        // set. Its live guard still charges actual old/literal storage, and
        // the complete final plan is validated before source activation.
        let maximum = request.maximum_selected_changed_bytes()?;
        let qualification_root = output.join("qualification");
        let packed_path = qualification_root.join("changed-clusters.bin");
        let capture_budget = request.max_literal_backing_bytes.map(|literal| {
            crate::general_shadow::source_backed::CaptureBudget {
                selected_capacity_policy: request.selected_capacity_policy,
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
                    let mut observation = serde_json::json!({
                        "changed_bytes":progress.changed_bytes,
                        "literal_backing_bytes":progress.literal_backing_bytes,
                        "next_append_bytes":progress.next_append_bytes,
                        "required_available_bytes":required,"space":space,
                    });
                    if !progress.selected_capacity_policy.is_conservative() {
                        observation["selected_capacity_policy"] =
                            serde_json::to_value(progress.selected_capacity_policy)?;
                        observation["old_zero_bytes"] =
                            serde_json::to_value(progress.old_zero_bytes)?;
                        if let Some(free) = progress.source_free_bytes {
                            observation["source_free_bytes"] = free.into();
                            observation["source_free_hash_table_bytes"] = (free / 256).into();
                        }
                        observation["projected_journal_bytes"] =
                            progress.projected_journal_bytes.into();
                        observation["projected_combined_bytes"] =
                            progress.projected_combined_bytes.into();
                    }
                    capacity_observations.push(observation);
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
            expected_pages,
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
        let inline_expectation = if expected_pages.is_none() {
            Some(serde_json::from_slice::<crate::shadow_tree::ExpectedTree>(
                &expected,
            )?)
        } else {
            None
        };
        let expectation = match (&expected_pages, &inline_expectation) {
            (Some(pages), None) => crate::shadow_tree::pages::ExpectedTreeView::Paged(pages),
            (None, Some(tree)) => crate::shadow_tree::pages::ExpectedTreeView::Inline(tree),
            _ => anyhow::bail!("fresh expectation ownership is ambiguous"),
        };
        use crate::shadow_tree::ExpectedObjectDomain as _;
        expectation.revalidate_domain()?;
        let expectation_pin = Artifact::Expectation.save(output, &expectation)?;
        ensure!(
            expectation_pin == expected_tree_sha256,
            "saved expectation differs from the admitted target"
        );
        drop(expected);
        let paged_admission = resources
            .count_admission()?
            .filter(|a| a.requires_paged_metadata());
        let expectation_pages_pin = if let Some(admission) = paged_admission {
            let pages = expected_pages.as_ref().context(
                "admitted paged resources require the actual held expected-object owner",
            )?;
            ensure!(
                pages.budget() == admission.expected_page_budget()?
                    && pages.semantic_byte_budget()
                        == u64::from(admission.maximum_expected_tree_bytes)
                    && pages.semantic_sha256() == expectation_pin,
                "held expectation pages differ from the admitted resource or semantic pin"
            );
            let path = output.join("expectation.pages");
            pages.copy_to(&path)?;
            Some(serde_json::json!({"path":path,"sha256":pages.file_sha256()}))
        } else {
            None
        };
        let (extent_streams, partial_extent_streams) =
            reconstruct::fast_verification::extent_stream_counts(&expectation)?;
        let plan = proof.plan(request.max_journal_bytes)?;
        let marker_profile = if production_markers {
            reconstruct::selected_native_journal::production_marker_profile(&plan)
        } else {
            marker_profile
        };
        // Every profile, including a production fallback to legacy, retains
        // the complete plan and exact selected journal capacity validation.
        let (selected_bytes, journal_bytes) = plan.validate_marker_profile(marker_profile)?;
        request.validate_selected_capacity(&plan)?;
        let new_zero_bytes = plan.new_zero_bytes()?;
        let new_copy_bytes = plan.new_copy_bytes()?;
        let old_zero_bytes = plan.old_zero_bytes()?;
        let source_free_bytes = plan.source_free_bytes()?;
        let packed_bytes = proof.capture().layout.packed_bytes();
        let plan_pin = Artifact::Plan.save(output, &plan)?;
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
                "old_zero_bytes":old_zero_bytes,
                "source_free_bytes":source_free_bytes,
                "source_free_hash_table_bytes":source_free_bytes / 256,
                "rollback_preserves_free_space_contents":source_free_bytes == 0,
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
        expectation.revalidate_domain()?;
        let (mut journal, journal_identity) = NativeSelectedJournal::create_new(
            &journal_path,
            &request.journal,
            profile,
            marker_profile,
            if production_markers {
                MarkerStorageUse::QualifiedProduction
            } else {
                MarkerStorageUse::EnrolledUnqualifiedLab
            },
            lab_pause,
        )?;
        qualification::save(
            output,
            "journal-location.json",
            &serde_json::json!({
                "path":journal_path,"identity":journal_identity,
                "format":if marker_profile.is_some() { "N2RFRE02" } else { plan.encoding_name() },
                "journal_format_version":if marker_profile.is_some() { 6 } else { plan.encoding_version() },
                "journal_record_bytes":plan.journal_record_bytes(),
                "old_zero_bytes":old_zero_bytes,
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
        let (prepared, preparation_source_copy_bytes_reused) = {
            let mut image = proof.image(&mut complement)?;
            if request.verification_policy.is_fast()
                && ((interrupt_after_writes.is_none() && !interrupt_after_first_copy_write)
                    || fresh_exclusive_v3_first_write_fault)
            {
                let (owner, reused) = if marker_profile.is_some() {
                    sj::prepare_exclusive_owned_source_backed_sealed(
                        &mut source,
                        &mut image,
                        &mut journal,
                        &plan,
                        &mut preparation_events,
                        marker_profile,
                        |journal, ticket| {
                            journal.seal_redundant(ticket)?;
                            qualification::save(
                                output,
                                "native-marker-storage.json",
                                journal
                                    .marker_observation()
                                    .context("native marker storage not sealed")?,
                            )?;
                            Ok(())
                        },
                    )?
                } else {
                    sj::prepare_exclusive_owned_source_backed(
                        &mut source,
                        &mut image,
                        &mut journal,
                        &plan,
                        &mut preparation_events,
                    )?
                };
                (PreparedJournal::Exclusive(owner), reused)
            } else {
                ensure!(
                    marker_profile.is_none(),
                    "native markers require exclusive sealed preparation"
                );
                let ticket = sj::prepare(&mut source, &mut image, &mut journal, &plan)?;
                (
                    PreparedJournal::Legacy {
                        journal: &mut journal,
                        ticket,
                    },
                    0,
                )
            }
        };
        let prepared_journal_owner_reused = matches!(&prepared, PreparedJournal::Exclusive(_));
        // This immutable copy is persisted and bound into other evidence; the
        // fresh owner retains its original ticket and authenticated records.
        let ticket = prepared.ticket().clone();
        ensure!(
            complement.state(&mut preparation_events)? == complement_before
                && source.state(&mut preparation_events)? == source_before,
            "source or complement changed during selected journal preparation"
        );
        drop(complement);
        proof.revalidate_backing()?;
        qualification::save(
            output,
            "preparation-source-copy-reuse.json",
            &serde_json::json!({
                "schema_version":1,"scope":"same-frozen-native-source-reference-construction-v1",
                "actual_source_copy_bytes_reused":preparation_source_copy_bytes_reused,
                "candidate_bytes_still_read_and_hashed":true,
                "resolved_journal_copy_readback_retained":true,
                "fresh_old_target_gate_retained":true,
                "source_admission_granted":false,
            }),
        )?;
        ensure!(
            ticket.selected_bytes == selected_bytes
                && ticket.journal_length == journal_bytes
                && ticket.new_selected_sha256 != ticket.old_selected_sha256,
            "selected ticket differs from the admitted plan"
        );
        qualification::save(output, "preparation-events.json", &preparation_events)?;
        let ticket_pin = Artifact::Ticket.save(output, &ticket)?;
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
                    resources,
                )
            })
            .transpose()?;
        let recovery_payload_manifest = if expectation.has_extent_only_streams()? {
            let path = output.join(reconstruct::fast_verification::PAGED_MAP_FILENAME);
            let sha256 = fresh_payload_proof
                .as_ref()
                .context("hash-free source requires the original fresh payload proof")?
                .write_recovery_manifest(&path)?;
            Some(serde_json::json!({"path":path,"sha256":sha256}))
        } else {
            None
        };
        // Publish one checksummed locator before activation. It carries pins
        // only; the recovery engine rechecks the journal and device itself.
        let request_pin = Artifact::Request.save(output, request)?;
        let verification_pin = Artifact::Verification.save(
            output,
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
        if let Some(pin) = expectation_pages_pin {
            recovery_bundle["expectation_pages"] = pin;
        }
        if let Some(manifest) = recovery_payload_manifest {
            recovery_bundle["recovery_payload_manifest"] = manifest;
        }
        if marker_profile.is_some() {
            // A pinned locator fact only. Recovery must reopen and bind its
            // own typed native handle and fully authenticate actual J bytes.
            recovery_bundle["marker_storage_identity"] = serde_json::to_value(&journal_identity)?;
        }
        let recovery_pin = Artifact::Bundle.save(output, &recovery_bundle)?;
        if fresh_exclusive_v3_first_write_fault {
            request
                .source_resource_profile
                .unwrap_or_default()
                .count_admission()?;
            qualification::save(
                output,
                "fresh-exclusive-fault-path.json",
                &serde_json::json!({
                    "schema_version":2,"kind":"lab-fresh-exclusive-v3-first-write-path",
                    "source_resource_profile":request.source_resource_profile,
                    "preparation_completed":"prepare_exclusive_owned",
                    "apply_entrypoint_requested":"PreparedExclusiveJournal::apply_and_handoff",
                    "prepared_journal_owner_reused":prepared_journal_owner_reused,
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
        expectation.revalidate_domain()?;
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
        if source_free_bytes != 0 {
            ensure!(
                request.selected_capacity_policy.allows_source_free()
                    && plan.encoding_version() == 5,
                "source-free writes require format five policy"
            );
            target.arm_source_free_actual_bytes_v3_writes(
                policy,
                journal_bytes,
                old_zero_bytes,
                source_free_bytes,
                request.max_journal_bytes,
                &mut events,
            )?;
        } else if old_zero_bytes != 0 && !request.selected_capacity_policy.is_conservative() {
            ensure!(
                plan.encoding_version() == 4,
                "actual-byte capacity requires format four"
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
        } else if new_zero_bytes == 0 && new_copy_bytes == 0 {
            target.arm_writes(policy, &mut events)?;
        } else {
            target.arm_encoded_selected_writes(policy, journal_bytes, &mut events)?;
        }
        qualification::save(output, "activation-events.json", &events)?;
        events.clear();

        phase = "selected-apply";
        announce_conversion_phase("applying the selected ranges");
        let (applied, handoff) = match prepared {
            PreparedJournal::Exclusive(prepared) => {
                if fresh_exclusive_v3_first_write_fault {
                    let mut interrupted =
                        reconstruct::InterruptingGeneralTarget::new(&mut target, 1);
                    let _ = prepared.apply_and_handoff(&mut interrupted, |_| {
                        anyhow::bail!(
                            "exclusive first-write interruption was not reached; refusing HND"
                        )
                    })?;
                    anyhow::bail!(
                        "exclusive first-write interruption unexpectedly returned; no retry"
                    )
                }
                ensure!(
                    interrupt_after_writes.is_none() && copy_interruption_target.is_none(),
                    "prepared exclusive journal cannot enter a legacy fault path"
                );
                // The same journal borrow and completed validating readback
                // span metadata publication, source activation and durable HND.
                prepared.apply_and_handoff(&mut target, |applied| {
                    qualification::save(output, "apply.json", applied)?;
                    record_process_io(output, "applied")?;
                    phase = "selected-handoff";
                    announce_conversion_phase(
                        "completing ReFS handoff and verifying mounted file contents",
                    );
                    Ok(())
                })?
            }
            PreparedJournal::Legacy { journal, .. } => {
                let applied = match (interrupt_after_writes, copy_interruption_target.as_ref()) {
                    (Some(remaining), _) => {
                        // Legacy lab fault: flush and exit86 after accepted writes.
                        let mut interrupted =
                            reconstruct::InterruptingGeneralTarget::new(&mut target, remaining);
                        let result = sj::apply(&mut interrupted, journal, &plan, &ticket)?;
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
                        let result = sj::apply(&mut interrupted, journal, &plan, &ticket)?;
                        anyhow::bail!(
                            "first-copy interruption not reached: qualified copy at {} for {} bytes; {} ranges applied",
                            copy.offset,
                            copy.length,
                            result.range_count
                        )
                    }
                    (None, None) => sj::apply(&mut target, journal, &plan, &ticket)?,
                };
                qualification::save(output, "apply.json", &applied)?;
                record_process_io(output, "applied")?;
                phase = "selected-handoff";
                announce_conversion_phase(
                    "completing ReFS handoff and verifying mounted file contents",
                );
                let handoff = sj::handoff(&mut target, journal, &plan, &ticket)?;
                (applied, handoff)
            }
        };
        qualification::save(output, "handoff.json", &handoff)?;
        expectation.revalidate_domain()?;
        journal.require_native_mount_barriers(&ticket)?;
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
        let mut result = serde_json::json!({
            "schema_version":1,"kind":"experimental-allocation-bounded-conversion",
            "success":true,"source_admitted":true,"rollback_closed":true,
            "verification_policy":request.verification_policy,
            "actual_source_verification_policy":request.verification_policy,
            "raw_source_logical_hashes":!expectation.has_extent_only_streams()?,
            "raw_source_extent_only_streams":extent_streams,
            "raw_source_extent_only_partial_streams":partial_extent_streams,
            "actual_target_verification_policy":request.verification_policy,
            "actual_full_file_hashes":request.verification_policy.is_full_content(),
            "exclusive_apply_handoff_used":request.verification_policy.is_fast(),
            "prepared_journal_owner_reused":prepared_journal_owner_reused,
            "preparation_source_copy_bytes_reused":preparation_source_copy_bytes_reused,
            "exclusive_preparation_readback_used":request.verification_policy.is_fast()
                && interrupt_after_writes.is_none() && !interrupt_after_first_copy_write,
            "journal_path":journal_path,"ticket_sha256":ticket_pin,"plan_sha256":plan_pin,
            "expected_tree_sha256":expected_tree_sha256,
            "selected_ranges":plan.ranges.len(),"selected_bytes":selected_bytes,
            "journal_bytes":journal_bytes,"selection_sha256":proof.selection_sha256(),
            "packed_bytes":packed_bytes,"new_zero_bytes":new_zero_bytes,
            "new_copy_bytes":new_copy_bytes,
            "old_zero_bytes":old_zero_bytes,
            "old_zero_payload_storage_elided":old_zero_bytes > 0,
            "source_free_old_payload_storage_elided":source_free_bytes > 0,
            "source_free_bytes":source_free_bytes,
            "source_free_hash_table_bytes":source_free_bytes / 256,
            "rollback_preserves_free_space_contents":source_free_bytes == 0,
            "zero_payload_storage_elided":new_zero_bytes > 0,
            "free_space_contents_compared":false,"recovery_bundle_sha256":recovery_pin,
            "general_conversion_qualified":false,
        });
        if !request.selected_capacity_policy.is_conservative() {
            result["selected_capacity_policy"] =
                serde_json::to_value(request.selected_capacity_policy)?;
        }
        qualification::save(output, "result.json", &result)?;
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
