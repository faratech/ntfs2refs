//! Experimental owning-process conversion using a freshly admitted source and
//! a compact, completely compared native target. This is not a CLI entry point.
//! Full-shadow conversion and recovery behavior remain unchanged.
use super::*;
use n2r_win32::GeneralFrozenPartition;

/// Retain the original source admission capability through compact preparation,
/// activation and handoff. A source-backed capture/report alone never enters
/// this path. The optional stop uses the existing flushed-write fault injector.
pub(crate) fn convert_composite_existing_experimental(
    request: &Request,
    output: &Path,
    interrupt_after_writes: Option<u32>,
) -> Result<()> {
    convert_composite(request, output, None, interrupt_after_writes, false)
}

pub(crate) fn convert_composite_fresh_experimental(
    request: &Request,
    output: &Path,
    construction: qualification::CompactConstructionBudget,
    interrupt_after_writes: Option<u32>,
) -> Result<()> {
    construction.validate(request.pair.source.identity.partition_bytes)?;
    convert_composite(
        request,
        output,
        Some(construction),
        interrupt_after_writes,
        false,
    )
}

pub(super) fn convert_compact_selected(
    request: &Request,
    construction: qualification::CompactConstructionBudget,
    output: &Path,
) -> Result<()> {
    convert_composite(request, output, Some(construction), None, true)
}

fn selected_device_preflight(request: &Request) -> Result<serde_json::Value> {
    use n2r_win32::discovery::{self, Role};
    let source = discovery::discover(
        &format!("{}\\", request.pair.source.volume_path()?),
        Role::Source,
    )?;
    let shadow = discovery::discover(
        &format!("{}\\", request.pair.shadow.volume_path()?),
        Role::Shadow,
    )?;
    let journal = discovery::discover(
        &format!("{}\\", request.journal.disk.volume_path()?),
        Role::Journal {
            allow_additional_partitions: request.journal.allow_additional_partitions,
        },
    )?;
    ensure!(
        source.binding == request.pair.source
            && shadow.binding == request.pair.shadow
            && journal.binding == request.journal.disk
            && source.filesystem == "NTFS"
            && shadow.filesystem == "ReFS"
            && shadow.label == "n2r-retained-shadow"
            && shadow.bytes_per_sector == 512
            && shadow.sectors_per_cluster == 8
            && matches!(journal.filesystem.as_str(), "NTFS" | "ReFS"),
        "selected source/shadow/journal native identities or filesystems differ"
    );
    let mut events = Vec::new();
    let mut reader = n2r_win32::GeneralPartitionReader::open(source.binding.clone(), &mut events)?;
    let mut boot = [0u8; 512];
    reader.read_exact(&mut boot)?;
    let geometry = crate::ntfs_inspect::inspect_boot_sector(&boot, reader.byte_len())?;
    ensure!(
        request
            .source_resource_profile
            .unwrap_or_default()
            .supports_source_geometry(&geometry),
        "selected source geometry exceeds the compact profile"
    );
    reader.revalidate_route(&mut events)?;
    let journal_space = discovery::observe_volume_space(&journal.volume_guid_path)?;
    ensure!(
        journal_space.available_bytes_to_caller
            >= n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE + 8192,
        "independent journal lacks minimum preparation space"
    );
    Ok(
        serde_json::json!({"kind":"read-only-selected-compact-preflight",
        "source":source,"shadow":shadow,"journal":journal,"source_geometry":geometry,
        "source_geometry_events":events,"journal_space":journal_space,
        "source_frozen":false,"source_admitted":false,"execution_authorized":false,
        "space_reserved":false}),
    )
}

fn convert_composite(
    request: &Request,
    output: &Path,
    construction: Option<qualification::CompactConstructionBudget>,
    interrupt_after_writes: Option<u32>,
    selected_devices: bool,
) -> Result<()> {
    request.validate()?;
    ensure!(
        request.verify_existing_shadow == construction.is_none(),
        "experimental composite fresh/existing selection differs from its request"
    );
    ensure!(
        interrupt_after_writes.is_none_or(|writes| (1..=4096).contains(&writes)),
        "composite interruption count must be 1..=4096"
    );
    let selected_preflight = if selected_devices {
        Some(selected_device_preflight(request)?)
    } else {
        None
    };
    qualification::create_output(output)?;
    if let Some(observation) = selected_preflight {
        qualification::save(output, "selected-device-preflight.json", &observation)?;
    }
    qualification::save(
        output,
        "conversion-intent.json",
        &serde_json::json!({
            "schema_version":1,"kind":"experimental-live-composite-conversion-intent",
            "request":request,"interrupt_after_writes":interrupt_after_writes,
            "construction_budget":construction,
            "selected_device_construction_enrollment":selected_devices,
            "requires_original_live_source_certificate":true,
            "source_admitted":false,"execution_authorized":false,
            "general_conversion_qualified":false,
        }),
    )?;
    let mut phase = "composite-qualification";
    let attempted = (|| -> Result<()> {
        let profile = JournalProfile::from_schema(request.schema_version)?;
        let maximum = crate::lab_reconstruct::changed_byte_budget_for_profile(
            profile,
            request.max_journal_bytes,
            request.pair.source.identity.partition_bytes,
        )?;
        let qualification_root = output.join("qualification");
        let packed_path = qualification_root.join("changed-clusters.bin");
        let qualification::QualifiedCompositeTree {
            mut source,
            native_target,
            proof,
            mut artifact,
            certificate,
            comparison,
            tree: _,
            expected,
            mount_paths,
            source_label,
        } = if let Some(budget) = construction {
            if selected_devices {
                qualification::prepare_composite_fresh_selected(
                    request.pair.clone(),
                    &qualification_root,
                    &packed_path,
                    maximum,
                    profile,
                    request.source_resource_profile.unwrap_or_default(),
                    budget,
                )?
            } else {
                qualification::prepare_composite_fresh(
                    request.pair.clone(),
                    &qualification_root,
                    &packed_path,
                    maximum,
                    profile,
                    request.source_resource_profile.unwrap_or_default(),
                    budget,
                    |_, _, _| Ok(()),
                )?
            }
        } else {
            qualification::prepare_composite_existing(
                request.pair.clone(),
                &qualification_root,
                &packed_path,
                maximum,
                profile,
                request.source_resource_profile.unwrap_or_default(),
                |_, _, _| Ok(()),
            )?
        };
        let plan = reconstruct::Request {
            schema_version: request.schema_version,
            source_resource_profile: request.source_resource_profile,
            experiment_id: request.experiment_id.clone(),
            expected_tree_sha256: hex::encode(Sha256::digest(&expected)),
            expected_mount_paths: Some(mount_paths.paths),
            expected_source_label: Some(source_label.label().clone()),
            pair: request.pair.clone(),
            comparison,
            journal: request.journal.clone(),
            max_journal_bytes: request.max_journal_bytes,
        };
        plan.validate()?;
        ensure!(
            certificate.binds_request(&plan),
            "original live source certificate does not bind the exact composite plan"
        );
        ensure!(
            proof.data_ties_verified()
                && proof.target_sha256() == plan.comparison.shadow_sha256
                && proof.source_sha256() == plan.comparison.source_sha256
                && proof.expected_tree_sha256() == plan.expected_tree_sha256,
            "live composite proof differs from the certified conversion plan"
        );
        let request_pin = qualification::save(output, "request.json", &plan)?;
        let expectation: crate::shadow_tree::ExpectedTree = serde_json::from_slice(&expected)?;
        qualification::save(output, "expectation.json", &expectation)?;
        artifact.revalidate()?;
        let artifact_identity = artifact.identity_sha256()?;
        qualification::save(
            output,
            "compact-backing.json",
            &serde_json::json!({
                "schema_version":1,"kind":"experimental-live-composite-recovery-backing",
                "report_path":qualification_root.join("composite-capture.json"),
                "packed_path":packed_path,"artifact":artifact.pins(),
                "artifact_identity_sha256":artifact_identity,"request_sha256":request_pin,
                "expected_tree_sha256":plan.expected_tree_sha256,
                "serialized_report_is_not_source_admission":true,
            }),
        )?;

        phase = "compact-journal-preparation";
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
            "ordinary composite journal parent required"
        );
        let directory = parent.join(&request.experiment_id);
        ensure!(
            !directory.exists(),
            "fresh composite journal experiment required"
        );
        fs::create_dir(&directory)?;
        let journal_path = directory.join("reconstruction.journal");
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
            "fresh empty composite journal required"
        );
        qualification::save(
            output,
            "journal-location.json",
            &serde_json::json!({
                "path":journal_path,"identity":observed.identity,
            }),
        )?;
        let mut progress = crate::preparation_progress::SnapshotFile::create(
            &output.join("journal-progress.json"),
        );
        let mut preparation_events = Vec::new();
        // This second handle supplies read-only complement bytes only. The
        // ORIGINAL source above retains the actual admission/freeze context.
        let mut complement =
            GeneralFrozenPartition::reopen(plan.pair.source.clone(), &mut preparation_events)?;
        let complement_before = complement.state(&mut preparation_events)?;
        let source_before = source.state(&mut preparation_events)?;
        ensure!(
            complement_before == source_before && complement_before.disk_attributes == 3,
            "compact preparation complement differs from the admitted source"
        );
        let mut image = artifact.image(&mut complement)?;
        let prepared = reconstruct::prepare_compact_with_progress(
            &plan,
            &mut source,
            &native_target,
            &mut image,
            &mut journal,
            &artifact_identity,
            &mut |snapshot| progress.report(snapshot),
        )?;
        drop(image);
        ensure!(
            complement.state(&mut preparation_events)? == complement_before
                && source.state(&mut preparation_events)? == source_before,
            "compact source or complement changed during journal preparation"
        );
        // No stale attrs3 source/complement reader survives activation or a
        // native mount. Execution creates its own bounded attrs1 read view.
        drop(complement);
        artifact.revalidate()?;
        let descriptor = crate::lab_reconstruct::inspect_journal(
            &mut journal,
            &prepared.journal.ticket,
            &prepared.observed_binding,
        )?;
        let ranges: Vec<_> = descriptor
            .patches
            .iter()
            .map(|patch| (patch.offset, patch.length))
            .collect();
        artifact.layout().require_exact_write_ranges(&ranges)?;
        ensure!(
            prepared.journal.expected_postimage_sha256 == plan.comparison.shadow_sha256
                && prepared.journal.changed_bytes == artifact.layout().changed_bytes(),
            "compact journal does not reconstruct the exact admitted target"
        );
        qualification::save(output, "prepare.json", &prepared)?;
        qualification::save(output, "preparation-events.json", &preparation_events)?;
        let ticket_pin = qualification::save(output, "ticket.json", &prepared.journal.ticket)?;
        // Keep the durable external ticket open exclusively until finalization.
        let mut ticket_file = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(output.join("ticket.json"))?;
        let mut ticket_bytes = Vec::new();
        (&mut ticket_file)
            .take(65537)
            .read_to_end(&mut ticket_bytes)?;
        ensure!(
            ticket_bytes.len() <= 65536 && hex::encode(Sha256::digest(&ticket_bytes)) == ticket_pin,
            "durable composite ticket readback differs"
        );
        let ticket: crate::lab_reconstruct::JournalTicket = serde_json::from_slice(&ticket_bytes)?;
        ensure!(
            serde_json::to_vec(&ticket)? == serde_json::to_vec(&prepared.journal.ticket)?,
            "persisted composite ticket differs from live preparation"
        );
        if let Some(writes) = interrupt_after_writes {
            qualification::save(
                output,
                "interruption-intent.json",
                &serde_json::json!({
                    "schema_version":1,"kind":"controlled-composite-conversion-interruption-intent",
                    "interrupt_after_writes":writes,"expected_process_exit_code":86,
                    "ticket_sha256":ticket_pin,"journal_path":journal_path,
                    "artifact_identity_sha256":artifact_identity,
                    "handoff_authorized":false,"ordinary_conversion_behavior_changed":false,
                }),
            )?;
        }

        phase = "compact-activation";
        ensure!(
            certificate.binds_request(&plan),
            "original live certificate no longer binds the composite activation plan"
        );
        let mut events = Vec::<NativeEvent>::new();
        let mut original = reconstruct::compact::activate(
            &plan,
            source,
            &native_target,
            &mut artifact,
            &mut journal,
            &ticket,
            &mut events,
        )?;
        qualification::save(output, "activation-events.json", &events)?;
        events.clear();
        phase = "compact-apply";
        let applied = reconstruct::compact::execute(
            reconstruct::RecoveryOperation::Apply,
            &plan,
            &mut original,
            &native_target,
            &mut artifact,
            &mut journal,
            &ticket,
            &mut events,
            interrupt_after_writes,
        )?;
        qualification::save(output, "apply.json", &applied)?;
        qualification::save(output, "apply-events.json", &events)?;
        phase = "compact-handoff";
        let finalization = reconstruct::compact_finalize::finalize(
            &plan,
            original,
            &native_target,
            &mut artifact,
            &mut journal,
            &ticket,
            &expected,
        )?;
        qualification::save(output, "finalization.json", &finalization)?;
        ensure!(
            finalization.success,
            "experimental compact native handoff failed: {:?}",
            finalization.error
        );
        qualification::save(
            output,
            "result.json",
            &serde_json::json!({
                "schema_version":1,"kind":"experimental-certificate-backed-composite-conversion",
                "success":true,"source_admitted":true,"rollback_closed":finalization.rollback_closed,
                "journal_path":journal_path,"ticket_sha256":ticket_pin,
                "artifact_identity_sha256":artifact_identity,
                "expected_tree_sha256":plan.expected_tree_sha256,"comparison":plan.comparison,
                "complete_native_address_space_compared":true,
                "changed_bytes":artifact.layout().changed_bytes(),
                "general_conversion_qualified":false,
            }),
        )?;
        // Retain both live proof and separately pinned recovery artifact until
        // the final native outcome and evidence are durable.
        drop(proof);
        Ok(())
    })();
    if let Err(error) = attempted {
        qualification::save(
            output,
            "failed.json",
            &serde_json::json!({
                "phase":phase,"error":format!("{error:#}"),"recovery_materials":output,
                "automatic_rollback_attempted":false,"general_conversion_qualified":false,
            }),
        )?;
        return Err(error);
    }
    Ok(())
}
