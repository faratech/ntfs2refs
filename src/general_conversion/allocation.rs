//! Experimental allocation-bounded conversion under the ntfs2btrfs-style
//! guarantee: only ranges the protected frozen shadow's native allocator reports
//! allocated are compared, journaled and written. The original live certificate
//! is still required. Recovery after an interruption is lab-only for now: the
//! public recovery bundle and typed Resume/Rollback do not read `N2RSEL01`.
use super::*;
use crate::selected_journal as sj;
use n2r_win32::{GeneralFrozenPartition, WritePolicy};

fn announce_conversion_phase(message: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "Conversion: {message}");
}

pub(super) fn convert_allocation_selected(
    request: &Request,
    construction: qualification::CompactConstructionBudget,
    output: &Path,
) -> Result<()> {
    request.validate()?;
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
            "requires_original_live_source_certificate":true,
            "free_space_contents_compared":false,"public_recovery_supported":false,
            "source_admitted":false,"execution_authorized":false,
            "general_conversion_qualified":false,
        }),
    )?;
    let mut phase = "allocation-bounded-qualification";
    let attempted = (|| -> Result<()> {
        let profile = JournalProfile::from_schema(request.schema_version)?;
        let maximum = crate::lab_reconstruct::changed_byte_budget_for_profile(
            profile,
            request.max_journal_bytes,
            request.pair.source.identity.partition_bytes,
        )?;
        let qualification_root = output.join("qualification");
        let packed_path = qualification_root.join("changed-clusters.bin");
        announce_conversion_phase(
            "inspecting NTFS, building the ReFS shadow and comparing its allocated ranges",
        );
        let qualification::QualifiedAllocationTree {
            mut source,
            native_target,
            mut proof,
            certificate,
            expected,
            mount_paths,
            source_label,
        } = qualification::prepare_allocation_fresh_selected(
            request.pair.clone(),
            &qualification_root,
            &packed_path,
            maximum,
            profile,
            request.source_resource_profile.unwrap_or_default(),
            construction,
        )?;
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
        let plan_pin = qualification::save(output, "selected-plan.json", &plan)?;

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
                "path":journal_path,"identity":observed.identity,"format":"N2RSEL01",
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
            sj::prepare(&mut source, &mut image, &mut journal, &plan)?
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
        qualification::save(
            output,
            "selected-recovery.json",
            &serde_json::json!({
                "schema_version":1,"kind":"lab-only-selected-recovery-pins",
                "plan":output.join("selected-plan.json"),"plan_sha256":plan_pin,
                "ticket":output.join("selected-ticket.json"),"ticket_sha256":ticket_pin,
                "journal":journal_path,"packed":packed_path,
                "expectation_sha256":expectation_pin,
                "public_recovery_supported":false,
                "note":"Resume or roll back only with selected_journal and this exact plan and ticket, on the lab VM.",
            }),
        )?;
        println!("Recovery directory: {}", output.display());

        phase = "selected-activation";
        announce_conversion_phase("activating the frozen source for selected writes");
        ensure!(
            certificate.binds(&proof),
            "original live certificate no longer binds the allocation-bounded proof"
        );
        let mut events = Vec::<NativeEvent>::new();
        let shadow_before = native_target.state(&mut events)?;
        let mut target = source.activate_for_journal(&mut events)?;
        ensure!(
            target.state(&mut events)?.disk_attributes == 1
                && native_target.state(&mut events)? == shadow_before,
            "selected activation lost exclusion"
        );
        target.arm_writes(
            WritePolicy {
                allowed: plan.ranges.iter().map(|r| (r.offset, r.length)).collect(),
                retained: Vec::new(),
                maximum_bytes: selected_bytes,
                journal_profile: profile,
            },
            &mut events,
        )?;
        qualification::save(output, "activation-events.json", &events)?;
        events.clear();

        phase = "selected-apply";
        announce_conversion_phase("applying the selected ranges");
        let applied = sj::apply(&mut target, &mut journal, &plan, &ticket)?;
        qualification::save(output, "apply.json", &applied)?;

        phase = "selected-handoff";
        announce_conversion_phase("completing ReFS handoff and verifying mounted file contents");
        let handoff = sj::handoff(&mut target, &mut journal, &plan, &ticket)?;
        qualification::save(output, "handoff.json", &handoff)?;
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
                reconstruct::verify_native_scoped(&scope, &expectation, &mut finalization, false);
            }
            Err(error) => finalization.error = Some(error.to_string()),
        }
        qualification::save(output, "finalization.json", &finalization)?;
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
                "journal_path":journal_path,"ticket_sha256":ticket_pin,"plan_sha256":plan_pin,
                "expected_tree_sha256":expected_tree_sha256,
                "selected_ranges":plan.ranges.len(),"selected_bytes":selected_bytes,
                "journal_bytes":journal_bytes,"selection_sha256":proof.selection_sha256(),
                "free_space_contents_compared":false,"public_recovery_supported":false,
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
                "automatic_rollback_attempted":false,"public_recovery_supported":false,
                "general_conversion_qualified":false,
            }),
        )?;
        return Err(error);
    }
    Ok(())
}
