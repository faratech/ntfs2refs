//! Internal compact handoff/finalization. Source admission must authorize the
//! caller separately; capture JSON or a prepared journal alone never does so.
use super::*;
use crate::refs_hybrid::delta::VerifiedDeltaArtifact;

fn expectation(request: &Request, bytes: &[u8]) -> Result<shadow_tree::ExpectedTree> {
    ensure!(
        hex::encode(Sha256::digest(bytes)) == request.expected_tree_sha256,
        "compact target expectation pin differs"
    );
    let expected: shadow_tree::ExpectedTree = serde_json::from_slice(bytes)?;
    expected.validate_with_resource_profile(request.source_resource_profile.unwrap_or_default())?;
    Ok(expected)
}

fn checked_binding(
    request: &Request,
    artifact: &VerifiedDeltaArtifact,
    journal: &mut File,
    ticket: &JournalTicket,
    completed: bool,
) -> Result<(JournalBinding, String)> {
    let observed = observe_journal(journal, request)?;
    let identity = artifact.identity_sha256()?;
    let bound = compact_binding(request, &observed.identity, &identity)?;
    ensure!(
        ticket.schema_version == request.schema_version
            && ticket.binding == bound
            && ticket.journal_length == observed.file_bytes
            && ticket.journal_length <= request.max_journal_bytes
            && ticket.immutable_length.checked_add(8192) == Some(ticket.journal_length),
        "compact handoff ticket identity/length differs"
    );
    let descriptor = if completed {
        lab_reconstruct::inspect_completed_journal(journal, ticket, &bound)?
    } else {
        lab_reconstruct::inspect_journal(journal, ticket, &bound)?
    };
    ensure!(
        serde_json::to_vec(&descriptor.request)? == serde_json::to_vec(&request.comparison)?,
        "compact handoff request differs from immutable journal"
    );
    let ranges: Vec<_> = descriptor
        .patches
        .iter()
        .map(|patch| (patch.offset, patch.length))
        .collect();
    artifact.layout().require_exact_write_ranges(&ranges)?;
    Ok((bound, identity))
}

fn report(events: Vec<NativeEvent>, rollback_closed: bool) -> Finalization {
    Finalization {
        success: false,
        rollback_closed,
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
    }
}

fn verify_native(
    request: &Request,
    expected: &shadow_tree::ExpectedTree,
    report: &mut Finalization,
    restored_label: bool,
) {
    match verify_converted_tree(request, expected, &mut report.events, restored_label) {
        Ok(native) => {
            record_mount_paths(request, &native, report);
            report.native = Some(native);
            if report.error.is_none() {
                restore_source_label(request, report);
            }
            report.success = report.error.is_none();
        }
        Err(error) => report.error = Some(error.to_string()),
    }
}

/// Complete target/candidate hashes and durable HND write precede the first
/// native mount, exactly as in the legacy workflow. The compact source read
/// view is explicitly closed before the source can become online.
#[allow(dead_code, reason = "compact source admission not yet connected")]
pub(crate) fn finalize(
    request: &Request,
    mut target: GeneralJournaledPartition,
    native_shadow: &GeneralFrozenPartition,
    artifact: &mut VerifiedDeltaArtifact,
    journal: &mut File,
    ticket: &JournalTicket,
    expected_tree_bytes: &[u8],
) -> Result<Finalization> {
    request.validate()?;
    let expected = expectation(request, expected_tree_bytes)?;
    ensure!(
        target.binding() == &request.pair.source && native_shadow.binding() == &request.pair.shadow,
        "compact handoff device bindings differ"
    );
    let mut events = Vec::new();
    ensure!(
        target.state(&mut events)?.disk_attributes == 1
            && native_shadow.state(&mut events)?.disk_attributes == 3,
        "compact handoff requires offline target/frozen native shadow"
    );
    let shadow_before = native_shadow.state(&mut events)?;
    artifact.revalidate()?;
    let (bound, _) = checked_binding(request, artifact, journal, ticket, false)?;
    let mut original = target.read_only_view(&mut events)?;
    let read_before = original.state(&mut events)?;
    let mut image = artifact.image(&mut original)?;
    let mut result = report(events, false);
    // A partial marker also closes rollback. Never repair/retry it here.
    result.rollback_closed = true;
    let handoff = lab_reconstruct::mark_handoff(&mut target, &mut image, journal, ticket, &bound);
    drop(image);
    let read_after = original.state(&mut result.events);
    drop(original);
    match handoff {
        Ok(handoff) => result.handoff = Some(handoff),
        Err(error) => {
            result.error = Some(format!("{error:#}"));
            return Ok(result);
        }
    }
    if let Err(error) = (|| -> Result<()> {
        ensure!(
            read_after? == read_before,
            "compact handoff read-view route changed"
        );
        artifact.revalidate()?;
        ensure!(
            native_shadow.state(&mut result.events)? == shadow_before,
            "compact native shadow route changed during handoff"
        );
        Ok(())
    })() {
        result.error = Some(format!("{error:#}"));
        return Ok(result);
    }
    if let Err(error) = target.bring_online(&mut result.events) {
        result.error = Some(error.to_string());
        return Ok(result);
    }
    verify_native(request, &expected, &mut result, false);
    Ok(result)
}

/// Resume only an exact readable completed HND, with full image proofs and a
/// fresh journal sync/revalidation gate. Partial/unknown markers never mount.
#[allow(dead_code, reason = "compact recovery CLI not yet connected")]
pub(crate) fn finalize_after_marker(
    request: &Request,
    mut target: GeneralJournaledPartition,
    native_shadow: &GeneralFrozenPartition,
    artifact: &mut VerifiedDeltaArtifact,
    journal: &mut File,
    ticket: &JournalTicket,
    expected_tree_bytes: &[u8],
) -> Result<Finalization> {
    request.validate()?;
    let expected = expectation(request, expected_tree_bytes)?;
    ensure!(
        target.binding() == &request.pair.source && native_shadow.binding() == &request.pair.shadow,
        "completed compact handoff device bindings differ"
    );
    let mut events = Vec::new();
    ensure!(
        target.state(&mut events)?.disk_attributes == 1
            && native_shadow.state(&mut events)?.disk_attributes == 3,
        "completed compact handoff requires offline target/frozen shadow"
    );
    let shadow_before = native_shadow.state(&mut events)?;
    artifact.revalidate()?;
    let (bound, artifact_identity) = checked_binding(request, artifact, journal, ticket, true)?;
    let mut original = target.read_only_view(&mut events)?;
    let read_before = original.state(&mut events)?;
    let mut image = artifact.image(&mut original)?;
    let proof = lab_reconstruct::verify_completed_refs_marker_from_journal(
        &mut target,
        &mut image,
        journal,
        ticket,
        &bound,
        request.comparison.expected_length,
    )?;
    drop(image);
    ensure!(
        original.state(&mut events)? == read_before,
        "completed compact read-view route changed"
    );
    drop(original);
    artifact.revalidate()?;
    ensure!(
        native_shadow.state(&mut events)? == shadow_before,
        "completed compact native shadow route changed"
    );
    let durable = lab_reconstruct::guard_completed_marker_durability(
        journal,
        ticket,
        &bound,
        &proof,
        |file| {
            let observed = observe_journal(file, request)?;
            ensure!(
                observed.file_bytes == ticket.journal_length,
                "completed compact journal length changed"
            );
            compact_binding(request, &observed.identity, &artifact_identity)
        },
    )?;
    let mut result = report(events, true);
    result.completed_marker_proof = Some(proof);
    if let Err(error) = durable.with_mount(|| target.bring_online(&mut result.events)) {
        result.error = Some(error.to_string());
        return Ok(result);
    }
    let restored_label = if let Some(desired) = &request.expected_source_label {
        match rediscover_general_volume_wait(request.pair.source.clone(), &mut result.events)
            .and_then(|binding| n2r_win32::volume_label::observe_label(binding, "ReFS"))
        {
            Ok(observed) => observed.label == *desired,
            Err(error) => {
                result.error = Some(error.to_string());
                return Ok(result);
            }
        }
    } else {
        false
    };
    verify_native(request, &expected, &mut result, restored_label);
    Ok(result)
}

fn inspect_restored_ntfs(request: &Request, target: &mut GeneralJournaledPartition) -> Result<()> {
    let length = target.byte_len();
    let raw = ntfs_inspect::inspect_with_limits(
        target,
        length,
        ntfs_inspect::limits_for_resource_profile(
            request.source_resource_profile.unwrap_or_default(),
        ),
    )?;
    ntfs_backup::verify(target, length, &raw)?;
    ntfs_log::verify(target, &raw)?;
    Ok(())
}

fn rollback_report(events: Vec<NativeEvent>) -> RollbackFinalization {
    RollbackFinalization {
        success: false,
        // A partial marker also closes replay. Never repair it here.
        replay_closed: true,
        shadow_available: true,
        marker: None,
        completed_marker_proof: None,
        mounted_filesystem: None,
        error: None,
        events,
        production_conversion_qualified: false,
    }
}

fn verify_native_ntfs(request: &Request, report: &mut RollbackFinalization) {
    let mounted = rediscover_general_volume_wait(request.pair.source.clone(), &mut report.events)
        .and_then(|binding| mounted_filesystem_general(binding, &mut report.events));
    match mounted {
        Ok(name) if name == "NTFS" => {
            report.mounted_filesystem = Some(name);
            report.success = true;
        }
        Ok(name) => {
            report.mounted_filesystem = Some(name);
            report.error = Some("compact restored original did not mount as NTFS".into());
        }
        Err(error) => report.error = Some(error.to_string()),
    }
}

/// Close replay only after the complete original NTFS and compact candidate
/// have been rehashed. The existing marker writer flushes the restored target,
/// then durably records/readbacks ABT before any writable native NTFS mount.
#[allow(dead_code, reason = "compact rollback completion not yet connected")]
pub(crate) fn complete_rollback(
    request: &Request,
    mut target: GeneralJournaledPartition,
    native_shadow: &GeneralFrozenPartition,
    artifact: &mut VerifiedDeltaArtifact,
    journal: &mut File,
    ticket: &JournalTicket,
    mut events: Vec<NativeEvent>,
) -> Result<RollbackFinalization> {
    request.validate()?;
    ensure!(
        target.binding() == &request.pair.source && native_shadow.binding() == &request.pair.shadow,
        "compact NTFS rollback completion device bindings differ"
    );
    let target_before = target.state(&mut events)?;
    let shadow_before = native_shadow.state(&mut events)?;
    ensure!(
        target_before.disk_attributes == 1 && shadow_before.disk_attributes == 3,
        "compact NTFS rollback requires offline target/frozen native shadow"
    );
    artifact.revalidate()?;
    let (bound, _) = checked_binding(request, artifact, journal, ticket, false)?;
    inspect_restored_ntfs(request, &mut target)?;
    let mut original = target.read_only_view(&mut events)?;
    let read_before = original.state(&mut events)?;
    let mut image = artifact.image(&mut original)?;
    let mut result = rollback_report(events);
    let marker =
        lab_reconstruct::mark_rollback_complete(&mut target, &mut image, journal, ticket, &bound);
    drop(image);
    let read_after = original.state(&mut result.events);
    drop(original);
    match marker {
        Ok(marker) => result.marker = Some(marker),
        Err(error) => {
            result.error = Some(format!("{error:#}"));
            return Ok(result);
        }
    }
    if let Err(error) = (|| -> Result<()> {
        ensure!(
            read_after? == read_before && target.state(&mut result.events)? == target_before,
            "compact rollback target/read-view route changed"
        );
        artifact.revalidate()?;
        ensure!(
            native_shadow.state(&mut result.events)? == shadow_before,
            "compact native shadow route changed during rollback completion"
        );
        Ok(())
    })() {
        result.error = Some(format!("{error:#}"));
        return Ok(result);
    }
    if let Err(error) = target.bring_online(&mut result.events) {
        result.error = Some(error.to_string());
        return Ok(result);
    }
    verify_native_ntfs(request, &mut result);
    Ok(result)
}

/// Resume an exact completed ABT after process death. Full source/candidate
/// proofs and a fresh composite-bound journal durability gate precede mount;
/// readable partial/foreign markers are never repaired or promoted.
#[allow(dead_code, reason = "compact rollback recovery not yet connected")]
pub(crate) fn resume_completed_rollback(
    request: &Request,
    mut target: GeneralJournaledPartition,
    native_shadow: &GeneralFrozenPartition,
    artifact: &mut VerifiedDeltaArtifact,
    journal: &mut File,
    ticket: &JournalTicket,
    mut events: Vec<NativeEvent>,
) -> Result<RollbackFinalization> {
    request.validate()?;
    ensure!(
        target.binding() == &request.pair.source && native_shadow.binding() == &request.pair.shadow,
        "completed compact NTFS rollback device bindings differ"
    );
    let target_before = target.state(&mut events)?;
    let shadow_before = native_shadow.state(&mut events)?;
    ensure!(
        target_before.disk_attributes == 1 && shadow_before.disk_attributes == 3,
        "completed compact NTFS rollback requires offline target/frozen shadow"
    );
    artifact.revalidate()?;
    let (bound, artifact_identity) = checked_binding(request, artifact, journal, ticket, true)?;
    let mut original = target.read_only_view(&mut events)?;
    let read_before = original.state(&mut events)?;
    let mut image = artifact.image(&mut original)?;
    let proof = lab_reconstruct::verify_completed_marker(
        &mut target,
        &mut image,
        journal,
        ticket,
        &bound,
        lab_reconstruct::CompletionKind::NtfsRollback,
        request.comparison.expected_length,
        &request.comparison.source_sha256,
        &request.comparison.shadow_sha256,
    )?;
    drop(image);
    ensure!(
        original.state(&mut events)? == read_before,
        "completed compact rollback read-view route changed"
    );
    drop(original);
    inspect_restored_ntfs(request, &mut target)?;
    artifact.revalidate()?;
    ensure!(
        target.state(&mut events)? == target_before
            && native_shadow.state(&mut events)? == shadow_before,
        "completed compact rollback device route changed"
    );
    let durable = lab_reconstruct::guard_completed_marker_durability(
        journal,
        ticket,
        &bound,
        &proof,
        |file| {
            let observed = observe_journal(file, request)?;
            ensure!(
                observed.file_bytes == ticket.journal_length,
                "completed compact rollback journal length changed"
            );
            compact_binding(request, &observed.identity, &artifact_identity)
        },
    )?;
    let mut result = rollback_report(events);
    result.completed_marker_proof = Some(proof);
    if let Err(error) = durable.with_mount(|| target.bring_online(&mut result.events)) {
        result.error = Some(error.to_string());
        return Ok(result);
    }
    verify_native_ntfs(request, &mut result);
    Ok(result)
}
