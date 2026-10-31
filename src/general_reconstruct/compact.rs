//! Internal compact execution plumbing. Source admission and native handoff
//! remain separate prerequisites; no serialized capture flag grants writes.
use super::*;
use crate::refs_hybrid::delta::VerifiedDeltaArtifact;

fn ticket_descriptor(
    request: &Request,
    journal: &mut File,
    ticket: &JournalTicket,
    observed: &JournalFileSnapshot,
    bound: &JournalBinding,
) -> Result<JournalDescriptor> {
    ensure!(
        ticket.schema_version == request.schema_version
            && &ticket.binding == bound
            && ticket.journal_length == observed.file_bytes
            && ticket.journal_length <= request.max_journal_bytes
            && ticket.immutable_length.checked_add(8192) == Some(ticket.journal_length),
        "compact ticket identity/length differs"
    );
    let descriptor = lab_reconstruct::inspect_journal(journal, ticket, bound)?;
    ensure!(
        serde_json::to_vec(&descriptor.request)? == serde_json::to_vec(&request.comparison)?,
        "compact journal request differs"
    );
    Ok(descriptor)
}
fn bound(
    request: &Request,
    observed: &JournalFileSnapshot,
    artifact: &VerifiedDeltaArtifact,
) -> Result<JournalBinding> {
    let identity = artifact.identity_sha256()?;
    compact_binding(request, &observed.identity, &identity)
}
fn exact_ranges(
    artifact: &VerifiedDeltaArtifact,
    descriptor: &JournalDescriptor,
) -> Result<Vec<(u64, u64)>> {
    let ranges: Vec<_> = descriptor
        .patches
        .iter()
        .map(|p| (p.offset, p.length))
        .collect();
    artifact.layout().require_exact_write_ranges(&ranges)?;
    Ok(ranges)
}

#[allow(dead_code, reason = "compact source admission not yet connected")]
pub(crate) fn activate(
    request: &Request,
    source: GeneralFrozenPartition,
    native_shadow: &GeneralFrozenPartition,
    artifact: &mut VerifiedDeltaArtifact,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
) -> Result<GeneralJournaledPartition> {
    request.validate()?;
    ensure!(
        source.binding() == &request.pair.source && native_shadow.binding() == &request.pair.shadow,
        "compact activation device bindings differ"
    );
    let source_before = source.state(events)?;
    let shadow_before = native_shadow.state(events)?;
    ensure!(
        source_before.disk_attributes == 3 && shadow_before.disk_attributes == 3,
        "compact activation requires excluded read-only inputs"
    );
    artifact.revalidate()?;
    let before = observe_journal(journal, request)?;
    let binding = bound(request, &before, artifact)?;
    let descriptor = ticket_descriptor(request, journal, ticket, &before, &binding)?;
    exact_ranges(artifact, &descriptor)?;
    let target = source.activate_for_journal(events)?;
    ensure!(
        target.state(events)?.disk_attributes == 1 && native_shadow.state(events)? == shadow_before,
        "compact activation lost exclusion"
    );
    let after = observe_journal(journal, request)?;
    ensure!(
        after.identity == before.identity && after.file_bytes == before.file_bytes,
        "compact journal changed during activation"
    );
    Ok(target)
}

/// Full recovery hashes/normalized-source checks remain in the journal engine.
/// Its writes use journal bytes only; exact range coverage protects every byte
/// the candidate reader obtains from the current source complement.
#[allow(dead_code, reason = "compact source admission not yet connected")]
pub(crate) fn execute(
    operation: RecoveryOperation,
    request: &Request,
    target: &mut GeneralJournaledPartition,
    native_shadow: &GeneralFrozenPartition,
    artifact: &mut VerifiedDeltaArtifact,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
    interrupt: Option<u32>,
) -> Result<Execution> {
    request.validate()?;
    ensure!(
        interrupt.is_none_or(
            |n| (1..=4096).contains(&n) && matches!(operation, RecoveryOperation::Apply)
        ),
        "invalid compact interruption point"
    );
    ensure!(
        target.binding() == &request.pair.source && native_shadow.binding() == &request.pair.shadow,
        "compact execution device bindings differ"
    );
    let target_before = target.state(events)?;
    let shadow_before = native_shadow.state(events)?;
    ensure!(
        target_before.disk_attributes == 1 && shadow_before.disk_attributes == 3,
        "compact execution requires offline target/frozen native shadow"
    );
    artifact.revalidate()?;
    let before = observe_journal(journal, request)?;
    let binding = bound(request, &before, artifact)?;
    let descriptor = ticket_descriptor(request, journal, ticket, &before, &binding)?;
    let allowed = exact_ranges(artifact, &descriptor)?;
    if !allowed.is_empty() {
        target.arm_writes(
            WritePolicy {
                allowed,
                retained: request
                    .comparison
                    .retained_ranges
                    .iter()
                    .map(|r| (r.offset, r.length))
                    .collect(),
                maximum_bytes: descriptor.changed_bytes,
                journal_profile: request.journal_profile()?,
            },
            events,
        )?;
    }
    let mut original = target.read_only_view(events)?;
    let read_before = original.state(events)?;
    let mut image = artifact.image(&mut original)?;
    let result = match (operation, interrupt) {
        (RecoveryOperation::Apply, Some(remaining)) => {
            let mut interrupted = InterruptingGeneralTarget {
                inner: target,
                remaining,
            };
            let result =
                lab_reconstruct::apply(&mut interrupted, &mut image, journal, ticket, &binding)?;
            anyhow::bail!(
                "compact interruption not reached: {} patches",
                result.patches_written
            )
        }
        (RecoveryOperation::Apply | RecoveryOperation::Resume, None) => {
            lab_reconstruct::execute_compact(
                target, &mut image, journal, ticket, &binding, events, true,
            )?
        }
        (RecoveryOperation::Rollback, None) => lab_reconstruct::execute_compact(
            target, &mut image, journal, ticket, &binding, events, false,
        )?,
        _ => unreachable!(),
    };
    drop(image);
    ensure!(
        original.state(events)? == read_before,
        "compact complement view route changed"
    );
    drop(original);
    artifact.revalidate()?;
    let target_after = target.state(events)?;
    let shadow_after = native_shadow.state(events)?;
    let after = observe_journal(journal, request)?;
    ensure!(
        target_before == target_after
            && shadow_before == shadow_after
            && before.identity == after.identity
            && before.file_bytes == after.file_bytes,
        "compact execution storage state changed"
    );
    let expected_target_sha256 = if matches!(operation, RecoveryOperation::Rollback) {
        request.comparison.source_sha256.clone()
    } else {
        request.comparison.shadow_sha256.clone()
    };
    Ok(Execution {
        operation,
        result,
        expected_target_sha256,
        target_before,
        target_after,
        shadow_before,
        shadow_after,
        target_write_bytes_requested: target.native_write_bytes_requested,
        target_bytes_written: target.native_bytes_written,
        source_admitted: false,
        conversion_qualified: false,
    })
}
