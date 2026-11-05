//! One-shot partition source certificate -> actual publication/AP/native writer.
//! Dedicated apply remains independent. Reports/DTOs never issue this owner.
use super::*;
use crate::{
    general_source_admission::resource::{
        PreparedResourceSourceAdmission, partition::PartitionResourceSourceContext,
    },
    selected_journal::{self as sj, MarkerKind, SelectedResult},
};
use n2r_win32::{NativeEvent, PartitionOwnerToken};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    sync::Arc,
};

/// Actual completed non-discovery source flush/readback facts only. This is
/// diagnostic progress, never a writer/recovery token or first-write proof.
#[derive(Serialize)]
pub(crate) struct PartitionPostFlushReceipt {
    pub kind: &'static str,
    pub image_length: u64,
    pub selected_bytes: u64,
    pub range_count: u32,
    pub native_bytes_written: u64,
    pub delayed_discovery_bytes: u64,
    pub immutable_journal_sha256: [u8; 32],
    pub flush_and_pending_readback_succeeded: bool,
    pub first_flushed_write_qualified: bool,
}

pub(crate) struct PartitionResourcePreparedConversion<'j, 'd, 'c, 'p, 's, 'e> {
    prepared: PartitionProtectedPreparedJournal<'j, 'd, 'c, 'p, 's>,
    expected: &'e PagedExpectedTree,
    maps: Option<V4RecoveryMaps>,
    locator: super::super::super::durable_anchor::DurableRecoveryLocator,
    metadata: PartitionMetadataPublication,
    closure: PreparedArenaClosure,
    _memory: ArenaRamLease,
}
pub(crate) struct PartitionFreshApply<'j, 'd, 'c, 'p, 's, 'e> {
    published: PartitionResourcePreparedConversion<'j, 'd, 'c, 'p, 's, 'e>,
    certificate: PreparedResourceSourceAdmission,
}
/// Only actual completed native apply/HND can construct this terminal outcome.
/// It owns a same-J SDK witness, never a success boolean or stale NTFS proof.
pub(crate) struct PartitionApplyOutcome {
    witness: n2r_win32::PartitionHandoffWitness,
    source: PartitionOwnerToken,
    scope: Arc<crate::general_composite_target::paged::CaptureScopeIdentity>,
    applied: SelectedResult,
    handoff: SelectedResult,
    native_bytes_written: u64,
    verification: PartitionRetainedVerification,
}
impl<'j, 'd, 'c, 'p, 's, 'e> PartitionResourcePreparedConversion<'j, 'd, 'c, 'p, 's, 'e> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish(
        mut prepared: PartitionProtectedPreparedJournal<'j, 'd, 'c, 'p, 's>,
        expected: &'e PagedExpectedTree,
        map_group: Option<&ArtifactGroupPermit>,
        map_scratch: &SourceScratch,
        map_path: Option<&Path>,
        recovery_group: &ArtifactGroupPermit,
        recovery_scratch: &SourceScratch,
        locator_path: &Path,
        publication_path: &Path,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<Self> {
        checkpoint_native_events(events, &mut checkpoint)?;
        prepared.revalidate(events)?;
        let arena = prepared.context.arena().clone();
        ensure!(
            recovery_group.group() == ArtifactGroup::RecoveryCopy
                && recovery_group.arena().same_arena(&arena),
            "partition publication recovery group differs from actual arena"
        );
        let memory = arena.reserve_ram(1024 * 1024)?;
        let required = expected_requires_maps(expected, prepared.context.verification_policy())?;
        ensure!(
            required == map_group.is_some() && required == map_path.is_some(),
            "actual partition recovery-map requirement differs"
        );
        let maps = if let (Some(group), Some(path)) = (map_group, map_path) {
            let value = V4RecoveryMaps::create_partition(
                prepared.candidate.protected_proof(),
                expected,
                prepared.context,
                prepared.domain,
                &prepared.ticket,
                group,
                map_scratch,
                path,
            )?;
            group.seal()?;
            Some(value)
        } else {
            None
        };
        checkpoint_native_events(events, &mut checkpoint)?;
        prepared.revalidate(events)?;
        let mut observation =
            super::super::super::reopen::BoundJournalObservation::from_prepared_creation(
                prepared.journal,
                &prepared.facts.native,
                &prepared.ticket,
                &prepared.write_index,
                recovery_scratch,
            )?;
        let mut locator=prepared.context.with_publication_handoff(events,|owner,admission,stable,events|{
            super::super::super::durable_anchor::DurableRecoveryLocator::create_partition_from_actual_owners(
                owner,stable,admission,&mut observation,recovery_group,recovery_scratch,locator_path,events)
        })?;
        let metadata = persist_partition_metadata(
            prepared.context,
            expected,
            maps.as_ref(),
            &mut locator,
            &mut observation,
            prepared.facts.native.shadow,
            recovery_group,
            recovery_scratch,
            publication_path,
            events,
        )?;
        drop(observation);
        prepared.revalidate(events)?;
        checkpoint_native_events(events, &mut checkpoint)?;
        let closure = arena.close_prepared(prepared.facts.native.journal_quota)?;
        let mut result = Self {
            prepared,
            expected,
            maps,
            locator,
            metadata,
            closure,
            _memory: memory,
        };
        result.revalidate(events)?;
        checkpoint_native_events(events, &mut checkpoint)?;
        Ok(result)
    }
    pub(crate) fn revalidate(&mut self, events: &mut Vec<NativeEvent>) -> Result<()> {
        self.closure.revalidate()?;
        self.metadata.publication_lease().revalidate()?;
        self.metadata.checksum_lease().revalidate()?;
        self.locator.revalidate()?;
        self.prepared.revalidate(events)?;
        let p = &mut self.prepared;
        let token = p.context.owner_token();
        p.candidate
            .protected_proof()
            .native()
            .require_partition_source_owner(&token)?;
        p.write_index
            .require_same_sealed_journal(p.journal, &p.ticket)?;
        ensure!(
            same_ticket(self.locator.ticket(), &p.ticket)?
                && self.locator.source() == &p.context.binding().storage
                && self.locator.journal_binding() == p.facts.native.binding
                && self.locator.journal_identity() == *p.facts.native.identity
                && self.locator.journal_path() == p.facts.native.path,
            "partition publication/actual J locator ownership changed"
        );
        self.locator
            .source_scope()
            .require_journal_route(&p.context.binding().storage, p.facts.native.binding)?;
        if let Some(maps) = &self.maps {
            maps.require_binding_partition(
                p.candidate.protected_proof(),
                self.expected,
                p.context,
                p.domain,
                &p.ticket,
            )?;
        }
        ensure!(
            expected_requires_maps(self.expected, p.context.verification_policy())?
                == self.maps.is_some(),
            "actual partition maps requirement changed"
        );
        Ok(())
    }
    pub(crate) fn into_fresh_apply(
        mut self,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<PartitionFreshApply<'j, 'd, 'c, 'p, 's, 'e>> {
        self.revalidate(events)?;
        checkpoint_native_events(events, &mut checkpoint)?;
        let p = &mut self.prepared;
        ensure!(
            p.ticket.marker_profile.is_none(),
            "partition fresh apply requires actual markerless ticket"
        );
        let certificate = p.context.qualify_prepared_target(
            p.candidate.protected_proof(),
            self.expected,
            &self.closure,
            events,
        )?;
        certificate.require_partition_binding(
            p.context,
            p.candidate.protected_proof(),
            self.expected,
            &self.closure,
        )?;
        self.revalidate(events)?;
        checkpoint_native_events(events, &mut checkpoint)?;
        Ok(PartitionFreshApply {
            published: self,
            certificate,
        })
    }
}
pub(crate) enum PartitionExecutionOutcome {
    Handoff(PartitionApplyOutcome),
    Interrupted(PartitionApplyFailure),
}
pub(crate) struct PartitionApplyFailure {
    error: anyhow::Error,
    source: PartitionOwnerToken,
    scope: Arc<crate::general_composite_target::paged::CaptureScopeIdentity>,
    _original_certificate: PreparedResourceSourceAdmission,
}
impl PartitionApplyFailure {
    pub(crate) fn error(&self) -> &anyhow::Error {
        &self.error
    }
    pub(crate) fn require_owner_scope(
        &self,
        context: &PartitionResourceSourceContext,
        proof: &crate::general_composite_target::paged::ProtectedPagedTargetSelection,
    ) -> Result<()> {
        ensure!(
            self.source.same_owner(&context.owner_token())
                && Arc::ptr_eq(&self.scope, &proof.scope().capture_identity()),
            "interrupted partition execution is not this original source/capture"
        );
        Ok(())
    }
}
fn write_partition_span(
    writer: &mut n2r_win32::PartitionPagedWriter<'_, '_>,
    domain: &ResourceJournalDomain<'_>,
    ordinal: u64,
    row: JournalLayoutRow,
    start: u64,
    length: u64,
    buffers: &mut super::apply::Buffers,
) -> Result<()> {
    ensure!(
        start
            .checked_add(length)
            .is_some_and(|end| end <= row.capture.length),
        "partition span escapes actual descriptor"
    );
    let original = {
        let mut journal = writer.journal_read_view()?;
        super::apply::record(row, domain, &mut journal)?
    };
    let mut done = 0;
    while done < length {
        let count = usize::try_from((length - done).min(BUFFER as u64))?;
        let within = add(start, done)?;
        let offset = add(row.capture.offset, within)?;
        at(writer, offset, &mut buffers.current[..count])?;
        {
            let mut journal = writer.journal_read_view()?;
            super::apply::read_new(
                domain,
                &mut journal,
                row,
                ordinal,
                within,
                &mut buffers.new[..count],
            )?;
            if row.capture.old_is_source_free {
                sj::check_free_granules(
                    &mut journal,
                    &original,
                    within,
                    &buffers.current[..count],
                    Some(&buffers.new[..count]),
                )?;
            } else {
                sj::read_before(&mut journal, &original, within, &mut buffers.old[..count])?;
                ensure!(
                    sj::bytes_are_old_or_new(
                        &buffers.current[..count],
                        &buffers.old[..count],
                        &buffers.new[..count]
                    ),
                    "partition selected bytes changed immediately before native write"
                );
            }
        }
        if buffers.current[..count] != buffers.new[..count] {
            writer.seek(SeekFrom::Start(offset))?;
            ensure!(
                writer.write(&buffers.new[..count])? == count,
                "short bounded partition native write"
            );
        }
        done = add(done, count as u64)?;
    }
    Ok(())
}
impl<'j, 'd, 'c, 'p, 's, 'e> PartitionFreshApply<'j, 'd, 'c, 'p, 's, 'e> {
    /// Consumes actual original admission exactly once. Failure is an explicit
    /// interrupted execution, never a request to hash or restore stale NTFS.
    pub(crate) fn apply_and_handoff(
        self,
        events: &mut Vec<NativeEvent>,
        checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
        after_apply: impl FnOnce(&SelectedResult) -> Result<()>,
    ) -> PartitionExecutionOutcome {
        self.apply_and_handoff_inner(events, checkpoint, after_apply,
            None::<fn(&PartitionPostFlushReceipt, &mut Vec<NativeEvent>) -> Result<()>>)
    }
    /// Explicit lab progress observer. The default entry above stays hook-free.
    /// Returning an error preserves actual AP/private recovery state; no retry.
    pub(crate) fn apply_and_handoff_with_post_flush(
        self,
        events: &mut Vec<NativeEvent>,
        checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
        after_apply: impl FnOnce(&SelectedResult) -> Result<()>,
        post_flush: impl FnOnce(&PartitionPostFlushReceipt, &mut Vec<NativeEvent>) -> Result<()>,
    ) -> PartitionExecutionOutcome {
        self.apply_and_handoff_inner(events, checkpoint, after_apply, Some(post_flush))
    }
    fn apply_and_handoff_inner(
        mut self,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
        after_apply: impl FnOnce(&SelectedResult) -> Result<()>,
        post_flush: Option<impl FnOnce(&PartitionPostFlushReceipt, &mut Vec<NativeEvent>) -> Result<()>>,
    ) -> PartitionExecutionOutcome {
        let source = self.published.prepared.context.owner_token();
        let scope = self
            .published
            .prepared
            .candidate
            .protected_proof()
            .scope()
            .capture_identity();
        match self.try_apply(events, &mut checkpoint, after_apply, post_flush) {
            Ok(outcome) => PartitionExecutionOutcome::Handoff(outcome),
            Err(error) => PartitionExecutionOutcome::Interrupted(PartitionApplyFailure {
                error,
                source,
                scope,
                _original_certificate: self.certificate,
            }),
        }
    }
    fn try_apply(
        &mut self,
        events: &mut Vec<NativeEvent>,
        checkpoint: &mut impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
        after_apply: impl FnOnce(&SelectedResult) -> Result<()>,
        post_flush: Option<impl FnOnce(&PartitionPostFlushReceipt, &mut Vec<NativeEvent>) -> Result<()>>,
    ) -> Result<PartitionApplyOutcome> {
        checkpoint_native_events(events, checkpoint)?;
        self.published.revalidate(events)?;
        let p = &mut self.published.prepared;
        let ticket = &p.ticket;
        let proof = p.candidate.protected_proof();
        self.certificate.require_partition_binding(
            p.context,
            proof,
            self.published.expected,
            &self.published.closure,
        )?;
        let _memory = self
            .published
            .closure
            .arena()
            .reserve_ram(12 * BUFFER as u64)?;
        let mut buffers = super::apply::Buffers::new();
        p.write_index
            .require_same_sealed_journal(p.journal, ticket)?;
        ensure!(
            sj::classify(p.journal, ticket)? == sj::SelectedLifecycle::PreparedClear,
            "partition apply requires real clear lifecycle"
        );
        let facts = &p.facts.native;
        let policy = p.write_index.policy();
        let pins = n2r_win32::PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        let source_token = p.context.owner_token();
        let scope = proof.scope().capture_identity();
        let (source, admission) = p.context.source_and_admission_for_fresh_apply();
        let mut gate = p
            .journal
            .qualify_sealed_partition_apply(source, admission, &policy, &pins, events)?;
        let mut writer = p.journal.begin_sealed_partition_apply(
            source,
            &mut gate,
            admission,
            policy.clone(),
            &pins,
            events,
        )?;
        ensure!(
            writer.byte_len() == ticket.image_length
                && p.shadow.state(events)? == *proof.native().after(),
            "partition native AP transition changed source geometry or actual shadow"
        );
        checkpoint_native_events(events, checkpoint)?;
        for ordinal in 0..u64::from(ticket.range_count) {
            let row = p.domain.row(ordinal)?;
            let skip = if row.capture.offset == 0 { GRANULE } else { 0 };
            write_partition_span(
                &mut writer,
                p.domain,
                ordinal,
                row,
                skip,
                row.capture.length - skip,
                &mut buffers,
            )?;
        }
        writer.sync_all()?;
        if let Some(observe) = post_flush {
            let native_bytes_written = writer.native_bytes_written();
            ensure!(native_bytes_written > 0,
                "post-flush progress requires an actual completed source write");
            let first = p.domain.row(0)?;
            let receipt = PartitionPostFlushReceipt {
                kind: "partition-nondiscovery-source-writes-flushed-v1",
                image_length: ticket.image_length,
                selected_bytes: ticket.selected_bytes,
                range_count: ticket.range_count,
                native_bytes_written,
                delayed_discovery_bytes: if first.capture.offset == 0 { GRANULE } else { 0 },
                immutable_journal_sha256: ticket.immutable_sha256,
                flush_and_pending_readback_succeeded: true,
                first_flushed_write_qualified: false,
            };
            observe(&receipt, events)?;
            ensure!(events.is_empty(), "post-flush observer did not drain actual native events");
        }
        let first = p.domain.row(0)?;
        if first.capture.offset == 0 {
            write_partition_span(&mut writer, p.domain, 0, first, 0, GRANULE, &mut buffers)?;
        }
        writer.sync_all()?;
        writer.revalidate(events)?;
        let digest = super::apply::check_selected(
            &mut writer,
            p.domain,
            &mut buffers.current,
            ticket.new_selected_sha256,
        )?;
        let native_bytes_written = writer.native_bytes_written();
        // SDK independently authenticates complete NEW/J before releasing the
        // mutable J borrow. No stale original source fingerprint is consulted.
        writer.finish_new(events)?;
        let applied = SelectedResult {
            selected_sha256: digest,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: false,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: None,
        };
        after_apply(&applied)?;
        self.published.closure.revalidate()?;
        p.write_index
            .require_same_sealed_journal(p.journal, ticket)?;
        self.published.metadata.publication_lease().revalidate()?;
        self.published.metadata.checksum_lease().revalidate()?;
        self.published.locator.revalidate()?;
        let digest = super::apply::check_selected(
            source,
            p.domain,
            &mut buffers.current,
            ticket.new_selected_sha256,
        )?;
        ensure!(
            sj::classify(p.journal, ticket)? == sj::SelectedLifecycle::ApplyIntent,
            "partition AP changed before HND"
        );
        source.revalidate(events)?;
        sj::write_lifecycle_marker(p.journal, ticket, MarkerKind::Handoff)?;
        p.journal.require_native_mount_barriers(ticket)?;
        ensure!(
            sj::classify(p.journal, ticket)? == sj::SelectedLifecycle::Handoff,
            "partition HND failed to close actual AP"
        );
        let witness = p
            .journal
            .finish_sealed_partition_handoff(source, gate, admission, &policy, &pins, events)?;
        checkpoint_native_events(events, checkpoint)?;
        let handoff = SelectedResult {
            selected_sha256: digest,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: None,
        };
        let verification = PartitionRetainedVerification {
            maps: self.published.maps.take(),
            ticket: ticket.clone(),
            admission: self
                .published
                .expected
                .header()
                .resource_admission
                .context("actual expected admission absent")?,
            expected_owner: self
                .published
                .expected
                .artifact_lease()
                .context("actual expected owner absent")?
                .clone(),
            source: source_token.clone(),
        };
        Ok(PartitionApplyOutcome {
            witness,
            source: source_token,
            scope,
            applied,
            handoff,
            native_bytes_written,
            verification,
        })
    }
}
impl PartitionApplyOutcome {
    pub(crate) fn require_terminal(
        &mut self,
        context: &mut PartitionResourceSourceContext,
        shadow: &mut n2r_win32::GeneralFrozenPartition,
        proof: &crate::general_composite_target::paged::ProtectedPagedTargetSelection,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        ensure!(
            self.source.same_owner(&context.owner_token())
                && Arc::ptr_eq(&self.scope, &proof.scope().capture_identity()),
            "actual partition HND outcome belongs to another source/capture"
        );
        proof.recheck_frozen_target(shadow, events)?;
        let (source, _) = context.source_and_inspection();
        self.witness.revalidate(source, events)?;
        Ok(())
    }
    pub(crate) fn applied(&self) -> &SelectedResult {
        &self.applied
    }
    pub(crate) fn handoff(&self) -> &SelectedResult {
        &self.handoff
    }
    pub(crate) fn native_bytes_written(&self) -> u64 {
        self.native_bytes_written
    }
}

impl PartitionResourcePreparedConversion<'_, '_, '_, '_, '_, '_> {
    pub(crate) fn publication_path(&self) -> &Path {
        self.metadata.publication_lease().path()
    }
    pub(crate) fn publication_sha256(&self) -> &str {
        self.metadata.publication_lease().sha256()
    }
    pub(crate) fn locator_sha256(&self) -> [u8; 32] {
        self.locator.external_sha256()
    }
    pub(crate) fn locator_path(&self) -> &str {
        &self.locator.snapshot().final_path
    }
    pub(crate) fn duplicate_locator_file(&mut self) -> Result<std::fs::File> {
        self.locator.duplicate_readonly_origin_file()
    }
}

/// Retains actual source-derived map/expected owners across shadow/context
/// teardown and the first protected native mount. This has no writer/DTO ctor.
pub(crate) struct PartitionRetainedVerification {
    maps: Option<V4RecoveryMaps>,
    ticket: crate::selected_journal::SelectedTicket,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
    expected_owner: ArtifactLease,
    source: PartitionOwnerToken,
}
impl PartitionRetainedVerification {
    pub(crate) fn verify_terminal_report(
        &self,
        expected: &PagedExpectedTree,
        observed: &n2r_win32::PartitionTerminalNativeObservation,
    ) -> Result<()> {
        ensure!(
            expected
                .artifact_lease()
                .is_some_and(|p| p.same_owner(&self.expected_owner)),
            "terminal verification lost actual expected owner"
        );
        expected.require_resource_owner(self.admission)?;
        let report = observed.report();
        let content = report
            .content_observation
            .as_ref()
            .context("actual terminal content report absent")?;
        let known = content
            .known_content
            .as_ref()
            .context("actual terminal known-content checks absent")?;
        ensure!(
            observed.filesystem() == "ReFS"
                && !report.conversion_qualified
                && report.native.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(self.admission)
                    ))
                && report.native.retained_rows_ram_accounted()
                && report.native.objects.len() == expected.len()
                && report.native.base_sectors == 0
                && content.metadata_and_namespace_verified
                && content.complete_stream_mappings_observed
                && content.data_storage_validity_checked
                && !content.full_file_hashes
                && known
                    .streams_hashed
                    .checked_add(known.streams_without_content_baseline)
                    == Some(usize::try_from(self.admission.data_streams)?)
                && known.payload_bytes_read == content.admitted_payload_bytes_read,
            "actual terminal metadata/namespace/known-content/storage evidence differs"
        );
        match &self.maps {
            Some(maps) => {
                maps.compare_terminal_report(expected, &self.ticket, report)?;
            }
            None => ensure!(
                known.streams_without_content_baseline == 0
                    && known.streams_hashed == usize::try_from(self.admission.data_streams)?,
                "terminal streams without content baselines require retained actual maps"
            ),
        }
        Ok(())
    }
    pub(crate) fn source_token(&self) -> &PartitionOwnerToken {
        &self.source
    }
}
impl PartitionApplyOutcome {
    pub(crate) fn into_terminal_parts(
        self,
    ) -> (
        n2r_win32::PartitionHandoffWitness,
        PartitionRetainedVerification,
    ) {
        (self.witness, self.verification)
    }
    pub(crate) fn verify_terminal_report(
        &self,
        expected: &PagedExpectedTree,
        observed: &n2r_win32::PartitionTerminalNativeObservation,
    ) -> Result<()> {
        self.verification.verify_terminal_report(expected, observed)
    }
}
