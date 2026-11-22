//! Experimental, non-authorizing streaming journal construction and readback.
//! Only a freshly created ordinary arena file is writable here. This module
//! cannot publish a ticket, activate a target, or open a source for writes.
use super::*;
use crate::selected_journal::{
    self, BUFFER, PinHash, RecordHashes, RowDigest, SelectedRange, SelectedTicket, ZeroDigests,
    aggregate_pin_hash, at, burst_pin_hash, capture_free_selected, copy_selected_with, finish,
    frame, get_u32, get_u64, pin_hash, put_u32, put_u64, verify_zero_selected_with,
};
use crate::{
    general_reconstruct::selected_native_journal::{
        BoundNativeCreationFacts, BoundNativeCreationJournal, NativeSelectedJournal,
    },
    general_shadow::paged_capture::CaptureRevalidation,
    lab_reconstruct::{DurableIo, ReadSeek},
};
use n2r_win32::bulk_digest::Algorithm;

mod qualification;
mod source_prefetch;
mod stage_writer;
pub(super) use qualification::FrozenPreparedWitness;
pub(crate) use qualification::partition_apply::{
    PartitionApplyFailure, PartitionApplyOutcome, PartitionExecutionOutcome, PartitionFreshApply,
    PartitionPostFlushReceipt, PartitionResourcePreparedConversion, PartitionRetainedVerification,
    WindowsPreparedArtifact, WindowsPreparedBundleCore,
};
pub(crate) use qualification::{
    FirstFlushedWrite, ResourceAppliedConversion, ResourceFreshApply, ResourcePreparedConversion,
};

/// Keeps the completed diagnostic journal and its capture alive, but exposes
/// neither its independently trusted ticket nor a raw replay capability.
pub(crate) struct DiagnosticPreparedJournal<'domain, 'capture> {
    _domain: &'domain ResourceJournalDomain<'capture>,
    _journal: File,
    _lease: ArtifactLease,
    ticket: SelectedTicket,
}

/// Completed diagnostic preparation on the exact native journal owner. Its
/// private ticket and held storage facts are not an Apply/recovery capability.
pub(crate) struct NativeDiagnosticPreparedJournal<'journal, 'domain, 'capture> {
    _journal: &'journal mut NativeSelectedJournal,
    _facts: BoundNativeCreationFacts<'journal>,
    _domain: &'domain ResourceJournalDomain<'capture>,
    ticket: SelectedTicket,
}

/// Holds every real owner used by the protected capture and native journal
/// preparation until a diagnostic locator is durably recorded. This is not a
/// source certificate or a write/activation capability.
pub(crate) struct ProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope> {
    inner: NativeDiagnosticPreparedJournal<'journal, 'domain, 'capture>,
    context: &'scope mut crate::general_source_admission::resource::ResourceSourceContext,
    shadow: &'scope mut n2r_win32::GeneralFrozenPartition,
    candidate: &'scope mut super::captured_candidate::ProtectedCapturedCandidate<'proof>,
}

/// Genuine partition V4 preparation, retaining actual source/context, frozen
/// shadow, protected NEW capture, native J/quota and its sealed closed index.
/// It is neither the legacy Dedicated preparation nor an apply/writer token.
pub(crate) struct PartitionProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope> {
    journal: &'journal mut NativeSelectedJournal,
    facts: crate::general_reconstruct::selected_native_journal::BoundPartitionCreationFacts<'journal>,
    domain: &'domain ResourceJournalDomain<'capture>,
    context: &'scope mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
    shadow: &'scope mut n2r_win32::GeneralFrozenPartition,
    candidate: &'scope mut super::captured_candidate::ProtectedCapturedCandidate<'proof>,
    ticket: SelectedTicket,
    write_index: super::reopen::PreparedJournalIndex,
}

impl PartitionProtectedPreparedJournal<'_, '_, '_, '_, '_> {
    /// Advisory same-held-file metadata and already computed format facts.
    /// Errors remain unknown telemetry; this does not revalidate/hash payloads
    /// or participate in source admission, reservation or writer decisions.
    pub(crate) fn pre_apply_accounting(&self) -> serde_json::Value {
        let capture = self.candidate.protected_proof().captured();
        let literal = capture.literal().pin();
        let index = capture.index().pin();
        let literal_allocation = capture.literal().observe_allocation_bytes();
        let index_allocation = capture.index().observe_allocation_bytes();
        let arena = self.context.arena();
        let usage = arena.usage();
        let native_journal = arena.observe_native_journal_metadata();
        let journal_sample = native_journal.as_ref().ok().and_then(|v| v.as_ref());
        let reads = capture.summary().get("read_counts");
        let f = self.domain.facts();
        let mut report = serde_json::json!({"kind":"pre-ap-resource-accounting-v1","source_scope":"selected_partition",
            "phase":"native-journal-prepared-before-publication","metadata_queries_only":true,
            "admitted_arena_ram_bytes":arena.budget().ram_bytes,
            "capture_literal_file_bytes":literal.snapshot.file_bytes,
            "capture_literal_recorded_allocation_bytes":literal.snapshot.allocation_bytes,
            "capture_literal_current_allocation_bytes":literal_allocation.as_ref().ok().copied(),
            "capture_literal_allocation_error":literal_allocation.as_ref().err().map(ToString::to_string),
            "capture_index_wire_bytes":index.bytes,
            "capture_index_current_allocation_bytes":index_allocation.as_ref().ok().copied(),
            "capture_index_allocation_error":index_allocation.as_ref().err().map(ToString::to_string),
            "capture_allocation_basis":"current same-held metadata; recorded literal pin separately labelled",
            "encoded_journal_bytes":f.journal_length,
            "journal_current_allocation_bytes":journal_sample.map(|v|v.0),
            "journal_current_file_bytes":journal_sample.map(|v|v.1),
            "journal_allocation_error":native_journal.as_ref().err().map(ToString::to_string),
            "journal_allocation_owner_present":native_journal.as_ref().ok().map(Option::is_some),
            "encoded_journal_length_is_not_allocation":true,
            "selected_bytes":f.selected_bytes,"old_zero_bytes":f.old_zero_bytes,"source_free_bytes":f.source_free_bytes,
            "new_zero_bytes":f.new_zero_bytes,"copy_bytes":f.copy_bytes,"literal_bytes":f.literal_bytes,
            "classification_basis":"journal encoding classes, not file relocation or source-device I/O counters"});
        let counters = serde_json::json!({
            "retained_file_payload_bytes":Option::<u64>::None,"relocated_file_payload_bytes":Option::<u64>::None,
            "source_payload_bytes_read_total":Option::<u64>::None,"source_payload_bytes_written_total":Option::<u64>::None,
            "capture_source_logical_bytes":reads.and_then(|v|v.get("source_logical_bytes")).and_then(serde_json::Value::as_u64),
            "capture_shadow_bytes":reads.and_then(|v|v.get("shadow_bytes")).and_then(serde_json::Value::as_u64),
            "capture_source_reference_bytes":reads.and_then(|v|v.get("source_reference_bytes")).and_then(serde_json::Value::as_u64),
            "capture_source_reference_bytes_reused":reads.and_then(|v|v.get("source_reference_bytes_reused")).and_then(serde_json::Value::as_u64),
            "capture_counters_are_single_stage_not_total_device_IO":true,
            "arena_current_wire_bytes":usage.as_ref().ok().map(|u|u.actual_wire_bytes),
            "arena_current_allocation_bytes":usage.as_ref().ok().map(|u|u.actual_allocated_bytes),
            "arena_promised_bytes":usage.as_ref().ok().map(|u|u.promised_bytes),
            "arena_leased_ram_bytes":usage.as_ref().ok().map(|u|u.leased_ram_bytes),
            "arena_registry_ram_bytes":usage.as_ref().ok().map(|u|u.registry_ram_bytes),
            "arena_observation_error":usage.as_ref().err().map(ToString::to_string),
            "peak_RAM_or_allocation_measured":false,"source_or_replay_authority_granted":false});
        if let (Some(report), serde_json::Value::Object(counters)) =
            (report.as_object_mut(), counters)
        {
            report.extend(counters);
        }
        report
    }
    pub(crate) fn revalidate(&mut self, events: &mut Vec<n2r_win32::NativeEvent>) -> Result<()> {
        let proof = self.candidate.protected_proof();
        let result = proof.captured().with_revalidation(|witness| {
            self.domain.revalidate()?;
            self.candidate.require_domain(self.domain)?;
            self.candidate.revalidate_partition_with_capture_witness(
                self.context,
                self.shadow,
                events,
                witness,
            )?;
            self.facts.revalidate_source(self.context, events)?;
            self.journal
                .revalidate_resource_preparation(&self.facts.native, &self.ticket)?;
            self.write_index
                .require_same_sealed_journal(self.journal, &self.ticket)?;
            ensure!(
                selected_journal::classify(self.journal, &self.ticket)?
                    == selected_journal::SelectedLifecycle::PreparedClear,
                "partition prepared journal is no longer actual clear state"
            );
            self.domain.revalidate()?;
            Ok(())
        });
        let closing = proof.captured().revalidate();
        match (result, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
    pub(crate) fn prepared_index(&self) -> &super::reopen::PreparedJournalIndex {
        &self.write_index
    }
    /// Non-escaping metadata bridge for the versioned partition publisher.
    /// The actual sealed creation J/facts/ticket/context remain borrowed and
    /// every source/capture/index/lifecycle close runs even on callback error.
    /// It is not an apply issuer and exposes no writable source handle.
    pub(crate) fn with_actual_publication_owners<T>(
        &mut self,
        events: &mut Vec<n2r_win32::NativeEvent>,
        action:impl FnOnce(
            &mut NativeSelectedJournal,
            &crate::general_reconstruct::selected_native_journal::BoundPartitionCreationFacts<'_>,
            &SelectedTicket,
            &super::reopen::PreparedJournalIndex,
            &mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
            &mut Vec<n2r_win32::NativeEvent>,
        )->Result<T>,
    ) -> Result<T> {
        self.revalidate(events)?;
        let result = action(
            self.journal,
            &self.facts,
            &self.ticket,
            &self.write_index,
            self.context,
            events,
        );
        let closing = self.revalidate(events);
        match (result, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
    /// Read-only routing facts for the later explicitly scoped metadata
    /// publisher. This clone cannot recreate any held owner or writer.
    pub(crate) fn locator_facts(
        &mut self,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<PreparedLocatorFacts> {
        self.revalidate(events)?;
        let f = &self.facts.native;
        Ok(PreparedLocatorFacts {
            source: f.source.clone(),
            shadow: f.shadow.clone(),
            journal_binding: f.binding.clone(),
            journal_identity: f.identity.clone(),
            journal_path: f.path.to_path_buf(),
            profile: f.profile,
            marker_use: f.marker_use,
            marker_native_qualified: None,
            ticket: self.ticket.clone(),
        })
    }
}

/// Explicit partition source adapter around the SAME complete streaming core.
/// OLD bytes come from the actual partition owner and NEW/COPY/zero bytes from
/// the actual protected candidate. No GeneralFrozen source is fabricated.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_native_partition_from_protected_capture<
    'journal,
    'domain,
    'capture,
    'proof,
    'scope,
>(
    domain: &'domain ResourceJournalDomain<'capture>,
    context:&'scope mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
    shadow: &'scope mut n2r_win32::GeneralFrozenPartition,
    candidate: &'scope mut super::captured_candidate::ProtectedCapturedCandidate<'proof>,
    creation:&'journal mut crate::general_reconstruct::selected_native_journal::BoundPartitionCreationJournal,
    index_group: &ArtifactGroupPermit,
    index_scratch: &SourceScratch,
    index_path: &std::path::Path,
    maximum_index_bytes: u64,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<PartitionProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope>> {
    domain.revalidate()?;
    candidate.require_domain(domain)?;
    candidate.revalidate_partition(context, shadow, events)?;
    let shadow_before = shadow.state(events)?;
    let f = domain.facts;
    ensure!(
        shadow_before.disk_attributes == 3
            && f.marker_profile.is_none()
            && context.binding().storage.identity.partition_bytes == f.image_length
            && n2r_win32::GeneralFrozenPartition::byte_len(shadow) == f.image_length
            && candidate.byte_len()? == f.image_length,
        "partition source/shadow/candidate length or marker profile differs"
    );
    let (memory, read_back_buffers) = lease_preparation(domain)?;
    let (journal, facts) = creation.split_for_partition_preparation(context, events)?;
    let capture_group = domain
        .scratch
        .artifact_group()
        .context("partition capture arena absent")?;
    let quota = f
        .journal_length
        .checked_add(capture_group.arena().allocation_slack_bytes())
        .context("partition journal quota overflow")?;
    ensure!(
        facts.native.source == &context.binding().storage
            && facts.native.shadow == shadow.binding()
            && facts.native.marker_profile.is_none()
            && facts.native.expected_journal_length == f.journal_length
            && f.journal_length <= facts.native.profile.max_journal_bytes()
            && facts.native.journal_quota.group() == ArtifactGroup::NativeJournal
            && facts
                .native
                .journal_quota
                .arena()
                .same_arena(capture_group.arena())
            && facts.native.journal_quota.maximum_bytes()? == quota
            && index_group.group() == ArtifactGroup::RecoveryCopy
            && index_group.arena().same_arena(capture_group.arena()),
        "partition actual J/profile/quota/index ownership differs"
    );
    let volume = format!("{}\\", facts.native.binding.disk.volume_path()?);
    ensure!(
        n2r_win32::discovery::observe_volume_space(&volume)?.available_bytes_to_caller
            >= f.journal_length,
        "actual partition J volume lacks calculated space"
    );
    let prepared = context.with_publication_handoff(events, |source, admission, stable, events| {
        ensure!(
            facts.source_owner.same_owner(stable),
            "partition OLD reader is another actual owner"
        );
        admission.revalidate_publication_handoff(source, facts.guard_pin, events)?;
        // Unchanged core performs complete source/capture descriptors, payload,
        // COPY, canonical-zero/source-free framing and independent readback.
        let result = prepare_inner(
            domain,
            source,
            candidate,
            journal,
            facts.native.path,
            true,
            false,
            None,
            read_back_buffers,
            false,
            |_, _| (),
        );
        let closing = admission.revalidate_publication_handoff(source, facts.guard_pin, events);
        match (result, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error.into()),
        }
    });
    let closing = candidate.revalidate_partition(context, shadow, events);
    let (ticket, _whole) = match (prepared, closing) {
        (Ok(value), Ok(())) => value,
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    ensure!(
        ticket.marker_profile.is_none() && ticket.journal_length == f.journal_length,
        "partition actual ticket profile/length differs"
    );
    let allocation = journal.fix_length_and_observe_allocation(&facts.native, &ticket)?;
    facts
        .native
        .journal_quota
        .arena()
        .attach_native_journal(facts.native.journal_quota, allocation)?;
    facts.revalidate_source(context, events)?;
    ensure!(
        journal.byte_len()? == f.journal_length && shadow.state(events)? == shadow_before,
        "partition source/J/frozen shadow changed around complete preparation"
    );
    domain.revalidate()?;
    // The real scanner builds its actual closed paged index and seals this
    // same J body. A ticket, path or digest cannot stand in for that owner.
    let write_index = super::reopen::JournalObservation::open(
        journal,
        &ticket,
        index_group,
        index_scratch,
        index_path,
        maximum_index_bytes,
    )?
    .into_prepared_index()?;
    drop(memory);
    let mut result = PartitionProtectedPreparedJournal {
        journal,
        facts,
        domain,
        context,
        shadow,
        candidate,
        ticket,
        write_index,
    };
    result.revalidate(events)?;
    Ok(result)
}

/// Owned copies for writing a diagnostic locator only. This structure cannot
/// reconstruct any live proof or authorize conversion/recovery.
pub(super) struct PreparedLocatorFacts {
    pub source: n2r_win32::general_layout::GeneralDiskBinding,
    pub shadow: n2r_win32::general_layout::GeneralDiskBinding,
    pub journal_binding: n2r_win32::journal_file::GeneralJournalStorageBinding,
    pub journal_identity: n2r_win32::journal_file::JournalFileIdentity,
    pub journal_path: std::path::PathBuf,
    pub profile: n2r_win32::journal_file::JournalProfile,
    pub marker_use: n2r_win32::journal_file::MarkerStorageUse,
    pub marker_native_qualified: Option<bool>,
    pub ticket: SelectedTicket,
}

impl ProtectedPreparedJournal<'_, '_, '_, '_, '_> {
    pub(crate) fn recovery_maps_required(
        &self,
        expected: &crate::shadow_tree::PagedExpectedTree,
    ) -> Result<bool> {
        expected.require_resource_owner(self.context.resource_admission())?;
        expected.require_shared_memory(
            self.context
                .arena()
                .context("prepared source arena absent")?,
        )?;
        qualification::expected_requires_maps(expected, self.context.report().policy)
    }

    /// Build complete recovery-map facts only from the still-held original
    /// source, target, expected owner and this exact prepared native ticket.
    pub(crate) fn create_recovery_maps(
        &mut self,
        expected: &crate::shadow_tree::PagedExpectedTree,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &std::path::Path,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<crate::general_reconstruct::fast_verification::v4_maps::V4RecoveryMaps> {
        self.revalidate(events)?;
        let maps = crate::general_reconstruct::fast_verification::v4_maps::V4RecoveryMaps::create(
            self.candidate.protected_proof(),
            expected,
            self.context,
            self.inner._domain,
            &self.inner.ticket,
            group,
            scratch,
            path,
        )?;
        self.revalidate(events)?;
        Ok(maps)
    }

    pub(super) fn require_arena(&self, group: &ArtifactGroupPermit) -> Result<()> {
        let arena = self
            .context
            .arena()
            .context("protected source arena is absent")?;
        ensure!(
            arena.same_arena(group.arena()),
            "locator arena differs from the live protected preparation"
        );
        Ok(())
    }

    pub(crate) fn revalidate(&mut self, events: &mut Vec<n2r_win32::NativeEvent>) -> Result<()> {
        let proof = self.candidate.protected_proof();
        proof
            .captured()
            .with_revalidation(|witness| self.revalidate_with_capture_witness(witness, events))?;
        // Ordinary share-zero handles exclude filename writers, not raw/admin
        // aliases to the journal volume. Preserve the old final byte check
        // after every nested source/target/layout/lifecycle observation.
        proof.captured().revalidate()
    }

    /// All live source, target, layout and journal checks except the capture
    /// content hash. The witness is usable only inside the same capture's
    /// scoped before/after boundary and cannot authorize a write.
    fn revalidate_with_capture_witness(
        &mut self,
        witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<()> {
        self.candidate.require_domain(self.inner._domain)?;
        witness.require_capture(self.candidate.protected_proof().captured())?;
        self.candidate.revalidate_with_capture_witness(
            self.context,
            self.shadow,
            events,
            witness,
        )?;
        self.inner
            ._journal
            .revalidate_resource_preparation(&self.inner._facts, &self.inner.ticket)?;
        ensure!(
            selected_journal::classify(self.inner._journal, &self.inner.ticket)?
                == selected_journal::SelectedLifecycle::PreparedClear,
            "protected preparation journal is not in its original clear lifecycle"
        );
        self.inner._domain.revalidate_with_witness(witness)
    }

    pub(super) fn locator_facts(
        &mut self,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<PreparedLocatorFacts> {
        self.revalidate(events)?;
        Ok(self.copy_locator_facts())
    }

    /// Copy routing only inside the exact live owner's non-escaping frozen
    /// boundary. The surrounding constructor still checks the actual journal
    /// and native owners; these facts never carry replay or Apply authority.
    pub(super) fn locator_facts_with_frozen_witness(
        &self,
        witness: &FrozenPreparedWitness<'_>,
    ) -> Result<PreparedLocatorFacts> {
        witness.require(self)?;
        Ok(self.copy_locator_facts())
    }

    fn copy_locator_facts(&self) -> PreparedLocatorFacts {
        let marker_native_qualified = self
            .inner
            ._journal
            .marker_observation()
            .map(|m| m.native_qualified);
        let facts = &self.inner._facts;
        PreparedLocatorFacts {
            source: facts.source.clone(),
            shadow: facts.shadow.clone(),
            journal_binding: facts.binding.clone(),
            journal_identity: facts.identity.clone(),
            journal_path: facts.path.to_path_buf(),
            profile: facts.profile,
            marker_use: facts.marker_use,
            marker_native_qualified,
            ticket: self.inner.ticket.clone(),
        }
    }
}

impl NativeDiagnosticPreparedJournal<'_, '_, '_> {
    pub(crate) fn selected_bytes(&self) -> u64 {
        self.ticket.selected_bytes
    }
    pub(crate) fn journal_length(&self) -> u64 {
        self.ticket.journal_length
    }
    pub(crate) fn range_count(&self) -> u32 {
        self.ticket.range_count
    }
}

impl DiagnosticPreparedJournal<'_, '_> {
    pub(crate) fn selected_bytes(&self) -> u64 {
        self.ticket.selected_bytes
    }
    pub(crate) fn journal_length(&self) -> u64 {
        self.ticket.journal_length
    }
    pub(crate) fn range_count(&self) -> u32 {
        self.ticket.range_count
    }

    /// Remove this diagnostic journal only after releasing the extra readonly
    /// handle; the arena checks the exact file identity and bytes before credit.
    pub(crate) fn retire(self) -> Result<()> {
        let Self {
            _journal, _lease, ..
        } = self;
        drop(_journal);
        _lease.retire()
    }
}

fn kind(f: JournalLayoutFacts) -> (&'static [u8; 8], &'static [u8; 8], u32, usize) {
    if f.marker_profile.is_some() {
        (b"N2RFRE02", b"N2RFEND2", 6, 40)
    } else if f.source_free_bytes != 0 {
        (b"N2RFRE01", b"N2RFEND1", 5, 40)
    } else if f.old_zero_bytes != 0 {
        (b"N2ROLD01", b"N2ROEND1", 4, 40)
    } else if f.copy_bytes != 0 {
        (b"N2RCPY01", b"N2RCEND1", 3, 32)
    } else if f.new_zero_bytes != 0 {
        (b"N2RZERO1", b"N2RZEND1", 2, 24)
    } else {
        (b"N2RSEL01", b"N2RSEND1", 1, 16)
    }
}

fn encode_record(
    row: JournalLayoutRow,
    f: JournalLayoutFacts,
    old: [u8; 32],
    new: [u8; 32],
) -> [u8; OLD_ZERO_RECORD] {
    let mut bytes = [0u8; OLD_ZERO_RECORD];
    put_u64(&mut bytes, 0, row.capture.offset);
    put_u64(&mut bytes, 8, row.capture.length);
    let hashes = kind(f).3;
    if hashes >= 32 {
        put_u64(
            &mut bytes,
            16,
            if row.capture.new_is_zero {
                1
            } else if row.capture.copy_source_offset.is_some() {
                2
            } else {
                0
            },
        );
        put_u64(&mut bytes, 24, row.capture.copy_source_offset.unwrap_or(0));
        if hashes == 40 {
            put_u64(
                &mut bytes,
                32,
                if row.capture.old_is_source_free {
                    2
                } else {
                    u64::from(row.capture.old_is_zero)
                },
            );
        }
    } else if hashes == 24 {
        put_u64(&mut bytes, 16, u64::from(row.capture.new_is_zero));
    }
    bytes[hashes..hashes + 32].copy_from_slice(&old);
    bytes[hashes + 32..hashes + 64].copy_from_slice(&new);
    bytes
}

fn copy_candidate_checked<S: ReadSeek, R: ReadSeek, J: Write>(
    domain: &ResourceJournalDomain<'_>,
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    row: JournalLayoutRow,
    aggregate: &mut PinHash,
    candidate_buffer: &mut [u8],
    compare_buffer: &mut [u8],
    same_captured_source: bool,
    records: &mut RecordHashes,
) -> Result<RowDigest> {
    let range = SelectedRange {
        offset: row.capture.offset,
        length: row.capture.length,
    };
    frame(aggregate, &range)?;
    let mut hash = records.begin()?;
    let mut done = 0u64;
    while done < range.length {
        let count = usize::try_from((range.length - done).min(BUFFER as u64))?;
        at(
            candidate,
            add(range.offset, done)?,
            &mut candidate_buffer[..count],
        )?;
        if !same_captured_source {
            if let Some(copy_source) = row.capture.copy_source_offset {
                at(
                    source,
                    add(copy_source, done)?,
                    &mut compare_buffer[..count],
                )?;
            } else {
                domain.capture.literal().read_exact_at(
                    add(row.capture.packed_offset, done)?,
                    &mut compare_buffer[..count],
                )?;
            }
            ensure!(
                candidate_buffer[..count] == compare_buffer[..count],
                "candidate differs from captured literal or retained COPY source"
            );
        }
        if row.capture.copy_source_offset.is_none() {
            journal.write_all(&candidate_buffer[..count])?;
        }
        hash.update(&candidate_buffer[..count])?;
        aggregate.update(&candidate_buffer[..count])?;
        done = add(done, count as u64)?;
    }
    hash.finish(None)
}

/// Zero bytes for [`old_zero_unread_selected`] to give the digests: part of
/// the program's image, not memory a run holds.
static ZERO_CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];

/// `verify_zero_selected_with` for an OLD-zero row that is not read again
/// (`old_zero_unread` in [`prepare_inner`]): as many zero bytes as the row
/// has go to the OLD aggregates and to the row's own digest, framed and in
/// the order that reading the row gives them, so every digest is the one a
/// read of the row's zero bytes makes. A digest already known for the row's
/// length is used, as there; one computed here is of zero bytes this
/// program made, which the cache of zero digests admits.
fn old_zero_unread_selected(
    range: &SelectedRange,
    selected: &mut PinHash,
    zero_digests: &mut ZeroDigests,
    mut restored: Option<&mut PinHash>,
    records: &mut RecordHashes,
) -> Result<RowDigest> {
    frame(selected, range)?;
    if let Some(restored) = restored.as_deref_mut() {
        frame(restored, range)?;
    }
    let cached = zero_digests.get(range.length);
    let mut hash = if cached.is_some() {
        None
    } else {
        Some(records.begin()?)
    };
    let mut remaining = range.length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(ZERO_CHUNK.len() as u64))?;
        selected.update(&ZERO_CHUNK[..count])?;
        if let Some(restored) = restored.as_deref_mut() {
            restored.update(&ZERO_CHUNK[..count])?;
        }
        if let Some(hash) = hash.as_mut() {
            hash.update(&ZERO_CHUNK[..count])?;
        }
        remaining -= count as u64;
    }
    let digest = match hash {
        Some(hash) => hash.finish(Some(range.length))?,
        None => RowDigest::Known(cached.context("verified zero digest absent")?),
    };
    if let RowDigest::Known(digest) = &digest {
        zero_digests.remember_verified(range.length, *digest);
    }
    Ok(digest)
}

/// The workspace of a journal's preparation, in buffers of [`BUFFER`] bytes:
/// the read and compare buffers, two for each of the five file-wide digests'
/// workers, two for each of the two workers of the rows' own digests, and one
/// for those workers' lists and the rows whose digests are owed.
pub(super) const PREPARATION_BUFFERS: u64 = 17;

/// A row whose payloads are in the journal and whose descriptor waits for
/// their digests.
struct OwedRow {
    row: JournalLayoutRow,
    old: RowDigest,
    new: RowDigest,
}

/// The most rows, and about the most bytes of them, that are written before
/// their descriptors: the workers that hash the payloads are never more than
/// this far behind, and the rows are read back while they are still near.
const MOST_OWED_ROWS: usize = 256;
const MOST_OWED_BYTES: u64 = READ_BACK_BUFFERS as u64 * BUFFER as u64;

/// How many megabytes the two digests of the file's own bytes take in a
/// burst. Rows are read back a burst at a time, after their descriptors are
/// written, and the writing thread then turns to the next rows' payloads:
/// with room for a burst, those two workers hash it meanwhile. With the two
/// buffers of an ordinary pipeline the writing thread waited for them
/// megabyte by megabyte, 34 s of the full Windows volume's journal.
const READ_BACK_BUFFERS: usize = 16;

/// The preparation's workspace with room for the read-back bursts.
const PREPARATION_BUFFERS_WITH_BURSTS: u64 =
    PREPARATION_BUFFERS + 2 * (READ_BACK_BUFFERS as u64 - 2);

/// Leases the workspace of a journal's preparation: with room for the
/// read-back bursts where that can be paid, and otherwise as it was, with
/// the file's digests taking two megabytes at a time. Returns the lease and
/// how many buffers each of those two digests may have.
fn lease_preparation(
    domain: &ResourceJournalDomain<'_>,
) -> Result<(crate::ntfs_inspect::paged_storage::SourceRamLease, usize)> {
    match domain
        .scratch
        .lease_ram_if_room(PREPARATION_BUFFERS_WITH_BURSTS * BUFFER as u64)
    {
        Ok(lease) => Ok((lease, READ_BACK_BUFFERS)),
        Err(_) => Ok((
            domain
                .scratch
                .lease_ram(PREPARATION_BUFFERS * BUFFER as u64)?,
            2,
        )),
    }
}

/// File-wide hashes of the journal being written: `whole` is only computed for
/// diagnostic callers that verify the whole file including its leading marker
/// region; `immutable` hashes the immutable body from `header` through `footer`
/// on a background 4 MiB `HashedBehind` worker.
///
/// `read_back`: a staged batch of rows is read back from the file and held to
/// the bytes written before it is hashed. A run that verifies each thing once
/// (`verify_policy::verifies_once`) hashes the batch as it is written instead:
/// the gate before the first write to the source reads the whole body again
/// and holds it to this digest (`bulk_digest::journal_body`, from
/// `begin_paged_fresh_apply`), and the batch is the very bytes the rows'
/// digests were computed from. A row written without a stage is read back
/// either way: its descriptor follows its payloads, and the file's bytes are
/// hashed in file order.
struct WrittenHashes {
    whole: Option<PinHash>,
    immutable: n2r_win32::bulk_digest::HashedBehind,
    read_back: bool,
}

impl WrittenHashes {
    fn update(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(whole) = self.whole.as_mut() {
            whole.update(bytes)?;
        }
        self.immutable.update(bytes)?;
        Ok(())
    }
}

/// Completes the rows whose payloads are written, in their order: each row's
/// two digests are taken from the workers, its descriptor is written in its
/// place and, where the file's hashes are computed as it is written, the row
/// is read back from the file and hashed in file order. Leaves the file at
/// the end of the last of them.
#[allow(clippy::too_many_arguments)]
fn complete_rows<J: DurableIo>(
    f: JournalLayoutFacts,
    file: &mut J,
    owed: &mut Vec<OwedRow>,
    old_records: &mut RecordHashes,
    new_records: &mut RecordHashes,
    check_records: &mut RecordHashes,
    zeros: &mut ZeroDigests,
    mut written: Option<&mut WrittenHashes>,
    buffer: &mut [u8],
) -> Result<()> {
    let Some(end) = owed.last().map(|last| last.row.next_offset) else {
        return Ok(());
    };
    let mut checked: Vec<(&'static str, u64, u64, u64, [u8; 32], RowDigest)> = Vec::new();
    for OwedRow { row, old, new } in owed.drain(..) {
        let old = old_records.settle(old, zeros)?;
        let new = new_records.settle(new, zeros)?;
        let record = encode_record(row, f, old, new);
        file.seek(SeekFrom::Start(row.descriptor_offset))?;
        file.write_all(&record[..f.record_size])?;
        if let Some(written) = written.as_deref_mut() {
            file.seek(SeekFrom::Start(row.descriptor_offset))?;
            let mut stored = [0u8; OLD_ZERO_RECORD];
            file.read_exact(&mut stored[..f.record_size])?;
            ensure!(
                stored[..f.record_size] == record[..f.record_size],
                "journal descriptor read back differs from the one written"
            );
            written.update(&stored[..f.record_size])?;
            ensure!(
                row.descriptor_offset.checked_add(f.record_size as u64)
                    == Some(row.old_storage_offset),
                "journal row layout differs: its OLD payload does not follow its descriptor"
            );
            // Each payload stored in full is held to the digest of the bytes
            // it was written from (the source's OLD bytes, the candidate's
            // NEW bytes) as it is read back. Under the check-once policy this
            // read-back is the only comparison of these stored payloads with
            // their digests before the first write to the source: the gate
            // hashes the body as a whole, and an apply that verifies each
            // thing once no longer reads the source against the stored OLD
            // bytes before writing (#203). (A staged row is hashed from the
            // very bytes its digests were computed from, and the gate holds
            // the stored body to that hash: `WrittenHashes::read_back`.) A
            // zero row stores nothing and a COPY row's NEW bytes are an
            // earlier row's OLD bytes, checked there.
            let full = |stored: u64| stored != 0 && stored == row.capture.length;
            let payloads = [
                (
                    "OLD",
                    row.old_storage_offset,
                    row.new_storage_offset
                        .checked_sub(row.old_storage_offset)
                        .context("journal row layout underflow")?,
                    old,
                ),
                (
                    "NEW",
                    row.new_storage_offset,
                    row.next_offset
                        .checked_sub(row.new_storage_offset)
                        .context("journal row layout underflow")?,
                    new,
                ),
            ];
            for (kind, storage_offset, stored, expected) in payloads {
                let mut check = if full(stored) {
                    Some(check_records.begin()?)
                } else {
                    None
                };
                let mut left = stored;
                while left != 0 {
                    let count = usize::try_from(left.min(buffer.len() as u64))?;
                    file.read_exact(&mut buffer[..count])?;
                    written.update(&buffer[..count])?;
                    if let Some(check) = check.as_mut() {
                        check.update(&buffer[..count])?;
                    }
                    left -= count as u64;
                }
                if let Some(check) = check {
                    checked.push((
                        kind,
                        storage_offset,
                        row.capture.offset,
                        row.capture.length,
                        expected,
                        check.finish(None)?,
                    ));
                }
            }
        }
    }
    for (kind, storage_offset, range_offset, range_length, expected, digest) in checked {
        ensure!(
            check_records.settle(digest, zeros)? == expected,
            "journal preparation read-back: the {kind} payload stored at offset {storage_offset} for the source range at {range_offset} ({range_length} bytes) differs from the digest of the bytes it was written from; the journal is not used"
        );
    }
    file.seek(SeekFrom::Start(end))?;
    Ok(())
}

/// Staged in-memory batch completion: patches all descriptors in `stage`,
/// writes the entire contiguous batch in one sequential `write_all`, and when
/// `written` is active feeds it: where it reads back (`--verify thorough`),
/// from the batch read back sequentially in 1 MiB chunks and held to `stage`
/// byte for byte; otherwise from `stage` itself (`WrittenHashes::read_back`).
/// Leaves the file at the end of the batch.
///
/// With a `writer`, the batch is hashed from `stage` here, the bytes the
/// rows' digests were computed from, and handed to the writing thread, which
/// writes it, and reads it back and holds it to those bytes where batches are
/// read back; `stage` becomes the other, empty, buffer. The hash is the same:
/// the bytes read back are the batch's or the preparation stops. The file is
/// then the writing thread's until [`stage_writer::StageWriter::drain`].
///
/// Either way the batch is written only where the journal's position is the
/// batch's own offset: where it is not read back, nothing else would notice
/// it written anywhere else before the gate.
#[allow(clippy::too_many_arguments)]
fn complete_staged_rows<J: DurableIo>(
    f: JournalLayoutFacts,
    file: &mut J,
    journal_path: &Path,
    stage: &mut Vec<u8>,
    stage_start: &mut Option<u64>,
    owed: &mut Vec<OwedRow>,
    old_records: &mut RecordHashes,
    new_records: &mut RecordHashes,
    zeros: &mut ZeroDigests,
    mut written: Option<&mut WrittenHashes>,
    buffer: &mut [u8],
    writer: Option<&mut stage_writer::StageWriter<'_, '_>>,
) -> Result<()> {
    let Some(end) = owed.last().map(|last| last.row.next_offset) else {
        stage.clear();
        *stage_start = None;
        return Ok(());
    };
    let base = stage_start
        .take()
        .context("staged journal batch base offset absent")?;
    ensure!(
        base.checked_add(stage.len() as u64) == Some(end),
        "staged journal batch byte length differs from planned layout"
    );
    for OwedRow { row, old, new } in owed.drain(..) {
        let old = old_records.settle(old, zeros)?;
        let new = new_records.settle(new, zeros)?;
        let record = encode_record(row, f, old, new);
        let rel = usize::try_from(
            row.descriptor_offset
                .checked_sub(base)
                .context("staged journal descriptor offset precedes batch")?,
        )?;
        ensure!(
            rel + f.record_size <= stage.len(),
            "staged journal descriptor escapes batch buffer"
        );
        stage[rel..rel + f.record_size].copy_from_slice(&record[..f.record_size]);
    }
    if let Some(writer) = writer {
        if let Some(written) = written {
            written.update(stage)?;
        }
        *stage = writer.submit(base, std::mem::take(stage))?;
        return Ok(());
    }
    let at = file.stream_position()?;
    ensure!(
        at == base,
        "journal preparation: the journal {} is at offset {at}, not at offset {base} where its staged rows begin; the journal is not used",
        journal_path.display()
    );
    file.write_all(stage)?;
    match written.as_deref_mut() {
        // Hashed as written, in file order; the gate reads the body again.
        Some(written) if !written.read_back => written.update(stage)?,
        Some(written) => {
            file.seek(SeekFrom::Start(base))?;
            let mut pos = 0usize;
            while pos < stage.len() {
                let count = (stage.len() - pos).min(buffer.len());
                file.read_exact(&mut buffer[..count])?;
                ensure!(
                    buffer[..count] == stage[pos..pos + count],
                    "journal preparation read-back: staged batch at offset {} differs from the bytes written; the journal is not used",
                    base + pos as u64
                );
                written.update(&buffer[..count])?;
                pos += count;
            }
        }
        None => {}
    }
    stage.clear();
    Ok(())
}

/// Write and independently validate one diagnostic journal. Space is reserved
/// before `CreateNew`; the function never accepts an arbitrary writable disk.
pub(crate) fn prepare_diagnostic<'domain, 'capture, R: ReadSeek, S: ReadSeek>(
    domain: &'domain ResourceJournalDomain<'capture>,
    source: &mut R,
    candidate: &mut S,
    group: &ArtifactGroupPermit,
    path: &Path,
) -> Result<DiagnosticPreparedJournal<'domain, 'capture>> {
    ensure!(
        domain.capture.index().same_group(group),
        "diagnostic journal group differs from held capture"
    );
    domain.revalidate()?;
    let f = domain.facts;
    ensure!(
        source.byte_len()? == f.image_length && candidate.byte_len()? == f.image_length,
        "diagnostic source/candidate length differs"
    );
    let (memory, read_back_buffers) = lease_preparation(domain)?;
    let permit = group.reserve_file(path, f.journal_length)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(permit.path())?;
    ensure!(
        file.metadata()?.len() == 0,
        "diagnostic journal is not fresh"
    );
    let (ticket, whole) = prepare_inner(
        domain,
        source,
        candidate,
        &mut file,
        permit.path(),
        false,
        false,
        None,
        read_back_buffers,
        true,
        |_, _| (),
    )?;
    let readonly = n2r_win32::file_storage::duplicate_readonly(&file)?;
    drop(file);
    // The whole file's digest is of the ticket's algorithm, whatever the
    // journal's bytes begin with.
    let lease = permit.verify_closed_handle_by(
        ticket.digest_algorithm(),
        &readonly,
        &hex::encode(whole),
    )?;
    drop(memory);
    Ok(DiagnosticPreparedJournal {
        _domain: domain,
        _journal: readonly,
        _lease: lease,
        ticket,
    })
}

/// Use the capacity/profile-bound native journal instead of an arbitrary file.
/// All source/target owners are rechecked while the exact journal handle and
/// its observed binding remain borrowed. This still grants no ticket or replay
/// authority until the private protected target/source issuer is completed.
pub(crate) fn prepare_native_diagnostic<'journal, 'domain, 'capture, S: ReadSeek>(
    domain: &'domain ResourceJournalDomain<'capture>,
    source: &mut n2r_win32::GeneralFrozenPartition,
    shadow: &mut n2r_win32::GeneralFrozenPartition,
    candidate: &mut S,
    creation: &'journal mut BoundNativeCreationJournal,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<NativeDiagnosticPreparedJournal<'journal, 'domain, 'capture>> {
    prepare_native_inner(
        domain, source, shadow, candidate, creation, events, false, None,
    )
}

/// The only optimized construction entry takes the actual private protected
/// capture reader and rechecks its source/target owners around preparation.
/// It can reuse its own captured literal and COPY reads, but still does not
/// issue a source certificate, recovery ticket or target-write authority.
pub(crate) fn prepare_native_from_protected_capture<'journal, 'domain, 'capture, 'proof, 'scope>(
    domain: &'domain ResourceJournalDomain<'capture>,
    context: &'scope mut crate::general_source_admission::resource::ResourceSourceContext,
    shadow: &'scope mut n2r_win32::GeneralFrozenPartition,
    candidate: &'scope mut super::captured_candidate::ProtectedCapturedCandidate<'proof>,
    creation: &'journal mut BoundNativeCreationJournal,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<ProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope>> {
    candidate.require_domain(domain)?;
    let proof = candidate.protected_proof();
    // This scope reads the same held capture and writes only the separately
    // owned native journal. Its witness cannot escape into the returned owner.
    // Full capture hashes bracket the whole operation; nested consumers still
    // validate their actual index/layout and source/target owners.
    let prepared = proof.captured().with_revalidation(move |witness| {
        let opening = candidate.revalidate_with_capture_witness(context, shadow, events, witness);
        let result = match opening {
            Ok(()) => match context.source_and_inspection() {
                Ok((source, _)) => prepare_native_inner(
                    domain,
                    source,
                    shadow,
                    candidate,
                    creation,
                    events,
                    true,
                    Some(witness),
                ),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        // Attempt source/target closing even if opening or preparation failed.
        let closing = candidate.revalidate_with_capture_witness(context, shadow, events, witness);
        let prepared =
            close_preparation(result, closing, "protected journal source/target closing")?;
        Ok(ProtectedPreparedJournal {
            inner: prepared,
            context,
            shadow,
            candidate,
        })
    });
    // Do not use `?` before this closing: failed callbacks and failed opening
    // capture checks must still attempt complete held index/literal validation.
    let closing = proof.captured().revalidate();
    close_preparation(prepared, closing, "protected journal capture closing")
}

fn close_preparation<T>(result: Result<T>, closing: Result<()>, label: &str) -> Result<T> {
    match (result, closing) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Err(close)) => Err(error.context(format!("{label} also failed: {close:#}"))),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error.context(label.to_owned())),
    }
}

fn revalidate_preparation_domain(
    domain: &ResourceJournalDomain<'_>,
    witness: Option<&CaptureRevalidation<'_>>,
) -> Result<()> {
    match witness {
        Some(witness) => domain.revalidate_with_witness(witness),
        None => domain.revalidate(),
    }
}

fn prepare_native_inner<'journal, 'domain, 'capture, S: ReadSeek>(
    domain: &'domain ResourceJournalDomain<'capture>,
    source: &mut n2r_win32::GeneralFrozenPartition,
    shadow: &mut n2r_win32::GeneralFrozenPartition,
    candidate: &mut S,
    creation: &'journal mut BoundNativeCreationJournal,
    events: &mut Vec<n2r_win32::NativeEvent>,
    same_captured_source: bool,
    capture_witness: Option<&CaptureRevalidation<'_>>,
) -> Result<NativeDiagnosticPreparedJournal<'journal, 'domain, 'capture>> {
    revalidate_preparation_domain(domain, capture_witness)?;
    let before_source = source.state(events)?;
    let before_shadow = shadow.state(events)?;
    ensure!(
        before_source.disk_attributes == 3 && before_shadow.disk_attributes == 3,
        "native journal preparation requires the actual frozen source and shadow"
    );
    let f = domain.facts;
    ensure!(
        n2r_win32::GeneralFrozenPartition::byte_len(source) == f.image_length
            && n2r_win32::GeneralFrozenPartition::byte_len(shadow) == f.image_length
            && candidate.byte_len()? == f.image_length,
        "native journal source, shadow or candidate length differs"
    );
    let (memory, read_back_buffers) = lease_preparation(domain)?;
    let (journal, facts) = creation.split_for_preparation()?;
    let capture_group = domain
        .scratch
        .artifact_group()
        .context("native journal capture arena absent")?;
    let quota_bytes = f
        .journal_length
        .checked_add(capture_group.arena().allocation_slack_bytes())
        .context("native journal quota overflow")?;
    ensure!(
        source.binding() == facts.source
            && shadow.binding() == facts.shadow
            && f.journal_length <= facts.profile.max_journal_bytes()
            && f.marker_profile == facts.marker_profile
            && facts.expected_journal_length == f.journal_length
            && facts.journal_quota.group() == ArtifactGroup::NativeJournal
            && facts
                .journal_quota
                .arena()
                .same_arena(capture_group.arena())
            && facts.journal_quota.maximum_bytes()? == quota_bytes,
        "native journal creation facts differ from frozen owners or admitted capacity"
    );
    let volume = format!("{}\\", facts.binding.disk.volume_path()?);
    let space = n2r_win32::discovery::observe_volume_space(&volume)?;
    ensure!(
        space.available_bytes_to_caller >= f.journal_length,
        "native journal volume lacks the calculated available space"
    );
    // The journal takes the source's changed ranges in ascending order, read
    // ahead to the end of each group of ranges that lie close together, as
    // the apply's passes read them (`AscendingRanges`): a window that ran a
    // megabyte past the first range of a group read 5.8 GB on the full
    // Windows volume that no range used.
    //
    // A run that verifies each thing once does not read the OLD-zero ranges
    // of a markerless journal made from this run's own capture: the capture's
    // comparison read every one of their bytes from this held source and
    // found them zero, and the gate before the first write to the source
    // reads every selected range again against the OLD aggregate these zero
    // bytes go into (`begin_paged_fresh_apply`). Their bytes in the journal
    // (none), their digests and the aggregates are the same. About half the
    // full Windows volume's selected bytes (6.8 of 14.2 GB).
    let old_zero_unread = n2r_win32::verify_policy::verifies_once()
        && same_captured_source
        && f.marker_profile.is_none();
    let (ticket, _whole) = source_prefetch::with_prefetched_source(
        source,
        domain,
        capture_group.arena(),
        old_zero_unread,
        events,
        |prefetched| {
            prepare_inner(
                domain,
                prefetched,
                candidate,
                journal,
                facts.path,
                same_captured_source,
                old_zero_unread,
                capture_witness,
                read_back_buffers,
                false,
                source_prefetch::SourceReader::set_read_ahead_reach,
            )
        },
    )?;
    if ticket.marker_profile.is_some() {
        journal.seal_redundant(&ticket)?;
        let marker = journal
            .marker_observation()
            .context("native marker journal failed to seal")?;
        ensure!(
            marker.identity == *facts.identity
                && marker.journal_length == f.journal_length
                && (facts.marker_use
                    == n2r_win32::journal_file::MarkerStorageUse::EnrolledUnqualifiedLab
                    || marker.native_qualified),
            "sealed native journal identity or qualification differs"
        );
    }
    // Seal EOF through the actual native owner before crediting any allocated
    // storage. The arena keeps a readonly same-file metadata witness and
    // re-queries it live; only fixed logical bytes can reduce pending quota.
    let allocation = journal.fix_length_and_observe_allocation(&facts, &ticket)?;
    facts
        .journal_quota
        .arena()
        .attach_native_journal(facts.journal_quota, allocation)?;
    ensure!(
        journal.byte_len()? == f.journal_length
            && source.state(events)? == before_source
            && shadow.state(events)? == before_shadow,
        "native journal or frozen source/shadow changed during preparation"
    );
    revalidate_preparation_domain(domain, capture_witness)?;
    drop(memory);
    Ok(NativeDiagnosticPreparedJournal {
        _journal: journal,
        _facts: facts,
        _domain: domain,
        ticket,
    })
}

/// A journal this preparation writes: its own handle, where its writes go
/// straight to the file and a second thread may write its staged rows
/// through it ([`stage_writer`]).
trait PreparedJournal: DurableIo {
    fn plain_handle(&self) -> Option<&File>;
}

impl PreparedJournal for File {
    fn plain_handle(&self) -> Option<&File> {
        Some(self)
    }
}

impl PreparedJournal for NativeSelectedJournal {
    fn plain_handle(&self) -> Option<&File> {
        self.preparation_handle()
    }
}

/// The largest batch of rows (descriptors + OLD + NEW) staged in memory.
const STAGE_BYTES: usize = 4 * 1024 * 1024;

/// Whether the journal's file hashes are computed as it is written, rather
/// than by reading the finished journal back, and if so whether each staged
/// batch is read back before it is hashed (`WrittenHashes::read_back`).
fn hashed_as_written(f: JournalLayoutFacts) -> Option<bool> {
    (n2r_win32::verify_policy::checks_once() && f.source_free_bytes == 0)
        .then(|| !n2r_win32::verify_policy::verifies_once())
}

/// Write and independently read back to the actual exclusively held journal,
/// at `journal_path`. The returned ticket remains private to this module
/// until a live issuer exists.
///
/// `reach(source, end)` is told, at the first of each group of ranges that
/// lie close together, where the group ends (`AscendingRanges`), so that a
/// source that reads ahead reads the group and not the megabyte after its
/// first range. The rows are taken in the same order and each read as
/// before; only the index is looked at a few rows ahead.
///
/// With `old_zero_unread`, an OLD-zero row is not read from `source`: its
/// zero bytes are given to the OLD aggregates and its digest from memory
/// ([`old_zero_unread_selected`]). Only for a run that verifies each thing
/// once, from its own capture, which read those bytes and found them zero,
/// before a gate that reads them again against the OLD aggregate.
#[allow(clippy::too_many_arguments)]
fn prepare_inner<R: ReadSeek, S: ReadSeek, J: PreparedJournal>(
    domain: &ResourceJournalDomain<'_>,
    source: &mut R,
    candidate: &mut S,
    file: &mut J,
    journal_path: &Path,
    same_captured_source: bool,
    old_zero_unread: bool,
    capture_witness: Option<&CaptureRevalidation<'_>>,
    read_back_buffers: usize,
    need_whole: bool,
    reach: impl FnMut(&mut R, u64),
) -> Result<(SelectedTicket, [u8; 32])> {
    let f = domain.facts;
    // Stage contiguous batches of up to 4 MiB (descriptors + OLD + NEW) in
    // spare RAM so descriptors are patched in memory and flushed in a single
    // sequential write + sequential read-back, avoiding hundreds of thousands
    // of tiny unbuffered seek/write/read syscalls.
    let stage: Option<(Vec<u8>, crate::ntfs_inspect::paged_storage::SourceRamLease)> = domain
        .scratch
        .lease_spare_ram(STAGE_BYTES as u64)
        .ok()
        .map(|lease| (Vec::with_capacity(STAGE_BYTES), lease));
    // With a second batch buffer, also spare memory, a thread of its own
    // writes each batch (and reads it back where batches are) while this one
    // stages the next. Without it, or for a journal written through a cache
    // of its own, this thread writes them, as before.
    let read_back = hashed_as_written(f) == Some(true);
    let writing = if stage.is_some() && file.plain_handle().is_some() {
        WriterMemory::lease(domain, read_back)
    } else {
        None
    };
    let Some(WriterMemory {
        lease,
        spare,
        read_back,
    }) = writing
    else {
        return write_journal(
            domain,
            source,
            candidate,
            file,
            journal_path,
            same_captured_source,
            old_zero_unread,
            capture_witness,
            read_back_buffers,
            need_whole,
            reach,
            stage,
            None,
        );
    };
    let handle = file
        .plain_handle()
        .context("journal preparation: the journal's handle is no longer plain")?;
    let in_flight = std::cell::Cell::new(0usize);
    let result = std::thread::scope(|scope| {
        let mut shared = stage_writer::SharedJournal::new(handle, &in_flight);
        // A thread that cannot be started leaves the batches to this one.
        let writer = stage_writer::StageWriter::start(
            scope,
            handle,
            journal_path,
            spare,
            read_back,
            &in_flight,
        )
        .ok();
        write_journal(
            domain,
            source,
            candidate,
            &mut shared,
            journal_path,
            same_captured_source,
            old_zero_unread,
            capture_witness,
            read_back_buffers,
            need_whole,
            reach,
            stage,
            writer,
        )
    });
    drop(lease);
    result
}

/// The memory of a thread that writes the staged batches, leased as spare
/// memory: the second batch buffer and, where each batch is read back, the
/// buffer it is read into.
struct WriterMemory {
    lease: crate::ntfs_inspect::paged_storage::SourceRamLease,
    spare: Vec<u8>,
    read_back: Option<Vec<u8>>,
}

impl WriterMemory {
    /// `None` where the lease is not granted or the buffers cannot be had.
    fn lease(domain: &ResourceJournalDomain<'_>, read_back: bool) -> Option<Self> {
        let read_back_bytes = if read_back { BUFFER } else { 0 };
        let lease = domain
            .scratch
            .lease_spare_ram((STAGE_BYTES + read_back_bytes) as u64)
            .ok()?;
        let mut spare = Vec::new();
        spare.try_reserve_exact(STAGE_BYTES).ok()?;
        let read_back = if read_back {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(BUFFER).ok()?;
            buffer.resize(BUFFER, 0);
            Some(buffer)
        } else {
            None
        };
        Some(Self {
            lease,
            spare,
            read_back,
        })
    }
}

/// The body of [`prepare_inner`]: writes the journal through `file`, staging
/// rows in `stage` where it is given, and handing the staged batches to
/// `writer` where there is one.
#[allow(clippy::too_many_arguments)]
fn write_journal<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    domain: &ResourceJournalDomain<'_>,
    source: &mut R,
    candidate: &mut S,
    mut file: &mut J,
    journal_path: &Path,
    same_captured_source: bool,
    old_zero_unread: bool,
    capture_witness: Option<&CaptureRevalidation<'_>>,
    read_back_buffers: usize,
    need_whole: bool,
    mut reach: impl FnMut(&mut R, u64),
    mut stage: Option<(Vec<u8>, crate::ntfs_inspect::paged_storage::SourceRamLease)>,
    mut writer: Option<stage_writer::StageWriter<'_, '_>>,
) -> Result<(SelectedTicket, [u8; 32])> {
    let f = domain.facts;
    ensure!(file.byte_len()? == 0, "new native journal is not empty");
    let mut header = [0u8; HEADER];
    let (magic, footer_magic, version, _) = kind(f);
    header[..8].copy_from_slice(magic);
    put_u32(&mut header, 8, version);
    put_u32(&mut header, 12, f.range_count);
    put_u64(&mut header, 16, f.image_length);
    put_u64(&mut header, 24, f.selected_bytes);
    put_u64(&mut header, 32, f.journal_length);
    file.write_all(&vec![0u8; usize::try_from(f.body_offset)?])?;
    file.write_all(&header)?;
    let mut position = f
        .body_offset
        .checked_add(HEADER as u64)
        .context("journal header position overflow")?;
    // The journal's two file hashes cover its bytes in file order, and a row's
    // descriptor is only known after its payload. They used to come from
    // reading the finished journal back, twice over where rows copy from
    // earlier ones, with every range hashed again (77 s for 3.2 GB). Under
    // the check-once policy each row is read back from the file as soon as
    // it is complete and hashed in order, so the hashes are those of the
    // file's own bytes; the gate before the first write to the source hashes
    // the whole body again. A run that verifies each thing once does not read
    // a staged batch back: it hashes the batch it writes, the bytes the rows'
    // digests were computed from, and the gate holds the stored body to that
    // hash (`WrittenHashes::read_back`). A journal with source-free rows
    // rewrites its header at the end and keeps the read-back.
    //
    // Every digest of a journal this build writes, and its ticket's, is
    // BLAKE3 (`n2r_win32::bulk_digest`); the ticket says so.
    let algorithm = Algorithm::WRITTEN;
    let mut written = if let Some(read_back) = hashed_as_written(f) {
        let whole = if need_whole {
            let mut whole = burst_pin_hash(algorithm, read_back_buffers)?;
            whole.update(&vec![0u8; usize::try_from(f.body_offset)?])?;
            whole.update(&header)?;
            Some(whole)
        } else {
            None
        };
        let mut immutable = n2r_win32::bulk_digest::HashedBehind::new(algorithm, 4 * BUFFER)?;
        immutable.update(&header)?;
        Some(WrittenHashes {
            whole,
            immutable,
            read_back,
        })
    } else {
        None
    };
    let mut old_selected = aggregate_pin_hash(algorithm)?;
    let mut old_restored = if f.source_free_bytes != 0 {
        Some(aggregate_pin_hash(algorithm)?)
    } else {
        None
    };
    let mut new_selected = aggregate_pin_hash(algorithm)?;
    let mut buffer = vec![0u8; BUFFER];
    let mut compare = vec![0u8; BUFFER];
    let mut zeros = ZeroDigests::new();
    // A row's descriptor holds the digests of its two payloads. They are
    // computed on two workers, one for the old payloads and one for the new,
    // while this thread reads on: the payloads of a few rows are written
    // first, and then their descriptors, in the same places as before.
    let mut old_records = RecordHashes::overlapped(algorithm)?;
    let mut new_records = RecordHashes::overlapped(algorithm)?;
    let mut check_records = RecordHashes::overlapped(algorithm)?;
    let mut owed: Vec<OwedRow> = Vec::with_capacity(MOST_OWED_ROWS);
    let mut owed_bytes = 0u64;
    let mut stage_start: Option<u64> = None;
    let mut paths = RowPaths {
        threaded: writer.is_some(),
        ..RowPaths::default()
    };
    let mut rows = n2r_win32::AscendingRanges::new(u64::from(f.range_count));
    while let Some((row, group_end)) = rows.next(|ordinal| {
        domain
            .row(ordinal)
            .map(|row| (row, row.capture.offset, row.capture.length))
    })? {
        if let Some(end) = group_end {
            reach(source, end);
        }
        ensure!(
            position == row.descriptor_offset,
            "diagnostic journal descriptor offset differs"
        );
        let row_bytes = row
            .next_offset
            .checked_sub(row.descriptor_offset)
            .context("journal row layout underflow")?;
        let use_stage = stage
            .as_ref()
            .is_some_and(|(buf, _)| row_bytes <= buf.capacity() as u64);
        paths.count(row, row_bytes, use_stage, old_zero_unread);
        if use_stage {
            let (buf, _) = stage.as_mut().unwrap();
            if stage_start.is_some()
                && (owed.len() == MOST_OWED_ROWS
                    || buf.len() as u64 + row_bytes > buf.capacity() as u64)
            {
                // With a writing thread, it writes this batch while this
                // thread stages the next in the other buffer.
                complete_staged_rows(
                    f,
                    file,
                    journal_path,
                    buf,
                    &mut stage_start,
                    &mut owed,
                    &mut old_records,
                    &mut new_records,
                    &mut zeros,
                    written.as_mut(),
                    &mut buffer,
                    writer.as_mut(),
                )?;
                owed_bytes = 0;
            } else if stage_start.is_none() && !owed.is_empty() {
                if let Some(writer) = writer.as_mut() {
                    writer.drain()?;
                }
                complete_rows(
                    f,
                    file,
                    &mut owed,
                    &mut old_records,
                    &mut new_records,
                    &mut check_records,
                    &mut zeros,
                    written.as_mut(),
                    &mut buffer,
                )?;
                owed_bytes = 0;
            }
            if stage_start.is_none() {
                stage_start = Some(row.descriptor_offset);
            }
            buf.write_all(&[0u8; OLD_ZERO_RECORD][..f.record_size])?;
            position = position
                .checked_add(f.record_size as u64)
                .context("journal descriptor position overflow")?;
            let range = SelectedRange {
                offset: row.capture.offset,
                length: row.capture.length,
            };
            let old = if row.capture.old_is_source_free {
                RowDigest::Known(capture_free_selected(
                    source,
                    &range,
                    buf,
                    &mut old_selected,
                    &mut buffer,
                )?)
            } else if row.capture.old_is_zero && old_zero_unread {
                old_zero_unread_selected(
                    &range,
                    &mut old_selected,
                    &mut zeros,
                    old_restored.as_mut(),
                    &mut old_records,
                )?
            } else if row.capture.old_is_zero {
                verify_zero_selected_with(
                    source,
                    &range,
                    &mut old_selected,
                    &mut buffer,
                    &mut zeros,
                    "source OLD-zero row is nonzero",
                    old_restored.as_mut(),
                    &mut old_records,
                )?
            } else {
                let digest = copy_selected_with(
                    source,
                    &range,
                    buf,
                    &mut old_selected,
                    &mut buffer,
                    old_restored.as_mut(),
                    &mut old_records,
                )?;
                position = position
                    .checked_add(row.capture.length)
                    .context("journal old payload position overflow")?;
                digest
            };
            ensure!(
                position == row.new_storage_offset,
                "diagnostic old payload length differs"
            );
            let new = if row.capture.new_is_zero {
                verify_zero_selected_with(
                    candidate,
                    &range,
                    &mut new_selected,
                    &mut buffer,
                    &mut zeros,
                    "candidate zero row is nonzero",
                    None,
                    &mut new_records,
                )?
            } else {
                let digest = copy_candidate_checked(
                    domain,
                    source,
                    candidate,
                    buf,
                    row,
                    &mut new_selected,
                    &mut buffer,
                    &mut compare,
                    same_captured_source,
                    &mut new_records,
                )?;
                if row.capture.copy_source_offset.is_none() {
                    position = position
                        .checked_add(row.capture.length)
                        .context("journal new payload position overflow")?;
                }
                digest
            };
            ensure!(
                position == row.next_offset,
                "diagnostic new payload length differs"
            );
            owed.push(OwedRow { row, old, new });
            continue;
        }
        if let Some((buf, _)) = stage.as_mut() {
            if stage_start.is_some() {
                complete_staged_rows(
                    f,
                    file,
                    journal_path,
                    buf,
                    &mut stage_start,
                    &mut owed,
                    &mut old_records,
                    &mut new_records,
                    &mut zeros,
                    written.as_mut(),
                    &mut buffer,
                    writer.as_mut(),
                )?;
                owed_bytes = 0;
            }
        }
        // This row is written by this thread, after every batch before it.
        if let Some(writer) = writer.as_mut() {
            writer.drain()?;
        }
        file.write_all(&[0u8; OLD_ZERO_RECORD][..f.record_size])?;
        position = position
            .checked_add(f.record_size as u64)
            .context("journal descriptor position overflow")?;
        let range = SelectedRange {
            offset: row.capture.offset,
            length: row.capture.length,
        };
        let old = if row.capture.old_is_source_free {
            RowDigest::Known(capture_free_selected(
                source,
                &range,
                &mut file,
                &mut old_selected,
                &mut buffer,
            )?)
        } else if row.capture.old_is_zero && old_zero_unread {
            old_zero_unread_selected(
                &range,
                &mut old_selected,
                &mut zeros,
                old_restored.as_mut(),
                &mut old_records,
            )?
        } else if row.capture.old_is_zero {
            verify_zero_selected_with(
                source,
                &range,
                &mut old_selected,
                &mut buffer,
                &mut zeros,
                "source OLD-zero row is nonzero",
                old_restored.as_mut(),
                &mut old_records,
            )?
        } else {
            let digest = copy_selected_with(
                source,
                &range,
                &mut file,
                &mut old_selected,
                &mut buffer,
                old_restored.as_mut(),
                &mut old_records,
            )?;
            position = position
                .checked_add(row.capture.length)
                .context("journal old payload position overflow")?;
            digest
        };
        ensure!(
            position == row.new_storage_offset,
            "diagnostic old payload length differs"
        );
        let new = if row.capture.new_is_zero {
            verify_zero_selected_with(
                candidate,
                &range,
                &mut new_selected,
                &mut buffer,
                &mut zeros,
                "candidate zero row is nonzero",
                None,
                &mut new_records,
            )?
        } else {
            let digest = copy_candidate_checked(
                domain,
                source,
                candidate,
                &mut file,
                row,
                &mut new_selected,
                &mut buffer,
                &mut compare,
                same_captured_source,
                &mut new_records,
            )?;
            if row.capture.copy_source_offset.is_none() {
                position = position
                    .checked_add(row.capture.length)
                    .context("journal new payload position overflow")?;
            }
            digest
        };
        ensure!(
            position == row.next_offset,
            "diagnostic new payload length differs"
        );
        owed_bytes = owed_bytes.saturating_add(row_bytes);
        owed.push(OwedRow { row, old, new });
        if owed.len() == MOST_OWED_ROWS || owed_bytes >= MOST_OWED_BYTES {
            complete_rows(
                f,
                file,
                &mut owed,
                &mut old_records,
                &mut new_records,
                &mut check_records,
                &mut zeros,
                written.as_mut(),
                &mut buffer,
            )?;
            owed_bytes = 0;
        }
    }
    if let Some((buf, _)) = stage.as_mut() {
        if stage_start.is_some() {
            complete_staged_rows(
                f,
                file,
                journal_path,
                buf,
                &mut stage_start,
                &mut owed,
                &mut old_records,
                &mut new_records,
                &mut zeros,
                written.as_mut(),
                &mut buffer,
                writer.as_mut(),
            )?;
        }
    }
    // Every batch is in the journal before this thread writes what follows.
    if let Some(writer) = writer.take() {
        writer.finish()?;
    }
    drop(stage);
    complete_rows(
        f,
        file,
        &mut owed,
        &mut old_records,
        &mut new_records,
        &mut check_records,
        &mut zeros,
        written.as_mut(),
        &mut buffer,
    )?;
    old_records.finish()?;
    new_records.finish()?;
    check_records.finish()?;
    let old_sha = finish(old_selected)?;
    let restored_sha = old_restored.map(finish).transpose()?;
    let new_sha = finish(new_selected)?;
    let mut footer = [0u8; FOOTER];
    footer[..8].copy_from_slice(footer_magic);
    footer[8..40].copy_from_slice(&old_sha);
    footer[40..72].copy_from_slice(&new_sha);
    put_u64(&mut footer, 72, f.journal_length);
    file.write_all(&footer)?;
    if let Some(written) = written.as_mut() {
        written.update(&footer)?;
    }
    if let Some(restored) = restored_sha {
        header[40..72].copy_from_slice(&restored);
        put_u64(&mut header, 72, f.source_free_bytes);
        file.seek(SeekFrom::Start(f.body_offset))?;
        file.write_all(&header)?;
    }
    ensure!(
        file.byte_len()? == f.journal_length
            && source.byte_len()? == f.image_length
            && candidate.byte_len()? == f.image_length,
        "diagnostic journal or input length changed"
    );
    file.sync_all()?;
    let mut ticket = SelectedTicket {
        image_length: f.image_length,
        selected_bytes: f.selected_bytes,
        range_count: f.range_count,
        journal_length: f.journal_length,
        immutable_sha256: [0; 32],
        marker_profile: f.marker_profile,
        old_selected_sha256: old_sha,
        old_restored_selected_sha256: restored_sha,
        new_selected_sha256: new_sha,
        whole_image_verified: false,
        digest: Some(algorithm),
    };
    let (immutable, whole) = match written {
        Some(written) => (
            written.immutable.finish()?,
            match written.whole {
                Some(whole) => finish(whole)?,
                None => [0u8; 32],
            },
        ),
        None => validate_readback(domain, file, &ticket, &mut buffer, &mut compare)?,
    };
    ticket.immutable_sha256 = immutable;
    // The whole body was just read back and compared with its sources, or,
    // in a run that verifies each thing once, its staged batches hashed as
    // they were written. Either way a full read of it is left out until the
    // gate before the first write to the source, which makes one
    // (`bulk_digest::journal_body_already_verified`).
    if ticket.marker_profile.is_none() {
        n2r_win32::bulk_digest::note_journal_body_verified(
            algorithm,
            &immutable,
            BODY,
            ticket.journal_length - BODY,
        );
    }
    revalidate_preparation_domain(domain, capture_witness)?;
    eprintln!("{}", paths.line());
    Ok((ticket, whole))
}

/// How the journal's rows were written, for the line its preparation prints
/// (as the apply prints `apply-writes:`): the rows staged in batches and
/// those written one at a time, and the OLD-zero bytes not read again.
#[derive(Default)]
struct RowPaths {
    threaded: bool,
    staged_rows: u64,
    staged_bytes: u64,
    direct_rows: u64,
    direct_bytes: u64,
    old_zero_unread_bytes: u64,
}

impl RowPaths {
    fn count(
        &mut self,
        row: JournalLayoutRow,
        row_bytes: u64,
        staged: bool,
        old_zero_unread: bool,
    ) {
        if staged {
            self.staged_rows += 1;
            self.staged_bytes = self.staged_bytes.saturating_add(row_bytes);
        } else {
            self.direct_rows += 1;
            self.direct_bytes = self.direct_bytes.saturating_add(row_bytes);
        }
        if old_zero_unread && row.capture.old_is_zero && !row.capture.old_is_source_free {
            self.old_zero_unread_bytes = self
                .old_zero_unread_bytes
                .saturating_add(row.capture.length);
        }
    }

    fn line(&self) -> String {
        let gb = |bytes: u64| bytes as f64 / (1u64 << 30) as f64;
        format!(
            "journal-preparation: {} rows staged ({:.2} GB, written {}), {} rows written one at a time ({:.2} GB, read back); OLD-zero ranges not read again: {:.2} GB",
            self.staged_rows,
            gb(self.staged_bytes),
            if self.threaded {
                "on a thread of their own"
            } else {
                "by the preparing thread"
            },
            self.direct_rows,
            gb(self.direct_bytes),
            gb(self.old_zero_unread_bytes)
        )
    }
}

fn read_stored<J: ReadSeek>(
    file: &mut J,
    length: u64,
    stored: bool,
    expected: &[u8],
    range: &SelectedRange,
    mut selected: Option<&mut PinHash>,
    immutable: &mut PinHash,
    whole: &mut PinHash,
    buffer: &mut [u8],
) -> Result<()> {
    if let Some(selected) = selected.as_deref_mut() {
        frame(selected, range)?;
    }
    let mut hash = pin_hash(immutable.algorithm())?;
    let mut remaining = length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))?;
        if stored {
            file.read_exact(&mut buffer[..count])?;
            immutable.update(&buffer[..count])?;
            whole.update(&buffer[..count])?;
        } else {
            buffer[..count].fill(0);
        }
        hash.update(&buffer[..count])?;
        if let Some(selected) = selected.as_deref_mut() {
            selected.update(&buffer[..count])?;
        }
        remaining -= count as u64;
    }
    ensure!(
        finish(hash)?.as_slice() == expected,
        "diagnostic journal payload digest differs"
    );
    Ok(())
}

/// Resolve an OLD byte position only from the held planned rows; source-free
/// rows have digest tables and cannot satisfy COPY references.
fn read_prior_old<J: Read + Seek>(
    domain: &ResourceJournalDomain<'_>,
    file: &mut J,
    mut source: u64,
    before_ordinal: u64,
    out: &mut [u8],
) -> Result<()> {
    let (mut low, mut high) = (0u64, before_ordinal);
    while low < high {
        let middle = low + (high - low) / 2;
        if row_end(domain.capture.index().range(middle)?)? <= source {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    let mut filled = 0usize;
    while filled < out.len() {
        ensure!(
            low < before_ordinal,
            "diagnostic COPY source leaves earlier rows"
        );
        let row = domain.row(low)?;
        let end = row_end(row.capture)?;
        ensure!(
            row.capture.offset <= source && source < end && !row.capture.old_is_source_free,
            "diagnostic COPY source is missing or digest-only"
        );
        let count = usize::try_from((end - source).min((out.len() - filled) as u64))?;
        if row.capture.old_is_zero {
            out[filled..filled + count].fill(0);
        } else {
            at(
                file,
                add(row.old_storage_offset, source - row.capture.offset)?,
                &mut out[filled..filled + count],
            )?;
        }
        source = add(source, count as u64)?;
        filled += count;
        low += 1;
    }
    Ok(())
}

/// The diagnostic ticket stays private until a separate native target proof
/// exists. This validates descriptors, stored payloads, COPY resolution, both
/// aggregates, markers, and both whole-file and immutable hashes in bounded
/// memory, with no `Vec<JournalRecord>` or count cap beyond the ticket format.
fn validate_readback<J: ReadSeek>(
    domain: &ResourceJournalDomain<'_>,
    file: &mut J,
    ticket: &SelectedTicket,
    buffer: &mut [u8],
    compare: &mut [u8],
) -> Result<([u8; 32], [u8; 32])> {
    let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::JournalRead);
    n2r_win32::perf::step("read journal back: stored bytes");
    let f = domain.facts;
    ensure!(
        ticket.image_length == f.image_length
            && ticket.range_count == f.range_count
            && ticket.selected_bytes == f.selected_bytes
            && ticket.journal_length == f.journal_length
            && ticket.marker_profile == f.marker_profile
            && !ticket.whole_image_verified
            && ticket.old_restored_selected_sha256.is_some() == (f.source_free_bytes != 0)
            && file.byte_len()? == f.journal_length,
        "diagnostic ticket/layout differs"
    );
    let algorithm = ticket.digest_algorithm();
    file.seek(SeekFrom::Start(0))?;
    let mut whole = aggregate_pin_hash(algorithm)?;
    let mut marker_bytes = vec![0u8; usize::try_from(f.body_offset)?];
    file.read_exact(&mut marker_bytes)?;
    ensure!(
        marker_bytes.iter().all(|&b| b == 0),
        "diagnostic journal markers are not clear"
    );
    whole.update(&marker_bytes)?;
    let mut immutable = aggregate_pin_hash(algorithm)?;
    let mut hdr = [0u8; HEADER];
    file.read_exact(&mut hdr)?;
    whole.update(&hdr)?;
    immutable.update(&hdr)?;
    let (magic, footer_magic, version, hashes) = kind(f);
    ensure!(
        &hdr[..8] == magic
            && get_u32(&hdr, 8) == version
            && get_u32(&hdr, 12) == f.range_count
            && get_u64(&hdr, 16) == f.image_length
            && get_u64(&hdr, 24) == f.selected_bytes
            && get_u64(&hdr, 32) == f.journal_length
            && match ticket.old_restored_selected_sha256 {
                Some(hash) => hdr[40..72] == hash && get_u64(&hdr, 72) == f.source_free_bytes,
                None => hdr[40..].iter().all(|&b| b == 0),
            },
        "diagnostic journal header differs"
    );
    let mut old = aggregate_pin_hash(algorithm)?;
    let mut new = if f.copy_bytes == 0 {
        Some(aggregate_pin_hash(algorithm)?)
    } else {
        None
    };
    for ordinal in 0..u64::from(f.range_count) {
        let row = domain.row(ordinal)?;
        ensure!(
            file.stream_position()? == row.descriptor_offset,
            "diagnostic descriptor position differs"
        );
        let mut descriptor = [0u8; OLD_ZERO_RECORD];
        file.read_exact(&mut descriptor[..f.record_size])?;
        immutable.update(&descriptor[..f.record_size])?;
        whole.update(&descriptor[..f.record_size])?;
        let old_hash: [u8; 32] = descriptor[hashes..hashes + 32].try_into()?;
        let new_hash: [u8; 32] = descriptor[hashes + 32..hashes + 64].try_into()?;
        ensure!(
            descriptor == encode_record(row, f, old_hash, new_hash),
            "diagnostic journal descriptor differs"
        );
        let range = SelectedRange {
            offset: row.capture.offset,
            length: row.capture.length,
        };
        if row.capture.old_is_source_free {
            let table_length = old_stored(row.capture)?;
            read_stored(
                file,
                table_length,
                true,
                &old_hash,
                &range,
                None,
                &mut immutable,
                &mut whole,
                buffer,
            )?;
        } else {
            read_stored(
                file,
                range.length,
                !row.capture.old_is_zero,
                &old_hash,
                &range,
                Some(&mut old),
                &mut immutable,
                &mut whole,
                buffer,
            )?;
        }
        ensure!(
            file.stream_position()? == row.new_storage_offset,
            "diagnostic OLD readback position differs"
        );
        if row.capture.copy_source_offset.is_none() {
            read_stored(
                file,
                range.length,
                !row.capture.new_is_zero,
                &new_hash,
                &range,
                new.as_mut(),
                &mut immutable,
                &mut whole,
                buffer,
            )?;
        }
        ensure!(
            file.stream_position()? == row.next_offset,
            "diagnostic NEW readback position differs"
        );
    }
    let mut footer = [0u8; FOOTER];
    file.read_exact(&mut footer)?;
    immutable.update(&footer)?;
    whole.update(&footer)?;
    ensure!(
        &footer[..8] == footer_magic
            && footer[8..40] == ticket.old_selected_sha256
            && footer[40..72] == ticket.new_selected_sha256
            && get_u64(&footer, 72) == f.journal_length
            && finish(old)?
                == ticket
                    .old_restored_selected_sha256
                    .unwrap_or(ticket.old_selected_sha256)
            && file.stream_position()? == f.journal_length,
        "diagnostic footer or OLD aggregate differs"
    );
    if let Some(new) = new {
        ensure!(
            finish(new)? == ticket.new_selected_sha256,
            "diagnostic NEW aggregate differs"
        );
    } else if !n2r_win32::verify_policy::checks_once() {
        n2r_win32::perf::step("read journal back: resolve copied ranges");
        let mut aggregate = aggregate_pin_hash(algorithm)?;
        for ordinal in 0..u64::from(f.range_count) {
            let row = domain.row(ordinal)?;
            let range = SelectedRange {
                offset: row.capture.offset,
                length: row.capture.length,
            };
            frame(&mut aggregate, &range)?;
            let mut descriptor = [0u8; OLD_ZERO_RECORD];
            at(
                file,
                row.descriptor_offset,
                &mut descriptor[..f.record_size],
            )?;
            let mut hash = pin_hash(algorithm)?;
            let mut done = 0u64;
            while done < range.length {
                let count = usize::try_from((range.length - done).min(buffer.len() as u64))?;
                if row.capture.new_is_zero {
                    buffer[..count].fill(0);
                } else if let Some(copy_source) = row.capture.copy_source_offset {
                    read_prior_old(
                        domain,
                        file,
                        add(copy_source, done)?,
                        ordinal,
                        &mut buffer[..count],
                    )?;
                } else {
                    at(
                        file,
                        add(row.new_storage_offset, done)?,
                        &mut buffer[..count],
                    )?;
                }
                hash.update(&buffer[..count])?;
                aggregate.update(&buffer[..count])?;
                done = add(done, count as u64)?;
            }
            ensure!(
                finish(hash)?.as_slice() == &descriptor[hashes + 32..hashes + 64],
                "diagnostic resolved NEW row digest differs"
            );
        }
        ensure!(
            finish(aggregate)? == ticket.new_selected_sha256,
            "diagnostic resolved NEW aggregate differs"
        );
    }
    // Keep the second fixed buffer part of the checked working-set lease even
    // for no-COPY layouts; construction uses it for source/literal comparison.
    ensure!(
        compare.len() >= BUFFER && buffer.len() >= BUFFER,
        "diagnostic I/O buffers differ"
    );
    n2r_win32::perf::step("after journal read-back");
    Ok((finish(immutable)?, finish(whole)?))
}

impl PartitionProtectedPreparedJournal<'_, '_, '_, '_, '_> {
    pub(crate) fn recovery_maps_required(
        &self,
        expected: &crate::shadow_tree::PagedExpectedTree,
    ) -> Result<bool> {
        expected.require_resource_owner(self.context.resource_admission())?;
        expected.require_shared_memory(self.context.arena())?;
        qualification::expected_requires_maps(expected, self.context.verification_policy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A journal in memory; `corrupt_at` changes the byte written there, as a
    /// device that stores something else than it was given would.
    struct Memory {
        bytes: Cursor<Vec<u8>>,
        corrupt_at: Option<u64>,
    }
    impl Read for Memory {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.bytes.read(out)
        }
    }
    impl Write for Memory {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let at = self.bytes.position();
            let written = self.bytes.write(bytes)?;
            if let Some(corrupt) = self.corrupt_at
                && (at..at + written as u64).contains(&corrupt)
            {
                self.bytes.get_mut()[usize::try_from(corrupt).unwrap()] ^= 0x5a;
            }
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Seek for Memory {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            self.bytes.seek(from)
        }
    }
    impl ReadSeek for Memory {
        fn byte_len(&mut self) -> std::io::Result<u64> {
            Ok(self.bytes.get_ref().len() as u64)
        }
    }
    impl DurableIo for Memory {
        fn sync_all(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const ROW: u64 = 4096;

    fn facts(rows: u32) -> JournalLayoutFacts {
        JournalLayoutFacts {
            image_length: 1 << 30,
            range_count: rows,
            selected_bytes: u64::from(rows) * ROW,
            old_zero_bytes: 0,
            source_free_bytes: 0,
            new_zero_bytes: 0,
            copy_bytes: 0,
            literal_bytes: u64::from(rows) * ROW,
            body_offset: BODY,
            record_size: RECORD,
            journal_length: BODY
                + HEADER as u64
                + u64::from(rows) * (RECORD as u64 + 2 * ROW)
                + FOOTER as u64,
            marker_profile: None,
        }
    }

    /// `rows` literal rows from `base`, staged as `prepare_inner` stages them
    /// (descriptors still zero), and the rows the stage owes descriptors for.
    fn staged(base: u64, rows: u32) -> (Vec<u8>, Vec<OwedRow>) {
        let algorithm = Algorithm::WRITTEN;
        let mut stage = Vec::new();
        let mut owed = Vec::new();
        let mut at = base;
        for ordinal in 0..u64::from(rows) {
            let old: Vec<u8> = (0..ROW).map(|i| (i * 7 + ordinal) as u8).collect();
            let new: Vec<u8> = (0..ROW).map(|i| (i * 13 + ordinal + 1) as u8).collect();
            let row = JournalLayoutRow {
                capture: CaptureIndexRange {
                    offset: (ordinal + 1) * 1024 * 1024,
                    length: ROW,
                    packed_offset: ordinal * ROW,
                    new_is_zero: false,
                    old_is_zero: false,
                    old_is_source_free: false,
                    copy_source_offset: None,
                },
                descriptor_offset: at,
                old_storage_offset: at + RECORD as u64,
                new_storage_offset: at + RECORD as u64 + ROW,
                next_offset: at + RECORD as u64 + 2 * ROW,
            };
            stage.extend_from_slice(&[0u8; RECORD]);
            stage.extend_from_slice(&old);
            stage.extend_from_slice(&new);
            owed.push(OwedRow {
                row,
                old: RowDigest::Known(n2r_win32::bulk_digest::digest(algorithm, &old).unwrap()),
                new: RowDigest::Known(n2r_win32::bulk_digest::digest(algorithm, &new).unwrap()),
            });
            at = row.next_offset;
        }
        (stage, owed)
    }

    /// Completes `rows` staged rows into a journal whose bytes before `base`
    /// are written; returns the immutable digest of what was hashed, or the
    /// error, and the journal.
    fn complete(read_back: bool, corrupt_at: Option<u64>) -> (Result<[u8; 32]>, Memory) {
        let algorithm = Algorithm::WRITTEN;
        let rows = 3;
        let base = BODY + HEADER as u64;
        let mut journal = Memory {
            bytes: Cursor::new(vec![0u8; usize::try_from(base).unwrap()]),
            corrupt_at,
        };
        journal.seek(SeekFrom::Start(base)).unwrap();
        let (mut stage, mut owed) = staged(base, rows);
        let mut written = WrittenHashes {
            whole: None,
            immutable: n2r_win32::bulk_digest::HashedBehind::new(algorithm, 4096).unwrap(),
            read_back,
        };
        let mut stage_start = Some(base);
        let result = complete_staged_rows(
            facts(rows),
            &mut journal,
            Path::new("journal"),
            &mut stage,
            &mut stage_start,
            &mut owed,
            &mut RecordHashes::here(algorithm),
            &mut RecordHashes::here(algorithm),
            &mut ZeroDigests::new(),
            Some(&mut written),
            &mut vec![0u8; 1000],
            None,
        );
        let digest = result.and_then(|()| {
            ensure!(
                stage.is_empty() && stage_start.is_none() && owed.is_empty(),
                "the batch was not completed"
            );
            Ok(written.immutable.finish()?)
        });
        (digest, journal)
    }

    /// As [`complete`], with a thread that writes the batch through the
    /// journal's handle; returns the digest, the journal's bytes and where
    /// its handle was left.
    fn complete_on_a_writing_thread(read_back: bool) -> ([u8; 32], Vec<u8>, u64) {
        let algorithm = Algorithm::WRITTEN;
        let rows = 3;
        let base = BODY + HEADER as u64;
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0u8; usize::try_from(base).unwrap()])
            .unwrap();
        let (mut stage, mut owed) = staged(base, rows);
        let mut written = WrittenHashes {
            whole: None,
            immutable: n2r_win32::bulk_digest::HashedBehind::new(algorithm, 4096).unwrap(),
            read_back,
        };
        let in_flight = std::cell::Cell::new(0);
        let mut shared = stage_writer::SharedJournal::new(&file, &in_flight);
        std::thread::scope(|scope| {
            let mut writer = stage_writer::StageWriter::start(
                scope,
                &file,
                Path::new("journal"),
                Vec::with_capacity(stage.capacity()),
                read_back.then(|| vec![0u8; 1000]),
                &in_flight,
            )
            .unwrap();
            let mut stage_start = Some(base);
            complete_staged_rows(
                facts(rows),
                &mut shared,
                Path::new("journal"),
                &mut stage,
                &mut stage_start,
                &mut owed,
                &mut RecordHashes::here(algorithm),
                &mut RecordHashes::here(algorithm),
                &mut ZeroDigests::new(),
                Some(&mut written),
                &mut vec![0u8; 1000],
                Some(&mut writer),
            )
            .unwrap();
            assert!(
                stage.is_empty() && stage_start.is_none() && owed.is_empty(),
                "the batch was handed over and the other buffer taken"
            );
            writer.finish().unwrap();
        });
        let at = shared.stream_position().unwrap();
        let mut stored = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut stored).unwrap();
        (written.immutable.finish().unwrap(), stored, at)
    }

    #[test]
    fn an_old_zero_row_left_unread_gives_the_digests_reading_it_gives() {
        let algorithm = Algorithm::WRITTEN;
        let lengths = [4096u64, 64 * 1024, 3 * 1024 * 1024 + 4096, 4096];
        let mut source = Cursor::new(vec![0u8; 8 << 20]);
        for overlapped in [false, true] {
            let records = || {
                if overlapped {
                    RecordHashes::overlapped(algorithm).unwrap()
                } else {
                    RecordHashes::here(algorithm)
                }
            };
            let (mut read, mut unread) = (
                aggregate_pin_hash(algorithm).unwrap(),
                aggregate_pin_hash(algorithm).unwrap(),
            );
            let (mut read_restored, mut unread_restored) = (
                aggregate_pin_hash(algorithm).unwrap(),
                aggregate_pin_hash(algorithm).unwrap(),
            );
            let (mut read_records, mut unread_records) = (records(), records());
            let (mut read_zeros, mut unread_zeros) = (ZeroDigests::new(), ZeroDigests::new());
            let mut buffer = vec![0xa5u8; BUFFER];
            // The last row has a length seen before: its digest is the one
            // remembered for that length, either way.
            for (ordinal, &length) in lengths.iter().enumerate() {
                let range = SelectedRange {
                    offset: (ordinal as u64 + 1) * 4096,
                    length,
                };
                let by_reading = verify_zero_selected_with(
                    &mut source,
                    &range,
                    &mut read,
                    &mut buffer,
                    &mut read_zeros,
                    "source OLD-zero row is nonzero",
                    Some(&mut read_restored),
                    &mut read_records,
                )
                .unwrap();
                let unread_digest = old_zero_unread_selected(
                    &range,
                    &mut unread,
                    &mut unread_zeros,
                    Some(&mut unread_restored),
                    &mut unread_records,
                )
                .unwrap();
                assert_eq!(
                    read_records.settle(by_reading, &mut read_zeros).unwrap(),
                    unread_records
                        .settle(unread_digest, &mut unread_zeros)
                        .unwrap(),
                    "row {ordinal} of {length} bytes, overlapped: {overlapped}"
                );
            }
            read_records.finish().unwrap();
            unread_records.finish().unwrap();
            assert_eq!(finish(read).unwrap(), finish(unread).unwrap());
            assert_eq!(
                finish(read_restored).unwrap(),
                finish(unread_restored).unwrap()
            );
        }
    }

    #[test]
    fn a_batch_written_on_a_thread_of_its_own_is_the_batch_written_here() {
        let (here, journal) = complete(false, None);
        let here = here.unwrap();
        for read_back in [false, true] {
            let (digest, stored, at) = complete_on_a_writing_thread(read_back);
            assert_eq!(&stored, journal.bytes.get_ref(), "read back: {read_back}");
            assert_eq!(digest, here, "read back: {read_back}");
            assert_eq!(at, journal.bytes.position(), "read back: {read_back}");
        }
    }

    #[test]
    fn a_staged_batch_hashes_the_same_whether_it_is_read_back_or_not() {
        let (read_back, journal) = complete(true, None);
        let (as_written, unread) = complete(false, None);
        let (read_back, as_written) = (read_back.unwrap(), as_written.unwrap());
        let base = usize::try_from(BODY + HEADER as u64).unwrap();
        let stored = journal.bytes.get_ref().clone();
        assert_eq!(
            stored,
            *unread.bytes.get_ref(),
            "the same bytes are written"
        );
        assert_eq!(
            read_back, as_written,
            "the hash of the bytes read back is the hash of the bytes written"
        );
        assert_eq!(
            as_written,
            n2r_win32::bulk_digest::digest(Algorithm::WRITTEN, &stored[base..]).unwrap(),
            "the hash is of the journal's own bytes, descriptors in place"
        );
        assert_eq!(
            journal.bytes.position(),
            unread.bytes.position(),
            "either way the file is left at the end of the batch"
        );
        assert_eq!(unread.bytes.position(), stored.len() as u64);
        let (old, new) = (
            &stored[base + RECORD..],
            &stored[base + RECORD + ROW as usize..],
        );
        let record = &stored[base..base + RECORD];
        assert_eq!(
            record[16..48],
            n2r_win32::bulk_digest::digest(Algorithm::WRITTEN, &old[..ROW as usize]).unwrap(),
            "the first row's descriptor holds its OLD digest"
        );
        assert_eq!(
            record[48..80],
            n2r_win32::bulk_digest::digest(Algorithm::WRITTEN, &new[..ROW as usize]).unwrap(),
            "and its NEW digest"
        );
    }

    #[test]
    fn a_staged_batch_is_written_only_at_its_own_offset() {
        let algorithm = Algorithm::WRITTEN;
        let base = BODY + HEADER as u64;
        for read_back in [false, true] {
            let mut journal = Memory {
                bytes: Cursor::new(vec![0u8; usize::try_from(base).unwrap() + 1]),
                corrupt_at: None,
            };
            journal.seek(SeekFrom::Start(base + 1)).unwrap();
            let (mut stage, mut owed) = staged(base, 2);
            let mut written = WrittenHashes {
                whole: None,
                immutable: n2r_win32::bulk_digest::HashedBehind::new(algorithm, 4096).unwrap(),
                read_back,
            };
            let error = complete_staged_rows(
                facts(2),
                &mut journal,
                Path::new("journal"),
                &mut stage,
                &mut Some(base),
                &mut owed,
                &mut RecordHashes::here(algorithm),
                &mut RecordHashes::here(algorithm),
                &mut ZeroDigests::new(),
                Some(&mut written),
                &mut vec![0u8; 1000],
                None,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains(&format!(
                    "the journal journal is at offset {}, not at offset {base}",
                    base + 1
                )),
                "{error:#}"
            );
            assert_eq!(
                journal.bytes.get_ref().len(),
                usize::try_from(base).unwrap() + 1,
                "nothing was written"
            );
        }
    }

    #[test]
    fn only_a_read_back_finds_a_batch_stored_differently_at_once() {
        let corrupt = BODY + HEADER as u64 + RECORD as u64 + 100;
        let (read_back, _) = complete(true, Some(corrupt));
        let error = format!("{:#}", read_back.unwrap_err());
        assert!(
            error.contains("differs from the bytes written"),
            "a run that reads back stops here: {error}"
        );
        // A run that verifies each thing once hashes what it wrote; the gate
        // before the first write to the source then finds the stored body
        // differs from that hash.
        let (as_written, stored) = complete(false, Some(corrupt));
        let base = usize::try_from(BODY + HEADER as u64).unwrap();
        assert_ne!(
            as_written.unwrap(),
            n2r_win32::bulk_digest::digest(Algorithm::WRITTEN, &stored.bytes.get_ref()[base..])
                .unwrap()
        );
    }
}
