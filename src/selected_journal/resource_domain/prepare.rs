//! Experimental, non-authorizing streaming journal construction and readback.
//! Only a freshly created ordinary arena file is writable here. This module
//! cannot publish a ticket, activate a target, or open a source for writes.
use super::*;
use crate::selected_journal::{
    self, BUFFER, PinHash, RecordHashes, RowDigest, SelectedRange, SelectedTicket, ZeroDigests,
    aggregate_pin_hash, at, capture_free_selected, copy_selected_with, finish, frame, get_u32,
    get_u64, pin_hash, put_u32, put_u64, verify_zero_selected_with,
};
use crate::{
    general_reconstruct::selected_native_journal::{
        BoundNativeCreationFacts, BoundNativeCreationJournal, NativeSelectedJournal,
    },
    general_shadow::paged_capture::CaptureRevalidation,
    lab_reconstruct::{DurableIo, ReadSeek},
};

mod qualification;
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
    let memory = domain
        .scratch
        .lease_ram(PREPARATION_BUFFERS * BUFFER as u64)?;
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
        let result = prepare_inner(domain, source, candidate, journal, true, None);
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
const MOST_OWED_BYTES: u64 = 64 * 1024 * 1024;

/// Completes the rows whose payloads are written, in their order: each row's
/// two digests are taken from the workers, its descriptor is written in its
/// place and, where the file's hashes are computed as it is written, the row
/// is read back from the file and hashed in file order. Leaves the file at
/// the end of the last of them.
fn complete_rows<J: DurableIo>(
    f: JournalLayoutFacts,
    file: &mut J,
    owed: &mut Vec<OwedRow>,
    old_records: &mut RecordHashes,
    new_records: &mut RecordHashes,
    zeros: &mut ZeroDigests,
    mut written: Option<&mut (PinHash, PinHash)>,
    buffer: &mut [u8],
) -> Result<()> {
    let Some(end) = owed.last().map(|last| last.row.next_offset) else {
        return Ok(());
    };
    for OwedRow { row, old, new } in owed.drain(..) {
        let old = old_records.settle(old, zeros)?;
        let new = new_records.settle(new, zeros)?;
        let record = encode_record(row, f, old, new);
        file.seek(SeekFrom::Start(row.descriptor_offset))?;
        file.write_all(&record[..f.record_size])?;
        if let Some((whole, immutable)) = written.as_deref_mut() {
            file.seek(SeekFrom::Start(row.descriptor_offset))?;
            let mut stored = [0u8; OLD_ZERO_RECORD];
            file.read_exact(&mut stored[..f.record_size])?;
            ensure!(
                stored[..f.record_size] == record[..f.record_size],
                "journal descriptor read back differs from the one written"
            );
            whole.update(&stored[..f.record_size])?;
            immutable.update(&stored[..f.record_size])?;
            let mut left = row
                .next_offset
                .checked_sub(row.descriptor_offset)
                .and_then(|n| n.checked_sub(f.record_size as u64))
                .context("journal row layout underflow")?;
            while left != 0 {
                let count = usize::try_from(left.min(buffer.len() as u64))?;
                file.read_exact(&mut buffer[..count])?;
                whole.update(&buffer[..count])?;
                immutable.update(&buffer[..count])?;
                left -= count as u64;
            }
        }
    }
    file.seek(SeekFrom::Start(end))?;
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
    let memory = domain
        .scratch
        .lease_ram(PREPARATION_BUFFERS * BUFFER as u64)?;
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
    let (ticket, whole) = prepare_inner(domain, source, candidate, &mut file, false, None)?;
    let readonly = n2r_win32::file_storage::duplicate_readonly(&file)?;
    drop(file);
    let lease = permit.verify_closed_handle(&readonly, &hex::encode(whole))?;
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
    let memory = domain
        .scratch
        .lease_ram(PREPARATION_BUFFERS * BUFFER as u64)?;
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
    // The journal takes the source's changed ranges in ascending order.
    let (ticket, _whole) = source.with_read_ahead(|source| {
        prepare_inner(
            domain,
            source,
            candidate,
            journal,
            same_captured_source,
            capture_witness,
        )
    })?;
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

/// Write and independently read back to the actual exclusively held journal.
/// The returned ticket remains private to this module until a live issuer exists.
fn prepare_inner<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    domain: &ResourceJournalDomain<'_>,
    source: &mut R,
    candidate: &mut S,
    mut file: &mut J,
    same_captured_source: bool,
    capture_witness: Option<&CaptureRevalidation<'_>>,
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
    // The journal's two file hashes cover its bytes in file order, and a row's
    // descriptor is only known after its payload. They used to come from
    // reading the finished journal back, twice over where rows copy from
    // earlier ones, with every range hashed again (77 s for 3.2 GB). Under
    // the check-once policy each row is read back from the file as soon as
    // it is complete and hashed in order, so the hashes are those of the
    // file's own bytes; the gate before the first write to the source hashes
    // the whole body again. A journal with source-free rows rewrites its
    // header at the end and keeps the read-back.
    let mut written = if n2r_win32::verify_policy::checks_once() && f.source_free_bytes == 0 {
        let mut whole = aggregate_pin_hash()?;
        let mut immutable = aggregate_pin_hash()?;
        whole.update(&vec![0u8; usize::try_from(f.body_offset)?])?;
        whole.update(&header)?;
        immutable.update(&header)?;
        Some((whole, immutable))
    } else {
        None
    };
    let mut old_selected = aggregate_pin_hash()?;
    let mut old_restored = if f.source_free_bytes != 0 {
        Some(aggregate_pin_hash()?)
    } else {
        None
    };
    let mut new_selected = aggregate_pin_hash()?;
    let mut buffer = vec![0u8; BUFFER];
    let mut compare = vec![0u8; BUFFER];
    let mut zeros = ZeroDigests::new();
    // A row's descriptor holds the digests of its two payloads. They are
    // computed on two workers, one for the old payloads and one for the new,
    // while this thread reads on: the payloads of a few rows are written
    // first, and then their descriptors, in the same places as before.
    let mut old_records = RecordHashes::overlapped()?;
    let mut new_records = RecordHashes::overlapped()?;
    let mut owed: Vec<OwedRow> = Vec::with_capacity(MOST_OWED_ROWS);
    let mut owed_bytes = 0u64;
    for ordinal in 0..u64::from(f.range_count) {
        let row = domain.row(ordinal)?;
        ensure!(
            file.stream_position()? == row.descriptor_offset,
            "diagnostic journal descriptor offset differs"
        );
        file.write_all(&[0u8; OLD_ZERO_RECORD][..f.record_size])?;
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
            copy_selected_with(
                source,
                &range,
                &mut file,
                &mut old_selected,
                &mut buffer,
                old_restored.as_mut(),
                &mut old_records,
            )?
        };
        ensure!(
            file.stream_position()? == row.new_storage_offset,
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
            copy_candidate_checked(
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
            )?
        };
        ensure!(
            file.stream_position()? == row.next_offset,
            "diagnostic new payload length differs"
        );
        owed_bytes = owed_bytes.saturating_add(
            row.next_offset
                .checked_sub(row.descriptor_offset)
                .context("journal row layout underflow")?,
        );
        owed.push(OwedRow { row, old, new });
        if owed.len() == MOST_OWED_ROWS || owed_bytes >= MOST_OWED_BYTES {
            complete_rows(
                f,
                file,
                &mut owed,
                &mut old_records,
                &mut new_records,
                &mut zeros,
                written.as_mut(),
                &mut buffer,
            )?;
            owed_bytes = 0;
        }
    }
    complete_rows(
        f,
        file,
        &mut owed,
        &mut old_records,
        &mut new_records,
        &mut zeros,
        written.as_mut(),
        &mut buffer,
    )?;
    old_records.finish()?;
    new_records.finish()?;
    let old_sha = finish(old_selected)?;
    let restored_sha = old_restored.map(finish).transpose()?;
    let new_sha = finish(new_selected)?;
    let mut footer = [0u8; FOOTER];
    footer[..8].copy_from_slice(footer_magic);
    footer[8..40].copy_from_slice(&old_sha);
    footer[40..72].copy_from_slice(&new_sha);
    put_u64(&mut footer, 72, f.journal_length);
    file.write_all(&footer)?;
    if let Some((whole, immutable)) = written.as_mut() {
        whole.update(&footer)?;
        immutable.update(&footer)?;
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
    };
    let (immutable, whole) = match written {
        Some((whole, immutable)) => (finish(immutable)?, finish(whole)?),
        None => validate_readback(domain, file, &ticket, &mut buffer, &mut compare)?,
    };
    ticket.immutable_sha256 = immutable;
    // The whole body was just read back and compared with its sources.
    if ticket.marker_profile.is_none() {
        n2r_win32::sha256_native::note_journal_body_verified(
            &immutable,
            BODY,
            ticket.journal_length - BODY,
        );
    }
    revalidate_preparation_domain(domain, capture_witness)?;
    Ok((ticket, whole))
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
    let mut hash = pin_hash()?;
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
    file.seek(SeekFrom::Start(0))?;
    let mut whole = aggregate_pin_hash()?;
    let mut marker_bytes = vec![0u8; usize::try_from(f.body_offset)?];
    file.read_exact(&mut marker_bytes)?;
    ensure!(
        marker_bytes.iter().all(|&b| b == 0),
        "diagnostic journal markers are not clear"
    );
    whole.update(&marker_bytes)?;
    let mut immutable = aggregate_pin_hash()?;
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
    let mut old = aggregate_pin_hash()?;
    let mut new = if f.copy_bytes == 0 {
        Some(aggregate_pin_hash()?)
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
    } else {
        n2r_win32::perf::step("read journal back: resolve copied ranges");
        let mut aggregate = aggregate_pin_hash()?;
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
            let mut hash = pin_hash()?;
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
