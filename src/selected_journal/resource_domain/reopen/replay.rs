//! Streaming replay over an authenticated, held native journal and excluded
//! device. Serialized tickets or indexes alone never construct the native
//! writer; the same actual journal and target must pass the SDK gate first.
use super::*;
use crate::{
    lab_reconstruct::DurableIo,
    selected_journal::{self as sj, JournalRecord, MarkerKind, NewBytes, OldBytes, SelectedResult},
};
use n2r_win32::{
    GeneralExclusiveRecoveryTarget, GeneralFrozenPartition, GeneralJournaledPartition, NativeEvent,
    PagedRecoveryDirection, PagedRecoveryPins,
};

/// Constructed privately only after the real native paged-recovery gate has
/// authenticated the held journal, device, policy and durable lifecycle.
struct ExcludedRecoveryAuthority<'a> {
    target: &'a mut GeneralJournaledPartition,
}

/// Opaque read-only CURRENT OLD-or-NEW observation. There is no constructor
/// from JSON, a selected hash, a path, or a fresh NTFS admission; no Clone,
/// Deserialize, Write implementation or native-writer accessor is exposed.
pub(crate) struct PartitionMixedObservation {
    owner: n2r_win32::PartitionOwnerToken,
    source: n2r_win32::partition_isolation::PartitionSourceBinding,
    journal_owner: usize,
    publication_owner: usize,
    journal_binding: n2r_win32::journal_file::GeneralJournalStorageBinding,
    journal_identity: n2r_win32::journal_file::JournalFileIdentity,
    ticket_sha256: [u8; 32],
    index_sha256: [u8; 32],
    lifecycle: SelectedLifecycle,
    current_selected_sha256: [u8; 32],
}

fn partition_mixed_ticket_pin(ticket: &sj::SelectedTicket) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(ticket)?;
    ensure!(bytes.len() <= 4096, "partition MIXED ticket exceeds bound");
    Ok(<sha2::Sha256 as sha2::Digest>::digest(bytes).into())
}

impl PartitionMixedObservation {
    /// Consume the one-shot observation against the same actual context.
    /// The complete checker runs again, so a stale digest cannot replace the
    /// actual current MIXED bytes. Success is still not a native writer grant:
    /// publication-scope issuance and the SDK partition replay gate remain
    /// separate required boundaries, and HND/ABT are never raw-replayed.
    pub(crate) fn consume_revalidated(
        self,
        observation: &mut BoundJournalObservation<'_>,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        publication: &mut super::envelope::PartitionRecoveryPublicationBinding<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        ensure!(
            self.owner.same_owner(stable)
                && stable.same_owner(&owner.owner_token())
                && owner.binding() == &self.source
                && std::ptr::from_ref(&*observation.observation.journal) as usize
                    == self.journal_owner
                && publication.publication_owner_identity() == self.publication_owner
                && *observation.facts.binding == self.journal_binding
                && *observation.facts.identity == self.journal_identity
                && partition_mixed_ticket_pin(observation.observation.ticket)?
                    == self.ticket_sha256,
            "partition MIXED observation belongs to another actual owner/publication/journal"
        );
        let current = observation.observe_partition_mixed(
            owner, stable, publication, events,
        )?;
        ensure!(
            current.lifecycle == self.lifecycle
                && current.index_sha256 == self.index_sha256
                && current.current_selected_sha256 == self.current_selected_sha256,
            "partition MIXED lifecycle/index/current bytes changed before consumption"
        );
        Ok(())
    }
}

/// Successful terminal replay is returned as the same excluded target with
/// its raw write policy already removed. A HND/ABT result is not permission to
/// mount without the separate native finalization/verification phase.
pub(super) struct MarkerlessReplayResult {
    pub target: GeneralExclusiveRecoveryTarget,
    pub selected: SelectedResult,
    pub handoff: Option<SelectedResult>,
}

pub(super) enum MarkerlessRecoveryTarget {
    Frozen(GeneralFrozenPartition),
    Activated(GeneralExclusiveRecoveryTarget),
}
impl MarkerlessRecoveryTarget {
    fn binding(&self) -> &n2r_win32::general_layout::GeneralDiskBinding {
        match self {
            Self::Frozen(target) => target.binding(),
            Self::Activated(target) => target.binding(),
        }
    }
}

impl BoundJournalObservation<'_> {
    /// Explicit partition CURRENT OLD-or-NEW validation. This is the same
    /// complete per-record/span/granule checker used by dedicated replay,
    /// including resolved COPY, canonical zero and source-free semantics.
    /// It deliberately supplies NO aggregate OLD/NEW expected hash.
    pub(crate) fn observe_partition_mixed(
        &mut self,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        publication: &mut super::envelope::PartitionRecoveryPublicationBinding<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> Result<PartitionMixedObservation> {
        owner.revalidate(events)?;
        ensure!(
            stable.same_owner(&owner.owner_token())
                && self.observation.ticket.marker_profile.is_none()
                && self.facts.marker_native_qualified.is_none()
                && (1..=5).contains(&self.observation.format.version),
            "partition MIXED observation requires the actual stable owner and markerless journal"
        );
        self.observation.revalidate_index()?;
        let lifecycle = self.observation.lifecycle()?;
        ensure!(
            matches!(
                lifecycle,
                SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
            ),
            "partition MIXED observation requires live AP/RB; clear/HND/ABT refuse raw recovery"
        );
        let source = owner.binding().clone();
        let length = owner.byte_len();
        publication.revalidate_partition_mixed(
            owner,
            stable,
            self.observation.journal,
            &self.facts,
            self.observation.ticket,
            events,
        )?;

        // None is intentional: Some(OLD/NEW) would only authenticate one
        // endpoint and would not validate an interrupted mixed target.
        let current_selected_sha256 =
            self.observation.check_target_reader(owner, length, None, false)?;

        publication.revalidate_partition_mixed(
            owner,
            stable,
            self.observation.journal,
            &self.facts,
            self.observation.ticket,
            events,
        )?;
        self.observation.revalidate_index()?;
        ensure!(
            self.observation.lifecycle()? == lifecycle
                && owner.binding() == &source
                && owner.byte_len() == length
                && stable.same_owner(&owner.owner_token()),
            "partition MIXED actual owner/binding/journal lifecycle changed during scan"
        );
        owner.revalidate(events)?;
        let index_sha256 = self.observation.index.facts()?.index_sha256;
        Ok(PartitionMixedObservation {
            owner: stable.clone(),
            source,
            journal_owner: std::ptr::from_ref(&*self.observation.journal) as usize,
            publication_owner: publication.publication_owner_identity(),
            journal_binding: self.facts.binding.clone(),
            journal_identity: self.facts.identity.clone(),
            ticket_sha256: partition_mixed_ticket_pin(self.observation.ticket)?,
            index_sha256,
            lifecycle,
            current_selected_sha256,
        })
    }

    /// The caller must retain its independently pinned recovery publication,
    /// expected/map owners, and exact target binding throughout this one-shot
    /// operation. The actual journal scanner and its paged index stay alive
    /// through every native write and marker barrier.
    pub(super) fn replay_markerless<F: FnOnce(&SelectedResult) -> Result<()>>(
        mut self,
        target: MarkerlessRecoveryTarget,
        expected_source: &n2r_win32::general_layout::GeneralDiskBinding,
        direction: PagedRecoveryDirection,
        after_resume: F,
        events: &mut Vec<NativeEvent>,
    ) -> Result<MarkerlessReplayResult> {
        ensure!(
            self.observation.ticket.marker_profile.is_none()
                && self.facts.marker_native_qualified.is_none()
                && target.binding() == expected_source,
            "resource replay currently supports markerless native journals only"
        );
        self.observation.revalidate_index()?;
        let state = self.observation.lifecycle()?;
        ensure!(
            match direction {
                PagedRecoveryDirection::Resume => state == SelectedLifecycle::ApplyIntent,
                PagedRecoveryDirection::Rollback => matches!(
                    state,
                    SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
                ),
            },
            "actual held journal lifecycle refuses the requested resource replay"
        );
        let ticket = self.observation.ticket;
        let pins = PagedRecoveryPins {
            journal_binding: self.facts.binding,
            journal_identity: self.facts.identity,
            journal_path: self.facts.path,
            journal_profile: self.facts.profile,
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        // Keep the arena's actual index owner alive after the scanner is
        // consumed and until the native writer has discarded its clone.
        let index_owner = self.observation.index_lease.clone();
        let policy = self.observation.index.clone();
        let mut writer = {
            let held_journal = self.observation.journal.markerless_recovery_file()?;
            let target = match target {
                MarkerlessRecoveryTarget::Frozen(source) => source
                    .into_paged_recovery_target_from_frozen(
                        &policy,
                        held_journal,
                        &pins,
                        direction,
                        events,
                    )?,
                MarkerlessRecoveryTarget::Activated(target) => target,
            };
            target.arm_paged_recovery(policy, held_journal, &pins, direction, events)?
        };
        let authority = ExcludedRecoveryAuthority {
            target: &mut writer,
        };
        let (selected, handoff) = match direction {
            PagedRecoveryDirection::Resume => {
                let (selected, handoff) =
                    self.observation.resume_guarded(authority, after_resume)?;
                (selected, Some(handoff))
            }
            PagedRecoveryDirection::Rollback => {
                let selected = self.observation.rollback_guarded(authority)?;
                (selected, None)
            }
        };
        let target = writer.into_unarmed_paged_recovery(events)?;
        index_owner.retire()?;
        Ok(MarkerlessReplayResult {
            target,
            selected,
            handoff,
        })
    }

    /// Observe a fully authenticated durable HND and its exact selected target
    /// bytes through the same held offline target. This is read-only and does
    /// not establish namespace, payload-map or mounted-filesystem validity.
    pub(super) fn verify_handoff_data<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<[u8; 32]> {
        self.observation.revalidate_index()?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::Handoff,
            "a durable handoff is required before target verification"
        );
        let expected = self.observation.ticket.new_selected_sha256;
        let digest =
            self.observation
                .check_target_reader(target, target_length, Some(expected), false)?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::Handoff,
            "handoff lifecycle changed during target verification"
        );
        self.observation
            .journal
            .require_native_mount_barriers(self.observation.ticket)?;
        Ok(digest)
    }

    pub(super) fn verify_aborted_data<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<[u8; 32]> {
        self.observation.revalidate_index()?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::Aborted,
            "durable abort is required before restored-source verification"
        );
        let mut intent = [0u8; GRANULE as usize];
        at(self.observation.journal, GRANULE, &mut intent)?;
        let digest = if intent.iter().all(|&b| b == 0) {
            self.observation.check_target_reader(
                target,
                target_length,
                Some(self.observation.ticket.old_selected_sha256),
                true,
            )?
        } else {
            self.observation
                .check_restored_reader(target, target_length)?
        };
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::Aborted,
            "abort lifecycle changed during restored-source verification"
        );
        self.observation
            .journal
            .require_native_mount_barriers(self.observation.ticket)?;
        Ok(digest)
    }

    /// Close a never-started, actually clear journal without issuing any
    /// source writes. A failed/torn marker remains an explicit recovery error.
    pub(super) fn abandon_clear_data<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<()> {
        self.abandon_clear_data_with_before_abort(target, target_length, || Ok(()))
    }

    /// The callback exists only inside this actual clear-journal/OLD-source
    /// proof boundary. It may retire a preparation-only guard before ABT; no
    /// saved phase or successful earlier observation can invoke it separately.
    pub(super) fn abandon_clear_data_with_before_abort<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
        before_abort: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        ensure!(
            self.observation.ticket.marker_profile.is_none()
                && self.facts.marker_native_qualified.is_none(),
            "clear abandonment supports markerless journals only"
        );
        self.observation.revalidate_index()?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::PreparedClear,
            "actual journal is not clear for abandonment"
        );
        self.observation.check_target_reader(
            target,
            target_length,
            Some(self.observation.ticket.old_selected_sha256),
            true,
        )?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::PreparedClear,
            "journal changed during clear-source verification"
        );
        before_abort()?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::PreparedClear,
            "journal changed during preparation-guard retirement"
        );
        sj::write_lifecycle_marker(
            self.observation.journal,
            self.observation.ticket,
            MarkerKind::Aborted,
        )?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::Aborted,
            "durable abandonment marker did not read back"
        );
        self.observation
            .journal
            .require_native_mount_barriers(self.observation.ticket)?;
        Ok(())
    }
}

fn record(row: Record) -> JournalRecord {
    JournalRecord {
        range: row.range(),
        before: match row.old_kind {
            0 => OldBytes::Payload(row.old_payload),
            1 => OldBytes::Zero,
            2 => OldBytes::SourceFree(row.old_payload),
            _ => unreachable!(),
        },
        after: match row.new_kind {
            0 => NewBytes::Payload(row.new_payload),
            1 => NewBytes::Zero,
            2 => NewBytes::OldReference(row.copy_source),
            _ => unreachable!(),
        },
        new_sha256: row.new_hash,
    }
}

struct Buffers {
    current: Vec<u8>,
    before: Vec<u8>,
    after: Vec<u8>,
}
impl Buffers {
    fn new() -> Self {
        Self {
            current: vec![0; BUFFER],
            before: vec![0; BUFFER],
            after: vec![0; BUFFER],
        }
    }
}

impl JournalObservation<'_> {
    fn read_after_row(
        &mut self,
        row: Record,
        ordinal: u64,
        within: u64,
        out: &mut [u8],
    ) -> Result<()> {
        ensure!(
            within
                .checked_add(out.len() as u64)
                .is_some_and(|end| end <= row.length),
            "replay NEW read escapes record"
        );
        match row.new_kind {
            0 => at(self.journal, add(row.new_payload, within)?, out),
            1 => {
                out.fill(0);
                Ok(())
            }
            2 => self.read_prior_old(add(row.copy_source, within)?, ordinal, out),
            _ => unreachable!(),
        }
    }

    /// Exact digest when provided; otherwise reject every foreign byte (or
    /// foreign source-free granule), matching selected_journal::check_target.
    fn check_target(
        &mut self,
        target: &mut GeneralJournaledPartition,
        expected: Option<[u8; 32]>,
        fresh_old: bool,
    ) -> Result<[u8; 32]> {
        let length = GeneralJournaledPartition::byte_len(target);
        self.check_target_reader(target, length, expected, fresh_old)
    }

    /// The same complete selected-byte check also applies to a held
    /// read-only recovery target when verifying an already durable handoff.
    fn check_target_reader<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
        expected: Option<[u8; 32]>,
        fresh_old: bool,
    ) -> Result<[u8; 32]> {
        ensure!(
            target_length == self.ticket.image_length,
            "replay target length differs"
        );
        let mut digest = pin_hash()?;
        let mut buffers = Buffers::new();
        for ordinal in 0..u64::from(self.ticket.range_count) {
            let row = self.record(ordinal)?;
            frame(&mut digest, &row.range())?;
            let record = record(row);
            let mut done = 0u64;
            while done < row.length {
                let count = usize::try_from((row.length - done).min(BUFFER as u64))?;
                at(
                    target,
                    add(row.offset, done)?,
                    &mut buffers.current[..count],
                )?;
                if expected.is_some() && fresh_old && row.old_kind == 2 {
                    sj::check_free_granules(
                        self.journal,
                        &record,
                        done,
                        &buffers.current[..count],
                        None,
                    )?;
                } else if expected.is_none() {
                    self.read_after_row(row, ordinal, done, &mut buffers.after[..count])?;
                    if row.old_kind == 2 {
                        sj::check_free_granules(
                            self.journal,
                            &record,
                            done,
                            &buffers.current[..count],
                            Some(&buffers.after[..count]),
                        )?;
                    } else {
                        sj::read_before(self.journal, &record, done, &mut buffers.before[..count])?;
                        ensure!(
                            sj::bytes_are_old_or_new(
                                &buffers.current[..count],
                                &buffers.before[..count],
                                &buffers.after[..count]
                            ),
                            "replay target contains a foreign byte"
                        );
                    }
                }
                digest.update(&buffers.current[..count])?;
                done = add(done, count as u64)?;
            }
        }
        let actual = finish(digest)?;
        ensure!(
            expected.is_none_or(|value| value == actual),
            "replay target digest differs"
        );
        Ok(actual)
    }

    fn check_restored(&mut self, target: &mut GeneralJournaledPartition) -> Result<[u8; 32]> {
        let length = target.byte_len()?;
        self.check_restored_reader(target, length)
    }

    fn check_restored_reader<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<[u8; 32]> {
        let Some(expected) = self.ticket.old_restored_selected_sha256 else {
            return self.check_target_reader(
                target,
                target_length,
                Some(self.ticket.old_selected_sha256),
                false,
            );
        };
        ensure!(
            target_length == self.ticket.image_length,
            "replay target length differs"
        );
        let mut digest = pin_hash()?;
        let mut buffers = Buffers::new();
        for ordinal in 0..u64::from(self.ticket.range_count) {
            let row = self.record(ordinal)?;
            if row.old_kind != 2 {
                frame(&mut digest, &row.range())?;
            }
            let record = record(row);
            let mut done = 0u64;
            while done < row.length {
                let count = usize::try_from((row.length - done).min(BUFFER as u64))?;
                at(
                    target,
                    add(row.offset, done)?,
                    &mut buffers.current[..count],
                )?;
                if row.old_kind == 2 {
                    self.read_after_row(row, ordinal, done, &mut buffers.after[..count])?;
                    sj::check_free_granules(
                        self.journal,
                        &record,
                        done,
                        &buffers.current[..count],
                        Some(&buffers.after[..count]),
                    )?;
                } else {
                    digest.update(&buffers.current[..count])?;
                }
                done = add(done, count as u64)?;
            }
        }
        let actual = finish(digest)?;
        ensure!(actual == expected, "replay restore-required digest differs");
        Ok(actual)
    }

    fn write_span(
        &mut self,
        target: &mut GeneralJournaledPartition,
        row: Record,
        ordinal: u64,
        start: u64,
        length: u64,
        forward: bool,
        buffers: &mut Buffers,
    ) -> Result<()> {
        ensure!(
            start
                .checked_add(length)
                .is_some_and(|end| end <= row.length),
            "replay span exceeds record"
        );
        let record = record(row);
        let mut done = 0u64;
        while done < length {
            let count = usize::try_from((length - done).min(BUFFER as u64))?;
            let within = add(start, done)?;
            let offset = add(row.offset, within)?;
            at(target, offset, &mut buffers.current[..count])?;
            self.read_after_row(row, ordinal, within, &mut buffers.after[..count])?;
            if row.old_kind == 2 {
                sj::check_free_granules(
                    self.journal,
                    &record,
                    within,
                    &buffers.current[..count],
                    Some(&buffers.after[..count]),
                )?;
                if !forward {
                    done = add(done, count as u64)?;
                    continue;
                }
            } else {
                sj::read_before(self.journal, &record, within, &mut buffers.before[..count])?;
                ensure!(
                    sj::bytes_are_old_or_new(
                        &buffers.current[..count],
                        &buffers.before[..count],
                        &buffers.after[..count]
                    ),
                    "replay target changed before write"
                );
            }
            let desired = if forward {
                &buffers.after[..count]
            } else {
                &buffers.before[..count]
            };
            if &buffers.current[..count] != desired {
                target.seek(SeekFrom::Start(offset))?;
                ensure!(target.write(desired)? == count, "short replay target write");
            }
            done = add(done, count as u64)?;
        }
        Ok(())
    }

    fn execute(
        &mut self,
        target: &mut GeneralJournaledPartition,
        forward: bool,
    ) -> Result<SelectedResult> {
        self.revalidate_index()?;
        let (apply, rollback) = sj::read_markers(self.journal, self.ticket)?;
        ensure!(
            if forward {
                apply && !rollback
            } else {
                apply || rollback
            },
            "replay lifecycle does not permit this direction"
        );
        target.sync_all()?;
        self.check_target(target, None, false)?;
        if !forward && self.ticket.marker_profile.is_some() {
            ensure!(
                apply && sj::read_marker_pair(self.journal, self.ticket, MarkerKind::Apply)?,
                "rollback cannot repair an absent apply intent"
            );
            sj::write_lifecycle_marker(self.journal, self.ticket, MarkerKind::Apply)?;
            ensure!(
                sj::read_markers(self.journal, self.ticket)? == (apply, rollback),
                "replay lifecycle changed during peer repair"
            );
        }
        sj::write_lifecycle_marker(
            self.journal,
            self.ticket,
            if forward {
                MarkerKind::Apply
            } else {
                MarkerKind::Rollback
            },
        )?;
        let mut buffers = Buffers::new();
        for ordinal in 0..u64::from(self.ticket.range_count) {
            let row = self.record(ordinal)?;
            let skip = if row.offset == 0 { GRANULE } else { 0 };
            self.write_span(
                target,
                row,
                ordinal,
                skip,
                row.length - skip,
                forward,
                &mut buffers,
            )?;
        }
        target.sync_all()?;
        let first = self.record(0)?;
        if first.offset == 0 {
            self.write_span(target, first, 0, 0, GRANULE, forward, &mut buffers)?;
        }
        drop(buffers);
        target.sync_all()?;
        let digest = if forward {
            self.check_target(target, Some(self.ticket.new_selected_sha256), false)?
        } else {
            self.check_restored(target)?
        };
        if !forward {
            sj::write_lifecycle_marker(self.journal, self.ticket, MarkerKind::Aborted)?;
        }
        let restored_bytes = if !forward && self.ticket.old_restored_selected_sha256.is_some() {
            let mut total = 0u64;
            for ordinal in 0..u64::from(self.ticket.range_count) {
                let row = self.record(ordinal)?;
                if row.old_kind != 2 {
                    total = add(total, row.length)?;
                }
            }
            Some(total)
        } else {
            None
        };
        Ok(SelectedResult {
            selected_sha256: digest,
            selected_bytes: self.ticket.selected_bytes,
            range_count: self.ticket.range_count,
            replay_closed: !forward,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: restored_bytes,
        })
    }

    fn resume_guarded<F: FnOnce(&SelectedResult) -> Result<()>>(
        mut self,
        authority: ExcludedRecoveryAuthority<'_>,
        after_resume: F,
    ) -> Result<(SelectedResult, SelectedResult)> {
        ensure!(
            sj::classify(self.journal, self.ticket)? == SelectedLifecycle::ApplyIntent,
            "resume requires observed apply intent"
        );
        let resumed = self.execute(authority.target, true)?;
        after_resume(&resumed)?;
        let (apply, rollback) = sj::read_markers(self.journal, self.ticket)?;
        ensure!(
            apply && !rollback,
            "handoff requires completed forward intent"
        );
        authority.target.sync_all()?;
        let digest = self.check_target(
            authority.target,
            Some(self.ticket.new_selected_sha256),
            false,
        )?;
        sj::write_lifecycle_marker(self.journal, self.ticket, MarkerKind::Handoff)?;
        self.journal.require_native_mount_barriers(self.ticket)?;
        let closed = SelectedResult {
            selected_sha256: digest,
            selected_bytes: self.ticket.selected_bytes,
            range_count: self.ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: None,
        };
        Ok((resumed, closed))
    }

    fn rollback_guarded(
        mut self,
        authority: ExcludedRecoveryAuthority<'_>,
    ) -> Result<SelectedResult> {
        ensure!(
            matches!(
                sj::classify(self.journal, self.ticket)?,
                SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
            ),
            "rollback requires observed operation intent"
        );
        let result = self.execute(authority.target, false)?;
        self.journal.require_native_mount_barriers(self.ticket)?;
        Ok(result)
    }

    fn restored_bytes(&mut self) -> Result<Option<u64>> {
        if self.ticket.old_restored_selected_sha256.is_none() {
            return Ok(None);
        }
        let mut total = 0u64;
        for ordinal in 0..u64::from(self.ticket.range_count) {
            let row = self.record(ordinal)?;
            if row.old_kind != 2 {
                total = add(total, row.length)?;
            }
        }
        Ok(Some(total))
    }

    fn abandon_guarded(
        mut self,
        authority: ExcludedRecoveryAuthority<'_>,
    ) -> Result<SelectedResult> {
        ensure!(
            sj::classify(self.journal, self.ticket)? == SelectedLifecycle::PreparedClear,
            "abandon requires an observed clear lifecycle"
        );
        let (apply, rollback) = sj::read_markers(self.journal, self.ticket)?;
        ensure!(!apply && !rollback, "abandon requires no operation intent");
        authority.target.sync_all()?;
        let original = self.check_target(
            authority.target,
            Some(self.ticket.old_selected_sha256),
            true,
        )?;
        sj::write_lifecycle_marker(self.journal, self.ticket, MarkerKind::Aborted)?;
        self.journal.require_native_mount_barriers(self.ticket)?;
        let restored_bytes = self.restored_bytes()?;
        Ok(SelectedResult {
            selected_sha256: self.ticket.old_restored_selected_sha256.unwrap_or(original),
            selected_bytes: self.ticket.selected_bytes,
            range_count: self.ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: restored_bytes,
        })
    }

    fn verify_closed_guarded(
        mut self,
        authority: ExcludedRecoveryAuthority<'_>,
    ) -> Result<(SelectedLifecycle, SelectedResult)> {
        self.revalidate_index()?;
        let state = sj::classify(self.journal, self.ticket)?;
        ensure!(
            matches!(
                state,
                SelectedLifecycle::Handoff | SelectedLifecycle::Aborted
            ),
            "closed verification requires HND or ABT"
        );
        let digest = if state == SelectedLifecycle::Handoff {
            self.check_target(
                authority.target,
                Some(self.ticket.new_selected_sha256),
                false,
            )?
        } else {
            self.check_restored(authority.target)?
        };
        ensure!(
            sj::classify(self.journal, self.ticket)? == state,
            "closed lifecycle changed"
        );
        if self.ticket.marker_profile.is_some() {
            sj::write_lifecycle_marker(
                self.journal,
                self.ticket,
                if state == SelectedLifecycle::Handoff {
                    MarkerKind::Handoff
                } else {
                    MarkerKind::Aborted
                },
            )?;
            let after = if state == SelectedLifecycle::Handoff {
                self.check_target(
                    authority.target,
                    Some(self.ticket.new_selected_sha256),
                    false,
                )?
            } else {
                self.check_restored(authority.target)?
            };
            ensure!(
                after == digest && sj::classify(self.journal, self.ticket)? == state,
                "closed target or lifecycle changed during peer repair"
            );
        }
        self.journal.require_native_mount_barriers(self.ticket)?;
        let restored = if state == SelectedLifecycle::Aborted {
            self.restored_bytes()?
        } else {
            None
        };
        Ok((
            state,
            SelectedResult {
                selected_sha256: digest,
                selected_bytes: self.ticket.selected_bytes,
                range_count: self.ticket.range_count,
                replay_closed: true,
                whole_image_verified: false,
                conversion_qualified: false,
                old_restoration_bytes: restored,
            },
        ))
    }
}
