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
        let current = observation.observe_partition_mixed(owner, stable, publication, events)?;
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

/// Where a resumed replay ends: at the handoff, as every run did before, or
/// before it, for a run whose handoff follows its verification (#148).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ResumeEnd {
    Handoff,
    BeforeHandoff,
}

pub(super) enum MarkerlessRecoveryTarget {
    Frozen(GeneralFrozenPartition),
    /// The frozen source of a run whose authenticated publication records
    /// that it stops for a review (#110) or that its handoff follows its
    /// verification (#148): exactly old or exactly new.
    FrozenReview(GeneralFrozenPartition),
    Activated(GeneralExclusiveRecoveryTarget),
}
impl MarkerlessRecoveryTarget {
    fn binding(&self) -> &n2r_win32::general_layout::GeneralDiskBinding {
        match self {
            Self::Frozen(target) | Self::FrozenReview(target) => target.binding(),
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
        let length = n2r_win32::PartitionScopedOwner::byte_len(owner);
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
        let current_selected_sha256 = self
            .observation
            .check_target_reader(owner, length, None, false)?;

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
                && n2r_win32::PartitionScopedOwner::byte_len(owner) == length
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
        resume_end: ResumeEnd,
        after_resume: F,
        events: &mut Vec<NativeEvent>,
    ) -> Result<MarkerlessReplayResult> {
        n2r_win32::perf::step("replay: authenticate journal and arm");
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
            digest: ticket.digest_algorithm(),
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
                MarkerlessRecoveryTarget::FrozenReview(source) => source
                    .into_paged_recovery_target_from_frozen_for_review(
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
                self.observation
                    .resume_guarded(authority, resume_end, after_resume)?
            }
            PagedRecoveryDirection::Rollback => {
                let selected = self.observation.rollback_guarded(authority)?;
                (selected, None)
            }
        };
        n2r_win32::perf::step("replay: disarm and revalidate");
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
    pub(super) fn verify_handoff_data<R: OrderedSource>(
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
        // The apply step read every changed range back after writing it and
        // the source has been offline and read-only since. When that happened
        // in this same process the read-back is not made a second time; a
        // recovery process always makes it.
        let digest = if n2r_win32::selected_new_bytes_verified(
            &self.observation.ticket.immutable_sha256,
            &expected,
        ) {
            ensure!(
                target_length == self.observation.ticket.image_length,
                "replay target length differs"
            );
            expected
        } else {
            self.observation
                .check_target_ahead(target, target_length, Some(expected), false)?
        };
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::Handoff,
            "handoff lifecycle changed during target verification"
        );
        self.observation
            .journal
            .require_native_mount_barriers(self.observation.ticket)?;
        n2r_win32::note_selected_new_bytes_verified(
            &self.observation.ticket.immutable_sha256,
            &expected,
        );
        Ok(digest)
    }

    /// The verification before a handoff (the review stop, #110, and a run
    /// whose handoff follows its verification, #148): the apply intent alone,
    /// and every selected byte exactly NEW, through the same held offline
    /// target. Like the handoff's above, it is read-only and claims nothing
    /// about the converted namespace.
    pub(super) fn verify_review_data<R: OrderedSource>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<[u8; 32]> {
        self.observation.revalidate_index()?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::ApplyIntent,
            "verification before the handoff requires the apply intent alone"
        );
        let expected = self.observation.ticket.new_selected_sha256;
        let digest = if n2r_win32::selected_new_bytes_verified(
            &self.observation.ticket.immutable_sha256,
            &expected,
        ) {
            ensure!(
                target_length == self.observation.ticket.image_length,
                "target length differs before the handoff"
            );
            expected
        } else {
            self.observation
                .check_target_ahead(target, target_length, Some(expected), false)?
        };
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::ApplyIntent,
            "the lifecycle changed during target verification before the handoff"
        );
        n2r_win32::note_selected_new_bytes_verified(
            &self.observation.ticket.immutable_sha256,
            &expected,
        );
        Ok(digest)
    }

    /// Writes the handoff of a run whose handoff follows its verification
    /// (#148): the apply intent alone and every selected byte exactly NEW
    /// are authenticated through the same held, sealed source first; the
    /// marker is then written, flushed and read back as a replay's is. The
    /// caller holds the proof that the converted volume passed its
    /// verification; nothing is written to the source.
    pub(super) fn write_handoff_after_verification<R: OrderedSource>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<[u8; 32]> {
        let journal = self.facts.path;
        ensure!(
            self.observation.ticket.marker_profile.is_none()
                && self.facts.marker_native_qualified.is_none(),
            "handoff after the verification: the recovery journal {} keeps redundant or \
             natively qualified markers, and a handoff after the verification supports \
             markerless journals only; nothing was written",
            journal.display()
        );
        let digest = self
            .verify_review_data(target, target_length)
            .with_context(|| {
                format!(
                    "handoff after the verification: authenticating the apply intent alone and \
                     every new byte against the recovery journal {} before the handoff is \
                     written; nothing was written",
                    journal.display()
                )
            })?;
        let (apply, rollback) = sj::read_markers(self.observation.journal, self.observation.ticket)
            .with_context(|| {
                format!(
                    "handoff after the verification: reading the lifecycle markers of the \
                     recovery journal {}",
                    journal.display()
                )
            })?;
        ensure!(
            apply && !rollback,
            "handoff after the verification: the recovery journal {} does not hold the apply \
             intent alone (apply {apply}, rollback {rollback}); nothing was written",
            journal.display()
        );
        sj::write_lifecycle_marker(
            self.observation.journal,
            self.observation.ticket,
            MarkerKind::Handoff,
        )
        .with_context(|| {
            format!(
                "handoff after the verification: writing the handoff marker of the recovery \
                 journal {}",
                journal.display()
            )
        })?;
        self.observation
            .journal
            .require_native_mount_barriers(self.observation.ticket)
            .with_context(|| {
                format!(
                    "handoff after the verification: flushing the handoff marker of the \
                     recovery journal {}",
                    journal.display()
                )
            })?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::Handoff,
            "handoff after the verification: the handoff marker of the recovery journal {} did \
             not read back as written",
            journal.display()
        );
        Ok(digest)
    }

    pub(super) fn verify_aborted_data<R: OrderedSource>(
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
            self.observation.check_target_ahead(
                target,
                target_length,
                Some(self.observation.ticket.old_selected_sha256),
                true,
            )?
        } else {
            self.observation
                .check_restored_ahead(target, target_length)?
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
    /// source writes. A marker write that fails here is an explicit error; one
    /// that a power loss cut short is settled by the next recovery, before it
    /// reads the lifecycle (`interrupted_marker`).
    pub(super) fn abandon_clear_data<R: OrderedSource>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<()> {
        self.abandon_clear_data_with_before_abort(target, target_length, || Ok(()))
    }

    /// The callback exists only inside this actual clear-journal/OLD-source
    /// proof boundary. It may retire a preparation-only guard before ABT; no
    /// saved phase or successful earlier observation can invoke it separately.
    pub(super) fn abandon_clear_data_with_before_abort<R: OrderedSource>(
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
        self.observation.check_target_ahead(
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

/// A held source whose changed ranges a pass reads in ascending order and
/// can therefore read ahead: the journaled target of a replay, the excluded
/// target it leaves, and the frozen source. Nothing writes to the source
/// during such a pass, and the read-ahead window is dropped when it ends,
/// so no later read is served from memory.
pub(super) trait OrderedSource: Read + Seek {
    /// Runs `pass` with read-ahead on, and turns it off again.
    fn reading_ahead<T>(&mut self, pass: impl FnOnce(&mut Self) -> T) -> T;
    /// Tells read-ahead where the ranges the pass reads next end.
    fn reach(&mut self, end: u64);
}
impl OrderedSource for GeneralJournaledPartition {
    fn reading_ahead<T>(&mut self, pass: impl FnOnce(&mut Self) -> T) -> T {
        self.set_read_ahead(true);
        let result = pass(self);
        self.set_read_ahead(false);
        result
    }
    fn reach(&mut self, end: u64) {
        self.set_read_ahead_reach(end);
    }
}
impl OrderedSource for GeneralExclusiveRecoveryTarget {
    fn reading_ahead<T>(&mut self, pass: impl FnOnce(&mut Self) -> T) -> T {
        self.set_read_ahead(true);
        let result = pass(self);
        self.set_read_ahead(false);
        result
    }
    fn reach(&mut self, end: u64) {
        self.set_read_ahead_reach(end);
    }
}
impl OrderedSource for GeneralFrozenPartition {
    fn reading_ahead<T>(&mut self, pass: impl FnOnce(&mut Self) -> T) -> T {
        self.with_read_ahead(pass)
    }
    fn reach(&mut self, end: u64) {
        self.set_read_ahead_reach(end);
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

/// What the classification in front of a replay's write pass found: one bit
/// for each chunk that pass takes, in the order it counts them, set where
/// the replay has nothing to write. Such a chunk already holds what the
/// replay would write, or is one a rollback never writes (a source-free
/// range has no old bytes to put back).
///
/// It is a local of the one `execute` that classified, held in spare memory
/// and never stored: a replay that is run again classifies the device again.
struct Classified {
    bits: Vec<u64>,
    /// How many chunks the classification has noted.
    noted: u64,
    _memory: crate::artifact_arena::ArenaRamLease,
}
impl Classified {
    /// Room for every chunk of the write pass, or `None` where the arena
    /// has no spare memory for it. The replay then runs without it: every
    /// chunk is read again before it is written, as before.
    fn reserve(
        arena: &crate::artifact_arena::ArtifactArena,
        ticket: &SelectedTicket,
    ) -> Option<Self> {
        // A range is cut into megabyte chunks, the last of them shorter;
        // the first granule of a range at offset 0 is one more.
        let chunks = (ticket.selected_bytes / BUFFER as u64)
            .checked_add(u64::from(ticket.range_count))?
            .checked_add(1)?;
        let words = usize::try_from(chunks.div_ceil(64)).ok()?;
        let bytes = u64::try_from(words).ok()?.checked_mul(8)?;
        let memory = arena.reserve_spare_ram(bytes).ok()?;
        let mut bits = Vec::new();
        bits.try_reserve_exact(words).ok()?;
        bits.resize(words, 0);
        Some(Self {
            bits,
            noted: 0,
            _memory: memory,
        })
    }

    /// Notes the next chunk, in the order the write pass counts them.
    fn note(&mut self, nothing_to_write: bool) {
        let word = usize::try_from(self.noted / 64)
            .ok()
            .and_then(|word| self.bits.get_mut(word));
        if let (true, Some(word)) = (nothing_to_write, word) {
            *word |= 1 << (self.noted % 64);
        }
        self.noted = self.noted.saturating_add(1);
    }

    /// Whether every chunk that was noted has a bit. A ticket whose counts
    /// understate its ranges leaves chunks without one, and the write pass
    /// then does without all of it.
    fn complete(&self) -> bool {
        self.noted <= (self.bits.len() as u64).saturating_mul(64)
    }

    /// Whether the replay has nothing to write to chunk `chunk`; `None` for
    /// a chunk the classification did not note, which the write pass then
    /// reads first, as it does without this.
    fn nothing_to_write(&self, chunk: u64) -> Option<bool> {
        if chunk >= self.noted {
            return None;
        }
        let word = self.bits.get(usize::try_from(chunk / 64).ok()?)?;
        Some((word >> (chunk % 64)) & 1 == 1)
    }
}

/// A classification made in front of a replay's write pass (`execute`):
/// the direction of the replay and, if memory for it was granted, where the
/// verdict on each chunk is kept.
struct Classify<'a> {
    forward: bool,
    remembered: Option<&'a mut Classified>,
}

/// What the write pass knows of a span from the classification in front of
/// it (`Classified`).
#[derive(Clone, Copy)]
struct Known<'a> {
    classified: &'a Classified,
    /// The number of the span's first chunk, as the classification counted.
    first: u64,
    /// Whether a chunk that needs writing is written without being read
    /// first, as the apply of the run being recovered did
    /// (`verify_policy::repeats_once_as_verified`).
    unread: bool,
}

/// Refuses a chunk that holds a byte that is neither its old nor its new
/// one, naming the first such byte and its granule.
fn require_old_or_new(
    row: Record,
    ordinal: u64,
    done: u64,
    count: usize,
    buffers: &Buffers,
) -> Result<()> {
    if sj::bytes_are_old_or_new(
        &buffers.current[..count],
        &buffers.before[..count],
        &buffers.after[..count],
    ) {
        return Ok(());
    }
    let foreign = buffers.current[..count]
        .iter()
        .zip(&buffers.before[..count])
        .zip(&buffers.after[..count])
        .position(|((current, old), new)| current != old && current != new)
        .context("foreign-byte comparison has no differing position")?;
    let start = foreign / GRANULE as usize * GRANULE as usize;
    let end = (start + GRANULE as usize).min(count);
    let hash = |bytes: &[u8]| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
    anyhow::bail!(
        "replay target contains a foreign byte: descriptor={ordinal}, range_offset={}, range_length={}, byte_offset={}, granule_offset={}, old_kind={}, new_kind={}, current_sha256={}, old_sha256={}, new_sha256={}",
        row.offset,
        row.length,
        add(add(row.offset, done)?, foreign as u64)?,
        add(add(row.offset, done)?, start as u64)?,
        row.old_kind,
        row.new_kind,
        hash(&buffers.current[start..end]),
        hash(&buffers.before[start..end]),
        hash(&buffers.after[start..end]),
    );
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
        self.check_target_ahead(target, length, expected, fresh_old)
    }

    /// [`Self::check_target_reader`] for a source that reads ahead. The pass
    /// reads every changed range once, in ascending order, and writes
    /// nothing; read-ahead is on for the pass alone.
    fn check_target_ahead<R: OrderedSource>(
        &mut self,
        target: &mut R,
        target_length: u64,
        expected: Option<[u8; 32]>,
        fresh_old: bool,
    ) -> Result<[u8; 32]> {
        target.reading_ahead(|target| {
            self.check_target_reaching(target, target_length, expected, fresh_old, R::reach, None)
        })
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
        self.check_target_reaching(target, target_length, expected, fresh_old, |_, _| (), None)
    }

    /// Holds one chunk of the target, already read into `buffers.current`,
    /// to the rule of a classification: every byte is its recorded old or
    /// new byte, and every granule of a source-free range is original or
    /// new. `direction` is that of the replay the classification is made
    /// for, if it is made for one; what is returned is whether that replay
    /// has nothing to write to the chunk.
    ///
    /// With a direction, the side the replay will write is read first, and
    /// the other side only where the chunk differs from it: a chunk that
    /// equals either side is old-or-new whatever the other holds
    /// (`bytes_are_old_or_new` is true on that equality alone), so the
    /// verdict is the one both sides give. Without a direction both sides
    /// are read, as they always were.
    fn classify_chunk(
        &mut self,
        row: Record,
        ordinal: u64,
        done: u64,
        count: usize,
        buffers: &mut Buffers,
        direction: Option<bool>,
    ) -> Result<bool> {
        let record = &record(row);
        if direction == Some(false) && row.old_kind != 2 {
            sj::read_before(self.journal, record, done, &mut buffers.before[..count])?;
            if buffers.current[..count] == buffers.before[..count] {
                return Ok(true);
            }
            self.read_after_row(row, ordinal, done, &mut buffers.after[..count])?;
            require_old_or_new(row, ordinal, done, count, buffers)?;
            return Ok(false);
        }
        self.read_after_row(row, ordinal, done, &mut buffers.after[..count])?;
        let new = direction == Some(true) && buffers.current[..count] == buffers.after[..count];
        if row.old_kind == 2 {
            sj::check_free_granules(
                self.journal,
                record,
                done,
                &buffers.current[..count],
                Some(&buffers.after[..count]),
            )?;
            // Forward, a source-free chunk is written unless it is new
            // already. A rollback never writes one: there are no old bytes
            // to put back, and the check above is all it does there.
            return Ok(new || direction == Some(false));
        }
        if !new {
            sj::read_before(self.journal, record, done, &mut buffers.before[..count])?;
            require_old_or_new(row, ordinal, done, count, buffers)?;
        }
        Ok(new)
    }

    /// [`Self::check_target_reader`] for a target that may read ahead:
    /// `reach(target, end)` is told, at the first of each group of ranges
    /// that lie close together, where the group ends, so a read-ahead window
    /// holds those ranges and not the megabyte that follows the first of
    /// them. The rows are taken in the same order and each is read from the
    /// journal as before; only the index entries are looked at a few ahead.
    ///
    /// `replay` is given by the classification in front of a replay's write
    /// pass (no `expected` digest) and by nothing else. The ranges are then
    /// cut into the chunks of that write pass, which takes the first granule
    /// of a range at offset 0 on its own, and the verdict on each chunk is
    /// kept where `replay` says. The bytes read, their order and the digest
    /// are the same either way.
    fn check_target_reaching<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
        expected: Option<[u8; 32]>,
        fresh_old: bool,
        mut reach: impl FnMut(&mut R, u64),
        mut replay: Option<Classify<'_>>,
    ) -> Result<[u8; 32]> {
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::TargetCheck);
        ensure!(
            target_length == self.ticket.image_length,
            "replay target length differs"
        );
        let mut digest = pin_hash(self.ticket.digest_algorithm())?;
        let mut buffers = Buffers::new();
        let mut rows = n2r_win32::AscendingRanges::new(u64::from(self.ticket.range_count));
        while let Some((ordinal, group_end)) = rows.next(|ordinal| {
            self.index_entry(ordinal)
                .map(|(offset, length, _, _)| (ordinal, offset, length))
        })? {
            if let Some(end) = group_end {
                reach(target, end);
            }
            let row = self.record(ordinal)?;
            frame(&mut digest, &row.range())?;
            let record = record(row);
            // The first chunk of a range at offset 0, where the pass counts
            // chunks as a replay's write pass does: its first granule.
            let boot = if replay.is_some() && row.offset == 0 {
                GRANULE
            } else {
                0
            };
            let mut done = 0u64;
            while done < row.length {
                let count = usize::try_from(if done < boot {
                    boot
                } else {
                    (row.length - done).min(BUFFER as u64)
                })?;
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
                    let nothing_to_write = self.classify_chunk(
                        row,
                        ordinal,
                        done,
                        count,
                        &mut buffers,
                        replay.as_ref().map(|replay| replay.forward),
                    )?;
                    if let Some(remembered) = replay
                        .as_mut()
                        .and_then(|replay| replay.remembered.as_deref_mut())
                    {
                        remembered.note(nothing_to_write);
                    }
                }
                digest.update(&buffers.current[..count])?;
                // What was read of the target, so that the number of passes
                // a run makes over its changed ranges shows in the point's
                // bytes.
                n2r_win32::perf::add_bytes(n2r_win32::perf::Point::TargetCheck, count as u64);
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
        self.check_restored_ahead(target, length)
    }

    /// [`Self::check_restored_reader`] for a source that reads ahead, as
    /// [`Self::check_target_ahead`] is.
    fn check_restored_ahead<R: OrderedSource>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<[u8; 32]> {
        target.reading_ahead(|target| self.check_restored_reaching(target, target_length, R::reach))
    }

    fn check_restored_reader<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
    ) -> Result<[u8; 32]> {
        self.check_restored_reaching(target, target_length, |_, _| ())
    }

    /// [`Self::check_restored_reader`] for a target that may read ahead; see
    /// [`Self::check_target_reaching`].
    fn check_restored_reaching<R: Read + Seek>(
        &mut self,
        target: &mut R,
        target_length: u64,
        mut reach: impl FnMut(&mut R, u64),
    ) -> Result<[u8; 32]> {
        let Some(expected) = self.ticket.old_restored_selected_sha256 else {
            return self.check_target_reaching(
                target,
                target_length,
                Some(self.ticket.old_selected_sha256),
                false,
                reach,
                None,
            );
        };
        // The same pass over the changed ranges as `check_target_reader`,
        // which the branch above is counted in.
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::TargetCheck);
        ensure!(
            target_length == self.ticket.image_length,
            "replay target length differs"
        );
        let mut digest = pin_hash(self.ticket.digest_algorithm())?;
        let mut buffers = Buffers::new();
        let mut rows = n2r_win32::AscendingRanges::new(u64::from(self.ticket.range_count));
        while let Some((ordinal, group_end)) = rows.next(|ordinal| {
            self.index_entry(ordinal)
                .map(|(offset, length, _, _)| (ordinal, offset, length))
        })? {
            if let Some(end) = group_end {
                reach(target, end);
            }
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
                n2r_win32::perf::add_bytes(n2r_win32::perf::Point::TargetCheck, count as u64);
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

    /// Writes one span of a range: each chunk is read, held to the rule of
    /// the classification once more, and written where it differs from the
    /// side the replay wants.
    ///
    /// `known` is what the classification in front of this pass found, where
    /// it was kept and the recovery makes an identical check once
    /// (`verify_policy::repeats_once`). The target has been held by this
    /// process, armed for it alone, since the classification read it, and
    /// nothing has been written to a chunk before this pass reaches it. So:
    ///
    /// - a chunk the classification found with nothing to write is passed
    ///   over. Reading it here would find the same bytes, hold them to the
    ///   same rule and write nothing;
    /// - a chunk that needs writing is still read and checked first, unless
    ///   the run being recovered was published with `--verify fast`
    ///   (`verify_policy::repeats_once_as_verified`): its own apply wrote
    ///   each range without reading it again first, and so does its replay.
    ///   What is written is the same authenticated journal bytes, through
    ///   the same armed policy.
    ///
    /// Either way everything is read back after the flush, against the NEW
    /// or restored digest.
    fn write_span(
        &mut self,
        target: &mut GeneralJournaledPartition,
        row: Record,
        ordinal: u64,
        start: u64,
        length: u64,
        forward: bool,
        buffers: &mut Buffers,
        known: Option<Known<'_>>,
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
            if let Some(known) = known {
                // Every chunk of a span but its last is a whole buffer.
                let chunk = add(known.first, done / BUFFER as u64)?;
                let nothing_to_write = known.classified.nothing_to_write(chunk);
                if nothing_to_write == Some(true) {
                    done = add(done, count as u64)?;
                    continue;
                }
                // A rollback has no bytes to write to a source-free chunk;
                // one that is not marked is left to the check below.
                if nothing_to_write == Some(false) && known.unread && (forward || row.old_kind != 2)
                {
                    let desired = if forward {
                        self.read_after_row(row, ordinal, within, &mut buffers.after[..count])?;
                        &buffers.after[..count]
                    } else {
                        sj::read_before(
                            self.journal,
                            &record,
                            within,
                            &mut buffers.before[..count],
                        )?;
                        &buffers.before[..count]
                    };
                    target.seek(SeekFrom::Start(offset))?;
                    ensure!(target.write(desired)? == count, "short replay target write");
                    done = add(done, count as u64)?;
                    continue;
                }
            }
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
        n2r_win32::perf::step("replay: classify changed ranges");
        target.sync_all()?;
        // The classification is complete before the direction marker and
        // the first write: a foreign byte anywhere refuses the replay with
        // nothing written. A recovery that makes an identical check once
        // (`verify_policy::repeats_once`; not one started with
        // `--recheck-everything`) classifies for its direction and keeps
        // the verdict on each chunk for the write pass (`Classified`), in
        // spare memory. Where that is refused, and for a recovery that
        // repeats every check, the write pass reads every chunk again.
        let once = n2r_win32::verify_policy::repeats_once();
        let unread = once && n2r_win32::verify_policy::repeats_once_as_verified();
        let mut classified = if once {
            Classified::reserve(self.index_lease.arena(), self.ticket)
        } else {
            None
        };
        // Read-ahead is on for this pass and for the read-back below, each
        // of which reads every changed range in ascending order and writes
        // nothing. It is off across the write pass and the flushes between
        // them, so nothing read there, or read back afterwards, comes from
        // memory a write went through.
        let length = GeneralJournaledPartition::byte_len(target);
        target.reading_ahead(|target| {
            self.check_target_reaching(
                target,
                length,
                None,
                false,
                GeneralJournaledPartition::reach,
                once.then(|| Classify {
                    forward,
                    remembered: classified.as_mut(),
                }),
            )
        })?;
        let classified = classified.as_ref().filter(|found| found.complete());
        n2r_win32::perf::step("replay: write changed ranges");
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
        // The number of the next chunk, counted as the classification
        // counted them: the first granule of a range at offset 0, which is
        // written last, and then megabyte chunks of what follows it.
        let mut chunk = 0u64;
        for ordinal in 0..u64::from(self.ticket.range_count) {
            let row = self.record(ordinal)?;
            let skip = if row.offset == 0 { GRANULE } else { 0 };
            chunk = add(chunk, skip / GRANULE)?;
            self.write_span(
                target,
                row,
                ordinal,
                skip,
                row.length - skip,
                forward,
                &mut buffers,
                classified.map(|classified| Known {
                    classified,
                    first: chunk,
                    unread,
                }),
            )?;
            chunk = add(chunk, (row.length - skip).div_ceil(BUFFER as u64))?;
        }
        n2r_win32::perf::step("replay: flush and write boot sector");
        target.sync_all()?;
        let first = self.record(0)?;
        if first.offset == 0 {
            // The boot granule is the first chunk the classification noted:
            // only the first range can lie at offset 0.
            self.write_span(
                target,
                first,
                0,
                0,
                GRANULE,
                forward,
                &mut buffers,
                classified.map(|classified| Known {
                    classified,
                    first: 0,
                    unread,
                }),
            )?;
        }
        drop(buffers);
        target.sync_all()?;
        n2r_win32::perf::step("replay: read back changed ranges");
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
        end: ResumeEnd,
        after_resume: F,
    ) -> Result<(SelectedResult, Option<SelectedResult>)> {
        ensure!(
            sj::classify(self.journal, self.ticket)? == SelectedLifecycle::ApplyIntent,
            "resume requires observed apply intent"
        );
        let resumed = self.execute(authority.target, true)?;
        n2r_win32::perf::step("replay: read back again");
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
        if end == ResumeEnd::BeforeHandoff {
            // Every new byte is on the source again; the handoff is left to
            // the finalizer, which writes it after its verification.
            ensure!(
                digest == resumed.selected_sha256,
                "the replayed source changed before it could be sealed"
            );
            return Ok((resumed, None));
        }
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
        Ok((resumed, Some(closed)))
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

/// Actual terminal result of restarted replay, not a success DTO. HND and ABT
/// witnesses own their same-J policy/identity and bind the live source token.
pub(crate) enum PartitionReplayResult {
    Resumed {
        selected: SelectedResult,
        handoff: SelectedResult,
        witness: n2r_win32::PartitionHandoffWitness,
        index_owner: crate::artifact_arena::ArtifactLease,
    },
    RolledBack {
        selected: SelectedResult,
        closed: n2r_win32::PartitionClosedJournalObservation,
        index_owner: crate::artifact_arena::ArtifactLease,
    },
}
fn partition_record<J: Read + Seek>(
    policy: &n2r_win32::HeldPagedWritePolicy,
    journal: &mut J,
    format: JournalFormat,
    ticket: &SelectedTicket,
    ordinal: u64,
) -> Result<Record> {
    let item = policy.row(ordinal)?;
    let mut bytes = [0u8; OLD_ZERO_RECORD];
    at(
        journal,
        item.descriptor_offset,
        &mut bytes[..format.record_size],
    )?;
    let row = Record::decode(&bytes, item.descriptor_offset, format, ticket.image_length)?;
    ensure!(
        row.offset == item.offset
            && row.length == item.length
            && item.flags == (row.old_kind | (row.new_kind << 2)),
        "replay record differs from actual held index"
    );
    Ok(row)
}
fn partition_read_old<J: Read + Seek>(
    policy: &n2r_win32::HeldPagedWritePolicy,
    journal: &mut J,
    format: JournalFormat,
    ticket: &SelectedTicket,
    mut source: u64,
    before: u64,
    out: &mut [u8],
) -> Result<()> {
    let (mut low, mut high) = (0, before);
    while low < high {
        let mid = low + (high - low) / 2;
        let r = policy.row(mid)?;
        if add(r.offset, r.length)? <= source {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    let mut filled = 0;
    while filled < out.len() {
        ensure!(low < before, "replay COPY escapes earlier OLD rows");
        let row = partition_record(policy, journal, format, ticket, low)?;
        let end = add(row.offset, row.length)?;
        ensure!(
            row.offset <= source && source < end && row.old_kind != 2,
            "replay COPY crosses gap/digest-only source"
        );
        let n = usize::try_from((end - source).min((out.len() - filled) as u64))?;
        if row.old_kind == 1 {
            out[filled..filled + n].fill(0);
        } else {
            at(
                journal,
                add(row.old_payload, source - row.offset)?,
                &mut out[filled..filled + n],
            )?;
        }
        filled += n;
        source = add(source, n as u64)?;
        low += 1;
    }
    Ok(())
}
fn partition_read_new<J: Read + Seek>(
    policy: &n2r_win32::HeldPagedWritePolicy,
    journal: &mut J,
    format: JournalFormat,
    ticket: &SelectedTicket,
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
        0 => at(journal, add(row.new_payload, within)?, out)?,
        1 => out.fill(0),
        2 => partition_read_old(
            policy,
            journal,
            format,
            ticket,
            add(row.copy_source, within)?,
            ordinal,
            out,
        )?,
        _ => anyhow::bail!("unknown authenticated replay kind"),
    };
    Ok(())
}
// IO-only adapter for the two already-authorized native writer types.
// It cannot construct either writer or obtain a File/raw handle.
trait ReplayPagedWriter: Read + Seek + std::io::Write {
    fn replay_journal_view(&mut self) -> std::io::Result<impl Read + Seek + '_>;
}
impl ReplayPagedWriter for n2r_win32::PartitionPagedWriter<'_, '_> {
    fn replay_journal_view(&mut self) -> std::io::Result<impl Read + Seek + '_> {
        self.journal_read_view()
    }
}
impl ReplayPagedWriter for n2r_win32::offline_environment::OfflinePagedWriter<'_, '_> {
    fn replay_journal_view(&mut self) -> std::io::Result<impl Read + Seek + '_> {
        self.journal_read_view()
    }
}
fn partition_write_span(
    writer: &mut impl ReplayPagedWriter,
    policy: &n2r_win32::HeldPagedWritePolicy,
    format: JournalFormat,
    ticket: &SelectedTicket,
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
        "partition replay span escapes record"
    );
    let original = record(row);
    let mut done = 0;
    while done < length {
        let n = usize::try_from((length - done).min(BUFFER as u64))?;
        let within = add(start, done)?;
        let at_source = add(row.offset, within)?;
        at(writer, at_source, &mut buffers.current[..n])
            .with_context(||format!("partition replay: current-source read request offset={at_source},bytes={n} (includes pending flush/readback)"))?;
        {
            let mut journal = writer.replay_journal_view().context(
                "partition replay: opening same-J read view after pending source flush/readback",
            )?;
            partition_read_new(
                policy,
                &mut journal,
                format,
                ticket,
                row,
                ordinal,
                within,
                &mut buffers.after[..n],
            )?;
            if row.old_kind == 2 {
                sj::check_free_granules(
                    &mut journal,
                    &original,
                    within,
                    &buffers.current[..n],
                    Some(&buffers.after[..n]),
                )?;
                if !forward {
                    done = add(done, n as u64)?;
                    continue;
                }
            } else {
                sj::read_before(&mut journal, &original, within, &mut buffers.before[..n])?;
                ensure!(
                    sj::bytes_are_old_or_new(
                        &buffers.current[..n],
                        &buffers.before[..n],
                        &buffers.after[..n]
                    ),
                    "partition replay changed immediately before write"
                );
            }
        }
        let desired = if forward {
            &buffers.after[..n]
        } else {
            &buffers.before[..n]
        };
        if &buffers.current[..n] != desired {
            writer.seek(SeekFrom::Start(at_source))
                .with_context(||format!("partition replay: prewrite logical seek offset={at_source} (includes pending flush/readback)"))?;
            ensure!(
                writer.write(desired)
                    .with_context(||format!("partition replay: bounded native source write request offset={at_source},bytes={n},forward={forward}"))? == n,
                "short bounded partition replay write"
            );
        }
        done = add(done, n as u64)?;
    }
    Ok(())
}
impl BoundJournalObservation<'_> {
    /// Actual publisher/intent/MIXED owner must be consumed immediately before
    /// the SDK's independently authenticated CURRENT-state gate is issued.
    pub(crate) fn replay_partition(
        &mut self,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        publication: &mut super::envelope::PartitionRecoveryPublicationBinding<'_>,
        mixed: PartitionMixedObservation,
        direction: PagedRecoveryDirection,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<PartitionReplayResult> {
        mixed.consume_revalidated(self, owner, stable, publication, events)?;
        if !events.is_empty() {
            checkpoint(events)?;
            ensure!(
                events.is_empty(),
                "replay checkpoint did not drain native events"
            );
        }
        self.observation.revalidate_index()?;
        let ticket = self.observation.ticket;
        let format = self.observation.format;
        let policy = self.observation.index.clone();
        let pins = PagedRecoveryPins {
            journal_binding: self.facts.binding,
            journal_identity: self.facts.identity,
            journal_path: self.facts.path,
            journal_profile: self.facts.profile,
            digest: ticket.digest_algorithm(),
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        let memory = publication.scratch_memory(12 * BUFFER as u64)?;
        let mut buffers = Buffers::new();
        let mut gate = self
            .observation
            .journal
            .qualify_partition_replay(owner, &policy, &pins, direction, events)?;
        let mut writer = self.observation.journal.begin_partition_replay(
            owner,
            &mut gate,
            policy.clone(),
            &pins,
            events,
        )?;

        let forward = direction == PagedRecoveryDirection::Resume;
        for ordinal in 0..u64::from(ticket.range_count) {
            let row = {
                let mut journal = writer.journal_read_view()
                .context("partition replay: opening same-J read view after pending source flush/readback")?;
                partition_record(&policy, &mut journal, format, ticket, ordinal)?
            };
            let skip = if row.offset == 0 { GRANULE } else { 0 };
            partition_write_span(
                &mut writer,
                &policy,
                format,
                ticket,
                row,
                ordinal,
                skip,
                row.length - skip,
                forward,
                &mut buffers,
            )?;
        }
        writer
            .sync_all()
            .context("partition replay: non-discovery pending source flush/readback")?;
        let first = {
            let mut journal = writer.journal_read_view().context(
                "partition replay: opening same-J read view after pending source flush/readback",
            )?;
            partition_record(&policy, &mut journal, format, ticket, 0)?
        };
        if first.offset == 0 {
            partition_write_span(
                &mut writer,
                &policy,
                format,
                ticket,
                first,
                0,
                0,
                GRANULE,
                forward,
                &mut buffers,
            )?;
        }
        writer
            .sync_all()
            .context("partition replay: discovery pending source flush/readback")?;
        writer.revalidate(events)?;
        if forward {
            writer.finish_new(events)?;
        } else {
            writer.finish_old(events)?;
        }
        drop(buffers);
        drop(memory);
        let length = n2r_win32::PartitionScopedOwner::byte_len(owner);
        let digest = if forward {
            self.observation.check_target_reader(
                owner,
                length,
                Some(ticket.new_selected_sha256),
                false,
            )?
        } else {
            self.observation.check_restored_reader(owner, length)?
        };
        let restored = if forward {
            None
        } else {
            self.observation.restored_bytes()?
        };
        let selected = SelectedResult {
            selected_sha256: digest,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: !forward,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: restored,
        };
        ensure!(
            self.observation.lifecycle()?
                == if forward {
                    SelectedLifecycle::ApplyIntent
                } else {
                    SelectedLifecycle::RollbackIntent
                },
            "actual replay lifecycle changed before terminal marker"
        );
        sj::write_lifecycle_marker(
            self.observation.journal,
            ticket,
            if forward {
                MarkerKind::Handoff
            } else {
                MarkerKind::Aborted
            },
        )?;
        self.observation
            .journal
            .require_native_mount_barriers(ticket)?;
        let result = if forward {
            let witness = self
                .observation
                .journal
                .finish_partition_resume(owner, gate, &policy, &pins, events)?;
            let handoff = SelectedResult {
                selected_sha256: digest,
                selected_bytes: ticket.selected_bytes,
                range_count: ticket.range_count,
                replay_closed: true,
                whole_image_verified: false,
                conversion_qualified: false,
                old_restoration_bytes: None,
            };
            PartitionReplayResult::Resumed {
                selected,
                handoff,
                witness,
                index_owner: self.observation.index_lease.clone(),
            }
        } else {
            let closed = self
                .observation
                .journal
                .finish_partition_rollback(owner, gate, &policy, &pins, events)?;
            PartitionReplayResult::RolledBack {
                selected,
                closed,
                index_owner: self.observation.index_lease.clone(),
            }
        };
        publication.revalidate_partition_mixed(
            owner,
            stable,
            self.observation.journal,
            &self.facts,
            ticket,
            events,
        )?;
        checkpoint(events)?;
        ensure!(
            events.is_empty(),
            "terminal replay checkpoint did not drain"
        );
        Ok(result)
    }
}

mod prepared_offline;
pub(crate) use prepared_offline::PreparedOfflineRun;

mod prepared_recovery;
pub(crate) use prepared_recovery::PreparedOfflineReplayRun;

mod prepared_closed;
pub(crate) use prepared_closed::PreparedOfflineClosedRun;
