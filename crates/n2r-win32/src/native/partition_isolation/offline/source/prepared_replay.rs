//! Authenticated cold Windows-prepared CURRENT mixed replay. No fresh NTFS
//! proof, original metadata fingerprint, historical lock or JSON writer grant.
use super::*;
use super::{
    paged,
    prepared::{OfflinePreparedBootGuardRequirements, OfflinePreparedSource},
    prepared_apply::{PreparedPublicationPin, PreparedWriteProtection},
};
use crate::native::{
    HeldPagedWritePolicy,
    paged_recovery::{
        OwnedPartitionJournalPins, PagedRecoveryDirection, PagedRecoveryPins, PartitionJournalPhase,
    },
    recovery_boot::RecoveryBootGuard,
};
use std::os::windows::io::AsRawHandle;

pub struct OfflinePreparedReplayQualification {
    owner: OfflineSourceOwnerToken,
    binding: PartitionSourceBinding,
    boot: OfflineBootIdentity,
    pins: OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    journal_handle: usize,
    current_sha256: [u8; 32],
    lifecycle_sha256: [u8; 32],
    direction: PagedRecoveryDirection,
    requirements: OfflinePreparedBootGuardRequirements,
}
impl OfflinePreparedReplayQualification {
    pub fn boot_guard_requirements(&self) -> &OfflinePreparedBootGuardRequirements {
        &self.requirements
    }
    pub fn direction(&self) -> PagedRecoveryDirection {
        self.direction
    }
    pub fn require_owner(&self, token: &OfflineSourceOwnerToken) -> io::Result<()> {
        require(
            self.owner.same_owner(token),
            "prepared replay qualification belongs to another actual owner",
        )
    }
    pub(super) fn require_terminal_binding(
        &self,
        source: &OfflinePreparedSource,
        pins: &PagedRecoveryPins<'_>,
    ) -> io::Result<()> {
        self.require_owner(&source.owner_token())?;
        self.pins.require(pins)?;
        require(
            self.binding == *source.binding() && self.boot == source.core.env.facts.boot,
            "prepared replay terminal owner/boot/J changed",
        )
    }
    /// Repeat the SAME CURRENT byte/granule OLD-or-NEW checker and actual held
    /// publication/J/index/native bookends. No allOLD or NTFS parse is used.
    pub fn revalidate(
        &self,
        source: &mut OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        outer: &mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.require_terminal_binding(source, pins)?;
        require(
            self.index_sha256 == policy.facts()?.index_sha256
                && journal.as_raw_handle() as usize == self.journal_handle,
            "prepared replay lost same actual J/index",
        )?;
        source.require_sealed_publication(
            outer,
            self.requirements.sealed_publication_sha256,
            pins,
            Some(&self.requirements.sealed_publication_file),
        )?;
        let current = paged::authenticate(
            &mut source.core,
            policy,
            journal,
            pins,
            PartitionJournalPhase::Mixed(self.direction),
            events,
        )?;
        require(
            current == Some(self.current_sha256)
                && paged::lifecycle_digest(journal)? == self.lifecycle_sha256,
            "prepared replay CURRENT mixed bytes/lifecycle changed",
        )
    }
}
impl OfflinePreparedSource {
    pub fn qualify_prepared_replay_journal(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        outer: &mut File,
        independent_outer_sha256: [u8; 32],
        direction: PagedRecoveryDirection,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePreparedReplayQualification> {
        checkpoint(
            &self.core.sink,
            "offline-prepared-CURRENT-recovery-opening",
            events,
        )?;
        let result = (|| {
            require(
                !self.core.fresh
                    && self.core.fresh_witness.is_none()
                    && !self.core.gate_ever_issued
                    && !self.core.writer_ever_issued
                    && self.source_was_already_offline_on_enrollment
                    && self.core.expected_attributes == 3,
                "cold prepared replay requires actual early-offline/new readonly owner, never fresh/native or spent admission",
            )?;
            self.state(events)?;
            let outer_file =
                self.require_sealed_publication(outer, independent_outer_sha256, pins, None)?;
            let current = paged::authenticate(
                &mut self.core,
                policy,
                journal,
                pins,
                PartitionJournalPhase::Mixed(direction),
                events,
            )?
            .ok_or_else(|| invalid("actual CURRENT mixed authentication returned no digest"))?;
            let lifecycle = paged::lifecycle_digest(journal)?;
            let index = policy.facts()?;
            let requirements = OfflinePreparedBootGuardRequirements {
                kind: "offline-current-prepared-recovery-boot-requirements-v1",
                source: self.binding().clone(),
                current_boot: self.core.env.facts.boot.clone(),
                prepared_readonly_gpt_sha256: self.source_readonly_gpt_sha256,
                actual_excluded_disk_attributes: 3,
                source_was_already_offline_on_enrollment: true,
                journal_identity: pins.journal_identity.clone(),
                journal_path: pins.journal_path.to_string_lossy().into_owned(),
                journal_immutable_sha256: pins.immutable_sha256,
                index_sha256: index.index_sha256,
                old_selected_sha256: pins.old_selected_sha256,
                selected_bytes: index.selected_bytes,
                range_count: index.range_count,
                lifecycle_prefix_sha256: lifecycle,
                sealed_publication_sha256: independent_outer_sha256,
                sealed_publication_file: outer_file,
                requires_actual_Root_sealed_publication_authentication: true,
                requires_actual_durable_boot_guard_before_writer: true,
                facts_grant_write_authority: false,
            };
            Ok(OfflinePreparedReplayQualification {
                owner: self.owner_token(),
                binding: self.binding().clone(),
                boot: self.core.env.facts.boot.clone(),
                pins: OwnedPartitionJournalPins::capture(pins),
                index_sha256: index.index_sha256,
                journal_handle: journal.as_raw_handle() as usize,
                current_sha256: current,
                lifecycle_sha256: lifecycle,
                direction,
                requirements,
            })
        })();
        let closing = checkpoint(
            &self.core.sink,
            "offline-prepared-CURRENT-recovery-closed",
            events,
        );
        match (result, closing) {
            (Ok(v), Ok(())) => Ok(v),
            (Err(e), Ok(())) => Err(e),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Err(c)) => Err(invalid(&format!(
                "CURRENT prepared replay failed:{e}; closing checkpoint:{c}"
            ))),
        }
    }
    pub fn qualify_guarded_prepared_replay(
        &mut self,
        qualification: &OfflinePreparedReplayQualification,
        boot: &mut RecoveryBootGuard,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        outer: &mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::OfflineSourceApplyGate> {
        checkpoint(
            &self.core.sink,
            "offline-prepared-replay-boot-gate-opening",
            events,
        )?;
        let checked = (|| {
            qualification.revalidate(self, policy, journal, pins, outer, events)?;
            boot.require_current_boot(&self.owner_token(), events)?;
            let publication = PreparedPublicationPin::from_replay(qualification, outer);
            publication.revalidate(outer, pins, self.core.env.budget.ram_bytes / 8)?;
            paged::qualify_prepared_replay(
                &mut self.core,
                policy,
                journal,
                pins,
                publication,
                qualification.direction,
                events,
            )
        })();
        let drained = checkpoint(
            &self.core.sink,
            "offline-prepared-replay-boot-gate-closed",
            events,
        );
        match (checked, drained) {
            (Ok(v), Ok(())) => Ok(v),
            (Err(e), Ok(())) | (Ok(_), Err(e)) => {
                self.core.poisoned = true;
                Err(e)
            }
            (Err(e), Err(c)) => {
                self.core.poisoned = true;
                Err(invalid(&format!(
                    "prepared replay gate:{e}; checkpoint:{c}"
                )))
            }
        }
    }
    pub fn begin_guarded_prepared_replay<'a, 'p>(
        &'a mut self,
        gate: &'a mut super::OfflineSourceApplyGate,
        qualification: &OfflinePreparedReplayQualification,
        boot: &'a mut RecoveryBootGuard,
        policy: HeldPagedWritePolicy,
        journal: &'a mut File,
        pins: &'a PagedRecoveryPins<'p>,
        outer: &'a mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::OfflinePagedWriter<'a, 'p>> {
        paged::require_prepared_replay_gate(gate, qualification.direction)?;
        checkpoint(
            &self.core.sink,
            "offline-prepared-replay-before-AP-RB-opening",
            events,
        )?;
        let checked = (|| {
            qualification.revalidate(self, &policy, journal, pins, outer, events)?;
            boot.require_current_boot(&self.owner_token(), events)
        })();
        let drained = checkpoint(
            &self.core.sink,
            "offline-prepared-replay-before-AP-RB-closed",
            events,
        );
        match (checked, drained) {
            (Ok(()), Ok(())) => (),
            (Err(e), _) | (_, Err(e)) => {
                self.core.poisoned = true;
                return Err(e);
            }
        }
        paged::begin(
            &mut self.core,
            gate,
            policy,
            journal,
            pins,
            None,
            Some(PreparedWriteProtection::new(boot, outer)),
            events,
        )
    }
    pub fn into_terminal_metadata_after_replay(
        self,
        closed: super::OfflineClosedJournalObservation,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        boot: &mut RecoveryBootGuard,
        outer: &mut File,
        qualification: &OfflinePreparedReplayQualification,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::prepared_apply::OfflinePreparedTerminalSource> {
        qualification.require_terminal_binding(&self, pins)?;
        let publication = PreparedPublicationPin::from_replay(qualification, outer);
        self.into_closed_terminal_with_publication(
            closed,
            policy,
            journal,
            pins,
            boot,
            outer,
            publication,
            events,
        )
    }
}
