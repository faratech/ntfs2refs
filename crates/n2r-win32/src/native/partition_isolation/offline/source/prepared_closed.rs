//! Closed HND/ABT restart only. No AP, RB, writer, payload mutation or replay.
use super::*;
use super::{
    paged,
    prepared::{OfflinePreparedBootGuardRequirements, OfflinePreparedSource},
    prepared_apply::PreparedPublicationPin,
};
use crate::native::{
    HeldPagedWritePolicy,
    paged_recovery::{OwnedPartitionJournalPins, PagedRecoveryPins},
    recovery_boot::RecoveryBootGuard,
};
use std::os::windows::io::AsRawHandle;
pub struct OfflinePreparedClosedQualification {
    owner: OfflineSourceOwnerToken,
    binding: PartitionSourceBinding,
    boot: OfflineBootIdentity,
    pins: OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    journal_handle: usize,
    lifecycle_sha256: [u8; 32],
    closed: paged::OfflineClosedJournalObservation,
    requirements: OfflinePreparedBootGuardRequirements,
}
impl OfflinePreparedClosedQualification {
    pub fn boot_guard_requirements(&self) -> &OfflinePreparedBootGuardRequirements {
        &self.requirements
    }
    pub fn kind(&self) -> paged::OfflineTerminalKind {
        self.closed.kind()
    }
    pub fn require_owner(&self, token: &OfflineSourceOwnerToken) -> io::Result<()> {
        require(
            self.owner.same_owner(token),
            "closed prepared qualification belongs to another actual source",
        )
    }
    pub fn revalidate(
        &self,
        source: &mut OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        outer: &mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.require_owner(&source.owner_token())?;
        self.pins.require(pins)?;
        require(
            self.binding == *source.binding()
                && self.boot == source.core.env.facts.boot
                && self.index_sha256 == policy.facts()?.index_sha256
                && self.journal_handle == journal.as_raw_handle() as usize,
            "closed prepared source/boot/J/index identity differs",
        )?;
        source.require_sealed_publication(
            outer,
            self.requirements.sealed_publication_sha256,
            pins,
            Some(&self.requirements.sealed_publication_file),
        )?;
        self.closed
            .revalidate_prepared(source, policy, journal, pins, events)?;
        require(
            paged::lifecycle_digest(journal)? == self.lifecycle_sha256,
            "closed HND/ABT lifecycle changed",
        )
    }
    /// Consume the ACTUAL closed witness into the metadata-only source owner.
    /// No fabricated replay/handoff result and no fresh/native admission.
    pub fn into_terminal(
        self,
        mut source: OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        boot: &mut RecoveryBootGuard,
        outer: &mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::prepared_apply::OfflinePreparedTerminalSource> {
        self.revalidate(&mut source, policy, journal, pins, outer, events)?;
        boot.require_current_boot(&source.owner_token(), events)?;
        let publication = PreparedPublicationPin::from_closed(&self, outer);
        source.into_closed_terminal_with_publication(
            self.closed,
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
impl OfflinePreparedSource {
    pub fn qualify_prepared_closed_journal(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        outer: &mut File,
        outer_sha256: [u8; 32],
        kind: paged::OfflineTerminalKind,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePreparedClosedQualification> {
        checkpoint(
            &self.core.sink,
            "offline-prepared-CLOSED-reopen-opening",
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
                "closed prepared reopen requires actual early-offline/new readonly owner",
            )?;
            self.state(events)?;
            let publication = self.require_sealed_publication(outer, outer_sha256, pins, None)?;
            let closed = self.authenticate_closed(policy, journal, pins, kind, events)?;
            let index = policy.facts()?;
            let lifecycle = paged::lifecycle_digest(journal)?;
            let requirements = OfflinePreparedBootGuardRequirements {
                kind: "offline-closed-prepared-recovery-boot-requirements-v1",
                source: self.binding().clone(),
                current_boot: self.core.env.facts.boot.clone(),
                prepared_readonly_gpt_sha256: self.source_readonly_gpt_sha256,
                actual_excluded_disk_attributes: 3,
                source_was_already_offline_on_enrollment: self.source_was_already_offline_on_enrollment,
                actual_current_boot_volume_locks_acquired: self.actual_current_boot_volume_locks_acquired,
                journal_identity: pins.journal_identity.clone(),
                journal_path: pins.journal_path.to_string_lossy().into_owned(),
                journal_immutable_sha256: pins.immutable_sha256,
                index_sha256: index.index_sha256,
                old_selected_sha256: pins.old_selected_sha256,
                selected_bytes: index.selected_bytes,
                range_count: index.range_count,
                lifecycle_prefix_sha256: lifecycle,
                sealed_publication_sha256: outer_sha256,
                sealed_publication_file: publication,
                requires_actual_Root_sealed_publication_authentication: true,
                requires_actual_durable_boot_guard_before_writer: true,
                facts_grant_write_authority: false,
            };
            Ok(OfflinePreparedClosedQualification {
                owner: self.owner_token(),
                binding: self.binding().clone(),
                boot: self.core.env.facts.boot.clone(),
                pins: OwnedPartitionJournalPins::capture(pins),
                index_sha256: index.index_sha256,
                journal_handle: journal.as_raw_handle() as usize,
                lifecycle_sha256: lifecycle,
                closed,
                requirements,
            })
        })();
        let closing = checkpoint(
            &self.core.sink,
            "offline-prepared-CLOSED-reopen-closed",
            events,
        );
        match (result, closing) {
            (Ok(v), Ok(())) => Ok(v),
            (Err(e), Ok(())) => Err(e),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Err(c)) => Err(invalid(&format!(
                "closed prepared reopen:{e}; checkpoint:{c}"
            ))),
        }
    }
}
