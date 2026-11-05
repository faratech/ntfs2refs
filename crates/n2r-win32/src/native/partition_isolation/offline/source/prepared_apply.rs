//! Cold Windows-prepared AP activation. Actual opaque boot/J/source owners,
//! no PE-fresh NTFS witness, JSON certificate, GPT repin or replay shortcut.
use super::paged::{
    self, OfflineClosedJournalObservation, OfflinePagedWriter, OfflineSourceApplyGate,
    OfflineTerminalKind,
};
use super::prepared::{OfflinePreparedJournalQualification, OfflinePreparedSource};
use super::*;
use crate::native::{
    HeldPagedWritePolicy, paged_recovery::PagedRecoveryPins, recovery_boot::RecoveryBootGuard,
};
use crate::reference_file::ReferenceFileSnapshot;
use std::os::windows::io::AsRawHandle;

pub(super) struct PreparedPublicationPin {
    snapshot: ReferenceFileSnapshot,
    sha256: [u8; 32],
    file_handle: usize,
}
impl PreparedPublicationPin {
    fn from_actual(qualification: &OfflinePreparedJournalQualification, file: &File) -> Self {
        let facts = qualification.boot_guard_requirements();
        Self {
            snapshot: facts.sealed_publication_file.clone(),
            sha256: facts.sealed_publication_sha256,
            file_handle: file.as_raw_handle() as usize,
        }
    }
    fn revalidate(
        &self,
        file: &mut File,
        pins: &PagedRecoveryPins<'_>,
        maximum: u64,
    ) -> io::Result<()> {
        crate::file_storage::require_readonly_access(file)?;
        require(
            file.as_raw_handle() as usize == self.file_handle,
            "prepared writer requires SAME actual held sealed outer file",
        )?;
        let before =
            crate::reference_file::observe_reference_file_handle_with_limit(file, maximum)?;
        let prefix = format!(
            "{}\\",
            pins.journal_binding
                .disk
                .volume_path()?
                .trim_end_matches('\\')
        );
        require(
            before == self.snapshot
                && before.file_bytes > 0
                && before.number_of_links == 1
                && before.volume_serial_number == pins.journal_identity.volume_serial_number
                && before
                    .final_path
                    .get(..prefix.len())
                    .is_some_and(|s| s.eq_ignore_ascii_case(&prefix)),
            "prepared same-held outer identity/native J volume changed",
        )?;
        require(
            crate::sha256_native::hash_range(file, 0, before.file_bytes)? == self.sha256
                && crate::reference_file::observe_reference_file_handle_with_limit(file, maximum)?
                    == before,
            "prepared same-held outer content changed",
        )
    }
}
pub(super) struct PreparedWriteProtection<'a> {
    boot: &'a mut RecoveryBootGuard,
    outer: &'a mut File,
}
impl PreparedWriteProtection<'_> {
    pub(super) fn revalidate(
        &mut self,
        token: &OfflineSourceOwnerToken,
        pin: &PreparedPublicationPin,
        pins: &PagedRecoveryPins<'_>,
        maximum: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        // After AP this deliberately checks boot/artifact/current source epoch,
        // never the stale all-OLD requirement used before activation.
        self.boot.require_current_boot(token, events)?;
        pin.revalidate(self.outer, pins, maximum)
    }
}
impl OfflinePreparedSource {
    /// Root must first authenticate the held Windows READY bundle semantics and
    /// current metadata/extent fingerprint. SDK separately proves actual cold
    /// exclusion, same J/index/all-OLD and actual persistent recovery boot.
    #[allow(clippy::too_many_arguments)]
    pub fn qualify_guarded_paged_apply(
        &mut self,
        qualification: &OfflinePreparedJournalQualification,
        boot: &mut RecoveryBootGuard,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        outer: &mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflineSourceApplyGate> {
        require(
            !self.core.fresh
                && self.core.fresh_witness.is_none()
                && !self.core.gate_ever_issued
                && !self.core.writer_ever_issued
                && !self.core.poisoned,
            "prepared apply cannot reuse fresh/native or spent source ownership",
        )?;
        checkpoint(
            &self.core.sink,
            "offline-PREPARED-actual-boot-OLD-gate-opening",
            events,
        )?;
        let result = (|| {
            boot.require_before_writer(self, qualification, policy, journal, pins, outer, events)?;
            let publication = PreparedPublicationPin::from_actual(qualification, outer);
            publication.revalidate(outer, pins, self.core.env.budget.ram_bytes / 8)?;
            paged::qualify_prepared(&mut self.core, policy, journal, pins, publication, events)
        })();
        let drained = checkpoint(
            &self.core.sink,
            "offline-PREPARED-actual-boot-OLD-gate-closed",
            events,
        );
        match (result, drained) {
            (Ok(gate), Ok(())) => Ok(gate),
            (Err(a), Err(b)) => {
                self.core.poisoned = true;
                Err(invalid(&format!(
                    "prepared qualification failed:{a}; durable checkpoint also failed:{b}"
                )))
            }
            (Err(e), _) | (_, Err(e)) => {
                self.core.poisoned = true;
                Err(e)
            }
        }
    }
    /// One-shot AP: source remains whole-disk OFFLINE, GPT BASIC+READONLY stays
    /// byte-exact. Only physical-disk READ_ONLY is cleared after AP flush/readback.
    /// Failure preserves current exclusion and poisons this live owner; no retry.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_guarded_paged_apply<'a, 'p>(
        &'a mut self,
        gate: &'a mut OfflineSourceApplyGate,
        qualification: &OfflinePreparedJournalQualification,
        boot: &'a mut RecoveryBootGuard,
        policy: HeldPagedWritePolicy,
        journal: &'a mut File,
        pins: &'a PagedRecoveryPins<'p>,
        outer: &'a mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePagedWriter<'a, 'p>> {
        paged::require_prepared_gate(gate)?;
        checkpoint(
            &self.core.sink,
            "offline-PREPARED-before-one-shot-AP-opening",
            events,
        )?;
        let checked =
            boot.require_before_writer(self, qualification, &policy, journal, pins, outer, events);
        let drained = checkpoint(
            &self.core.sink,
            "offline-PREPARED-before-one-shot-AP-closed",
            events,
        );
        if let Err(e) = match (checked, drained) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(a), Err(b)) => Err(invalid(&format!(
                "prepared pre-AP proof failed:{a}; durable checkpoint also failed:{b}"
            ))),
            (Err(e), _) | (_, Err(e)) => Err(e),
        } {
            self.core.poisoned = true;
            return Err(e);
        }
        paged::begin(
            &mut self.core,
            gate,
            policy,
            journal,
            pins,
            None,
            Some(PreparedWriteProtection { boot, outer }),
            events,
        )
    }
    pub fn authenticate_closed(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        kind: OfflineTerminalKind,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflineClosedJournalObservation> {
        // HND validates all selected NEW/COPY/zero; ABT validates restored OLD
        // and admitted source-free semantics using the unchanged generic checker.
        paged::closed(&mut self.core, policy, journal, pins, kind, events)
    }
    /// Consume all source write/replay entry points. Closed witness + current
    /// boot/full native source bookends precede replacing the RW data object
    /// with an actual READONLY handle. Returned owner has no Write/activation.
    #[allow(clippy::too_many_arguments)]
    pub fn into_terminal_metadata(
        mut self,
        closed: OfflineClosedJournalObservation,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        boot: &mut RecoveryBootGuard,
        outer: &mut File,
        qualification: &OfflinePreparedJournalQualification,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePreparedTerminalSource> {
        checkpoint(
            &self.core.sink,
            "offline-PREPARED-closed-terminal-transfer-opening",
            events,
        )?;
        qualification.require_terminal_binding(&self, pins)?;
        boot.require_current_boot(&self.owner_token(), events)?;
        let publication = PreparedPublicationPin::from_actual(qualification, outer);
        publication.revalidate(outer, pins, self.core.env.budget.ram_bytes / 8)?;
        closed.revalidate_prepared(&mut self, policy, journal, pins, events)?;
        self.state(events)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                self.binding().storage.disk_number
            ))?;
        paged::gate_file_state(&file, &self.core, self.core.expected_attributes, events)?;
        let old = std::mem::replace(&mut self.core.file, file);
        close_file(
            old,
            "offline-PREPARED-source-RW-file-close-before-terminal-capability",
            events,
        )?;
        self.core.state(events)?;
        boot.require_current_boot(&self.owner_token(), events)?;
        publication.revalidate(outer, pins, self.core.env.budget.ram_bytes / 8)?;
        checkpoint(
            &self.core.sink,
            "offline-PREPARED-closed-terminal-transfer-complete",
            events,
        )?;
        Ok(OfflinePreparedTerminalSource {
            source: self,
            closed,
        })
    }
}
impl OfflineClosedJournalObservation {
    pub fn revalidate_prepared(
        &self,
        source: &mut OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.revalidate(&mut source.core, policy, journal, pins, events)
    }
}
/// Actual closed-J source owner for the metadata/availability restoration
/// protocol. Never Deserialize, Write, a raw File, AP, replay or live NTFS proof.
pub struct OfflinePreparedTerminalSource {
    source: OfflinePreparedSource,
    closed: OfflineClosedJournalObservation,
}
impl OfflinePreparedTerminalSource {
    pub fn binding(&self) -> &PartitionSourceBinding {
        self.source.binding()
    }
    pub fn byte_len(&self) -> u64 {
        self.source.byte_len()
    }
    pub fn owner_token(&self) -> OfflineSourceOwnerToken {
        self.source.owner_token()
    }
    pub fn terminal_kind(&self) -> OfflineTerminalKind {
        self.closed.kind()
    }
    pub fn offline_environment_facts(&self) -> &OfflineOwningFacts {
        self.source.offline_environment_facts()
    }
    pub fn basic_readonly_partition_info(&self) -> &[u8] {
        self.source.basic_readonly_partition_info()
    }
    pub fn state(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<OfflineSourceState> {
        self.source.state(events)
    }
    /// Explicit availability transition ONLY after current closed HND/ABT proof.
    /// Selected source GPT BASIC+RO and every sibling remain unchanged; this is
    /// not selected-source writable restoration, replay or boot selection.
    #[allow(clippy::too_many_arguments)]
    pub fn make_available_for_boot_restoration(
        mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        boot: &mut RecoveryBootGuard,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePreparedAvailableSource> {
        self.revalidate_closed(policy, journal, pins, boot, events)?;
        let before = self.source.core.state(events)?;
        require(
            matches!(before.actual.disk_attributes, 1 | 3)
                && before.actual.gpt.target_attributes == 0x1000_0000_0000_0000,
            "terminal availability requires actual excluded disk and unchanged source BASICRO",
        )?;
        checkpoint(
            &self.source.core.sink,
            "offline-PREPARED-closed-before-availability-SET0",
            events,
        )?;
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding().storage.disk_number),
            true,
            false,
        )?;
        paged::gate_file_state(
            &management,
            &self.source.core,
            self.source.core.expected_attributes,
            events,
        )?;
        // No raw data method is exposed or invoked on this management handle.
        // Failure does not run a restore/setter fallback.
        set_attributes(&management, 0, events)?;
        paged::gate_file_state(&management, &self.source.core, 0, events)?;
        self.source.core.expected_attributes = 0;
        close_file(
            management,
            "offline-PREPARED-terminal-availability-management-close",
            events,
        )?;
        let after = self.source.core.state(events)?;
        require(
            after.actual.disk_attributes == 0 && after.actual.gpt == before.actual.gpt,
            "terminal availability changed source/sibling GPT or protection unexpectedly",
        )?;
        self.closed
            .revalidate_prepared(&mut self.source, policy, journal, pins, events)?;
        boot.require_current_boot(&self.source.owner_token(), events)?;
        checkpoint(
            &self.source.core.sink,
            "offline-PREPARED-closed-availability-SET0-complete",
            events,
        )?;
        Ok(OfflinePreparedAvailableSource {
            source: self.source,
            closed: self.closed,
        })
    }
    pub fn revalidate_closed(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        boot: &mut RecoveryBootGuard,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        boot.require_current_boot(&self.source.owner_token(), events)?;
        self.closed
            .revalidate_prepared(&mut self.source, policy, journal, pins, events)?;
        boot.require_current_boot(&self.source.owner_token(), events)
    }
}
impl Read for OfflinePreparedTerminalSource {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.source.read(out)
    }
}
impl Seek for OfflinePreparedTerminalSource {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.source.seek(from)
    }
}

/// Closed-J, actual source-disk ONLINE/RW metadata availability owner. The
/// selected D partition remains GPT BASIC+RO. No Write/activate/replay/File API.
/// Boot restoration must accept this opaque owner, never its serialized facts.
pub struct OfflinePreparedAvailableSource {
    source: OfflinePreparedSource,
    closed: OfflineClosedJournalObservation,
}
impl OfflinePreparedAvailableSource {
    pub fn binding(&self) -> &PartitionSourceBinding {
        self.source.binding()
    }
    pub fn owner_token(&self) -> OfflineSourceOwnerToken {
        self.source.owner_token()
    }
    pub fn terminal_kind(&self) -> OfflineTerminalKind {
        self.closed.kind()
    }
    pub fn offline_environment_facts(&self) -> &OfflineOwningFacts {
        self.source.offline_environment_facts()
    }
    pub fn state(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<OfflineSourceState> {
        let state = self.source.core.state(events)?;
        require(
            state.actual.disk_attributes == 0
                && state.actual.gpt.target_attributes == 0x1000_0000_0000_0000,
            "terminal available source lost exact BASICRO source/full native baseline",
        )?;
        Ok(state)
    }
    pub fn revalidate_closed(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.state(events)?;
        self.closed
            .revalidate_prepared(&mut self.source, policy, journal, pins, events)?;
        self.state(events).map(|_| ())
    }
}
