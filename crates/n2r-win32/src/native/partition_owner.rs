//! Actual held private-partition owner with explicit same-guard fresh writer
//! admission. No CLI selector, setter, repair or Drop teardown.
use super::partition_dump_locations::{
    ConfiguredDumpObservation, observe_configured_dump_locations,
};
use super::partition_isolation::{
    PartitionIsolationObservation, PartitionObservationBudget, PartitionSourceBinding,
};
use super::partition_runtime_roles::{
    RuntimeVolumeRoleDiagnostic, runtime_volume_role_diagnostics,
};
use super::partition_storage_roles::{PartitionStorageRoleObservation,observe_partition_storage_roles};
use super::{AlignedBuffer, HeldPagedWritePolicy, MAX_IO, NativeEvent, control};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    sync::{Arc, Mutex, MutexGuard},
};

const PRIVATE_TYPE: &str = "b627aadb-a893-48b6-aa0b-71e5f30ee370";
const GRANULE: u64 = 4096;

#[derive(Clone, Debug, Serialize)]
pub struct PartitionOwnerState {
    pub partition: PartitionIsolationObservation,
    pub(super) configured_dump_locations: ConfiguredDumpObservation,
    // Optional provenance captured at owner opening only; never current-role authority.
    #[serde(rename = "vds_opening_volume_roles")]
    pub(super) vds_current_volume_roles: RuntimeVolumeRoleDiagnostic,
    pub(super) storage_current_partition_roles:PartitionStorageRoleObservation,
    pub source_admission_issued: bool,
    pub loaded_dump_exclusion_qualified: bool,
}

/// The RW kernel file is private; the public type exposes bounded reads only.
/// Input binding is routing data; actual GPT/critical/native checks issue owner.
/// Drop closes handles and leaves the observed private type unchanged.
pub struct PartitionScopedOwner {
    identity: Arc<PartitionOwnerIdentity>,
    file: File,
    physical_readonly: File,
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    enrolled: PartitionOwnerState,
    buffer: AlignedBuffer,
    position: u64,
    poisoned: bool,
    recovery_events: Option<super::partition_lifecycle::PartitionNativeEventSink>,
}
struct PartitionOwnerIdentity {
    data_cursor: Mutex<()>,
}
/// Stable equality identity from an actual owner, never source admission.
/// Moving the owner preserves it; no serialized/path constructor exists.
#[derive(Clone)]
pub struct PartitionOwnerToken(Arc<PartitionOwnerIdentity>);
impl PartitionOwnerToken {
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Private synchronization only; no handle or source permission is issued.
    pub(super) fn lock_data_cursor(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.0.data_cursor.lock().map_err(|_|io::Error::other("actual source FILE_OBJECT cursor lock poisoned"))
    }
}

/// Only actual fresh NTFS admission plus complete same-owner clear J/OLD
/// authentication issue this gate. No Clone, Deserialize or path constructor.
pub struct PartitionSourceAdmissionGate {
    owner_identity: Arc<PartitionOwnerIdentity>,
    binding: PartitionSourceBinding,
    preparation: super::partition_lifecycle::PartitionPreparationToken,
    preparation_pin: super::partition_lifecycle::PartitionPreparationPin,
    journal: super::paged_recovery::OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    used: bool,
}

impl PartitionSourceAdmissionGate {
    fn require_bound(&self, owner: &PartitionScopedOwner,
        admission: &super::partition_lifecycle::PartitionNtfsAdmission,
        policy: &HeldPagedWritePolicy, pins: &super::paged_recovery::PagedRecoveryPins<'_>) -> io::Result<()> {
        super::partition_lifecycle::require_complete_fresh_ntfs_admission(owner, admission)?;
        if !Arc::ptr_eq(&self.owner_identity, &owner.identity) || self.binding != owner.binding
            || !self.preparation.same_owner(admission.preparation_token())
            || self.preparation_pin != admission.durable_preparation_pin()?
            || self.index_sha256 != policy.facts()?.index_sha256 {
            return Err(io::Error::other("partition apply gate owner/preparation/index differs"));
        }
        self.journal.require(pins)
    }
}

/// Single-use actual reopened MIXED observation. Serialized publication pins
/// cannot construct it. ROOT must ALSO consume its independently authenticated
/// publication/current-MIXED token before invoking this native issuer.
pub struct PartitionMixedReplayGate {
    owner: PartitionOwnerToken,
    binding: PartitionSourceBinding,
    journal: super::paged_recovery::OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    current_sha256: [u8; 32],
    lifecycle_sha256: [u8; 32],
    direction: super::paged_recovery::PagedRecoveryDirection,
    used: bool,
}
impl PartitionMixedReplayGate {
    fn require_bound(&self, owner: &PartitionScopedOwner, policy: &HeldPagedWritePolicy,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>) -> io::Result<()> {
        if !self.owner.same_owner(&owner.owner_token()) || self.binding != *owner.binding()
            || self.index_sha256 != policy.facts()?.index_sha256 {
            return Err(io::Error::other("partition replay owner/index binding differs"));
        }
        self.journal.require(pins)
    }
}

impl PartitionScopedOwner {
    pub fn qualify_partition_paged_replay(&mut self, policy: &HeldPagedWritePolicy,
        journal: &mut File, pins: &super::paged_recovery::PagedRecoveryPins<'_>,
        direction: super::paged_recovery::PagedRecoveryDirection, events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionMixedReplayGate> {
        if self.enrolled.source_admission_issued {
            return Err(io::Error::other("partition source gate already issued; reopen actual recovery owner"));
        }
        self.revalidate_current_critical_volume_policy(events)?;
        let (current_sha256, lifecycle_sha256) = super::paged_recovery::authenticate_partition_mixed(
            self, policy, journal, pins, direction)?;
        self.revalidate_current_critical_volume_policy(events)?;
        let gate = PartitionMixedReplayGate { owner: self.owner_token(), binding: self.binding.clone(),
            journal: super::paged_recovery::OwnedPartitionJournalPins::capture(pins),
            index_sha256: policy.facts()?.index_sha256, current_sha256, lifecycle_sha256, direction, used: false };
        self.enrolled.source_admission_issued = true;
        Ok(gate)
    }

    /// Recheck the ENTIRE same CURRENT mixed state. Retire the gate before any
    /// RB attempt or writer issuance. Resume requires AP; rollback durably
    /// writes/readbacks canonical RB before exposing the bounded writer.
    pub fn begin_partition_paged_replay<'a, 'p>(&'a mut self,
        gate: &'a mut PartitionMixedReplayGate, policy: HeldPagedWritePolicy,
        journal: &'a mut File, pins: &'a super::paged_recovery::PagedRecoveryPins<'p>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionPagedWriter<'a, 'p>> {
        if gate.used { return Err(io::Error::other("partition replay gate spent")); }
        gate.require_bound(self, &policy, pins)?;
        self.revalidate_current_critical_volume_policy(events)?;
        let (current, lifecycle) = super::paged_recovery::authenticate_partition_mixed(
            self, &policy, journal, pins, gate.direction)?;
        if current != gate.current_sha256 || lifecycle != gate.lifecycle_sha256 {
            return Err(io::Error::other("partition CURRENT mixed state/lifecycle changed since qualification"));
        }
        self.revalidate_current_critical_volume_policy(events)?;
        gate.used = true;
        let activation = (|| {
            if gate.direction == super::paged_recovery::PagedRecoveryDirection::Rollback {
                super::paged_recovery::publish_partition_rollback_marker(journal, pins, events)?;
            }
            super::paged_recovery::authenticate_scoped_partition_paged_source(self, &policy,
                journal, pins, super::paged_recovery::PartitionJournalPhase::Replaying(gate.direction))?;
            self.revalidate_current_critical_volume_policy(events)
        })();
        if let Err(error) = activation { self.poisoned = true; return Err(error); }
        Ok(PartitionPagedWriter { owner: self, policy, journal, pins,
            _admission: None, native_admission: None, replay_admission: Some(gate),
            requested: 0, written: 0, pending: None, poisoned: false })
    }

    pub fn finish_partition_replay_handoff(&mut self, gate: PartitionMixedReplayGate,
        policy: &HeldPagedWritePolicy, journal: &mut File,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>, events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::paged_recovery::PartitionHandoffWitness> {
        gate.require_bound(self, policy, pins)?;
        if !gate.used || gate.direction != super::paged_recovery::PagedRecoveryDirection::Resume {
            return Err(io::Error::other("partition HND requires consumed Resume writer gate"));
        }
        self.revalidate_current_critical_volume_policy(events)?;
        super::paged_recovery::PartitionHandoffWitness::from_spent_gate(self, policy, journal, pins, events)
    }

    pub fn finish_partition_replay_abort(&mut self, gate: PartitionMixedReplayGate,
        policy: &HeldPagedWritePolicy, journal: &mut File,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>, events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::paged_recovery::PartitionClosedJournalObservation> {
        gate.require_bound(self, policy, pins)?;
        if !gate.used || gate.direction != super::paged_recovery::PagedRecoveryDirection::Rollback {
            return Err(io::Error::other("partition ABT requires consumed Rollback writer gate"));
        }
        super::paged_recovery::authenticate_partition_closed_journal(self, policy, journal, pins,
            super::paged_recovery::PartitionTerminalKind::Aborted, events)
    }
}

impl PartitionScopedOwner {
    /// Consume only the original live, never-activated source owner. A saved
    /// flag or another reopened owner cannot match the actual admission token.
    pub(super) fn into_unactivated_cancellation_parts(mut self,
        admission:&mut super::partition_lifecycle::PartitionNtfsAdmission,
        events:&mut Vec<NativeEvent>,
    )->io::Result<super::partition_restoration::PartitionTerminalTargetParts>{
        if self.enrolled.source_admission_issued{return Err(io::Error::other("source gate was already issued; live cancellation is permanently unavailable"));}
        super::partition_lifecycle::require_complete_fresh_ntfs_admission(&self,admission)?;
        let pin=admission.durable_preparation_pin()?;
        admission.revalidate_publication_handoff(&mut self,&pin,events)?;
        self.revalidate_current_critical_volume_policy(events)?;
        if self.enrolled.source_admission_issued{return Err(io::Error::other("source gate issued during cancellation authentication"));}
        let token=self.owner_token();
        Ok(super::partition_restoration::PartitionTerminalTargetParts{file:self.file,physical_readonly:self.physical_readonly,
            binding:self.binding,budget:self.budget,state:self.enrolled,token})
    }
    /// Only the terminal restoration module receives these original retained
    /// objects. It must validate its BasicRO state independently after the
    /// target type transition; no path reopen or copied admission is involved.
    pub(super) fn into_terminal_restoration_parts(mut self,
        closed: &super::paged_recovery::PartitionClosedJournalObservation,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::partition_restoration::PartitionTerminalTargetParts> {
        let token = self.owner_token();
        closed.require_owner(&token)?;
        self.revalidate_current_critical_volume_policy(events)?;
        Ok(super::partition_restoration::PartitionTerminalTargetParts {
            file: self.file, physical_readonly: self.physical_readonly,
            binding: self.binding, budget: self.budget, state: self.enrolled, token,
        })
    }
    /// Named current-critical-volume policy, not hidden loaded-driver proof.
    /// revalidate reobserves actual complete VDS roles/native critical extents,
    /// Windows/pagefiles, resolved configured dumps and private target baseline.
    /// The raw runtime_loaded_dump_locations_verified diagnostic stays false;
    /// existing unknown/custom-filter refusals remain in the collector.
    pub(super) fn revalidate_current_critical_volume_policy(&mut self,
        events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.revalidate(events)?;
        let paging = &self.enrolled.partition.paging;
        let roles = &self.enrolled.storage_current_partition_roles;
        if !paging.enumeration_succeeded || !paging.all_locations_resolved
            || paging.source_hosts_active_pagefile
            || !roles.catalog_complete
            || !self.enrolled.configured_dump_locations.configured_locations_outside_target {
            return Err(io::Error::other("current-critical-volume partition policy unresolved"));
        }
        Ok(())
    }

    pub fn qualify_fresh_paged_apply(&mut self,
        admission: &mut super::partition_lifecycle::PartitionNtfsAdmission,
        policy: &HeldPagedWritePolicy, journal: &mut File,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>, events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionSourceAdmissionGate> {
        if self.enrolled.source_admission_issued {
            return Err(io::Error::other("partition fresh source admission already issued"));
        }
        self.revalidate_current_critical_volume_policy(events)?;
        super::partition_lifecycle::require_complete_fresh_ntfs_admission(self, admission)?;
        let preparation_pin = admission.durable_preparation_pin()?;
        admission.revalidate_publication_handoff(self, &preparation_pin, events)?;
        super::paged_recovery::authenticate_scoped_partition_paged_source(self, policy, journal,
            pins, super::paged_recovery::PartitionJournalPhase::FreshOld)?;
        admission.revalidate_publication_handoff(self, &preparation_pin, events)?;
        self.revalidate_current_critical_volume_policy(events)?;
        let gate = PartitionSourceAdmissionGate { owner_identity: self.identity.clone(),
            binding: self.binding.clone(), preparation: admission.preparation_token().clone(),
            preparation_pin, journal: super::paged_recovery::OwnedPartitionJournalPins::capture(pins),
            index_sha256: policy.facts()?.index_sha256, used: false };
        self.enrolled.source_admission_issued = true;
        Ok(gate)
    }

    /// Spend this actual gate BEFORE any AP write attempt. Flush/read back AP
    /// before returning the only bounded writer. No device setter is needed.
    pub fn begin_fresh_partition_paged_apply<'a, 'p>(&'a mut self,
        gate: &'a mut PartitionSourceAdmissionGate,
        admission: &'a mut super::partition_lifecycle::PartitionNtfsAdmission,
        policy: HeldPagedWritePolicy, journal: &'a mut File,
        pins: &'a super::paged_recovery::PagedRecoveryPins<'p>, events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionPagedWriter<'a, 'p>> {
        if gate.used { return Err(io::Error::other("partition AP gate is spent")); }
        gate.require_bound(self, admission, &policy, pins)?;
        self.revalidate_current_critical_volume_policy(events)?;
        admission.revalidate_publication_handoff(self, &gate.preparation_pin, events)?;
        super::paged_recovery::authenticate_scoped_partition_paged_source(self, &policy, journal,
            pins, super::paged_recovery::PartitionJournalPhase::FreshOld)?;
        admission.revalidate_publication_handoff(self, &gate.preparation_pin, events)?;
        self.revalidate_current_critical_volume_policy(events)?;
        gate.used = true;
        let activation = (|| {
            super::paged_recovery::publish_partition_apply_marker(journal, pins, events)?;
            admission.revalidate_publication_handoff(self, &gate.preparation_pin, events)?;
            self.revalidate_current_critical_volume_policy(events)?;
            super::paged_recovery::authenticate_scoped_partition_paged_source(self, &policy,
                journal, pins, super::paged_recovery::PartitionJournalPhase::Applying)
        })();
        if let Err(error) = activation { self.poisoned = true; return Err(error); }
        Ok(PartitionPagedWriter { owner: self, policy, journal, pins, _admission: Some(gate),
            native_admission: Some(admission), replay_admission: None,
            requested: 0, written: 0, pending: None, poisoned: false })
    }

    /// Consume only the actual AP-spent gate. A readonly SAME-FileObject J
    /// duplicate is retained after canonical HND and complete NEW verification.
    pub fn finish_fresh_partition_handoff(&mut self, gate: PartitionSourceAdmissionGate,
        admission: &mut super::partition_lifecycle::PartitionNtfsAdmission,
        policy: &HeldPagedWritePolicy, journal: &mut File,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>, events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::paged_recovery::PartitionHandoffWitness> {
        if !gate.used { return Err(io::Error::other("partition HND requires spent actual AP gate")); }
        gate.require_bound(self, admission, policy, pins)?;
        admission.revalidate_publication_handoff(self, &gate.preparation_pin, events)?;
        self.revalidate_current_critical_volume_policy(events)?;
        let witness = super::paged_recovery::PartitionHandoffWitness::from_spent_gate(
            self, policy, journal, pins, events)?;
        admission.revalidate_publication_handoff(self, &gate.preparation_pin, events)?;
        self.revalidate_current_critical_volume_policy(events)?;
        Ok(witness)
    }
}

impl PartitionScopedOwner {
    pub fn open_private(
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        budget.validate()?;
        let metadata_work = budget
            .gpt_entry_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(u64::from(budget.native_layout_bytes) * 8))
            .and_then(|n| n.checked_add(u64::from(budget.read_buffer_bytes) * 2))
            .and_then(|n| n.checked_add(2 * 1024 * 1024 + MAX_IO as u64 + 256 * 1024))
            .and_then(|n| n.checked_add(budget.ram_bytes / 4))
            .ok_or_else(|| io::Error::other("partition owner memory accounting overflow"))?;
        if metadata_work > budget.ram_bytes
            || !binding
                .storage
                .identity
                .partition_bytes
                .is_multiple_of(GRANULE)
            || !binding
                .storage
                .identity
                .partition_offset
                .is_multiple_of(GRANULE)
        {
            return Err(io::Error::other(
                "partition owner geometry/metadata buffers exceed explicit budget",
            ));
        }
        let physical = format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number);
        let mut physical_readonly = OpenOptions::new().read(true).share_mode(3).open(physical)?;
        let partition = super::partition_isolation::observe_private(
            &mut physical_readonly,
            &binding,
            budget,
            events,
        )?;
        let dumps = observe_configured_dump_locations(&binding, budget, events)?;
        let vds_roles = runtime_volume_role_diagnostics(&binding,budget,events);
        let storage_roles=observe_partition_storage_roles(&binding,budget,events)?;
        if !dumps.configured_locations_outside_target
            || !storage_roles.catalog_complete
        {
            return Err(io::Error::other(
                "configured dump routes or current Storage Management partition roles are unresolved",
            ));
        }
        let enrolled = PartitionOwnerState {
            partition,
            configured_dump_locations: dumps,
            vds_current_volume_roles: vds_roles,
            storage_current_partition_roles:storage_roles,
            source_admission_issued: false,
            loaded_dump_exclusion_qualified: false,
        };
        let route = format!(
            "\\\\?\\GLOBALROOT\\Device\\Harddisk{}\\Partition{}",
            binding.storage.disk_number, binding.storage.identity.partition_number
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(1)
            .custom_flags(0xa000_0000)
            .open(route)?;
        let mut owner = Self {
            identity: Arc::new(PartitionOwnerIdentity { data_cursor: Mutex::new(()) }),
            file,
            physical_readonly,
            binding,
            budget,
            enrolled,
            buffer: AlignedBuffer::new()?,
            position: 0,
            poisoned: false,
            recovery_events: None,
        };
        owner.revalidate(events)?;
        Ok(owner)
    }
    /// Transfer only the actual retained lifecycle File objects. No target
    /// pathname is opened, and no serialized flag creates the owner/token.
    pub(super) fn adopt_lifecycle_owner(
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        file: File,
        mut physical_readonly: File,
        events_sink:super::partition_lifecycle::PartitionNativeEventSink,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        budget.validate()?;
        let partition = super::partition_isolation::observe_private(
            &mut physical_readonly, &binding, budget, events,
        )?;
        let dumps = observe_configured_dump_locations(&binding, budget, events)?;
        let vds_roles = runtime_volume_role_diagnostics(&binding,budget,events);
        let storage_roles=observe_partition_storage_roles(&binding,budget,events)?;
        if !dumps.configured_locations_outside_target
            || !storage_roles.catalog_complete
        {
            return Err(io::Error::other("lifecycle adoption lost critical-volume disjointness"));
        }
        let info = control(&file, "adopt-original-partition-owner-info", 0x0007_0048, &[], 144, events)?;
        let target = crate::layout::guid_bytes(&binding.storage.identity.partition_guid)?;
        let expected = partition.gpt.native_layout[48..].chunks_exact(144)
            .find(|row| row[48..64] == target)
            .ok_or_else(|| io::Error::other("adopted target native row missing"))?;
        if info.as_slice() != expected || info[32..48] != crate::layout::guid_bytes(PRIVATE_TYPE)?
            || crate::layout::u64_at(&info, 64)? != 0
        {
            return Err(io::Error::other("original lifecycle File is not the actual private target"));
        }
        let mut owner = Self {
            identity: Arc::new(PartitionOwnerIdentity { data_cursor: Mutex::new(()) }),
            file, physical_readonly, binding, budget,
            enrolled: PartitionOwnerState {
                partition, configured_dump_locations: dumps, vds_current_volume_roles: vds_roles,
            storage_current_partition_roles:storage_roles,
                source_admission_issued: false, loaded_dump_exclusion_qualified: false,
            },
            buffer: AlignedBuffer::new()?, position: 0, poisoned: false, recovery_events:Some(events_sink),
        };
        owner.revalidate(events)?;
        Ok(owner)
    }
    /// Reduced read duplicate of this actual retained source FileObject.
    /// Caller brackets construction with full actual owner revalidation.
    pub(super) fn duplicate_source_read_lane(&self, events: &mut Vec<NativeEvent>)
        -> io::Result<super::partition_lifecycle::held_read::HeldSourceRead> {
        if self.poisoned { return Err(io::Error::other("poisoned source cannot issue a held read lane")); }
        let guid=crate::layout::guid_bytes(&self.binding.storage.identity.partition_guid)?;
        let expected=self.enrolled.partition.gpt.native_layout.get(48..)
            .and_then(|rows|rows.chunks_exact(144).find(|row|row[48..64]==guid))
            .ok_or_else(||io::Error::other("held read lane source native row absent"))?;
        super::partition_lifecycle::held_read::duplicate_bound(
            &self.file,&self.binding,expected,&self.owner_token(),events)
    }
    pub fn construction_metadata_memory_bytes(&self) -> u64 { self.budget.ram_bytes }
    /// Query-only duplicate of the original lifecycle FileObject. Neither a
    /// pathname nor serialized state can create this construction witness.
    pub fn construction_metadata_witness(
        &mut self,
        admission: &super::partition_lifecycle::PartitionNtfsAdmission,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::PartitionSourceMetadataWitness> {
        use crate::attestation::NativeObservationDomain;
        admission.checkpoint_native_events("partition-construction-owner-opening",events)?;
        let result=(|| {
        self.revalidate(events)?;
        super::partition_lifecycle::require_complete_fresh_ntfs_admission(self, admission)?;
        admission.native().domain().revalidate()?;
        let pin = admission.durable_preparation_pin()?;
        let target_guid=crate::layout::guid_bytes(&self.binding.storage.identity.partition_guid)?;
        let expected=self.enrolled.partition.gpt.native_layout.get(48..)
            .and_then(|rows|rows.chunks_exact(144).find(|row|row[48..64]==target_guid))
            .ok_or_else(||io::Error::other("construction source native GPT row absent before volume duplicate"))?;
        let duplicate = super::partition_source_metadata::volume_query::duplicate_bound(
            &self.file,&self.binding,expected,&self.owner_token(),events)?;
        let witness = super::PartitionSourceMetadataWitness::from_live(
            duplicate, self.binding.clone(), self.budget, self.owner_token(), self.enrolled.clone(),
            admission.native().domain().sha256().to_owned(), pin.intent_prefix_sha256,
            admission.native().domain().header().request.resource_profile,
            admission.event_sink(),
        )?;
        witness.revalidate(events)?;

        self.revalidate(events)?;
        Ok(witness)
        })();
        let closed=admission.checkpoint_native_events("partition-construction-owner-closed",events);
        match(result,closed){(Ok(value),Ok(()))=>Ok(value),(Err(error),_)|(_,Err(error))=>Err(error)}
    }
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.binding
    }
    pub fn owner_token(&self) -> PartitionOwnerToken {
        PartitionOwnerToken(self.identity.clone())
    }
    pub fn state(&self) -> &PartitionOwnerState {
        &self.enrolled
    }
    pub fn byte_len(&self) -> u64 {
        self.binding.storage.identity.partition_bytes
    }
    pub fn revalidate(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if let Some(sink)=&self.recovery_events{
            if let Err(error)=sink.checkpoint("partition-recovery-owner-before",events){self.poisoned=true;return Err(error);}
        }
        let result = self.revalidate_inner(events);
        let result=if let Some(sink)=&self.recovery_events{
            let closed=sink.checkpoint("partition-recovery-owner-after",events);
            match(result,closed){
                (Ok(()),Ok(()))=>Ok(()),
                (Err(error),Err(checkpoint))=>Err(io::Error::new(error.kind(),format!("{error}; recovery event checkpoint also failed: {checkpoint}"))),
                (Err(error),_)|(_,Err(error))=>Err(error),
            }
        }else{result};
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn revalidate_inner(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let current = super::partition_isolation::observe_private(
            &mut self.physical_readonly,
            &self.binding,
            self.budget,
            events,
        )?;
        let dumps = observe_configured_dump_locations(&self.binding, self.budget, events)?;
        let storage_roles=observe_partition_storage_roles(&self.binding,self.budget,events)?;
        if !super::partition_isolation::same_private_identity(&self.enrolled.partition, &current)
            || dumps != self.enrolled.configured_dump_locations
            || !dumps.configured_locations_outside_target
            || !storage_roles.catalog_complete
            || !storage_roles.same_critical_roles(&self.enrolled.storage_current_partition_roles)
        {
            self.poisoned = true;
            return Err(io::Error::other(
                "partition GPT/siblings/critical locations changed",
            ));
        }
        let number = control(
            &self.file,
            "partition-owner-device",
            super::DEVICE,
            &[],
            12,
            events,
        )?;
        let info = control(
            &self.file,
            "partition-owner-native-info",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        let target_guid = crate::layout::guid_bytes(&self.binding.storage.identity.partition_guid)?;
        let row = self.enrolled.partition.gpt.native_layout[48..]
            .chunks_exact(144)
            .find(|row| row[48..64] == target_guid)
            .ok_or_else(|| io::Error::other("partition owner target native row absent"))?;
        if number.len() != 12
            || crate::layout::u32_at(&number, 0)? != 7
            || crate::layout::u32_at(&number, 4)? != self.binding.storage.disk_number
            || crate::layout::u32_at(&number, 8)? != self.binding.storage.identity.partition_number
            || info.len() != 144
            || info != row
            || info[32..48] != crate::layout::guid_bytes(PRIVATE_TYPE)?
        {
            self.poisoned = true;
            return Err(io::Error::other(
                "same held partition handle identity/type/extent changed",
            ));
        }
        if self.poisoned {
            return Err(io::Error::other("partition owner is poisoned"));
        }
        Ok(())
    }

    /// Internal only and currently unreachable: no PartitionSourceAdmissionGate
    /// issuer exists. Native journal/OLD gates are required even after issuance.
    pub(super) fn lease_old<'a, 'p>(
        &'a mut self,
        admission: &'a PartitionSourceAdmissionGate,
        policy: HeldPagedWritePolicy,
        journal: &'a mut File,
        pins: &'a super::paged_recovery::PagedRecoveryPins<'p>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionPagedWriter<'a, 'p>> {
        if !Arc::ptr_eq(&admission.owner_identity, &self.identity)
            || admission.binding != self.binding
        {
            return Err(io::Error::other(
                "partition live source admission does not bind this owner",
            ));
        }
        // Configured registry locations alone cannot establish the kernel's
        // loaded crash/dump roles. No gate issuer exists until this is proven.
        if !self
            .enrolled
            .configured_dump_locations
            .runtime_loaded_dump_locations_verified
        {
            return Err(io::Error::other(
                "runtime loaded critical-role exclusion remains unqualified",
            ));
        }
        self.revalidate(events)?;
        super::paged_recovery::authenticate_partition_paged_source(
            self, &policy, journal, pins, false,
        )?;
        self.revalidate(events)?;
        Ok(PartitionPagedWriter {
            owner: self,
            policy,
            journal,
            pins,
            _admission: Some(admission),
            native_admission: None,
            replay_admission: None,
            requested: 0,
            written: 0,
            pending: None,
            poisoned: false,
        })
    }
}

impl PartitionScopedOwner{
    /// Attach only an owned durable observation destination to this actual
    /// private owner. It grants no admission, direction, setter or writer.
    /// The callback remains live until this owner is consumed or dropped.
    pub fn attach_recovery_observer(mut self,observer:Box<dyn super::partition_lifecycle::PartitionPreparationObserver>,
        events:&mut Vec<NativeEvent>)->io::Result<Self>{
        if self.recovery_events.is_some(){return Err(io::Error::other("recovery owner already has a durable event destination"));}
        self.recovery_events=Some(super::partition_lifecycle::PartitionNativeEventSink::new(observer));
        self.revalidate(events)?;Ok(self)
    }
}

impl Seek for PartitionScopedOwner {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let value = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.byte_len()) + i128::from(n),
        };
        if value < 0 || value > i128::from(self.byte_len()) {
            return Err(io::Error::other("partition seek outside bounds"));
        }
        self.position = value as u64;
        Ok(self.position)
    }
}
impl Read for PartitionScopedOwner {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(io::Error::other("partition owner poisoned"));
        }
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let lead = (self.position % GRANULE) as usize;
        let count = ((output.len().min(MAX_IO - lead)) as u64).min(self.byte_len() - self.position)
            as usize;
        let transfer = (lead + count).div_ceil(GRANULE as usize) * GRANULE as usize;
        let expected = self.position - lead as u64;
        let result = (|| {
            let _cursor=self.identity.data_cursor.lock()
                .map_err(|_|io::Error::other("actual source FILE_OBJECT cursor lock poisoned"))?;
            if self.file.seek(SeekFrom::Start(expected))? != expected {
                return Err(io::Error::other("partition read seek differs"));
            }
            self.file.read(&mut self.buffer.bytes_mut()[..transfer])
        })();
        match result {
            Ok(n) if n >= lead + count => {
                output[..count].copy_from_slice(&self.buffer.bytes_mut()[lead..lead + count]);
                self.position += count as u64;
                Ok(count)
            }
            Ok(_) => {
                self.poisoned = true;
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short bounded partition read",
                ))
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}

pub struct PartitionPagedWriter<'a, 'p> {
    owner: &'a mut PartitionScopedOwner,
    policy: HeldPagedWritePolicy,
    journal: &'a mut File,
    pins: &'a super::paged_recovery::PagedRecoveryPins<'p>,
    _admission: Option<&'a PartitionSourceAdmissionGate>,
    native_admission: Option<&'a mut super::partition_lifecycle::PartitionNtfsAdmission>,
    replay_admission: Option<&'a PartitionMixedReplayGate>,
    requested: u64,
    written: u64,
    pending: Option<(u64, usize, [u8; 32])>,
    poisoned: bool,
}
impl PartitionPagedWriter<'_, '_> {
    fn poison(&mut self, error: io::Error) -> io::Error {
        self.poisoned = true;
        self.owner.poisoned = true;
        error
    }
    pub fn byte_len(&self) -> u64 {
        self.owner.byte_len()
    }
    pub fn native_bytes_written(&self) -> u64 {
        self.written
    }
    pub fn sync_all(&mut self) -> io::Result<()> {
        use sha2::{Digest, Sha256};
        let result = (|| {
            if self.poisoned || self.owner.poisoned {
                return Err(io::Error::other("partition paged writer poisoned"));
            }
            let _cursor=self.owner.identity.data_cursor.lock()
                .map_err(|_|io::Error::other("actual source FILE_OBJECT cursor lock poisoned"))?;
            self.owner.file.sync_all()?;
            if let Some((at, bytes, expected)) = self.pending {
                if self.owner.file.seek(SeekFrom::Start(at))? != at {
                    return Err(io::Error::other("partition readback seek differs"));
                }
                let got = self
                    .owner
                    .file
                    .read(&mut self.owner.buffer.bytes_mut()[..bytes])?;
                if got != bytes
                    || <[u8; 32]>::from(Sha256::digest(&self.owner.buffer.bytes_mut()[..bytes]))
                        != expected
                {
                    return Err(io::Error::other("partition write flush/readback failed"));
                }
                self.pending = None;
            }
            Ok(())
        })();
        result.map_err(|error| self.poison(error))
    }
    /// Read+Seek only, borrowing this SAME J. Drop before the next source write.
    pub fn journal_read_view(&mut self) -> io::Result<PartitionJournalReadView<'_>> {
        self.sync_all()?;
        let length = self.policy.facts()?.journal_length;
        let position = self.journal.stream_position()?;
        if position > length { return Err(self.poison(io::Error::other("partition J view position outside actual length"))); }
        Ok(PartitionJournalReadView { journal: self.journal, length, position })
    }
    pub fn revalidate(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let result = (|| {
            self.sync_all()?;
            self.owner.revalidate_current_critical_volume_policy(events)?;
            if let Some(admission) = self.native_admission.as_deref_mut() {
                let gate = self._admission.ok_or_else(|| io::Error::other("fresh partition writer gate missing"))?;
                gate.require_bound(self.owner, admission, &self.policy, self.pins)?;
                admission.revalidate_publication_handoff(self.owner, &gate.preparation_pin, events)?;
                super::paged_recovery::authenticate_scoped_partition_paged_source(self.owner,
                    &self.policy, self.journal, self.pins, super::paged_recovery::PartitionJournalPhase::Applying)?;
            } else if let Some(gate) = self.replay_admission {
                gate.require_bound(self.owner, &self.policy, self.pins)?;
                if !gate.used { return Err(io::Error::other("partition replay writer gate not spent")); }
                super::paged_recovery::authenticate_scoped_partition_paged_source(self.owner,
                    &self.policy, self.journal, self.pins,
                    super::paged_recovery::PartitionJournalPhase::Replaying(gate.direction))?;
            } else { return Err(io::Error::other("legacy partition lease lacks current-policy admission")); }
            self.owner.revalidate_current_critical_volume_policy(events)
        })();
        result.map_err(|error| self.poison(error))
    }
    pub fn finish_new(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let result = (|| {
            self.sync_all()?;
            if let Some(gate) = self.replay_admission {
                if gate.direction != super::paged_recovery::PagedRecoveryDirection::Resume {
                    return Err(io::Error::other("Rollback writer cannot finish NEW"));
                }
            }
            if self.native_admission.is_some() || self.replay_admission.is_some() {
                self.revalidate(events)?;
                super::paged_recovery::authenticate_scoped_partition_paged_source(self.owner,
                    &self.policy, self.journal, self.pins, super::paged_recovery::PartitionJournalPhase::New)?;
                return self.revalidate(events);
            }
            self.owner.revalidate(events)?;
            super::paged_recovery::authenticate_partition_paged_source(
                self.owner,
                &self.policy,
                self.journal,
                self.pins,
                true,
            )?;
            self.owner.revalidate(events)
        })();
        result.map_err(|error| self.poison(error))
    }
    /// Complete restore-required OLD digest plus source-free OLD/NEW granules,
    /// while exact RB is still active. ROOT then flushes canonical ABT and uses
    /// finish_partition_replay_abort to consume the spent direction-bound gate.
    pub fn finish_old(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let result = (|| {
            let gate = self.replay_admission.ok_or_else(|| io::Error::other("finish OLD requires reopened Rollback gate"))?;
            if gate.direction != super::paged_recovery::PagedRecoveryDirection::Rollback {
                return Err(io::Error::other("Resume writer cannot finish OLD"));
            }
            self.revalidate(events)?;
            super::paged_recovery::authenticate_scoped_partition_paged_source(self.owner,
                &self.policy, self.journal, self.pins, super::paged_recovery::PartitionJournalPhase::Restored)?;
            self.revalidate(events)
        })();
        result.map_err(|error| self.poison(error))
    }
}

/// Bounded readonly borrow; no Write/File/raw-handle/clone interface exists.
pub struct PartitionJournalReadView<'a> {
    journal: &'a mut File,
    length: u64,
    position: u64,
}
impl Read for PartitionJournalReadView<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = (out.len().min(MAX_IO) as u64).min(self.length - self.position) as usize;
        if count == 0 { return Ok(0); }
        if self.journal.seek(SeekFrom::Start(self.position))? != self.position {
            return Err(io::Error::other("partition J view seek differs"));
        }
        let n = self.journal.read(&mut out[..count])?;
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for PartitionJournalReadView<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let at = match from { SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n) };
        if at < 0 || at > i128::from(self.length) { return Err(io::Error::other("partition J view outside bounds")); }
        self.position = at as u64;
        Ok(self.position)
    }
}
impl Read for PartitionPagedWriter<'_, '_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.sync_all()?;
        let result = self.owner.read(b);
        result.map_err(|error| self.poison(error))
    }
}
impl Seek for PartitionPagedWriter<'_, '_> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.sync_all()?;
        let result = self.owner.seek(p);
        result.map_err(|error| self.poison(error))
    }
}
impl Write for PartitionPagedWriter<'_, '_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        use sha2::{Digest, Sha256};
        if input.is_empty() {
            return Ok(0);
        }
        let admission = (|| {
            let requested = self
                .requested
                .checked_add(input.len() as u64)
                .ok_or_else(|| io::Error::other("partition write accounting overflow"))?;
            let facts = self.policy.facts()?;
            let permitted = self
                .policy
                .permits(self.owner.position, input.len() as u64)?;
            if self.poisoned
                || self.owner.poisoned
                || self.pending.is_some()
                || input.len() > MAX_IO
                || !self.owner.position.is_multiple_of(GRANULE)
                || !(input.len() as u64).is_multiple_of(GRANULE)
                || self
                    .owner
                    .position
                    .checked_add(input.len() as u64)
                    .is_none_or(|end| end > self.byte_len())
                || !permitted
                || requested > facts.selected_bytes
            {
                return Err(io::Error::other(
                    "partition write outside authenticated bounded policy or prior readback pending",
                ));
            }
            Ok(requested)
        })();
        let requested = admission.map_err(|error| self.poison(error))?;
        let at = self.owner.position;
        let result = (|| {
            let _cursor=self.owner.identity.data_cursor.lock()
                .map_err(|_|io::Error::other("actual source FILE_OBJECT cursor lock poisoned"))?;
            if self.owner.file.seek(SeekFrom::Start(at))? != at {
                return Err(io::Error::other("partition write seek differs"));
            }
            self.owner.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
            self.requested = requested;
            let n=self.owner.file.write(&self.owner.buffer.bytes_mut()[..input.len()])?;
            if n!=input.len() {return Err(io::Error::new(io::ErrorKind::WriteZero,
                "short partition write; authenticated recovery required"));}
            self.written += n as u64;
            self.owner.position += n as u64;
            self.pending = Some((at, n, Sha256::digest(input).into()));
            Ok(n)
        })();
        // The mutex guard is gone before poisoning either borrowed owner.
        result.map_err(|error|self.poison(error))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}
