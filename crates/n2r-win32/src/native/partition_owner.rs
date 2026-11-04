//! UNAPPLIED foundation: an actual held private-partition owner, not a frozen
//! NTFS admission certificate. No CLI selector, setter, repair or Drop teardown.
use super::partition_dump_locations::{
    ConfiguredDumpObservation, observe_configured_dump_locations,
};
use super::partition_isolation::{
    PartitionIsolationObservation, PartitionObservationBudget, PartitionSourceBinding,
};
use super::partition_runtime_roles::{
    RuntimeVolumeRoleObservation, observe_runtime_volume_roles,
};
use super::{AlignedBuffer, HeldPagedWritePolicy, MAX_IO, NativeEvent, control};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    sync::Arc,
};

const PRIVATE_TYPE: &str = "b627aadb-a893-48b6-aa0b-71e5f30ee370";
const GRANULE: u64 = 4096;

#[derive(Clone, Debug, Serialize)]
pub struct PartitionOwnerState {
    pub partition: PartitionIsolationObservation,
    pub(super) configured_dump_locations: ConfiguredDumpObservation,
    pub(super) vds_current_volume_roles: RuntimeVolumeRoleObservation,
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
}
struct PartitionOwnerIdentity {
    _private: (),
}
/// Stable equality identity from an actual owner, never source admission.
/// Moving the owner preserves it; no serialized/path constructor exists.
#[derive(Clone)]
pub struct PartitionOwnerToken(Arc<PartitionOwnerIdentity>);
impl PartitionOwnerToken {
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Intentionally UNISSUED. No constructor, Deserialize, saved flag or public
/// observer can create this. Full live NTFS/target admission remains pending.
pub(super) struct PartitionSourceAdmissionGate {
    owner_identity: Arc<PartitionOwnerIdentity>,
    binding: PartitionSourceBinding,
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
        let vds_roles = observe_runtime_volume_roles(&binding, budget, events)?;
        if !dumps.configured_locations_outside_target
            || !vds_roles.vds_enumeration_completed
            || !vds_roles.vds_critical_role_extents_outside_target
        {
            return Err(io::Error::other(
                "configured dump routes or current VDS critical-volume extents are unresolved",
            ));
        }
        let enrolled = PartitionOwnerState {
            partition,
            configured_dump_locations: dumps,
            vds_current_volume_roles: vds_roles,
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
            identity: Arc::new(PartitionOwnerIdentity { _private: () }),
            file,
            physical_readonly,
            binding,
            budget,
            enrolled,
            buffer: AlignedBuffer::new()?,
            position: 0,
            poisoned: false,
        };
        owner.revalidate(events)?;
        Ok(owner)
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
        let result = self.revalidate_inner(events);
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
        let vds_roles = observe_runtime_volume_roles(&self.binding, self.budget, events)?;
        if !super::partition_isolation::same_private_identity(&self.enrolled.partition, &current)
            || dumps != self.enrolled.configured_dump_locations
            || !dumps.configured_locations_outside_target
            || !vds_roles.vds_enumeration_completed
            || !vds_roles.vds_critical_role_extents_outside_target
            || !vds_roles.same_critical_roles(&self.enrolled.vds_current_volume_roles)
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
            _admission: admission,
            requested: 0,
            written: 0,
            pending: None,
            poisoned: false,
        })
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
        let sought = match self.file.seek(SeekFrom::Start(expected)) {
            Ok(at) => at,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if sought != expected {
            self.poisoned = true;
            return Err(io::Error::other("partition read seek differs"));
        }
        let result = self.file.read(&mut self.buffer.bytes_mut()[..transfer]);
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
    _admission: &'a PartitionSourceAdmissionGate,
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
    pub fn finish_new(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let result = (|| {
            self.sync_all()?;
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
        let sought = self
            .owner
            .file
            .seek(SeekFrom::Start(at))
            .map_err(|error| self.poison(error))?;
        if sought != at {
            return Err(self.poison(io::Error::other("partition write seek differs")));
        }
        self.owner.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
        self.requested = requested;
        match self
            .owner
            .file
            .write(&self.owner.buffer.bytes_mut()[..input.len()])
        {
            Ok(n) if n == input.len() => {
                self.written += n as u64;
                self.owner.position += n as u64;
                self.pending = Some((at, n, Sha256::digest(input).into()));
                Ok(n)
            }
            Ok(_) => {
                self.poisoned = true;
                self.owner.poisoned = true;
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short partition write; authenticated recovery required",
                ))
            }
            Err(error) => {
                self.poisoned = true;
                self.owner.poisoned = true;
                Err(error)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}
