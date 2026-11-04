//! Query-only source metadata witness issued from the actual owner/admission.
//! Its readonly duplicate retains the ORIGINAL FileObject/lock. No Read, Seek,
//! payload operation, path constructor, Deserialize or source writer is exposed.
use super::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
use super::{NativeEvent, PartitionOwnerState, PartitionOwnerToken, control, device_file};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fmt, fs::File, io};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionSourceMetadataState {
    pub binding: PartitionSourceBinding,
    pub native_partition_info: Vec<u8>,
    pub original_gpt_entries_sha256: String,
    pub native_metadata_file_sha256: String,
    pub preparation_intent_sha256: String,
    pub grants_source_write_authority: bool,
    pub retained_memory_ceiling_bytes: u64,
    pub resource_profile: Option<crate::attestation::ResourceProfile>,
}
pub struct PartitionSourceMetadataWitness {
    file: File,
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    token: PartitionOwnerToken,
    baseline: PartitionOwnerState,
    state: PartitionSourceMetadataState,
    event_sink: super::partition_lifecycle::PartitionNativeEventSink,
    _memory: Option<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>,
}
impl fmt::Debug for PartitionSourceMetadataWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartitionSourceMetadataWitness")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
impl PartitionSourceMetadataWitness {
    pub(super) fn from_live(
        file: File,
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        token: PartitionOwnerToken,
        baseline: PartitionOwnerState,
        native_sha: String,
        intent_sha: String,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        event_sink: super::partition_lifecycle::PartitionNativeEventSink,
    ) -> io::Result<Self> {
        crate::file_storage::require_readonly_access(&file)?;
        let guid = crate::layout::guid_bytes(&binding.storage.identity.partition_guid)?;
        let row = baseline.partition.gpt.native_layout[48..]
            .chunks_exact(144)
            .find(|row| row[48..64] == guid)
            .ok_or_else(|| io::Error::other("source witness native target row absent"))?;
        let state = PartitionSourceMetadataState {
            binding: binding.clone(),
            native_partition_info: row.to_vec(),
            original_gpt_entries_sha256: hex::encode(Sha256::digest(
                &baseline.partition.gpt.entries,
            )),
            native_metadata_file_sha256: native_sha,
            preparation_intent_sha256: intent_sha,
            grants_source_write_authority: false,
            retained_memory_ceiling_bytes: budget.ram_bytes,
            resource_profile,
        };
        Ok(Self {
            file,
            binding,
            budget,
            token,
            baseline,
            state,
            event_sink,
            _memory: None,
        })
    }
    pub fn state(&self) -> &PartitionSourceMetadataState {
        &self.state
    }
    pub fn owner_token(&self) -> &PartitionOwnerToken {
        &self.token
    }
    pub(crate) fn retain_memory(
        mut self,
        memory: Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>,
    ) -> Self {
        self._memory = Some(memory);
        self
    }
    pub fn require_profile(&self, profile: crate::attestation::ResourceProfile) -> io::Result<()> {
        if self.state.resource_profile == Some(profile) {
            Ok(())
        } else {
            Err(io::Error::other(
                "construction resource/native admission differs",
            ))
        }
    }
    pub fn require_owner(&self, token: &PartitionOwnerToken) -> io::Result<()> {
        if self.token.same_owner(token) {
            Ok(())
        } else {
            Err(io::Error::other(
                "partition metadata belongs to another actual owner",
            ))
        }
    }
    pub fn require_binding(
        &self,
        binding: &crate::general_layout::GeneralDiskBinding,
    ) -> io::Result<()> {
        if &self.binding.storage == binding {
            Ok(())
        } else {
            Err(io::Error::other(
                "partition metadata source binding differs",
            ))
        }
    }
    pub fn checkpoint_native_events(
        &self,
        phase: &'static str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.event_sink.checkpoint(phase, events)
    }
    pub fn revalidate(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.checkpoint_native_events("partition-source-metadata-opening", events)?;
        let result = (|| -> io::Result<()> {
            crate::file_storage::require_readonly_access(&self.file)?;
            let device = control(
                &self.file,
                "construction-original-source-device",
                super::DEVICE,
                &[],
                12,
                events,
            )?;
            let info = control(
                &self.file,
                "construction-original-source-partition",
                0x0007_0048,
                &[],
                144,
                events,
            )?;
            if device.len() != 12
                || crate::layout::u32_at(&device, 0)? != 7
                || crate::layout::u32_at(&device, 4)? != self.binding.storage.disk_number
                || crate::layout::u32_at(&device, 8)?
                    != self.binding.storage.identity.partition_number
                || info != self.state.native_partition_info
                || info[32..48]
                    != crate::layout::guid_bytes("b627aadb-a893-48b6-aa0b-71e5f30ee370")?
                || crate::layout::u64_at(&info, 64)? != 0
            {
                return Err(io::Error::other(
                    "same original source FileObject private identity changed",
                ));
            }
            // This independent readonly physical metadata FileObject has its OWN
            // cursor. Original source-volume FileObject receives queries only.
            let mut physical = device_file(
                &format!("\\\\.\\PhysicalDrive{}", self.binding.storage.disk_number),
                false,
                false,
            )?;
            let current = super::partition_isolation::observe_private(
                &mut physical,
                &self.binding,
                self.budget,
                events,
            )?;
            if !super::partition_isolation::same_private_identity(
                &self.baseline.partition,
                &current,
            ) {
                return Err(io::Error::other(
                    "partition metadata GPT/C/pagefile baseline changed",
                ));
            }
            let dumps = super::partition_dump_locations::observe_configured_dump_locations(
                &self.binding,
                self.budget,
                events,
            )?;
            let _vds_diagnostics=super::partition_runtime_roles::runtime_volume_role_diagnostics(&self.binding,self.budget,events);
            let roles=super::partition_storage_roles::observe_partition_storage_roles(&self.binding,self.budget,events)?;
            if dumps != self.baseline.configured_dump_locations
                || !roles.same_critical_roles(&self.baseline.storage_current_partition_roles)
            {
                return Err(io::Error::other(
                    "partition metadata critical-volume bindings changed",
                ));
            }
            Ok(())
        })();
        let closed = self.checkpoint_native_events("partition-source-metadata-closed", events);
        match (result, closed) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
    /// Conservative retained fact/handle workspace under the caller's actual
    /// V4 accountant. This excludes the caller's independent input row leases.
    pub fn retained_memory_bytes(&self) -> u64 {
        self.budget.ram_bytes
    }
}
