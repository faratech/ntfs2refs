//! Actual live journal ownership for unactivated preparation cancellation.
//! No saved marker flag, missing pathname or publication grants this type.
use crate::artifact_arena::ArenaRamLease;
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent, PartitionOwnerToken, PartitionScopedOwner,
    partition_lifecycle::PartitionNtfsAdmission,
    journal_file::{
        GeneralJournalStorageBinding, JournalFileIdentity, JournalFileSnapshot, JournalProfile,
        observe_general_journal_file_with_profile,
    },
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::OpenOptionsExt,
};

pub(super) enum LiveCancellationJournal {
    NotStarted,
    Attempting,
    Owned(LiveClearJournal),
}
/// This charge covers both bounded native observation copies/path storage and
/// the fixed lifecycle read. The context prepays it before any CreateNew.
pub(crate) const WORKING_MEMORY_BYTES: u64 = 256 * 1024;
// Provenance is captured only from an actual matching SDK admission. The
// retained enum is not deserializable or caller-constructed routing authority.
enum LiveJournalLocation {
    CurrentWindows,
    ExternalPreparation(GeneralJournalStorageBinding),
}
pub(crate) struct LiveClearJournal {
    file: File,
    identity: JournalFileIdentity,
    final_path: String,
    file_attributes: u32,
    binding: GeneralJournalStorageBinding,
    profile: JournalProfile,
    source: PartitionOwnerToken,
    location: LiveJournalLocation,
    memory: Option<ArenaRamLease>,
}
impl LiveClearJournal {
    /// Called only while the actual created native J FileObject is held. The
    /// duplicate keeps that exact sharing exclusion; no pathname is reopened.
    pub(crate) fn capture(
        file: &File,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        owner: &PartitionScopedOwner,
        admission: &PartitionNtfsAdmission,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        ensure!(
            !owner.state().source_admission_issued,
            "source gate already issued; no unactivated J capture"
        );
        ensure!(
            profile.version() == 3,
            "live partition cancellation requires actual capacity-pinned J profile"
        );
        n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(owner, admission)?;
        let location = match admission.external_intent_journal() {
            Some(enrolled) => {
                ensure!(enrolled == binding,
                    "actual external preparation intent and held native J enrollment differ");
                LiveJournalLocation::ExternalPreparation(enrolled.clone())
            }
            None => LiveJournalLocation::CurrentWindows,
        };
        let before = observe_general_journal_file_with_profile(file, binding, profile)?;
        Self::require_location(&before, binding, owner, &location)?;
        Self::deny_second_writer(&before.final_path)?;
        let readonly = n2r_win32::file_storage::duplicate_readonly(file)?;
        n2r_win32::file_storage::require_readonly_access(&readonly)?;
        let after = observe_general_journal_file_with_profile(&readonly, binding, profile)?;
        ensure!(
            before.identity == after.identity
                && before.final_path == after.final_path
                && before.file_bytes == after.file_bytes
                && before.file_attributes == after.file_attributes
                && after.number_of_links == 1
                && !owner.state().source_admission_issued,
            "actual created J changed while retaining readonly same-object owner"
        );
        Self::require_location(&after, binding, owner, &location)?;
        Self::record(
            events,
            "live-unactivated-journal-captured",
            serde_json::json!({
            "kind":"actual-live-journal-fileobject-retained","final_path":after.final_path,
            "file_bytes":after.file_bytes,"file_id_128":hex::encode(after.identity.file_id_128),
            "volume_serial_decimal":after.identity.volume_serial_number.to_string(),
            "same_created_fileobject_readonly_duplicate":true,"source_gate_issued":false,
            "saved_receipt_grants_authority":false}),
        )?;
        Ok(Self {
            file: readonly,
            identity: after.identity,
            final_path: after.final_path,
            file_attributes: after.file_attributes,
            binding: binding.clone(),
            profile,
            source: owner.owner_token(),
            location,
            memory: None,
        })
    }
    pub(crate) fn retained_memory_bytes(&self) -> u64 {
        WORKING_MEMORY_BYTES
    }
    pub(crate) fn retain_memory(mut self, mut memory: ArenaRamLease) -> Result<Self> {
        memory.shrink_to(WORKING_MEMORY_BYTES)?;
        self.memory = Some(memory);
        Ok(self)
    }
    /// Positively observe this actual owned J immediately before cancellation.
    /// EOF0 is observed, not inferred from missing files. Otherwise both4KiB
    /// lifecycle slots must exist and be entirely zero; torn/foreign markers
    /// and a partial prefix refuse. The J body is deliberately not scanned.
    pub(crate) fn require_clear(
        &mut self,
        owner: &PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
    ) -> Result<serde_json::Value> {
        ensure!(
            self.memory.is_some(),
            "live J cancellation metadata lacks its actual arena reservation"
        );
        ensure!(
            self.source.same_owner(&owner.owner_token()) && !owner.state().source_admission_issued,
            "live J belongs to another source or a source gate was already issued"
        );
        n2r_win32::file_storage::require_readonly_access(&self.file)?;
        let before =
            observe_general_journal_file_with_profile(&self.file, &self.binding, self.profile)?;
        Self::require_location(&before, &self.binding, owner, &self.location)?;
        self.require_same(&before)?;
        Self::deny_second_writer(&self.final_path)?;
        let position = self.file.stream_position()?;
        let prefix = (|| -> Result<bool> {
            if before.file_bytes == 0 {
                return Ok(false);
            }
            ensure!(
                before.file_bytes >= 8192,
                "actual J lifecycle prefix is incomplete; cancellation refuses"
            );
            let mut bytes = [0u8; 8192];
            ensure!(
                self.file.seek(SeekFrom::Start(0))? == 0,
                "live J lifecycle seek differs"
            );
            self.file.read_exact(&mut bytes)?;
            ensure!(
                bytes.iter().all(|byte| *byte == 0),
                "actual J has AP/RB/HND/ABT or foreign/torn lifecycle bytes"
            );
            Ok(true)
        })();
        let restored = self
            .file
            .seek(SeekFrom::Start(position))
            .map(|actual| actual == position)
            .map_err(anyhow::Error::from)
            .and_then(|same| {
                ensure!(same, "live J shared cursor restore differs");
                Ok(())
            });
        let canonical_zero_prefix = match (prefix, restored) {
            (Ok(value), Ok(())) => value,
            (Err(error), Err(restore)) => {
                return Err(error.context(format!(
                    "same-object J cursor restore also failed: {restore:#}"
                )));
            }
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        let after =
            observe_general_journal_file_with_profile(&self.file, &self.binding, self.profile)?;
        Self::require_location(&after, &self.binding, owner, &self.location)?;
        self.require_same(&after)?;
        ensure!(
            before.identity == after.identity
                && before.file_bytes == after.file_bytes
                && before.allocation_bytes == after.allocation_bytes
                && before.file_attributes == after.file_attributes
                && before.final_path == after.final_path
                && !owner.state().source_admission_issued,
            "actual live J metadata/source gate changed across clear-lifecycle observation"
        );
        let receipt = serde_json::json!({"kind":"actual-live-unactivated-journal-clear",
            "final_path":after.final_path,"file_id_128":hex::encode(after.identity.file_id_128),
            "volume_serial_decimal":after.identity.volume_serial_number.to_string(),
            "current_file_bytes":after.file_bytes,"positively_observed_empty_file":after.file_bytes==0,
            "complete_zero_lifecycle_8192":canonical_zero_prefix,"journal_body_scanned":false,
            "source_gate_issued":false,"shared_file_cursor_restored":true,"saved_receipt_grants_authority":false});
        Self::record(events, "live-unactivated-journal-clear", receipt.clone())?;
        Ok(receipt)
    }
    fn require_same(&self, actual: &JournalFileSnapshot) -> Result<()> {
        ensure!(
            actual.identity == self.identity
                && actual.final_path.eq_ignore_ascii_case(&self.final_path)
                && actual.file_attributes == self.file_attributes
                && actual.number_of_links == 1,
            "same-created-file J native identity/path/ordinary attributes changed"
        );
        Ok(())
    }
    fn require_location(
        actual: &JournalFileSnapshot,
        binding: &GeneralJournalStorageBinding,
        owner: &PartitionScopedOwner,
        location: &LiveJournalLocation,
    ) -> Result<()> {
        let windows = &owner.state().partition.windows_volume;
        let source = &owner.binding().storage;
        let j = &binding.disk;
        match location {
            LiveJournalLocation::CurrentWindows => {
                ensure!(
                    actual.number_of_links == 1
                        && actual.observations_match_before_after
                        && actual.disk_number == windows.disk_number
                        && j.disk_number == windows.disk_number
                        && actual.identity.partition_offset == windows.offset
                        && actual.identity.partition_bytes == windows.length
                        && j.identity.partition_offset == windows.offset
                        && j.identity.partition_bytes == windows.length,
                    "actual J must be an ordinary held file on current Windows C volume"
                );
            }
            LiveJournalLocation::ExternalPreparation(enrolled) => {
                // Each snapshot above has already checked the actual held file,
                // volume extents, native physical GUID/layout/alignment, and
                // complete before/after identity against this exact binding.
                ensure!(enrolled == binding
                    && actual.number_of_links == 1
                    && actual.observations_match_before_after
                    && actual.disk_number == enrolled.disk.disk_number
                    && actual.identity.disk_guid == n2r_win32::layout::guid_bytes(&enrolled.disk.identity.disk_guid)?
                    && actual.identity.partition_guid == n2r_win32::layout::guid_bytes(&enrolled.disk.identity.partition_guid)?
                    && actual.identity.partition_number == enrolled.disk.identity.partition_number
                    && actual.identity.partition_offset == enrolled.disk.identity.partition_offset
                    && actual.identity.partition_bytes == enrolled.disk.identity.partition_bytes
                    && source.disk_number != enrolled.disk.disk_number
                    && n2r_win32::layout::guid_bytes(&source.identity.disk_guid)?
                        != n2r_win32::layout::guid_bytes(&enrolled.disk.identity.disk_guid)?,
                    "actual held J lost the independent external preparation enrollment");
            }
        }
        let source_guid = n2r_win32::layout::guid_bytes(&source.identity.disk_guid)?;
        let journal_guid = n2r_win32::layout::guid_bytes(&j.identity.disk_guid)?;
        ensure!(
            (source.disk_number == j.disk_number) == (source_guid == journal_guid),
            "native source/J physical identity aliases another disk"
        );
        if source.disk_number == j.disk_number {
            let se = source
                .identity
                .partition_offset
                .checked_add(source.identity.partition_bytes)
                .context("source extent overflow")?;
            let je = actual
                .identity
                .partition_offset
                .checked_add(actual.identity.partition_bytes)
                .context("actual J extent overflow")?;
            ensure!(
                source.identity.disk_bytes == actual.identity.disk_bytes
                    && source.identity.logical_sector_bytes == actual.identity.logical_sector_bytes
                    && source.identity.physical_sector_bytes
                        == actual.identity.physical_sector_bytes
                    && (se <= actual.identity.partition_offset
                        || je <= source.identity.partition_offset),
                "actual Windows J extent overlaps or differs from selected source disk"
            );
        }
        Ok(())
    }
    fn deny_second_writer(path: &str) -> Result<()> {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(path)
        {
            Err(error) if error.raw_os_error() == Some(32) => Ok(()),
            Err(error) => Err(error).context("live J original sharing exclusion is unknown"),
            Ok(contender) => {
                drop(contender);
                anyhow::bail!("actual held J permits another ordinary RW writer")
            }
        }
    }
    fn record(
        events: &mut Vec<NativeEvent>,
        operation: &str,
        value: serde_json::Value,
    ) -> Result<()> {
        ensure!(
            events.len() < n2r_win32::MAX_BATCH_EVENTS,
            "live J cancellation native event budget exhausted"
        );
        let output = serde_json::to_vec(&value)?;
        ensure!(
            output.len() <= 65536,
            "live J cancellation receipt exceeds fixed metadata budget"
        );
        events.push(NativeEvent {
            operation: operation.into(),
            control_code: 0,
            input: Vec::new(),
            succeeded: true,
            native_error: None,
            output,
        });
        Ok(())
    }
}
