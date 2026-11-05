//! Cold prepared source: genuine PE exclusion/read + clear/allOLD journal proof.
//! NEVER OfflineFrozenSource/fresh PE native witness. No writer is exposed here.
use super::*;
use crate::native::{
    HeldPagedWritePolicy,
    paged_recovery::{self, OwnedPartitionJournalPins, PagedRecoveryPins, PartitionJournalPhase},
};
use sha2::{Digest, Sha256};
use std::os::windows::io::AsRawHandle;
const SOURCE_READONLY: u64 = 0x1000_0000_0000_0000;
fn metadata_pin(g: &super::super::PartitionGptObservation) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&g.primary_header);
    h.update(&g.entries);
    h.update(&g.backup_header);
    h.update(&g.native_layout);
    h.finalize().into()
}

/// Opaque actual cold prepared holder. The Core is explicitly NOT fresh, and
/// has NO live PE/preboot native observation. It cannot call FreshPE gates.
pub struct OfflinePreparedSource {
    pub(super) core: Core,
    pub(super) source_readonly_gpt_sha256: [u8; 32],
    basic_readonly_info: Vec<u8>,
    actual_current_boot_volume_locks_acquired: bool,
    pub(super) source_was_already_offline_on_enrollment: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct OfflinePreparedBootGuardRequirements {
    pub kind: &'static str,
    pub source: PartitionSourceBinding,
    pub current_boot: OfflineBootIdentity,
    pub prepared_readonly_gpt_sha256: [u8; 32],
    pub actual_excluded_disk_attributes: u64,
    pub source_was_already_offline_on_enrollment: bool,
    pub journal_identity: crate::journal_file::JournalFileIdentity,
    pub journal_path: String,
    pub journal_immutable_sha256: [u8; 32],
    pub index_sha256: [u8; 32],
    pub old_selected_sha256: [u8; 32],
    pub selected_bytes: u64,
    pub range_count: u32,
    pub lifecycle_prefix_sha256: [u8; 32],
    pub sealed_publication_sha256: [u8; 32],
    pub sealed_publication_file: crate::reference_file::ReferenceFileSnapshot,
    pub requires_actual_Root_sealed_publication_authentication: bool,
    pub requires_actual_durable_boot_guard_before_writer: bool,
    pub facts_grant_write_authority: bool,
}
/// Read/current-J qualification ONLY. No Clone/Deserialize/into-writer exists.
/// Root's actual BootGuard handoff is a separate mandatory consuming protocol.
pub struct OfflinePreparedJournalQualification {
    owner: OfflineSourceOwnerToken,
    boot: OfflineBootIdentity,
    binding: PartitionSourceBinding,
    pins: OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    journal_file_object: usize,
    lifecycle_sha256: [u8; 32],
    requirements: OfflinePreparedBootGuardRequirements,
}
impl OfflinePreparedJournalQualification {
    pub fn boot_guard_requirements(&self) -> &OfflinePreparedBootGuardRequirements {
        &self.requirements
    }
    pub fn require_owner(&self, t: &OfflineSourceOwnerToken) -> io::Result<()> {
        require(
            self.owner.same_owner(t),
            "prepared J qualification belongs to another actual owner",
        )
    }
    // Terminal binding only: no stale original source-byte check after AP.
    pub(super) fn require_terminal_binding(&self,source:&OfflinePreparedSource,
        pins:&PagedRecoveryPins<'_>)->io::Result<()> {
        self.require_owner(&source.owner_token())?;
        self.pins.require(pins)?;
        require(self.boot==source.core.env.facts.boot&&self.binding==*source.binding(),
            "prepared terminal lost original actual owner/boot/J binding")
    }
    pub fn revalidate(
        &self,
        source: &mut OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        sealed_publication: &mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.require_owner(&source.owner_token())?;
        self.pins.require(pins)?;
        require(
            self.boot == source.core.env.facts.boot
                && self.binding == *source.binding()
                && self.index_sha256 == policy.facts()?.index_sha256
                && self.journal_file_object == journal.as_raw_handle() as usize,
            "prepared same-epoch source/J/index binding changed",
        )?;
        source.require_sealed_publication(
            sealed_publication,
            self.requirements.sealed_publication_sha256,
            pins,
            Some(&self.requirements.sealed_publication_file),
        )?;
        source.authenticate_clear_old(policy, journal, pins, events)?;
        require(
            prefix_digest(journal)? == self.lifecycle_sha256,
            "PreparedClear lifecycle changed after qualification",
        )
    }
}
fn prefix_digest(j: &mut File) -> io::Result<[u8; 32]> {
    let pos = j.stream_position()?;
    let result = crate::sha256_native::hash_range(j, 0, 8192);
    let restored = j.seek(SeekFrom::Start(pos));
    match (result, restored) {
        (Ok(h), Ok(n)) if n == pos => Ok(h),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Err(invalid("J cursor restore differs")),
    }
}
struct PreparedReader<'a>(&'a mut Core);
impl Read for PreparedReader<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl Seek for PreparedReader<'_> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.0.seek(p)
    }
}
impl OfflinePreparedSource {
    /// Actual BASICRO/fullGPT must equal independently pinned Windows-prepared
    /// state before any source FSD/data open. Pin alone is NOT writer authority.
    pub fn exclude(
        mut env: OfflineOwningEnvironment,
        expected_readonly_gpt_sha256: [u8; 32],
        journal: &GeneralJournalStorageBinding,
        journal_volume: &File,
        exclusion_intent: File,
        observer: Box<dyn PartitionPreparationObserver>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        require_owner_budget(env.budget)?;
        let sink = PartitionNativeEventSink::new(observer);
        checkpoint(&sink, "offline-PREPARED-exclusion-opening", events)?;
        require(
            journal.disk.disk_number != env.source.storage.disk_number
                && layout::guid_bytes(&journal.disk.identity.disk_guid)?
                    != layout::guid_bytes(&env.source.storage.identity.disk_guid)?,
            "cold prepared exclusion requires an independent physical journal disk",
        )?;
        env.require_current(events)?;
        env.require_journal_disjoint(journal, journal_volume, events)?;
        let enrolled_attributes = env.facts.source_physical.disk_attributes;
        require(
            matches!(enrolled_attributes, 0 | 1 | 3)
                && env.facts.source_physical.gpt.target_attributes == SOURCE_READONLY
                && metadata_pin(&env.facts.source_physical.gpt) == expected_readonly_gpt_sha256,
            "cold prepared source is not actual pinned BASICRO/fullGPT with supported disk0/1/3 state",
        )?;
        let guid = layout::guid_bytes(&env.source.storage.identity.partition_guid)?;
        let rows: Vec<_> = env.facts.source_physical.gpt.native_layout[48..]
            .chunks_exact(144)
            .filter(|r| r[48..64] == guid)
            .collect();
        require(
            rows.len() == 1
                && rows[0][32..48] == layout::guid_bytes(BASIC)?
                && layout::u64_at(rows[0], 64)? == SOURCE_READONLY,
            "actual cold source native row is not BASICRO",
        )?;
        let basic_readonly_info = rows[0].to_vec();
        checkpoint(
            &sink,
            "offline-PREPARED-source-and-independent-J-native-bound",
            events,
        )?;
        // NO fresh NTFS/TxF/VSS collection and NO fabricated preboot witness.
        // SAN3-cold source is ALREADY offline1/3. Do not open any source
        // volume/FSD or pretend to inherit a prior Windows/PE filesystem lock.
        let locked = if enrolled_attributes == 0 {
            lock_source_volumes(&mut env, &sink, events)?
        } else {
            Vec::new()
        };
        let actual_current_boot_volume_locks_acquired = enrolled_attributes == 0;
        env.require_current(events)?;
        checkpoint(
            &sink,
            if enrolled_attributes == 0 {
                "offline-PREPARED-current-volume-locks-held"
            } else {
                "offline-PREPARED-actual-ALREADY-OFFLINE-no-volume-open"
            },
            events,
        )?;
        let intent = HeldIntent::persist(exclusion_intent, &env, journal, 3)?;
        checkpoint(&sink, "offline-PREPARED-exclusion-intent-durable", events)?;
        let mut management = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                env.source.storage.disk_number
            ))?;
        require(
            source_facts(&mut management, &env.source, env.budget, events)?
                == env.facts.source_physical,
            "actual prepared exclusion management handle lost full native binding",
        )?;
        if enrolled_attributes != 3 {
            set_attributes(&management, 3, events)?;
        }
        env.require_current_at_attributes(3, events)?;
        checkpoint(&sink, "offline-PREPARED-actual-whole-disk3", events)?;
        for volume in locked {
            close_file(
                volume,
                "offline-PREPARED-real-volume-lock-close-ONLY-after-disk3",
                events,
            )?;
        }
        close_file(management, "offline-PREPARED-management-close", events)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                env.source.storage.disk_number
            ))?;
        let mut source = Self {
            core: Core {
                env,
                file,
                expected_attributes: 3,
                position: 0,
                buffer: AlignedBuffer::new()?,
                token: OfflineSourceOwnerToken(Arc::new(())),
                poisoned: false,
                fresh: false,
                gate_ever_issued: false,
                writer_ever_issued: false,
                fresh_witness: None,
                native_read_bytes_requested: 0,
                native_read_bytes_succeeded: 0,
                native_read_error_count: 0,
                native_read_short_count: 0,
                intent: Some(intent),
                sink,
            },
            source_readonly_gpt_sha256: expected_readonly_gpt_sha256,
            basic_readonly_info,
            actual_current_boot_volume_locks_acquired,
            source_was_already_offline_on_enrollment: matches!(enrolled_attributes, 1 | 3),
        };
        source.state(events)?;
        Ok(source)
    }
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.core.env.source
    }
    pub fn offline_environment_facts(&self) -> &OfflineOwningFacts {
        self.core.env.facts()
    }
    pub fn byte_len(&self) -> u64 {
        self.core.env.source.storage.identity.partition_bytes
    }
    pub fn owner_token(&self) -> OfflineSourceOwnerToken {
        self.core.token.clone()
    }
    pub fn preparation_pin(&self) -> &OfflineSourceIntentPin {
        &self
            .core
            .intent
            .as_ref()
            .expect("prepared owner holds actual exclusion intent")
            .pin
    }
    pub fn basic_readonly_partition_info(&self) -> &[u8] {
        &self.basic_readonly_info
    }
    pub fn state(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<OfflineSourceState> {
        let mut state = self.core.state(events)?;
        require(
            (state.actual.disk_attributes == 3 || (state.actual.disk_attributes == 1 && self.core.gate_ever_issued && self.core.writer_ever_issued))
                && state.actual.gpt.target_attributes == SOURCE_READONLY
                && metadata_pin(&state.actual.gpt) == self.source_readonly_gpt_sha256,
            "prepared current exclusion/native enrollment changed",
        )?;
        state.mode = "cold-Windows-sealed-prepared-current-PE-excluded";
        state.original_live_volume_locks_acquired = self.actual_current_boot_volume_locks_acquired;
        Ok(state)
    }
    fn authenticate_clear_old(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.state(events)?;
        pins.journal_binding.validate()?;
        require(
            self.binding().storage.disk_number != pins.journal_binding.disk.disk_number
                && layout::guid_bytes(&self.binding().storage.identity.disk_guid)?
                    != layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?,
            "prepared J must be on independent physical disk",
        )?;
        let binding = self.binding().clone();
        let length = self.byte_len();
        let checked = paged_recovery::authenticate_scoped_partition_reader(
            &mut PreparedReader(&mut self.core),
            length,
            &binding,
            policy,
            journal,
            pins,
            PartitionJournalPhase::FreshOld,
        );
        let closing = self.state(events);
        match (checked, closing) {
            (Ok(None), Ok(_)) => Ok(()),
            (Ok(Some(_)), _) => Err(invalid("clear/allOLD checker returned mixed state")),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }
    pub(super) fn require_sealed_publication(
        &self,
        file: &mut File,
        pin: [u8; 32],
        pins: &PagedRecoveryPins<'_>,
        expected: Option<&crate::reference_file::ReferenceFileSnapshot>,
    ) -> io::Result<crate::reference_file::ReferenceFileSnapshot> {
        crate::file_storage::require_readonly_access(file)?;
        let maximum = self.core.env.budget.ram_bytes / 8;
        let before =
            crate::reference_file::observe_reference_file_handle_with_limit(file, maximum)?;
        require(
            before.file_bytes > 0 && before.file_bytes <= maximum && before.number_of_links == 1,
            "actual bounded ordinary sealed publication required",
        )?;
        let prefix = format!(
            "{}\\",
            pins.journal_binding
                .disk
                .volume_path()?
                .trim_end_matches('\\')
        );
        require(
            before
                .final_path
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
                && before.volume_serial_number == pins.journal_identity.volume_serial_number,
            "actual held prepared publication not on native J volume",
        )?;
        if let Some(expected) = expected {
            require(
                &before == expected,
                "same held sealed publication native identity changed",
            )?;
        }
        require(
            crate::sha256_native::hash_range(file, 0, before.file_bytes)? == pin
                && crate::reference_file::observe_reference_file_handle_with_limit(file, maximum)?
                    == before,
            "actual sealed publication SHA/native identity changed",
        )?;
        Ok(before)
    }
    /// Read-only qualification; source data remains READONLY and no AP is
    /// published. Root must authenticate semantic outer bundle/artifacts too.
    pub fn qualify_prepared_journal(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        sealed_publication: &mut File,
        independent_outer_sha256: [u8; 32],
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePreparedJournalQualification> {
        require(
            !self.core.gate_ever_issued && !self.core.writer_ever_issued && !self.core.poisoned,
            "cold prepared owner was already activated",
        )?;
        checkpoint(
            &self.core.sink,
            "offline-PREPARED-clear-OLD-qualification-opening",
            events,
        )?;
        let publication = self.require_sealed_publication(
            sealed_publication,
            independent_outer_sha256,
            pins,
            None,
        )?;
        self.authenticate_clear_old(policy, journal, pins, events)?;
        let prefix = prefix_digest(journal)?;
        let facts = policy.facts()?;
        let requirements = OfflinePreparedBootGuardRequirements {
            kind: "actual-cold-prepared-boot-guard-requirements-v1",
            source: self.binding().clone(),
            current_boot: self.core.env.facts.boot.clone(),
            prepared_readonly_gpt_sha256: self.source_readonly_gpt_sha256,
            actual_excluded_disk_attributes: 3,
            source_was_already_offline_on_enrollment: self.source_was_already_offline_on_enrollment,
            journal_identity: pins.journal_identity.clone(),
            journal_path: pins.journal_path.to_string_lossy().into_owned(),
            journal_immutable_sha256: pins.immutable_sha256,
            index_sha256: facts.index_sha256,
            old_selected_sha256: pins.old_selected_sha256,
            selected_bytes: facts.selected_bytes,
            range_count: facts.range_count,
            lifecycle_prefix_sha256: prefix,
            sealed_publication_sha256: independent_outer_sha256,
            sealed_publication_file: publication,
            requires_actual_Root_sealed_publication_authentication: true,
            requires_actual_durable_boot_guard_before_writer: true,
            facts_grant_write_authority: false,
        };
        let qualified = OfflinePreparedJournalQualification {
            owner: self.owner_token(),
            boot: self.core.env.facts.boot.clone(),
            binding: self.binding().clone(),
            pins: OwnedPartitionJournalPins::capture(pins),
            index_sha256: facts.index_sha256,
            journal_file_object: journal.as_raw_handle() as usize,
            lifecycle_sha256: prefix,
            requirements,
        };
        checkpoint(
            &self.core.sink,
            "offline-PREPARED-clear-OLD-qualification-complete",
            events,
        )?;
        Ok(qualified)
    }
}
impl Read for OfflinePreparedSource {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.core.read(b)
    }
}
impl Seek for OfflinePreparedSource {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.core.seek(p)
    }
}
