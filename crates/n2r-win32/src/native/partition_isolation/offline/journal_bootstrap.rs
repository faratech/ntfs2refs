//! Boot-bound independent journal enrollment. Only the independently observed
//! J disk becomes available. Source BASIC+READONLY protects its filesystem until
//! the prepared-source owner acquires actual locks and whole-disk exclusion.
use super::*;
use crate::native::partition_lifecycle::PartitionPreparationObserver;

impl OfflineOwningEnvironment {
    pub fn open_independent_journal_for_recovery(
        &mut self,
        journal: &GeneralJournalStorageBinding,
        ram_bootstrap: &mut File,
        observer: &mut impl PartitionPreparationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<File> {
        observer.checkpoint("offline-J-bootstrap-opening", events)?;
        self.require_current(events)?;
        journal.validate()?;
        require_bootstrap_route(self, journal, ram_bootstrap)?;
        require_bootstrap_source_protection(self)?;
        require(
            journal.disk.disk_number != self.source.storage.disk_number
                && layout::guid_bytes(&journal.disk.identity.disk_guid)?
                    != layout::guid_bytes(&self.source.storage.identity.disk_guid)?,
            "recovery bootstrap J must be a distinct native physical disk",
        )?;
        let binding = PartitionSourceBinding {
            storage: journal.disk.clone(),
        };
        let mut disk = device_file(
            &format!("\\\\.\\PhysicalDrive{}", journal.disk.disk_number),
            true,
            false,
        )?;
        let before = source_facts(&mut disk, &binding, self.budget, events)?;
        let offset = before
            .gpt
            .target_slot
            .checked_sub(1)
            .and_then(|n| n.checked_mul(before.gpt.entry_bytes))
            .ok_or_else(|| invalid("journal GPT slot overflow"))? as usize;
        require(
            before.gpt.entries.get(offset..offset + 16)
                == Some(layout::guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?.as_slice())
                && before.gpt.target_attributes == 0
                && matches!(before.disk_attributes, 0 | 1 | 3),
            "journal bootstrap requires actual basic writable GPT and expected SAN attributes",
        )?;
        let repeat = source_facts(&mut disk, &binding, self.budget, events)?;
        require(
            before == repeat,
            "actual independent J physical identity changed before availability",
        )?;
        events.push(bootstrap_event(&journal.disk, &before)?);
        observer.checkpoint(
            "offline-J-bootstrap-before-independent-availability",
            events,
        )?;
        self.require_current(events)?;
        require_bootstrap_route(self, journal, ram_bootstrap)?;
        if before.disk_attributes != 0 {
            crate::native::set_attributes(&disk, 0, events)?;
        }
        let after = source_facts(&mut disk, &binding, self.budget, events)?;
        require(
            after.disk_attributes == 0
                && after.device == before.device
                && after.length == before.length
                && after.alignment == before.alignment
                && after.gpt == before.gpt,
            "journal availability changed native identity/GPT unexpectedly",
        )?;
        self.require_current(events)?;
        observer.checkpoint(
            "offline-J-bootstrap-independent-availability-complete",
            events,
        )?;
        let volume = device_file(&journal.disk.volume_path()?, true, false)?;
        self.require_journal_disjoint(journal, &volume, events)?;
        self.require_current(events)?;
        observer.checkpoint("offline-J-bootstrap-held-volume-enrolled", events)?;
        Ok(volume)
    }
}

fn require_bootstrap_source_protection(environment: &OfflineOwningEnvironment) -> io::Result<()> {
    let actual = &environment.facts.source_physical;
    const BASIC_READONLY: u64 = 0x1000_0000_0000_0000;
    require(
        matches!(actual.disk_attributes, 0 | 1 | 3)
            && actual.gpt.target_attributes == BASIC_READONLY,
        "J bootstrap requires actual source BASIC+READONLY and supported disk attributes",
    )?;
    let guid = layout::guid_bytes(&environment.source.storage.identity.partition_guid)?;
    let rows: Vec<_> = actual
        .gpt
        .native_layout
        .get(48..)
        .ok_or_else(|| invalid("J bootstrap source native layout is truncated"))?
        .chunks_exact(144)
        .filter(|row| row[48..64] == guid)
        .collect();
    require(
        rows.len() == 1
            && rows[0][32..48]
                == layout::guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?
            && layout::u64_at(rows[0], 64)? == BASIC_READONLY,
        "J bootstrap source native partition row does not prove BASIC+READONLY",
    )?;
    // SAN3 can leave an existing/system disk online. This authorizes only
    // disjoint J metadata availability, never source I/O or source writes.
    // PreparedClear still needs actual volume LOCK/DISMOUNT -> durable intent
    // -> whole-disk3 before its opaque source/J/writer qualification. AP/RB
    // reopening retains its stricter already-offline requirement.
    Ok(())
}

fn require_bootstrap_route(
    environment: &OfflineOwningEnvironment,
    journal: &GeneralJournalStorageBinding,
    file: &mut File,
) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    crate::file_storage::require_readonly_access(file)?;
    let expected_path = format!(
        "{}\\System32\\n2r-bootstrap.json",
        environment.facts.windows_directory.trim_end_matches('\\')
    );
    let (ram, _) =
        crate::native::offline_environment::kernel_ram_backing::require_file(&expected_path, file)?;
    require(
        ram.dos_root == environment.facts.windows_ram_root,
        "actual held bootstrap is not on the current RAM Windows volume",
    )?;
    let length = file.metadata()?.len();
    require(
        length > 0 && length <= environment.budget.ram_bytes / 64,
        "RAM bootstrap exceeds prepaid decoding memory",
    )?;
    let expected = crate::native::recovery_boot::current_recovery_bootstrap_sha256()?;
    require(
        crate::sha256_native::hash_range(file, 0, length)? == expected,
        "actual RAM bootstrap differs from native current boot selection",
    )?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(io::Error::other)?;
    file.take(length + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 == length && <[u8; 32]>::from(Sha256::digest(&bytes)) == expected,
        "same held RAM bootstrap changed during routing read",
    )?;
    #[derive(Deserialize)]
    struct Routing {
        schema_version: u32,
        source: PartitionSourceBinding,
        journal: GeneralJournalStorageBinding,
    }
    let route: Routing = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    require(
        route.schema_version == 1
            && route.source == environment.source
            && route.journal == *journal,
        "current boot-bound bootstrap does not authorize this metadata-only independent J route",
    )
}

fn bootstrap_event(
    binding: &crate::general_layout::GeneralDiskBinding,
    before: &OfflineSourcePhysicalFacts,
) -> io::Result<NativeEvent> {
    // Reuse the native event's ordinary serialized observation shape rather
    // than treating a saved intent as permission on a later boot.
    let value = serde_json::json!({"kind":"actual-independent-J-availability-intent",
        "journal":binding,"actual_before":before,"desired_disk_attributes":0,
        "source_setters":0,"source_data_writers":0,"saved_record_grants_authority":false});
    Ok(NativeEvent {
        operation: "offline-J-bootstrap-intent".into(),
        control_code: 0,
        input: Vec::new(),
        succeeded: true,
        native_error: None,
        output: serde_json::to_vec(&value).map_err(io::Error::other)?,
    })
}
