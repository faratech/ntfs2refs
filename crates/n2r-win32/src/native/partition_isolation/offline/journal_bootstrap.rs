//! Boot-bound independent journal enrollment. Only the independently observed
//! J disk becomes available. Source BASIC+READONLY protects its filesystem until
//! the prepared-source owner acquires actual locks and whole-disk exclusion.
use super::*;
use crate::native::partition_lifecycle::PartitionPreparationObserver;

impl OfflineOwningEnvironment {
    /// Resolve only a current ordinary drive-letter alias of the already held
    /// native J directory. This is routing, never source or artifact authority.
    pub fn ordinary_journal_directory(
        &mut self,
        journal: &GeneralJournalStorageBinding,
        journal_volume: &File,
        directory: &File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<std::path::PathBuf> {
        use std::{os::windows::fs::MetadataExt, path::{Component, Path, PathBuf}};
        self.require_journal_disjoint(journal, journal_volume, events)?;
        let metadata = directory.metadata()?;
        require(metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "current J output parent must be an actual ordinary directory")?;
        let identity = crate::file_storage::file_id_info(directory)?;
        let guid_path = crate::file_storage::final_path_guid(directory)?;
        let prefix = format!("{}\\", journal.disk.volume_path()?.trim_end_matches('\\'));
        require(guid_path.get(..prefix.len()).is_some_and(|s| s.eq_ignore_ascii_case(&prefix)),
            "actual output parent is not on held native J")?;
        let relative = Path::new(&guid_path[prefix.len()..]);
        require(!relative.as_os_str().is_empty(), "J output parent cannot be the volume root")?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(invalid("J output suffix contains a non-normal component"));
            };
            let name = name.to_str().ok_or_else(|| invalid("Unicode J output component required"))?;
            let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
            require(!name.is_empty() && !name.ends_with([' ', '.'])
                && !name.chars().any(|c| c.is_control() || matches!(c, ':'|'/'|'\\'|'"'|'<'|'>'|'|'|'?'|'*'))
                && !matches!(stem.as_str(), "CON"|"PRN"|"AUX"|"NUL")
                && !((stem.starts_with("COM") || stem.starts_with("LPT"))
                    && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit()),
                "J output suffix is not an unambiguous ordinary component")?;
        }
        // Existing bounded Mount Manager enumeration independently reverse-
        // resolves every returned alias to this exact native volume GUID.
        let mounts = crate::native::capture_mount_paths_for_bound_volume(journal.disk.clone())?;
        require(mounts.all_paths_resolve_to_bound_volume && mounts.binding == journal.disk,
            "current J mount-route observation differs from held native owner")?;
        let mut drives: Vec<_> = mounts.paths.iter().filter(|path| {
            let bytes = path.as_bytes();
            bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1..] == *b":\\"
        }).collect();
        drives.sort_by_key(|path| path.to_ascii_uppercase());
        let drive = drives.first().ok_or_else(|| invalid("held J has no current ordinary drive-letter alias"))?;
        let candidate = PathBuf::from(drive.as_str()).join(relative);
        let mapped = OpenOptions::new().access_mode(0x80).share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000).open(&candidate)?;
        let mapped_meta = mapped.metadata()?;
        require(mapped_meta.is_dir() && mapped_meta.file_attributes() & 0x400 == 0
            && crate::file_storage::file_id_info(&mapped)? == identity
            && crate::file_storage::final_path_guid(&mapped)?.eq_ignore_ascii_case(&guid_path),
            "ordinary J output alias is not the same held directory identity/GUID")?;
        self.require_journal_disjoint(journal, journal_volume, events)?;
        require(crate::file_storage::file_id_info(directory)? == identity
            && crate::file_storage::file_id_info(&mapped)? == identity
            && crate::file_storage::final_path_guid(directory)?.eq_ignore_ascii_case(&guid_path),
            "held J output directory changed during ordinary alias resolution")?;
        events.push(NativeEvent {
            operation:"offline-current-J-ordinary-output-alias-bound".into(),
            control_code:0,input:Vec::new(),succeeded:true,native_error:None,
            output:serde_json::to_vec(&serde_json::json!({
                "actual_guid_directory":guid_path,"current_ordinary_directory":candidate,
                "native_parent_file_id_and_volume_serial_equal":true,
                "all_mount_aliases_reverse_resolve_to_native_J":true,
                "sealed_GUID_inputs_changed":false,"source_write_authority":false,
            })).map_err(io::Error::other)?,
        });
        Ok(candidate)
    }
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
