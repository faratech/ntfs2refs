//! The way back for a source partition that was made read-only (BASIC with
//! the GPT read-only attribute) for a restart conversion that never started.
//!
//! Why this is sound where `PartitionTerminalRestorationGuard::cancel_pre_ap`
//! refuses: that refusal is about the private-partition protocol, whose
//! source NTFS could still change after a restart, so that nothing saved
//! proved it was the original. Here the partition has been write-protected
//! by its GPT attribute since the record this module reads was made, Windows
//! mounts it read-only, and the only writer of the route is the recovery
//! runner, which makes its apply marker durable in the journal before the
//! disk is made writable. The caller proves from the journal that no such
//! marker exists; this module proves the rest from the disk: the partition is
//! exactly the recorded original with the read-only attribute set, the GPT is
//! the recorded one in every other byte, and the protective MBR and the NTFS
//! boot sector are the recorded ones. It then changes one thing, the
//! attribute, back to the recorded value, and checks the result. It never
//! writes to the partition's contents and has no handle that could.
use super::*;
use std::time::{Duration, Instant};

/// A preparation appends at most this many records to its intent file.
const INTENT_FRAMES: u64 = 4;
const PROTECT_KIND: &str = "partition-target-only-pre-AP-intent";
const HANDOFF_KIND: &str = "partition-readonly-physical-pre-AP-intent-v2";

/// What the partition's GPT entry is now, of the two states this way back
/// knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedSourceProtection {
    /// The original entry with the read-only attribute: as the run left it.
    Protected,
    /// The original entry: already given back, or never protected.
    Original,
}

/// What a run recorded of its source before it made it read-only, read from
/// the run's intent file. Routing and comparison values only: every one of
/// them is checked against the disk before anything is changed.
pub struct PreparedSourceOrigin {
    binding: PartitionSourceBinding,
    original_info: Vec<u8>,
    protected_info: Vec<u8>,
    original_gpt: Value,
    original_mbr: Vec<u8>,
    ntfs_primary_sha256: [u8; 32],
    frames: u64,
    intent_bytes: u64,
    intent_sha256: [u8; 32],
}
impl PreparedSourceOrigin {
    /// Reads every record of a held intent file. Each record carries its own
    /// length and SHA-256; all of them must name `binding` and the same
    /// original, and none may say that an apply was issued.
    pub fn read(
        intent: &mut File,
        binding: &PartitionSourceBinding,
        ram_bytes: u64,
    ) -> io::Result<Self> {
        binding.validate()?;
        let length = intent.metadata()?.len();
        need(
            length <= MAX_INTENT,
            &format!("the intent file is {length} bytes, more than a preparation writes"),
        )?;
        need(
            length > 0,
            "the intent file holds no record: this run never made the partition read-only",
        )?;
        let expected_binding = serde_json::to_value(binding).map_err(io::Error::other)?;
        intent.seek(SeekFrom::Start(0))?;
        let mut whole = Sha256::new();
        let (mut consumed, mut sequence) = (0u64, 0u64);
        let mut first: Option<Value> = None;
        let mut latest: Option<Value> = None;
        while consumed < length {
            let mut head = [0u8; 40];
            need(
                length - consumed >= 40,
                &format!(
                    "the intent file ends inside the header of record {}: its last write was cut short",
                    sequence + 1
                ),
            )?;
            intent.read_exact(&mut head)?;
            let n = u64::from_le_bytes(head[..8].try_into().map_err(io::Error::other)?);
            need(
                n > 0 && n <= MAX_JSON && n.checked_mul(32).is_some_and(|n| n <= ram_bytes),
                &format!(
                    "record {} of the intent file claims {n} bytes, outside what a preparation writes or this run may hold",
                    sequence + 1
                ),
            )?;
            need(
                consumed + 40 + n <= length,
                &format!(
                    "the intent file ends inside record {}: its last write was cut short",
                    sequence + 1
                ),
            )?;
            let mut body = vec![0; n as usize];
            intent.read_exact(&mut body)?;
            need(
                sha(&body) == head[8..40],
                &format!(
                    "record {} of the intent file does not have the SHA-256 written with it",
                    sequence + 1
                ),
            )?;
            whole.update(head);
            whole.update(&body);
            let frame: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
            sequence += 1;
            need(
                sequence <= INTENT_FRAMES && num_field(&frame, "sequence")? == sequence,
                &format!("record {sequence} of the intent file is out of sequence"),
            )?;
            let known = match (num_field(&frame, "version")?, str_field(&frame, "kind")?) {
                (1, PROTECT_KIND) => true,
                (2, HANDOFF_KIND) => sequence == 2,
                _ => false,
            };
            need(
                known,
                &format!(
                    "record {sequence} of the intent file is of a kind this way back does not know"
                ),
            )?;
            need(
                frame["binding"] == expected_binding,
                &format!(
                    "record {sequence} of the intent file names another partition than this run's"
                ),
            )?;
            need(
                frame["source_AP_issued"] == Value::Bool(false),
                &format!(
                    "record {sequence} of the intent file does not say that no apply was issued"
                ),
            )?;
            if let Some(first) = &first {
                need(
                    frame["original_partition_info"] == first["original_partition_info"]
                        && frame["original_gpt"] == first["original_gpt"]
                        && frame["original_mbr"] == first["original_mbr"]
                        && frame["ntfs_primary_sha256"] == first["ntfs_primary_sha256"],
                    &format!(
                        "record {sequence} of the intent file names another original than record 1"
                    ),
                )?;
            } else {
                first = Some(frame.clone());
            }
            latest = Some(frame);
            consumed += 40 + n;
        }
        let frame = latest.ok_or_else(|| bad("the intent file holds no complete record"))?;
        let original_info = json_bytes(&frame["original_partition_info"])?;
        need(
            original_info.len() == 144
                && original_info[32..48] == crate::layout::guid_bytes(BASIC)?
                && crate::layout::u64_at(&original_info, 64)? == 0
                && original_info[48..64]
                    == crate::layout::guid_bytes(&binding.storage.identity.partition_guid)?
                && crate::layout::u64_at(&original_info, 8)?
                    == binding.storage.identity.partition_offset
                && crate::layout::u64_at(&original_info, 16)?
                    == binding.storage.identity.partition_bytes,
            "the recorded original partition is not this run's basic data partition without attributes",
        )?;
        let mut protected_info = original_info.clone();
        protected_info[64..72].copy_from_slice(&RO.to_le_bytes());
        // Every record this route writes asks for the read-only entry, or
        // (a cancellation the run began itself) for the original one. A
        // record that asks for anything else belongs to another protocol.
        intent.seek(SeekFrom::Start(0))?;
        let desired = json_bytes(&frame["desired_partition_info"])?;
        need(
            desired == protected_info || desired == original_info,
            "the last record of the intent file asks for a partition state that is neither read-only nor the original: this run used another protocol",
        )?;
        let original_gpt = frame["original_gpt"].clone();
        need(
            original_gpt.is_object(),
            "the recorded original GPT is absent",
        )?;
        let original_mbr = json_bytes(&frame["original_mbr"])?;
        need(
            original_mbr.len() == 512,
            "the recorded original first sector of the disk is not 512 bytes",
        )?;
        Ok(Self {
            binding: binding.clone(),
            original_info,
            protected_info,
            original_gpt,
            original_mbr,
            ntfs_primary_sha256: digest(&frame, "ntfs_primary_sha256")?,
            frames: sequence,
            intent_bytes: length,
            intent_sha256: whole.finalize().into(),
        })
    }
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.binding
    }
    /// The 144 bytes Windows reported for the partition before the run.
    pub fn original_partition_info(&self) -> &[u8] {
        &self.original_info
    }
    /// The same with the read-only attribute: what the run left.
    pub fn protected_partition_info(&self) -> &[u8] {
        &self.protected_info
    }
    pub fn original_attributes(&self) -> u64 {
        crate::layout::u64_at(&self.original_info, 64).unwrap_or(0)
    }
    pub fn ntfs_primary_sha256(&self) -> [u8; 32] {
        self.ntfs_primary_sha256
    }
    /// SHA-256 of the recorded original GPT (headers, entries, native layout).
    pub fn original_gpt_sha256(&self) -> io::Result<[u8; 32]> {
        original_gpt_sha256(&self.original_gpt)
    }
    pub fn records(&self) -> u64 {
        self.frames
    }
    pub fn intent_bytes(&self) -> u64 {
        self.intent_bytes
    }
    /// SHA-256 of the whole intent file as read.
    pub fn intent_sha256(&self) -> [u8; 32] {
        self.intent_sha256
    }
    /// Which of the two known states these 144 bytes of the partition are.
    pub fn classify(&self, current: &[u8]) -> io::Result<PreparedSourceProtection> {
        if current == self.protected_info.as_slice() {
            Ok(PreparedSourceProtection::Protected)
        } else if current == self.original_info.as_slice() {
            Ok(PreparedSourceProtection::Original)
        } else {
            let (kind, attributes) = if current.len() == 144 {
                (
                    hex::encode(&current[32..48]),
                    crate::layout::u64_at(current, 64)?,
                )
            } else {
                ("unknown".to_owned(), 0)
            };
            Err(bad(&format!(
                "partition {} of disk {} is neither as this run recorded it nor as it left it: its type is {kind} and its attributes are {attributes:#x} (recorded: basic data, {:#x}; left: basic data, {RO:#x}), or its name, identifier or place changed",
                self.binding.storage.identity.partition_number,
                self.binding.storage.disk_number,
                self.original_attributes(),
            )))
        }
    }
    /// The disk's GPT is the recorded one with the partition in `state`.
    pub(in crate::native) fn require_gpt(
        &self,
        state: PreparedSourceProtection,
        actual: &partition_isolation::PartitionGptObservation,
    ) -> io::Result<()> {
        let info = match state {
            PreparedSourceProtection::Protected => &self.protected_info,
            PreparedSourceProtection::Original => &self.original_info,
        };
        require_gpt_from_original(&self.original_gpt, &self.binding, info, actual).map_err(|error| {
            bad(&format!(
                "the partition table of disk {} is not the recorded one with the partition {}: {error}",
                self.binding.storage.disk_number,
                match state {
                    PreparedSourceProtection::Protected => "read-only",
                    PreparedSourceProtection::Original => "as it was",
                }
            ))
        })
    }
    /// The first sector of the disk and of the partition are the recorded
    /// ones. Returns the partition's first sector.
    pub(in crate::native) fn require_first_sectors(&self) -> io::Result<Vec<u8>> {
        let sector = (self.binding.storage.identity.logical_sector_bytes as usize).max(512);
        need(
            sector <= 65536 && sector.is_multiple_of(512),
            "the disk's sector size is outside what a first-sector read takes",
        )?;
        let mbr = physical_read(&self.binding, 0, sector)?;
        need(
            mbr[..512] == self.original_mbr[..],
            &format!(
                "the first sector of disk {} differs from the one recorded",
                self.binding.storage.disk_number
            ),
        )?;
        let primary = physical_read(
            &self.binding,
            self.binding.storage.identity.partition_offset,
            sector,
        )?;
        need(
            sha(&primary[..512]) == self.ntfs_primary_sha256,
            &format!(
                "the first sector of partition {} of disk {} (the NTFS boot sector) has SHA-256 {}, and the one recorded is {}",
                self.binding.storage.identity.partition_number,
                self.binding.storage.disk_number,
                hex::encode(sha(&primary[..512])),
                hex::encode(self.ntfs_primary_sha256)
            ),
        )?;
        Ok(primary[..512].to_vec())
    }
}

/// The serial number in the recorded NTFS boot sector, read from the disk
/// after its SHA-256 was found to be the recorded one.
pub(in crate::native) fn read_ntfs_serial(origin: &PreparedSourceOrigin) -> io::Result<u64> {
    let primary = origin.require_first_sectors()?;
    need(
        &primary[3..11] == b"NTFS    ",
        "the recorded first sector of the partition is not an NTFS boot sector",
    )?;
    crate::layout::u64_at(&primary, 0x48)
}

/// What a way back did and found. Nothing in it is authority for anything.
#[derive(Clone, Debug, Serialize)]
pub struct PreparedSourceReturn {
    pub kind: &'static str,
    pub binding: PartitionSourceBinding,
    pub found: PreparedSourceProtection,
    pub attributes_restored_by_this_call: bool,
    pub original_attributes: u64,
    pub gpt_equals_original: bool,
    pub ntfs_primary_sha256: String,
    pub filesystem: String,
    pub writable: bool,
    pub ntfs_serial: u64,
    pub label: Option<String>,
    pub source_payload_write_calls: u64,
}

/// The one change: the partition's recorded original type, name, identifier
/// and attributes, set through `management`, between complete checks of the
/// disk's partition table and first sectors. `retire_filesystem` first locks
/// and dismounts the read-only file system on that same handle, where the
/// environment keeps it mounted across the change otherwise.
pub(in crate::native) fn restore_original_attributes(
    origin: &PreparedSourceOrigin,
    management: File,
    retire_filesystem: bool,
    observe: &mut dyn FnMut(
        &mut Vec<NativeEvent>,
    ) -> io::Result<partition_isolation::PartitionGptObservation>,
    before_change: &mut dyn FnMut(&[u8], &[u8]) -> io::Result<()>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    origin.require_gpt(PreparedSourceProtection::Protected, &observe(events)?)?;
    origin.require_first_sectors()?;
    let extents = control(
        &management,
        "prepared-cancel-management-extents",
        VOLUME_EXTENTS,
        &[],
        32,
        events,
    )?;
    origin.binding.storage.validate_volume_extent(&extents)?;
    need(
        control(
            &management,
            "prepared-cancel-management-partition-info",
            0x0007_0048,
            &[],
            144,
            events,
        )? == origin.protected_info,
        "the handle for the change names another partition or state than the read-only one",
    )?;
    before_change(&origin.protected_info, &origin.original_info)?;
    if retire_filesystem {
        for (code, phase) in [
            (LOCK, "prepared-cancel-readonly-filesystem-LOCK"),
            (DISMOUNT, "prepared-cancel-readonly-filesystem-DISMOUNT"),
        ] {
            need(
                control(&management, phase, code, &[], 0, events)?.is_empty(),
                "locking or dismounting the read-only file system returned unexpected data",
            )?;
        }
        need(
            control(
                &management,
                "prepared-cancel-locked-partition-info",
                0x0007_0048,
                &[],
                144,
                events,
            )? == origin.protected_info,
            "the partition changed while its read-only file system was dismounted",
        )?;
    }
    let mut input = [0u8; 120];
    input[..4].copy_from_slice(&1u32.to_le_bytes());
    input[8..120].copy_from_slice(&origin.original_info[32..144]);
    let reply = control_set_gpt_partition(
        &management,
        "prepared-cancel-SET_PARTITION_INFO_EX-once",
        &input,
        events,
    )?;
    need(
        reply.is_empty(),
        "the partition setter returned unexpected data",
    )?;
    need(
        control(
            &management,
            "prepared-cancel-original-partition-info-readback",
            0x0007_0048,
            &[],
            144,
            events,
        )? == origin.original_info,
        "the partition does not read back as the recorded original after the change",
    )?;
    drop(management);
    origin.require_gpt(PreparedSourceProtection::Original, &observe(events)?)?;
    origin.require_first_sectors()?;
    Ok(())
}

/// Waits for Windows to publish the volume of the original partition.
pub(in crate::native) fn wait_original_volume(
    origin: &PreparedSourceOrigin,
    budget: PartitionObservationBudget,
    observer: &mut impl PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> io::Result<File> {
    let started = Instant::now();
    let bound = Duration::from_secs(30);
    loop {
        match find_terminal_volume(
            &origin.binding,
            &origin.original_info,
            budget,
            observer,
            events,
        ) {
            Ok((_, volume)) => return Ok(volume),
            Err(error) if terminal_publication_pending(&error) && started.elapsed() < bound => {
                publication_checkpoint(
                    Ok(()),
                    observer,
                    "prepared-cancel-volume-publication-pending",
                    events,
                )?;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "Windows did not publish the volume of partition {} of disk {} after its attributes were restored: {error}",
                        origin.binding.storage.identity.partition_number,
                        origin.binding.storage.disk_number
                    ),
                ));
            }
        }
    }
}

/// What the published volume is: its file system, whether it takes writes,
/// its NTFS serial number and its label.
pub(in crate::native) struct ReturnedVolume {
    pub(in crate::native) filesystem: String,
    pub(in crate::native) writable: bool,
    pub(in crate::native) ntfs_serial: u64,
    pub(in crate::native) label: crate::volume_label::VolumeLabel,
}
pub(in crate::native) fn observe_returned_volume(
    volume: &File,
    events: &mut Vec<NativeEvent>,
) -> io::Result<ReturnedVolume> {
    let facts = terminal_volume_info(volume)?;
    need(
        facts.filesystem == "NTFS",
        &format!("the volume mounts as {} and not as NTFS", facts.filesystem),
    )?;
    let ntfs = control(
        volume,
        "prepared-cancel-NTFS-volume-data",
        0x0009_0064,
        &[],
        128,
        events,
    )?;
    need(ntfs.len() >= 96, "the NTFS volume data reply is short")?;
    let at = events.len();
    let tested = control(
        volume,
        "prepared-cancel-IS_WRITABLE",
        0x0007_0024,
        &[],
        0,
        events,
    );
    let device_writable = match tested {
        Ok(reply) => reply.is_empty(),
        Err(error)
            if events
                .get(at)
                .is_some_and(|event| !event.succeeded && event.native_error == Some(19)) =>
        {
            let _ = error;
            false
        }
        Err(error) => return Err(error),
    };
    Ok(ReturnedVolume {
        filesystem: facts.filesystem,
        writable: device_writable && facts.flags & 0x80000 == 0,
        ntfs_serial: crate::layout::u64_at(&ntfs, 0)?,
        label: facts.label,
    })
}

/// The checks every way back ends with, in the words a user is told.
pub(in crate::native) fn require_returned_volume(
    origin: &PreparedSourceOrigin,
    actual: &ReturnedVolume,
    expected_label: Option<&crate::volume_label::VolumeLabel>,
) -> io::Result<()> {
    let recorded = read_ntfs_serial(origin)?;
    need(
        actual.ntfs_serial == recorded,
        &format!(
            "the mounted NTFS volume has serial number {:016X}, and the recorded boot sector has {recorded:016X}",
            actual.ntfs_serial
        ),
    )?;
    if let Some(expected) = expected_label {
        need(
            actual.label == *expected,
            &format!(
                "the volume's label is {:?}, and the recorded one is {:?}",
                actual.label.text().unwrap_or_default(),
                expected.text().unwrap_or_default()
            ),
        )?;
    }
    need(
        actual.writable,
        "the partition is no longer marked read-only, but Windows still has its file system mounted read-only",
    )
}

/// In the running Windows: give a prepared, unapplied source back as the
/// NTFS volume it was. The caller has proved that the conversion never
/// started. Finding the partition already original is not an error: the
/// checks are then made without a change.
pub fn give_back_prepared_source_in_windows(
    origin: &PreparedSourceOrigin,
    budget: PartitionObservationBudget,
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    observer: &mut impl PartitionRestorationObserver,
    before_change: &mut dyn FnMut(&[u8], &[u8]) -> io::Result<()>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PreparedSourceReturn> {
    budget.validate()?;
    publication_checkpoint(Ok(()), observer, "prepared-cancel-opening", events)?;
    let (info, _) = super::partition_storage_roles::selected_from_physical_layout(
        &origin.binding,
        budget,
        events,
    )?;
    let found = origin.classify(&info)?;
    let binding = origin.binding.clone();
    // From the physical disk, as the terminal guard observes a basic
    // partition: whether its volume is published at that moment is not part
    // of what the partition table is.
    let mut observe = |events: &mut Vec<NativeEvent>| {
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
            false,
            false,
        )?;
        Ok(partition_isolation::observe_basic(&mut physical, &binding, budget, events)?.gpt)
    };
    let changed = match found {
        PreparedSourceProtection::Protected => {
            // The existing owner of exactly this state: the partition is
            // BASIC read-only, write-protected, mounted, holds no page file
            // or dump route, and its disk is the running Windows disk's.
            let terminal = PartitionBasicReadonlyTerminal::open_if_actual_basic_ro(
                origin.binding.clone(),
                budget,
                observer,
                events,
            )?
            .ok_or_else(|| bad("the partition is not basic read-only any more"))?;
            need(
                terminal.filesystem() == "NTFS",
                &format!(
                    "the read-only partition mounts as {} and not as NTFS: its conversion was written",
                    terminal.filesystem()
                ),
            )?;
            terminal.revalidate(observer, events)?;
            // Its handles close before the change, as at the end of a
            // conversion in Windows.
            drop(terminal);
            let management = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(3)
                .open(format!(
                    "\\\\?\\GLOBALROOT\\Device\\Harddisk{}\\Partition{}",
                    origin.binding.storage.disk_number,
                    origin.binding.storage.identity.partition_number
                ))?;
            let result = restore_original_attributes(
                origin,
                management,
                false,
                &mut observe,
                before_change,
                events,
            );
            publication_checkpoint(
                result,
                observer,
                "prepared-cancel-original-attributes-restored",
                events,
            )?;
            true
        }
        PreparedSourceProtection::Original => {
            let checked = (|| {
                origin.require_gpt(PreparedSourceProtection::Original, &observe(events)?)?;
                origin.require_first_sectors().map(|_| ())
            })();
            publication_checkpoint(
                checked,
                observer,
                "prepared-cancel-found-original-attributes",
                events,
            )?;
            false
        }
    };
    let mut volume = wait_original_volume(origin, budget, observer, events)?;
    let mut actual = observe_returned_volume(&volume, events)?;
    if !actual.writable {
        // The file system Windows mounted while the partition was read-only
        // can outlive the attribute. Nothing can be unwritten on it: ask for
        // a remount once, and only if nothing else has the volume open.
        drop(volume);
        let remount = (|| {
            let fresh = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(3)
                .open(origin.binding.storage.volume_path()?)?;
            control(&fresh, "prepared-cancel-remount-LOCK", LOCK, &[], 0, events)?;
            control(
                &fresh,
                "prepared-cancel-remount-DISMOUNT",
                DISMOUNT,
                &[],
                0,
                events,
            )
            .map(|_| ())
        })();
        if let Err(error) =
            publication_checkpoint(remount, observer, "prepared-cancel-remount", events)
        {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "the partition is no longer marked read-only, but Windows still has its file system mounted read-only and it is in use ({error}); close what uses the volume and run the cancellation again, or restart Windows"
                ),
            ));
        }
        volume = wait_original_volume(origin, budget, observer, events)?;
        actual = observe_returned_volume(&volume, events)?;
    }
    let checked = require_returned_volume(origin, &actual, expected_label);
    publication_checkpoint(
        checked,
        observer,
        "prepared-cancel-returned-volume-verified",
        events,
    )?;
    Ok(PreparedSourceReturn {
        kind: "prepared-unapplied-source-returned-in-windows-v1",
        binding: origin.binding.clone(),
        found,
        attributes_restored_by_this_call: changed,
        original_attributes: origin.original_attributes(),
        gpt_equals_original: true,
        ntfs_primary_sha256: hex::encode(origin.ntfs_primary_sha256),
        filesystem: actual.filesystem,
        writable: actual.writable,
        ntfs_serial: actual.ntfs_serial,
        label: actual.label.text(),
        source_payload_write_calls: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn binding() -> PartitionSourceBinding {
        serde_json::from_value(serde_json::json!({"storage":{
            "disk_number":0,
            "volume_guid":"11111111-2222-3333-4444-555555555555",
            "identity":{
                "disk_guid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "partition_guid":"01234567-89ab-cdef-0123-456789abcdef",
                "partition_number":4,
                "partition_offset":1048576u64,
                "partition_bytes":6442450944u64,
                "disk_bytes":136365211648u64,
                "logical_sector_bytes":512,
                "physical_sector_bytes":4096
            }
        }}))
        .unwrap()
    }
    fn info(binding: &PartitionSourceBinding, attributes: u64) -> Vec<u8> {
        let mut info = vec![0u8; 144];
        info[..4].copy_from_slice(&1u32.to_le_bytes());
        info[8..16].copy_from_slice(&binding.storage.identity.partition_offset.to_le_bytes());
        info[16..24].copy_from_slice(&binding.storage.identity.partition_bytes.to_le_bytes());
        info[24..28].copy_from_slice(&binding.storage.identity.partition_number.to_le_bytes());
        info[32..48].copy_from_slice(&crate::layout::guid_bytes(BASIC).unwrap());
        info[48..64].copy_from_slice(
            &crate::layout::guid_bytes(&binding.storage.identity.partition_guid).unwrap(),
        );
        info[64..72].copy_from_slice(&attributes.to_le_bytes());
        info
    }
    fn frame(
        binding: &PartitionSourceBinding,
        sequence: u64,
        version: u32,
        kind: &str,
        desired: &[u8],
        applied: bool,
    ) -> Vec<u8> {
        let body = serde_json::to_vec(&serde_json::json!({
            "version":version,"kind":kind,"sequence":sequence,"stage":"BasicLocked",
            "binding":binding,
            "original_partition_info":info(binding,0),
            "current_partition_info":info(binding,0),
            "desired_partition_info":desired,
            "original_gpt":{"entries":[1,2,3],"entry_bytes":128,"target_slot":1},
            "original_mbr":vec![7u8;512],
            "ntfs_primary_sha256":hex::encode([9u8;32]),
            "source_AP_issued":applied,"process_death_recovery_authority":false,
        }))
        .unwrap();
        let mut out = (body.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(&sha(&body));
        out.extend_from_slice(&body);
        out
    }
    fn file(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file
    }
    fn read(bytes: &[u8]) -> io::Result<PreparedSourceOrigin> {
        PreparedSourceOrigin::read(&mut file(bytes), &binding(), 64 << 20)
    }

    #[test]
    fn the_records_of_a_protected_source_give_its_original_and_both_known_states() {
        let binding = binding();
        let readonly = info(&binding, RO);
        // A run that failed right after protecting has one record; a
        // prepared run has the handoff record as its second.
        let mut bytes = frame(&binding, 1, 1, PROTECT_KIND, &readonly, false);
        let one = read(&bytes).unwrap();
        assert_eq!((one.records(), one.original_attributes()), (1, 0));
        bytes.extend(frame(&binding, 2, 2, HANDOFF_KIND, &readonly, false));
        let origin = read(&bytes).unwrap();
        assert_eq!(origin.records(), 2);
        assert_eq!(origin.intent_bytes(), bytes.len() as u64);
        assert_eq!(origin.intent_sha256(), sha(&bytes));
        assert_eq!(origin.ntfs_primary_sha256(), [9u8; 32]);
        assert_eq!(origin.original_partition_info(), info(&binding, 0));
        assert_eq!(
            origin.classify(&readonly).unwrap(),
            PreparedSourceProtection::Protected
        );
        assert_eq!(
            origin.classify(&info(&binding, 0)).unwrap(),
            PreparedSourceProtection::Original
        );
        // Anything else is refused by name: hidden as well as read-only,
        // another type, another place.
        let refusal = origin
            .classify(&info(&binding, RO | 0x4000_0000_0000_0000))
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("partition 4 of disk 0") && refusal.contains("0x5000000000000000"),
            "{refusal}"
        );
        let mut moved = readonly.clone();
        moved[8] ^= 1;
        assert!(origin.classify(&moved).is_err());
        // A cancellation the run began itself asks for the original.
        let mut cancelled = frame(&binding, 1, 1, PROTECT_KIND, &readonly, false);
        cancelled.extend(frame(
            &binding,
            2,
            1,
            PROTECT_KIND,
            &info(&binding, 0),
            false,
        ));
        assert_eq!(read(&cancelled).unwrap().records(), 2);
    }

    #[test]
    fn records_that_are_not_this_runs_or_not_whole_are_refused_by_what_is_wrong() {
        let binding = binding();
        let readonly = info(&binding, RO);
        let good = frame(&binding, 1, 1, PROTECT_KIND, &readonly, false);
        let says = |bytes: &[u8]| read(bytes).err().expect("refused").to_string();
        assert!(says(&[]).contains("holds no record"));
        assert!(says(&good[..20]).contains("cut short"));
        assert!(says(&good[..good.len() - 1]).contains("cut short"));
        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(says(&flipped).contains("SHA-256"));
        // An apply that was issued, another partition, another protocol.
        assert!(
            says(&frame(&binding, 1, 1, PROTECT_KIND, &readonly, true))
                .contains("no apply was issued")
        );
        let mut other = binding.clone();
        other.storage.identity.partition_number = 5;
        assert!(
            says(&frame(&other, 1, 1, PROTECT_KIND, &info(&other, RO), false))
                .contains("another partition")
        );
        let mut private = info(&binding, 0);
        private[32..48].copy_from_slice(&crate::layout::guid_bytes(PRIVATE).unwrap());
        assert!(
            says(&frame(&binding, 1, 1, PROTECT_KIND, &private, false))
                .contains("another protocol")
        );
        assert!(
            says(&frame(&binding, 1, 3, "something-else", &readonly, false))
                .contains("does not know")
        );
        assert!(
            says(&frame(&binding, 2, 1, PROTECT_KIND, &readonly, false))
                .contains("out of sequence")
        );
        // The handoff record is the second one only.
        assert!(
            says(&frame(&binding, 1, 2, HANDOFF_KIND, &readonly, false)).contains("does not know")
        );
    }
}
