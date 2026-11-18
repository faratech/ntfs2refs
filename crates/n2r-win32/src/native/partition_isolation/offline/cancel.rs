//! The way back inside the recovery environment, for a conversion that never
//! started there. It runs after the runner's own owners have failed or were
//! never built, so it cannot borrow their proofs: every function here makes
//! its own, smaller ones, and none of them can reach the partition's
//! contents. A disk is identified by its number, length and GUID in its own
//! GPT header before its availability is changed; the working disk is the
//! one the boot-bound request names; the source is given back through the
//! same single-partition setter and the same checks as in Windows
//! (`partition_restoration::prepared_cancel`).
use super::*;
use crate::native::partition_restoration::{
    PartitionRestorationObserver, PreparedSourceOrigin, PreparedSourceProtection,
    PreparedSourceReturn, find_terminal_volume, observe_returned_volume, require_returned_volume,
    restore_original_attributes, wait_original_volume,
};
use crate::native::set_attributes;
use std::io::{Read, Seek, SeekFrom};

fn drain(
    observer: &mut impl PartitionRestorationObserver,
    phase: &'static str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    observer.checkpoint_native_events(phase, events)?;
    require(
        events.is_empty(),
        "cancellation event checkpoint did not drain",
    )
}

/// The disk at this number is the recorded one: its length, and the disk
/// GUID in its primary GPT header. Read-only; changes nothing.
fn require_disk_identity(
    disk: &mut File,
    binding: &crate::general_layout::GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    let device = control(disk, "cancel-disk-native-DEVICE", DEVICE, &[], 12, events)?;
    layout::validate_device(&device, binding.disk_number)?;
    let length = control(disk, "cancel-disk-native-length", LENGTH, &[], 8, events)?;
    require(
        length.len() == 8 && layout::u64_at(&length, 0)? == binding.identity.disk_bytes,
        &format!(
            "disk {} is not {} bytes long as recorded: another disk has this number now",
            binding.disk_number, binding.identity.disk_bytes
        ),
    )?;
    let sector = (binding.identity.logical_sector_bytes as usize).max(512);
    require(
        sector <= 4096,
        "the disk's sector size is outside a GPT header read",
    )?;
    let mut first = vec![0u8; sector * 2];
    disk.seek(SeekFrom::Start(0))?;
    disk.read_exact(&mut first)?;
    let header = &first[sector..];
    require(
        &header[..8] == b"EFI PART"
            && header[56..72] == layout::guid_bytes(&binding.identity.disk_guid)?,
        &format!(
            "disk {} does not carry the recorded disk identifier {} in its partition table: another disk has this number now",
            binding.disk_number, binding.identity.disk_guid
        ),
    )
}

/// Brings the recorded disk online and writable if it is not. Returns
/// whether its state was changed. The partitions on it are not touched: a
/// partition that is marked read-only in the GPT stays so.
pub(crate) fn make_disk_available(
    binding: &crate::general_layout::GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<bool> {
    let mut disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        true,
        false,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("opening disk {}: {error}", binding.disk_number),
        )
    })?;
    require_disk_identity(&mut disk, binding, events)?;
    let before = attributes(&disk, events)?;
    if before == 0 {
        return Ok(false);
    }
    set_attributes(&disk, 0, events)?;
    require_disk_identity(&mut disk, binding, events)?;
    require(
        attributes(&disk, events)? == 0,
        &format!(
            "disk {} did not come online and writable",
            binding.disk_number
        ),
    )?;
    Ok(true)
}

/// The native partition layout of an available disk.
pub(crate) fn available_disk_layout(
    binding: &crate::general_layout::GeneralDiskBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    let mut disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        false,
        false,
    )?;
    require_disk_identity(&mut disk, binding, events)?;
    require(
        attributes(&disk, events)? == 0,
        &format!("disk {} is not online and writable", binding.disk_number),
    )?;
    native_layout(&disk, budget, events)
}

/// The RAM volume the current Windows runs from, and its kernel identity.
pub(crate) fn current_ram() -> io::Result<(
    String,
    crate::native::offline_environment::KernelRamBackingFacts,
)> {
    let windows = current_windows()?;
    let root = require_ram_root(&windows)?;
    let ram = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(format!("\\\\.\\{}:", &root[..1]))?;
    let backing =
        crate::native::offline_environment::kernel_ram_backing::require_held(&windows, &ram)?;
    require(
        backing.positive_native_kernel_ramdisk,
        "the current Windows does not run from a kernel RAM disk",
    )?;
    Ok((root, backing))
}

/// Opens the working volume the boot-bound request names, bringing its disk
/// online first if it is not. This is the journal enrollment of the runner
/// without the source: it reads the request the kernel was started with,
/// requires that request to name `journal`, identifies the disk, and never
/// opens or changes the source's disk. `source_disk` is only compared, so
/// that the working disk can never be the source's.
pub fn open_journal_volume_for_cancellation(
    journal: &GeneralJournalStorageBinding,
    source_disk: &crate::general_layout::GeneralDiskBinding,
    ram_bootstrap: &mut File,
    budget: PartitionObservationBudget,
    observer: &mut impl PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> io::Result<File> {
    budget.validate()?;
    journal.validate()?;
    drain(observer, "cancel-J-enrollment-opening", events)?;
    require(
        journal.disk.disk_number != source_disk.disk_number
            && layout::guid_bytes(&journal.disk.identity.disk_guid)?
                != layout::guid_bytes(&source_disk.identity.disk_guid)?,
        "the working disk of a cancellation must be another physical disk than the source's",
    )?;
    // The request on the RAM disk is the one the current kernel was started
    // with, and it names this working volume.
    crate::file_storage::require_readonly_access(ram_bootstrap)?;
    let windows = current_windows()?;
    let ram_root = require_ram_root(&windows)?;
    let expected_path = format!(
        "{}\\System32\\n2r-bootstrap.json",
        windows.trim_end_matches('\\')
    );
    let (ram, _) = crate::native::offline_environment::kernel_ram_backing::require_file(
        &expected_path,
        ram_bootstrap,
    )?;
    require(
        ram.dos_root == ram_root,
        "the held request is not on the current RAM Windows volume",
    )?;
    let length = ram_bootstrap.metadata()?.len();
    require(
        length > 0 && length <= budget.ram_bytes / 64,
        "the RAM request exceeds what its decoding may hold",
    )?;
    let pinned = crate::native::recovery_boot::current_recovery_bootstrap_sha256()?;
    ram_bootstrap.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(io::Error::other)?;
    ram_bootstrap.take(length + 1).read_to_end(&mut bytes)?;
    ram_bootstrap.seek(SeekFrom::Start(0))?;
    require(
        bytes.len() as u64 == length && <[u8; 32]>::from(Sha256::digest(&bytes)) == pinned,
        "the RAM request is not the one the current boot selection names",
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
            && route.source.storage == *source_disk
            && route.journal == *journal,
        "the boot-bound request names another source or working volume",
    )?;
    make_disk_available(&journal.disk, events).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "the working disk (disk {}) could not be reached: {error}",
                journal.disk.disk_number
            ),
        )
    })?;
    drain(observer, "cancel-J-disk-available", events)?;
    // The volume appears a moment after its disk comes online.
    let path = journal.disk.volume_path()?;
    let mut opened = None;
    for attempt in 0..60 {
        match device_file(&path, true, false) {
            Ok(volume) => {
                opened = Some(volume);
                break;
            }
            Err(error)
                if attempt < 59 && matches!(error.raw_os_error(), Some(2 | 3 | 15 | 21 | 53)) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("opening the working volume {path}: {error}"),
                ));
            }
        }
    }
    let volume = opened.ok_or_else(|| invalid("the working volume was not published"))?;
    let device = control(
        &volume,
        "cancel-J-volume-native-device",
        DEVICE,
        &[],
        12,
        events,
    )?;
    let info = control(
        &volume,
        "cancel-J-volume-native-partition",
        0x0007_0048,
        &[],
        144,
        events,
    )?;
    let extents = control(
        &volume,
        "cancel-J-volume-native-extents",
        VOLUME_EXTENTS,
        &[],
        32,
        events,
    )?;
    journal.disk.validate_volume_extent(&extents)?;
    let id = &journal.disk.identity;
    require(
        device.len() == 12
            && layout::u32_at(&device, 0)? == 7
            && layout::u32_at(&device, 4)? == journal.disk.disk_number
            && layout::u32_at(&device, 8)? == id.partition_number
            && info.len() == 144
            && info[48..64] == layout::guid_bytes(&id.partition_guid)?
            && layout::u64_at(&info, 8)? == id.partition_offset
            && layout::u64_at(&info, 16)? == id.partition_bytes,
        "the opened working volume is not the recorded partition",
    )?;
    drain(observer, "cancel-J-volume-enrolled", events)?;
    Ok(volume)
}

/// In the recovery environment: give a prepared, unapplied source back as
/// the NTFS volume it was. The caller has proved from the journal that the
/// conversion never started. The source's disk is brought online first if a
/// failed start left it offline.
pub fn give_back_prepared_source_offline(
    origin: &PreparedSourceOrigin,
    budget: PartitionObservationBudget,
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    observer: &mut impl PartitionRestorationObserver,
    before_change: &mut dyn FnMut(&[u8], &[u8]) -> io::Result<()>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PreparedSourceReturn> {
    budget.validate()?;
    drain(observer, "cancel-offline-source-opening", events)?;
    let binding = origin.binding().clone();
    make_disk_available(&binding.storage, events)?;
    drain(observer, "cancel-offline-source-disk-available", events)?;
    let mut physical = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
        false,
        false,
    )?;
    let facts = source_facts(&mut physical, &binding, budget, events)?;
    require(
        facts.disk_attributes == 0,
        "the source's disk is not online and writable",
    )?;
    let guid = layout::guid_bytes(&binding.storage.identity.partition_guid)?;
    let rows: Vec<_> = facts.gpt.native_layout[48..]
        .chunks_exact(144)
        .filter(|row| row[48..64] == guid)
        .collect();
    require(
        rows.len() == 1,
        "the source partition is not unique on its disk",
    )?;
    let found = origin.classify(rows[0])?;
    drain(observer, "cancel-offline-source-classified", events)?;
    let mut observe = |events: &mut Vec<NativeEvent>| {
        let mut disk = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
            false,
            false,
        )?;
        let facts = source_facts(&mut disk, &binding, budget, events)?;
        require(
            facts.disk_attributes == 0,
            "the source's disk left the online state",
        )?;
        Ok(facts.gpt)
    };
    let changed = match found {
        PreparedSourceProtection::Protected => {
            // The read-only volume of the partition, as this Windows
            // publishes it; the file system on it must be the NTFS.
            let mut mounted = None;
            for attempt in 0..60 {
                match find_terminal_volume(
                    &binding,
                    origin.protected_partition_info(),
                    budget,
                    observer,
                    events,
                ) {
                    Ok(found) => {
                        mounted = Some(found);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound && attempt < 59 => {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                    Err(error) => return Err(error),
                }
            }
            let (mounted_binding, volume) =
                mounted.ok_or_else(|| invalid("the read-only source volume was not published"))?;
            let before = observe_returned_volume(&volume, events)?;
            require(
                before.filesystem == "NTFS" && !before.writable,
                "the read-only source does not mount as write-protected NTFS",
            )?;
            drop(volume);
            // One handle on the selected volume for lock, dismount and the
            // setter, as at the end of a conversion here: closing readers
            // does not retire a mounted read-only file system.
            let management = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(3)
                .custom_flags(0xa000_0000)
                .open(mounted_binding.volume_path()?)?;
            let result = restore_original_attributes(
                origin,
                management,
                true,
                &mut observe,
                before_change,
                events,
            );
            let drained = drain(
                observer,
                "cancel-offline-original-attributes-restored",
                events,
            );
            result?;
            drained?;
            true
        }
        PreparedSourceProtection::Original => {
            origin.require_gpt(PreparedSourceProtection::Original, &facts.gpt)?;
            origin.require_first_sectors()?;
            false
        }
    };
    let volume = wait_original_volume(origin, budget, observer, events)?;
    let actual = observe_returned_volume(&volume, events)?;
    let checked = require_returned_volume(origin, &actual, expected_label);
    let drained = drain(observer, "cancel-offline-returned-volume-verified", events);
    checked?;
    drained?;
    Ok(PreparedSourceReturn {
        kind: "prepared-unapplied-source-returned-in-recovery-environment-v1",
        binding: origin.binding().clone(),
        found,
        attributes_restored_by_this_call: changed,
        original_attributes: origin.original_attributes(),
        gpt_equals_original: true,
        ntfs_primary_sha256: hex::encode(origin.ntfs_primary_sha256()),
        filesystem: actual.filesystem,
        writable: actual.writable,
        ntfs_serial: actual.ntfs_serial,
        label: actual.label.text(),
        source_payload_write_calls: 0,
    })
}
