//! Read-only routes/status, never source admission or storage-write authority.
use serde::Serialize;
use std::io;
#[cfg(windows)]
#[path = "drive_inventory_native.rs"]
mod native;

#[derive(Clone, Debug, Serialize)]
pub struct InventoryError {
    pub scope: String,
    pub operation: String,
    pub os_error: Option<i32>,
    pub message: String,
    pub enumeration_incomplete: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct VolumeExtent {
    pub disk_number: u32,
    pub offset_bytes: u64,
    pub length_bytes: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct VolumeInventory {
    pub volume_guid_path: String,
    pub mount_paths: Vec<String>,
    pub filesystem: Option<String>,
    pub label: Option<String>,
    pub filesystem_read_only: Option<bool>,
    /// The volume serial number Windows reports (the low half of an NTFS one).
    pub volume_serial: Option<u32>,
    pub contains_running_windows: Option<bool>,
    pub extents: Vec<VolumeExtent>,
    pub errors: Vec<InventoryError>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PartitionInventory {
    pub disk_number: u32,
    pub partition_number: u32,
    pub partition_style: String,
    pub offset_bytes: Option<u64>,
    pub size_bytes: Option<u64>,
    pub partition_guid: Option<String>,
    pub partition_type_guid: Option<String>,
    pub gpt_name: Option<String>,
    pub mbr_type: Option<u8>,
    /// Active MBR flag, not an assertion of the current Windows/system volume.
    pub mbr_active: Option<bool>,
    pub service_partition: Option<bool>,
    pub volume_guid_paths: Vec<String>,
    pub mount_paths: Vec<String>,
    pub filesystem: Option<String>,
    pub label: Option<String>,
    /// The serial number of the one volume on this partition, as `vol` prints it.
    pub volume_serial: Option<u32>,
    /// Whether the partition's first sector is BitLocker's. `None`: not
    /// looked at (reading it takes administrator rights), or not readable.
    pub bitlocker: Option<bool>,
    pub read_only: Option<bool>,
    pub offline: Option<bool>,
    pub contains_running_windows: Option<bool>,
    /// Unknown unless independently established; never inferred from EFI type.
    pub is_system: Option<bool>,
    pub unsupported_reason: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DiskInventory {
    pub disk_number: u32,
    pub device_path: String,
    pub size_bytes: Option<u64>,
    pub partition_style: Option<String>,
    pub disk_guid: Option<String>,
    pub mbr_signature: Option<u32>,
    pub read_only: Option<bool>,
    pub offline: Option<bool>,
    pub contains_running_windows: Option<bool>,
    pub is_system: Option<bool>,
    pub partitions: Vec<PartitionInventory>,
    pub errors: Vec<InventoryError>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DriveInventory {
    pub schema_version: u32,
    pub disks: Vec<DiskInventory>,
    pub volumes: Vec<VolumeInventory>,
    /// Also preserves optical/network/removable roots without a basic mapping.
    pub logical_drive_roots: Vec<String>,
    pub errors: Vec<InventoryError>,
    pub enumeration_complete: bool,
    pub source_authorized: bool,
    pub mutation_authorized: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct PartitionSelection {
    pub requested_drive: String,
    pub disk_number: u32,
    pub partition_number: u32,
    pub disk_guid: Option<String>,
    pub partition_guid: Option<String>,
    pub partition: PartitionInventory,
    pub volume_guid_path: String,
    pub source_authorized: bool,
    pub mutation_authorized: bool,
}

/// What to say when a drive letter leads to no volume. A disk that is
/// offline has no letters, and a conversion that was cut off leaves its disk
/// offline: that is the case someone is most likely to be in.
fn no_volume_at(inventory: &DriveInventory, root: &str) -> String {
    let offline: Vec<String> = inventory
        .disks
        .iter()
        .filter(|disk| disk.offline == Some(true))
        .map(|disk| disk.disk_number.to_string())
        .collect();
    if offline.is_empty() {
        return format!(
            "no volume is mounted as {root}; `ntfs2refs --list` shows the volumes there are"
        );
    }
    format!(
        "no volume is mounted as {root}. Disk {} offline, and a volume on an offline disk has no drive letter. If a conversion of that volume was cut off, do not start another: run the `--recover` command that run printed (the one with `--rollback` gives the NTFS volume back). `ntfs2refs --list` shows the disks",
        match offline.as_slice() {
            [one] => format!("{one} is"),
            many => format!("{} are", many.join(", ")),
        }
    )
}

pub fn parse_drive_letter(value: &str) -> io::Result<char> {
    let bytes = value.as_bytes();
    if !matches!(bytes.len(), 1 | 2 | 3)
        || !bytes[0].is_ascii_alphabetic()
        || (bytes.len() >= 2 && bytes[1] != b':')
        || (bytes.len() == 3 && bytes[2] != b'\\')
    {
        return Err(invalid("drive letter must be D, D: or D:\\"));
    }
    Ok(char::from(bytes[0].to_ascii_uppercase()))
}

/// Deterministic point-in-time selection only. Numeric disks require a partition;
/// a partition accompanying a letter must match that letter's actual volume.
pub fn resolve_selection(
    inventory: &DriveInventory,
    drive: &str,
    partition: Option<u32>,
) -> io::Result<PartitionSelection> {
    if partition == Some(0) {
        return Err(invalid("partition number must be nonzero"));
    }
    let (disk_number, number, requested_volume) = if !drive.is_empty()
        && drive.bytes().all(|byte| byte.is_ascii_digit())
    {
        (
            drive
                .parse::<u32>()
                .map_err(|_| invalid("disk number overflow"))?,
            partition.ok_or_else(|| {
                invalid("numeric disk selection requires an explicit partition number")
            })?,
            None,
        )
    } else {
        let root = format!("{}:\\", parse_drive_letter(drive)?);
        let volumes: Vec<_> = inventory
            .volumes
            .iter()
            .filter(|volume| {
                volume
                    .mount_paths
                    .iter()
                    .any(|path| path.eq_ignore_ascii_case(&root))
            })
            .collect();
        if volumes.is_empty() {
            return Err(invalid(&no_volume_at(inventory, &root)));
        }
        if volumes.len() != 1 {
            return Err(invalid(&format!(
                "{} volumes are mounted as {root}; select the partition by disk number and --partition instead",
                volumes.len()
            )));
        }
        if volumes[0].extents.len() != 1 {
            return Err(invalid(&format!(
                "the volume mounted as {root} lies on {} disk extents (a spanned, striped or mirrored volume); only a volume that is one partition can be converted",
                volumes[0].extents.len()
            )));
        }
        if let Some(error) = volumes[0].errors.first() {
            return Err(invalid(&format!(
                "Windows did not answer every question about the volume mounted as {root} ({}: {}); `ntfs2refs --list` shows what it did answer",
                error.operation, error.message
            )));
        }
        let volume = volumes[0];
        let extent = &volume.extents[0];
        let rows: Vec<_> = inventory
            .disks
            .iter()
            .filter(|disk| disk.disk_number == extent.disk_number)
            .flat_map(|disk| &disk.partitions)
            .filter(|row| {
                row.offset_bytes == Some(extent.offset_bytes)
                    && row.size_bytes == Some(extent.length_bytes)
            })
            .collect();
        if rows.len() != 1 || partition.is_some_and(|number| number != rows[0].partition_number) {
            return Err(invalid(
                "partition does not match the drive letter's exact observed partition",
            ));
        }
        (
            extent.disk_number,
            rows[0].partition_number,
            Some(volume.volume_guid_path.as_str()),
        )
    };
    let disks: Vec<_> = inventory
        .disks
        .iter()
        .filter(|disk| disk.disk_number == disk_number)
        .collect();
    if disks.len() != 1 || !disks[0].errors.is_empty() {
        return Err(invalid(
            "selected disk identity/layout is unavailable or ambiguous",
        ));
    }
    let disk = disks[0];
    let rows: Vec<_> = disk
        .partitions
        .iter()
        .filter(|row| row.partition_number == number)
        .collect();
    if rows.len() != 1 {
        return Err(invalid("selected partition is absent or ambiguous"));
    }
    let row = rows[0];
    if disk.partition_style.as_deref() == Some("GPT")
        && (disk.disk_guid.is_none()
            || row.partition_guid.is_none()
            || row.partition_type_guid.is_none())
    {
        return Err(invalid(
            "selected GPT disk/partition identities are incomplete",
        ));
    }
    if row.unsupported_reason.is_some()
        || row.offset_bytes.is_none()
        || row.size_bytes.is_none()
        || row.volume_guid_paths.len() != 1
    {
        return Err(invalid(
            "partition lacks one supported volume route; list its inventory for details",
        ));
    }
    let volume_path = &row.volume_guid_paths[0];
    crate::discovery::volume_guid(volume_path)?;
    if requested_volume.is_some_and(|expected| !expected.eq_ignore_ascii_case(volume_path)) {
        return Err(invalid("letter/partition volume identity differs"));
    }
    let volumes: Vec<_> = inventory
        .volumes
        .iter()
        .filter(|volume| volume.volume_guid_path.eq_ignore_ascii_case(volume_path))
        .collect();
    if volumes.len() != 1 || !volumes[0].errors.is_empty() || volumes[0].extents.len() != 1 {
        return Err(invalid(
            "selected volume is unknown, spanned or has query errors",
        ));
    }
    let extent = &volumes[0].extents[0];
    if extent.disk_number != disk_number
        || Some(extent.offset_bytes) != row.offset_bytes
        || Some(extent.length_bytes) != row.size_bytes
    {
        return Err(invalid("selected volume extent differs from its partition"));
    }
    Ok(PartitionSelection {
        requested_drive: drive.into(),
        disk_number,
        partition_number: number,
        disk_guid: disk.disk_guid.clone(),
        partition_guid: row.partition_guid.clone(),
        partition: row.clone(),
        volume_guid_path: volume_path.clone(),
        source_authorized: false,
        mutation_authorized: false,
    })
}

#[cfg(windows)]
pub fn inventory_drives_readonly() -> io::Result<DriveInventory> {
    native::inventory()
}
#[cfg(not(windows))]
pub fn inventory_drives_readonly() -> io::Result<DriveInventory> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native drive inventory requires Windows",
    ))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// BitLocker replaces the NTFS boot sector's file-system name with its own.
/// The sector has to come from the disk: through the volume, an unlocked
/// BitLocker volume shows the NTFS one.
pub fn is_bitlocker_boot_sector(bytes: &[u8]) -> bool {
    bytes.get(3..11) == Some(b"-FVE-FS-")
}

/// Whether a root such as `E:\` is an optical drive: a disc, or a mounted
/// disc image. Such a volume lies on no disk and is never a source.
#[cfg(windows)]
pub fn optical_drive(root: &str) -> bool {
    native::optical(root)
}
#[cfg(not(windows))]
pub fn optical_drive(_root: &str) -> bool {
    false
}

/// Reads the first sector of every partition that could hold an NTFS volume
/// and records whether it is BitLocker's. Needs administrator rights; a
/// partition that cannot be read keeps `None`. Reads only.
#[cfg(windows)]
pub fn annotate_bitlocker(inventory: &mut DriveInventory) {
    native::annotate_bitlocker(inventory)
}
#[cfg(not(windows))]
pub fn annotate_bitlocker(_inventory: &mut DriveInventory) {}

const TYPE_BASIC_DATA: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
const TYPE_EFI: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const TYPE_MSR: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
const TYPE_RECOVERY: &str = "de94bba4-06d1-4d40-a16a-bfd50179d6ac";

/// What a conversion would say about one partition, from the inventory
/// alone: whether its disk has the layout the converter takes, in the words
/// a refusal would otherwise only use minutes into a run. `None` for a
/// partition that is not NTFS: there is nothing to convert.
///
/// This is advice for `--list`. It admits nothing; a run examines the disk
/// itself, and the volume's contents can still refuse it.
pub fn conversion_note(disk: &DiskInventory, partition: &PartitionInventory) -> Option<String> {
    // Windows reports an unlocked BitLocker volume as NTFS and a locked one
    // as nothing at all; its first sector says what it is.
    if partition.bitlocker == Some(true) {
        return Some("not convertible: encrypted with BitLocker; decrypt it first (manage-bde -off <drive>), suspending is not enough".into());
    }
    if partition.filesystem.as_deref() != Some("NTFS") {
        return None;
    }
    let unchecked = if partition.bitlocker.is_none() {
        "; BitLocker not checked (run --list from an elevated terminal)"
    } else {
        ""
    };
    if partition.contains_running_windows == Some(true) {
        return Some("not convertible: this is the running Windows (convert it from another Windows installation)".into());
    }
    if let Some(reason) = &partition.unsupported_reason {
        return Some(format!("not convertible: {reason}"));
    }
    if disk.partition_style.as_deref() != Some("GPT") {
        return Some(format!(
            "not convertible: the disk is {}, and the converter takes GPT disks only",
            disk.partition_style
                .as_deref()
                .unwrap_or("of an unknown partition style")
        ));
    }
    if disk.contains_running_windows == Some(true) {
        return Some("not convertible: it shares its disk with the running Windows, and a conversion takes the whole disk offline".into());
    }
    let kind = |other: &PartitionInventory| other.partition_type_guid.clone().unwrap_or_default();
    let others: Vec<String> = disk
        .partitions
        .iter()
        .filter(|other| other.partition_number != partition.partition_number)
        .map(kind)
        .collect();
    let count = |wanted: &str| others.iter().filter(|kind| kind.as_str() == wanted).count();
    if others.iter().all(|kind| kind == TYPE_MSR) && others.len() <= 1 {
        return Some(format!("convertible as a data volume{unchecked}"));
    }
    if others.len() == 3
        && count(TYPE_EFI) == 1
        && count(TYPE_MSR) == 1
        && count(TYPE_RECOVERY) == 1
    {
        return Some(format!(
            "convertible as a Windows boot volume (--windows-boot-volume), if it is a qualified Windows build{unchecked}"
        ));
    }
    // A data disk with other partitions: the whole disk still goes offline,
    // and the volumes beside this one with it.
    Some(format!(
        "convertible as a data volume; the disk's {} other partition(s) go offline with it for the length of the run{unchecked}",
        others
            .iter()
            .filter(|kind| kind.as_str() != TYPE_MSR)
            .count()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partition(number: u32, kind: &str, filesystem: Option<&str>) -> PartitionInventory {
        PartitionInventory {
            disk_number: 1,
            partition_number: number,
            partition_style: "GPT".into(),
            offset_bytes: Some(u64::from(number) << 30),
            size_bytes: Some(1 << 30),
            partition_guid: None,
            partition_type_guid: Some(kind.into()),
            gpt_name: None,
            mbr_type: None,
            mbr_active: None,
            service_partition: None,
            volume_guid_paths: Vec::new(),
            mount_paths: Vec::new(),
            filesystem: filesystem.map(str::to_owned),
            label: None,
            volume_serial: None,
            bitlocker: Some(false),
            read_only: None,
            offline: None,
            contains_running_windows: Some(false),
            is_system: None,
            unsupported_reason: None,
        }
    }
    fn disk(style: &str, partitions: Vec<PartitionInventory>) -> DiskInventory {
        DiskInventory {
            disk_number: 1,
            device_path: "\\\\.\\PhysicalDrive1".into(),
            size_bytes: Some(1 << 40),
            partition_style: Some(style.into()),
            disk_guid: None,
            mbr_signature: None,
            read_only: Some(false),
            offline: Some(false),
            contains_running_windows: Some(false),
            is_system: None,
            partitions,
            errors: Vec::new(),
        }
    }
    const BASIC: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";

    #[test]
    fn a_letter_that_leads_to_no_volume_says_so_and_names_an_offline_disk() {
        let inventory = |offline: bool| DriveInventory {
            schema_version: 1,
            disks: vec![DiskInventory {
                offline: Some(offline),
                ..disk("GPT", vec![partition(2, BASIC, Some("NTFS"))])
            }],
            volumes: Vec::new(),
            logical_drive_roots: Vec::new(),
            errors: Vec::new(),
            enumeration_complete: true,
            source_authorized: false,
            mutation_authorized: false,
        };
        let refused = |offline: bool| {
            resolve_selection(&inventory(offline), "V", None)
                .unwrap_err()
                .to_string()
        };
        let plain = refused(false);
        assert!(
            plain.contains("no volume is mounted as V:\\") && plain.contains("--list"),
            "{plain}"
        );
        assert!(!plain.contains("offline"), "{plain}");
        // What a run that was cut off while it prepared leaves behind.
        let after_a_stop = refused(true);
        for expected in [
            "Disk 1 is offline",
            "--recover",
            "--rollback",
            "do not start another",
        ] {
            assert!(
                after_a_stop.contains(expected),
                "{expected}: {after_a_stop}"
            );
        }
    }

    #[test]
    fn list_says_what_it_knows_of_bitlocker() {
        let only = |bitlocker: Option<bool>, filesystem: Option<&str>| {
            let mut data = partition(1, BASIC, filesystem);
            data.bitlocker = bitlocker;
            let disk = disk("GPT", vec![data]);
            conversion_note(&disk, &disk.partitions[0])
        };
        // Seen in the first sector: Windows calls an unlocked one NTFS and a
        // locked one nothing at all.
        for filesystem in [Some("NTFS"), None] {
            let note = only(Some(true), filesystem).unwrap();
            assert!(
                note.starts_with("not convertible: encrypted with BitLocker")
                    && note.contains("manage-bde -off"),
                "{note}"
            );
        }
        // Looked at, and not BitLocker.
        assert_eq!(
            only(Some(false), Some("NTFS")).as_deref(),
            Some("convertible as a data volume")
        );
        // Not looked at: the list was not made by an elevated process.
        let unchecked = only(None, Some("NTFS")).unwrap();
        assert!(
            unchecked.starts_with("convertible as a data volume")
                && unchecked.contains("BitLocker not checked")
                && unchecked.contains("elevated"),
            "{unchecked}"
        );
        assert_eq!(only(None, None), None);
        assert!(is_bitlocker_boot_sector(b"\xeb\x58\x90-FVE-FS-\0\x02"));
        assert!(!is_bitlocker_boot_sector(b"\xeb\x52\x90NTFS    \0\x02"));
        assert!(!is_bitlocker_boot_sector(b"\xeb\x58"));
    }

    #[test]
    fn list_says_which_partitions_the_default_route_takes_and_why_not() {
        let note = |disk: &DiskInventory, number: u32| {
            conversion_note(
                disk,
                disk.partitions
                    .iter()
                    .find(|p| p.partition_number == number)
                    .unwrap(),
            )
        };
        // A data volume alone on its disk, with or without a reserved partition.
        let alone = disk(
            "GPT",
            vec![
                partition(1, TYPE_MSR, None),
                partition(2, BASIC, Some("NTFS")),
            ],
        );
        assert_eq!(
            note(&alone, 2).as_deref(),
            Some("convertible as a data volume")
        );
        assert_eq!(note(&alone, 1), None);
        let only = disk("GPT", vec![partition(1, BASIC, Some("NTFS"))]);
        assert_eq!(
            note(&only, 1).as_deref(),
            Some("convertible as a data volume")
        );
        // Two data partitions on one disk.
        let shared = disk(
            "GPT",
            vec![
                partition(1, TYPE_MSR, None),
                partition(2, BASIC, Some("NTFS")),
                partition(3, BASIC, Some("NTFS")),
            ],
        );
        assert_eq!(
            note(&shared, 2).as_deref(),
            Some(
                "convertible as a data volume; the disk's 1 other partition(s) go offline with it for the length of the run"
            )
        );
        // An offline Windows disk.
        let windows = disk(
            "GPT",
            vec![
                partition(1, TYPE_EFI, Some("FAT32")),
                partition(2, TYPE_MSR, None),
                partition(3, BASIC, Some("NTFS")),
                partition(4, TYPE_RECOVERY, Some("NTFS")),
            ],
        );
        assert!(
            note(&windows, 3)
                .unwrap()
                .starts_with("convertible as a Windows boot volume")
        );
        // MBR, the running Windows and its disk, and a volume that is already ReFS.
        let mbr = disk("MBR", vec![partition(1, BASIC, Some("NTFS"))]);
        assert!(note(&mbr, 1).unwrap().contains("the disk is MBR"));
        let mut running = disk(
            "GPT",
            vec![
                partition(1, BASIC, Some("NTFS")),
                partition(2, BASIC, Some("NTFS")),
            ],
        );
        running.contains_running_windows = Some(true);
        running.partitions[0].contains_running_windows = Some(true);
        assert!(
            note(&running, 1)
                .unwrap()
                .contains("this is the running Windows")
        );
        assert!(
            note(&running, 2)
                .unwrap()
                .contains("shares its disk with the running Windows")
        );
        let refs = disk("GPT", vec![partition(1, BASIC, Some("ReFS"))]);
        assert_eq!(note(&refs, 1), None);
    }
}
