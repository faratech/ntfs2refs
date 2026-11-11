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
        if volumes.len() != 1 || volumes[0].extents.len() != 1 || !volumes[0].errors.is_empty() {
            return Err(invalid(
                "letter has absent/ambiguous/unsupported volume mapping",
            ));
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
