//! Bounded read-only volume/disk identity discovery. These values are routing
//! inputs, never a source certificate or permission to change disk state.
use crate::{
    general_layout::GeneralDiskBinding,
    layout::{self, PartitionIdentity, guid_bytes, u32_at, u64_at},
};
use serde::Serialize;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Role {
    Source,
    OfflineWindowsSource,
    Shadow,
    ShadowReadOnly,
    Journal { allow_additional_partitions: bool },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StorageEvidence {
    pub volume_extents: Vec<u8>,
    pub device: Vec<u8>,
    pub disk_length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub gpt_layout: Vec<u8>,
    pub disk_attributes: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct VolumeDiscovery {
    pub schema_version: u32,
    pub role: Role,
    pub requested_root: String,
    pub resolved_root: String,
    pub volume_guid_path: String,
    pub binding: GeneralDiskBinding,
    pub filesystem: String,
    pub label: String,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub volume_serial_low32: u32,
    pub filesystem_flags: u32,
    pub windows_disk_number: u32,
    pub disk_is_windows_disk: bool,
    pub evidence: StorageEvidence,
    pub observed_twice_unchanged: bool,
    pub read_only: bool,
    pub source_write_requests: u64,
}

/// A point-in-time filesystem capacity observation. This is advisory: other
/// writers, quotas, metadata allocation and target construction can change it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VolumeSpaceObservation {
    pub available_bytes_to_caller: u64,
    pub total_bytes_available_to_caller: u64,
    pub total_free_bytes: u64,
    pub informational_only: bool,
    pub reserves_space: bool,
    pub execution_authorized: bool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}

pub fn validate_root(root: &str) -> io::Result<()> {
    let is_guid = root.starts_with("\\\\?\\Volume{");
    require(
        !root.is_empty()
            && root.encode_utf16().count() < 4096
            && root.ends_with('\\')
            && !root.contains(['\0', '/', '*', '<', '>', '|', '"'])
            && (!root.contains('?') || is_guid),
        "explicit bounded local volume root required",
    )?;
    if root.starts_with("\\\\?\\Volume{") {
        volume_guid(root)?;
        return Ok(());
    }
    let bytes = root.as_bytes();
    require(
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
            && !root[2..].contains(':'),
        "drive-root or local mounted-folder root required",
    )?;
    let tail = &root[3..];
    if tail.is_empty() {
        return Ok(());
    }
    require(
        tail.strip_suffix('\\').is_some_and(|tail| {
            tail.split('\\').all(|part| {
                !part.is_empty() && part != "." && part != ".." && !part.ends_with([' ', '.'])
            })
        }),
        "ambiguous root component",
    )
}

pub fn volume_guid(path: &str) -> io::Result<String> {
    require(
        path.encode_utf16().count() < 4096 && !path.contains('\0'),
        "bounded volume GUID path required",
    )?;
    let guid = path
        .strip_prefix("\\\\?\\Volume{")
        .and_then(|v| v.strip_suffix("}\\"))
        .ok_or_else(|| invalid("volume GUID path syntax differs"))?;
    guid_bytes(guid)?;
    Ok(guid.to_ascii_lowercase())
}

pub fn single_extent(bytes: &[u8]) -> io::Result<(u32, u64, u64)> {
    require(
        bytes.len() == 32 && u32_at(bytes, 0)? == 1,
        "volume must have exactly one complete disk extent",
    )?;
    let number = u32_at(bytes, 8)?;
    let offset = u64_at(bytes, 16)?;
    let length = u64_at(bytes, 24)?;
    require(
        offset > 0 && length > 0 && offset.checked_add(length).is_some(),
        "invalid volume extent",
    )?;
    Ok((number, offset, length))
}

fn guid_text(bytes: &[u8]) -> io::Result<String> {
    let mut raw: [u8; 16] = bytes.try_into().map_err(|_| invalid("short GUID"))?;
    require(raw != [0; 16], "empty GPT identity")?;
    raw[..4].reverse();
    raw[4..6].reverse();
    raw[6..8].reverse();
    let hex = hex::encode(raw);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// The GPT basic-data partition at exactly `offset` and `length`: its
/// number and GUID, and how many partitions lie beside it, a reserved one
/// not counted.
fn gpt_partition(
    raw: &[u8],
    disk_bytes: u64,
    offset: u64,
    length: u64,
    role: Role,
) -> io::Result<(u32, String, usize)> {
    require(
        (48..=65536).contains(&raw.len()) && u32_at(raw, 0)? == 1,
        "GPT disk required",
    )?;
    let count = u32_at(raw, 4)? as usize;
    require(
        count != 0 && count.checked_mul(144).and_then(|n| n.checked_add(48)) == Some(raw.len()),
        "incomplete or excessive GPT entry array",
    )?;
    let first = u64_at(raw, 24)?;
    let usable = u64_at(raw, 32)?;
    let last = first
        .checked_add(usable)
        .ok_or_else(|| invalid("GPT usable range overflow"))?;
    require(
        first >= 512
            && first.is_multiple_of(512)
            && usable > 0
            && usable.is_multiple_of(512)
            && last <= disk_bytes,
        "GPT usable range differs from disk geometry",
    )?;
    let mut seen = Vec::<(u32, u64, u64, [u8; 16])>::new();
    let mut target = None;
    // Partitions beside the volume's own, a reserved one not counted.
    let mut beside = 0usize;
    let basic = guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?;
    let reserved = guid_bytes("e3c9e316-0b5c-4db8-817d-f92df00215ae")?;
    for index in 0..count {
        let at = 48 + index * 144;
        let part_number = u32_at(raw, at + 24)?;
        let start = u64_at(raw, at + 8)?;
        let size = u64_at(raw, at + 16)?;
        let kind = &raw[at + 32..at + 48];
        let id: [u8; 16] = raw[at + 48..at + 64].try_into().unwrap();
        if part_number == 0 && size == 0 && kind == [0; 16] {
            require(start == 0 && id == [0; 16], "ambiguous unused GPT entry")?;
            continue;
        }
        let end = start
            .checked_add(size)
            .ok_or_else(|| invalid("GPT partition overflow"))?;
        require(
            u32_at(raw, at)? == 1
                && part_number > 0
                && size > 0
                && start >= first
                && end <= last
                && start.is_multiple_of(512)
                && size.is_multiple_of(512)
                && kind != [0; 16]
                && id != [0; 16]
                && !seen.iter().any(|(n, lo, hi, other)| {
                    part_number == *n || start < *hi && *lo < end || id == *other
                }),
            "duplicate, overlapping or malformed GPT entry",
        )?;
        seen.push((part_number, start, end, id));
        if start == offset && size == length {
            require(
                target.is_none()
                    && kind == basic
                    && (matches!(
                        role,
                        Role::Journal {
                            allow_additional_partitions: true
                        }
                    ) || u64_at(raw, at + 64)? == 0),
                "ambiguous or unsupported target partition",
            )?;
            target = Some((part_number, guid_text(&id)?));
        } else if kind != reserved {
            beside += 1;
        }
    }
    let (partition_number, partition_guid) = target.ok_or_else(|| {
        invalid("single volume extent does not identify a GPT basic-data partition")
    })?;
    Ok((partition_number, partition_guid, beside))
}

/// Pure decoder shared with tests. Native discovery separately requires two
/// identical observations and never deserializes this result as authority.
pub fn binding_from_evidence(
    guid: &str,
    e: &StorageEvidence,
    role: Role,
    windows_disk: u32,
) -> io::Result<GeneralDiskBinding> {
    guid_bytes(guid)?;
    let (number, offset, length) = single_extent(&e.volume_extents)?;
    layout::validate_device(&e.device, number)?;
    require(
        e.disk_length.len() == 8 && e.alignment.len() == 28,
        "incomplete native geometry",
    )?;
    let disk_bytes = u64_at(&e.disk_length, 0)?;
    let raw = &e.gpt_layout;
    // Working storage and a data volume to convert may lie on an MBR disk,
    // which has no GUIDs: its identity is made of the disk's signature and
    // the partition's place (`mbr_layout`). An installed Windows, the
    // shadow, and working storage that must have a disk to itself take a
    // GPT disk only.
    let (partition_number, disk_guid, partition_guid, beside) = if matches!(
        role,
        Role::Source
            | Role::Journal {
                allow_additional_partitions: true
            }
    )
        && crate::mbr_layout::is_mbr_layout(raw)
    {
        let found = crate::mbr_layout::mbr_partition(raw, disk_bytes, offset, length)?;
        // A volume to convert may share its MBR disk with other partitions,
        // as on GPT: the disk's other volumes go offline with it, and what a
        // run asks Windows about them first (the storage catalog, page
        // files, dump destinations) knows an MBR partition by its place.
        // Working storage shares an MBR disk with anything.
        (
            found.partition_number,
            found.disk_guid,
            found.partition_guid,
            found.beside,
        )
    } else {
        let (partition_number, partition_guid, beside) =
            gpt_partition(raw, disk_bytes, offset, length, role)?;
        (
            partition_number,
            guid_text(&raw[8..24])?,
            partition_guid,
            beside,
        )
    };
    let binding = GeneralDiskBinding {
        // A data volume's disk is a dedicated one, or one it shares with
        // other partitions: the layout says which, not the caller.
        layout_profile: match role {
            Role::OfflineWindowsSource => {
                crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            }
            Role::Source if beside > 0 => {
                crate::general_layout::GeneralDiskLayoutProfile::SharedData
            }
            _ => Default::default(),
        },
        disk_number: number,
        volume_guid: guid.to_ascii_lowercase(),
        identity: PartitionIdentity {
            disk_guid,
            partition_guid,
            partition_number,
            disk_bytes,
            partition_offset: offset,
            partition_bytes: length,
            logical_sector_bytes: u32_at(&e.alignment, 16)?,
            physical_sector_bytes: u32_at(&e.alignment, 20)?,
        },
    };
    match role {
        Role::Journal { .. } => binding.validate_working_storage()?,
        _ => binding.validate()?,
    }
    binding.validate_alignment(&e.alignment)?;
    binding.validate_volume_extent(&e.volume_extents)?;
    require(
        e.disk_attributes.len() == 16
            && u32_at(&e.disk_attributes, 0)? == 16
            && u64_at(&e.disk_attributes, 8)? == if role == Role::ShadowReadOnly { 2 } else { 0 },
        "conversion-request discovery disk attributes differ from the explicit role",
    )?;
    match role {
        Role::Source | Role::OfflineWindowsSource | Role::Shadow | Role::ShadowReadOnly => {
            require(
                number != windows_disk,
                "Windows OS disk is excluded from source/shadow roles",
            )?;
            binding.validate_layout(raw)?;
        }
        Role::Journal {
            allow_additional_partitions,
        } => {
            require(
                number != windows_disk || allow_additional_partitions,
                "OS journal storage requires explicit additional-partitions permission",
            )?;
            if !allow_additional_partitions {
                binding.validate_working_storage_layout(raw)?;
            }
        }
    }
    Ok(binding)
}

#[cfg(windows)]
#[path = "discovery_native.rs"]
mod native;
#[cfg(windows)]
pub use native::{discover, observe_volume_space};
