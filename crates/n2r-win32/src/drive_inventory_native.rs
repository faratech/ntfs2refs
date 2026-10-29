use super::*;
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_WRITE_PROTECT, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetLogicalDriveStringsW,
        GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
        GetVolumePathNamesForVolumeNameW, QueryDosDeviceW,
    },
    System::{
        IO::DeviceIoControl, Ioctl::IOCTL_DISK_IS_WRITABLE,
        SystemInformation::GetWindowsDirectoryW,
    },
};

const MAX_REPLY: usize = 1024 * 1024;
const MAX_DISKS: usize = 1024;
const MAX_VOLUMES: usize = 4096;
const MAX_PARTITIONS: usize = 16384;
const MAX_STRING_UNITS: usize = 65536;
const MAX_RETAINED_TEXT: usize = 16 * 1024 * 1024;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn text(buffer: &[u16]) -> io::Result<String> {
    let end = buffer
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| invalid("unterminated native string"))?;
    String::from_utf16(&buffer[..end]).map_err(|_| invalid("invalid native UTF-16"))
}
fn multistring(buffer: &[u16]) -> io::Result<Vec<String>> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while cursor < buffer.len() {
        let count = buffer[cursor..]
            .iter()
            .position(|value| *value == 0)
            .ok_or_else(|| invalid("unterminated native MULTI_SZ"))?;
        if count == 0 {
            return Ok(result);
        }
        if result.len() >= 8192 {
            return Err(invalid("native string count exceeds inventory bound"));
        }
        result.push(
            String::from_utf16(&buffer[cursor..cursor + count])
                .map_err(|_| invalid("invalid native MULTI_SZ UTF-16"))?,
        );
        cursor += count + 1;
    }
    Err(invalid("native MULTI_SZ terminator absent"))
}
fn error(scope: &str, operation: &str, value: io::Error, incomplete: bool) -> InventoryError {
    InventoryError {
        scope: scope.into(),
        operation: operation.into(),
        os_error: value.raw_os_error(),
        message: value.to_string().chars().take(1024).collect(),
        enumeration_incomplete: incomplete,
    }
}
fn open_device(path: &str) -> io::Result<File> {
    // No data write/read access, locks, privilege changes or storage setters.
    OpenOptions::new().access_mode(0).share_mode(7).open(path)
}
fn query(file: &File, code: u32, capacity: usize) -> io::Result<Vec<u8>> {
    if !matches!(
        code,
        0x0007_405c
            | 0x0007_00a0
            | 0x0007_0050
            | 0x0007_00f0
            | 0x0056_0000
            | IOCTL_DISK_IS_WRITABLE
    ) || (capacity == 0 && code != IOCTL_DISK_IS_WRITABLE)
        || (code == IOCTL_DISK_IS_WRITABLE && capacity != 0)
        || capacity > MAX_REPLY
    {
        return Err(invalid("read-only inventory query exceeds bounds"));
    }
    let mut bytes = vec![0u64; capacity.div_ceil(8)];
    let mut returned = 0u32;
    // SAFETY: live borrowed handle; initialized aligned output of advertised
    // capacity; this whitelist contains metadata queries only, no input/setter.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            ptr::null(),
            0,
            if capacity == 0 {
                ptr::null_mut()
            } else {
                bytes.as_mut_ptr().cast()
            },
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if returned as usize > capacity {
        return Err(invalid("native inventory query exceeded output capacity"));
    }
    // SAFETY: returned is checked against initialized allocation above.
    Ok(
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), returned as usize) }
            .to_vec(),
    )
}
fn growing_query(file: &File, code: u32) -> io::Result<Vec<u8>> {
    let mut capacity = 4096;
    loop {
        match query(file, code, capacity) {
            Err(value)
                if matches!(value.raw_os_error(), Some(122 | 234)) && capacity < MAX_REPLY =>
            {
                capacity *= 2
            }
            result => return result,
        }
    }
}
fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(
                at..at
                    .checked_add(4)
                    .ok_or_else(|| invalid("offset overflow"))?,
            )
            .ok_or_else(|| invalid("truncated inventory u32"))?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(
                at..at
                    .checked_add(8)
                    .ok_or_else(|| invalid("offset overflow"))?,
            )
            .ok_or_else(|| invalid("truncated inventory u64"))?
            .try_into()
            .unwrap(),
    ))
}
fn nonnegative(bytes: &[u8], at: usize) -> io::Result<u64> {
    let value = u64_at(bytes, at)?;
    if value > i64::MAX as u64 {
        return Err(invalid("negative Windows disk offset/length"));
    }
    Ok(value)
}
fn guid(bytes: &[u8]) -> io::Result<Option<String>> {
    if bytes.len() != 16 {
        return Err(invalid("native GUID size differs"));
    }
    if bytes == [0; 16] {
        return Ok(None);
    }
    Ok(Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        bytes[8],
        bytes[9],
        hex::encode(&bytes[10..])
    )))
}
fn style(value: u32) -> String {
    match value {
        0 => "MBR".into(),
        1 => "GPT".into(),
        2 => "RAW".into(),
        _ => format!("unknown-{value}"),
    }
}

fn disk_numbers() -> io::Result<Vec<u32>> {
    let mut capacity = MAX_STRING_UNITS;
    let names = loop {
        let mut buffer = vec![0u16; capacity];
        // SAFETY: NULL enumerates DOS device names into the initialized buffer.
        let count =
            unsafe { QueryDosDeviceW(ptr::null(), buffer.as_mut_ptr(), buffer.len() as u32) }
                as usize;
        if count == 0 {
            let value = io::Error::last_os_error();
            if value.raw_os_error() == Some(122) && capacity < MAX_REPLY / 2 {
                capacity *= 2;
                continue;
            }
            return Err(value);
        }
        if count > buffer.len() {
            return Err(invalid("DOS device enumeration exceeded capacity"));
        }
        break multistring(&buffer[..count])?;
    };
    let mut numbers = BTreeSet::new();
    for name in names {
        if let Some(number) = name.strip_prefix("PhysicalDrive") {
            if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            numbers.insert(
                number
                    .parse()
                    .map_err(|_| invalid("physical disk number overflow"))?,
            );
            if numbers.len() > MAX_DISKS {
                return Err(invalid("available disks exceed inventory bound"));
            }
        }
    }
    Ok(numbers.into_iter().collect())
}

fn layout(disk: &mut DiskInventory, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() < 48 {
        return Err(invalid("drive layout header is incomplete"));
    }
    let kind = u32_at(bytes, 0)?;
    let count = u32_at(bytes, 4)? as usize;
    let required = count
        .checked_mul(144)
        .and_then(|value| value.checked_add(48))
        .ok_or_else(|| invalid("drive layout size overflow"))?;
    if count > 4096 || bytes.len() < required {
        return Err(invalid(
            "partition layout count/reply exceeds bounds or is incomplete",
        ));
    }
    disk.partition_style = Some(style(kind));
    if kind == 1 {
        disk.disk_guid = guid(&bytes[8..24])?;
    }
    if kind == 0 {
        disk.mbr_signature = Some(u32_at(bytes, 8)?);
    }
    for index in 0..count {
        let row = &bytes[48 + index * 144..48 + (index + 1) * 144];
        let row_style = u32_at(row, 0)?;
        let number = u32_at(row, 24)?;
        let offset = nonnegative(row, 8);
        let length = nonnegative(row, 16);
        // Unused slots in the MBR layout are not actual partitions.
        if number == 0
            && offset.as_ref().is_ok_and(|value| *value == 0)
            && length.as_ref().is_ok_and(|value| *value == 0)
        {
            continue;
        }
        let mut part = PartitionInventory {
            disk_number: disk.disk_number,
            partition_number: number,
            partition_style: style(row_style),
            offset_bytes: offset.ok(),
            size_bytes: length.ok(),
            partition_guid: None,
            partition_type_guid: None,
            gpt_name: None,
            mbr_type: None,
            mbr_active: None,
            service_partition: (row[29] <= 1).then_some(row[29] != 0),
            volume_guid_paths: vec![],
            mount_paths: vec![],
            filesystem: None,
            label: None,
            read_only: disk.read_only,
            offline: disk.offline,
            contains_running_windows: None,
            is_system: None,
            unsupported_reason: None,
        };
        if row_style != kind
            || number == 0
            || part.offset_bytes.is_none()
            || part.size_bytes == Some(0)
            || part.size_bytes.is_none()
            || part
                .offset_bytes
                .zip(part.size_bytes)
                .and_then(|(at, len)| at.checked_add(len))
                .is_none_or(|end| disk.size_bytes.is_some_and(|size| end > size))
        {
            part.unsupported_reason =
                Some("invalid, unbounded or inconsistent native partition entry".into());
        }
        if row_style == 1 {
            part.partition_type_guid = guid(&row[32..48])?;
            part.partition_guid = guid(&row[48..64])?;
            let name: Vec<_> = row[72..144]
                .chunks_exact(2)
                .map(|value| u16::from_le_bytes(value.try_into().unwrap()))
                .collect();
            part.gpt_name = Some(text(
                &name.iter().copied().chain(Some(0)).collect::<Vec<_>>(),
            )?);
            if matches!(
                part.partition_type_guid.as_deref(),
                Some(
                    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" | "af9b60a0-1431-4f62-bc68-3311714a69ad"
                )
            ) {
                part.unsupported_reason = Some("dynamic/LDM partition is display-only".into());
            }
            if u64_at(row, 64)? & (1u64 << 60) != 0 {
                part.read_only = Some(true);
            }
        } else if row_style == 0 {
            part.mbr_type = Some(row[32]);
            part.mbr_active = (row[33] <= 1).then_some(row[33] != 0);
            if matches!(row[32], 0x05 | 0x0f | 0x85 | 0x42) {
                part.unsupported_reason = Some("extended/dynamic MBR entry is display-only".into());
            }
        } else {
            part.unsupported_reason = Some("unsupported partition style".into());
        }
        disk.partitions.push(part);
    }
    Ok(())
}

fn disk(number: u32) -> DiskInventory {
    let path = format!("\\\\.\\PhysicalDrive{number}");
    let mut result = DiskInventory {
        disk_number: number,
        device_path: path.clone(),
        size_bytes: None,
        partition_style: None,
        disk_guid: None,
        mbr_signature: None,
        read_only: None,
        offline: None,
        contains_running_windows: None,
        is_system: None,
        partitions: vec![],
        errors: vec![],
    };
    let file = match open_device(&path) {
        Ok(value) => value,
        Err(value) => {
            result
                .errors
                .push(error(&path, "open metadata", value, true));
            return result;
        }
    };
    let size = query(&file, 0x0007_405c, 8)
        .and_then(|bytes| nonnegative(&bytes, 0))
        .or_else(|_| query(&file, 0x0007_00a0, 256).and_then(|bytes| nonnegative(&bytes, 24)));
    match size {
        Ok(value) => result.size_bytes = Some(value),
        Err(value) => result
            .errors
            .push(error(&path, "disk length/geometry", value, false)),
    }
    let software_read_only = match query(&file, 0x0007_00f0, 16).and_then(|bytes| {
        if bytes.len() != 16 {
            return Err(invalid("disk attribute reply size differs"));
        }
        u64_at(&bytes, 8)
    }) {
        Ok(value) => {
            result.offline = Some(value & 1 != 0);
            Some(value & 2 != 0)
        }
        Err(value) => {
            result
                .errors
                .push(error(&path, "disk attributes", value, false));
            None
        }
    };
    result.read_only = software_read_only.filter(|value| *value);
    if software_read_only != Some(true) {
        // Provider/hardware protection need not appear in the software attribute
        // bits. This zero-output ANY_ACCESS control only queries writability; it
        // does not request write access, perform a trial write or alter state.
        match query(&file, IOCTL_DISK_IS_WRITABLE, 0) {
            Ok(_) => {
                if software_read_only == Some(false) {
                    result.read_only = Some(false);
                }
            }
            Err(value) if value.raw_os_error() == Some(ERROR_WRITE_PROTECT as i32) => {
                result.read_only = Some(true);
            }
            Err(value) => result
                .errors
                .push(error(&path, "disk writability", value, false)),
        }
    }
    match growing_query(&file, 0x0007_0050).and_then(|bytes| layout(&mut result, &bytes)) {
        Ok(()) => (),
        Err(value) => result
            .errors
            .push(error(&path, "partition layout", value, true)),
    }
    result
}

struct VolumeSearch(HANDLE);
impl Drop for VolumeSearch {
    fn drop(&mut self) {
        // SAFETY: owned volume enumeration handle, closed once.
        unsafe {
            FindVolumeClose(self.0);
        }
    }
}
fn mount_paths(root: &str) -> io::Result<Vec<String>> {
    let name = wide(root);
    let mut capacity = 1024;
    loop {
        let mut buffer = vec![0u16; capacity];
        let mut needed = 0;
        // SAFETY: initialized bounded output and NUL-terminated volume root.
        let ok = unsafe {
            GetVolumePathNamesForVolumeNameW(
                name.as_ptr(),
                buffer.as_mut_ptr(),
                capacity as u32,
                &mut needed,
            )
        };
        if ok != 0 {
            return multistring(&buffer);
        }
        let value = io::Error::last_os_error();
        if value.raw_os_error() == Some(234)
            && needed as usize > capacity
            && needed as usize <= MAX_STRING_UNITS
        {
            capacity = needed as usize;
        } else {
            return Err(value);
        }
    }
}
fn volume(root: String, windows: Option<&str>) -> VolumeInventory {
    let mut result = VolumeInventory {
        contains_running_windows: windows.map(|value| value.eq_ignore_ascii_case(&root)),
        volume_guid_path: root.clone(),
        mount_paths: vec![],
        filesystem: None,
        label: None,
        filesystem_read_only: None,
        extents: vec![],
        errors: vec![],
    };
    match mount_paths(&root) {
        Ok(paths) => result.mount_paths = paths,
        Err(value) => result
            .errors
            .push(error(&root, "mount paths", value, false)),
    }
    let root_w = wide(&root);
    let mut label = [0u16; 256];
    let mut fs = [0u16; 256];
    let (mut serial, mut component, mut flags) = (0, 0, 0);
    // SAFETY: all initialized writable buffers match their advertised lengths.
    if unsafe {
        GetVolumeInformationW(
            root_w.as_ptr(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } != 0
    {
        match text(&label).and_then(|label| text(&fs).map(|filesystem| (label, filesystem))) {
            Ok((label, filesystem)) => {
                result.label = Some(label);
                result.filesystem = Some(filesystem);
                result.filesystem_read_only = Some(flags & 0x0008_0000 != 0);
            }
            Err(value) => result
                .errors
                .push(error(&root, "filesystem text", value, false)),
        }
    } else {
        result.errors.push(error(
            &root,
            "filesystem/label",
            io::Error::last_os_error(),
            false,
        ));
    }
    let extents = open_device(root.trim_end_matches('\\'))
        .and_then(|file| growing_query(&file, 0x0056_0000))
        .and_then(|bytes| {
            let count = u32_at(&bytes, 0)? as usize;
            let required = count
                .checked_mul(24)
                .and_then(|value| value.checked_add(8))
                .ok_or_else(|| invalid("volume extent size overflow"))?;
            if count == 0 || count > 4096 || bytes.len() < required {
                return Err(invalid("volume extent reply incomplete or outside bound"));
            }
            let mut out = Vec::with_capacity(count);
            for index in 0..count {
                let at = 8 + index * 24;
                let offset = nonnegative(&bytes, at + 8)?;
                let length = nonnegative(&bytes, at + 16)?;
                if length == 0 || offset.checked_add(length).is_none() {
                    return Err(invalid("volume extent overflow/empty range"));
                }
                out.push(VolumeExtent {
                    disk_number: u32_at(&bytes, at)?,
                    offset_bytes: offset,
                    length_bytes: length,
                });
            }
            Ok(out)
        });
    match extents {
        Ok(value) => result.extents = value,
        Err(value) => result
            .errors
            .push(error(&root, "volume disk extents", value, false)),
    }
    result
}

fn windows_volume() -> io::Result<String> {
    let mut windows = vec![0u16; 32768];
    // SAFETY: initialized UTF-16 buffers; all calls only query paths.
    let count =
        unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) } as usize;
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count >= windows.len() {
        return Err(invalid("Windows path exceeds bound"));
    }
    let mut mount = vec![0u16; 32768];
    if unsafe { GetVolumePathNameW(windows.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut guid = [0u16; 64];
    if unsafe {
        GetVolumeNameForVolumeMountPointW(mount.as_ptr(), guid.as_mut_ptr(), guid.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    text(&guid)
}

pub(super) fn inventory() -> io::Result<DriveInventory> {
    let numbers = disk_numbers()?;
    let mut result = DriveInventory {
        schema_version: 1,
        disks: vec![],
        volumes: vec![],
        logical_drive_roots: vec![],
        errors: vec![],
        enumeration_complete: true,
        source_authorized: false,
        mutation_authorized: false,
    };
    let windows = match windows_volume() {
        Ok(value) => Some(value),
        Err(value) => {
            result
                .errors
                .push(error("Windows", "running Windows volume", value, false));
            None
        }
    };
    let mut roots = [0u16; 256];
    // SAFETY: writable bounded buffer for drive-root MULTI_SZ.
    let count = unsafe { GetLogicalDriveStringsW(roots.len() as u32, roots.as_mut_ptr()) } as usize;
    if count == 0 || count >= roots.len() {
        result.errors.push(error(
            "logical roots",
            "enumerate",
            if count == 0 {
                io::Error::last_os_error()
            } else {
                invalid("drive roots exceeded bound")
            },
            true,
        ));
    } else {
        match multistring(&roots[..count + 1]) {
            Ok(value) => result.logical_drive_roots = value,
            Err(value) => result
                .errors
                .push(error("logical roots", "decode", value, true)),
        }
    }
    let mut retained = 0usize;
    let mut name = [0u16; 1024];
    // SAFETY: writable initialized volume-name buffer; returned handle owned below.
    let handle = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        result.errors.push(error(
            "volumes",
            "FindFirstVolumeW",
            io::Error::last_os_error(),
            true,
        ));
    } else {
        let _search = VolumeSearch(handle);
        let mut volume_steps = 0usize;
        loop {
            volume_steps += 1;
            if volume_steps > MAX_VOLUMES {
                return Err(invalid("volume enumeration exceeds inventory bound"));
            }
            if result.volumes.len() >= MAX_VOLUMES {
                return Err(invalid("volume count exceeds inventory bound"));
            }
            match text(&name) {
                Ok(root) => {
                    let item = volume(root, windows.as_deref());
                    retained = retained
                        .checked_add(serde_json::to_vec(&item).map_err(io::Error::other)?.len())
                        .ok_or_else(|| invalid("inventory text size overflow"))?;
                    if retained > MAX_RETAINED_TEXT {
                        return Err(invalid("volume text exceeds inventory bound"));
                    }
                    result.volumes.push(item);
                }
                Err(value) => {
                    result
                        .errors
                        .push(error("volumes", "decode volume name", value, true))
                }
            }
            name.fill(0);
            // SAFETY: handle is live and output capacity matches initialized buffer.
            if unsafe { FindNextVolumeW(handle, name.as_mut_ptr(), name.len() as u32) } == 0 {
                let value = io::Error::last_os_error();
                if value.raw_os_error() != Some(18) {
                    result
                        .errors
                        .push(error("volumes", "FindNextVolumeW", value, true));
                }
                break;
            }
        }
    }
    let windows_disks = windows
        .as_deref()
        .and_then(|root| {
            result
                .volumes
                .iter()
                .find(|volume| volume.volume_guid_path.eq_ignore_ascii_case(root))
        })
        .filter(|volume| !volume.extents.is_empty())
        .map(|volume| {
            volume
                .extents
                .iter()
                .map(|extent| extent.disk_number)
                .collect::<BTreeSet<_>>()
        });
    let mut partition_count = 0usize;
    for number in numbers {
        let mut disk = disk(number);
        partition_count = partition_count
            .checked_add(disk.partitions.len())
            .ok_or_else(|| invalid("partition count overflow"))?;
        if partition_count > MAX_PARTITIONS {
            return Err(invalid("total partitions exceed inventory bound"));
        }
        for part in &mut disk.partitions {
            for volume in &result.volumes {
                let matches = volume.extents.iter().any(|extent| {
                    extent.disk_number == number
                        && Some(extent.offset_bytes) == part.offset_bytes
                        && Some(extent.length_bytes) == part.size_bytes
                });
                if !matches {
                    continue;
                }
                if volume.extents.len() != 1 {
                    part.unsupported_reason =
                        Some("spanned/multiple-extent volume is display-only".into());
                }
                let association_bytes = volume
                    .mount_paths
                    .iter()
                    .try_fold(volume.volume_guid_path.len(), |sum, path| {
                        sum.checked_add(path.len())
                            .ok_or_else(|| invalid("mount text size overflow"))
                    })?
                    .checked_add(volume.filesystem.as_ref().map_or(0, String::len))
                    .and_then(|sum| sum.checked_add(volume.label.as_ref().map_or(0, String::len)))
                    .and_then(|sum| sum.checked_mul(6))
                    .and_then(|sum| sum.checked_add(256))
                    .ok_or_else(|| invalid("association text size overflow"))?;
                retained = retained
                    .checked_add(association_bytes)
                    .ok_or_else(|| invalid("inventory text size overflow"))?;
                if retained > MAX_RETAINED_TEXT {
                    return Err(invalid("partition mount text exceeds inventory bound"));
                }
                part.volume_guid_paths.push(volume.volume_guid_path.clone());
                part.mount_paths.extend(volume.mount_paths.clone());
                if part.volume_guid_paths.len() == 1 {
                    part.filesystem = volume.filesystem.clone();
                    part.label = volume.label.clone();
                    part.contains_running_windows = volume.contains_running_windows;
                } else {
                    part.filesystem = None;
                    part.label = None;
                    part.unsupported_reason = Some("multiple volumes map to this partition".into());
                }
                if volume.filesystem_read_only == Some(true) {
                    part.read_only = Some(true);
                }
            }
            part.mount_paths.sort();
            part.mount_paths.dedup();
        }
        disk.contains_running_windows = windows_disks
            .as_ref()
            .map(|numbers| numbers.contains(&number));
        retained = retained
            .checked_add(serde_json::to_vec(&disk).map_err(io::Error::other)?.len())
            .ok_or_else(|| invalid("inventory text size overflow"))?;
        if retained > MAX_RETAINED_TEXT {
            return Err(invalid("disk metadata exceeds inventory bound"));
        }
        result.disks.push(disk);
    }
    result.enumeration_complete = !result
        .errors
        .iter()
        .chain(result.disks.iter().flat_map(|disk| &disk.errors))
        .any(|item| item.enumeration_incomplete);
    // Bound retained UTF-8/JSON output, not just native query allocations.
    if serde_json::to_vec(&result).map_err(io::Error::other)?.len() > MAX_RETAINED_TEXT {
        return Err(invalid("drive inventory exceeds retained-output bound"));
    }
    Ok(result)
}
