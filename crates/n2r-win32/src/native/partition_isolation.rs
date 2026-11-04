//! Experimental, read-only observation of one data partition, including a
//! partition sharing the running Windows disk. This module has no writer,
//! offline setter, availability transition, or conversion-admission issuer.
use super::{
    ALIGNMENT, DEVICE, LAYOUT, LENGTH, NativeEvent, VOLUME_EXTENTS, attributes, control,
    device_file,
};
use crate::{general_layout::GeneralDiskBinding, layout};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
};
use windows_sys::Win32::{
    Storage::FileSystem::{GetVolumeNameForVolumeMountPointW, GetVolumePathNameW},
    System::{
        IO::DeviceIoControl,
        ProcessStatus::{ENUM_PAGE_FILE_INFORMATION, EnumPageFilesW},
        SystemInformation::GetWindowsDirectoryW,
    },
};

const PARTITION_OFFLINE: u64 = 0x0800_0000_0000_0000;
const PARTITION_READ_ONLY: u64 = 0x1000_0000_0000_0000;
const NO_DRIVE_LETTER: u64 = 0x8000_0000_0000_0000;
const ALLOWED_ATTRIBUTES: u64 = PARTITION_OFFLINE | PARTITION_READ_ONLY | NO_DRIVE_LETTER;
const GRANULE: u64 = 4096;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(value: bool, message: &str) -> io::Result<()> {
    if value { Ok(()) } else { Err(invalid(message)) }
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("partition observation byte overflow"))
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("partition observation byte overflow"))
}
fn bytes(size: u64) -> io::Result<Vec<u8>> {
    let n = usize::try_from(size)
        .map_err(|_| invalid("partition observation exceeds address space"))?;
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(io::Error::other)?;
    out.resize(n, 0);
    Ok(out)
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// Explicit metadata and I/O limits, not disk/partition/count ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionObservationBudget {
    pub ram_bytes: u64,
    pub native_layout_bytes: u32,
    pub gpt_entry_bytes: u64,
    pub read_buffer_bytes: u32,
}
impl PartitionObservationBudget {
    pub fn validate(self) -> io::Result<()> {
        let work = add(
            add(
                mul(self.gpt_entry_bytes, 8)?,
                mul(u64::from(self.native_layout_bytes), 8)?,
            )?,
            add(mul(u64::from(self.read_buffer_bytes), 2)?, 2 * 1024 * 1024)?,
        )?;
        require(
            self.native_layout_bytes >= 192
                && self.gpt_entry_bytes >= 128
                && self.read_buffer_bytes >= 4096
                && self.read_buffer_bytes.is_multiple_of(4096)
                && work <= self.ram_bytes,
            "partition observation buffers exceed the explicit RAM budget",
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionSourceBinding {
    pub storage: GeneralDiskBinding,
}
impl PartitionSourceBinding {
    pub fn validate(&self) -> io::Result<()> {
        self.storage.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionObservationMode {
    Online,
    ReadOnly,
    Offline,
    OfflineReadOnly,
}
impl PartitionObservationMode {
    fn from_attributes(attributes: u64) -> Self {
        match attributes & (PARTITION_OFFLINE | PARTITION_READ_ONLY) {
            0 => Self::Online,
            PARTITION_READ_ONLY => Self::ReadOnly,
            PARTITION_OFFLINE => Self::Offline,
            _ => Self::OfflineReadOnly,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionVolumeExtent {
    pub disk_number: u32,
    pub offset: u64,
    pub length: u64,
    pub native_bytes: Vec<u8>,
}
fn extent(
    file: &File,
    operation: &str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionVolumeExtent> {
    let raw = control(file, operation, VOLUME_EXTENTS, &[], 1024, events)?;
    let (disk_number, offset, length) = crate::discovery::single_extent(&raw)?;
    Ok(PartitionVolumeExtent {
        disk_number,
        offset,
        length,
        native_bytes: raw,
    })
}

/// This module's complete, resource-bounded readonly layout query. Keep the
/// whole-disk workflow's fixed control-buffer policy unchanged. The requested
/// capacity and its four-observation/event-copy overlap were charged by the
/// explicit eight-times native-layout allowance before allocating here.
fn native_layout(
    file: &File,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    budget.validate()?;
    require(events.len() < 128, "partition layout event budget exceeded")?;
    let retained = events
        .iter()
        .filter(|event| event.operation == "partition-observer-native-gpt")
        .try_fold(0u64, |total, event| add(total, event.output.len() as u64))?;
    // Preserve room for the live/new observation, query and event-copy
    // overlap. A caller retaining extra revalidation batches must drain them;
    // accepting another complete query cannot exceed this fixed RAM allowance.
    require(
        add(retained, mul(u64::from(budget.native_layout_bytes), 4)?)?
            <= mul(u64::from(budget.native_layout_bytes), 8)?,
        "retained partition layout events exhaust their admitted RAM allowance",
    )?;
    let mut output = bytes(u64::from(budget.native_layout_bytes))?;
    let mut returned = 0u32;
    // SAFETY: the caller owns this readonly disk handle; this one synchronous
    // IOCTL_DISK_GET_DRIVE_LAYOUT_EX request has no input or mutation path.
    // Its initialized output allocation has the exact admitted DWORD capacity.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            LAYOUT,
            core::ptr::null(),
            0,
            output.as_mut_ptr().cast(),
            budget.native_layout_bytes,
            &mut returned,
            core::ptr::null_mut(),
        )
    } != 0;
    let error = (!succeeded).then(io::Error::last_os_error);
    require(
        u64::from(returned) <= u64::from(budget.native_layout_bytes),
        "partition layout returned more bytes than its admitted output buffer",
    )?;
    output.truncate(returned as usize);
    let mut recorded = Vec::new();
    recorded
        .try_reserve_exact(output.len())
        .map_err(io::Error::other)?;
    recorded.extend_from_slice(&output);
    events.try_reserve(1).map_err(io::Error::other)?;
    events.push(NativeEvent {
        operation: "partition-observer-native-gpt".into(),
        control_code: LAYOUT,
        input: Vec::new(),
        succeeded,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: recorded,
    });
    if let Some(error) = error {
        return Err(io::Error::new(
            error.kind(),
            format!("partition-observer-native-gpt: {error}"),
        ));
    }
    // The GPT parser below still requires the ENTIRE native partition array
    // and its exact correspondence to both CRC-checked raw entry arrays.
    Ok(output)
}

fn overlap(a: &PartitionVolumeExtent, binding: &GeneralDiskBinding) -> io::Result<bool> {
    let p = &binding.identity;
    Ok(a.disk_number == binding.disk_number
        && a.offset < add(p.partition_offset, p.partition_bytes)?
        && p.partition_offset < add(a.offset, a.length)?)
}
fn windows_extent(events: &mut Vec<NativeEvent>) -> io::Result<PartitionVolumeExtent> {
    let mut value = vec![0u16; 32768];
    // SAFETY: initialized writable UTF-16 buffer; synchronous Windows query.
    let n = unsafe { GetWindowsDirectoryW(value.as_mut_ptr(), value.len() as u32) } as usize;
    require(
        n >= 3 && n < value.len() && value[1] == u16::from(b':') && value[2] == u16::from(b'\\'),
        "current Windows volume cannot be resolved",
    )?;
    let letter = char::from_u32(u32::from(value[0]))
        .ok_or_else(|| invalid("invalid Windows drive letter"))?;
    require(
        letter.is_ascii_alphabetic(),
        "current Windows path has no local drive root",
    )?;
    let file = device_file(&format!("\\\\.\\{letter}:"), false, false)?;
    extent(&file, "partition-observer-current-windows-extents", events)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PagingFileLocation {
    pub path_utf16: Vec<u16>,
    pub extent: Option<PartitionVolumeExtent>,
    pub resolution_error: Option<i32>,
    pub resolved: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PagingObservation {
    pub enumeration_succeeded: bool,
    pub enumeration_error: Option<i32>,
    pub all_locations_resolved: bool,
    pub source_hosts_active_pagefile: bool,
    pub locations: Vec<PagingFileLocation>,
}
struct PagingContext {
    paths: Vec<Vec<u16>>,
    maximum_units: usize,
    units: usize,
    failed: bool,
}
unsafe extern "system" fn pagefile_callback(
    context: *mut core::ffi::c_void,
    _info: *mut ENUM_PAGE_FILE_INFORMATION,
    name: *const u16,
) -> i32 {
    if context.is_null() || name.is_null() {
        return 0;
    }
    // SAFETY: EnumPageFilesW supplies the live context for this synchronous call.
    let context = unsafe { &mut *context.cast::<PagingContext>() };
    let mut n = 0usize;
    while n < 32768 {
        // SAFETY: the callback's filename is NUL terminated by Windows; bound
        // it independently before constructing any slice or allocation.
        if unsafe { *name.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    if n == 0
        || n == 32768
        || context
            .units
            .checked_add(n)
            .is_none_or(|v| v > context.maximum_units)
        || context.paths.try_reserve(1).is_err()
    {
        context.failed = true;
        return 0;
    }
    let mut path = Vec::new();
    if path.try_reserve_exact(n).is_err() {
        context.failed = true;
        return 0;
    }
    for at in 0..n {
        // SAFETY: the bounded filename prefix remains live until callback return.
        path.push(unsafe { *name.add(at) });
    }
    context.units += n;
    context.paths.push(path);
    1
}
fn paging(
    binding: &GeneralDiskBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PagingObservation> {
    let maximum_units = usize::try_from(budget.gpt_entry_bytes / 8)
        .map_err(|_| invalid("paging path budget overflow"))?;
    let mut context = PagingContext {
        paths: Vec::new(),
        maximum_units,
        units: 0,
        failed: false,
    };
    // SAFETY: callback and context remain live until this synchronous call ends.
    let ok = unsafe {
        EnumPageFilesW(
            Some(pagefile_callback),
            (&mut context as *mut PagingContext).cast(),
        )
    } != 0;
    let error = (!ok)
        .then(|| io::Error::last_os_error().raw_os_error())
        .flatten();
    let mut result = PagingObservation {
        enumeration_succeeded: ok && !context.failed,
        enumeration_error: error,
        all_locations_resolved: ok && !context.failed,
        source_hosts_active_pagefile: false,
        locations: Vec::new(),
    };
    context.paths.sort();
    for name in context.paths {
        let resolved = (|| -> io::Result<PartitionVolumeExtent> {
            let name = String::from_utf16(&name)
                .map_err(|_| invalid("pagefile path encoding cannot be resolved"))?;
            let name = name.strip_prefix("\\??\\").unwrap_or(&name);
            let input = wide(name);
            let mut root = vec![0u16; 32768];
            // SAFETY: bounded NUL-terminated input and initialized output buffer.
            if unsafe { GetVolumePathNameW(input.as_ptr(), root.as_mut_ptr(), root.len() as u32) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            let count = root
                .iter()
                .position(|v| *v == 0)
                .ok_or_else(|| invalid("pagefile volume path is unterminated"))?;
            require(
                count == 3 && root[1] == u16::from(b':') && root[2] == u16::from(b'\\'),
                "pagefile volume requires an unresolved mounted-folder route",
            )?;
            let root = String::from_utf16(&root[..2])
                .map_err(|_| invalid("pagefile drive cannot be decoded"))?;
            let file = device_file(&format!("\\\\.\\{root}"), false, false)?;
            extent(&file, "partition-observer-active-pagefile-extents", events)
        })();
        match resolved {
            Ok(value) => {
                result.source_hosts_active_pagefile |= overlap(&value, binding)?;
                result.locations.push(PagingFileLocation {
                    path_utf16: name,
                    extent: Some(value),
                    resolution_error: None,
                    resolved: true,
                });
            }
            Err(error) => {
                result.all_locations_resolved = false;
                result.locations.push(PagingFileLocation {
                    path_utf16: name,
                    extent: None,
                    resolution_error: error.raw_os_error(),
                    resolved: false,
                });
            }
        }
    }
    Ok(result)
}

/// Complete CRC-checked GPT bytes are diagnostic evidence, not an exclusion lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionGptObservation {
    pub primary_header: Vec<u8>,
    pub backup_header: Vec<u8>,
    pub entries: Vec<u8>,
    pub entry_bytes: u32,
    pub entry_count: u32,
    pub target_slot: u32,
    pub target_attributes: u64,
    pub sibling_entries_sha256: String,
    pub native_layout: Vec<u8>,
    pub primary_crc_valid: bool,
    pub backup_crc_valid: bool,
    pub entry_arrays_equal: bool,
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320u32 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn read_at(file: &mut File, offset: u64, size: u64, disk_bytes: u64) -> io::Result<Vec<u8>> {
    require(
        add(offset, size)? <= disk_bytes,
        "GPT metadata read escapes physical disk",
    )?;
    let mut value = bytes(size)?;
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut value)?;
    Ok(value)
}
fn header(value: &[u8], own_lba: u64, other_lba: u64, disk_guid: &[u8; 16]) -> io::Result<()> {
    require(
        value.len() >= 92 && &value[..8] == b"EFI PART" && layout::u32_at(value, 8)? == 0x0001_0000,
        "raw GPT signature/revision differs",
    )?;
    let n = usize::try_from(layout::u32_at(value, 12)?)
        .map_err(|_| invalid("GPT header size overflow"))?;
    require(
        (92..=value.len()).contains(&n)
            && layout::u32_at(value, 20)? == 0
            && layout::u64_at(value, 24)? == own_lba
            && layout::u64_at(value, 32)? == other_lba
            && &value[56..72] == disk_guid,
        "raw GPT header identity or bounds differ",
    )?;
    let mut checked = value[..n].to_vec();
    checked[16..20].fill(0);
    require(
        crc32(&checked) == layout::u32_at(value, 16)?,
        "raw GPT header CRC differs",
    )
}
fn gpt(
    file: &mut File,
    binding: &GeneralDiskBinding,
    budget: PartitionObservationBudget,
    native: Vec<u8>,
    target_type: [u8; 16],
) -> io::Result<PartitionGptObservation> {
    let identity = &binding.identity;
    let sector = u64::from(identity.logical_sector_bytes);
    require(
        identity.disk_bytes.is_multiple_of(sector),
        "disk has a partial logical sector",
    )?;
    let last_lba = identity.disk_bytes / sector - 1;
    let disk_guid = layout::guid_bytes(&identity.disk_guid)?;
    let primary = read_at(file, sector, sector, identity.disk_bytes)?;
    let backup = read_at(file, mul(last_lba, sector)?, sector, identity.disk_bytes)?;
    header(&primary, 1, last_lba, &disk_guid)?;
    header(&backup, last_lba, 1, &disk_guid)?;
    let count = layout::u32_at(&primary, 80)?;
    let entry = layout::u32_at(&primary, 84)?;
    require(
        count > 0 && entry >= 128 && entry.is_multiple_of(128),
        "raw GPT entry geometry differs",
    )?;
    let entry_len = mul(u64::from(count), u64::from(entry))?;
    require(
        entry_len <= budget.gpt_entry_bytes,
        "complete GPT array exceeds explicit metadata budget",
    )?;
    require(
        primary[8..16] == backup[8..16]
            && primary[40..72] == backup[40..72]
            && primary[80..92] == backup[80..92],
        "primary/backup GPT common fields differ",
    )?;
    let first = layout::u64_at(&primary, 40)?;
    let last = layout::u64_at(&primary, 48)?;
    require(
        first > 1 && first <= last && last < last_lba,
        "raw GPT usable interval differs",
    )?;
    let rounded = entry_len
        .div_ceil(sector)
        .checked_mul(sector)
        .ok_or_else(|| invalid("GPT entry alignment overflow"))?;
    let primary_array = layout::u64_at(&primary, 72)?;
    let backup_array = layout::u64_at(&backup, 72)?;
    let array_sectors = rounded / sector;
    require(
        primary_array >= 2
            && add(primary_array, array_sectors)? <= first
            && backup_array > last
            && add(backup_array, array_sectors)? <= last_lba,
        "GPT metadata arrays overlap usable partitions or a header",
    )?;
    let mut entries = read_at(
        file,
        mul(layout::u64_at(&primary, 72)?, sector)?,
        rounded,
        identity.disk_bytes,
    )?;
    let mut duplicate = read_at(
        file,
        mul(layout::u64_at(&backup, 72)?, sector)?,
        rounded,
        identity.disk_bytes,
    )?;
    entries.truncate(entry_len as usize);
    duplicate.truncate(entry_len as usize);
    require(
        entries == duplicate && crc32(&entries) == layout::u32_at(&primary, 88)?,
        "raw GPT entry arrays or CRC differ",
    )?;
    require(
        native.len() >= 48 && layout::u32_at(&native, 0)? == 1 && native[8..24] == disk_guid,
        "native GPT header differs",
    )?;
    let native_count = layout::u32_at(&native, 4)? as usize;
    require(
        native_count > 0
            && native_count
                .checked_mul(144)
                .and_then(|n| n.checked_add(48))
                == Some(native.len())
            && layout::u64_at(&native, 24)? == mul(first, sector)?
            && layout::u64_at(&native, 32)? == mul(last - first + 1, sector)?
            && layout::u32_at(&native, 40)? == count,
        "native GPT layout is incomplete or has different usable bounds",
    )?;
    let basic = target_type;
    let target_guid = layout::guid_bytes(&identity.partition_guid)?;
    let mut seen = Vec::<([u8; 16], u64, u64)>::new();
    let mut target = None;
    let mut siblings = Sha256::new();
    for (index, raw) in entries.chunks_exact(entry as usize).enumerate() {
        let kind: [u8; 16] = raw[..16].try_into().unwrap();
        if kind == [0; 16] {
            require(
                raw.iter().all(|b| *b == 0),
                "ambiguous unused raw GPT entry",
            )?;
            siblings.update((index as u64).to_le_bytes());
            siblings.update(raw);
            continue;
        }
        let id: [u8; 16] = raw[16..32].try_into().unwrap();
        let lo = layout::u64_at(raw, 32)?;
        let hi = layout::u64_at(raw, 40)?;
        require(
            id != [0; 16]
                && lo >= first
                && lo <= hi
                && hi <= last
                && !seen
                    .iter()
                    .any(|(other, a, b)| *other == id || lo <= *b && *a <= hi),
            "duplicate or overlapping raw GPT partition",
        )?;
        seen.try_reserve(1).map_err(io::Error::other)?;
        seen.push((id, lo, hi));
        let mut found = None;
        for n in 0..native_count {
            let at = 48 + n * 144;
            if native[at + 48..at + 64] == id {
                require(found.is_none(), "duplicate native GPT partition GUID")?;
                found = Some(at);
            }
        }
        let at =
            found.ok_or_else(|| invalid("raw GPT entry is absent from complete native layout"))?;
        require(
            layout::u32_at(&native, at)? == 1
                && native[at + 32..at + 48] == kind
                && layout::u64_at(&native, at + 8)? == mul(lo, sector)?
                && layout::u64_at(&native, at + 16)? == mul(hi - lo + 1, sector)?
                && layout::u64_at(&native, at + 64)? == layout::u64_at(raw, 48)?
                && native[at + 72..at + 144] == raw[56..128],
            "raw/native GPT entry fields differ",
        )?;
        if id == target_guid {
            let attributes = layout::u64_at(raw, 48)?;
            require(
                target.is_none()
                    && kind == basic
                    && attributes & !ALLOWED_ATTRIBUTES == 0
                    && layout::u32_at(&native, at + 24)? == identity.partition_number
                    && mul(lo, sector)? == identity.partition_offset
                    && mul(hi - lo + 1, sector)? == identity.partition_bytes,
                "source is not the exact nonrequired basic data partition",
            )?;
            target = Some((
                u32::try_from(index + 1).map_err(|_| invalid("GPT slot overflow"))?,
                attributes,
            ));
        } else {
            siblings.update((index as u64).to_le_bytes());
            siblings.update(raw);
        }
    }
    let native_used = (0..native_count)
        .filter(|i| native[48 + i * 144 + 32..48 + i * 144 + 48] != [0; 16])
        .count();
    require(
        native_used == seen.len(),
        "native GPT has entries absent from the CRC-checked disk array",
    )?;
    let (target_slot, target_attributes) =
        target.ok_or_else(|| invalid("bound source partition not present"))?;
    Ok(PartitionGptObservation {
        primary_header: primary,
        backup_header: backup,
        entries,
        entry_bytes: entry,
        entry_count: count,
        target_slot,
        target_attributes,
        sibling_entries_sha256: hex::encode(siblings.finalize()),
        native_layout: native,
        primary_crc_valid: true,
        backup_crc_valid: true,
        entry_arrays_equal: true,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionIsolationObservation {
    pub schema_version: u32,
    pub profile: &'static str,
    pub binding: PartitionSourceBinding,
    pub disk_device: Vec<u8>,
    pub disk_length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub disk_attributes: u64,
    pub gpt: PartitionGptObservation,
    /// Protection bits observed in GPT, not a provider runtime-offline claim.
    pub gpt_mode: PartitionObservationMode,
    pub windows_volume: PartitionVolumeExtent,
    pub source_volume_extent: Option<PartitionVolumeExtent>,
    pub source_volume_open_error: Option<i32>,
    pub source_volume_route_observed: bool,
    pub paging: PagingObservation,
    pub dump_configuration_collected: bool,
    pub conversion_admitted: bool,
    pub grants_isolation_or_recovery_authority: bool,
}
fn observe(
    file: &mut File,
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionIsolationObservation> {
    observe_with_type(
        file,
        binding,
        budget,
        events,
        layout::guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?,
    )
}

/// New explicit private-type READONLY profile; never a write/admission issuer.
pub(super) fn observe_private(
    file: &mut File,
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionIsolationObservation> {
    let mut value = observe_with_type(
        file,
        binding,
        budget,
        events,
        layout::guid_bytes("b627aadb-a893-48b6-aa0b-71e5f30ee370")?,
    )?;
    require(
        value.gpt.target_attributes == 0,
        "private owner profile requires unchanged zero target attributes",
    )?;
    value.profile = "partition_private_owner_foundation_v1";
    Ok(value)
}

pub(super) fn same_private_identity(
    a: &PartitionIsolationObservation,
    b: &PartitionIsolationObservation,
) -> bool {
    a.binding == b.binding
        && a.disk_device == b.disk_device
        && a.disk_length == b.disk_length
        && a.alignment == b.alignment
        && a.disk_attributes == b.disk_attributes
        && a.gpt == b.gpt
        && a.windows_volume == b.windows_volume
        && a.paging == b.paging
}
fn observe_with_type(
    file: &mut File,
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
    target_type: [u8; 16],
) -> io::Result<PartitionIsolationObservation> {
    binding.validate()?;
    budget.validate()?;
    let storage = &binding.storage;
    let windows = windows_extent(events)?;
    require(
        !overlap(&windows, storage)?,
        "running Windows partition cannot be a source",
    )?;
    let device = control(file, "partition-observer-device", DEVICE, &[], 12, events)?;
    layout::validate_device(&device, storage.disk_number)?;
    let length = control(
        file,
        "partition-observer-disk-length",
        LENGTH,
        &[],
        8,
        events,
    )?;
    require(
        length.len() == 8 && layout::u64_at(&length, 0)? == storage.identity.disk_bytes,
        "partition observer disk length differs",
    )?;
    let mut query = [0u8; 12];
    query[0] = 6;
    let alignment = control(
        file,
        "partition-observer-alignment",
        ALIGNMENT,
        &query,
        28,
        events,
    )?;
    storage.validate_alignment(&alignment)?;
    let disk_attributes = attributes(file, events)?;
    require(
        disk_attributes == 0,
        "partition-scoped observation requires the physical disk to remain online/writable",
    )?;
    let native = native_layout(file, budget, events)?;
    let gpt = gpt(file, storage, budget, native, target_type)?;
    let mode = PartitionObservationMode::from_attributes(gpt.target_attributes);
    let (volume, volume_error) = match device_file(&storage.volume_path()?, false, false) {
        Ok(volume) => {
            let value = extent(&volume, "partition-observer-source-volume-extents", events)?;
            require(
                value.disk_number == storage.disk_number
                    && value.offset == storage.identity.partition_offset
                    && value.length == storage.identity.partition_bytes,
                "source volume GUID resolves to a different partition",
            )?;
            (Some(value), None)
        }
        // An offline provider can remove the volume namespace without setting
        // the GPT offline bit. Missing volume proof never admits isolation.
        Err(error) => (None, error.raw_os_error()),
    };
    let paging = paging(storage, budget, events)?;
    require(
        !paging.source_hosts_active_pagefile,
        "an active paging-file partition cannot be a source",
    )?;
    Ok(PartitionIsolationObservation {
        schema_version: 1,
        profile: "experimental_partition_readonly_v1",
        binding: binding.clone(),
        disk_device: device,
        disk_length: length,
        alignment,
        disk_attributes,
        gpt,
        gpt_mode: mode,
        windows_volume: windows,
        source_volume_route_observed: volume.is_some(),
        source_volume_extent: volume,
        source_volume_open_error: volume_error,
        paging,
        dump_configuration_collected: false,
        conversion_admitted: false,
        grants_isolation_or_recovery_authority: false,
    })
}

/// Actual readonly raw-disk owner with partition-relative bounds. No `Write`
/// implementation or setter can be obtained from it. Online contents may change;
/// unchanged layout is not a claim that payload bytes are frozen.
pub struct PartitionScopedReader {
    file: File,
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    observation: PartitionIsolationObservation,
    buffer: Vec<u8>,
    position: u64,
    native_bytes_read: u64,
}

/// Prevent the diagnostic's metadata report from becoming a filesystem write
/// on its selected source. Sibling partitions on the same disk remain usable.
pub fn metadata_destination_outside_source(
    binding: &PartitionSourceBinding,
    existing_parent: &Path,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionVolumeExtent> {
    binding.validate()?;
    let path: Vec<u16> = existing_parent
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    require(
        path.len() <= 32768,
        "metadata destination path exceeds the Windows namespace",
    )?;
    let mut root = vec![0u16; 32768];
    let mut guid = vec![0u16; 32768];
    // SAFETY: bounded NUL-terminated input and initialized UTF-16 outputs.
    if unsafe { GetVolumePathNameW(path.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetVolumePathNameW returned a bounded NUL-terminated root.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(root.as_ptr(), guid.as_mut_ptr(), guid.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let n = guid
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| invalid("metadata volume GUID is unterminated"))?;
    let path = String::from_utf16(&guid[..n])
        .map_err(|_| invalid("metadata volume GUID cannot be decoded"))?;
    let volume = device_file(path.trim_end_matches('\\'), false, false)?;
    let value = extent(
        &volume,
        "partition-observer-metadata-output-extents",
        events,
    )?;
    require(
        !overlap(&value, &binding.storage)?,
        "metadata output is on the selected source partition",
    )?;
    Ok(value)
}
impl PartitionScopedReader {
    pub fn open(
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        budget.validate()?;
        let mut file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
            false,
            false,
        )?;
        let before = observe(&mut file, &binding, budget, events)?;
        let after = observe(&mut file, &binding, budget, events)?;
        require(
            before == after,
            "partition identity, siblings, attributes or critical routes changed while opening",
        )?;
        Ok(Self {
            file,
            binding,
            budget,
            observation: after,
            buffer: bytes(u64::from(budget.read_buffer_bytes))?,
            position: 0,
            native_bytes_read: 0,
        })
    }
    pub fn observation(&self) -> &PartitionIsolationObservation {
        &self.observation
    }
    pub fn byte_len(&self) -> u64 {
        self.binding.storage.identity.partition_bytes
    }
    pub fn native_bytes_read(&self) -> u64 {
        self.native_bytes_read
    }
    pub fn revalidate(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let actual = observe(&mut self.file, &self.binding, self.budget, events)?;
        require(
            actual == self.observation,
            "partition identity, siblings, protection or critical routes changed",
        )
    }
}
impl Read for PartitionScopedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output.len().min(self.buffer.len() - prefix).min(
            usize::try_from((self.byte_len() - self.position).min(self.buffer.len() as u64))
                .map_err(|_| invalid("read size overflow"))?,
        );
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        require(
            add(aligned, count as u64)? <= self.byte_len(),
            "aligned partition read escapes selected source",
        )?;
        self.file.seek(SeekFrom::Start(add(
            self.binding.storage.identity.partition_offset,
            aligned,
        )?))?;
        self.file.read_exact(&mut self.buffer[..count])?;
        self.native_bytes_read = add(self.native_bytes_read, count as u64)?;
        output[..wanted].copy_from_slice(&self.buffer[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}
impl Seek for PartitionScopedReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let at = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.byte_len()) + i128::from(v),
        };
        require(
            at >= 0 && at <= i128::from(self.byte_len()),
            "seek escapes selected partition",
        )?;
        self.position = at as u64;
        Ok(self.position)
    }
}
