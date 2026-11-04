//! Configured system dump destinations, observed afresh by a live owner.
//! Readonly registry/location queries only: no data-file open, setter or issuer.
//! Registry changes require reboot, so this NEVER proves loaded crash-dump roles.
//! The upper owner must separately require its runtime critical-role witness.
//!
//! Primary contracts:
//! https://learn.microsoft.com/troubleshoot/windows-server/performance/memory-dump-file-options
//! https://learn.microsoft.com/windows-server/administration/server-core/server-core-memory-dump
//! https://learn.microsoft.com/windows/win32/wer/wer-settings
//! https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamew
//! https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents
use super::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
use super::{NativeEvent, VOLUME_EXTENTS, control, device_file};
use serde::Serialize;
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME},
    Storage::FileSystem::{GetVolumeNameForVolumeMountPointW, GetVolumePathNameW},
    System::{
        Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ,
            REG_MULTI_SZ, REG_SZ, RegCloseKey, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
        },
        SystemInformation::GetWindowsDirectoryW,
    },
};

const CRASH_KEY: &str = r"SYSTEM\CurrentControlSet\Control\CrashControl";
const LIVE_KEY: &str = r"SYSTEM\CurrentControlSet\Control\CrashControl\LiveKernelReports";
const MAX_VALUES: usize = 64;
const MAX_VALUE_BYTES: usize = 8192;
const MAX_PATH_UNITS: usize = 4096;
const MAX_LOCATIONS: usize = 8;
const MAX_EXTENTS: usize = 16;
const WORKING_RAM_BYTES: u64 = 2 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn text(value: &[u16]) -> io::Result<String> {
    String::from_utf16(value).map_err(|_| invalid("dump location is not valid UTF-16"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct DumpRegistryValue {
    pub name: String,
    pub registry_type: u32,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct DumpRegistrySnapshot {
    pub key: String,
    pub key_present: bool,
    pub key_last_write_filetime: u64,
    pub values: Vec<DumpRegistryValue>,
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: this owns the successful readonly RegOpenKeyExW result.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn key_stamp(key: HKEY) -> io::Result<(u32, u64)> {
    let mut count = 0;
    let mut stamp = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: live readonly registry key and initialized optional output fields.
    let status = unsafe {
        RegQueryInfoKeyW(
            key,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut count,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut stamp,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    require(
        count as usize <= MAX_VALUES,
        "CrashControl value count exceeds its fixed bound",
    )?;
    Ok((
        count,
        u64::from(stamp.dwLowDateTime) | (u64::from(stamp.dwHighDateTime) << 32),
    ))
}
fn registry_snapshot(path: &str, optional: bool) -> io::Result<DumpRegistrySnapshot> {
    let path_w = wide(path);
    let mut raw = ptr::null_mut();
    // SAFETY: fixed machine subkey, query-only64-bit view; no create/set right.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut raw,
        )
    };
    if status == ERROR_FILE_NOT_FOUND && optional {
        return Ok(DumpRegistrySnapshot {
            key: path.into(),
            key_present: false,
            key_last_write_filetime: 0,
            values: Vec::new(),
        });
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let key = Key(raw);
    let opening = key_stamp(key.0)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(opening.0 as usize)
        .map_err(io::Error::other)?;
    for index in 0..=opening.0 {
        let mut name = [0u16; 256];
        let mut name_units = name.len() as u32;
        let mut kind = 0;
        let mut data = vec![0u8; MAX_VALUE_BYTES];
        let mut bytes = data.len() as u32;
        // SAFETY: bounded initialized buffers, live query-only key, synchronous call.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_units,
                ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut bytes,
            )
        };
        if index == opening.0 {
            require(
                status == ERROR_NO_MORE_ITEMS,
                "CrashControl enumeration changed or is incomplete",
            )?;
            break;
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        require(
            name_units > 0
                && (name_units as usize) < name.len()
                && bytes as usize <= MAX_VALUE_BYTES,
            "CrashControl value/name exceeds its fixed bound",
        )?;
        data.truncate(bytes as usize);
        values.push(DumpRegistryValue {
            name: text(&name[..name_units as usize])?,
            registry_type: kind,
            data,
        });
    }
    require(
        key_stamp(key.0)? == opening,
        "CrashControl changed during readonly collection",
    )?;
    values.sort_by_key(|value| value.name.to_ascii_lowercase());
    require(
        !values
            .windows(2)
            .any(|pair| pair[0].name.eq_ignore_ascii_case(&pair[1].name)),
        "CrashControl contains ambiguous duplicate value names",
    )?;
    Ok(DumpRegistrySnapshot {
        key: path.into(),
        key_present: true,
        key_last_write_filetime: opening.1,
        values,
    })
}
fn value<'a>(snapshot: &'a DumpRegistrySnapshot, name: &str) -> Option<&'a DumpRegistryValue> {
    snapshot
        .values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
}
fn dword(snapshot: &DumpRegistrySnapshot, name: &str) -> io::Result<Option<u32>> {
    value(snapshot, name)
        .map(|value| {
            require(
                value.registry_type == REG_DWORD && value.data.len() == 4,
                "CrashControl numeric setting is not an exact REG_DWORD",
            )?;
            Ok(u32::from_le_bytes(
                value.data.as_slice().try_into().map_err(io::Error::other)?,
            ))
        })
        .transpose()
}
fn string(value: &DumpRegistryValue) -> io::Result<String> {
    require(
        matches!(value.registry_type, REG_SZ | REG_EXPAND_SZ)
            && value.data.len() >= 2
            && value.data.len().is_multiple_of(2),
        "Dump destination must be a bounded terminated REG_SZ/REG_EXPAND_SZ",
    )?;
    let units: Vec<u16> = value
        .data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    require(
        units.last() == Some(&0)
            && !units[..units.len() - 1].contains(&0)
            && units.len() <= MAX_PATH_UNITS,
        "Dump destination has missing/embedded terminator or is too long",
    )?;
    let result = text(&units[..units.len() - 1])?;
    require(
        !result.is_empty(),
        "Empty configured dump destination is ambiguous",
    )?;
    Ok(result)
}
fn windows_directory() -> io::Result<String> {
    let mut out = vec![0u16; MAX_PATH_UNITS];
    // SAFETY: bounded initialized output; no process-environment value is trusted.
    let n = unsafe { GetWindowsDirectoryW(out.as_mut_ptr(), out.len() as u32) } as usize;
    require(
        n >= 3
            && n < out.len()
            && ((65..=90).contains(&out[0]) || (97..=122).contains(&out[0]))
            && out[1] == 58
            && out[2] == 92,
        "Actual Windows directory has no supported local DOS route",
    )?;
    text(&out[..n])
}
fn normalize(configured: &str, kind: u32, windows: &str) -> io::Result<String> {
    let mut path = configured.to_owned();
    if kind == REG_EXPAND_SZ {
        for _ in 0..8 {
            let Some(start) = path.find('%') else { break };
            let end = path[start + 1..]
                .find('%')
                .map(|n| n + start + 1)
                .ok_or_else(|| invalid("Unclosed dump environment token"))?;
            let name = &path[start + 1..end];
            let replacement =
                if name.eq_ignore_ascii_case("SystemRoot") || name.eq_ignore_ascii_case("windir") {
                    windows
                } else if name.eq_ignore_ascii_case("SystemDrive") {
                    &windows[..2]
                } else {
                    return Err(invalid(
                        "Dump path depends on an unresolved SYSTEM environment token",
                    ));
                };
            path.replace_range(start..=end, replacement);
        }
    }
    require(!path.contains('%'), "Unexpanded dump path is ambiguous")?;
    if path
        .get(..12)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\SystemRoot\"))
    {
        path = format!("{}\\{}", windows, &path[12..]);
    }
    if let Some(rest) = path.strip_prefix(r"\??\") {
        path = rest.to_owned();
    }
    if path.starts_with(r"\\?\") && !path.starts_with(r"\\?\Volume{") {
        path = path[4..].to_owned();
    }
    let root = if path.starts_with(r"\\?\Volume{") {
        let end = path
            .find("}\\")
            .ok_or_else(|| invalid("Malformed dump volume-GUID route"))?;
        require(
            crate::layout::guid_bytes(&path[11..end])? != [0; 16],
            "Empty dump volume GUID",
        )?;
        end + 2
    } else {
        let b = path.as_bytes();
        require(
            b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\',
            "Dump location is not an unambiguous absolute local DOS/GUID path",
        )?;
        3
    };
    require(
        path.encode_utf16().count() < MAX_PATH_UNITS && !path[root..].is_empty(),
        "Dump path has no bounded location component",
    )?;
    for component in path[root..].split('\\') {
        require(
            !component.is_empty()
                && !matches!(component, "." | "..")
                && !component.ends_with([' ', '.'])
                && !component
                    .chars()
                    .any(|c| c.is_control() || "<>:\"/|?*".contains(c)),
            "Dump path has an unsupported/relative/stream component",
        )?;
        let base = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        require(
            !matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(base.len() == 4
                    && (base.starts_with("COM") || base.starts_with("LPT"))
                    && base.as_bytes()[3].is_ascii_digit()),
            "Dump path contains a DOS device alias",
        )?;
    }
    Ok(path)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct DumpExtent {
    pub disk_number: u32,
    pub offset: u64,
    pub length: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ConfiguredDumpLocation {
    pub setting: String,
    pub configured_path: Option<String>,
    pub effective_path: String,
    pub documented_default_used: bool,
    pub resolved_volume_guid_path: String,
    pub extents: Vec<DumpExtent>,
}
fn volume_route(path: &str) -> io::Result<String> {
    let input = wide(path);
    let mut mount = vec![0u16; MAX_PATH_UNITS];
    let mut guid = [0u16; 64];
    // SAFETY: bounded canonical Win32 input and initialized output. This follows
    // junction/mount chains; unsupported NT paths were refused before this call.
    if unsafe { GetVolumePathNameW(input.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    require(
        mount.iter().any(|unit| *unit == 0),
        "Dump mount route is unterminated",
    )?;
    // SAFETY: NUL-terminated mount root returned above, bounded GUID output.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(mount.as_ptr(), guid.as_mut_ptr(), guid.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let n = guid
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("Dump volume GUID route unterminated"))?;
    let result = text(&guid[..n])?;
    require(
        result.starts_with(r"\\?\Volume{")
            && result.ends_with("}\\")
            && crate::layout::guid_bytes(&result[11..result.len() - 2])? != [0; 16],
        "Dump destination did not resolve to a local volume GUID",
    )?;
    Ok(result)
}
fn location(
    setting: &str,
    configured: Option<&DumpRegistryValue>,
    fallback: &str,
    windows: &str,
    binding: &PartitionSourceBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<ConfiguredDumpLocation> {
    let raw = configured.map(string).transpose()?;
    let effective = normalize(
        raw.as_deref().unwrap_or(fallback),
        configured.map_or(REG_EXPAND_SZ, |value| value.registry_type),
        windows,
    )?;
    let route = volume_route(&effective)?;
    let file = device_file(route.trim_end_matches('\\'), false, false)?;
    let capacity = 8 + 24 * MAX_EXTENTS;
    let bytes = control(
        &file,
        "partition-configured-dump-volume-extents",
        VOLUME_EXTENTS,
        &[],
        capacity,
        events,
    )?;
    require(
        bytes.len() >= 8,
        "Dump volume extent response is incomplete",
    )?;
    let count = crate::layout::u32_at(&bytes, 0)? as usize;
    require(
        count > 0 && count <= MAX_EXTENTS && bytes.len() == 8 + count * 24,
        "Dump volume extents are incomplete, unbounded or ambiguous",
    )?;
    let mut extents = Vec::new();
    extents.try_reserve_exact(count).map_err(io::Error::other)?;
    let target = &binding.storage.identity;
    let target_end = target
        .partition_offset
        .checked_add(target.partition_bytes)
        .ok_or_else(|| invalid("Target extent overflow"))?;
    for i in 0..count {
        let at = 8 + i * 24;
        let extent = DumpExtent {
            disk_number: crate::layout::u32_at(&bytes, at)?,
            offset: crate::layout::u64_at(&bytes, at + 8)?,
            length: crate::layout::u64_at(&bytes, at + 16)?,
        };
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or_else(|| invalid("Dump extent overflow"))?;
        require(
            extent.length > 0 && extent.offset <= i64::MAX as u64 && end <= i64::MAX as u64,
            "Dump extent is empty or outside signed native bounds",
        )?;
        require(
            extent.disk_number != binding.storage.disk_number
                || extent.offset >= target_end
                || end <= target.partition_offset,
            "Configured/potential system dump location overlaps selected partition",
        )?;
        extents.push(extent);
    }
    require(
        volume_route(&effective)? == route,
        "Dump namespace route changed across extent observation",
    )?;
    extents.sort_by_key(|value| (value.disk_number, value.offset, value.length));
    require(
        !extents.windows(2).any(|pair| {
            pair[0].disk_number == pair[1].disk_number
                && pair[0].offset + pair[0].length > pair[1].offset
        }),
        "Dump volume has ambiguous overlapping extents",
    )?;
    Ok(ConfiguredDumpLocation {
        setting: setting.into(),
        configured_path: raw,
        effective_path: effective,
        documented_default_used: configured.is_none(),
        resolved_volume_guid_path: route,
        extents,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ConfiguredDumpObservation {
    pub crash_control: DumpRegistrySnapshot,
    pub live_kernel_reports: DumpRegistrySnapshot,
    pub crash_dump_enabled: u32,
    pub filter_pages: u32,
    pub windows_directory: String,
    pub locations: Vec<ConfiguredDumpLocation>,
    pub configured_locations_outside_target: bool,
    pub runtime_loaded_dump_locations_verified: bool,
    pub current_windows_and_pagefiles_require_separate_live_observation: bool,
    pub serialized_observation_grants_authority: bool,
}

/// Explicit configured-filter policy. Microsoft's built-in BitLocker dump
/// filter transforms dump/hibernation contents; this does not establish which
/// filter image the running kernel loaded. Actual critical-volume and dump
/// destination observations remain independently required by the owner.
/// https://learn.microsoft.com/windows-hardware/drivers/storage/crash-dump-filter-drivers
/// https://devblogs.microsoft.com/oldnewthing/20160913-00/?p=94305
fn require_known_dump_filters(value: &DumpRegistryValue) -> io::Result<()> {
    require(value.registry_type == REG_MULTI_SZ
        && value.data.len() >= 4
        && value.data.len() <= MAX_VALUE_BYTES
        && value.data.len().is_multiple_of(2),
        "DumpFilters must be bounded UTF-16 REG_MULTI_SZ")?;
    let units: Vec<u16> = value.data.chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    require(units.ends_with(&[0, 0]), "DumpFilters lacks its double terminator")?;
    if units.iter().all(|unit| *unit == 0) { return Ok(()); }
    let name = &units[..units.len() - 2];
    require(!name.is_empty() && !name.contains(&0)
        && text(name)?.eq_ignore_ascii_case("dumpfve.sys"),
        "Unknown/custom dump filters require an explicit supported policy")
}

pub(super) fn observe_configured_dump_locations(
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<ConfiguredDumpObservation> {
    binding.validate()?;
    budget.validate()?;
    require(
        budget.ram_bytes >= WORKING_RAM_BYTES && events.len() + MAX_LOCATIONS < 128,
        "Configured dump collector lacks bounded metadata/event workspace",
    )?;
    let crash = registry_snapshot(CRASH_KEY, false)?;
    let live = registry_snapshot(LIVE_KEY, true)?;
    // Unknown text/path settings and custom dump filters are not ignored.
    for item in &crash.values {
        match item.name.to_ascii_lowercase().as_str() {
            "dumpfile" | "dedicateddumpfile" | "minidumpdir" => {
                let _ = string(item)?;
            }
            "dumpfilters" => {
                require_known_dump_filters(item)?;
            }
            "crashdumpenabled"
            | "filterpages"
            | "dumpfilesize"
            | "autoreboot"
            | "logevent"
            | "overwrite"
            | "sendalert"
            | "alwayskeepmemorydump"
            | "ignorepagefilesize"
            | "minidumpscount"
            | "nmicrashdump"
            | "displayparameters"
            | "dumploglevel"
            | "enablelogfile" => {
                let _ = dword(&crash, &item.name)?;
            }
            _ => {
                return Err(invalid(
                    "Unknown CrashControl setting requires an explicit dump-location policy",
                ));
            }
        }
    }
    for item in &live.values {
        require(
            item.name.eq_ignore_ascii_case("LiveKernelReportsPath"),
            "Unknown LiveKernelReports setting requires an explicit location policy",
        )?;
        let _ = string(item)?;
    }
    let mode = dword(&crash, "CrashDumpEnabled")?
        .ok_or_else(|| invalid("Missing CrashDumpEnabled is unknown, not disabled"))?;
    require(
        matches!(mode, 0 | 1 | 2 | 3 | 7),
        "Unknown system crash-dump mode",
    )?;
    let filter = dword(&crash, "FilterPages")?.unwrap_or(0);
    require(
        filter <= 1 && (filter == 0 || mode == 1),
        "Unknown active-dump filtering mode",
    )?;
    let windows = windows_directory()?;
    let mut locations = Vec::new();
    locations
        .try_reserve_exact(MAX_LOCATIONS)
        .map_err(io::Error::other)?;
    // Resolve potential destinations even when mode0/another mode is selected;
    // absence uses documented defaults, never an inference that no writer exists.
    locations.push(location(
        "DumpFile",
        value(&crash, "DumpFile"),
        r"%SystemRoot%\MEMORY.DMP",
        &windows,
        binding,
        events,
    )?);
    locations.push(location(
        "MinidumpDir",
        value(&crash, "MinidumpDir"),
        r"%SystemRoot%\Minidump",
        &windows,
        binding,
        events,
    )?);
    if let Some(dedicated) = value(&crash, "DedicatedDumpFile") {
        locations.push(location(
            "DedicatedDumpFile",
            Some(dedicated),
            "",
            &windows,
            binding,
            events,
        )?);
    }
    locations.push(location(
        "LiveKernelReportsPath",
        value(&live, "LiveKernelReportsPath"),
        r"%SystemRoot%\LiveKernelReports",
        &windows,
        binding,
        events,
    )?);
    // Current configuration may differ from the boot-loaded dump stack. Always
    // include documented Windows defaults as potential routes; the separate
    // runtime witness is still required and is deliberately false below.
    locations.push(location(
        "PotentialDefaultDumpFile",
        None,
        r"%SystemRoot%\MEMORY.DMP",
        &windows,
        binding,
        events,
    )?);
    require(
        registry_snapshot(CRASH_KEY, false)? == crash && registry_snapshot(LIVE_KEY, true)? == live,
        "System dump configuration changed across volume resolution",
    )?;
    Ok(ConfiguredDumpObservation {
        crash_control: crash,
        live_kernel_reports: live,
        crash_dump_enabled: mode,
        filter_pages: filter,
        windows_directory: windows,
        locations,
        configured_locations_outside_target: true,
        runtime_loaded_dump_locations_verified: false,
        current_windows_and_pagefiles_require_separate_live_observation: true,
        serialized_observation_grants_authority: false,
    })
}
