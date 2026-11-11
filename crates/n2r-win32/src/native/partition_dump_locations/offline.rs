//! Explicit offline current-role facts. Positive RAM routes and complete
//! native SystemPagefileInformation replace neither VSS nor an exclusion lease.
use super::*;
use std::{ffi::c_void, os::windows::io::AsRawHandle};
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        buffer: *mut c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}
fn offline_location(
    setting: &str,
    configured: Option<&DumpRegistryValue>,
    fallback: &str,
    windows: &str,
    binding: &PartitionSourceBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<serde_json::Value> {
    let raw = configured.map(string).transpose()?;
    let effective = normalize(
        raw.as_deref().unwrap_or(fallback),
        configured.map_or(REG_EXPAND_SZ, |v| v.registry_type),
        windows,
    )?;
    let mut root = [0u16; 4096];
    if unsafe {
        GetVolumePathNameW(
            wide(&effective).as_ptr(),
            root.as_mut_ptr(),
            root.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let n = root
        .iter()
        .position(|u| *u == 0)
        .ok_or_else(|| invalid("offline critical root unterminated"))?;
    let root = text(&root[..n])?;
    let kind = unsafe { GetDriveTypeW(wide(&root).as_ptr()) };
    if root.len() == 3
        && windows
            .get(..3)
            .is_some_and(|w| w.eq_ignore_ascii_case(&root))
    {
        // Exact current Windows root must have positive SAME held kernel
        // Ramdisk proof even when the actual WinPE drive classification is3.
        let native_ram =
            crate::native::offline_environment::kernel_ram_backing::require_path(&effective)?;
        require(
            native_ram.dos_root.eq_ignore_ascii_case(&root),
            "critical currentRAM native root differs",
        )?;
        // Positive actual current-RAM backing, never a failed extent query.
        require(
            root.len() == 3
                && windows
                    .get(..3)
                    .is_some_and(|w| w.eq_ignore_ascii_case(&root)),
            "unbound noncurrent RAM critical route",
        )?;
        require(
            crate::native::offline_environment::kernel_ram_backing::require_path(&effective)?
                == native_ram,
            "critical currentRAM kernel device proof changed",
        )?;
        let mut closing_root = [0u16; 4096];
        if unsafe {
            GetVolumePathNameW(
                wide(&effective).as_ptr(),
                closing_root.as_mut_ptr(),
                closing_root.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let end = closing_root
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("closing critical RAM root unterminated"))?;
        require(
            text(&closing_root[..end])? == root,
            "critical RAM effective path changed volume during observation",
        )?;
        return Ok(
            serde_json::json!({"setting":setting,"configured_path":raw,"effective_path":effective,
            "documented_default_used":configured.is_none(),"backing":"positively_matched_current_kernel_Ramdisk_GUID_v1",
            "actual_drive_type":kind,"native_ram_backing":native_ram,"ram_root":root,"physical_extents":null,"unqueried_extents_are_not_absence":true}),
        );
    }
    require(
        kind == 3,
        "offline critical route is unknown/remote/removable",
    )?;
    let physical = location(setting, configured, fallback, windows, binding, events)?;
    require(
        physical
            .extents
            .iter()
            .all(|e| e.disk_number != binding.storage.disk_number),
        "offline whole-source-disk route hosts current paging/dump data",
    )?;
    Ok(serde_json::json!({"backing":"complete_native_physical_extents","location":physical}))
}
fn native_pagefiles(
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    windows: &str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<serde_json::Value>> {
    // x64 SYSTEM_PAGEFILE_INFORMATION: fixed32B + counted UTF16 path. The
    // synchronous STATUS_SUCCESS + complete NextEntryOffset chain is required.
    let cap = usize::try_from(budget.ram_bytes / 16).map_err(io::Error::other)?;
    require(
        cap >= 32 && cap <= u32::MAX as usize,
        "native paging observation budget invalid",
    )?;
    let mut raw = vec![0u64; cap.div_ceil(8)];
    let mut returned = 0;
    let status = unsafe {
        NtQuerySystemInformation(
            18,
            raw.as_mut_ptr().cast(),
            u32::try_from(raw.len() * 8).map_err(io::Error::other)?,
            &mut returned,
        )
    };
    require(
        status == 0,
        "native SystemPagefileInformation incomplete/unsupported; no empty-pagefile inference",
    )?;
    require(
        returned as usize <= raw.len() * 8,
        "native pagefile reply exceeds admitted capacity",
    )?;
    if returned == 0 {
        require(
            raw.iter().all(|v| *v == 0),
            "native paging returned unframed nonempty data; no empty inference",
        )?;
        return Ok(Vec::new());
    }
    let bytes = unsafe { std::slice::from_raw_parts(raw.as_ptr().cast::<u8>(), returned as usize) };
    let base = bytes.as_ptr() as usize;
    let mut at = 0usize;
    let mut result = Vec::new();
    loop {
        require(
            at.checked_add(32).is_some_and(|end| end <= bytes.len()),
            "native pagefile row incomplete",
        )?;
        let next = crate::layout::u32_at(bytes, at)? as usize;
        let len = u16::from_le_bytes(
            bytes[at + 16..at + 18]
                .try_into()
                .map_err(io::Error::other)?,
        ) as usize;
        let maximum = u16::from_le_bytes(
            bytes[at + 18..at + 20]
                .try_into()
                .map_err(io::Error::other)?,
        ) as usize;
        let pointer =
            usize::try_from(crate::layout::u64_at(bytes, at + 24)?).map_err(io::Error::other)?;
        let start = pointer
            .checked_sub(base)
            .ok_or_else(|| invalid("pagefile name points outside native reply"))?;
        require(
            len > 0
                && len.is_multiple_of(2)
                && len <= maximum
                && len <= MAX_PATH_UNITS * 2
                && start.checked_add(len).is_some_and(|end| end <= bytes.len()),
            "native pagefile name range invalid",
        )?;
        let units: Vec<u16> = bytes[start..start + len]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        require(
            !units.contains(&0),
            "embedded NUL in native active pagefile name",
        )?;
        let mut data = units
            .iter()
            .chain(std::iter::once(&0))
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        let value = DumpRegistryValue {
            name: "ActualNativePagefile".into(),
            registry_type: REG_SZ,
            data: std::mem::take(&mut data),
        };
        let location = offline_location(
            "NativeSystemPagefileInformation",
            Some(&value),
            "",
            windows,
            binding,
            events,
        )?;
        result.push(serde_json::json!({"path":text(&units)?,"location":location}));
        require(
            result.len() as u64 <= budget.ram_bytes / 8192,
            "native pagefile rows exceed admitted workspace",
        )?;
        if next == 0 {
            break;
        }
        require(
            next >= 32
                && next.is_multiple_of(8)
                && at.checked_add(next).is_some_and(|end| end < bytes.len()),
            "native pagefile chain malformed",
        )?;
        at += next;
    }
    result.sort_by_key(|v| v["path"].as_str().unwrap_or("").to_owned());
    require(
        !result.windows(2).any(|w| w[0]["path"] == w[1]["path"]),
        "duplicate native pagefile route",
    )?;
    Ok(result)
}
pub(in crate::native) fn observe(
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    expected_windows: &str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<serde_json::Value> {
    binding.validate()?;
    budget.validate()?;
    require(
        budget.ram_bytes >= WORKING_RAM_BYTES
            && events.len() + MAX_LOCATIONS < crate::MAX_BATCH_EVENTS,
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
    require(
        windows == expected_windows,
        "offline critical configuration currentWindows differs",
    )?;
    let mut locations = Vec::new();
    locations
        .try_reserve_exact(MAX_LOCATIONS)
        .map_err(io::Error::other)?;
    // Resolve potential destinations even when mode0/another mode is selected;
    // absence uses documented defaults, never an inference that no writer exists.
    locations.push(offline_location(
        "DumpFile",
        value(&crash, "DumpFile"),
        r"%SystemRoot%\MEMORY.DMP",
        &windows,
        binding,
        events,
    )?);
    locations.push(offline_location(
        "MinidumpDir",
        value(&crash, "MinidumpDir"),
        r"%SystemRoot%\Minidump",
        &windows,
        binding,
        events,
    )?);
    if let Some(dedicated) = value(&crash, "DedicatedDumpFile") {
        locations.push(offline_location(
            "DedicatedDumpFile",
            Some(dedicated),
            "",
            &windows,
            binding,
            events,
        )?);
    }
    locations.push(offline_location(
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
    locations.push(offline_location(
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
    let paging = native_pagefiles(binding, budget, &windows, events)?;
    require(
        registry_snapshot(CRASH_KEY, false)? == crash && registry_snapshot(LIVE_KEY, true)? == live,
        "offline configuration changed across native paging query",
    )?;
    Ok(
        serde_json::json!({"kind":"offline-native-current-critical-routes-v1",
        "crash_control":crash,"live_kernel_reports":live,"crash_dump_enabled":mode,"filter_pages":filter,
        "windows_directory":windows,"configured_and_potential_locations":locations,"native_system_pagefiles":paging,
        "all_actual_routes_outside_entire_source_disk":true,"runtime_loaded_dump_driver_locations_proven":false,
        "vss_or_wmi_absence_assumed_clear":false,"source_write_authority":false}),
    )
}
