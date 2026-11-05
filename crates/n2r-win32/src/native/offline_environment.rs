//! Read-only environment facts for a future offline boot lane. No constructor
//! here issues source admission, exclusion, restoration or write authority.
pub use super::partition_isolation::offline::{OfflinePreparedTerminalGuard,OfflineTerminalReadonlyVolume,OfflinePreparedTerminalReceipt};
pub use super::partition_isolation::offline::OfflinePreparedReplayQualification;
pub use super::partition_isolation::offline::OfflinePreparedClosedQualification;
pub use super::partition_isolation::offline::{OfflineOwningEnvironment,OfflineOwningFacts,OfflineSourcePhysicalFacts};
pub use super::partition_isolation::offline::{OfflineFreshWitness,OfflinePagedNtfsObservation,OfflineReadonlyNtfsPhase};
pub use super::partition_isolation::offline::{OfflinePreparedAvailableSource,OfflinePreparedTerminalSource,OfflinePreparedSource,OfflinePreparedJournalQualification,OfflinePreparedBootGuardRequirements};
use super::{NativeEvent, control, device_file};
use crate::general_layout::GeneralDiskBinding;
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io, os::windows::fs::OpenOptionsExt, path::Path, ptr};
use windows_sys::Win32::{
    Storage::FileSystem::{GetDriveTypeW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW},
    System::{
        Registry::{
            HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, RegCloseKey, RegOpenKeyExW,
        },
        SystemInformation::{
            GetFirmwareType, GetWindowsDirectoryW, GlobalMemoryStatusEx, MEMORYSTATUSEX,
            OSVERSIONINFOW,
        },
    },
};

#[path = "offline_environment_wmi.rs"]
mod wmi;
#[path="kernel_ram_backing.rs"]
pub(crate) mod kernel_ram_backing;
pub use kernel_ram_backing::{KernelRamBackingFacts,KernelRamBackingObservation,NativeNameObservation,Legacy52Observation};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut OSVERSIONINFOW) -> i32;
}
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeBudget {
    /// Collector workspace only; the lab caller reserves worker stacks apart.
    pub ram_bytes: u64,
    pub maximum_json_bytes: u64,
    /// Aggregate ordinary component bytes hashed, not per-file allowance.
    pub maximum_component_bytes: u64,
}
impl ProbeBudget {
    pub fn validate(self) -> io::Result<()> {
        if self.ram_bytes < 16 * 1024 * 1024
            || self.maximum_json_bytes == 0
            || self.maximum_json_bytes > self.ram_bytes / 4
            || self.maximum_component_bytes > i64::MAX as u64
        {
            return Err(bad("explicit bounded offline-observation budget required"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Failure {
    pub native_error: Option<i32>,
    pub detail: String,
}
impl Failure {
    fn from(error: io::Error) -> Self {
        Self {
            native_error: error.raw_os_error(),
            detail: error.to_string(),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Fact<T> {
    pub value: Option<T>,
    pub failure: Option<Failure>,
}
impl<T> Fact<T> {
    fn result(value: io::Result<T>) -> Self {
        match value {
            Ok(value) => Self {
                value: Some(value),
                failure: None,
            },
            Err(error) => Self {
                value: None,
                failure: Some(Failure::from(error)),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQuery {
    /// Only a local DOS volume or canonical Volume GUID route is accepted.
    pub volume_path: String,
    pub expected_binding: Option<GeneralDiskBinding>,
}
#[derive(Debug, Serialize)]
pub struct VolumeQuery {
    pub path: String,
    pub open: Fact<bool>,
    pub controls: Vec<NativeEvent>,
    pub decoded_physical_extents: Option<Vec<PhysicalExtent>>,
    pub decode_error: Option<String>,
    pub expected_partition_identity_coordinates_match: Option<bool>,
    pub handles_closed: bool,
}
#[derive(Debug, Serialize)]
pub struct PhysicalExtent {
    pub disk_number: u32,
    pub offset: u64,
    pub length: u64,
}
#[derive(Debug, Serialize)]
pub struct MiniNtObservation {
    pub present: Option<bool>,
    pub registry_status: u32,
    pub query_only: bool,
}
#[derive(Debug, Serialize)]
pub struct ComponentObservation {
    pub path: String,
    pub actual_file_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub failure: Option<Failure>,
    pub version_collected: bool,
    pub authenticode_collected: bool,
    pub held_object_name_query:Option<NativeNameObservation>,
    pub legacy_file_info52_query:Option<Legacy52Observation>,
    pub file_id128_qualification_failure:Option<String>,
}
#[derive(Debug, Serialize)]
pub struct VssAvailability {
    pub attempted_volume_guid_route: Option<String>,
    pub result: Option<crate::vss_observation::Observation>,
    pub failure: Option<Failure>,
    pub catalog_clear_established: bool,
}
#[derive(Debug, Serialize)]
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub budget: ProbeBudget,
    pub windows_directory: Fact<String>,
    pub windows_volume_root: Fact<String>,
    pub current_volume_guid_root: Fact<String>,
    pub drive_type: Option<u32>,
    pub drive_type_name: &'static str,
    pub mini_nt: MiniNtObservation,
    pub firmware_type: Fact<u32>,
    pub rtl_get_version_status: i32,
    pub running_kernel_version: Option<[u32; 3]>,
    pub current_volume: Option<VolumeQuery>,
    pub native_kernel_ram_backing:Option<KernelRamBackingObservation>,
    pub positive_ramdisk_reported_by_get_drive_type: bool,
    pub native_physical_extents_reported: bool,
    pub backing_classification: &'static str,
    pub selected_source: Option<VolumeQuery>,
    pub storage_wmi: wmi::Availability,
    pub vss: VssAvailability,
    pub components: Vec<ComponentObservation>,
    pub component_bytes_hashed: u64,
    pub component_read_budget_debited_bytes: u64,
    pub all_direct_volume_handles_closed: bool,
    pub critical_roles_clear: bool,
    pub offline_environment_qualified: bool,
    pub source_write_requests: u64,
    pub grants_conversion_or_recovery_authority: bool,
}

fn windows_directory() -> io::Result<String> {
    let mut units = vec![0u16; 32768];
    // SAFETY: owned initialized UTF16 output, retained for synchronous call.
    let count = unsafe { GetWindowsDirectoryW(units.as_mut_ptr(), units.len() as u32) } as usize;
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count >= units.len() {
        return Err(bad("Windows directory exceeds bounded buffer"));
    }
    String::from_utf16(&units[..count]).map_err(io::Error::other)
}
fn volume_root(path: &str) -> io::Result<String> {
    let path = wide(path);
    let mut units = vec![0u16; 32768];
    // SAFETY: NUL-terminated input and owned initialized synchronous output.
    if unsafe { GetVolumePathNameW(path.as_ptr(), units.as_mut_ptr(), units.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = units
        .iter()
        .position(|u| *u == 0)
        .ok_or_else(|| bad("volume root unterminated"))?;
    if end == 0 {
        return Err(bad("volume root is empty"));
    }
    String::from_utf16(&units[..end]).map_err(io::Error::other)
}
fn guid_root(root: &str) -> io::Result<String> {
    let path = wide(root);
    let mut units = [0u16; 128];
    // SAFETY: exact observed root and fixed writable output.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(path.as_ptr(), units.as_mut_ptr(), units.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let end = units
        .iter()
        .position(|u| *u == 0)
        .ok_or_else(|| bad("volume GUID root unterminated"))?;
    String::from_utf16(&units[..end]).map_err(io::Error::other)
}
fn local_volume_route(path: &str) -> io::Result<String> {
    let path = path.trim_end_matches('\\');
    if path.len() == 6
        && path.starts_with(r"\\.\")
        && path.as_bytes()[4].is_ascii_alphabetic()
        && path.ends_with(':')
    {
        return Ok(path.to_owned());
    }
    if let Some(guid) = path
        .strip_prefix(r"\\?\Volume{")
        .and_then(|v| v.strip_suffix('}'))
    {
        if guid.len() == 36 && crate::layout::guid_bytes(guid).is_ok() {
            return Ok(path.to_owned());
        }
    }
    Err(bad(
        "explicit local DOS volume or canonical Volume GUID route required",
    ))
}
fn current_route(root: &str, guid: Option<&str>) -> io::Result<String> {
    if let Some(guid) = guid {
        return local_volume_route(guid);
    }
    // Explicit diagnostic DOS route is useful if RAMdisk mount-manager GUID
    // publication is unsupported. No physical/exclusion claim follows.
    if root.len() == 3 && root.as_bytes()[0].is_ascii_alphabetic() && &root[1..] == ":\\" {
        return local_volume_route(&format!(r"\\.\{}:", &root[..1]));
    }
    Err(bad(
        "current root has no directly queryable local volume route",
    ))
}
fn extents(bytes: &[u8]) -> io::Result<Vec<PhysicalExtent>> {
    let count = crate::layout::u32_at(bytes, 0)? as usize;
    if count == 0 || count > 64 || bytes.len() != 8 + 24 * count {
        return Err(bad(
            "complete bounded positive physical extent array not observed",
        ));
    }
    let mut output = Vec::new();
    for n in 0..count {
        let at = 8 + 24 * n;
        let offset = crate::layout::u64_at(bytes, at + 8)?;
        let length = crate::layout::u64_at(bytes, at + 16)?;
        if length == 0
            || offset > i64::MAX as u64
            || length > i64::MAX as u64
            || offset.checked_add(length).is_none()
        {
            return Err(bad("invalid native extent"));
        }
        output.push(PhysicalExtent {
            disk_number: crate::layout::u32_at(bytes, at)?,
            offset,
            length,
        });
    }
    Ok(output)
}
fn volume(path: &str, expected: Option<&GeneralDiskBinding>) -> VolumeQuery {
    let mut report = VolumeQuery {
        path: path.to_owned(),
        open: Fact::result(Ok(false)),
        controls: Vec::new(),
        decoded_physical_extents: None,
        decode_error: None,
        expected_partition_identity_coordinates_match: None,
        handles_closed: true,
    };
    let file = match device_file(path, false, false) {
        Ok(file) => {
            report.open = Fact::result(Ok(true));
            file
        }
        Err(error) => {
            report.open = Fact::result(Err(error));
            return report;
        }
    };
    for (name, code, capacity) in [
        ("offline-volume-DEVICE", super::DEVICE, 12),
        ("offline-volume-LENGTH", super::LENGTH, 8),
        ("offline-volume-VOLUME_EXTENTS", super::VOLUME_EXTENTS, 4096),
        ("offline-volume-PARTITION_INFO", 0x0007_0048, 144),
        ("offline-volume-NTFS_DATA", 0x0009_0064, 128),
    ] {
        let _ = control(&file, name, code, &[], capacity, &mut report.controls);
    }
    if let Some(event) = report
        .controls
        .iter()
        .find(|e| e.control_code == super::VOLUME_EXTENTS && e.succeeded)
    {
        match extents(&event.output) {
            Ok(value) => report.decoded_physical_extents = Some(value),
            Err(error) => report.decode_error = Some(error.to_string()),
        }
    }
    if let Some(binding) = expected {
        let matched = (|| {
            binding.validate()?;
            let device = report
                .controls
                .iter()
                .find(|e| e.control_code == super::DEVICE && e.succeeded)
                .ok_or_else(|| bad("device query unavailable"))?;
            let info = report
                .controls
                .iter()
                .find(|e| e.control_code == 0x0007_0048 && e.succeeded)
                .ok_or_else(|| bad("partition query unavailable"))?;
            let extent = report
                .controls
                .iter()
                .find(|e| e.control_code == super::VOLUME_EXTENTS && e.succeeded)
                .ok_or_else(|| bad("extent query unavailable"))?;
            binding.validate_volume_extent(&extent.output)?;
            if device.output.len() != 12
                || crate::layout::u32_at(&device.output, 4)? != binding.disk_number
                || crate::layout::u32_at(&device.output, 8)? != binding.identity.partition_number
                || info.output.len() != 144
                || crate::layout::u32_at(&info.output, 0)? != 1
                || crate::layout::u64_at(&info.output, 8)? != binding.identity.partition_offset
                || crate::layout::u64_at(&info.output, 16)? != binding.identity.partition_bytes
                || info.output[48..64]
                    != crate::layout::guid_bytes(&binding.identity.partition_guid)?
            {
                return Err(bad(
                    "actual selected native metadata differs from expected routing binding",
                ));
            }
            Ok(())
        })();
        report.expected_partition_identity_coordinates_match = matched.as_ref().ok().map(|()| true);
        if let Err(error) = matched {
            report.decode_error = Some(error.to_string());
        }
    }
    drop(file);
    report
}
fn mini_nt() -> MiniNtObservation {
    let name = wide(r"SYSTEM\CurrentControlSet\Control\MiniNT");
    let mut key = ptr::null_mut();
    // SAFETY: query-only machine key; no create or value mutation.
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if code == 0 {
        unsafe { RegCloseKey(key) };
    }
    MiniNtObservation {
        present: match code {
            0 => Some(true),
            2 | 3 => Some(false),
            _ => None,
        },
        registry_status: code,
        query_only: true,
    }
}
fn component(path: &Path, remaining: &mut u64) -> ComponentObservation {
    let mut out = ComponentObservation {
        path: path.to_string_lossy().into_owned(),
        actual_file_bytes: None,
        sha256: None,
        failure: None,
        version_collected: false,
        authenticode_collected: false,
        held_object_name_query:None,legacy_file_info52_query:None,file_id128_qualification_failure:None,
    };
    let result = (|| {
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        crate::file_storage::require_readonly_access(&file)?;
        // Distinct diagnostic calls on this SAME held ordinary component.
        // Legacy52 success is recorded only; it does NOT relax the Id128 gate.
        out.held_object_name_query=Some(kernel_ram_backing::object_name(&file));
        out.legacy_file_info52_query=Some(kernel_ram_backing::legacy52(&file));
        let before=match crate::reference_file::observe_reference_file_handle_with_limit(&file,*remaining){
            Ok(v)=>v,Err(e)=>{out.file_id128_qualification_failure=Some(format!("reference_file FileId128/standard metadata failed: native_error={:?}; {e}",e.raw_os_error()));return Err(e)},
        };
        out.actual_file_bytes = Some(before.file_bytes);
        let modified = file.metadata()?.modified()?;
        *remaining = remaining
            .checked_sub(before.file_bytes)
            .ok_or_else(|| bad("component read budget exhausted"))?;
        let hash = crate::sha256_native::hash_range(&mut file, 0, before.file_bytes)?;
        if crate::reference_file::observe_reference_file_handle_with_limit(
            &file,
            before.file_bytes,
        )? != before
            || file.metadata()?.modified()? != modified
        {
            return Err(bad("held component changed during hash"));
        }
        out.sha256 = Some(hex::encode(hash));
        Ok(())
    })();
    if let Err(error) = result {
        out.failure = Some(Failure::from(error));
    }
    out
}

pub fn available_ram_bytes() -> io::Result<u64> {
    let mut value = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: exact SDK structure is initialized and retained for the query.
    if unsafe { GlobalMemoryStatusEx(&mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if value.ullAvailPhys > value.ullTotalPhys {
        return Err(bad("memory availability is contradictory"));
    }
    Ok(value.ullAvailPhys)
}

/// Return observations even when volume APIs/WMI/VSS are unsupported. Such
/// failures never become clear-role, RAMdisk or conversion admission flags.
pub fn observe(
    budget: ProbeBudget,
    selected: Option<&SourceQuery>,
    query_vss: bool,
) -> io::Result<Observation> {
    budget.validate()?;
    if budget.ram_bytes > available_ram_bytes()? {
        return Err(bad("collector RAM exceeds actual sampled availability"));
    }
    let windows_directory = Fact::result(windows_directory());
    let windows_volume_root = Fact::result(
        windows_directory
            .value
            .as_deref()
            .ok_or_else(|| bad("Windows directory unavailable"))
            .and_then(volume_root),
    );
    let current_volume_guid_root = Fact::result(
        windows_volume_root
            .value
            .as_deref()
            .ok_or_else(|| bad("current root unavailable"))
            .and_then(guid_root),
    );
    let drive_type = windows_volume_root.value.as_ref().map(|root| {
        let root = wide(root);
        unsafe { GetDriveTypeW(root.as_ptr()) }
    });
    let drive_type_name = match drive_type {
        Some(0) => "unknown",
        Some(1) => "no-root",
        Some(2) => "removable",
        Some(3) => "fixed",
        Some(4) => "remote",
        Some(5) => "cdrom",
        Some(6) => "ramdisk",
        _ => "not-observed-or-unrecognized",
    };
    let native_kernel_ram_backing=windows_directory.value.as_deref().map(kernel_ram_backing::observe);
    let firmware_type = Fact::result({
        let mut value = 0;
        let ok = unsafe { GetFirmwareType(&mut value) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(value as u32)
        }
    });
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    let rtl_get_version_status = unsafe { RtlGetVersion(&mut version) };
    let route = windows_volume_root
        .value
        .as_deref()
        .map(|root| current_route(root, current_volume_guid_root.value.as_deref()));
    let current_volume = route.map(|route| match route {
        Ok(route) => volume(&route, None),
        Err(error) => VolumeQuery {
            path: String::new(),
            open: Fact::result(Err(error)),
            controls: Vec::new(),
            decoded_physical_extents: None,
            decode_error: None,
            expected_partition_identity_coordinates_match: None,
            handles_closed: true,
        },
    });
    let native_physical_extents_reported = current_volume
        .as_ref()
        .is_some_and(|q| q.decoded_physical_extents.is_some());
    let selected_source = selected.map(|query| match local_volume_route(&query.volume_path) {
        Ok(route) => volume(&route, query.expected_binding.as_ref()),
        Err(error) => VolumeQuery {
            path: query.volume_path.clone(),
            open: Fact::result(Err(error)),
            controls: Vec::new(),
            decoded_physical_extents: None,
            decode_error: None,
            expected_partition_identity_coordinates_match: None,
            handles_closed: true,
        },
    });
    // An explicit DOS source must resolve to its own GUID root. A failed
    // source resolution must never silently query the current Windows volume.
    let vss_route = if let Some(query) = selected {
        local_volume_route(&query.volume_path).and_then(|route| {
            if route.starts_with(r"\\?\Volume{") {
                Ok(format!("{route}\\"))
            } else {
                guid_root(&format!("{}\\", &route[4..]))
            }
        })
    } else {
        current_volume_guid_root.value.clone()
            .ok_or_else(|| bad("current volume GUID root unavailable for VSS query"))
    };
    let mut vss = VssAvailability {
        attempted_volume_guid_route: None,
        result: None,
        failure: None,
        catalog_clear_established: false,
    };
    if query_vss {
        if let Ok(route) = vss_route {
            vss.attempted_volume_guid_route = Some(route.clone());
            match crate::vss_observation::observe_snapshot_presence(&route) {
                Ok(value) => vss.result = Some(value),
                Err(error) => vss.failure = Some(Failure::from(error)),
            }
        } else if let Err(error) = vss_route {
            vss.failure = Some(Failure::from(error));
        }
    }
    let storage_wmi = wmi::observe();
    let mut remaining = budget.maximum_component_bytes;
    let mut components = Vec::new();
    if let Some(root) = &windows_directory.value {
        for rel in [
            r"System32\drivers\refs.sys",
            r"System32\drivers\ntfs.sys",
            r"System32\winload.efi",
            r"System32\ntoskrnl.exe",
            r"System32\vssapi.dll",
        ] {
            components.push(component(&Path::new(root).join(rel), &mut remaining));
        }
    }
    Ok(Observation {
        schema_version: 1,
        kind: "offline-environment-readonly-native-facts-v1",
        budget,
        windows_directory,
        windows_volume_root,
        current_volume_guid_root,
        drive_type,
        drive_type_name,
        mini_nt: mini_nt(),
        firmware_type,
        rtl_get_version_status,
        running_kernel_version: if rtl_get_version_status == 0 {
            Some([
                version.dwMajorVersion,
                version.dwMinorVersion,
                version.dwBuildNumber,
            ])
        } else {
            None
        },
        current_volume,
        native_kernel_ram_backing: native_kernel_ram_backing.clone(),
        positive_ramdisk_reported_by_get_drive_type: drive_type == Some(6),
        native_physical_extents_reported,
        backing_classification: if native_kernel_ram_backing.as_ref().and_then(|v|v.facts.as_ref()).is_some_and(|v|v.positive_native_kernel_ramdisk){
            "positively_matched_current_kernel_Ramdisk_GUID_v1"
        }else if drive_type == Some(6) && native_physical_extents_reported {
            "RAMDISK-reported-and-physical-extents-also-observed"
        } else if drive_type == Some(6) {
            "RAMDISK-positively-reported-by-GetDriveTypeW"
        } else if native_physical_extents_reported {
            "native-physical-extents-observed"
        } else {
            "unclassified"
        },
        selected_source,
        storage_wmi,
        vss,
        component_bytes_hashed: components
            .iter()
            .filter(|c| c.sha256.is_some())
            .filter_map(|c| c.actual_file_bytes)
            .sum(),
        component_read_budget_debited_bytes: budget.maximum_component_bytes - remaining,
        components,
        all_direct_volume_handles_closed: true,
        critical_roles_clear: false,
        offline_environment_qualified: false,
        source_write_requests: 0,
        grants_conversion_or_recovery_authority: false,
    })
}

pub use super::partition_isolation::offline::{OfflineFrozenSource,OfflineRecoverySource,OfflineSourceOwnerToken,OfflineSourceState,OfflineSourceIntentPin};

pub use super::partition_isolation::offline::{OfflineSourceApplyGate,OfflinePagedWriter,OfflineJournalReadView,OfflineClosedJournalObservation,OfflineTerminalKind};
