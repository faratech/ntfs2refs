//! Positive RAM-Windows owning environment. Readonly facts/owners only; this
//! token never substitutes a physical C: extent, FS lock, VSS catalog or writer.
mod source;
use super::*;
use crate::journal_file::GeneralJournalStorageBinding;
pub use source::{
    OfflineFreshWitness, OfflineFrozenSource, OfflinePagedNtfsObservation,
    OfflineReadonlyNtfsPhase, OfflineRecoverySource, OfflineSourceIntentPin,
    OfflineSourceOwnerToken, OfflineSourceState,
};
use std::{ffi::c_void, fs::OpenOptions, os::windows::fs::OpenOptionsExt, ptr};
use windows_sys::Win32::{
    Storage::FileSystem::GetDriveTypeW,
    System::{
        Registry::{
            HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, RegCloseKey, RegOpenKeyExW,
        },
        SystemInformation::{GetFirmwareType, OSVERSIONINFOW},
    },
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleFileNameW(module: *mut c_void, path: *mut u16, characters: u32) -> u32;
    fn K32EnumDeviceDrivers(bases: *mut *mut c_void, bytes: u32, needed: *mut u32) -> i32;
    fn K32GetDeviceDriverFileNameW(base: *mut c_void, path: *mut u16, characters: u32) -> u32;
    fn GetFileInformationByHandle(file: *mut c_void, info: *mut c_void) -> i32;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetProcessTimes(
        process: *mut c_void,
        creation: *mut u64,
        exit: *mut u64,
        kernel: *mut u64,
        user: *mut u64,
    ) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        output: *mut c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
    fn RtlGetVersion(version: *mut OSVERSIONINFOW) -> i32;
}
fn text(units: &[u16]) -> io::Result<String> {
    String::from_utf16(units).map_err(io::Error::other)
}
fn root(path: &str) -> io::Result<String> {
    let mut out = vec![0u16; 32768];
    if unsafe { GetVolumePathNameW(wide(path).as_ptr(), out.as_mut_ptr(), out.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let n = out
        .iter()
        .position(|u| *u == 0)
        .ok_or_else(|| invalid("offline root unterminated"))?;
    let value = text(&out[..n])?;
    require(
        value.len() == 3 && value.as_bytes()[0].is_ascii_alphabetic() && &value[1..] == ":\\",
        "offline RAM root must be an actual local DOS root",
    )?;
    Ok(value)
}
fn current_windows() -> io::Result<String> {
    let mut out = vec![0u16; 32768];
    let n = unsafe { GetWindowsDirectoryW(out.as_mut_ptr(), out.len() as u32) } as usize;
    require(n > 0 && n < out.len(), "native Windows directory unknown")?;
    text(&out[..n])
}
fn require_ram_root(path: &str) -> io::Result<String> {
    // DriveType is only a classification: actual WinPE WIM reports FIXED3.
    // Require matching kernel-owned DOS mapping + SAME held Ramdisk volume.
    Ok(crate::native::offline_environment::kernel_ram_backing::require_path(path)?.dos_root)
}
fn mini_nt() -> io::Result<()> {
    let mut key = ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(r"SYSTEM\CurrentControlSet\Control\MiniNT").as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("positive native MiniNT key required; registry_status={status}"),
        ));
    }
    let closed = unsafe { RegCloseKey(key) };
    if closed != 0 {
        return Err(io::Error::from_raw_os_error(closed as i32));
    }
    Ok(())
}
fn system_bytes(class: u32, n: usize) -> io::Result<Vec<u8>> {
    let mut b = bytes(n as u64)?;
    let mut returned = 0;
    let status = unsafe {
        NtQuerySystemInformation(
            class,
            b.as_mut_ptr().cast(),
            u32::try_from(n).map_err(io::Error::other)?,
            &mut returned,
        )
    };
    if status != 0 {
        return Err(io::Error::other(format!(
            "offline NtQuerySystemInformation({class}) unknown: status0x{:08x},returned={returned}",
            status as u32
        )));
    }
    require(
        returned as usize <= n,
        "native offline reply exceeds admitted buffer",
    )?;
    b.truncate(returned as usize);
    Ok(b)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OfflineBootIdentity {
    pub boot_time_100ns: u64,
    pub boot_identifier: Vec<u8>,
    pub firmware_type: u32,
    pub kernel_version: [u32; 3],
    pub process_id: u32,
    pub process_creation_100ns: u64,
}
fn boot_identity() -> io::Result<OfflineBootIdentity> {
    let time = system_bytes(3, 48)?;
    require(time.len() == 48, "native boot-time reply incomplete")?;
    let boot = system_bytes(90, 32)?;
    require(
        boot.len() == 32 && boot[..16].iter().any(|v| *v != 0),
        "native boot-environment identity incomplete",
    )?;
    let mut firmware = 0i32;
    require(
        unsafe { GetFirmwareType(&mut firmware) } != 0 && matches!(firmware, 1 | 2),
        "native firmware type unknown",
    )?;
    let firmware = firmware as u32;
    require(
        layout::u32_at(&boot, 16)? == firmware,
        "firmware/native boot identity differs",
    )?;
    let mut version: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    version.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    require(
        unsafe { RtlGetVersion(&mut version) } == 0 && version.dwMajorVersion >= 10,
        "running native kernel version unavailable",
    )?;
    let (mut creation, mut exit, mut kernel, mut user) = (0, 0, 0, 0);
    require(
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } != 0,
        "actual running-process birth unavailable",
    )?;
    require(
        layout::u64_at(&time, 0)? > 0
            && creation >= layout::u64_at(&time, 0)?
            && creation <= layout::u64_at(&time, 8)?,
        "native boot/process timestamps inconsistent",
    )?;
    Ok(OfflineBootIdentity {
        boot_time_100ns: layout::u64_at(&time, 0)?,
        boot_identifier: boot[..16].to_vec(),
        firmware_type: firmware,
        kernel_version: [
            version.dwMajorVersion,
            version.dwMinorVersion,
            version.dwBuildNumber,
        ],
        process_id: unsafe { GetCurrentProcessId() },
        process_creation_100ns: creation,
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OfflineImageIdentity {
    pub path: String,
    pub ram_root: String,
    pub file_identity: Vec<u8>,
    pub bytes: u64,
    pub sha256: String,
    pub loaded_image_bytes_hashed: bool,
    pub held_nt_object_name: String,
    pub ram_device_object_name: String,
}
struct ImageOwner {
    file: File,
    identity: OfflineImageIdentity,
}
fn file_identity(file: &File) -> io::Result<(Vec<u8>, u64)> {
    let mut raw = [0u32; 13];
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), raw.as_mut_ptr().cast()) } == 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "ImageOwner GetFileInformationByHandle(52B) failed: native_error={:?}; {error}",
                error.raw_os_error()
            ),
        ));
    }
    require(
        raw[0] & 0x410 == 0 && raw[10] == 1,
        "offline component must be ordinary single-link non-reparse file",
    )?;
    let size = (u64::from(raw[8]) << 32) | u64::from(raw[9]);
    require(size > 0, "offline component is empty")?;
    // Access time may change when read. Preserve attrs/write time/volume serial,
    // exact EOF/link count/file index; this retained FileObject excludes writers.
    let mut stable = Vec::new();
    for index in [0, 5, 6, 7, 8, 9, 10, 11, 12] {
        stable.extend_from_slice(&raw[index].to_le_bytes());
    }
    Ok((stable, size))
}
impl ImageOwner {
    fn hold(path: String, remaining: &mut u64) -> io::Result<Self> {
        let ram_root = require_ram_root(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&path)?;
        let (native_backing, held_nt_object_name) =
            crate::native::offline_environment::kernel_ram_backing::require_file(&path, &file)?;
        require(
            native_backing.dos_root == ram_root,
            "actual image native RAM root differs",
        )?;
        let (id, size) = file_identity(&file)?;
        require(
            size <= *remaining,
            "native component hashing exceeds admitted component-byte ceiling",
        )?;
        *remaining -= size;
        let hash = crate::sha256_native::hash_range(&mut file, 0, size)?;
        require(
            file_identity(&file)? == (id.clone(), size),
            "held offline component changed during hash",
        )?;
        Ok(Self {
            file,
            identity: OfflineImageIdentity {
                path,
                ram_root,
                file_identity: id,
                bytes: size,
                sha256: hex::encode(hash),
                loaded_image_bytes_hashed: false,
                held_nt_object_name,
                ram_device_object_name: native_backing.ram_device_object_name,
            },
        })
    }
    fn require_current(&self) -> io::Result<()> {
        let (backing, name) = crate::native::offline_environment::kernel_ram_backing::require_file(
            &self.identity.path,
            &self.file,
        )?;
        require(
            name == self.identity.held_nt_object_name
                && backing.ram_device_object_name == self.identity.ram_device_object_name,
            "held offline image kernel RAM device/name changed",
        )?;
        require(
            require_ram_root(&self.identity.path)? == self.identity.ram_root
                && file_identity(&self.file)?
                    == (self.identity.file_identity.clone(), self.identity.bytes),
            "held offline component/positive RAM backing changed",
        )
    }
}
fn process_image() -> io::Result<String> {
    let mut out = vec![0u16; 32768];
    let n =
        unsafe { GetModuleFileNameW(ptr::null_mut(), out.as_mut_ptr(), out.len() as u32) } as usize;
    require(n > 0 && n < out.len(), "actual running image path unknown")?;
    text(&out[..n])
}
fn kernel_image(
    windows: &str,
    ram: &str,
    budget: PartitionObservationBudget,
) -> io::Result<String> {
    let count = usize::try_from(budget.ram_bytes / 128).map_err(io::Error::other)?;
    require(
        count > 0
            && count
                .checked_mul(std::mem::size_of::<*mut c_void>())
                .is_some_and(|n| n <= u32::MAX as usize),
        "native driver inventory budget invalid",
    )?;
    let mut bases = vec![ptr::null_mut(); count];
    let capacity = bases.len() * std::mem::size_of::<*mut c_void>();
    let mut needed = 0;
    if unsafe { K32EnumDeviceDrivers(bases.as_mut_ptr(), capacity as u32, &mut needed) } == 0 {
        return Err(io::Error::last_os_error());
    }
    require(
        needed > 0
            && needed as usize <= capacity
            && (needed as usize).is_multiple_of(std::mem::size_of::<*mut c_void>()),
        "native loaded-driver enumeration incomplete",
    )?;
    let mut found = None;
    for base in bases
        .into_iter()
        .take(needed as usize / std::mem::size_of::<*mut c_void>())
    {
        require(
            !base.is_null(),
            "native loaded-driver address unavailable (including disabled SeDebug); no privilege is changed",
        )?;
        let mut out = vec![0u16; 32768];
        let n = unsafe { K32GetDeviceDriverFileNameW(base, out.as_mut_ptr(), out.len() as u32) }
            as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        require(n < out.len(), "native kernel-module path truncated")?;
        let name = text(&out[..n])?;
        let lower = name.to_ascii_lowercase();
        if lower.ends_with("\\ntoskrnl.exe") || lower.ends_with("\\ntkrnlmp.exe") {
            let path = if lower.starts_with("\\systemroot\\") {
                format!("{}\\{}", windows.trim_end_matches('\\'), &name[12..])
            } else if lower.starts_with("\\??\\") {
                name[4..].to_owned()
            } else {
                name.clone()
            };
            require(
                require_ram_root(&path)? == ram && found.is_none(),
                "native loaded kernel path is not unique/current RAM Windows",
            )?;
            found = Some(path);
        }
    }
    found.ok_or_else(|| invalid("actual loaded kernel module was not positively identified"))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OfflineSourcePhysicalFacts {
    pub device: Vec<u8>,
    pub length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub disk_attributes: u64,
    pub gpt: PartitionGptObservation,
}
fn source_facts(
    file: &mut File,
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OfflineSourcePhysicalFacts> {
    let device = control(
        file,
        "offline-source-native-DEVICE",
        DEVICE,
        &[],
        12,
        events,
    )?;
    layout::validate_device(&device, binding.storage.disk_number)?;
    require(
        device.len() == 12 && layout::u32_at(&device, 8)? == 0,
        "source metadata handle must be actual physical disk-part0",
    )?;
    let length = control(file, "offline-source-native-length", LENGTH, &[], 8, events)?;
    require(
        length.len() == 8 && layout::u64_at(&length, 0)? == binding.storage.identity.disk_bytes,
        "offline source physical length differs",
    )?;
    let mut query = [0u8; 12];
    query[0] = 6;
    let alignment = control(
        file,
        "offline-source-native-alignment",
        ALIGNMENT,
        &query,
        28,
        events,
    )?;
    binding.storage.validate_alignment(&alignment)?;
    let disk_attributes = attributes(file, events)?;
    let native = native_layout(file, budget, events)?;
    require(
        native.len() >= 48 && (native.len() - 48).is_multiple_of(144),
        "offline source native layout is incomplete",
    )?;
    let guid = layout::guid_bytes(&binding.storage.identity.partition_guid)?;
    let rows: Vec<_> = native[48..]
        .chunks_exact(144)
        .filter(|r| r[48..64] == guid)
        .collect();
    require(
        rows.len() == 1,
        "offline selected native partition is not unique",
    )?;
    let kind: [u8; 16] = rows[0][32..48].try_into().map_err(io::Error::other)?;
    require(
        kind == layout::guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")?
            || kind == layout::guid_bytes("b627aadb-a893-48b6-aa0b-71e5f30ee370")?,
        "offline source may not be EFI/reserved/unknown partition type",
    )?;
    let gpt = gpt(file, &binding.storage, budget, native, kind)?;
    Ok(OfflineSourcePhysicalFacts {
        device,
        length,
        alignment,
        disk_attributes,
        gpt,
    })
}
#[derive(Clone, Debug, Serialize)]
pub struct OfflineOwningFacts {
    pub source: PartitionSourceBinding,
    pub windows_directory: String,
    pub windows_ram_root: String,
    pub windows_drive_type: u32,
    pub native_ram_backing: crate::native::offline_environment::KernelRamBackingFacts,
    pub mini_nt_present: bool,
    pub boot: OfflineBootIdentity,
    pub running_image: OfflineImageIdentity,
    pub kernel_image: OfflineImageIdentity,
    pub current_ram_volume_device: Vec<u8>,
    pub current_ram_volume_length: Vec<u8>,
    pub source_physical: OfflineSourcePhysicalFacts,
    pub critical_routes: serde_json::Value,
    pub vss_catalog_clear_proven: bool,
    pub wmi_roles_assumed_clear: bool,
    pub environment_identity_qualified: bool,
    pub source_exclusion_qualified: bool,
    pub grants_source_write_authority: bool,
}
/// No Deserialize, Clone, path/JSON constructor, source-write or raw-handle API.
pub struct OfflineOwningEnvironment {
    source: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    ram: File,
    physical: File,
    running_image: ImageOwner,
    kernel: ImageOwner,
    facts: OfflineOwningFacts,
}
impl OfflineOwningEnvironment {
    pub fn observe_and_require(
        source: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        source.validate()?;
        budget.validate()?;
        require(
            events.len() < 48,
            "offline proof requires drained native-event workspace",
        )?;
        let windows = current_windows()?;
        let ram_root = require_ram_root(&windows)?;
        let ram = OpenOptions::new()
            .access_mode(0x00100080)
            .share_mode(3)
            .open(format!("\\\\.\\{}:", &ram_root[..1]))?;
        let native_ram_backing =
            crate::native::offline_environment::kernel_ram_backing::require_held(&windows, &ram)?;
        mini_nt()?;
        let boot = boot_identity()?;
        let mut component_bytes = budget.ram_bytes;
        let running_image = ImageOwner::hold(process_image()?, &mut component_bytes)?;
        require(
            running_image.identity.ram_root == ram_root,
            "offline requester image must execute from actual RAM Windows volume",
        )?;
        let kernel = ImageOwner::hold(
            kernel_image(&windows, &ram_root, budget)?,
            &mut component_bytes,
        )?;
        let device = control(
            &ram,
            "offline-current-RAM-volume-device",
            DEVICE,
            &[],
            12,
            events,
        )?;
        let length = control(
            &ram,
            "offline-current-RAM-volume-length",
            LENGTH,
            &[],
            8,
            events,
        )?;
        require(
            device.len() == 12 && length.len() == 8 && layout::u64_at(&length, 0)? > 0,
            "actual held RAM volume native identity/length unavailable",
        )?;
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", source.storage.disk_number),
            false,
            false,
        )?;
        let physical_facts = source_facts(&mut physical, &source, budget, events)?;
        let critical = super::super::partition_dump_locations::offline::observe(
            &source, budget, &windows, events,
        )?;
        let facts = OfflineOwningFacts {
            source: source.clone(),
            windows_directory: windows,
            windows_ram_root: ram_root,
            windows_drive_type: native_ram_backing.actual_drive_type,
            native_ram_backing,
            mini_nt_present: true,
            boot,
            running_image: running_image.identity.clone(),
            kernel_image: kernel.identity.clone(),
            current_ram_volume_device: device,
            current_ram_volume_length: length,
            source_physical: physical_facts,
            critical_routes: critical,
            vss_catalog_clear_proven: false,
            wmi_roles_assumed_clear: false,
            environment_identity_qualified: true,
            source_exclusion_qualified: false,
            grants_source_write_authority: false,
        };
        let mut value = Self {
            source,
            budget,
            ram,
            physical,
            running_image,
            kernel,
            facts,
        };
        value.require_current(events)?;
        Ok(value)
    }
    pub fn windows_backing_is_ram(&self) -> bool {
        self.facts.native_ram_backing.positive_native_kernel_ramdisk
    }
    pub fn facts(&self) -> &OfflineOwningFacts {
        &self.facts
    }
    pub fn require_current(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.require_current_at_attributes(self.facts.source_physical.disk_attributes, events)
    }
    // SDK-owner-only bookend after its ACTUAL durable disk transition. Original
    // enrollment facts are never rewritten or reconstructed from a pin/DTO.
    fn require_current_at_attributes(
        &mut self,
        expected_attributes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        require(
            current_windows()? == self.facts.windows_directory
                && require_ram_root(&self.facts.windows_directory)? == self.facts.windows_ram_root,
            "current RAM Windows root changed",
        )?;
        require(
            crate::native::offline_environment::kernel_ram_backing::require_held(
                &self.facts.windows_directory,
                &self.ram,
            )? == self.facts.native_ram_backing,
            "current actual kernel RAM backing changed",
        )?;
        require(
            self.running_image.identity.ram_device_object_name
                == self.facts.native_ram_backing.ram_device_object_name
                && self.kernel.identity.ram_device_object_name
                    == self.facts.native_ram_backing.ram_device_object_name,
            "current Windows/process/loaded kernel are not on SAME native RAMdisk",
        )?;
        mini_nt()?;
        require(
            boot_identity()? == self.facts.boot,
            "actual offline boot/process identity changed",
        )?;
        require(
            process_image()? == self.running_image.identity.path,
            "running image route changed",
        )?;
        self.running_image.require_current()?;
        self.kernel.require_current()?;
        require(
            kernel_image(
                &self.facts.windows_directory,
                &self.facts.windows_ram_root,
                self.budget,
            )? == self.kernel.identity.path,
            "actual loaded kernel route changed",
        )?;
        let device = control(
            &self.ram,
            "offline-current-RAM-volume-device-recheck",
            DEVICE,
            &[],
            12,
            events,
        )?;
        let length = control(
            &self.ram,
            "offline-current-RAM-volume-length-recheck",
            LENGTH,
            &[],
            8,
            events,
        )?;
        require(
            device == self.facts.current_ram_volume_device
                && length == self.facts.current_ram_volume_length,
            "held RAM volume native identity changed",
        )?;
        let actual = source_facts(&mut self.physical, &self.source, self.budget, events)?;
        let original = &self.facts.source_physical;
        require(
            actual.device == original.device
                && actual.length == original.length
                && actual.alignment == original.alignment
                && actual.gpt == original.gpt
                && actual.disk_attributes == expected_attributes,
            "offline source full GPT/native identity or actual expected disk protection changed",
        )?;
        let critical = super::super::partition_dump_locations::offline::observe(
            &self.source,
            self.budget,
            &self.facts.windows_directory,
            events,
        )?;
        require(
            critical == self.facts.critical_routes,
            "offline current paging/configured critical routes changed",
        )
    }
    pub fn require_journal_disjoint(
        &mut self,
        journal: &GeneralJournalStorageBinding,
        volume: &File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.require_current(events)?;
        journal.validate()?;
        let device = control(
            volume,
            "offline-held-journal-native-device",
            DEVICE,
            &[],
            12,
            events,
        )?;
        let info = control(
            volume,
            "offline-held-journal-native-partition",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        let extents = control(
            volume,
            "offline-held-journal-native-extents",
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
                && layout::u32_at(&info, 0)? == 1
                && info[48..64] == layout::guid_bytes(&id.partition_guid)?
                && layout::u64_at(&info, 8)? == id.partition_offset
                && layout::u64_at(&info, 16)? == id.partition_bytes,
            "actual held journal native identity differs",
        )?;
        let target = &self.source.storage.identity;
        require(
            journal.disk.disk_number != self.source.storage.disk_number
                && layout::guid_bytes(&id.disk_guid)? != layout::guid_bytes(&target.disk_guid)?,
            "offline whole-source-disk proof requires an independently bound journal disk",
        )?;
        self.require_current(events)
    }
}

pub use source::{
    OfflineClosedJournalObservation, OfflineJournalReadView, OfflinePagedWriter,
    OfflineSourceApplyGate, OfflineTerminalKind,
};
