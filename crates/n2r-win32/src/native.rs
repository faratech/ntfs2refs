use crate::{
    general_layout::GeneralDiskBinding,
    layout::{self, DiskBinding, GRANULE, invalid},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, IntoRawHandle},
    },
    ptr::{self, NonNull},
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW, SetVolumeMountPointW,
};
use windows_sys::Win32::System::{IO::DeviceIoControl, SystemInformation::GetWindowsDirectoryW};

const DEVICE: u32 = 0x002d1080;
const LENGTH: u32 = 0x0007405c;
const ALIGNMENT: u32 = 0x002d1400;
const LAYOUT: u32 = 0x00070050;
const GET_ATTRIBUTES: u32 = 0x000700f0;
const SET_ATTRIBUTES: u32 = 0x0007c0f4;
const UPDATE_PROPERTIES: u32 = 0x00070140;
const VOLUME_EXTENTS: u32 = 0x00560000;
const LOCK: u32 = 0x00090018;
const UNLOCK: u32 = 0x0009001c;
const DISMOUNT: u32 = 0x00090020;
const OFFLINE: u64 = 1;
const READ_ONLY: u64 = 2;
const MAX_IO: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct NativeEvent {
    pub operation: String,
    pub control_code: u32,
    pub input: Vec<u8>,
    pub succeeded: bool,
    pub native_error: Option<i32>,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PartitionSnapshot {
    pub binding: DiskBinding,
    pub disk_attributes: u64,
    pub device: Vec<u8>,
    pub length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub layout: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GeneralProbe {
    pub binding: GeneralDiskBinding,
    pub disk_attributes_before: u64,
    pub disk_attributes_after: u64,
    pub device: Vec<u8>,
    pub disk_length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub gpt_layout: Vec<u8>,
    pub volume_extents: Vec<u8>,
    pub read_only_probe: bool,
    pub source_write_requests: u64,
    pub conversion_qualified: bool,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct MountPathObservation {
    pub binding: GeneralDiskBinding,
    pub paths: Vec<String>,
    pub all_paths_resolve_to_bound_volume: bool,
}

#[derive(Debug, Serialize)]
pub struct DriveLetterRestore {
    pub requested: String,
    pub before: MountPathObservation,
    pub after: MountPathObservation,
    pub changed: bool,
    pub target_filesystem: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct GeneralDiskState {
    pub device: Vec<u8>,
    pub disk_length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub gpt_layout: Vec<u8>,
    pub disk_attributes: u64,
}
/// Created only by a physically read-only native observation bracketed by
/// actual excluded-device snapshots. Exporting it cannot recreate a lease.
#[derive(Debug, Serialize)]
pub struct LiveNtfsObservation {
    report: crate::attestation::Report,
    before: PartitionSnapshot,
    after: PartitionSnapshot,
}
#[derive(Debug, Serialize)]
pub struct GeneralLiveNtfsObservation {
    report: crate::attestation::Report,
    txf: Option<crate::txf_native::GeneralObservation>,
    txf_error: Option<String>,
    before: GeneralDiskState,
    after: GeneralDiskState,
}
impl GeneralLiveNtfsObservation {
    pub fn report(&self) -> &crate::attestation::Report {
        &self.report
    }
    pub fn txf(&self) -> Option<&crate::txf_native::GeneralObservation> {
        self.txf.as_ref()
    }
    pub fn txf_error(&self) -> Option<&str> {
        self.txf_error.as_deref()
    }
}
impl LiveNtfsObservation {
    pub fn report(&self) -> &crate::attestation::Report {
        &self.report
    }
    pub fn binding(&self) -> &DiskBinding {
        &self.after.binding
    }
}
struct ReadonlyObservationLease<'a> {
    file: &'a File,
    events: &'a mut Vec<NativeEvent>,
    restoration_attempted: bool,
}
impl ReadonlyObservationLease<'_> {
    fn finish(&mut self) -> io::Result<()> {
        self.restoration_attempted = true;
        set_attributes(self.file, OFFLINE | READ_ONLY, self.events)?;
        control(
            self.file,
            "refresh-excluded-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            self.events,
        )?;
        Ok(())
    }
}
impl Drop for ReadonlyObservationLease<'_> {
    fn drop(&mut self) {
        if !self.restoration_attempted {
            let _ = self.finish();
        }
    }
}

#[derive(Clone, Debug)]
pub struct WritePolicy {
    pub allowed: Vec<(u64, u64)>,
    pub retained: Vec<(u64, u64)>,
    pub maximum_bytes: u64,
}

impl WritePolicy {
    pub fn validate(&self, length: u64) -> io::Result<()> {
        layout::validate_ranges(&self.allowed, length)?;
        // Relocation-only tree plans have no retained ranges. The native
        // fixture adapter still enforces its original one-range profile.
        if !self.retained.is_empty() {
            layout::validate_ranges(&self.retained, length)?;
        }
        let mut bytes = 0_u64;
        for &(offset, count) in &self.allowed {
            bytes = bytes
                .checked_add(count)
                .ok_or_else(|| invalid("write budget overflow"))?;
            for &(keep, keep_count) in &self.retained {
                if offset < keep + keep_count && keep < offset + count {
                    return Err(invalid("write policy overlaps retained data"));
                }
            }
        }
        if bytes > self.maximum_bytes || self.maximum_bytes > 256 * 1024 * 1024 {
            return Err(invalid(
                "native write policy exceeds the explicit 256 MiB profile",
            ));
        }
        Ok(())
    }

    fn permits(&self, offset: u64, count: u64) -> bool {
        if !offset.is_multiple_of(GRANULE) || !count.is_multiple_of(GRANULE) || count == 0 {
            return false;
        }
        offset.checked_add(count).is_some_and(|end| {
            self.allowed
                .iter()
                .any(|&(at, len)| at <= offset && end <= at + len)
        })
    }
}

fn control(
    file: &File,
    name: &str,
    code: u32,
    input: &[u8],
    capacity: usize,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    if input.len() > 64 || capacity > 65536 || events.len() >= 128 {
        return Err(invalid("native control budget exceeded"));
    }
    let mut output = vec![0; capacity];
    let mut returned = 0_u32;
    // SAFETY: File owns a live Windows handle; input/output are separately owned
    // buffers of the declared sizes. Synchronous I/O retains neither pointer.
    let success = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if output.is_empty() {
                ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } != 0;
    let error = if success {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    if returned as usize > capacity {
        return Err(invalid(
            "native control returned more bytes than its buffer",
        ));
    }
    output.truncate(returned as usize);
    events.push(NativeEvent {
        operation: name.into(),
        control_code: code,
        input: input.to_vec(),
        succeeded: success,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: output.clone(),
    });
    if let Some(error) = error {
        return Err(io::Error::new(error.kind(), format!("{name}: {error}")));
    }
    Ok(output)
}

fn device_file(path: &str, writable: bool, unbuffered: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(writable).share_mode(3);
    if unbuffered {
        options.custom_flags(0xa000_0000);
    } // NO_BUFFERING | WRITE_THROUGH
    options.open(path)
}

fn attributes(file: &File, events: &mut Vec<NativeEvent>) -> io::Result<u64> {
    let bytes = control(file, "get-disk-attributes", GET_ATTRIBUTES, &[], 16, events)?;
    if bytes.len() != 16 || layout::u32_at(&bytes, 0)? != 16 {
        return Err(invalid("disk attributes response differs"));
    }
    let attributes = layout::u64_at(&bytes, 8)?;
    if attributes & !(OFFLINE | READ_ONLY) != 0 {
        return Err(invalid("unknown disk attributes"));
    }
    Ok(attributes)
}

fn set_attributes(file: &File, value: u64, events: &mut Vec<NativeEvent>) -> io::Result<()> {
    if value & !(OFFLINE | READ_ONLY) != 0 {
        return Err(invalid("unknown requested attributes"));
    }
    let mut bytes = [0_u8; 40];
    bytes[..4].copy_from_slice(&40_u32.to_le_bytes());
    bytes[4] = 1; // Persist: the exclusion must survive a restart.
    bytes[8..16].copy_from_slice(&value.to_le_bytes());
    bytes[16..24].copy_from_slice(&(OFFLINE | READ_ONLY).to_le_bytes());
    control(
        file,
        "set-persistent-disk-attributes",
        SET_ATTRIBUTES,
        &bytes,
        0,
        events,
    )?;
    if attributes(file, events)? != value {
        return Err(invalid("disk attribute transition did not take effect"));
    }
    Ok(())
}

pub(crate) fn current_windows_disk(events: &mut Vec<NativeEvent>) -> io::Result<u32> {
    let mut name = vec![0_u16; 512];
    // SAFETY: the output buffer contains 512 writable UTF-16 elements.
    let count = unsafe { GetWindowsDirectoryW(name.as_mut_ptr(), name.len() as u32) } as usize;
    if count < 3 || count >= name.len() || name[1] != b':' as u16 || name[2] != b'\\' as u16 {
        return Err(invalid(
            "current Windows volume cannot be safely identified",
        ));
    }
    let letter =
        char::from_u32(u32::from(name[0])).ok_or_else(|| invalid("invalid system drive"))?;
    if !letter.is_ascii_alphabetic() {
        return Err(invalid("current Windows path is not a drive path"));
    }
    let volume = device_file(&format!("\\\\.\\{letter}:"), false, false)?;
    let bytes = control(
        &volume,
        "current-windows-extents",
        VOLUME_EXTENTS,
        &[],
        1024,
        events,
    )?;
    if bytes.len() != 32 || layout::u32_at(&bytes, 0)? != 1 {
        return Err(invalid("current Windows disk is not a simple volume"));
    }
    layout::u32_at(&bytes, 8)
}

pub(crate) fn snapshot(
    file: &File,
    binding: &DiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionSnapshot> {
    binding.validate()?;
    let device = control(file, "storage-device-number", DEVICE, &[], 12, events)?;
    layout::validate_device(&device, binding.disk_number)?;
    let length = control(file, "disk-length", LENGTH, &[], 8, events)?;
    if length.len() != 8 || layout::u64_at(&length, 0)? != binding.identity.disk_bytes {
        return Err(invalid("physical disk length differs"));
    }
    let mut property = [0_u8; 12];
    property[0] = 6;
    let alignment = control(file, "storage-alignment", ALIGNMENT, &property, 28, events)?;
    layout::validate_alignment(&alignment)?;
    let layout_bytes = control(file, "gpt-layout", LAYOUT, &[], 65536, events)?;
    layout::validate_layout(&layout_bytes, binding)?;
    let disk_attributes = attributes(file, events)?;
    Ok(PartitionSnapshot {
        binding: binding.clone(),
        disk_attributes,
        device,
        length,
        alignment,
        layout: layout_bytes,
    })
}

/// Recheck immutable disk route, geometry and layout through the same handle.
fn general_disk_state(
    disk: &File,
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskState> {
    binding.validate()?;
    let device = control(&disk, "general-storage-device", DEVICE, &[], 12, events)?;
    layout::validate_device(&device, binding.disk_number)?;
    let disk_length = control(&disk, "general-disk-length", LENGTH, &[], 8, events)?;
    if disk_length.len() != 8 || layout::u64_at(&disk_length, 0)? != binding.identity.disk_bytes {
        return Err(invalid("general disk length differs"));
    }
    let mut property = [0u8; 12];
    property[0] = 6;
    let alignment = control(
        &disk,
        "general-storage-alignment",
        ALIGNMENT,
        &property,
        28,
        events,
    )?;
    binding.validate_alignment(&alignment)?;
    let gpt_layout = control(&disk, "general-gpt-layout", LAYOUT, &[], 65536, events)?;
    binding.validate_layout(&gpt_layout)?;
    let disk_attributes = attributes(&disk, events)?;
    Ok(GeneralDiskState {
        device,
        disk_length,
        alignment,
        gpt_layout,
        disk_attributes,
    })
}

/// Probe one dedicated non-system basic data disk without locking, dismounting,
/// setting attributes or issuing raw writes. This is not a conversion lease.
pub fn probe_general(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralProbe> {
    binding.validate()?;
    if current_windows_disk(events)? == binding.disk_number {
        return Err(invalid("current Windows disk is excluded"));
    }
    let disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        false,
        false,
    )?;
    let state = general_disk_state(&disk, &binding, events)?;
    let disk_attributes_before = state.disk_attributes;
    if disk_attributes_before != 0 {
        return Err(invalid("general data disk is not online and writable"));
    }
    let volume = device_file(&binding.volume_path()?, false, false)?;
    let volume_extents = control(
        &volume,
        "general-volume-extents",
        VOLUME_EXTENTS,
        &[],
        1024,
        events,
    )?;
    binding.validate_volume_extent(&volume_extents)?;
    let after = general_disk_state(&disk, &binding, events)?;
    let disk_attributes_after = after.disk_attributes;
    if after.device != state.device
        || after.disk_length != state.disk_length
        || after.alignment != state.alignment
        || after.gpt_layout != state.gpt_layout
    {
        return Err(invalid("general disk layout changed during probe"));
    }
    if disk_attributes_after != disk_attributes_before {
        return Err(invalid("general disk attributes changed during probe"));
    }
    Ok(GeneralProbe {
        binding,
        disk_attributes_before,
        disk_attributes_after,
        device: state.device,
        disk_length: state.disk_length,
        alignment: state.alignment,
        gpt_layout: state.gpt_layout,
        volume_extents,
        read_only_probe: true,
        source_write_requests: 0,
        conversion_qualified: false,
    })
}

/// Observe the mounted filesystem name only after the bound dedicated disk
/// has become online and writable. The GPT route is rechecked first.
pub fn mounted_filesystem_general(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<String> {
    probe_general(binding.clone(), events)?;
    let path = format!("{}\\", binding.volume_path()?);
    let mut path_wide: Vec<u16> = path.encode_utf16().collect();
    path_wide.push(0);
    let mut filesystem = [0u16; 32];
    let mut serial = 0u32;
    let mut component = 0u32;
    let mut flags = 0u32;
    // SAFETY: both buffers are initialized, the path is NUL-terminated, and
    // the synchronous API retains no pointer.
    let success = unsafe {
        GetVolumeInformationW(
            path_wide.as_ptr(),
            ptr::null_mut(),
            0,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = filesystem
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("mounted filesystem name is unterminated"))?;
    String::from_utf16(&filesystem[..end])
        .map_err(|_| invalid("mounted filesystem name is invalid UTF-16"))
}

fn decode_mount_paths(buffer: &[u16], returned: usize) -> io::Result<Vec<String>> {
    if returned == 0 || returned > buffer.len() {
        return Err(invalid("mount-path list exceeds bounded buffer"));
    }
    let mut paths = Vec::new();
    let mut start = 0usize;
    while start < returned {
        let end = buffer[start..returned]
            .iter()
            .position(|unit| *unit == 0)
            .map(|relative| start + relative)
            .ok_or_else(|| invalid("mount-path list is unterminated"))?;
        if end == start {
            return Ok(paths);
        }
        let path = String::from_utf16(&buffer[start..end])
            .map_err(|_| invalid("mount path is invalid UTF-16"))?;
        if !path.ends_with('\\') || paths.contains(&path) || paths.len() >= 128 {
            return Err(invalid("mount path is malformed or repeated"));
        }
        paths.push(path);
        start = end + 1;
    }
    Err(invalid("mount-path list has no final terminator"))
}

/// Capture every drive-letter or mounted-folder path that Windows currently
/// associates with the exact bound volume. Every returned path is resolved
/// back to the same volume GUID through a separate Mount Manager query.
pub fn capture_mount_paths_general(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<MountPathObservation> {
    probe_general(binding.clone(), events)?;
    let root = format!("{}\\", binding.volume_path()?);
    let mut root_wide: Vec<u16> = root.encode_utf16().collect();
    root_wide.push(0);
    let mut buffer = [0u16; 4096];
    let mut returned = 0u32;
    // SAFETY: initialized NUL-terminated input and writable bounded output.
    let success = unsafe {
        GetVolumePathNamesForVolumeNameW(
            root_wide.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut returned,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let paths = decode_mount_paths(&buffer, returned as usize)?;
    for path in &paths {
        let mut path_wide: Vec<u16> = path.encode_utf16().collect();
        path_wide.push(0);
        let mut mapped = [0u16; 1024];
        // SAFETY: initialized NUL-terminated mount path and writable output.
        if unsafe {
            GetVolumeNameForVolumeMountPointW(
                path_wide.as_ptr(),
                mapped.as_mut_ptr(),
                mapped.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mapped_end = mapped
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("resolved mount volume name is unterminated"))?;
        let mapped_name = String::from_utf16(&mapped[..mapped_end])
            .map_err(|_| invalid("resolved mount volume name is invalid UTF-16"))?;
        if layout::guid_bytes(&enumerated_guid(&mapped_name)?)?
            != layout::guid_bytes(&binding.volume_guid)?
        {
            return Err(invalid("mount path resolves to a different volume"));
        }
    }
    Ok(MountPathObservation {
        binding,
        paths,
        all_paths_resolve_to_bound_volume: true,
    })
}

/// Add one original drive letter to a converted ReFS data volume only when
/// the letter is unbound and the volume has no different drive letter. No
/// existing mount point is deleted or reassigned by this operation.
pub fn restore_drive_letter_general(
    binding: GeneralDiskBinding,
    requested: &str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<DriveLetterRestore> {
    let bytes = requested.as_bytes();
    if bytes.len() != 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\'
    {
        return Err(invalid("requested mount point is not a drive-letter root"));
    }
    let bound = rediscover_general_volume_wait(binding, events)?;
    let filesystem = mounted_filesystem_general(bound.clone(), events)?;
    if filesystem != "ReFS" {
        return Err(invalid("drive-letter restoration requires converted ReFS"));
    }
    let before = capture_mount_paths_general(bound.clone(), events)?;
    if before
        .paths
        .iter()
        .any(|path| path.eq_ignore_ascii_case(requested))
    {
        return Ok(DriveLetterRestore {
            requested: requested.into(),
            after: before.clone(),
            before,
            changed: false,
            target_filesystem: filesystem,
        });
    }
    if before.paths.iter().any(|path| {
        let bytes = path.as_bytes();
        bytes.len() == 3 && bytes[1] == b':' && bytes[2] == b'\\'
    }) {
        return Err(invalid(
            "converted ReFS volume already has another drive letter",
        ));
    }
    let mut mount_wide: Vec<u16> = requested.encode_utf16().collect();
    mount_wide.push(0);
    let mut existing = [0u16; 1024];
    // SAFETY: bounded NUL-terminated path and initialized output buffer.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(
            mount_wide.as_ptr(),
            existing.as_mut_ptr(),
            existing.len() as u32,
        )
    } != 0
    {
        let end = existing
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("occupied drive volume name is unterminated"))?;
        let name = String::from_utf16(&existing[..end])
            .map_err(|_| invalid("occupied drive volume name is invalid UTF-16"))?;
        if layout::guid_bytes(&enumerated_guid(&name)?)? != layout::guid_bytes(&bound.volume_guid)?
        {
            return Err(invalid("requested drive letter belongs to another volume"));
        }
        return Err(invalid(
            "drive letter maps to target but was absent from mount-path enumeration",
        ));
    }
    let volume_root = format!("{}\\", bound.volume_path()?);
    let mut volume_wide: Vec<u16> = volume_root.encode_utf16().collect();
    volume_wide.push(0);
    // SAFETY: both paths are NUL-terminated and the synchronous API retains
    // no pointer. The Windows mount manager refuses occupied drive letters.
    if unsafe { SetVolumeMountPointW(mount_wide.as_ptr(), volume_wide.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let after = capture_mount_paths_general(bound, events)?;
    if !after
        .paths
        .iter()
        .any(|path| path.eq_ignore_ascii_case(requested))
    {
        return Err(invalid("new drive-letter mount point was not observed"));
    }
    Ok(DriveLetterRestore {
        requested: requested.into(),
        before,
        after,
        changed: true,
        target_filesystem: filesystem,
    })
}

fn enumerated_guid(name: &str) -> io::Result<String> {
    let guid = name
        .strip_prefix("\\\\?\\Volume{")
        .and_then(|rest| rest.strip_suffix("}\\"))
        .ok_or_else(|| invalid("enumerated volume GUID path differs"))?;
    layout::guid_bytes(guid)?;
    Ok(guid.into())
}

struct VolumeEnumeration(windows_sys::Win32::Foundation::HANDLE);
impl Drop for VolumeEnumeration {
    fn drop(&mut self) {
        // SAFETY: this is the unique live search handle returned by
        // FindFirstVolumeW; Drop runs exactly once.
        unsafe { FindVolumeClose(self.0) };
    }
}

/// Rediscover the volume-GUID path of the same GPT partition after formatting
/// changes the filesystem identity. Every candidate must resolve to the exact
/// bound physical disk/partition; zero or multiple matches are refused.
pub fn rediscover_general_volume(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskBinding> {
    binding.validate()?;
    if current_windows_disk(events)? == binding.disk_number {
        return Err(invalid("current Windows disk is excluded"));
    }
    let disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        false,
        false,
    )?;
    if general_disk_state(&disk, &binding, events)?.disk_attributes != 0 {
        return Err(invalid(
            "general volume rediscovery requires online writable disk",
        ));
    }
    let mut buffer = [0u16; 1024];
    // SAFETY: initialized writable UTF-16 buffer of the declared length.
    let handle = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let _search = VolumeEnumeration(handle);
    let mut matches = Vec::new();
    let mut finished = false;
    for _ in 0..1024 {
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("enumerated volume name is unterminated"))?;
        let name = String::from_utf16(&buffer[..end])
            .map_err(|_| invalid("enumerated volume name is invalid UTF-16"))?;
        if let Ok(guid) = enumerated_guid(&name)
            && let Ok(volume) = device_file(name.trim_end_matches('\\'), false, false)
            && let Ok(extents) = control(
                &volume,
                "rediscovered-volume-extents",
                VOLUME_EXTENTS,
                &[],
                1024,
                events,
            )
            && binding.validate_volume_extent(&extents).is_ok()
        {
            matches.push(guid);
        }
        buffer.fill(0);
        // SAFETY: the search handle and writable buffer remain live for this
        // synchronous enumeration call.
        if unsafe { FindNextVolumeW(handle, buffer.as_mut_ptr(), buffer.len() as u32) } == 0 {
            // SAFETY: the error belongs to the immediately preceding call.
            if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                return Err(io::Error::last_os_error());
            }
            finished = true;
            break;
        }
    }
    if !finished {
        return Err(invalid("volume enumeration exceeded its bounded scan"));
    }
    if matches.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "bound physical partition has no published volume-GUID path",
        ));
    }
    if matches.len() != 1 {
        return Err(invalid("physical partition has multiple volume-GUID paths"));
    }
    let mut updated = binding;
    updated.volume_guid = matches.remove(0);
    probe_general(updated.clone(), events)?;
    Ok(updated)
}

/// Wait at most 15 seconds for a newly online volume interface to appear.
/// Only absence is retried; identity, geometry and duplicate-route failures
/// remain immediate hard refusals.
pub fn rediscover_general_volume_wait(
    binding: GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskBinding> {
    for attempt in 0..60 {
        match rediscover_general_volume(binding.clone(), events) {
            Ok(found) => return Ok(found),
            Err(error) if error.kind() == io::ErrorKind::NotFound && attempt < 59 => {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Err(error) => return Err(error),
        }
    }
    Err(invalid("volume publication retry bound exhausted"))
}

struct AlignedBuffer {
    pointer: NonNull<u8>,
    layout: Layout,
}
impl AlignedBuffer {
    fn new() -> io::Result<Self> {
        let layout = Layout::from_size_align(MAX_IO, GRANULE as usize)
            .map_err(|_| invalid("alignment layout"))?;
        // SAFETY: layout is nonzero and valid. The allocation is owned here and
        // freed once in Drop with the identical layout; every byte is initialized.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| io::Error::other("aligned allocation failed"))?;
        Ok(Self { pointer, layout })
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: self uniquely owns MAX_IO initialized bytes at pointer.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), MAX_IO) }
    }
}
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: pointer/layout came from alloc_zeroed and are released once.
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}

/// Partition-relative stream whose raw file never escapes. Drop does not clear
/// persistent offline/read-only attributes and therefore cannot mount partial data.
pub struct OfflinePartition {
    file: File,
    binding: DiskBinding,
    read_only: bool,
    position: u64,
    buffer: AlignedBuffer,
    policy: Option<WritePolicy>,
    write_poisoned: bool,
    pub native_bytes_read: u64,
    pub native_bytes_written: u64,
    pub native_write_bytes_requested: u64,
}

/// Partition-relative, physically aligned read-only view of a currently
/// mounted dedicated data disk. Concurrent filesystem writes remain possible;
/// callers must not mistake an inspection through this handle for admission.
pub struct GeneralPartitionReader {
    file: File,
    binding: GeneralDiskBinding,
    initial_probe: GeneralProbe,
    position: u64,
    buffer: AlignedBuffer,
    pub native_bytes_read: u64,
}

/// Read-only raw partition access while a mounted data volume is locked.
/// Closing the lock handle releases the lock; no disk attributes are changed.
/// This is a short-lived observation primitive, not persistent conversion
/// exclusion or a certificate that survives process death.
pub struct GeneralLockedPartition {
    reader: GeneralPartitionReader,
    volume_lock: Option<File>,
}

impl GeneralLockedPartition {
    pub fn open(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        let reader = GeneralPartitionReader::open(binding.clone(), events)?;
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let extents = control(
            &volume,
            "policy-lock-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&extents)?;
        control(&volume, "policy-lock-volume", LOCK, &[], 0, events)?;
        Ok(Self {
            reader,
            volume_lock: Some(volume),
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.reader.byte_len()
    }
    pub fn native_bytes_read(&self) -> u64 {
        self.reader.native_bytes_read
    }

    /// Explicitly release the observation lock and verify the original route.
    /// An error also closes the local lock handle during unwinding.
    pub fn finish(mut self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralProbe> {
        let volume = self
            .volume_lock
            .take()
            .ok_or_else(|| invalid("volume lock already released"))?;
        control(&volume, "policy-unlock-volume", UNLOCK, &[], 0, events)?;
        close_file(volume, "close-policy-volume-lock", events)?;
        self.reader.revalidate_route(events)
    }
}

impl Read for GeneralLockedPartition {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reader.read(bytes)
    }
}
impl Seek for GeneralLockedPartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.reader.seek(from)
    }
}

/// Persistently excluded general data partition. This handle has no Write
/// implementation and cannot make the disk mountable.
pub struct GeneralFrozenPartition {
    file: File,
    binding: GeneralDiskBinding,
    frozen_state: GeneralDiskState,
    position: u64,
    buffer: AlignedBuffer,
    native_bytes_read: u64,
    freeze_observation: Option<GeneralFreezeObservation>,
}

/// Constructed only across an actual native observation, successful volume
/// lock/dismount and persistent exclusion. Reopening cannot recreate it.
#[derive(Debug, Serialize)]
pub struct GeneralFreezeObservation {
    mounted_ntfs: crate::txf_native::GeneralObservation,
    frozen_state: GeneralDiskState,
}
impl GeneralFreezeObservation {
    pub fn mounted_ntfs(&self) -> &crate::txf_native::GeneralObservation {
        &self.mounted_ntfs
    }
}

/// Activated, persistently offline general target. Writes remain unavailable
/// until the caller arms the exact patch set of a durable external journal.
/// Dropping this handle never clears OFFLINE.
pub struct GeneralJournaledPartition {
    inner: GeneralFrozenPartition,
    policy: Option<WritePolicy>,
    write_poisoned: bool,
    pub native_bytes_written: u64,
    pub native_write_bytes_requested: u64,
}

impl GeneralFrozenPartition {
    pub fn isolate_observed_ntfs(
        binding: GeneralDiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        if mounted_filesystem_general(binding.clone(), events)? != "NTFS" {
            return Err(invalid("observed source freeze requires mounted NTFS"));
        }
        let mounted_ntfs = crate::txf_native::observe_general(binding.clone())?;
        if mounted_ntfs.observation.default_rm_state()
            == crate::txf_native::DefaultRmState::Unresolved
        {
            return Err(invalid(
                "default NTFS resource manager is not idle or inactive",
            ));
        }
        let mut frozen = Self::isolate(binding, events)?;
        frozen.freeze_observation = Some(GeneralFreezeObservation {
            mounted_ntfs,
            frozen_state: frozen.frozen_state.clone(),
        });
        Ok(frozen)
    }

    pub fn freeze_observation(&self) -> Option<&GeneralFreezeObservation> {
        self.freeze_observation.as_ref().filter(|proof| {
            proof.frozen_state == self.frozen_state && proof.mounted_ntfs.binding == self.binding
        })
    }
    /// Lock/dismount and persistently exclude a bound dedicated data disk.
    /// Dropping the returned handle does not bring the disk online.
    pub fn isolate(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        let before = probe_general(binding.clone(), events)?;
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let pre_lock = general_disk_state(&management, &binding, events)?;
        if pre_lock.disk_attributes != 0
            || pre_lock.device != before.device
            || pre_lock.disk_length != before.disk_length
            || pre_lock.alignment != before.alignment
            || pre_lock.gpt_layout != before.gpt_layout
        {
            return Err(invalid("general disk changed before lock"));
        }
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let extents = control(
            &volume,
            "general-lock-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&extents)?;
        let buffer = AlignedBuffer::new()?;
        control(&volume, "general-lock-volume", LOCK, &[], 0, events)?;
        control(&volume, "general-dismount-volume", DISMOUNT, &[], 0, events)?;
        set_attributes(&management, OFFLINE | READ_ONLY, events)?;
        close_file(volume, "close-general-volume-lock", events)?;
        let frozen = general_disk_state(&management, &binding, events)?;
        if frozen.disk_attributes != OFFLINE | READ_ONLY
            || frozen.device != pre_lock.device
            || frozen.disk_length != pre_lock.disk_length
            || frozen.alignment != pre_lock.alignment
            || frozen.gpt_layout != pre_lock.gpt_layout
        {
            return Err(invalid("general disk exclusion or identity changed"));
        }
        close_file(management, "close-general-management", events)?;
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            true,
        )?;
        if general_disk_state(&file, &binding, events)? != frozen {
            return Err(invalid("general read-only reopen differs after exclusion"));
        }
        Ok(Self {
            file,
            binding,
            frozen_state: frozen,
            position: 0,
            buffer,
            native_bytes_read: 0,
            freeze_observation: None,
        })
    }

    pub fn reopen(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            true,
        )?;
        let frozen_state = general_disk_state(&file, &binding, events)?;
        if frozen_state.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "general disk is not persistently offline and read-only",
            ));
        }
        Ok(Self {
            file,
            binding,
            frozen_state,
            position: 0,
            buffer: AlignedBuffer::new()?,
            native_bytes_read: 0,
            freeze_observation: None,
        })
    }

    /// Recover from process death during native observation. An already
    /// excluded disk is reopened unchanged. A still-mounted READ_ONLY disk is
    /// locked, dismounted and returned to persistent OFFLINE|READ_ONLY. Any
    /// writable, foreign or changed disk is refused.
    pub fn restore_exclusion(
        binding: GeneralDiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<(Self, bool)> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            false,
        )?;
        let before = general_disk_state(&management, &binding, events)?;
        if before.disk_attributes == OFFLINE | READ_ONLY {
            close_file(management, "close-general-already-excluded", events)?;
            return Ok((Self::reopen(binding, events)?, false));
        }
        if before.disk_attributes != READ_ONLY {
            return Err(invalid(
                "general observation recovery requires read-only disk",
            ));
        }
        let volume = device_file(&binding.volume_path()?, false, false)?;
        let extents = control(
            &volume,
            "general-recovery-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        binding.validate_volume_extent(&extents)?;
        control(
            &volume,
            "general-recovery-lock-volume",
            LOCK,
            &[],
            0,
            events,
        )?;
        control(
            &volume,
            "general-recovery-dismount-volume",
            DISMOUNT,
            &[],
            0,
            events,
        )?;
        set_attributes(&management, OFFLINE | READ_ONLY, events)?;
        close_file(volume, "close-general-recovery-volume", events)?;
        let mut expected = before;
        expected.disk_attributes = OFFLINE | READ_ONLY;
        if general_disk_state(&management, &binding, events)? != expected {
            return Err(invalid(
                "general exclusion recovery changed storage identity",
            ));
        }
        close_file(management, "close-general-recovery-management", events)?;
        let restored = Self::reopen(binding, events)?;
        if restored.frozen_state != expected {
            return Err(invalid("general exclusion recovery reopen differs"));
        }
        Ok((restored, true))
    }

    pub fn revalidate_route(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if general_disk_state(&self.file, &self.binding, events)? != self.frozen_state {
            return Err(invalid("general frozen route changed"));
        }
        Ok(())
    }

    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }

    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }

    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        let state = general_disk_state(&self.file, &self.binding, events)?;
        if state != self.frozen_state {
            return Err(invalid("general frozen route changed"));
        }
        Ok(state)
    }

    pub fn native_bytes_read(&self) -> u64 {
        self.native_bytes_read
    }

    /// Abort before journal activation. A complete hash of the unchanged
    /// offline/read-only partition is required before the original NTFS disk
    /// can be made writable and mountable again.
    pub fn bring_original_online_unchanged(
        mut self,
        expected_sha256: &str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if expected_sha256.len() != 64
            || !expected_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid original NTFS SHA-256 pin"));
        }
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("original source is not offline and read-only"));
        }
        self.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; MAX_IO];
        let mut left = self.byte_len();
        while left != 0 {
            let count = left.min(MAX_IO as u64) as usize;
            self.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            left -= count as u64;
        }
        if hex::encode(hash.finalize()) != expected_sha256 || self.state(events)? != before {
            return Err(invalid("original source bytes or exclusion changed"));
        }
        let binding = self.binding.clone();
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &binding, events)? != before {
            return Err(invalid("original source control-handle route differs"));
        }
        close_file(self.file, "close-original-source-before-online", events)?;
        set_attributes(&management, 0, events)?;
        control(
            &management,
            "refresh-original-source-online-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            events,
        )?;
        let mut expected = before;
        expected.disk_attributes = 0;
        if general_disk_state(&management, &binding, events)? != expected {
            return Err(invalid(
                "original NTFS online transition changed storage identity",
            ));
        }
        close_file(
            management,
            "close-original-source-online-management",
            events,
        )
    }

    /// Temporarily publish only a READ_ONLY NTFS view for native semantic
    /// collection, then restore OFFLINE|READ_ONLY before returning. A process
    /// death can leave a write-protected mounted view requiring explicit
    /// recovery; no automatic writable fallback exists.
    pub fn observe_ntfs_files(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveNtfsObservation> {
        request.validate()?;
        if request.schema_version != 2
            || request.disk_number != self.binding.disk_number
            || request.volume != format!("{}\\", self.binding.volume_path()?)
            || request.partition_offset != self.binding.identity.partition_offset
            || request.partition_length != self.byte_len()
        {
            return Err(invalid("general native observer binding differs"));
        }
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("general source is not persistently excluded"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &self.binding, events)? != before {
            return Err(invalid("general observer control-handle route differs"));
        }
        let mut lease = ReadonlyObservationLease {
            file: &management,
            events,
            restoration_attempted: false,
        };
        set_attributes(lease.file, READ_ONLY, lease.events)?;
        control(
            lease.file,
            "refresh-general-readonly-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            lease.events,
        )?;
        let mut ready = false;
        for _ in 0..60 {
            if attributes(lease.file, lease.events)? != READ_ONLY {
                return Err(invalid(
                    "general source read-only observation state changed",
                ));
            }
            match device_file(&self.binding.volume_path()?, false, false) {
                Ok(volume) => {
                    drop(volume);
                    ready = true;
                    break;
                }
                Err(error) if matches!(error.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                    std::thread::sleep(std::time::Duration::from_millis(250))
                }
                Err(error) => return Err(error),
            }
        }
        if !ready {
            return Err(invalid(
                "general read-only volume was not published within 15 seconds",
            ));
        }
        let collected = crate::attestation_native::collect_file_metadata(request);
        let (txf, txf_error) = match crate::txf_native::observe_general(self.binding.clone()) {
            Ok(observation) => (Some(observation), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let restored = lease.finish();
        drop(lease);
        restored?;
        let after = self.state(events)?;
        if before != after {
            return Err(invalid(
                "general source exclusion changed during native observation",
            ));
        }
        Ok(GeneralLiveNtfsObservation {
            report: collected?,
            txf,
            txf_error,
            before,
            after,
        })
    }

    /// Transition only an unchanged OFFLINE|READ_ONLY source to OFFLINE. The
    /// caller must first persist and verify its external recovery journal.
    pub fn activate_for_journal(
        mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralJournaledPartition> {
        self.state(events)?;
        if self.frozen_state.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "general journal activation requires frozen read-only disk",
            ));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &self.binding, events)? != self.frozen_state {
            return Err(invalid("general activation control-handle route differs"));
        }
        set_attributes(&management, OFFLINE, events)?;
        let writable = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            true,
        )?;
        let mut expected = self.frozen_state.clone();
        expected.disk_attributes = OFFLINE;
        if general_disk_state(&writable, &self.binding, events)? != expected {
            return Err(invalid(
                "general journal activation lost persistent exclusion",
            ));
        }
        close_file(management, "close-general-activation-management", events)?;
        self.file = writable;
        self.frozen_state = expected;
        Ok(GeneralJournaledPartition {
            inner: self,
            policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }
}

impl GeneralJournaledPartition {
    /// Reopen an already activated target after an interruption. A missing
    /// OFFLINE attribute is a hard refusal; no attribute repair is attempted.
    pub fn reopen(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let frozen_state = general_disk_state(&file, &binding, events)?;
        if frozen_state.disk_attributes != OFFLINE {
            return Err(invalid(
                "general journal target is not persistently offline",
            ));
        }
        Ok(Self {
            inner: GeneralFrozenPartition {
                freeze_observation: None,
                file,
                binding,
                frozen_state,
                position: 0,
                buffer: AlignedBuffer::new()?,
                native_bytes_read: 0,
            },
            policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.inner.byte_len()
    }

    pub fn binding(&self) -> &GeneralDiskBinding {
        self.inner.binding()
    }

    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        self.inner.state(events)
    }

    pub fn arm_writes(
        &mut self,
        policy: WritePolicy,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if self.policy.is_some() || self.write_poisoned || self.native_write_bytes_requested != 0 {
            return Err(invalid("general journal write policy is already consumed"));
        }
        policy.validate(self.byte_len())?;
        if self.state(events)?.disk_attributes != OFFLINE {
            return Err(invalid("general target is not excluded from mounting"));
        }
        self.policy = Some(policy);
        Ok(())
    }

    pub fn sync_all(&mut self) -> io::Result<()> {
        if let Err(error) = self.inner.file.sync_all() {
            self.write_poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Call only after a durable journal handoff or verified rollback. This
    /// consumes the handle and is the sole general target mount transition.
    pub fn bring_online(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if self.write_poisoned {
            return Err(invalid("cannot expose a failed general target"));
        }
        self.policy = None;
        self.sync_all()?;
        self.state(events)?;
        set_attributes(&self.inner.file, 0, events)?;
        control(
            &self.inner.file,
            "refresh-online-general-target-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            events,
        )?;
        close_file(self.inner.file, "close-online-general-target", events)
    }
}

impl Read for GeneralJournaledPartition {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }
}

impl Seek for GeneralJournaledPartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.inner.seek(from)
    }
}

impl Write for GeneralJournaledPartition {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let policy = self.policy.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "general raw writes are not armed",
            )
        })?;
        let attempted = self
            .native_write_bytes_requested
            .checked_add(input.len() as u64)
            .ok_or_else(|| invalid("general write accounting overflow"))?;
        if self.write_poisoned
            || input.len() > MAX_IO
            || !policy.permits(self.inner.position, input.len() as u64)
            || attempted > policy.maximum_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "general native write violates bounded journal policy",
            ));
        }
        self.inner.file.seek(SeekFrom::Start(
            self.inner.binding.identity.partition_offset + self.inner.position,
        ))?;
        self.inner.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
        self.native_write_bytes_requested = attempted;
        let result = self
            .inner
            .file
            .write(&self.inner.buffer.bytes_mut()[..input.len()]);
        match result {
            Ok(count) => {
                self.native_bytes_written += count as u64;
                if count != input.len() {
                    self.write_poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short general native write; reopen through recovery",
                    ));
                }
                self.inner.position += count as u64;
                Ok(count)
            }
            Err(error) => {
                self.write_poisoned = true;
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl GeneralPartitionReader {
    pub fn open(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        let initial_probe = probe_general(binding.clone(), events)?;
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            true,
        )?;
        Ok(Self {
            file,
            binding,
            initial_probe,
            position: 0,
            buffer: AlignedBuffer::new()?,
            native_bytes_read: 0,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }

    pub fn initial_probe(&self) -> &GeneralProbe {
        &self.initial_probe
    }

    pub fn revalidate_route(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralProbe> {
        let after = probe_general(self.binding.clone(), events)?;
        if after.binding != self.initial_probe.binding
            || after.device != self.initial_probe.device
            || after.disk_length != self.initial_probe.disk_length
            || after.alignment != self.initial_probe.alignment
            || after.gpt_layout != self.initial_probe.gpt_layout
            || after.volume_extents != self.initial_probe.volume_extents
            || after.disk_attributes_after != self.initial_probe.disk_attributes_after
        {
            return Err(invalid(
                "general disk route changed during read-only inventory",
            ));
        }
        Ok(after)
    }
}

impl Read for GeneralPartitionReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned general read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read += read as u64;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short general aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Seek for GeneralPartitionReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes general partition"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

impl Read for GeneralFrozenPartition {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned frozen read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read += read as u64;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short frozen aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Seek for GeneralFrozenPartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes frozen partition"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

fn close_file(file: File, name: &str, events: &mut Vec<NativeEvent>) -> io::Result<()> {
    let raw = file.into_raw_handle();
    // SAFETY: into_raw_handle transferred sole ownership; this is the only close.
    // On failure, do not blindly close again: the handle value could be reused.
    let success = unsafe { CloseHandle(raw) } != 0;
    let error = if success {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    events.push(NativeEvent {
        operation: name.into(),
        control_code: 0,
        input: vec![],
        succeeded: success,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: vec![],
    });
    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

impl OfflinePartition {
    /// Lock/dismount the bound volume, then persist physical disk exclusion.
    /// No raw payload write is issued. Failure does not bring anything online.
    pub fn isolate(
        binding: DiskBinding,
        read_only: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let before = snapshot(&file, &binding, events)?;
        if before.disk_attributes != 0 {
            return Err(invalid("initial disk must be online and writable"));
        }
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let extents = control(
            &volume,
            "bound-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        layout::validate_volume_extent(&extents, &binding)?;
        // Allocate before any device mutation.
        let buffer = AlignedBuffer::new()?;
        control(&volume, "lock-volume", LOCK, &[], 0, events)?;
        control(&volume, "dismount-volume", DISMOUNT, &[], 0, events)?;
        let expected = OFFLINE | if read_only { READ_ONLY } else { 0 };
        set_attributes(&file, expected, events)?;
        // Persistent exclusion is proven before closing the lock owner. Close
        // releases the volume lock; no online/unlock fallback is attempted.
        close_file(volume, "close-isolated-volume", events)?;
        let after = snapshot(&file, &binding, events)?;
        if after.disk_attributes != expected {
            return Err(invalid("disk isolation was lost"));
        }
        Ok(Self {
            file,
            binding,
            read_only,
            position: 0,
            buffer,
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    /// Reopen an already excluded device after interruption. Never changes
    /// attributes as a fallback and never selects a disk by number alone.
    pub fn reopen(
        binding: DiskBinding,
        read_only: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            !read_only,
            true,
        )?;
        let expected = OFFLINE | if read_only { READ_ONLY } else { 0 };
        let found = snapshot(&file, &binding, events)?;
        if found.disk_attributes != expected {
            return Err(invalid(
                "persistent offline state differs; no automatic repair",
            ));
        }
        Ok(Self {
            file,
            binding,
            read_only,
            position: 0,
            buffer: AlignedBuffer::new()?,
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }
    pub fn binding(&self) -> &DiskBinding {
        &self.binding
    }
    pub fn inspect(&self, events: &mut Vec<NativeEvent>) -> io::Result<PartitionSnapshot> {
        snapshot(&self.file, &self.binding, events)
    }
    /// Mount only an already frozen source read-only for supported NTFS API
    /// queries, then persist exclusion again. READ_ONLY is never cleared.
    /// A killed observer can leave a valid, write-protected NTFS mount; this
    /// operation is forbidden after reconstruction has begun.
    pub fn observe_ntfs_files(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<LiveNtfsObservation> {
        request.validate()?;
        if !self.read_only
            || self.policy.is_some()
            || self.native_write_bytes_requested != 0
            || self.native_bytes_written != 0
            || request.disk_number != self.binding.disk_number
            || request.volume.trim_end_matches('\\') != self.binding.volume_path()?
            || request.partition_offset != self.binding.identity.partition_offset
            || request.partition_length != self.byte_len()
        {
            return Err(invalid("read-only source observation binding differs"));
        }
        let before = self.inspect(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("source must already be excluded and read-only"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        let actual = snapshot(&management, &self.binding, events)?;
        if actual.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("control handle source state differs"));
        }
        let mut lease = ReadonlyObservationLease {
            file: &management,
            events,
            restoration_attempted: false,
        };
        set_attributes(lease.file, READ_ONLY, lease.events)?;
        control(
            lease.file,
            "refresh-readonly-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            lease.events,
        )?;
        // Disk attributes and volume-interface publication are distinct. Poll
        // only harmless opens, never repeat a management mutation or drop RO.
        let mut ready = false;
        for _ in 0..60 {
            if attributes(lease.file, lease.events)? != READ_ONLY {
                return Err(invalid("source read-only observation state changed"));
            }
            match device_file(&self.binding.volume_path()?, false, false) {
                Ok(volume) => {
                    drop(volume);
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                    std::thread::sleep(std::time::Duration::from_millis(250))
                }
                Err(e) => return Err(e),
            }
        }
        if !ready {
            return Err(invalid(
                "read-only source volume interface was not published within 15 seconds",
            ));
        }
        let collected = crate::attestation_native::collect_file_metadata(request);
        let restored = lease.finish();
        drop(lease);
        restored?;
        let after = self.inspect(events)?;
        if after.disk_attributes != OFFLINE | READ_ONLY
            || before.binding != after.binding
            || before.device != after.device
            || before.layout != after.layout
            || before.length != after.length
            || before.alignment != after.alignment
        {
            return Err(invalid(
                "source identity or exclusion changed during observation",
            ));
        }
        Ok(LiveNtfsObservation {
            report: collected?,
            before,
            after,
        })
    }

    /// Caller must finish and flush its complete journal and independently
    /// validate the journal ticket before supplying this explicit write set.
    pub fn enable_excluded_writes(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if !self.read_only
            || self.policy.is_some()
            || self.write_poisoned
            || self.native_write_bytes_requested != 0
            || self.inspect(events)?.disk_attributes != OFFLINE | READ_ONLY
        {
            return Err(invalid(
                "journal activation requires an unchanged excluded read-only handle",
            ));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        if snapshot(&management, &self.binding, events)?.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("activation control-handle binding differs"));
        }
        // Persist OFFLINE throughout. If reopening fails, recovery observes the
        // actual state; never retry the transition or expose the volume.
        set_attributes(&management, OFFLINE, events)?;
        let writable = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            true,
        )?;
        if snapshot(&writable, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("journal activation lost persistent exclusion"));
        }
        self.file = writable;
        self.read_only = false;
        Ok(())
    }

    /// Arm the exact ranges of an already durable, independently pinned journal.
    pub fn arm_writes(
        &mut self,
        policy: WritePolicy,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if self.read_only || self.policy.is_some() || self.write_poisoned {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write arming is unavailable in this state",
            ));
        }
        policy.validate(self.byte_len())?;
        if snapshot(&self.file, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("target is not excluded from mounting"));
        }
        self.policy = Some(policy);
        Ok(())
    }

    pub fn sync_all(&mut self) -> io::Result<()> {
        if let Err(error) = self.file.sync_all() {
            self.write_poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Explicit native mount boundary. Journal handoff (or verified rollback
    /// completion) must be durable before this is called. Consumes the stream.
    pub fn bring_online(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if self.read_only || self.write_poisoned {
            return Err(invalid("cannot expose a read-only or failed target"));
        }
        self.policy = None;
        self.sync_all()?;
        if snapshot(&self.file, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("target isolation changed before handoff"));
        }
        set_attributes(&self.file, 0, events)?;
        control(
            &self.file,
            "refresh-online-target-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            events,
        )?;
        close_file(self.file, "close-online-target", events)
    }
}

impl Read for OfflinePartition {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read += read as u64;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short native aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Write for OfflinePartition {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let policy = self.policy.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "raw writes are not armed")
        })?;
        let attempted = self
            .native_write_bytes_requested
            .checked_add(input.len() as u64)
            .ok_or_else(|| invalid("native write accounting overflow"))?;
        if self.read_only
            || self.write_poisoned
            || input.len() > MAX_IO
            || !policy.permits(self.position, input.len() as u64)
            || attempted > policy.maximum_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native write violates bounded policy",
            ));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + self.position,
        ))?;
        self.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
        // A failed/short dispatch has unknown completion. Never retry it through
        // this handle, including through Write::write_all.
        self.native_write_bytes_requested = attempted;
        let result = self.file.write(&self.buffer.bytes_mut()[..input.len()]);
        match result {
            Ok(count) => {
                self.native_bytes_written += count as u64;
                if count != input.len() {
                    self.write_poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short native write; reopen through recovery",
                    ));
                }
                self.position += count as u64;
                Ok(count)
            }
            Err(error) => {
                self.write_poisoned = true;
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl Seek for OfflinePartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes partition"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::PartitionIdentity;

    #[test]
    fn enumerated_volume_name_must_be_a_complete_guid_root() {
        assert_eq!(
            enumerated_guid("\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\").unwrap(),
            "11111111-2222-3333-4444-555555555555"
        );
        for name in [
            "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}",
            "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\file",
            "\\\\?\\Volume{not-a-guid}\\",
        ] {
            assert!(enumerated_guid(name).is_err());
        }
    }

    #[test]
    fn mount_path_multisz_requires_final_terminator_and_no_duplicates() {
        let mut value: Vec<u16> = "F:\\".encode_utf16().collect();
        value.push(0);
        value.extend("C:\\mount\\".encode_utf16());
        value.extend([0, 0]);
        assert_eq!(
            decode_mount_paths(&value, value.len()).unwrap(),
            ["F:\\", "C:\\mount\\"]
        );
        assert!(decode_mount_paths(&value[..value.len() - 1], value.len() - 1).is_err());
        let mut repeated: Vec<u16> = "F:\\".encode_utf16().collect();
        repeated.push(0);
        repeated.extend("F:\\".encode_utf16());
        repeated.extend([0, 0]);
        assert!(decode_mount_paths(&repeated, repeated.len()).is_err());
    }

    fn ordinary_stream() -> OfflinePartition {
        let mut file = tempfile::tempfile().unwrap();
        let bytes: Vec<u8> = (0..73728).map(|n| (n % 251) as u8).collect();
        file.write_all(&bytes).unwrap();
        OfflinePartition {
            file,
            binding: DiskBinding {
                disk_number: 1,
                volume_guid: String::new(),
                identity: PartitionIdentity {
                    disk_guid: String::new(),
                    partition_guid: String::new(),
                    partition_number: 2,
                    disk_bytes: 73728,
                    partition_offset: 4096,
                    partition_bytes: 65536,
                    logical_sector_bytes: 512,
                    physical_sector_bytes: 4096,
                },
            },
            read_only: false,
            position: 0,
            buffer: AlignedBuffer::new().unwrap(),
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        }
    }

    #[test]
    fn arbitrary_reads_remain_inside_the_partition_and_match_bytes() {
        let mut stream = ordinary_stream();
        assert_eq!(stream.buffer.pointer.as_ptr() as usize % 4096, 0);
        for (at, count) in [(0, 1), (3, 5000), (4095, 4098), (65535, 10), (65536, 1)] {
            stream.seek(SeekFrom::Start(at)).unwrap();
            let mut bytes = vec![0; count];
            let read = stream.read(&mut bytes).unwrap();
            assert_eq!(read, count.min((65536 - at) as usize));
            for (index, &byte) in bytes[..read].iter().enumerate() {
                assert_eq!(byte, ((4096 + at + index as u64) % 251) as u8);
            }
        }
        assert!(stream.seek(SeekFrom::End(1)).is_err());
        assert!(stream.seek(SeekFrom::Start(u64::MAX)).is_err());
        stream.seek(SeekFrom::Start(0)).unwrap();
        assert!(stream.seek(SeekFrom::Current(-1)).is_err());
    }

    #[test]
    fn general_read_only_reader_uses_the_same_partition_bounded_bounce() {
        let OfflinePartition {
            file,
            binding,
            buffer,
            ..
        } = ordinary_stream();
        let binding = GeneralDiskBinding {
            disk_number: binding.disk_number,
            volume_guid: binding.volume_guid,
            identity: binding.identity,
        };
        let mut reader = GeneralPartitionReader {
            file,
            initial_probe: GeneralProbe {
                binding: binding.clone(),
                disk_attributes_before: 0,
                disk_attributes_after: 0,
                device: vec![],
                disk_length: vec![],
                alignment: vec![],
                gpt_layout: vec![],
                volume_extents: vec![],
                read_only_probe: true,
                source_write_requests: 0,
                conversion_qualified: false,
            },
            binding,
            position: 0,
            buffer,
            native_bytes_read: 0,
        };
        for (at, count) in [(0, 1), (3, 5000), (4095, 4098), (65535, 10)] {
            reader.seek(SeekFrom::Start(at)).unwrap();
            let mut bytes = vec![0; count];
            let read = reader.read(&mut bytes).unwrap();
            assert_eq!(read, count.min((65536 - at) as usize));
            for (index, &byte) in bytes[..read].iter().enumerate() {
                assert_eq!(byte, ((4096 + at + index as u64) % 251) as u8);
            }
        }
        assert!(reader.seek(SeekFrom::End(1)).is_err());
        assert!(reader.seek(SeekFrom::Current(-65537)).is_err());
    }

    #[test]
    fn frozen_general_reader_is_read_only_and_partition_relative() {
        let OfflinePartition {
            file,
            binding,
            buffer,
            ..
        } = ordinary_stream();
        let binding = GeneralDiskBinding {
            disk_number: binding.disk_number,
            volume_guid: binding.volume_guid,
            identity: binding.identity,
        };
        let mut reader = GeneralFrozenPartition {
            freeze_observation: None,
            file,
            binding,
            frozen_state: GeneralDiskState {
                device: vec![],
                disk_length: vec![],
                alignment: vec![],
                gpt_layout: vec![],
                disk_attributes: OFFLINE | READ_ONLY,
            },
            position: 0,
            buffer,
            native_bytes_read: 0,
        };
        assert!(reader.freeze_observation().is_none());
        reader.seek(SeekFrom::Start(4095)).unwrap();
        let mut bytes = vec![0; 4098];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes[0], ((4096 + 4095) % 251) as u8);
        assert_eq!(bytes[4097], ((4096 + 4095 + 4097) % 251) as u8);
        assert!(reader.seek(SeekFrom::Start(65537)).is_err());
        reader.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(reader.read(&mut bytes).unwrap(), 0);
    }

    #[test]
    fn general_journal_target_requires_an_exact_armed_write_set() {
        let OfflinePartition {
            file,
            binding,
            buffer,
            ..
        } = ordinary_stream();
        let mut target = GeneralJournaledPartition {
            inner: GeneralFrozenPartition {
                freeze_observation: None,
                file,
                binding: GeneralDiskBinding {
                    disk_number: binding.disk_number,
                    volume_guid: binding.volume_guid,
                    identity: binding.identity,
                },
                frozen_state: GeneralDiskState {
                    device: vec![],
                    disk_length: vec![],
                    alignment: vec![],
                    gpt_layout: vec![],
                    disk_attributes: OFFLINE,
                },
                position: 0,
                buffer,
                native_bytes_read: 0,
            },
            policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        };
        let block = vec![0xa7; 4096];
        assert!(target.write(&block).is_err());
        target.policy = Some(WritePolicy {
            allowed: vec![(0, 4096)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 4096,
        });
        target.write_all(&block).unwrap();
        assert_eq!(target.native_bytes_written, 4096);
        assert_eq!(target.native_write_bytes_requested, 4096);
        assert!(target.write(&block).is_err());
        target.seek(SeekFrom::Start(4096)).unwrap();
        assert!(target.write(&block).is_err());
        target.seek(SeekFrom::Start(0)).unwrap();
        let mut readback = vec![0; 4096];
        target.read_exact(&mut readback).unwrap();
        assert_eq!(readback, block);
    }

    #[test]
    fn explicit_write_set_retained_exclusion_and_attempt_budget_are_enforced() {
        let mut stream = ordinary_stream();
        let block = vec![0xa7; 4096];
        assert!(stream.write(&block).is_err());
        let policy = WritePolicy {
            allowed: vec![(0, 4096), (8192, 4096)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 8192,
        };
        policy.validate(stream.byte_len()).unwrap();
        let bad = WritePolicy {
            allowed: vec![(0, 8192)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 8192,
        };
        assert!(bad.validate(stream.byte_len()).is_err());
        stream.policy = Some(policy);
        assert!(stream.write(&block[..1]).is_err());
        stream.seek(SeekFrom::Start(4096)).unwrap();
        assert!(stream.write(&block).is_err());
        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.write_all(&block).unwrap();
        stream.seek(SeekFrom::Start(8192)).unwrap();
        stream.write_all(&block).unwrap();
        stream.sync_all().unwrap();
        stream.seek(SeekFrom::Start(0)).unwrap();
        assert!(stream.write(&block).is_err());
        assert_eq!(stream.native_bytes_written, 8192);
        assert_eq!(stream.native_write_bytes_requested, 8192);
        let mut raw = vec![0; 73728];
        stream.file.seek(SeekFrom::Start(0)).unwrap();
        stream.file.read_exact(&mut raw).unwrap();
        for (n, byte) in raw.into_iter().enumerate() {
            let changed = (4096..8192).contains(&n) || (12288..16384).contains(&n);
            assert_eq!(
                byte,
                if changed { 0xa7 } else { (n % 251) as u8 },
                "byte {n}"
            );
        }
    }
}
