//! Read-only clean NTFS geometry for explicit offline-Windows maintenance.
//! This observation does not grant a raw writer or resize authority.
use crate::{GeneralProbe, NativeEvent, general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile}};
use serde::Serialize;
use std::{fs::OpenOptions, io, os::windows::{fs::OpenOptionsExt, io::AsRawHandle}, ptr};
use windows_sys::Win32::System::IO::DeviceIoControl;

#[derive(Debug, Serialize)]
pub struct CleanNtfsGeometry {
    pub binding: GeneralDiskBinding,
    pub ntfs_serial: u64,
    pub dirty_flags: u32,
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
    pub filesystem_bytes: u64,
    pub native_volume_data: Vec<u8>,
    pub probe: GeneralProbe,
}
fn bad(message: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn query(file: &std::fs::File, code: u32, length: usize) -> io::Result<Vec<u8>> {
    let mut storage = [0u64; 12]; let mut used = 0;
    if length > 96 { return Err(bad("bounded NTFS geometry query required")); }
    // SAFETY: held synchronous read-only volume, initialized aligned outputs,
    // documented query-only FSCTLs and no caller-controlled input buffer.
    if unsafe { DeviceIoControl(file.as_raw_handle(), code, ptr::null(), 0,
        storage.as_mut_ptr().cast(), length as u32, &mut used, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if used as usize != length { return Err(bad("short NTFS geometry query")); }
    Ok(unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length) }.to_vec())
}
pub fn observe_clean(binding: &GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> io::Result<CleanNtfsGeometry> {
    if binding.layout_profile != GeneralDiskLayoutProfile::OfflineWindows {
        return Err(bad("offline Windows geometry profile required"));
    }
    let before = crate::probe_general(binding.clone(), events)?;
    let volume = OpenOptions::new().read(true).share_mode(3).custom_flags(0x0020_0000)
        .open(binding.volume_path()?)?;
    binding.validate_volume_extent(&query(&volume, 0x0056_0000, 32)?)?;
    let dirty = query(&volume, 0x0009_0078, 4)?;
    let dirty_flags = u32::from_le_bytes(dirty[..4].try_into().unwrap());
    // SESSION_OPEN is compatible with mounted clean NTFS; dirty, scheduled
    // upgrade and unknown flags cannot authorize this maintenance step.
    if dirty_flags & !4 != 0 { return Err(bad("clean NTFS without pending upgrade required before boot geometry maintenance")); }
    let native_volume_data = query(&volume, 0x0009_0064, 96)?;
    let ntfs_serial = u64::from_le_bytes(native_volume_data[..8].try_into().unwrap());
    let sectors = u64::from_le_bytes(native_volume_data[8..16].try_into().unwrap());
    let bytes_per_sector = u32::from_le_bytes(native_volume_data[40..44].try_into().unwrap());
    let bytes_per_cluster = u32::from_le_bytes(native_volume_data[44..48].try_into().unwrap());
    let filesystem_bytes = sectors.checked_mul(u64::from(bytes_per_sector)).ok_or_else(||bad("NTFS geometry overflow"))?;
    if bytes_per_sector != binding.identity.logical_sector_bytes || !bytes_per_cluster.is_power_of_two()
        || bytes_per_cluster < bytes_per_sector || ntfs_serial == 0
        || !(filesystem_bytes == binding.identity.partition_bytes
            || filesystem_bytes.checked_add(u64::from(bytes_per_sector)) == Some(binding.identity.partition_bytes)) {
        return Err(bad("native clean NTFS geometry differs from selected partition"));
    }
    let closing_dirty = query(&volume, 0x0009_0078, 4)?;
    binding.validate_volume_extent(&query(&volume, 0x0056_0000, 32)?)?;
    let after = crate::probe_general(binding.clone(), events)?;
    if closing_dirty != dirty || before.binding != after.binding || before.device != after.device
        || before.disk_length != after.disk_length || before.alignment != after.alignment
        || before.gpt_layout != after.gpt_layout || before.disk_attributes_after != after.disk_attributes_after {
        return Err(bad("source route or clean NTFS state changed during geometry observation"));
    }
    Ok(CleanNtfsGeometry { binding: binding.clone(), ntfs_serial, dirty_flags, bytes_per_sector,
        bytes_per_cluster, filesystem_bytes, native_volume_data, probe: after })
}
