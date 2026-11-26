//! Read-only clean NTFS geometry for explicit offline-Windows maintenance.
//! This observation does not grant a raw writer or resize authority.
use crate::{
    GeneralProbe, NativeEvent,
    general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile},
};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
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
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn query(file: &std::fs::File, code: u32, length: usize) -> io::Result<Vec<u8>> {
    let mut storage = [0u64; 12];
    let mut used = 0;
    if length > 96 {
        return Err(bad("bounded NTFS geometry query required"));
    }
    // SAFETY: held synchronous read-only volume, initialized aligned outputs,
    // documented query-only FSCTLs and no caller-controlled input buffer.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            ptr::null(),
            0,
            storage.as_mut_ptr().cast(),
            length as u32,
            &mut used,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if used as usize != length {
        return Err(bad("short NTFS geometry query"));
    }
    Ok(unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length) }.to_vec())
}
pub fn observe_clean(
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<CleanNtfsGeometry> {
    // Either source layout: an offline Windows disk, or a data disk of its
    // own. What is observed is the same clean, mounted NTFS volume.
    let before = crate::probe_general(binding.clone(), events)?;
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(binding.volume_path()?)?;
    binding.validate_volume_extent(&query(&volume, 0x0056_0000, 32)?)?;
    let dirty = query(&volume, 0x0009_0078, 4)?;
    let dirty_flags = u32::from_le_bytes(dirty[..4].try_into().unwrap());
    // SESSION_OPEN is compatible with mounted clean NTFS; dirty, scheduled
    // upgrade and unknown flags cannot authorize this maintenance step.
    if dirty_flags & !4 != 0 {
        return Err(bad(
            "clean NTFS without pending upgrade required before boot geometry maintenance",
        ));
    }
    let native_volume_data = query(&volume, 0x0009_0064, 96)?;
    let ntfs_serial = u64::from_le_bytes(native_volume_data[..8].try_into().unwrap());
    let sectors = u64::from_le_bytes(native_volume_data[8..16].try_into().unwrap());
    let bytes_per_sector = u32::from_le_bytes(native_volume_data[40..44].try_into().unwrap());
    let bytes_per_cluster = u32::from_le_bytes(native_volume_data[44..48].try_into().unwrap());
    let filesystem_bytes = sectors
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or_else(|| bad("NTFS geometry overflow"))?;
    if bytes_per_sector != binding.identity.logical_sector_bytes
        || !bytes_per_cluster.is_power_of_two()
        || bytes_per_cluster < bytes_per_sector
        || ntfs_serial == 0
        || !(filesystem_bytes == binding.identity.partition_bytes
            || filesystem_bytes.checked_add(u64::from(bytes_per_sector))
                == Some(binding.identity.partition_bytes))
    {
        return Err(bad(
            "native clean NTFS geometry differs from selected partition",
        ));
    }
    let closing_dirty = query(&volume, 0x0009_0078, 4)?;
    binding.validate_volume_extent(&query(&volume, 0x0056_0000, 32)?)?;
    let after = crate::probe_general(binding.clone(), events)?;
    if closing_dirty != dirty
        || before.binding != after.binding
        || before.device != after.device
        || before.disk_length != after.disk_length
        || before.alignment != after.alignment
        || before.gpt_layout != after.gpt_layout
        || before.disk_attributes_after != after.disk_attributes_after
    {
        return Err(bad(
            "source route or clean NTFS state changed during geometry observation",
        ));
    }
    Ok(CleanNtfsGeometry {
        binding: binding.clone(),
        ntfs_serial,
        dirty_flags,
        bytes_per_sector,
        bytes_per_cluster,
        filesystem_bytes,
        native_volume_data,
        probe: after,
    })
}

/// What Windows said of an NTFS volume it was asked to mount read-write and
/// to write out, for the upgrade of an NTFS 1.2 or 3.0 volume to 3.1.
#[derive(Debug, Serialize)]
pub struct NtfsVersionSettle {
    pub binding: GeneralDiskBinding,
    pub ntfs_serial: u64,
    pub dirty_flags: u32,
    /// The NTFS version Windows reports for the mounted volume
    /// (NTFS_EXTENDED_VOLUME_DATA), before and after the flush.
    pub windows_version_before: Option<(u16, u16)>,
    pub windows_version_after: Option<(u16, u16)>,
    /// The LFS version Windows reports, where it reports one.
    pub windows_lfs_version: Option<(u16, u16)>,
    pub probe: GeneralProbe,
}

/// FSCTL_GET_NTFS_VOLUME_DATA with room for NTFS_EXTENDED_VOLUME_DATA
/// after the 96-byte NTFS_VOLUME_DATA_BUFFER. Windows fills what it has.
fn ntfs_volume_data(file: &std::fs::File) -> io::Result<Vec<u8>> {
    const LENGTH: usize = 128;
    let mut storage = [0u64; LENGTH / 8];
    let mut used = 0;
    // SAFETY: held synchronous volume handle, initialized aligned output of
    // LENGTH bytes, a documented query-only FSCTL and no input buffer.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_0064,
            ptr::null(),
            0,
            storage.as_mut_ptr().cast(),
            LENGTH as u32,
            &mut used,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let used = used as usize;
    if !(96..=LENGTH).contains(&used) {
        return Err(bad("short NTFS volume data"));
    }
    Ok(unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), used) }.to_vec())
}

/// A (major, minor) version Windows reports.
pub type Version = (u16, u16);

/// The (NTFS, LFS) versions in NTFS_EXTENDED_VOLUME_DATA, where present:
/// ByteCount at 96, MajorVersion and MinorVersion at 100 and 102,
/// LfsMajorVersion and LfsMinorVersion at 108 and 110.
pub fn extended_versions(data: &[u8]) -> (Option<Version>, Option<Version>) {
    let word = |at: usize| {
        data.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let count = data
        .get(96..100)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
        .unwrap_or(0);
    let pair = |at: usize, needed: usize| {
        (count >= needed)
            .then(|| word(at).zip(word(at + 2)))
            .flatten()
    };
    (pair(100, 8), pair(108, 16))
}

/// Have Windows mount the volume read-write, as it does when a volume is
/// opened for writing, and write out everything it holds for it. Windows
/// upgrades an NTFS volume of an older version when it mounts it
/// read-write; the caller reads $Volume again from the raw partition to
/// see whether it did. Nothing is written here but by the NTFS driver.
pub fn settle_ntfs_version(
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<NtfsVersionSettle> {
    let before = crate::probe_general(binding.clone(), events)?;
    let volume = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(binding.volume_path()?)?;
    binding.validate_volume_extent(&query(&volume, 0x0056_0000, 32)?)?;
    let dirty = query(&volume, 0x0009_0078, 4)?;
    let dirty_flags = u32::from_le_bytes(dirty[..4].try_into().unwrap());
    if dirty_flags & 1 != 0 {
        return Err(bad(
            "the volume is marked dirty: run `chkdsk <drive>: /f` before its NTFS version is upgraded",
        ));
    }
    let data = ntfs_volume_data(&volume)?;
    let ntfs_serial = u64::from_le_bytes(data[..8].try_into().unwrap());
    let (windows_version_before, _) = extended_versions(&data);
    // FlushFileBuffers on a volume handle writes out every file and all of
    // NTFS's own metadata for it, $Volume among them.
    volume.sync_all()?;
    let data = ntfs_volume_data(&volume)?;
    let (windows_version_after, windows_lfs_version) = extended_versions(&data);
    if u64::from_le_bytes(data[..8].try_into().unwrap()) != ntfs_serial || ntfs_serial == 0 {
        return Err(bad(
            "the NTFS serial number changed while the volume was mounted",
        ));
    }
    binding.validate_volume_extent(&query(&volume, 0x0056_0000, 32)?)?;
    drop(volume);
    let after = crate::probe_general(binding.clone(), events)?;
    if before.binding != after.binding
        || before.device != after.device
        || before.disk_length != after.disk_length
        || before.alignment != after.alignment
        || before.gpt_layout != after.gpt_layout
    {
        return Err(bad(
            "the source route changed while Windows mounted the volume for its NTFS upgrade",
        ));
    }
    Ok(NtfsVersionSettle {
        binding: binding.clone(),
        ntfs_serial,
        dirty_flags,
        windows_version_before,
        windows_version_after,
        windows_lfs_version,
        probe: after,
    })
}

#[cfg(test)]
mod tests {
    use super::extended_versions;

    #[test]
    fn the_versions_windows_reports_are_read_where_it_fills_them() {
        let mut data = vec![0u8; 112];
        data[96..100].copy_from_slice(&32u32.to_le_bytes());
        data[100..102].copy_from_slice(&3u16.to_le_bytes());
        data[102..104].copy_from_slice(&1u16.to_le_bytes());
        data[108..110].copy_from_slice(&2u16.to_le_bytes());
        data[110..112].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(extended_versions(&data), (Some((3, 1)), Some((2, 0))));
        // Only the NTFS version filled.
        data[96..100].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(extended_versions(&data), (Some((3, 1)), None));
        // No extended data at all.
        assert_eq!(extended_versions(&data[..96]), (None, None));
    }
}
