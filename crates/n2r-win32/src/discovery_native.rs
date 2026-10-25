use super::*;
use std::{
    fs::File,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        GetDiskFreeSpaceW, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW,
        GetVolumePathNameW,
    },
    System::IO::DeviceIoControl,
};
const MAX_REPLY: usize = 65536;
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn text(buffer: &[u16]) -> io::Result<String> {
    let end = buffer
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| invalid("unterminated native volume string"))?;
    String::from_utf16(&buffer[..end]).map_err(|_| invalid("invalid UTF-16 native volume string"))
}
fn control(file: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    require(
        input.len() <= 16 && capacity <= MAX_REPLY,
        "discovery control bound exceeded",
    )?;
    let mut output = vec![0u64; capacity.div_ceil(8)];
    let mut returned = 0;
    // SAFETY: borrowed live handle and initialized aligned bounded buffers
    // remain valid through this synchronous query; no setter is dispatched.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            output.as_mut_ptr().cast(),
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    require(returned as usize <= capacity, "oversized discovery reply")?;
    // SAFETY: returned bytes are bounded by the initialized allocation above.
    Ok(
        unsafe { std::slice::from_raw_parts(output.as_ptr().cast::<u8>(), returned as usize) }
            .to_vec(),
    )
}
fn observe(volume: &File, disk: &File) -> io::Result<StorageEvidence> {
    let mut property = [0u8; 12];
    property[0] = 6;
    Ok(StorageEvidence {
        volume_extents: control(volume, 0x0056_0000, &[], 32)?,
        device: control(disk, 0x002d_1080, &[], 12)?,
        disk_length: control(disk, 0x0007_405c, &[], 8)?,
        alignment: control(disk, 0x002d_1400, &property, 28)?,
        gpt_layout: control(disk, 0x0007_0050, &[], MAX_REPLY)?,
        disk_attributes: control(disk, 0x0007_00f0, &[], 16)?,
    })
}

pub fn discover(root: &str, role: Role) -> io::Result<VolumeDiscovery> {
    validate_root(root)?;
    let root_w = wide(root);
    let mut resolved = vec![0u16; 4096];
    // SAFETY: initialized fixed-capacity output and NUL-terminated input.
    if unsafe {
        GetVolumePathNameW(
            root_w.as_ptr(),
            resolved.as_mut_ptr(),
            resolved.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let resolved_root = text(&resolved)?;
    require(
        resolved_root.eq_ignore_ascii_case(root),
        "input is not an exact mounted volume root",
    )?;
    let mut name = [0u16; 64];
    let resolved_w = wide(&resolved_root);
    // SAFETY: fixed output accommodates the documented volume-GUID path.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(resolved_w.as_ptr(), name.as_mut_ptr(), name.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let guid_path = text(&name)?;
    let guid = volume_guid(&guid_path)?;
    let volume = File::options()
        .read(true)
        .share_mode(3)
        .open(guid_path.trim_end_matches('\\'))?;
    let initial_extents = control(&volume, 0x0056_0000, &[], 32)?;
    let (number, _, _) = single_extent(&initial_extents)?;
    let disk = File::options()
        .read(true)
        .share_mode(3)
        .open(format!("\\\\.\\PhysicalDrive{number}"))?;
    let windows_disk_number = crate::native::current_windows_disk(&mut Vec::new())?;
    let before = observe(&volume, &disk)?;
    require(
        before.volume_extents == initial_extents,
        "volume route changed during discovery",
    )?;
    let binding = binding_from_evidence(&guid, &before, role, windows_disk_number)?;
    let mut label = [0u16; 128];
    let mut filesystem = [0u16; 32];
    let mut serial = 0;
    let mut component = 0;
    let mut flags = 0;
    let mut sectors_per_cluster = 0;
    let mut bytes_per_sector = 0;
    let mut free = 0;
    let mut total = 0;
    let volume_root = wide(&guid_path);
    // SAFETY: initialized bounded SDK outputs and valid NUL-terminated root.
    unsafe {
        if GetVolumeInformationW(
            volume_root.as_ptr(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if GetDiskFreeSpaceW(
            volume_root.as_ptr(),
            &mut sectors_per_cluster,
            &mut bytes_per_sector,
            &mut free,
            &mut total,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    require(
        bytes_per_sector == binding.identity.logical_sector_bytes
            && sectors_per_cluster > 0
            && flags & 0x80000 == 0,
        "native filesystem geometry differs or the volume is read-only",
    )?;
    let after = observe(&volume, &disk)?;
    require(
        before == after
            && windows_disk_number == crate::native::current_windows_disk(&mut Vec::new())?,
        "storage or Windows disk changed during discovery",
    )?;
    let mut final_name = [0u16; 64];
    // SAFETY: same bounded name query verifies the requested mount route again.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(
            resolved_w.as_ptr(),
            final_name.as_mut_ptr(),
            final_name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    require(
        volume_guid(&text(&final_name)?)? == guid,
        "mount root changed during discovery",
    )?;
    Ok(VolumeDiscovery {
        schema_version: 1,
        role,
        requested_root: root.into(),
        resolved_root,
        volume_guid_path: guid_path,
        binding,
        filesystem: text(&filesystem)?,
        label: text(&label)?,
        bytes_per_sector,
        sectors_per_cluster,
        volume_serial_low32: serial,
        filesystem_flags: flags,
        windows_disk_number,
        disk_is_windows_disk: number == windows_disk_number,
        evidence: before,
        observed_twice_unchanged: true,
        read_only: true,
        source_write_requests: 0,
    })
}
