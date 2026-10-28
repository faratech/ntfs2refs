//! Read-only filesystem storage accounting for ordinary scratch files. This
//! measures GetCompressedFileSizeW storage, not physical device write traffic.
use std::{
    fs::OpenOptions,
    io,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError},
    Storage::FileSystem::{GetCompressedFileSizeW, GetFileInformationByHandleEx},
};

#[derive(serde::Serialize)]
pub struct StorageUse {
    pub file_length_bytes: u64,
    pub filesystem_storage_bytes: u64,
    pub attributes: u32,
    pub file_id_info: String,
    pub data_bytes_read: u64,
    pub data_bytes_written: u64,
}

pub fn observe(path: &Path) -> io::Result<StorageUse> {
    let file = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x00200000)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other(
            "ordinary non-reparse scratch file required",
        ));
    }
    let id = |file: &std::fs::File| -> io::Result<[u64; 3]> {
        let mut info = [0u64; 3];
        // SAFETY: live metadata handle and aligned FILE_ID_INFO output.
        if unsafe {
            GetFileInformationByHandleEx(file.as_raw_handle(), 18, info.as_mut_ptr().cast(), 24)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    };
    let original_id = id(&file)?;
    use std::os::windows::ffi::OsStrExt;
    let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    if name.len() > 32768 || name[..name.len() - 1].contains(&0) {
        return Err(io::Error::other("scratch path bounds differ"));
    }
    let mut high = 0u32;
    // SAFETY: bounded NUL-terminated path and initialized high DWORD. Clear
    // last error because low=0xffffffff can be a successful large-file size.
    unsafe { SetLastError(0) };
    let low = unsafe { GetCompressedFileSizeW(name.as_ptr(), &mut high) };
    let error = unsafe { GetLastError() };
    if low == u32::MAX && error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let reopened = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x00200000)
        .open(path)?;
    let after = file.metadata()?;
    if original_id != id(&reopened)?
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(io::Error::other(
            "scratch identity or metadata changed during storage query",
        ));
    }
    let bytes: Vec<u8> = original_id.iter().flat_map(|n| n.to_le_bytes()).collect();
    Ok(StorageUse {
        file_length_bytes: before.len(),
        filesystem_storage_bytes: (u64::from(high) << 32) | u64::from(low),
        attributes: before.file_attributes(),
        file_id_info: hex::encode(bytes),
        data_bytes_read: 0,
        data_bytes_written: 0,
    })
}
