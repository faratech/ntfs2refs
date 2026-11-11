//! Read-only, same-handle identity for large ordinary reference files.
//! This is not journal enrollment, storage authority, or a sharing-mode proof.
use serde::Serialize;
use std::io;

pub const MAX_REFERENCE_FILE_BYTES: u64 = (128_u64 << 30) + 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReferenceFileSnapshot {
    pub final_path: String,
    pub volume_serial_number: u64,
    pub file_id_128: [u8; 16],
    pub file_bytes: u64,
    pub allocation_bytes: u64,
    pub file_attributes: u32,
    pub number_of_links: u32,
}

fn snapshot(
    path: String,
    id: [u8; 24],
    standard: [u8; 24],
    tag: [u8; 8],
) -> io::Result<ReferenceFileSnapshot> {
    snapshot_with_bounds(
        path,
        id,
        standard,
        tag,
        MAX_REFERENCE_FILE_BYTES,
        MAX_REFERENCE_FILE_BYTES + 65535,
    )
}
fn snapshot_with_bounds(
    path: String,
    id: [u8; 24],
    standard: [u8; 24],
    tag: [u8; 8],
    maximum: u64,
    maximum_allocation: u64,
) -> io::Result<ReferenceFileSnapshot> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "reference handle lacks bounded ordinary-file identity",
        )
    };
    let suffix = path
        .strip_prefix("\\\\?\\Volume{")
        .and_then(|p| p.split_once("}\\"));
    let Some((volume, name)) = suffix else {
        return Err(invalid());
    };
    let volume_guid = crate::layout::guid_bytes(volume)?;
    if volume_guid == [0; 16]
        || name.is_empty()
        || name.split('\\').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.ends_with([' ', '.'])
                || part.chars().any(|c| {
                    c.is_control() || matches!(c, ':' | '/' | '"' | '<' | '>' | '|' | '?' | '*')
                })
        })
    {
        return Err(invalid());
    }
    let volume_serial_number = u64::from_le_bytes(id[..8].try_into().unwrap());
    let file_id_128 = id[8..].try_into().unwrap();
    let allocation_bytes = u64::from_le_bytes(standard[..8].try_into().unwrap());
    let file_bytes = u64::from_le_bytes(standard[8..16].try_into().unwrap());
    let number_of_links = u32::from_le_bytes(standard[16..20].try_into().unwrap());
    let file_attributes = u32::from_le_bytes(tag[..4].try_into().unwrap());
    // Directory, device, sparse, reparse, compressed, offline and encrypted.
    const FORBIDDEN: u32 = 0x10 | 0x40 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x4000;
    if volume_serial_number == 0
        || file_id_128 == [0; 16]
        || maximum > i64::MAX as u64
        || file_bytes > maximum
        || allocation_bytes > maximum_allocation.min(i64::MAX as u64)
        || number_of_links == 0
        || standard[20] != 0
        || standard[21] != 0
        || file_attributes & FORBIDDEN != 0
        || tag[4..] != [0; 4]
    {
        return Err(invalid());
    }
    Ok(ReferenceFileSnapshot {
        final_path: path,
        volume_serial_number,
        file_id_128,
        file_bytes,
        allocation_bytes,
        file_attributes,
        number_of_links,
    })
}

#[cfg(windows)]
/// Observe only the borrowed ordinary-file handle; never open a disk/volume.
/// The caller must choose read-only access and write/delete exclusion. This
/// function cannot discover or certify the handle's access or sharing flags.
pub fn observe_reference_file_handle(file: &std::fs::File) -> io::Result<ReferenceFileSnapshot> {
    observe_handle(file, MAX_REFERENCE_FILE_BYTES, false)
}
#[cfg(windows)]
pub fn observe_reference_file_handle_with_limit(
    file: &std::fs::File,
    maximum: u64,
) -> io::Result<ReferenceFileSnapshot> {
    observe_handle(file, maximum, true)
}
#[cfg(windows)]
fn observe_handle(
    file: &std::fs::File,
    maximum: u64,
    resource: bool,
) -> io::Result<ReferenceFileSnapshot> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_INFO_BY_HANDLE_CLASS, FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo,
        FileStandardInfo, GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
        VOLUME_NAME_GUID,
    };
    #[repr(C, align(8))]
    struct Buffer([u8; 24]);
    fn info<const N: usize>(
        file: &std::fs::File,
        class: FILE_INFO_BY_HANDLE_CLASS,
    ) -> io::Result<[u8; N]> {
        if N > 24 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reference information exceeds buffer",
            ));
        }
        let mut b = Buffer([0; 24]);
        // SAFETY: a live borrowed handle and aligned buffer of the advertised size;
        // all three callers request at most 24 bytes and the API retains no pointer.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                b.0.as_mut_ptr().cast(),
                N as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(b.0[..N].try_into().unwrap())
    }
    // SAFETY: the borrowed file owns a live handle throughout these observations.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reference is not a disk file",
        ));
    }
    let mut path = vec![0_u16; 4096];
    // SAFETY: path is initialized and exactly the advertised length; no pointer escapes.
    let mut count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    if resource && count >= path.len() {
        if count > 32768 {
            return Err(io::Error::other(
                "resource reference final path exceeds native bound",
            ));
        }
        path.resize(count, 0);
        // SAFETY: live same handle and initialized buffer of the required size.
        count = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                VOLUME_NAME_GUID,
            )
        } as usize;
    }
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count >= path.len() || path[count] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reference final path exceeds bound",
        ));
    }
    let path = String::from_utf16(&path[..count])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid reference final path"))?;
    let id = info(file, FileIdInfo)?;
    let standard = info(file, FileStandardInfo)?;
    let tag = info(file, FileAttributeTagInfo)?;
    if resource {
        snapshot_with_bounds(path, id, standard, tag, maximum, i64::MAX as u64)
    } else {
        snapshot(path, id, standard, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fields(length: u64) -> (String, [u8; 24], [u8; 24], [u8; 8]) {
        let mut id = [1; 24];
        id[..8].copy_from_slice(&123_u64.to_le_bytes());
        let mut standard = [0; 24];
        standard[..8].copy_from_slice(&length.to_le_bytes());
        standard[8..16].copy_from_slice(&length.to_le_bytes());
        standard[16..20].copy_from_slice(&1_u32.to_le_bytes());
        let mut tag = [0; 8];
        tag[0] = 0x20;
        (
            "\\\\?\\Volume{12345678-1234-1234-abcd-123456789abc}\\reference.vhd".into(),
            id,
            standard,
            tag,
        )
    }
    #[test]
    fn accepts_large_reference_metadata_without_allocating_a_large_file() {
        for length in [0, (64_u64 << 30) + 512, MAX_REFERENCE_FILE_BYTES] {
            let (p, i, s, t) = fields(length);
            assert_eq!(snapshot(p, i, s, t).unwrap().file_bytes, length);
        }
        let (p, i, s, t) = fields(MAX_REFERENCE_FILE_BYTES + 1);
        assert!(snapshot(p, i, s, t).is_err());
    }
    #[test]
    fn refuses_unsupported_identity_attributes_and_nonordinary_paths() {
        let (p, i, s, t) = fields(1);
        for bit in [0x10_u32, 0x40, 0x200, 0x400, 0x800, 0x1000, 0x4000] {
            let mut bad = t;
            bad[..4].copy_from_slice(&bit.to_le_bytes());
            assert!(snapshot(p.clone(), i, s, bad).is_err());
        }
        assert!(snapshot(p.clone(), [0; 24], s, t).is_err());
        for offset in [20, 21] {
            let mut bad = s;
            bad[offset] = 1;
            assert!(snapshot(p.clone(), i, bad, t).is_err());
        }
        let mut bad = t;
        bad[4] = 1;
        assert!(snapshot(p.clone(), i, s, bad).is_err());
        for path in [
            "\\\\.\\PhysicalDrive0",
            "\\\\?\\Volume{12345678-1234-1234-abcd-123456789abc}\\",
            "\\\\?\\Volume{12345678-1234-1234-abcd-123456789abc}\\file:stream",
        ] {
            assert!(snapshot(path.into(), i, s, t).is_err());
        }
    }
    #[cfg(windows)]
    #[test]
    fn observes_only_the_held_small_file_without_opening_a_device() {
        let mut file = tempfile::tempfile().unwrap();
        use std::io::Write;
        file.write_all(b"reference").unwrap();
        let before = observe_reference_file_handle(&file).unwrap();
        assert_eq!(before.file_bytes, 9);
        assert_eq!(before, observe_reference_file_handle(&file).unwrap());
    }
}
