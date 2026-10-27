use super::*;
use std::{
    fs::{File, OpenOptions},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_INFO_BY_HANDLE_CLASS, FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo,
        FileStandardInfo, GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
        VOLUME_NAME_GUID,
    },
    System::IO::DeviceIoControl,
};

// All controls here are observations. There is no disk-attribute, locking,
// privilege, formatter, content-write or create-file operation in this module.
const DEVICE: u32 = 0x002d1080;
const LENGTH: u32 = 0x0007405c;
const ALIGNMENT: u32 = 0x002d1400;
const LAYOUT: u32 = 0x00070050;
const VOLUME_EXTENTS: u32 = 0x00560000;

#[repr(C, align(8))]
struct InfoBuffer([u8; 24]);

fn information<const N: usize>(
    file: &File,
    class: FILE_INFO_BY_HANDLE_CLASS,
) -> io::Result<[u8; N]> {
    require(N <= 24, "file information exceeds fixed ABI buffer")?;
    let mut buffer = InfoBuffer([0; 24]);
    // SAFETY: the borrowed File owns a live handle; the 8-byte aligned buffer
    // has at least N writable bytes. The synchronous API retains no pointer.
    // Raw bytes avoid constructing Rust bools from native BOOLEAN fields.
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            buffer.0.as_mut_ptr().cast(),
            N as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer.0[..N].try_into().expect("bounded information array"))
}

fn file_observation(file: &File) -> io::Result<(String, JournalFileEvidence)> {
    // SAFETY: file owns the handle for the complete synchronous call.
    require(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "journal handle is not a disk file",
    )?;
    let mut path = [0_u16; MAX_PATH_UNITS];
    // SAFETY: path has exactly the advertised number of initialized, writable
    // UTF-16 elements. No pointer escapes the synchronous call.
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    require(
        count < path.len() && path[count] == 0,
        "journal final path exceeds fixed buffer",
    )?;
    let path = String::from_utf16(&path[..count])
        .map_err(|_| invalid("journal final path is not valid UTF-16"))?;
    let e = JournalFileEvidence {
        file_id_info: information(file, FileIdInfo)?,
        file_standard_info: information(file, FileStandardInfo)?,
        file_attribute_tag_info: information(file, FileAttributeTagInfo)?,
        volume_extents: vec![],
        disk_device_number: vec![],
        disk_length: vec![],
        disk_alignment: vec![],
        disk_layout: vec![],
    };
    validate_file_fields(&e)?;
    Ok((path, e))
}

/// Observe an existing ordinary file twice without opening a disk or volume.
/// This does not certify sharing mode, enrollment, content or durability. The
/// caller holds the handle and chooses its sharing mode. The 768 MiB file bound
/// and ordinary-stream/link/attribute guards are shared with journal observation.
pub fn observe_ordinary_file_handle(file: &File) -> io::Result<OrdinaryFileSnapshot> {
    let (path, before) = file_observation(file)?;
    let snapshot = ordinary_snapshot(&path, &before)?;
    let (after_path, after) = file_observation(file)?;
    require(
        path == after_path && before == after,
        "ordinary file changed during observation",
    )?;
    Ok(snapshot)
}

fn query(file: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    require(
        input.len() <= 12 && (1..=65536).contains(&capacity),
        "journal observation query exceeds budget",
    )?;
    let mut output = vec![0; capacity];
    let mut returned = 0_u32;
    // SAFETY: file owns its handle; input and output are disjoint live buffers
    // of the declared sizes. This is synchronous, non-overlapped I/O.
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
            output.as_mut_ptr().cast(),
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    require(
        returned as usize <= capacity,
        "journal observation returned oversized output",
    )?;
    output.truncate(returned as usize);
    Ok(output)
}

fn storage_observation(volume: &File, disk: &File, e: &mut JournalFileEvidence) -> io::Result<()> {
    e.volume_extents = query(volume, VOLUME_EXTENTS, &[], 32)?;
    e.disk_device_number = query(disk, DEVICE, &[], 12)?;
    e.disk_length = query(disk, LENGTH, &[], 8)?;
    let mut property = [0; 12];
    property[0] = 6; // StorageAccessAlignmentProperty / PropertyStandardQuery.
    e.disk_alignment = query(disk, ALIGNMENT, &property, 28)?;
    e.disk_layout = query(disk, LAYOUT, &[], 65536)?;
    Ok(())
}

/// Observe the existing handle and its exact enrolled backing storage twice.
///
/// Caller preconditions: open the journal on the enrolled J: volume with
/// sharing mode zero; retain that handle and exclude its own concurrent access.
/// This observer only opens existing volume/device handles for read access. It
/// does not read journal contents or assert journal integrity/durability.
pub fn observe_journal_file(
    file: &File,
    expected: &JournalStorageBinding,
) -> io::Result<JournalFileSnapshot> {
    expected.validate()?; // Invalid requests issue no native calls.
    let (before_path, mut before) = file_observation(file)?;
    let volume_path = final_volume_path(&before_path, &guid_bytes(&expected.volume_guid)?)?;
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(volume_path)?;
    let disk = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(format!("\\\\.\\PhysicalDrive{}", expected.disk_number))?;
    storage_observation(&volume, &disk, &mut before)?;
    let snapshot = validate_evidence(expected, &before_path, before)?;
    let (after_path, mut after) = file_observation(file)?;
    storage_observation(&volume, &disk, &mut after)?;
    finish_observation(snapshot, &after_path, &after)
}

/// Observe a journal file on any separately bound dedicated GPT data disk.
/// The caller still owns its exclusive file handle and durable ticket.
pub fn observe_general_journal_file(
    file: &File,
    expected: &GeneralJournalStorageBinding,
) -> io::Result<JournalFileSnapshot> {
    observe_general_journal_file_with_profile(file, expected, JournalProfile::LegacyV1)
}

/// Explicitly selected versioned capacity profile. The owning request/ticket
/// must bind this profile independently before any write authorization.
pub fn observe_general_journal_file_with_profile(
    file: &File,
    expected: &GeneralJournalStorageBinding,
    profile: JournalProfile,
) -> io::Result<JournalFileSnapshot> {
    expected.validate()?;
    let (before_path, mut before) = file_observation(file)?;
    let volume_path = final_volume_path(&before_path, &guid_bytes(&expected.disk.volume_guid)?)?;
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(volume_path)?;
    let disk = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(format!("\\\\.\\PhysicalDrive{}", expected.disk.disk_number))?;
    storage_observation(&volume, &disk, &mut before)?;
    let snapshot = validate_general_evidence_for_profile(expected, &before_path, before, profile)?;
    let (after_path, mut after) = file_observation(file)?;
    storage_observation(&volume, &disk, &mut after)?;
    finish_observation(snapshot, &after_path, &after)
}
