//! Whether Windows holds a directory of a mounted NTFS volume to be
//! case-sensitive, asked by the directory's file reference. Queries only:
//! the volume and each directory are opened to read attributes, nothing else.
use std::{
    fs::{File, OpenOptions},
    io, mem,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType, GetFileInformationByHandleEx,
        OpenFileById,
    },
};

/// FILE_READ_ATTRIBUTES: the only access asked for.
const READ_ATTRIBUTES: u32 = 0x80;
/// FILE_FLAG_BACKUP_SEMANTICS, to open a directory, with
/// FILE_FLAG_OPEN_REPARSE_POINT, so that no reparse point is followed.
const DIRECTORY_AS_ITSELF: u32 = 0x0220_0000;
/// FileCaseSensitiveInfo of FILE_INFO_BY_HANDLE_CLASS. Its answer,
/// FILE_CASE_SENSITIVE_INFO, is one ULONG of flags; 1 is case-sensitive.
const CASE_SENSITIVE_INFO: i32 = 23;

/// A volume whose directories can be asked.
pub struct DirectoryCaseProbe {
    volume: File,
}

impl DirectoryCaseProbe {
    /// `volume_root` is the volume's root directory, for example
    /// `\\?\Volume{...}\`.
    pub fn open(volume_root: &str) -> io::Result<Self> {
        let volume = OpenOptions::new()
            .access_mode(READ_ATTRIBUTES)
            .share_mode(7)
            .custom_flags(DIRECTORY_AS_ITSELF)
            .open(volume_root)?;
        Ok(Self { volume })
    }

    /// The case-sensitivity flags Windows reports for the directory with
    /// this file reference (its record number, with its sequence number in
    /// the top 16 bits): 0 for an ordinary directory, 1 for one marked
    /// case-sensitive. An error is Windows' own, with nothing assumed.
    pub fn flags(&self, file_reference: u64) -> io::Result<u32> {
        let descriptor = FILE_ID_DESCRIPTOR {
            dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                FileId: file_reference as i64,
            },
        };
        // SAFETY: an initialized descriptor and a live volume handle; the
        // access asked for is FILE_READ_ATTRIBUTES alone.
        let handle = unsafe {
            OpenFileById(
                self.volume.as_raw_handle(),
                &descriptor,
                READ_ATTRIBUTES,
                7,
                ptr::null(),
                DIRECTORY_AS_ITSELF,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: sole ownership of the handle just opened.
        let directory = unsafe { File::from_raw_handle(handle) };
        let mut flags = 0u32;
        // SAFETY: a buffer of exactly the four bytes this class returns, and
        // a live handle, for a synchronous query.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                CASE_SENSITIVE_INFO,
                (&mut flags as *mut u32).cast(),
                mem::size_of::<u32>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flags)
    }
}
