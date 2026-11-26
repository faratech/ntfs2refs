//! A minimal Projected File System (ProjFS) provider, for the laboratory
//! only (`lab-projfs-provider`).
//!
//! It projects a backing folder (on another volume) into a virtualization
//! root, so that the lab makes ProjFS placeholders that are hydrated and
//! not, and runs a conversion with the provider running or stopped. Nothing
//! of the converter uses it: ProjectedFSLib.dll is imported only by the
//! program that calls it, and is there only where the Client-ProjFS
//! optional feature is enabled.
use std::{
    collections::HashMap,
    ffi::c_void,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use windows_sys::{
    Win32::Storage::ProjectedFileSystem::{
        PRJ_CALLBACK_DATA, PRJ_CALLBACKS, PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN,
        PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO, PRJ_FILE_STATE,
        PRJ_FILE_STATE_DIRTY_PLACEHOLDER, PRJ_FILE_STATE_FULL, PRJ_FILE_STATE_HYDRATED_PLACEHOLDER,
        PRJ_FILE_STATE_PLACEHOLDER, PRJ_FILE_STATE_TOMBSTONE, PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
        PRJ_PLACEHOLDER_INFO, PrjAllocateAlignedBuffer, PrjFileNameCompare, PrjFileNameMatch,
        PrjFillDirEntryBuffer, PrjFreeAlignedBuffer, PrjGetOnDiskFileState,
        PrjMarkDirectoryAsPlaceholder, PrjStartVirtualizing, PrjStopVirtualizing, PrjWriteFileData,
        PrjWritePlaceholderInfo,
    },
    core::{GUID, HRESULT, PCWSTR},
};

/// The virtualization instance's identity.
const INSTANCE: GUID = GUID::from_u128(0x7d3c_1b2a_5e4f_4a6b_8c9d_0e1f_2a3b_4c5d);
/// What it writes at most in one transfer.
const CHUNK: u64 = 1 << 20;
/// HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER): the enumeration
/// buffer is full.
const BUFFER_FULL: HRESULT = 0x8007_007au32 as HRESULT;
/// HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND).
const NOT_FOUND: HRESULT = 0x8007_0002u32 as HRESULT;

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// A terminated UTF-16 string ProjFS passes.
unsafe fn text(pointer: PCWSTR) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: ProjFS passes terminated strings.
    while unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` units, read above.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
}

fn hresult(error: &io::Error) -> HRESULT {
    match error.raw_os_error() {
        Some(code) => (0x8007_0000u32 | (code as u32 & 0xffff)) as HRESULT,
        None => 0x8000_4005u32 as HRESULT,
    }
}

fn failed(what: &str, result: HRESULT) -> io::Error {
    io::Error::other(format!("{what}: HRESULT {:#010x}", result as u32))
}

struct Entry {
    name: Vec<u16>,
    info: PRJ_FILE_BASIC_INFO,
}

struct Enumeration {
    entries: Vec<Entry>,
    next: usize,
}

struct Provider {
    backing: PathBuf,
    enumerations: Mutex<HashMap<u128, Enumeration>>,
}

static PROVIDER: OnceLock<Provider> = OnceLock::new();

fn provider() -> &'static Provider {
    PROVIDER
        .get()
        .expect("the provider is set before it starts")
}

fn basic_info(metadata: &std::fs::Metadata) -> PRJ_FILE_BASIC_INFO {
    PRJ_FILE_BASIC_INFO {
        IsDirectory: metadata.is_dir(),
        FileSize: if metadata.is_dir() {
            0
        } else {
            metadata.len() as i64
        },
        CreationTime: metadata.creation_time() as i64,
        LastAccessTime: metadata.last_access_time() as i64,
        LastWriteTime: metadata.last_write_time() as i64,
        ChangeTime: metadata.last_write_time() as i64,
        // Only what a projection may give: directory, read-only, archive.
        FileAttributes: metadata.file_attributes() & (0x10 | 0x01 | 0x20),
    }
}

fn backing_of(data: &PRJ_CALLBACK_DATA) -> PathBuf {
    // SAFETY: ProjFS's own string.
    let relative = unsafe { text(data.FilePathName) };
    provider().backing.join(relative)
}

unsafe extern "system" fn start_enumeration(
    data: *const PRJ_CALLBACK_DATA,
    id: *const GUID,
) -> HRESULT {
    // SAFETY: valid for the call.
    let (data, id) = unsafe { (&*data, &*id) };
    let directory = backing_of(data);
    let read = || -> io::Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            entries.push(Entry {
                name: wide(&entry.file_name()),
                info: basic_info(&entry.metadata()?),
            });
        }
        // SAFETY: terminated names.
        entries.sort_by(|a, b| {
            unsafe { PrjFileNameCompare(a.name.as_ptr(), b.name.as_ptr()) }.cmp(&0)
        });
        Ok(entries)
    };
    match read() {
        Ok(entries) => {
            provider()
                .enumerations
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id_key(id), Enumeration { entries, next: 0 });
            0
        }
        Err(error) => hresult(&error),
    }
}

fn id_key(id: &GUID) -> u128 {
    (u128::from(id.data1) << 96)
        | (u128::from(id.data2) << 80)
        | (u128::from(id.data3) << 64)
        | u128::from(u64::from_be_bytes(id.data4))
}

unsafe extern "system" fn end_enumeration(
    _data: *const PRJ_CALLBACK_DATA,
    id: *const GUID,
) -> HRESULT {
    // SAFETY: valid for the call.
    let id = unsafe { &*id };
    provider()
        .enumerations
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id_key(id));
    0
}

unsafe extern "system" fn get_enumeration(
    data: *const PRJ_CALLBACK_DATA,
    id: *const GUID,
    search: PCWSTR,
    buffer: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> HRESULT {
    // SAFETY: valid for the call.
    let (data, id) = unsafe { (&*data, &*id) };
    let mut enumerations = provider()
        .enumerations
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let Some(enumeration) = enumerations.get_mut(&id_key(id)) else {
        return NOT_FOUND;
    };
    if data.Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN != 0 {
        enumeration.next = 0;
    }
    while let Some(entry) = enumeration.entries.get(enumeration.next) {
        // SAFETY: terminated strings; `search` may be null.
        let wanted = search.is_null()
            || unsafe { *search } == 0
            || unsafe { PrjFileNameMatch(entry.name.as_ptr(), search) };
        if wanted {
            // SAFETY: a terminated name, a complete structure.
            let result = unsafe { PrjFillDirEntryBuffer(entry.name.as_ptr(), &entry.info, buffer) };
            if result == BUFFER_FULL {
                break;
            }
            if result < 0 {
                return result;
            }
        }
        enumeration.next += 1;
    }
    0
}

unsafe extern "system" fn get_placeholder_info(data: *const PRJ_CALLBACK_DATA) -> HRESULT {
    // SAFETY: valid for the call.
    let data = unsafe { &*data };
    let metadata = match std::fs::metadata(backing_of(data)) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return NOT_FOUND,
        Err(error) => return hresult(&error),
    };
    let info = PRJ_PLACEHOLDER_INFO {
        FileBasicInfo: basic_info(&metadata),
        ..Default::default()
    };
    // SAFETY: ProjFS's own context and name; a complete structure.
    unsafe {
        PrjWritePlaceholderInfo(
            data.NamespaceVirtualizationContext,
            data.FilePathName,
            &info,
            std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
        )
    }
}

unsafe extern "system" fn get_file_data(
    data: *const PRJ_CALLBACK_DATA,
    offset: u64,
    length: u32,
) -> HRESULT {
    // SAFETY: valid for the call.
    let data = unsafe { &*data };
    let serve = || -> Result<(), HRESULT> {
        let mut file = File::open(backing_of(data)).map_err(|e| hresult(&e))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| hresult(&e))?;
        let context = data.NamespaceVirtualizationContext;
        let mut at = offset;
        let end = offset + u64::from(length);
        while at < end {
            let size = (end - at).min(CHUNK) as usize;
            // SAFETY: ProjFS's own context.
            let buffer = unsafe { PrjAllocateAlignedBuffer(context, size) };
            if buffer.is_null() {
                return Err(0x8007_000eu32 as HRESULT);
            }
            // SAFETY: `size` bytes, allocated above.
            let slice = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), size) };
            let result = file
                .read_exact(slice)
                .map_err(|e| hresult(&e))
                .and_then(|()| {
                    // SAFETY: the buffer and the stream ProjFS named.
                    let written = unsafe {
                        PrjWriteFileData(
                            context,
                            &data.DataStreamId,
                            buffer as *const c_void,
                            at,
                            size as u32,
                        )
                    };
                    if written < 0 { Err(written) } else { Ok(()) }
                });
            // SAFETY: allocated above.
            unsafe { PrjFreeAlignedBuffer(buffer) };
            result?;
            at += size as u64;
        }
        Ok(())
    };
    match serve() {
        Ok(()) => 0,
        Err(result) => result,
    }
}

/// The virtualization root, served while it lives.
pub struct Running(PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT);

impl Drop for Running {
    fn drop(&mut self) {
        // SAFETY: the context PrjStartVirtualizing gave.
        unsafe { PrjStopVirtualizing(self.0) };
    }
}

/// Marks `root`, a new empty folder, as a virtualization root.
pub fn mark(root: &Path) -> io::Result<()> {
    let path = wide(root.as_os_str());
    // SAFETY: a terminated path and a GUID that outlive the call.
    let result = unsafe {
        PrjMarkDirectoryAsPlaceholder(path.as_ptr(), std::ptr::null(), std::ptr::null(), &INSTANCE)
    };
    if result < 0 {
        return Err(failed(
            &format!("marking {} as a virtualization root", root.display()),
            result,
        ));
    }
    Ok(())
}

/// Projects `backing` into `root` until the result is dropped.
pub fn start(root: &Path, backing: &Path) -> io::Result<Running> {
    let _ = PROVIDER.set(Provider {
        backing: backing.to_owned(),
        enumerations: Mutex::new(HashMap::new()),
    });
    let callbacks = PRJ_CALLBACKS {
        StartDirectoryEnumerationCallback: Some(start_enumeration),
        EndDirectoryEnumerationCallback: Some(end_enumeration),
        GetDirectoryEnumerationCallback: Some(get_enumeration),
        GetPlaceholderInfoCallback: Some(get_placeholder_info),
        GetFileDataCallback: Some(get_file_data),
        QueryFileNameCallback: None,
        NotificationCallback: None,
        CancelCommandCallback: None,
    };
    let path = wide(root.as_os_str());
    let mut context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT = std::ptr::null_mut();
    // SAFETY: a terminated path and complete structures; ProjFS copies
    // the callbacks.
    let result = unsafe {
        PrjStartVirtualizing(
            path.as_ptr(),
            &callbacks,
            std::ptr::null(),
            std::ptr::null(),
            &mut context,
        )
    };
    if result < 0 {
        return Err(failed(
            &format!("starting to project {}", root.display()),
            result,
        ));
    }
    Ok(Running(context))
}

/// What ProjFS reports of `path` on the disk.
pub fn state(path: &Path) -> String {
    let name = wide(path.as_os_str());
    let mut state: PRJ_FILE_STATE = 0;
    // SAFETY: a terminated path; an out value.
    let result = unsafe { PrjGetOnDiskFileState(name.as_ptr(), &mut state) };
    if result < 0 {
        return format!("HRESULT {:#010x}", result as u32);
    }
    let mut names = Vec::new();
    for (bit, name) in [
        (PRJ_FILE_STATE_PLACEHOLDER, "placeholder"),
        (PRJ_FILE_STATE_HYDRATED_PLACEHOLDER, "hydrated"),
        (PRJ_FILE_STATE_DIRTY_PLACEHOLDER, "dirty"),
        (PRJ_FILE_STATE_FULL, "full"),
        (PRJ_FILE_STATE_TOMBSTONE, "tombstone"),
    ] {
        if state & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "not projected".into()
    } else {
        names.join("+")
    }
}

/// Every file and folder under `directory`, relative to it, folders
/// before what they hold.
pub fn walk(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        for entry in std::fs::read_dir(directory.join(&relative))? {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                pending.push(path.clone());
            }
            found.push(path);
        }
    }
    Ok(found)
}
