//! Complete EA observations/restoration on caller-held synchronous handles.
//! Query failures never become empty sets. Restoration is only for fresh
//! constructor-owned canonical file/directory handles, never named ADS handles.
//! Sources: Microsoft ZwQueryEaFile, ZwSetEaFile and FILE_FULL_EA_INFORMATION.
use crate::{
    extended_attributes::{self, Set},
    file_storage,
};
use std::{
    collections::BTreeSet, ffi::c_void, fmt, fs::File, io, os::windows::io::AsRawHandle, ptr,
};
use windows_sys::Win32::{Foundation::HANDLE, System::IO::IO_STATUS_BLOCK};

const SUCCESS: i32 = 0;
const BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const NO_MORE_EAS: i32 = 0x8000_0012u32 as i32;
const NO_EAS_ON_FILE: i32 = 0xc000_0052u32 as i32;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryEaFile(
        handle: HANDLE,
        status: *mut IO_STATUS_BLOCK,
        buffer: *mut c_void,
        length: u32,
        single: u8,
        list: *const c_void,
        list_length: u32,
        index: *const u32,
        restart: u8,
    ) -> i32;
    fn NtSetEaFile(
        handle: HANDLE,
        status: *mut IO_STATUS_BLOCK,
        buffer: *const c_void,
        length: u32,
    ) -> i32;
    fn NtQueryInformationFile(
        handle: HANDLE,
        status: *mut IO_STATUS_BLOCK,
        information: *mut c_void,
        length: u32,
        class: i32,
    ) -> i32;
}

#[derive(Debug)]
pub struct Error {
    pub operation: &'static str,
    pub ntstatus: Option<i32>,
    pub completion_status: Option<i32>,
    pub information: usize,
    pub message: String,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.operation, self.message)?;
        if let Some(status) = self.ntstatus {
            write!(f, "; NTSTATUS=0x{:08x}", status as u32)?;
        }
        if let Some(status) = self.completion_status {
            write!(f, "; completion=0x{:08x}", status as u32)?;
        }
        write!(f, "; information={}", self.information)
    }
}
impl std::error::Error for Error {}
fn invalid(operation: &'static str, message: impl Into<String>) -> Error {
    Error {
        operation,
        ntstatus: None,
        completion_status: None,
        information: 0,
        message: message.into(),
    }
}
fn native_error(
    operation: &'static str,
    status: i32,
    completion: i32,
    information: usize,
) -> Error {
    Error {
        operation,
        ntstatus: Some(status),
        completion_status: Some(completion),
        information,
        message: "native EA operation refused or returned an inconsistent completion".into(),
    }
}
fn checked(operation: &'static str, result: io::Result<()>) -> Result<(), Error> {
    result.map_err(|error| invalid(operation, error.to_string()))
}
fn identity(file: &File) -> Result<String, Error> {
    file_storage::file_id_info(file).map_err(|error| invalid("EA identity", error.to_string()))
}
fn synchronous(file: &File) -> Result<(), Error> {
    let mut mode = 0u32;
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: FILE_INFORMATION_CLASS FileModeInformation (16) is a fixed,
    // I/O-manager-local query on a live handle with aligned initialized output.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            (&mut mode as *mut u32).cast(),
            4,
            16,
        )
    };
    // SAFETY: initialized IO_STATUS_BLOCK; the native call is complete.
    let completion = unsafe { status_block.Anonymous.Status };
    if status != SUCCESS || completion != SUCCESS || status_block.Information != 4 {
        return Err(native_error(
            "EA synchronous-handle check",
            status,
            completion,
            status_block.Information,
        ));
    }
    if mode & 0x30 == 0 {
        return Err(invalid(
            "EA synchronous-handle check",
            "asynchronous file handles are not supported",
        ));
    }
    Ok(())
}

/// Enumerate a complete set on the exact supplied FILE/DIR handle. Requires
/// FILE_READ_EA and FILE_READ_ATTRIBUTES; no path reopen, payload read or setter.
/// A positive terminal status is required after nonempty enumeration. Returned
/// names are byte-preserved; Set's ordering/uniqueness is ASCII case-insensitive.
pub fn capture(file: &File) -> Result<Set, Error> {
    synchronous(file)?;
    let before = identity(file)?;
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut native_total = 0usize;
    // u64 storage supplies alignment as well as a strict fixed response bound.
    let mut storage = vec![0u64; extended_attributes::MAX_EA_BYTES / 8];
    let mut complete = false;
    for call in 0..=extended_attributes::MAX_ENTRIES {
        storage.fill(0);
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: synchronous handle checked above; buffers are live, aligned,
        // initialized and bounded. No filter/index requests partial named data.
        let status = unsafe {
            NtQueryEaFile(
                file.as_raw_handle(),
                &mut status_block,
                storage.as_mut_ptr().cast(),
                extended_attributes::MAX_EA_BYTES as u32,
                0,
                ptr::null(),
                0,
                ptr::null(),
                u8::from(call == 0),
            )
        };
        // SAFETY: the checked synchronous native call has completed.
        let completion = unsafe { status_block.Anonymous.Status };
        let used = status_block.Information;
        if completion != status || used > extended_attributes::MAX_EA_BYTES {
            return Err(native_error("NtQueryEaFile", status, completion, used));
        }
        if (status == NO_EAS_ON_FILE && call == 0 || status == NO_MORE_EAS && !entries.is_empty())
            && used == 0
        {
            complete = true;
            break;
        }
        if !matches!(status, SUCCESS | BUFFER_OVERFLOW) || used == 0 {
            return Err(native_error("NtQueryEaFile", status, completion, used));
        }
        // SAFETY: Information was bounded by the initialized storage length.
        let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), used) };
        let page = extended_attributes::parse_native(bytes)
            .map_err(|error| invalid("native EA decode", error.to_string()))?;
        if page.is_empty() {
            return Err(invalid(
                "native EA enumeration",
                "successful page made no progress",
            ));
        }
        for entry in page.entries {
            let name: Vec<u8> = entry
                .name
                .iter()
                .map(|byte| byte.to_ascii_uppercase())
                .collect();
            if !names.insert(name) {
                return Err(invalid(
                    "native EA enumeration",
                    "EA name repeated across pages",
                ));
            }
            native_total = native_total
                .checked_add((9 + entry.name.len() + entry.value.len() + 3) & !3)
                .filter(|total| *total <= extended_attributes::MAX_EA_BYTES + 3)
                .ok_or_else(|| {
                    invalid(
                        "native EA enumeration",
                        "complete EA set exceeds bounded profile",
                    )
                })?;
            entries.push(entry);
            if entries.len() > extended_attributes::MAX_ENTRIES {
                return Err(invalid(
                    "native EA enumeration",
                    "EA count exceeds bounded profile",
                ));
            }
        }
    }
    if !complete {
        return Err(invalid(
            "native EA enumeration",
            "terminal EA response not observed",
        ));
    }
    let set = Set::new(entries).map_err(|error| invalid("native EA set", error.to_string()))?;
    if identity(file)? != before {
        return Err(invalid(
            "EA identity",
            "held identity changed during enumeration",
        ));
    }
    Ok(set)
}

/// Caller must supply a newly created, constructor-owned canonical FILE/DIR
/// handle with FILE_READ_EA, FILE_WRITE_EA and FILE_READ_ATTRIBUTES. This is not
/// an arbitrary-existing-file replacement API: any existing EA causes refusal.
/// The caller owns volume durability barriers and source exclusion; this
/// function claims semantic readback only, not durable media persistence.
pub fn restore_fresh_owned(file: &File, expected: &Set) -> Result<Set, Error> {
    checked("EA expected set", expected.validate())?;
    let before = identity(file)?;
    let current = capture(file)?;
    if !current.is_empty() {
        return Err(invalid(
            "EA fresh target",
            "constructor target already has EAs",
        ));
    }
    if !expected.is_empty() {
        let bytes = extended_attributes::encode_native(expected)
            .map_err(|error| invalid("native EA encode", error.to_string()))?;
        let mut storage = vec![0u64; bytes.len().div_ceil(8)];
        // SAFETY: bounded allocated u64 storage is writable for its full size.
        unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), bytes.len()) }
            .copy_from_slice(&bytes);
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: capture checked this exact synchronous handle; complete
        // validated native list and aligned initialized input remain live.
        let status = unsafe {
            NtSetEaFile(
                file.as_raw_handle(),
                &mut status_block,
                storage.as_ptr().cast(),
                bytes.len() as u32,
            )
        };
        // SAFETY: the synchronous native call has completed.
        let completion = unsafe { status_block.Anonymous.Status };
        if status != SUCCESS || completion != SUCCESS {
            return Err(native_error(
                "NtSetEaFile",
                status,
                completion,
                status_block.Information,
            ));
        }
    }
    let observed = capture(file)?;
    if !expected.equivalent(&observed) {
        return Err(invalid(
            "EA restore readback",
            "EA flags/names/values differ",
        ));
    }
    if identity(file)? != before {
        return Err(invalid(
            "EA restore identity",
            "constructor identity changed",
        ));
    }
    Ok(observed)
}
