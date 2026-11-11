//! Kernel-owned RAMdisk names, independent of GetDriveType's fixed/RAM label.
//! Readonly facts only. No path/JSON fact can issue an environment/writer token.
use serde::Serialize;
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumePathNameW, QueryDosDeviceW};
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(h: *mut c_void, class: u32, b: *mut c_void, n: u32, returned: *mut u32)
    -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(h: *mut c_void, info: *mut c_void) -> i32;
}
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
const _: () = assert!(std::mem::size_of::<UnicodeString>() == 16);
fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn need(v: bool, m: &str) -> io::Result<()> {
    if v { Ok(()) } else { Err(bad(m)) }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeNameObservation {
    pub ntstatus: i32,
    pub returned_bytes: u32,
    pub name: Option<String>,
    pub failure: Option<String>,
}
pub(crate) fn object_name(file: &File) -> NativeNameObservation {
    let mut words = vec![0u64; 8192];
    let capacity = words.len() * 8;
    let mut returned = 0;
    // SAFETY: live owned FileObject, aligned initialized bounded reply. Every
    // returned UNICODE_STRING pointer is validated within this reply before use.
    let status = unsafe {
        NtQueryObject(
            file.as_raw_handle(),
            1,
            words.as_mut_ptr().cast(),
            capacity as u32,
            &mut returned,
        )
    };
    let parsed = (|| -> io::Result<String> {
        need(status == 0, "NtQueryObject(ObjectNameInformation) failed")?;
        need(
            returned as usize >= std::mem::size_of::<UnicodeString>()
                && returned as usize <= capacity,
            "ObjectNameInformation returned length invalid",
        )?;
        let u = unsafe { &*words.as_ptr().cast::<UnicodeString>() };
        let base = words.as_ptr() as usize;
        let start = (u.buffer as usize)
            .checked_sub(base)
            .ok_or_else(|| bad("objectname pointer before reply"))?;
        need(
            u.length > 0
                && (u.buffer as usize) % 2 == 0
                && u.length % 2 == 0
                && u.length <= u.maximum
                && (u.maximum as usize) <= capacity
                && start >= 16
                && start
                    .checked_add(u.length as usize)
                    .is_some_and(|e| e <= returned as usize),
            "objectname Unicode range invalid",
        )?;
        let units = unsafe { std::slice::from_raw_parts(u.buffer, u.length as usize / 2) };
        need(!units.contains(&0), "embeddedNUL objectname")?;
        String::from_utf16(units).map_err(io::Error::other)
    })();
    match parsed {
        Ok(name) => NativeNameObservation {
            ntstatus: status,
            returned_bytes: returned,
            name: Some(name),
            failure: None,
        },
        Err(e) => NativeNameObservation {
            ntstatus: status,
            returned_bytes: returned,
            name: None,
            failure: Some(format!(
                "{e}; NTSTATUS0x{:08x}; returned={returned}",
                status as u32
            )),
        },
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Legacy52Observation {
    pub succeeded: bool,
    pub native_error: Option<i32>,
    pub raw_u32: Option<Vec<u32>>,
    pub qualification_fallback_used: bool,
}
pub(crate) fn legacy52(file: &File) -> Legacy52Observation {
    let mut raw = [0u32; 13];
    let ok =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), raw.as_mut_ptr().cast()) } != 0;
    let e = (!ok).then(io::Error::last_os_error);
    Legacy52Observation {
        succeeded: ok,
        native_error: e.as_ref().and_then(io::Error::raw_os_error),
        raw_u32: ok.then(|| raw.to_vec()),
        qualification_fallback_used: false,
    }
}
pub(crate) fn dos_root(path: &str) -> io::Result<String> {
    let mut b = [0u16; 32768];
    if unsafe { GetVolumePathNameW(wide(path).as_ptr(), b.as_mut_ptr(), b.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let n = b
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| bad("DOS root unterminated"))?;
    let root = String::from_utf16(&b[..n]).map_err(io::Error::other)?;
    need(
        root.len() == 3 && root.as_bytes()[0].is_ascii_alphabetic() && &root[1..] == ":\\",
        "actual local DOS root required",
    )?;
    Ok(root)
}
fn targets(root: &str) -> io::Result<Vec<String>> {
    let mut b = vec![0u16; 32768];
    let n = unsafe { QueryDosDeviceW(wide(&root[..2]).as_ptr(), b.as_mut_ptr(), b.len() as u32) }
        as usize;
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    need(n <= b.len() && b[n - 1] == 0, "DOS target reply incomplete")?;
    let mut result = Vec::new();
    let mut at = 0;
    while at < n {
        let end = b[at..n]
            .iter()
            .position(|c| *c == 0)
            .map(|e| at + e)
            .ok_or_else(|| bad("DOS target unterminated"))?;
        if end == at {
            break;
        }
        result.push(String::from_utf16(&b[at..end]).map_err(io::Error::other)?);
        at = end + 1;
    }
    need(
        !result.is_empty() && result.len() <= 128,
        "DOS target count invalid",
    )?;
    Ok(result)
}
fn ram_device(name: &str, allow_file_suffix: bool) -> io::Result<String> {
    let prefix = r"\Device\Ramdisk{";
    need(
        name.get(..prefix.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(prefix)),
        "native kernel object is not Device\\Ramdisk{GUID}",
    )?;
    let close = name
        .find('}')
        .ok_or_else(|| bad("RAM device GUID unterminated"))?;
    let id = &name[prefix.len()..close];
    need(
        id.len() == 36 && crate::layout::guid_bytes(id).is_ok(),
        "native RAM device GUID invalid",
    )?;
    let tail = &name[close + 1..];
    need(
        tail.is_empty() || tail == "\\" || (allow_file_suffix && tail.starts_with('\\')),
        "native RAM device suffix invalid",
    )?;
    Ok(name[..close + 1].to_owned())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KernelRamBackingFacts {
    pub version: u32,
    pub kind: &'static str,
    pub dos_root: String,
    pub actual_drive_type: u32,
    pub dos_device_targets: Vec<String>,
    pub held_volume_object_name: String,
    pub ram_device_object_name: String,
    pub positive_native_kernel_ramdisk: bool,
    pub grants_source_write_authority: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct KernelRamBackingObservation {
    pub facts: Option<KernelRamBackingFacts>,
    pub actual_drive_type: Option<u32>,
    pub dos_root: Option<String>,
    pub dos_device_targets: Option<Vec<String>>,
    pub dos_query_error: Option<String>,
    pub volume_object_name: Option<NativeNameObservation>,
    pub failure: Option<String>,
    pub all_query_handles_closed: bool,
}
pub(crate) fn require_held(path: &str, volume: &File) -> io::Result<KernelRamBackingFacts> {
    let root = dos_root(path)?;
    let drive = unsafe { GetDriveTypeW(wide(&root).as_ptr()) };
    let dos = targets(&root)?;
    let q = object_name(volume);
    let native = q.name.as_ref().ok_or_else(|| {
        bad(q
            .failure
            .clone()
            .unwrap_or_else(|| "native volume objectname unknown".into()))
    })?;
    let a = ram_device(&dos[0], false)?;
    let b = ram_device(native, false)?;
    need(
        a.eq_ignore_ascii_case(&b) && matches!(drive, 3 | 6),
        "currentDOS/heldvolume RAMdevice mismatch or unknown drive classification",
    )?;
    Ok(KernelRamBackingFacts {
        version: 1,
        kind: "actual-kernel-Ramdisk-GUID-backing-v1",
        dos_root: root,
        actual_drive_type: drive,
        dos_device_targets: dos,
        held_volume_object_name: native.clone(),
        ram_device_object_name: b,
        positive_native_kernel_ramdisk: true,
        grants_source_write_authority: false,
    })
}
pub(crate) fn require_path(path: &str) -> io::Result<KernelRamBackingFacts> {
    let root = dos_root(path)?;
    let volume = OpenOptions::new()
        .access_mode(0x00100080)
        .share_mode(3)
        .open(format!(r"\\.\{}", &root[..2]))?;
    require_held(path, &volume)
}
pub(crate) fn require_file(path: &str, file: &File) -> io::Result<(KernelRamBackingFacts, String)> {
    let facts = require_path(path)?;
    let q = object_name(file);
    let native = q.name.ok_or_else(|| {
        bad(q
            .failure
            .unwrap_or_else(|| "native image objectname unknown".into()))
    })?;
    let dev = ram_device(&native, true)?;
    need(
        dev.eq_ignore_ascii_case(&facts.ram_device_object_name),
        "actual held image is not on same kernel RAMdevice",
    )?;
    let expected = format!("{}\\{}", facts.ram_device_object_name, &path[3..]);
    need(
        native.eq_ignore_ascii_case(&expected),
        "actual held image NTname differs from currentWindows DOS path",
    )?;
    Ok((facts, native))
}
pub(crate) fn observe(path: &str) -> KernelRamBackingObservation {
    let mut out = KernelRamBackingObservation {
        facts: None,
        actual_drive_type: None,
        dos_root: None,
        dos_device_targets: None,
        dos_query_error: None,
        volume_object_name: None,
        failure: None,
        all_query_handles_closed: true,
    };
    let result = (|| {
        let root = dos_root(path)?;
        out.actual_drive_type = Some(unsafe { GetDriveTypeW(wide(&root).as_ptr()) });
        out.dos_root = Some(root.clone());
        match targets(&root) {
            Ok(v) => out.dos_device_targets = Some(v),
            Err(e) => out.dos_query_error = Some(e.to_string()),
        };
        let volume = OpenOptions::new()
            .access_mode(0x00100080)
            .share_mode(3)
            .open(format!(r"\\.\{}", &root[..2]))?;
        out.volume_object_name = Some(object_name(&volume));
        let facts = require_held(path, &volume)?;
        out.facts = Some(facts);
        Ok::<(), io::Error>(())
    })();
    if let Err(e) = result {
        out.failure = Some(e.to_string())
    }
    out
}
