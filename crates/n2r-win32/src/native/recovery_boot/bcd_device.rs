//! Read-only encoded BootMgr device observation on caller-owned fresh copies.
//! The caller authenticates the copied input and its independent-J destination.
//! An observation grants no source, boot-selection, restoration or write right.
use super::*;
use crate::reference_file::{ReferenceFileSnapshot, observe_reference_file_handle_with_limit};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_QUERY_VALUE, KEY_READ, REG_BINARY, REG_PROCESS_APPKEY, RegCloseKey,
    RegLoadAppKeyW, RegOpenKeyExW, RegQueryValueExW,
};

pub(super) struct DeviceElementObservation {
    pub(super) file: ReferenceFileSnapshot,
    pub(super) file_sha256: [u8; 32],
    pub(super) value_sha256: [u8; 32],
    pub(super) bytes: Vec<u8>,
}

struct ReadonlyKey(HKEY);
impl ReadonlyKey {
    fn close(mut self) -> io::Result<()> {
        // SAFETY: this owner uniquely holds a live registry key. It is closed
        // before any post-query file observation or content comparison.
        let status = unsafe { RegCloseKey(self.0) };
        self.0 = ptr::null_mut();
        status_result(status)
    }
}
impl Drop for ReadonlyKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the owner has not previously closed this live key.
            unsafe { RegCloseKey(self.0); }
        }
    }
}
fn status_result(status: u32) -> io::Result<()> {
    if status == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(status as i32)) }
}
fn read_element(path: &Path, maximum: u32) -> io::Result<Vec<u8>> {
    let path = path.to_str().ok_or_else(|| bad("Unicode owned BCD query copy required"))?;
    let mut root = ptr::null_mut();
    // The existing file and no-delete parents are held by observe_owned_copy.
    // This is a process-private, KEY_READ application hive, never a global mount.
    // SAFETY: terminated path and output handle outlive this synchronous call.
    status_result(unsafe {
        RegLoadAppKeyW(wide(path).as_ptr(), &mut root, KEY_READ, REG_PROCESS_APPKEY, 0)
    })?;
    let root = ReadonlyKey(root);
    let mut child = ptr::null_mut();
    // SAFETY: the parent is live; the static terminated subkey is bounded.
    status_result(unsafe {
        RegOpenKeyExW(root.0,
            wide(r"Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\Elements\11000001").as_ptr(),
            0, KEY_QUERY_VALUE, &mut child)
    })?;
    let child = ReadonlyKey(child);
    let (mut kind, mut length) = (0u32, 0u32);
    // SAFETY: query size/type only; no data buffer is supplied.
    status_result(unsafe {
        RegQueryValueExW(child.0, wide("Element").as_ptr(), ptr::null(),
            &mut kind, ptr::null_mut(), &mut length)
    })?;
    need(kind == REG_BINARY && length > 0 && length <= maximum,
        "encoded BootMgr device exceeds admitted binary workspace")?;
    let expected = length;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length as usize).map_err(io::Error::other)?;
    bytes.resize(length as usize, 0);
    // SAFETY: initialized exactly-sized output and live read-only key.
    status_result(unsafe {
        RegQueryValueExW(child.0, wide("Element").as_ptr(), ptr::null(),
            &mut kind, bytes.as_mut_ptr(), &mut length)
    })?;
    need(kind == REG_BINARY && length == expected,
        "encoded BootMgr device changed during native query")?;
    child.close()?;
    root.close()?;
    Ok(bytes)
}
fn hash_same_copy(path: &Path, expected: &ReferenceFileSnapshot, maximum: u64)
    -> io::Result<[u8; 32]> {
    // Read-data sharing is deliberately a separate epoch. Holding GENERIC_READ
    // across RegLoadAppKey causes ERROR_SHARING_VIOLATION on real WinPE.
    let mut data = OpenOptions::new().read(true).share_mode(3)
        .custom_flags(0x0020_0000).open(path)?;
    crate::file_storage::require_readonly_access(&data)?;
    need(observe_reference_file_handle_with_limit(&data, maximum)? == *expected,
        "owned BCD data handle differs from held copy identity")?;
    let mut signature = [0u8; 4];
    data.read_exact(&mut signature)?;
    need(&signature == b"regf", "owned BCD copy is not a registry hive")?;
    let hash = crate::sha256_native::hash_range(&mut data, 0, expected.file_bytes)?;
    need(observe_reference_file_handle_with_limit(&data, maximum)? == *expected,
        "owned BCD copy changed during complete-file hash")?;
    // This data FileObject closes before the caller loads an application hive.
    Ok(hash)
}

/// Caller supplies a fresh owned, already authenticated, independent-J copy.
/// RegLoadAppKey can create missing files: positive existing-file ownership and
/// no-delete handles are therefore mandatory before it is ever invoked.
pub(super) fn observe_owned_copy(
    path: &Path,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<DeviceElementObservation> {
    budget.validate()?;
    let result = (|| {
        need(path.is_absolute()
            && !path.components().any(|c| matches!(c, std::path::Component::CurDir | std::path::Component::ParentDir)),
            "absolute owned BCD copy without traversal required")?;
        let initial = std::fs::symlink_metadata(path)?;
        need(initial.is_file() && initial.file_attributes() & 0x400 == 0
            && initial.len() >= 4 && initial.len() <= budget.maximum_store_bytes,
            "existing bounded ordinary BCD query copy required")?;
        let value_maximum = (budget.maximum_control_bytes / 8)
            .min(budget.ram_bytes / 32).min(65536);
        need(value_maximum > 0, "encoded-device workspace is empty")?;
        let path_workspace = (path.as_os_str().as_encoded_bytes().len() as u64)
            .checked_mul(32).ok_or_else(|| bad("BCD query path workspace overflow"))?;
        let required = initial.len().checked_mul(3)
            .and_then(|n| n.checked_add(value_maximum * 3))
            .and_then(|n| n.checked_add(path_workspace))
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or_else(|| bad("BCD private-hive working memory overflow"))?;
        need(required <= budget.ram_bytes, "actual owned BCD query exceeds admitted RAM")?;
        let mut parents = Vec::new();
        parents.try_reserve_exact(path.ancestors().count()).map_err(io::Error::other)?;
        for parent in path.parent().ok_or_else(|| bad("BCD query parent absent"))?
            .ancestors().filter(|p| !p.as_os_str().is_empty()) {
            let file = OpenOptions::new().access_mode(0x80).share_mode(3)
                .custom_flags(0x0220_0000).open(parent)?;
            let metadata = file.metadata()?;
            need(metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "owned BCD query parent is not an ordinary held directory")?;
            parents.push(file);
        }
        let keeper = OpenOptions::new().access_mode(0x80).share_mode(3)
            .custom_flags(0x0020_0000).open(path)?;
        let before = observe_reference_file_handle_with_limit(&keeper, budget.maximum_store_bytes)?;
        need(before.file_bytes == initial.len() && before.number_of_links == 1,
            "owned BCD query copy size or single-link identity differs")?;
        let parent = crate::file_storage::final_path_guid(parents.first()
            .ok_or_else(|| bad("held BCD copy parent absent"))?)?;
        need(Path::new(&before.final_path).parent().and_then(Path::to_str)
            .is_some_and(|p| p.eq_ignore_ascii_case(parent.trim_end_matches('\\'))),
            "owned BCD query copy lost its held native parent")?;
        // Use the held file's native GUID route, so a drive-letter remapping
        // cannot redirect either the registry loader or subsequent byte reads.
        let native_path = Path::new(&before.final_path);
        let before_hash = hash_same_copy(native_path, &before, budget.maximum_store_bytes)?;
        let queried = read_element(native_path, value_maximum as u32);
        // Always observe the file after all app-hive handles have closed, even
        // when the native registry call failed. No failed query authorizes I/O.
        let closing = (|| {
            need(observe_reference_file_handle_with_limit(&keeper, budget.maximum_store_bytes)? == before,
                "owned BCD identity changed after private-hive close")?;
            need(hash_same_copy(native_path, &before, budget.maximum_store_bytes)? == before_hash,
                "owned BCD bytes changed after private-hive close")
        })();
        let bytes = match (queried, closing) {
            (Ok(bytes), Ok(())) => bytes,
            (Err(error), Ok(())) | (_, Err(error)) => return Err(error),
        };
        let observation = DeviceElementObservation {
            file: before, file_sha256: before_hash, value_sha256: digest(&bytes), bytes,
        };
        events.push(NativeEvent {
            operation: "boot-owned-copy-encoded-device-readonly-verified".into(),
            control_code: 0, input: Vec::new(), succeeded: true, native_error: None,
            output: serde_json::to_vec(&serde_json::json!({
                "copy": observation.file, "complete_file_sha256": hex::encode(observation.file_sha256),
                "element_type": "11000001", "element_bytes": observation.bytes.len(),
                "element_sha256": hex::encode(observation.value_sha256),
                "native_file_identity_and_complete_bytes_unchanged": true,
                "private_hive_KEY_READ_only": true, "working_memory_bound": required,
                "source_write_authority": false,
            })).map_err(io::Error::other)?,
        });
        Ok(observation)
    })();
    native::diagnose(result, "boot-owned-copy-encoded-device-readonly-failed",
        "private-app-hive-read-and-file-bookends", &path.to_string_lossy(), events)
}
