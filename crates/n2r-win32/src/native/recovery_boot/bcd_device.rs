//! Read-only encoded BootMgr device observation on caller-owned fresh copies.
//! The caller authenticates the copied input and its independent-J destination.
//! An observation grants no source, boot-selection, restoration or write right.
use super::*;
use crate::reference_file::{ReferenceFileSnapshot, observe_reference_file_handle_with_limit};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use crate::native::offline_environment::kernel_ram_backing::{self, KernelRamBackingFacts};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_DISPOSITION_INFO, FileDispositionInfo,
    GetFileInformationByHandle, SetFileInformationByHandle,
};
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
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct RamFileIdentity {
    volume_serial: u32,
    file_index: u64,
    file_bytes: u64,
    attributes: u32,
    links: u32,
    created: u64,
    modified: u64,
}
fn ram_identity(file: &File, directory: bool) -> io::Result<RamFileIdentity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: borrowed live handle and a complete initialized native output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let value = RamFileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        file_bytes: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
        created: (u64::from(info.ftCreationTime.dwHighDateTime) << 32)
            | u64::from(info.ftCreationTime.dwLowDateTime),
        modified: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(info.ftLastWriteTime.dwLowDateTime),
    };
    need(value.volume_serial != 0 && value.file_index != 0 && value.links > 0
        && (value.attributes & 0x10 != 0) == directory
        && value.attributes & (0x40 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x4000) == 0,
        "fresh kernel-RAM BCD object lacks ordinary native identity")?;
    Ok(value)
}
fn same_ram_object(a: &RamFileIdentity, b: &RamFileIdentity) -> bool {
    a.volume_serial == b.volume_serial && a.file_index == b.file_index
        && a.attributes == b.attributes && a.links == b.links && a.created == b.created
}
fn require_ram_file(path: &Path, file: &File, expected: &KernelRamBackingFacts)
    -> io::Result<String> {
    let (actual, native) = kernel_ram_backing::require_file(
        path.to_str().ok_or_else(|| bad("Unicode kernel-RAM query path required"))?, file)?;
    need(actual == *expected && actual.positive_native_kernel_ramdisk
        && !actual.grants_source_write_authority,
        "BCD query copy is not on the current held kernel RAM device")?;
    Ok(native)
}
fn ram_bytes(path: &Path, expected: &RamFileIdentity, backing: &KernelRamBackingFacts)
    -> io::Result<Vec<u8>> {
    let mut data = OpenOptions::new().read(true).share_mode(3)
        .custom_flags(0x0020_0000).open(path)?;
    crate::file_storage::require_readonly_access(&data)?;
    require_ram_file(path, &data, backing)?;
    need(ram_identity(&data, false)? == *expected,
        "kernel-RAM BCD read handle differs from its held copy")?;
    let bound = expected.file_bytes.checked_add(1).ok_or_else(|| bad("RAM copy size overflow"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(bound).map_err(io::Error::other)?)
        .map_err(io::Error::other)?;
    (&mut data).take(bound).read_to_end(&mut bytes)?;
    need(bytes.len() as u64 == expected.file_bytes
        && ram_identity(&data, false)? == *expected,
        "kernel-RAM BCD bytes or identity changed during complete read")?;
    require_ram_file(path, &data, backing)?;
    Ok(bytes)
}
fn retire_ram_object(path: &Path, identity: &RamFileIdentity, directory: bool,
    backing: &KernelRamBackingFacts) -> io::Result<()> {
    // Reopen DELETE on the exact positively identified object after all query
    // handles close. Disposition by this handle cannot delete a replacement.
    let file = OpenOptions::new().access_mode(0x0001_0080).share_mode(3)
        .custom_flags(if directory { 0x0220_0000 } else { 0x0020_0000 }).open(path)?;
    require_ram_file(path, &file, backing)?;
    let actual = ram_identity(&file, directory)?;
    need(same_ram_object(&actual, identity)
        && (directory || identity.file_bytes != 0 || actual == *identity),
        "fresh RAM BCD object changed before bounded retirement")?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: live DELETE handle, fixed initialized input, synchronous call.
    if unsafe { SetFileInformationByHandle(file.as_raw_handle(), FileDispositionInfo,
        (&disposition as *const FILE_DISPOSITION_INFO).cast(),
        std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn retire_empty_ram_logs(directory: &Path, held: &File, backing: &KernelRamBackingFacts)
    -> io::Result<u32> {
    require_ram_file(directory, held, backing)?;
    let mut seen = [false; 2];
    let mut logs = Vec::new();
    logs.try_reserve_exact(2).map_err(io::Error::other)?;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| bad("non-Unicode RAM query sidecar"))?;
        let slot = if name.eq_ignore_ascii_case("query.bcd.LOG1") { 0 }
            else if name.eq_ignore_ascii_case("query.bcd.LOG2") { 1 }
            else { return Err(bad("unexpected file in fresh private RAM query directory")); };
        need(!seen[slot], "duplicate RAM query log name")?;
        seen[slot] = true;
        let path = directory.join(name);
        let file = OpenOptions::new().access_mode(0x80).share_mode(1)
            .custom_flags(0x0020_0000).open(&path)?;
        require_ram_file(&path, &file, backing)?;
        let id = ram_identity(&file, false)?;
        // Actual KEY_READ AppHive creates these two empty files on WinPE.
        // A nonempty, aliased, reparse or multiply-linked object is never retired.
        need(id.file_bytes == 0 && id.links == 1 && ram_identity(&file, false)? == id,
            "RAM query log is not an unchanged empty single-link owned file")?;
        drop(file);
        logs.push((path, id));
    }
    // Finish the bounded enumeration before changing directory contents.
    let retired = logs.len() as u32;
    for (path, id) in logs { retire_ram_object(&path, &id, false, backing)?; }
    require_ram_file(directory, held, backing)?;
    Ok(retired)
}
static RAM_COPY_ORDINAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Caller supplies a fresh owned, already authenticated, independent-J copy.
/// RegLoadAppKey can create missing files: positive existing-file ownership and
/// no-delete handles are therefore mandatory before it is ever invoked.
pub(super) fn observe_owned_copy(
    path: &Path,
    ram_root: &str,
    ram_backing: &KernelRamBackingFacts,
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
        let path_workspace = (path.as_os_str().as_encoded_bytes().len() as u64 + 256)
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
        // The durable J copy remains pristine and write/delete excluded. The
        // application hive is loaded only from a different, fresh RAM object.
        let mut keeper = OpenOptions::new().read(true).share_mode(1)
            .custom_flags(0x0020_0000).open(path)?;
        crate::file_storage::require_readonly_access(&keeper)?;
        let before = observe_reference_file_handle_with_limit(&keeper, budget.maximum_store_bytes)?;
        need(before.file_bytes == initial.len() && before.number_of_links == 1,
            "owned BCD query copy size or single-link identity differs")?;
        let parent = crate::file_storage::final_path_guid(parents.first()
            .ok_or_else(|| bad("held BCD copy parent absent"))?)?;
        need(Path::new(&before.final_path).parent().and_then(Path::to_str)
            .is_some_and(|p| p.eq_ignore_ascii_case(parent.trim_end_matches('\\'))),
            "owned BCD query copy lost its held native parent")?;
        let before_hash = crate::sha256_native::hash_range(&mut keeper, 0, before.file_bytes)?;
        need(kernel_ram_backing::require_path(ram_root)? == *ram_backing,
            "current kernel RAM root differs from actual recovery environment")?;
        let root = Path::new(ram_root);
        let root_holder = OpenOptions::new().access_mode(0x80).share_mode(3)
            .custom_flags(0x0220_0000).open(root)?;
        need(root_holder.metadata()?.is_dir() && root_holder.metadata()?.file_attributes() & 0x400 == 0,
            "ordinary held current RAM root required")?;
        let ordinal = RAM_COPY_ORDINAL.fetch_update(std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| bad("RAM BCD copy ordinal overflow"))?;
        let ram_directory = root.join(format!("N2R-BCD-query-{}-{ordinal:016x}", std::process::id()));
        std::fs::create_dir(&ram_directory)?;
        let directory_holder = OpenOptions::new().access_mode(0x80).share_mode(3)
            .custom_flags(0x0220_0000).open(&ram_directory)?;
        require_ram_file(&ram_directory, &directory_holder, ram_backing)?;
        let directory_id = ram_identity(&directory_holder, true)?;
        let ram_path = ram_directory.join("query.bcd");
        let copied = (|| {
            let mut output = OpenOptions::new().read(true).write(true).share_mode(3)
                .create_new(true).open(&ram_path)?;
            require_ram_file(&ram_path, &output, ram_backing)?;
            keeper.seek(SeekFrom::Start(0))?;
            need(io::copy(&mut (&mut keeper).take(before.file_bytes), &mut output)? == before.file_bytes,
                "authenticated J BCD input became short during RAM copy")?;
            output.sync_all()?;
            let id = ram_identity(&output, false)?;
            need(id.file_bytes == before.file_bytes && id.links == 1
                && crate::sha256_native::hash_range(&mut output, 0, id.file_bytes)? == before_hash,
                "fresh kernel-RAM BCD copy differs from authenticated J input")?;
            Ok::<_, io::Error>(id)
        })();
        let ram_id = match copied {
            Ok(id) => id,
            Err(error) => return Err(error), // No unvalidated path is retired.
        };
        let mut query_modified_time_changed = false;
        let mut query_modified_times = None;
        let queried = (|| {
            let ram_keeper = OpenOptions::new().access_mode(0x80).share_mode(3)
                .custom_flags(0x0020_0000).open(&ram_path)?;
            let native_name = require_ram_file(&ram_path, &ram_keeper, ram_backing)?;
            // Writer close can finalize LastWriteTime after FlushFileBuffers.
            // Begin the immutable query epoch only after that writer is closed.
            let query_id = ram_identity(&ram_keeper, false)?;
            need(same_ram_object(&query_id, &ram_id) && query_id.file_bytes == before.file_bytes,
                "RAM query keeper differs from freshly authenticated copy")?;
            let original_bytes = ram_bytes(&ram_path, &query_id, ram_backing)?;
            need(original_bytes.get(..4) == Some(b"regf") && digest(&original_bytes) == before_hash,
                "authenticated kernel-RAM query copy is not the exact BCD hive")?;
            // Match the measured ordinary RAM route. Current DOS mapping and
            // the SAME held NT Ramdisk object are positively checked on both sides.
            let result = read_element(&ram_path, value_maximum as u32);
            let closing = (|| {
                let after_name = require_ram_file(&ram_path, &ram_keeper, ram_backing)?;
                let after_id = ram_identity(&ram_keeper, false)?;
                let same_nt_name = after_name == native_name;
                query_modified_times = Some([query_id.modified, after_id.modified]);
                let stable_identity = same_ram_object(&after_id, &query_id)
                    && after_id.file_bytes == query_id.file_bytes;
                if !same_nt_name || !stable_identity {
                    events.push(NativeEvent {
                        operation: "boot-RAM-query-native-identity-comparison-failed".into(),
                        control_code: 0, input: Vec::new(), succeeded: false, native_error: None,
                        output: serde_json::to_vec(&serde_json::json!({
                            "before": query_id, "after": after_id,
                            "before_NT_name": native_name, "after_NT_name": after_name,
                            "same_NT_name": same_nt_name, "stable_native_identity": stable_identity,
                            "source_write_authority": false,
                        })).map_err(io::Error::other)?,
                    });
                }
                need(same_nt_name && stable_identity,
                    "kernel-RAM BCD query identity changed after private-hive close")?;
                // Read-only Registry can finalize LastWriteTime on this OWNED
                // scratch copy. Stable native identity and every content byte
                // must still match; the new read epoch has full bookends.
                query_modified_time_changed = after_id.modified != query_id.modified;
                let closing_bytes = ram_bytes(&ram_path, &after_id, ram_backing)?;
                need(closing_bytes == original_bytes && digest(&closing_bytes) == before_hash,
                    "kernel-RAM BCD query bytes changed after private-hive close")?;
                require_ram_file(&ram_directory, &directory_holder, ram_backing)?;
                Ok::<_, io::Error>(())
            })();
            match (result, closing) {
                (Ok(bytes), Ok(())) => Ok(bytes),
                (Err(error), Ok(())) | (_, Err(error)) => Err(error),
            }
        })();
        // J is never mapped by Registry, and is checked even if querying failed.
        let closing_j = (|| {
            need(observe_reference_file_handle_with_limit(&keeper, budget.maximum_store_bytes)? == before
                && crate::sha256_native::hash_range(&mut keeper, 0, before.file_bytes)? == before_hash
                && observe_reference_file_handle_with_limit(&keeper, budget.maximum_store_bytes)? == before,
                "pristine authenticated J BCD input changed during RAM query")
        })();
        let cleanup_file = retire_ram_object(&ram_path, &ram_id, false, ram_backing);
        let cleanup_logs = if cleanup_file.is_ok() {
            retire_empty_ram_logs(&ram_directory, &directory_holder, ram_backing)
        } else { Err(bad("RAM sidecar retirement skipped after primary-copy retirement failed")) };
        drop(directory_holder);
        let cleanup_directory = retire_ram_object(&ram_directory, &directory_id, true, ram_backing);
        if queried.is_err() || closing_j.is_err() || cleanup_file.is_err()
            || cleanup_logs.is_err() || cleanup_directory.is_err() {
            events.push(NativeEvent {
                operation: "boot-owned-RAM-query-and-retirement-failed".into(),
                control_code: 0, input: Vec::new(), succeeded: false, native_error: None,
                output: serde_json::to_vec(&serde_json::json!({
                    "RAM_directory": ram_directory, "query_ok": queried.is_ok(),
                    "query_error": queried.as_ref().err().map(ToString::to_string),
                    "pristine_J_bookends_ok": closing_j.is_ok(),
                    "pristine_J_error": closing_j.as_ref().err().map(ToString::to_string),
                    "primary_retirement_error": cleanup_file.as_ref().err().map(ToString::to_string),
                    "empty_logs_retirement_error": cleanup_logs.as_ref().err().map(ToString::to_string),
                    "directory_retirement_error": cleanup_directory.as_ref().err().map(ToString::to_string),
                    "source_write_authority": false,
                })).map_err(io::Error::other)?,
            });
        }
        // Cleanup is attempted even after a failed query, but cannot hide the
        // original query or pristine-J bookend failure.
        let bytes = queried?;
        closing_j?;
        cleanup_file?;
        let retired_logs = cleanup_logs?;
        cleanup_directory?;
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
                "query_copy_backing": "current-positive-kernel-RAM",
                "pristine_J_copy_complete_bytes_unchanged": true,
                "RAM_native_object_identity_size_and_all_bytes_unchanged": true,
                "RAM_query_modified_time_changed": query_modified_time_changed,
                "RAM_query_modified_times_before_after": query_modified_times,
                "RAM_copy_retired_by_exact_native_handle": true,
                "empty_RAM_registry_logs_retired": retired_logs,
                "source_write_authority": false,
            })).map_err(io::Error::other)?,
        });
        Ok(observation)
    })();
    native::diagnose(result, "boot-owned-copy-encoded-device-readonly-failed",
        "private-app-hive-read-and-file-bookends", &path.to_string_lossy(), events)
}
