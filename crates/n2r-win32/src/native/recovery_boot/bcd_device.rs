//! Encoded device observation using the documented read-only offline reader.
//! Input files and the actual sealed RAM DLL retain full identity/byte bookends.
use super::*;
use super::offreg::{OfflineRegistry, OfflineBcdObject};
use crate::native::offline_environment::kernel_ram_backing::{self, KernelRamBackingFacts};
use crate::reference_file::{ReferenceFileSnapshot, observe_reference_file_handle_with_limit};
use std::os::windows::{fs::{MetadataExt, OpenOptionsExt}, io::AsRawHandle};
use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};

pub(super) struct DeviceElementObservation {
    pub(super) file: ReferenceFileSnapshot,
    pub(super) file_sha256: [u8; 32],
    pub(super) value_sha256: [u8; 32],
    pub(super) bytes: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct LibraryIdentity {
    serial: u32, index: u64, bytes: u64, attributes: u32,
    links: u32, created: u64, modified: u64,
}
fn library_identity(file: &File) -> io::Result<LibraryIdentity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: borrowed live handle and complete initialized native output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let value = LibraryIdentity {
        serial: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        bytes: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        attributes: info.dwFileAttributes, links: info.nNumberOfLinks,
        created: (u64::from(info.ftCreationTime.dwHighDateTime) << 32) | u64::from(info.ftCreationTime.dwLowDateTime),
        modified: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32) | u64::from(info.ftLastWriteTime.dwLowDateTime),
    };
    need(value.serial != 0 && value.index != 0 && value.links == 1 && value.bytes > 0
        && value.attributes & (0x10 | 0x40 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x4000) == 0,
        "sealed RAM offline-registry library lacks ordinary native identity")?;
    Ok(value)
}
fn parents(path: &Path) -> io::Result<Vec<File>> {
    need(path.is_absolute() && !path.components().any(|p| matches!(p,
        std::path::Component::ParentDir | std::path::Component::CurDir)),
        "absolute offline-registry path without traversal required")?;
    let mut held = Vec::new();
    held.try_reserve_exact(path.ancestors().count()).map_err(io::Error::other)?;
    for parent in path.parent().ok_or_else(|| bad("offline-registry parent absent"))?
        .ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let file = OpenOptions::new().access_mode(0x80).share_mode(3)
            .custom_flags(0x0220_0000).open(parent)?;
        let meta = file.metadata()?;
        need(meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "ordinary held offline-registry parent required")?;
        held.push(file);
    }
    Ok(held)
}
/// Private current-boot DLL owner, authenticated against the sealed WIM marker.
/// No Clone/Deserialize, hive save/set API, or source write authority.
pub(super) struct OfflineRegistryLibrary {
    provider: OfflineRegistry,
    path: PathBuf,
    location: LibraryLocation,
    identity: LibraryIdentity,
    sha256: [u8; 32],
    working_bytes: u64,
    _parents: Vec<File>,
}
enum LibraryLocation {
    CurrentRam { native_name: String, backing: KernelRamBackingFacts },
    SealedJournal(ReferenceFileSnapshot),
}
impl OfflineRegistryLibrary {
    pub(super) fn open(path: &Path, expected: [u8; 32], expected_bytes: u64,
        backing: &KernelRamBackingFacts, budget: RecoveryBootBudget,
        events: &mut Vec<NativeEvent>) -> io::Result<Self> {
        budget.validate()?;
        let working_bytes = expected_bytes.checked_mul(3)
            .and_then(|n| n.checked_add(1024 * 1024))
            .and_then(|n| n.checked_add((path.as_os_str().as_encoded_bytes().len() as u64) * 32))
            .ok_or_else(|| bad("offline registry library RAM charge overflow"))?;
        need(expected_bytes > 0 && expected_bytes <= budget.maximum_image_bytes
            && working_bytes <= budget.ram_bytes,
            "actual sealed offline-registry library exceeds admitted resources")?;
        let held_parents = parents(path)?;
        let mut file = OpenOptions::new().read(true).share_mode(1)
            .custom_flags(0x0020_0000).open(path)?;
        crate::file_storage::require_readonly_access(&file)?;
        let identity = library_identity(&file)?;
        let (actual, native_name) = kernel_ram_backing::require_file(
            path.to_str().ok_or_else(|| bad("Unicode RAM library path required"))?, &file)?;
        need(actual == *backing && actual.positive_native_kernel_ramdisk
            && !actual.grants_source_write_authority && identity.bytes == expected_bytes
            && crate::sha256_native::hash_range(&mut file, 0, expected_bytes)? == expected
            && library_identity(&file)? == identity,
            "actual current kernel-RAM library differs from sealed image dependency")?;
        let provider = OfflineRegistry::load(path, file)?;
        let owner = Self { provider, path: path.to_owned(),
            location: LibraryLocation::CurrentRam { native_name, backing: backing.clone() },
            identity, sha256: expected, working_bytes,
            _parents: held_parents };
        owner.require_unchanged()?;
        events.push(NativeEvent { operation: "boot-sealed-RAM-offline-registry-loaded".into(),
            control_code: 0, input: Vec::new(), succeeded: true, native_error: None,
            output: serde_json::to_vec(&serde_json::json!({"actual_RAM_file": owner.identity,
                "sha256": hex::encode(owner.sha256), "working_bytes": owner.working_bytes,
                "documented_read_only_exports": ["OROpenHive", "ORGetValue", "ORCloseHive"],
                "save_set_exports_resolved": 0, "source_write_authority": false})).map_err(io::Error::other)? });
        Ok(owner)
    }
    pub(super) fn open_sealed_journal(path: &Path, expected: [u8; 32],
        expected_snapshot: &ReferenceFileSnapshot, journal: &GeneralJournalStorageBinding,
        budget: RecoveryBootBudget) -> io::Result<Self> {
        budget.validate()?;
        let working_bytes = expected_snapshot.file_bytes.checked_mul(3)
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or_else(|| bad("sealed journal library RAM overflow"))?;
        need(working_bytes <= budget.ram_bytes, "sealed journal library exceeds RAM")?;
        let held_parents = parents(path)?;
        let mut file = OpenOptions::new().read(true).share_mode(1)
            .custom_flags(0x0020_0000).open(path)?;
        crate::file_storage::require_readonly_access(&file)?;
        let identity = library_identity(&file)?;
        let snapshot = observe_reference_file_handle_with_limit(&file, budget.maximum_image_bytes)?;
        let prefix = format!("{}\\", journal.disk.volume_path()?.trim_end_matches('\\'));
        need(snapshot == *expected_snapshot && snapshot.number_of_links == 1
            && snapshot.final_path.get(..prefix.len()).is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
            && crate::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)? == expected,
            "actual sealed J library identity/hash differs from owned image")?;
        let provider = OfflineRegistry::load(path, file)?;
        let owner = Self { provider, path: path.to_owned(), location: LibraryLocation::SealedJournal(snapshot),
            identity, sha256: expected, working_bytes, _parents: held_parents };
        owner.require_unchanged()?;
        Ok(owner)
    }
    fn require_unchanged(&self) -> io::Result<()> {
        let file = self.provider.held_file();
        match &self.location {
            LibraryLocation::CurrentRam { native_name, backing } => {
                let (actual, name) = kernel_ram_backing::require_file(
                    self.path.to_str().ok_or_else(|| bad("Unicode RAM library path required"))?, file)?;
                need(actual == *backing && name == *native_name,
                    "held current-RAM offline-registry DLL backing changed")?;
            }
            LibraryLocation::SealedJournal(snapshot) => need(
                observe_reference_file_handle_with_limit(file, snapshot.file_bytes)? == *snapshot,
                "held sealed J offline-registry DLL identity changed")?,
        }
        need(library_identity(file)? == self.identity, "held offline-registry DLL identity changed")?;
        let mut data = file.try_clone()?;
        need(crate::sha256_native::hash_range(&mut data, 0, self.identity.bytes)? == self.sha256
            && library_identity(file)? == self.identity,
            "held current-RAM offline-registry DLL bytes changed")
    }
}
fn input_bytes(file: &mut File, before: &ReferenceFileSnapshot, maximum: u64) -> io::Result<Vec<u8>> {
    need(observe_reference_file_handle_with_limit(file, maximum)? == *before,
        "held readonly BCD input identity changed")?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(before.file_bytes).map_err(io::Error::other)?)
        .map_err(io::Error::other)?;
    bytes.resize(before.file_bytes as usize, 0);
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    need(observe_reference_file_handle_with_limit(file, maximum)? == *before,
        "held readonly BCD input changed during complete read")?;
    Ok(bytes)
}
fn observe_with<T>(path: &Path, library: &OfflineRegistryLibrary,
    budget: RecoveryBootBudget, events: &mut Vec<NativeEvent>, extra: u64,
    read: impl FnOnce(&OfflineRegistry, &Path, u32) -> io::Result<T>)
    -> io::Result<(ReferenceFileSnapshot, [u8; 32], T, u64)> {
    budget.validate()?;
    let result = (|| {
        let initial = std::fs::symlink_metadata(path)?;
        need(initial.is_file() && initial.file_attributes() & 0x400 == 0
            && initial.len() >= 4 && initial.len() <= budget.maximum_store_bytes,
            "existing bounded ordinary BCD query copy required")?;
        let value_maximum = (budget.maximum_control_bytes / 8).min(budget.ram_bytes / 32).min(65536);
        let required = initial.len().checked_mul(3)
            .and_then(|n| n.checked_add(value_maximum * 3))
            .and_then(|n| n.checked_add(library.working_bytes))
            .and_then(|n| n.checked_add(extra))
            .and_then(|n| n.checked_add((path.as_os_str().as_encoded_bytes().len() as u64) * 32))
            .ok_or_else(|| bad("offline registry query workspace overflow"))?;
        need(value_maximum > 0 && required <= budget.ram_bytes,
            "actual readonly BCD query exceeds admitted RAM")?;
        let held_parents = parents(path)?;
        let mut file = OpenOptions::new().read(true).share_mode(1)
            .custom_flags(0x0020_0000).open(path)?;
        crate::file_storage::require_readonly_access(&file)?;
        let before = observe_reference_file_handle_with_limit(&file, budget.maximum_store_bytes)?;
        need(before.file_bytes == initial.len() && before.number_of_links == 1,
            "readonly owned BCD copy size or single-link identity differs")?;
        let parent = crate::file_storage::final_path_guid(held_parents.first()
            .ok_or_else(|| bad("held BCD parent absent"))?)?;
        need(Path::new(&before.final_path).parent().and_then(Path::to_str)
            .is_some_and(|p| p.eq_ignore_ascii_case(parent.trim_end_matches('\\'))),
            "readonly BCD input lost its held native parent")?;
        let original = input_bytes(&mut file, &before, budget.maximum_store_bytes)?;
        need(original.get(..4) == Some(b"regf"), "owned BCD input is not a registry hive")?;
        let original_sha = digest(&original);
        library.require_unchanged()?;
        // The documented reader validates/loads in memory without repair/save.
        // Use the held native GUID route rather than a mutable drive alias.
        let queried = read(&library.provider, Path::new(&before.final_path), value_maximum as u32);
        let closing = (|| {
            let after = input_bytes(&mut file, &before, budget.maximum_store_bytes)?;
            let after_sha = digest(&after);
            if after != original || after_sha != original_sha {
                let mut first = Vec::new();
                first.try_reserve_exact(32).map_err(io::Error::other)?;
                let mut count = 0u64;
                for (offset, (&old, &new)) in original.iter().zip(&after).enumerate() {
                    if old != new { count += 1; if first.len() < 32 { first.push([offset as u64, u64::from(old), u64::from(new)]); } }
                }
                events.push(NativeEvent { operation: "boot-OFFREG-input-complete-bytes-failed".into(),
                    control_code: 0, input: Vec::new(), succeeded: false, native_error: None,
                    output: serde_json::to_vec(&serde_json::json!({"before_sha256": hex::encode(original_sha),
                        "after_sha256": hex::encode(after_sha), "different_bytes": count,
                        "first32_offset_before_after": first, "held_input": before,
                        "source_write_authority": false})).map_err(io::Error::other)? });
                return Err(bad("readonly offline-registry input bytes changed"));
            }
            library.require_unchanged()
        })();
        let bytes = match (queried, closing) {
            (Ok(bytes), Ok(())) => bytes,
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        Ok((before, original_sha, bytes, required))
    })();
    native::diagnose(result, "boot-owned-copy-encoded-device-readonly-failed",
        "offline-registry-read-and-file-bookends", &path.to_string_lossy(), events)
}
pub(super) fn observe_owned_copy(path: &Path, library: &OfflineRegistryLibrary,
    budget: RecoveryBootBudget, events: &mut Vec<NativeEvent>) -> io::Result<DeviceElementObservation> {
        let (file, file_sha256, bytes, required) = observe_with(path,library,budget,events,0,
            |reader,path,maximum| reader.read_device(path,maximum))?;
        let observation = DeviceElementObservation { file, file_sha256,
            value_sha256: digest(&bytes), bytes };
        events.push(NativeEvent { operation: "boot-owned-copy-encoded-device-readonly-verified".into(),
            control_code: 0, input: Vec::new(), succeeded: true, native_error: None,
            output: serde_json::to_vec(&serde_json::json!({"copy": observation.file,
                "complete_file_sha256": hex::encode(observation.file_sha256), "element_type": "11000001",
                "element_bytes": observation.bytes.len(), "element_sha256": hex::encode(observation.value_sha256),
                "native_file_identity_and_complete_bytes_unchanged": true,
                "backend": "documented-readonly-offline-registry", "working_memory_bound": required,
                "save_set_active_hive_calls": 0, "source_write_authority": false})).map_err(io::Error::other)? });
        Ok(observation)
}
pub(super) struct ObjectObservation {
    pub(super) file_sha256: [u8;32],
    pub(super) object: OfflineBcdObject,
}
pub(super) fn observe_object(path:&Path, object_guid:&str, library:&OfflineRegistryLibrary,
    budget:RecoveryBootBudget, events:&mut Vec<NativeEvent>) -> io::Result<ObjectObservation> {
    let map_bound = budget.maximum_control_bytes.min(budget.ram_bytes / 16);
    let elements = u32::try_from(map_bound / 1024).map_err(io::Error::other)?;
    need(elements > 0, "offline BCD object workspace empty")?;
    let (_,file_sha256,object,_) = observe_with(path,library,budget,events,
        map_bound.checked_mul(3).ok_or_else(||bad("BCD map workspace overflow"))?,
        |reader,path,maximum|reader.read_object(path,object_guid,maximum,map_bound,elements))?;
    Ok(ObjectObservation{file_sha256,object})
}
