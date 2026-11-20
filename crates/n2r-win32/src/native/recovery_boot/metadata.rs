use super::*;
use crate::native::partition_isolation::offline::OfflineBootMetadataWitness;
type ProtectedBootBinding<'a> = (
    &'a OfflineBootMetadataWitness,
    &'a crate::offline_environment::OfflineSourceOwnerToken,
);
static DEVICE_COPY_ORDINAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LIVE_QUERY_ORDINAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(super) fn copy_authenticated_held(
    input: &mut File,
    expected: [u8; 32],
    path: &Path,
    journal: &GeneralJournalStorageBinding,
    budget: RecoveryBootBudget,
) -> io::Result<PathBuf> {
    budget.validate()?;
    crate::file_storage::require_readonly_access(input)?;
    let before = crate::reference_file::observe_reference_file_handle_with_limit(
        input,
        budget.maximum_store_bytes,
    )?;
    let prefix = format!("{}\\", journal.disk.volume_path()?.trim_end_matches('\\'));
    need(
        before.file_bytes > 0
            && before.number_of_links == 1
            && before
                .final_path
                .get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(&prefix))
            && crate::sha256_native::hash_range(input, 0, before.file_bytes)? == expected,
        "authenticated held BCD input is not the exact native J metadata",
    )?;
    let parent = path
        .parent()
        .ok_or_else(|| bad("owned BCD copy parent absent"))?;
    let held_parent = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(parent)?;
    let parent_guid = crate::file_storage::final_path_guid(&held_parent)?;
    need(
        parent_guid
            .get(..prefix.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(&prefix))
            && held_parent.metadata()?.is_dir()
            && held_parent.metadata()?.file_attributes() & 0x400 == 0,
        "owned BCD copy destination is not actual ordinary J",
    )?;
    native::owned_control_usage(
        parent,
        budget.maximum_control_bytes,
        before
            .file_bytes
            .checked_add(65535)
            .ok_or_else(|| bad("BCD copy quota overflow"))?,
    )?;
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .create_new(true)
        .open(path)?;
    input.seek(SeekFrom::Start(0))?;
    need(
        io::copy(&mut (&mut *input).take(before.file_bytes), &mut output)? == before.file_bytes,
        "owned BCD copy input became short",
    )?;
    output.sync_all()?;
    let after = crate::reference_file::observe_reference_file_handle_with_limit(
        &output,
        budget.maximum_store_bytes,
    )?;
    need(
        after.file_bytes == before.file_bytes
            && after.number_of_links == 1
            && after.volume_serial_number == before.volume_serial_number
            && after
                .final_path
                .get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(&prefix))
            && crate::sha256_native::hash_range(&mut output, 0, after.file_bytes)? == expected
            && crate::reference_file::observe_reference_file_handle_with_limit(
                input,
                budget.maximum_store_bytes,
            )? == before
            && crate::sha256_native::hash_range(input, 0, before.file_bytes)? == expected,
        "owned BCD copy or original held input changed",
    )?;
    native::register_owned_query_store(
        &output,
        path,
        budget.maximum_store_bytes,
        budget.maximum_control_bytes,
    )?;
    drop(output);
    native::owned_control_usage(parent, budget.maximum_control_bytes, 0)?;
    Ok(path.to_path_buf())
}
pub(super) fn prove_unchanged_device(
    original: &mut File,
    original_sha: [u8; 32],
    current_copy: &Path,
    current_sha: [u8; 32],
    directory: &Path,
    journal: &GeneralJournalStorageBinding,
    offline_registry: &bcd_device::OfflineRegistryLibrary,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<BootManagerDeviceProof> {
    let ordinal = DEVICE_COPY_ORDINAL
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |n| n.checked_add(1),
        )
        .map_err(|_| bad("device-copy ordinal overflow"))?;
    let original_path = copy_authenticated_held(
        original,
        original_sha,
        &directory.join(format!("encoded-device-original-{ordinal:04}.bcd")),
        journal,
        budget,
    )?;
    let first = bcd_device::observe_owned_copy(&original_path, offline_registry, budget, events)?;
    let second = bcd_device::observe_owned_copy(current_copy, offline_registry, budget, events)?;
    need(
        first.file_sha256 == original_sha
            && second.file_sha256 == current_sha
            && first.file.volume_serial_number == second.file.volume_serial_number
            && first.bytes == second.bytes
            && first.value_sha256 == second.value_sha256,
        "actual encoded BootMgr device element changed or copy authentication differs",
    )?;
    native::owned_control_usage(directory, budget.maximum_control_bytes, 0)?;
    events.push(NativeEvent {
        operation: "boot-original-current-encoded-device-exact-equality".into(),
        control_code: 0,
        input: Vec::new(),
        succeeded: true,
        native_error: None,
        output: serde_json::to_vec(
            &serde_json::json!({"original_store_sha256":hex::encode(original_sha),
            "current_store_sha256":hex::encode(current_sha),"element_type":"11000001",
            "encoded_bytes":first.bytes.len(),"encoded_sha256":hex::encode(first.value_sha256),
            "rendered_alias_is_not_device_identity":true,"source_write_authority":false}),
        )
        .map_err(io::Error::other)?,
    });
    Ok(BootManagerDeviceProof {
        original_store_sha256: original_sha,
        current_store_sha256: current_sha,
        element_sha256: first.value_sha256,
        element_bytes: first.bytes.len() as u64,
    })
}
pub(super) fn prove_available_store_device(
    efi: &EfiIdentity,
    pin: &StorePin,
    original: &mut File,
    original_sha: [u8; 32],
    directory: &Path,
    journal: &GeneralJournalStorageBinding,
    offline_registry: &bcd_device::OfflineRegistryLibrary,
    budget: RecoveryBootBudget,
    source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
    events: &mut Vec<NativeEvent>,
) -> io::Result<BootManagerDeviceProof> {
    let ordinal = DEVICE_COPY_ORDINAL
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |n| n.checked_add(1),
        )
        .map_err(|_| bad("device-copy ordinal overflow"))?;
    let path = directory.join(format!("encoded-device-current-{ordinal:04}.bcd"));
    let actual = with_live_source(efi, source, events, |events| {
        raw_copy_bound(
            efi,
            pin,
            &path,
            budget.maximum_store_bytes,
            budget.maximum_control_bytes,
            None,
            true,
            events,
        )
    })?;
    need(
        actual == pin.sha256,
        "current available EFI device-proof copy differs from actual store epoch",
    )?;
    prove_unchanged_device(
        original,
        original_sha,
        &path,
        actual,
        directory,
        journal,
        offline_registry,
        budget,
        events,
    )
}
use std::os::windows::fs::MetadataExt;
use windows_sys::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetDiskFreeSpaceW,
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: *mut std::ffi::c_void,
        output: *mut std::ffi::c_void,
    ) -> i32;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct EfiIdentity {
    pub binding: GeneralDiskBinding,
    pub native_partition_info: Vec<u8>,
    pub bcd_path: PathBuf,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RawSpan {
    pub(super) file_offset: u64,
    pub(super) physical_offset: u64,
    pub(super) bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StorePin {
    pub bytes: u64,
    pub sha256: [u8; 32],
    identity: Vec<u8>,
    pub(super) spans: Vec<RawSpan>,
    pub(super) fat_boot_sha256: [u8; 32],
    cluster_bytes: u64,
    file_area_bytes: u64,
}
impl StorePin {
    pub(super) fn same_file_map(&self, other: &Self) -> bool {
        self.same_file_map_storage(other) && self.fat_boot_sha256 == other.fat_boot_sha256
    }
    fn same_file_map_storage(&self, other: &Self) -> bool {
        self.bytes == other.bytes
            && self.identity == other.identity
            && self.spans == other.spans
            && self.cluster_bytes == other.cluster_bytes
            && self.file_area_bytes == other.file_area_bytes
    }
}
// Only a genuine closed-J AvailableSource can select the live EFI lane. The
// protected-source and ordinary observation entry points remain exact.
fn with_live_source<T>(
    efi: &EfiIdentity,
    source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
    events: &mut Vec<NativeEvent>,
    operation: impl FnOnce(&mut Vec<NativeEvent>) -> io::Result<T>,
) -> io::Result<T> {
    fn require(
        efi: &EfiIdentity,
        source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let state = source.state(events)?;
        need(
            state.actual.disk_attributes == 0 && !state.disk_offline_in_current_environment,
            "live EFI metadata requires the actual closed/available source0 owner",
        )?;
        require_source_efi_identity(efi, &state)
    }
    require(efi, source, events)?;
    let result = operation(events);
    let closing = require(efi, source, events);
    match (result, closing) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(closing)) => Err(bad(&format!(
            "{error}; live EFI source closing proof also failed:{closing}"
        ))),
    }
}
/// Native BCD query APIs may update the hive they open. Query only a disposable
/// B copied from a held pristine A on J; never query the live EFI store here.
pub(super) fn enum_available_store(
    efi: &EfiIdentity,
    pin: &StorePin,
    source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
    tool: &native::Tool,
    directory: &Path,
    journal: &GeneralJournalStorageBinding,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>>>
{
    budget.validate()?;
    with_live_source(efi, source, events, |events| {
        need(
            pin.bytes > 0 && pin.bytes <= budget.maximum_store_bytes,
            "available BCD query exceeds admitted store bytes",
        )?;
        let ordinal = LIVE_QUERY_ORDINAL
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_add(1),
            )
            .map_err(|_| bad("available BCD query ordinal overflow"))?;
        let parent = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(directory)?;
        let parent_guid = crate::file_storage::final_path_guid(&parent)?;
        let prefix = format!("{}\\", journal.disk.volume_path()?.trim_end_matches('\\'));
        need(
            parent.metadata()?.is_dir()
                && parent.metadata()?.file_attributes() & 0x400 == 0
                && parent_guid
                    .get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(&prefix)),
            "available BCD query directory is not actual ordinary J",
        )?;
        let pending = pin
            .bytes
            .checked_add(65535)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| bad("available BCD query reservation overflow"))?;
        native::owned_control_usage(directory, budget.maximum_control_bytes, pending)?;
        let copy_a = directory.join(format!("available-query-pristine-A-{ordinal:04}.bcd"));
        let copy_b = directory.join(format!("available-query-disposable-B-{ordinal:04}.bcd"));
        need(
            raw_copy_bound(
                efi,
                pin,
                &copy_a,
                budget.maximum_store_bytes,
                budget.maximum_control_bytes,
                None,
                true,
                events,
            )? == pin.sha256,
            "available BCD pristine A differs from actual pinned EFI epoch",
        )?;
        let mut pristine = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&copy_a)?;
        crate::file_storage::require_readonly_access(&pristine)?;
        let a_before = crate::reference_file::observe_reference_file_handle_with_limit(
            &pristine,
            budget.maximum_store_bytes,
        )?;
        need(
            a_before.file_bytes == pin.bytes
                && a_before.number_of_links == 1
                && a_before
                    .final_path
                    .get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
                && crate::sha256_native::hash_range(&mut pristine, 0, pin.bytes)? == pin.sha256,
            "held available BCD pristine A identity/bytes differ",
        )?;
        copy_authenticated_held(&mut pristine, pin.sha256, &copy_b, journal, budget)?;
        let mut query = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x00200000)
            .open(&copy_b)?;
        let b_before = crate::reference_file::observe_reference_file_handle_with_limit(
            &query,
            budget.maximum_store_bytes,
        )?;
        need(
            b_before.file_bytes == pin.bytes
                && b_before.number_of_links == 1
                && b_before.volume_serial_number == a_before.volume_serial_number
                && crate::sha256_native::hash_range(&mut query, 0, pin.bytes)? == pin.sha256,
            "disposable available BCD query B did not start as exact A",
        )?;
        drop(query);
        // The only native query target is the separately enrolled J copy B.
        let queried = tool.enum_all(&copy_b, directory);
        let closing = (|| -> io::Result<()> {
            let mut query = OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x00200000)
                .open(&copy_b)?;
            let b_after = crate::reference_file::observe_reference_file_handle_with_limit(
                &query,
                budget.maximum_store_bytes,
            )?;
            need(
                b_after.file_id_128 == b_before.file_id_128
                    && b_after.volume_serial_number == b_before.volume_serial_number
                    && b_after.final_path == b_before.final_path
                    && b_after.file_bytes == b_before.file_bytes
                    && b_after.number_of_links == 1,
                "native query replaced available BCD B or changed its bounded EOF",
            )?;
            let b_after_sha256 =
                crate::sha256_native::hash_range(&mut query, 0, b_after.file_bytes)?;
            need(
                crate::reference_file::observe_reference_file_handle_with_limit(
                    &pristine,
                    budget.maximum_store_bytes,
                )? == a_before
                    && crate::sha256_native::hash_range(&mut pristine, 0, pin.bytes)? == pin.sha256,
                "available BCD pristine A changed during disposable query",
            )?;
            need(
                raw_hash_bound(efi, pin, budget.maximum_control_bytes, None, true, events)?
                    == pin.sha256,
                "actual live EFI BCD epoch changed during disposable J query",
            )?;
            native::owned_control_usage(directory, budget.maximum_control_bytes, 0)?;
            native::persist(
                &directory.join(format!("available-query-{ordinal:04}.json")),
                &serde_json::json!({"kind":"actual-available-BCD-pristine-A-disposable-B-query-v1",
                    "actual_EFI_BCD_path":efi.bcd_path,"actual_store":pin,
                    "pristine_A_path":copy_a,"pristine_A_snapshot":a_before,"pristine_A_sha256":pin.sha256,
                    "query_B_path":copy_b,"query_B_before":b_before,"query_B_after":b_after,
                    "query_B_sha256_before":pin.sha256,"query_B_sha256_after":b_after_sha256,
                    "query_B_mutated_by_native_query":b_after_sha256!=pin.sha256,
                    "query_B_never_used_as_source_or_pristine_bytes":true,
                    "native_query_succeeded":queried.is_ok(),"live_EFI_query_calls":0,
                    "source_raw_hash_and_FAT_bookends_equal":true,"record_grants_authority":false}),
                budget.maximum_control_bytes,
            )?;
            Ok(())
        })();
        match (queried, closing) {
            (Ok(objects), Ok(())) => Ok(objects),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(closing)) => Err(bad(&format!(
                "disposable BCD query:{error}; closing:{closing}"
            ))),
        }
    })
}
pub(super) fn require_live_boot_epoch(
    efi: &EfiIdentity,
    first: &StorePin,
    second: &StorePin,
    source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
    metadata_limit: u64,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    with_live_source(efi, source, events, |events| {
        let mut file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", efi.binding.disk_number),
            false,
            false,
        )?;
        let opening = physical_binding_bound(&mut file, efi, None, events)?;
        let observed = fat::require_live_boot(
            &mut file,
            efi,
            first.fat_boot_sha256,
            second.fat_boot_sha256,
            metadata_limit,
        )?;
        need(
            physical_binding_bound(&mut file, efi, None, events)? == opening,
            "live EFI boot fingerprint physical binding changed",
        )?;
        events.push(NativeEvent{operation:"closed-available-EFI-full-sector-dirty-flag-proof".into(),
            control_code:0,input:Vec::new(),succeeded:true,native_error:None,
            output:serde_json::to_vec(&serde_json::json!({"first_full_sector_sha256":hex::encode(first.fat_boot_sha256),
                "second_full_sector_sha256":hex::encode(second.fat_boot_sha256),
                "observed_full_sector_sha256":hex::encode(observed),"only_runtime_dirty_bit_may_differ":true,
                "source_actual_attributes":0,"source_write_authority":false})).map_err(io::Error::other)?});
        Ok(())
    })
}
pub(super) fn require_live_file_map(
    efi: &EfiIdentity,
    current: &StorePin,
    expected: &StorePin,
    source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
    metadata_limit: u64,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    need(
        current.same_file_map_storage(expected),
        "current published EFI BCD file mapping changed",
    )?;
    require_live_boot_epoch(efi, current, expected, source, metadata_limit, events)
}
pub(super) fn fresh_external(
    directory: &Path,
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    need(
        directory.is_absolute() && !directory.exists(),
        "fresh absolute external boot directory required",
    )?;
    let parent = directory
        .parent()
        .ok_or_else(|| bad("boot directory parent absent"))?;
    for item in parent.ancestors() {
        let m = std::fs::symlink_metadata(item)?;
        need(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "ordinary boot output ancestry required",
        )?;
    }
    let destination = super::super::partition_isolation::metadata_destination_outside_source(
        source, parent, events,
    )?;
    need(
        destination.disk_number == journal.disk.disk_number
            && destination.offset == journal.disk.identity.partition_offset
            && destination.length == journal.disk.identity.partition_bytes
            && journal.disk.disk_number != source.storage.disk_number,
        "boot records must be on actual separately enrolled J",
    )?;
    let available = crate::resource_native::observe_available_resources(parent)?;
    let required = budget
        .maximum_store_bytes
        .checked_mul(2)
        .and_then(|v| v.checked_add(budget.maximum_control_bytes))
        .and_then(|v| v.checked_add(budget.minimum_free_bytes))
        .ok_or_else(|| bad("boot storage reservation overflow"))?;
    need(
        available.available_physical_bytes >= budget.ram_bytes
            && available.scratch_available_bytes >= required,
        "boot resources unavailable",
    )?;
    std::fs::create_dir(directory)?;
    Ok(())
}
struct Enumeration(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Enumeration {
    fn drop(&mut self) {
        unsafe {
            FindVolumeClose(self.0);
        }
    }
}
pub(super) fn system_efi(
    source: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<EfiIdentity> {
    let roles = super::super::partition_storage_roles::observe_partition_storage_roles(
        source, budget, events,
    )?;
    let efi = layout::guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")?;
    let rows: Vec<_> = roles
        .critical_partitions
        .iter()
        .filter(|v| v.role.is_system && v.role.gpt_type == efi)
        .collect();
    need(
        roles.catalog_complete
            && rows.len() == 1
            && rows[0].role.disk_number == source.storage.disk_number
            && roles
                .current_windows
                .as_ref()
                .is_some_and(|current| current.role.disk_number == source.storage.disk_number),
        "alpha requires unique native same-disk system EFI/current Windows",
    )?;
    let row = rows[0];
    let mut name = [0u16; 1024];
    let handle = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let enumeration = Enumeration(handle);
    let mut found = None;
    let mut complete = false;
    for _ in 0..budget.ram_bytes / 4096 {
        let n = name
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| bad("EFI volume GUID unterminated"))?;
        let value = String::from_utf16(&name[..n]).map_err(io::Error::other)?;
        need(
            value.len() == 49 && value.starts_with(r"\\?\Volume{") && value.ends_with("}\\"),
            "native EFI volume catalog malformed",
        )?;
        let file = device_file(value.trim_end_matches('\\'), false, false)?;
        let device = control(
            &file,
            "recovery-boot-EFI-volume-native-device",
            DEVICE,
            &[],
            12,
            events,
        )?;
        if device.len() == 12
            && layout::u32_at(&device, 4)? == row.role.disk_number
            && layout::u32_at(&device, 8)? == row.role.partition_number
        {
            let info = control(
                &file,
                "recovery-boot-EFI-native-partition",
                0x0007_0048,
                &[],
                144,
                events,
            )?;
            let ext = control(
                &file,
                "recovery-boot-EFI-native-extents",
                VOLUME_EXTENTS,
                &[],
                32,
                events,
            )?;
            need(
                info == row.native_partition_info
                    && ext.len() == 32
                    && layout::u32_at(&ext, 0)? == 1
                    && layout::u32_at(&ext, 8)? == row.role.disk_number
                    && layout::u64_at(&ext, 16)? == row.role.offset
                    && layout::u64_at(&ext, 24)? == row.role.size
                    && found.is_none(),
                "actual system EFI volume identity ambiguous",
            )?;
            let mut binding = source.storage.clone();
            binding.volume_guid = value[11..47].into();
            binding.identity.partition_guid = guid(&row.role.guid)?.trim_matches(['{', '}']).into();
            binding.identity.partition_number = row.role.partition_number;
            binding.identity.partition_offset = row.role.offset;
            binding.identity.partition_bytes = row.role.size;
            binding.validate()?;
            found = Some(EfiIdentity {
                binding,
                native_partition_info: info,
                bcd_path: PathBuf::from(&value).join(r"EFI\Microsoft\Boot\BCD"),
            });
        }
        drop(file);
        name.fill(0);
        if unsafe { FindNextVolumeW(enumeration.0, name.as_mut_ptr(), name.len() as u32) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(18) {
                complete = true;
                break;
            }
            return Err(error);
        }
    }
    need(complete, "complete native EFI volume catalog required")?;
    found.ok_or_else(|| bad("actual system EFI GUID volume unavailable"))
}
fn legacy_identity(file: &File) -> io::Result<(Vec<u8>, u64)> {
    let mut data = [0u32; 13];
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), data.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    need(
        data[0] & 0x410 == 0 && data[10] == 1,
        "actual ordinary single-link non-reparse BCD file required",
    )?;
    let mut identity = Vec::new();
    for i in [0, 7, 10, 11, 12] {
        identity.extend_from_slice(&data[i].to_le_bytes());
    }
    Ok((identity, (u64::from(data[8]) << 32) | u64::from(data[9])))
}
static ACTIVE_CAPTURE_ORDINAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn preserve_capture_events(
    directory: &Path,
    ordinal: u64,
    phase: &str,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    native::persist(
        &directory.join(format!(
            "active-capture-{ordinal:04}-{phase}-native-events.json"
        )),
        &serde_json::json!({"kind":"actual-active-hive-capture-native-events-v1","phase":phase,"events":&*events}),
        budget.maximum_control_bytes,
    )?;
    // Only successful same-file flush/readback above permits a drain.
    events.clear();
    Ok(())
}
pub(super) fn capture_store(
    efi: &EfiIdentity,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<StorePin> {
    capture_store_inner(efi, budget, None, false, events)
}
pub(super) fn capture_store_live(
    efi: &EfiIdentity,
    budget: RecoveryBootBudget,
    source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
    events: &mut Vec<NativeEvent>,
) -> io::Result<StorePin> {
    with_live_source(efi, source, events, |events| {
        capture_store_inner(efi, budget, None, true, events)
    })
}
/// Explicit current-SYSTEM capture. Only genuine sharing32 may select the
/// observed attribute-only lane; native semantic + physical proofs replace
/// unavailable logical file reads, never a caller flag or unexplained bypass.
pub(super) fn capture_active_store(
    efi: &EfiIdentity,
    budget: RecoveryBootBudget,
    tool: &native::Tool,
    directory: &Path,
    events: &mut Vec<NativeEvent>,
) -> io::Result<StorePin> {
    let ordinal = ACTIVE_CAPTURE_ORDINAL
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |v| v.checked_add(1),
        )
        .map_err(|_| bad("active BCD capture ordinal overflow"))?;
    preserve_capture_events(directory, ordinal, "opening", budget, events)?;
    let result = capture_store_inner(efi, budget, Some((tool, directory, ordinal)), false, events);
    let drained = preserve_capture_events(directory, ordinal, "closing", budget, events);
    match (result, drained) {
        (Ok(pin), Ok(())) => Ok(pin),
        (Err(original), _) => Err(original),
        (Ok(_), Err(error)) => Err(error),
    }
}
fn capture_store_inner(
    efi: &EfiIdentity,
    budget: RecoveryBootBudget,
    active: Option<(&native::Tool, &Path, u64)>,
    live: bool,
    events: &mut Vec<NativeEvent>,
) -> io::Result<StorePin> {
    let context = efi.bcd_path.to_string_lossy();
    let mut phase = "enable-SeManageVolumePrivilege";
    let mut privilege = native::diagnose(
        crate::attestation_native::Privileges::enable_for(&["SeManageVolumePrivilege"]),
        "boot-store-capture-failed",
        phase,
        &context,
        events,
    )?;
    let result = (|| {
        phase = "CreateFileW-GENERIC_READ-share3-OPEN_REPARSE_POINT";
        let opened = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(&efi.bcd_path);
        let (mut file, has_read_data) = match opened {
            Ok(file) => (file, true),
            Err(error) if error.raw_os_error() == Some(32) && active.is_some() => {
                let _ = native::diagnose::<()>(
                    Err(error),
                    "boot-store-active-hive-read-data-sharing-refusal",
                    phase,
                    &context,
                    events,
                );
                phase = "CreateFileW-FILE_READ_ATTRIBUTES-share3-OPEN_REPARSE_POINT";
                (
                    OpenOptions::new()
                        .access_mode(0x80)
                        .share_mode(3)
                        .custom_flags(0x0020_0000)
                        .open(&efi.bcd_path)?,
                    false,
                )
            }
            Err(error) => return Err(error),
        };
        phase = "GetFileInformationByHandle-actual-held-BCD";
        let (identity, bytes) = legacy_identity(&file)?;
        phase = "validate-actual-BCD-EOF-and-capacity";
        need(
            bytes >= 4096 && bytes.is_multiple_of(4096) && bytes <= budget.maximum_store_bytes,
            "native BCD store EOF outside admitted alpha bounds",
        )?;
        phase = "CreateFileW-actual-EFI-volume-GENERIC_READ-share3";
        let volume = device_file(&efi.binding.volume_path()?, false, false)?;
        phase = "query-actual-EFI-native144";
        let info = control(
            &volume,
            "boot-store-EFI-native-partition",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        phase = "query-actual-EFI-extents";
        let ext = control(
            &volume,
            "boot-store-EFI-native-extents",
            VOLUME_EXTENTS,
            &[],
            32,
            events,
        )?;
        phase = "validate-EFI-native144-and-extents";
        efi.binding.validate_volume_extent(&ext)?;
        need(
            info == efi.native_partition_info,
            "actual EFI mapping changed",
        )?;
        let root = format!("{}\\", efi.binding.volume_path()?);
        let (mut sectors, mut sector, mut free, mut total) = (0, 0, 0, 0);
        phase = "GetDiskFreeSpaceW-actual-EFI-volume";
        if unsafe {
            GetDiskFreeSpaceW(
                wide(&root).as_ptr(),
                &mut sectors,
                &mut sector,
                &mut free,
                &mut total,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        need(
            sector == efi.binding.identity.logical_sector_bytes && sectors > 0,
            "EFI filesystem allocation geometry unknown",
        )?;
        let cluster_bytes = u64::from(sectors)
            .checked_mul(u64::from(sector))
            .ok_or_else(|| bad("EFI allocation size overflow"))?;
        phase = "query-FAT-cluster-heap-base";
        let base = control(
            &volume,
            "boot-store-FAT-cluster-heap-sector-base",
            0x0009_0234,
            &[],
            8,
            events,
        )?;
        need(base.len() == 8, "FAT cluster heap base missing")?;
        let file_area_bytes = layout::u64_at(&base, 0)?
            .checked_mul(u64::from(sector))
            .ok_or_else(|| bad("EFI file area offset overflow"))?;
        phase = "FSCTL_GET_RETRIEVAL_POINTERS-actual-held-BCD";
        let pointers = control(
            &file,
            "boot-store-actual-file-retrieval-pointers",
            0x0009_0073,
            &[0; 8],
            65536,
            events,
        )?;
        phase = "validate-complete-BCD-retrieval-map";
        need(
            pointers.len() >= 16 && layout::u64_at(&pointers, 8)? == 0,
            "complete initial BCD retrieval mapping required",
        )?;
        let count = layout::u32_at(&pointers, 0)? as usize;
        need(
            count > 0 && pointers.len() == 16 + 16 * count,
            "complete bounded BCD retrieval map required",
        )?;
        let (mut vcn, mut covered) = (0u64, 0u64);
        let mut spans = Vec::new();
        for i in 0..count {
            let at = 16 + 16 * i;
            let next = layout::u64_at(&pointers, at)?;
            let lcn = layout::u64_at(&pointers, at + 8)?;
            need(
                next > vcn && lcn <= i64::MAX as u64,
                "BCD sparse/negative/overlapping retrieval row refused",
            )?;
            let logical = vcn
                .checked_mul(cluster_bytes)
                .ok_or_else(|| bad("BCD VCN overflow"))?;
            let allocation = (next - vcn)
                .checked_mul(cluster_bytes)
                .ok_or_else(|| bad("BCD retrieval length overflow"))?;
            if logical < bytes {
                let n = allocation.min(bytes - logical);
                let relative = file_area_bytes
                    .checked_add(
                        lcn.checked_mul(cluster_bytes)
                            .ok_or_else(|| bad("BCD LCN overflow"))?,
                    )
                    .ok_or_else(|| bad("BCD file-area addition overflow"))?;
                need(
                    logical == covered
                        && relative
                            .checked_add(n)
                            .is_some_and(|end| end <= efi.binding.identity.partition_bytes),
                    "BCD retrieval escapes actual EFI partition",
                )?;
                spans.push(RawSpan {
                    file_offset: logical,
                    physical_offset: efi
                        .binding
                        .identity
                        .partition_offset
                        .checked_add(relative)
                        .ok_or_else(|| bad("BCD physical base overflow"))?,
                    bytes: n,
                });
                covered += n;
            }
            vcn = next;
        }
        need(
            covered == bytes,
            "BCD physical mappings do not cover exact EOF",
        )?;
        phase = "hash-actual-held-BCD-logical-bytes-opening";
        let logical_sha256 = if has_read_data {
            Some(crate::sha256_native::hash_range(&mut file, 0, bytes)?)
        } else {
            None
        };
        let sha256 = logical_sha256.unwrap_or([0; 32]);
        phase = "CreateFileW-actual-EFI-physical-readonly-share3";
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", efi.binding.disk_number),
            false,
            false,
        )?;
        phase = "validate-actual-EFI-physical-native-binding";
        physical_binding(&physical, efi, events)?;
        phase = "hash-actual-EFI-FAT-boot-sector";
        let fat_boot_sha256 = fat::boot_sha(&mut physical, efi)?;
        let mut pin = StorePin {
            bytes,
            sha256,
            identity,
            spans,
            cluster_bytes,
            file_area_bytes,
            fat_boot_sha256,
        };
        if let Some(sha256) = logical_sha256 {
            phase = "hash-current-FAT-namespace-and-raw-BCD-bytes";
            let raw = raw_hash_bound(efi, &pin, budget.maximum_control_bytes, None, live, events)?;
            // Keep the original short-circuit order/checks: later native reads
            // occur only when every preceding comparison already passed.
            let same = if raw == sha256 {
                phase = "hash-actual-held-BCD-logical-bytes-closing";
                if crate::sha256_native::hash_range(&mut file, 0, bytes)? == sha256 {
                    phase = "GetFileInformationByHandle-actual-held-BCD-closing";
                    legacy_identity(&file)? == (pin.identity.clone(), bytes)
                } else {
                    false
                }
            } else {
                false
            };
            phase = "validate-logical-raw-and-native-identity-bookends";
            need(same, "actual logical/raw BCD bytes or identity differ")?;
        } else {
            let (tool, directory, ordinal) = active.ok_or_else(|| {
                bad("attribute-only BCD capture lacks actual native semantic authority")
            })?;
            phase = "active-hive-current-FAT-raw-hash-opening";
            let raw_before = raw_hash(efi, &pin, budget.maximum_control_bytes, events)?;
            pin.sha256 = raw_before;
            phase = "active-hive-bound-raw-copy-capacity";
            // Pre-admit immutable A plus a full maximum-store window for
            // disposable B. Existing .bcd copies share the same two-store cap.
            let mut used = bytes
                .checked_add(budget.maximum_store_bytes)
                .ok_or_else(|| bad("pristine/query BCD reservation overflow"))?;
            let census = native::owned_control_usage(directory, budget.maximum_control_bytes, 0)?;
            used = used
                .checked_add(census.stores)
                .ok_or_else(|| bad("aggregate BCD allocation overflow"))?;
            need(
                used <= budget
                    .maximum_store_bytes
                    .checked_mul(2)
                    .ok_or_else(|| bad("BCD metadata reserve overflow"))?,
                "actual raw/backup BCD copies exceed existing two-store metadata reservation",
            )?;
            let copy_a = directory.join(format!("active-hive-pristine-{ordinal:04}.bcd"));
            let copy_b = directory.join(format!("active-hive-query-{ordinal:04}.bcd"));
            phase = "active-hive-current-FAT-namespace-bound-pristine-A-copy";
            need(
                raw_copy(
                    efi,
                    &pin,
                    &copy_a,
                    budget.maximum_store_bytes,
                    budget.maximum_control_bytes,
                    events,
                )? == raw_before,
                "active hive pristine A differs from opening actual physical hash",
            )?;
            // A remains immutable and is NEVER passed to BcdEdit. A normal
            // read handle with share-read only denies ordinary write/delete.
            let mut pristine = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x00200000)
                .open(&copy_a)?;
            let pristine_snapshot =
                crate::reference_file::observe_reference_file_handle_with_limit(
                    &pristine,
                    budget.maximum_store_bytes,
                )?;
            need(
                pristine_snapshot.file_bytes == bytes
                    && pristine_snapshot.number_of_links == 1
                    && crate::sha256_native::hash_range(&mut pristine, 0, bytes)? == raw_before,
                "held pristine A native identity/bytes differ",
            )?;
            phase = "active-hive-pristine-A-to-disposable-query-B-copy";
            pristine.seek(SeekFrom::Start(0))?;
            {
                let mut query = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(1)
                    .create_new(true)
                    .open(&copy_b)?;
                let mut buffer = [0u8; 65536];
                let mut left = bytes;
                while left > 0 {
                    let n = left.min(buffer.len() as u64) as usize;
                    pristine.read_exact(&mut buffer[..n])?;
                    query.write_all(&buffer[..n])?;
                    left -= n as u64;
                }
                query.sync_all()?;
                need(
                    query.metadata()?.len() == bytes
                        && crate::sha256_native::hash_range(&mut query, 0, bytes)? == raw_before,
                    "disposable B durable copy differs from immutable A",
                )?;
            }
            // B is deliberately mutable scratch for Microsoft's query API.
            // Do not retain a sharing-excluding handle across its hive load.
            let mut query = OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x00200000)
                .open(&copy_b)?;
            let query_before = crate::reference_file::observe_reference_file_handle_with_limit(
                &query,
                budget.maximum_store_bytes,
            )?;
            let query_before_sha256 =
                crate::sha256_native::hash_range(&mut query, 0, query_before.file_bytes)?;
            need(
                query_before.file_bytes == bytes && query_before_sha256 == raw_before,
                "query B did not start as the exact pristine snapshot",
            )?;
            native::register_owned_query_store(
                &query,
                &copy_b,
                budget.maximum_store_bytes,
                budget.maximum_control_bytes,
            )?;
            drop(query);
            phase = "active-hive-native-complete-current-system-enum-all";
            let current = tool.enum_system_all(directory)?;
            phase = "active-hive-native-complete-disposable-B-enum-all";
            let raw_semantics = tool.enum_all(&copy_b, directory)?;
            need(
                current == raw_semantics,
                "current SYSTEM BCD and pristine-derived query B differ in complete native semantics",
            )?;
            phase = "active-hive-disposable-query-B-native-identity-and-hash-observation";
            let mut query = OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x00200000)
                .open(&copy_b)?;
            let query_after = crate::reference_file::observe_reference_file_handle_with_limit(
                &query,
                budget.maximum_store_bytes,
            )?;
            need(
                query_after.file_id_128 == query_before.file_id_128
                    && query_after.volume_serial_number == query_before.volume_serial_number
                    && query_after.final_path == query_before.final_path
                    && query_after.file_bytes == query_before.file_bytes
                    && query_after.number_of_links == 1,
                "native query replaced B or changed its bounded file identity/EOF",
            )?;
            let query_after_sha256 =
                crate::sha256_native::hash_range(&mut query, 0, query_after.file_bytes)?;
            // Native /enum may update B's REGF bytes. Such mutation is data
            // about disposable B, never a source/pristine hash equality claim.
            phase = "active-hive-pristine-A-immutable-native-and-byte-bookend";
            need(
                crate::reference_file::observe_reference_file_handle_with_limit(
                    &pristine,
                    budget.maximum_store_bytes,
                )? == pristine_snapshot
                    && crate::sha256_native::hash_range(&mut pristine, 0, bytes)? == raw_before,
                "held pristine A changed during native semantic query",
            )?;
            phase = "active-hive-current-FAT-raw-hash-closing";
            need(
                raw_hash(efi, &pin, budget.maximum_control_bytes, events)? == raw_before
                    && legacy_identity(&file)? == (pin.identity.clone(), bytes),
                "active hive physical/FAT/held metadata changed across native semantic check",
            )?;
            native::persist(
                &directory.join(format!("active-hive-capture-{ordinal:04}.json")),
                &serde_json::json!({"kind":"actual-active-BCD-attribute-only-raw-capture-v1",
                    "actual_EFI_BCD_path":efi.bcd_path,"metadata_desired_access":128,"share_mode":3,
                    "source_file_read_data_available":false,"source_file_data_read_calls":0,
                    "pristine_A_path":copy_a,"pristine_A_snapshot":pristine_snapshot,
                    "pristine_A_sha256":raw_before,"pristine_A_share_read_only_held":true,
                    "query_B_path":copy_b,"query_B_before":query_before,"query_B_after":query_after,
                    "query_B_sha256_before":query_before_sha256,"query_B_sha256_after":query_after_sha256,
                    "query_B_mutated_by_native_query":query_before_sha256!=query_after_sha256,
                    "query_B_never_used_as_pristine_source_bytes":true,
                    "raw_store":pin,"complete_native_system_and_pristine_derived_B_semantics_equal":true,
                    "native_objects_compared":current.len(),"physical_raw_hashes_and_current_FAT_map_equal":true,
                    "actual_held_legacy52_EOF_identity_equal":true,"record_grants_authority":false}),
                budget.maximum_control_bytes,
            )?;
        }
        Ok(pin)
    })();
    let result = native::diagnose(result, "boot-store-capture-failed", phase, &context, events);
    let restored = native::diagnose(
        privilege.restore(),
        "boot-store-capture-privilege-restore-failed",
        "restore-SeManageVolumePrivilege",
        &context,
        events,
    );
    match (result, restored) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}
pub(super) fn raw_hash(
    efi: &EfiIdentity,
    pin: &StorePin,
    metadata_limit: u64,
    events: &mut Vec<NativeEvent>,
) -> io::Result<[u8; 32]> {
    raw_hash_bound(efi, pin, metadata_limit, None, false, events)
}
pub(super) fn raw_hash_live(
    efi: &EfiIdentity,
    pin: &StorePin,
    metadata_limit: u64,
    source: &mut crate::offline_environment::OfflinePreparedAvailableSource,
    events: &mut Vec<NativeEvent>,
) -> io::Result<[u8; 32]> {
    with_live_source(efi, source, events, |events| {
        raw_hash_bound(efi, pin, metadata_limit, None, true, events)
    })
}
pub(super) fn raw_hash_protected(
    efi: &EfiIdentity,
    pin: &StorePin,
    metadata_limit: u64,
    witness: &OfflineBootMetadataWitness,
    owner: &crate::offline_environment::OfflineSourceOwnerToken,
    events: &mut Vec<NativeEvent>,
) -> io::Result<[u8; 32]> {
    raw_hash_bound(
        efi,
        pin,
        metadata_limit,
        Some((witness, owner)),
        false,
        events,
    )
}
fn raw_hash_bound(
    efi: &EfiIdentity,
    pin: &StorePin,
    metadata_limit: u64,
    protected: Option<ProtectedBootBinding<'_>>,
    live: bool,
    events: &mut Vec<NativeEvent>,
) -> io::Result<[u8; 32]> {
    need(
        !live || protected.is_none(),
        "protected EFI metadata cannot select live runtime state",
    )?;
    let mut file = device_file(
        &format!("\\\\.\\PhysicalDrive{}", efi.binding.disk_number),
        false,
        false,
    )?;
    let opening = physical_binding_bound(&mut file, efi, protected, events)?;
    current_map(&mut file, efi, pin, metadata_limit, live).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("raw BCD opening FAT namespace: {error}"),
        )
    })?;
    let mut hash = sha2::Sha256::new();
    let mut buffer = [0; 65536];
    let mut covered = 0;
    let end = efi
        .binding
        .identity
        .partition_offset
        .checked_add(efi.binding.identity.partition_bytes)
        .ok_or_else(|| bad("EFI extent overflow"))?;
    for span in &pin.spans {
        need(
            span.file_offset == covered
                && span.physical_offset >= efi.binding.identity.partition_offset
                && span.bytes > 0
                && span
                    .physical_offset
                    .checked_add(span.bytes)
                    .is_some_and(|n| n <= end)
                && covered
                    .checked_add(span.bytes)
                    .is_some_and(|n| n <= pin.bytes),
            "pinned raw BCD span escapes EFI/EOF",
        )?;
        file.seek(SeekFrom::Start(span.physical_offset))?;
        let mut left = span.bytes;
        while left > 0 {
            let n = left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..n])?;
            hash.update(&buffer[..n]);
            left -= n as u64;
        }
        covered += span.bytes;
    }
    need(covered == pin.bytes, "raw BCD EOF coverage differs")?;
    current_map(&mut file, efi, pin, metadata_limit, live).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("raw BCD closing FAT namespace: {error}"),
        )
    })?;
    need(
        physical_binding_bound(&mut file, efi, protected, events)? == opening,
        "same raw BCD physical handle metadata changed",
    )?;
    Ok(hash.finalize().into())
}
pub(super) fn require_cold_efi(
    efi: &EfiIdentity,
    state: &crate::offline_environment::OfflineSourceState,
) -> io::Result<()> {
    need(
        state.disk_offline_in_current_environment,
        "boot EFI requires the actual excluded source disk",
    )?;
    require_source_efi_identity(efi, state)
}
fn require_source_efi_identity(
    efi: &EfiIdentity,
    state: &crate::offline_environment::OfflineSourceState,
) -> io::Result<()> {
    let binding = &state.binding.storage;
    let e = &efi.binding;
    need(
        e.disk_number == binding.disk_number
            && e.identity.disk_guid == binding.identity.disk_guid
            && e.identity.disk_bytes == binding.identity.disk_bytes
            && e.identity.logical_sector_bytes == binding.identity.logical_sector_bytes
            && e.identity.partition_guid != binding.identity.partition_guid,
        "boot EFI is not on actual excluded source disk",
    )?;
    let rows = &state.actual.gpt.native_layout;
    need(
        rows.len() >= 48 && (rows.len() - 48).is_multiple_of(144),
        "actual source native GPT rows incomplete",
    )?;
    let id = layout::guid_bytes(&e.identity.partition_guid)?;
    let found: Vec<_> = rows[48..]
        .chunks_exact(144)
        .filter(|r| r[48..64] == id)
        .collect();
    need(
        found.len() == 1
            && found[0] == efi.native_partition_info
            && layout::u32_at(found[0], 0)? == 1
            && found[0][32..48] == layout::guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")?
            && layout::u64_at(found[0], 8)? == e.identity.partition_offset
            && layout::u64_at(found[0], 16)? == e.identity.partition_bytes
            && layout::u32_at(found[0], 24)? == e.identity.partition_number,
        "actual excluded-source EFI native identity differs",
    )
}
pub(super) fn raw_copy(
    efi: &EfiIdentity,
    pin: &StorePin,
    path: &Path,
    maximum: u64,
    metadata_limit: u64,
    events: &mut Vec<NativeEvent>,
) -> io::Result<[u8; 32]> {
    raw_copy_bound(efi, pin, path, maximum, metadata_limit, None, false, events)
}
pub(super) fn raw_copy_protected(
    efi: &EfiIdentity,
    pin: &StorePin,
    path: &Path,
    maximum: u64,
    metadata_limit: u64,
    witness: &OfflineBootMetadataWitness,
    owner: &crate::offline_environment::OfflineSourceOwnerToken,
    events: &mut Vec<NativeEvent>,
) -> io::Result<[u8; 32]> {
    raw_copy_bound(
        efi,
        pin,
        path,
        maximum,
        metadata_limit,
        Some((witness, owner)),
        false,
        events,
    )
}
fn current_map(
    file: &mut File,
    efi: &EfiIdentity,
    pin: &StorePin,
    limit: u64,
    live: bool,
) -> io::Result<()> {
    if live {
        fat::require_current_map_live(file, efi, pin, limit)
    } else {
        fat::require_current_map(file, efi, pin, limit)
    }
}
fn raw_copy_bound(
    efi: &EfiIdentity,
    pin: &StorePin,
    path: &Path,
    maximum: u64,
    metadata_limit: u64,
    protected: Option<ProtectedBootBinding<'_>>,
    live: bool,
    events: &mut Vec<NativeEvent>,
) -> io::Result<[u8; 32]> {
    need(
        !live || protected.is_none(),
        "protected EFI copy cannot select live runtime state",
    )?;
    need(
        pin.bytes <= maximum,
        "raw BCD copy exceeds admitted metadata bytes",
    )?;
    let mut source = device_file(
        &format!("\\\\.\\PhysicalDrive{}", efi.binding.disk_number),
        false,
        false,
    )?;
    let opening = physical_binding_bound(&mut source, efi, protected, events)?;
    current_map(&mut source, efi, pin, metadata_limit, live)?;
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(1)
        .create_new(true)
        .open(path)?;
    let mut hash = sha2::Sha256::new();
    let mut buffer = [0; 65536];
    let mut covered = 0;
    let efi_end = efi
        .binding
        .identity
        .partition_offset
        .checked_add(efi.binding.identity.partition_bytes)
        .ok_or_else(|| bad("EFI span overflow"))?;
    for span in &pin.spans {
        need(
            span.file_offset == covered
                && span.bytes > 0
                && span.physical_offset >= efi.binding.identity.partition_offset
                && span
                    .physical_offset
                    .checked_add(span.bytes)
                    .is_some_and(|n| n <= efi_end)
                && covered
                    .checked_add(span.bytes)
                    .is_some_and(|n| n <= pin.bytes),
            "raw copy BCD mapping escapes exact EFI/EOF window",
        )?;
        source.seek(SeekFrom::Start(span.physical_offset))?;
        let mut left = span.bytes;
        while left > 0 {
            let n = left.min(buffer.len() as u64) as usize;
            source.read_exact(&mut buffer[..n])?;
            output.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
            left -= n as u64;
        }
        covered += span.bytes;
    }
    need(covered == pin.bytes, "raw BCD copy EOF differs")?;
    current_map(&mut source, efi, pin, metadata_limit, live)?;
    need(
        physical_binding_bound(&mut source, efi, protected, events)? == opening,
        "same raw BCD copy physical metadata changed",
    )?;
    output.sync_all()?;
    let sha: [u8; 32] = hash.finalize().into();
    need(
        crate::sha256_native::hash_range(&mut output, 0, pin.bytes)? == sha,
        "raw BCD metadata copy readback differs",
    )?;
    native::register_owned_query_store(&output, path, maximum, metadata_limit)?;
    Ok(sha)
}
pub(super) fn read_external(
    path: &Path,
    journal: &GeneralJournalStorageBinding,
    maximum: u64,
) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let snapshot = crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    need(
        snapshot.number_of_links == 1
            && snapshot.file_bytes > 0
            && snapshot
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(journal.disk.volume_path()?.to_ascii_lowercase() + "\\")),
        "actual boot metadata is not on enrolled J",
    )?;
    let mut out = vec![0; usize::try_from(snapshot.file_bytes).map_err(io::Error::other)?];
    file.read_exact(&mut out)?;
    need(
        crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == snapshot,
        "actual held external boot metadata changed",
    )?;
    Ok(out)
}
pub(super) fn hash_external(
    path: &Path,
    journal: &GeneralJournalStorageBinding,
    maximum: u64,
) -> io::Result<[u8; 32]> {
    read_external(path, journal, maximum).map(|v| digest(&v))
}
pub(super) fn guid_external_path(
    path: &Path,
    journal: &GeneralJournalStorageBinding,
    maximum: u64,
) -> io::Result<PathBuf> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let pin = crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    need(
        pin.number_of_links == 1
            && pin
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(journal.disk.volume_path()?.to_ascii_lowercase() + "\\")),
        "actual external boot file GUID route not on J",
    )?;
    Ok(PathBuf::from(pin.final_path))
}
pub(super) fn bcd_image_routes(
    image: &OwnedRecoveryImage,
    options: &str,
) -> io::Result<(String, String, String)> {
    let wim = image
        .wim_path()
        .to_str()
        .ok_or_else(|| bad("Unicode WIM DOS path required"))?;
    let sdi = image
        .sdi_path()
        .to_str()
        .ok_or_else(|| bad("Unicode SDI DOS path required"))?;
    need(
        wim.len() > 3
            && sdi.len() > 3
            && wim.as_bytes()[0].is_ascii_alphabetic()
            && &wim[1..3] == ":\\"
            && sdi[..3].eq_ignore_ascii_case(&wim[..3]),
        "same ordinary native J DOS image routes required",
    )?;
    Ok((
        format!("ramdisk=[{}]\\{},{}", &wim[..2], &wim[3..], options),
        format!("partition={}", &wim[..2]),
        format!("\\{}", &sdi[3..]),
    ))
}

fn physical_binding(
    file: &File,
    efi: &EfiIdentity,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    physical_binding_native(file, efi, events)
}
fn physical_binding_bound(
    file: &mut File,
    efi: &EfiIdentity,
    protected: Option<ProtectedBootBinding<'_>>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    if let Some((witness, owner)) = protected {
        let actual = witness.verify_file(file, owner, events)?;
        let native = actual.gpt.native_layout;
        let id = layout::guid_bytes(&efi.binding.identity.partition_guid)?;
        need(
            actual.device.len() == 12
                && layout::u32_at(&actual.device, 4)? == efi.binding.disk_number
                && layout::u32_at(&actual.device, 8)? == 0
                && layout::u64_at(&actual.length, 0)? == efi.binding.identity.disk_bytes
                && native.len() >= 48
                && (native.len() - 48).is_multiple_of(144)
                && native[8..24] == layout::guid_bytes(&efi.binding.identity.disk_guid)?
                && native[48..]
                    .chunks_exact(144)
                    .filter(|r| r[48..64] == id && *r == efi.native_partition_info.as_slice())
                    .count()
                    == 1,
            "current raw BCD source/EFI differs from actual protected source witness",
        )?;
        return Ok(native);
    }
    physical_binding_native(file, efi, events)
}
fn physical_binding_native(
    file: &File,
    efi: &EfiIdentity,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    let device = control(
        file,
        "boot-raw-store-physical-DEVICE",
        DEVICE,
        &[],
        12,
        events,
    )?;
    let length = control(
        file,
        "boot-raw-store-physical-LENGTH",
        LENGTH,
        &[],
        8,
        events,
    )?;
    let native = control(
        file,
        "boot-raw-store-physical-GPT-layout",
        LAYOUT,
        &[],
        65536,
        events,
    )?;
    need(
        device.len() == 12
            && layout::u32_at(&device, 4)? == efi.binding.disk_number
            && layout::u32_at(&device, 8)? == 0
            && length.len() == 8
            && layout::u64_at(&length, 0)? == efi.binding.identity.disk_bytes
            && native.len() >= 48
            && (native.len() - 48).is_multiple_of(144)
            && layout::u32_at(&native, 0)? == 1
            && layout::u32_at(&native, 4)? as usize == (native.len() - 48) / 144
            && native[8..24] == layout::guid_bytes(&efi.binding.identity.disk_guid)?,
        "actual raw BCD physical device/length/GPT mismatch",
    )?;
    let id = layout::guid_bytes(&efi.binding.identity.partition_guid)?;
    let rows: Vec<_> = native[48..]
        .chunks_exact(144)
        .filter(|r| r[48..64] == id)
        .collect();
    need(
        rows.len() == 1 && rows[0] == efi.native_partition_info,
        "actual raw BCD EFI native row differs",
    )?;
    Ok(native)
}

/// Resolve CURRENT published EFI alias by positive native DEVICE/144B/extents.
/// The original Windows volume GUID is routing history, not a PE alias claim.
pub(super) fn available_efi(
    expected: &EfiIdentity,
    state: &crate::offline_environment::OfflineSourceState,
    memory_bytes: u64,
    ram_root: &str,
    ram_backing: &crate::native::offline_environment::kernel_ram_backing::KernelRamBackingFacts,
    events: &mut Vec<NativeEvent>,
) -> io::Result<EfiIdentity> {
    need(
        state.actual.disk_attributes == 0
            && !state.disk_offline_in_current_environment
            && state.binding.storage.disk_number == expected.binding.disk_number
            && state.binding.storage.identity.disk_guid == expected.binding.identity.disk_guid,
        "actual closed-terminal source disk must be available before EFI publication",
    )?;
    published_efi(
        expected,
        &state.actual.gpt.native_layout,
        memory_bytes,
        ram_root,
        ram_backing,
        events,
    )
}
/// The same resolution from the native layout of the EFI partition's disk
/// alone. Its callers say why that disk is available: a closed conversion's
/// source owner above, or the cancellation of one that never started.
pub(super) fn published_efi(
    expected: &EfiIdentity,
    rows: &[u8],
    memory_bytes: u64,
    ram_root: &str,
    ram_backing: &crate::native::offline_environment::kernel_ram_backing::KernelRamBackingFacts,
    events: &mut Vec<NativeEvent>,
) -> io::Result<EfiIdentity> {
    let id = layout::guid_bytes(&expected.binding.identity.partition_guid)?;
    need(
        rows.len() >= 48
            && (rows.len() - 48).is_multiple_of(144)
            && rows[48..]
                .chunks_exact(144)
                .filter(|r| r[48..64] == id && *r == expected.native_partition_info)
                .count()
                == 1,
        "actual available EFI native row differs from original boot intent",
    )?;
    let mut name = [0u16; 1024];
    let h = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let enumeration = Enumeration(h);
    let mut found = None;
    let mut complete = false;
    for _ in 0..memory_bytes / 4096 {
        let n = name
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| bad("EFI publication name unterminated"))?;
        let value = String::from_utf16(&name[..n]).map_err(io::Error::other)?;
        need(
            value.len() == 49 && value.starts_with(r"\\?\Volume{") && value.ends_with("}\\"),
            "current EFI publication catalog malformed",
        )?;
        let opened = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .open(value.trim_end_matches('\\'));
        let file = match opened {
            Ok(f) => Some(f),
            Err(e) if e.raw_os_error() == Some(21) => None,
            Err(e) => return Err(e),
        };
        if let Some(file) = file {
            let same_current_ram = matches!(
                crate::native::offline_environment::kernel_ram_backing::require_held(ram_root,&file),
                Ok(actual)if actual.positive_native_kernel_ramdisk&&actual==*ram_backing);
            if same_current_ram {
                need(
                    events.len() < crate::MAX_BATCH_EVENTS,
                    "terminal EFI publication native event budget exceeded",
                )?;
                events.push(NativeEvent {
                    operation: "terminal-boot-EFI-publication-current-kernel-RAM-nonsource".into(),
                    control_code: 0,
                    input: Vec::new(),
                    succeeded: true,
                    native_error: None,
                    output: serde_json::to_vec(&serde_json::json!({"path":&value,
                        "same_current_kernel_RAM_backing_verified":true,
                        "positive_native_kernel_ramdisk":true,
                        "grants_source_write_authority":false,"source_data_io":false}))
                    .map_err(io::Error::other)?,
                });
            } else {
                let device = control(
                    &file,
                    "terminal-boot-EFI-published-native-device",
                    DEVICE,
                    &[],
                    12,
                    events,
                );
                let device = match device {
                    Ok(v) => Some(v),
                    Err(e) if e.raw_os_error() == Some(21) => None,
                    Err(e) => return Err(e),
                };
                if let Some(device) = device {
                    if device.len() == 12
                        && layout::u32_at(&device, 0)? == 7
                        && layout::u32_at(&device, 4)? == expected.binding.disk_number
                        && layout::u32_at(&device, 8)? == expected.binding.identity.partition_number
                    {
                        let info = control(
                            &file,
                            "terminal-boot-EFI-published-native144",
                            0x00070048,
                            &[],
                            144,
                            events,
                        )?;
                        let ext = control(
                            &file,
                            "terminal-boot-EFI-published-extents",
                            VOLUME_EXTENTS,
                            &[],
                            32,
                            events,
                        )?;
                        expected.binding.validate_volume_extent(&ext)?;
                        need(
                            info == expected.native_partition_info && found.is_none(),
                            "actual EFI publication identity ambiguous",
                        )?;
                        let mut actual = expected.clone();
                        actual.binding.volume_guid = value[11..47].into();
                        actual.bcd_path = PathBuf::from(&value).join(r"EFI\Microsoft\Boot\BCD");
                        found = Some(actual);
                    }
                }
            }
        }
        name.fill(0);
        if unsafe { FindNextVolumeW(enumeration.0, name.as_mut_ptr(), name.len() as u32) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(18) {
                complete = true;
                break;
            }
            return Err(e);
        }
    }
    need(
        complete,
        "current published EFI catalog exceeds admitted bound",
    )?;
    found.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "actual available EFI volume not yet published",
        )
    })
}
/// Flush only the positively bound explicit EFI BCD, not a PE default hive.
pub(super) fn flush_explicit_store(efi: &EfiIdentity) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .custom_flags(0x00200000)
        .open(&efi.bcd_path)?;
    legacy_identity(&file)?;
    let actual = crate::file_storage::final_path_guid(&file)?;
    need(
        actual.eq_ignore_ascii_case(
            efi.bcd_path
                .to_str()
                .ok_or_else(|| bad("Unicode actual EFI BCD path required"))?,
        ),
        "explicit BCD flush file escaped actual EFI route",
    )?;
    file.sync_all()
}
