use super::*;
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
        self.bytes == other.bytes
            && self.identity == other.identity
            && self.spans == other.spans
            && self.cluster_bytes == other.cluster_bytes
            && self.file_area_bytes == other.file_area_bytes
            && self.fat_boot_sha256 == other.fat_boot_sha256
    }
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
            && roles.current_windows.role.disk_number == source.storage.disk_number,
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
static ACTIVE_CAPTURE_ORDINAL:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);
fn preserve_capture_events(directory:&Path,ordinal:u64,phase:&str,budget:RecoveryBootBudget,
    events:&mut Vec<NativeEvent>)->io::Result<()> {
    if events.is_empty(){return Ok(())}
    native::persist(&directory.join(format!("active-capture-{ordinal:04}-{phase}-native-events.json")),
        &serde_json::json!({"kind":"actual-active-hive-capture-native-events-v1","phase":phase,"events":&*events}),
        budget.maximum_control_bytes)?;
    // Only successful same-file flush/readback above permits a drain.
    events.clear();Ok(())
}
pub(super) fn capture_store(efi:&EfiIdentity,budget:RecoveryBootBudget,events:&mut Vec<NativeEvent>)->io::Result<StorePin>{
    capture_store_inner(efi,budget,None,events)
}
/// Explicit current-SYSTEM capture. Only genuine sharing32 may select the
/// observed attribute-only lane; native semantic + physical proofs replace
/// unavailable logical file reads, never a caller flag or unexplained bypass.
pub(super) fn capture_active_store(efi:&EfiIdentity,budget:RecoveryBootBudget,tool:&native::Tool,
    directory:&Path,events:&mut Vec<NativeEvent>)->io::Result<StorePin>{
    let ordinal=ACTIVE_CAPTURE_ORDINAL.fetch_update(std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,|v|v.checked_add(1)).map_err(|_|bad("active BCD capture ordinal overflow"))?;
    preserve_capture_events(directory,ordinal,"opening",budget,events)?;
    let result=capture_store_inner(efi,budget,Some((tool,directory,ordinal)),events);
    let drained=preserve_capture_events(directory,ordinal,"closing",budget,events);
    match(result,drained){(Ok(pin),Ok(()))=>Ok(pin),(Err(original),_)=>Err(original),(Ok(_),Err(error))=>Err(error)}
}
fn capture_store_inner(
    efi: &EfiIdentity,
    budget: RecoveryBootBudget,
    active:Option<(&native::Tool,&Path,u64)>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<StorePin> {
    let context=efi.bcd_path.to_string_lossy();
    let mut phase="enable-SeManageVolumePrivilege";
    let mut privilege=native::diagnose(
        crate::attestation_native::Privileges::enable_for(&["SeManageVolumePrivilege"]),
        "boot-store-capture-failed",phase,&context,events)?;
    let result = (|| {
        phase="CreateFileW-GENERIC_READ-share3-OPEN_REPARSE_POINT";
        let opened=OpenOptions::new().read(true).share_mode(3)
            .custom_flags(0x0020_0000).open(&efi.bcd_path);
        let (mut file,has_read_data)=match opened {
            Ok(file)=>(file,true),
            Err(error)if error.raw_os_error()==Some(32)&&active.is_some()=>{
                let _=native::diagnose::<()>(Err(error),"boot-store-active-hive-read-data-sharing-refusal",
                    phase,&context,events);
                phase="CreateFileW-FILE_READ_ATTRIBUTES-share3-OPEN_REPARSE_POINT";
                (OpenOptions::new().access_mode(0x80).share_mode(3)
                    .custom_flags(0x0020_0000).open(&efi.bcd_path)?,false)
            }
            Err(error)=>return Err(error),
        };
        phase="GetFileInformationByHandle-actual-held-BCD";
        let (identity, bytes) = legacy_identity(&file)?;
        phase="validate-actual-BCD-EOF-and-capacity";
        need(
            bytes >= 4096 && bytes.is_multiple_of(4096) && bytes <= budget.maximum_store_bytes,
            "native BCD store EOF outside admitted alpha bounds",
        )?;
        phase="CreateFileW-actual-EFI-volume-GENERIC_READ-share3";
        let volume = device_file(&efi.binding.volume_path()?, false, false)?;
        phase="query-actual-EFI-native144";
        let info = control(
            &volume,
            "boot-store-EFI-native-partition",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        phase="query-actual-EFI-extents";
        let ext = control(
            &volume,
            "boot-store-EFI-native-extents",
            VOLUME_EXTENTS,
            &[],
            32,
            events,
        )?;
        phase="validate-EFI-native144-and-extents";
        efi.binding.validate_volume_extent(&ext)?;
        need(
            info == efi.native_partition_info,
            "actual EFI mapping changed",
        )?;
        let root = format!("{}\\", efi.binding.volume_path()?);
        let (mut sectors, mut sector, mut free, mut total) = (0, 0, 0, 0);
        phase="GetDiskFreeSpaceW-actual-EFI-volume";
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
        phase="query-FAT-cluster-heap-base";
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
        phase="FSCTL_GET_RETRIEVAL_POINTERS-actual-held-BCD";
        let pointers = control(
            &file,
            "boot-store-actual-file-retrieval-pointers",
            0x0009_0073,
            &[0; 8],
            65536,
            events,
        )?;
        phase="validate-complete-BCD-retrieval-map";
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
        phase="hash-actual-held-BCD-logical-bytes-opening";
        let logical_sha256=if has_read_data{Some(crate::sha256_native::hash_range(&mut file,0,bytes)?)}else{None};
        let sha256=logical_sha256.unwrap_or([0;32]);
        phase="CreateFileW-actual-EFI-physical-readonly-share3";
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", efi.binding.disk_number),
            false,
            false,
        )?;
        phase="validate-actual-EFI-physical-native-binding";
        physical_binding(&physical, efi, events)?;
        phase="hash-actual-EFI-FAT-boot-sector";
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
        if let Some(sha256)=logical_sha256 {
            phase="hash-current-FAT-namespace-and-raw-BCD-bytes";
            let raw=raw_hash(efi,&pin,budget.maximum_control_bytes,events)?;
            // Keep the original short-circuit order/checks: later native reads
            // occur only when every preceding comparison already passed.
            let same=if raw==sha256 {
                phase="hash-actual-held-BCD-logical-bytes-closing";
                if crate::sha256_native::hash_range(&mut file,0,bytes)?==sha256 {
                    phase="GetFileInformationByHandle-actual-held-BCD-closing";
                    legacy_identity(&file)?==(pin.identity.clone(),bytes)
                }else{false}
            }else{false};
            phase="validate-logical-raw-and-native-identity-bookends";
            need(same,"actual logical/raw BCD bytes or identity differ")?;
        }else{
            let (tool,directory,ordinal)=active.ok_or_else(||bad("attribute-only BCD capture lacks actual native semantic authority"))?;
            phase="active-hive-current-FAT-raw-hash-opening";
            let raw_before=raw_hash(efi,&pin,budget.maximum_control_bytes,events)?;
            pin.sha256=raw_before;
            phase="active-hive-bound-raw-copy-capacity";
            let mut used=bytes;
            for entry in std::fs::read_dir(directory)?{
                let path=entry?.path();let metadata=std::fs::symlink_metadata(&path)?;
                need(metadata.is_file()&&metadata.file_attributes()&0x400==0,"ordinary owned active-BCD capture directory required")?;
                if path.extension().and_then(|v|v.to_str())==Some("bcd"){
                    used=used.checked_add(metadata.len()).ok_or_else(||bad("aggregate BCD metadata capacity overflow"))?;
                }
            }
            need(used<=budget.maximum_store_bytes.checked_mul(2).ok_or_else(||bad("BCD metadata reserve overflow"))?,
                "actual raw/backup BCD copies exceed existing two-store metadata reservation")?;
            let copy=directory.join(format!("active-hive-raw-{ordinal:04}.bcd"));
            phase="active-hive-current-FAT-namespace-bound-raw-copy";
            need(raw_copy(efi,&pin,&copy,budget.maximum_store_bytes,budget.maximum_control_bytes,events)?==raw_before,
                "active hive raw copy differs from opening actual physical hash")?;
            // The raw file is ordinary bounded J metadata. Attribute-only
            // source handle is NEVER read for data and is not claimed to be.
            let mut copied=OpenOptions::new().read(true).share_mode(3).custom_flags(0x00200000).open(&copy)?;
            let copy_before=crate::reference_file::observe_reference_file_handle_with_limit(&copied,budget.maximum_store_bytes)?;
            phase="active-hive-native-complete-current-system-enum-all";
            let current=tool.enum_system_all(directory)?;
            phase="active-hive-native-complete-durable-raw-copy-enum-all";
            let raw_semantics=tool.enum_all(&copy,directory)?;
            need(current==raw_semantics,"current SYSTEM BCD and durable FAT-bound raw copy differ in complete native semantics")?;
            phase="active-hive-raw-copy-native-identity-and-content-bookend";
            need(crate::reference_file::observe_reference_file_handle_with_limit(&copied,budget.maximum_store_bytes)?==copy_before
                &&crate::sha256_native::hash_range(&mut copied,0,bytes)?==raw_before,
                "native semantic query changed actual raw-copy identity/content")?;
            phase="active-hive-current-FAT-raw-hash-closing";
            need(raw_hash(efi,&pin,budget.maximum_control_bytes,events)?==raw_before
                &&legacy_identity(&file)?==(pin.identity.clone(),bytes),
                "active hive physical/FAT/held metadata changed across native semantic check")?;
            native::persist(&directory.join(format!("active-hive-capture-{ordinal:04}.json")),
                &serde_json::json!({"kind":"actual-active-BCD-attribute-only-raw-capture-v1",
                    "actual_EFI_BCD_path":efi.bcd_path,"metadata_desired_access":128,"share_mode":3,
                    "source_file_read_data_available":false,"source_file_data_read_calls":0,
                    "raw_copy_path":copy,"raw_store":pin,"complete_native_system_and_raw_copy_semantics_equal":true,
                    "native_objects_compared":current.len(),"physical_raw_hashes_and_current_FAT_map_equal":true,
                    "actual_held_legacy52_EOF_identity_equal":true,"record_grants_authority":false}),
                budget.maximum_control_bytes)?;
        }
        Ok(pin)
    })();
    let result=native::diagnose(result,"boot-store-capture-failed",phase,&context,events);
    let restored=native::diagnose(privilege.restore(),"boot-store-capture-privilege-restore-failed",
        "restore-SeManageVolumePrivilege",&context,events);
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
    let mut file = device_file(
        &format!("\\\\.\\PhysicalDrive{}", efi.binding.disk_number),
        false,
        false,
    )?;
    let opening = physical_binding(&file, efi, events)?;
    fat::require_current_map(&mut file, efi, pin, metadata_limit)?;
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
    fat::require_current_map(&mut file, efi, pin, metadata_limit)?;
    need(
        physical_binding(&file, efi, events)? == opening,
        "same raw BCD physical handle metadata changed",
    )?;
    Ok(hash.finalize().into())
}
pub(super) fn require_cold_efi(
    efi: &EfiIdentity,
    state: &crate::offline_environment::OfflineSourceState,
) -> io::Result<()> {
    let binding = &state.binding.storage;
    let e = &efi.binding;
    need(
        state.disk_offline_in_current_environment
            && e.disk_number == binding.disk_number
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
    need(
        pin.bytes <= maximum,
        "raw BCD copy exceeds admitted metadata bytes",
    )?;
    let mut source = device_file(
        &format!("\\\\.\\PhysicalDrive{}", efi.binding.disk_number),
        false,
        false,
    )?;
    let opening = physical_binding(&source, efi, events)?;
    fat::require_current_map(&mut source, efi, pin, metadata_limit)?;
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
    fat::require_current_map(&mut source, efi, pin, metadata_limit)?;
    need(
        physical_binding(&source, efi, events)? == opening,
        "same raw BCD copy physical metadata changed",
    )?;
    output.sync_all()?;
    let sha: [u8; 32] = hash.finalize().into();
    need(
        crate::sha256_native::hash_range(&mut output, 0, pin.bytes)? == sha,
        "raw BCD metadata copy readback differs",
    )?;
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
pub(super) fn available_efi(expected:&EfiIdentity,state:&crate::offline_environment::OfflineSourceState,
    memory_bytes:u64,events:&mut Vec<NativeEvent>)->io::Result<EfiIdentity> {
    need(state.actual.disk_attributes==0&&!state.disk_offline_in_current_environment
        &&state.binding.storage.disk_number==expected.binding.disk_number
        &&state.binding.storage.identity.disk_guid==expected.binding.identity.disk_guid,
        "actual closed-terminal source disk must be available before EFI publication")?;
    let id=layout::guid_bytes(&expected.binding.identity.partition_guid)?;
    let rows=&state.actual.gpt.native_layout;
    need(rows.len()>=48&&(rows.len()-48).is_multiple_of(144)
        &&rows[48..].chunks_exact(144).filter(|r|r[48..64]==id&&*r==expected.native_partition_info).count()==1,
        "actual available EFI native row differs from original boot intent")?;
    let mut name=[0u16;1024];let h=unsafe{FindFirstVolumeW(name.as_mut_ptr(),name.len()as u32)};
    if h==INVALID_HANDLE_VALUE{return Err(io::Error::last_os_error())}
    let enumeration=Enumeration(h);let mut found=None;let mut complete=false;
    for _ in 0..memory_bytes/4096 {
        let n=name.iter().position(|v|*v==0).ok_or_else(||bad("EFI publication name unterminated"))?;
        let value=String::from_utf16(&name[..n]).map_err(io::Error::other)?;
        need(value.len()==49&&value.starts_with(r"\\?\Volume{")&&value.ends_with("}\\"),"current EFI publication catalog malformed")?;
        let opened=OpenOptions::new().access_mode(0x80).share_mode(3).open(value.trim_end_matches('\\'));
        let file=match opened {Ok(f)=>Some(f),Err(e)if e.raw_os_error()==Some(21)=>None,Err(e)=>return Err(e)};
        if let Some(file)=file {
            let device=control(&file,"terminal-boot-EFI-published-native-device",DEVICE,&[],12,events);
            let device=match device {Ok(v)=>Some(v),Err(e)if e.raw_os_error()==Some(21)=>None,Err(e)=>return Err(e)};
            if let Some(device)=device {
                if device.len()==12&&layout::u32_at(&device,0)?==7
                    &&layout::u32_at(&device,4)?==expected.binding.disk_number
                    &&layout::u32_at(&device,8)?==expected.binding.identity.partition_number {
                    let info=control(&file,"terminal-boot-EFI-published-native144",0x00070048,&[],144,events)?;
                    let ext=control(&file,"terminal-boot-EFI-published-extents",VOLUME_EXTENTS,&[],32,events)?;
                    expected.binding.validate_volume_extent(&ext)?;
                    need(info==expected.native_partition_info&&found.is_none(),"actual EFI publication identity ambiguous")?;
                    let mut actual=expected.clone();actual.binding.volume_guid=value[11..47].into();
                    actual.bcd_path=PathBuf::from(&value).join(r"EFI\Microsoft\Boot\BCD");
                    found=Some(actual);
                }
            }
        }
        name.fill(0);
        if unsafe{FindNextVolumeW(enumeration.0,name.as_mut_ptr(),name.len()as u32)}==0{
            let e=io::Error::last_os_error();if e.raw_os_error()==Some(18){complete=true;break}return Err(e)
        }
    }
    need(complete,"current published EFI catalog exceeds admitted bound")?;
    found.ok_or_else(||io::Error::new(io::ErrorKind::NotFound,"actual available EFI volume not yet published"))
}
/// Flush only the positively bound explicit EFI BCD, not a PE default hive.
pub(super) fn flush_explicit_store(efi:&EfiIdentity)->io::Result<()> {
    let file=OpenOptions::new().read(true).write(true).share_mode(3)
        .custom_flags(0x00200000).open(&efi.bcd_path)?;
    legacy_identity(&file)?;
    let actual=crate::file_storage::final_path_guid(&file)?;
    need(actual.eq_ignore_ascii_case(efi.bcd_path.to_str().ok_or_else(||bad("Unicode actual EFI BCD path required"))?),
        "explicit BCD flush file escaped actual EFI route")?;
    file.sync_all()
}
