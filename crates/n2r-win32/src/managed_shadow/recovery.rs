//! Existing pinned shadow attachment only: no create, GPT, format or replay.
use super::*;

pub struct ReattachedShadow {
    pub binding: GeneralDiskBinding,
    pub path: PathBuf,
    pub virtual_disk_id: String,
    _attachment: RecoveryAttachment,
    _backing: File,
}
struct RecoveryHandle(VirtualHandle);
struct RecoveryAttachment {
    handle: RecoveryHandle,
    number: u32,
}

fn query(handle: &RecoveryHandle, version: GET_VIRTUAL_DISK_INFO_VERSION) -> io::Result<Vec<u8>> {
    let mut storage = [0u64; 32];
    storage[0] = version as u64;
    let mut size = 256;
    let mut used = 0;
    // SAFETY: live query handle and aligned initialized information union.
    win(unsafe {
        GetVirtualDiskInformation(
            handle.0.0,
            &mut size,
            storage.as_mut_ptr().cast(),
            &mut used,
        )
    })?;
    if !(8..=256).contains(&used) {
        return Err(invalid("recovery provider query size differs"));
    }
    // SAFETY: returned length is bounded by the initialized union allocation.
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), used as usize) }
        .to_vec();
    if layout::u32_at(&bytes, 0)? != version as u32 {
        return Err(invalid("recovery query version differs"));
    }
    Ok(bytes)
}
fn verify(handle: &RecoveryHandle, id: &[u8; 16], expected: &GeneralDiskBinding) -> io::Result<()> {
    let actual_id = query(handle, GET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID)?;
    let size = query(handle, GET_VIRTUAL_DISK_INFO_SIZE)?;
    let kind = query(handle, GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE)?;
    let physical = query(handle, GET_VIRTUAL_DISK_INFO_VHD_PHYSICAL_SECTOR_SIZE)?;
    let storage = query(handle, GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE)?;
    if actual_id.get(8..24) != Some(id.as_slice())
        || layout::u64_at(&size, 8)? != expected.identity.disk_bytes
        || layout::u32_at(&size, 24)? != 2 << 20
        || layout::u32_at(&size, 28)? != expected.identity.logical_sector_bytes
        || layout::u32_at(&physical, 8)? != expected.identity.physical_sector_bytes
        || layout::u32_at(&kind, 8)? != 3
        || layout::u32_at(&storage, 8)? != VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
        || storage.get(12..28)
            != Some(guid_bytes(&VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT).as_slice())
    {
        return Err(invalid(
            "existing recovery provider identity/type/geometry differs",
        ));
    }
    Ok(())
}
impl RecoveryHandle {
    fn attach(self) -> io::Result<RecoveryAttachment> {
        let mut p = ATTACH_VIRTUAL_DISK_PARAMETERS::default();
        p.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
        // SAFETY: actual opened-existing READ_ONLY handle and version1 input.
        // No writable attachment or drive-letter publication is requested.
        win(unsafe {
            AttachVirtualDisk(
                self.0.0,
                ptr::null_mut(),
                ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY
                    | ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME
                    | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                0,
                &p,
                ptr::null(),
            )
        })?;
        let mut path = [0u16; 256];
        let mut size = 512;
        // SAFETY: live attached handle and initialized bounded UTF-16 output.
        win(unsafe { GetVirtualDiskPhysicalPath(self.0.0, &mut size, path.as_mut_ptr()) })?;
        let end = path
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| invalid("recovery provider path unterminated"))?;
        let path = String::from_utf16(&path[..end])
            .map_err(|_| invalid("recovery provider path UTF-16"))?;
        let number = path
            .strip_prefix("\\\\.\\PhysicalDrive")
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|n| *n <= 4095)
            .ok_or_else(|| invalid("recovery provider disk path differs"))?;
        Ok(RecoveryAttachment {
            handle: self,
            number,
        })
    }
}

/// Reattach a pinned existing VHDX read-only, then require the exact recorded
/// disk route, GPT/geometry and persisted OFFLINE|READ_ONLY state. No source
/// certificate or replay authority is issued. No attributes are repaired.
/// Windows must honor its previously persisted OFFLINE state at device arrival;
/// READ_ONLY/NO_DRIVE_LETTER flags cannot replace that persistence policy.
pub fn reattach_existing(
    path: &Path,
    pinned_virtual_disk_id: &str,
    expected: &GeneralDiskBinding,
) -> io::Result<ReattachedShadow> {
    expected.validate()?;
    let id = layout::guid_bytes(pinned_virtual_disk_id)?;
    if id == [0; 16]
        || !path.is_absolute()
        || path
            .extension()
            .and_then(|v| v.to_str())
            .is_none_or(|v| !v.eq_ignore_ascii_case("vhdx"))
    {
        return Err(invalid("pinned existing local recovery VHDX required"));
    }
    for part in path.components() {
        match part {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                return Err(invalid("local recovery path required"));
            }
            Component::ParentDir => return Err(invalid("recovery path traversal refused")),
            Component::Normal(v)
                if v.to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                return Err(invalid("ambiguous recovery path"));
            }
            _ => {}
        }
    }
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.file_attributes() & 0x400 != 0 {
            return Err(invalid("ordinary recovery ancestry required"));
        }
    }
    let backing = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let metadata = backing.metadata()?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.file_attributes() & (0x400 | 0x800 | 0x4000) != 0
    {
        return Err(invalid(
            "ordinary uncompressed unencrypted recovery VHDX required",
        ));
    }
    let file_id = crate::file_storage::file_id_info(&backing)?;
    let modified = metadata.modified()?;
    let storage = VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    let mut p = OPEN_VIRTUAL_DISK_PARAMETERS::default();
    p.Version = OPEN_VIRTUAL_DISK_VERSION_2;
    p.Anonymous = OPEN_VIRTUAL_DISK_PARAMETERS_0 {
        Version2: OPEN_VIRTUAL_DISK_PARAMETERS_0_1 {
            GetInfoOnly: 0,
            ReadOnly: 1,
            ..Default::default()
        },
    };
    let name = wide(
        path.to_str()
            .ok_or_else(|| invalid("Unicode recovery path required"))?,
    )?;
    let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    let mut opened = ptr::null_mut();
    // SAFETY: open-existing only, complete version2 READ_ONLY parameters and
    // its required zero access mask. This call cannot initialize or format.
    win(unsafe {
        OpenVirtualDisk(
            &storage,
            name.as_ptr(),
            VIRTUAL_DISK_ACCESS_NONE,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            &p,
            &mut opened,
        )
    })?;
    if opened.is_null() || opened == INVALID_HANDLE_VALUE {
        return Err(invalid("no recovery provider handle"));
    }
    let handle = RecoveryHandle(VirtualHandle(opened));
    verify(&handle, &id, expected)?;
    let attachment = handle.attach()?;
    if attachment.number != expected.disk_number {
        return Err(invalid(
            "recovery disk number changed; pinned routing was not rewritten",
        ));
    }
    verify(&attachment.handle, &id, expected)?;
    let actual = native::observe_general_disk_state_readonly(expected.clone(), &mut Vec::new())?;
    if actual.disk_attributes != 3 {
        return Err(invalid(
            "recovery shadow lacks persistent OFFLINE|READ_ONLY state; no attributes changed",
        ));
    }
    if crate::file_storage::file_id_info(&backing)? != file_id
        || backing.metadata()?.len() != metadata.len()
        || backing.metadata()?.modified()? != modified
    {
        return Err(invalid("held recovery VHDX identity or metadata changed"));
    }
    privileges.restore()?;
    Ok(ReattachedShadow {
        binding: expected.clone(),
        path: path.to_owned(),
        virtual_disk_id: pinned_virtual_disk_id.into(),
        _attachment: attachment,
        _backing: backing,
    })
}
