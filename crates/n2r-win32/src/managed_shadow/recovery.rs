//! Existing pinned shadow attachment only: no create, GPT, format or replay.
use super::*;
use windows_sys::Win32::{
    Foundation::ERROR_WRITE_PROTECT,
    System::Ioctl::{IOCTL_DISK_IS_WRITABLE, IOCTL_DISK_SET_DISK_ATTRIBUTES},
};

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
    fn physical_number(&self) -> io::Result<u32> {
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
        path.strip_prefix("\\\\.\\PhysicalDrive")
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|n| *n <= 4095)
            .ok_or_else(|| invalid("recovery provider disk path differs"))
    }

    fn attach(self) -> io::Result<RecoveryAttachment> {
        let number = match self.physical_number() {
            // A previous attempt can leave this same pinned VHDX attached.
            // Reuse the provider-derived route rather than attaching it twice.
            Ok(number) => number,
            Err(error) if error.raw_os_error().is_some() => {
                let mut p = ATTACH_VIRTUAL_DISK_PARAMETERS::default();
                p.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
                // SAFETY: opened-existing READ_ONLY handle and version1 input.
                // The only attachment requested is READ_ONLY, including arrival.
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
                })
                .map_err(|e| operation_error("attach pinned recovery shadow READ_ONLY", e))?;
                self.physical_number().map_err(|e| {
                    operation_error("query attached recovery shadow physical path", e)
                })?
            }
            // Successful provider output with malformed path is never retried.
            Err(error) => return Err(error),
        };
        Ok(RecoveryAttachment {
            handle: self,
            number,
        })
    }
}

fn operation_error(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

fn require_write_protected(disk: &File, software_attributes: u64, phase: &str) -> io::Result<()> {
    let operation = format!(
        "{phase}: software_attributes={software_attributes:#x}, IOCTL_DISK_IS_WRITABLE={IOCTL_DISK_IS_WRITABLE:#x}"
    );
    // This is a query, not a trial data write. Only the positive native
    // ERROR_WRITE_PROTECT response proves this device is already protected.
    match control(disk, IOCTL_DISK_IS_WRITABLE, &[], 0) {
        Err(error) if error.raw_os_error() == Some(ERROR_WRITE_PROTECT as i32) => Ok(()),
        Ok(_) => Err(invalid(&format!(
            "{operation}: device is writable; no protection shortcut authorized"
        ))),
        Err(error) => Err(operation_error(&operation, error)),
    }
}

impl RecoveryAttachment {
    fn require_offline_readonly(&self, expected: &GeneralDiskBinding) -> io::Result<()> {
        let mut events = Vec::new();
        // This checks actual device/GPT/geometry and excludes the Windows disk
        // before any attribute control handle is opened.
        let before = native::observe_general_disk_state_readonly(expected.clone(), &mut events)?;
        match before.disk_attributes {
            3 => return Ok(()),
            0..=2 => {}
            _ => {
                return Err(invalid(&format!(
                    "recovery shadow has unknown software attributes {:#x}; no attributes changed",
                    before.disk_attributes
                )));
            }
        }
        // The device path comes only from this owned, verified virtual-disk
        // handle, and its exact recorded number was checked by the caller.
        // GENERIC_WRITE is for the attribute IOCTL; no data writes are issued.
        let disk = native::device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.number),
            true,
            false,
        )
        .map_err(|e| {
            operation_error(
                &format!(
                    "open verified shadow for protection control: software_attributes={:#x}",
                    before.disk_attributes
                ),
                e,
            )
        })?;
        // A READ_ONLY virtual-disk attachment can report software attributes
        // zero while its provider still write-protects the underlying device.
        // Never turn an actually writable device read-only to pass this gate.
        require_write_protected(&disk, before.disk_attributes, "before protection control")?;
        if native::current_windows_disk(&mut events)? == self.number
            || native::general_disk_state(&disk, expected, &mut events)? != before
        {
            return Err(invalid(
                "verified recovery shadow changed before OFFLINE control",
            ));
        }
        let mut attributes = [0u8; 40];
        attributes[..4].copy_from_slice(&40u32.to_le_bytes());
        attributes[4] = 1; // Persist the restriction across restart.
        let missing = 3u64 & !before.disk_attributes;
        attributes[8..16].copy_from_slice(&3u64.to_le_bytes());
        attributes[16..24].copy_from_slice(&missing.to_le_bytes());
        // Set only missing protection bits; no existing bit can be cleared.
        let operation = format!(
            "persist missing protection bits on verified protected shadow: software_attributes={:#x}, mask={missing:#x}, IOCTL_DISK_SET_DISK_ATTRIBUTES={IOCTL_DISK_SET_DISK_ATTRIBUTES:#x}",
            before.disk_attributes
        );
        control(&disk, IOCTL_DISK_SET_DISK_ATTRIBUTES, &attributes, 0)
            .map_err(|e| operation_error(&operation, e))?;
        control(&disk, IOCTL_DISK_UPDATE_PROPERTIES, &[], 0)
            .map_err(|e| {
                operation_error(
                    &format!(
                        "refresh protected recovery shadow: prior_software_attributes={:#x}, IOCTL_DISK_UPDATE_PROPERTIES={IOCTL_DISK_UPDATE_PROPERTIES:#x}",
                        before.disk_attributes
                    ),
                    e,
                )
            })?;
        let mut required = before;
        required.disk_attributes = 3;
        if native::general_disk_state(&disk, expected, &mut events)? != required
            || native::observe_general_disk_state_readonly(expected.clone(), &mut events)?
                != required
        {
            return Err(invalid(
                "recovery shadow did not retain exact OFFLINE|READ_ONLY state",
            ));
        }
        require_write_protected(&disk, required.disk_attributes, "after protection control")?;
        Ok(())
    }
}

/// Reattach a pinned existing VHDX read-only, then require the exact recorded
/// disk route and GPT/geometry. Reuse an existing exact attachment. A native
/// write-protection query must prove protection before adding missing persistent
/// OFFLINE/READ_ONLY bits. An actually writable device is never changed to pass
/// this gate. No source certificate, replay, writable attachment or transition
/// to online is authorized.
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
    attachment.require_offline_readonly(expected)?;
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
