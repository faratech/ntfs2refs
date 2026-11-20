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
        // Persist=1 lands in the SYSTEM hive, which Windows writes lazily. A
        // power-off before that write would bring the shadow back without
        // the bits just read back; do not report them until they are on disk.
        native::flush_persisted_attributes(&mut events)
            .map_err(|e| operation_error("flush the persisted shadow protection to disk", e))?;
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

/// Detaches the working volume a run built (`shadow.vhdx` in its working
/// directory) when Windows still has it attached, which it does after the run
/// was cut off: the run attached it for the lifetime of the machine, and
/// nothing detached it. Called only after a recovery or a cancellation has
/// completed, when nothing needs that volume any more; the file is not
/// deleted. Returns whether a detach was done.
///
/// Whether it is attached is asked on a query-only handle, which is closed
/// before the detach: Windows detaches only when no other handle to the
/// virtual disk is open. The detach goes first through the read-only handle
/// that detached in the soak (#175). A forward recovery in the recovery
/// environment had that open or detach refused with Access is denied, which
/// of the two was not recorded (#182); then the detach is tried again,
/// that handle closed, through one opened with `VIRTUAL_DISK_ACCESS_DETACH`
/// and no write access, which Windows documents for a handle to a
/// permanently attached virtual disk. A failure names each step tried.
pub fn detach_left_behind(path: &Path) -> io::Result<bool> {
    let name = left_behind_name(path)?;
    let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])
        .map_err(|e| operation_error("enable SeManageVolumePrivilege to detach", e))?;
    // Not attached: nothing to do. The query handle is closed on return.
    if !left_behind_attached(&name)? {
        privileges.restore()?;
        return Ok(false);
    }
    detach_through(&name, LeftBehindOpen::ReadOnly).or_else(|first| {
        detach_through(&name, LeftBehindOpen::Detach)
            .map_err(|second| io::Error::new(second.kind(), format!("{first}; then {second}")))
    })?;
    if left_behind_attached(&name)? {
        return Err(invalid(
            "the working volume is still attached after the detach",
        ));
    }
    privileges.restore()?;
    Ok(true)
}

/// The UTF-16 name of a run's own `shadow.vhdx`; anything else is refused
/// before Windows is asked anything.
fn left_behind_name(path: &Path) -> io::Result<Vec<u16>> {
    if path.file_name().and_then(|name| name.to_str()) != Some("shadow.vhdx") || !path.is_absolute()
    {
        return Err(invalid("only a run's own shadow.vhdx is detached"));
    }
    wide(
        path.to_str()
            .ok_or_else(|| invalid("Unicode working-volume path required"))?,
    )
}

/// Whether Windows has this image attached, from a query-only handle that is
/// closed before this returns.
fn left_behind_attached(name: &[u16]) -> io::Result<bool> {
    let handle = open_left_behind(name, LeftBehindOpen::Query)?;
    Ok(handle.physical_number().is_ok())
}

/// How a left-behind working volume is opened. None opens it for writing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeftBehindOpen {
    /// Version 2, query-only and read-only: to ask whether it is attached.
    Query,
    /// Version 2, read-only, no access mask: the handle #175's detach used,
    /// which detached in the soak.
    ReadOnly,
    /// Version 1, `VIRTUAL_DISK_ACCESS_DETACH | GET_INFO`, depth 0: what
    /// Windows documents for a handle to a permanently attached disk.
    Detach,
}

impl LeftBehindOpen {
    fn phase(self) -> &'static str {
        match self {
            Self::Query => "open the working volume to ask whether it is attached",
            Self::ReadOnly => "open the attached working volume read-only for detach",
            Self::Detach => {
                "open the attached working volume for detach (VIRTUAL_DISK_ACCESS_DETACH)"
            }
        }
    }
}

/// Detaches through one kind of handle, closed before this returns; the
/// error names the handle and the step.
fn detach_through(name: &[u16], how: LeftBehindOpen) -> io::Result<()> {
    let handle = open_left_behind(name, how)?;
    // SAFETY: the live handle opened above for this exact file.
    win(unsafe { DetachVirtualDisk(handle.0.0, DETACH_VIRTUAL_DISK_FLAG_NONE, 0) }).map_err(|e| {
        operation_error(
            &format!(
                "detach the working volume through the handle of \"{}\" (another process may hold the disk or its volume open)",
                how.phase()
            ),
            e,
        )
    })
}

/// Open-existing only, never with write access.
fn open_left_behind(name: &[u16], how: LeftBehindOpen) -> io::Result<RecoveryHandle> {
    let storage = VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    let version2 = |get_info_only| OPEN_VIRTUAL_DISK_PARAMETERS {
        Version: OPEN_VIRTUAL_DISK_VERSION_2,
        Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
            Version2: OPEN_VIRTUAL_DISK_PARAMETERS_0_1 {
                GetInfoOnly: get_info_only,
                ReadOnly: 1,
                ..Default::default()
            },
        },
    };
    let (p, access) = match how {
        LeftBehindOpen::Query => (version2(1), VIRTUAL_DISK_ACCESS_NONE),
        LeftBehindOpen::ReadOnly => (version2(0), VIRTUAL_DISK_ACCESS_NONE),
        LeftBehindOpen::Detach => (
            OPEN_VIRTUAL_DISK_PARAMETERS {
                Version: OPEN_VIRTUAL_DISK_VERSION_1,
                Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
                    Version1: OPEN_VIRTUAL_DISK_PARAMETERS_0_0 { RWDepth: 0 },
                },
            },
            VIRTUAL_DISK_ACCESS_DETACH | VIRTUAL_DISK_ACCESS_GET_INFO,
        ),
    };
    let phase = how.phase();
    let mut opened = ptr::null_mut();
    // SAFETY: open-existing only with complete parameters for their version;
    // nothing is created, initialized or opened for writing.
    win(unsafe {
        OpenVirtualDisk(
            &storage,
            name.as_ptr(),
            access,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            &p,
            &mut opened,
        )
    })
    .map_err(|e| operation_error(phase, e))?;
    if opened.is_null() || opened == INVALID_HANDLE_VALUE {
        return Err(invalid("no working-volume provider handle"));
    }
    Ok(RecoveryHandle(VirtualHandle(opened)))
}

#[cfg(test)]
mod left_behind_tests {
    use super::*;

    #[test]
    fn only_a_runs_own_shadow_is_detached_and_windows_is_not_asked_otherwise() {
        for path in [
            Path::new("C:\\runs\\x\\journal.vhdx"),
            Path::new("C:\\runs\\x\\Shadow.vhdx.bak"),
            Path::new("runs\\x\\shadow.vhdx"),
        ] {
            let error = detach_left_behind(path).unwrap_err();
            assert!(
                error.to_string().contains("only a run's own shadow.vhdx"),
                "{path:?}: {error}"
            );
        }
        assert!(left_behind_name(Path::new("C:\\runs\\x\\shadow.vhdx")).is_ok());
    }

    #[test]
    fn each_way_of_opening_says_what_it_opened_for() {
        let phases = [
            LeftBehindOpen::Query,
            LeftBehindOpen::ReadOnly,
            LeftBehindOpen::Detach,
        ]
        .map(LeftBehindOpen::phase);
        assert!(phases[0].contains("whether it is attached"));
        assert!(phases[1].contains("read-only for detach"));
        assert!(phases[2].contains("VIRTUAL_DISK_ACCESS_DETACH"));
        assert!(phases[0] != phases[1] && phases[1] != phases[2]);
    }

    #[test]
    fn a_failed_step_is_named_in_its_error() {
        let error = operation_error(
            "detach the working volume (another process may hold the disk or its volume open)",
            io::Error::from_raw_os_error(5),
        );
        let said = error.to_string();
        assert!(said.starts_with("detach the working volume"), "{said}");
        assert!(said.contains("os error 5"), "{said}");
    }
}
