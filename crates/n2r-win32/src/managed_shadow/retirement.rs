//! Explicit retirement of a newly owned shadow after successful V4 completion.
//! No Drop cleanup, source access, pathname-only deletion or recovery replay.
use super::*;
use crate::reference_file::{ReferenceFileSnapshot, observe_reference_file_handle_with_limit};

pub(super) struct OwnedBacking {
    file: File,
    path: PathBuf,
    identity: ReferenceFileSnapshot,
}

fn ordinary(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("ordinary owned shadow path required"));
    }
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("owned shadow ancestry is redirected"));
        }
    }
    Ok(())
}

fn snapshot(file: &File) -> io::Result<ReferenceFileSnapshot> {
    let result = observe_reference_file_handle_with_limit(file, i64::MAX as u64)?;
    if result.file_bytes == 0 || result.number_of_links != 1 {
        return Err(invalid(
            "single-link ordinary owned shadow backing required",
        ));
    }
    Ok(result)
}

fn same_identity(
    expected: &ReferenceFileSnapshot,
    actual: &ReferenceFileSnapshot,
) -> io::Result<()> {
    // EOF/allocation may change while the provider writes and closes VHDX.
    // Neither is used as file identity or as a claim about physical free space.
    if expected.volume_serial_number != actual.volume_serial_number
        || expected.file_id_128 != actual.file_id_128
        || !expected.final_path.eq_ignore_ascii_case(&actual.final_path)
        || expected.file_attributes != actual.file_attributes
        || actual.number_of_links != 1
    {
        return Err(invalid(
            "owned shadow backing identity or ordinary attributes changed",
        ));
    }
    Ok(())
}

impl OwnedBacking {
    pub(super) fn enroll(path: &Path) -> io::Result<Self> {
        ordinary(path)?;
        // Permit the newly owned provider's reads/writes, but exclude deletion
        // and replacement for this file's entire construction lifetime.
        let file = OpenOptions::new()
            .access_mode(0x80) // FILE_READ_ATTRIBUTES; no payload reads.
            .share_mode(3) // FILE_SHARE_READ | FILE_SHARE_WRITE, never DELETE.
            .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT.
            .open(path)?;
        let identity = snapshot(&file)?;
        Ok(Self {
            file,
            path: path.into(),
            identity,
        })
    }

    fn observe(&self) -> io::Result<ReferenceFileSnapshot> {
        ordinary(&self.path)?;
        let actual = snapshot(&self.file)?;
        same_identity(&self.identity, &actual)?;
        Ok(actual)
    }
}

/// Observations only. A cleanup failure does not undo a completed conversion,
/// authorize recovery, or establish physical storage/RAM savings.
#[derive(Debug, Serialize)]
pub struct ShadowRetirementReceipt {
    pub schema_version: u32,
    pub kind: &'static str,
    pub path: PathBuf,
    pub virtual_disk_id: String,
    pub shadow: GeneralDiskBinding,
    pub success: bool,
    pub phase: &'static str,
    pub provider_loaded_before_detach: Option<bool>,
    pub provider_loaded_after_detach: Option<bool>,
    pub shadow_disk_attributes_before_detach: Option<u64>,
    pub detached_observed: bool,
    pub backing_retirement_requested: bool,
    pub backing_retired_observed: bool,
    pub backing_before_detach: Option<ReferenceFileSnapshot>,
    pub backing_before_retirement: Option<ReferenceFileSnapshot>,
    pub error: Option<String>,
    pub native_error: Option<i32>,
    pub payload_io_issued: bool,
    pub source_device_access_issued: bool,
    pub recovery_files_retired: bool,
    pub physical_freed_bytes_or_ram_reduction_measured: bool,
}

fn loaded(attachment: &AttachedDisk) -> io::Result<bool> {
    let bytes = attachment.query(GET_VIRTUAL_DISK_INFO_IS_LOADED)?;
    if bytes.len() < 12 || layout::u32_at(&bytes, 0)? != GET_VIRTUAL_DISK_INFO_IS_LOADED as u32 {
        return Err(invalid("owned shadow loaded-state query differs"));
    }
    match layout::u32_at(&bytes, 8)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("owned shadow loaded-state boolean differs")),
    }
}

fn require_path(attachment: &AttachedDisk) -> io::Result<()> {
    let mut output = [0u16; 256];
    let mut bytes = 512;
    // SAFETY: the original owned provider handle and initialized UTF-16 output.
    win(unsafe {
        GetVirtualDiskPhysicalPath(attachment.created.handle.0, &mut bytes, output.as_mut_ptr())
    })?;
    if !(2..=512).contains(&bytes) || !bytes.is_multiple_of(2) {
        return Err(invalid("owned shadow provider path byte count differs"));
    }
    let end = output
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| invalid("owned shadow provider path is unterminated"))?;
    let actual = String::from_utf16(&output[..end])
        .map_err(|_| invalid("owned shadow provider path UTF-16 differs"))?;
    if actual != format!("\\\\.\\PhysicalDrive{}", attachment.number) {
        return Err(invalid("owned shadow provider physical route changed"));
    }
    Ok(())
}

impl ManagedShadow {
    /// Consume only this fresh constructor-owned shadow after its caller has
    /// completed V4 HND/native finalization and released every raw/tree owner.
    /// Legacy/failure paths must retain ordinary permanent-attachment Drop.
    /// This cannot access a source disk or retire any journal/evidence file.
    pub fn retire_after_successful_v4(self) -> ShadowRetirementReceipt {
        let mut receipt = ShadowRetirementReceipt {
            schema_version: 1,
            kind: "owned-shadow-post-v4-retirement",
            path: self._backing.path.clone(),
            virtual_disk_id: guid_text(&self._attachment.created.id),
            shadow: self._owned_binding.clone(),
            success: false,
            phase: "verify-owned-shadow",
            provider_loaded_before_detach: None,
            provider_loaded_after_detach: None,
            shadow_disk_attributes_before_detach: None,
            detached_observed: false,
            backing_retirement_requested: false,
            backing_retired_observed: false,
            backing_before_detach: None,
            backing_before_retirement: None,
            error: None,
            native_error: None,
            payload_io_issued: false,
            source_device_access_issued: false,
            recovery_files_retired: false,
            physical_freed_bytes_or_ram_reduction_measured: false,
        };
        let result = self.retire_owned(&mut receipt);
        match result {
            Ok(()) => receipt.success = true,
            Err(error) => {
                receipt.native_error = error.raw_os_error();
                receipt.error = Some(error.to_string());
            }
        }
        receipt
    }

    fn retire_owned(self, receipt: &mut ShadowRetirementReceipt) -> io::Result<()> {
        if self.binding != self._owned_binding
            || self.path != self._backing.path
            || self.virtual_disk_id != guid_text(&self._attachment.created.id)
            || self.binding.disk_number != self._attachment.number
        {
            return Err(invalid(
                "public shadow route differs from its actual owned identity",
            ));
        }
        self._attachment.verify_provider()?;
        require_path(&self._attachment)?;
        let before_loaded = loaded(&self._attachment)?;
        receipt.provider_loaded_before_detach = Some(before_loaded);
        if !before_loaded {
            return Err(invalid(
                "owned shadow was not attached before explicit retirement",
            ));
        }
        let mut events = Vec::new();
        let state =
            native::observe_general_disk_state_readonly(self._owned_binding.clone(), &mut events)?;
        receipt.shadow_disk_attributes_before_detach = Some(state.disk_attributes);
        if state.disk_attributes != 3 {
            return Err(invalid("owned shadow is not frozen OFFLINE|READ_ONLY"));
        }
        receipt.backing_before_detach = Some(self._backing.observe()?);
        self._attachment.verify_provider()?;
        require_path(&self._attachment)?;
        receipt.phase = "detach-owned-provider";
        let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
        // SAFETY: the original newly-created provider handle, not a path-opened
        // replacement. No source or unrelated attachment enters this boundary.
        win(unsafe {
            DetachVirtualDisk(
                self._attachment.created.handle.0,
                DETACH_VIRTUAL_DISK_FLAG_NONE,
                0,
            )
        })?;
        receipt.phase = "observe-provider-detached";
        self._attachment.verify_provider()?;
        // A successful Detach call alone need not remove a permanent attachment.
        // Require a successful positive provider query of IsLoaded == false.
        let after_loaded = loaded(&self._attachment)?;
        receipt.provider_loaded_after_detach = Some(after_loaded);
        if after_loaded {
            return Err(invalid("owned shadow remains loaded after explicit detach"));
        }
        receipt.detached_observed = true;
        self._backing.observe()?;
        privileges.restore()?;
        let ManagedShadow {
            _attachment,
            _backing,
            ..
        } = self;
        let OwnedBacking {
            file,
            path,
            identity,
        } = _backing;
        // Provider closure can finalize VHDX EOF/allocation. Only after that
        // closure release the no-delete identity guard and request DELETE.
        drop(_attachment);
        drop(file);
        receipt.phase = "open-exact-detached-backing";
        ordinary(&path)?;
        let delete = OpenOptions::new()
            .access_mode(0x80 | 0x10000) // FILE_READ_ATTRIBUTES | DELETE.
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&path)?;
        let current = snapshot(&delete)?;
        same_identity(&identity, &current)?;
        receipt.backing_before_retirement = Some(current);
        receipt.phase = "retire-exact-detached-backing";
        crate::file_storage::mark_delete_on_close(&delete)?;
        receipt.backing_retirement_requested = true;
        drop(delete);
        receipt.phase = "observe-backing-retired";
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(invalid(
                    "owned backing retirement was not observed complete",
                ));
            }
        }
        receipt.backing_retired_observed = true;
        receipt.phase = "complete";
        Ok(())
    }
}

/// Read-only metadata meter issued only from an original constructor-held
/// FILE_READ_ATTRIBUTES backing owner. No path/JSON constructor or authority.
/// It can move to the conversion worker independently of provider attachment.
pub struct StagingAllocationMeter {
    file: File,
    identity: ReferenceFileSnapshot,
    kind: &'static str,
}
#[derive(Debug, Serialize)]
pub struct StagingAllocationObservation {
    pub backing_kind: &'static str,
    pub backing_file: ReferenceFileSnapshot,
    pub outer_backing_files_counted: u32,
    pub nested_members_counted_separately: bool,
    pub payload_bytes_read_by_meter: u64,
    pub measured_peak_or_physical_usage: bool,
}
impl StagingAllocationMeter {
    pub fn try_clone(&self) -> io::Result<Self> {
        Self::from_held(&self.file, &self.identity, self.kind)
    }

    pub(super) fn from_held(
        file: &File,
        identity: &ReferenceFileSnapshot,
        kind: &'static str,
    ) -> io::Result<Self> {
        let file = file.try_clone()?; // original read-attributes access only
        let actual = snapshot(&file)?;
        same_identity(identity, &actual)?;
        Ok(Self {
            file,
            identity: identity.clone(),
            kind,
        })
    }
    pub fn observe(&self) -> io::Result<StagingAllocationObservation> {
        let actual = snapshot(&self.file)?; // metadata only, no path reopen
        same_identity(&self.identity, &actual)?; // EOF/allocation may grow
        Ok(StagingAllocationObservation {
            backing_kind: self.kind,
            backing_file: actual,
            outer_backing_files_counted: 1,
            nested_members_counted_separately: false,
            payload_bytes_read_by_meter: 0,
            measured_peak_or_physical_usage: false,
        })
    }
}
impl ManagedShadow {
    pub fn staging_allocation_meter(&self) -> io::Result<StagingAllocationMeter> {
        // Observe against the existing owned identity before duplicating it.
        self._backing.observe()?;
        StagingAllocationMeter::from_held(
            &self._backing.file,
            &self._backing.identity,
            "native-vhdx-outer-backing",
        )
    }
}
