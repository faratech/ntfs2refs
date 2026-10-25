use super::*;
use crate::{GeneralProbe, NativeEvent};
use std::{
    fs::File,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Storage::FileSystem::{GetVolumeInformationByHandleW, SetVolumeLabelW},
    System::IO::DeviceIoControl,
};

#[derive(Debug, Serialize)]
pub struct LabelObservation {
    pub binding: GeneralDiskBinding,
    pub label: VolumeLabel,
    pub filesystem: String,
    pub volume_serial_low32: u32,
    pub filesystem_flags: u32,
    pub probe_before: GeneralProbe,
    pub probe_after: GeneralProbe,
    pub volume_extents: Vec<u8>,
    pub events: Vec<NativeEvent>,
    pub source_payload_writes: u64,
}
/// Constructed from an actual mounted NTFS handle, never deserialized.
#[derive(Debug, Serialize)]
pub struct SourceLabel {
    observation: LabelObservation,
}
impl SourceLabel {
    pub fn label(&self) -> &VolumeLabel {
        &self.observation.label
    }
    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.observation.binding
    }
}

#[derive(Debug, Serialize)]
pub struct LabelRestoration {
    pub original_binding: GeneralDiskBinding,
    pub converted_binding: GeneralDiskBinding,
    pub expected_before: VolumeLabel,
    pub desired: VolumeLabel,
    pub before: LabelObservation,
    pub after: Option<LabelObservation>,
    pub setter_called: bool,
    pub setter_succeeded: bool,
    pub flush_required: bool,
    pub flushed: bool,
    pub readback_matches: bool,
    pub success: bool,
    pub error: Option<String>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn extents(file: &File) -> io::Result<Vec<u8>> {
    let mut bytes = [0u64; 4];
    let mut returned = 0;
    // SAFETY: synchronous query on the retained handle and aligned output.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0056_0000,
            ptr::null(),
            0,
            bytes.as_mut_ptr().cast(),
            32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned != 32 {
        return Err(invalid("label volume has incomplete or multiple extents"));
    }
    Ok(bytes.into_iter().flat_map(u64::to_le_bytes).collect())
}
fn info(file: &File) -> io::Result<(VolumeLabel, String, u32, u32)> {
    let mut label = [0u16; 261];
    let mut fs = [0u16; 32];
    let mut serial = 0;
    let mut component = 0;
    let mut flags = 0;
    // SAFETY: fixed initialized buffers queried through the bound file handle.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let end = label
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| invalid("unterminated volume label"))?;
    let label = VolumeLabel::from_utf16(label[..end].to_vec())?;
    let end = fs
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| invalid("unterminated filesystem name"))?;
    let filesystem =
        String::from_utf16(&fs[..end]).map_err(|_| invalid("invalid filesystem name"))?;
    Ok((label, filesystem, serial, flags))
}

fn observe_on_handle(
    binding: &GeneralDiskBinding,
    file: &File,
    filesystem: &str,
) -> io::Result<LabelObservation> {
    let mut events = Vec::new();
    let before = crate::probe_general(binding.clone(), &mut events)?;
    let first = extents(file)?;
    binding.validate_volume_extent(&first)?;
    let (label, fs, serial, flags) = info(file)?;
    if fs != filesystem || flags & 0x80000 != 0 {
        return Err(invalid("label filesystem or writable state differs"));
    }
    let (second, fs_after, serial_after, flags_after) = info(file)?;
    let last = extents(file)?;
    binding.validate_volume_extent(&last)?;
    let after = crate::probe_general(binding.clone(), &mut events)?;
    if first != last
        || label != second
        || fs != fs_after
        || serial != serial_after
        || flags != flags_after
        || before.device != after.device
        || before.disk_length != after.disk_length
        || before.alignment != after.alignment
        || before.gpt_layout != after.gpt_layout
        || before.volume_extents != after.volume_extents
    {
        return Err(invalid(
            "label or native device route changed during observation",
        ));
    }
    Ok(LabelObservation {
        binding: binding.clone(),
        label,
        filesystem: fs,
        volume_serial_low32: serial,
        filesystem_flags: flags,
        probe_before: before,
        probe_after: after,
        volume_extents: first,
        events,
        source_payload_writes: 0,
    })
}
pub fn observe_label(
    binding: GeneralDiskBinding,
    filesystem: &str,
) -> io::Result<LabelObservation> {
    binding.validate()?;
    if !matches!(filesystem, "NTFS" | "ReFS") {
        return Err(invalid("label observation requires NTFS or ReFS"));
    }
    let file = File::options()
        .read(true)
        .share_mode(3)
        .open(binding.volume_path()?)?;
    observe_on_handle(&binding, &file, filesystem)
}
pub fn capture_source_label(binding: GeneralDiskBinding) -> io::Result<SourceLabel> {
    Ok(SourceLabel {
        observation: observe_label(binding, "NTFS")?,
    })
}

/// Caller must already have verified durable irreversible handoff. Changes
/// supported filesystem metadata only; no raw sector write is issued.
pub fn restore_after_handoff(
    source: &SourceLabel,
    converted: GeneralDiskBinding,
    expected_before: &VolumeLabel,
) -> io::Result<LabelRestoration> {
    restore_verified_label(source.binding(), source.label(), converted, expected_before)
}

/// Recovery supplies the desired label from its separately pinned request.
/// Actual identity, current ReFS state and enrollment label are rechecked.
pub fn restore_verified_label(
    original: &GeneralDiskBinding,
    desired: &VolumeLabel,
    converted: GeneralDiskBinding,
    expected_before: &VolumeLabel,
) -> io::Result<LabelRestoration> {
    validate_original_partition(original, &converted)?;
    desired.validate()?;
    expected_before.validate()?;
    let file = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(converted.volume_path()?)?;
    let before = observe_on_handle(&converted, &file, "ReFS")?;
    let change = require_expected_current(&before.label, expected_before, desired)?;
    let mut report = LabelRestoration {
        original_binding: original.clone(),
        converted_binding: converted.clone(),
        expected_before: expected_before.clone(),
        desired: desired.clone(),
        before,
        after: None,
        setter_called: false,
        setter_succeeded: false,
        flush_required: true,
        flushed: false,
        readback_matches: false,
        success: false,
        error: None,
    };
    if change {
        // Check the canonical GUID route immediately before mutation while
        // retaining the original bound handle. No drive-letter path is used.
        let route = File::options()
            .read(true)
            .share_mode(3)
            .open(converted.volume_path()?)?;
        converted.validate_volume_extent(&extents(&route)?)?;
        let (current, fs, serial, flags) = info(&route)?;
        drop(route);
        if current != report.before.label
            || fs != "ReFS"
            || serial != report.before.volume_serial_low32
            || flags & 0x80000 != 0
        {
            return Err(invalid(
                "enrollment label or volume changed immediately before restoration",
            ));
        }
        let root: Vec<u16> = format!("{}\\", converted.volume_path()?)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let label = desired.terminated()?;
        report.setter_called = true;
        // SAFETY: validated exact GUID root and bounded NUL-terminated UTF-16
        // label remain live; empty labels use an explicit empty string.
        report.setter_succeeded = unsafe { SetVolumeLabelW(root.as_ptr(), label.as_ptr()) } != 0;
        if !report.setter_succeeded {
            report.error = Some(io::Error::last_os_error().to_string());
        }
    }
    // An already-desired label can be the result of a prior successful setter
    // followed by a failed flush. Idempotent completion still needs durability.
    match file.sync_all() {
        Ok(()) => report.flushed = true,
        Err(error) => {
            if report.error.is_none() {
                report.error = Some(error.to_string());
            }
        }
    }
    match observe_on_handle(&converted, &file, "ReFS") {
        Ok(after) => {
            report.readback_matches = after.label == *desired
                && after.volume_serial_low32 == report.before.volume_serial_low32;
            report.after = Some(after);
        }
        Err(error) => {
            if report.error.is_none() {
                report.error = Some(error.to_string());
            }
        }
    }
    if !report.readback_matches && report.error.is_none() {
        report.error = Some("driver label readback differs from source label".into());
    }
    report.success = (!change || report.setter_succeeded)
        && report.flushed
        && report.readback_matches
        && report.error.is_none();
    Ok(report)
}
