//! Point-in-time persistent-volume policy observed on the actual mounted route.
//! No formatter, setter, trust, filter or registry operation is exposed. Machine
//! trust is queried here; it is never inferred from another volume's metadata.
use crate::{GeneralDiskState, NativeEvent, general_layout::GeneralDiskBinding, native};
use serde::Serialize;
use std::{
    fs::File,
    io,
    os::windows::io::AsRawHandle,
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::System::IO::DeviceIoControl;

// Windows SDK 10.0.26100.0 winioctl.h: filesystem function143, METHOD_BUFFERED,
// FILE_ANY_ACCESS. The query takes/returns four ULONGs in this exact order.
// https://learn.microsoft.com/windows-hardware/drivers/ifs/fsctl-query-persistent-volume-state
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_fs_persistent_volume_information
const QUERY_PERSISTENT_VOLUME_STATE: u32 = 590396;
const VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
const DEV_VOLUME: u32 = 0x0000_2000;
const TRUSTED_VOLUME: u32 = 0x0000_4000;
const QUERY_MASK: u32 = DEV_VOLUME | TRUSTED_VOLUME;
const QUERY_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Known,
    Partial,
    Unsupported,
    ApiError,
    InvalidReply,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueryError {
    pub win32_code: Option<i32>,
    pub message: String,
}

/// Descriptive native facts only, not source admission or policy authority.
/// A false designation/trust value is present only when that returned mask bit
/// was actually supported in a complete, recognized successful query response.
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub binding: GeneralDiskBinding,
    pub volume_path: String,
    pub observed_unix_ms: Option<u64>,
    pub control_code: u32,
    pub request_flag_mask: u32,
    pub request_version: u32,
    pub bytes_returned: u32,
    pub api_succeeded: bool,
    pub status: QueryStatus,
    pub api_error: Option<QueryError>,
    pub reply_issue: Option<&'static str>,
    pub raw_volume_flags: Option<u32>,
    pub raw_flag_mask: Option<u32>,
    pub raw_version: Option<u32>,
    pub raw_reserved: Option<u32>,
    pub developer_volume: Option<bool>,
    pub trusted_volume: Option<bool>,
    pub trust_scope: &'static str,
    pub disk_before: GeneralDiskState,
    pub disk_after: GeneralDiskState,
    pub volume_extents_before: Vec<u8>,
    pub volume_extents_after: Vec<u8>,
    pub read_only_query: bool,
    pub policy_changed: bool,
    pub grants_source_or_execution_authority: bool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn extents(file: &File, events: &mut Vec<NativeEvent>) -> io::Result<Vec<u8>> {
    let mut output = [0u64; 4];
    let mut returned = 0u32;
    // SAFETY: an actual retained read-only volume handle and bounded aligned
    // output. This synchronous metadata query cannot retain the stack buffer.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            VOLUME_DISK_EXTENTS,
            ptr::null(),
            0,
            output.as_mut_ptr().cast(),
            32,
            &mut returned,
            ptr::null_mut(),
        )
    } != 0;
    let error = (!succeeded).then(io::Error::last_os_error);
    let bytes: Vec<u8> = output.into_iter().flat_map(u64::to_le_bytes).collect();
    events.push(NativeEvent {
        operation: "volume-policy-readonly-volume-extents".into(),
        control_code: VOLUME_DISK_EXTENTS,
        input: Vec::new(),
        succeeded,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: if succeeded && returned == 32 {
            bytes.clone()
        } else {
            Vec::new()
        },
    });
    if let Some(error) = error {
        return Err(error);
    }
    if returned != 32 {
        return Err(invalid(
            "volume policy requires one complete bound volume extent",
        ));
    }
    Ok(bytes)
}

/// Observe the policy of this mounted, non-Windows-disk partition through an
/// actual read-only volume handle. Route/exclusion errors fail; unsupported,
/// failed or malformed policy replies return an observation with unknown bits.
/// Callers may require a known developer designation before construction but
/// must not treat machine trust as copied data or as a permission to change it.
pub fn observe(
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Observation> {
    binding.validate()?;
    let disk_before = crate::observe_general_disk_state_readonly(binding.clone(), events)?;
    if disk_before.disk_attributes & 1 != 0 {
        return Err(invalid(
            "volume policy observation requires an already mounted route",
        ));
    }
    let volume_path = binding.volume_path()?;
    let volume = native::device_file(&volume_path, false, false)?;
    let volume_extents_before = extents(&volume, events)?;
    binding.validate_volume_extent(&volume_extents_before)?;
    let input = [0u32, QUERY_MASK, QUERY_VERSION, 0];
    let mut output = [0u32; 4];
    let mut returned = 0u32;
    // SAFETY: the same actual read-only mounted-volume handle, two distinct
    // initialized four-ULONG buffers and the synchronous query-only FSCTL.
    let api_succeeded = unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            QUERY_PERSISTENT_VOLUME_STATE,
            input.as_ptr().cast(),
            16,
            output.as_mut_ptr().cast(),
            16,
            &mut returned,
            ptr::null_mut(),
        )
    } != 0;
    let error = (!api_succeeded).then(io::Error::last_os_error);
    let observed_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok());
    events.push(NativeEvent {
        operation: "query-persistent-volume-policy-readonly".into(),
        control_code: QUERY_PERSISTENT_VOLUME_STATE,
        input: input.into_iter().flat_map(u32::to_le_bytes).collect(),
        succeeded: api_succeeded,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: if api_succeeded {
            output
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .take((returned as usize).min(16))
                .collect()
        } else {
            Vec::new()
        },
    });
    let volume_extents_after = extents(&volume, events)?;
    binding.validate_volume_extent(&volume_extents_after)?;
    let disk_after = crate::observe_general_disk_state_readonly(binding.clone(), events)?;
    if disk_before != disk_after || volume_extents_before != volume_extents_after {
        return Err(invalid(
            "actual mounted volume route changed during policy query",
        ));
    }

    let raw = (api_succeeded && returned >= 16).then_some(output);
    let mut developer_volume = None;
    let mut trusted_volume = None;
    let mut reply_issue = None;
    let status = if let Some(error) = &error {
        if matches!(error.raw_os_error(), Some(1 | 50)) {
            QueryStatus::Unsupported
        } else {
            QueryStatus::ApiError
        }
    } else if returned != 16 {
        reply_issue = Some("persistent policy reply is not exactly four ULONGs");
        QueryStatus::InvalidReply
    } else if output[2] != QUERY_VERSION || output[3] != 0 {
        reply_issue = Some("persistent policy reply version or reserved field is unrecognized");
        QueryStatus::InvalidReply
    } else {
        if output[1] & DEV_VOLUME != 0 {
            developer_volume = Some(output[0] & DEV_VOLUME != 0);
        }
        if output[1] & TRUSTED_VOLUME != 0 {
            trusted_volume = Some(output[0] & TRUSTED_VOLUME != 0);
        }
        if developer_volume == Some(false) && trusted_volume == Some(true) {
            developer_volume = None;
            trusted_volume = None;
            reply_issue = Some("trusted-volume reply contradicts the developer-volume designation");
            QueryStatus::InvalidReply
        } else if developer_volume.is_some() && trusted_volume.is_some() {
            QueryStatus::Known
        } else {
            reply_issue =
                Some("persistent policy returned mask does not cover both requested bits");
            QueryStatus::Partial
        }
    };
    Ok(Observation {
        schema_version: 1,
        kind: "mounted-volume-persistent-policy-observation-v1",
        binding: binding.clone(),
        volume_path,
        observed_unix_ms,
        control_code: QUERY_PERSISTENT_VOLUME_STATE,
        request_flag_mask: QUERY_MASK,
        request_version: QUERY_VERSION,
        bytes_returned: returned,
        api_succeeded,
        status,
        api_error: error.map(|error| QueryError {
            win32_code: error.raw_os_error(),
            message: error.to_string(),
        }),
        reply_issue,
        raw_volume_flags: raw.map(|values| values[0]),
        raw_flag_mask: raw.map(|values| values[1]),
        raw_version: raw.map(|values| values[2]),
        raw_reserved: raw.map(|values| values[3]),
        developer_volume,
        trusted_volume,
        trust_scope: "queried on this machine; never inferred from another volume",
        disk_before,
        disk_after,
        volume_extents_before,
        volume_extents_after,
        read_only_query: true,
        policy_changed: false,
        grants_source_or_execution_authority: false,
    })
}
