//! Bounded owning-guest experiment, outside the converter construction path.
//! Creates one SYSTEM-only file on the enrolled shadow; never reads its data.
use super::{GetVolumeInformationByHandleW, ctl, info, invalid, native, snapshot, wide};
use crate::{attestation_native::Privileges, general_layout::GeneralSourceShadowBinding};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io, mem,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{CreateFileW, SetFileInformationByHandle, SetFileValidData},
};

const VALID_BYTES: u64 = 1024 * 1024;
const FILE_BYTES: u64 = VALID_BYTES + 4096;

#[derive(Serialize)]
pub struct Query {
    bytes: Vec<u8>,
    native_error: Option<i32>,
}

fn observed(value: io::Result<Vec<u8>>) -> Query {
    match value {
        Ok(bytes) => Query {
            bytes,
            native_error: None,
        },
        Err(error) => Query {
            bytes: vec![],
            native_error: Some(error.raw_os_error().unwrap_or(31)),
        },
    }
}

fn regions(file: &File, usage: u32) -> Query {
    let mut query = [0u8; 24];
    query[8..16].copy_from_slice(&FILE_BYTES.to_le_bytes());
    query[16..20].copy_from_slice(&usage.to_le_bytes());
    observed(ctl(file, 0x90284, &query, 16 + 24 * 1024))
}

fn observation(file: &File) -> serde_json::Value {
    let (first, continuation) = crate::stream_native::retrieval_queries(file);
    serde_json::json!({
        "snapshot":snapshot(file),"standard":observed(info(file,1,24)),
        "retrieval_first":first,"retrieval_continuation":continuation,
        "cached_regions":regions(file,1),"storage_regions":regions(file,2),
        "integrity":observed(ctl(file,0x9027c,&[],16))
    })
}

/// No mount, disk-attribute change, raw write, source write, data read or delete.
/// The file is intentionally retained with a protected SYSTEM-only DACL, even
/// on error/reboot, because successful valid-data advancement can expose old
/// contents. A returned success is not an extent-adoption or I/O-cost proof.
pub fn run(pair: &GeneralSourceShadowBinding, experiment: &str) -> io::Result<serde_json::Value> {
    run_inner(pair, experiment, None)
}

/// Try placement while VDL is zero, then advance VDL only after native mapping
/// confirmation. Only the new private file on the enrolled shadow is moved.
pub fn run_placed(
    pair: &GeneralSourceShadowBinding,
    experiment: &str,
    destination_lcn: u64,
) -> io::Result<serde_json::Value> {
    let end = destination_lcn
        .checked_mul(4096)
        .and_then(|v| v.checked_add(VALID_BYTES));
    if destination_lcn < 256 || end.is_none_or(|v| v > pair.shadow.identity.partition_bytes) {
        return Err(invalid("private placement outside enrolled partition"));
    }
    run_inner(pair, experiment, Some(destination_lcn))
}

fn run_inner(
    pair: &GeneralSourceShadowBinding,
    experiment: &str,
    destination_lcn: Option<u64>,
) -> io::Result<serde_json::Value> {
    pair.validate_with_resource_profile(Some(
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    ))?;
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        || pair.source.disk_number != 1
        || pair.shadow.disk_number != 3
        || pair
            .source
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "1b191872-c372-41ee-a416-e18863996f54"
        || pair
            .shadow
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "c0f2cd39-ad3d-484e-9990-0e6eba74485f"
        || experiment.len() != 32
        || !experiment.bytes().all(|v| v.is_ascii_hexdigit())
    {
        return Err(invalid("exact disposable streaming fixture required"));
    }
    let mut events = Vec::new();
    let source_before =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    let shadow_before =
        native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
    if source_before.disk_attributes != 3
        || shadow_before.disk_attributes != 0
        || native::mounted_filesystem_general(pair.shadow.clone(), &mut events)? != "ReFS"
    {
        return Err(invalid("excluded source and writable ReFS shadow required"));
    }
    let mut privilege = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    let sddl = wide("O:SYG:SYD:P(A;;FA;;;SY)");
    let mut descriptor = ptr::null_mut();
    // SAFETY: NUL-terminated constant SDDL; the allocated descriptor is freed
    // immediately after the synchronous atomic create, including failure.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let path = format!(
        "{}\\n2r-valid-data-{experiment}.bin",
        pair.shadow.volume_path()?
    );
    let name = wide(&path);
    // SAFETY: measured volume-GUID root, CREATE_NEW, sharing disabled and
    // protected security descriptor. No caller-selected path is accepted.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0xc0020000,
            0,
            &sa,
            1,
            0x80200080,
            ptr::null_mut(),
        )
    };
    let create_error = io::Error::last_os_error();
    unsafe {
        LocalFree(descriptor);
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(create_error);
    }
    // SAFETY: transfer unique ownership of the successfully created handle.
    let file = unsafe { File::from_raw_handle(handle) };
    // Only this new private file: ordinary target data must not inherit an
    // integrity-stream checksum policy that requires initialized payload.
    ctl(&file, 0x9c280, &[0; 8], 0)?;
    let allocation = FILE_BYTES;
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            5,
            (&allocation as *const u64).cast(),
            8,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    file.set_len(FILE_BYTES)?;
    let before = observation(&file);
    let placement = if let Some(lcn) = destination_lcn {
        let volume = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(pair.shadow.volume_path()?)?;
        pair.shadow
            .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
        let partition = pair.shadow.identity.partition_bytes;
        let legacy =
            crate::bitmap_observation::Observation::capture(&volume, &[0; 8], partition, true)?;
        let mut extended = [0u8; 16];
        extended[8] = 1;
        let metadata =
            crate::bitmap_observation::Observation::capture(&volume, &extended, partition, true)?;
        let old = legacy.view(partition)?.candidate(lcn * 4096, VALID_BYTES)?;
        let all = metadata
            .view(partition)?
            .candidate(lcn * 4096, VALID_BYTES)?;
        if old.declared_clusters != partition / 4096
            || all.declared_clusters != partition / 4096
            || old.allocated_clusters != 0
            || all.allocated_clusters != 0
        {
            return Err(invalid(
                "private placement requires both live bitmap views free",
            ));
        }
        let mut input = [0u8; 32];
        input[..8].copy_from_slice(&(file.as_raw_handle() as usize as u64).to_le_bytes());
        input[16..24].copy_from_slice(&lcn.to_le_bytes());
        input[24..28].copy_from_slice(&((VALID_BYTES / 4096) as u32).to_le_bytes());
        let moved = ctl(&volume, 0x90074, &input, 0);
        let capture = crate::stream_native::retrieval_capture(&file)?;
        let mapped = super::mapping_matches_run(
            &crate::stream_layout::parse_complete_retrieval(&capture.canonical)?,
            0,
            lcn,
            (VALID_BYTES / 4096) as u32,
        )?;
        Some(
            serde_json::json!({"destination_lcn":lcn,"clusters":VALID_BYTES/4096,
            "starting_vcn":0,"submitted_once":true,"before_valid_data_advance":true,
            "native_error":moved.err().map(|e| e.raw_os_error().unwrap_or(31)),
            "mapping_matches":mapped,"mapping_after":capture.canonical,
            "mapping_page_proof":capture.proof,"legacy_candidate":old,
            "metadata_candidate":all,"after_move":observation(&file)}),
        )
    } else {
        None
    };
    let may_advance = placement
        .as_ref()
        .is_none_or(|p| p["mapping_matches"] == true && p["native_error"].is_null());
    // SAFETY: live new private file; manage-volume privilege was enabled when
    // opened. The positive VDL is strictly below EOF. Contents are never read.
    let ok = if may_advance {
        unsafe { SetFileValidData(file.as_raw_handle(), VALID_BYTES as i64) }
    } else {
        0
    };
    let valid_data_error =
        (may_advance && ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
    let immediate = observation(&file);
    file.sync_all()?;
    let after_flush = observation(&file);
    let source_after =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    if source_after != source_before {
        return Err(invalid("source exclusion or identity changed during probe"));
    }
    privilege.restore()?;
    Ok(serde_json::json!({
        "schema_version":1,"kind":"native-private-valid-data-probe","experiment_id":experiment,
        "path":path,"file_bytes":FILE_BYTES,"requested_valid_bytes":VALID_BYTES,
        "set_valid_data_succeeded":ok!=0,"set_valid_data_error":valid_data_error,
        "valid_data_call_submitted":may_advance,"placement":placement,
        "before":before,"immediate":immediate,"after_flush":after_flush,
        "source_before":source_before,"source_after":source_after,"shadow_before":shadow_before,
        "privileges":privilege.audit(),"events":events,"payload_write_calls":0,"payload_reads":0,
        "physical_payload_writes_measured":false,"file_retained_system_only":true,
        "extent_adoption_qualified":false,"conversion_qualified":false
    }))
}

/// Read metadata at the recorded private path on a read-only shadow. File-ID
/// equivalence is reported separately; mismatches never qualify adoption.
/// No privilege change, payload read, flush, valid-data call or write occurs.
pub fn observe_existing(
    pair: &GeneralSourceShadowBinding,
    experiment: &str,
    expected_file_id_info: &[u8],
) -> io::Result<serde_json::Value> {
    pair.validate_with_resource_profile(Some(
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    ))?;
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        || pair.source.disk_number != 1
        || pair.shadow.disk_number != 3
        || pair
            .source
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "1b191872-c372-41ee-a416-e18863996f54"
        || pair
            .shadow
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "c0f2cd39-ad3d-484e-9990-0e6eba74485f"
        || experiment.len() != 32
        || !experiment.bytes().all(|v| v.is_ascii_hexdigit())
        || expected_file_id_info.len() != 24
    {
        return Err(invalid("exact private-file observation fixture required"));
    }
    let mut events = Vec::new();
    let source_before =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    let shadow_before =
        native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
    if source_before.disk_attributes != 3 || shadow_before.disk_attributes != 2 {
        return Err(invalid(
            "excluded source and read-only ReFS shadow required",
        ));
    }
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(pair.shadow.volume_path()?)?;
    pair.shadow
        .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
    let mut filesystem = [0u16; 32];
    // SAFETY: live read-only volume handle and bounded initialized output.
    if unsafe {
        GetVolumeInformationByHandleW(
            volume.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem.as_mut_ptr(),
            32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if filesystem[..5] != [b'R' as u16, b'e' as u16, b'F' as u16, b'S' as u16, 0] {
        return Err(invalid("read-only probe volume is not ReFS"));
    }
    let path = format!(
        "{}\\n2r-valid-data-{experiment}.bin",
        pair.shadow.volume_path()?
    );
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&path)?;
    let standard = info(&file, 1, 24)?;
    let actual_id = info(&file, 18, 24)?;
    let identity_matches = actual_id.as_slice() == expected_file_id_info;
    // Deferred allocation can change when an unwritten tail is closed. Record
    // that observation rather than discarding all diagnostic evidence. This
    // does not relax any converter or extent-adoption gate.
    let metadata_matches = u64::from_le_bytes(standard[8..16].try_into().unwrap()) == FILE_BYTES
        && u32::from_le_bytes(standard[16..20].try_into().unwrap()) == 1
        && standard[20] == 0
        && standard[21] == 0;
    let before = observation(&file);
    let after = observation(&file);
    let source_after =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    let shadow_after =
        native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
    let after_id = info(&file, 18, 24)?;
    let after_standard = info(&file, 1, 24)?;
    if source_before != source_after || shadow_before != shadow_after {
        return Err(invalid(
            "private file or protected disk changed during observation",
        ));
    }
    Ok(serde_json::json!({
        "schema_version":1,"kind":"native-private-valid-data-observation",
        "experiment_id":experiment,"path":path,"expected_file_id_info":hex::encode(expected_file_id_info),
        "file_id_info_matches":identity_matches && after_id==actual_id,
        "observed_file_id_info":hex::encode(&actual_id),"after_file_id_info":hex::encode(&after_id),
        "file_metadata_matches":metadata_matches,"standard_info_stable":after_standard==standard,
        "before_standard_info":standard,"after_standard_info":after_standard,
        "before":before,"after":after,
        "source_before":source_before,"source_after":source_after,
        "shadow_before":shadow_before,"shadow_after":shadow_after,"events":events,
        "payload_write_calls":0,"payload_reads":0,"valid_data_calls":0,"privilege_changes":0,
        "extent_adoption_qualified":false,"conversion_qualified":false
    }))
}
