//! Bounded owning-guest experiment, outside the converter construction path.
//! Creates one SYSTEM-only file on the enrolled shadow; never reads its data.
use super::{GetVolumeInformationByHandleW, ctl, info, invalid, native, snapshot};
use crate::{attestation_native::Privileges, general_layout::GeneralSourceShadowBinding};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
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
    run_inner(pair, experiment, &[], false)
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
    run_inner(
        pair,
        experiment,
        &[(0, destination_lcn, (VALID_BYTES / 4096) as u32)],
        false,
    )
}

pub fn run_split(
    pair: &GeneralSourceShadowBinding,
    experiment: &str,
    first_lcn: u64,
    second_lcn: u64,
) -> io::Result<serde_json::Value> {
    let clusters = (VALID_BYTES / 4096 / 2) as u32;
    run_inner(
        pair,
        experiment,
        &[
            (0, first_lcn, clusters),
            (u64::from(clusters), second_lcn, clusters),
        ],
        false,
    )
}

pub fn run_repositioned(
    pair: &GeneralSourceShadowBinding,
    experiment: &str,
    temporary_lcn: u64,
    final_lcn: u64,
) -> io::Result<serde_json::Value> {
    let clusters = (VALID_BYTES / 4096) as u32;
    run_inner(
        pair,
        experiment,
        &[
            (0, temporary_lcn, clusters),
            (u64::from(clusters / 4), final_lcn, clusters / 4),
        ],
        true,
    )
}

fn run_inner(
    pair: &GeneralSourceShadowBinding,
    experiment: &str,
    requested: &[(u64, u64, u32)],
    reposition: bool,
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
    let mut placeholder = super::unwritten::PrivatePlaceholder::allocate(
        &pair.shadow.volume_path()?,
        experiment,
        FILE_BYTES,
        pair.shadow.identity.partition_bytes,
    )?;
    let path = placeholder.path.clone();
    let before = observation(placeholder.metadata_handle());
    let mut placements = Vec::new();
    if !requested.is_empty() {
        let volume = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(pair.shadow.volume_path()?)?;
        pair.shadow
            .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
        for (index, &(vcn, lcn, clusters)) in requested.iter().enumerate() {
            let attempt = if reposition && index > 0 {
                placeholder.reposition(&volume, vcn, lcn, clusters)?
            } else {
                placeholder.place(&volume, vcn, lcn, clusters)?
            };
            let matched = attempt.mapping_matches
                && attempt.all_placements_match
                && attempt.native_error.is_none();
            let mut value = serde_json::to_value(attempt).map_err(io::Error::other)?;
            value["after_move"] = observation(placeholder.metadata_handle());
            placements.push(value);
            if !matched {
                break;
            }
        }
    }
    let may_advance = placements.len() == requested.len()
        && placements.iter().all(|p| {
            p["mapping_matches"] == true
                && p["all_placements_match"] == true
                && p["native_error"].is_null()
        });
    let advancement =
        may_advance.then(|| placeholder.advance_valid_data(VALID_BYTES, !requested.is_empty()));
    let ok = advancement.as_ref().is_some_and(|result| result.is_ok());
    let valid_data_error = advancement
        .and_then(Result::err)
        .map(|error| error.raw_os_error().unwrap_or(31));
    let file = placeholder.metadata_handle();
    let immediate = observation(file);
    file.sync_all()?;
    let after_flush = observation(file);
    let source_after =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    if source_after != source_before {
        return Err(invalid("source exclusion or identity changed during probe"));
    }
    privilege.restore()?;
    Ok(serde_json::json!({
        "schema_version":if requested.len()>1 {2}else{1},"kind":"native-private-valid-data-probe","experiment_id":experiment,
        "path":path,"file_bytes":FILE_BYTES,"requested_valid_bytes":VALID_BYTES,
        "set_valid_data_succeeded":ok,"set_valid_data_error":valid_data_error,
        "valid_data_call_submitted":may_advance,"placement":if placements.len()==1 {placements.first()}else{None},
        "placements":placements,"advance_includes_flush_and_mapping_recheck":true,
        "planned_repositioning":reposition,
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
