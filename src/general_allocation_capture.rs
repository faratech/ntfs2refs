//! Lock-stage allocation evidence for future target write-set qualification.
//! This module cannot authorize reconstruction or replay.
use crate::{general_qualification as artifacts, refs_inspect};
use anyhow::{Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition,
    general_layout::GeneralDiskBinding,
    volume_label::{self, VolumeLabel},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
mod ownership;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub binding: GeneralDiskBinding,
    pub expected_label: VolumeLabel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_profile: Option<crate::ntfs_admission::ResourceProfile>,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.expected_label.validate()?;
        if let Some(resources) = self.resource_profile {
            resources.count_admission()?;
        }
        ensure!(
            matches!(
                (self.schema_version, self.resource_profile),
                (1, None)
                    | (
                        2,
                        Some(crate::ntfs_admission::ResourceProfile::ExperimentalLargeTreeV1 | crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2 | crate::ntfs_admission::ResourceProfile::ExperimentalObjectEnvelopeV3(_))
                    )
            ),
            "allocation capture schema differs"
        );
        Ok(())
    }
}

/// Leaves the selected disk offline/read-only. Reporting errors never bring
/// it online; the lab operator must inspect its actual state before recovery.
pub fn capture(request: &Request, output: &Path) -> Result<()> {
    capture_profile(request, output)
}

/// Collect the required graph and raw/native allocation comparison through
/// the same live freeze witness. This remains a read-only observation.
pub fn capture_with_required_ownership(request: &Request, output: &Path) -> Result<()> {
    capture_readonly_profile(request, output)
}

fn capture_profile(request: &Request, output: &Path) -> Result<()> {
    request.validate()?;
    artifacts::create_output(output)?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({
        "schema_version":1,"kind":"locked-refs-allocation-capture-intent",
        "request":request,"leaves_disk_offline_read_only":true,
        "required_ownership_requested":false,
        "raw_writes_authorized":false,"reconstruction_authorized":false}),
    )?;
    let mut events = Vec::new();
    let mut phase = "mounted-source";
    let attempted = (|| -> Result<()> {
        let before = volume_label::observe_label(request.binding.clone(), "ReFS")?;
        ensure!(
            before.label == request.expected_label,
            "capture label differs"
        );
        artifacts::save(output, "mounted-before.json", &before)?;
        phase = "allocation-freeze";
        let (mut frozen, witness) =
            GeneralFrozenPartition::isolate_with_allocation_with_resource_profile(
                request.binding.clone(),
                request
                    .resource_profile
                    .and_then(|profile| profile.native_profile()),
                &mut events,
            )?;
        ensure!(
            witness.schema_version() == request.schema_version,
            "allocation witness profile differs"
        );
        frozen.validate_allocation_witness(&witness, &mut events)?;
        artifacts::save(output, "allocation-freeze.json", &witness)?;
        phase = "frozen-bootstrap";
        let length = frozen.byte_len();
        let refs = refs_inspect::inspect(&mut frozen, length)?;
        ensure!(
            refs.geometry.major_version == 3
                && refs.geometry.minor_version == 14
                && refs.geometry.bytes_per_cluster == 4096
                && refs.geometry.bytes_per_sector == 512
                && refs.geometry.volume_bytes == length,
            "frozen ReFS profile differs"
        );
        artifacts::save(output, "frozen-refs.json", &refs)?;
        let state = frozen.state(&mut events)?;
        ensure!(
            state.disk_attributes == 3,
            "capture lost persistent exclusion"
        );
        frozen.validate_allocation_witness(&witness, &mut events)?;
        artifacts::save(output, "events.json", &events)?;
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({
            "schema_version":1,"kind":"locked-refs-allocation-capture","success":true,
            "binding":request.binding,"frozen_state":state,"raw_source_writes":0,
            "complete_metadata_graph_proven":false,"reconstruction_authorized":false,
            "disk_left_offline_read_only":true}),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        artifacts::save(output, "events.json", &events)?;
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({
            "schema_version":1,"kind":"locked-refs-allocation-capture-failure",
            "phase":phase,"error":format!("{error:#}"),
            "automatic_online_restore_attempted":false,"raw_writes_authorized":false}),
        )?;
        return Err(error);
    }
    Ok(())
}

fn capture_readonly_profile(request: &Request, output: &Path) -> Result<()> {
    request.validate()?;
    ensure!(
        request.resource_profile.is_some_and(|p| p.is_streaming()),
        "protected allocation ownership needs the explicit streaming-v2 profile"
    );
    artifacts::create_output(output)?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({
            "schema_version":2,"kind":"protected-readonly-refs-ownership-intent","request":request,
            "allocation_query_phase":"protected-readonly-mount-after-freeze",
            "post_lock_bitmap_required":false,"raw_writes_authorized":false,"reconstruction_authorized":false,
            "leaves_disk_offline_read_only":true
        }),
    )?;
    let mut events = Vec::new();
    let mut phase = "mounted-source";
    let attempted = (|| -> Result<()> {
        let before = volume_label::observe_label(request.binding.clone(), "ReFS")?;
        ensure!(
            before.label == request.expected_label,
            "capture label differs"
        );
        artifacts::save(output, "mounted-before.json", &before)?;
        phase = "isolate-without-post-lock-query";
        let mut frozen = GeneralFrozenPartition::isolate(request.binding.clone(), &mut events)?;
        phase = "protected-readonly-allocation";
        let witness = frozen.observe_refs_allocation_readonly(
            request.resource_profile.and_then(|p| p.native_profile()),
            &mut events,
        )?;
        frozen.validate_readonly_allocation_witness(&witness, &mut events)?;
        artifacts::save(output, "readonly-allocation.json", &witness)?;
        phase = "frozen-required-ownership";
        let report = ownership::collect(
            &mut frozen,
            &witness,
            request.resource_profile.unwrap_or_default(),
            &mut events,
        )?;
        artifacts::save(output, "required-ownership.json", &report)?;
        let state = frozen.state(&mut events)?;
        frozen.validate_readonly_allocation_witness(&witness, &mut events)?;
        artifacts::save(output, "events.json", &events)?;
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({
                "schema_version":2,"kind":"protected-readonly-refs-ownership-capture","success":true,
                "binding":request.binding,"frozen_state":state,"raw_source_writes":0,
                "complete_metadata_graph_proven":false,"reconstruction_authorized":false,
                "disk_left_offline_read_only":true
            }),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        artifacts::save(output, "events.json", &events)?;
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({
                "schema_version":2,"kind":"protected-readonly-refs-ownership-failure","phase":phase,
                "error":format!("{error:#}"),"automatic_online_restore_attempted":false,"raw_writes_authorized":false
            }),
        )?;
        return Err(error);
    }
    Ok(())
}
