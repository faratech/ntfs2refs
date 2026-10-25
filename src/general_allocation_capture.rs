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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub binding: GeneralDiskBinding,
    pub expected_label: VolumeLabel,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.expected_label.validate()?;
        ensure!(
            self.schema_version == 1,
            "allocation capture schema differs"
        );
        Ok(())
    }
}

/// Leaves the selected disk offline/read-only. Reporting errors never bring
/// it online; the lab operator must inspect its actual state before recovery.
pub fn capture(request: &Request, output: &Path) -> Result<()> {
    request.validate()?;
    artifacts::create_output(output)?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({
        "schema_version":1,"kind":"locked-refs-allocation-capture-intent",
        "request":request,"leaves_disk_offline_read_only":true,
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
            GeneralFrozenPartition::isolate_with_allocation(request.binding.clone(), &mut events)?;
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
