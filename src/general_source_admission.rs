//! Live, device-bound source diagnostics for a dedicated NTFS data disk. This
//! does not issue an admission certificate or authorize journal activation.
use crate::{
    lab_reconstruct, ntfs_admission, ntfs_attestation, ntfs_backup, ntfs_inspect, ntfs_log,
    ntfs_source_view,
};
use anyhow::{Result, ensure};
use n2r_win32::{GeneralFrozenPartition, GeneralLiveNtfsObservation, NativeEvent};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct LiveAssessment {
    pub comparison: ntfs_attestation::Comparison,
    pub assessment: ntfs_admission::Assessment,
    pub source_sha256: String,
    pub canonical_inspection_sha256: String,
    pub source_admitted: bool,
    pub execution_authorized: bool,
}

pub fn assess(
    source: &mut GeneralFrozenPartition,
    raw: &ntfs_inspect::NtfsInspection,
    canonical_inspection_sha256: &str,
    expected_source_sha256: &str,
    backups: &ntfs_backup::VerifiedBackups,
    log_restart: Option<&ntfs_log::VerifiedRestart>,
    observed: &GeneralLiveNtfsObservation,
    events: &mut Vec<NativeEvent>,
) -> Result<LiveAssessment> {
    ensure!(
        canonical_inspection_sha256 == hex::encode(Sha256::digest(serde_json::to_vec(raw)?))
            && backups.binds(raw)
            && observed.report().request.schema_version == 2
            && observed.report().request.disk_number == source.binding().disk_number
            && observed.report().request.partition_offset
                == source.binding().identity.partition_offset
            && observed.report().request.partition_length == source.byte_len()
            && observed.report().request.source_inspection_sha256 == canonical_inspection_sha256,
        "general live source, backup or native inspection identity differs"
    );
    let before = source.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "general source is not offline read-only"
    );
    let source_sha256 = hex::encode(lab_reconstruct::hash_range(source, 0, source.byte_len())?);
    let after = source.state(events)?;
    ensure!(
        before == after && source_sha256 == expected_source_sha256,
        "general source changed since the native observation"
    );
    let comparison =
        ntfs_attestation::compare(raw, canonical_inspection_sha256, observed.report())?;
    let mut view = ntfs_source_view::diagnose(raw, canonical_inspection_sha256, observed.report())?;
    view.bind_frozen_source(&source_sha256);
    let mut assessment = ntfs_admission::assess_ordinary_source_view(
        raw,
        &comparison,
        observed.report().schema_version,
        Some(backups),
        Some(view),
    );
    for gate in &mut assessment.gates {
        if gate.code == "frozen_device_basis" {
            gate.satisfied = true;
            gate.detail = "actual dedicated disk remained offline/read-only and matched the complete pinned source hash after native collection".into();
        }
        if gate.code == "log_restart_pages" && log_restart.is_some_and(|proof| proof.binds(raw)) {
            gate.satisfied = true;
            gate.detail = "both clean NTFS restart copies matched the frozen source; full log replay remains unproven".into();
        }
    }
    Ok(LiveAssessment {
        comparison,
        assessment,
        source_sha256,
        canonical_inspection_sha256: canonical_inspection_sha256.into(),
        source_admitted: false,
        execution_authorized: false,
    })
}
