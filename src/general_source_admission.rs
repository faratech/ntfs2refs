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
    pub txf_evidence_sha256: Option<String>,
    pub short_name_creation_disabled: Option<bool>,
    pub queried_rm_stably_empty: Option<bool>,
    pub all_resource_managers_checked: bool,
    pub txf_error: Option<String>,
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
    }
    if let Some(proof) = log_restart {
        ntfs_admission::bind_clean_log(&mut assessment, raw, proof);
    }
    let txf = observed.txf();
    let txf_evidence_sha256 = txf
        .map(|evidence| {
            serde_json::to_vec(evidence).map(|bytes| hex::encode(Sha256::digest(bytes)))
        })
        .transpose()?;
    let short_name_creation_disabled = txf.and_then(|evidence| {
        evidence
            .observation
            .short_name_state_stable
            .then(|| {
                evidence
                    .observation
                    .persistent_state_before
                    .as_ref()
                    .map(|state| state.short_name_creation_disabled)
            })
            .flatten()
    });
    ntfs_admission::bind_short_name_policy(&mut assessment, raw, observed);
    Ok(LiveAssessment {
        comparison,
        assessment,
        source_sha256,
        canonical_inspection_sha256: canonical_inspection_sha256.into(),
        txf_evidence_sha256,
        short_name_creation_disabled,
        queried_rm_stably_empty: txf.map(|evidence| evidence.observation.queried_rm_stably_empty),
        all_resource_managers_checked: txf
            .is_some_and(|evidence| evidence.observation.all_resource_managers_checked),
        txf_error: observed.txf_error().map(str::to_owned),
        source_admitted: false,
        execution_authorized: false,
    })
}
