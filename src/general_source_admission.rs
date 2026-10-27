//! Live source admission for a dedicated NTFS data disk. Inspection alone
//! cannot issue a certificate; a bound frozen native target is also required.
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
    #[serde(skip)]
    context: AdmissionContext,
    pub comparison: ntfs_attestation::Comparison,
    pub assessment: ntfs_admission::Assessment,
    pub source_sha256: String,
    pub canonical_inspection_sha256: String,
    pub txf_evidence_sha256: Option<String>,
    pub txf_observation: Option<serde_json::Value>,
    pub short_name_creation_disabled: Option<bool>,
    pub queried_rm_stably_empty: Option<bool>,
    pub all_resource_managers_checked: bool,
    pub txf_error: Option<String>,
    pub internal_indexes: Option<crate::ntfs_internal::VerifiedIndexes>,
    pub internal_indexes_error: Option<String>,
    pub transaction_freeze: Option<crate::ntfs_transactions::VerifiedTransactions>,
    pub transaction_freeze_error: Option<String>,
    pub freeze_observation: Option<serde_json::Value>,
    pub internal_replacements: Option<Vec<ntfs_admission::InternalReplacement>>,
    pub source_admitted: bool,
    pub execution_authorized: bool,
}

#[derive(Debug)]
struct AdmissionContext {
    source_binding: n2r_win32::general_layout::GeneralDiskBinding,
    resources: ntfs_admission::ResourceProfile,
    source_sha256: String,
    inspection_sha256: String,
    source_gates_satisfied: bool,
    source_views_sha256: String,
}

/// Issued only after live source admission and same-tree native target
/// preservation pass. A serialized copy cannot recreate write authority.
#[derive(Debug, Serialize)]
pub struct SourceCertificate {
    source_sha256: String,
    inspection_sha256: String,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    comparison: crate::retained_compare::RetainedCompareRequest,
    expected_tree_sha256: String,
    assessment_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_resource_profile: Option<ntfs_admission::ResourceProfile>,
}
impl SourceCertificate {
    pub fn binds_request(&self, request: &crate::general_reconstruct::Request) -> bool {
        self.pair == request.pair
            && self.source_resource_profile == request.source_resource_profile
            && self.expected_tree_sha256 == request.expected_tree_sha256
            && self.source_sha256 == request.comparison.source_sha256
            && matches!((serde_json::to_vec(&self.comparison), serde_json::to_vec(&request.comparison)),
                (Ok(a),Ok(b)) if a == b)
    }
}
impl LiveAssessment {
    pub fn qualify_target(
        &mut self,
        raw: &ntfs_inspect::NtfsInspection,
        target: &crate::general_target_preservation::FrozenTargetPreservation,
    ) -> Result<SourceCertificate> {
        ensure!(
            self.context.source_gates_satisfied
                && target.pair().source == self.context.source_binding
                && target.native_resource_profile() == self.context.resources.native_profile()
                && self.source_sha256 == self.context.source_sha256
                && self.canonical_inspection_sha256 == self.context.inspection_sha256
                && target.binds(raw, &self.source_sha256)
                && target.source_views_sha256() == self.context.source_views_sha256
                && self.canonical_inspection_sha256 == self.assessment.source_inspection_sha256
                && self.assessment.source_view.as_ref().is_some_and(|view| view
                    .binds_live_source(&self.canonical_inspection_sha256, &self.source_sha256)
                    && serde_json::to_vec(view).is_ok_and(|bytes| hex::encode(Sha256::digest(
                        bytes
                    )) == self
                        .context
                        .source_views_sha256)),
            "source admission is refused or target preservation differs from the original live device context"
        );
        for gate in &mut self.assessment.gates {
            if gate.code == "security_timestamp_preservation" {
                gate.satisfied = true;
                gate.detail = "actual native ReFS tree verified stored times, descriptors, attributes, namespace and contents; the same target was locked/dismounted and its complete image hash bound".into();
            } else if gate.code == "target_resource_profile_support" {
                ensure!(
                    self.context.resources.native_profile().is_some(),
                    "unexpected expanded target gate on an alpha source"
                );
                gate.satisfied = true;
                gate.detail = "the opaque protected ReFS target observation verified the same expanded resource profile and the exact frozen-source semantic tree".into();
            }
        }
        let refusals: Vec<_> = self
            .assessment
            .gates
            .iter()
            .filter(|g| !g.satisfied)
            .map(|g| g.code.as_str())
            .collect();
        ensure!(
            refusals.is_empty(),
            "source admission remains refused: {refusals:?}"
        );
        self.source_admitted = true;
        self.assessment.source_admitted = true;
        self.assessment.certificate_issued = true;
        Ok(SourceCertificate {
            source_sha256: self.source_sha256.clone(),
            inspection_sha256: self.canonical_inspection_sha256.clone(),
            pair: target.pair().clone(),
            comparison: target.comparison().clone(),
            expected_tree_sha256: target.expected_tree_sha256().into(),
            assessment_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&self)?)),
            source_resource_profile: match self.context.resources {
                ntfs_admission::ResourceProfile::AlphaV1 => None,
                resource => Some(resource),
            },
        })
    }
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
    let resources = match (
        observed.report().request.schema_version,
        observed.report().request.resource_profile,
    ) {
        (2, None) => ntfs_admission::ResourceProfile::AlphaV1,
        (3, Some(n2r_win32::attestation::ResourceProfile::ExperimentalLargeTreeV1)) => {
            ntfs_admission::ResourceProfile::ExperimentalLargeTreeV1
        }
        (3, Some(n2r_win32::attestation::ResourceProfile::ExperimentalStreamingTreeV2)) => {
            ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2
        }
        _ => anyhow::bail!("unsupported or mismatched native source resource profile"),
    };
    ensure!(
        canonical_inspection_sha256 == hex::encode(Sha256::digest(serde_json::to_vec(raw)?))
            && backups.binds(raw)
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
    let source_sha256 = hex::encode(lab_reconstruct::hash_range_with_resource_profile(
        source,
        0,
        source.byte_len(),
        resources,
    )?);
    let after = source.state(events)?;
    ensure!(
        before == after && source_sha256 == expected_source_sha256,
        "general source changed since the native observation"
    );
    let comparison =
        ntfs_attestation::compare(raw, canonical_inspection_sha256, observed.report())?;
    let mut view = ntfs_source_view::diagnose(raw, canonical_inspection_sha256, observed.report())?;
    view.bind_frozen_source(&source_sha256);
    let mut assessment = ntfs_admission::assess_ordinary_source_view_with_resources(
        raw,
        &comparison,
        observed.report().schema_version,
        Some(backups),
        Some(view),
        resources,
    );
    for gate in &mut assessment.gates {
        if gate.code == "frozen_device_basis" {
            gate.satisfied = true;
            gate.detail = "actual dedicated disk remained offline/read-only and matched the complete pinned source hash after native collection".into();
        }
    }
    if resources.native_profile().is_some() {
        ntfs_admission::bind_large_native_profile(&mut assessment, raw, observed, &source_sha256)?;
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
    let (internal_indexes, internal_indexes_error) = match crate::ntfs_internal::verify(source, raw)
    {
        Ok(mut proof) => {
            proof.bind_native_quota(observed);
            (Some(proof), None)
        }
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    if let Some(indexes) = &internal_indexes {
        ntfs_admission::bind_internal_volume_identity(&mut assessment, raw, indexes);
    }
    assessment.gates.push(ntfs_admission::Gate {
        code: "internal_indexes".into(),
        satisfied: internal_indexes.as_ref().is_some_and(|proof| proof.binds(raw) && proof.replacement_supported),
        detail: "reread object-ID, reparse and quota indexes must contain supported empty/default state or the exact cross-bound internal volume identity; user object IDs and transaction replacement remain separate".into(),
    });
    let (transaction_freeze, transaction_freeze_error) = match (source.freeze_observation(), log_restart) {
        (Some(freeze), Some(log)) => match crate::ntfs_transactions::verify(raw,log,freeze,observed) {
            Ok(proof) => (Some(proof),None), Err(error) => (None,Some(format!("{error:#}"))),
        },
        _ => (None,Some("actual observed lock/dismount freeze and clean restart evidence are required; reopening cannot recreate this witness".into())),
    };
    assessment.gates.push(ntfs_admission::Gate {
        code:"transaction_freeze".into(),
        satisfied:transaction_freeze.as_ref().is_some_and(|proof|proof.binds(raw)),
        detail:"idle/inactive native default RM, actual lock/dismount exclusion, clean restart copies and empty deferred namespaces must agree".into(),
    });
    let internal_replacements = match (&internal_indexes, &transaction_freeze) {
        (Some(indexes), Some(transactions)) => {
            ntfs_admission::bind_internal_replacement(&mut assessment, raw, indexes, transactions)
        }
        _ => None,
    };
    let context = AdmissionContext {
        source_views_sha256: hex::encode(Sha256::digest(serde_json::to_vec(
            &assessment.source_view,
        )?)),
        source_binding: source.binding().clone(),
        resources,
        source_sha256: source_sha256.clone(),
        inspection_sha256: canonical_inspection_sha256.into(),
        source_gates_satisfied: assessment
            .gates
            .iter()
            .filter(|g| {
                g.code != "security_timestamp_preservation"
                    && g.code != "target_resource_profile_support"
            })
            .all(|g| g.satisfied),
    };
    Ok(LiveAssessment {
        context,
        comparison,
        assessment,
        source_sha256,
        canonical_inspection_sha256: canonical_inspection_sha256.into(),
        txf_evidence_sha256,
        txf_observation: txf.map(serde_json::to_value).transpose()?,
        short_name_creation_disabled,
        queried_rm_stably_empty: txf.map(|evidence| evidence.observation.queried_rm_stably_empty),
        all_resource_managers_checked: txf
            .is_some_and(|evidence| evidence.observation.all_resource_managers_checked),
        txf_error: observed.txf_error().map(str::to_owned),
        internal_indexes,
        internal_indexes_error,
        transaction_freeze,
        transaction_freeze_error,
        internal_replacements,
        freeze_observation: source
            .freeze_observation()
            .map(serde_json::to_value)
            .transpose()?,
        source_admitted: false,
        execution_authorized: false,
    })
}
