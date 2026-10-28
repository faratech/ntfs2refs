//! Fresh source facts for an already excluded disk. This is deliberately not
//! a substitute for the live transaction-freeze or target-preservation witness.
//! No deserializer, writer constructor or source-activation route is exposed.
use crate::{
    general_reconstruct, general_source_admission, lab_reconstruct, ntfs_admission,
    ntfs_attestation, ntfs_backup, ntfs_inspect, ntfs_log, shadow_tree, source_volume_label,
};
use anyhow::{Result, ensure};
use n2r_win32::{GeneralDiskState, GeneralFrozenPartition, NativeEvent};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct FrozenSourceAssessment {
    source_binding: n2r_win32::general_layout::GeneralDiskBinding,
    resource_profile: ntfs_admission::ResourceProfile,
    source_sha256: String,
    canonical_inspection_sha256: String,
    semantic_tree_sha256: Option<String>,
    source_before: GeneralDiskState,
    source_after: GeneralDiskState,
    raw: ntfs_inspect::NtfsInspection,
    backups: ntfs_backup::VerifiedBackups,
    log_restart: ntfs_log::VerifiedRestart,
    label: Option<source_volume_label::FrozenLabelProof>,
    native_observation: serde_json::Value,
    assessment: general_source_admission::LiveAssessment,
    source_refusals: Vec<String>,
    expected_tree_matches: bool,
    original_live_freeze_witness_present: bool,
    source_admitted: bool,
    execution_authorized: bool,
}
impl FrozenSourceAssessment {
    pub fn source_refusals(&self) -> &[String] {
        &self.source_refusals
    }
    pub fn assessment(&self) -> &general_source_admission::LiveAssessment {
        &self.assessment
    }
    pub fn raw(&self) -> &ntfs_inspect::NtfsInspection {
        &self.raw
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub fn semantic_tree_sha256(&self) -> Option<&str> {
        self.semantic_tree_sha256.as_deref()
    }
    /// Identity/content correlation only. This method never supplies the
    /// missing live-freeze/target witness or grants conversion authority.
    pub fn binds_request(&self, request: &general_reconstruct::Request) -> bool {
        self.source_binding == request.pair.source
            && self.resource_profile == request.source_resource_profile.unwrap_or_default()
            && self.source_sha256 == request.comparison.source_sha256
            && self.semantic_tree_sha256.as_deref() == Some(request.expected_tree_sha256.as_str())
    }
    pub fn require_source_gates(&self) -> Result<()> {
        ensure!(
            self.source_refusals.is_empty() && self.expected_tree_matches,
            "already-frozen source remains unadmitted: {:?}; expected tree matched={}",
            self.source_refusals,
            self.expected_tree_matches
        );
        Ok(())
    }
}

/// Reread the original disk, backup/log/internal structures and full contents,
/// collect genuine native metadata/logical data through a physically read-only
/// observation lease, and recheck its complete hash. The existing admission
/// gates remain unchanged; in particular reopening cannot recreate the old
/// online-to-lock transaction witness. Callers must preserve those refusals.
pub fn assess(
    source: &mut GeneralFrozenPartition,
    request: &general_reconstruct::Request,
    events: &mut Vec<NativeEvent>,
) -> Result<FrozenSourceAssessment> {
    request.validate()?;
    ensure!(
        source.binding() == &request.pair.source,
        "frozen assessment source binding differs"
    );
    let resources = request.source_resource_profile.unwrap_or_default();
    let before = source.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "already excluded read-only source required"
    );
    let length = source.byte_len();
    let source_sha256 = hex::encode(lab_reconstruct::hash_range_with_resource_profile(
        source, 0, length, resources,
    )?);
    ensure!(
        source_sha256 == request.comparison.source_sha256,
        "frozen source differs from prepared compact journal preimage"
    );
    let raw = ntfs_inspect::inspect_with_limits(
        source,
        length,
        ntfs_inspect::limits_for_resource_profile(resources),
    )?;
    ensure!(
        resources.supports_source_geometry(&raw.geometry),
        "frozen source geometry exceeds profile"
    );
    let pin = hex::encode(Sha256::digest(serde_json::to_vec(&raw)?));
    let backups = ntfs_backup::verify(source, length, &raw)?;
    let log_restart = ntfs_log::verify(source, &raw)?;
    let label = request
        .expected_source_label
        .as_ref()
        .map(|label| source_volume_label::verify(source, &raw, label))
        .transpose()?;
    let native_request = if let Some(profile) = resources.native_profile() {
        ntfs_attestation::request_for_general_inspection_with_profile(
            &raw,
            &pin,
            source.binding(),
            profile,
        )?
    } else {
        ntfs_attestation::request_for_general_inspection(&raw, &pin, source.binding())?
    };
    let observed = source.observe_ntfs_files(&native_request, events)?;
    let native_observation = serde_json::to_value(&observed)?;
    let assessment = general_source_admission::assess(
        source,
        &raw,
        &pin,
        &source_sha256,
        &backups,
        Some(&log_restart),
        &observed,
        events,
    )?;
    let mut source_refusals: Vec<_> = assessment
        .assessment
        .gates
        .iter()
        .filter(|g| {
            g.code != "security_timestamp_preservation"
                && g.code != "target_resource_profile_support"
                && !g.satisfied
        })
        .map(|g| g.code.clone())
        .collect();
    // Do not fabricate a target-matching tree if source view diagnosis failed.
    let semantic_tree_sha256 = if let Some(views) = assessment.assessment.source_view.as_ref() {
        let tree = (|| -> Result<_> {
            let mut tree = shadow_tree::derive_ordinary_with_resource_profile(&raw, resources)?;
            tree.bind_security_views(views)?;
            let expected = shadow_tree::ExpectedTree::from(&tree);
            expected.validate_with_resource_profile(resources)?;
            Ok(hex::encode(Sha256::digest(serde_json::to_vec_pretty(
                &expected,
            )?)))
        })();
        match tree {
            Ok(pin) => Some(pin),
            Err(error) => {
                source_refusals.push(format!("canonical_source_tree: {error:#}"));
                None
            }
        }
    } else {
        source_refusals.push("canonical_source_tree: source views absent".into());
        None
    };
    let expected_tree_matches =
        semantic_tree_sha256.as_deref() == Some(request.expected_tree_sha256.as_str());
    if !expected_tree_matches {
        source_refusals.push("expected_tree_binding".into());
    }
    let after = source.state(events)?;
    ensure!(
        before == after,
        "source exclusion/identity changed during frozen assessment"
    );
    let original_live_freeze_witness_present = source.freeze_observation().is_some();
    // The old source certificate's admission and target-preservation requirements
    // are intentionally neither rewritten nor silently marked satisfied here.
    ensure!(
        !assessment.source_admitted && !assessment.execution_authorized,
        "source-only assessment unexpectedly authorized conversion"
    );
    Ok(FrozenSourceAssessment {
        source_binding: source.binding().clone(),
        resource_profile: resources,
        source_sha256,
        canonical_inspection_sha256: pin,
        semantic_tree_sha256,
        source_before: before,
        source_after: after,
        raw,
        backups,
        log_restart,
        label,
        native_observation,
        assessment,
        source_refusals,
        expected_tree_matches,
        original_live_freeze_witness_present,
        source_admitted: false,
        execution_authorized: false,
    })
}
