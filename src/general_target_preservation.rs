//! Freeze the ReFS target, verify its native semantics while read-only, and
//! bracket that observation with unchanged raw-image hashes. Serialized reports cannot create
//! this witness or supply an unfrozen target to journal activation.
use crate::{
    general_shadow, lab_reconstruct, ntfs_attestation, ntfs_inspect, refs_inspect,
    refs_retained_allocation, shadow_tree, tree_placement,
};
use anyhow::{Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, GeneralLiveRefsObservation, NativeEvent,
    general_layout::GeneralSourceShadowBinding,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek},
    path::Path,
};

fn bracket_image<R: Read + Seek, T>(
    image: &mut R,
    length: u64,
    observe: impl FnOnce(&mut R) -> Result<T>,
) -> Result<(T, String)> {
    let before = lab_reconstruct::hash_range(image, 0, length)?;
    let observation = observe(image)?;
    let after = lab_reconstruct::hash_range(image, 0, length)?;
    ensure!(
        before == after,
        "protected semantic observation changed frozen image bytes"
    );
    Ok((observation, hex::encode(after)))
}

/// Native semantics of an exact, protected image. This is not source admission
/// or a complete ReFS allocator/metadata-graph proof.
#[derive(Debug, Serialize)]
pub struct ProtectedTargetSemantics {
    native: GeneralLiveRefsObservation,
    target_sha256: String,
    expected_tree_sha256: String,
    frozen_state: GeneralDiskState,
}
impl ProtectedTargetSemantics {
    pub fn native(&self) -> &GeneralLiveRefsObservation {
        &self.native
    }
    pub fn target_sha256(&self) -> &str {
        &self.target_sha256
    }
}

pub fn verify_frozen_tree(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &shadow_tree::ExpectedTree,
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetSemantics> {
    verify_frozen_tree_with_resource_profile(
        target,
        pair,
        expected,
        crate::ntfs_admission::ResourceProfile::AlphaV1,
        events,
    )
}

pub fn verify_frozen_tree_with_resource_profile(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &shadow_tree::ExpectedTree,
    resources: crate::ntfs_admission::ResourceProfile,
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetSemantics> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    expected.validate_with_resource_profile(resources)?;
    ensure!(
        target.binding() == &pair.shadow,
        "protected target binding differs"
    );
    let before = target.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "target must be frozen before semantic observation"
    );
    let tree = shadow_tree::Tree {
        profile: resources.ordinary_shadow_profile(),
        objects: expected.objects.clone(),
        logical_bytes: expected.logical_bytes,
        internal_replacement_pending: expected.internal_replacement_pending.clone(),
    };
    let input = general_shadow::native_inputs(&tree);
    let length = target.byte_len();
    let (native, target_sha256) = bracket_image(target, length, |target| {
        Ok(target.observe_refs_files_with_resource_profile(
            pair,
            &input,
            |a, b| {
                ntfs_attestation::same_security(a, b)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            },
            resources.native_profile(),
            events,
        )?)
    })?;
    ensure!(
        native.before() == &before && native.after() == &before && target.state(events)? == before,
        "protected target observation changed persistent exclusion"
    );
    Ok(ProtectedTargetSemantics {
        native,
        target_sha256,
        expected_tree_sha256: hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?)),
        frozen_state: before,
    })
}

/// Qualify the same protected contract without source admission or writes.
pub fn observe_frozen_run(
    pair: GeneralSourceShadowBinding,
    expected: &shadow_tree::ExpectedTree,
    output: &Path,
) -> Result<()> {
    use crate::general_qualification as artifacts;
    pair.validate()?;
    expected.validate()?;
    artifacts::create_output(output)?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({
        "kind":"protected-frozen-target-observation-intent","pair":pair,
        "expected_tree_sha256":hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?)),
        "source_admission_authorized":false,"raw_writes_authorized":false}),
    )?;
    let mut events = Vec::new();
    let attempted = (|| -> Result<()> {
        let state =
            n2r_win32::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
        let mut target = match state.disk_attributes {
            0 => GeneralFrozenPartition::isolate(pair.shadow.clone(), &mut events)?,
            3 => GeneralFrozenPartition::reopen(pair.shadow.clone(), &mut events)?,
            _ => anyhow::bail!(
                "target must be mounted writable or persistently frozen before observation"
            ),
        };
        let proof = verify_frozen_tree(&mut target, pair, expected, &mut events)?;
        artifacts::save(output, "protected-semantics.json", &proof)?;
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({
            "kind":"protected-frozen-target-observation","success":true,
            "target_sha256":proof.target_sha256(),"objects":expected.objects.len(),
            "frozen_image_unchanged":true,"disk_left_offline_read_only":true,
            "source_admission_authorized":false,"raw_writes_authorized":false}),
        )?;
        Ok(())
    })();
    artifacts::save(output, "events.json", &events)?;
    if let Err(error) = attempted {
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({
            "kind":"protected-frozen-target-observation-failure","error":format!("{error:#}"),
            "raw_writes_authorized":false,"automatic_writable_retry":false}),
        )?;
        return Err(error);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct FrozenTargetPreservation {
    pair: GeneralSourceShadowBinding,
    inspection_sha256: String,
    source_sha256: String,
    target_sha256: String,
    expected_tree_sha256: String,
    native: ProtectedTargetSemantics,
    target_sha256_before_observation: String,
    before: GeneralDiskState,
    after: GeneralDiskState,
    placement: tree_placement::Plan,
    comparison: crate::retained_compare::RetainedCompareRequest,
    refs: refs_inspect::RefsInspection,
    retained_allocation: Option<refs_retained_allocation::Coverage>,
    source_views_sha256: String,
}

impl FrozenTargetPreservation {
    pub fn binds(&self, raw: &ntfs_inspect::NtfsInspection, source_sha256: &str) -> bool {
        self.source_sha256 == source_sha256
            && serde_json::to_vec(raw)
                .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
    }
    pub fn comparison(&self) -> &crate::retained_compare::RetainedCompareRequest {
        &self.comparison
    }
    pub fn expected_tree_sha256(&self) -> &str {
        &self.expected_tree_sha256
    }
    pub fn pair(&self) -> &GeneralSourceShadowBinding {
        &self.pair
    }
    pub(crate) fn source_views_sha256(&self) -> &str {
        &self.source_views_sha256
    }
    pub(crate) fn native_resource_profile(
        &self,
    ) -> Option<n2r_win32::attestation::ResourceProfile> {
        self.native.native().report().native.resource_profile
    }
}

pub fn verify_and_freeze(
    source: &mut GeneralFrozenPartition,
    raw: &ntfs_inspect::NtfsInspection,
    source_sha256: &str,
    source_views: &crate::ntfs_source_view::Analysis,
    pair: GeneralSourceShadowBinding,
    max_change_bytes: u64,
    profile: n2r_win32::journal_file::JournalProfile,
    resources: crate::ntfs_admission::ResourceProfile,
    events: &mut Vec<NativeEvent>,
) -> Result<(GeneralFrozenPartition, FrozenTargetPreservation)> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    general_shadow::Request {
        schema_version: 1,
        pair: pair.clone(),
        source_sha256: source_sha256.into(),
        expected_mount_paths: None,
    }
    .validate_with_resource_profile(resources)?;
    ensure!(
        source.binding() == &pair.source
            && (1..=profile.max_changed_bytes()).contains(&max_change_bytes),
        "target preservation source or comparison bound differs"
    );
    let source_before = source.state(events)?;
    ensure!(
        source_before.disk_attributes == 3,
        "source must remain persistently excluded"
    );
    let source_length = source.byte_len();
    let actual_raw = ntfs_inspect::inspect_with_limits(
        source,
        source_length,
        ntfs_inspect::limits_for_resource_profile(resources),
    )?;
    let inspection_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    ensure!(
        hex::encode(Sha256::digest(serde_json::to_vec(&actual_raw)?)) == inspection_sha256,
        "source inventory changed before target verification"
    );
    ensure!(
        source_views.binds_live_source(&inspection_sha256, source_sha256),
        "target requires the bound live source views"
    );
    let mut tree = shadow_tree::derive_ordinary_with_resource_profile(raw, resources)?;
    tree.bind_security_views(source_views)?;
    let expected = shadow_tree::ExpectedTree::from(&tree);
    expected.validate_with_resource_profile(resources)?;
    let mut target = GeneralFrozenPartition::isolate(pair.shadow.clone(), events)?;
    let before = target.state(events)?;
    let length = target.byte_len();
    let native = verify_frozen_tree_with_resource_profile(
        &mut target,
        pair.clone(),
        &expected,
        resources,
        events,
    )?;
    let target_sha256 = native.target_sha256().to_owned();
    let target_sha256_before_observation = target_sha256.clone();
    // Derive placement from this protected observation of the exact frozen
    // image, never an earlier writable construction report.
    let mappings = tree_placement::mappings_from_native(&tree, &native.native().report().native)?;
    let limits = resources.limits();
    let mut range_budget = ntfs_inspect::StreamTransferBudget::new(
        limits.maximum_stream_bytes,
        limits.maximum_logical_bytes,
    )?;
    let placement = tree_placement::diagnose_measured(
        &tree,
        &mappings,
        source,
        source_length,
        |reader, object, start, end| {
            if resources.native_profile().is_some() {
                ntfs_inspect::hash_plain_stream_range_with_budget(
                    reader,
                    raw,
                    object.record_number,
                    start,
                    end - start,
                    &mut range_budget,
                )
            } else {
                ntfs_inspect::hash_plain_stream_range(
                    reader,
                    raw,
                    object.record_number,
                    start,
                    end - start,
                    256 * 1024 * 1024,
                )
            }
        },
    )?;
    let refs = refs_inspect::inspect_with_resource_profile(&mut target, length, resources)?;
    ensure!(
        refs.geometry.major_version == 3
            && refs.geometry.minor_version == 14
            && refs.geometry.bytes_per_cluster == 4096
            && refs.geometry.bytes_per_sector == 512
            && refs.geometry.volume_bytes == length
            && refs.backup_header_status == refs_inspect::BackupHeaderStatus::Matching,
        "frozen target ReFS format differs"
    );
    let comparison =
        placement.comparison_request(length, source_sha256, &target_sha256, max_change_bytes)?;
    let retained_allocation = if comparison.retained_ranges.is_empty() {
        None
    } else {
        let allocation = refs_retained_allocation::inspect_with_resource_profile(
            &mut target,
            length,
            &comparison,
            resources,
        )?;
        ensure!(
            allocation.retained_allocator_coverage_verified,
            "frozen retained target ownership is incomplete"
        );
        Some(allocation)
    };
    let after = target.state(events)?;
    ensure!(
        before == after
            && before.disk_attributes == 3
            && source.state(events)? == source_before
            && hex::encode(lab_reconstruct::hash_range_with_resource_profile(
                source,
                0,
                source_length,
                resources,
            )?) == source_sha256,
        "source or frozen target changed during preservation verification"
    );
    let proof = FrozenTargetPreservation {
        pair,
        inspection_sha256,
        source_sha256: source_sha256.into(),
        target_sha256,
        expected_tree_sha256: hex::encode(Sha256::digest(serde_json::to_vec_pretty(&expected)?)),
        native,
        target_sha256_before_observation,
        before,
        after,
        placement,
        comparison,
        refs,
        retained_allocation,
        source_views_sha256: hex::encode(Sha256::digest(serde_json::to_vec(source_views)?)),
    };
    Ok((target, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn late_change_between_semantics_and_freeze_hash_cannot_create_a_result() {
        let mut image = Cursor::new(vec![0x31; 3 * 4096]);
        let error = bracket_image(&mut image, 3 * 4096, |image| {
            // Simulates an out-of-band change after an otherwise successful
            // semantic observation, without changing device identity/state.
            image.get_mut()[4096] ^= 1;
            Ok("semantic-report")
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed frozen image bytes"));
    }

    #[test]
    fn incomplete_final_image_or_failed_semantics_cannot_create_a_result() {
        let mut image = Cursor::new(vec![0x31; 8192]);
        assert!(
            bracket_image(&mut image, 8192, |image| {
                image.get_mut().truncate(4096);
                Ok(())
            })
            .is_err()
        );
        let mut image = Cursor::new(vec![0x31; 8192]);
        assert!(
            bracket_image::<_, ()>(&mut image, 8192, |_| {
                anyhow::bail!("native tree mismatch")
            })
            .is_err()
        );
        let (result, hash) = bracket_image(&mut image, 8192, |_| Ok(7)).unwrap();
        assert_eq!(result, 7);
        assert_eq!(hash, hex::encode(Sha256::digest(vec![0x31; 8192])));
    }
}
