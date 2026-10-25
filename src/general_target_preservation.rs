//! Verify the actual native ReFS tree against the frozen NTFS semantics, then
//! freeze the same target and bind its bytes. Serialized reports cannot create
//! this witness or supply an unfrozen target to journal activation.
use crate::{
    general_shadow, lab_reconstruct, ntfs_attestation, ntfs_inspect, refs_inspect,
    refs_retained_allocation, shadow_tree, tree_placement,
};
use anyhow::{Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, NativeEvent,
    general_layout::GeneralSourceShadowBinding, shadow_native,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct FrozenTargetPreservation {
    pair: GeneralSourceShadowBinding,
    inspection_sha256: String,
    source_sha256: String,
    target_sha256: String,
    expected_tree_sha256: String,
    native: shadow_native::GeneralReport,
    before: GeneralDiskState,
    after: GeneralDiskState,
    placement: tree_placement::Plan,
    comparison: crate::retained_compare::RetainedCompareRequest,
    refs: refs_inspect::RefsInspection,
    retained_allocation: Option<refs_retained_allocation::Coverage>,
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
}

pub fn verify_and_freeze(
    source: &mut GeneralFrozenPartition,
    raw: &ntfs_inspect::NtfsInspection,
    source_sha256: &str,
    pair: GeneralSourceShadowBinding,
    max_change_bytes: u64,
    events: &mut Vec<NativeEvent>,
) -> Result<(GeneralFrozenPartition, FrozenTargetPreservation)> {
    pair.validate()?;
    general_shadow::Request {
        schema_version: 1,
        pair: pair.clone(),
        source_sha256: source_sha256.into(),
        expected_mount_paths: None,
    }
    .validate()?;
    ensure!(
        source.binding() == &pair.source && (1..=256 * 1024 * 1024).contains(&max_change_bytes),
        "target preservation source or comparison bound differs"
    );
    let source_before = source.state(events)?;
    ensure!(
        source_before.disk_attributes == 3,
        "source must remain persistently excluded"
    );
    let source_length = source.byte_len();
    let actual_raw = ntfs_inspect::inspect(source, source_length)?;
    let inspection_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    ensure!(
        hex::encode(Sha256::digest(serde_json::to_vec(&actual_raw)?)) == inspection_sha256,
        "source inventory changed before target verification"
    );
    let tree = shadow_tree::derive_ordinary(raw)?;
    let expected = shadow_tree::ExpectedTree::from(&tree);
    expected.validate()?;
    let input = general_shadow::native_inputs(&tree);
    let native = shadow_native::verify_general_ordinary(pair.clone(), &input, |a, b| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    })?;
    let mappings = tree_placement::mappings_from_native(&tree, &native.native)?;
    let placement = tree_placement::diagnose_measured(
        &tree,
        &mappings,
        source,
        source_length,
        |reader, object, start, end| {
            ntfs_inspect::hash_plain_stream_range(
                reader,
                raw,
                object.record_number,
                start,
                end - start,
                256 * 1024 * 1024,
            )
        },
    )?;
    let mut target = GeneralFrozenPartition::isolate(pair.shadow.clone(), events)?;
    let before = target.state(events)?;
    let length = target.byte_len();
    let refs = refs_inspect::inspect(&mut target, length)?;
    ensure!(
        refs.geometry.major_version == 3
            && refs.geometry.minor_version == 14
            && refs.geometry.bytes_per_cluster == 4096
            && refs.geometry.bytes_per_sector == 512
            && refs.geometry.volume_bytes == length
            && refs.backup_header_status == refs_inspect::BackupHeaderStatus::Matching,
        "frozen target ReFS format differs"
    );
    let target_sha256 = hex::encode(lab_reconstruct::hash_range(&mut target, 0, length)?);
    let comparison =
        placement.comparison_request(length, source_sha256, &target_sha256, max_change_bytes)?;
    let retained_allocation = if comparison.retained_ranges.is_empty() {
        None
    } else {
        let allocation = refs_retained_allocation::inspect(&mut target, length, &comparison)?;
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
            && hex::encode(lab_reconstruct::hash_range(source, 0, source_length)?) == source_sha256,
        "source or frozen target changed during preservation verification"
    );
    let proof = FrozenTargetPreservation {
        pair,
        inspection_sha256,
        source_sha256: source_sha256.into(),
        target_sha256,
        expected_tree_sha256: hex::encode(Sha256::digest(serde_json::to_vec_pretty(&expected)?)),
        native,
        before,
        after,
        placement,
        comparison,
        refs,
        retained_allocation,
    };
    Ok((target, proof))
}
