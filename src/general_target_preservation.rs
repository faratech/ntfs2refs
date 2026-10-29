//! Freeze the ReFS target, verify its native semantics while read-only, and
//! bracket that observation with unchanged raw-image hashes. Serialized reports cannot create
//! this witness or supply an unfrozen target to journal activation.
use crate::{
    general_shadow, lab_reconstruct, ntfs_attestation, ntfs_inspect, refs_inspect,
    refs_retained_allocation, shadow_tree, tree_placement,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, GeneralLiveRefsLayoutObservation,
    GeneralLiveRefsObservation, NativeEvent, general_layout::GeneralSourceShadowBinding,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek},
    path::Path,
};

mod allocation;
pub use allocation::{CapturedDeltaAllocationDiagnostic, ProtectedAllocationCoverage};

fn bracket_image<R: Read + Seek, T>(
    image: &mut R,
    length: u64,
    observe: impl FnOnce(&mut R) -> Result<T>,
) -> Result<(T, String)> {
    bracket_image_with_resource_profile(
        image,
        length,
        crate::ntfs_admission::ResourceProfile::AlphaV1,
        observe,
    )
}

fn bracket_image_with_resource_profile<R: Read + Seek, T>(
    image: &mut R,
    length: u64,
    resources: crate::ntfs_admission::ResourceProfile,
    observe: impl FnOnce(&mut R) -> Result<T>,
) -> Result<(T, String)> {
    let before = lab_reconstruct::hash_range_with_resource_profile(image, 0, length, resources)?;
    let observation = observe(image)?;
    let after = lab_reconstruct::hash_range_with_resource_profile(image, 0, length, resources)?;
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

/// Protected native metadata/layout of one byte-identical frozen shadow.
/// Placeholder contents remain unverified. Neither this opaque witness nor
/// its serialized diagnostic report constitutes source or write admission.
#[derive(Debug, Serialize)]
pub struct ProtectedTargetLayout {
    native: GeneralLiveRefsLayoutObservation,
    raw_sha256: String,
    expected_tree_sha256: String,
    frozen_state: GeneralDiskState,
    resources: crate::ntfs_admission::ResourceProfile,
    routes: n2r_win32::shadow_native::private_tree::SourceBackedRoutes,
    allocation_coverage: ProtectedAllocationCoverage,
    raw_image_unchanged: bool,
    /// Present only when the closing bracket covered the protected allocation
    /// rather than the complete image (allocation-bounded mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    bracket_closure: Option<AllocationBracketClosure>,
    logical_payload_verified: bool,
    complete_allocation_graph_verified: bool,
    source_admitted: bool,
    conversion_qualified: bool,
}

impl ProtectedTargetLayout {
    pub fn native(&self) -> &GeneralLiveRefsLayoutObservation {
        &self.native
    }
    pub fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }
    pub fn expected_tree_sha256(&self) -> &str {
        &self.expected_tree_sha256
    }
    pub fn routes(&self) -> &n2r_win32::shadow_native::private_tree::SourceBackedRoutes {
        &self.routes
    }
    pub fn frozen_state(&self) -> &GeneralDiskState {
        &self.frozen_state
    }
    pub fn resource_profile(&self) -> crate::ntfs_admission::ResourceProfile {
        self.resources
    }
    pub fn allocation_coverage(&self) -> &ProtectedAllocationCoverage {
        &self.allocation_coverage
    }
}

/// Verify native metadata and stream layout after final freeze, with complete
/// raw-image equality around the physically read-only native observation.
/// File contents are deliberately not read from allocation-only placeholders;
/// the caller must separately prove the complete source-backed target image.
pub fn verify_frozen_layout_with_resource_profile(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &shadow_tree::ExpectedTree,
    resources: crate::ntfs_admission::ResourceProfile,
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    verify_frozen_layout_profile(target, pair, expected, resources, None, events)
}

/// Opt-in initialized-suffix verification for a source-backed composite. The
/// caller freshly obtains each expectation through the frozen NTFS reader.
pub fn verify_frozen_layout_residuals_with_resource_profile(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &shadow_tree::ExpectedTree,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: &[n2r_win32::shadow_native::LayoutResidualExpectation],
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    verify_frozen_layout_profile(target, pair, expected, resources, Some(residuals), events)
}

fn verify_frozen_layout_profile(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &shadow_tree::ExpectedTree,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: Option<&[n2r_win32::shadow_native::LayoutResidualExpectation]>,
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    expected.validate_with_resource_profile(resources)?;
    ensure!(
        target.binding() == &pair.shadow,
        "protected layout target binding differs"
    );
    let before = target.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "layout observation requires a frozen target"
    );
    let expected_tree_sha256 = hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?));
    let tree = shadow_tree::Tree {
        profile: resources.ordinary_shadow_profile(),
        objects: expected.objects.clone(),
        logical_bytes: expected.logical_bytes,
        internal_replacement_pending: expected.internal_replacement_pending.clone(),
    };
    let input = general_shadow::native_inputs(&tree);
    let length = target.byte_len();
    let ((native, anchors), raw_sha256) =
        bracket_image_with_resource_profile(target, length, resources, |target| {
            let same_security = |a: &[u8], b: &[u8]| {
                ntfs_attestation::same_security(a, b)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            };
            let native = match residuals {
                Some(residuals) => target.observe_refs_layout_residuals_with_resource_profile(
                    pair.clone(),
                    &input,
                    residuals,
                    same_security,
                    resources.native_profile(),
                    events,
                )?,
                None => target.observe_refs_layout_with_resource_profile(
                    pair.clone(),
                    &input,
                    same_security,
                    resources.native_profile(),
                    events,
                )?,
            };
            // This bounded raw inspection shares the same unchanged-image
            // bracket. Unknown/rejected anchor forms remain explicit diagnostics;
            // they must not silently establish required-byte completeness.
            let anchors = refs_inspect::inspect_with_resource_profile(target, length, resources)
                .and_then(|refs| crate::refs_write_set::observed_anchors(&refs))
                .map_err(|error| format!("{error:#}"));
            Ok((native, anchors))
        })?;
    ensure!(
        native.before() == &before
            && native.after() == &before
            && native.observed_readonly().disk_attributes == 2
            && native.report().pair() == &pair
            && target.state(events)? == before,
        "protected layout observation changed its identity or persistent exclusion"
    );
    let routes =
        n2r_win32::shadow_native::private_tree::SourceBackedRoutes::from_protected_layout(&native)?;
    let allocation_coverage = allocation::reconcile(&native, anchors, &raw_sha256, length)?;
    Ok(ProtectedTargetLayout {
        native,
        raw_sha256,
        expected_tree_sha256,
        frozen_state: before,
        resources,
        routes,
        allocation_coverage,
        raw_image_unchanged: true,
        bracket_closure: None,
        logical_payload_verified: false,
        complete_allocation_graph_verified: false,
        source_admitted: false,
        conversion_qualified: false,
    })
}

#[derive(Debug, Serialize)]
pub struct AllocationBracketClosure {
    opening: &'static str,
    raw_sha256_meaning: &'static str,
    opening_chunks: usize,
    opening_bytes: u64,
    closing_ranges: usize,
    closing_chunks: usize,
    closing_bytes_reread: u64,
    free_space_rechecked: bool,
}

const BRACKET_CHUNK: u64 = 1024 * 1024;

/// Sorted distinct 1 MiB chunk indices overlapping the sorted `ranges`.
fn chunk_indices(ranges: &[crate::refs_write_set::ByteRange], length: u64) -> Result<Vec<u64>> {
    let mut indices: Vec<u64> = Vec::new();
    for range in ranges {
        let end = range
            .offset
            .checked_add(range.length)
            .context("bracket range overflow")?;
        ensure!(
            range.length != 0 && end <= length,
            "bracket range escapes the image"
        );
        for index in range.offset / BRACKET_CHUNK..=(end - 1) / BRACKET_CHUNK {
            if indices.last() != Some(&index) {
                indices.push(index);
            }
        }
    }
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

/// The bracket chunks at `indices`, each clipped to the image end.
fn bracket_chunks(indices: &[u64], length: u64) -> Result<Vec<crate::parallel_digest::Chunk>> {
    indices
        .iter()
        .map(|&index| {
            let offset = index * BRACKET_CHUNK;
            Ok(crate::parallel_digest::Chunk {
                offset,
                length: usize::try_from((length - offset).min(BRACKET_CHUNK))?,
            })
        })
        .collect()
}

/// Opening pass over only the chunks overlapping `ranges`: their XXH3-128
/// change-detection digests, plus one SHA-256 over every (index, digest) pair.
/// The image is read on this thread while the spare cores hash.
fn open_allocated_bracket<R: Read + Seek>(
    image: &mut R,
    length: u64,
    ranges: &[crate::refs_write_set::ByteRange],
) -> Result<(String, Vec<(u64, [u8; 16])>, u64)> {
    let indices = chunk_indices(ranges, length)?;
    let chunks = bracket_chunks(&indices, length)?;
    let hashed = crate::parallel_digest::digest_chunks(image, &chunks)?;
    let bytes = chunks.iter().map(|chunk| chunk.length as u64).sum();
    let digests: Vec<_> = indices.into_iter().zip(hashed).collect();
    let mut summary = n2r_win32::sha256_native::Sha256::new()?;
    for (index, digest) in &digests {
        summary.update(&index.to_le_bytes())?;
        summary.update(digest)?;
    }
    Ok((hex::encode(summary.finish()?), digests, bytes))
}

/// Recheck every chunk overlapping the sorted `ranges` against the opening
/// pass. A chunk the opening pass did not hash refuses before any read.
fn close_allocated_bracket<R: Read + Seek>(
    image: &mut R,
    length: u64,
    opened: &[(u64, [u8; 16])],
    ranges: &[crate::refs_write_set::ByteRange],
) -> Result<(usize, u64)> {
    let indices = chunk_indices(ranges, length)?;
    let expected = indices
        .iter()
        .map(|&index| {
            opened
                .binary_search_by_key(&index, |(opened, _)| *opened)
                .map(|position| opened[position].1)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "closing allocation includes a chunk the opening pass did not hash"
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let chunks = bracket_chunks(&indices, length)?;
    let hashed = crate::parallel_digest::digest_chunks(image, &chunks)?;
    ensure!(
        hashed == expected,
        "protected observation changed allocated frozen image bytes"
    );
    let reread = chunks.iter().map(|chunk| chunk.length as u64).sum();
    Ok((indices.len(), reread))
}

/// Allocation-bounded counterpart of
/// [`verify_frozen_layout_residuals_with_resource_profile`] under the user's
/// allocation guarantee. A first protected read-only mount supplies the native
/// allocation map; the bracket opens over its chunks, the full observation runs,
/// both mounts must report the identical map, and the bracket closes over the
/// observed allocation. No pass reads the complete image.
pub fn verify_frozen_layout_residuals_allocation_closed(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &shadow_tree::ExpectedTree,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: &[n2r_win32::shadow_native::LayoutResidualExpectation],
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    expected.validate_with_resource_profile(resources)?;
    ensure!(
        target.binding() == &pair.shadow,
        "protected layout target binding differs"
    );
    let before = target.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "layout observation requires a frozen target"
    );
    let expected_tree_sha256 = hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?));
    let tree = shadow_tree::Tree {
        profile: resources.ordinary_shadow_profile(),
        objects: expected.objects.clone(),
        logical_bytes: expected.logical_bytes,
        internal_replacement_pending: expected.internal_replacement_pending.clone(),
    };
    let input = general_shadow::native_inputs(&tree);
    let length = target.byte_len();
    let witness = target.observe_refs_allocation_readonly(resources.native_profile(), events)?;
    target.validate_readonly_allocation_witness(&witness, events)?;
    let premap = witness.snapshot().metadata_inclusive();
    let opening: Vec<_> = premap
        .ranges
        .iter()
        .map(|range| crate::refs_write_set::ByteRange {
            offset: range.offset,
            length: range.length,
        })
        .collect();
    let (raw_sha256, chunks, opening_bytes) = open_allocated_bracket(target, length, &opening)?;
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    let native = target.observe_refs_layout_residuals_with_resource_profile(
        pair.clone(),
        &input,
        residuals,
        same_security,
        resources.native_profile(),
        events,
    )?;
    let anchors = refs_inspect::inspect_with_resource_profile(target, length, resources)
        .and_then(|refs| crate::refs_write_set::observed_anchors(&refs))
        .map_err(|error| format!("{error:#}"));
    ensure!(
        native.before() == &before
            && native.after() == &before
            && native.observed_readonly().disk_attributes == 2
            && native.report().pair() == &pair
            && target.state(events)? == before,
        "protected layout observation changed its identity or persistent exclusion"
    );
    let observed_map = native
        .report()
        .native()
        .metadata_allocation
        .as_ref()
        .context("protected allocation bitmap absent")?;
    ensure!(
        observed_map.bitmap_sha256 == premap.bitmap_sha256
            && observed_map.cluster_count == premap.cluster_count,
        "the two protected read-only mounts reported different allocation maps"
    );
    let routes =
        n2r_win32::shadow_native::private_tree::SourceBackedRoutes::from_protected_layout(&native)?;
    let allocation_coverage = allocation::reconcile(&native, anchors, &raw_sha256, length)?;
    let selection = allocation_coverage.observed_ranges(&native)?;
    let (closing_chunks, closing_bytes_reread) =
        close_allocated_bracket(target, length, &chunks, &selection)?;
    ensure!(
        target.state(events)? == before,
        "protected allocation bracket changed persistent exclusion"
    );
    Ok(ProtectedTargetLayout {
        native,
        raw_sha256,
        expected_tree_sha256,
        frozen_state: before,
        resources,
        routes,
        allocation_coverage,
        raw_image_unchanged: false,
        bracket_closure: Some(AllocationBracketClosure {
            opening: "1 MiB chunk XXH3-128 digests over the allocation map of a prior protected read-only mount",
            raw_sha256_meaning: "SHA-256 over the opening (chunk index, XXH3-128 chunk digest) pairs; detects change between the two passes, not a cryptographic content hash or a whole-image hash",
            opening_chunks: chunks.len(),
            opening_bytes,
            closing_ranges: selection.len(),
            closing_chunks,
            closing_bytes_reread,
            free_space_rechecked: false,
        }),
        logical_payload_verified: false,
        complete_allocation_graph_verified: false,
        source_admitted: false,
        conversion_qualified: false,
    })
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
    let observe = |target: &mut GeneralFrozenPartition| {
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
    };
    let (native, target_sha256) =
        if resources == crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2 {
            bracket_image_with_resource_profile(target, length, resources, observe)?
        } else {
            bracket_image(target, length, observe)?
        };
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
    pub(crate) fn native_report(&self) -> &n2r_win32::shadow_native::GeneralReport {
        self.native.native().report()
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
    reuse_frozen: bool,
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
    let mut target = if reuse_frozen {
        ensure!(
            resources == crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2,
            "frozen-shadow reuse requires the explicit streaming profile"
        );
        match n2r_win32::observe_general_disk_state_readonly(pair.shadow.clone(), events)?
            .disk_attributes
        {
            3 => GeneralFrozenPartition::reopen(pair.shadow.clone(), events)?,
            0 => GeneralFrozenPartition::isolate(pair.shadow.clone(), events)?,
            _ => anyhow::bail!("existing shadow must be writable or persistently excluded"),
        }
    } else {
        GeneralFrozenPartition::isolate(pair.shadow.clone(), events)?
    };
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
    let mut comparison =
        placement.comparison_request(length, source_sha256, &target_sha256, max_change_bytes)?;
    if reuse_frozen {
        // Bound the retry's patch metadata and sparse COW allocation exposure.
        // The existing complete comparison refuses excess ranges before writes.
        comparison.max_ranges = 1024;
    }
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
