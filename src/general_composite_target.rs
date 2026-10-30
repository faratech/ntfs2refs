//! Frozen native-shadow target whose ordinary payload is supplied by the
//! frozen NTFS source. Complete address-space comparison, not bitmap inference,
//! proves the compact backing. This module issues no source/write certificate.
use crate::{
    general_shadow::source_backed::{
        ChangeClassSplit, ChangedClassCounters, DifferenceCapture, SourceBackedShadow,
    },
    general_target_preservation::{self, CapturedDeltaAllocationDiagnostic, ProtectedTargetLayout},
    lab_reconstruct,
    ntfs_admission::ResourceProfile,
    ntfs_inspect, ntfs_source_view,
    refs_hybrid::delta::DifferenceImage,
    retained_compare::RetainedCompareRequest,
    shadow_tree,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, NativeEvent,
    general_layout::GeneralSourceShadowBinding,
    reference_file::{self, ReferenceFileSnapshot},
    shadow_native::LayoutResidualExpectation,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, Prefix},
    time::SystemTime,
};

#[derive(Debug, Serialize)]
struct PinnedBacking {
    snapshot: ReferenceFileSnapshot,
    sha256: String,
    #[serde(skip)]
    modified: SystemTime,
    #[serde(skip)]
    file: File,
}
impl PinnedBacking {
    fn open(path: &Path, length: u64, expected: &str) -> Result<Self> {
        // READ sharing excludes writers/deleters for this exact held handle;
        // OPEN_REPARSE_POINT also prevents final-component redirection.
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let snapshot = reference_file::observe_reference_file_handle(&file)?;
        let modified = file.metadata()?.modified()?;
        ensure!(
            snapshot.file_bytes == length && snapshot.number_of_links == 1,
            "composite packed backing length or link count differs"
        );
        let sha256 = hex::encode(n2r_win32::sha256_native::hash_range(&mut file, 0, length)?);
        ensure!(
            sha256 == expected,
            "composite packed backing hash differs from live capture"
        );
        let mut value = Self {
            snapshot,
            sha256,
            modified,
            file,
        };
        value.revalidate()?;
        Ok(value)
    }
    fn revalidate(&mut self) -> Result<()> {
        ensure!(
            reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "composite held backing identity or metadata changed"
        );
        let actual = hex::encode(n2r_win32::sha256_native::hash_range(
            &mut self.file,
            0,
            self.snapshot.file_bytes,
        )?);
        ensure!(
            actual == self.sha256
                && reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "composite held backing changed during complete rehash"
        );
        Ok(())
    }
}

/// Created only from actual frozen devices and a freshly written compact
/// backing retained under a read-only no-writer/delete handle. Deserialization
/// is deliberately unavailable. Source admission still needs the original live
/// source assessment and transaction-freeze witness.
#[derive(Serialize)]
pub struct FrozenCompositeTargetPreservation {
    pair: GeneralSourceShadowBinding,
    inspection_sha256: String,
    source_sha256: String,
    source_views_sha256: String,
    expected_tree_sha256: String,
    resources: ResourceProfile,
    protected: ProtectedTargetLayout,
    residuals: Vec<LayoutResidualExpectation>,
    capture: DifferenceCapture,
    allocation_delta_diagnostic: Option<CapturedDeltaAllocationDiagnostic>,
    allocation_delta_diagnostic_error: Option<String>,
    selective_plan_diagnostic: Option<SelectivePlanDiagnostic>,
    selective_plan_diagnostic_error: Option<String>,
    backing: PinnedBacking,
    composite_target_sha256: String,
    comparison: RetainedCompareRequest,
    source_before: GeneralDiskState,
    source_after: GeneralDiskState,
    target_before: GeneralDiskState,
    target_after: GeneralDiskState,
    frozen_source_hash_and_inventory_verified: bool,
    source_views_bound: bool,
    logical_payload_tied_to_frozen_source: bool,
    complete_native_address_space_compared: bool,
    compact_image_matches_supplied_candidate: bool,
    complete_allocation_graph_verified: bool,
    source_admitted: bool,
    conversion_qualified: bool,
}
impl FrozenCompositeTargetPreservation {
    pub fn pair(&self) -> &GeneralSourceShadowBinding {
        &self.pair
    }
    pub fn comparison(&self) -> &RetainedCompareRequest {
        &self.comparison
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub fn inspection_sha256(&self) -> &str {
        &self.inspection_sha256
    }
    pub fn source_views_sha256(&self) -> &str {
        &self.source_views_sha256
    }
    pub fn expected_tree_sha256(&self) -> &str {
        &self.expected_tree_sha256
    }
    pub fn resource_profile(&self) -> ResourceProfile {
        self.resources
    }
    pub fn protected_layout(&self) -> &ProtectedTargetLayout {
        &self.protected
    }
    pub fn target_sha256(&self) -> &str {
        &self.composite_target_sha256
    }
    pub fn capture(&self) -> &DifferenceCapture {
        &self.capture
    }
    pub fn binds(&self, raw: &ntfs_inspect::NtfsInspection, source: &str) -> bool {
        self.source_sha256 == source
            && serde_json::to_vec(raw)
                .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
    }
    pub fn native_resource_profile(&self) -> Option<n2r_win32::attestation::ResourceProfile> {
        self.resources.native_profile()
    }
    pub fn data_ties_verified(&self) -> bool {
        self.frozen_source_hash_and_inventory_verified
            && self.source_views_bound
            && self.logical_payload_tied_to_frozen_source
            && self.complete_native_address_space_compared
            && self.compact_image_matches_supplied_candidate
    }
    /// Read-only composite over the held backing and the exact frozen source.
    /// The caller still needs a separately admitted journal before any writes.
    pub fn image<'a>(
        &'a mut self,
        source: &'a mut GeneralFrozenPartition,
    ) -> Result<DifferenceImage<'a, GeneralFrozenPartition, File>> {
        ensure!(
            source.binding() == &self.pair.source
                && source.state(&mut Vec::new())? == self.source_after,
            "composite view source binding or exclusion differs"
        );
        self.backing.revalidate()?;
        DifferenceImage::new(source, &mut self.backing.file, &self.capture.layout)
    }
    pub fn revalidate_backing(&mut self) -> Result<()> {
        self.backing.revalidate()
    }

    /// Persist recovery inputs while retaining the actual live proof. Reopening
    /// this diagnostic artifact alone never recreates its source certificate.
    /// Both objects keep read-only handles on the exact same packed file.
    #[allow(
        dead_code,
        reason = "called by the intentionally unexposed composite orchestration"
    )]
    pub(crate) fn persist_delta_artifact(
        &mut self,
        report_path: &Path,
        packed_path: &Path,
    ) -> Result<crate::refs_hybrid::delta::VerifiedDeltaArtifact> {
        ensure!(
            self.data_ties_verified()
                && self.capture.selected_bytes_compared == self.capture.layout.partition_bytes(),
            "only a complete live composite proof can publish recovery inputs"
        );
        self.backing.revalidate()?;
        fresh_ordinary_path(report_path)?;
        let value = serde_json::json!({
            "schema_version": 1,
            "kind": "frozen-composite-target-capture",
            "success": true,
            "source_backed_payloads": true,
            "source_admitted": false,
            "conversion_qualified": false,
            "pair": self.pair,
            "source_sha256": self.source_sha256,
            "inspection_sha256": self.inspection_sha256,
            "source_views_sha256": self.source_views_sha256,
            "expected_tree_sha256": self.expected_tree_sha256,
            "source_resource_profile": self.resources,
            "composite_target_sha256": self.composite_target_sha256,
            "native": {"compact_difference_capture": self.capture}
        });
        let bytes = serde_json::to_vec_pretty(&value)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "composite capture report exceeds bound"
        );
        let mut report = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(report_path)?;
        std::io::Write::write_all(&mut report, &bytes)?;
        report.sync_all()?;
        drop(report);
        let report_sha256 = hex::encode(Sha256::digest(&bytes));
        let mut artifact = crate::refs_hybrid::delta::VerifiedDeltaArtifact::open(
            report_path,
            &report_sha256,
            packed_path,
            self.capture.layout.partition_bytes(),
            self.capture.layout.changed_bytes(),
        )?;
        ensure!(
            artifact.pins().packed_file_id_info.as_deref()
                == Some(n2r_win32::file_storage::file_id_info(&self.backing.file)?.as_str())
                && artifact.pins().packed_sha256 == self.backing.sha256
                && serde_json::to_vec(artifact.layout())?
                    == serde_json::to_vec(&self.capture.layout)?,
            "published compact artifact differs from the held live composite backing"
        );
        self.backing.revalidate()?;
        artifact.revalidate()?;
        Ok(artifact)
    }
}

/// Build a complete source-backed target proof without initializing duplicate
/// full-cluster payload. All source gates remain the live assessor's job.
pub fn verify_and_capture(
    source: &mut GeneralFrozenPartition,
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    raw: &ntfs_inspect::NtfsInspection,
    source_views: &ntfs_source_view::Analysis,
    source_sha256: &str,
    resources: ResourceProfile,
    packed_path: &Path,
    max_changed_bytes: u64,
    events: &mut Vec<NativeEvent>,
) -> Result<FrozenCompositeTargetPreservation> {
    let ProtectedPrefix {
        length,
        source_before,
        target_before,
        inspection_sha256,
        source_views_sha256,
        tree,
        expected_tree_sha256,
        residuals,
        protected,
    } = protected_prefix(
        source,
        target,
        &pair,
        raw,
        source_views,
        source_sha256,
        resources,
        packed_path,
        max_changed_bytes,
        events,
        false,
    )?;
    let capture = SourceBackedShadow::new(
        source,
        target,
        raw,
        &tree,
        protected.routes(),
        protected.routes().payload_bytes().max(1),
    )?
    .capture_complete_differences_to_new_file(packed_path, max_changed_bytes)?;
    // The complete capture hashes the exact original chunks it already read.
    // This fresh in-memory sidecar cannot be imported from a capture report.
    ensure!(
        capture.source_raw_sha256() == Some(source_sha256),
        "composite capture frozen source SHA-256 differs"
    );
    ensure!(
        capture.selected_bytes_compared == length
            && capture
                .equal_selected_bytes
                .checked_add(capture.layout.changed_bytes())
                == Some(length)
            && !capture.conversion_qualified,
        "composite capture does not cover the complete frozen source address space"
    );
    // Retrospective accounting only: the complete capture remains unchanged.
    // A partial/unsupported diagnostic cannot alter conversion admission.
    let (allocation_delta_diagnostic, allocation_delta_diagnostic_error) = match protected
        .allocation_coverage()
        .classify_capture(protected.native(), &capture.layout)
    {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    // Retrospective and non-gating, like the diagnostic above: would a selection
    // driven by the protected shadow allocation have found exactly this write
    // set? It reads only the observed allocation through a fresh view.
    let (selective_plan_diagnostic, selective_plan_diagnostic_error) = match selective_plan(
        source,
        target,
        raw,
        &tree,
        &protected,
        &capture,
        max_changed_bytes,
    ) {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let mut backing = PinnedBacking::open(
        packed_path,
        capture.layout.changed_bytes(),
        &capture.packed_sha256,
    )?;
    for binding in [&pair.source, &pair.shadow] {
        ensure!(
            !backing
                .snapshot
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
            "composite backing must be outside both frozen volumes"
        );
    }
    // Keep this fresh shadow check before the final source check. The latter
    // now also hashes the candidate from the same source bytes plus packed
    // overlays, rather than rereading the source complement separately.
    ensure!(
        hex::encode(lab_reconstruct::hash_range_with_resource_profile(
            target, 0, length, resources,
        )?) == protected.raw_sha256(),
        "raw shadow changed after protected observation"
    );
    let final_digests = {
        let mut image = DifferenceImage::new(source, &mut backing.file, &capture.layout)?;
        image.hash_pair_for_frozen_source(&pair.source, length, events)?
    };
    ensure!(
        final_digests.source_raw == source_sha256,
        "source changed around composite preparation"
    );
    ensure!(
        final_digests.source_framed == capture.source_selected_sha256,
        "final source framing differs from the complete capture"
    );
    ensure!(
        final_digests.candidate_framed == capture.candidate_selected_sha256,
        "reopened compact image differs from the complete supplied candidate"
    );
    // As before, the fresh candidate raw digest becomes the comparison pin
    // only after its complete framed digest matches the captured candidate.
    let composite_target_sha256 = final_digests.candidate_raw;
    backing.revalidate()?;
    let source_after = source.state(events)?;
    let target_after = target.state(events)?;
    ensure!(
        source_after == source_before && target_after == target_before,
        "composite preparation changed persistent device identity or exclusion"
    );
    let comparison = RetainedCompareRequest {
        schema_version: 2,
        sector_size: 4096,
        expected_length: length,
        source_sha256: source_sha256.into(),
        shadow_sha256: composite_target_sha256.clone(),
        // Retention is already proved by complete equal-byte comparison. Do
        // not invent a dummy semantic retained range to satisfy an interface.
        retained_ranges: Vec::new(),
        max_change_bytes: max_changed_bytes,
        max_ranges: 65536,
    };
    crate::retained_compare::validate_request(&comparison)?;
    Ok(FrozenCompositeTargetPreservation {
        pair,
        inspection_sha256,
        source_sha256: source_sha256.into(),
        source_views_sha256,
        expected_tree_sha256,
        resources,
        protected,
        residuals,
        capture,
        allocation_delta_diagnostic,
        allocation_delta_diagnostic_error,
        selective_plan_diagnostic,
        selective_plan_diagnostic_error,
        backing,
        composite_target_sha256,
        comparison,
        source_before,
        source_after,
        target_before,
        target_after,
        frozen_source_hash_and_inventory_verified: true,
        source_views_bound: true,
        logical_payload_tied_to_frozen_source: true,
        complete_native_address_space_compared: true,
        compact_image_matches_supplied_candidate: true,
        complete_allocation_graph_verified: false,
        source_admitted: false,
        conversion_qualified: false,
    })
}

/// Allocation-bounded counterpart of [`FrozenCompositeTargetPreservation`]
/// under the ntfs2btrfs-style guarantee: only ranges the protected frozen
/// shadow's native allocator reports allocated, plus known anchors and streams,
/// are compared and may be written. Free-space contents are not proven equal,
/// and the source is not rehashed here: its frozen state must stay unchanged
/// from the live assessment. Deserialization is deliberately unavailable.
#[derive(Serialize)]
pub struct FrozenAllocationTargetPreservation {
    pair: GeneralSourceShadowBinding,
    inspection_sha256: String,
    source_sha256: String,
    source_views_sha256: String,
    expected_tree_sha256: String,
    resources: ResourceProfile,
    protected: ProtectedTargetLayout,
    residuals: Vec<LayoutResidualExpectation>,
    selection: Vec<crate::refs_write_set::ByteRange>,
    selection_sha256: String,
    /// The selection minus payload proven in place by identical physical runs.
    compared: Vec<crate::refs_write_set::ByteRange>,
    in_place_payload_bytes_not_compared: u64,
    capture: DifferenceCapture,
    /// Non-gating destination split of the captured changed granules; it
    /// binds and authorizes nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    changed_classes: Option<ChangedClassCounters>,
    backing: PinnedBacking,
    source_before: GeneralDiskState,
    source_after: GeneralDiskState,
    target_before: GeneralDiskState,
    target_after: GeneralDiskState,
    frozen_source_inventory_verified: bool,
    frozen_source_inventory_basis: &'static str,
    source_views_bound: bool,
    logical_payload_tied_to_frozen_source: bool,
    allocation_bounded_selection_compared: bool,
    free_space_contents_proven_equal: bool,
    source_admitted: bool,
    conversion_qualified: bool,
}

impl FrozenAllocationTargetPreservation {
    pub fn pair(&self) -> &GeneralSourceShadowBinding {
        &self.pair
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub fn inspection_sha256(&self) -> &str {
        &self.inspection_sha256
    }
    pub fn source_views_sha256(&self) -> &str {
        &self.source_views_sha256
    }
    pub fn expected_tree_sha256(&self) -> &str {
        &self.expected_tree_sha256
    }
    pub fn resource_profile(&self) -> ResourceProfile {
        self.resources
    }
    pub fn native_resource_profile(&self) -> Option<n2r_win32::attestation::ResourceProfile> {
        self.resources.native_profile()
    }
    pub fn selection_sha256(&self) -> &str {
        &self.selection_sha256
    }
    pub fn capture(&self) -> &DifferenceCapture {
        &self.capture
    }
    pub fn binds(&self, raw: &ntfs_inspect::NtfsInspection, source: &str) -> bool {
        self.source_sha256 == source
            && serde_json::to_vec(raw)
                .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
    }
    pub fn data_ties_verified(&self) -> bool {
        self.frozen_source_inventory_verified
            && self.source_views_bound
            && self.logical_payload_tied_to_frozen_source
            && self.allocation_bounded_selection_compared
    }
    /// The differing ranges as a selected-range journal plan.
    pub fn plan(&self, max_journal_bytes: u64) -> Result<crate::selected_journal::SelectedPlan> {
        let plan = crate::selected_journal::SelectedPlan {
            image_length: self.capture.layout.partition_bytes(),
            ranges: self
                .capture
                .layout
                .intervals()
                .iter()
                .map(|range| crate::selected_journal::SelectedRange {
                    offset: range.offset,
                    length: range.length,
                })
                .collect(),
            max_selected_bytes: self.capture.layout.changed_bytes(),
            max_journal_bytes,
            new_zero_ranges: self
                .capture
                .layout
                .new_zero_ranges()
                .into_iter()
                .map(|(offset, length)| crate::selected_journal::SelectedRange { offset, length })
                .collect(),
            new_copy_ranges: self
                .capture
                .layout
                .new_copy_ranges()
                .into_iter()
                .map(
                    |(offset, length, source_offset)| crate::selected_journal::SelectedCopyRange {
                        offset,
                        length,
                        source_offset,
                    },
                )
                .collect(),
        };
        plan.validate()?;
        Ok(plan)
    }
    /// Read-only candidate over the held backing and a frozen source handle.
    pub fn image<'a>(
        &'a mut self,
        source: &'a mut GeneralFrozenPartition,
    ) -> Result<DifferenceImage<'a, GeneralFrozenPartition, File>> {
        ensure!(
            source.binding() == &self.pair.source
                && source.state(&mut Vec::new())? == self.source_after,
            "allocation-bounded view source binding or exclusion differs"
        );
        self.backing.revalidate()?;
        DifferenceImage::new(source, &mut self.backing.file, &self.capture.layout)
    }
    pub fn revalidate_backing(&mut self) -> Result<()> {
        self.backing.revalidate()
    }
}

/// Shadow routes whose physical location equals the frozen NTFS run for the
/// same logical bytes. The source-backed candidate reads those very bytes, so
/// comparing them with the source is redundant. Only whole granules below the
/// stream's EOF qualify; relocated pieces and EOF tails stay compared.
fn in_place_payload_ranges(
    raw: &ntfs_inspect::NtfsInspection,
    tree: &shadow_tree::Tree,
    routes: &n2r_win32::shadow_native::private_tree::SourceBackedRoutes,
) -> Result<Vec<crate::refs_write_set::ByteRange>> {
    let mut found = Vec::new();
    for route in routes.entries() {
        let object = tree
            .objects
            .get(route.object_index)
            .context("in-place route object absent")?;
        let stream = object
            .stream(&route.stream_name_utf16)
            .context("in-place route stream absent")?;
        ensure!(
            stream.length == route.stream_length && stream.sha256 == route.expected_sha256,
            "in-place route stream differs from canonical source"
        );
        let files: Vec<_> = raw
            .files
            .iter()
            .filter(|file| {
                file.record_number == object.record_number
                    && file.sequence_number == object.sequence_number
            })
            .collect();
        ensure!(files.len() == 1, "in-place route source file is ambiguous");
        let data: Vec<_> = files[0]
            .attributes
            .iter()
            .filter(|a| a.type_code == 0x80 && a.name_utf16 == route.stream_name_utf16)
            .collect();
        let [data] = data.as_slice() else {
            continue; // Ambiguous or absent DATA: keep it compared.
        };
        if data.resident || data.flags != 0 || data.lowest_vcn != 0 {
            continue;
        }
        // Only initialized source clusters contain the logical bytes that a
        // retained target may expose. Allocated NTFS bytes beyond VDL may be
        // nonzero even though reads return zeros, so they must stay compared.
        let whole_end = route
            .stream_length
            .min(data.logical_size)
            .min(data.initialized_size)
            / 4096
            * 4096;
        let route_end = route
            .logical_offset
            .checked_add(route.length)
            .context("route overflow")?
            .min(whole_end);
        for extent in &data.extents {
            let Some(physical) = extent.physical_offset else {
                continue;
            };
            let start = extent.logical_offset.max(route.logical_offset);
            let end = extent
                .logical_offset
                .checked_add(extent.length)
                .context("NTFS extent overflow")?
                .min(route_end);
            if end <= start {
                continue;
            }
            let ntfs_physical = physical + (start - extent.logical_offset);
            let shadow_physical = route.target_physical_offset + (start - route.logical_offset);
            if ntfs_physical == shadow_physical
                && start.is_multiple_of(4096)
                && end.is_multiple_of(4096)
            {
                found.push(crate::refs_write_set::ByteRange {
                    offset: shadow_physical,
                    length: end - start,
                });
            }
        }
    }
    found.sort_by_key(|range| range.offset);
    let mut merged: Vec<crate::refs_write_set::ByteRange> = Vec::with_capacity(found.len());
    for range in found {
        match merged.last_mut() {
            Some(last) if range.offset <= last.offset + last.length => {
                last.length =
                    (last.offset + last.length).max(range.offset + range.length) - last.offset;
            }
            _ => merged.push(range),
        }
    }
    Ok(merged)
}

/// Candidate copy addresses come only from the same inventory and protected
/// native routes used by the live target proof. Capture still compares their
/// actual bytes and admits only origins covered by preceding changed ranges.
fn payload_copy_candidates(
    volume_bytes: u64,
    raw: &ntfs_inspect::NtfsInspection,
    tree: &shadow_tree::Tree,
    routes: &n2r_win32::shadow_native::private_tree::SourceBackedRoutes,
) -> Result<Vec<crate::payload_copy_plan::CopySpan>> {
    use crate::payload_copy_plan::{
        self as cp, ByteRange, FileIdentity, SourceExtent, SourceStream, TargetRoute,
    };
    use std::collections::BTreeMap;
    let mut attributes = BTreeMap::new();
    let mut requested = Vec::new();
    let mut target_routes = Vec::new();
    for route in routes.entries() {
        let object = tree
            .objects
            .get(route.object_index)
            .context("copy route object absent")?;
        let stream = object
            .stream(&route.stream_name_utf16)
            .context("copy route stream absent")?;
        ensure!(
            stream.length == route.stream_length && stream.sha256 == route.expected_sha256,
            "copy route differs from canonical stream"
        );
        let mut matches = raw.files.iter().filter(|file| {
            file.record_number == object.record_number
                && file.sequence_number == object.sequence_number
        });
        let file = matches.next().context("copy route source absent")?;
        ensure!(matches.next().is_none(), "copy route source ambiguous");
        let data: Vec<_> = file
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.type_code == 0x80 && attribute.name_utf16 == route.stream_name_utf16
            })
            .collect();
        let [attribute] = data.as_slice() else {
            continue;
        };
        if file.is_directory
            || object.directory
            || attribute.resident
            || attribute.flags != 0
            || attribute.lowest_vcn != 0
            || attribute.compression_unit != 0
            || attribute.extents.iter().any(|extent| {
                extent.physical_offset.is_none()
                    || !extent.logical_offset.is_multiple_of(4096)
                    || !extent.length.is_multiple_of(4096)
                    || !extent.physical_offset.unwrap_or(1).is_multiple_of(4096)
            })
        {
            continue;
        }
        ensure!(
            attribute.logical_size == route.stream_length,
            "copy route stream size differs"
        );
        let end = route
            .logical_offset
            .checked_add(route.length)
            .context("copy route overflow")?
            .min(attribute.initialized_size)
            .min(attribute.logical_size)
            / 4096
            * 4096;
        let start = route
            .logical_offset
            .checked_add(4095)
            .context("copy route alignment overflow")?
            / 4096
            * 4096;
        if end <= start {
            continue;
        }
        let destination_offset = route
            .target_physical_offset
            .checked_add(start - route.logical_offset)
            .context("copy destination overflow")?;
        let identity = FileIdentity {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
        };
        attributes
            .entry((identity, route.stream_name_utf16.clone()))
            .or_insert(*attribute);
        requested.push(ByteRange {
            offset: destination_offset,
            length: end - start,
        });
        target_routes.push(TargetRoute {
            identity,
            stream_name_utf16: &route.stream_name_utf16,
            logical_offset: start,
            destination_offset,
            length: end - start,
            stream_length: route.stream_length,
        });
    }
    requested.sort_by_key(|range| range.offset);
    let storage: Vec<_> = attributes
        .into_iter()
        .map(|(identity, attribute)| {
            let extents: Vec<_> = attribute
                .extents
                .iter()
                .map(|extent| SourceExtent {
                    logical_offset: extent.logical_offset,
                    physical_offset: extent.physical_offset,
                    length: extent.length,
                })
                .collect();
            (identity, attribute, extents)
        })
        .collect();
    let streams: Vec<_> = storage
        .iter()
        .map(|((identity, name), attribute, extents)| SourceStream {
            identity: *identity,
            stream_name_utf16: name,
            logical_length: attribute.logical_size,
            initialized_length: attribute.initialized_size,
            ordinary_file: true,
            nonresident: true,
            default_data: name.is_empty(),
            attribute_flags: attribute.flags,
            lowest_vcn: attribute.lowest_vcn,
            extents,
        })
        .collect();
    cp::plan_copies(volume_bytes, &requested, &streams, &target_routes)
}

/// `left` minus `right`, both sorted and coalesced.
fn subtract_ranges(
    left: &[crate::refs_write_set::ByteRange],
    right: &[crate::refs_write_set::ByteRange],
) -> Vec<crate::refs_write_set::ByteRange> {
    let mut out = Vec::new();
    let mut first = 0usize;
    for range in left {
        let end = range.offset + range.length;
        while first < right.len() && right[first].offset + right[first].length <= range.offset {
            first += 1;
        }
        let mut cursor = range.offset;
        for other in &right[first..] {
            if other.offset >= end {
                break;
            }
            if cursor < other.offset {
                out.push(crate::refs_write_set::ByteRange {
                    offset: cursor,
                    length: other.offset - cursor,
                });
            }
            cursor = cursor.max((other.offset + other.length).min(end));
        }
        if cursor < end {
            out.push(crate::refs_write_set::ByteRange {
                offset: cursor,
                length: end - cursor,
            });
        }
    }
    out
}

/// Allocation-bounded target proof: the shared protected prefix, then a
/// source-backed capture over only the protected native allocation.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_select(
    source: &mut GeneralFrozenPartition,
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    raw: &ntfs_inspect::NtfsInspection,
    source_views: &ntfs_source_view::Analysis,
    source_sha256: &str,
    resources: ResourceProfile,
    packed_path: &Path,
    max_changed_bytes: u64,
    events: &mut Vec<NativeEvent>,
) -> Result<FrozenAllocationTargetPreservation> {
    let ProtectedPrefix {
        length,
        source_before,
        target_before,
        inspection_sha256,
        source_views_sha256,
        tree,
        expected_tree_sha256,
        residuals,
        protected,
    } = protected_prefix(
        source,
        target,
        &pair,
        raw,
        source_views,
        source_sha256,
        resources,
        packed_path,
        max_changed_bytes,
        events,
        true,
    )?;
    let selection = protected
        .allocation_coverage()
        .observed_ranges(protected.native())?;
    let selection_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&selection)?));
    // Payload that stayed at its NTFS location is the same physical bytes in
    // both images; compare everything else in the selection.
    let in_place = in_place_payload_ranges(raw, &tree, protected.routes())?;
    let compared = subtract_ranges(&selection, &in_place);
    let compared_bytes: u64 = compared.iter().map(|range| range.length).sum();
    let selection_bytes: u64 = selection.iter().map(|range| range.length).sum();
    let in_place_bytes = selection_bytes - compared_bytes;
    // Non-gating destination split of the changed granules. The bracket above
    // already required this model; were it unavailable, the split would only
    // mark its NTFS counters unavailable.
    let ntfs_allocated = raw.allocated_byte_ranges(length).ok();
    let copy_candidates = payload_copy_candidates(length, raw, &tree, protected.routes())?;
    let mut capture = SourceBackedShadow::new(
        source,
        target,
        raw,
        &tree,
        protected.routes(),
        protected.routes().payload_bytes().max(1),
    )?
    .capture_listed_source_references_to_new_file(
        &compared,
        packed_path,
        max_changed_bytes,
        Some(ChangeClassSplit {
            ntfs_allocated: ntfs_allocated.as_deref(),
        }),
        &copy_candidates,
    )?;
    // Record the split once, beside the capture, keeping the capture object
    // in its earlier shape.
    let changed_classes = capture.changed_classes.take();
    ensure!(
        capture.selected_bytes_compared == compared_bytes
            && capture
                .equal_selected_bytes
                .checked_add(capture.layout.changed_bytes())
                == Some(compared_bytes)
            && capture.layout.changed_bytes() > 0
            && !capture.conversion_qualified,
        "allocation-bounded capture does not cover exactly the protected selection"
    );
    let mut backing = PinnedBacking::open(
        packed_path,
        capture.layout.packed_bytes(),
        &capture.packed_sha256,
    )?;
    for binding in [&pair.source, &pair.shadow] {
        ensure!(
            !backing
                .snapshot
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
            "allocation-bounded backing must be outside both frozen volumes"
        );
    }
    backing.revalidate()?;
    let source_after = source.state(events)?;
    let target_after = target.state(events)?;
    ensure!(
        source_after == source_before && target_after == target_before,
        "allocation-bounded preparation changed persistent device identity or exclusion"
    );
    Ok(FrozenAllocationTargetPreservation {
        pair,
        inspection_sha256,
        source_sha256: source_sha256.into(),
        source_views_sha256,
        expected_tree_sha256,
        resources,
        protected,
        residuals,
        selection,
        selection_sha256,
        compared,
        in_place_payload_bytes_not_compared: in_place_bytes,
        capture,
        changed_classes,
        backing,
        source_before,
        source_after,
        target_before,
        target_after,
        frozen_source_inventory_verified: true,
        frozen_source_inventory_basis: "allocated-range digest recheck; admission proved the inspection read only those ranges",
        source_views_bound: true,
        logical_payload_tied_to_frozen_source: true,
        allocation_bounded_selection_compared: true,
        free_space_contents_proven_equal: false,
        source_admitted: false,
        conversion_qualified: false,
    })
}

struct ProtectedPrefix {
    length: u64,
    source_before: GeneralDiskState,
    target_before: GeneralDiskState,
    inspection_sha256: String,
    source_views_sha256: String,
    tree: shadow_tree::Tree,
    expected_tree_sha256: String,
    residuals: Vec<LayoutResidualExpectation>,
    protected: ProtectedTargetLayout,
}

/// Shared by complete and allocation-bounded preparation: frozen bindings, the
/// unchanged source inventory, bound views, actual residual reads and the
/// protected native shadow observation. No difference capture happens here.
#[allow(clippy::too_many_arguments)]
fn protected_prefix(
    source: &mut GeneralFrozenPartition,
    target: &mut GeneralFrozenPartition,
    pair: &GeneralSourceShadowBinding,
    raw: &ntfs_inspect::NtfsInspection,
    source_views: &ntfs_source_view::Analysis,
    source_sha256: &str,
    resources: ResourceProfile,
    packed_path: &Path,
    max_changed_bytes: u64,
    events: &mut Vec<NativeEvent>,
    allocation_closed_bracket: bool,
) -> Result<ProtectedPrefix> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    ensure!(
        source.binding() == &pair.source
            && target.binding() == &pair.shadow
            && source.byte_len() == target.byte_len(),
        "composite device bindings differ"
    );
    let length = source.byte_len();
    ensure!(
        max_changed_bytes <= length
            && max_changed_bytes <= reference_file::MAX_REFERENCE_FILE_BYTES,
        "composite backing exceeds explicit byte or held-file profile bound"
    );
    fresh_ordinary_path(packed_path)?;
    let source_before = source.state(events)?;
    let target_before = target.state(events)?;
    ensure!(
        source_before.disk_attributes == 3 && target_before.disk_attributes == 3,
        "composite preparation requires both devices persistently frozen"
    );
    let inspection_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    if allocation_closed_bracket {
        // Admission digested the NTFS-allocated ranges and proved its
        // deterministic inspection read only inside them, so unchanged ranges
        // mean the same inspection; no second stream-hashing pass is needed.
        let ranges = raw.allocated_byte_ranges(length)?;
        ensure!(
            hex::encode(crate::lab_reconstruct::hash_ranges_xxh3(source, &ranges)?)
                == source_sha256,
            "composite frozen source allocated bytes changed"
        );
    } else {
        let actual = ntfs_inspect::inspect_with_limits(
            source,
            length,
            ntfs_inspect::limits_for_resource_profile(resources),
        )?;
        ensure!(
            hex::encode(Sha256::digest(serde_json::to_vec(&actual)?)) == inspection_sha256,
            "composite frozen source inventory changed"
        );
    }
    ensure!(
        source_views.binds_live_source(&inspection_sha256, source_sha256),
        "composite requires the same bound live source views"
    );
    let source_views_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(source_views)?));
    let mut tree = shadow_tree::derive_ordinary_with_resource_profile(raw, resources)?;
    tree.bind_security_views(source_views)?;
    let expected = shadow_tree::ExpectedTree::from(&tree);
    expected.validate_with_resource_profile(resources)?;
    let expected_tree_sha256 = hex::encode(Sha256::digest(serde_json::to_vec_pretty(&expected)?));
    let limits = resources.limits();
    let mut residual_budget = ntfs_inspect::StreamTransferBudget::new(
        limits.maximum_stream_bytes,
        limits.maximum_logical_bytes,
    )?;
    let mut residuals = Vec::new();
    let mut buffer = [0u8; 4096];
    for (index, object) in tree
        .objects
        .iter()
        .enumerate()
        .filter(|(_, item)| !item.directory)
    {
        for stream in object.data_streams() {
            let count = (stream.length % 4096) as usize;
            if count == 0 {
                continue;
            }
            let offset = stream.length / 4096 * 4096;
            let proof = ntfs_inspect::read_plain_named_stream_range_into(
                source,
                raw,
                object.record_number,
                stream.name_utf16,
                offset,
                &mut buffer[..count],
                &mut residual_budget,
            )?;
            ensure!(
                proof.stream_logical_bytes == stream.length
                    && stream.sha256 == proof.expected_stream_sha256,
                "composite residual source stream identity or digest differs"
            );
            residuals.push(LayoutResidualExpectation {
                object_index: index,
                stream_name_utf16: stream.name_utf16.to_vec(),
                logical_offset: offset,
                length: count as u64,
                sha256: proof.sha256,
            });
        }
    }
    let protected = if allocation_closed_bracket {
        general_target_preservation::verify_frozen_layout_residuals_allocation_closed(
            target,
            pair.clone(),
            &expected,
            resources,
            &residuals,
            events,
        )?
    } else {
        general_target_preservation::verify_frozen_layout_residuals_with_resource_profile(
            target,
            pair.clone(),
            &expected,
            resources,
            &residuals,
            events,
        )?
    };
    ensure!(
        protected.expected_tree_sha256() == expected_tree_sha256
            && protected.native().report().residual_contents_verified()
            && protected.native().report().residuals() == residuals,
        "protected composite target does not bind exact source residuals"
    );
    Ok(ProtectedPrefix {
        length,
        source_before,
        target_before,
        inspection_sha256,
        source_views_sha256,
        tree,
        expected_tree_sha256,
        residuals,
        protected,
    })
}

/// Retrospective comparison of an allocation-driven selection with the complete
/// capture. It grants nothing; the complete capture remains authoritative.
#[derive(Debug, Serialize)]
pub struct SelectivePlanDiagnostic {
    coarse_ranges: usize,
    coarse_bytes: u64,
    planned_ranges: usize,
    planned_bytes: u64,
    planned_journal_bytes: u64,
    complete_capture_ranges: usize,
    equals_complete_capture: bool,
    original_bytes_read: u64,
    candidate_source_logical_bytes_read: u64,
    candidate_shadow_bytes_read: u64,
    elapsed_seconds: f64,
    selective_capture_executable: bool,
    raw_write_authority: bool,
}

fn coalesced(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (offset, length) in ranges {
        match out.last_mut() {
            Some(last) if last.0 + last.1 == offset => last.1 += length,
            _ => out.push((offset, length)),
        }
    }
    out
}

fn selective_plan(
    source: &mut GeneralFrozenPartition,
    target: &mut GeneralFrozenPartition,
    raw: &ntfs_inspect::NtfsInspection,
    tree: &shadow_tree::Tree,
    protected: &ProtectedTargetLayout,
    capture: &DifferenceCapture,
    max_changed_bytes: u64,
) -> Result<SelectivePlanDiagnostic> {
    let started = std::time::Instant::now();
    let coarse: Vec<_> = protected
        .allocation_coverage()
        .observed_ranges(protected.native())?
        .into_iter()
        .map(|range| crate::selected_journal::SelectedRange {
            offset: range.offset,
            length: range.length,
        })
        .collect();
    let coarse_bytes: u64 = coarse.iter().map(|range| range.length).sum();
    let view = SourceBackedShadow::new(
        source,
        target,
        raw,
        tree,
        protected.routes(),
        protected.routes().payload_bytes().max(1),
    )?;
    let (plan, counts, original_bytes_read) =
        view.plan_changed_granules(&coarse, max_changed_bytes, u64::MAX)?;
    let (planned_bytes, planned_journal_bytes) = plan.validate()?;
    let complete = coalesced(
        capture
            .layout
            .intervals()
            .iter()
            .map(|range| (range.offset, range.length))
            .collect(),
    );
    let planned: Vec<_> = plan.ranges.iter().map(|r| (r.offset, r.length)).collect();
    Ok(SelectivePlanDiagnostic {
        coarse_ranges: coarse.len(),
        coarse_bytes,
        planned_ranges: planned.len(),
        planned_bytes,
        planned_journal_bytes,
        complete_capture_ranges: complete.len(),
        equals_complete_capture: planned == complete,
        original_bytes_read,
        candidate_source_logical_bytes_read: counts.source_logical_bytes,
        candidate_shadow_bytes_read: counts.shadow_bytes,
        elapsed_seconds: started.elapsed().as_secs_f64(),
        selective_capture_executable: false,
        raw_write_authority: false,
    })
}

fn fresh_ordinary_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && !path.exists(),
        "fresh absolute composite backing path required"
    );
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => ensure!(
                matches!(prefix.kind(), Prefix::Disk(_)),
                "composite backing requires an ordinary local drive path"
            ),
            Component::ParentDir | Component::CurDir => {
                anyhow::bail!("ambiguous composite backing path")
            }
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .context("Unicode composite backing path required")?;
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                ensure!(
                    !name.contains([':', '\0'])
                        && !name.ends_with([' ', '.'])
                        && !matches!(
                            stem.as_str(),
                            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                        )
                        && !(stem.len() == 4
                            && (stem.starts_with("COM") || stem.starts_with("LPT"))
                            && stem.as_bytes()[3].is_ascii_digit()),
                    "nonordinary composite backing name"
                );
            }
            _ => {}
        }
    }
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|value| !value.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "composite backing ancestry contains a reparse point or nondirectory"
        );
    }
    Ok(())
}
