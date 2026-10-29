//! Frozen native-shadow target whose ordinary payload is supplied by the
//! frozen NTFS source. Complete address-space comparison, not bitmap inference,
//! proves the compact backing. This module issues no source/write certificate.
use crate::{
    general_shadow::source_backed::{DifferenceCapture, SourceBackedShadow},
    general_target_preservation::{self, ProtectedTargetLayout},
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
    io::{Read, Seek, SeekFrom},
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
    let (observed_source_sha256, source_framed_sha256) = hash_image(source, length)?;
    ensure!(
        observed_source_sha256 == source_sha256,
        "composite frozen source SHA-256 differs"
    );
    let inspection_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    let actual = ntfs_inspect::inspect_with_limits(
        source,
        length,
        ntfs_inspect::limits_for_resource_profile(resources),
    )?;
    ensure!(
        hex::encode(Sha256::digest(serde_json::to_vec(&actual)?)) == inspection_sha256,
        "composite frozen source inventory changed"
    );
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
        let count = (object.length % 4096) as usize;
        if count == 0 {
            continue;
        }
        let offset = object.length / 4096 * 4096;
        let proof = ntfs_inspect::read_plain_stream_range_into(
            source,
            raw,
            object.record_number,
            offset,
            &mut buffer[..count],
            &mut residual_budget,
        )?;
        ensure!(
            proof.stream_logical_bytes == object.length
                && object.sha256.as_deref() == Some(proof.expected_stream_sha256.as_str()),
            "composite residual source stream identity or digest differs"
        );
        residuals.push(LayoutResidualExpectation {
            object_index: index,
            logical_offset: offset,
            length: count as u64,
            sha256: proof.sha256,
        });
    }
    let protected =
        general_target_preservation::verify_frozen_layout_residuals_with_resource_profile(
            target,
            pair.clone(),
            &expected,
            resources,
            &residuals,
            events,
        )?;
    ensure!(
        protected.expected_tree_sha256() == expected_tree_sha256
            && protected.native().report().residual_contents_verified()
            && protected.native().report().residuals() == residuals,
        "protected composite target does not bind exact source residuals"
    );
    let capture = SourceBackedShadow::new(
        source,
        target,
        raw,
        &tree,
        protected.routes(),
        protected.routes().payload_bytes().max(1),
    )?
    .capture_complete_differences_to_new_file(packed_path, max_changed_bytes)?;
    ensure!(
        capture.selected_bytes_compared == length
            && capture.source_selected_sha256 == source_framed_sha256
            && capture
                .equal_selected_bytes
                .checked_add(capture.layout.changed_bytes())
                == Some(length)
            && !capture.conversion_qualified,
        "composite capture does not cover the complete frozen source address space"
    );
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
    let (composite_target_sha256, composite_framed_sha256) = {
        let mut image = DifferenceImage::new(source, &mut backing.file, &capture.layout)?;
        hash_image(&mut image, length)?
    };
    ensure!(
        composite_framed_sha256 == capture.candidate_selected_sha256,
        "reopened compact image differs from the complete supplied candidate"
    );
    backing.revalidate()?;
    ensure!(
        hex::encode(lab_reconstruct::hash_range_with_resource_profile(
            target, 0, length, resources,
        )?) == protected.raw_sha256(),
        "raw shadow changed after protected observation"
    );
    ensure!(
        hex::encode(lab_reconstruct::hash_range_with_resource_profile(
            source, 0, length, resources,
        )?) == source_sha256,
        "source changed around composite preparation"
    );
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

fn hash_image(reader: &mut (impl Read + Seek), length: u64) -> Result<(String, String)> {
    ensure!(
        reader.seek(SeekFrom::End(0))? == length,
        "composite hash reader length differs"
    );
    reader.seek(SeekFrom::Start(0))?;
    let mut raw = n2r_win32::sha256_native::Sha256::new()?;
    let mut framed = n2r_win32::sha256_native::Sha256::new()?;
    framed.update(&0u64.to_le_bytes())?;
    framed.update(&length.to_le_bytes())?;
    // This is a complete native/difference-image hash, not a logical NTFS
    // parser read. Match the native reader's 1 MiB batch while keeping the
    // same exact byte sequence and both raw/framed digest contracts.
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut remaining = length;
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        raw.update(&buffer[..count])?;
        framed.update(&buffer[..count])?;
        remaining -= count as u64;
    }
    Ok((hex::encode(raw.finish()?), hex::encode(framed.finish()?)))
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
