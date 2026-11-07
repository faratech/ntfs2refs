//! Resource-selected native requests backed by the actual complete raw page
//! owner. This avoids rebuilding a volume-sized selector Vec in Request JSON.
use crate::{
    ntfs_inspect::{PagedInspection, RootFileDomain},
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::attestation::NativeObservationDomain;
use n2r_win32::{
    attestation::{FileIdentity, NativeRequestDomain, NativeRequestRow, Request, ResourceProfile},
    general_layout::GeneralDiskBinding,
    tree_resources::{MetadataPageBudget, ResourceBudget, SourceResourceAdmission},
};
use serde::Serialize;
use std::{borrow::Cow, io};

pub struct PagedObservationRequest<'a> {
    source: &'a PagedInspection,
    request: Request,
    admission: SourceResourceAdmission,
    policy: VerificationPolicy,
    length: usize,
    windows_paths: bool,
}
impl<'a> PagedObservationRequest<'a> {
    pub fn new(
        source: &'a PagedInspection,
        binding: &GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
    ) -> Result<Self> {
        binding.validate()?;
        budget.validate()?;
        // Collection observes canonical native names. DOS alias preservation
        // remains a separate boot-only shadow obligation and admission gate.
        let windows_paths = binding.layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows;
        ensure!(windows_paths == source.is_windows_conversion(),
            "native Windows namespace policy differs from actual source inspection purpose");
        let header = source.header();
        ensure!(
            header.inventory_complete
                && header.records_scanned != 0
                && header.records_scanned <= header.mft_record_count,
            "native selector requires the actual complete source inventory"
        );
        ensure!(
            header.geometry.volume_size == binding.identity.partition_bytes
                || header
                    .geometry
                    .volume_size
                    .checked_add(u64::from(header.geometry.bytes_per_sector))
                    == Some(binding.identity.partition_bytes),
            "paged source and actual native partition geometry differ"
        );
        let pin = source.canonical_sha256()?;
        let pin_bytes: [u8; 32] = hex::decode(&pin)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("paged source pin length differs"))?;
        let mut files = 0u64;
        let mut directories = 0u64;
        let mut streams = 0u64;
        for ordinal in 0..source.file_count() {
            let file = source.file(ordinal)?;
            if crate::ntfs_admission::paged::internal_role(source, &file)?.is_some() {
                continue;
            }
            if windows_paths {
                crate::ntfs_admission::paged::canonical_paths_for_alias_preparation(source, &file)?;
            } else {
                crate::ntfs_admission::paged::user_paths(source, &file)?;
            }
            if file.is_directory {
                directories = directories
                    .checked_add(1)
                    .context("directory count overflow")?;
            } else {
                files = files.checked_add(1).context("file count overflow")?;
                streams = streams
                    .checked_add(u64::try_from(file.streams.len())?)
                    .context("stream count overflow")?;
            }
        }
        let admission = SourceResourceAdmission::new(
            pin_bytes,
            header.mft_record_count,
            source.file_count(),
            files,
            directories,
            streams,
            budget,
        )?;
        source.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        let value = Self {
            source,
            request: Request {
                schema_version: if policy.is_fast() { 8 } else { 7 },
                resource_profile: Some(ResourceProfile::ResourceBoundedV4(Some(admission))),
                source_inspection_sha256: pin,
                volume: format!("{}\\", binding.volume_path()?),
                disk_number: binding.disk_number,
                partition_offset: binding.identity.partition_offset,
                partition_length: binding.identity.partition_bytes,
                ntfs_serial: header.geometry.serial_number,
                files: Vec::new(),
                extent_identity_streams: Vec::new(),
            },
            admission,
            policy,
            length: usize::try_from(source.file_count())?,
            windows_paths,
        };
        n2r_win32::attestation::validate_native_request_domain(&value)?;
        Ok(value)
    }
    pub fn admission(&self) -> SourceResourceAdmission {
        self.admission
    }
}
impl NativeRequestDomain for PagedObservationRequest<'_> {
    fn header(&self) -> &Request {
        &self.request
    }
    fn len(&self) -> usize {
        self.length
    }
    fn identity(&self, index: usize) -> io::Result<FileIdentity> {
        if index >= self.length {
            return Err(io::Error::other("source selector ordinal absent"));
        }
        let file = self.source.file(index as u64).map_err(io::Error::other)?;
        Ok(FileIdentity {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
        })
    }
    fn windows_txf_metadata_identity(&self, index: usize) -> io::Result<Option<FileIdentity>> {
        (|| -> Result<_> {
            if !self.windows_paths { return Ok(None); }
            ensure!(self.source.is_windows_conversion() && index < self.length,
                "Windows TxF selector does not belong to the retained Windows source");
            let file = self.source.file(index as u64)?;
            if file.record_number != 5 && (file.record_number < 16
                || file.metadata_role != crate::ntfs_inspect::MetadataRole::OutsideExtendCandidate) {
                return Ok(None);
            }
            let mut attributes = file.attributes.iter().filter(|attribute| attribute.type_code == 0x100
                && attribute.name_utf16 == [36,84,88,70,95,68,65,84,65]);
            let Some(attribute) = attributes.next() else { return Ok(None); };
            ensure!(attributes.next().is_none() && crate::ntfs_admission::recognized_root_txf(attribute)
                && attribute.resident_metadata_hex.as_ref().is_some_and(|bytes| bytes.len() == 112),
                "Windows TxF selector requires exact bounded resident marker bytes at FILE {}", file.record_number);
            Ok(Some(FileIdentity { record_number: file.record_number, sequence_number: file.sequence_number }))
        })().map_err(io::Error::other)
    }
    fn windows_object_id_identity(&self, index: usize) -> io::Result<Option<FileIdentity>> {
        (|| -> Result<_> {
            if !self.windows_paths { return Ok(None); }
            ensure!(self.source.is_windows_conversion() && index < self.length,
                "Windows object-ID selector does not belong to the retained Windows source");
            let file = self.source.file(index as u64)?;
            if file.record_number < 16 { return Ok(None); }
            let mut attributes = file.attributes.iter().filter(|attribute| attribute.type_code == 0x40);
            let Some(attribute) = attributes.next() else { return Ok(None); };
            ensure!(file.base_file_reference == 0
                && file.metadata_role == crate::ntfs_inspect::MetadataRole::OutsideExtendCandidate
                && attributes.next().is_none() && attribute.resident && attribute.name_utf16.is_empty()
                && attribute.flags == 0 && attribute.logical_size == 16
                && attribute.initialized_size == 16 && attribute.allocated_size == 16
                && attribute.lowest_vcn == 0 && attribute.compression_unit == 0 && attribute.extents.is_empty()
                && attribute.resident_metadata_hex.as_ref().is_some_and(|bytes| bytes.len() == 32),
                "Windows object-ID selector requires exact resident16 bytes at FILE {}", file.record_number);
            Ok(Some(FileIdentity { record_number: file.record_number, sequence_number: file.sequence_number }))
        })().map_err(io::Error::other)
    }
    fn row(&self, index: usize) -> io::Result<Cow<'_, NativeRequestRow>> {
        (|| -> Result<_> {
            ensure!(index < self.length, "source selector ordinal absent");
            let file = self.source.file(index as u64)?;
            let mut row = NativeRequestRow {
                identity: FileIdentity {
                    record_number: file.record_number,
                    sequence_number: file.sequence_number,
                },
                extent_identity_streams: Vec::new(),
            };
            if self.policy.is_fast() {
                for stream in &file.streams {
                    let selector = if self.windows_paths {
                        super::extent_identity_stream_request_windows_domain(self.source, &file, stream)?
                    } else {
                        super::extent_identity_stream_request_domain(
                            self.source, &file, stream, true, true,
                        )?
                    };
                    if let Some(selector) = selector {
                        row.extent_identity_streams.push(selector);
                    }
                }
            }
            // Enforce the row budget while serializing without allocating a
            // second JSON buffer. The raw owner bounds its decoded input row.
            struct Counter {
                bytes: u64,
                maximum: u64,
            }
            impl io::Write for Counter {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    self.bytes = self
                        .bytes
                        .checked_add(bytes.len() as u64)
                        .filter(|n| *n <= self.maximum)
                        .ok_or_else(|| {
                            io::Error::other("native selector row exceeds admitted RAM")
                        })?;
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            serde_json::to_writer(
                Counter {
                    bytes: 0,
                    maximum: self.admission.budget.max_row_bytes,
                },
                &row,
            )?;
            Ok(Cow::Owned(row))
        })()
        .map_err(io::Error::other)
    }
    fn revalidate(&self) -> io::Result<()> {
        self.source.revalidate().map_err(io::Error::other)?;
        if self.source.canonical_sha256().map_err(io::Error::other)?
            != self.request.source_inspection_sha256
        {
            return Err(io::Error::other(
                "complete source pin changed during native selection",
            ));
        }
        Ok(())
    }
    fn require_paged_source(&self, budget: MetadataPageBudget, semantic: u64) -> io::Result<()> {
        if budget != self.admission.source_pages
            || semantic != self.admission.semantic_byte_budget()
        {
            return Err(io::Error::other(
                "native selector resource admission differs",
            ));
        }
        self.source
            .require_paged_source(budget, semantic)
            .map_err(io::Error::other)
    }
}

#[derive(Serialize)]
pub struct PagedFileComparison {
    pub record_number: u64,
    pub sequence_number: u16,
    pub internal_replacement_role: Option<String>,
    pub metadata: crate::ntfs_stream_attestation::Check,
    pub streams: crate::ntfs_stream_attestation::Check,
    pub logical_data: crate::ntfs_stream_attestation::Check,
    pub namespace: Option<crate::ntfs_stream_attestation::Check>,
    pub directory_case: Option<crate::ntfs_stream_attestation::Check>,
    pub timestamps: Option<crate::ntfs_source_view::TimestampView>,
    pub security: Option<crate::ntfs_source_view::SecurityView>,
    pub complete_logical_bytes: u64,
    pub extent_identity_streams: u64,
    pub extent_identity_logical_bytes: u64,
}
#[derive(Serialize)]
pub struct PagedComparisonSummary {
    pub schema_version: u32,
    pub source_inspection_sha256: String,
    pub source_resource_admission: SourceResourceAdmission,
    pub requested_files: u64,
    pub user_objects: u64,
    pub matched_user_objects: u64,
    pub recognized_internal_objects: u64,
    pub all_supported_user_views_compatible: bool,
    pub conversion_qualified: bool,
}

/// Reconcile every actual native row against the retained complete source.
/// Per-object results go directly to the caller's bounded sink. No report-sized
/// object collection or selector list is reconstructed. Recognized filesystem
/// internals retain their individual failures and replacement obligations;
/// this diagnostic never supplies source admission or a conversion certificate.
pub fn compare_domain(
    source: &PagedInspection,
    binding: &GeneralDiskBinding,
    budget: ResourceBudget,
    policy: VerificationPolicy,
    native: &impl NativeObservationDomain,
    emit: impl FnMut(PagedFileComparison) -> Result<()>,
) -> Result<PagedComparisonSummary> {
    compare_domain_with_header(source,binding,budget,policy,native,emit,super::check_header_geometry)
}
/// Only an actual phase-bound wrapper may select partition protection rules.
pub(crate) fn compare_partition_domain(
    source: &PagedInspection,
    binding: &GeneralDiskBinding,
    budget: ResourceBudget,
    policy: VerificationPolicy,
    observed: &n2r_win32::attestation_partition::PartitionPagedNtfsObservation,
    phase: &mut n2r_win32::partition_lifecycle::PartitionReadonlyPhase<'_>,
    events: &mut Vec<n2r_win32::NativeEvent>,
    emit: impl FnMut(PagedFileComparison)->Result<()>,
) -> Result<PagedComparisonSummary> {
    observed.require_phase(phase,events)?;
    let result=compare_domain_with_header(source,binding,budget,policy,observed.domain(),emit,
        |geometry,_|super::check_partition_header_geometry(geometry,observed))?;
    observed.require_phase(phase,events)?;
    Ok(result)
}
fn compare_domain_with_header(
    source: &PagedInspection,
    binding: &GeneralDiskBinding,
    budget: ResourceBudget,
    policy: VerificationPolicy,
    native: &impl NativeObservationDomain,
    mut emit: impl FnMut(PagedFileComparison) -> Result<()>,
    mut check_header: impl FnMut(&crate::ntfs_inspect::NtfsGeometry,&n2r_win32::attestation::Report)->Result<()>,
) -> Result<PagedComparisonSummary> {
    use crate::ntfs_stream_attestation::Check;
    let expected = PagedObservationRequest::new(source, binding, budget, policy)?;
    let admission = expected.admission();
    let header = native.header();
    ensure!(
        native.is_paged()
            && matches!(
                (header.schema_version, header.request.schema_version),
                (15, 7) | (16, 8)
            )
            && !header.conversion_qualified,
        "resource reconciliation requires the actual paged native owner"
    );
    n2r_win32::attestation::validate_domain_resources(native)?;
    ensure!(
        serde_json::to_vec(&header.request)? == serde_json::to_vec(expected.header())?,
        "native request differs from complete current source selection"
    );
    ensure!(
        native.len() == expected.len()
            && native.logical_len() == expected.len()
            && native.namespace_len() == expected.len()
            && native.request_len()? == expected.len(),
        "native source coverage differs"
    );
    check_header(&source.header().geometry, header)?;
    let allocation = header
        .allocation
        .as_ref()
        .context("native allocation bracket absent")?;
    let base = crate::ntfs_stream_attestation::base(&allocation.base_before)?;
    ensure!(
        allocation.base_before == allocation.base_after,
        "native retrieval base changed"
    );
    ensure!(
        allocation.bitmap_before == allocation.bitmap_after
            && allocation.streamed_before == allocation.streamed_after,
        "native allocation response or complete bitmap bracket changed"
    );
    let raw_allocation = source.allocation();
    let bitmap = crate::ntfs_allocation::BitmapSummary {
        sha256: raw_allocation.bitmap_sha256.clone(),
        bitmap_bytes: raw_allocation.domain_clusters.div_ceil(8),
        allocated_clusters: raw_allocation.allocated_clusters,
        free_clusters: raw_allocation.free_clusters,
    };
    for (first, summary) in [
        (&allocation.bitmap_before, &allocation.streamed_before),
        (&allocation.bitmap_after, &allocation.streamed_after),
    ] {
        crate::ntfs_stream_attestation::check_streamed_bitmap_with_resources(
            &source.header().geometry,
            &bitmap,
            first,
            summary
                .as_ref()
                .context("complete native bitmap summary absent")?,
            admission,
        )?;
    }
    let mut summary = PagedComparisonSummary {
        schema_version: 1,
        source_inspection_sha256: source.canonical_sha256()?,
        source_resource_admission: admission,
        requested_files: source.file_count(),
        user_objects: 0,
        matched_user_objects: 0,
        recognized_internal_objects: 0,
        all_supported_user_views_compatible: false,
        conversion_qualified: false,
    };
    for ordinal in 0..expected.len() {
        let file = source.file(ordinal as u64)?;
        let native_row = native.row_view(ordinal)?;
        let selector = native_row.request();
        ensure!(
            selector == expected.row(ordinal)?.as_ref(),
            "native selector row differs from independently decoded source"
        );
        let observation = native_row.observation();
        let logical = native_row.logical()?;
        ensure!(
            observation.identity == selector.identity && logical.identity == selector.identity,
            "native row identity differs from selected source record"
        );
        let role = crate::ntfs_admission::paged::internal_role(source, &file)?;
        let mut timestamps = None;
        let mut security_view = None;
        let mut metadata = Check::from((|| {
            ensure!(
                observation.open_error.is_none(),
                "native metadata open refused: {:?}",
                observation.open_error
            );
            let binding = source
                .security()
                .find_binding(file.record_number)?
                .context("source security binding absent")?;
            ensure!(
                binding.sequence_number == file.sequence_number,
                "source security binding sequence differs"
            );
            let descriptor = if let Some(id) = binding.security_id {
                source.security().find_id(id)?
            } else {
                source.security().find_legacy(file.record_number)?
            }
            .context("source security descriptor absent")?;
            ensure!(
                descriptor.descriptor.sha256 == binding.descriptor_sha256,
                "source security descriptor binding differs"
            );
            let descriptor = hex::decode(&descriptor.descriptor.relative_hex)?;
            let before = observation
                .before
                .as_ref()
                .context("native metadata before absent")?;
            let after = observation
                .after
                .as_ref()
                .context("native metadata after absent")?;
            let check_metadata = if expected.windows_paths {
                crate::ntfs_source_view::check_metadata_windows_with_limit
            } else {
                crate::ntfs_source_view::check_metadata_with_limit
            };
            timestamps = Some(check_metadata(
                &file,
                source.header().geometry.serial_number,
                &descriptor,
                before,
                after,
                admission.budget.max_row_bytes,
            )?);
            security_view = Some(crate::ntfs_source_view::check_security_views_with_limit(
                &descriptor,
                before,
                after,
                admission.budget.max_row_bytes,
            )?);
            Ok(())
        })());
        if expected.windows_paths && metadata.matched
            && usize::from(file.hard_link_count) != file.names.len() {
            metadata.detail = format!(
                "raw FILE header link-counter hint preserved: raw={}, FILE_NAME={}, canonical={}; native before/after canonical counts match; complete native namespace coverage remains required",
                file.hard_link_count, file.names.len(),
                file.names.iter().filter(|name| name.namespace != 2).count());
        }
        let streams = Check::from((|| {
            ensure!(
                observation.open_error.is_none(),
                "native stream metadata open refused"
            );
            for capture in [&observation.streams_before, &observation.streams_after] {
                crate::ntfs_stream_attestation::check_file_with_resources(
                    &file,
                    capture
                        .as_ref()
                        .context("native complete stream mapping absent")?,
                    base,
                    &source.header().geometry,
                    admission,
                )?;
            }
            ensure!(
                observation.streams_before == observation.streams_after,
                "native complete stream observations changed between passes"
            );
            Ok(())
        })());
        let mut logical_bytes = (0, 0, 0);
        let logical_data = Check::from((|| {
            ensure!(
                observation.open_error.is_none(),
                "native logical file open refused"
            );
            logical_bytes = crate::ntfs_data_attestation::check_file_with_extent_evidence_domain_scoped(
                source,
                &file,
                &logical,
                &observation,
                header,
                &selector,
                admission,
                expected.windows_paths,
            )?;
            Ok(())
        })());
        let directory = native_row.namespace()?;
        ensure!(
            directory.identity == selector.identity,
            "native namespace row coverage/order differs"
        );
        let (namespace, directory_case) = if file.is_directory {
            ensure!(
                directory.identity == selector.identity,
                "native directory coverage/order differs"
            );
            (
                Some(Check::from(
                    crate::ntfs_namespace_attestation::check_projected_directory_domain(
                        source,
                        source.directories(),
                        &file,
                        &directory,
                        admission,
                    )
                    .map(|_| ()),
                )),
                Some(Check::from(super::check_directory_case_observation(
                    &file,
                    source.header().geometry.serial_number,
                    &observation,
                ))),
            )
        } else {
            ensure!(
                directory.before.is_none() && directory.after.is_none(),
                "native non-directory carries directory enumeration"
            );
            (None, None)
        };
        let matched = metadata.matched
            && streams.matched
            && logical_data.matched
            && namespace.as_ref().is_none_or(|c| c.matched)
            && directory_case.as_ref().is_none_or(|c| c.matched);
        if role.is_some() {
            summary.recognized_internal_objects += 1;
        } else {
            summary.user_objects += 1;
            summary.matched_user_objects += u64::from(matched);
        }
        emit(PagedFileComparison {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            internal_replacement_role: role,
            metadata,
            streams,
            logical_data,
            namespace,
            directory_case,
            timestamps,
            security: security_view,
            complete_logical_bytes: logical_bytes.0,
            extent_identity_streams: u64::try_from(logical_bytes.1)?,
            extent_identity_logical_bytes: logical_bytes.2,
        })?;
    }
    expected.revalidate()?;
    native.revalidate()?;
    summary.all_supported_user_views_compatible =
        summary.user_objects != 0 && summary.matched_user_objects == summary.user_objects;
    Ok(summary)
}
