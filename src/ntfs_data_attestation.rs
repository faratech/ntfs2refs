//! Logical data equality through native file reads, including EOF and zeroes.
use crate::{
    ntfs_inspect::{FileInventory, LogicalHashStatus, NtfsInspection},
    ntfs_stream_attestation::Check,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    attestation::{LogicalFile, Query, Report, StreamHash},
    logical_hash::Status,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct FileCheck {
    pub record_number: u64,
    pub sequence_number: u16,
    pub streams: usize,
    pub logical_bytes: u64,
    pub all_requested_stream_evidence_matched: bool,
    #[serde(skip_serializing_if = "zero_count")]
    pub extent_identity_streams: usize,
    #[serde(skip_serializing_if = "zero_bytes")]
    pub extent_identity_logical_bytes: u64,
    pub check: Check,
}
#[derive(Debug, Serialize)]
pub struct Reconciliation {
    pub audit: Check,
    pub matched_files: usize,
    pub matched_streams: usize,
    pub logical_bytes_verified_per_pass: u64,
    pub native_bytes_read: u64,
    pub files: Vec<FileCheck>,
    pub all_logical_data_matched: bool,
    /// Full hashes or explicitly checked physical identity, with the methods
    /// counted separately. This never means unread content was hashed.
    pub all_requested_stream_evidence_matched: bool,
    #[serde(skip_serializing_if = "zero_count")]
    pub extent_identity_streams: usize,
    #[serde(skip_serializing_if = "zero_bytes")]
    pub extent_identity_logical_bytes: u64,
    pub conversion_qualified: bool,
}
fn zero_count(n: &usize) -> bool {
    *n == 0
}
fn zero_bytes(n: &u64) -> bool {
    *n == 0
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn identity(q: Option<&Query>, file: &FileInventory, serial: u64) -> Result<()> {
    let q = q.context("missing logical-read identity")?;
    ensure!(
        q.class == 18 && q.bytes.len() == 24 && q.native_error.is_none(),
        "logical-read identity query refused"
    );
    ensure!(
        u64le(&q.bytes, 0) == serial
            && u64le(&q.bytes, 8) == (file.record_number | u64::from(file.sequence_number) << 48)
            && u64le(&q.bytes, 16) == 0,
        "logical-read identity differs"
    );
    Ok(())
}
fn standard(q: Option<&Query>, expected: u64) -> Result<()> {
    let q = q.context("missing logical-read length evidence")?;
    ensure!(
        q.class == 1 && q.bytes.len() == 24 && q.native_error.is_none(),
        "logical-read length query refused"
    );
    ensure!(
        u64le(&q.bytes, 8) == expected && q.bytes[20] == 0,
        "logical-read EOF or delete state differs"
    );
    Ok(())
}
pub fn check_file(file: &FileInventory, native: &LogicalFile, serial: u64) -> Result<u64> {
    ensure!(
        native.identity.record_number == file.record_number
            && native.identity.sequence_number == file.sequence_number,
        "logical file identity differs"
    );
    ensure!(
        file.base_file_reference == 0
            && !file
                .attributes
                .iter()
                .any(|a| a.type_code == 0x20 || a.lowest_vcn != 0),
        "logical attribute assembly incomplete"
    );
    let mut total = 0u64;
    for pass in [&native.before, &native.after] {
        let names: BTreeSet<_> = pass.iter().map(|h| &h.name_utf16).collect();
        let expected: BTreeSet<_> = file.streams.iter().map(|s| &s.name_utf16).collect();
        ensure!(
            pass.len() == file.streams.len()
                && names.len() == pass.len()
                && expected.len() == file.streams.len()
                && names == expected,
            "logical stream coverage differs"
        );
        for s in &file.streams {
            let h: &StreamHash = pass.iter().find(|h| h.name_utf16 == s.name_utf16).unwrap();
            ensure!(
                s.logical_hash_status == LogicalHashStatus::Complete,
                "raw logical stream hash is incomplete"
            );
            let expected = s
                .logical_sha256
                .as_ref()
                .context("missing raw logical hash")?;
            ensure!(
                h.logical_size == s.logical_size
                    && h.outcome.status == Status::Complete
                    && h.outcome.eof_confirmed
                    && h.outcome.bytes_read == s.logical_size
                    && h.outcome.native_error.is_none()
                    && h.outcome.detail.is_none(),
                "native logical read incomplete: {:?}, {:?}",
                h.outcome.status,
                h.outcome.detail
            );
            ensure!(
                h.outcome.sha256.as_ref() == Some(expected),
                "native logical bytes differ from raw initialized/sparse interpretation"
            );
            identity(h.identity_before.as_ref(), file, serial)?;
            identity(h.identity_after.as_ref(), file, serial)?;
            standard(h.standard_before.as_ref(), s.logical_size)?;
            standard(h.standard_after.as_ref(), s.logical_size)?;
            ensure!(
                h.identity_before == h.identity_after && h.standard_before == h.standard_after,
                "native logical read binding changed"
            );
        }
    }
    ensure!(
        native.before == native.after,
        "native logical stream snapshots differ"
    );
    for s in &file.streams {
        total = total
            .checked_add(s.logical_size)
            .context("logical byte accounting overflow")?;
    }
    Ok(total)
}

fn check_file_with_extent_evidence(
    raw: &NtfsInspection,
    file: &FileInventory,
    logical: &LogicalFile,
    observation: &n2r_win32::attestation::Observation,
    native: &Report,
) -> Result<(u64, usize, u64)> {
    check_file_with_selectors(
        &raw.geometry,
        file,
        logical,
        observation,
        native,
        &native.request.extent_identity_streams,
        |stream| crate::ntfs_attestation::extent_identity_stream_request(raw, file, stream),
        None,
    )
}

#[cfg(windows)]
pub fn check_file_with_extent_evidence_domain(
    source: &impl crate::ntfs_inspect::RootFileDomain,
    file: &FileInventory,
    logical: &LogicalFile,
    observation: &n2r_win32::attestation::Observation,
    native: &Report,
    selector: &n2r_win32::attestation::NativeRequestRow,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
) -> Result<(u64, usize, u64)> {
    check_file_with_extent_evidence_domain_scoped(
        source,
        file,
        logical,
        observation,
        native,
        selector,
        resources,
        false,
    )
}

/// Native comparison scope only. The caller derives Windows scope from the
/// bound layout; this flag cannot satisfy source or alias-preservation gates.
#[cfg(windows)]
pub(crate) fn check_file_with_extent_evidence_domain_scoped(
    source: &impl crate::ntfs_inspect::RootFileDomain,
    file: &FileInventory,
    logical: &LogicalFile,
    observation: &n2r_win32::attestation::Observation,
    native: &Report,
    selector: &n2r_win32::attestation::NativeRequestRow,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    windows_paths: bool,
) -> Result<(u64, usize, u64)> {
    resources.validate()?;
    ensure!(
        selector.identity == logical.identity,
        "logical selector identity differs"
    );
    check_file_with_selectors(
        &source.header().geometry,
        file,
        logical,
        observation,
        native,
        &selector.extent_identity_streams,
        |stream| {
            if windows_paths {
                crate::ntfs_attestation::extent_identity_stream_request_windows_domain(
                    source, file, stream,
                )
            } else {
                crate::ntfs_attestation::extent_identity_stream_request_domain(
                    source, file, stream, true, true,
                )
            }
        },
        Some(resources),
    )
}

fn check_file_with_selectors(
    geometry: &crate::ntfs_inspect::NtfsGeometry,
    file: &FileInventory,
    logical: &LogicalFile,
    observation: &n2r_win32::attestation::Observation,
    native: &Report,
    selectors: &[n2r_win32::attestation::ExtentIdentityStream],
    mut candidate: impl FnMut(
        &crate::ntfs_inspect::StreamInventory,
    ) -> Result<Option<n2r_win32::attestation::ExtentIdentityStream>>,
    resources: Option<n2r_win32::tree_resources::SourceResourceAdmission>,
) -> Result<(u64, usize, u64)> {
    if !logical
        .before
        .iter()
        .chain(&logical.after)
        .any(|h| h.outcome.status == Status::NotReadExtentIdentityV1)
    {
        return Ok((check_file(file, logical, geometry.serial_number)?, 0, 0));
    }
    ensure!(
        matches!(
            (native.schema_version, native.request.schema_version),
            (12, 4) | (14, 6) | (16, 8)
        ),
        "native read elision lacks its explicit protocol"
    );
    ensure!(
        logical.identity.record_number == file.record_number
            && logical.identity.sequence_number == file.sequence_number,
        "extent-identity logical file differs"
    );
    let allocation = native
        .allocation
        .as_ref()
        .context("extent-identity native allocation evidence absent")?;
    let base = crate::ntfs_stream_attestation::base(&allocation.base_before)?;
    ensure!(
        allocation.base_before == allocation.base_after
            && crate::ntfs_stream_attestation::base(&allocation.base_after)? == base,
        "extent-identity retrieval base changed"
    );
    for capture in [&observation.streams_before, &observation.streams_after] {
        let capture = capture
            .as_ref()
            .context("complete native stream map absent")?;
        if let Some(resources) = resources {
            crate::ntfs_stream_attestation::check_file_with_resources(
                file, capture, base, geometry, resources,
            )?;
        } else {
            crate::ntfs_stream_attestation::check_file(file, capture, base, geometry)?;
        }
    }
    let mut full_bytes = 0u64;
    let mut extent_streams = 0;
    let mut extent_bytes = 0u64;
    for (pass_index, pass) in [&logical.before, &logical.after].into_iter().enumerate() {
        let names: BTreeSet<_> = pass.iter().map(|h| &h.name_utf16).collect();
        let expected_names: BTreeSet<_> = file.streams.iter().map(|s| &s.name_utf16).collect();
        ensure!(
            pass.len() == file.streams.len()
                && names.len() == pass.len()
                && expected_names.len() == file.streams.len()
                && names == expected_names,
            "extent-identity stream namespace differs"
        );
        for s in &file.streams {
            let h = pass.iter().find(|h| h.name_utf16 == s.name_utf16).unwrap();
            let expected = if h.outcome.status == Status::NotReadExtentIdentityV1
                || s.logical_hash_status == LogicalHashStatus::NotReadExtentIdentityV1
            {
                candidate(s)?
            } else {
                None
            };
            let source_valid = match s.logical_hash_status {
                LogicalHashStatus::Complete => s
                    .logical_sha256
                    .as_deref()
                    .is_some_and(n2r_win32::content_digest::is_hex),
                LogicalHashStatus::NotReadExtentIdentityV1 => {
                    s.logical_sha256.is_none() && expected.is_some()
                }
                _ => false,
            };
            ensure!(
                source_valid,
                "raw stream has no supported content or extent evidence"
            );
            ensure!(
                h.logical_size == s.logical_size,
                "native stream EOF differs"
            );
            if h.outcome.status == Status::NotReadExtentIdentityV1 {
                let expected =
                    expected.context("native elision requested for an ineligible raw stream")?;
                let candidates: Vec<_> = selectors
                    .iter()
                    .filter(|candidate| {
                        candidate.identity == logical.identity
                            && candidate.name_utf16 == s.name_utf16
                    })
                    .collect();
                ensure!(
                    candidates.len() == 1 && candidates[0] == &expected,
                    "native elision mapping differs from independently decoded DATA"
                );
                ensure!(
                    h.outcome.bytes_read == 0
                        && !h.outcome.eof_confirmed
                        && h.outcome.sha256.is_none()
                        && h.outcome.native_error.is_none()
                        && h.outcome.detail.is_none(),
                    "unread stream must have no digest, EOF probe, read bytes or error"
                );
                if pass_index == 0 {
                    extent_streams += 1;
                    extent_bytes = extent_bytes
                        .checked_add(s.logical_size)
                        .context("extent identity byte count overflow")?;
                }
            } else {
                ensure!(
                    s.logical_hash_status == LogicalHashStatus::Complete
                        && s.logical_sha256
                            .as_deref()
                            .is_some_and(n2r_win32::content_digest::is_hex)
                        && h.outcome.status == Status::Complete
                        && h.outcome.eof_confirmed
                        && h.outcome.bytes_read == s.logical_size
                        && h.outcome.native_error.is_none()
                        && h.outcome.detail.is_none()
                        && h.outcome.sha256.as_ref() == s.logical_sha256.as_ref(),
                    "fallback native logical read is incomplete or differs"
                );
                if pass_index == 0 {
                    full_bytes = full_bytes
                        .checked_add(s.logical_size)
                        .context("full logical byte count overflow")?;
                }
            }
            identity(h.identity_before.as_ref(), file, geometry.serial_number)?;
            identity(h.identity_after.as_ref(), file, geometry.serial_number)?;
            standard(h.standard_before.as_ref(), s.logical_size)?;
            standard(h.standard_after.as_ref(), s.logical_size)?;
            ensure!(
                h.identity_before == h.identity_after && h.standard_before == h.standard_after,
                "native read/elision identity or EOF changed"
            );
            if h.outcome.status == Status::NotReadExtentIdentityV1 {
                ensure!(
                    h.standard_before
                        .as_ref()
                        .is_some_and(|q| u64le(&q.bytes, 0) == s.allocated_size),
                    "native extent-identity allocation differs"
                );
            }
        }
    }
    ensure!(
        logical.before == logical.after,
        "native logical/elision snapshots differ"
    );
    Ok((full_bytes, extent_streams, extent_bytes))
}
pub fn reconcile(raw: &NtfsInspection, native: &Report) -> Result<Reconciliation> {
    if !raw.attribute_assemblies.is_empty() {
        crate::ntfs_inspect::validate_record_coverage(raw)?;
    }
    ensure!(
        matches!(native.schema_version, 4..=14),
        "native logical-data profile absent"
    );
    crate::ntfs_stream_attestation::validate_paging_schema(native)?;
    if native.request.uses_extent_identity() {
        let mut expected = Vec::new();
        for file in &raw.files {
            for stream in &file.streams {
                if let Some(candidate) =
                    crate::ntfs_attestation::extent_identity_stream_request(raw, file, stream)?
                {
                    expected.push(candidate);
                }
            }
        }
        ensure!(
            matches!(
                (native.schema_version, native.request.schema_version),
                (12, 4) | (14, 6)
            ) && native.request.extent_identity_streams == expected,
            "native read-elision request set differs from the complete raw eligibility set"
        );
    } else {
        ensure!(
            native.request.extent_identity_streams.is_empty(),
            "legacy native request contains read-elision claims"
        );
    }
    let data = native
        .logical_data
        .as_ref()
        .context("missing native logical data")?;
    ensure!(
        data.files.len() == raw.files.len() && native.files.len() == raw.files.len(),
        "logical file coverage differs"
    );
    let mut indexed = BTreeMap::new();
    for f in &data.files {
        ensure!(
            indexed
                .insert((f.identity.record_number, f.identity.sequence_number), f)
                .is_none(),
            "duplicate logical file observation"
        );
    }
    let mut observed = 0u64;
    let mut complete = 0u64;
    ensure!(
        matches!(native.content_passes, 1 | 2),
        "native content pass count is unsupported"
    );
    for file in &data.files {
        // A single content pass is mirrored into `after`; count it once.
        ensure!(
            native.content_passes == 2 || file.after == file.before,
            "single-pass native logical data is not mirrored exactly"
        );
        let after: &[_] = if native.content_passes == 1 {
            &[]
        } else {
            &file.after
        };
        for h in file.before.iter().chain(after) {
            observed = observed
                .checked_add(h.outcome.bytes_read)
                .context("native logical byte sum overflow")?;
            if h.outcome.status == Status::Complete {
                complete += 1;
            }
        }
    }
    let audit = Check::from((|| {
        let a = &data.audit;
        ensure!(
            a.limit_bytes == native.request.limits().logical_read_bytes
                && a.reserved_bytes <= a.limit_bytes
                && a.bytes_read <= a.reserved_bytes
                && a.bytes_read == observed,
            "native logical read budget accounting differs"
        );
        ensure!(
            a.eof_probes >= complete && a.eof_probes <= a.read_calls,
            "native EOF accounting differs"
        );
        Ok(())
    })());
    let mut files = vec![];
    let mut matched_files = 0;
    let mut matched_streams = 0;
    let mut logical_bytes = 0u64;
    let mut extent_identity_streams = 0;
    let mut extent_identity_logical_bytes = 0u64;
    for f in &raw.files {
        let data = indexed
            .get(&(f.record_number, f.sequence_number))
            .context("missing logical file observation")?;
        let opened: Vec<_> = native
            .files
            .iter()
            .filter(|o| {
                o.identity.record_number == f.record_number
                    && o.identity.sequence_number == f.sequence_number
            })
            .collect();
        ensure!(
            opened.len() == 1,
            "native metadata identity coverage differs"
        );
        let mut bytes = 0;
        let mut extent_streams = 0;
        let mut extent_bytes = 0;
        let check = Check::from((|| {
            ensure!(
                opened[0].open_error.is_none(),
                "native file open refused: {:?}",
                opened[0].open_error
            );
            if f.streams.is_empty() {
                for capture in [&opened[0].streams_before, &opened[0].streams_after] {
                    let c = capture
                        .as_ref()
                        .context("missing empty-stream enumeration")?;
                    ensure!(
                        c.enumeration.class == 7
                            && c.enumeration.native_error == Some(38)
                            && c.enumeration.bytes.is_empty()
                            && c.streams.is_empty()
                            && c.parse_error.is_none(),
                        "empty logical namespace is unverified"
                    );
                }
            }
            (bytes, extent_streams, extent_bytes) =
                check_file_with_extent_evidence(raw, f, data, opened[0], native)?;
            Ok(())
        })());
        if check.matched {
            matched_files += 1;
            matched_streams += f.streams.len();
            logical_bytes = logical_bytes
                .checked_add(bytes)
                .context("verified logical byte sum overflow")?;
            extent_identity_streams += extent_streams;
            extent_identity_logical_bytes = extent_identity_logical_bytes
                .checked_add(extent_bytes)
                .context("extent-identity verified byte sum overflow")?;
        }
        files.push(FileCheck {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            streams: f.streams.len(),
            logical_bytes: bytes,
            all_requested_stream_evidence_matched: check.matched,
            extent_identity_streams: extent_streams,
            extent_identity_logical_bytes: extent_bytes,
            check,
        });
    }
    Ok(Reconciliation {
        all_logical_data_matched: audit.matched
            && matched_files == files.len()
            && extent_identity_streams == 0,
        all_requested_stream_evidence_matched: audit.matched && matched_files == files.len(),
        extent_identity_streams,
        extent_identity_logical_bytes,
        audit,
        matched_files,
        matched_streams,
        logical_bytes_verified_per_pass: logical_bytes,
        native_bytes_read: observed,
        files,
        conversion_qualified: false,
    })
}
