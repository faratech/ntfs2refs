//! Early pure target-security eligibility over the held raw source metadata.
//! This does not query native security, admit a source, or authorize a write.
use crate::{
    ntfs_admission,
    ntfs_inspect::{PagedInspection, RootFileDomain, paged_storage::SourceScratch},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{refs_security_descriptor, tree_resources::SourceResourceAdmission};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Serialize)]
pub(super) struct Rejection {
    record_number: u64,
    sequence_number: u16,
    security_id: Option<u32>,
    descriptor_sha256: String,
    detail: String,
}

/// Small descriptive output only. In particular, a passing raw eligibility
/// check cannot satisfy any of the deferred source/native/target obligations.
#[derive(Serialize)]
pub(super) struct Report {
    schema_version: u32,
    kind: &'static str,
    source_inspection_sha256: String,
    raw_identities: u64,
    target_objects_checked: u64,
    unique_referenced_descriptors_checked: u64,
    unique_process_trust_descriptors: u64,
    maximum_descriptor_bytes: u64,
    scratch_ram_reserved_bytes: u64,
    pub(super) scan_complete: bool,
    pub(super) pure_security_eligible: bool,
    first_rejection: Option<Rejection>,
    api_descriptor_views_available: bool,
    deferred_checks: [&'static str; 5],
    source_admitted: bool,
    native_security_preservation_qualified: bool,
    execution_authorized: bool,
}

/// Check exactly the root/user descriptor domain that will be projected later,
/// not unused or filesystem-internal descriptors in the central table. Reuse
/// the SDK's full layout/observed-profile/hash checks, including descriptors
/// without trust ACEs, so this catches the same pure failures as late recipes.
pub(super) fn inspect(
    source: &PagedInspection,
    admission: SourceResourceAdmission,
    scratch: &SourceScratch,
) -> Result<Report> {
    admission.validate()?;
    let source_pin = source.canonical_sha256()?;
    let budget = source.budget();
    let actual = scratch.budget();
    ensure!(
        source.is_windows_conversion()
            && source.header().inventory_complete
            && source_pin == hex::encode(admission.source_inspection_sha256)
            && source.file_count() == admission.raw_identities
            && source.header().mft_record_count == admission.mft_records
            && budget.ram_bytes == actual.ram_bytes
            && budget.scratch_bytes == actual.scratch_bytes
            && budget.record_bytes == actual.record_bytes
            && budget.page_bytes == actual.page_bytes,
        "early target security requires its actual complete Windows source and scratch owner"
    );
    let maximum = admission
        .budget
        .max_row_bytes
        .min(refs_security_descriptor::MAX_DESCRIPTOR_BYTES as u64);
    // One current file/security record and SDK transform; never retain all SDs.
    let working_bytes = budget
        .record_bytes
        .checked_mul(8)
        .and_then(|bytes| {
            bytes.checked_add(refs_security_descriptor::constructor_working_bytes(maximum).ok()?)
        })
        .context("early target-security working RAM overflow")?;
    let _working = scratch.lease_ram(working_bytes)?;
    let descriptor_count = source.security().descriptor_count();
    // Each unique digest pays three complete pinned BTree node allocations,
    // plus set/report storage. The source's closed descriptor count is an upper
    // bound on referenced unique descriptors, not a new filesystem count cap.
    let index_bytes = descriptor_count
        .checked_mul(3072)
        .and_then(|bytes| bytes.checked_add(4096))
        .context("early target-security digest RAM overflow")?;
    let _index = scratch.lease_ram(index_bytes)?;
    let mut seen = BTreeSet::<[u8; 32]>::new();
    let mut report = Report {
        schema_version: 1,
        kind: "early-Windows-raw-target-security-eligibility-v1",
        source_inspection_sha256: source_pin.clone(),
        raw_identities: source.file_count(),
        target_objects_checked: 0,
        unique_referenced_descriptors_checked: 0,
        unique_process_trust_descriptors: 0,
        maximum_descriptor_bytes: maximum,
        scratch_ram_reserved_bytes: working_bytes
            .checked_add(index_bytes)
            .context("early target-security total RAM overflow")?,
        scan_complete: false,
        pure_security_eligible: false,
        first_rejection: None,
        api_descriptor_views_available: false,
        deferred_checks: [
            "paired API/kernel source security, identity and namespace observations",
            "live TxF/object-ID and internal-index disposition witnesses",
            "remaining path, stream, EA, reparse and constructor metadata eligibility",
            "native placeholder preservation, canonical raw repair and original target readback",
            "all existing source, resource, target and activation admission gates",
        ],
        source_admitted: false,
        native_security_preservation_qualified: false,
        execution_authorized: false,
    };
    let mut root_seen = false;
    for ordinal in 0..source.file_count() {
        let file = source.file(ordinal)?;
        if file.record_number != 5 && ntfs_admission::paged::internal_role(source, &file)?.is_some()
        {
            continue;
        }
        root_seen |= file.record_number == 5;
        report.target_objects_checked = report
            .target_objects_checked
            .checked_add(1)
            .context("early target-security object count overflow")?;
        let binding = source
            .security()
            .find_binding(file.record_number)?
            .context("early target-security source binding absent")?;
        ensure!(
            binding.sequence_number == file.sequence_number,
            "early target-security source binding sequence differs"
        );
        let digest: [u8; 32] = hex::decode(&binding.descriptor_sha256)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("early target-security digest width differs"))?;
        if seen.contains(&digest) {
            continue;
        }
        ensure!(
            (seen.len() as u64) < descriptor_count,
            "early target-security unique domain exceeds closed source descriptors"
        );
        let descriptor = if let Some(id) = binding.security_id {
            source.security().find_id(id)?
        } else {
            source.security().find_legacy(file.record_number)?
        }
        .context("early target-security referenced descriptor absent")?;
        ensure!(
            descriptor.descriptor.sha256 == binding.descriptor_sha256
                && descriptor.security_id == binding.security_id
                && (binding.security_id.is_some()
                    || descriptor.legacy_record == Some(file.record_number)),
            "early target-security descriptor identity differs from source binding"
        );
        let bytes = hex::decode(&descriptor.descriptor.relative_hex)?;
        ensure!(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == digest,
            "early target-security descriptor bytes differ from complete source digest"
        );
        seen.insert(digest);
        report.unique_referenced_descriptors_checked += 1;
        match refs_security_descriptor::prepare_trust_label_placeholder(&bytes, maximum) {
            Ok(Some(_)) => report.unique_process_trust_descriptors += 1,
            Ok(None) => {}
            Err(error) => {
                report.first_rejection = Some(Rejection {
                    record_number: file.record_number,
                    sequence_number: file.sequence_number,
                    security_id: binding.security_id,
                    descriptor_sha256: binding.descriptor_sha256,
                    detail: error.to_string().chars().take(512).collect(),
                });
                break;
            }
        }
    }
    // The selector constructor already authenticated the whole source before
    // this pass. Keep an independent close bookend before native capture.
    source.revalidate()?;
    ensure!(
        source.canonical_sha256()? == source_pin,
        "raw source changed across early target-security eligibility"
    );
    if report.first_rejection.is_none() {
        ensure!(
            root_seen && report.target_objects_checked == admission.objects()?,
            "early target-security root/user coverage differs from source admission counts"
        );
        report.scan_complete = true;
        report.pure_security_eligible = true;
    }
    Ok(report)
}
