//! Disposable owning-guest exercise of the general conversion engine. This
//! is not general source admission or a production conversion entry point.
use crate::{
    general_reconstruct::{self, Request},
    lab_reconstruct::{self, JournalTicket},
    ntfs_backup, ntfs_inspect, ntfs_log, shadow_tree,
};
use anyhow::{Result, ensure};
use n2r_win32::{GeneralFrozenPartition, GeneralJournaledPartition, NativeEvent};
use serde::Serialize;
use sha2::Digest;
use std::fs::File;

const DISK_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const PARTITION_BYTES: u64 = 52 * 1024 * 1024 * 1024;
const JOURNAL_DISK_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub fn require_disposable_guest(request: &Request) -> Result<()> {
    request.validate()?;
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11")
            && request.pair.source.disk_number == 1
            && request.pair.shadow.disk_number == 3
            && request.journal.disk.disk_number == 2
            && request.pair.source.identity.disk_bytes == DISK_BYTES
            && request.pair.shadow.identity.disk_bytes == DISK_BYTES
            && request.pair.source.identity.partition_bytes == PARTITION_BYTES
            && request.pair.shadow.identity.partition_bytes == PARTITION_BYTES
            && request.journal.disk.identity.disk_bytes == JOURNAL_DISK_BYTES,
        "general conversion exercise requires enrolled disposable guest geometry"
    );
    Ok(())
}

/// Fresh native construction and real source admission in one owning process.
/// These checks enroll scratch devices, never replace the source certificate.
pub fn convert_fresh_compact(
    request: &crate::general_conversion::Request,
    budget: crate::general_qualification::CompactConstructionBudget,
    output: &std::path::Path,
    interrupt_after_writes: Option<u32>,
) -> Result<()> {
    request.validate()?;
    budget.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11")
            && request.source_resource_profile
                == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2)
            && !request.verify_existing_shadow
            && request.pair.source.disk_number == 1
            && request.pair.shadow.disk_number == 3
            && request.journal.disk.disk_number == 2
            && request.pair.source.identity.disk_bytes == DISK_BYTES
            && request.pair.shadow.identity.disk_bytes == DISK_BYTES
            && request.pair.source.identity.partition_bytes == PARTITION_BYTES
            && request.pair.shadow.identity.partition_bytes == PARTITION_BYTES
            && request.journal.disk.identity.disk_bytes == JOURNAL_DISK_BYTES,
        "fresh compact exercise requires enrolled disposable guest devices/profile"
    );
    for (actual, expected) in [
        (
            &request.pair.source.identity.disk_guid,
            "1b191872-c372-41ee-a416-e18863996f54",
        ),
        (
            &request.pair.shadow.identity.disk_guid,
            "c0f2cd39-ad3d-484e-9990-0e6eba74485f",
        ),
        (
            &request.journal.disk.identity.disk_guid,
            "09fcc613-b8c2-4a1a-8833-226f9399be7f",
        ),
    ] {
        ensure!(
            actual
                .trim_matches(['{', '}'])
                .eq_ignore_ascii_case(expected),
            "fresh compact exercise device identity differs"
        );
    }
    crate::general_conversion::convert_composite_fresh_experimental(
        request,
        output,
        budget,
        interrupt_after_writes,
    )
}

/// Controlled selected-device experiment only. Actual enrollment is rechecked
/// by selected_device_preflight; the shared flow must obtain its genuine fresh
/// SourceCertificate before activation. No public conversion fault flag exists.
pub fn convert_fresh_compact_selected(
    request: &crate::general_conversion::Request,
    budget: crate::general_qualification::CompactConstructionBudget,
    output: &std::path::Path,
    interrupt_after_writes: Option<u32>,
) -> Result<()> {
    request.validate()?;
    budget.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        request.source_resource_profile
            == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2)
            && !request.verify_existing_shadow,
        "selected compact lab exercise requires the explicit streaming profile and a fresh shadow"
    );
    crate::general_conversion::convert_compact_selected_for_lab(
        request,
        budget,
        output,
        interrupt_after_writes,
    )
}

/// Controlled selected-device experiment of the allocation-bounded backend,
/// under the same preflight and genuine fresh SourceCertificate requirement.
pub fn convert_fresh_allocation_selected(
    request: &crate::general_conversion::Request,
    budget: crate::general_qualification::CompactConstructionBudget,
    output: &std::path::Path,
    interrupt_after_writes: Option<u32>,
) -> Result<()> {
    crate::general_conversion::convert_allocation_selected_for_lab(
        request,
        budget,
        output,
        interrupt_after_writes,
    )
}

/// Exercise the private fresh writer on a newly admitted V3 source. No saved
/// Some descriptor or prior source certificate enters this lab route.
pub fn convert_fresh_allocation_exclusive_v3_first_write(
    request: &crate::general_conversion::Request,
    budget: crate::general_qualification::CompactConstructionBudget,
    output: &std::path::Path,
) -> Result<()> {
    crate::general_conversion::convert_allocation_exclusive_v3_first_write_for_lab(
        request, budget, output,
    )
}

/// Stop after the first actual native target write into the first qualified
/// old-payload-copy destination. The selected plan determines the destination.
pub fn convert_fresh_allocation_selected_after_first_copy(
    request: &crate::general_conversion::Request,
    budget: crate::general_qualification::CompactConstructionBudget,
    output: &std::path::Path,
) -> Result<()> {
    crate::general_conversion::convert_allocation_first_copy_interrupted_for_lab(
        request, budget, output,
    )
}

#[derive(Debug, Serialize)]
pub struct ApplyReport {
    pub kind: &'static str,
    pub expected_tree_sha256: String,
    pub source_sha256: String,
    pub source_ntfs_volume_flags: Option<u16>,
    pub source_log_clean_restart: bool,
    pub execution: general_reconstruct::Execution,
    pub events: Vec<NativeEvent>,
    pub source_remains_offline: bool,
    pub general_conversion_qualified: bool,
}

pub fn apply(
    request: &Request,
    ticket: &JournalTicket,
    journal: &mut File,
    expected_tree_bytes: &[u8],
) -> Result<ApplyReport> {
    apply_profile(request, ticket, journal, expected_tree_bytes, None)
}

pub fn apply_interrupted(
    request: &Request,
    ticket: &JournalTicket,
    journal: &mut File,
    expected_tree_bytes: &[u8],
    writes: u32,
) -> Result<ApplyReport> {
    apply_profile(request, ticket, journal, expected_tree_bytes, Some(writes))
}

fn apply_profile(
    request: &Request,
    ticket: &JournalTicket,
    journal: &mut File,
    expected_tree_bytes: &[u8],
    interrupt_after_writes: Option<u32>,
) -> Result<ApplyReport> {
    require_disposable_guest(request)?;
    ensure!(
        hex::encode(sha2::Sha256::digest(expected_tree_bytes)) == request.expected_tree_sha256,
        "guest source-tree pin differs"
    );
    let expected: shadow_tree::ExpectedTree = serde_json::from_slice(expected_tree_bytes)?;
    expected.validate()?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
    let source_length = source.byte_len();
    let source_sha256 = hex::encode(lab_reconstruct::hash_range(&mut source, 0, source_length)?);
    ensure!(
        source_sha256 == request.comparison.source_sha256,
        "guest frozen NTFS source changed before activation"
    );
    let raw = ntfs_inspect::inspect(&mut source, source_length)?;
    let derived = if expected.objects.iter().any(|o| o.api_security.is_some()) {
        crate::general_shadow::observed_tree(&mut source, &raw, &mut events)?.0
    } else {
        shadow_tree::derive_ordinary(&raw)?
    };
    ensure!(
        shadow_tree::ExpectedTree::from(&derived) == expected,
        "guest expected tree differs from the actual NTFS source"
    );
    ntfs_backup::verify(&mut source, source_length, &raw)?;
    let clean_log = ntfs_log::verify(&mut source, &raw)?
        .restart
        .candidate_clean_dismount;
    let mut target =
        general_reconstruct::activate(request, source, &mut shadow, journal, ticket, &mut events)?;
    let execution = if let Some(writes) = interrupt_after_writes {
        general_reconstruct::execute_interrupted_apply(
            request,
            &mut target,
            &mut shadow,
            journal,
            ticket,
            &mut events,
            writes,
        )?
    } else {
        general_reconstruct::execute(
            general_reconstruct::RecoveryOperation::Apply,
            request,
            &mut target,
            &mut shadow,
            journal,
            ticket,
            &mut events,
        )?
    };
    let source_remains_offline = target.state(&mut events)?.disk_attributes == 1;
    ensure!(
        source_remains_offline,
        "guest target isolation changed after apply"
    );
    Ok(ApplyReport {
        kind: "disposable-general-ntfs-refs-apply",
        expected_tree_sha256: request.expected_tree_sha256.clone(),
        source_sha256,
        source_ntfs_volume_flags: raw.volume_flags,
        source_log_clean_restart: clean_log,
        execution,
        events,
        source_remains_offline,
        general_conversion_qualified: false,
    })
}

pub fn finalize(
    request: &Request,
    ticket: &JournalTicket,
    journal: &mut File,
    expected_tree_bytes: &[u8],
) -> Result<general_reconstruct::Finalization> {
    require_disposable_guest(request)?;
    let mut events = Vec::new();
    let target = GeneralJournaledPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
    let mut report = general_reconstruct::finalize(
        request,
        target,
        &mut shadow,
        journal,
        ticket,
        expected_tree_bytes,
    )?;
    report.events.splice(0..0, events);
    Ok(report)
}

pub fn finalize_after_marker(
    request: &Request,
    ticket: &JournalTicket,
    journal: &mut File,
    expected_tree_bytes: &[u8],
) -> Result<general_reconstruct::Finalization> {
    require_disposable_guest(request)?;
    let mut events = Vec::new();
    let target = GeneralJournaledPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
    let mut report = general_reconstruct::finalize_after_marker(
        request,
        target,
        &mut shadow,
        journal,
        ticket,
        expected_tree_bytes,
    )?;
    report.events.splice(0..0, events);
    Ok(report)
}
