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
    let derived = shadow_tree::derive_ordinary(&raw)?;
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
