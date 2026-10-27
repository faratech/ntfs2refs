//! General source/shadow journal plumbing. Preparation is read-only on both
//! data disks; activation and execution remain internal until admission and
//! target qualification supply the missing write authority.
use crate::{
    lab_native_reconstruct::{identity_hash, partition_hash},
    lab_reconstruct::{self, JournalBinding, JournalDescriptor, JournalSummary, JournalTicket},
    ntfs_attestation, ntfs_backup, ntfs_inspect, ntfs_log, refs_inspect, refs_retained_allocation,
    retained_compare::{self, RetainedCompareRequest},
    shadow_tree,
};
use anyhow::{Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, GeneralJournaledPartition, MountPathObservation,
    NativeEvent, WritePolicy, capture_mount_paths_general,
    general_layout::GeneralSourceShadowBinding,
    journal_file::{
        GeneralJournalStorageBinding, JournalFileIdentity, JournalFileSnapshot, JournalProfile,
        observe_general_journal_file_with_profile,
    },
    layout::guid_bytes,
    mounted_filesystem_general, rediscover_general_volume_wait, shadow_native,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

fn observe_journal(file: &File, request: &Request) -> Result<JournalFileSnapshot> {
    Ok(observe_general_journal_file_with_profile(
        file,
        &request.journal,
        JournalProfile::from_schema(request.schema_version)?,
    )?)
}

fn binding(request: &Request, journal: &JournalFileIdentity) -> Result<JournalBinding> {
    Ok(JournalBinding {
        experiment_id: request.experiment_id.clone(),
        source_resource_profile: request.source_resource_profile,
        target_identity_sha256: partition_hash(&request.pair.source.identity)?,
        shadow_identity_sha256: partition_hash(&request.pair.shadow.identity)?,
        journal_identity_sha256: identity_hash(
            b"ntfs2refs/general/journal-file-identity/v1",
            journal,
        )?,
    })
}

fn validated_ticket(
    request: &Request,
    journal: &mut File,
    ticket: &JournalTicket,
    identity: &JournalFileIdentity,
    file_bytes: u64,
) -> Result<JournalDescriptor> {
    validated_ticket_for_phase(request, journal, ticket, identity, file_bytes, false)
}

/// Completed markers must bind the same profile and complete immutable plan
/// before any durability barrier can expose the target for a native mount.
fn validated_completed_ticket(
    request: &Request,
    journal: &mut File,
    ticket: &JournalTicket,
    identity: &JournalFileIdentity,
    file_bytes: u64,
) -> Result<JournalDescriptor> {
    validated_ticket_for_phase(request, journal, ticket, identity, file_bytes, true)
}

fn validated_ticket_for_phase(
    request: &Request,
    journal: &mut File,
    ticket: &JournalTicket,
    identity: &JournalFileIdentity,
    file_bytes: u64,
    completed: bool,
) -> Result<JournalDescriptor> {
    let observed = binding(request, identity)?;
    ensure!(
        ticket.schema_version == request.schema_version
            && ticket.binding == observed
            && ticket.journal_length == file_bytes
            && ticket.journal_length <= request.max_journal_bytes
            && ticket.immutable_length.checked_add(8192) == Some(ticket.journal_length),
        "general ticket, journal length or storage identity differs"
    );
    let descriptor = if completed {
        lab_reconstruct::inspect_completed_journal(journal, ticket, &observed)?
    } else {
        lab_reconstruct::inspect_journal(journal, ticket, &observed)?
    };
    ensure!(
        serde_json::to_vec(&descriptor.request)? == serde_json::to_vec(&request.comparison)?,
        "general journal plan differs from request"
    );
    Ok(descriptor)
}

fn durable_marker_for_mount<'a>(
    request: &Request,
    journal: &'a mut File,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    proof: &lab_reconstruct::CompletedMarkerProof,
) -> Result<lab_reconstruct::DurableCompletedMarker<'a, File>> {
    lab_reconstruct::guard_completed_marker_durability(
        journal,
        ticket,
        observed_binding,
        proof,
        |file| {
            let observed = observe_journal(file, request)?;
            ensure!(
                observed.file_bytes == ticket.journal_length,
                "completed journal length changed around durability barrier"
            );
            binding(request, &observed.identity)
        },
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_resource_profile: Option<crate::ntfs_admission::ResourceProfile>,
    pub experiment_id: String,
    pub expected_tree_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_mount_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_source_label: Option<n2r_win32::volume_label::VolumeLabel>,
    pub pair: GeneralSourceShadowBinding,
    pub comparison: RetainedCompareRequest,
    pub journal: GeneralJournalStorageBinding,
    pub max_journal_bytes: u64,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        let profile = JournalProfile::from_schema(self.schema_version)?;
        lab_reconstruct::validate_source_profile_binding(
            self.schema_version,
            self.source_resource_profile,
        )?;
        ensure!(
            self.experiment_id.len() == 32
                && self
                    .experiment_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid general preparation experiment identity"
        );
        ensure!(
            self.expected_tree_sha256.len() == 64
                && self
                    .expected_tree_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "missing pinned general target expectation"
        );
        self.pair.validate_with_resource_profile(
            self.source_resource_profile
                .unwrap_or_default()
                .native_profile(),
        )?;
        crate::general_shadow::validate_mount_paths(&self.expected_mount_paths)?;
        if let Some(label) = &self.expected_source_label {
            label.validate()?;
        }
        self.journal.validate()?;
        retained_compare::validate_request(&self.comparison)?;
        ensure!(
            self.comparison.schema_version == 2
                && self.comparison.sector_size == 4096
                && self.comparison.expected_length == self.pair.source.identity.partition_bytes
                && self.comparison.max_change_bytes <= profile.max_changed_bytes()
                && (1..=profile.max_journal_bytes()).contains(&self.max_journal_bytes),
            "general comparison or journal budget differs"
        );
        for data in [&self.pair.source, &self.pair.shadow] {
            ensure!(
                data.disk_number != self.journal.disk.disk_number
                    && guid_bytes(&data.identity.disk_guid)?
                        != guid_bytes(&self.journal.disk.identity.disk_guid)?
                    && guid_bytes(&data.identity.partition_guid)?
                        != guid_bytes(&self.journal.disk.identity.partition_guid)?
                    && guid_bytes(&data.volume_guid)?
                        != guid_bytes(&self.journal.disk.volume_guid)?,
                "external journal overlaps a data disk"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Preparation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub request: Request,
    pub observed_binding: JournalBinding,
    pub source_before: GeneralDiskState,
    pub source_after: GeneralDiskState,
    pub shadow_before: GeneralDiskState,
    pub shadow_after: GeneralDiskState,
    pub source_ntfs_dirty: Option<bool>,
    pub source_ntfs_volume_flags: Option<u16>,
    pub shadow_refs_version: String,
    pub retained_allocation: Option<refs_retained_allocation::Coverage>,
    pub journal: JournalSummary,
    pub events: Vec<NativeEvent>,
    pub source_admitted: bool,
    pub target_profile_qualified: bool,
    pub execution_authorized: bool,
}

/// The caller owns a fresh exclusive journal file and separately frozen data
/// disks. Successful return supplies a ticket to persist outside the journal;
/// it does not grant authority to activate the target.
pub fn prepare(
    request: &Request,
    source: &mut GeneralFrozenPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
) -> Result<Preparation> {
    prepare_with_progress(request, source, shadow, journal, &mut |_| {})
}

pub fn prepare_with_progress(
    request: &Request,
    source: &mut GeneralFrozenPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    progress: &mut dyn FnMut(crate::preparation_progress::Progress),
) -> Result<Preparation> {
    request.validate()?;
    ensure!(
        source.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "actual frozen source/shadow bindings differ"
    );
    let mut events = Vec::new();
    let source_before = source.state(&mut events)?;
    let shadow_before = shadow.state(&mut events)?;
    let journal_before = observe_journal(journal, request)?;
    ensure!(
        journal_before.file_bytes == 0,
        "journal is not a fresh empty file"
    );
    let ntfs = ntfs_inspect::inspect_with_limits(
        source,
        source.byte_len(),
        ntfs_inspect::limits_for_resource_profile(
            request.source_resource_profile.unwrap_or_default(),
        ),
    )?;
    let refs = refs_inspect::inspect_with_resource_profile(
        shadow,
        shadow.byte_len(),
        request.source_resource_profile.unwrap_or_default(),
    )?;
    ensure!(
        request
            .source_resource_profile
            .unwrap_or_default()
            .supports_source_geometry(&ntfs.geometry)
            && refs.geometry.major_version == 3
            && refs.geometry.minor_version == 14
            && refs.geometry.bytes_per_cluster == 4096
            && refs.geometry.volume_bytes == shadow.byte_len(),
        "initial NTFS/ReFS format geometry differs"
    );
    let retained_allocation = if request.comparison.retained_ranges.is_empty() {
        None
    } else {
        let shadow_length = shadow.byte_len();
        let observed = refs_retained_allocation::inspect_with_resource_profile(
            shadow,
            shadow_length,
            &request.comparison,
            request.source_resource_profile.unwrap_or_default(),
        )?;
        ensure!(
            observed.retained_allocator_coverage_verified,
            "retained data lacks unambiguous ReFS allocator coverage"
        );
        Some(observed)
    };
    let observed_binding = binding(request, &journal_before.identity)?;
    let summary = lab_reconstruct::prepare_journal_with_profile_and_progress(
        source,
        shadow,
        journal,
        &request.comparison,
        &observed_binding,
        request.max_journal_bytes,
        JournalProfile::from_schema(request.schema_version)?,
        progress,
    )?;
    let source_after = source.state(&mut events)?;
    let shadow_after = shadow.state(&mut events)?;
    let journal_after = observe_journal(journal, request)?;
    ensure!(
        source_before == source_after
            && shadow_before == shadow_after
            && journal_before.identity == journal_after.identity
            && journal_after.file_bytes == summary.ticket.journal_length,
        "general data or journal binding changed during preparation"
    );
    Ok(Preparation {
        schema_version: 1,
        kind: "general-frozen-ntfs-refs-journal-preparation",
        request: request.clone(),
        observed_binding,
        source_before,
        source_after,
        shadow_before,
        shadow_after,
        source_ntfs_dirty: ntfs.dirty,
        source_ntfs_volume_flags: ntfs.volume_flags,
        shadow_refs_version: format!(
            "{}.{}",
            refs.geometry.major_version, refs.geometry.minor_version
        ),
        retained_allocation,
        journal: summary,
        events,
        source_admitted: false,
        target_profile_qualified: false,
        execution_authorized: false,
    })
}

/// Only a separately pinned, fully inspected journal can remove READ_ONLY
/// from the still-offline source. No payload range is armed at this point.
#[allow(
    dead_code,
    reason = "General source admission does not yet call activation"
)]
pub(crate) fn activate(
    request: &Request,
    source: GeneralFrozenPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
) -> Result<GeneralJournaledPartition> {
    request.validate()?;
    ensure!(
        source.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "general activation data bindings differ"
    );
    source.state(events)?;
    let shadow_before = shadow.state(events)?;
    let before = observe_journal(journal, request)?;
    validated_ticket(
        request,
        journal,
        ticket,
        &before.identity,
        before.file_bytes,
    )?;
    let target = source.activate_for_journal(events)?;
    ensure!(
        target.state(events)?.disk_attributes == 1 && shadow.state(events)? == shadow_before,
        "general activation lost disk exclusion"
    );
    let after = observe_journal(journal, request)?;
    ensure!(
        after.identity == before.identity && after.file_bytes == before.file_bytes,
        "general journal changed during activation"
    );
    Ok(target)
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOperation {
    Apply,
    Resume,
    Rollback,
}

#[derive(Debug, Serialize)]
pub struct Execution {
    pub operation: RecoveryOperation,
    pub result: lab_reconstruct::ExecutionReport,
    pub expected_target_sha256: String,
    pub target_before: GeneralDiskState,
    pub target_after: GeneralDiskState,
    pub shadow_before: GeneralDiskState,
    pub shadow_after: GeneralDiskState,
    pub target_write_bytes_requested: u64,
    pub target_bytes_written: u64,
    pub source_admitted: bool,
    pub conversion_qualified: bool,
}

/// Public recovery is limited to an already activated, persistently offline
/// target. Fresh apply and activation remain internal pending admission.
pub fn recover(
    operation: RecoveryOperation,
    request: &Request,
    target: &mut GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
) -> Result<Execution> {
    ensure!(
        matches!(
            operation,
            RecoveryOperation::Resume | RecoveryOperation::Rollback
        ),
        "general recovery cannot initiate a new apply"
    );
    execute(operation, request, target, shadow, journal, ticket, events)
}

#[derive(Debug, Serialize)]
pub struct ShadowlessRollback {
    pub result: lab_reconstruct::ExecutionReport,
    pub expected_target_sha256: String,
    pub target_before: GeneralDiskState,
    pub target_after: GeneralDiskState,
    pub target_write_bytes_requested: u64,
    pub target_bytes_written: u64,
    pub shadow_available: bool,
    pub conversion_qualified: bool,
}

/// Restore NTFS from the pinned old-byte journal when the independent ReFS
/// shadow is unavailable. This cannot resume ReFS apply or reopen recovery
/// after a handoff marker. The target remains persistently excluded.
pub fn rollback_without_shadow(
    request: &Request,
    target: &mut GeneralJournaledPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
) -> Result<ShadowlessRollback> {
    request.validate()?;
    ensure!(
        target.binding() == &request.pair.source,
        "shadowless rollback target binding differs"
    );
    let before = target.state(events)?;
    ensure!(
        before.disk_attributes == 1,
        "rollback target is not offline"
    );
    let observed = observe_journal(journal, request)?;
    let descriptor = validated_ticket(
        request,
        journal,
        ticket,
        &observed.identity,
        observed.file_bytes,
    )?;
    if !descriptor.patches.is_empty() {
        target.arm_writes(
            WritePolicy {
                allowed: descriptor
                    .patches
                    .iter()
                    .map(|p| (p.offset, p.length))
                    .collect(),
                retained: request
                    .comparison
                    .retained_ranges
                    .iter()
                    .map(|r| (r.offset, r.length))
                    .collect(),
                maximum_bytes: descriptor.changed_bytes,
                journal_profile: n2r_win32::journal_file::JournalProfile::from_schema(
                    request.schema_version,
                )?,
            },
            events,
        )?;
    }
    let bound = binding(request, &observed.identity)?;
    let result = lab_reconstruct::rollback_without_shadow(target, journal, ticket, &bound)?;
    let after = target.state(events)?;
    let journal_after = observe_journal(journal, request)?;
    ensure!(
        before == after
            && observed.identity == journal_after.identity
            && observed.file_bytes == journal_after.file_bytes,
        "shadowless rollback storage binding changed"
    );
    Ok(ShadowlessRollback {
        result,
        expected_target_sha256: request.comparison.source_sha256.clone(),
        target_before: before,
        target_after: after,
        target_write_bytes_requested: target.native_write_bytes_requested,
        target_bytes_written: target.native_bytes_written,
        shadow_available: false,
        conversion_qualified: false,
    })
}

/// Recovery remains possible only while the journal's handoff sector is all
/// zero. The journal descriptor, rather than serialized plan flags, supplies
/// the exact patch policy. No operation here exposes a disk for mounting.
#[allow(dead_code, reason = "General recovery CLI awaits source admission")]
pub(crate) fn execute(
    operation: RecoveryOperation,
    request: &Request,
    target: &mut GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
) -> Result<Execution> {
    execute_with_interruption(
        operation, request, target, shadow, journal, ticket, events, None,
    )
}

/// Disposable guest fault injection after N complete, flushed target writes.
/// The process exits before any handoff; recovery reopens the same journal.
pub(crate) fn execute_interrupted_apply(
    request: &Request,
    target: &mut GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
    writes: u32,
) -> Result<Execution> {
    execute_with_interruption(
        RecoveryOperation::Apply,
        request,
        target,
        shadow,
        journal,
        ticket,
        events,
        Some(writes),
    )
}

struct InterruptingGeneralTarget<'a> {
    inner: &'a mut GeneralJournaledPartition,
    remaining: u32,
}
impl Read for InterruptingGeneralTarget<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}
impl Seek for InterruptingGeneralTarget<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.inner.seek(from)
    }
}
impl Write for InterruptingGeneralTarget<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        if written > 0 {
            self.remaining -= 1;
            if self.remaining == 0 {
                self.inner.sync_all()?;
                eprintln!(
                    "Controlled general target interruption; source stays offline, recover using the pinned ticket."
                );
                std::process::exit(86);
            }
        }
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.sync_all()
    }
}
impl lab_reconstruct::ReadSeek for InterruptingGeneralTarget<'_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(n2r_win32::GeneralJournaledPartition::byte_len(self.inner))
    }
}
impl lab_reconstruct::DurableIo for InterruptingGeneralTarget<'_> {
    fn sync_all(&mut self) -> io::Result<()> {
        self.inner.sync_all()
    }
}

fn execute_with_interruption(
    operation: RecoveryOperation,
    request: &Request,
    target: &mut GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    events: &mut Vec<NativeEvent>,
    interrupt_after_writes: Option<u32>,
) -> Result<Execution> {
    request.validate()?;
    ensure!(
        interrupt_after_writes.is_none_or(|count| {
            (1..=4096).contains(&count) && matches!(operation, RecoveryOperation::Apply)
        }),
        "invalid general interruption point"
    );
    ensure!(
        target.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "general execution data bindings differ"
    );
    let target_before = target.state(events)?;
    let shadow_before = shadow.state(events)?;
    ensure!(
        target_before.disk_attributes == 1 && shadow_before.disk_attributes == 3,
        "general execution requires an excluded target and shadow"
    );
    let before = observe_journal(journal, request)?;
    let descriptor = validated_ticket(
        request,
        journal,
        ticket,
        &before.identity,
        before.file_bytes,
    )?;
    if !descriptor.patches.is_empty() {
        target.arm_writes(
            WritePolicy {
                allowed: descriptor
                    .patches
                    .iter()
                    .map(|p| (p.offset, p.length))
                    .collect(),
                retained: request
                    .comparison
                    .retained_ranges
                    .iter()
                    .map(|r| (r.offset, r.length))
                    .collect(),
                maximum_bytes: descriptor.changed_bytes,
                journal_profile: n2r_win32::journal_file::JournalProfile::from_schema(
                    request.schema_version,
                )?,
            },
            events,
        )?;
    }
    let observed = binding(request, &before.identity)?;
    let result = match (operation, interrupt_after_writes) {
        (RecoveryOperation::Apply, Some(remaining)) => {
            let mut interrupted = InterruptingGeneralTarget {
                inner: target,
                remaining,
            };
            let result =
                lab_reconstruct::apply(&mut interrupted, shadow, journal, ticket, &observed)?;
            anyhow::bail!(
                "requested general interruption was not reached: {} patches",
                result.patches_written
            )
        }
        (RecoveryOperation::Apply, None) => {
            lab_reconstruct::apply(target, shadow, journal, ticket, &observed)?
        }
        (RecoveryOperation::Resume, None) => {
            lab_reconstruct::resume(target, shadow, journal, ticket, &observed)?
        }
        (RecoveryOperation::Rollback, None) => {
            lab_reconstruct::rollback(target, shadow, journal, ticket, &observed)?
        }
        _ => unreachable!(),
    };
    let target_after = target.state(events)?;
    let shadow_after = shadow.state(events)?;
    let after = observe_journal(journal, request)?;
    ensure!(
        target_before == target_after
            && shadow_before == shadow_after
            && before.identity == after.identity
            && before.file_bytes == after.file_bytes,
        "general execution storage binding changed"
    );
    Ok(Execution {
        operation,
        result,
        expected_target_sha256: if matches!(operation, RecoveryOperation::Rollback) {
            request.comparison.source_sha256.clone()
        } else {
            descriptor.expected_postimage_sha256
        },
        target_before,
        target_after,
        shadow_before,
        shadow_after,
        target_write_bytes_requested: target.native_write_bytes_requested,
        target_bytes_written: target.native_bytes_written,
        source_admitted: false,
        conversion_qualified: false,
    })
}

#[derive(Debug, Serialize)]
pub struct Finalization {
    pub success: bool,
    pub rollback_closed: bool,
    pub handoff: Option<lab_reconstruct::ExecutionReport>,
    pub completed_marker_proof: Option<lab_reconstruct::CompletedMarkerProof>,
    pub native: Option<shadow_native::GeneralConvertedReport>,
    pub label_restoration: Option<n2r_win32::volume_label::LabelRestoration>,
    pub mount_paths_after: Option<MountPathObservation>,
    pub mount_paths_preserved: Option<bool>,
    pub mount_paths_error: Option<String>,
    pub error: Option<String>,
    pub events: Vec<NativeEvent>,
    pub general_conversion_qualified: bool,
}

fn record_mount_paths(
    request: &Request,
    native: &shadow_native::GeneralConvertedReport,
    report: &mut Finalization,
) {
    match capture_mount_paths_general(native.pair.source.clone(), &mut report.events) {
        Ok(observed) => {
            report.mount_paths_preserved = request.expected_mount_paths.as_ref().map(|expected| {
                let before: BTreeSet<_> = expected.iter().map(|path| path.to_lowercase()).collect();
                let after: BTreeSet<_> = observed
                    .paths
                    .iter()
                    .map(|path| path.to_lowercase())
                    .collect();
                before == after
            });
            if report.mount_paths_preserved == Some(false) {
                report.error =
                    Some("converted ReFS mount paths differ from the original NTFS volume".into());
            }
            report.mount_paths_after = Some(observed);
        }
        Err(error) => {
            report.mount_paths_error = Some(error.to_string());
            if request.expected_mount_paths.is_some() {
                report.error = Some("converted ReFS mount paths could not be verified".into());
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RollbackFinalization {
    pub success: bool,
    pub replay_closed: bool,
    pub shadow_available: bool,
    pub marker: Option<lab_reconstruct::ExecutionReport>,
    pub completed_marker_proof: Option<lab_reconstruct::CompletedMarkerProof>,
    pub mounted_filesystem: Option<String>,
    pub error: Option<String>,
    pub events: Vec<NativeEvent>,
    pub production_conversion_qualified: bool,
}

/// Close stale conversion recovery before returning an exact restored NTFS
/// image to ordinary writable service. A partial marker is treated as closed.
pub fn complete_rollback(
    request: &Request,
    mut target: GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    mut events: Vec<NativeEvent>,
) -> Result<RollbackFinalization> {
    request.validate()?;
    ensure!(
        target.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "NTFS rollback completion data bindings differ"
    );
    ensure!(
        target.state(&mut events)?.disk_attributes == 1
            && shadow.state(&mut events)?.disk_attributes == 3,
        "NTFS rollback completion requires excluded target and shadow"
    );
    let observed_journal = observe_journal(journal, request)?;
    validated_ticket(
        request,
        journal,
        ticket,
        &observed_journal.identity,
        observed_journal.file_bytes,
    )?;
    let length = target.byte_len();
    let raw = ntfs_inspect::inspect_with_limits(
        &mut target,
        length,
        ntfs_inspect::limits_for_resource_profile(
            request.source_resource_profile.unwrap_or_default(),
        ),
    )?;
    ntfs_backup::verify(&mut target, length, &raw)?;
    ntfs_log::verify(&mut target, &raw)?;
    let observed_binding = binding(request, &observed_journal.identity)?;
    let mut report = RollbackFinalization {
        success: false,
        replay_closed: true,
        shadow_available: true,
        marker: None,
        completed_marker_proof: None,
        mounted_filesystem: None,
        error: None,
        events,
        production_conversion_qualified: false,
    };
    match lab_reconstruct::mark_rollback_complete(
        &mut target,
        shadow,
        journal,
        ticket,
        &observed_binding,
    ) {
        Ok(marker) => report.marker = Some(marker),
        Err(error) => {
            report.error = Some(format!("{error:#}"));
            return Ok(report);
        }
    }
    if let Err(error) = target.bring_online(&mut report.events) {
        report.error = Some(error.to_string());
        return Ok(report);
    }
    let mounted = rediscover_general_volume_wait(request.pair.source.clone(), &mut report.events)
        .and_then(|binding| mounted_filesystem_general(binding, &mut report.events));
    match mounted {
        Ok(name) if name == "NTFS" => {
            report.mounted_filesystem = Some(name);
            report.success = true;
        }
        Ok(name) => {
            report.mounted_filesystem = Some(name);
            report.error = Some("restored original did not mount as NTFS".into());
        }
        Err(error) => report.error = Some(error.to_string()),
    }
    Ok(report)
}

/// Finish a journal-only rollback after proving the exact original NTFS
/// image. No ReFS shadow is required for this direction of recovery.
pub fn complete_rollback_without_shadow(
    request: &Request,
    mut target: GeneralJournaledPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    mut events: Vec<NativeEvent>,
) -> Result<RollbackFinalization> {
    request.validate()?;
    ensure!(
        target.binding() == &request.pair.source,
        "rollback target binding differs"
    );
    ensure!(
        target.state(&mut events)?.disk_attributes == 1,
        "rollback target is not offline"
    );
    let observed = observe_journal(journal, request)?;
    validated_ticket(
        request,
        journal,
        ticket,
        &observed.identity,
        observed.file_bytes,
    )?;
    let length = target.byte_len();
    let raw = ntfs_inspect::inspect_with_limits(
        &mut target,
        length,
        ntfs_inspect::limits_for_resource_profile(
            request.source_resource_profile.unwrap_or_default(),
        ),
    )?;
    ntfs_backup::verify(&mut target, length, &raw)?;
    ntfs_log::verify(&mut target, &raw)?;
    let bound = binding(request, &observed.identity)?;
    let mut report = RollbackFinalization {
        success: false,
        replay_closed: true,
        shadow_available: false,
        marker: None,
        completed_marker_proof: None,
        mounted_filesystem: None,
        error: None,
        events,
        production_conversion_qualified: false,
    };
    match lab_reconstruct::mark_rollback_complete_without_shadow(
        &mut target,
        journal,
        ticket,
        &bound,
    ) {
        Ok(marker) => report.marker = Some(marker),
        Err(error) => {
            report.error = Some(format!("{error:#}"));
            return Ok(report);
        }
    }
    if let Err(error) = target.bring_online(&mut report.events) {
        report.error = Some(error.to_string());
        return Ok(report);
    }
    let mounted = rediscover_general_volume_wait(request.pair.source.clone(), &mut report.events)
        .and_then(|binding| mounted_filesystem_general(binding, &mut report.events));
    match mounted {
        Ok(name) if name == "NTFS" => {
            report.mounted_filesystem = Some(name);
            report.success = true;
        }
        Ok(name) => {
            report.mounted_filesystem = Some(name);
            report.error = Some("restored original did not mount as NTFS".into());
        }
        Err(error) => report.error = Some(error.to_string()),
    }
    Ok(report)
}

/// Complete a fully verified readable rollback marker with a fresh journal
/// durability barrier. This never writes or repairs the journal marker.
pub fn resume_completed_rollback(
    request: &Request,
    mut target: GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    mut events: Vec<NativeEvent>,
) -> Result<RollbackFinalization> {
    request.validate()?;
    ensure!(
        target.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "completed NTFS rollback data bindings differ"
    );
    ensure!(
        target.state(&mut events)?.disk_attributes == 1
            && shadow.state(&mut events)?.disk_attributes == 3,
        "completed NTFS rollback requires excluded target and shadow"
    );
    let observed_journal = observe_journal(journal, request)?;
    validated_completed_ticket(
        request,
        journal,
        ticket,
        &observed_journal.identity,
        observed_journal.file_bytes,
    )?;
    let observed_binding = binding(request, &observed_journal.identity)?;
    let proof = lab_reconstruct::verify_completed_marker(
        &mut target,
        shadow,
        journal,
        ticket,
        &observed_binding,
        lab_reconstruct::CompletionKind::NtfsRollback,
        request.comparison.expected_length,
        &request.comparison.source_sha256,
        &request.comparison.shadow_sha256,
    )?;
    let length = target.byte_len();
    let raw = ntfs_inspect::inspect_with_limits(
        &mut target,
        length,
        ntfs_inspect::limits_for_resource_profile(
            request.source_resource_profile.unwrap_or_default(),
        ),
    )?;
    ntfs_backup::verify(&mut target, length, &raw)?;
    ntfs_log::verify(&mut target, &raw)?;
    let durable = durable_marker_for_mount(request, journal, ticket, &observed_binding, &proof)?;
    let mut report = RollbackFinalization {
        success: false,
        replay_closed: true,
        shadow_available: true,
        marker: None,
        completed_marker_proof: Some(proof),
        mounted_filesystem: None,
        error: None,
        events,
        production_conversion_qualified: false,
    };
    if let Err(error) = durable.with_mount(|| target.bring_online(&mut report.events)) {
        report.error = Some(error.to_string());
        return Ok(report);
    }
    let mounted = rediscover_general_volume_wait(request.pair.source.clone(), &mut report.events)
        .and_then(|binding| mounted_filesystem_general(binding, &mut report.events));
    match mounted {
        Ok(name) if name == "NTFS" => {
            report.mounted_filesystem = Some(name);
            report.success = true;
        }
        Ok(name) => {
            report.mounted_filesystem = Some(name);
            report.error = Some("completed rollback did not mount as NTFS".into());
        }
        Err(error) => report.error = Some(error.to_string()),
    }
    Ok(report)
}

/// Finish a readable NTFS rollback marker after process death when the ReFS
/// shadow is unavailable. Synchronize and revalidate the journal before mount;
/// the marker bytes are never rewritten or repaired.
pub fn resume_completed_rollback_without_shadow(
    request: &Request,
    mut target: GeneralJournaledPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    mut events: Vec<NativeEvent>,
) -> Result<RollbackFinalization> {
    request.validate()?;
    ensure!(
        target.binding() == &request.pair.source,
        "completed rollback target binding differs"
    );
    ensure!(
        target.state(&mut events)?.disk_attributes == 1,
        "completed rollback target is not offline"
    );
    let observed = observe_journal(journal, request)?;
    validated_completed_ticket(
        request,
        journal,
        ticket,
        &observed.identity,
        observed.file_bytes,
    )?;
    let bound = binding(request, &observed.identity)?;
    let proof = lab_reconstruct::verify_completed_rollback_marker_without_shadow(
        &mut target,
        journal,
        ticket,
        &bound,
        request.comparison.expected_length,
        &request.comparison.source_sha256,
    )?;
    let length = target.byte_len();
    let raw = ntfs_inspect::inspect_with_limits(
        &mut target,
        length,
        ntfs_inspect::limits_for_resource_profile(
            request.source_resource_profile.unwrap_or_default(),
        ),
    )?;
    ntfs_backup::verify(&mut target, length, &raw)?;
    ntfs_log::verify(&mut target, &raw)?;
    let durable = durable_marker_for_mount(request, journal, ticket, &bound, &proof)?;
    let mut report = RollbackFinalization {
        success: false,
        replay_closed: true,
        shadow_available: false,
        marker: None,
        completed_marker_proof: Some(proof),
        mounted_filesystem: None,
        error: None,
        events,
        production_conversion_qualified: false,
    };
    if let Err(error) = durable.with_mount(|| target.bring_online(&mut report.events)) {
        report.error = Some(error.to_string());
        return Ok(report);
    }
    let mounted = rediscover_general_volume_wait(request.pair.source.clone(), &mut report.events)
        .and_then(|binding| mounted_filesystem_general(binding, &mut report.events));
    match mounted {
        Ok(name) if name == "NTFS" => {
            report.mounted_filesystem = Some(name);
            report.success = true;
        }
        Ok(name) => {
            report.mounted_filesystem = Some(name);
            report.error = Some("completed rollback did not mount as NTFS".into());
        }
        Err(error) => report.error = Some(error.to_string()),
    }
    Ok(report)
}

/// Shared native readback of the original disk after a durable ReFS handoff.
fn verify_converted_tree(
    request: &Request,
    expectation: &shadow_tree::ExpectedTree,
    events: &mut Vec<NativeEvent>,
    restored_label: bool,
) -> std::io::Result<shadow_native::GeneralConvertedReport> {
    let mut pair = request.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, events)?;
    let input: Vec<_> = expectation
        .objects
        .iter()
        .map(|object| shadow_native::Input {
            components: &object.path,
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
            expected_api_security: object.api_security.as_deref(),
            payload: &[],
            expected_length: if object.directory {
                None
            } else {
                Some(object.length)
            },
            expected_sha256: if object.directory {
                None
            } else {
                object.sha256.as_deref()
            },
            source_offset: object.source_offset,
            source_runs: object
                .source_extents
                .iter()
                .map(|run| shadow_native::SourceRun {
                    logical_offset: run.logical_offset,
                    physical_offset: run.physical_offset,
                    length: run.length,
                })
                .collect(),
        })
        .collect();
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    if restored_label && let Some(label) = &request.expected_source_label {
        shadow_native::verify_general_converted_ordinary_with_label_and_resource_profile(
            pair,
            &input,
            label,
            same_security,
            request
                .source_resource_profile
                .unwrap_or_default()
                .native_profile(),
        )
    } else {
        shadow_native::verify_general_converted_ordinary_with_resource_profile(
            pair,
            &input,
            same_security,
            request
                .source_resource_profile
                .unwrap_or_default()
                .native_profile(),
        )
    }
}

fn restore_source_label(request: &Request, report: &mut Finalization) {
    let Some(desired) = &request.expected_source_label else {
        return;
    };
    let Some(native) = &report.native else {
        report.error =
            Some("label restoration requires successful native tree verification".into());
        return;
    };
    let enrollment = match n2r_win32::volume_label::VolumeLabel::from_text("n2r-retained-shadow") {
        Ok(value) => value,
        Err(error) => {
            report.error = Some(error.to_string());
            return;
        }
    };
    match n2r_win32::volume_label::restore_verified_label(
        &request.pair.source,
        desired,
        native.pair.source.clone(),
        &enrollment,
    ) {
        Ok(restored) => {
            if !restored.success {
                report.error = Some(format!(
                    "source label restoration failed: {:?}",
                    restored.error
                ));
            }
            report.label_restoration = Some(restored);
        }
        Err(error) => report.error = Some(format!("source label restoration refused: {error}")),
    }
}

/// The only planned general transition from an offline journal target to a
/// writable ReFS mount. Keep this internal until source admission and target
/// profile qualification issue an execution certificate.
#[allow(
    dead_code,
    reason = "General handoff awaits admission and native qualification"
)]
pub(crate) fn finalize(
    request: &Request,
    mut target: GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    expected_tree_bytes: &[u8],
) -> Result<Finalization> {
    request.validate()?;
    ensure!(
        hex::encode(Sha256::digest(expected_tree_bytes)) == request.expected_tree_sha256,
        "general target expectation pin differs"
    );
    let expectation: shadow_tree::ExpectedTree = serde_json::from_slice(expected_tree_bytes)?;
    expectation
        .validate_with_resource_profile(request.source_resource_profile.unwrap_or_default())?;
    ensure!(
        target.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "general handoff data bindings differ"
    );
    let mut events = Vec::new();
    ensure!(
        target.state(&mut events)?.disk_attributes == 1
            && shadow.state(&mut events)?.disk_attributes == 3,
        "general handoff requires excluded target and shadow"
    );
    let observed_journal = observe_journal(journal, request)?;
    validated_ticket(
        request,
        journal,
        ticket,
        &observed_journal.identity,
        observed_journal.file_bytes,
    )?;
    let observed_binding = binding(request, &observed_journal.identity)?;
    let mut report = Finalization {
        success: false,
        rollback_closed: false,
        handoff: None,
        completed_marker_proof: None,
        native: None,
        label_restoration: None,
        mount_paths_after: None,
        mount_paths_preserved: None,
        mount_paths_error: None,
        error: None,
        events,
        general_conversion_qualified: false,
    };
    // A partial marker also closes rollback; record that boundary before the
    // first handoff write and never retry it on this handle.
    report.rollback_closed = true;
    let handoff =
        lab_reconstruct::mark_handoff(&mut target, shadow, journal, ticket, &observed_binding);
    match handoff {
        Ok(value) => report.handoff = Some(value),
        Err(error) => {
            report.error = Some(format!("{error:#}"));
            return Ok(report);
        }
    }
    if let Err(error) = target.bring_online(&mut report.events) {
        report.error = Some(error.to_string());
        return Ok(report);
    }
    match verify_converted_tree(request, &expectation, &mut report.events, false) {
        Ok(native) => {
            record_mount_paths(request, &native, &mut report);
            report.native = Some(native);
            if report.error.is_none() {
                restore_source_label(request, &mut report);
            }
            report.success = report.error.is_none();
        }
        Err(error) => report.error = Some(error.to_string()),
    }
    Ok(report)
}

/// Finish a readable ReFS handoff marker after process death. Keep the exact
/// image proof and establish a fresh journal sync/revalidation before mount,
/// without writing or repairing any journal bytes.
pub fn finalize_after_marker(
    request: &Request,
    mut target: GeneralJournaledPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
    ticket: &JournalTicket,
    expected_tree_bytes: &[u8],
) -> Result<Finalization> {
    request.validate()?;
    ensure!(
        hex::encode(Sha256::digest(expected_tree_bytes)) == request.expected_tree_sha256,
        "completed ReFS target expectation pin differs"
    );
    let expectation: shadow_tree::ExpectedTree = serde_json::from_slice(expected_tree_bytes)?;
    expectation
        .validate_with_resource_profile(request.source_resource_profile.unwrap_or_default())?;
    ensure!(
        target.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "completed ReFS handoff data bindings differ"
    );
    let mut events = Vec::new();
    ensure!(
        target.state(&mut events)?.disk_attributes == 1
            && shadow.state(&mut events)?.disk_attributes == 3,
        "completed ReFS handoff requires excluded target and shadow"
    );
    let observed_journal = observe_journal(journal, request)?;
    validated_completed_ticket(
        request,
        journal,
        ticket,
        &observed_journal.identity,
        observed_journal.file_bytes,
    )?;
    let observed_binding = binding(request, &observed_journal.identity)?;
    let proof = lab_reconstruct::verify_completed_refs_marker_from_journal(
        &mut target,
        shadow,
        journal,
        ticket,
        &observed_binding,
        request.comparison.expected_length,
    )?;
    let durable = durable_marker_for_mount(request, journal, ticket, &observed_binding, &proof)?;
    let mut report = Finalization {
        success: false,
        rollback_closed: true,
        handoff: None,
        completed_marker_proof: Some(proof),
        native: None,
        label_restoration: None,
        mount_paths_after: None,
        mount_paths_preserved: None,
        mount_paths_error: None,
        error: None,
        events,
        general_conversion_qualified: false,
    };
    if let Err(error) = durable.with_mount(|| target.bring_online(&mut report.events)) {
        report.error = Some(error.to_string());
        return Ok(report);
    }
    let restored_label = if let Some(desired) = &request.expected_source_label {
        match rediscover_general_volume_wait(request.pair.source.clone(), &mut report.events)
            .and_then(|binding| n2r_win32::volume_label::observe_label(binding, "ReFS"))
        {
            Ok(observed) => observed.label == *desired,
            Err(error) => {
                report.error = Some(error.to_string());
                return Ok(report);
            }
        }
    } else {
        false
    };
    match verify_converted_tree(request, &expectation, &mut report.events, restored_label) {
        Ok(native) => {
            record_mount_paths(request, &native, &mut report);
            report.native = Some(native);
            if report.error.is_none() {
                restore_source_label(request, &mut report);
            }
            report.success = report.error.is_none();
        }
        Err(error) => report.error = Some(error.to_string()),
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::{general_layout::GeneralDiskBinding, layout::PartitionIdentity};

    fn disk(
        number: u32,
        disk_guid: &str,
        partition_guid: &str,
        volume_guid: &str,
    ) -> GeneralDiskBinding {
        GeneralDiskBinding {
            disk_number: number,
            volume_guid: volume_guid.into(),
            identity: PartitionIdentity {
                disk_guid: disk_guid.into(),
                partition_guid: partition_guid.into(),
                partition_number: 1,
                disk_bytes: 8 << 30,
                partition_offset: 1 << 20,
                partition_bytes: 4 << 30,
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
        }
    }

    fn request() -> Request {
        Request {
            schema_version: 1,
            source_resource_profile: None,
            experiment_id: "a".repeat(32),
            expected_tree_sha256: "c".repeat(64),
            expected_mount_paths: None,
            expected_source_label: None,
            pair: GeneralSourceShadowBinding {
                source: disk(
                    1,
                    "11111111-1111-1111-1111-111111111111",
                    "22222222-2222-2222-2222-222222222222",
                    "33333333-3333-3333-3333-333333333333",
                ),
                shadow: disk(
                    3,
                    "44444444-4444-4444-4444-444444444444",
                    "55555555-5555-5555-5555-555555555555",
                    "66666666-6666-6666-6666-666666666666",
                ),
            },
            comparison: RetainedCompareRequest {
                schema_version: 2,
                sector_size: 4096,
                expected_length: 4 << 30,
                source_sha256: "1".repeat(64),
                shadow_sha256: "2".repeat(64),
                retained_ranges: vec![],
                max_change_bytes: 256 << 20,
                max_ranges: 65536,
            },
            journal: GeneralJournalStorageBinding {
                externally_enrolled_disk_unique_id: "JOURNAL-TEST".into(),
                allow_additional_partitions: false,
                disk: GeneralDiskBinding {
                    disk_number: 2,
                    volume_guid: "77777777-7777-7777-7777-777777777777".into(),
                    identity: PartitionIdentity {
                        disk_guid: "88888888-8888-8888-8888-888888888888".into(),
                        partition_guid: "99999999-9999-9999-9999-999999999999".into(),
                        partition_number: 2,
                        disk_bytes: 8 << 30,
                        partition_offset: 16 << 20,
                        partition_bytes: (8 << 30) - (32 << 20),
                        logical_sector_bytes: 512,
                        physical_sector_bytes: 4096,
                    },
                },
            },
            max_journal_bytes: 768 << 20,
        }
    }

    #[test]
    fn general_request_requires_distinct_external_journal_and_equal_partitions() {
        let valid = request();
        valid.validate().unwrap();
        let mut overlapping = valid.clone();
        overlapping.pair.source.disk_number = 2;
        assert!(overlapping.validate().is_err());
        let mut unequal = valid.clone();
        unequal.pair.shadow.identity.partition_bytes += 4096;
        assert!(unequal.validate().is_err());
        let mut wrong_image = valid;
        wrong_image.comparison.expected_length += 4096;
        assert!(wrong_image.validate().is_err());
    }
    #[test]
    fn general_request_accepts_capacity_derived_bound_but_not_a_larger_one() {
        let mut valid = request();
        valid.comparison.max_change_bytes = lab_reconstruct::MAX_CHANGE_BYTES;
        valid.validate().unwrap();
        valid.comparison.max_change_bytes += 4096;
        assert!(valid.validate().is_err());
    }
    #[test]
    fn request_profile_and_write_budget_are_explicit() {
        let mut value = request();
        value.max_journal_bytes = 2u64 << 30;
        value.comparison.max_change_bytes = 512u64 << 20;
        assert!(value.validate().is_err());
        value.schema_version = 2;
        value.validate().unwrap();
        value.schema_version = 3;
        assert!(value.validate().is_err());
    }
    #[test]
    fn completed_ticket_rejects_cross_profile_and_different_immutable_plan() {
        use std::io::{Seek, SeekFrom, Write};
        for version in [1, 2] {
            let mut req = request();
            req.schema_version = version;
            let old = vec![0x31; 16384];
            let mut new = old.clone();
            new[8192..12288].fill(0x72);
            req.comparison.expected_length = old.len() as u64;
            req.comparison.max_change_bytes = old.len() as u64;
            req.comparison.source_sha256 = hex::encode(Sha256::digest(&old));
            req.comparison.shadow_sha256 = hex::encode(Sha256::digest(&new));
            let identity = JournalFileIdentity {
                volume_serial_number: 1,
                file_id_128: [2; 16],
                volume_guid: guid_bytes(&req.journal.disk.volume_guid).unwrap(),
                disk_guid: guid_bytes(&req.journal.disk.identity.disk_guid).unwrap(),
                partition_guid: guid_bytes(&req.journal.disk.identity.partition_guid).unwrap(),
                partition_number: req.journal.disk.identity.partition_number,
                disk_bytes: req.journal.disk.identity.disk_bytes,
                partition_offset: req.journal.disk.identity.partition_offset,
                partition_bytes: req.journal.disk.identity.partition_bytes,
                logical_sector_bytes: req.journal.disk.identity.logical_sector_bytes,
                physical_sector_bytes: req.journal.disk.identity.physical_sector_bytes,
            };
            let bound = binding(&req, &identity).unwrap();
            let mut source = tempfile::tempfile().unwrap();
            let mut shadow = tempfile::tempfile().unwrap();
            let mut journal = tempfile::tempfile().unwrap();
            source.write_all(&old).unwrap();
            shadow.write_all(&new).unwrap();
            source.seek(SeekFrom::Start(0)).unwrap();
            shadow.seek(SeekFrom::Start(0)).unwrap();
            let summary = lab_reconstruct::prepare_journal_with_profile(
                &mut source,
                &mut shadow,
                &mut journal,
                &req.comparison,
                &bound,
                req.max_journal_bytes,
                JournalProfile::from_schema(version).unwrap(),
            )
            .unwrap();
            let length = summary.ticket.journal_length;
            validated_completed_ticket(&req, &mut journal, &summary.ticket, &identity, length)
                .unwrap();
            let mut crossed = req.clone();
            crossed.schema_version = if version == 1 { 2 } else { 1 };
            assert!(
                validated_completed_ticket(
                    &crossed,
                    &mut journal,
                    &summary.ticket,
                    &identity,
                    length
                )
                .is_err()
            );
            crossed = req.clone();
            crossed.comparison.max_ranges -= 1;
            assert!(
                validated_completed_ticket(
                    &crossed,
                    &mut journal,
                    &summary.ticket,
                    &identity,
                    length
                )
                .is_err()
            );

            // Exercise both ABT proof forms after the actual marker exists.
            let mut target = tempfile::tempfile().unwrap();
            target.write_all(&old).unwrap();
            lab_reconstruct::mark_rollback_complete_without_shadow(
                &mut target,
                &mut journal,
                &summary.ticket,
                &bound,
            )
            .unwrap();
            validated_completed_ticket(&req, &mut journal, &summary.ticket, &identity, length)
                .unwrap();
            lab_reconstruct::verify_completed_marker(
                &mut target,
                &mut shadow,
                &mut journal,
                &summary.ticket,
                &bound,
                lab_reconstruct::CompletionKind::NtfsRollback,
                old.len() as u64,
                &req.comparison.source_sha256,
                &req.comparison.shadow_sha256,
            )
            .unwrap();
            lab_reconstruct::verify_completed_rollback_marker_without_shadow(
                &mut target,
                &mut journal,
                &summary.ticket,
                &bound,
                old.len() as u64,
                &req.comparison.source_sha256,
            )
            .unwrap();
            let mut crossed = req.clone();
            crossed.schema_version = if version == 1 { 2 } else { 1 };
            assert!(
                validated_completed_ticket(
                    &crossed,
                    &mut journal,
                    &summary.ticket,
                    &identity,
                    length
                )
                .is_err()
            );

            // The HND path must satisfy the same comparison and profile gate.
            let mut handoff_journal = tempfile::tempfile().unwrap();
            let handoff = lab_reconstruct::prepare_journal_with_profile(
                &mut source,
                &mut shadow,
                &mut handoff_journal,
                &req.comparison,
                &bound,
                req.max_journal_bytes,
                JournalProfile::from_schema(version).unwrap(),
            )
            .unwrap();
            lab_reconstruct::apply(
                &mut target,
                &mut shadow,
                &mut handoff_journal,
                &handoff.ticket,
                &bound,
            )
            .unwrap();
            lab_reconstruct::mark_handoff(
                &mut target,
                &mut shadow,
                &mut handoff_journal,
                &handoff.ticket,
                &bound,
            )
            .unwrap();
            validated_completed_ticket(
                &req,
                &mut handoff_journal,
                &handoff.ticket,
                &identity,
                handoff.ticket.journal_length,
            )
            .unwrap();
            lab_reconstruct::verify_completed_refs_marker_from_journal(
                &mut target,
                &mut shadow,
                &mut handoff_journal,
                &handoff.ticket,
                &bound,
                old.len() as u64,
            )
            .unwrap();
            assert!(
                validated_completed_ticket(
                    &crossed,
                    &mut handoff_journal,
                    &handoff.ticket,
                    &identity,
                    handoff.ticket.journal_length
                )
                .is_err()
            );
        }
    }
    #[test]
    fn source_labels_preserve_legacy_request_bytes_and_validate_new_metadata() {
        let old = request();
        let bytes = serde_json::to_vec(&old).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("expected_source_label"));
        let replay: Request = serde_json::from_slice(&bytes).unwrap();
        assert!(replay.expected_source_label.is_none());
        assert_eq!(serde_json::to_vec(&replay).unwrap(), bytes);
        let mut labeled = old;
        labeled.expected_source_label =
            Some(n2r_win32::volume_label::VolumeLabel::from_text("工程 😀").unwrap());
        labeled.validate().unwrap();
        let value = serde_json::to_value(&labeled).unwrap();
        let replay: Request = serde_json::from_value(value.clone()).unwrap();
        replay.validate().unwrap();
        assert_eq!(replay.expected_source_label, labeled.expected_source_label);
        let mut bad = value;
        bad["expected_source_label"] = serde_json::json!({"utf16":[65,0,66]});
        assert!(
            serde_json::from_value::<Request>(bad)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
