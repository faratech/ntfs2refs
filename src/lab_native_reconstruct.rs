//! Explicit laboratory integration for already-offline native partitions.
//!
//! The caller owns the exclusive ordinary journal File, independent enrollment
//! evidence, and a separately pinned, durable ticket. Preparation never arms
//! target writes. Execution never isolates an online disk or brings a disk
//! online, including after handoff. Native qualification remains external.
use crate::{
    lab_native::ProbeRequest,
    lab_reconstruct::{self, JournalBinding, JournalDescriptor, JournalSummary, JournalTicket},
    retained_compare::{self, RetainedCompareRequest},
};
use anyhow::{Result, ensure};
use n2r_win32::{
    NativeEvent, OfflinePartition, PartitionSnapshot, WritePolicy,
    journal_file::{
        JournalFileIdentity, JournalFileSnapshot, JournalStorageBinding, MAX_JOURNAL_BYTES,
        observe_journal_file,
    },
    layout::{PARTITION_BYTES, PartitionIdentity, guid_bytes},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;

const RETAINED_BYTES: u64 = 65536;
const MAX_CHANGE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReconstructRequest {
    pub schema_version: u32,
    pub experiment_id: String,
    pub probe: ProbeRequest,
    pub comparison: RetainedCompareRequest,
    pub journal: JournalStorageBinding,
    pub max_journal_bytes: u64,
}

impl NativeReconstructRequest {
    /// Pure validation. No file, volume or device is opened by this method.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported native reconstruction request"
        );
        self.probe.validate()?;
        ensure!(
            self.comparison.schema_version == 1,
            "legacy fixture requires comparison schema 1"
        );
        self.journal.validate()?;
        ensure!(
            self.experiment_id == self.probe.experiment_id,
            "experiment differs from native probe enrollment"
        );
        retained_compare::validate_request(&self.comparison)?;
        let c = &self.comparison;
        ensure!(
            c.expected_length == PARTITION_BYTES && c.sector_size == 4096,
            "native reconstruction requires exact 52 GiB partitions and 4096-byte granules"
        );
        ensure!(
            c.max_change_bytes <= MAX_CHANGE_BYTES,
            "native changed-byte budget exceeds 256 MiB"
        );
        ensure!(
            (1..=MAX_JOURNAL_BYTES).contains(&self.max_journal_bytes),
            "native journal budget is outside profile"
        );
        ensure!(
            c.retained_ranges.len() == 1,
            "native profile requires exactly one retained range"
        );
        let retained = &c.retained_ranges[0];
        ensure!(
            retained.offset == self.probe.retained_offset
                && retained.length == RETAINED_BYTES
                && retained.source_sha256 == self.probe.source_retained_sha256
                && retained.shadow_sha256 == self.probe.shadow_retained_sha256,
            "retained range differs from enrolled native A/B proof"
        );
        for data in [&self.probe.target, &self.probe.shadow] {
            ensure!(
                data.disk_number != self.journal.disk_number
                    && guid_bytes(&data.identity.disk_guid)?
                        != guid_bytes(&self.journal.identity.disk_guid)?
                    && guid_bytes(&data.identity.partition_guid)?
                        != guid_bytes(&self.journal.identity.partition_guid)?
                    && guid_bytes(&data.volume_guid)? != guid_bytes(&self.journal.volume_guid)?,
                "journal storage overlaps a data-partition enrollment"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeReconstructOperation {
    Apply,
    Resume,
    Rollback,
    Handoff,
}

impl NativeReconstructOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Resume => "resume",
            Self::Rollback => "rollback",
            Self::Handoff => "handoff",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct NativeIoCounters {
    pub target_bytes_read: u64,
    pub target_bytes_written: u64,
    pub target_write_bytes_requested: u64,
    pub shadow_bytes_read: u64,
    pub shadow_bytes_written: u64,
    pub shadow_write_bytes_requested: u64,
}

#[derive(Debug, Serialize)]
pub struct NativeJournalPlan {
    pub patch_count: usize,
    pub changed_bytes: u64,
    pub expected_postimage_sha256: String,
    pub immutable_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct NativeReconstructReport {
    pub schema_version: u32,
    pub kind: String,
    pub operation: String,
    pub request: NativeReconstructRequest,
    pub success: bool,
    pub phase: String,
    pub error: Option<String>,
    pub observed_binding: Option<JournalBinding>,
    pub target_before: Option<PartitionSnapshot>,
    pub shadow_before: Option<PartitionSnapshot>,
    pub journal_before: Option<JournalFileSnapshot>,
    pub target_after: Option<PartitionSnapshot>,
    pub shadow_after: Option<PartitionSnapshot>,
    pub journal_after: Option<JournalFileSnapshot>,
    pub plan: Option<NativeJournalPlan>,
    pub preparation: Option<JournalSummary>,
    pub execution: Option<lab_reconstruct::ExecutionReport>,
    pub counters: NativeIoCounters,
    pub events: Vec<NativeEvent>,
    pub payload_write_requests_issued: bool,
    pub journal_write_requests_may_have_been_issued: bool,
    pub handoff_request_may_have_been_issued: bool,
    pub disks_observed_offline_at_end: bool,
    pub online_transition_requested: bool,
    pub conversion_qualified: bool,
    pub boot_qualified: bool,
}

impl NativeReconstructReport {
    fn new(request: &NativeReconstructRequest, operation: &str) -> Self {
        Self {
            schema_version: 1,
            kind: "native-lab-journal-reconstruction".into(),
            operation: operation.into(),
            request: request.clone(),
            success: false,
            phase: "validate".into(),
            error: None,
            observed_binding: None,
            target_before: None,
            shadow_before: None,
            journal_before: None,
            target_after: None,
            shadow_after: None,
            journal_after: None,
            plan: None,
            preparation: None,
            execution: None,
            counters: NativeIoCounters::default(),
            events: vec![],
            payload_write_requests_issued: false,
            journal_write_requests_may_have_been_issued: false,
            handoff_request_may_have_been_issued: false,
            disks_observed_offline_at_end: false,
            online_transition_requested: false,
            conversion_qualified: false,
            boot_qualified: false,
        }
    }

    fn finish(
        &mut self,
        result: Result<()>,
        target: Option<&OfflinePartition>,
        shadow: Option<&OfflinePartition>,
    ) {
        if let Some(t) = target {
            self.counters.target_bytes_read = t.native_bytes_read;
            self.counters.target_bytes_written = t.native_bytes_written;
            self.counters.target_write_bytes_requested = t.native_write_bytes_requested;
            self.payload_write_requests_issued = t.native_write_bytes_requested != 0;
        }
        if let Some(s) = shadow {
            self.counters.shadow_bytes_read = s.native_bytes_read;
            self.counters.shadow_bytes_written = s.native_bytes_written;
            self.counters.shadow_write_bytes_requested = s.native_write_bytes_requested;
        }
        match result {
            Ok(()) => {
                self.phase = "complete-disks-remain-offline".into();
                self.success = true;
            }
            Err(error) => self.error = Some(format!("{error:#}")),
        }
    }
}

#[derive(Serialize)]
struct CanonicalPartitionIdentity {
    disk_guid: [u8; 16],
    partition_guid: [u8; 16],
    partition_number: u32,
    disk_bytes: u64,
    partition_offset: u64,
    partition_bytes: u64,
    logical_sector_bytes: u32,
    physical_sector_bytes: u32,
}

pub(crate) fn identity_hash(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(serde_json::to_vec(value)?);
    Ok(hex::encode(hash.finalize()))
}

pub(crate) fn partition_hash(p: &PartitionIdentity) -> Result<String> {
    identity_hash(
        b"ntfs2refs/lab/gpt-partition-identity/v1",
        &CanonicalPartitionIdentity {
            disk_guid: guid_bytes(&p.disk_guid)?,
            partition_guid: guid_bytes(&p.partition_guid)?,
            partition_number: p.partition_number,
            disk_bytes: p.disk_bytes,
            partition_offset: p.partition_offset,
            partition_bytes: p.partition_bytes,
            logical_sector_bytes: p.logical_sector_bytes,
            physical_sector_bytes: p.physical_sector_bytes,
        },
    )
}

fn observed_binding(
    request: &NativeReconstructRequest,
    target: &PartitionSnapshot,
    shadow: &PartitionSnapshot,
    journal: &JournalFileIdentity,
) -> Result<JournalBinding> {
    ensure!(
        target.disk_attributes == 1 && shadow.disk_attributes == 3,
        "native isolation attributes differ"
    );
    // OfflinePartition's snapshot parser has checked each field against the
    // current raw device responses. Routes and volume paths are not hashed.
    let target_identity_sha256 = partition_hash(&target.binding.identity)?;
    let shadow_identity_sha256 = partition_hash(&shadow.binding.identity)?;
    ensure!(
        target_identity_sha256 == partition_hash(&request.probe.target.identity)?
            && shadow_identity_sha256 == partition_hash(&request.probe.shadow.identity)?,
        "observed partitions differ from enrollment"
    );
    Ok(JournalBinding {
        experiment_id: request.experiment_id.clone(),
        target_identity_sha256,
        shadow_identity_sha256,
        journal_identity_sha256: identity_hash(b"ntfs2refs/lab/journal-file-identity/v1", journal)?,
    })
}

fn preflight_ticket(request: &NativeReconstructRequest, ticket: &JournalTicket) -> Result<()> {
    ensure!(
        ticket.schema_version == 1 && ticket.binding.experiment_id == request.experiment_id,
        "ticket experiment or schema differs"
    );
    ensure!(
        ticket.binding.target_identity_sha256 == partition_hash(&request.probe.target.identity)?
            && ticket.binding.shadow_identity_sha256
                == partition_hash(&request.probe.shadow.identity)?,
        "ticket data-partition identities differ from enrollment"
    );
    for pin in [
        &ticket.immutable_sha256,
        &ticket.binding.journal_identity_sha256,
    ] {
        ensure!(
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid ticket pin"
        );
    }
    ensure!(
        ticket.journal_length <= request.max_journal_bytes
            && ticket.immutable_length >= 256
            && ticket.immutable_length.checked_add(8192) == Some(ticket.journal_length),
        "ticket journal length is outside the exact bounded format"
    );
    Ok(())
}

fn write_policy(
    request: &NativeReconstructRequest,
    descriptor: &JournalDescriptor,
) -> Result<Option<WritePolicy>> {
    ensure!(
        serde_json::to_vec(&descriptor.request)? == serde_json::to_vec(&request.comparison)?,
        "journal comparison differs from the requested native operation"
    );
    ensure!(
        descriptor.patches.len() <= request.comparison.max_ranges as usize,
        "journal patch count exceeds requested bound"
    );
    let bytes = descriptor
        .patches
        .iter()
        .try_fold(0_u64, |sum, patch| sum.checked_add(patch.length))
        .ok_or_else(|| anyhow::anyhow!("journal patch-byte sum overflow"))?;
    ensure!(
        bytes == descriptor.changed_bytes
            && bytes <= request.comparison.max_change_bytes
            && bytes <= MAX_CHANGE_BYTES,
        "journal patch-byte budget differs"
    );
    if descriptor.patches.is_empty() {
        return Ok(None); // No raw write arming for an empty change set.
    }
    let policy = WritePolicy {
        allowed: descriptor
            .patches
            .iter()
            .map(|p| (p.offset, p.length))
            .collect(),
        retained: request
            .comparison
            .retained_ranges
            .iter()
            .map(|p| (p.offset, p.length))
            .collect(),
        maximum_bytes: bytes,
    };
    policy.validate(PARTITION_BYTES)?;
    Ok(Some(policy))
}

fn postcheck(
    report: &mut NativeReconstructReport,
    journal: &File,
    target: &OfflinePartition,
    shadow: &OfflinePartition,
    expected_length: u64,
) -> Result<()> {
    report.phase = "post-operation-identities".into();
    report.journal_after = Some(observe_journal_file(journal, &report.request.journal)?);
    report.target_after = Some(target.inspect(&mut report.events)?);
    report.shadow_after = Some(shadow.inspect(&mut report.events)?);
    let j = report.journal_after.as_ref().expect("observed journal");
    ensure!(
        j.file_bytes == expected_length,
        "journal length changed outside operation"
    );
    let after = observed_binding(
        &report.request,
        report.target_after.as_ref().unwrap(),
        report.shadow_after.as_ref().unwrap(),
        &j.identity,
    )?;
    ensure!(
        Some(&after) == report.observed_binding.as_ref(),
        "storage binding changed during operation"
    );
    report.disks_observed_offline_at_end = true;
    Ok(())
}

/// Prepare and flush a journal without arming any target write. The caller must
/// independently store and flush preparation.ticket before a separate execute
/// invocation. A failed report does not authorize execution or baseline cleanup.
pub fn prepare(request: &NativeReconstructRequest, journal: &mut File) -> NativeReconstructReport {
    let mut report = NativeReconstructReport::new(request, "prepare");
    let (mut target, mut shadow) = (None, None);
    let result = (|| -> Result<()> {
        request.validate()?;
        report.phase = "journal-identity-before".into();
        report.journal_before = Some(observe_journal_file(journal, &request.journal)?);
        ensure!(
            report.journal_before.as_ref().unwrap().file_bytes == 0,
            "preparation journal must be empty"
        );
        report.phase = "target-reopen-offline".into();
        target = Some(OfflinePartition::reopen(
            request.probe.target.clone(),
            false,
            &mut report.events,
        )?);
        report.target_before = Some(target.as_ref().unwrap().inspect(&mut report.events)?);
        report.phase = "shadow-reopen-offline-read-only".into();
        shadow = Some(OfflinePartition::reopen(
            request.probe.shadow.clone(),
            true,
            &mut report.events,
        )?);
        report.shadow_before = Some(shadow.as_ref().unwrap().inspect(&mut report.events)?);
        let binding = observed_binding(
            request,
            report.target_before.as_ref().unwrap(),
            report.shadow_before.as_ref().unwrap(),
            &report.journal_before.as_ref().unwrap().identity,
        )?;
        report.observed_binding = Some(binding.clone());
        report.phase = "prepare-complete-journal".into();
        report.journal_write_requests_may_have_been_issued = true;
        let summary = lab_reconstruct::prepare_journal(
            target.as_mut().unwrap(),
            shadow.as_mut().unwrap(),
            journal,
            &request.comparison,
            &binding,
            request.max_journal_bytes,
        )?;
        let length = summary.ticket.journal_length;
        report.preparation = Some(summary);
        postcheck(
            &mut report,
            journal,
            target.as_ref().unwrap(),
            shadow.as_ref().unwrap(),
            length,
        )
    })();
    report.finish(result, target.as_ref(), shadow.as_ref());
    report
}

/// Execute using a ticket already loaded from independently pinned durable
/// storage. Supplying an arbitrary JSON ticket cannot establish that trust.
/// Handoff writes the core's irreversible recovery barrier but leaves both
/// disks offline. The caller must preserve failures, including torn handoff.
pub fn execute(
    operation: NativeReconstructOperation,
    request: &NativeReconstructRequest,
    journal: &mut File,
    trusted_ticket: &JournalTicket,
) -> NativeReconstructReport {
    let mut report = NativeReconstructReport::new(request, operation.name());
    let (mut target, mut shadow) = (None, None);
    let result = (|| -> Result<()> {
        request.validate()?;
        preflight_ticket(request, trusted_ticket)?;
        report.phase = "journal-identity-before".into();
        report.journal_before = Some(observe_journal_file(journal, &request.journal)?);
        ensure!(
            report.journal_before.as_ref().unwrap().file_bytes == trusted_ticket.journal_length,
            "observed journal length differs from trusted ticket"
        );
        report.phase = "target-reopen-offline".into();
        target = Some(OfflinePartition::reopen(
            request.probe.target.clone(),
            false,
            &mut report.events,
        )?);
        report.target_before = Some(target.as_ref().unwrap().inspect(&mut report.events)?);
        report.phase = "shadow-reopen-offline-read-only".into();
        shadow = Some(OfflinePartition::reopen(
            request.probe.shadow.clone(),
            true,
            &mut report.events,
        )?);
        report.shadow_before = Some(shadow.as_ref().unwrap().inspect(&mut report.events)?);
        let binding = observed_binding(
            request,
            report.target_before.as_ref().unwrap(),
            report.shadow_before.as_ref().unwrap(),
            &report.journal_before.as_ref().unwrap().identity,
        )?;
        report.observed_binding = Some(binding.clone());
        ensure!(
            binding == trusted_ticket.binding,
            "observed storage binding differs from trusted ticket"
        );
        report.phase = "inspect-pinned-journal".into();
        let descriptor = lab_reconstruct::inspect_journal(journal, trusted_ticket, &binding)?;
        let policy = write_policy(request, &descriptor)?;
        report.plan = Some(NativeJournalPlan {
            patch_count: descriptor.patches.len(),
            changed_bytes: descriptor.changed_bytes,
            expected_postimage_sha256: descriptor.expected_postimage_sha256,
            immutable_sha256: descriptor.immutable_sha256,
        });
        if operation != NativeReconstructOperation::Handoff
            && let Some(policy) = policy
        {
            report.phase = "arm-exact-journal-ranges".into();
            target
                .as_mut()
                .unwrap()
                .arm_writes(policy, &mut report.events)?;
        }
        report.phase = format!("execute-{}", operation.name());
        report.journal_write_requests_may_have_been_issued = true;
        let t = target.as_mut().unwrap();
        let s = shadow.as_mut().unwrap();
        report.execution = Some(match operation {
            NativeReconstructOperation::Apply => {
                lab_reconstruct::apply(t, s, journal, trusted_ticket, &binding)?
            }
            NativeReconstructOperation::Resume => {
                lab_reconstruct::resume(t, s, journal, trusted_ticket, &binding)?
            }
            NativeReconstructOperation::Rollback => {
                lab_reconstruct::rollback(t, s, journal, trusted_ticket, &binding)?
            }
            NativeReconstructOperation::Handoff => {
                report.handoff_request_may_have_been_issued = true;
                lab_reconstruct::mark_handoff(t, s, journal, trusted_ticket, &binding)?
            }
        });
        postcheck(
            &mut report,
            journal,
            target.as_ref().unwrap(),
            shadow.as_ref().unwrap(),
            trusted_ticket.journal_length,
        )
    })();
    report.finish(result, target.as_ref(), shadow.as_ref());
    report
}

#[cfg(test)]
#[path = "../tests/support/lab_native_reconstruct.rs"]
mod tests;
