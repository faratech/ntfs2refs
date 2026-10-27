//! Native journaled reconstruction for the enrolled four-file tree and a
//! versioned ordinary-tree laboratory profile. Both use the same durable
//! journal engine. General-purpose source admission remains separate.
use crate::{
    lab_native_reconstruct::{identity_hash, partition_hash},
    lab_reconstruct::{self, JournalBinding, JournalSummary, JournalTicket},
    retained_compare::{self, RetainedCompareRequest},
};
use anyhow::{Result, ensure};
use n2r_win32::{
    NativeEvent, OfflinePartition, PartitionSnapshot, WritePolicy,
    journal_file::{JournalStorageBinding, MAX_JOURNAL_BYTES, observe_journal_file},
    layout::{DiskBinding, PARTITION_BYTES, guid_bytes},
};
use serde::{Deserialize, Serialize};
use std::fs::File;

pub const SOURCE_SHA256: &str = "798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89";
pub const SHADOW_SHA256: &str = "da1e6cd1d676ce806e5937d934ab57ebed57fa6bf4c0f6593fb8d34859490e01";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub experiment_id: String,
    pub source: DiskBinding,
    pub shadow: DiskBinding,
    pub comparison: RetainedCompareRequest,
    pub journal: JournalStorageBinding,
    pub max_journal_bytes: u64,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.schema_version, 2 | 3)
                && self.experiment_id.len() == 32
                && self
                    .experiment_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid tree reconstruction identity"
        );
        self.source.validate()?;
        self.shadow.validate()?;
        self.journal.validate()?;
        ensure!(
            self.source.disk_number == 1 && self.shadow.disk_number == 3,
            "tree source/shadow routes differ"
        );
        if self.schema_version == 2 {
            ensure!(
                guid_bytes(&self.source.identity.disk_guid)?
                    == guid_bytes("a01574d5-2a5c-4136-958a-dcf0d0e0f7aa")?
                    && guid_bytes(&self.source.identity.partition_guid)?
                        == guid_bytes("79eaccdf-38d3-4561-97cc-9276af5d223a")?
                    && guid_bytes(&self.source.volume_guid)?
                        == guid_bytes("79eaccdf-38d3-4561-97cc-9276af5d223a")?
                    && guid_bytes(&self.shadow.identity.disk_guid)?
                        == guid_bytes("cd923950-593c-41f2-bc9b-7b2625d6cb6a")?
                    && guid_bytes(&self.shadow.identity.partition_guid)?
                        == guid_bytes("f9fefbb5-3781-45aa-a8d4-69463f46bf51")?
                    && guid_bytes(&self.shadow.volume_guid)?
                        == guid_bytes("f9fefbb5-3781-45aa-a8d4-69463f46bf51")?,
                "natural-tree experiment enrollment differs"
            );
        }
        retained_compare::validate_request(&self.comparison)?;
        let c = &self.comparison;
        ensure!(
            c.schema_version == 2
                && c.expected_length == PARTITION_BYTES
                && c.sector_size == 4096
                && c.max_change_bytes <= 256 * 1024 * 1024
                && (self.schema_version == 3
                    || (c.source_sha256 == SOURCE_SHA256
                        && c.shadow_sha256 == SHADOW_SHA256
                        && c.retained_ranges.is_empty())),
            "tree image pins, placement or budgets differ"
        );
        if self.schema_version == 3 {
            ensure!(
                guid_bytes(&self.source.identity.disk_guid)?
                    != guid_bytes(&self.shadow.identity.disk_guid)?
                    && guid_bytes(&self.source.identity.partition_guid)?
                        != guid_bytes(&self.shadow.identity.partition_guid)?
                    && guid_bytes(&self.source.volume_guid)?
                        != guid_bytes(&self.shadow.volume_guid)?,
                "ordinary source and shadow identities overlap"
            );
        }
        ensure!(
            (1..=MAX_JOURNAL_BYTES).contains(&self.max_journal_bytes),
            "invalid journal capacity"
        );
        for data in [&self.source, &self.shadow] {
            ensure!(
                guid_bytes(&data.identity.disk_guid)?
                    != guid_bytes(&self.journal.identity.disk_guid)?
                    && guid_bytes(&data.identity.partition_guid)?
                        != guid_bytes(&self.journal.identity.partition_guid)?
                    && guid_bytes(&data.volume_guid)? != guid_bytes(&self.journal.volume_guid)?,
                "external journal overlaps a data volume"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Prepare,
    Activate,
    Apply,
    Resume,
    Rollback,
    Handoff,
}
impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
pub fn prepare(request: &Request, journal: &mut File) -> Report {
    run(Operation::Prepare, request, journal, None)
}
pub fn execute(
    operation: Operation,
    request: &Request,
    journal: &mut File,
    ticket: &JournalTicket,
) -> Report {
    run(operation, request, journal, Some(ticket))
}
/// Deliberately terminate the converter after N durable target writes. The
/// journal and persistent OFFLINE bit survive; no handoff is issued.
pub fn execute_interrupted(
    operation: Operation,
    request: &Request,
    journal: &mut File,
    ticket: &JournalTicket,
    writes: u32,
) -> Report {
    run_with_interruption(operation, request, journal, Some(ticket), Some(writes))
}
struct InterruptingTarget<'a> {
    inner: &'a mut OfflinePartition,
    remaining: u32,
}
impl std::io::Read for InterruptingTarget<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(self.inner, b)
    }
}
impl std::io::Seek for InterruptingTarget<'_> {
    fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
        std::io::Seek::seek(self.inner, p)
    }
}
impl std::io::Write for InterruptingTarget<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = std::io::Write::write(self.inner, b)?;
        if n > 0 {
            self.remaining -= 1;
            if self.remaining == 0 {
                self.inner.sync_all()?;
                eprintln!(
                    "Controlled interruption after durable target write; disk remains offline, journal recovery required."
                );
                std::process::exit(86);
            }
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.sync_all()
    }
}
impl lab_reconstruct::ReadSeek for InterruptingTarget<'_> {
    fn byte_len(&mut self) -> std::io::Result<u64> {
        Ok(OfflinePartition::byte_len(self.inner))
    }
}
impl lab_reconstruct::DurableIo for InterruptingTarget<'_> {
    fn sync_all(&mut self) -> std::io::Result<()> {
        self.inner.sync_all()
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub kind: &'static str,
    pub operation: Operation,
    pub request: Request,
    pub success: bool,
    pub phase: String,
    pub error: Option<String>,
    pub preparation: Option<JournalSummary>,
    pub execution: Option<lab_reconstruct::ExecutionReport>,
    pub target_before: Option<PartitionSnapshot>,
    pub target_after: Option<PartitionSnapshot>,
    pub shadow_before: Option<PartitionSnapshot>,
    pub shadow_after: Option<PartitionSnapshot>,
    pub observed_binding: Option<JournalBinding>,
    pub target_bytes_read: u64,
    pub target_write_bytes_requested: u64,
    pub target_bytes_written: u64,
    pub shadow_bytes_read: u64,
    pub journal_write_requests_may_have_been_issued: bool,
    pub activation_may_have_been_issued: bool,
    pub events: Vec<NativeEvent>,
    pub general_source_admission_issued: bool,
    pub conversion_qualified: bool,
}
fn binding(
    request: &Request,
    target: &PartitionSnapshot,
    shadow: &PartitionSnapshot,
    journal: &n2r_win32::journal_file::JournalFileIdentity,
    read_only: bool,
) -> Result<JournalBinding> {
    ensure!(
        target.disk_attributes == if read_only { 3 } else { 1 }
            && shadow.disk_attributes == 3
            && target.binding == request.source
            && shadow.binding == request.shadow,
        "actual data identities or persistent exclusion differ"
    );
    Ok(JournalBinding {
        experiment_id: request.experiment_id.clone(),
        target_identity_sha256: partition_hash(&target.binding.identity)?,
        shadow_identity_sha256: partition_hash(&shadow.binding.identity)?,
        journal_identity_sha256: identity_hash(b"ntfs2refs/lab/journal-file-identity/v1", journal)?,
    })
}
/// A pinned ticket is persisted separately by the CLI before Activate or any
/// payload operation. Prepare accepts a read-only original source. Activate
/// changes only READ_ONLY while retaining persistent OFFLINE; Apply performs
/// the journal engine's full preimage/recovery checks before its first write.
pub fn run(
    operation: Operation,
    request: &Request,
    journal: &mut File,
    ticket: Option<&JournalTicket>,
) -> Report {
    run_with_interruption(operation, request, journal, ticket, None)
}
fn run_with_interruption(
    operation: Operation,
    request: &Request,
    journal: &mut File,
    ticket: Option<&JournalTicket>,
    interrupt_after_writes: Option<u32>,
) -> Report {
    let mut report = Report {
        schema_version: 1,
        kind: if request.schema_version == 3 {
            "native-ordinary-tree-journal-reconstruction"
        } else {
            "native-natural-tree-journal-reconstruction"
        },
        operation,
        request: request.clone(),
        success: false,
        phase: "validate".into(),
        error: None,
        preparation: None,
        execution: None,
        target_before: None,
        target_after: None,
        shadow_before: None,
        shadow_after: None,
        observed_binding: None,
        target_bytes_read: 0,
        target_write_bytes_requested: 0,
        target_bytes_written: 0,
        shadow_bytes_read: 0,
        journal_write_requests_may_have_been_issued: false,
        activation_may_have_been_issued: false,
        events: vec![],
        general_source_admission_issued: false,
        conversion_qualified: false,
    };
    let (mut target, mut shadow) = (None, None);
    let outcome = (|| -> Result<()> {
        request.validate()?;
        ensure!(
            interrupt_after_writes.is_none_or(|n| (1..=4096).contains(&n)
                && matches!(
                    operation,
                    Operation::Apply | Operation::Resume | Operation::Rollback
                )),
            "invalid interruption point or operation"
        );
        ensure!(
            std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
            "tree laboratory operation must run inside the owning guest"
        );
        let read_only = matches!(operation, Operation::Prepare | Operation::Activate);
        let before = observe_journal_file(journal, &request.journal)?;
        ensure!(
            if operation == Operation::Prepare {
                before.file_bytes == 0
            } else {
                ticket.is_some()
            },
            "empty new journal or separately trusted recovery ticket required"
        );
        report.phase = "reopen-excluded-devices".into();
        target = Some(OfflinePartition::reopen(
            request.source.clone(),
            read_only,
            &mut report.events,
        )?);
        shadow = Some(OfflinePartition::reopen(
            request.shadow.clone(),
            true,
            &mut report.events,
        )?);
        let t = target.as_mut().unwrap();
        let s = shadow.as_mut().unwrap();
        report.target_before = Some(t.inspect(&mut report.events)?);
        report.shadow_before = Some(s.inspect(&mut report.events)?);
        let actual = binding(
            request,
            report.target_before.as_ref().unwrap(),
            report.shadow_before.as_ref().unwrap(),
            &before.identity,
            read_only,
        )?;
        report.observed_binding = Some(actual.clone());
        let expected_length;
        if operation == Operation::Prepare {
            report.phase = "prepare-durable-old-new-journal".into();
            report.journal_write_requests_may_have_been_issued = true;
            let summary = lab_reconstruct::prepare_journal(
                t,
                s,
                journal,
                &request.comparison,
                &actual,
                request.max_journal_bytes,
            )?;
            ensure!(
                summary.expected_postimage_sha256 == request.comparison.shadow_sha256,
                "relocation-only postimage differs"
            );
            expected_length = summary.ticket.journal_length;
            report.preparation = Some(summary);
        } else {
            let ticket = ticket.unwrap();
            ensure!(
                ticket.schema_version == 1
                    && ticket.binding == actual
                    && ticket.journal_length == before.file_bytes
                    && ticket.journal_length <= request.max_journal_bytes
                    && ticket.immutable_length.checked_add(8192) == Some(ticket.journal_length),
                "trusted ticket binding or journal size differs"
            );
            report.phase = "inspect-trusted-journal".into();
            let descriptor = lab_reconstruct::inspect_journal(journal, ticket, &actual)?;
            ensure!(
                serde_json::to_vec(&descriptor.request)?
                    == serde_json::to_vec(&request.comparison)?
                    && descriptor.expected_postimage_sha256 == request.comparison.shadow_sha256,
                "journal plan differs from the enrolled tree conversion"
            );
            expected_length = ticket.journal_length;
            if operation == Operation::Activate {
                report.phase = "activate-offline-journal-target".into();
                report.activation_may_have_been_issued = true;
                t.enable_excluded_writes(&mut report.events)?;
            } else {
                if operation != Operation::Handoff && !descriptor.patches.is_empty() {
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
                            .map(|r| (r.offset, r.length))
                            .collect(),
                        maximum_bytes: descriptor.changed_bytes,
                        journal_profile: n2r_win32::journal_file::JournalProfile::LegacyV1,
                    };
                    t.arm_writes(policy, &mut report.events)?;
                }
                report.phase = format!("execute-{operation:?}");
                report.journal_write_requests_may_have_been_issued = true;
                if let Some(remaining) = interrupt_after_writes {
                    let mut interrupted = InterruptingTarget {
                        inner: t,
                        remaining,
                    };
                    report.execution = Some(match operation {
                        Operation::Apply => {
                            lab_reconstruct::apply(&mut interrupted, s, journal, ticket, &actual)?
                        }
                        Operation::Resume => {
                            lab_reconstruct::resume(&mut interrupted, s, journal, ticket, &actual)?
                        }
                        Operation::Rollback => lab_reconstruct::rollback(
                            &mut interrupted,
                            s,
                            journal,
                            ticket,
                            &actual,
                        )?,
                        _ => unreachable!(),
                    });
                    anyhow::bail!(
                        "requested interruption point was not reached; do not infer crash coverage"
                    );
                }
                report.execution = Some(match operation {
                    Operation::Apply => lab_reconstruct::apply(t, s, journal, ticket, &actual)?,
                    Operation::Resume => lab_reconstruct::resume(t, s, journal, ticket, &actual)?,
                    Operation::Rollback => {
                        lab_reconstruct::rollback(t, s, journal, ticket, &actual)?
                    }
                    Operation::Handoff => {
                        lab_reconstruct::mark_handoff(t, s, journal, ticket, &actual)?
                    }
                    _ => unreachable!(),
                });
            }
        }
        report.phase = "post-operation-device-binding".into();
        report.target_after = Some(t.inspect(&mut report.events)?);
        report.shadow_after = Some(s.inspect(&mut report.events)?);
        let after = observe_journal_file(journal, &request.journal)?;
        ensure!(
            after.file_bytes == expected_length
                && binding(
                    request,
                    report.target_after.as_ref().unwrap(),
                    report.shadow_after.as_ref().unwrap(),
                    &after.identity,
                    operation == Operation::Prepare
                )? == actual,
            "post-operation storage binding changed"
        );
        Ok(())
    })();
    if let Some(t) = target {
        report.target_bytes_read = t.native_bytes_read;
        report.target_write_bytes_requested = t.native_write_bytes_requested;
        report.target_bytes_written = t.native_bytes_written;
    }
    if let Some(s) = shadow {
        report.shadow_bytes_read = s.native_bytes_read;
    }
    match outcome {
        Ok(()) => {
            report.success = true;
            report.phase = "complete-disks-remain-offline".into();
        }
        Err(e) => report.error = Some(format!("{e:#}")),
    }
    report
}

#[derive(Debug, Serialize)]
pub struct FinalizeReport {
    pub success: bool,
    pub handoff: Report,
    pub native: Option<n2r_win32::shadow_native::Report>,
    pub events: Vec<NativeEvent>,
    pub error: Option<String>,
    pub rollback_closed: bool,
    pub general_conversion_qualified: bool,
}
/// Complete the irreversible handoff and immediately verify the converted
/// original through Microsoft's driver. A verifier refusal never reopens the
/// old NTFS recovery path after handoff.
pub fn finalize(
    request: &Request,
    journal: &mut File,
    ticket: &JournalTicket,
    expectation: &crate::lab_tree_expectation::Expectation,
) -> Result<FinalizeReport> {
    request.validate()?;
    expectation.validate(request)?;
    let handoff = run(Operation::Handoff, request, journal, Some(ticket));
    let mut report = FinalizeReport {
        success: false,
        rollback_closed: handoff.journal_write_requests_may_have_been_issued,
        handoff,
        native: None,
        events: vec![],
        error: None,
        general_conversion_qualified: false,
    };
    let result = (|| -> Result<()> {
        ensure!(
            report.handoff.success,
            "handoff failed: {:?}",
            report.handoff.error
        );
        let disk = OfflinePartition::reopen(request.source.clone(), false, &mut report.events)?;
        disk.bring_online(&mut report.events)?;
        // Publication can lag the persistent disk-attribute transition.
        std::thread::sleep(std::time::Duration::from_millis(1000));
        report.native = Some(expectation.verify(request)?);
        Ok(())
    })();
    match result {
        Ok(()) => report.success = true,
        Err(e) => report.error = Some(format!("{e:#}")),
    }
    Ok(report)
}
