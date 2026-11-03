//! Optional NTFS-driver prealignment. A saved hint is never move authority:
//! the SDK owns and freshly verifies every file, map and free destination.
mod receipts;

use super::PreparationPlan;
use crate::{
    artifact_arena::{ArenaRamLease, ArtifactArena, ArtifactGroup, ArtifactGroupSeal},
    general_composite_target::paged_memory::ArenaReportMemory,
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent,
    attestation::FileIdentity,
    ntfs_preparation::{
        MoveRequest,
        resource::{self as native, MoveBudget},
    },
    tree_resources::ResourceBudget,
};
use receipts::{ClosedReceipts, ReceiptWriter};
use serde::Serialize;
use std::{fmt::Write as _, io, path::Path, sync::Arc};

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum StopKind {
    OperationalBudget,
    BeforeSubmission,
    UnverifiedSubmission,
    ExecutionError,
    FinalValidation,
}
#[derive(Serialize)]
struct Stop {
    kind: StopKind,
    reason: String,
    first_incomplete_plan_move: u64,
}
#[derive(Default, Serialize)]
struct Counters {
    complete_plan_moves: u64,
    skipped_missing_or_busy_plan_moves: u64,
    skipped_missing_or_busy_bytes: u64,
    submitted_moves: u64,
    submitted_bytes: u64,
    verified_moves: u64,
    verified_bytes: u64,
    opened_files: u64,
}
/// The enum forces a caller to distinguish a complete pass from an explicitly
/// stopped pass. Either variant owns the fully closed factual receipt archive.
pub(crate) enum PreparationExecutionOutcome {
    Completed(PreparationExecution),
    Stopped(PreparationExecution),
}
pub(crate) struct PreparationExecution {
    receipts: ClosedReceipts,
    seal: ArtifactGroupSeal,
    counters: Counters,
    stop: Option<Stop>,
    plan_moves: u64,
    _directory: std::fs::File,
    // All bounded strings, observer state and Arc adapters above drop first.
    _control_memory: ArenaRamLease,
}
impl PreparationExecution {
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.receipts.revalidate()?;
        self.seal.revalidate()
    }
    pub(crate) fn summary(&self) -> serde_json::Value {
        serde_json::json!({"kind":"resource-ntfs-prealignment-execution-v1", "counters":self.counters,
            "plan_moves":self.plan_moves,"stop":self.stop,"receipts":self.receipts.summary(),
            "ntfs_driver_owned":true,"raw_source_writes":0,"retry_or_undo_performed":false,
            "fresh_post_preparation_source_context_required":true,"source_admission":false,
            "rollback_baseline":"fresh NTFS state after preparation"})
    }
}
impl PreparationExecutionOutcome {
    pub(crate) fn execution(&self) -> &PreparationExecution {
        match self {
            Self::Completed(owner) | Self::Stopped(owner) => owner,
        }
    }
}
fn bounded_error(error: &dyn std::fmt::Display) -> String {
    struct Limited(String);
    impl std::fmt::Write for Limited {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let mut end = text.len().min(4096usize.saturating_sub(self.0.len()));
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            Ok(())
        }
    }
    let mut value = Limited(String::with_capacity(4096));
    let _ = write!(&mut value, "{error}");
    value.0
}
fn add(value: &mut u64, increment: u64) -> Result<()> {
    *value = value
        .checked_add(increment)
        .context("NTFS preparation execution count overflow")?;
    Ok(())
}
fn missing_or_busy(error: &io::Error) -> bool {
    // ACCESS_DENIED is deliberately not treated as a harmless busy result.
    matches!(error.raw_os_error(), Some(2 | 3 | 32 | 33))
}
fn identity(hint: &super::planner::Move) -> FileIdentity {
    FileIdentity {
        record_number: hint.record_number,
        sequence_number: hint.sequence_number,
    }
}
fn same_file(hint: &super::planner::Move, file: &FileIdentity) -> bool {
    hint.record_number == file.record_number && hint.sequence_number == file.sequence_number
}

#[derive(Serialize)]
struct OpenReceipt<'a> {
    identity: &'a FileIdentity,
    expected_logical_bytes: u64,
    first_plan_move: u64,
    error_code: Option<i32>,
    error: Option<&'a str>,
    submitted: bool,
}
#[derive(Serialize)]
struct Attempt<'a, T: Serialize> {
    plan_move: u64,
    submove: u64,
    capacity: &'a SubmissionCapacity,
    native: &'a T,
}
#[derive(Serialize)]
struct BeforeSubmissionError<'a> {
    plan_move: u64,
    submove: u64,
    request: &'a MoveRequest,
    native_error_code: Option<i32>,
    error: &'a str,
    capacity: Option<&'a SubmissionCapacity>,
    submitted: bool,
}
#[derive(Serialize)]
struct Skip<'a> {
    plan_move: u64,
    hint: &'a super::planner::Move,
    native_error_code: Option<i32>,
    reason: &'a str,
    submitted: bool,
}

#[derive(Serialize)]
struct SubmissionCapacity {
    available_bytes_to_caller: u64,
    minimum_free_bytes: u64,
    arena_promised_bytes: u64,
    closed_arena_allocated_bytes: u64,
    remaining_arena_reserved_bytes: u64,
    required_available_bytes: u64,
}
fn submission_capacity(
    arena: &ArtifactArena,
    minimum_free_bytes: u64,
) -> Result<SubmissionCapacity> {
    // The complete next receipt has already been prepaid, including both
    // ordinary data/directory encodings and their page/allocation framing.
    // Promised group quotas cover it plus all other outstanding arena work.
    // Credit only verified closed allocations, as the arena's own free-space
    // checks do; buffered/live writers are conservatively still outstanding.
    let usage = arena.usage()?;
    let pending = usage
        .promised_bytes
        .checked_sub(usage.actual_allocated_bytes)
        .context("NTFS pre-submit physical reservation accounting underflow")?;
    let required = minimum_free_bytes
        .checked_add(pending)
        .context("NTFS pre-submit free-space reserve overflow")?;
    let root = format!("{}\\", arena.volume_guid_path()?);
    let space = n2r_win32::discovery::observe_volume_space(&root)?;
    ensure!(
        space.available_bytes_to_caller >= required,
        "NTFS move not submitted: available journal space {} cannot cover unchanged reserve {} plus outstanding arena allocation {} (required {})",
        space.available_bytes_to_caller,
        minimum_free_bytes,
        pending,
        required
    );
    // An actual sample, not physical space reserved against unrelated writers.
    Ok(SubmissionCapacity {
        available_bytes_to_caller: space.available_bytes_to_caller,
        minimum_free_bytes,
        arena_promised_bytes: usage.promised_bytes,
        closed_arena_allocated_bytes: usage.actual_allocated_bytes,
        remaining_arena_reserved_bytes: pending,
        required_available_bytes: required,
    })
}

fn run(
    source: &mut native::OpenedSource,
    plan: &PreparationPlan,
    resources: ResourceBudget,
    limits: MoveBudget,
    minimum_free_bytes: u64,
    receipts: &mut ReceiptWriter,
    counters: &mut Counters,
) -> Result<Option<Stop>> {
    let cluster = plan.cluster_bytes();
    // Share the native response/window bound, independently of the explicit
    // moved-byte budget. The SDK still captures and checks the live window.
    let maximum_window_clusters = u64::from(native::maximum_clusters_per_move(
        resources,
        u32::try_from(cluster)?,
    )?);
    let maximum_clusters = (limits.maximum_move_bytes / cluster).min(maximum_window_clusters);
    ensure!(
        maximum_clusters > 0,
        "NTFS move budget cannot contain one cluster"
    );
    let mut cursor = 0u64;
    let mut previous_file = None;
    while cursor < plan.move_count() {
        let first = plan.move_hint(cursor)?;
        let file_id = identity(&first);
        ensure!(
            previous_file.is_none_or(|last| last < file_id.record_number),
            "NTFS plan file order differs"
        );
        previous_file = Some(file_id.record_number);
        match source.open_file(file_id.clone(), first.expected_logical_bytes) {
            Err(error) => {
                let reason = bounded_error(&error);
                receipts.append(
                    "file_open",
                    &OpenReceipt {
                        identity: &file_id,
                        expected_logical_bytes: first.expected_logical_bytes,
                        first_plan_move: cursor,
                        error_code: error.raw_os_error(),
                        error: Some(&reason),
                        submitted: false,
                    },
                )?;
                if !missing_or_busy(&error) {
                    return Ok(Some(Stop {
                        kind: StopKind::BeforeSubmission,
                        reason,
                        first_incomplete_plan_move: cursor,
                    }));
                }
                while cursor < plan.move_count() {
                    let hint = plan.move_hint(cursor)?;
                    if !same_file(&hint, &file_id) {
                        break;
                    }
                    let bytes = u64::from(hint.cluster_count)
                        .checked_mul(cluster)
                        .context("skipped hint bytes overflow")?;
                    receipts.append(
                        "missing_or_busy_skip",
                        &Skip {
                            plan_move: cursor,
                            hint: &hint,
                            native_error_code: error.raw_os_error(),
                            reason: &reason,
                            submitted: false,
                        },
                    )?;
                    add(&mut counters.skipped_missing_or_busy_plan_moves, 1)?;
                    add(&mut counters.skipped_missing_or_busy_bytes, bytes)?;
                    add(&mut counters.complete_plan_moves, 1)?;
                    cursor += 1;
                }
            }
            Ok(mut file) => {
                add(&mut counters.opened_files, 1)?;
                receipts.append(
                    "file_open",
                    &OpenReceipt {
                        identity: &file_id,
                        expected_logical_bytes: first.expected_logical_bytes,
                        first_plan_move: cursor,
                        error_code: None,
                        error: None,
                        submitted: false,
                    },
                )?;
                let mut previous_end = 0u64;
                while cursor < plan.move_count() {
                    let hint = plan.move_hint(cursor)?;
                    if !same_file(&hint, &file_id) {
                        break;
                    }
                    ensure!(
                        hint.expected_logical_bytes == first.expected_logical_bytes
                            && hint.cluster_count > 0
                            && hint.starting_vcn >= previous_end,
                        "NTFS per-file hint EOF/VCN order differs"
                    );
                    previous_end = hint
                        .starting_vcn
                        .checked_add(u64::from(hint.cluster_count))
                        .context("NTFS hint VCN overflow")?;
                    let mut completed = 0u64;
                    let mut submove = 0u64;
                    while completed < u64::from(hint.cluster_count) {
                        let remaining_bytes = limits
                            .maximum_total_move_bytes
                            .saturating_sub(counters.submitted_bytes);
                        let clusters = (u64::from(hint.cluster_count) - completed)
                            .min(maximum_clusters)
                            .min(remaining_bytes / cluster);
                        if counters.submitted_moves >= limits.maximum_moves || clusters == 0 {
                            return Ok(Some(Stop {
                                kind: StopKind::OperationalBudget,
                                reason:
                                    "explicit NTFS-driver move budget exhausted before submission"
                                        .into(),
                                first_incomplete_plan_move: cursor,
                            }));
                        }
                        let request = MoveRequest {
                            identity: file_id.clone(),
                            expected_logical_bytes: hint.expected_logical_bytes,
                            starting_vcn: hint
                                .starting_vcn
                                .checked_add(completed)
                                .context("move VCN overflow")?,
                            expected_source_lcn: hint
                                .source_lcn
                                .checked_add(completed)
                                .context("move source LCN overflow")?,
                            destination_lcn: hint
                                .destination_lcn
                                .checked_add(completed)
                                .context("move destination LCN overflow")?,
                            cluster_count: u32::try_from(clusters)?,
                            length_bytes: clusters
                                .checked_mul(cluster)
                                .context("move bytes overflow")?,
                        };
                        let mut capacity = None;
                        match file.move_clusters_with_reservation(&request, |maximum| {
                            receipts.reserve_native(maximum).map_err(io::Error::other)?;
                            capacity = Some(
                                submission_capacity(plan.artifact_arena(), minimum_free_bytes)
                                    .map_err(io::Error::other)?,
                            );
                            Ok(())
                        }) {
                            Err(error) => {
                                // SDK errors return only before FSCTL submission;
                                // submitted failures return the actual leased row.
                                let reason = bounded_error(&error);
                                receipts.append(
                                    "before_submission_error",
                                    &BeforeSubmissionError {
                                        plan_move: cursor,
                                        submove,
                                        request: &request,
                                        native_error_code: error.raw_os_error(),
                                        error: &reason,
                                        capacity: capacity.as_ref(),
                                        submitted: false,
                                    },
                                )?;
                                return Ok(Some(Stop {
                                    kind: StopKind::BeforeSubmission,
                                    reason,
                                    first_incomplete_plan_move: cursor,
                                }));
                            }
                            Ok(observation) => {
                                // Persist the sole actual result before checking
                                // its verification or deciding to stop. Never retry.
                                receipts.append(
                                    "native_move",
                                    &Attempt {
                                        plan_move: cursor,
                                        submove,
                                        capacity: capacity.as_ref().context(
                                            "submitted NTFS move lacks its actual pre-submit space observation",
                                        )?,
                                        native: &observation,
                                    },
                                )?;
                                ensure!(
                                    observation.submitted,
                                    "SDK returned a move row without submission"
                                );
                                add(&mut counters.submitted_moves, 1)?;
                                add(&mut counters.submitted_bytes, request.length_bytes)?;
                                let counters_match = observation.attempted_moves
                                    == counters.submitted_moves
                                    && observation.attempted_payload_bytes
                                        == counters.submitted_bytes;
                                if !observation.verified
                                    || observation.source_owner_poisoned
                                    || !counters_match
                                {
                                    return Ok(Some(Stop { kind:StopKind::UnverifiedSubmission,
                                        reason:"actual NTFS submission was not fully verified; no retry or undo performed".into(),
                                        first_incomplete_plan_move:cursor }));
                                }
                                add(&mut counters.verified_moves, 1)?;
                                add(&mut counters.verified_bytes, request.length_bytes)?;
                            }
                        }
                        completed += clusters;
                        submove += 1;
                    }
                    add(&mut counters.complete_plan_moves, 1)?;
                    cursor += 1;
                }
            }
        }
    }
    Ok(None)
}

/// Execute only an actual closed preparation-plan owner. No CLI selection,
/// source freeze/certificate, conversion journal, raw source writer or replay
/// is exposed. Every return with an owner has synced and read back all receipts.
pub(crate) fn execute_plan(
    plan: &PreparationPlan,
    resources: ResourceBudget,
    limits: MoveBudget,
    maximum_receipt_wire_bytes: u64,
    minimum_free_bytes: u64,
    output: &Path,
    arena: &ArtifactArena,
    events: &mut Vec<NativeEvent>,
) -> Result<PreparationExecutionOutcome> {
    resources.validate()?;
    ensure!(
        plan.artifact_arena().same_arena(arena) && arena.budget() == resources,
        "NTFS preparation plan/execution resource owner differs"
    );
    ensure!(
        maximum_receipt_wire_bytes > 0
            && maximum_receipt_wire_bytes <= resources.scratch_bytes
            && minimum_free_bytes > 0
            && limits.maximum_moves > 0
            && limits.maximum_move_bytes >= plan.cluster_bytes()
            && limits.maximum_total_move_bytes >= plan.cluster_bytes(),
        "explicit NTFS execution budget differs"
    );
    plan.revalidate()?;
    let control_memory = arena.reserve_ram(
        (output.as_os_str().as_encoded_bytes().len() as u64)
            .checked_mul(12)
            .and_then(|n| n.checked_add(65536))
            .context("NTFS executor state memory overflow")?,
    )?;
    let directory = super::create_child(arena, output)?;
    let group = arena.reserve_group(ArtifactGroup::RecoveryCopy, maximum_receipt_wire_bytes)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(
        SourceMetadataBudget::from_resource_budget(resources)?,
        group,
    )?;
    let mut receipts = ReceiptWriter::new(&output.join("execution"), scratch.clone())?;
    receipts.append("begin", &serde_json::json!({"schema_version":1,"source":plan.source(),
        "source_metadata_sha256":plan.metadata_sha256(),"ntfs_serial":plan.ntfs_serial(),
        "cluster_bytes":plan.cluster_bytes(),"plan_moves":plan.move_count(),"resources":resources,
        "maximum_moves":limits.maximum_moves,"maximum_move_bytes":limits.maximum_move_bytes,
        "maximum_total_move_bytes":limits.maximum_total_move_bytes,"minimum_free_bytes":minimum_free_bytes,
        "free_space_checks_are_observations_only":true,"fresh_post_preparation_source_context_required":true}))?;
    let payer = Arc::new(ArenaReportMemory(arena.clone()));
    let mut counters = Counters::default();
    let mut stop;
    match native::OpenedSource::open(
        plan.source().clone(),
        resources,
        plan.ntfs_serial(),
        u32::try_from(plan.cluster_bytes())?,
        limits,
        payer.clone(),
    ) {
        Err(error) => {
            receipts.append(
                "source_open_error",
                &serde_json::json!({"native_error_code":error.raw_os_error(),
                    "error":bounded_error(&error),"submitted":false}),
            )?;
            stop = Some(Stop {
                kind: StopKind::BeforeSubmission,
                reason: bounded_error(&error),
                first_incomplete_plan_move: 0,
            });
        }
        Ok(mut source) => {
            stop = match run(
                &mut source,
                plan,
                resources,
                limits,
                minimum_free_bytes,
                &mut receipts,
                &mut counters,
            ) {
                Ok(stopped) => stopped,
                Err(error) => Some(Stop {
                    kind: StopKind::ExecutionError,
                    reason: bounded_error(&error),
                    first_incomplete_plan_move: counters.complete_plan_moves,
                }),
            };
            match source.finish() {
                Ok(completion) => {
                    receipts.append("source_completion", &completion)?;
                    if completion.attempted_moves != counters.submitted_moves
                        || completion.attempted_payload_bytes != counters.submitted_bytes
                        || completion.source_owner_poisoned
                        || !completion.verified
                    {
                        stop.get_or_insert(Stop {
                            kind: StopKind::FinalValidation,
                            reason: "actual source completion counters or poison state differ"
                                .into(),
                            first_incomplete_plan_move: counters.complete_plan_moves,
                        });
                    }
                }
                Err(error) => {
                    let reason = bounded_error(&error);
                    receipts.append("source_completion_error", &reason)?;
                    stop.get_or_insert(Stop {
                        kind: StopKind::FinalValidation,
                        reason,
                        first_incomplete_plan_move: counters.complete_plan_moves,
                    });
                }
            }
        }
    }
    // Source::finish checks its actual held route/geometry and always attempts
    // privilege restoration after the final file and byte-range lock drop.
    // No stale raw inventory is treated as current post-move source evidence.
    drop(payer);
    match n2r_win32::observe_general_disk_state_readonly(plan.source().clone(), events) {
        Ok(state) => {
            receipts.append("final_physical_state", &state)?;
            if state.disk_attributes != 0 {
                stop.get_or_insert(Stop {
                    kind: StopKind::FinalValidation,
                    reason: "source is not online writable after NTFS preparation".into(),
                    first_incomplete_plan_move: counters.complete_plan_moves,
                });
            }
        }
        Err(error) => {
            let reason = bounded_error(&error);
            receipts.append("final_physical_state_error", &reason)?;
            stop.get_or_insert(Stop {
                kind: StopKind::FinalValidation,
                reason,
                first_incomplete_plan_move: counters.complete_plan_moves,
            });
        }
    }
    if let Err(error) = plan.revalidate() {
        let reason = bounded_error(&error);
        receipts.append("closing_plan_validation_error", &reason)?;
        stop.get_or_insert(Stop {
            kind: StopKind::FinalValidation,
            reason,
            first_incomplete_plan_move: counters.complete_plan_moves,
        });
    }
    if stop.is_none() && counters.complete_plan_moves != plan.move_count() {
        stop = Some(Stop {
            kind: StopKind::FinalValidation,
            reason: "NTFS plan prefix is incomplete".into(),
            first_incomplete_plan_move: counters.complete_plan_moves,
        });
    }
    receipts.append(
        "terminal",
        &serde_json::json!({"counters":counters,"stop":stop,
        "fresh_post_preparation_source_context_required":true,"source_admission":false}),
    )?;
    let receipts = receipts.close()?;
    let seal = scratch.seal()?;
    let completed = stop.is_none();
    let owner = PreparationExecution {
        receipts,
        seal,
        counters,
        stop,
        plan_moves: plan.move_count(),
        _directory: directory,
        _control_memory: control_memory,
    };
    owner.revalidate()?;
    Ok(if completed {
        PreparationExecutionOutcome::Completed(owner)
    } else {
        PreparationExecutionOutcome::Stopped(owner)
    })
}
