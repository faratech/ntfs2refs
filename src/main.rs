use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use ntfs2refs::{block_io, ntfs_inspect::InspectionLimits, planner};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "NTFS/ReFS inspection and experimental certificate-backed data-volume conversion.",
    args_conflicts_with_subcommands = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(flatten)]
    drive: ntfs2refs::drive_cli::DriveArgs,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Clone, ValueEnum)]
enum Target {
    Win11,
    Server,
}
#[derive(Subcommand)]
enum Command {
    /// Inspect a raw partition image (never a VHDX container or live device).
    Inspect {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Maximum cumulative logical NTFS stream bytes to hash, including zeros.
        #[arg(long, default_value_t = 1024)]
        stream_hash_budget_mib: u64,
    },
    /// Produce a non-executable feasibility report with explicit blockers.
    Plan {
        #[arg(long)]
        image: PathBuf,
        #[arg(long, value_enum)]
        target: Target,
        #[arg(long)]
        target_build: String,
        #[arg(long)]
        boot: bool,
        #[arg(long, default_value_t = 8192)]
        journal_budget_mib: u64,
        /// Maximum cumulative logical NTFS stream bytes to hash, including zeros.
        #[arg(long, default_value_t = 1024)]
        stream_hash_budget_mib: u64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify byte identity against an inspection report; not conversion validity.
    Verify {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        baseline: PathBuf,
    },
    /// List the implemented and gated capabilities.
    Capabilities,
    /// Compare same-sized native-format corpus images in bounded memory.
    Diff {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
        #[arg(long, default_value_t = 4096)]
        block_size: usize,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Compare frozen images while retaining explicit source byte ranges; never authorizes writes.
    CompareRetained {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        shadow: PathBuf,
        /// Bounded JSON request with full-image and retained-range hash pins.
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Convert a bound data volume through live qualification and an external journal.
    Convert {
        /// Legacy feasibility plans remain non-executable.
        #[arg(long, required_unless_present = "request", conflicts_with = "request")]
        plan: Option<PathBuf>,
        /// Device-bound conversion request; success flags do not authorize writes.
        #[arg(long, requires_all = ["request_sha256", "output"])]
        request: Option<PathBuf>,
        #[arg(long, requires = "request")]
        request_sha256: Option<String>,
        /// Fresh artifact directory on the Windows OS volume.
        #[arg(long, requires = "request")]
        output: Option<PathBuf>,
    },
    /// Resume an already activated offline target using pinned recovery inputs.
    Resume(RecoveryArgs),
    /// Restore the admitted NTFS preimage before the handoff barrier.
    Rollback(RecoveryArgs),
    /// Complete native ReFS handoff after an exact completed apply.
    Finalize(RecoveryArgs),
    /// Complete only the source label on a strictly verified mounted ReFS target.
    CompleteLabel(LabelCompletionArgs),
    /// Report verified public-run lifecycle facts without changing disk state.
    OperationState(RunOperationArgs),
    /// Restore unchanged NTFS availability before reconstruction activation.
    Cancel(RunOperationArgs),
}

#[derive(clap::Args)]
struct RunOperationArgs {
    #[arg(long)]
    run_directory: PathBuf,
    /// SHA-256 of the run's conversion-intent.json.
    #[arg(long)]
    intent_sha256: String,
    /// SHA-256 of qualification/source-frozen.json, required when present.
    #[arg(long)]
    frozen_source_sha256: Option<String>,
    /// SHA-256 of qualification/source-mount-paths.json, required when present.
    #[arg(long)]
    mount_paths_sha256: Option<String>,
    /// SHA-256 of the derived request.json, required when present.
    #[arg(long)]
    request_sha256: Option<String>,
    /// SHA-256 of the derived ticket.json, required when present.
    #[arg(long)]
    ticket_sha256: Option<String>,
    #[arg(long)]
    output: PathBuf,
}
fn run_operation(args: RunOperationArgs, cancel: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let input = ntfs2refs::general_operation_state::Inputs {
            run_directory: args.run_directory,
            intent_sha256: args.intent_sha256,
            frozen_source_sha256: args.frozen_source_sha256,
            mount_paths_sha256: args.mount_paths_sha256,
            request_sha256: args.request_sha256,
            ticket_sha256: args.ticket_sha256,
        };
        if cancel {
            ntfs2refs::general_cancel::cancel(&input, &args.output)?;
        } else {
            let report = ntfs2refs::general_operation_state::inspect(&input, &args.output)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (args, cancel);
        anyhow::bail!("public run state and cancellation require Windows")
    }
}

#[derive(clap::Args)]
struct LabelCompletionArgs {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    request_sha256: String,
    #[arg(long)]
    ticket: PathBuf,
    #[arg(long)]
    ticket_sha256: String,
    #[arg(long)]
    journal: PathBuf,
    #[arg(long)]
    expectation: PathBuf,
    #[arg(long)]
    expectation_sha256: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(clap::Args)]
struct RecoveryArgs {
    #[arg(long)]
    journal: PathBuf,
    #[arg(long, requires_all = ["request_sha256", "ticket", "ticket_sha256", "output"])]
    request: Option<PathBuf>,
    #[arg(long, requires = "request")]
    request_sha256: Option<String>,
    #[arg(long, requires = "request")]
    ticket: Option<PathBuf>,
    #[arg(long, requires = "request")]
    ticket_sha256: Option<String>,
    #[arg(long, requires = "request")]
    output: Option<PathBuf>,
    /// Required for finalize; must match the request's expected tree hash.
    #[arg(long, requires_all = ["request", "expectation_sha256"])]
    expectation: Option<PathBuf>,
    #[arg(long, requires = "expectation")]
    expectation_sha256: Option<String>,
    /// Complete an already durable rollback or handoff marker after process death.
    #[arg(long, requires = "request")]
    after_marker: bool,
    /// Use only the pinned old-byte journal for NTFS rollback; never resumes ReFS apply.
    #[arg(long, requires = "request")]
    without_shadow: bool,
}
#[derive(Deserialize)]
struct IdentityBaseline {
    schema_version: u32,
    source: block_io::SourceIdentity,
}
fn output(value: &impl Serialize, destination: Option<&Path>) -> Result<()> {
    if let Some(path) = destination {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .context("create report (existing files are never overwritten)")?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    } else {
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer_pretty(&mut stdout, value)?;
        stdout.write_all(b"\n")?;
    }
    Ok(())
}
fn inspection_limits(stream_hash_budget_mib: u64) -> Result<InspectionLimits> {
    ensure!(
        stream_hash_budget_mib > 0,
        "stream hash budget must be positive"
    );
    let max_stream_hash_bytes = stream_hash_budget_mib
        .checked_mul(1024 * 1024)
        .context("stream hash budget overflow")?;
    Ok(InspectionLimits {
        max_stream_hash_bytes,
        ..InspectionLimits::default()
    })
}
fn retained_request(path: &Path) -> Result<ntfs2refs::retained_compare::RetainedCompareRequest> {
    let file = File::open(path).context("open retained comparison request")?;
    ensure!(file.metadata()?.is_file(), "request must be a regular file");
    const LIMIT: u64 = 128 * 1024;
    ensure!(file.metadata()?.len() <= LIMIT, "request exceeds 128 KiB");
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "request exceeds 128 KiB");
    serde_json::from_slice(&bytes).context("parse retained comparison request")
}

#[cfg(windows)]
fn conversion_request(path: &Path, pin: &str) -> Result<ntfs2refs::general_conversion::Request> {
    use sha2::{Digest, Sha256};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const LIMIT: u64 = 16 * 1024;
    ensure!(
        pin.len() == 64
            && pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "conversion request SHA-256 must be canonical lowercase hex"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
        "conversion request must be an ordinary file"
    );
    ensure!(metadata.len() <= LIMIT, "conversion request exceeds 16 KiB");
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= LIMIT,
        "opened conversion request differs from bounded ordinary input"
    );
    let mut bytes = Vec::new();
    (&mut file).take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT && hex::encode(Sha256::digest(&bytes)) == pin,
        "conversion request SHA-256 differs"
    );
    let request: ntfs2refs::general_conversion::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    Ok(request)
}

fn recover(args: RecoveryArgs, operation: &str) -> Result<()> {
    ensure!(
        !args.without_shadow || operation == "rollback",
        "--without-shadow is only valid for rollback"
    );
    let Some(request) = args.request else {
        return planner::require_writer();
    };
    ensure!(
        !args.after_marker || matches!(operation, "finalize" | "rollback"),
        "--after-marker is only valid for rollback or finalize"
    );
    #[cfg(windows)]
    {
        use ntfs2refs::general_recovery::{Inputs, Operation};
        let operation = match (operation, args.after_marker, args.without_shadow) {
            ("resume", false, false) => Operation::Resume,
            ("rollback", false, false) => Operation::Rollback,
            ("rollback", true, false) => Operation::RollbackAfterMarker,
            ("rollback", false, true) => Operation::RollbackWithoutShadow,
            ("rollback", true, true) => Operation::RollbackAfterMarkerWithoutShadow,
            ("finalize", false, false) => Operation::Finalize,
            ("finalize", true, false) => Operation::FinalizeAfterMarker,
            _ => anyhow::bail!("unsupported recovery operation"),
        };
        let inputs = Inputs {
            request,
            request_sha256: args.request_sha256.context("request SHA-256 required")?,
            ticket: args.ticket.context("ticket required")?,
            ticket_sha256: args.ticket_sha256.context("ticket SHA-256 required")?,
            journal: args.journal,
            expectation: args.expectation,
            expectation_sha256: args.expectation_sha256,
        };
        ntfs2refs::general_recovery::recover(
            operation,
            &inputs,
            &args.output.context("fresh output required")?,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (
            request,
            args.journal,
            args.request_sha256,
            args.ticket,
            args.ticket_sha256,
            args.output,
            args.expectation,
            args.expectation_sha256,
            operation,
        );
        anyhow::bail!("native journal recovery requires Windows")
    }
}
fn run() -> Result<u8> {
    let cli = Cli::parse();
    if cli.drive.requested() {
        return ntfs2refs::drive_cli::run(cli.drive);
    }
    match cli.command.context("use --list, --drive, or a subcommand")? {
        Command::Inspect {
            image,
            output: destination,
            stream_hash_budget_mib,
        } => {
            output(
                &planner::inspect_image_with_limits(
                    &image,
                    inspection_limits(stream_hash_budget_mib)?,
                )?,
                destination.as_deref(),
            )?;
        }
        Command::Plan {
            image,
            target,
            target_build,
            boot,
            journal_budget_mib,
            stream_hash_budget_mib,
            output: destination,
        } => {
            let budget = journal_budget_mib
                .checked_mul(1024 * 1024)
                .context("journal budget overflow")?;
            let target = match target {
                Target::Win11 => "win11",
                Target::Server => "server",
            };
            let plan = planner::plan(
                planner::inspect_image_with_limits(
                    &image,
                    inspection_limits(stream_hash_budget_mib)?,
                )?,
                target,
                &target_build,
                boot,
                budget,
            )?;
            output(&plan, destination.as_deref())?;
            eprintln!(
                "Image plan is blocked: {} qualification/preservation findings. This report cannot authorize conversion writes.",
                plan.blockers.len()
            );
            return Ok(2);
        }
        Command::Verify { image, baseline } => {
            let expected: IdentityBaseline = serde_json::from_reader(File::open(baseline)?)?;
            ensure!(
                expected.schema_version == 1,
                "unsupported inspection schema"
            );
            let actual = block_io::identity(&mut block_io::open_image(&image)?, &image)?;
            ensure!(
                expected.source.length == actual.length && expected.source.sha256 == actual.sha256,
                "image differs from baseline"
            );
            output(
                &serde_json::json!({"schema_version":1,"matches_baseline":true,"scope":"raw image byte identity only; does not validate conversion or native mountability"}),
                None,
            )?;
        }
        Command::Capabilities => {
            let registry = ntfs2refs::capability_evidence::Registry::embedded()?;
            let large =
                ntfs2refs::ntfs_admission::ResourceProfile::ExperimentalLargeTreeV1.limits();
            output(
                &serde_json::json!({"schema_version":1,"raw_image_inspection":true,"ntfs_inventory_complete":false,"refs_header_inspection":true,"retained_range_comparison":true,"conversion_planning":"image feasibility reports remain non-executable","native_refs_writer":false,"conversion_writes":cfg!(windows),"journal_recovery":cfg!(windows),"native_workflow":"experimental nonboot data volumes; live qualification and external journal required","experimental_large_tree":{"available":cfg!(windows),"maximum_files":large.maximum_files,"maximum_directories":large.maximum_directories,"maximum_logical_bytes":large.maximum_logical_bytes,"maximum_partition_bytes":n2r_win32::general_layout::MAX_LIVE_PARTITION_BYTES,"source_cluster_bytes":4096,"native_qualified":false},"qualified_boot_builds":[],
                    "qualification_registry_scope":registry.scope,
                    "recorded_qualification":registry.matrix()?,
                    "recorded_evidence_grants_runtime_authority":false}),
                None,
            )?;
        }
        Command::Diff {
            before,
            after,
            block_size,
            output: destination,
        } => output(
            &ntfs2refs::corpus::diff(&before, &after, block_size)?,
            destination.as_deref(),
        )?,
        Command::CompareRetained {
            source,
            shadow,
            request,
            output: destination,
        } => output(
            &ntfs2refs::retained_compare::compare_retained(
                &source,
                &shadow,
                &retained_request(&request)?,
            )?,
            destination.as_deref(),
        )?,
        Command::Convert {
            request: Some(request),
            request_sha256,
            output,
            ..
        } => {
            #[cfg(windows)]
            ntfs2refs::general_conversion::convert(
                &conversion_request(
                    &request,
                    &request_sha256.context("request SHA-256 required")?,
                )?,
                &output.context("fresh artifact output required")?,
            )?;
            #[cfg(not(windows))]
            {
                let _ = (request, request_sha256, output);
                anyhow::bail!("native data-volume conversion requires Windows");
            }
        }
        Command::Convert { .. } => planner::require_writer()?,
        Command::Resume(args) => recover(args, "resume")?,
        Command::Rollback(args) => recover(args, "rollback")?,
        Command::Finalize(args) => recover(args, "finalize")?,
        Command::OperationState(args) => run_operation(args, false)?,
        Command::Cancel(args) => run_operation(args, true)?,
        Command::CompleteLabel(args) => {
            #[cfg(windows)]
            ntfs2refs::general_label_completion::complete(
                &ntfs2refs::general_label_completion::Inputs {
                    request: args.request,
                    request_sha256: args.request_sha256,
                    ticket: args.ticket,
                    ticket_sha256: args.ticket_sha256,
                    journal: args.journal,
                    expectation: args.expectation,
                    expectation_sha256: args.expectation_sha256,
                },
                &args.output,
            )?;
            #[cfg(not(windows))]
            {
                let _ = args;
                anyhow::bail!("native label completion requires Windows");
            }
        }
    }
    Ok(0)
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
