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
    about = "NTFS/ReFS inspection and feasibility-gated conversion research. Conversion writes are not enabled."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    /// Unavailable until a ReFS writer passes native-driver qualification.
    Convert {
        #[arg(long)]
        plan: PathBuf,
    },
    /// Unavailable until the recovery protocol passes power-loss qualification.
    Resume {
        #[arg(long)]
        journal: PathBuf,
    },
    /// Unavailable until the recovery protocol passes power-loss qualification.
    Rollback {
        #[arg(long)]
        journal: PathBuf,
    },
    /// Unavailable until conversion and recovery qualification are complete.
    Finalize {
        #[arg(long)]
        journal: PathBuf,
    },
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
fn run() -> Result<u8> {
    match Cli::parse().command {
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
                "Plan is blocked: {} qualification/preservation findings. No conversion writes are available.",
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
        Command::Capabilities => output(
            &serde_json::json!({"schema_version":1,"raw_image_inspection":true,"ntfs_inventory_complete":false,"refs_header_inspection":true,"retained_range_comparison":true,"conversion_planning":"feasibility only","native_refs_writer":false,"conversion_writes":false,"journal_recovery":false,"qualified_boot_builds":[]}),
            None,
        )?,
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
        Command::Convert { .. }
        | Command::Resume { .. }
        | Command::Rollback { .. }
        | Command::Finalize { .. } => planner::require_writer()?,
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
