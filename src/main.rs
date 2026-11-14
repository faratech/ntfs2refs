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

/// What `--help` ends with: the order to do things in, and where the rest is.
const AFTER_HELP: &str = "\
Start with these, from an elevated terminal:
  ntfs2refs --list
  ntfs2refs --drive E --scratch-directory S:\\runs --diagnose
  ntfs2refs --drive E --scratch-directory S:\\runs

--list says for each NTFS partition whether it can be converted. --diagnose
checks a volume without writing to it. A conversion prints a recovery command
before its first write to the volume; keep it. docs/cli-workflow.md is the
guide. `ntfs2refs capabilities` prints what this executable admits and
refuses, and names the commands of earlier designs that this help no longer
lists.";

#[derive(Parser)]
#[command(
    version,
    about = "Converts an NTFS volume to ReFS in place.",
    after_help = AFTER_HELP,
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
/// `capabilities` is the command of the product. The others are research
/// tools for raw images and the request-file commands of earlier designs:
/// they still work and have their own `--help`, and `capabilities` names
/// them, but the top-level help does not list them.
#[derive(Subcommand)]
enum Command {
    /// Inspect a raw partition image (never a VHDX container or live device).
    #[command(hide = true)]
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
    #[command(hide = true)]
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
    #[command(hide = true)]
    Verify {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        baseline: PathBuf,
    },
    /// Print, as JSON, what this executable admits, refuses and does not carry over.
    Capabilities,
    /// Compare same-sized native-format corpus images in bounded memory.
    #[command(hide = true)]
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
    #[command(hide = true)]
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
    #[command(hide = true)]
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
    #[command(hide = true)]
    Resume(RecoveryArgs),
    /// Restore the admitted NTFS preimage before the handoff barrier.
    #[command(hide = true)]
    Rollback(RecoveryArgs),
    /// Complete native ReFS handoff after an exact completed apply.
    #[command(hide = true)]
    Finalize(RecoveryArgs),
    /// Complete only the source label on a strictly verified mounted ReFS target.
    #[command(hide = true)]
    CompleteLabel(LabelCompletionArgs),
    /// Report verified public-run lifecycle facts without changing disk state.
    #[command(hide = true)]
    OperationState(RunOperationArgs),
    /// Restore unchanged NTFS availability before reconstruction activation.
    #[command(hide = true)]
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
/// The hidden subcommands, as `capabilities` names them. A test holds this
/// to the commands the parser has and to what `--help` lists.
const HIDDEN_IMAGE_COMMANDS: &[&str] = &["inspect", "plan", "verify", "diff", "compare-retained"];
const HIDDEN_REQUEST_COMMANDS: &[&str] = &[
    "convert",
    "resume",
    "rollback",
    "finalize",
    "complete-label",
    "operation-state",
    "cancel",
];

fn run() -> Result<u8> {
    let cli = Cli::parse();
    if cli.drive.requested() {
        return ntfs2refs::drive_cli::run(cli.drive);
    }
    match cli
        .command
        .context("use --list, --drive, or a subcommand")?
    {
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
            let diagnose_refuses: Vec<_> = ntfs2refs::drive_cli::DriveArgs::DIAGNOSE_REFUSES
                .iter()
                .map(|(option, reason)| serde_json::json!({"option": option, "reason": reason}))
                .collect();
            output(
                &serde_json::json!({
                    "schema_version": 5,
                    "tool_version": env!("CARGO_PKG_VERSION"),
                    "raw_image_inspection": true,
                    "ntfs_inventory_complete": false,
                    "refs_header_inspection": true,
                    "retained_range_comparison": true,
                    "conversion_planning": "image feasibility reports remain non-executable",
                    "conversion_writes": cfg!(windows),
                    "journal_recovery": cfg!(windows),
                    // Windows builds the ReFS metadata on a temporary shadow;
                    // this executable writes ReFS structures raw in one place.
                    "refs_metadata_builder": "windows",
                    "raw_refs_writes": ["trust-label patch on the temporary shadow"],
                    "conversion_routes": [
                        {"route": "dedicated-data-volume", "option": "--drive", "in_help": true,
                         "status": "the default route; what the lab showed of it is in docs/feature-matrix.md and docs/recovery-matrix.md"},
                        {"route": "windows-boot-volume", "option": "--windows-boot-volume", "in_help": true,
                         "status": "admitted for the listed boot profiles only; converted, booted and used in the lab"},
                        {"route": "whole-image", "option": "--whole-image-verification", "in_help": false,
                         "status": "an earlier design; experimental; data volumes only",
                         "fixed_limits": {"files": 1024, "directories": 256, "placed_ntfs_runs": 4096},
                         "limits_note": "refused before anything is written; the other routes are bounded by the machine's memory and working storage, not by fixed counts"},
                        {"route": "shared-disk", "option": "--offline-media", "in_help": false,
                         "status": "an earlier design; experimental; needs ntfs2refs-recovery.exe, which no release ships"},
                    ],
                    // Subcommands that still work and that --help no longer lists.
                    "commands_not_in_help": {
                        "status": "experimental; kept so that the records of earlier builds can still be read; not covered by the matrices",
                        "raw_image_research": HIDDEN_IMAGE_COMMANDS,
                        "request_file_route": HIDDEN_REQUEST_COMMANDS,
                    },
                    // The rows the boot-volume admission gate enforces.
                    "qualified_boot_profiles": ntfs2refs::boot_profile::QUALIFIED,
                    // What the default data-volume route admits. A Windows
                    // boot volume is one of the profiles above.
                    "source_geometry": {
                        "sector_bytes": [512, 4096],
                        "cluster_bytes": {"minimum": 512, "maximum": 2 * 1024 * 1024},
                        "file_record_bytes": [1024, 4096],
                        "index_record_bytes": {"minimum": 512, "maximum": 65536,
                            "note": "Windows formats 4096; other sizes are checked by constructed indexes only"},
                        "partition_length": "any; one that is not a multiple of 64 MiB is first shrunk to one",
                    },
                    "target": {
                        "option": "--target-cluster-bytes",
                        "refs_cluster_bytes": n2r_win32::target_cluster::SUPPORTED_BYTES,
                        "default_refs_cluster_bytes": n2r_win32::target_cluster::DEFAULT_BYTES,
                        "windows_boot_volume_refs_cluster_bytes": [n2r_win32::target_cluster::DEFAULT_BYTES],
                        "formats": {
                            "option": "--target-format",
                            "dev-drive": "the default on Windows 11 and other workstation editions, and the only format of a Windows boot volume",
                            "standard": "the default for a data volume on Windows Server; works only where Windows itself formats an ordinary ReFS volume",
                            "shown": "both on Windows Server 2025 (build 26100); dev-drive on Windows 11 (build 26300), which does not format a standard volume",
                        },
                        "refs_version": "the version Windows formats the shadow with: 3.14 or a later 3.x (only 3.14 has been converted)",
                        "data_stays_in_place": "only where it lies on target-cluster boundaries; the rest is copied through the working storage",
                    },
                    "windows_builds": {
                        "minimum_build": n2r_win32::windows_build::MINIMUM_BUILD,
                        "confirmed_builds": n2r_win32::windows_build::LAB_BUILDS,
                        "other_builds": "accepted, with a notice before the prompt that the build has not been tried",
                    },
                    // What a data volume that has been in use meets.
                    "data_volume": {
                        "disk_layout": "a GPT disk on which the volume is the only partition apart from a Microsoft reserved partition; --list says for each NTFS partition whether it qualifies",
                        "requires": ["administrator rights, checked before a disk is opened",
                                     "the Windows build, checked before a disk is opened"],
                        "not_carried_over": [
                            {"what": "object IDs of files and directories, which Windows gives to the targets of shortcuts",
                             "why": "ReFS has no object IDs",
                             "record": "each is matched with the volume's object-ID index and kept in the run's records; their number is printed"},
                            {"what": "the NTFS compression flag", "why": "compressed data is stored as ordinary data on ReFS"},
                            {"what": "the change journal", "why": "the converted volume starts a new one"},
                        ],
                        "refused_by_name": [
                            {"what": "8.3 short names", "remedy": "fsutil 8dot3name strip, then fsutil 8dot3name set <drive>: 1"},
                            {"what": "a BitLocker-encrypted volume", "remedy": "decrypt it (manage-bde -off)"},
                            {"what": "shadow copies of the volume, snapshot storage kept on it, or a shadow-copy provider other than Windows' own and Hyper-V's",
                             "remedy": "delete the shadow copies; the provider is named"},
                            {"what": "EFS-encrypted files", "remedy": "cipher /d"},
                            {"what": "files with the TEMPORARY or OFFLINE attribute"},
                            {"what": "reparse points other than symbolic links, junctions and app execution aliases (Data Deduplication, compact /exe, cloud placeholders, WSL)",
                             "remedy": "named per kind"},
                            {"what": "a named data stream on a directory"},
                            {"what": "disk quotas in use", "remedy": "fsutil quota disable"},
                            {"what": "case-sensitive directories", "remedy": "fsutil file setCaseSensitiveInfo <directory> disable"},
                            {"what": "a dirty volume, an NTFS log that was not closed, an open transaction", "remedy": "chkdsk /f, or a clean dismount"},
                            {"what": "a volume with no file on it", "remedy": "format it as ReFS"},
                        ],
                    },
                    "source_changes_before_apply": [
                        {"when": "the partition length is not a multiple of 64 MiB (ReFS covers a volume in whole units of that size)",
                         "change": "the Windows NTFS driver shrinks the partition to one",
                         "undone_if_the_run_stops": false},
                        {"when": "--minimize-scratch",
                         "change": "files are moved through NTFS before the source is frozen",
                         "undone_if_the_run_stops": false},
                    ],
                    "unattended": {
                        "option": "--yes",
                        "answers": "every question of the run",
                        "requires": "--volume-serial for a conversion or a diagnose run (the serial number --list prints); a recovery is bound to its run by its checksum",
                    },
                    "list": {
                        "option": "--list",
                        "shows": "for each NTFS partition whether a conversion would take it, and its volume serial number",
                        "bitlocker": "shown when --list runs elevated (it reads each partition's first sector); otherwise it says that BitLocker was not checked",
                        "exit_codes": {
                            "0": "every disk and volume was queried",
                            (ntfs2refs::drive_cli::EXIT_LIST_INCOMPLETE.to_string()):
                                "some device could not be queried; the list is partial",
                        },
                    },
                    "check": {
                        "option": "--check",
                        "for": "a data volume",
                        "changes_the_volume": false,
                        "reads": "the volume while it stays online and in use: its NTFS structures and the shadow-copy catalog. Nothing is frozen, formatted or shrunk; its own pages are kept in the working directory meanwhile and removed",
                        "reports": [
                            "every refusal a conversion would give that those decide",
                            "what a conversion would take: files, directories and streams; bytes that stay in place and bytes that are copied; working storage and memory at least; time, from the lab's runs",
                        ],
                        "decided_only_when_frozen": ntfs2refs::drive_cli::CHECK_DECIDED_WHEN_FROZEN,
                        "exit_codes": {
                            "0": "nothing was found that a conversion refuses",
                            (ntfs2refs::drive_cli::EXIT_CHECK_REFUSALS.to_string()):
                                "a conversion would refuse the volume; each reason is printed",
                            (ntfs2refs::drive_cli::EXIT_CHECK_INCONCLUSIVE.to_string()):
                                "the volume changed during every reading: nothing is known and nothing is refused",
                            "1": "the check could not be made",
                        },
                    },
                    "diagnose": {
                        "option": "--diagnose",
                        "ntfs2refs_writes_to_source": false,
                        "exit_codes": {
                            "0": "every object was examined and none failed",
                            (ntfs2refs::drive_cli::EXIT_DIAGNOSE_FAILURES.to_string()):
                                "failures were reported, or the run stopped at its failure limit",
                            "1": "the diagnosis could not finish",
                        },
                        "refuses": diagnose_refuses,
                        "also_refuses": "a partition that a conversion would first shrink",
                        "failure_limit": {"option": "--diagnose-limit", "default": 500, "zero_means": "no limit"},
                    },
                    "verification_modes": [
                        {"option": null, "name": "extent identity (default)",
                         "changes": "data that stays in place is proven by the identity of its extents; everything else is read and checksummed"},
                        {"option": "--verify-full-content", "name": "full content",
                         "changes": "what is checked: every stream's complete contents are read and hashed"},
                        {"option": "--recheck-everything", "name": "repeated re-reads",
                         "changes": "how often, not what: full re-reads at every checkpoint instead of once before the first source write"},
                    ],
                    "listing_comparison": {
                        "tool": "lab-volume-manifest",
                        "accepted_differences": n2r_win32::volume_manifest::ALLOWED_DIFFERENCES,
                        "short_names": "each NTFS 8.3 name must be a same-directory link to its long name",
                    },
                    "experimental_large_tree": {
                        "available": cfg!(windows),
                        "maximum_files": large.maximum_files,
                        "maximum_directories": large.maximum_directories,
                        "maximum_logical_bytes": large.maximum_logical_bytes,
                        "native_qualified": false,
                    },
                    // What the lab showed of this route, and what it did not.
                    "lab_evidence": {
                        "feature_matrix": "docs/feature-matrix.md",
                        "recovery_matrix": "docs/recovery-matrix.md",
                        "guide": "docs/cli-workflow.md",
                        "grants_runtime_authority": false,
                        "not_shown": [
                            "a physical disk: every lab disk is virtual",
                            "a volume holding more than 23 GB",
                            "a power cut to the storage itself: the lab ends the converter's process or turns the virtual machine off",
                            "a Windows build other than those in windows_builds.confirmed_builds, and a ReFS version other than 3.14",
                            "a conversion to standard ReFS on Windows 11 (the lab's does not format one), a Windows boot volume of Windows Server, and Windows 11 on build 26100",
                            "--minimize-scratch, and the routes and commands that --help does not list",
                        ],
                    },
                    // The registry of 2026-10-28 records builds before 0.2.0.
                    // Its schema has fixed limits per profile and no entry
                    // for a boot volume or a data volume as they are now, so
                    // it is counted here and no longer printed.
                    "earlier_builds": {
                        "registry": "evidence/qualification-registry.json",
                        "scope": registry.scope,
                        "profiles": registry.profiles.len(),
                        "evidence_records": registry.evidence.len(),
                        "claims": registry.claims.len(),
                        "documents": "docs/history",
                        "note": "observations of builds before 0.2.0, kept as they were recorded; they are not statements about this executable",
                    },
                }),
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
