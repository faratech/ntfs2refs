use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::{fs::OpenOptions, io::Write, path::Path, process::ExitCode};

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
refuses.";

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
/// `capabilities` is the one subcommand. The research tools for raw images
/// and the request-file commands of earlier designs were removed with 0.0.1;
/// the tag `archive/hidden-routes` keeps them.
#[derive(Subcommand)]
enum Command {
    /// Print, as JSON, what this executable admits, refuses and does not carry over.
    Capabilities,
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
fn run() -> Result<u8> {
    let cli = Cli::parse();
    if cli.drive.requested() {
        return ntfs2refs::drive_cli::run(cli.drive);
    }
    match cli
        .command
        .context("use --list, --drive, or a subcommand")?
    {
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
                        {"route": "restart", "option": "--restart-media", "in_help": true,
                         "status": "a data partition on the GPT disk of the running Windows: prepared in Windows, converted after a restart into a minimal Windows made from installation media, by ntfs2refs-recovery.exe; working storage on NTFS on another disk; converted, and cancelled before the conversion started in Windows and in the minimal Windows, in the lab on Windows Server 2025"},
                    ],
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
                        "disk_layout": "a disk other than the running Windows': a GPT disk, or an MBR disk on which the volume is a primary partition; either may hold other partitions; --list says for each NTFS partition whether it qualifies",
                        "other_partitions_on_the_disk": {
                            "allowed": true,
                            "during_the_run": "the whole disk is offline: their volumes are dismounted first, are unavailable until the run ends, and are not written to",
                            "after_an_interruption": "they stay offline with the disk until --recover finishes or undoes the run",
                            "refused_when": ["the running Windows has a page file or its crash-dump file on the disk, or its boot or system partition",
                                             "a volume beside the source has shadow copies or stores those of another volume",
                                             "a program has a file open on a volume beside the source (found when the run locks it, not by --check)",
                                             "the source holds an installed Windows and the disk has an EFI system partition: --windows-boot-volume is for that",
                                             "the source holds an installed Windows and the disk is MBR: it would no longer start, and --windows-boot-volume takes a GPT disk only"],
                        },
                        "requires": ["administrator rights, checked before a disk is opened",
                                     "the Windows build, checked before a disk is opened"],
                        "not_carried_over": [
                            {"what": "object IDs of files and directories, which Windows gives to the targets of shortcuts",
                             "why": "ReFS has no object IDs",
                             "record": "each is matched with the volume's object-ID index and kept in the run's records; their number is printed"},
                            {"what": "the NTFS compression flag", "why": "compressed data is stored as ordinary data on ReFS"},
                            {"what": "the change journal", "why": "the converted volume starts a new one"},
                            {"what": "the case-sensitive mark of a directory in which no two names differ only by case, except where case_sensitive_mark.set_on lists the running Windows",
                             "why": "the converter does not set it on the new volume; every name stays reachable",
                             "record": "the directories are kept in the run's records, and their number and the reason are printed before the prompt"},
                        ],
                        // A directory's case-sensitive mark: where it is
                        // set on the new volume, and where it is not.
                        "case_sensitive_mark": {
                            "set_on": n2r_win32::windows_build::CASE_MARK_BUILDS
                                .iter()
                                .map(|shown| serde_json::json!({
                                    "windows": shown.name, "build": shown.build, "server_edition": shown.server,
                                }))
                                .collect::<Vec<_>>(),
                            "how": "every directory of the new volume is made with the mark its source directory has, the mark is read back, and a directory whose mark differs afterwards fails the run",
                            "not_set": ["on any other Windows: Windows 11 build 26300 stops with a bugcheck when a ReFS volume holding a marked directory is taken offline, which a conversion does with the volume it builds",
                                        "in a recovery or installation environment",
                                        "on a volume whose root directory is itself marked: the new root is never empty when its mark could be set, so no mark is set on that volume",
                                        "on a volume that holds a Windows (--windows-boot-volume, and the running Windows)",
                                        "on a partition of the running Windows disk, which is converted through a restart"],
                            "the_run_says": "before the prompt, and --check: how many directories are marked, whether the mark is set, and where it is not, why",
                            "two_names_that_differ_only_by_case": "refused everywhere, with both names",
                        },
                        "refused_by_name": [
                            {"what": "8.3 short names", "remedy": "fsutil 8dot3name strip, then fsutil 8dot3name set <drive>: 1",
                             "or": "--short-names drop converts without them: every object under its long name, each short name kept in the run's records"},
                            {"what": "a BitLocker-encrypted volume", "remedy": "decrypt it (manage-bde -off)"},
                            {"what": "shadow copies of the volume, snapshot storage kept on it, or a shadow-copy provider of backup software that holds a shadow copy on the machine or does not answer",
                             "remedy": "delete the shadow copies; the provider is named",
                             "passed_over": "a provider of backup software that answers and holds no shadow copy, named in a note: make a full backup afterwards"},
                            {"what": "EFS-encrypted files", "remedy": "cipher /d"},
                            {"what": "files with the TEMPORARY or OFFLINE attribute"},
                            {"what": "reparse points other than symbolic links, junctions, app execution aliases and the files of the Windows Subsystem for Linux (Data Deduplication, compact /exe, cloud placeholders)",
                             "remedy": "named per kind"},
                            {"what": "a named data stream on a directory"},
                            {"what": "disk quotas in use", "remedy": "fsutil quota disable"},
                            {"what": "two names in one directory that differ only by case", "remedy": "rename one of them, then fsutil file setCaseSensitiveInfo <directory> disable"},
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
                        "also_made_by": "every conversion and diagnose run of a data volume, before it asks, before the partition is shrunk and before the disk is taken offline",
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
                        "also_refuses": "a Windows boot volume that a conversion would first shrink",
                        "on_a_data_volume_to_shrink": "makes the read-only check of --check alone, and says so: a diagnosis never shrinks",
                        "failure_limit": {"option": "--diagnose-limit", "default": 500, "zero_means": "no limit"},
                    },
                    "review": {
                        "option": "--review",
                        "stops": "before the handoff: every new byte written, flushed and read back, the converted volume mounted read-only as ReFS",
                        "then": {"commit": "--recover <dir> --recovery-sha256 <sum>",
                                 "roll_back": "--recover <dir> --recovery-sha256 <sum> --rollback"},
                        "refuses_both_once_writable": true,
                        "restored_ntfs_held_to_source_fingerprint": true,
                        "for": "a data volume on a disk of its own",
                        "refused_with": ["--windows-boot-volume", "--restart-media", "--check", "--diagnose", "--compare-listing", "--minimize-scratch", "a partition on the running Windows disk", "a disk with other partitions"],
                        "lab_evidence": false,
                    },
                    "verification_modes": [
                        {"option": "--verify fast", "name": "fast, extent identity (default)",
                         "changes": "data that stays in place is proven by the identity of its extents; everything else is read and checksummed",
                         "checks_once": {
                             "unless": ["--recheck-everything", "--diagnose"],
                             "never_verifies_once": ["--verify thorough", "--recheck-everything", "--diagnose", "--recover (a resumed preparation, an interrupted apply, a finalization)", "a partition on the running Windows disk", "--check"],
                             "why_not_a_diagnosis": "it stops before the new volume is examined, where a conversion makes the checks it leaves out earlier",
                             "leaves_out": [
                                 "reading through Windows the contents of plain source streams (one non-resident DATA attribute of a user file, not assembled from an attribute list, uncompressed, unsparse, initialized to its end, every run on disk): their raw checksum is a straight read of the clusters their run list names, and that run list is held to Windows' retrieval pointers",
                                 "reading the new volume's payloads back a second time before the changes are captured",
                                 "reading the new volume's restored metadata back before it is frozen",
                                 "listing the new volume's directories a second time after its metadata is restored",
                                 "the second probe of each short-name link on the converted volume",
                             ],
                             "source_still_checked_through_windows": "every object's metadata snapshot (times, attributes, both security views, extended attributes, reparse point, case mark); its streams' names, sizes and allocation; each non-resident stream's retrieval pointers, held to the raw run list; each stream's identity and end of file through an open read handle; for a plain stream whose contents are not read, that its valid data runs to its end; the contents of every stream that is neither proven by its extents (kept in place) nor plain: resident, compressed, sparse, partly initialized, assembled from an attribute list, system and every other copied stream; every directory listing",
                             "not_confirmed_through_windows_for_a_plain_stream": "its flags and compression unit, which with its valid data length make it plain, are taken from the raw reading; Windows confirms where it lies, its sizes, identity and end of file, and that its valid data runs to its end (FSCTL_QUERY_FILE_REGIONS, without reading it; a plain stream it does not say that of is read through Windows), not those two fields",
                             "a_cut_off_preparation": "is not resumed where its fast run left plain streams unread through Windows, since a resumed run does not verify once: such a run writes no resume checkpoint and says so once it has read the source, and a cut-off one is cancelled with the --rollback command it printed at its start and started again",
                             "still_runs": "the examination of the frozen new volume that the changes are captured from, and the full verification of the converted volume after they are written",
                         }},
                        {"option": "--verify thorough", "name": "thorough, full content",
                         "also_accepted": "--verify-full-content",
                         "changes": "what is checked: every stream's complete contents are read and hashed"},
                        {"option": "--recheck-everything", "name": "repeated re-reads",
                         "changes": "full re-reads at every checkpoint instead of once before the first source write, and with --verify fast every check that checks_once leaves out is made: Windows reads the contents of every source stream its extents do not prove, the new volume is read back before the changes are captured and its short-name links are probed twice"},
                    ],
                    "listing_comparison": {
                        "tool": "lab-volume-manifest",
                        "by_the_run": {
                            "option": "--compare-listing",
                            "does": "lists the volume before the conversion and after it with the tool's own code, compares the two, prints the result and keeps both listings and the report in the run's records",
                            "costs": "two full reads of the volume",
                            "exit_codes": {
                                "0": "the volume lists as it did before",
                                (ntfs2refs::drive_cli::EXIT_LISTING_DIFFERS.to_string()):
                                    "the conversion completed and the listings differ, or the second listing could not be made",
                            },
                        },
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
                            "--minimize-scratch",
                            "the restart route (--restart-media) on Windows 11, on a physical machine, with BitLocker on the Windows volume, and interrupted while it converts",
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
    }
    Ok(0)
}
fn main() -> ExitCode {
    // Before anything else, whatever was asked: see DISCLAIMER.md.
    ntfs2refs::disclaimer::print();
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
