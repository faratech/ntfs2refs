//! Drive-oriented interactive entry. Listing and declining never stage or freeze.
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::PathBuf;

#[cfg(windows)]
#[path = "drive_boot.rs"]
mod boot;
#[cfg(windows)]
#[path = "drive_listing.rs"]
mod listing;
#[cfg(windows)]
#[path = "drive_partition.rs"]
mod partition;
#[cfg(windows)]
#[path = "drive_precheck.rs"]
mod precheck;
#[cfg(windows)]
#[path = "drive_resource.rs"]
mod resource;
#[cfg(windows)]
#[path = "drive_staging.rs"]
mod staging;

#[derive(Args, Debug)]
pub struct DriveArgs {
    /// Show the disks and partitions, and for each NTFS partition whether
    /// it can be converted and, if not, why.
    #[arg(long, conflicts_with_all = ["drive", "partition", "scratch_directory", "recover", "recovery_sha256", "rollback"])]
    pub list: bool,
    /// The volume to convert: a drive letter, or a disk number with
    /// --partition. Also accepts --drive D partition 2.
    #[arg(long, num_args = 1..=3, value_name = "DRIVE", conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback"])]
    pub drive: Option<Vec<String>>,
    /// Exact partition number. A letter must already identify that partition.
    #[arg(long, requires = "drive")]
    pub partition: Option<u32>,
    /// The serial number of the volume that is meant, as --list and `vol`
    /// print it (1A2B-3C4D). A run on a volume with another serial number is
    /// refused before anything is opened. Required with --yes.
    #[arg(long, requires = "drive", value_name = "XXXX-XXXX", value_parser = crate::confirmation::parse_volume_serial)]
    pub volume_serial: Option<u32>,
    /// Answer every question of this run with yes, for a script. A conversion
    /// or a diagnose run also needs --volume-serial, so that a wrong drive
    /// letter is refused instead of converted; a recovery is already bound to
    /// its run by its checksum.
    #[arg(long, conflicts_with = "list")]
    pub yes: bool,
    /// Working directory for the run's temporary virtual disk and recovery
    /// files, on a different disk from the volume. Keep it until the
    /// conversion has finished.
    #[arg(long, requires = "drive")]
    pub scratch_directory: Option<PathBuf>,
    /// For a data partition on the disk of the running Windows, which cannot
    /// be converted while Windows runs: Windows installation media of this
    /// Windows' language (a mounted ISO, a DVD, a USB stick; its drive or
    /// directory). The run prepares everything in Windows, restarts the
    /// machine into a minimal Windows made from that media, converts the
    /// partition there and returns to Windows. --scratch-directory has to be
    /// on an NTFS volume of another disk, which stays connected until
    /// Windows is back. Needs ntfs2refs-recovery.exe beside ntfs2refs.exe.
    #[arg(
        long = "restart-media",
        alias = "offline-media",
        value_name = "DIR",
        requires = "drive"
    )]
    pub offline_recovery_media: Option<PathBuf>,
    /// For the Windows this machine runs (--drive C): the drive letter of a
    /// FAT32 partition on another disk (a USB stick will do, 100 MB or more)
    /// that the machine starts its recovery environment from. The disk a
    /// machine starts from cannot be taken offline, and the conversion takes
    /// the Windows disk offline. Keep it connected until Windows is back.
    #[arg(long, requires = "drive", value_name = "LETTER", value_parser = n2r_win32::drive_inventory::parse_drive_letter)]
    pub boot_partition: Option<char>,
    /// The volume is an installed Windows that is not running; the Windows
    /// that runs the converter is on another disk and is never converted.
    /// Admitted for the boot profiles `ntfs2refs capabilities` lists.
    #[arg(long, requires = "drive", conflicts_with = "offline_recovery_media")]
    pub windows_boot_volume: bool,
    /// How Windows formats the new file system: dev-drive or standard. The
    /// default is standard on Windows Server and dev-drive elsewhere.
    /// Standard works only where Windows itself formats ordinary ReFS
    /// volumes; there is no fallback from one to the other.
    #[arg(long, requires = "drive", value_parser = ["dev-drive", "standard"])]
    pub target_format: Option<String>,
    /// What to do with the 8.3 short names of a data volume, which ReFS
    /// does not have: `refuse` the volume (the default), with the commands
    /// that remove them; or `drop` them, converting with every object under
    /// its long name and the short names kept in the run's records. A
    /// program that stored a path in its short form no longer finds it.
    #[arg(long, requires = "drive", value_parser = ["refuse", "drop"], conflicts_with_all = ["windows_boot_volume", "recover", "list"])]
    pub short_names: Option<String>,
    /// Allocation unit of the ReFS target in bytes: 4096 (default) or 65536.
    /// Data stays where it is only if it lies on boundaries of this size, so
    /// 65536 suits a source with clusters of 64 KiB or larger; from smaller
    /// clusters most data is copied through the working storage instead.
    #[arg(long, requires = "drive", value_parser = ["4096", "65536"])]
    pub target_cluster_bytes: Option<String>,
    /// Finish an interrupted run from its conversion directory, as printed
    /// in its "To recover:" line. With --rollback, undo it instead.
    // (The checksum is asked for where the directory is read: the folder of
    // a run that restarts the machine is recognised by its own records and
    // takes none.)
    #[arg(long, conflicts_with_all = ["list", "drive", "partition", "scratch_directory"])]
    pub recover: Option<PathBuf>,
    /// Used by the recovery environment that converting the running Windows
    /// restarts into: runs that conversion from its session file.
    #[arg(long, hide = true, conflicts_with_all = ["list", "drive", "recover"])]
    pub running_windows_session: Option<PathBuf>,
    /// The checksum printed with that directory (the SHA-256 of its
    /// recovery-envelope.json), or the preparation SHA-256 printed at the
    /// start of a run that had not yet written to the volume.
    #[arg(long, requires = "recover")]
    pub recovery_sha256: Option<String>,
    /// Continue prepublication preparation on a different independent local
    /// volume. Saved source evidence and the existing shadow are reused.
    #[arg(long, requires = "recover", conflicts_with = "rollback")]
    pub resume_workspace: Option<PathBuf>,
    /// With --recover: put the NTFS volume back as it was, or cancel a
    /// preparation that had not finished. Possible until the handoff only.
    #[arg(long, requires = "recover")]
    pub rollback: bool,
    /// Read and hash the complete contents of every stream. By default,
    /// data that stays in place is proven by the identity of its extents and
    /// only the rest is read. Slower. This changes what is checked.
    #[arg(long, requires = "drive")]
    pub verify_full_content: bool,
    /// Experimental: reduce the working storage by not saving what unused
    /// NTFS space holds, so a rollback does not restore it. It first moves
    /// files on the volume through NTFS; those moves are not undone if the
    /// run stops later. Refused with --verify-full-content and on a volume
    /// with shadow copies.
    #[arg(long, requires = "drive", conflicts_with = "verify_full_content")]
    pub minimize_scratch: bool,
    /// Check the volume while it stays online: nothing is frozen, formatted
    /// or written. Prints every refusal a conversion would give that the
    /// volume's NTFS structures and shadow copies decide, and what a
    /// conversion would take in working storage, memory and time. For a
    /// data volume. Exit 0: nothing found; 3: a conversion would refuse;
    /// 5: the volume kept changing while it was read, so nothing is known.
    #[arg(long, requires = "drive", conflicts_with_all = [
        "list", "recover", "rollback", "diagnose", "yes",
        "windows_boot_volume", "minimize_scratch",
        "offline_recovery_media", "controlled_post_flush_pause_nonce",
        "acknowledge_controlled_post_flush_pause", "lab_hold_at",
    ])]
    pub check: bool,
    /// Check without converting: build the ReFS shadow, report every
    /// per-object failure instead of stopping at the first, then stop before
    /// anything is published. ntfs2refs writes nothing to the source. Exit 0:
    /// no failures; 3: failures reported. Where a conversion would first
    /// shrink the partition, a data volume gets the read-only check of
    /// --check alone and a Windows boot volume is refused. Not with
    /// --minimize-scratch.
    #[arg(long, requires = "drive", conflicts_with_all = [
        "list", "recover", "rollback", "minimize_scratch",
        "offline_recovery_media", "controlled_post_flush_pause_nonce",
        "acknowledge_controlled_post_flush_pause",
    ])]
    pub diagnose: bool,
    /// How many failures --diagnose lists before it stops (default 500);
    /// 0 lists every failure on the volume.
    #[arg(long, requires = "diagnose")]
    pub diagnose_limit: Option<usize>,
    /// List the volume before the conversion and after it, compare the two
    /// and keep both with the run's records: every file's contents, streams,
    /// links, times, attributes, security, reparse points and extended
    /// attributes, as the lab compares every conversion it runs. Two full
    /// reads of the volume. Exit 6 when the listings differ.
    #[arg(long, requires = "drive", conflicts_with_all = ["list", "recover", "rollback", "check", "diagnose"])]
    pub compare_listing: bool,
    /// Re-read every working file and the whole source at every checkpoint
    /// instead of once, immediately before the first write to the source.
    /// Much slower; the result is the same. This changes how often things
    /// are checked, not what.
    #[arg(long, requires = "drive", conflicts_with_all = ["list", "recover", "rollback"])]
    pub recheck_everything: bool,
    /// A ceiling on the memory the run may use, in MiB. Without it a run
    /// fits itself to the machine: it takes up to two thirds of the memory
    /// that is free when it starts and, where a volume needs more, goes on
    /// with the page file and is slower. With a limit it never goes beyond
    /// it: --check says what a volume needs at least, and a limit below
    /// that is refused before anything is built. Give a recovery the limit
    /// too if it should keep to one.
    #[arg(long, value_name = "MIB", conflicts_with = "list", value_parser = clap::value_parser!(u64).range(256..=16_777_216))]
    pub memory_limit: Option<u64>,
    /// Laboratory: sample the worker's call stack a hundred times a second
    /// and write the profile to this file. Needs the .pdb beside the executable.
    #[arg(long, hide = true, value_name = "FILE")]
    pub sample_stacks: Option<PathBuf>,
    /// Qualification-only bounded wait after actual source flush/readback.
    #[arg(long, hide = true, value_parser = parse_controlled_pause_nonce,
        requires_all = ["drive", "acknowledge_controlled_post_flush_pause"],
        conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback"])]
    pub controlled_post_flush_pause_nonce: Option<String>,
    /// Separate acknowledgement for shared-partition qualification control.
    #[arg(long, hide = true,
        requires_all = ["drive", "controlled_post_flush_pause_nonce"],
        conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback"])]
    pub acknowledge_controlled_post_flush_pause: bool,
    /// Laboratory: stop for ever at a named point of apply or handoff, so
    /// that recovery can be exercised from there. The run never completes.
    #[arg(long, hide = true, value_name = "POINT",
        requires_all = ["drive", "acknowledge_lab_hold_never_completes"],
        conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback", "diagnose"])]
    pub lab_hold_at: Option<String>,
    /// Laboratory: separate acknowledgement that a held run never completes.
    #[arg(long, hide = true, requires = "lab_hold_at")]
    pub acknowledge_lab_hold_never_completes: bool,
    /// Laboratory: make a run that restarts the machine fail at a named
    /// point, so that each way back from there can be exercised.
    #[arg(long, hide = true, value_name = "POINT",
        requires_all = ["drive", "offline_recovery_media", "acknowledge_lab_fail_stops_the_run"],
        conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback", "diagnose", "check", "lab_hold_at"])]
    pub lab_fail_at: Option<String>,
    /// Laboratory: separate acknowledgement that such a run does not convert.
    #[arg(long, hide = true, requires = "lab_fail_at")]
    pub acknowledge_lab_fail_stops_the_run: bool,
}
fn parse_controlled_pause_nonce(value: &str) -> std::result::Result<String, String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(value.to_owned())
    } else {
        Err("controlled pause requires an independently chosen64-character lowercase hexadecimal nonce".into())
    }
}
/// Exit code of a diagnose run that completed and reported failures.
pub const EXIT_DIAGNOSE_FAILURES: u8 = 3;
/// What a check cannot say, because only the frozen source shows it: in the
/// words of its report.
pub const CHECK_DECIDED_WHEN_FROZEN: &str = "that the NTFS log closes cleanly, the backup boot sector and the MFT mirror, an open transaction, whether quota management is switched on, and that Windows shows every file as the raw volume holds it";
/// GPT partition types a run names: an EFI system partition, and the
/// reserved partition that holds no volume.
#[cfg_attr(not(windows), allow(dead_code))]
const EFI_SYSTEM_PARTITION: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
#[cfg_attr(not(windows), allow(dead_code))]
const RESERVED_PARTITION: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
/// Why a volume that holds an installed Windows on an MBR disk it shares
/// with other partitions is not converted as a data volume.
#[cfg_attr(not(windows), allow(dead_code))]
const MBR_INSTALLED_WINDOWS: &str = "holds an installed Windows (Windows\\System32\\ntoskrnl.exe) on an MBR disk it shares with other partitions. Converted as a data volume it would no longer start, and the converter starts an installed Windows only from a GPT disk (--windows-boot-volume)";
/// Exit code of `--check` when it found something a conversion would refuse.
pub const EXIT_CHECK_REFUSALS: u8 = 3;
/// Exit code of `--check` when the volume changed during every reading:
/// nothing is known of it, and nothing is refused.
pub const EXIT_CHECK_INCONCLUSIVE: u8 = 5;
/// Exit code of a conversion with `--compare-listing` that completed and
/// whose volume does not list afterwards as it did before.
pub const EXIT_LISTING_DIFFERS: u8 = 6;
/// Exit code of `--list` when some disk or volume could not be queried: what
/// was printed is a partial list and must not be read as the whole machine.
pub const EXIT_LIST_INCOMPLETE: u8 = 4;

/// What `--list` exits with, from whether the inventory covered every device.
pub(crate) fn list_exit_code(enumeration_complete: bool) -> u8 {
    if enumeration_complete {
        0
    } else {
        EXIT_LIST_INCOMPLETE
    }
}

/// The question asked before anything is started. A diagnose run is not a
/// conversion and is not confirmed as one.
#[cfg_attr(not(windows), allow(dead_code))]
fn confirmation_prompt(mode: crate::execution_mode::ExecutionMode) -> &'static str {
    match mode {
        crate::execution_mode::ExecutionMode::Convert => {
            "Convert this partition to ReFS in place, preserving supported files? [y/N]"
        }
        crate::execution_mode::ExecutionMode::Diagnose => {
            "Diagnose this partition without converting it? It is taken offline and read-only meanwhile, is not written to by ntfs2refs, and is returned as NTFS. [y/N]"
        }
    }
}

impl DriveArgs {
    pub fn requested(&self) -> bool {
        self.list
            || self.drive.is_some()
            || self.recover.is_some()
            || self.running_windows_session.is_some()
    }

    /// What `--diagnose` cannot be combined with, and why. Diagnose never
    /// changes the source; each of these would, or has no diagnose stop.
    pub const DIAGNOSE_REFUSES: &'static [(&'static str, &'static str)] = &[
        (
            "--minimize-scratch",
            "it moves files on the source before preparation starts",
        ),
        (
            "--restart-media",
            "that route arms a restart into the conversion",
        ),
        (
            "--controlled-post-flush-pause-nonce",
            "it controls a run that writes to the source",
        ),
        (
            "--acknowledge-controlled-post-flush-pause",
            "it controls a run that writes to the source",
        ),
        ("--lab-hold-at", "it stops a run that writes to the source"),
    ];

    /// `--yes` answers the question that names the volume, so it is taken
    /// only with something else that names it: the volume's serial number
    /// for a conversion or a diagnose run, the checksum for a recovery.
    pub(crate) fn unattended(&self) -> Result<bool> {
        ensure!(
            !self.yes || self.recover.is_some() || self.volume_serial.is_some(),
            "--yes needs --volume-serial: the serial number of the volume to convert, as `ntfs2refs --list` prints it. Nothing was changed."
        );
        Ok(self.yes)
    }

    /// Decides once, before anything is opened, whether this run converts or
    /// only diagnoses, and refuses a diagnose it could not honour. The parser
    /// rejects the same combinations; this holds whatever built the arguments.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn execution_mode(&self) -> Result<crate::execution_mode::ExecutionMode> {
        use crate::execution_mode::ExecutionMode;
        if !self.diagnose {
            return Ok(ExecutionMode::Convert);
        }
        ensure!(
            self.drive.is_some() && !self.list && self.recover.is_none() && !self.rollback,
            "--diagnose applies only to a --drive selection"
        );
        // In the order of DIAGNOSE_REFUSES; a test sets each field in turn
        // and checks that the refusal names its flag.
        let requested = [
            self.minimize_scratch,
            self.offline_recovery_media.is_some(),
            self.controlled_post_flush_pause_nonce.is_some(),
            self.acknowledge_controlled_post_flush_pause,
            self.lab_hold_at.is_some(),
        ];
        for ((flag, reason), requested) in Self::DIAGNOSE_REFUSES.iter().zip(requested) {
            ensure!(
                !requested,
                "--diagnose cannot be combined with {flag}: {reason}. Nothing was changed."
            );
        }
        Ok(ExecutionMode::Diagnose)
    }
}
pub fn run(args: DriveArgs) -> Result<u8> {
    #[cfg(windows)]
    {
        // Windows executables normally reserve only 1 MiB for the main
        // thread. The paged metadata inspectors have nested bounded decode
        // frames; keep them on an explicitly sized worker instead of changing
        // the frozen executable entrypoint or every dependency's link flags.
        if let Some(output) = &args.sample_stacks {
            n2r_win32::stack_sampler::start(output.clone());
        }
        crate::panic_report::install();
        // Says once if Windows' drive optimization runs during a conversion (#132).
        if args.drive.is_some() || args.recover.is_some() {
            n2r_win32::maintenance_watch::start();
        }
        std::thread::Builder::new()
            .name("ntfs2refs-drive".to_owned())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let result = windows::run(args);
                n2r_win32::perf::finish();
                result
            })
            .context("could not create the drive worker stack")?
            .join()
            .map_err(|panic| {
                crate::panic_report::worker_error(
                    "ntfs2refs-drive",
                    panic,
                    "preserve its recovery records",
                )
            })?
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        anyhow::bail!("drive selection and conversion require Windows")
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use n2r_win32::{
        discovery::{self, Role},
        drive_inventory::{self, DriveInventory},
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{BufRead, Read, Write},
        time::{SystemTime, UNIX_EPOCH},
    };
    fn clean(value: &str) -> String {
        value
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect()
    }
    fn size(bytes: Option<u64>) -> String {
        bytes
            .map(|n| format!("{:.2} GiB", n as f64 / 1073741824.0))
            .unwrap_or_else(|| "unknown".into())
    }
    fn list(inventory: &DriveInventory) {
        println!("DISK  PART  DRIVE/MOUNT       FILESYSTEM  SIZE          LABEL / STATUS");
        for disk in &inventory.disks {
            println!(
                "Disk {}: {} ({}){}{}",
                disk.disk_number,
                clean(&disk.device_path),
                size(disk.size_bytes),
                if disk.offline == Some(true) {
                    " [offline]"
                } else {
                    ""
                },
                if disk.read_only == Some(true) {
                    " [read-only]"
                } else {
                    ""
                }
            );
            for part in &disk.partitions {
                let mounts = if part.mount_paths.is_empty() {
                    "-".into()
                } else {
                    part.mount_paths
                        .iter()
                        .map(|p| clean(p))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let mut notes = Vec::new();
                // Whether a conversion would take it, and why not: what a
                // run would otherwise say only after it had started.
                let conversion = drive_inventory::conversion_note(disk, part);
                if part.contains_running_windows == Some(true) && conversion.is_none() {
                    notes.push(
                        "running Windows: converts through a restart into its recovery environment (--drive, --scratch-directory)"
                            .into(),
                    );
                }
                if part.offline == Some(true) {
                    notes.push("offline".into());
                }
                if part.read_only == Some(true) {
                    notes.push("read-only".into());
                }
                if let Some(note) = conversion {
                    notes.push(clean(&note));
                } else if let Some(reason) = &part.unsupported_reason {
                    notes.push(clean(reason));
                }
                if let Some(serial) = part.volume_serial {
                    notes.push(format!(
                        "serial {}",
                        crate::confirmation::format_volume_serial(serial)
                    ));
                }
                if let Some(name) = &part.gpt_name {
                    if !name.is_empty() {
                        notes.push(clean(name));
                    }
                }
                println!(
                    "{:>4}  {:>4}  {:<16}  {:<10}  {:>12}  {}{}",
                    disk.disk_number,
                    part.partition_number,
                    mounts,
                    part.filesystem.as_deref().unwrap_or("-"),
                    size(part.size_bytes),
                    clean(part.label.as_deref().unwrap_or("")),
                    if notes.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", notes.join("; "))
                    }
                );
            }
            for e in &disk.errors {
                eprintln!(
                    "Disk {}: {}: {}",
                    disk.disk_number,
                    clean(&e.operation),
                    clean(&e.message)
                );
            }
        }
        for e in &inventory.errors {
            eprintln!("Inventory: {}: {}", clean(&e.operation), clean(&e.message));
        }
        for v in &inventory.volumes {
            // Named by its letter too, where it has one: a volume name is
            // a GUID nobody can place.
            let at = if v.mount_paths.is_empty() {
                String::new()
            } else {
                format!(" ({})", clean(&v.mount_paths.join(", ")))
            };
            for e in &v.errors {
                eprintln!(
                    "Volume {}{at}: {}: {}",
                    clean(&v.volume_guid_path),
                    clean(&e.operation),
                    clean(&e.message)
                );
            }
        }
        for root in &inventory.logical_drive_roots {
            if !inventory
                .disks
                .iter()
                .flat_map(|d| &d.partitions)
                .any(|p| p.mount_paths.iter().any(|m| m.eq_ignore_ascii_case(root)))
            {
                println!(
                    "   -     -  {:<16}  {:<10}  {:>12}  [{}]",
                    clean(root),
                    "-",
                    "-",
                    if n2r_win32::drive_inventory::optical_drive(root) {
                        "optical drive or disc image: not a disk volume"
                    } else {
                        "no basic partition mapping"
                    }
                );
            }
        }
        if !inventory.enumeration_complete {
            eprintln!(
                "Some devices could not be queried; see the inventory errors above. \
                 This list is incomplete (exit code {}).",
                super::EXIT_LIST_INCOMPLETE
            );
        }
    }
    fn save_new(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "drive-workflow artifact exceeds its bound"
        );
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        Ok(())
    }
    pub(super) fn ordinary_parents(path: &std::path::Path) -> Result<()> {
        use std::os::windows::fs::MetadataExt;
        let mut parents: Vec<_> = path.ancestors().collect();
        parents.reverse();
        for p in parents {
            if !p.exists() {
                fs::create_dir(p)
                    .with_context(|| format!("creating the working directory {}", p.display()))?;
            }
            let m = fs::symlink_metadata(p)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "scratch ancestry must be ordinary directories"
            );
        }
        Ok(())
    }

    /// One machine-readable line and a saved report. Exit 0 only when every
    /// object was examined and none failed.
    fn report_diagnosis(
        run: &std::path::Path,
        outcome: &crate::resource_preparation::DiagnoseOutcome,
        shadow_removed: bool,
    ) -> Result<u8> {
        let clean = outcome.failures.is_empty() && !outcome.stopped_at_limit;
        if let Err(error) = save_new(&run.join("diagnose-result.json"), outcome) {
            eprintln!("The diagnose report could not be saved: {error}");
        }
        println!(
            "{}",
            serde_json::json!({
                "kind": "diagnose-result-v1",
                "failures": outcome.failures.len(),
                "examined_all_objects": !outcome.stopped_at_limit,
                "source_disk": outcome.restored_disk_number,
                "ntfs2refs_wrote_to_source": false,
                "shadow_removed": shadow_removed,
            })
        );
        if clean {
            println!(
                "Diagnose complete: no per-object failures. The source is unchanged NTFS on disk {}.",
                outcome.restored_disk_number
            );
        } else {
            println!(
                "Diagnose complete: {} per-object failure(s) reported above{}. The source is unchanged NTFS on disk {}.",
                outcome.failures.len(),
                if outcome.stopped_at_limit {
                    "; it stopped at the failure limit before examining every object"
                } else {
                    ""
                },
                outcome.restored_disk_number
            );
        }
        println!("Working files: {}", run.display());
        Ok(if clean {
            0
        } else {
            super::EXIT_DIAGNOSE_FAILURES
        })
    }
    // Same bounded affirmative confirmation for both actual source scopes.
    pub(super) fn confirm(prompt: &str) -> Result<bool> {
        println!("{prompt}");
        print!("> ");
        Ok(crate::confirmation::answer()?)
    }
    /// The Windows this machine runs: prepared here, converted in its own
    /// recovery environment after a restart.
    fn running_windows_route(
        args: &DriveArgs,
        inventory: &drive_inventory::DriveInventory,
        selected: &drive_inventory::PartitionSelection,
        mode: crate::execution_mode::ExecutionMode,
    ) -> Result<u8> {
        ensure!(
            !args.check,
            "--check reads a volume that stays online; the running Windows is checked in its recovery environment, with --diagnose. Nothing was changed."
        );
        ensure!(
            !args.windows_boot_volume && args.offline_recovery_media.is_none(),
            "the running Windows converts through its own recovery environment: drop --windows-boot-volume and --restart-media. Nothing was changed."
        );
        let scratch = args.scratch_directory.as_deref().context(
            "the running Windows converts through a restart, and the run needs --scratch-directory on a volume of another disk that stays connected until Windows is back. Nothing was changed.",
        )?;
        let letter = selected
            .partition
            .mount_paths
            .iter()
            .find_map(|path| path.chars().next().filter(|c| c.is_ascii_alphabetic()))
            .context("the running Windows volume has no drive letter")?;
        ensure!(
            selected.partition.bitlocker != Some(true),
            "this Windows is on a BitLocker volume, which the recovery environment cannot read without its key: it is not converted. Nothing was changed."
        );
        let serial = selected
            .partition
            .volume_serial
            .map(crate::confirmation::format_volume_serial)
            .context("the volume's serial number could not be read")?;
        let boot = args.boot_partition.context(
            "the running Windows converts through its recovery environment, which the machine starts from a FAT32 partition on another disk: format one (a USB stick will do, 100 MB or more) and give its letter with --boot-partition. Nothing was changed.",
        )?;
        let root = format!("{}:\\", boot.to_ascii_uppercase());
        let boot_disk = inventory
            .disks
            .iter()
            .find(|disk| {
                disk.partitions.iter().any(|part| {
                    part.mount_paths
                        .iter()
                        .any(|path| path.eq_ignore_ascii_case(&root))
                })
            })
            .map(|disk| disk.disk_number)
            .with_context(|| format!("--boot-partition {boot}: is not a partition of a disk this machine lists. Nothing was changed."))?;
        ensure!(
            boot_disk != selected.disk_number,
            "--boot-partition {boot}: is on disk {boot_disk}, the Windows disk; it has to be on another disk, which can stay online while the Windows disk is offline. Nothing was changed."
        );
        let diagnose = matches!(mode, crate::execution_mode::ExecutionMode::Diagnose);
        println!(
            "{letter}: is the Windows this machine runs. It is converted in its own Windows Recovery Environment: this run stages that environment, restarts the machine into it, converts the volume there and starts Windows again from it.
The machine restarts, possibly more than once. Do not switch it off while the conversion runs; keep {} connected.",
            scratch.display()
        );
        let prompt = if diagnose {
            "Restart now to diagnose this Windows without converting it? [y/N]"
        } else {
            "Restart now to convert this Windows? [y/N]"
        };
        if !confirm(prompt)? {
            println!("Nothing was changed.");
            return Ok(0);
        }
        crate::running_windows::stage_and_restart(&crate::running_windows::Request {
            windows_drive: letter,
            volume_serial: serial,
            scratch_directory: scratch,
            diagnose,
            target_format: args.target_format.as_deref(),
            verify_full_content: args.verify_full_content,
            boot_volume: boot,
        })?;
        Ok(0)
    }
    /// Administrator rights, asked before a disk is opened. Without them the
    /// first device open failed, with an OS error and no advice.
    fn require_elevation(action: &str) -> Result<()> {
        ensure!(
            n2r_win32::run_environment::is_elevated()?,
            "{action} needs administrator rights: run ntfs2refs from an elevated terminal (\"Run as administrator\"). Nothing was changed."
        );
        Ok(())
    }
    /// The running Windows build, refused here when it is too old. It used to
    /// be found out when the frozen source's observations were checked,
    /// minutes into a run and with the disk offline.
    fn require_windows_build(action: &str) -> Result<[u32; 3]> {
        let version = n2r_win32::run_environment::windows_version()?;
        ensure!(
            n2r_win32::windows_build::supported(version),
            "this is Windows {}; {action} needs build {} or later (Windows 11 24H2, Windows Server 2025), the first whose formatter makes the ReFS it builds on. Nothing was changed.",
            n2r_win32::windows_build::describe(version),
            n2r_win32::windows_build::MINIMUM_BUILD
        );
        Ok(version)
    }
    pub(super) fn run(args: DriveArgs) -> Result<u8> {
        if let Some(session) = &args.running_windows_session {
            return crate::running_windows::run_session(session);
        }
        let mode = args.execution_mode()?;
        if args.unattended()? {
            crate::confirmation::assume_yes();
        }
        if args.short_names.as_deref() == Some("drop") {
            // Read where the volume is checked and where it is admitted.
            crate::short_name_disposition::drop_for_this_run();
        }
        if let Some(mib) = args.memory_limit {
            // Before anything reads how much memory is free.
            n2r_win32::resource_native::limit_memory(mib << 20)?;
        } else {
            // Nobody asked for a ceiling: where memory comes short the run
            // goes on with what Windows can give it, and does not stop.
            n2r_win32::resource_native::fit_memory_to_the_machine();
        }
        if mode == crate::execution_mode::ExecutionMode::Diagnose {
            // A backstop beneath the routes: nothing in this process may now
            // open a disk to raw writes.
            n2r_win32::forbid_raw_write_activation();
        }
        if args.check {
            // And beneath a check: no disk is opened to raw writes, and no
            // disk's offline or read-only state is changed at all.
            n2r_win32::forbid_raw_write_activation();
            n2r_win32::forbid_disk_state_changes();
        }
        if let Some(point) = &args.lab_hold_at {
            ensure!(
                args.acknowledge_lab_hold_never_completes,
                "a laboratory hold needs --acknowledge-lab-hold-never-completes"
            );
            // An unknown point is refused here, before anything is opened.
            n2r_win32::lab_hold::arm(point)?;
        }
        if let Some(point) = &args.lab_fail_at {
            ensure!(
                args.acknowledge_lab_fail_stops_the_run,
                "a laboratory failure point needs --acknowledge-lab-fail-stops-the-run"
            );
            ensure!(
                args.offline_recovery_media.is_some(),
                "laboratory failure points apply only to a run that restarts the machine (--restart-media)"
            );
            // An unknown point is refused here, before anything is opened.
            n2r_win32::lab_fail::arm(point)?;
        }
        if let Some(directory) = args.recover {
            // (Not the build: a recovery must run wherever its conversion did.)
            require_elevation("recovery")?;
            // The folder of a run that restarts the machine, recognised by
            // its admission record. Its ways back are bound to the run by
            // the records in it, not by a checksum.
            let named = if directory.is_absolute() {
                directory.clone()
            } else {
                std::path::absolute(&directory)
                    .with_context(|| format!("resolving the folder {}", directory.display()))?
            };
            if let Some(run) = crate::resource_partition_alpha::recognise_run(&named)? {
                ensure!(
                    args.recovery_sha256.is_none() && args.resume_workspace.is_none(),
                    "the run in {} is recovered by its folder alone: give neither --recovery-sha256 nor --resume-workspace. Nothing was changed.",
                    run.display()
                );
                return super::partition::recover_restart_run(&run, args.rollback);
            }
            let checksum = args.recovery_sha256.context(
                "--recover needs --recovery-sha256, the checksum printed with the conversion directory. Nothing was changed.",
            )?;
            let has_preparation = directory.join("preparation-intent.json").exists()
                || directory.join("resume-intent.json").exists();
            // A matching external pin selects the early-cancellation protocol,
            // even if a later publication exists. Only its actual paired state
            // and native owner can authorize cancellation; absence of an
            // envelope is never permission to clear source exclusion.
            if has_preparation
                && super::resource::preparation_intent_matches(&directory, &checksum)?
            {
                return super::resource::recover_preparation_in_workspace(
                    &directory,
                    &checksum,
                    args.rollback,
                    args.resume_workspace.as_deref(),
                );
            }
            if directory.join("recovery-envelope.json").exists() {
                ensure!(
                    args.resume_workspace.is_none(),
                    "published conversion recovery uses its original workspace"
                );
                return super::resource::recover(&directory, &checksum, args.rollback);
            }
            if has_preparation {
                // Preserve a bad/missing pin as a hard refusal in its selected
                // protocol. Do not fall back to a legacy recovery writer.
                return super::resource::recover_preparation_in_workspace(
                    &directory,
                    &checksum,
                    args.rollback,
                    args.resume_workspace.as_deref(),
                );
            }
            ensure!(
                args.resume_workspace.is_none(),
                "workspace continuation requires a pinned prepublication checkpoint"
            );
            if let Some(result) =
                super::partition::try_recover(&directory, &checksum, args.rollback)?
            {
                return Ok(result);
            }
            return crate::drive_recovery::run(&directory, &checksum, args.rollback);
        }
        let mut inventory = drive_inventory::inventory_drives_readonly()?;
        if args.list {
            // Windows reports a BitLocker volume as NTFS. What it is shows in
            // its first sector, which only an elevated process may read.
            if n2r_win32::run_environment::is_elevated().unwrap_or(false) {
                drive_inventory::annotate_bitlocker(&mut inventory);
            }
            list(&inventory);
            return Ok(super::list_exit_code(inventory.enumeration_complete));
        }
        let action = match mode {
            _ if args.check => "a check",
            crate::execution_mode::ExecutionMode::Convert => "a conversion",
            crate::execution_mode::ExecutionMode::Diagnose => "a diagnose run",
        };
        require_elevation(action)?;
        let windows = require_windows_build(action)?;
        let values = args.drive.as_ref().context("drive selection required")?;
        let drive = values.first().context("drive value required")?;
        // Chosen before anything is planned: every count of target clusters
        // in this process uses it.
        let target_cluster: u64 = args
            .target_cluster_bytes
            .as_deref()
            .unwrap_or("4096")
            .parse()
            .context("target cluster size")?;
        ensure!(
            target_cluster == n2r_win32::target_cluster::DEFAULT_BYTES
                || !(args.windows_boot_volume || args.offline_recovery_media.is_some()),
            "a {target_cluster}-byte ReFS allocation unit is for a data volume on the default route; a Windows boot volume and offline media use 4096"
        );
        n2r_win32::target_cluster::choose(target_cluster)?;
        let partition = match values.as_slice() {
            [_] => args.partition,
            [_, marker, number] => {
                ensure!(
                    marker.eq_ignore_ascii_case("partition")
                        || marker.eq_ignore_ascii_case("partiton"),
                    "use --drive D partition NUMBER or --partition NUMBER"
                );
                ensure!(args.partition.is_none(), "partition was specified twice");
                Some(
                    number
                        .parse::<u32>()
                        .context("partition number must be a positive integer")?,
                )
            }
            _ => anyhow::bail!("use --drive D or --drive DISK partition NUMBER"),
        };
        let selected = drive_inventory::resolve_selection(&inventory, drive, partition)?;
        if let Some(wanted) = args.volume_serial {
            // The volume that was meant, checked before anything is opened.
            let found = selected.partition.volume_serial;
            ensure!(
                found == Some(wanted),
                "--volume-serial {} does not name the volume at {}: {}. Nothing was changed.",
                crate::confirmation::format_volume_serial(wanted),
                clean(drive),
                match found {
                    Some(serial) => format!(
                        "its serial number is {}",
                        crate::confirmation::format_volume_serial(serial)
                    ),
                    None => "Windows gave no serial number for it".into(),
                }
            );
        }
        if args.check {
            return check(
                &args,
                &mut inventory,
                &selected,
                drive,
                target_cluster,
                windows,
            );
        }
        ensure!(
            selected.partition.filesystem.as_deref() != Some("ReFS"),
            "selected partition is already ReFS"
        );
        // The listing reads the volume as its files are opened, through a
        // drive letter, which the volume has again when it is converted.
        let listing_root = if args.compare_listing {
            Some(
                selected
                    .partition
                    .mount_paths
                    .iter()
                    .find(|path| {
                        path.len() == 3
                            && path.as_bytes()[0].is_ascii_alphabetic()
                            && path.ends_with(":\\")
                    })
                    .cloned()
                    .context(
                        "--compare-listing lists the volume through its drive letter, and this volume has none: give it one, or compare by hand with lab-volume-manifest. Nothing was changed.",
                    )?,
            )
        } else {
            None
        };
        if selected.partition.contains_running_windows == Some(true) {
            return running_windows_route(&args, &inventory, &selected, mode);
        }
        // Inventory is routing only. The partition path independently probes
        // actual source/GPT/current-Windows roles before any write admission.
        if !args.windows_boot_volume
            && inventory.disks.iter().any(|disk| {
                disk.disk_number == selected.disk_number
                    && disk.contains_running_windows == Some(true)
            })
        {
            ensure!(
                args.lab_hold_at.is_none(),
                "laboratory holds apply only to a dedicated or Windows boot source"
            );
            ensure!(
                target_cluster == n2r_win32::target_cluster::DEFAULT_BYTES,
                "a {target_cluster}-byte ReFS allocation unit is for a volume on a disk of its own; a partition on the running Windows disk uses 4096"
            );
            // This route has no diagnose stop; refuse before discovering anything.
            let authority = mode
                .source_change_authority("conversion of a partition on the running Windows disk")?;
            let before = discovery::discover(
                &selected.volume_guid_path,
                Role::Journal {
                    allow_additional_partitions: true,
                },
            )?;
            // That role also finds working storage, which may lie on an
            // MBR disk. A volume to convert may not.
            ensure!(
                !n2r_win32::mbr_layout::is_mbr_disk(&before.binding.identity.disk_guid),
                "the selected volume's disk is MBR, and the converter takes volumes on GPT disks only. Nothing was changed."
            );
            return super::partition::convert(&args, selected, before, &authority);
        }
        ensure!(
            args.controlled_post_flush_pause_nonce.is_none()
                && !args.acknowledge_controlled_post_flush_pause,
            "controlled post-flush qualification flags apply only to a data partition sharing the current Windows disk; dedicated conversion does not accept them"
        );
        ensure!(
            args.lab_fail_at.is_none(),
            "laboratory failure points apply only to a run that restarts the machine: a partition on the running Windows disk"
        );
        let source_role = if args.windows_boot_volume {
            Role::OfflineWindowsSource
        } else {
            Role::Source
        };
        let default_format = n2r_win32::managed_shadow::TargetFormatProfile::default_for(
            n2r_win32::run_environment::is_windows_server()?,
            args.windows_boot_volume,
        );
        let target_format = match args.target_format.as_deref() {
            Some(named) => named.parse()?,
            None => default_format,
        };
        if args.windows_boot_volume {
            ensure!(
                target_format.is_dev_drive(),
                "the demonstrated Windows boot profile uses the native Dev Drive target format"
            );
        }
        let before = discovery::discover(&selected.volume_guid_path, source_role)
            .map_err(|error| if error.raw_os_error() == Some(5) {
                anyhow::anyhow!("administrator access is required for conversion; run from an elevated Windows terminal: {error}")
            } else { anyhow::anyhow!("the selected volume's disk is not one a data volume is converted on: {error}") })?;
        ensure!(
            before.filesystem == "NTFS",
            "selected partition must currently be NTFS"
        );
        // A disk the volume shares with other partitions: what else is on
        // it, for the lines before the prompt. Refused here where the
        // volume is an installed Windows that would be left unable to start.
        let beside = if before.binding.layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::SharedData
        {
            let disk = inventory
                .disks
                .iter()
                .find(|disk| disk.disk_number == selected.disk_number)
                .context("the selected disk is no longer listed")?;
            let others: Vec<&drive_inventory::PartitionInventory> = disk
                .partitions
                .iter()
                .filter(|other| other.partition_number != selected.partition_number)
                .collect();
            let efi = others.iter().any(|other| {
                other
                    .partition_type_guid
                    .as_deref()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case(EFI_SYSTEM_PARTITION))
            });
            let installed = selected.partition.mount_paths.iter().any(|root| {
                std::path::Path::new(root)
                    .join("Windows\\System32\\ntoskrnl.exe")
                    .exists()
            });
            ensure!(
                !(efi && installed),
                "this volume holds an installed Windows (Windows\\System32\\ntoskrnl.exe) on a disk with an EFI system partition. Converted as a data volume it would no longer start. Convert it with --windows-boot-volume, which is admitted for the boot profiles `ntfs2refs capabilities` lists. Nothing was changed."
            );
            // An MBR disk has no EFI system partition: the Windows it holds
            // starts from the disk itself, and no route converts it.
            ensure!(
                !(installed && disk.partition_style.as_deref() == Some("MBR")),
                "this volume {MBR_INSTALLED_WINDOWS}. Nothing was changed."
            );
            Some(shared_disk_lines(selected.disk_number, &others))
        } else {
            None
        };
        // Decided from the partition length before anything is asked.
        // ReFS covers a volume in whole 64 MiB units, whatever the source
        // is: a partition that is not a multiple is first shrunk to one. A
        // diagnosis never shrinks: of a Windows boot volume it is refused
        // here, and of a data volume it is the read-only check below alone.
        let boot_geometry = {
            let partition_bytes = before.binding.identity.partition_bytes;
            let decision = super::boot::geometry_decision(partition_bytes)?;
            if args.windows_boot_volume {
                super::boot::admit_geometry(decision, partition_bytes, mode)?;
                super::boot::validate(&before.binding)?;
            }
            Some(decision)
        };
        let resources = crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(None);
        let mut events = Vec::new();
        // What the running Windows keeps on the volume's disk (a page file,
        // its crash dumps) refuses the disk before anything else is asked.
        let mut reader =
            n2r_win32::GeneralPartitionReader::open(before.binding.clone(), &mut events).map_err(
                |error| {
                    if n2r_win32::refusal::is_refusal(&error) {
                        anyhow::anyhow!(
                            "this volume is refused, and nothing on it was changed (it stayed online and was only read): {error}"
                        )
                    } else {
                        error.into()
                    }
                },
            )?;
        let mut boot = [0u8; 512];
        reader.read_exact(&mut boot)?;
        let geometry = crate::ntfs_inspect::inspect_boot_sector(&boot, reader.byte_len())?;
        ensure!(
            resources.supports_source_geometry(&geometry),
            "selected NTFS geometry is not supported by this conversion profile"
        );
        reader.revalidate_route(&mut events)?;
        drop(reader);
        println!(
            "Selected: {} — disk {}, partition {}",
            clean(drive),
            selected.disk_number,
            selected.partition_number
        );
        println!(
            "Filesystem: NTFS   Size: {}   Label: {}",
            size(Some(before.binding.identity.partition_bytes)),
            clean(&before.label)
        );
        println!(
            "Requested target: {} (ReFS, {} KiB clusters).",
            match (
                target_format.is_dev_drive(),
                target_format == default_format
            ) {
                (true, true) => "Dev Drive, the default",
                (true, false) => "Dev Drive",
                (false, true) => "standard ReFS, the default on Windows Server",
                (false, false) => "standard ReFS, if this Windows formats it",
            },
            n2r_win32::target_cluster::bytes() / 1024
        );
        println!(
            "Windows will report the converted volume's actual developer designation and trust state."
        );
        let verification_policy = if !args.verify_full_content {
            crate::verification_policy::VerificationPolicy::ExtentIdentityV1
        } else {
            crate::verification_policy::VerificationPolicy::FullContent
        };
        println!(
            "Mode: allocation-bounded (compares and writes only the ranges the new ReFS allocates; free space is not verified)"
        );
        println!(
            "NTFS-compressed streams, when present, are decoded into ordinary ReFS data and require space for their logical contents."
        );
        if args.minimize_scratch {
            println!(
                "Reduced scratch: rollback restores allocated NTFS data and metadata; unused-space contents may change. Volumes with VSS snapshots or hosted diff areas are refused."
            );
        }
        if let Some(decision) = boot_geometry {
            super::boot::describe_geometry(decision);
        }
        for line in beside.iter().flatten() {
            println!("{line}");
        }
        if !n2r_win32::windows_build::shown_in_lab(windows) {
            println!(
                "Note: this is Windows {}. Conversions have been run in the lab on builds {} only; this build is accepted and has not been tried.",
                n2r_win32::windows_build::describe(windows),
                n2r_win32::windows_build::lab_builds()
            );
        }
        if mode == crate::execution_mode::ExecutionMode::Diagnose {
            println!(
                "Diagnose mode: the ReFS shadow is built in the working directory and every per-object failure is reported. ntfs2refs writes nothing to the source."
            );
        }
        if args.recheck_everything {
            crate::resource_preparation::set_recheck_everything();
        }
        if let Some(limit) = args.diagnose_limit {
            crate::general_shadow::set_diagnose_limit(limit);
        }
        if let Some(point) = n2r_win32::lab_hold::armed() {
            println!("Laboratory hold armed at {point}: this run stops there and never completes.");
        }
        // Before anything is asked or changed: what the volume's own
        // structures decide is found out while it is online and as it was.
        // A partition is not shrunk, and a disk not taken offline, for a
        // volume that would be refused. (A Windows boot volume is examined
        // when it is frozen, as before.)
        let shrink = match boot_geometry {
            Some(super::boot::GeometryDecision::Shrink { shrink_bytes, .. }) => Some(shrink_bytes),
            _ => None,
        };
        if !args.windows_boot_volume {
            println!("Checking the volume first: it stays online and is only read.");
            let (os_root, work_root, journal) =
                working_volume(args.scratch_directory.as_deref(), &before)?;
            let parent = working_directory(args.scratch_directory.clone(), &os_root, &work_root)?;
            let checked = super::precheck::examine(
                &before,
                &journal_storage(&journal),
                &parent,
                &new_run_id()?,
            )?;
            match &checked {
                super::precheck::Outcome::Read(report) if !report.refusals.is_empty() => {
                    if mode == crate::execution_mode::ExecutionMode::Diagnose {
                        for line in super::precheck::lines(&checked, target_cluster) {
                            println!("{line}");
                        }
                        println!(
                            "The diagnosis stops here: a conversion would stop for this before it built anything. Nothing was changed."
                        );
                        return Ok(EXIT_DIAGNOSE_FAILURES);
                    }
                    anyhow::bail!(
                        "this volume is refused, and nothing on it was changed (it stayed online and was only read): {}",
                        report.refusals.join(" | ")
                    );
                }
                super::precheck::Outcome::Read(report) => {
                    // What is not carried over is said before the question.
                    for note in &report.notes {
                        println!("Note: {note}");
                    }
                    if let Some(estimate) = &report.estimate {
                        println!("Nothing was found that refuses it. What this run takes:");
                        for line in super::precheck::describe(estimate, target_cluster) {
                            println!("  {line}");
                        }
                    }
                }
                super::precheck::Outcome::Changing { last } => println!(
                    "The volume changed while it was read, so this check says nothing of it (the last reading stopped at: {last}). The run examines the volume again once it is frozen{}.",
                    if shrink.is_some() {
                        ", after the partition has been shrunk; to have the check first, start again when nothing writes to the volume"
                    } else {
                        ""
                    }
                ),
            }
            if let (Some(shrink_bytes), crate::execution_mode::ExecutionMode::Diagnose) =
                (shrink, mode)
            {
                println!(
                    "A full diagnosis builds the working ReFS volume at the length the partition has when it is converted. This partition would first be shrunk by {shrink_bytes} bytes, which a diagnosis never does, so the check above is all that was done. Nothing was changed."
                );
                return Ok(match checked {
                    super::precheck::Outcome::Changing { .. } => EXIT_CHECK_INCONCLUSIVE,
                    super::precheck::Outcome::Read(_) => 0,
                });
            }
        }
        if !confirm(confirmation_prompt(mode))? {
            println!("Cancelled. No conversion started.");
            return Ok(0);
        }
        let current = discovery::discover(&selected.volume_guid_path, source_role)?;
        ensure!(
            current.binding == before.binding && current.filesystem == "NTFS",
            "selected drive identity changed while awaiting confirmation"
        );
        convert_selected(
            args.scratch_directory,
            before,
            selected,
            verification_policy,
            args.minimize_scratch,
            target_format,
            mode,
            boot_geometry,
            listing_root,
        )
    }
    /// What a run says, before it asks, of the partitions that share the
    /// source's disk: which they are, and what happens to their volumes.
    pub(super) fn shared_disk_lines(
        disk_number: u32,
        others: &[&drive_inventory::PartitionInventory],
    ) -> Vec<String> {
        let named: Vec<String> = others
            .iter()
            .filter(|other| {
                !other
                    .partition_type_guid
                    .as_deref()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case(RESERVED_PARTITION))
            })
            .map(|other| {
                format!(
                    "{} ({}, {}{})",
                    if other.mount_paths.is_empty() {
                        format!("partition {}", other.partition_number)
                    } else {
                        other.mount_paths.join(", ")
                    },
                    other
                        .filesystem
                        .as_deref()
                        .unwrap_or("no file system Windows knows"),
                    size(other.size_bytes),
                    other
                        .label
                        .as_deref()
                        .filter(|label| !label.is_empty())
                        .map(|label| format!(", {}", clean(label)))
                        .unwrap_or_default()
                )
            })
            .collect();
        vec![
            format!(
                "This volume shares disk {disk_number} with {} other partition(s): {}.",
                named.len(),
                named.join("; ")
            ),
            "A conversion takes the whole disk offline. The volumes on those partitions are dismounted first and are not available until the run ends; for part of it Windows shows them read-only. Nothing is written to them. Close what uses them before you go on.".to_owned(),
            "If the run is cut off, they stay offline with the disk until the run is finished or undone with --recover.".to_owned(),
        ]
    }

    /// The volume that holds the working directory, with the root of the
    /// running Windows and its own. Working storage (run records, shadow
    /// VHDX, journal) lives there. It defaults to the Windows volume but may
    /// be any local volume on a disk other than the source, so a large
    /// shadow cannot fill the running operating system's disk.
    fn working_volume(
        scratch: Option<&std::path::Path>,
        source: &discovery::VolumeDiscovery,
    ) -> Result<(String, String, discovery::VolumeDiscovery)> {
        let system = n2r_win32::current_windows_directory()?
            .to_str()
            .context("Unicode native Windows directory required")?
            .to_owned();
        let os_root = format!(
            "{}\\",
            system
                .get(..2)
                .context("Windows system drive unavailable")?
        );
        let work_root = match scratch {
            Some(path) => {
                let root = path
                    .to_str()
                    .and_then(|text| text.get(..3))
                    .context("scratch directory must be a Unicode drive-letter path")?;
                ensure!(
                    root.as_bytes()[0].is_ascii_alphabetic() && &root[1..] == ":\\",
                    "scratch directory must be an absolute drive-letter path"
                );
                root.to_ascii_uppercase()
            }
            None => os_root.clone(),
        };
        let journal = discovery::discover(
            &work_root,
            Role::Journal {
                allow_additional_partitions: true,
            },
        )?;
        ensure!(
            journal.binding.disk_number != source.binding.disk_number,
            "working storage must be independent of the source disk"
        );
        Ok((os_root, work_root, journal))
    }

    /// The working directory itself, made if it is not there: an ordinary
    /// path on the working volume.
    fn working_directory(
        scratch: Option<PathBuf>,
        os_root: &str,
        work_root: &str,
    ) -> Result<PathBuf> {
        let parent = scratch
            .unwrap_or_else(|| PathBuf::from(format!("{}ProgramData\\ntfs2refs\\runs", os_root)));
        let text = parent.to_str().context("Unicode scratch path required")?;
        ensure!(
            parent.is_absolute()
                && text
                    .get(..3)
                    .is_some_and(|s| s.eq_ignore_ascii_case(work_root))
                && !text[3..].contains(':')
                && !parent
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir)),
            "scratch directory must be an ordinary path on its working volume"
        );
        ordinary_parents(&parent)?;
        Ok(parent)
    }

    /// A name for this run's directory that no other run has.
    fn new_run_id() -> Result<String> {
        let mut hash = Sha256::new();
        hash.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
                .to_le_bytes(),
        );
        hash.update(std::process::id().to_le_bytes());
        Ok(hex::encode(hash.finalize())[..32].to_owned())
    }

    /// The working volume as the run's records enrol it.
    fn journal_storage(
        journal: &discovery::VolumeDiscovery,
    ) -> n2r_win32::journal_file::GeneralJournalStorageBinding {
        n2r_win32::journal_file::GeneralJournalStorageBinding {
            disk: journal.binding.clone(),
            externally_enrolled_disk_unique_id: n2r_win32::journal_file::enrolled_disk_label(
                &journal.binding.identity.disk_guid,
            ),
            allow_additional_partitions: true,
        }
    }

    /// `--check`: reads the volume while it stays online and in use, and
    /// says what a conversion would refuse and what it would take.
    fn check(
        args: &DriveArgs,
        inventory: &mut DriveInventory,
        selected: &drive_inventory::PartitionSelection,
        drive: &str,
        target_cluster: u64,
        windows: [u32; 3],
    ) -> Result<u8> {
        println!(
            "Checking {} — disk {}, partition {}. A check changes nothing on it: the volume stays online and is only read.",
            clean(drive),
            selected.disk_number,
            selected.partition_number
        );
        // What stops a conversion before the volume's contents matter.
        let stopped = |reason: &str| -> Result<u8> {
            println!("A conversion would refuse this volume: {reason}");
            println!("Its contents were not read: this has to change first.");
            Ok(EXIT_CHECK_REFUSALS)
        };
        drive_inventory::annotate_bitlocker(inventory);
        let disk = inventory
            .disks
            .iter()
            .find(|disk| disk.disk_number == selected.disk_number)
            .context("the selected disk is no longer listed")?;
        let partition = disk
            .partitions
            .iter()
            .find(|partition| partition.partition_number == selected.partition_number)
            .context("the selected partition is no longer listed")?;
        match drive_inventory::conversion_note(disk, partition) {
            None => {
                return stopped(&format!(
                    "it is {}, not NTFS",
                    partition
                        .filesystem
                        .as_deref()
                        .unwrap_or("a volume Windows does not name")
                ));
            }
            Some(note) if note.starts_with("convertible as a data volume") => {}
            Some(note) if note.starts_with("convertible as a Windows boot volume") => {
                println!(
                    "This is the layout of a Windows installation. A check reads data volumes only; for this volume, run `--windows-boot-volume --diagnose` from another Windows installation."
                );
                return Ok(EXIT_CHECK_INCONCLUSIVE);
            }
            // An unlocked BitLocker volume is refused below from its first
            // sector, in the words a run uses.
            Some(_) if partition.bitlocker == Some(true) => {}
            Some(note) => return stopped(note.trim_start_matches("not convertible: ")),
        }
        let before = match discovery::discover(&selected.volume_guid_path, Role::Source) {
            Ok(found) if found.filesystem == "NTFS" => found,
            Ok(found) => return stopped(&format!("it is {}, not NTFS", found.filesystem)),
            Err(_) if partition.bitlocker == Some(true) => {
                return stopped(
                    "it is encrypted with BitLocker; decrypt it first (manage-bde -off <drive>), suspending is not enough",
                );
            }
            Err(error) => {
                return stopped(&format!(
                    "its disk is not one a data volume is converted on: {error}"
                ));
            }
        };
        let mut events = Vec::new();
        let mut reader =
            match n2r_win32::GeneralPartitionReader::open(before.binding.clone(), &mut events) {
                Ok(reader) => reader,
                // What the running Windows keeps on the volume's disk (a page
                // file, its crash dumps) is the converter's own decision
                // about the disk, not a read that failed.
                Err(error) if n2r_win32::refusal::is_refusal(&error) => {
                    return stopped(&error.to_string());
                }
                Err(error) => return Err(error.into()),
            };
        let mut boot = [0u8; 512];
        reader.read_exact(&mut boot)?;
        let geometry = match crate::ntfs_inspect::inspect_boot_sector(&boot, reader.byte_len()) {
            Ok(geometry) => geometry,
            Err(error) => return stopped(&format!("{error:#}")),
        };
        drop(reader);
        if !crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(None)
            .supports_source_geometry(&geometry)
        {
            return stopped(
                "its sector, cluster, file-record or index-record size is not one the converter handles",
            );
        }
        let partition_bytes = before.binding.identity.partition_bytes;
        println!(
            "Filesystem: NTFS   Size: {}   Label: {}   Serial: {}",
            size(Some(partition_bytes)),
            clean(&before.label),
            crate::confirmation::format_volume_serial(before.volume_serial_low32)
        );
        if before.binding.layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::SharedData
        {
            let others: Vec<&drive_inventory::PartitionInventory> = disk
                .partitions
                .iter()
                .filter(|other| other.partition_number != selected.partition_number)
                .collect();
            let efi = others.iter().any(|other| {
                other
                    .partition_type_guid
                    .as_deref()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case(EFI_SYSTEM_PARTITION))
            });
            let installed = partition.mount_paths.iter().any(|root| {
                std::path::Path::new(root)
                    .join("Windows\\System32\\ntoskrnl.exe")
                    .exists()
            });
            if efi && installed {
                return stopped(
                    "it holds an installed Windows (Windows\\System32\\ntoskrnl.exe) on a disk with an EFI system partition; converted as a data volume it would no longer start. Such a volume is converted with --windows-boot-volume",
                );
            }
            if installed && disk.partition_style.as_deref() == Some("MBR") {
                return stopped(&format!("it {MBR_INSTALLED_WINDOWS}"));
            }
            for line in shared_disk_lines(selected.disk_number, &others) {
                println!("{line}");
            }
        }
        let default_format = n2r_win32::managed_shadow::TargetFormatProfile::default_for(
            n2r_win32::run_environment::is_windows_server()?,
            false,
        );
        let target_format = match args.target_format.as_deref() {
            Some(named) => named.parse()?,
            None => default_format,
        };
        println!(
            "A conversion would ask Windows for {} (ReFS, {} KiB clusters); whether this Windows formats it is found out when the run starts, before the volume is touched.",
            match (
                target_format.is_dev_drive(),
                target_format == default_format
            ) {
                (true, true) => "a Dev Drive, the default",
                (true, false) => "a Dev Drive",
                (false, true) => "standard ReFS, the default on Windows Server",
                (false, false) => "standard ReFS",
            },
            target_cluster / 1024
        );
        if let super::boot::GeometryDecision::Shrink {
            target_bytes,
            shrink_bytes,
        } = super::boot::geometry_decision(partition_bytes)?
        {
            println!(
                "The partition's length is not a multiple of 64 MiB, the unit ReFS covers a volume in: a conversion first has the Windows NTFS driver shrink it by {shrink_bytes} bytes, to {target_bytes}."
            );
        }
        if !n2r_win32::windows_build::shown_in_lab(windows) {
            println!(
                "Note: this is Windows {}. Conversions have been run in the lab on builds {} only; this build is accepted and has not been tried.",
                n2r_win32::windows_build::describe(windows),
                n2r_win32::windows_build::lab_builds()
            );
        }
        let (os_root, work_root, journal) =
            working_volume(args.scratch_directory.as_deref(), &before)?;
        let parent = working_directory(args.scratch_directory.clone(), &os_root, &work_root)?;
        println!(
            "Reading the volume's NTFS structures (the check keeps its own pages under {} meanwhile, and removes them).",
            parent.display()
        );
        let outcome =
            super::precheck::examine(&before, &journal_storage(&journal), &parent, &new_run_id()?)?;
        for line in super::precheck::lines(&outcome, target_cluster) {
            println!("{line}");
        }
        Ok(match outcome {
            super::precheck::Outcome::Changing { .. } => EXIT_CHECK_INCONCLUSIVE,
            super::precheck::Outcome::Read(report) if report.refusals.is_empty() => 0,
            super::precheck::Outcome::Read(_) => EXIT_CHECK_REFUSALS,
        })
    }

    fn convert_selected(
        scratch: Option<PathBuf>,
        before: discovery::VolumeDiscovery,
        selected: drive_inventory::PartitionSelection,
        verification_policy: crate::verification_policy::VerificationPolicy,
        minimize_scratch: bool,
        target_format: n2r_win32::managed_shadow::TargetFormatProfile,
        mode: crate::execution_mode::ExecutionMode,
        boot_geometry: Option<super::boot::GeometryDecision>,
        // The drive root to list before and after, for --compare-listing.
        compare_listing: Option<String>,
    ) -> Result<u8> {
        let (os_root, work_root, journal) = working_volume(scratch.as_deref(), &before)?;
        let space = discovery::observe_volume_space(&journal.volume_guid_path)?;
        ensure!(
            space.available_bytes_to_caller >= 4 * 1024 * 1024 * 1024,
            "working volume {work_root} lacks space for the conversion: {} bytes available, 4 GiB required",
            space.available_bytes_to_caller
        );
        let reserve = (space.available_bytes_to_caller / 4).min(16 * 1024 * 1024 * 1024);
        // Journal and literal backing share one measured pool. Encoded
        // zeros/copies must not strand an unused fixed backing fraction.
        let usable = space.available_bytes_to_caller - reserve;
        let journal_bytes = usable / 4096 * 4096;
        let id = new_run_id()?;
        let parent = working_directory(scratch, &os_root, &work_root)?;
        let run = parent.join(&id);
        fs::create_dir(&run)
            .with_context(|| format!("creating this run's directory {}", run.display()))?;
        save_new(
            &run.join("drive-selection.json"),
            &serde_json::json!({"selected":selected,"source":before,"confirmation":"interactive affirmative","journal_budget_bytes":journal_bytes,"requested_target_format":target_format,"explicit_trust_or_filter_configuration_requested":false,"source_write_authority":false,"lab_hold_point":n2r_win32::lab_hold::armed()}),
        )?;
        if let Some(root) = &compare_listing {
            // Before anything of this run touches the volume.
            super::listing::before(root, &run)?;
        }
        let native_creation_admission =
            n2r_win32::managed_shadow::admit_fresh_native_backing(&run.join("shadow.vhdx"))?;
        save_new(
            &run.join("native-shadow-creation-admission.json"),
            &native_creation_admission.observe()?,
        )?;
        ensure!(
            boot_geometry.is_some(),
            "the partition's ReFS geometry was not decided"
        );
        // The length the partition has when it is converted. The working
        // volume is formatted at that length first: Windows refusing to
        // format it is found out while the partition is still as it was.
        let converted_partition_bytes = match boot_geometry {
            Some(super::boot::GeometryDecision::Shrink { target_bytes, .. }) => target_bytes,
            _ => before.binding.identity.partition_bytes,
        };
        println!(
            "Preparing temporary ReFS metadata storage. Recovery files: {}",
            run.display()
        );
        native_creation_admission.check()?;
        let staged =
            super::staging::StageOwner::Vhdx(n2r_win32::managed_shadow::create_with_profile(
                &run.join("shadow.vhdx"),
                converted_partition_bytes,
                before.binding.identity.logical_sector_bytes,
                before.binding.identity.physical_sector_bytes,
                target_format,
            )?);
        native_creation_admission.check()?;
        // The version is whatever this Windows formatted. One the lab never
        // converted is accepted, and the run says that it is the first.
        let refs_version = n2r_win32::target_refs_version::get();
        if refs_version != n2r_win32::target_refs_version::DEFAULT {
            println!(
                "Note: Windows formatted the working ReFS as version {}.{}. Conversions have been run in the lab to ReFS {}.{} only; this version is accepted and has not been tried.",
                refs_version.0,
                refs_version.1,
                n2r_win32::target_refs_version::DEFAULT.0,
                n2r_win32::target_refs_version::DEFAULT.1
            );
        }
        // Only now, with a working volume that Windows did format, is the
        // partition shrunk to the length that volume has.
        let before = if let Some(super::boot::GeometryDecision::Shrink { .. }) = boot_geometry {
            let authority = mode.source_change_authority(
                "the Windows NTFS driver shrink that prepares ReFS geometry",
            )?;
            let shrunk = super::boot::normalize_geometry(before, &run, &authority)?;
            ensure!(
                shrunk.binding.identity.partition_bytes == converted_partition_bytes,
                "the Windows NTFS driver left the partition {} bytes long, not the {converted_partition_bytes} the working volume was formatted for",
                shrunk.binding.identity.partition_bytes
            );
            shrunk
        } else {
            before
        };
        let provider_commitment = staged.initial_host_backing_commitment()?;
        // Record the provider identity as well as the disk identity: a guest
        // reboot can remove the attachment while leaving the recovery backing
        // intact. These facts locate the original shadow; they never grant
        // source admission, formatting or journal replay authority.
        save_new(&run.join("managed-shadow.json"), &staged.location())?;
        save_new(
            &run.join("managed-shadow-policy.json"),
            &serde_json::json!({
                "schema_version":1,"kind":"requested-and-observed-shadow-format-policy",
                "requested_target_format":target_format,"shadow_binding":staged.binding(),
                "actual_shadow_policy":staged.format_policy(),
                "requested_designation_verified":true,"explicit_trust_or_filter_configuration_changed":false,
                "source_trust_inferred_from_shadow":false,
                "grants_source_or_replay_authority":false,
            }),
        )?;
        let result = super::resource::convert_owned_with_provider_commitment(
            n2r_win32::general_layout::GeneralSourceShadowBinding {
                source: before.binding.clone(),
                shadow: staged.binding().clone(),
            },
            n2r_win32::journal_file::GeneralJournalStorageBinding {
                disk: journal.binding.clone(),
                externally_enrolled_disk_unique_id: n2r_win32::journal_file::enrolled_disk_label(
                    &journal.binding.identity.disk_guid,
                ),
                allow_additional_partitions: true,
            },
            &run,
            verification_policy,
            if minimize_scratch {
                crate::selected_capacity::SelectedCapacityPolicy::SourceFreeActualBytesV1
            } else {
                Default::default()
            },
            provider_commitment,
            0,
            staged.staging_allocation_meter(),
            mode,
        );
        let output = run.join("conversion");
        match result {
            Ok(super::resource::ConversionOutcome::Diagnosed(outcome)) => {
                // The shadow was built only to be examined; nothing was
                // published from it, so it is detached and removed.
                let retirement = staged.retire_after_diagnose();
                if !retirement.success() {
                    eprintln!(
                        "Diagnose finished, but its temporary shadow could not be removed (stopped at {}: {}). It remains in {}.",
                        retirement.phase(),
                        retirement.error().unwrap_or("cleanup incomplete"),
                        run.display()
                    );
                }
                if let Err(error) = save_new(&run.join("shadow-retirement.json"), &retirement) {
                    eprintln!("The temporary-shadow cleanup receipt could not be saved: {error}");
                }
                report_diagnosis(&run, &outcome, retirement.success())
            }
            Ok(super::resource::ConversionOutcome::Converted) => {
                // This live Ok comes only after V4 HND/native finalization
                // returned and all construction/raw owners were released.
                // Its replay is self-contained.
                let retirement = staged.retire_after_successful_v4();
                if !retirement.success() {
                    eprintln!(
                        "Conversion completed; temporary shadow cleanup stopped at {}: {}. Preserve any remaining staging files. Raw rollback remains closed.",
                        retirement.phase(),
                        retirement.error().unwrap_or("cleanup incomplete")
                    );
                }
                if let Err(error) = save_new(&run.join("shadow-retirement.json"), &retirement) {
                    eprintln!(
                        "Conversion completed; its temporary-shadow cleanup receipt could not be saved: {error}"
                    );
                }
                // The source's actual post-handoff policy is independent of the
                // temporary shadow's trust. Observation/report errors cannot
                // reopen raw replay or invalidate an already closed handoff.
                let mut policy_events = Vec::new();
                let actual_policy =
                    n2r_win32::volume_policy::observe(&before.binding, &mut policy_events);
                let developer = actual_policy
                    .as_ref()
                    .ok()
                    .and_then(|policy| policy.developer_volume);
                let trusted = actual_policy
                    .as_ref()
                    .ok()
                    .and_then(|policy| policy.trusted_volume);
                let designation = match developer {
                    Some(true) => "Dev Drive (ReFS)",
                    Some(false) => "standard ReFS",
                    None => "unknown",
                };
                let trust = match trusted {
                    Some(true) => "trusted",
                    Some(false) => "not marked trusted",
                    None => "unknown",
                };
                println!("Windows reports the converted source: {designation}; trust: {trust}.");
                if developer.is_some_and(|value| value != target_format.is_dev_drive()) {
                    eprintln!(
                        "The observed source designation differs from the requested target format; raw rollback remains closed."
                    );
                }
                if let Err(error) = save_new(
                    &run.join("source-volume-policy.json"),
                    &serde_json::json!({
                        "schema_version":1,"kind":"post-handoff-source-volume-policy",
                        "requested_target_format":target_format,
                        "actual_source_policy":actual_policy.as_ref().ok(),
                        "observation_error":actual_policy.as_ref().err().map(ToString::to_string),
                        "requested_designation_matches":developer.map(|value| value == target_format.is_dev_drive()),
                        "events":policy_events,"source_trust_inferred_from_shadow":false,
                        "explicit_trust_or_filter_configuration_changed":false,
                        "handoff_remains_closed":true,"grants_source_or_replay_authority":false,
                    }),
                ) {
                    eprintln!(
                        "Conversion completed; the source policy report could not be saved: {error}"
                    );
                }
                println!(
                    "Conversion completed. Recovery records: {}",
                    output.display()
                );
                if let Some(root) = &compare_listing {
                    // The conversion stands whatever this finds or fails at.
                    match super::listing::after(root, &run) {
                        Ok(true) => {}
                        Ok(false) => return Ok(EXIT_LISTING_DIFFERS),
                        Err(error) => {
                            eprintln!(
                                "The conversion completed. The listing after it could not be made or compared: {error:#}. The listing taken before is in {}; `lab-volume-manifest` makes and compares listings by hand.",
                                run.display()
                            );
                            return Ok(EXIT_LISTING_DIFFERS);
                        }
                    }
                }
                Ok(0)
            }
            Err(e) => {
                // Preserve the permanent attachment/backing on every error,
                // including committed-but-incomplete native finalization.
                drop(staged);
                if e.downcast_ref::<crate::resource_finalize::CommittedFinalizationError>()
                    .is_some()
                {
                    eprintln!("{e:#}");
                    eprintln!(
                        "Preserve the recovery records at {}. Raw rollback is closed.",
                        run.display()
                    );
                    return Err(e);
                }
                if mode == crate::execution_mode::ExecutionMode::Diagnose {
                    eprintln!(
                        "Diagnose could not finish. Its working files are at {}",
                        run.display()
                    );
                } else {
                    eprintln!(
                        "Conversion stopped. Preserve all recovery files at {}",
                        run.display()
                    );
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_mode::ExecutionMode;

    #[cfg(windows)]
    #[test]
    fn a_run_names_the_partitions_that_go_offline_with_the_volume() {
        use n2r_win32::drive_inventory::PartitionInventory;
        let partition = |number: u32, kind: &str, letter: Option<&str>, label: Option<&str>| {
            PartitionInventory {
                disk_number: 3,
                partition_number: number,
                partition_style: "GPT".into(),
                offset_bytes: Some(0),
                size_bytes: Some(2 * 1024 * 1024 * 1024),
                partition_guid: None,
                partition_type_guid: Some(kind.into()),
                gpt_name: None,
                mbr_type: None,
                mbr_active: None,
                service_partition: None,
                volume_guid_paths: Vec::new(),
                mount_paths: letter.iter().map(|letter| (*letter).to_owned()).collect(),
                filesystem: letter.map(|_| "NTFS".to_owned()),
                label: label.map(str::to_owned),
                volume_serial: None,
                bitlocker: None,
                read_only: None,
                offline: None,
                contains_running_windows: Some(false),
                is_system: None,
                unsupported_reason: None,
            }
        };
        let basic = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
        let reserved = partition(1, &RESERVED_PARTITION.to_ascii_uppercase(), None, None);
        let lettered = partition(2, basic, Some("W:\\"), Some("Photos"));
        let bare = partition(4, "0fc63daf-8483-4772-8e79-3d69d8477de4", None, None);
        let said = windows::shared_disk_lines(3, &[&reserved, &lettered, &bare]);
        // The reserved partition holds no volume and is not counted; a
        // partition without a letter is named by its number.
        assert_eq!(
            said[0],
            "This volume shares disk 3 with 2 other partition(s): W:\\ (NTFS, 2.00 GiB, Photos); partition 4 (no file system Windows knows, 2.00 GiB)."
        );
        // What happens to them, and what a run that is cut off leaves.
        assert!(said[1].contains("takes the whole disk offline"), "{said:?}");
        assert!(said[1].contains("Nothing is written to them"), "{said:?}");
        assert!(said[2].contains("--recover"), "{said:?}");
        assert_eq!(said.len(), 3);
        // The guide quotes the two lines that are the same for every disk.
        let guide = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/cli-workflow.md"));
        for line in &said[1..] {
            assert!(
                guide.contains(line.as_str()),
                "the guide does not quote {line:?}"
            );
        }
    }
    use clap::{Parser, error::ErrorKind};

    #[derive(Parser, Debug)]
    struct Cli {
        #[command(flatten)]
        drive: DriveArgs,
    }
    #[test]
    fn a_partial_drive_list_does_not_exit_as_a_complete_one() {
        assert_eq!(list_exit_code(true), 0);
        assert_eq!(list_exit_code(false), EXIT_LIST_INCOMPLETE);
        // Distinct from success, a failure, a usage error and diagnose failures.
        for taken in [0, 1, 2, EXIT_DIAGNOSE_FAILURES] {
            assert_ne!(EXIT_LIST_INCOMPLETE, taken);
        }
    }

    fn parse(extra: &[&str]) -> std::result::Result<DriveArgs, clap::Error> {
        let mut arguments = vec!["ntfs2refs", "--drive", "D"];
        arguments.extend_from_slice(extra);
        Cli::try_parse_from(arguments).map(|cli| cli.drive)
    }
    const NONCE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn short_names_are_refused_unless_the_run_is_asked_to_drop_them() {
        // Nothing given: the volume's short names refuse it.
        assert_eq!(parse(&[]).unwrap().short_names, None);
        assert_eq!(
            parse(&["--short-names", "refuse"])
                .unwrap()
                .short_names
                .as_deref(),
            Some("refuse")
        );
        assert_eq!(
            parse(&["--short-names", "drop"])
                .unwrap()
                .short_names
                .as_deref(),
            Some("drop")
        );
        // It is one of the two, and a matter of data volumes: a Windows
        // boot volume's short names become links.
        assert!(parse(&["--short-names", "links"]).is_err());
        assert!(parse(&["--short-names", "drop", "--windows-boot-volume"]).is_err());
        // A check takes it, to say what a run with it would do.
        assert!(parse(&["--short-names", "drop", "--check"]).is_ok());
    }

    #[test]
    fn a_laboratory_hold_needs_its_own_acknowledgement() {
        assert!(parse(&["--lab-hold-at", "handoff-sealed"]).is_err());
        assert!(parse(&["--acknowledge-lab-hold-never-completes"]).is_err());
        let held = parse(&[
            "--lab-hold-at",
            "handoff-sealed",
            "--acknowledge-lab-hold-never-completes",
        ])
        .unwrap();
        assert_eq!(held.lab_hold_at.as_deref(), Some("handoff-sealed"));
        assert_eq!(held.execution_mode().unwrap(), ExecutionMode::Convert);
    }

    #[test]
    fn a_laboratory_failure_point_needs_the_restart_route_and_its_own_acknowledgement() {
        const ACK: &str = "--acknowledge-lab-fail-stops-the-run";
        const MEDIA: &[&str] = &["--restart-media", "E:\\"];
        let with = |extra: &[&str]| {
            let mut arguments = MEDIA.to_vec();
            arguments.extend_from_slice(extra);
            parse(&arguments)
        };
        // Neither half alone, and not without the route that restarts.
        assert!(with(&["--lab-fail-at", "restart-after-protect"]).is_err());
        assert!(with(&[ACK]).is_err());
        assert!(parse(&["--lab-fail-at", "restart-after-protect", ACK]).is_err());
        for &point in n2r_win32::lab_fail::POINTS {
            let armed = with(&["--lab-fail-at", point, ACK]).unwrap();
            assert_eq!(armed.lab_fail_at.as_deref(), Some(point));
            assert!(armed.acknowledge_lab_fail_stops_the_run);
            // Parsing arms nothing: only a run does, and it refuses a name
            // it does not know before anything is opened.
            assert_eq!(n2r_win32::lab_fail::armed(), None);
        }
        assert!(n2r_win32::lab_fail::known("restart-after-reboot").is_err());
        // Not together with a hold, a check, a diagnose run or a recovery.
        for refused in [
            &[
                "--lab-fail-at",
                "restart-after-arm",
                ACK,
                "--lab-hold-at",
                "handoff-sealed",
                "--acknowledge-lab-hold-never-completes",
            ][..],
            &["--lab-fail-at", "restart-after-arm", ACK, "--check"],
            &["--lab-fail-at", "restart-after-arm", ACK, "--diagnose"],
        ] {
            assert!(with(refused).is_err(), "{refused:?}");
        }
        assert!(
            Cli::try_parse_from([
                "ntfs2refs",
                "--recover",
                "S:\\run",
                "--lab-fail-at",
                "restart-after-arm",
                ACK
            ])
            .is_err()
        );
        // The switches are hidden from --help.
        let help = <Cli as clap::CommandFactory>::command()
            .render_long_help()
            .to_string();
        assert!(!help.contains("lab-fail"), "{help}");
    }

    #[test]
    fn a_recovery_is_parsed_with_its_folder_alone_and_with_its_checksum() {
        // The folder of a run that restarts the machine takes no checksum;
        // whether a folder is one is decided from its records, when it is
        // read, and every other folder is then asked for its checksum.
        let alone = Cli::try_parse_from(["ntfs2refs", "--recover", "S:\\run", "--rollback"])
            .unwrap()
            .drive;
        assert!(alone.rollback && alone.recovery_sha256.is_none());
        assert_eq!(
            alone.recover.as_deref(),
            Some(std::path::Path::new("S:\\run"))
        );
        let status = Cli::try_parse_from(["ntfs2refs", "--recover", "S:\\run"])
            .unwrap()
            .drive;
        assert!(!status.rollback);
        let pinned = Cli::try_parse_from([
            "ntfs2refs",
            "--recover",
            "S:\\run",
            "--recovery-sha256",
            NONCE,
        ])
        .unwrap()
        .drive;
        assert_eq!(pinned.recovery_sha256.as_deref(), Some(NONCE));
        // --yes answers the question of a recovery without a serial number.
        let unattended =
            Cli::try_parse_from(["ntfs2refs", "--recover", "S:\\run", "--rollback", "--yes"])
                .unwrap()
                .drive;
        assert!(unattended.unattended().unwrap());
        // A checksum or a rollback without a folder is still refused.
        assert!(Cli::try_parse_from(["ntfs2refs", "--rollback"]).is_err());
        assert!(Cli::try_parse_from(["ntfs2refs", "--recovery-sha256", NONCE]).is_err());
    }

    #[test]
    fn a_check_takes_nothing_that_would_change_a_volume() {
        let check = parse(&["--check"]).unwrap();
        assert!(check.check && !check.diagnose && !check.yes);
        // What a conversion would be asked for may be named, so that the
        // estimate is the one for it; and the volume may be named twice.
        for accepted in [
            &["--check", "--target-cluster-bytes", "65536"][..],
            &["--check", "--target-format", "standard"],
            &["--check", "--scratch-directory", "S:\\runs"],
            &["--check", "--volume-serial", "1A2B-3C4D"],
        ] {
            assert!(parse(accepted).is_ok(), "{accepted:?}");
        }
        for refused in [
            &["--check", "--diagnose"][..],
            &["--check", "--yes", "--volume-serial", "1A2B-3C4D"],
            &["--check", "--windows-boot-volume"],
            &["--check", "--minimize-scratch"],
            &[
                "--check",
                "--lab-hold-at",
                "handoff-sealed",
                "--acknowledge-lab-hold-never-completes",
            ],
        ] {
            let error = parse(refused).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{refused:?}");
        }
        // Not without a volume, and not with the list or a recovery.
        for refused in [
            &["ntfs2refs", "--check"][..],
            &["ntfs2refs", "--list", "--check"],
        ] {
            assert!(
                Cli::try_parse_from(refused.iter().copied()).is_err(),
                "{refused:?}"
            );
        }
        // A check converts nothing, so there is nothing to list twice.
        assert_eq!(
            parse(&["--check", "--compare-listing"]).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse(&["--diagnose", "--compare-listing"])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );
        assert!(parse(&["--compare-listing"]).unwrap().compare_listing);
        assert_eq!(EXIT_LISTING_DIFFERS, 6);
        // The codes a script reads are three different ones.
        assert_eq!(EXIT_CHECK_REFUSALS, 3);
        assert_eq!(EXIT_CHECK_INCONCLUSIVE, 5);
        assert_ne!(EXIT_CHECK_INCONCLUSIVE, EXIT_LIST_INCOMPLETE);
    }

    #[test]
    fn a_diagnose_run_is_not_confirmed_as_a_conversion() {
        assert!(
            confirmation_prompt(ExecutionMode::Convert)
                .starts_with("Convert this partition to ReFS in place")
        );
        let diagnose = confirmation_prompt(ExecutionMode::Diagnose);
        assert!(
            diagnose.starts_with("Diagnose this partition without converting it")
                && !diagnose.contains("Convert this partition"),
            "{diagnose}"
        );
    }

    #[test]
    fn a_conversion_and_a_plain_diagnose_are_admitted() {
        let mode = |extra: &[&str]| parse(extra).unwrap().execution_mode().unwrap();
        assert_eq!(mode(&[]), ExecutionMode::Convert);
        assert_eq!(mode(&["--diagnose"]), ExecutionMode::Diagnose);
        assert_eq!(
            mode(&[
                "--diagnose",
                "--windows-boot-volume",
                "--verify-full-content",
                "--recheck-everything",
            ]),
            ExecutionMode::Diagnose
        );
        // Without --diagnose these are ordinary conversion requests.
        assert_eq!(mode(&["--minimize-scratch"]), ExecutionMode::Convert);
    }

    #[test]
    fn the_parser_rejects_diagnose_with_every_option_it_cannot_honour() {
        let cases: [&[&str]; 4] = [
            &[
                "--lab-hold-at",
                "handoff-sealed",
                "--acknowledge-lab-hold-never-completes",
            ],
            &["--minimize-scratch"],
            &["--restart-media", "E:\\"],
            &[
                "--controlled-post-flush-pause-nonce",
                NONCE,
                "--acknowledge-controlled-post-flush-pause",
            ],
        ];
        for extra in cases {
            // Each is accepted by the parser on its own.
            assert!(parse(extra).is_ok(), "{extra:?}");
            let mut arguments = vec!["--diagnose"];
            arguments.extend_from_slice(extra);
            let error = parse(&arguments).unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::ArgumentConflict,
                "{arguments:?}: {error}"
            );
        }
    }

    #[test]
    fn admission_refuses_each_combination_whatever_built_the_arguments() {
        type Set = fn(&mut DriveArgs);
        let cases: [Set; 5] = [
            |a| a.minimize_scratch = true,
            |a| a.offline_recovery_media = Some(PathBuf::from("E:\\")),
            |a| a.controlled_post_flush_pause_nonce = Some(NONCE.to_owned()),
            |a| a.acknowledge_controlled_post_flush_pause = true,
            |a| a.lab_hold_at = Some("handoff-sealed".to_owned()),
        ];
        assert_eq!(cases.len(), DriveArgs::DIAGNOSE_REFUSES.len());
        for (set, (flag, reason)) in cases.iter().zip(DriveArgs::DIAGNOSE_REFUSES) {
            let mut arguments = parse(&["--diagnose"]).unwrap();
            set(&mut arguments);
            let refusal = arguments.execution_mode().unwrap_err().to_string();
            assert!(
                refusal.contains(flag) && refusal.contains(reason),
                "{flag}: {refusal}"
            );
            arguments.diagnose = false;
            assert_eq!(
                arguments.execution_mode().unwrap(),
                ExecutionMode::Convert,
                "{flag}"
            );
        }
    }
}
