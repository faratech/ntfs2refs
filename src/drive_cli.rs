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
    /// Mounted Windows installation-media directory for offline shared-disk
    /// conversion. An earlier design: it needs ntfs2refs-recovery.exe, which
    /// no release ships, and is not listed by --help.
    #[arg(long = "offline-media", requires = "drive", hide = true)]
    pub offline_recovery_media: Option<PathBuf>,
    /// The volume is an installed Windows that is not running; the Windows
    /// that runs the converter is on another disk and is never converted.
    /// Admitted for the boot profiles `ntfs2refs capabilities` lists.
    #[arg(long, requires="drive", conflicts_with_all=["offline_recovery_media","whole_image_verification","experimental_thin_shadow"])]
    pub windows_boot_volume: bool,
    /// How Windows formats the new file system: dev-drive or standard. The
    /// default is standard on Windows Server and dev-drive elsewhere.
    /// Standard works only where Windows itself formats ordinary ReFS
    /// volumes; there is no fallback from one to the other.
    #[arg(long, requires = "drive", value_parser = ["dev-drive", "standard"])]
    pub target_format: Option<String>,
    /// Allocation unit of the ReFS target in bytes: 4096 (default) or 65536.
    /// Data stays where it is only if it lies on boundaries of this size, so
    /// 65536 suits a source with clusters of 64 KiB or larger; from smaller
    /// clusters most data is copied through the working storage instead.
    #[arg(long, requires = "drive", value_parser = ["4096", "65536"])]
    pub target_cluster_bytes: Option<String>,
    /// Finish an interrupted run from its conversion directory, as printed
    /// in its "To recover:" line. With --rollback, undo it instead.
    #[arg(long, requires = "recovery_sha256", conflicts_with_all = ["list", "drive", "partition", "scratch_directory"])]
    pub recover: Option<PathBuf>,
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
    /// Accepted for compatibility: allocation-bounded conversion is the default.
    #[arg(long, requires = "drive", hide = true)]
    pub experimental_allocation_bounded: bool,
    /// Compare and journal the complete source and ReFS images instead of only
    /// the ranges the new ReFS allocates. Much slower; also proves that free
    /// space is unchanged. This older route keeps fixed limits the default
    /// route does not have: at most 1,024 files, 256 directories and 4,096
    /// placed NTFS runs. A larger volume is refused before anything is written.
    /// An earlier design, not listed by --help.
    #[arg(
        long,
        requires = "drive",
        conflicts_with = "experimental_allocation_bounded",
        hide = true
    )]
    pub whole_image_verification: bool,
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
    #[arg(long, requires = "drive", conflicts_with_all = ["whole_image_verification", "verify_full_content"])]
    pub minimize_scratch: bool,
    /// Check the volume while it stays online: nothing is frozen, formatted
    /// or written. Prints every refusal a conversion would give that the
    /// volume's NTFS structures and shadow copies decide, and what a
    /// conversion would take in working storage, memory and time. For a
    /// data volume. Exit 0: nothing found; 3: a conversion would refuse;
    /// 5: the volume kept changing while it was read, so nothing is known.
    #[arg(long, requires = "drive", conflicts_with_all = [
        "list", "recover", "rollback", "diagnose", "yes",
        "windows_boot_volume", "whole_image_verification", "minimize_scratch",
        "offline_recovery_media", "controlled_post_flush_pause_nonce",
        "acknowledge_controlled_post_flush_pause", "experimental_thin_shadow",
        "experimental_thin_backing_bytes", "lab_hold_at",
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
        "list", "recover", "rollback", "whole_image_verification", "minimize_scratch",
        "offline_recovery_media", "controlled_post_flush_pause_nonce",
        "acknowledge_controlled_post_flush_pause", "experimental_thin_shadow",
        "experimental_thin_backing_bytes",
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
    /// Laboratory: sample the worker's call stack a hundred times a second
    /// and write the profile to this file. Needs the .pdb beside the executable.
    #[arg(long, hide = true, value_name = "FILE")]
    pub sample_stacks: Option<PathBuf>,
    /// Qualification-only: use bounded thin temporary storage on the V4 route.
    #[arg(
        long,
        requires = "drive",
        conflicts_with = "whole_image_verification",
        hide = true
    )]
    pub experimental_thin_shadow: bool,
    /// Qualification-only bound on the thin provider's carrier and metadata.
    #[arg(long, requires = "experimental_thin_shadow", hide = true)]
    pub experimental_thin_backing_bytes: Option<u64>,
    /// Qualification-only bounded wait after actual source flush/readback.
    #[arg(long, hide = true, value_parser = parse_controlled_pause_nonce,
        requires_all = ["drive", "acknowledge_controlled_post_flush_pause"],
        conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback", "whole_image_verification", "experimental_thin_shadow", "experimental_thin_backing_bytes"])]
    pub controlled_post_flush_pause_nonce: Option<String>,
    /// Separate acknowledgement for shared-partition qualification control.
    #[arg(long, hide = true,
        requires_all = ["drive", "controlled_post_flush_pause_nonce"],
        conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback", "whole_image_verification", "experimental_thin_shadow", "experimental_thin_backing_bytes"])]
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
        self.list || self.drive.is_some() || self.recover.is_some()
    }

    /// What `--diagnose` cannot be combined with, and why. Diagnose never
    /// changes the source; each of these would, or has no diagnose stop.
    pub const DIAGNOSE_REFUSES: &'static [(&'static str, &'static str)] = &[
        (
            "--whole-image-verification",
            "that route has no diagnose stop and would apply the conversion",
        ),
        (
            "--minimize-scratch",
            "it moves files on the source before preparation starts",
        ),
        (
            "--offline-media",
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
        (
            "--experimental-thin-shadow",
            "diagnose builds and removes only the ordinary shadow",
        ),
        (
            "--experimental-thin-backing-bytes",
            "diagnose builds and removes only the ordinary shadow",
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
            self.whole_image_verification,
            self.minimize_scratch,
            self.offline_recovery_media.is_some(),
            self.controlled_post_flush_pause_nonce.is_some(),
            self.acknowledge_controlled_post_flush_pause,
            self.experimental_thin_shadow,
            self.experimental_thin_backing_bytes.is_some(),
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
        io::{self, BufRead, IsTerminal, Read, Write},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
                    notes.push("running Windows".into());
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
            for e in &v.errors {
                eprintln!(
                    "Volume {}: {}",
                    clean(&v.volume_guid_path),
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
                    "   -     -  {:<16}  {:<10}  {:>12}  [no basic partition mapping]",
                    clean(root),
                    "-",
                    "-"
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

    // These are observations of fixed local artifact names only. They neither
    // read payload/recovery storage nor grant permission to advance a phase.
    fn conversion_phase(output: &std::path::Path) -> &'static str {
        use std::os::windows::fs::MetadataExt;
        let exists = |name| {
            fs::symlink_metadata(output.join(name))
                .is_ok_and(|metadata| metadata.is_file() && metadata.file_attributes() & 0x400 == 0)
        };
        if exists("apply.json") {
            "Verifying files"
        } else if exists("activation-events.json") {
            "Applying conversion"
        } else if exists("journal-progress.json")
            || exists("journal-location.json")
            || exists("compact-backing.json")
        {
            "Preparing recovery journal"
        } else if exists("qualification/construction-freeze.json")
            || exists("qualification/target-freeze-events.json")
        {
            "Verifying target"
        } else if exists("qualification/construction-intent.json") {
            "Building ReFS metadata"
        } else {
            "Inspecting NTFS"
        }
    }

    /// What to tell the owner of a whole-image run that froze its source and
    /// stopped before it published a recovery bundle. That route leaves the
    /// disk offline and read-only on purpose; `ntfs2refs cancel` returns it
    /// once it has proved the whole image unchanged, and needs the digests of
    /// three of the run's records. `None` when the run froze nothing, or got
    /// as far as a bundle (whose "To recover:" line is then the way back).
    pub(super) fn frozen_source_way_back(conversion: &std::path::Path) -> Option<String> {
        if [
            "compact-recovery-bundle.json",
            "allocation-recovery-bundle.json",
        ]
        .iter()
        .any(|bundle| conversion.join(bundle).exists())
        {
            return None;
        }
        let digest = |record: &str| {
            fs::read(conversion.join(record))
                .ok()
                .map(|bytes| hex::encode(Sha256::digest(bytes)))
        };
        let intent = digest("conversion-intent.json")?;
        let frozen = digest("qualification/source-frozen.json")?;
        let mounts = digest("qualification/source-mount-paths.json")?;
        Some(format!(
            "The source disk was left offline and read-only. Nothing was written to it. To \
             return the NTFS volume, run this; it proves the whole volume unchanged first:\n  \
             ntfs2refs cancel --run-directory \"{}\" --intent-sha256 {intent} \
             --frozen-source-sha256 {frozen} --mount-paths-sha256 {mounts} --output \"{}\"",
            conversion.display(),
            conversion.with_file_name("cancel").display()
        ))
    }

    fn convert_with_progress(
        request: crate::general_conversion::Request,
        budget: crate::general_qualification::CompactConstructionBudget,
        output: PathBuf,
        allocation_bounded: bool,
        // This backend has no diagnose stop: it activates the source and applies.
        _authority: &crate::execution_mode::SourceChangeAuthority,
    ) -> Result<()> {
        let worker_output = output.clone();
        std::thread::scope(|scope| {
            // All source handles, assessment and SourceCertificate are created
            // and retained in this same worker. Only routing data crosses in.
            let worker = scope.spawn(move || {
                if allocation_bounded {
                    crate::general_conversion::convert_allocation_experimental(
                        &request,
                        budget,
                        &worker_output,
                    )
                } else {
                    crate::general_conversion::convert_compact_experimental(
                        &request,
                        budget,
                        &worker_output,
                    )
                }
            });
            let started = Instant::now();
            let mut previous = "";
            let interactive = io::stdout().is_terminal();
            while !worker.is_finished() {
                let phase = conversion_phase(&output);
                let mut console = io::stdout().lock();
                if !interactive {
                    if phase != previous {
                        let _ = writeln!(
                            console,
                            "{phase} ({}s elapsed)",
                            started.elapsed().as_secs()
                        );
                    }
                    previous = phase;
                    drop(console);
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                if phase != previous && !previous.is_empty() {
                    let _ = writeln!(console);
                }
                let _ = write!(
                    console,
                    "\r{phase} ({}s elapsed)   ",
                    started.elapsed().as_secs()
                );
                let _ = console.flush();
                previous = phase;
                drop(console);
                std::thread::sleep(Duration::from_secs(2));
            }
            let _ = writeln!(io::stdout());
            let result = worker.join().map_err(|panic| {
                let detail = panic
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("unexpected worker panic");
                anyhow::anyhow!("conversion worker panicked: {}", clean(detail))
            })?;
            if result.is_ok() {
                // Completion comes from the actual worker result, never from
                // a filename or a parsed serialized success flag.
                let _ = writeln!(io::stdout(), "Complete");
            }
            result
        })
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
        let mode = args.execution_mode()?;
        if args.unattended()? {
            crate::confirmation::assume_yes();
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
        if let Some(directory) = args.recover {
            // (Not the build: a recovery must run wherever its conversion did.)
            require_elevation("recovery")?;
            let checksum = args
                .recovery_sha256
                .context("original recovery checksum required")?;
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
                || !(args.windows_boot_volume
                    || args.whole_image_verification
                    || args.offline_recovery_media.is_some()
                    || args.experimental_thin_shadow),
            "a {target_cluster}-byte ReFS allocation unit is for a data volume on the default route; a Windows boot volume, whole-image verification, offline media and the thin shadow use 4096"
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
        ensure!(
            selected.partition.contains_running_windows != Some(true),
            "the running Windows partition is not supported for conversion"
        );
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
            return super::partition::convert(&args, selected, before, &authority);
        }
        ensure!(
            args.controlled_post_flush_pause_nonce.is_none()
                && !args.acknowledge_controlled_post_flush_pause,
            "controlled post-flush qualification flags apply only to a data partition sharing the current Windows disk; dedicated conversion does not accept them"
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
            } else { anyhow::anyhow!("selected volume is not an eligible dedicated data volume: {error}") })?;
        ensure!(
            before.filesystem == "NTFS",
            "selected partition must currently be NTFS"
        );
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
        let resources = if !args.whole_image_verification {
            crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(None)
        } else {
            crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2
        };
        let mut events = Vec::new();
        let mut reader =
            n2r_win32::GeneralPartitionReader::open(before.binding.clone(), &mut events)?;
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
        let allocation_bounded = !args.whole_image_verification;
        let verification_policy = if allocation_bounded && !args.verify_full_content {
            crate::verification_policy::VerificationPolicy::ExtentIdentityV1
        } else {
            crate::verification_policy::VerificationPolicy::FullContent
        };
        println!(
            "Mode: {}",
            if allocation_bounded {
                "allocation-bounded (compares and writes only the ranges the new ReFS allocates; free space is not verified)"
            } else {
                "whole-image verification (compares and journals every byte; much slower)"
            }
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
        // volume that would be refused. (A Windows boot volume and the
        // whole-image route are examined when they are frozen, as before.)
        let shrink = match boot_geometry {
            Some(super::boot::GeometryDecision::Shrink { shrink_bytes, .. }) => Some(shrink_bytes),
            _ => None,
        };
        if allocation_bounded && !args.windows_boot_volume {
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
            resources,
            allocation_bounded,
            verification_policy,
            args.minimize_scratch,
            target_format,
            args.experimental_thin_shadow,
            args.experimental_thin_backing_bytes,
            mode,
            boot_geometry,
            listing_root,
        )
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
            externally_enrolled_disk_unique_id: format!(
                "gpt-{}",
                journal.binding.identity.disk_guid.trim_matches(['{', '}'])
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
                    "it is not a data volume on a disk of its own: {error}"
                ));
            }
        };
        let mut events = Vec::new();
        let mut reader =
            n2r_win32::GeneralPartitionReader::open(before.binding.clone(), &mut events)?;
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
        resources: crate::ntfs_admission::ResourceProfile,
        allocation_bounded: bool,
        verification_policy: crate::verification_policy::VerificationPolicy,
        minimize_scratch: bool,
        target_format: n2r_win32::managed_shadow::TargetFormatProfile,
        thin_shadow: bool,
        thin_backing_bytes: Option<u64>,
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
        // Encoded selection stores D old bytes and L literal-new bytes, with
        // a separate L-byte backing (L <= D). Thus backing <= journal / 2.
        // Retain the legacy thirds budget for the whole-image route.
        let usable = space.available_bytes_to_caller - reserve;
        let journal_share = if allocation_bounded {
            // Journal and literal backing share one measured pool. Encoded
            // zeros/copies must not strand an unused fixed backing fraction.
            usable
        } else {
            usable / 3
        };
        let journal_bytes = if allocation_bounded {
            journal_share / 4096 * 4096
        } else {
            journal_share.min(n2r_win32::journal_file::MAX_EXPERIMENTAL_JOURNAL_BYTES) / 4096 * 4096
        };
        let literal_backing_bytes = allocation_bounded.then(|| {
            (usable / 3).min(n2r_win32::reference_file::MAX_REFERENCE_FILE_BYTES) / 4096 * 4096
        });
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
        let native_creation_admission = if thin_shadow {
            None
        } else {
            let admitted =
                n2r_win32::managed_shadow::admit_fresh_native_backing(&run.join("shadow.vhdx"))?;
            save_new(
                &run.join("native-shadow-creation-admission.json"),
                &admitted.observe()?,
            )?;
            Some(admitted)
        };
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
        let staged = if thin_shadow {
            ensure!(
                allocation_bounded,
                "thin temporary storage requires the V4 route"
            );
            ensure!(
                before.binding.identity.logical_sector_bytes == 512
                    && before.binding.identity.physical_sector_bytes == 4096,
                "thin temporary storage has not qualified this sector geometry"
            );
            let available = n2r_win32::resource_native::observe_available_resources(&run)?;
            let planned_carrier = (usable - usable / 3).min(64u64 << 40);
            let carrier_scratch = thin_backing_bytes
                .unwrap_or(planned_carrier)
                .min(planned_carrier)
                / (2 << 20)
                * (2 << 20);
            let provider_bytes = converted_partition_bytes
                .checked_add(64 << 20)
                .context("thin provider geometry overflow")?;
            let owner = n2r_win32::managed_shadow::thin_pool::create_bounded_with_carrier(
                &run.join("thin-provider"),
                &super::staging::windows_storage_subsystem()?,
                provider_bytes,
                n2r_win32::managed_shadow::thin_pool::Budget {
                    rust_ram_bytes: available.available_physical_bytes / 16,
                    powershell_ram_bytes: available.available_physical_bytes / 4,
                    scratch_bytes: carrier_scratch,
                    minimum_free_bytes: reserve,
                },
            )?;
            super::staging::StageOwner::Thin(
                owner.format(converted_partition_bytes, target_format)?,
            )
        } else {
            native_creation_admission
                .as_ref()
                .context("native shadow creation capacity owner absent")?
                .check()?;
            super::staging::StageOwner::Vhdx(n2r_win32::managed_shadow::create_with_profile(
                &run.join("shadow.vhdx"),
                converted_partition_bytes,
                before.binding.identity.logical_sector_bytes,
                before.binding.identity.physical_sector_bytes,
                target_format,
            )?)
        };
        if let Some(admitted) = &native_creation_admission {
            admitted.check()?;
        }
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
        let result = if allocation_bounded {
            super::resource::convert_owned_with_provider_commitment(
                n2r_win32::general_layout::GeneralSourceShadowBinding {
                    source: before.binding.clone(),
                    shadow: staged.binding().clone(),
                },
                n2r_win32::journal_file::GeneralJournalStorageBinding {
                    disk: journal.binding.clone(),
                    externally_enrolled_disk_unique_id: format!(
                        "gpt-{}",
                        journal.binding.identity.disk_guid.trim_matches(['{', '}'])
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
                if thin_shadow { reserve } else { 0 },
                staged.staging_allocation_meter(),
                mode,
            )
        } else {
            let authority = mode.source_change_authority("whole-image conversion")?;
            if minimize_scratch {
                println!("Preparing NTFS file placement to reduce recovery storage.");
                let preparation = crate::ntfs_preparation::prepare(
                    before.binding.clone(),
                    staged.binding().clone(),
                    resources,
                    &run.join("ntfs-preparation"),
                    crate::ntfs_preparation::Budget {
                        metadata_bytes: 64 * 1024 * 1024,
                        receipt_bytes: 64 * 1024 * 1024,
                        maximum_moves: 32768,
                        maximum_move_bytes: 64 * 1024 * 1024,
                        maximum_payload_bytes: before.binding.identity.partition_bytes,
                    },
                )?;
                save_new(&run.join("ntfs-preparation-result.json"), &preparation)?;
            }
            let request = crate::general_conversion::Request {
                verification_policy,
                selected_capacity_policy: if minimize_scratch {
                    crate::selected_capacity::SelectedCapacityPolicy::SourceFreeActualBytesV1
                } else {
                    Default::default()
                },
                schema_version: if allocation_bounded { 3 } else { 2 },
                source_resource_profile: Some(resources),
                experiment_id: id,
                pair: n2r_win32::general_layout::GeneralSourceShadowBinding {
                    source: before.binding.clone(),
                    shadow: staged.binding().clone(),
                },
                journal: n2r_win32::journal_file::GeneralJournalStorageBinding {
                    disk: journal.binding.clone(),
                    externally_enrolled_disk_unique_id: format!(
                        "gpt-{}",
                        journal.binding.identity.disk_guid.trim_matches(['{', '}'])
                    ),
                    allow_additional_partitions: true,
                },
                max_journal_bytes: journal_bytes,
                max_literal_backing_bytes: literal_backing_bytes,
                max_combined_scratch_bytes: allocation_bounded.then_some(usable),
                verify_existing_shadow: false,
            };
            request.validate()?;
            save_new(&run.join("devices.json"), &request)?;
            let output = run.join("conversion");
            let budget = crate::general_qualification::CompactConstructionBudget {
                maximum_placement_bytes: request
                    .pair
                    .source
                    .identity
                    .partition_bytes
                    .saturating_mul(4),
                maximum_placement_submissions:
                    n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS,
                maximum_exception_bytes: 16 * 1024 * 1024,
            };
            // Keep the native attachment owner on this thread until the conversion
            // worker has returned, including error/panic handling.
            convert_with_progress(
                request,
                budget,
                output.clone(),
                allocation_bounded,
                &authority,
            )
            .map(|()| super::resource::ConversionOutcome::Converted)
        };
        let output = run.join("conversion");
        match result {
            Ok(super::resource::ConversionOutcome::Diagnosed(outcome)) => {
                // The shadow was built only to be examined; nothing was
                // published from it, so it is detached and removed.
                let shadow_removed = match staged.retire_after_diagnose() {
                    Some(retirement) => {
                        if !retirement.success() {
                            eprintln!(
                                "Diagnose finished, but its temporary shadow could not be removed (stopped at {}: {}). It remains in {}.",
                                retirement.phase(),
                                retirement.error().unwrap_or("cleanup incomplete"),
                                run.display()
                            );
                        }
                        if let Err(error) =
                            save_new(&run.join("shadow-retirement.json"), &retirement)
                        {
                            eprintln!(
                                "The temporary-shadow cleanup receipt could not be saved: {error}"
                            );
                        }
                        retirement.success()
                    }
                    None => false,
                };
                report_diagnosis(&run, &outcome, shadow_removed)
            }
            Ok(super::resource::ConversionOutcome::Converted) => {
                if allocation_bounded {
                    // This live Ok comes only after V4 HND/native finalization
                    // returned and all construction/raw owners were released.
                    // Its replay is self-contained; legacy compact recovery
                    // still requires its original protected shadow backing.
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
                } else {
                    drop(staged);
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
                    if let Some(way_back) = frozen_source_way_back(&output) {
                        eprintln!("{way_back}");
                    }
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
    fn a_run_that_left_its_source_frozen_is_told_how_to_return_it() {
        use sha2::{Digest, Sha256};
        let run = tempfile::tempdir().unwrap();
        let conversion = run.path().join("conversion");
        std::fs::create_dir_all(conversion.join("qualification")).unwrap();
        // A run that froze nothing has nothing to return.
        assert_eq!(windows::frozen_source_way_back(&conversion), None);
        std::fs::write(conversion.join("conversion-intent.json"), b"intent").unwrap();
        std::fs::write(
            conversion.join("qualification/source-frozen.json"),
            b"frozen",
        )
        .unwrap();
        assert_eq!(windows::frozen_source_way_back(&conversion), None);
        std::fs::write(
            conversion.join("qualification/source-mount-paths.json"),
            b"mounts",
        )
        .unwrap();
        let said = windows::frozen_source_way_back(&conversion).unwrap();
        assert!(said.contains("left offline and read-only"), "{said}");
        assert!(said.contains("ntfs2refs cancel --run-directory"), "{said}");
        for (flag, record) in [
            ("--intent-sha256", &b"intent"[..]),
            ("--frozen-source-sha256", b"frozen"),
            ("--mount-paths-sha256", b"mounts"),
        ] {
            let pin = format!("{flag} {}", hex::encode(Sha256::digest(record)));
            assert!(said.contains(&pin), "{said}");
        }
        let fresh = format!("--output \"{}\"", run.path().join("cancel").display());
        assert!(said.contains(&fresh), "{said}");
        // Once a recovery bundle is published, its recovery command is the way.
        std::fs::write(conversion.join("compact-recovery-bundle.json"), b"{}").unwrap();
        assert_eq!(windows::frozen_source_way_back(&conversion), None);
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
            &["--check", "--whole-image-verification"],
            &["--check", "--experimental-thin-shadow"],
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
        assert_eq!(
            mode(&["--whole-image-verification"]),
            ExecutionMode::Convert
        );
    }

    #[test]
    fn the_parser_rejects_diagnose_with_every_option_it_cannot_honour() {
        let cases: [&[&str]; 7] = [
            &[
                "--lab-hold-at",
                "handoff-sealed",
                "--acknowledge-lab-hold-never-completes",
            ],
            &["--whole-image-verification"],
            &["--minimize-scratch"],
            &["--offline-media", "E:\\"],
            &["--experimental-thin-shadow"],
            &[
                "--experimental-thin-shadow",
                "--experimental-thin-backing-bytes",
                "1073741824",
            ],
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
        let cases: [Set; 8] = [
            |a| a.whole_image_verification = true,
            |a| a.minimize_scratch = true,
            |a| a.offline_recovery_media = Some(PathBuf::from("E:\\")),
            |a| a.controlled_post_flush_pause_nonce = Some(NONCE.to_owned()),
            |a| a.acknowledge_controlled_post_flush_pause = true,
            |a| a.experimental_thin_shadow = true,
            |a| a.experimental_thin_backing_bytes = Some(1 << 30),
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
