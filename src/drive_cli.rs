//! Drive-oriented interactive entry. Listing and declining never stage or freeze.
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::PathBuf;

#[cfg(windows)]
#[path = "drive_boot.rs"]
mod boot;
#[cfg(windows)]
#[path = "drive_partition.rs"]
mod partition;
#[cfg(windows)]
#[path = "drive_resource.rs"]
mod resource;
#[cfg(windows)]
#[path = "drive_staging.rs"]
mod staging;

#[derive(Args, Debug)]
pub struct DriveArgs {
    /// Show available Windows disks, partition numbers and mounted volumes.
    #[arg(long, conflicts_with_all = ["drive", "partition", "scratch_directory", "recover", "recovery_sha256", "rollback"])]
    pub list: bool,
    /// Drive letter or disk number; also accepts --drive D partition 2.
    #[arg(long, num_args = 1..=3, value_name = "DRIVE", conflicts_with_all = ["list", "recover", "recovery_sha256", "rollback"])]
    pub drive: Option<Vec<String>>,
    /// Exact partition number. A letter must already identify that partition.
    #[arg(long, requires = "drive")]
    pub partition: Option<u32>,
    /// Working directory; shared-disk conversion requires a different physical disk.
    #[arg(long, requires = "drive")]
    pub scratch_directory: Option<PathBuf>,
    /// Mounted Windows installation-media directory for offline shared-disk conversion.
    #[arg(long = "offline-media", requires = "drive")]
    pub offline_recovery_media: Option<PathBuf>,
    /// Convert an offline Windows installation from a different physical
    /// Windows boot disk. The running Windows volume remains excluded.
    #[arg(long, requires="drive", conflicts_with_all=["offline_recovery_media","whole_image_verification","experimental_thin_shadow"])]
    pub windows_boot_volume: bool,
    /// Native target format: dev-drive (experimental default) or standard ReFS.
    /// Standard formatting must be supported by Windows; no fallback is used.
    #[arg(long, requires = "drive", value_parser = ["dev-drive", "standard"])]
    pub target_format: Option<String>,
    /// Recover an interrupted run using its original saved conversion directory.
    #[arg(long, requires = "recovery_sha256", conflicts_with_all = ["list", "drive", "partition", "scratch_directory"])]
    pub recover: Option<PathBuf>,
    /// Original recovery or preparation SHA-256 printed before source changes.
    #[arg(long, requires = "recover")]
    pub recovery_sha256: Option<String>,
    /// Continue prepublication preparation on a different independent local
    /// volume. Saved source evidence and the existing shadow are reused.
    #[arg(long, requires = "recover", conflicts_with = "rollback")]
    pub resume_workspace: Option<PathBuf>,
    /// Restore NTFS, or cancel unfinished preparation, before handoff only.
    #[arg(long, requires = "recover")]
    pub rollback: bool,
    /// Accepted for compatibility: allocation-bounded conversion is the default.
    #[arg(long, requires = "drive", hide = true)]
    pub experimental_allocation_bounded: bool,
    /// Compare and journal the complete source and ReFS images instead of only
    /// the ranges the new ReFS allocates. Much slower; also proves that free
    /// space is unchanged.
    #[arg(
        long,
        requires = "drive",
        conflicts_with = "experimental_allocation_bounded"
    )]
    pub whole_image_verification: bool,
    /// Verify complete logical contents of every stream. Extent-identity fast
    /// verification is the allocation-bounded default; full mode stays available.
    #[arg(long, requires = "drive")]
    pub verify_full_content: bool,
    /// Experimental: reduce recovery storage by leaving unused NTFS space unrestored on
    /// rollback. Requires fast verification and no VSS snapshots/diff areas.
    #[arg(long, requires = "drive", conflicts_with_all = ["whole_image_verification", "verify_full_content"])]
    pub minimize_scratch: bool,
    /// Build the complete ReFS shadow, report every per-object failure instead
    /// of stopping at the first, then stop before anything is published or
    /// written to the source. The source volume is left as NTFS.
    #[arg(long, requires = "drive", conflicts_with_all = ["list", "recover", "rollback"])]
    pub diagnose: bool,
    /// Re-read every working file and the whole source at every checkpoint
    /// instead of once, immediately before the first write to the source.
    /// Much slower; the result is the same.
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
impl DriveArgs {
    pub fn requested(&self) -> bool {
        self.list || self.drive.is_some() || self.recover.is_some()
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
            .map_err(|_| anyhow::anyhow!("drive worker panicked; preserve its recovery records"))?
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
                if part.contains_running_windows == Some(true) {
                    notes.push("running Windows".into());
                }
                if part.offline == Some(true) {
                    notes.push("offline".into());
                }
                if part.read_only == Some(true) {
                    notes.push("read-only".into());
                }
                if let Some(reason) = &part.unsupported_reason {
                    notes.push(clean(reason));
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
            eprintln!("Some devices could not be queried; see the inventory errors above.");
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
                fs::create_dir(p)?;
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

    fn convert_with_progress(
        request: crate::general_conversion::Request,
        budget: crate::general_qualification::CompactConstructionBudget,
        output: PathBuf,
        allocation_bounded: bool,
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
    // Same bounded affirmative confirmation for both actual source scopes.
    pub(super) fn confirm(prompt: &str) -> Result<bool> {
        println!("{prompt}");
        print!("> ");
        io::stdout().flush()?;
        let input = io::stdin();
        let mut bounded = input.lock().take(65);
        let mut answer = String::new();
        bounded.read_line(&mut answer)?;
        drop(bounded);
        Ok(answer.len() < 65 && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
    }
    pub(super) fn run(args: DriveArgs) -> Result<u8> {
        if let Some(directory) = args.recover {
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
        let inventory = drive_inventory::inventory_drives_readonly()?;
        if args.list {
            list(&inventory);
            return Ok(0);
        }
        let values = args.drive.as_ref().context("drive selection required")?;
        let drive = values.first().context("drive value required")?;
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
        ensure!(
            selected.partition.filesystem.as_deref() != Some("ReFS"),
            "selected partition is already ReFS"
        );
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
            let before = discovery::discover(
                &selected.volume_guid_path,
                Role::Journal {
                    allow_additional_partitions: true,
                },
            )?;
            return super::partition::convert(&args, selected, before);
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
        if args.windows_boot_volume {
            ensure!(
                args.target_format.as_deref().unwrap_or("dev-drive") == "dev-drive",
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
        if args.windows_boot_volume {
            super::boot::validate(&before.binding)?;
        }
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
        let target_format: n2r_win32::managed_shadow::TargetFormatProfile = args
            .target_format
            .as_deref()
            .unwrap_or("dev-drive")
            .parse()?;
        println!(
            "Requested target: {} (ReFS, 4 KiB clusters).",
            if target_format.is_dev_drive() {
                "Dev Drive; experimental default"
            } else {
                "standard ReFS; Windows formatter support required"
            }
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
        if args.windows_boot_volume {
            super::boot::describe_geometry(&before.binding);
        }
        if args.diagnose {
            crate::resource_preparation::set_diagnose();
            println!(
                "Diagnose mode: every per-object failure is reported and nothing is written to the source."
            );
        }
        if args.recheck_everything {
            crate::resource_preparation::set_recheck_everything();
        }
        if !confirm("Convert this partition to ReFS in place, preserving supported files? [y/N]")? {
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
        )
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
    ) -> Result<u8> {
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
        // Working storage (run records, shadow VHDX, journal) lives on the
        // volume that holds the scratch directory. It defaults to the Windows
        // volume but may be any local volume on a disk other than the source,
        // so a large shadow cannot fill the running operating system's disk.
        let work_root = match &scratch {
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
            journal.binding.disk_number != before.binding.disk_number,
            "working storage must be independent of the source disk"
        );
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
        let mut hash = Sha256::new();
        hash.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
                .to_le_bytes(),
        );
        hash.update(std::process::id().to_le_bytes());
        let id = hex::encode(hash.finalize())[..32].to_owned();
        let parent = scratch
            .unwrap_or_else(|| PathBuf::from(format!("{}ProgramData\\ntfs2refs\\runs", os_root)));
        let text = parent.to_str().context("Unicode scratch path required")?;
        ensure!(
            parent.is_absolute()
                && text
                    .get(..3)
                    .is_some_and(|s| s.eq_ignore_ascii_case(&work_root))
                && !text[3..].contains(':')
                && !parent
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir)),
            "scratch directory must be an ordinary path on its working volume"
        );
        ordinary_parents(&parent)?;
        let run = parent.join(&id);
        fs::create_dir(&run)?;
        save_new(
            &run.join("drive-selection.json"),
            &serde_json::json!({"selected":selected,"source":before,"confirmation":"interactive affirmative","journal_budget_bytes":journal_bytes,"requested_target_format":target_format,"explicit_trust_or_filter_configuration_requested":false,"source_write_authority":false}),
        )?;
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
        let before = if before.binding.layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        {
            super::boot::normalize_geometry(before, &run)?
        } else {
            before
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
            let provider_bytes = before
                .binding
                .identity
                .partition_bytes
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
                owner.format(before.binding.identity.partition_bytes, target_format)?,
            )
        } else {
            native_creation_admission
                .as_ref()
                .context("native shadow creation capacity owner absent")?
                .check()?;
            super::staging::StageOwner::Vhdx(n2r_win32::managed_shadow::create_with_profile(
                &run.join("shadow.vhdx"),
                before.binding.identity.partition_bytes,
                before.binding.identity.logical_sector_bytes,
                before.binding.identity.physical_sector_bytes,
                target_format,
            )?)
        };
        if let Some(admitted) = &native_creation_admission {
            admitted.check()?;
        }
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
            )
        } else {
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
            convert_with_progress(request, budget, output.clone(), allocation_bounded)
        };
        let output = run.join("conversion");
        match result {
            Ok(()) => {
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
                eprintln!(
                    "Conversion stopped. Preserve all recovery files at {}",
                    run.display()
                );
                Err(e)
            }
        }
    }
}
