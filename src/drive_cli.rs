//! Drive-oriented interactive entry. Listing and declining never stage or freeze.
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct DriveArgs {
    /// Show available Windows disks, partition numbers and mounted volumes.
    #[arg(long, conflicts_with_all = ["drive", "partition", "scratch_directory"])]
    pub list: bool,
    /// Drive letter or disk number; also accepts --drive D partition 2.
    #[arg(long, num_args = 1..=3, value_name = "DRIVE", conflicts_with = "list")]
    pub drive: Option<Vec<String>>,
    /// Exact partition number. A letter must already identify that partition.
    #[arg(long, requires = "drive")]
    pub partition: Option<u32>,
    /// Optional working directory on the Windows OS volume.
    #[arg(long, requires = "drive")]
    pub scratch_directory: Option<PathBuf>,
}
impl DriveArgs {
    pub fn requested(&self) -> bool {
        self.list || self.drive.is_some()
    }
}
pub fn run(args: DriveArgs) -> Result<u8> {
    #[cfg(windows)]
    {
        windows::run(args)
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
        io::{self, Read, Write},
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
    fn ordinary_parents(path: &std::path::Path) -> Result<()> {
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
    pub(super) fn run(args: DriveArgs) -> Result<u8> {
        let inventory = drive_inventory::inventory_drives_readonly()?;
        if args.list {
            list(&inventory);
            return Ok(0);
        }
        let values = args.drive.context("drive selection required")?;
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
        let before = discovery::discover(&selected.volume_guid_path, Role::Source)
            .map_err(|error| if error.raw_os_error() == Some(5) {
                anyhow::anyhow!("administrator access is required for conversion; run from an elevated Windows terminal: {error}")
            } else { anyhow::anyhow!("selected volume is not an eligible dedicated data volume: {error}") })?;
        ensure!(
            before.filesystem == "NTFS",
            "selected partition must currently be NTFS"
        );
        let resources = crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2;
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
        println!("Convert this partition to ReFS in place, preserving supported files? [y/N]");
        print!("> ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Cancelled. No conversion started.");
            return Ok(0);
        }
        let current = discovery::discover(&selected.volume_guid_path, Role::Source)?;
        ensure!(
            current.binding == before.binding && current.filesystem == "NTFS",
            "selected drive identity changed while awaiting confirmation"
        );
        convert_selected(args.scratch_directory, before, selected, resources)
    }
    fn convert_selected(
        scratch: Option<PathBuf>,
        before: discovery::VolumeDiscovery,
        selected: drive_inventory::PartitionSelection,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<u8> {
        let system = std::env::var("SystemRoot").context("Windows system path unavailable")?;
        let os_root = format!(
            "{}\\",
            system
                .get(..2)
                .context("Windows system drive unavailable")?
        );
        let journal = discovery::discover(
            &os_root,
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
            "Windows volume lacks working space for the conversion"
        );
        let reserve = (space.available_bytes_to_caller / 4).min(16 * 1024 * 1024 * 1024);
        let journal_bytes = ((space.available_bytes_to_caller - reserve) / 3)
            .min(n2r_win32::journal_file::MAX_EXPERIMENTAL_JOURNAL_BYTES)
            / 4096
            * 4096;
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
                    .is_some_and(|s| s.eq_ignore_ascii_case(&os_root))
                && !text[3..].contains(':')
                && !parent
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir)),
            "scratch directory must be an ordinary path on the Windows OS volume"
        );
        ordinary_parents(&parent)?;
        let run = parent.join(&id);
        fs::create_dir(&run)?;
        save_new(
            &run.join("drive-selection.json"),
            &serde_json::json!({"selected":selected,"source":before,"confirmation":"interactive affirmative","journal_budget_bytes":journal_bytes,"source_write_authority":false}),
        )?;
        println!(
            "Preparing temporary ReFS metadata storage. Recovery files: {}",
            run.display()
        );
        let staged = n2r_win32::managed_shadow::create(
            &run.join("shadow.vhdx"),
            before.binding.identity.partition_bytes,
            before.binding.identity.logical_sector_bytes,
            before.binding.identity.physical_sector_bytes,
        )?;
        let request = crate::general_conversion::Request {
            schema_version: 2,
            source_resource_profile: Some(resources),
            experiment_id: id,
            pair: n2r_win32::general_layout::GeneralSourceShadowBinding {
                source: before.binding.clone(),
                shadow: staged.binding.clone(),
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
            verify_existing_shadow: false,
        };
        request.validate()?;
        save_new(&run.join("devices.json"), &request)?;
        let output = run.join("conversion");
        let result = crate::general_conversion::convert_compact_experimental(
            &request,
            crate::general_qualification::CompactConstructionBudget {
                maximum_placement_bytes: request
                    .pair
                    .source
                    .identity
                    .partition_bytes
                    .saturating_mul(4),
                maximum_placement_submissions:
                    n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS,
                maximum_exception_bytes: 16 * 1024 * 1024,
            },
            &output,
        );
        match result {
            Ok(()) => {
                println!(
                    "Conversion completed. Recovery records: {}",
                    output.display()
                );
                Ok(0)
            }
            Err(e) => {
                eprintln!(
                    "Conversion stopped. Preserve all recovery files at {}",
                    run.display()
                );
                Err(e)
            }
        }
    }
}
