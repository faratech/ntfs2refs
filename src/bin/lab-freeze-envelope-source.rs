//! Freeze only the enrolled F: lab source for a read-only baseline capture.
//! No whole-image hash, source certificate, journal or protection-clearing API.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        GeneralFrozenPartition, GeneralPartitionReader, capture_mount_paths_general,
        general_layout::GeneralDiskBinding,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        /// Informational lab reference; the host verifies the actual parent.
        #[arg(long)]
        source_checkpoint: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn path(path: &Path, exists: bool) -> Result<()> {
        let text = path.to_str().context("non-Unicode lab path")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains('/')
                && !text.contains("..")
                && !text.ends_with([' ', '.'])
                && path.extension().is_some_and(|s| s == "json"),
            "ordinary C:\\ntfs2refs JSON path required"
        );
        for (index, ancestor) in path.ancestors().enumerate() {
            if index == 0 && !exists {
                ensure!(!ancestor.exists(), "fresh output required");
                continue;
            }
            let meta = fs::symlink_metadata(ancestor)?;
            ensure!(
                meta.file_attributes() & 0x400 == 0
                    && if index == 0 {
                        meta.is_file()
                    } else {
                        meta.is_dir()
                    },
                "lab artifact type or ancestry differs"
            );
        }
        Ok(())
    }
    fn save(pathname: &Path, value: &impl Serialize) -> Result<()> {
        path(pathname, false)?;
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(bytes.len() <= 1024 * 1024, "freeze receipt exceeds 1MiB");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(pathname)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    let args = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME")?.eq_ignore_ascii_case("N2R-WIN11"),
        "enrolled lab guest required"
    );
    ensure!(
        n2r_win32::layout::guid_bytes(&args.source_checkpoint)? != [0; 16],
        "nonzero lab source checkpoint reference required"
    );
    path(&args.binding, true)?;
    path(&args.output, false)?;
    let intent = args.output.with_extension("intent.json");
    path(&intent, false)?;
    ensure!(
        args.binding != args.output,
        "distinct binding and output required"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.binding)?;
    ensure!(input.metadata()?.len() <= 16_384, "binding exceeds 16KiB");
    let mut bytes = Vec::new();
    (&mut input).take(16_385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16_384
            && args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    binding.validate()?;
    let identity = &binding.identity;
    ensure!(
        binding.disk_number == 1
            && binding
                .volume_guid
                .eq_ignore_ascii_case("f06075a8-67a2-46b9-8fac-4af4da809617")
            && identity
                .disk_guid
                .eq_ignore_ascii_case("1b191872-c372-41ee-a416-e18863996f54")
            && identity
                .partition_guid
                .eq_ignore_ascii_case("f06075a8-67a2-46b9-8fac-4af4da809617")
            && identity.disk_bytes == 64 * 1024 * 1024 * 1024
            && identity.partition_number == 2
            && identity.partition_offset == 16 * 1024 * 1024
            && identity.partition_bytes == 52 * 1024 * 1024 * 1024
            && identity.logical_sector_bytes == 512
            && identity.physical_sector_bytes == 4096,
        "exact enrolled mixed F: source required"
    );
    let mut events = Vec::new();
    let mut online = GeneralPartitionReader::open(binding.clone(), &mut events)?;
    let mut boot = [0; 512];
    online.read_exact(&mut boot)?;
    let geometry = ntfs2refs::ntfs_inspect::inspect_boot_sector(&boot, online.byte_len())?;
    ensure!(geometry.cluster_size == 65_536, "NTFS64KiB source required");
    let online_read_bytes = online.native_bytes_read;
    online.revalidate_route(&mut events)?;
    drop(online);
    let mounts = capture_mount_paths_general(binding.clone(), &mut events)?;
    ensure!(
        mounts.paths.iter().any(|p| p == "F:\\"),
        "source F: mount required"
    );
    save(
        &intent,
        &serde_json::json!({
            "kind":"lab-readonly-baseline-freeze-intent", "binding":binding,
            "binding_sha256":args.binding_sha256, "source_checkpoint":args.source_checkpoint,
            "checkpoint_is_host_verified_lab_reference":true,
            "source_payload_writes_authorized":false, "grants_conversion_authority":false
        }),
    )?;
    // This existing API locks, flushes/dismounts and persistently excludes the
    // disk. Its returned handle has no Write implementation; dropping leaves3.
    let mut frozen = GeneralFrozenPartition::isolate(binding.clone(), &mut events)?;
    let before = frozen.state(&mut events)?;
    let mut after_boot = [0; 512];
    frozen.read_exact(&mut after_boot)?;
    let after = frozen.state(&mut events)?;
    ensure!(
        before == after && after.disk_attributes == 3 && boot == after_boot,
        "frozen source state or NTFS boot identity differs"
    );
    save(
        &args.output,
        &serde_json::json!({
            "schema_version":1, "kind":"lab-readonly-baseline-source-frozen",
            "binding":binding, "binding_sha256":args.binding_sha256,
            "source_checkpoint":args.source_checkpoint, "before":before, "after":after,
            "mount_paths_before":mounts, "geometry":geometry,
            "boot_sector_sha256":hex::encode(Sha256::digest(boot)),
            "requested_boot_bytes_read":1024,
            "native_bytes_read":online_read_bytes + frozen.native_bytes_read(),
            "whole_image_hashed":false, "source_payload_bytes_read":0,
            "source_payload_writes":0, "source_certificate_issued":false,
            "grants_conversion_authority":false, "protection_cleared":false, "events":events
        }),
    )?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the enrolled lab baseline source freeze requires Windows");
    std::process::exit(1);
}
