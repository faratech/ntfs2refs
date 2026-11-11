//! Lock/dismount a dedicated NTFS data disk, persist OFFLINE|READ_ONLY and
//! capture its post-flush bytes. No payload write or mount transition follows.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        GeneralFrozenPartition, GeneralPartitionReader, capture_mount_paths_general,
        general_layout::GeneralDiskBinding,
    };
    use ntfs2refs::{lab_reconstruct, ntfs_backup, ntfs_inspect, ntfs_log};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        output: PathBuf,
        /// Collect live native evidence in the same process as the actual
        /// observed freeze. Reopened reports cannot supply this witness.
        #[arg(long)]
        native: bool,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "source freeze report exceeds bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    let intent = args.output.with_extension("intent.json");
    ensure!(
        !args.output.exists() && !intent.exists(),
        "fresh source freeze report and intent required"
    );
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 16384,
        "bounded ordinary source binding required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.binding)?;
    let mut bytes = Vec::new();
    (&mut file).take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16384
            && args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "source binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    binding.validate()?;
    let mut events = Vec::new();
    let mut online = GeneralPartitionReader::open(binding.clone(), &mut events)?;
    let mut boot = [0u8; 512];
    online.read_exact(&mut boot)?;
    let geometry = ntfs_inspect::inspect_boot_sector(&boot, online.byte_len())?;
    ensure!(
        geometry.cluster_size == 4096 && geometry.bytes_per_sector == 512,
        "initial general NTFS source geometry differs"
    );
    online.revalidate_route(&mut events)?;
    drop(online);
    let mount_paths = capture_mount_paths_general(binding.clone(), &mut events)?;
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"general-ntfs-freeze-intent",
            "binding_sha256":args.binding_sha256,"disk_number":binding.disk_number,
            "mount_paths":mount_paths.paths,
            "source_payload_writes_authorized":false,"conversion_qualified":false}),
    )?;
    let mut source = if args.native {
        GeneralFrozenPartition::isolate_observed_ntfs(binding, &mut events)?
    } else {
        GeneralFrozenPartition::isolate(binding, &mut events)?
    };
    let before = source.state(&mut events)?;
    let length = source.byte_len();
    let source_sha256 = hex::encode(lab_reconstruct::hash_range(&mut source, 0, length)?);
    let ntfs = ntfs_inspect::inspect(&mut source, length)?;
    let backups = ntfs_backup::verify(&mut source, length, &ntfs)?;
    let (log_restart, log_restart_error) = match ntfs_log::verify(&mut source, &ntfs) {
        Ok(proof) => (Some(proof), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let canonical_pin = hex::encode(Sha256::digest(serde_json::to_vec(&ntfs)?));
    let (live_assessment, native_error) = if args.native {
        let request = ntfs2refs::ntfs_attestation::request_for_fresh_general_inspection(
            &ntfs,
            &canonical_pin,
            source.binding(),
            None,
            ntfs2refs::verification_policy::VerificationPolicy::FullContent,
        )?;
        match source.observe_ntfs_files(&request, &mut events) {
            Ok(observed) => match ntfs2refs::general_source_admission::assess(
                &mut source,
                &ntfs,
                &canonical_pin,
                &source_sha256,
                &backups,
                log_restart.as_ref(),
                &observed,
                &mut events,
            ) {
                Ok(assessment) => (Some(assessment), None),
                Err(error) => (None, Some(format!("{error:#}"))),
            },
            Err(error) => (None, Some(error.to_string())),
        }
    } else {
        (None, None)
    };
    let after_sha256 = if let Some(assessment) = &live_assessment {
        assessment.source_sha256.clone()
    } else {
        hex::encode(lab_reconstruct::hash_range(&mut source, 0, length)?)
    };
    let after = source.state(&mut events)?;
    ensure!(
        before == after && source_sha256 == after_sha256,
        "frozen source changed during inspection"
    );
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-frozen-ntfs-source",
            "binding_sha256":args.binding_sha256,"source_sha256":source_sha256,
            "before":before,"after":after,
            "mount_paths":mount_paths,
            "ntfs":ntfs,"backups":backups,"log_restart":log_restart,
            "log_restart_error":log_restart_error,"events":events,
            "canonical_inspection_sha256":canonical_pin,"live_assessment":live_assessment,"native_error":native_error,
            "source_payload_writes":0,"source_admitted":false,"conversion_qualified":false}),
    )?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general NTFS source freeze requires Windows");
    std::process::exit(1);
}
