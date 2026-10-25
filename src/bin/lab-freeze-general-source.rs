//! Lock/dismount a dedicated NTFS data disk, persist OFFLINE|READ_ONLY and
//! capture its post-flush bytes. No payload write or mount transition follows.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        GeneralFrozenPartition, GeneralPartitionReader, general_layout::GeneralDiskBinding,
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
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"general-ntfs-freeze-intent",
            "binding_sha256":args.binding_sha256,"disk_number":binding.disk_number,
            "source_payload_writes_authorized":false,"conversion_qualified":false}),
    )?;
    let mut source = GeneralFrozenPartition::isolate(binding, &mut events)?;
    let before = source.state(&mut events)?;
    let length = source.byte_len();
    let source_sha256 = hex::encode(lab_reconstruct::hash_range(&mut source, 0, length)?);
    let ntfs = ntfs_inspect::inspect(&mut source, length)?;
    let backups = ntfs_backup::verify(&mut source, length, &ntfs)?;
    let (log_restart, log_restart_error) = match ntfs_log::verify(&mut source, &ntfs) {
        Ok(proof) => (Some(proof), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let after_sha256 = hex::encode(lab_reconstruct::hash_range(&mut source, 0, length)?);
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
            "ntfs":ntfs,"backups":backups,"log_restart":log_restart,
            "log_restart_error":log_restart_error,"events":events,
            "source_payload_writes":0,"source_admitted":false,"conversion_qualified":false}),
    )?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general NTFS source freeze requires Windows");
    std::process::exit(1);
}
