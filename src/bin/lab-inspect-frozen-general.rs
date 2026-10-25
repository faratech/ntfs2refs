//! Read-only basis for an already excluded dedicated NTFS data disk. This
//! command cannot isolate, write, repair, mount or admit the source.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, general_layout::GeneralDiskBinding};
    use ntfs2refs::{
        lab_reconstruct, ntfs_backup, ntfs_inspect, ntfs_log, ntfs_stream_plan, shadow_tree,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
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
        #[arg(long)]
        ordinary_tree: bool,
    }
    #[derive(Serialize)]
    struct Report {
        schema_version: u32,
        kind: &'static str,
        binding_sha256: String,
        source_sha256: String,
        before: n2r_win32::GeneralDiskState,
        after: n2r_win32::GeneralDiskState,
        ntfs: ntfs_inspect::NtfsInspection,
        backups: ntfs_backup::VerifiedBackups,
        log_restart: Option<ntfs_log::VerifiedRestart>,
        log_restart_error: Option<String>,
        stream_plan: ntfs_stream_plan::Plan,
        ordinary_tree: Option<shadow_tree::Tree>,
        ordinary_tree_refusal: Option<String>,
        native_bytes_read: u64,
        events: Vec<n2r_win32::NativeEvent>,
        source_frozen: bool,
        source_admitted: bool,
        conversion_qualified: bool,
    }
    let args = Args::parse();
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16384,
        "bounded ordinary binding required"
    );
    let bytes = fs::read(&args.binding)?;
    ensure!(
        args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(binding, &mut events)?;
    let before = source.state(&mut events)?;
    let length = source.byte_len();
    let hash = lab_reconstruct::hash_range(&mut source, 0, length)?;
    let ntfs = ntfs_inspect::inspect(&mut source, length)?;
    let backups = ntfs_backup::verify(&mut source, length, &ntfs)?;
    let (log_restart, log_restart_error) = match ntfs_log::verify(&mut source, &ntfs) {
        Ok(proof) => (Some(proof), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let stream_plan = ntfs_stream_plan::classify(&ntfs);
    let (ordinary_tree, ordinary_tree_refusal) = if args.ordinary_tree {
        match shadow_tree::derive_ordinary(&ntfs) {
            Ok(tree) => (Some(tree), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        }
    } else {
        (None, None)
    };
    let after_hash = lab_reconstruct::hash_range(&mut source, 0, length)?;
    ensure!(hash == after_hash, "excluded NTFS source bytes changed");
    let after = source.state(&mut events)?;
    ensure!(
        before == after,
        "excluded disk route changed during inspection"
    );
    let report = Report {
        schema_version: 1,
        kind: "general-frozen-ntfs-read-only-basis",
        binding_sha256: args.binding_sha256,
        source_sha256: hex::encode(hash),
        before,
        after,
        ntfs,
        backups,
        log_restart,
        log_restart_error,
        stream_plan,
        ordinary_tree,
        ordinary_tree_refusal,
        native_bytes_read: source.native_bytes_read(),
        events,
        source_frozen: true,
        source_admitted: false,
        conversion_qualified: false,
    };
    let output = serde_json::to_vec_pretty(&report)?;
    ensure!(
        output.len() <= 64 * 1024 * 1024,
        "basis report exceeds bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    file.write_all(&output)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("frozen data-disk inspection requires Windows");
    std::process::exit(1);
}
