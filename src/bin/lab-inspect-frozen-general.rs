//! Read-only basis for an already excluded dedicated NTFS data disk. This
//! command cannot isolate, write, repair, mount or admit the source.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, general_layout::GeneralDiskBinding};
    use ntfs2refs::{
        lab_reconstruct, ntfs_attestation, ntfs_backup, ntfs_inspect, ntfs_log, ntfs_stream_plan,
        shadow_tree,
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
        /// Temporarily publish a write-protected NTFS mount for native file
        /// evidence, then restore persistent offline/read-only exclusion.
        #[arg(long)]
        native: bool,
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
        canonical_inspection_sha256: String,
        native: Option<serde_json::Value>,
        native_comparison: Option<ntfs_attestation::Comparison>,
        native_error: Option<String>,
        native_bytes_read: u64,
        events: Vec<n2r_win32::NativeEvent>,
        source_frozen: bool,
        source_admitted: bool,
        conversion_qualified: bool,
    }
    let args = Args::parse();
    ensure!(!args.output.exists(), "fresh frozen-source output required");
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
    let canonical_inspection_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&ntfs)?));
    let observed = if args.native {
        let intent = args.output.with_extension("intent.json");
        ensure!(!intent.exists(), "fresh native observation intent required");
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":1,"kind":"general-frozen-native-observation-intent",
            "source_sha256":hex::encode(hash),
            "canonical_inspection_sha256":canonical_inspection_sha256.clone(),
            "source_writes_authorized":false,"conversion_qualified":false
        }))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(intent)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let request = ntfs_attestation::request_for_general_inspection(
            &ntfs,
            &canonical_inspection_sha256,
            source.binding(),
        )?;
        Some(source.observe_ntfs_files(&request, &mut events))
    } else {
        None
    };
    let after_hash = lab_reconstruct::hash_range(&mut source, 0, length)?;
    ensure!(hash == after_hash, "excluded NTFS source bytes changed");
    let after = source.state(&mut events)?;
    ensure!(
        before == after,
        "excluded disk route changed during inspection"
    );
    let (native, native_comparison, native_error) = match observed {
        Some(Ok(observation)) => {
            let comparison = ntfs_attestation::compare(
                &ntfs,
                &canonical_inspection_sha256,
                observation.report(),
            );
            let native = Some(serde_json::to_value(observation.report())?);
            match comparison {
                Ok(comparison) => (native, Some(comparison), None),
                Err(error) => (native, None, Some(format!("{error:#}"))),
            }
        }
        Some(Err(error)) => (None, None, Some(error.to_string())),
        None => (None, None, None),
    };
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
        canonical_inspection_sha256,
        native,
        native_comparison,
        native_error,
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
