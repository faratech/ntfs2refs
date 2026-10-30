//! Replay pinned source metadata only; no disk opener, live binding or authority.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    basis: PathBuf,
    #[arg(long)]
    basis_sha256: String,
    #[arg(long)]
    native: PathBuf,
    #[arg(long)]
    native_sha256: String,
    #[arg(long)]
    output: PathBuf,
}
fn load<T: DeserializeOwned>(path: &PathBuf, pin: &str) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= 64 * 1024 * 1024,
        "bounded ordinary JSON required"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "reparse input refused"
        );
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len() && hex::encode(Sha256::digest(&bytes)) == pin,
        "metadata length or pin differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn main() -> Result<()> {
    let args = Args::parse();
    let basis: serde_json::Value = load(&args.basis, &args.basis_sha256)?;
    let raw: ntfs2refs::ntfs_inspect::NtfsInspection = serde_json::from_value(
        basis
            .get("ntfs")
            .context("source basis lacks NTFS inventory")?
            .clone(),
    )?;
    let native: n2r_win32::attestation::Report = load(&args.native, &args.native_sha256)?;
    let inspection = hex::encode(Sha256::digest(serde_json::to_vec(&raw)?));
    ensure!(
        basis["canonical_inspection_sha256"] == inspection,
        "canonical source inventory pin differs"
    );
    let comparison = ntfs2refs::ntfs_attestation::compare(&raw, &inspection, &native)?;
    let views = ntfs2refs::ntfs_source_view::diagnose(&raw, &inspection, &native)?;
    let assessment = ntfs2refs::ntfs_admission::assess_ordinary_with_resource_profile(
        &raw,
        &comparison,
        native.schema_version,
        None,
        ntfs2refs::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2,
    );
    let report = serde_json::json!({"kind":"saved-source-diagnostics","schema_version":1,
        "basis_sha256":args.basis_sha256,"native_sha256":args.native_sha256,
        "comparison":comparison,"views":views,"assessment_without_live_view":assessment,
        "source_admitted":false,"live_source_bound":false,"conversion_authorized":false});
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        bytes.len() <= 64 * 1024 * 1024,
        "diagnostic report exceeds bound"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"output":args.output,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),"live_source_bound":false})
    );
    Ok(())
}
