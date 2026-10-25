//! Pinned report replay. Never opens a disk, binds a live source or issues a
//! certificate. Strict comparison remains alongside the conditional views.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
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
fn pinned(path: &Path, pin: &str) -> Result<serde_json::Value> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 64 * 1024 * 1024,
        "bounded ordinary replay input required"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024 * 1024 && hex::encode(Sha256::digest(&bytes)) == pin,
        "replay pin differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn save(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        "replay output exceeds bound"
    );
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(!args.output.exists(), "fresh replay output required");
    let basis = pinned(&args.basis, &args.basis_sha256)?;
    let native = pinned(&args.native, &args.native_sha256)?;
    let raw: ntfs2refs::ntfs_inspect::NtfsInspection =
        serde_json::from_value(basis.get("ntfs").context("NTFS basis absent")?.clone())?;
    let report: n2r_win32::attestation::Report = serde_json::from_value(
        native
            .get("native_observation")
            .and_then(|v| v.get("report"))
            .context("native file report absent")?
            .clone(),
    )?;
    let pin = hex::encode(Sha256::digest(serde_json::to_vec(&raw)?));
    let comparison = ntfs2refs::ntfs_attestation::compare(&raw, &pin, &report)?;
    let views = ntfs2refs::ntfs_source_view::diagnose(&raw, &pin, &report)?;
    let mut tree = ntfs2refs::shadow_tree::derive_ordinary(&raw)?;
    tree.bind_security_views(&views)?;
    let expected = ntfs2refs::shadow_tree::ExpectedTree::from(&tree);
    expected.validate()?;
    fs::create_dir(&args.output)?;
    save(&args.output.join("strict.json"), &comparison)?;
    save(&args.output.join("views.json"), &views)?;
    save(&args.output.join("tree.json"), &expected)?;
    let summary = serde_json::json!({"schema_version":1,"kind":"conditional-source-view-replay",
        "basis_sha256":args.basis_sha256,"native_sha256":args.native_sha256,"inspection_sha256":pin,
        "objects":tree.objects.len(),"api_projection_objects":tree.objects.iter().filter(|o|o.api_security.is_some()).count(),
        "all_user_views_compatible":views.all_user_views_compatible,"source_admitted":false,"execution_authorized":false});
    save(&args.output.join("summary.json"), &summary)?;
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}
