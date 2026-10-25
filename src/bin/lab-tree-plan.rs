//! Assemble the measured ordinary-tree journal request. The resulting JSON is
//! only an input: the owning-guest executor reopens and hashes both partitions
//! before any journaled target write.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use n2r_win32::{journal_file::JournalStorageBinding, layout::DiskBinding};
use ntfs2refs::{lab_tree_reconstruct::Request, retained_compare::RetainedCompareRequest};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(about = "Assemble a bounded ordinary-tree conversion request from measured bindings")]
struct Args {
    #[arg(long)]
    source_binding: PathBuf,
    #[arg(long)]
    shadow_binding: PathBuf,
    #[arg(long)]
    comparison: PathBuf,
    #[arg(long)]
    journal_binding: PathBuf,
    #[arg(long)]
    experiment_id: String,
    #[arg(long)]
    max_journal_bytes: u64,
    #[arg(long)]
    output: PathBuf,
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 131072,
        "bounded plain JSON file required: {}",
        path.display()
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn main() -> Result<()> {
    let args = Args::parse();
    let request = Request {
        schema_version: 3,
        experiment_id: args.experiment_id,
        source: read::<DiskBinding>(&args.source_binding).context("source binding")?,
        shadow: read::<DiskBinding>(&args.shadow_binding).context("shadow binding")?,
        comparison: read::<RetainedCompareRequest>(&args.comparison)
            .context("frozen comparison")?,
        journal: read::<JournalStorageBinding>(&args.journal_binding)
            .context("external journal binding")?,
        max_journal_bytes: args.max_journal_bytes,
    };
    request.validate()?;
    let bytes = serde_json::to_vec_pretty(&request)?;
    ensure!(
        bytes.len() <= 131072,
        "request exceeds executor input budget"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!("{}", hex::encode(Sha256::digest(bytes)));
    Ok(())
}
