//! Read-only audit of a candidate ReFS metadata overlay. The external writer
//! and Windows-generated base image are never opened with write access.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use ntfs2refs::{refs_cow_overlay::RefsCowOverlay, refs_inspect};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    base: PathBuf,
    #[arg(long)]
    overlay: PathBuf,
    #[arg(long)]
    physical_lcn: u64,
    #[arg(long)]
    expected_sha256: String,
}

#[derive(Serialize)]
struct Report {
    base_bytes: u64,
    overlay_records: usize,
    overlay_written_bytes: u64,
    adopted_physical_lcn: u64,
    adopted_byte_offset: u64,
    adopted_byte_length: u64,
    base_payload_sha256: String,
    merged_payload_sha256: String,
    adopted_payload_not_written: bool,
    refs: refs_inspect::RefsInspection,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut image = RefsCowOverlay::open(&args.base, &args.overlay)?;
    let image_len = image.length();
    let refs = refs_inspect::inspect(&mut image, image_len)?;
    let cluster = u64::from(refs.geometry.bytes_per_cluster);
    let at = args
        .physical_lcn
        .checked_mul(cluster)
        .context("LCN overflow")?;
    ensure!(
        at.checked_add(cluster).is_some_and(|end| end <= image_len),
        "adopted payload outside image"
    );
    let mut original = File::open(&args.base)?;
    original.seek(SeekFrom::Start(at))?;
    let mut base_bytes = vec![0; cluster as usize];
    original.read_exact(&mut base_bytes)?;
    image.seek(SeekFrom::Start(at))?;
    let mut merged_bytes = vec![0; cluster as usize];
    image.read_exact(&mut merged_bytes)?;
    let base_hash = hex::encode(Sha256::digest(&base_bytes));
    let merged_hash = hex::encode(Sha256::digest(&merged_bytes));
    let untouched = !image.writes_overlap(at, cluster)?;
    ensure!(
        base_hash == args.expected_sha256 && merged_hash == base_hash && untouched,
        "adopted physical payload changed or its expected hash differs"
    );
    let report = Report {
        base_bytes: image_len,
        overlay_records: image.writes().len(),
        overlay_written_bytes: image.writes().iter().map(|w| u64::from(w.length)).sum(),
        adopted_physical_lcn: args.physical_lcn,
        adopted_byte_offset: at,
        adopted_byte_length: cluster,
        base_payload_sha256: base_hash,
        merged_payload_sha256: merged_hash,
        adopted_payload_not_written: untouched,
        refs,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
