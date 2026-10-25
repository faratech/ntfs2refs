//! Candidate hybrid-image write set from a raw ReFS header probe and native
//! metadata-inclusive allocation map. No volume or image writes are issued.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use n2r_win32::bitmap_layout::AllocationMap;
use ntfs2refs::{refs_inspect::RefsInspection, refs_write_set};
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
    inspection: PathBuf,
    #[arg(long)]
    allocation: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    kind: &'static str,
    inspection_sha256: String,
    allocation_sha256: String,
    observed_anchors: Vec<refs_write_set::ByteRange>,
    plan: refs_write_set::WriteSetPlan,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let inspection_bytes = fs::read(&args.inspection).context("read ReFS inspection")?;
    let allocation_bytes = fs::read(&args.allocation).context("read target allocation")?;
    ensure!(
        inspection_bytes.len() <= 16 * 1024 * 1024 && allocation_bytes.len() <= 16 * 1024 * 1024,
        "input evidence exceeds bound"
    );
    let raw_inspection: serde_json::Value = serde_json::from_slice(&inspection_bytes)?;
    let inspection: RefsInspection =
        serde_json::from_value(if raw_inspection.get("geometry").is_some() {
            raw_inspection
        } else {
            ensure!(
                raw_inspection["filesystem"]["filesystem"] == "Refs",
                "ReFS inspection required"
            );
            raw_inspection["filesystem"]["details"].clone()
        })?;
    let raw_allocation: serde_json::Value = serde_json::from_slice(&allocation_bytes)?;
    let allocation: AllocationMap =
        serde_json::from_value(if raw_allocation.get("native").is_some() {
            ensure!(
                raw_allocation["success"] == true,
                "successful native shadow report required"
            );
            raw_allocation["native"]["metadata_allocation"].clone()
        } else {
            raw_allocation
        })?;
    let anchors = refs_write_set::observed_anchors(&inspection)?;
    let plan = refs_write_set::plan(
        inspection.geometry.volume_bytes,
        u64::from(inspection.geometry.bytes_per_cluster),
        &allocation,
        &anchors,
    )?;
    let report = Report {
        schema_version: 1,
        kind: "refs-hybrid-write-set-candidate",
        inspection_sha256: hex::encode(Sha256::digest(&inspection_bytes)),
        allocation_sha256: hex::encode(Sha256::digest(&allocation_bytes)),
        observed_anchors: anchors,
        plan,
    };
    let output = serde_json::to_vec_pretty(&report)?;
    ensure!(
        output.len() <= 16 * 1024 * 1024,
        "candidate report exceeds bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    file.write_all(&output)?;
    file.sync_all()?;
    Ok(())
}
