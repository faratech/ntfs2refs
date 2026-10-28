//! Candidate hybrid-image write set from a raw ReFS header probe and native
//! metadata-inclusive allocation map. No volume or image writes are issued.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use n2r_win32::bitmap_layout::AllocationMap;
use ntfs2refs::{refs_hybrid::packed, refs_inspect::RefsInspection, refs_write_set};
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
    /// Optional frozen ordinary image to compact; never opens a writable volume.
    #[arg(long, requires = "packed_output")]
    shadow: Option<PathBuf>,
    #[arg(long, requires = "shadow")]
    packed_output: Option<PathBuf>,
    /// Refuse before creating scratch when selected bytes exceed this budget.
    #[arg(long, default_value_t = 268435456)]
    max_packed_bytes: u64,
    /// Inspect the hybrid against this ordinary source image after packing.
    #[arg(long, requires = "packed_output")]
    original: Option<PathBuf>,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    kind: &'static str,
    inspection_sha256: String,
    allocation_sha256: String,
    observed_anchors: Vec<refs_write_set::ByteRange>,
    plan: refs_write_set::WriteSetPlan,
    #[serde(skip_serializing_if = "Option::is_none")]
    packed: Option<packed::PackReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hybrid_inspection: Option<RefsInspection>,
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
    // Reserve a fresh report name before any scratch creation. An interrupted
    // pack leaves an empty report and partial scratch, never a success receipt.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    let packed = if let (Some(source), Some(destination)) = (&args.shadow, &args.packed_output) {
        ensure!(
            plan.target_owned_bytes <= args.max_packed_bytes,
            "selected bytes exceed the compact scratch budget"
        );
        let mut shadow = OpenOptions::new().read(true).open(source)?;
        let before = shadow.metadata()?;
        ensure!(
            before.is_file(),
            "compact input must be an ordinary frozen image"
        );
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let receipt = packed::pack(&mut shadow, &mut output, &plan)?;
        output.sync_all()?;
        let after = shadow.metadata()?;
        ensure!(
            before.len() == after.len() && before.modified()? == after.modified()?,
            "shadow changed during compact extraction"
        );
        Some(receipt)
    } else {
        None
    };
    let hybrid_inspection = if let Some(original) = &args.original {
        let mut original = OpenOptions::new().read(true).open(original)?;
        ensure!(
            original.metadata()?.is_file(),
            "hybrid source must be an ordinary image"
        );
        let mut backing = OpenOptions::new().read(true).open(
            args.packed_output
                .as_ref()
                .context("compact backing required")?,
        )?;
        let mut compact = packed::PackedShadow::new(&mut backing, &plan)?;
        let mut hybrid =
            ntfs2refs::refs_hybrid::CandidateHybrid::new(&mut original, &mut compact, &plan)?;
        Some(ntfs2refs::refs_inspect::inspect(
            &mut hybrid,
            plan.partition_bytes,
        )?)
    } else {
        None
    };
    let report = Report {
        schema_version: 1,
        kind: "refs-hybrid-write-set-candidate",
        inspection_sha256: hex::encode(Sha256::digest(&inspection_bytes)),
        allocation_sha256: hex::encode(Sha256::digest(&allocation_bytes)),
        observed_anchors: anchors,
        plan,
        packed,
        hybrid_inspection,
    };
    let output = serde_json::to_vec_pretty(&report)?;
    ensure!(
        output.len() <= 16 * 1024 * 1024,
        "candidate report exceeds bound"
    );
    file.write_all(&output)?;
    file.sync_all()?;
    Ok(())
}
