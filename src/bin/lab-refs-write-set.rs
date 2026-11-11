//! Candidate hybrid-image write set from a raw ReFS header probe and native
//! metadata-inclusive allocation map. Optional output writes only new ordinary
//! compact scratch files; source images and volumes are never written.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use n2r_win32::bitmap_layout::AllocationMap;
use ntfs2refs::{refs_hybrid::packed, refs_inspect::RefsInspection, refs_write_set};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
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
    /// Comparison request containing hash-pinned retained ranges (diagnostic).
    #[arg(long, requires_all = ["original", "shadow", "packed_output"])]
    retained_request: Option<PathBuf>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    retained_request_sha256: Option<String>,
}

fn evidence(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "input evidence exceeds bound"
    );
    Ok(bytes)
}

fn hash_range(file: &mut File, range: &refs_write_set::ByteRange) -> Result<String> {
    file.seek(SeekFrom::Start(range.offset))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut left = range.length;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        digest.update(&buffer[..count]);
        left -= count as u64;
    }
    Ok(hex::encode(digest.finalize()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let inspection_bytes = evidence(&args.inspection).context("read ReFS inspection")?;
    let allocation_bytes = evidence(&args.allocation).context("read target allocation")?;
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
    let retained_bytes = args.retained_request.as_deref().map(evidence).transpose()?;
    let retained_request = if let Some(bytes) = &retained_bytes {
        let raw: serde_json::Value = serde_json::from_slice(bytes)?;
        let request: ntfs2refs::retained_compare::RetainedCompareRequest =
            serde_json::from_value(raw.get("comparison").unwrap_or(&raw).clone())?;
        ensure!(
            request.schema_version == 1
                && request.sector_size == 512
                && request.expected_length == plan.partition_bytes
                && request.retained_ranges.len() <= 1024,
            "retained request geometry or budget differs"
        );
        request.retained_ranges
    } else {
        vec![]
    };
    let retained: Vec<_> = retained_request
        .iter()
        .map(|r| refs_write_set::ByteRange {
            offset: r.offset,
            length: r.length,
        })
        .collect();
    let required = packed::required_bytes(&plan, &retained)?;
    for r in &retained {
        ensure!(
            !anchors
                .iter()
                .any(|a| r.offset < a.offset + a.length && a.offset < r.offset + r.length),
            "retained payload overlaps an observed metadata anchor"
        );
    }
    // Reserve a fresh report name before any scratch creation. An interrupted
    // pack leaves an empty report and partial scratch, never a success receipt.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    let packed = if let (Some(source), Some(destination)) = (&args.shadow, &args.packed_output) {
        ensure!(
            required <= args.max_packed_bytes,
            "selected bytes exceed the compact scratch budget"
        );
        let mut shadow = OpenOptions::new().read(true).open(source)?;
        let before = shadow.metadata()?;
        ensure!(
            before.is_file(),
            "compact input must be an ordinary frozen image"
        );
        if !retained.is_empty() {
            let mut original =
                File::open(args.original.as_ref().context("retained source required")?)?;
            let metadata = original.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() == plan.partition_bytes,
                "retained source must be an ordinary same-size image"
            );
            for (range, request) in retained.iter().zip(&retained_request) {
                ensure!(
                    request.source_sha256 == request.shadow_sha256
                        && request.source_sha256.len() == 64
                        && request.source_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                    "retained range requires equal pinned source/shadow hashes"
                );
                ensure!(
                    hash_range(&mut original, range)? == request.source_sha256
                        && hash_range(&mut shadow, range)? == request.shadow_sha256,
                    "retained source or shadow bytes differ from request"
                );
            }
            let after = original.metadata()?;
            ensure!(
                metadata.len() == after.len() && metadata.modified()? == after.modified()?,
                "retained source changed during hashing"
            );
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let receipt = packed::pack_with_retained(&mut shadow, &mut output, &plan, &retained)?;
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
        let mut retained_source = File::open(args.original.as_ref().context("original required")?)?;
        let mut compact = packed::PackedShadow::with_retained(
            &mut backing,
            &mut retained_source,
            &plan,
            &retained,
        )?;
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
        retained_request_sha256: retained_bytes
            .as_ref()
            .map(|b| hex::encode(Sha256::digest(b))),
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
