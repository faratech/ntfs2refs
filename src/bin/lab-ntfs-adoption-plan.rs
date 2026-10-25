//! Read-only physical-range classification for a frozen ordinary NTFS source.
//! A separately verified ReFS occupancy map is required before any adoption.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use ntfs2refs::{
    extent_adoption::{self, PhysicalRange},
    ntfs_inspect::NtfsInspection,
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
    inspection: PathBuf,
    /// Sorted occupied physical byte ranges from an independent target view.
    #[arg(long)]
    occupied: PathBuf,
    #[arg(long, default_value_t = 4096)]
    refs_cluster: u32,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct FilePlan {
    record_number: u64,
    sequence_number: u16,
    path: Vec<String>,
    stream: extent_adoption::StreamPlan,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    kind: &'static str,
    inspection_sha256: String,
    occupied_sha256: String,
    target_occupied_ranges: usize,
    files: Vec<FilePlan>,
    adopted_logical_bytes: u64,
    relocated_logical_bytes: u64,
    materialized_logical_bytes: u64,
    sparse_logical_bytes: u64,
    executable: bool,
    pending: Vec<&'static str>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let inspected = fs::read(&args.inspection).context("read source inspection")?;
    let occupancy = fs::read(&args.occupied).context("read target occupancy")?;
    ensure!(
        inspected.len() <= 16 * 1024 * 1024 && occupancy.len() <= 1024 * 1024,
        "input evidence size exceeds laboratory bound"
    );
    let value: serde_json::Value = serde_json::from_slice(&inspected)?;
    let source_partition_bytes = value["source"]["length"].as_u64();
    let raw_value = if value.get("files").is_some() {
        value
    } else {
        ensure!(
            value["filesystem"]["filesystem"] == "Ntfs",
            "NTFS inspection required"
        );
        value["filesystem"]["details"].clone()
    };
    let raw: NtfsInspection = serde_json::from_value(raw_value)?;
    let partition_bytes = source_partition_bytes.unwrap_or_else(|| {
        let sector = u64::from(raw.geometry.bytes_per_sector);
        if raw
            .geometry
            .volume_size
            .is_multiple_of(u64::from(args.refs_cluster))
        {
            raw.geometry.volume_size
        } else {
            raw.geometry.volume_size.saturating_add(sector)
        }
    });
    ensure!(
        partition_bytes >= raw.geometry.volume_size
            && partition_bytes - raw.geometry.volume_size
                <= u64::from(raw.geometry.bytes_per_sector),
        "partition length differs from NTFS boot geometry"
    );
    let target_occupied: Vec<PhysicalRange> = serde_json::from_slice(&occupancy)?;
    let tree = shadow_tree::derive_ordinary(&raw)?;
    let mut plans = Vec::new();
    let mut adopted = 0u64;
    let mut relocated = 0u64;
    let mut materialized = 0u64;
    let mut sparse = 0u64;
    for object in tree.objects.iter().filter(|object| !object.directory) {
        let file = raw
            .files
            .iter()
            .find(|file| {
                file.record_number == object.record_number
                    && file.sequence_number == object.sequence_number
            })
            .context("source file identity absent")?;
        ensure!(
            file.streams.len() == 1 && file.streams[0].name_utf16.is_empty(),
            "ordinary unnamed stream required"
        );
        let stream = extent_adoption::plan_stream(
            &file.streams[0],
            raw.geometry.cluster_size,
            args.refs_cluster,
            partition_bytes,
            &target_occupied,
        )?;
        adopted = adopted
            .checked_add(stream.adopted_logical_bytes)
            .context("adopt sum overflow")?;
        relocated = relocated
            .checked_add(stream.relocated_logical_bytes)
            .context("relocate sum overflow")?;
        materialized = materialized
            .checked_add(stream.materialized_logical_bytes)
            .context("materialize sum overflow")?;
        sparse = sparse
            .checked_add(stream.sparse_logical_bytes)
            .context("sparse sum overflow")?;
        plans.push(FilePlan {
            record_number: object.record_number,
            sequence_number: object.sequence_number,
            path: object.path.clone(),
            stream,
        });
    }
    ensure!(
        adopted + relocated + materialized + sparse == tree.logical_bytes,
        "ordinary tree stream coverage differs"
    );
    let report = Report {
        schema_version: 1,
        kind: "ntfs-refs-direct-adoption-candidates",
        inspection_sha256: hex::encode(Sha256::digest(&inspected)),
        occupied_sha256: hex::encode(Sha256::digest(&occupancy)),
        target_occupied_ranges: target_occupied.len(),
        files: plans,
        adopted_logical_bytes: adopted,
        relocated_logical_bytes: relocated,
        materialized_logical_bytes: materialized,
        sparse_logical_bytes: sparse,
        executable: false,
        pending: vec![
            "independent ReFS allocator and metadata ownership proof",
            "writer support for every file identity, stream extent and security descriptor",
            "durable source freeze, journal and native Windows mount qualification",
        ],
    };
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(bytes.len() <= 16 * 1024 * 1024, "plan report exceeds bound");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}
