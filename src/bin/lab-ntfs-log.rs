//! Read-only $LogFile restart evidence from a raw NTFS partition image.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use ntfs2refs::{ntfs_inspect::NtfsInspection, ntfs_log};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    image: PathBuf,
    #[arg(long)]
    inspection: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    kind: &'static str,
    inspection_sha256: String,
    partition_bytes: u64,
    restart: ntfs_log::VerifiedRestart,
    source_admitted: bool,
    execution_authorized: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let inspection = fs::read(&args.inspection).context("read NTFS inspection")?;
    ensure!(
        inspection.len() <= 16 * 1024 * 1024,
        "inspection exceeds bound"
    );
    let value: serde_json::Value = serde_json::from_slice(&inspection)?;
    let raw: NtfsInspection = serde_json::from_value(if value.get("files").is_some() {
        value.clone()
    } else {
        ensure!(
            value["filesystem"]["filesystem"] == "Ntfs",
            "NTFS inspection required"
        );
        value["filesystem"]["details"].clone()
    })?;
    let mut image = File::open(&args.image).context("open source image read-only")?;
    let length = image.metadata()?.len();
    ensure!(
        length >= raw.geometry.volume_size
            && length - raw.geometry.volume_size <= u64::from(raw.geometry.bytes_per_sector),
        "raw image length differs from NTFS geometry"
    );
    let restart = ntfs_log::verify(&mut image, &raw)?;
    let report = Report {
        schema_version: 1,
        kind: "raw-ntfs-log-restart-observation",
        inspection_sha256: hex::encode(Sha256::digest(&inspection)),
        partition_bytes: length,
        restart,
        source_admitted: false,
        execution_authorized: false,
    };
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(bytes.len() <= 65536, "restart report exceeds bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
