//! Read-only source transport for the independent-writer native experiment.
use anyhow::Result;
use clap::Parser;
use ntfs2refs::refs_reference_transport::{Selection, pack_files};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    about = "Pack a pinned fixed VHD into a bounded nonzero-chunk reference packet; no devices or mounts"
)]
struct Args {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    disk_bytes: u64,
    #[arg(long)]
    fixed_vhd_sha256: String,
    #[arg(long)]
    partition_offset: u64,
    #[arg(long)]
    partition_bytes: u64,
    #[arg(long)]
    partition_sha256: String,
    #[arg(long)]
    payload_offset: u64,
    #[arg(long)]
    payload_bytes: u64,
    #[arg(long)]
    payload_sha256: String,
}
fn main() -> Result<()> {
    let args = Args::parse();
    let selection = Selection {
        schema_version: 1,
        disk_bytes: args.disk_bytes,
        fixed_vhd_sha256: args.fixed_vhd_sha256,
        partition_offset: args.partition_offset,
        partition_bytes: args.partition_bytes,
        partition_sha256: args.partition_sha256,
        payload_offset: args.payload_offset,
        payload_bytes: args.payload_bytes,
        payload_sha256: args.payload_sha256,
    };
    let result = pack_files(&args.source, &args.output, &selection)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
