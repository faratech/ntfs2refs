//! Read-only Medium allocator observation from a raw ReFS 3.14 image or its
//! isolated metadata overlay. This never claims whole-volume ownership.
use anyhow::{Result, ensure};
use clap::Parser;
use ntfs2refs::{refs_allocator, refs_cow_overlay::RefsCowOverlay};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    base: PathBuf,
    #[arg(long)]
    overlay: Option<PathBuf>,
    #[arg(long)]
    query_lcn: Option<u64>,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct Report {
    observation: refs_allocator::MediumAllocatorObservation,
    query_lcn: Option<u64>,
    query_medium_allocated: Option<bool>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let observation = if let Some(overlay) = &args.overlay {
        let mut image = RefsCowOverlay::open(&args.base, overlay)?;
        let length = image.length();
        refs_allocator::inspect_medium(&mut image, length)?
    } else {
        let mut image = File::open(&args.base)?;
        let length = image.metadata()?.len();
        refs_allocator::inspect_medium(&mut image, length)?
    };
    let query_medium_allocated = args.query_lcn.map(|lcn| observation.medium_allocated(lcn));
    let report = Report {
        observation,
        query_lcn: args.query_lcn,
        query_medium_allocated,
    };
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "allocator report exceeds bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
