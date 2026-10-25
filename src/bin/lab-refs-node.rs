//! Bounded read-only inspection of one ReFS 3.14 metadata root page.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use ntfs2refs::{refs_cow_overlay::RefsCowOverlay, refs_node};
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
    overlay: Option<PathBuf>,
    #[arg(long)]
    physical_lcn: u64,
    #[arg(long)]
    child: bool,
}

fn inspect(reader: &mut (impl Read + Seek), image_bytes: u64, lcn: u64, child: bool) -> Result<()> {
    let offset = lcn.checked_mul(4096).context("page address overflow")?;
    ensure!(
        offset
            .checked_add(16384)
            .is_some_and(|end| end <= image_bytes),
        "page outside image"
    );
    reader.seek(SeekFrom::Start(offset))?;
    let mut page = [0u8; 16384];
    reader.read_exact(&mut page)?;
    if child {
        println!(
            "{}",
            serde_json::to_string_pretty(&refs_node::inspect_child_node(&page)?)?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&refs_node::inspect_root_node(&page)?)?
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(overlay) = args.overlay {
        let mut image = RefsCowOverlay::open(&args.base, &overlay)?;
        let length = image.length();
        inspect(&mut image, length, args.physical_lcn, args.child)
    } else {
        let mut image = File::open(args.base)?;
        let length = image.metadata()?.len();
        inspect(&mut image, length, args.physical_lcn, args.child)
    }
}
