//! Live owning-machine qualification; no journal activation or source writes.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf};
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        pair: PathBuf,
        #[arg(long)]
        pair_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        verify_existing: bool,
    }
    let args = Args::parse();
    let meta = fs::symlink_metadata(&args.pair)?;
    ensure!(
        meta.is_file() && meta.len() <= 16384,
        "bounded pair input required"
    );
    let bytes = fs::read(&args.pair)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == args.pair_sha256,
        "pair pin differs"
    );
    let pair: n2r_win32::general_layout::GeneralSourceShadowBinding =
        serde_json::from_slice(&bytes)?;
    if args.verify_existing {
        ntfs2refs::general_qualification::qualify_existing(pair, &args.output)?;
    } else {
        ntfs2refs::general_qualification::qualify(pair, &args.output)?;
    }
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-machine qualification required");
    std::process::exit(2);
}
