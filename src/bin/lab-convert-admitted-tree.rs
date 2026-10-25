//! Owning-guest exercise of the certificate-backed conversion workflow.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf};
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "disposable owning-guest exercise required"
    );
    let meta = fs::symlink_metadata(&args.request)?;
    ensure!(
        meta.is_file() && meta.len() <= 16384,
        "bounded request required"
    );
    let bytes = fs::read(&args.request)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request pin differs"
    );
    let request: ntfs2refs::general_conversion::Request = serde_json::from_slice(&bytes)?;
    ensure!(
        request.pair.source.disk_number == 1
            && request.pair.shadow.disk_number == 3
            && request.journal.disk.disk_number == 2,
        "enrolled disposable disk roles differ"
    );
    ntfs2refs::general_conversion::convert(&request, &args.output)
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-guest conversion required");
    std::process::exit(2);
}
