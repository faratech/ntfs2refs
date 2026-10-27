//! Owning-guest private one-MiB ReFS validity experiment. No converter route.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::windows::fs::MetadataExt,
        path::PathBuf,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    ensure!(
        !args.output.exists() && args.output != args.request,
        "fresh distinct report required"
    );
    let metadata = fs::symlink_metadata(&args.request)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 131072,
        "bounded ordinary request required"
    );
    let bytes = fs::read(&args.request)?;
    ensure!(
        bytes.len() <= 131072 && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request pin differs"
    );
    let request: ntfs2refs::general_reconstruct::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let result =
        n2r_win32::shadow_native::valid_data_probe::run(&request.pair, &args.experiment_id)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    file.write_all(&serde_json::to_vec_pretty(&result)?)?;
    file.sync_all()?;
    println!("Private validity probe complete; original source was not opened for writes.");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("native validity probe requires Windows");
    std::process::exit(1);
}
