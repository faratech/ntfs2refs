//! Owning-machine allocation-freeze observation, with no reconstruction path.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use ntfs2refs::general_allocation_capture::{self, Request};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Read,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn pinned(args: &Args) -> Result<Vec<u8>> {
        let meta = fs::symlink_metadata(&args.request)?;
        ensure!(
            meta.is_file() && meta.file_attributes() & 0x400 == 0,
            "ordinary capture request required"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&args.request)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.file_attributes() & 0x400 == 0 && meta.len() <= 16384,
            "bounded capture request required"
        );
        let mut bytes = Vec::new();
        (&mut file).take(16385).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 16384
                && args.request_sha256.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
            "capture request pin differs"
        );
        Ok(bytes)
    }
    let args = Args::parse();
    let request: Request = serde_json::from_slice(&pinned(&args)?)?;
    general_allocation_capture::capture(&request, &args.output)
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Native allocation freeze requires Windows on the owning machine");
    std::process::exit(2);
}
