//! Observe the exact frozen ReFS target through a physically read-only lease.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use ntfs2refs::{
        general_reconstruct::Request, general_target_preservation, shadow_tree::ExpectedTree,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Read,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn pinned(path: &Path, pin: &str, limit: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() <= limit,
            "bounded ordinary input required"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() <= limit,
            "opened input differs"
        );
        let mut bytes = Vec::new();
        (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= limit
                && pin.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == pin,
            "input SHA-256 differs"
        );
        Ok(bytes)
    }
    let args = Args::parse();
    let request: Request =
        serde_json::from_slice(&pinned(&args.request, &args.request_sha256, 131072)?)?;
    request.validate()?;
    ensure!(
        request.expected_tree_sha256 == args.expectation_sha256,
        "expected tree pin differs from request"
    );
    let expected: ExpectedTree = serde_json::from_slice(&pinned(
        &args.expectation,
        &args.expectation_sha256,
        16 * 1024 * 1024,
    )?)?;
    general_target_preservation::observe_frozen_run(request.pair, &expected, &args.output)
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Protected ReFS observation requires Windows");
    std::process::exit(2);
}
