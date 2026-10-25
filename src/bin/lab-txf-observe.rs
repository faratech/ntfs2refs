//! Read-only TxF resource-manager query while the enrolled NTFS data volume
//! is mounted. This cannot establish a frozen-source certificate by itself.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{layout::DiskBinding, txf_native};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn ordinary(path: &Path, exists: bool) -> Result<()> {
        let text = path.to_str().context("non-Unicode artifact")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains('/')
                && !text.contains("..")
                && !text.ends_with([' ', '.']),
            "guest-local ordinary C: artifact required"
        );
        for (index, ancestor) in path.ancestors().enumerate() {
            if index == 0 && !exists {
                ensure!(!ancestor.exists(), "fresh output required");
                continue;
            }
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(
                metadata.file_attributes() & 0x400 == 0
                    && if index == 0 {
                        metadata.is_file()
                    } else {
                        metadata.is_dir()
                    },
                "reparse point or unexpected artifact ancestry"
            );
        }
        Ok(())
    }
    let args = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "owning disposable guest required"
    );
    ordinary(&args.binding, true)?;
    ordinary(&args.output, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.binding)?;
    ensure!(file.metadata()?.len() <= 16384, "binding exceeds bound");
    let mut bytes = vec![];
    (&mut file).take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16384
            && args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: DiskBinding = serde_json::from_slice(&bytes)?;
    let report = txf_native::observe(binding)?;
    let output = serde_json::to_vec_pretty(&report)?;
    ensure!(output.len() <= 65536, "TxF report exceeds bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&args.output)?;
    file.write_all(&output)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("native TxF observation requires Windows");
    std::process::exit(1);
}
