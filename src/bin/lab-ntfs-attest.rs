//! Bounded lab collector/comparator. No source-admission or conversion command.
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use n2r_win32::attestation::{Report, Request};
use ntfs2refs::{ntfs_attestation, ntfs_inspect::NtfsInspection};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Collect {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
    },
    Compare {
        #[arg(long)]
        inspection: PathBuf,
        #[arg(long)]
        inspection_sha256: String,
        #[arg(long)]
        native: PathBuf,
        #[arg(long)]
        native_sha256: String,
        #[arg(long)]
        output: PathBuf,
    },
}
fn pinned(path: &Path, hash: &str, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA256 pin"
    );
    ensure!(
        std::fs::symlink_metadata(path)?.is_file(),
        "ordinary input file required"
    );
    let mut f = File::open(path)?;
    ensure!(f.metadata()?.len() <= limit, "input exceeds bound");
    let mut b = vec![];
    (&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit && hex::encode(Sha256::digest(&b)) == hash,
        "input hash or length differs"
    );
    Ok(b)
}
fn save(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let b = serde_json::to_vec_pretty(value)?;
    ensure!(b.len() <= 16 * 1024 * 1024, "report exceeds bound");
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(&b)?;
    f.sync_all()?;
    Ok(())
}
fn main() -> Result<()> {
    match Args::parse().command {
        Command::Collect {
            request,
            request_sha256,
            output,
        } => {
            let r: Request = serde_json::from_slice(&pinned(&request, &request_sha256, 65536)?)?;
            r.validate()?;
            #[cfg(windows)]
            {
                let report = n2r_win32::collect_file_metadata(&r)?;
                save(&output, &report)?;
            }
            #[cfg(not(windows))]
            {
                let _ = output;
                anyhow::bail!("native collection requires Windows");
            }
        }
        Command::Compare {
            inspection,
            inspection_sha256,
            native,
            native_sha256,
            output,
        } => {
            let raw: serde_json::Value = serde_json::from_slice(&pinned(
                &inspection,
                &inspection_sha256,
                64 * 1024 * 1024,
            )?)?;
            let ntfs: NtfsInspection = serde_json::from_value(
                raw.get("filesystem")
                    .and_then(|v| v.get("details"))
                    .context("missing NTFS inspection")?
                    .clone(),
            )?;
            let report: Report =
                serde_json::from_slice(&pinned(&native, &native_sha256, 16 * 1024 * 1024)?)?;
            save(
                &output,
                &ntfs_attestation::compare(&ntfs, &inspection_sha256, &report)?,
            )?;
        }
    }
    Ok(())
}
