//! Bounded read-only collector/comparator and source-policy diagnostics.
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
    Request {
        #[arg(long)]
        inspection: PathBuf,
        #[arg(long)]
        inspection_sha256: String,
        #[arg(long)]
        source_binding: PathBuf,
        #[arg(long)]
        source_binding_sha256: String,
        #[arg(long)]
        output: PathBuf,
    },
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
        /// Optional read-only source-policy assessment, never a write ticket.
        #[arg(long)]
        admission_output: Option<PathBuf>,
        /// Optional source image, rehashed against the pinned inspection, for
        /// actual backup reads. Requires --admission-output; never written.
        #[arg(long, requires = "admission_output")]
        source_image: Option<PathBuf>,
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
        Command::Request {
            inspection,
            inspection_sha256,
            source_binding,
            source_binding_sha256,
            output,
        } => {
            let raw: ntfs2refs::planner::Inspection = serde_json::from_slice(&pinned(
                &inspection,
                &inspection_sha256,
                64 * 1024 * 1024,
            )?)?;
            let input: serde_json::Value =
                serde_json::from_slice(&pinned(&source_binding, &source_binding_sha256, 16_384)?)?;
            ensure!(
                input.get("schema_version").and_then(|v| v.as_u64()) == Some(1),
                "source binding schema differs"
            );
            let binding: n2r_win32::layout::DiskBinding = serde_json::from_value(
                input
                    .get("source")
                    .context("missing source binding")?
                    .clone(),
            )?;
            save(
                &output,
                &ntfs_attestation::request_for_inspection(&raw, &inspection_sha256, &binding)?,
            )?;
        }
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
            admission_output,
            source_image,
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
            let comparison = ntfs_attestation::compare(&ntfs, &inspection_sha256, &report)?;
            let backups = if let Some(path) = source_image {
                let expected: ntfs2refs::block_io::SourceIdentity = serde_json::from_value(
                    raw.get("source")
                        .context("missing source image binding")?
                        .clone(),
                )?;
                let mut file = ntfs2refs::block_io::open_image(&path)?;
                let before = ntfs2refs::block_io::identity(&mut file, &path)?;
                ensure!(
                    before.sha256 == expected.sha256 && before.length == expected.length,
                    "actual source image differs from pinned inspection"
                );
                let evidence = ntfs2refs::ntfs_backup::verify(&mut file, before.length, &ntfs)?;
                let after = ntfs2refs::block_io::identity(&mut file, &path)?;
                ensure!(
                    after.sha256 == before.sha256 && after.length == before.length,
                    "source image changed during backup validation"
                );
                Some(evidence)
            } else {
                None
            };
            save(&output, &comparison)?;
            if let Some(path) = admission_output {
                save(
                    &path,
                    &ntfs2refs::ntfs_admission::assess_with_backups(
                        &ntfs,
                        &comparison,
                        report.schema_version,
                        backups.as_ref(),
                    ),
                )?;
            }
        }
    }
    Ok(())
}
