//! Capture the source tree's exact expectations, then hand off and verify the
//! journaled original partition inside the owning guest.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::{Parser, ValueEnum};
    use ntfs2refs::{
        lab_reconstruct::JournalTicket,
        lab_tree_expectation::{self, Expectation},
        lab_tree_reconstruct::{self, Request},
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    #[derive(Clone, Copy, ValueEnum, PartialEq, Serialize)]
    enum Mode {
        Capture,
        Finish,
    }
    #[derive(Parser)]
    struct Args {
        #[arg(value_enum)]
        mode: Mode,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        expectation: Option<PathBuf>,
        #[arg(long)]
        expectation_sha256: Option<String>,
        #[arg(long)]
        ticket: Option<PathBuf>,
        #[arg(long)]
        ticket_sha256: Option<String>,
        #[arg(long)]
        journal: Option<PathBuf>,
    }
    fn ordinary(path: &Path, existing: bool) -> Result<()> {
        let text = path.to_str().context("non-Unicode artifact")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains('/')
                && !text.contains("..")
                && !text.ends_with([' ', '.']),
            "ordinary guest C: artifacts required"
        );
        for (i, a) in path.ancestors().enumerate() {
            if i == 0 && !existing {
                ensure!(!a.exists(), "fresh output required");
                continue;
            }
            let m = fs::symlink_metadata(a)?;
            ensure!(
                m.file_attributes() & 0x400 == 0 && if i == 0 { m.is_file() } else { m.is_dir() },
                "artifact ancestor/type differs"
            );
        }
        Ok(())
    }
    fn pinned(path: &Path, expected: &str, max: u64) -> Result<(std::fs::File, Vec<u8>)> {
        ordinary(path, true)?;
        let mut f = OpenOptions::new().read(true).share_mode(1).open(path)?;
        ensure!(f.metadata()?.len() <= max, "input too large");
        let mut b = vec![];
        (&mut f).take(max + 1).read_to_end(&mut b)?;
        ensure!(
            b.len() as u64 <= max
                && expected.len() == 64
                && hex::encode(Sha256::digest(&b)) == expected,
            "artifact pin differs"
        );
        Ok((f, b))
    }
    fn save(path: &Path, value: &impl Serialize) -> Result<()> {
        ordinary(path, false)?;
        let b = serde_json::to_vec_pretty(value)?;
        ensure!(b.len() <= 16 * 1024 * 1024, "report exceeds bound");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        f.write_all(&b)?;
        f.sync_all()?;
        Ok(())
    }
    let a = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "owning disposable guest required"
    );
    ordinary(&a.output, false)?;
    let (_request_file, b) = pinned(&a.request, &a.request_sha256, 131072)?;
    let request: Request = serde_json::from_slice(&b)?;
    request.validate()?;
    if a.mode == Mode::Capture {
        ensure!(
            a.expectation.is_none() && a.ticket.is_none() && a.journal.is_none(),
            "capture does not accept execution inputs"
        );
        save(
            &a.output.with_extension("intent.json"),
            &serde_json::json!({"mode":"capture","request_sha256":a.request_sha256,"source_writes_allowed":false}),
        )?;
        let mut events = vec![];
        let expectation = lab_tree_expectation::capture(&request, &mut events)?;
        save(&a.output, &expectation)?;
        println!("Exact source expectation captured; no source writes.");
    } else {
        let (_expectation_file, b) = pinned(
            a.expectation.as_ref().context("--expectation required")?,
            a.expectation_sha256
                .as_deref()
                .context("--expectation-sha256 required")?,
            8 * 1024 * 1024,
        )?;
        let expectation: Expectation = serde_json::from_slice(&b)?;
        let (_ticket_file, b) = pinned(
            a.ticket.as_ref().context("--ticket required")?,
            a.ticket_sha256
                .as_deref()
                .context("--ticket-sha256 required")?,
            65536,
        )?;
        let ticket: JournalTicket = serde_json::from_slice(&b)?;
        let journal_path = a.journal.as_ref().context("--journal required")?;
        ensure!(
            journal_path.to_str()
                == Some(
                    format!(
                        "J:\\ntfs2refs-shadow\\{}\\reconstruction.journal",
                        request.experiment_id
                    )
                    .as_str()
                ),
            "exact external journal path required"
        );
        // The core observes its complete native identity before any transition.
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x00200000)
            .open(journal_path)?;
        save(
            &a.output.with_extension("intent.json"),
            &serde_json::json!({"mode":"finish","request_sha256":a.request_sha256,
            "ticket_sha256":a.ticket_sha256,"expectation_sha256":a.expectation_sha256,"handoff_will_close_rollback":true}),
        )?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&a.output)?;
        let report = lab_tree_reconstruct::finalize(&request, &mut journal, &ticket, &expectation)?;
        let bytes = serde_json::to_vec_pretty(&report)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "complete native report exceeds bound"
        );
        out.write_all(&bytes)?;
        out.sync_all()?;
        ensure!(
            report.success,
            "native finish refused: {:?}; preserve journal, ticket and handoff",
            report.error
        );
        println!("Original partition converted and native tree verification passed.");
    }
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-guest operation required");
    std::process::exit(1);
}
