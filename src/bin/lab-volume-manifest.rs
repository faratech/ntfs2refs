//! Lists every object on a mounted volume, or compares two such listings.
//!
//!   lab-volume-manifest capture --root D:\ --output before.jsonl
//!   lab-volume-manifest compare --before before.jsonl --after after.jsonl --report report.json
//!   lab-volume-manifest compare --exact --before before.jsonl --after after.jsonl --report report.json
//!
//! The lab harness lists the NTFS source before a conversion and the same
//! volume once it mounts as ReFS, then compares the two. Capturing is read
//! only. `compare` exits 0 when the listings match and 2 when they do not.
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use n2r_win32::volume_manifest::{self, Record};
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// List a mounted volume into a file, one JSON object per line.
    Capture {
        /// The volume, as a drive root such as D:\
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 8)]
        threads: usize,
    },
    /// Compare the listing taken before a conversion with the one taken after.
    Compare {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
        #[arg(long)]
        report: PathBuf,
        /// Require the two listings to be equal in every recorded field, with
        /// nothing accepted as an expected difference: for a volume that
        /// must not have changed, such as the NTFS source before and after a
        /// diagnose run or a rollback.
        #[arg(long)]
        exact: bool,
    },
}

fn read(path: &Path) -> Result<Vec<Record>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let line = line?;
            serde_json::from_str(&line)
                .with_context(|| format!("{} line {}", path.display(), index + 1))
        })
        .collect()
}

fn main() -> Result<ExitCode> {
    match Args::parse().command {
        Command::Capture {
            root,
            output,
            threads,
        } => {
            #[cfg(windows)]
            {
                let started = std::time::Instant::now();
                let records = volume_manifest::capture(&root, threads)
                    .with_context(|| format!("listing {}", root.display()))?;
                let mut out = BufWriter::new(
                    File::create(&output)
                        .with_context(|| format!("creating {}", output.display()))?,
                );
                for record in &records {
                    serde_json::to_writer(&mut out, record)?;
                    out.write_all(b"\n")?;
                }
                out.flush()?;
                let unreadable = records
                    .iter()
                    .filter(|record| !record.errors.is_empty())
                    .count();
                println!(
                    "{}",
                    serde_json::json!({
                        "objects": records.len(),
                        "unreadable": unreadable,
                        "bytes": records.iter().map(|record| record.bytes).sum::<u64>(),
                        "seconds": started.elapsed().as_secs_f64(),
                    })
                );
                Ok(ExitCode::SUCCESS)
            }
            #[cfg(not(windows))]
            {
                let _ = (root, output, threads);
                anyhow::bail!("listing a volume requires Windows")
            }
        }
        Command::Compare {
            before,
            after,
            report,
            exact,
        } => {
            let (before, after) = (read(&before)?, read(&after)?);
            let comparison = if exact {
                volume_manifest::compare_exact(&before, &after)
            } else {
                volume_manifest::compare(&before, &after)
            };
            let mut out = BufWriter::new(
                File::create(&report).with_context(|| format!("creating {}", report.display()))?,
            );
            serde_json::to_writer_pretty(&mut out, &comparison)?;
            out.flush()?;
            println!(
                "{}",
                serde_json::json!({
                    "identical": comparison.identical(),
                    "before_objects": comparison.before_objects,
                    "after_objects": comparison.after_objects,
                    "short_names_as_links": comparison.short_names_as_links,
                    "allowed": comparison.allowed,
                    "differences": comparison.difference_count,
                    "kinds": comparison.difference_kinds,
                })
            );
            Ok(if comparison.identical() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}
