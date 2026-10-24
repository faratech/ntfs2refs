//! Lab-only extraction of an immutable partition artifact, never conversion.
use anyhow::Result;
use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    about = "LAB ONLY: copy a partition range from an offline fixed VHD. No filesystem conversion, devices, or GPT validation."
)]
struct Arguments {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// JSON selection derived from verified guest evidence; see docs/fixed-vhd-extraction.md.
    #[arg(long)]
    selection: PathBuf,
}

fn run() -> Result<()> {
    let arguments = Arguments::parse();
    let record =
        ntfs2refs::fixed_vhd::extract(&arguments.source, &arguments.output, &arguments.selection)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Extraction refused or incomplete: {error:#}");
            ExitCode::FAILURE
        }
    }
}
