//! Validate and render recorded evidence without opening native devices or
//! historical image/artifact paths.
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use ntfs2refs::capability_evidence::{self, Registry};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[derive(Parser)]
struct Args {
    /// Optional registry file; the checked-in embedded registry is the default.
    #[arg(long)]
    registry: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "markdown")]
    format: Format,
    /// Fresh output file. Omit to write to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Markdown,
    Json,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let registry = match args.registry {
        None => Registry::embedded()?,
        Some(path) => capability_evidence::load_registry(&path)?,
    };
    let contents = match args.format {
        Format::Markdown => capability_evidence::render_markdown(&registry)?,
        Format::Json => serde_json::to_string_pretty(&registry.matrix()?)? + "\n",
    };
    match args.output {
        None => std::io::stdout().write_all(contents.as_bytes())?,
        Some(path) => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .context("create fresh output")?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
        }
    }
    Ok(())
}
