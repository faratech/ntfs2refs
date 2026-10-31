//! Capture lab-only full source content/metadata, with no source-write authority.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use ntfs2refs::lab_source_baseline::{CaptureInput, InputPin};
    use std::path::PathBuf;
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        directory_growth: PathBuf,
        #[arg(long)]
        directory_growth_sha256: String,
        #[arg(long)]
        original_fixture: PathBuf,
        #[arg(long)]
        original_fixture_sha256: String,
        #[arg(long)]
        historical_full_expectation: PathBuf,
        #[arg(long)]
        historical_full_expectation_sha256: String,
        #[arg(long)]
        source_checkpoint: String,
        #[arg(long)]
        output: PathBuf,
    }
    let a = Args::parse();
    let manifest = ntfs2refs::lab_source_baseline::capture(
        CaptureInput {
            binding: InputPin {
                path: a.binding,
                sha256: a.binding_sha256,
            },
            directory_growth: InputPin {
                path: a.directory_growth,
                sha256: a.directory_growth_sha256,
            },
            original_fixture: InputPin {
                path: a.original_fixture,
                sha256: a.original_fixture_sha256,
            },
            historical_full_expectation: InputPin {
                path: a.historical_full_expectation,
                sha256: a.historical_full_expectation_sha256,
            },
            source_checkpoint: a.source_checkpoint,
        },
        &a.output,
    )?;
    println!(
        "{}",
        serde_json::json!({"success":true,"manifest":a.output.join("baseline-manifest.json"),"objects":manifest["objects"],"streams":manifest["actual_fresh_stream_hashes_matched"],"source_admitted":false,"conversion_authorized":false})
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("native frozen-source baseline requires Windows");
    std::process::exit(1);
}
