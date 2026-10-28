//! Explicit experimental restart for an already activated compact conversion.
//! No fresh source activation or Apply operation is exposed here.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::{Parser, ValueEnum};
    use ntfs2refs::general_recovery::{
        ExperimentalCompactInputs, ExperimentalCompactOperation, recover_compact_experimental,
    };
    use std::path::PathBuf;
    #[derive(Clone, Copy, ValueEnum)]
    enum Mode {
        Resume,
        Rollback,
        Finalize,
        FinalizeAfterMarker,
        FinalizeRollback,
    }
    #[derive(Parser)]
    struct Args {
        #[arg(value_enum)]
        operation: Mode,
        #[arg(long)]
        acknowledge_experimental_compact_recovery: bool,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long)]
        ticket_sha256: String,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        capture: PathBuf,
        #[arg(long)]
        capture_sha256: String,
        #[arg(long)]
        packed: PathBuf,
        #[arg(long)]
        packed_sha256: String,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_experimental_compact_recovery,
        "explicit experimental compact recovery acknowledgment required"
    );
    let operation = match args.operation {
        Mode::Resume => ExperimentalCompactOperation::Resume,
        Mode::Rollback => ExperimentalCompactOperation::Rollback,
        Mode::Finalize => ExperimentalCompactOperation::Finalize,
        Mode::FinalizeAfterMarker => ExperimentalCompactOperation::FinalizeAfterMarker,
        Mode::FinalizeRollback => ExperimentalCompactOperation::FinalizeRollback,
    };
    recover_compact_experimental(
        operation,
        &ExperimentalCompactInputs {
            request: args.request,
            request_sha256: args.request_sha256,
            ticket: args.ticket,
            ticket_sha256: args.ticket_sha256,
            journal: args.journal,
            capture: args.capture,
            capture_sha256: args.capture_sha256,
            packed: args.packed,
            packed_sha256: args.packed_sha256,
            expectation: args.expectation,
            expectation_sha256: args.expectation_sha256,
        },
        &args.output,
    )
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-machine recovery required");
    std::process::exit(2);
}
