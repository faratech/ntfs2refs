//! Recovery on the machine owning the disks; no Hyper-V enrollment required.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::{Parser, ValueEnum};
    use ntfs2refs::general_recovery::{self, Inputs, Operation};
    use std::path::PathBuf;
    #[derive(Clone, Copy, ValueEnum)]
    enum Mode {
        Resume,
        Rollback,
        RollbackAfterMarker,
        Finalize,
        FinalizeAfterMarker,
    }
    #[derive(Parser)]
    #[command(about = "Recover an already activated NTFS-to-ReFS journal on its owning machine")]
    struct Args {
        #[arg(value_enum)]
        mode: Mode,
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
        #[arg(long, requires = "expectation_sha256")]
        expectation: Option<PathBuf>,
        #[arg(long, requires = "expectation")]
        expectation_sha256: Option<String>,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    let operation = match args.mode {
        Mode::Resume => Operation::Resume,
        Mode::Rollback => Operation::Rollback,
        Mode::RollbackAfterMarker => Operation::RollbackAfterMarker,
        Mode::Finalize => Operation::Finalize,
        Mode::FinalizeAfterMarker => Operation::FinalizeAfterMarker,
    };
    general_recovery::recover(
        operation,
        &Inputs {
            request: args.request,
            request_sha256: args.request_sha256,
            ticket: args.ticket,
            ticket_sha256: args.ticket_sha256,
            journal: args.journal,
            expectation: args.expectation,
            expectation_sha256: args.expectation_sha256,
        },
        &args.output,
    )
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Journal recovery requires Windows on the machine owning the disks");
    std::process::exit(2);
}
