//! Restricted owning-guest native acceptance import; not a conversion CLI.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: std::path::PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: std::path::PathBuf,
        /// Bring only the fresh imported reference online after durable proofs.
        #[arg(long)]
        handoff: bool,
    }
    let a = Args::parse();
    let r = ntfs2refs::refs_reference_import::load_request(&a.request, &a.request_sha256)?;
    ntfs2refs::refs_reference_import::run(&r, &a.output, a.handoff)
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Restricted reference import requires its enrolled Windows guest");
    std::process::exit(2);
}
