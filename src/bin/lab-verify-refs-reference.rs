//! Read-only packet/full-file reproducibility proof; never a cleanup command.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    #[derive(Parser)]
    #[command(
        about = "Verify the pinned reference packet and current fixed VHD read-only; no disk output or cleanup"
    )]
    struct Args {
        #[arg(long)]
        packet: std::path::PathBuf,
        #[arg(long)]
        source: std::path::PathBuf,
        /// Reuse the exact pinned earlier reconstruction; still freshly hash both inputs.
        #[arg(long)]
        reuse_reconstruction_proof: Option<std::path::PathBuf>,
    }
    let args = Args::parse();
    let report = if let Some(proof) = args.reuse_reconstruction_proof {
        ntfs2refs::reference_file_verification::recheck_pinned_files(
            &args.packet,
            &args.source,
            &proof,
        )?
    } else {
        ntfs2refs::reference_file_verification::verify_pinned_files(&args.packet, &args.source)?
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Same-handle reference identity requires Windows");
    std::process::exit(2);
}
