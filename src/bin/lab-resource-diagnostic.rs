//! Owning-guest V4 diagnostic restricted to the explicitly enrolled,
//! Job-bounded disposable fixture. Apply requires an explicit invocation flag
//! and the same actual source/target/journal admission as the public engine.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt, path::PathBuf};

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        acknowledge_disposable_shadow: bool,
        /// Apply the real prepared journal, reseal, and verify native ReFS.
        /// Omitted preserves the existing preparation-only diagnostic.
        #[arg(long)]
        apply_and_verify: bool,
    }
    let args = Args::parse();
    ensure!(
        args.request_sha256.len() == 64
            && args
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "exact lowercase independently supplied request checksum required"
    );
    let parent = args
        .output
        .parent()
        .context("diagnostic output parent absent")?;
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    let max_request = available.available_physical_bytes / 128;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.request)?;
    let snapshot =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, max_request)?;
    let modified = file.metadata()?.modified()?;
    ensure!(
        snapshot.file_bytes > 0 && snapshot.number_of_links == 1,
        "bounded ordinary diagnostic request required"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(snapshot.file_bytes)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == snapshot.file_bytes
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256
            && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &file,
                max_request
            )? == snapshot
            && file.metadata()?.modified()? == modified,
        "diagnostic request identity or checksum differs"
    );
    let request: ntfs2refs::resource_diagnostic::ResourceDiagnosticRequest =
        serde_json::from_slice(&bytes)?;
    ntfs2refs::resource_diagnostic::run_guest_diagnostic_with_operation(
        request,
        &args.output,
        args.acknowledge_disposable_shadow,
        if args.apply_and_verify {
            ntfs2refs::resource_diagnostic::ResourceDiagnosticOperation::ApplyAndVerify
        } else {
            ntfs2refs::resource_diagnostic::ResourceDiagnosticOperation::PrepareOnly
        },
    )
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The resource diagnostic requires Windows.");
}
