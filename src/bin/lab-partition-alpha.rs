//! Explicit owning-machine experimental source conversion; no host/VM actions.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    // Windows gives the executable's initial thread a 1 MiB stack. The
    // owning preparation chain nests several bounded parser frames; keep its
    // stack explicit and charge the reservation in the conversion budget.
    std::thread::Builder::new()
        .name("partition-alpha".into())
        .stack_size(ntfs2refs::resource_partition_alpha::WORKER_STACK_BYTES)
        .spawn(run)?
        .join()
        .map_err(|_| anyhow::anyhow!("partition conversion worker panicked; preserve its run"))?
}
#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom},
        os::windows::fs::OpenOptionsExt,
        path::PathBuf,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        acknowledge_disposable_source_conversion: bool,
        /// Exercise live BasicRO cancellation before creating a shadow.
        #[arg(long, hide = true, conflicts_with_all = ["controlled_post_flush_pause_nonce", "acknowledge_controlled_post_flush_pause"])]
        cancel_before_private: bool,
        /// Exact nonce for the owning launcher's StandardInput Continue pipe.
        #[arg(
            long,
            hide = true,
            requires = "acknowledge_controlled_post_flush_pause"
        )]
        controlled_post_flush_pause_nonce: Option<String>,
        #[arg(long, hide = true, requires = "controlled_post_flush_pause_nonce")]
        acknowledge_controlled_post_flush_pause: bool,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_source_conversion,
        "explicit acknowledgement required for actual in-place conversion"
    );
    ensure!(
        args.request_sha256.len() == 64
            && args
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "independently supplied canonical request SHA256 required"
    );
    let available = n2r_win32::resource_native::observe_available_resources(
        args.output.parent().context("output parent absent")?,
    )?;
    let maximum = available.available_physical_bytes / 128;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.request)?;
    n2r_win32::file_storage::require_readonly_access(&file)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    let modified = file.metadata()?.modified()?;
    ensure!(
        before.file_bytes > 0 && before.number_of_links == 1,
        "ordinary bounded request required"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(before.file_bytes)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.file_bytes
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "actual request checksum differs"
    );
    file.seek(SeekFrom::Start(0))?;
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == before
            && file.metadata()?.modified()? == modified,
        "request identity changed during read"
    );
    let request: ntfs2refs::resource_partition_alpha::PartitionAlphaRequest =
        serde_json::from_slice(&bytes)?;
    drop(bytes);
    drop(file);
    if args.cancel_before_private {
        return ntfs2refs::resource_partition_alpha::run_cancel_before_private(
            request,
            &args.output,
            args.acknowledge_disposable_source_conversion,
        );
    }
    match args.controlled_post_flush_pause_nonce {
        Some(nonce) => ntfs2refs::resource_partition_alpha::run_with_controlled_post_flush_pause(
            request,
            &args.output,
            args.acknowledge_disposable_source_conversion,
            nonce,
            args.acknowledge_controlled_post_flush_pause,
        ),
        None => ntfs2refs::resource_partition_alpha::run(
            request,
            &args.output,
            args.acknowledge_disposable_source_conversion,
        ),
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("The experimental partition alpha requires Windows.");
}
