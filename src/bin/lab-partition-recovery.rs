//! Explicit owning-machine experimental partition AP resume/rollback.
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
        acknowledge_disposable_partition_recovery: bool,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_partition_recovery,
        "explicit disposable partition recovery acknowledgement required"
    );
    ensure!(
        args.request_sha256.len() == 64
            && args
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical independently supplied request checksum required"
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
        "ordinary bounded recovery request required"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(before.file_bytes)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.file_bytes
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256
            && n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
                == before
            && file.metadata()?.modified()? == modified,
        "held recovery request identity/checksum changed"
    );
    let request: ntfs2refs::resource_partition_alpha::PartitionRecoveryRequest =
        serde_json::from_slice(&bytes)?;
    drop(bytes);
    drop(file);
    std::thread::Builder::new()
        .name("partition-recovery".into())
        .stack_size(ntfs2refs::resource_partition_alpha::PARTITION_RECOVERY_WORKER_STACK_BYTES)
        .spawn(move || {
            ntfs2refs::resource_partition_alpha::run_recovery(
                request,
                &args.output,
                args.acknowledge_disposable_partition_recovery,
            )
        })?
        .join()
        .map_err(|_| {
            anyhow::anyhow!("partition recovery worker panicked; preserve actual source/J state")
        })?
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Partition recovery requires the Windows machine owning the source.");
}
