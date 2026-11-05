//! Owning-machine preparation only. Produces a sealed bundle before AP;
//! offline apply/recovery is a separate consumer of the saved artifacts.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("windows-offline-preparation".into())
        .stack_size(ntfs2refs::resource_partition_alpha::WORKER_STACK_BYTES)
        .spawn(run)?
        .join()
        .map_err(|_| anyhow::anyhow!("preparation worker panicked; preserve its run"))?
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Native partition preparation requires Windows.");
    std::process::exit(1);
}
#[cfg(windows)]
fn run() -> anyhow::Result<()> {
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
        acknowledge_source_preparation: bool,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_source_preparation,
        "explicit preparation acknowledgement required"
    );
    ensure!(
        args.request_sha256.len() == 64
            && args
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "independent canonical request SHA256 required"
    );
    let resources = n2r_win32::resource_native::observe_available_resources(
        args.output.parent().context("output parent absent")?,
    )?;
    let maximum = resources.available_physical_bytes / 128;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.request)?;
    n2r_win32::file_storage::require_readonly_access(&file)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    ensure!(
        before.file_bytes > 0 && before.number_of_links == 1,
        "ordinary bounded request required"
    );
    let modified = file.metadata()?.modified()?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(before.file_bytes)?)?;
    (&mut file)
        .take(
            before
                .file_bytes
                .checked_add(1)
                .context("request length overflow")?,
        )
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.file_bytes
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "actual request length/checksum differs"
    );
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == before
            && file.metadata()?.modified()? == modified,
        "request changed during held read"
    );
    let request: ntfs2refs::resource_partition_alpha::PartitionAlphaRequest =
        serde_json::from_slice(&bytes)?;
    drop(bytes);
    drop(file);
    let result = ntfs2refs::resource_partition_alpha::prepare_for_offline_apply(
        request,
        &args.output,
        args.acknowledge_source_preparation,
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
