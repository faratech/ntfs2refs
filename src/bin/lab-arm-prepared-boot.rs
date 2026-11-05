//! Exact owning-machine boot handoff; never executes the data writer.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("prepared-recovery-boot".into())
        .stack_size(ntfs2refs::resource_partition_alpha::WORKER_STACK_BYTES)
        .spawn(run)?
        .join()
        .map_err(|_| {
            anyhow::anyhow!("boot handoff worker panicked; preserve all artifacts and boot state")
        })?
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Recovery boot installation requires Windows.");
    std::process::exit(1);
}
#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
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
        acknowledge_persistent_recovery_boot: bool,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_persistent_recovery_boot,
        "recovery boot acknowledgement required"
    );
    ensure!(
        args.request_sha256.len() == 64
            && args
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical request SHA256 required"
    );
    let maximum = n2r_win32::offline_environment::available_ram_bytes()? / 256;
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
        "bounded ordinary request required"
    );
    ensure!(
        hex::encode(n2r_win32::sha256_native::hash_range(
            &mut file,
            0,
            before.file_bytes
        )?) == args.request_sha256,
        "held request differs from independent SHA256"
    );
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(before.file_bytes)?)?;
    (&mut file)
        .take(
            before
                .file_bytes
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("request overflow"))?,
        )
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.file_bytes
            && n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
                == before,
        "held request changed during decoding"
    );
    let request: ntfs2refs::resource_partition_alpha::PreparedBootRequest =
        serde_json::from_slice(&bytes)?;
    drop(bytes);
    let receipt = ntfs2refs::resource_partition_alpha::arm_prepared_boot(
        request,
        &args.output,
        args.acknowledge_persistent_recovery_boot,
    )?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
