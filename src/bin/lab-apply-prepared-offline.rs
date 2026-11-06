//! Startup entry for the boot-bound RAM request; no path/flag is write authority.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("cold-prepared-conversion".into())
        .stack_size(ntfs2refs::resource_partition_alpha::WORKER_STACK_BYTES)
        .spawn(run)?
        .join()
        .map_err(|_| {
            anyhow::anyhow!("offline worker panicked; keep recovery boot and all artifacts")
        })?
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Offline conversion requires Windows.");
    std::process::exit(1);
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
        request: Option<PathBuf>,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        bundle_sha256: String,
        #[arg(long)]
        acknowledge_offline_conversion: bool,
        #[arg(long)]
        rollback: bool,
        /// Finish only an already authenticated closed HND/ABT; never apply/replay.
        #[arg(long)]
        finalize_closed_boot_only: bool,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_offline_conversion,
        "explicit offline conversion acknowledgement required"
    );
    let path = match args.request {
        Some(p) => p,
        None => std::env::current_exe()?
            .parent()
            .context("RAM image parent absent")?
            .join("n2r-bootstrap.json"),
    };
    let native = n2r_win32::recovery_boot::current_recovery_bootstrap_sha256()
        .context("read current native recovery bootstrap pin")?;
    ensure!(
        args.request_sha256 == hex::encode(native),
        "request pin differs from actual current boot selection"
    );
    let maximum = n2r_win32::offline_environment::available_ram_bytes()
        .context("sample RAM before opening boot-bound bootstrap")? / 256;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&path).with_context(|| format!("open boot-bound RAM bootstrap {}", path.display()))?;
    n2r_win32::file_storage::require_readonly_access(&file)
        .context("query actual bootstrap handle read-only access")?;
    let length = file.metadata().context("query RAM bootstrap metadata")?.len();
    ensure!(
        length > 0 && length <= maximum,
        "bounded RAM bootstrap required"
    );
    ensure!(
        n2r_win32::sha256_native::hash_range(&mut file, 0, length)
            .context("hash actual held RAM bootstrap bytes")? == native,
        "actual held RAM request differs from native boot pin"
    );
    file.seek(SeekFrom::Start(0)).context("seek held RAM bootstrap for decoding")?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(length)?)?;
    (&mut file)
        .take(length.checked_add(1).context("request length overflow")?)
        .read_to_end(&mut bytes).context("read held RAM bootstrap for decoding")?;
    ensure!(
        bytes.len() as u64 == length
            && <[u8; 32]>::from(Sha256::digest(&bytes)) == native
            && file.metadata()?.len() == length,
        "RAM bootstrap changed during decoding"
    );
    let mut request: ntfs2refs::resource_partition_alpha::PreparedOfflineRequest =
        serde_json::from_slice(&bytes).context("decode boot-bound offline request")?;
    ensure!(
        request.prepared_bundle_sha256 == args.bundle_sha256,
        "startup selects another bundle than the current boot-bound request"
    );
    drop(bytes);
    if args.rollback {
        ensure!(!args.finalize_closed_boot_only,"closed-only boot repair never selects rollback/replay");
        request.action = ntfs2refs::resource_partition_alpha::PreparedOfflineAction::Rollback;
    }
    if args.finalize_closed_boot_only {
        return ntfs2refs::resource_partition_alpha::finalize_closed_boot_only(
            request,file,args.acknowledge_offline_conversion);
    }
    ntfs2refs::resource_partition_alpha::run_prepared_offline(
        request,
        file,
        args.acknowledge_offline_conversion,
    )
}
