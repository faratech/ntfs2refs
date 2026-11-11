//! One fresh private thin constructor. No source, GPT, formatter or cleanup.
#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("private thin constructor stopped: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::managed_shadow::thin_pool::{self, Budget};
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, PathBuf, Prefix},
    };

    const GOAL_BYTES: u64 = 1_000_000_000_000_000;
    const RESULT_BYTES: u64 = 128 << 10;

    #[derive(Parser)]
    struct Args {
        /// New ordinary metadata parent; provider files go beneath provider/.
        #[arg(long)]
        directory: PathBuf,
        /// Exact Windows Storage subsystem UniqueId; never a pool/device route.
        #[arg(long)]
        storage_subsystem: String,
        #[arg(long)]
        acknowledge_new_disposable_staging: bool,
    }

    struct CappedWriter {
        file: File,
        remaining: u64,
    }
    impl Write for CappedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() as u64 > self.remaining {
                return Err(io::Error::other(
                    "thin lab result exceeds its metadata allowance",
                ));
            }
            let count = self.file.write(bytes)?;
            self.remaining -= count as u64;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    let args = Args::parse();
    ensure!(
        args.acknowledge_new_disposable_staging,
        "explicit new disposable staging acknowledgement required"
    );
    args.directory
        .to_str()
        .context("Unicode lab directory required")?;
    ensure!(
        args.directory.is_absolute() && !args.directory.exists(),
        "fresh absolute ordinary local lab directory required"
    );
    for component in args.directory.components() {
        match component {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                anyhow::bail!("local lab directory required")
            }
            Component::CurDir | Component::ParentDir => {
                anyhow::bail!("lab directory traversal refused")
            }
            Component::Normal(s)
                if s.to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                anyhow::bail!("ambiguous lab directory component")
            }
            _ => {}
        }
    }
    for parent in args
        .directory
        .parent()
        .context("lab parent absent")?
        .ancestors()
    {
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "ordinary lab ancestry required"
        );
    }
    fs::create_dir(&args.directory)?;
    // Retain the actual metadata parent without DELETE sharing. Elevation is
    // checked by the constructor's real native privilege lease; no environment
    // name or serialized identity is accepted as proof of SYSTEM/elevation.
    let _parent = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(&args.directory)?;
    let budget = Budget {
        rust_ram_bytes: 64 << 20,
        powershell_ram_bytes: 384 << 20,
        scratch_bytes: 12 << 30,
        minimum_free_bytes: 1 << 30,
    };
    let result = thin_pool::create_new(
        &args.directory.join("provider"),
        &args.storage_subsystem,
        GOAL_BYTES,
        budget,
    );
    let mut output = CappedWriter {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.directory.join("result.json"))?,
        remaining: RESULT_BYTES,
    };
    let report = match &result {
        Ok(owner) => serde_json::json!({
            "schema_version":1,"kind":"lab-private-thin-constructor","success":true,
            "requested_bytes":GOAL_BYTES,"budget":budget,"observation":owner.observation(),
            "source_argument_supplied":false,"conversion_authorized":false,
            "gpt_or_format_requested":false,"cleanup_or_retry_attempted":false,
            "persistent_reattachment_or_conversion_qualified":false
        }),
        Err(error) => serde_json::json!({
            "schema_version":1,"kind":"lab-private-thin-constructor","success":false,
            "requested_bytes":GOAL_BYTES,"budget":budget,"error":error.to_string(),
            "native_error":error.raw_os_error(),"source_argument_supplied":false,
            "conversion_authorized":false,"gpt_or_format_requested":false,
            "cleanup_or_retry_attempted":false,"all_created_assets_preserved":true,
            "persistent_reattachment_or_conversion_qualified":false
        }),
    };
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    output.file.sync_all()?;
    // Keep a successful live owner through the durable result write. Dropping
    // it closes handles only; the permanent members and pool remain preserved.
    drop(result?);
    println!(
        "Private constructor completed. Records: {}",
        args.directory.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("private thin constructor requires Windows");
    std::process::exit(1);
}
