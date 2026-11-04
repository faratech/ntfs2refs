//! Fresh, constructor-owned large ReFS format probe. No source or recovery.
#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("private thin format stopped: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{
        file_storage,
        managed_shadow::{
            TargetFormatProfile,
            thin_pool::{self, Budget},
        },
    };
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, PathBuf, Prefix},
    };
    use xxhash_rust::xxh3::xxh3_128;

    const PARTITION_BYTES: u64 = 72 << 40;
    const PROVIDER_GOAL_BYTES: u64 = PARTITION_BYTES + (64 << 20);
    const PROBE_BYTES: usize = 64 << 10;
    const RESULT_BYTES: u64 = 128 << 10;

    #[derive(Parser)]
    struct Args {
        /// New ordinary metadata parent; fresh provider files go beneath it.
        #[arg(long)]
        directory: PathBuf,
        /// Exact Windows Storage subsystem UniqueId, never a device or pool.
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
                return Err(io::Error::other("thin format result exceeds its allowance"));
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
    let mut output = CappedWriter {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.directory.join("result.json"))?,
        remaining: RESULT_BYTES,
    };
    let mut phase = "create-new-bounded-private-provider";
    let operation = (|| -> anyhow::Result<_> {
        let owner = thin_pool::create_bounded_with_carrier(
            &args.directory.join("provider"),
            &args.storage_subsystem,
            PROVIDER_GOAL_BYTES,
            budget,
        )?;
        phase = "format-constructor-owned-partition";
        let owner = owner.format(PARTITION_BYTES, TargetFormatProfile::DevDrive)?;
        phase = "ordinary-file-write-flush-readback";
        let probe_path =
            PathBuf::from(format!("{}\\", owner.binding().volume_path()?)).join("probe.bin");
        let mut probe = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&probe_path)?;
        let id = file_storage::file_id_info(&probe)?;
        let mut expected = [0u8; PROBE_BYTES];
        for (index, byte) in expected.iter_mut().enumerate() {
            *byte = ((index * 17 + index / 251 + 83) % 251) as u8;
        }
        let expected_hash = xxh3_128(&expected);
        probe.write_all(&expected)?;
        probe.sync_all()?;
        ensure!(
            probe.metadata()?.len() == PROBE_BYTES as u64,
            "probe length after flush differs"
        );
        probe.seek(SeekFrom::Start(0))?;
        let mut actual = [0u8; PROBE_BYTES];
        probe.read_exact(&mut actual)?;
        let mut extra = [0u8; 1];
        let eof = probe.read(&mut extra)? == 0;
        let actual_hash = xxh3_128(&actual);
        let final_metadata = probe.metadata()?;
        ensure!(
            eof && final_metadata.len() == PROBE_BYTES as u64
                && final_metadata.is_file()
                && final_metadata.file_attributes() & 0x400 == 0
                && file_storage::file_id_info(&probe)? == id
                && actual_hash == expected_hash
                && actual == expected,
            "ordinary file identity, length, EOF or XXH3-128 readback differs"
        );
        let receipt = serde_json::json!({
            "path":probe_path,"bytes":PROBE_BYTES,"file_id":id,
            "expected_xxh3_128":format!("{expected_hash:032x}"),
            "readback_xxh3_128":format!("{actual_hash:032x}"),
            "sync_all_succeeded":true,"length_verified":true,
            "eof_verified":eof,"same_handle_identity_verified":true,
            "exact_bytes_verified":true,"ordinary_filesystem_io_only":true,
            "actual_high_offset_io_qualified":false
        });
        phase = "completed";
        Ok((owner, receipt))
    })();
    let report = match &operation {
        Ok((owner, probe)) => serde_json::json!({
            "schema_version":1,"kind":"lab-private-thin-format","success":true,
            "phase":phase,"directory":args.directory,"budget":budget,
            "partition_bytes":PARTITION_BYTES,"provider_goal_bytes":PROVIDER_GOAL_BYTES,
            "binding":owner.binding(),"format_policy":owner.format_policy(),
            "observation":owner.observation(),"ordinary_file_probe":probe,
            "source_argument_supplied":false,"conversion_authorized":false,
            "conversion_or_recovery_qualified":false,"public_backend_changed":false,
            "persistent_reattachment_qualified":false,"actual_high_offset_io_qualified":false,
            "cleanup_or_retry_attempted":false,"all_created_assets_preserved":true
        }),
        Err(error) => serde_json::json!({
            "schema_version":1,"kind":"lab-private-thin-format","success":false,
            "phase":phase,"directory":args.directory,"budget":budget,
            "partition_bytes":PARTITION_BYTES,"provider_goal_bytes":PROVIDER_GOAL_BYTES,
            "error":format!("{error:#}"),
            "native_error":error.chain().find_map(|e| e.downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error)),
            "source_argument_supplied":false,"conversion_authorized":false,
            "conversion_or_recovery_qualified":false,"public_backend_changed":false,
            "persistent_reattachment_qualified":false,"actual_high_offset_io_qualified":false,
            "cleanup_or_retry_attempted":false,"all_created_assets_preserved":true
        }),
    };
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    output.file.sync_all()?;
    // Keep the actual formatted owner until the result is durable. Drop closes
    // handles only; all fresh provider, filesystem and metadata assets remain.
    drop(operation?);
    println!(
        "Private large-volume format completed. Records: {}",
        args.directory.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("private thin format requires Windows");
    std::process::exit(1);
}
