//! One constructor-owned empty-image retirement primitive probe, never V4
//! integration qualification. No source/device argument or cleanup fallback.
#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("owned empty-shadow retirement probe: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, file_storage, managed_shadow, resource_native};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{self, Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, PathBuf, Prefix},
    };
    const RAM: u64 = 256 * 1024 * 1024;
    const SCRATCH: u64 = 2 * 1024 * 1024 * 1024;
    const FLOOR: u64 = 1024 * 1024 * 1024;
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        acknowledge_new_disposable_staging: bool,
    }
    struct BoundedFile {
        file: std::fs::File,
        remaining: u64,
    }
    impl Write for BoundedFile {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() as u64 > self.remaining {
                return Err(io::Error::other("probe receipt exceeds1MiB"));
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
    ensure!(
        args.directory.is_absolute() && !args.directory.exists(),
        "fresh absolute ordinary directory required"
    );
    for item in args.directory.components() {
        match item {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                anyhow::bail!("local drive required")
            }
            Component::CurDir | Component::ParentDir => {
                anyhow::bail!("directory traversal refused")
            }
            Component::Normal(s)
                if s.to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                anyhow::bail!("ambiguous directory component")
            }
            _ => {}
        }
    }
    let parent = args.directory.parent().context("staging parent absent")?;
    for path in parent.ancestors() {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "reparse/ordinary ancestry differs"
        );
    }
    let available = resource_native::observe_available_resources(parent)?;
    ensure!(
        available.available_physical_bytes >= RAM
            && available.scratch_available_bytes >= SCRATCH + FLOOR + 1024 * 1024,
        "256MiB RAM/2GiB scratch/1GiB free floor unavailable"
    );
    fs::create_dir(&args.directory)?;
    let sentinel_path = args.directory.join("required-recovery.sentinel");
    let sentinel_bytes: Vec<u8> = (0..4096).map(|i| ((i * 17 + 83) % 251) as u8).collect();
    let expected_sentinel_sha = hex::encode(Sha256::digest(&sentinel_bytes));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sentinel_path)?;
        f.write_all(&sentinel_bytes)?;
        f.sync_all()?;
    }
    let mut sentinel = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&sentinel_path)?;
    let sentinel_id = file_storage::file_id_info(&sentinel)?;
    let image = args.directory.join("shadow.vhdx");
    let mut events = Vec::new();
    let mut before_storage = None;
    let mut owned_binding = None;
    let primitive = (|| -> anyhow::Result<_> {
        let shadow = managed_shadow::create(&image, 50 * 1024 * 1024 * 1024, 512, 4096)?;
        owned_binding = Some(shadow.binding.clone());
        let storage = file_storage::observe(&image)?;
        ensure!(
            storage.filesystem_storage_bytes <= SCRATCH,
            "observed backing exceeds2GiB phase allowance; preserve without cleanup"
        );
        before_storage = Some(storage);
        ensure!(
            resource_native::observe_available_resources(&args.directory)?.scratch_available_bytes
                >= FLOOR + 1024 * 1024,
            "free floor unavailable; preserve without cleanup"
        );
        let raw = GeneralFrozenPartition::isolate(shadow.binding.clone(), &mut events)?;
        drop(raw);
        // Intentionally test only the constructor-owner detach/delete API
        // primitive. No real V4 finalizer or conversion ran in this experiment.
        Ok(shadow.retire_after_successful_v4())
    })();
    sentinel.seek(SeekFrom::Start(0))?;
    let mut actual = Vec::with_capacity(4096);
    Read::by_ref(&mut sentinel)
        .take(4097)
        .read_to_end(&mut actual)?;
    let actual_sentinel_sha = hex::encode(Sha256::digest(&actual));
    let sentinel_preserved = sentinel_path.is_file()
        && actual.len() == 4096
        && actual_sentinel_sha == expected_sentinel_sha
        && file_storage::file_id_info(&sentinel)? == sentinel_id;
    let image_present = image.try_exists()?;
    let success =
        primitive.as_ref().is_ok_and(|r| r.success) && !image_present && sentinel_preserved;
    let error = primitive.as_ref().err().map(|e| format!("{e:#}"));
    let receipt = primitive.as_ref().ok();
    let report = serde_json::json!({"schema_version":1,"kind":"owned-empty-shadow-retirement-primitive-probe","success":success,
        "directory":args.directory,"owned_binding":owned_binding,"before_backing_storage":before_storage,"retirement":receipt,"error":error,
        "native_isolation_events":events,"sentinel_path":sentinel_path,"sentinel_file_id":sentinel_id,"sentinel_expected_sha256":expected_sentinel_sha,
        "sentinel_readback_sha256":actual_sentinel_sha,"sentinel_preserved":sentinel_preserved,"image_present_after_primitive":image_present,
        "ram_admission_bytes":RAM,"scratch_phase_allowance_bytes":SCRATCH,"minimum_free_bytes":FLOOR,"available_before":available,
        "budgets_are_sampled_not_kernel_quotas":true,"v4_integration_qualified":false,"real_v4_finalizer_executed":false,
        "source_binding_supplied":false,"source_or_existing_alpha_access_requested":false,"automatic_retry_or_fallback":false,
        "physical_freed_bytes_or_ram_savings_measured":false});
    let mut out = BoundedFile {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.directory.join("result.json"))?,
        remaining: 1024 * 1024,
    };
    serde_json::to_writer_pretty(&mut out, &report)?;
    out.write_all(b"\n")?;
    out.file.sync_all()?;
    primitive?;
    ensure!(
        success,
        "primitive retirement or external sentinel verification failed; preserve remaining files without retry"
    );
    println!(
        "Owned empty-shadow retirement primitive completed. Records: {}",
        args.directory.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("owned-shadow retirement primitive requires Windows");
    std::process::exit(1);
}
