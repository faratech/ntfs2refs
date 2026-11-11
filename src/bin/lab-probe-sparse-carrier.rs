//! Explicit private native experiment; never invokes conversion or recovery.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{reference_file, shadow_native::sparse_carrier_probe};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
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
        acknowledge_disposable_data_volume: bool,
    }
    fn metadata_path(path: &Path) -> anyhow::Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|v| v == "json"),
            "absolute C JSON metadata path required"
        );
        for part in path.components() {
            match part {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(b'C' | b'c')),
                    "probe metadata must stay on C"
                ),
                Component::RootDir => (),
                Component::Normal(value) => ensure!(
                    n2r_win32::shadow_names::valid_unicode_component(
                        value.to_str().context("Unicode metadata path required")?
                    ),
                    "invalid metadata component"
                ),
                _ => anyhow::bail!("metadata traversal refused"),
            }
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "ordinary metadata ancestry required"
            );
        }
        Ok(())
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume
            && std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "explicit disposable owning-guest acknowledgement required"
    );
    ensure!(
        args.request_sha256.len() == 64
            && args
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase request SHA256 required"
    );
    metadata_path(&args.request)?;
    metadata_path(&args.output)?;
    ensure!(!args.output.try_exists()?, "fresh report path required");
    let m = fs::symlink_metadata(&args.request)?;
    ensure!(
        m.is_file() && m.file_attributes() & 0x400 == 0,
        "ordinary request file required"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&args.request)?;
    let before = reference_file::observe_reference_file_handle(&input)?;
    ensure!(
        (1..=16384).contains(&before.file_bytes),
        "bounded probe request required"
    );
    let mut bytes = Vec::new();
    (&mut input).take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.file_bytes
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256
            && reference_file::observe_reference_file_handle(&input)? == before,
        "request identity or pin differs"
    );
    let request: sparse_carrier_probe::Request = serde_json::from_slice(&bytes)?;
    let report = sparse_carrier_probe::run(&request)?;
    ensure!(
        reference_file::observe_reference_file_handle(&input)? == before,
        "request changed during probe"
    );
    let bytes = serde_json::to_vec(&report)?;
    ensure!(bytes.len() <= 1024 * 1024, "probe report exceeds one MiB");
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&args.output)?;
    out.write_all(&bytes)?;
    out.sync_all()?;
    drop(out);
    println!(
        "{}",
        serde_json::json!({"kind":"sparse-carrier-probe-completion","success":report["success"],"report_path":args.output,"report_sha256":sha256,"report_bytes":bytes.len(),"request_sha256":args.request_sha256,"conversion_qualified":false})
    );
    ensure!(
        report["success"] == true,
        "sparse carrier probe failed; bounded report preserved"
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Private sparse carrier probe requires the enrolled Windows guest");
    std::process::exit(2);
}
