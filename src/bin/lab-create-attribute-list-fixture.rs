//! Create only new, driver-relocated ATTRIBUTE_LIST fixtures on enrolled H:.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        probe_id: String,
        #[arg(long)]
        acknowledge_disposable_data_volume: bool,
    }
    fn output_path(path: &Path) -> anyhow::Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|e| e == "json"),
            "absolute fresh C: JSON output required"
        );
        for component in path.components() {
            match component {
                Component::Prefix(p) => ensure!(
                    matches!(p.kind(), Prefix::Disk(b'C' | b'c')),
                    "output must be on C: metadata volume"
                ),
                Component::RootDir => (),
                Component::Normal(p) => ensure!(
                    n2r_win32::shadow_names::valid_unicode_component(
                        p.to_str().context("Unicode output required")?
                    ),
                    "invalid output component"
                ),
                _ => anyhow::bail!("output traversal refused"),
            }
        }
        ensure!(!path.try_exists()?, "output already exists");
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "ordinary output ancestry required"
            );
        }
        Ok(())
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume,
        "explicit disposable data-volume acknowledgement required"
    );
    ensure!(
        args.probe_id.len() == 32
            && args
                .probe_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase 32-character probe ID required"
    );
    output_path(&args.output)?;
    // Reserve the fresh report before modifying the fixture. No path is ever
    // overwritten or deleted, including a partial report on an I/O failure.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.output)?;
    let report = n2r_win32::lab_ntfs_fragmentation::create(&args.probe_id);
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "fixture report exceeds four MiB"
    );
    output.write_all(&bytes)?;
    output.sync_all()?;
    let success = report["success"] == true;
    println!(
        "{}",
        json!({"success":success,"report":args.output,
        "report_sha256":hex::encode(Sha256::digest(&bytes)),"conversion_qualified":false})
    );
    ensure!(
        success,
        "fixture creation refused or incomplete; inspect preserved report"
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("ATTRIBUTE_LIST fixture creation requires the enrolled Windows guest");
    std::process::exit(2);
}
