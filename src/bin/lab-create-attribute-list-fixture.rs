//! Create only new, driver-relocated ATTRIBUTE_LIST fixtures on enrolled H:.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
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
        #[arg(long)]
        observe_existing: bool,
        #[arg(long)]
        prior_report: Option<PathBuf>,
        #[arg(long)]
        prior_sha256: Option<String>,
    }
    fn json_path(path: &Path, fresh: bool) -> anyhow::Result<()> {
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
        if fresh {
            ensure!(!path.try_exists()?, "output already exists");
        } else {
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.is_file()
                    && metadata.file_attributes() & 0x400 == 0
                    && metadata.len() <= 4 * 1024 * 1024,
                "ordinary bounded prior JSON report required"
            );
        }
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
    fn prior(path: &Path, expected_sha256: &str) -> anyhow::Result<(File, serde_json::Value)> {
        json_path(path, false)?;
        ensure!(
            expected_sha256.len() == 64
                && expected_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "lowercase SHA256 pin required"
        );
        // Keep the exact original report held without write/delete sharing for
        // the complete observation and fresh-report persistence.
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let before = file.metadata()?;
        ensure!(
            before.is_file()
                && before.file_attributes() & 0x400 == 0
                && before.len() <= 4 * 1024 * 1024,
            "prior report handle differs"
        );
        let identity = n2r_win32::file_storage::file_id_info(&file)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == before.len()
                && bytes.len() <= 4 * 1024 * 1024
                && hex::encode(Sha256::digest(&bytes)) == expected_sha256,
            "prior report length or SHA256 differs"
        );
        let after = file.metadata()?;
        ensure!(
            after.len() == before.len()
                && after.modified()? == before.modified()?
                && n2r_win32::file_storage::file_id_info(&file)? == identity,
            "prior report changed during pinned read"
        );
        Ok((file, serde_json::from_slice(&bytes)?))
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
    ensure!(
        if args.observe_existing {
            args.prior_report.is_some() && args.prior_sha256.is_some()
        } else {
            args.prior_report.is_none() && args.prior_sha256.is_none()
        },
        "--observe-existing requires --prior-report and --prior-sha256 together; creation accepts neither"
    );
    json_path(&args.output, true)?;
    let prior = if let (Some(path), Some(pin)) = (&args.prior_report, &args.prior_sha256) {
        Some(prior(path, pin)?)
    } else {
        None
    };
    // Reserve the fresh report before modifying the fixture. No path is ever
    // overwritten or deleted, including a partial report on an I/O failure.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.output)?;
    let mut report = if let Some((_held_original, value)) = &prior {
        n2r_win32::lab_ntfs_fragmentation::observe_existing(&args.probe_id, value)
    } else {
        n2r_win32::lab_ntfs_fragmentation::create(&args.probe_id)
    };
    if args.observe_existing {
        report["prior_report_path"] = json!(args.prior_report);
        report["prior_report_sha256"] = json!(args.prior_sha256);
        report["prior_report_immutable_held"] = json!(true);
    }
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
