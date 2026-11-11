//! Read-only owning-guest extent query. Never opens a raw writer or reads any
//! queried file payload. The report is evidence, not conversion authority.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{extent_observation as extents, layout::guid_bytes, reference_file};
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

    fn ordinary_c_json(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|s| s == "json"),
            "absolute ordinary C JSON metadata path required"
        );
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(b'C' | b'c')),
                    "lab request/report must stay on the C metadata volume"
                ),
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = name.to_str().context("Unicode metadata path required")?;
                    ensure!(
                        n2r_win32::shadow_names::valid_unicode_component(name),
                        "ambiguous or reserved metadata path component"
                    );
                }
                _ => anyhow::bail!("metadata path traversal refused"),
            }
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let meta = fs::symlink_metadata(parent)?;
            ensure!(
                meta.is_dir() && meta.file_attributes() & 0x400 == 0,
                "ordinary non-reparse metadata ancestry required"
            );
        }
        Ok(())
    }

    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume
            && std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "explicit disposable N2R-WIN11 guest acknowledgement required"
    );
    ensure!(
        args.request_sha256.len() == 64
            && args
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase SHA-256 request pin required"
    );
    ordinary_c_json(&args.request)?;
    ordinary_c_json(&args.output)?;
    ensure!(!args.output.try_exists()?, "fresh report path required");
    let meta = fs::symlink_metadata(&args.request)?;
    ensure!(
        meta.is_file() && meta.file_attributes() & 0x400 == 0,
        "ordinary request file required"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.request)?;
    let before = reference_file::observe_reference_file_handle(&input)?;
    ensure!(
        (1..=extents::MAX_REQUEST_BYTES).contains(&before.file_bytes),
        "extent request exceeds four MiB"
    );
    let mut bytes = Vec::new();
    (&mut input)
        .take(extents::MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.file_bytes
            && reference_file::observe_reference_file_handle(&input)? == before
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request bytes, identity or pin differ"
    );
    let request: extents::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let b = &request.binding;
    ensure!(
        b.disk_number == 1
            && guid_bytes(&b.identity.disk_guid)?
                == guid_bytes("1b191872-c372-41ee-a416-e18863996f54")?
            && guid_bytes(&b.identity.partition_guid)?
                == guid_bytes("f06075a8-67a2-46b9-8fac-4af4da809617")?
            && b.identity.disk_bytes == 64_u64 * 1024 * 1024 * 1024
            && b.identity.partition_number == 2
            && b.identity.partition_offset == 16_u64 * 1024 * 1024
            && b.identity.partition_bytes == 52_u64 * 1024 * 1024 * 1024
            && b.identity.logical_sector_bytes == 512
            && b.identity.physical_sector_bytes == 4096,
        "read-only extent query requires the exact enrolled source1 GPT data partition"
    );

    // Native probes independently exclude the actual current Windows disk and
    // verify this mounted binding before and after metadata-only observations.
    let report = extents::query(&request)?;
    ensure!(
        reference_file::observe_reference_file_handle(&input)? == before,
        "held request identity changed during extent observation"
    );
    let output_bytes = serde_json::to_vec(&report)?;
    ensure!(
        output_bytes.len() as u64 <= extents::MAX_REPORT_BYTES,
        "extent report exceeds 64 MiB"
    );
    let report_sha256 = hex::encode(Sha256::digest(&output_bytes));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.output)?;
    output.write_all(&output_bytes)?;
    output.sync_all()?;
    drop(output);
    println!(
        "{}",
        serde_json::json!({
            "kind":"readonly-refs-extent-query-completion","success":report.success,
            "request_sha256":args.request_sha256,"report_path":args.output,
            "report_sha256":report_sha256,"report_bytes":output_bytes.len(),
            "files_requested":report.files_requested,"files_matching":report.files_matching,
            "payload_bytes_read":0,"source_write_requests":0,"raw_write_authority":false,
        })
    );
    ensure!(
        report.success,
        "fresh native extent evidence differs; closed report preserved"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Read-only ReFS extent observation requires the enrolled Windows guest");
    std::process::exit(2);
}
