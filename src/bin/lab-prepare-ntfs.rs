//! Explicit owning-Windows NTFS-managed preparation. No raw writer/cutover.
#![forbid(unsafe_code)]
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Read,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, PathBuf, Prefix},
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
        acknowledge_ntfs_managed_preparation: bool,
        #[arg(long,default_value_t=64*1024*1024)]
        metadata_bytes: u64,
        #[arg(long,default_value_t=64*1024*1024)]
        receipt_bytes: u64,
        #[arg(long, default_value_t = 32768)]
        maximum_moves: u64,
        #[arg(long,default_value_t=64*1024*1024)]
        maximum_move_bytes: u64,
        #[arg(long)]
        maximum_payload_bytes: u64,
    }
    let a = Args::parse();
    ensure!(
        a.acknowledge_ntfs_managed_preparation,
        "explicit preparation acknowledgement required"
    );
    for p in [&a.request, &a.output] {
        ensure!(p.is_absolute(), "absolute ordinary path required");
        for part in p.components() {
            match part {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(_)),
                    "device/UNC paths refused"
                ),
                Component::RootDir => (),
                Component::Normal(name) => {
                    let s = name.to_str().context("Unicode path required")?;
                    ensure!(
                        !s.contains(':') && !s.ends_with(['.', ' ']),
                        "alternate/ambiguous path refused"
                    )
                }
                _ => anyhow::bail!("path traversal refused"),
            }
        }
        for parent in p.ancestors().skip(1).filter(|p| !p.as_os_str().is_empty()) {
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "ordinary ancestry required"
            );
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&a.request)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.file_attributes() & 0x400 == 0 && before.len() <= 131072,
        "bounded ordinary request required"
    );
    let mut bytes = Vec::new();
    (&mut file).take(131073).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && hex::encode(Sha256::digest(&bytes)) == a.request_sha256,
        "request pin/length differs"
    );
    let r: ntfs2refs::general_conversion::Request = serde_json::from_slice(&bytes)?;
    r.validate()?;
    let resources = r
        .source_resource_profile
        .context("explicit source resources required")?;
    ensure!(
        resources.is_streaming() && !r.verify_existing_shadow,
        "fresh streaming preparation required"
    );
    let report = ntfs2refs::ntfs_preparation::prepare(
        r.pair.source,
        r.pair.shadow,
        resources,
        &a.output,
        ntfs2refs::ntfs_preparation::Budget {
            metadata_bytes: a.metadata_bytes,
            receipt_bytes: a.receipt_bytes,
            maximum_moves: a.maximum_moves,
            maximum_move_bytes: a.maximum_move_bytes,
            maximum_payload_bytes: a.maximum_payload_bytes,
        },
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("NTFS preparation requires the owning Windows machine")
}
