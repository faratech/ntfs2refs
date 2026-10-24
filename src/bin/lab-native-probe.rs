//! Explicit native lab qualification, with no raw payload write command.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use ntfs2refs::lab_native::{ProbeRequest, probe};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    #[derive(Parser)]
    struct Arguments {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        reopen: bool,
        #[arg(long)]
        whole_partition: bool,
    }
    fn check_path(path: &Path, existing: bool) -> anyhow::Result<()> {
        let text = path.to_str().context("non-Unicode path")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains('/')
                && !text.contains("..")
                && !text.ends_with([' ', '.']),
            "probe artifacts must be ordinary paths under C:\\ntfs2refs"
        );
        for (index, part) in path.ancestors().enumerate() {
            if index == 0 && !existing {
                ensure!(!part.exists(), "output already exists");
                continue;
            }
            let meta = fs::symlink_metadata(part)?;
            ensure!(
                meta.file_attributes() & 0x400 == 0,
                "reparse ancestor refused"
            );
            ensure!(
                if index == 0 {
                    meta.is_file()
                } else {
                    meta.is_dir()
                },
                "unexpected artifact or ancestor type"
            );
        }
        Ok(())
    }
    fn save_new(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
        check_path(path, false)?;
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(bytes.len() <= 1024 * 1024, "report exceeds1MiB");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Arguments::parse();
    check_path(&args.request, true)?;
    check_path(&args.output, false)?;
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.request)?;
    ensure!(
        input.metadata()?.len() <= 16384,
        "probe request exceeds16KiB"
    );
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request hash differs"
    );
    let request: ProbeRequest = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let intent = args.output.with_extension("intent.json");
    save_new(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"native-isolation-intent",
        "request_sha256":args.request_sha256,"request":request,"reopen":args.reopen,
        "whole_partition":args.whole_partition,"payload_write_requests_issued":false}),
    )?;
    let report = probe(request, args.reopen, args.whole_partition);
    save_new(&args.output, &report)?;
    ensure!(
        report.success,
        "native isolation probe failed: {}",
        report.error.as_deref().unwrap_or("unknown")
    );
    println!("Native isolation and raw retained reads verified; disks remain offline.");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Native lab qualification requires Windows.");
    std::process::exit(1);
}
