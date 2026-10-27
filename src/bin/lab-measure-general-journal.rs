//! Read-only journal sizing of an already excluded source/shadow pair.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::GeneralFrozenPartition;
    use ntfs2refs::general_reconstruct;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
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
        progress: PathBuf,
    }
    let args = Args::parse();
    ensure!(
        args.request != args.output
            && args.request != args.progress
            && args.output != args.progress
            && !args.output.exists()
            && !args.progress.exists(),
        "fresh distinct sizing outputs required"
    );
    let metadata = fs::symlink_metadata(&args.request)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 131072,
        "bounded ordinary pinned request required"
    );
    let bytes = fs::read(&args.request)?;
    ensure!(
        bytes.len() <= 131072 && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "sizing request pin differs"
    );
    let request: general_reconstruct::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
    let mut status = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(&args.progress)?;
    let mut progress_error = None;
    let report = general_reconstruct::measure_journal_requirements(
        &request,
        &mut source,
        &mut shadow,
        &mut |value| {
            let written = (|| -> std::io::Result<()> {
                let bytes = serde_json::to_vec(&value).map_err(std::io::Error::other)?;
                status.seek(SeekFrom::Start(0))?;
                status.write_all(&bytes)?;
                status.set_len(bytes.len() as u64)?;
                status.flush()
            })();
            if let Err(error) = written {
                progress_error.get_or_insert(error);
            }
        },
    )?;
    if let Some(error) = progress_error {
        return Err(error.into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&args.output)?;
    output.write_all(&serde_json::to_vec_pretty(&serde_json::json!({
        "request_sha256":args.request_sha256,"measurement":report,"open_events":events
    }))?)?;
    output.sync_all()?;
    println!("Frozen journal sizing complete; no journal or source writes.");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("frozen native journal sizing requires Windows");
    std::process::exit(1);
}
