//! Prepare a durable old/new journal for two already excluded, independently
//! bound data partitions. This command does not activate or write the source.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, NativeEvent};
    use ntfs2refs::general_reconstruct::{self, Request};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long)]
        report: PathBuf,
    }
    fn regular(path: &Path) -> anyhow::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
            "pinned input is not an ordinary file"
        );
        Ok(())
    }
    fn save(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    for path in [&args.journal, &args.ticket, &args.report] {
        ensure!(
            !path.exists(),
            "fresh journal, ticket and report paths required"
        );
    }
    ensure!(
        args.journal != args.ticket
            && args.journal != args.report
            && args.ticket != args.report
            && args.request != args.journal
            && args.request != args.ticket
            && args.request != args.report,
        "artifact paths alias"
    );
    regular(&args.request)?;
    let mut request_file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.request)?;
    ensure!(
        request_file.metadata()?.len() <= 131072,
        "request exceeds bound"
    );
    let mut bytes = Vec::new();
    (&mut request_file).take(131073).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 131072
            && args.request_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "general request pin differs"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let mut events = Vec::<NativeEvent>::new();
    let mut source = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(&args.journal)?;
    let prepared = general_reconstruct::prepare(&request, &mut source, &mut shadow, &mut journal)?;
    let ticket = serde_json::to_vec_pretty(&prepared.journal.ticket)?;
    let report = serde_json::to_vec_pretty(&prepared)?;
    ensure!(
        ticket.len() <= 65536 && report.len() <= 64 * 1024 * 1024,
        "general preparation artifact exceeds bound"
    );
    save(&args.ticket, &ticket)?;
    save(&args.report, &report)?;
    println!(
        "General journal prepared; ticket SHA-256 {}; source remains excluded read-only.",
        hex::encode(Sha256::digest(&ticket))
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general journal preparation requires Windows");
    std::process::exit(1);
}
