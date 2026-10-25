//! Read-only raw NTFS inventory of a dedicated Windows data disk. The source
//! may change while mounted, so this output never grants conversion authority.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralPartitionReader, general_layout::GeneralDiskBinding};
    use ntfs2refs::ntfs_inspect;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        path::PathBuf,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    #[derive(Serialize)]
    struct Report {
        schema_version: u32,
        kind: &'static str,
        binding_sha256: String,
        before: n2r_win32::GeneralProbe,
        after: n2r_win32::GeneralProbe,
        ntfs: ntfs_inspect::NtfsInspection,
        native_bytes_read: u64,
        events: Vec<n2r_win32::NativeEvent>,
        source_frozen: bool,
        source_admitted: bool,
        conversion_qualified: bool,
    }
    let args = Args::parse();
    let input = fs::symlink_metadata(&args.binding)?;
    ensure!(
        input.is_file() && input.len() <= 16384,
        "bounded ordinary binding required"
    );
    let bytes = fs::read(&args.binding)?;
    ensure!(
        args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    let mut events = Vec::new();
    let mut reader = GeneralPartitionReader::open(binding, &mut events)?;
    let before = reader.initial_probe().clone();
    let length = reader.byte_len();
    let ntfs = ntfs_inspect::inspect(&mut reader, length)?;
    let after = reader.revalidate_route(&mut events)?;
    let report = Report {
        schema_version: 1,
        kind: "general-mounted-ntfs-read-only-inventory",
        binding_sha256: args.binding_sha256,
        before,
        after,
        ntfs,
        native_bytes_read: reader.native_bytes_read,
        events,
        source_frozen: false,
        source_admitted: false,
        conversion_qualified: false,
    };
    let output = serde_json::to_vec_pretty(&report)?;
    ensure!(
        output.len() <= 64 * 1024 * 1024,
        "inventory report exceeds bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    file.write_all(&output)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("native disk inventory requires Windows");
    std::process::exit(1);
}
