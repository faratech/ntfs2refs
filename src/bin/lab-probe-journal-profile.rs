//! Metadata-only profile observation of an existing, unopened-for-write journal.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::journal_file::{JournalProfile, observe_general_journal_file_with_profile};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
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
        journal: PathBuf,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    ensure!(
        !args.output.exists() && args.output != args.request && args.output != args.journal,
        "fresh distinct report required"
    );
    let m = fs::symlink_metadata(&args.request)?;
    ensure!(
        m.is_file() && m.file_attributes() & 0x400 == 0 && m.len() <= 131072,
        "bounded ordinary request required"
    );
    let bytes = fs::read(&args.request)?;
    ensure!(
        bytes.len() <= 131072 && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request pin differs"
    );
    let request: ntfs2refs::general_reconstruct::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    ensure!(request.schema_version == 2, "explicit v2 request required");
    let file = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x00200000)
        .open(&args.journal)?;
    let legacy = observe_general_journal_file_with_profile(
        &file,
        &request.journal,
        JournalProfile::LegacyV1,
    );
    let legacy_error = legacy.as_ref().err().map(|e| e.to_string());
    let snapshot = observe_general_journal_file_with_profile(
        &file,
        &request.journal,
        JournalProfile::ExperimentalLargeV2,
    )?;
    let report = serde_json::json!({"schema_version":1,"kind":"existing-journal-profile-observation",
        "request_sha256":args.request_sha256,"legacy_accepted":legacy.is_ok(),"legacy_error":legacy_error,
        "v2_snapshot":snapshot,"journal_content_reads":0,"journal_writes":0,"source_device_opens":0,
        "execution_authorized":false,"conversion_qualified":false});
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    out.write_all(&serde_json::to_vec_pretty(&report)?)?;
    out.sync_all()?;
    println!("Existing journal metadata observed; no content reads or writes.");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("native journal metadata observation requires Windows");
    std::process::exit(1);
}
