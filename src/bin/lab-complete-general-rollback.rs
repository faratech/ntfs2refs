//! Finish a fully restored NTFS preimage: close stale journal replay, bring
//! the original data disk online and confirm Windows mounts it as NTFS.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, GeneralJournaledPartition};
    use ntfs2refs::{general_reconstruct, lab_reconstruct::JournalTicket};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
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
        ticket: PathBuf,
        #[arg(long)]
        ticket_sha256: String,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        output: PathBuf,
    }
    fn pinned(path: &PathBuf, sha256: &str, max: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "rollback completion input is not an ordinary bounded file"
        );
        let mut file = OpenOptions::new().read(true).share_mode(1).open(path)?;
        let mut bytes = Vec::new();
        (&mut file).take(max + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= max
                && sha256.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == sha256,
            "rollback completion input pin differs"
        );
        Ok(bytes)
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "rollback completion report exceeds bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    let intent = args.output.with_extension("intent.json");
    ensure!(
        !args.output.exists() && !intent.exists(),
        "fresh rollback completion report and intent required"
    );
    let request: general_reconstruct::Request =
        serde_json::from_slice(&pinned(&args.request, &args.request_sha256, 131072)?)?;
    request.validate()?;
    let ticket: JournalTicket =
        serde_json::from_slice(&pinned(&args.ticket, &args.ticket_sha256, 65536)?)?;
    let mut events = Vec::new();
    let target = GeneralJournaledPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(&args.journal)?;
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"general-ntfs-rollback-completion-intent",
            "request_sha256":args.request_sha256,"ticket_sha256":args.ticket_sha256,
            "journal_replay_will_close":true,"source_payload_writes":0}),
    )?;
    let completed = general_reconstruct::complete_rollback(
        &request,
        target,
        &mut shadow,
        &mut journal,
        &ticket,
        events,
    )?;
    let success = completed.success;
    save(&args.output, &completed)?;
    ensure!(
        success,
        "original NTFS online completion refused; preserve journal and inspect disk state"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general NTFS rollback completion requires Windows");
    std::process::exit(1);
}
