//! Resume or roll back an already activated general data partition. The target
//! stays persistently offline; this command cannot initiate a new apply.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::{Parser, ValueEnum};
    use n2r_win32::{GeneralFrozenPartition, GeneralJournaledPartition};
    use ntfs2refs::{
        general_reconstruct::{self, RecoveryOperation},
        lab_reconstruct::JournalTicket,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Clone, Copy, ValueEnum, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum Mode {
        Resume,
        Rollback,
    }
    #[derive(Parser)]
    struct Args {
        #[arg(value_enum)]
        mode: Mode,
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
        /// Restore NTFS from the trusted old-byte journal when the ReFS shadow
        /// is unavailable. Valid only with rollback, never with resume.
        #[arg(long)]
        without_shadow: bool,
    }
    fn pinned(path: &PathBuf, expected: &str, max: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "recovery input is not a bounded ordinary file"
        );
        let mut file = OpenOptions::new().read(true).share_mode(1).open(path)?;
        let mut bytes = Vec::new();
        (&mut file).take(max + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= max
                && expected.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == expected,
            "recovery input pin differs"
        );
        Ok(bytes)
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "recovery report exceeds bound"
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
    ensure!(
        !args.without_shadow || matches!(args.mode, Mode::Rollback),
        "shadowless recovery is restricted to NTFS rollback"
    );
    let intent = args.output.with_extension("intent.json");
    ensure!(
        !args.output.exists() && !intent.exists(),
        "fresh recovery output and intent required"
    );
    let request: general_reconstruct::Request =
        serde_json::from_slice(&pinned(&args.request, &args.request_sha256, 131072)?)?;
    request.validate()?;
    let ticket: JournalTicket =
        serde_json::from_slice(&pinned(&args.ticket, &args.ticket_sha256, 65536)?)?;
    let mut events = Vec::new();
    let mut target = GeneralJournaledPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(&args.journal)?;
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"general-journal-recovery-intent",
            "mode":args.mode,"request_sha256":args.request_sha256,
            "ticket_sha256":args.ticket_sha256,"source_disk":request.pair.source.disk_number,
            "shadow_available":!args.without_shadow,"handoff_authorized":false}),
    )?;
    let operation = match args.mode {
        Mode::Resume => RecoveryOperation::Resume,
        Mode::Rollback => RecoveryOperation::Rollback,
    };
    let (attempted, shadow_state) = if args.without_shadow {
        (
            general_reconstruct::rollback_without_shadow(
                &request,
                &mut target,
                &mut journal,
                &ticket,
                &mut events,
            )
            .and_then(|report| Ok(serde_json::to_value(report)?)),
            None,
        )
    } else {
        let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
        let attempted = general_reconstruct::recover(
            operation,
            &request,
            &mut target,
            &mut shadow,
            &mut journal,
            &ticket,
            &mut events,
        )
        .and_then(|report| Ok(serde_json::to_value(report)?));
        (attempted, shadow.state(&mut events).ok())
    };
    let target_state = target.state(&mut events).ok();
    let target_offline_observed = target_state
        .as_ref()
        .is_some_and(|state| state.disk_attributes == 1);
    let shadow_excluded_observed = shadow_state
        .as_ref()
        .is_some_and(|state| state.disk_attributes == 3);
    let success = attempted.is_ok()
        && target_offline_observed
        && (args.without_shadow || shadow_excluded_observed);
    let error = attempted.as_ref().err().map(|error| format!("{error:#}"));
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-journal-recovery",
            "success":success,"mode":args.mode,"execution":attempted.ok(),
            "error":error,"target_write_bytes_requested":target.native_write_bytes_requested,
            "target_bytes_written":target.native_bytes_written,"events":events,
            "target_state":target_state,"shadow_state":shadow_state,
            "target_offline_observed":target_offline_observed,
            "shadow_excluded_observed":shadow_excluded_observed,
            "shadow_available":!args.without_shadow,"handoff_recorded":false,
            "conversion_qualified":false}),
    )?;
    ensure!(
        success,
        "general journal recovery failed; preserve excluded disks and ticket"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general journal recovery requires Windows");
    std::process::exit(1);
}
