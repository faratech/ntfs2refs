//! One owning-guest run of the bounded general journal engine. Every durable
//! stage is saved on independent C: storage before the next transition.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::GeneralFrozenPartition;
    use ntfs2refs::{general_lab, general_reconstruct, lab_reconstruct::JournalTicket};
    use serde::Serialize;
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
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        artifacts: PathBuf,
    }
    fn ordinary(path: &Path, existing: bool) -> Result<()> {
        let text = path.to_str().context("non-Unicode guest artifact")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains('/')
                && !text.contains("..")
                && !text.ends_with([' ', '.']),
            "guest artifacts must be ordinary paths under C:\\ntfs2refs"
        );
        for (index, ancestor) in path.ancestors().enumerate() {
            if index == 0 && !existing {
                ensure!(!ancestor.exists(), "fresh artifact path required");
                continue;
            }
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(
                metadata.file_attributes() & 0x400 == 0
                    && if index == 0 {
                        metadata.is_file() == existing
                    } else {
                        metadata.is_dir()
                    },
                "guest artifact ancestry or type differs"
            );
        }
        Ok(())
    }
    fn pinned(path: &Path, expected: &str, max: u64) -> Result<Vec<u8>> {
        ordinary(path, true)?;
        let mut file = OpenOptions::new().read(true).share_mode(1).open(path)?;
        ensure!(file.metadata()?.len() <= max, "pinned input exceeds bound");
        let mut bytes = Vec::new();
        (&mut file).take(max + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= max
                && expected.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == expected,
            "guest input SHA-256 differs"
        );
        Ok(bytes)
    }
    fn save(path: &Path, bytes: &[u8]) -> Result<String> {
        ordinary(path, false)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "guest artifact exceeds bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
    fn save_json(path: &Path, value: &impl Serialize) -> Result<String> {
        save(path, &serde_json::to_vec_pretty(value)?)
    }
    let args = Args::parse();
    let request_bytes = pinned(&args.request, &args.request_sha256, 131072)?;
    let request: general_reconstruct::Request = serde_json::from_slice(&request_bytes)?;
    general_lab::require_disposable_guest(&request)?;
    let expectation_bytes = pinned(
        &args.expectation,
        &args.expectation_sha256,
        16 * 1024 * 1024,
    )?;
    ensure!(
        args.expectation_sha256 == request.expected_tree_sha256,
        "expected tree does not belong to this conversion request"
    );
    let expected_journal = format!(
        "J:\\ntfs2refs-shadow\\{}\\reconstruction.journal",
        request.experiment_id
    );
    ensure!(
        args.journal.to_str() == Some(expected_journal.as_str()),
        "guest lab journal path differs"
    );
    ordinary(&args.artifacts, false)?;
    fs::create_dir(&args.artifacts)?;
    let mut phase = "intent";
    let outcome = (|| -> Result<()> {
        save_json(
            &args.artifacts.join("intent.json"),
            &serde_json::json!({"schema_version":1,"kind":"disposable-general-complete-intent",
                "request_sha256":args.request_sha256,
                "expectation_sha256":args.expectation_sha256,
                "journal":args.journal,"rollback_closes_before_native_mount":true,
                "production_conversion_qualified":false}),
        )?;
        ensure!(
            save(&args.artifacts.join("request.json"), &request_bytes)? == args.request_sha256
                && save(&args.artifacts.join("expectation.json"), &expectation_bytes)?
                    == args.expectation_sha256,
            "durable guest recovery inputs differ"
        );
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&args.journal)?;
        phase = "prepare";
        let mut events = Vec::new();
        let mut source = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
        let mut shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
        let prepared =
            general_reconstruct::prepare(&request, &mut source, &mut shadow, &mut journal)?;
        save_json(&args.artifacts.join("prepare.json"), &prepared)?;
        drop(source);
        drop(shadow);
        let ticket_bytes = serde_json::to_vec_pretty(&prepared.journal.ticket)?;
        let ticket_sha256 = save(&args.artifacts.join("ticket.json"), &ticket_bytes)?;
        let ticket_readback = pinned(&args.artifacts.join("ticket.json"), &ticket_sha256, 65536)?;
        ensure!(
            ticket_readback == ticket_bytes
                && hex::encode(Sha256::digest(&ticket_readback)) == ticket_sha256,
            "durable ticket readback differs"
        );
        let ticket: JournalTicket = serde_json::from_slice(&ticket_readback)?;
        save_json(
            &args.artifacts.join("recovery.json"),
            &serde_json::json!({"schema_version":1,"kind":"general-recovery-pins",
                "request_sha256":args.request_sha256,
                "expectation_sha256":args.expectation_sha256,
                "ticket_sha256":ticket_sha256,"journal":args.journal,
                "recovery_commands":["lab-recover-general-journal resume","lab-recover-general-journal rollback"],
                "rollback_expires_at_handoff":true}),
        )?;
        phase = "apply";
        let applied = general_lab::apply(&request, &ticket, &mut journal, &expectation_bytes)?;
        save_json(&args.artifacts.join("apply.json"), &applied)?;
        phase = "finalize";
        let finished = general_lab::finalize(&request, &ticket, &mut journal, &expectation_bytes)?;
        save_json(&args.artifacts.join("finish.json"), &finished)?;
        ensure!(
            finished.success,
            "native ReFS verification refused after handoff: {:?}",
            finished.error
        );
        phase = "complete";
        Ok(())
    })();
    if let Err(error) = &outcome {
        let _ = save_json(
            &args.artifacts.join("failure.json"),
            &serde_json::json!({"schema_version":1,"kind":"disposable-general-complete-failure",
                "phase":phase,"error":format!("{error:#}"),
                "inspect_journal_marker_and_disk_state_before_any_action":true,
                "production_conversion_qualified":false}),
        );
    }
    outcome
}

#[cfg(not(windows))]
fn main() {
    eprintln!("disposable general conversion requires Windows");
    std::process::exit(1);
}
