//! Guest-only end-to-end exercise of the general engine on the enrolled
//! disposable disk geometry. Never a production conversion command.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::{Parser, ValueEnum};
    use ntfs2refs::{general_lab, general_reconstruct, lab_reconstruct::JournalTicket};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Clone, Copy, Serialize, ValueEnum)]
    #[serde(rename_all = "snake_case")]
    enum Mode {
        Apply,
        Finalize,
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
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        output: PathBuf,
    }
    fn pinned(path: &PathBuf, expected: &str, max: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "guest experiment input is not an ordinary bounded file"
        );
        let mut file = OpenOptions::new().read(true).share_mode(1).open(path)?;
        let mut bytes = Vec::new();
        (&mut file).take(max + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= max
                && expected.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == expected,
            "guest experiment input pin differs"
        );
        Ok(bytes)
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "guest experiment report exceeds bound"
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
        "fresh guest experiment result and intent required"
    );
    let request: general_reconstruct::Request =
        serde_json::from_slice(&pinned(&args.request, &args.request_sha256, 131072)?)?;
    general_lab::require_disposable_guest(&request)?;
    let ticket: JournalTicket =
        serde_json::from_slice(&pinned(&args.ticket, &args.ticket_sha256, 65536)?)?;
    let expectation = pinned(
        &args.expectation,
        &args.expectation_sha256,
        16 * 1024 * 1024,
    )?;
    ensure!(
        args.expectation_sha256 == request.expected_tree_sha256,
        "guest expectation differs from the journal request"
    );
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(&args.journal)?;
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"disposable-general-conversion-intent",
            "mode":args.mode,"request_sha256":args.request_sha256,
            "ticket_sha256":args.ticket_sha256,
            "expectation_sha256":args.expectation_sha256,
            "guest_only":true,"production_conversion_qualified":false}),
    )?;
    let (success, rollback_closed, result, error) = match args.mode {
        Mode::Apply => match general_lab::apply(&request, &ticket, &mut journal, &expectation) {
            Ok(report) => (true, false, Some(serde_json::to_value(report)?), None),
            Err(error) => (false, false, None, Some(format!("{error:#}"))),
        },
        Mode::Finalize => {
            match general_lab::finalize(&request, &ticket, &mut journal, &expectation) {
                Ok(report) => {
                    let success = report.success;
                    let rollback_closed = report.rollback_closed;
                    let error = report.error.clone();
                    (
                        success,
                        rollback_closed,
                        Some(serde_json::to_value(report)?),
                        error,
                    )
                }
                Err(error) => (false, false, None, Some(format!("{error:#}"))),
            }
        }
    };
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"disposable-general-conversion",
            "mode":args.mode,"success":success,"rollback_closed":rollback_closed,
            "result":result,"error":error,"production_conversion_qualified":false}),
    )?;
    ensure!(
        success,
        "guest general conversion operation refused; preserve journal and disks"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("disposable general conversion exercise requires Windows");
    std::process::exit(1);
}
