//! Assemble a general journal request from pinned frozen-shadow evidence.
//! The subsequent preparation command reopens and rehashes the actual disks.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralDiskState, journal_file::GeneralJournalStorageBinding};
    use ntfs2refs::{
        general_reconstruct, general_shadow, retained_compare::RetainedCompareRequest,
    };
    use serde::Deserialize;
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
        freeze: PathBuf,
        #[arg(long)]
        freeze_sha256: String,
        #[arg(long)]
        journal_binding: PathBuf,
        #[arg(long)]
        journal_binding_sha256: String,
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        output: PathBuf,
    }
    #[derive(Deserialize)]
    struct Frozen {
        schema_version: u32,
        kind: String,
        request: general_shadow::Request,
        source_sha256: String,
        shadow_sha256: String,
        native_evidence_sha256: String,
        source_before: GeneralDiskState,
        source_after: GeneralDiskState,
        shadow_before: GeneralDiskState,
        shadow_after: GeneralDiskState,
        comparison_request: RetainedCompareRequest,
        retained_allocator_coverage_verified: bool,
    }
    fn pinned(path: &PathBuf, sha256: &str, limit: u64) -> anyhow::Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() <= limit,
            "bounded ordinary pinned input required"
        );
        let bytes = fs::read(path)?;
        ensure!(
            sha256.len() == 64 && hex::encode(Sha256::digest(&bytes)) == sha256,
            "input SHA-256 pin differs"
        );
        Ok(bytes)
    }
    let args = Args::parse();
    ensure!(
        !args.output.exists(),
        "fresh general journal request output required"
    );
    let freeze: Frozen = serde_json::from_slice(&pinned(
        &args.freeze,
        &args.freeze_sha256,
        64 * 1024 * 1024,
    )?)?;
    let journal: GeneralJournalStorageBinding = serde_json::from_slice(&pinned(
        &args.journal_binding,
        &args.journal_binding_sha256,
        16384,
    )?)?;
    freeze.request.validate()?;
    ensure!(
        freeze.schema_version == 1
            && freeze.kind == "general-frozen-refs-shadow"
            && freeze.native_evidence_sha256.len() == 64
            && freeze
                .native_evidence_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && freeze.source_sha256 == freeze.request.source_sha256
            && freeze.comparison_request.source_sha256 == freeze.source_sha256
            && freeze.comparison_request.shadow_sha256 == freeze.shadow_sha256
            && freeze.source_before == freeze.source_after
            && freeze.shadow_before == freeze.shadow_after
            && freeze.source_after.disk_attributes == 3
            && freeze.shadow_after.disk_attributes == 3
            && (freeze.comparison_request.retained_ranges.is_empty()
                || freeze.retained_allocator_coverage_verified),
        "frozen source/shadow request or exclusion differs"
    );
    let request = general_reconstruct::Request {
        schema_version: 1,
        experiment_id: args.experiment_id,
        pair: freeze.request.pair,
        comparison: freeze.comparison_request,
        journal,
        max_journal_bytes: 768 * 1024 * 1024,
    };
    request.validate()?;
    let bytes = serde_json::to_vec_pretty(&request)?;
    ensure!(bytes.len() <= 131072, "journal request exceeds bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&args.output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!(
        "General journal request SHA-256 {}",
        hex::encode(Sha256::digest(&bytes))
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general journal request assembly requires Windows");
    std::process::exit(1);
}
