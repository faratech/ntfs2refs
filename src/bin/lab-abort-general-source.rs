//! Abort before journal activation: restore the byte-identical original NTFS
//! source from OFFLINE|READ_ONLY to online. This cannot open an activated disk.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralDiskState, GeneralFrozenPartition, general_layout::GeneralDiskBinding};
    use serde::{Deserialize, Serialize};
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
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        frozen_report: PathBuf,
        #[arg(long)]
        frozen_report_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    #[derive(Deserialize)]
    struct Frozen {
        schema_version: u32,
        kind: String,
        binding_sha256: String,
        source_sha256: String,
        before: GeneralDiskState,
        after: GeneralDiskState,
    }
    fn pinned(path: &PathBuf, sha256: &str, max: u64) -> anyhow::Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "bounded ordinary pinned input required"
        );
        let bytes = fs::read(path)?;
        ensure!(
            sha256.len() == 64 && hex::encode(Sha256::digest(&bytes)) == sha256,
            "abort input pin differs"
        );
        Ok(bytes)
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "abort artifact exceeds bound"
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
        "fresh abort report and intent required"
    );
    let binding: GeneralDiskBinding =
        serde_json::from_slice(&pinned(&args.binding, &args.binding_sha256, 16384)?)?;
    let frozen: Frozen = serde_json::from_slice(&pinned(
        &args.frozen_report,
        &args.frozen_report_sha256,
        64 * 1024 * 1024,
    )?)?;
    binding.validate()?;
    ensure!(
        frozen.schema_version == 1
            && matches!(
                frozen.kind.as_str(),
                "general-frozen-ntfs-source" | "general-frozen-ntfs-read-only-basis"
            )
            && frozen.binding_sha256 == args.binding_sha256
            && frozen.before == frozen.after
            && frozen.after.disk_attributes == 3
            && frozen.source_sha256.len() == 64
            && frozen
                .source_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "original NTFS freeze evidence differs"
    );
    let mut events = Vec::new();
    let source = GeneralFrozenPartition::reopen(binding, &mut events)?;
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"general-original-source-abort-intent",
            "binding_sha256":args.binding_sha256,
            "frozen_report_sha256":args.frozen_report_sha256,
            "source_sha256":frozen.source_sha256,"source_payload_writes":0}),
    )?;
    source.bring_original_online_unchanged(&frozen.source_sha256, &mut events)?;
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-original-source-aborted",
            "source_sha256":frozen.source_sha256,"original_ntfs_online":true,
            "source_payload_writes":0,"events":events,"conversion_qualified":false}),
    )?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general original-source abort requires Windows");
    std::process::exit(1);
}
