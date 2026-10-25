//! Restore persistent offline/read-only exclusion after an interrupted native
//! NTFS observation. Never clears write protection or writes partition bytes.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, general_layout::GeneralDiskBinding};
    use ntfs2refs::lab_reconstruct;
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
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        source_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "exclusion report exceeds bound"
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
        "fresh exclusion output and intent required"
    );
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 16384,
        "bounded ordinary binding required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.binding)?;
    let mut bytes = Vec::new();
    (&mut file).take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16384
            && args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256
            && args.source_sha256.len() == 64
            && args
                .source_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "exclusion binding or source pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    binding.validate()?;
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"restore-general-exclusion-intent",
            "binding_sha256":args.binding_sha256,"source_sha256":args.source_sha256,
            "source_writes_authorized":false,"conversion_qualified":false}),
    )?;
    let mut events = Vec::new();
    let (mut source, changed) = GeneralFrozenPartition::restore_exclusion(binding, &mut events)?;
    let before = source.state(&mut events)?;
    let length = source.byte_len();
    let actual = hex::encode(lab_reconstruct::hash_range(&mut source, 0, length)?);
    let after = source.state(&mut events)?;
    ensure!(
        actual == args.source_sha256 && before == after,
        "restored excluded source differs from pinned bytes or route"
    );
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-exclusion-restored",
            "changed":changed,"source_sha256":actual,"before":before,"after":after,
            "events":events,"source_payload_writes":0,"source_admitted":false,
            "conversion_qualified":false}),
    )?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general exclusion recovery requires Windows");
    std::process::exit(1);
}
