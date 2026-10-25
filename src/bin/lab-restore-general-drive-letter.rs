//! Restore one pinned original drive letter after ReFS handoff. Never deletes
//! or reassigns an existing mount point; conflicting mappings are refused.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::restore_drive_letter_general;
    use ntfs2refs::general_reconstruct;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeSet,
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
        output: PathBuf,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "mount restoration report exceeds bound"
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
        "fresh mount restoration output and intent required"
    );
    let metadata = fs::symlink_metadata(&args.request)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 131072,
        "bounded ordinary journal request required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.request)?;
    let mut bytes = Vec::new();
    (&mut file).take(131073).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 131072
            && args.request_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "mount restoration request pin differs"
    );
    let request: general_reconstruct::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let expected = request
        .expected_mount_paths
        .as_ref()
        .filter(|paths| paths.len() == 1)
        .ok_or_else(|| anyhow::anyhow!("exactly one original drive-letter path required"))?;
    let wanted = &expected[0];
    ensure!(
        wanted.len() == 3
            && wanted.as_bytes()[0].is_ascii_alphabetic()
            && wanted.as_bytes()[1] == b':'
            && wanted.as_bytes()[2] == b'\\',
        "mounted-folder restoration is outside this first profile"
    );
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"general-refs-drive-letter-restore-intent",
            "request_sha256":args.request_sha256,"original_mount_path":wanted,
            "existing_mount_points_will_not_be_deleted":true}),
    )?;
    let mut events = Vec::new();
    let restored = restore_drive_letter_general(request.pair.source.clone(), wanted, &mut events)?;
    let before: BTreeSet<_> = expected.iter().map(|path| path.to_lowercase()).collect();
    let after: BTreeSet<_> = restored
        .after
        .paths
        .iter()
        .map(|path| path.to_lowercase())
        .collect();
    let success = before == after;
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-refs-drive-letter-restored",
            "success":success,"restoration":restored,"events":events,
            "mount_paths_preserved":success,"ntfs_rollback_closed":true,
            "production_conversion_qualified":false}),
    )?;
    ensure!(
        success,
        "drive letter restored but other mount paths still differ; report saved"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("drive-letter restoration requires Windows on the owning machine");
    std::process::exit(1);
}
