//! Construct a pinned general shadow request from the actual frozen NTFS
//! source and a separately bound Windows-created ReFS data disk.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{
        GeneralDiskState, MountPathObservation,
        general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    };
    use ntfs2refs::general_shadow;
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
        frozen_source: PathBuf,
        #[arg(long)]
        frozen_source_sha256: String,
        #[arg(long)]
        source_binding: PathBuf,
        #[arg(long)]
        source_binding_sha256: String,
        #[arg(long)]
        shadow_binding: PathBuf,
        #[arg(long)]
        shadow_binding_sha256: String,
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
        mount_paths: MountPathObservation,
    }
    fn pinned(path: &PathBuf, expected: &str, max: u64) -> anyhow::Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "general shadow input is not a bounded ordinary file"
        );
        let bytes = fs::read(path)?;
        ensure!(
            expected.len() == 64 && hex::encode(Sha256::digest(&bytes)) == expected,
            "general shadow source or binding pin differs"
        );
        Ok(bytes)
    }
    let args = Args::parse();
    ensure!(
        !args.output.exists(),
        "fresh general shadow request required"
    );
    let frozen: Frozen = serde_json::from_slice(&pinned(
        &args.frozen_source,
        &args.frozen_source_sha256,
        64 * 1024 * 1024,
    )?)?;
    let source: GeneralDiskBinding = serde_json::from_slice(&pinned(
        &args.source_binding,
        &args.source_binding_sha256,
        16384,
    )?)?;
    let shadow: GeneralDiskBinding = serde_json::from_slice(&pinned(
        &args.shadow_binding,
        &args.shadow_binding_sha256,
        16384,
    )?)?;
    ensure!(
        frozen.schema_version == 1
            && frozen.kind == "general-frozen-ntfs-source"
            && frozen.binding_sha256 == args.source_binding_sha256
            && frozen.before == frozen.after
            && frozen.after.disk_attributes == 3
            && frozen.mount_paths.binding == source
            && frozen.mount_paths.all_paths_resolve_to_bound_volume,
        "frozen NTFS source or mount-path evidence differs"
    );
    let request = general_shadow::Request {
        schema_version: 1,
        pair: GeneralSourceShadowBinding { source, shadow },
        source_sha256: frozen.source_sha256,
        expected_mount_paths: Some(frozen.mount_paths.paths),
    };
    request.validate()?;
    let bytes = serde_json::to_vec_pretty(&request)?;
    ensure!(bytes.len() <= 16384, "general shadow request exceeds bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&args.output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!(
        "General shadow request SHA-256 {}",
        hex::encode(Sha256::digest(&bytes))
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general shadow request assembly requires Windows");
    std::process::exit(1);
}
