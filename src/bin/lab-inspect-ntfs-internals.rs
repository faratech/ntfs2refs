//! Bounded raw internal-index observation on an already excluded data disk.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, general_layout::GeneralDiskBinding};
    use ntfs2refs::{ntfs_inspect, ntfs_internal};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        path::PathBuf,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        native: bool,
    }
    let args = Args::parse();
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16384,
        "bounded binding required"
    );
    let bytes = fs::read(&args.binding)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(binding, &mut events)?;
    let before = source.state(&mut events)?;
    let length = source.byte_len();
    let raw = ntfs_inspect::inspect(&mut source, length)?;
    let (mut proof, error) = match ntfs_internal::verify(&mut source, &raw) {
        Ok(proof) => (Some(proof), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let (native_observation, native_error) = if args.native {
        let pin = hex::encode(Sha256::digest(serde_json::to_vec(&raw)?));
        let request = ntfs2refs::ntfs_attestation::request_for_general_inspection(
            &raw,
            &pin,
            source.binding(),
        )?;
        match source.observe_ntfs_files(&request, &mut events) {
            Ok(observed) => {
                if let Some(proof) = &mut proof {
                    proof.bind_native_quota(&observed);
                }
                (Some(serde_json::to_value(observed)?), None)
            }
            Err(error) => (None, Some(error.to_string())),
        }
    } else {
        (None, None)
    };
    let after = source.state(&mut events)?;
    ensure!(
        before == after && before.disk_attributes == 3,
        "frozen source route changed"
    );
    let report = serde_json::json!({"schema_version":1, "kind":"frozen-ntfs-internal-index-observation",
        "binding_sha256":args.binding_sha256, "before":before, "after":after,
        "inspection_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&raw)?)),
        "internal_indexes":proof, "internal_indexes_error":error, "events":events,
        "native_observation":native_observation, "native_error":native_error,
        "source_admitted":false,"execution_authorized":false});
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)?;
    output.write_all(&serde_json::to_vec_pretty(&report)?)?;
    output.sync_all()?;
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows native source observation required");
    std::process::exit(2);
}
