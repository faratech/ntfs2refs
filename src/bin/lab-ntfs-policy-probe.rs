//! Narrow locked raw-NTFS observation for the disposable volume-policy
//! differential. It changes no policy, payload or persistent disk attributes.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{GeneralLockedPartition, general_layout::GeneralDiskBinding};
    use ntfs2refs::{ntfs_backup, ntfs_inspect};
    use serde::Serialize;
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
        output: PathBuf,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "policy report exceeds bound"
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
        "fresh policy report and intent required"
    );
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 16384,
        "ordinary bounded binding required"
    );
    let bytes = fs::read(&args.binding)?;
    ensure!(
        args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "policy binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    binding.validate()?;
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11")
            && binding.disk_number == 1,
        "disposable NTFS policy guest required"
    );
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"locked-ntfs-policy-intent","binding_sha256":args.binding_sha256,"binding":binding,"payload_writes":0,"policy_changes":0}),
    )?;
    let mut events = Vec::new();
    let observation = (|| -> Result<_> {
        let mut locked = GeneralLockedPartition::open(binding.clone(), &mut events)?;
        let length = locked.byte_len();
        let ntfs = ntfs_inspect::inspect_with_limits(
            &mut locked,
            length,
            ntfs_inspect::InspectionLimits {
                max_stream_hash_bytes: 128 * 1024 * 1024,
                ..Default::default()
            },
        )?;
        let record = ntfs
            .files
            .iter()
            .find(|file| file.record_number == 3)
            .ok_or_else(|| anyhow::anyhow!("volume record absent"))?;
        let values: Vec<_> = record
            .attributes
            .iter()
            .filter(|attribute| attribute.type_code == 0x70 && attribute.name_utf16.is_empty())
            .collect();
        ensure!(
            values.len() == 1 && values[0].resident && values[0].logical_size == 12,
            "volume information form differs"
        );
        let value = hex::decode(
            values[0]
                .resident_metadata_hex
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("volume bytes absent"))?,
        )?;
        ensure!(
            value.len() == 12
                && ntfs.volume_flags == Some(u16::from_le_bytes(value[10..12].try_into()?)),
            "volume flag interpretations differ"
        );
        let (backups, backup_error) = match ntfs_backup::verify(&mut locked, length, &ntfs) {
            Ok(proof) => (Some(proof), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
        let read_bytes = locked.native_bytes_read();
        let route_after_unlock = locked.finish(&mut events)?;
        Ok(
            serde_json::json!({"volume_flags":ntfs.volume_flags,"volume_version":ntfs.volume_version,"dirty":ntfs.dirty,"volume_information_hex":hex::encode(value),"record_sequence":record.sequence_number,"native_bytes_read":read_bytes,"route_after_unlock":route_after_unlock,"backups":backups,"backup_error":backup_error,"ntfs":ntfs,"unlock_verified":true}),
        )
    })();
    let success = observation.is_ok();
    let error = observation.as_ref().err().map(|error| format!("{error:#}"));
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"locked-ntfs-policy-observation","binding_sha256":args.binding_sha256,"success":success,"observation":observation.ok(),"error":error,"events":events,"payload_writes":0,"policy_changes":0,"source_admitted":false,"conversion_qualified":false}),
    )?;
    ensure!(
        success,
        "locked NTFS policy observation failed; report saved"
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("locked NTFS policy observation requires Windows");
    std::process::exit(1);
}
