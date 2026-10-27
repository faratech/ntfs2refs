//! Read-only discovery of the device identities for an owning-machine run.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        discovery::{self, Role},
        general_layout::GeneralSourceShadowBinding,
        journal_file::{GeneralJournalStorageBinding, MAX_JOURNAL_BYTES},
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::OpenOptions,
        io::Write,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    #[derive(Parser)]
    #[command(about = "Discover GPT volume bindings without changing volume or disk state")]
    struct Args {
        #[arg(long)]
        source: String,
        #[arg(long)]
        shadow: String,
        #[arg(long)]
        journal: String,
        #[arg(long)]
        experiment_id: String,
        #[arg(long,default_value_t=MAX_JOURNAL_BYTES)]
        max_journal_bytes: u64,
        /// Permit additional GPT partitions on journal storage, including the OS disk.
        #[arg(long)]
        journal_additional_partitions: bool,
        /// Informational enrollment label; defaults to a derived GPT label, not MSFT_Disk.UniqueId.
        #[arg(long)]
        journal_enrollment_label: Option<String>,
        #[arg(long)]
        verify_existing_shadow: bool,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        evidence: Option<PathBuf>,
    }
    fn save(path: &Path, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "binding output exceeds bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        ensure!(
            file.metadata()?.file_attributes() & 0x400 == 0,
            "ordinary output required"
        );
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    fn ordinary_output(path: &Path) -> Result<()> {
        let text = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Unicode output path required"))?;
        let system_root = std::env::var("SystemRoot")?;
        ensure!(
            text.get(..3).is_some_and(|prefix| system_root
                .get(..3)
                .is_some_and(|root| prefix.eq_ignore_ascii_case(root)))
                && !text[3..].contains(':')
                && !text.contains(['/', '\0'])
                && !text.contains("..")
                && !path.exists(),
            "fresh output on the Windows OS volume required"
        );
        for ancestor in path.ancestors().skip(1) {
            let meta = std::fs::symlink_metadata(ancestor)?;
            ensure!(
                meta.is_dir() && meta.file_attributes() & 0x400 == 0,
                "ordinary output ancestry required"
            );
        }
        Ok(())
    }
    let args = Args::parse();
    ensure!(
        args.experiment_id.len() == 32
            && args
                .experiment_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (1..=MAX_JOURNAL_BYTES).contains(&args.max_journal_bytes),
        "fresh lowercase experiment identifier and bounded journal budget required"
    );
    ordinary_output(&args.output)?;
    if let Some(path) = &args.evidence {
        ordinary_output(path)?;
        ensure!(
            !path
                .to_string_lossy()
                .eq_ignore_ascii_case(&args.output.to_string_lossy()),
            "distinct output files required"
        );
    }
    let source = discovery::discover(&args.source, Role::Source)?;
    let shadow = discovery::discover(&args.shadow, Role::Shadow)?;
    let journal = discovery::discover(
        &args.journal,
        Role::Journal {
            allow_additional_partitions: args.journal_additional_partitions,
        },
    )?;
    ensure!(
        source.filesystem == "NTFS"
            && shadow.filesystem == "ReFS"
            && shadow.label == "n2r-retained-shadow"
            && source.bytes_per_sector == 512
            && source
                .sectors_per_cluster
                .checked_mul(source.bytes_per_sector)
                == Some(4096)
            && shadow.bytes_per_sector == 512
            && shadow
                .sectors_per_cluster
                .checked_mul(shadow.bytes_per_sector)
                == Some(4096),
        "source NTFS/shadow ReFS label or 512-byte/4-KiB filesystem profile differs"
    );
    ensure!(
        matches!(journal.filesystem.as_str(), "NTFS" | "ReFS"),
        "journal requires local NTFS or ReFS storage"
    );
    let derived_label = format!(
        "gpt-{}",
        journal.binding.identity.disk_guid.trim_matches(['{', '}'])
    );
    let label = args
        .journal_enrollment_label
        .as_deref()
        .unwrap_or(&derived_label);
    let request = ntfs2refs::general_conversion::Request {
        schema_version: 1,
        experiment_id: args.experiment_id,
        pair: GeneralSourceShadowBinding {
            source: source.binding.clone(),
            shadow: shadow.binding.clone(),
        },
        journal: GeneralJournalStorageBinding {
            disk: journal.binding.clone(),
            externally_enrolled_disk_unique_id: label.into(),
            allow_additional_partitions: args.journal_additional_partitions,
        },
        max_journal_bytes: args.max_journal_bytes,
        verify_existing_shadow: args.verify_existing_shadow,
    };
    request.validate()?;
    let bytes = serde_json::to_vec_pretty(&request)?;
    ensure!(
        bytes.len() <= 16384,
        "generated request exceeds conversion-input bound"
    );
    // Capacity is transient and the final journal length is determined later
    // from the actual frozen comparison. Never treat this as a reservation or a
    // reason to skip the existing live checks.
    let shadow_space = discovery::observe_volume_space(&shadow.volume_guid_path);
    let journal_space = discovery::observe_volume_space(&journal.volume_guid_path);
    let space_report =
        |name: &str, result: &std::io::Result<discovery::VolumeSpaceObservation>| match result {
            Ok(space) => {
                println!(
                    "{name} available bytes: {}",
                    space.available_bytes_to_caller
                );
                serde_json::json!({"observation":space,"error":null})
            }
            Err(error) => {
                eprintln!("{name} available space could not be queried: {error}");
                serde_json::json!({"observation":null,"error":error.to_string()})
            }
        };
    let shadow_space_report = space_report("Shadow", &shadow_space);
    let journal_space_report = space_report("Journal", &journal_space);
    if journal_space
        .as_ref()
        .is_ok_and(|space| space.available_bytes_to_caller < request.max_journal_bytes)
    {
        eprintln!(
            "Journal free space is below the configured maximum journal size; the actual journal size is determined during conversion."
        );
    }
    println!("Space is a point-in-time observation, not a reservation or a conversion estimate.");
    if let Some(path) = args.evidence {
        save(
            &path,
            &serde_json::to_vec_pretty(
                &serde_json::json!({"schema_version":1,"kind":"read-only-conversion-binding-discovery",
            "source":source,"shadow":shadow,"journal":journal,"space_observations":{"shadow":shadow_space_report,"journal":journal_space_report},"journal_enrollment_source":if args.journal_enrollment_label.is_some(){"caller-supplied informational label"}else{"derived GPT label; not MSFT_Disk.UniqueId"},
            "request_sha256":hex::encode(Sha256::digest(&bytes)),"source_write_requests":0,"source_admitted":false,"execution_authorized":false}),
            )?,
        )?;
    }
    save(&args.output, &bytes)?;
    println!("Request SHA-256 {}", hex::encode(Sha256::digest(&bytes)));
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Native binding discovery requires Windows");
    std::process::exit(2);
}
