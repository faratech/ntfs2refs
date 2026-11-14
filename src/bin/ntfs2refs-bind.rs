//! Read-only discovery of the device identities for an owning-machine run.
#[cfg(any(windows, test))]
fn validate_source_geometry(
    geometry: &ntfs2refs::ntfs_inspect::NtfsGeometry,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        geometry.bytes_per_sector == 512
            && geometry.sectors_per_cluster == 8
            && geometry.cluster_size == 4096
            && geometry.file_record_size == 1024,
        "source geometry preflight refused: volume {} bytes has {}-byte sectors, {}-byte clusters and {}-byte MFT records; the current converter requires 512-byte sectors, 4096-byte clusters and 1024-byte MFT records; no output was created",
        geometry.volume_size,
        geometry.bytes_per_sector,
        geometry.cluster_size,
        geometry.file_record_size,
    );
    Ok(())
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        GeneralPartitionReader,
        discovery::{self, Role},
        general_layout::GeneralSourceShadowBinding,
        journal_file::{GeneralJournalStorageBinding, JournalProfile, MAX_JOURNAL_BYTES},
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
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
        /// Opt in to the experimental v2 journal profile (up to 16 GiB).
        #[arg(long)]
        experimental_large_journal: bool,
        /// Opt in to experimental tree/volume budgets; requires a v2 journal.
        #[arg(long, requires = "experimental_large_journal")]
        experimental_large_tree: bool,
        /// Stream payloads beyond the v1 4 GiB budget. Still requires exact
        /// shadow/journal capacity and the bounded ordinary-tree feature set.
        #[arg(long, requires = "experimental_large_tree")]
        experimental_streaming_payload: bool,
        /// Permit additional GPT partitions on journal storage, including the OS disk.
        #[arg(long)]
        journal_additional_partitions: bool,
        /// Informational enrollment label; defaults to a derived GPT label, not MSFT_Disk.UniqueId.
        #[arg(long)]
        journal_enrollment_label: Option<String>,
        #[arg(long)]
        verify_existing_shadow: bool,
        /// Bind an already prepared shadow through a read-only mount.
        #[arg(long, requires = "verify_existing_shadow")]
        read_only_shadow: bool,
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
    let resources = if args.experimental_streaming_payload {
        ntfs2refs::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2
    } else if args.experimental_large_tree {
        ntfs2refs::ntfs_admission::ResourceProfile::ExperimentalLargeTreeV1
    } else {
        ntfs2refs::ntfs_admission::ResourceProfile::AlphaV1
    };
    if args.experimental_large_tree {
        eprintln!(
            "Using experimental larger-source profile (partition routing budget {} bytes); native conversion and recovery have not been qualified for this profile.",
            resources
                .native_profile()
                .unwrap()
                .maximum_partition_bytes()
        );
    }
    let profile = if args.experimental_large_journal {
        eprintln!(
            "Using experimental v2 journal profile; native conversion and recovery at this capacity are not yet qualified."
        );
        JournalProfile::ExperimentalLargeV2
    } else {
        JournalProfile::LegacyV1
    };
    ensure!(
        args.experiment_id.len() == 32
            && args
                .experiment_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (1..=profile.max_journal_bytes()).contains(&args.max_journal_bytes),
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
    // This route binds a pair of dedicated disks and knows nothing of
    // volumes beside the source.
    ensure!(
        source.binding.layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::DedicatedData,
        "ntfs2refs-bind takes a source that has its disk to itself; `ntfs2refs --drive` converts a volume that shares its disk"
    );
    ensure!(
        !args.read_only_shadow || args.experimental_streaming_payload,
        "read-only shadow binding requires the explicit streaming profile"
    );
    let shadow = discovery::discover(
        &args.shadow,
        if args.read_only_shadow {
            Role::ShadowReadOnly
        } else {
            Role::Shadow
        },
    )?;
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
            && shadow.bytes_per_sector == 512
            && shadow
                .sectors_per_cluster
                .checked_mul(shadow.bytes_per_sector)
                == Some(4096),
        "source must be NTFS and the prepared shadow must be 512-byte/4-KiB ReFS with the expected label"
    );
    ensure!(
        matches!(journal.filesystem.as_str(), "NTFS" | "ReFS"),
        "journal requires local NTFS or ReFS storage"
    );
    // Inspect only the source boot sector through the existing read-only raw
    // boundary. Neither discovery nor this geometry check freezes the source.
    let mut source_events = Vec::new();
    let mut source_reader =
        GeneralPartitionReader::open(source.binding.clone(), &mut source_events)?;
    let source_before = source_reader.initial_probe().clone();
    let mut boot = [0; 512];
    source_reader.read_exact(&mut boot)?;
    let source_geometry =
        ntfs2refs::ntfs_inspect::inspect_boot_sector(&boot, source_reader.byte_len())?;
    if args.experimental_large_tree {
        ensure!(
            resources.supports_source_geometry(&source_geometry),
            "source geometry preflight refused: experimental conversion requires 512-byte sectors, power-of-two clusters from 4 KiB through 2 MiB, 1 KiB MFT records and 4 KiB index records; no output was created"
        );
    } else {
        validate_source_geometry(&source_geometry)?;
    }
    ensure!(
        u32::from(source_geometry.bytes_per_sector) == source.bytes_per_sector
            && source_geometry.sectors_per_cluster == source.sectors_per_cluster
            && source_geometry.serial_number as u32 == source.volume_serial_low32,
        "source boot geometry or serial differs from mounted discovery; no output was created"
    );
    let source_after = source_reader.revalidate_route(&mut source_events)?;
    let source_native_bytes_read = source_reader.native_bytes_read;
    drop(source_reader);
    let preflight_scope = "File features/contents, full live admission and source consistency remain unassessed. Live observations may change; this preflight does not authorize conversion or replace frozen admission.";
    println!(
        "Source geometry preflight: {}-byte sectors, {}-byte clusters, {}-byte MFT records.",
        source_geometry.bytes_per_sector,
        source_geometry.cluster_size,
        source_geometry.file_record_size,
    );
    println!("{preflight_scope}");
    let source_preflight = serde_json::json!({
        "kind":"read-only-source-geometry-preflight",
        "geometry":source_geometry,"before":source_before,"after":source_after,
        "boot_bytes_requested":512,"native_bytes_read":source_native_bytes_read,
        "events":source_events,"feature_contents_assessed":false,
        "full_live_admission_assessed":false,"source_consistency_assessed":false,
        "source_frozen":false,"source_admitted":false,"execution_authorized":false,
        "scope":preflight_scope
    });
    let derived_label = format!(
        "gpt-{}",
        journal.binding.identity.disk_guid.trim_matches(['{', '}'])
    );
    let label = args
        .journal_enrollment_label
        .as_deref()
        .unwrap_or(&derived_label);
    let request = ntfs2refs::general_conversion::Request {
        selected_capacity_policy: Default::default(),
        verification_policy: ntfs2refs::verification_policy::VerificationPolicy::FullContent,
        max_literal_backing_bytes: None,
        max_combined_scratch_bytes: None,
        schema_version: profile.version(),
        source_resource_profile: args.experimental_large_tree.then_some(resources),
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
            "source":source,"shadow":shadow,"journal":journal,"source_geometry_preflight":source_preflight,"space_observations":{"shadow":shadow_space_report,"journal":journal_space_report},"journal_enrollment_source":if args.journal_enrollment_label.is_some(){"caller-supplied informational label"}else{"derived GPT label; not MSFT_Disk.UniqueId"},
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

#[cfg(test)]
mod tests {
    use super::*;
    use ntfs2refs::ntfs_inspect::{NtfsGeometry, inspect_boot_sector};

    fn geometry() -> NtfsGeometry {
        NtfsGeometry {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_size: 4096,
            total_sectors: 4096,
            volume_size: 2 * 1024 * 1024,
            total_clusters: 512,
            mft_lcn: 4,
            mftmirr_lcn: 30,
            file_record_size: 1024,
            index_record_size: 4096,
            serial_number: 0x1122_3344_5566_7788,
        }
    }

    #[test]
    fn accepts_current_source_geometry() {
        validate_source_geometry(&geometry()).unwrap();
    }

    #[test]
    fn refuses_unsupported_source_geometry_without_device_access() {
        let baseline = geometry();
        for altered in [
            NtfsGeometry {
                bytes_per_sector: 4096,
                ..baseline.clone()
            },
            NtfsGeometry {
                sectors_per_cluster: 16,
                ..baseline.clone()
            },
            NtfsGeometry {
                cluster_size: 65536,
                ..baseline.clone()
            },
            NtfsGeometry {
                file_record_size: 4096,
                ..baseline.clone()
            },
            NtfsGeometry {
                file_record_size: 0,
                ..baseline
            },
        ] {
            let error = validate_source_geometry(&altered).unwrap_err();
            assert!(error.to_string().contains("no output was created"));
        }
    }

    #[test]
    fn checks_the_decoded_boot_record_size_instead_of_assuming_one_kib() {
        let mut boot = [0; 512];
        boot[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 8;
        boot[40..48].copy_from_slice(&4096u64.to_le_bytes());
        boot[48..56].copy_from_slice(&4u64.to_le_bytes());
        boot[56..64].copy_from_slice(&30u64.to_le_bytes());
        boot[64] = (-10i8) as u8;
        boot[68] = 1;
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        let accepted = inspect_boot_sector(&boot, 2 * 1024 * 1024).unwrap();
        validate_source_geometry(&accepted).unwrap();
        boot[64] = (-12i8) as u8;
        let refused = inspect_boot_sector(&boot, 2 * 1024 * 1024).unwrap();
        assert_eq!(refused.file_record_size, 4096);
        assert!(validate_source_geometry(&refused).is_err());
    }
}
