//! Explicit experimental compact CLI. Source-certificate and recovery authority
//! remain in the existing owning-machine implementations, never in this parser.
#[cfg(windows)]
mod app {
    use anyhow::{Result, ensure};
    use clap::{Args, Parser, Subcommand};
    use ntfs2refs::{
        general_conversion::Request,
        general_qualification::CompactConstructionBudget,
        general_recovery::{
            ExperimentalCompactInputs, ExperimentalCompactOperation, recover_compact_experimental,
        },
        ntfs_admission::ResourceProfile,
    };
    use sha2::{Digest, Sha256};
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt, path::PathBuf};

    #[derive(Parser)]
    #[command(
        version,
        about = "Experimental compact NTFS-to-ReFS conversion and recovery.",
        long_about = "Experimental compact NTFS-to-ReFS conversion and recovery on the Windows machine owning the selected data devices. Convert uses experimental_streaming_tree_v2 and independently checked source, shadow and journal storage. Source semantics and resource/geometry checks remain bounded; this is not boot-volume or arbitrary-geometry qualification. Live source admission, native target preservation, journal identity and handoff barriers remain mandatory."
    )]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Print selected implementation limits without opening devices or creating artifacts.
        Profile,
        /// Construct a fresh native shadow and convert a newly admitted NTFS data volume.
        Convert(ConvertArgs),
        /// Finish an already activated compact apply; leave the exact target offline.
        Resume(RecoveryArgs),
        /// Restore the exact original NTFS preimage before handoff; complete ABT/native checks.
        Rollback(RecoveryArgs),
        /// Complete an exact unmarked ReFS image; persist HND before native mounting.
        Finalize(RecoveryArgs),
        /// Complete an existing HND only while exact offline-image/durability checks pass.
        FinalizeAfterMarker(RecoveryArgs),
        /// Complete an existing ABT only while exact original-image/durability checks pass.
        FinalizeRollback(RecoveryArgs),
    }

    #[derive(Args)]
    struct ExperimentalAcknowledgement {
        /// Accept selected experimental data-device scope; grants no admission or replay authority.
        #[arg(long, required = true)]
        acknowledge_experimental_compact: bool,
    }

    #[derive(Args)]
    struct ConvertArgs {
        #[command(flatten)]
        experimental: ExperimentalAcknowledgement,
        /// Fresh device-bound conversion request from ntfs2refs-bind, not a reconstruction request.
        #[arg(long)]
        request: PathBuf,
        #[arg(long, value_parser = canonical_pin)]
        request_sha256: String,
        /// Fresh ordinary artifact directory on the Windows OS volume.
        #[arg(long)]
        output: PathBuf,
        /// Explicit maximum charged shadow-placement bytes; checked against actual partition size.
        #[arg(long)]
        maximum_placement_bytes: u64,
        /// Maximum native placement submissions; the mover's shared ceiling is enforced.
        #[arg(long, default_value_t = n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS)]
        maximum_placement_submissions: usize,
        /// Maximum system/residual payload bytes; the constructor enforces its existing bound.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        maximum_exception_bytes: u64,
    }

    #[derive(Args)]
    struct RecoveryArgs {
        #[command(flatten)]
        experimental: ExperimentalAcknowledgement,
        /// Generated reconstruction request from the original compact run.
        #[arg(long)]
        request: PathBuf,
        #[arg(long, value_parser = canonical_pin)]
        request_sha256: String,
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long, value_parser = canonical_pin)]
        ticket_sha256: String,
        /// Original independent journal; actual file identity and complete bytes are rechecked.
        #[arg(long)]
        journal: PathBuf,
        /// Original qualification/composite-capture.json; this is not a source certificate.
        #[arg(long)]
        capture: PathBuf,
        #[arg(long, value_parser = canonical_pin)]
        capture_sha256: String,
        /// Original qualification/changed-clusters.bin backing.
        #[arg(long)]
        packed: PathBuf,
        #[arg(long, value_parser = canonical_pin)]
        packed_sha256: String,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long, value_parser = canonical_pin)]
        expectation_sha256: String,
        /// Optional existing staging VHDX to reattach read-only after restart.
        #[arg(long, requires = "managed_shadow_id")]
        managed_shadow: Option<PathBuf>,
        /// Pinned provider VirtualDiskId from the original managed-shadow receipt.
        #[arg(long, requires = "managed_shadow")]
        managed_shadow_id: Option<String>,
        /// Fresh ordinary recovery-artifact directory on the Windows OS volume.
        #[arg(long)]
        output: PathBuf,
    }

    fn canonical_pin(value: &str) -> std::result::Result<String, String> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(value.into())
        } else {
            Err("expected exactly 64 lowercase hexadecimal SHA-256 characters".into())
        }
    }

    fn profile() -> Result<()> {
        let selected = ResourceProfile::ExperimentalStreamingTreeV2;
        let limits = selected.limits();
        let native = n2r_win32::attestation::ResourceProfile::ExperimentalStreamingTreeV2;
        let native_limits = native.limits();
        let journal = n2r_win32::journal_file::JournalProfile::ExperimentalLargeV2;
        let source_clusters: Vec<_> = (12..=21)
            .map(|shift| 1u32 << shift)
            .filter(|size| ntfs2refs::ntfs_index::supports_cluster_size(*size))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version":1,"kind":"experimental-compact-cli-profile",
                "source_resource_profile":selected,"source_tree_profile":selected.ordinary_shadow_profile(),
                "conversion_scope":"selected independent dedicated data devices; actual enrollment, original live source certificate and native target proof required",
                "recovery_scope":"previously activated compact run only; pinned request/ticket/capture/packed backing/expectation and actual journal/device state required",
                "machine_owning_conversion":true,"hypervisor_dependency":false,
                "boot_volume_support":false,"arbitrary_geometry_qualified":false,"production_qualified":false,
                "this_cli_has_native_qualification":false,"limits_are_implementation_bounds_not_filesystem_or_provider_limits":true,
                "maximum_files":limits.maximum_files,"maximum_directories_including_root":limits.maximum_directories,
                "maximum_logical_bytes":limits.maximum_logical_bytes,"maximum_stream_bytes":limits.maximum_stream_bytes,
                "maximum_partition_bytes":native.maximum_partition_bytes(),"maximum_native_identities":native_limits.maximum_identities,
                "native_logical_read_budget_bytes":native_limits.logical_read_bytes,
                "source_logical_sector_bytes":512,"source_mft_record_bytes":1024,"source_index_record_bytes":4096,
                "source_cluster_bytes":source_clusters,"target_profile":"native ReFS3.14 with4KiB allocation units",
                "path_policy":"streaming Unicode components: at most255 UTF-16 units and16 components; names remain unchanged; conservative duplicate checks and native creation remain required",
                "maximum_placement_submissions":n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS,
                "placement_bytes":"explicit caller budget; validated by the existing constructor before output/source freeze/allocation",
                "exception_bytes":"existing CompactConstructionBudget bound; system streams and residual bytes only",
                "maximum_journal_bytes":journal.max_journal_bytes(),"maximum_changed_bytes_for_journal_profile":journal.max_changed_bytes(),
                "complete_native_evidence_still_required":true,"serialized_reports_recreate_source_certificate":false
            }))?
        );
        Ok(())
    }

    fn convert(args: ConvertArgs) -> Result<()> {
        ensure!(
            args.experimental.acknowledge_experimental_compact,
            "explicit experimental compact data-device acknowledgment required"
        );
        // Preserve the existing held-request/hash/identity contract. The exact
        // handle stays alive across the complete owning conversion call.
        let mut input = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&args.request)?;
        let snapshot = n2r_win32::reference_file::observe_reference_file_handle(&input)?;
        ensure!(
            snapshot.file_bytes <= 131072 && snapshot.number_of_links == 1,
            "bounded ordinary conversion request required"
        );
        let mut bytes = Vec::new();
        (&mut input).take(131073).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == snapshot.file_bytes
                && hex::encode(Sha256::digest(&bytes)) == args.request_sha256
                && n2r_win32::reference_file::observe_reference_file_handle(&input)? == snapshot,
            "conversion request pin or held identity differs"
        );
        let request: Request = serde_json::from_slice(&bytes)?;
        ensure!(
            request.source_resource_profile == Some(ResourceProfile::ExperimentalStreamingTreeV2)
                && !request.verify_existing_shadow,
            "compact CLI requires fresh experimental_streaming_tree_v2 construction"
        );
        let result = ntfs2refs::general_conversion::convert_compact_experimental(
            &request,
            CompactConstructionBudget {
                maximum_placement_bytes: args.maximum_placement_bytes,
                maximum_placement_submissions: args.maximum_placement_submissions,
                maximum_exception_bytes: args.maximum_exception_bytes,
            },
            &args.output,
        );
        drop(input);
        result
    }

    fn recover(operation: ExperimentalCompactOperation, args: RecoveryArgs) -> Result<()> {
        ensure!(
            args.experimental.acknowledge_experimental_compact,
            "explicit experimental compact data-device acknowledgment required"
        );
        let managed = match (&args.managed_shadow, &args.managed_shadow_id) {
            (Some(path), Some(provider_id)) => {
                // Read the ORIGINAL pinned reconstruction request under a
                // retained no-writer/delete handle before using its shadow
                // binding. Native reattachment refuses route/identity drift.
                let mut input = OpenOptions::new()
                    .read(true)
                    .share_mode(1)
                    .custom_flags(0x0020_0000)
                    .open(&args.request)?;
                let snapshot = n2r_win32::reference_file::observe_reference_file_handle(&input)?;
                ensure!(
                    snapshot.file_bytes <= 131072 && snapshot.number_of_links == 1,
                    "bounded ordinary original reconstruction request required"
                );
                let mut bytes = Vec::new();
                (&mut input).take(131073).read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() as u64 == snapshot.file_bytes
                        && hex::encode(Sha256::digest(&bytes)) == args.request_sha256
                        && n2r_win32::reference_file::observe_reference_file_handle(&input)?
                            == snapshot,
                    "original recovery request pin or held identity differs"
                );
                let request: ntfs2refs::general_reconstruct::Request =
                    serde_json::from_slice(&bytes)?;
                request.validate()?;
                let owner = n2r_win32::managed_shadow::reattach_existing(
                    path,
                    provider_id,
                    &request.pair.shadow,
                )?;
                Some((owner, input))
            }
            (None, None) => None,
            _ => anyhow::bail!("--managed-shadow and --managed-shadow-id are required together"),
        };
        // Typed recovery still holds/verifies all original inputs and native
        // state itself. No entry here can activate or start a fresh Apply.
        let result = recover_compact_experimental(
            operation,
            &ExperimentalCompactInputs {
                request: args.request,
                request_sha256: args.request_sha256,
                ticket: args.ticket,
                ticket_sha256: args.ticket_sha256,
                journal: args.journal,
                capture: args.capture,
                capture_sha256: args.capture_sha256,
                packed: args.packed,
                packed_sha256: args.packed_sha256,
                expectation: args.expectation,
                expectation_sha256: args.expectation_sha256,
            },
            &args.output,
        );
        // Retain the attachment and original request guard until the typed
        // recovery/finalization call has returned, including its error path.
        drop(managed);
        result
    }

    pub(super) fn run() -> Result<()> {
        match Cli::parse().command {
            Command::Profile => profile(),
            Command::Convert(args) => convert(args),
            Command::Resume(args) => recover(ExperimentalCompactOperation::Resume, args),
            Command::Rollback(args) => recover(ExperimentalCompactOperation::Rollback, args),
            Command::Finalize(args) => recover(ExperimentalCompactOperation::Finalize, args),
            Command::FinalizeAfterMarker(args) => {
                recover(ExperimentalCompactOperation::FinalizeAfterMarker, args)
            }
            Command::FinalizeRollback(args) => {
                recover(ExperimentalCompactOperation::FinalizeRollback, args)
            }
        }
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    app::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "Experimental compact conversion/recovery requires the Windows machine owning the data volumes."
    );
    std::process::exit(2);
}
