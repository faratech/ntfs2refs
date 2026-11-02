//! Explicit native marker integration experiment, never a production CLI mode.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::{Parser, Subcommand};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::Read,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        acknowledge_enrolled_disposable_devices: bool,
        #[arg(long)]
        acknowledge_unqualified_native_markers: bool,
        #[command(subcommand)]
        operation: Operation,
    }
    #[derive(Subcommand)]
    enum Operation {
        Fresh {
            #[arg(long)]
            request: PathBuf,
            #[arg(long)]
            request_sha256: String,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            maximum_placement_bytes: u64,
            #[arg(long, default_value_t = n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS)]
            maximum_placement_submissions: usize,
            #[arg(long, default_value_t = 16777216)]
            maximum_exception_bytes: u64,
            /// Exit86 after the first actual flushed selected payload write.
            #[arg(long)]
            first_write_fault: bool,
        },
        Recover {
            #[arg(long)]
            bundle: PathBuf,
            #[arg(long)]
            bundle_sha256: String,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            rollback: bool,
        },
        /// Metadata-only constructor diagnostic. Creates one empty journal
        /// and a JSON report on enrolled C0; this does mutate file metadata.
        Probe {
            #[arg(long)]
            request: PathBuf,
            #[arg(long)]
            request_sha256: String,
            #[arg(long)]
            journal: PathBuf,
            #[arg(long)]
            output: PathBuf,
        },
    }

    fn open_request(
        path: &Path,
        sha256: &str,
    ) -> anyhow::Result<(File, ntfs2refs::general_conversion::Request)> {
        let mut input = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let snapshot = n2r_win32::reference_file::observe_reference_file_handle(&input)?;
        ensure!(
            snapshot.file_bytes <= 131072 && snapshot.number_of_links == 1,
            "bounded ordinary conversion request required"
        );
        let mut bytes = Vec::new();
        (&mut input).take(131073).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == snapshot.file_bytes
                && hex::encode(Sha256::digest(&bytes)) == sha256
                && n2r_win32::reference_file::observe_reference_file_handle(&input)? == snapshot,
            "conversion request pin or identity differs"
        );
        Ok((input, serde_json::from_slice(&bytes)?))
    }

    fn probe_path(path: &Path) -> anyhow::Result<(&str, &str)> {
        let text = path.to_str().context("probe path must be Unicode")?;
        let suffix = text
            .strip_prefix("C:\\ntfs2refs\\native-marker-backend-probe-")
            .context("probe files must be under the enrolled C0 probe stage")?;
        let (run, leaf) = suffix
            .split_once('\\')
            .context("probe stage and direct filename required")?;
        ensure!(
            run.len() == 32
                && run
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && !leaf.is_empty()
                && leaf.len() <= 64
                && !leaf.starts_with('.')
                && !leaf.ends_with('.')
                && leaf
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
            "bounded lowercase-hex stage and ordinary direct filename required"
        );
        ensure!(
            path.is_absolute() && text.len() <= 192,
            "bounded absolute probe path required"
        );
        let mut parent = path.parent();
        while let Some(directory) = parent {
            let metadata = std::fs::symlink_metadata(directory)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "probe ancestry must contain existing ordinary directories only"
            );
            parent = directory.parent();
        }
        Ok((run, leaf))
    }

    fn probe(
        request_path: &Path,
        request_sha256: &str,
        journal_path: &Path,
        output: &Path,
    ) -> anyhow::Result<()> {
        use n2r_win32::journal_file::{JournalProfile, UnbufferedJournalFile};
        ensure!(
            std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
            "native constructor probe requires the enrolled disposable owning guest"
        );
        let (run, journal_leaf) = probe_path(journal_path)?;
        let (output_run, output_leaf) = probe_path(output)?;
        let (request_run, request_leaf) = probe_path(request_path)?;
        ensure!(
            run == output_run
                && run == request_run
                && journal_leaf.eq_ignore_ascii_case("selected.journal")
                && output_leaf.eq_ignore_ascii_case("probe.json")
                && request_leaf.eq_ignore_ascii_case("request.json"),
            "one fresh probe stage with selected.journal, probe.json and held request.json required"
        );
        let (_held_request, request) = open_request(request_path, request_sha256)?;
        request.journal.validate()?;
        let profile = request.journal_profile()?;
        ensure!(
            matches!(profile, JournalProfile::CapacityPinnedV3 { max_journal_bytes } if max_journal_bytes == 8 * 1024 * 1024 * 1024),
            "probe requires the existing explicit 8 GiB CapacityPinnedV3 request"
        );
        let binding = &request.journal;
        let disk = &binding.disk;
        let identity = &disk.identity;
        ensure!(
            disk.disk_number == 0
                && disk
                    .volume_guid
                    .eq_ignore_ascii_case("c6c3318f-a7c8-47b9-be6d-6dde5e00862f")
                && identity
                    .disk_guid
                    .eq_ignore_ascii_case("1f804918-e98f-4a71-9022-fc00c3cb7c26")
                && identity
                    .partition_guid
                    .eq_ignore_ascii_case("c6c3318f-a7c8-47b9-be6d-6dde5e00862f")
                && identity.partition_number == 3
                && identity.disk_bytes == 68719476736
                && identity.partition_offset == 331350016
                && identity.partition_bytes == 66238545920
                && identity.logical_sector_bytes == 512
                && identity.physical_sector_bytes == 4096
                && binding.allow_additional_partitions
                && binding.externally_enrolled_disk_unique_id
                    == "gpt-1f804918-e98f-4a71-9022-fc00c3cb7c26",
            "probe is restricted to the exact enrolled C0 journal binding"
        );
        // create_new remains the authoritative no-replacement operation. The
        // preliminary check also refuses dangling links and existing aliases.
        ensure!(
            matches!(std::fs::symlink_metadata(journal_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "probe journal must be a brand-new path; nothing is replaced or removed"
        );
        let mut report = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(output)?;
        let report_identity = n2r_win32::reference_file::observe_reference_file_handle(&report)?;
        ensure!(
            report_identity.file_bytes == 0
                && report_identity.number_of_links == 1
                && report_identity.final_path
                    == format!(
                        "\\\\?\\Volume{{c6c3318f-a7c8-47b9-be6d-6dde5e00862f}}\\ntfs2refs\\native-marker-backend-probe-{run}\\{output_leaf}"
                    ),
            "new report must be the exact ordinary file on enrolled C0"
        );
        // No source/shadow constructor, payload Read/Write, sealing, cluster
        // protection or privilege acquisition is called on this branch.
        let attempted = (|| -> anyhow::Result<_> {
            let journal = UnbufferedJournalFile::create_new(journal_path, binding, profile)?;
            let length = journal.byte_len()?;
            let identity = journal.identity().clone();
            let ordinary_storage = journal.ordinary_storage_observation().clone();
            ensure!(
                length == 0,
                "new constructor probe journal must remain empty"
            );
            drop(journal);
            Ok((length, identity, ordinary_storage))
        })();
        let chain = attempted.as_ref().err().map(|error| {
            error
                .chain()
                .map(|cause| {
                    let native = cause.downcast_ref::<std::io::Error>();
                    serde_json::json!({
                        "message":cause.to_string(),
                        "io_error_kind":native.map(|error| format!("{:?}", error.kind())),
                        "raw_os_error":native.and_then(std::io::Error::raw_os_error),
                    })
                })
                .collect::<Vec<_>>()
        });
        let value = serde_json::json!({
            "schema_version":1,"kind":"lab-native-marker-backend-constructor-probe",
            "success":attempted.is_ok(),"request_sha256":request_sha256,
            "journal_path":journal_path,"journal_binding":binding,
            "journal_profile":"CapacityPinnedV3","maximum_journal_bytes":profile.max_journal_bytes(),
            "journal_length":attempted.as_ref().ok().map(|(length,_,_)| *length),
            "journal_identity":attempted.as_ref().ok().map(|(_,identity,_)| identity),
            "ordinary_storage":attempted.as_ref().ok().map(|(_,_,ordinary)| ordinary),
            "error_chain":chain,"native_marker_qualified":false,
            "scope":"metadata-only empty-file constructor diagnostic; creates journal and JSON report metadata",
            "no_source_io":true,"source_opened":false,"shadow_opened":false,
            "no_journal_file_payload_io":true,"journal_payload_bytes_read":0,"journal_payload_bytes_written":0,
            "sealing_requested":false,"marker_creation_requested":false,
            "cluster_protection_requested":false,"privilege_acquisition_requested":false,
            "globally_read_only":false,"empty_file_creation_is_metadata_mutation":true,
            "existing_file_replacement":false,"automatic_retry":false,
        });
        serde_json::to_writer_pretty(&mut report, &value)?;
        report.sync_all()?;
        drop(report);
        attempted.map(|_| ())
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_enrolled_disposable_devices && args.acknowledge_unqualified_native_markers,
        "explicit enrolled-device and unqualified-native-marker acknowledgments required"
    );
    match args.operation {
        Operation::Fresh {
            request,
            request_sha256,
            output,
            maximum_placement_bytes,
            maximum_placement_submissions,
            maximum_exception_bytes,
            first_write_fault,
        } => {
            let (_held_request, request) = open_request(&request, &request_sha256)?;
            let budget = ntfs2refs::general_qualification::CompactConstructionBudget {
                maximum_placement_bytes,
                maximum_placement_submissions,
                maximum_exception_bytes,
            };
            ntfs2refs::general_lab::convert_fresh_allocation_redundant_markers(
                &request,
                budget,
                &output,
                first_write_fault,
            )
        }
        Operation::Recover {
            bundle,
            bundle_sha256,
            output,
            rollback,
        } => {
            ntfs2refs::general_lab::recover_allocation_redundant_markers(
                &bundle,
                &bundle_sha256,
                rollback,
                &output,
            )?;
            Ok(())
        }
        Operation::Probe {
            request,
            request_sha256,
            journal,
            output,
        } => probe(&request, &request_sha256, &journal, &output),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows enrolled owning-guest marker experiment required");
    std::process::exit(2);
}
