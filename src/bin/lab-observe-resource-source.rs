//! Owning-machine integration entry for resource-selected source paging.
//! Freezes one explicitly bound dedicated NTFS data disk and performs no
//! conversion or source payload writes. It leaves persistent exclusion intact.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{
        GeneralFrozenPartition, attestation::NativeObservationDomain,
        general_layout::GeneralDiskBinding, resource_native::observe_available_resources,
        tree_resources::ResourceBudget,
    };
    use ntfs2refs::{
        ntfs_attestation::paged::{PagedObservationRequest, compare_domain},
        ntfs_inspect::{
            self, RootFileDomain, SourceMetadataBudget, paged_storage::SourceScratch,
            record_store::SortedRecordWriter,
        },
        verification_policy::VerificationPolicy,
    };
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
        /// Required: freezes the bound dedicated data disk and leaves it offline/read-only.
        #[arg(long)]
        acknowledge_resource_source_freeze: bool,
        /// Collect actual native rows through a physically read-only mount lease.
        #[arg(long)]
        native: bool,
        #[arg(long)]
        verify_full_content: bool,
        /// Optional resource share, cross-checked against actual available RAM.
        #[arg(long)]
        ram_bytes: Option<u64>,
        /// Optional metadata scratch share, cross-checked against actual free space.
        #[arg(long)]
        scratch_bytes: Option<u64>,
    }
    fn save(path: &std::path::Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_resource_source_freeze,
        "explicit source-freeze acknowledgment required"
    );
    ensure!(
        !args.output.exists(),
        "fresh resource observation output required"
    );
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16384,
        "bounded ordinary binding required"
    );
    let bytes = fs::read(&args.binding)?;
    ensure!(
        args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    binding.validate()?;
    let parent = args
        .output
        .parent()
        .context("resource output parent absent")?;
    let available = observe_available_resources(parent)?;
    let ram = args
        .ram_bytes
        .unwrap_or(available.available_physical_bytes / 2);
    let budget = ResourceBudget {
        schema_version: 1,
        ram_bytes: ram,
        scratch_bytes: args
            .scratch_bytes
            .unwrap_or(available.scratch_available_bytes / 8),
        page_bytes: u32::try_from((ram / 64).min(4 * 1024 * 1024).max(256))?,
        max_row_bytes: ram / 64,
        retained_index_bytes: ram / 4,
        handle_slots: ram / 1024,
    };
    available.validate_budget(budget)?;
    let policy = if args.verify_full_content {
        VerificationPolicy::FullContent
    } else {
        VerificationPolicy::ExtentIdentityV1
    };
    fs::create_dir(&args.output)?;
    save(
        &args.output.join("intent.json"),
        &serde_json::json!({
            "schema_version":1,"kind":"resource-source-observation-intent",
            "binding":binding,"binding_sha256":args.binding_sha256,
            "observed_available_resources":available,"resource_budget":budget,
            "verification_policy":policy,"source_payload_writes_authorized":false,
            "conversion_authorized":false
        }),
    )?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::isolate_observed_ntfs_with_resource_budget(
        binding.clone(),
        budget,
        &mut events,
    )?;
    let before = source.state(&mut events)?;
    ensure!(
        before.disk_attributes == 3,
        "source exclusion is incomplete"
    );
    let length = source.byte_len();
    let raw = ntfs_inspect::inspect_paged_with_policy(
        &mut source,
        length,
        budget,
        policy,
        &args.output.join("source"),
    )?;
    let pin = raw.canonical_sha256()?;
    save(&args.output.join("source-manifest.json"), raw.pin())?;
    let comparison = if args.native {
        let selectors = PagedObservationRequest::new(&raw, &binding, budget, policy)?;
        let admission = selectors.admission();
        let native = source.observe_ntfs_files_paged_domain(
            &selectors,
            &args.output.join("native.pages"),
            admission.native_observation_budget()?,
            policy.is_fast(),
            true,
            &mut events,
        )?;
        save(
            &args.output.join("native-header.json"),
            native.domain().header(),
        )?;
        let comparison_scratch =
            SourceScratch::new(SourceMetadataBudget::from_resource_budget(budget)?)?;
        let mut rows = SortedRecordWriter::new(
            &args.output.join("comparison"),
            *b"N2RCMP01",
            &comparison_scratch,
        )?;
        let mut ordinal = 0u64;
        let summary = compare_domain(&raw, &binding, budget, policy, native.domain(), |row| {
            let mut key = [0; 16];
            key[..8].copy_from_slice(&ordinal.to_be_bytes());
            rows.push(key, &row)?;
            ordinal = ordinal
                .checked_add(1)
                .context("comparison row ordinal overflow")?;
            Ok(())
        })?;
        let rows = rows.finish()?;
        ensure!(ordinal == raw.file_count(), "comparison coverage differs");
        save(
            &args.output.join("comparison-manifest.json"),
            &serde_json::json!({
                "summary":summary,"rows":rows,"native_sha256":native.domain().sha256(),
                "native_bytes":native.domain().byte_len(),"native_pages":native.domain().page_count(),
                "txf_error":native.txf_error(),"vss_observation":native.vss_observation(),
                "source_admitted":false,"execution_authorized":false
            }),
        )?;
        Some(summary)
    } else {
        None
    };
    raw.revalidate()?;
    let after = source.state(&mut events)?;
    ensure!(
        before == after && pin == raw.canonical_sha256()?,
        "frozen source route or page evidence changed"
    );
    save(
        &args.output.join("result.json"),
        &serde_json::json!({
            "schema_version":1,"kind":"resource-paged-source-observation",
            "source_pin":pin,"resource_budget":budget,"before":before,"after":after,
            "objects":raw.file_count(),"physical_records":raw.header().records_scanned,
            "mft_record_capacity":raw.header().mft_record_count,"blockers":raw.blocker_count(),
            "comparison":comparison,"native_bytes_read":source.native_bytes_read(),"events":events,
            "source_admitted":false,"execution_authorized":false,"conversion_qualified":false
        }),
    )?;
    println!("{}", args.output.join("result.json").display());
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Resource source observation requires Windows.");
    std::process::exit(1);
}
