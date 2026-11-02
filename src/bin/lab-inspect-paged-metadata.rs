//! Read-only lab observer for the complete pinned paged metadata domains.
//! Opens ordinary metadata files only, never journals, disks or source volumes.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{general_layout::GeneralSourceShadowBinding, reference_file};
    use ntfs2refs::{
        general_conversion::Request, general_reconstruct, selected_journal, shadow_tree,
    };
    use serde::de::DeserializeOwned;
    use std::{
        fs::{self, File, OpenOptions},
        io::{Seek, SeekFrom},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
        time::SystemTime,
    };

    fn pin(value: &str) -> std::result::Result<String, String> {
        if value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(value.to_owned())
        } else {
            Err("canonical lowercase SHA-256 required".into())
        }
    }
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long, value_parser = pin)]
        request_sha256: String,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long, value_parser = pin)]
        expectation_sha256: String,
        #[arg(long)]
        expected_pages: PathBuf,
        #[arg(long, value_parser = pin)]
        expected_pages_sha256: String,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, value_parser = pin)]
        plan_sha256: String,
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long, value_parser = pin)]
        ticket_sha256: String,
        #[arg(long)]
        payload_pages: PathBuf,
        #[arg(long, value_parser = pin)]
        payload_pages_sha256: String,
    }
    fn outside_data_volumes(path: &str, pair: &GeneralSourceShadowBinding) -> Result<()> {
        for binding in [&pair.source, &pair.shadow] {
            ensure!(
                !path
                    .to_ascii_lowercase()
                    .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
                "observer metadata must be independent of both data volumes"
            );
        }
        Ok(())
    }
    fn ordinary(path: &Path, leaf: &str) -> Result<()> {
        ensure!(
            path.is_absolute() && path.file_name().and_then(|v| v.to_str()) == Some(leaf),
            "exact ordinary metadata role/path required"
        );
        for component in path.components() {
            match component {
                Component::Prefix(p) => ensure!(
                    matches!(p.kind(), Prefix::Disk(_)),
                    "local metadata drive path required"
                ),
                Component::RootDir => {}
                Component::Normal(value) => {
                    let value = value.to_str().context("metadata path must be Unicode")?;
                    ensure!(
                        !value.ends_with([' ', '.'])
                            && !value.chars().any(|c| c.is_control()
                                || matches!(c, ':' | '"' | '<' | '>' | '|' | '?' | '*')),
                        "ambiguous metadata path refused"
                    );
                }
                _ => anyhow::bail!("metadata path traversal refused"),
            }
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "metadata reparse ancestry refused"
            );
        }
        Ok(())
    }
    struct Held {
        file: File,
        snapshot: reference_file::ReferenceFileSnapshot,
        modified: SystemTime,
        sha256: String,
    }
    impl Held {
        fn open(
            path: &Path,
            leaf: &str,
            sha256: &str,
            maximum: u64,
            pair: Option<&GeneralSourceShadowBinding>,
        ) -> Result<Self> {
            ordinary(path, leaf)?;
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(path)?;
            let snapshot = reference_file::observe_reference_file_handle(&file)?;
            ensure!(
                snapshot.file_bytes > 0 && snapshot.file_bytes <= maximum,
                "metadata role exceeds byte ceiling"
            );
            if let Some(pair) = pair {
                outside_data_volumes(&snapshot.final_path, pair)?;
            }
            let modified = file.metadata()?.modified()?;
            ensure!(
                hex::encode(n2r_win32::sha256_native::hash_range(
                    &mut file,
                    0,
                    snapshot.file_bytes
                )?) == sha256,
                "actual held metadata file SHA differs"
            );
            let mut held = Self {
                file,
                snapshot,
                modified,
                sha256: sha256.to_owned(),
            };
            held.revalidate()?;
            Ok(held)
        }
        fn read<T: DeserializeOwned>(&mut self) -> Result<T> {
            self.file.seek(SeekFrom::Start(0))?;
            Ok(serde_json::from_reader(&mut self.file)?)
        }
        fn revalidate(&mut self) -> Result<()> {
            ensure!(
                reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                    && self.file.metadata()?.modified()? == self.modified,
                "held metadata identity or timestamp changed"
            );
            ensure!(
                hex::encode(n2r_win32::sha256_native::hash_range(
                    &mut self.file,
                    0,
                    self.snapshot.file_bytes
                )?) == self.sha256
                    && reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                    && self.file.metadata()?.modified()? == self.modified,
                "held complete metadata bytes changed"
            );
            Ok(())
        }
    }
    let args = Args::parse();
    let mut request_file = Held::open(
        &args.request,
        "request.json",
        &args.request_sha256,
        128 * 1024,
        None,
    )?;
    let request: Request = request_file.read()?;
    // This validates serialized routing and policy only. It performs no native
    // journal/device open and creates no source or execution capability.
    request.validate()?;
    outside_data_volumes(&request_file.snapshot.final_path, &request.pair)?;
    let resources = request
        .source_resource_profile
        .context("pinned source resource profile absent")?;
    let admission = resources
        .count_admission()?
        .context("complete count admission absent")?;
    ensure!(
        admission.requires_paged_metadata(),
        "this observer requires schema-two paged resource admission"
    );
    let mut expectation_file = Held::open(
        &args.expectation,
        "expectation.json",
        &args.expectation_sha256,
        u64::from(admission.maximum_expected_tree_bytes),
        Some(&request.pair),
    )?;
    let mut plan_file = Held::open(
        &args.plan,
        "selected-plan.json",
        &args.plan_sha256,
        16 * 1024 * 1024,
        Some(&request.pair),
    )?;
    let mut ticket_file = Held::open(
        &args.ticket,
        "selected-ticket.json",
        &args.ticket_sha256,
        65536,
        Some(&request.pair),
    )?;
    let plan: selected_journal::SelectedPlan = plan_file.read()?;
    let ticket: selected_journal::SelectedTicket = ticket_file.read()?;
    // The library's map inspection below performs the complete marker-profile
    // plan validation, including format-six body geometry. Keep that protocol
    // private instead of substituting the legacy public format-five validator.
    ensure!(
        plan.image_length == request.pair.source.identity.partition_bytes
            && plan.max_journal_bytes == request.max_journal_bytes
            && ticket.journal_length > 0
            && ticket.journal_length <= request.max_journal_bytes
            && ticket.selected_bytes > 0
            && ticket.image_length == plan.image_length
            && ticket.range_count as usize == plan.ranges.len()
            && !ticket.whole_image_verified,
        "pinned request/plan/ticket domain differs"
    );
    ordinary(&args.expected_pages, "expectation.pages")?;
    ordinary(&args.payload_pages, "recovery-payload-manifest.pages")?;
    let expected = shadow_tree::PagedExpectedTree::open_with_limits(
        &args.expected_pages,
        &args.expected_pages_sha256,
        &args.expectation_sha256,
        admission.expected_page_budget()?,
        u64::from(admission.maximum_expected_tree_bytes),
    )?;
    outside_data_volumes(&expected.final_path(), &request.pair)?;
    expected.validate_with_resource_profile(resources)?;
    let counts = expected.counts();
    admission.validate_tree(
        usize::try_from(counts.files)?,
        usize::try_from(counts.directories)?,
        usize::try_from(counts.data_streams)?,
    )?;
    let map = general_reconstruct::inspect_pinned_recovery_pages(
        &args.payload_pages,
        &args.payload_pages_sha256,
        &request.pair.source,
        &expected,
        &plan,
        &ticket,
        resources,
    )?;
    let map_path = map
        .get("actual_final_path")
        .and_then(serde_json::Value::as_str)
        .context("validated map owner has no actual route")?;
    outside_data_volumes(map_path, &request.pair)?;
    for file in [
        &mut request_file,
        &mut expectation_file,
        &mut plan_file,
        &mut ticket_file,
    ] {
        file.revalidate()?;
    }
    expected.revalidate()?;
    let report = serde_json::json!({
        "schema_version":1,"kind":"lab-paged-resource-metadata-verification","success":true,
        "request_sha256":args.request_sha256,"expectation_sha256":args.expectation_sha256,
        "plan_sha256":args.plan_sha256,"ticket_sha256":args.ticket_sha256,
        "expected_pages_sha256":args.expected_pages_sha256,"payload_pages_sha256":args.payload_pages_sha256,
        "admission":admission,"admitted_raw_identities":admission.raw_identities,
        "raw_identity_guard_retained":n2r_win32::tree_resources::RAW_IDENTITIES,
        "actual_expected_counts":counts,"actual_legacy_expectation_bytes":expectation_file.snapshot.file_bytes,
        "actual_expected_pages":expected.page_count(),"actual_expected_page_file_bytes":expected.byte_len(),
        "actual_expected_page_budget":expected.budget(),"semantic_byte_budget":expected.semantic_byte_budget(),
        "legacy_pretty_semantic_pin_reconstructed":true,"all_expected_objects_validated":true,
        "complete_recovery_map_inspection":map,"independent_metadata_volume_routes_checked":true,
        "source_inspection_or_native_report_revalidated":false,
        "ordinary_metadata_only":true,"source_device_opened":false,"raw_journal_opened":false,
        "converter_or_recovery_launched":false,"source_certificate_recreated":false,
        "grants_source_admission":false,"grants_write_authority":false,"grants_replay_authority":false
    });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    Ok(())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("paged metadata ownership inspection requires Windows")
}
