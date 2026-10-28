//! Explicit allocation-only namespace template. Source JSON is diagnostic
//! input, not admission; this command cannot write or convert the source.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use ntfs2refs::{general_shadow, ntfs_admission::ResourceProfile, shadow_tree};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        path::{Path, PathBuf},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        tree: PathBuf,
        #[arg(long)]
        tree_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        observe_existing: bool,
        #[arg(long, requires_all=["inspection","inspection_sha256"], conflicts_with="observe_existing")]
        materialize_small: bool,
        #[arg(long, requires = "materialize_small")]
        prepare_large_tails: bool,
        #[arg(long, requires = "materialize_small")]
        inspection: Option<PathBuf>,
        #[arg(long, requires = "materialize_small")]
        inspection_sha256: Option<String>,
    }
    fn evidence(path: &Path) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "ordinary evidence file required"
        );
        let mut bytes = vec![];
        file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16 * 1024 * 1024, "evidence budget exceeded");
        Ok(bytes)
    }
    fn save(path: &Path, value: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "private tree report exceeds bound"
        );
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    ensure!(!args.output.exists(), "fresh report required");
    let request_bytes = evidence(&args.request)?;
    let tree_bytes = evidence(&args.tree)?;
    ensure!(
        hex::encode(Sha256::digest(&request_bytes)) == args.request_sha256
            && hex::encode(Sha256::digest(&tree_bytes)) == args.tree_sha256,
        "input pins differ"
    );
    let request: general_shadow::Request = serde_json::from_slice(&request_bytes)?;
    let resources = ResourceProfile::ExperimentalStreamingTreeV2;
    request.validate_with_resource_profile(resources)?;
    let expected: shadow_tree::ExpectedTree = serde_json::from_slice(&tree_bytes)?;
    expected.validate_with_resource_profile(resources)?;
    let tree = shadow_tree::Tree {
        profile: resources.ordinary_shadow_profile(),
        objects: expected.objects,
        logical_bytes: expected.logical_bytes,
        internal_replacement_pending: expected.internal_replacement_pending,
    };
    let inspection = if args.materialize_small {
        let bytes = evidence(args.inspection.as_deref().unwrap())?;
        ensure!(
            Some(hex::encode(Sha256::digest(&bytes))) == args.inspection_sha256,
            "inspection pin differs"
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        Some(serde_json::from_value::<
            ntfs2refs::ntfs_inspect::NtfsInspection,
        >(value.get("ntfs").unwrap_or(&value).clone())?)
    } else {
        None
    };
    save(
        &args.output.with_extension("intent.json"),
        &serde_json::json!({
        "kind":if args.observe_existing {"private-tree-observation-intent"}else{"private-tree-allocation-intent"},
        "observe_existing":args.observe_existing,"allocation_writes_authorized":!args.observe_existing,
        "materialize_small":args.materialize_small,"prepare_large_tails":args.prepare_large_tails,
        "inspection_sha256":args.inspection_sha256,
        "request_sha256":args.request_sha256,
        "tree_sha256":args.tree_sha256,"source_writes_authorized":false,
        "source_image_hash_reverified":false,"source_admitted":false,"conversion_qualified":false}),
    )?;
    let attempt = if args.observe_existing {
        n2r_win32::shadow_native::private_tree::observe_existing(
            &request.pair,
            &general_shadow::native_inputs(&tree),
        )
        .map_err(anyhow::Error::from)
    } else {
        (|| -> Result<serde_json::Value> {
            let selected: Vec<_> = tree
                .objects
                .iter()
                .enumerate()
                .filter(|(_, o)| {
                    !o.directory
                        && (o.length <= 4096 || (args.prepare_large_tails && o.length % 4096 != 0))
                        && !o
                            .path
                            .first()
                            .is_some_and(|s| s == "System Volume Information")
                })
                .map(|(i, o)| {
                    if o.length <= 4096 {
                        (i, 0, o.length as usize)
                    } else {
                        (i, o.length / 4096 * 4096, (o.length % 4096) as usize)
                    }
                })
                .collect();
            let mut events = Vec::new();
            let mut source = if args.materialize_small {
                Some(n2r_win32::GeneralFrozenPartition::reopen(
                    request.pair.source.clone(),
                    &mut events,
                )?)
            } else {
                None
            };
            let mut budget = ntfs2refs::ntfs_inspect::StreamTransferBudget::new(
                resources.limits().maximum_stream_bytes,
                8 * 1024 * 1024,
            )?;
            // Check all source ranges before creating a namespace. A stale
            // raw model must not cause needless partial shadow allocation.
            if let (Some(source), Some(raw)) = (source.as_mut(), inspection.as_ref()) {
                let mut buffer = [0u8; 4096];
                for &(index, offset, length) in &selected {
                    let object = &tree.objects[index];
                    let matches: Vec<_> = raw
                        .files
                        .iter()
                        .filter(|f| f.record_number == object.record_number)
                        .collect();
                    ensure!(
                        matches.len() == 1 && matches[0].sequence_number == object.sequence_number,
                        "small source file identity differs from tree"
                    );
                    let proof = ntfs2refs::ntfs_inspect::read_plain_stream_range_into(
                        source,
                        raw,
                        object.record_number,
                        offset,
                        &mut buffer[..length],
                        &mut budget,
                    )?;
                    ensure!(
                        Some(&proof.expected_stream_sha256) == object.sha256.as_ref()
                            && proof.stream_logical_bytes == object.length,
                        "small source object differs from tree"
                    );
                }
            }
            let mut template = general_shadow::allocate_private_tree(&request.pair, &tree)?;
            let mut transfers = Vec::new();
            let mut unverified_prefixes = Vec::new();
            if let (Some(source), Some(raw)) = (source.as_mut(), inspection.as_ref()) {
                for &(index, offset, length) in &selected {
                    if offset > 0 {
                        unverified_prefixes.push(template.prepare_unplaced_prefix(index, offset)?);
                    }
                    transfers.push(general_shadow::materialize_private_range(
                        source,
                        raw,
                        &tree,
                        &mut template,
                        index,
                        offset,
                        length,
                        &mut budget,
                    )?);
                }
            }
            let mut report = template.report()?;
            report["source_materialization_ranges"] = serde_json::to_value(transfers)?;
            report["private_unverified_prefixes"] = serde_json::to_value(unverified_prefixes)?;
            report["source_logical_range_bytes_charged"] = budget.reserved_bytes().into();
            report["large_payload_initialization_selected"] = false.into();
            Ok(report)
        })()
    };
    let failure = attempt.as_ref().err().map(ToString::to_string);
    let native = match attempt {
        Ok(value) => value,
        Err(error) => {
            serde_json::json!({"kind":"private-tree-allocation-failure","error":error.to_string()})
        }
    };
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"private-tree-allocation",
        "success":failure.is_none(),"observe_existing":args.observe_existing,
        "materialize_small":args.materialize_small,"prepare_large_tails":args.prepare_large_tails,
        "inspection_sha256":args.inspection_sha256,
        "request_sha256":args.request_sha256,"tree_sha256":args.tree_sha256,
        "request":request,"native":native,"source_image_hash_reverified":false,
        "source_admitted":false,"conversion_qualified":false}),
    )?;
    if let Some(error) = failure {
        anyhow::bail!("private allocation failed: {error}");
    }
    println!(
        "Private tree staging/observation complete; payload supply and metadata restoration remain pending."
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("private tree allocation requires Windows");
    std::process::exit(1);
}
