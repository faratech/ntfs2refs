//! Explicit allocation-only namespace template. Source JSON is diagnostic
//! input, not admission; this command cannot write or convert the source.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{ensure, Result};
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
        place_source_prefixes: bool,
        #[arg(long, default_value_t = 8589934592)]
        max_placement_bytes: u64,
        #[arg(long, default_value_t = 1024)]
        max_placement_moves: usize,
        #[arg(long, requires = "place_source_prefixes")]
        materialize_relocations: bool,
        #[arg(
            long,
            requires = "place_source_prefixes",
            conflicts_with = "materialize_relocations"
        )]
        source_backed_payloads: bool,
        #[arg(long, requires = "materialize_relocations")]
        verify_logical_hybrid: bool,
        #[arg(long, default_value_t = 268435456)]
        max_materialize_bytes: u64,
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
        "place_source_prefixes":args.place_source_prefixes,
        "source_backed_payloads":args.source_backed_payloads,
        "max_placement_bytes":args.max_placement_bytes,"max_placement_moves":args.max_placement_moves,
        "materialize_relocations":args.materialize_relocations,"max_materialize_bytes":args.max_materialize_bytes,
        "verify_logical_hybrid":args.verify_logical_hybrid,
        "inspection_sha256":args.inspection_sha256,
        "request_sha256":args.request_sha256,
        "tree_sha256":args.tree_sha256,"source_writes_authorized":false,
        "source_image_hash_reverified":false,"source_admitted":false,"conversion_qualified":false}),
    )?;
    let mut failed_placement = None;
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
                        && (o.length <= 4096
                            || ((args.prepare_large_tails || args.source_backed_payloads)
                                && o.length % 4096 != 0))
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
                if args.materialize_relocations {
                    args.max_materialize_bytes
                        .checked_add(8 * 1024 * 1024)
                        .ok_or_else(|| anyhow::anyhow!("materialization budget overflow"))?
                } else {
                    8 * 1024 * 1024
                },
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
            let placement = if args.place_source_prefixes {
                let result = template.place_source_prefixes_with_limits(
                    &general_shadow::native_inputs(&tree),
                    args.max_placement_bytes,
                    args.max_placement_moves,
                );
                match result {
                    Ok(value) => Some(value),
                    Err(error) => {
                        failed_placement = Some(template.placement_progress().clone());
                        return Err(error.into());
                    }
                }
            } else {
                None
            };
            let mut transfers = Vec::new();
            let mut unverified_prefixes = Vec::new();
            let mut relocation_materialization = None;
            let mut logical_hybrid = None;
            if args.source_backed_payloads {
                template.prepare_source_backed_prefixes()?;
            }
            if let (Some(source), Some(raw)) = (source.as_mut(), inspection.as_ref()) {
                if args.materialize_relocations {
                    relocation_materialization =
                        Some(general_shadow::materialize_private_supply_plan(
                            source,
                            raw,
                            &tree,
                            &mut template,
                            args.max_materialize_bytes,
                            &mut budget,
                        )?);
                    if args.verify_logical_hybrid {
                        logical_hybrid = Some(general_shadow::verify_private_hybrid_contents(
                            source,
                            &tree,
                            &mut template,
                        )?);
                    }
                } else {
                    for &(index, offset, length) in &selected {
                        if offset > 0 && !args.source_backed_payloads {
                            if args.place_source_prefixes {
                                template.advance_placed_prefix(index, offset)?;
                                unverified_prefixes.push(serde_json::json!({"object_index":index,
                                "storage_valid_prefix_bytes":offset,"native_placements_complete":true,
                                "source_prefix_contents_verified":false,"private_scratch_only":true,
                                "conversion_qualified":false}));
                            } else {
                                unverified_prefixes
                                    .push(template.prepare_unplaced_prefix(index, offset)?);
                            }
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
            }
            let mut report = template.report()?;
            report["source_materialization_ranges"] = serde_json::to_value(transfers)?;
            report["private_unverified_prefixes"] = serde_json::to_value(unverified_prefixes)?;
            report["source_prefix_placement"] = serde_json::to_value(placement)?;
            report["relocation_materialization"] =
                serde_json::to_value(relocation_materialization)?;
            report["logical_hybrid_verification"] = serde_json::to_value(logical_hybrid)?;
            if args.source_backed_payloads {
                report["source_backed_payload_routes"] = serde_json::to_value(
                    template.source_backed_routes(&general_shadow::native_inputs(&tree))?,
                )?;
                report["relocated_payload_shadow_initialization_skipped"] = true.into();
                report["frozen_required_byte_capture_pending"] = true.into();
            }
            report["source_logical_range_bytes_charged"] = budget.reserved_bytes().into();
            report["large_payload_initialization_selected"] = false.into();
            Ok(report)
        })()
    };
    let failure = attempt.as_ref().err().map(ToString::to_string);
    let native = match attempt {
        Ok(value) => value,
        Err(error) => {
            serde_json::json!({"kind":"private-tree-allocation-failure","error":error.to_string(),
                "placement_progress":failed_placement})
        }
    };
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"private-tree-allocation",
        "success":failure.is_none(),"observe_existing":args.observe_existing,
        "verify_logical_hybrid":args.verify_logical_hybrid,
        "materialize_small":args.materialize_small,"prepare_large_tails":args.prepare_large_tails,
        "place_source_prefixes":args.place_source_prefixes,
        "source_backed_payloads":args.source_backed_payloads,
        "materialize_relocations":args.materialize_relocations,"max_materialize_bytes":args.max_materialize_bytes,
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
