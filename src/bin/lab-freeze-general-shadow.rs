//! Freeze a completed independent ReFS shadow. The NTFS source is opened only
//! read-only, and neither partition receives a payload write.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, shadow_native};
    use ntfs2refs::{
        general_shadow::Request, lab_reconstruct, ntfs_attestation, ntfs_inspect, refs_inspect,
        refs_retained_allocation, shadow_tree, tree_placement,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "freeze report exceeds bound"
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
    let intent_path = args.output.with_extension("intent.json");
    let native_path = args.output.with_extension("native.json");
    let expectation_path = args.output.with_extension("expectation.json");
    ensure!(
        !args.output.exists()
            && !intent_path.exists()
            && !native_path.exists()
            && !expectation_path.exists(),
        "fresh freeze output and evidence paths required"
    );
    let metadata = fs::symlink_metadata(&args.request)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 16384,
        "bounded ordinary request required"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.request)?;
    let mut bytes = Vec::new();
    (&mut input).take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16384
            && args.request_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "general freeze request pin differs"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
    let source_before = source.state(&mut events)?;
    let source_length = source.byte_len();
    let source_hash = hex::encode(lab_reconstruct::hash_range(&mut source, 0, source_length)?);
    ensure!(
        source_hash == request.source_sha256,
        "source differs before ReFS shadow freeze"
    );
    save(
        &intent_path,
        &serde_json::json!({"schema_version":1,"kind":"general-shadow-freeze-intent",
            "request_sha256":args.request_sha256,"source_sha256":source_hash,
            "shadow_disk_number":request.pair.shadow.disk_number,
            "source_writes_authorized":false,"conversion_qualified":false}),
    )?;
    let raw = ntfs_inspect::inspect(&mut source, source_length)?;
    let (tree, source_views) =
        ntfs2refs::general_shadow::observed_tree(&mut source, &raw, &mut events)?;
    save(
        &args.output.with_extension("source-views.json"),
        &source_views,
    )?;
    let expectation = shadow_tree::ExpectedTree::from(&tree);
    expectation.validate()?;
    save(&expectation_path, &expectation)?;
    let expectation_sha256 = hex::encode(Sha256::digest(fs::read(&expectation_path)?));
    let input: Vec<_> = tree
        .objects
        .iter()
        .map(|object| shadow_native::Input {
            components: &object.path,
            additional_names: &object.additional_names,
            named_streams: ntfs2refs::general_shadow::native_named_streams(object),
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
            expected_api_security: object.api_security.as_deref(),
            payload: &[],
            expected_length: if object.directory {
                None
            } else {
                Some(object.length)
            },
            expected_sha256: if object.directory {
                None
            } else {
                object.sha256.as_deref()
            },
            source_offset: object.source_offset,
            source_runs: object
                .source_extents
                .iter()
                .map(|run| shadow_native::SourceRun {
                    logical_offset: run.logical_offset,
                    physical_offset: run.physical_offset,
                    length: run.length,
                })
                .collect(),
        })
        .collect();
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    let native =
        shadow_native::verify_general_ordinary(request.pair.clone(), &input, same_security)?;
    save(&native_path, &native)?;
    let native_sha256 = hex::encode(Sha256::digest(fs::read(&native_path)?));
    let mappings = tree_placement::mappings_from_native(&tree, &native.native)?;
    let placement = tree_placement::diagnose_measured(
        &tree,
        &mappings,
        &mut source,
        source_length,
        |reader, object, start, end| {
            ntfs_inspect::hash_plain_stream_range(
                reader,
                &raw,
                object.record_number,
                start,
                end - start,
                256 * 1024 * 1024,
            )
        },
    )?;
    let mut shadow = GeneralFrozenPartition::isolate(request.pair.shadow.clone(), &mut events)?;
    let shadow_before = shadow.state(&mut events)?;
    let shadow_length = shadow.byte_len();
    let shadow_hash = hex::encode(lab_reconstruct::hash_range(&mut shadow, 0, shadow_length)?);
    let refs = refs_inspect::inspect(&mut shadow, shadow_length)?;
    ensure!(
        refs.geometry.major_version == 3
            && refs.geometry.minor_version == 14
            && refs.geometry.bytes_per_cluster == 4096
            && refs.geometry.volume_bytes == shadow_length,
        "frozen shadow ReFS profile differs"
    );
    let source_after_hash =
        hex::encode(lab_reconstruct::hash_range(&mut source, 0, source_length)?);
    let source_after = source.state(&mut events)?;
    ensure!(
        source_after_hash == source_hash && source_before == source_after,
        "source changed during shadow freeze"
    );
    let comparison = placement.comparison_request(
        shadow_length,
        &source_hash,
        &shadow_hash,
        256 * 1024 * 1024,
    )?;
    let (retained_allocation, retained_allocation_error) = if comparison.retained_ranges.is_empty()
    {
        (None, None)
    } else {
        match refs_retained_allocation::inspect(&mut shadow, shadow_length, &comparison) {
            Ok(observation) => (Some(observation), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        }
    };
    let retained_allocator_coverage_verified = comparison.retained_ranges.is_empty()
        || retained_allocation
            .as_ref()
            .is_some_and(|observation| observation.retained_allocator_coverage_verified);
    let shadow_after = shadow.state(&mut events)?;
    ensure!(
        shadow_before == shadow_after,
        "shadow exclusion changed during freeze"
    );
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-frozen-refs-shadow",
            "request":request,"source_sha256":source_hash,"shadow_sha256":shadow_hash,
            "source_before":source_before,"source_after":source_after,
            "shadow_before":shadow_before,"shadow_after":shadow_after,
            "refs":refs,"native_evidence_sha256":native_sha256,
            "expectation_sha256":expectation_sha256,
            "placement":placement,"comparison_request":comparison,
            "retained_allocation":retained_allocation,
            "retained_allocation_error":retained_allocation_error,
            "retained_allocator_coverage_verified":retained_allocator_coverage_verified,
            "events":events,
            "source_writes":0,"shadow_payload_writes":0,
            "source_admitted":false,"conversion_qualified":false}),
    )?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general shadow freeze requires Windows");
    std::process::exit(1);
}
