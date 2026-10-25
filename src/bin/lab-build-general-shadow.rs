//! Build an independent Windows-native ReFS shadow from an already excluded
//! NTFS data partition. This command has no source write or disk-online path.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, GeneralPartitionReader, shadow_native};
    use ntfs2refs::{
        general_shadow::Request, lab_reconstruct, ntfs_attestation, ntfs_inspect, refs_inspect,
        shadow_tree,
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
        #[arg(long, conflicts_with = "verify_only")]
        retain_eligible: bool,
        #[arg(long)]
        verify_only: bool,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "general shadow report exceeds bound"
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
    let metadata = fs::symlink_metadata(&args.request)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 16384,
        "bounded ordinary request required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.request)?;
    let mut bytes = Vec::new();
    (&mut file).take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16384
            && args.request_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "general shadow request pin differs"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    ensure!(
        !args.output.exists(),
        "fresh general shadow output required"
    );
    let mut events = Vec::new();
    let mut shadow_reader = GeneralPartitionReader::open(request.pair.shadow.clone(), &mut events)?;
    let shadow_length = shadow_reader.byte_len();
    let target = refs_inspect::inspect(&mut shadow_reader, shadow_length)?;
    ensure!(
        target.geometry.major_version == 3
            && target.geometry.minor_version == 14
            && target.geometry.bytes_per_cluster == 4096
            && target.geometry.volume_bytes == shadow_length,
        "general shadow is not the ReFS 3.14/4 KiB profile"
    );
    shadow_reader.revalidate_route(&mut events)?;
    drop(shadow_reader);
    let mut source = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
    let source_before = source.state(&mut events)?;
    let source_hash = hex::encode(lab_reconstruct::hash_range(
        &mut source,
        0,
        request.pair.source.identity.partition_bytes,
    )?);
    ensure!(
        source_hash == request.source_sha256,
        "frozen source bytes differ before shadow construction"
    );
    let source_length = source.byte_len();
    let raw = ntfs_inspect::inspect(&mut source, source_length)?;
    let tree = shadow_tree::derive_ordinary(&raw)?;
    let input: Vec<_> = tree
        .objects
        .iter()
        .map(|object| shadow_native::Input {
            components: &object.path,
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
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
    save(
        &args.output.with_extension("intent.json"),
        &serde_json::json!({"schema_version":1,"kind":"general-shadow-intent",
            "request_sha256":args.request_sha256,"source_sha256":source_hash,
            "retain_eligible":args.retain_eligible,"verify_only":args.verify_only,
            "source_writes_authorized":false,
            "conversion_qualified":false}),
    )?;
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    let attempted = if args.verify_only {
        shadow_native::verify_general_ordinary(request.pair.clone(), &input, same_security)
    } else {
        let mut writer = |index: usize, target: &mut std::fs::File| -> std::io::Result<()> {
            let object = tree
                .objects
                .get(index)
                .ok_or_else(|| std::io::Error::other("stream index outside tree"))?;
            if object.directory {
                return Err(std::io::Error::other(
                    "directory cannot receive stream bytes",
                ));
            }
            let proof = ntfs_inspect::copy_plain_stream(
                &mut source,
                &raw,
                object.record_number,
                256 * 1024 * 1024,
                target,
            )
            .map_err(std::io::Error::other)?;
            if proof.logical_bytes != object.length || Some(&proof.sha256) != object.sha256.as_ref()
            {
                return Err(std::io::Error::other(
                    "source stream changed during construction",
                ));
            }
            Ok(())
        };
        shadow_native::run_general_ordinary_streaming(
            request.pair.clone(),
            &input,
            args.retain_eligible,
            &mut writer,
            same_security,
        )
    };
    let source_after_hash = hex::encode(lab_reconstruct::hash_range(
        &mut source,
        0,
        request.pair.source.identity.partition_bytes,
    )?);
    let source_after = source.state(&mut events)?;
    ensure!(
        source_hash == source_after_hash && source_before == source_after,
        "frozen source changed during shadow construction"
    );
    let report = match attempted {
        Ok(native) => serde_json::json!({"schema_version":1,"kind":"general-native-shadow",
            "success":true,"verify_only":args.verify_only,"request":request,"tree":tree,"native":native,
            "source_before":source_before,"source_after":source_after,
            "source_bytes_read":source.native_bytes_read(),"source_writes":0,
            "source_admitted":false,"conversion_qualified":false}),
        Err(error) => serde_json::json!({"schema_version":1,"kind":"general-native-shadow",
            "success":false,"verify_only":args.verify_only,"request":request,"error":error.to_string(),
            "source_before":source_before,"source_after":source_after,
            "source_bytes_read":source.native_bytes_read(),"source_writes":0,
            "source_admitted":false,"conversion_qualified":false}),
    };
    save(&args.output, &report)?;
    ensure!(
        report["success"] == true,
        "general native shadow construction failed"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general native shadow construction requires Windows");
    std::process::exit(1);
}
