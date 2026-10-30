//! Bounded independent-shadow experiment. This command cannot arm source writes.
#[cfg(not(windows))]
fn main() {
    eprintln!("native tree shadow requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{OfflinePartition, layout::DiskBinding, shadow_native};
    use ntfs2refs::{ntfs_attestation, ntfs_freeze, ntfs_inspect, shadow_tree};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        verify_only: bool,
        #[arg(long, conflicts_with = "verify_only")]
        root_security_experiment: bool,
        #[arg(long,conflicts_with_all=["verify_only","root_security_experiment"])]
        finalize_security: bool,
        #[arg(long, requires = "verify_only")]
        freeze_shadow: bool,
        /// Place eligible target streams at the frozen source locations using
        /// native ReFS movement; conflicting streams retain their real target
        /// allocations and are counted as journaled relocations.
        #[arg(long,conflicts_with_all=["verify_only","finalize_security","root_security_experiment"])]
        retain_eligible: bool,
        /// Materialize empty/resident/fragmented/tail streams and restore
        /// inherited descriptors on the independent shadow (profile v2).
        #[arg(long, conflicts_with = "root_security_experiment")]
        ordinary_files: bool,
        /// Construct the independent shadow directly from bounded source
        /// reads without retaining all logical payload bytes in memory.
        #[arg(
            long,
            requires = "ordinary_files",
            conflicts_with = "root_security_experiment"
        )]
        stream_payload: bool,
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        schema_version: u32,
        source: DiskBinding,
        source_sha256: String,
        shadow: DiskBinding,
    }
    fn ordinary(p: &Path, existing: bool) -> Result<()> {
        let text = p.to_str().context("non-Unicode artifact path")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains('/')
                && !text.contains("..")
                && !text.ends_with([' ', '.']),
            "ordinary guest-local artifacts required"
        );
        for (i, a) in p.ancestors().enumerate() {
            if i == 0 && !existing {
                ensure!(!a.exists(), "output exists");
                continue;
            }
            let m = fs::symlink_metadata(a)?;
            ensure!(
                m.file_attributes() & 0x400 == 0 && if i == 0 { m.is_file() } else { m.is_dir() },
                "artifact ancestry differs"
            );
        }
        Ok(())
    }
    fn save(p: &Path, v: &impl Serialize) -> Result<()> {
        ordinary(p, false)?;
        let b = serde_json::to_vec_pretty(v)?;
        ensure!(b.len() <= 16 * 1024 * 1024, "evidence budget exceeded");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(p)?;
        f.write_all(&b)?;
        f.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    ordinary(&args.request, true)?;
    ordinary(&args.output, false)?;
    let mut f = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.request)?;
    ensure!(f.metadata()?.len() <= 16384, "request exceeds bound");
    let mut bytes = vec![];
    (&mut f).take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16384 && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request pin differs"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    request.source.validate()?;
    request.shadow.validate()?;
    ensure!(
        request.schema_version == 1
            && request.source.disk_number == 1
            && request.shadow.disk_number == 3
            && request.source.volume_guid != request.shadow.volume_guid
            && request.source.identity.disk_guid != request.shadow.identity.disk_guid,
        "distinct restricted source and shadow required"
    );
    save(
        &args.output.with_extension("intent.json"),
        &serde_json::json!({"kind":"existing-tree-shadow-intent-v1",
        "request":request,"request_sha256":args.request_sha256,"verify_only":args.verify_only,
        "root_security_experiment":args.root_security_experiment,
        "finalize_security":args.finalize_security,
        "freeze_shadow":args.freeze_shadow,
        "retain_eligible":args.retain_eligible,
        "ordinary_files":args.ordinary_files,
        "stream_payload":args.stream_payload,
        "source_writes_authorized":false,"conversion_qualified":false}),
    )?;
    let mut events = vec![];
    let mut phase = "reopen-excluded-source";
    let mut native_failure_basis = None;
    let result = (|| -> Result<(serde_json::Value, bool)> {
        let mut source = OfflinePartition::reopen(request.source.clone(), true, &mut events)?;
        phase = "derive-tree-from-actual-device";
        let length = source.byte_len();
        let raw = ntfs_inspect::inspect(&mut source, length)?;
        let tree = if args.ordinary_files {
            shadow_tree::derive_ordinary(&raw)?
        } else {
            shadow_tree::derive(&raw)?
        };
        let mut payloads = vec![];
        for o in &tree.objects {
            let mut bytes = if args.stream_payload {
                vec![]
            } else if args.ordinary_files && !o.directory {
                ntfs_inspect::read_plain_stream(
                    &mut source,
                    &raw,
                    o.record_number,
                    256 * 1024 * 1024,
                )?
            } else {
                vec![0; o.length as usize]
            };
            if !args.ordinary_files
                && let Some(offset) = o.source_offset
            {
                source.seek(SeekFrom::Start(offset))?;
                source.read_exact(&mut bytes)?;
                ensure!(
                    Some(hex::encode(Sha256::digest(&bytes))) == o.sha256,
                    "source stream hash differs"
                );
            }
            payloads.push(bytes);
        }
        let input: Vec<_> = tree
            .objects
            .iter()
            .zip(&payloads)
            .map(|(o, p)| shadow_native::Input {
                components: &o.path,
                additional_names: &o.additional_names,
                directory: o.directory,
                times: o.stored_times,
                attributes: o.attributes,
                security: &o.security,
                expected_api_security: o.api_security.as_deref(),
                payload: p,
                expected_length: if args.stream_payload && !o.directory {
                    Some(o.length)
                } else {
                    None
                },
                expected_sha256: if args.stream_payload && !o.directory {
                    o.sha256.as_deref()
                } else {
                    None
                },
                source_offset: o.source_offset,
                source_runs: o
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
        // Read-only destination refusal may precede the expensive full source
        // hash. No shadow creation is permitted until the actual source pin
        // has been checked; all metadata still comes from raw device reads.
        let same_security = |a: &[u8], b: &[u8]| {
            ntfs_attestation::same_security(a, b).map_err(|e| std::io::Error::other(e.to_string()))
        };
        let native_run = |mode| {
            if args.ordinary_files {
                shadow_native::run_ordinary(
                    request.shadow.clone(),
                    request.source.disk_number,
                    &input,
                    mode,
                    same_security,
                )
            } else {
                shadow_native::run(
                    request.shadow.clone(),
                    request.source.disk_number,
                    &input,
                    mode,
                    same_security,
                )
            }
        };
        if args.root_security_experiment {
            phase = "root-security-interop-only";
            let before = source.inspect(&mut events)?;
            let attempted = shadow_native::run(
                request.shadow.clone(),
                request.source.disk_number,
                &input,
                shadow_native::Mode::RestoreRootOnly,
                same_security,
            );
            let after = source.inspect(&mut events)?;
            ensure!(
                before.disk_attributes == 3
                    && after.disk_attributes == 3
                    && before.binding == after.binding
                    && source.native_bytes_written == 0
                    && source.native_write_bytes_requested == 0,
                "source exclusion changed"
            );
            native_failure_basis = Some(
                serde_json::json!({"source_before":before,"source_after":after,
                "source_bytes_written":0,"full_source_hash_verified":false}),
            );
            let native = attempted?;
            return Ok((
                serde_json::json!({"schema_version":1,"kind":"root-security-interop-v1",
                "success":true,"native":native,"expected_root":tree.objects.first(),
                "source_snapshots":native_failure_basis,"source_bytes_read":source.native_bytes_read,
                "source_bytes_written":0,"full_source_hash_verified":false,
                "source_admitted":false,"conversion_qualified":false}),
                true,
            ));
        }
        phase = "probe-native-shadow-root";
        let _probe = native_run(shadow_native::Mode::ProbeRoot)?;
        phase = "revalidate-actual-source-before";
        let before = ntfs_freeze::revalidate_pin(&mut source, &request.source_sha256, &mut events)?;
        phase = "native-independent-shadow";
        let native_result = if args.finalize_security {
            if args.ordinary_files {
                shadow_native::repair_security_ordinary(
                    request.shadow.clone(),
                    request.source.disk_number,
                    &input,
                    same_security,
                )
            } else {
                shadow_native::repair_security(
                    request.shadow.clone(),
                    request.source.disk_number,
                    &input,
                    same_security,
                )
            }
        } else if args.stream_payload && !args.verify_only {
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
                if proof.logical_bytes != object.length
                    || Some(&proof.sha256) != object.sha256.as_ref()
                {
                    return Err(std::io::Error::other(
                        "streamed NTFS payload differs from the tree",
                    ));
                }
                Ok(())
            };
            shadow_native::run_ordinary_streaming(
                request.shadow.clone(),
                request.source.disk_number,
                &input,
                args.retain_eligible,
                &mut writer,
                same_security,
            )
        } else {
            native_run(if args.verify_only {
                shadow_native::Mode::Verify
            } else if args.retain_eligible {
                shadow_native::Mode::ConstructRetaining
            } else {
                shadow_native::Mode::Construct
            })
        };
        phase = "revalidate-actual-source-after";
        let after = ntfs_freeze::revalidate_pin(&mut source, &request.source_sha256, &mut events)?;
        let native = match native_result {
            Ok(native) => native,
            Err(error) => {
                native_failure_basis = Some(serde_json::json!({"tree":tree,"source_before":before,
                    "source_after":after,"source_bytes_read":source.native_bytes_read,
                    "source_bytes_written":source.native_bytes_written}));
                phase = "native-independent-shadow";
                return Err(error.into());
            }
        };
        phase = "compare-shadow-semantics";
        let comparison:Vec<_>=tree.objects.iter().zip(&native.objects).map(|(expected,actual)|->Result<_>{
            ensure!(expected.path==actual.components,"shadow result identity order differs");
            let mut wanted=vec![];
            for t in expected.stored_times { wanted.extend_from_slice(&t.to_le_bytes()); }
            wanted.extend_from_slice(&expected.attributes.to_le_bytes()); wanted.extend_from_slice(&[0;4]);
            let basic_matches=actual.before.queries.iter().find(|q|q.class==0)
                .is_some_and(|q|q.native_error.is_none() && q.bytes==wanted);
            let api_security_matches=actual.before.security_error.is_none()
                && ntfs_attestation::same_security(&expected.security,&actual.before.security)?;
            let kernel_security_matches=actual.before.kernel_security.as_ref().is_some_and(|q|
                q.native_error.is_none() && ntfs_attestation::same_security(&expected.security,&q.bytes).unwrap_or(false));
            let content_matches=actual.logical_sha256==expected.sha256;
            let expected_names:std::collections::BTreeSet<_>=tree.objects.iter().filter(|o|o.path.len()==expected.path.len()+1
                && o.path.starts_with(&expected.path)).map(|o|o.path.last().unwrap().encode_utf16().collect::<Vec<_>>()).collect();
            let actual_names:std::collections::BTreeSet<_>=actual.namespace.iter().filter(|n|
                n.name_utf16!=[46] && n.name_utf16!=[46,46] && !(expected.path.is_empty()
                    && n.name_utf16=="System Volume Information".encode_utf16().collect::<Vec<_>>()))
                .map(|n|n.name_utf16.clone()).collect();
            let namespace_identity_matches=actual.namespace.iter().filter(|n|n.name_utf16!=[46] && n.name_utf16!=[46,46]
                && !(expected.path.is_empty() && n.name_utf16=="System Volume Information".encode_utf16().collect::<Vec<_>>()))
                .all(|entry|tree.objects.iter().zip(&native.objects).any(|(child,measured)|
                    child.path.len()==expected.path.len()+1 && child.path.starts_with(&expected.path)
                    && child.path.last().unwrap().encode_utf16().collect::<Vec<_>>()==entry.name_utf16
                    && entry.attributes==child.attributes && measured.before.queries.iter().any(|q|
                        q.class==18 && q.native_error.is_none() && q.bytes.len()==24 && q.bytes[8..24]==entry.file_id)));
            let namespace_matches=!expected.directory || (expected_names==actual_names && namespace_identity_matches);
            Ok(serde_json::json!({"record_number":expected.record_number,"path":expected.path,
                "basic_matches":basic_matches,"api_security_matches":api_security_matches,
                "kernel_security_matches":kernel_security_matches,"content_matches":content_matches,
                "namespace_matches":namespace_matches,"matched":basic_matches && api_security_matches
                    && kernel_security_matches && content_matches && namespace_matches}))
        }).collect::<Result<_>>()?;
        ensure!(
            tree.objects.len() == native.objects.len(),
            "shadow object coverage differs"
        );
        let mappings = ntfs2refs::tree_placement::mappings_from_native(&tree, &native)?;
        let partition_len = source.byte_len();
        let placement = if args.stream_payload {
            ntfs2refs::tree_placement::diagnose_measured(
                &tree,
                &mappings,
                &mut source,
                partition_len,
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
            )?
        } else {
            ntfs2refs::tree_placement::diagnose(&tree, &mappings, &payloads, partition_len)?
        };
        let matched = comparison.iter().all(|c| c["matched"] == true);
        let frozen_shadow = if args.freeze_shadow {
            ensure!(matched, "shadow semantics must match before freezing");
            phase = "freeze-actual-independent-shadow";
            Some(ntfs2refs::shadow_freeze::FrozenShadow::capture(
                request.shadow.clone(),
                &native,
                &tree,
                &placement,
                &mut events,
            )?)
        } else {
            None
        };
        let comparison_request = frozen_shadow
            .as_ref()
            .map(|frozen| {
                frozen.comparison_request(&placement, &request.source_sha256, 256 * 1024 * 1024)
            })
            .transpose()?;
        Ok((
            serde_json::json!({"schema_version":1,"kind":"existing-tree-shadow-v1","success":matched,
            "verify_only":args.verify_only,"finalize_security":args.finalize_security,"tree":tree,"native":native,"comparison":comparison,
            "source_before":before,"source_after":after,"source_bytes_read":source.native_bytes_read,
            "source_bytes_written":source.native_bytes_written,"placement":placement,"frozen_shadow":frozen_shadow,
            "full_source_hash_verified":true,"source_admitted":false,"conversion_qualified":false,"comparison_request":comparison_request}),
            matched,
        ))
    })();
    let success = result.as_ref().is_ok_and(|r| r.1);
    let mut report = match result {
        Ok((value, _)) => value,
        Err(error) => {
            serde_json::json!({"schema_version":1,"kind":"existing-tree-shadow-v1","success":false,
            "phase":phase,"error":format!("{error:#}"),"source_events":events,"native_failure_source_verification":native_failure_basis,
            "source_admitted":false,"conversion_qualified":false})
        }
    };
    report["source_events"] = serde_json::to_value(events)?;
    save(&args.output, &report)?;
    ensure!(
        success,
        "independent tree shadow did not pass; source remains excluded and read-only"
    );
    Ok(())
}
