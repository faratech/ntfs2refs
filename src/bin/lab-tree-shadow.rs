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
        let tree = shadow_tree::derive(&raw)?;
        let mut payloads = vec![];
        for o in &tree.objects {
            let mut bytes = vec![0; o.length as usize];
            if let Some(offset) = o.source_offset {
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
                directory: o.directory,
                times: o.stored_times,
                attributes: o.attributes,
                security: &o.security,
                payload: p,
                source_offset: o.source_offset,
            })
            .collect();
        // Read-only destination refusal may precede the expensive full source
        // hash. No shadow creation is permitted until the actual source pin
        // has been checked; all metadata still comes from raw device reads.
        let same_security = |a: &[u8], b: &[u8]| {
            ntfs_attestation::same_security(a, b).map_err(|e| std::io::Error::other(e.to_string()))
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
        let _probe = shadow_native::run(
            request.shadow.clone(),
            request.source.disk_number,
            &input,
            shadow_native::Mode::ProbeRoot,
            same_security,
        )?;
        phase = "revalidate-actual-source-before";
        let before = ntfs_freeze::revalidate_pin(&mut source, &request.source_sha256, &mut events)?;
        phase = "native-independent-shadow";
        let native_result = if args.finalize_security {
            shadow_native::repair_security(
                request.shadow.clone(),
                request.source.disk_number,
                &input,
                same_security,
            )
        } else {
            shadow_native::run(
                request.shadow.clone(),
                request.source.disk_number,
                &input,
                if args.verify_only {
                    shadow_native::Mode::Verify
                } else {
                    shadow_native::Mode::Construct
                },
                same_security,
            )
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
        let mappings: Vec<_> = tree
            .objects
            .iter()
            .zip(&native.objects)
            .filter(|(o, _)| !o.directory)
            .map(|(o, n)| -> Result<_> {
                let id = n
                    .before
                    .queries
                    .iter()
                    .find(|q| q.class == 18 && q.native_error.is_none() && q.bytes.len() == 24)
                    .context("missing target file identity")?;
                let extents = n2r_win32::stream_layout::parse_retrieval(&n.retrieval)?
                    .into_iter()
                    .map(|r| -> Result<_> {
                        Ok(ntfs_inspect::Extent {
                            logical_offset: r.vcn.checked_mul(4096).context("VCN overflow")?,
                            physical_offset: Some(
                                r.lcn
                                    .context("target sparse mapping")?
                                    .checked_mul(4096)
                                    .context("LCN overflow")?,
                            ),
                            length: r
                                .clusters
                                .checked_mul(4096)
                                .context("run length overflow")?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(ntfs2refs::tree_placement::Mapping {
                    record_number: o.record_number,
                    sequence_number: o.sequence_number,
                    target_file_id: id.bytes[8..24].try_into()?,
                    logical_sha256: n
                        .logical_sha256
                        .clone()
                        .context("missing target logical hash")?,
                    extents,
                })
            })
            .collect::<Result<_>>()?;
        let placement =
            ntfs2refs::tree_placement::diagnose(&tree, &mappings, &payloads, source.byte_len())?;
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
        Ok((
            serde_json::json!({"schema_version":1,"kind":"existing-tree-shadow-v1","success":matched,
            "verify_only":args.verify_only,"finalize_security":args.finalize_security,"tree":tree,"native":native,"comparison":comparison,
            "source_before":before,"source_after":after,"source_bytes_read":source.native_bytes_read,
            "source_bytes_written":source.native_bytes_written,"placement":placement,"frozen_shadow":frozen_shadow,
            "full_source_hash_verified":true,"source_admitted":false,"conversion_qualified":false}),
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
