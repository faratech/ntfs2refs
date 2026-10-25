//! Explicit native source freeze and fresh raw inspection, without payload writes.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{OfflinePartition, layout::DiskBinding};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
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
        #[arg(long, required_unless_present_any = ["verify_source_sha256","native_interface_probe"])]
        inspection_output: Option<PathBuf>,
        #[arg(long)]
        reopen: bool,
        #[arg(long, requires = "reopen", conflicts_with = "inspection_output")]
        verify_source_sha256: Option<String>,
        #[arg(long, requires = "reopen", conflicts_with = "verify_source_sha256")]
        observation_output: Option<PathBuf>,
        #[arg(long,requires="reopen",conflicts_with_all=["verify_source_sha256","observation_output","inspection_output"])]
        native_interface_probe: bool,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        schema_version: u32,
        experiment_id: String,
        source: DiskBinding,
    }
    fn path(path: &Path, existing: bool) -> Result<()> {
        let text = path.to_str().context("non-Unicode artifact path")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains('/')
                && !text.contains("..")
                && !text.ends_with([' ', '.']),
            "ordinary artifacts under C:\\ntfs2refs required"
        );
        for (i, ancestor) in path.ancestors().enumerate() {
            if i == 0 && !existing {
                ensure!(!ancestor.exists(), "output exists");
                continue;
            }
            let m = fs::symlink_metadata(ancestor)?;
            ensure!(
                m.file_attributes() & 0x400 == 0 && if i == 0 { m.is_file() } else { m.is_dir() },
                "artifact or ancestor type differs"
            );
        }
        Ok(())
    }
    fn save(pathname: &Path, value: &impl Serialize, maximum: usize) -> Result<String> {
        path(pathname, false)?;
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(bytes.len() <= maximum, "artifact exceeds bound");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(pathname)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
    let args = Args::parse();
    path(&args.output, false)?;
    if let Some(inspection_output) = &args.inspection_output {
        path(inspection_output, false)?;
        ensure!(
            args.output != *inspection_output,
            "distinct fresh outputs required"
        );
    }
    if let Some(observation) = &args.observation_output {
        path(observation, false)?;
        ensure!(
            *observation != args.output && args.inspection_output.as_ref() != Some(observation),
            "distinct fresh observation output required"
        );
    }
    path(&args.request, true)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&args.request)?;
    ensure!(file.metadata()?.len() <= 16_384, "request exceeds bound");
    let mut bytes = vec![];
    (&mut file).take(16_385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16_384
            && args.request_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request pin differs"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    ensure!(
        request.schema_version == 1
            && request.experiment_id.len() == 32
            && request
                .experiment_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid freeze request profile"
    );
    request.source.validate()?;
    save(
        &args.output.with_extension("intent.json"),
        &serde_json::json!({
            "schema_version":1,"kind":"ntfs-source-freeze-intent-v1","request":request,
            "request_sha256":args.request_sha256,"reopen":args.reopen,
            "source_payload_write_requests_issued":false,"persistent_exclusion_may_follow":!args.reopen,
            "verify_source_sha256":args.verify_source_sha256,
            "native_observation_requested":args.observation_output.is_some()
            ,"native_interface_probe":args.native_interface_probe
        }),
        65_536,
    )?;
    let mut events = vec![];
    if args.native_interface_probe {
        let result = (|| -> Result<_> {
            let mut source = OfflinePartition::reopen(request.source, true, &mut events)?;
            let length = source.byte_len();
            let raw = ntfs2refs::ntfs_inspect::inspect(&mut source, length)?;
            let inspection = ntfs2refs::planner::Inspection {
                schema_version: 1,
                source: ntfs2refs::block_io::SourceIdentity {
                    path: source.binding().volume_path()?.into(),
                    length,
                    sha256: String::new(), // diagnostic probe: no full-image digest claimed
                },
                filesystem: ntfs2refs::planner::Filesystem::Ntfs(raw),
            };
            let pin = hex::encode(Sha256::digest(serde_json::to_vec(&inspection)?));
            let request = ntfs2refs::ntfs_attestation::request_for_inspection(
                &inspection,
                &pin,
                source.binding(),
            )?;
            source
                .observe_ntfs_files(&request, &mut events)
                .map_err(Into::into)
        })();
        let success = result.is_ok();
        let report = match result {
            Ok(observation) => {
                serde_json::json!({"schema_version":1,"kind":"native-source-interface-probe-v1","success":true,
                "observation":observation,"full_source_hash_verified":false,"source_admitted":false,"conversion_qualified":false,"events":events})
            }
            Err(error) => {
                serde_json::json!({"schema_version":1,"kind":"native-source-interface-probe-v1","success":false,
                "error":format!("{error:#}"),"full_source_hash_verified":false,"source_admitted":false,"conversion_qualified":false,"events":events})
            }
        };
        save(&args.output, &report, 32 * 1024 * 1024)?;
        ensure!(
            success,
            "native interface probe failed; inspect recorded source state"
        );
        return Ok(());
    }
    if let Some(expected) = args.verify_source_sha256 {
        let result = (|| -> Result<_> {
            let mut source = OfflinePartition::reopen(request.source, true, &mut events)?;
            ntfs2refs::ntfs_freeze::revalidate_pin(&mut source, &expected, &mut events)
        })();
        let success = result.is_ok();
        let report = match result {
            Ok(proof) => {
                serde_json::json!({"schema_version":1,"kind":"ntfs-source-revalidation-v1",
                "success":true,"verification":proof,"events":events,"source_admitted":false,
                "conversion_qualified":false})
            }
            Err(error) => {
                serde_json::json!({"schema_version":1,"kind":"ntfs-source-revalidation-v1",
                "success":false,"error":format!("{error:#}"),"events":events,
                "source_admitted":false,"conversion_qualified":false})
            }
        };
        save(&args.output, &report, 1024 * 1024)?;
        ensure!(
            success,
            "source revalidation failed; exclusion remains unchanged"
        );
        return Ok(());
    }
    let mut phase = "open-source";
    let result = (|| -> Result<_> {
        let mut source = if args.reopen {
            OfflinePartition::reopen(request.source, true, &mut events)?
        } else {
            OfflinePartition::isolate(request.source, true, &mut events)?
        };
        phase = "capture-post-exclusion-basis";
        let basis = ntfs2refs::ntfs_freeze::FrozenBasis::capture(&mut source, &mut events)?;
        let observation_hash = if let Some(output) = &args.observation_output {
            phase = "observe-protected-source-and-revalidate";
            let observed = basis.observe_native(&mut source, &mut events)?;
            let assessment = observed.assessment(&basis)?;
            phase = "persist-live-source-observation";
            Some(save(
                output,
                &serde_json::json!({"schema_version":1,"kind":"live-frozen-ntfs-observation-v1",
                "observation":observed,"assessment":assessment,"source_admitted":false,
                "certificate_issued":false,"conversion_qualified":false}),
                32 * 1024 * 1024,
            )?)
        } else {
            phase = "revalidate-actual-source";
            basis.revalidate(&mut source, &mut events)?;
            None
        };
        phase = "persist-inspection";
        let inspection_hash = save(
            args.inspection_output
                .as_ref()
                .context("missing inspection output")?,
            basis.inspection(),
            64 * 1024 * 1024,
        )?;
        phase = "complete-source-remains-offline-read-only";
        Ok((
            basis,
            inspection_hash,
            source.native_bytes_read,
            observation_hash,
        ))
    })();
    let success = result.is_ok();
    let report = match result {
        Ok((basis, hash, bytes, observation_hash)) => {
            serde_json::json!({"schema_version":1,"kind":"ntfs-source-freeze-v1",
            "success":true,"phase":phase,"basis":basis.evidence(),"inspection_sha256":hash,
            "native_bytes_read":bytes,"native_bytes_written":0,"events":events,"observation_sha256":observation_hash,
            "source_admitted":false,"conversion_qualified":false})
        }
        Err(error) => serde_json::json!({"schema_version":1,"kind":"ntfs-source-freeze-v1",
            "success":false,"phase":phase,"error":format!("{error:#}"),"events":events,
            "source_admitted":false,"conversion_qualified":false}),
    };
    save(&args.output, &report, 1024 * 1024)?;
    ensure!(
        success,
        "freeze/inspection failed; inspect recorded native state before continuing"
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Native source freeze requires Windows.");
    std::process::exit(2);
}
