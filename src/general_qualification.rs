//! One owning-machine source/target qualification run. Keeps the actual freeze
//! witness alive through native reconstruction and certificate issuance.
use crate::{
    general_shadow, general_source_admission, general_target_preservation, lab_reconstruct,
    ntfs_attestation, ntfs_backup, ntfs_inspect, ntfs_log, shadow_tree,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent, general_layout::GeneralSourceShadowBinding,
    journal_file::JournalProfile, shadow_native,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Bound serialization before opening the destination. `to_vec_pretty` followed
/// by a length check can allocate an arbitrarily large buffer before refusing.
struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let needed = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "qualification artifact exceeds bound",
            )
        })?;
        if needed > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "qualification artifact exceeds bound",
            ));
        }
        if needed > self.bytes.capacity() {
            let desired = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(4096)
                .max(needed)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(desired - self.bytes.len())
                .map_err(|_| io::Error::other("qualification artifact allocation failed"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn save_bounded(root: &Path, name: &str, value: &impl Serialize, limit: usize) -> Result<String> {
    let mut output = BoundedJson {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer_pretty(&mut output, value)?;
    let bytes = output.bytes;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(root.join(name))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

pub(crate) fn save(root: &Path, name: &str, value: &impl Serialize) -> Result<String> {
    save_bounded(root, name, value, MAX_ARTIFACT_BYTES)
}

pub fn qualify(pair: GeneralSourceShadowBinding, output: &Path) -> Result<()> {
    prepare(pair, output, false).map(drop)
}

pub fn qualify_existing(pair: GeneralSourceShadowBinding, output: &Path) -> Result<()> {
    prepare(pair, output, true).map(drop)
}

pub(crate) struct QualifiedTree {
    pub source: GeneralFrozenPartition,
    pub target: GeneralFrozenPartition,
    pub certificate: general_source_admission::SourceCertificate,
    pub comparison: crate::retained_compare::RetainedCompareRequest,
    pub expected: Vec<u8>,
    pub mount_paths: n2r_win32::MountPathObservation,
    pub source_label: n2r_win32::volume_label::SourceLabel,
}

pub(crate) fn create_output(output: &Path) -> Result<()> {
    let path = output
        .to_str()
        .context("qualification output must be Unicode")?;
    let system_root = std::env::var("SystemRoot")?;
    ensure!(
        path.len() <= 512
            && path.get(..3).is_some_and(|prefix| system_root
                .get(..3)
                .is_some_and(|root| prefix.eq_ignore_ascii_case(root)))
            && !path[3..].contains(':')
            && !path.contains(['/', '\0'])
            && !path.contains("..")
            && !output.exists(),
        "fresh OS-volume output required"
    );
    let mut parents: Vec<_> = output.ancestors().skip(1).collect();
    parents.reverse();
    for ancestor in parents {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(ancestor)?,
            Err(error) => return Err(error.into()),
        }
        let meta = fs::symlink_metadata(ancestor)?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "ordinary output ancestry required"
        );
    }
    fs::create_dir(output)?;
    Ok(())
}

pub(crate) fn prepare(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    verify_existing: bool,
) -> Result<QualifiedTree> {
    prepare_with_budget(pair, output, verify_existing, 256 * 1024 * 1024)
}

pub(crate) fn prepare_with_budget(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    verify_existing: bool,
    max_change_bytes: u64,
) -> Result<QualifiedTree> {
    prepare_with_budget_and_source_freeze_hook(
        pair,
        output,
        verify_existing,
        max_change_bytes,
        JournalProfile::LegacyV1,
        crate::ntfs_admission::ResourceProfile::AlphaV1,
        |_, _, _| Ok(()),
    )
}

/// The laboratory may stop after the real durable source-freeze artifact.
/// The callback borrows the actual frozen handle and receives only pins from
/// the current native run; no deserialized completion flag enters this path.
pub(crate) fn prepare_with_budget_and_source_freeze_hook(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    verify_existing: bool,
    max_change_bytes: u64,
    profile: JournalProfile,
    resources: crate::ntfs_admission::ResourceProfile,
    after_source_freeze: impl FnOnce(&GeneralFrozenPartition, &str, &str) -> Result<()>,
) -> Result<QualifiedTree> {
    pair.validate()?;
    ensure!(
        (1..=profile.max_changed_bytes()).contains(&max_change_bytes)
            && max_change_bytes <= pair.source.identity.partition_bytes,
        "qualification changed-byte budget differs"
    );
    // Qualification artifacts stay on the Windows OS volume, which both
    // dedicated data-disk routes explicitly exclude.
    create_output(output)?;
    save(
        output,
        "intent.json",
        &serde_json::json!({"schema_version":1,"kind":"live-general-qualification-intent",
        "pair":pair,"verify_existing":verify_existing,"max_change_bytes":max_change_bytes,
        "source_payload_writes_authorized":false,"source_admitted":false}),
    )?;
    let mut phase = "source-freeze";
    let attempted = (|| -> Result<QualifiedTree> {
        let mut events = Vec::<NativeEvent>::new();
        let mut online = n2r_win32::GeneralPartitionReader::open(pair.source.clone(), &mut events)?;
        let mut boot = [0; 512];
        online.read_exact(&mut boot)?;
        let geometry = ntfs_inspect::inspect_boot_sector(&boot, online.byte_len())?;
        ensure!(
            resources.supports_source_geometry(&geometry),
            "source geometry exceeds the supported qualification profile"
        );
        online.revalidate_route(&mut events)?;
        drop(online);
        let mount_paths = n2r_win32::capture_mount_paths_general(pair.source.clone(), &mut events)?;
        save(output, "source-mount-paths.json", &mount_paths)?;
        let source_label = n2r_win32::volume_label::capture_source_label(pair.source.clone())?;
        save(output, "source-label.json", &source_label)?;
        save(output, "preflight-events.json", &events)?;
        events.clear();
        let mut source =
            GeneralFrozenPartition::isolate_observed_ntfs(pair.source.clone(), &mut events)?;
        let length = source.byte_len();
        let source_hash = hex::encode(lab_reconstruct::hash_range(&mut source, 0, length)?);
        save_source_frozen_then(
            output,
            &serde_json::json!({"schema_version":1,
            "kind":"observed-frozen-source-identity","binding":source.binding(),"source_sha256":source_hash,
            "state":source.state(&mut events)?,"freeze_observation":source.freeze_observation(),"source_payload_writes":0}),
            |artifact_sha256| after_source_freeze(&source, &source_hash, artifact_sha256),
        )?;
        let raw = ntfs_inspect::inspect_with_limits(
            &mut source,
            length,
            ntfs_inspect::limits_for_resource_profile(resources),
        )?;
        let source_label_frozen =
            crate::source_volume_label::verify(&mut source, &raw, source_label.label())?;
        save(output, "source-label-frozen.json", &source_label_frozen)?;
        let pin = hex::encode(Sha256::digest(serde_json::to_vec(&raw)?));
        let backups = ntfs_backup::verify(&mut source, length, &raw)?;
        let log = ntfs_log::verify(&mut source, &raw)?;
        save(
            output,
            "source-basis.json",
            &serde_json::json!({"source_sha256":source_hash,
            "canonical_inspection_sha256":pin,"ntfs":raw,"backups":backups,"log_restart":log,
            "freeze_observation":source.freeze_observation(),"events":events}),
        )?;
        phase = "source-observation";
        let request = if let Some(native_profile) = resources.native_profile() {
            ntfs_attestation::request_for_general_inspection_with_profile(
                &raw,
                &pin,
                source.binding(),
                native_profile,
            )?
        } else {
            ntfs_attestation::request_for_general_inspection(&raw, &pin, source.binding())?
        };
        let observed = source.observe_ntfs_files(&request, &mut events)?;
        save(output, "native-source.json", observed.report())?;
        let mut assessment = general_source_admission::assess(
            &mut source,
            &raw,
            &pin,
            &source_hash,
            &backups,
            Some(&log),
            &observed,
            &mut events,
        )?;
        save(output, "source-assessment.json", &assessment)?;
        save(output, "source-events.json", &events)?;
        events.clear();
        let refusals: Vec<_> = assessment
            .assessment
            .gates
            .iter()
            .filter(|g| {
                g.code != "security_timestamp_preservation"
                    && g.code != "target_resource_profile_support"
                    && !g.satisfied
            })
            .map(|g| g.code.clone())
            .collect();
        ensure!(
            refusals.is_empty(),
            "source is not eligible for target qualification: {refusals:?}"
        );
        let views = assessment
            .assessment
            .source_view
            .as_ref()
            .context("live source views absent")?;
        let mut tree = shadow_tree::derive_ordinary_with_resource_profile(&raw, resources)?;
        tree.bind_security_views(views)?;
        let expected = shadow_tree::ExpectedTree::from(&tree);
        expected.validate_with_resource_profile(resources)?;
        let expected_sha256 = save(output, "expectation.json", &expected)?;
        phase = "native-shadow-construction";
        let input = general_shadow::native_inputs(&tree);
        let limits = resources.limits();
        let mut transfer_budget = ntfs_inspect::StreamTransferBudget::new(
            limits.maximum_stream_bytes,
            limits.maximum_logical_bytes,
        )?;
        let mut writer = |index: usize, target: &mut fs::File| -> std::io::Result<()> {
            let object = tree
                .objects
                .get(index)
                .ok_or_else(|| std::io::Error::other("source object index differs"))?;
            let copied = if resources.native_profile().is_some() {
                ntfs_inspect::copy_plain_stream_with_budget(
                    &mut source,
                    &raw,
                    object.record_number,
                    &mut transfer_budget,
                    target,
                )
            } else {
                ntfs_inspect::copy_plain_stream(
                    &mut source,
                    &raw,
                    object.record_number,
                    256 * 1024 * 1024,
                    target,
                )
            }
            .map_err(|e| std::io::Error::other(e.to_string()))?;
            if copied.logical_bytes != object.length
                || Some(&copied.sha256) != object.sha256.as_ref()
            {
                return Err(std::io::Error::other(
                    "source stream changed during construction",
                ));
            }
            Ok(())
        };
        let same = |a: &[u8], b: &[u8]| {
            ntfs_attestation::same_security(a, b).map_err(|e| std::io::Error::other(e.to_string()))
        };
        let native = if verify_existing {
            shadow_native::verify_general_ordinary_with_resource_profile(
                pair.clone(),
                &input,
                same,
                resources.native_profile(),
            )?
        } else {
            shadow_native::run_general_ordinary_streaming_with_resource_profile(
                pair.clone(),
                &input,
                true,
                &mut writer,
                |a, b| {
                    ntfs_attestation::same_security(a, b)
                        .map_err(|e| std::io::Error::other(e.to_string()))
                },
                resources.native_profile(),
            )?
        };
        save(output, "native-shadow.json", &native)?;
        phase = "target-preservation-freeze";
        let (target, proof) = general_target_preservation::verify_and_freeze(
            &mut source,
            &raw,
            &source_hash,
            views,
            pair.clone(),
            max_change_bytes,
            profile,
            resources,
            &mut events,
        )?;
        save(output, "target-preservation.json", &proof)?;
        save(output, "target-events.json", &events)?;
        phase = "source-certificate";
        let certificate = assessment.qualify_target(&raw, &proof)?;
        let certificate_sha256 = save(output, "certificate.json", &certificate)?;
        save(output, "admitted-assessment.json", &assessment)?;
        save(
            output,
            "result.json",
            &serde_json::json!({"schema_version":1,"kind":"live-general-tree-qualification",
            "success":true,"source_admitted":true,"execution_authorized":false,"source_payload_writes":0,
            "source_sha256":source_hash,"expected_tree_sha256":expected_sha256,"certificate_sha256":certificate_sha256,
            "objects":tree.objects.len(),"comparison":proof.comparison(),"source_after":source.state(&mut events)?,
            "target_after":target.state(&mut events)?,"events":events}),
        )?;
        Ok(QualifiedTree {
            source,
            target,
            certificate,
            comparison: proof.comparison().clone(),
            expected: serde_json::to_vec_pretty(&expected)?,
            mount_paths,
            source_label,
        })
    })();
    match attempted {
        Ok(qualified) => Ok(qualified),
        Err(error) => {
            save(
                output,
                "failed.json",
                &serde_json::json!({"schema_version":1,"kind":"live-general-qualification-failure",
            "phase":phase,"error":format!("{error:#}"),"source_payload_writes":0,"execution_authorized":false}),
            )?;
            Err(error)
        }
    }
}

/// Successful return from save includes its durable flush. Keeping the next
/// phase behind this callback makes a failed save or injected stop prevent
/// raw metadata inspection, target construction and journal activation.
fn save_source_frozen_then(
    output: &Path,
    frozen: &impl Serialize,
    after_saved: impl FnOnce(&str) -> Result<()>,
) -> Result<String> {
    let pin = save(output, "source-frozen.json", frozen)?;
    after_saved(&pin)?;
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_serialization_preserves_bytes_and_refuses_before_creating_files() {
        let temporary = tempfile::tempdir().unwrap();
        let value = serde_json::json!({"names":["abc", "a\nb", "😀"], "number": 42});
        let expected = serde_json::to_vec_pretty(&value).unwrap();
        let pin = save_bounded(temporary.path(), "exact.json", &value, expected.len()).unwrap();
        assert_eq!(
            fs::read(temporary.path().join("exact.json")).unwrap(),
            expected
        );
        assert_eq!(pin, hex::encode(Sha256::digest(&expected)));

        let error = save_bounded(
            temporary.path(),
            "too-large.json",
            &value,
            expected.len() - 1,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("qualification artifact exceeds bound"));
        assert!(!temporary.path().join("too-large.json").exists());
    }

    #[test]
    fn fresh_artifact_output_creates_missing_ordinary_parents_and_refuses_reuse() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("missing").join("parents").join("run");
        create_output(&output).unwrap();
        assert!(output.is_dir());
        assert!(create_output(&output).is_err());
        let file = temporary.path().join("file");
        fs::write(&file, b"keep").unwrap();
        assert!(create_output(&file.join("run")).is_err());
        assert_eq!(fs::read(file).unwrap(), b"keep");
    }

    #[test]
    fn source_freeze_hook_observes_durable_artifact_and_its_actual_pin() {
        let temporary = tempfile::tempdir().unwrap();
        let frozen =
            serde_json::json!({"source_sha256":"a".repeat(64),"state":{"disk_attributes":3}});
        let mut hook_called = false;
        let pin = save_source_frozen_then(temporary.path(), &frozen, |pin| {
            let bytes = fs::read(temporary.path().join("source-frozen.json"))?;
            ensure!(hex::encode(Sha256::digest(&bytes)) == pin);
            ensure!(serde_json::from_slice::<serde_json::Value>(&bytes)? == frozen);
            hook_called = true;
            Ok(())
        })
        .unwrap();
        assert!(hook_called);
        assert_eq!(pin.len(), 64);
    }

    #[test]
    fn failed_freeze_save_or_hook_prevents_the_next_phase() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("source-frozen.json"), b"keep").unwrap();
        let mut hook_called = false;
        assert!(
            save_source_frozen_then(temporary.path(), &serde_json::json!({}), |_| {
                hook_called = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!hook_called);
        assert_eq!(
            fs::read(temporary.path().join("source-frozen.json")).unwrap(),
            b"keep"
        );
        let fresh = tempfile::tempdir().unwrap();
        let mut next_phase_started = false;
        let stopped: Result<()> = (|| {
            save_source_frozen_then(fresh.path(), &serde_json::json!({}), |_| {
                anyhow::bail!("controlled source-freeze stop")
            })?;
            next_phase_started = true;
            Ok(())
        })();
        assert!(
            stopped
                .unwrap_err()
                .to_string()
                .contains("source-freeze stop")
        );
        assert!(!next_phase_started);
        assert!(fresh.path().join("source-frozen.json").is_file());
    }
}
