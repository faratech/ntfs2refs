//! One owning-machine source/target qualification run. Keeps the actual freeze
//! witness alive through native reconstruction and certificate issuance.
use crate::{
    general_shadow, general_source_admission, lab_reconstruct, ntfs_attestation, ntfs_backup,
    ntfs_inspect, ntfs_log, shadow_tree,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent, general_layout::GeneralSourceShadowBinding,
    journal_file::JournalProfile,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufWriter, Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[allow(
    dead_code,
    reason = "composite orchestration awaits native qualification before CLI exposure"
)]
mod composite;
pub(crate) use composite::{
    QualifiedCompositeTree, prepare_composite_existing, prepare_composite_fresh,
    prepare_composite_fresh_selected,
};
mod compact_construction;
pub use compact_construction::CompactConstructionBudget;

const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Count and hash the serializer's exact output without retaining an artifact.
/// The first pass is a sink, so an oversize value still refuses before the
/// destination is opened. The second pass writes the same bytes through one
/// fixed-size buffer and must match the first pass before returning its pin.
struct BoundedJson<W> {
    output: W,
    bytes: usize,
    limit: usize,
    hash: Sha256,
}

impl<W: Write> BoundedJson<W> {
    fn new(output: W, limit: usize) -> Self {
        Self {
            output,
            bytes: 0,
            limit,
            hash: Sha256::new(),
        }
    }
}

impl<W: Write> Write for BoundedJson<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let needed = self.bytes.checked_add(bytes.len()).ok_or_else(|| {
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
        self.output.write_all(bytes)?;
        self.hash.update(bytes);
        self.bytes = needed;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

/// Apply the artifact's existing pretty-JSON byte ceiling without allocating
/// its complete serialization. This reads only the supplied in-memory value.
pub(crate) fn serialized_len_bounded(value: &impl Serialize, limit: usize) -> Result<usize> {
    let mut output = BoundedJson::new(io::sink(), limit);
    serde_json::to_writer_pretty(&mut output, value)?;
    Ok(output.bytes)
}

pub(crate) fn save_bounded(
    root: &Path,
    name: &str,
    value: &impl Serialize,
    limit: usize,
) -> Result<String> {
    let mut counted = BoundedJson::new(io::sink(), limit);
    serde_json::to_writer_pretty(&mut counted, value)?;
    let expected_bytes = counted.bytes;
    let expected_hash = counted.hash.finalize();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(root.join(name))?;
    let mut output = BoundedJson::new(BufWriter::with_capacity(64 * 1024, file), expected_bytes);
    serde_json::to_writer_pretty(&mut output, value)?;
    output.flush()?;
    let actual_hash = output.hash.finalize();
    ensure!(
        output.bytes == expected_bytes && actual_hash == expected_hash,
        "qualification artifact serialization changed between sizing and writing"
    );
    output.output.get_ref().sync_all()?;
    Ok(hex::encode(actual_hash))
}

pub(crate) fn canonical_json_sha256(value: &impl Serialize) -> Result<String> {
    // Compact serialization is the same byte stream used by to_vec, without
    // its additional inventory-sized allocation. This reads no device bytes.
    let mut output = BoundedJson::new(io::sink(), usize::MAX);
    serde_json::to_writer(&mut output, value)?;
    Ok(hex::encode(output.hash.finalize()))
}

/// Hash the exact pretty-JSON artifact bytes without retaining a serialization.
/// Artifact writers and callers still enforce their existing byte ceilings.
pub(crate) fn pretty_json_sha256(value: &impl Serialize) -> Result<String> {
    let mut output = BoundedJson::new(io::sink(), usize::MAX);
    serde_json::to_writer_pretty(&mut output, value)?;
    Ok(hex::encode(output.hash.finalize()))
}

pub(crate) fn save(root: &Path, name: &str, value: &impl Serialize) -> Result<String> {
    save_bounded(root, name, value, MAX_ARTIFACT_BYTES)
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

/// One original online-to-frozen source assessment, retained in memory. No
/// reopening or deserialized report can manufacture its transaction context.
struct PreparedSourceContext {
    resources: crate::ntfs_admission::ResourceProfile,
    source: GeneralFrozenPartition,
    raw: ntfs_inspect::NtfsInspection,
    assessment: general_source_admission::LiveAssessment,
    tree: shadow_tree::Tree,
    expected: shadow_tree::ExpectedTree,
    expected_sha256: String,
    source_hash: String,
    mount_paths: n2r_win32::MountPathObservation,
    source_label: n2r_win32::volume_label::SourceLabel,
}

/// Shared unchanged source sequence for full-shadow and composite targets.
/// The caller creates the fresh output and validates the pair/resource budget.
/// How the frozen source is bound across its native observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceDigest {
    /// Complete source image SHA-256 (the composite path).
    WholeImage,
    /// Framed digest of the NTFS-allocated ranges only (allocation-bounded mode,
    /// under the user's extended allocation guarantee).
    NtfsAllocated,
}

fn prepare_source_context(
    pair: &GeneralSourceShadowBinding,
    output: &Path,
    resources: crate::ntfs_admission::ResourceProfile,
    events: &mut Vec<NativeEvent>,
    phase: &mut &'static str,
    after_source_freeze: impl FnOnce(&GeneralFrozenPartition, &str, &str) -> Result<()>,
    digest_kind: SourceDigest,
    verification_policy: crate::verification_policy::VerificationPolicy,
) -> Result<PreparedSourceContext> {
    // Every newly issued source certificate needs affirmative VSS evidence,
    // independently of scratch policy or full/extent content verification.
    // Hosted storage is queried while the source is still online; only source
    // presence can be queried later inside the existing protected native view.
    *phase = "source-vss-catalog-before-freeze";
    let source_volume = format!("{}\\", pair.source.volume_path()?);
    let vss_storage_before = n2r_win32::vss_observation::observe_catalog(&source_volume)?;
    save(output, "source-vss-before-freeze.json", &vss_storage_before)?;
    vss_storage_before.require_observed_catalog_clear()?;
    ensure!(
        vss_storage_before
            .source_volume_guid
            .eq_ignore_ascii_case(&source_volume),
        "pre-freeze VSS storage observation differs from the source route"
    );
    *phase = "source-freeze";
    let mut online = n2r_win32::GeneralPartitionReader::open(pair.source.clone(), events)?;
    let mut boot = [0; 512];
    online.read_exact(&mut boot)?;
    let geometry = ntfs_inspect::inspect_boot_sector(&boot, online.byte_len())?;
    ensure!(
        resources.supports_source_geometry(&geometry),
        "source geometry exceeds the supported qualification profile"
    );
    online.revalidate_route(events)?;
    drop(online);
    let mount_paths = n2r_win32::capture_mount_paths_general(pair.source.clone(), events)?;
    save(output, "source-mount-paths.json", &mount_paths)?;
    let source_label = n2r_win32::volume_label::capture_source_label(pair.source.clone())?;
    save(output, "source-label.json", &source_label)?;
    save(output, "preflight-events.json", &events)?;
    events.clear();
    let mut source = GeneralFrozenPartition::isolate_observed_ntfs(pair.source.clone(), events)?;
    let length = source.byte_len();
    // The allocated ranges come from the inspection, so that mode inspects the
    // frozen source first, recording what it reads. Target verification later
    // rechecks the allocated-range digest instead of repeating the inspection,
    // which holds only if the inspection read nothing outside those ranges.
    // The whole-image path keeps its original order.
    let (early_raw, inspection_reads) = match digest_kind {
        SourceDigest::WholeImage => (None, None),
        SourceDigest::NtfsAllocated => {
            let mut recorder = ntfs_inspect::ReadRecorder::new(&mut source)?;
            let raw = ntfs_inspect::inspect_with_limits_and_policy(
                &mut recorder,
                length,
                ntfs_inspect::limits_for_resource_profile(resources),
                verification_policy,
            )?;
            (Some(raw), Some(recorder.ranges()))
        }
    };
    let fingerprint = match &early_raw {
        Some(raw) => Some(
            crate::source_fingerprint::SourceFingerprint::for_inspection(
                raw,
                length,
                verification_policy,
            )?,
        ),
        None => None,
    };
    if let (Some(fingerprint), Some(reads)) = (&fingerprint, &inspection_reads) {
        fingerprint.validate_inspection_reads(reads)?;
    }
    let source_hash = match &fingerprint {
        None => hex::encode(lab_reconstruct::hash_range_with_resource_profile(
            &mut source,
            0,
            length,
            resources,
        )?),
        Some(fingerprint) => fingerprint.hash(&mut source)?,
    };
    let allocated = early_raw
        .as_ref()
        .map(|raw| raw.allocated_byte_ranges(length))
        .transpose()?;
    let mut frozen_identity = serde_json::json!({"schema_version":1,
        "kind":"observed-frozen-source-identity","binding":source.binding(),"source_sha256":source_hash,
        "source_digest_kind":digest_kind,"source_digest_ranges":allocated.as_ref().map(Vec::len),
        "source_digest_bytes":allocated.as_ref().map(|ranges| ranges.iter().map(|range| range.1).sum::<u64>()),
        "inspection_read_ranges":inspection_reads.as_ref().map(Vec::len),
        "inspection_reads_within_digest":inspection_reads.as_ref().map(|_| true),
        "state":source.state(events)?,"freeze_observation":source.freeze_observation(),"source_payload_writes":0});
    if verification_policy.is_fast() {
        let basis = fingerprint
            .as_ref()
            .context("fast source fingerprint absent")?;
        frozen_identity["source_digest_kind"] = serde_json::to_value(basis.kind())?;
        frozen_identity["source_fingerprint"] = serde_json::to_value(basis.report())?;
        frozen_identity["source_digest_ranges"] = serde_json::Value::Null;
        frozen_identity["source_digest_bytes"] = serde_json::Value::Null;
        frozen_identity["verification_policy"] = serde_json::to_value(verification_policy)?;
        frozen_identity["inspection_reads_within_digest"] = serde_json::Value::Bool(false);
        frozen_identity["inspection_reads_within_digest_or_explicit_payload"] =
            serde_json::Value::Bool(true);
    }
    save_source_frozen_then(output, &frozen_identity, |artifact_sha256| {
        after_source_freeze(&source, &source_hash, artifact_sha256)
    })?;
    let raw = match early_raw {
        Some(raw) => raw,
        None => ntfs_inspect::inspect_with_limits(
            &mut source,
            length,
            ntfs_inspect::limits_for_resource_profile(resources),
        )?,
    };
    let source_label_frozen =
        crate::source_volume_label::verify(&mut source, &raw, source_label.label())?;
    save(output, "source-label-frozen.json", &source_label_frozen)?;
    let pin = canonical_json_sha256(&raw)?;
    let resources = match digest_kind {
        SourceDigest::NtfsAllocated => resources.admit_inspection_paged(&raw, &pin)?,
        SourceDigest::WholeImage => resources.admit_inspection(&raw, &pin)?,
    };
    if let Some(admission) = resources.count_admission()? {
        save(
            output,
            "tree-resource-admission.json",
            &serde_json::json!({"admission":admission,"source_admitted":false,"execution_authorized":false}),
        )?;
    }
    let backups = ntfs_backup::verify(&mut source, length, &raw)?;
    let log = ntfs_log::verify(&mut source, &raw)?;
    save(
        output,
        "source-basis.json",
        &serde_json::json!({"source_sha256":source_hash,
        "canonical_inspection_sha256":pin,"ntfs":raw,"backups":backups,"log_restart":log,
        "freeze_observation":source.freeze_observation(),"events":events}),
    )?;
    *phase = "source-observation";
    let request = ntfs_attestation::request_for_fresh_general_inspection(
        &raw,
        &pin,
        source.binding(),
        resources.native_profile(),
        verification_policy,
    )?;
    // In the allocation-bounded mode the allocated-range digest brackets this
    // observation over the frozen, read-only source, so one content pass is
    // enough; the whole-image path keeps both passes.
    let observed = match digest_kind {
        SourceDigest::WholeImage => source.observe_ntfs_files_with_vss(&request, events)?,
        SourceDigest::NtfsAllocated => {
            source.observe_ntfs_files_single_content_pass_with_vss(&request, events)?
        }
    };
    let observation = observed
        .vss_observation()
        .context("fresh source admission requires VSS evidence from the protected native lease")?;
    save(output, "source-vss-after-freeze.json", observation)?;
    observation.require_observed_snapshot_absence()?;
    ensure!(
        vss_storage_before.same_source_and_provider_inventory(observation),
        "VSS source/provider inventory changed across frozen admission"
    );
    save(output, "native-source.json", observed.report())?;
    let assessment = match &fingerprint {
        None => general_source_admission::assess(
            &mut source,
            &raw,
            &pin,
            &source_hash,
            &backups,
            Some(&log),
            &observed,
            events,
        )?,
        Some(fingerprint) => general_source_admission::assess_with_source_digest(
            &mut source,
            &raw,
            &pin,
            &source_hash,
            &backups,
            Some(&log),
            &observed,
            events,
            |source, _| fingerprint.hash(source),
        )?,
    };
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
    Ok(PreparedSourceContext {
        resources,
        source,
        raw,
        assessment,
        tree,
        expected,
        expected_sha256,
        source_hash,
        mount_paths,
        source_label,
    })
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
