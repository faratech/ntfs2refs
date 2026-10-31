//! Lab-only full logical-content baseline of an already frozen NTFS source.
//! No isolator, writer, source assessment/certificate, journal or replay API.
use crate::{
    general_qualification, ntfs_admission::ResourceProfile, ntfs_attestation, ntfs_inspect,
    ntfs_source_view, shadow_tree,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{GeneralFrozenPartition, general_layout::GeneralDiskBinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize)]
pub struct InputPin {
    pub path: PathBuf,
    pub sha256: String,
}
pub struct CaptureInput {
    pub binding: InputPin,
    pub directory_growth: InputPin,
    pub original_fixture: InputPin,
    pub historical_full_expectation: InputPin,
    pub source_checkpoint: String,
}
#[derive(Deserialize)]
struct Fixture {
    files: usize,
    directories: usize,
    total_bytes: serde_json::Number,
    manifest: Vec<FixtureFile>,
}
#[derive(Deserialize)]
struct FixtureFile {
    path: String,
    length: u64,
    sha256: String,
}

fn ordinary(path: &Path, existing: bool) -> Result<()> {
    let text = path.to_str().context("non-Unicode lab path")?;
    ensure!(
        text.starts_with("C:\\ntfs2refs\\")
            && !text[3..].contains(':')
            && !text.contains('/')
            && !text.contains("..")
            && !text.ends_with([' ', '.']),
        "ordinary owned C lab path required"
    );
    for (index, p) in path.ancestors().enumerate() {
        if index == 0 && !existing {
            ensure!(!p.exists(), "fresh baseline output required");
            continue;
        }
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.file_attributes() & 0x400 == 0 && (index == 0 || m.is_dir()),
            "reparse or non-directory lab ancestry refused"
        );
    }
    Ok(())
}
fn held(pin: &InputPin, maximum: u64) -> Result<(File, Vec<u8>)> {
    ordinary(&pin.path, true)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&pin.path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.file_attributes() & 0x400 == 0 && m.len() > 0 && m.len() <= maximum,
        "bounded ordinary pinned input required"
    );
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len() && hex::encode(Sha256::digest(&bytes)) == pin.sha256,
        "baseline input length or SHA differs"
    );
    Ok((file, bytes))
}
fn source_binding(binding: &GeneralDiskBinding) -> Result<()> {
    binding.validate()?;
    ensure!(
        binding.disk_number == 1
            && binding.identity.partition_number == 2
            && binding
                .identity
                .disk_guid
                .eq_ignore_ascii_case("1b191872-c372-41ee-a416-e18863996f54")
            && binding
                .identity
                .partition_guid
                .eq_ignore_ascii_case("f06075a8-67a2-46b9-8fac-4af4da809617")
            && binding.identity.partition_bytes == 52 * 1024 * 1024 * 1024,
        "exact mixed F source binding required"
    );
    Ok(())
}
fn key(path: &[String], name: &[u16]) -> (Vec<String>, Vec<u16>) {
    (path.to_vec(), name.to_vec())
}

pub fn capture(input: CaptureInput, output: &Path) -> Result<serde_json::Value> {
    n2r_win32::layout::guid_bytes(&input.source_checkpoint)?;
    ordinary(output, false)?;
    let (_binding_file, binding_bytes) = held(&input.binding, 16384)?;
    let (_growth_file, growth_bytes) = held(&input.directory_growth, 64 * 1024 * 1024)?;
    let (_fixture_file, fixture_bytes) = held(&input.original_fixture, 1024 * 1024)?;
    let (_reference_file, reference_bytes) =
        held(&input.historical_full_expectation, 16 * 1024 * 1024)?;
    let binding: GeneralDiskBinding = serde_json::from_slice(&binding_bytes)?;
    source_binding(&binding)?;
    let growth: serde_json::Value = serde_json::from_slice(&growth_bytes)?;
    ensure!(
        growth["schema_version"] == 1
            && growth["kind"] == "ntfs-directory-object-envelope-fixture"
            && growth["success"] == true
            && growth["source"]["binding"] == serde_json::to_value(&binding)?
            && growth["original_fixture_manifest_sha256"] == input.original_fixture.sha256
            && growth["created_directories"] == 151
            && growth["created_payload_files"] == 0
            && growth["originals_verified"] == 808
            && growth["original_payload_writes"] == 0
            && growth["original_payload_bytes_read"] == 0
            && growth["extent_moves"] == 0,
        "complete metadata-only directory growth receipt required"
    );
    let created: Vec<Vec<String>> = serde_json::from_value(growth["created_paths"].clone())?;
    let created_set: BTreeSet<_> = created.iter().cloned().collect();
    ensure!(
        created.len() == 151
            && created_set.len() == 151
            && created.iter().all(|p| !p.is_empty()
                && p.iter().all(|c| !c.is_empty()
                    && !matches!(c.as_str(), "." | "..")
                    && !c.contains(['\\', '/', ':']))),
        "complete unique created directory paths required"
    );
    let fixture: Fixture = serde_json::from_slice(&fixture_bytes)?;
    ensure!(
        fixture.files == 808
            && fixture.directories == 120
            && fixture.total_bytes.as_f64() == Some(9885781381.0)
            && fixture.manifest.len() == 808,
        "original complete mixed fixture reference required"
    );
    let total = fixture.manifest.iter().try_fold(0u64, |sum, file| {
        sum.checked_add(file.length)
            .context("fixture byte sum overflow")
    })?;
    ensure!(
        total == 9885781381,
        "exact original fixture entry byte sum differs"
    );
    let historical: shadow_tree::ExpectedTree = serde_json::from_slice(&reference_bytes)?;
    historical.validate_with_resource_profile(ResourceProfile::ExperimentalStreamingTreeV2)?;
    ensure!(
        !historical.has_extent_only_streams(),
        "historical content reference must contain actual full digests"
    );
    fs::create_dir(output)?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(binding.clone(), &mut events)?;
    let before = source.state(&mut events)?;
    ensure!(
        before.disk_attributes == 3,
        "source must already be offline read-only"
    );
    let attempted = (|| -> Result<serde_json::Value> {
        let raw = ntfs_inspect::inspect_with_limits(
            &mut source,
            binding.identity.partition_bytes,
            ntfs_inspect::limits_for_resource_profile(
                ResourceProfile::ExperimentalObjectEnvelopeV3(None),
            ),
        )?;
        let inspection_pin = hex::encode(Sha256::digest(serde_json::to_vec(&raw)?));
        let resources = ResourceProfile::ExperimentalObjectEnvelopeV3(None)
            .admit_inspection(&raw, &inspection_pin)?;
        let admission = resources
            .count_admission()?
            .context("complete source count admission absent")?;
        ensure!(
            raw.geometry.cluster_size == 65536
                && admission.files == 811
                && admission.directories > 256,
            "fresh complete NTFS64K source must exceed the old directory split and retain811 files"
        );
        let request = ntfs_attestation::request_for_general_inspection_with_profile(
            &raw,
            &inspection_pin,
            &binding,
            resources
                .native_profile()
                .context("native profile absent")?,
        )?;
        ensure!(
            request.extent_identity_streams.is_empty(),
            "full baseline must not request content elisions"
        );
        let observed = source.observe_ntfs_files_single_content_pass(&request, &mut events)?;
        let native = observed.report();
        ensure!(
            native.content_passes == 1,
            "exactly one actual native content pass required"
        );
        let comparison = ntfs_attestation::compare(&raw, &inspection_pin, native)?;
        let views = ntfs_source_view::diagnose(&raw, &inspection_pin, native)?;
        ensure!(
            views.all_user_views_compatible,
            "fresh raw/native source metadata, namespace or security differs"
        );
        let mut tree = shadow_tree::derive_ordinary_with_resource_profile(&raw, resources)?;
        tree.bind_security_views(&views)?;
        let expected = shadow_tree::ExpectedTree::from(&tree);
        expected.validate_with_resource_profile(resources)?;
        ensure!(
            !expected.has_extent_only_streams(),
            "full fresh source baseline cannot omit content digests"
        );
        let mut content = BTreeMap::new();
        let mut current_objects = BTreeMap::new();
        let logical = native
            .logical_data
            .as_ref()
            .context("actual native logical reads absent")?;
        let mut matched = 0usize;
        for object in &expected.objects {
            ensure!(
                current_objects
                    .insert(object.path.clone(), object)
                    .is_none(),
                "duplicate canonical source path"
            );
            if object.directory {
                continue;
            }
            let files: Vec<_> = logical
                .files
                .iter()
                .filter(|f| {
                    f.identity.record_number == object.record_number
                        && f.identity.sequence_number == object.sequence_number
                })
                .collect();
            ensure!(
                files.len() == 1,
                "native content identity absent or duplicate"
            );
            for stream in object.data_streams() {
                let digest = stream
                    .sha256
                    .context("fresh complete raw stream digest absent")?;
                let native_streams: Vec<_> = files[0]
                    .before
                    .iter()
                    .filter(|s| s.name_utf16 == stream.name_utf16)
                    .collect();
                ensure!(
                    native_streams.len() == 1,
                    "native source stream absent or duplicate"
                );
                let actual = &native_streams[0];
                ensure!(
                    actual.logical_size == stream.length
                        && actual.outcome.status == n2r_win32::logical_hash::Status::Complete
                        && actual.outcome.bytes_read == stream.length
                        && actual.outcome.eof_confirmed
                        && actual.outcome.sha256.as_deref() == Some(digest),
                    "actual complete native content differs from full raw source"
                );
                ensure!(content.insert(key(&object.path,stream.name_utf16),serde_json::json!({"record_number":object.record_number,"sequence_number":object.sequence_number,"path":object.path,"name_utf16":stream.name_utf16,"length":stream.length,"actual_raw_content_digest":digest,"actual_native_content_digest":actual.outcome.sha256,"native_eof_confirmed":true})).is_none(),"duplicate fresh source content key");
                matched += 1;
            }
        }
        ensure!(matched == 811, "complete811 fresh source streams required");
        for path in &created {
            let object = current_objects
                .get(path)
                .context("created directory absent from fresh raw/native canonical tree")?;
            ensure!(
                object.directory && object.length == 0 && object.named_streams.is_empty(),
                "created directory unexpectedly has DATA payload"
            );
        }
        let mut original_rows = Vec::new();
        let mut seen = BTreeSet::new();
        for file in &fixture.manifest {
            ensure!(
                file.path.starts_with("F:\\")
                    && file.sha256.len() == 64
                    && file.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "historical fixture path/hash invalid"
            );
            let path: Vec<String> = file.path[3..].split('\\').map(str::to_owned).collect();
            ensure!(seen.insert(path.clone()), "duplicate original fixture path");
            let old: Vec<_> = historical
                .objects
                .iter()
                .filter(|o| o.path == path && !o.directory)
                .collect();
            ensure!(
                old.len() == 1 && old[0].length == file.length,
                "historical full content reference lacks original fixture path/length"
            );
            let actual = content
                .get(&key(&path, &[]))
                .context("original fixture file absent from fresh full source")?;
            ensure!(
                actual["length"] == file.length
                    && actual["actual_raw_content_digest"]
                        == old[0]
                            .sha256
                            .as_deref()
                            .context("historical full digest absent")?,
                "original user-file fresh content differs from pinned historical actual digest"
            );
            original_rows.push(serde_json::json!({"path":path,"length":file.length,"historical_fixture_sha256_expectation":file.sha256,"historical_actual_xxh3_128":old[0].sha256,"fresh_actual_xxh3_128":actual["actual_raw_content_digest"],"fresh_sha256_claimed":false}));
        }
        let after = source.state(&mut events)?;
        ensure!(
            after == before && after.disk_attributes == 3,
            "baseline source exclusion or identity changed"
        );
        let mut artifacts = BTreeMap::new();
        for (name, value) in [
            (
                "source-basis.json",
                serde_json::json!({"schema_version":1,"kind":"lab-full-source-raw-basis","binding":binding,"canonical_inspection_sha256":inspection_pin,"ntfs":raw,"before":before,"after":after,"source_admitted":false,"execution_authorized":false}),
            ),
            ("native-source.json", serde_json::to_value(native)?),
            ("source-views.json", serde_json::to_value(&views)?),
            ("strict-comparison.json", serde_json::to_value(&comparison)?),
            ("expectation.json", serde_json::to_value(&expected)?),
            (
                "independent-content.json",
                serde_json::json!({"success":true,"scope":"fresh-full-raw-and-independent-native-source-content-v1","content_algorithm":"xxh3-128","actual_raw_logical_passes":1,"actual_native_content_passes":1,"native_after_content_capture_is_mirror":true,"streams":matched,"original_fixture_files_matched":808,"fresh_sha256_of_original_files_claimed":false,"streams_actual":content.values().collect::<Vec<_>>(),"original_user_content_reference":original_rows}),
            ),
            ("observation-events.json", serde_json::to_value(&events)?),
        ] {
            let sha = general_qualification::save(output, name, &value)?;
            artifacts.insert(name,serde_json::json!({"path":output.join(name),"bytes":fs::metadata(output.join(name))?.len(),"sha256":sha}));
        }
        let manifest = serde_json::json!({"schema_version":1,"kind":"lab-full-source-content-baseline-v1","success":true,"source_checkpoint":input.source_checkpoint,"source_binding":binding,"directory_growth_receipt":input.directory_growth,"original_fixture":input.original_fixture,"historical_full_content_reference":input.historical_full_expectation,"source_resource_profile":resources,"source_inspection_sha256":inspection_pin,"objects":expected.objects.len(),"files":admission.files,"directories":admission.directories,"data_streams":admission.data_streams,"created_directories":created.len(),"raw_logical_hash_bytes":raw.stream_hash_bytes,"native_logical_read_audit":native.logical_data.as_ref().map(|l|&l.audit),"actual_raw_logical_passes":1,"actual_native_content_passes":1,"actual_fresh_stream_hashes_matched":matched,"original808_content_matches_historical_actual_xxh3":true,"historical_fixture_sha256_rehashed":false,"source_before":before,"source_after":after,"source_payload_writes":0,"extent_moves":0,"source_admitted":false,"certificate_issued":false,"conversion_authorized":false,"replay_authorized":false,"full_image_sha256_computed":false,"artifacts":artifacts});
        general_qualification::save(output, "baseline-manifest.json", &manifest)?;
        Ok(manifest)
    })();
    if let Err(error) = &attempted {
        let state = source.state(&mut events).ok();
        let _ = general_qualification::save(
            output,
            "baseline-failed.json",
            &serde_json::json!({"success":false,"kind":"lab-full-source-content-baseline-failure","error":format!("{error:#}"),"actual_after":state,"source_payload_writes":0,"source_admitted":false,"conversion_authorized":false,"automatic_retry":false}),
        );
    }
    attempted
}
