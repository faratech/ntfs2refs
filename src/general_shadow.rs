//! Immutable request shared by general native shadow construction and freeze.
use anyhow::{Context, Result, ensure};
use n2r_win32::general_layout::GeneralSourceShadowBinding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[cfg(windows)]
pub mod source_backed;

/// Capture both descriptor views for the canonical source tree. The returned
/// analysis is diagnostic; source admission separately binds actual image bytes.
pub fn observed_tree(
    source: &mut n2r_win32::GeneralFrozenPartition,
    raw: &crate::ntfs_inspect::NtfsInspection,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<(crate::shadow_tree::Tree, crate::ntfs_source_view::Analysis)> {
    use sha2::{Digest, Sha256};
    let before = source.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "source must remain excluded during descriptor capture"
    );
    let pin = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    let request =
        crate::ntfs_attestation::request_for_general_inspection(raw, &pin, source.binding())?;
    let observed = source.observe_ntfs_files(&request, events)?;
    let views = crate::ntfs_source_view::diagnose(raw, &pin, observed.report())?;
    let mut tree = crate::shadow_tree::derive_ordinary(raw)?;
    tree.bind_security_views(&views)?;
    ensure!(
        source.state(events)? == before,
        "source exclusion changed during descriptor capture"
    );
    Ok((tree, views))
}

/// One native input per file identity. Additional names are namespace links to
/// that input, never extra payload allocations or source-backed routes.
pub fn native_named_streams(
    object: &crate::shadow_tree::Object,
) -> Vec<n2r_win32::shadow_native::NamedStreamInput<'_>> {
    object
        .named_streams
        .iter()
        .map(|stream| n2r_win32::shadow_native::NamedStreamInput {
            name_utf16: &stream.name_utf16,
            sparse: stream.sparse.as_ref(),
            expected_length: stream.length,
            expected_sha256: stream.sha256.as_deref(),
            source_offset: stream.source_offset,
            source_runs: stream
                .source_extents
                .iter()
                .map(|run| n2r_win32::shadow_native::SourceRun {
                    logical_offset: run.logical_offset,
                    physical_offset: run.physical_offset,
                    length: run.length,
                })
                .collect(),
        })
        .collect()
}

pub fn native_inputs(tree: &crate::shadow_tree::Tree) -> Vec<n2r_win32::shadow_native::Input<'_>> {
    tree.objects
        .iter()
        .map(|object| n2r_win32::shadow_native::Input {
            components: &object.path,
            additional_names: &object.additional_names,
            sparse: object.sparse.as_ref(),
            named_streams: native_named_streams(object),
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
            expected_api_security: object.api_security.as_deref(),
            extended_attributes: object.extended_attributes.as_ref(),
            reparse: object.reparse.as_ref(),
            payload: &[],
            expected_length: (!object.directory).then_some(object.length),
            expected_sha256: if object.directory {
                None
            } else {
                object.sha256.as_deref()
            },
            source_offset: object.source_offset,
            source_runs: object
                .source_extents
                .iter()
                .map(|run| n2r_win32::shadow_native::SourceRun {
                    logical_offset: run.logical_offset,
                    physical_offset: run.physical_offset,
                    length: run.length,
                })
                .collect(),
        })
        .collect()
}

/// Allocation-only staging on the enrolled shadow, never source admission or
/// conversion authority. Original metadata remains in the canonical tree;
/// the native placeholders stay private while payload supply is pending.
#[cfg(windows)]
pub fn allocate_private_tree(
    pair: &GeneralSourceShadowBinding,
    tree: &crate::shadow_tree::Tree,
) -> Result<n2r_win32::shadow_native::private_tree::PrivateTree> {
    crate::shadow_tree::ExpectedTree::from(tree).validate_with_resource_profile(
        crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2,
    )?;
    Ok(n2r_win32::shadow_native::private_tree::allocate(
        pair,
        &native_inputs(tree),
    )?)
}

/// Construct on selected dedicated disks only after live enrollment from the
/// original observed source freeze. Neither this capability nor its report is
/// a substitute for the later full source certificate and target comparison.
pub fn allocate_private_tree_enrolled(
    source: &n2r_win32::GeneralFrozenPartition,
    pair: &GeneralSourceShadowBinding,
    tree: &crate::shadow_tree::Tree,
) -> Result<n2r_win32::shadow_native::private_tree::PrivateTree> {
    crate::shadow_tree::ExpectedTree::from(tree).validate_with_resource_profile(
        crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2,
    )?;
    let enrollment = n2r_win32::shadow_native::private_tree::enroll(source, pair)?;
    Ok(n2r_win32::shadow_native::private_tree::allocate_enrolled(
        enrollment,
        &native_inputs(tree),
    )?)
}

/// Copy only bounded recognized system streams; large user streams remain
/// source-backed. All source bytes are checked through the existing NTFS reader.
/// An absent IndexerVolumeGuid produces an empty optional cache payload; no
/// replacement cache content is invented for fresh NTFS data volumes.
#[cfg(windows)]
pub fn materialize_private_system_payloads(
    source: &mut n2r_win32::GeneralFrozenPartition,
    raw: &crate::ntfs_inspect::NtfsInspection,
    tree: &crate::shadow_tree::Tree,
    template: &mut n2r_win32::shadow_native::private_tree::PrivateTree,
    budget: &mut crate::ntfs_inspect::StreamTransferBudget,
) -> Result<(serde_json::Value, Vec<u8>)> {
    ensure!(
        source.binding() == template.source_binding(),
        "system source binding differs"
    );
    let mut events = Vec::new();
    let before = source.state(&mut events)?;
    ensure!(
        before.disk_attributes == 3,
        "system payload source must stay excluded"
    );
    let selected: Vec<_> = tree
        .objects
        .iter()
        .enumerate()
        .filter(|(_, o)| {
            !o.directory
                && o.path
                    .first()
                    .is_some_and(|s| s == "System Volume Information")
        })
        .collect();
    for (_, object) in &selected {
        ensure!(
            object.sparse.is_none(),
            "legacy system materialization cannot copy a sparse stream"
        );
        ensure!(
            object.length <= 1024 * 1024,
            "system stream exceeds bounded materialization profile"
        );
        let identities: Vec<_> = raw
            .files
            .iter()
            .filter(|f| f.record_number == object.record_number)
            .collect();
        ensure!(
            identities.len() == 1 && identities[0].sequence_number == object.sequence_number,
            "system source identity differs"
        );
        let proof = crate::ntfs_inspect::copy_plain_stream_with_budget(
            source,
            raw,
            object.record_number,
            budget,
            &mut std::io::sink(),
        )?;
        ensure!(
            proof.logical_bytes == object.length && Some(&proof.sha256) == object.sha256.as_ref(),
            "system source preflight differs from canonical tree"
        );
    }
    let mut receipts = Vec::new();
    let mut writer = |index: usize, file: &mut std::fs::File| -> std::io::Result<()> {
        let object = tree
            .objects
            .get(index)
            .ok_or_else(|| std::io::Error::other("system source index absent"))?;
        if object.directory
            || !object
                .path
                .first()
                .is_some_and(|s| s == "System Volume Information")
        {
            return Err(std::io::Error::other("non-system payload refused"));
        }
        let proof = crate::ntfs_inspect::copy_plain_stream_with_budget(
            source,
            raw,
            object.record_number,
            budget,
            file,
        )
        .map_err(std::io::Error::other)?;
        if proof.logical_bytes != object.length || Some(&proof.sha256) != object.sha256.as_ref() {
            return Err(std::io::Error::other("system source transfer differs"));
        }
        receipts.push(proof);
        Ok(())
    };
    let native = template.materialize_system_payloads(&native_inputs(tree), &mut writer)?;
    drop(writer);
    let cache = selected
        .iter()
        .find(|(_, o)| o.path == ["System Volume Information", "IndexerVolumeGuid"])
        .map(|(_, object)| *object);
    let payload = if let Some(cache) = cache {
        ensure!(cache.length == 76, "source indexer cache length differs");
        let mut payload = vec![0u8; 76];
        let proof = crate::ntfs_inspect::read_plain_stream_range_into(
            source,
            raw,
            cache.record_number,
            0,
            &mut payload,
            budget,
        )?;
        // The range proof is SHA-256; the cached object carries a content digest.
        ensure!(
            proof.whole_stream_hash_matched
                && Some(&n2r_win32::content_digest::of(&payload)) == cache.sha256.as_ref(),
            "source indexer cache digest differs"
        );
        payload
    } else {
        Vec::new()
    };
    ensure!(
        source.state(&mut events)? == before,
        "system source state changed"
    );
    Ok((
        serde_json::json!({"native":native,"source_receipts":receipts,"source_payload_writes":0,
        "indexer_payload_present":cache.is_some(),"indexer_payload_bytes":payload.len(),
        "conversion_qualified":false}),
        payload,
    ))
}

/// Supply only a bounded exception range to its same named private file.
/// Native staging refuses a gap beyond its initialized prefix, so a final
/// byte of a huge stream cannot accidentally zero-fill the entire prefix.
#[cfg(windows)]
pub fn materialize_private_range(
    source: &mut n2r_win32::GeneralFrozenPartition,
    raw: &crate::ntfs_inspect::NtfsInspection,
    tree: &crate::shadow_tree::Tree,
    template: &mut n2r_win32::shadow_native::private_tree::PrivateTree,
    object_index: usize,
    offset: u64,
    length: usize,
    budget: &mut crate::ntfs_inspect::StreamTransferBudget,
) -> Result<serde_json::Value> {
    materialize_private_named_range(
        source,
        raw,
        tree,
        template,
        object_index,
        &[],
        offset,
        length,
        budget,
    )
}

#[cfg(windows)]
fn canonical_stream_shape<'a>(
    object: &'a crate::shadow_tree::Object,
    stream_name_utf16: &[u16],
) -> Result<(
    u64,
    Option<&'a str>,
    Option<&'a n2r_win32::sparse_layout::SparseLayout>,
)> {
    ensure!(!object.directory, "directories do not receive payload");
    if stream_name_utf16.is_empty() {
        return Ok((
            object.length,
            object.sha256.as_deref(),
            object.sparse.as_ref(),
        ));
    }
    let mut streams = object
        .named_streams
        .iter()
        .filter(|stream| stream.name_utf16 == stream_name_utf16);
    let stream = streams.next().context("canonical named stream absent")?;
    ensure!(
        streams.next().is_none(),
        "canonical named stream duplicated"
    );
    Ok((
        stream.length,
        stream.sha256.as_deref(),
        stream.sparse.as_ref(),
    ))
}

/// Materialize an exact named or unnamed stream range. A name selects the
/// already inventoried stream; it is never appended to an arbitrary path.
#[cfg(windows)]
pub fn materialize_private_named_range(
    source: &mut n2r_win32::GeneralFrozenPartition,
    raw: &crate::ntfs_inspect::NtfsInspection,
    tree: &crate::shadow_tree::Tree,
    template: &mut n2r_win32::shadow_native::private_tree::PrivateTree,
    object_index: usize,
    stream_name_utf16: &[u16],
    offset: u64,
    length: usize,
    budget: &mut crate::ntfs_inspect::StreamTransferBudget,
) -> Result<serde_json::Value> {
    ensure!(
        length <= 65536 && source.binding() == template.source_binding(),
        "private materialization source binding or buffer bound differs"
    );
    let object = tree
        .objects
        .get(object_index)
        .context("private object index outside canonical tree")?;
    let (stream_length, stream_digest, sparse) = canonical_stream_shape(object, stream_name_utf16)?;
    let identities: Vec<_> = raw
        .files
        .iter()
        .filter(|f| f.record_number == object.record_number)
        .collect();
    ensure!(
        identities.len() == 1 && identities[0].sequence_number == object.sequence_number,
        "canonical materialization source identity differs"
    );
    let mut events = Vec::new();
    let before = source.state(&mut events)?;
    ensure!(
        before.disk_attributes == 3,
        "materialization source must remain excluded"
    );
    let mut buffer = [0u8; 65536];
    let read = if sparse.is_some() {
        crate::ntfs_inspect::read_sparse_named_stream_range_into(
            source,
            raw,
            object.record_number,
            stream_name_utf16,
            offset,
            &mut buffer[..length],
            budget,
        )?
    } else {
        crate::ntfs_inspect::read_plain_named_stream_range_into(
            source,
            raw,
            object.record_number,
            stream_name_utf16,
            offset,
            &mut buffer[..length],
            budget,
        )?
    };
    ensure!(
        read.stream_logical_bytes == stream_length
            && read.stream_name_utf16 == stream_name_utf16
            && read.expected_stream_sha256.as_deref() == stream_digest,
        "materialization source differs from canonical object"
    );
    ensure!(
        source.state(&mut events)? == before,
        "source exclusion changed around range read"
    );
    let write = template.materialize_range_named(
        object_index,
        stream_name_utf16,
        &object.path,
        stream_length,
        offset,
        &buffer[..length],
    )?;
    ensure!(
        write["sha256"] == read.sha256 && write["readback_verified"] == true,
        "private materialization destination proof differs"
    );
    ensure!(
        source.state(&mut events)? == before,
        "source exclusion changed during materialization"
    );
    let mut receipt = serde_json::json!({"kind":"private-exception-materialization","object_index":object_index,
        "source":read,"destination":write,"source_payload_writes":0,"conversion_qualified":false});
    if !stream_name_utf16.is_empty() {
        receipt["stream_name_utf16"] = serde_json::json!(stream_name_utf16);
    }
    Ok(receipt)
}

/// Stream only the live plan's non-reference data into private shadow files.
/// Hash the ordered chunk receipts instead of retaining payload-sized data or
/// an unbounded list of receipts. Original-coordinate data is never copied.
#[cfg(windows)]
pub fn materialize_private_supply_plan(
    source: &mut n2r_win32::GeneralFrozenPartition,
    raw: &crate::ntfs_inspect::NtfsInspection,
    tree: &crate::shadow_tree::Tree,
    template: &mut n2r_win32::shadow_native::private_tree::PrivateTree,
    max_bytes: u64,
    budget: &mut crate::ntfs_inspect::StreamTransferBudget,
) -> Result<serde_json::Value> {
    use sha2::{Digest, Sha256};
    ensure!(
        source.binding() == template.source_binding(),
        "planned materialization source binding differs"
    );
    let mut state_events = Vec::new();
    let source_before = source.state(&mut state_events)?;
    ensure!(
        source_before.disk_attributes == 3,
        "planned materialization requires excluded source"
    );
    let plan = template.supply_plan()?;
    ensure!(
        plan.materialize_bytes <= max_bytes,
        "necessary materialization exceeds explicit payload budget"
    );
    let mut files = std::collections::BTreeSet::new();
    for range in plan.materialization_ranges() {
        files.insert((range.object_index, range.stream_name_utf16.clone()));
    }
    for range in plan.source_reference_ranges() {
        files.insert((range.object_index, range.stream_name_utf16.clone()));
    }
    // Make complete tracked prefixes valid before later-offset writes. This
    // changes only private metadata; those bytes are not source-authenticated.
    for (index, stream_name) in &files {
        let object = tree
            .objects
            .get(*index)
            .context("supply object outside canonical tree")?;
        let (length, _, sparse) = canonical_stream_shape(object, stream_name)?;
        // The sparse backend prepares its compact carrier from allocated
        // logical intervals. Advancing to logical EOF would materialize holes.
        if sparse.is_some() {
            continue;
        }
        let prefix = length / 4096 * 4096;
        if prefix > 0 {
            template.advance_placed_prefix_named(*index, stream_name, prefix)?;
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"n2r-private-materialization-receipts-v1\0");
    let mut count = 0u64;
    let mut written = 0u64;
    let mut samples = Vec::new();
    for range in plan.materialization_ranges() {
        let mut done = 0;
        loop {
            let length = (range.length - done).min(65536) as usize;
            let receipt = materialize_private_named_range(
                source,
                raw,
                tree,
                template,
                range.object_index,
                &range.stream_name_utf16,
                range.logical_offset + done,
                length,
                budget,
            )?;
            let bytes = serde_json::to_vec(&receipt)?;
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(&bytes);
            count = count
                .checked_add(1)
                .context("materialization receipt count overflow")?;
            written = written
                .checked_add(length as u64)
                .context("materialization written-byte overflow")?;
            if samples.len() < 32 {
                samples.push(receipt);
            }
            done += length as u64;
            if done == range.length {
                break;
            }
        }
    }
    ensure!(
        written == plan.materialize_bytes,
        "private supply materialization accounting differs"
    );
    // Recheck native placements after all writes; no persisted plan flag can
    // substitute for these live observations.
    let after = template.supply_plan()?;
    ensure!(
        serde_json::to_vec(&plan)? == serde_json::to_vec(&after)?,
        "private source-reference mapping changed during supply"
    );
    ensure!(
        source.state(&mut state_events)? == source_before,
        "source state changed during planned materialization"
    );
    Ok(
        serde_json::json!({"kind":"private-planned-materialization","plan":plan,
        "materialized_bytes":written,"receipt_count":count,"sample_receipts":samples,
        "ordered_receipt_sha256":hex::encode(digest.finalize()),
        "source_payload_writes":0,"logical_hybrid_verification_pending":true,"conversion_qualified":false}),
    )
}

/// Verify mixed logical data without copying original-coordinate payload.
/// This checks live stream mappings, not the frozen ReFS metadata graph.
#[cfg(windows)]
pub fn verify_private_hybrid_contents(
    source: &mut n2r_win32::GeneralFrozenPartition,
    tree: &crate::shadow_tree::Tree,
    template: &mut n2r_win32::shadow_native::private_tree::PrivateTree,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    ensure!(
        tree.objects
            .iter()
            .all(|object| object.data_streams().all(|stream| stream.sparse.is_none())),
        "legacy hybrid content verifier cannot account for sparse holes"
    );
    ensure!(
        source.binding() == template.source_binding(),
        "hybrid source binding differs"
    );
    let mut events = Vec::new();
    let before = source.state(&mut events)?;
    ensure!(
        before.disk_attributes == 3,
        "hybrid verification requires excluded source"
    );
    let plan = template.supply_plan()?;
    let mut ranges: Vec<_> = plan
        .materialization_ranges()
        .iter()
        .chain(plan.source_reference_ranges())
        .collect();
    ranges.sort_by_key(|r| {
        (
            r.object_index,
            r.stream_name_utf16.clone(),
            r.logical_offset,
        )
    });
    let mut grouped = std::collections::BTreeMap::<(usize, Vec<u16>), Vec<_>>::new();
    for range in ranges {
        grouped
            .entry((range.object_index, range.stream_name_utf16.clone()))
            .or_default()
            .push(range);
    }
    let mut files = Vec::new();
    let mut source_bytes = 0u64;
    let mut shadow_bytes = 0u64;
    let mut buffer = [0u8; 65536];
    for ((index, stream_name), ranges) in grouped {
        let object = tree
            .objects
            .get(index)
            .context("hybrid stream outside canonical tree")?;
        let (stream_length, stream_digest, _) = canonical_stream_shape(object, &stream_name)?;
        let stream_digest =
            stream_digest.context("legacy full hybrid verification requires a content baseline")?;
        template.validate_stream_shape_named(index, &stream_name, &object.path, stream_length)?;
        let mut cursor = 0u64;
        // Canonical stream digests use content_digest (currently XXH3-128),
        // including named streams. SHA-256 remains for artifact/range pins.
        let mut hash = n2r_win32::content_digest::Hasher::new();
        for range in ranges {
            ensure!(
                range.logical_offset == cursor,
                "hybrid logical range gap or overlap"
            );
            let end = cursor
                .checked_add(range.length)
                .context("hybrid range overflow")?;
            ensure!(end <= stream_length, "hybrid logical range exceeds EOF");
            let mut done = 0;
            while done < range.length {
                let count = (range.length - done).min(buffer.len() as u64) as usize;
                if let Some(physical) = range.source_physical_offset {
                    let offset = physical
                        .checked_add(done)
                        .context("hybrid physical offset overflow")?;
                    ensure!(
                        offset
                            .checked_add(count as u64)
                            .is_some_and(|v| v <= source.byte_len()),
                        "hybrid source reference escapes partition"
                    );
                    source.seek(SeekFrom::Start(offset))?;
                    source.read_exact(&mut buffer[..count])?;
                    source_bytes = source_bytes
                        .checked_add(count as u64)
                        .context("hybrid source read accounting overflow")?;
                } else {
                    template.read_materialized_range_named(
                        index,
                        &stream_name,
                        cursor + done,
                        &mut buffer[..count],
                    )?;
                    shadow_bytes = shadow_bytes
                        .checked_add(count as u64)
                        .context("hybrid shadow read accounting overflow")?;
                }
                hash.update(&buffer[..count]);
                done += count as u64;
            }
            cursor = end;
        }
        ensure!(cursor == stream_length, "hybrid stream coverage incomplete");
        let actual = hash.finish();
        ensure!(
            actual == stream_digest,
            "hybrid logical stream differs: {:?}",
            object.path
        );
        template.validate_stream_shape_named(index, &stream_name, &object.path, stream_length)?;
        let mut receipt = serde_json::json!({"object_index":index,"components":object.path,
            "record_number":object.record_number,"logical_bytes":cursor,"sha256":actual});
        if !stream_name.is_empty() {
            receipt["stream_name_utf16"] = serde_json::json!(stream_name);
        }
        files.push(receipt);
    }
    let after = template.supply_plan()?;
    ensure!(
        serde_json::to_vec(&plan)? == serde_json::to_vec(&after)?,
        "hybrid native mapping changed around verification"
    );
    ensure!(
        source.state(&mut events)? == before,
        "hybrid source state changed during verification"
    );
    ensure!(
        source_bytes == plan.source_reference_bytes && shadow_bytes == plan.materialize_bytes,
        "hybrid read accounting differs from live supply plan"
    );
    Ok(
        serde_json::json!({"kind":"private-logical-hybrid-verification","success":true,
        "files":files,"source_reference_bytes_read":source_bytes,"shadow_materialization_bytes_read":shadow_bytes,
        "logical_bytes_verified":plan.logical_bytes,"payload_bytes_written":0,
        "frozen_metadata_graph_verified":false,"source_metadata_restoration_pending":true,
        "conversion_qualified":false}),
    )
}

pub fn validate_mount_paths(paths: &Option<Vec<String>>) -> Result<()> {
    let Some(paths) = paths else { return Ok(()) };
    ensure!(paths.len() <= 128, "too many source mount paths");
    let mut seen = BTreeSet::new();
    for path in paths {
        let bytes = path.as_bytes();
        ensure!(
            (3..=1024).contains(&bytes.len())
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
                && path.ends_with('\\')
                && !path.contains(['/', '\0'])
                && (bytes.len() == 3
                    || path[3..path.len() - 1].split('\\').all(|part| {
                        !part.is_empty()
                            && part != "."
                            && part != ".."
                            && !part.chars().any(|character| {
                                character.is_control()
                                    || matches!(character, ':' | '*' | '?' | '"' | '<' | '>' | '|')
                            })
                    }))
                && seen.insert(path.to_lowercase()),
            "source mount path is ambiguous or repeated"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub pair: GeneralSourceShadowBinding,
    pub source_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_mount_paths: Option<Vec<String>>,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        self.validate_with_resource_profile(crate::ntfs_admission::ResourceProfile::AlphaV1)
    }

    pub fn validate_with_resource_profile(
        &self,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<()> {
        self.pair
            .validate_with_resource_profile(resources.native_profile())?;
        ensure!(
            self.schema_version == 1
                && self.source_sha256.len() == 64
                && self
                    .source_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "general shadow request profile or source pin differs"
        );
        validate_mount_paths(&self.expected_mount_paths)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_path_policy_accepts_bounded_drive_and_folder_roots() {
        validate_mount_paths(&Some(vec!["F:\\".into(), "C:\\mounted\\data\\".into()])).unwrap();
        for path in ["F:", "F:/", "C:\\..\\", "C:\\mount//", "F:\\0"] {
            assert!(validate_mount_paths(&Some(vec![path.into()])).is_err());
        }
        assert!(validate_mount_paths(&Some(vec!["F:\\".into(), "f:\\".into()])).is_err());
    }
}
