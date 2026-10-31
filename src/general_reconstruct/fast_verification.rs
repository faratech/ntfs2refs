//! Fresh conversion evidence and separately authenticated, read-only recovery
//! map facts. Deserializing facts never recreates source or write admission.
use super::*;
use crate::{
    general_composite_target::FrozenAllocationTargetPreservation,
    general_source_admission::AllocationCertificate, selected_journal,
};
use anyhow::{Context, ensure};
use n2r_win32::{attestation::Snapshot, shadow_native::Report};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) struct FreshPayloadProof {
    expected_tree_sha256: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    maps: BTreeMap<(Vec<String>, Vec<u16>), StreamMap>,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    plan_sha256: String,
    ticket_sha256: String,
    tail_extent_streams: usize,
    tail_payload_bytes_verified: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamMap {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: Vec<u8>,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<n2r_win32::sparse_layout::SparseLayout>,
    integrity: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StreamStandard {
    Data([u8; 22]),
    // Directory tree storage may grow for the separately verified post-mount
    // indexer cache. It is not retained file payload; namespace stays checked.
    DirectoryLinksAndType([u8; 6]),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapEntry {
    components: Vec<String>,
    name_utf16: Vec<u16>,
    map: StreamMap,
}

/// Immutable observation facts pinned by the recovery bundle. No lifecycle,
/// device exclusion, native observation or write capability can be serialized.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPayloadManifest {
    schema_version: u32,
    kind: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    expected_tree_sha256: String,
    plan_sha256: String,
    ticket_sha256: String,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    bindings: Vec<MapEntry>,
    grants_write_authority: bool,
    initial_retained_content_digests_available: bool,
}

pub(crate) struct RecoveryPayloadProof {
    facts: RecoveryPayloadManifest,
    maps: BTreeMap<(Vec<String>, Vec<u16>), StreamMap>,
}

fn query(snapshot: &Snapshot, class: i32) -> Result<&[u8]> {
    let mut found = snapshot.queries.iter().filter(|query| query.class == class);
    let value = found.next().context("fast stream binding query absent")?;
    ensure!(
        found.next().is_none() && value.native_error.is_none() && value.bytes.len() == 24,
        "fast stream binding query refused or ambiguous"
    );
    Ok(&value.bytes)
}

fn stream_map(
    snapshot: &Snapshot,
    retrieval: &[u8],
    paged: bool,
    resident: bool,
    sparse: Option<&n2r_win32::sparse_layout::SparseLayout>,
    integrity: &[u8],
) -> Result<StreamMap> {
    let identity = query(snapshot, 18)?;
    let standard = query(snapshot, 1)?;
    ensure!(standard[20] == 0, "fast stream is delete pending");
    // File identities live in the copied ReFS metadata graph. Volume paths and
    // disk numbers change at cutover; neither substitutes for the 128-bit ID.
    Ok(StreamMap {
        file_id: identity[8..].try_into()?,
        standard: if standard[21] == 0 {
            StreamStandard::Data(standard[..22].try_into()?)
        } else {
            StreamStandard::DirectoryLinksAndType(standard[16..22].try_into()?)
        },
        retrieval: retrieval.to_vec(),
        complete_page_proof: paged,
        resident,
        sparse: sparse.cloned(),
        integrity: integrity.to_vec(),
    })
}

fn maps(report: &Report) -> Result<BTreeMap<(Vec<String>, Vec<u16>), StreamMap>> {
    let mut maps = BTreeMap::new();
    for object in &report.objects {
        ensure!(
            object.before == object.after,
            "fast object metadata changed during observation"
        );
        let value = stream_map(
            &object.before,
            &object.retrieval,
            object.retrieval_page_proof.is_some(),
            object.resident_data,
            object.sparse.as_ref().map(|sparse| &sparse.expected),
            &object.integrity,
        )?;
        ensure!(
            maps.insert((object.components.clone(), Vec::new()), value)
                .is_none(),
            "duplicate fast canonical object"
        );
        for stream in &object.named_streams {
            ensure!(
                stream.before == stream.after,
                "fast named stream metadata changed"
            );
            let value = stream_map(
                &stream.before,
                &stream.retrieval,
                stream.retrieval_page_proof.is_some(),
                stream.resident_data,
                stream.sparse.as_ref().map(|sparse| &sparse.expected),
                &stream.integrity,
            )?;
            ensure!(
                !stream.name_utf16.is_empty()
                    && maps
                        .insert(
                            (object.components.clone(), stream.name_utf16.clone()),
                            value
                        )
                        .is_none(),
                "duplicate fast named stream"
            );
        }
    }
    Ok(maps)
}

impl FreshPayloadProof {
    pub(crate) fn new(
        proof: &FrozenAllocationTargetPreservation,
        certificate: &AllocationCertificate,
        expected: &shadow_tree::ExpectedTree,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
    ) -> Result<Self> {
        let expected_tree_sha256 =
            hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?));
        ensure!(
            certificate.binds(proof)
                && proof.data_ties_verified()
                && proof.expected_tree_sha256() == expected_tree_sha256
                && certificate.expected_tree_sha256() == expected_tree_sha256
                && serde_json::to_vec(plan)?
                    == serde_json::to_vec(&proof.plan(plan.max_journal_bytes)?)?,
            "fresh payload proof differs from the original live certificate or exact selected plan"
        );
        let (selected_bytes, journal_bytes) = plan.validate()?;
        ensure!(
            ticket.image_length == proof.pair().source.identity.partition_bytes
                && ticket.selected_bytes == selected_bytes
                && ticket.journal_length == journal_bytes
                && ticket.range_count as usize == plan.ranges.len()
                && !ticket.whole_image_verified
                && ticket.new_selected_sha256 != ticket.old_selected_sha256,
            "fresh payload ticket differs from its prepared plan"
        );
        let native = proof.protected_layout().native().report().native();
        let protected = proof.protected_layout().native().report();
        let mut tail_extent_streams = 0usize;
        let mut tail_payload_bytes_verified = 0u64;
        for (object_index, object) in expected.objects.iter().enumerate() {
            for stream in object.data_streams().filter(|s| {
                s.source_evidence
                    == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
            }) {
                let matches: Vec<_> = protected
                    .residuals()
                    .iter()
                    .filter(|r| {
                        r.object_index == object_index && r.stream_name_utf16 == stream.name_utf16
                    })
                    .collect();
                ensure!(
                    protected.residual_contents_verified()
                        && matches.len() == 1
                        && matches[0].logical_offset == stream.length / 4096 * 4096
                        && matches[0].length == stream.length % 4096
                        && matches[0].sha256.len() == 64,
                    "extent-only partial tail lacks exact protected source-to-target residual verification"
                );
                tail_extent_streams += 1;
                tail_payload_bytes_verified = tail_payload_bytes_verified
                    .checked_add(matches[0].length)
                    .context("verified extent-tail byte count overflow")?;
            }
        }
        Ok(Self {
            expected_tree_sha256,
            source: proof.pair().source.clone(),
            maps: maps(native)?,
            base_sectors: native.base_sectors,
            new_selected_sha256: ticket.new_selected_sha256,
            selected_bytes,
            range_count: ticket.range_count,
            plan_sha256: hex::encode(Sha256::digest(serde_json::to_vec(plan)?)),
            ticket_sha256: hex::encode(Sha256::digest(serde_json::to_vec(ticket)?)),
            tail_extent_streams,
            tail_payload_bytes_verified,
        })
    }

    pub(crate) fn recovery_manifest(&self) -> Result<RecoveryPayloadManifest> {
        let manifest = RecoveryPayloadManifest {
            schema_version: 1,
            kind: "protected-target-stream-map-facts-v1".into(),
            source: self.source.clone(),
            expected_tree_sha256: self.expected_tree_sha256.clone(),
            plan_sha256: self.plan_sha256.clone(),
            ticket_sha256: self.ticket_sha256.clone(),
            base_sectors: self.base_sectors,
            new_selected_sha256: self.new_selected_sha256,
            selected_bytes: self.selected_bytes,
            range_count: self.range_count,
            bindings: self
                .maps
                .iter()
                .map(|((components, name_utf16), map)| MapEntry {
                    components: components.clone(),
                    name_utf16: name_utf16.clone(),
                    map: map.clone(),
                })
                .collect(),
            grants_write_authority: false,
            initial_retained_content_digests_available: false,
        };
        ensure!(
            serde_json::to_vec_pretty(&manifest)?.len() <= 64 * 1024 * 1024,
            "recovery map facts exceed the bounded metadata artifact"
        );
        Ok(manifest)
    }

    fn verify(
        &self,
        scope: &NativeVerificationScope<'_>,
        expected: &shadow_tree::ExpectedTree,
        applied: &selected_journal::SelectedResult,
        handoff: &selected_journal::SelectedResult,
        native: &shadow_native::GeneralConvertedReport,
    ) -> Result<Value> {
        ensure!(
            scope.pair.source == self.source
                && native.pair.source.identity == self.source.identity
                && hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?))
                    == self.expected_tree_sha256,
            "fresh payload source or expected tree changed at handoff"
        );
        for result in [applied, handoff] {
            ensure!(
                result.selected_sha256 == self.new_selected_sha256
                    && result.selected_bytes == self.selected_bytes
                    && result.range_count == self.range_count
                    && !result.whole_image_verified,
                "fresh payload apply/handoff checksum differs"
            );
        }
        ensure!(
            handoff.replay_closed,
            "extent verification requires a durable closed handoff"
        );
        let observation = native
            .content_observation
            .as_ref()
            .context("metadata observation scope absent")?;
        ensure!(
            !observation.full_file_hashes
                && observation.admitted_payload_bytes_read == 0
                && observation.metadata_and_namespace_verified
                && observation.complete_stream_mappings_observed
                && observation.data_storage_validity_checked
                && native.native.base_sectors == self.base_sectors
                && maps(&native.native)? == self.maps,
            "mounted file identities, complete physical maps or storage validity differ from the protected candidate"
        );
        Ok(
            serde_json::json!({"schema_version":1,"scope":"fresh-conversion-extent-identity-v1",
            "expected_tree_sha256":self.expected_tree_sha256,"stream_and_directory_bindings":self.maps.len(),
            "selected_bytes_checksummed":self.selected_bytes,"selected_sha256":hex::encode(self.new_selected_sha256),
            "retained_bytes_proven_by_same_physical_mapping":true,
            "resident_and_residual_bytes_bound_by_selected_image":true,
            "all_complete_maps_identical":true,"handoff_replay_closed":true,
            "extent_only_partial_streams":self.tail_extent_streams,
            "materialized_extent_tail_bytes_verified":self.tail_payload_bytes_verified,
            "target_full_file_hashes":false,"target_admitted_payload_bytes_read":0,
            "saved_receipt_grants_execution_authority":false}),
        )
    }
}

impl RecoveryPayloadProof {
    /// Call only with the separately pinned, write/delete-excluded artifact.
    /// This validates facts; actual SJ lifecycle/checksums remain mandatory.
    pub(crate) fn from_pinned_manifest(
        bytes: &[u8],
        source: &n2r_win32::general_layout::GeneralDiskBinding,
        expected: &shadow_tree::ExpectedTree,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "recovery map artifact exceeds bound"
        );
        expected.validate_with_resource_profile(
            crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2,
        )?;
        let facts: RecoveryPayloadManifest = serde_json::from_slice(bytes)?;
        let (selected_bytes, journal_bytes) = plan.validate()?;
        ensure!(
            expected.has_extent_only_streams()
                && facts.schema_version == 1
                && facts.kind == "protected-target-stream-map-facts-v1"
                && !facts.grants_write_authority
                && !facts.initial_retained_content_digests_available
                && &facts.source == source
                && facts.expected_tree_sha256
                    == hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?))
                && facts.plan_sha256 == hex::encode(Sha256::digest(serde_json::to_vec(plan)?))
                && facts.ticket_sha256 == hex::encode(Sha256::digest(serde_json::to_vec(ticket)?))
                && ticket.image_length == source.identity.partition_bytes
                && !ticket.whole_image_verified
                && ticket.selected_bytes == selected_bytes
                && ticket.journal_length == journal_bytes
                && ticket.range_count as usize == plan.ranges.len()
                && facts.new_selected_sha256 == ticket.new_selected_sha256
                && facts.selected_bytes == selected_bytes
                && facts.range_count == ticket.range_count,
            "pinned recovery map facts differ from tree, source, selected plan or trusted ticket"
        );
        let mut expected_keys = std::collections::BTreeSet::new();
        for object in &expected.objects {
            expected_keys.insert((object.path.clone(), Vec::new()));
            for stream in &object.named_streams {
                expected_keys.insert((object.path.clone(), stream.name_utf16.clone()));
            }
        }
        ensure!(
            facts.bindings.len() == expected_keys.len(),
            "recovery map binding count differs"
        );
        let mut maps = BTreeMap::new();
        for entry in &facts.bindings {
            let key = (entry.components.clone(), entry.name_utf16.clone());
            ensure!(
                expected_keys.contains(&key)
                    && entry.map.file_id != [0; 16]
                    && maps.insert(key, entry.map.clone()).is_none(),
                "duplicate or unexpected recovery map binding"
            );
            ensure!(
                entry.map.retrieval.len() <= n2r_win32::retrieval_paging::MAX_RETURNED_BYTES,
                "recovery stream map exceeds retrieval bound"
            );
        }
        Ok(Self { facts, maps })
    }
}

/// Recovery never reissues a fresh source certificate. Its existing journal
/// protocol first proves a closed target against the complete immutable body;
/// this routine then compares all mounted maps against independently pinned facts.
pub(crate) fn verify_native_recovery_extents_scoped(
    scope: &NativeVerificationScope<'_>,
    expected: &shadow_tree::ExpectedTree,
    report: &mut Finalization,
    proof: &RecoveryPayloadProof,
    closed: &selected_journal::SelectedResult,
    restored_label: bool,
) -> Result<Value> {
    let facts = &proof.facts;
    ensure!(
        scope.pair.source == facts.source
            && closed.replay_closed
            && !closed.whole_image_verified
            && closed.selected_sha256 == facts.new_selected_sha256
            && closed.selected_bytes == facts.selected_bytes
            && closed.range_count == facts.range_count
            && facts.expected_tree_sha256
                == hex::encode(Sha256::digest(serde_json::to_vec_pretty(expected)?)),
        "recovery requires the actual closed selected-target result for its pinned maps"
    );
    let native = observe_native_metadata(scope, expected, report, restored_label)?;
    let observation = native
        .content_observation
        .as_ref()
        .context("recovery metadata observation absent")?;
    let known = observation
        .known_content
        .as_ref()
        .context("recovery known-content checks absent")?;
    let mut known_streams = 0usize;
    let mut unknown_streams = 0usize;
    let mut known_bytes = 0u64;
    let mut unknown_partial_streams = 0usize;
    let mut unknown_partial_tail_bytes = 0u64;
    for object in &expected.objects {
        for stream in object.data_streams() {
            if stream.sha256.is_some() {
                known_streams += 1;
                known_bytes = known_bytes
                    .checked_add(stream.length)
                    .context("recovery known stream total overflow")?;
            } else {
                unknown_streams += 1;
                if stream.source_evidence
                    == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
                {
                    unknown_partial_streams += 1;
                    unknown_partial_tail_bytes = unknown_partial_tail_bytes
                        .checked_add(stream.length % 4096)
                        .context("recovery extent-tail byte total overflow")?;
                }
            }
        }
    }
    ensure!(
        observation.metadata_and_namespace_verified
            && observation.complete_stream_mappings_observed
            && observation.data_storage_validity_checked
            && !observation.full_file_hashes
            && observation.admitted_payload_bytes_read == known_bytes
            && known.payload_bytes_read == known_bytes
            && known.streams_hashed == known_streams
            && known.streams_without_content_baseline == unknown_streams
            && native.pair.source.identity == facts.source.identity
            && native.native.base_sectors == facts.base_sectors
            && maps(&native.native)? == proof.maps,
        "recovery mounted metadata, storage validity or complete maps differ from pinned target facts"
    );
    record_mount_paths_scoped(scope, &native, report);
    report.native = Some(native);
    if report.error.is_none() && !restored_label {
        restore_source_label_scoped(scope, report);
    }
    report.success = report.error.is_none();
    Ok(
        serde_json::json!({"schema_version":1,"scope":"recovery-selected-checksums-and-pinned-stream-maps-v1",
        "all_complete_maps_identical":true,"stream_and_directory_bindings":proof.maps.len(),
        "selected_bytes_checksummed":closed.selected_bytes,"selected_sha256":hex::encode(closed.selected_sha256),
        "handoff_replay_closed":true,"full_file_hashes":false,"initial_retained_content_digests_available":false,
        "known_content_streams_hashed":known_streams,"known_content_payload_bytes_read":known_bytes,
        "extent_only_streams":unknown_streams,
        "extent_only_partial_streams":unknown_partial_streams,
        "extent_only_partial_tail_bytes":unknown_partial_tail_bytes,
        "post_operational_source_equality_claimed":false,"grants_fresh_source_or_write_authority":false}),
    )
}

fn observe_native_metadata(
    scope: &NativeVerificationScope<'_>,
    expected: &shadow_tree::ExpectedTree,
    report: &mut Finalization,
    restored_label: bool,
) -> Result<shadow_native::GeneralConvertedReport> {
    let mut pair = scope.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, &mut report.events)?;
    let tree = shadow_tree::Tree {
        profile: scope
            .source_resource_profile
            .unwrap_or_default()
            .ordinary_shadow_profile(),
        objects: expected.objects.clone(),
        logical_bytes: expected.logical_bytes,
        internal_replacement_pending: expected.internal_replacement_pending.clone(),
    };
    let input = crate::general_shadow::native_inputs(&tree);
    Ok(
        shadow_native::verify_general_converted_known_contents_with_resource_profile(
            pair,
            &input,
            if restored_label {
                scope.expected_source_label
            } else {
                None
            },
            |a, b| {
                ntfs_attestation::same_security(a, b)
                    .map_err(|error| io::Error::other(error.to_string()))
            },
            scope
                .source_resource_profile
                .unwrap_or_default()
                .native_profile(),
        )?,
    )
}

/// Only the fresh allocation route can supply this in-memory proof and its
/// actual Apply/HND results. Recovery uses its distinct pinned-fact protocol.
pub(crate) fn verify_native_extents_scoped(
    scope: &NativeVerificationScope<'_>,
    expected: &shadow_tree::ExpectedTree,
    report: &mut Finalization,
    proof: &FreshPayloadProof,
    applied: &selected_journal::SelectedResult,
    handoff: &selected_journal::SelectedResult,
) -> Result<Value> {
    let mut pair = scope.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, &mut report.events)?;
    let tree = shadow_tree::Tree {
        profile: scope
            .source_resource_profile
            .unwrap_or_default()
            .ordinary_shadow_profile(),
        objects: expected.objects.clone(),
        logical_bytes: expected.logical_bytes,
        internal_replacement_pending: expected.internal_replacement_pending.clone(),
    };
    let input = crate::general_shadow::native_inputs(&tree);
    let native = shadow_native::observe_general_converted_metadata_with_resource_profile(
        pair,
        &input,
        None,
        |a, b| {
            ntfs_attestation::same_security(a, b)
                .map_err(|error| io::Error::other(error.to_string()))
        },
        scope
            .source_resource_profile
            .unwrap_or_default()
            .native_profile(),
    )?;
    let receipt = proof.verify(scope, expected, applied, handoff, &native)?;
    record_mount_paths_scoped(scope, &native, report);
    report.native = Some(native);
    if report.error.is_none() {
        restore_source_label_scoped(scope, report);
    }
    report.success = report.error.is_none();
    Ok(receipt)
}
