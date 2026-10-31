//! Fresh owning-conversion evidence for mounted extent verification. This has
//! no deserializer and is never used by recovery or a separate observer.
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
}

#[derive(PartialEq, Eq)]
struct StreamMap {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: Vec<u8>,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<n2r_win32::sparse_layout::SparseLayout>,
    integrity: Vec<u8>,
}

#[derive(PartialEq, Eq)]
enum StreamStandard {
    Data([u8; 22]),
    // Directory tree storage may grow for the separately verified post-mount
    // indexer cache. It is not retained file payload; namespace stays checked.
    DirectoryLinksAndType([u8; 6]),
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
        Ok(Self {
            expected_tree_sha256,
            source: proof.pair().source.clone(),
            maps: maps(native)?,
            base_sectors: native.base_sectors,
            new_selected_sha256: ticket.new_selected_sha256,
            selected_bytes,
            range_count: ticket.range_count,
        })
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
            "target_full_file_hashes":false,"target_admitted_payload_bytes_read":0,
            "saved_receipt_grants_execution_authority":false}),
        )
    }
}

/// Only the fresh allocation route can supply this in-memory proof and its
/// actual Apply/HND results. Fresh recovery still calls the full verifier.
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
