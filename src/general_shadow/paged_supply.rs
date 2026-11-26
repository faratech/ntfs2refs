//! Supply and verify the actual resource-owned private tree one stream at a time.
//! These observations grant neither source admission nor cutover authority.
use super::{
    PagedInputs,
    source_backed::{PagedSourceByteAdapterWithScope, PagedStreamIdentity},
};
use crate::{
    shadow_tree::{Object, PagedExpectedTree, StreamRef},
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    shadow_native::private_tree::{PrivateTree, StreamSupplySummary, SupplyKind, SupplyRange},
    tree_resources::SourceResourceAdmission,
};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

const WINDOW: usize = 65536;

fn phase(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
    template: &PrivateTree,
) -> Result<SourceResourceAdmission> {
    let admission = expected
        .header()
        .resource_admission
        .context("resource expected owner required")?;
    expected.require_resource_owner(admission)?;
    let group = bytes
        .metadata_scratch()
        .artifact_group()
        .context("actual source arena required for paged supply")?;
    expected.require_shared_memory(group.arena())?;
    bytes.require_admission(admission)?;
    ensure!(
        bytes.source_binding() == template.source_binding(),
        "private supply source binding differs"
    );
    template.validate_input_domain(&PagedInputs(expected))?;
    Ok(admission)
}

fn system(object: &Object) -> bool {
    object
        .path
        .first()
        .is_some_and(|s| s == "System Volume Information")
}

fn identity<'a>(object: &Object, stream: StreamRef<'a>) -> PagedStreamIdentity<'a> {
    PagedStreamIdentity {
        record_number: object.record_number,
        sequence_number: object.sequence_number,
        name_utf16: stream.name_utf16,
        length: stream.length,
        sha256: stream.sha256,
        allow_sparse: stream.sparse.is_some(),
    }
}

fn frame(hash: &mut Sha256, value: &impl serde::Serialize) -> Result<()> {
    // Only bounded scalar/range receipts are encoded, never a collection of objects.
    let encoded = serde_json::to_vec(value)?;
    hash.update((encoded.len() as u64).to_le_bytes());
    hash.update(encoded);
    Ok(())
}

fn observe_stream(
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
) -> Result<StreamSupplySummary> {
    Ok(template.visit_supply_stream_named(
        index,
        stream.name_utf16,
        &object.path,
        stream.length,
        |_, _| Ok(()),
    )?)
}

fn stream_ranges(
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    maximum_bytes: u64,
) -> Result<(StreamSupplySummary, Vec<(SupplyKind, SupplyRange)>)> {
    let summary = observe_stream(template, index, object, stream)?;
    stream_ranges_from_summary(template, index, object, stream, maximum_bytes, summary)
}

/// The summary must come from the immediately preceding actual observation
/// of this same held tree/stream. The second native visit remains a fresh
/// before/after checked observation and must reproduce it exactly.
fn stream_ranges_from_summary(
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    maximum_bytes: u64,
    summary: StreamSupplySummary,
) -> Result<(StreamSupplySummary, Vec<(SupplyKind, SupplyRange)>)> {
    let entry_bytes = (std::mem::size_of::<(SupplyKind, SupplyRange)>() as u64)
        .checked_add(
            (stream.name_utf16.len() as u64)
                .checked_mul(2)
                .context("range name overflow")?,
        )
        .context("range storage overflow")?;
    ensure!(
        summary
            .ranges
            .checked_mul(entry_bytes)
            .is_some_and(|n| n <= maximum_bytes),
        "one live stream supply map exceeds admitted working RAM"
    );
    let mut ranges = Vec::new();
    ranges.try_reserve_exact(usize::try_from(summary.ranges)?)?;
    let observed = template.visit_supply_stream_named(
        index,
        stream.name_utf16,
        &object.path,
        stream.length,
        |kind, range| {
            ranges.push((kind, range.clone()));
            Ok(())
        },
    )?;
    ensure!(
        summary == observed && ranges.len() as u64 == summary.ranges,
        "live supply mapping changed during range observation"
    );
    Ok((summary, ranges))
}

fn user_plan(
    expected: &PagedExpectedTree,
    template: &PrivateTree,
) -> Result<(String, u64, u64, u64, u64)> {
    let mut hash = Sha256::new();
    hash.update(b"n2r-paged-private-user-supply-v1\0");
    let (mut logical, mut materialized, mut referenced, mut holes) = (0u64, 0u64, 0u64, 0u64);
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        // A directory's data streams are its named ones, if any.
        if system(&object) {
            continue;
        }
        for stream in object.data_streams() {
            let summary = observe_stream(template, index, &object, stream)?;
            frame(&mut hash, &summary)?;
            logical = logical
                .checked_add(summary.logical_bytes)
                .context("logical supply overflow")?;
            materialized = materialized
                .checked_add(summary.materialize_bytes)
                .context("materialized supply overflow")?;
            referenced = referenced
                .checked_add(summary.source_reference_bytes)
                .context("reference supply overflow")?;
            holes = holes
                .checked_add(summary.hole_bytes)
                .context("hole supply overflow")?;
        }
    }
    Ok((
        hex::encode(hash.finalize()),
        logical,
        materialized,
        referenced,
        holes,
    ))
}

/// Copy only actual non-reference ranges. The complete live total is checked
/// before the first payload write, then the complete map is checked again.
pub fn materialize_private_supply_plan_domain(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
    template: &mut PrivateTree,
    maximum_bytes: u64,
) -> Result<serde_json::Value> {
    let admission = phase(bytes, expected, template)?;
    let row_window = admission
        .budget
        .max_row_bytes
        .checked_mul(8)
        .context("supply RAM overflow")?;
    let _ram = bytes.lease_working_ram(
        row_window
            .checked_add(admission.budget.max_row_bytes)
            .and_then(|n| n.checked_add(WINDOW as u64))
            .context("supply RAM overflow")?,
    )?;
    let before = user_plan(expected, template)?;
    ensure!(
        before.2 <= maximum_bytes,
        "necessary materialization exceeds explicit payload budget: logical_bytes={}, materialize_bytes={}, source_reference_bytes={}, hole_bytes={}, maximum_materialized_bytes={}, supply_plan_sha256={}",
        before.1,
        before.2,
        before.3,
        before.4,
        maximum_bytes,
        before.0
    );
    let mut buffer = vec![0; WINDOW];
    let (mut written, mut count) = (0u64, 0u64);
    let mut hash = Sha256::new();
    hash.update(b"n2r-paged-private-materialization-v1\0");
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        // A directory's data streams are its named ones, if any.
        if system(&object) {
            continue;
        }
        for stream in object.data_streams() {
            if stream.sparse.is_none() {
                let prefix = n2r_win32::target_cluster::floor(stream.length);
                if prefix != 0 {
                    template.advance_placed_prefix_named(index, stream.name_utf16, prefix)?;
                }
            }
            let (summary, ranges) = stream_ranges(template, index, &object, stream, row_window)?;
            let id = identity(&object, stream);
            for (kind, range) in &ranges {
                if *kind != SupplyKind::Materialize {
                    continue;
                }
                let mut done = 0u64;
                loop {
                    let n = (range.length - done).min(WINDOW as u64) as usize;
                    let offset = range
                        .logical_offset
                        .checked_add(done)
                        .context("materialization offset overflow")?;
                    let read = bytes.read_range_proof(&id, offset, &mut buffer[..n])?;
                    let write = template.materialize_range_named(
                        index,
                        stream.name_utf16,
                        &object.path,
                        stream.length,
                        offset,
                        &buffer[..n],
                    )?;
                    ensure!(
                        write["sha256"] == read.sha256 && write["readback_verified"] == true,
                        "private materialization readback differs from checked source bytes"
                    );
                    bytes.validate_protection()?;
                    frame(
                        &mut hash,
                        &serde_json::json!({"object_index":index,"source":read,"destination":write}),
                    )?;
                    written = written
                        .checked_add(n as u64)
                        .context("materialization total overflow")?;
                    count = count
                        .checked_add(1)
                        .context("materialization count overflow")?;
                    done += n as u64;
                    if done == range.length {
                        break;
                    }
                }
            }
            bytes.finish_stream()?;
            ensure!(
                summary == observe_stream(template, index, &object, stream)?,
                "native mapping changed during stream supply"
            );
        }
    }
    ensure!(
        written == before.2 && before == user_plan(expected, template)?,
        "complete supply mapping/accounting changed"
    );
    phase(bytes, expected, template)?;
    Ok(
        serde_json::json!({"kind":"paged-private-planned-materialization","materialized_bytes":written,
        "receipt_count":count,"ordered_receipt_sha256":hex::encode(hash.finalize()),"live_supply_sha256":before.0,
        "source_payload_writes":0,"logical_hybrid_verification_pending":true,"conversion_qualified":false}),
    )
}

/// Check every materialized byte against current protected-source reads. Known
/// content also receives the complete ordered hybrid hash. Extent-only streams
/// retain a distinct mapping+copied-byte scope, without a fabricated digest.
pub fn verify_private_hybrid_contents_domain(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
    template: &mut PrivateTree,
    policy: VerificationPolicy,
) -> Result<serde_json::Value> {
    let admission = phase(bytes, expected, template)?;
    template.require_system_payloads_complete()?;
    let row_window = admission
        .budget
        .max_row_bytes
        .checked_mul(8)
        .context("hybrid RAM overflow")?;
    let _ram = bytes.lease_working_ram(
        row_window
            .checked_add(admission.budget.max_row_bytes)
            .and_then(|n| n.checked_add(2 * WINDOW as u64))
            .context("hybrid RAM overflow")?,
    )?;
    let before = user_plan(expected, template)?;
    let source_reads_before = bytes.logical_bytes_read();
    let (mut content_streams, mut extent_streams, mut materialized, mut references, mut holes) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut receipts = Sha256::new();
    receipts.update(b"n2r-paged-private-hybrid-verification-v1\0");
    let mut source_buffer = vec![0; WINDOW];
    let mut target_buffer = vec![0; WINDOW];
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        // A directory's data streams are its named ones, if any.
        if system(&object) {
            continue;
        }
        for stream in object.data_streams() {
            ensure!(
                stream.sha256.is_some() || (policy.is_fast() && stream.source_evidence.is_some()),
                "full-content verification requires an actual complete content baseline"
            );
            let (summary, ranges) = stream_ranges(template, index, &object, stream, row_window)?;
            let id = identity(&object, stream);
            let mut content = n2r_win32::content_digest::Hasher::new();
            bytes.check_stream(&id)?;
            let mut copied = Sha256::new();
            copied.update(b"n2r-paged-private-materialized-readback-v1\0");
            for (kind, range) in &ranges {
                match kind {
                    SupplyKind::SourceReference => {
                        bytes.require_reference(
                            &id,
                            range.logical_offset,
                            range
                                .source_physical_offset
                                .context("reference coordinate absent")?,
                            range.length,
                        )?;
                        references = references
                            .checked_add(range.length)
                            .context("reference count overflow")?;
                    }
                    SupplyKind::Hole => {
                        bytes.require_hole(&id, range.logical_offset, range.length)?;
                        holes = holes
                            .checked_add(range.length)
                            .context("hole count overflow")?;
                    }
                    SupplyKind::Materialize => {
                        ensure!(
                            range.source_physical_offset.is_none(),
                            "materialized range carries reference coordinate"
                        );
                        materialized = materialized
                            .checked_add(range.length)
                            .context("materialized count overflow")?;
                    }
                }
                // Fast retained extents are deliberately not read. Every copied
                // byte is read and compared, regardless of the requested policy.
                if *kind != SupplyKind::Materialize && stream.sha256.is_none() {
                    continue;
                }
                let mut done = 0u64;
                while done < range.length {
                    let n = (range.length - done).min(WINDOW as u64) as usize;
                    let offset = range
                        .logical_offset
                        .checked_add(done)
                        .context("hybrid offset overflow")?;
                    match kind {
                        SupplyKind::Hole => {
                            target_buffer[..n].fill(0);
                        }
                        SupplyKind::SourceReference => {
                            bytes.read_into(&id, offset, &mut target_buffer[..n])?;
                        }
                        SupplyKind::Materialize => {
                            bytes.read_into(&id, offset, &mut source_buffer[..n])?;
                            template.read_materialized_range_named(
                                index,
                                stream.name_utf16,
                                offset,
                                &mut target_buffer[..n],
                            )?;
                            ensure!(
                                source_buffer[..n] == target_buffer[..n],
                                "materialized hybrid bytes differ from protected source"
                            );
                            copied.update(offset.to_le_bytes());
                            copied.update((n as u64).to_le_bytes());
                            copied.update(Sha256::digest(&target_buffer[..n]));
                        }
                    }
                    if stream.sha256.is_some() {
                        content.update(&target_buffer[..n]);
                    }
                    done += n as u64;
                }
            }
            let whole = if let Some(wanted) = stream.sha256 {
                let actual = content.finish();
                ensure!(
                    actual == wanted,
                    "complete logical hybrid digest differs from source baseline"
                );
                content_streams = content_streams
                    .checked_add(1)
                    .context("content stream count overflow")?;
                Some(actual)
            } else {
                extent_streams = extent_streams
                    .checked_add(1)
                    .context("extent stream count overflow")?;
                None
            };
            bytes.finish_stream()?;
            ensure!(
                summary == observe_stream(template, index, &object, stream)?,
                "native hybrid mapping changed around verification"
            );
            frame(
                &mut receipts,
                &serde_json::json!({"object_index":index,"stream_name_utf16":stream.name_utf16,
                "record_number":object.record_number,"logical_bytes":stream.length,"whole_content_digest":whole,
                "scope":if whole.is_some(){"complete_logical_content"}else{"extent_identity_and_materialized_bytes"},
                "supply":summary,"materialized_readback_sha256":hex::encode(copied.finalize())}),
            )?;
        }
    }
    ensure!(
        before == user_plan(expected, template)?
            && materialized == before.2
            && references == before.3
            && holes == before.4,
        "complete hybrid mapping/accounting changed"
    );
    phase(bytes, expected, template)?;
    Ok(
        serde_json::json!({"kind":"paged-private-hybrid-verification","success":true,"verification_policy":policy,
        "complete_content_streams":content_streams,"extent_identity_streams":extent_streams,
        "logical_bytes_accounted":before.1,"materialized_bytes_compared":materialized,
        "retained_mapping_bytes_checked":references,"logical_hole_bytes_checked":holes,
        "actual_source_logical_bytes_read":bytes.logical_bytes_read()-source_reads_before,
        "ordered_stream_receipt_sha256":hex::encode(receipts.finalize()),"live_supply_sha256":before.0,
        "source_payload_writes":0,"frozen_metadata_graph_verified":false,
        "source_metadata_restoration_pending":true,"conversion_qualified":false}),
    )
}

fn copy_system_stream(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    object: &Object,
    output: &mut dyn Write,
) -> Result<String> {
    ensure!(
        !object.directory
            && object.sparse.is_none()
            && object.named_streams.is_empty()
            && object.length <= 1024 * 1024,
        "system payload exceeds unchanged preservation profile"
    );
    let wanted = object
        .sha256
        .as_deref()
        .context("system stream content baseline absent")?;
    let stream = object.stream(&[]).context("system DATA absent")?;
    let id = identity(object, stream);
    bytes.check_stream(&id)?;
    let mut hash = n2r_win32::content_digest::Hasher::new();
    let mut buffer = vec![0; WINDOW];
    let mut offset = 0;
    while offset < stream.length {
        let n = (stream.length - offset).min(WINDOW as u64) as usize;
        bytes.read_into(&id, offset, &mut buffer[..n])?;
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
        offset += n as u64;
    }
    bytes.finish_stream()?;
    let actual = hash.finish();
    ensure!(actual == wanted, "complete system source content differs");
    Ok(actual)
}

/// Preserve the existing system-payload phase, using the held paged expected
/// owner and actual DATA sessions rather than reconstructing a legacy Tree.
pub fn materialize_private_system_payloads_paged_domain(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
    template: &mut PrivateTree,
) -> Result<(serde_json::Value, Vec<u8>)> {
    let admission = phase(bytes, expected, template)?;
    let _ram = bytes.lease_working_ram(
        admission
            .budget
            .max_row_bytes
            .checked_add(WINDOW as u64)
            .context("system supply RAM overflow")?,
    )?;
    // Preserve the old full-source preflight before any system destination write.
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        if !object.directory && system(&object) {
            copy_system_stream(bytes, &object, &mut io::sink())?;
        }
    }
    let mut receipt_hash = Sha256::new();
    receipt_hash.update(b"n2r-paged-system-source-transfer-v1\0");
    let mut count = 0u64;
    let native = template.materialize_system_payloads_domain(&PagedInputs(expected), &mut |index, output| {
        let result = (|| -> Result<()> {
            let object = expected.object_leased(index)?;
            ensure!(system(&object),"system writer received unrelated object");
            let digest = copy_system_stream(bytes,&object,output)?;
            frame(&mut receipt_hash,&serde_json::json!({"object_index":index,"logical_bytes":object.length,"content_digest":digest}))?;
            count = count.checked_add(1).context("system receipt count overflow")?;
            Ok(())
        })();
        result.map_err(io::Error::other)
    })?;
    let mut payload = Vec::new();
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        if object.path == ["System Volume Information", "IndexerVolumeGuid"] {
            ensure!(
                payload.is_empty() && !object.directory && object.length == 76,
                "source indexer cache identity/length differs"
            );
            payload.resize(76, 0);
            let stream = object.stream(&[]).context("source indexer DATA absent")?;
            let proof = bytes.read_range_proof(&identity(&object, stream), 0, &mut payload)?;
            ensure!(
                proof.whole_stream_hash_matched,
                "source indexer cache content differs"
            );
        }
    }
    template.require_system_payloads_complete()?;
    phase(bytes, expected, template)?;
    Ok((
        serde_json::json!({"native":native,"source_receipt_count":count,
        "ordered_source_receipt_sha256":hex::encode(receipt_hash.finalize()),
        "source_payload_writes":0,"indexer_payload_present":!payload.is_empty(),
        "indexer_payload_bytes":payload.len(),"conversion_qualified":false}),
        payload,
    ))
}
pub(crate) mod routed;
