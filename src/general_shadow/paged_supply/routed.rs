//! Explicit protected-prefix supply for the V4 diagnostic. Relocated full
//! clusters are routed from the frozen source later; their bytes are not copied
//! into the private shadow. This stage issues no conversion authority.
use super::*;
use crate::shadow_tree::SourceStreamEvidence;

// Fixed receipts and source-range proofs contain only bounded scalars and
// digests. Both data windows are paid separately below. Variable stream-name
// JSON is reserved for its actual UTF-16 length at each framing call.
const ROUTED_RECEIPT_RAM: u64 = 1024 * 1024;

fn frame_ram(
    bytes: &PagedSourceByteAdapter<'_>,
    name_units: usize,
) -> Result<crate::ntfs_inspect::paged_storage::SourceRamLease> {
    let requested = (name_units as u64)
        .checked_mul(128)
        .and_then(|n| n.checked_add(65536))
        .context("routed frame RAM overflow")?;
    bytes.lease_working_ram(requested)
}

#[derive(Clone, Copy)]
enum Piece {
    Reference(u64),
    Routed(u64),
    Materialize,
    Hole,
}

fn eligible_prefix(stream: StreamRef<'_>) -> Result<Option<u64>> {
    let Some(evidence) = stream.source_evidence else {
        return Ok(None);
    };
    ensure!(
        stream.sha256.is_none() && stream.sparse.is_none(),
        "routed prefix requires the explicit plain extent-identity evidence"
    );
    let prefix = stream.length / 4096 * 4096;
    ensure!(
        prefix != 0
            && match evidence {
                SourceStreamEvidence::ExtentIdentityV1 => prefix == stream.length,
                SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1 =>
                    prefix < stream.length,
            },
        "routed prefix evidence and source EOF differ"
    );
    ensure!(
        stream.source_offset.is_some() != !stream.source_extents.is_empty(),
        "routed prefix needs exactly one complete source mapping form"
    );
    Ok(Some(prefix))
}

/// Split a routed logical interval at actual source run boundaries. The
/// caller separately rechecks each resulting VCN/physical pair and source VDL.
fn source_pieces(
    stream: StreamRef<'_>,
    offset: u64,
    length: u64,
    mut emit: impl FnMut(u64, u64, u64) -> Result<()>,
) -> Result<()> {
    if length == 0 {
        return Ok(());
    }
    let end = offset
        .checked_add(length)
        .context("routed source interval overflow")?;
    ensure!(
        offset.is_multiple_of(4096)
            && length.is_multiple_of(4096)
            && end <= stream.length / 4096 * 4096,
        "routed source interval is not a full prefix"
    );
    if let Some(base) = stream.source_offset {
        ensure!(
            stream.source_extents.is_empty() && base.is_multiple_of(4096),
            "routed source offset differs"
        );
        return emit(
            offset,
            length,
            base.checked_add(offset)
                .context("routed physical overflow")?,
        );
    }
    let mut cursor = offset;
    for run in stream.source_extents {
        let run_end = run
            .logical_offset
            .checked_add(run.length)
            .context("routed source run overflow")?;
        if run_end <= cursor {
            continue;
        }
        if cursor == end {
            break;
        }
        ensure!(
            run.logical_offset <= cursor && run.length > 0 && run.length.is_multiple_of(4096),
            "routed source has a gap or unaligned run"
        );
        let physical = run
            .physical_offset
            .context("routed source contains a hole")?
            .checked_add(cursor - run.logical_offset)
            .context("routed physical overflow")?;
        let length = end.min(run_end) - cursor;
        ensure!(
            physical.is_multiple_of(4096) && length.is_multiple_of(4096),
            "routed source physical span is unaligned"
        );
        emit(cursor, length, physical)?;
        cursor += length;
    }
    ensure!(
        cursor == end,
        "routed source prefix is not completely mapped"
    );
    Ok(())
}

fn pieces(
    stream: StreamRef<'_>,
    kind: SupplyKind,
    range: &SupplyRange,
    routed_prefix: Option<u64>,
    mut emit: impl FnMut(Piece, u64, u64) -> Result<()>,
) -> Result<()> {
    if range.length == 0 {
        return Ok(());
    }
    let end = range
        .logical_offset
        .checked_add(range.length)
        .context("supply interval overflow")?;
    ensure!(end <= stream.length, "supply interval escapes stream EOF");
    match kind {
        SupplyKind::SourceReference => emit(
            Piece::Reference(
                range
                    .source_physical_offset
                    .context("reference physical address absent")?,
            ),
            range.logical_offset,
            range.length,
        ),
        SupplyKind::Hole => emit(Piece::Hole, range.logical_offset, range.length),
        SupplyKind::Materialize => {
            ensure!(
                range.source_physical_offset.is_none(),
                "materialized target unexpectedly has source coordinates"
            );
            if let Some(prefix) = routed_prefix {
                let routed_end = end.min(prefix);
                if range.logical_offset < routed_end {
                    source_pieces(
                        stream,
                        range.logical_offset,
                        routed_end - range.logical_offset,
                        |logical, length, physical| emit(Piece::Routed(physical), logical, length),
                    )?;
                }
                if end > prefix {
                    let start = range.logical_offset.max(prefix);
                    emit(Piece::Materialize, start, end - start)?;
                }
                Ok(())
            } else {
                emit(Piece::Materialize, range.logical_offset, range.length)
            }
        }
    }
}

fn routed_in(ranges: &[(SupplyKind, SupplyRange)], prefix: Option<u64>) -> bool {
    prefix.is_some_and(|prefix| {
        ranges.iter().any(|(kind, range)| {
            *kind == SupplyKind::Materialize && range.length != 0 && range.logical_offset < prefix
        })
    })
}

/// The native pre-observation lease pays for the actual held coordinate-map
/// clone. Once its count is observed, reserve the separate returned range
/// vector before asking native code to produce it. Leases outlive the vector.
struct LeasedRanges {
    summary: StreamSupplySummary,
    ranges: Vec<(SupplyKind, SupplyRange)>,
    _range_ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
    native_ram: Option<crate::ntfs_inspect::paged_storage::SourceRamLease>,
}
fn leased_ranges(
    bytes: &PagedSourceByteAdapter<'_>,
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    row_window: u64,
) -> Result<LeasedRanges> {
    let native_bytes = template.supply_stream_workspace_bytes(index, stream.name_utf16)?;
    let native_ram = bytes.lease_working_ram(native_bytes)?;
    let first = observe_stream(template, index, object, stream)?;
    let per_range = (std::mem::size_of::<(SupplyKind, SupplyRange)>() as u64)
        .checked_add(
            (stream.name_utf16.len() as u64)
                .checked_mul(2)
                .context("range name overflow")?,
        )
        .context("range charge overflow")?;
    let exact = first
        .ranges
        .checked_mul(per_range)
        .context("range charge overflow")?;
    ensure!(
        exact <= row_window,
        "one live stream supply map exceeds admitted working RAM"
    );
    // Account for allocator spare capacity and callback/name temporaries.
    let charged = exact
        .checked_mul(2)
        .and_then(|n| n.checked_add(4096))
        .context("range charge overflow")?;
    let range_ram = bytes.lease_working_ram(charged)?;
    let (summary, ranges) = stream_ranges(template, index, object, stream, row_window)?;
    ensure!(
        summary == first,
        "native stream supply changed while reserving workspace"
    );
    let mut actual = (ranges.capacity() as u64)
        .checked_mul(std::mem::size_of::<(SupplyKind, SupplyRange)>() as u64)
        .context("range capacity overflow")?;
    for (_, range) in &ranges {
        ensure!(
            range.stream_name_utf16 == stream.name_utf16,
            "native range stream identity differs"
        );
        actual = actual
            .checked_add(
                (range.stream_name_utf16.capacity() as u64)
                    .checked_mul(2)
                    .context("range name capacity overflow")?,
            )
            .context("range capacity overflow")?;
    }
    ensure!(
        actual <= charged,
        "native range allocation exceeded its pre-admitted workspace"
    );
    Ok(LeasedRanges {
        summary,
        ranges,
        _range_ram: range_ram,
        native_ram: Some(native_ram),
    })
}

/// Unsupported target forms use the existing checked materialization path.
/// Other errors, including a failed revalidation, are never downgraded.
fn route_decision(
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    ranges: &[(SupplyKind, SupplyRange)],
) -> Result<Option<(u64, String)>> {
    let prefix = eligible_prefix(stream)?;
    if !routed_in(ranges, prefix) {
        return Ok(None);
    }
    let prefix = prefix.context("routed prefix absent")?;
    let ready = match template.observe_routed_prefix_named(
        index,
        stream.name_utf16,
        &object.path,
        stream.length,
        prefix,
    ) {
        Ok(ready) => ready,
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ready.revalidate()?;
    Ok(Some((prefix, ready.evidence_sha256().to_owned())))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoutedPlan {
    sha256: String,
    logical: u64,
    referenced: u64,
    routed: u64,
    materialized: u64,
    holes: u64,
}

fn scan_plan(
    bytes: &mut PagedSourceByteAdapter<'_>,
    expected: &PagedExpectedTree,
    template: &PrivateTree,
    row_window: u64,
) -> Result<RoutedPlan> {
    let mut hash = Sha256::new();
    hash.update(b"n2r-private-routed-prefix-plan-v1\0");
    let (mut logical, mut referenced, mut routed, mut materialized, mut holes) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        if object.directory || system(&object) {
            continue;
        }
        for stream in object.data_streams() {
            let id = identity(&object, stream);
            bytes.check_stream(&id)?;
            let mut observed = leased_ranges(bytes, template, index, &object, stream, row_window)?;
            let decision = route_decision(template, index, &object, stream, &observed.ranges)?;
            // The native observations and route proof own their temporary
            // allocations; only the separate range vector remains live.
            drop(observed.native_ram.take());
            let summary = &observed.summary;
            let ranges = &observed.ranges;
            let prefix = decision.as_ref().map(|(prefix, _)| *prefix);
            let target_pin = decision.as_ref().map(|(_, pin)| pin);
            let _frame_ram = frame_ram(bytes, stream.name_utf16.len())?;
            frame(
                &mut hash,
                &serde_json::json!({"object_index":index,"record_number":object.record_number,
                "sequence_number":object.sequence_number,"stream_name_utf16":stream.name_utf16,
                "summary":summary,"target_readiness_sha256":target_pin}),
            )?;
            drop(_frame_ram);
            logical = logical
                .checked_add(summary.logical_bytes)
                .context("routed logical total overflow")?;
            for (kind, range) in ranges {
                pieces(stream, *kind, range, prefix, |piece, offset, length| {
                    match piece {
                        Piece::Reference(physical) => {
                            bytes.require_reference(&id, offset, physical, length)?;
                            referenced = referenced
                                .checked_add(length)
                                .context("reference total overflow")?;
                        }
                        Piece::Routed(physical) => {
                            bytes.require_reference(&id, offset, physical, length)?;
                            routed = routed
                                .checked_add(length)
                                .context("routed total overflow")?;
                        }
                        Piece::Materialize => {
                            materialized = materialized
                                .checked_add(length)
                                .context("materialized total overflow")?
                        }
                        Piece::Hole => {
                            bytes.require_hole(&id, offset, length)?;
                            holes = holes.checked_add(length).context("hole total overflow")?;
                        }
                    }
                    Ok(())
                })?;
            }
            bytes.finish_stream()?;
        }
    }
    ensure!(
        referenced
            .checked_add(routed)
            .and_then(|n| n.checked_add(materialized))
            .and_then(|n| n.checked_add(holes))
            == Some(logical),
        "routed supply does not cover the complete logical domain"
    );
    Ok(RoutedPlan {
        sha256: hex::encode(hash.finalize()),
        logical,
        referenced,
        routed,
        materialized,
        holes,
    })
}

/// Holds the exact source adapter, expected pages and native private tree from
/// preflight through materialization, system supply and final verification.
/// No saved JSON, independent pointer or count can reconstruct this owner.
pub(crate) struct RoutedSupplyOwner<'a, 'source> {
    bytes: &'a mut PagedSourceByteAdapter<'source>,
    expected: &'a PagedExpectedTree,
    template: &'a mut PrivateTree,
    plan: RoutedPlan,
    row_window: u64,
    _ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
}

pub(crate) fn prepare<'a, 'source>(
    bytes: &'a mut PagedSourceByteAdapter<'source>,
    expected: &'a PagedExpectedTree,
    template: &'a mut PrivateTree,
    maximum_materialized_bytes: u64,
    policy: VerificationPolicy,
) -> Result<RoutedSupplyOwner<'a, 'source>> {
    ensure!(
        policy.is_fast(),
        "routed-prefix supply requires explicit extent-identity verification"
    );
    let admission = phase(bytes, expected, template)?;
    let row_window = admission
        .budget
        .max_row_bytes
        .checked_mul(8)
        .context("routed row RAM overflow")?;
    let ram = bytes.lease_working_ram(
        ROUTED_RECEIPT_RAM
            .checked_add(2 * WINDOW as u64)
            .context("routed supply RAM overflow")?,
    )?;
    let plan = scan_plan(bytes, expected, template, row_window)?;
    ensure!(
        plan.materialized <= maximum_materialized_bytes,
        "necessary routed-plan materialization exceeds explicit payload budget: logical_bytes={}, materialize_bytes={}, same_coordinate_reference_bytes={}, routed_prefix_bytes={}, hole_bytes={}, maximum_materialized_bytes={}, supply_plan_sha256={}",
        plan.logical,
        plan.materialized,
        plan.referenced,
        plan.routed,
        plan.holes,
        maximum_materialized_bytes,
        plan.sha256
    );
    let mut buffer = vec![0u8; WINDOW];
    let mut written = 0u64;
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        if object.directory || system(&object) {
            continue;
        }
        for stream in object.data_streams() {
            let id = identity(&object, stream);
            let mut observed = leased_ranges(bytes, template, index, &object, stream, row_window)?;
            let decision = route_decision(template, index, &object, stream, &observed.ranges)?;
            drop(observed.native_ram.take());
            let summary = &observed.summary;
            let ranges = &observed.ranges;
            let prefix = decision.as_ref().map(|(prefix, _)| *prefix);
            for (kind, range) in ranges {
                pieces(stream, *kind, range, prefix, |piece, offset, length| {
                    if !matches!(piece, Piece::Materialize) {
                        return Ok(());
                    }
                    let mut done = 0u64;
                    while done < length {
                        let n = usize::try_from((length - done).min(WINDOW as u64))?;
                        let next_written = written
                            .checked_add(n as u64)
                            .context("routed materialization total overflow")?;
                        ensure!(
                            next_written <= plan.materialized
                                && next_written <= maximum_materialized_bytes,
                            "routed materialization changed or exceeds its preflight budget"
                        );
                        let at = offset
                            .checked_add(done)
                            .context("routed materialization offset overflow")?;
                        let read = bytes.read_range_proof(&id, at, &mut buffer[..n])?;
                        // Sparse materialization can return an island/parts
                        // receipt; retain the original complete-row allowance
                        // only while that native proof is built and consumed.
                        let _sparse_proof_ram = if stream.sparse.is_some() {
                            Some(bytes.lease_working_ram(admission.budget.max_row_bytes)?)
                        } else {
                            None
                        };
                        let write = template.materialize_range_named(
                            index,
                            stream.name_utf16,
                            &object.path,
                            stream.length,
                            at,
                            &buffer[..n],
                        )?;
                        ensure!(
                            write["sha256"] == read.sha256 && write["readback_verified"] == true,
                            "routed remaining materialization readback differs"
                        );
                        bytes.validate_protection()?;
                        written = next_written;
                        done += n as u64;
                    }
                    Ok(())
                })?;
            }
            bytes.finish_stream()?;
            let _closing_native_ram = bytes.lease_working_ram(
                template.supply_stream_workspace_bytes(index, stream.name_utf16)?,
            )?;
            ensure!(
                *summary == observe_stream(template, index, &object, stream)?,
                "native stream mapping changed during routed preparation"
            );
        }
    }
    ensure!(
        written == plan.materialized,
        "routed materialization byte count differs from preflight"
    );
    phase(bytes, expected, template)?;
    Ok(RoutedSupplyOwner {
        bytes,
        expected,
        template,
        plan,
        row_window,
        _ram: ram,
    })
}

impl RoutedSupplyOwner<'_, '_> {
    /// System data remains on the existing checked/materialized path.
    pub(crate) fn materialize_system_payloads(&mut self) -> Result<(serde_json::Value, Vec<u8>)> {
        super::materialize_private_system_payloads_paged_domain(
            self.bytes,
            self.expected,
            self.template,
        )
    }

    /// Verify every required materialized byte and each live source mapping.
    /// The private target still needs the later protected native layout,
    /// validity, exact route, capture and journal checks before any authority.
    pub(crate) fn verify(mut self) -> Result<serde_json::Value> {
        self.template.require_system_payloads_complete()?;
        phase(self.bytes, self.expected, self.template)?;
        let before_reads = self.bytes.logical_bytes_read();
        let (mut logical, mut referenced, mut routed, mut materialized, mut holes) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        let mut source_buffer = vec![0u8; WINDOW];
        let mut target_buffer = vec![0u8; WINDOW];
        let mut receipt_hash = Sha256::new();
        receipt_hash.update(b"n2r-private-routed-prefix-verification-v1\0");
        for index in 0..self.expected.len() {
            let object = self.expected.object_leased(index)?;
            if object.directory || system(&object) {
                continue;
            }
            for stream in object.data_streams() {
                ensure!(
                    stream.sha256.is_some() || stream.source_evidence.is_some(),
                    "routed verification lacks source content or extent evidence"
                );
                let id = identity(&object, stream);
                self.bytes.check_stream(&id)?;
                let mut observed = leased_ranges(
                    self.bytes,
                    self.template,
                    index,
                    &object,
                    stream,
                    self.row_window,
                )?;
                let decision =
                    route_decision(self.template, index, &object, stream, &observed.ranges)?;
                drop(observed.native_ram.take());
                let summary = &observed.summary;
                let ranges = &observed.ranges;
                let prefix = decision.as_ref().map(|(prefix, _)| *prefix);
                logical = logical
                    .checked_add(summary.logical_bytes)
                    .context("routed verification total overflow")?;
                let mut content = n2r_win32::content_digest::Hasher::new();
                for (kind, range) in ranges {
                    pieces(stream, *kind, range, prefix, |piece, offset, length| {
                        match piece {
                            Piece::Reference(physical) => {
                                self.bytes
                                    .require_reference(&id, offset, physical, length)?;
                                referenced = referenced
                                    .checked_add(length)
                                    .context("reference total overflow")?;
                            }
                            Piece::Routed(physical) => {
                                ensure!(
                                    stream.sha256.is_none() && stream.source_evidence.is_some(),
                                    "routed prefix cannot claim an unmeasured content digest"
                                );
                                self.bytes
                                    .require_reference(&id, offset, physical, length)?;
                                routed = routed
                                    .checked_add(length)
                                    .context("routed total overflow")?;
                            }
                            Piece::Materialize => {
                                materialized = materialized
                                    .checked_add(length)
                                    .context("materialized total overflow")?;
                            }
                            Piece::Hole => {
                                self.bytes.require_hole(&id, offset, length)?;
                                holes = holes.checked_add(length).context("hole total overflow")?;
                            }
                        }
                        if !matches!(piece, Piece::Materialize) && stream.sha256.is_none() {
                            return Ok(());
                        }
                        let mut done = 0u64;
                        while done < length {
                            let n = usize::try_from((length - done).min(WINDOW as u64))?;
                            let at = offset
                                .checked_add(done)
                                .context("routed verify offset overflow")?;
                            match piece {
                                Piece::Hole => target_buffer[..n].fill(0),
                                Piece::Reference(_) => {
                                    self.bytes.read_into(&id, at, &mut target_buffer[..n])?
                                }
                                Piece::Routed(_) => anyhow::bail!(
                                    "routed extent unexpectedly requires full-content verification"
                                ),
                                Piece::Materialize => {
                                    self.bytes.read_into(&id, at, &mut source_buffer[..n])?;
                                    self.template.read_materialized_range_named(
                                        index,
                                        stream.name_utf16,
                                        at,
                                        &mut target_buffer[..n],
                                    )?;
                                    ensure!(
                                        source_buffer[..n] == target_buffer[..n],
                                        "routed remaining materialization differs from actual source"
                                    );
                                }
                            }
                            if stream.sha256.is_some() {
                                content.update(&target_buffer[..n]);
                            }
                            done += n as u64;
                        }
                        Ok(())
                    })?;
                }
                let digest = if let Some(wanted) = stream.sha256 {
                    let actual = content.finish();
                    ensure!(
                        actual == wanted,
                        "routed complete logical content digest differs"
                    );
                    Some(actual)
                } else {
                    None
                };
                self.bytes.finish_stream()?;
                let _closing_native_ram = self.bytes.lease_working_ram(
                    self.template
                        .supply_stream_workspace_bytes(index, stream.name_utf16)?,
                )?;
                ensure!(
                    *summary == observe_stream(self.template, index, &object, stream)?,
                    "native stream mapping changed during routed verification"
                );
                let _frame_ram = frame_ram(self.bytes, stream.name_utf16.len())?;
                frame(
                    &mut receipt_hash,
                    &serde_json::json!({"object_index":index,
                    "record_number":object.record_number,"stream_name_utf16":stream.name_utf16,
                    "logical_bytes":stream.length,"complete_content_digest":digest,
                    "supply":summary}),
                )?;
            }
        }
        ensure!(
            logical == self.plan.logical
                && referenced == self.plan.referenced
                && routed == self.plan.routed
                && materialized == self.plan.materialized
                && holes == self.plan.holes,
            "routed verification counts differ from the complete preflight"
        );
        let final_plan = scan_plan(self.bytes, self.expected, self.template, self.row_window)?;
        ensure!(
            final_plan == self.plan,
            "routed source/target mappings changed across preparation"
        );
        phase(self.bytes, self.expected, self.template)?;
        Ok(
            serde_json::json!({"kind":"private-routed-prefix-verification", "success":true,
            "logical_bytes":logical,"same_coordinate_reference_bytes":referenced,
            "relocated_prefix_routed_bytes":routed,"shadow_materialized_bytes":materialized,
            "hole_bytes":holes,"actual_source_logical_bytes_read":self.bytes.logical_bytes_read()-before_reads,
            "ordered_receipt_sha256":hex::encode(receipt_hash.finalize()),"routed_plan_sha256":self.plan.sha256,
            "target_route_capture_pending":true,"journal_copy_literal_split_pending":true,
            "source_payload_writes":0,"source_admitted":false,"execution_authorized":false,
            "conversion_qualified":false}),
        )
    }
}
