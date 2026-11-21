//! Explicit protected-prefix supply for the V4 diagnostic. Relocated full
//! clusters are routed from the frozen source later; their bytes are not copied
//! into the private shadow. This stage issues no conversion authority.
use super::*;
use crate::shadow_tree::{SourceStreamEvidence, pages::LeasedExpectedObject};
use n2r_win32::progress::{Counters, Phase, Reporter, Unit, Update};
use n2r_win32::shadow_native::private_tree::{
    SUPPLY_BATCH_STREAMS, SupplyStreamRequest, SupplyStreamSeen,
};

fn supply_progress(
    reporter: &Reporter,
    phase: Phase,
    pass: u32,
    completed: usize,
    total: usize,
    source_read: u64,
    written: Option<u64>,
) {
    reporter.report(
        Update::new(phase, Unit::Objects, completed as u64, Some(total as u64))
            .with_pass(pass)
            .with_counters(Counters {
                logical_source_bytes_read: Some(source_read),
                payload_bytes_written: written,
                ..Counters::default()
            }),
    );
}

// Fixed receipts and source-range proofs contain only bounded scalars and
// digests. Both data windows are paid separately below. Variable stream-name
// JSON is reserved for its actual UTF-16 length at each framing call.
const ROUTED_RECEIPT_RAM: u64 = 1024 * 1024;

fn frame_ram(
    bytes: &PagedSourceByteAdapterWithScope<'_, '_>,
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
    let prefix = n2r_win32::target_cluster::floor(stream.length);
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

/// Holds a stream to what its run's verification rests on. A thorough run
/// (`--verify thorough`) rests on the digest of every stream's complete
/// contents: the source inspection then recorded one for each stream and
/// proved none by its extents, so [`eligible_prefix`] routes nothing, every
/// whole cluster that moves is written to the shadow and read back, and the
/// verification reads and hashes every stream. A stream that carries only
/// its extents there is refused before anything is materialized, never
/// supplied the way a fast run's would be.
fn require_policy_evidence(policy: VerificationPolicy, stream: StreamRef<'_>) -> Result<()> {
    ensure!(
        policy.is_fast() || stream.sha256.is_some(),
        "--verify thorough rests on the digest of every stream's complete contents; stream {:?} ({} bytes) carries only the identity of its extents",
        String::from_utf16_lossy(stream.name_utf16),
        stream.length
    );
    Ok(())
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
    let cluster = n2r_win32::target_cluster::bytes();
    ensure!(
        offset.is_multiple_of(cluster)
            && length.is_multiple_of(cluster)
            && end <= stream.length / cluster * cluster,
        "routed source interval is not a full prefix"
    );
    if let Some(base) = stream.source_offset {
        ensure!(
            stream.source_extents.is_empty() && base.is_multiple_of(cluster),
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
            run.logical_offset <= cursor && run.length > 0 && run.length.is_multiple_of(cluster),
            "routed source has a gap or unaligned run"
        );
        let physical = run
            .physical_offset
            .context("routed source contains a hole")?
            .checked_add(cursor - run.logical_offset)
            .context("routed physical overflow")?;
        let length = end.min(run_end) - cursor;
        ensure!(
            physical.is_multiple_of(cluster) && length.is_multiple_of(cluster),
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
/// `seen` is what a helper thread saw of this stream where a batch took it
/// ([`StreamsAtOnce`]): the snapshot's two observations of the stream's
/// files are then the helper's, and everything else here is as it is for a
/// stream taken by itself.
fn leased_ranges(
    bytes: &PagedSourceByteAdapterWithScope<'_, '_>,
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    row_window: u64,
    seen: Option<&mut SupplyStreamSeen>,
) -> Result<LeasedRanges> {
    // SDK owns one actual readonly native snapshot and closes its complete
    // source/shadow/file checks before this paid APP clone can escape.
    let result = template.with_readonly_supply_stream_snapshot_seen(
        index,
        stream.name_utf16,
        &object.path,
        stream.length,
        row_window,
        seen,
        |snapshot| {
            (|| -> Result<LeasedRanges> {
                let summary = snapshot.summary().clone();
                ensure!(
                    snapshot.ranges().len() as u64 == summary.ranges,
                    "native snapshot range count differs"
                );
                let per_range = (std::mem::size_of::<(SupplyKind, SupplyRange)>() as u64)
                    .checked_add(
                        (stream.name_utf16.len() as u64)
                            .checked_mul(2)
                            .context("snapshot name charge overflow")?,
                    )
                    .context("snapshot range charge overflow")?;
                let exact = summary
                    .ranges
                    .checked_mul(per_range)
                    .context("snapshot range charge overflow")?;
                ensure!(
                    exact <= row_window,
                    "one native stream snapshot exceeds admitted APP range window"
                );
                let charged = exact
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(4096))
                    .context("snapshot APP allocation overflow")?;
                let range_ram = bytes.lease_working_ram(charged)?;
                let mut ranges = Vec::new();
                ranges.try_reserve_exact(snapshot.ranges().len())?;
                for (kind, range) in snapshot.ranges() {
                    ensure!(
                        range.object_index == index && range.stream_name_utf16 == stream.name_utf16,
                        "native snapshot range belongs to another stream"
                    );
                    ranges.push((*kind, range.clone()));
                }
                let actual = (ranges.capacity() as u64)
                    .checked_mul(std::mem::size_of::<(SupplyKind, SupplyRange)>() as u64)
                    .context("snapshot APP capacity overflow")?;
                let actual = ranges
                    .iter()
                    .try_fold(actual, |n, (_, range)| {
                        n.checked_add((range.stream_name_utf16.capacity() as u64).checked_mul(2)?)
                    })
                    .context("snapshot APP retained name overflow")?;
                ensure!(
                    actual <= charged,
                    "native snapshot clone exceeds its actual APP payment"
                );
                Ok(LeasedRanges {
                    summary,
                    ranges,
                    _range_ram: range_ram,
                    native_ram: None,
                })
            })()
            .map_err(io::Error::other)
        },
    );
    result.with_context(||format!("readonly supply snapshot: object_index={index}, FILE {}/{}, path={:?}, stream={:?}, EOF={}",
        object.record_number,object.sequence_number,object.path,stream.name_utf16,stream.length))
}

/// Unsupported target forms use the existing checked materialization path.
/// Other errors, including a failed revalidation, are never downgraded.
///
/// `seen` is what a helper thread saw of this stream where a batch took it
/// ([`StreamsAtOnce`]): the observation of the prefix and its revalidation
/// are then the helper's, held to the same rules here.
fn route_decision(
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    ranges: &[(SupplyKind, SupplyRange)],
    seen: Option<&mut SupplyStreamSeen>,
) -> Result<Option<(u64, String)>> {
    let prefix = eligible_prefix(stream)?;
    if !routed_in(ranges, prefix) {
        return Ok(None);
    }
    let prefix = prefix.context("routed prefix absent")?;
    let ready = match template.observe_routed_prefix_named_seen(
        index,
        stream.name_utf16,
        &object.path,
        stream.length,
        prefix,
        seen,
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

/// The stream observed again as it closes: [`observe_stream`], where `seen`
/// is what a helper thread saw of this stream if a batch took it. The three
/// comparisons of the file's mapping are then the helper's, and everything
/// else is as it is for a stream taken by itself.
fn closing_stream(
    template: &PrivateTree,
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    seen: Option<&mut SupplyStreamSeen>,
) -> Result<StreamSupplySummary> {
    Ok(template.visit_supply_stream_named_seen(
        index,
        stream.name_utf16,
        &object.path,
        stream.length,
        seen,
        |_, _| Ok(()),
    )?)
}

/// Whether a pass over every stream hands its streams to helper threads in
/// batches. It does where the run verifies each thing once and the tree
/// can take a batch (not with a partition source, whose fences stand around
/// every stream). A thorough run, a diagnosis, `--recheck-everything` and a
/// recovered supply take one stream at a time, as before.
fn observes_at_once(
    bytes: &PagedSourceByteAdapterWithScope<'_, '_>,
    template: &PrivateTree,
    at_once: bool,
) -> Option<crate::artifact_arena::ArtifactArena> {
    if !at_once || !template.observes_supply_streams_at_once() {
        return None;
    }
    bytes
        .metadata_scratch()
        .artifact_group()
        .map(|group| group.arena().clone())
}

/// The objects a pass takes next, from `first` on: one, or with `at_once`
/// as many as have [`SUPPLY_BATCH_STREAMS`] streams to supply between them
/// and the ledger has spare room for, and never more objects than that
/// (directories have no stream to count). What the first object fails with
/// is the pass's error, as it is for an object taken by itself.
fn objects_from(
    expected: &PagedExpectedTree,
    first: usize,
    at_once: bool,
) -> Result<Vec<LeasedExpectedObject>> {
    if !at_once {
        return Ok(vec![expected.object_leased(first)?]);
    }
    let (mut objects, mut streams) = (0usize, 0usize);
    expected.objects_leased_at_once(first, |object| {
        objects += 1;
        if !(object.directory || system(object)) {
            streams += object.data_streams().count();
        }
        objects < SUPPLY_BATCH_STREAMS && streams < SUPPLY_BATCH_STREAMS
    })
}

/// The streams of a batch of objects whose read-only observations of the
/// shadow are made on helper threads.
///
/// Planning and verification ask Windows several hundred things about
/// every stream's file on the shadow, and one thread asked all of them: 80 s
/// and 30 s of the full Windows volume (#140). The streams of the objects
/// held here are handed to the tree [`SUPPLY_BATCH_STREAMS`] at a time
/// (`PrivateTree::observe_supply_streams_at_once`); its helpers make each
/// stream's observations, and the pass then takes the streams in order, as
/// it always did, giving each stream's entry to the functions that observe a
/// stream taken by itself. Those take the helper's result where they would
/// have asked Windows and do everything else themselves, so each stream's
/// checks, their order and the first failure are what they were, and so
/// are the frames the plan and receipt digests are made of.
///
/// A stream no batch took (its workspace was refused, or one of its own
/// checks is about to report) has no entry and is taken by itself.
struct StreamsAtOnce<'a> {
    requests: Vec<SupplyStreamRequest<'a>>,
    streams: Vec<StreamRef<'a>>,
    // How many of them the pass has come to.
    taken: usize,
    // What helpers saw of the streams from `taken` on.
    seen: std::collections::VecDeque<SupplyStreamSeen>,
    closing: bool,
    _ram: Option<crate::artifact_arena::ArenaRamLease>,
}
impl<'a> StreamsAtOnce<'a> {
    /// The supplied streams of `objects`, the first of which is object
    /// `first`, in the order the pass takes them. Without `arena`, or where
    /// it has no spare room for this list, no stream is handed to a batch.
    fn new(
        objects: &'a [LeasedExpectedObject],
        first: usize,
        closing: bool,
        arena: Option<&crate::artifact_arena::ArtifactArena>,
    ) -> Self {
        let mut batch = Self {
            requests: Vec::new(),
            streams: Vec::new(),
            taken: 0,
            seen: std::collections::VecDeque::new(),
            closing,
            _ram: None,
        };
        let Some(arena) = arena else {
            return batch;
        };
        let supplied = || {
            objects
                .iter()
                .enumerate()
                .filter(|(_, object)| !(object.directory || system(object)))
        };
        let count: usize = supplied()
            .map(|(_, object)| object.data_streams().count())
            .sum();
        let entry =
            std::mem::size_of::<SupplyStreamRequest<'_>>() + std::mem::size_of::<StreamRef<'_>>();
        let Ok(ram) = arena.reserve_spare_ram((count * entry) as u64 + 4096) else {
            return batch;
        };
        if batch.requests.try_reserve_exact(count).is_err()
            || batch.streams.try_reserve_exact(count).is_err()
        {
            return batch;
        }
        for (offset, object) in supplied() {
            for stream in object.data_streams() {
                batch.requests.push(SupplyStreamRequest {
                    object_index: first + offset,
                    name_utf16: stream.name_utf16,
                    components: &object.path,
                    logical_length: stream.length,
                });
                batch.streams.push(stream);
            }
        }
        batch._ram = Some(ram);
        batch
    }

    /// What a helper saw of the stream the pass comes to now, if a batch
    /// took it. Called once for every supplied stream, in order.
    fn next(&mut self, template: &PrivateTree, row_window: u64) -> Option<SupplyStreamSeen> {
        if self.taken >= self.requests.len() {
            return None;
        }
        if self.seen.is_empty() {
            let end = (self.taken + SUPPLY_BATCH_STREAMS).min(self.requests.len());
            let streams = &self.streams[self.taken..end];
            // A prefix is observed for exactly the streams `route_decision`
            // observes one for; what `eligible_prefix` refuses is reported
            // there, when the pass comes to the stream.
            self.seen = template
                .observe_supply_streams_at_once(
                    &self.requests[self.taken..end],
                    row_window,
                    self.closing,
                    |slot, ranges| {
                        let prefix = eligible_prefix(streams[slot]).ok().flatten();
                        prefix.filter(|_| routed_in(ranges, prefix))
                    },
                )
                .into();
        }
        self.taken += 1;
        self.seen.pop_front()
    }
}

/// Names the object a supply pass stopped on. The loops that use this run
/// inside a closure only so the failing ordinal is known; their control flow
/// is unchanged.
fn at_object(
    expected: &PagedExpectedTree,
    pass: &str,
    index: usize,
    error: anyhow::Error,
) -> anyhow::Error {
    let path = expected
        .object_leased(index)
        .map(|object| format!("{:?}", object.path))
        .unwrap_or_else(|_| "<path unavailable>".to_owned());
    error.context(format!("{pass}: object {index} path={path}"))
}

/// Check every declared physical source proposal before native target scans.
/// This reads only the already held raw metadata model: no source payload,
/// native file query, disk-role probe, or target observation occurs here.
pub(crate) fn preflight_source_references(
    bytes: &PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
) -> Result<()> {
    use crate::ntfs_inspect::RootFileDomain;
    let raw = bytes.raw_source();
    let admission = expected
        .header()
        .resource_admission
        .context("reference preflight expected admission absent")?;
    ensure!(
        raw.canonical_sha256()? == hex::encode(admission.source_inspection_sha256),
        "reference preflight raw/expected source pin differs"
    );
    // Each record is paid for while it is held, below; this is for the
    // loop's own state. (It was eight of the largest row the budget admits
    // for the whole pass.)
    let _working = bytes.lease_working_ram(65536)?;
    for index in 0..expected.len() {
        let object = expected.object_leased(index)?;
        if object.directory || system(&object) {
            continue;
        }
        for stream in object.data_streams() {
            let prefix = n2r_win32::target_cluster::floor(stream.length);
            if prefix == 0 || (stream.source_offset.is_none() && stream.source_extents.is_empty()) {
                continue;
            }
            let _record_ram =
                bytes.lease_working_ram(raw.record_workspace(object.record_number)?)?;
            let file = raw
                .find_record(object.record_number, Some(object.sequence_number))?
                .with_context(|| {
                    format!(
                        "reference preflight missing FILE {}/{} path={:?}",
                        object.record_number, object.sequence_number, object.path
                    )
                })?;
            let mut source_streams = file
                .streams
                .iter()
                .filter(|s| s.name_utf16 == stream.name_utf16);
            let source = source_streams
                .next()
                .context("reference preflight source DATA stream absent")?;
            ensure!(
                source_streams.next().is_none() && source.logical_size == stream.length,
                "reference preflight source stream coverage/EOF differs: FILE {}/{} path={:?} stream={:?}",
                object.record_number,
                object.sequence_number,
                object.path,
                stream.name_utf16
            );
            let mut attributes = file.attributes.iter().filter(|a| {
                a.type_code == 0x80 && a.name_utf16 == stream.name_utf16 && a.lowest_vcn == 0
            });
            let attribute = attributes
                .next()
                .context("reference preflight base DATA attribute absent")?;
            ensure!(
                attributes.next().is_none()
                    && attribute.flags == source.flags
                    && attribute.resident == source.resident
                    && attribute.logical_size == source.logical_size
                    && attribute.initialized_size == source.initialized_size,
                "reference preflight DATA attribute/model binding differs: FILE {}/{} path={:?} stream={:?}",
                object.record_number,
                object.sequence_number,
                object.path,
                stream.name_utf16
            );
            // Both mappings are ordered by logical position. Retain the raw
            // cursor across proposed runs instead of rescanning from run zero
            // for every fragment (quadratic work on fragmented files).
            let mut previous_source_end = 0u64;
            for run in &source.extents {
                ensure!(
                    run.length > 0 && run.logical_offset >= previous_source_end,
                    "preflight raw source extents overlap or are unordered"
                );
                previous_source_end = run
                    .logical_offset
                    .checked_add(run.length)
                    .context("preflight source extent overflow")?;
            }
            let mut source_index = 0usize;
            let mut previous_reference_end = 0u64;
            let mut check = |offset: u64, physical: u64, length: u64| -> Result<()> {
                let context = || {
                    format!(
                        "declared retained reference preflight: object_index={index}, FILE {}/{}, path={:?}, stream={:?}, flags=0x{:04x}, compression_unit={}, resident={}, VDL={}, EOF={}, offset={offset}, length={length}, physical={physical}",
                        object.record_number,
                        object.sequence_number,
                        object.path,
                        stream.name_utf16,
                        attribute.flags,
                        attribute.compression_unit,
                        attribute.resident,
                        attribute.initialized_size,
                        attribute.logical_size
                    )
                };
                crate::ntfs_inspect::require_initialized_uncompressed_range(
                    attribute, offset, length,
                )
                .with_context(|| context())?;
                let end = offset
                    .checked_add(length)
                    .context("preflight reference end overflow")?;
                ensure!(
                    offset >= previous_reference_end,
                    "{}: declared references overlap or are unordered",
                    context()
                );
                previous_reference_end = end;
                let mut cursor = offset;
                while cursor < end && source_index < source.extents.len() {
                    let run = &source.extents[source_index];
                    let stop = run
                        .logical_offset
                        .checked_add(run.length)
                        .context("preflight source extent overflow")?;
                    if stop <= cursor {
                        source_index += 1;
                        continue;
                    }
                    ensure!(
                        run.logical_offset <= cursor,
                        "{}: source mapping gap",
                        context()
                    );
                    let actual = run
                        .physical_offset
                        .with_context(|| format!("{}: source range is a hole", context()))?
                        .checked_add(cursor - run.logical_offset)
                        .context("preflight actual physical overflow")?;
                    let wanted = physical
                        .checked_add(cursor - offset)
                        .context("preflight wanted physical overflow")?;
                    ensure!(
                        actual == wanted,
                        "{}: current physical mapping differs",
                        context()
                    );
                    cursor = end.min(stop);
                    if cursor == stop {
                        source_index += 1;
                    }
                }
                ensure!(
                    cursor == end,
                    "{}: physical source coverage incomplete",
                    context()
                );
                Ok(())
            };
            if let Some(base) = stream.source_offset {
                ensure!(
                    stream.source_extents.is_empty(),
                    "preflight mixed source mapping forms"
                );
                check(0, base, prefix)?;
            } else {
                for run in stream.source_extents {
                    let end = run
                        .logical_offset
                        .checked_add(run.length)
                        .context("preflight declared extent overflow")?
                        .min(prefix);
                    if run.logical_offset >= end {
                        continue;
                    }
                    if let Some(physical) = run.physical_offset {
                        check(run.logical_offset, physical, end - run.logical_offset)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn scan_plan(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
    template: &PrivateTree,
    row_window: u64,
    policy: VerificationPolicy,
    at_once: bool,
    progress: &Reporter,
) -> Result<RoutedPlan> {
    let mut hash = Sha256::new();
    hash.update(b"n2r-private-routed-prefix-plan-v1\0");
    let (mut logical, mut referenced, mut routed, mut materialized, mut holes) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let failing_object = std::cell::Cell::new(0usize);
    // With an arena here, the streams' observations of the shadow are made
    // by helper threads, a batch of objects at a time ([`StreamsAtOnce`]);
    // without one `held` is one object and nothing is handed to a batch.
    let arena = observes_at_once(bytes, template, at_once);
    let announce = |index: usize| {
        failing_object.set(index);
        supply_progress(
            progress,
            Phase::PayloadSupply,
            1,
            index,
            expected.len(),
            0,
            None,
        );
    };
    (|| -> Result<()> {
        let mut first = 0usize;
        while first < expected.len() {
            announce(first);
            let held = objects_from(expected, first, arena.is_some())?;
            let mut batch = StreamsAtOnce::new(&held, first, false, arena.as_ref());
            for (index, object) in (first..).zip(&held) {
                if index > first {
                    announce(index);
                }
                if object.directory || system(object) {
                    continue;
                }
                for stream in object.data_streams() {
                    let mut seen = batch.next(template, row_window);
                    require_policy_evidence(policy, stream)?;
                    let id = identity(object, stream);
                    bytes.check_stream(&id)?;
                    let mut observed = leased_ranges(
                        bytes,
                        template,
                        index,
                        object,
                        stream,
                        row_window,
                        seen.as_mut(),
                    )?;
                    let decision = route_decision(
                        template,
                        index,
                        object,
                        stream,
                        &observed.ranges,
                        seen.as_mut(),
                    )?;
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
                        &serde_json::json!({"object_index":index,
                    "record_number":object.record_number,
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
                                    holes =
                                        holes.checked_add(length).context("hole total overflow")?;
                                }
                            }
                            Ok(())
                        })?;
                    }
                    bytes.finish_stream()?;
                }
            }
            first += held.len();
        }
        Ok(())
    })()
    .map_err(|error| {
        at_object(
            expected,
            "payload supply planning",
            failing_object.get(),
            error,
        )
    })?;
    ensure!(
        referenced
            .checked_add(routed)
            .and_then(|n| n.checked_add(materialized))
            .and_then(|n| n.checked_add(holes))
            == Some(logical),
        "routed supply does not cover the complete logical domain"
    );
    supply_progress(
        progress,
        Phase::PayloadSupply,
        1,
        expected.len(),
        expected.len(),
        0,
        None,
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
pub(crate) struct RoutedSupplyOwner<'a, 'source, 'scope> {
    bytes: &'a mut PagedSourceByteAdapterWithScope<'source, 'scope>,
    expected: &'a PagedExpectedTree,
    template: &'a mut PrivateTree,
    plan: RoutedPlan,
    row_window: u64,
    recovered: bool,
    /// Whether `verify` reads the payload bytes again. It does not where the
    /// run verifies once and this process supplied the payloads itself.
    reread: bool,
    /// Whether `verify` hands its streams' observations of the shadow to
    /// helper threads ([`StreamsAtOnce`]): where the run verifies once. A
    /// recovered owner, a thorough run and a diagnosis take one stream at a
    /// time.
    at_once: bool,
    progress: Reporter,
    _ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
}

pub(crate) fn prepare<'a, 'source, 'scope>(
    bytes: &'a mut PagedSourceByteAdapterWithScope<'source, 'scope>,
    expected: &'a PagedExpectedTree,
    template: &'a mut PrivateTree,
    maximum_materialized_bytes: u64,
    policy: VerificationPolicy,
    progress: &Reporter,
) -> Result<RoutedSupplyOwner<'a, 'source, 'scope>> {
    // Both verifications are supplied here: the conversion routes have no
    // other supply. What is routed follows each stream's evidence, not the
    // policy. A stream proven by its extents (a fast run's) has the whole
    // clusters that move routed. A thorough run has no such stream
    // (`require_policy_evidence`): its moved clusters are written to the
    // shadow and read back, as those of every hashed stream are. Data that
    // stays where it is is referenced in place in both.
    preflight_source_references(bytes, expected)?;
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
    // The verification hands its streams to helper threads where the run
    // verifies each thing once. Planning takes one stream at a time.
    let at_once = policy.verifies_once();
    let plan = scan_plan(
        bytes, expected, template, row_window, policy, false, progress,
    )?;
    ensure!(
        plan.materialized <= maximum_materialized_bytes,
        "necessary routed-plan materialization exceeds explicit payload budget: logical_bytes={}, materialize_bytes={}, same_coordinate_reference_bytes={}, routed_prefix_bytes={}, hole_bytes={}, maximum_materialized_bytes={}, supply_plan_sha256={}; the data that does not stay where it is needs more working storage than this run has: use a working volume with more free space{}",
        plan.logical,
        plan.materialized,
        plan.referenced,
        plan.routed,
        plan.holes,
        maximum_materialized_bytes,
        plan.sha256,
        if policy.is_fast() {
            ""
        } else {
            ", or --verify fast, which does not copy the whole clusters of a stream it proves by its extents"
        }
    );
    let mut buffer = vec![0u8; WINDOW];
    let mut written = 0u64;
    let before_reads = bytes.logical_bytes_read();
    let failing_object = std::cell::Cell::new(0usize);
    (|| -> Result<()> {
        for index in 0..expected.len() {
            failing_object.set(index);
            supply_progress(
                progress,
                Phase::PayloadSupply,
                2,
                index,
                expected.len(),
                bytes.logical_bytes_read() - before_reads,
                Some(written),
            );
            let object = expected.object_leased(index)?;
            if object.directory || system(&object) {
                continue;
            }
            for stream in object.data_streams() {
                let id = identity(&object, stream);
                let mut observed =
                    leased_ranges(bytes, template, index, &object, stream, row_window, None)?;
                let decision =
                    route_decision(template, index, &object, stream, &observed.ranges, None)?;
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
                                write["sha256"] == read.sha256
                                    && write["readback_verified"] == true,
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
        Ok(())
    })()
    .map_err(|error| {
        at_object(
            expected,
            "payload materialization",
            failing_object.get(),
            error,
        )
    })?;
    ensure!(
        written == plan.materialized,
        "routed materialization byte count differs from preflight"
    );
    supply_progress(
        progress,
        Phase::PayloadSupply,
        2,
        expected.len(),
        expected.len(),
        bytes.logical_bytes_read() - before_reads,
        Some(written),
    );
    phase(bytes, expected, template)?;
    Ok(RoutedSupplyOwner {
        bytes,
        expected,
        template,
        plan,
        row_window,
        recovered: false,
        reread: !policy.verifies_once(),
        at_once,
        progress: progress.clone(),
        _ram: ram,
    })
}

/// Reuse completed payloads only after fresh native adoption and full source/
/// target verification. The prior plan digest is an authenticated selector;
/// this constructor performs no materialization or system stream writes.
pub(crate) fn prepare_recovered<'a, 'source, 'scope>(
    bytes: &'a mut PagedSourceByteAdapterWithScope<'source, 'scope>,
    expected: &'a PagedExpectedTree,
    template: &'a mut PrivateTree,
    maximum_materialized_bytes: u64,
    policy: VerificationPolicy,
    prior_plan_sha256: &str,
    progress: &Reporter,
) -> Result<RoutedSupplyOwner<'a, 'source, 'scope>> {
    // Only a fast run's preparation is resumed: its checkpoints are written
    // for that policy alone and a saved session of another is refused
    // (`resource_preparation`, `resume_session_inputs`, `resume_origin`). A
    // thorough run therefore never comes here.
    ensure!(
        policy.is_fast(),
        "recovered routed supply requires extent identity policy"
    );
    preflight_source_references(bytes, expected)?;
    let admission = phase(bytes, expected, template)?;
    let row_window = admission
        .budget
        .max_row_bytes
        .checked_mul(8)
        .context("recovered routed row RAM overflow")?;
    let ram = bytes.lease_working_ram(
        ROUTED_RECEIPT_RAM
            .checked_add(2 * WINDOW as u64)
            .context("recovered routed supply RAM overflow")?,
    )?;
    // A recovered supply takes one stream at a time, as before.
    let plan = scan_plan(
        bytes, expected, template, row_window, policy, false, progress,
    )?;
    ensure!(
        plan.materialized <= maximum_materialized_bytes && plan.sha256 == prior_plan_sha256,
        "recovered payload plan differs from the authenticated completed supply"
    );
    template.revalidate_recovered_system_payloads_domain(&PagedInputs(expected))?;
    Ok(RoutedSupplyOwner {
        bytes,
        expected,
        template,
        plan,
        row_window,
        recovered: true,
        reread: true,
        at_once: false,
        progress: progress.clone(),
        _ram: ram,
    })
}

impl RoutedSupplyOwner<'_, '_, '_> {
    /// System data remains on the existing checked/materialized path.
    pub(crate) fn materialize_system_payloads(&mut self) -> Result<(serde_json::Value, Vec<u8>)> {
        ensure!(
            !self.recovered,
            "recovered payload owner permits verification only"
        );
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
        // Every byte materialized on the shadow was read back and held to
        // the source's when it was written (`prepare`), and a stream with a
        // digest is read in full on the converted volume after the apply.
        // Under "verify once" this pass therefore reads no payload: it still
        // walks every stream's mapping on both sides, which is what the plan
        // digest in its receipt is made from.
        let reread = self.reread;
        let (mut logical, mut referenced, mut routed, mut materialized, mut holes) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        let mut source_buffer = vec![0u8; WINDOW];
        let mut target_buffer = vec![0u8; WINDOW];
        let mut receipt_hash = Sha256::new();
        receipt_hash.update(b"n2r-private-routed-prefix-verification-v1\0");
        let mut plan_hash = Sha256::new();
        plan_hash.update(b"n2r-private-routed-prefix-plan-v1\0");
        let failing_object = std::cell::Cell::new(0usize);
        // Where no payload is read again, this pass only observes: every
        // stream's files on the shadow, and the source's mapping from the
        // raw model. The observations of the shadow are then made by helper
        // threads, a batch of objects at a time ([`StreamsAtOnce`]), and
        // taken here in order. Otherwise `held` is one object and nothing is
        // handed to a batch.
        let arena = observes_at_once(self.bytes, self.template, self.at_once && !reread);
        (|| -> Result<()> {
        let mut first = 0usize;
        while first < self.expected.len() {
            failing_object.set(first);
            supply_progress(&self.progress,Phase::PayloadVerification,0,first,self.expected.len(),self.bytes.logical_bytes_read()-before_reads,None);
            let held = objects_from(self.expected, first, arena.is_some())?;
            let mut batch = StreamsAtOnce::new(&held, first, true, arena.as_ref());
            for (index, object) in (first..).zip(&held) {
                if index > first {
                    failing_object.set(index);
                    supply_progress(&self.progress,Phase::PayloadVerification,0,index,self.expected.len(),self.bytes.logical_bytes_read()-before_reads,None);
                }
                if object.directory || system(object) {
                    continue;
                }
                for stream in object.data_streams() {
                    let mut seen = batch.next(self.template, self.row_window);
                    ensure!(
                        stream.sha256.is_some() || stream.source_evidence.is_some(),
                        "routed verification lacks source content or extent evidence"
                    );
                    let id = identity(object, stream);
                    self.bytes.check_stream(&id)?;
                    let mut observed = leased_ranges(
                        self.bytes,
                        self.template,
                        index,
                        object,
                        stream,
                        self.row_window,
                        seen.as_mut(),
                    )?;
                    let decision = route_decision(
                        self.template,
                        index,
                        object,
                        stream,
                        &observed.ranges,
                        seen.as_mut(),
                    )?;
                    drop(observed.native_ram.take());
                    let summary = &observed.summary;
                    let ranges = &observed.ranges;
                    let prefix = decision.as_ref().map(|(prefix, _)| *prefix);
                    let target_pin=decision.as_ref().map(|(_,pin)|pin);
                    let plan_frame_ram=frame_ram(self.bytes,stream.name_utf16.len())?;
                    frame(&mut plan_hash,&serde_json::json!({"object_index":index,"record_number":object.record_number,
                        "sequence_number":object.sequence_number,"stream_name_utf16":stream.name_utf16,
                        "summary":summary,"target_readiness_sha256":target_pin}))?;
                    drop(plan_frame_ram);
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
                            if !reread {
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
                                        if self.recovered {
                                            self.template.revalidate_recovered_materialized_tail_named(
                                                index,stream.name_utf16,&object.path,stream.length,at,&source_buffer[..n])?;
                                        }
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
                    let digest = if !reread {
                        // Nothing was read: no digest is claimed.
                        None
                    } else if let Some(wanted) = stream.sha256 {
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
                    // The workspace of the closing observation's mapping
                    // queries. Where a batch's helper made them, they ran under
                    // what the batch reserved for the stream, which `seen`
                    // holds until the stream is done.
                    let _closing_native_ram = if seen
                        .as_ref()
                        .is_some_and(SupplyStreamSeen::closing_observed)
                    {
                        None
                    } else {
                        Some(self.bytes.lease_working_ram(
                            self.template
                                .supply_stream_workspace_bytes(index, stream.name_utf16)?,
                        )?)
                    };
                    ensure!(
                        *summary
                            == closing_stream(self.template, index, object, stream, seen.as_mut())?,
                        "native stream mapping changed during routed verification"
                    );
                    ensure!(route_decision(self.template,index,object,stream,ranges,seen.as_mut())?==decision,
                        "native routed prefix readiness changed during verification");
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
            first += held.len();
        }
        Ok(())
        })()
        .map_err(|error| at_object(self.expected, "payload verification", failing_object.get(), error))?;
        ensure!(
            logical == self.plan.logical
                && referenced == self.plan.referenced
                && routed == self.plan.routed
                && materialized == self.plan.materialized
                && holes == self.plan.holes,
            "routed verification counts differ from the complete preflight"
        );
        let final_plan = RoutedPlan {
            sha256: hex::encode(plan_hash.finalize()),
            logical,
            referenced,
            routed,
            materialized,
            holes,
        };
        ensure!(
            final_plan == self.plan,
            "routed source/target mappings changed across preparation"
        );
        supply_progress(
            &self.progress,
            Phase::PayloadVerification,
            0,
            self.expected.len(),
            self.expected.len(),
            self.bytes.logical_bytes_read() - before_reads,
            None,
        );
        phase(self.bytes, self.expected, self.template)?;
        let mut receipt = serde_json::json!({"kind":"private-routed-prefix-verification", "success":true,
            "logical_bytes":logical,"same_coordinate_reference_bytes":referenced,
            "relocated_prefix_routed_bytes":routed,"shadow_materialized_bytes":materialized,
            "hole_bytes":holes,"actual_source_logical_bytes_read":self.bytes.logical_bytes_read()-before_reads,
            "ordered_receipt_sha256":hex::encode(receipt_hash.finalize()),"routed_plan_sha256":self.plan.sha256,
            "target_route_capture_pending":true,"journal_copy_literal_split_pending":true,
            "source_payload_writes":0,"source_admitted":false,"execution_authorized":false,
            "completed_payloads_reused":self.recovered,"payload_bytes_rematerialized":if self.recovered {Some(0u64)}else{None},
            "conversion_qualified":false});
        if !reread {
            receipt["payload_bytes_reread"] = false.into();
            receipt["payload_contents_held_by"] =
                "read-back at materialization; complete digests on the converted volume".into();
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream<'a>(
        sha256: Option<&'a str>,
        source_evidence: Option<SourceStreamEvidence>,
    ) -> StreamRef<'a> {
        StreamRef {
            name_utf16: &[],
            source_offset: Some(1 << 20),
            source_extents: &[],
            length: 8192,
            sha256,
            source_evidence,
            sparse: None,
        }
    }

    /// #212: the supply refused `--verify thorough` outright, so no thorough
    /// run converted. A thorough run's streams all carry a digest and are
    /// supplied; none of them is routed by its extents.
    #[test]
    fn a_thorough_run_is_supplied_and_routes_nothing_by_its_extents() {
        let digest = "00".repeat(32);
        let hashed = stream(Some(&digest), None);
        let by_extents = stream(None, Some(SourceStreamEvidence::ExtentIdentityV1));
        for policy in [
            VerificationPolicy::FullContent,
            VerificationPolicy::ExtentIdentityV1,
        ] {
            require_policy_evidence(policy, hashed).unwrap();
            assert_eq!(eligible_prefix(hashed).unwrap(), None);
        }
        // Only a fast run has a stream proven by its extents, and routes it.
        require_policy_evidence(VerificationPolicy::ExtentIdentityV1, by_extents).unwrap();
        assert_eq!(eligible_prefix(by_extents).unwrap(), Some(8192));
        let refusal = require_policy_evidence(VerificationPolicy::FullContent, by_extents)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("--verify thorough"), "{refusal}");
    }
}
