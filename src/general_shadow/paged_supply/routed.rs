//! Explicit protected-prefix supply for the V4 diagnostic. Relocated full
//! clusters are routed from the frozen source later; their bytes are not copied
//! into the private shadow. This stage issues no conversion authority.
use super::*;
use crate::general_shadow::source_backed::{TAIL_BATCH, TAIL_BATCH_BYTES, tail_place};
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
    ///
    /// A batch begins with the stream the pass comes to now, once every
    /// entry of the one before has been taken. Every call moves `taken` on
    /// by one, entry or not: where the batch could not take even its first
    /// stream it is empty, that stream is taken by itself (`None`), and the
    /// next call begins a batch with the stream after it. So no stream is
    /// handed over more than twice (behind others, then first), and each is
    /// observed once: by a helper where it has an entry, and otherwise by
    /// the pass.
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

    /// Takes what a helper already saw of this batch's first streams
    /// ([`ObservedAhead`]), as the first observation [`Self::next`] makes
    /// would have returned it. Nothing is taken where this batch hands no
    /// stream over, or has begun: the streams are then taken as before.
    fn seen_ahead(&mut self, seen: Vec<SupplyStreamSeen>) {
        if self.taken == 0 && self.seen.is_empty() && seen.len() <= self.requests.len() {
            self.seen = seen.into();
        }
    }
}

/// The observations of the next batch's first streams, made by the tree's
/// helpers while the planning pass takes the batch before it.
///
/// The planning pass handed a batch's streams to the tree's helpers
/// ([`StreamsAtOnce`]) and waited for them, and the helpers then waited
/// while the pass took the batch's streams one by one (the source's side of
/// each, its frames and its counts). Here the pass makes the next batch
/// ready before it takes this one, exactly as [`StreamsAtOnce::next`] does
/// when it comes to that batch (the same streams in the same order, the same
/// reservations of spare memory, the same function), and the helpers
/// observe while the pass takes this batch. The pass then takes their
/// results as it takes what it asked for itself
/// ([`StreamsAtOnce::seen_ahead`]); every check is made where it was, in the
/// same order. The planning pass only observes: it writes nothing to the
/// shadow, so what a helper sees of a stream before the pass comes to it is
/// what the pass would have seen. Where the next objects cannot be held now,
/// or nothing is handed over, the next batch is taken as before.
struct ObservedAhead<'scope> {
    objects: Vec<LeasedExpectedObject>,
    seen: Option<std::thread::ScopedJoinHandle<'scope, Vec<SupplyStreamSeen>>>,
}
impl<'scope> ObservedAhead<'scope> {
    /// Makes the first streams of `objects` (the first of which is object
    /// `first`) ready and starts their observation on a thread of `scope`.
    fn start<'tree: 'scope>(
        scope: &'scope std::thread::Scope<'scope, '_>,
        template: &'tree PrivateTree,
        objects: Vec<LeasedExpectedObject>,
        first: usize,
        row_window: u64,
    ) -> Self {
        let mut requests = Vec::new();
        let mut streams = Vec::new();
        'objects: for (offset, object) in objects.iter().enumerate() {
            if object.directory || system(object) {
                continue;
            }
            for stream in object.data_streams() {
                if requests.len() == SUPPLY_BATCH_STREAMS {
                    break 'objects;
                }
                requests.push(SupplyStreamRequest {
                    object_index: first + offset,
                    name_utf16: stream.name_utf16,
                    components: &object.path,
                    logical_length: stream.length,
                });
                streams.push(stream);
            }
        }
        // A prefix is observed for exactly the streams `StreamsAtOnce::next`
        // observes one for.
        let seen = if requests.is_empty() {
            None
        } else {
            template.observe_supply_streams_ahead(
                scope,
                &requests,
                row_window,
                false,
                |slot, ranges| {
                    let prefix = eligible_prefix(streams[slot]).ok().flatten();
                    prefix.filter(|_| routed_in(ranges, prefix))
                },
            )
        };
        drop(requests);
        drop(streams);
        Self { objects, seen }
    }

    /// The objects and what the helpers saw of their first streams (nothing
    /// where nothing was handed over). A helper that panicked is not hidden:
    /// its panic is carried on here, on the pass's thread, as a helper's of a
    /// batch the pass waits for is (`ordered_observation::observe_batch`);
    /// it may have left a lock of the ledger poisoned.
    fn finish(self) -> (Vec<LeasedExpectedObject>, Vec<SupplyStreamSeen>) {
        let seen = match self.seen.map(std::thread::ScopedJoinHandle::join) {
            Some(Ok(seen)) => seen,
            Some(Err(panic)) => std::panic::resume_unwind(panic),
            None => Vec::new(),
        };
        (self.objects, seen)
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

/// One stream's frame of the ordered receipt of the supply's verification
/// ([`RoutedSupplyOwner::verify`]); the planning pass of a run that
/// verifies each thing once makes the same frames ([`scan_plan`]).
fn receipt_frame(
    index: usize,
    object: &Object,
    stream: StreamRef<'_>,
    complete_content_digest: Option<String>,
    summary: &StreamSupplySummary,
) -> serde_json::Value {
    serde_json::json!({"object_index":index,
        "record_number":object.record_number,"stream_name_utf16":stream.name_utf16,
        "logical_bytes":stream.length,"complete_content_digest":complete_content_digest,
        "supply":summary})
}

type MaterializedPlan = std::collections::BTreeMap<
    (usize, usize),
    (
        n2r_win32::shadow_native::private_tree::StreamSupplySummary,
        Vec<(u64, u64)>,
    ),
>;

/// The plan of the streams whose bytes are written to the shadow, with the
/// memory it holds paid for. It keeps an entry for every such stream of the
/// volume from planning until the supply is verified (some 97,000 on the
/// full Windows volume, about 20 MB), so it is leased as it grows (#268),
/// in steps of at least [`MATERIALIZED_LEASE_STEP`].
#[derive(Default)]
struct LeasedMaterializedPlan {
    plan: MaterializedPlan,
    held: u64,
    leased: u64,
    leases: Vec<crate::ntfs_inspect::paged_storage::SourceRamLease>,
}
impl std::ops::Deref for LeasedMaterializedPlan {
    type Target = MaterializedPlan;
    fn deref(&self) -> &MaterializedPlan {
        &self.plan
    }
}
impl LeasedMaterializedPlan {
    /// Pays for `more` bytes the plan is about to hold.
    fn hold(&mut self, more: u64, bytes: &PagedSourceByteAdapterWithScope<'_, '_>) -> Result<()> {
        self.held = self
            .held
            .checked_add(more)
            .context("materialized plan RAM overflow")?;
        if self.held > self.leased {
            let step = (self.held - self.leased).max(MATERIALIZED_LEASE_STEP);
            self.leases.push(bytes.lease_working_ram(step)?);
            self.leased = self
                .leased
                .checked_add(step)
                .context("materialized plan RAM overflow")?;
        }
        Ok(())
    }
}
const MATERIALIZED_LEASE_STEP: u64 = 1024 * 1024;
/// One interval of a stream's plan, with the room its list grows into.
const MATERIALIZED_INTERVAL_BYTES: u64 = 2 * std::mem::size_of::<(u64, u64)>() as u64;
/// One stream's entry besides its intervals: its key and summary, the text
/// of the summary's digest, and half as much again for the map's nodes.
fn materialized_entry_bytes(
    summary: &n2r_win32::shadow_native::private_tree::StreamSupplySummary,
) -> u64 {
    let entry = std::mem::size_of::<(usize, usize)>()
        + std::mem::size_of::<(
            n2r_win32::shadow_native::private_tree::StreamSupplySummary,
            Vec<(u64, u64)>,
        )>()
        + summary.ordered_range_sha256.capacity();
    (entry + entry / 2) as u64
}

#[allow(clippy::too_many_arguments)]
fn scan_plan(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
    template: &PrivateTree,
    row_window: u64,
    policy: VerificationPolicy,
    at_once: bool,
    progress: &Reporter,
) -> Result<(RoutedPlan, LeasedMaterializedPlan, Option<String>)> {
    let mut hash = Sha256::new();
    hash.update(b"n2r-private-routed-prefix-plan-v1\0");
    // A run that verifies each thing once (`at_once`) does not observe the
    // shadow's streams again when it verifies the supply
    // ([`RoutedSupplyOwner::verify`]): the frames of that pass's ordered
    // receipt are made here instead, from this pass's observation of each
    // stream, which is what that pass held its own to. Nothing was read
    // there in such a run, so no stream's frame claims a content digest.
    let mut receipt_hash = at_once.then(|| {
        let mut receipt = Sha256::new();
        receipt.update(b"n2r-private-routed-prefix-verification-v1\0");
        receipt
    });
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
    let mut materialized_streams = LeasedMaterializedPlan::default();
    std::thread::scope(|scope| -> Result<()> {
        // The next batch, observed by the tree's helpers while this one is
        // taken.
        let mut ahead: Option<ObservedAhead<'_>> = None;
        let planned = (|| -> Result<()> {
            let mut first = 0usize;
            while first < expected.len() {
                announce(first);
                let (held, seen) = match ahead.take() {
                    Some(ahead) => ahead.finish(),
                    None => (objects_from(expected, first, arena.is_some())?, Vec::new()),
                };
                let mut batch = StreamsAtOnce::new(&held, first, false, arena.as_ref());
                batch.seen_ahead(seen);
                let after = first + held.len();
                // What the next batch's first object fails with is reported when
                // the pass comes to it.
                if arena.is_some()
                    && after < expected.len()
                    && let Ok(next) = objects_from(expected, after, true)
                {
                    ahead = Some(ObservedAhead::start(
                        scope, template, next, after, row_window,
                    ));
                }
                for (index, object) in (first..).zip(&held) {
                    if index > first {
                        announce(index);
                    }
                    if object.directory || system(object) {
                        continue;
                    }
                    for (stream_ordinal, stream) in object.data_streams().enumerate() {
                        let mut seen = batch.next(template, row_window);
                        require_policy_evidence(policy, stream)?;
                        // The verification's own check of the stream's evidence,
                        // made here where that pass no longer takes the stream.
                        ensure!(
                            receipt_hash.is_none()
                                || stream.sha256.is_some()
                                || stream.source_evidence.is_some(),
                            "routed verification lacks source content or extent evidence"
                        );
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
                        if let Some(receipt) = receipt_hash.as_mut() {
                            // The frame `verify` makes of the stream, field for field.
                            frame(
                                receipt,
                                &receipt_frame(index, object, stream, None, summary),
                            )?;
                        }
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
                                        ensure!(
                                            receipt_hash.is_none()
                                                || (stream.sha256.is_none()
                                                    && stream.source_evidence.is_some()),
                                            "routed prefix cannot claim an unmeasured content digest"
                                        );
                                        bytes.require_reference(&id, offset, physical, length)?;
                                        routed = routed
                                            .checked_add(length)
                                            .context("routed total overflow")?;
                                    }
                                    Piece::Materialize => {
                                        let key = (index, stream_ordinal);
                                        let more = if materialized_streams.contains_key(&key) {
                                            MATERIALIZED_INTERVAL_BYTES
                                        } else {
                                            materialized_entry_bytes(summary)
                                                .checked_add(MATERIALIZED_INTERVAL_BYTES)
                                                .context("materialized plan RAM overflow")?
                                        };
                                        materialized_streams.hold(more, bytes)?;
                                        materialized_streams
                                            .plan
                                            .entry(key)
                                            .or_insert_with(|| (summary.clone(), Vec::new()))
                                            .1
                                            .push((offset, length));
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
                first = after;
            }
            Ok(())
        })();
        // Where the pass stops early, the helpers still observing are waited
        // for and what they saw is let go before the pass reports.
        if let Some(ahead) = ahead.take() {
            drop(ahead.finish());
        }
        planned
    })
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
    Ok((
        RoutedPlan {
            sha256: hex::encode(hash.finalize()),
            logical,
            referenced,
            routed,
            materialized,
            holes,
        },
        materialized_streams,
        receipt_hash.map(|receipt| hex::encode(receipt.finalize())),
    ))
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
    /// The ordered receipt digest of `verify`, made by the planning pass of
    /// a run that verifies each thing once: such a run's `verify` observes
    /// no stream of the shadow again.
    planned_receipt: Option<String>,
    progress: Reporter,
    supplied_tails: Option<crate::ntfs_inspect::record_store::SortedRecordStore>,
    _ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
}

fn supplied_tail_key(object: u64, stream: u64) -> [u8; 16] {
    let mut out = [0; 16];
    out[..8].copy_from_slice(&object.to_be_bytes());
    out[8..].copy_from_slice(&stream.to_be_bytes());
    out
}

/// Tails within this many bytes of each other on the disk are read as one
/// span, the bytes between them too.
const TAIL_COALESCE_GAP: u64 = 64 * 1024;
/// The longest span one lane read makes.
const TAIL_COALESCE_MAX: u64 = 1024 * 1024;

/// The lane reads of `asks` (each a tail's place on the disk and its length,
/// sorted by place): neighbours within [`TAIL_COALESCE_GAP`] are read as one
/// span of at most [`TAIL_COALESCE_MAX`] bytes, gaps included, as long as
/// every span's bytes, gaps included, stay within `limit`. Each span is its
/// start, its length and the end of its tails in `asks`.
///
/// A span holds the bytes between its tails as well as theirs, and all of a
/// batch's spans are read at once (#265): counting only the tails let 8,192
/// of them, merged across gaps of up to 64 KiB, hold some 528 MiB against
/// the 16 MiB reserved for them. Here a merge is made only where what it
/// adds, with every tail still to come counted at its own length, fits
/// `limit`; a tail that may not be merged starts a span of its own. Where
/// the tails alone fit `limit`, every tail is read. A tail that would not
/// fit even alone is not asked for (its stream reads it as before).
fn tail_spans(asks: &[(u64, u32)], limit: u64) -> Vec<(u64, u64, usize)> {
    let mut remaining: u64 = asks.iter().map(|&(_, count)| u64::from(count)).sum();
    let mut total = 0u64;
    let mut spans = Vec::new();
    let mut next = 0usize;
    while next < asks.len() {
        let (start, count) = asks[next];
        let count = u64::from(count);
        remaining -= count;
        if total.saturating_add(count) > limit {
            break;
        }
        total += count;
        let mut end = start.saturating_add(count);
        next += 1;
        while next < asks.len() {
            let (place, count) = asks[next];
            let count = u64::from(count);
            if place > end.saturating_add(TAIL_COALESCE_GAP) {
                break;
            }
            let merged_end = end.max(place.saturating_add(count));
            if merged_end - start > TAIL_COALESCE_MAX {
                break;
            }
            let added = merged_end - end;
            let rest = remaining - count;
            if total.saturating_add(added).saturating_add(rest) > limit {
                break;
            }
            total += added;
            remaining = rest;
            end = merged_end;
            next += 1;
        }
        spans.push((start, end - start, next));
    }
    spans
}

/// One lane read of a batch's tails, and how many of the batch's tails are
/// still to take bytes from it: its bytes are let go with the last.
struct TailSpan {
    ticket: Option<u64>,
    bytes: Option<Vec<u8>>,
    left: u32,
}
/// Where one stream's tail lies in the lane reads of its batch.
struct TailSlot {
    index: usize,
    ordinal: usize,
    place: u64,
    count: u32,
    span: u32,
    rel: u32,
}
/// No span: the tail was not asked for.
const NO_SPAN: u32 = u32::MAX;

/// The tails of one batch asked of the source's lanes, in the order the pass
/// takes their streams, and the lease of the spans' bytes beyond what
/// [`super::super::source_backed::tails_ahead`] reserved for a batch.
struct TailBatchReads {
    spans: Vec<TailSpan>,
    slots: Vec<TailSlot>,
    next: usize,
    _beyond: Option<crate::artifact_arena::ArenaRamLease>,
}
impl TailBatchReads {
    /// Asks the lanes for the tail of every stream of `held` (the first of
    /// which is object `first`) that the plan materializes, as many as one
    /// batch takes ([`TAIL_BATCH`], [`TAIL_BATCH_BYTES`] of tails), in their
    /// order on the disk.
    ///
    /// The spans' bytes, gaps included, are held to what is leased for
    /// them: [`TAIL_BATCH_BYTES`], reserved with the lanes, and what the
    /// spans need beyond that where the ledger grants it as spare memory.
    /// Where it does not, the spans are coalesced within
    /// [`TAIL_BATCH_BYTES`] ([`tail_spans`]). Every span is asked at once,
    /// so what the lanes read and hold, in their results too, is never more
    /// than that.
    fn ask(
        reads: &mut super::super::source_backed::original_prefetch::LaneReads,
        arena: Option<&crate::artifact_arena::ArtifactArena>,
        bytes: &PagedSourceByteAdapterWithScope<'_, '_>,
        held: &[LeasedExpectedObject],
        first: usize,
        planned: &MaterializedPlan,
    ) -> Self {
        let cluster = n2r_win32::target_cluster::bytes();
        let mut slots = Vec::new();
        let mut asked_bytes = 0u64;
        for (index, object) in (first..).zip(held) {
            if object.directory || system(object) {
                continue;
            }
            for (stream_ordinal, stream) in object.data_streams().enumerate() {
                let offset = stream.length / cluster * cluster;
                let count = stream.length - offset;
                if count == 0
                    || !planned.contains_key(&(index, stream_ordinal))
                    || slots.len() >= TAIL_BATCH
                    || asked_bytes + count > TAIL_BATCH_BYTES
                {
                    continue;
                }
                let place = tail_place(&stream, offset, count).or_else(|| {
                    use crate::ntfs_inspect::source_domain::RootFileDomain;
                    bytes
                        .raw_source()
                        .find_record_shared(object.record_number, Some(object.sequence_number))
                        .ok()
                        .flatten()
                        .and_then(|file| {
                            let raw_stream = file
                                .streams
                                .iter()
                                .find(|s| s.name_utf16 == stream.name_utf16)?;
                            if raw_stream.resident || raw_stream.flags != 0 {
                                return None;
                            }
                            let end = offset.checked_add(count)?;
                            let run = raw_stream.extents.iter().find(|run| {
                                run.logical_offset <= offset
                                    && run
                                        .logical_offset
                                        .checked_add(run.length)
                                        .is_some_and(|stop| end <= stop)
                            })?;
                            run.physical_offset?
                                .checked_add(offset - run.logical_offset)
                        })
                });
                if let (Some(place), Ok(count)) = (place, u32::try_from(count)) {
                    asked_bytes += u64::from(count);
                    slots.push(TailSlot {
                        index,
                        ordinal: stream_ordinal,
                        place,
                        count,
                        span: NO_SPAN,
                        rel: 0,
                    });
                }
            }
        }
        // The slots in their order on the disk.
        let mut order: Vec<u32> = (0..slots.len() as u32).collect();
        order.sort_unstable_by_key(|&slot| (slots[slot as usize].place, slot));
        let sorted: Vec<(u64, u32)> = order
            .iter()
            .map(|&slot| (slots[slot as usize].place, slots[slot as usize].count))
            .collect();
        let mut spans = tail_spans(&sorted, u64::MAX);
        let total: u64 = spans.iter().map(|&(_, length, _)| length).sum();
        let mut beyond = None;
        if total > TAIL_BATCH_BYTES {
            match arena.map(|arena| arena.reserve_spare_ram(total - TAIL_BATCH_BYTES)) {
                Some(Ok(lease)) => beyond = Some(lease),
                _ => spans = tail_spans(&sorted, TAIL_BATCH_BYTES),
            }
        }
        drop(sorted);
        let mut batch = Self {
            spans: Vec::with_capacity(spans.len()),
            slots,
            next: 0,
            _beyond: beyond,
        };
        let mut member = 0usize;
        for (start, length, end) in spans {
            let span = batch.spans.len() as u32;
            let ticket = usize::try_from(length)
                .ok()
                .map(|length| reads.ask(start, length));
            let mut left = 0u32;
            for &slot in &order[member..end] {
                let slot = &mut batch.slots[slot as usize];
                if ticket.is_some() {
                    slot.span = span;
                    slot.rel = (slot.place - start) as u32;
                    left += 1;
                }
            }
            member = end;
            batch.spans.push(TailSpan {
                ticket,
                bytes: None,
                left,
            });
        }
        batch
    }

    /// The tail of stream `ordinal` of object `index`, where it was asked
    /// for and read: its place on the partition and its bytes. Called for
    /// the streams in the order the pass takes them. The bytes of a span are
    /// let go once its last tail has been taken.
    fn take(
        &mut self,
        reads: &mut super::super::source_backed::original_prefetch::LaneReads,
        index: usize,
        ordinal: usize,
    ) -> Option<(u64, Vec<u8>)> {
        while self
            .slots
            .get(self.next)
            .is_some_and(|slot| (slot.index, slot.ordinal) < (index, ordinal))
        {
            self.next += 1;
        }
        let slot = self
            .slots
            .get(self.next)
            .filter(|slot| (slot.index, slot.ordinal) == (index, ordinal))?;
        self.next += 1;
        let span = self.spans.get_mut(slot.span as usize)?;
        if span.bytes.is_none()
            && let Some(ticket) = span.ticket.take()
            && let Ok(bytes) = reads.take(ticket)
        {
            span.bytes = Some(bytes);
        }
        let (rel, count) = (slot.rel as usize, slot.count as usize);
        let tail = span
            .bytes
            .as_ref()
            .filter(|bytes| rel + count <= bytes.len())
            .map(|bytes| (slot.place, bytes[rel..rel + count].to_vec()));
        span.left = span.left.saturating_sub(1);
        if span.left == 0 {
            span.bytes = None;
        }
        tail
    }

    /// Takes back what was asked and not taken (every tail asked for is
    /// taken by its stream; should one not have been, its bytes are not
    /// kept past its batch).
    fn finish(self, reads: &mut super::super::source_backed::original_prefetch::LaneReads) {
        for span in self.spans {
            if let Some(ticket) = span.ticket {
                let _ = reads.take(ticket);
            }
        }
    }
}

/// The one range of a stream a run that verifies once writes together with
/// other streams' ([`PendingTails`]): a single materialized interval of at
/// most one window, of a stream that is not sparse.
fn batchable(at_once: bool, stream: StreamRef<'_>, intervals: &[(u64, u64)]) -> Option<(u64, u64)> {
    match intervals {
        [(at, length)]
            if at_once && stream.sparse.is_none() && *length > 0 && *length <= WINDOW as u64 =>
        {
            Some((*at, *length))
        }
        _ => None,
    }
}

/// What one tail waiting to be written holds beside its bytes: its entry
/// here, the item its batch's write is handed, and that write's own lists
/// of it (its key, its path on the shadow and its results).
fn pending_overhead(object: &Object, stream: StreamRef<'_>) -> u64 {
    let path = object
        .path
        .iter()
        .map(|component| component.len() as u64 + 1)
        .sum::<u64>()
        + 2 * stream.name_utf16.len() as u64
        + 64;
    1024 + 4 * path
}

/// What a stream's record for the supplied tails holds while it waits.
const PENDING_RECORD_BYTES: u64 = 256;
/// What the tails waiting to be written are held to where the ledger has
/// no spare room for all of a batch's.
const PENDING_FALLBACK_BYTES: u64 = 4 * 1024 * 1024;

/// What the tails of `held` (the first of which is object `first`) that
/// wait to be written with their batch hold at most, with their records
/// where the supplied tails are `recorded`. Nothing waits in a run that
/// does not verify once.
fn pending_need(
    held: &[LeasedExpectedObject],
    first: usize,
    planned: &MaterializedPlan,
    at_once: bool,
    recorded: bool,
) -> u64 {
    let mut need = 0u64;
    if !at_once {
        return need;
    }
    for (index, object) in (first..).zip(held) {
        if object.directory || system(object) {
            continue;
        }
        for (ordinal, stream) in object.data_streams().enumerate() {
            let Some((_, intervals)) = planned.get(&(index, ordinal)) else {
                continue;
            };
            if let Some((_, length)) = batchable(at_once, stream, intervals) {
                need = need
                    .saturating_add(length)
                    .saturating_add(pending_overhead(object, stream));
            }
            if recorded && stream.tail_requires_materialization() {
                need = need.saturating_add(PENDING_RECORD_BYTES);
            }
        }
    }
    need
}

/// A tail read from the source that waits to be written with its batch.
struct PendingTailWrite<'o> {
    object_index: usize,
    name: &'o [u16],
    components: &'o [String],
    logical_length: u64,
    offset: u64,
    bytes: Vec<u8>,
    /// Where its record's digest begins in `bytes`.
    digest_from: Option<usize>,
    /// Its record in [`PendingTails::records`].
    record: Option<usize>,
}

/// A stream's record for the supplied tails, waiting for the writes before
/// it (the records are kept in the order of their keys) or for its digest.
struct PendingRecord<'o> {
    key: [u8; 16],
    object_index: usize,
    name: &'o [u16],
    logical_offset: u64,
    length: u64,
    sha256: Option<String>,
}

/// The tails of a batch waiting to be written together
/// (`PrivateTree::materialize_tails_batch_unhashed`), and the records of
/// the supplied tails behind them.
///
/// They were held without a lease, up to a window for every stream of a
/// batch of 8,192 objects. What they hold is now paid for as spare memory:
/// what all of the batch's need where the ledger grants it, otherwise a few
/// MiB, and the tails waiting are written whenever the next would pass what
/// is paid for. Where nothing is granted each tail is written by itself, as
/// a stream is that does not wait.
///
/// A stream whose range does not wait (several intervals, a longer one, a
/// sparse stream) is written while the tails before it wait: each stream is
/// written to its own file, a tail into the clusters its file was given
/// when it was made, so the order of the writes to different files does not
/// change what any of them holds; a batch's writes were made at once on
/// helper threads, in no order, before.
struct PendingTails<'o> {
    writes: Vec<PendingTailWrite<'o>>,
    records: Vec<PendingRecord<'o>>,
    held: u64,
    budget: u64,
    _lease: Option<crate::artifact_arena::ArenaRamLease>,
}
impl<'o> PendingTails<'o> {
    fn new(arena: Option<&crate::artifact_arena::ArtifactArena>, need: u64) -> Self {
        let mut pending = Self {
            writes: Vec::new(),
            records: Vec::new(),
            held: 0,
            budget: 0,
            _lease: None,
        };
        if need == 0 {
            return pending;
        }
        let Some(arena) = arena else {
            return pending;
        };
        for budget in [need, need.min(PENDING_FALLBACK_BYTES)] {
            if let Ok(lease) = arena.reserve_spare_ram(budget) {
                pending.budget = budget;
                pending._lease = Some(lease);
                break;
            }
        }
        pending
    }

    fn has_writes(&self) -> bool {
        !self.writes.is_empty()
    }

    /// Leaves `write` to be written with the tails waiting, with its
    /// `record` for the supplied tails, if it has one. What waits is written
    /// first where `write` would pass what is paid for, and `write` itself
    /// at once where it passes it alone.
    fn write(
        &mut self,
        template: &mut PrivateTree,
        mut writer: Option<&mut crate::ntfs_inspect::record_store::SortedRecordWriter>,
        mut write: PendingTailWrite<'o>,
        record: Option<PendingRecord<'o>>,
        overhead: u64,
    ) -> Result<()> {
        let cost = (write.bytes.len() as u64)
            .saturating_add(overhead)
            .saturating_add(if record.is_some() {
                PENDING_RECORD_BYTES
            } else {
                0
            });
        if self.held.saturating_add(cost) > self.budget {
            self.flush(template, writer.as_deref_mut())?;
        }
        if let Some(record) = record {
            write.record = Some(self.records.len());
            self.records.push(record);
        }
        self.writes.push(write);
        self.held = self.held.saturating_add(cost);
        if self.held > self.budget {
            self.flush(template, writer)?;
        }
        Ok(())
    }

    /// Adds the record of a stream whose tail was written by itself: at
    /// once where no record waits before it, otherwise behind them.
    fn record(
        &mut self,
        writer: &mut crate::ntfs_inspect::record_store::SortedRecordWriter,
        record: PendingRecord<'o>,
    ) -> Result<()> {
        if self.records.is_empty() {
            return push_supplied_tail(writer, record);
        }
        self.records.push(record);
        self.held = self.held.saturating_add(PENDING_RECORD_BYTES);
        Ok(())
    }

    /// Writes every tail waiting, at once on helper threads, and then the
    /// records waiting, in their order, each with the digest of its tail
    /// taken as the tail was written.
    fn flush(
        &mut self,
        template: &mut PrivateTree,
        writer: Option<&mut crate::ntfs_inspect::record_store::SortedRecordWriter>,
    ) -> Result<()> {
        if !self.writes.is_empty() {
            let items: Vec<n2r_win32::shadow_native::private_tree::TailBatchItem<'_>> = self
                .writes
                .iter()
                .map(
                    |item| n2r_win32::shadow_native::private_tree::TailBatchItem {
                        object_index: item.object_index,
                        name: item.name,
                        components: item.components,
                        logical_length: item.logical_length,
                        offset: item.offset,
                        bytes: item.bytes.as_slice(),
                        digest_from: item.digest_from,
                    },
                )
                .collect();
            let digests = template.materialize_tails_batch_unhashed(&items)?;
            drop(items);
            ensure!(
                digests.len() == self.writes.len(),
                "parallel tail materialization returned a digest for another count of tails"
            );
            for (write, digest) in self.writes.iter().zip(digests) {
                if let Some(record) = write.record {
                    self.records[record].sha256 = digest;
                }
            }
            self.writes.clear();
        }
        match writer {
            Some(writer) => {
                for record in self.records.drain(..) {
                    push_supplied_tail(writer, record)?;
                }
            }
            None => self.records.clear(),
        }
        self.held = 0;
        Ok(())
    }
}

fn push_supplied_tail(
    writer: &mut crate::ntfs_inspect::record_store::SortedRecordWriter,
    record: PendingRecord<'_>,
) -> Result<()> {
    let sha256 = record.sha256.with_context(|| {
        format!(
            "supplied tail of object {} stream {:?} has no digest",
            record.object_index,
            String::from_utf16_lossy(record.name)
        )
    })?;
    writer.push(
        record.key,
        &n2r_win32::shadow_native::LayoutResidualExpectation {
            object_index: record.object_index,
            stream_name_utf16: record.name.to_vec(),
            logical_offset: record.logical_offset,
            length: record.length,
            sha256,
        },
    )
}

pub(crate) fn prepare<'a, 'source, 'scope>(
    bytes: &'a mut PagedSourceByteAdapterWithScope<'source, 'scope>,
    expected: &'a PagedExpectedTree,
    template: &'a mut PrivateTree,
    maximum_materialized_bytes: u64,
    policy: VerificationPolicy,
    progress: &Reporter,
) -> Result<RoutedSupplyOwner<'a, 'source, 'scope>> {
    prepare_recording_tails(
        bytes,
        expected,
        template,
        maximum_materialized_bytes,
        policy,
        progress,
        None,
    )
}

pub(crate) fn prepare_recording_tails<'a, 'source, 'scope>(
    bytes: &'a mut PagedSourceByteAdapterWithScope<'source, 'scope>,
    expected: &'a PagedExpectedTree,
    template: &'a mut PrivateTree,
    maximum_materialized_bytes: u64,
    policy: VerificationPolicy,
    progress: &Reporter,
    tail_output: Option<(
        &std::path::Path,
        &crate::ntfs_inspect::paged_storage::SourceScratch,
    )>,
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
    // Planning only observes the shadow, and so does the verification of a
    // run that verifies each thing once: such a run hands the streams of
    // both to helper threads. The pass below stays one stream at a time: it
    // writes, and what it observes of a file after writing to it is not
    // what a helper would have seen before. The budget refusal still stands
    // between the plan and the first write.
    let at_once = policy.verifies_once();
    let (plan, materialized_streams, planned_receipt) = scan_plan(
        bytes, expected, template, row_window, policy, at_once, progress,
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
    // What a run that verifies once materializes is, but for the streams
    // whose routing is not supported, the tail of each stream beyond its
    // routed prefix: some 97,000 reads of a few KiB of the source on the
    // full Windows volume, one after another, each waited for in turn
    // (17 s). Where the source is read through lanes of its own, the objects
    // are taken in batches, and the tail of each stream of a batch that the
    // plan materializes is asked of the lanes at once, in its order on the
    // disk, from where the expected run list places it, and offered to the
    // adapter's reads of that stream (`offer_read_ahead`). Those reads are
    // otherwise what they were: the session maps every window from the
    // source's own record and takes the bytes read ahead only for a read
    // wholly inside them, a fresh read of the same frozen device at that
    // place; every other read, a read ahead that failed among them, is made
    // by the adapter as before. Without lanes, or memory to spare, an
    // object is taken at a time as before.
    let mut ahead = if at_once {
        super::super::source_backed::tails_ahead(
            bytes,
            bytes.metadata_scratch().artifact_group(),
            "n2r-supply-tails-ahead",
        )?
    } else {
        None
    };
    let mut tail_writer = if at_once
        && n2r_win32::verify_policy::checks_once()
        && let Some((tail_path, tail_scratch)) = tail_output
    {
        Some((
            crate::ntfs_inspect::record_store::SortedRecordWriter::new(
                tail_path,
                *b"N2RSRTL1",
                tail_scratch,
            )?,
            tail_scratch,
        ))
    } else {
        None
    };
    let cluster = n2r_win32::target_cluster::bytes();
    // The ledger that pays, as spare memory, for what a batch holds beside
    // the lanes: the spans of its tails beyond what `tails_ahead` reserved,
    // and its tails waiting to be written.
    let supply_arena = bytes
        .metadata_scratch()
        .artifact_group()
        .map(|group| group.arena().clone());
    let tail_arena = ahead.as_ref().and(supply_arena.as_ref());
    // One batch of objects from `first` on: as many as one batch of tails
    // takes where the tails are read ahead, one otherwise.
    let lease_batch = |first: usize, lanes: bool| -> Result<Vec<LeasedExpectedObject>> {
        if lanes {
            let mut objects = 0usize;
            expected.objects_leased_at_once(first, |_object| {
                objects += 1;
                objects < TAIL_BATCH
            })
        } else {
            Ok(vec![expected.object_leased(first)?])
        }
    };
    (|| -> Result<()> {
        let mut first = 0usize;
        // The batch after the one being written, where its tails were asked
        // of the lanes before that batch's tails were written.
        let mut asked_next: Option<(Vec<LeasedExpectedObject>, Option<TailBatchReads>)> = None;
        while first < expected.len() {
            // An object that does not decode is reported as itself: a batch
            // ends before it, and it is the first of the next.
            failing_object.set(first);
            let (held, mut tail_reads) = match asked_next.take() {
                Some(next) => next,
                None => {
                    let held = lease_batch(first, ahead.is_some())?;
                    // The tails of the batch's materialized streams are asked
                    // of the lanes at once, in their order on the disk,
                    // coalesced into spans whose bytes, gaps included, stay
                    // within what is leased for them.
                    let reads = ahead.as_mut().map(|reads| {
                        TailBatchReads::ask(
                            reads,
                            tail_arena,
                            bytes,
                            &held,
                            first,
                            &materialized_streams,
                        )
                    });
                    (held, reads)
                }
            };
            let mut pending = PendingTails::new(
                supply_arena.as_ref(),
                pending_need(
                    &held,
                    first,
                    &materialized_streams,
                    at_once,
                    tail_writer.is_some(),
                ),
            );
            for (index, object) in (first..).zip(&held) {
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
                if object.directory || system(object) {
                    continue;
                }
                let mut tail_ordinal = 0u64;
                for (stream_ordinal, stream) in object.data_streams().enumerate() {
                    let needs_tail = stream.tail_requires_materialization();
                    let this_tail_ordinal = if needs_tail {
                        let o = tail_ordinal;
                        tail_ordinal += 1;
                        Some(o)
                    } else {
                        None
                    };
                    let planned = materialized_streams.get(&(index, stream_ordinal));
                    if at_once && planned.is_none() {
                        continue;
                    }
                    // A read ahead that failed is left to the adapter to make
                    // again, and to report if it fails there too.
                    if let (Some(reads), Some(batch)) = (ahead.as_mut(), tail_reads.as_mut())
                        && let Some((place, tail)) = batch.take(reads, index, stream_ordinal)
                    {
                        bytes.offer_read_ahead(place, tail);
                    }
                    // What was offered is withdrawn once the stream's windows
                    // are done, whether or not they were materialized.
                    let mut recorded_tail_sha: Option<String> = None;
                    // Where the stream's tail was left to wait with its
                    // batch: the digest of its bytes from there on is taken
                    // as it is written.
                    let mut waits_from: Option<usize> = None;
                    let tail_offset = stream.length / cluster * cluster;
                    let tail_len = stream.length - tail_offset;
                    let materialized = (|| -> Result<n2r_win32::shadow_native::private_tree::StreamSupplySummary> {
                        let id = identity(object, stream);
                        let (summary, intervals) = if let (true, Some((summary, intervals))) =
                            (at_once, planned)
                        {
                            (summary.clone(), intervals.clone())
                        } else {
                            let mut observed = leased_ranges(
                                bytes, template, index, object, stream, row_window, None,
                            )?;
                            let decision = route_decision(
                                template,
                                index,
                                object,
                                stream,
                                &observed.ranges,
                                None,
                            )?;
                            drop(observed.native_ram.take());
                            let prefix = decision.as_ref().map(|(prefix, _)| *prefix);
                            let mut intervals = Vec::new();
                            for (kind, range) in &observed.ranges {
                                pieces(stream, *kind, range, prefix, |piece, offset, length| {
                                    if matches!(piece, Piece::Materialize) {
                                        intervals.push((offset, length));
                                    }
                                    Ok(())
                                })?;
                            }
                            (observed.summary, intervals)
                        };
                        if let Some((at, length)) = batchable(at_once, stream, &intervals) {
                            let n = usize::try_from(length)?;
                            let next_written = written
                                .checked_add(n as u64)
                                .context("routed materialization total overflow")?;
                            ensure!(
                                next_written <= plan.materialized
                                    && next_written <= maximum_materialized_bytes,
                                "routed materialization changed or exceeds its preflight budget"
                            );
                            bytes.read_range_checked(&id, at, &mut buffer[..n])?;
                            if tail_writer.is_some()
                                && needs_tail
                                && at <= tail_offset
                                && at + n as u64 == stream.length
                            {
                                let start = (tail_offset - at) as usize;
                                if n - start == tail_len as usize {
                                    waits_from = Some(start);
                                }
                            }
                            // Its record for the supplied tails waits with it
                            // for the digest taken as it is written.
                            let record = waits_from.zip(this_tail_ordinal).map(|(_, ordinal)| {
                                PendingRecord {
                                    key: supplied_tail_key(index as u64, ordinal),
                                    object_index: index,
                                    name: stream.name_utf16,
                                    logical_offset: tail_offset,
                                    length: tail_len,
                                    sha256: None,
                                }
                            });
                            pending.write(
                                template,
                                tail_writer.as_mut().map(|(writer, _)| writer),
                                PendingTailWrite {
                                    object_index: index,
                                    name: stream.name_utf16,
                                    components: &object.path,
                                    logical_length: stream.length,
                                    offset: at,
                                    bytes: buffer[..n].to_vec(),
                                    digest_from: waits_from,
                                    record: None,
                                },
                                record,
                                pending_overhead(object, stream),
                            )?;
                            bytes.validate_protection()?;
                            written = next_written;
                        } else {
                            // The tails waiting with the batch are written
                            // with it: they are other streams' and are written
                            // to their own files, so this stream's windows do
                            // not wait for them.
                            for (offset, length) in intervals {
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
                                    // The window is written from this very buffer and
                                    // read back and compared with it byte for byte.
                                    // Neither side keeps a record of the window: the
                                    // SHA-256 of the source read and that of the
                                    // bytes written were both taken of this buffer
                                    // and compared with each other, which could not
                                    // differ. They are no longer computed.
                                    bytes.read_range_checked(&id, at, &mut buffer[..n])?;
                                    if tail_writer.is_some()
                                        && needs_tail
                                        && recorded_tail_sha.is_none()
                                        && at <= tail_offset
                                        && at + n as u64 == stream.length
                                    {
                                        let start = (tail_offset - at) as usize;
                                        if n - start == tail_len as usize {
                                            recorded_tail_sha = Some(hex::encode(Sha256::digest(
                                                &buffer[start..n],
                                            )));
                                        }
                                    }
                                    // Sparse materialization can return an island/parts
                                    // receipt; retain the original complete-row allowance
                                    // only while that native proof is built and consumed.
                                    let _sparse_proof_ram = if stream.sparse.is_some() {
                                        Some(
                                            bytes
                                                .lease_working_ram(admission.budget.max_row_bytes)?,
                                        )
                                    } else {
                                        None
                                    };
                                    let write = template.materialize_range_named_unhashed(
                                        index,
                                        stream.name_utf16,
                                        &object.path,
                                        stream.length,
                                        at,
                                        &buffer[..n],
                                    )?;
                                    ensure!(
                                        write["readback_verified"] == true,
                                        "routed remaining materialization readback differs"
                                    );
                                    bytes.validate_protection()?;
                                    written = next_written;
                                    done += n as u64;
                                }
                            }
                        }
                        Ok(summary)
                    })();
                    bytes.withdraw_read_ahead(drop);
                    let summary = materialized?;
                    if let (Some((writer, _)), Some(ordinal), Some(sha256)) =
                        (tail_writer.as_mut(), this_tail_ordinal, recorded_tail_sha)
                    {
                        pending.record(
                            writer,
                            PendingRecord {
                                key: supplied_tail_key(index as u64, ordinal),
                                object_index: index,
                                name: stream.name_utf16,
                                logical_offset: tail_offset,
                                length: tail_len,
                                sha256: Some(sha256),
                            },
                        )?;
                    }
                    bytes.finish_stream()?;
                    if !at_once {
                        let _closing_native_ram = bytes.lease_working_ram(
                            template.supply_stream_workspace_bytes(index, stream.name_utf16)?,
                        )?;
                        ensure!(
                            summary == observe_stream(template, index, object, stream)?,
                            "native stream mapping changed during routed preparation"
                        );
                    }
                }
            }
            // Every tail of the batch has been taken: its lane reads are let
            // go before the next batch's are asked.
            if let (Some(reads), Some(batch)) = (ahead.as_mut(), tail_reads.take()) {
                batch.finish(reads);
            }
            let after = first + held.len();
            // The next batch's tails are asked of the lanes before this
            // batch's tails are written, so that the lanes read while the
            // tails are written. Its spans are held to what `tails_ahead`
            // reserved, which this batch's spans no longer hold, and to
            // spare memory beyond it; the tails waiting here hold a lease of
            // their own. Where the next batch's objects cannot be held now,
            // they are taken in turn once this batch is written, and what
            // the first of them fails with is reported then.
            if pending.has_writes()
                && after < expected.len()
                && let Some(reads) = ahead.as_mut()
                && let Ok(next) = lease_batch(after, true)
            {
                let next_reads = TailBatchReads::ask(
                    reads,
                    tail_arena,
                    bytes,
                    &next,
                    after,
                    &materialized_streams,
                );
                asked_next = Some((next, Some(next_reads)));
            }
            pending.flush(template, tail_writer.as_mut().map(|(writer, _)| writer))?;
            drop(pending);
            first = after;
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
    // The lanes are closed before the adapter's scope ends.
    drop(ahead);
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
    let supplied_tails = match tail_writer {
        Some((writer, tail_scratch)) => {
            let pin = writer.finish()?;
            Some(crate::ntfs_inspect::record_store::SortedRecordStore::open(
                &pin,
                tail_scratch,
            )?)
        }
        None => None,
    };
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
        planned_receipt,
        progress: progress.clone(),
        supplied_tails,
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
    let (plan, _, _) = scan_plan(
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
        planned_receipt: None,
        progress: progress.clone(),
        supplied_tails: None,
        _ram: ram,
    })
}

impl RoutedSupplyOwner<'_, '_, '_> {
    pub(crate) fn take_supplied_tails(
        &mut self,
    ) -> Option<crate::ntfs_inspect::record_store::SortedRecordStore> {
        self.supplied_tails.take()
    }
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
        // Under "verify once" this pass therefore reads no payload.
        let reread = self.reread;
        // Nor, under "verify once" (owner decision D2, #251), does it walk
        // the source's side of each stream again: opening the stream's
        // session (its file record read from the source and decoded), each
        // reference and hole held to the source's run list, and closing the
        // session (the record read again and the mapping checked). The
        // planning pass (`scan_plan`) of this same process made exactly
        // those checks of every stream, on a source that has been offline,
        // read-only and held since; the source's read-only state and
        // protection are still checked here as this pass begins and ends
        // (`phase`); and the gate in front of the first write to the source
        // reads every metadata range and extent the inspection read again and
        // holds them to the source fingerprint pinned at inspection
        // (`recheck_source`), so a changed file record or run list stops the
        // run before it writes. A run that reads the payloads again
        // (thorough, `--recheck-everything`, a recovered supply) walks both
        // sides.
        let walk_source = reread;
        // Nor, in a run that verifies each thing once, does it observe the
        // shadow's side of each stream again (#140: 8.9 s of the full
        // Windows volume): a duplicate of each stream's file, its metadata,
        // security and complete mapping, and for a stream proven by its
        // extents the comparison of its tracked pieces, the observation of
        // its prefix (identity, security, mapping, initialized regions and
        // integrity) and that again, all held to what the planning pass of
        // this process had observed of the same held file. Every stream's
        // file stays held by this process and nothing else can write to the
        // shadow; what this process wrote since the plan (the materialized
        // ranges) was read back as it was written; and the walk of the
        // frozen shadow (`walk shadow (closing)`) captures every stream's
        // complete mapping, both initialized-region views and its integrity
        // again, holds each mapping to its expected allocation and reads
        // every materialized tail back against its digest, before the
        // capture is compared with the source and the gate re-reads the
        // source's mappings against its fingerprint. The counts and the plan
        // digest are then the plan's, and the ordered receipt digest is the
        // one the planning pass framed of the same streams with the same
        // fields ([`scan_plan`]); the receipt is the one this pass made.
        // Nothing reads what the observations made here: each was compared
        // and let go. A thorough run, a diagnosis, `--recheck-everything`
        // and a recovered supply observe every stream as before.
        if let Some(ordered_receipt_sha256) = self
            .planned_receipt
            .take()
            .filter(|_| !reread && !self.recovered && n2r_win32::verify_policy::verifies_once())
        {
            supply_progress(
                &self.progress,
                Phase::PayloadVerification,
                0,
                0,
                self.expected.len(),
                0,
                None,
            );
            let plan = &self.plan;
            ensure!(
                plan.referenced
                    .checked_add(plan.routed)
                    .and_then(|n| n.checked_add(plan.materialized))
                    .and_then(|n| n.checked_add(plan.holes))
                    == Some(plan.logical),
                "routed verification counts differ from the complete preflight"
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
            return Ok(self.receipt(
                ordered_receipt_sha256,
                self.bytes.logical_bytes_read() - before_reads,
                reread,
                walk_source,
            ));
        }
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
        // When `reread` is false under `verifies_once()`, no bytes are read or
        // written between the opening and closing stream checks, so repeating
        // the exact same retrieval-pointer and metadata queries on the same
        // held handle is redundant; the frozen shadow walk verifies every
        // stream's final mapping again before capture.
        let observe_closing = reread || !n2r_win32::verify_policy::verifies_once();
        (|| -> Result<()> {
        let mut first = 0usize;
        while first < self.expected.len() {
            failing_object.set(first);
            supply_progress(&self.progress,Phase::PayloadVerification,0,first,self.expected.len(),self.bytes.logical_bytes_read()-before_reads,None);
            let held = objects_from(self.expected, first, arena.is_some())?;
            let mut batch = StreamsAtOnce::new(&held, first, observe_closing, arena.as_ref());
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
                    if walk_source {
                        self.bytes.check_stream(&id)?;
                    }
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
                                    if walk_source {
                                        self.bytes
                                            .require_reference(&id, offset, physical, length)?;
                                    }
                                    referenced = referenced
                                        .checked_add(length)
                                        .context("reference total overflow")?;
                                }
                                Piece::Routed(physical) => {
                                    ensure!(
                                        stream.sha256.is_none() && stream.source_evidence.is_some(),
                                        "routed prefix cannot claim an unmeasured content digest"
                                    );
                                    if walk_source {
                                        self.bytes
                                            .require_reference(&id, offset, physical, length)?;
                                    }
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
                                    if walk_source {
                                        self.bytes.require_hole(&id, offset, length)?;
                                    }
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
                    if walk_source {
                        self.bytes.finish_stream()?;
                    }
                    if observe_closing {
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
                    }
                    if !n2r_win32::verify_policy::verifies_once() {
                        ensure!(
                            route_decision(
                                self.template,
                                index,
                                object,
                                stream,
                                ranges,
                                seen.as_mut()
                            )? == decision,
                            "native routed prefix readiness changed during verification"
                        );
                    }
                    let _frame_ram = frame_ram(self.bytes, stream.name_utf16.len())?;
                    frame(
                        &mut receipt_hash,
                        &receipt_frame(index, object, stream, digest, summary),
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
        Ok(self.receipt(
            hex::encode(receipt_hash.finalize()),
            self.bytes.logical_bytes_read() - before_reads,
            reread,
            walk_source,
        ))
    }

    /// The receipt of [`Self::verify`]. Its counts are the plan's, which
    /// the verification either held its own to or, in a run that verifies
    /// each thing once, took.
    fn receipt(
        &self,
        ordered_receipt_sha256: String,
        source_bytes_read: u64,
        reread: bool,
        walk_source: bool,
    ) -> serde_json::Value {
        let plan = &self.plan;
        let (logical, referenced, routed, materialized, holes) = (
            plan.logical,
            plan.referenced,
            plan.routed,
            plan.materialized,
            plan.holes,
        );
        let mut receipt = serde_json::json!({"kind":"private-routed-prefix-verification", "success":true,
            "logical_bytes":logical,"same_coordinate_reference_bytes":referenced,
            "relocated_prefix_routed_bytes":routed,"shadow_materialized_bytes":materialized,
            "hole_bytes":holes,"actual_source_logical_bytes_read":source_bytes_read,
            "ordered_receipt_sha256":ordered_receipt_sha256,"routed_plan_sha256":self.plan.sha256,
            "target_route_capture_pending":true,"journal_copy_literal_split_pending":true,
            "source_payload_writes":0,"source_admitted":false,"execution_authorized":false,
            "completed_payloads_reused":self.recovered,"payload_bytes_rematerialized":if self.recovered {Some(0u64)}else{None},
            "conversion_qualified":false});
        if !reread {
            receipt["payload_bytes_reread"] = false.into();
            receipt["payload_contents_held_by"] =
                "read-back at materialization; complete digests on the converted volume".into();
        }
        if !walk_source {
            receipt["source_mappings_rewalked"] = false.into();
            receipt["source_mappings_held_by"] =
                "the planning pass; the source fingerprint at the gate before the first source write"
                    .into();
        }
        receipt
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

    #[test]
    fn only_one_short_range_of_a_plain_stream_waits_with_its_batch() {
        let plain = stream(None, Some(SourceStreamEvidence::ExtentIdentityV1));
        let window = WINDOW as u64;
        assert_eq!(batchable(true, plain, &[(4096, 100)]), Some((4096, 100)));
        assert_eq!(batchable(true, plain, &[(0, window)]), Some((0, window)));
        // Not in a run that does not verify once, not an empty, a longer or
        // a second range.
        assert_eq!(batchable(false, plain, &[(4096, 100)]), None);
        assert_eq!(batchable(true, plain, &[(4096, 0)]), None);
        assert_eq!(batchable(true, plain, &[(0, window + 1)]), None);
        assert_eq!(batchable(true, plain, &[(0, 100), (8192, 100)]), None);
        assert_eq!(batchable(true, plain, &[]), None);
    }

    fn span_bytes(spans: &[(u64, u64, usize)]) -> u64 {
        spans.iter().map(|&(_, length, _)| length).sum()
    }

    /// #265: a batch's spans held the gaps between its tails as well as the
    /// tails, against a lease of the tails alone.
    #[test]
    fn a_batchs_spans_hold_their_gaps_within_what_is_leased() {
        const KIB: u64 = 1024;
        // 8,192 tails of 2 KiB, each 63 KiB after the one before: merged
        // across the gaps (into spans of up to 1 MiB) they are read as
        // nearly 500 MiB.
        let asks: Vec<(u64, u32)> = (0..8192u64).map(|n| (n * 65 * KIB, 2048)).collect();
        let tails: u64 = asks.iter().map(|&(_, count)| u64::from(count)).sum();
        let unbounded = tail_spans(&asks, u64::MAX);
        assert!(span_bytes(&unbounded) > 450 * 1024 * KIB);
        // Held to the lease, every tail is still read and the gaps merged
        // only as far as they fit.
        let limit = 16 * 1024 * KIB;
        let bounded = tail_spans(&asks, limit);
        assert!(span_bytes(&bounded) <= limit, "{}", span_bytes(&bounded));
        assert!(span_bytes(&bounded) >= tails);
        assert_eq!(bounded.last().map(|span| span.2), Some(asks.len()));
        // Every tail lies wholly inside its span.
        let mut member = 0;
        for &(start, length, end) in &bounded {
            for &(place, count) in &asks[member..end] {
                assert!(place >= start && place + u64::from(count) <= start + length);
            }
            member = end;
        }
        // The tails alone at the limit: each is read by itself.
        let exact = tail_spans(&asks, tails);
        assert_eq!(span_bytes(&exact), tails);
        assert_eq!(exact.len(), asks.len());
    }

    #[test]
    fn spans_merge_neighbours_up_to_their_longest_and_no_further() {
        // Two neighbours 1 KiB apart are one span; one beyond the gap is not.
        let asks = [(0u64, 4096u32), (5120, 4096), (5120 + 4096 + 65537, 4096)];
        assert_eq!(
            tail_spans(&asks, u64::MAX),
            vec![(0, 9216, 2), (5120 + 4096 + 65537, 4096, 3)]
        );
        // No span is longer than TAIL_COALESCE_MAX.
        let asks: Vec<(u64, u32)> = (0..600u64).map(|n| (n * 4096, 4096)).collect();
        let spans = tail_spans(&asks, u64::MAX);
        assert!(
            spans
                .iter()
                .all(|&(_, length, _)| length <= TAIL_COALESCE_MAX)
        );
        assert_eq!(span_bytes(&spans), 600 * 4096);
        // A tail that does not fit at all is not asked for.
        assert_eq!(tail_spans(&[(0, 4096), (1 << 30, 4096)], 6000).len(), 1);
    }
}
