//! The read-only observations of a batch of streams, made on helper threads.
//!
//! The supply plans and verifies one stream after another, and for each
//! stream it asks Windows several hundred things about the stream's file on
//! the shadow: a snapshot of its metadata and complete mapping taken twice,
//! the readiness of its prefix observed twice and each of those twice over,
//! and its mapping compared with its tracked pieces before and after. One
//! thread made all of those calls, 110 s of the full Windows volume (#140),
//! while the files are held and nothing writes to them.
//!
//! Here the calling thread makes a batch of streams ready: it finds each
//! stream's files in this tree, derives the stream's ranges from this
//! process's own records to learn whether its prefix will be observed, and
//! reserves every workspace the observations take. Helper threads
//! (`each_at_once`) then make the observations, each stream's in the order
//! the calling thread makes them for a stream taken by itself, and close
//! every duplicate they opened.
//!
//! Nothing is decided here. What a helper saw of a stream is handed, stage
//! by stage, to the very functions that observe a stream taken by itself
//! (`supply_snapshot::with_snapshot`, `routed_prefix::observe`,
//! `RoutedPrefixReady::revalidate`, `PrivateTree::visit_supply_stream_named`):
//! each takes the helper's result where it would have asked Windows and
//! does everything else itself, in its own order, on the calling thread, as
//! the caller takes the streams one by one. So every check is made, every
//! observation is made as often as before, and the first failure in stream
//! order is the one reported. What differs is where the observations lie in
//! time: a stream's are made together, before the calling thread comes to
//! it, and no longer around its own work on that stream. That work does not
//! touch the shadow.
//!
//! Every workspace of a batch, its first stream's included, is memory for
//! doing more at once (`reserve_spare`), which the ledger grants only while
//! room stays for what the pass cannot do without. A stream a helper
//! observes holds its workspaces together until the pass has taken it, more
//! than the same stream taken by itself holds at once; paid from spare
//! memory, that never leaves short a reservation that one stream at a time
//! would have been granted.
//!
//! A stream that cannot be made ready (a workspace refused, or anything its
//! own checks would report) ends the batch before it. The caller hands it
//! over again as the first of its next batch, once the streams before it
//! have returned what was reserved for them; if it cannot be made ready
//! then either, the batch is empty and the caller takes the stream by
//! itself, under its own reservations and on the path that reports, and
//! hands over the stream after it next. A stage a helper did not come to is
//! made by the calling thread.
use super::*;
use crate::shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease};
use std::collections::VecDeque;

type Lease = Box<dyn ReportMemoryLease>;

/// How many streams a caller hands over at once.
pub const SUPPLY_BATCH_STREAMS: usize = crate::shadow_native::PARALLEL_BATCH;

/// What a helper returns for a stream beside what is reserved for it by
/// name below: its results' own records.
const RESULT_BYTES: u64 = 4096;

/// One stream of a batch: what [`PrivateTree::with_readonly_supply_stream_snapshot`]
/// is given for it.
pub struct SupplyStreamRequest<'a> {
    pub object_index: usize,
    pub name_utf16: &'a [u16],
    pub components: &'a [String],
    pub logical_length: u64,
}

/// What a helper thread saw of one stream, and the workspaces the batch
/// reserved for it. There is no way to make one but a batch, and each part
/// is taken once, by the function that would have made the observation.
pub struct SupplyStreamSeen {
    object_index: usize,
    name_utf16: Vec<u16>,
    snapshot: Option<supply_snapshot::PrepaidSnapshot>,
    // The observations of the prefix in the order the pass makes them: with
    // the stream's snapshot, and again when the stream closes.
    routes: VecDeque<routed_prefix::PrepaidPrefix>,
    closing: Option<[Option<io::Result<()>>; 3]>,
    // What the helper's mapping queries and revalidations ran under, and
    // this entry itself: held until the caller has taken the stream.
    _memory: Lease,
}
impl SupplyStreamSeen {
    fn require(&self, index: usize, name: &[u16]) -> io::Result<()> {
        if self.object_index != index || self.name_utf16 != name {
            return Err(invalid(
                "a batch's observation of one stream was handed to another",
            ));
        }
        Ok(())
    }
    pub(super) fn take_snapshot(
        &mut self,
        index: usize,
        name: &[u16],
    ) -> io::Result<Option<supply_snapshot::PrepaidSnapshot>> {
        self.require(index, name)?;
        Ok(self.snapshot.take())
    }
    pub(super) fn take_route(
        &mut self,
        index: usize,
        name: &[u16],
    ) -> io::Result<Option<routed_prefix::PrepaidPrefix>> {
        self.require(index, name)?;
        Ok(self.routes.pop_front())
    }
    pub(super) fn take_closing(
        &mut self,
        index: usize,
        name: &[u16],
    ) -> io::Result<[Option<io::Result<()>>; 3]> {
        self.require(index, name)?;
        Ok(self.closing.take().unwrap_or([None, None, None]))
    }
    /// Whether the batch's helper made the comparisons of the stream's
    /// closing observation: its workspace is then the batch's, and the
    /// caller reserves none.
    pub fn closing_observed(&self) -> bool {
        self.closing.is_some()
    }
}

/// One stream made ready for a helper: its files, what to ask of its
/// prefix, and every workspace the asking takes.
struct Ready<'tree> {
    primary: Option<&'tree unwritten::PrivatePlaceholder>,
    sparse: Option<&'tree File>,
    route: Option<routed_prefix::Plan<'tree>>,
    closing: bool,
    snapshot_memory: Lease,
    ranges_memory: Lease,
    // One for each observation of the prefix.
    route_work: Vec<Lease>,
    memory: Lease,
}
/// What a helper saw of one stream, in the order it looked.
struct Observed {
    snapshot: supply_snapshot::SnapshotSeen,
    route: Option<routed_prefix::PrefixSeen>,
    closing: Option<[Option<io::Result<()>>; 3]>,
    closing_route: Option<routed_prefix::PrefixSeen>,
}

fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("supply batch RAM overflow"))
}

/// Who pays for a batch of this tree's streams, or `None` where the tree
/// takes its streams one at a time.
///
/// A partition source is fenced for every stream and not at intervals
/// (`PrivateTree::require_source_excluded`), so its supply keeps each
/// stream's observations between that stream's own fences. A tree without
/// its allocator or its admission has no batch to pay for, and neither has
/// one whose handle slots have no room for the helpers' duplicates.
pub(super) fn payer(tree: &PrivateTree) -> Option<Arc<dyn ReportMemoryAccountant>> {
    let threads = std::thread::available_parallelism().map_or(1, |cores| cores.get());
    if !supply_snapshot::handles_admit_helpers(tree, threads) {
        return None;
    }
    Some(tree.memory.as_ref()?.payer())
}

/// Everything the calling thread does for one stream before a helper
/// observes it. Any failure ends the batch before this stream: nothing is
/// reported from here.
///
/// Every workspace is reserved as spare memory, the first stream's too;
/// where the ledger refuses one, the stream is taken by itself.
fn prepare<'tree>(
    tree: &'tree PrivateTree,
    payer: &dyn ReportMemoryAccountant,
    request: &SupplyStreamRequest<'_>,
    maximum_range_bytes: u64,
    closing: bool,
    wants_route: impl FnOnce(&[(SupplyKind, SupplyRange)]) -> Option<u64>,
) -> io::Result<Ready<'tree>> {
    // The fence every observation of a stream begins with: made at
    // intervals, here as there, and never left to a helper.
    tree.require_source_excluded()?;
    let admission = tree
        .metadata_resource_admission
        .ok_or_else(|| invalid("supply batch requires V4 admission"))?;
    let (index, name) = (request.object_index, request.name_utf16);
    let key = StreamKey::named(index, name);
    let primary = tree.files.get(&key);
    let sparse = tree.sparse_targets.get(&key);
    // The two reservations of the stream's snapshot, in its order.
    let snapshot_memory = payer.reserve_spare(add(
        supply::batch_workspace_bytes(tree, index, name)?,
        1024 * 1024,
    )?)?;
    let maximum = supply_snapshot::range_window(&admission, maximum_range_bytes)?;
    let (maximum_ranges, range_memory) = supply_snapshot::range_bound(tree, &key, name, maximum)?;
    let ranges_memory = payer.reserve_spare(range_memory)?;
    // Whether the pass observes the stream's prefix follows from its
    // ranges, so they are derived here once, for that question alone.
    let route = {
        let mut ranges = supply_snapshot::RangeSink::new(maximum, maximum_ranges)?;
        supply::stream_before_observation(tree, &key, |kind, range| ranges.push(kind, range))?;
        wants_route(ranges.ranges()).and_then(|prefix| {
            routed_prefix::plan(
                tree,
                index,
                name,
                request.components,
                request.logical_length,
                prefix,
            )
        })
    };
    // A helper works through one stream's observations in turn, so one
    // mapping workspace and one revalidation workspace serve all of them.
    // With them goes the stream's place in the batch's own lists, counted
    // three times over for a list that grows.
    let mut held = (3
        * (std::mem::size_of::<Ready<'_>>()
            + std::mem::size_of::<Observed>()
            + std::mem::size_of::<SupplyStreamSeen>())
        + 2 * std::mem::size_of_val(name)) as u64;
    if let Some(bytes) = primary
        .map(|file| file.mapping_workspace_bytes())
        .transpose()?
        .flatten()
    {
        held = add(held, bytes)?;
    }
    let mut route_work = Vec::new();
    if let Some(plan) = &route {
        held = add(held, plan.revalidation_bytes()?)?;
        // What an observation of the prefix keeps is held until the caller
        // takes the stream, so each has a workspace of its own.
        for _ in 0..1 + usize::from(closing) {
            route_work.push(payer.reserve_spare(plan.observation_bytes()?)?);
        }
    }
    Ok(Ready {
        primary,
        sparse: sparse.map(|target| &target.file),
        route,
        closing,
        snapshot_memory,
        ranges_memory,
        route_work,
        memory: payer.reserve_spare(held)?,
    })
}

/// One stream's observations on a helper thread, in the order the calling
/// thread makes them for a stream taken by itself: its snapshot, its prefix,
/// and for a closing stream the three comparisons of its mapping and its
/// prefix again. The first failure ends the looking; the calling thread then
/// reports it when it comes to it there, and never comes to what follows.
fn observe_stream(ready: &Ready<'_>) -> Observed {
    let mut observed = Observed {
        snapshot: supply_snapshot::observe_prepaid(ready.primary, ready.sparse),
        route: None,
        closing: None,
        closing_route: None,
    };
    if !observed.snapshot.held() {
        return observed;
    }
    if let Some(plan) = &ready.route {
        let seen = plan.observe();
        let held = seen.held();
        observed.route = Some(seen);
        if !held {
            return observed;
        }
    }
    if !ready.closing {
        return observed;
    }
    if let Some(file) = ready.primary {
        let mut placements = [None, None, None];
        let mut held = true;
        if crate::verify_policy::verifies_once() {
            let seen = file.check_placements_prepaid();
            held = seen.is_ok();
            placements[0] = Some(seen);
            if held {
                placements[1] = Some(Ok(()));
                placements[2] = Some(Ok(()));
            }
        } else {
            for slot in &mut placements {
                let seen = file.check_placements_prepaid();
                held = seen.is_ok();
                *slot = Some(seen);
                if !held {
                    break;
                }
            }
        }
        observed.closing = Some(placements);
        if !held {
            return observed;
        }
    }
    if let Some(plan) = &ready.route {
        observed.closing_route = Some(plan.observe());
    }
    observed
}

/// A batch made ready on the calling thread: who pays for it, each stream's
/// files, plans and workspaces, and the stream each is.
struct Prepared<'tree> {
    payer: Arc<dyn ReportMemoryAccountant>,
    ready: Vec<Ready<'tree>>,
    streams: Vec<(usize, Vec<u16>)>,
}

/// Everything the calling thread does for a batch before its helpers start.
fn prepare_batch<'tree>(
    tree: &'tree PrivateTree,
    streams: &[SupplyStreamRequest<'_>],
    maximum_range_bytes: u64,
    closing: bool,
    wants_route: impl Fn(usize, &[(SupplyKind, SupplyRange)]) -> Option<u64>,
) -> Option<Prepared<'tree>> {
    let payer = payer(tree)?;
    let mut ready: Vec<Ready<'_>> = Vec::new();
    for (slot, request) in streams.iter().enumerate() {
        match prepare(
            tree,
            payer.as_ref(),
            request,
            maximum_range_bytes,
            closing,
            |ranges| wants_route(slot, ranges),
        ) {
            Ok(stream) => ready.push(stream),
            Err(_) => break,
        }
    }
    let streams = streams
        .iter()
        .take(ready.len())
        .map(|request| (request.object_index, request.name_utf16.to_vec()))
        .collect();
    Some(Prepared {
        payer,
        ready,
        streams,
    })
}

pub(super) fn observe(
    tree: &PrivateTree,
    streams: &[SupplyStreamRequest<'_>],
    maximum_range_bytes: u64,
    closing: bool,
    wants_route: impl Fn(usize, &[(SupplyKind, SupplyRange)]) -> Option<u64>,
) -> Vec<SupplyStreamSeen> {
    match prepare_batch(tree, streams, maximum_range_bytes, closing, wants_route) {
        Some(prepared) => observe_prepared(prepared),
        None => Vec::new(),
    }
}

/// [`observe`], with the helpers' part on a thread of `scope` that the
/// caller joins later: the calling thread makes the batch ready here, as
/// `observe` does, and goes on with its own work while the helpers make the
/// observations. `None` where the tree takes its streams one at a time, or
/// no thread could be started (the batch's reservations are then returned).
pub(super) fn observe_ahead<'scope, 'tree: 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    tree: &'tree PrivateTree,
    streams: &[SupplyStreamRequest<'_>],
    maximum_range_bytes: u64,
    closing: bool,
    wants_route: impl Fn(usize, &[(SupplyKind, SupplyRange)]) -> Option<u64>,
) -> Option<std::thread::ScopedJoinHandle<'scope, Vec<SupplyStreamSeen>>> {
    let prepared = prepare_batch(tree, streams, maximum_range_bytes, closing, wants_route)?;
    std::thread::Builder::new()
        .name("n2r-supply-observe-ahead".into())
        .spawn_scoped(scope, move || {
            let _sampled = crate::stack_sampler::helper();
            observe_prepared(prepared)
        })
        .ok()
}

/// The helpers' observations of a batch made ready, each stream's handed
/// back with what was reserved for it.
fn observe_prepared(prepared: Prepared<'_>) -> Vec<SupplyStreamSeen> {
    let Prepared {
        payer,
        ready,
        streams,
    } = prepared;
    // Every workspace is held above; what `each_at_once` reserves for a
    // stream is the little its helper returns.
    let observed = crate::shadow_native::each_at_once(
        Some(payer.as_ref()),
        &ready,
        |_| Some(RESULT_BYTES),
        observe_stream,
    );
    ready
        .into_iter()
        .zip(observed)
        .zip(streams)
        .map(
            |((ready, observed), (object_index, name_utf16))| SupplyStreamSeen {
                object_index,
                name_utf16,
                snapshot: Some(supply_snapshot::PrepaidSnapshot {
                    seen: observed.snapshot,
                    memory: ready.snapshot_memory,
                    ranges_memory: ready.ranges_memory,
                }),
                routes: [observed.route, observed.closing_route]
                    .into_iter()
                    .flatten()
                    .zip(ready.route_work)
                    .map(|(seen, work)| routed_prefix::PrepaidPrefix { seen, work })
                    .collect(),
                closing: observed.closing,
                _memory: ready.memory,
            },
        )
        .collect()
}
