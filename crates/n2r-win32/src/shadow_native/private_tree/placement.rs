//! Tree-wide zero-VDL allocation and original-coordinate placement. Only the
//! independent shadow moves; source data and conversion authority are absent.
use super::super::input_domain::{InputDomain, ObjectInput, SliceInputs};
use super::*;
use crate::{bitmap_observation::Observation, retention_layout, shadow_evacuation};

mod resource;
use resource::Limits as PlacementLimits;
pub use resource::{PlacementEvidenceSink, ResourcePlacementReport};

const MOVE_BYTES: u64 = 512 * 1024 * 1024;
/// What working out the move records' bounds holds at once: one widest
/// record of two pages and one extent, as typed values, as JSON and as its
/// text (`the_move_template_fits_what_is_reserved_for_it` measures it).
const MOVE_TEMPLATE_RAM: u64 = 1024 * 1024;

/// Bytes in one cluster of the shadow volume.
fn cluster() -> u64 {
    crate::target_cluster::bytes()
}

/// A move's length as the cluster count Windows is asked to move. Every move
/// planned here is a whole number of target clusters and fits one request; a
/// length that is not would otherwise be floored and truncated in silence.
fn move_clusters(length: u64) -> io::Result<u32> {
    if !length.is_multiple_of(cluster()) {
        return Err(invalid(&format!(
            "a placement move of {length} bytes is not a whole number of clusters"
        )));
    }
    u32::try_from(length / cluster()).map_err(|_| {
        invalid(&format!(
            "a placement move of {length} bytes is more clusters than one request holds"
        ))
    })
}

/// The byte range of `clusters` clusters that start at cluster `first`.
fn cluster_span(first: u64, clusters: u32) -> io::Result<(u64, u64)> {
    let cluster = cluster();
    first
        .checked_mul(cluster)
        .and_then(|start| Some((start, start.checked_add(u64::from(clusters) * cluster)?)))
        .ok_or_else(|| {
            invalid(&format!(
                "{clusters} clusters from cluster {first} lie beyond any byte offset"
            ))
        })
}
/// Tree-wide FSCTL_MOVE_FILE submissions, shared by every phase.
const MAX_MOVES: usize = super::MAX_PLACEMENT_SUBMISSIONS;
/// Planner ceiling on tree-wide desired NTFS runs (E): a fragmented tree of
/// up to 1024 files averaging 16 retained runs. One stream retains at most
/// 1024 runs. Admission is clamped lower; see MAX_ADMITTED_RANGES.
const MAX_PLACEMENT_RANGES: usize = 16_384;
/// Route and supply-range ceiling after placement: source_backed.rs
/// (from_protected_layout and capture) and supply.rs (plan). Every retained
/// desired run yields at least one route and copied gaps add more, so a tree
/// with more desired runs would refuse there only after every native move.
const DOWNSTREAM_ROUTE_LIMIT: usize = 4096;
/// Pre-write desired-run admission: the smaller of both ceilings.
const MAX_ADMITTED_RANGES: usize = if DOWNSTREAM_ROUTE_LIMIT < MAX_PLACEMENT_RANGES {
    DOWNSTREAM_ROUTE_LIMIT
} else {
    MAX_PLACEMENT_RANGES
};
/// Every tracked shadow mapping after deferred allocation: initial ReFS runs
/// plus deferred submissions, each bounded by MAX_MOVES before coalescing.
const MAX_TRACKED_EXTENTS: usize = 2 * MAX_MOVES;
/// Tracked mappings that intersect a desired run. Only these can block one
/// or already be in place; their sweep yields at most this many plus
/// MAX_PLACEMENT_RANGES intersections, the evacuation planner's bound.
const MAX_OWNED_RANGES: usize = MAX_MOVES;
/// Bootstrap safety margin at each partition end; never a destination.
const MARGIN: u64 = 1024 * 1024;
/// construction-placement.json is saved pretty-printed under the 64 MiB
/// qualification artifact bound. Each move proof, the parked plan record and
/// each original-coordinate row is charged by its exact bytes in that
/// document; 64 KiB stays for the scalar fields and framing.
const MAX_PLACEMENT_ARTIFACT_BYTES: usize = 64 * 1024 * 1024 - 64 * 1024;
/// Merged scratch occupancy: both bitmap views (at most 65,536 allocated
/// ranges each, bitmap_streaming::source_limits), every desired run and the
/// two margins.
const MAX_SCRATCH_INTERVALS: usize = 2 * 65_536 + MAX_PLACEMENT_RANGES + 2;
/// Fresh-snapshot re-plans allowed in each of the deferred and final phases
/// after the mover finds a planned destination allocated since the snapshot.
const MAX_DRIFT_REPLANS: usize = 8;

/// Evidence reservation allowance: one extra extent per this many bytes moved.
const SPLIT_ALLOWANCE_BYTES: u64 = 64 * 1024 * 1024;

// The coupled ceilings are raised together; none may undercut another.
const _: () = assert!(
    MAX_MOVES <= retention_layout::MAX_SUBRUNS
        && MAX_MOVES <= shadow_evacuation::MAX_MOVES
        && MAX_TRACKED_EXTENTS <= shadow_evacuation::MAX_EXTENTS
        && MAX_PLACEMENT_RANGES <= shadow_evacuation::MAX_EXTENTS
        && MAX_OWNED_RANGES + MAX_PLACEMENT_RANGES <= 2 * shadow_evacuation::MAX_EXTENTS
);

const DEFERRED_ORIGINAL: &str = "allocate-deferred-original";
const DEFERRED_SCRATCH: &str = "allocate-deferred-scratch";

pub(super) fn validate_limits(bytes: u64, submissions: usize) -> io::Result<()> {
    if bytes == 0 || !(1..=MAX_MOVES).contains(&submissions) {
        return Err(invalid("explicit placement limits differ"));
    }
    Ok(())
}

/// Diagnostic counts recorded with every progress update, so a refusal
/// artifact shows which bounded quantity was exceeded.
#[derive(Default, serde::Serialize)]
struct Counters {
    files: usize,
    #[serde(skip_serializing_if = "zero_count")]
    named_streams: usize,
    #[serde(skip_serializing_if = "zero_count")]
    sparse_streams: usize,
    #[serde(skip_serializing_if = "zero_count")]
    all_hole_sparse_streams: usize,
    #[serde(skip_serializing_if = "zero_bytes")]
    sparse_carrier_bytes: u64,
    #[serde(skip_serializing_if = "zero_count")]
    named_carrier_streams: usize,
    #[serde(skip_serializing_if = "zero_bytes")]
    named_carrier_bytes: u64,
    desired_runs: usize,
    desired_runs_limit: usize,
    initial_tracked_extents: usize,
    deferred_holes: usize,
    direct_pieces: usize,
    scratch_free_intervals: usize,
    planned_deferred_submissions: usize,
    tracked_extents: usize,
    tracked_extents_limit: usize,
    owned_intersecting_desired: usize,
    owned_intersecting_desired_limit: usize,
    eligible_runs: usize,
    evacuation_planned_moves: usize,
    evacuation_planned_submissions: usize,
    evacuation_remaining_blocked_bytes: u64,
    deferred_original_submissions: usize,
    deferred_scratch_submissions: usize,
    evacuation_submissions: usize,
    final_submissions: usize,
    // Recorded moves whose proof holds the mapping of the range they moved
    // (`retrieval_paging::RANGE_ENCODING`); every other one holds the file's
    // complete mapping. Only a run that verifies each thing once has any:
    // fewer than its submissions means ranged queries fell back.
    #[serde(skip_serializing_if = "zero_count")]
    moved_range_proofs: usize,
    move_submissions_limit: usize,
    move_evidence_bytes: usize,
    move_evidence_reservation_bytes: usize,
    placement_artifact_bytes: usize,
    placement_artifact_bytes_limit: usize,
    phase_bitmap_snapshots: usize,
    evacuation_drift_replans: usize,
    deferred_drift_replans: usize,
    final_drift_replans: usize,
    drift_replans_limit_per_phase: usize,
    // Kept at the progress/result top level, within the scalar-field reserve.
    #[serde(skip)]
    post_evacuation_barrier: Option<serde_json::Value>,
}

fn zero_count(value: &usize) -> bool {
    *value == 0
}
/// Counts a verified move whose proof holds the mapping of its range only
/// or defers retrieval verification to the end-of-placement complete check.
fn count_proof_form(counters: &mut Counters, proof: &serde_json::Value) {
    let encoding = &proof["mapping_page_proof"]["encoding"];
    if encoding == crate::retrieval_paging::RANGE_ENCODING
        || encoding == crate::retrieval_paging::DEFERRED_ENCODING
    {
        counters.moved_range_proofs += 1;
    }
}
fn zero_bytes(value: &u64) -> bool {
    *value == 0
}

fn placement_path(tree: &PrivateTree, key: &StreamKey, item: &Input<'_>) -> io::Result<String> {
    if tree.sparse_targets.contains_key(key) {
        use sha2::Digest as _;
        let directory = tree
            .carrier_directory
            .as_ref()
            .ok_or_else(|| invalid("sparse placement carrier directory absent"))?;
        let mut hash = sha2::Sha256::new();
        for unit in &key.name_utf16 {
            hash.update(unit.to_le_bytes());
        }
        Ok(format!(
            "{}\\carrier-{}-{}.bin",
            directory.path,
            key.object_index,
            hex::encode(hash.finalize())
        ))
    } else {
        streams::path(
            &tree.pair.shadow.volume_path()?,
            item.components,
            &key.name_utf16,
        )
    }
}

/// Slots are temporary planner IDs. A default stream keeps its historical
/// object index; every named stream has a distinct synthetic slot. No two
/// slots may reach the same placeholder or discard a placeholder entirely.
fn validate_stream_slots(tree: &PrivateTree, input: &impl InputDomain) -> io::Result<()> {
    if tree.stream_slots.len() != tree.files.len() {
        return Err(invalid(
            "stream placement slot/placeholder coverage differs",
        ));
    }
    let mut keys = BTreeSet::new();
    for (&slot, key) in &tree.stream_slots {
        if u32::try_from(slot).is_err()
            || key.object_index >= input.len()
            || (key.name_utf16.is_empty() && slot != key.object_index)
            || (!key.name_utf16.is_empty() && slot < input.len())
            || !tree.files.contains_key(key)
            || !keys.insert(key.clone())
        {
            return Err(invalid("stream placement slot is ambiguous or misbound"));
        }
        let owner = input.object(key.object_index)?;
        let object = owner.input();
        let original = streams::view_object(&object, &key.name_utf16)?;
        let needs_carrier = original.sparse.is_some()
            || (!key.name_utf16.is_empty() && original.logical_length() >= cluster());
        if needs_carrier != tree.sparse_targets.contains_key(key) {
            return Err(invalid("stream and carrier association differs"));
        }
        let stream = tree.placement_view_object(&object, key)?;
        if stream.directory || stream.sparse.is_some() {
            return Err(invalid("directory carries a data placement slot"));
        }
    }
    if tree.files.keys().any(|key| !keys.contains(key)) {
        return Err(invalid("stream placement omits a placeholder"));
    }
    for (key, target) in &tree.sparse_targets {
        let owner = input.object(key.object_index)?;
        let object = owner.input();
        let original = streams::view_object(&object, &key.name_utf16)?;
        target.layout.validate(target.logical_length)?;
        let layout_matches = if target.sparse_mode {
            original.sparse == Some(&target.layout)
        } else {
            original.sparse.is_none()
                && !key.name_utf16.is_empty()
                && original.logical_length() >= cluster()
                && target.layout.initialized_length == original.logical_length()
                && target.layout.holes.is_empty()
                && target.layout.allocated.len() == 1
                && target.layout.allocated[0].offset == 0
                && crate::target_cluster::ceil(original.logical_length())
                    == Some(target.layout.allocated[0].length)
        };
        if !layout_matches
            || original.logical_length() != target.logical_length
            || target.path
                != streams::path(
                    &tree.pair.shadow.volume_path()?,
                    original.components,
                    &key.name_utf16,
                )?
            || target.dense_length != target.layout.allocated_bytes()?
            || (target.dense_length == 0 && (tree.files.contains_key(key) || keys.contains(key)))
            || (target.dense_length != 0 && (!tree.files.contains_key(key) || !keys.contains(key)))
        {
            return Err(invalid("sparse target or dense carrier coverage differs"));
        }
    }
    Ok(())
}

fn progress(
    tree: &mut PrivateTree,
    phase: &str,
    charged_bytes: u64,
    verified: &Evidence<'_>,
    mut pending: Option<serde_json::Value>,
    counters: &Counters,
) {
    if let Some(row) = pending.as_mut()
        && let Some(slot) = row["object_index"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
        && let Some(key) = tree.stream_slots.get(&slot)
        && !key.name_utf16.is_empty()
    {
        row["canonical_object_index"] = key.object_index.into();
        row["stream_name_utf16"] = serde_json::json!(&key.name_utf16);
    }
    tree.placement_progress = progress_document(phase, charged_bytes, verified, pending, counters);
}

/// What a move's proof holds of its file's mapping, as the report and the
/// progress artifact name it. `complete-file-mapping`: every proof has the
/// whole mapping after the move (`retrieval_paging::ENCODING`).
/// `moved-range-v1`, on the resource route of a run that verifies each thing
/// once: the proof of a move that landed has the mapping of the range it
/// moved (`retrieval_paging::RANGE_ENCODING`); any other proof still has the
/// whole mapping. Each proof's `mapping_page_proof.encoding` says which of
/// the two it is (a range that starts at VCN 0 has the complete form's
/// layout, so the encoding is what tells them apart). The complete mapping of
/// every stream is compared with its tracked pieces once, when placement
/// ends. Nothing reads a move's mapping back from the records: an
/// interrupted placement is recovered, and a recovered one audited
/// (`audit_recovered_maps`), from the files' current native mappings and both
/// complete bitmaps, whichever form the records were written in.
fn per_move_retrieval_scope(resource: bool) -> &'static str {
    if resource && crate::verify_policy::verifies_once() {
        "moved-range-v1"
    } else {
        "complete-file-mapping"
    }
}

/// The progress artifact, rebuilt for every move (and once more after the
/// last: [`settle_progress`]). The recent phases and the pending step are
/// moved into it; `json!` copied each of them once more, value by value, on
/// the way in.
fn progress_document(
    phase: &str,
    charged_bytes: u64,
    verified: &Evidence<'_>,
    pending: Option<serde_json::Value>,
    counters: &Counters,
) -> serde_json::Value {
    // Keep a bounded tail, not a second copy of the complete mapping proofs.
    let phases: Vec<_> = verified
        .moves
        .iter()
        .rev()
        .take(16)
        .map(|m| serde_json::json!({"object_index":m["object_index"],"phase":m["phase"]}))
        .collect();
    let mut document = serde_json::json!({
        "schema_version":2,"kind":"private-placement-progress","phase":phase,
        "occupancy_evidence_scope":"destination-window-v1",
        // Only the resource route records its moves through a sink.
        "per_move_retrieval_scope":per_move_retrieval_scope(verified.sink.is_some()),
        "phase_bitmap_scope":"full-volume",
        "charged_move_bytes":charged_bytes,"verified_move_submissions":verified.len(),
        "counters":counters,
        "placement_complete":false,"resume_authorized":false,"conversion_qualified":false
    });
    document["recent_verified_phases_newest_first"] = serde_json::Value::Array(phases);
    document["pending"] = pending.unwrap_or(serde_json::Value::Null);
    if let Some(barrier) = &counters.post_evacuation_barrier {
        document["post_evacuation_barrier"] = barrier.clone();
    }
    document
}

/// The progress artifact once the move recorded as pending in it has been
/// made and before its proof is recorded: [`progress`] with nothing pending
/// would build the same document again, since nothing it is made of has
/// changed but what was written into it as the move went (its charge and
/// its evidence reservation).
fn settle_progress(tree: &mut PrivateTree) {
    settled(&mut tree.placement_progress);
}
fn settled(document: &mut serde_json::Value) {
    document["pending"] = serde_json::Value::Null;
}

/// Record the bounded quantity in the progress artifact and refuse.
fn refuse(tree: &mut PrivateTree, counters: &Counters, message: String) -> io::Error {
    if !tree.placement_progress.is_object() {
        progress(
            tree,
            "plan-desired-runs",
            0,
            &Evidence::default(),
            None,
            counters,
        );
    }
    tree.placement_progress["counters"] = serde_json::to_value(counters).unwrap_or_default();
    tree.placement_progress["refusal"] = message.as_str().into();
    invalid(&message)
}

fn charge_move(used: &mut u64, length: u64, limit: u64) -> io::Result<()> {
    let next = used
        .checked_add(length)
        .ok_or_else(|| invalid("placement byte budget overflow"))?;
    if next > limit {
        return Err(invalid(
            "placement byte budget exhausted before native IO; preserve without retry",
        ));
    }
    *used = next;
    Ok(())
}

/// Return the byte charge of a step the mover refused before submission.
fn uncharge_move(tree: &mut PrivateTree, used: &mut u64, length: u64) {
    *used -= length;
    tree.placement_progress["charged_move_bytes"] = (*used).into();
    tree.placement_progress["pending"]["budget_charged"] = false.into();
}

/// The mover found a planned destination allocated in its own live capture
/// of both views. That refusal precedes FSCTL_MOVE_FILE, poisoning and the
/// submission count, so the step may be planned again from a fresh snapshot.
/// Every other error, including any native one, stays fatal.
fn destination_drifted(error: &io::Error) -> bool {
    unwritten::OccupiedDestination::from_error(error).is_some()
}

/// Bytes `value` adds to the saved document as one element of a top-level
/// array: separator, two indentation levels before it and on each of its
/// inner lines (serde_json's pretty formatter indents two spaces).
fn saved_size(value: &(impl serde::Serialize + ?Sized)) -> Result<usize, String> {
    // Counted as it is written: the text itself is not needed.
    struct Count {
        bytes: usize,
        lines: usize,
    }
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("placement saved size overflow"))?;
            self.lines += bytes.iter().filter(|&&b| b == b'\n').count();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count { bytes: 0, lines: 0 };
    serde_json::to_writer_pretty(&mut count, value).map_err(|e| e.to_string())?;
    count
        .lines
        .checked_mul(4)
        .and_then(|n| n.checked_add(count.bytes))
        .and_then(|n| n.checked_add(6))
        .ok_or_else(|| "placement evidence accounting overflow".to_owned())
}

fn compact_size(value: &serde_json::Value) -> Result<usize, String> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("placement compact size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value).map_err(|e| e.to_string())?;
    Ok(count.0)
}

/// Move proofs are kept exactly as before. Their compact size is still
/// reported; the binding charge is each section's exact contribution to the
/// pretty-printed construction-placement.json, which must fit its save bound.
struct Evidence<'a> {
    moves: Vec<serde_json::Value>,
    compact_bytes: usize,
    saved_bytes: usize,
    count: usize,
    maximum: usize,
    sink: Option<&'a mut dyn PlacementEvidenceSink>,
}
impl Default for Evidence<'_> {
    fn default() -> Self {
        Self {
            moves: Vec::new(),
            compact_bytes: 0,
            saved_bytes: 0,
            count: 0,
            maximum: MAX_PLACEMENT_ARTIFACT_BYTES,
            sink: None,
        }
    }
}
impl<'a> Evidence<'a> {
    fn new(sink: Option<&'a mut dyn PlacementEvidenceSink>, maximum: usize) -> Self {
        Self {
            maximum,
            sink,
            ..Self::default()
        }
    }
    fn len(&self) -> usize {
        if self.sink.is_some() {
            self.count
        } else {
            self.moves.len()
        }
    }
    fn charge(&mut self, value: &serde_json::Value) -> Result<(), String> {
        let total = if self.sink.is_some() {
            compact_size(value)?
        } else {
            saved_size(value)?
        }
        .checked_add(self.saved_bytes)
        .ok_or("placement evidence accounting overflow")?;
        if total > self.maximum {
            return Err(format!(
                "placement evidence budget exceeded: {total} saved artifact bytes > \
                 {} after {} move proofs; preserve shadow without retry",
                self.maximum,
                self.len()
            ));
        }
        if let Some(sink) = &mut self.sink {
            sink.push("section", value).map_err(|e| e.to_string())?;
        }
        self.saved_bytes = total;
        Ok(())
    }

    fn push_move(&mut self, value: serde_json::Value) -> Result<(), String> {
        // Measured once: every move's proof was serialized twice here only to
        // count its bytes, before being serialized a third time to be stored.
        let size = compact_size(&value)?;
        let compact = size
            .checked_add(self.compact_bytes)
            .ok_or("placement evidence accounting overflow")?;
        if let Some(sink) = &mut self.sink {
            let total = self
                .saved_bytes
                .checked_add(size)
                .filter(|n| *n <= self.maximum)
                .ok_or("paged placement evidence resource exhausted")?;
            sink.push("move", &value).map_err(|e| e.to_string())?;
            self.saved_bytes = total;
            self.count = self
                .count
                .checked_add(1)
                .ok_or("placement move count overflow")?;
            // Progress uses only these two scalar fields. Every full proof is
            // already streamed; no second all-moves collection is retained.
            let recent =
                serde_json::json!({"object_index":value["object_index"],"phase":value["phase"]});
            if self.moves.len() == 16 {
                self.moves.remove(0);
            }
            self.moves.push(recent);
            drop(value);
        } else {
            self.charge(&value)?;
            self.moves.push(value);
        }
        self.compact_bytes = compact;
        Ok(())
    }

    /// Record a verified move: `{"object_index","phase","proof"}`, as
    /// `push_move` records it. A sink receives the record serialized once,
    /// straight from the proof; without one it is kept as a JSON value.
    fn push_move_proof(
        &mut self,
        object_index: u64,
        phase: &'static str,
        proof: &resource::MoveProof,
    ) -> Result<(), String> {
        if self.sink.is_none() {
            return self.push_move(serde_json::json!({
                "object_index":object_index,"phase":phase,"proof":proof
            }));
        }
        let json = move_record_json(object_index, phase, proof)?;
        let size = json.len();
        let compact = size
            .checked_add(self.compact_bytes)
            .ok_or("placement evidence accounting overflow")?;
        let total = self
            .saved_bytes
            .checked_add(size)
            .filter(|n| *n <= self.maximum)
            .ok_or("paged placement evidence resource exhausted")?;
        self.sink
            .as_mut()
            .ok_or("placement evidence sink absent")?
            .push_compact("move", &json)
            .map_err(|e| e.to_string())?;
        drop(json);
        self.saved_bytes = total;
        self.count = self
            .count
            .checked_add(1)
            .ok_or("placement move count overflow")?;
        let recent = serde_json::json!({"object_index":object_index,"phase":phase});
        if self.moves.len() == 16 {
            self.moves.remove(0);
        }
        self.moves.push(recent);
        self.compact_bytes = compact;
        Ok(())
    }

    fn failed_move(&mut self, value: serde_json::Value) -> Result<serde_json::Value, String> {
        if self.sink.is_none() {
            return Ok(value);
        }
        self.charge(&value)?;
        let summary = serde_json::json!({"object_index":value["object_index"],
            "phase":value["phase"],"native_error":value["proof"]["native_error"],
            "mapping_matches":value["proof"]["mapping_matches"],
            "all_placements_match":value["proof"]["all_placements_match"],
            "complete_proof_in_paged_evidence":true});
        drop(value);
        Ok(summary)
    }

    /// Refuse before native IO unless the next move record, at its bound,
    /// still fits. The exact charge after the move is unchanged.
    fn reserve(&mut self, bound: usize) -> Result<(), String> {
        if self
            .saved_bytes
            .checked_add(bound)
            .is_none_or(|total| total > self.maximum)
        {
            return Err(format!(
                "placement evidence reservation exceeded before native IO: {} saved artifact bytes \
                 + {bound} bound for the next move proof > {} after {} \
                 move proofs; preserve shadow without retry",
                self.saved_bytes,
                self.maximum,
                self.len()
            ));
        }
        if let Some(sink) = &mut self.sink {
            sink.reserve_next(bound as u64).map_err(|e| e.to_string())?;
            // Resource NativeMoveValue transfers the complete query/JSON
            // allowance which was prepaid before the physical operation.
        }
        Ok(())
    }
}

/// The compact JSON of a move record: the bytes of
/// `json!({"object_index":object_index,"phase":phase,"proof":proof})`,
/// whose keys a JSON value keeps in this order, without building that value.
fn move_record_json(
    object_index: u64,
    phase: &'static str,
    proof: &resource::MoveProof,
) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize)]
    struct Record<'a> {
        object_index: u64,
        phase: &'static str,
        proof: &'a resource::MoveProof,
    }
    serde_json::to_vec(&Record {
        object_index,
        phase,
        proof,
    })
    .map_err(|e| e.to_string())
}

/// Upper bound on a move record before native submission. Retrieval fields
/// retain their widest representation and all paging allowances. The actual
/// destination-window proof is charged after capture, before FSCTL_MOVE_FILE;
/// its serialized size cannot be inferred from the requested cluster count.
struct Reservation {
    base: usize,
    per_extent: usize,
    empty_destination: usize,
    maximum_resource_extents: Option<usize>,
}

impl Reservation {
    fn new() -> Result<Self, String> {
        Self::with_pages(crate::retrieval_paging::max_pages())
    }
    /// The bounds for records of `pages` retrieval pages, worked out from
    /// records of one and two pages and one extent.
    ///
    /// Every page of the widest record is the same text at the same depth
    /// (each of its fields at its widest), and so is every extent, so the
    /// saved size grows by the same number of bytes with each page from the
    /// first on, and with each extent. The record used to be built at
    /// `pages` pages to be measured: 3.5 KiB of memory a page, for as many
    /// pages as the budget's largest row admits (187,245 with a ledger of
    /// 10 GiB), and prepaid at 8,192 bytes a page, about a seventh of the
    /// ledger, at the start of placement (#129). The bounds are the same to the byte
    /// (`the_move_bounds_are_those_of_the_record_built_whole`).
    fn with_pages(pages: usize) -> Result<Self, String> {
        let base = widest_move_record_size(0, pages)?;
        let per_extent = widest_move_record_size(1, pages)?
            .checked_sub(base)
            .ok_or("placement evidence reservation differs")?;
        let empty_destination = saved_size(&serde_json::json!({
            "proof":{"destination_bitmap":serde_json::Value::Null}
        }))?;
        Ok(Self {
            base,
            per_extent,
            empty_destination,
            maximum_resource_extents: None,
        })
    }

    fn with_resource_limits(limits: crate::retrieval_paging::Limits) -> Result<Self, String> {
        let mut reservation = Self::with_pages(limits.max_pages)?;
        reservation.maximum_resource_extents = Some(limits.max_extents);
        Ok(reservation)
    }

    /// The file's canonical extents after a verified move: its current count,
    /// two for splitting one existing extent around the moved range, and one
    /// per 64 MiB moved as allowance for ReFS describing other ranges (for
    /// example a completed delayed allocation) with more extents. A larger
    /// proof is still refused by the exact charge after the move.
    fn bound(
        &self,
        current_extents: usize,
        length: u64,
        destination: &unwritten::DestinationWindows,
    ) -> Result<usize, String> {
        let allowance = usize::try_from(length.div_ceil(SPLIT_ALLOWANCE_BYTES))
            .map_err(|_| "placement evidence reservation overflow")?;
        let extents = if let Some(maximum) = self.maximum_resource_extents {
            if current_extents > maximum {
                return Err("current map exceeds original resource retrieval bound".into());
            }
            // Match the complete after-map accepted by the native resource
            // collector, including legal growth not predicted by this move.
            maximum
        } else {
            current_extents
                .checked_add(2)
                .and_then(|n| n.checked_add(allowance))
                .ok_or("placement evidence reservation overflow")?
        };
        // Use the exact enclosing shape so the pretty-printed indentation and
        // line count are charged at the proof's real nesting depth. Replacing
        // null here adds exactly the same bytes as in widest_move_record.
        // Measured as it is written, not built as a JSON value first: a
        // pretty-printed object takes the same bytes and lines whatever the
        // order of its keys.
        #[derive(serde::Serialize)]
        struct Destination<'a> {
            destination_bitmap: &'a unwritten::DestinationWindows,
        }
        #[derive(serde::Serialize)]
        struct Enclosing<'a> {
            proof: Destination<'a>,
        }
        let destination_bytes = saved_size(&Enclosing {
            proof: Destination {
                destination_bitmap: destination,
            },
        })?
        .checked_sub(self.empty_destination)
        .ok_or("placement destination evidence accounting differs")?;
        self.per_extent
            .checked_mul(extents)
            .and_then(|n| n.checked_add(self.base))
            .and_then(|n| n.checked_add(destination_bytes))
            .ok_or_else(|| "placement evidence reservation overflow".into())
    }
}

/// `saved_size` of `widest_move_record(extents, pages)`. A run's resource
/// limits allow thousands of pages, and the record was built and printed
/// with all of them. Its page proofs are identical elements of one array,
/// so from the first one on each further page adds the same bytes and lines.
fn widest_move_record_size(extents: usize, pages: usize) -> Result<usize, String> {
    if pages <= 2 {
        return saved_size(&widest_move_record(extents, pages)?);
    }
    let one = saved_size(&widest_move_record(extents, 1)?)?;
    let page = saved_size(&widest_move_record(extents, 2)?)?
        .checked_sub(one)
        .ok_or("placement evidence reservation differs")?;
    page.checked_mul(pages - 1)
        .and_then(|n| n.checked_add(one))
        .ok_or_else(|| "placement evidence reservation overflow".into())
}

fn widest_move_record(extents: usize, pages: usize) -> Result<serde_json::Value, String> {
    let digest = "f".repeat(64);
    let page = crate::retrieval_paging::PageProof {
        input: vec![u8::MAX; 8],
        response_header: [u8::MAX; 16],
        response_bytes: usize::MAX,
        native_error: Some(i32::MIN),
        response_sha256: digest.clone(),
    };
    let mapping_page_proof = crate::retrieval_paging::Proof {
        encoding: crate::retrieval_paging::ENCODING.into(),
        canonical_sha256: digest.clone(),
        extent_count: usize::MAX,
        virtual_clusters: u64::MAX,
        pages: vec![page; pages],
    };
    // Keep the destination field a null placeholder: its actual complete
    // transport is added by bound() immediately before the native submission.
    let proof = serde_json::json!({
        "destination_lcn":u64::MAX,"starting_vcn":u64::MAX,"clusters":u32::MAX,
        "submitted_once":false,"before_valid_data_advance":false,
        "native_error":i32::MIN,"mapping_matches":false,
        "all_placements_match":false,"reposition":false,
        "mapping_after":vec![u8::MAX;16+16*extents],
        "mapping_page_proof":mapping_page_proof,"destination_bitmap":serde_json::Value::Null,
    });
    // Wider than every object index and longer than every phase name.
    Ok(serde_json::json!({"object_index":u64::MAX,"phase":"x".repeat(64),"proof":proof}))
}

/// Check the next move's evidence bound before its native submission.
fn reserve_move(
    counters: &mut Counters,
    evidence: &mut Evidence<'_>,
    reservation: &Reservation,
    current_extents: usize,
    length: u64,
    destination: &unwritten::DestinationWindows,
) -> io::Result<()> {
    let bound = reservation
        .bound(current_extents, length, destination)
        .map_err(|message| invalid(&message))?;
    counters.move_evidence_reservation_bytes = bound;
    evidence.reserve(bound).map_err(|message| invalid(&message))
}

fn views(
    tree: &PrivateTree,
    limits: PlacementLimits,
) -> io::Result<(resource::Bitmap, resource::Bitmap)> {
    let a = resource::capture_bitmap(tree, &[0; 8], limits)?;
    let mut ex = [0u8; 16];
    ex[8] = 1;
    let b = resource::capture_bitmap(tree, &ex, limits)?;
    Ok((a, b))
}

/// Scalar diagnostics from actual complete views. No predicted free bit or
/// metadata-only ownership inference participates in these measurements.
fn barrier_snapshot(
    legacy: &Observation,
    metadata: &Observation,
    desired: &BTreeMap<usize, Vec<SourceRun>>,
    partition: u64,
    limits: PlacementLimits,
    payer: Option<&dyn report_memory::ReportMemoryAccountant>,
) -> io::Result<serde_json::Value> {
    let a = legacy.view(partition)?.candidate(0, partition)?;
    let b = metadata.view(partition)?.candidate(0, partition)?;
    let planner = resource::planner(legacy, metadata, partition, limits, payer)?;
    let mut free_bytes = 0u64;
    for run in desired.values().flatten() {
        let plan = planner.plan(
            retention_layout::SourceRun {
                logical_offset: run.logical_offset,
                physical_offset: run.physical_offset.ok_or_else(|| {
                    invalid("barrier measurement desired range lacks physical ownership")
                })?,
                length: run.length,
            },
            limits.subruns,
        )?;
        free_bytes = free_bytes
            .checked_add(plan.free_bytes)
            .ok_or_else(|| invalid("barrier desired free-byte count overflow"))?;
    }
    Ok(serde_json::json!({
        "legacy_full_map_sha256":a.bitmap_sha256,
        "metadata_full_map_sha256":b.bitmap_sha256,
        "legacy_allocated_clusters":a.allocated_clusters,
        "metadata_allocated_clusters":b.allocated_clusters,
        "desired_eligible_free_bytes":free_bytes,
        "volume_clusters":partition / cluster(),
        "observation_scope":"full-volume"
    }))
}

/// First-fit scratch over one phase snapshot: free in both native views,
/// outside every desired run and both margins, and not granted earlier in
/// this phase. Each grant is still rechecked by the mover's live capture.
struct Scratch {
    free: Vec<(u64, u64)>,
    /// Maximum remaining span length in each subtree. Leaves retain physical
    /// free-span order, so descending left first preserves exact first-fit
    /// choices without rescanning earlier too-small spans for every request.
    longest: Vec<u64>,
    leaves: usize,
    _memory: Option<Box<dyn report_memory::ReportMemoryLease>>,
}

impl Scratch {
    fn new(
        legacy: &Observation,
        metadata: &Observation,
        avoid: &[(u64, u64)],
        partition: u64,
        limits: PlacementLimits,
        payer: Option<&dyn report_memory::ReportMemoryAccountant>,
    ) -> Result<Self, String> {
        let count_ranges = |view: &Observation| -> Result<usize, String> {
            match view {
                Observation::Streamed { summary, .. } => Ok(summary.allocated_ranges.len()),
                _ => Err("resource scratch needs streamed complete bitmaps".into()),
            }
        };
        let memory = if limits.resource {
            let maps = count_ranges(legacy)?
                .checked_add(count_ranges(metadata)?)
                .ok_or("scratch map count overflow")?;
            let occupied = maps
                .checked_add(avoid.len())
                .and_then(|n| n.checked_add(2))
                .ok_or("scratch occupancy count overflow")?;
            let leaves = occupied
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or("scratch index count overflow")?;
            let bytes = (maps as u64)
                .checked_mul(64)
                .and_then(|n| n.checked_add((occupied as u64).checked_mul(128)?))
                .and_then(|n| n.checked_add((leaves as u64).checked_mul(32)?))
                .and_then(|n| n.checked_add(65536))
                .ok_or("scratch RAM overflow")?;
            Some(
                payer
                    .ok_or("scratch payer absent")?
                    .reserve(bytes)
                    .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let a = legacy
            .allocation_map(partition)
            .map_err(|e| e.to_string())?;
        let b = metadata
            .allocation_map(partition)
            .map_err(|e| e.to_string())?;
        let count = a
            .ranges
            .len()
            .checked_add(b.ranges.len())
            .and_then(|n| n.checked_add(avoid.len()))
            .and_then(|n| n.checked_add(2))
            .ok_or("scratch occupancy count overflow")?;
        if count > limits.scratch_intervals {
            return Err(format!(
                "scratch occupancy budget exceeded: {count} intervals > {}",
                limits.scratch_intervals
            ));
        }
        let mut occupied: Vec<(u64, u64)> = a
            .ranges
            .iter()
            .chain(&b.ranges)
            .map(|r| (r.offset, r.offset + r.length))
            .chain(avoid.iter().map(|&(start, length)| (start, start + length)))
            .chain([(0, MARGIN), (partition.saturating_sub(MARGIN), partition)])
            .collect();
        occupied.sort_unstable();
        let mut free = Vec::new();
        let mut cursor = 0;
        for (start, end) in occupied {
            if start > cursor {
                free.push((cursor, start));
            }
            cursor = cursor.max(end);
        }
        if cursor < partition {
            free.push((cursor, partition));
        }
        let leaves = free
            .len()
            .checked_next_power_of_two()
            .ok_or("scratch span index size overflow")?;
        let entries = leaves
            .checked_mul(2)
            .ok_or("scratch span index size overflow")?;
        let mut longest = Vec::new();
        longest
            .try_reserve_exact(entries)
            .map_err(|e| format!("scratch span index allocation failed: {e}"))?;
        longest.resize(entries, 0);
        for (i, &(start, end)) in free.iter().enumerate() {
            longest[leaves + i] = end - start;
        }
        for parent in (1..leaves).rev() {
            longest[parent] = longest[parent * 2].max(longest[parent * 2 + 1]);
        }
        Ok(Self {
            free,
            longest,
            leaves,
            _memory: memory,
        })
    }

    /// One contiguous span of at least `length`, lowest offset first. Spans
    /// too small for this request stay available to later, smaller ones.
    fn take(&mut self, length: u64) -> Option<u64> {
        if length == 0 || self.longest[1] < length {
            return None;
        }
        let mut node = 1;
        while node < self.leaves {
            let left = node * 2;
            node = if self.longest[left] >= length {
                left
            } else {
                left + 1
            };
        }
        let span = self.free.get_mut(node - self.leaves)?;
        let at = span.0;
        span.0 += length;
        self.longest[node] = span.1 - span.0;
        while node > 1 {
            node /= 2;
            self.longest[node] = self.longest[node * 2].max(self.longest[node * 2 + 1]);
        }
        Some(at)
    }
}

fn intersects_desired(avoid: &[(u64, u64)], offset: u64, length: u64) -> bool {
    // `avoid` is sorted and disjoint, so its ends are sorted as well.
    let first = avoid.partition_point(|&(start, len)| start + len <= offset);
    avoid
        .get(first)
        .is_some_and(|&(start, _)| start < offset + length)
}

pub(super) fn source_runs(item: &Input<'_>, partition: u64) -> io::Result<Vec<SourceRun>> {
    let prefix = crate::target_cluster::floor(item.logical_length());
    if item.source_offset.is_some() && !item.source_runs.is_empty() {
        return Err(invalid("mixed source placement forms"));
    }
    let result = if let Some(offset) = item.source_offset {
        vec![SourceRun {
            logical_offset: 0,
            physical_offset: Some(offset),
            length: prefix,
        }]
    } else {
        item.source_runs.clone()
    };
    let mut logical = 0;
    for (number, run) in result.iter().enumerate() {
        let physical = run
            .physical_offset
            .ok_or_else(|| invalid("private placement rejects source holes"))?;
        if run.length == 0
            || run.logical_offset != logical
            || !run.length.is_multiple_of(cluster())
            || !physical.is_multiple_of(cluster())
            || physical
                .checked_add(run.length)
                .is_none_or(|v| v > partition)
        {
            // Which run of which object, and what about it: a refusal that
            // says only that a mapping differs cannot be followed up.
            return Err(invalid(&format!(
                "source placement mapping differs for {}: run {number} of {} holds {} bytes at logical offset {} (expected {logical}) and physical offset {physical}, in clusters of {} bytes on a partition of {partition} bytes; the stream is {} bytes long",
                item.components.join("\\"),
                result.len(),
                run.length,
                run.logical_offset,
                cluster(),
                item.logical_length()
            )));
        }
        logical = logical
            .checked_add(run.length)
            .ok_or_else(|| invalid("source placement overflow"))?;
    }
    if logical > prefix {
        return Err(invalid("source placement exceeds logical prefix"));
    }
    Ok(result)
}

#[derive(Clone, Copy)]
struct Deferred {
    index: usize,
    logical: u64,
    destination: u64,
    length: u64,
    phase: &'static str,
    /// End of the deferred hole this step belongs to, for re-planning.
    hole_end: u64,
}

/// The memory of an index of the placement, paid for as the index grows.
///
/// The holes to allocate and the plan of deferred steps were each reserved
/// for as many entries as the indexes may ever hold, before the first was
/// found: 50 MiB of a run with 1.7 GiB, and eight times that once a slot
/// was counted at what it takes.
struct StepMemory<'a> {
    payer: &'a dyn report_memory::ReportMemoryAccountant,
    entry: u64,
    paid: usize,
    leases: Vec<Box<dyn report_memory::ReportMemoryLease>>,
}
impl<'a> StepMemory<'a> {
    /// A step, its place in `remaining_holes` and in a plan that replaces
    /// this one while both exist, in Vecs that double.
    const STEP: u64 =
        ((mem::size_of::<Deferred>() + 2 * mem::size_of::<(usize, u64, u64)>()) * 8) as u64;
    /// A hole, in a Vec that doubles and is copied once.
    const HOLE: u64 = (4 * mem::size_of::<(usize, u64, u64)>()) as u64;
    /// A range of a recovered stream's coordinates with its share of the
    /// stream's key, and its row of the report while that is written.
    const RECOVERED_RANGE: u64 = 512;
    /// A range of the audit of recovered allocations, in a Vec that doubles
    /// and is sorted.
    const AUDITED_RANGE: u64 = 128;
    const FIRST: usize = 1024;

    fn new(payer: &'a dyn report_memory::ReportMemoryAccountant, entry: u64) -> Self {
        Self {
            payer,
            entry,
            paid: 0,
            leases: Vec::new(),
        }
    }
    /// Pay for an index of `entries` before it holds that many; `limit` is
    /// the most it may hold.
    fn admit(&mut self, entries: usize, limit: usize) -> io::Result<()> {
        while entries > self.paid {
            let next = self
                .paid
                .saturating_mul(2)
                .clamp(Self::FIRST.min(limit), limit.max(entries));
            let more = (next - self.paid) as u64;
            self.leases.push(
                self.payer.reserve(
                    more.checked_mul(self.entry)
                        .and_then(|n| n.checked_add(65536))
                        .ok_or_else(|| invalid("placement index RAM overflow"))?,
                )?,
            );
            self.paid = next;
        }
        Ok(())
    }
}

/// Inputs fixed before the first native move.
#[derive(Clone, Copy)]
struct Wanted<'a> {
    desired: &'a BTreeMap<usize, Vec<SourceRun>>,
    avoid: &'a [(u64, u64)],
    partition: u64,
    max_moves: usize,
    limits: PlacementLimits,
    payer: Option<&'a dyn report_memory::ReportMemoryAccountant>,
}

/// The unexecuted part of each hole in `steps`, in plan order.
fn remaining_holes(steps: &[Deferred]) -> Vec<(usize, u64, u64)> {
    let mut holes: Vec<(usize, u64, u64)> = Vec::new();
    for step in steps {
        if holes
            .last()
            .is_none_or(|&(index, _, end)| index != step.index || end != step.hole_end)
        {
            holes.push((step.index, step.logical, step.hole_end));
        }
    }
    holes
}

/// Plan deferred allocation of `holes` (object index, start and end byte)
/// from one snapshot of both native views. Direct pieces land only in the
/// file's own desired runs (disjoint, checked by the caller) and scratch only
/// outside every desired run, so moves in this plan cannot change what it
/// relies on; each move still captures both live views and is refused unless
/// its destination is free in both. `executed` moves already used the budget.
/// The outer error is native, the inner one a bounded refusal.
fn plan_deferred(
    wanted: Wanted<'_>,
    legacy: &Observation,
    metadata: &Observation,
    holes: &[(usize, u64, u64)],
    executed: usize,
    counters: &mut Counters,
    mut memory: Option<&mut StepMemory<'_>>,
) -> io::Result<Result<Vec<Deferred>, String>> {
    let Wanted {
        desired,
        avoid,
        partition,
        max_moves,
        limits,
        payer,
    } = wanted;
    let mut scratch = match Scratch::new(legacy, metadata, avoid, partition, limits, payer) {
        Ok(value) => value,
        Err(message) => return Ok(Err(message)),
    };
    counters.scratch_free_intervals = scratch.free.len();
    let planner = resource::planner(legacy, metadata, partition, limits, payer)?;
    let mut deferred = Vec::new();
    for &(index, start, end) in holes {
        // A deferred range has no old physical ownership to evacuate.
        // Allocate it at the wanted coordinates first where both native
        // views agree they are free, rather than parking the entire range
        // and submitting the same bytes a second time during final placement.
        let mut direct = Vec::new();
        // Desired runs were validated once as a disjoint logical prefix.
        // Skip runs ending before this hole, then visit only its intersections.
        // The old full scan emitted these same pieces in this same order.
        let runs = &desired[&index];
        let first = runs.partition_point(|run| run.logical_offset + run.length <= start);
        for run in &runs[first..] {
            if run.logical_offset >= end {
                break;
            }
            let from = start.max(run.logical_offset);
            let to = end.min(run.logical_offset + run.length);
            if from >= to {
                continue;
            }
            let plan = planner.plan(
                retention_layout::SourceRun {
                    logical_offset: from,
                    physical_offset: run.physical_offset.unwrap() + from - run.logical_offset,
                    length: to - from,
                },
                max_moves.min(limits.subruns),
            )?;
            for subrun in plan.subruns.iter().copied() {
                // Keep the same bootstrap margins as scratch allocation.
                let physical_start = subrun.physical_offset.max(MARGIN);
                let physical_end =
                    (subrun.physical_offset + subrun.length).min(partition.saturating_sub(MARGIN));
                if physical_start < physical_end {
                    if limits.resource && direct.len() == limits.subruns {
                        return Ok(Err(
                            "resource direct-piece index exhausted before native IO".into(),
                        ));
                    }
                    direct.push((
                        subrun.logical_offset + physical_start - subrun.physical_offset,
                        physical_start,
                        physical_end - physical_start,
                    ));
                }
            }
            if direct.len() > max_moves {
                counters.direct_pieces += direct.len();
                return Ok(Err(format!(
                    "direct deferred allocation range budget exhausted: {} pieces in one hole > {max_moves}",
                    direct.len()
                )));
            }
        }
        direct.sort_unstable_by_key(|r| r.0);
        counters.direct_pieces += direct.len();
        let mut cursor = start;
        let mut next_direct = 0;
        while cursor < end {
            if limits.resource && deferred.len() == limits.subruns {
                return Ok(Err(format!(
                    "resource deferred-step index exhausted before native IO: more than the {} steps this much memory indexes",
                    limits.subruns
                )));
            }
            if let Some(memory) = memory.as_deref_mut() {
                memory.admit(deferred.len() + 1, limits.subruns)?;
            }
            if executed + deferred.len() >= max_moves {
                counters.planned_deferred_submissions = executed + deferred.len();
                return Ok(Err(format!(
                    "deferred allocation move budget exhausted before native IO: more than {max_moves} planned submissions"
                )));
            }
            while next_direct < direct.len()
                && direct[next_direct].0 + direct[next_direct].2 <= cursor
            {
                next_direct += 1;
            }
            let (destination, length, phase) = match direct.get(next_direct) {
                Some(&(logical, physical, bytes)) if logical <= cursor => (
                    physical + cursor - logical,
                    (logical + bytes - cursor).min(MOVE_BYTES),
                    DEFERRED_ORIGINAL,
                ),
                candidate => {
                    let stop = candidate.map_or(end, |r| r.0.min(end));
                    let length = (stop - cursor).min(MOVE_BYTES);
                    let Some(destination) = scratch.take(length) else {
                        counters.planned_deferred_submissions = executed + deferred.len();
                        return Ok(Err(format!(
                            "no independently free scratch span outside desired source ranges: {length} bytes requested from {} snapshot intervals",
                            counters.scratch_free_intervals
                        )));
                    };
                    (destination, length, DEFERRED_SCRATCH)
                }
            };
            deferred.push(Deferred {
                index,
                logical: cursor,
                destination,
                length,
                phase,
                hole_end: end,
            });
            cursor += length;
        }
    }
    counters.planned_deferred_submissions = executed + deferred.len();
    Ok(Ok(deferred))
}

/// Allocate only still-unmapped logical holes. The same implementation serves
/// both phase orders; prior verified evacuation moves still consume the shared
/// move/evidence budgets. Native destination and complete-map checks are unchanged.
fn allocate_deferred(
    tree: &mut PrivateTree,
    wanted: Wanted<'_>,
    holes: &[(usize, u64, u64)],
    max_move_bytes: u64,
    reservation: &Reservation,
    evidence: &mut Evidence,
    counters: &mut Counters,
    move_bytes: &mut u64,
    initial_views: Option<(resource::Bitmap, resource::Bitmap)>,
) -> io::Result<()> {
    // Plan every deferred hole from one snapshot of both native views. If
    // ReFS allocates a planned destination after it, the mover refuses that
    // step before submission; the rest of the phase is then planned again
    // from one fresh snapshot, a bounded number of times.
    let mut deferred_memory = if wanted.limits.resource {
        Some(StepMemory::new(
            wanted
                .payer
                .ok_or_else(|| invalid("deferred payer absent"))?,
            StepMemory::STEP,
        ))
    } else {
        None
    };
    let (legacy, metadata) = match initial_views {
        Some(pair) => pair,
        None => {
            counters.phase_bitmap_snapshots += 1;
            views(tree, wanted.limits)?
        }
    };
    let mut base_moves = evidence.len();
    let mut deferred = match plan_deferred(
        wanted,
        &legacy,
        &metadata,
        holes,
        base_moves,
        counters,
        deferred_memory.as_mut(),
    )? {
        Ok(steps) => steps,
        Err(message) => return Err(refuse(tree, counters, message)),
    };
    let mut next_step = 0;
    while let Some(&step) = deferred.get(next_step) {
        progress(
            tree,
            step.phase,
            *move_bytes,
            &evidence,
            Some(serde_json::json!({
            "object_index":step.index,"logical_offset":step.logical,"destination":step.destination,
            "length":step.length,"placement_result_recorded":false,"budget_charged":false})),
            counters,
        );
        let current_extents = tree.file_by_slot(step.index)?.retrieval_extents();
        charge_move(move_bytes, step.length, max_move_bytes)?;
        tree.placement_progress["charged_move_bytes"] = (*move_bytes).into();
        tree.placement_progress["pending"]["budget_charged"] = true.into();
        let attempt = resource::move_slot(
            tree,
            step.index,
            step.logical / cluster(),
            step.destination / cluster(),
            move_clusters(step.length)?,
            false,
            wanted.limits.resource,
            |destination| {
                reserve_move(
                    counters,
                    evidence,
                    reservation,
                    current_extents,
                    step.length,
                    destination,
                )
            },
        );
        tree.placement_progress["counters"]["move_evidence_reservation_bytes"] =
            counters.move_evidence_reservation_bytes.into();
        let proof = match attempt {
            Err(error) if destination_drifted(&error) => {
                uncharge_move(tree, move_bytes, step.length);
                if counters.deferred_drift_replans == MAX_DRIFT_REPLANS {
                    return Err(refuse(
                        tree,
                        counters,
                        format!(
                            "deferred allocation destination allocated after {MAX_DRIFT_REPLANS} \
                             fresh-snapshot re-plans: {error}; preserve shadow without retry"
                        ),
                    ));
                }
                counters.deferred_drift_replans += 1;
                let remaining = remaining_holes(&deferred[next_step..]);
                let (legacy, metadata) = views(tree, wanted.limits)?;
                counters.phase_bitmap_snapshots += 1;
                let planned = match plan_deferred(
                    wanted,
                    &legacy,
                    &metadata,
                    &remaining,
                    base_moves + next_step,
                    counters,
                    deferred_memory.as_mut(),
                )? {
                    Ok(steps) => steps,
                    Err(message) => return Err(refuse(tree, counters, message)),
                };
                if wanted.limits.resource {
                    deferred = planned;
                    next_step = 0;
                    base_moves = evidence.len();
                } else {
                    deferred.truncate(next_step);
                    deferred.extend(planned);
                }
                continue;
            }
            result => result?,
        };
        if proof["native_error"] != serde_json::Value::Null || proof["all_placements_match"] != true
        {
            tree.placement_progress["failed_native_move"] = evidence
                .failed_move(serde_json::json!({
                    "object_index":step.index,"phase":step.phase,"proof":proof
                }))
                .map_err(|e| invalid(&e))?;
            return Err(invalid(
                "deferred unwritten allocation refused; preserve without retry",
            ));
        }
        if step.phase == DEFERRED_ORIGINAL {
            counters.deferred_original_submissions += 1;
        } else {
            counters.deferred_scratch_submissions += 1;
        }
        count_proof_form(counters, &proof);
        let recorded = evidence.push_move_proof(step.index as u64, step.phase, &proof);
        counters.move_evidence_bytes = evidence.compact_bytes;
        counters.placement_artifact_bytes = evidence.saved_bytes;
        if let Err(message) = recorded {
            return Err(refuse(tree, counters, message));
        }
        // Where another step follows, the next thing done is to record it
        // as pending: this record would be replaced unread.
        if next_step + 1 >= deferred.len() {
            progress(tree, step.phase, *move_bytes, &evidence, None, counters);
        }
        next_step += 1;
    }
    Ok(())
}

pub(super) fn run(
    tree: &mut PrivateTree,
    input: &[Input<'_>],
    max_move_bytes: u64,
    max_moves: usize,
) -> io::Result<serde_json::Value> {
    run_domain(tree, &SliceInputs(input), max_move_bytes, max_moves)
}

pub(super) fn run_domain(
    tree: &mut PrivateTree,
    input: &impl InputDomain,
    max_move_bytes: u64,
    max_moves: usize,
) -> io::Result<serde_json::Value> {
    let limits = PlacementLimits::legacy(tree.pair.shadow.identity.partition_bytes, max_moves)?;
    run_domain_inner(tree, input, max_move_bytes, max_moves, limits, None, None)
}

pub(super) fn run_resource_domain(
    tree: &mut PrivateTree,
    input: &impl InputDomain,
    max_move_bytes: u64,
    max_moves: usize,
    sink: &mut dyn PlacementEvidenceSink,
) -> io::Result<ResourcePlacementReport> {
    tree.require_dedicated_shadow_boundary()?;
    let result = (|| {
        let admission = tree
            .metadata_resource_admission
            .ok_or_else(|| invalid("actual resource private-tree admission absent"))?;
        if tree.memory.is_none() {
            return Err(invalid("actual resource placement payer absent"));
        }
        input.require_resource_metadata(admission)?;
        let limits = PlacementLimits::resource(
            admission,
            tree.pair.shadow.identity.partition_bytes,
            max_move_bytes,
            max_moves,
            sink.maximum_bytes(),
        )?;
        let payer = tree
            .memory
            .as_ref()
            .ok_or_else(|| invalid("actual resource placement payer absent"))?
            .payer();
        for file in tree.files.values_mut() {
            file.enable_resource_placement(
                admission,
                limits.tracked,
                limits.moves,
                max_move_bytes,
                payer.clone(),
            )?;
        }
        let report_memory = payer.reserve(2 * 1024 * 1024)?;
        let value = run_domain_inner(
            tree,
            input,
            max_move_bytes,
            limits.moves,
            limits,
            Some(sink),
            None,
        )?;
        match ResourcePlacementReport::new(value, report_memory) {
            Ok(report) => {
                tree.placement_complete = true;
                tree.placement_progress["placement_complete"] = true.into();
                Ok(report)
            }
            Err(error) => {
                tree.placement_complete = false;
                tree.original_coordinates.clear();
                Err(error)
            }
        }
    })();
    let closing = tree.require_dedicated_shadow_boundary();
    match (result, closing) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Err(boundary)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; dedicated shadow placement closing roles also failed: {boundary}"),
        )),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

/// Additional entry point requires a freshly issued native recovered origin;
/// the fresh constructor's single-attempt checks above remain unchanged.
pub(super) fn run_recovered_resource_domain(
    tree: &mut PrivateTree,
    input: &impl InputDomain,
    origin: &recovery::RecoveredOrigin,
    sink: &mut dyn PlacementEvidenceSink,
) -> io::Result<ResourcePlacementReport> {
    origin.require_tree(tree)?;
    tree.require_dedicated_shadow_boundary()?;
    let result = (|| {
        let admission = tree
            .metadata_resource_admission
            .ok_or_else(|| invalid("recovered admission absent"))?;
        input.require_resource_metadata(admission)?;
        let (bytes, moves) = origin.remaining();
        let limits = PlacementLimits::resource(
            admission,
            tree.pair.shadow.identity.partition_bytes,
            bytes,
            moves,
            sink.maximum_bytes(),
        )?;
        if tree.files.values().any(|f| !f.resource_placement_enabled()) {
            return Err(invalid(
                "recovered file lacks fresh native map/resource owner",
            ));
        }
        let payer = tree
            .memory
            .as_ref()
            .ok_or_else(|| invalid("recovered payer absent"))?
            .payer();
        let report_memory = payer.reserve(2 * 1024 * 1024)?;
        let mut value = run_domain_inner(
            tree,
            input,
            bytes,
            limits.moves,
            limits,
            Some(sink),
            Some(origin),
        )?;
        value["recovered_origin"] = origin.receipt();
        let report = ResourcePlacementReport::new(value, report_memory)?;
        tree.placement_complete = true;
        tree.placement_progress["placement_complete"] = true.into();
        Ok(report)
    })();
    let closing = tree.require_dedicated_shadow_boundary();
    match (result, closing) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), Err(boundary)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; recovered closing roles also failed: {boundary}"),
        )),
        (Err(error), _) | (_, Err(error)) => {
            tree.placement_complete = false;
            Err(error)
        }
    }
}

/// Subtract only exact current logical-to-physical matches. Occupied ranges
/// belonging to another coordinate remain work for the existing planner.
pub(super) fn rehydrate_recovered_resource_domain(
    tree: &mut PrivateTree,
    input: &impl InputDomain,
    origin: &recovery::RecoveredOrigin,
    sink: &mut dyn PlacementEvidenceSink,
) -> io::Result<ResourcePlacementReport> {
    origin.require_tree(tree)?;
    tree.require_dedicated_shadow_boundary()?;
    tree.require_bound_input_domain(input)?;
    let admission = tree
        .metadata_resource_admission
        .ok_or_else(|| invalid("placed recovery admission absent"))?;
    input.require_resource_metadata(admission)?;
    if input.len() != tree.initial_objects.len() {
        return Err(invalid("placed recovery object coverage differs"));
    }
    let (bytes, moves) = origin.remaining();
    let limits = PlacementLimits::resource(
        admission,
        tree.pair.shadow.identity.partition_bytes,
        bytes,
        moves,
        sink.maximum_bytes(),
    )?;
    let payer = tree
        .memory
        .as_ref()
        .ok_or_else(|| invalid("placed recovery payer absent"))?
        .payer();
    // Paid for as the ranges are found. It was reserved for as many as the
    // index may ever hold before the first was read: 26 MiB of a run with
    // 1.7 GiB, and 212 MiB once a slot was counted at what it takes.
    let _fixed_memory = payer.reserve(4 * 1024 * 1024)?;
    let mut range_memory = StepMemory::new(&*payer, StepMemory::RECOVERED_RANGE);
    let report_memory = payer.reserve(2 * 1024 * 1024)?;
    let mut retained_streams = BTreeMap::new();
    let mut retained_bytes = 0u64;
    let mut retained_ranges = 0usize;
    for (&slot, key) in &tree.stream_slots {
        let file = tree.file_by_slot(slot)?;
        let owner = input.object(key.object_index)?;
        let object = owner.input();
        let item = tree.placement_view_object(&object, key)?;
        let prefix = crate::target_cluster::floor(item.logical_length());
        if file.logical_length() != item.logical_length()
            || file.path != placement_path(tree, key, &item)?
            || file.valid_prefix()
                != if origin.payloads_ready() {
                    item.logical_length()
                } else {
                    prefix
                }
        {
            return Err(invalid(
                "placed recovery stream shape or initialized prefix differs",
            ));
        }
        if prefix > 0 && !file.revalidate_recovered_prefix(prefix)? {
            return Err(invalid(
                "placed recovery prefix lacks current native readiness",
            ));
        }
        file.check_placements()?;
        let tracked = file.tracked_mappings();
        let mut cursor = 0u64;
        for &(v, l, n) in tracked {
            if n == 0
                || v != cursor
                || l.checked_add(u64::from(n))
                    .is_none_or(|e| e > tree.pair.shadow.identity.partition_bytes / cluster())
            {
                return Err(invalid(
                    "placed recovery mapping is not a complete dense prefix",
                ));
            }
            cursor = cursor
                .checked_add(u64::from(n))
                .ok_or_else(|| invalid("placed recovery logical map overflow"))?;
        }
        if cursor != prefix / cluster() {
            return Err(invalid("placed recovery complete prefix map absent"));
        }
        let mut ranges = Vec::new();
        for source in source_runs(&item, tree.pair.shadow.identity.partition_bytes)? {
            let wanted_vcn = source.logical_offset / cluster();
            let wanted_lcn = source
                .physical_offset
                .ok_or_else(|| invalid("placed recovery source LCN absent"))?
                / cluster();
            let wanted_end = wanted_vcn
                .checked_add(source.length / cluster())
                .ok_or_else(|| invalid("placed recovery source VCN overflow"))?;
            let first = tracked.partition_point(|&(v, _, n)| v + u64::from(n) <= wanted_vcn);
            for &(v, l, n) in &tracked[first..] {
                if v >= wanted_end {
                    break;
                }
                let start = v.max(wanted_vcn);
                let end = (v + u64::from(n)).min(wanted_end);
                if start >= end || l + start - v != wanted_lcn + start - wanted_vcn {
                    continue;
                }
                if retained_ranges == limits.tracked {
                    return Err(invalid("placed recovery coordinate index exhausted"));
                }
                range_memory.admit(retained_ranges + 1, limits.tracked)?;
                retained_ranges += 1;
                let row = (
                    start * cluster(),
                    (l + start - v) * cluster(),
                    (end - start) * cluster(),
                );
                retained_bytes = retained_bytes
                    .checked_add(row.2)
                    .ok_or_else(|| invalid("placed recovery retained bytes overflow"))?;
                let value = serde_json::json!({"object_index":slot,"logical_offset":row.0,
                    "source_physical_offset":row.1,"target_physical_offset":row.1,"length":row.2,
                    "source_contents_verified":false,"derived_from_current_native_maps":true});
                let maximum = serde_json::to_vec(&value).map_err(io::Error::other)?.len() as u64;
                sink.reserve_next(maximum)?;
                sink.push("section", &value)?;
                ranges.push(row);
            }
        }
        if !ranges.is_empty() && retained_streams.insert(key.clone(), ranges).is_some() {
            return Err(invalid("placed recovery stream coordinates collide"));
        }
    }
    // This is a fresh complete ownership audit, not an old placement verdict.
    audit_recovered_maps(tree, bytes, moves)?;
    tree.require_source_excluded()?;
    tree.require_dedicated_shadow_boundary()?;
    let receipt = sink.finish()?;
    let retained = memory::coordinate_map_bytes(&retained_streams)?;
    // What is kept is measured now: its reservation takes the place of
    // what the ranges paid while they were found.
    drop(range_memory);
    let mut memory = Some(payer.reserve(retained)?);
    tree.memory
        .as_ref()
        .ok_or_else(|| invalid("placed recovery memory absent"))?
        .retain_from(&mut memory, retained)?;
    let value = serde_json::json!({"schema_version":3,"kind":"private-source-backed-placement-revalidation-pages",
        "recovered_origin":origin.receipt(),"paged_evidence":receipt,
        "original_coordinate_bytes":retained_bytes,"move_bytes_submitted":0,"move_count":0,
        "max_move_bytes":bytes,"max_move_submissions":moves,
        "counters":{"retained_ranges":retained_ranges,"native_move_submissions":0},
        "payload_contents_verified":false,"historical_payloads_trusted":false,"source_payload_writes":0,
        "conversion_qualified":false});
    let report = ResourcePlacementReport::new(value, report_memory)?;
    tree.original_coordinates = retained_streams;
    tree.placement_complete = true;
    tree.placement_progress = serde_json::json!({"phase":"current-native-placement-revalidated","placement_complete":true,"native_move_submissions":0});
    Ok(report)
}

fn unfinished_runs(
    file: &unwritten::PrivatePlaceholder,
    run: &SourceRun,
    maximum: usize,
) -> io::Result<Vec<SourceRun>> {
    let start = run.logical_offset;
    let end = start
        .checked_add(run.length)
        .ok_or_else(|| invalid("recovered desired logical range overflow"))?;
    let wanted = run
        .physical_offset
        .ok_or_else(|| invalid("recovered desired physical range absent"))?;
    let mut cursor = start;
    let mut out = Vec::new();
    let cluster = cluster();
    for &(v, l, n) in file.tracked_mappings() {
        let a = (v * cluster).max(start);
        let b = ((v + u64::from(n)) * cluster).min(end);
        if a >= b || l * cluster + a - v * cluster != wanted + a - start {
            continue;
        }
        if a > cursor {
            if out.len() == maximum {
                return Err(invalid("recovered remaining-range index exhausted"));
            }
            out.push(SourceRun {
                logical_offset: cursor,
                physical_offset: Some(wanted + cursor - start),
                length: a - cursor,
            });
        }
        cursor = cursor.max(b);
    }
    if cursor < end {
        if out.len() == maximum {
            return Err(invalid("recovered remaining-range index exhausted"));
        }
        out.push(SourceRun {
            logical_offset: cursor,
            physical_offset: Some(wanted + cursor - start),
            length: end - cursor,
        });
    }
    Ok(out)
}

/// Of the row a recovered target's mapping queries are limited to, what the
/// mapping of a target of `rounded` bytes with `allocated` bytes of
/// allocation can take. Every allocated extent is a cluster or more, and
/// between two of them there is one hole at the most: a target of `n`
/// allocated clusters has no more than `2n + 1` extents. Counted here are
/// twice its clusters and one response's worth more, at what a row holds
/// them as ([`crate::retrieval_paging::Limits::for_resource_bytes`]: a
/// quarter of the row for what is returned, sixteen bytes an extent, twice,
/// and sixteen a page). The workspace was eight of the row itself, an
/// eighth of the run's memory, for every target, whatever it held.
fn recovered_retrieval_bytes(row: usize, rounded: u64, allocated: u64) -> usize {
    let per_response = crate::stream_layout::MAX_EXTENTS as u64;
    let clusters = rounded.max(allocated).div_ceil(cluster());
    let extents = clusters.saturating_mul(2).saturating_add(per_response);
    let pages = (extents / per_response).saturating_mul(2).max(2);
    let returned = extents
        .saturating_mul(16)
        .saturating_add(16)
        .saturating_mul(2)
        .saturating_add(pages.saturating_mul(16));
    usize::try_from(returned.saturating_mul(4))
        .unwrap_or(usize::MAX)
        .min(row)
}

/// Native audit of complete CURRENT retrievals against BOTH full bitmaps.
/// Bitmap occupancy does not create ownership: every range came from a held
/// recovered file's own complete retrieval capture, and aliases refuse.
pub(super) fn audit_recovered_maps(tree: &PrivateTree, bytes: u64, moves: usize) -> io::Result<()> {
    let admission = tree
        .metadata_resource_admission
        .ok_or_else(|| invalid("recovered admission absent"))?;
    let limits = PlacementLimits::resource(
        admission,
        tree.pair.shadow.identity.partition_bytes,
        bytes,
        moves,
        admission.budget.scratch_bytes,
    )?;
    let payer = tree
        .memory
        .as_ref()
        .ok_or_else(|| invalid("recovered audit payer absent"))?
        .payer();
    // Paid for as the ranges are found, not for as many as the index may
    // ever hold.
    let mut range_memory = StepMemory::new(&*payer, StepMemory::AUDITED_RANGE);
    let (legacy, metadata) = views(tree, limits)?;
    let partition = tree.pair.shadow.identity.partition_bytes;
    let a = legacy.view(partition)?;
    let b = metadata.view(partition)?;
    let mut ranges = Vec::new();
    for target in tree.sparse_targets.values() {
        let rounded = crate::target_cluster::ceil(target.logical_length)
            .ok_or_else(|| invalid("recovered target EOF overflow"))?;
        let identity = info(&target.file, 18, 24)?;
        let standard = info(&target.file, 1, 24)?;
        unwritten::recovery::require_zero_storage_vdl(&target.file, rounded)?;
        let evidence_bytes =
            usize::try_from(admission.budget.max_row_bytes).map_err(io::Error::other)?;
        // The queries stay limited to the row; their workspace is what
        // this target's allocation can make of it. (`standard` is held to
        // what it is here until the capture has been read.)
        let workspace =
            recovered_retrieval_bytes(evidence_bytes, rounded, layout::u64_at(&standard, 0)?);
        let _retrieval_memory = payer.reserve(
            (workspace as u64)
                .checked_mul(8)
                .and_then(|n| n.checked_add(4 * 1024 * 1024))
                .ok_or_else(|| invalid("recovered target retrieval RAM overflow"))?,
        )?;
        let (first, continuation) =
            crate::stream_native::retrieval_queries_resource(&target.file, evidence_bytes)?;
        let empty_retrieval = continuation.is_empty()
            && layout::u64_at(&standard, 0)? == 0
            && ((first.native_error == Some(38) && first.bytes.is_empty())
                || (first.native_error.is_none()
                    && first.bytes.len() == 16
                    && layout::u32_at(&first.bytes, 0)? == 0
                    && rounded == 0));
        if !empty_retrieval {
            let capture = crate::retrieval_paging::assemble_queries_with_limits(
                &first,
                &continuation,
                crate::retrieval_paging::Limits::for_resource_bytes(evidence_bytes)?,
            )?;
            for run in &capture.runs {
                let Some(lcn) = run.lcn else {
                    continue;
                };
                sparse_stream::require_recovered_island(&target.layout, &target.path, run)?;
                if run.clusters == 0 || ranges.len() == limits.tracked {
                    return Err(invalid("recovered allocation range bound exhausted"));
                }
                range_memory.admit(ranges.len() + 1, limits.tracked)?;
                let offset = lcn
                    .checked_mul(cluster())
                    .ok_or_else(|| invalid("recovered target LCN overflow"))?;
                let length = run
                    .clusters
                    .checked_mul(cluster())
                    .ok_or_else(|| invalid("recovered target allocation overflow"))?;
                let aa = a.candidate(offset, length)?;
                let bb = b.candidate(offset, length)?;
                if aa.allocated_clusters != run.clusters || bb.allocated_clusters != run.clusters {
                    return Err(invalid(
                        "native recovered target ownership is absent from a complete bitmap view",
                    ));
                }
                ranges.push((
                    lcn,
                    lcn.checked_add(run.clusters)
                        .ok_or_else(|| invalid("recovered target LCN end overflow"))?,
                ));
            }
        }
        if info(&target.file, 18, 24)? != identity || info(&target.file, 1, 24)? != standard {
            return Err(invalid(
                "recovered target identity or lengths changed during allocation audit",
            ));
        }
        unwritten::recovery::require_zero_storage_vdl(&target.file, rounded)?;
    }
    for file in tree.files.values() {
        file.check_placements()?;
        for (lcn, clusters) in file.current_allocated_ranges()? {
            if clusters == 0 || ranges.len() == limits.tracked {
                return Err(invalid("recovered allocation range bound exhausted"));
            }
            range_memory.admit(ranges.len() + 1, limits.tracked)?;
            let aa = a.candidate(lcn * cluster(), clusters * cluster())?;
            let bb = b.candidate(lcn * cluster(), clusters * cluster())?;
            if aa.allocated_clusters != clusters || bb.allocated_clusters != clusters {
                return Err(invalid(
                    "native recovered ownership is absent from a complete bitmap view",
                ));
            }
            ranges.push((lcn, lcn + clusters));
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(invalid(
            "native recovered files have overlapping physical ownership",
        ));
    }
    tree.require_source_excluded()?;
    Ok(())
}

/// How many files' first mapping queries [`TrackingQueries`] makes at a
/// time: their runs wait here until the files are tracked.
const TRACKING_ROUND: usize = 4096;
/// The most helpers that make them, as the final comparison of the files'
/// mappings has.
const TRACKING_HELPERS: usize = 8;

/// The first query of every file's mapping, which binds its allocated
/// ownership before any move, made by helper threads.
///
/// One thread asked Windows for the complete mapping of every stream's file
/// on the shadow, one after another, before the first move. The queries
/// are read-only, of different files, and nothing changes the shadow until
/// they are all made (the loop that makes them changes only this process's
/// records of each file). Here, in a run that verifies each thing once, up
/// to [`TRACKING_HELPERS`] helpers make the queries of a round of files,
/// each under its file's tracking workspace reserved as spare memory and
/// then held to the runs it returned, and the calling thread takes them in
/// slot order and tracks each file from them as it would have from its own
/// query ([`unwritten::PrivatePlaceholder::track_current_prefix_resource_queried`]):
/// every check, the order of the files and the first failure reported are
/// what they were. A file no helper queried (its workspace refused, too few
/// helpers granted a stack) is queried by the calling thread, as before. A
/// thorough run and a recovered placement query one file at a time.
struct TrackingQueries<'p> {
    payer: Option<&'p dyn report_memory::ReportMemoryAccountant>,
    // The positions in the slot order of the round's files.
    start: usize,
    end: usize,
    // What the helpers' queries of the round returned, and the lease of
    // this list; empty where the round was not handed to helpers.
    runs: Vec<Option<QueriedRuns>>,
    _lists: Option<Box<dyn report_memory::ReportMemoryLease>>,
}
type QueriedRuns = (
    io::Result<Vec<crate::stream_layout::Run>>,
    Box<dyn report_memory::ReportMemoryLease>,
);
impl<'p> TrackingQueries<'p> {
    fn new(payer: Option<&'p dyn report_memory::ReportMemoryAccountant>) -> Self {
        Self {
            payer,
            start: 0,
            end: 0,
            runs: Vec::new(),
            _lists: None,
        }
    }

    /// Makes the queries of the round of files that begins at `position`
    /// of `slots`, where the round before has been taken.
    fn ahead(&mut self, tree: &PrivateTree, slots: &[usize], position: usize) {
        let Some(payer) = self.payer else {
            return;
        };
        if position < self.end {
            return;
        }
        self.runs = Vec::new();
        self._lists = None;
        self.start = position;
        self.end = position.saturating_add(TRACKING_ROUND).min(slots.len());
        let count = self.end - self.start;
        let wanted = std::thread::available_parallelism()
            .map_or(1, |cores| cores.get())
            .min(TRACKING_HELPERS)
            .min(count);
        let mut stacks = Vec::new();
        while wanted >= 2 && stacks.len() < wanted {
            match payer.reserve_spare(super::super::HELPER_THREAD_BYTES) {
                Ok(lease) => stacks.push(lease),
                Err(_) => break,
            }
        }
        // The round's lists: the files, the helpers' results and what waits.
        let lists = (count
            * (std::mem::size_of::<Option<&unwritten::PrivatePlaceholder>>()
                + std::mem::size_of::<std::sync::Mutex<Option<QueriedRuns>>>()
                + std::mem::size_of::<Option<QueriedRuns>>())) as u64
            + 4096;
        let lists = match stacks.len() >= 2 {
            true => payer.reserve_spare(lists).ok(),
            false => None,
        };
        if lists.is_none() {
            return;
        }
        let files: Vec<Option<&unwritten::PrivatePlaceholder>> = slots[self.start..self.end]
            .iter()
            .map(|&slot| tree.file_by_slot(slot).ok())
            .collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: Vec<std::sync::Mutex<Option<QueriedRuns>>> =
            files.iter().map(|_| std::sync::Mutex::new(None)).collect();
        let query = || {
            let _sampled = crate::stack_sampler::helper();
            loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let Some(file) = files.get(index) else {
                    break;
                };
                let Some(file) = file else {
                    continue;
                };
                let Some(Ok(bytes)) = file.tracking_query_bytes() else {
                    continue;
                };
                let Ok(mut lease) = payer.reserve_spare(bytes) else {
                    continue;
                };
                let Some(runs) = ({
                    let _timed = crate::perf::scope(crate::perf::Point::AtOnce);
                    file.tracking_runs()
                }) else {
                    continue;
                };
                // What waits for the calling thread is the runs.
                let kept = runs.as_ref().map_or(0, |runs| {
                    runs.capacity() * std::mem::size_of::<crate::stream_layout::Run>()
                }) as u64
                    + 4096;
                let _ = lease.shrink_to(kept);
                if let Ok(mut slot) = results[index].lock() {
                    *slot = Some((runs, lease));
                }
            }
        };
        std::thread::scope(|scope| {
            let helpers: Vec<_> = (0..stacks.len())
                .map_while(|_| {
                    std::thread::Builder::new()
                        .name("n2r-placement-track".into())
                        .spawn_scoped(scope, &query)
                        .ok()
                })
                .collect();
            // A helper that could not be started leaves its files to the
            // calling thread. One that panicked is not hidden: every helper
            // is waited for and the first panic is carried on here, as a
            // batch's helper's is (`ordered_observation::observe_batch`); it
            // may have left a lock of the ledger poisoned.
            let mut panicked = None;
            for helper in helpers {
                if let Err(panic) = helper.join() {
                    panicked.get_or_insert(panic);
                }
            }
            if let Some(panic) = panicked {
                std::panic::resume_unwind(panic);
            }
        });
        drop(stacks);
        self.runs = results
            .into_iter()
            .map(|slot| {
                slot.into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            })
            .collect();
        self._lists = lists;
    }

    /// What a helper's query returned for the file at `position` of the slot
    /// order, with the lease it is held under; `None` where none was made.
    fn take(&mut self, position: usize) -> Option<QueriedRuns> {
        self.runs
            .get_mut(position.checked_sub(self.start)?)
            .and_then(Option::take)
    }
}

fn run_domain_inner(
    tree: &mut PrivateTree,
    input: &impl InputDomain,
    max_move_bytes: u64,
    max_moves: usize,
    limits: PlacementLimits,
    sink: Option<&mut dyn PlacementEvidenceSink>,
    recovered: Option<&recovery::RecoveredOrigin>,
) -> io::Result<serde_json::Value> {
    tree.require_source_excluded()?;
    tree.require_bound_input_domain(input)?;
    if !limits.resource {
        validate_limits(max_move_bytes, max_moves)?;
    }
    if let Some(origin) = recovered {
        origin.require_tree(tree)?;
    } else if tree.placement_started {
        return Err(invalid(
            "tree placement already attempted; preserve without retry",
        ));
    }
    if input.len() != tree.initial_objects.len() {
        return Err(invalid("private placement object count differs"));
    }
    let payer = tree.memory.as_ref().map(|m| m.payer());
    let _index_memory = if limits.resource {
        let mut ranges = 0usize;
        let mut named = 0usize;
        let mut name_units = 0usize;
        for key in tree.stream_slots.values() {
            let owner = input.object(key.object_index)?;
            let object = owner.input();
            let item = tree.placement_view_object(&object, key)?;
            ranges = ranges
                .checked_add(item.source_runs.len())
                .and_then(|n| n.checked_add(usize::from(item.source_offset.is_some())))
                .ok_or_else(|| invalid("resource desired count overflow"))?;
            if !key.name_utf16.is_empty() {
                named += 1;
                name_units = name_units
                    .checked_add(key.name_utf16.len())
                    .ok_or_else(|| invalid("resource stream name count overflow"))?;
            }
        }
        let mut map_rows = named;
        for (key, target) in &tree.sparse_targets {
            map_rows = map_rows
                .checked_add(target.islands.len())
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| invalid("resource island count overflow"))?;
            name_units = name_units
                .checked_add(key.name_utf16.len())
                .ok_or_else(|| invalid("resource stream name count overflow"))?;
        }
        let bytes = memory::placement_index_bytes(&memory::PlacementIndex {
            streams: tree.stream_slots.len().max(tree.files.len()),
            ranges,
            map_rows,
            map_name_units: name_units,
        })?;
        Some(
            payer
                .as_deref()
                .ok_or_else(|| invalid("resource placement payer absent"))?
                .reserve(bytes)?,
        )
    } else {
        None
    };
    validate_stream_slots(tree, input)?;
    let partition = tree.pair.shadow.identity.partition_bytes;
    let mut counters = Counters {
        files: tree
            .files
            .keys()
            .map(|key| key.object_index)
            .collect::<BTreeSet<_>>()
            .len(),
        named_streams: tree
            .files
            .keys()
            .filter(|key| !key.name_utf16.is_empty())
            .count(),
        sparse_streams: tree
            .sparse_targets
            .values()
            .filter(|t| t.sparse_mode)
            .count(),
        all_hole_sparse_streams: tree
            .sparse_targets
            .values()
            .filter(|target| target.sparse_mode && target.dense_length == 0)
            .count(),
        sparse_carrier_bytes: tree
            .sparse_targets
            .values()
            .filter(|target| target.sparse_mode)
            .try_fold(0u64, |bytes, target| {
                bytes
                    .checked_add(target.dense_length)
                    .ok_or_else(|| invalid("sparse carrier byte count overflow"))
            })?,
        named_carrier_streams: tree
            .sparse_targets
            .values()
            .filter(|t| !t.sparse_mode)
            .count(),
        named_carrier_bytes: tree
            .sparse_targets
            .values()
            .filter(|t| !t.sparse_mode)
            .try_fold(0u64, |bytes, target| {
                bytes
                    .checked_add(target.dense_length)
                    .ok_or_else(|| invalid("named carrier byte count overflow"))
            })?,
        desired_runs_limit: limits.desired,
        tracked_extents_limit: limits.tracked,
        owned_intersecting_desired_limit: limits.owned,
        move_submissions_limit: max_moves,
        placement_artifact_bytes_limit: limits.evidence,
        drift_replans_limit_per_phase: MAX_DRIFT_REPLANS,
        ..Counters::default()
    };
    let reservation = if limits.resource {
        let admission = tree
            .metadata_resource_admission
            .ok_or_else(|| invalid("resource admission absent"))?;
        let query = crate::retrieval_paging::Limits::for_resource_bytes(
            usize::try_from(admission.budget.max_row_bytes).map_err(io::Error::other)?,
        )?;
        // The bounds are worked out from records of one and two pages,
        // whatever the page limit (`Reservation::with_pages`).
        let _memory = payer
            .as_deref()
            .ok_or_else(|| invalid("reservation payer absent"))?
            .reserve(MOVE_TEMPLATE_RAM)?;
        Reservation::with_resource_limits(query).map_err(|message| invalid(&message))?
    } else {
        Reservation::new().map_err(|message| invalid(&message))?
    };
    let mut desired = BTreeMap::new();
    let mut avoid = Vec::new();

    for (&index, key) in &tree.stream_slots {
        let file = tree
            .files
            .get(key)
            .ok_or_else(|| invalid("stream placement placeholder absent"))?;
        let owner = input.object(key.object_index)?;
        let object = owner.input();
        let item = tree.placement_view_object(&object, key)?;
        let path = placement_path(tree, key, &item)?;
        if item.directory
            || file.path != path
            || file.logical_length() != item.logical_length()
            || file.valid_prefix() != 0
        {
            return Err(invalid(&format!(
                "private placement input or zero-VDL state differs for slot {index}, {path}: \
                 directory={}, placeholder at {}, placeholder length {} against {}, valid prefix {}",
                item.directory,
                file.path,
                file.logical_length(),
                item.logical_length(),
                file.valid_prefix()
            )));
        }
        let runs = source_runs(&item, partition)?;
        for run in &runs {
            avoid.push((run.physical_offset.unwrap(), run.length));
        }
        desired.insert(index, runs);
        if avoid.len() > limits.desired {
            break;
        }
    }
    counters.desired_runs = avoid.len();
    if avoid.len() > limits.desired {
        return Err(refuse(
            tree,
            &counters,
            format!(
                "global source placement range budget exceeded: {} desired NTFS runs > {}",
                avoid.len(),
                limits.desired
            ),
        ));
    }
    avoid.sort_by_key(|r| r.0);
    if let Some(pair) = avoid
        .windows(2)
        .find(|w| w[0].0.checked_add(w[0].1).is_none_or(|end| end > w[1].0))
    {
        return Err(invalid(&format!(
            "source desired physical ownership overlaps: {} bytes at offset {} and {} bytes at offset {}",
            pair[0].1, pair[0].0, pair[1].1, pair[1].0
        )));
    }
    let mut evidence = Evidence::new(sink, limits.evidence);
    let mut move_bytes = 0u64;
    let mut parked = Vec::new();
    if !tree.sparse_targets.is_empty() {
        let mapping = serde_json::json!({"strategy":"sparse-carrier-coordinate-map",
            "sparse_stream_placement_offsets_are_dense_carrier_offsets":true,
            "streams":tree.sparse_targets.iter().map(|(key,target)|serde_json::json!({
                "canonical_object_index":key.object_index,"stream_name_utf16":key.name_utf16,
                "logical_length":target.logical_length,"dense_carrier_bytes":target.dense_length,
                "sparse_mode":target.sparse_mode,
                "islands":target.islands.iter().map(|island|serde_json::json!({"logical_offset":island.logical,"dense_offset":island.dense,"length":island.length})).collect::<Vec<_>>()
            })).collect::<Vec<_>>()});
        if let Err(message) = evidence.charge(&mapping) {
            return Err(refuse(tree, &counters, message));
        }
        counters.placement_artifact_bytes = evidence.saved_bytes;
        if limits.resource {
            drop(mapping);
        } else {
            parked.push(mapping);
        }
    }
    if counters.named_streams != 0 {
        let mapping = serde_json::json!({
            "strategy":"named-stream-slot-map",
            "streams":tree.stream_slots.iter().filter(|(_, key)| !key.name_utf16.is_empty())
                .map(|(slot,key)|serde_json::json!({"placement_slot":slot,
                    "canonical_object_index":key.object_index,"stream_name_utf16":key.name_utf16}))
                .collect::<Vec<_>>()
        });
        if let Err(message) = evidence.charge(&mapping) {
            return Err(refuse(tree, &counters, message));
        }
        counters.placement_artifact_bytes = evidence.saved_bytes;
        if limits.resource {
            drop(mapping);
        } else {
            parked.push(mapping);
        }
    }
    tree.placement_started = true;
    progress(tree, "track-zero-vdl", 0, &evidence, None, &counters);
    let indexes: Vec<_> = tree.stream_slots.keys().copied().collect();
    // Bind existing allocated ownership of every file before any native move.
    // Tracking only reads a placeholder's own live retrieval map, a move never
    // changes another placeholder's mapping, and a file's complete tracked
    // mapping is verified before its first move and again when placement
    // ends (and after every move unless the run verifies each thing once).
    // No user bytes are initialized.
    let mut hole_memory = if limits.resource {
        Some(StepMemory::new(
            payer
                .as_deref()
                .ok_or_else(|| invalid("hole payer absent"))?,
            StepMemory::HOLE,
        ))
    } else {
        None
    };
    let mut holes = Vec::new();
    let mut queried = TrackingQueries::new(payer.as_deref().filter(|_| {
        limits.resource && recovered.is_none() && crate::verify_policy::verifies_once()
    }));
    for (position, index) in indexes.iter().enumerate() {
        queried.ahead(tree, &indexes, position);
        let file = tree.file_by_slot_mut(*index)?;
        if limits.resource {
            let file_holes = if recovered.is_some() {
                file.recovered_holes_resource()?
            } else if let Some((runs, _lease)) = queried.take(position) {
                file.track_current_prefix_resource_queried(runs)?
            } else {
                file.track_current_prefix_resource()?
            };
            counters.initial_tracked_extents = counters
                .initial_tracked_extents
                .checked_add(file.tracked_mappings().len())
                .ok_or_else(|| invalid("tracked extent count overflow"))?;
            counters.deferred_holes = counters
                .deferred_holes
                .checked_add(file_holes.len())
                .ok_or_else(|| invalid("deferred hole count overflow"))?;
            for (vcn, clusters) in file_holes.iter().copied() {
                if holes.len() == limits.tracked {
                    return Err(invalid("resource deferred hole index exhausted"));
                }
                if let Some(memory) = hole_memory.as_mut() {
                    memory.admit(holes.len() + 1, limits.tracked)?;
                }
                let (start, end) = cluster_span(vcn, clusters)?;
                holes.push((*index, start, end));
            }
        } else {
            let file_holes = file.track_current_prefix()?;
            counters.initial_tracked_extents += file.tracked_mappings().len();
            counters.deferred_holes += file_holes.len();
            for (vcn, clusters) in file_holes {
                let (start, end) = cluster_span(vcn, clusters)?;
                holes.push((*index, start, end));
            }
        }
    }
    let wanted = Wanted {
        desired: &desired,
        avoid: &avoid,
        partition,
        max_moves,
        limits,
        payer: payer.as_deref(),
    };
    // Preserve the frozen legacy/alpha order. Resource construction can
    // evacuate the already tracked initial blockers before allocating holes,
    // avoiding scratch allocation followed by a second final move.
    let deferred_after_evacuation = tree.metadata_resource_admission.is_some();
    if !deferred_after_evacuation {
        allocate_deferred(
            tree,
            wanted,
            &holes,
            max_move_bytes,
            &reservation,
            &mut evidence,
            &mut counters,
            &mut move_bytes,
            None,
        )?;
    }
    'evacuation: loop {
        let _owned_memory = if limits.resource {
            let tracked = tree.files.values().try_fold(0usize, |n, file| {
                n.checked_add(file.tracked_mappings().len())
                    .ok_or_else(|| invalid("tracked count overflow"))
            })?;
            if tracked > limits.tracked {
                return Err(invalid("resource tracked extent index exhausted"));
            }
            Some(
                payer
                    .as_deref()
                    .ok_or_else(|| invalid("ownership payer absent"))?
                    .reserve(memory::placement_ownership_bytes(tracked, avoid.len())?)?,
            )
        } else {
            None
        };
        let mut owned = Vec::new();
        let mut eligible = Vec::new();
        for index in &indexes {
            let file = tree.file_by_slot(*index)?;
            if counters.evacuation_drift_replans != 0
                || !(deferred_after_evacuation && crate::verify_policy::verifies_once())
            {
                file.check_placements()?;
            }
            for &(v, l, n) in file.tracked_mappings() {
                owned.push(shadow_evacuation::Extent {
                    file_index: u32::try_from(*index)
                        .map_err(|_| invalid("placement slot exceeds planner identity"))?,
                    logical_offset: cluster_span(v, n)?.0,
                    physical_offset: cluster_span(l, n)?.0,
                    length: u64::from(n) * cluster(),
                });
            }
            for run in &desired[index] {
                let remaining;
                let runs = if recovered.is_some() {
                    remaining = unfinished_runs(file, run, limits.tracked)?;
                    remaining.as_slice()
                } else {
                    std::slice::from_ref(run)
                };
                for run in runs {
                    eligible.push(shadow_evacuation::Extent {
                        file_index: u32::try_from(*index)
                            .map_err(|_| invalid("placement slot exceeds planner identity"))?,
                        logical_offset: run.logical_offset,
                        physical_offset: run.physical_offset.unwrap(),
                        length: run.length,
                    });
                }
            }
        }
        // Only initial ReFS runs can block a desired range: direct pieces sit at
        // their own coordinates and scratch avoids every desired range. The cap
        // therefore bounds the intersecting set, not one entry per file; the
        // planner still validates every tracked mapping against both views.
        counters.tracked_extents = owned.len();
        counters.eligible_runs = eligible.len();
        counters.owned_intersecting_desired = owned
            .iter()
            .filter(|e| intersects_desired(&avoid, e.physical_offset, e.length))
            .count();
        if owned.len() > limits.tracked {
            return Err(refuse(
                tree,
                &counters,
                format!(
                    "global tracked shadow mapping budget exceeded: {} tracked mappings > {}",
                    owned.len(),
                    limits.tracked
                ),
            ));
        }
        if counters.owned_intersecting_desired > limits.owned {
            return Err(refuse(
                tree,
                &counters,
                format!(
                    "global tracked ownership range budget exceeded: {} tracked mappings intersect desired runs > {}",
                    counters.owned_intersecting_desired, limits.owned
                ),
            ));
        }
        let (legacy, metadata) = views(tree, limits)?;
        counters.phase_bitmap_snapshots += 1;
        progress(
            tree,
            "plan-evacuation",
            move_bytes,
            &evidence,
            None,
            &counters,
        );
        let Some(remaining) = max_moves.checked_sub(evidence.len()).filter(|v| *v > 0) else {
            return Err(refuse(
                tree,
                &counters,
                format!(
                    "no evacuation move budget: {} of {max_moves} submissions used",
                    evidence.len()
                ),
            ));
        };
        let evacuation = resource::evacuation(
            &legacy,
            &metadata,
            &eligible,
            &owned,
            partition,
            remaining,
            limits,
            payer.as_deref(),
        )?;
        let required: usize = evacuation
            .moves
            .iter()
            .map(|m| m.length.div_ceil(MOVE_BYTES) as usize)
            .sum();
        counters.evacuation_planned_moves = evacuation.moves.len();
        counters.evacuation_planned_submissions = required;
        counters.evacuation_remaining_blocked_bytes = evacuation.remaining_blocked_bytes;
        if required >= remaining {
            return Err(refuse(
                tree,
                &counters,
                format!(
                    "evacuation leaves no final-placement budget: {required} evacuation submissions of {remaining} remaining"
                ),
            ));
        }
        for movement in &evacuation.moves {
            if movement.destination_offset < MARGIN
                || movement
                    .destination_offset
                    .checked_add(movement.length)
                    .is_none_or(|v| v > partition.saturating_sub(MARGIN))
            {
                return Err(invalid(
                    "evacuation destination enters bootstrap safety margin",
                ));
            }
        }
        // The plan record is complete before any evacuation move, so its saved
        // size is charged before native IO in this phase.
        let plan_json_memory = if limits.resource {
            let rows = owned
                .len()
                .checked_add(evacuation.moves.len())
                .ok_or_else(|| invalid("evacuation JSON count overflow"))?;
            Some(
                payer
                    .as_deref()
                    .ok_or_else(|| invalid("evacuation JSON payer absent"))?
                    .reserve(memory::placement_plan_record_bytes(rows)?)?,
            )
        } else {
            None
        };
        let plan_record = serde_json::json!({"strategy":"selective-user-blockers","initial_owned_ranges":owned,
        "evacuation_plan":&*evacuation});
        let charged = evidence.charge(&plan_record);
        counters.placement_artifact_bytes = evidence.saved_bytes;
        if let Err(message) = charged {
            return Err(refuse(tree, &counters, message));
        }
        if limits.resource {
            drop(plan_record);
        } else {
            parked.push(plan_record);
        }
        drop(plan_json_memory);
        for (moved, movement) in evacuation.moves.iter().enumerate() {
            let mut offset = 0;
            while offset < movement.length {
                let length = (movement.length - offset).min(MOVE_BYTES);
                progress(
                    tree,
                    "evacuate-blocker",
                    move_bytes,
                    &evidence,
                    Some(serde_json::json!({
                "object_index":movement.file_index,"logical_offset":movement.logical_offset+offset,
                "destination":movement.destination_offset+offset,"length":length,
                "placement_result_recorded":false,"budget_charged":false})),
                    &counters,
                );
                let current_extents = tree
                    .file_by_slot(movement.file_index as usize)?
                    .retrieval_extents();
                charge_move(&mut move_bytes, length, max_move_bytes)?;
                tree.placement_progress["charged_move_bytes"] = move_bytes.into();
                tree.placement_progress["pending"]["budget_charged"] = true.into();
                let attempt = resource::move_slot(
                    tree,
                    movement.file_index as usize,
                    (movement.logical_offset + offset) / cluster(),
                    (movement.destination_offset + offset) / cluster(),
                    move_clusters(length)?,
                    true,
                    limits.resource,
                    |destination| {
                        reserve_move(
                            &mut counters,
                            &mut evidence,
                            &reservation,
                            current_extents,
                            length,
                            destination,
                        )
                    },
                );
                tree.placement_progress["counters"]["move_evidence_reservation_bytes"] =
                    counters.move_evidence_reservation_bytes.into();
                let proof = match attempt {
                    Err(error)
                        if unwritten::OccupiedDestination::from_error(&error)
                            .is_some_and(|drift| drift.before_submission()) =>
                    {
                        uncharge_move(tree, &mut move_bytes, length);
                        if counters.evacuation_drift_replans == MAX_DRIFT_REPLANS {
                            return Err(refuse(
                                tree,
                                &counters,
                                format!(
                                    "evacuate blocker for slot {} after {MAX_DRIFT_REPLANS} fresh plans: {error}",
                                    movement.file_index
                                ),
                            ));
                        }
                        // Previous moves remain charged and recorded. Rebuild ownership from
                        // their verified mappings and choose destinations from both fresh views.
                        counters.evacuation_drift_replans += 1;
                        continue 'evacuation;
                    }
                    result => result?,
                };
                if proof["native_error"] != serde_json::Value::Null
                    || proof["all_placements_match"] != true
                {
                    let refusal = format!(
                        "selective unwritten evacuation refused for slot {}: {length} bytes at logical offset {} \
                     to physical offset {}, native error {}, placements match {}; preserve without retry",
                        movement.file_index,
                        movement.logical_offset + offset,
                        movement.destination_offset + offset,
                        proof["native_error"],
                        proof["all_placements_match"]
                    );
                    tree.placement_progress["failed_native_move"] = evidence
                    .failed_move(serde_json::json!({
                        "object_index":movement.file_index,"phase":"evacuate-blocker","proof":proof
                    }))
                    .map_err(|e| invalid(&e))?;
                    return Err(invalid(&refusal));
                }
                counters.evacuation_submissions += 1;
                count_proof_form(&mut counters, &proof);
                let recorded = evidence.push_move_proof(
                    u64::from(movement.file_index),
                    "evacuate-blocker",
                    &proof,
                );
                counters.move_evidence_bytes = evidence.compact_bytes;
                counters.placement_artifact_bytes = evidence.saved_bytes;
                if let Err(message) = recorded {
                    return Err(refuse(tree, &counters, message));
                }
                // Where another piece follows, the next thing done is to record
                // it as pending: this record would be replaced unread.
                let last = offset + length >= movement.length
                    && evacuation.moves[moved + 1..]
                        .iter()
                        .all(|later| later.length == 0);
                if last {
                    progress(
                        tree,
                        "evacuate-blocker",
                        move_bytes,
                        &evidence,
                        None,
                        &counters,
                    );
                }
                offset += length;
            }
        }
        break;
    }
    // One snapshot after evacuation plans every desired run. Final moves land
    // only in their own disjoint desired runs, so no earlier move in this
    // phase allocates inside a later run; each move rechecks both live views.
    // If ReFS allocates a planned destination after the snapshot, the mover
    // refuses before submission and this run and every later one are planned
    // from one fresh snapshot, a bounded number of times. Pieces already
    // placed are allocated in it and so are not planned again.
    let (mut legacy, mut metadata) = views(tree, limits)?;
    counters.phase_bitmap_snapshots += 1;
    if counters.evacuation_submissions > 0 {
        counters.post_evacuation_barrier = Some(serde_json::json!({
            "schema_version":1,"kind":"post-evacuation-volume-flush",
            "status":"observing-before","flush_succeeded":false,
            "source_exclusion_checked_before":false,"source_exclusion_checked_after":false,
            "diagnostic_only":true,"predicted_free_bits_used":false,
            "source_writes_authorized":false
        }));
        progress(
            tree,
            "post-evacuation-barrier",
            move_bytes,
            &evidence,
            None,
            &counters,
        );
        let observed = (|| -> io::Result<(resource::Bitmap, resource::Bitmap)> {
            let trace = counters.post_evacuation_barrier.as_mut().unwrap();
            trace["before"] = barrier_snapshot(
                &legacy,
                &metadata,
                &desired,
                partition,
                limits,
                payer.as_deref(),
            )?;
            trace["status"] = "checking-source-exclusion".into();
            tree.require_source_excluded()?;
            trace["source_exclusion_checked_before"] = true.into();
            trace["status"] = "flushing-owned-shadow-volume".into();
            let started = std::time::Instant::now();
            let flushed = crate::perf::flush(crate::perf::Point::VolumeFlush, &tree.volume);
            trace["flush_elapsed_microseconds"] = u64::try_from(started.elapsed().as_micros())
                .map_err(|_| invalid("barrier flush timing overflow"))?
                .into();
            trace["flush_succeeded"] = flushed.is_ok().into();
            if let Err(error) = flushed {
                trace["flush_native_error"] = serde_json::json!(error.raw_os_error());
                return Err(error);
            }
            trace["status"] = "rechecking-source-exclusion".into();
            tree.require_source_excluded()?;
            trace["source_exclusion_checked_after"] = true.into();
            trace["status"] = "observing-after".into();
            let (after_legacy, after_metadata) = views(tree, limits)?;
            counters.phase_bitmap_snapshots += 1;
            trace["after"] = barrier_snapshot(
                &after_legacy,
                &after_metadata,
                &desired,
                partition,
                limits,
                payer.as_deref(),
            )?;
            trace["status"] = "complete".into();
            // The existing evidence budget reserves 64 KiB for framing and
            // scalars. This trace cannot consume unbounded move-proof space.
            if serde_json::to_vec_pretty(trace)
                .map_err(io::Error::other)?
                .len()
                > 4096
            {
                return Err(invalid("post-evacuation scalar trace exceeds reserve"));
            }
            Ok((after_legacy, after_metadata))
        })();
        match observed {
            Ok(after) => (legacy, metadata) = after,
            Err(error) => {
                if let Some(trace) = &mut counters.post_evacuation_barrier {
                    trace["error"] = error.to_string().into();
                }
                progress(
                    tree,
                    "post-evacuation-barrier",
                    move_bytes,
                    &evidence,
                    None,
                    &counters,
                );
                return Err(refuse(
                    tree,
                    &counters,
                    format!(
                        "post-evacuation barrier failed before source writes: {error}; preserve shadow without retry"
                    ),
                ));
            }
        }
        progress(
            tree,
            "post-evacuation-barrier",
            move_bytes,
            &evidence,
            None,
            &counters,
        );
    }
    if deferred_after_evacuation && !holes.is_empty() {
        // Initial blocker relocation leaves deferred VCN holes unchanged.
        // The freshly observed, post-flush views alone decide whether each
        // hole can now land directly at its own source coordinates. Scratch
        // continues to exclude every desired run and both bootstrap margins.
        allocate_deferred(
            tree,
            wanted,
            &holes,
            max_move_bytes,
            &reservation,
            &mut evidence,
            &mut counters,
            &mut move_bytes,
            Some((legacy, metadata)),
        )?;
        // Direct deferred allocations are now occupied and must not be planned
        // again. Never infer these bitmap bits from submitted move receipts.
        (legacy, metadata) = views(tree, limits)?;
        counters.phase_bitmap_snapshots += 1;
    }
    // Only actual post-flush/post-deferred views can make a destination eligible.
    let mut planner = resource::planner(&legacy, &metadata, partition, limits, payer.as_deref())?;
    for &index in &indexes {
        for run in &desired[&index] {
            // Current ownership, never old FSCTL records, identifies pieces
            // already at the exact desired logical/physical coordinates.
            let remaining;
            let runs = if recovered.is_some() {
                remaining = unfinished_runs(tree.file_by_slot(index)?, run, limits.tracked)?;
                remaining.as_slice()
            } else {
                std::slice::from_ref(run)
            };
            for run in runs {
                loop {
                    let Some(remaining) = max_moves.checked_sub(evidence.len()).filter(|v| *v > 0)
                    else {
                        return Err(refuse(
                            tree,
                            &counters,
                            format!(
                                "tree placement move budget exhausted: {} of {max_moves} submissions used",
                                evidence.len()
                            ),
                        ));
                    };
                    let plan = planner.plan(
                        retention_layout::SourceRun {
                            logical_offset: run.logical_offset,
                            physical_offset: run.physical_offset.unwrap(),
                            length: run.length,
                        },
                        remaining.min(limits.subruns),
                    )?;
                    let required: usize = plan
                        .subruns
                        .iter()
                        .map(|r| r.length.div_ceil(MOVE_BYTES) as usize)
                        .sum();
                    if required > remaining {
                        return Err(refuse(
                            tree,
                            &counters,
                            format!(
                                "final-placement split budget exceeded: {required} submissions needed, {remaining} of {max_moves} remaining"
                            ),
                        ));
                    }
                    let mut drifted = None;
                    'pieces: for subrun in plan.subruns.iter().copied() {
                        let mut offset = 0;
                        while offset < subrun.length {
                            let length = (subrun.length - offset).min(MOVE_BYTES);
                            let logical = subrun.logical_offset + offset;
                            let physical = subrun.physical_offset + offset;
                            progress(
                                tree,
                                "original-coordinate",
                                move_bytes,
                                &evidence,
                                Some(serde_json::json!({
                            "object_index":index,"logical_offset":logical,"destination":physical,"length":length,
                            "placement_result_recorded":false,"budget_charged":false})),
                                &counters,
                            );
                            let current_extents = tree.file_by_slot(index)?.retrieval_extents();
                            charge_move(&mut move_bytes, length, max_move_bytes)?;
                            tree.placement_progress["charged_move_bytes"] = move_bytes.into();
                            tree.placement_progress["pending"]["budget_charged"] = true.into();
                            let attempt = resource::move_slot(
                                tree,
                                index,
                                logical / cluster(),
                                physical / cluster(),
                                move_clusters(length)?,
                                true,
                                limits.resource,
                                |destination| {
                                    reserve_move(
                                        &mut counters,
                                        &mut evidence,
                                        &reservation,
                                        current_extents,
                                        length,
                                        destination,
                                    )
                                },
                            );
                            tree.placement_progress["counters"]["move_evidence_reservation_bytes"] =
                                counters.move_evidence_reservation_bytes.into();
                            let proof = match attempt {
                                Err(error) if destination_drifted(&error) => {
                                    uncharge_move(tree, &mut move_bytes, length);
                                    drifted = Some(error);
                                    break 'pieces;
                                }
                                result => result?,
                            };
                            settle_progress(tree);
                            if proof["native_error"] != serde_json::Value::Null
                                || proof["all_placements_match"] != true
                            {
                                let message = format!(
                                    "original-coordinate reposition refused (native_error={}, mapping_matches={}, all_placements_match={}); preserve without retry",
                                    proof["native_error"],
                                    proof["mapping_matches"],
                                    proof["all_placements_match"]
                                );
                                tree.placement_progress["failed_native_move"] = evidence
                                .failed_move(serde_json::json!({
                                    "object_index":index,"phase":"original-coordinate","proof":proof
                                }))
                                .map_err(|e| invalid(&e))?;
                                return Err(invalid(&message));
                            }
                            counters.final_submissions += 1;
                            count_proof_form(&mut counters, &proof);
                            let recorded = evidence.push_move_proof(
                                index as u64,
                                "original-coordinate",
                                &proof,
                            );
                            counters.move_evidence_bytes = evidence.compact_bytes;
                            counters.placement_artifact_bytes = evidence.saved_bytes;
                            if let Err(message) = recorded {
                                return Err(refuse(tree, &counters, message));
                            }
                            offset += length;
                        }
                    }
                    let Some(error) = drifted else {
                        break;
                    };
                    if counters.final_drift_replans == MAX_DRIFT_REPLANS {
                        return Err(refuse(
                            tree,
                            &counters,
                            format!(
                                "original-coordinate destination allocated after {MAX_DRIFT_REPLANS} \
                             fresh-snapshot re-plans: {error}; preserve shadow without retry"
                            ),
                        ));
                    }
                    counters.final_drift_replans += 1;
                    drop(planner);
                    (legacy, metadata) = views(tree, limits)?;
                    planner =
                        resource::planner(&legacy, &metadata, partition, limits, payer.as_deref())?;
                    counters.phase_bitmap_snapshots += 1;
                }
            }
        }
    }
    // Derive every final original-coordinate reference from live tracked
    // mappings, including data already correctly placed before this operation.
    // Planned destinations and bitmap bits alone never count as ownership.
    // Do not build tentative coordinate rows per submitted move: they were
    // discarded here. The complete final live mappings below are the sole
    // source of these unchanged evidence rows, including already-placed data.
    let mut coordinates_memory = if limits.resource {
        // A piece is where a tracked mapping and a run wanted meet: a file
        // has no more of them than it has mappings and runs together.
        let mut pieces = avoid.len();
        let mut name_units = 0usize;
        for &index in &indexes {
            pieces = pieces
                .checked_add(tree.file_by_slot(index)?.tracked_mappings().len())
                .ok_or_else(|| invalid("coordinate piece count overflow"))?;
            name_units = name_units
                .checked_add(
                    tree.stream_slots
                        .get(&index)
                        .map_or(0, |key| key.name_utf16.len()),
                )
                .ok_or_else(|| invalid("coordinate name count overflow"))?;
        }
        Some(
            payer
                .as_deref()
                .ok_or_else(|| invalid("coordinate payer absent"))?
                .reserve(memory::placement_coordinates_bytes(
                    indexes.len(),
                    name_units,
                    pieces,
                )?)?,
        )
    } else {
        None
    };
    let mut retained = Vec::new();
    let mut original_coordinates: BTreeMap<usize, Vec<(u64, u64, u64)>> = BTreeMap::new();
    let mut retained_bytes = 0u64;
    // Every stream's complete mapping, read now and compared with every
    // piece tracked for it. For a run that verifies each thing once this
    // is the one comparison of the pieces a stream's moves did not
    // themselves move: `indexes` is every stream slot of the tree, and
    // no move follows this loop. Run read-only retrieval queries in parallel
    // across worker threads and report the first error in slot order.
    let files: Vec<(usize, &crate::shadow_native::unwritten::PrivatePlaceholder)> = indexes
        .iter()
        .map(|&index| tree.file_by_slot(index).map(|file| (index, file)))
        .collect::<io::Result<_>>()?;
    let workers = if crate::verify_policy::verifies_once() && files.len() >= 32 {
        std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(8)
    } else {
        1
    };
    if workers > 1 {
        let chunk_size = files.len().div_ceil(workers);
        let first_error: Option<io::Error> = std::thread::scope(|scope| {
            let handles: Vec<_> = files
                .chunks(chunk_size)
                .map(|chunk| {
                    scope.spawn(move || {
                        for &(index, file) in chunk {
                            if let Err(error) = file.check_placements() {
                                return Some(io::Error::new(
                                    error.kind(),
                                    format!(
                                        "extent placement, final comparison of the complete mapping: stream slot \
                                         {index}, {} ({} tracked pieces): {error}",
                                        file.path,
                                        file.tracked_mappings().len()
                                    ),
                                ));
                            }
                        }
                        None
                    })
                })
                .collect();
            let mut first = None;
            for handle in handles {
                if let Ok(Some(err)) = handle.join()
                    && first.is_none()
                {
                    first = Some(err);
                }
            }
            first
        });
        if let Some(err) = first_error {
            return Err(err);
        }
    }
    for (index, file) in files {
        if workers <= 1 {
            file.check_placements().map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "extent placement, final comparison of the complete mapping: stream slot \
                         {index}, {} ({} tracked pieces): {error}",
                        file.path,
                        file.tracked_mappings().len()
                    ),
                )
            })?;
        }
        let tracked = file.tracked_mappings();
        // The owning file records native tracking in VCN order and sorts and
        // coalesces each successful move. Check the entire in-memory ordering
        // once before using a monotonic intersection cursor. This does not
        // replace or narrow the complete live retrieval check above.
        let mut previous_end = 0;
        for &(v, _, n) in tracked {
            let end = v
                .checked_add(u64::from(n))
                .ok_or_else(|| invalid("tracked placement logical end overflow"))?;
            if n == 0 || v < previous_end {
                return Err(invalid("tracked placement logical order differs"));
            }
            previous_end = end;
        }
        let mut first_tracked = 0;
        for source in &desired[&index] {
            let wanted_vcn = source.logical_offset / cluster();
            let wanted_lcn = source.physical_offset.unwrap() / cluster();
            let wanted_end = wanted_vcn + source.length / cluster();
            while tracked
                .get(first_tracked)
                .is_some_and(|&(v, _, n)| v + u64::from(n) <= wanted_vcn)
            {
                first_tracked += 1;
            }
            for &(v, l, n) in &tracked[first_tracked..] {
                if v >= wanted_end {
                    break;
                }
                let start = v.max(wanted_vcn);
                let end = (v + u64::from(n)).min(wanted_end);
                if start >= end || l + start - v != wanted_lcn + start - wanted_vcn {
                    continue;
                }
                let logical = start * cluster();
                let physical = (l + start - v) * cluster();
                let length = (end - start) * cluster();
                original_coordinates
                    .entry(index)
                    .or_default()
                    .push((logical, physical, length));
                let row = serde_json::json!({"object_index":index,"logical_offset":logical,
                    "source_physical_offset":physical,"target_physical_offset":physical,"length":length,
                    "source_contents_verified":false});
                if limits.resource {
                    evidence.charge(&row).map_err(|e| invalid(&e))?;
                } else {
                    retained.push(row);
                }
                retained_bytes = retained_bytes
                    .checked_add(length)
                    .ok_or_else(|| invalid("final original-coordinate byte overflow"))?;
            }
        }
    }
    for row in &retained {
        let charged = evidence.charge(row);
        counters.placement_artifact_bytes = evidence.saved_bytes;
        if let Err(message) = charged {
            return Err(refuse(tree, &counters, message));
        }
    }
    tree.require_source_excluded()?;
    let mut retained_streams = BTreeMap::new();
    for (slot, ranges) in original_coordinates {
        let key = tree
            .stream_slots
            .get(&slot)
            .cloned()
            .ok_or_else(|| invalid("retained stream slot missing"))?;
        if retained_streams.insert(key, ranges).is_some() {
            return Err(invalid("retained streams collide after slot translation"));
        }
    }
    if limits.resource {
        let actual = tree
            .memory
            .as_ref()
            .ok_or_else(|| invalid("resource placement payer absent"))?;
        let retained = memory::coordinate_map_bytes(&retained_streams)?;
        // All local planner indexes/JSON are gone before their guard is
        // narrowed to the state which remains inside the live PrivateTree.
        drop(planner);
        drop(legacy);
        drop(metadata);
        drop(desired);
        drop(avoid);
        drop(holes);
        drop(indexes);
        let receipt = evidence
            .sink
            .as_mut()
            .ok_or_else(|| invalid("actual paged evidence sink absent"))?
            .finish()?;
        let result = serde_json::json!({"schema_version":3,"kind":"private-unwritten-tree-placement-pages",
            "occupancy_evidence_scope":"destination-window-v1",
            "per_move_retrieval_scope":per_move_retrieval_scope(true),
            "phase_bitmap_scope":"full-volume","paged_evidence":receipt,"move_count":evidence.len(),
            "original_coordinate_bytes":retained_bytes,"move_evidence_bytes":evidence.compact_bytes,
            "placement_artifact_bytes":evidence.saved_bytes,"max_placement_artifact_bytes":limits.evidence,
            "counters":counters,"move_bytes_submitted":move_bytes,"max_move_bytes":max_move_bytes,
            "max_move_submissions":max_moves,"payload_contents_verified":false,"source_payload_writes":0,
            "conversion_qualified":false});
        actual.retain_from(&mut coordinates_memory, retained)?;
        tree.original_coordinates = retained_streams;
        progress(tree, "complete", move_bytes, &evidence, None, &counters);
        return Ok(result);
    }
    tree.original_coordinates = retained_streams;
    tree.placement_complete = true;
    progress(tree, "complete", move_bytes, &evidence, None, &counters);
    tree.placement_progress["placement_complete"] = true.into();
    let mut result = serde_json::json!({"schema_version":2,"kind":"private-unwritten-tree-placement",
        "occupancy_evidence_scope":"destination-window-v1","per_move_retrieval_scope":"complete-file-mapping",
        "phase_bitmap_scope":"full-volume","parked":parked,"moves":evidence.moves,
        "original_coordinate_ranges":retained,"original_coordinate_bytes":retained_bytes,
        "move_evidence_bytes":evidence.compact_bytes,
        "placement_artifact_bytes":evidence.saved_bytes,
        "max_placement_artifact_bytes":MAX_PLACEMENT_ARTIFACT_BYTES,"counters":counters,
        "move_bytes_submitted":move_bytes,"max_move_bytes":max_move_bytes,"max_move_submissions":max_moves,
        "payload_contents_verified":false,"source_payload_writes":0,"conversion_qualified":false});
    if let Some(barrier) = counters.post_evacuation_barrier {
        result["post_evacuation_barrier"] = barrier;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_recovered_targets_mapping_workspace_holds_every_extent_it_can_have() {
        use super::recovered_retrieval_bytes;
        use crate::retrieval_paging::Limits;
        const MIB: usize = 1024 * 1024;
        // A machine with 16 GB free limits a row to 141 MiB.
        let row = 141 * MIB;
        let cluster = super::cluster();
        // A target of one cluster: under a megabyte where it was the row,
        // and with the four fixed MiB under six where it was 1.1 GB.
        let small = recovered_retrieval_bytes(row, cluster, cluster);
        assert!(small < MIB / 2, "{small}");
        assert!(8 * small + 4 * MIB < 6 * MIB);
        for (rounded, allocated) in [
            (0, 0),
            (cluster, cluster),
            (0, 64 * cluster),
            (1 << 20, 1 << 20),
            (1 << 30, 1 << 28),
            (1 << 28, 1 << 30),
            (1 << 31, 1 << 31),
        ] {
            let workspace = recovered_retrieval_bytes(row, rounded, allocated);
            assert!(workspace < row, "{rounded} {allocated}");
            // The most extents the target can be in, and the responses that
            // many take.
            let extents = usize::try_from(allocated.div_ceil(cluster) * 2 + 1).unwrap();
            let pages = extents.div_ceil(crate::stream_layout::MAX_EXTENTS) + 1;
            // What a row of the workspace's size is held to by the queries'
            // own limits has room for all of them.
            let holds = Limits::for_resource_bytes(workspace).unwrap();
            assert!(holds.max_extents >= extents, "{rounded} {allocated}");
            assert!(holds.max_returned_bytes >= 16 * extents + 16 * pages);
            assert!(holds.max_pages >= pages, "{rounded} {allocated}");
        }
        // A target that could fill the row is held to it, as before.
        assert_eq!(recovered_retrieval_bytes(row, 1 << 40, 1 << 40), row);
        assert_eq!(recovered_retrieval_bytes(row, u64::MAX, u64::MAX), row);
        assert_eq!(recovered_retrieval_bytes(65536, 1 << 30, 1 << 30), 65536);
    }

    #[test]
    fn deferred_steps_are_paid_for_as_the_plan_grows_and_not_by_what_it_may_hold() {
        use crate::shadow_native::report_memory::test_payer::Counted;
        let payer = Counted::with_limit(u64::MAX);
        let mut memory = StepMemory::new(&payer, StepMemory::STEP);
        // A run with 1.7 GiB may index 435,000 steps.
        let limit = 435_000;
        memory.admit(1, limit).unwrap();
        assert_eq!(memory.paid, 1024);
        assert_eq!(payer.held(), 1024 * StepMemory::STEP + 65536);
        memory.admit(1024, limit).unwrap();
        assert_eq!(memory.paid, 1024);
        // Doubling: a plan of 100,000 steps has paid for 131,072.
        for steps in 1..=100_000 {
            memory.admit(steps, limit).unwrap();
        }
        assert_eq!(memory.paid, 131_072);
        assert!(payer.held() < 131_072 * StepMemory::STEP + 9 * 65536);
        // Never for more than the indexes hold.
        memory.admit(limit, limit).unwrap();
        assert_eq!(memory.paid, limit);
        // A plan that replaces this one is within what was paid.
        let held = payer.held();
        memory.admit(90_000, limit).unwrap();
        assert_eq!(payer.held(), held);
        // What a step takes is refused where there is no room for it.
        let small = Counted::with_limit(1024 * StepMemory::STEP + 65536);
        let mut memory = StepMemory::new(&small, StepMemory::STEP);
        memory.admit(1024, limit).unwrap();
        assert!(memory.admit(1025, limit).is_err());
        drop(memory);
        assert_eq!(small.held(), 0);
    }

    use super::*;

    /// What building the widest record of `extents` extents and `pages`
    /// pages and measuring it holds at once: the typed pages (a `Vec` of
    /// `PageProof`, each with its input and digest on the heap), the JSON
    /// value, and its pretty text in a `Vec` that doubles.
    fn record_footprint(extents: usize, pages: usize) -> u64 {
        let record = widest_move_record(extents, pages).unwrap();
        let text = serde_json::to_vec_pretty(&record).unwrap().len() as u64;
        let typed = pages as u64
            * (std::mem::size_of::<crate::retrieval_paging::PageProof>() as u64 + 8 + 64);
        memory::value_bytes(&record).unwrap() + 2 * text + typed
    }

    #[test]
    fn the_move_bounds_are_those_of_the_record_built_whole() {
        // The bounds as they were worked out before: the record built at
        // its full page count and measured.
        let built = |pages: usize| {
            let base = saved_size(&widest_move_record(0, pages).unwrap()).unwrap();
            let per_extent = saved_size(&widest_move_record(1, pages).unwrap()).unwrap() - base;
            (base, per_extent)
        };
        for pages in [0, 1, 2, 3, 4, 17, 128, 1000, 4099] {
            let reservation = Reservation::with_pages(pages).unwrap();
            assert_eq!(
                (reservation.base, reservation.per_extent),
                built(pages),
                "{pages} pages"
            );
        }
        // And for a record of several extents, as `bound` charges it.
        let reservation = Reservation::with_pages(300).unwrap();
        assert_eq!(
            reservation.base + 5 * reservation.per_extent,
            saved_size(&widest_move_record(5, 300).unwrap()).unwrap()
        );
    }

    #[test]
    fn the_move_template_fits_what_is_reserved_for_it() {
        // Working the bounds out holds one record of two pages and one
        // extent at a time.
        let held = record_footprint(1, 2);
        assert!(held < MOVE_TEMPLATE_RAM / 16, "{held}");
        // What a page of a record built whole took, which was prepaid at
        // 8,192 bytes a page for every page the budget's row admits.
        let page = record_footprint(0, 1001) - record_footprint(0, 1000);
        assert!((1024..8192).contains(&page), "{page} bytes a page");
    }

    #[test]
    fn moves_and_spans_are_counted_in_target_clusters() {
        assert_eq!(move_clusters(8192).unwrap(), 2);
        assert_eq!(cluster_span(2, 3).unwrap(), (8192, 20_480));
        crate::target_cluster::with(65536, || {
            assert!(move_clusters(8192).is_err());
            assert_eq!(move_clusters(131_072).unwrap(), 2);
            assert_eq!(cluster_span(2, 3).unwrap(), (131_072, 327_680));
        });
    }
}

#[cfg(test)]
mod move_record_tests {
    use super::*;
    use crate::shadow_native::unwritten::proof_samples::placement;

    /// What a sink is given: each record as the compact JSON it stores.
    #[derive(Default)]
    struct Recorded(Vec<(&'static str, Vec<u8>)>);
    impl PlacementEvidenceSink for Recorded {
        fn maximum_bytes(&self) -> u64 {
            u64::MAX
        }
        fn reserve_next(&mut self, _: u64) -> io::Result<()> {
            Ok(())
        }
        fn push(&mut self, kind: &'static str, value: &serde_json::Value) -> io::Result<()> {
            self.0.push((kind, serde_json::to_vec(value)?));
            Ok(())
        }
        fn push_compact(&mut self, kind: &'static str, json: &[u8]) -> io::Result<()> {
            self.0.push((kind, json.to_vec()));
            Ok(())
        }
        fn finish(&mut self) -> io::Result<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
    }

    fn resource(extents: usize, native_error: Option<i32>) -> resource::MoveProof {
        resource::MoveProof::Resource(
            placement(extents, 9_000 + extents as u64, 4_096, native_error)
                .into_resource_value()
                .unwrap(),
        )
    }
    /// The record as it was made before: the whole proof as one JSON value.
    fn as_before(index: u64, phase: &str, extents: usize, error: Option<i32>) -> serde_json::Value {
        let proof =
            serde_json::to_value(placement(extents, 9_000 + extents as u64, 4_096, error)).unwrap();
        serde_json::json!({"object_index":index,"phase":phase,"proof":proof})
    }

    const CASES: [(u64, &str, usize, Option<i32>); 6] = [
        (0, DEFERRED_ORIGINAL, 1, None),
        (3, DEFERRED_SCRATCH, 0, None),
        (17, "evacuate-blocker", 1024, None),
        (u32::MAX as u64, "original-coordinate", 1025, None),
        (u64::MAX, "original-coordinate", 4_000, None),
        (5, "original-coordinate", 2, Some(87)),
    ];

    #[test]
    fn a_move_record_is_the_bytes_of_the_value_it_was_made_as() {
        for (index, phase, extents, error) in CASES {
            let before = as_before(index, phase, extents, error);
            let proof = resource(extents, error);
            let json = move_record_json(index, phase, &proof).unwrap();
            assert_eq!(json, serde_json::to_vec(&before).unwrap());
            assert_eq!(json.len(), compact_size(&before).unwrap());
            // A refused move's record, and the record kept without a sink.
            let value = serde_json::json!({"object_index":index,"phase":phase,"proof":proof});
            assert_eq!(value, before);
            // The fields a refusal is decided and reported by.
            for key in ["native_error", "mapping_matches", "all_placements_match"] {
                assert_eq!(proof[key], before["proof"][key], "{key}");
            }
        }
    }

    #[test]
    fn evidence_records_a_move_proof_as_it_recorded_its_value() {
        // With a sink, as a resource placement records: the same bytes,
        // counts and recent phases.
        let mut old_sink = Recorded::default();
        let mut new_sink = Recorded::default();
        let mut old = Evidence::new(Some(&mut old_sink), usize::MAX);
        let mut new = Evidence::new(Some(&mut new_sink), usize::MAX);
        for round in 0..4 {
            for (index, phase, extents, error) in CASES {
                let index = index.wrapping_add(round);
                old.push_move(as_before(index, phase, extents, error))
                    .unwrap();
                new.push_move_proof(index, phase, &resource(extents, error))
                    .unwrap();
            }
        }
        assert_eq!(
            (old.compact_bytes, old.saved_bytes, old.count, old.len()),
            (new.compact_bytes, new.saved_bytes, new.count, new.len())
        );
        assert_eq!(old.moves, new.moves);
        drop((old, new));
        assert_eq!(old_sink.0, new_sink.0);
        // Without one, every proof is kept as a value, as before.
        let mut old = Evidence::default();
        let mut new = Evidence::default();
        for (index, phase, extents, error) in CASES {
            old.push_move(as_before(index, phase, extents, error))
                .unwrap();
            new.push_move_proof(index, phase, &resource(extents, error))
                .unwrap();
        }
        assert_eq!(
            (old.compact_bytes, old.saved_bytes, old.len()),
            (new.compact_bytes, new.saved_bytes, new.len())
        );
        assert_eq!(old.moves, new.moves);
    }

    #[test]
    fn a_settled_move_is_the_progress_document_made_again_without_it() {
        let mut sink = Recorded::default();
        let with_sink = Evidence::new(Some(&mut sink), usize::MAX);
        let without = Evidence::default();
        for evidence in [&with_sink, &without] {
            let mut counters = Counters {
                files: 7,
                desired_runs: 12,
                move_evidence_reservation_bytes: 5,
                ..Counters::default()
            };
            let pending = serde_json::json!({"object_index":3,"logical_offset":4096,
                "destination":1 << 30,"length":65536,"placement_result_recorded":false,
                "budget_charged":false,"canonical_object_index":2,"stream_name_utf16":[65, 66]});
            let mut document = progress_document(
                "original-coordinate",
                1 << 20,
                evidence,
                Some(pending),
                &counters,
            );
            // What a move writes into the document as it goes.
            document["charged_move_bytes"] = ((1u64 << 20) + 65536).into();
            document["pending"]["budget_charged"] = true.into();
            counters.move_evidence_reservation_bytes = 777;
            document["counters"]["move_evidence_reservation_bytes"] =
                counters.move_evidence_reservation_bytes.into();
            settled(&mut document);
            let again = progress_document(
                "original-coordinate",
                (1 << 20) + 65536,
                evidence,
                None,
                &counters,
            );
            assert_eq!(document, again);
            assert_eq!(
                serde_json::to_vec(&document).unwrap(),
                serde_json::to_vec(&again).unwrap()
            );
        }
    }

    #[test]
    fn the_progress_document_is_the_one_json_made() {
        let document_before = |phase: &str,
                               charged: u64,
                               verified: &Evidence<'_>,
                               pending: Option<serde_json::Value>,
                               counters: &Counters| {
            let phases: Vec<_> = verified
                .moves
                .iter()
                .rev()
                .take(16)
                .map(|m| serde_json::json!({"object_index":m["object_index"],"phase":m["phase"]}))
                .collect();
            let mut document = serde_json::json!({
                "schema_version":2,"kind":"private-placement-progress","phase":phase,
                "occupancy_evidence_scope":"destination-window-v1",
                "per_move_retrieval_scope":"complete-file-mapping","phase_bitmap_scope":"full-volume",
                "charged_move_bytes":charged,"verified_move_submissions":verified.len(),
                "recent_verified_phases_newest_first":phases,"pending":pending,"counters":counters,
                "placement_complete":false,"resume_authorized":false,"conversion_qualified":false
            });
            if let Some(barrier) = &counters.post_evacuation_barrier {
                document["post_evacuation_barrier"] = barrier.clone();
            }
            document
        };
        let mut sink = Recorded::default();
        let mut with_sink = Evidence::new(Some(&mut sink), usize::MAX);
        let mut without = Evidence::default();
        let mut counters = Counters {
            files: 7,
            desired_runs: 12,
            ..Counters::default()
        };
        let pending = serde_json::json!({"object_index":3,"logical_offset":4096,
            "destination":1 << 30,"length":65536,"placement_result_recorded":false,
            "budget_charged":false,"stream_name_utf16":[65, 66]});
        for round in 0..20u64 {
            for evidence in [&with_sink, &without] {
                for pending in [None, Some(pending.clone())] {
                    let document = progress_document(
                        "original-coordinate",
                        round << 20,
                        evidence,
                        pending.clone(),
                        &counters,
                    );
                    assert_eq!(
                        serde_json::to_vec(&document).unwrap(),
                        serde_json::to_vec(&document_before(
                            "original-coordinate",
                            round << 20,
                            evidence,
                            pending,
                            &counters
                        ))
                        .unwrap()
                    );
                }
            }
            let (index, phase, extents, error) = CASES[round as usize % CASES.len()];
            let index = index.wrapping_add(round);
            with_sink
                .push_move_proof(index, phase, &resource(extents, error))
                .unwrap();
            without
                .push_move(as_before(index, phase, extents, error))
                .unwrap();
            counters.final_submissions += 1;
            if round == 10 {
                counters.post_evacuation_barrier =
                    Some(serde_json::json!({"moves":3,"ranges":[1,2]}));
            }
        }
    }

    /// `saved_size` as it was: the whole text printed, then measured.
    fn printed_size(value: &serde_json::Value) -> usize {
        let pretty = serde_json::to_vec_pretty(value).unwrap();
        pretty.iter().filter(|&&b| b == b'\n').count() * 4 + pretty.len() + 6
    }

    #[test]
    fn sizes_measured_as_written_are_the_sizes_of_the_printed_values() {
        for (index, phase, extents, error) in CASES {
            let record = as_before(index, phase, extents, error);
            assert_eq!(saved_size(&record).unwrap(), printed_size(&record));
        }
        // The widest record, for every count of pages a run may allow.
        for extents in [0, 1] {
            for pages in (0..40).chain([255, 1_000, 4_097]) {
                assert_eq!(
                    widest_move_record_size(extents, pages).unwrap(),
                    printed_size(&widest_move_record(extents, pages).unwrap()),
                    "{extents} extents, {pages} pages"
                );
            }
        }
        // A move's bound, with the destination windows as a JSON value.
        let reservation = Reservation::with_resource_limits(crate::retrieval_paging::Limits {
            max_returned_bytes: 1 << 20,
            max_extents: 3_000,
            max_pages: 37,
        })
        .unwrap();
        for (extents, clusters) in [(1, 1), (40, 4_096), (2_999, 131_072)] {
            let destination = placement(extents, 9_000, clusters, None).destination_bitmap;
            let printed = printed_size(&serde_json::json!({
                "proof":{"destination_bitmap":&destination}
            })) - reservation.empty_destination;
            assert_eq!(
                reservation
                    .bound(extents, u64::from(clusters) * 4096, &destination)
                    .unwrap(),
                reservation.per_extent * 3_000 + reservation.base + printed
            );
        }
    }

    /// Sizing a move's bound and the widest record, before and after. Not run
    /// by default:
    /// `cargo test --release -p n2r-win32 reservation_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn reservation_cost() {
        use std::time::Instant;
        let reservation = Reservation::with_pages(1).unwrap();
        let destination = placement(1, 9_000, 131_072, None).destination_bitmap;
        let rounds = 20_000;
        let start = Instant::now();
        for _ in 0..rounds {
            std::hint::black_box(printed_size(&serde_json::json!({
                "proof":{"destination_bitmap":&destination}
            })));
        }
        let before = start.elapsed().as_secs_f64() / f64::from(rounds);
        let start = Instant::now();
        for _ in 0..rounds {
            std::hint::black_box(reservation.bound(1, 1 << 29, &destination).unwrap());
        }
        let after = start.elapsed().as_secs_f64() / f64::from(rounds);
        println!(
            "a move's bound: {:.1} us before, {:.1} us after",
            before * 1e6,
            after * 1e6
        );
        for pages in [1_000, 10_000, 160_000] {
            let start = Instant::now();
            for extents in [0, 1] {
                std::hint::black_box(printed_size(&widest_move_record(extents, pages).unwrap()));
            }
            let before = start.elapsed().as_secs_f64();
            let start = Instant::now();
            std::hint::black_box(Reservation::with_pages(pages).unwrap());
            let after = start.elapsed().as_secs_f64();
            println!(
                "the widest record of {pages} pages: {:.1} ms before, {:.3} ms after",
                before * 1e3,
                after * 1e3
            );
        }
    }

    /// The JSON work of recording one move, before and after, for files in
    /// growing numbers of pieces. Not run by default:
    /// `cargo test --release -p n2r-win32 move_record_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn move_record_cost() {
        use std::time::Instant;
        for extents in [16, 256, 1024, 4096, 16_384] {
            let rounds = (2_000_000 / extents).clamp(20, 20_000);
            let mut sink = io::sink();
            let start = Instant::now();
            for _ in 0..rounds {
                let sample = placement(extents, 9_000, 4_096, None);
                let proof = serde_json::to_value(&sample).unwrap();
                drop(sample);
                let record = serde_json::json!({"object_index":7,"phase":"original-coordinate",
                    "proof":resource::MoveProof::Legacy(proof)});
                let size = compact_size(&record).unwrap();
                let mut blocks = io::BufWriter::with_capacity(64 * 1024, &mut sink);
                serde_json::to_writer(&mut blocks, &record).unwrap();
                std::hint::black_box(size);
            }
            let before = start.elapsed().as_secs_f64() / rounds as f64;
            let start = Instant::now();
            for _ in 0..rounds {
                let proof = resource::MoveProof::Resource(
                    placement(extents, 9_000, 4_096, None)
                        .into_resource_value()
                        .unwrap(),
                );
                let json = move_record_json(7, "original-coordinate", &proof).unwrap();
                io::Write::write_all(&mut sink, &json).unwrap();
            }
            let after = start.elapsed().as_secs_f64() / rounds as f64;
            // Making the sample is in both; take it out of each.
            let start = Instant::now();
            for _ in 0..rounds {
                std::hint::black_box(placement(extents, 9_000, 4_096, None));
            }
            let made = start.elapsed().as_secs_f64() / rounds as f64;
            let proof = resource::MoveProof::Resource(
                placement(extents, 9_000, 4_096, None)
                    .into_resource_value()
                    .unwrap(),
            );
            let bytes = move_record_json(7, "original-coordinate", &proof)
                .unwrap()
                .len();
            println!(
                "{extents:>6} extents, {bytes:>9} bytes of record: {:>9.1} us a move before, {:>9.1} us after ({:.1}x); {:.2} ns a byte saved",
                (before - made) * 1e6,
                (after - made) * 1e6,
                (before - made) / (after - made),
                (before - after) * 1e9 / bytes as f64
            );
        }
    }
}
