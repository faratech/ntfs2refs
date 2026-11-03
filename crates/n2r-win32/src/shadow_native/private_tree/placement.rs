//! Tree-wide zero-VDL allocation and original-coordinate placement. Only the
//! independent shadow moves; source data and conversion authority are absent.
use super::super::input_domain::{InputDomain, ObjectInput, SliceInputs};
use super::*;
use crate::{bitmap_observation::Observation, retention_layout, shadow_evacuation};

const MOVE_BYTES: u64 = 512 * 1024 * 1024;
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
/// The mover's refusal text for that case (unwritten.rs, ResourceBusy).
const DRIFT_REFUSAL: &str = "private placement requires both current bitmap views free";
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
    move_submissions_limit: usize,
    move_evidence_bytes: usize,
    move_evidence_reservation_bytes: usize,
    placement_artifact_bytes: usize,
    placement_artifact_bytes_limit: usize,
    phase_bitmap_snapshots: usize,
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
            || (!key.name_utf16.is_empty() && original.logical_length() >= 4096);
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
                && original.logical_length() >= 4096
                && target.layout.initialized_length == original.logical_length()
                && target.layout.holes.is_empty()
                && target.layout.allocated.len() == 1
                && target.layout.allocated[0].offset == 0
                && original.logical_length().checked_next_multiple_of(4096)
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
    verified: &[serde_json::Value],
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
    // Keep a bounded tail, not a second copy of the complete mapping proofs.
    let phases: Vec<_> = verified
        .iter()
        .rev()
        .take(16)
        .map(|m| serde_json::json!({"object_index":m["object_index"],"phase":m["phase"]}))
        .collect();
    tree.placement_progress = serde_json::json!({
        "schema_version":2,"kind":"private-placement-progress","phase":phase,
        "occupancy_evidence_scope":"destination-window-v1",
        "per_move_retrieval_scope":"complete-file-mapping","phase_bitmap_scope":"full-volume",
        "charged_move_bytes":charged_bytes,"verified_move_submissions":verified.len(),
        "recent_verified_phases_newest_first":phases,"pending":pending,"counters":counters,
        "placement_complete":false,"resume_authorized":false,"conversion_qualified":false
    });
    if let Some(barrier) = &counters.post_evacuation_barrier {
        tree.placement_progress["post_evacuation_barrier"] = barrier.clone();
    }
}

/// Record the bounded quantity in the progress artifact and refuse.
fn refuse(tree: &mut PrivateTree, counters: &Counters, message: String) -> io::Error {
    if !tree.placement_progress.is_object() {
        progress(tree, "plan-desired-runs", 0, &[], None, counters);
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
    error.kind() == io::ErrorKind::ResourceBusy
        && error.raw_os_error().is_none()
        && error
            .get_ref()
            .is_some_and(|inner| inner.to_string() == DRIFT_REFUSAL)
}

/// Bytes `value` adds to the saved document as one element of a top-level
/// array: separator, two indentation levels before it and on each of its
/// inner lines (serde_json's pretty formatter indents two spaces).
fn saved_size(value: &serde_json::Value) -> Result<usize, String> {
    let pretty = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let lines = pretty.iter().filter(|&&b| b == b'\n').count();
    lines
        .checked_mul(4)
        .and_then(|n| n.checked_add(pretty.len() + 6))
        .ok_or_else(|| "placement evidence accounting overflow".to_owned())
}

/// Move proofs are kept exactly as before. Their compact size is still
/// reported; the binding charge is each section's exact contribution to the
/// pretty-printed construction-placement.json, which must fit its save bound.
#[derive(Default)]
struct Evidence {
    moves: Vec<serde_json::Value>,
    compact_bytes: usize,
    saved_bytes: usize,
}

impl Evidence {
    fn charge(&mut self, value: &serde_json::Value) -> Result<(), String> {
        let total = saved_size(value)?
            .checked_add(self.saved_bytes)
            .ok_or("placement evidence accounting overflow")?;
        if total > MAX_PLACEMENT_ARTIFACT_BYTES {
            return Err(format!(
                "placement evidence budget exceeded: {total} saved artifact bytes > \
                 {MAX_PLACEMENT_ARTIFACT_BYTES} after {} move proofs; preserve shadow without retry",
                self.moves.len()
            ));
        }
        self.saved_bytes = total;
        Ok(())
    }

    fn push_move(&mut self, value: serde_json::Value) -> Result<(), String> {
        let compact = serde_json::to_vec(&value)
            .map_err(|e| e.to_string())?
            .len()
            .checked_add(self.compact_bytes)
            .ok_or("placement evidence accounting overflow")?;
        self.charge(&value)?;
        self.compact_bytes = compact;
        self.moves.push(value);
        Ok(())
    }

    /// Refuse before native IO unless the next move record, at its bound,
    /// still fits. The exact charge after the move is unchanged.
    fn reserve(&self, bound: usize) -> Result<(), String> {
        if self
            .saved_bytes
            .checked_add(bound)
            .is_none_or(|total| total > MAX_PLACEMENT_ARTIFACT_BYTES)
        {
            return Err(format!(
                "placement evidence reservation exceeded before native IO: {} saved artifact bytes \
                 + {bound} bound for the next move proof > {MAX_PLACEMENT_ARTIFACT_BYTES} after {} \
                 move proofs; preserve shadow without retry",
                self.saved_bytes,
                self.moves.len()
            ));
        }
        Ok(())
    }
}

/// Upper bound on a move record before native submission. Retrieval fields
/// retain their widest representation and all paging allowances. The actual
/// destination-window proof is charged after capture, before FSCTL_MOVE_FILE;
/// its serialized size cannot be inferred from the requested cluster count.
struct Reservation {
    base: usize,
    per_extent: usize,
    empty_destination: usize,
}

impl Reservation {
    fn new() -> Result<Self, String> {
        let base = saved_size(&widest_move_record(0)?)?;
        let per_extent = saved_size(&widest_move_record(1)?)?
            .checked_sub(base)
            .ok_or("placement evidence reservation differs")?;
        let empty_destination = saved_size(&serde_json::json!({
            "proof":{"destination_bitmap":serde_json::Value::Null}
        }))?;
        Ok(Self {
            base,
            per_extent,
            empty_destination,
        })
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
        let extents = current_extents
            .checked_add(2)
            .and_then(|n| n.checked_add(allowance))
            .ok_or("placement evidence reservation overflow")?;
        // Use the exact enclosing shape so the pretty-printed indentation and
        // line count are charged at the proof's real nesting depth. Replacing
        // null here adds exactly the same bytes as in widest_move_record.
        let destination_bytes = saved_size(&serde_json::json!({
            "proof":{"destination_bitmap":destination}
        }))?
        .checked_sub(self.empty_destination)
        .ok_or("placement destination evidence accounting differs")?;
        self.per_extent
            .checked_mul(extents)
            .and_then(|n| n.checked_add(self.base))
            .and_then(|n| n.checked_add(destination_bytes))
            .ok_or_else(|| "placement evidence reservation overflow".into())
    }
}

fn widest_move_record(extents: usize) -> Result<serde_json::Value, String> {
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
        pages: vec![page; crate::retrieval_paging::MAX_PAGES],
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
    evidence: &Evidence,
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

fn views(tree: &PrivateTree) -> io::Result<(Observation, Observation)> {
    let bytes = tree.pair.shadow.identity.partition_bytes;
    let a = Observation::capture(&tree.volume, &[0; 8], bytes, true)?;
    let mut ex = [0u8; 16];
    ex[8] = 1;
    let b = Observation::capture(&tree.volume, &ex, bytes, true)?;
    Ok((a, b))
}

/// Scalar diagnostics from actual complete views. No predicted free bit or
/// metadata-only ownership inference participates in these measurements.
fn barrier_snapshot(
    legacy: &Observation,
    metadata: &Observation,
    desired: &BTreeMap<usize, Vec<SourceRun>>,
    partition: u64,
) -> io::Result<serde_json::Value> {
    let a = legacy.view(partition)?.candidate(0, partition)?;
    let b = metadata.view(partition)?.candidate(0, partition)?;
    let planner = legacy.retention_planner(metadata, partition)?;
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
            retention_layout::MAX_SUBRUNS,
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
        "volume_clusters":partition / 4096,
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
}

impl Scratch {
    fn new(
        legacy: &Observation,
        metadata: &Observation,
        avoid: &[(u64, u64)],
        partition: u64,
    ) -> Result<Self, String> {
        let a = legacy
            .allocation_map(partition)
            .map_err(|e| e.to_string())?;
        let b = metadata
            .allocation_map(partition)
            .map_err(|e| e.to_string())?;
        let count = a.ranges.len() + b.ranges.len() + avoid.len() + 2;
        if count > MAX_SCRATCH_INTERVALS {
            return Err(format!(
                "scratch occupancy budget exceeded: {count} intervals > {MAX_SCRATCH_INTERVALS}"
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

fn source_runs(item: &Input<'_>, partition: u64) -> io::Result<Vec<SourceRun>> {
    let prefix = item.logical_length() / 4096 * 4096;
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
    for run in &result {
        let physical = run
            .physical_offset
            .ok_or_else(|| invalid("private placement rejects source holes"))?;
        if run.length == 0
            || run.logical_offset != logical
            || !run.length.is_multiple_of(4096)
            || !physical.is_multiple_of(4096)
            || physical
                .checked_add(run.length)
                .is_none_or(|v| v > partition)
        {
            return Err(invalid("source placement mapping differs"));
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

/// Inputs fixed before the first native move.
#[derive(Clone, Copy)]
struct Wanted<'a> {
    desired: &'a BTreeMap<usize, Vec<SourceRun>>,
    avoid: &'a [(u64, u64)],
    partition: u64,
    max_moves: usize,
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
) -> io::Result<Result<Vec<Deferred>, String>> {
    let Wanted {
        desired,
        avoid,
        partition,
        max_moves,
    } = wanted;
    let mut scratch = match Scratch::new(legacy, metadata, avoid, partition) {
        Ok(value) => value,
        Err(message) => return Ok(Err(message)),
    };
    counters.scratch_free_intervals = scratch.free.len();
    let planner = legacy.retention_planner(metadata, partition)?;
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
                max_moves,
            )?;
            for subrun in plan.subruns {
                // Keep the same bootstrap margins as scratch allocation.
                let physical_start = subrun.physical_offset.max(MARGIN);
                let physical_end =
                    (subrun.physical_offset + subrun.length).min(partition.saturating_sub(MARGIN));
                if physical_start < physical_end {
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
) -> io::Result<()> {
    // Plan every deferred hole from one snapshot of both native views. If
    // ReFS allocates a planned destination after it, the mover refuses that
    // step before submission; the rest of the phase is then planned again
    // from one fresh snapshot, a bounded number of times.
    let (legacy, metadata) = views(tree)?;
    counters.phase_bitmap_snapshots += 1;
    let base_moves = evidence.moves.len();
    let mut deferred = match plan_deferred(wanted, &legacy, &metadata, holes, base_moves, counters)?
    {
        Ok(steps) => steps,
        Err(message) => return Err(refuse(tree, counters, message)),
    };
    let mut next_step = 0;
    while let Some(&step) = deferred.get(next_step) {
        progress(
            tree,
            step.phase,
            *move_bytes,
            &evidence.moves,
            Some(serde_json::json!({
            "object_index":step.index,"logical_offset":step.logical,"destination":step.destination,
            "length":step.length,"placement_result_recorded":false,"budget_charged":false})),
            counters,
        );
        let current_extents = tree.file_by_slot(step.index)?.retrieval_extents();
        charge_move(move_bytes, step.length, max_move_bytes)?;
        tree.placement_progress["charged_move_bytes"] = (*move_bytes).into();
        tree.placement_progress["pending"]["budget_charged"] = true.into();
        let attempt = tree.place_slot_with_evidence(
            step.index,
            step.logical / 4096,
            step.destination / 4096,
            (step.length / 4096) as u32,
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
                let (legacy, metadata) = views(tree)?;
                counters.phase_bitmap_snapshots += 1;
                let planned = match plan_deferred(
                    wanted,
                    &legacy,
                    &metadata,
                    &remaining,
                    base_moves + next_step,
                    counters,
                )? {
                    Ok(steps) => steps,
                    Err(message) => return Err(refuse(tree, counters, message)),
                };
                deferred.truncate(next_step);
                deferred.extend(planned);
                continue;
            }
            result => result?,
        };
        if proof["native_error"] != serde_json::Value::Null || proof["all_placements_match"] != true
        {
            tree.placement_progress["failed_native_move"] = serde_json::json!({
                "object_index":step.index,"phase":step.phase,"proof":proof
            });
            return Err(invalid(
                "deferred unwritten allocation refused; preserve without retry",
            ));
        }
        if step.phase == DEFERRED_ORIGINAL {
            counters.deferred_original_submissions += 1;
        } else {
            counters.deferred_scratch_submissions += 1;
        }
        let recorded = evidence.push_move(
            serde_json::json!({"object_index":step.index,"phase":step.phase,"proof":proof}),
        );
        counters.move_evidence_bytes = evidence.compact_bytes;
        counters.placement_artifact_bytes = evidence.saved_bytes;
        if let Err(message) = recorded {
            return Err(refuse(tree, counters, message));
        }
        progress(
            tree,
            step.phase,
            *move_bytes,
            &evidence.moves,
            None,
            counters,
        );
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
    tree.require_source_excluded()?;
    tree.require_bound_input_domain(input)?;
    validate_limits(max_move_bytes, max_moves)?;
    if tree.placement_started {
        return Err(invalid(
            "tree placement already attempted; preserve without retry",
        ));
    }
    if input.len() != tree.initial_objects.len() {
        return Err(invalid("private placement object count differs"));
    }
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
        desired_runs_limit: MAX_ADMITTED_RANGES,
        tracked_extents_limit: MAX_TRACKED_EXTENTS,
        owned_intersecting_desired_limit: MAX_OWNED_RANGES,
        move_submissions_limit: max_moves,
        placement_artifact_bytes_limit: MAX_PLACEMENT_ARTIFACT_BYTES,
        drift_replans_limit_per_phase: MAX_DRIFT_REPLANS,
        ..Counters::default()
    };
    let reservation = Reservation::new().map_err(|message| invalid(&message))?;
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
            return Err(invalid("private placement input or zero-VDL state differs"));
        }
        let runs = source_runs(&item, partition)?;
        for run in &runs {
            avoid.push((run.physical_offset.unwrap(), run.length));
        }
        desired.insert(index, runs);
        if avoid.len() > MAX_ADMITTED_RANGES {
            break;
        }
    }
    counters.desired_runs = avoid.len();
    if avoid.len() > MAX_ADMITTED_RANGES {
        return Err(refuse(
            tree,
            &counters,
            format!(
                "global source placement range budget exceeded: {} desired NTFS runs > {MAX_ADMITTED_RANGES} \
                 (placement planner limit {MAX_PLACEMENT_RANGES}, downstream source-backed route and \
                 supply-range limit {DOWNSTREAM_ROUTE_LIMIT})",
                avoid.len()
            ),
        ));
    }
    avoid.sort_by_key(|r| r.0);
    if avoid.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) {
        return Err(invalid("source desired physical ownership overlaps"));
    }
    let mut evidence = Evidence::default();
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
        parked.push(mapping);
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
        parked.push(mapping);
    }
    tree.placement_started = true;
    progress(tree, "track-zero-vdl", 0, &evidence.moves, None, &counters);
    let indexes: Vec<_> = tree.stream_slots.keys().copied().collect();
    // Bind existing allocated ownership of every file before any native move.
    // Tracking only reads a placeholder's own live retrieval map, a move never
    // changes another placeholder's mapping, and every move still verifies its
    // file's complete tracked mapping first. No user bytes are initialized.
    let mut holes = Vec::new();
    for index in &indexes {
        let file = tree.file_by_slot_mut(*index)?;
        let file_holes = file.track_current_prefix()?;
        counters.initial_tracked_extents += file.tracked_mappings().len();
        counters.deferred_holes += file_holes.len();
        for (vcn, clusters) in file_holes {
            let start = vcn * 4096;
            holes.push((*index, start, start + u64::from(clusters) * 4096));
        }
    }
    let wanted = Wanted {
        desired: &desired,
        avoid: &avoid,
        partition,
        max_moves,
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
        )?;
    }
    let mut owned = Vec::new();
    let mut eligible = Vec::new();
    for index in &indexes {
        let file = tree.file_by_slot(*index)?;
        file.check_placements()?;
        for &(v, l, n) in file.tracked_mappings() {
            owned.push(shadow_evacuation::Extent {
                file_index: u32::try_from(*index)
                    .map_err(|_| invalid("placement slot exceeds planner identity"))?,
                logical_offset: v * 4096,
                physical_offset: l * 4096,
                length: u64::from(n) * 4096,
            });
        }
        for run in &desired[index] {
            eligible.push(shadow_evacuation::Extent {
                file_index: u32::try_from(*index)
                    .map_err(|_| invalid("placement slot exceeds planner identity"))?,
                logical_offset: run.logical_offset,
                physical_offset: run.physical_offset.unwrap(),
                length: run.length,
            });
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
    if owned.len() > MAX_TRACKED_EXTENTS {
        return Err(refuse(
            tree,
            &counters,
            format!(
                "global tracked shadow mapping budget exceeded: {} tracked mappings > {MAX_TRACKED_EXTENTS}",
                owned.len()
            ),
        ));
    }
    if counters.owned_intersecting_desired > MAX_OWNED_RANGES {
        return Err(refuse(
            tree,
            &counters,
            format!(
                "global tracked ownership range budget exceeded: {} tracked mappings intersect desired runs > {MAX_OWNED_RANGES}",
                counters.owned_intersecting_desired
            ),
        ));
    }
    let (legacy, metadata) = views(tree)?;
    counters.phase_bitmap_snapshots += 1;
    progress(
        tree,
        "plan-evacuation",
        move_bytes,
        &evidence.moves,
        None,
        &counters,
    );
    let Some(remaining) = max_moves
        .checked_sub(evidence.moves.len())
        .filter(|v| *v > 0)
    else {
        return Err(refuse(
            tree,
            &counters,
            format!(
                "no evacuation move budget: {} of {max_moves} submissions used",
                evidence.moves.len()
            ),
        ));
    };
    let evacuation = shadow_evacuation::plan_ranges(
        &legacy.allocation_map(partition)?,
        &metadata.allocation_map(partition)?,
        &eligible,
        &owned,
        partition,
        remaining,
        shadow_evacuation::RangeLimits {
            max_source_extents: MAX_PLACEMENT_RANGES,
            max_shadow_extents: MAX_TRACKED_EXTENTS,
            max_blocked: MAX_OWNED_RANGES + MAX_PLACEMENT_RANGES,
            max_moves: MAX_MOVES,
            margin: MARGIN,
        },
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
    let plan_record = serde_json::json!({"strategy":"selective-user-blockers","initial_owned_ranges":owned,
        "evacuation_plan":evacuation});
    let charged = evidence.charge(&plan_record);
    counters.placement_artifact_bytes = evidence.saved_bytes;
    if let Err(message) = charged {
        return Err(refuse(tree, &counters, message));
    }
    parked.push(plan_record);
    for movement in &evacuation.moves {
        let mut offset = 0;
        while offset < movement.length {
            let length = (movement.length - offset).min(MOVE_BYTES);
            progress(
                tree,
                "evacuate-blocker",
                move_bytes,
                &evidence.moves,
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
            let attempt = tree.reposition_slot_with_evidence(
                movement.file_index as usize,
                (movement.logical_offset + offset) / 4096,
                (movement.destination_offset + offset) / 4096,
                (length / 4096) as u32,
                |destination| {
                    reserve_move(
                        &mut counters,
                        &evidence,
                        &reservation,
                        current_extents,
                        length,
                        destination,
                    )
                },
            );
            tree.placement_progress["counters"]["move_evidence_reservation_bytes"] =
                counters.move_evidence_reservation_bytes.into();
            let proof = attempt?;
            if proof["native_error"] != serde_json::Value::Null
                || proof["all_placements_match"] != true
            {
                tree.placement_progress["failed_native_move"] = serde_json::json!({
                    "object_index":movement.file_index,"phase":"evacuate-blocker","proof":proof
                });
                return Err(invalid(
                    "selective unwritten evacuation refused; preserve without retry",
                ));
            }
            counters.evacuation_submissions += 1;
            let recorded = evidence.push_move(
                serde_json::json!({"object_index":movement.file_index,"phase":"evacuate-blocker","proof":proof}),
            );
            counters.move_evidence_bytes = evidence.compact_bytes;
            counters.placement_artifact_bytes = evidence.saved_bytes;
            if let Err(message) = recorded {
                return Err(refuse(tree, &counters, message));
            }
            progress(
                tree,
                "evacuate-blocker",
                move_bytes,
                &evidence.moves,
                None,
                &counters,
            );
            offset += length;
        }
    }
    // One snapshot after evacuation plans every desired run. Final moves land
    // only in their own disjoint desired runs, so no earlier move in this
    // phase allocates inside a later run; each move rechecks both live views.
    // If ReFS allocates a planned destination after the snapshot, the mover
    // refuses before submission and this run and every later one are planned
    // from one fresh snapshot, a bounded number of times. Pieces already
    // placed are allocated in it and so are not planned again.
    let (mut legacy, mut metadata) = views(tree)?;
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
            &evidence.moves,
            None,
            &counters,
        );
        let observed = (|| -> io::Result<(Observation, Observation)> {
            let trace = counters.post_evacuation_barrier.as_mut().unwrap();
            trace["before"] = barrier_snapshot(&legacy, &metadata, &desired, partition)?;
            trace["status"] = "checking-source-exclusion".into();
            tree.require_source_excluded()?;
            trace["source_exclusion_checked_before"] = true.into();
            trace["status"] = "flushing-owned-shadow-volume".into();
            let started = std::time::Instant::now();
            let flushed = tree.volume.sync_all();
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
            let (after_legacy, after_metadata) = views(tree)?;
            counters.phase_bitmap_snapshots += 1;
            trace["after"] = barrier_snapshot(&after_legacy, &after_metadata, &desired, partition)?;
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
                    &evidence.moves,
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
            &evidence.moves,
            None,
            &counters,
        );
    }
    if deferred_after_evacuation {
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
        )?;
        // Direct deferred allocations are now occupied and must not be planned
        // again. Never infer these bitmap bits from submitted move receipts.
        (legacy, metadata) = views(tree)?;
        counters.phase_bitmap_snapshots += 1;
    }
    // Only actual post-flush/post-deferred views can make a destination eligible.
    let mut planner = legacy.retention_planner(&metadata, partition)?;
    for &index in &indexes {
        for run in &desired[&index] {
            loop {
                let Some(remaining) = max_moves
                    .checked_sub(evidence.moves.len())
                    .filter(|v| *v > 0)
                else {
                    return Err(refuse(
                        tree,
                        &counters,
                        format!(
                            "tree placement move budget exhausted: {} of {max_moves} submissions used",
                            evidence.moves.len()
                        ),
                    ));
                };
                let plan = planner.plan(
                    retention_layout::SourceRun {
                        logical_offset: run.logical_offset,
                        physical_offset: run.physical_offset.unwrap(),
                        length: run.length,
                    },
                    remaining,
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
                'pieces: for subrun in plan.subruns {
                    let mut offset = 0;
                    while offset < subrun.length {
                        let length = (subrun.length - offset).min(MOVE_BYTES);
                        let logical = subrun.logical_offset + offset;
                        let physical = subrun.physical_offset + offset;
                        progress(
                            tree,
                            "original-coordinate",
                            move_bytes,
                            &evidence.moves,
                            Some(serde_json::json!({
                            "object_index":index,"logical_offset":logical,"destination":physical,"length":length,
                            "placement_result_recorded":false,"budget_charged":false})),
                            &counters,
                        );
                        let current_extents = tree.file_by_slot(index)?.retrieval_extents();
                        charge_move(&mut move_bytes, length, max_move_bytes)?;
                        tree.placement_progress["charged_move_bytes"] = move_bytes.into();
                        tree.placement_progress["pending"]["budget_charged"] = true.into();
                        let attempt = tree.reposition_slot_with_evidence(
                            index,
                            logical / 4096,
                            physical / 4096,
                            (length / 4096) as u32,
                            |destination| {
                                reserve_move(
                                    &mut counters,
                                    &evidence,
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
                        progress(
                            tree,
                            "original-coordinate",
                            move_bytes,
                            &evidence.moves,
                            None,
                            &counters,
                        );
                        if proof["native_error"] != serde_json::Value::Null
                            || proof["all_placements_match"] != true
                        {
                            let message = format!(
                                "original-coordinate reposition refused (native_error={}, mapping_matches={}, all_placements_match={}); preserve without retry",
                                proof["native_error"],
                                proof["mapping_matches"],
                                proof["all_placements_match"]
                            );
                            tree.placement_progress["failed_native_move"] = serde_json::json!({
                                "object_index":index,"phase":"original-coordinate","proof":proof
                            });
                            return Err(invalid(&message));
                        }
                        counters.final_submissions += 1;
                        let recorded = evidence.push_move(
                            serde_json::json!({"object_index":index,"phase":"original-coordinate","proof":proof}),
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
                (legacy, metadata) = views(tree)?;
                planner = legacy.retention_planner(&metadata, partition)?;
                counters.phase_bitmap_snapshots += 1;
            }
        }
    }
    // Derive every final original-coordinate reference from live tracked
    // mappings, including data already correctly placed before this operation.
    // Planned destinations and bitmap bits alone never count as ownership.
    // Do not build tentative coordinate rows per submitted move: they were
    // discarded here. The complete final live mappings below are the sole
    // source of these unchanged evidence rows, including already-placed data.
    let mut retained = Vec::new();
    let mut original_coordinates: BTreeMap<usize, Vec<(u64, u64, u64)>> = BTreeMap::new();
    let mut retained_bytes = 0u64;
    for &index in &indexes {
        let file = tree.file_by_slot(index)?;
        file.check_placements()?;
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
            let wanted_vcn = source.logical_offset / 4096;
            let wanted_lcn = source.physical_offset.unwrap() / 4096;
            let wanted_end = wanted_vcn + source.length / 4096;
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
                let logical = start * 4096;
                let physical = (l + start - v) * 4096;
                let length = (end - start) * 4096;
                original_coordinates
                    .entry(index)
                    .or_default()
                    .push((logical, physical, length));
                retained.push(serde_json::json!({"object_index":index,"logical_offset":logical,
                    "source_physical_offset":physical,"target_physical_offset":physical,"length":length,
                    "source_contents_verified":false}));
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
    tree.original_coordinates = retained_streams;
    tree.placement_complete = true;
    progress(
        tree,
        "complete",
        move_bytes,
        &evidence.moves,
        None,
        &counters,
    );
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
