//! Tree-wide zero-VDL allocation and original-coordinate placement. Only the
//! independent shadow moves; source data and conversion authority are absent.
use super::*;
use crate::{bitmap_observation::Observation, retention_layout};

const MOVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MOVES: usize = 1024;
const MAX_MOVE_EVIDENCE: usize = 16 * 1024 * 1024;

fn progress(
    tree: &mut PrivateTree,
    phase: &str,
    charged_bytes: u64,
    verified: &[serde_json::Value],
    pending: Option<serde_json::Value>,
) {
    // Keep a bounded tail, not a second copy of the complete mapping proofs.
    let phases: Vec<_> = verified
        .iter()
        .rev()
        .take(16)
        .map(|m| serde_json::json!({"object_index":m["object_index"],"phase":m["phase"]}))
        .collect();
    tree.placement_progress = serde_json::json!({
        "kind":"private-placement-progress","phase":phase,
        "charged_move_bytes":charged_bytes,"verified_move_submissions":verified.len(),
        "recent_verified_phases_newest_first":phases,"pending":pending,
        "placement_complete":false,"resume_authorized":false,"conversion_qualified":false
    });
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

fn append_move(
    moves: &mut Vec<serde_json::Value>,
    bytes: &mut usize,
    value: serde_json::Value,
) -> io::Result<()> {
    let length = serde_json::to_vec(&value).map_err(io::Error::other)?.len();
    let total = bytes
        .checked_add(length)
        .ok_or_else(|| invalid("placement evidence accounting overflow"))?;
    if total > MAX_MOVE_EVIDENCE {
        return Err(invalid(
            "placement evidence budget exceeded; preserve shadow without retry",
        ));
    }
    *bytes = total;
    moves.push(value);
    Ok(())
}

fn views(tree: &PrivateTree) -> io::Result<(Observation, Observation)> {
    let bytes = tree.pair.shadow.identity.partition_bytes;
    let a = Observation::capture(&tree.volume, &[0; 8], bytes, true)?;
    let mut ex = [0u8; 16];
    ex[8] = 1;
    let b = Observation::capture(&tree.volume, &ex, bytes, true)?;
    Ok((a, b))
}

fn scratch(tree: &PrivateTree, length: u64, avoid: &[(u64, u64)]) -> io::Result<u64> {
    let bytes = tree.pair.shadow.identity.partition_bytes;
    let (a, b) = views(tree)?;
    let plan = a.plan_free_subruns(
        &b,
        retention_layout::SourceRun {
            logical_offset: 0,
            physical_offset: 0,
            length: bytes,
        },
        bytes,
        1024,
    )?;
    for free in plan.subruns {
        let mut cursor = free.physical_offset.max(1024 * 1024);
        let end = (free.physical_offset + free.length).min(bytes.saturating_sub(1024 * 1024));
        if cursor >= end {
            continue;
        }
        for &(start, len) in avoid {
            let stop = start + len;
            if stop <= cursor {
                continue;
            }
            if start >= end {
                break;
            }
            if start > cursor && start - cursor >= length {
                return Ok(cursor);
            }
            cursor = cursor.max(stop);
            if cursor >= end {
                break;
            }
        }
        if cursor < end && end - cursor >= length {
            return Ok(cursor);
        }
    }
    Err(invalid(
        "no independently free scratch span outside desired source ranges",
    ))
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

pub(super) fn run(
    tree: &mut PrivateTree,
    input: &[Input<'_>],
    max_move_bytes: u64,
    max_moves: usize,
) -> io::Result<serde_json::Value> {
    tree.require_source_excluded()?;
    if max_move_bytes == 0 || !(1..=MAX_MOVES).contains(&max_moves) {
        return Err(invalid("explicit placement limits differ"));
    }
    if tree.placement_started {
        return Err(invalid(
            "tree placement already attempted; preserve without retry",
        ));
    }
    if input.len() != tree.initial_objects.len() {
        return Err(invalid("private placement object count differs"));
    }
    let partition = tree.pair.shadow.identity.partition_bytes;
    let mut desired = BTreeMap::new();
    let mut avoid = Vec::new();

    for (&index, file) in &tree.files {
        let item = input
            .get(index)
            .ok_or_else(|| invalid("private placement index differs"))?;
        let path = format!(
            "{}\\{}",
            tree.pair.shadow.volume_path()?,
            item.components.join("\\")
        );
        if item.directory
            || file.path != path
            || file.logical_length() != item.logical_length()
            || file.valid_prefix() != 0
        {
            return Err(invalid("private placement input or zero-VDL state differs"));
        }
        let runs = source_runs(item, partition)?;
        for run in &runs {
            avoid.push((run.physical_offset.unwrap(), run.length));
        }
        if avoid.len() > 1024 {
            return Err(invalid("global source placement range budget exceeded"));
        }
        desired.insert(index, runs);
    }
    avoid.sort_by_key(|r| r.0);
    if avoid.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) {
        return Err(invalid("source desired physical ownership overlaps"));
    }
    let mut moves = Vec::new();
    let mut move_bytes = 0u64;
    tree.placement_started = true;
    progress(tree, "track-zero-vdl", 0, &moves, None);
    let mut evidence_bytes = 0usize;
    let mut parked = Vec::new();
    let indexes: Vec<_> = tree.files.keys().copied().collect();
    // Bind existing allocated ownership; explicitly place only deferred holes.
    // No user bytes are initialized by tracking a native unwritten mapping.
    for index in &indexes {
        let holes = tree.files.get_mut(index).unwrap().track_current_prefix()?;
        for (vcn, clusters) in holes {
            let start = vcn * 4096;
            let end = start + u64::from(clusters) * 4096;
            // A deferred range has no old physical ownership to evacuate.
            // Allocate it at the wanted coordinates first where both native
            // views agree they are free, rather than parking the entire range
            // and submitting the same bytes a second time during final placement.
            let mut direct = Vec::new();
            for run in &desired[index] {
                let from = start.max(run.logical_offset);
                let to = end.min(run.logical_offset + run.length);
                if from >= to {
                    continue;
                }
                let (a, b) = views(tree)?;
                let plan = a.plan_free_subruns(
                    &b,
                    retention_layout::SourceRun {
                        logical_offset: from,
                        physical_offset: run.physical_offset.unwrap() + from - run.logical_offset,
                        length: to - from,
                    },
                    partition,
                    max_moves,
                )?;
                for subrun in plan.subruns {
                    // Keep the same bootstrap margins as scratch allocation.
                    let physical_start = subrun.physical_offset.max(1024 * 1024);
                    let physical_end = (subrun.physical_offset + subrun.length)
                        .min(partition.saturating_sub(1024 * 1024));
                    if physical_start < physical_end {
                        direct.push((
                            subrun.logical_offset + physical_start - subrun.physical_offset,
                            physical_start,
                            physical_end - physical_start,
                        ));
                    }
                    if direct.len() > MAX_MOVES {
                        return Err(invalid("direct deferred allocation range budget exhausted"));
                    }
                }
            }
            direct.sort_unstable_by_key(|r| r.0);
            let mut cursor = start;
            let mut next_direct = 0;
            while cursor < end {
                if moves.len() >= max_moves {
                    return Err(invalid("deferred allocation move budget exhausted"));
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
                        "allocate-deferred-original",
                    ),
                    candidate => {
                        let stop = candidate.map_or(end, |r| r.0.min(end));
                        let length = (stop - cursor).min(MOVE_BYTES);
                        (
                            scratch(tree, length, &avoid)?,
                            length,
                            "allocate-deferred-scratch",
                        )
                    }
                };
                progress(
                    tree,
                    phase,
                    move_bytes,
                    &moves,
                    Some(serde_json::json!({
                    "object_index":index,"logical_offset":cursor,"destination":destination,"length":length,
                    "placement_result_recorded":false,"budget_charged":false})),
                );
                charge_move(&mut move_bytes, length, max_move_bytes)?;
                tree.placement_progress["charged_move_bytes"] = move_bytes.into();
                tree.placement_progress["pending"]["budget_charged"] = true.into();
                let proof = tree.place(
                    *index,
                    cursor / 4096,
                    destination / 4096,
                    (length / 4096) as u32,
                )?;
                if proof["native_error"] != serde_json::Value::Null
                    || proof["all_placements_match"] != true
                {
                    return Err(invalid(
                        "deferred unwritten allocation refused; preserve without retry",
                    ));
                }
                append_move(
                    &mut moves,
                    &mut evidence_bytes,
                    serde_json::json!({"object_index":index,"phase":phase,"proof":proof}),
                )?;
                progress(tree, phase, move_bytes, &moves, None);
                cursor += length;
            }
        }
    }
    let mut owned = Vec::new();
    let mut eligible = Vec::new();
    for index in &indexes {
        let file = &tree.files[index];
        file.check_placements()?;
        for &(v, l, n) in file.tracked_mappings() {
            owned.push(crate::shadow_evacuation::Extent {
                file_index: *index as u32,
                logical_offset: v * 4096,
                physical_offset: l * 4096,
                length: u64::from(n) * 4096,
            });
        }
        for run in &desired[index] {
            eligible.push(crate::shadow_evacuation::Extent {
                file_index: *index as u32,
                logical_offset: run.logical_offset,
                physical_offset: run.physical_offset.unwrap(),
                length: run.length,
            });
        }
    }
    if owned.len() > 1024 {
        return Err(invalid("global tracked ownership range budget exceeded"));
    }
    let (legacy, metadata) = views(tree)?;
    progress(tree, "plan-evacuation", move_bytes, &moves, None);
    let remaining = max_moves
        .checked_sub(moves.len())
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid("no evacuation move budget"))?;
    let evacuation = crate::shadow_evacuation::plan_ranges(
        &legacy.allocation_map(partition)?,
        &metadata.allocation_map(partition)?,
        &eligible,
        &owned,
        partition,
        remaining,
    )?;
    let required: usize = evacuation
        .moves
        .iter()
        .map(|m| m.length.div_ceil(MOVE_BYTES) as usize)
        .sum();
    if required >= remaining {
        return Err(invalid("evacuation leaves no final-placement budget"));
    }
    for movement in &evacuation.moves {
        if movement.destination_offset < 1024 * 1024
            || movement
                .destination_offset
                .checked_add(movement.length)
                .is_none_or(|v| v > partition.saturating_sub(1024 * 1024))
        {
            return Err(invalid(
                "evacuation destination enters bootstrap safety margin",
            ));
        }
    }
    for movement in &evacuation.moves {
        let mut offset = 0;
        while offset < movement.length {
            let length = (movement.length - offset).min(MOVE_BYTES);
            progress(
                tree,
                "evacuate-blocker",
                move_bytes,
                &moves,
                Some(serde_json::json!({
                "object_index":movement.file_index,"logical_offset":movement.logical_offset+offset,
                "destination":movement.destination_offset+offset,"length":length,
                "placement_result_recorded":false,"budget_charged":false})),
            );
            charge_move(&mut move_bytes, length, max_move_bytes)?;
            tree.placement_progress["charged_move_bytes"] = move_bytes.into();
            tree.placement_progress["pending"]["budget_charged"] = true.into();
            let proof = tree.reposition(
                movement.file_index as usize,
                (movement.logical_offset + offset) / 4096,
                (movement.destination_offset + offset) / 4096,
                (length / 4096) as u32,
            )?;
            if proof["native_error"] != serde_json::Value::Null
                || proof["all_placements_match"] != true
            {
                return Err(invalid(
                    "selective unwritten evacuation refused; preserve without retry",
                ));
            }
            append_move(
                &mut moves,
                &mut evidence_bytes,
                serde_json::json!({"object_index":movement.file_index,"phase":"evacuate-blocker","proof":proof}),
            )?;
            progress(tree, "evacuate-blocker", move_bytes, &moves, None);
            offset += length;
        }
    }
    parked.push(
        serde_json::json!({"strategy":"selective-user-blockers","initial_owned_ranges":owned,
        "evacuation_plan":evacuation}),
    );
    let mut retained = Vec::new();
    let mut original_coordinates: BTreeMap<usize, Vec<(u64, u64, u64)>> = BTreeMap::new();
    let mut retained_bytes = 0u64;
    for &index in &indexes {
        for run in &desired[&index] {
            let remaining = max_moves
                .checked_sub(moves.len())
                .filter(|v| *v > 0)
                .ok_or_else(|| invalid("tree placement move budget exhausted"))?;
            let (a, b) = views(tree)?;
            let plan = a.plan_free_subruns(
                &b,
                retention_layout::SourceRun {
                    logical_offset: run.logical_offset,
                    physical_offset: run.physical_offset.unwrap(),
                    length: run.length,
                },
                partition,
                remaining,
            )?;
            let required: usize = plan
                .subruns
                .iter()
                .map(|r| r.length.div_ceil(MOVE_BYTES) as usize)
                .sum();
            if required > remaining {
                return Err(invalid("final-placement split budget exceeded"));
            }
            for subrun in plan.subruns {
                let mut offset = 0;
                while offset < subrun.length {
                    let length = (subrun.length - offset).min(MOVE_BYTES);
                    let logical = subrun.logical_offset + offset;
                    let physical = subrun.physical_offset + offset;
                    progress(
                        tree,
                        "original-coordinate",
                        move_bytes,
                        &moves,
                        Some(serde_json::json!({
                        "object_index":index,"logical_offset":logical,"destination":physical,"length":length,
                        "placement_result_recorded":false,"budget_charged":false})),
                    );
                    charge_move(&mut move_bytes, length, max_move_bytes)?;
                    tree.placement_progress["charged_move_bytes"] = move_bytes.into();
                    tree.placement_progress["pending"]["budget_charged"] = true.into();
                    let proof = tree.reposition(
                        index,
                        logical / 4096,
                        physical / 4096,
                        (length / 4096) as u32,
                    )?;
                    progress(tree, "original-coordinate", move_bytes, &moves, None);
                    if proof["native_error"] != serde_json::Value::Null
                        || proof["all_placements_match"] != true
                    {
                        return Err(invalid(
                            "original-coordinate reposition refused; preserve without retry",
                        ));
                    }
                    append_move(
                        &mut moves,
                        &mut evidence_bytes,
                        serde_json::json!({"object_index":index,"phase":"original-coordinate","proof":proof}),
                    )?;
                    retained.push(serde_json::json!({"object_index":index,"logical_offset":logical,
                        "source_physical_offset":physical,"target_physical_offset":physical,"length":length,
                        "source_contents_verified":false}));
                    original_coordinates
                        .entry(index)
                        .or_default()
                        .push((logical, physical, length));
                    retained_bytes = retained_bytes
                        .checked_add(length)
                        .ok_or_else(|| invalid("retained byte overflow"))?;
                    offset += length;
                }
            }
        }
    }
    // Derive every final original-coordinate reference from live tracked
    // mappings, including data already correctly placed before this operation.
    // Planned destinations and bitmap bits alone never count as ownership.
    retained.clear();
    original_coordinates.clear();
    retained_bytes = 0;
    for &index in &indexes {
        let file = &tree.files[&index];
        file.check_placements()?;
        for source in &desired[&index] {
            let wanted_vcn = source.logical_offset / 4096;
            let wanted_lcn = source.physical_offset.unwrap() / 4096;
            let wanted_end = wanted_vcn + source.length / 4096;
            for &(v, l, n) in file.tracked_mappings() {
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
    tree.require_source_excluded()?;
    tree.original_coordinates = original_coordinates;
    tree.placement_complete = true;
    progress(tree, "complete", move_bytes, &moves, None);
    tree.placement_progress["placement_complete"] = true.into();
    Ok(
        serde_json::json!({"kind":"private-unwritten-tree-placement","parked":parked,"moves":moves,
        "original_coordinate_ranges":retained,"original_coordinate_bytes":retained_bytes,
        "move_evidence_bytes":evidence_bytes,
        "move_bytes_submitted":move_bytes,"max_move_bytes":max_move_bytes,"max_move_submissions":max_moves,
        "payload_contents_verified":false,"source_payload_writes":0,"conversion_qualified":false}),
    )
}
