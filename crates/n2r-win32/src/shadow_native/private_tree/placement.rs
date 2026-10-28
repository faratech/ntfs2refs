//! Tree-wide zero-VDL parking and original-coordinate placement. Only the
//! independent shadow moves; source data and conversion authority are absent.
use super::*;
use crate::{bitmap_observation::Observation, retention_layout};

const MOVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MOVES: usize = 1024;
const MAX_MOVE_EVIDENCE: usize = 16 * 1024 * 1024;

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

pub(super) fn run(tree: &mut PrivateTree, input: &[Input<'_>]) -> io::Result<serde_json::Value> {
    tree.require_source_excluded()?;
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
    tree.placement_started = true;
    let mut evidence_bytes = 0usize;
    let mut parked = Vec::new();
    let indexes: Vec<_> = tree.files.keys().copied().collect();
    // Bind existing allocated ownership; explicitly place only deferred holes.
    // No user bytes are initialized by tracking a native unwritten mapping.
    for index in &indexes {
        let holes = tree.files.get_mut(index).unwrap().track_current_prefix()?;
        for (vcn, clusters) in holes {
            let bytes = u64::from(clusters) * 4096;
            let destination = scratch(tree, bytes, &avoid)?;
            let mut offset = 0;
            while offset < bytes {
                if moves.len() >= MAX_MOVES {
                    return Err(invalid("deferred allocation move budget exhausted"));
                }
                let length = (bytes - offset).min(MOVE_BYTES);
                let proof = tree.place(
                    *index,
                    vcn + offset / 4096,
                    (destination + offset) / 4096,
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
                    serde_json::json!({"object_index":index,"phase":"allocate-deferred","proof":proof}),
                )?;
                offset += length;
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
    let remaining = MAX_MOVES
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
            let remaining = MAX_MOVES
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
                    let proof = tree.reposition(
                        index,
                        logical / 4096,
                        physical / 4096,
                        (length / 4096) as u32,
                    )?;
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
    Ok(
        serde_json::json!({"kind":"private-unwritten-tree-placement","parked":parked,"moves":moves,
        "original_coordinate_ranges":retained,"original_coordinate_bytes":retained_bytes,
        "move_evidence_bytes":evidence_bytes,
        "payload_contents_verified":false,"source_payload_writes":0,"conversion_qualified":false}),
    )
}
