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
    if input.len() != tree.initial_objects.len() {
        return Err(invalid("private placement object count differs"));
    }
    let partition = tree.pair.shadow.identity.partition_bytes;
    let mut desired = BTreeMap::new();
    let mut avoid = Vec::new();
    let mut parking_moves = 0usize;
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
        parking_moves = parking_moves
            .checked_add((item.logical_length() / 4096 * 4096).div_ceil(MOVE_BYTES) as usize)
            .ok_or_else(|| invalid("parking move budget overflow"))?;
    }
    if parking_moves >= MAX_MOVES {
        return Err(invalid("parking leaves no final-placement move budget"));
    }
    avoid.sort_by_key(|r| r.0);
    if avoid.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) {
        return Err(invalid("source desired physical ownership overlaps"));
    }
    let mut moves = Vec::new();
    let mut evidence_bytes = 0usize;
    let mut parked = Vec::new();
    let indexes: Vec<_> = tree.files.keys().copied().collect();
    // Park EVERY file first, so one file's automatic allocation cannot block
    // another's final original-coordinate destination.
    for index in &indexes {
        let prefix = input[*index].logical_length() / 4096 * 4096;
        if prefix == 0 {
            continue;
        }
        let destination = scratch(tree, prefix, &avoid)?;
        let mut offset = 0;
        while offset < prefix {
            let length = (prefix - offset).min(MOVE_BYTES);
            let proof = tree.place(
                *index,
                offset / 4096,
                (destination + offset) / 4096,
                (length / 4096) as u32,
            )?;
            if proof["native_error"] != serde_json::Value::Null
                || proof["all_placements_match"] != true
            {
                return Err(invalid(
                    "unwritten parking refused or incomplete; preserve without retry",
                ));
            }
            append_move(
                &mut moves,
                &mut evidence_bytes,
                serde_json::json!({"object_index":index,"phase":"park","proof":proof}),
            )?;
            offset += length;
        }
        parked.push(serde_json::json!({"object_index":index,"prefix_bytes":prefix,"temporary_offset":destination}));
    }
    let mut retained = Vec::new();
    let mut retained_bytes = 0u64;
    for index in indexes {
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
                    retained_bytes = retained_bytes
                        .checked_add(length)
                        .ok_or_else(|| invalid("retained byte overflow"))?;
                    offset += length;
                }
            }
        }
    }
    tree.require_source_excluded()?;
    Ok(
        serde_json::json!({"kind":"private-unwritten-tree-placement","parked":parked,"moves":moves,
        "original_coordinate_ranges":retained,"original_coordinate_bytes":retained_bytes,
        "move_evidence_bytes":evidence_bytes,
        "payload_contents_verified":false,"source_payload_writes":0,"conversion_qualified":false}),
    )
}
