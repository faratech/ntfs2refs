//! Logical data-supply plan derived only from this process's native placement
//! results. Serialization is diagnostic; no deserializer or write authority.
use super::*;

#[derive(Clone, Serialize)]
pub struct SupplyRange {
    pub object_index: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_name_utf16: Vec<u16>,
    pub logical_offset: u64,
    pub length: u64,
    pub source_physical_offset: Option<u64>,
}

#[derive(Serialize)]
pub struct SupplyPlan {
    materialize: Vec<SupplyRange>,
    source_reference: Vec<SupplyRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    holes: Vec<SupplyRange>,
    #[serde(skip_serializing_if = "zero")]
    pub hole_bytes: u64,
    pub materialize_bytes: u64,
    pub source_reference_bytes: u64,
    pub logical_bytes: u64,
    pub payload_contents_verified: bool,
    pub conversion_qualified: bool,
}
fn zero(value: &u64) -> bool {
    *value == 0
}
impl SupplyPlan {
    pub fn materialization_ranges(&self) -> &[SupplyRange] {
        &self.materialize
    }
    pub fn source_reference_ranges(&self) -> &[SupplyRange] {
        &self.source_reference
    }
    pub fn hole_ranges(&self) -> &[SupplyRange] {
        &self.holes
    }
}

fn emit(
    result: &mut SupplyPlan,
    tree: &PrivateTree,
    key: &StreamKey,
    offset: u64,
    length: u64,
    physical: Option<u64>,
) -> io::Result<()> {
    let parts = if let Some(target) = tree.sparse_targets.get(key) {
        target.parts(offset, length, true)?
    } else {
        vec![sparse_stream::Island {
            logical: offset,
            dense: offset,
            length,
        }]
    };
    for part in parts {
        let n = tree.sparse_targets.get(key).map_or(part.length, |target| {
            part.length
                .min(target.logical_length.saturating_sub(part.logical))
        });
        if n == 0 && (length != 0 || tree.sparse_targets.contains_key(key)) {
            continue;
        }
        let range = SupplyRange {
            object_index: key.object_index,
            stream_name_utf16: key.name_utf16.clone(),
            logical_offset: part.logical,
            length: n,
            source_physical_offset: physical.map(|p| p + part.dense - offset),
        };
        if physical.is_some() {
            result.source_reference_bytes += n;
            result.source_reference.push(range);
        } else {
            result.materialize_bytes += n;
            result.materialize.push(range);
        }
    }
    Ok(())
}

pub(super) fn plan(tree: &PrivateTree) -> io::Result<SupplyPlan> {
    tree.require_source_excluded()?;
    if !tree.placement_complete {
        return Err(invalid(
            "complete live tree placement required for supply plan",
        ));
    }
    let mut result = SupplyPlan {
        materialize: vec![],
        source_reference: vec![],
        holes: vec![],
        hole_bytes: 0,
        materialize_bytes: 0,
        source_reference_bytes: 0,
        logical_bytes: 0,
        payload_contents_verified: false,
        conversion_qualified: false,
    };
    for (key, file) in &tree.files {
        file.check_placements()?;
        let length = file.logical_length();
        let mut cursor = 0;
        let mut reference = tree
            .original_coordinates
            .get(key)
            .cloned()
            .unwrap_or_default();
        reference.sort_by_key(|r| r.0);
        for (logical, physical, bytes) in reference {
            let end = logical
                .checked_add(bytes)
                .ok_or_else(|| invalid("source reference overflow"))?;
            if bytes == 0
                || logical < cursor
                || end > length
                || !logical.is_multiple_of(4096)
                || !physical.is_multiple_of(4096)
                || !bytes.is_multiple_of(4096)
            {
                return Err(invalid(
                    "live original-coordinate references overlap or escape file",
                ));
            }
            if logical > cursor {
                emit(&mut result, tree, key, cursor, logical - cursor, None)?;
            }
            emit(&mut result, tree, key, logical, bytes, Some(physical))?;
            cursor = end;
        }
        if cursor < length || length == 0 {
            emit(&mut result, tree, key, cursor, length - cursor, None)?;
        }
        result.logical_bytes = result
            .logical_bytes
            .checked_add(
                tree.sparse_targets
                    .get(key)
                    .map_or(length, |t| t.logical_length),
            )
            .ok_or_else(|| invalid("logical total overflow"))?;
        if result.materialize.len() + result.source_reference.len() > 4096 {
            return Err(invalid("supply range budget exceeded"));
        }
    }
    for (key, target) in &tree.sparse_targets {
        if !tree.files.contains_key(key) {
            result.logical_bytes += target.logical_length;
        }
        for hole in &target.layout.holes {
            result.holes.push(SupplyRange {
                object_index: key.object_index,
                stream_name_utf16: key.name_utf16.clone(),
                logical_offset: hole.offset,
                length: hole.length,
                source_physical_offset: None,
            });
            result.hole_bytes += hole.length;
        }
    }
    if result.materialize.len() + result.source_reference.len() + result.holes.len() > 4096 {
        return Err(invalid("sparse supply range budget exceeded"));
    }
    if result
        .materialize_bytes
        .checked_add(result.source_reference_bytes)
        .and_then(|n| n.checked_add(result.hole_bytes))
        != Some(result.logical_bytes)
    {
        return Err(invalid(
            "private supply plan does not cover logical namespace",
        ));
    }
    tree.require_source_excluded()?;
    Ok(result)
}
