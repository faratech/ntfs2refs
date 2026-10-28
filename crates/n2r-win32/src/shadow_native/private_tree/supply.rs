//! Logical data-supply plan derived only from this process's native placement
//! results. Serialization is diagnostic; no deserializer or write authority.
use super::*;

#[derive(Clone, Serialize)]
pub struct SupplyRange {
    pub object_index: usize,
    pub logical_offset: u64,
    pub length: u64,
    pub source_physical_offset: Option<u64>,
}

#[derive(Serialize)]
pub struct SupplyPlan {
    materialize: Vec<SupplyRange>,
    source_reference: Vec<SupplyRange>,
    pub materialize_bytes: u64,
    pub source_reference_bytes: u64,
    pub logical_bytes: u64,
    pub payload_contents_verified: bool,
    pub conversion_qualified: bool,
}
impl SupplyPlan {
    pub fn materialization_ranges(&self) -> &[SupplyRange] {
        &self.materialize
    }
    pub fn source_reference_ranges(&self) -> &[SupplyRange] {
        &self.source_reference
    }
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
        materialize_bytes: 0,
        source_reference_bytes: 0,
        logical_bytes: 0,
        payload_contents_verified: false,
        conversion_qualified: false,
    };
    for (&index, file) in &tree.files {
        file.check_placements()?;
        let length = file.logical_length();
        let mut cursor = 0;
        let mut reference = tree
            .original_coordinates
            .get(&index)
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
                result.materialize.push(SupplyRange {
                    object_index: index,
                    logical_offset: cursor,
                    length: logical - cursor,
                    source_physical_offset: None,
                });
                result.materialize_bytes =
                    result
                        .materialize_bytes
                        .checked_add(logical - cursor)
                        .ok_or_else(|| invalid("materialization total overflow"))?;
            }
            result.source_reference.push(SupplyRange {
                object_index: index,
                logical_offset: logical,
                length: bytes,
                source_physical_offset: Some(physical),
            });
            result.source_reference_bytes = result
                .source_reference_bytes
                .checked_add(bytes)
                .ok_or_else(|| invalid("source reference total overflow"))?;
            cursor = end;
        }
        if cursor < length || length == 0 {
            result.materialize.push(SupplyRange {
                object_index: index,
                logical_offset: cursor,
                length: length - cursor,
                source_physical_offset: None,
            });
            result.materialize_bytes = result
                .materialize_bytes
                .checked_add(length - cursor)
                .ok_or_else(|| invalid("materialization total overflow"))?;
        }
        result.logical_bytes = result
            .logical_bytes
            .checked_add(length)
            .ok_or_else(|| invalid("logical total overflow"))?;
        if result.materialize.len() + result.source_reference.len() > 4096 {
            return Err(invalid("supply range budget exceeded"));
        }
    }
    if result
        .materialize_bytes
        .checked_add(result.source_reference_bytes)
        != Some(result.logical_bytes)
    {
        return Err(invalid(
            "private supply plan does not cover logical namespace",
        ));
    }
    tree.require_source_excluded()?;
    Ok(result)
}
