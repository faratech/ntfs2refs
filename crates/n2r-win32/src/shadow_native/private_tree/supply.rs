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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyKind {
    Materialize,
    SourceReference,
    Hole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StreamSupplySummary {
    pub logical_bytes: u64,
    pub materialize_bytes: u64,
    pub source_reference_bytes: u64,
    pub hole_bytes: u64,
    pub ranges: u64,
    pub ordered_range_sha256: String,
}

/// No native query, path construction, owned key, or map clone precedes this
/// estimate. A caller can therefore pay before the first summary observation.
pub(super) fn workspace_bytes(tree: &PrivateTree, index: usize, name: &[u16]) -> io::Result<u64> {
    let add = |a: u64, b: u64| {
        a.checked_add(b)
            .ok_or_else(|| invalid("stream supply working RAM overflow"))
    };
    let mul = |a: u64, b: u64| {
        a.checked_mul(b)
            .ok_or_else(|| invalid("stream supply working RAM overflow"))
    };
    // The empty-name lower bound owns no allocation. Only this object's
    // existing keys are visited; the getter never constructs a named key.
    let lower = || StreamKey {
        object_index: index,
        name_utf16: Vec::new(),
    };
    let file = tree
        .files
        .range(lower()..)
        .take_while(|(key, _)| key.object_index == index)
        .find(|(key, _)| key.name_utf16.as_slice() == name);
    let sparse = tree
        .sparse_targets
        .range(lower()..)
        .take_while(|(key, _)| key.object_index == index)
        .find(|(key, _)| key.name_utf16.as_slice() == name);
    let key = file
        .map(|(key, _)| key)
        .or_else(|| sparse.map(|(key, _)| key))
        .ok_or_else(|| invalid("private supply stream absent"))?;
    let references = tree.original_coordinates.get(key).map_or(0, Vec::len);
    let path = file
        .map(|(_, file)| file.path.len())
        .or_else(|| sparse.map(|(_, target)| target.path.len()))
        .unwrap_or(0);
    // check_placements uses the existing intrinsic retrieval capture and a
    // second parsed PreparedMapping. This is the same conservative query
    // multiplier used by the native constructor, independent of source row
    // size. Coordinate cloning and stable-sort scratch can coexist with it.
    let mut bytes = mul(crate::retrieval_paging::MAX_RETURNED_BYTES as u64, 32)?;
    bytes = add(bytes, 4 * 1024 * 1024)?;
    bytes = add(bytes, mul(path as u64 + 4096, 16)?)?;
    bytes = add(bytes, mul(name.len() as u64, 32)?)?;
    bytes = add(
        bytes,
        mul(
            references as u64,
            2 * std::mem::size_of::<(u64, u64, u64)>() as u64,
        )?,
    )?;
    if let Some((_, target)) = sparse {
        // Sparse translation may build an island vector. Preserve the old
        // complete-row allowance as well as paying for its actual islands;
        // sparse forms do not inherit the cheaper ordinary-stream estimate.
        let row = tree
            .metadata_resource_admission
            .ok_or_else(|| invalid("resource supply working admission absent"))?
            .budget
            .max_row_bytes;
        bytes = bytes.max(mul(row, 8)?);
        bytes = add(
            bytes,
            mul(
                (target.islands.len() as u64).max(4),
                2 * std::mem::size_of::<sparse_stream::Island>() as u64,
            )?,
        )?;
    }
    Ok(bytes)
}

fn visit_data(
    tree: &PrivateTree,
    key: &StreamKey,
    mut visit: impl FnMut(SupplyRange) -> io::Result<()>,
) -> io::Result<u64> {
    visit_data_inner(tree,key,true,&mut visit)
}
fn visit_data_inner(
    tree:&PrivateTree,key:&StreamKey,check_mapping:bool,
    mut visit:impl FnMut(SupplyRange)->io::Result<()>,
)->io::Result<u64>{
    let Some(file) = tree.files.get(key) else {
        if let Some(target) = tree.sparse_targets.get(key) {
            if target.dense_length == 0 {
                return Ok(target.logical_length);
            }
        }
        return Err(invalid("private supply stream absent"));
    };
    if check_mapping {file.check_placements()?;}
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
            visit_parts(tree, key, cursor, logical - cursor, None, &mut visit)?;
        }
        visit_parts(tree, key, logical, bytes, Some(physical), &mut visit)?;
        cursor = end;
    }
    if cursor < length || length == 0 {
        visit_parts(tree, key, cursor, length - cursor, None, &mut visit)?;
    }
    Ok(tree
        .sparse_targets
        .get(key)
        .map_or(length, |t| t.logical_length))
}

fn visit_parts(
    tree: &PrivateTree,
    key: &StreamKey,
    offset: u64,
    length: u64,
    physical: Option<u64>,
    visit: &mut impl FnMut(SupplyRange) -> io::Result<()>,
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
        let source_physical_offset = if let Some(p) = physical {
            Some(
                p.checked_add(
                    part.dense
                        .checked_sub(offset)
                        .ok_or_else(|| invalid("sparse supply source precedes range"))?,
                )
                .ok_or_else(|| invalid("sparse supply physical range overflow"))?,
            )
        } else {
            None
        };
        visit(SupplyRange {
            object_index: key.object_index,
            stream_name_utf16: key.name_utf16.clone(),
            logical_offset: part.logical,
            length: n,
            source_physical_offset,
        })?;
    }
    Ok(())
}

pub(super) fn stream(
    tree: &PrivateTree,
    key: &StreamKey,
    mut emit: impl FnMut(SupplyKind, &SupplyRange) -> io::Result<()>,
) -> io::Result<StreamSupplySummary> {
    tree.require_source_excluded()?;
    let result=stream_inner(tree,key,true,&mut emit);
    let closing=tree.require_source_excluded();
    super::supply_snapshot::close_result(result,closing,"stream supply source closing fence")
}
/// The token is issued only after the batch's actual entry fence and native
/// same-file map capture; it cannot be constructed from a report or flags.
pub(super) fn stream_in_snapshot(
    snapshot:&super::supply_snapshot::NativeReadOnlySupplyStreamSnapshot<'_>,
    emit:impl FnMut(SupplyKind,&SupplyRange)->io::Result<()>,
)->io::Result<StreamSupplySummary>{
    stream_inner(snapshot.tree(),snapshot.key(),false,emit)
}
fn stream_inner(
    tree:&PrivateTree,key:&StreamKey,check_mapping:bool,
    mut emit:impl FnMut(SupplyKind,&SupplyRange)->io::Result<()>,
)->io::Result<StreamSupplySummary>{
    if !tree.placement_complete {
        return Err(invalid(
            "complete live placement required for stream supply",
        ));
    }
    if let Some(admission) = tree.metadata_resource_admission {
        let references = tree.original_coordinates.get(key).map_or(0, Vec::len);
        let bytes = (references as u64)
            .checked_mul(std::mem::size_of::<(u64, u64, u64)>() as u64)
            .ok_or_else(|| invalid("stream reference working RAM overflow"))?;
        if bytes > admission.budget.max_row_bytes.saturating_mul(8) {
            return Err(invalid("stream reference map exceeds resource working row"));
        }
    }
    let logical_bytes = tree
        .sparse_targets
        .get(key)
        .map(|t| t.logical_length)
        .or_else(|| tree.files.get(key).map(|f| f.logical_length()))
        .ok_or_else(|| invalid("private supply stream absent"))?;
    let holes = tree
        .sparse_targets
        .get(key)
        .map(|t| t.layout.holes.as_slice())
        .unwrap_or(&[]);
    let mut next_hole = 0usize;
    let mut summary = StreamSupplySummary {
        logical_bytes,
        materialize_bytes: 0,
        source_reference_bytes: 0,
        hole_bytes: 0,
        ranges: 0,
        ordered_range_sha256: String::new(),
    };
    let mut hash = Sha256::new();
    hash.update(b"n2r-private-stream-supply-v1\0");
    hash.update((key.object_index as u64).to_le_bytes());
    hash.update((key.name_utf16.len() as u64).to_le_bytes());
    for unit in &key.name_utf16 {
        hash.update(unit.to_le_bytes());
    }
    hash.update(logical_bytes.to_le_bytes());
    let mut cursor = 0u64;
    let mut output = |kind: SupplyKind, range: &SupplyRange| -> io::Result<()> {
        if range.logical_offset != cursor {
            return Err(invalid("stream supply has a logical gap or overlap"));
        }
        cursor = cursor
            .checked_add(range.length)
            .ok_or_else(|| invalid("stream supply coverage overflow"))?;
        if cursor > logical_bytes {
            return Err(invalid("stream supply escapes logical EOF"));
        }
        let total = match kind {
            SupplyKind::Materialize => &mut summary.materialize_bytes,
            SupplyKind::SourceReference => &mut summary.source_reference_bytes,
            SupplyKind::Hole => &mut summary.hole_bytes,
        };
        *total = total
            .checked_add(range.length)
            .ok_or_else(|| invalid("stream supply total overflow"))?;
        summary.ranges = summary
            .ranges
            .checked_add(1)
            .ok_or_else(|| invalid("stream range count overflow"))?;
        hash.update([match kind {
            SupplyKind::Materialize => 0,
            SupplyKind::SourceReference => 1,
            SupplyKind::Hole => 2,
        }]);
        hash.update(range.logical_offset.to_le_bytes());
        hash.update(range.length.to_le_bytes());
        hash.update([u8::from(range.source_physical_offset.is_some())]);
        hash.update(range.source_physical_offset.unwrap_or(0).to_le_bytes());
        emit(kind, range)
    };
    let observed_length = visit_data_inner(tree, key, check_mapping, |range| {
        while next_hole < holes.len() && holes[next_hole].offset < range.logical_offset {
            let hole = &holes[next_hole];
            output(
                SupplyKind::Hole,
                &SupplyRange {
                    object_index: key.object_index,
                    stream_name_utf16: key.name_utf16.clone(),
                    logical_offset: hole.offset,
                    length: hole.length,
                    source_physical_offset: None,
                },
            )?;
            next_hole += 1;
        }
        output(
            if range.source_physical_offset.is_some() {
                SupplyKind::SourceReference
            } else {
                SupplyKind::Materialize
            },
            &range,
        )
    })?;
    while next_hole < holes.len() {
        let hole = &holes[next_hole];
        output(
            SupplyKind::Hole,
            &SupplyRange {
                object_index: key.object_index,
                stream_name_utf16: key.name_utf16.clone(),
                logical_offset: hole.offset,
                length: hole.length,
                source_physical_offset: None,
            },
        )?;
        next_hole += 1;
    }
    drop(output);
    if observed_length != logical_bytes || cursor != logical_bytes {
        return Err(invalid(
            "stream supply does not cover complete logical stream",
        ));
    }
    summary.ordered_range_sha256 = hex::encode(hash.finalize());
    Ok(summary)
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
    for key in tree.files.keys() {
        let logical = visit_data(tree, key, |range| {
            if range.source_physical_offset.is_some() {
                result.source_reference_bytes += range.length;
                result.source_reference.push(range);
            } else {
                result.materialize_bytes += range.length;
                result.materialize.push(range);
            }
            Ok(())
        })?;
        result.logical_bytes = result
            .logical_bytes
            .checked_add(logical)
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
