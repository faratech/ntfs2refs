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
    /// Supplied from the run's plain copy store (`crate::plain_copy`): the
    /// bytes a program read through Windows' filters on the frozen source,
    /// for an object converted to a plain file. Nothing is supplied so yet:
    /// no range of this kind is derived, and every consumer refuses one.
    PlainCopy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StreamSupplySummary {
    pub logical_bytes: u64,
    pub materialize_bytes: u64,
    pub source_reference_bytes: u64,
    pub hole_bytes: u64,
    #[serde(skip_serializing_if = "zero")]
    pub plain_copy_bytes: u64,
    pub ranges: u64,
    pub ordered_range_sha256: String,
}

/// No native query, path construction, owned key, or map clone precedes this
/// estimate. A caller can therefore pay before the first summary observation.
pub(super) fn workspace_bytes(tree: &PrivateTree, index: usize, name: &[u16]) -> io::Result<u64> {
    workspace_bytes_with(tree, index, name, |_| {
        crate::retrieval_paging::max_returned_bytes()
    })
}
/// [`workspace_bytes`] for a stream that a batch pays for before a helper
/// thread observes it. A batch holds one of these for every stream it
/// takes, as memory the pass can do without, so it is as long as that
/// memory reaches: the term for the mapping follows the file's own length
/// here (a file has no more extents than clusters;
/// [`crate::retrieval_paging::returned_bytes_for_stream`]), where the
/// estimate above takes the longest mapping any file may have, 67 MB at the
/// least, for a file of one cluster too. The comparison of the mapping
/// itself is paid for apart, as it is today
/// ([`unwritten::PrivatePlaceholder::mapping_workspace_bytes`]).
pub(super) fn batch_workspace_bytes(
    tree: &PrivateTree,
    index: usize,
    name: &[u16],
) -> io::Result<u64> {
    workspace_bytes_with(
        tree,
        index,
        name,
        crate::retrieval_paging::returned_bytes_for_stream,
    )
}
fn workspace_bytes_with(
    tree: &PrivateTree,
    index: usize,
    name: &[u16],
    mapping_bytes: impl Fn(u64) -> usize,
) -> io::Result<u64> {
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
    let mapped = file.map_or(0, |(_, file)| file.logical_length());
    let mut bytes = mul(mapping_bytes(mapped) as u64, 32)?;
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

/// How the comparison of a file's complete mapping with its tracked pieces
/// is made where a stream's ranges are derived.
pub(super) enum MappingCheck {
    /// Here, by asking Windows for the mapping.
    Live,
    /// Not here: the caller's own capture of the same file's mapping
    /// encloses the derivation (a read-only snapshot), or nothing of the
    /// derivation leaves the caller unless such a capture holds (a batch
    /// deciding which prefixes its helpers observe).
    Held,
    /// A helper thread of a batch made it; this is what it returned.
    Seen(io::Result<()>),
}

fn visit_data(
    tree: &PrivateTree,
    key: &StreamKey,
    mut visit: impl FnMut(SupplyRange) -> io::Result<()>,
) -> io::Result<u64> {
    visit_data_inner(tree, key, MappingCheck::Live, &mut visit)
}
fn visit_data_inner(
    tree: &PrivateTree,
    key: &StreamKey,
    mapping: MappingCheck,
    mut visit: impl FnMut(SupplyRange) -> io::Result<()>,
) -> io::Result<u64> {
    let Some(file) = tree.files.get(key) else {
        if let Some(target) = tree.sparse_targets.get(key) {
            if target.dense_length == 0 {
                return Ok(target.logical_length);
            }
        }
        return Err(invalid("private supply stream absent"));
    };
    match mapping {
        MappingCheck::Live => file.check_placements()?,
        MappingCheck::Held => {}
        MappingCheck::Seen(seen) => seen?,
    }
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
            || !crate::target_cluster::aligned(logical)
            || !crate::target_cluster::aligned(physical)
            || !crate::target_cluster::aligned(bytes)
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

/// One stream's ranges between two source fences. `seen` is the comparison
/// of the file's mapping as a helper thread of a batch made it; `None` makes
/// it here.
pub(super) fn stream(
    tree: &PrivateTree,
    key: &StreamKey,
    seen: Option<io::Result<()>>,
    mut emit: impl FnMut(SupplyKind, &SupplyRange) -> io::Result<()>,
) -> io::Result<StreamSupplySummary> {
    tree.require_source_excluded()?;
    let mapping = seen.map_or(MappingCheck::Live, MappingCheck::Seen);
    let result = stream_inner(tree, key, mapping, &mut emit);
    let closing = tree.require_source_excluded();
    super::supply_snapshot::close_result(result, closing, "stream supply source closing fence")
}
/// The token is issued only after the batch's actual entry fence and native
/// same-file map capture; it cannot be constructed from a report or flags.
pub(super) fn stream_in_snapshot(
    snapshot: &super::supply_snapshot::NativeReadOnlySupplyStreamSnapshot<'_>,
    emit: impl FnMut(SupplyKind, &SupplyRange) -> io::Result<()>,
) -> io::Result<StreamSupplySummary> {
    stream_inner(snapshot.tree(), snapshot.key(), MappingCheck::Held, emit)
}
/// A stream's ranges from this process's own records alone, for a batch
/// that has to know them before its helpers observe anything: whether a
/// prefix is observed follows from them. They decide only that. What the
/// pass uses is derived again inside the stream's snapshot, whose capture
/// and revalidation of the file's mapping the batch's helper makes.
pub(super) fn stream_before_observation(
    tree: &PrivateTree,
    key: &StreamKey,
    emit: impl FnMut(SupplyKind, &SupplyRange) -> io::Result<()>,
) -> io::Result<StreamSupplySummary> {
    stream_inner(tree, key, MappingCheck::Held, emit)
}
fn stream_inner(
    tree: &PrivateTree,
    key: &StreamKey,
    mapping: MappingCheck,
    mut emit: impl FnMut(SupplyKind, &SupplyRange) -> io::Result<()>,
) -> io::Result<StreamSupplySummary> {
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
        plain_copy_bytes: 0,
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
            SupplyKind::PlainCopy => &mut summary.plain_copy_bytes,
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
            SupplyKind::PlainCopy => 3,
        }]);
        hash.update(range.logical_offset.to_le_bytes());
        hash.update(range.length.to_le_bytes());
        hash.update([u8::from(range.source_physical_offset.is_some())]);
        hash.update(range.source_physical_offset.unwrap_or(0).to_le_bytes());
        emit(kind, range)
    };
    let observed_length = visit_data_inner(tree, key, mapping, |range| {
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
