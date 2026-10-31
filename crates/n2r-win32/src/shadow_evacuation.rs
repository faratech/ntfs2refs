//! Shadow-user-data evacuation planning. Never moves metadata,
//! mutates the NTFS source, or grants authority to execute the returned plan.
use crate::bitmap_layout;
use serde::Serialize;
use std::{collections::BTreeMap, io};

const CLUSTER: u64 = 4096;
/// Ceiling for any one validated extent list. The intersection is a sorted
/// sweep, so this bounds memory (32 B per extent), not a nested product.
pub const MAX_EXTENTS: usize = 65_536;
/// Ceiling for a caller's move budget: the private-tree submission ceiling.
pub const MAX_MOVES: usize = 32_768;
/// The older ConstructRetaining evacuation loop keeps its original budgets.
pub const LEGACY_MAX_EXTENTS: usize = 1024;
pub const LEGACY_MAX_MOVES: usize = 1024;

/// Caller-selected bounds, each checked against the ceilings above.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RangeLimits {
    pub max_source_extents: usize,
    pub max_shadow_extents: usize,
    pub max_blocked: usize,
    pub max_moves: usize,
    /// Bytes at each partition end that are never chosen as a destination.
    pub margin: u64,
}

pub(crate) const LEGACY_LIMITS: RangeLimits = RangeLimits {
    max_source_extents: LEGACY_MAX_EXTENTS,
    max_shadow_extents: LEGACY_MAX_EXTENTS,
    max_blocked: LEGACY_MAX_MOVES,
    max_moves: LEGACY_MAX_MOVES,
    margin: 0,
};
#[cfg(test)]
pub const MAX_SCAN_CLUSTERS: u64 = 16 * 1024 * 1024;
#[cfg(test)]
pub const MAX_EVACUATION_BYTES: u64 = 256 * 1024 * 1024;

/// A caller-identified file's eligible source range or measured shadow extent.
/// The caller must obtain shadow ownership from actual ordinary-file mappings;
/// allocated bitmap bits alone do not identify a cluster's owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Extent {
    pub file_index: u32,
    pub logical_offset: u64,
    pub physical_offset: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug)]
#[cfg(test)]
pub struct Limits {
    pub max_moves: usize,
    pub max_scan_clusters: u64,
    pub max_evacuation_bytes: u64,
}
#[cfg(test)]
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_moves: LEGACY_MAX_MOVES,
            max_scan_clusters: MAX_SCAN_CLUSTERS,
            max_evacuation_bytes: MAX_EVACUATION_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Move {
    pub file_index: u32,
    pub logical_offset: u64,
    pub source_offset: u64,
    pub destination_offset: u64,
    pub length: u64,
    pub starting_vcn: u64,
    pub destination_lcn: u64,
    pub clusters: u32,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub legacy_bitmap_sha256: String,
    pub metadata_bitmap_sha256: String,
    pub evacuated_bytes: u64,
    pub already_in_place_bytes: u64,
    pub scanned_clusters: u64,
    pub moves: Vec<Move>,
    pub remaining_blocked_bytes: u64,
}

/// Interval-based planning for the streaming native path. Complete maps are
/// supplied by live observations; bitmap occupancy alone is never ownership.
/// No volume-sized bitmap or per-cluster scan is assembled here.
pub(crate) fn plan_ranges(
    legacy: &bitmap_layout::AllocationMap,
    metadata: &bitmap_layout::AllocationMap,
    eligible_source: &[Extent],
    shadow: &[Extent],
    partition: u64,
    move_budget: usize,
    limits: RangeLimits,
) -> io::Result<Plan> {
    const MAX_MAP_RANGES: usize = 262_144;
    const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024 * 1024;
    if partition == 0
        || partition > MAX_BYTES
        || !partition.is_multiple_of(CLUSTER)
        || limits.max_source_extents > MAX_EXTENTS
        || limits.max_shadow_extents > MAX_EXTENTS
        || limits.max_blocked > 2 * MAX_EXTENTS
        || limits.max_moves > MAX_MOVES
        || !(1..=limits.max_moves).contains(&move_budget)
        || !limits.margin.is_multiple_of(CLUSTER)
        || limits.margin.checked_mul(2).is_none_or(|m| m >= partition)
    {
        return Err(invalid("streaming evacuation geometry differs"));
    }
    for map in [legacy, metadata] {
        if map.ranges.len() > MAX_MAP_RANGES {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "evacuation interval budget exceeded",
            ));
        }
        if map.cluster_count != partition / CLUSTER
            || map.ranges.len() > MAX_MAP_RANGES
            || map.bitmap_sha256.len() != 64
            || !map
                .bitmap_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(invalid("streaming evacuation map domain or budget differs"));
        }
        let mut end = 0;
        let mut allocated = 0u64;
        for range in &map.ranges {
            let next = range
                .offset
                .checked_add(range.length)
                .filter(|next| *next <= partition)
                .ok_or_else(|| invalid("evacuation allocation escapes partition"))?;
            if range.offset < end
                || range.length == 0
                || !range.offset.is_multiple_of(CLUSTER)
                || !range.length.is_multiple_of(CLUSTER)
            {
                return Err(invalid(
                    "evacuation allocation ordering or alignment differs",
                ));
            }
            allocated += range.length / CLUSTER;
            end = next;
        }
        if allocated != map.allocated_clusters {
            return Err(invalid("evacuation allocation count differs"));
        }
    }
    let source = validated_extents_streamed(eligible_source, partition, limits.max_source_extents)?;
    let owned = validated_extents_streamed(shadow, partition, limits.max_shadow_extents)?;
    let mut blocked = Vec::new();
    let mut already = 0u64;
    // Both lists are physically sorted and internally disjoint, so their ends
    // are sorted too. A source range ending at or before this extent's start
    // cannot meet this or any later extent; the rest are visited in the same
    // order as the former nested loop, so the blocked list is unchanged.
    let mut next_source = 0;
    for extent in &owned {
        for map in [legacy, metadata] {
            let end = extent.physical_offset + extent.length;
            let first = map
                .ranges
                .partition_point(|r| r.offset + r.length <= extent.physical_offset);
            let covered: u64 = map.ranges[first..]
                .iter()
                .take_while(|r| r.offset < end)
                .map(|r| (r.offset + r.length).min(end) - r.offset.max(extent.physical_offset))
                .sum();
            if covered != extent.length {
                return Err(invalid(
                    "measured shadow extent is not allocated in both maps",
                ));
            }
        }
        let extent_end = extent.physical_offset + extent.length;
        while source.get(next_source).is_some_and(|candidate| {
            candidate.physical_offset + candidate.length <= extent.physical_offset
        }) {
            next_source += 1;
        }
        for candidate in source[next_source..]
            .iter()
            .take_while(|candidate| candidate.physical_offset < extent_end)
        {
            let start = extent.physical_offset.max(candidate.physical_offset);
            let end = extent_end.min(candidate.physical_offset + candidate.length);
            if start >= end {
                continue;
            }
            let logical = extent.logical_offset + start - extent.physical_offset;
            let desired = candidate.logical_offset + start - candidate.physical_offset;
            if extent.file_index == candidate.file_index && logical == desired {
                already += end - start;
            } else {
                if blocked.len() == limits.max_blocked {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "evacuation intersection budget exceeded: more than {} blocked intersections",
                            limits.max_blocked
                        ),
                    ));
                }
                blocked.push(Extent {
                    file_index: extent.file_index,
                    logical_offset: logical,
                    physical_offset: start,
                    length: end - start,
                });
            }
        }
    }
    // All three complete inputs are already physically ordered. Merge them
    // with the bootstrap margins directly: the union and first-fit order are
    // identical to sorting their concatenation, without its extra allocation
    // or O(N log N) sort. No occupancy or source-exclusion range is omitted.
    let margins = [(0, limits.margin), (partition - limits.margin, partition)];
    let margins: &[(u64, u64)] = if limits.margin > 0 { &margins } else { &[] };
    let mut indices = [0usize; 4];
    let mut occupied: Vec<(u64, u64)> = Vec::new();
    loop {
        let candidates = [
            legacy
                .ranges
                .get(indices[0])
                .map(|r| (r.offset, r.offset + r.length)),
            metadata
                .ranges
                .get(indices[1])
                .map(|r| (r.offset, r.offset + r.length)),
            source
                .get(indices[2])
                .map(|r| (r.physical_offset, r.physical_offset + r.length)),
            margins.get(indices[3]).copied(),
        ];
        let Some((input, (start, end))) = candidates
            .into_iter()
            .enumerate()
            .filter_map(|(input, range)| range.map(|range| (input, range)))
            .min_by_key(|(_, range)| *range)
        else {
            break;
        };
        indices[input] += 1;
        if let Some(last) = occupied.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            occupied.push((start, end));
        }
    }
    let mut cursor = 0;
    let mut index = 0;
    let mut moves = Vec::new();
    let mut total = 0u64;
    let blocked_bytes: u64 = blocked.iter().map(|extent| extent.length).sum();
    'extents: for extent in blocked {
        let mut done = 0;
        while done < extent.length {
            while index < occupied.len() && occupied[index].0 <= cursor {
                cursor = cursor.max(occupied[index].1);
                index += 1;
            }
            let free_end = occupied.get(index).map_or(partition, |r| r.0);
            if cursor >= partition {
                break 'extents;
            }
            let length = (free_end - cursor)
                .min(extent.length - done)
                .min(u32::MAX as u64 * CLUSTER);
            if length == 0 {
                return Err(invalid("empty evacuation free interval"));
            }
            if moves.len() == move_budget {
                break 'extents;
            }
            moves.push(Move {
                file_index: extent.file_index,
                logical_offset: extent.logical_offset + done,
                source_offset: extent.physical_offset + done,
                destination_offset: cursor,
                length,
                starting_vcn: (extent.logical_offset + done) / CLUSTER,
                destination_lcn: cursor / CLUSTER,
                clusters: (length / CLUSTER) as u32,
            });
            cursor += length;
            done += length;
            total += length;
        }
    }
    Ok(Plan {
        legacy_bitmap_sha256: legacy.bitmap_sha256.clone(),
        metadata_bitmap_sha256: metadata.bitmap_sha256.clone(),
        evacuated_bytes: total,
        already_in_place_bytes: already,
        scanned_clusters: 0,
        moves,
        remaining_blocked_bytes: blocked_bytes - total,
    })
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
fn validated_extents(extents: &[Extent], partition: u64) -> io::Result<Vec<Extent>> {
    if extents
        .iter()
        .any(|extent| u32::try_from(extent.length / CLUSTER).is_err())
    {
        return Err(invalid("legacy evacuation extent exceeds native move size"));
    }
    validated_extents_streamed(extents, partition, LEGACY_MAX_EXTENTS)
}

fn validated_extents_streamed(
    extents: &[Extent],
    partition: u64,
    max_extents: usize,
) -> io::Result<Vec<Extent>> {
    if extents.len() > max_extents {
        return Err(invalid(&format!(
            "evacuation extent budget exceeded: {} extents > {max_extents}",
            extents.len()
        )));
    }
    let mut physical = extents.to_vec();
    let mut logical = BTreeMap::<u32, Vec<(u64, u64)>>::new();
    for extent in extents {
        let logical_end = extent
            .logical_offset
            .checked_add(extent.length)
            .ok_or_else(|| invalid("evacuation logical extent overflow"))?;
        let physical_end = extent
            .physical_offset
            .checked_add(extent.length)
            .ok_or_else(|| invalid("evacuation physical extent overflow"))?;
        if extent.length == 0
            || !extent.length.is_multiple_of(CLUSTER)
            || !extent.logical_offset.is_multiple_of(CLUSTER)
            || !extent.physical_offset.is_multiple_of(CLUSTER)
            || physical_end > partition
            || logical_end > partition
        {
            return Err(invalid("evacuation extent geometry exceeds profile"));
        }
        logical
            .entry(extent.file_index)
            .or_default()
            .push((extent.logical_offset, logical_end));
    }
    // Valid ownership has distinct physical starts. An unstable sort therefore
    // has the same validated output and avoids a stable sort's scratch buffer.
    physical.sort_unstable_by_key(|extent| extent.physical_offset);
    if physical
        .windows(2)
        .any(|pair| pair[0].physical_offset + pair[0].length > pair[1].physical_offset)
    {
        return Err(invalid("evacuation physical ownership overlaps"));
    }
    for ranges in logical.values_mut() {
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(invalid("evacuation logical ownership overlaps"));
        }
    }
    Ok(physical)
}

#[cfg(test)]
struct Allocator<'a> {
    legacy: &'a [u8],
    metadata: &'a [u8],
    excluded: &'a [Extent],
    cursor: u64,
    domain: u64,
    exclusion: usize,
    scanned: u64,
    budget: u64,
}
#[cfg(test)]
impl Allocator<'_> {
    fn next_cluster(&mut self) -> io::Result<Option<(u64, bool)>> {
        if self.cursor == self.domain {
            return Ok(None);
        }
        if self.scanned == self.budget {
            return Err(invalid("evacuation free-space scan budget exceeded"));
        }
        let cluster = self.cursor;
        self.cursor += 1;
        self.scanned += 1;
        while self.exclusion < self.excluded.len()
            && (self.excluded[self.exclusion].physical_offset
                + self.excluded[self.exclusion].length)
                / CLUSTER
                <= cluster
        {
            self.exclusion += 1;
        }
        let excluded = self.exclusion < self.excluded.len()
            && self.excluded[self.exclusion].physical_offset / CLUSTER <= cluster;
        let at = 16 + (cluster / 8) as usize;
        let mask = 1u8 << (cluster % 8);
        Ok(Some((
            cluster,
            !excluded && self.legacy[at] & mask == 0 && self.metadata[at] & mask == 0,
        )))
    }
    fn next_run(&mut self, needed: u64) -> io::Result<Option<(u64, u64)>> {
        while let Some((start, free)) = self.next_cluster()? {
            if !free {
                continue;
            }
            let mut count = 1;
            while count < needed {
                match self.next_cluster()? {
                    Some((_, true)) => count += 1,
                    _ => break,
                }
            }
            return Ok(Some((start, count)));
        }
        Ok(None)
    }
}

/// Plan moves only for measured shadow user data obstructing eligible source
/// destinations. Destinations are first-fit, free in both complete native maps,
/// and outside every eligible source range. Already-correct same-file/VCN
/// placement is left untouched. An error returns no partial relocation plan.
#[cfg(test)]
pub fn plan(
    legacy: &[u8],
    metadata: &[u8],
    eligible_source: &[Extent],
    shadow: &[Extent],
    partition: u64,
    limits: Limits,
) -> io::Result<Plan> {
    if partition == 0
        || !partition.is_multiple_of(CLUSTER)
        || !(1..=LEGACY_MAX_MOVES).contains(&limits.max_moves)
        || !(1..=MAX_SCAN_CLUSTERS).contains(&limits.max_scan_clusters)
        || !(1..=MAX_EVACUATION_BYTES).contains(&limits.max_evacuation_bytes)
    {
        return Err(invalid("evacuation geometry or resource budget differs"));
    }
    let legacy_header = bitmap_layout::candidate(legacy, 0, CLUSTER, partition)?;
    let metadata_header = bitmap_layout::candidate(metadata, 0, CLUSTER, partition)?;
    let domain = partition / CLUSTER;
    if legacy_header.declared_clusters != domain || metadata_header.declared_clusters != domain {
        return Err(invalid(
            "evacuation bitmaps do not cover the same complete partition domain",
        ));
    }
    let source = validated_extents(eligible_source, partition)?;
    let owned = validated_extents(shadow, partition)?;
    let mut blocked = Vec::new();
    let mut already_in_place_bytes = 0u64;
    for extent in &owned {
        for cluster in
            extent.physical_offset / CLUSTER..(extent.physical_offset + extent.length) / CLUSTER
        {
            let at = 16 + (cluster / 8) as usize;
            let mask = 1u8 << (cluster % 8);
            if legacy[at] & mask == 0 || metadata[at] & mask == 0 {
                return Err(invalid("shadow user extent is not allocated in both views"));
            }
        }
        for candidate in &source {
            let begin = extent.physical_offset.max(candidate.physical_offset);
            let end = (extent.physical_offset + extent.length)
                .min(candidate.physical_offset + candidate.length);
            if begin >= end {
                continue;
            }
            let logical = extent.logical_offset + (begin - extent.physical_offset);
            let desired = candidate.logical_offset + (begin - candidate.physical_offset);
            if extent.file_index == candidate.file_index && logical == desired {
                already_in_place_bytes += end - begin;
            } else {
                blocked.push(Extent {
                    file_index: extent.file_index,
                    logical_offset: logical,
                    physical_offset: begin,
                    length: end - begin,
                });
            }
        }
    }
    blocked.sort_by_key(|extent| (extent.file_index, extent.logical_offset));
    let total = blocked.iter().try_fold(0u64, |total, extent| {
        total
            .checked_add(extent.length)
            .ok_or_else(|| invalid("evacuation byte count overflow"))
    })?;
    if total > limits.max_evacuation_bytes {
        return Err(invalid("evacuation byte budget exceeded"));
    }
    let mut allocator = Allocator {
        legacy,
        metadata,
        excluded: &source,
        cursor: 0,
        domain,
        exclusion: 0,
        scanned: 0,
        budget: limits.max_scan_clusters,
    };
    let mut moves = Vec::new();
    for extent in blocked {
        let mut completed = 0u64;
        while completed < extent.length {
            if moves.len() == limits.max_moves {
                return Err(invalid("evacuation move budget exceeded"));
            }
            let (destination, count) = allocator
                .next_run((extent.length - completed) / CLUSTER)?
                .ok_or_else(|| {
                invalid("insufficient free space outside all source candidates")
            })?;
            let logical_offset = extent.logical_offset + completed;
            let length = count * CLUSTER;
            moves.push(Move {
                file_index: extent.file_index,
                logical_offset,
                source_offset: extent.physical_offset + completed,
                destination_offset: destination * CLUSTER,
                length,
                starting_vcn: logical_offset / CLUSTER,
                destination_lcn: destination,
                clusters: u32::try_from(count)
                    .map_err(|_| invalid("evacuation move exceeds u32 cluster count"))?,
            });
            completed += length;
        }
    }
    Ok(Plan {
        legacy_bitmap_sha256: legacy_header.bitmap_sha256,
        metadata_bitmap_sha256: metadata_header.bitmap_sha256,
        evacuated_bytes: total,
        already_in_place_bytes,
        scanned_clusters: allocator.scanned,
        moves,
        remaining_blocked_bytes: 0,
    })
}
