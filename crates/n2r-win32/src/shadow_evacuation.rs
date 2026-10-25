//! Research-only shadow-user-data evacuation planning. Never moves metadata,
//! mutates the NTFS source, or grants authority to execute the returned plan.
use crate::bitmap_layout;
use serde::Serialize;
use std::{collections::BTreeMap, io};

const CLUSTER: u64 = 4096;
pub const MAX_EXTENTS: usize = 1024;
pub const MAX_MOVES: usize = 1024;
pub const MAX_SCAN_CLUSTERS: u64 = 16 * 1024 * 1024;
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
pub struct Limits {
    pub max_moves: usize,
    pub max_scan_clusters: u64,
    pub max_evacuation_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_moves: MAX_MOVES,
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
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validated_extents(extents: &[Extent], partition: u64) -> io::Result<Vec<Extent>> {
    if extents.len() > MAX_EXTENTS {
        return Err(invalid("evacuation extent budget exceeded"));
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
            || u32::try_from(extent.length / CLUSTER).is_err()
        {
            return Err(invalid("evacuation extent geometry exceeds profile"));
        }
        logical
            .entry(extent.file_index)
            .or_default()
            .push((extent.logical_offset, logical_end));
    }
    physical.sort_by_key(|extent| extent.physical_offset);
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
        || !(1..=MAX_MOVES).contains(&limits.max_moves)
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
    })
}
