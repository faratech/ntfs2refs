//! Logical sparse allocation and VDL, independent of filesystem block addresses.
//! This is checked metadata, not device ownership or permission to write.
use serde::{Deserialize, Serialize};
use std::io;

pub const CLUSTER_BYTES: u64 = 4096;
pub const MAX_LAYOUT_RANGES: usize = crate::stream_layout::MAX_COMPLETE_EXTENTS;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SparseLayout {
    pub initialized_length: u64,
    /// Whole allocated clusters, including an allocated partial EOF cluster.
    pub allocated: Vec<LogicalRange>,
    /// Exact logical complement of `allocated`, clipped to logical EOF.
    pub holes: Vec<LogicalRange>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn rounded_length(length: u64) -> io::Result<u64> {
    if length > i64::MAX as u64 {
        return Err(invalid(
            "sparse logical length exceeds native signed bounds",
        ));
    }
    length
        .checked_add(CLUSTER_BYTES - 1)
        .map(|n| n / CLUSTER_BYTES * CLUSTER_BYTES)
        .ok_or_else(|| invalid("sparse logical rounding overflow"))
}
fn end(range: &LogicalRange) -> io::Result<u64> {
    range
        .offset
        .checked_add(range.length)
        .ok_or_else(|| invalid("sparse range overflow"))
}
fn complement(allocated: &[LogicalRange], length: u64) -> io::Result<Vec<LogicalRange>> {
    let mut holes = Vec::new();
    let mut cursor = 0u64;
    for range in allocated {
        let start = range.offset.min(length);
        if cursor < start {
            holes.push(LogicalRange {
                offset: cursor,
                length: start - cursor,
            });
        }
        cursor = cursor.max(end(range)?.min(length));
    }
    if cursor < length {
        holes.push(LogicalRange {
            offset: cursor,
            length: length - cursor,
        });
    }
    Ok(holes)
}

impl SparseLayout {
    /// Normalize ordered or unordered allocated islands by joining adjacency.
    /// Overlaps remain errors. Generated holes describe logical bytes only.
    pub fn from_allocated(
        logical_length: u64,
        initialized_length: u64,
        mut allocated: Vec<LogicalRange>,
    ) -> io::Result<Self> {
        let rounded = rounded_length(logical_length)?;
        if allocated.len() > MAX_LAYOUT_RANGES || initialized_length > logical_length {
            return Err(invalid("sparse range count or initialized length differs"));
        }
        allocated.sort_unstable_by_key(|range| range.offset);
        let mut normalized: Vec<LogicalRange> = Vec::with_capacity(allocated.len());
        for range in allocated {
            if range.length == 0
                || !range.offset.is_multiple_of(CLUSTER_BYTES)
                || !range.length.is_multiple_of(CLUSTER_BYTES)
                || end(&range)? > rounded
            {
                return Err(invalid(
                    "sparse allocation is unaligned or outside rounded EOF",
                ));
            }
            if let Some(previous) = normalized.last_mut() {
                let previous_end = end(previous)?;
                if range.offset < previous_end {
                    return Err(invalid("sparse allocated ranges overlap"));
                }
                if range.offset == previous_end {
                    previous.length = previous
                        .length
                        .checked_add(range.length)
                        .ok_or_else(|| invalid("sparse coalescing overflow"))?;
                    continue;
                }
            }
            normalized.push(range);
        }
        let holes = complement(&normalized, logical_length)?;
        let result = Self {
            initialized_length,
            allocated: normalized,
            holes,
        };
        result.validate(logical_length)?;
        Ok(result)
    }

    pub fn validate(&self, logical_length: u64) -> io::Result<()> {
        let rounded = rounded_length(logical_length)?;
        if self.initialized_length > logical_length
            || self
                .allocated
                .len()
                .checked_add(self.holes.len())
                .is_none_or(|count| count > MAX_LAYOUT_RANGES)
        {
            return Err(invalid("sparse VDL or combined range count exceeds bounds"));
        }
        let mut previous_end = 0u64;
        for range in &self.allocated {
            let range_end = end(range)?;
            if range.length == 0
                || !range.offset.is_multiple_of(CLUSTER_BYTES)
                || !range.length.is_multiple_of(CLUSTER_BYTES)
                || range.offset < previous_end
                || range_end > rounded
            {
                return Err(invalid(
                    "sparse allocation overlaps, is unaligned or exceeds rounded EOF",
                ));
            }
            previous_end = range_end;
        }
        if self.holes != complement(&self.allocated, logical_length)? {
            return Err(invalid(
                "sparse holes are not the exact logical allocation complement",
            ));
        }
        Ok(())
    }

    pub fn allocated_bytes(&self) -> io::Result<u64> {
        self.allocated.iter().try_fold(0u64, |sum, range| {
            sum.checked_add(range.length)
                .ok_or_else(|| invalid("sparse allocated byte count overflow"))
        })
    }
    pub fn hole_bytes(&self) -> io::Result<u64> {
        self.holes.iter().try_fold(0u64, |sum, range| {
            sum.checked_add(range.length)
                .ok_or_else(|| invalid("sparse hole byte count overflow"))
        })
    }
}
