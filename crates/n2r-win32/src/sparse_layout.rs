//! Logical sparse allocation and VDL, independent of filesystem block addresses.
//! This is checked metadata, not device ownership or permission to write.
use serde::{Deserialize, Serialize};
use std::io;

/// Allocated ranges are whole clusters of the target volume.
pub fn cluster_bytes() -> u64 {
    crate::target_cluster::bytes()
}
/// The range count of the older fixed profiles; the resource profile sizes
/// its own from its budget, and a layout itself is bounded by its stream.
pub const MAX_LAYOUT_RANGES: usize = crate::stream_layout::MAX_COMPLETE_EXTENTS;

/// The most allocated ranges (or holes) a stream that rounds to `rounded`
/// bytes can have: they alternate, and each is at least one target cluster.
fn maximum_ranges(rounded: u64) -> u64 {
    rounded / cluster_bytes() / 2 + 1
}

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
    let cluster = cluster_bytes();
    length
        .checked_add(cluster - 1)
        .map(|n| n / cluster * cluster)
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
        if initialized_length > logical_length {
            return Err(invalid(&format!(
                "sparse initialized length {initialized_length} exceeds the stream's {logical_length} bytes"
            )));
        }
        // No fixed number of islands: a stream cannot have more separate
        // ranges than it has clusters, and whoever holds the layout pays for
        // it from its own budget.
        if allocated.len() as u64 > maximum_ranges(rounded) {
            return Err(invalid(&format!(
                "sparse stream of {logical_length} bytes cannot have {} allocated ranges",
                allocated.len()
            )));
        }
        allocated.sort_unstable_by_key(|range| range.offset);
        let mut normalized: Vec<LogicalRange> = Vec::with_capacity(allocated.len());
        let cluster = cluster_bytes();
        for range in allocated {
            if range.length == 0
                || !range.offset.is_multiple_of(cluster)
                || !range.length.is_multiple_of(cluster)
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
                .is_none_or(|count| count as u64 > maximum_ranges(rounded).saturating_mul(2))
        {
            return Err(invalid(&format!(
                "sparse VDL {} or range count {} + {} exceeds what a stream of {logical_length} bytes can have",
                self.initialized_length,
                self.allocated.len(),
                self.holes.len()
            )));
        }
        let mut previous_end = 0u64;
        let cluster = cluster_bytes();
        for range in &self.allocated {
            let range_end = end(range)?;
            if range.length == 0
                || !range.offset.is_multiple_of(cluster)
                || !range.length.is_multiple_of(cluster)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn range(offset: u64, length: u64) -> LogicalRange {
        LogicalRange { offset, length }
    }

    #[test]
    fn allocated_ranges_are_whole_clusters_of_the_target_unit() {
        let islands = || vec![range(4096, 8192)];
        let layout = SparseLayout::from_allocated(70_000, 70_000, islands()).unwrap();
        assert_eq!(layout.holes, [range(0, 4096), range(12_288, 57_712)]);
        crate::target_cluster::with(65536, || {
            // An island on 4 KiB boundaries is not on 64 KiB ones.
            assert!(SparseLayout::from_allocated(70_000, 70_000, islands()).is_err());
            assert!(layout.validate(70_000).is_err());
            let layout =
                SparseLayout::from_allocated(70_000, 70_000, vec![range(65_536, 65_536)]).unwrap();
            assert_eq!(layout.holes, [range(0, 65_536)]);
            assert_eq!(layout.allocated_bytes().unwrap(), 65_536);
            // The end of file rounds up to 131,072 bytes and no further.
            assert!(
                SparseLayout::from_allocated(70_000, 70_000, vec![range(131_072, 65_536)]).is_err()
            );
        });
        assert!(layout.validate(70_000).is_ok());
    }

    /// A sparse file with more islands than the 65,536 that used to be the
    /// most: as many ranges as the stream has room for, and no more.
    #[test]
    fn a_layout_may_have_as_many_islands_as_its_stream_has_clusters_for() {
        let islands = 70_000u64;
        // One 4 KiB island in every second cluster.
        let length = islands * 8192;
        let allocated: Vec<_> = (0..islands).map(|i| range(i * 8192, 4096)).collect();
        let layout = SparseLayout::from_allocated(length, length, allocated).unwrap();
        assert_eq!(layout.allocated.len(), 70_000);
        assert_eq!(layout.holes.len(), 70_000);
        layout.validate(length).unwrap();
        // The same islands cannot belong to a stream too short to hold them.
        assert!(layout.validate(length / 2).is_err());
        let mut impossible = layout.clone();
        impossible
            .holes
            .extend(std::iter::repeat_n(range(0, 4096), 140_010));
        assert!(impossible.validate(length).is_err());
    }
}
