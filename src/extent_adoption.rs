//! Byte-based NTFS stream classification for a future direct ReFS extent
//! writer. This is a deterministic planner, never authority to write a volume.
use crate::ntfs_inspect::{LogicalHashStatus, StreamInventory};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Adopt,
    Relocate,
    Materialize,
    Hole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Segment {
    pub logical_offset: u64,
    pub logical_length: u64,
    pub source_physical_offset: Option<u64>,
    /// Physical ownership required by an adopted ReFS extent. Zero for
    /// rewrites and sparse holes whose destination is chosen later.
    pub adopted_physical_length: u64,
    pub action: Action,
}

#[derive(Clone, Debug, Serialize)]
pub struct StreamPlan {
    pub profile: &'static str,
    pub logical_size: u64,
    pub logical_sha256: String,
    pub segments: Vec<Segment>,
    pub adopted_logical_bytes: u64,
    pub relocated_logical_bytes: u64,
    pub materialized_logical_bytes: u64,
    pub sparse_logical_bytes: u64,
    pub executable: bool,
}

fn rounded(value: u64, cluster: u64) -> Option<u64> {
    value
        .checked_add(cluster - 1)
        .map(|end| end / cluster * cluster)
}

pub fn plan_stream(
    stream: &StreamInventory,
    source_cluster: u32,
    refs_cluster: u32,
    volume_bytes: u64,
    target_occupied: &[PhysicalRange],
) -> Result<StreamPlan> {
    let source = u64::from(source_cluster);
    let target = u64::from(refs_cluster);
    ensure!(
        source.is_power_of_two()
            && target.is_power_of_two()
            && (512..=2 * 1024 * 1024).contains(&source)
            && matches!(target, 4096 | 65536)
            && volume_bytes >= target
            && volume_bytes.is_multiple_of(target),
        "unsupported source/target geometry"
    );
    ensure!(
        stream.flags == 0
            && stream.name_utf16.is_empty()
            && stream.logical_hash_status == LogicalHashStatus::Complete
            && stream.initialized_size <= stream.logical_size
            && stream.logical_size <= volume_bytes,
        "unsupported named, encoded, unverified or oversized stream"
    );
    let digest = stream
        .logical_sha256
        .as_deref()
        .context("complete logical stream lacks digest")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid logical stream digest"
    );
    let mut last = 0u64;
    for range in target_occupied {
        let end = range
            .offset
            .checked_add(range.length)
            .context("target range overflow")?;
        ensure!(
            range.length > 0
                && range.offset >= last
                && range.offset.is_multiple_of(target)
                && range.length.is_multiple_of(target)
                && end <= volume_bytes,
            "target occupied ranges overlap, are unaligned or exceed volume"
        );
        last = end;
    }
    let mut result = StreamPlan {
        profile: "refs-direct-adoption-candidate-v1",
        logical_size: stream.logical_size,
        logical_sha256: digest.into(),
        segments: Vec::new(),
        adopted_logical_bytes: 0,
        relocated_logical_bytes: 0,
        materialized_logical_bytes: 0,
        sparse_logical_bytes: 0,
        executable: false,
    };
    if stream.logical_size == 0 {
        ensure!(
            stream.extents.is_empty(),
            "empty stream has physical extents"
        );
        return Ok(result);
    }
    if stream.resident {
        ensure!(
            stream.extents.is_empty(),
            "resident stream has physical extents"
        );
        result.segments.push(Segment {
            logical_offset: 0,
            logical_length: stream.logical_size,
            source_physical_offset: None,
            adopted_physical_length: 0,
            action: Action::Materialize,
        });
        result.materialized_logical_bytes = stream.logical_size;
        return Ok(result);
    }
    let mut covered = 0u64;
    for extent in &stream.extents {
        ensure!(
            extent.logical_offset == covered
                && extent.length > 0
                && extent.length.is_multiple_of(source),
            "source extent gap, overlap or partial cluster"
        );
        let next = covered
            .checked_add(extent.length)
            .context("source run overflow")?;
        ensure!(next <= volume_bytes, "source run exceeds bounded volume");
        if covered >= stream.logical_size {
            ensure!(next == covered, "extent after logical EOF");
            break;
        }
        let logical_length = extent.length.min(stream.logical_size - covered);
        let (action, adopted_physical_length) = match extent.physical_offset {
            None => {
                let at_eof = covered + logical_length == stream.logical_size;
                if covered.is_multiple_of(target)
                    && (logical_length.is_multiple_of(target) || at_eof)
                {
                    (Action::Hole, 0)
                } else {
                    (Action::Materialize, 0)
                }
            }
            Some(physical) => {
                let end = physical
                    .checked_add(extent.length)
                    .context("physical run overflow")?;
                ensure!(
                    physical.is_multiple_of(source) && end <= volume_bytes,
                    "source physical run outside volume"
                );
                let needed =
                    rounded(logical_length, target).context("target run rounding overflow")?;
                let aligned = covered.is_multiple_of(target)
                    && physical.is_multiple_of(target)
                    && extent.length >= needed;
                let collision = target_occupied.iter().any(|range| {
                    physical < range.offset + range.length && physical + needed > range.offset
                });
                if stream.initialized_size != stream.logical_size {
                    (Action::Materialize, 0)
                } else if aligned && !collision {
                    (Action::Adopt, needed)
                } else {
                    (Action::Relocate, 0)
                }
            }
        };
        result.segments.push(Segment {
            logical_offset: covered,
            logical_length,
            source_physical_offset: extent.physical_offset,
            adopted_physical_length,
            action,
        });
        match action {
            Action::Adopt => result.adopted_logical_bytes += logical_length,
            Action::Relocate => result.relocated_logical_bytes += logical_length,
            Action::Materialize => result.materialized_logical_bytes += logical_length,
            Action::Hole => result.sparse_logical_bytes += logical_length,
        }
        covered = next;
    }
    ensure!(
        covered >= stream.logical_size,
        "source extents do not cover logical EOF"
    );
    ensure!(
        result.adopted_logical_bytes
            + result.relocated_logical_bytes
            + result.materialized_logical_bytes
            + result.sparse_logical_bytes
            == stream.logical_size,
        "stream disposition coverage differs"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs_inspect::Extent;

    fn stream(size: u64, extents: Vec<Extent>) -> StreamInventory {
        StreamInventory {
            name: String::new(),
            name_utf16: vec![],
            resident: false,
            flags: 0,
            logical_size: size,
            initialized_size: size,
            allocated_size: extents
                .iter()
                .filter(|e| e.physical_offset.is_some())
                .map(|e| e.length)
                .sum(),
            extents,
            resident_sha256: None,
            logical_sha256: Some("a".repeat(64)),
            logical_hash_status: LogicalHashStatus::Complete,
        }
    }

    #[test]
    fn aligned_existing_data_is_adoptable_including_eof_tail() {
        let s = stream(
            4097,
            vec![Extent {
                logical_offset: 0,
                physical_offset: Some(8192),
                length: 8192,
            }],
        );
        let p = plan_stream(&s, 4096, 4096, 65536, &[]).unwrap();
        assert_eq!(p.segments[0].action, Action::Adopt);
        assert_eq!(p.segments[0].logical_length, 4097);
        assert_eq!(p.segments[0].adopted_physical_length, 8192);
    }

    #[test]
    fn metadata_collision_relocates_and_sparse_range_stays_a_hole() {
        let s = stream(
            8192,
            vec![
                Extent {
                    logical_offset: 0,
                    physical_offset: Some(8192),
                    length: 4096,
                },
                Extent {
                    logical_offset: 4096,
                    physical_offset: None,
                    length: 4096,
                },
            ],
        );
        let p = plan_stream(
            &s,
            4096,
            4096,
            65536,
            &[PhysicalRange {
                offset: 8192,
                length: 4096,
            }],
        )
        .unwrap();
        assert_eq!(
            p.segments.iter().map(|x| x.action).collect::<Vec<_>>(),
            [Action::Relocate, Action::Hole]
        );
        assert_eq!(p.relocated_logical_bytes, 4096);
        assert_eq!(p.sparse_logical_bytes, 4096);
    }

    #[test]
    fn smaller_source_clusters_and_uninitialized_tail_cannot_be_adopted() {
        let s = stream(
            1024,
            vec![Extent {
                logical_offset: 0,
                physical_offset: Some(1024),
                length: 1024,
            }],
        );
        assert_eq!(
            plan_stream(&s, 1024, 4096, 65536, &[]).unwrap().segments[0].action,
            Action::Relocate
        );
        let mut s = stream(
            4096,
            vec![Extent {
                logical_offset: 0,
                physical_offset: Some(8192),
                length: 4096,
            }],
        );
        s.initialized_size = 3072;
        assert_eq!(
            plan_stream(&s, 4096, 4096, 65536, &[]).unwrap().segments[0].action,
            Action::Materialize
        );
    }

    #[test]
    fn subcluster_sparse_region_requires_materialization() {
        let s = stream(
            4096,
            vec![
                Extent {
                    logical_offset: 0,
                    physical_offset: None,
                    length: 1024,
                },
                Extent {
                    logical_offset: 1024,
                    physical_offset: Some(8192),
                    length: 3072,
                },
            ],
        );
        let p = plan_stream(&s, 1024, 4096, 65536, &[]).unwrap();
        assert_eq!(p.segments[0].action, Action::Materialize);
        assert_eq!(p.segments[1].action, Action::Relocate);
    }
}
