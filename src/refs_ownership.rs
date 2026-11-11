//! Bounded interval reconciliation of independently obtained ReFS allocation
//! and required-range observations. This module reads no volume bytes and
//! cannot authenticate inputs or authorize selective capture or raw writes.
use crate::refs_write_set::ByteRange;
use anyhow::{Context, Result, ensure};
use serde::Serialize;

const CLUSTER: u64 = 4096;
const MAX_INPUT_RANGES: usize = 262_144;

#[derive(Debug, Serialize)]
pub struct OwnershipReconciliation {
    pub partition_bytes: u64,
    pub native_allocated_bytes: u64,
    pub raw_union_allocated_bytes: u64,
    pub observed_required_bytes: u64,
    pub required_not_native_bytes: u64,
    pub required_not_raw_union_bytes: u64,
    pub native_not_raw_union_bytes: u64,
    pub raw_union_not_native_bytes: u64,
    pub required_not_native: Vec<ByteRange>,
    pub required_not_raw_union: Vec<ByteRange>,
    pub native_not_raw_union: Vec<ByteRange>,
    pub raw_union_not_native: Vec<ByteRange>,
    pub conservative_required_union: Vec<ByteRange>,
    pub conservative_required_union_bytes: u64,
    pub input_authentication_verified: bool,
    pub complete_graph_verified: bool,
    pub complement_safe_to_preserve: bool,
    pub source_admitted: bool,
    pub raw_write_authority: bool,
}

fn validate_ranges(ranges: &[ByteRange], volume: u64) -> Result<()> {
    let mut previous_end = 0u64;
    for range in ranges {
        let end = range
            .offset
            .checked_add(range.length)
            .context("allocation range overflow")?;
        ensure!(
            range.length != 0
                && range.offset.is_multiple_of(CLUSTER)
                && range.length.is_multiple_of(CLUSTER)
                && range.offset >= previous_end
                && end <= volume,
            "allocation ranges overlap, are unaligned, unsorted or outside the volume"
        );
        previous_end = end;
    }
    Ok(())
}

fn push_coalesced(result: &mut Vec<ByteRange>, start: u64, end: u64) -> Result<()> {
    if start >= end {
        return Ok(());
    }
    if let Some(last) = result.last_mut() {
        let last_end = last
            .offset
            .checked_add(last.length)
            .context("merged range overflow")?;
        if start <= last_end {
            last.length = last_end.max(end) - last.offset;
            return Ok(());
        }
    }
    ensure!(
        result.len() < MAX_INPUT_RANGES,
        "allocation output interval budget exceeded"
    );
    result.push(ByteRange {
        offset: start,
        length: end - start,
    });
    Ok(())
}

/// Merge two sorted, internally disjoint lists. Cross-list overlaps are
/// expected, including Medium/Small allocator reservations.
fn union(left: &[ByteRange], right: &[ByteRange]) -> Result<Vec<ByteRange>> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < left.len() || j < right.len() {
        let take_left = j == right.len() || (i < left.len() && left[i].offset <= right[j].offset);
        let range = if take_left {
            let range = left[i];
            i += 1;
            range
        } else {
            let range = right[j];
            j += 1;
            range
        };
        push_coalesced(&mut out, range.offset, range.offset + range.length)?;
    }
    Ok(out)
}

/// Exact left-minus-right interval sweep over validated/coalesced ranges.
fn subtract(left: &[ByteRange], right: &[ByteRange]) -> Result<Vec<ByteRange>> {
    let mut out = Vec::new();
    let mut first = 0usize;
    for range in left {
        let end = range.offset + range.length;
        while first < right.len() && right[first].offset + right[first].length <= range.offset {
            first += 1;
        }
        let mut cursor = range.offset;
        for other in &right[first..] {
            if other.offset >= end {
                break;
            }
            if cursor < other.offset {
                push_coalesced(&mut out, cursor, other.offset.min(end))?;
            }
            cursor = cursor.max((other.offset + other.length).min(end));
            if cursor == end {
                break;
            }
        }
        if cursor < end {
            push_coalesced(&mut out, cursor, end)?;
        }
    }
    Ok(out)
}

fn total(ranges: &[ByteRange]) -> Result<u64> {
    ranges.iter().try_fold(0u64, |sum, range| {
        sum.checked_add(range.length)
            .context("allocation byte total overflow")
    })
}

/// Reconcile the actual observed inputs. `required` should include every
/// independently observed target metadata and data range, but the API cannot
/// prove that the caller supplied every reachable page, reservation or stream.
/// Every native/raw allocation is included in the conservative union, even if
/// it has not yet been classified as metadata, user data or a reservation.
pub fn reconcile(
    volume_bytes: u64,
    native: &[ByteRange],
    raw_medium: &[ByteRange],
    raw_small: &[ByteRange],
    required: &[ByteRange],
) -> Result<OwnershipReconciliation> {
    ensure!(
        volume_bytes >= CLUSTER && volume_bytes.is_multiple_of(CLUSTER),
        "unsupported allocation reconciliation geometry"
    );
    let input_count = [
        native.len(),
        raw_medium.len(),
        raw_small.len(),
        required.len(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, count| sum.checked_add(count))
    .context("allocation input count overflow")?;
    ensure!(
        input_count <= MAX_INPUT_RANGES,
        "allocation input interval budget exceeded"
    );
    for input in [native, raw_medium, raw_small, required] {
        validate_ranges(input, volume_bytes)?;
    }
    let raw = union(raw_medium, raw_small)?;
    let native_and_raw = union(native, &raw)?;
    let conservative = union(&native_and_raw, required)?;
    let required_not_native = subtract(required, native)?;
    let required_not_raw = subtract(required, &raw)?;
    let native_not_raw = subtract(native, &raw)?;
    let raw_not_native = subtract(&raw, native)?;
    Ok(OwnershipReconciliation {
        partition_bytes: volume_bytes,
        native_allocated_bytes: total(native)?,
        raw_union_allocated_bytes: total(&raw)?,
        observed_required_bytes: total(required)?,
        required_not_native_bytes: total(&required_not_native)?,
        required_not_raw_union_bytes: total(&required_not_raw)?,
        native_not_raw_union_bytes: total(&native_not_raw)?,
        raw_union_not_native_bytes: total(&raw_not_native)?,
        required_not_native,
        required_not_raw_union: required_not_raw,
        native_not_raw_union: native_not_raw,
        raw_union_not_native: raw_not_native,
        conservative_required_union_bytes: total(&conservative)?,
        conservative_required_union: conservative,
        input_authentication_verified: false,
        complete_graph_verified: false,
        complement_safe_to_preserve: false,
        source_admitted: false,
        raw_write_authority: false,
    })
}
