//! Pure planning for ordinary payload copied from its frozen NTFS locations.
//!
//! These structures describe addresses, not trusted file or device identities.
//! The native adapter must bind them to its live source inventory, protected
//! target routes, write plan, and exclusion lifetime. This module opens no IO,
//! reads no bytes, and grants no conversion or recovery authority.
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;

const GRANULE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileIdentity {
    pub record_number: u64,
    pub sequence_number: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceExtent {
    pub logical_offset: u64,
    pub physical_offset: Option<u64>,
    pub length: u64,
}

/// Borrow the participating DATA stream's exact name and extent model. Extents
/// must be sorted by logical offset. They may extend past EOF because NTFS can
/// preallocate a stream; only whole initialized clusters may be requested.
#[derive(Debug)]
pub struct SourceStream<'a> {
    pub identity: FileIdentity,
    pub stream_name_utf16: &'a [u16],
    pub logical_length: u64,
    pub initialized_length: u64,
    pub ordinary_file: bool,
    pub nonresident: bool,
    pub default_data: bool,
    pub attribute_flags: u16,
    pub lowest_vcn: u64,
    pub extents: &'a [SourceExtent],
}

/// A protected target route after the adapter binds its object index, native
/// identity, names and stream expectations to the source identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetRoute<'a> {
    pub identity: FileIdentity,
    pub stream_name_utf16: &'a [u16],
    pub logical_offset: u64,
    pub destination_offset: u64,
    pub length: u64,
    pub stream_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopySpan {
    pub destination_offset: u64,
    pub source_offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopySource {
    /// Old bytes saved for the indicated entry in the exact journal write plan.
    JournalOld { write_index: usize, within: u64 },
    /// Frozen source bytes outside every journal write, retained until handoff.
    RetainedSource { offset: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedCopySpan {
    pub destination_offset: u64,
    pub length: u64,
    pub source: CopySource,
}

fn volume(volume_bytes: u64) -> Result<()> {
    ensure!(
        volume_bytes != 0 && volume_bytes.is_multiple_of(GRANULE),
        "payload copy volume must contain whole 4 KiB granules"
    );
    Ok(())
}

fn end(offset: u64, length: u64) -> Result<u64> {
    offset
        .checked_add(length)
        .context("payload copy range overflow")
}

fn checked_range(offset: u64, length: u64, volume_bytes: u64) -> Result<u64> {
    ensure!(
        length != 0 && offset.is_multiple_of(GRANULE) && length.is_multiple_of(GRANULE),
        "payload copy ranges must be nonempty aligned 4 KiB granules"
    );
    let limit = end(offset, length)?;
    ensure!(
        limit <= volume_bytes,
        "payload copy range escapes the volume"
    );
    Ok(limit)
}

fn sorted_ranges(ranges: &[ByteRange], volume_bytes: u64) -> Result<()> {
    let mut previous_end = 0;
    for range in ranges {
        let limit = checked_range(range.offset, range.length, volume_bytes)?;
        ensure!(
            range.offset >= previous_end,
            "payload copy ranges overlap or are unordered"
        );
        previous_end = limit;
    }
    Ok(())
}

fn append_copy(copies: &mut Vec<CopySpan>, span: CopySpan) -> Result<()> {
    if let Some(last) = copies.last_mut()
        && end(last.destination_offset, last.length)? == span.destination_offset
        && end(last.source_offset, last.length)? == span.source_offset
    {
        last.length = end(last.length, span.length)?;
        return Ok(());
    }
    copies.push(span);
    Ok(())
}

/// Resolve every requested destination granule through one target route and
/// one initialized ordinary source extent. Requests must be sorted and
/// disjoint; routes may arrive in any order. Duplicate identities, overlapping
/// physical owners, ambiguous logical routes, gaps, holes and unsupported
/// stream encodings refuse the complete plan rather than yielding a partial
/// result. An empty request is permitted and returns an empty plan.
pub fn plan_copies(
    volume_bytes: u64,
    requested: &[ByteRange],
    streams: &[SourceStream<'_>],
    routes: &[TargetRoute<'_>],
) -> Result<Vec<CopySpan>> {
    volume(volume_bytes)?;
    sorted_ranges(requested, volume_bytes)?;

    let mut by_identity = BTreeMap::new();
    let mut physical_owners = Vec::new();
    for stream in streams {
        ensure!(
            stream.ordinary_file
                && stream.nonresident
                && stream.stream_name_utf16.len() <= 255
                && stream.default_data == stream.stream_name_utf16.is_empty()
                && stream.attribute_flags == 0
                && stream.lowest_vcn == 0
                && stream.initialized_length <= stream.logical_length,
            "payload copy requires initialized ordinary nonresident DATA"
        );
        ensure!(
            by_identity
                .insert((stream.identity, stream.stream_name_utf16), stream)
                .is_none(),
            "payload copy source stream identity is duplicated"
        );
        let mut logical_end = 0;
        for extent in stream.extents {
            let physical = extent
                .physical_offset
                .context("payload copy source contains a hole")?;
            checked_range(physical, extent.length, volume_bytes)?;
            ensure!(
                extent.logical_offset.is_multiple_of(GRANULE)
                    && extent.logical_offset >= logical_end,
                "payload copy source extents overlap or are unordered"
            );
            logical_end = end(extent.logical_offset, extent.length)?;
            physical_owners.push(ByteRange {
                offset: physical,
                length: extent.length,
            });
        }
    }
    physical_owners.sort_unstable_by_key(|range| range.offset);
    sorted_ranges(&physical_owners, volume_bytes)?;

    let mut route_order: Vec<_> = routes.iter().collect();
    route_order.sort_unstable_by_key(|route| route.destination_offset);
    let mut destination_end = 0;
    let mut logical_routes = Vec::with_capacity(routes.len());
    for route in &route_order {
        let route_end = checked_range(route.destination_offset, route.length, volume_bytes)?;
        ensure!(
            route.destination_offset >= destination_end,
            "payload copy target routes overlap"
        );
        destination_end = route_end;
        let stream = by_identity
            .get(&(route.identity, route.stream_name_utf16))
            .context("payload copy route has no source identity")?;
        let logical_end = end(route.logical_offset, route.length)?;
        ensure!(
            route.stream_length == stream.logical_length
                && route.logical_offset.is_multiple_of(GRANULE)
                && logical_end <= stream.initialized_length / GRANULE * GRANULE,
            "payload copy route exceeds its initialized whole-cluster stream"
        );
        logical_routes.push((
            (route.identity, route.stream_name_utf16),
            route.logical_offset,
            logical_end,
        ));
    }
    logical_routes.sort_unstable();
    for pair in logical_routes.windows(2) {
        ensure!(
            pair[0].0 != pair[1].0 || pair[0].2 <= pair[1].1,
            "payload copy stream has ambiguous overlapping target routes"
        );
    }

    let mut copies = Vec::new();
    let mut route_index = 0;
    for request in requested {
        let request_end = end(request.offset, request.length)?;
        let mut cursor = request.offset;
        while cursor < request_end {
            while route_order.get(route_index).is_some_and(|route| {
                // Every route end was checked above.
                route.destination_offset + route.length <= cursor
            }) {
                route_index += 1;
            }
            let route = route_order
                .get(route_index)
                .context("payload copy destination is not routed")?;
            ensure!(
                route.destination_offset <= cursor,
                "payload copy destination has a route gap"
            );
            let stream = by_identity[&(route.identity, route.stream_name_utf16)];
            let route_part_end = request_end.min(end(route.destination_offset, route.length)?);
            let mut logical = end(route.logical_offset, cursor - route.destination_offset)?;
            let mut extent_index = stream.extents.partition_point(|extent| {
                // Every logical end was checked above.
                extent.logical_offset + extent.length <= logical
            });
            while cursor < route_part_end {
                let extent = stream
                    .extents
                    .get(extent_index)
                    .context("payload copy source coverage is incomplete")?;
                ensure!(
                    extent.logical_offset <= logical,
                    "payload copy source has an extent gap"
                );
                let length = (route_part_end - cursor)
                    .min(end(extent.logical_offset, extent.length)? - logical);
                let source_offset = end(
                    extent
                        .physical_offset
                        .context("payload copy source contains a hole")?,
                    logical - extent.logical_offset,
                )?;
                checked_range(source_offset, length, volume_bytes)?;
                append_copy(
                    &mut copies,
                    CopySpan {
                        destination_offset: cursor,
                        source_offset,
                        length,
                    },
                )?;
                cursor = end(cursor, length)?;
                logical = end(logical, length)?;
                extent_index += 1;
            }
        }
    }
    Ok(copies)
}

fn append_resolved(spans: &mut Vec<ResolvedCopySpan>, span: ResolvedCopySpan) -> Result<()> {
    if let Some(last) = spans.last_mut()
        && end(last.destination_offset, last.length)? == span.destination_offset
    {
        let contiguous = match (last.source, span.source) {
            (
                CopySource::JournalOld {
                    write_index: left,
                    within,
                },
                CopySource::JournalOld {
                    write_index: right,
                    within: next,
                },
            ) => left == right && end(within, last.length)? == next,
            (
                CopySource::RetainedSource { offset },
                CopySource::RetainedSource { offset: next },
            ) => end(offset, last.length)? == next,
            _ => false,
        };
        if contiguous {
            last.length = end(last.length, span.length)?;
            return Ok(());
        }
    }
    spans.push(span);
    Ok(())
}

/// Split each source interval at the exact sorted, disjoint journal-write
/// boundaries. Source bytes to be overwritten resolve to their journal's old
/// payload; all other source bytes resolve to retained source addresses. This
/// describes where bytes must come from during recovery; it does not establish
/// that the journal is durable, that retained bytes remain excluded from writes,
/// or that either input belongs to an admitted conversion.
pub fn resolve_sources(
    volume_bytes: u64,
    copies: &[CopySpan],
    journal_writes: &[ByteRange],
) -> Result<Vec<ResolvedCopySpan>> {
    volume(volume_bytes)?;
    sorted_ranges(journal_writes, volume_bytes)?;
    let mut previous_end = 0;
    for copy in copies {
        let limit = checked_range(copy.destination_offset, copy.length, volume_bytes)?;
        checked_range(copy.source_offset, copy.length, volume_bytes)?;
        ensure!(
            copy.destination_offset >= previous_end,
            "payload copy destinations overlap or are unordered"
        );
        previous_end = limit;
    }

    let mut resolved = Vec::new();
    for copy in copies {
        let source_end = end(copy.source_offset, copy.length)?;
        let mut cursor = copy.source_offset;
        let mut write_index = journal_writes.partition_point(|range| {
            // Every journal end was checked above.
            range.offset + range.length <= cursor
        });
        while cursor < source_end {
            let (part_end, source) = match journal_writes.get(write_index) {
                Some(write) if write.offset <= cursor => (
                    source_end.min(end(write.offset, write.length)?),
                    CopySource::JournalOld {
                        write_index,
                        within: cursor - write.offset,
                    },
                ),
                Some(write) => (
                    source_end.min(write.offset),
                    CopySource::RetainedSource { offset: cursor },
                ),
                None => (source_end, CopySource::RetainedSource { offset: cursor }),
            };
            let length = part_end - cursor;
            ensure!(length != 0, "payload source segmentation made no progress");
            let destination_offset = end(copy.destination_offset, cursor - copy.source_offset)?;
            append_resolved(
                &mut resolved,
                ResolvedCopySpan {
                    destination_offset,
                    length,
                    source,
                },
            )?;
            cursor = part_end;
            if journal_writes
                .get(write_index)
                .is_some_and(|write| write.offset + write.length == cursor)
            {
                write_index += 1;
            }
        }
    }
    Ok(resolved)
}
