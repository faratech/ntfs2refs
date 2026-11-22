//! Actual protected target observations and disk-backed comparison scope.
//! This stage deliberately issues neither a source certificate nor activation.
use crate::{
    artifact_arena::{ArtifactGroup, ArtifactGroupPermit, ArtifactLease},
    general_shadow::{
        PagedInputs,
        source_backed::{
            PagedSourceByteAdapter, PagedSourceByteAdapterWithScope, PagedStreamIdentity,
            TAIL_BATCH, TAIL_BATCH_BYTES, original_prefetch::OriginalPrefetch, tail_place,
            tails_ahead,
        },
    },
    ntfs_inspect::{
        external_sort::ExternalSort,
        paged_storage::SourceScratch,
        record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
    },
    shadow_tree::{ExpectedObjectDomain, PagedExpectedTree},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    layout_residual_pages::LayoutResidualProvider, shadow_native::LayoutResidualExpectation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::{io, path::Path};

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Span {
    offset: u64,
    length: u64,
}
impl Span {
    fn end(&self) -> Result<u64> {
        self.offset
            .checked_add(self.length)
            .context("target interval overflow")
    }
    fn validate(&self, image: u64) -> Result<()> {
        ensure!(
            self.length > 0
                && self.offset.is_multiple_of(4096)
                && self.length.is_multiple_of(4096)
                && self.end()? <= image,
            "target interval escapes aligned partition"
        );
        Ok(())
    }
}
fn key(offset: u64, ordinal: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&offset.to_be_bytes());
    key[8..].copy_from_slice(&ordinal.to_be_bytes());
    key
}

struct Intervals {
    store: SortedRecordStore,
    image: u64,
    bytes: u64,
    // The rows the last lookup decoded, for the next one: see `RowMemo`.
    rows: crate::general_shadow::paged_capture::RowMemo<Span>,
}
impl Intervals {
    fn finish(
        sort: ExternalSort,
        path: &Path,
        image: u64,
        scratch: &SourceScratch,
        purpose: [u8; 8],
    ) -> Result<Self> {
        let sorted = sort.finish()?;
        let input = SortedRecordStore::open(&sorted, scratch)?;
        let mut output = SortedRecordWriter::new(path, purpose, scratch)?;
        let mut current: Option<Span> = None;
        let mut bytes = 0u64;
        for ordinal in 0..input.len() {
            let row: Span = input.get(ordinal)?;
            row.validate(image)?;
            ensure!(
                input.key(ordinal)?[..8] == row.offset.to_be_bytes(),
                "target sort key differs"
            );
            if let Some(previous) = &mut current {
                if row.offset <= previous.end()? {
                    previous.length = previous.end()?.max(row.end()?) - previous.offset;
                    continue;
                }
                output.push(key(previous.offset, 0), previous)?;
                bytes = bytes
                    .checked_add(previous.length)
                    .context("target byte count overflow")?;
            }
            current = Some(row);
        }
        if let Some(row) = current {
            output.push(key(row.offset, 0), &row)?;
            bytes = bytes
                .checked_add(row.length)
                .context("target byte count overflow")?;
        }
        let pin = output.finish()?;
        drop(input);
        scratch.retire_created(&sorted.data)?;
        scratch.retire_created(&sorted.directory)?;
        let store = SortedRecordStore::open(&pin, scratch)?;
        Ok(Self {
            store,
            image,
            bytes,
            rows: crate::general_shadow::paged_capture::RowMemo::new(),
        })
    }
    fn row(&self, ordinal: u64) -> Result<Span> {
        self.rows.row(ordinal, || self.store.get(ordinal))
    }
    fn subtract(
        &self,
        excluded: &Self,
        path: &Path,
        scratch: &SourceScratch,
        purpose: [u8; 8],
    ) -> Result<Self> {
        ensure!(
            self.image == excluded.image,
            "target interval domains differ"
        );
        let mut writer = SortedRecordWriter::new(path, purpose, scratch)?;
        let (mut other, mut bytes) = (0u64, 0u64);
        for ordinal in 0..self.store.len() {
            let row = self.row(ordinal)?;
            let end = row.end()?;
            let mut cursor = row.offset;
            while other < excluded.store.len() && excluded.row(other)?.end()? <= cursor {
                other += 1;
            }
            while cursor < end && other < excluded.store.len() {
                let next = excluded.row(other)?;
                if next.offset >= end {
                    break;
                }
                if next.offset > cursor {
                    let part = Span {
                        offset: cursor,
                        length: end.min(next.offset) - cursor,
                    };
                    writer.push(key(part.offset, 0), &part)?;
                    bytes = bytes
                        .checked_add(part.length)
                        .context("target difference count overflow")?;
                }
                cursor = end.min(next.end()?);
                if next.end()? <= end {
                    other += 1;
                }
            }
            if cursor < end {
                let part = Span {
                    offset: cursor,
                    length: end - cursor,
                };
                writer.push(key(part.offset, 0), &part)?;
                bytes = bytes
                    .checked_add(part.length)
                    .context("target difference count overflow")?;
            }
        }
        let pin = writer.finish()?;
        Ok(Self {
            store: SortedRecordStore::open(&pin, scratch)?,
            image: self.image,
            bytes,
            rows: crate::general_shadow::paged_capture::RowMemo::new(),
        })
    }
    fn same(&self, other: &Self) -> Result<bool> {
        if self.image != other.image
            || self.bytes != other.bytes
            || self.store.len() != other.store.len()
        {
            return Ok(false);
        }
        for ordinal in 0..self.store.len() {
            let a = self.row(ordinal)?;
            let b = other.row(ordinal)?;
            if a.offset != b.offset || a.length != b.length {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn revalidate(&self) -> Result<()> {
        self.store.revalidate()
    }
    fn covered_bytes(&self, offset: u64, length: u64) -> Result<u64> {
        let end = offset
            .checked_add(length)
            .context("in-place intersection overflow")?;
        let (mut low, mut high) = (0, self.store.len());
        let mut step = 0;
        while low < high {
            let middle = low + (high - low) / 2;
            let row = self.rows.step(step, middle, || self.store.get(middle))?;
            step += 1;
            if row.end()? <= offset {
                low = middle + 1;
            } else {
                // Where the search ends, if it is not lowered again.
                self.rows.keep(middle, row);
                high = middle;
            }
        }
        let mut bytes = 0u64;
        while low < self.store.len() {
            let row = self.row(low)?;
            if row.offset >= end {
                break;
            }
            bytes = bytes
                .checked_add(end.min(row.end()?).saturating_sub(offset.max(row.offset)))
                .context("in-place intersection count overflow")?;
            low += 1;
        }
        Ok(bytes)
    }
}

/// Source tail rows are emitted from actual checked DATA range reads. This
/// owner cannot be constructed from a pin, record count or success JSON.
struct SourceTailProvider {
    store: SortedRecordStore,
    pin_sha256: String,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
}

impl SourceTailProvider {
    /// Every stream's tail is read from the source again here and its digest
    /// is the expectation the shadow's tail is held to: for a stream whose
    /// contents were not hashed at inspection, that second reading is the
    /// only independent check of its tail (#225).
    ///
    /// One small read of the source after another, each waited for in turn,
    /// was the whole of this pass (18 s on the full Windows volume). Where
    /// the source may be read through lanes of its own ([`tails_ahead`]),
    /// the objects are taken in batches (`objects_leased_at_once`), the
    /// tails of a batch are asked of the lanes at once, in their order on
    /// the disk, from where the expected run list places them
    /// ([`tail_place`]), and each tail's bytes, once read, are offered to
    /// the adapter's read of that tail (`offer_read_ahead`). That read is
    /// otherwise what it was: the stream's session is opened from the
    /// source's record, the tail's range is mapped by it and the bytes are
    /// taken from the read ahead only where they lie wholly inside what was
    /// read there, a fresh read of the same frozen device; anything else,
    /// a read ahead that failed among it, is read by the adapter as before.
    /// The tails are taken, hashed and written in the same order as before,
    /// so the store and its pin are the same.
    fn capture(
        bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
        expected: &PagedExpectedTree,
        path: &Path,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        Self::capture_reusing(bytes, expected, path, scratch, None)
    }

    fn capture_reusing(
        bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
        expected: &PagedExpectedTree,
        path: &Path,
        scratch: &SourceScratch,
        supplied: Option<&SortedRecordStore>,
    ) -> Result<Self> {
        let admission = expected
            .header()
            .resource_admission
            .context("paged target requires resource admission")?;
        expected.require_resource_owner(admission)?;
        bytes.require_admission(admission)?;
        let mut writer = SortedRecordWriter::new(path, *b"N2RSRTL1", scratch)?;
        // A tail is shorter than one target cluster.
        let cluster = n2r_win32::target_cluster::bytes();
        let mut buffer = vec![0; usize::try_from(cluster)?];
        let supplied = supplied.filter(|_| n2r_win32::verify_policy::checks_once());
        let mut supplied_cursor = 0u64;
        let mut next_supplied: Option<LayoutResidualExpectation> = match supplied {
            Some(store) if store.len() > 0 => Some(store.get(0)?),
            _ => None,
        };
        let mut ahead = if supplied.is_some() {
            None
        } else {
            tails_ahead(bytes, scratch.artifact_group(), "n2r-source-tails-ahead")?
        };
        let mut first = 0usize;
        while first < expected.len() {
            let held = if ahead.is_some() {
                let (mut objects, mut tails) = (0usize, 0usize);
                expected.objects_leased_at_once(first, |object| {
                    objects += 1;
                    tails += object
                        .data_streams()
                        .filter(|s| s.tail_requires_materialization())
                        .count();
                    objects < TAIL_BATCH && tails < TAIL_BATCH
                })?
            } else {
                vec![expected.object_leased(first)?]
            };
            // For each tail of the batch, in the order it is taken below:
            // its ticket and place, where it was asked for.
            let mut tickets: std::collections::VecDeque<Option<(u64, u64)>> =
                std::collections::VecDeque::new();
            if let Some(reads) = ahead.as_mut() {
                let mut asks = Vec::new();
                let mut asked_bytes = 0u64;
                for object in held.iter().filter(|object| !object.directory) {
                    // The tails in the order they are taken below.
                    let mut tails: Vec<_> = object
                        .data_streams()
                        .filter(|s| s.tail_requires_materialization())
                        .collect();
                    tails.sort_unstable_by(|a, b| a.name_utf16.cmp(b.name_utf16));
                    for stream in tails {
                        let offset = stream.length / cluster * cluster;
                        let count = stream.length - offset;
                        let slot = tickets.len();
                        tickets.push_back(None);
                        if asks.len() < TAIL_BATCH
                            && asked_bytes + count <= TAIL_BATCH_BYTES
                            && let Some(place) = tail_place(&stream, offset, count)
                        {
                            asked_bytes += count;
                            asks.push((place, count as usize, slot));
                        }
                    }
                }
                asks.sort_unstable();
                for (place, count, slot) in asks {
                    tickets[slot] = Some((reads.ask(place, count), place));
                }
            }
            for (index, object) in (first..).zip(&held) {
                if object.directory {
                    continue;
                }
                // Pay for this actual object's reference vector before allocating
                // it; the expected-object lease separately owns the names/data.
                // The reserve also covers the one tail, of less than a target
                // cluster, and bounded current source proof/expectation name
                // copies, not an entire maximum row.
                let count = object
                    .data_streams()
                    .filter(|s| s.tail_requires_materialization())
                    .count();
                let max_name_units = object
                    .data_streams()
                    .filter(|s| s.tail_requires_materialization())
                    .map(|s| s.name_utf16.len())
                    .max()
                    .unwrap_or(0);
                let reference_bytes = (count as u64)
                    .checked_mul(std::mem::size_of::<crate::shadow_tree::StreamRef<'_>>() as u64)
                    .context("source tail reference RAM overflow")?;
                let admitted = reference_bytes
                    .checked_mul(2)
                    .and_then(|n| n.checked_add((max_name_units as u64).checked_mul(16)?))
                    .and_then(|n| n.checked_add(65536 - 4096 + cluster))
                    .context("source tail RAM overflow")?;
                ensure!(
                    reference_bytes
                        <= admission
                            .budget
                            .max_row_bytes
                            .checked_mul(8)
                            .context("source tail row bound overflow")?,
                    "source tail references exceed admitted row workspace"
                );
                let _tail_ram = bytes.lease_working_ram(admitted)?;
                let mut tails = Vec::new();
                tails.try_reserve_exact(count)?;
                tails.extend(
                    object
                        .data_streams()
                        .filter(|s| s.tail_requires_materialization()),
                );
                ensure!(
                    tails.len() == count
                        && (tails.capacity() as u64)
                            .checked_mul(
                                std::mem::size_of::<crate::shadow_tree::StreamRef<'_>>() as u64
                            )
                            .is_some_and(|n| n <= admitted),
                    "source tail reference allocation differs"
                );
                tails.sort_unstable_by(|a, b| a.name_utf16.cmp(b.name_utf16));
                for (ordinal, stream) in tails.into_iter().enumerate() {
                    let offset = stream.length / cluster * cluster;
                    let count = usize::try_from(stream.length - offset)?;
                    ensure!(
                        (1..buffer.len()).contains(&count),
                        "source tail width differs"
                    );
                    if let Some(store) = supplied {
                        while let Some(candidate) = next_supplied.as_ref() {
                            if candidate.object_index < index
                                || (candidate.object_index == index
                                    && candidate.stream_name_utf16.as_slice() < stream.name_utf16)
                            {
                                supplied_cursor += 1;
                                next_supplied = if supplied_cursor < store.len() {
                                    Some(store.get(supplied_cursor)?)
                                } else {
                                    None
                                };
                            } else {
                                break;
                            }
                        }
                        if let Some(candidate) = next_supplied.as_ref()
                            && candidate.object_index == index
                            && candidate.stream_name_utf16.as_slice() == stream.name_utf16
                            && candidate.logical_offset == offset
                            && candidate.length == count as u64
                        {
                            writer.push(key(index as u64, ordinal as u64), candidate)?;
                            supplied_cursor += 1;
                            next_supplied = if supplied_cursor < store.len() {
                                Some(store.get(supplied_cursor)?)
                            } else {
                                None
                            };
                            continue;
                        }
                    }
                    let identity = PagedStreamIdentity {
                        record_number: object.record_number,
                        sequence_number: object.sequence_number,
                        name_utf16: stream.name_utf16,
                        length: stream.length,
                        sha256: stream.sha256,
                        allow_sparse: stream.sparse.is_some(),
                    };
                    // A read ahead that failed is left to the adapter to make
                    // again, and to report if it fails there too.
                    if let (Some(reads), Some((ticket, place))) =
                        (ahead.as_mut(), tickets.pop_front().flatten())
                        && let Ok(read) = reads.take(ticket)
                    {
                        bytes.offer_read_ahead(place, read);
                    }
                    let proof = bytes.read_range_proof(&identity, offset, &mut buffer[..count]);
                    bytes.withdraw_read_ahead(drop);
                    let proof = proof?;
                    ensure!(
                        proof.stream_logical_bytes == stream.length
                            && proof.expected_stream_sha256.as_deref() == stream.sha256
                            && proof.stream_name_utf16 == stream.name_utf16,
                        "source residual identity changed"
                    );
                    writer.push(
                        key(index as u64, ordinal as u64),
                        &LayoutResidualExpectation {
                            object_index: index,
                            stream_name_utf16: stream.name_utf16.to_vec(),
                            logical_offset: offset,
                            length: count as u64,
                            sha256: proof.sha256,
                        },
                    )?;
                }
            }
            first += held.len();
        }
        // The lanes are closed before the adapter's scope ends.
        drop(ahead);
        let pin = writer.finish()?;
        let store = SortedRecordStore::open(&pin, scratch)?;
        // The provider's data-file pin is an actual complete-file SHA. Its
        // separate ordinal directory remains held and revalidated as well.
        let pin_sha256 = pin.data.file_sha256.clone();
        bytes.finish_stream()?;
        expected.require_resource_owner(admission)?;
        Ok(Self {
            store,
            pin_sha256,
            admission,
        })
    }
}

struct TargetReadRecorder<'a> {
    target: &'a mut n2r_win32::GeneralFrozenPartition,
    sort: ExternalSort,
    image: u64,
    position: u64,
    rows: u64,
    poisoned: bool,
}
impl Read for TargetReadRecorder<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(io::Error::other("target read transcript is incomplete"));
        }
        let result = (|| -> Result<usize> {
            let n = self.target.read(output)?;
            if n != 0 {
                let end = self
                    .position
                    .checked_add(n as u64)
                    .context("target raw read overflow")?;
                ensure!(end <= self.image, "target raw read escapes partition");
                let start = self.position / 4096 * 4096;
                let aligned = end
                    .checked_next_multiple_of(4096)
                    .context("target read alignment overflow")?;
                ensure!(
                    aligned <= self.image,
                    "target raw read granule escapes partition"
                );
                self.sort.push(
                    key(start, self.rows),
                    &Span {
                        offset: start,
                        length: aligned - start,
                    },
                )?;
                self.rows = self
                    .rows
                    .checked_add(1)
                    .context("target read count overflow")?;
                self.position = end;
            }
            Ok(n)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result.map_err(io::Error::other)
    }
}
impl Seek for TargetReadRecorder<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if self.poisoned {
            return Err(io::Error::other("target read transcript is incomplete"));
        }
        let at = self.target.seek(from)?;
        if at > self.image {
            self.poisoned = true;
            return Err(io::Error::other("target inspection seek escapes partition"));
        }
        self.position = at;
        Ok(at)
    }
}
fn anchors(
    target: &mut n2r_win32::GeneralFrozenPartition,
    image: u64,
    resources: crate::ntfs_admission::ResourceProfile,
    root: &Path,
    scratch: &SourceScratch,
) -> Result<(Intervals, Intervals, Option<String>)> {
    // Read count is not known until inspection finishes. Start with one page
    // of batch space; the normal spill/merge path accepts every later read.
    let sort = ExternalSort::with_record_hint(
        &root.join("reads-sort"),
        *b"N2RTRAW1",
        scratch,
        u64::from(scratch.budget().page_bytes).div_ceil(4096),
    )?;
    let position = target.stream_position()?;
    let mut recorder = TargetReadRecorder {
        target,
        sort,
        image,
        position,
        rows: 0,
        poisoned: false,
    };
    let found = crate::refs_inspect::inspect_with_resource_profile(&mut recorder, image, resources)
        .and_then(|value| crate::refs_write_set::observed_anchors(&value));
    ensure!(
        !recorder.poisoned,
        "target raw read transcript could not be recorded completely"
    );
    let reads = Intervals::finish(
        recorder.sort,
        &root.join("reads"),
        image,
        scratch,
        *b"N2RTRAW1",
    )?;
    let mut sort = ExternalSort::with_record_hint(
        &root.join("anchors-sort"),
        *b"N2RANCH1",
        scratch,
        found.as_ref().map_or(0, |rows| rows.len() as u64),
    )?;
    let error = match found {
        Ok(rows) => {
            for (ordinal, row) in rows.into_iter().enumerate() {
                sort.push(
                    key(row.offset, ordinal as u64),
                    &Span {
                        offset: row.offset,
                        length: row.length,
                    },
                )?;
            }
            None
        }
        Err(error) => Some(format!("{error:#}")),
    };
    Ok((
        Intervals::finish(sort, &root.join("anchors"), image, scratch, *b"N2RANCH1")?,
        reads,
        error,
    ))
}
fn union_rows(
    parts: &[&Intervals],
    path: &Path,
    image: u64,
    scratch: &SourceScratch,
    purpose: [u8; 8],
) -> Result<Intervals> {
    let records = parts.iter().try_fold(0u64, |n, part| {
        n.checked_add(part.store.len())
            .context("target union record hint overflow")
    })?;
    let mut sort =
        ExternalSort::with_record_hint(&path.with_extension("sort"), purpose, scratch, records)?;
    let mut ordinal = 0u64;
    for part in parts {
        ensure!(part.image == image, "target union geometry differs");
        for at in 0..part.store.len() {
            let row = part.row(at)?;
            sort.push(key(row.offset, ordinal), &row)?;
            ordinal = ordinal
                .checked_add(1)
                .context("target union count overflow")?;
        }
    }
    Intervals::finish(sort, path, image, scratch, purpose)
}
fn allocated(
    native: &n2r_win32::GeneralLiveRefsLayoutObservation,
    path: &Path,
    image: u64,
    scratch: &SourceScratch,
) -> Result<Intervals> {
    let report = native.report().native();
    let map = report
        .metadata_allocation
        .as_ref()
        .context("complete protected metadata allocation absent")?;
    let proof = report
        .metadata_allocation_page_proof
        .as_ref()
        .context("complete protected allocation page proof absent")?;
    ensure!(
        map.cluster_count
            .checked_mul(n2r_win32::target_cluster::bytes())
            == Some(image)
            && proof.cluster_count == map.cluster_count
            && proof.canonical_bitmap_sha256 == map.bitmap_sha256,
        "protected complete allocation domain/proof differs"
    );
    let mut sort = ExternalSort::with_record_hint(
        &path.with_extension("sort"),
        *b"N2RTALC1",
        scratch,
        map.ranges.len() as u64,
    )?;
    for (ordinal, row) in map.ranges.iter().enumerate() {
        sort.push(
            key(row.offset, ordinal as u64),
            &Span {
                offset: row.offset,
                length: row.length,
            },
        )?;
    }
    let output = Intervals::finish(sort, path, image, scratch, *b"N2RTALC1")?;
    ensure!(
        map.allocated_clusters
            .checked_mul(n2r_win32::target_cluster::bytes())
            == Some(output.bytes),
        "protected allocation count/order differs"
    );
    Ok(output)
}
fn result_budget(
    provider: &SourceTailProvider,
    pair: &n2r_win32::general_layout::GeneralSourceShadowBinding,
    scratch: &SourceScratch,
) -> Result<n2r_win32::metadata_pages::PageBudget> {
    // Bound the actual JSON codec, not a fixture tail count or a full page per
    // tiny row. One page/index frame per row is a conservative physical bound.
    let mut bytes = (serde_json::to_vec(pair)?.len() as u64)
        .checked_add(2048)
        .context("tail result header budget overflow")?;
    for ordinal in 0..provider.len() {
        let expectation = provider.expectation(ordinal)?;
        let maximum = n2r_win32::layout_residual_pages::LayoutResidualResult {
            expectation,
            native_file_id: [255; 16],
            actual_sha256: "f".repeat(64),
            bytes_read: u64::MAX,
            eof_observed: false,
        };
        bytes = bytes
            .checked_add(serde_json::to_vec(&maximum)?.len() as u64 + 144)
            .context("tail result byte budget overflow")?;
    }
    let mut budget = scratch.budget().page_budget()?;
    ensure!(
        bytes <= budget.max_file_bytes,
        "actual protected tail rows exceed arena resource budget"
    );
    budget.max_file_bytes = bytes;
    budget.max_records = provider
        .len()
        .checked_add(2)
        .context("tail result count overflow")?;
    budget.max_pages = budget.max_records;
    budget.validate()?;
    Ok(budget)
}

// Fixed application headroom for native hash handles/context, not a measured
// total OS allocation or a hard cap on the provider's private allocations.
const HASH_CONTEXT_RESERVE: u64 = 2 * 1024;
// The closing reader's read buffer and the hash context.
const CLOSING_READ_WORKSPACE: u64 =
    crate::ntfs_inspect::SESSION_READ_BYTES as u64 + HASH_CONTEXT_RESERVE;

/// What the stages between the walks hold of their own: one route as it is
/// read back, its text for the digest, and the interval being built. The
/// objects they look up are leased where they are decoded, and the sorts
/// and the residual pages pay for themselves. (This was eight of the
/// largest row the budget admits, an eighth of the ledger while the routes
/// were turned into intervals and the data in place was found.)
const STAGE_ROUTE_WORKSPACE: u64 = 4 * 1024 * 1024;

struct PagedShadowClosing<'a> {
    target_owner: usize,
    binding: n2r_win32::general_layout::GeneralDiskBinding,
    intervals: &'a Intervals,
    range: u64,
    done: u64,
    loaded_offset: u64,
    loaded_bytes: usize,
    buffer: Vec<u8>,
    // What tells one pass over these bytes from another in the same run: a
    // SHA-256 over the intervals and, for every read in order, its place,
    // its length and the XXH3-128 of its bytes. The reads are cut by the
    // intervals and the buffer alone, so every pass makes the same ones.
    // It is change detection between passes over bytes the run holds
    // frozen, as `parallel_digest` is, not a content hash: nothing outside
    // the run is compared with it. Every byte through SHA-256 was the
    // whole of this step on a volume with little on it: 12.6 of 12.8 s for
    // the 11 GB that a freshly formatted 50 GiB shadow has to account for.
    hash: Sha256,
    read: u64,
    reused: u64,
    // The same reads, made ahead of this pass by helper threads on read
    // lanes of the shadow, each with its XXH3-128. The pass still takes them
    // in order and holds each to the place and length the intervals give
    // it. The helpers have ended, and their lanes are closed, when the pass
    // is finished or dropped.
    ahead: Option<OriginalPrefetch>,
}
/// The most one read of the closing pass asks for.
const CLOSING_CHUNK: usize = crate::ntfs_inspect::SESSION_READ_BYTES;
impl<'a> PagedShadowClosing<'a> {
    /// `spare` is the ledger that may pay for reading ahead: for each of as
    /// many lanes as the device's depth asks for and the ledger grants
    /// (`OriginalPrefetch::lanes_for`), its chunks, the lane and a stack,
    /// and the list of the intervals, as spare memory. On a device that
    /// takes one read at a time, without a ledger or when it has no memory
    /// to spare, the pass reads through the target's owner as it did, as
    /// it also does when the helpers cannot be started.
    fn new(
        target: &n2r_win32::GeneralFrozenPartition,
        intervals: &'a Intervals,
        spare: Option<&crate::artifact_arena::ArtifactArena>,
    ) -> Result<Self> {
        let rows = intervals.store.len();
        let wanted = OriginalPrefetch::lanes_for(target.io_profile().queue_depth);
        let mut listed = spare
            .filter(|_| rows != 0 && wanted != 0)
            .and_then(|arena| {
                let (lanes, paid) =
                    OriginalPrefetch::reserve_lanes(wanted, CLOSING_CHUNK, rows, |bytes| {
                        arena.reserve_spare_ram(bytes).ok()
                    })?;
                let mut list = Vec::new();
                list.try_reserve_exact(usize::try_from(rows).ok()?).ok()?;
                Some((list, lanes, paid))
            });
        let mut hash = Sha256::new();
        hash.update(b"n2r-paged-target-consumed-bytes-v2\0");
        hash.update(intervals.image.to_le_bytes());
        hash.update(rows.to_le_bytes());
        for ordinal in 0..rows {
            let row = intervals.row(ordinal)?;
            hash.update(row.offset.to_le_bytes());
            hash.update(row.length.to_le_bytes());
            if let Some((list, _, _)) = &mut listed {
                list.push(crate::refs_write_set::ByteRange {
                    offset: row.offset,
                    length: row.length,
                });
            }
        }
        // The lanes only buy speed: lanes that cannot be opened (a handle,
        // an aligned buffer, the state query that binds it) leave the pass
        // reading through the target, as it did, with every check of its
        // own.
        let ahead = match listed {
            Some((list, lanes, paid)) => target
                .read_lanes(lanes, &mut Vec::new())
                .ok()
                .filter(|lanes| !lanes.is_empty())
                .and_then(|lanes| {
                    OriginalPrefetch::start(
                        "n2r-capture-shadow-ahead",
                        lanes,
                        list,
                        CLOSING_CHUNK,
                        true,
                        Some(Box::new(paid)),
                    )
                    .ok()
                }),
            None => None,
        };
        Ok(Self {
            target_owner: std::ptr::from_ref(target) as usize,
            binding: target.binding().clone(),
            intervals,
            range: 0,
            done: 0,
            loaded_offset: 0,
            loaded_bytes: 0,
            buffer: vec![0; CLOSING_CHUNK],
            hash,
            read: 0,
            reused: 0,
            ahead,
        })
    }
    fn validate_owner(&self, target: &n2r_win32::GeneralFrozenPartition) -> Result<()> {
        ensure!(
            std::ptr::from_ref(target) as usize == self.target_owner
                && target.binding() == &self.binding
                && target.byte_len() == self.intervals.image,
            "closing raw bytes require the same actual frozen target owner"
        );
        Ok(())
    }
    fn next(&mut self, target: &mut n2r_win32::GeneralFrozenPartition) -> Result<bool> {
        self.validate_owner(target)?;
        if self.range == self.intervals.store.len() {
            self.loaded_bytes = 0;
            return Ok(false);
        }
        let row = self.intervals.row(self.range)?;
        let at = row.offset + self.done;
        let n = (row.length - self.done).min(CLOSING_CHUNK as u64) as usize;
        let xxh3 = if let Some(ahead) = &mut self.ahead {
            // The helper read this chunk and hashed it; its buffer takes
            // the place of this pass's, which goes back to the helper.
            let chunk = ahead.next(at, n)?;
            let xxh3 = chunk
                .xxh3_128
                .context("shadow chunk read ahead was not hashed")?;
            ahead.recycle(std::mem::replace(&mut self.buffer, chunk.bytes));
            xxh3
        } else {
            if self.buffer.len() < n {
                self.buffer.resize(n, 0);
            }
            target.seek(SeekFrom::Start(at))?;
            target.read_exact(&mut self.buffer[..n])?;
            crate::parallel_digest::xxh3_128(&self.buffer[..n])
        };
        self.hash.update(at.to_le_bytes());
        self.hash.update((n as u64).to_le_bytes());
        self.hash.update(xxh3);
        self.loaded_offset = at;
        self.loaded_bytes = n;
        self.read = self
            .read
            .checked_add(n as u64)
            .context("closing raw count overflow")?;
        self.done += n as u64;
        if self.done == row.length {
            self.range += 1;
            self.done = 0;
        }
        Ok(true)
    }
    fn finish(
        mut self,
        target: &mut n2r_win32::GeneralFrozenPartition,
    ) -> Result<(String, u64, u64)> {
        while self.next(target)? {}
        // The helper has read exactly these chunks and ends here, its lane
        // with it, before the target's state is looked at again.
        if let Some(ahead) = self.ahead.take() {
            ahead.finish()?;
        }
        ensure!(
            self.read == self.intervals.bytes,
            "closing raw coverage differs"
        );
        Ok((hex::encode(self.hash.finalize()), self.read, self.reused))
    }
}
impl crate::general_shadow::source_backed::ClosingShadowBytes for PagedShadowClosing<'_> {
    fn read_shadow_exact(
        &mut self,
        target: &mut n2r_win32::GeneralFrozenPartition,
        offset: u64,
        output: &mut [u8],
    ) -> Result<u64> {
        self.validate_owner(target)?;
        let mut at = offset;
        let mut done = 0;
        while done < output.len() {
            if self.loaded_bytes == 0 || at >= self.loaded_offset + self.loaded_bytes as u64 {
                ensure!(
                    self.next(target)?,
                    "capture requires raw bytes beyond complete closing scope"
                );
                continue;
            }
            ensure!(
                at >= self.loaded_offset,
                "closing capture raw requests regress or cross unbracketed bytes"
            );
            let local = usize::try_from(at - self.loaded_offset)?;
            let n = (output.len() - done).min(self.loaded_bytes - local);
            output[done..done + n].copy_from_slice(&self.buffer[local..local + n]);
            done += n;
            at += n as u64;
        }
        self.reused = self
            .reused
            .checked_add(output.len() as u64)
            .context("closing byte reuse overflow")?;
        Ok(output.len() as u64)
    }
}

fn route_intervals(
    routes: &crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
    path: &Path,
    image: u64,
    scratch: &SourceScratch,
) -> Result<(Intervals, String)> {
    let mut sort = ExternalSort::with_record_hint(
        &path.with_extension("sort"),
        *b"N2RTEXC1",
        scratch,
        routes.len(),
    )?;
    let mut hash = Sha256::new();
    hash.update(b"n2r-protected-paged-routes-v1\0");
    for ordinal in 0..routes.len() {
        let route = routes.route(ordinal)?;
        let encoded = serde_json::to_vec(&route)?;
        hash.update((encoded.len() as u64).to_le_bytes());
        hash.update(encoded);
        sort.push(
            key(route.target_physical_offset(), ordinal),
            &Span {
                offset: route.target_physical_offset(),
                length: route.length(),
            },
        )?;
    }
    let output = Intervals::finish(sort, path, image, scratch, *b"N2RTEXC1")?;
    ensure!(
        output.bytes == routes.payload_bytes(),
        "payload exclusion union loses route ownership"
    );
    Ok((output, hex::encode(hash.finalize())))
}
fn source_in_place(
    bytes: &mut PagedSourceByteAdapterWithScope<'_, '_>,
    expected: &PagedExpectedTree,
    routes: &crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
    path: &Path,
    image: u64,
    scratch: &SourceScratch,
) -> Result<Intervals> {
    let mut sort = ExternalSort::with_record_hint(
        &path.with_extension("sort"),
        *b"N2RTIPL1",
        scratch,
        routes.len(),
    )?;
    // The routes of one stream follow one another. Closing a stream's
    // session reads its file records again and checks its mapping; done
    // after every route, a stream in thousands of runs was opened and closed
    // once per run, which is quadratic in its runs. The session is closed
    // when the stream changes, and after every route only where everything
    // is re-read at each step.
    let every_route = n2r_win32::verify_policy::full_unremembered();
    let mut open: Option<(usize, Vec<u16>)> = None;
    for ordinal in 0..routes.len() {
        let route = routes.route(ordinal)?;
        let object = expected.object_leased(route.object_index())?;
        let stream = object
            .stream(route.stream_name_utf16())
            .context("in-place source stream absent")?;
        if open.as_ref().is_some_and(|(index, name)| {
            *index != route.object_index() || name != stream.name_utf16
        }) {
            bytes.finish_stream()?;
            open = None;
        }
        let id = PagedStreamIdentity {
            record_number: object.record_number,
            sequence_number: object.sequence_number,
            name_utf16: stream.name_utf16,
            length: stream.length,
            sha256: stream.sha256,
            allow_sparse: stream.sparse.is_some(),
        };
        // Only a complete route with the CURRENT identical linear source map
        // is omitted. Mixed/ambiguous routes stay in the actual comparison.
        if bytes.source_physical_for(&id, route.logical_offset(), route.length())?
            == Some(route.target_physical_offset())
        {
            sort.push(
                key(route.target_physical_offset(), ordinal),
                &Span {
                    offset: route.target_physical_offset(),
                    length: route.length(),
                },
            )?;
        }
        if every_route {
            bytes.finish_stream()?;
        } else if open.is_none() {
            open = Some((route.object_index(), stream.name_utf16.to_vec()));
        }
    }
    if open.is_some() {
        bytes.finish_stream()?;
    }
    Intervals::finish(sort, path, image, scratch, *b"N2RTIPL1")
}

#[path = "partition_context.rs"]
mod partition_context;
use partition_context::ScopedSourceContext;

/// A private scope issued only by the live native/closing-bracket constructor.
/// Compared bytes exclude only actual same-source in-place mappings. This is
/// deliberately not constructible from a RecordStorePin or serialized flags.
pub(crate) struct PagedTargetScope {
    required: crate::general_shadow::paged_capture::DiagnosticCaptureSelection,
    compared: crate::general_shadow::paged_capture::DiagnosticCaptureSelection,
    in_place: Intervals,
    consumed: Intervals,
    expected_tree_sha256: String,
    source_inspection_sha256: String,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    identity: Arc<CaptureScopeIdentity>,
    native_report: Arc<n2r_win32::shadow_native::Report>,
    source_owner: usize,
    _ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
}
pub(crate) struct CaptureScopeIdentity {
    _ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
}
impl PagedTargetScope {
    /// Compare only an identity obtained from the currently held source owner;
    /// this scalar cannot construct this scope or replace its other checks.
    pub(crate) fn matches_source_owner(&self, identity: usize) -> bool {
        identity == self.source_owner
    }
    pub(crate) fn matches_candidate(
        &self,
        candidate: &crate::general_shadow::paged_candidate::PagedSourceBackedCandidateWithScope<
            '_,
            '_,
            '_,
        >,
    ) -> bool {
        candidate.source_owner_identity() == self.source_owner
            && candidate.matches_native_report(&self.native_report)
    }
    pub(crate) fn capture_identity(&self) -> Arc<CaptureScopeIdentity> {
        Arc::clone(&self.identity)
    }
    pub(crate) fn covers_route(&self, offset: u64, length: u64) -> Result<bool> {
        Ok(self.required.covers(offset, length)?
            && self
                .compared
                .covered_bytes(offset, length)?
                .checked_add(self.in_place.covered_bytes(offset, length)?)
                == Some(length))
    }
    pub(crate) fn required(
        &self,
    ) -> &crate::general_shadow::paged_capture::DiagnosticCaptureSelection {
        &self.required
    }
    pub(crate) fn compared(
        &self,
    ) -> &crate::general_shadow::paged_capture::DiagnosticCaptureSelection {
        &self.compared
    }
    pub(crate) fn in_place_bytes(&self) -> u64 {
        self.in_place.bytes
    }
    pub(crate) fn expected_tree_sha256(&self) -> &str {
        &self.expected_tree_sha256
    }
    pub(crate) fn source_inspection_sha256(&self) -> &str {
        &self.source_inspection_sha256
    }
    pub(crate) fn pair(&self) -> &n2r_win32::general_layout::GeneralSourceShadowBinding {
        &self.pair
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.required.revalidate()?;
        self.compared.revalidate()?;
        self.in_place.revalidate()?;
        self.consumed.revalidate()
    }
}
pub(crate) struct ProtectedPagedTargetSelection {
    native: n2r_win32::GeneralLiveRefsLayoutObservation,
    windows_aliases: Option<n2r_win32::shadow_native::windows_aliases::ObservedWindowsAliases>,
    windows_alias_owner: Option<Arc<crate::boot_alias::WindowsAliasDomain>>,
    windows_alias_digest: Option<[u8; 32]>,
    scope: PagedTargetScope,
    captured: crate::general_shadow::paged_capture::DiagnosticSelectedCapture,
    // Absent when the expected tree was not re-derived (check-once policy).
    source_projection: Option<crate::shadow_tree::source_pages::ProjectionRevalidationOwner>,
    source_tails: SourceTailProvider,
    // One per observation of the shadow: two, or one under the check-once policy.
    _native_leases: Vec<ArtifactLease>,
    // The files the walks wrote their rows to, where memory was short.
    _spilled_rows: super::paged_memory::SpilledFiles,
    _native_result_ram: Vec<crate::artifact_arena::ArenaRamLease>,
    _scratch: SourceScratch,
    opening_sha256: String,
    closing_sha256: String,
    raw_consumed_bytes: u64,
    raw_reused_bytes: u64,
    // Native wrapper control events and three disk-state bookends per call
    // remain owned after collection, separate from SDK report row leases.
    _native_wrapper_ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
}
impl ProtectedPagedTargetSelection {
    /// Close boot-only alias preservation against the actual final protected
    /// observer, original source-plan owner and complete canonical input.
    pub(crate) fn require_windows_alias_source(
        &self,
        owner: &Arc<crate::boot_alias::WindowsAliasDomain>,
        source_pin: [u8; 32],
        expected: &PagedExpectedTree,
    ) -> Result<()> {
        ensure!(
            self.windows_alias_owner
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, owner)),
            "target aliases do not retain the original Windows source-plan owner"
        );
        let observed = self
            .windows_aliases
            .as_ref()
            .context("protected target alias witness absent")?;
        let digest = self
            .windows_alias_digest
            .context("protected target alias digest absent")?;
        ensure!(
            observed.len() as u64 == owner.len()
                && owner.source_inspection_sha256() == hex::encode(source_pin),
            "protected target alias coverage or source differs"
        );
        observed.require_scope(self.scope.pair(), source_pin, digest)?;
        observed.require_input(&PagedInputs(expected))?;
        Ok(())
    }
    /// Recheck only the exact non-payload raw bracket owned by this proof.
    /// Routed payload is not reread or represented by a fabricated full hash.
    pub(crate) fn recheck_frozen_target(
        &self,
        target: &mut n2r_win32::GeneralFrozenPartition,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<()> {
        self.captured.with_revalidation(|witness| {
            self.recheck_frozen_target_with_capture_witness(target, events, witness)
        })?;
        // This standalone wrapper is a complete temporal boundary too; the
        // normal file handle does not prove raw/admin aliases are excluded.
        self.captured.revalidate()
    }

    /// Reuse only the full capture check performed by this immediate read-only
    /// boundary. The witness cannot escape its producer's scoped callback.
    pub(crate) fn recheck_frozen_target_with_capture_witness(
        &self,
        target: &mut n2r_win32::GeneralFrozenPartition,
        events: &mut Vec<n2r_win32::NativeEvent>,
        witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    ) -> Result<()> {
        witness.require_capture(&self.captured)?;
        ensure!(
            target.binding() == &self.scope.pair.shadow,
            "target recheck route differs from protected proof"
        );
        let before = target.state(events)?;
        ensure!(
            &before == self.native.after() && before.disk_attributes == 3,
            "target recheck requires original frozen device state"
        );
        let _ram = self._scratch.lease_ram(CLOSING_READ_WORKSPACE)?;
        self.scope.revalidate()?;
        ensure!(
            self.captured.is_for_scope(&self.scope),
            "captured data lost its actual target scope binding"
        );
        if let Some(projection) = &self.source_projection {
            projection.revalidate()?;
        }
        self.source_tails.revalidate()?;
        for lease in &self._native_leases {
            lease.revalidate()?;
        }
        self.native
            .report()
            .paged_residuals()
            .context("protected target residual owner absent")?
            .revalidate()?;
        // The shadow is read-only and held, and nothing reads it again after
        // capture: the journal holds every byte the apply step writes. Under
        // the check-once policy its state is confirmed and its metadata is
        // not read a third time.
        if n2r_win32::verify_policy::checks_once() {
            ensure!(
                target.state(events)? == before,
                "protected target frozen identity changed after capture"
            );
            return Ok(());
        }
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::ShadowMetadataRead);
        let group = self._scratch.artifact_group();
        let (digest, bytes, _) = PagedShadowClosing::new(
            target,
            &self.scope.consumed,
            group.as_ref().map(|group| group.arena()),
        )?
        .finish(target)?;
        ensure!(
            digest == self.closing_sha256
                && bytes == self.raw_consumed_bytes
                && target.state(events)? == before,
            "protected target consumed bytes or frozen identity changed after capture"
        );
        Ok(())
    }
    pub(crate) fn native(&self) -> &n2r_win32::GeneralLiveRefsLayoutObservation {
        &self.native
    }
    pub(crate) fn scope(&self) -> &PagedTargetScope {
        &self.scope
    }
    pub(crate) fn captured(
        &self,
    ) -> &crate::general_shadow::paged_capture::DiagnosticSelectedCapture {
        &self.captured
    }
    pub(crate) fn diagnostic(&self) -> serde_json::Value {
        serde_json::json!({
        "kind":"protected-paged-target-selection","expected_tree_sha256":self.scope.expected_tree_sha256,
        "source_inspection_sha256":self.scope.source_inspection_sha256,"in_place_bytes":self.scope.in_place.bytes,
        "raw_opening_sha256":self.opening_sha256,"raw_closing_sha256":self.closing_sha256,
        "raw_consumed_bytes":self.raw_consumed_bytes,"actual_closing_bytes_reused":self.raw_reused_bytes,
        "source_tail_count":self.source_tails.len(),"required_selection":self.scope.required.pin(),
        "compared_selection":self.scope.compared.pin(),"activation_authorized":false,"conversion_qualified":false})
    }
}

/// The consumer executes inside the closing raw-byte bracket and receives its
/// actual immutable buffers. Source fingerprint gates close again after it.
/// T cannot grant activation here; the journal/source-certificate stage is a
/// separate unfinished contract. No legacy all-object/route/range Vec is built.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_and_select_paged(
    context: &mut crate::general_source_admission::resource::ResourceSourceContext,
    target: &mut n2r_win32::GeneralFrozenPartition,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    expected: &PagedExpectedTree,
    capture_group: &ArtifactGroupPermit,
    output: &Path,
    events: &mut Vec<n2r_win32::NativeEvent>,
    consume: impl FnOnce(
        &mut crate::general_source_admission::resource::ResourceSourceContext,
        &mut n2r_win32::GeneralFrozenPartition,
        &PagedExpectedTree,
        crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
        &PagedTargetScope,
        &mut dyn crate::general_shadow::source_backed::ClosingShadowBytes,
        &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<crate::general_shadow::paged_capture::DiagnosticSelectedCapture>,
) -> Result<ProtectedPagedTargetSelection> {
    let mut scoped = ScopedSourceContext::Dedicated(context);
    observe_and_select_scoped(
        &mut scoped,
        target,
        pair,
        expected,
        capture_group,
        output,
        events,
        None,
        None,
        |scoped, target, expected, routes, scope, closing, native_events| match scoped {
            ScopedSourceContext::Dedicated(context) => consume(
                context,
                target,
                expected,
                routes,
                scope,
                closing,
                native_events,
            ),
            ScopedSourceContext::Partition(_) => {
                anyhow::bail!("dedicated target callback received partition source")
            }
        },
    )
}

pub(crate) fn observe_and_select_paged_windows_aliases(
    context: &mut crate::general_source_admission::resource::ResourceSourceContext,
    target: &mut n2r_win32::GeneralFrozenPartition,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    expected: &PagedExpectedTree,
    capture_group: &ArtifactGroupPermit,
    output: &Path,
    events: &mut Vec<n2r_win32::NativeEvent>,
    aliases: &Arc<n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>,
    mapped: &crate::boot_alias::WindowsAliasNativeDomain<'_>,
    consume: impl FnOnce(
        &mut crate::general_source_admission::resource::ResourceSourceContext,
        &mut n2r_win32::GeneralFrozenPartition,
        &PagedExpectedTree,
        crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
        &PagedTargetScope,
        &mut dyn crate::general_shadow::source_backed::ClosingShadowBytes,
        &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<crate::general_shadow::paged_capture::DiagnosticSelectedCapture>,
) -> Result<ProtectedPagedTargetSelection> {
    let owner = context
        .windows_aliases()
        .context("actual Windows source alias owner absent")?;
    ensure!(
        mapped.uses_alias_owner(&owner) && aliases.len() as u64 == owner.len(),
        "alias constructor does not cover the original Windows source plan"
    );
    let digest = mapped.semantic_digest();
    aliases.require_scope(
        &pair,
        context.resource_admission().source_inspection_sha256,
        digest,
    )?;
    let aliases = WindowsAliasSelection {
        constructor: aliases,
        owner,
        digest,
    };
    let mut scoped = ScopedSourceContext::Dedicated(context);
    observe_and_select_scoped(
        &mut scoped,
        target,
        pair,
        expected,
        capture_group,
        output,
        events,
        Some(aliases),
        None,
        |scoped, target, expected, routes, scope, closing, native_events| match scoped {
            ScopedSourceContext::Dedicated(context) => consume(
                context,
                target,
                expected,
                routes,
                scope,
                closing,
                native_events,
            ),
            ScopedSourceContext::Partition(_) => {
                anyhow::bail!("Windows alias observer received an ordinary partition source")
            }
        },
    )
}

struct WindowsAliasSelection<'a> {
    constructor: &'a Arc<n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>,
    owner: Arc<crate::boot_alias::WindowsAliasDomain>,
    digest: [u8; 32],
}

pub(crate) fn observe_and_select_paged_optional_windows_aliases(
    context: &mut crate::general_source_admission::resource::ResourceSourceContext,
    target: &mut n2r_win32::GeneralFrozenPartition,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    expected: &PagedExpectedTree,
    capture_group: &ArtifactGroupPermit,
    output: &Path,
    events: &mut Vec<n2r_win32::NativeEvent>,
    aliases: Option<(
        &Arc<n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>,
        &crate::boot_alias::WindowsAliasNativeDomain<'_>,
    )>,
    consume: impl FnOnce(
        &mut crate::general_source_admission::resource::ResourceSourceContext,
        &mut n2r_win32::GeneralFrozenPartition,
        &PagedExpectedTree,
        crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
        &PagedTargetScope,
        &mut dyn crate::general_shadow::source_backed::ClosingShadowBytes,
        &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<crate::general_shadow::paged_capture::DiagnosticSelectedCapture>,
) -> Result<ProtectedPagedTargetSelection> {
    if let Some((verified, mapped)) = aliases {
        observe_and_select_paged_windows_aliases(
            context,
            target,
            pair,
            expected,
            capture_group,
            output,
            events,
            verified,
            mapped,
            consume,
        )
    } else {
        observe_and_select_paged(
            context,
            target,
            pair,
            expected,
            capture_group,
            output,
            events,
            consume,
        )
    }
}

pub(crate) fn observe_and_select_paged_optional_windows_aliases_with_tails(
    context: &mut crate::general_source_admission::resource::ResourceSourceContext,
    target: &mut n2r_win32::GeneralFrozenPartition,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    expected: &PagedExpectedTree,
    capture_group: &ArtifactGroupPermit,
    output: &Path,
    events: &mut Vec<n2r_win32::NativeEvent>,
    aliases: Option<(
        &Arc<n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>,
        &crate::boot_alias::WindowsAliasNativeDomain<'_>,
    )>,
    supplied_tails: Option<&SortedRecordStore>,
    consume: impl FnOnce(
        &mut crate::general_source_admission::resource::ResourceSourceContext,
        &mut n2r_win32::GeneralFrozenPartition,
        &PagedExpectedTree,
        crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
        &PagedTargetScope,
        &mut dyn crate::general_shadow::source_backed::ClosingShadowBytes,
        &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<crate::general_shadow::paged_capture::DiagnosticSelectedCapture>,
) -> Result<ProtectedPagedTargetSelection> {
    let selection = if let Some((verified, mapped)) = aliases {
        let owner = context
            .windows_aliases()
            .context("actual Windows source alias owner absent")?;
        ensure!(
            mapped.uses_alias_owner(&owner) && verified.len() as u64 == owner.len(),
            "alias constructor does not cover the original Windows source plan"
        );
        let digest = mapped.semantic_digest();
        verified.require_scope(
            &pair,
            context.resource_admission().source_inspection_sha256,
            digest,
        )?;
        Some(WindowsAliasSelection {
            constructor: verified,
            owner,
            digest,
        })
    } else {
        None
    };
    let mut scoped = ScopedSourceContext::Dedicated(context);
    observe_and_select_scoped(
        &mut scoped,
        target,
        pair,
        expected,
        capture_group,
        output,
        events,
        selection,
        supplied_tails,
        |scoped, target, expected, routes, scope, closing, native_events| match scoped {
            ScopedSourceContext::Dedicated(context) => consume(
                context,
                target,
                expected,
                routes,
                scope,
                closing,
                native_events,
            ),
            ScopedSourceContext::Partition(_) => {
                anyhow::bail!("dedicated target callback received partition source")
            }
        },
    )
}

pub(crate) fn observe_and_select_partition_paged(
    context: &mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
    target: &mut n2r_win32::GeneralFrozenPartition,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    expected: &PagedExpectedTree,
    capture_group: &ArtifactGroupPermit,
    output: &Path,
    events: &mut Vec<n2r_win32::NativeEvent>,
    consume: impl FnOnce(
        &mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        &mut n2r_win32::GeneralFrozenPartition,
        &PagedExpectedTree,
        crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
        &PagedTargetScope,
        &mut dyn crate::general_shadow::source_backed::ClosingShadowBytes,
        &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<crate::general_shadow::paged_capture::DiagnosticSelectedCapture>,
) -> Result<ProtectedPagedTargetSelection> {
    let mut scoped = ScopedSourceContext::Partition(context);
    observe_and_select_scoped(
        &mut scoped,
        target,
        pair,
        expected,
        capture_group,
        output,
        events,
        None,
        None,
        |scoped, target, expected, routes, scope, closing, native_events| match scoped {
            ScopedSourceContext::Partition(context) => consume(
                context,
                target,
                expected,
                routes,
                scope,
                closing,
                native_events,
            ),
            ScopedSourceContext::Dedicated(_) => {
                anyhow::bail!("partition target callback received dedicated source")
            }
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn observe_and_select_scoped(
    context: &mut ScopedSourceContext<'_>,
    target: &mut n2r_win32::GeneralFrozenPartition,
    pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
    expected: &PagedExpectedTree,
    capture_group: &ArtifactGroupPermit,
    output: &Path,
    events: &mut Vec<n2r_win32::NativeEvent>,
    aliases: Option<WindowsAliasSelection<'_>>,
    supplied_tails: Option<&SortedRecordStore>,
    consume: impl FnOnce(
        &mut ScopedSourceContext<'_>,
        &mut n2r_win32::GeneralFrozenPartition,
        &PagedExpectedTree,
        crate::general_shadow::paged_candidate::PagedPayloadRoutes<'_>,
        &PagedTargetScope,
        &mut dyn crate::general_shadow::source_backed::ClosingShadowBytes,
        &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<crate::general_shadow::paged_capture::DiagnosticSelectedCapture>,
) -> Result<ProtectedPagedTargetSelection> {
    let admission = context.resource_admission();
    let resources = crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission));
    let arena = context
        .arena()
        .context("target requires the actual cross-stage source arena")?
        .clone();
    ensure!(
        capture_group.group() == ArtifactGroup::Capture
            && capture_group.arena().same_arena(&arena)
            && context.source_group_seal().is_some()
            && context.native_group_seal().is_some(),
        "target group does not share the closed source/native arena"
    );
    pair.validate_with_resource_profile(resources.native_profile())?;
    ensure!(
        target.binding() == &pair.shadow,
        "actual frozen target association differs"
    );
    expected.require_resource_owner(admission)?;
    expected.require_shared_memory(&arena)?;
    // The walks' rows that have no room in memory go to files of the
    // capture's group, kept as long as its other files.
    let spilled = super::paged_memory::SpilledFiles::default();
    let memory = super::paged_memory::ArenaReportStorage::new(
        super::paged_memory::ArenaReportMemory(arena),
        capture_group.clone(),
        output,
        std::sync::Arc::clone(&spilled),
    );
    context.recheck_source(events)?;
    let source_before = context.source_state(&pair, events)?;
    source_before.require_excluded()?;
    let target_before = target.state(events)?;
    ensure!(
        target_before.disk_attributes == 3,
        "protected target requires both frozen disks"
    );
    ensure!(!output.exists(), "fresh target scope directory required");
    std::fs::create_dir(output)?;
    let scratch = SourceScratch::new_auxiliary_in_arena(
        context.inspection().budget(),
        capture_group.clone(),
    )?;
    let projection_dir = output.join("source-projection");
    std::fs::create_dir(&projection_dir)?;
    // The projection must retain the exact admitted expected-page budget;
    // the shared capture group can be larger for the later selection files.
    let projection_scratch = SourceScratch::new_bounded_auxiliary_in_arena(
        context.inspection().budget(),
        capture_group.clone(),
    )?;
    // The expected tree was derived from the held source evidence when it was
    // built, and both have been held since. Deriving it all over again here
    // only to compare the two (a minute at 26,000 objects) repeats a
    // deterministic computation on the same inputs; under the check-once
    // policy it is not repeated.
    let source_projection = if n2r_win32::verify_policy::checks_once() {
        None
    } else {
        n2r_win32::perf::step("derive source projection");
        let source_projection =
            context.derive_projection(admission, &projection_dir, &projection_scratch)?;
        ensure!(
            crate::general_qualification::pretty_json_sha256(&source_projection)?
                == expected.semantic_sha256(),
            "held expected pages differ from the actual source/native projection"
        );
        // No later stage decodes this independently compared projection. Retain
        // its real immutable files and revalidation owner, releasing only the
        // now-unused object decoding workspace.
        Some(source_projection.into_revalidation_owner()?)
    };
    n2r_win32::perf::step("capture source tails");
    let source_tails = context.with_bytes(
        admission,
        expected.logical_bytes().max(1),
        events,
        |bytes| {
            SourceTailProvider::capture_reusing(
                bytes,
                expected,
                &output.join("source-tails"),
                &scratch,
                supplied_tails,
            )
        },
    )?;
    // Source projection and tail capture carry their own row/name/writer
    // leases. Their temporary source adapter has now closed, before the
    // additional workspace needed by the following native target operations.
    let stage_ram_bytes = STAGE_ROUTE_WORKSPACE
        .checked_add(crate::ntfs_inspect::SESSION_READ_BYTES as u64)
        .and_then(|n| n.checked_add(CLOSING_READ_WORKSPACE))
        .context("target stage RAM overflow")?;
    let stage_ram = scratch.lease_ram(stage_ram_bytes)?;
    let result_budget = result_budget(&source_tails, &pair, &scratch)?;
    let result_ram_bytes = u64::from(result_budget.max_page_bytes)
        .checked_mul(3)
        .and_then(|n| n.checked_add(65536 + 16384))
        .context("native residual owner RAM overflow")?;
    let input = PagedInputs(expected);
    let same_security = |a: &[u8], b: &[u8]| {
        crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b).map_err(io::Error::other)
    };
    // The native wrapper has at most 128 control events with <=64 KiB
    // replies, plus fixed-size disk-state clones. Keep a separate allowance
    // for those real owners; the SDK independently prepays indexes, root,
    // per-object queries/retained rows and the paged residual writer.
    let native_wrapper_ram = scratch.lease_ram(32 * 1024 * 1024)?;
    drop(stage_ram);
    let image = target.byte_len();
    // The shadow is observed twice, before and after its raw metadata is
    // read, and the two observations must agree. It is offline, read-only and
    // held throughout, so under the check-once policy it is observed once and
    // everything below comes from that one observation.
    let opening = if n2r_win32::verify_policy::checks_once() {
        None
    } else {
        let opening_result_ram = capture_group.arena().reserve_ram(result_ram_bytes)?;
        let prelim_path = output.join("opening-native-tails.pages");
        let prelim_permit =
            capture_group.reserve_file(&prelim_path, result_budget.max_file_bytes)?;
        n2r_win32::perf::step("walk shadow (opening)");
        let (preliminary, opening_aliases) = context.observe_target(
            target,
            pair.clone(),
            &input,
            &source_tails,
            prelim_permit.path(),
            result_budget,
            same_security,
            resources.native_profile(),
            &memory,
            aliases.as_ref().map(|a| a.constructor.as_ref()),
            events,
        )?;
        let stage_ram = scratch.lease_ram(stage_ram_bytes)?;
        let prelim_results = preliminary
            .report()
            .paged_residuals()
            .context("protected opening tail owner absent")?;
        let preliminary_lease = prelim_permit.verify_closed(prelim_results.sha256())?;
        // Route capture pays its own source session, row codec, native visitor
        // and bounded sort. Do not hold the unrelated raw/interval workspace
        // across those independently accounted allocations.
        drop(stage_ram);
        n2r_win32::perf::step("capture payload routes (opening)");
        let opening_routes = context.with_bytes(admission, 1, events, |bytes| {
            crate::general_shadow::paged_candidate::PagedPayloadRoutes::capture(
                &preliminary,
                expected,
                bytes,
                &output.join("opening-routes"),
                capture_group,
                aliases.as_ref().map(|a| a.constructor.as_ref()),
            )
        })?;
        let stage_ram = scratch.lease_ram(stage_ram_bytes)?;
        let (exclusions, route_sha) = route_intervals(
            &opening_routes,
            &output.join("route-exclusions"),
            image,
            &scratch,
        )?;
        n2r_win32::perf::step("find data already in place");
        let in_place = context.with_bytes(admission, 1, events, |bytes| {
            source_in_place(
                bytes,
                expected,
                &opening_routes,
                &output.join("in-place"),
                image,
                &scratch,
            )
        })?;
        let allocation = allocated(
            &preliminary,
            &output.join("opening-allocation"),
            image,
            &scratch,
        )?;
        ensure!(
            exclusions
                .subtract(
                    &allocation,
                    &output.join("bad-payload-allocation"),
                    &scratch,
                    *b"N2RTBAD1"
                )?
                .bytes
                == 0,
            "actual protected payload routes escape complete native allocation"
        );
        let opening_dir = output.join("opening-raw");
        std::fs::create_dir(&opening_dir)?;
        let (opening_anchors, opening_reads, _opening_error) =
            anchors(target, image, resources, &opening_dir, &scratch)?;
        for known in [&opening_anchors, &opening_reads] {
            ensure!(
                known
                    .subtract(
                        &exclusions,
                        &output.join(if std::ptr::eq(known, &opening_anchors) {
                            "opening-anchors-safe"
                        } else {
                            "opening-reads-safe"
                        }),
                        &scratch,
                        *b"N2RTSAF1"
                    )?
                    .bytes
                    == known.bytes,
                "raw metadata anchors/reads overlap excluded payload"
            );
        }
        let opening_required = union_rows(
            &[&allocation, &opening_anchors, &opening_reads],
            &output.join("opening-required"),
            image,
            &scratch,
            *b"N2RSEL01",
        )?;
        let consumed = opening_required.subtract(
            &exclusions,
            &output.join("consumed"),
            &scratch,
            *b"N2RTCON1",
        )?;
        n2r_win32::perf::step("read shadow metadata (opening)");
        let digest = PagedShadowClosing::new(target, &consumed, Some(capture_group.arena()))?
            .finish(target)?;
        // The opening report's complete rows are no longer consumed below. Keep
        // its closed artifact owner and the exact serialized allocation digest,
        // then release the decoded rows before collecting the closing report.
        ensure!(
            preliminary.report().native().retained_rows_ram_accounted(),
            "protected opening report lacks actual retained-row RAM leases"
        );
        ensure!(
            preliminary.before() == &target_before
                && preliminary.after() == &target_before
                && preliminary.observed_readonly().disk_attributes == 2
                && preliminary.report().pair() == &pair,
            "protected opening target identity/exclusion changed"
        );
        let allocation_sha256 = crate::general_qualification::pretty_json_sha256(
            &preliminary.report().native().metadata_allocation.as_ref(),
        )?;
        opening_routes.retire()?;
        drop(preliminary);
        drop(opening_aliases);
        drop(stage_ram);
        Some((
            exclusions,
            route_sha,
            in_place,
            allocation,
            consumed,
            digest,
            allocation_sha256,
            preliminary_lease,
            opening_result_ram,
        ))
    };
    let closing_path = output.join("closing-native-tails.pages");
    let closing_result_ram = capture_group.arena().reserve_ram(result_ram_bytes)?;
    let closing_permit = capture_group.reserve_file(&closing_path, result_budget.max_file_bytes)?;
    n2r_win32::perf::step("walk shadow (closing)");
    let (native, windows_aliases) = context.observe_target(
        target,
        pair.clone(),
        &input,
        &source_tails,
        closing_permit.path(),
        result_budget,
        same_security,
        resources.native_profile(),
        &memory,
        aliases.as_ref().map(|a| a.constructor.as_ref()),
        events,
    )?;
    let stage_ram = scratch.lease_ram(stage_ram_bytes)?;
    let closing_results = native
        .report()
        .paged_residuals()
        .context("protected closing tail owner absent")?;
    let closing_lease = closing_permit.verify_closed(closing_results.sha256())?;
    drop(stage_ram);
    n2r_win32::perf::step("capture payload routes (closing)");
    let closing_routes = context.with_bytes(admission, 1, events, |bytes| {
        crate::general_shadow::paged_candidate::PagedPayloadRoutes::capture(
            &native,
            expected,
            bytes,
            &output.join("closing-routes"),
            capture_group,
            aliases.as_ref().map(|a| a.constructor.as_ref()),
        )
    })?;
    let _stage_ram = scratch.lease_ram(stage_ram_bytes)?;
    let (closing_exclusions, closing_route_sha) = route_intervals(
        &closing_routes,
        &output.join("closing-route-exclusions"),
        image,
        &scratch,
    )?;
    // Keep the exact closing routing owner for the capture consumer.
    let closing_allocation =
        allocated(&native, &output.join("closing-allocation"), image, &scratch)?;
    let (
        exclusions,
        in_place,
        opening_consumed,
        opening_digest,
        mut native_leases,
        mut native_result_ram,
    ) = match opening {
        Some((
            exclusions,
            route_sha,
            in_place,
            allocation,
            consumed,
            digest,
            allocation_sha256,
            lease,
            ram,
        )) => {
            ensure!(
                route_sha == closing_route_sha && exclusions.same(&closing_exclusions)?,
                "protected native stream IDs/maps changed during raw bracket"
            );
            ensure!(
                allocation.same(&closing_allocation)?
                    && allocation_sha256
                        == crate::general_qualification::pretty_json_sha256(
                            &native.report().native().metadata_allocation.as_ref(),
                        )?,
                "protected complete allocation changed during raw bracket"
            );
            (
                exclusions,
                in_place,
                Some(consumed),
                Some(digest),
                vec![lease],
                vec![ram],
            )
        }
        None => {
            n2r_win32::perf::step("find data already in place");
            let in_place = context.with_bytes(admission, 1, events, |bytes| {
                source_in_place(
                    bytes,
                    expected,
                    &closing_routes,
                    &output.join("in-place"),
                    image,
                    &scratch,
                )
            })?;
            ensure!(
                closing_exclusions
                    .subtract(
                        &closing_allocation,
                        &output.join("bad-payload-allocation"),
                        &scratch,
                        *b"N2RTBAD1"
                    )?
                    .bytes
                    == 0,
                "actual protected payload routes escape complete native allocation"
            );
            n2r_win32::perf::step("read raw metadata anchors");
            (
                closing_exclusions,
                in_place,
                None,
                None,
                Vec::new(),
                Vec::new(),
            )
        }
    };
    native_leases.push(closing_lease);
    native_result_ram.push(closing_result_ram);
    let closing_dir = output.join("closing-raw");
    std::fs::create_dir(&closing_dir)?;
    let (closing_anchors, closing_reads, _closing_error) =
        anchors(target, image, resources, &closing_dir, &scratch)?;
    for (name, known) in [
        ("closing-anchors-safe", &closing_anchors),
        ("closing-reads-safe", &closing_reads),
    ] {
        ensure!(
            known
                .subtract(&exclusions, &output.join(name), &scratch, *b"N2RTSAF1")?
                .bytes
                == known.bytes,
            "closing raw metadata anchors/reads overlap excluded payload"
        );
    }
    let required = union_rows(
        &[&closing_allocation, &closing_anchors, &closing_reads],
        &output.join("required"),
        image,
        &scratch,
        *b"N2RSEL01",
    )?;
    let closing_consumed = required.subtract(
        &exclusions,
        &output.join("closing-consumed"),
        &scratch,
        *b"N2RTCON1",
    )?;
    let consumed = match opening_consumed {
        Some(consumed) => {
            ensure!(
                closing_consumed
                    .subtract(
                        &consumed,
                        &output.join("unbracketed"),
                        &scratch,
                        *b"N2RTBAD1"
                    )?
                    .bytes
                    == 0,
                "closing target metadata requires unbracketed raw bytes"
            );
            consumed
        }
        None => closing_consumed,
    };
    let compared =
        required.subtract(&in_place, &output.join("compared"), &scratch, *b"N2RSEL01")?;
    ensure!(
        in_place
            .subtract(
                &required,
                &output.join("unselected-in-place"),
                &scratch,
                *b"N2RTBAD1"
            )?
            .bytes
            == 0,
        "in-place omission escapes actual required selection"
    );
    // Charge the small Arc control block, both live Arc values and the token
    // before allocation. Its identity never enters a serialized receipt.
    let identity_ram = scratch.lease_ram(128)?;
    let source_owner = context.source_owner_identity();
    let scope = PagedTargetScope {
        required:
            crate::general_shadow::paged_capture::DiagnosticCaptureSelection::from_held_store(
                required.store,
                image,
            )?,
        compared:
            crate::general_shadow::paged_capture::DiagnosticCaptureSelection::from_held_store(
                compared.store,
                image,
            )?,
        in_place,
        consumed,
        expected_tree_sha256: expected.semantic_sha256().to_owned(),
        source_inspection_sha256: context.inspection_sha256().to_owned(),
        pair: pair.clone(),
        identity: Arc::new(CaptureScopeIdentity { _ram: identity_ram }),
        native_report: native.report().native_observation(),
        source_owner,
        _ram: scratch.lease_ram(16 * 1024)?,
    };
    // The capture candidate and reducer independently pay for their source
    // session, decoded object/routes and I/O buffers. Only the closing reader
    // below needs a buffer from this layer during consume().
    let _closing_read_ram = scratch.lease_ram(CLOSING_READ_WORKSPACE)?;
    drop(_stage_ram);
    n2r_win32::perf::step("compare shadow with source");
    let mut closing =
        PagedShadowClosing::new(target, &scope.consumed, Some(capture_group.arena()))?;
    let captured = consume(
        context,
        target,
        expected,
        closing_routes,
        &scope,
        &mut closing,
        events,
    )?;
    ensure!(
        captured.is_for_scope(&scope),
        "consumer returned a capture from another or unqualified target scope"
    );
    n2r_win32::perf::step("read shadow metadata (closing)");
    let closing = closing.finish(target)?;
    if let Some(opening) = &opening_digest {
        ensure!(
            opening.0 == closing.0 && opening.1 == closing.1,
            "protected target consumed bytes changed across native observation/capture"
        );
    }
    ensure!(
        native.report().native().retained_rows_ram_accounted(),
        "protected closing report lacks actual retained-row RAM leases"
    );
    ensure!(
        native.before() == &target_before
            && native.after() == &target_before
            && native.observed_readonly().disk_attributes == 2
            && native.report().pair() == &pair,
        "protected closing target identity/exclusion changed"
    );
    ensure!(
        target.state(events)? == target_before,
        "frozen target changed during selection/capture"
    );
    scope.revalidate()?;
    source_tails.revalidate()?;
    if let Some(projection) = &source_projection {
        projection.revalidate()?;
    }
    expected.require_resource_owner(admission)?;
    context.recheck_source(events)?;
    ensure!(
        context.source_state(&pair, events)?.same(&source_before),
        "frozen source changed during target selection/capture"
    );
    Ok(ProtectedPagedTargetSelection {
        native,
        windows_aliases,
        windows_alias_owner: aliases.as_ref().map(|a| Arc::clone(&a.owner)),
        windows_alias_digest: aliases.as_ref().map(|a| a.digest),
        scope,
        captured,
        source_projection,
        source_tails,
        _native_leases: native_leases,
        _spilled_rows: spilled,
        _native_result_ram: native_result_ram,
        _scratch: scratch,
        opening_sha256: opening_digest.map_or_else(|| closing.0.clone(), |opening| opening.0),
        closing_sha256: closing.0,
        raw_consumed_bytes: closing.1,
        raw_reused_bytes: closing.2,
        _native_wrapper_ram: native_wrapper_ram,
    })
}
impl LayoutResidualProvider for SourceTailProvider {
    fn len(&self) -> u64 {
        self.store.len()
    }
    fn expectation(&self, ordinal: u64) -> io::Result<LayoutResidualExpectation> {
        self.store.get(ordinal).map_err(io::Error::other)
    }
    fn file_sha256(&self) -> &str {
        &self.pin_sha256
    }
    fn revalidate(&self) -> io::Result<()> {
        self.admission.validate()?;
        self.store.revalidate().map_err(io::Error::other)
    }
}
