//! Bounded selected capture over actual frozen-source candidate bytes.
//! A generic selection store is diagnostic only. No activation constructor or
//! conversion into the legacy DeltaLayout/SelectedPlan exists here.
use super::{
    capture_index::{CaptureBatchRange, CaptureIndexRange, ClosedCaptureIndex, OwnedCaptureIndex},
    paged_candidate::PagedSourceBackedCandidateWithScope,
    source_backed::{CaptureBudget, CaptureProgress, ChangedClassCounters, ReadCounts},
};
use crate::{
    ntfs_inspect::{
        paged_storage::{SourceRamLease, SourceScratch},
        record_store::{RecordStorePin, SortedRecordStore},
    },
    refs_write_set::ByteRange,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::reference_file::ReferenceFileSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};

const CHUNK: usize = crate::ntfs_inspect::SESSION_READ_BYTES;
const GRANULE: usize = 4096;
const SELECTED_DIGEST: &str = "sha256-over-frames-and-xxh3-128-per-compared-chunk";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeWire {
    offset: u64,
    length: u64,
}

/// An authenticated, complete store of the explicitly selected ranges. Its
/// constructor proves only those rows, never required-byte graph completeness.
/// Production activation must additionally bind an opaque frozen target proof.
pub(crate) struct DiagnosticCaptureSelection {
    store: SortedRecordStore,
    image: u64,
    bytes: u64,
}
impl DiagnosticCaptureSelection {
    pub(crate) fn from_held_store(store: SortedRecordStore, image: u64) -> Result<Self> {
        ensure!(
            image > 0
                && image.is_multiple_of(4096)
                && image <= i64::MAX as u64
                && store.pin().purpose == *b"N2RSEL01",
            "diagnostic selection resource domain differs"
        );
        let (mut end, mut bytes) = (0u64, 0u64);
        for ordinal in 0..store.len() {
            let range: RangeWire = store.get(ordinal)?;
            let next = range
                .offset
                .checked_add(range.length)
                .context("selection range overflow")?;
            let mut key = [0; 16];
            key[..8].copy_from_slice(&range.offset.to_be_bytes());
            ensure!(
                range.length > 0
                    && range.length.is_multiple_of(4096)
                    && range.offset.is_multiple_of(4096)
                    && range.offset >= end
                    && next <= image
                    && store.key(ordinal)? == key,
                "complete diagnostic selection order/alignment/partition bounds differ"
            );
            end = next;
            bytes = bytes
                .checked_add(range.length)
                .context("selection byte count overflow")?;
        }
        ensure!(bytes != 0, "empty diagnostic selection");
        store.revalidate()?;
        Ok(Self {
            store,
            image,
            bytes,
        })
    }
    fn range(&self, ordinal: u64) -> Result<ByteRange> {
        let r: RangeWire = self.store.get(ordinal)?;
        Ok(ByteRange {
            offset: r.offset,
            length: r.length,
        })
    }
    pub(crate) fn covers(&self, offset: u64, length: u64) -> Result<bool> {
        let end = offset
            .checked_add(length)
            .context("selection coverage overflow")?;
        let (mut low, mut high) = (0, self.store.len());
        while low < high {
            let middle = low + (high - low) / 2;
            let r = self.range(middle)?;
            if r.offset + r.length <= offset {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut cursor = offset;
        while cursor < end {
            if low == self.store.len() {
                return Ok(false);
            }
            let r = self.range(low)?;
            if r.offset > cursor {
                return Ok(false);
            }
            cursor = end.min(r.offset + r.length);
            low += 1;
        }
        Ok(true)
    }
    pub(crate) fn pin(&self) -> &RecordStorePin {
        self.store.pin()
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.store.revalidate()
    }
    pub(crate) fn covered_bytes(&self, offset: u64, length: u64) -> Result<u64> {
        let end = offset
            .checked_add(length)
            .context("selection intersection overflow")?;
        let (mut low, mut high) = (0, self.store.len());
        while low < high {
            let middle = low + (high - low) / 2;
            let r = self.range(middle)?;
            if r.offset + r.length <= offset {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut bytes = 0u64;
        while low < self.store.len() {
            let r = self.range(low)?;
            if r.offset >= end {
                break;
            }
            bytes = bytes
                .checked_add(
                    end.min(r.offset + r.length)
                        .saturating_sub(offset.max(r.offset)),
                )
                .context("selection intersection total overflow")?;
            low += 1;
        }
        Ok(bytes)
    }
}

#[derive(Serialize)]
pub(crate) struct LiteralCapturePin {
    pub path: PathBuf,
    /// The digest of the complete literal file, in hex, of the algorithm
    /// `digest` names. The field keeps its historical name.
    pub sha256: String,
    pub digest: n2r_win32::bulk_digest::Algorithm,
    pub snapshot: ReferenceFileSnapshot,
}
pub(crate) struct ClosedCaptureLiteral {
    file: RefCell<File>,
    pin: LiteralCapturePin,
    limit: u64,
    _ram: SourceRamLease,
    artifact: crate::artifact_arena::ArtifactLease,
}
impl ClosedCaptureLiteral {
    pub(crate) fn pin(&self) -> &LiteralCapturePin {
        &self.pin
    }
    /// Same-held-file metadata only. This never hashes or scans literal bytes
    /// and never replaces the stricter capture/admission revalidation.
    pub(crate) fn observe_allocation_bytes(&self) -> Result<u64> {
        let file = self
            .file
            .try_borrow()
            .map_err(|_| anyhow::anyhow!("capture literal metadata handle already borrowed"))?;
        let current =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, self.limit)?;
        let old = &self.pin.snapshot;
        ensure!(
            current.final_path == old.final_path
                && current.volume_serial_number == old.volume_serial_number
                && current.file_id_128 == old.file_id_128
                && current.file_bytes == old.file_bytes
                && current.file_attributes == old.file_attributes
                && current.number_of_links == old.number_of_links,
            "capture literal metadata identity differs from actual closed owner"
        );
        Ok(current.allocation_bytes)
    }
    pub(crate) fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        ensure!(
            offset
                .checked_add(output.len() as u64)
                .is_some_and(|end| end <= self.pin.snapshot.file_bytes),
            "literal capture read escapes closed backing"
        );
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(output)?;
        Ok(())
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.revalidate_using(|artifact| artifact.revalidate())
    }
    fn revalidate_with_arena_witness(
        &self,
        witness: &crate::artifact_arena::PreparedArenaRevalidation<'_>,
    ) -> Result<()> {
        self.revalidate_using(|artifact| artifact.revalidate_with_arena_witness(witness))
    }
    fn revalidate_using(
        &self,
        validate_artifact: impl FnOnce(&crate::artifact_arena::ArtifactLease) -> Result<()>,
    ) -> Result<()> {
        let mut file = self.file.borrow_mut();
        let position = file.stream_position()?;
        let modified = file.metadata()?.modified()?;
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, self.limit)?
                == self.pin.snapshot
                && self.artifact.snapshot() == &self.pin.snapshot
                && self.artifact.sha256() == self.pin.sha256,
            "closed capture literal and actual hashed artifact identities differ"
        );
        // The actual same-file artifact owner either hashes here or proves
        // membership in an immediate exhaustive arena hashing boundary. The
        // literal handle is a readonly duplicate of that same file object.
        // Restore its cursor on either result before propagating a failure.
        let verified = validate_artifact(&self.artifact);
        file.seek(SeekFrom::Start(position))?;
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, self.limit)?
                == self.pin.snapshot
                && file.metadata()?.modified()? == modified,
            "closed capture literal identity changed around artifact validation"
        );
        verified
    }
}

/// Closed capture observations only. Its index/literal owners stay alive for
/// later validation; no method grants source writes or journal activation.
pub(crate) struct DiagnosticSelectedCapture {
    index: ClosedCaptureIndex,
    literal: ClosedCaptureLiteral,
    selection: RecordStorePin,
    summary: serde_json::Value,
    scope_identity:
        Option<std::sync::Arc<crate::general_composite_target::paged::CaptureScopeIdentity>>,
}

/// Ephemeral proof that this exact held capture passed its complete index and
/// literal-content hash at the current operation boundary. It cannot be
/// deserialized or created from saved hashes, and never grants write access.
pub(crate) struct CaptureRevalidation<'a> {
    capture: &'a DiagnosticSelectedCapture,
}
impl CaptureRevalidation<'_> {
    pub(crate) fn require_capture(&self, capture: &DiagnosticSelectedCapture) -> Result<()> {
        ensure!(
            std::ptr::eq(self.capture, capture),
            "capture witness owner differs"
        );
        Ok(())
    }
}
impl DiagnosticSelectedCapture {
    pub(crate) fn is_for_scope(
        &self,
        scope: &crate::general_composite_target::paged::PagedTargetScope,
    ) -> bool {
        self.scope_identity
            .as_ref()
            .is_some_and(|owned| std::sync::Arc::ptr_eq(owned, &scope.capture_identity()))
    }
    pub(crate) fn index(&self) -> &ClosedCaptureIndex {
        &self.index
    }
    pub(crate) fn literal(&self) -> &ClosedCaptureLiteral {
        &self.literal
    }
    pub(crate) fn summary(&self) -> &serde_json::Value {
        &self.summary
    }
    pub(crate) fn selection_pin(&self) -> &RecordStorePin {
        &self.selection
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.index.revalidate()?;
        self.literal.revalidate()
    }

    /// Run one synchronous, read-only boundary under a fresh full content
    /// check. The higher-ranked callback prevents its short-lived witness
    /// from being returned or retained for a later operation.
    pub(crate) fn with_revalidation<T>(
        &self,
        callback: impl for<'boundary> FnOnce(&'boundary CaptureRevalidation<'boundary>) -> Result<T>,
    ) -> Result<T> {
        self.revalidate()?;
        let witness = CaptureRevalidation { capture: self };
        callback(&witness)
    }

    /// Reuse the complete literal hash only inside an already active closed-
    /// arena before/after boundary covering this exact runtime artifact owner.
    /// Keep the index's full structural checks and both actual literal-handle
    /// identity bookends. The enclosing arena always hashes all bytes again.
    pub(crate) fn with_arena_revalidation<T>(
        &self,
        arena: &crate::artifact_arena::PreparedArenaRevalidation<'_>,
        callback: impl for<'boundary> FnOnce(&'boundary CaptureRevalidation<'boundary>) -> Result<T>,
    ) -> Result<T> {
        self.index.revalidate()?;
        self.literal.revalidate_with_arena_witness(arena)?;
        let witness = CaptureRevalidation { capture: self };
        let result = callback(&witness);
        self.index.revalidate()?;
        self.literal.revalidate_with_arena_witness(arena)?;
        result
    }
}

fn add(target: &mut u64, amount: u64) -> Result<()> {
    *target = target
        .checked_add(amount)
        .context("paged capture counter overflow")?;
    Ok(())
}
fn validate_budget(budget: CaptureBudget, image: u64) -> Result<()> {
    ensure!(
        budget.max_changed_bytes > 0
            && budget.max_changed_bytes.is_multiple_of(4096)
            && budget.max_changed_bytes <= image
            && budget.max_journal_bytes >= n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE
            && budget.max_literal_backing_bytes <= i64::MAX as u64
            && budget.minimum_free_bytes > 0,
        "resource capture budget/geometry differs"
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn progress(
    budget: CaptureBudget,
    changed: u64,
    old_zero: u64,
    source_free: u64,
    literal: u64,
    append: u64,
    copy_bytes: u64,
    new_zero_bytes: u64,
    ranges: u64,
    index_append: u64,
) -> Result<CaptureProgress> {
    let next_literal = literal
        .checked_add(append)
        .context("literal projection overflow")?;
    let stored_old = if budget.selected_capacity_policy.is_conservative() {
        changed
    } else {
        changed
            .checked_sub(old_zero)
            .and_then(|n| n.checked_sub(source_free))
            .context("OLD omission credit overlap")?
    };
    // Unlike the legacy fixed metadata reserve admission, each actual row is
    // conservatively charged too. This is a projection, not a journal format.
    let metadata = n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE
        .checked_add(
            ranges
                .checked_mul(104)
                .context("journal row projection overflow")?,
        )
        .context("journal metadata projection overflow")?;
    let journal = stored_old
        .checked_add(next_literal)
        .and_then(|n| n.checked_add(source_free / 256))
        .and_then(|n| n.checked_add(metadata))
        .context("journal projection overflow")?;
    let index = 256u64
        .checked_add(
            ranges
                .checked_mul(80)
                .context("index projection overflow")?,
        )
        .context("index projection overflow")?;
    let combined = journal
        .checked_add(next_literal)
        .and_then(|n| n.checked_add(index))
        .context("combined projection overflow")?;
    ensure!(
        changed <= budget.max_changed_bytes
            && next_literal <= budget.max_literal_backing_bytes
            && journal <= budget.max_journal_bytes
            && combined <= budget.max_combined_backing_and_journal_bytes,
        "paged capture capacity exhausted before accepting changed bytes: projected_changed_bytes={changed}, max_changed_bytes={}, projected_literal_bytes={next_literal}, max_literal_backing_bytes={}, projected_copy_bytes={copy_bytes}, projected_new_zero_bytes={new_zero_bytes}, projected_old_zero_bytes={old_zero}, projected_source_free_bytes={source_free}, projected_journal_bytes={journal}, max_journal_bytes={}, projected_combined_bytes={combined}, max_combined_bytes={}; these are measured so far, not final requirements",
        budget.max_changed_bytes,
        budget.max_literal_backing_bytes,
        budget.max_journal_bytes,
        budget.max_combined_backing_and_journal_bytes
    );
    Ok(CaptureProgress {
        changed_bytes: changed,
        literal_backing_bytes: literal,
        next_append_bytes: append
            .checked_add(index_append)
            .context("capture append projection overflow")?,
        range_count: usize::try_from(ranges)?,
        projected_journal_bytes: journal,
        projected_combined_bytes: combined,
        minimum_free_bytes: budget.minimum_free_bytes,
        selected_capacity_policy: budget.selected_capacity_policy,
        old_zero_bytes: (!budget.selected_capacity_policy.is_conservative()).then_some(old_zero),
        source_free_bytes: budget
            .selected_capacity_policy
            .allows_source_free()
            .then_some(source_free),
    })
}

fn literal_file(path: &Path, index_path: &Path, limit: u64) -> Result<File> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            && !path
                .file_name()
                .context("literal capture filename absent")?
                .to_string_lossy()
                .contains([':', '\0']),
        "ordinary fresh literal capture path required"
    );
    // The index owns ordinary non-delete-shared ancestry for this same parent.
    ensure!(
        fs::canonicalize(path.parent().context("literal parent absent")?)?
            == fs::canonicalize(index_path.parent().context("index parent absent")?)?,
        "index/literal backing parents differ"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let snapshot =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, limit)?;
    ensure!(
        snapshot.file_bytes == 0,
        "literal capture file is not fresh"
    );
    Ok(file)
}

/// Actual V4 selected comparison with ZERO/COPY/literal backing. Selection
/// provenance remains diagnostic until an opaque target proof binds it. Root's
/// fresh capture caller owns the journal consumer; this function never writes
/// the source, opens a journal, changes protection or returns a legacy Vec plan.
pub(crate) fn capture_diagnostic_selected(
    mut candidate: PagedSourceBackedCandidateWithScope<'_, '_, '_>,
    selection: &DiagnosticCaptureSelection,
    literal_path: &Path,
    index_path: &Path,
    budget: CaptureBudget,
    guard: &mut dyn FnMut(CaptureProgress) -> Result<()>,
) -> Result<DiagnosticSelectedCapture> {
    capture_selected_inner(
        candidate,
        selection,
        literal_path,
        index_path,
        budget,
        guard,
        None,
    )
}

/// Only the live protected target producer can supply the in-place omission
/// owner. This remains diagnostic until the enclosing raw/source gates close.
pub(crate) fn capture_target_selected(
    candidate: PagedSourceBackedCandidateWithScope<'_, '_, '_>,
    scope: &crate::general_composite_target::paged::PagedTargetScope,
    literal_path: &Path,
    index_path: &Path,
    budget: CaptureBudget,
    guard: &mut dyn FnMut(CaptureProgress) -> Result<()>,
) -> Result<DiagnosticSelectedCapture> {
    capture_selected_inner(
        candidate,
        scope.compared(),
        literal_path,
        index_path,
        budget,
        guard,
        Some(scope),
    )
}

#[allow(clippy::too_many_arguments)]
fn capture_selected_inner(
    mut candidate: PagedSourceBackedCandidateWithScope<'_, '_, '_>,
    selection: &DiagnosticCaptureSelection,
    literal_path: &Path,
    index_path: &Path,
    budget: CaptureBudget,
    guard: &mut dyn FnMut(CaptureProgress) -> Result<()>,
    scope: Option<&crate::general_composite_target::paged::PagedTargetScope>,
) -> Result<DiagnosticSelectedCapture> {
    let image = candidate.byte_len();
    ensure!(
        selection.image == image,
        "selection/candidate partition differs"
    );
    validate_budget(budget, image)?;
    selection.store.revalidate()?;
    if let Some(scope) = scope {
        scope.revalidate()?;
        ensure!(
            scope.pair() == candidate.routes().pair()
                && scope.expected_tree_sha256() == candidate.expected_tree_sha256()
                && scope.matches_candidate(&candidate),
            "capture target scope differs from actual native candidate"
        );
    }
    for ordinal in 0..candidate.routes().len() {
        let route = candidate.routes().route(ordinal)?;
        ensure!(
            if let Some(scope) = scope {
                scope.covers_route(route.target_physical_offset(), route.length())?
            } else {
                selection.covers(route.target_physical_offset(), route.length())?
            },
            "selection omits actual measured payload route"
        );
    }
    let scratch: SourceScratch = candidate.capture_scratch();
    let capture_group = candidate.capture_group()?;
    let span_bytes = (crate::ntfs_inspect::MAX_DIRECT_READ_SPANS as u64)
        .checked_mul(64)
        .context("capture span RAM overflow")?;
    let _ram = scratch.lease_ram((2 * CHUNK + GRANULE) as u64 + span_bytes)?;
    let _allocation_ram = scratch.lease_ram(std::mem::size_of::<
        crate::ntfs_inspect::allocation_domain::AllocationCursor<'_>,
    >() as u64)?;
    let mut allocation = candidate.allocation_cursor()?;
    guard(progress(budget, 0, 0, 0, 0, 0, 0, 0, 0, 256)?)?;
    let mut capacity_guard_calls = 1u64;
    let mut capacity_batches = 0u64;
    let mut literal_growth_admissions = 0u64;
    let mut index_growth_admissions = 0u64;
    let mut index = OwnedCaptureIndex::create(index_path, image, &scratch, &capture_group)?;
    let mut literal_permit = capture_group.reserve_file(literal_path, 0)?;
    let literal_path = literal_permit.path().to_path_buf();
    let mut literal = literal_file(&literal_path, index_path, budget.max_literal_backing_bytes)?;
    let first_route = if candidate.routes().is_empty() {
        None
    } else {
        Some(candidate.routes().route(0)?.target_physical_offset())
    };
    let mut classes = ChangedClassCounters {
        first_route_destination_offset: first_route,
        ntfs_allocation_available: true,
        ..Default::default()
    };
    let (mut changed, mut packed, mut compared, mut old_zero, mut source_free) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut copied, mut new_zero_total) = (0u64, 0u64);
    let mut previous_free = false;
    let mut source_digest = Sha256::new();
    let mut candidate_digest = Sha256::new();
    // The digest of the literal bytes, as they are written: BLAKE3
    // (`n2r_win32::bulk_digest`). On a processor without SHA instructions a
    // SHA-256 of three gigabytes of literal bytes took ten seconds of this
    // step, and the gate before the first write to the source reads the file
    // again to compare it with this.
    let literal_digest = n2r_win32::bulk_digest::Algorithm::WRITTEN;
    let mut packed_digest = n2r_win32::bulk_digest::Hasher::new(literal_digest)?;
    let whole = selection.store.len() == 1
        && selection.range(0)?
            == ByteRange {
                offset: 0,
                length: image,
            };
    let mut raw_digest = if whole {
        Some(n2r_win32::sha256_native::Sha256::new()?)
    } else {
        None
    };
    let mut original = vec![0; CHUNK];
    let mut new_bytes = vec![0; CHUNK];
    let mut copy_check = [0; GRANULE];
    // One plan retains only this already-read comparison chunk. Pay its actual
    // bounded vector before allocation and retain the payment through drop.
    let maximum_batch = CHUNK / GRANULE;
    let batch_bytes = maximum_batch
        .checked_mul(std::mem::size_of::<CaptureBatchRange>())
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(256))
        .context("capture batch RAM overflow")?;
    let _batch_ram = scratch.lease_ram(batch_bytes as u64)?;
    let mut batch: Vec<CaptureBatchRange> = Vec::new();
    batch.try_reserve_exact(maximum_batch)?;
    ensure!(
        batch
            .capacity()
            .checked_mul(std::mem::size_of::<CaptureBatchRange>())
            .is_some_and(|n| n <= batch_bytes),
        "capture batch allocation exceeds its payment"
    );
    for ordinal in 0..selection.store.len() {
        let selected = selection.range(ordinal)?;
        source_digest.update(selected.offset.to_le_bytes());
        source_digest.update(selected.length.to_le_bytes());
        candidate_digest.update(selected.offset.to_le_bytes());
        candidate_digest.update(selected.length.to_le_bytes());
        let mut done = 0;
        while done < selected.length {
            let count = (selected.length - done).min(CHUNK as u64) as usize;
            let at = selected
                .offset
                .checked_add(done)
                .context("capture selected offset overflow")?;
            let chunk = candidate.read_capture_chunk(at, &mut new_bytes[..count], true)?;
            candidate.read_original_exact(at, &mut original[..count])?;
            source_digest.update(crate::parallel_digest::xxh3_128(&original[..count]));
            candidate_digest.update(crate::parallel_digest::xxh3_128(chunk.bytes()));
            if let Some(hash) = &mut raw_digest {
                hash.update(&original[..count])?;
            }
            batch.clear();
            let packed_before = packed;
            let ranges_before = index.len();
            let mut planned_ranges = ranges_before;
            let mut planned_tail = index.last_range();
            for local in (0..count).step_by(GRANULE) {
                let old = &original[local..local + GRANULE];
                let new = &chunk.bytes()[local..local + GRANULE];
                if old == new {
                    continue;
                }
                let destination = at + local as u64;
                let new_zero = new.iter().all(|b| *b == 0);
                let was_zero = old.iter().all(|b| *b == 0);
                let ownership = allocation.granule(destination)?;
                let free = budget.selected_capacity_policy.allows_source_free()
                    && ownership.is_source_free;
                let mut copy = None;
                if !new_zero {
                    if let Some(source) = candidate.copy_source_for(&chunk, local, GRANULE)? {
                        if source.is_multiple_of(4096)
                            && index.covers_prior_with_batch(
                                &batch,
                                source,
                                GRANULE as u64,
                                destination,
                            )?
                        {
                            candidate.raw_source().require_allocated_range(
                                source,
                                GRANULE as u64,
                                image,
                            )?;
                            if !candidate.reuse_copy_read(&chunk, local, source, GRANULE)? {
                                candidate.read_reference_exact(source, &mut copy_check)?;
                                ensure!(
                                    &copy_check[..] == new,
                                    "COPY source differs from actual candidate bytes"
                                );
                            }
                            copy = Some(source);
                        }
                    }
                }
                let range = CaptureIndexRange {
                    offset: destination,
                    length: GRANULE as u64,
                    packed_offset: packed,
                    new_is_zero: new_zero,
                    old_is_zero: was_zero,
                    old_is_source_free: free && !was_zero,
                    copy_source_offset: copy,
                };
                let previous = planned_tail;
                let may_extend = !budget.selected_capacity_policy.allows_source_free()
                    || (previous_free == free
                        && previous.is_none_or(|r| r.old_is_zero == was_zero));
                let (extends, projected) =
                    index.project_batch_range(previous, range, may_extend)?;
                let next_ranges = planned_ranges
                    .checked_add(u64::from(!extends))
                    .context("capture planned range overflow")?;
                let next_changed = changed
                    .checked_add(GRANULE as u64)
                    .context("changed byte count overflow")?;
                let mut next_zero = old_zero;
                if extends {
                    if let Some(previous) = previous {
                        if previous.old_is_zero {
                            next_zero -= previous.length;
                        }
                    }
                }
                if projected.old_is_zero {
                    add(&mut next_zero, projected.length)?;
                }
                let next_free = source_free
                    .checked_add(if free && !was_zero { GRANULE as u64 } else { 0 })
                    .context("source-free count overflow")?;
                let append = if !new_zero && copy.is_none() {
                    GRANULE as u64
                } else {
                    0
                };
                let next_copied = copied
                    .checked_add(if copy.is_some() { GRANULE as u64 } else { 0 })
                    .context("COPY byte count overflow")?;
                let next_new_zero = new_zero_total
                    .checked_add(if new_zero { GRANULE as u64 } else { 0 })
                    .context("new zero byte count overflow")?;
                // Preserve every exact granule budget/arithmetic refusal,
                // including OLD-zero credit lost when a prior tail extends.
                // The native guard runs once after this actual batch is known.
                let _ = progress(
                    budget,
                    next_changed,
                    next_zero,
                    next_free,
                    packed,
                    append,
                    next_copied,
                    next_new_zero,
                    next_ranges,
                    if extends { 0 } else { 80 },
                )?;
                ensure!(
                    batch.len() < maximum_batch,
                    "capture plan exceeds its paid granule bound"
                );
                batch.push(CaptureBatchRange {
                    range,
                    may_extend_previous: may_extend,
                    projected,
                    extends_previous: extends,
                });
                add(&mut packed, append)?;
                planned_ranges = next_ranges;
                planned_tail = Some(projected);
                changed = next_changed;
                old_zero = next_zero;
                source_free = next_free;
                copied = next_copied;
                new_zero_total = next_new_zero;
                previous_free = free;
                add(&mut classes.changed_bytes_total, GRANULE as u64)?;
                let allocated = if destination < 4096 || destination >= image - 4096 {
                    GRANULE as u64
                } else {
                    ownership.allocated_bytes
                };
                add(
                    &mut classes.changed_bytes_ntfs_allocated_destination,
                    allocated,
                )?;
                add(
                    &mut classes.changed_bytes_ntfs_free_destination,
                    GRANULE as u64 - allocated,
                )?;
                // Actual route membership is already checked by the candidate.
                let in_route = candidate.route_bytes_in(destination, GRANULE as u64)?;
                add(&mut classes.changed_bytes_in_payload_route, in_route)?;
                add(
                    &mut classes.changed_bytes_outside_routes,
                    GRANULE as u64 - in_route,
                )?;
                let below = first_route.map_or(GRANULE as u64, |first| {
                    first
                        .min(destination + GRANULE as u64)
                        .saturating_sub(destination)
                });
                add(
                    &mut classes.changed_bytes_below_first_route_destination,
                    below,
                )?;
                if new_zero {
                    add(&mut classes.changed_bytes_new_is_zero, GRANULE as u64)?;
                }
                if was_zero {
                    add(&mut classes.changed_bytes_old_is_zero, GRANULE as u64)?;
                }
            }
            if !batch.is_empty() {
                let literal_append = packed
                    .checked_sub(packed_before)
                    .context("capture batch literal accounting regressed")?;
                let additional_rows = planned_ranges
                    .checked_sub(ranges_before)
                    .context("capture batch index accounting regressed")?;
                let index_append = additional_rows
                    .checked_mul(80)
                    .context("capture batch index append overflow")?;
                // Reserve exact classified growth, not a worst-case chunk.
                // Tight volumes therefore need only the bytes this batch will
                // actually append. No writes precede all three admissions.
                guard(progress(
                    budget,
                    changed,
                    old_zero,
                    source_free,
                    packed_before,
                    literal_append,
                    copied,
                    new_zero_total,
                    planned_ranges,
                    index_append,
                )?)?;
                capacity_guard_calls = capacity_guard_calls.saturating_add(1);
                if literal_append != 0 {
                    literal_permit.extend(literal_append)?;
                    literal_growth_admissions = literal_growth_admissions.saturating_add(1);
                }
                index.reserve_batch_rows(additional_rows)?;
                if additional_rows != 0 {
                    index_growth_admissions = index_growth_admissions.saturating_add(1);
                }
                for planned in &batch {
                    // Actual pending tokens and COPY checks remain ordered:
                    // earlier planned OLD rows must now be genuinely accepted.
                    let pending = index.reserve_next(planned.range, planned.may_extend_previous)?;
                    ensure!(
                        pending.projected_range() == planned.projected
                            && pending.extends_previous() == planned.extends_previous,
                        "capture coalescing differs from its exact batch admission"
                    );
                    if !planned.range.new_is_zero && planned.range.copy_source_offset.is_none() {
                        let local = usize::try_from(planned.range.offset - at)?;
                        let bytes = &chunk.bytes()[local..local + GRANULE];
                        literal.write_all(bytes)?;
                        packed_digest.update(bytes)?;
                    }
                    index.append_accepted(pending)?;
                }
                index.finish_batch()?;
                ensure!(
                    index.len() == planned_ranges
                        && index.packed_bytes() == packed
                        && index.last_range() == planned_tail,
                    "actual capture acceptance differs from its admitted batch"
                );
                capacity_batches = capacity_batches.saturating_add(1);
            }
            done += count as u64;
            add(&mut compared, count as u64)?;
        }
    }
    ensure!(
        compared == selection.bytes && index.packed_bytes() == packed,
        "capture comparison/index/backing accounting differs"
    );
    literal.sync_all()?;
    let literal_hash = hex::encode(packed_digest.finish()?);
    // NTFS can keep speculative growth allocation on the writable FILE_OBJECT
    // even after its last writable handle is dropped. Normalize through this
    // exact writer before readonly duplication; EOF and the existing full
    // literal hash/arena allocation checks remain unchanged.
    {
        // Covers both bounded native GUID-path/snapshot observations while the
        // writer is normalized. Do not retain their heap buffers in the capture.
        let _allocation_ram = scratch.lease_ram(512 * 1024)?;
        let _allocation = n2r_win32::file_storage::normalize_allocation_at_eof(
            &literal,
            packed,
            budget.max_literal_backing_bytes,
            capture_group.arena().allocation_slack_bytes(),
        )
        .context("normalize owned capture literal allocation before sealing")?;
    }
    let readonly = n2r_win32::file_storage::duplicate_readonly(&literal)?;
    drop(literal);
    let snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
        &readonly,
        budget.max_literal_backing_bytes,
    )?;
    ensure!(
        snapshot.file_bytes == packed,
        "durable literal backing length differs"
    );
    // Bytes of the volume, hashed as they were written: held to that digest,
    // whatever they begin with.
    let artifact =
        literal_permit.verify_closed_handle_by(literal_digest, &readonly, &literal_hash)?;
    let literal = ClosedCaptureLiteral {
        file: RefCell::new(readonly),
        pin: LiteralCapturePin {
            path: literal_path,
            sha256: literal_hash,
            digest: literal_digest,
            snapshot,
        },
        limit: budget.max_literal_backing_bytes,
        _ram: scratch.lease_ram(65536)?,
        artifact,
    };
    literal.revalidate()?;
    let index = index.finish(&scratch)?;
    ensure!(
        index.pin().old_zero_bytes == old_zero && index.pin().source_free_bytes == source_free,
        "actual per-range OLD classification differs from capture accounting"
    );
    classes.changed_ranges = index.len();
    selection.store.revalidate()?;
    let counts: ReadCounts = candidate.finish()?;
    let raw_sha = match raw_digest {
        Some(hash) => Some(hex::encode(hash.finish()?)),
        None => None,
    };
    let summary = serde_json::json!({"schema_version":1,"kind":"diagnostic-paged-selected-capture",
        "selected_bytes_compared":compared,"equal_selected_bytes":compared-changed,"changed_bytes":changed,
        "packed_bytes":packed,"old_zero_bytes":old_zero,"source_free_bytes":source_free,
        "selected_digest":SELECTED_DIGEST,"source_selected_sha256":hex::encode(source_digest.finalize()),
        "candidate_selected_sha256":hex::encode(candidate_digest.finalize()),"source_raw_sha256":raw_sha,
        "index":index.pin(),"literal":literal.pin(),"selection":selection.pin(),"read_counts":counts,"changed_classes":classes,
        "capacity_admission":{"batches":capacity_batches,"guard_calls":capacity_guard_calls,
            "literal_growth_checks":literal_growth_admissions,"index_growth_checks":index_growth_admissions},
        "activation_authorized":false,"conversion_qualified":false,"source_payload_writes":0,
        "required_byte_completeness_verified":false,"journal_preparation_pending":true,
        "old_free_foreign_detection_hashes_pending":true,"journal_length_projection_is_authority":false});
    Ok(DiagnosticSelectedCapture {
        index,
        literal,
        selection: selection.pin().clone(),
        summary,
        scope_identity: scope.map(|scope| scope.capture_identity()),
    })
}
