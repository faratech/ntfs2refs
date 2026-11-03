//! Resource-bounded selected-journal layout derived from a held capture.
//!
//! This is a planning owner, not a target proof, journal ticket, or replay
//! authority. It retains the actual capture and a small disk-backed offset
//! index; it never deserializes authority from a saved pin or materializes the
//! complete range set in memory.
pub(crate) mod captured_candidate;
pub(crate) mod durable_anchor;
pub(crate) mod prepare;
pub(crate) mod reopen;

use super::{
    BODY, COPY_RECORD, FOOTER, FREE_DIGEST, GRANULE, HEADER, OLD_ZERO_RECORD, RECORD,
    REDUNDANT_BODY, SelectedMarkerProfile, ZERO_RECORD,
};
use crate::{
    artifact_arena::{ArtifactGroup, ArtifactGroupPermit, ArtifactLease},
    general_shadow::{
        capture_index::{CaptureIndexRange, ClosedCaptureIndex},
        paged_capture::DiagnosticSelectedCapture,
    },
    ntfs_inspect::paged_storage::{SourceRamLease, SourceScratch},
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};

const INDEX_HEADER: u64 = 128;
const INDEX_ROW: u64 = 8;
const INDEX_FOOTER: u64 = 64;
const INDEX_MAGIC: &[u8; 8] = b"N2RJIX01";
const INDEX_END: &[u8; 8] = b"N2RJIEND";

#[derive(Clone, Copy, Debug)]
pub(crate) struct ResourceJournalBudget {
    pub max_selected_bytes: u64,
    pub max_journal_bytes: u64,
    pub marker_profile: Option<SelectedMarkerProfile>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct JournalLayoutFacts {
    pub image_length: u64,
    pub range_count: u32,
    pub selected_bytes: u64,
    pub old_zero_bytes: u64,
    pub source_free_bytes: u64,
    pub new_zero_bytes: u64,
    pub copy_bytes: u64,
    pub literal_bytes: u64,
    pub body_offset: u64,
    pub record_size: usize,
    pub journal_length: u64,
    pub marker_profile: Option<SelectedMarkerProfile>,
}

/// Exact on-disk offsets for a single row, without granting write authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct JournalLayoutRow {
    pub capture: CaptureIndexRange,
    pub descriptor_offset: u64,
    pub old_storage_offset: u64,
    pub new_storage_offset: u64,
    pub next_offset: u64,
}

/// Owns a readonly offset index and borrows the live closed capture. Dropping
/// the capture or the actual arena-owned offset file invalidates this owner.
pub(crate) struct ResourceJournalDomain<'a> {
    capture: &'a DiagnosticSelectedCapture,
    offsets: RefCell<BufReader<File>>,
    offsets_position: Cell<u64>,
    offset_lease: ArtifactLease,
    scratch: SourceScratch,
    _index_memory: SourceRamLease,
    facts: JournalLayoutFacts,
    index_length: u64,
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("resource journal layout overflow")
}

fn old_stored(row: CaptureIndexRange) -> Result<u64> {
    if row.old_is_zero {
        Ok(0)
    } else if row.old_is_source_free {
        (row.length / GRANULE)
            .checked_mul(FREE_DIGEST)
            .context("resource free-digest table overflow")
    } else {
        Ok(row.length)
    }
}

fn new_stored(row: CaptureIndexRange) -> u64 {
    if row.new_is_zero || row.copy_source_offset.is_some() {
        0
    } else {
        row.length
    }
}

fn row_end(row: CaptureIndexRange) -> Result<u64> {
    add(row.offset, row.length)
}

/// Each COPY source must have complete earlier retained OLD coverage. In
/// particular, a digest-only source-free row cannot provide COPY bytes.
fn require_copy_coverage(
    index: &ClosedCaptureIndex,
    before_ordinal: u64,
    row: CaptureIndexRange,
) -> Result<()> {
    let Some(start) = row.copy_source_offset else {
        return Ok(());
    };
    let end = add(start, row.length)?;
    ensure!(
        start.is_multiple_of(GRANULE) && end <= row.offset,
        "resource COPY source must precede its destination"
    );
    let (mut low, mut high) = (0u64, before_ordinal);
    while low < high {
        let middle = low + (high - low) / 2;
        if row_end(index.range(middle)?)? <= start {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    let mut cursor = start;
    while cursor < end {
        ensure!(
            low < before_ordinal,
            "resource COPY source is not in earlier OLD rows"
        );
        let prior = index.range(low)?;
        let prior_end = row_end(prior)?;
        ensure!(
            prior.offset <= cursor && cursor < prior_end && !prior.old_is_source_free,
            "resource COPY source crosses a gap or a digest-only OLD row"
        );
        cursor = end.min(prior_end);
        low += 1;
    }
    Ok(())
}

fn facts(
    capture: &DiagnosticSelectedCapture,
    budget: ResourceJournalBudget,
) -> Result<JournalLayoutFacts> {
    let index = capture.index();
    let pin = index.pin();
    let image = pin.image_length;
    let count =
        u32::try_from(index.len()).context("selected ticket range count exceeds its format")?;
    ensure!(
        image >= GRANULE
            && image.is_multiple_of(GRANULE)
            && count != 0
            && budget.max_selected_bytes <= image,
        "resource journal geometry or selected-byte budget differs"
    );
    let mut end = 0u64;
    let (mut selected, mut old_zero, mut free, mut new_zero, mut copy, mut literal) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for ordinal in 0..index.len() {
        let row = index.range(ordinal)?;
        let row_end = row_end(row)?;
        ensure!(
            row.length > 0
                && row.offset.is_multiple_of(GRANULE)
                && row.length.is_multiple_of(GRANULE)
                && row.offset >= end
                && row_end <= image
                && !(row.new_is_zero && row.copy_source_offset.is_some())
                && !(row.old_is_zero && row.old_is_source_free)
                && row.packed_offset == literal,
            "resource journal capture order, alignment or encoding differs"
        );
        if row.old_is_source_free {
            ensure!(
                row.offset >= GRANULE && row_end <= image - GRANULE,
                "resource source-free row covers a protected bookend"
            );
            free = add(free, row.length)?;
        } else if row.old_is_zero {
            old_zero = add(old_zero, row.length)?;
        }
        if row.new_is_zero {
            new_zero = add(new_zero, row.length)?;
        } else if row.copy_source_offset.is_some() {
            require_copy_coverage(index, ordinal, row)?;
            copy = add(copy, row.length)?;
        } else {
            literal = add(literal, row.length)?;
        }
        selected = add(selected, row.length)?;
        end = row_end;
    }
    ensure!(
        selected <= budget.max_selected_bytes
            && selected == pin.changed_bytes
            && old_zero == pin.old_zero_bytes
            && free == pin.source_free_bytes
            && literal == pin.packed_bytes
            && literal == capture.literal().pin().snapshot.file_bytes,
        "resource journal complete counts or literal owner differ"
    );
    ensure!(
        budget.marker_profile.is_none() || free != 0,
        "redundant source-free markers require source-free rows"
    );
    let record_size = if free != 0 || old_zero != 0 {
        OLD_ZERO_RECORD
    } else if copy != 0 {
        COPY_RECORD
    } else if new_zero != 0 {
        ZERO_RECORD
    } else {
        RECORD
    };
    let body_offset = if budget.marker_profile.is_some() {
        REDUNDANT_BODY
    } else {
        BODY
    };
    let payload = selected
        .checked_mul(2)
        .and_then(|n| n.checked_sub(new_zero))
        .and_then(|n| n.checked_sub(copy))
        .and_then(|n| n.checked_sub(old_zero))
        .and_then(|n| n.checked_sub(free))
        .and_then(|n| n.checked_add((free / GRANULE).checked_mul(FREE_DIGEST)?))
        .context("resource journal payload size overflow")?;
    let journal_length = body_offset
        .checked_add(HEADER as u64)
        .and_then(|n| n.checked_add((count as u64).checked_mul(record_size as u64)?))
        .and_then(|n| n.checked_add(payload))
        .and_then(|n| n.checked_add(FOOTER as u64))
        .context("resource journal total size overflow")?;
    ensure!(
        journal_length <= budget.max_journal_bytes,
        "resource journal exceeds its budget"
    );
    Ok(JournalLayoutFacts {
        image_length: image,
        range_count: count,
        selected_bytes: selected,
        old_zero_bytes: old_zero,
        source_free_bytes: free,
        new_zero_bytes: new_zero,
        copy_bytes: copy,
        literal_bytes: literal,
        body_offset,
        record_size,
        journal_length,
        marker_profile: budget.marker_profile,
    })
}

fn header(f: JournalLayoutFacts, capture_sha: &str) -> Result<[u8; INDEX_HEADER as usize]> {
    let mut out = [0u8; INDEX_HEADER as usize];
    out[..8].copy_from_slice(INDEX_MAGIC);
    out[8..16].copy_from_slice(&(f.range_count as u64).to_le_bytes());
    out[16..24].copy_from_slice(&f.image_length.to_le_bytes());
    out[24..32].copy_from_slice(&f.selected_bytes.to_le_bytes());
    out[32..40].copy_from_slice(&f.body_offset.to_le_bytes());
    out[40..48].copy_from_slice(&(f.record_size as u64).to_le_bytes());
    out[48..56].copy_from_slice(&f.journal_length.to_le_bytes());
    let sha = hex::decode(capture_sha)?;
    ensure!(sha.len() == 32, "capture index SHA width differs");
    out[56..88].copy_from_slice(&sha);
    Ok(out)
}

fn layout_row(
    row: CaptureIndexRange,
    descriptor: u64,
    record_size: usize,
) -> Result<JournalLayoutRow> {
    let old_storage_offset = add(descriptor, record_size as u64)?;
    let new_storage_offset = add(old_storage_offset, old_stored(row)?)?;
    let next_offset = add(new_storage_offset, new_stored(row))?;
    Ok(JournalLayoutRow {
        capture: row,
        descriptor_offset: descriptor,
        old_storage_offset,
        new_storage_offset,
        next_offset,
    })
}

impl<'a> ResourceJournalDomain<'a> {
    /// Build an eight-byte-per-range disk index under a reservation made before
    /// creation. Counts and COPY coverage are recomputed from held rows; no
    /// external report or serialized pin can construct this domain.
    pub(crate) fn from_capture(
        capture: &'a DiagnosticSelectedCapture,
        budget: ResourceJournalBudget,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
    ) -> Result<Self> {
        ensure!(
            group.group() == ArtifactGroup::Capture,
            "capture group required"
        );
        ensure!(
            capture.index().same_group(group),
            "journal index must use the capture's actual arena and group"
        );
        let scratch_group = scratch
            .artifact_group()
            .context("journal scratch is not arena-owned")?;
        ensure!(
            scratch_group.group() == group.group()
                && scratch_group.arena().same_arena(group.arena()),
            "journal scratch is not in the capture group"
        );
        capture.revalidate()?;
        let f = facts(capture, budget)?;
        let size = INDEX_HEADER
            .checked_add(
                u64::from(f.range_count)
                    .checked_mul(INDEX_ROW)
                    .context("journal index size overflow")?,
            )
            .and_then(|n| n.checked_add(INDEX_FOOTER))
            .context("journal index total overflow")?;
        let permit = group.reserve_file(path, size)?;
        let memory = scratch.lease_ram(2 * 256 * 1024)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(permit.path())?;
        let mut file = BufWriter::with_capacity(256 * 1024, file);
        let head = header(f, &capture.index().pin().file_sha256)?;
        let mut hash = Sha256::new();
        file.write_all(&head)?;
        hash.update(head);
        let mut position = add(f.body_offset, HEADER as u64)?;
        for ordinal in 0..u64::from(f.range_count) {
            let row = capture.index().range(ordinal)?;
            let bytes = position.to_le_bytes();
            file.write_all(&bytes)?;
            hash.update(bytes);
            position = layout_row(row, position, f.record_size)?.next_offset;
        }
        ensure!(
            add(position, FOOTER as u64)? == f.journal_length,
            "journal range layout does not close"
        );
        let mut footer = [0u8; INDEX_FOOTER as usize];
        footer[..8].copy_from_slice(INDEX_END);
        footer[8..16].copy_from_slice(&u64::from(f.range_count).to_le_bytes());
        footer[16..24].copy_from_slice(&position.to_le_bytes());
        footer[24..56].copy_from_slice(&hash.clone().finalize());
        file.write_all(&footer)?;
        hash.update(footer);
        file.flush()?;
        file.get_ref().sync_all()?;
        ensure!(
            file.get_ref().metadata()?.len() == size,
            "journal index length differs"
        );
        let expected_sha = hex::encode(hash.finalize());
        let readonly = n2r_win32::file_storage::duplicate_readonly(file.get_ref())?;
        drop(file);
        let offset_lease = permit.verify_closed_handle(&readonly, &expected_sha)?;
        let result = Self {
            capture,
            offsets: RefCell::new(BufReader::with_capacity(256 * 1024, readonly)),
            offsets_position: Cell::new(u64::MAX),
            offset_lease,
            scratch: scratch.clone(),
            _index_memory: memory,
            facts: f,
            index_length: size,
        };
        result.revalidate()?;
        Ok(result)
    }

    pub(crate) fn facts(&self) -> JournalLayoutFacts {
        self.facts
    }

    /// The actual live index owner, not the index's serialized identity.
    pub(crate) fn artifact_lease(&self) -> &ArtifactLease {
        &self.offset_lease
    }

    pub(crate) fn row(&self, ordinal: u64) -> Result<JournalLayoutRow> {
        ensure!(
            ordinal < u64::from(self.facts.range_count),
            "journal row ordinal exceeds domain"
        );
        let offset = INDEX_HEADER
            .checked_add(
                ordinal
                    .checked_mul(INDEX_ROW)
                    .context("journal index offset overflow")?,
            )
            .context("journal index offset overflow")?;
        let mut bytes = [0u8; 8];
        let mut file = self.offsets.borrow_mut();
        let previous = self.offsets_position.replace(u64::MAX);
        if previous != offset {
            file.seek(SeekFrom::Start(offset))?;
        }
        file.read_exact(&mut bytes)?;
        self.offsets_position.set(add(offset, INDEX_ROW)?);
        let descriptor = u64::from_le_bytes(bytes);
        let result = layout_row(
            self.capture.index().range(ordinal)?,
            descriptor,
            self.facts.record_size,
        )?;
        ensure!(
            result.next_offset <= self.facts.journal_length - FOOTER as u64,
            "journal row exceeds payload region"
        );
        Ok(result)
    }

    pub(crate) fn capture(&self) -> &DiagnosticSelectedCapture {
        self.capture
    }

    /// Retire only the actual index owned by this domain. The arena credits
    /// space only after its exclusive identity/hash checked deletion succeeds.
    pub(crate) fn retire(self) -> Result<()> {
        let Self {
            offsets,
            offset_lease,
            ..
        } = self;
        drop(offsets);
        offset_lease.retire()
    }

    /// Recompute both owners and every offset before a caller uses the plan.
    /// The caller must still bind the actual protected target/source proof.
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.capture
            .with_revalidation(|witness| self.revalidate_with_witness(witness))
    }

    /// Reuse one full same-capture content check within an operation boundary.
    /// The witness is lifetime-bound to the real capture and cannot be loaded
    /// from a serialized hash or fabricated as a recovery capability.
    pub(crate) fn revalidate_with_witness(
        &self,
        witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    ) -> Result<()> {
        witness.require_capture(self.capture)?;
        self.revalidate_layout_only()
    }

    /// Check actual held index/layout ownership for metadata-only consumers.
    /// This does not claim literal content has been freshly hashed and must
    /// never replace a full boundary check before journal/recovery operations.
    pub(crate) fn revalidate_layout_only(&self) -> Result<()> {
        self.capture.index().revalidate()?;
        self.offset_lease.revalidate()?;
        ensure!(
            self.offset_lease.wire_bytes() == self.index_length,
            "journal index owner length changed"
        );
        let mut file = self.offsets.borrow_mut();
        self.offsets_position.set(u64::MAX);
        file.seek(SeekFrom::Start(0))?;
        let mut head = [0u8; INDEX_HEADER as usize];
        file.read_exact(&mut head)?;
        ensure!(
            head == header(self.facts, &self.capture.index().pin().file_sha256)?,
            "journal index header differs"
        );
        let mut hash = Sha256::new();
        hash.update(head);
        let mut expected = add(self.facts.body_offset, HEADER as u64)?;
        for ordinal in 0..u64::from(self.facts.range_count) {
            let mut bytes = [0u8; 8];
            file.read_exact(&mut bytes)?;
            ensure!(
                u64::from_le_bytes(bytes) == expected,
                "journal index offset differs"
            );
            hash.update(bytes);
            expected = layout_row(
                self.capture.index().range(ordinal)?,
                expected,
                self.facts.record_size,
            )?
            .next_offset;
        }
        let mut footer = [0u8; INDEX_FOOTER as usize];
        file.read_exact(&mut footer)?;
        ensure!(
            &footer[..8] == INDEX_END
                && u64::from_le_bytes(footer[8..16].try_into()?)
                    == u64::from(self.facts.range_count)
                && u64::from_le_bytes(footer[16..24].try_into()?) == expected
                && footer[24..56] == hash.finalize()[..]
                && footer[56..].iter().all(|&x| x == 0)
                && add(expected, FOOTER as u64)? == self.facts.journal_length
                && file.stream_position()? == self.index_length,
            "journal index footer or closed extent differs"
        );
        self.offsets_position.set(self.index_length);
        Ok(())
    }
}
