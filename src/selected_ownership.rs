//! Source-allocation planning for selected 4 KiB destinations.
//!
//! A free result is a claim about a reconciled NTFS allocation model, never
//! about contents, VDL or current target allocation. It is not source admission:
//! the caller must bind this model/pin to its original opaque live source
//! context before using the plan. Neither this type nor its JSON is write or
//! replay authority. Recognized/replaced NTFS internals keep their allocations.
use crate::{
    ntfs_inspect::{AllocationReconciliationStatus, NtfsInspection},
    selected_journal::{SelectedCopyRange, SelectedPlan, SelectedRange},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

const GRANULE: u64 = 4096;
const MAX_RANGES: usize = 65_536;
const MAX_INSPECTION_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub maximum_allocation_intervals: usize,
    pub maximum_protected_intervals: usize,
    pub maximum_output_ranges: usize,
    pub maximum_inspection_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            maximum_allocation_intervals: MAX_RANGES,
            maximum_protected_intervals: MAX_RANGES,
            maximum_output_ranges: MAX_RANGES,
            maximum_inspection_bytes: MAX_INSPECTION_BYTES,
        }
    }
}

impl Limits {
    fn validate(self) -> Result<()> {
        ensure!(
            (1..=MAX_RANGES).contains(&self.maximum_allocation_intervals)
                && (1..=MAX_RANGES).contains(&self.maximum_protected_intervals)
                && (1..=MAX_RANGES).contains(&self.maximum_output_ranges)
                && (1..=MAX_INSPECTION_BYTES).contains(&self.maximum_inspection_bytes),
            "selected ownership planning budget differs"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    RestoreRequired,
    SourceFree,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ClassifiedRange {
    /// Never merge across original range boundaries: new-payload/COPY flags
    /// belong to that original selected range and must be split with it.
    pub selected_index: usize,
    pub offset: u64,
    pub length: u64,
    pub disposition: Disposition,
}

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub selected_bytes: u64,
    pub restore_required_bytes: u64,
    pub source_free_bytes: u64,
    /// These three causes may overlap; do not add them to derive the union.
    pub ntfs_allocated_selected_bytes: u64,
    pub protected_copy_source_selected_bytes: u64,
    pub discovery_selected_bytes: u64,
    pub input_selected_ranges: usize,
    pub output_ranges: usize,
}

#[derive(Debug, Serialize)]
pub struct OwnershipPlan {
    scope: &'static str,
    source_inspection_sha256: String,
    ntfs_bitmap_sha256: String,
    partition_bytes: u64,
    ranges: Vec<ClassifiedRange>,
    counts: Counts,
    grants_write_or_replay_authority: bool,
}

impl OwnershipPlan {
    pub fn ranges(&self) -> &[ClassifiedRange] {
        &self.ranges
    }

    pub fn counts(&self) -> &Counts {
        &self.counts
    }
}

/// Bounded, non-deserializable planning input. Construction verifies model
/// consistency and pins the actual supplied inventory; it does NOT establish
/// that a deserialized inventory is live or recreate an admission certificate.
pub struct ReconciledSourceAllocation {
    partition_bytes: u64,
    allocated: Vec<(u64, u64)>,
    source_inspection_sha256: String,
    ntfs_bitmap_sha256: String,
    limits: Limits,
}

struct InspectionPin {
    hash: Sha256,
    bytes: u64,
    maximum: u64,
}

impl Write for InspectionPin {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("selected ownership inspection pin exceeds budget"))?;
        self.hash.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn end(offset: u64, length: u64) -> Result<u64> {
    offset
        .checked_add(length)
        .context("selected ownership interval overflow")
}

/// All intervals are validated before sorting or classification. Any partial
/// granule overlap protects that whole granule, including partition-tail bytes.
fn normalize(mut ranges: Vec<(u64, u64)>, partition: u64) -> Result<Vec<(u64, u64)>> {
    for (offset, length) in &mut ranges {
        let finish = end(*offset, *length)?;
        ensure!(
            *length != 0 && finish <= partition,
            "ownership interval leaves partition"
        );
        let start = *offset / GRANULE * GRANULE;
        let finish = finish
            .checked_next_multiple_of(GRANULE)
            .context("ownership granule rounding overflow")?;
        ensure!(
            finish <= partition,
            "rounded ownership interval leaves partition"
        );
        *offset = start;
        *length = finish - start;
    }
    ranges.sort_unstable_by_key(|r| r.0);
    let mut used = 0usize;
    for i in 0..ranges.len() {
        let (offset, length) = ranges[i];
        let finish = end(offset, length)?;
        if used != 0 && offset <= end(ranges[used - 1].0, ranges[used - 1].1)? {
            let previous = &mut ranges[used - 1];
            previous.1 = end(previous.0, previous.1)?.max(finish) - previous.0;
        } else {
            ranges[used] = (offset, length);
            used += 1;
        }
    }
    ranges.truncate(used);
    Ok(ranges)
}

impl ReconciledSourceAllocation {
    pub fn from_inspection(
        raw: &NtfsInspection,
        partition_bytes: u64,
        limits: Limits,
    ) -> Result<Self> {
        limits.validate()?;
        ensure!(
            partition_bytes > 0 && partition_bytes.is_multiple_of(GRANULE),
            "ownership partition is not granule aligned"
        );
        crate::ntfs_inspect::validate_record_coverage(raw)?;
        let reconciliation = raw
            .allocation_reconciliation
            .as_ref()
            .context("selected ownership requires reconciled NTFS allocation")?;
        ensure!(
            raw.schema_version == 1
                && reconciliation.status == AllocationReconciliationStatus::ConsistentRawModel
                && reconciliation.domain_clusters == raw.geometry.total_clusters
                && reconciliation.bitmap_sha256.len() == 64
                && reconciliation
                    .bitmap_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "selected ownership allocation model or bitmap pin differs"
        );
        let list_storage = raw.attribute_assemblies.iter().filter_map(|a| {
            a.base
                .attributes
                .iter()
                .find(|a| a.type_code == 0x20 && !a.resident)
        });
        let cluster = u64::from(raw.geometry.cluster_size);
        ensure!(
            (512..=2 * 1024 * 1024).contains(&cluster) && cluster.is_power_of_two(),
            "ownership NTFS cluster geometry differs"
        );
        let domain = raw
            .geometry
            .total_clusters
            .checked_mul(cluster)
            .context("ownership cluster domain overflow")?;
        ensure!(
            domain > 0 && domain <= partition_bytes,
            "ownership cluster domain leaves partition"
        );
        // Budget the exact iterator used by allocated_byte_ranges BEFORE that
        // existing model helper materializes its vector. Reuse its ownership
        // semantics, including nonresident attribute-list storage and tails.
        let mut interval_count = 0usize;
        for attribute in raw
            .files
            .iter()
            .flat_map(|f| &f.attributes)
            .chain(list_storage)
        {
            if attribute.resident {
                continue;
            }
            for extent in &attribute.extents {
                if extent.physical_offset.is_none() {
                    continue;
                }
                interval_count = interval_count
                    .checked_add(1)
                    .filter(|count| *count <= limits.maximum_allocation_intervals)
                    .context("ownership physical allocation interval budget exceeded")?;
            }
        }
        ensure!(
            interval_count == reconciliation.physical_intervals
                && interval_count
                    .checked_add(usize::from(domain < partition_bytes))
                    .is_some_and(|count| count <= limits.maximum_allocation_intervals),
            "ownership allocation interval count or tail budget differs"
        );
        let intervals = raw.allocated_byte_ranges(partition_bytes)?;
        ensure!(
            intervals.len() <= limits.maximum_allocation_intervals,
            "merged ownership allocation interval budget exceeded"
        );
        let mut pin = InspectionPin {
            hash: Sha256::new(),
            bytes: 0,
            maximum: limits.maximum_inspection_bytes,
        };
        serde_json::to_writer(&mut pin, raw).context("ownership source inventory pin failed")?;
        Ok(Self {
            partition_bytes,
            allocated: normalize(intervals, partition_bytes)?,
            source_inspection_sha256: hex::encode(pin.hash.finalize()),
            ntfs_bitmap_sha256: reconciliation.bitmap_sha256.clone(),
            limits,
        })
    }

    /// Conservative complete-granule coverage of the reconciled raw model.
    /// All original allocation bytes remain covered; partial granules expand.
    pub fn allocated_byte_ranges(&self) -> &[(u64, u64)] {
        &self.allocated
    }

    pub fn source_inspection_sha256(&self) -> &str {
        &self.source_inspection_sha256
    }
    pub fn ntfs_bitmap_sha256(&self) -> &str {
        &self.ntfs_bitmap_sha256
    }

    /// Linear sweep after bounded normalization of potentially unordered COPY
    /// sources. Every protected original byte must already have journal-domain
    /// coverage; otherwise the caller must retain/capture it or choose literals.
    pub fn classify(
        &self,
        selected: &[SelectedRange],
        protected_copy_sources: &[(u64, u64)],
    ) -> Result<OwnershipPlan> {
        ensure!(
            selected.len() <= self.limits.maximum_output_ranges
                && protected_copy_sources.len() <= self.limits.maximum_protected_intervals,
            "selected ownership input range budget exceeded"
        );
        let mut previous = 0;
        for r in selected {
            let finish = end(r.offset, r.length)?;
            ensure!(
                r.length > 0
                    && r.offset.is_multiple_of(GRANULE)
                    && r.length.is_multiple_of(GRANULE)
                    && r.offset >= previous
                    && finish <= self.partition_bytes,
                "selected ownership input overlaps, is unaligned or leaves partition"
            );
            previous = finish;
        }
        let mut protected = Vec::new();
        protected
            .try_reserve_exact(protected_copy_sources.len())
            .context("COPY protection storage unavailable")?;
        protected.extend_from_slice(protected_copy_sources);
        let protected = normalize(protected, self.partition_bytes)?;
        let mut selection = 0;
        for &(offset, length) in &protected {
            let mut cursor = offset;
            let finish = end(offset, length)?;
            while cursor < finish {
                while selected
                    .get(selection)
                    .is_some_and(|r| r.offset + r.length <= cursor)
                {
                    selection += 1;
                }
                let r = selected
                    .get(selection)
                    .context("COPY source leaves the selected journal domain")?;
                ensure!(
                    r.offset <= cursor,
                    "COPY source crosses an unjournaled selected gap"
                );
                cursor = finish.min(r.offset + r.length);
            }
        }
        let mut ranges: Vec<ClassifiedRange> = Vec::new();
        let mut counts = Counts {
            input_selected_ranges: selected.len(),
            ..Counts::default()
        };
        let (mut allocated_index, mut protected_index) = (0, 0);
        for (selected_index, r) in selected.iter().enumerate() {
            let finish = r.offset + r.length;
            let mut cursor = r.offset;
            while cursor < finish {
                while self
                    .allocated
                    .get(allocated_index)
                    .is_some_and(|r| r.0 + r.1 <= cursor)
                {
                    allocated_index += 1;
                }
                while protected
                    .get(protected_index)
                    .is_some_and(|r| r.0 + r.1 <= cursor)
                {
                    protected_index += 1;
                }
                let a = self.allocated.get(allocated_index);
                let p = protected.get(protected_index);
                let allocated = a.is_some_and(|r| r.0 <= cursor);
                let copy = p.is_some_and(|r| r.0 <= cursor);
                let discovery = cursor < GRANULE;
                let mut next = finish;
                for (interval, active) in [(a, allocated), (p, copy)] {
                    if let Some(&(offset, length)) = interval {
                        next = next.min(if active { offset + length } else { offset });
                    }
                }
                if discovery {
                    next = next.min(GRANULE);
                }
                ensure!(next > cursor, "selected ownership sweep did not advance");
                let bytes = next - cursor;
                let disposition = if allocated || copy || discovery {
                    Disposition::RestoreRequired
                } else {
                    Disposition::SourceFree
                };
                counts.selected_bytes = counts
                    .selected_bytes
                    .checked_add(bytes)
                    .context("selected ownership byte total overflow")?;
                let total = match disposition {
                    Disposition::RestoreRequired => &mut counts.restore_required_bytes,
                    Disposition::SourceFree => &mut counts.source_free_bytes,
                };
                *total = total
                    .checked_add(bytes)
                    .context("ownership disposition byte total overflow")?;
                if allocated {
                    counts.ntfs_allocated_selected_bytes = counts
                        .ntfs_allocated_selected_bytes
                        .checked_add(bytes)
                        .context("allocated selected byte total overflow")?;
                }
                if copy {
                    counts.protected_copy_source_selected_bytes = counts
                        .protected_copy_source_selected_bytes
                        .checked_add(bytes)
                        .context("protected COPY byte total overflow")?;
                }
                if discovery {
                    counts.discovery_selected_bytes = counts
                        .discovery_selected_bytes
                        .checked_add(bytes)
                        .context("discovery byte total overflow")?;
                }
                if let Some(last) = ranges.last_mut().filter(|last| {
                    last.selected_index == selected_index
                        && last.disposition == disposition
                        && last.offset + last.length == cursor
                }) {
                    last.length = last
                        .length
                        .checked_add(bytes)
                        .context("ownership range length overflow")?;
                } else {
                    ensure!(
                        ranges.len() < self.limits.maximum_output_ranges,
                        "ownership split range budget exceeded"
                    );
                    ranges
                        .try_reserve(1)
                        .context("ownership output storage unavailable")?;
                    ranges.push(ClassifiedRange {
                        selected_index,
                        offset: cursor,
                        length: bytes,
                        disposition,
                    });
                }
                cursor = next;
            }
        }
        ensure!(
            counts
                .restore_required_bytes
                .checked_add(counts.source_free_bytes)
                == Some(counts.selected_bytes),
            "ownership exact coverage accounting differs"
        );
        counts.output_ranges = ranges.len();
        Ok(OwnershipPlan {
            scope: "reconciled-ntfs-selected-ownership-v1",
            source_inspection_sha256: self.source_inspection_sha256.clone(),
            ntfs_bitmap_sha256: self.ntfs_bitmap_sha256.clone(),
            partition_bytes: self.partition_bytes,
            ranges,
            counts,
            grants_write_or_replay_authority: false,
        })
    }

    /// Refine only a fresh non-free plan. Source-free old storage is selected
    /// only when its exact encoded journal is smaller, keeping the original
    /// framing and format byte-compatible on an unprofitable/no-free result.
    pub fn refine_selected_plan(&self, plan: &SelectedPlan) -> Result<SelectedPlan> {
        ensure!(
            plan.image_length == self.partition_bytes && plan.source_free_ranges.is_empty(),
            "ownership refinement requires the same fresh non-free selected domain"
        );
        ensure!(
            plan.ranges.len() <= self.limits.maximum_output_ranges
                && plan.new_zero_ranges.len() <= plan.ranges.len()
                && plan.new_copy_ranges.len() <= self.limits.maximum_protected_intervals
                && plan.new_copy_ranges.len() <= plan.ranges.len()
                && plan.old_zero_ranges.len() <= plan.ranges.len(),
            "ownership refinement input range budget exceeded"
        );
        let mut measured = plan.clone();
        measured.max_journal_bytes = u64::MAX; // Measurement only; never returned.
        let (_, old_journal_bytes) = measured.validate()?;
        let mut protected = Vec::new();
        protected
            .try_reserve_exact(plan.new_copy_ranges.len())
            .context("COPY source protection unavailable")?;
        protected.extend(
            plan.new_copy_ranges
                .iter()
                .map(|c| (c.source_offset, c.length)),
        );
        let ownership = self.classify(&plan.ranges, &protected)?;
        if ownership.counts.source_free_bytes == 0 {
            plan.validate()?;
            return Ok(plan.clone());
        }
        let mut candidate = SelectedPlan {
            image_length: plan.image_length,
            ranges: Vec::new(),
            max_selected_bytes: plan.max_selected_bytes,
            max_journal_bytes: u64::MAX,
            new_zero_ranges: Vec::new(),
            new_copy_ranges: Vec::new(),
            old_zero_ranges: Vec::new(),
            source_free_ranges: Vec::new(),
        };
        candidate
            .ranges
            .try_reserve_exact(ownership.ranges.len())
            .context("refined range storage unavailable")?;
        candidate
            .new_zero_ranges
            .try_reserve_exact(ownership.ranges.len())
            .context("refined new-zero storage unavailable")?;
        candidate
            .new_copy_ranges
            .try_reserve_exact(ownership.ranges.len())
            .context("refined COPY storage unavailable")?;
        candidate
            .old_zero_ranges
            .try_reserve_exact(ownership.ranges.len())
            .context("refined old-zero storage unavailable")?;
        candidate
            .source_free_ranges
            .try_reserve_exact(ownership.ranges.len())
            .context("refined source-free storage unavailable")?;
        for r in &ownership.ranges {
            let original = &plan.ranges[r.selected_index];
            let range = SelectedRange {
                offset: r.offset,
                length: r.length,
            };
            candidate.ranges.push(range.clone());
            if plan
                .new_zero_ranges
                .binary_search_by_key(&original.offset, |z| z.offset)
                .is_ok()
            {
                candidate.new_zero_ranges.push(range.clone());
            }
            if let Ok(index) = plan
                .new_copy_ranges
                .binary_search_by_key(&original.offset, |c| c.offset)
            {
                let copy = &plan.new_copy_ranges[index];
                candidate.new_copy_ranges.push(SelectedCopyRange {
                    offset: r.offset,
                    length: r.length,
                    source_offset: copy
                        .source_offset
                        .checked_add(r.offset - original.offset)
                        .context("refined COPY source overflow")?,
                });
            }
            let old_zero = plan
                .old_zero_ranges
                .binary_search_by_key(&original.offset, |z| z.offset)
                .is_ok();
            if old_zero {
                candidate.old_zero_ranges.push(range);
            } else if r.disposition == Disposition::SourceFree {
                candidate.source_free_ranges.push(range);
            }
        }
        if candidate.source_free_ranges.is_empty() {
            plan.validate()?;
            return Ok(plan.clone());
        }
        let (_, new_journal_bytes) = candidate.validate()?;
        if new_journal_bytes >= old_journal_bytes {
            plan.validate()?;
            return Ok(plan.clone());
        }
        candidate.max_journal_bytes = plan.max_journal_bytes;
        candidate.validate()?;
        Ok(candidate)
    }
}
