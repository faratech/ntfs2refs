//! Source-allocation planning for selected 4 KiB destinations.
//!
//! A free result is a claim about a reconciled NTFS allocation model, never
//! about contents, VDL or current target allocation. It is not source admission:
//! the caller must bind this model/pin to its original opaque live source
//! context before using the plan. Neither this type nor its JSON is write or
//! replay authority. Recognized/replaced NTFS internals keep their allocations;
//! the backup boot granule always requires restoration, even inside a bitmap
//! domain that marks the final cluster free.
use crate::ntfs_inspect::{AllocationReconciliationStatus, NtfsInspection};
use anyhow::{Context, Result, ensure};
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

/// Bounded, non-deserializable planning input. Construction verifies model
/// consistency and pins the actual supplied inventory; it does NOT establish
/// that a deserialized inventory is live or recreate an admission certificate.
pub struct ReconciledSourceAllocation {
    allocated: Vec<(u64, u64)>,
    source_inspection_sha256: String,
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
        let backup_granule = partition_bytes - GRANULE;
        // Budget the exact iterator used by allocated_byte_ranges BEFORE that
        // existing model helper materializes its vector. A partial tail or
        // extent overlap already rounds to protect the complete final granule;
        // otherwise reserve one additional interval for the backup boot sector.
        let mut interval_count = 0usize;
        let mut backup_protected = domain < partition_bytes;
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
                let Some(physical) = extent.physical_offset else {
                    continue;
                };
                let finish = physical
                    .checked_add(extent.length)
                    .context("ownership physical allocation interval overflow")?;
                backup_protected |=
                    extent.length != 0 && physical < partition_bytes && finish > backup_granule;
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
                    .and_then(|count| count.checked_add(usize::from(!backup_protected)))
                    .is_some_and(|count| count <= limits.maximum_allocation_intervals),
            "ownership allocation interval count, tail or backup reserve budget differs"
        );
        let mut intervals = raw.allocated_byte_ranges(partition_bytes)?;
        if !backup_protected {
            intervals
                .try_reserve_exact(1)
                .context("backup boot protection interval storage unavailable")?;
            intervals.push((backup_granule, GRANULE));
        }
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
            allocated: normalize(intervals, partition_bytes)?,
            source_inspection_sha256: hex::encode(pin.hash.finalize()),
        })
    }

    /// Conservative complete-granule coverage of the reconciled raw model.
    /// All original allocation bytes and the backup boot sector remain covered;
    /// partial granules expand. Capture capacity and final plan refinement use
    /// this same conservative coverage.
    pub fn allocated_byte_ranges(&self) -> &[(u64, u64)] {
        &self.allocated
    }

    pub fn source_inspection_sha256(&self) -> &str {
        &self.source_inspection_sha256
    }
}
