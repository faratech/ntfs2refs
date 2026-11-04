//! Complete paged allocation ownership. No source or write authority is issued.
use super::{
    AllocationReconciliationStatus, AttributeInventory, RootFileDomain,
    assembled_io::PagedAssemblyEvidence,
    external_sort::ExternalSort,
    paged_storage::SourceScratch,
    record_store::{RecordStorePin, SortedRecordStore},
};
use crate::{ntfs_allocation::BitmapSummary, ntfs_attribute_list::Assembly};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagedAllocationReconciliation {
    pub status: AllocationReconciliationStatus,
    pub bitmap_sha256: String,
    pub domain_clusters: u64,
    pub physical_intervals: u64,
    pub distinct_attributes: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    pub padding_bits_set: u32,
    pub physical_ownership: RecordStorePin,
    pub logical_ownership: RecordStorePin,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Interval {
    owner: u64,
    ordinal: u64,
    record_number: u64,
    sequence_number: u16,
    type_code: u32,
    name_utf16: Vec<u16>,
    instance: u16,
    vcn: u64,
    lcn: u64,
    clusters: u64,
}

fn query_domain(
    store: &SortedRecordStore,
    geometry: &super::NtfsGeometry,
    summary: &PagedAllocationReconciliation,
    offset: u64,
    length: u64,
    partition_bytes: u64,
) -> Result<(u64, u64)> {
    let pin = store.pin();
    let original = &summary.physical_ownership;
    ensure!(
        summary.status == AllocationReconciliationStatus::ConsistentRawModel
            && summary.domain_clusters == geometry.total_clusters
            && store.len() == summary.physical_intervals
            && pin.purpose == original.purpose
            && pin.records == original.records
            && pin.data.file_sha256 == original.data.file_sha256
            && pin.directory.file_sha256 == original.directory.file_sha256,
        "allocation query requires its actual reconciled held ownership index"
    );
    let cluster = u64::from(geometry.cluster_size);
    ensure!(
        cluster > 0
            && cluster.is_power_of_two()
            && length > 0
            && (partition_bytes == geometry.volume_size
                || geometry
                    .volume_size
                    .checked_add(u64::from(geometry.bytes_per_sector))
                    == Some(partition_bytes)),
        "allocation query geometry/partition boundary differs"
    );
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= partition_bytes)
        .context("allocation query escapes actual partition")?;
    let domain = geometry
        .total_clusters
        .checked_mul(cluster)
        .filter(|domain| *domain <= geometry.volume_size)
        .context("allocation cluster domain overflow")?;
    Ok((end, domain))
}
fn interval_bytes(
    store: &SortedRecordStore,
    ordinal: u64,
    cluster: u64,
    domain: u64,
) -> Result<(u64, u64)> {
    let row: Interval = store.get(ordinal)?;
    ensure!(
        store.key(ordinal)? == key(row.lcn, row.ordinal) && row.clusters > 0,
        "held allocation interval key/length differs"
    );
    let start = row
        .lcn
        .checked_mul(cluster)
        .context("allocation byte start overflow")?;
    let end = row
        .lcn
        .checked_add(row.clusters)
        .and_then(|end| end.checked_mul(cluster))
        .filter(|end| *end <= domain)
        .context("allocation byte end escapes bitmap domain")?;
    Ok((start, end))
}
/// Count true NTFS-owned bytes. Reserved bootstrap/tail bytes are deliberately
/// not invented as bitmap allocation; is_free_granule protects them separately.
pub fn allocated_bytes_in(
    store: &SortedRecordStore,
    geometry: &super::NtfsGeometry,
    summary: &PagedAllocationReconciliation,
    offset: u64,
    length: u64,
    partition_bytes: u64,
) -> Result<u64> {
    let (end, domain) = query_domain(store, geometry, summary, offset, length, partition_bytes)?;
    if offset >= domain {
        return Ok(0);
    }
    let cluster = u64::from(geometry.cluster_size);
    let (mut low, mut high) = (0, store.len());
    while low < high {
        let mid = low + (high - low) / 2;
        if interval_bytes(store, mid, cluster, domain)?.1 <= offset {
            low = mid + 1
        } else {
            high = mid
        }
    }
    let mut bytes = 0u64;
    let mut prior_end = None;
    for ordinal in low..store.len() {
        let (start, finish) = interval_bytes(store, ordinal, cluster, domain)?;
        if start >= end {
            break;
        }
        ensure!(
            prior_end.is_none_or(|prior| prior <= start),
            "held physical ownership overlaps"
        );
        prior_end = Some(finish);
        let first = start.max(offset);
        let last = finish.min(end);
        if first < last {
            bytes = bytes
                .checked_add(last - first)
                .context("allocation query total overflow")?;
        }
    }
    ensure!(bytes <= length, "allocation query exceeds requested range");
    Ok(bytes)
}
pub fn require_allocated_range(
    store: &SortedRecordStore,
    geometry: &super::NtfsGeometry,
    summary: &PagedAllocationReconciliation,
    offset: u64,
    length: u64,
    partition_bytes: u64,
) -> Result<()> {
    ensure!(
        allocated_bytes_in(store, geometry, summary, offset, length, partition_bytes)? == length,
        "source range is not completely owned by the reconciled NTFS allocation"
    );
    Ok(())
}
pub fn is_free_granule(
    store: &SortedRecordStore,
    geometry: &super::NtfsGeometry,
    summary: &PagedAllocationReconciliation,
    offset: u64,
    partition_bytes: u64,
) -> Result<bool> {
    let (end, domain) = query_domain(store, geometry, summary, offset, 4096, partition_bytes)?;
    ensure!(
        offset.is_multiple_of(4096),
        "free-source query must be a complete aligned granule"
    );
    if partition_bytes < 4096 || offset < 4096 || end > partition_bytes - 4096 || end > domain {
        return Ok(false);
    }
    Ok(allocated_bytes_in(store, geometry, summary, offset, 4096, partition_bytes)? == 0)
}

/// One destination classification, not source admission or a write capability.
pub(crate) struct GranuleAllocation {
    pub allocated_bytes: u64,
    pub is_source_free: bool,
}

/// Forward queries over the actual held ownership index. Cache only the current
/// scalar interval; the source adapter retains its complete metadata bookends.
pub(crate) struct AllocationCursor<'a> {
    store: &'a SortedRecordStore,
    geometry: &'a super::NtfsGeometry,
    summary: &'a PagedAllocationReconciliation,
    partition_bytes: u64,
    domain: u64,
    next_ordinal: u64,
    current: Option<(u64, u64)>,
    prior_interval_end: Option<u64>,
    last_query_end: Option<u64>,
    poisoned: bool,
}
impl<'a> AllocationCursor<'a> {
    pub(super) fn new(
        store: &'a SortedRecordStore,
        geometry: &'a super::NtfsGeometry,
        summary: &'a PagedAllocationReconciliation,
        partition_bytes: u64,
    ) -> Result<Self> {
        let (_, domain) = query_domain(store, geometry, summary, 0, 4096, partition_bytes)?;
        Ok(Self {
            store,
            geometry,
            summary,
            partition_bytes,
            domain,
            next_ordinal: 0,
            current: None,
            prior_interval_end: None,
            last_query_end: None,
            poisoned: false,
        })
    }

    fn advance(&mut self) -> Result<()> {
        self.current = None;
        if self.next_ordinal < self.store.len() {
            let row = interval_bytes(
                self.store,
                self.next_ordinal,
                u64::from(self.geometry.cluster_size),
                self.domain,
            )?;
            ensure!(
                self.prior_interval_end.is_none_or(|end| end <= row.0),
                "held physical ownership overlaps in forward query"
            );
            self.next_ordinal = self
                .next_ordinal
                .checked_add(1)
                .context("allocation cursor ordinal overflow")?;
            self.prior_interval_end = Some(row.1);
            self.current = Some(row);
        }
        Ok(())
    }

    fn seek_forward(&mut self, offset: u64) -> Result<()> {
        // A sparse selection may jump over millions of irrelevant user-data
        // intervals. Seek once across that gap rather than scanning them all.
        let (mut low, mut high) = (self.next_ordinal, self.store.len());
        let cluster = u64::from(self.geometry.cluster_size);
        while low < high {
            let middle = low + (high - low) / 2;
            if interval_bytes(self.store, middle, cluster, self.domain)?.1 <= offset {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        self.current = None;
        self.next_ordinal = low;
        self.prior_interval_end = if low > 0 {
            Some(interval_bytes(self.store, low - 1, cluster, self.domain)?.1)
        } else {
            None
        };
        self.advance()
    }

    pub(crate) fn granule(&mut self, offset: u64) -> Result<GranuleAllocation> {
        ensure!(!self.poisoned, "failed allocation cursor cannot be reused");
        self.poisoned = true;
        let (end, domain) = query_domain(
            self.store,
            self.geometry,
            self.summary,
            offset,
            4096,
            self.partition_bytes,
        )?;
        ensure!(
            domain == self.domain
                && offset.is_multiple_of(4096)
                && self.last_query_end.is_none_or(|prior| offset >= prior),
            "allocation cursor requires forward, disjoint aligned granules"
        );
        let mut allocated_bytes = 0u64;
        if offset < domain {
            if self.current.is_none() && self.next_ordinal < self.store.len()
                || self.current.is_some_and(|(_, finish)| finish <= offset)
                    && self.last_query_end != Some(offset)
            {
                self.seek_forward(offset)?;
            }
            while let Some((start, finish)) = self.current {
                if finish <= offset {
                    self.advance()?;
                    continue;
                }
                if start >= end {
                    break;
                }
                let first = start.max(offset);
                let last = finish.min(end);
                if first < last {
                    allocated_bytes = allocated_bytes
                        .checked_add(last - first)
                        .context("allocation cursor byte count overflow")?;
                }
                if finish >= end {
                    break;
                }
                self.advance()?;
            }
        }
        ensure!(allocated_bytes <= 4096, "allocation cursor exceeds granule");
        let is_source_free = offset >= 4096
            && self
                .partition_bytes
                .checked_sub(4096)
                .is_some_and(|tail| end <= tail)
            && end <= domain
            && allocated_bytes == 0;
        self.last_query_end = Some(end);
        self.poisoned = false;
        Ok(GranuleAllocation {
            allocated_bytes,
            is_source_free,
        })
    }
}
fn key(a: u64, b: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&a.to_be_bytes());
    key[8..].copy_from_slice(&b.to_be_bytes());
    key
}

struct Collector {
    physical: ExternalSort,
    logical: ExternalSort,
    owners: u64,
    intervals: u64,
    cluster: u64,
    domain: u64,
}
impl Collector {
    fn attribute(&mut self, number: u64, sequence: u16, a: &AttributeInventory) -> Result<()> {
        ensure!(
            number <= 0x0000_ffff_ffff_ffff
                && sequence != 0
                && a.type_code != 0
                && a.type_code.is_multiple_of(16)
                && a.name_utf16.len() <= 255,
            "invalid physical allocation attribute identity"
        );
        if a.resident {
            return Ok(());
        }
        let owner = self.owners;
        let mut used = false;
        for extent in &a.extents {
            let Some(physical) = extent.physical_offset else {
                continue;
            };
            ensure!(
                extent.logical_offset.is_multiple_of(self.cluster)
                    && physical.is_multiple_of(self.cluster)
                    && extent.length > 0
                    && extent.length.is_multiple_of(self.cluster),
                "attribute extent is not a nonempty cluster interval"
            );
            let vcn = extent.logical_offset / self.cluster;
            let lcn = physical / self.cluster;
            let clusters = extent.length / self.cluster;
            ensure!(
                vcn.checked_add(clusters).is_some()
                    && lcn
                        .checked_add(clusters)
                        .is_some_and(|end| end <= self.domain),
                "attribute interval overflows or escapes the volume bitmap domain"
            );
            let interval = Interval {
                owner,
                ordinal: self.intervals,
                record_number: number,
                sequence_number: sequence,
                type_code: a.type_code,
                name_utf16: a.name_utf16.clone(),
                instance: a.instance,
                vcn,
                lcn,
                clusters,
            };
            self.logical.push(key(owner, vcn), &interval)?;
            self.physical.push(key(lcn, self.intervals), &interval)?;
            self.intervals = self
                .intervals
                .checked_add(1)
                .context("physical interval count overflow")?;
            used = true;
        }
        if used {
            self.owners = self
                .owners
                .checked_add(1)
                .context("allocation owner count overflow")?;
        }
        Ok(())
    }
}

/// A partial-byte mask followed by words and a final mask avoids per-cluster
/// work over large contiguous retained/free ranges. All offsets are window local.
fn matches_bits(bytes: &[u8], mut start: u64, end: u64, allocated: bool) -> bool {
    if start == end {
        return true;
    }
    if !start.is_multiple_of(8) {
        let count = (8 - start % 8).min(end - start);
        let mask = (((1u16 << count) - 1) << (start % 8)) as u8;
        let byte = bytes[(start / 8) as usize];
        if (if allocated { !byte } else { byte }) & mask != 0 {
            return false;
        }
        start += count;
    }
    while end - start >= 64 {
        let at = (start / 8) as usize;
        let word = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded complete word"));
        if word != if allocated { u64::MAX } else { 0 } {
            return false;
        }
        start += 64;
    }
    while end - start >= 8 {
        if bytes[(start / 8) as usize] != if allocated { 255 } else { 0 } {
            return false;
        }
        start += 8;
    }
    if start < end {
        let mask = ((1u16 << (end - start)) - 1) as u8;
        let byte = bytes[(start / 8) as usize];
        if (if allocated { !byte } else { byte }) & mask != 0 {
            return false;
        }
    }
    true
}

pub fn reconcile_allocation_domain<R: Read + Seek>(
    files: &impl RootFileDomain,
    assemblies: &PagedAssemblyEvidence,
    bitmap: &mut R,
    original: &BitmapSummary,
    root: &Path,
    scratch: &SourceScratch,
) -> Result<PagedAllocationReconciliation> {
    scratch.budget().validate()?;
    files.revalidate()?;
    let geometry = &files.header().geometry;
    let cluster = u64::from(geometry.cluster_size);
    let domain = geometry.total_clusters;
    ensure!(
        cluster > 0
            && cluster.is_power_of_two()
            && domain > 0
            && assemblies.schema_version == 1
            && assemblies.record_count == files.header().mft_record_count
            && assemblies.canonical_records == files.file_count()
            && assemblies.allocated_records == files.header().records_scanned,
        "allocation source/assembly domain closure differs"
    );
    // One decoded source/assembly row plus its derived scalar/name buffers.
    // Spill batches, page readers and merge heads use separate aggregate leases.
    let _row_ram = scratch.lease_ram(
        scratch
            .budget()
            .record_bytes
            .checked_mul(4)
            .context("allocation row RAM overflow")?,
    )?;
    let assembly_rows = SortedRecordStore::open(&assemblies.assemblies, scratch)?;
    let physical_extensions = SortedRecordStore::open(&assemblies.physical_extensions, scratch)?;
    let consumed_extensions = SortedRecordStore::open(&assemblies.consumed_extensions, scratch)?;
    ensure!(
        physical_extensions.len() == assemblies.extension_records
            && consumed_extensions.len() == physical_extensions.len(),
        "extension ownership domain differs"
    );
    for ordinal in 0..physical_extensions.len() {
        ensure!(
            physical_extensions.key(ordinal)? == consumed_extensions.key(ordinal)?
                && physical_extensions.get_json(ordinal)?
                    == consumed_extensions.get_json(ordinal)?,
            "consumed/physical extension facts differ during allocation closure"
        );
    }
    let mut collector = Collector {
        physical: ExternalSort::new(&root.join("allocation-physical"), *b"N2RALPH1", scratch)?,
        logical: ExternalSort::new(&root.join("allocation-logical"), *b"N2RALLG1", scratch)?,
        owners: 0,
        intervals: 0,
        cluster,
        domain,
    };
    let mut previous = None;
    for ordinal in 0..files.file_count() {
        let file = files.file(ordinal)?;
        ensure!(
            file.base_file_reference == 0
                && previous.is_none_or(|number| number < file.record_number),
            "unassembled, duplicate or unordered canonical allocation record"
        );
        previous = Some(file.record_number);
        let mut instances = BTreeSet::new();
        for attribute in &file.attributes {
            ensure!(
                attribute.type_code != 0x20
                    && attribute.lowest_vcn == 0
                    && instances.insert(attribute.instance),
                "unassembled allocation attribute or duplicate local instance"
            );
            collector.attribute(file.record_number, file.sequence_number, attribute)?;
        }
    }
    let mut previous = None;
    for ordinal in 0..assembly_rows.len() {
        let assembly: Assembly = assembly_rows.get(ordinal)?;
        let base = &assembly.base;
        ensure!(
            previous.is_none_or(|number| number < base.record_number)
                && files
                    .find_record(base.record_number, Some(base.sequence_number))?
                    .is_some(),
            "duplicate or orphaned allocation assembly base"
        );
        previous = Some(base.record_number);
        let mut lists = base.attributes.iter().filter(|a| a.type_code == 0x20);
        let list = lists
            .next()
            .context("assembly physical attribute-list storage is absent")?;
        ensure!(
            lists.next().is_none(),
            "assembly has duplicate list storage owners"
        );
        collector.attribute(base.record_number, base.sequence_number, list)?;
    }
    let expected_intervals = collector.intervals;
    let expected_owners = collector.owners;
    let logical_pin = collector.logical.finish()?;
    let physical_pin = collector.physical.finish()?;
    let logical = SortedRecordStore::open(&logical_pin, scratch)?;
    let physical = SortedRecordStore::open(&physical_pin, scratch)?;
    ensure!(
        logical.len() == expected_intervals && physical.len() == expected_intervals,
        "external ownership ordering lost allocation intervals"
    );
    let mut previous: Option<Interval> = None;
    let mut owners = 0u64;
    for ordinal in 0..logical.len() {
        let interval: Interval = logical.get(ordinal)?;
        ensure!(
            logical.key(ordinal)? == key(interval.owner, interval.vcn),
            "logical interval key differs"
        );
        if let Some(old) = &previous {
            if old.owner == interval.owner {
                ensure!(
                    old.vcn
                        .checked_add(old.clusters)
                        .is_some_and(|end| end <= interval.vcn),
                    "physical attribute claims overlapping VCN ranges"
                );
                ensure!(
                    (
                        old.record_number,
                        old.sequence_number,
                        old.type_code,
                        &old.name_utf16,
                        old.instance
                    ) == (
                        interval.record_number,
                        interval.sequence_number,
                        interval.type_code,
                        &interval.name_utf16,
                        interval.instance
                    ),
                    "logical allocation owner identity changed"
                );
            } else {
                owners = owners.checked_add(1).context("attribute count overflow")?;
            }
        } else {
            owners = 1;
        }
        previous = Some(interval);
    }
    ensure!(
        owners == expected_owners,
        "complete logical allocation owner count differs"
    );
    let mut previous_end = 0;
    for ordinal in 0..physical.len() {
        let interval: Interval = physical.get(ordinal)?;
        ensure!(
            physical.key(ordinal)? == key(interval.lcn, interval.ordinal)
                && interval.lcn >= previous_end,
            "physical allocation intervals overlap"
        );
        previous_end = interval
            .lcn
            .checked_add(interval.clusters)
            .context("physical end overflow")?;
        ensure!(
            previous_end <= domain,
            "physical allocation escapes bitmap domain"
        );
    }
    let needed = domain.div_ceil(8);
    ensure!(
        original.bitmap_bytes == needed && bitmap.seek(SeekFrom::End(0))? == needed,
        "volume bitmap length differs from complete cluster domain"
    );
    bitmap.seek(SeekFrom::Start(0))?;
    let _bitmap_ram = scratch.lease_ram(65536)?;
    let mut window = [0u8; 65536];
    let mut offset = 0;
    let mut digest = Sha256::new();
    let mut allocated = 0u64;
    let mut padding = 0;
    let mut interval_ordinal = 0;
    let mut current = if physical.is_empty() {
        None
    } else {
        Some(physical.get::<Interval>(0)?)
    };
    while offset < needed {
        let count = usize::try_from((needed - offset).min(window.len() as u64))?;
        bitmap.read_exact(&mut window[..count])?;
        digest.update(&window[..count]);
        let base = offset
            .checked_mul(8)
            .context("bitmap bit offset overflow")?;
        let stop = domain.min(
            (offset + count as u64)
                .checked_mul(8)
                .context("bitmap stop overflow")?,
        );
        let mut cursor = base;
        while cursor < stop {
            let (end, expected) = if let Some(interval) = &current {
                let end = interval
                    .lcn
                    .checked_add(interval.clusters)
                    .context("interval end overflow")?;
                if cursor < interval.lcn {
                    (interval.lcn.min(stop), false)
                } else {
                    (end.min(stop), true)
                }
            } else {
                (stop, false)
            };
            ensure!(
                end > cursor && matches_bits(&window[..count], cursor - base, end - base, expected),
                "bitmap has claimed-free or allocated-unowned source clusters at/after LCN {cursor}"
            );
            cursor = end;
            if current
                .as_ref()
                .is_some_and(|i| i.lcn + i.clusters == cursor)
            {
                interval_ordinal += 1;
                current = if interval_ordinal < physical.len() {
                    Some(physical.get(interval_ordinal)?)
                } else {
                    None
                };
            }
        }
        let mut chunk_allocated = window[..count]
            .iter()
            .map(|b| u64::from(b.count_ones()))
            .sum::<u64>();
        if offset + count as u64 == needed && domain % 8 != 0 {
            let mask = (1u8 << (domain % 8)) - 1;
            padding = (window[count - 1] & !mask).count_ones();
            chunk_allocated -= u64::from(padding);
        }
        allocated = allocated
            .checked_add(chunk_allocated)
            .context("allocated cluster count overflow")?;
        offset += count as u64;
    }
    let mut extra = [0];
    ensure!(
        bitmap.read(&mut extra)? == 0
            && bitmap.seek(SeekFrom::End(0))? == needed
            && current.is_none()
            && interval_ordinal == physical.len(),
        "bitmap EOF or complete physical interval coverage changed"
    );
    let current = BitmapSummary {
        sha256: hex::encode(digest.finalize()),
        bitmap_bytes: needed,
        allocated_clusters: allocated,
        free_clusters: domain - allocated,
    };
    ensure!(
        current == *original,
        "volume bitmap changed during complete allocation reconciliation"
    );
    logical.revalidate()?;
    physical.revalidate()?;
    assembly_rows.revalidate()?;
    physical_extensions.revalidate()?;
    consumed_extensions.revalidate()?;
    files.revalidate()?;
    Ok(PagedAllocationReconciliation{status:AllocationReconciliationStatus::ConsistentRawModel,
        bitmap_sha256:current.sha256,domain_clusters:domain,physical_intervals:expected_intervals,
        distinct_attributes:owners,allocated_clusters:allocated,free_clusters:domain-allocated,
        padding_bits_set:padding,physical_ownership:physical_pin,logical_ownership:logical_pin,
        detail:"Complete raw allocation graph reconciles; native and semantic admission remain separate".into()})
}
