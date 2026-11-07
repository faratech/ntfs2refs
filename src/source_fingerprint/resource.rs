//! Resource-backed source ranges and actual inspector-read provenance.
//! Range pins are ordinary metadata, never source exclusion or write authority.
use crate::{
    ntfs_inspect::{
        self, LogicalHashStatus, MetadataRole, PagedInspection, RootFileDomain,
        SourceMetadataBudget,
        external_sort::ExternalSort,
        paged_storage::SourceScratch,
        record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
    },
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

pub const FULL_KIND: &str = "ntfs_resource_allocated_ranges_xxh3_128_4mib_pieces_v1";
pub const EXTENT_KIND: &str = "ntfs_resource_metadata_and_extent_fingerprint_v1";
const DOMAIN: &[u8] = b"ntfs2refs/source/resource-metadata-and-extents/v1\0";
const GRANULE: u64 = 4096;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    offset: u64,
    length: u64,
}
impl Range {
    fn end(self) -> Result<u64> {
        self.offset
            .checked_add(self.length)
            .context("source range overflow")
    }
}
fn key(start: u64, ordinal: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&start.to_be_bytes());
    key[8..].copy_from_slice(&ordinal.to_be_bytes());
    key
}
fn span(start: u64, length: u64, limit: u64) -> Result<Range> {
    ensure!(
        length > 0 && start.checked_add(length).is_some_and(|end| end <= limit),
        "source range is empty or escapes partition"
    );
    Ok(Range {
        offset: start,
        length,
    })
}
fn union_push(
    current: &mut Option<Range>,
    writer: &mut SortedRecordWriter,
    row: Range,
) -> Result<()> {
    if let Some(prior) = current {
        ensure!(
            prior.offset <= row.offset,
            "source union input order regressed"
        );
        if row.offset <= prior.end()? {
            prior.length = prior.end()?.max(row.end()?) - prior.offset;
            return Ok(());
        }
        writer.push(key(prior.offset, 0), prior)?;
    }
    *current = Some(row);
    Ok(())
}
fn normalize(
    pin: RecordStorePin,
    root: &Path,
    limit: u64,
    scratch: &SourceScratch,
) -> Result<RecordStorePin> {
    let input = SortedRecordStore::open(&pin, scratch)?;
    let mut writer = SortedRecordWriter::new(root, *b"N2RFRNG1", scratch)?;
    let mut current: Option<Range> = None;
    for ordinal in 0..input.len() {
        let row: Range = input.get(ordinal)?;
        let row = span(row.offset, row.length, limit)?;
        ensure!(
            input.key(ordinal)?[..8] == row.offset.to_be_bytes(),
            "range sort key differs"
        );
        if let Some(prior) = &mut current {
            if row.offset <= prior.end()? {
                prior.length = prior.end()?.max(row.end()?) - prior.offset;
                continue;
            }
            writer.push(key(prior.offset, 0), prior)?;
        }
        current = Some(row);
    }
    if let Some(row) = current {
        writer.push(key(row.offset, 0), &row)?;
    }
    input.revalidate()?;
    let output = writer.finish()?;
    drop(input);
    scratch.retire_created(&pin.data)?;
    scratch.retire_created(&pin.directory)?;
    Ok(output)
}
fn covers(outer: &SortedRecordStore, inner: &SortedRecordStore) -> Result<()> {
    let mut at = 0;
    let mut current = if outer.is_empty() {
        None
    } else {
        Some(outer.get::<Range>(0)?)
    };
    for ordinal in 0..inner.len() {
        let row: Range = inner.get(ordinal)?;
        while current.is_some_and(|r| r.offset + r.length <= row.offset) {
            at += 1;
            current = if at < outer.len() {
                Some(outer.get(at)?)
            } else {
                None
            };
        }
        ensure!(
            current.is_some_and(
                |r| r.offset <= row.offset && r.offset + r.length >= row.offset + row.length
            ),
            "source reads/exclusions escape their complete covering domain"
        );
    }
    Ok(())
}
fn difference(
    outer: &SortedRecordStore,
    removed: &SortedRecordStore,
    root: &Path,
    scratch: &SourceScratch,
) -> Result<RecordStorePin> {
    let mut writer = SortedRecordWriter::new(root, *b"N2RFRNG1", scratch)?;
    let mut index = 0;
    let mut current = if removed.is_empty() {
        None
    } else {
        Some(removed.get::<Range>(0)?)
    };
    for ordinal in 0..outer.len() {
        let row: Range = outer.get(ordinal)?;
        let end = row.end()?;
        let mut cursor = row.offset;
        while current.is_some_and(|r| r.offset + r.length <= cursor) {
            index += 1;
            current = if index < removed.len() {
                Some(removed.get(index)?)
            } else {
                None
            };
        }
        while let Some(cut) = current.filter(|r| r.offset < end) {
            if cut.offset > cursor {
                writer.push(
                    key(cursor, 0),
                    &Range {
                        offset: cursor,
                        length: cut.offset.min(end) - cursor,
                    },
                )?;
            }
            cursor = cursor.max(cut.end()?.min(end));
            if cut.end()? > end {
                break;
            }
            index += 1;
            current = if index < removed.len() {
                Some(removed.get(index)?)
            } else {
                None
            };
        }
        if cursor < end {
            writer.push(
                key(cursor, 0),
                &Range {
                    offset: cursor,
                    length: end - cursor,
                },
            )?;
        }
    }
    writer.finish()
}
fn range_bytes(store: &SortedRecordStore) -> Result<u64> {
    let mut bytes = 0u64;
    for ordinal in 0..store.len() {
        let row: Range = store.get(ordinal)?;
        bytes = bytes
            .checked_add(row.length)
            .context("source range byte count overflow")?;
    }
    Ok(bytes)
}

fn contains_range(store: &SortedRecordStore, wanted: Range) -> Result<bool> {
    for ordinal in 0..store.len() {
        let row: Range = store.get(ordinal)?;
        if row.offset > wanted.offset {
            return Ok(false);
        }
        if row.offset <= wanted.offset && row.end()? >= wanted.end()? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn classify_reads(
    reads: &SortedRecordStore,
    covered: &SortedRecordStore,
    omitted: &SortedRecordStore,
) -> Result<()> {
    struct Cursor<'a> {
        store: &'a SortedRecordStore,
        ordinal: u64,
        current: Option<Range>,
    }
    impl<'a> Cursor<'a> {
        fn new(store: &'a SortedRecordStore) -> Result<Self> {
            Ok(Self {
                store,
                ordinal: 0,
                current: if store.is_empty() {
                    None
                } else {
                    Some(store.get(0)?)
                },
            })
        }
        fn at(&mut self, offset: u64) -> Result<Option<Range>> {
            while self.current.is_some_and(|r| r.offset + r.length <= offset) {
                self.ordinal = self
                    .ordinal
                    .checked_add(1)
                    .context("read classification ordinal overflow")?;
                self.current = if self.ordinal < self.store.len() {
                    Some(self.store.get(self.ordinal)?)
                } else {
                    None
                };
            }
            Ok(self.current.filter(|r| r.offset <= offset))
        }
    }
    let mut covered = Cursor::new(covered)?;
    let mut omitted = Cursor::new(omitted)?;
    for ordinal in 0..reads.len() {
        let row: Range = reads.get(ordinal)?;
        let end = row.end()?;
        let mut at = row.offset;
        while at < end {
            let a = covered.at(at)?;
            let b = omitted.at(at)?;
            ensure!(
                a.is_some() != b.is_some(),
                "actual inspection bytes are missing or multiply classified by fingerprint scope"
            );
            let mut next = a.or(b).context("inspection scope absent")?.end()?.min(end);
            for cursor in [&covered, &omitted] {
                if let Some(row) = cursor.current.filter(|row| row.offset > at) {
                    next = next.min(row.offset);
                }
            }
            ensure!(next > at, "inspection read classification made no progress");
            at = next;
        }
    }
    Ok(())
}

/// All returned bytes are recorded only after the underlying actual read
/// succeeds. Failed reads/spills poison finish rather than producing a partial
/// successful transcript. The standalone result is deliberately unbound.
pub struct PagedReadRecorder<R> {
    inner: R,
    position: u64,
    length: u64,
    sort: ExternalSort,
    scratch: SourceScratch,
    root: std::path::PathBuf,
    reads: u64,
    bytes: u64,
    poisoned: bool,
}
pub struct UnboundReadCoverage {
    store: SortedRecordStore,
    reads: u64,
    bytes: u64,
    length: u64,
}
impl<R: Read + Seek> PagedReadRecorder<R> {
    pub fn new(mut inner: R, length: u64, root: &Path, scratch: &SourceScratch) -> Result<Self> {
        let position = inner.stream_position()?;
        ensure!(
            position <= length,
            "initial source read position escapes partition"
        );
        Ok(Self {
            inner,
            position,
            length,
            sort: ExternalSort::new(&root.join("read-events"), *b"N2RREAD1", scratch)?,
            scratch: scratch.clone(),
            root: root.to_owned(),
            reads: 0,
            bytes: 0,
            poisoned: false,
        })
    }
    pub fn finish(self) -> Result<(R, UnboundReadCoverage)> {
        ensure!(
            !self.poisoned,
            "cannot finish incomplete source-read transcript"
        );
        let pin = normalize(
            self.sort.finish()?,
            &self.root.join("read-union"),
            self.length,
            &self.scratch,
        )?;
        let store = SortedRecordStore::open(&pin, &self.scratch)?;
        Ok((
            self.inner,
            UnboundReadCoverage {
                store,
                reads: self.reads,
                bytes: self.bytes,
                length: self.length,
            },
        ))
    }
}
impl<R: Read + Seek> Read for PagedReadRecorder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(io::Error::other("source-read transcript is poisoned"));
        }
        let result = (|| -> Result<usize> {
            let count = self.inner.read(output)?;
            ensure!(
                count <= output.len(),
                "underlying source returned an oversized read"
            );
            if count > 0 {
                let row = span(self.position, count as u64, self.length)?;
                self.sort.push(key(row.offset, self.reads), &row)?;
                self.reads = self.reads.checked_add(1).context("read count overflow")?;
                self.bytes = self
                    .bytes
                    .checked_add(count as u64)
                    .context("read byte count overflow")?;
                self.position = row.end()?;
            }
            Ok(count)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result.map_err(io::Error::other)
    }
}
impl<R: Read + Seek> Seek for PagedReadRecorder<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.poisoned {
            return Err(io::Error::other("source-read transcript is poisoned"));
        }
        let result = self.inner.seek(position).and_then(|position| {
            if position > self.length {
                return Err(io::Error::other("source seek escapes partition"));
            }
            self.position = position;
            Ok(position)
        });
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
#[derive(Serialize)]
pub struct ReadCoverageReport {
    pub source_inspection_sha256: String,
    pub successful_reads: u64,
    pub returned_bytes: u64,
    pub unique_ranges: u64,
    pub unique_bytes: u64,
    pub ranges: RecordStorePin,
    pub actual_inspector_invocation_bound: bool,
    pub grants_source_admission: bool,
}
pub struct InspectionReadCoverage {
    coverage: UnboundReadCoverage,
    source_pin: String,
}
impl InspectionReadCoverage {
    pub fn report(&self) -> Result<ReadCoverageReport> {
        Ok(ReadCoverageReport {
            source_inspection_sha256: self.source_pin.clone(),
            successful_reads: self.coverage.reads,
            returned_bytes: self.coverage.bytes,
            unique_ranges: self.coverage.store.len(),
            unique_bytes: range_bytes(&self.coverage.store)?,
            ranges: self.coverage.store.pin().clone(),
            actual_inspector_invocation_bound: true,
            grants_source_admission: false,
        })
    }
}
/// Only this function binds a transcript to the actual inspector invocation.
/// A standalone recorder or serialized pin cannot manufacture that association.
pub fn inspect_recorded<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    budget: n2r_win32::tree_resources::ResourceBudget,
    policy: VerificationPolicy,
    root: &Path,
) -> Result<(PagedInspection, InspectionReadCoverage)> {
    let scratch = SourceScratch::new(SourceMetadataBudget::from_resource_budget(budget)?)?;
    inspect_recorded_with_scratch(reader, length, budget, policy, root, &scratch)
}

pub fn inspect_recorded_with_scratch<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    budget: n2r_win32::tree_resources::ResourceBudget,
    policy: VerificationPolicy,
    root: &Path,
    scratch: &SourceScratch,
) -> Result<(PagedInspection, InspectionReadCoverage)> {
    inspect_recorded_with_layout_scope(reader,length,budget,policy,root,scratch,
        n2r_win32::general_layout::GeneralDiskLayoutProfile::DedicatedData)
}

pub(crate) fn inspect_recorded_with_layout_scope<R: Read + Seek>(
    reader:&mut R,length:u64,budget:n2r_win32::tree_resources::ResourceBudget,
    policy:VerificationPolicy,root:&Path,scratch:&SourceScratch,
    layout:n2r_win32::general_layout::GeneralDiskLayoutProfile,
) -> Result<(PagedInspection,InspectionReadCoverage)> {
    ensure!(!root.exists(), "fresh recorded source directory required");
    fs::create_dir(root)?;
    let mut recorder = PagedReadRecorder::new(reader, length, root, scratch)?;
    let source = ntfs_inspect::inspect_paged_with_layout_scope(
        &mut recorder,
        length,
        budget,
        policy,
        &root.join("raw"),
        scratch,
        layout,
    )?;
    let (_, coverage) = recorder.finish()?;
    let source_pin = source.canonical_sha256()?;
    Ok((
        source,
        InspectionReadCoverage {
            coverage,
            source_pin,
        },
    ))
}

#[derive(Clone, Debug, Serialize)]
pub struct FingerprintPins {
    pub schema_version: u32,
    pub kind: &'static str,
    pub partition_bytes: u64,
    pub source_inspection_sha256: String,
    pub policy: VerificationPolicy,
    pub allocated: RecordStorePin,
    pub covered: RecordStorePin,
    pub omitted: RecordStorePin,
    pub allocated_bytes: u64,
    pub covered_bytes: u64,
    pub omitted_bytes: u64,
    pub raw_extent_identity_streams: u64,
}
/// Serializable metadata for a cold reader. Reopening this does not recreate
/// the original inspector, a live source certificate, or write authority.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReopenedFingerprintPins {
    pub schema_version: u32,
    pub kind: String,
    pub partition_bytes: u64,
    pub source_inspection_sha256: String,
    pub policy: VerificationPolicy,
    pub allocated: RecordStorePin,
    pub covered: RecordStorePin,
    pub omitted: RecordStorePin,
    pub allocated_bytes: u64,
    pub covered_bytes: u64,
    pub omitted_bytes: u64,
    pub raw_extent_identity_streams: u64,
}
impl ReopenedFingerprintPins {
    pub(crate) fn open(self, scratch: &SourceScratch) -> Result<PagedSourceFingerprint> {
        let kind = if self.policy.is_fast() {
            EXTENT_KIND
        } else {
            FULL_KIND
        };
        ensure!(
            self.schema_version == 1
                && self.kind == kind
                && self.partition_bytes >= GRANULE
                && self.partition_bytes.is_multiple_of(GRANULE)
                && self.source_inspection_sha256.len() == 64
                && self
                    .source_inspection_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "cold fingerprint schema, geometry or inspection pin differs"
        );
        let allocated = SortedRecordStore::open(&self.allocated, scratch)?;
        let covered = SortedRecordStore::open(&self.covered, scratch)?;
        let omitted = SortedRecordStore::open(&self.omitted, scratch)?;
        let check = |store: &SortedRecordStore, expected: u64| -> Result<()> {
            let mut bytes = 0u64;
            let mut prior_end = None;
            for ordinal in 0..store.len() {
                let range: Range = store.get(ordinal)?;
                let range = span(range.offset, range.length, self.partition_bytes)?;
                ensure!(
                    store.key(ordinal)?[..8] == range.offset.to_be_bytes()
                        && prior_end.is_none_or(|end| end < range.offset),
                    "cold fingerprint ranges are not canonical and disjoint"
                );
                bytes = bytes
                    .checked_add(range.length)
                    .context("cold fingerprint byte overflow")?;
                prior_end = Some(range.end()?);
            }
            ensure!(bytes == expected, "cold fingerprint range total differs");
            Ok(())
        };
        check(&allocated, self.allocated_bytes)?;
        check(&covered, self.covered_bytes)?;
        check(&omitted, self.omitted_bytes)?;
        ensure!(
            allocated.len() > 0
                && covered.len() > 0
                && self.covered_bytes.checked_add(self.omitted_bytes) == Some(self.allocated_bytes)
                && self.allocated_bytes <= self.partition_bytes
                && (self.policy.is_fast() || self.omitted_bytes == 0),
            "cold fingerprint allocation classification is incomplete"
        );
        let (mut ci, mut oi) = (0, 0);
        for ai in 0..allocated.len() {
            let allocation: Range = allocated.get(ai)?;
            let mut cursor = allocation.offset;
            let end = allocation.end()?;
            while cursor < end {
                let c: Option<Range> = (ci < covered.len()).then(|| covered.get(ci)).transpose()?;
                let o: Option<Range> = (oi < omitted.len()).then(|| omitted.get(oi)).transpose()?;
                let take_covered = match (c, o) {
                    (Some(c), Some(o)) => c.offset <= o.offset,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    _ => anyhow::bail!("cold fingerprint leaves allocated bytes unclassified"),
                };
                let range = if take_covered {
                    ci += 1;
                    c.unwrap()
                } else {
                    oi += 1;
                    o.unwrap()
                };
                ensure!(
                    range.offset == cursor && range.end()? <= end,
                    "cold fingerprint covered/omitted union differs from allocation"
                );
                cursor = range.end()?;
            }
        }
        ensure!(
            ci == covered.len() && oi == omitted.len(),
            "cold fingerprint has extra classified ranges"
        );
        let value = PagedSourceFingerprint {
            pins: FingerprintPins {
                schema_version: self.schema_version,
                kind,
                partition_bytes: self.partition_bytes,
                source_inspection_sha256: self.source_inspection_sha256,
                policy: self.policy,
                allocated: self.allocated,
                covered: self.covered,
                omitted: self.omitted,
                allocated_bytes: self.allocated_bytes,
                covered_bytes: self.covered_bytes,
                omitted_bytes: self.omitted_bytes,
                raw_extent_identity_streams: self.raw_extent_identity_streams,
            },
            allocated,
            covered,
            omitted,
            scratch: scratch.clone(),
        };
        value.revalidate()?;
        Ok(value)
    }
}
#[derive(Serialize)]
pub struct FingerprintReport {
    pub kind: &'static str,
    pub partition_bytes: u64,
    pub allocated_ranges: u64,
    pub allocated_bytes: u64,
    pub fingerprint_ranges: u64,
    pub fingerprint_bytes: u64,
    pub omitted_initialized_payload_ranges: u64,
    pub omitted_initialized_payload_bytes: u64,
    pub raw_extent_identity_streams: u64,
    pub whole_source_content_digest: bool,
    pub raw_inspector_content_hashes_preserved: bool,
    pub grants_source_admission: bool,
}
pub struct PagedSourceFingerprint {
    pins: FingerprintPins,
    allocated: SortedRecordStore,
    covered: SortedRecordStore,
    omitted: SortedRecordStore,
    scratch: SourceScratch,
}
#[derive(Deserialize)]
struct PhysicalCoordinate {
    lcn: u64,
    clusters: u64,
}
impl PagedSourceFingerprint {
    pub fn for_inspection(
        source: &PagedInspection,
        partition_bytes: u64,
        policy: VerificationPolicy,
        root: &Path,
    ) -> Result<Self> {
        source.revalidate()?;
        ensure!(
            partition_bytes >= GRANULE
                && source.header().geometry.volume_size <= partition_bytes
                && source.allocation().status
                    == ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel,
            "source fingerprint requires complete physical allocation"
        );
        ensure!(
            !root.exists(),
            "fresh fingerprint metadata directory required"
        );
        fs::create_dir(root)?;
        let scratch = source.metadata_scratch();
        let _row = scratch.lease_ram(
            scratch
                .budget()
                .record_bytes
                .checked_mul(4)
                .context("fingerprint row RAM overflow")?,
        )?;
        let physical = SortedRecordStore::open(&source.allocation().physical_ownership, &scratch)?;
        ensure!(
            physical.len() == source.allocation().physical_intervals,
            "physical ownership count differs"
        );
        let cluster = u64::from(source.header().geometry.cluster_size);
        let domain = source
            .header()
            .geometry
            .total_clusters
            .checked_mul(cluster)
            .context("cluster byte domain overflow")?;
        ensure!(
            domain <= partition_bytes,
            "cluster domain escapes partition"
        );
        // Ownership is already globally ordered by LCN. Merge the three
        // fixed reserved regions directly instead of sorting/copying that
        // complete physical table a second time.
        let mut writer = SortedRecordWriter::new(&root.join("allocated"), *b"N2RFRNG1", &scratch)?;
        let mut literals = [
            Some(span(0, GRANULE, partition_bytes)?),
            Some(span(partition_bytes - GRANULE, GRANULE, partition_bytes)?),
            if domain < partition_bytes {
                Some(span(domain, partition_bytes - domain, partition_bytes)?)
            } else {
                None
            },
        ];
        literals.sort_unstable_by_key(|row| row.map_or(u64::MAX, |r| r.offset));
        let mut literal = 0usize;
        let mut current = None;
        let mut prior_end = 0;
        for index in 0..physical.len() {
            let row: PhysicalCoordinate = physical.get(index)?;
            ensure!(
                physical.key(index)?[..8] == row.lcn.to_be_bytes(),
                "physical ownership key differs"
            );
            let start = row
                .lcn
                .checked_mul(cluster)
                .context("physical offset overflow")?;
            let length = row
                .clusters
                .checked_mul(cluster)
                .context("physical length overflow")?;
            let range = span(start, length, domain)?;
            ensure!(start >= prior_end, "source physical ownership overlaps");
            prior_end = range.end()?;
            while literal < literals.len() && literals[literal].is_some_and(|r| r.offset <= start) {
                union_push(
                    &mut current,
                    &mut writer,
                    literals[literal].context("reserved source range absent")?,
                )?;
                literal += 1;
            }
            union_push(&mut current, &mut writer, range)?;
        }
        while literal < literals.len() {
            if let Some(row) = literals[literal] {
                union_push(&mut current, &mut writer, row)?;
            }
            literal += 1;
        }
        if let Some(row) = current {
            writer.push(key(row.offset, 0), &row)?;
        }
        physical.revalidate()?;
        drop(physical);
        let allocated_pin = writer.finish()?;
        let allocated = SortedRecordStore::open(&allocated_pin, &scratch)?;
        let mut omitted = ExternalSort::new(&root.join("omitted-input"), *b"N2RFOMI1", &scratch)?;
        let mut ordinal = 0;
        let mut extent_streams = 0u64;
        let final_granule = (partition_bytes - GRANULE) / GRANULE * GRANULE;
        for index in 0..source.file_count() {
            let file = source.file(index)?;
            for stream in &file.streams {
                extent_streams = extent_streams
                    .checked_add(u64::from(
                        stream.logical_hash_status == LogicalHashStatus::NotReadExtentIdentityV1,
                    ))
                    .context("extent-evidence stream count overflow")?;
            }
            if !policy.is_fast()
                || file.is_directory
                || file.is_metadata
                || file.base_file_reference != 0
                || file.record_number < 16
                || file.metadata_role != MetadataRole::OutsideExtendCandidate
                || file.metadata_role_issue.is_some()
            {
                continue;
            }
            for stream in &file.streams {
                let explicit = stream.logical_hash_status
                    == LogicalHashStatus::NotReadExtentIdentityV1
                    && stream.logical_sha256.is_none()
                    && (if source.is_windows_conversion() {
                        crate::ntfs_attestation::extent_identity_stream_request_windows_domain(
                            source, &file, stream,
                        )
                    } else {
                        crate::ntfs_attestation::extent_identity_stream_request_domain(
                            source, &file, stream, true, true,
                        )
                    }).with_context(|| format!(
                        "source fingerprint extent selector at FILE {} stream {:?}",
                        file.record_number, stream.name_utf16,
                    ))?
                    .is_some();
                if stream.resident
                    || stream.flags != 0
                    || stream.initialized_size != stream.logical_size
                    || (!explicit
                        && (stream.logical_hash_status != LogicalHashStatus::Complete
                            || !stream
                                .logical_sha256
                                .as_deref()
                                .is_some_and(n2r_win32::content_digest::is_hex)))
                {
                    continue;
                }
                let mut attrs = file
                    .attributes
                    .iter()
                    .filter(|a| a.type_code == 0x80 && a.name_utf16 == stream.name_utf16);
                let Some(attribute) = attrs.next() else {
                    continue;
                };
                ensure!(
                    attrs.next().is_none(),
                    "ambiguous fingerprint DATA attribute"
                );
                ensure!(
                    !attribute.resident
                        && attribute.flags == 0
                        && attribute.compression_unit == 0
                        && attribute.lowest_vcn == 0
                        && attribute.total_allocated_size.is_none()
                        && attribute.logical_size == stream.logical_size
                        && attribute.initialized_size == stream.initialized_size
                        && attribute.allocated_size == stream.allocated_size
                        && attribute.extents == stream.extents,
                    "fingerprint DATA differs from its stream inventory"
                );
                let prefix = stream.logical_size / GRANULE * GRANULE;
                let mut coverage = 0u64;
                for extent in &stream.extents {
                    ensure!(
                        extent.logical_offset == coverage
                            && extent.length > 0
                            && extent.length.is_multiple_of(GRANULE),
                        "invalid fingerprint DATA coverage"
                    );
                    coverage = coverage
                        .checked_add(extent.length)
                        .context("fingerprint DATA coverage overflow")?;
                    let start = extent
                        .physical_offset
                        .context("plain fingerprint DATA has a sparse run")?;
                    ensure!(
                        start.is_multiple_of(GRANULE),
                        "unaligned fingerprint DATA physical run"
                    );
                    if extent.logical_offset < prefix {
                        let length = extent.length.min(prefix - extent.logical_offset);
                        let end = start
                            .checked_add(length)
                            .context("fingerprint payload overflow")?
                            .min(final_granule);
                        let start = start.max(GRANULE);
                        if start < end {
                            omitted.push(
                                key(start, ordinal),
                                &Range {
                                    offset: start,
                                    length: end - start,
                                },
                            )?;
                            ordinal = ordinal
                                .checked_add(1)
                                .context("omitted range ordinal overflow")?;
                        }
                    }
                }
                ensure!(
                    coverage == stream.allocated_size && coverage >= stream.logical_size,
                    "fingerprint DATA allocation differs from complete mapping"
                );
            }
        }
        let omitted_pin = normalize(
            omitted.finish()?,
            &root.join("omitted"),
            partition_bytes,
            &scratch,
        )?;
        let omitted = SortedRecordStore::open(&omitted_pin, &scratch)?;
        covers(&allocated, &omitted)?;
        let covered_pin = difference(&allocated, &omitted, &root.join("covered"), &scratch)?;
        let covered = SortedRecordStore::open(&covered_pin, &scratch)?;
        ensure!(
            contains_range(
                &covered,
                Range {
                    offset: 0,
                    length: GRANULE
                }
            )? && contains_range(
                &covered,
                Range {
                    offset: partition_bytes - GRANULE,
                    length: GRANULE
                }
            )?,
            "fingerprint must read both complete bootstrap bookends"
        );
        let allocated_bytes = range_bytes(&allocated)?;
        let covered_bytes = range_bytes(&covered)?;
        let omitted_bytes = range_bytes(&omitted)?;
        ensure!(
            covered_bytes.checked_add(omitted_bytes) == Some(allocated_bytes),
            "fingerprint byte coverage is incomplete"
        );
        let pins = FingerprintPins {
            schema_version: 1,
            kind: if policy.is_fast() {
                EXTENT_KIND
            } else {
                FULL_KIND
            },
            partition_bytes,
            source_inspection_sha256: source.canonical_sha256()?,
            policy,
            allocated: allocated_pin,
            covered: covered_pin,
            omitted: omitted_pin,
            allocated_bytes,
            covered_bytes,
            omitted_bytes,
            raw_extent_identity_streams: extent_streams,
        };
        source.revalidate()?;
        let value = Self {
            pins,
            allocated,
            covered,
            omitted,
            scratch,
        };
        value.revalidate()?;
        Ok(value)
    }
    pub fn pins(&self) -> &FingerprintPins {
        &self.pins
    }
    pub fn kind(&self) -> &'static str {
        self.pins.kind
    }
    pub fn matches_inspection(&self, source: &PagedInspection) -> bool {
        source
            .canonical_sha256()
            .is_ok_and(|pin| pin == self.pins.source_inspection_sha256)
    }
    pub fn covered_range_count(&self) -> u64 {
        self.covered.len()
    }
    pub fn covered_range(&self, ordinal: u64) -> Result<(u64, u64)> {
        let row: Range = self.covered.get(ordinal)?;
        Ok((row.offset, row.length))
    }
    pub fn report(&self) -> FingerprintReport {
        FingerprintReport {
            kind: self.kind(),
            partition_bytes: self.pins.partition_bytes,
            allocated_ranges: self.allocated.len(),
            allocated_bytes: self.pins.allocated_bytes,
            fingerprint_ranges: self.covered.len(),
            fingerprint_bytes: self.pins.covered_bytes,
            omitted_initialized_payload_ranges: self.omitted.len(),
            omitted_initialized_payload_bytes: self.pins.omitted_bytes,
            raw_extent_identity_streams: self.pins.raw_extent_identity_streams,
            whole_source_content_digest: false,
            raw_inspector_content_hashes_preserved: self.pins.raw_extent_identity_streams == 0,
            grants_source_admission: false,
        }
    }
    pub fn revalidate(&self) -> Result<()> {
        self.allocated.revalidate()?;
        self.covered.revalidate()?;
        self.omitted.revalidate()
    }
    pub fn validate_inspection_reads(&self, reads: &InspectionReadCoverage) -> Result<()> {
        self.revalidate()?;
        reads.coverage.store.revalidate()?;
        ensure!(
            reads.source_pin == self.pins.source_inspection_sha256
                && reads.coverage.length == self.pins.partition_bytes,
            "inspection read transcript belongs to another source invocation"
        );
        covers(&self.allocated, &reads.coverage.store)?;
        classify_reads(&reads.coverage.store, &self.covered, &self.omitted)?;
        Ok(())
    }
    pub fn validate_reads(&self, reads: &InspectionReadCoverage) -> Result<()> {
        self.validate_inspection_reads(reads)
    }
    pub fn hash(&self, source: &mut n2r_win32::GeneralFrozenPartition) -> Result<String> {
        use crate::parallel_digest::{Chunk, MAX_CHUNK_BYTES, digest_frozen_chunks};
        ensure!(
            source.byte_len() == self.pins.partition_bytes,
            "fingerprint source length differs"
        );
        self.revalidate()?;
        let batch = usize::try_from((u64::from(self.scratch.budget().page_bytes) / 128).max(1))?;
        let depth = source
            .io_profile()
            .queue_depth
            .clamp(1, 8)
            .min(batch.max(1));
        let workers = crate::parallel_digest::workers().min(batch).max(1);
        let (buffers, threads) = if depth > 1 {
            (depth, depth - 1)
        } else {
            (workers + 2, workers)
        };
        // Each additional physical lane has its own SDK aligned buffer in
        // addition to the caller-owned digest buffer. Reserve both before
        // digest_frozen_chunks can open any lane. The original source buffer
        // is already owned and paid by ResourceSourceContext.
        let extra_lanes = depth.saturating_sub(1) as u64;
        let lane_bytes = extra_lanes
            .checked_mul(n2r_win32::GeneralFrozenPartition::read_buffer_memory_bytes())
            .and_then(|n| n.checked_add(extra_lanes * 65536))
            .context("fingerprint physical lane RAM overflow")?;
        let ram = (buffers as u64)
            .checked_mul(MAX_CHUNK_BYTES as u64)
            .and_then(|n| n.checked_add(lane_bytes))
            .and_then(|n| n.checked_add(threads as u64 * 2 * 1024 * 1024))
            .and_then(|n| n.checked_add(batch as u64 * 256))
            .context("fingerprint worker RAM overflow")?;
        let _ram = self.scratch.lease_ram(ram)?;
        let mut pieces = Vec::new();
        pieces.try_reserve_exact(batch)?;
        let mut frames = Vec::new();
        frames.try_reserve_exact(batch)?;
        let mut digest = n2r_win32::sha256_native::Sha256::new()?;
        let mut flush = |pieces: &mut Vec<Chunk>, frames: &mut Vec<Option<Range>>| -> Result<()> {
            let digests = digest_frozen_chunks(source, pieces)?;
            ensure!(
                digests.len() == frames.len(),
                "fingerprint piece digest coverage differs"
            );
            for (frame, hash) in frames.iter().zip(digests) {
                if let Some(row) = frame {
                    digest.update(&row.offset.to_le_bytes())?;
                    digest.update(&row.length.to_le_bytes())?;
                }
                digest.update(&hash)?;
            }
            pieces.clear();
            frames.clear();
            Ok(())
        };
        for ordinal in 0..self.covered.len() {
            let row: Range = self.covered.get(ordinal)?;
            let mut done = 0;
            while done < row.length {
                let length = (row.length - done).min(MAX_CHUNK_BYTES as u64) as usize;
                pieces.push(Chunk {
                    offset: row.offset + done,
                    length,
                });
                frames.push((done == 0).then_some(row));
                done += length as u64;
                if pieces.len() == batch {
                    flush(&mut pieces, &mut frames)?;
                }
            }
        }
        if !pieces.is_empty() {
            flush(&mut pieces, &mut frames)?;
        }
        drop(flush);
        let inner = digest.finish()?;
        let mut envelope = Sha256::new();
        envelope.update(DOMAIN);
        envelope.update(self.pins.partition_bytes.to_le_bytes());
        envelope.update(hex::decode(&self.pins.source_inspection_sha256)?);
        envelope.update([u8::from(self.pins.policy.is_fast())]);
        for ranges in [&self.covered, &self.omitted] {
            envelope.update(ranges.len().to_le_bytes());
            for ordinal in 0..ranges.len() {
                let row: Range = ranges.get(ordinal)?;
                envelope.update(row.offset.to_le_bytes());
                envelope.update(row.length.to_le_bytes());
            }
        }
        envelope.update(inner);
        self.revalidate()?;
        Ok(hex::encode(envelope.finalize()))
    }
    /// Same canonical fingerprint with a bounded partition reader. Its caller
    /// brackets the actual phase/owner; generic bytes cannot issue admission.
    pub(crate) fn hash_partition_reader<R: Read + Seek>(
        &self,
        source: &mut R,
        partition_bytes: u64,
    ) -> Result<String> {
        use crate::parallel_digest::{Chunk, MAX_CHUNK_BYTES, digest_chunks};
        ensure!(
            partition_bytes == self.pins.partition_bytes,
            "fingerprint source length differs"
        );
        self.revalidate()?;
        let batch = usize::try_from((u64::from(self.scratch.budget().page_bytes) / 128).max(1))?;
        let depth = 1usize;
        let workers = crate::parallel_digest::workers().min(batch).max(1);
        let (buffers, threads) = if depth > 1 {
            (depth, depth - 1)
        } else {
            (workers + 2, workers)
        };
        // Each additional physical lane has its own SDK aligned buffer in
        // addition to the caller-owned digest buffer. Reserve both before
        // digest_frozen_chunks can open any lane. The original source buffer
        // is already owned and paid by ResourceSourceContext.
        let extra_lanes = depth.saturating_sub(1) as u64;
        let lane_bytes = extra_lanes
            .checked_mul(n2r_win32::GeneralFrozenPartition::read_buffer_memory_bytes())
            .and_then(|n| n.checked_add(extra_lanes * 65536))
            .context("fingerprint physical lane RAM overflow")?;
        let ram = (buffers as u64)
            .checked_mul(MAX_CHUNK_BYTES as u64)
            .and_then(|n| n.checked_add(lane_bytes))
            .and_then(|n| n.checked_add(threads as u64 * 2 * 1024 * 1024))
            .and_then(|n| n.checked_add(batch as u64 * 256))
            .context("fingerprint worker RAM overflow")?;
        let _ram = self.scratch.lease_ram(ram)?;
        let mut pieces = Vec::new();
        pieces.try_reserve_exact(batch)?;
        let mut frames = Vec::new();
        frames.try_reserve_exact(batch)?;
        let mut digest = n2r_win32::sha256_native::Sha256::new()?;
        let mut flush = |pieces: &mut Vec<Chunk>, frames: &mut Vec<Option<Range>>| -> Result<()> {
            let digests = digest_chunks(source, pieces)?;
            ensure!(
                digests.len() == frames.len(),
                "fingerprint piece digest coverage differs"
            );
            for (frame, hash) in frames.iter().zip(digests) {
                if let Some(row) = frame {
                    digest.update(&row.offset.to_le_bytes())?;
                    digest.update(&row.length.to_le_bytes())?;
                }
                digest.update(&hash)?;
            }
            pieces.clear();
            frames.clear();
            Ok(())
        };
        for ordinal in 0..self.covered.len() {
            let row: Range = self.covered.get(ordinal)?;
            let mut done = 0;
            while done < row.length {
                let length = (row.length - done).min(MAX_CHUNK_BYTES as u64) as usize;
                pieces.push(Chunk {
                    offset: row.offset + done,
                    length,
                });
                frames.push((done == 0).then_some(row));
                done += length as u64;
                if pieces.len() == batch {
                    flush(&mut pieces, &mut frames)?;
                }
            }
        }
        if !pieces.is_empty() {
            flush(&mut pieces, &mut frames)?;
        }
        drop(flush);
        let inner = digest.finish()?;
        let mut envelope = Sha256::new();
        envelope.update(DOMAIN);
        envelope.update(self.pins.partition_bytes.to_le_bytes());
        envelope.update(hex::decode(&self.pins.source_inspection_sha256)?);
        envelope.update([u8::from(self.pins.policy.is_fast())]);
        for ranges in [&self.covered, &self.omitted] {
            envelope.update(ranges.len().to_le_bytes());
            for ordinal in 0..ranges.len() {
                let row: Range = ranges.get(ordinal)?;
                envelope.update(row.offset.to_le_bytes());
                envelope.update(row.length.to_le_bytes());
            }
        }
        envelope.update(inner);
        self.revalidate()?;
        Ok(hex::encode(envelope.finalize()))
    }
}
