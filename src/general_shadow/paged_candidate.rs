//! Resource-owned source-backed bytes. Routes originate only in an actual
//! post-freeze native layout observation; saved facts cannot construct an owner.
use super::{
    PagedInputs,
    source_backed::{
        CandidateChunk, CandidateReadSpans, ClosingShadowBytes, ClosingSourceBytes,
        PagedSourceByteAdapter, PagedStreamIdentity, ReadCounts, candidate_span_workspace_bytes,
    },
};
use crate::{
    ntfs_inspect::{
        external_sort::ExternalSort,
        paged_storage::{SourceRamLease, SourceScratch},
        record_store::{RecordStorePin, SortedRecordStore},
    },
    shadow_tree::PagedExpectedTree,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, GeneralLiveRefsLayoutObservation,
    general_layout::GeneralSourceShadowBinding,
    shadow_native::private_tree::{PayloadRoute, SourceBackedRoutes},
    tree_resources::SourceResourceAdmission,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

const CHUNK: usize = crate::ntfs_inspect::SESSION_READ_BYTES;
const PURPOSE: [u8; 8] = *b"N2RROUT1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagedPayloadRoute {
    object_index: usize,
    stream_name_utf16: Vec<u16>,
    logical_offset: u64,
    target_physical_offset: u64,
    length: u64,
    stream_length: u64,
    components: Vec<String>,
    expected_sha256: Option<String>,
    native_file_id: Vec<u8>,
    expected_link_count: u32,
}
impl PagedPayloadRoute {
    pub fn object_index(&self) -> usize {
        self.object_index
    }
    pub fn stream_name_utf16(&self) -> &[u16] {
        &self.stream_name_utf16
    }
    pub fn logical_offset(&self) -> u64 {
        self.logical_offset
    }
    pub fn target_physical_offset(&self) -> u64 {
        self.target_physical_offset
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn stream_length(&self) -> u64 {
        self.stream_length
    }
    pub fn components(&self) -> &[String] {
        &self.components
    }
    pub fn expected_sha256(&self) -> Option<&str> {
        self.expected_sha256.as_deref()
    }
    pub fn native_file_id(&self) -> &[u8] {
        &self.native_file_id
    }
    pub fn expected_link_count(&self) -> u32 {
        self.expected_link_count
    }
}
impl From<PayloadRoute> for PagedPayloadRoute {
    fn from(route: PayloadRoute) -> Self {
        Self {
            object_index: route.object_index,
            stream_name_utf16: route.stream_name_utf16,
            logical_offset: route.logical_offset,
            target_physical_offset: route.target_physical_offset,
            length: route.length,
            stream_length: route.stream_length,
            components: route.components,
            expected_sha256: route.expected_sha256,
            native_file_id: route.native_file_id,
            expected_link_count: route.expected_link_count,
        }
    }
}

/// A single decoded route, with prepayment retained until all of its owned
/// paths/names have dropped. Its serialization is exactly the stored row.
#[derive(Serialize)]
#[serde(transparent)]
pub struct LeasedPagedPayloadRoute {
    route: PagedPayloadRoute,
    #[serde(skip)]
    _memory: SourceRamLease,
}
impl std::ops::Deref for LeasedPagedPayloadRoute {
    type Target = PagedPayloadRoute;
    fn deref(&self) -> &Self::Target {
        &self.route
    }
}
fn decode_route(
    store: &SortedRecordStore,
    scratch: &SourceScratch,
    ordinal: u64,
) -> Result<LeasedPagedPayloadRoute> {
    let bytes = store
        .record_bytes(ordinal)?
        .checked_mul(32)
        .and_then(|n| n.checked_add(65536 + 4096))
        .context("decoded route RAM overflow")?;
    // The directory supplies the exact JSON length without decoding a row.
    // Pay its string/Vec capacities and current serializer/parser window
    // before serde allocates; the paged reader caches have separate owners.
    let memory = scratch.lease_ram(bytes)?;
    let route = store.get(ordinal)?;
    Ok(LeasedPagedPayloadRoute {
        route,
        _memory: memory,
    })
}
fn route_key(offset: u64, ordinal: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&offset.to_be_bytes());
    key[8..].copy_from_slice(&ordinal.to_be_bytes());
    key
}

/// Fully closed disk-sorted routing facts plus the actual protected native
/// origin. There is deliberately no constructor accepting a serialized pin.
pub struct PagedPayloadRoutes<'observation> {
    origin: &'observation GeneralLiveRefsLayoutObservation,
    store: SortedRecordStore,
    admission: SourceResourceAdmission,
    expected_sha256: String,
    payload_bytes: u64,
    scratch: SourceScratch,
}
impl<'observation> PagedPayloadRoutes<'observation> {
    pub fn capture(
        observation: &'observation GeneralLiveRefsLayoutObservation,
        expected: &PagedExpectedTree,
        bytes: &mut PagedSourceByteAdapter<'_>,
        output: &Path,
        capture_group: &crate::artifact_arena::ArtifactGroupPermit,
    ) -> Result<Self> {
        let admission = expected
            .header()
            .resource_admission
            .context("resource expected owner required for routes")?;
        expected.require_resource_owner(admission)?;
        bytes.require_admission(admission)?;
        ensure!(
            bytes.source_binding() == &observation.report().pair().source,
            "protected route source differs from actual frozen source"
        );
        ensure!(
            observation.report().native().resource_profile
                == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                    Some(admission)
                )),
            "protected layout resource profile differs from actual expected owner"
        );
        let source_scratch = bytes.metadata_scratch();
        let source_group = source_scratch
            .artifact_group()
            .context("resource routes require the actual source arena")?;
        expected.require_shared_memory(source_group.arena())?;
        ensure!(
            capture_group.group() == crate::artifact_arena::ArtifactGroup::Capture
                && source_group.arena().same_arena(capture_group.arena()),
            "route capture must share the actual source arena"
        );
        let scratch =
            SourceScratch::new_auxiliary_in_arena(source_scratch.budget(), capture_group.clone())?;
        let memory = crate::general_composite_target::paged_memory::ArenaReportMemory(
            capture_group.arena().clone(),
        );
        let input = PagedInputs(expected);
        let validated = SourceBackedRoutes::validate_protected_layout_domain_with_memory(
            observation,
            &input,
            |a, b| crate::ntfs_attestation::same_security(a, b).map_err(io::Error::other),
            &memory,
        )?;
        let ram = scratch.lease_ram(
            admission
                .budget
                .max_row_bytes
                .checked_mul(8)
                .context("route row RAM overflow")?,
        )?;
        // A count is a batch-size hint only; fragmented streams can emit any
        // number of extra routes and spill through the ordinary merge path.
        let mut sort =
            ExternalSort::with_record_hint(output, PURPOSE, &scratch, admission.data_streams)?;
        let mut emitted = 0u64;
        let payload_bytes = validated.visit(|route| {
            let key = route_key(route.target_physical_offset, emitted);
            sort.push(key, &PagedPayloadRoute::from(route))
                .map_err(io::Error::other)?;
            emitted = emitted
                .checked_add(1)
                .ok_or_else(|| io::Error::other("route count overflow"))?;
            Ok(())
        })?;
        drop(ram);
        let pin = sort.finish()?;
        let store = SortedRecordStore::open(&pin, &scratch)?;
        ensure!(store.len() == emitted, "complete route count differs");
        let mut end = 0u64;
        let mut total = 0u64;
        for ordinal in 0..store.len() {
            let route = decode_route(&store, &scratch, ordinal)?;
            let object = expected.object_leased(route.object_index)?;
            let stream = object
                .stream(&route.stream_name_utf16)
                .context("route stream absent from complete expected owner")?;
            let next = route
                .target_physical_offset
                .checked_add(route.length)
                .context("route target overflow")?;
            ensure!(
                !object.directory
                    && route.components == object.path
                    && route.stream_length == stream.length
                    && route.expected_sha256.as_deref() == stream.sha256
                    && usize::try_from(route.expected_link_count).ok()
                        == object.additional_names.len().checked_add(1)
                    && route.native_file_id.len() == 16
                    && route.length > 0
                    && route.target_physical_offset.is_multiple_of(4096)
                    && route.length.is_multiple_of(4096)
                    && route.logical_offset.is_multiple_of(4096)
                    && route
                        .logical_offset
                        .checked_add(route.length)
                        .is_some_and(|n| n <= stream.length / 4096 * 4096)
                    && route.target_physical_offset >= end
                    && next <= observation.report().pair().shadow.identity.partition_bytes
                    && store.key(ordinal)?[..8] == route.target_physical_offset.to_be_bytes(),
                "complete route identity, alignment, prefix, overlap or partition bounds differ"
            );
            end = next;
            total = total
                .checked_add(route.length)
                .context("route payload total overflow")?;
        }
        ensure!(
            total == payload_bytes,
            "complete route payload accounting differs"
        );
        let value = Self {
            origin: observation,
            store,
            admission,
            expected_sha256: expected.semantic_sha256().to_owned(),
            payload_bytes,
            scratch,
        };
        value.revalidate(expected)?;
        bytes.validate_protection()?;
        Ok(value)
    }
    pub fn route(&self, ordinal: u64) -> Result<LeasedPagedPayloadRoute> {
        decode_route(&self.store, &self.scratch, ordinal)
    }
    pub fn pin(&self) -> &RecordStorePin {
        self.store.pin()
    }
    /// Retire only this process's completed routing artifacts after all readers
    /// close. The shared scratch/arena checks file identity and full SHA before
    /// deletion and releases storage credit only after deletion is observed.
    pub(crate) fn retire(self) -> Result<()> {
        self.store.revalidate()?;
        let pin = self.store.pin().clone();
        let scratch = self.scratch.clone();
        drop(self);
        scratch.retire_created(&pin.data)?;
        scratch.retire_created(&pin.directory)?;
        Ok(())
    }
    pub fn len(&self) -> u64 {
        self.store.len()
    }
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
    pub fn pair(&self) -> &GeneralSourceShadowBinding {
        self.origin.report().pair()
    }
    pub(crate) fn matches_native_report(
        &self,
        report: &std::sync::Arc<n2r_win32::shadow_native::Report>,
    ) -> bool {
        std::sync::Arc::ptr_eq(&self.origin.report().native_observation(), report)
    }
    pub fn revalidate(&self, expected: &PagedExpectedTree) -> Result<()> {
        expected.require_resource_owner(self.admission)?;
        ensure!(
            expected.semantic_sha256() == self.expected_sha256
                && self.origin.before() == self.origin.after()
                && self.origin.after().disk_attributes == 3
                && self.origin.observed_readonly().disk_attributes == 2,
            "protected routing owner or complete expected identity changed"
        );
        self.store.revalidate()
    }
    fn locate(&self, position: u64) -> Result<(Option<LeasedPagedPayloadRoute>, u64)> {
        let (mut low, mut high) = (0u64, self.store.len());
        while low < high {
            let middle = low + (high - low) / 2;
            let key = self.store.key(middle)?;
            let start = u64::from_be_bytes(key[..8].try_into()?);
            if start <= position {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low > 0 {
            let previous = self.route(low - 1)?;
            let end = previous
                .target_physical_offset
                .checked_add(previous.length)
                .context("held route overflow")?;
            if position < end {
                return Ok((Some(previous), end));
            }
        }
        let boundary = if low < self.store.len() {
            let key = self.store.key(low)?;
            u64::from_be_bytes(key[..8].try_into()?)
        } else {
            self.pair().shadow.identity.partition_bytes
        };
        Ok((None, boundary))
    }
}

/// Immutable bytes and actual same-owner logical-read spans from one capture
/// chunk. It cannot be constructed from persisted maps or caller assertions.
pub(crate) struct PagedCandidateChunk<'buffer> {
    chunk: CandidateChunk<'buffer>,
    original_owner: usize,
    physical_offset: u64,
    // Chunk bytes and spans may outlive the candidate. Release the prepaid
    // receipt workspace only after the owned span Vec has been dropped.
    _ram: SourceRamLease,
}
impl PagedCandidateChunk<'_> {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.chunk.bytes()
    }
}

pub struct PagedSourceBackedCandidate<'source, 'observation> {
    bytes: PagedSourceByteAdapter<'source>,
    expected: &'source PagedExpectedTree,
    shadow: &'source mut GeneralFrozenPartition,
    routes: PagedPayloadRoutes<'observation>,
    shadow_before: n2r_win32::GeneralDiskState,
    position: u64,
    length: u64,
    source_reads_before: u64,
    counts: ReadCounts,
    object: Option<(usize, crate::shadow_tree::pages::LeasedExpectedObject)>,
    closing_shadow: Option<&'source mut dyn ClosingShadowBytes>,
    closing_source: Option<&'source mut dyn ClosingSourceBytes>,
    poisoned: bool,
    _ram: SourceRamLease,
}
impl<'source, 'observation> PagedSourceBackedCandidate<'source, 'observation> {
    pub fn new(
        mut bytes: PagedSourceByteAdapter<'source>,
        shadow: &'source mut GeneralFrozenPartition,
        expected: &'source PagedExpectedTree,
        routes: PagedPayloadRoutes<'observation>,
    ) -> Result<Self> {
        // Each native state query returns at most 64 KiB of layout plus small
        // fixed device/geometry buffers and event copies. One MiB pays the
        // retained shadow state together with an overlapping before/after query.
        // Routes, expected objects and the NTFS DATA session own their own
        // separately prepaid leases; no source-row-sized copy is made here.
        let ram = routes.scratch.lease_ram(1024 * 1024)?;
        routes.revalidate(expected)?;
        bytes.require_admission(routes.admission)?;
        ensure!(
            bytes.source_binding() == &routes.pair().source
                && shadow.binding() == &routes.pair().shadow,
            "paged candidate source/shadow association differs"
        );
        let shadow_before = shadow.state(&mut Vec::new())?;
        ensure!(
            &shadow_before == routes.origin.after() && shadow_before.disk_attributes == 3,
            "candidate requires the same post-observation frozen shadow"
        );
        let length = shadow.byte_len();
        ensure!(
            length == routes.pair().shadow.identity.partition_bytes,
            "candidate partition length differs"
        );
        let source_reads_before = bytes.logical_bytes_read();
        Ok(Self {
            bytes,
            shadow,
            expected,
            routes,
            shadow_before,
            position: 0,
            length,
            source_reads_before,
            counts: ReadCounts::default(),
            object: None,
            closing_shadow: None,
            closing_source: None,
            poisoned: false,
            _ram: ram,
        })
    }
    pub(crate) fn with_closing_bytes(
        mut self,
        observer: &'source mut dyn ClosingShadowBytes,
    ) -> Self {
        self.closing_shadow = Some(observer);
        self
    }
    pub(crate) fn with_closing_source_bytes(
        mut self,
        observer: &'source mut dyn ClosingSourceBytes,
    ) -> Self {
        self.closing_source = Some(observer);
        self
    }
    pub fn byte_len(&self) -> u64 {
        self.length
    }
    pub fn read_counts(&self) -> ReadCounts {
        self.counts
    }
    pub fn routes(&self) -> &PagedPayloadRoutes<'observation> {
        &self.routes
    }
    pub(crate) fn expected_tree_sha256(&self) -> &str {
        self.expected.semantic_sha256()
    }
    pub(crate) fn source_owner_identity(&self) -> usize {
        self.bytes.original_owner_id()
    }
    pub(crate) fn matches_native_report(
        &self,
        report: &std::sync::Arc<n2r_win32::shadow_native::Report>,
    ) -> bool {
        self.routes.matches_native_report(report)
    }

    pub(crate) fn capture_scratch(&self) -> SourceScratch {
        self.routes.scratch.clone()
    }
    pub(crate) fn capture_group(&self) -> Result<crate::artifact_arena::ArtifactGroupPermit> {
        self.routes
            .scratch
            .artifact_group()
            .context("candidate has no actual capture arena group")
    }
    pub(crate) fn raw_source(&self) -> &crate::ntfs_inspect::PagedInspection {
        self.bytes.raw_source()
    }
    pub(crate) fn allocation_cursor(
        &self,
    ) -> Result<crate::ntfs_inspect::allocation_domain::AllocationCursor<'source>> {
        self.bytes.allocation_cursor(self.length)
    }

    pub(crate) fn route_bytes_in(&self, offset: u64, length: u64) -> Result<u64> {
        let end = offset
            .checked_add(length)
            .context("route coverage overflow")?;
        ensure!(
            end <= self.length,
            "route coverage query escapes candidate partition"
        );
        let (mut cursor, mut covered) = (offset, 0u64);
        while cursor < end {
            let (route, boundary) = self.routes.locate(cursor)?;
            let stop = end.min(boundary);
            ensure!(stop > cursor, "held route coverage makes no progress");
            if route.is_some() {
                covered = covered
                    .checked_add(stop - cursor)
                    .context("route byte total overflow")?;
            }
            cursor = stop;
        }
        Ok(covered)
    }

    pub(crate) fn copy_source_for(
        &mut self,
        chunk: &PagedCandidateChunk<'_>,
        offset: usize,
        length: usize,
    ) -> Result<Option<u64>> {
        ensure!(
            !self.poisoned
                && chunk.original_owner == self.bytes.original_owner_id()
                && offset
                    .checked_add(length)
                    .is_some_and(|end| end <= chunk.bytes().len()),
            "COPY query differs from actual candidate chunk"
        );
        if let Some(source) = chunk.chunk.copy_source(offset, length) {
            return Ok(Some(source));
        }
        let at = chunk
            .physical_offset
            .checked_add(offset as u64)
            .context("COPY destination overflow")?;
        let (route, end) = self.routes.locate(at)?;
        let Some(route) = route else { return Ok(None) };
        if at.checked_add(length as u64).is_none_or(|stop| stop > end) {
            return Ok(None);
        }
        let object = self.expected.object_leased(route.object_index)?;
        let stream = object
            .stream(&route.stream_name_utf16)
            .context("COPY expected stream absent")?;
        let identity = PagedStreamIdentity {
            record_number: object.record_number,
            sequence_number: object.sequence_number,
            name_utf16: stream.name_utf16,
            length: stream.length,
            sha256: stream.sha256,
            allow_sparse: stream.sparse.is_some(),
        };
        self.bytes.source_physical_for(
            &identity,
            route.logical_offset + at - route.target_physical_offset,
            length as u64,
        )
    }

    fn read_observed(
        &mut self,
        output: &mut [u8],
        direct: bool,
    ) -> Result<(usize, Option<crate::ntfs_inspect::DirectReadReceipt>)> {
        ensure!(!self.poisoned, "poisoned paged candidate cannot read");
        if output.is_empty() || self.position == self.length {
            return Ok((0, None));
        }
        let (route, boundary) = self.routes.locate(self.position)?;
        ensure!(
            boundary > self.position && boundary <= self.length,
            "candidate routing boundary differs"
        );
        let count = (boundary - self.position)
            .min(output.len() as u64)
            .min(CHUNK as u64) as usize;
        let receipt = if let Some(route) = route {
            if self
                .object
                .as_ref()
                .is_none_or(|(index, _)| *index != route.object_index)
            {
                self.object = Some((
                    route.object_index,
                    self.expected.object_leased(route.object_index)?,
                ));
            }
            let object = &self
                .object
                .as_ref()
                .context("candidate expected object absent")?
                .1;
            let stream = object
                .stream(&route.stream_name_utf16)
                .context("candidate expected stream absent")?;
            ensure!(
                object.path == route.components
                    && stream.length == route.stream_length
                    && stream.sha256 == route.expected_sha256.as_deref(),
                "held route differs from expected object"
            );
            let identity = PagedStreamIdentity {
                record_number: object.record_number,
                sequence_number: object.sequence_number,
                name_utf16: stream.name_utf16,
                length: stream.length,
                sha256: stream.sha256,
                allow_sparse: stream.sparse.is_some(),
            };
            let logical = route
                .logical_offset
                .checked_add(self.position - route.target_physical_offset)
                .context("candidate logical offset overflow")?;
            let receipt = if direct {
                Some(self.bytes.read_with_direct_receipts(
                    &identity,
                    logical,
                    &mut output[..count],
                )?)
            } else {
                self.bytes
                    .read_into(&identity, logical, &mut output[..count])?;
                None
            };
            self.counts.source_logical_bytes = self
                .counts
                .source_logical_bytes
                .checked_add(count as u64)
                .context("candidate source byte count overflow")?;
            receipt
        } else {
            let reused = if let Some(observer) = &mut self.closing_shadow {
                observer.read_shadow_exact(self.shadow, self.position, &mut output[..count])?
            } else {
                self.shadow.seek(SeekFrom::Start(self.position))?;
                self.shadow.read_exact(&mut output[..count])?;
                0
            };
            ensure!(
                reused <= count as u64,
                "closing shadow reuse exceeds actual supplied bytes"
            );
            self.counts.shadow_bytes = self
                .counts
                .shadow_bytes
                .checked_add(count as u64 - reused)
                .context("candidate shadow count overflow")?;
            self.counts.shadow_bytes_reused_from_closing = self
                .counts
                .shadow_bytes_reused_from_closing
                .checked_add(reused)
                .context("candidate closing byte count overflow")?;
            None
        };
        self.position += count as u64;
        Ok((count, receipt))
    }

    pub(crate) fn read_capture_chunk<'buffer>(
        &mut self,
        offset: u64,
        output: &'buffer mut [u8],
        direct: bool,
    ) -> Result<PagedCandidateChunk<'buffer>> {
        ensure!(
            !self.poisoned && output.len() <= CHUNK,
            "candidate chunk exceeds bounded actual read window"
        );
        // The returned chunk owns its span Vec independently of `self`.
        // Its lease also covers the transient direct receipt and Vec growth
        // before any spans are allocated.
        let ram = self.routes.scratch.lease_ram(if direct {
            candidate_span_workspace_bytes()?
        } else {
            0
        })?;
        let result: Result<CandidateReadSpans> = (|| {
            self.seek(SeekFrom::Start(offset))?;
            let mut done = 0;
            let mut spans = CandidateReadSpans::new();
            while done < output.len() {
                let (count, receipt) = self.read_observed(&mut output[done..], direct)?;
                ensure!(
                    count != 0,
                    "candidate capture chunk ended before requested bytes"
                );
                if let Some(receipt) = receipt {
                    spans.append(done, count, &receipt);
                }
                done += count;
            }
            Ok(spans)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        let spans = result?;
        Ok(PagedCandidateChunk {
            chunk: CandidateChunk::from_actual_reads(output, spans),
            original_owner: self.bytes.original_owner_id(),
            physical_offset: offset,
            _ram: ram,
        })
    }
    /// Reuse only this candidate's original owner's actual direct-read spans.
    /// A false answer requires the ordinary raw equality fallback by capture.
    pub(crate) fn reuse_copy_read(
        &mut self,
        chunk: &PagedCandidateChunk<'_>,
        offset: usize,
        source: u64,
        length: usize,
    ) -> Result<bool> {
        ensure!(!self.poisoned, "poisoned candidate cannot reuse reads");
        if chunk.original_owner != self.bytes.original_owner_id()
            || !chunk.chunk.covers_copy(offset, source, length)
        {
            return Ok(false);
        }
        self.counts.source_reference_bytes_reused = self
            .counts
            .source_reference_bytes_reused
            .checked_add(length as u64)
            .context("candidate reused-reference count overflow")?;
        Ok(true)
    }
    /// The closing collector receives only the actual immutable original read
    /// buffer and this same frozen owner, before any caller can recycle it.
    pub(crate) fn read_original_exact(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        ensure!(
            !self.poisoned
                && output.len() <= CHUNK
                && offset
                    .checked_add(output.len() as u64)
                    .is_some_and(|end| end <= self.length),
            "original capture read escapes protected partition/window"
        );
        self.poisoned = true;
        let source = self.bytes.original_owner();
        source.seek(SeekFrom::Start(offset))?;
        source.read_exact(output)?;
        if let Some(observer) = &mut self.closing_source {
            observer.observe_original(source, offset, output)?;
        }
        self.poisoned = false;
        Ok(())
    }
    pub(crate) fn read_reference_exact(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        ensure!(
            !self.poisoned
                && output.len() <= CHUNK
                && offset
                    .checked_add(output.len() as u64)
                    .is_some_and(|end| end <= self.length),
            "COPY equality read escapes protected partition/window"
        );
        self.poisoned = true;
        let source = self.bytes.original_owner();
        source.seek(SeekFrom::Start(offset))?;
        source.read_exact(output)?;
        self.counts.source_reference_bytes = self
            .counts
            .source_reference_bytes
            .checked_add(output.len() as u64)
            .context("candidate reference count overflow")?;
        self.poisoned = false;
        Ok(())
    }
    pub fn finish(mut self) -> Result<ReadCounts> {
        ensure!(!self.poisoned, "failed paged candidate cannot finish");
        self.routes.revalidate(self.expected)?;
        ensure!(
            self.shadow.state(&mut Vec::new())? == self.shadow_before,
            "shadow identity/exclusion changed around candidate reads"
        );
        ensure!(
            self.bytes
                .logical_bytes_read()
                .checked_sub(self.source_reads_before)
                == Some(self.counts.source_logical_bytes),
            "candidate actual logical-read accounting differs"
        );
        self.bytes.finish()?;
        // These route files were used only while composing the captured
        // bytes. Release them through their actual closed owners now, rather
        // than dropping their last owners while stale arena entries remain.
        // Retirement independently verifies identity/hash and must complete
        // before this capture can be reported as finished.
        self.routes.retire()?;
        Ok(self.counts)
    }
}
impl Read for PagedSourceBackedCandidate<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self.read_observed(output, false) {
            Ok((count, _)) => Ok(count),
            Err(error) => {
                self.poisoned = true;
                Err(io::Error::other(error))
            }
        }
    }
}
impl Seek for PagedSourceBackedCandidate<'_, '_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if self.poisoned {
            return Err(io::Error::other("poisoned paged candidate cannot seek"));
        }
        let next = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "paged candidate seek escapes partition",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}
