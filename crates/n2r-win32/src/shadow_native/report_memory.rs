//! Portable accounting for retained native report rows. The payer owns every
//! lease; the SDK cannot deserialize or manufacture an accounting capability.
use super::*;
use std::fmt;

pub trait ReportMemoryLease: Send + Sync {
    /// Downward only. Query workspace remains charged until collection closes.
    fn shrink_to(&mut self, bytes: u64) -> io::Result<()>;
}
pub trait ReportMemoryAccountant: Send + Sync {
    /// Must reserve the complete request before returning a live lease.
    fn reserve(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>>;
    /// Actual adapter allocation, excluding the Box pointer stored by the SDK.
    fn lease_heap_bytes(&self) -> u64;
}
pub(super) struct LayoutRetained {
    _lease: Box<dyn ReportMemoryLease>,
}
impl fmt::Debug for LayoutRetained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetainedLayoutExpectationMemory")
    }
}
impl LayoutRetained {
    pub(super) fn new(
        payer: &dyn ReportMemoryAccountant,
        objects: usize,
        pair: &GeneralSourceShadowBinding,
    ) -> io::Result<Self> {
        let bytes = domain_memory::expected_vector_bytes(objects, pair)?
            .checked_add(payer.lease_heap_bytes())
            .ok_or_else(|| invalid("layout expectation lease RAM overflow"))?;
        Ok(Self {
            _lease: payer.reserve(bytes)?,
        })
    }
}
pub(super) struct Retained {
    rows: Vec<Box<dyn ReportMemoryLease>>,
    root: Option<Box<dyn ReportMemoryLease>>,
    root_bytes: u64,
    bitmap: Option<Box<dyn ReportMemoryLease>>,
    vector_other_bytes: u64,
    object_capacity: Option<usize>,
    prelude: Box<dyn ReportMemoryLease>,
    _vectors: Box<dyn ReportMemoryLease>,
}
impl fmt::Debug for Retained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedNativeReportMemory")
            .field("rows", &self.rows.len())
            .finish_non_exhaustive()
    }
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("native report RAM overflow"))
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("native report RAM overflow"))
}
fn vec_bytes<T>(v: &Vec<T>) -> io::Result<u64> {
    mul(v.capacity() as u64, mem::size_of::<T>() as u64)
}
fn strings(v: &Vec<String>) -> io::Result<u64> {
    v.iter()
        .try_fold(vec_bytes(v)?, |n, s| add(n, s.capacity() as u64))
}
fn option_string(v: &Option<String>) -> u64 {
    v.as_ref().map_or(0, |s| s.capacity() as u64)
}
fn snapshot_bytes(s: &Snapshot) -> io::Result<u64> {
    let mut n = add(vec_bytes(&s.queries)?, vec_bytes(&s.security)?)?;
    for q in &s.queries {
        n = add(n, vec_bytes(&q.bytes)?)?;
    }
    if let Some(q) = &s.kernel_security {
        n = add(n, vec_bytes(&q.bytes)?)?;
    }
    if let Some(ea) = &s.extended_attributes {
        n = add(n, vec_bytes(&ea.entries)?)?;
        for e in &ea.entries {
            n = add(n, add(vec_bytes(&e.name)?, vec_bytes(&e.value)?)?)?;
        }
    }
    n = add(n, option_string(&s.extended_attributes_error))?;
    if let Some(r) = &s.reparse {
        if let Some(p) = &r.point {
            n = add(n, vec_bytes(&p.buffer)?)?;
        }
        n = add(n, option_string(&r.error))?;
    }
    if let Some(q) = &s.directory_case_sensitivity {
        n = add(n, vec_bytes(&q.bytes)?)?;
    }
    Ok(n)
}
fn ioctl_bytes(q: &crate::attestation::IoctlQuery) -> io::Result<u64> {
    add(vec_bytes(&q.input)?, vec_bytes(&q.bytes)?)
}
fn sparse_bytes(s: &sparse_stream::Observation) -> io::Result<u64> {
    let mut n = add(
        vec_bytes(&s.expected.allocated)?,
        vec_bytes(&s.actual_allocated)?,
    )?;
    n = add(
        n,
        add(
            vec_bytes(&s.cached_regions)?,
            vec_bytes(&s.storage_regions)?,
        )?,
    )?;
    for q in s.cached_regions.iter().chain(&s.storage_regions) {
        n = add(n, ioctl_bytes(q)?)?;
    }
    Ok(n)
}
fn retrieval_proof(p: &crate::retrieval_paging::Proof) -> io::Result<u64> {
    let mut n = add(
        add(
            p.encoding.capacity() as u64,
            p.canonical_sha256.capacity() as u64,
        )?,
        vec_bytes(&p.pages)?,
    )?;
    for page in &p.pages {
        n = add(
            n,
            add(
                vec_bytes(&page.input)?,
                page.response_sha256.capacity() as u64,
            )?,
        )?;
    }
    Ok(n)
}
fn bitmap_proof(p: &crate::bitmap_paging::Proof) -> io::Result<u64> {
    let mut n = add(
        add(
            p.encoding.capacity() as u64,
            p.canonical_bitmap_sha256.capacity() as u64,
        )?,
        vec_bytes(&p.pages)?,
    )?;
    for page in &p.pages {
        n = add(
            n,
            add(
                vec_bytes(&page.input)?,
                page.response_sha256.capacity() as u64,
            )?,
        )?;
    }
    if let Some(s) = &p.streaming {
        n = add(
            n,
            add(
                s.bitmap_data_sha256.capacity() as u64,
                s.page_transcript_sha256.capacity() as u64,
            )?,
        )?;
    }
    Ok(n)
}
/// Release spare query storage after validation, retaining every returned byte
/// and namespace/stream entry. The original row query lease remains alive
/// during reallocations; retain() measures the capacities actually left.
pub(super) fn compact_row(row: &mut ObjectReport) {
    fn snapshot(snapshot: &mut Snapshot) {
        for query in &mut snapshot.queries {
            query.bytes.shrink_to_fit();
        }
        snapshot.queries.shrink_to_fit();
        snapshot.security.shrink_to_fit();
        if let Some(kernel) = &mut snapshot.kernel_security {
            kernel.bytes.shrink_to_fit();
        }
    }
    fn sparse(sparse: &mut sparse_stream::Observation) {
        for query in sparse
            .cached_regions
            .iter_mut()
            .chain(&mut sparse.storage_regions)
        {
            query.input.shrink_to_fit();
            query.bytes.shrink_to_fit();
        }
        sparse.cached_regions.shrink_to_fit();
        sparse.storage_regions.shrink_to_fit();
        sparse.actual_allocated.shrink_to_fit();
    }
    snapshot(&mut row.before);
    snapshot(&mut row.after);
    for bytes in [
        &mut row.retrieval,
        &mut row.cached_validity,
        &mut row.storage_validity,
        &mut row.integrity,
        &mut row.streams,
    ] {
        bytes.shrink_to_fit();
    }
    for pages in [&mut row.cached_validity_pages,&mut row.storage_validity_pages].into_iter().flatten(){pages.compact();}
    for stream in &mut row.named_streams {
        snapshot(&mut stream.before);
        snapshot(&mut stream.after);
        for bytes in [
            &mut stream.retrieval,
            &mut stream.cached_validity,
            &mut stream.storage_validity,
            &mut stream.integrity,
        ] {
            bytes.shrink_to_fit();
        }
        for pages in [&mut stream.cached_validity_pages,&mut stream.storage_validity_pages].into_iter().flatten(){pages.compact();}
        if let Some(layout) = &mut stream.sparse {
            sparse(layout);
        }
    }
    if let Some(layout) = &mut row.sparse {
        sparse(layout);
    }
    row.named_streams.shrink_to_fit();
    row.namespace.shrink_to_fit();
}
pub(super) fn row_bytes(r: &ObjectReport) -> io::Result<u64> {
    let mut n = strings(&r.components)?;
    n = add(
        n,
        add(snapshot_bytes(&r.before)?, snapshot_bytes(&r.after)?)?,
    )?;
    n = add(n, option_string(&r.logical_sha256))?;
    for b in [
        &r.retrieval,
        &r.cached_validity,
        &r.storage_validity,
        &r.integrity,
        &r.streams,
    ] {
        n = add(n, vec_bytes(b)?)?;
    }
    if let Some(p) = &r.retrieval_page_proof {
        n = add(n, retrieval_proof(p)?)?;
    }
    for pages in [&r.cached_validity_pages,&r.storage_validity_pages].into_iter().flatten(){n=add(n,pages.retained_bytes()?)?;}
    n = add(n, vec_bytes(&r.namespace)?)?;
    for entry in &r.namespace {
        n = add(n, vec_bytes(&entry.name_utf16)?)?;
    }
    n = add(n, vec_bytes(&r.named_streams)?)?;
    for s in &r.named_streams {
        n = add(n, vec_bytes(&s.name_utf16)?)?;
        n = add(
            n,
            add(
                option_string(&s.expected_sha256),
                option_string(&s.logical_sha256),
            )?,
        )?;
        n = add(
            n,
            add(snapshot_bytes(&s.before)?, snapshot_bytes(&s.after)?)?,
        )?;
        for b in [
            &s.retrieval,
            &s.cached_validity,
            &s.storage_validity,
            &s.integrity,
        ] {
            n = add(n, vec_bytes(b)?)?;
        }
        if let Some(p) = &s.retrieval_page_proof {
            n = add(n, retrieval_proof(p)?)?;
        }
        for pages in [&s.cached_validity_pages,&s.storage_validity_pages].into_iter().flatten(){n=add(n,pages.retained_bytes()?)?;}
        if let Some(s) = &s.sparse {
            n = add(n, sparse_bytes(s)?)?;
        }
    }
    n = add(n, vec_bytes(&r.additional_names)?)?;
    for alias in &r.additional_names {
        n = add(
            n,
            add(
                strings(&alias.components)?,
                add(
                    snapshot_bytes(&alias.before)?,
                    snapshot_bytes(&alias.after)?,
                )?,
            )?,
        )?;
    }
    if let Some(s) = &r.sparse {
        n = add(n, sparse_bytes(s)?)?;
    }
    if let Some(c) = &r.source_candidate {
        n = add(
            n,
            add(
                c.legacy.bitmap_sha256.capacity() as u64,
                c.metadata_inclusive.bitmap_sha256.capacity() as u64,
            )?,
        )?;
        n = add(
            n,
            add(
                bitmap_proof(&c.legacy_page_proof)?,
                bitmap_proof(&c.metadata_page_proof)?,
            )?,
        )?;
    }
    Ok(n)
}
fn snapshot_peak(maximum: u64) -> io::Result<u64> {
    add(
        mul(
            maximum.max(crate::attestation::MAX_SECURITY_BYTES as u64),
            8,
        )?,
        1024 * 1024,
    )
}
/// One root capture plus its full before/after clone. API/kernel descriptors
/// need at most four simultaneous maximum-size byte buffers here; eight pay
/// allocator/clone slack. The additional eight MiB cover fixed EA/reparse and
/// metadata query buffers. The descriptor acceptance limit is unchanged.
pub(super) fn root_peak(maximum: u64) -> io::Result<u64> {
    add(snapshot_peak(maximum)?, 7 * 1024 * 1024)
}
/// Resource range limits permit at most row/(2*sizeof(ClusterRange)) runs.
/// Four rows cover Vec growth/reallocation, retained first-page ranges or
/// summary, and the AllocationMap duplicate. Native response/overlap/first
/// page windows are bounded independently of volume size by sixteen MiB.
pub(super) fn bitmap_peak(row: u64) -> io::Result<u64> {
    add(mul(row, 4)?, 16 * 1024 * 1024)
}
fn root_bytes(root: &RootSecurity) -> io::Result<u64> {
    if root.backup.is_some() {
        return Err(invalid("accounted readonly root cannot own a restoration"));
    }
    add(snapshot_bytes(&root.before)?, snapshot_bytes(&root.after)?)
}
fn sparse_peak(s: Option<&crate::sparse_layout::SparseLayout>) -> io::Result<u64> {
    s.map_or(Ok(0), |s| {
        add(
            mul(s.allocated.len() as u64, 2 * (16 + 24 * 1024 + 256))?,
            mul(s.allocated.capacity() as u64, 128)?,
        )
    })
}
/// One currently collected row only, not object_count multiplied by a row
/// maximum. Covers the existing bounded raw retrieval/namespace APIs and
/// their simultaneous decode buffers; all arithmetic is checked before I/O.
pub(super) fn row_peak(i: &Input<'_>, maximum: u64) -> io::Result<u64> {
    let retrieval = mul(crate::retrieval_paging::MAX_RETURNED_BYTES as u64, 16)?;
    let stream = add(
        add(mul(snapshot_peak(maximum)?, 2)?, retrieval)?,
        4 * 1024 * 1024,
    )?;
    let mut n = add(stream, mul(namespace_layout::MAX_EVIDENCE as u64, 12)?)?;
    let path_bytes = i.components.iter().try_fold(
        mul(i.components.len() as u64, mem::size_of::<String>() as u64)?,
        |n, s| add(n, s.len() as u64),
    )?;
    n = add(n, mul(path_bytes, 4)?)?;
    n = add(n, sparse_peak(i.sparse)?)?;
    for named in &i.named_streams {
        n = add(n, add(stream, sparse_peak(named.sparse)?)?)?;
    }
    for alias in i.additional_names {
        n = add(
            n,
            add(mul(snapshot_peak(maximum)?, 2)?, mul(strings(alias)?, 4)?)?,
        )?;
    }
    Ok(n)
}
impl Retained {
    pub(super) fn new(
        accountant: &dyn ReportMemoryAccountant,
        objects: usize,
        _maximum: u64,
    ) -> io::Result<Self> {
        // Reserve pointer slots and their actual adapter payloads before either
        // the outer ObjectReport Vec or this lease Vec is allocated.
        let slots = add(
            mul(
                objects as u64,
                (mem::size_of::<ObjectReport>() + mem::size_of::<Option<String>>() + 64) as u64,
            )?,
            mul(
                add(objects as u64, 1)?,
                mem::size_of::<Box<dyn ReportMemoryLease>>() as u64,
            )?,
        )?;
        let adapters = mul(add(objects as u64, 5)?, accountant.lease_heap_bytes())?;
        let vector_bytes = add(mul(slots, 2)?, adapters)?;
        let object_bytes = mul(
            mul(objects as u64, 2)?,
            mem::size_of::<ObjectReport>() as u64,
        )?;
        let vector_other_bytes = vector_bytes
            .checked_sub(object_bytes)
            .ok_or_else(|| invalid("native vector allowance underflow"))?;
        let vectors = accountant.reserve(vector_bytes)?;
        // Static volume/bitmap/event workspace. The root query/clone is paid
        // immediately before capture, then retained at its actual capacities.
        let prelude = accountant.reserve(32 * 1024 * 1024)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(
            objects
                .checked_add(1)
                .ok_or_else(|| invalid("native lease count overflow"))?,
        )
        .map_err(io::Error::other)?;
        Ok(Self {
            _vectors: vectors,
            prelude,
            rows,
            root: None,
            root_bytes: 0,
            bitmap: None,
            vector_other_bytes,
            object_capacity: None,
        })
    }
    pub(super) fn observe_object_capacity(&mut self, capacity: usize) -> io::Result<()> {
        if self.object_capacity.is_some() {
            return Err(invalid("native object vector capacity was already bound"));
        }
        let bytes = add(
            self.vector_other_bytes,
            mul(capacity as u64, mem::size_of::<ObjectReport>() as u64)?,
        )?;
        // Downward-only shrink refuses any actual allocation larger than the
        // original prepaid object-slot bound. Every unrelated allowance stays.
        self._vectors.shrink_to(bytes)?;
        self.object_capacity = Some(capacity);
        Ok(())
    }
    pub(super) fn retain_bitmap_workspace(
        &mut self,
        lease: Box<dyn ReportMemoryLease>,
    ) -> io::Result<()> {
        if self.bitmap.is_some() {
            return Err(invalid("native bitmap memory was already prepaid"));
        }
        self.bitmap = Some(lease);
        Ok(())
    }
    pub(super) fn bitmap_captured(
        &mut self,
        map: Option<&crate::bitmap_layout::AllocationMap>,
        proof: Option<&crate::bitmap_paging::Proof>,
    ) -> io::Result<()> {
        if map.is_none() || proof.is_none() {
            return Err(invalid("accounted bitmap lost its actual map/proof"));
        }
        let bytes = bitmap_parts_bytes(map, proof)?;
        self.bitmap
            .as_mut()
            .ok_or_else(|| invalid("bitmap query lease absent"))?
            .shrink_to(bytes)
    }
    pub(super) fn retain_root(
        &mut self,
        mut lease: Box<dyn ReportMemoryLease>,
        root: &RootSecurity,
    ) -> io::Result<()> {
        if self.root.is_some() {
            return Err(invalid("native root memory was already retained"));
        }
        let bytes = root_bytes(root)?;
        lease.shrink_to(bytes)?;
        self.root_bytes = bytes;
        self.root = Some(lease);
        Ok(())
    }
    pub(super) fn retain(
        &mut self,
        mut lease: Box<dyn ReportMemoryLease>,
        row: &ObjectReport,
        maximum: u64,
    ) -> io::Result<()> {
        let actual = row_bytes(row)?;
        if actual > maximum {
            return Err(invalid(
                "native retained row exceeded its prepaid query/decode reservation",
            ));
        }
        lease.shrink_to(actual)?;
        if self.rows.len() == self.rows.capacity() {
            return Err(invalid("native row lease slots exceeded prepaid capacity"));
        }
        self.rows.push(lease);
        Ok(())
    }
    pub(super) fn finish(&mut self, report: &Report) -> io::Result<()> {
        if self.object_capacity != Some(report.objects.capacity()) {
            return Err(invalid("native object vector grew after capacity binding"));
        }
        if self.root.is_none() || root_bytes(&report.root_security)? != self.root_bytes {
            return Err(invalid("native retained root ownership changed"));
        }
        let bitmap = report_bitmap_bytes(report)?;
        let prelude = report_prelude_bytes(report)?;
        if let Some(lease) = &mut self.bitmap {
            // The caller has dropped both native bitmap observations before
            // finish; only this exact map/proof remains in the returned report.
            lease.shrink_to(bitmap)?;
            self.prelude.shrink_to(prelude)?;
        } else {
            self.prelude.shrink_to(add(prelude, bitmap)?)?;
        }
        Ok(())
    }
    pub(super) fn retain_residual(
        &mut self,
        lease: &mut Option<Box<dyn ReportMemoryLease>>,
        actual: u64,
    ) -> io::Result<()> {
        if self.rows.len() == self.rows.capacity() {
            return Err(invalid(
                "native residual lease slots exceeded prepaid capacity",
            ));
        }
        lease
            .as_mut()
            .ok_or_else(|| invalid("native residual lease absent"))?
            .shrink_to(actual)?;
        // Slots and shrink are checked while the caller still owns its earlier
        // lease. No fallible operation follows taking it into this live owner.
        self.rows
            .push(lease.take().expect("validated residual lease"));
        Ok(())
    }
}
/// Total retained report payload for existing residual-owner callers. Root
/// bytes remain included here; only Retained's independently paid prelude
/// uses the narrower helper below.
pub(super) fn report_bytes(report: &Report) -> io::Result<u64> {
    add(
        add(
            snapshot_bytes(&report.root_security.before)?,
            snapshot_bytes(&report.root_security.after)?,
        )?,
        add(report_prelude_bytes(report)?, report_bitmap_bytes(report)?)?,
    )
}
fn report_bitmap_bytes(report: &Report) -> io::Result<u64> {
    bitmap_parts_bytes(
        report.metadata_allocation.as_ref(),
        report.metadata_allocation_page_proof.as_ref(),
    )
}
fn bitmap_parts_bytes(
    map: Option<&crate::bitmap_layout::AllocationMap>,
    proof: Option<&crate::bitmap_paging::Proof>,
) -> io::Result<u64> {
    let mut n = 0;
    if let Some(map) = map {
        n = add(
            n,
            add(map.bitmap_sha256.capacity() as u64, vec_bytes(&map.ranges)?)?,
        )?;
    }
    if let Some(proof) = proof {
        n = add(n, bitmap_proof(proof)?)?;
    }
    Ok(n)
}
fn report_prelude_bytes(report: &Report) -> io::Result<u64> {
    // Root and accounted bitmap owners have independent retained leases.
    let mut n = 0;
    for s in [&report.before, &report.after] {
        for b in [&s.device, &s.length, &s.alignment, &s.layout] {
            n = add(n, vec_bytes(b)?)?;
        }
        n = add(n, binding_bytes(&s.binding)?)?;
    }
    n = add(n, binding_bytes(&report.binding)?)?;
    n = add(n, vec_bytes(&report.events)?)?;
    for e in &report.events {
        n = add(
            n,
            add(
                e.operation.capacity() as u64,
                add(vec_bytes(&e.input)?, vec_bytes(&e.output)?)?,
            )?,
        )?;
    }
    n = add(n, vec_bytes(&report.privilege_states)?)?;
    for p in &report.privilege_states {
        n = add(n, p.name.capacity() as u64)?;
    }
    Ok(n)
}
fn binding_bytes(b: &DiskBinding) -> io::Result<u64> {
    add(
        b.volume_guid.capacity() as u64,
        add(
            b.identity.disk_guid.capacity() as u64,
            b.identity.partition_guid.capacity() as u64,
        )?,
    )
}

pub(super) fn residual_peak(maximum: u64, page: u32) -> io::Result<u64> {
    add(residual_query_peak(maximum)?, residual_writer_peak(page)?)
}
pub(super) fn residual_query_peak(maximum: u64) -> io::Result<u64> {
    mul(snapshot_peak(maximum)?, 2)
}
pub(super) fn residual_writer_peak(page: u32) -> io::Result<u64> {
    add(mul(u64::from(page), 8)?, 16 * 1024 * 1024)
}
pub(super) fn residual_retained_peak(page: u32, extra_report: u64) -> io::Result<u64> {
    // Retain the returned result reader/cache and bounded header/current row
    // as well as the native report's newly appended events/privilege records.
    add(add(mul(u64::from(page), 3)?, 256 * 1024)?, extra_report)
}
