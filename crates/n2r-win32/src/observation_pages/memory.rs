//! Prepaid portable memory ownership for paged NTFS observations.
use super::*;
use crate::shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease};
use std::{mem, sync::Arc};

pub(crate) struct Memory {
    pub accountant: Arc<dyn ReportMemoryAccountant>,
    pub header: Box<dyn ReportMemoryLease>,
    pub index: Box<dyn ReportMemoryLease>,
    pub _caches: Box<dyn ReportMemoryLease>,
    pub expected_rows: usize,
    pub index_reserved: u64,
    construction: bool,
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| io::Error::other("native shared memory overflow"))
}
fn vec_bytes<T>(v: &Vec<T>) -> io::Result<u64> {
    mul(v.capacity() as u64, mem::size_of::<T>() as u64)
}
fn ioctl(q: &IoctlQuery) -> io::Result<u64> {
    add(vec_bytes(&q.input)?, vec_bytes(&q.bytes)?)
}
fn summary(s: &crate::bitmap_streaming::Summary) -> io::Result<u64> {
    let n = add(
        add(
            s.encoding.capacity() as u64,
            s.bitmap_data_sha256.capacity() as u64,
        )?,
        add(
            s.canonical_bitmap_sha256.capacity() as u64,
            s.page_transcript_sha256.capacity() as u64,
        )?,
    )?;
    add(n, vec_bytes(&s.allocated_ranges)?)
}
fn header_bytes(h: &Report) -> io::Result<u64> {
    require(
        h.files.is_empty()
            && h.logical_data.as_ref().is_some_and(|d| d.files.is_empty())
            && h.namespace.as_ref().is_some_and(|d| d.files.is_empty()),
        "accounted native header contains object rows",
    )?;
    let r = &h.request;
    let mut n = add(
        add(
            r.source_inspection_sha256.capacity() as u64,
            r.volume.capacity() as u64,
        )?,
        add(vec_bytes(&r.files)?, vec_bytes(&r.extent_identity_streams)?)?,
    )?;
    for s in &r.extent_identity_streams {
        n = add(n, add(vec_bytes(&s.name_utf16)?, vec_bytes(&s.extents)?)?)?;
    }
    for b in [
        &h.volume_extents_before,
        &h.volume_extents_after,
        &h.ntfs_data_before,
        &h.ntfs_data_after,
        &h.disk_attributes_before,
        &h.disk_attributes_after,
    ] {
        n = add(n, vec_bytes(b)?)?;
    }
    n = add(n, vec_bytes(&h.privilege_states)?)?;
    for p in &h.privilege_states {
        n = add(n, p.name.capacity() as u64)?;
    }
    if let Some(a) = &h.allocation {
        for q in [
            &a.base_before,
            &a.base_after,
            &a.bitmap_before,
            &a.bitmap_after,
        ] {
            n = add(n, ioctl(q)?)?;
        }
        for v in [&a.bitmap_before_continuation, &a.bitmap_after_continuation] {
            n = add(n, vec_bytes(v)?)?;
            for q in v {
                n = add(n, ioctl(q)?)?;
            }
        }
        for s in [&a.streamed_before, &a.streamed_after]
            .into_iter()
            .flatten()
        {
            n = add(n, summary(s)?)?;
        }
    }
    if let Some(d) = &h.logical_data {
        n = add(n, vec_bytes(&d.files)?)?;
    }
    if let Some(ns) = &h.namespace {
        n = add(n, vec_bytes(&ns.files)?)?;
    }
    Ok(n)
}
impl Memory {
    pub(crate) fn new(
        accountant: Arc<dyn ReportMemoryAccountant>,
        budget: NativeObservationBudget,
        rows: usize,
        path: &Path,
    ) -> io::Result<Self> {
        budget.validate()?;
        let working = add(
            add(
                mul(budget.max_row_bytes, 32)?,
                mul(u64::from(budget.pages.max_page_bytes), 12)?,
            )?,
            64 * 1024 * 1024,
        )?;
        // One current collection/decode window, not rows multiplied by its
        // maximum. Before/after bitmap/header owners remain in this window.
        let header = accountant.reserve(working)?;
        let index_reserved = add(
            mul(rows as u64, 4 * mem::size_of::<RowIndex>() as u64)?,
            256,
        )?;
        let index = accountant.reserve(index_reserved)?;
        let caches = add(
            add(
                mul(u64::from(budget.pages.max_page_bytes), 6)?,
                65536 + 16384,
            )?,
            mul(path.as_os_str().as_encoded_bytes().len() as u64, 16)?,
        )?;
        let caches = add(caches, mul(accountant.lease_heap_bytes(), 4)?)?;
        let caches = accountant.reserve(caches)?;
        Ok(Self {
            accountant,
            header,
            index,
            _caches: caches,
            expected_rows: rows,
            index_reserved,
            construction: true,
        })
    }
    pub(super) fn close(
        &mut self,
        header: &Report,
        files: &Vec<RowIndex>,
        namespace: &Vec<RowIndex>,
    ) -> io::Result<()> {
        require(
            files.len() == self.expected_rows && namespace.len() == self.expected_rows,
            "accounted native complete row count changed",
        )?;
        let index = add(vec_bytes(files)?, vec_bytes(namespace)?)?;
        require(
            index <= self.index_reserved,
            "native index capacity exceeded prepaid reservation",
        )?;
        self.index.shrink_to(index)?;
        self.header.shrink_to(header_bytes(header)?)?;
        self.construction = false;
        Ok(())
    }
    pub(super) fn decode(
        &self,
        budget: NativeObservationBudget,
        row_bytes: u64,
    ) -> io::Result<Option<Box<dyn ReportMemoryLease>>> {
        require(
            row_bytes > 0
                && row_bytes
                    <= budget
                        .max_row_bytes
                        .checked_mul(2)
                        .ok_or_else(|| io::Error::other("native decode row bound overflow"))?,
            "native decode rows exceed their authenticated limits",
        )?;
        if self.construction {
            return Ok(None);
        }
        self.accountant
            .reserve(add(
                add(
                    // RowIndex.bytes was authenticated while opening the
                    // complete report. Pay the actual simultaneously decoded
                    // JSON rows, retaining the conservative expansion factor.
                    mul(row_bytes, 16)?,
                    mul(u64::from(budget.pages.max_page_bytes), 6)?,
                )?,
                65536 + 4096,
            )?)
            .map(Some)
    }
}
