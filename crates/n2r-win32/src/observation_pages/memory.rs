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
    // The row the window was sized for; a longer one pays for the rest.
    window_row: u64,
}

/// The row the collection's window is sized for. A row is one object as
/// Windows shows it (its security, streams, mappings, names), and nearly
/// every one is a few kilobytes; the largest the budget admits is a
/// sixty-fourth of the run's memory. The window used to be thirty-two of
/// those: half of the ledger, held for the whole observation of the source,
/// whatever the volume held (4.6 GB of the 4.9 GB that a volume of 100,000
/// small files could not do without on a machine with 16 GB). A row longer
/// than this pays for what it is longer by while it is written and while it
/// is read back ([`Memory::beyond_window`]).
pub(crate) const WINDOW_ROW_BYTES: u64 = 1024 * 1024;
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
pub(super) fn header_bytes(h: &Report) -> io::Result<u64> {
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
        let window_row = budget.max_row_bytes.min(WINDOW_ROW_BYTES);
        // One current collection/decode window, not rows multiplied by its
        // maximum: thirty-two rows of the size the window is made for. The
        // before/after bitmap and header owners remain in this window, and
        // what they can hold follows the row limit: four rows, as the walks
        // reserve for their bitmap views.
        let working = add(
            add(
                add(mul(window_row, 32)?, mul(budget.max_row_bytes, 4)?)?,
                mul(u64::from(budget.pages.max_page_bytes), 12)?,
            )?,
            64 * 1024 * 1024,
        )?;
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
            window_row,
        })
    }
    /// The workspace of a row of `row_bytes` beyond what the window holds for
    /// it, `factor` times what it is longer by: nothing for a row the window
    /// was made for.
    pub(crate) fn beyond_window(
        accountant: &dyn ReportMemoryAccountant,
        window_row: u64,
        row_bytes: u64,
        factor: u64,
    ) -> io::Result<Option<Box<dyn ReportMemoryLease>>> {
        match row_bytes.checked_sub(window_row) {
            Some(more) if more > 0 => accountant.reserve(mul(more, factor)?).map(Some),
            _ => Ok(None),
        }
    }
    pub(crate) fn window_row(&self) -> u64 {
        self.window_row
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
        let kept = header_bytes(header)?;
        if self.header.shrink_to(kept).is_err() {
            // The header holds more than the window was: a reservation of
            // what it holds takes the window's place.
            self.header = self.accountant.reserve(kept)?;
        }
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
            // The window holds the rows it was made for while they are read
            // back; longer ones pay for the rest, at the factor below.
            return Self::beyond_window(&*self.accountant, self.window_row, row_bytes, 16);
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
#[cfg(test)]
mod window_tests {
    use super::*;
    use crate::shadow_native::report_memory::test_payer::Counted;

    const MIB: u64 = 1024 * 1024;

    fn budget(max_row_bytes: u64, max_page_bytes: u32) -> NativeObservationBudget {
        NativeObservationBudget {
            pages: PageBudget {
                max_page_bytes,
                max_records_per_page: 1024,
                max_records: 1 << 30,
                max_pages: 1 << 30,
                max_file_bytes: 1 << 40,
            },
            max_row_bytes,
            max_total_row_bytes: 1 << 40,
            max_index_bytes: 1 << 30,
        }
    }

    #[test]
    fn the_window_is_made_for_rows_of_a_megabyte_whatever_the_budget_admits() {
        let held_for = |max_row_bytes: u64| {
            let payer = Arc::new(Counted::with_limit(u64::MAX));
            let memory = Memory::new(
                payer.clone(),
                budget(max_row_bytes, 4 * 1024 * 1024),
                1000,
                Path::new("native.pages"),
            )
            .unwrap();
            (payer.held(), memory)
        };
        // A machine with 16 GB free admits rows of 141 MiB, one with 64 GB
        // rows of 600 MiB.
        let (small, _small) = held_for(141 * MIB);
        let (large, _large) = held_for(600 * MIB);
        // Thirty-two rows of a megabyte, four of the largest for the bitmap
        // and header owners, twelve pages and 64 MiB; the index and the
        // caches are 25 MiB besides.
        let window = |row: u64| 32 * MIB + 4 * row + 12 * 4 * MIB + 64 * MIB;
        assert!(
            (window(141 * MIB)..window(141 * MIB) + 32 * MIB).contains(&small),
            "{small}"
        );
        assert_eq!(large - small, 4 * (600 - 141) * MIB);
        // It was thirty-two of the largest row: 4.5 GiB there.
        assert!(small < 32 * 141 * MIB / 5, "{small}");
        // Where the largest row is shorter than a megabyte the window is
        // made for that row.
        let (least, memory) = held_for(64 * 1024);
        assert_eq!(memory.window_row(), 64 * 1024);
        assert!(least < 36 * 64 * 1024 + 12 * 4 * MIB + 64 * MIB + 32 * MIB);
    }

    #[test]
    fn a_row_longer_than_the_window_pays_for_what_it_is_longer_by() {
        let payer = Counted::with_limit(100 * MIB);
        for ordinary in [1, 4096, MIB] {
            assert!(
                Memory::beyond_window(&payer, MIB, ordinary, 16)
                    .unwrap()
                    .is_none()
            );
        }
        let lease = Memory::beyond_window(&payer, MIB, 3 * MIB, 16)
            .unwrap()
            .unwrap();
        assert_eq!(payer.held(), 32 * MIB);
        drop(lease);
        assert_eq!(payer.held(), 0);
        // With no room for it the row is refused, never read unpaid.
        let refused = Memory::beyond_window(&payer, MIB, 9 * MIB, 16)
            .err()
            .unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(payer.held(), 0);
    }

    #[test]
    fn rows_read_back_while_the_window_is_held_pay_only_beyond_it() {
        let payer = Arc::new(Counted::with_limit(u64::MAX));
        let budget = budget(8 * MIB, 4 * 1024 * 1024);
        let memory = Memory::new(payer.clone(), budget, 10, Path::new("native.pages")).unwrap();
        let window = payer.held();
        assert!(memory.decode(budget, 2000).unwrap().is_none());
        assert_eq!(payer.held(), window);
        let long = memory.decode(budget, 5 * MIB).unwrap().unwrap();
        assert_eq!(payer.held(), window + 16 * 4 * MIB);
        drop(long);
        // More than two of the largest row is not a row of this collection.
        assert!(memory.decode(budget, 16 * MIB + 1).is_err());
    }

    #[test]
    fn a_long_row_is_paid_for_while_it_is_written_and_no_longer() {
        let directory = tempfile::tempdir().unwrap();
        let budget = budget(64 * 1024, 4096);
        let mut writer =
            Writer::new(&directory.path().join("rows.pages"), PURPOSE, budget.pages).unwrap();
        let payer = Counted::with_limit(MIB);
        let mut row = |ordinal: u64, bytes: usize, payer: &Counted| -> io::Result<u64> {
            let mut sink = ChunkSink {
                writer: &mut writer,
                budget,
                phase: 0,
                ordinal,
                chunk: 0,
                bytes: 0,
                buffer: Vec::new(),
                payer: Some(payer),
                paid: 1024,
                beyond: Vec::new(),
            };
            for piece in vec![b'x'; bytes].chunks(700) {
                sink.write_all(piece)?;
            }
            sink.emit()?;
            Ok(payer.held())
        };
        // A row the window was made for is written without a reservation.
        assert_eq!(row(0, 1024, &payer).unwrap(), 0);
        assert_eq!(payer.peak(), 0);
        // A longer one pays thirty-two times what it is longer by, in steps
        // that double: here to 8,192 bytes for a row of 5,000.
        assert_eq!(row(1, 5000, &payer).unwrap(), 32 * (8192 - 1024));
        assert_eq!(payer.held(), 0);
        // The longest row the budget admits pays no more than that row.
        let longest = Counted::with_limit(u64::MAX);
        assert_eq!(
            row(2, 64 * 1024, &longest).unwrap(),
            32 * (64 * 1024 - 1024)
        );
        // Without room for it the row is not written, and the refusal names
        // the row.
        let none = Counted::with_limit(1000);
        let refused = row(3, 5000, &none).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::OutOfMemory);
        let text = refused.to_string();
        assert!(
            text.contains("row 3 of the observation of the source through Windows"),
            "{text}"
        );
        assert_eq!(none.held(), 0);
    }
}
