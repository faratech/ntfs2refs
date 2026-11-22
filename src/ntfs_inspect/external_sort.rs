//! Resource-accounted spill/merge ordering for complete source facts.
//! Keys are unique over the complete output, including across spill runs.
use super::{
    paged_storage::{SourceRamLease, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    io::{self, Write},
    mem::size_of,
    path::{Path, PathBuf},
};

struct Row {
    key: [u8; 16],
    json: Vec<u8>,
}
struct Run {
    pin: RecordStorePin,
    _ram: SourceRamLease,
}
struct Level {
    runs: Vec<Run>,
    _ram: SourceRamLease,
}

/// The number of levels is bounded by the u64 record-count domain, rather
/// than by a filesystem-specific count. A consumed run is retired only by the
/// storage owner's authenticated creation/identity/hash/deletion protocol.
pub struct ExternalSort {
    base: PathBuf,
    purpose: [u8; 8],
    scratch: SourceScratch,
    batch: Vec<Row>,
    batch_payload: u64,
    batch_capacity: usize,
    batch_payload_limit: u64,
    /// What the batch may take in all: where it spills.
    batch_target: u64,
    /// What the batch holds now, leased as it grows (`admit`): the rows'
    /// vector at its capacity and every row's JSON. A sort of few rows
    /// holds a lease of their size, not of the batch it was allowed.
    batch_ram: Vec<SourceRamLease>,
    batch_leased: u64,
    /// What writing the batch out leases (the page windows of a run's two
    /// files); the batch grows only where that would still have room.
    spill_room: u64,
    levels: [Option<Level>; 64],
    fan_in: usize,
    next_run: u64,
    records: u64,
    poisoned: bool,
}

/// The rows' vector starts with room for this many rows and doubles.
const FIRST_ROWS: usize = 64;
/// A batch at least doubles its lease with every step but its last, so its
/// steps are bounded by the u64 byte domain.
const LEASE_STEPS: usize = 66;

struct Count(u64);
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("source sort row length overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Exact<'a> {
    bytes: &'a mut Vec<u8>,
    remaining: u64,
}
impl Write for Exact<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() as u64 > self.remaining {
            return Err(io::Error::other(
                "source sort serialization exceeded counted row",
            ));
        }
        self.bytes.extend_from_slice(input);
        self.remaining -= input.len() as u64;
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ExternalSort {
    pub fn new(base: &Path, purpose: [u8; 8], scratch: &SourceScratch) -> Result<Self> {
        let budget = scratch.budget();
        budget.validate()?;
        Self::with_batch_target(base, purpose, scratch, budget.ram_bytes / 8, None)
    }

    /// Size the in-memory batch from an actual domain count when available.
    /// The count is ONLY a performance hint: extra records and unusually
    /// large rows still spill through the exact same checked merge path.
    pub fn with_record_hint(
        base: &Path,
        purpose: [u8; 8],
        scratch: &SourceScratch,
        record_hint: u64,
    ) -> Result<Self> {
        let budget = scratch.budget();
        budget.validate()?;
        let estimate = record_hint.saturating_mul(4096);
        let target = estimate
            .max(u64::from(budget.page_bytes))
            .min(budget.ram_bytes / 8);
        Self::with_batch_target(base, purpose, scratch, target, Some(record_hint))
    }

    /// Concurrent projection sorters share the admitted batch allowance: three
    /// of them run at once, so each may take a thirty-second of the budget.
    /// (A five-hundred-twelfth made a 26,000-object projection spill and
    /// merge two runs at a time, each run a hashed and reopened page file.)
    /// Complete oversized rows still use the existing singleton spill path.
    pub(crate) fn with_shared_projection_hint(
        base: &Path,
        purpose: [u8; 8],
        scratch: &SourceScratch,
        record_hint: u64,
    ) -> Result<Self> {
        let budget = scratch.budget();
        budget.validate()?;
        let target = record_hint
            .saturating_mul(4096)
            .max(u64::from(budget.page_bytes))
            .min(budget.ram_bytes / 32)
            .max(size_of::<Row>() as u64 + 129);
        let mut sort = Self::with_batch_target(base, purpose, scratch, target, Some(record_hint))?;
        // Each sorter computed its fan-in as if it owned the whole budget.
        sort.fan_in = sort.fan_in.clamp(2, 8);
        Ok(sort)
    }

    fn with_batch_target(
        base: &Path,
        purpose: [u8; 8],
        scratch: &SourceScratch,
        bytes: u64,
        record_hint: Option<u64>,
    ) -> Result<Self> {
        let budget = scratch.budget();
        let calculated = (bytes / (size_of::<Row>() as u64 + 128)).max(1);
        let capacity =
            usize::try_from(record_hint.map_or(calculated, |hint| calculated.min(hint.max(1))))?;
        let overhead = (capacity as u64)
            .checked_mul(size_of::<Row>() as u64)
            .context("source sort batch accounting overflow")?;
        ensure!(
            overhead < bytes,
            "source sort batch metadata exceeds RAM budget"
        );
        // The batch starts with a page of memory and takes more as rows
        // arrive, up to `bytes`. (Leased whole here, the sorts made with
        // `new` each held an eighth of the budget whatever they sorted:
        // 1,122 MiB at this place on a volume of 143,000 objects.)
        let first = bytes.min(u64::from(budget.page_bytes));
        let mut batch_ram = Vec::new();
        batch_ram.try_reserve_exact(LEASE_STEPS)?;
        batch_ram.push(scratch.lease_ram(first)?);
        // Six page windows per two-range reader, plus one record per head.
        // Use at least a two-way merge; the aggregate ledger still admits
        // actual readers/heads before allocating any of their bytes.
        let head = u64::from(budget.page_bytes)
            .checked_mul(6)
            .and_then(|n| n.checked_add(budget.record_bytes))
            .context("source sort merge RAM overflow")?;
        let available = budget
            .ram_bytes
            .saturating_sub(bytes)
            .saturating_sub(u64::from(budget.page_bytes) * 6);
        let fan_in =
            usize::try_from(u64::from(budget.merge_fan_in).min((available / head).max(2)))?;
        // A run is written through two page files of three page windows
        // each; twice that is left free. (Merges lease as they go, as they
        // always have: a merge of the whole fan-in is most of the budget,
        // and holding the batch back for one would keep it at its first
        // page.)
        let spill_room = u64::from(budget.page_bytes)
            .checked_mul(12)
            .context("source sort spill RAM overflow")?;
        Ok(Self {
            base: base.to_owned(),
            purpose,
            scratch: scratch.clone(),
            batch: Vec::new(),
            batch_payload: 0,
            batch_capacity: capacity,
            batch_payload_limit: bytes - overhead,
            batch_target: bytes,
            batch_ram,
            batch_leased: first,
            spill_room,
            levels: std::array::from_fn(|_| None),
            fan_in,
            next_run: 0,
            records: 0,
            poisoned: false,
        })
    }

    /// Lease what the batch holds once it has one more row of `payload`
    /// bytes, and make room for that row in the rows' vector, before either
    /// is allocated. False: there is no room for it beside what the run
    /// holds, and the batch is as it was (it is then written out).
    ///
    /// Caches are given up for the batch as they were when it was leased
    /// whole; but growing is for speed, so where there is still no room
    /// beside what writing a run takes, the batch is written out instead.
    /// Only a row that an empty batch has no lease for is memory the sort
    /// cannot do without (`required`).
    fn admit(&mut self, payload: u64, required: bool) -> Result<bool> {
        let row = size_of::<Row>() as u64;
        let held = self.batch.capacity();
        let rows = if self.batch.len() == held {
            held.saturating_mul(2)
                .max(FIRST_ROWS)
                .min(self.batch_capacity)
        } else {
            held
        };
        ensure!(
            rows > self.batch.len(),
            "source sort batch has no row left to admit"
        );
        let needed = (rows as u64)
            .checked_mul(row)
            .and_then(|n| n.checked_add(self.batch_payload))
            .and_then(|n| n.checked_add(payload))
            .context("source sort batch accounting overflow")?;
        // Rows within the capacity and payload within its limit: never
        // more than the batch was allowed.
        ensure!(
            needed <= self.batch_target,
            "source sort batch exceeds its admitted RAM"
        );
        if needed > self.batch_leased {
            // At least what is needed; twice what is held where that is
            // more, so that a batch takes its memory in a few steps.
            let step = (needed - self.batch_leased)
                .max(self.batch_leased)
                .min(self.batch_target - self.batch_leased);
            let lease = match self.scratch.lease_ram_beside(step, self.spill_room) {
                Ok(lease) => lease,
                Err(_) if !required => return Ok(false),
                Err(_) => self.scratch.lease_ram(step)?,
            };
            ensure!(
                self.batch_ram.len() < self.batch_ram.capacity(),
                "source sort batch lease steps exceed the u64 byte domain"
            );
            self.batch_ram.push(lease);
            self.batch_leased += step;
        }
        if rows > held {
            // The rows are moved to a larger vector: until that is done
            // both exist.
            let moving = (held as u64) * row;
            let _moving = if moving == 0 {
                None
            } else {
                match self.scratch.lease_ram_beside(moving, self.spill_room) {
                    Ok(lease) => Some(lease),
                    Err(_) if !required => return Ok(false),
                    Err(_) => Some(self.scratch.lease_ram(moving)?),
                }
            };
            self.batch.try_reserve_exact(rows - self.batch.len())?;
            ensure!(
                self.batch.capacity() == rows,
                "source sort batch capacity differs from its RAM lease"
            );
        }
        Ok(true)
    }

    pub fn push(&mut self, key: [u8; 16], value: &impl Serialize) -> Result<()> {
        ensure!(!self.poisoned, "source sort is poisoned");
        self.poisoned = true;
        let limit = self.scratch.budget().record_bytes;
        let mut json = Vec::new();
        serde_json::to_writer(
            &mut Exact {
                bytes: &mut json,
                remaining: limit,
            },
            value,
        )?;
        json.shrink_to_fit();
        let len = json.len() as u64;
        ensure!(
            len > 0 && len <= limit,
            "source sort row exceeds admitted working record bytes"
        );
        if self.batch.len() == self.batch_capacity
            || self
                .batch_payload
                .checked_add(len)
                .is_none_or(|n| n > self.batch_payload_limit)
        {
            self.spill()?;
        }
        let singleton = len > self.batch_payload_limit;
        if !singleton && !self.admit(len, self.batch.is_empty())? {
            // No room to grow: what the batch holds goes to a run, and the
            // row starts the next batch in the memory already leased.
            self.spill()?;
            ensure!(
                self.admit(len, true)?,
                "source sort row was refused the RAM its empty batch needs"
            );
        }
        let singleton_ram = if singleton {
            Some(self.scratch.lease_ram(len)?)
        } else {
            None
        };
        self.records = self
            .records
            .checked_add(1)
            .context("source sort record count overflow")?;
        if singleton {
            let path = self.next_path()?;
            let mut writer = SortedRecordWriter::new(&path, self.purpose, &self.scratch)?;
            writer.push_trusted_json(key, &json)?;
            let pin = writer.finish()?;
            drop(json);
            drop(singleton_ram);
            let run = self.retain(pin)?;
            self.add_run(0, run)?;
        } else {
            self.batch_payload = self
                .batch_payload
                .checked_add(len)
                .context("sort RAM overflow")?;
            self.batch.push(Row { key, json });
        }
        self.poisoned = false;
        Ok(())
    }

    fn next_path(&mut self) -> Result<PathBuf> {
        let ordinal = self.next_run;
        self.next_run = self
            .next_run
            .checked_add(1)
            .context("source sort run count overflow")?;
        let mut path = self.base.as_os_str().to_os_string();
        path.push(format!(".run-{ordinal:020}"));
        Ok(PathBuf::from(path))
    }
    fn retain(&self, pin: RecordStorePin) -> Result<Run> {
        let bytes = (size_of::<Run>() as u64)
            .checked_add(
                ((pin.data.path.as_os_str().len() + pin.directory.path.as_os_str().len()) as u64)
                    * 4,
            )
            .and_then(|n| n.checked_add(2048))
            .context("sort run metadata overflow")?;
        Ok(Run {
            pin,
            _ram: self.scratch.lease_ram(bytes)?,
        })
    }
    fn spill(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        self.batch.sort_unstable_by_key(|row| row.key);
        ensure!(
            self.batch.windows(2).all(|p| p[0].key < p[1].key),
            "duplicate complete source fact key in spill run"
        );
        let path = self.next_path()?;
        let mut writer = SortedRecordWriter::new(&path, self.purpose, &self.scratch)?;
        for row in &self.batch {
            writer.push_trusted_json(row.key, &row.json)?;
        }
        let pin = writer.finish()?;
        self.batch.clear();
        self.batch_payload = 0;
        let run = self.retain(pin)?;
        self.add_run(0, run)
    }
    fn add_run(&mut self, level: usize, run: Run) -> Result<()> {
        ensure!(
            level < self.levels.len(),
            "source sort exceeds u64 merge-depth domain"
        );
        if self.levels[level].is_none() {
            let bytes = (self.fan_in as u64)
                .checked_mul(size_of::<Run>() as u64)
                .context("source sort level RAM overflow")?;
            let ram = self.scratch.lease_ram(bytes)?;
            let mut runs = Vec::new();
            runs.try_reserve_exact(self.fan_in)?;
            ensure!(
                runs.capacity() == self.fan_in,
                "source sort level allocation changed"
            );
            self.levels[level] = Some(Level { runs, _ram: ram });
        }
        let owner = self.levels[level].as_mut().context("sort level missing")?;
        owner.runs.push(run);
        if owner.runs.len() == self.fan_in {
            let full = self.levels[level]
                .take()
                .context("sort full level missing")?;
            let merged = self.merge(&full.runs)?;
            drop(full);
            self.add_run(level + 1, merged)?;
        }
        Ok(())
    }
    fn merge(&mut self, runs: &[Run]) -> Result<Run> {
        ensure!(
            !runs.is_empty() && runs.len() <= self.fan_in,
            "sort merge fan-in differs"
        );
        struct Head {
            store: SortedRecordStore,
            ordinal: u64,
            key: Option<[u8; 16]>,
            json: Vec<u8>,
            ram: Option<SourceRamLease>,
        }
        let _heads_ram = self
            .scratch
            .lease_ram((runs.len() * size_of::<Head>()) as u64)?;
        let mut heads = Vec::new();
        heads.try_reserve_exact(runs.len())?;
        for run in runs {
            let store = SortedRecordStore::open(&run.pin, &self.scratch)?;
            heads.push(Head {
                store,
                ordinal: 0,
                key: None,
                json: Vec::new(),
                ram: None,
            });
        }
        fn advance(head: &mut Head, scratch: &SourceScratch) -> Result<()> {
            head.json = Vec::new();
            head.ram = None;
            if head.ordinal == head.store.len() {
                head.key = None;
                return Ok(());
            }
            let bytes = head.store.record_bytes(head.ordinal)?;
            let ram = scratch.lease_ram(bytes)?;
            let json = head.store.get_json(head.ordinal)?;
            ensure!(
                json.capacity() as u64 <= bytes,
                "source merge row capacity changed"
            );
            head.key = Some(head.store.key(head.ordinal)?);
            head.json = json;
            head.ram = Some(ram);
            head.ordinal += 1;
            Ok(())
        }
        for head in &mut heads {
            advance(head, &self.scratch)?;
        }
        let path = self.next_path()?;
        let mut writer = SortedRecordWriter::new(&path, self.purpose, &self.scratch)?;
        while let Some(index) = heads
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.key.map(|k| (i, k)))
            .min_by_key(|(_, key)| *key)
            .map(|(i, _)| i)
        {
            let head = &mut heads[index];
            writer.push_json(head.key.context("merge head absent")?, &head.json)?;
            advance(head, &self.scratch)?;
        }
        for head in &heads {
            head.store.revalidate()?;
        }
        let pin = writer.finish()?;
        drop(heads);
        for run in runs {
            self.scratch.retire_created(&run.pin.data)?;
            self.scratch.retire_created(&run.pin.directory)?;
        }
        self.retain(pin)
    }
    pub fn finish(mut self) -> Result<RecordStorePin> {
        ensure!(!self.poisoned, "cannot finish poisoned source sort");
        self.poisoned = true;
        self.spill()?;
        let mut output: Option<Run> = None;
        for level in 0..self.levels.len() {
            if let Some(owner) = self.levels[level].take() {
                for run in owner.runs {
                    output = Some(match output.take() {
                        None => run,
                        Some(prior) => self.merge(&[prior, run])?,
                    });
                }
            }
        }
        let pin = if let Some(run) = output {
            run.pin
        } else {
            let path = self.next_path()?;
            SortedRecordWriter::new(&path, self.purpose, &self.scratch)?.finish()?
        };
        ensure!(
            pin.records == self.records,
            "source sort lost complete records"
        );
        Ok(pin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs_inspect::source_domain::SourceMetadataBudget;

    const RAM: u64 = 64 * 1024 * 1024;

    fn scratch(ram_bytes: u64) -> SourceScratch {
        SourceScratch::new(SourceMetadataBudget {
            ram_bytes,
            scratch_bytes: 256 * 1024 * 1024,
            page_bytes: 4096,
            record_bytes: 64 * 1024,
            merge_fan_in: 8,
        })
        .unwrap()
    }
    fn key(n: u64) -> [u8; 16] {
        // Not in ascending order of arrival.
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&(n.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_be_bytes());
        key[8..].copy_from_slice(&n.to_be_bytes());
        key
    }
    fn value(n: u64) -> String {
        "v".repeat(40 + (n % 97) as usize)
    }
    /// What the batch really holds: the rows' vector and every row's JSON.
    fn held(sort: &ExternalSort) -> u64 {
        (sort.batch.capacity() * size_of::<Row>()) as u64
            + sort
                .batch
                .iter()
                .map(|row| row.json.capacity() as u64)
                .sum::<u64>()
    }
    fn leased(sort: &ExternalSort) -> u64 {
        sort.batch_ram.iter().map(SourceRamLease::held_bytes).sum()
    }
    fn rows(pin: &RecordStorePin, scratch: &SourceScratch) -> Vec<([u8; 16], Vec<u8>)> {
        let store = SortedRecordStore::open(pin, scratch).unwrap();
        (0..store.len())
            .map(|n| (store.key(n).unwrap(), store.get_json(n).unwrap()))
            .collect()
    }

    #[test]
    fn the_batch_leases_what_it_holds_not_what_it_may_take() {
        let directory = tempfile::tempdir().unwrap();
        let scratch = scratch(RAM);
        let before = scratch.working_ram_bytes();
        let mut sort =
            ExternalSort::new(&directory.path().join("sort"), *b"N2RTEST1", &scratch).unwrap();
        // The whole batch (an eighth of the budget) used to be leased here.
        assert_eq!(sort.batch_target, RAM / 8);
        assert_eq!(scratch.working_ram_bytes() - before, 4096);
        const ROWS: u64 = 5_000;
        for n in 0..ROWS {
            sort.push(key(n), &value(n)).unwrap();
            // The lease is never less than the memory the batch has.
            assert!(leased(&sort) >= held(&sort), "row {n}");
            assert_eq!(leased(&sort), sort.batch_leased);
            assert!(sort.batch_leased <= sort.batch_target);
        }
        assert_eq!(sort.next_run, 0, "5,000 rows fit the batch");
        // Geometric growth: within twice what is held (and its first page).
        assert!(leased(&sort) <= 2 * held(&sort) + 4096);
        assert!(leased(&sort) < RAM / 32);
        let pin = sort.finish().unwrap();
        let rows = rows(&pin, &scratch);
        assert_eq!(rows.len() as u64, ROWS);
        assert!(rows.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }

    #[test]
    fn a_batch_with_no_room_to_grow_is_written_out_and_the_rows_are_the_same() {
        const ROWS: u64 = 1_200;
        let directory = tempfile::tempdir().unwrap();
        let roomy = scratch(RAM);
        let mut sort =
            ExternalSort::new(&directory.path().join("roomy"), *b"N2RTEST1", &roomy).unwrap();
        for n in 0..ROWS {
            sort.push(key(n), &value(n)).unwrap();
        }
        assert_eq!(sort.next_run, 0);
        let expected = rows(&sort.finish().unwrap(), &roomy);

        // The same sort beside a holder that leaves the ledger 64 KiB more
        // than writing a batch out takes: it was refused its whole batch at
        // once before, and now sorts in what there is.
        let tight = scratch(RAM);
        let mut sort =
            ExternalSort::new(&directory.path().join("tight"), *b"N2RTEST1", &tight).unwrap();
        let free = 64 * 1024;
        let holder = tight
            .lease_ram(RAM - tight.working_ram_bytes() - free - sort.spill_room)
            .unwrap();
        for n in 0..ROWS {
            sort.push(key(n), &value(n)).unwrap();
            assert!(leased(&sort) >= held(&sort), "row {n}");
            assert!(leased(&sort) <= free + 4096);
            // The writers of the runs are leased only while they write;
            // `holder` keeps the rest.
            assert!(tight.working_ram_bytes() <= RAM);
        }
        assert!(sort.next_run > 1, "the batch was written out in runs");
        drop(holder);
        assert_eq!(rows(&sort.finish().unwrap(), &tight), expected);
    }

    #[test]
    fn a_growing_batch_is_given_a_caches_memory_as_the_whole_batch_was() {
        use crate::ntfs_inspect::{
            paged_storage::PagedMetadataRange, source_domain::SourceMetadataRange,
        };
        let directory = tempfile::tempdir().unwrap();
        let scratch = scratch(RAM);
        // A store held in memory, and a holder that leaves the ledger less
        // than the rows below take.
        let bytes = vec![0x5a_u8; 600_000];
        let pin = PagedMetadataRange::capture(
            &directory.path().join("store"),
            *b"N2RTEST1",
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &scratch,
        )
        .unwrap();
        let store = PagedMetadataRange::open(&pin, &scratch).unwrap();
        assert!(store.is_held_in_memory());
        let mut sort =
            ExternalSort::new(&directory.path().join("sort"), *b"N2RTEST1", &scratch).unwrap();
        let _holder = scratch
            .lease_ram(RAM - scratch.working_ram_bytes() - 128 * 1024 - sort.spill_room)
            .unwrap();
        for n in 0..3_000 {
            sort.push(key(n), &value(n)).unwrap();
            assert!(leased(&sort) >= held(&sort), "row {n}");
        }
        // The rows (half a megabyte) stayed in the batch: the store's
        // memory went to it, and the store is read through its pages.
        assert_eq!(sort.next_run, 0);
        assert!(!store.is_held_in_memory());
        let mut byte = [0u8];
        store.read_exact_at(599_999, &mut byte).unwrap();
        assert_eq!(byte[0], 0x5a);
    }

    #[test]
    fn a_small_batch_spills_where_it_did() {
        let directory = tempfile::tempdir().unwrap();
        let scratch = scratch(RAM);
        // 16 KiB of batch: rows of about 130 bytes with their 40 of
        // bookkeeping spill every hundred rows or so.
        let mut sort = ExternalSort::with_batch_target(
            &directory.path().join("sort"),
            *b"N2RTEST1",
            &scratch,
            16 * 1024,
            None,
        )
        .unwrap();
        let capacity = (16 * 1024) / (size_of::<Row>() + 128);
        assert_eq!(sort.batch_capacity, capacity);
        assert_eq!(
            sort.batch_payload_limit,
            (16 * 1024 - capacity * size_of::<Row>()) as u64
        );
        for n in 0..2_000 {
            sort.push(key(n), &value(n)).unwrap();
            assert!(leased(&sort) >= held(&sort), "row {n}");
            assert!(sort.batch.capacity() <= capacity);
            assert!(leased(&sort) <= 16 * 1024);
        }
        assert!(sort.next_run > 10);
        let pin = sort.finish().unwrap();
        assert_eq!(pin.records, 2_000);
    }
}
