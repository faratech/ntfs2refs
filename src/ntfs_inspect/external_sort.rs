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
    _batch_ram: SourceRamLease,
    levels: [Option<Level>; 64],
    fan_in: usize,
    next_run: u64,
    records: u64,
    poisoned: bool,
}

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
        let ram = scratch.lease_ram(bytes)?;
        let mut batch = Vec::new();
        batch.try_reserve_exact(capacity)?;
        let overhead = (batch.capacity() as u64)
            .checked_mul(size_of::<Row>() as u64)
            .context("source sort batch accounting overflow")?;
        ensure!(
            overhead < bytes,
            "source sort batch metadata exceeds RAM budget"
        );
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
        Ok(Self {
            base: base.to_owned(),
            purpose,
            scratch: scratch.clone(),
            batch,
            batch_payload: 0,
            batch_capacity: capacity,
            batch_payload_limit: bytes - overhead,
            _batch_ram: ram,
            levels: std::array::from_fn(|_| None),
            fan_in,
            next_run: 0,
            records: 0,
            poisoned: false,
        })
    }

    pub fn push(&mut self, key: [u8; 16], value: &impl Serialize) -> Result<()> {
        ensure!(!self.poisoned, "source sort is poisoned");
        self.poisoned = true;
        let mut count = Count(0);
        serde_json::to_writer(&mut count, value)?;
        ensure!(
            count.0 > 0 && count.0 <= self.scratch.budget().record_bytes,
            "source sort row exceeds admitted working record bytes"
        );
        if self.batch.len() == self.batch_capacity
            || self
                .batch_payload
                .checked_add(count.0)
                .is_none_or(|n| n > self.batch_payload_limit)
        {
            self.spill()?;
        }
        let singleton = count.0 > self.batch_payload_limit;
        let singleton_ram = if singleton {
            Some(self.scratch.lease_ram(count.0)?)
        } else {
            None
        };
        let mut json = Vec::new();
        json.try_reserve_exact(usize::try_from(count.0)?)?;
        ensure!(
            json.capacity() as u64 <= count.0,
            "source sort row capacity exceeds RAM lease"
        );
        serde_json::to_writer(
            &mut Exact {
                bytes: &mut json,
                remaining: count.0,
            },
            value,
        )?;
        ensure!(
            json.len() as u64 == count.0 && json.capacity() as u64 <= count.0,
            "source sort serialization/capacity changed between bounded passes"
        );
        self.records = self
            .records
            .checked_add(1)
            .context("source sort record count overflow")?;
        if singleton {
            let path = self.next_path()?;
            let mut writer = SortedRecordWriter::new(&path, self.purpose, &self.scratch)?;
            writer.push_json(key, &json)?;
            let pin = writer.finish()?;
            drop(json);
            drop(singleton_ram);
            let run = self.retain(pin)?;
            self.add_run(0, run)?;
        } else {
            self.batch_payload = self
                .batch_payload
                .checked_add(count.0)
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
            writer.push_json(row.key, &row.json)?;
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
