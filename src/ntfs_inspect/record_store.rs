//! Sorted ordinary metadata records with a disk-resident fixed-width directory.
//! Pins describe stored facts; they never grant device or conversion authority.
use super::{
    SourceMetadataRange,
    paged_storage::{
        PagedMetadataRange, SourcePagePin, SourceRamLease, SourceRangeWriter, SourceScratch,
    },
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

const DIRECTORY_BYTES: u64 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordStorePin {
    pub schema_version: u32,
    pub purpose: [u8; 8],
    pub data: SourcePagePin,
    pub directory: SourcePagePin,
    pub records: u64,
}

pub struct SortedRecordWriter {
    data: SourceRangeWriter,
    directory: SourceRangeWriter,
    purpose: [u8; 8],
    maximum_record_bytes: u64,
    previous: Option<[u8; 16]>,
    records: u64,
    bytes: u64,
    poisoned: bool,
}

fn directory_purpose(mut purpose: [u8; 8]) -> [u8; 8] {
    purpose[0] ^= 0x80;
    purpose
}
fn sibling(base: &Path, extension: &str) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(extension);
    PathBuf::from(name)
}

impl SortedRecordWriter {
    pub fn new(base: &Path, purpose: [u8; 8], scratch: &SourceScratch) -> Result<Self> {
        Ok(Self {
            data: scratch.writer(&sibling(base, ".data.pages"), purpose)?,
            directory: scratch.writer(
                &sibling(base, ".directory.pages"),
                directory_purpose(purpose),
            )?,
            purpose,
            maximum_record_bytes: scratch.budget().record_bytes,
            previous: None,
            records: 0,
            bytes: 0,
            poisoned: false,
        })
    }

    /// Prepay the actual data and ordinal-directory files before native IO
    /// creates the next proof. This is a quota operation, not an advisory size.
    pub fn reserve_next_record(&mut self, maximum_json_bytes: u64) -> Result<()> {
        ensure!(
            !self.poisoned
                && maximum_json_bytes > 0
                && maximum_json_bytes <= self.maximum_record_bytes,
            "next record exceeds its actual resource working window"
        );
        self.reserve_record_batch(maximum_json_bytes, 1)
    }

    /// Reserve complete multi-record output before an external operation.
    /// Individual pushes retain the original per-record working-window check;
    /// this only prepays a bounded logical record split across many rows.
    pub fn reserve_record_batch(
        &mut self,
        maximum_json_bytes: u64,
        maximum_records: u64,
    ) -> Result<()> {
        ensure!(
            !self.poisoned && maximum_records > 0 && maximum_json_bytes >= maximum_records,
            "invalid prepaid record batch"
        );
        let data = self
            .bytes
            .checked_add(maximum_json_bytes)
            .context("prepaid record bytes overflow")?;
        let directory = self
            .records
            .checked_add(maximum_records)
            .and_then(|n| n.checked_mul(DIRECTORY_BYTES))
            .context("prepaid record directory overflow")?;
        self.data.reserve_logical_bytes(data)?;
        self.directory.reserve_logical_bytes(directory)
    }

    pub fn push(&mut self, key: [u8; 16], value: &impl Serialize) -> Result<()> {
        ensure!(!self.poisoned, "record writer is poisoned");
        // Mark intent before serialization: a partially encoded row can never
        // be certified by finish(), including errors unrelated to underlying IO.
        self.poisoned = true;
        ensure!(
            self.previous.is_none_or(|previous| previous < key),
            "record keys duplicate or unordered"
        );
        struct Row<'a> {
            output: &'a mut SourceRangeWriter,
            bytes: u64,
            maximum: u64,
        }
        impl Write for Row<'_> {
            fn write(&mut self, input: &[u8]) -> io::Result<usize> {
                let next = self
                    .bytes
                    .checked_add(input.len() as u64)
                    .filter(|n| *n <= self.maximum)
                    .ok_or_else(|| io::Error::other("record exceeds resource working window"))?;
                self.output.write_all(input)?;
                self.bytes = next;
                Ok(input.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.output.flush()
            }
        }
        let mut row = Row {
            output: &mut self.data,
            bytes: 0,
            maximum: self.maximum_record_bytes,
        };
        serde_json::to_writer(&mut row, value)?;
        let length = row.bytes;
        ensure!(length > 0, "empty record JSON");
        let end = self
            .bytes
            .checked_add(length)
            .context("record byte offset overflow")?;
        let records = self
            .records
            .checked_add(1)
            .context("record count overflow")?;
        let mut entry = [0u8; 32];
        entry[..16].copy_from_slice(&key);
        entry[16..24].copy_from_slice(&self.bytes.to_le_bytes());
        entry[24..].copy_from_slice(&length.to_le_bytes());
        self.directory.write_all(&entry)?;
        self.previous = Some(key);
        self.bytes = end;
        self.records = records;
        self.poisoned = false;
        Ok(())
    }

    /// Preserve an already encoded spill/merge row exactly. Validation does
    /// not allocate a serde Value tree; partial writes poison this owner.
    pub fn push_json(&mut self, key: [u8; 16], payload: &[u8]) -> Result<()> {
        ensure!(!self.poisoned, "record writer is poisoned");
        self.poisoned = true;
        ensure!(
            self.previous.is_none_or(|previous| previous < key)
                && !payload.is_empty()
                && payload.len() as u64 <= self.maximum_record_bytes,
            "encoded record key/length exceeds complete resource domain"
        );
        let mut parser = serde_json::Deserializer::from_slice(payload);
        let _ = serde::de::IgnoredAny::deserialize(&mut parser)?;
        parser.end()?;
        let length = payload.len() as u64;
        let end = self
            .bytes
            .checked_add(length)
            .context("record byte offset overflow")?;
        let records = self
            .records
            .checked_add(1)
            .context("record count overflow")?;
        self.data.write_all(payload)?;
        let mut entry = [0u8; 32];
        entry[..16].copy_from_slice(&key);
        entry[16..24].copy_from_slice(&self.bytes.to_le_bytes());
        entry[24..].copy_from_slice(&length.to_le_bytes());
        self.directory.write_all(&entry)?;
        self.previous = Some(key);
        self.bytes = end;
        self.records = records;
        self.poisoned = false;
        Ok(())
    }

    pub fn finish(self) -> Result<RecordStorePin> {
        ensure!(!self.poisoned, "cannot finish incomplete record store");
        let data = self.data.finish()?;
        let directory = self.directory.finish()?;
        ensure!(
            data.logical_bytes == self.bytes
                && self.records.checked_mul(DIRECTORY_BYTES) == Some(directory.logical_bytes),
            "complete record store lengths differ"
        );
        Ok(RecordStorePin {
            schema_version: 1,
            purpose: self.purpose,
            data,
            directory,
            records: self.records,
        })
    }
}

pub struct SortedRecordStore {
    data: PagedMetadataRange,
    directory: PagedMetadataRange,
    // A cache: given up, with its reservation, when the run's memory is
    // short.
    directory_cache: Option<n2r_win32::evict::Evictable<DirectoryCache>>,
    pin: RecordStorePin,
    maximum_record_bytes: u64,
}

struct DirectoryCache {
    bytes: Vec<u8>,
    // Declared after the buffer so the allocation is dropped before its credit.
    _ram: SourceRamLease,
}
impl DirectoryCache {
    fn try_load(directory: &PagedMetadataRange, scratch: &SourceScratch) -> Result<Option<Self>> {
        let budget = scratch.budget();
        let maximum = (budget.ram_bytes / 64).min(budget.record_bytes);
        let length = directory.byte_len();
        let Some(charge) = length
            .checked_add(std::mem::size_of::<Self>() as u64)
            .filter(|n| length > 0 && *n <= maximum)
        else {
            return Ok(None);
        };
        let Ok(size) = usize::try_from(length) else {
            return Ok(None);
        };
        // This is an optional optimization, never a new admission requirement.
        // Reservation/allocation refusals retain the original paged reader.
        let Ok(ram) = scratch.lease_optional_ram(charge) else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(size).is_err() || bytes.capacity() != size {
            return Ok(None);
        }
        bytes.resize(size, 0);
        // PagedMetadataRange already authenticates the complete logical stream.
        // Read failures remain failures, not an optimization fallback waiver.
        directory.read_exact_at(0, &mut bytes)?;
        Ok(Some(Self { bytes, _ram: ram }))
    }
}

impl SortedRecordStore {
    pub fn open(pin: &RecordStorePin, scratch: &SourceScratch) -> Result<Self> {
        ensure!(
            pin.schema_version == 1
                && pin.data.purpose == pin.purpose
                && pin.directory.purpose == directory_purpose(pin.purpose)
                && pin.data.path != pin.directory.path
                && pin.records.checked_mul(DIRECTORY_BYTES) == Some(pin.directory.logical_bytes),
            "invalid record store root/counts"
        );
        let data = PagedMetadataRange::open(&pin.data, scratch)?;
        let directory = PagedMetadataRange::open(&pin.directory, scratch)?;
        let directory_cache =
            DirectoryCache::try_load(&directory, scratch)?.map(n2r_win32::evict::Evictable::new);
        let store = Self {
            data,
            directory,
            directory_cache,
            pin: pin.clone(),
            maximum_record_bytes: scratch.budget().record_bytes,
        };
        // A store this process wrote and has not seen change (check-once
        // policy) had every record serialized by its writer; its directory is
        // still walked, but its records are not all parsed again to open it.
        let parse_records =
            !(store.data.written_by_this_process() && store.directory.written_by_this_process());
        let mut offset = 0;
        let mut previous = None;
        for ordinal in 0..store.len() {
            let (key, start, length) = store.entry(ordinal)?;
            ensure!(
                previous.is_none_or(|prior| prior < key) && start == offset,
                "record directory duplicate, unordered or incomplete"
            );
            // Parse every complete record before returning any owner. This
            // retains only bounded decoder state, not a serde Value tree.
            if parse_records {
                store.data.with_bytes_at(start, length, |bytes| {
                    let mut parser = serde_json::Deserializer::from_slice(bytes);
                    let _ = serde::de::IgnoredAny::deserialize(&mut parser)?;
                    Ok(parser.end()?)
                })?;
            }
            previous = Some(key);
            offset = start.checked_add(length).context("record range overflow")?;
        }
        ensure!(
            offset == store.data.byte_len(),
            "unindexed trailing metadata bytes"
        );
        store.revalidate()?;
        Ok(store)
    }

    pub fn len(&self) -> u64 {
        self.pin.records
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn pin(&self) -> &RecordStorePin {
        &self.pin
    }
    fn entry(&self, ordinal: u64) -> Result<([u8; 16], u64, u64)> {
        ensure!(
            ordinal < self.len(),
            "record ordinal outside complete domain"
        );
        let mut bytes = [0u8; 32];
        let at = ordinal
            .checked_mul(DIRECTORY_BYTES)
            .context("record index overflow")?;
        if let Some(cache) = self.directory_cache.as_ref().and_then(|cache| cache.get()) {
            let start =
                usize::try_from(at).context("resident record index exceeds address space")?;
            let end = start
                .checked_add(bytes.len())
                .context("resident record index overflow")?;
            bytes.copy_from_slice(
                cache
                    .bytes
                    .get(start..end)
                    .context("resident record index exceeds complete directory")?,
            );
        } else {
            self.directory.read_exact_at(at, &mut bytes)?;
        }
        let key = bytes[..16].try_into()?;
        let offset = u64::from_le_bytes(bytes[16..24].try_into()?);
        let length = u64::from_le_bytes(bytes[24..].try_into()?);
        ensure!(
            length > 0
                && length <= self.maximum_record_bytes
                && offset
                    .checked_add(length)
                    .is_some_and(|end| end <= self.data.byte_len()),
            "record range exceeds complete data/resource budget"
        );
        Ok((key, offset, length))
    }
    pub fn key(&self, ordinal: u64) -> Result<[u8; 16]> {
        Ok(self.entry(ordinal)?.0)
    }
    pub fn record_bytes(&self, ordinal: u64) -> Result<u64> {
        Ok(self.entry(ordinal)?.2)
    }
    pub fn get_json(&self, ordinal: u64) -> Result<Vec<u8>> {
        let (_, offset, length) = self.entry(ordinal)?;
        let size = usize::try_from(length)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size)?;
        bytes.resize(size, 0);
        self.data.read_exact_at(offset, &mut bytes)?;
        Ok(bytes)
    }
    /// Decodes one record. The record is parsed from its bytes in memory: a
    /// reader-based parse took a fresh 64 KiB buffer and went through the
    /// JSON a byte at a time for every record looked up.
    ///
    /// The record is checked to be UTF-8 once, as a whole, and parsed as
    /// text. Parsed as bytes, every string in it, each field's name among
    /// them, was checked by itself: a tenth of what decoding rows cost.
    pub fn get<T: DeserializeOwned>(&self, ordinal: u64) -> Result<T> {
        let (_, offset, length) = self.entry(ordinal)?;
        self.data.with_bytes_at(offset, length, |bytes| {
            Ok(serde_json::from_str(std::str::from_utf8(bytes)?)?)
        })
    }
    pub fn find_ordinal(&self, key: [u8; 16]) -> Result<Option<u64>> {
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let middle = low + (high - low) / 2;
            match self.key(middle)?.cmp(&key) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(Some(middle)),
            }
        }
        Ok(None)
    }
    pub fn find<T: DeserializeOwned>(&self, key: [u8; 16]) -> Result<Option<T>> {
        self.find_ordinal(key)?
            .map(|ordinal| self.get(ordinal))
            .transpose()
    }
    pub fn revalidate(&self) -> Result<()> {
        self.data.revalidate()?;
        self.directory.revalidate()
    }
    pub(crate) fn clear_resident_cache(&mut self) {
        self.data.clear_resident_cache();
        self.directory.clear_resident_cache();
    }
}
