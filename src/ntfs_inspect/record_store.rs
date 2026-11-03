//! Sorted ordinary metadata records with a disk-resident fixed-width directory.
//! Pins describe stored facts; they never grant device or conversion authority.
use super::{
    SourceMetadataRange,
    paged_storage::{PagedMetadataRange, SourcePagePin, SourceRangeWriter, SourceScratch},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    io::{self, BufReader, Read, Write},
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
    pin: RecordStorePin,
    maximum_record_bytes: u64,
    read_buffer_bytes: usize,
}

struct RowReader<'a> {
    range: &'a dyn SourceMetadataRange,
    offset: u64,
    remaining: u64,
}
impl Read for RowReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let length =
            usize::try_from(self.remaining.min(output.len() as u64)).map_err(io::Error::other)?;
        if length == 0 {
            return Ok(0);
        }
        self.range
            .read_exact_at(self.offset, &mut output[..length])
            .map_err(io::Error::other)?;
        self.offset += length as u64;
        self.remaining -= length as u64;
        Ok(length)
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
        let store = Self {
            data: PagedMetadataRange::open(&pin.data, scratch)?,
            directory: PagedMetadataRange::open(&pin.directory, scratch)?,
            pin: pin.clone(),
            maximum_record_bytes: scratch.budget().record_bytes,
            read_buffer_bytes: usize::try_from(
                (u64::from(scratch.budget().page_bytes) / 4).clamp(1, 64 * 1024),
            )?,
        };
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
            let reader = BufReader::with_capacity(
                store.read_buffer_bytes,
                RowReader {
                    range: &store.data,
                    offset: start,
                    remaining: length,
                },
            );
            let mut parser = serde_json::Deserializer::from_reader(reader);
            let _ = serde::de::IgnoredAny::deserialize(&mut parser)?;
            parser.end()?;
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
        self.directory.read_exact_at(
            ordinal
                .checked_mul(DIRECTORY_BYTES)
                .context("record index overflow")?,
            &mut bytes,
        )?;
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
    pub fn get<T: DeserializeOwned>(&self, ordinal: u64) -> Result<T> {
        let (_, offset, remaining) = self.entry(ordinal)?;
        Ok(serde_json::from_reader(BufReader::with_capacity(
            self.read_buffer_bytes,
            RowReader {
                range: &self.data,
                offset,
                remaining,
            },
        ))?)
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
        self.find_ordinal(key)?.map(|ordinal| self.get(ordinal)).transpose()
    }
    pub fn revalidate(&self) -> Result<()> {
        self.data.revalidate()?;
        self.directory.revalidate()
    }
}
