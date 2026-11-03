//! Ordinary scratch metadata in authenticated bounded chunks. No device I/O.
use super::source_domain::{SourceMetadataBudget, SourceMetadataRange};
use anyhow::{Context, Result, ensure};
use n2r_win32::metadata_pages::{PageBudget, Reader, Writer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    rc::Rc,
    time::SystemTime,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePagePin {
    pub path: PathBuf,
    pub purpose: [u8; 8],
    pub file_sha256: String,
    pub logical_sha256: String,
    pub logical_bytes: u64,
    pub wire_bytes: u64,
    pub chunk_bytes: u32,
    pub page_budget: PageBudget,
}
struct Ledger {
    budget: SourceMetadataBudget,
    wire: u64,
    ram: u64,
    poisoned: bool,
    created: BTreeMap<PathBuf, CreatedFile>,
}
struct CreatedFile {
    pin: SourcePagePin,
    file_id: String,
    parent_id: String,
    canonical_parent: PathBuf,
    modified: SystemTime,
    readers: u64,
    ram: u64,
}
#[derive(Clone)]
pub struct SourceScratch(Rc<RefCell<Ledger>>);
impl SourceScratch {
    pub fn new(budget: SourceMetadataBudget) -> Result<Self> {
        budget.validate()?;
        Ok(Self(Rc::new(RefCell::new(Ledger {
            budget,
            wire: 0,
            ram: 0,
            poisoned: false,
            created: BTreeMap::new(),
        }))))
    }
    pub fn remaining_bytes(&self) -> u64 {
        let ledger = self.0.borrow();
        ledger.budget.scratch_bytes - ledger.wire
    }
    pub fn budget(&self) -> SourceMetadataBudget {
        self.0.borrow().budget
    }
    pub fn used_bytes(&self) -> u64 {
        self.0.borrow().wire
    }
    pub fn working_ram_bytes(&self) -> u64 {
        self.0.borrow().ram
    }
    pub fn is_poisoned(&self) -> bool {
        self.0.borrow().poisoned
    }
    fn parent_handles(path: &Path) -> Result<(Vec<File>, String, PathBuf)> {
        let parent = path.parent().context("source scratch parent absent")?;
        let mut handles = Vec::new();
        for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "ordinary scratch parent required"
            );
            let handle = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(3)
                .custom_flags(0x0200_0000 | 0x0020_0000)
                .open(ancestor)?;
            ensure!(
                handle.metadata()?.is_dir() && handle.metadata()?.file_attributes() & 0x400 == 0,
                "scratch parent handle differs"
            );
            handles.try_reserve(1)?;
            handles.push(handle);
        }
        let id = n2r_win32::file_storage::file_id_info(
            handles.first().context("scratch parent handle absent")?,
        )?;
        Ok((handles, id, fs::canonicalize(parent)?))
    }
    fn register_created(&self, pin: &SourcePagePin) -> Result<()> {
        let (_parents, parent_id, canonical_parent) = Self::parent_handles(&pin.path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&pin.path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && n2r_win32::file_storage::number_of_links(&file)? == 1
                && metadata.len() == pin.wire_bytes,
            "new scratch file identity differs"
        );
        let file_id = n2r_win32::file_storage::file_id_info(&file)?;
        let ram = (std::mem::size_of::<CreatedFile>() as u64)
            .checked_add(256)
            .and_then(|n| n.checked_add((pin.path.as_os_str().as_encoded_bytes().len() as u64) * 4))
            .and_then(|n| {
                n.checked_add((canonical_parent.as_os_str().as_encoded_bytes().len() as u64) * 4)
            })
            .and_then(|n| n.checked_add(256))
            .context("scratch registry memory overflow")?;
        let mut ledger = self.0.borrow_mut();
        ensure!(
            !ledger.poisoned && !ledger.created.contains_key(&pin.path),
            "duplicate or poisoned created scratch registry"
        );
        let total = ledger
            .ram
            .checked_add(ram)
            .context("scratch registry RAM overflow")?;
        ensure!(
            total <= ledger.budget.ram_bytes,
            "created scratch identity registry RAM exhausted"
        );
        ledger.ram = total;
        ledger.created.insert(
            pin.path.clone(),
            CreatedFile {
                pin: pin.clone(),
                file_id,
                parent_id,
                canonical_parent,
                modified: metadata.modified()?,
                readers: 0,
                ram,
            },
        );
        Ok(())
    }
    fn reader_lease(&self, pin: &SourcePagePin) -> Result<Option<CreatedReaderLease>> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&pin.path)?;
        let identity = n2r_win32::file_storage::file_id_info(&file)?;
        let metadata = file.metadata()?;
        let mut ledger = self.0.borrow_mut();
        if let Some(created) = ledger.created.get_mut(&pin.path) {
            ensure!(
                &created.pin == pin
                    && created.file_id == identity
                    && metadata.len() == pin.wire_bytes
                    && metadata.modified()? == created.modified,
                "created source pin or held identity differs from registry"
            );
            created.readers = created
                .readers
                .checked_add(1)
                .context("scratch reader count overflow")?;
            return Ok(Some(CreatedReaderLease {
                scratch: self.clone(),
                path: pin.path.clone(),
            }));
        }
        Ok(None)
    }
    /// Delete only an exact closed file created by this same private ledger.
    /// JSON pins supply no credit. No pathname deletion or permission change.
    pub fn retire_created(&self, pin: &SourcePagePin) -> Result<()> {
        let result = (|| -> Result<()> {
            let _ram = self.lease_ram(65536)?;
            let (id, parent, canonical, modified, bytes, registry_ram) = {
                let ledger = self.0.borrow();
                ensure!(!ledger.poisoned, "source scratch is poisoned");
                let entry = ledger
                    .created
                    .get(&pin.path)
                    .context("scratch file was not created by this ledger")?;
                ensure!(
                    entry.pin == *pin && entry.readers == 0,
                    "scratch file pin differs or an owner still reads it"
                );
                (
                    entry.file_id.clone(),
                    entry.parent_id.clone(),
                    entry.canonical_parent.clone(),
                    entry.modified,
                    entry.pin.wire_bytes,
                    entry.ram,
                )
            };
            let (_parents, current_parent, current_canonical) = Self::parent_handles(&pin.path)?;
            ensure!(
                current_parent == parent && current_canonical == canonical,
                "scratch parent identity changed"
            );
            // DELETE access is obtained without delete-on-close. Nothing can
            // be removed before the same-handle identity and full SHA pass.
            let mut file = OpenOptions::new()
                .access_mode(0x8000_0000 | 0x0001_0000)
                .share_mode(0)
                .custom_flags(0x0020_0000)
                .open(&pin.path)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file()
                    && metadata.file_attributes() & 0x400 == 0
                    && n2r_win32::file_storage::number_of_links(&file)? == 1
                    && metadata.len() == bytes
                    && metadata.modified()? == modified
                    && n2r_win32::file_storage::file_id_info(&file)? == id,
                "registered scratch handle identity differs"
            );
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut left = bytes;
            file.seek(SeekFrom::Start(0))?;
            while left > 0 {
                let n = left.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..n])?;
                hash.update(&buffer[..n]);
                left -= n as u64;
            }
            ensure!(
                hex::encode(hash.finalize()) == pin.file_sha256
                    && file.metadata()?.len() == bytes
                    && file.metadata()?.modified()? == modified,
                "registered scratch bytes changed"
            );
            n2r_win32::file_storage::mark_delete_on_close(&file)?;
            drop(file);
            match fs::symlink_metadata(&pin.path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => anyhow::bail!("registered scratch deletion was not observed complete"),
            }
            let mut ledger = self.0.borrow_mut();
            let entry = ledger
                .created
                .remove(&pin.path)
                .context("created scratch registration disappeared")?;
            ensure!(
                entry.readers == 0 && entry.pin == *pin,
                "created scratch owner changed"
            );
            ledger.wire = ledger
                .wire
                .checked_sub(bytes)
                .context("scratch wire credit underflow")?;
            ledger.ram = ledger
                .ram
                .checked_sub(registry_ram)
                .context("scratch RAM credit underflow")?;
            Ok(())
        })();
        if result.is_err() {
            self.0.borrow_mut().poisoned = true;
        }
        result
    }
    fn reserve_wire(&self, bytes: u64) -> Result<()> {
        let mut ledger = self.0.borrow_mut();
        ensure!(!ledger.poisoned, "source scratch is poisoned");
        let used = ledger
            .wire
            .checked_add(bytes)
            .context("source scratch byte overflow")?;
        ensure!(
            used <= ledger.budget.scratch_bytes,
            "source metadata scratch exhausted"
        );
        ledger.wire = used;
        Ok(())
    }
    pub fn lease_ram(&self, bytes: u64) -> Result<SourceRamLease> {
        let mut ledger = self.0.borrow_mut();
        ensure!(!ledger.poisoned, "source scratch is poisoned");
        let used = ledger
            .ram
            .checked_add(bytes)
            .context("metadata RAM overflow")?;
        ensure!(
            used <= ledger.budget.ram_bytes,
            "source metadata working RAM exhausted"
        );
        ledger.ram = used;
        Ok(SourceRamLease {
            scratch: self.clone(),
            bytes,
        })
    }
    fn lease_window(&self) -> Result<SourceRamLease> {
        let bytes = u64::from(self.budget().page_bytes)
            .checked_mul(3)
            .context("metadata RAM overflow")?;
        self.lease_ram(bytes)
    }
    pub fn reserve_temporary(
        &self,
        wire_bytes: u64,
        ram_bytes: u64,
    ) -> Result<SourceTemporaryLease> {
        let ram = self.lease_ram(ram_bytes)?;
        self.reserve_wire(wire_bytes)?;
        Ok(SourceTemporaryLease {
            _ram: ram,
            bytes: wire_bytes,
        })
    }
    pub fn writer(&self, path: &Path, purpose: [u8; 8]) -> Result<SourceRangeWriter> {
        let ram = self.lease_window()?;
        let page = self.0.borrow().budget.page_bytes;
        // Both count ceilings derive from physical scratch bytes and minimum
        // record/frame sizes. They impose no independent filesystem limit.
        let budget = self.0.borrow().budget.page_budget()?;
        budget.validate()?;
        let chunk_bytes = page
            .checked_sub(192)
            .context("source page cannot hold a chunk")?
            / 4
            * 3;
        ensure!(chunk_bytes != 0, "source page cannot hold a chunk");
        self.reserve_wire(1024)?;
        let mut writer = Writer::new(path, purpose, budget)?;
        writer.push(
            &[],
            &serde_json::to_vec(&RangeHeader {
                schema_version: 1,
                chunk_bytes,
            })?,
        )?;
        let mut body = Vec::new();
        body.try_reserve_exact(chunk_bytes as usize)
            .context("source chunk RAM unavailable")?;
        Ok(SourceRangeWriter {
            writer: Some(writer),
            scratch: self.clone(),
            _ram: ram,
            path: path.to_owned(),
            purpose,
            budget,
            chunk_bytes,
            body,
            logical_bytes: 0,
            chunks: 0,
            hash: Sha256::new(),
            reserved: 1024,
            complete: false,
        })
    }
}
pub struct SourceRamLease {
    scratch: SourceScratch,
    bytes: u64,
}
struct CreatedReaderLease {
    scratch: SourceScratch,
    path: PathBuf,
}
impl Drop for CreatedReaderLease {
    fn drop(&mut self) {
        if let Some(entry) = self.scratch.0.borrow_mut().created.get_mut(&self.path) {
            entry.readers -= 1;
        }
    }
}
impl Drop for SourceRamLease {
    fn drop(&mut self) {
        self.scratch.0.borrow_mut().ram -= self.bytes;
    }
}
pub struct SourceTemporaryLease {
    _ram: SourceRamLease,
    bytes: u64,
}
impl SourceTemporaryLease {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeHeader {
    schema_version: u32,
    chunk_bytes: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeFooter {
    logical_bytes: u64,
    chunks: u64,
    logical_sha256: String,
}

struct Base64<'a>(&'a [u8]);
impl std::fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for value in self.0.chunks(3) {
            let a = value[0];
            let b = value.get(1).copied();
            let c = value.get(2).copied();
            let encoded = [
                ABC[(a >> 2) as usize],
                ABC[(((a & 3) << 4) | (b.unwrap_or(0) >> 4)) as usize],
                b.map_or(b'=', |b| {
                    ABC[(((b & 15) << 2) | (c.unwrap_or(0) >> 6)) as usize]
                }),
                c.map_or(b'=', |c| ABC[(c & 63) as usize]),
            ];
            f.write_str(std::str::from_utf8(&encoded).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for Base64<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
fn decode(payload: &[u8], maximum: usize) -> Result<Vec<u8>> {
    let text: &str = serde_json::from_slice(payload)?;
    let input = text.as_bytes();
    ensure!(
        !input.is_empty() && input.len().is_multiple_of(4),
        "source chunk base64 length differs"
    );
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    ensure!(padding <= 2, "source chunk base64 padding differs");
    let length = (input.len() / 4)
        .checked_mul(3)
        .and_then(|n| n.checked_sub(padding))
        .context("source chunk length overflow")?;
    ensure!(
        length > 0 && length <= maximum,
        "source chunk exceeds working window"
    );
    let digit = |b| -> Result<u8> {
        Ok(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => anyhow::bail!("noncanonical source chunk alphabet"),
        })
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    for (index, value) in input.chunks_exact(4).enumerate() {
        let last = index + 1 == input.len() / 4;
        let a = digit(value[0])?;
        let b = digit(value[1])?;
        bytes.push((a << 2) | (b >> 4));
        if value[2] == b'=' {
            ensure!(
                last && value[3] == b'=' && b & 15 == 0,
                "noncanonical source chunk padding"
            );
        } else {
            let c = digit(value[2])?;
            bytes.push((b << 4) | (c >> 2));
            if value[3] == b'=' {
                ensure!(last && c & 3 == 0, "noncanonical source chunk padding");
            } else {
                bytes.push((c << 6) | digit(value[3])?);
            }
        }
    }
    ensure!(bytes.len() == length, "source chunk decoded length differs");
    Ok(bytes)
}

pub struct SourceRangeWriter {
    writer: Option<Writer>,
    scratch: SourceScratch,
    _ram: SourceRamLease,
    path: PathBuf,
    purpose: [u8; 8],
    budget: PageBudget,
    chunk_bytes: u32,
    body: Vec<u8>,
    logical_bytes: u64,
    chunks: u64,
    hash: Sha256,
    reserved: u64,
    complete: bool,
}
impl SourceRangeWriter {
    pub fn byte_len(&self) -> u64 {
        self.logical_bytes
    }
    fn chunk(&mut self) -> Result<()> {
        if self.body.is_empty() {
            return Ok(());
        }
        let payload = serde_json::to_vec(&Base64(&self.body))?;
        // Reserve the full encoded row plus its own page and index frames.
        // Shared concurrent writers cannot overrun aggregate scratch first.
        let bytes = (payload.len() as u64)
            .checked_add(8 + 8 + 64 + 64)
            .context("source wire overflow")?;
        self.scratch.reserve_wire(bytes)?;
        self.reserved += bytes;
        self.writer
            .as_mut()
            .context("source writer absent")?
            .push(&self.chunks.to_be_bytes(), &payload)?;
        self.chunks = self
            .chunks
            .checked_add(1)
            .context("source chunk count overflow")?;
        self.body.clear();
        Ok(())
    }
    pub fn finish(mut self) -> Result<SourcePagePin> {
        self.chunk()?;
        let logical_sha256 = hex::encode(self.hash.clone().finalize());
        let footer = RangeFooter {
            logical_bytes: self.logical_bytes,
            chunks: self.chunks,
            logical_sha256: logical_sha256.clone(),
        };
        self.writer
            .as_mut()
            .context("source writer absent")?
            .push(&u64::MAX.to_be_bytes(), &serde_json::to_vec(&footer)?)?;
        let summary = self
            .writer
            .take()
            .context("source writer absent")?
            .finish()?;
        ensure!(
            summary.bytes <= self.reserved,
            "source wire accounting differs"
        );
        self.scratch.0.borrow_mut().wire -= self.reserved - summary.bytes;
        let pin = SourcePagePin {
            path: self.path.clone(),
            purpose: self.purpose,
            file_sha256: summary.sha256,
            logical_sha256,
            logical_bytes: self.logical_bytes,
            wire_bytes: summary.bytes,
            chunk_bytes: self.chunk_bytes,
            page_budget: self.budget,
        };
        self.scratch.register_created(&pin)?;
        self.complete = true;
        Ok(pin)
    }
}
impl Write for SourceRangeWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let total = bytes.len();
        let result = (|| -> Result<()> {
            ensure!(
                !self.scratch.0.borrow().poisoned,
                "source scratch is poisoned"
            );
            self.logical_bytes = self
                .logical_bytes
                .checked_add(total as u64)
                .context("source logical length overflow")?;
            self.hash.update(bytes);
            while !bytes.is_empty() {
                let n = bytes.len().min(self.chunk_bytes as usize - self.body.len());
                self.body.extend_from_slice(&bytes[..n]);
                bytes = &bytes[n..];
                if self.body.len() == self.chunk_bytes as usize {
                    self.chunk()?;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.scratch.0.borrow_mut().poisoned = true;
        }
        result.map(|()| total).map_err(io::Error::other)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for SourceRangeWriter {
    fn drop(&mut self) {
        if !self.complete {
            self.scratch.0.borrow_mut().poisoned = true;
        }
    }
}

pub struct PagedMetadataRange {
    reader: RefCell<Reader>,
    decoded: RefCell<DecodedChunks>,
    pin: SourcePagePin,
    _ram: SourceRamLease,
    // An optional second decoded chunk is charged to the same shared source
    // budget. On constrained systems the reader keeps the existing one-chunk
    // behavior rather than increasing the required memory.
    _extra_cache_ram: Option<SourceRamLease>,
    _created: Option<CreatedReaderLease>,
}
#[derive(Default)]
struct DecodedChunks {
    recent: Option<(u64, Vec<u8>)>,
    previous: Option<(u64, Vec<u8>)>,
}
impl PagedMetadataRange {
    pub fn capture(
        path: &Path,
        purpose: [u8; 8],
        source: &mut impl Read,
        byte_len: u64,
        scratch: &SourceScratch,
    ) -> Result<SourcePagePin> {
        let mut writer = scratch.writer(path, purpose)?;
        let length = scratch.0.borrow().budget.page_bytes as usize / 4;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(length)?;
        buffer.resize(length, 0);
        let mut left = byte_len;
        while left > 0 {
            let n = left.min(buffer.len() as u64) as usize;
            source.read_exact(&mut buffer[..n])?;
            writer.write_all(&buffer[..n])?;
            left -= n as u64;
        }
        writer.finish()
    }
    pub fn open(pin: &SourcePagePin, scratch: &SourceScratch) -> Result<Self> {
        ensure!(
            !scratch.is_poisoned()
                && pin.page_budget.max_page_bytes <= scratch.0.borrow().budget.page_bytes
                && pin.wire_bytes <= scratch.0.borrow().budget.scratch_bytes,
            "source range exceeds owner resources"
        );
        let ram = scratch.lease_window()?;
        let mut reader = Reader::open(&pin.path, &pin.file_sha256, pin.purpose, pin.page_budget)?;
        ensure!(
            reader.byte_len() == pin.wire_bytes && reader.len() >= 2,
            "source range wire length differs"
        );
        let head = reader.get(0)?;
        ensure!(head.key.is_empty(), "source range header key differs");
        let header: RangeHeader = serde_json::from_slice(&head.payload)?;
        ensure!(
            header.schema_version == 1
                && header.chunk_bytes == pin.chunk_bytes
                && pin.chunk_bytes
                    == pin
                        .page_budget
                        .max_page_bytes
                        .checked_sub(192)
                        .context("source chunk window differs")?
                        / 4
                        * 3,
            "source range chunk protocol differs"
        );
        let last = reader.get(reader.len() - 1)?;
        ensure!(
            last.key == u64::MAX.to_be_bytes(),
            "source range footer key differs"
        );
        let footer: RangeFooter = serde_json::from_slice(&last.payload)?;
        ensure!(
            footer.logical_bytes == pin.logical_bytes
                && footer.logical_sha256 == pin.logical_sha256
                && footer.chunks.checked_add(2) == Some(reader.len())
                && footer.chunks == pin.logical_bytes.div_ceil(u64::from(pin.chunk_bytes)),
            "source range footer domain differs"
        );
        let mut hash = Sha256::new();
        let mut total = 0u64;
        for ordinal in 0..footer.chunks {
            let row = reader.get(ordinal + 1)?;
            ensure!(
                row.key == ordinal.to_be_bytes(),
                "source range chunk order differs"
            );
            let chunk = decode(&row.payload, pin.chunk_bytes as usize)?;
            let expected = (pin.logical_bytes - total).min(u64::from(pin.chunk_bytes));
            ensure!(
                chunk.len() as u64 == expected,
                "source range has a short interior chunk"
            );
            hash.update(&chunk);
            total += chunk.len() as u64;
        }
        ensure!(
            total == pin.logical_bytes && hex::encode(hash.finalize()) == pin.logical_sha256,
            "complete source range logical SHA differs"
        );
        reader.revalidate()?;
        let created = scratch.reader_lease(pin)?;
        // File inventory lookups repeatedly alternate between an object and
        // its root/parent record. Other range types are normally sequential;
        // avoid reserving a second window for every directory/index/descriptor.
        let extra_cache_ram = if pin.purpose == *b"N2RFILE1"
            && pin.logical_bytes > u64::from(pin.chunk_bytes)
            && u64::from(pin.chunk_bytes) <= scratch.budget().ram_bytes / 64
        {
            scratch.lease_ram(u64::from(pin.chunk_bytes)).ok()
        } else {
            None
        };
        Ok(Self {
            reader: RefCell::new(reader),
            decoded: RefCell::new(DecodedChunks::default()),
            pin: pin.clone(),
            _ram: ram,
            _extra_cache_ram: extra_cache_ram,
            _created: created,
        })
    }
    pub fn slice(self: &Rc<Self>, offset: u64, bytes: u64) -> Result<SourceMetadataSlice> {
        ensure!(
            offset
                .checked_add(bytes)
                .is_some_and(|n| n <= self.pin.logical_bytes),
            "source metadata slice escapes owner"
        );
        Ok(SourceMetadataSlice {
            owner: Rc::clone(self),
            offset,
            bytes,
        })
    }
}
impl SourceMetadataRange for PagedMetadataRange {
    fn byte_len(&self) -> u64 {
        self.pin.logical_bytes
    }
    fn read_exact_at(&self, offset: u64, mut output: &mut [u8]) -> Result<()> {
        ensure!(
            offset
                .checked_add(output.len() as u64)
                .is_some_and(|n| n <= self.pin.logical_bytes),
            "source range read escapes metadata"
        );
        let mut at = offset;
        while !output.is_empty() {
            let ordinal = at / u64::from(self.pin.chunk_bytes);
            let skip = (at % u64::from(self.pin.chunk_bytes)) as usize;
            {
                let mut cache = self.decoded.borrow_mut();
                if !cache.recent.as_ref().is_some_and(|(n, _)| *n == ordinal)
                    && cache.previous.as_ref().is_some_and(|(n, _)| *n == ordinal)
                {
                    let previous = cache.previous.take();
                    cache.previous = cache.recent.take();
                    cache.recent = previous;
                }
            }
            if !self
                .decoded
                .borrow()
                .recent
                .as_ref()
                .is_some_and(|(n, _)| *n == ordinal)
            {
                {
                    let mut cache = self.decoded.borrow_mut();
                    cache.previous = if self._extra_cache_ram.is_some() {
                        cache.recent.take()
                    } else {
                        cache.recent = None;
                        None
                    };
                }
                let row = self.reader.borrow_mut().get(ordinal + 1)?;
                ensure!(
                    row.key == ordinal.to_be_bytes(),
                    "held source range chunk key differs"
                );
                let chunk = decode(&row.payload, self.pin.chunk_bytes as usize)?;
                let remaining = self.pin.logical_bytes - ordinal * u64::from(self.pin.chunk_bytes);
                ensure!(
                    chunk.len() as u64 == remaining.min(u64::from(self.pin.chunk_bytes)),
                    "held source range chunk length differs"
                );
                self.decoded.borrow_mut().recent = Some((ordinal, chunk));
            }
            let cached = self.decoded.borrow();
            let chunk = &cached
                .recent
                .as_ref()
                .context("source chunk cache absent")?
                .1;
            let n = output.len().min(chunk.len() - skip);
            output[..n].copy_from_slice(&chunk[skip..skip + n]);
            output = &mut output[n..];
            at += n as u64;
        }
        Ok(())
    }
    fn revalidate(&self) -> Result<()> {
        self.reader.borrow_mut().revalidate()?;
        Ok(())
    }
}
pub struct SourceMetadataSlice {
    owner: Rc<PagedMetadataRange>,
    offset: u64,
    bytes: u64,
}
impl SourceMetadataRange for SourceMetadataSlice {
    fn byte_len(&self) -> u64 {
        self.bytes
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        ensure!(
            offset
                .checked_add(output.len() as u64)
                .is_some_and(|n| n <= self.bytes),
            "source slice read escapes range"
        );
        self.owner.read_exact_at(self.offset + offset, output)
    }
    fn revalidate(&self) -> Result<()> {
        self.owner.revalidate()
    }
}
