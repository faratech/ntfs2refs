//! Canonical raw files over a complete fixed-width disk index and bitmap facts.
use super::*;
use super::{
    paged_storage::{PagedMetadataRange, SourcePagePin, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore},
};

pub(super) fn file_key(number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key
}

pub struct PagedRawFiles {
    header: SourceHeader,
    files: SortedRecordStore,
    allocated: Box<dyn SourceMetadataRange>,
    extensions: PagedMetadataRange,
    extension_pin: SourcePagePin,
    scratch: SourceScratch,
}
impl PagedRawFiles {
    pub(super) fn from_live_bitmap(
        header: SourceHeader,
        files: &RecordStorePin,
        allocated: Box<dyn SourceMetadataRange>,
        extensions: &SourcePagePin,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        ensure!(
            header.schema_version == 2
                && header.mft_record_count > 6
                && header.mft_record_count <= 1 << 48
                && header.records_scanned <= header.mft_record_count,
            "paged source intrinsic MFT domain differs"
        );
        let value = Self {
            header,
            files: SortedRecordStore::open(files, scratch)?,
            allocated,
            extensions: PagedMetadataRange::open(extensions, scratch)?,
            extension_pin: extensions.clone(),
            scratch: scratch.clone(),
        };
        value.validate_complete_files()?;
        Ok(value)
    }
    pub fn file_pin(&self) -> &RecordStorePin {
        self.files.pin()
    }
    pub fn extension_pin(&self) -> &SourcePagePin {
        &self.extension_pin
    }
    pub fn budget(&self) -> SourceMetadataBudget {
        self.scratch.budget()
    }
    pub(super) fn set_header(&mut self, header: SourceHeader) -> Result<()> {
        ensure!(
            header.schema_version == self.header.schema_version
                && header.geometry == self.header.geometry
                && header.mft_record_count == self.header.mft_record_count
                && header.records_scanned == self.header.records_scanned,
            "source summary cannot rebind its physical file domain"
        );
        self.header = header;
        Ok(())
    }
    pub(super) fn replace_files(&mut self, pin: &RecordStorePin) -> Result<()> {
        ensure!(
            pin.records == self.files.len() && pin.data.path != self.files.pin().data.path,
            "source row replacement cannot change its complete identity domain"
        );
        let replacement = SortedRecordStore::open(pin, &self.scratch)?;
        for ordinal in 0..replacement.len() {
            ensure!(
                replacement.key(ordinal)? == self.files.key(ordinal)?,
                "source row replacement changed a canonical identity"
            );
        }
        let old = self.files.pin().clone();
        self.files = replacement;
        self.validate_complete_files()?;
        self.scratch.retire_created(&old.data)?;
        self.scratch.retire_created(&old.directory)?;
        Ok(())
    }
    pub(super) fn ordinal(&self, number: u64) -> Result<Option<u64>> {
        let key = file_key(number);
        let (mut low, mut high) = (0, self.files.len());
        while low < high {
            let mid = low + (high - low) / 2;
            match self.files.key(mid)?.cmp(&key) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
            }
        }
        Ok(None)
    }
    pub(super) fn record_wire_bytes(&self, number: u64) -> Result<Option<u64>> {
        self.ordinal(number)?.map(|ordinal| self.files.record_bytes(ordinal)).transpose()
    }
    pub(super) fn ordinal_wire_bytes(&self, ordinal: u64) -> Result<u64> {
        self.files.record_bytes(ordinal)
    }
    fn bit(&self, range: &dyn SourceMetadataRange, number: u64) -> Result<bool> {
        ensure!(
            number < self.header.mft_record_count,
            "record-bit query escapes MFT"
        );
        let mut byte = [0];
        range.read_exact_at(number / 8, &mut byte)?;
        Ok(byte[0] & (1 << (number % 8)) != 0)
    }
    fn validate_complete_files(&self) -> Result<()> {
        self.revalidate()?;
        let bytes = self.header.mft_record_count.div_ceil(8);
        ensure!(
            self.allocated.byte_len() >= bytes && self.extensions.byte_len() == bytes,
            "complete physical record bitmap lengths differ"
        );
        let window = (u64::from(self.budget().page_bytes) / 4).clamp(1, 65536) as usize;
        let _ram = self.scratch.lease_ram(
            self.budget()
                .record_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(2 * window as u64))
                .context("file validation RAM overflow")?,
        )?;
        let mut allocated = Vec::new();
        allocated.try_reserve_exact(window)?;
        allocated.resize(window, 0);
        let mut extensions = Vec::new();
        extensions.try_reserve_exact(window)?;
        extensions.resize(window, 0);
        let (mut at, mut allocated_count, mut extension_count) = (0u64, 0u64, 0u64);
        while at < self.allocated.byte_len() {
            let n = (self.allocated.byte_len() - at).min(window as u64) as usize;
            self.allocated.read_exact_at(at, &mut allocated[..n])?;
            extensions[..n].fill(0);
            if at < bytes {
                let count = (bytes - at).min(n as u64) as usize;
                self.extensions
                    .read_exact_at(at, &mut extensions[..count])?;
            }
            for index in 0..n {
                let position = at + index as u64;
                let first = position
                    .checked_mul(8)
                    .context("record bitmap address overflow")?;
                let mask = if first >= self.header.mft_record_count {
                    0
                } else {
                    let bits = (self.header.mft_record_count - first).min(8) as u32;
                    ((1u16 << bits) - 1) as u8
                };
                ensure!(
                    allocated[index] & !mask == 0 && extensions[index] & !allocated[index] == 0,
                    "physical extension/free/tail bitmap conservation differs"
                );
                allocated_count += u64::from(allocated[index].count_ones());
                extension_count += u64::from(extensions[index].count_ones());
            }
            at += n as u64;
        }
        ensure!(
            allocated_count == self.header.records_scanned
                && self.files.len().checked_add(extension_count) == Some(allocated_count),
            "complete canonical and physical extension record counts differ"
        );
        let mut previous = None;
        for ordinal in 0..self.files.len() {
            let file: FileInventory = self.files.get(ordinal)?;
            ensure!(
                self.files.key(ordinal)? == file_key(file.record_number)
                    && previous.is_none_or(|n| n < file.record_number)
                    && file.base_file_reference == 0
                    && self.bit(self.allocated.as_ref(), file.record_number)?
                    && !self.bit(&self.extensions, file.record_number)?,
                "canonical source identity/key/allocation differs"
            );
            ensure!(
                file_heap_bytes(&file)?
                    .checked_add(std::mem::size_of::<FileInventory>() as u64)
                    .is_some_and(|n| n <= self.budget().record_bytes.saturating_mul(8)),
                "one source row exceeds its resource working window"
            );
            previous = Some(file.record_number);
        }
        self.revalidate()
    }
}
impl RootFileDomain for PagedRawFiles {
    fn header(&self) -> &SourceHeader {
        &self.header
    }
    fn file_count(&self) -> u64 {
        self.files.len()
    }
    fn file(&self, ordinal: u64) -> Result<FileInventory> {
        self.files.get(ordinal)
    }
    fn find_record(&self, number: u64, sequence: Option<u16>) -> Result<Option<FileInventory>> {
        let Some(ordinal) = self.ordinal(number)? else {
            return Ok(None);
        };
        let file = self.file(ordinal)?;
        Ok(if sequence.is_none_or(|s| s == file.sequence_number) {
            Some(file)
        } else {
            None
        })
    }
    fn allocated_record(&self, number: u64) -> Result<bool> {
        self.bit(self.allocated.as_ref(), number)
    }
    fn extension_record(&self, number: u64) -> Result<bool> {
        self.bit(&self.extensions, number)
    }
    fn revalidate(&self) -> Result<()> {
        self.files.revalidate()?;
        self.allocated.revalidate()?;
        self.extensions.revalidate()
    }
}
