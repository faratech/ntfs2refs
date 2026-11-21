//! Complete paged raw-source metadata access. These are observations, never
//! source admission, device exclusion or write/replay authority.
use super::{FileInventory, NtfsGeometry};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Resource quantities supplied by the owning caller, never fixture counts.
/// Wire pages/chunks bound working buffers; they do not limit source objects.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMetadataBudget {
    pub ram_bytes: u64,
    pub scratch_bytes: u64,
    pub page_bytes: u32,
    pub record_bytes: u64,
    pub merge_fan_in: u32,
}
impl SourceMetadataBudget {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.page_bytes >= 256
                && self.page_bytes <= 4 * 1024 * 1024
                && self.record_bytes > 0
                && self.record_bytes <= self.ram_bytes / 4
                && u64::from(self.page_bytes)
                    .checked_mul(3)
                    .is_some_and(|n| n <= self.ram_bytes / 2)
                && self.scratch_bytes > u64::from(self.page_bytes)
                && self.scratch_bytes <= i64::MAX as u64
                && self.merge_fan_in >= 2
                && u64::from(self.merge_fan_in)
                    .checked_mul(u64::from(self.page_bytes))
                    .is_some_and(|n| n <= self.ram_bytes / 2),
            "raw-source working memory, record, merge or scratch budget differs"
        );
        Ok(())
    }
    #[cfg(windows)]
    pub fn page_budget(&self) -> Result<n2r_win32::metadata_pages::PageBudget> {
        self.validate()?;
        let budget = n2r_win32::metadata_pages::PageBudget {
            max_page_bytes: self.page_bytes,
            max_records_per_page: (self.page_bytes - 64) / 9,
            // Every row has an eight-byte prefix and every page/index pair
            // consumes128 bytes before payload. These derive from bytes only.
            max_records: self
                .scratch_bytes
                .checked_sub(192)
                .context("source metadata framing exceeds scratch")?
                / 9,
            max_pages: self
                .scratch_bytes
                .checked_sub(192)
                .context("source metadata framing exceeds scratch")?
                / 137,
            max_file_bytes: self.scratch_bytes,
        };
        budget.validate()?;
        Ok(budget)
    }
    pub fn from_resource_budget(budget: n2r_win32::tree_resources::ResourceBudget) -> Result<Self> {
        budget.validate()?;
        let page = u64::from(budget.page_bytes);
        let fan_in = budget
            .handle_slots
            .min(budget.ram_bytes / (2 * page))
            .min(u64::from(u32::MAX))
            .max(2) as u32;
        let value = Self {
            ram_bytes: budget.ram_bytes,
            scratch_bytes: budget.page_budget()?.max_file_bytes,
            page_bytes: budget.page_bytes,
            record_bytes: budget.max_row_bytes,
            merge_fan_in: fan_in,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Scalar domain header. Global reconciliation payloads live in their owning
/// page/index domains, not in collections hidden behind this header.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHeader {
    pub schema_version: u32,
    pub geometry: NtfsGeometry,
    pub volume_version: Option<String>,
    pub volume_flags: Option<u16>,
    pub dirty: Option<bool>,
    pub mft_record_count: u64,
    pub records_scanned: u64,
    pub allocated_clusters: Option<u64>,
    pub free_clusters: Option<u64>,
    pub inventory_complete: bool,
    pub stream_hash_bytes: u64,
}

/// Canonical base records are in strictly increasing MFT record-number order.
/// The returned record owns only this object's variable metadata. Physical
/// extension segments remain separately covered by the exact allocated bitmap.
pub trait RootFileDomain {
    fn header(&self) -> &SourceHeader;
    fn file_count(&self) -> u64;
    fn file(&self, ordinal: u64) -> Result<FileInventory>;
    /// What `read` makes of the row at `ordinal`. A domain that holds the
    /// row lends it; a caller that reads a few of its fields is not handed
    /// a row of its own for that.
    fn with_file<T>(
        &self,
        ordinal: u64,
        read: impl FnOnce(&FileInventory) -> Result<T>,
    ) -> Result<T>
    where
        Self: Sized,
    {
        read(&self.file(ordinal)?)
    }
    /// The row at `ordinal` to keep, shared: for a caller that holds on to
    /// the row beyond one read of it. This copies the row through
    /// [`file`](Self::file); a domain that holds its rows shared hands out
    /// the one it holds, and the caller is not given a copy for that.
    fn file_shared(&self, ordinal: u64) -> Result<Arc<FileInventory>> {
        self.file(ordinal).map(Arc::new)
    }
    fn find_record(&self, number: u64, sequence: Option<u16>) -> Result<Option<FileInventory>>;
    /// The record that [`find_record`](Self::find_record) finds to keep,
    /// shared, on the terms of [`file_shared`](Self::file_shared).
    fn find_record_shared(
        &self,
        number: u64,
        sequence: Option<u16>,
    ) -> Result<Option<Arc<FileInventory>>> {
        Ok(self.find_record(number, sequence)?.map(Arc::new))
    }
    /// What `read` makes of the record that [`find_record`](Self::find_record)
    /// finds, or `None` where it finds none. A domain that holds the row
    /// lends it: a caller that wants one name of a directory, or its parent,
    /// is not handed a copy of the whole row for it.
    fn with_record<T>(
        &self,
        number: u64,
        sequence: Option<u16>,
        read: impl FnOnce(&FileInventory) -> Result<T>,
    ) -> Result<Option<T>>
    where
        Self: Sized,
    {
        self.find_record(number, sequence)?
            .map(|file| read(&file))
            .transpose()
    }
    fn allocated_record(&self, number: u64) -> Result<bool>;
    fn extension_record(&self, number: u64) -> Result<bool>;
    fn revalidate(&self) -> Result<()>;
}

/// An owning metadata page/range reader. Every range must be completely closed
/// against its held-file pin before a caller can consume bytes. This interface
/// deliberately exposes no source/raw-device or writable handle.
pub trait SourceMetadataRange {
    fn byte_len(&self) -> u64;
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()>;
    fn revalidate(&self) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDirectoryHeader {
    pub record_number: u64,
    pub sequence_number: u16,
    pub entries: u64,
    pub index_blocks: u64,
    pub evidence_sha256: String,
}
pub trait RootDirectoryDomain {
    fn directory_count(&self) -> u64;
    fn directory(&self, ordinal: u64) -> Result<SourceDirectoryHeader>;
    /// Locate a directory ordinal by its MFT `record_number`. Paged stores
    /// override this with a key-only binary search to avoid decoding
    /// `SourceDirectoryHeader` JSON on every probe.
    fn find_directory_ordinal(&self, record_number: u64) -> Result<Option<u64>> {
        let mut low = 0;
        let mut high = self.directory_count();
        while low < high {
            let middle = low + (high - low) / 2;
            match self.directory(middle)?.record_number.cmp(&record_number) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(Some(middle)),
            }
        }
        Ok(None)
    }
    fn entry(
        &self,
        directory_ordinal: u64,
        entry_ordinal: u64,
    ) -> Result<crate::ntfs_namespace::Link>;
    fn upcase(&self) -> &dyn SourceMetadataRange;
    fn revalidate(&self) -> Result<()>;
}

pub struct SourceIndexRanges<'a> {
    pub root: &'a dyn SourceMetadataRange,
    pub allocation: Option<&'a dyn SourceMetadataRange>,
    pub bitmap: Option<&'a dyn SourceMetadataRange>,
    pub initialized_allocation_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySecurityRecord {
    pub record_number: u64,
    pub sequence_number: u16,
    pub bytes: Vec<u8>,
}
pub trait RootSecurityCaptureDomain {
    fn sds(&self) -> &dyn SourceMetadataRange;
    fn index(&self, kind: crate::ntfs_security::IndexKind) -> Result<SourceIndexRanges<'_>>;
    /// Legacy descriptor rows follow strict ascending canonical MFT numbers.
    fn legacy_count(&self) -> u64;
    fn legacy(&self, ordinal: u64) -> Result<LegacySecurityRecord>;
    fn revalidate(&self) -> Result<()>;
}
