//! Versioned count admission within the existing owning-tree resource envelope.
//! These facts do not supply native evidence, a source certificate or write authority.
use serde::{Deserialize, Serialize};
use std::io;

pub const OBJECT_SLOTS: usize = 1280;
pub const RAW_IDENTITIES: usize = 2048;
pub const DATA_STREAMS: usize = 16_384;
pub const EXPECTED_TREE_BYTES: usize = 16 * 1024 * 1024;
pub const INSPECTION_BYTES: usize = 64 * 1024 * 1024;
pub const NATIVE_REPORT_BYTES: usize = 64 * 1024 * 1024;
// metadata_targets: <=objects; native sparse/ADS target and optional carrier:
// <=two per DATA stream; eight slots cover volume/root/carrier/temporary opens.
pub const OWNED_HANDLE_SLOTS: usize = OBJECT_SLOTS + 2 * DATA_STREAMS + 8;

/// Page/chunk sizes bound transient storage; they are not filesystem count caps.
pub const METADATA_PAGE_BYTES: u32 = 4 * 1024 * 1024;
pub const METADATA_RECORDS_PER_PAGE: u32 = 128;
pub const EXPECTED_CHUNK_BYTES: u32 = 768 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataPageBudget {
    pub max_page_bytes: u32,
    pub max_records_per_page: u32,
    pub max_records: u64,
    pub max_pages: u64,
    pub max_file_bytes: u64,
}

impl MetadataPageBudget {
    #[cfg(windows)]
    pub fn native(self) -> io::Result<crate::metadata_pages::PageBudget> {
        let budget = crate::metadata_pages::PageBudget {
            max_page_bytes: self.max_page_bytes,
            max_records_per_page: self.max_records_per_page,
            max_records: self.max_records,
            max_pages: self.max_pages,
            max_file_bytes: self.max_file_bytes,
        };
        budget.validate()?;
        Ok(budget)
    }
}

/// A caller-selected share of observed available hardware and ordinary scratch
/// space. This is a resource contract, not a filesystem count/size allowance or
/// live source authority. Fresh callers must bind it to their actual observation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub schema_version: u32,
    pub ram_bytes: u64,
    pub scratch_bytes: u64,
    pub page_bytes: u32,
    pub max_row_bytes: u64,
    pub retained_index_bytes: u64,
    pub handle_slots: u64,
}
impl ResourceBudget {
    pub fn validate(self) -> io::Result<()> {
        let working = self
            .max_row_bytes
            .checked_mul(8)
            .and_then(|n| {
                u64::from(self.page_bytes.max(crate::logical_hash::CHUNK as u32))
                    .checked_mul(8)
                    .and_then(|p| n.checked_add(p))
            })
            .and_then(|n| n.checked_add(self.retained_index_bytes))
            .and_then(|n| {
                self.handle_slots
                    .checked_mul(256)
                    .and_then(|h| n.checked_add(h))
            });
        if self.schema_version != 1
            || !(256..=METADATA_PAGE_BYTES).contains(&self.page_bytes)
            || self.max_row_bytes == 0
            || self.retained_index_bytes == 0
            || !working.is_some_and(|n| n <= self.ram_bytes)
            || self.ram_bytes > isize::MAX as u64
            || self.scratch_bytes > i64::MAX as u64
            || self.scratch_bytes / 8 <= u64::from(self.page_bytes) + 192
            || self.max_row_bytes > self.scratch_bytes / 16
            || self.handle_slots < 8
            || self.handle_slots > self.ram_bytes / 256
        {
            return Err(io::Error::other(format!(
                "the memory and working storage available do not make a workable budget: {} MiB of memory, {} MiB of working storage, {}-byte pages, {} file handles, rows of up to {} bytes. A conversion needs a few GiB of each",
                self.ram_bytes >> 20,
                self.scratch_bytes >> 20,
                self.page_bytes,
                self.handle_slots,
                self.max_row_bytes
            )));
        }
        Ok(())
    }
    /// Each primary source/observation/expected/map artifact group has an
    /// eighth of scratch. Legacy semantic JSON has a separate sixteenth;
    /// auxiliary/copy capacity is held by the live aggregate arena. These
    /// ceilings alone do not prove aggregate reservation or current free space.
    pub fn page_budget(self) -> io::Result<MetadataPageBudget> {
        self.validate()?;
        let bytes = self.scratch_bytes / 8;
        Ok(MetadataPageBudget {
            max_page_bytes: self.page_bytes,
            max_records_per_page: (self.page_bytes - 64) / 9,
            max_records: (bytes - 192) / 9,
            max_pages: (bytes - 192) / 137,
            max_file_bytes: bytes,
        })
    }
    /// Explicit Windows native-evidence share. The owning arena must debit
    /// LegacyExpectation and retain the same aggregate scratch/free-space
    /// checks; this budget alone grants neither allocation nor source access.
    pub fn windows_native_page_budget(self) -> io::Result<MetadataPageBudget> {
        self.validate()?;
        let bytes = 3 * (self.scratch_bytes / 16);
        Ok(MetadataPageBudget {
            max_page_bytes: self.page_bytes,
            max_records_per_page: (self.page_bytes - 64) / 9,
            max_records: (bytes - 192) / 9,
            max_pages: (bytes - 192) / 137,
            max_file_bytes: bytes,
        })
    }
}

/// Complete actual source counts, authenticated by the caller's frozen raw
/// inspection pin. Saved JSON preserves these facts for recovery; it cannot
/// recreate the frozen owner, native observation or fresh Apply certificate.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceResourceAdmission {
    pub schema_version: u32,
    pub source_inspection_sha256: [u8; 32],
    pub mft_records: u64,
    pub raw_identities: u64,
    pub files: u64,
    pub directories: u64,
    pub data_streams: u64,
    pub budget: ResourceBudget,
    pub source_pages: MetadataPageBudget,
    pub native_pages: MetadataPageBudget,
    pub expected_pages: MetadataPageBudget,
    pub map_pages: MetadataPageBudget,
}
impl SourceResourceAdmission {
    pub fn new(
        source_inspection_sha256: [u8; 32],
        mft_records: u64,
        raw_identities: u64,
        files: u64,
        directories: u64,
        data_streams: u64,
        budget: ResourceBudget,
    ) -> io::Result<Self> {
        let pages = budget.page_budget()?;
        let value = Self {
            schema_version: 1,
            source_inspection_sha256,
            mft_records,
            raw_identities,
            files,
            directories,
            data_streams,
            budget,
            source_pages: pages,
            native_pages: pages,
            expected_pages: pages,
            map_pages: pages,
        };
        value.validate()?;
        Ok(value)
    }
    /// Schema2 pins the Legacy-funded Windows native allocation. Source,
    /// expected and map pages retain schema1's exact resource shares.
    pub fn new_windows(
        source_inspection_sha256: [u8; 32],
        mft_records: u64,
        raw_identities: u64,
        files: u64,
        directories: u64,
        data_streams: u64,
        budget: ResourceBudget,
    ) -> io::Result<Self> {
        let mut value = Self::new(
            source_inspection_sha256,
            mft_records,
            raw_identities,
            files,
            directories,
            data_streams,
            budget,
        )?;
        value.schema_version = 2;
        value.native_pages = budget.windows_native_page_budget()?;
        value.validate()?;
        Ok(value)
    }
    pub fn objects(self) -> io::Result<u64> {
        self.files
            .checked_add(self.directories)
            .ok_or_else(|| io::Error::other("source object count overflow"))
    }
    pub fn projected_handles(self) -> io::Result<u64> {
        self.data_streams
            .checked_mul(2)
            .and_then(|n| n.checked_add(self.files))
            .and_then(|n| n.checked_add(self.directories))
            .and_then(|n| n.checked_add(8))
            .ok_or_else(|| io::Error::other("source owned handle count overflow"))
    }
    pub fn validate(self) -> io::Result<()> {
        self.budget.validate()?;
        let pages = self.budget.page_budget()?;
        let native_pages = match self.schema_version {
            1 => pages,
            2 => self.budget.windows_native_page_budget()?,
            _ => return Err(io::Error::other("unknown source resource admission schema")),
        };
        // Per-entry state covers scalar source/native identity indexes and
        // target/map ordinal indexes. Large bytes remain in paged records.
        let indexes = self.raw_identities.checked_mul(256).and_then(|n| {
            self.objects()
                .ok()
                .and_then(|o| o.checked_add(self.data_streams))
                .and_then(|o| o.checked_mul(64))
                .and_then(|o| n.checked_add(o))
        });
        if self.source_inspection_sha256 == [0; 32]
            || self.directories == 0
            || self.raw_identities == 0
            || self.raw_identities > self.mft_records
            || self.mft_records > 1 << 48
            || self.objects()? > self.raw_identities
            || self.files > self.data_streams
            || !indexes.is_some_and(|n| n <= self.budget.retained_index_bytes)
            || self.projected_handles()? > self.budget.handle_slots
            || self.source_pages != pages
            || self.native_pages != native_pages
            || self.expected_pages != pages
            || self.map_pages != pages
        {
            return Err(io::Error::other(
                "complete source domain exceeds its pinned resource budget",
            ));
        }
        Ok(())
    }
    pub fn validate_tree(self, files: u64, directories: u64, streams: u64) -> io::Result<()> {
        self.validate()?;
        if (files, directories, streams) != (self.files, self.directories, self.data_streams) {
            return Err(io::Error::other(
                "actual tree differs from complete resource admission",
            ));
        }
        Ok(())
    }
    pub fn semantic_byte_budget(self) -> u64 {
        self.budget.scratch_bytes / 16
    }
    /// Decoded native row bytes occupy the same HEX-encoded native artifact;
    /// this is not an additional disk reservation or constructor allowance.
    pub fn native_semantic_byte_budget(self) -> u64 {
        self.native_pages.max_file_bytes / 2
    }
    pub fn maximum_namespace_names(self) -> io::Result<usize> {
        self.validate()?;
        usize::try_from(self.budget.retained_index_bytes / 128).map_err(io::Error::other)
    }
    pub fn validate_constructor_metadata(self, value: &impl Serialize) -> io::Result<u64> {
        self.validate()?;
        struct Counter {
            used: u64,
            maximum: u64,
        }
        impl io::Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.used = self
                    .used
                    .checked_add(bytes.len() as u64)
                    .filter(|n| *n <= self.maximum)
                    .ok_or_else(|| {
                        io::Error::other("constructor metadata exceeds pinned resource budget")
                    })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut counter = Counter {
            used: 0,
            maximum: self.semantic_byte_budget(),
        };
        serde_json::to_writer_pretty(&mut counter, value).map_err(io::Error::other)?;
        Ok(counter.used)
    }
    #[cfg(windows)]
    pub fn expected_page_budget(self) -> io::Result<crate::metadata_pages::PageBudget> {
        self.validate()?;
        self.expected_pages.native()
    }
    #[cfg(windows)]
    pub fn map_page_budget(self) -> io::Result<crate::metadata_pages::PageBudget> {
        self.validate()?;
        self.map_pages.native()
    }
    #[cfg(windows)]
    pub fn source_page_budget(self) -> io::Result<crate::metadata_pages::PageBudget> {
        self.validate()?;
        self.source_pages.native()
    }
    #[cfg(windows)]
    pub fn native_page_budget(self) -> io::Result<crate::metadata_pages::PageBudget> {
        self.validate()?;
        self.native_pages.native()
    }
    #[cfg(windows)]
    pub fn native_observation_budget(
        self,
    ) -> io::Result<crate::observation_pages::NativeObservationBudget> {
        self.validate()?;
        let result = crate::observation_pages::NativeObservationBudget {
            pages: self.native_pages.native()?,
            max_row_bytes: self.budget.max_row_bytes,
            max_total_row_bytes: self.native_semantic_byte_budget(),
            max_index_bytes: self.budget.retained_index_bytes,
        };
        result.validate()?;
        Ok(result)
    }
}

/// Pinned wire budgets for the active paged constructor/expected-tree and
/// recovery-map domains. These facts do not prove that a caller uses those
/// domains; the actual owning APIs must require paged inputs for schema two.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PagedResourceBudget {
    pub schema_version: u32,
    pub expected_chunk_bytes: u32,
    pub expected_tree_pages: MetadataPageBudget,
    pub recovery_map_pages: MetadataPageBudget,
}

impl PagedResourceBudget {
    fn for_counts(objects: u64, dirs: u64, streams: u64, semantic_bytes: u64) -> io::Result<Self> {
        let overflow = || io::Error::other("paged resource budget overflow");
        // Sum ceil(object_bytes/chunk) is bounded by object count plus the
        // complete semantic byte budget divided by chunk size. One global
        // header and one conservative final-chunk slot are included.
        let records = objects
            .checked_add(semantic_bytes / u64::from(EXPECTED_CHUNK_BYTES))
            .and_then(|n| n.checked_add(2))
            .ok_or_else(overflow)?;
        // Exact public chunk-wire bound: base64 + per-record key/frame overhead,
        // at most one page/index frame per record, one page of slack, footer.
        // This wire capacity is separate from the unchanged semantic 16MiB cap.
        let wire_bytes = semantic_bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(2))
            .map(|n| n / 3)
            .and_then(|n| records.checked_mul(32).and_then(|r| n.checked_add(r)))
            .and_then(|n| records.checked_mul(128).and_then(|r| n.checked_add(r)))
            .and_then(|n| n.checked_add(u64::from(METADATA_PAGE_BYTES)))
            .and_then(|n| n.checked_add(192))
            .ok_or_else(overflow)?;
        let map_records = dirs
            .checked_add(streams)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(overflow)?;
        let file_budget = |records, bytes| MetadataPageBudget {
            max_page_bytes: METADATA_PAGE_BYTES,
            max_records_per_page: METADATA_RECORDS_PER_PAGE,
            max_records: records,
            max_pages: records,
            max_file_bytes: bytes,
        };
        Ok(Self {
            schema_version: 1,
            expected_chunk_bytes: EXPECTED_CHUNK_BYTES,
            expected_tree_pages: file_budget(records, wire_bytes),
            // Same 64MiB complete recovery-map artifact ceiling as the legacy
            // reader; no count-derived payload or journal space is granted.
            recovery_map_pages: file_budget(map_records, NATIVE_REPORT_BYTES as u64),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CountAdmission {
    pub schema_version: u32,
    pub source_inspection_sha256: [u8; 32],
    pub raw_identities: u32,
    pub files: u32,
    pub directories: u32,
    pub data_streams: u32,
    pub object_slots: u32,
    pub raw_identity_slots: u32,
    pub data_stream_slots: u32,
    pub maximum_expected_tree_bytes: u32,
    pub maximum_inspection_bytes: u32,
    pub maximum_native_report_bytes: u32,
    pub projected_owned_handle_slots: u32,
    pub maximum_owned_handle_slots: u32,
    pub maximum_constructor_input_metadata_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paged_resources: Option<PagedResourceBudget>,
}

impl CountAdmission {
    pub fn new(
        source_inspection_sha256: [u8; 32],
        raw: usize,
        files: usize,
        dirs: usize,
        streams: usize,
    ) -> io::Result<Self> {
        let narrow = |n| u32::try_from(n).map_err(io::Error::other);
        let value = Self {
            schema_version: 1,
            source_inspection_sha256,
            raw_identities: narrow(raw)?,
            files: narrow(files)?,
            directories: narrow(dirs)?,
            data_streams: narrow(streams)?,
            object_slots: OBJECT_SLOTS as u32,
            raw_identity_slots: RAW_IDENTITIES as u32,
            data_stream_slots: DATA_STREAMS as u32,
            maximum_expected_tree_bytes: EXPECTED_TREE_BYTES as u32,
            maximum_inspection_bytes: INSPECTION_BYTES as u32,
            maximum_native_report_bytes: NATIVE_REPORT_BYTES as u32,
            projected_owned_handle_slots: narrow(
                files
                    .checked_add(dirs)
                    .and_then(|n| streams.checked_mul(2).and_then(|s| n.checked_add(s)))
                    .and_then(|n| n.checked_add(8))
                    .ok_or_else(|| io::Error::other("owning handle projection overflow"))?,
            )?,
            maximum_owned_handle_slots: OWNED_HANDLE_SLOTS as u32,
            maximum_constructor_input_metadata_bytes: EXPECTED_TREE_BYTES as u32,
            paged_resources: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// Select schema two only from complete actual source counts. The caller
    /// still needs the live frozen source and active paged owning consumers.
    pub fn new_paged(
        source_inspection_sha256: [u8; 32],
        raw: usize,
        files: usize,
        dirs: usize,
        streams: usize,
    ) -> io::Result<Self> {
        let narrow = |n| u32::try_from(n).map_err(io::Error::other);
        let stream_handles = streams
            .checked_mul(2)
            .and_then(|n| n.checked_add(8))
            .ok_or_else(|| io::Error::other("owning handle projection overflow"))?;
        let object_slots = raw.min(
            OWNED_HANDLE_SLOTS
                .checked_sub(stream_handles)
                .ok_or_else(|| {
                    io::Error::other("streams exhaust the existing owned-handle budget")
                })?,
        );
        let objects = files
            .checked_add(dirs)
            .ok_or_else(|| io::Error::other("complete object count overflow"))?;
        let value = Self {
            schema_version: 2,
            source_inspection_sha256,
            raw_identities: narrow(raw)?,
            files: narrow(files)?,
            directories: narrow(dirs)?,
            data_streams: narrow(streams)?,
            object_slots: narrow(object_slots)?,
            raw_identity_slots: RAW_IDENTITIES as u32,
            data_stream_slots: DATA_STREAMS as u32,
            maximum_expected_tree_bytes: EXPECTED_TREE_BYTES as u32,
            maximum_inspection_bytes: INSPECTION_BYTES as u32,
            maximum_native_report_bytes: NATIVE_REPORT_BYTES as u32,
            projected_owned_handle_slots: narrow(
                objects
                    .checked_add(stream_handles)
                    .ok_or_else(|| io::Error::other("owning handle projection overflow"))?,
            )?,
            maximum_owned_handle_slots: OWNED_HANDLE_SLOTS as u32,
            maximum_constructor_input_metadata_bytes: EXPECTED_TREE_BYTES as u32,
            paged_resources: Some(PagedResourceBudget::for_counts(
                objects as u64,
                dirs as u64,
                streams as u64,
                EXPECTED_TREE_BYTES as u64,
            )?),
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn requires_paged_metadata(&self) -> bool {
        self.schema_version == 2
    }

    #[cfg(windows)]
    pub fn expected_page_budget(&self) -> io::Result<crate::metadata_pages::PageBudget> {
        self.validate()?;
        self.paged_resources
            .ok_or_else(|| io::Error::other("legacy admission has no paged budget"))?
            .expected_tree_pages
            .native()
    }

    #[cfg(windows)]
    pub fn map_page_budget(&self) -> io::Result<crate::metadata_pages::PageBudget> {
        self.validate()?;
        self.paged_resources
            .ok_or_else(|| io::Error::other("legacy admission has no paged budget"))?
            .recovery_map_pages
            .native()
    }

    pub fn validate(&self) -> io::Result<()> {
        let objects = u64::from(self.files) + u64::from(self.directories);
        if !matches!(self.schema_version, 1 | 2)
            || self.source_inspection_sha256 == [0; 32]
            || self.directories == 0
            || self.raw_identities == 0
            || objects > u64::from(self.raw_identities)
            || objects > u64::from(self.object_slots)
            || self.files > self.data_streams
            || self.data_streams > self.data_stream_slots
            || self.raw_identities > self.raw_identity_slots
            || self.object_slots == 0
            || self.object_slots as usize
                > if self.schema_version == 1 {
                    OBJECT_SLOTS
                } else {
                    RAW_IDENTITIES
                }
            || self.raw_identity_slots == 0
            || self.raw_identity_slots as usize > RAW_IDENTITIES
            || self.data_stream_slots == 0
            || self.data_stream_slots as usize > DATA_STREAMS
            || self.maximum_expected_tree_bytes == 0
            || self.maximum_expected_tree_bytes as usize > EXPECTED_TREE_BYTES
            || self.maximum_inspection_bytes == 0
            || self.maximum_inspection_bytes as usize > INSPECTION_BYTES
            || self.maximum_native_report_bytes == 0
            || self.maximum_native_report_bytes as usize > NATIVE_REPORT_BYTES
            || u64::from(self.projected_owned_handle_slots)
                != objects + 2 * u64::from(self.data_streams) + 8
            || self.projected_owned_handle_slots > self.maximum_owned_handle_slots
            || self.maximum_owned_handle_slots as usize > OWNED_HANDLE_SLOTS
            || self.maximum_constructor_input_metadata_bytes == 0
            || self.maximum_constructor_input_metadata_bytes as usize > EXPECTED_TREE_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded tree count admission",
            ));
        }
        if self.schema_version == 1 {
            if self.paged_resources.is_some() {
                return Err(io::Error::other(
                    "legacy count admission cannot claim paged resources",
                ));
            }
        } else {
            let remaining = u64::from(self.maximum_owned_handle_slots)
                .checked_sub(2 * u64::from(self.data_streams) + 8)
                .ok_or_else(|| io::Error::other("paged stream handles exhaust the owned budget"))?;
            let expected = PagedResourceBudget::for_counts(
                objects,
                u64::from(self.directories),
                u64::from(self.data_streams),
                u64::from(self.maximum_expected_tree_bytes),
            )?;
            if u64::from(self.object_slots) != u64::from(self.raw_identities).min(remaining)
                || self.paged_resources != Some(expected)
            {
                return Err(io::Error::other(
                    "paged count/resource budget differs from the complete domain",
                ));
            }
        }
        Ok(())
    }

    pub fn validate_tree(&self, files: usize, dirs: usize, streams: usize) -> io::Result<()> {
        self.validate()?;
        if files != self.files as usize
            || dirs != self.directories as usize
            || streams != self.data_streams as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "complete tree counts differ from source admission",
            ));
        }
        Ok(())
    }

    pub fn validate_expected_bytes(&self, value: &impl Serialize) -> io::Result<usize> {
        self.validate_serialized_bytes(value, self.maximum_expected_tree_bytes as usize)
    }
    pub fn validate_constructor_metadata(&self, value: &impl Serialize) -> io::Result<usize> {
        self.validate_serialized_bytes(
            value,
            self.maximum_constructor_input_metadata_bytes as usize,
        )
    }
    pub fn validate_inspection_bytes(&self, value: &impl Serialize) -> io::Result<usize> {
        self.validate_serialized_bytes(value, self.maximum_inspection_bytes as usize)
    }
    fn validate_serialized_bytes(&self, value: &impl Serialize, limit: usize) -> io::Result<usize> {
        struct Count {
            used: usize,
            limit: usize,
        }
        impl io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.used = self
                    .used
                    .checked_add(bytes.len())
                    .filter(|n| *n <= self.limit)
                    .ok_or_else(|| {
                        io::Error::other("metadata exceeds pinned tree resource byte ceiling")
                    })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        self.validate()?;
        let mut count = Count { used: 0, limit };
        serde_json::to_writer_pretty(&mut count, value).map_err(io::Error::other)?;
        Ok(count.used)
    }
}
