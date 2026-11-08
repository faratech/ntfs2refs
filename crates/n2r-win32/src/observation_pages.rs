//! Complete, authenticated native source evidence, retaining one typed row.
//! This is metadata storage, never a source certificate or a device lease.
use crate::{
    attestation::*,
    metadata_pages::{PageBudget, Reader, Summary, Writer},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    cell::RefCell,
    io::{self, Read, Write},
    path::Path,
};

pub(crate) mod memory;

const PURPOSE: [u8; 8] = *b"N2RNAT01";
const INDEX_BYTES: u64 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationBudget {
    pub pages: PageBudget,
    pub max_row_bytes: u64,
    pub max_total_row_bytes: u64,
    /// Compact (first record, record count, decoded bytes) entries, not rows.
    pub max_index_bytes: u64,
}
impl NativeObservationBudget {
    pub fn validate(self) -> io::Result<()> {
        self.pages.validate()?;
        require(
            self.pages.max_page_bytes > 92
                && self.max_row_bytes > 0
                && self.max_row_bytes <= self.max_total_row_bytes
                && self.max_total_row_bytes <= i64::MAX as u64
                && self.max_index_bytes >= INDEX_BYTES,
            "invalid native observation budget",
        )
    }
    fn chunk_bytes(self) -> usize {
        ((self.pages.max_page_bytes - 91) / 2) as usize
    }
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| io::Error::other("native observation accounting overflow"))
}
fn key(phase: u8, row: u64, chunk: u64) -> [u8; 17] {
    let mut key = [0; 17];
    key[0] = phase;
    key[1..9].copy_from_slice(&row.to_be_bytes());
    key[9..].copy_from_slice(&chunk.to_be_bytes());
    key
}
fn decode_key(key: &[u8]) -> io::Result<(u8, u64, u64)> {
    require(
        key.len() == 17 && key[0] <= 2,
        "invalid native observation key",
    )?;
    Ok((
        key[0],
        u64::from_be_bytes(key[1..9].try_into().unwrap()),
        u64::from_be_bytes(key[9..17].try_into().unwrap()),
    ))
}
fn decode_chunk(payload: &[u8], maximum: usize) -> io::Result<Vec<u8>> {
    let text: &str = serde_json::from_slice(payload).map_err(io::Error::other)?;
    require(
        text.len() <= maximum * 2
            && text.len().is_multiple_of(2)
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical native observation chunk",
    )?;
    hex::decode(text).map_err(io::Error::other)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRow {
    request: NativeRequestRow,
    observation: Observation,
    logical: LogicalFile,
}
#[derive(Serialize)]
struct BorrowedFileRow<'a> {
    request: &'a NativeRequestRow,
    observation: &'a Observation,
    logical: &'a LogicalFile,
}

pub(crate) struct NativePageWriter {
    writer: Writer,
    budget: NativeObservationBudget,
    total: u64,
    files: u64,
    namespace: u64,
    poisoned: bool,
    resources: ResourceAudit,
}
impl NativePageWriter {
    pub(crate) fn new(
        path: &Path,
        budget: NativeObservationBudget,
        profile: ResourceProfile,
    ) -> io::Result<Self> {
        budget.validate()?;
        Ok(Self {
            writer: Writer::new(path, PURPOSE, budget.pages)?,
            budget,
            total: 0,
            files: 0,
            namespace: 0,
            poisoned: false,
            resources: ResourceAudit {
                profile,
                security_bytes: 0,
                stream_evidence_bytes: 0,
                bitmap_evidence_bytes: 0,
                namespace_evidence_bytes: 0,
            },
        })
    }
    fn row(&mut self, phase: u8, ordinal: u64, value: &impl Serialize) -> io::Result<()> {
        require(!self.poisoned, "native page writer is incomplete")?;
        self.poisoned = true;
        let mut sink = ChunkSink {
            writer: &mut self.writer,
            budget: self.budget,
            phase,
            ordinal,
            chunk: 0,
            bytes: 0,
            buffer: Vec::new(),
        };
        serde_json::to_writer(&mut sink, value).map_err(io::Error::other)?;
        sink.emit()?; // Always a short final chunk, including exact multiples.
        self.total = add(self.total, sink.bytes)?;
        require(
            self.total <= self.budget.max_total_row_bytes,
            "native observation total budget exhausted",
        )?;
        self.poisoned = false;
        Ok(())
    }
    pub(crate) fn file(
        &mut self,
        request: &NativeRequestRow,
        observation: &Observation,
        logical: &LogicalFile,
    ) -> io::Result<()> {
        require(
            self.namespace == 0
                && request.identity == observation.identity
                && observation.identity == logical.identity,
            "native observation row identity or order differs",
        )?;
        self.row(
            0,
            self.files,
            &BorrowedFileRow {
                request,
                observation,
                logical,
            },
        )?;
        self.add_resources(measured_row_resources(
            self.resources.profile,
            Some(observation),
            Some(logical),
            None,
        )?)?;
        self.files = add(self.files, 1)?;
        Ok(())
    }
    pub(crate) fn namespace(&mut self, row: &NamespaceFile) -> io::Result<()> {
        require(
            self.namespace < self.files,
            "native namespace row count differs",
        )?;
        self.row(1, self.namespace, row)?;
        self.add_resources(measured_row_resources(
            self.resources.profile,
            None,
            None,
            Some(row),
        )?)?;
        self.namespace = add(self.namespace, 1)?;
        Ok(())
    }
    fn add_resources(&mut self, row: ResourceAudit) -> io::Result<()> {
        self.resources.merge(row)
    }
    pub(crate) fn resources(&self) -> &ResourceAudit {
        &self.resources
    }
    pub(crate) fn maximum_row_bytes(&self) -> u64 {
        self.budget.max_row_bytes
    }
    pub(crate) fn finish(mut self, header: &Report) -> io::Result<Summary> {
        require(
            self.files == self.namespace
                && self.files == header.request.selected_count()? as u64
                && header.files.is_empty()
                && header
                    .logical_data
                    .as_ref()
                    .is_some_and(|d| d.files.is_empty())
                && header
                    .namespace
                    .as_ref()
                    .is_some_and(|d| d.files.is_empty()),
            "native observation incomplete closure",
        )?;
        self.row(2, 0, header)?;
        self.writer.finish()
    }
}
struct ChunkSink<'a> {
    writer: &'a mut Writer,
    budget: NativeObservationBudget,
    phase: u8,
    ordinal: u64,
    chunk: u64,
    bytes: u64,
    buffer: Vec<u8>,
}
impl ChunkSink<'_> {
    fn emit(&mut self) -> io::Result<()> {
        let payload = serde_json::to_vec(&hex::encode(&self.buffer)).map_err(io::Error::other)?;
        self.writer
            .push(&key(self.phase, self.ordinal, self.chunk), &payload)?;
        self.chunk = add(self.chunk, 1)?;
        self.buffer.clear();
        Ok(())
    }
}
impl Write for ChunkSink<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        self.bytes = add(self.bytes, length as u64)?;
        require(
            self.bytes <= self.budget.max_row_bytes,
            "native observation row budget exhausted",
        )?;
        while !bytes.is_empty() {
            let n = bytes
                .len()
                .min(self.budget.chunk_bytes() - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.buffer.len() == self.budget.chunk_bytes() {
                self.emit()?;
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
struct RowIndex {
    first: u64,
    records: u64,
    bytes: u64,
}

/// Held ordinary file, authenticated and fully decoded/validated before return.
/// No raw handle is exposed; callers still exclude raw aliases and preexisting
/// writable mappings under the same artifact ownership contract as other pins.
pub struct PagedNativeObservation {
    reader: RefCell<Reader>,
    // File and namespace rows are written in separate phases. Independent
    // authenticated page caches prevent an identity join from reloading and
    // rehashing a full page every time it switches between those phases.
    namespace_reader: RefCell<Reader>,
    header: Report,
    // SDK-issued volume refresh only. The immutable file/header and every
    // per-file row remain the original authenticated historical evidence.
    refreshed_header: Option<Report>,
    header_wire_bytes: u64,
    files: Vec<RowIndex>,
    namespace: Vec<RowIndex>,
    budget: NativeObservationBudget,
    total_bytes: u64,
    sha256: String,
    _refreshed_header_memory:
        Option<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>,
    // Drop decoded/header/index/cache storage before returning shared RAM.
    memory: Option<memory::Memory>,
}
impl std::fmt::Debug for PagedNativeObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PagedNativeObservation")
            .field("sha256", &self.sha256)
            .field("rows", &self.files.len())
            .field("budget", &self.budget)
            .finish()
    }
}
impl PagedNativeObservation {
    pub fn open(path: &Path, sha256: &str, budget: NativeObservationBudget) -> io::Result<Self> {
        Self::open_accounted(path, sha256, budget, None)
    }
    pub(crate) fn open_with_memory(
        path: &Path,
        sha256: &str,
        budget: NativeObservationBudget,
        memory: memory::Memory,
    ) -> io::Result<Self> {
        Self::open_accounted(path, sha256, budget, Some(memory))
    }
    fn open_accounted(
        path: &Path,
        sha256: &str,
        budget: NativeObservationBudget,
        memory: Option<memory::Memory>,
    ) -> io::Result<Self> {
        budget.validate()?;
        let mut reader = Reader::open(path, sha256, PURPOSE, budget.pages)?;
        // The terminal header is indexed by its own canonical last chunk key.
        // Read it first so the two scalar directories reserve their exact final
        // lengths rather than temporarily exceeding the pinned memory budget.
        require(!reader.is_empty(), "empty native observation file")?;
        let last_ordinal = reader.len() - 1;
        let last = reader.get(last_ordinal)?;
        let (phase, ordinal, last_chunk) = decode_key(&last.key)?;
        require(phase == 2 && ordinal == 0, "missing terminal native header")?;
        let first = last_ordinal
            .checked_sub(last_chunk)
            .ok_or_else(|| io::Error::other("native header chunk index underflow"))?;
        let mut terminal = RowIndex {
            first,
            records: add(last_chunk, 1)?,
            bytes: 0,
        };
        for chunk in 0..terminal.records {
            let record = reader.get(add(first, chunk)?)?;
            require(
                decode_key(&record.key)? == (2, 0, chunk),
                "native header chunk sequence differs",
            )?;
            let bytes = decode_chunk(&record.payload, budget.chunk_bytes())?;
            require(
                if chunk == last_chunk {
                    bytes.len() < budget.chunk_bytes()
                } else {
                    bytes.len() == budget.chunk_bytes()
                },
                "native header terminal chunk differs",
            )?;
            terminal.bytes = add(terminal.bytes, bytes.len() as u64)?;
            require(
                terminal.bytes <= budget.max_row_bytes,
                "native header row budget exceeded",
            )?;
        }
        let header: Report = decode_row(&mut reader, terminal, budget)?;
        header.request.validate()?;
        if let Some(admission) = header
            .request
            .resource_profile
            .map(ResourceProfile::resource_admission)
            .transpose()?
            .flatten()
        {
            require(
                budget == admission.native_observation_budget()?,
                "native observation budget differs from pinned profile",
            )?;
        }
        let count = header.request.selected_count()?;
        require(
            (count as u64)
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| n.checked_mul(INDEX_BYTES))
                .is_some_and(|n| n <= budget.max_index_bytes),
            "native observation index budget exceeded",
        )?;
        if let Some(memory) = &memory {
            require(
                count == memory.expected_rows,
                "native header count changed before index allocation",
            )?;
        }
        let mut files = Vec::new();
        let mut namespace = Vec::new();
        files.try_reserve_exact(count).map_err(io::Error::other)?;
        namespace
            .try_reserve_exact(count)
            .map_err(io::Error::other)?;
        let mut header_index = None;
        let mut at = 0;
        let mut total = 0;
        while at < reader.len() {
            let first = reader.get(at)?;
            let (phase, ordinal, chunk) = decode_key(&first.key)?;
            require(
                chunk == 0
                    && match phase {
                        0 => {
                            namespace.is_empty()
                                && header_index.is_none()
                                && ordinal == files.len() as u64
                                && files.len() < count
                        }
                        1 => {
                            header_index.is_none()
                                && ordinal == namespace.len() as u64
                                && ordinal < files.len() as u64
                        }
                        2 => {
                            ordinal == 0 && header_index.is_none() && files.len() == namespace.len()
                        }
                        _ => false,
                    },
                "native observation row sequence differs",
            )?;
            let mut index = RowIndex {
                first: at,
                records: 0,
                bytes: 0,
            };
            loop {
                require(
                    at < reader.len(),
                    "native observation lacks terminal row chunk",
                )?;
                let record = reader.get(at)?;
                require(
                    decode_key(&record.key)? == (phase, ordinal, index.records),
                    "native observation chunk sequence differs",
                )?;
                let bytes = decode_chunk(&record.payload, budget.chunk_bytes())?;
                index.bytes = add(index.bytes, bytes.len() as u64)?;
                index.records = add(index.records, 1)?;
                at = add(at, 1)?;
                require(
                    index.bytes <= budget.max_row_bytes,
                    "native observation row budget exceeded",
                )?;
                if bytes.len() < budget.chunk_bytes() {
                    break;
                }
            }
            total = add(total, index.bytes)?;
            require(
                total <= budget.max_total_row_bytes,
                "native observation total budget exceeded",
            )?;
            let entries = add(add(files.len() as u64, namespace.len() as u64)?, 1)?;
            require(
                entries
                    .checked_mul(INDEX_BYTES)
                    .is_some_and(|n| n <= budget.max_index_bytes),
                "native observation index budget exceeded",
            )?;
            match phase {
                0 => files.push(index),
                1 => namespace.push(index),
                _ => {
                    header_index = Some(index);
                    require(at == reader.len(), "native observation has trailing rows")?;
                }
            }
        }
        let actual_header =
            header_index.ok_or_else(|| io::Error::other("missing native observation header"))?;
        require(
            actual_header.first == terminal.first
                && actual_header.records == terminal.records
                && actual_header.bytes == terminal.bytes,
            "native header closure differs",
        )?;
        require(
            header.files.is_empty()
                && header
                    .logical_data
                    .as_ref()
                    .is_some_and(|d| d.files.is_empty())
                && header
                    .namespace
                    .as_ref()
                    .is_some_and(|d| d.files.is_empty())
                && !header.conversion_qualified
                && files.len() == count,
            "native paged header contains rows or incomplete counts",
        )?;
        let namespace_reader = Reader::open(path, sha256, PURPOSE, budget.pages)?;
        require(
            namespace_reader.final_path() == reader.final_path()
                && namespace_reader.byte_len() == reader.byte_len()
                && namespace_reader.len() == reader.len(),
            "native observation readers differ",
        )?;
        let mut result = Self {
            memory,
            reader: RefCell::new(reader),
            namespace_reader: RefCell::new(namespace_reader),
            header,
            refreshed_header: None,
            header_wire_bytes: actual_header.bytes,
            files,
            namespace,
            budget,
            total_bytes: total,
            sha256: sha256.to_owned(),
            _refreshed_header_memory: None,
        };
        for i in 0..result.len() {
            let row = result.row_view(i)?;
            require(
                (result.header.request.has_paged_selectors()
                    || row.request().identity == result.header.request.files[i])
                    && row.observation().identity == row.request().identity
                    && row.logical()?.identity == row.observation().identity
                    && row.namespace()?.identity == row.request().identity,
                "native observation identity closure differs",
            )?;
        }
        validate_domain_resources(&result)?;
        result.revalidate()?;
        if let Some(memory) = &mut result.memory {
            memory.close(&result.header, &result.files, &result.namespace)?;
        }
        Ok(result)
    }
    fn file_row(&self, i: usize) -> io::Result<FileRow> {
        let row = *self
            .files
            .get(i)
            .ok_or_else(|| io::Error::other("native observation index outside domain"))?;
        require(
            row.bytes > 0 && row.bytes <= self.budget.max_row_bytes,
            "native file row exceeds its authenticated decode limit",
        )?;
        let _decode = self
            .memory
            .as_ref()
            .map(|m| m.decode(self.budget, row.bytes))
            .transpose()?;
        decode_row(&mut self.reader.borrow_mut(), row, self.budget)
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub(crate) fn reserve_metadata_refresh_memory(
        &self,
    ) -> io::Result<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>> {
        require(
            self.refreshed_header.is_none(),
            "native header was already refreshed",
        )?;
        let clusters = u64::from_le_bytes(
            self.header
                .ntfs_data_before
                .get(16..24)
                .ok_or_else(|| io::Error::other("cached NTFS cluster count absent"))?
                .try_into()
                .unwrap(),
        );
        let limits = source_bitmap_limits(self.header.request.resource_profile, clusters)?;
        // Two completed bitmap summaries plus bounded collector growth/prefix
        // copies, old-header cloning, and fixed bitmap/privilege workspaces.
        let bytes = (limits.max_allocated_ranges as u64)
            .checked_mul(128)
            .and_then(|n| n.checked_add(16 * 1024 * 1024))
            .and_then(|n| {
                memory::header_bytes(&self.header)
                    .ok()
                    .and_then(|h| h.checked_mul(2))
                    .and_then(|h| n.checked_add(h))
            })
            .ok_or_else(|| io::Error::other("native refreshed header RAM overflow"))?;
        self.memory
            .as_ref()
            .ok_or_else(|| io::Error::other("refreshed header needs actual native memory owner"))?
            .accountant
            .reserve(bytes)
    }
    pub(crate) fn install_metadata_refreshed_header(
        &mut self,
        header: Report,
        mut memory: Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>,
    ) -> io::Result<()> {
        require(
            self.refreshed_header.is_none()
                && header.files.is_empty()
                && header
                    .logical_data
                    .as_ref()
                    .is_some_and(|d| d.files.is_empty())
                && header
                    .namespace
                    .as_ref()
                    .is_some_and(|d| d.files.is_empty())
                && !header.conversion_qualified,
            "native refreshed header shape differs",
        )?;
        let profile = header
            .request
            .resource_profile
            .ok_or_else(|| io::Error::other("native refreshed profile absent"))?;
        self.refreshed_header = Some(header);
        let resources = measured_domain_resources(self, profile)?;
        self.refreshed_header.as_mut().unwrap().resources = Some(resources);
        struct Count {
            bytes: u64,
            maximum: u64,
        }
        impl Write for Count {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes = self
                    .bytes
                    .checked_add(bytes.len() as u64)
                    .filter(|n| *n <= self.maximum)
                    .ok_or_else(|| {
                        io::Error::other("native refreshed header exceeds row budget")
                    })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut count = Count {
            bytes: 0,
            maximum: self.budget.max_row_bytes,
        };
        serde_json::to_writer(&mut count, self.refreshed_header.as_ref().unwrap())
            .map_err(io::Error::other)?;
        self.total_bytes = self
            .total_bytes
            .checked_sub(self.header_wire_bytes)
            .and_then(|n| n.checked_add(count.bytes))
            .filter(|n| *n <= self.budget.max_total_row_bytes)
            .ok_or_else(|| io::Error::other("native refreshed total evidence budget exceeded"))?;
        memory.shrink_to(memory::header_bytes(
            self.refreshed_header.as_ref().unwrap(),
        )?)?;
        self._refreshed_header_memory = Some(memory);
        validate_domain_resources(self)
    }
    /// Collector, immutable header, index vectors and both page caches share
    /// actual leases. Cow-returning decoded rows need separate consumer leases.
    pub fn retained_storage_ram_accounted(&self) -> bool {
        self.memory.is_some()
    }
    pub fn budget(&self) -> NativeObservationBudget {
        self.budget
    }
    pub fn byte_len(&self) -> u64 {
        self.reader.borrow().byte_len()
    }
    pub fn page_count(&self) -> u64 {
        self.reader.borrow().page_count()
    }
    pub fn final_path(&self) -> String {
        self.reader.borrow().final_path().to_owned()
    }
    pub fn copy_to(&self, path: &Path) -> io::Result<()> {
        self.reader.borrow_mut().copy_to(path)
    }
}
impl NativeObservationDomain for PagedNativeObservation {
    fn header(&self) -> &Report {
        self.refreshed_header.as_ref().unwrap_or(&self.header)
    }
    fn len(&self) -> usize {
        self.files.len()
    }
    fn logical_len(&self) -> usize {
        self.files.len()
    }
    fn namespace_len(&self) -> usize {
        self.namespace.len()
    }
    fn row_view(&self, i: usize) -> io::Result<NativeObservationRow<'_>> {
        let file_index = *self
            .files
            .get(i)
            .ok_or_else(|| io::Error::other("native row ordinal outside domain"))?;
        let namespace_index = *self
            .namespace
            .get(i)
            .ok_or_else(|| io::Error::other("native namespace ordinal outside domain"))?;
        require(
            file_index.bytes > 0
                && file_index.bytes <= self.budget.max_row_bytes
                && namespace_index.bytes > 0
                && namespace_index.bytes <= self.budget.max_row_bytes,
            "native paired rows exceed their authenticated decode limits",
        )?;
        let simultaneous_bytes = add(file_index.bytes, namespace_index.bytes)?;
        let memory = self
            .memory
            .as_ref()
            .map(|m| m.decode(self.budget, simultaneous_bytes))
            .transpose()?
            .flatten();
        let file: FileRow = decode_row(&mut self.reader.borrow_mut(), file_index, self.budget)?;
        let namespace: NamespaceFile = decode_row(
            &mut self.namespace_reader.borrow_mut(),
            namespace_index,
            self.budget,
        )?;
        Ok(NativeObservationRow::new(
            Cow::Owned(file.request),
            Cow::Owned(file.observation),
            Some(Cow::Owned(file.logical)),
            Some(Cow::Owned(namespace)),
        )
        .with_memory(memory))
    }
    fn observation(&self, i: usize) -> io::Result<Cow<'_, Observation>> {
        Ok(Cow::Owned(self.file_row(i)?.observation))
    }
    fn logical_file(&self, i: usize) -> io::Result<Cow<'_, LogicalFile>> {
        Ok(Cow::Owned(self.file_row(i)?.logical))
    }
    fn namespace_file(&self, i: usize) -> io::Result<Cow<'_, NamespaceFile>> {
        let row = *self
            .namespace
            .get(i)
            .ok_or_else(|| io::Error::other("namespace index outside domain"))?;
        require(
            row.bytes > 0 && row.bytes <= self.budget.max_row_bytes,
            "native namespace row exceeds its authenticated decode limit",
        )?;
        let _decode = self
            .memory
            .as_ref()
            .map(|m| m.decode(self.budget, row.bytes))
            .transpose()?;
        Ok(Cow::Owned(decode_row(
            &mut self.namespace_reader.borrow_mut(),
            row,
            self.budget,
        )?))
    }
    fn request_row(&self, i: usize) -> io::Result<Cow<'_, NativeRequestRow>> {
        Ok(Cow::Owned(self.file_row(i)?.request))
    }
    fn revalidate(&self) -> io::Result<()> {
        self.reader.borrow_mut().revalidate()?;
        self.namespace_reader.borrow_mut().revalidate()
    }
    fn validate_encoded_size(&self, maximum: usize) -> io::Result<()> {
        require(
            self.total_bytes <= maximum as u64,
            "native observation semantic encoding budget exceeded",
        )
    }
    fn is_paged(&self) -> bool {
        true
    }
    fn maximum_security_descriptor_bytes(&self) -> usize {
        usize::try_from(self.budget.max_row_bytes).unwrap_or(usize::MAX)
    }
}
struct ChunkReader<'a> {
    reader: &'a mut Reader,
    row: RowIndex,
    budget: NativeObservationBudget,
    next: u64,
    buffer: Vec<u8>,
    position: usize,
}
impl Read for ChunkReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.position == self.buffer.len() {
            if self.next == self.row.records {
                return Ok(0);
            }
            let record = self.reader.get(self.row.first + self.next)?;
            self.buffer = decode_chunk(&record.payload, self.budget.chunk_bytes())?;
            self.next += 1;
            self.position = 0;
        }
        let n = out.len().min(self.buffer.len() - self.position);
        out[..n].copy_from_slice(&self.buffer[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}
fn decode_row<T: serde::de::DeserializeOwned>(
    reader: &mut Reader,
    row: RowIndex,
    budget: NativeObservationBudget,
) -> io::Result<T> {
    let input = ChunkReader {
        reader,
        row,
        budget,
        next: 0,
        buffer: Vec::new(),
        position: 0,
    };
    let mut decoder = serde_json::Deserializer::from_reader(input);
    let result = T::deserialize(&mut decoder).map_err(io::Error::other)?;
    decoder.end().map_err(io::Error::other)?;
    Ok(result)
}
