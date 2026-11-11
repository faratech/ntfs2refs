//! Complete paged initialized-tail observations. Only a protected native
//! observer creates the result owner; saved rows never recreate that lease.
use crate::{
    general_layout::GeneralSourceShadowBinding,
    metadata_pages::{PageBudget, Reader, Writer},
    shadow_native::LayoutResidualExpectation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, io, path::Path};
const PURPOSE: [u8; 8] = *b"N2RTAIL1";
pub trait LayoutResidualProvider {
    fn len(&self) -> u64;
    fn expectation(&self, ordinal: u64) -> io::Result<LayoutResidualExpectation>;
    fn file_sha256(&self) -> &str;
    fn revalidate(&self) -> io::Result<()>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutResidualResult {
    pub expectation: LayoutResidualExpectation,
    pub native_file_id: [u8; 16],
    pub actual_sha256: String,
    pub bytes_read: u64,
    pub eof_observed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema_version: u32,
    pair: GeneralSourceShadowBinding,
    input_objects: u64,
    provider_sha256: String,
    input_metadata_sha256: String,
    expected_rows: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Footer {
    rows: u64,
    payload_bytes_read: u64,
    rows_sha256: String,
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}
fn plus(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| io::Error::other("residual accounting overflow"))
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate(row: &LayoutResidualResult, objects: u64) -> io::Result<()> {
    let e = &row.expectation;
    require(
        (e.object_index as u64) < objects
            && e.stream_name_utf16.len() <= 255
            && !e.stream_name_utf16.contains(&0)
            && e.logical_offset.is_multiple_of(4096)
            && (1..4096).contains(&e.length)
            && e.logical_offset
                .checked_add(e.length)
                .is_some_and(|n| n <= i64::MAX as u64)
            && hash(&e.sha256)
            && row.actual_sha256 == e.sha256
            && row.native_file_id != [0; 16]
            && row.bytes_read == e.length
            && row.eof_observed,
        "invalid actual residual observation",
    )
}
fn key(e: &LayoutResidualExpectation) -> (usize, &[u16]) {
    (e.object_index, &e.stream_name_utf16)
}
pub(crate) struct ResidualResultsWriter {
    writer: Writer,
    header: Header,
    rows: u64,
    bytes: u64,
    hash: Sha256,
    previous: Option<LayoutResidualExpectation>,
}
impl ResidualResultsWriter {
    pub(crate) fn new(
        path: &Path,
        budget: PageBudget,
        pair: GeneralSourceShadowBinding,
        input_objects: u64,
        provider_sha256: &str,
        input_metadata_sha256: String,
        expected_rows: u64,
    ) -> io::Result<Self> {
        require(
            hash(provider_sha256)
                && hash(&input_metadata_sha256)
                && expected_rows
                    .checked_add(2)
                    .is_some_and(|n| n <= budget.max_records),
            "residual result budget/pins invalid",
        )?;
        let header = Header {
            schema_version: 1,
            pair,
            input_objects,
            provider_sha256: provider_sha256.into(),
            input_metadata_sha256,
            expected_rows,
        };
        let mut writer = Writer::new(path, PURPOSE, budget)?;
        writer.push(&[], &serde_json::to_vec(&header).map_err(io::Error::other)?)?;
        Ok(Self {
            writer,
            header,
            rows: 0,
            bytes: 0,
            hash: Sha256::new(),
            previous: None,
        })
    }
    pub(crate) fn push(&mut self, row: &LayoutResidualResult) -> io::Result<()> {
        validate(row, self.header.input_objects)?;
        require(
            self.rows < self.header.expected_rows
                && self
                    .previous
                    .as_ref()
                    .is_none_or(|p| key(p) < key(&row.expectation)),
            "residual result order/count differs",
        )?;
        let payload = serde_json::to_vec(row).map_err(io::Error::other)?;
        self.writer.push(&self.rows.to_be_bytes(), &payload)?;
        self.hash.update((payload.len() as u64).to_le_bytes());
        self.hash.update(payload);
        self.rows = plus(self.rows, 1)?;
        self.bytes = plus(self.bytes, row.bytes_read)?;
        self.previous = Some(row.expectation.clone());
        Ok(())
    }
    pub(crate) fn finish(
        mut self,
        path: &Path,
        budget: PageBudget,
    ) -> io::Result<PagedLayoutResidualResults> {
        require(
            self.rows == self.header.expected_rows,
            "residual results incomplete",
        )?;
        let footer = Footer {
            rows: self.rows,
            payload_bytes_read: self.bytes,
            rows_sha256: hex::encode(self.hash.finalize()),
        };
        self.writer.push(
            &u64::MAX.to_be_bytes(),
            &serde_json::to_vec(&footer).map_err(io::Error::other)?,
        )?;
        let summary = self.writer.finish()?;
        PagedLayoutResidualResults::open(path, &summary.sha256, budget, &self.header)
    }
}
pub struct PagedLayoutResidualResults {
    reader: RefCell<Reader>,
    header: Header,
    sha256: String,
    payload_bytes_read: u64,
}
impl std::fmt::Debug for PagedLayoutResidualResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PagedLayoutResidualResults")
            .field("sha256", &self.sha256)
            .field("rows", &self.header.expected_rows)
            .finish()
    }
}
impl Serialize for PagedLayoutResidualResults {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Receipt<'a> {
            schema_version: u32,
            file_sha256: &'a str,
            rows: u64,
            bytes: u64,
            pages: u64,
            payload_bytes_read: u64,
            provider_sha256: &'a str,
            input_metadata_sha256: &'a str,
        }
        Receipt {
            schema_version: 1,
            file_sha256: &self.sha256,
            rows: self.len(),
            bytes: self.byte_len(),
            pages: self.page_count(),
            payload_bytes_read: self.payload_bytes_read,
            provider_sha256: &self.header.provider_sha256,
            input_metadata_sha256: &self.header.input_metadata_sha256,
        }
        .serialize(serializer)
    }
}
impl PagedLayoutResidualResults {
    fn open(path: &Path, sha256: &str, budget: PageBudget, expected: &Header) -> io::Result<Self> {
        let mut reader = Reader::open(path, sha256, PURPOSE, budget)?;
        require(reader.len() >= 2, "residual result header/footer absent")?;
        let first = reader.get(0)?;
        require(first.key.is_empty(), "residual result header key differs")?;
        let header: Header = serde_json::from_slice(&first.payload).map_err(io::Error::other)?;
        require(
            serde_json::to_vec(&header).map_err(io::Error::other)?
                == serde_json::to_vec(expected).map_err(io::Error::other)?
                && header.schema_version == 1,
            "residual result header identity differs",
        )?;
        let last = reader.get(reader.len() - 1)?;
        require(
            last.key == u64::MAX.to_be_bytes(),
            "residual result footer key differs",
        )?;
        let footer: Footer = serde_json::from_slice(&last.payload).map_err(io::Error::other)?;
        require(
            footer.rows == header.expected_rows && footer.rows.checked_add(2) == Some(reader.len()),
            "residual complete row count differs",
        )?;
        let mut digest = Sha256::new();
        let mut bytes = 0u64;
        let mut previous = None;
        for ordinal in 0..footer.rows {
            let record = reader.get(ordinal + 1)?;
            require(
                record.key == ordinal.to_be_bytes(),
                "residual ordinal differs",
            )?;
            let row: LayoutResidualResult =
                serde_json::from_slice(&record.payload).map_err(io::Error::other)?;
            validate(&row, header.input_objects)?;
            require(
                previous
                    .as_ref()
                    .is_none_or(|p| key(p) < key(&row.expectation)),
                "residual global order differs",
            )?;
            digest.update((record.payload.len() as u64).to_le_bytes());
            digest.update(&record.payload);
            bytes = plus(bytes, row.bytes_read)?;
            previous = Some(row.expectation);
        }
        require(
            hex::encode(digest.finalize()) == footer.rows_sha256
                && bytes == footer.payload_bytes_read,
            "residual complete digest/byte closure differs",
        )?;
        reader.revalidate()?;
        Ok(Self {
            reader: RefCell::new(reader),
            header,
            sha256: sha256.into(),
            payload_bytes_read: bytes,
        })
    }
    pub fn len(&self) -> u64 {
        self.header.expected_rows
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn provider_sha256(&self) -> &str {
        &self.header.provider_sha256
    }
    pub fn input_metadata_sha256(&self) -> &str {
        &self.header.input_metadata_sha256
    }
    pub fn payload_bytes_read(&self) -> u64 {
        self.payload_bytes_read
    }
    pub fn byte_len(&self) -> u64 {
        self.reader.borrow().byte_len()
    }
    pub fn page_count(&self) -> u64 {
        self.reader.borrow().page_count()
    }
    pub fn final_path(&self) -> String {
        self.reader.borrow().final_path().into()
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.reader.borrow_mut().revalidate()
    }
    pub fn get(&self, ordinal: u64) -> io::Result<LayoutResidualResult> {
        require(
            ordinal < self.len(),
            "residual result ordinal outside owner",
        )?;
        let record = self.reader.borrow_mut().get(ordinal + 1)?;
        require(
            record.key == ordinal.to_be_bytes(),
            "residual result ordinal changed",
        )?;
        serde_json::from_slice(&record.payload).map_err(io::Error::other)
    }
    pub fn find(
        &self,
        object_index: usize,
        name: &[u16],
    ) -> io::Result<Option<LayoutResidualResult>> {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let mid = low + (high - low) / 2;
            let row = self.get(mid)?;
            match key(&row.expectation).cmp(&(object_index, name)) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Ok(Some(row)),
            }
        }
        Ok(None)
    }
}
