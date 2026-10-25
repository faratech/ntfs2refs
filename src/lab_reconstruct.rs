//! Explicit laboratory reconstruction over caller-owned, exclusively held IO.
//! No device opener or production conversion command is provided here.
//! Successful sync_all is assumed durable. Mount exclusion, physical storage
//! guarantees, trusted-ticket storage and filesystem semantics are external.
//! Any persisted handoff byte permanently closes recovery through this core.
use crate::retained_compare::{self, RetainedCompareRequest};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

const GRANULE: u64 = 4096;
const BODY_START: u64 = 8192;
const HEADER_SIZE: usize = 128;
const RECORD_SIZE: usize = 160;
const FOOTER_SIZE: usize = 128;
const MAX_METADATA: usize = 1024 * 1024;
const MAX_CHANGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 768 * 1024 * 1024;
const BUFFER: usize = 1024 * 1024;

/// Caller keeps the exact storage binding and exclusive lease intact.
pub trait ReadSeek: Read + Seek {
    fn byte_len(&mut self) -> io::Result<u64>;
}
pub trait DurableIo: ReadSeek + Write {
    fn sync_all(&mut self) -> io::Result<()>;
}
impl ReadSeek for File {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}
impl DurableIo for File {
    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

#[cfg(windows)]
impl ReadSeek for n2r_win32::GeneralFrozenPartition {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(n2r_win32::GeneralFrozenPartition::byte_len(self))
    }
}

#[cfg(windows)]
impl ReadSeek for n2r_win32::GeneralJournaledPartition {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(n2r_win32::GeneralJournaledPartition::byte_len(self))
    }
}

#[cfg(windows)]
impl DurableIo for n2r_win32::GeneralJournaledPartition {
    fn sync_all(&mut self) -> io::Result<()> {
        n2r_win32::GeneralJournaledPartition::sync_all(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalBinding {
    pub experiment_id: String,
    pub target_identity_sha256: String,
    pub shadow_identity_sha256: String,
    pub journal_identity_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalTicket {
    pub schema_version: u32,
    pub binding: JournalBinding,
    pub immutable_sha256: String,
    pub immutable_length: u64,
    pub journal_length: u64,
}
#[derive(Debug, Serialize)]
pub struct JournalSummary {
    pub ticket: JournalTicket,
    pub changed_bytes: u64,
    pub before_payload_bytes: u64,
    pub after_payload_bytes: u64,
    pub overhead_bytes: u64,
    pub patch_count: u32,
    pub expected_postimage_sha256: String,
    pub preparation_durable: bool,
    pub conversion_qualified: bool,
}
#[derive(Debug, Serialize)]
pub struct ExecutionReport {
    pub operation: String,
    pub target_sha256: String,
    pub target_bytes_written: u64,
    pub patches_written: u32,
    pub retained_bytes_unchanged: bool,
    pub handoff_recorded: bool,
    pub conversion_qualified: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionKind {
    Refs,
    NtfsRollback,
}

#[derive(Debug, Serialize)]
pub struct CompletedMarkerProof {
    pub kind: CompletionKind,
    pub target_sha256: String,
    /// None when an NTFS rollback marker is verified after shadow loss.
    pub shadow_sha256: Option<String>,
    pub marker_sha256: String,
    pub immutable_journal_sha256: String,
    pub marker_exact: bool,
    pub target_exact: bool,
    pub shadow_exact: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct JournalPatchRange {
    pub offset: u64,
    pub length: u64,
}

/// Constructed only by inspecting a complete, externally pinned journal.
/// No Deserialize implementation: a serialized descriptor is not write authority.
#[derive(Debug, Serialize)]
pub struct JournalDescriptor {
    pub binding: JournalBinding,
    pub request: RetainedCompareRequest,
    pub patches: Vec<JournalPatchRange>,
    pub changed_bytes: u64,
    pub expected_postimage_sha256: String,
    pub immutable_sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    binding: JournalBinding,
    request: RetainedCompareRequest,
    expected_postimage_sha256: String,
}
struct Record {
    offset: u64,
    length: u64,
    before_data: u64,
    after_data: u64,
    before_hash: [u8; 32],
    after_hash: [u8; 32],
}
struct Loaded {
    manifest: Manifest,
    records: Vec<Record>,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn pin(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lowercase SHA-256 pin"
    );
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes)?;
    Ok(bytes)
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed record bounds"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed record bounds"))
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn read_at<R: Read + Seek>(io: &mut R, at: u64, bytes: &mut [u8]) -> Result<()> {
    io.seek(SeekFrom::Start(at))?;
    io.read_exact(bytes)?;
    Ok(())
}
/// Hash an exact bounded source interval without issuing writes.
pub fn hash_range<R: Read + Seek>(io: &mut R, at: u64, length: u64) -> Result<[u8; 32]> {
    io.seek(SeekFrom::Start(at))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; usize::try_from(length.min(BUFFER as u64))?];
    let mut left = length;
    while left != 0 {
        let count = usize::try_from(left.min(BUFFER as u64))?;
        io.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        left -= count as u64;
    }
    Ok(hash.finalize().into())
}
fn validate_binding(binding: &JournalBinding) -> Result<()> {
    ensure!(
        binding.experiment_id.len() == 32
            && binding
                .experiment_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "experiment identity must be 32 lowercase hex digits"
    );
    pin(&binding.target_identity_sha256)?;
    pin(&binding.shadow_identity_sha256)?;
    pin(&binding.journal_identity_sha256)?;
    ensure!(
        binding.target_identity_sha256 != binding.shadow_identity_sha256
            && binding.target_identity_sha256 != binding.journal_identity_sha256
            && binding.shadow_identity_sha256 != binding.journal_identity_sha256,
        "target, shadow and external journal bindings must be distinct"
    );
    Ok(())
}
fn validate_profile(request: &RetainedCompareRequest) -> Result<()> {
    retained_compare::validate_request(request)?;
    ensure!(
        request.sector_size == GRANULE as u32,
        "reconstruction requires 4096-byte granules"
    );
    ensure!(
        request.max_change_bytes <= MAX_CHANGE_BYTES,
        "reconstruction changed-byte cap is 256 MiB"
    );
    Ok(())
}
fn copy_pinned<R: Read + Seek, J: Write>(
    source: &mut R,
    offset: u64,
    length: u64,
    journal: &mut J,
    expected: &str,
) -> Result<()> {
    source.seek(SeekFrom::Start(offset))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; usize::try_from(length.min(BUFFER as u64))?];
    let mut left = length;
    while left != 0 {
        let count = usize::try_from(left.min(BUFFER as u64))?;
        source.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        journal.write_all(&buffer[..count])?;
        left -= count as u64;
    }
    ensure!(
        hex::encode(hash.finalize()) == expected,
        "payload changed while preparing journal"
    );
    Ok(())
}

/// Writes only a new empty external journal. Both inputs are pinned completely
/// before journal preparation, and neither receives writes.
pub fn prepare_journal<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    shadow: &mut S,
    journal: &mut J,
    request: &RetainedCompareRequest,
    binding: &JournalBinding,
    max_journal_bytes: u64,
) -> Result<JournalSummary> {
    validate_profile(request)?;
    validate_binding(binding)?;
    ensure!(
        max_journal_bytes <= MAX_JOURNAL_BYTES,
        "journal budget exceeds hard cap"
    );
    ensure!(
        source.byte_len()? == request.expected_length
            && shadow.byte_len()? == request.expected_length,
        "source/shadow length differs"
    );
    ensure!(
        journal.byte_len()? == 0,
        "journal must be a newly created empty external file"
    );
    let comparison = retained_compare::compare_streams(source, shadow, request)?;
    ensure!(
        source.byte_len()? == request.expected_length
            && shadow.byte_len()? == request.expected_length,
        "input length changed during preparation"
    );
    let manifest = Manifest {
        schema_version: 1,
        binding: binding.clone(),
        request: request.clone(),
        expected_postimage_sha256: comparison.expected_postimage_sha256.clone(),
    };
    let metadata = serde_json::to_vec(&manifest)?;
    ensure!(
        metadata.len() <= MAX_METADATA,
        "journal metadata exceeds bound"
    );
    let count = u32::try_from(comparison.patches.len())?;
    let overhead = BODY_START
        + HEADER_SIZE as u64
        + metadata.len() as u64
        + u64::from(count) * RECORD_SIZE as u64
        + FOOTER_SIZE as u64;
    let journal_length = overhead
        .checked_add(
            comparison
                .patch_bytes
                .checked_mul(2)
                .context("payload budget overflow")?,
        )
        .context("journal budget overflow")?;
    ensure!(
        journal_length <= max_journal_bytes,
        "complete journal including metadata exceeds budget"
    );
    let mut header = [0; HEADER_SIZE];
    header[..8].copy_from_slice(b"N2RPREP1");
    put32(&mut header, 8, 1);
    put32(&mut header, 12, metadata.len() as u32);
    put32(&mut header, 16, count);
    put64(&mut header, 24, comparison.patch_bytes);
    put64(&mut header, 32, journal_length);
    header[40..72].copy_from_slice(&digest(&metadata));
    let hash = digest(&header[..96]);
    header[96..].copy_from_slice(&hash);
    journal.seek(SeekFrom::Start(0))?;
    journal.write_all(&[0; BODY_START as usize])?;
    journal.write_all(&header)?;
    journal.write_all(&metadata)?;
    let mut root = Sha256::new();
    root.update(header);
    root.update(&metadata);
    let mut chain: [u8; 32] = root.finalize().into();
    for (index, patch) in comparison.patches.iter().enumerate() {
        let mut record = [0; RECORD_SIZE];
        record[..8].copy_from_slice(b"N2RREC01");
        put64(&mut record, 8, index as u64);
        put64(&mut record, 16, patch.offset);
        put64(&mut record, 24, patch.length);
        record[32..64].copy_from_slice(&pin(&patch.before_sha256)?);
        record[64..96].copy_from_slice(&pin(&patch.after_sha256)?);
        record[96..128].copy_from_slice(&chain);
        chain = digest(&record[..128]);
        record[128..].copy_from_slice(&chain);
        journal.write_all(&record)?;
        copy_pinned(
            source,
            patch.offset,
            patch.length,
            journal,
            &patch.before_sha256,
        )?;
        copy_pinned(
            shadow,
            patch.offset,
            patch.length,
            journal,
            &patch.after_sha256,
        )?;
    }
    let end = journal.stream_position()?;
    let mut footer = [0; FOOTER_SIZE];
    footer[..8].copy_from_slice(b"N2REND01");
    put64(&mut footer, 8, u64::from(count));
    put64(&mut footer, 16, end);
    footer[24..56].copy_from_slice(&chain);
    footer[56..88].copy_from_slice(&digest(&header));
    let hash = digest(&footer[..96]);
    footer[96..].copy_from_slice(&hash);
    journal.write_all(&footer)?;
    ensure!(
        journal.byte_len()? == journal_length,
        "prepared journal length mismatch"
    );
    journal.sync_all()?;
    let ticket = JournalTicket {
        schema_version: 1,
        binding: binding.clone(),
        immutable_sha256: hex::encode(hash_range(
            journal,
            BODY_START,
            journal_length - BODY_START,
        )?),
        immutable_length: journal_length - BODY_START,
        journal_length,
    };
    load_journal(journal, &ticket)?;
    Ok(JournalSummary {
        ticket,
        changed_bytes: comparison.patch_bytes,
        before_payload_bytes: comparison.patch_bytes,
        after_payload_bytes: comparison.patch_bytes,
        overhead_bytes: overhead,
        patch_count: count,
        expected_postimage_sha256: comparison.expected_postimage_sha256,
        preparation_durable: true,
        conversion_qualified: false,
    })
}

fn load_journal<J: ReadSeek>(journal: &mut J, ticket: &JournalTicket) -> Result<Loaded> {
    load_journal_state(journal, ticket, true)
}

fn load_completed_journal<J: ReadSeek>(journal: &mut J, ticket: &JournalTicket) -> Result<Loaded> {
    load_journal_state(journal, ticket, false)
}

fn load_journal_state<J: ReadSeek>(
    journal: &mut J,
    ticket: &JournalTicket,
    require_zero_handoff: bool,
) -> Result<Loaded> {
    ensure!(ticket.schema_version == 1, "unsupported journal ticket");
    validate_binding(&ticket.binding)?;
    ensure!(
        ticket.journal_length <= MAX_JOURNAL_BYTES
            && ticket.immutable_length >= (HEADER_SIZE + FOOTER_SIZE) as u64
            && ticket.immutable_length.checked_add(BODY_START) == Some(ticket.journal_length),
        "invalid bounded journal length"
    );
    ensure!(
        journal.byte_len()? == ticket.journal_length,
        "journal length differs from trusted ticket"
    );
    let mut handoff = [0; GRANULE as usize];
    read_at(journal, 0, &mut handoff)?;
    if require_zero_handoff {
        ensure!(
            handoff.iter().all(|byte| *byte == 0),
            "handoff may have started; all reconstruction recovery is closed"
        );
    }
    ensure!(
        hash_range(journal, BODY_START, ticket.immutable_length)? == pin(&ticket.immutable_sha256)?,
        "immutable journal differs from trusted ticket"
    );
    let mut header = [0; HEADER_SIZE];
    read_at(journal, BODY_START, &mut header)?;
    ensure!(
        &header[..8] == b"N2RPREP1"
            && u32_at(&header, 8) == 1
            && header[20..24] == [0; 4]
            && header[72..96] == [0; 24]
            && header[96..] == digest(&header[..96]),
        "invalid prepared journal header"
    );
    let metadata_length = u32_at(&header, 12) as usize;
    let count = u32_at(&header, 16);
    let changed = u64_at(&header, 24);
    ensure!(
        metadata_length <= MAX_METADATA
            && count <= 65_536
            && changed <= MAX_CHANGE_BYTES
            && u64_at(&header, 32) == ticket.journal_length,
        "journal header exceeds bounds"
    );
    let mut metadata = vec![0; metadata_length];
    journal.read_exact(&mut metadata)?;
    ensure!(
        header[40..72] == digest(&metadata),
        "journal metadata digest differs"
    );
    let manifest: Manifest = serde_json::from_slice(&metadata)?;
    ensure!(
        manifest.schema_version == 1 && manifest.binding == ticket.binding,
        "journal storage binding differs"
    );
    validate_profile(&manifest.request)?;
    pin(&manifest.expected_postimage_sha256)?;
    ensure!(
        count <= manifest.request.max_ranges && changed <= manifest.request.max_change_bytes,
        "journal exceeds its requested limits"
    );
    let mut root = Sha256::new();
    root.update(header);
    root.update(&metadata);
    let mut chain: [u8; 32] = root.finalize().into();
    let mut records = Vec::new();
    let mut previous_end = 0;
    let mut payload_bytes = 0_u64;
    let mut retained_index = 0;
    for index in 0..count {
        let mut bytes = [0; RECORD_SIZE];
        journal.read_exact(&mut bytes)?;
        ensure!(
            &bytes[..8] == b"N2RREC01"
                && u64_at(&bytes, 8) == u64::from(index)
                && bytes[96..128] == chain
                && bytes[128..] == digest(&bytes[..128]),
            "journal record chain/index differs"
        );
        chain.copy_from_slice(&bytes[128..]);
        let offset = u64_at(&bytes, 16);
        let length = u64_at(&bytes, 24);
        let end = offset
            .checked_add(length)
            .context("journal range overflow")?;
        ensure!(
            length != 0
                && length.is_multiple_of(GRANULE)
                && offset.is_multiple_of(GRANULE)
                && offset >= previous_end
                && end <= manifest.request.expected_length,
            "journal range is invalid or overlaps"
        );
        while retained_index < manifest.request.retained_ranges.len()
            && manifest.request.retained_ranges[retained_index].offset
                + manifest.request.retained_ranges[retained_index].length
                <= offset
        {
            retained_index += 1;
        }
        ensure!(
            retained_index == manifest.request.retained_ranges.len()
                || manifest.request.retained_ranges[retained_index].offset >= end,
            "journal patch overlaps retained bytes"
        );
        previous_end = end;
        payload_bytes = payload_bytes
            .checked_add(length)
            .context("journal payload overflow")?;
        ensure!(
            payload_bytes <= changed,
            "journal payload exceeds declared budget"
        );
        let before_data = journal.stream_position()?;
        let after_data = before_data
            .checked_add(length)
            .context("journal position overflow")?;
        let next = after_data
            .checked_add(length)
            .context("journal position overflow")?;
        ensure!(
            next <= ticket.journal_length - FOOTER_SIZE as u64,
            "journal payload is truncated"
        );
        let before_hash: [u8; 32] = bytes[32..64].try_into().expect("fixed bounds");
        let after_hash: [u8; 32] = bytes[64..96].try_into().expect("fixed bounds");
        ensure!(
            hash_range(journal, before_data, length)? == before_hash
                && hash_range(journal, after_data, length)? == after_hash,
            "journal payload digest differs"
        );
        records.push(Record {
            offset,
            length,
            before_data,
            after_data,
            before_hash,
            after_hash,
        });
    }
    ensure!(payload_bytes == changed, "journal payload coverage differs");
    let footer_at = journal.stream_position()?;
    let mut footer = [0; FOOTER_SIZE];
    journal.read_exact(&mut footer)?;
    ensure!(
        &footer[..8] == b"N2REND01"
            && u64_at(&footer, 8) == u64::from(count)
            && u64_at(&footer, 16) == footer_at
            && footer[24..56] == chain
            && footer[56..88] == digest(&header)
            && footer[88..96] == [0; 8]
            && footer[96..] == digest(&footer[..96])
            && journal.stream_position()? == ticket.journal_length,
        "journal completion footer is absent or invalid"
    );
    Ok(Loaded { manifest, records })
}

/// Read-only validation for an adapter to inspect the exact immutable ranges.
/// The adapter separately establishes its observed storage binding and policy;
/// this function does not open a target, grant write permission or change state.
pub fn inspect_journal<J: ReadSeek>(
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<JournalDescriptor> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "observed storage binding differs from trusted ticket"
    );
    let loaded = load_journal(journal, ticket)?;
    Ok(JournalDescriptor {
        binding: loaded.manifest.binding,
        request: loaded.manifest.request,
        patches: loaded
            .records
            .iter()
            .map(|record| JournalPatchRange {
                offset: record.offset,
                length: record.length,
            })
            .collect(),
        changed_bytes: loaded.records.iter().map(|record| record.length).sum(),
        expected_postimage_sha256: loaded.manifest.expected_postimage_sha256,
        immutable_sha256: ticket.immutable_sha256.clone(),
    })
}

fn normalized_target<T: ReadSeek, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    loaded: &Loaded,
) -> Result<()> {
    let request = &loaded.manifest.request;
    ensure!(
        target.byte_len()? == request.expected_length,
        "target length differs from binding"
    );
    let mut current = vec![0; BUFFER];
    let mut before = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let mut normalized = Sha256::new();
    let mut offset = 0;
    let mut first_record = 0;
    while offset < request.expected_length {
        let count = usize::try_from((request.expected_length - offset).min(BUFFER as u64))?;
        read_at(target, offset, &mut current[..count])?;
        while first_record < loaded.records.len()
            && loaded.records[first_record].offset + loaded.records[first_record].length <= offset
        {
            first_record += 1;
        }
        for record in loaded.records[first_record..]
            .iter()
            .take_while(|record| record.offset < offset + count as u64)
        {
            let start = offset.max(record.offset);
            let end = (offset + count as u64).min(record.offset + record.length);
            let length = usize::try_from(end - start)?;
            let local = usize::try_from(start - offset)?;
            let within = start - record.offset;
            read_at(journal, record.before_data + within, &mut before[..length])?;
            read_at(journal, record.after_data + within, &mut after[..length])?;
            ensure!(
                current[local..local + length]
                    .iter()
                    .zip(&before[..length])
                    .zip(&after[..length])
                    .all(|((&value, &old), &new)| value == old || value == new),
                "target contains a foreign byte in a journaled range"
            );
            current[local..local + length].copy_from_slice(&before[..length]);
        }
        normalized.update(&current[..count]);
        offset += count as u64;
    }
    ensure!(
        hex::encode(normalized.finalize()) == request.source_sha256,
        "target retained or unmanaged bytes differ from source identity"
    );
    Ok(())
}

fn validate_recovery<T: ReadSeek, S: ReadSeek, J: DurableIo>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<Loaded> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "observed storage binding differs from trusted ticket"
    );
    let loaded = load_journal(journal, ticket)?;
    ensure!(
        shadow.byte_len()? == loaded.manifest.request.expected_length,
        "shadow length changed"
    );
    ensure!(
        retained_compare::hash_reader(shadow, loaded.manifest.request.expected_length)?
            == loaded.manifest.request.shadow_sha256,
        "shadow image changed"
    );
    normalized_target(target, journal, &loaded)?;
    Ok(loaded)
}

/// The old image is completely determined by the trusted journal and the
/// target's unpatched bytes. Rollback can therefore proceed when the shadow
/// disk is lost, provided no handoff has started and normalization proves the
/// entire target still belongs to the original source.
fn validate_recovery_without_shadow<T: ReadSeek, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<Loaded> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "observed storage binding differs from trusted ticket"
    );
    let loaded = load_journal(journal, ticket)?;
    normalized_target(target, journal, &loaded)?;
    Ok(loaded)
}

fn marker(
    magic: &[u8; 8],
    code: u8,
    ticket: &JournalTicket,
    target_hash: &str,
) -> Result<[u8; GRANULE as usize]> {
    let mut bytes = [0; GRANULE as usize];
    bytes[..8].copy_from_slice(magic);
    bytes[8] = code;
    bytes[16..48].copy_from_slice(&pin(&ticket.immutable_sha256)?);
    bytes[48..80].copy_from_slice(&pin(target_hash)?);
    let hash = digest(&bytes[..GRANULE as usize - 32]);
    bytes[GRANULE as usize - 32..].copy_from_slice(&hash);
    Ok(bytes)
}

/// Read-only proof for resuming an already durable final handoff after process
/// death. A partial or unknown marker is never repaired or interpreted as a
/// new write authorization.
pub fn verify_completed_marker<T: ReadSeek, S: ReadSeek, J: ReadSeek>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    kind: CompletionKind,
    expected_length: u64,
    expected_target_sha256: &str,
    expected_shadow_sha256: &str,
) -> Result<CompletedMarkerProof> {
    validate_binding(observed_binding)?;
    ensure!(
        ticket.schema_version == 1
            && ticket.binding == *observed_binding
            && ticket.immutable_length.checked_add(BODY_START) == Some(ticket.journal_length)
            && ticket.journal_length <= MAX_JOURNAL_BYTES
            && journal.byte_len()? == ticket.journal_length
            && target.byte_len()? == expected_length
            && shadow.byte_len()? == expected_length,
        "completed-marker ticket or storage length differs"
    );
    let loaded = load_completed_journal(journal, ticket)?;
    ensure!(
        loaded.manifest.request.expected_length == expected_length
            && loaded.manifest.request.shadow_sha256 == expected_shadow_sha256
            && expected_target_sha256
                == match kind {
                    CompletionKind::Refs => &loaded.manifest.expected_postimage_sha256,
                    CompletionKind::NtfsRollback => &loaded.manifest.request.source_sha256,
                },
        "completed-marker request differs from immutable journal"
    );
    let immutable = pin(&ticket.immutable_sha256)?;
    ensure!(
        loaded.manifest.binding == *observed_binding,
        "completed-marker journal binding changed"
    );
    let (magic, code) = match kind {
        CompletionKind::Refs => (b"N2RHND01", 3),
        CompletionKind::NtfsRollback => (b"N2RABT01", 4),
    };
    let expected_marker = marker(magic, code, ticket, expected_target_sha256)?;
    let mut observed = [0u8; GRANULE as usize];
    read_at(journal, 0, &mut observed)?;
    ensure!(
        observed == expected_marker,
        "completed handoff marker differs"
    );
    let target_sha256 = retained_compare::hash_reader(target, expected_length)?;
    let shadow_sha256 = retained_compare::hash_reader(shadow, expected_length)?;
    ensure!(
        target_sha256 == expected_target_sha256 && shadow_sha256 == expected_shadow_sha256,
        "completed-marker target or shadow bytes changed"
    );
    Ok(CompletedMarkerProof {
        kind,
        target_sha256,
        shadow_sha256: Some(shadow_sha256),
        marker_sha256: hex::encode(digest(&observed)),
        immutable_journal_sha256: hex::encode(immutable),
        marker_exact: true,
        target_exact: true,
        shadow_exact: true,
    })
}

/// Verify an already committed ReFS image whose retained source bytes make
/// its expected full-image hash different from the independent shadow. The
/// immutable journal supplies both exact expected hashes; no caller guesses
/// that the target equals the shadow.
pub fn verify_completed_refs_marker_from_journal<T: ReadSeek, S: ReadSeek, J: ReadSeek>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    expected_length: u64,
) -> Result<CompletedMarkerProof> {
    validate_binding(observed_binding)?;
    ensure!(
        ticket.binding == *observed_binding,
        "completed ReFS binding differs"
    );
    let loaded = load_completed_journal(journal, ticket)?;
    ensure!(
        loaded.manifest.request.expected_length == expected_length,
        "completed ReFS length differs from immutable journal"
    );
    verify_completed_marker(
        target,
        shadow,
        journal,
        ticket,
        observed_binding,
        CompletionKind::Refs,
        expected_length,
        &loaded.manifest.expected_postimage_sha256,
        &loaded.manifest.request.shadow_sha256,
    )
}

/// Prove a previously durable NTFS rollback marker after shadow loss. The
/// immutable journal is parsed in full and binds the expected source hash;
/// this path cannot verify or assert anything about the missing shadow.
pub fn verify_completed_rollback_marker_without_shadow<T: ReadSeek, J: ReadSeek>(
    target: &mut T,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    expected_length: u64,
    expected_source_sha256: &str,
) -> Result<CompletedMarkerProof> {
    validate_binding(observed_binding)?;
    ensure!(
        ticket.schema_version == 1
            && ticket.binding == *observed_binding
            && ticket.immutable_length.checked_add(BODY_START) == Some(ticket.journal_length)
            && ticket.journal_length <= MAX_JOURNAL_BYTES
            && journal.byte_len()? == ticket.journal_length
            && target.byte_len()? == expected_length,
        "shadowless rollback marker ticket or length differs"
    );
    let loaded = load_completed_journal(journal, ticket)?;
    ensure!(
        loaded.manifest.binding == *observed_binding
            && loaded.manifest.request.expected_length == expected_length
            && loaded.manifest.request.source_sha256 == expected_source_sha256,
        "shadowless rollback request differs from immutable journal"
    );
    let expected_marker = marker(b"N2RABT01", 4, ticket, expected_source_sha256)?;
    let mut observed = [0u8; GRANULE as usize];
    read_at(journal, 0, &mut observed)?;
    ensure!(
        observed == expected_marker,
        "completed NTFS rollback marker differs"
    );
    let target_sha256 = retained_compare::hash_reader(target, expected_length)?;
    ensure!(
        target_sha256 == expected_source_sha256,
        "completed NTFS rollback target differs"
    );
    Ok(CompletedMarkerProof {
        kind: CompletionKind::NtfsRollback,
        target_sha256,
        shadow_sha256: None,
        marker_sha256: hex::encode(digest(&observed)),
        immutable_journal_sha256: ticket.immutable_sha256.clone(),
        marker_exact: true,
        target_exact: true,
        shadow_exact: false,
    })
}

fn write_span<T: DurableIo, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    record: &Record,
    within: u64,
    length: u64,
    forward: bool,
) -> Result<u64> {
    if length == 0 {
        return Ok(0);
    }
    let capacity = usize::try_from(length.min(BUFFER as u64))?;
    let mut before = vec![0; capacity];
    let mut after = vec![0; capacity];
    let mut current = vec![0; capacity];
    let mut done = 0;
    while done < length {
        let count = usize::try_from((length - done).min(BUFFER as u64))?;
        let relative = within + done;
        let offset = record.offset + relative;
        read_at(journal, record.before_data + relative, &mut before[..count])?;
        read_at(journal, record.after_data + relative, &mut after[..count])?;
        read_at(target, offset, &mut current[..count])?;
        ensure!(
            current[..count]
                .iter()
                .zip(&before[..count])
                .zip(&after[..count])
                .all(|((&value, &old), &new)| value == old || value == new),
            "target changed before a journaled write"
        );
        let desired = if forward {
            &after[..count]
        } else {
            &before[..count]
        };
        target.seek(SeekFrom::Start(offset))?;
        // A short target write is an interruption, not permission to issue a
        // second possibly unaligned request. Recovery uses the durable preimage.
        ensure!(
            target.write(desired)? == count,
            "short target write; preserve journal and mount exclusion"
        );
        target.sync_all()?;
        read_at(target, offset, &mut current[..count])?;
        ensure!(
            &current[..count] == desired,
            "target write readback differs"
        );
        done += count as u64;
    }
    Ok(done)
}

fn execute<T: DurableIo, S: ReadSeek, J: DurableIo>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    forward: bool,
) -> Result<ExecutionReport> {
    let loaded = validate_recovery(target, shadow, journal, ticket, observed_binding)?;
    execute_loaded(target, journal, ticket, loaded, forward)
}

fn execute_loaded<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    ticket: &JournalTicket,
    loaded: Loaded,
    forward: bool,
) -> Result<ExecutionReport> {
    let expected = if forward {
        &loaded.manifest.expected_postimage_sha256
    } else {
        &loaded.manifest.request.source_sha256
    };
    let intent = marker(b"N2RINT01", if forward { 1 } else { 2 }, ticket, expected)?;
    journal.seek(SeekFrom::Start(GRANULE))?;
    journal.write_all(&intent)?;
    journal.sync_all()?;
    let mut intent_readback = [0; GRANULE as usize];
    read_at(journal, GRANULE, &mut intent_readback)?;
    ensure!(
        intent_readback == intent,
        "durable operation intent readback differs"
    );
    let mut written = 0;
    // Every non-discovery byte, including the tail of a coalesced range that
    // starts at zero, reaches a flush boundary before the first 4096 bytes.
    for record in &loaded.records {
        let skip = if record.offset == 0 { GRANULE } else { 0 };
        written += write_span(target, journal, record, skip, record.length - skip, forward)?;
    }
    target.sync_all()?;
    if let Some(discovery) = loaded.records.first().filter(|record| record.offset == 0) {
        written += write_span(target, journal, discovery, 0, GRANULE, forward)?;
    }
    target.sync_all()?;
    for record in &loaded.records {
        ensure!(
            hash_range(target, record.offset, record.length)?
                == if forward {
                    record.after_hash
                } else {
                    record.before_hash
                },
            "completed target range digest differs"
        );
    }
    ensure!(
        target.byte_len()? == loaded.manifest.request.expected_length,
        "target length changed during reconstruction"
    );
    let target_sha256 =
        retained_compare::hash_reader(target, loaded.manifest.request.expected_length)?;
    ensure!(
        target_sha256 == *expected,
        "complete target postimage differs"
    );
    ensure!(
        hash_range(journal, BODY_START, ticket.immutable_length)? == pin(&ticket.immutable_sha256)?,
        "journal changed during target writes"
    );
    Ok(ExecutionReport {
        operation: if forward {
            "applied-before-handoff"
        } else {
            "rolled-back-before-handoff"
        }
        .into(),
        target_sha256,
        target_bytes_written: written,
        patches_written: loaded.records.len() as u32,
        retained_bytes_unchanged: true,
        handoff_recorded: false,
        conversion_qualified: false,
    })
}

/// Apply or idempotently resume the complete pinned reconstruction. The caller
/// must keep the target excluded from native mounts through any error/restart.
pub fn apply<T: DurableIo, S: ReadSeek, J: DurableIo>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<ExecutionReport> {
    execute(target, shadow, journal, ticket, observed_binding, true)
}
pub fn resume<T: DurableIo, S: ReadSeek, J: DurableIo>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<ExecutionReport> {
    apply(target, shadow, journal, ticket, observed_binding)
}
pub fn rollback<T: DurableIo, S: ReadSeek, J: DurableIo>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<ExecutionReport> {
    execute(target, shadow, journal, ticket, observed_binding, false)
}

/// Restore the exact NTFS preimage even if the independent ReFS shadow has
/// been lost. This never permits resuming ReFS apply and never crosses a
/// nonzero handoff marker. The caller must keep the target excluded.
pub fn rollback_without_shadow<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<ExecutionReport> {
    let loaded = validate_recovery_without_shadow(target, journal, ticket, observed_binding)?;
    execute_loaded(target, journal, ticket, loaded, false)
}

/// Irreversibly close this core's recovery BEFORE any writable native mount.
/// A failed/partial marker is also a barrier; it must never be cleared here.
pub fn mark_handoff<T: DurableIo, S: ReadSeek, J: DurableIo>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<ExecutionReport> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "handoff storage binding differs"
    );
    let loaded = load_journal(journal, ticket)?;
    ensure!(
        target.byte_len()? == loaded.manifest.request.expected_length
            && shadow.byte_len()? == loaded.manifest.request.expected_length,
        "handoff data lengths changed"
    );
    ensure!(
        retained_compare::hash_reader(shadow, loaded.manifest.request.expected_length)?
            == loaded.manifest.request.shadow_sha256,
        "handoff shadow image changed"
    );
    // The complete expected-postimage check below is stronger than separately
    // normalizing its patches back to the source. Avoid that redundant full
    // target scan while retaining the pinned journal/shadow and flush barriers.
    target.sync_all()?;
    let target_sha256 =
        retained_compare::hash_reader(target, loaded.manifest.request.expected_length)?;
    ensure!(
        target_sha256 == loaded.manifest.expected_postimage_sha256,
        "handoff requires the complete expected postimage"
    );
    let handoff = marker(b"N2RHND01", 3, ticket, &target_sha256)?;
    journal.seek(SeekFrom::Start(0))?;
    journal.write_all(&handoff)?;
    journal.sync_all()?;
    let mut observed = [0; GRANULE as usize];
    read_at(journal, 0, &mut observed)?;
    ensure!(
        observed == handoff,
        "handoff marker readback differs; recovery remains closed"
    );
    Ok(ExecutionReport {
        operation: "handoff-recorded".into(),
        target_sha256,
        target_bytes_written: 0,
        patches_written: 0,
        retained_bytes_unchanged: true,
        handoff_recorded: true,
        conversion_qualified: false,
    })
}

/// Close the conversion journal before exposing a completely restored NTFS
/// preimage for ordinary writable service. Any partial marker also prevents
/// later replay; a separate completion path must inspect that state.
pub fn mark_rollback_complete<T: DurableIo, S: ReadSeek, J: DurableIo>(
    target: &mut T,
    shadow: &mut S,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<ExecutionReport> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "rollback completion storage binding differs"
    );
    let loaded = load_journal(journal, ticket)?;
    let length = loaded.manifest.request.expected_length;
    ensure!(
        target.byte_len()? == length && shadow.byte_len()? == length,
        "rollback completion data lengths changed"
    );
    ensure!(
        retained_compare::hash_reader(shadow, length)? == loaded.manifest.request.shadow_sha256,
        "rollback completion shadow image changed"
    );
    write_rollback_completion_marker(target, journal, ticket, loaded)
}

/// Close replay after a journal-only rollback. The complete restored NTFS
/// preimage, immutable journal and zero handoff sector are verified here;
/// the absent shadow is never inferred to have matched.
pub fn mark_rollback_complete_without_shadow<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<ExecutionReport> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "rollback completion storage binding differs"
    );
    let loaded = load_journal(journal, ticket)?;
    ensure!(
        target.byte_len()? == loaded.manifest.request.expected_length,
        "rollback completion target length changed"
    );
    write_rollback_completion_marker(target, journal, ticket, loaded)
}

fn write_rollback_completion_marker<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    ticket: &JournalTicket,
    loaded: Loaded,
) -> Result<ExecutionReport> {
    let length = loaded.manifest.request.expected_length;
    target.sync_all()?;
    let target_sha256 = retained_compare::hash_reader(target, length)?;
    ensure!(
        target_sha256 == loaded.manifest.request.source_sha256,
        "rollback completion requires the complete original NTFS image"
    );
    let complete = marker(b"N2RABT01", 4, ticket, &target_sha256)?;
    journal.seek(SeekFrom::Start(0))?;
    journal.write_all(&complete)?;
    journal.sync_all()?;
    let mut observed = [0; GRANULE as usize];
    read_at(journal, 0, &mut observed)?;
    ensure!(
        observed == complete,
        "rollback-complete marker readback differs; replay remains closed"
    );
    Ok(ExecutionReport {
        operation: "ntfs-rollback-complete".into(),
        target_sha256,
        target_bytes_written: 0,
        patches_written: 0,
        retained_bytes_unchanged: true,
        handoff_recorded: true,
        conversion_qualified: false,
    })
}
