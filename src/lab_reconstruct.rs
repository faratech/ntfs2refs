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
/// Reserve covers the bounded manifest, every permitted patch record and
/// fixed headers. Old and new payloads each consume the changed-byte count.
const JOURNAL_OVERHEAD_RESERVE: u64 = n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE;
#[cfg(test)]
pub(crate) const MAX_CHANGE_BYTES: u64 = n2r_win32::journal_file::MAX_CHANGED_BYTES;
#[cfg(test)]
const MAX_JOURNAL_BYTES: u64 = 768 * 1024 * 1024;
const BUFFER: usize = 1024 * 1024;

pub use n2r_win32::journal_file::JournalProfile;

/// Admission bound derived from independent journal capacity, not a promise
/// that a particular source fits. Preparation still enforces the exact size.
pub fn changed_byte_budget(max_journal_bytes: u64, image_bytes: u64) -> Result<u64> {
    changed_byte_budget_for_profile(JournalProfile::LegacyV1, max_journal_bytes, image_bytes)
}

/// Calculates a conservative changed-byte budget for an explicitly selected
/// core profile. It neither reserves storage nor authorizes native writes.
pub fn changed_byte_budget_for_profile(
    profile: JournalProfile,
    max_journal_bytes: u64,
    image_bytes: u64,
) -> Result<u64> {
    ensure!(
        max_journal_bytes <= profile.max_journal_bytes(),
        "journal budget exceeds supported ceiling"
    );
    ensure!(
        (GRANULE..=retained_compare::MAX_IMAGE_BYTES).contains(&image_bytes)
            && image_bytes.is_multiple_of(GRANULE),
        "comparison image size is unsupported"
    );
    let payload_capacity = max_journal_bytes
        .checked_sub(JOURNAL_OVERHEAD_RESERVE)
        .context("journal budget cannot reserve metadata overhead")?
        / 2;
    let budget = (payload_capacity
        .min(profile.max_changed_bytes())
        .min(image_bytes)
        / GRANULE)
        * GRANULE;
    ensure!(
        budget >= GRANULE,
        "journal budget cannot cover one changed granule and its recovery payload"
    );
    Ok(budget)
}

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
impl ReadSeek for n2r_win32::GeneralJournalReadView {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(n2r_win32::GeneralJournalReadView::byte_len(self))
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
    /// Omitted for historical alpha/v2-journal-only artifacts. A selected
    /// source/tree profile is pinned inside the immutable manifest and ticket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_resource_profile: Option<crate::ntfs_admission::ResourceProfile>,
}

/// Source-resource admission and journal sizing are distinct profiles. Only
/// the large source profile is serializable here; absent means the legacy
/// alpha profile and preserves old request/ticket bytes exactly.
pub fn validate_source_profile_binding(
    journal_schema: u32,
    source: Option<crate::ntfs_admission::ResourceProfile>,
) -> Result<()> {
    let journal = JournalProfile::from_schema(journal_schema)?;
    ensure!(
        source.is_none()
            || matches!(
                (journal, source),
                (
                    JournalProfile::ExperimentalLargeV2,
                    Some(
                        crate::ntfs_admission::ResourceProfile::ExperimentalLargeTreeV1
                            | crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2
                    )
                )
            ),
        "source resource profile requires the explicit v2 journal profile"
    );
    Ok(())
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

/// Readable marker/image consistency only. This does not establish journal
/// durability or authorize a writable native mount.
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

/// The journal and its irreversible handoff marker were validated. This
/// receipt says nothing about a currently mounted target or shadow image and
/// can never be passed to the raw replay/rollback APIs as write authority.
#[derive(Debug, Serialize)]
pub struct RefsHandoffReceipt {
    scope: &'static str,
    binding: JournalBinding,
    comparison: RetainedCompareRequest,
    expected_postimage_sha256: String,
    immutable_journal_sha256: String,
    marker_sha256: String,
}
impl RefsHandoffReceipt {
    pub fn binding(&self) -> &JournalBinding {
        &self.binding
    }
    pub fn comparison(&self) -> &RetainedCompareRequest {
        &self.comparison
    }
    pub fn expected_length(&self) -> u64 {
        self.comparison.expected_length
    }
    pub fn expected_postimage_sha256(&self) -> &str {
        &self.expected_postimage_sha256
    }
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

/// Preserve the exact SHA-256 contract while using Windows' optimized backend
/// for the explicitly selected streaming profile. Legacy profiles keep their
/// previous implementation; provider/read errors never become a partial hash.
#[cfg(windows)]
pub(crate) fn hash_range_with_resource_profile<R: Read + Seek>(
    io: &mut R,
    at: u64,
    length: u64,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<[u8; 32]> {
    if resources == crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2 {
        return Ok(n2r_win32::sha256_native::hash_range(io, at, length)?);
    }
    hash_range(io, at, length)
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

fn native_full_image_digest(binding: &JournalBinding) -> bool {
    cfg!(windows)
        && binding.source_resource_profile
            == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2)
}

/// Select only the complete-image digest backend after the caller's existing
/// ticket/binding checks. Patch, record, metadata and journal hashes stay separate.
fn hash_full_image<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    binding: &JournalBinding,
) -> Result<String> {
    validate_binding(binding)?;
    retained_compare::hash_reader_with_backend(reader, length, native_full_image_digest(binding))
}

fn validate_profile(request: &RetainedCompareRequest, profile: JournalProfile) -> Result<()> {
    retained_compare::validate_request(request)?;
    ensure!(
        request.sector_size == GRANULE as u32,
        "reconstruction requires 4096-byte granules"
    );
    ensure!(
        request.max_change_bytes <= profile.max_changed_bytes(),
        "reconstruction changed-byte cap exceeds supported journal capacity"
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
    prepare_journal_with_progress(
        source,
        shadow,
        journal,
        request,
        binding,
        max_journal_bytes,
        &mut |_| {},
    )
}

/// Same preparation protocol with rate-limited diagnostic observations. The
/// callback receives only counters, not storage handles, and grants no authority.
pub fn prepare_journal_with_progress<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    shadow: &mut S,
    journal: &mut J,
    request: &RetainedCompareRequest,
    binding: &JournalBinding,
    max_journal_bytes: u64,
    progress: &mut dyn FnMut(crate::preparation_progress::Progress),
) -> Result<JournalSummary> {
    prepare_journal_with_profile_and_progress(
        source,
        shadow,
        journal,
        request,
        binding,
        max_journal_bytes,
        JournalProfile::LegacyV1,
        progress,
    )
}

/// Explicit experimental journal construction over caller-owned streams.
/// This does not provide native-device write authority or widen production
/// conversion's legacy profile. The resulting ticket records the profile.
pub fn prepare_journal_with_profile<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    shadow: &mut S,
    journal: &mut J,
    request: &RetainedCompareRequest,
    binding: &JournalBinding,
    max_journal_bytes: u64,
    profile: JournalProfile,
) -> Result<JournalSummary> {
    prepare_journal_with_profile_and_progress(
        source,
        shadow,
        journal,
        request,
        binding,
        max_journal_bytes,
        profile,
        &mut |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_journal_with_profile_and_progress<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    shadow: &mut S,
    journal: &mut J,
    request: &RetainedCompareRequest,
    binding: &JournalBinding,
    max_journal_bytes: u64,
    profile: JournalProfile,
    progress: &mut dyn FnMut(crate::preparation_progress::Progress),
) -> Result<JournalSummary> {
    use crate::preparation_progress::{Reporter, Subphase};
    let mut progress = Reporter::new(request.expected_length, progress);
    validate_profile(request, profile)?;
    validate_binding(binding)?;
    validate_source_profile_binding(profile.version(), binding.source_resource_profile)?;
    ensure!(
        max_journal_bytes <= profile.max_journal_bytes(),
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
    let comparison = retained_compare::compare_streams_observed_with_resource_profile(
        source,
        shadow,
        request,
        &mut progress,
        binding.source_resource_profile.unwrap_or_default(),
    )?;
    ensure!(
        source.byte_len()? == request.expected_length
            && shadow.byte_len()? == request.expected_length,
        "input length changed during preparation"
    );
    let manifest = Manifest {
        schema_version: profile.version(),
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
    put32(&mut header, 8, profile.version());
    put32(&mut header, 12, metadata.len() as u32);
    put32(&mut header, 16, count);
    put64(&mut header, 24, comparison.patch_bytes);
    put64(&mut header, 32, journal_length);
    header[40..72].copy_from_slice(&digest(&metadata));
    let hash = digest(&header[..96]);
    header[96..].copy_from_slice(&hash);
    progress.update(Subphase::WritingJournal, 0);
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
    progress.update(Subphase::VerifyingJournal, 0);
    let ticket = JournalTicket {
        schema_version: profile.version(),
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
    progress.update(Subphase::Complete, 0);
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
    let profile = JournalProfile::from_schema(ticket.schema_version)?;
    validate_binding(&ticket.binding)?;
    validate_source_profile_binding(
        ticket.schema_version,
        ticket.binding.source_resource_profile,
    )?;
    ensure!(
        ticket.journal_length <= profile.max_journal_bytes()
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
            && u32_at(&header, 8) == profile.version()
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
            && changed <= profile.max_changed_bytes()
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
        manifest.schema_version == profile.version() && manifest.binding == ticket.binding,
        "journal storage binding differs"
    );
    validate_profile(&manifest.request, profile)?;
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

/// Read only the complete immutable journal across any marker state. This
/// deliberately does not validate/repair mutable lifecycle sectors or assert
/// anything about current target/shadow bytes. Status callers must validate
/// the exact marker separately; raw recovery still uses `load_journal`.
pub fn inspect_completed_journal<J: ReadSeek>(
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<JournalDescriptor> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "completed inspection binding differs from trusted ticket"
    );
    let loaded = load_completed_journal(journal, ticket)?;
    ensure!(
        loaded.manifest.binding == *observed_binding,
        "completed immutable binding differs"
    );
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

/// Runtime observation only, never deserialized into replay or mount authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JournalLifecycle {
    PreparedClear,
    ApplyIntent,
    RollbackIntent,
    RefsHandoff,
    NtfsRollback,
}

/// Check the entire immutable journal, exact plan and both lifecycle sectors.
/// The caller keeps this same exclusive handle through typed execution.
pub(crate) fn inspect_journal_lifecycle<J: ReadSeek>(
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    expected_request: &RetainedCompareRequest,
) -> Result<(JournalLifecycle, JournalDescriptor)> {
    let descriptor = inspect_completed_journal(journal, ticket, observed_binding)?;
    ensure!(
        serde_json::to_vec(&descriptor.request)? == serde_json::to_vec(expected_request)?,
        "journal lifecycle immutable request differs from the pinned plan"
    );
    let mut prefix = [0u8; BODY_START as usize];
    read_at(journal, 0, &mut prefix)?;
    let (handoff, intent) = prefix.split_at(GRANULE as usize);
    let zero = [0u8; GRANULE as usize];
    let refs = marker(
        b"N2RHND01",
        3,
        ticket,
        &descriptor.expected_postimage_sha256,
    )?;
    let rollback = marker(b"N2RABT01", 4, ticket, &descriptor.request.source_sha256)?;
    let apply = marker(
        b"N2RINT01",
        1,
        ticket,
        &descriptor.expected_postimage_sha256,
    )?;
    let undo = marker(b"N2RINT01", 2, ticket, &descriptor.request.source_sha256)?;
    let state = if handoff == zero && intent == zero {
        JournalLifecycle::PreparedClear
    } else if handoff == zero && intent == apply {
        JournalLifecycle::ApplyIntent
    } else if handoff == zero && intent == undo {
        JournalLifecycle::RollbackIntent
    } else if handoff == refs && (intent == zero || intent == apply) {
        JournalLifecycle::RefsHandoff
    } else if handoff == rollback && (intent == zero || intent == undo) {
        JournalLifecycle::NtfsRollback
    } else {
        anyhow::bail!("partial, foreign or contradictory journal lifecycle sectors")
    };
    Ok((state, descriptor))
}

fn normalized_target<T: ReadSeek, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    loaded: &Loaded,
) -> Result<()> {
    normalized_target_observed(target, journal, loaded, &mut |_| Ok(()))
}

fn normalized_target_observed<T: ReadSeek, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    loaded: &Loaded,
    on_chunk: &mut dyn FnMut(usize) -> Result<()>,
) -> Result<()> {
    let request = &loaded.manifest.request;
    ensure!(
        target.byte_len()? == request.expected_length,
        "target length differs from binding"
    );
    let mut current = vec![0; BUFFER];
    let mut before = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let native = native_full_image_digest(&loaded.manifest.binding);
    let mut normalized = retained_compare::stream_digest::StreamDigest::new(native)?;
    let mut offset = 0;
    let mut first_record = 0;
    while offset < request.expected_length {
        let count = usize::try_from((request.expected_length - offset).min(BUFFER as u64))?;
        read_at(target, offset, &mut current[..count])?;
        on_chunk(count)?;
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
        normalized.update(&current[..count])?;
        offset += count as u64;
    }
    ensure!(
        hex::encode(normalized.finish()?) == request.source_sha256,
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
    if loaded.manifest.binding.source_resource_profile
        == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2)
        && std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 2)
    {
        // Both complete images remain mandatory. Only digest work overlaps:
        // every device/journal read stays on the owning thread, and neither
        // result can authorize patches until the two full checks have passed.
        shadow.seek(SeekFrom::Start(0))?;
        let mut buffer = vec![0; BUFFER];
        let mut digest = retained_compare::digest_pipeline::Pipeline::with_native_backend(
            BUFFER,
            native_full_image_digest(&loaded.manifest.binding),
        )?;
        normalized_target_observed(target, journal, &loaded, &mut |count| {
            shadow.read_exact(&mut buffer[..count])?;
            digest.update(&buffer[..count])
        })?;
        ensure!(
            hex::encode(digest.finish()?) == loaded.manifest.request.shadow_sha256,
            "shadow image changed"
        );
        return Ok(loaded);
    }
    ensure!(
        hash_full_image(
            shadow,
            loaded.manifest.request.expected_length,
            &loaded.manifest.binding,
        )? == loaded.manifest.request.shadow_sha256,
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

/// Validate only a trusted completed journal and its exact ReFS handoff
/// marker. Post-mount completion must separately verify the original device,
/// mounted ReFS filesystem and complete native tree. No target/shadow handle
/// is accepted here, and no current-image hash assertion is manufactured.
pub fn verify_refs_handoff_receipt<J: ReadSeek>(
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
) -> Result<RefsHandoffReceipt> {
    validate_binding(observed_binding)?;
    ensure!(
        ticket.binding == *observed_binding,
        "handoff receipt storage binding differs from trusted ticket"
    );
    let loaded = load_completed_journal(journal, ticket)?;
    ensure!(
        loaded.manifest.binding == *observed_binding,
        "handoff receipt immutable binding differs"
    );
    let expected = marker(
        b"N2RHND01",
        3,
        ticket,
        &loaded.manifest.expected_postimage_sha256,
    )?;
    let mut observed = [0; GRANULE as usize];
    read_at(journal, 0, &mut observed)?;
    ensure!(
        observed == expected,
        "handoff receipt requires the exact completed ReFS marker"
    );
    Ok(RefsHandoffReceipt {
        scope: "journal_marker_only",
        binding: loaded.manifest.binding,
        comparison: loaded.manifest.request,
        expected_postimage_sha256: loaded.manifest.expected_postimage_sha256,
        immutable_journal_sha256: ticket.immutable_sha256.clone(),
        marker_sha256: hex::encode(digest(&observed)),
    })
}

#[cfg(test)]
mod handoff_receipt_tests {
    use super::*;
    #[derive(Clone)]
    struct Memory(std::io::Cursor<Vec<u8>>);
    impl Read for Memory {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.0.read(b)
        }
    }
    impl Seek for Memory {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.0.seek(p)
        }
    }
    impl Write for Memory {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ReadSeek for Memory {
        fn byte_len(&mut self) -> io::Result<u64> {
            Ok(self.0.get_ref().len() as u64)
        }
    }
    impl DurableIo for Memory {
        fn sync_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct ReadOnlyJournal<'a>(std::io::Cursor<&'a [u8]>);
    impl Read for ReadOnlyJournal<'_> {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.0.read(b)
        }
    }
    impl Seek for ReadOnlyJournal<'_> {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.0.seek(p)
        }
    }
    impl ReadSeek for ReadOnlyJournal<'_> {
        fn byte_len(&mut self) -> io::Result<u64> {
            Ok(self.0.get_ref().len() as u64)
        }
    }
    fn binding() -> JournalBinding {
        JournalBinding {
            experiment_id: "a".repeat(32),
            source_resource_profile: None,
            target_identity_sha256: "1".repeat(64),
            shadow_identity_sha256: "2".repeat(64),
            journal_identity_sha256: "3".repeat(64),
        }
    }
    fn hash(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    struct ProgressJournal {
        memory: Memory,
        events: Vec<String>,
        fail: Option<&'static str>,
    }
    impl Read for ProgressJournal {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.events.push(format!("read {}", bytes.len()));
            if self.fail == Some("read") {
                return Err(io::Error::other("injected journal read"));
            }
            self.memory.read(bytes)
        }
    }
    impl Seek for ProgressJournal {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.events.push(format!("seek {position:?}"));
            self.memory.seek(position)
        }
    }
    impl Write for ProgressJournal {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.events.push(format!("write {}", bytes.len()));
            if self.fail == Some("write") {
                return Err(io::Error::other("injected journal write"));
            }
            self.memory.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.memory.flush()
        }
    }
    impl ReadSeek for ProgressJournal {
        fn byte_len(&mut self) -> io::Result<u64> {
            self.memory.byte_len()
        }
    }
    impl DurableIo for ProgressJournal {
        fn sync_all(&mut self) -> io::Result<()> {
            self.events.push("sync_all".into());
            if self.fail == Some("sync") {
                return Err(io::Error::other("injected journal sync"));
            }
            self.memory.sync_all()
        }
    }

    fn progress_fixture() -> (Vec<u8>, Vec<u8>, RetainedCompareRequest) {
        let before = vec![0x31; 16384];
        let mut after = before.clone();
        after[..4096].fill(0x72);
        after[8192..12288].fill(0x73);
        let request = RetainedCompareRequest {
            schema_version: 2,
            sector_size: 4096,
            expected_length: 16384,
            source_sha256: hash(&before),
            shadow_sha256: hash(&after),
            retained_ranges: vec![crate::retained_compare::RetainedRangeRequest {
                offset: 4096,
                length: 4096,
                source_sha256: hash(&before[4096..8192]),
                shadow_sha256: hash(&after[4096..8192]),
            }],
            max_change_bytes: 8192,
            max_ranges: 2,
        };
        (before, after, request)
    }

    #[test]
    fn progress_preserves_journal_bytes_ticket_summary_and_durability_order() {
        use crate::preparation_progress::Subphase;
        let (before, after, request) = progress_fixture();
        // Generated independently from exact ceef114 source blobs, before the
        // observer change. These are memory-backend byte compatibility pins.
        let comparison = crate::retained_compare::compare_streams(
            &mut io::Cursor::new(before.clone()),
            &mut io::Cursor::new(after.clone()),
            &request,
        )
        .unwrap();
        assert_eq!(
            hash(&serde_json::to_vec(&comparison).unwrap()),
            "62527aaa882d4ae8de63bf6ad4e895be0e0018d0df6b856341bd92270c0c25fb"
        );
        let run = |observe| {
            let mut source = Memory(io::Cursor::new(before.clone()));
            let mut shadow = Memory(io::Cursor::new(after.clone()));
            let mut journal = ProgressJournal {
                memory: Memory(io::Cursor::new(vec![])),
                events: vec![],
                fail: None,
            };
            let mut progress = Vec::new();
            let summary = if observe {
                prepare_journal_with_progress(
                    &mut source,
                    &mut shadow,
                    &mut journal,
                    &request,
                    &binding(),
                    1024 * 1024,
                    &mut |p| progress.push(p),
                )
                .unwrap()
            } else {
                prepare_journal(
                    &mut source,
                    &mut shadow,
                    &mut journal,
                    &request,
                    &binding(),
                    1024 * 1024,
                )
                .unwrap()
            };
            (serde_json::to_value(summary).unwrap(), journal, progress)
        };
        let (baseline, old_journal, _) = run(false);
        let (observed, journal, progress) = run(true);
        assert_eq!(baseline, observed);
        assert_eq!(old_journal.memory.0.get_ref(), journal.memory.0.get_ref());
        assert_eq!(journal.memory.0.get_ref().len(), 26102);
        assert_eq!(
            hash(journal.memory.0.get_ref()),
            "25bc934cbfb11719fad3ae9c8434b115f048b6253b00d5a2f6f4ea86ef7578af"
        );
        assert_eq!(
            observed["ticket"]["immutable_sha256"],
            "138a579099c2c98d91d456421c88bd82127c48a4485be0c774c7269e0d627368"
        );
        assert_eq!(old_journal.events, journal.events);
        assert_eq!(
            journal
                .events
                .iter()
                .filter(|e| e.as_str() == "sync_all")
                .count(),
            1
        );
        assert_eq!(
            progress.iter().map(|p| p.subphase).collect::<Vec<_>>(),
            vec![
                Subphase::Comparing,
                Subphase::Comparing,
                Subphase::RecheckingSource,
                Subphase::RecheckingSource,
                Subphase::RecheckingShadow,
                Subphase::RecheckingShadow,
                Subphase::WritingJournal,
                Subphase::VerifyingJournal,
                Subphase::Complete,
            ]
        );
        assert!(
            progress
                .iter()
                .all(|p| !p.execution_authorized && p.total_scan_bytes == 65536)
        );
        assert_eq!(progress.last().unwrap().bytes_scanned, 65536);
    }

    #[test]
    fn journal_failures_and_bad_pins_propagate_without_false_completion() {
        use crate::preparation_progress::Subphase;
        let (before, after, original) = progress_fixture();
        for failure in ["write", "sync", "read", "source-pin", "retained-pin"] {
            let mut request = original.clone();
            if failure == "source-pin" {
                request.source_sha256 = "0".repeat(64);
            }
            if failure == "retained-pin" {
                request.retained_ranges[0].source_sha256 = "0".repeat(64);
            }
            let mut source = Memory(io::Cursor::new(before.clone()));
            let mut shadow = Memory(io::Cursor::new(after.clone()));
            let mut journal = ProgressJournal {
                memory: Memory(io::Cursor::new(vec![])),
                events: vec![],
                fail: Some(failure),
            };
            let mut progress = Vec::new();
            let error = prepare_journal_with_progress(
                &mut source,
                &mut shadow,
                &mut journal,
                &request,
                &binding(),
                1024 * 1024,
                &mut |p| progress.push(p),
            )
            .unwrap_err();
            assert!(
                !progress.iter().any(|p| p.subphase == Subphase::Complete),
                "{failure}"
            );
            if failure.ends_with("pin") {
                assert!(journal.memory.0.get_ref().is_empty(), "{failure}");
                assert!(error.to_string().contains("SHA-256 pin"), "{error:#}");
            } else {
                assert!(
                    error
                        .to_string()
                        .contains(&format!("injected journal {failure}")),
                    "{error:#}"
                );
            }
        }
    }

    #[test]
    fn unavailable_progress_file_does_not_change_journal_preparation() {
        let (before, after, request) = progress_fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("already-exists");
        std::fs::write(&path, b"keep").unwrap();
        let mut sidecar = crate::preparation_progress::SnapshotFile::create(&path);
        let mut source = Memory(io::Cursor::new(before));
        let mut shadow = Memory(io::Cursor::new(after));
        let mut journal = Memory(io::Cursor::new(vec![]));
        let summary = prepare_journal_with_progress(
            &mut source,
            &mut shadow,
            &mut journal,
            &request,
            &binding(),
            1024 * 1024,
            &mut |p| sidecar.report(p),
        )
        .unwrap();
        assert!(summary.preparation_durable);
        assert_eq!(std::fs::read(path).unwrap(), b"keep");
    }
    fn completed() -> (
        Memory,
        Memory,
        Memory,
        JournalTicket,
        RetainedCompareRequest,
    ) {
        let before = vec![0x31; 16384];
        let mut after = before.clone();
        after[..4096].fill(0x72);
        after[8192..12288].fill(0x73);
        let request = RetainedCompareRequest {
            schema_version: 2,
            sector_size: 4096,
            expected_length: 16384,
            source_sha256: hash(&before),
            shadow_sha256: hash(&after),
            retained_ranges: vec![],
            max_change_bytes: 8192,
            max_ranges: 2,
        };
        let mut source = Memory(std::io::Cursor::new(before.clone()));
        let mut target = Memory(std::io::Cursor::new(before));
        let mut shadow = Memory(std::io::Cursor::new(after));
        let mut journal = Memory(std::io::Cursor::new(vec![]));
        let prepared = prepare_journal(
            &mut source,
            &mut shadow,
            &mut journal,
            &request,
            &binding(),
            1024 * 1024,
        )
        .unwrap();
        apply(
            &mut target,
            &mut shadow,
            &mut journal,
            &prepared.ticket,
            &binding(),
        )
        .unwrap();
        mark_handoff(
            &mut target,
            &mut shadow,
            &mut journal,
            &prepared.ticket,
            &binding(),
        )
        .unwrap();
        (target, shadow, journal, prepared.ticket, request)
    }
    #[test]
    fn receipt_needs_only_readonly_journal_and_never_asserts_current_images() {
        let (mut target, mut shadow, mut journal, ticket, request) = completed();
        target.0.get_mut()[12288] ^= 1;
        shadow.0.get_mut()[4096] ^= 1;
        let bytes = journal.0.get_ref().clone();
        let mut readonly = ReadOnlyJournal(std::io::Cursor::new(bytes.as_slice()));
        let receipt = verify_refs_handoff_receipt(&mut readonly, &ticket, &binding()).unwrap();
        assert_eq!(receipt.expected_length(), request.expected_length);
        assert_eq!(receipt.expected_postimage_sha256(), request.shadow_sha256);
        assert_eq!(receipt.binding(), &binding());
        let descriptor = inspect_completed_journal(&mut readonly, &ticket, &binding()).unwrap();
        assert_eq!(descriptor.expected_postimage_sha256, request.shadow_sha256);
        assert!(inspect_journal(&mut readonly, &ticket, &binding()).is_err());
        assert_eq!(
            serde_json::to_vec(receipt.comparison()).unwrap(),
            serde_json::to_vec(&request).unwrap()
        );
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["scope"], "journal_marker_only");
        for field in [
            "target_exact",
            "shadow_exact",
            "current_target_sha256",
            "execution_authorized",
        ] {
            assert!(value.get(field).is_none());
        }
        assert_eq!(journal.0.get_ref(), &bytes);
        assert!(
            verify_completed_refs_marker_from_journal(
                &mut target,
                &mut shadow,
                &mut journal,
                &ticket,
                &binding(),
                16384
            )
            .is_err()
        );
        let original = target.0.get_ref().clone();
        assert!(rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding()).is_err());
        assert_eq!(target.0.get_ref(), &original);
    }
    #[test]
    fn receipt_rejects_zero_partial_foreign_rollback_and_retargeted_markers() {
        let (_, _, journal, ticket, request) = completed();
        let original = journal.0.get_ref().clone();
        let mut invalid = vec![[0; GRANULE as usize]];
        let mut partial = [0; GRANULE as usize];
        partial[..8].copy_from_slice(b"N2RHND01");
        invalid.push(partial);
        let mut corrupt: [u8; GRANULE as usize] = original[..GRANULE as usize].try_into().unwrap();
        corrupt[12] ^= 1;
        invalid.push(corrupt);
        invalid.push(marker(b"N2RABT01", 4, &ticket, &request.source_sha256).unwrap());
        invalid.push(marker(b"N2RHND01", 3, &ticket, &"0".repeat(64)).unwrap());
        let mut foreign = ticket.clone();
        foreign.immutable_sha256 = "f".repeat(64);
        invalid.push(marker(b"N2RHND01", 3, &foreign, &request.shadow_sha256).unwrap());
        for bytes in invalid {
            let mut changed = journal.clone();
            changed.0.get_mut()[..GRANULE as usize].copy_from_slice(&bytes);
            let before = changed.0.get_ref().clone();
            assert!(verify_refs_handoff_receipt(&mut changed, &ticket, &binding()).is_err());
            assert_eq!(changed.0.get_ref(), &before);
        }
    }
    #[test]
    fn receipt_validates_trusted_binding_complete_body_and_deep_record_digests() {
        let (_, _, journal, ticket, request) = completed();
        let mut foreign = binding();
        foreign.journal_identity_sha256 = "4".repeat(64);
        assert!(verify_refs_handoff_receipt(&mut journal.clone(), &ticket, &foreign).is_err());
        let mut wrong_ticket = ticket.clone();
        wrong_ticket.immutable_sha256 = "0".repeat(64);
        assert!(
            verify_refs_handoff_receipt(&mut journal.clone(), &wrong_ticket, &binding()).is_err()
        );
        let mut truncated = journal.clone();
        truncated.0.get_mut().pop();
        assert!(verify_refs_handoff_receipt(&mut truncated, &ticket, &binding()).is_err());
        let mut changed = journal.clone();
        let header = BODY_START as usize;
        let metadata_length = u32_at(changed.0.get_ref(), header + 12) as usize;
        let payload = header + HEADER_SIZE + metadata_length + RECORD_SIZE;
        changed.0.get_mut()[payload] ^= 1;
        assert!(verify_refs_handoff_receipt(&mut changed.clone(), &ticket, &binding()).is_err());
        // Even a newly pinned outer digest and matching HND marker cannot
        // excuse an inconsistent per-record payload inside the full journal.
        let mut repinned = ticket.clone();
        repinned.immutable_sha256 = hash(&changed.0.get_ref()[BODY_START as usize..]);
        let matching = marker(b"N2RHND01", 3, &repinned, &request.shadow_sha256).unwrap();
        changed.0.get_mut()[..GRANULE as usize].copy_from_slice(&matching);
        let error = verify_refs_handoff_receipt(&mut changed, &repinned, &binding()).unwrap_err();
        assert!(
            error.to_string().contains("journal payload digest differs"),
            "{error:#}"
        );
    }
}

/// Read-only consistency proof after process death. It does not prove the
/// readable marker reached stable storage. A partial or unknown marker is
/// never repaired or interpreted as a new write authorization.
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
    let profile = JournalProfile::from_schema(ticket.schema_version)?;
    ensure!(
        ticket.binding == *observed_binding
            && ticket.immutable_length.checked_add(BODY_START) == Some(ticket.journal_length)
            && ticket.journal_length <= profile.max_journal_bytes()
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
    let target_sha256 = hash_full_image(target, expected_length, &loaded.manifest.binding)?;
    let shadow_sha256 = hash_full_image(shadow, expected_length, &loaded.manifest.binding)?;
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

/// Inspect an exact readable NTFS rollback marker after shadow loss. The
/// immutable journal is parsed in full and binds the expected source hash;
/// this proves neither journal durability nor anything about the missing shadow.
pub fn verify_completed_rollback_marker_without_shadow<T: ReadSeek, J: ReadSeek>(
    target: &mut T,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    expected_length: u64,
    expected_source_sha256: &str,
) -> Result<CompletedMarkerProof> {
    validate_binding(observed_binding)?;
    let profile = JournalProfile::from_schema(ticket.schema_version)?;
    ensure!(
        ticket.binding == *observed_binding
            && ticket.immutable_length.checked_add(BODY_START) == Some(ticket.journal_length)
            && ticket.journal_length <= profile.max_journal_bytes()
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
    let target_sha256 = hash_full_image(target, expected_length, &loaded.manifest.binding)?;
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

/// A journal-only pre-mount barrier. The caller must retain all existing target,
/// required-shadow and native isolation checks. This cannot be serialized or
/// issued by read-only completed-marker inspection. The mutable journal lease
/// remains borrowed through the mount callback.
pub struct DurableCompletedMarker<'a, J: DurableIo> {
    journal: &'a mut J,
}

impl<J: DurableIo> DurableCompletedMarker<'_, J> {
    /// Invoke the caller's synchronous mount transition after this journal
    /// barrier. This is not general authority for deferred or spawned work.
    pub fn with_mount<R>(self, mount: impl FnOnce() -> R) -> R {
        let result = mount();
        let _held_journal = self.journal;
        result
    }
}

fn recheck_completed_journal<J: ReadSeek>(
    journal: &mut J,
    ticket: &JournalTicket,
    binding: &JournalBinding,
    proof: &CompletedMarkerProof,
) -> Result<()> {
    validate_binding(binding)?;
    ensure!(
        ticket.binding == *binding,
        "completed durability storage binding differs"
    );
    let loaded = load_completed_journal(journal, ticket)?;
    ensure!(
        loaded.manifest.binding == *binding,
        "completed durability immutable binding differs"
    );
    let (magic, code, expected_target) = match proof.kind {
        CompletionKind::Refs => (b"N2RHND01", 3, &loaded.manifest.expected_postimage_sha256),
        CompletionKind::NtfsRollback => (b"N2RABT01", 4, &loaded.manifest.request.source_sha256),
    };
    let expected = marker(magic, code, ticket, expected_target)?;
    ensure!(
        proof.marker_exact
            && proof.target_exact
            && proof.target_sha256 == *expected_target
            && proof.immutable_journal_sha256 == ticket.immutable_sha256
            && proof.marker_sha256 == hex::encode(digest(&expected)),
        "completed durability proof differs from immutable journal"
    );
    match &proof.shadow_sha256 {
        Some(hash) => ensure!(
            proof.shadow_exact && hash == &loaded.manifest.request.shadow_sha256,
            "completed durability shadow proof differs"
        ),
        None => ensure!(
            matches!(proof.kind, CompletionKind::NtfsRollback) && !proof.shadow_exact,
            "completed durability requires the original shadow proof"
        ),
    }
    let mut observed = [0; GRANULE as usize];
    read_at(journal, 0, &mut observed)?;
    ensure!(observed == expected, "completed durability marker differs");
    Ok(())
}

/// Establish a fresh journal durability barrier before an after-marker mount.
/// The same exclusively held, identity-bound handle must be supplied to both
/// observations. Unknown/partial/foreign markers are refused before sync; no
/// marker, intent or payload is written or repaired. A sync/recheck failure
/// returns no gate and must leave the target excluded.
///
/// This revalidates the bounded journal twice, without adding target/shadow
/// image scans. Successful sync is the DurableIo contract, not hardware proof.
pub fn guard_completed_marker_durability<'a, J: DurableIo>(
    journal: &'a mut J,
    ticket: &JournalTicket,
    expected_binding: &JournalBinding,
    proof: &CompletedMarkerProof,
    mut observe_binding: impl FnMut(&mut J) -> Result<JournalBinding>,
) -> Result<DurableCompletedMarker<'a, J>> {
    ensure!(
        observe_binding(journal)? == *expected_binding,
        "completed durability journal identity changed before sync"
    );
    recheck_completed_journal(journal, ticket, expected_binding, proof)?;
    journal.sync_all()?;
    ensure!(
        observe_binding(journal)? == *expected_binding,
        "completed durability journal identity changed after sync"
    );
    recheck_completed_journal(journal, ticket, expected_binding, proof)?;
    Ok(DurableCompletedMarker { journal })
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
    let target_sha256 = hash_full_image(
        target,
        loaded.manifest.request.expected_length,
        &loaded.manifest.binding,
    )?;
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
    let target_sha256 = if loaded.manifest.binding.source_resource_profile
        == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2)
        && loaded.manifest.request.expected_length >= 64 * 1024 * 1024
        && std::thread::available_parallelism().is_ok_and(|cores| cores.get() >= 2)
    {
        target.sync_all()?;
        let (target_hash, shadow_hash) = retained_compare::hash_pair_pipelined(
            target,
            shadow,
            loaded.manifest.request.expected_length,
            native_full_image_digest(&loaded.manifest.binding),
        )?;
        ensure!(
            shadow_hash == loaded.manifest.request.shadow_sha256,
            "handoff shadow image changed"
        );
        target_hash
    } else {
        ensure!(
            hash_full_image(
                shadow,
                loaded.manifest.request.expected_length,
                &loaded.manifest.binding,
            )? == loaded.manifest.request.shadow_sha256,
            "handoff shadow image changed"
        );
        // The full expected-postimage check is stronger than independently
        // normalizing its patches back to the source. Keep both full pins.
        target.sync_all()?;
        hash_full_image(
            target,
            loaded.manifest.request.expected_length,
            &loaded.manifest.binding,
        )?
    };
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

/// Native compact-only handoff. Both complete image pins are freshly computed;
/// the candidate's unchanged bytes share the actual target read view rather
/// than causing a second physical scan. No supplied digest can authorize HND.
#[cfg(windows)]
pub(crate) fn mark_compact_handoff<S: Read + Seek, J: DurableIo>(
    target: &mut n2r_win32::GeneralJournaledPartition,
    shadow: &mut crate::refs_hybrid::delta::DifferenceImage<
        '_,
        n2r_win32::GeneralJournalReadView,
        S,
    >,
    journal: &mut J,
    ticket: &JournalTicket,
    observed_binding: &JournalBinding,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<ExecutionReport> {
    validate_binding(observed_binding)?;
    ensure!(
        *observed_binding == ticket.binding,
        "compact handoff storage binding differs"
    );
    let loaded = load_journal(journal, ticket)?;
    let request = &loaded.manifest.request;
    ensure!(
        n2r_win32::GeneralJournaledPartition::byte_len(target) == request.expected_length,
        "compact handoff target length changed"
    );
    let ranges: Vec<_> = loaded
        .records
        .iter()
        .map(|record| (record.offset, record.length))
        .collect();
    target.sync_all()?;
    let (target_sha256, shadow_sha256) =
        shadow.hash_pair_for_target(target, request.expected_length, &ranges, events)?;
    ensure!(
        shadow_sha256 == request.shadow_sha256,
        "compact handoff shadow image changed"
    );
    ensure!(
        target_sha256 == loaded.manifest.expected_postimage_sha256,
        "compact handoff requires the complete expected postimage"
    );
    // Keep the same final marker write, durable flush and exact readback as the
    // generic handoff. Every nonzero/partial existing marker was refused above.
    let handoff = marker(b"N2RHND01", 3, ticket, &target_sha256)?;
    journal.seek(SeekFrom::Start(0))?;
    journal.write_all(&handoff)?;
    journal.sync_all()?;
    let mut observed = [0; GRANULE as usize];
    read_at(journal, 0, &mut observed)?;
    ensure!(
        observed == handoff,
        "compact handoff marker readback differs; recovery remains closed"
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
        hash_full_image(shadow, length, &loaded.manifest.binding)?
            == loaded.manifest.request.shadow_sha256,
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
    let target_sha256 = hash_full_image(target, length, &loaded.manifest.binding)?;
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

#[cfg(test)]
mod capacity_budget_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    #[derive(Clone)]
    struct Memory {
        bytes: Cursor<Vec<u8>>,
        largest_read: usize,
        largest_write: usize,
    }
    impl Memory {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes: Cursor::new(bytes),
                largest_read: 0,
                largest_write: 0,
            }
        }
    }
    impl Read for Memory {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.largest_read = self.largest_read.max(buffer.len());
            self.bytes.read(buffer)
        }
    }
    impl Seek for Memory {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(position)
        }
    }
    impl Write for Memory {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.largest_write = self.largest_write.max(bytes.len());
            self.bytes.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ReadSeek for Memory {
        fn byte_len(&mut self) -> io::Result<u64> {
            Ok(self.bytes.get_ref().len() as u64)
        }
    }
    impl DurableIo for Memory {
        fn sync_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn test_binding() -> JournalBinding {
        JournalBinding {
            experiment_id: "a".repeat(32),
            source_resource_profile: None,
            target_identity_sha256: "1".repeat(64),
            shadow_identity_sha256: "2".repeat(64),
            journal_identity_sha256: "3".repeat(64),
        }
    }

    fn fixture() -> (Vec<u8>, Vec<u8>, RetainedCompareRequest) {
        let source = vec![0x31; 3 * BUFFER];
        let mut shadow = source.clone();
        shadow[4096..2 * BUFFER + 4096].fill(0x72);
        let request = RetainedCompareRequest {
            schema_version: 2,
            sector_size: GRANULE as u32,
            expected_length: source.len() as u64,
            source_sha256: hex::encode(Sha256::digest(&source)),
            shadow_sha256: hex::encode(Sha256::digest(&shadow)),
            retained_ranges: vec![],
            max_change_bytes: source.len() as u64,
            max_ranges: 4,
        };
        (source, shadow, request)
    }
    #[test]
    fn journal_capacity_reserves_both_payloads_and_worst_case_metadata() {
        let image = 52u64 << 30;
        assert_eq!(changed_byte_budget(768 << 20, image).unwrap(), 376 << 20);
        assert_eq!(changed_byte_budget(512 << 20, image).unwrap(), 248 << 20);
        assert_eq!(changed_byte_budget(128 << 20, image).unwrap(), 56 << 20);
        assert_eq!(
            changed_byte_budget(JOURNAL_OVERHEAD_RESERVE + 2 * GRANULE, image).unwrap(),
            GRANULE
        );
        let worst_overhead = BODY_START
            + HEADER_SIZE as u64
            + MAX_METADATA as u64
            + 65536 * RECORD_SIZE as u64
            + FOOTER_SIZE as u64;
        assert!(worst_overhead <= JOURNAL_OVERHEAD_RESERVE);
        for journal in [
            JOURNAL_OVERHEAD_RESERVE + 2 * GRANULE,
            32 << 20,
            (128 << 20) + 1,
            MAX_JOURNAL_BYTES,
        ] {
            let changed = changed_byte_budget(journal, image).unwrap();
            assert!(changed.is_multiple_of(GRANULE));
            assert!(changed <= MAX_CHANGE_BYTES);
            assert!(2 * changed + worst_overhead <= journal);
        }
        assert_eq!(
            changed_byte_budget(MAX_JOURNAL_BYTES, 2 * GRANULE).unwrap(),
            2 * GRANULE
        );
    }
    #[test]
    fn undersized_or_overflowing_capacity_is_refused() {
        let image = 52u64 << 30;
        for journal in [
            0,
            JOURNAL_OVERHEAD_RESERVE - 1,
            JOURNAL_OVERHEAD_RESERVE,
            JOURNAL_OVERHEAD_RESERVE + 2 * GRANULE - 1,
            MAX_JOURNAL_BYTES + 1,
            u64::MAX,
        ] {
            assert!(
                changed_byte_budget(journal, image).is_err(),
                "journal {journal}"
            );
        }
        for image in [
            0,
            GRANULE - 1,
            GRANULE + 1,
            retained_compare::MAX_IMAGE_BYTES + GRANULE,
            u64::MAX,
        ] {
            assert!(
                changed_byte_budget(MAX_JOURNAL_BYTES, image).is_err(),
                "image {image}"
            );
        }
    }

    #[test]
    fn experimental_profile_is_explicit_and_preserves_legacy_ceiling() {
        let image = 52u64 << 30;
        let large = JournalProfile::ExperimentalLargeV2;
        assert_eq!(changed_byte_budget(768 << 20, image).unwrap(), 376 << 20);
        assert!(changed_byte_budget((768 << 20) + 1, image).is_err());
        assert_eq!(
            changed_byte_budget_for_profile(large, 16 << 30, image).unwrap(),
            ((16u64 << 30) - JOURNAL_OVERHEAD_RESERVE) / 2
        );
        assert!(changed_byte_budget_for_profile(large, (16u64 << 30) + 1, image).is_err());
        assert!(changed_byte_budget_for_profile(large, u64::MAX, image).is_err());
    }

    #[test]
    fn legacy_default_and_explicit_v1_produce_identical_journal_bytes() {
        let (old, new, request) = fixture();
        let binding = test_binding();
        let mut source = Memory::new(old.clone());
        let mut shadow = Memory::new(new.clone());
        let mut default_journal = Memory::new(vec![]);
        let default = prepare_journal(
            &mut source,
            &mut shadow,
            &mut default_journal,
            &request,
            &binding,
            MAX_JOURNAL_BYTES,
        )
        .unwrap();
        let mut source = Memory::new(old);
        let mut shadow = Memory::new(new);
        let mut explicit_journal = Memory::new(vec![]);
        let explicit = prepare_journal_with_profile(
            &mut source,
            &mut shadow,
            &mut explicit_journal,
            &request,
            &binding,
            MAX_JOURNAL_BYTES,
            JournalProfile::LegacyV1,
        )
        .unwrap();
        assert_eq!(default.ticket.schema_version, 1);
        assert_eq!(
            serde_json::to_vec(&default.ticket).unwrap(),
            serde_json::to_vec(&explicit.ticket).unwrap()
        );
        assert_eq!(
            default_journal.bytes.get_ref(),
            explicit_journal.bytes.get_ref()
        );
    }

    #[test]
    fn version_two_streaming_replay_and_rollback_preserve_integrity() {
        let (old, new, request) = fixture();
        let mut source = Memory::new(old.clone());
        let mut shadow = Memory::new(new.clone());
        let mut journal = Memory::new(vec![]);
        let binding = test_binding();
        let summary = prepare_journal_with_profile(
            &mut source,
            &mut shadow,
            &mut journal,
            &request,
            &binding,
            16 << 30,
            JournalProfile::ExperimentalLargeV2,
        )
        .unwrap();
        assert_eq!(summary.ticket.schema_version, 2);
        assert_eq!(summary.before_payload_bytes, 2 * BUFFER as u64);
        assert_eq!(summary.after_payload_bytes, 2 * BUFFER as u64);
        assert!(source.largest_read <= BUFFER && shadow.largest_read <= BUFFER);
        assert!(journal.largest_read <= BUFFER && journal.largest_write <= BUFFER);
        let descriptor = inspect_journal(&mut journal, &summary.ticket, &binding).unwrap();
        assert_eq!(descriptor.changed_bytes, 2 * BUFFER as u64);

        // A v2 journal cannot be replayed with a legacy/unknown ticket, even
        // when its small fixture length also fits the old profile.
        let mut wrong_version = summary.ticket.clone();
        wrong_version.schema_version = 1;
        assert!(inspect_journal(&mut journal, &wrong_version, &binding).is_err());
        wrong_version.schema_version = 3;
        assert!(inspect_journal(&mut journal, &wrong_version, &binding).is_err());

        let mut target = Memory::new(old.clone());
        let mut tampered = journal.clone();
        let last = tampered.bytes.get_ref().len() - 1;
        tampered.bytes.get_mut()[last] ^= 1;
        assert!(
            resume(
                &mut target,
                &mut shadow,
                &mut tampered,
                &summary.ticket,
                &binding
            )
            .is_err()
        );
        assert_eq!(target.bytes.get_ref(), &old);
        resume(
            &mut target,
            &mut shadow,
            &mut journal,
            &summary.ticket,
            &binding,
        )
        .unwrap();
        assert_eq!(target.bytes.get_ref(), &new);
        rollback(
            &mut target,
            &mut shadow,
            &mut journal,
            &summary.ticket,
            &binding,
        )
        .unwrap();
        assert_eq!(target.bytes.get_ref(), &old);
        mark_rollback_complete_without_shadow(&mut target, &mut journal, &summary.ticket, &binding)
            .unwrap();
        verify_completed_rollback_marker_without_shadow(
            &mut target,
            &mut journal,
            &summary.ticket,
            &binding,
            old.len() as u64,
            &request.source_sha256,
        )
        .unwrap();
        assert!(
            resume(
                &mut target,
                &mut shadow,
                &mut journal,
                &summary.ticket,
                &binding
            )
            .is_err()
        );
        assert_eq!(target.bytes.get_ref(), &old);
    }

    // Run-compressed random-access storage exercises real multi-hundred-MiB
    // journal offsets without a large disk artifact or per-byte allocation.
    #[derive(Clone)]
    enum TestPage {
        Uniform(u8),
        Mixed(Box<[u8; 4096]>),
    }

    #[derive(Clone)]
    struct SparseTestIo {
        length: u64,
        position: u64,
        default_byte: u8,
        pages: BTreeMap<u64, TestPage>,
        largest_read: usize,
        largest_write: usize,
    }
    impl SparseTestIo {
        fn new(length: u64, default_byte: u8) -> Self {
            Self {
                length,
                position: 0,
                default_byte,
                pages: BTreeMap::new(),
                largest_read: 0,
                largest_write: 0,
            }
        }
        fn page(&self, index: u64) -> [u8; 4096] {
            match self.pages.get(&index) {
                None => [self.default_byte; 4096],
                Some(TestPage::Uniform(byte)) => [*byte; 4096],
                Some(TestPage::Mixed(bytes)) => **bytes,
            }
        }
        fn write_page(&mut self, index: u64, offset: usize, data: &[u8]) {
            let mut bytes = self.page(index);
            bytes[offset..offset + data.len()].copy_from_slice(data);
            let byte = bytes[0];
            if bytes.iter().all(|value| *value == byte) {
                if byte == self.default_byte {
                    self.pages.remove(&index);
                } else {
                    self.pages.insert(index, TestPage::Uniform(byte));
                }
            } else {
                self.pages.insert(index, TestPage::Mixed(Box::new(bytes)));
            }
        }
    }
    impl Read for SparseTestIo {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.largest_read = self.largest_read.max(output.len());
            let count = output
                .len()
                .min(self.length.saturating_sub(self.position) as usize);
            let mut done = 0;
            while done < count {
                let index = self.position / 4096;
                let offset = (self.position % 4096) as usize;
                let step = (4096 - offset).min(count - done);
                match self.pages.get(&index) {
                    None => output[done..done + step].fill(self.default_byte),
                    Some(TestPage::Uniform(byte)) => output[done..done + step].fill(*byte),
                    Some(TestPage::Mixed(bytes)) => {
                        output[done..done + step].copy_from_slice(&bytes[offset..offset + step])
                    }
                }
                done += step;
                self.position += step as u64;
            }
            Ok(count)
        }
    }
    impl Seek for SparseTestIo {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            let next = match from {
                SeekFrom::Start(position) => i128::from(position),
                SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
                SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
            };
            if !(0..=i128::from(JournalProfile::ExperimentalLargeV2.max_journal_bytes()))
                .contains(&next)
            {
                return Err(io::Error::other("test seek out of range"));
            }
            self.position = next as u64;
            Ok(self.position)
        }
    }
    impl Write for SparseTestIo {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.largest_write = self.largest_write.max(input.len());
            let mut done = 0;
            while done < input.len() {
                let index = self.position / 4096;
                let offset = (self.position % 4096) as usize;
                let step = (4096 - offset).min(input.len() - done);
                self.write_page(index, offset, &input[done..done + step]);
                done += step;
                self.position += step as u64;
            }
            self.length = self.length.max(self.position);
            Ok(done)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ReadSeek for SparseTestIo {
        fn byte_len(&mut self) -> io::Result<u64> {
            Ok(self.length)
        }
    }
    impl DurableIo for SparseTestIo {
        fn sync_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    #[ignore = "streams over the legacy journal limit through bounded in-memory pages"]
    fn experimental_journal_over_legacy_limit_replays_and_rolls_back() {
        let length = (384u64 << 20) + GRANULE;
        let mut source = SparseTestIo::new(length, 0);
        let mut shadow = SparseTestIo::new(length, 0x72);
        let source_hash = retained_compare::hash_reader(&mut source, length).unwrap();
        let shadow_hash = retained_compare::hash_reader(&mut shadow, length).unwrap();
        let request = RetainedCompareRequest {
            schema_version: 2,
            sector_size: GRANULE as u32,
            expected_length: length,
            source_sha256: source_hash.clone(),
            shadow_sha256: shadow_hash,
            retained_ranges: vec![],
            max_change_bytes: length,
            max_ranges: 4,
        };
        let binding = test_binding();
        let mut journal = SparseTestIo::new(0, 0);
        assert!(
            prepare_journal(
                &mut source,
                &mut shadow,
                &mut journal,
                &request,
                &binding,
                MAX_JOURNAL_BYTES
            )
            .is_err()
        );
        assert_eq!(journal.length, 0);
        let summary = prepare_journal_with_profile(
            &mut source,
            &mut shadow,
            &mut journal,
            &request,
            &binding,
            16 << 30,
            JournalProfile::ExperimentalLargeV2,
        )
        .unwrap();
        assert!(summary.ticket.journal_length > MAX_JOURNAL_BYTES);
        assert_eq!(summary.changed_bytes, length);
        assert_eq!(summary.ticket.schema_version, 2);
        let mut wrong_profile = summary.ticket.clone();
        wrong_profile.schema_version = 1;
        assert!(inspect_journal(&mut journal, &wrong_profile, &binding).is_err());
        let mut target = SparseTestIo::new(length, 0);
        resume(
            &mut target,
            &mut shadow,
            &mut journal,
            &summary.ticket,
            &binding,
        )
        .unwrap();
        assert_eq!(
            retained_compare::hash_reader(&mut target, length).unwrap(),
            request.shadow_sha256
        );
        rollback_without_shadow(&mut target, &mut journal, &summary.ticket, &binding).unwrap();
        assert_eq!(
            retained_compare::hash_reader(&mut target, length).unwrap(),
            source_hash
        );
        mark_rollback_complete_without_shadow(&mut target, &mut journal, &summary.ticket, &binding)
            .unwrap();
        verify_completed_rollback_marker_without_shadow(
            &mut target,
            &mut journal,
            &summary.ticket,
            &binding,
            length,
            &source_hash,
        )
        .unwrap();
        assert!(
            resume(
                &mut target,
                &mut shadow,
                &mut journal,
                &summary.ticket,
                &binding
            )
            .is_err()
        );
        assert!(
            source.largest_read <= BUFFER
                && shadow.largest_read <= BUFFER
                && target.largest_read <= BUFFER
                && journal.largest_read <= BUFFER
        );
        assert!(target.largest_write <= BUFFER && journal.largest_write <= BUFFER);
    }
}
