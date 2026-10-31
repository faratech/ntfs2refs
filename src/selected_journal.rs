//! Selected-range reconstruction journal. This module opens no devices and
//! does not authenticate the selection, establish exclusion or certify a
//! filesystem. The caller owns those obligations and the trusted ticket.
//!
//! Empty `new_zero_ranges` preserves the original N2RSEL01 byte layout.
//! N2RZERO1 stores every old byte but represents selected all-zero new ranges
//! without payload. Both formats use the same selected-byte digests and replay
//! barriers; zero encoding changes storage, not the target write set.
//! N2RCPY01 additionally resolves new bytes from the journal's immutable old
//! payloads. It never needs a source device when replaying a copy.
use crate::lab_reconstruct::{DurableIo, ReadSeek};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

const GRANULE: u64 = 4096;
const BODY: u64 = 8192;
const HEADER: usize = 80;
const RECORD: usize = 80;
const ZERO_RECORD: usize = 88;
const COPY_RECORD: usize = 96;
const FOOTER: usize = 80;
const BUFFER: usize = 1024 * 1024;
const MAX_RANGES: usize = 65_536;
const FORMAT: u32 = 1;
const ZERO_FORMAT: u32 = 2;
const COPY_FORMAT: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedCopyRange {
    pub offset: u64,
    pub length: u64,
    pub source_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedPlan {
    pub image_length: u64,
    pub ranges: Vec<SelectedRange>,
    pub max_selected_bytes: u64,
    pub max_journal_bytes: u64,
    /// A sorted subset of `ranges` whose new contents are exactly zero. Every
    /// entry must equal a complete selected range. Preparation checks the
    /// actual candidate; this declaration alone never authenticates bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_zero_ranges: Vec<SelectedRange>,
    /// New bytes reproduced from original bytes of selected ranges. The
    /// entire source interval must be covered by the journal's old payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_copy_ranges: Vec<SelectedCopyRange>,
}

/// Trusted only when held independently by the caller. This format and its
/// magic are separate from full-image reconstruction journal versions 1/2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTicket {
    pub image_length: u64,
    pub selected_bytes: u64,
    pub range_count: u32,
    pub journal_length: u64,
    pub immutable_sha256: [u8; 32],
    pub old_selected_sha256: [u8; 32],
    pub new_selected_sha256: [u8; 32],
    pub whole_image_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct SelectedResult {
    pub selected_sha256: [u8; 32],
    pub selected_bytes: u64,
    pub range_count: u32,
    pub replay_closed: bool,
    pub whole_image_verified: bool,
    pub conversion_qualified: bool,
}

#[derive(Debug)]
struct JournalRecord {
    range: SelectedRange,
    before_at: u64,
    after: NewBytes,
    new_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
enum NewBytes {
    Payload(u64),
    Zero,
    OldReference(u64),
}

fn at<R: Read + Seek>(io: &mut R, offset: u64, bytes: &mut [u8]) -> Result<()> {
    io.seek(SeekFrom::Start(offset))?;
    io.read_exact(bytes)?;
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed field"))
}
fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed field"))
}
/// SHA-256 for the journal's pins: CNG on Windows (faster on CPUs without SHA
/// instructions), the sha2 crate elsewhere. The digest is identical.
type PinHash = crate::retained_compare::stream_digest::StreamDigest;
fn pin_hash() -> Result<PinHash> {
    PinHash::new(cfg!(windows))
}
fn finish(hash: PinHash) -> Result<[u8; 32]> {
    hash.finish()
}
fn frame(hash: &mut PinHash, range: &SelectedRange) -> Result<()> {
    hash.update(&range.offset.to_le_bytes())?;
    hash.update(&range.length.to_le_bytes())
}

impl SelectedPlan {
    pub fn new_copy_bytes(&self) -> Result<u64> {
        self.new_zero_bytes()?;
        let mut index = 0usize;
        let mut bytes = 0u64;
        for copy in &self.new_copy_ranges {
            while index < self.ranges.len() && self.ranges[index].offset < copy.offset {
                index += 1;
            }
            ensure!(
                self.ranges
                    .get(index)
                    .is_some_and(|r| r.offset == copy.offset && r.length == copy.length),
                "copy ranges must be a sorted unique exact subset of selected ranges"
            );
            ensure!(
                self.new_zero_ranges
                    .binary_search_by_key(&copy.offset, |r| r.offset)
                    .is_err(),
                "copy and zero destination ranges overlap"
            );
            let end = copy
                .source_offset
                .checked_add(copy.length)
                .context("copy source overflow")?;
            ensure!(
                copy.source_offset.is_multiple_of(GRANULE)
                    && copy.length > 0
                    && copy.length.is_multiple_of(GRANULE)
                    && end <= self.image_length,
                "copy source is unaligned or escapes the image"
            );
            let mut source_index = self.ranges.partition_point(|r| {
                r.offset
                    .checked_add(r.length)
                    .is_some_and(|end| end <= copy.source_offset)
            });
            let mut cursor = copy.source_offset;
            while cursor < end {
                let range = self
                    .ranges
                    .get(source_index)
                    .context("copy source leaves selected old payload")?;
                let range_end = range
                    .offset
                    .checked_add(range.length)
                    .context("selected old range overflow")?;
                ensure!(
                    range.offset <= cursor && cursor < range_end,
                    "copy source crosses an unjournaled gap"
                );
                cursor = end.min(range_end);
                source_index += 1;
            }
            bytes = bytes
                .checked_add(copy.length)
                .context("copy byte total overflow")?;
            index += 1;
        }
        Ok(bytes)
    }

    pub fn new_zero_bytes(&self) -> Result<u64> {
        let mut index = 0usize;
        let mut bytes = 0u64;
        for zero in &self.new_zero_ranges {
            while index < self.ranges.len() && self.ranges[index].offset < zero.offset {
                index += 1;
            }
            ensure!(
                self.ranges.get(index) == Some(zero),
                "zero ranges must be a sorted unique exact subset of selected ranges"
            );
            bytes = bytes
                .checked_add(zero.length)
                .context("zero byte total overflow")?;
            index += 1;
        }
        Ok(bytes)
    }

    fn zero_encoded(&self) -> bool {
        !self.new_zero_ranges.is_empty()
    }

    fn copy_encoded(&self) -> bool {
        !self.new_copy_ranges.is_empty()
    }

    fn copy_source(&self, range: &SelectedRange) -> Option<u64> {
        self.new_copy_ranges
            .binary_search_by_key(&range.offset, |r| r.offset)
            .ok()
            .map(|i| self.new_copy_ranges[i].source_offset)
    }

    fn format(&self) -> u32 {
        if self.copy_encoded() {
            COPY_FORMAT
        } else if self.zero_encoded() {
            ZERO_FORMAT
        } else {
            FORMAT
        }
    }

    fn magic(&self) -> &'static [u8; 8] {
        if self.copy_encoded() {
            b"N2RCPY01"
        } else if self.zero_encoded() {
            b"N2RZERO1"
        } else {
            b"N2RSEL01"
        }
    }

    fn footer_magic(&self) -> &'static [u8; 8] {
        if self.copy_encoded() {
            b"N2RCEND1"
        } else if self.zero_encoded() {
            b"N2RZEND1"
        } else {
            b"N2RSEND1"
        }
    }

    fn is_new_zero(&self, range: &SelectedRange) -> bool {
        self.new_zero_ranges
            .binary_search_by_key(&range.offset, |r| r.offset)
            .is_ok()
    }

    fn record_size(&self) -> usize {
        if self.copy_encoded() {
            COPY_RECORD
        } else if self.zero_encoded() {
            ZERO_RECORD
        } else {
            RECORD
        }
    }

    /// Computes exact journal size with checked arithmetic and bounded range
    /// memory. No filesystem or write-set correctness is implied.
    pub fn validate(&self) -> Result<(u64, u64)> {
        ensure!(
            self.image_length >= GRANULE
                && self.image_length.is_multiple_of(GRANULE)
                && !self.ranges.is_empty()
                && self.ranges.len() <= MAX_RANGES
                && self.max_selected_bytes <= self.image_length,
            "selected journal geometry or range budget invalid"
        );
        let mut previous_end = 0u64;
        let mut changed = 0u64;
        for range in &self.ranges {
            let end = range
                .offset
                .checked_add(range.length)
                .context("selected range overflow")?;
            ensure!(
                range.length != 0
                    && range.offset.is_multiple_of(GRANULE)
                    && range.length.is_multiple_of(GRANULE)
                    && range.offset >= previous_end
                    && end <= self.image_length,
                "selected ranges overlap, are unaligned or escape the image"
            );
            previous_end = end;
            changed = changed
                .checked_add(range.length)
                .context("selected byte total overflow")?;
        }
        ensure!(
            changed <= self.max_selected_bytes,
            "selected bytes exceed caller budget"
        );
        let zero_bytes = self.new_zero_bytes()?;
        let copy_bytes = self.new_copy_bytes()?;
        let journal_length = BODY
            .checked_add(HEADER as u64)
            .and_then(|n| {
                n.checked_add((self.ranges.len() as u64).checked_mul(self.record_size() as u64)?)
            })
            .and_then(|n| {
                n.checked_add(
                    changed
                        .checked_mul(2)?
                        .checked_sub(zero_bytes)?
                        .checked_sub(copy_bytes)?,
                )
            })
            .and_then(|n| n.checked_add(FOOTER as u64))
            .context("selected journal length overflow")?;
        ensure!(
            journal_length <= self.max_journal_bytes,
            "selected journal exceeds caller budget"
        );
        Ok((changed, journal_length))
    }
}

fn extend(runs: &mut Vec<SelectedRange>, offset: u64, length: u64) -> Result<()> {
    if let Some(last) = runs.last_mut()
        && last.offset + last.length == offset
    {
        last.length += length;
        return Ok(());
    }
    ensure!(
        runs.len() < MAX_RANGES,
        "differing granule runs exceed the selected journal range limit"
    );
    runs.push(SelectedRange { offset, length });
    Ok(())
}

/// Narrow a coarse selection to the 4 KiB granules in which `source` and
/// `candidate` differ, so equal bytes are neither journaled nor written. Both
/// inputs are read once over the coarse ranges and nowhere else. The coarse
/// selection is validated with the plan geometry rules but not authenticated,
/// and the result holds only while both inputs stay unchanged under the
/// caller's exclusion until the apply completes. It certifies nothing about
/// bytes outside the coarse selection.
pub fn changed_plan<R: ReadSeek, S: ReadSeek>(
    source: &mut R,
    candidate: &mut S,
    image_length: u64,
    coarse: &[SelectedRange],
    max_selected_bytes: u64,
    max_journal_bytes: u64,
) -> Result<SelectedPlan> {
    validate_coarse(image_length, coarse)?;
    ensure!(
        source.byte_len()? == image_length && candidate.byte_len()? == image_length,
        "planning inputs differ in length from the image"
    );
    let mut before = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let mut runs = Vec::new();
    for range in coarse {
        let mut done = 0u64;
        while done < range.length {
            let count = usize::try_from((range.length - done).min(BUFFER as u64))?;
            let base = range.offset + done;
            at(source, base, &mut before[..count])?;
            at(candidate, base, &mut after[..count])?;
            record_differing_granules(&mut runs, base, &before[..count], &after[..count])?;
            done += count as u64;
        }
    }
    finish_changed_plan(image_length, runs, max_selected_bytes, max_journal_bytes)
}

/// Geometry check for a coarse planning selection; budgets apply to the result.
pub(crate) fn validate_coarse(image_length: u64, coarse: &[SelectedRange]) -> Result<()> {
    SelectedPlan {
        image_length,
        ranges: coarse.to_vec(),
        max_selected_bytes: image_length,
        max_journal_bytes: u64::MAX,
        new_zero_ranges: Vec::new(),
        new_copy_ranges: Vec::new(),
    }
    .validate()?;
    Ok(())
}

/// Append the differing 4 KiB granules of one paired chunk read at `base`.
/// Shared by readers that cannot lend two independent handles to `changed_plan`.
pub(crate) fn record_differing_granules(
    runs: &mut Vec<SelectedRange>,
    base: u64,
    before: &[u8],
    after: &[u8],
) -> Result<()> {
    ensure!(
        before.len() == after.len() && before.len().is_multiple_of(GRANULE as usize),
        "paired planning chunks differ or are not granule aligned"
    );
    let granules = before
        .chunks(GRANULE as usize)
        .zip(after.chunks(GRANULE as usize));
    for (index, (old, new)) in granules.enumerate() {
        if old != new {
            extend(runs, base + index as u64 * GRANULE, GRANULE)?;
        }
    }
    Ok(())
}

pub(crate) fn finish_changed_plan(
    image_length: u64,
    runs: Vec<SelectedRange>,
    max_selected_bytes: u64,
    max_journal_bytes: u64,
) -> Result<SelectedPlan> {
    ensure!(
        !runs.is_empty(),
        "coarse selection contains no differing granule"
    );
    let plan = SelectedPlan {
        image_length,
        ranges: runs,
        max_selected_bytes,
        max_journal_bytes,
        new_zero_ranges: Vec::new(),
        new_copy_ranges: Vec::new(),
    };
    plan.validate()?;
    Ok(plan)
}

fn hash_range<R: Read + Seek>(io: &mut R, offset: u64, length: u64) -> Result<[u8; 32]> {
    io.seek(SeekFrom::Start(offset))?;
    let mut hash = pin_hash()?;
    let mut buffer = vec![0; BUFFER];
    let mut remaining = length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        io.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count])?;
        remaining -= count as u64;
    }
    finish(hash)
}

fn copy_selected<R: Read + Seek, J: Write>(
    input: &mut R,
    range: &SelectedRange,
    journal: &mut J,
    selected: &mut PinHash,
    buffer: &mut [u8],
) -> Result<[u8; 32]> {
    input.seek(SeekFrom::Start(range.offset))?;
    frame(selected, range)?;
    let mut hash = pin_hash()?;
    let mut remaining = range.length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        input.read_exact(&mut buffer[..count])?;
        journal.write_all(&buffer[..count])?;
        selected.update(&buffer[..count])?;
        hash.update(&buffer[..count])?;
        remaining -= count as u64;
    }
    finish(hash)
}

fn verify_zero_selected<R: Read + Seek>(
    input: &mut R,
    range: &SelectedRange,
    selected: &mut PinHash,
    buffer: &mut [u8],
) -> Result<[u8; 32]> {
    input.seek(SeekFrom::Start(range.offset))?;
    frame(selected, range)?;
    let mut hash = pin_hash()?;
    let mut remaining = range.length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        input.read_exact(&mut buffer[..count])?;
        ensure!(
            buffer[..count].iter().all(|&byte| byte == 0),
            "selected zero range contains nonzero candidate bytes"
        );
        selected.update(&buffer[..count])?;
        hash.update(&buffer[..count])?;
        remaining -= count as u64;
    }
    finish(hash)
}

fn verify_copy_selected<R: Read + Seek, S: Read + Seek>(
    source: &mut R,
    candidate: &mut S,
    ranges: &[SelectedRange],
    range: &SelectedRange,
    source_offset: u64,
    selected: &mut PinHash,
    before: &mut [u8],
    after: &mut [u8],
) -> Result<[u8; 32]> {
    frame(selected, range)?;
    let mut hash = pin_hash()?;
    let mut done = 0u64;
    while done < range.length {
        let count = usize::try_from((range.length - done).min(BUFFER as u64))?;
        at(candidate, range.offset + done, &mut after[..count])?;
        let mut cursor = source_offset + done;
        let mut filled = 0usize;
        while filled < count {
            let index = ranges.partition_point(|r| r.offset + r.length <= cursor);
            let old = ranges
                .get(index)
                .context("copy source leaves selected old ranges")?;
            ensure!(
                old.offset <= cursor,
                "copy source crosses an unjournaled gap"
            );
            let n =
                usize::try_from((old.offset + old.length - cursor).min((count - filled) as u64))?;
            at(source, cursor, &mut before[filled..filled + n])?;
            cursor += n as u64;
            filled += n;
        }
        ensure!(
            before[..count] == after[..count],
            "selected copy differs from original source bytes"
        );
        selected.update(&after[..count])?;
        hash.update(&after[..count])?;
        done += count as u64;
    }
    finish(hash)
}

/// Create and durably verify a new external journal. Only selected ranges are
/// read from the two images. Ticket issuance follows an independent readback.
pub fn prepare<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
) -> Result<SelectedTicket> {
    prepare_inner(source, candidate, journal, plan, false)
}

/// Prepare under continuous exclusive ownership of the new journal. The
/// caller must exclude writer/delete aliases, including hidden handles in the
/// source/candidate readers. Windows callers use a newly created share-zero
/// file and retain that owner throughout this call.
///
/// The complete post-flush validating readback computes the immutable pin
/// while checking descriptors, all payloads and source/candidate selected
/// digests. No preliminary hash-only scan is needed to issue the same pin.
/// Legacy preparation and every fresh recovery entry retain their checks.
pub(crate) fn prepare_exclusive<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
) -> Result<SelectedTicket> {
    prepare_inner(source, candidate, journal, plan, true)
}

fn prepare_inner<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
    exclusive_readback: bool,
) -> Result<SelectedTicket> {
    let (changed, journal_length) = plan.validate()?;
    ensure!(
        source.byte_len()? == plan.image_length
            && candidate.byte_len()? == plan.image_length
            && journal.byte_len()? == 0,
        "selected inputs differ in length or journal is not empty"
    );
    let mut header = [0u8; HEADER];
    let zero_encoded = plan.zero_encoded();
    let copy_encoded = plan.copy_encoded();
    header[..8].copy_from_slice(plan.magic());
    put_u32(&mut header, 8, plan.format());
    put_u32(&mut header, 12, u32::try_from(plan.ranges.len())?);
    put_u64(&mut header, 16, plan.image_length);
    put_u64(&mut header, 24, changed);
    put_u64(&mut header, 32, journal_length);
    journal.seek(SeekFrom::Start(0))?;
    journal.write_all(&[0; BODY as usize])?;
    journal.write_all(&header)?;
    let mut old_selected = pin_hash()?;
    let mut new_selected = pin_hash()?;
    // Fixed memory for the whole preparation; small fragmented ranges do not
    // repeatedly allocate/zero MiB-sized vectors. Each slice used below is
    // completely filled by its current read before hashing or comparison.
    let mut data_buffer = vec![0; BUFFER];
    let mut copy_buffer = vec![0; BUFFER];
    for range in &plan.ranges {
        let record_at = journal.stream_position()?;
        let mut record = [0u8; COPY_RECORD];
        journal.write_all(&record[..plan.record_size()])?;
        let old_hash = copy_selected(source, range, journal, &mut old_selected, &mut data_buffer)?;
        let is_zero = plan.is_new_zero(range);
        let copy_source = plan.copy_source(range);
        let new_hash = if is_zero {
            verify_zero_selected(candidate, range, &mut new_selected, &mut data_buffer)?
        } else if let Some(source_offset) = copy_source {
            verify_copy_selected(
                source,
                candidate,
                &plan.ranges,
                range,
                source_offset,
                &mut new_selected,
                &mut data_buffer,
                &mut copy_buffer,
            )?
        } else {
            copy_selected(
                candidate,
                range,
                journal,
                &mut new_selected,
                &mut data_buffer,
            )?
        };
        let next = journal.stream_position()?;
        put_u64(&mut record, 0, range.offset);
        put_u64(&mut record, 8, range.length);
        let hashes = if copy_encoded {
            put_u64(
                &mut record,
                16,
                if is_zero {
                    1
                } else if copy_source.is_some() {
                    2
                } else {
                    0
                },
            );
            put_u64(&mut record, 24, copy_source.unwrap_or(0));
            32
        } else if zero_encoded {
            put_u64(&mut record, 16, u64::from(is_zero));
            24
        } else {
            16
        };
        record[hashes..hashes + 32].copy_from_slice(&old_hash);
        record[hashes + 32..hashes + 64].copy_from_slice(&new_hash);
        journal.seek(SeekFrom::Start(record_at))?;
        journal.write_all(&record[..plan.record_size()])?;
        journal.seek(SeekFrom::Start(next))?;
    }
    let old_selected_sha256 = finish(old_selected)?;
    let new_selected_sha256 = finish(new_selected)?;
    drop(data_buffer);
    drop(copy_buffer);
    let mut footer = [0u8; FOOTER];
    footer[..8].copy_from_slice(plan.footer_magic());
    footer[8..40].copy_from_slice(&old_selected_sha256);
    footer[40..72].copy_from_slice(&new_selected_sha256);
    put_u64(&mut footer, 72, journal_length);
    journal.write_all(&footer)?;
    ensure!(
        journal.byte_len()? == journal_length
            && source.byte_len()? == plan.image_length
            && candidate.byte_len()? == plan.image_length,
        "selected preparation input or journal length changed"
    );
    journal.sync_all()?;
    let mut ticket = SelectedTicket {
        image_length: plan.image_length,
        selected_bytes: changed,
        range_count: u32::try_from(plan.ranges.len())?,
        journal_length,
        // This internal value is never returned or persisted before the
        // validating readback supplies the actual digest below.
        immutable_sha256: [0; 32],
        old_selected_sha256,
        new_selected_sha256,
        whole_image_verified: false,
    };
    if exclusive_readback {
        let (_, immutable_sha256) = validate_body(journal, plan, &ticket, None)?;
        ticket.immutable_sha256 = immutable_sha256;
    } else {
        ticket.immutable_sha256 = hash_range(journal, BODY, journal_length - BODY)?;
        load(journal, plan, &ticket)?;
    }
    let mut markers = [0u8; BODY as usize];
    at(journal, 0, &mut markers)?;
    ensure!(
        markers.iter().all(|&b| b == 0),
        "selected journal markers are not clear"
    );
    Ok(ticket)
}

/// Recheck the pinned complete immutable journal and each payload in one
/// sequential read pass. Synthetic zero bytes participate in the selected
/// digests, never the immutable journal digest. No record is returned before
/// the complete immutable pin and all payload/footer checks have passed.
/// Even a valid serialized ticket must be trusted independently by the caller.
fn load<J: ReadSeek>(
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<Vec<JournalRecord>> {
    Ok(validate_body(journal, plan, ticket, Some(&ticket.immutable_sha256))?.0)
}

/// No pin is issued, nor record returned, until the whole independent readback
/// and every selected/payload check succeeds. Only new-journal preparation may
/// create a pin; all journal consumers require the independently trusted pin.
fn validate_body<J: ReadSeek>(
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    expected_immutable: Option<&[u8; 32]>,
) -> Result<(Vec<JournalRecord>, [u8; 32])> {
    let (changed, journal_length) = plan.validate()?;
    ensure!(
        !ticket.whole_image_verified
            && ticket.image_length == plan.image_length
            && ticket.selected_bytes == changed
            && ticket.range_count as usize == plan.ranges.len()
            && ticket.journal_length == journal_length
            && journal.byte_len()? == journal_length,
        "selected ticket, plan or journal length differs"
    );
    let mut immutable = pin_hash()?;
    let mut header = [0u8; HEADER];
    at(journal, BODY, &mut header)?;
    immutable.update(&header)?;
    let zero_encoded = plan.zero_encoded();
    let copy_encoded = plan.copy_encoded();
    ensure!(
        &header[..8] == plan.magic()
            && get_u32(&header, 8) == plan.format()
            && get_u32(&header, 12) == ticket.range_count
            && get_u64(&header, 16) == plan.image_length
            && get_u64(&header, 24) == changed
            && get_u64(&header, 32) == journal_length
            && header[40..].iter().all(|&b| b == 0),
        "selected journal header differs"
    );
    let mut records = Vec::with_capacity(plan.ranges.len());
    let mut old_selected = pin_hash()?;
    let mut new_selected = pin_hash()?;
    let mut buffer = vec![0; BUFFER];
    for range in &plan.ranges {
        let mut record = [0u8; COPY_RECORD];
        journal.read_exact(&mut record[..plan.record_size()])?;
        immutable.update(&record[..plan.record_size()])?;
        ensure!(
            get_u64(&record, 0) == range.offset && get_u64(&record, 8) == range.length,
            "selected journal range differs"
        );
        let before_at = journal.stream_position()?;
        let after_at = before_at
            .checked_add(range.length)
            .context("selected journal offset overflow")?;
        let is_zero = plan.is_new_zero(range);
        let copy_source = plan.copy_source(range);
        let hashes = if copy_encoded {
            let kind = if is_zero {
                1
            } else if copy_source.is_some() {
                2
            } else {
                0
            };
            ensure!(
                get_u64(&record, 16) == kind && get_u64(&record, 24) == copy_source.unwrap_or(0),
                "selected journal copy descriptor differs from the pinned plan"
            );
            32
        } else if zero_encoded {
            ensure!(
                get_u64(&record, 16) == u64::from(is_zero),
                "selected journal zero flag differs from the pinned plan"
            );
            24
        } else {
            16
        };
        let next = after_at
            .checked_add(if is_zero || copy_source.is_some() {
                0
            } else {
                range.length
            })
            .context("selected journal offset overflow")?;
        ensure!(
            next <= journal_length - FOOTER as u64,
            "selected journal payload truncated"
        );
        for old in [true, false] {
            if !old && copy_source.is_some() {
                continue; // The complete old-payload table is needed first.
            }
            let offset = if old {
                Some(before_at)
            } else {
                (!is_zero).then_some(after_at)
            };
            let expected = if old {
                &record[hashes..hashes + 32]
            } else {
                &record[hashes + 32..hashes + 64]
            };
            let mut selected = if old {
                Some(&mut old_selected)
            } else if !copy_encoded {
                Some(&mut new_selected)
            } else {
                None
            };
            if let Some(offset) = offset {
                ensure!(
                    journal.stream_position()? == offset,
                    "selected journal sequential payload position differs"
                );
            }
            if let Some(selected) = selected.as_deref_mut() {
                frame(selected, range)?;
            }
            let mut hash = pin_hash()?;
            let mut remaining = range.length;
            while remaining > 0 {
                let count = usize::try_from(remaining.min(BUFFER as u64))?;
                if offset.is_some() {
                    journal.read_exact(&mut buffer[..count])?;
                    immutable.update(&buffer[..count])?;
                } else {
                    buffer[..count].fill(0);
                }
                if let Some(selected) = selected.as_deref_mut() {
                    selected.update(&buffer[..count])?;
                }
                hash.update(&buffer[..count])?;
                remaining -= count as u64;
            }
            ensure!(
                finish(hash)?.as_slice() == expected,
                "selected journal payload hash differs"
            );
        }
        records.push(JournalRecord {
            range: range.clone(),
            before_at,
            after: if is_zero {
                NewBytes::Zero
            } else if let Some(source) = copy_source {
                NewBytes::OldReference(source)
            } else {
                NewBytes::Payload(after_at)
            },
            new_sha256: record[hashes + 32..hashes + 64]
                .try_into()
                .expect("fixed digest"),
        });
        ensure!(
            journal.stream_position()? == next,
            "selected journal sequential record position differs"
        );
    }
    let mut footer = [0u8; FOOTER];
    journal.read_exact(&mut footer)?;
    immutable.update(&footer)?;
    ensure!(
        &footer[..8] == plan.footer_magic()
            && footer[8..40] == ticket.old_selected_sha256
            && footer[40..72] == ticket.new_selected_sha256
            && get_u64(&footer, 72) == journal_length
            && finish(old_selected)? == ticket.old_selected_sha256
            && (copy_encoded || finish(new_selected)? == ticket.new_selected_sha256)
            && journal.stream_position()? == journal_length,
        "selected journal footer or selected digest differs"
    );
    let immutable_sha256 = finish(immutable)?;
    if let Some(expected) = expected_immutable {
        ensure!(
            &immutable_sha256 == expected,
            "selected immutable journal differs from trusted ticket"
        );
    }
    if copy_encoded {
        // All old payloads and descriptors are authenticated before any
        // reference is followed. References resolve only to those old bytes,
        // so overlap, forward references and reference cycles are harmless.
        let mut new_selected = pin_hash()?;
        for record in &records {
            frame(&mut new_selected, &record.range)?;
            let mut hash = pin_hash()?;
            let mut done = 0u64;
            while done < record.range.length {
                let count = usize::try_from((record.range.length - done).min(BUFFER as u64))?;
                read_after(journal, &records, record, done, &mut buffer[..count])?;
                hash.update(&buffer[..count])?;
                new_selected.update(&buffer[..count])?;
                done += count as u64;
            }
            ensure!(
                finish(hash)? == record.new_sha256,
                "selected resolved copy hash differs"
            );
        }
        ensure!(
            finish(new_selected)? == ticket.new_selected_sha256,
            "selected resolved new digest differs"
        );
    }
    Ok((records, immutable_sha256))
}

fn marker(kind: &[u8; 8], ticket: &SelectedTicket, digest: &[u8; 32]) -> [u8; GRANULE as usize] {
    let mut marker = [0u8; GRANULE as usize];
    marker[..8].copy_from_slice(kind);
    marker[8..40].copy_from_slice(&ticket.immutable_sha256);
    marker[40..72].copy_from_slice(digest);
    let hash: [u8; 32] = Sha256::digest(&marker[..GRANULE as usize - 32]).into();
    marker[GRANULE as usize - 32..].copy_from_slice(&hash);
    marker
}

fn read_markers<J: Read + Seek>(journal: &mut J, ticket: &SelectedTicket) -> Result<(bool, bool)> {
    let mut completed = [0u8; GRANULE as usize];
    let mut intent = [0u8; GRANULE as usize];
    at(journal, 0, &mut completed)?;
    at(journal, GRANULE, &mut intent)?;
    ensure!(
        completed.iter().all(|&b| b == 0),
        "selected replay is closed or completion marker is foreign/torn"
    );
    let zero = [0u8; GRANULE as usize];
    let apply = marker(b"N2RSAP01", ticket, &ticket.new_selected_sha256);
    let rollback = marker(b"N2RSRB01", ticket, &ticket.old_selected_sha256);
    ensure!(
        intent == zero || intent == apply || intent == rollback,
        "selected intent marker is foreign or torn"
    );
    Ok((intent == apply, intent == rollback))
}

fn write_marker<J: DurableIo>(
    journal: &mut J,
    offset: u64,
    value: &[u8; GRANULE as usize],
) -> Result<()> {
    journal.seek(SeekFrom::Start(offset))?;
    ensure!(
        journal.write(value)? == value.len(),
        "short selected marker write"
    );
    journal.sync_all()?;
    let mut observed = [0u8; GRANULE as usize];
    at(journal, offset, &mut observed)?;
    ensure!(&observed == value, "selected marker readback differs");
    Ok(())
}

fn read_after<J: Read + Seek>(
    journal: &mut J,
    records: &[JournalRecord],
    record: &JournalRecord,
    within: u64,
    bytes: &mut [u8],
) -> Result<()> {
    match record.after {
        NewBytes::Payload(offset) => at(journal, offset + within, bytes),
        NewBytes::Zero => {
            bytes.fill(0);
            Ok(())
        }
        NewBytes::OldReference(source) => {
            let mut cursor = source + within;
            let mut filled = 0usize;
            while filled < bytes.len() {
                let index = records.partition_point(|r| r.range.offset + r.range.length <= cursor);
                let original = records
                    .get(index)
                    .context("copy leaves immutable old records")?;
                ensure!(
                    original.range.offset <= cursor,
                    "copy crosses an unjournaled old gap"
                );
                let count = usize::try_from(
                    (original.range.offset + original.range.length - cursor)
                        .min((bytes.len() - filled) as u64),
                )?;
                at(
                    journal,
                    original.before_at + cursor - original.range.offset,
                    &mut bytes[filled..filled + count],
                )?;
                cursor += count as u64;
                filled += count;
            }
            Ok(())
        }
    }
}

/// Whole old/new buffers use slice equality; interrupted mixed buffers retain
/// the exact per-byte rule. Equal lengths are required before zipped fallback.
fn bytes_are_old_or_new(current: &[u8], before: &[u8], after: &[u8]) -> bool {
    current.len() == before.len()
        && current.len() == after.len()
        && (current == before
            || current == after
            || current
                .iter()
                .zip(before)
                .zip(after)
                .all(|((&actual, &old), &new)| actual == old || actual == new))
}

/// Verify every selected actual byte is either its recorded old or new byte;
/// optionally require the complete framed selected target digest to match.
fn check_target<T: ReadSeek, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    records: &[JournalRecord],
    expected: Option<&[u8; 32]>,
) -> Result<[u8; 32]> {
    ensure!(
        target.byte_len()? == plan.image_length,
        "selected target length differs"
    );
    let mut current = vec![0; BUFFER];
    let mut before = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let mut digest = pin_hash()?;
    for record in records {
        frame(&mut digest, &record.range)?;
        let mut done = 0u64;
        while done < record.range.length {
            let count = usize::try_from((record.range.length - done).min(BUFFER as u64))?;
            at(target, record.range.offset + done, &mut current[..count])?;
            at(journal, record.before_at + done, &mut before[..count])?;
            read_after(journal, records, record, done, &mut after[..count])?;
            ensure!(
                bytes_are_old_or_new(&current[..count], &before[..count], &after[..count]),
                "selected target contains a foreign byte"
            );
            digest.update(&current[..count])?;
            done += count as u64;
        }
    }
    let digest = finish(digest)?;
    ensure!(
        expected.is_none_or(|expected| *expected == digest),
        "selected target digest differs"
    );
    Ok(digest)
}

/// One fixed working set for the entire replay. Every compared/written byte
/// is filled by the current IO before use; no previous span contents are used.
struct ReplayBuffers {
    current: Vec<u8>,
    before: Vec<u8>,
    after: Vec<u8>,
}

impl ReplayBuffers {
    fn new() -> Self {
        Self {
            current: vec![0; BUFFER],
            before: vec![0; BUFFER],
            after: vec![0; BUFFER],
        }
    }
}

fn write_span<T: DurableIo, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    records: &[JournalRecord],
    record: &JournalRecord,
    start: u64,
    length: u64,
    forward: bool,
    buffers: &mut ReplayBuffers,
) -> Result<()> {
    let ReplayBuffers {
        current,
        before,
        after,
    } = buffers;
    let mut done = 0u64;
    while done < length {
        let count = usize::try_from((length - done).min(BUFFER as u64))?;
        let within = start + done;
        let offset = record.range.offset + within;
        at(target, offset, &mut current[..count])?;
        at(journal, record.before_at + within, &mut before[..count])?;
        read_after(journal, records, record, within, &mut after[..count])?;
        ensure!(
            bytes_are_old_or_new(&current[..count], &before[..count], &after[..count]),
            "selected target changed before write"
        );
        let desired = if forward {
            &after[..count]
        } else {
            &before[..count]
        };
        if &current[..count] == desired {
            done += count as u64;
            continue;
        }
        // No flush or readback per chunk: replay accepts old or new bytes, the
        // caller flushes every span before the first granule and again after
        // it, and check_target then rereads every selected byte.
        target.seek(SeekFrom::Start(offset))?;
        ensure!(
            target.write(desired)? == count,
            "short selected target write"
        );
        done += count as u64;
    }
    Ok(())
}

fn execute<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    forward: bool,
    fresh: bool,
) -> Result<SelectedResult> {
    let records = load(journal, plan, ticket)?;
    execute_loaded(
        target, journal, plan, ticket, &records, forward, fresh, true,
    )
}

/// Both callers obtained these records through a complete load in this call.
/// Only the exclusive fresh path can retain that validation across its own
/// writes; legacy/recovery execution rehashes the immutable body afterward.
#[allow(clippy::too_many_arguments)]
fn execute_loaded<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    records: &[JournalRecord],
    forward: bool,
    fresh: bool,
    recheck_immutable: bool,
) -> Result<SelectedResult> {
    let (apply_intent, rollback_intent) = read_markers(journal, ticket)?;
    ensure!(
        !fresh || (!apply_intent && !rollback_intent),
        "fresh selected apply requires clear intent"
    );
    ensure!(
        fresh || !forward || apply_intent,
        "selected resume requires a durable apply intent"
    );
    ensure!(
        forward || apply_intent || rollback_intent,
        "selected rollback requires an existing durable operation intent"
    );
    ensure!(
        !forward || !rollback_intent,
        "selected rollback intent closes forward replay"
    );
    target.sync_all()?;
    check_target(
        target,
        journal,
        plan,
        records,
        fresh.then_some(&ticket.old_selected_sha256),
    )?;
    let intent = if forward {
        marker(b"N2RSAP01", ticket, &ticket.new_selected_sha256)
    } else {
        marker(b"N2RSRB01", ticket, &ticket.old_selected_sha256)
    };
    write_marker(journal, GRANULE, &intent)?;
    let mut replay_buffers = ReplayBuffers::new();
    for record in records {
        let skip = if record.range.offset == 0 { GRANULE } else { 0 };
        write_span(
            target,
            journal,
            records,
            record,
            skip,
            record.range.length - skip,
            forward,
            &mut replay_buffers,
        )?;
    }
    target.sync_all()?;
    if let Some(first) = records.first().filter(|r| r.range.offset == 0) {
        write_span(
            target,
            journal,
            records,
            first,
            0,
            GRANULE,
            forward,
            &mut replay_buffers,
        )?;
    }
    // The subsequent complete target check has its own fixed buffers. Release
    // replay scratch first so reuse does not double that phase's working set.
    drop(replay_buffers);
    target.sync_all()?;
    let expected = if forward {
        &ticket.new_selected_sha256
    } else {
        &ticket.old_selected_sha256
    };
    let selected_sha256 = check_target(target, journal, plan, records, Some(expected))?;
    if recheck_immutable {
        ensure!(
            hash_range(journal, BODY, ticket.journal_length - BODY)? == ticket.immutable_sha256,
            "selected journal changed during target writes"
        );
    }
    if !forward {
        let completed = marker(b"N2RSAB01", ticket, expected);
        write_marker(journal, 0, &completed)?;
    }
    Ok(SelectedResult {
        selected_sha256,
        selected_bytes: ticket.selected_bytes,
        range_count: ticket.range_count,
        replay_closed: !forward,
        whole_image_verified: false,
        conversion_qualified: false,
    })
}

pub fn apply<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    execute(target, journal, plan, ticket, true, true)
}

/// Fresh apply and durable handoff while one process retains exclusive owning
/// access to both resources. This is not a recovery API or persisted authority.
///
/// The caller must keep target/journal exclusively held (Windows share mode
/// zero where applicable), without clones, hidden mutable aliases, concurrent
/// workers or callback access that could mutate either resource. The callback
/// receives only the applied result and must durably save its receipt before
/// returning success. Exclusive `&mut` borrows span that callback and HND.
///
/// Entry validates every immutable byte, payload, descriptor and footer once.
/// Apply retains all pre/post target checks, original write order and flushes.
/// Under that continuous exclusive ownership the already validated immutable
/// body and post-target digest remain valid through the callback, so neither is
/// scanned again before HND. A callback error leaves the durable apply intent
/// open; all existing full-validation recovery entry points remain available.
pub fn apply_and_handoff_exclusive<
    T: DurableIo,
    J: DurableIo,
    F: FnOnce(&SelectedResult) -> Result<()>,
>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
    after_apply: F,
) -> Result<(SelectedResult, SelectedResult)> {
    let records = load(journal, plan, ticket)?;
    let applied = execute_loaded(target, journal, plan, ticket, &records, true, true, false)?;
    after_apply(&applied)?;
    // Preserve the handoff flush; no caller has received mutable device access
    // since the complete post-apply target verification above.
    target.sync_all()?;
    let completed = marker(b"N2RSHN01", ticket, &applied.selected_sha256);
    write_marker(journal, 0, &completed)?;
    let handed_off = SelectedResult {
        selected_sha256: applied.selected_sha256,
        selected_bytes: applied.selected_bytes,
        range_count: applied.range_count,
        replay_closed: true,
        whole_image_verified: false,
        conversion_qualified: false,
    };
    drop(records);
    Ok((applied, handed_off))
}
pub fn resume<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    execute(target, journal, plan, ticket, true, false)
}
pub fn rollback<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    execute(target, journal, plan, ticket, false, false)
}

/// Durable journal state, read after the complete immutable journal checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedLifecycle {
    PreparedClear,
    ApplyIntent,
    RollbackIntent,
    Handoff,
    Aborted,
}

/// Classify the markers of a fully verified journal. Foreign or torn markers
/// refuse; this never writes.
pub fn lifecycle<J: ReadSeek>(
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedLifecycle> {
    load(journal, plan, ticket)?;
    classify(journal, ticket)
}

fn classify<J: Read + Seek>(journal: &mut J, ticket: &SelectedTicket) -> Result<SelectedLifecycle> {
    let mut completed = [0u8; GRANULE as usize];
    let mut intent = [0u8; GRANULE as usize];
    at(journal, 0, &mut completed)?;
    at(journal, GRANULE, &mut intent)?;
    let zero = [0u8; GRANULE as usize];
    if completed == marker(b"N2RSHN01", ticket, &ticket.new_selected_sha256) {
        return Ok(SelectedLifecycle::Handoff);
    }
    if completed == marker(b"N2RSAB01", ticket, &ticket.old_selected_sha256) {
        return Ok(SelectedLifecycle::Aborted);
    }
    ensure!(
        completed == zero,
        "selected completion marker is foreign or torn"
    );
    if intent == zero {
        Ok(SelectedLifecycle::PreparedClear)
    } else if intent == marker(b"N2RSAP01", ticket, &ticket.new_selected_sha256) {
        Ok(SelectedLifecycle::ApplyIntent)
    } else if intent == marker(b"N2RSRB01", ticket, &ticket.old_selected_sha256) {
        Ok(SelectedLifecycle::RollbackIntent)
    } else {
        anyhow::bail!("selected intent marker is foreign or torn")
    }
}

/// Close replay for an apply that never wrote its intent: no target write can
/// have happened, and the complete selected old digest must still hold.
pub fn abandon<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    let records = load(journal, plan, ticket)?;
    let (apply_intent, rollback_intent) = read_markers(journal, ticket)?;
    ensure!(
        !apply_intent && !rollback_intent,
        "selected abandon requires a journal with no operation intent"
    );
    target.sync_all()?;
    let selected_sha256 = check_target(
        target,
        journal,
        plan,
        &records,
        Some(&ticket.old_selected_sha256),
    )?;
    let completed = marker(b"N2RSAB01", ticket, &ticket.old_selected_sha256);
    write_marker(journal, 0, &completed)?;
    Ok(SelectedResult {
        selected_sha256,
        selected_bytes: ticket.selected_bytes,
        range_count: ticket.range_count,
        replay_closed: true,
        whole_image_verified: false,
        conversion_qualified: false,
    })
}

/// Recheck a journal already closed by HND or ABT: the complete selected digest
/// must be the committed side. This writes nothing.
pub fn verify_closed<T: ReadSeek, J: ReadSeek>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<(SelectedLifecycle, SelectedResult)> {
    let records = load(journal, plan, ticket)?;
    let state = classify(journal, ticket)?;
    let expected = match state {
        SelectedLifecycle::Handoff => &ticket.new_selected_sha256,
        SelectedLifecycle::Aborted => &ticket.old_selected_sha256,
        _ => anyhow::bail!("selected journal is not closed by HND or ABT"),
    };
    let selected_sha256 = check_target(target, journal, plan, &records, Some(expected))?;
    Ok((
        state,
        SelectedResult {
            selected_sha256,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
        },
    ))
}

/// Permanently close raw replay before the caller permits a native mount.
pub fn handoff<T: DurableIo, J: DurableIo>(
    target: &mut T,
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<SelectedResult> {
    let records = load(journal, plan, ticket)?;
    let (apply_intent, rollback_intent) = read_markers(journal, ticket)?;
    ensure!(
        apply_intent && !rollback_intent,
        "selected handoff requires completed forward intent"
    );
    target.sync_all()?;
    let selected_sha256 = check_target(
        target,
        journal,
        plan,
        &records,
        Some(&ticket.new_selected_sha256),
    )?;
    ensure!(
        hash_range(journal, BODY, ticket.journal_length - BODY)? == ticket.immutable_sha256,
        "selected journal changed during handoff verification"
    );
    let completed = marker(b"N2RSHN01", ticket, &ticket.new_selected_sha256);
    write_marker(journal, 0, &completed)?;
    Ok(SelectedResult {
        selected_sha256,
        selected_bytes: ticket.selected_bytes,
        range_count: ticket.range_count,
        replay_closed: true,
        whole_image_verified: false,
        conversion_qualified: false,
    })
}
