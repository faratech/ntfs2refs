//! Selected-range reconstruction journal. This module opens no devices and
//! does not authenticate the selection, establish exclusion or certify a
//! filesystem. The caller owns those obligations and the trusted ticket.
use crate::lab_reconstruct::{DurableIo, ReadSeek};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

const GRANULE: u64 = 4096;
const BODY: u64 = 8192;
const HEADER: usize = 80;
const RECORD: usize = 80;
const FOOTER: usize = 80;
const BUFFER: usize = 1024 * 1024;
const MAX_RANGES: usize = 65_536;
const FORMAT: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedPlan {
    pub image_length: u64,
    pub ranges: Vec<SelectedRange>,
    pub max_selected_bytes: u64,
    pub max_journal_bytes: u64,
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
    after_at: u64,
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
fn finish(hash: Sha256) -> [u8; 32] {
    hash.finalize().into()
}
fn frame(hash: &mut Sha256, range: &SelectedRange) {
    hash.update(range.offset.to_le_bytes());
    hash.update(range.length.to_le_bytes());
}

impl SelectedPlan {
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
        let journal_length = BODY
            .checked_add(HEADER as u64)
            .and_then(|n| n.checked_add((self.ranges.len() as u64).checked_mul(RECORD as u64)?))
            .and_then(|n| n.checked_add(changed.checked_mul(2)?))
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
    };
    plan.validate()?;
    Ok(plan)
}

fn hash_range<R: Read + Seek>(io: &mut R, offset: u64, length: u64) -> Result<[u8; 32]> {
    io.seek(SeekFrom::Start(offset))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; BUFFER];
    let mut remaining = length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        io.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(finish(hash))
}

fn copy_selected<R: Read + Seek, J: Write>(
    input: &mut R,
    range: &SelectedRange,
    journal: &mut J,
    selected: &mut Sha256,
) -> Result<[u8; 32]> {
    input.seek(SeekFrom::Start(range.offset))?;
    frame(selected, range);
    let mut hash = Sha256::new();
    let mut buffer = vec![0; BUFFER];
    let mut remaining = range.length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(BUFFER as u64))?;
        input.read_exact(&mut buffer[..count])?;
        journal.write_all(&buffer[..count])?;
        selected.update(&buffer[..count]);
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(finish(hash))
}

/// Create and durably verify a new external journal. Only selected ranges are
/// read from the two images. Ticket issuance follows an independent readback.
pub fn prepare<R: ReadSeek, S: ReadSeek, J: DurableIo>(
    source: &mut R,
    candidate: &mut S,
    journal: &mut J,
    plan: &SelectedPlan,
) -> Result<SelectedTicket> {
    let (changed, journal_length) = plan.validate()?;
    ensure!(
        source.byte_len()? == plan.image_length
            && candidate.byte_len()? == plan.image_length
            && journal.byte_len()? == 0,
        "selected inputs differ in length or journal is not empty"
    );
    let mut header = [0u8; HEADER];
    header[..8].copy_from_slice(b"N2RSEL01");
    put_u32(&mut header, 8, FORMAT);
    put_u32(&mut header, 12, u32::try_from(plan.ranges.len())?);
    put_u64(&mut header, 16, plan.image_length);
    put_u64(&mut header, 24, changed);
    put_u64(&mut header, 32, journal_length);
    journal.seek(SeekFrom::Start(0))?;
    journal.write_all(&[0; BODY as usize])?;
    journal.write_all(&header)?;
    let mut old_selected = Sha256::new();
    let mut new_selected = Sha256::new();
    for range in &plan.ranges {
        let record_at = journal.stream_position()?;
        journal.write_all(&[0; RECORD])?;
        let old_hash = copy_selected(source, range, journal, &mut old_selected)?;
        let new_hash = copy_selected(candidate, range, journal, &mut new_selected)?;
        let next = journal.stream_position()?;
        let mut record = [0u8; RECORD];
        put_u64(&mut record, 0, range.offset);
        put_u64(&mut record, 8, range.length);
        record[16..48].copy_from_slice(&old_hash);
        record[48..80].copy_from_slice(&new_hash);
        journal.seek(SeekFrom::Start(record_at))?;
        journal.write_all(&record)?;
        journal.seek(SeekFrom::Start(next))?;
    }
    let old_selected_sha256 = finish(old_selected);
    let new_selected_sha256 = finish(new_selected);
    let mut footer = [0u8; FOOTER];
    footer[..8].copy_from_slice(b"N2RSEND1");
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
    let ticket = SelectedTicket {
        image_length: plan.image_length,
        selected_bytes: changed,
        range_count: u32::try_from(plan.ranges.len())?,
        journal_length,
        immutable_sha256: hash_range(journal, BODY, journal_length - BODY)?,
        old_selected_sha256,
        new_selected_sha256,
        whole_image_verified: false,
    };
    load(journal, plan, &ticket)?;
    let mut markers = [0u8; BODY as usize];
    at(journal, 0, &mut markers)?;
    ensure!(
        markers.iter().all(|&b| b == 0),
        "selected journal markers are not clear"
    );
    Ok(ticket)
}

/// Recheck the pinned complete immutable journal and each payload. Even a
/// valid serialized ticket must be trusted independently by the caller.
fn load<J: ReadSeek>(
    journal: &mut J,
    plan: &SelectedPlan,
    ticket: &SelectedTicket,
) -> Result<Vec<JournalRecord>> {
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
    ensure!(
        hash_range(journal, BODY, journal_length - BODY)? == ticket.immutable_sha256,
        "selected immutable journal differs from trusted ticket"
    );
    let mut header = [0u8; HEADER];
    at(journal, BODY, &mut header)?;
    ensure!(
        &header[..8] == b"N2RSEL01"
            && get_u32(&header, 8) == FORMAT
            && get_u32(&header, 12) == ticket.range_count
            && get_u64(&header, 16) == plan.image_length
            && get_u64(&header, 24) == changed
            && get_u64(&header, 32) == journal_length
            && header[40..].iter().all(|&b| b == 0),
        "selected journal header differs"
    );
    let mut records = Vec::with_capacity(plan.ranges.len());
    let mut old_selected = Sha256::new();
    let mut new_selected = Sha256::new();
    let mut buffer = vec![0; BUFFER];
    for range in &plan.ranges {
        let mut record = [0u8; RECORD];
        journal.read_exact(&mut record)?;
        ensure!(
            get_u64(&record, 0) == range.offset && get_u64(&record, 8) == range.length,
            "selected journal range differs"
        );
        let before_at = journal.stream_position()?;
        let after_at = before_at
            .checked_add(range.length)
            .context("selected journal offset overflow")?;
        let next = after_at
            .checked_add(range.length)
            .context("selected journal offset overflow")?;
        ensure!(
            next <= journal_length - FOOTER as u64,
            "selected journal payload truncated"
        );
        for (offset, selected, expected) in [
            (before_at, &mut old_selected, &record[16..48]),
            (after_at, &mut new_selected, &record[48..80]),
        ] {
            journal.seek(SeekFrom::Start(offset))?;
            frame(selected, range);
            let mut hash = Sha256::new();
            let mut remaining = range.length;
            while remaining > 0 {
                let count = usize::try_from(remaining.min(BUFFER as u64))?;
                journal.read_exact(&mut buffer[..count])?;
                selected.update(&buffer[..count]);
                hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            ensure!(
                finish(hash).as_slice() == expected,
                "selected journal payload hash differs"
            );
        }
        records.push(JournalRecord {
            range: range.clone(),
            before_at,
            after_at,
        });
    }
    let mut footer = [0u8; FOOTER];
    journal.read_exact(&mut footer)?;
    ensure!(
        &footer[..8] == b"N2RSEND1"
            && footer[8..40] == ticket.old_selected_sha256
            && footer[40..72] == ticket.new_selected_sha256
            && get_u64(&footer, 72) == journal_length
            && finish(old_selected) == ticket.old_selected_sha256
            && finish(new_selected) == ticket.new_selected_sha256
            && journal.stream_position()? == journal_length,
        "selected journal footer or selected digest differs"
    );
    Ok(records)
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
    let mut digest = Sha256::new();
    for record in records {
        frame(&mut digest, &record.range);
        let mut done = 0u64;
        while done < record.range.length {
            let count = usize::try_from((record.range.length - done).min(BUFFER as u64))?;
            at(target, record.range.offset + done, &mut current[..count])?;
            at(journal, record.before_at + done, &mut before[..count])?;
            at(journal, record.after_at + done, &mut after[..count])?;
            ensure!(
                current[..count]
                    .iter()
                    .zip(&before[..count])
                    .zip(&after[..count])
                    .all(|((&actual, &old), &new)| actual == old || actual == new),
                "selected target contains a foreign byte"
            );
            digest.update(&current[..count]);
            done += count as u64;
        }
    }
    let digest = finish(digest);
    ensure!(
        expected.is_none_or(|expected| *expected == digest),
        "selected target digest differs"
    );
    Ok(digest)
}

fn write_span<T: DurableIo, J: Read + Seek>(
    target: &mut T,
    journal: &mut J,
    record: &JournalRecord,
    start: u64,
    length: u64,
    forward: bool,
) -> Result<()> {
    let mut current = vec![0; BUFFER];
    let mut before = vec![0; BUFFER];
    let mut after = vec![0; BUFFER];
    let mut done = 0u64;
    while done < length {
        let count = usize::try_from((length - done).min(BUFFER as u64))?;
        let within = start + done;
        let offset = record.range.offset + within;
        at(target, offset, &mut current[..count])?;
        at(journal, record.before_at + within, &mut before[..count])?;
        at(journal, record.after_at + within, &mut after[..count])?;
        ensure!(
            current[..count]
                .iter()
                .zip(&before[..count])
                .zip(&after[..count])
                .all(|((&actual, &old), &new)| actual == old || actual == new),
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
        target.seek(SeekFrom::Start(offset))?;
        ensure!(
            target.write(desired)? == count,
            "short selected target write"
        );
        target.sync_all()?;
        at(target, offset, &mut current[..count])?;
        ensure!(
            &current[..count] == desired,
            "selected target write readback differs"
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
        &records,
        fresh.then_some(&ticket.old_selected_sha256),
    )?;
    let intent = if forward {
        marker(b"N2RSAP01", ticket, &ticket.new_selected_sha256)
    } else {
        marker(b"N2RSRB01", ticket, &ticket.old_selected_sha256)
    };
    write_marker(journal, GRANULE, &intent)?;
    for record in &records {
        let skip = if record.range.offset == 0 { GRANULE } else { 0 };
        write_span(
            target,
            journal,
            record,
            skip,
            record.range.length - skip,
            forward,
        )?;
    }
    target.sync_all()?;
    if let Some(first) = records.first().filter(|r| r.range.offset == 0) {
        write_span(target, journal, first, 0, GRANULE, forward)?;
    }
    target.sync_all()?;
    let expected = if forward {
        &ticket.new_selected_sha256
    } else {
        &ticket.old_selected_sha256
    };
    let selected_sha256 = check_target(target, journal, plan, &records, Some(expected))?;
    ensure!(
        hash_range(journal, BODY, ticket.journal_length - BODY)? == ticket.immutable_sha256,
        "selected journal changed during target writes"
    );
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
