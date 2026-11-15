//! Append-only accepted capture facts, queried through the same exclusive file.
//! This is not a source certificate, journal ticket or write/replay capability.
use crate::ntfs_inspect::paged_storage::{SourceRamLease, SourceScratch};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

const HEADER: u64 = 128;
const ROW: u64 = 80;
const FOOTER: u64 = 128;
const MAGIC: [u8; 8] = *b"N2RCAP02";
const END: [u8; 8] = *b"N2RCEND2";

/// Runtime facts supplied only by the fresh capture engine after comparison.
/// No deserializer exists. Flags still require their independent data/OLD/COPY
/// checks in the enclosing capture and journal preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CaptureIndexRange {
    pub offset: u64,
    pub length: u64,
    pub packed_offset: u64,
    pub new_is_zero: bool,
    pub old_is_zero: bool,
    pub old_is_source_free: bool,
    pub copy_source_offset: Option<u64>,
}
impl CaptureIndexRange {
    fn end(self) -> Result<u64> {
        self.offset
            .checked_add(self.length)
            .context("capture index range overflow")
    }
    fn literal_bytes(self) -> u64 {
        if self.new_is_zero || self.copy_source_offset.is_some() {
            0
        } else {
            self.length
        }
    }
    fn validate(self, image: u64) -> Result<()> {
        ensure!(
            self.length > 0
                && self.offset.is_multiple_of(4096)
                && self.length.is_multiple_of(4096)
                && self.end()? <= image
                && !(self.new_is_zero && self.copy_source_offset.is_some()),
            "capture index range bounds/encoding differ"
        );
        if let Some(source) = self.copy_source_offset {
            ensure!(
                source.is_multiple_of(4096)
                    && source
                        .checked_add(self.length)
                        .is_some_and(|end| end <= self.offset),
                "COPY source must precede its destination and stay inside captured address space"
            );
        }
        ensure!(
            !self.old_is_source_free
                || (!self.old_is_zero
                    && self.offset >= 4096
                    && self.end()? <= image.saturating_sub(4096)),
            "source-free row overlaps OLD-zero credit or protected bookend"
        );
        Ok(())
    }
}

/// A reserved append slot. Dropping it without acceptance leaves its owning
/// writer unfinished; no scratch credit or retry is inferred from that drop.
pub(crate) struct PendingCaptureRange {
    owner: [u8; 24],
    generation: u64,
    range: CaptureIndexRange,
    extends: bool,
    projected: CaptureIndexRange,
}
impl PendingCaptureRange {
    pub(crate) fn extends_previous(&self) -> bool {
        self.extends
    }
    pub(crate) fn projected_range(&self) -> CaptureIndexRange {
        self.projected
    }
}

/// Descriptive, bounded preflight only. These rows cannot supply an acceptance
/// token or bypass the writer's actual OLD/COPY prefix checks during commit.
#[derive(Clone, Copy)]
pub(crate) struct CaptureBatchRange {
    pub range: CaptureIndexRange,
    pub may_extend_previous: bool,
    pub projected: CaptureIndexRange,
    pub extends_previous: bool,
}

fn project_range(
    image: u64,
    previous: Option<CaptureIndexRange>,
    range: CaptureIndexRange,
    may_extend_previous: bool,
) -> Result<(bool, CaptureIndexRange)> {
    range.validate(image)?;
    let extends = if let Some(tail) = previous {
        ensure!(
            range.offset >= tail.end()?,
            "accepted capture ranges overlap or regress"
        );
        may_extend_previous
            && range.offset == tail.end()?
            && range.new_is_zero == tail.new_is_zero
            && range.old_is_source_free == tail.old_is_source_free
            && tail.copy_source_offset.is_none_or(|source| {
                source
                    .checked_add(tail.length)
                    .and_then(|end| end.checked_add(range.length))
                    .is_some_and(|end| end <= tail.offset)
            })
            && match (tail.copy_source_offset, range.copy_source_offset) {
                (None, None) => true,
                (Some(a), Some(b)) => a.checked_add(tail.length) == Some(b),
                _ => false,
            }
    } else {
        false
    };
    let projected = if extends {
        let mut tail = previous.context("projected capture tail absent")?;
        tail.length = tail
            .length
            .checked_add(range.length)
            .context("projected range overflow")?;
        tail.old_is_zero &= range.old_is_zero;
        tail.validate(image)?;
        tail
    } else {
        range
    };
    Ok((extends, projected))
}

#[derive(Clone, PartialEq, Eq)]
struct Snapshot {
    id: String,
    bytes: u64,
    modified: SystemTime,
    attributes: u32,
}
impl Snapshot {
    fn observe(file: &File) -> Result<Self> {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && n2r_win32::file_storage::number_of_links(file)? == 1,
            "capture index must be an ordinary single-link file"
        );
        Ok(Self {
            id: n2r_win32::file_storage::file_id_info(file)?,
            bytes: metadata.len(),
            modified: metadata.modified()?,
            attributes: metadata.file_attributes(),
        })
    }
}

pub(crate) struct OwnedCaptureIndex {
    file: File,
    path: PathBuf,
    parents: Vec<File>,
    parent_id: String,
    canonical_parent: PathBuf,
    _ram: SourceRamLease,
    owner: [u8; 24],
    image: u64,
    rows: u64,
    changed: u64,
    packed: u64,
    old_zero: u64,
    source_free: u64,
    tail: Option<CaptureIndexRange>,
    generation: u64,
    pending: Option<u64>,
    prepaid_rows: u64,
    batch_active: bool,
    hash: Sha256,
    poisoned: bool,
    artifact: Option<crate::artifact_arena::ArtifactPathPermit>,
    resident: ResidentRows,
}
#[derive(Serialize)]
pub(crate) struct CaptureIndexPin {
    pub schema_version: u32,
    pub path: PathBuf,
    pub bytes: u64,
    pub file_sha256: String,
    pub image_length: u64,
    pub ranges: u64,
    pub changed_bytes: u64,
    pub packed_bytes: u64,
    pub old_zero_bytes: u64,
    pub source_free_bytes: u64,
    pub serialized_facts_grant_authority: bool,
}
/// The completed domain retains the same kernel file object through a reduced
/// access handle. There is no constructor from a pin or saved success JSON.
pub(crate) struct ClosedCaptureIndex {
    file: RefCell<File>,
    pin: CaptureIndexPin,
    snapshot: Snapshot,
    _parents: Vec<File>,
    parent_id: String,
    canonical_parent: PathBuf,
    _ram: SourceRamLease,
    artifact: crate::artifact_arena::ArtifactLease,
    // The rows this process wrote to the file, when all of them were kept.
    resident: ResidentRows,
    last_full: n2r_win32::verify_policy::LastFull,
}

fn parents(path: &Path) -> Result<(Vec<File>, String, PathBuf)> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "fresh absolute capture index path required"
    );
    let parent = path.parent().context("capture index parent absent")?;
    let leaf = path
        .file_name()
        .context("capture index leaf absent")?
        .to_string_lossy();
    ensure!(
        !leaf.contains([':', '\0']),
        "capture index alternate-stream path refused"
    );
    let mut held = Vec::new();
    for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "ordinary capture index ancestry required"
        );
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(ancestor)?;
        ensure!(
            file.metadata()?.is_dir() && file.metadata()?.file_attributes() & 0x400 == 0,
            "capture index parent handle differs"
        );
        held.try_reserve(1)?;
        held.push(file);
    }
    let id = n2r_win32::file_storage::file_id_info(
        held.first().context("capture parent handle absent")?,
    )?;
    Ok((held, id, fs::canonicalize(parent)?))
}
fn ordinary_parents(path: &Path, held: &[File], id: &str, canonical: &Path) -> Result<()> {
    let parent = path.parent().context("capture index parent absent")?;
    ensure!(
        fs::canonicalize(parent)? == canonical
            && n2r_win32::file_storage::file_id_info(
                held.first().context("capture parent owner absent")?
            )? == id,
        "capture index parent identity changed"
    );
    for file in held {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "capture index ancestry changed"
        );
    }
    Ok(())
}
fn header(image: u64) -> [u8; HEADER as usize] {
    let mut out = [0; HEADER as usize];
    out[..8].copy_from_slice(&MAGIC);
    out[8..12].copy_from_slice(&2u32.to_le_bytes());
    out[12..16].copy_from_slice(&(ROW as u32).to_le_bytes());
    out[16..24].copy_from_slice(&image.to_le_bytes());
    out
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn row_digest(image: u64, bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"n2r-owned-capture-index-row-v2\0");
    hash.update(image.to_le_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
fn encode(range: CaptureIndexRange, ordinal: u64, image: u64) -> [u8; ROW as usize] {
    let mut out = [0; ROW as usize];
    out[..8].copy_from_slice(&range.offset.to_le_bytes());
    out[8..16].copy_from_slice(&range.length.to_le_bytes());
    out[16..24].copy_from_slice(&range.packed_offset.to_le_bytes());
    let flags = u64::from(range.new_is_zero)
        | (u64::from(range.old_is_zero) << 1)
        | (u64::from(range.copy_source_offset.is_some()) << 2)
        | (u64::from(range.old_is_source_free) << 3);
    out[24..32].copy_from_slice(&flags.to_le_bytes());
    out[32..40].copy_from_slice(&range.copy_source_offset.unwrap_or(0).to_le_bytes());
    out[40..48].copy_from_slice(&ordinal.to_le_bytes());
    let digest = row_digest(image, &out[..48]);
    out[48..].copy_from_slice(&digest);
    out
}
/// A row as it was read from the file: its hash, ordinal and flags are checked.
fn decode(bytes: &[u8; ROW as usize], ordinal: u64, image: u64) -> Result<CaptureIndexRange> {
    ensure!(
        bytes[48..] == row_digest(image, &bytes[..48]),
        "capture index row hash/ordinal/flags differ"
    );
    decode_held(bytes, ordinal, image)
}
/// A row this object encoded and still holds in memory. The row's hash
/// guards it in the file: it is checked when a row is read from there, and
/// the file as a whole when it is closed. Hashing a held row again on every
/// step of every binary search over the rows was 22 s of a full Windows
/// conversion. The ordinal and the flags are checked here as there.
fn decode_held(bytes: &[u8; ROW as usize], ordinal: u64, image: u64) -> Result<CaptureIndexRange> {
    let flags = u64_at(bytes, 24);
    ensure!(
        flags & !15 == 0 && u64_at(bytes, 40) == ordinal,
        "capture index row hash/ordinal/flags differ"
    );
    ensure!(
        flags & 4 != 0 || u64_at(bytes, 32) == 0,
        "capture index absent COPY coordinate differs"
    );
    let range = CaptureIndexRange {
        offset: u64_at(bytes, 0),
        length: u64_at(bytes, 8),
        packed_offset: u64_at(bytes, 16),
        new_is_zero: flags & 1 != 0,
        old_is_zero: flags & 2 != 0,
        old_is_source_free: flags & 8 != 0,
        copy_source_offset: (flags & 4 != 0).then(|| u64_at(bytes, 32)),
    };
    range.validate(image)?;
    Ok(range)
}
/// The rows written so far, as written, so a lookup of an earlier row does
/// not cost a seek and a read of the file. An optimization only: once it
/// cannot grow (the allocation is refused, or it would pass
/// `MAX_RESIDENT_ROWS`) it stops and later rows are read from the file.
#[derive(Default)]
struct ResidentRows {
    bytes: Vec<u8>,
    stopped: bool,
}
/// 256 MiB of rows: several million changed ranges.
const MAX_RESIDENT_ROWS: u64 = 256 * 1024 * 1024 / ROW;
impl ResidentRows {
    fn len(&self) -> u64 {
        self.bytes.len() as u64 / ROW
    }
    /// Called with every row in order, starting from the first.
    fn push(&mut self, row: &[u8; ROW as usize]) {
        if self.stopped {
            return;
        }
        if self.len() >= MAX_RESIDENT_ROWS || self.bytes.try_reserve(ROW as usize).is_err() {
            self.stopped = true;
            return;
        }
        self.bytes.extend_from_slice(row);
    }
    fn get(&self, ordinal: u64, image: u64) -> Option<Result<CaptureIndexRange>> {
        let start = usize::try_from(ordinal.checked_mul(ROW)?).ok()?;
        let row: &[u8; ROW as usize] = self
            .bytes
            .get(start..start.checked_add(ROW as usize)?)?
            .try_into()
            .ok()?;
        Some(decode_held(row, ordinal, image))
    }
}

fn read_row(file: &mut File, ordinal: u64, image: u64) -> Result<CaptureIndexRange> {
    let at = ordinal
        .checked_mul(ROW)
        .and_then(|n| n.checked_add(HEADER))
        .context("capture index offset overflow")?;
    file.seek(SeekFrom::Start(at))?;
    let mut bytes = [0; ROW as usize];
    file.read_exact(&mut bytes)?;
    decode(&bytes, ordinal, image)
}

fn covers_prefix(
    rows: u64,
    source: u64,
    length: u64,
    destination: u64,
    image: u64,
    mut range: impl FnMut(u64) -> Result<CaptureIndexRange>,
) -> Result<bool> {
    let end = source
        .checked_add(length)
        .context("COPY prefix range overflow")?;
    if length == 0
        || !source.is_multiple_of(4096)
        || !length.is_multiple_of(4096)
        || end > destination
        || destination > image
    {
        return Ok(false);
    }
    let (mut low, mut high) = (0, rows);
    while low < high {
        let middle = low + (high - low) / 2;
        if range(middle)?.end()? <= source {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    let mut cursor = source;
    while cursor < end {
        if low == rows {
            return Ok(false);
        }
        let row = range(low)?;
        if row.offset > cursor || row.old_is_source_free {
            return Ok(false);
        }
        cursor = end.min(row.end()?);
        low += 1;
    }
    Ok(true)
}

impl OwnedCaptureIndex {
    pub(crate) fn create(
        path: &Path,
        image: u64,
        scratch: &SourceScratch,
        group: &crate::artifact_arena::ArtifactGroupPermit,
    ) -> Result<Self> {
        ensure!(
            image > 0 && image.is_multiple_of(4096) && image <= i64::MAX as u64,
            "capture index image geometry differs"
        );
        let scratch_group = scratch
            .artifact_group()
            .context("capture index requires its actual arena")?;
        ensure!(
            group.group() == crate::artifact_arena::ArtifactGroup::Capture
                && group.arena().same_arena(scratch_group.arena()),
            "capture index arena association differs"
        );
        // Reserve the actual path before CreateNew, including its eventual footer.
        let artifact = group.reserve_file(path, HEADER + FOOTER)?;
        let path = artifact.path().to_path_buf();
        let path_bytes = path.as_os_str().as_encoded_bytes().len() as u64;
        let ram = scratch.lease_ram(
            path_bytes
                .checked_mul(4096)
                .and_then(|n| n.checked_add(65536))
                .context("capture index ancestry RAM overflow")?,
        )?;
        let (held, parent_id, canonical_parent) = parents(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&path)?;
        let snapshot = Snapshot::observe(&file)?;
        ensure!(snapshot.bytes == 0, "capture index is not fresh");
        let owner: [u8; 24] = hex::decode(&snapshot.id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("capture index identity width differs"))?;
        let bytes = header(image);
        file.write_all(&bytes)?;
        let mut hash = Sha256::new();
        hash.update(bytes);
        Ok(Self {
            file,
            path,
            parents: held,
            parent_id,
            canonical_parent,
            _ram: ram,
            owner,
            image,
            rows: 0,
            changed: 0,
            packed: 0,
            old_zero: 0,
            source_free: 0,
            tail: None,
            generation: 0,
            pending: None,
            prepaid_rows: 0,
            batch_active: false,
            hash,
            poisoned: false,
            artifact: Some(artifact),
            resident: ResidentRows::default(),
        })
    }
    pub(crate) fn len(&self) -> u64 {
        self.rows + u64::from(self.tail.is_some())
    }
    pub(crate) fn packed_bytes(&self) -> u64 {
        self.packed
    }
    pub(crate) fn last_range(&self) -> Option<CaptureIndexRange> {
        self.tail
    }

    pub(crate) fn project_batch_range(
        &self,
        previous: Option<CaptureIndexRange>,
        range: CaptureIndexRange,
        may_extend_previous: bool,
    ) -> Result<(bool, CaptureIndexRange)> {
        ensure!(
            !self.poisoned
                && self.pending.is_none()
                && self.prepaid_rows == 0
                && !self.batch_active,
            "incomplete capture writer cannot plan a batch"
        );
        let packed = previous.map_or(Ok(self.packed), |tail| {
            tail.packed_offset
                .checked_add(tail.literal_bytes())
                .context("planned packed prefix overflow")
        })?;
        ensure!(
            range.packed_offset == packed,
            "planned capture packed prefix differs"
        );
        project_range(self.image, previous, range, may_extend_previous)
    }

    /// Query committed OLD rows plus already compared, earlier batch granules.
    /// This is preflight only; reserve_next rechecks the committed prefix after
    /// those granules have actually been accepted in their original order.
    pub(crate) fn covers_prior_with_batch(
        &mut self,
        batch: &[CaptureBatchRange],
        source: u64,
        length: u64,
        destination: u64,
    ) -> Result<bool> {
        ensure!(
            !self.poisoned
                && self.pending.is_none()
                && self.prepaid_rows == 0
                && !self.batch_active,
            "incomplete capture prefix cannot plan COPY membership"
        );
        let committed = self.len();
        let rows = committed
            .checked_add(batch.len() as u64)
            .context("capture batch row overflow")?;
        covers_prefix(rows, source, length, destination, self.image, |ordinal| {
            if ordinal < committed {
                self.range(ordinal)
            } else {
                Ok(batch[usize::try_from(ordinal - committed)?].range)
            }
        })
    }

    /// Pay only the exact additional rows in one already classified chunk.
    /// No speculative blanket growth or allocation credit is introduced.
    pub(crate) fn reserve_batch_rows(&mut self, rows: u64) -> Result<()> {
        self.require_batch_complete()?;
        ensure!(
            rows <= (crate::ntfs_inspect::SESSION_READ_BYTES / 4096) as u64,
            "capture row batch exceeds the bounded comparison chunk"
        );
        if rows != 0 {
            self.artifact
                .as_mut()
                .context("capture index arena permit absent")?
                .extend(
                    rows.checked_mul(ROW)
                        .context("capture batch reservation overflow")?,
                )?;
            self.prepaid_rows = rows;
        }
        self.batch_active = true;
        Ok(())
    }

    pub(crate) fn require_batch_complete(&self) -> Result<()> {
        ensure!(
            !self.poisoned
                && self.pending.is_none()
                && self.prepaid_rows == 0
                && !self.batch_active,
            "capture row batch has unconsumed reservations or acceptance"
        );
        Ok(())
    }

    pub(crate) fn finish_batch(&mut self) -> Result<()> {
        ensure!(
            !self.poisoned && self.pending.is_none() && self.prepaid_rows == 0 && self.batch_active,
            "capture row batch did not consume its exact admission"
        );
        self.batch_active = false;
        Ok(())
    }

    /// Reserve before the backing/index write. The fresh capture engine calls
    /// append_accepted only AFTER actual comparison, capacity guard and backing
    /// acceptance. A failed/dropped pending token cannot be retried or closed.
    pub(crate) fn reserve_next(
        &mut self,
        range: CaptureIndexRange,
        may_extend_previous: bool,
    ) -> Result<PendingCaptureRange> {
        ensure!(
            !self.poisoned && self.pending.is_none(),
            "capture index writer is incomplete"
        );
        range.validate(self.image)?;
        if let Some(source) = range.copy_source_offset {
            ensure!(
                self.covers_prior(source, range.length, range.offset)?,
                "COPY source is not completely inside the already accepted changed prefix"
            );
        }
        ensure!(
            range.packed_offset == self.packed,
            "accepted capture packed prefix differs"
        );
        let (extends, projected) =
            project_range(self.image, self.tail, range, may_extend_previous)?;
        if !extends {
            if self.batch_active {
                ensure!(
                    self.prepaid_rows != 0,
                    "capture row exceeds the admitted batch"
                );
                self.prepaid_rows -= 1;
            } else {
                self.artifact
                    .as_mut()
                    .context("capture index arena permit absent")?
                    .extend(ROW)?;
            }
        }
        let generation = self
            .generation
            .checked_add(1)
            .context("capture index acceptance generation overflow")?;
        self.generation = generation;
        self.pending = Some(generation);
        Ok(PendingCaptureRange {
            owner: self.owner,
            generation,
            range,
            extends,
            projected,
        })
    }
    fn flush_tail(&mut self) -> Result<()> {
        if let Some(tail) = self.tail.take() {
            let bytes = encode(tail, self.rows, self.image);
            let offset = self
                .rows
                .checked_mul(ROW)
                .and_then(|n| n.checked_add(HEADER))
                .context("capture index append overflow")?;
            ensure!(
                self.file.metadata()?.len() == offset,
                "capture index append prefix changed"
            );
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(&bytes)?;
            self.hash.update(bytes);
            self.resident.push(&bytes);
            self.rows = self
                .rows
                .checked_add(1)
                .context("capture index count overflow")?;
        }
        Ok(())
    }
    pub(crate) fn append_accepted(&mut self, pending: PendingCaptureRange) -> Result<()> {
        ensure!(
            !self.poisoned
                && pending.owner == self.owner
                && self.pending == Some(pending.generation),
            "capture acceptance token belongs to another/incomplete writer"
        );
        self.poisoned = true;
        let range = pending.range;
        let changed = self
            .changed
            .checked_add(range.length)
            .context("capture changed-byte overflow")?;
        let packed = self
            .packed
            .checked_add(range.literal_bytes())
            .context("capture packed-byte overflow")?;
        let previous = if pending.extends { self.tail } else { None };
        let old_zero = self
            .old_zero
            .checked_sub(previous.filter(|r| r.old_is_zero).map_or(0, |r| r.length))
            .and_then(|n| {
                n.checked_add(if pending.projected.old_is_zero {
                    pending.projected.length
                } else {
                    0
                })
            })
            .context("capture OLD-zero range credit overflow")?;
        let source_free = self
            .source_free
            .checked_sub(
                previous
                    .filter(|r| r.old_is_source_free)
                    .map_or(0, |r| r.length),
            )
            .and_then(|n| {
                n.checked_add(if pending.projected.old_is_source_free {
                    pending.projected.length
                } else {
                    0
                })
            })
            .context("capture source-free range credit overflow")?;
        if pending.extends {
            let tail = self
                .tail
                .as_mut()
                .context("coalesced capture tail absent")?;
            tail.length = tail
                .length
                .checked_add(range.length)
                .context("coalesced capture range overflow")?;
            tail.old_is_zero &= range.old_is_zero;
            tail.validate(self.image)?;
        } else {
            self.flush_tail()?;
            self.tail = Some(range);
        }
        self.changed = changed;
        self.packed = packed;
        self.old_zero = old_zero;
        self.source_free = source_free;
        self.pending = None;
        self.poisoned = false;
        Ok(())
    }
    fn range(&mut self, ordinal: u64) -> Result<CaptureIndexRange> {
        ensure!(
            ordinal < self.len(),
            "capture prefix ordinal outside accepted domain"
        );
        if ordinal == self.rows {
            self.tail.context("capture tail absent")
        } else if let Some(row) = self.resident.get(ordinal, self.image) {
            row
        } else {
            read_row(&mut self.file, ordinal, self.image)
        }
    }
    /// Only accepted actual changed OLD destinations can supply COPY. A source
    /// ending after the new destination, an unaccepted token or a gap refuses.
    pub(crate) fn covers_prior(
        &mut self,
        source: u64,
        length: u64,
        destination: u64,
    ) -> Result<bool> {
        ensure!(
            !self.poisoned && self.pending.is_none(),
            "incomplete capture prefix cannot authorize COPY membership"
        );
        covers_prefix(
            self.len(),
            source,
            length,
            destination,
            self.image,
            |ordinal| self.range(ordinal),
        )
    }
    pub(crate) fn finish(mut self, scratch: &SourceScratch) -> Result<ClosedCaptureIndex> {
        self.require_batch_complete()?;
        ensure!(
            !self.poisoned && self.pending.is_none(),
            "incomplete capture index cannot close"
        );
        self.poisoned = true;
        self.flush_tail()?;
        let mut footer = [0; FOOTER as usize];
        footer[..8].copy_from_slice(&END);
        footer[8..16].copy_from_slice(&self.rows.to_le_bytes());
        footer[16..24].copy_from_slice(&self.changed.to_le_bytes());
        footer[24..32].copy_from_slice(&self.packed.to_le_bytes());
        footer[32..40].copy_from_slice(&self.image.to_le_bytes());
        footer[40..72].copy_from_slice(&self.hash.clone().finalize());
        footer[72..80].copy_from_slice(&self.old_zero.to_le_bytes());
        footer[80..88].copy_from_slice(&self.source_free.to_le_bytes());
        let at = self
            .rows
            .checked_mul(ROW)
            .and_then(|n| n.checked_add(HEADER))
            .context("capture index footer overflow")?;
        self.file.seek(SeekFrom::Start(at))?;
        self.file.write_all(&footer)?;
        self.file.sync_all()?;
        self.hash.update(footer);
        let sha256 = hex::encode(self.hash.clone().finalize());
        ordinary_parents(
            &self.path,
            &self.parents,
            &self.parent_id,
            &self.canonical_parent,
        )?;
        let bytes = at
            .checked_add(FOOTER)
            .context("capture index length overflow")?;
        // Use the same arena-backed scratch as create() while normalizing the
        // exact writer before readonly duplicates retain its FILE_OBJECT.
        {
            let group = scratch
                .artifact_group()
                .context("capture index requires its actual arena")?;
            let _allocation_ram = scratch.lease_ram(512 * 1024)?;
            let _allocation = n2r_win32::file_storage::normalize_allocation_at_eof(
                &self.file,
                bytes,
                bytes,
                group.arena().allocation_slack_bytes(),
            )
            .context("normalize owned capture index allocation before sealing")?;
        }
        let readonly = n2r_win32::file_storage::duplicate_readonly(&self.file)?;
        let snapshot = Snapshot::observe(&readonly)?;
        ensure!(
            snapshot.bytes == bytes,
            "capture index final length differs"
        );
        drop(self.file);
        let artifact = self
            .artifact
            .take()
            .context("closed capture arena permit absent")?
            .verify_closed_handle(&readonly, &sha256)?;
        let value = ClosedCaptureIndex {
            file: RefCell::new(readonly),
            pin: CaptureIndexPin {
                schema_version: 2,
                path: self.path,
                bytes: snapshot.bytes,
                file_sha256: sha256,
                image_length: self.image,
                ranges: self.rows,
                changed_bytes: self.changed,
                packed_bytes: self.packed,
                old_zero_bytes: self.old_zero,
                source_free_bytes: self.source_free,
                serialized_facts_grant_authority: false,
            },
            snapshot,
            _parents: self.parents,
            parent_id: self.parent_id,
            canonical_parent: self.canonical_parent,
            _ram: self._ram,
            artifact,
            resident: self.resident,
            last_full: n2r_win32::verify_policy::LastFull::new(),
        };
        value.revalidate_in_full()?;
        Ok(value)
    }
}

impl ClosedCaptureIndex {
    pub(crate) fn same_group(&self, permit: &crate::artifact_arena::ArtifactGroupPermit) -> bool {
        self.artifact.same_group(permit)
    }
    pub(crate) fn pin(&self) -> &CaptureIndexPin {
        &self.pin
    }
    /// Advisory allocation sample through the retained readonly file only.
    /// Uses the existing bounded metadata workspace; no seek, index scan or
    /// hash revalidation runs, and this observation grants no authority.
    pub(crate) fn observe_allocation_bytes(&self) -> Result<u64> {
        let file = self
            .file
            .try_borrow()
            .map_err(|_| anyhow::anyhow!("capture index metadata handle is in use"))?;
        ensure!(
            Snapshot::observe(&file)? == self.snapshot,
            "capture index held metadata changed before allocation observation"
        );
        let actual = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &file,
            self.snapshot.bytes,
        )?;
        let mut id = [0; 24];
        id[..8].copy_from_slice(&actual.volume_serial_number.to_le_bytes());
        id[8..].copy_from_slice(&actual.file_id_128);
        ensure!(
            hex::encode(id) == self.snapshot.id
                && actual.file_bytes == self.snapshot.bytes
                && actual.file_attributes == self.snapshot.attributes
                && actual.number_of_links == 1,
            "capture index allocation sample differs from its held identity"
        );
        Ok(actual.allocation_bytes)
    }
    pub(crate) fn len(&self) -> u64 {
        self.pin.ranges
    }
    pub(crate) fn range(&self, ordinal: u64) -> Result<CaptureIndexRange> {
        ensure!(
            ordinal < self.len(),
            "closed capture ordinal outside complete domain"
        );
        if let Some(row) = self.resident.get(ordinal, self.pin.image_length) {
            return row;
        }
        read_row(&mut self.file.borrow_mut(), ordinal, self.pin.image_length)
    }
    /// The file was read in full and checked when it was closed, and is held
    /// read-only since. Unless a full check is due (always, without the
    /// check-once policy; once inside each gate with it), confirm that it is
    /// still the same file with the same length and timestamp.
    pub(crate) fn revalidate(&self) -> Result<()> {
        if n2r_win32::verify_policy::full(&self.last_full) {
            return self.revalidate_in_full();
        }
        self.artifact.revalidate()?;
        ordinary_parents(
            &self.pin.path,
            &self._parents,
            &self.parent_id,
            &self.canonical_parent,
        )?;
        ensure!(
            Snapshot::observe(&self.file.borrow())? == self.snapshot,
            "capture index held identity changed"
        );
        Ok(())
    }
    fn revalidate_in_full(&self) -> Result<()> {
        self.artifact.revalidate()?;
        ordinary_parents(
            &self.pin.path,
            &self._parents,
            &self.parent_id,
            &self.canonical_parent,
        )?;
        let mut file = self.file.borrow_mut();
        ensure!(
            Snapshot::observe(&file)? == self.snapshot,
            "capture index held identity changed"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut head = [0; HEADER as usize];
        file.read_exact(&mut head)?;
        ensure!(
            head == header(self.pin.image_length),
            "capture index header differs"
        );
        let mut hash = Sha256::new();
        hash.update(head);
        let (mut end, mut changed, mut packed, mut old_zero, mut source_free) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        for ordinal in 0..self.pin.ranges {
            let mut bytes = [0; ROW as usize];
            file.read_exact(&mut bytes)?;
            let range = decode(&bytes, ordinal, self.pin.image_length)?;
            ensure!(
                range.offset >= end && range.packed_offset == packed,
                "closed capture ordering or packed prefix differs"
            );
            if let Some(source) = range.copy_source_offset {
                let position = file.stream_position()?;
                ensure!(
                    covers_prefix(
                        ordinal,
                        source,
                        range.length,
                        range.offset,
                        self.pin.image_length,
                        |prior| read_row(&mut file, prior, self.pin.image_length)
                    )?,
                    "closed COPY source is not completely inside earlier accepted ranges"
                );
                file.seek(SeekFrom::Start(position))?;
            }
            end = range.end()?;
            changed = changed
                .checked_add(range.length)
                .context("closed changed count overflow")?;
            packed = packed
                .checked_add(range.literal_bytes())
                .context("closed packed count overflow")?;
            old_zero = old_zero
                .checked_add(if range.old_is_zero { range.length } else { 0 })
                .context("closed OLD-zero count overflow")?;
            source_free = source_free
                .checked_add(if range.old_is_source_free {
                    range.length
                } else {
                    0
                })
                .context("closed source-free count overflow")?;
            hash.update(bytes);
        }
        let body: [u8; 32] = hash.clone().finalize().into();
        let mut footer = [0; FOOTER as usize];
        file.read_exact(&mut footer)?;
        ensure!(
            footer[..8] == END
                && u64_at(&footer, 8) == self.pin.ranges
                && u64_at(&footer, 16) == changed
                && u64_at(&footer, 24) == packed
                && u64_at(&footer, 32) == self.pin.image_length
                && footer[40..72] == body
                && u64_at(&footer, 72) == old_zero
                && u64_at(&footer, 80) == source_free
                && footer[88..].iter().all(|b| *b == 0)
                && changed == self.pin.changed_bytes
                && packed == self.pin.packed_bytes
                && old_zero == self.pin.old_zero_bytes
                && source_free == self.pin.source_free_bytes,
            "complete capture footer/counts/domain differ"
        );
        hash.update(footer);
        ensure!(
            hex::encode(hash.finalize()) == self.pin.file_sha256
                && file.stream_position()? == self.pin.bytes
                && Snapshot::observe(&file)? == self.snapshot,
            "complete capture index root hash/length/identity changed"
        );
        Ok(())
    }
}
