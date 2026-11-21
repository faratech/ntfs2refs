//! Same-owner, disk-backed selected write ranges. A verified index is a range
//! fact, not authority to open or modify a device. The actual V4 write gate
//! remains unreachable until journal/ticket/target routing is bound.
use crate::{file_storage, reference_file};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

const HEADER: u64 = 128;
const ROW: u64 = 32;
const FOOTER: u64 = 64;
const GRANULE: u64 = 4096;
const FREE_DIGEST: u64 = 16;
const MAGIC: &[u8; 8] = b"N2RRIX01";
const END: &[u8; 8] = b"N2RRIEND";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("paged write policy arithmetic overflow"))
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed field"))
}

/// Inputs are independently checked against the actual index bytes. They are
/// not an independently trusted ticket or source/target authorization.
#[derive(Clone, Copy)]
pub struct PagedPolicyIndexFacts {
    pub image_length: u64,
    pub selected_bytes: u64,
    pub old_zero_bytes: u64,
    pub source_free_bytes: u64,
    pub journal_length: u64,
    pub range_count: u32,
    pub format_version: u32,
    pub journal_immutable_sha256: [u8; 32],
    pub index_sha256: [u8; 32],
    pub max_index_bytes: u64,
}

#[derive(Clone, Copy)]
pub struct PagedPolicyIndexRow {
    pub offset: u64,
    pub length: u64,
    pub descriptor_offset: u64,
    pub flags: u64,
}
impl PagedPolicyIndexRow {
    fn decode(bytes: &[u8; ROW as usize]) -> Self {
        Self {
            offset: u64_at(bytes, 0),
            length: u64_at(bytes, 8),
            descriptor_offset: u64_at(bytes, 16),
            flags: u64_at(bytes, 24),
        }
    }
    fn end(self) -> io::Result<u64> {
        add(self.offset, self.length)
    }
    fn next_descriptor(self, version: u32) -> io::Result<u64> {
        let old = self.flags & 3;
        let new = (self.flags >> 2) & 3;
        if self.flags & !0x0f != 0
            || old
                > if version >= 5 {
                    2
                } else if version >= 4 {
                    1
                } else {
                    0
                }
            || new
                > if version >= 3 {
                    2
                } else if version >= 2 {
                    1
                } else {
                    0
                }
        {
            return Err(invalid("paged policy journal flags differ"));
        }
        let record = match version {
            1 => 80,
            2 => 88,
            3 => 96,
            4..=6 => 104,
            _ => return Err(invalid("paged policy journal format differs")),
        };
        let old_bytes = match old {
            0 => self.length,
            1 => 0,
            2 => (self.length / GRANULE)
                .checked_mul(FREE_DIGEST)
                .ok_or_else(|| invalid("paged policy free table overflow"))?,
            _ => unreachable!(),
        };
        let new_bytes = if new == 0 { self.length } else { 0 };
        add(
            add(add(self.descriptor_offset, record)?, old_bytes)?,
            new_bytes,
        )
    }
}

/// Created by this crate using CreateNew/share-zero. It provides sequential
/// writes but never exposes its writable File or a clone of the file handle.
pub struct PagedPolicyIndexBuilder {
    file: File,
}
impl PagedPolicyIndexBuilder {
    pub fn create_new(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 || file_storage::number_of_links(&file)? != 1
        {
            return Err(invalid("fresh ordinary single-link policy index required"));
        }
        Ok(Self { file })
    }
    pub fn finish(mut self, facts: PagedPolicyIndexFacts) -> io::Result<HeldPagedWritePolicy> {
        self.file.flush()?;
        self.file.sync_all()?;
        let produced = reference_file::observe_reference_file_handle_with_limit(
            &self.file,
            facts.max_index_bytes,
        )?;
        let produced_modified = self.file.metadata()?.modified()?;
        let maximum_allocation = add(
            add(
                produced.file_bytes,
                file_storage::artifact_allocation_slack(&self.file)?,
            )?,
            file_storage::append_preallocation_allowance(produced.file_bytes),
        )?;
        if produced.allocation_bytes > maximum_allocation {
            return Err(invalid(
                "policy index producer exceeds its actual allocation allowance",
            ));
        }
        validate_index(&mut self.file, facts)?;
        if reference_file::observe_reference_file_handle_with_limit(
            &self.file,
            facts.max_index_bytes,
        )? != produced
            || self.file.metadata()?.modified()? != produced_modified
        {
            return Err(invalid(
                "policy index producer changed before its final close",
            ));
        }
        // A reduced-access duplicate still owns the writable creator's NT
        // file object. NTFS can finalize timestamps/allocation only when that
        // object's LAST handle closes. Finish that lifecycle before pinning
        // immutable metadata; then independently bind and hash the same file.
        drop(self.file);
        let mut readonly = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&produced.final_path)?;
        file_storage::require_readonly_access(&readonly)?;
        let snapshot = reference_file::observe_reference_file_handle_with_limit(
            &readonly,
            facts.max_index_bytes,
        )?;
        if snapshot.final_path != produced.final_path
            || snapshot.volume_serial_number != produced.volume_serial_number
            || snapshot.file_id_128 != produced.file_id_128
            || snapshot.file_bytes != produced.file_bytes
            || snapshot.file_attributes != produced.file_attributes
            || snapshot.number_of_links != produced.number_of_links
            || snapshot.allocation_bytes > produced.allocation_bytes
            || snapshot.allocation_bytes > maximum_allocation
        {
            return Err(invalid(
                "policy index readonly reopen changed identity, EOF or allocation allowance",
            ));
        }
        let modified = readonly.metadata()?.modified()?;
        validate_index(&mut readonly, facts)?;
        if reference_file::observe_reference_file_handle_with_limit(
            &readonly,
            facts.max_index_bytes,
        )? != snapshot
            || readonly.metadata()?.modified()? != modified
        {
            return Err(invalid(
                "closed policy index changed during readonly validation",
            ));
        }
        Ok(HeldPagedWritePolicy(Arc::new(Mutex::new(PolicyOwner {
            reader: BufReader::with_capacity(256 * 1024, readonly),
            facts,
            snapshot,
            modified,
            cursor: u64::MAX,
            cached: None,
            lease_issued: false,
            rows: None,
            rows_lease: None,
            rows_refused: false,
        }))))
    }
}
impl Write for PagedPolicyIndexBuilder {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct PolicyOwner {
    reader: BufReader<File>,
    facts: PagedPolicyIndexFacts,
    snapshot: reference_file::ReferenceFileSnapshot,
    modified: SystemTime,
    cursor: u64,
    cached: Option<(u64, PagedPolicyIndexRow)>,
    lease_issued: bool,
    // Every row of the validated index, once any row has been asked for.
    // `None` until then, and for good if the rows could not be held.
    rows: Option<Vec<PagedPolicyIndexRow>>,
    rows_lease: Option<Box<dyn std::any::Any + Send>>,
    rows_refused: bool,
}
/// Clones share the same readonly file, buffered cursor and cache. No clone
/// grants target access or permits any writer alias to the original file.
#[derive(Clone)]
pub struct HeldPagedWritePolicy(Arc<Mutex<PolicyOwner>>);

fn validate_index(file: &mut File, facts: PagedPolicyIndexFacts) -> io::Result<()> {
    if facts.range_count == 0
        || facts.image_length < GRANULE
        || !facts.image_length.is_multiple_of(GRANULE)
        || facts.selected_bytes > facts.image_length
        || !(1..=6).contains(&facts.format_version)
    {
        return Err(invalid("paged policy facts have invalid geometry"));
    }
    let size = HEADER
        .checked_add(
            u64::from(facts.range_count)
                .checked_mul(ROW)
                .ok_or_else(|| invalid("paged policy index size overflow"))?,
        )
        .and_then(|n| n.checked_add(FOOTER))
        .ok_or_else(|| invalid("paged policy index size overflow"))?;
    if size > facts.max_index_bytes {
        return Err(invalid("paged policy index exceeds its budget"));
    }
    let before =
        reference_file::observe_reference_file_handle_with_limit(file, facts.max_index_bytes)?;
    let modified = file.metadata()?.modified()?;
    if before.file_bytes != size || before.number_of_links != 1 {
        return Err(invalid("paged policy held file identity differs"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::with_capacity(256 * 1024, &mut *file);
    let mut head = [0u8; HEADER as usize];
    reader.read_exact(&mut head)?;
    if &head[..8] != MAGIC
        || u32::from_le_bytes(head[8..12].try_into().unwrap()) != facts.range_count
        || u32::from_le_bytes(head[12..16].try_into().unwrap()) != facts.format_version
        || u64_at(&head, 16) != facts.image_length
        || u64_at(&head, 24) != facts.journal_length
        || head[32..64] != facts.journal_immutable_sha256
        || head[64..].iter().any(|&b| b != 0)
    {
        return Err(invalid("paged policy header differs"));
    }
    let mut body_hash = Sha256::new();
    body_hash.update(head);
    let mut full_hash = Sha256::new();
    full_hash.update(head);
    let mut previous_end = 0u64;
    let mut selected = 0u64;
    let mut old_zero = 0u64;
    let mut source_free = 0u64;
    let mut copy_seen = false;
    let mut new_zero_seen = false;
    let mut descriptor = if facts.format_version == 6 {
        8 * GRANULE + 80
    } else {
        2 * GRANULE + 80
    };
    for _ in 0..facts.range_count {
        let mut bytes = [0u8; ROW as usize];
        reader.read_exact(&mut bytes)?;
        body_hash.update(bytes);
        full_hash.update(bytes);
        let row = PagedPolicyIndexRow::decode(&bytes);
        let end = row.end()?;
        if row.length == 0
            || !row.offset.is_multiple_of(GRANULE)
            || !row.length.is_multiple_of(GRANULE)
            || row.offset < previous_end
            || end > facts.image_length
            || row.descriptor_offset != descriptor
        {
            return Err(invalid("paged policy row ordering or bounds differ"));
        }
        if row.flags & 3 == 2 && (row.offset < GRANULE || end > facts.image_length - GRANULE) {
            return Err(invalid(
                "paged policy source-free row covers a protected bookend",
            ));
        }
        if row.flags & 3 == 1 {
            old_zero = add(old_zero, row.length)?;
        }
        if row.flags & 3 == 2 {
            source_free = add(source_free, row.length)?;
        }
        copy_seen |= (row.flags >> 2) & 3 == 2;
        new_zero_seen |= (row.flags >> 2) & 3 == 1;
        previous_end = end;
        selected = add(selected, row.length)?;
        descriptor = row.next_descriptor(facts.format_version)?;
    }
    let mut footer = [0u8; FOOTER as usize];
    reader.read_exact(&mut footer)?;
    full_hash.update(footer);
    let canonical = if facts.format_version == 6 {
        6
    } else if source_free != 0 {
        5
    } else if old_zero != 0 {
        4
    } else if copy_seen {
        3
    } else if new_zero_seen {
        2
    } else {
        1
    };
    if &footer[..8] != END
        || u64_at(&footer, 8) != u64::from(facts.range_count)
        || u64_at(&footer, 16) != descriptor
        || footer[24..56] != body_hash.finalize()[..]
        || footer[56..].iter().any(|&b| b != 0)
        || add(descriptor, 80)? != facts.journal_length
        || selected != facts.selected_bytes
        || old_zero != facts.old_zero_bytes
        || source_free != facts.source_free_bytes
        || canonical != facts.format_version
        || (facts.format_version == 6 && source_free == 0)
        || <[u8; 32]>::from(full_hash.finalize()) != facts.index_sha256
    {
        return Err(invalid("paged policy footer, bytes or aggregate differs"));
    }
    drop(reader);
    if reference_file::observe_reference_file_handle_with_limit(file, facts.max_index_bytes)?
        != before
        || file.metadata()?.modified()? != modified
    {
        return Err(invalid("paged policy file changed during validation"));
    }
    Ok(())
}

impl PolicyOwner {
    /// Reads every row of the index into memory. A lookup by offset is a
    /// binary search, and each probe was a seek and a read of the file.
    fn load_rows(&mut self) -> io::Result<()> {
        let count = self.facts.range_count as usize;
        let bytes = (count as u64)
            .checked_mul(std::mem::size_of::<PagedPolicyIndexRow>() as u64)
            .ok_or_else(|| invalid("paged policy cache size overflow"))?;
        let lease = match crate::evict::pay_for_cache(bytes) {
            crate::evict::CachePayment::Paid(paid) => Some(paid),
            crate::evict::CachePayment::NoLedger => None,
            crate::evict::CachePayment::Refused => {
                self.rows_refused = true;
                return Ok(());
            }
        };
        let mut rows = Vec::new();
        if rows.try_reserve_exact(count).is_err() {
            self.rows_refused = true;
            return Ok(());
        }
        self.cursor = u64::MAX;
        self.reader.seek(SeekFrom::Start(HEADER))?;
        for _ in 0..count {
            let mut bytes = [0u8; ROW as usize];
            self.reader.read_exact(&mut bytes)?;
            rows.push(PagedPolicyIndexRow::decode(&bytes));
        }
        self.rows = Some(rows);
        self.rows_lease = lease;
        Ok(())
    }
    fn row(&mut self, ordinal: u64) -> io::Result<PagedPolicyIndexRow> {
        if ordinal >= u64::from(self.facts.range_count) {
            return Err(invalid("paged policy row outside index"));
        }
        if self.rows.is_none() && !self.rows_refused {
            self.load_rows()?;
        }
        if let Some(rows) = &self.rows {
            return rows
                .get(ordinal as usize)
                .copied()
                .ok_or_else(|| invalid("paged policy row outside index"));
        }
        let at = HEADER
            .checked_add(
                ordinal
                    .checked_mul(ROW)
                    .ok_or_else(|| invalid("paged policy row overflow"))?,
            )
            .ok_or_else(|| invalid("paged policy row offset overflow"))?;
        let previous = std::mem::replace(&mut self.cursor, u64::MAX);
        if previous != at {
            self.reader.seek(SeekFrom::Start(at))?;
        }
        let mut bytes = [0u8; ROW as usize];
        self.reader.read_exact(&mut bytes)?;
        self.cursor = add(at, ROW)?;
        Ok(PagedPolicyIndexRow::decode(&bytes))
    }
}
impl HeldPagedWritePolicy {
    fn lock(&self) -> io::Result<MutexGuard<'_, PolicyOwner>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("paged policy owner lock poisoned"))
    }
    pub fn facts(&self) -> io::Result<PagedPolicyIndexFacts> {
        Ok(self.lock()?.facts)
    }
    /// Issue one readonly duplicate for an arena lease during construction.
    /// That verifier must preserve the shared file cursor and release this
    /// temporary handle after retaining its own protected lease.
    pub fn take_lease_handle(&self) -> io::Result<File> {
        let mut owner = self.lock()?;
        if owner.lease_issued {
            return Err(invalid("paged policy lease handle already issued"));
        }
        let handle = file_storage::duplicate_readonly(owner.reader.get_ref())?;
        owner.lease_issued = true;
        Ok(handle)
    }
    pub fn row(&self, ordinal: u64) -> io::Result<PagedPolicyIndexRow> {
        self.lock()?.row(ordinal)
    }
    pub fn revalidate(&self) -> io::Result<()> {
        let mut owner = self.lock()?;
        let facts = owner.facts;
        let before = reference_file::observe_reference_file_handle_with_limit(
            owner.reader.get_ref(),
            facts.max_index_bytes,
        )?;
        if before != owner.snapshot
            || owner.reader.get_ref().metadata()?.modified()? != owner.modified
        {
            return Err(invalid("paged policy owner identity changed"));
        }
        owner.cursor = u64::MAX;
        validate_index(owner.reader.get_mut(), facts)?;
        // Discard any buffered bytes and reestablish the real shared cursor.
        owner.reader.seek(SeekFrom::Start(0))?;
        owner.cursor = 0;
        owner.cached = None;
        Ok(())
    }
    /// Accept a 4 KiB-aligned write only if every byte is covered by the
    /// verified sorted rows, including spans that cross adjacent rows.
    pub fn permits(&self, offset: u64, length: u64) -> io::Result<bool> {
        if length == 0 || !offset.is_multiple_of(GRANULE) || !length.is_multiple_of(GRANULE) {
            return Ok(false);
        }
        let end = match offset.checked_add(length) {
            Some(end) => end,
            None => return Ok(false),
        };
        let mut owner = self.lock()?;
        if end > owner.facts.image_length {
            return Ok(false);
        }
        let mut ordinal = if let Some((n, row)) = owner.cached {
            if row.offset <= offset && offset < row.end()? {
                n
            } else if offset == row.end()? && n + 1 < u64::from(owner.facts.range_count) {
                n + 1
            } else {
                find_row(&mut owner, offset)?
            }
        } else {
            find_row(&mut owner, offset)?
        };
        let mut position = offset;
        while position < end {
            if ordinal >= u64::from(owner.facts.range_count) {
                return Ok(false);
            }
            let row = if let Some((cached_ordinal, cached)) = owner.cached {
                if cached_ordinal == ordinal {
                    cached
                } else {
                    owner.row(ordinal)?
                }
            } else {
                owner.row(ordinal)?
            };
            let row_end = row.end()?;
            if row.offset > position || position >= row_end {
                return Ok(false);
            }
            position = end.min(row_end);
            owner.cached = Some((ordinal, row));
            ordinal += 1;
        }
        Ok(true)
    }
}
fn find_row(owner: &mut PolicyOwner, offset: u64) -> io::Result<u64> {
    let (mut low, mut high) = (0u64, u64::from(owner.facts.range_count));
    while low < high {
        let mid = low + (high - low) / 2;
        if owner.row(mid)?.end()? <= offset {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    Ok(low)
}
