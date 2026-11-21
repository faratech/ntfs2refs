//! Native markerless fresh-apply and recovery gates over actual held owners.
//!
//! Fresh apply requires the original frozen source and verified OLD selected
//! bytes; recovery requires an already excluded target and durable AP/RB. Both
//! bind the actual exclusively held native journal and paged write index. The
//! caller must still authenticate complete journal semantics and check every
//! target span against its old/new bytes before writing.
use super::{
    ERROR_SHARING_VIOLATION, GeneralExclusiveRecoveryTarget, GeneralFrozenPartition,
    GeneralJournaledPartition, HeldPagedWritePolicy, MAX_IO, NativeEvent, OFFLINE, READ_ONLY,
    ResourcePolicyAuthority, close_file, device_file, general_disk_state, set_attributes,
};
use crate::journal_file::{GeneralJournalStorageBinding, JournalFileIdentity, JournalProfile};
mod partition_scope;
pub(in crate::native) use partition_scope::authenticate_basic_ro_closed;
pub(in crate::native) use partition_scope::authenticate_scoped_partition_reader;
pub(super) use partition_scope::{
    OwnedPartitionJournalPins, PartitionJournalPhase, authenticate_partition_mixed,
    authenticate_scoped_partition_paged_source, publish_partition_apply_marker,
    publish_partition_rollback_marker,
};
pub use partition_scope::{
    PartitionClosedJournalObservation, PartitionHandoffWitness, PartitionTerminalKind,
    authenticate_partition_closed_journal,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
};

const GRANULE: u64 = 4096;
const BODY: u64 = 2 * GRANULE;
const HEADER: usize = 80;
const FOOTER: usize = 80;

fn protected_refs_label(file: &File) -> io::Result<crate::volume_label::VolumeLabel> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    let mut label = [0u16; 33];
    let mut filesystem = [0u16; 32];
    let mut serial = 0u32;
    let mut component = 0u32;
    let mut flags = 0u32;
    // SAFETY: the protected borrowed volume handle and fixed initialized
    // output buffers remain valid for this synchronous metadata-only query.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let label_end = label
        .iter()
        .position(|&v| v == 0)
        .ok_or_else(|| invalid("unterminated protected volume label"))?;
    let fs_end = filesystem
        .iter()
        .position(|&v| v == 0)
        .ok_or_else(|| invalid("unterminated protected filesystem name"))?;
    if String::from_utf16(&filesystem[..fs_end]).map_err(io::Error::other)? != "ReFS" {
        return Err(invalid("protected converted source is not ReFS"));
    }
    crate::volume_label::VolumeLabel::from_utf16(label[..label_end].to_vec())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("fixed field"))
}
fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("fixed field"))
}
fn read_at(file: &mut File, at: u64, output: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(at))?;
    file.read_exact(output)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagedRecoveryDirection {
    Resume,
    Rollback,
}

/// Actual converted-source metadata and known-content observations collected
/// under one native physically READ_ONLY volume lease. This opaque owner is
/// not itself a write, handoff or writable-mount authorization.
#[derive(Debug)]
pub struct GeneralLiveConvertedObservation {
    report: crate::shadow_native::GeneralConvertedReport,
    before: super::GeneralDiskState,
    observed_readonly: super::GeneralDiskState,
    after: super::GeneralDiskState,
}
impl GeneralLiveConvertedObservation {
    pub fn report(&self) -> &crate::shadow_native::GeneralConvertedReport {
        &self.report
    }
    pub fn before(&self) -> &super::GeneralDiskState {
        &self.before
    }
    pub fn observed_readonly(&self) -> &super::GeneralDiskState {
        &self.observed_readonly
    }
    pub fn after(&self) -> &super::GeneralDiskState {
        &self.after
    }
}

/// Independently retained ticket and storage facts, never authority by
/// themselves. Every field is checked against actual held native objects.
pub struct PagedRecoveryPins<'a> {
    pub journal_binding: &'a GeneralJournalStorageBinding,
    pub journal_identity: &'a JournalFileIdentity,
    pub journal_path: &'a Path,
    pub journal_profile: JournalProfile,
    /// The algorithm of the four digests below, as the ticket names it:
    /// BLAKE3 for a journal this build wrote, SHA-256 for an older one's.
    pub digest: crate::bulk_digest::Algorithm,
    pub immutable_sha256: [u8; 32],
    pub old_selected_sha256: [u8; 32],
    pub old_restored_selected_sha256: Option<[u8; 32]>,
    pub new_selected_sha256: [u8; 32],
}

fn marker(magic: &[u8; 8], immutable: &[u8; 32], selected: &[u8; 32]) -> [u8; GRANULE as usize] {
    let mut value = [0; GRANULE as usize];
    value[..8].copy_from_slice(magic);
    value[8..40].copy_from_slice(immutable);
    value[40..72].copy_from_slice(selected);
    let sha: [u8; 32] = Sha256::digest(&value[..GRANULE as usize - 32]).into();
    value[GRANULE as usize - 32..].copy_from_slice(&sha);
    value
}

fn check_lifecycle(
    file: &mut File,
    pins: &PagedRecoveryPins<'_>,
    direction: PagedRecoveryDirection,
) -> io::Result<()> {
    let mut completion = [0; GRANULE as usize];
    let mut intent = [0; GRANULE as usize];
    read_at(file, 0, &mut completion)?;
    read_at(file, GRANULE, &mut intent)?;
    if completion.iter().any(|&b| b != 0) {
        return Err(invalid(
            "paged recovery is closed or its completion marker is damaged",
        ));
    }
    let apply = marker(
        b"N2RSAP01",
        &pins.immutable_sha256,
        &pins.new_selected_sha256,
    );
    let rollback = marker(
        b"N2RSRB01",
        &pins.immutable_sha256,
        &pins.old_selected_sha256,
    );
    if intent != apply && !(direction == PagedRecoveryDirection::Rollback && intent == rollback) {
        return Err(invalid(
            "paged recovery direction does not match durable AP/RB intent",
        ));
    }
    Ok(())
}

fn check_clear_lifecycle(file: &mut File) -> io::Result<()> {
    let mut markers = [0; (2 * GRANULE) as usize];
    read_at(file, 0, &mut markers)?;
    if markers.iter().any(|&b| b != 0) {
        return Err(invalid(
            "fresh paged apply requires both actual marker blocks to be clear",
        ));
    }
    Ok(())
}

fn check_handoff_lifecycle(file: &mut File, pins: &PagedRecoveryPins<'_>) -> io::Result<()> {
    let mut completion = [0; GRANULE as usize];
    let mut intent = [0; GRANULE as usize];
    read_at(file, 0, &mut completion)?;
    read_at(file, GRANULE, &mut intent)?;
    if completion
        != marker(
            b"N2RSHN01",
            &pins.immutable_sha256,
            &pins.new_selected_sha256,
        )
        || intent
            != marker(
                b"N2RSAP01",
                &pins.immutable_sha256,
                &pins.new_selected_sha256,
            )
    {
        return Err(invalid("actual markerless AP and durable HND are required"));
    }
    Ok(())
}

fn check_aborted_lifecycle(file: &mut File, pins: &PagedRecoveryPins<'_>) -> io::Result<bool> {
    let mut completion = [0; GRANULE as usize];
    let mut intent = [0; GRANULE as usize];
    read_at(file, 0, &mut completion)?;
    read_at(file, GRANULE, &mut intent)?;
    let abandoned = intent.iter().all(|&b| b == 0);
    if completion
        != marker(
            b"N2RSAB01",
            &pins.immutable_sha256,
            &pins.old_selected_sha256,
        )
        || (!abandoned
            && intent
                != marker(
                    b"N2RSRB01",
                    &pins.immutable_sha256,
                    &pins.old_selected_sha256,
                ))
    {
        return Err(invalid(
            "actual markerless rollback or clear abandonment and durable ABT are required",
        ));
    }
    Ok(abandoned)
}

fn verify_journal_owner(
    file: &File,
    pins: &PagedRecoveryPins<'_>,
    expected_length: u64,
) -> io::Result<crate::journal_file::JournalFileSnapshot> {
    let snapshot = crate::journal_file::observe_general_journal_file_with_profile(
        file,
        pins.journal_binding,
        pins.journal_profile,
    )?;
    if &snapshot.identity != pins.journal_identity
        || snapshot.file_bytes != expected_length
        || !snapshot
            .final_path
            .eq_ignore_ascii_case(&pins.journal_path.to_string_lossy())
    {
        return Err(invalid(
            "actual held native journal identity, route or length differs",
        ));
    }
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(pins.journal_path);
    match probe {
        Ok(_) => return Err(invalid("held recovery journal permits a second writer")),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => (),
        Err(error) => return Err(error),
    }
    Ok(snapshot)
}

fn verify_selected_digest<R: Read + Seek>(
    source: &mut R,
    policy: &HeldPagedWritePolicy,
    algorithm: crate::bulk_digest::Algorithm,
    expected: [u8; 32],
) -> io::Result<()> {
    if selected_digest(source, policy, algorithm)? != expected {
        return Err(invalid("actual excluded source selected bytes differ"));
    }
    Ok(())
}

/// The digest of the source's selected ranges, framed as the journal frames
/// its OLD and NEW digests, by the journal's algorithm.
fn selected_digest<R: Read + Seek>(
    source: &mut R,
    policy: &HeldPagedWritePolicy,
    algorithm: crate::bulk_digest::Algorithm,
) -> io::Result<[u8; 32]> {
    selected_digest_reaching(source, policy, algorithm, false, |_, _| ())
}

/// The bytes a caller pays for, beside what [`selected_digest_reaching`]
/// holds anyway, to have the selected digest computed on a worker thread
/// (`hashed_behind`): the worker's second buffer.
pub const SELECTED_DIGEST_BEHIND_BYTES: u64 = MAX_IO as u64;

/// [`selected_digest`] for a source that reads ahead: `reach(source, end)`
/// is told, at the first of each group of ranges that lie close together,
/// where the group ends, so a read-ahead window holds those ranges and not
/// the megabyte that follows the first of them.
///
/// With `hashed_behind` the bytes are hashed on a worker
/// (`bulk_digest::HashedBehind`) while this thread reads on: hashed here,
/// each range of a few tens of kilobytes was too short to be divided among
/// the pool's threads and held up the next read. The caller pays for the
/// worker's second buffer ([`SELECTED_DIGEST_BEHIND_BYTES`]). The bytes
/// hashed, their order and so the digest are the same either way.
fn selected_digest_reaching<R: Read + Seek>(
    source: &mut R,
    policy: &HeldPagedWritePolicy,
    algorithm: crate::bulk_digest::Algorithm,
    hashed_behind: bool,
    mut reach: impl FnMut(&mut R, u64),
) -> io::Result<[u8; 32]> {
    let previous = source.stream_position()?;
    let result = (|| {
        let facts = policy.facts()?;
        let mut rows = super::AscendingRanges::new(u64::from(facts.range_count));
        if hashed_behind {
            let mut hash = crate::bulk_digest::HashedBehind::new(algorithm, MAX_IO)?;
            while let Some((row, group_end)) =
                rows.next(|ordinal| policy.row(ordinal).map(|row| (row, row.offset, row.length)))?
            {
                if let Some(end) = group_end {
                    reach(source, end);
                }
                hash.update(&row.offset.to_le_bytes())?;
                hash.update(&row.length.to_le_bytes())?;
                source.seek(SeekFrom::Start(row.offset))?;
                let mut remaining = row.length;
                while remaining != 0 {
                    let space = hash.space()?;
                    let count = remaining.min(space.len() as u64) as usize;
                    source.read_exact(&mut space[..count])?;
                    hash.filled(count);
                    remaining -= count as u64;
                }
            }
            return hash.finish();
        }
        let mut hash = crate::bulk_digest::Hasher::new(algorithm)?;
        let mut buffer = vec![0; MAX_IO];
        while let Some((row, group_end)) =
            rows.next(|ordinal| policy.row(ordinal).map(|row| (row, row.offset, row.length)))?
        {
            if let Some(end) = group_end {
                reach(source, end);
            }
            hash.update(&row.offset.to_le_bytes())?;
            hash.update(&row.length.to_le_bytes())?;
            source.seek(SeekFrom::Start(row.offset))?;
            let mut remaining = row.length;
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                source.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count])?;
                remaining -= count as u64;
            }
        }
        hash.finish()
    })();
    source.seek(SeekFrom::Start(previous))?;
    result
}

fn verify_restored_digest<R: Read + Seek>(
    source: &mut R,
    policy: &HeldPagedWritePolicy,
    pins: &PagedRecoveryPins<'_>,
) -> io::Result<()> {
    verify_restored_digest_reaching(source, policy, pins, |_, _| ())
}

fn verify_restored_digest_reaching<R: Read + Seek>(
    source: &mut R,
    policy: &HeldPagedWritePolicy,
    pins: &PagedRecoveryPins<'_>,
    mut reach: impl FnMut(&mut R, u64),
) -> io::Result<()> {
    let Some(expected) = pins.old_restored_selected_sha256 else {
        if selected_digest_reaching(source, policy, pins.digest, false, reach)?
            != pins.old_selected_sha256
        {
            return Err(invalid("actual excluded source selected bytes differ"));
        }
        return Ok(());
    };
    let previous = source.stream_position()?;
    let result = (|| {
        let facts = policy.facts()?;
        let mut hash = crate::bulk_digest::Hasher::new(pins.digest)?;
        let mut buffer = vec![0; MAX_IO];
        let mut rows = super::AscendingRanges::new(u64::from(facts.range_count));
        while let Some((row, group_end)) =
            rows.next(|ordinal| policy.row(ordinal).map(|row| (row, row.offset, row.length)))?
        {
            if row.flags & 3 == 2 {
                continue;
            }
            if let Some(end) = group_end {
                reach(source, end);
            }
            hash.update(&row.offset.to_le_bytes())?;
            hash.update(&row.length.to_le_bytes())?;
            source.seek(SeekFrom::Start(row.offset))?;
            let mut remaining = row.length;
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                source.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count])?;
                remaining -= count as u64;
            }
        }
        if hash.finish()? != expected {
            return Err(invalid("restored source allocated-range digest differs"));
        }
        Ok(())
    })();
    source.seek(SeekFrom::Start(previous))?;
    result
}

/// The original frozen source object remains at the same address throughout
/// this borrowed, range-limited native writer. Its disk stays offline on drop;
/// dropping it never mounts or repairs the source.
pub struct BorrowedPagedWriter<'a> {
    source: &'a mut GeneralFrozenPartition,
    policy: HeldPagedWritePolicy,
    poisoned: bool,
    requested: u64,
    written: u64,
}
impl BorrowedPagedWriter<'_> {
    /// The longest write the writer accepts: one native request.
    pub const MAX_WRITE: usize = MAX_IO;
    pub fn byte_len(&self) -> u64 {
        self.source.byte_len()
    }
    pub fn native_bytes_written(&self) -> u64 {
        self.written
    }
    /// Recheck the same actual disk identity and persistent OFFLINE state.
    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<super::GeneralDiskState> {
        self.source.state(events)
    }
    /// Read-ahead for the passes that read the changed ranges in order; see
    /// `GeneralFrozenPartition::with_read_ahead`. Every write through this
    /// writer is copied into the window, and dropping the writer turns it off.
    pub fn set_read_ahead(&mut self, enabled: bool) {
        self.source.set_read_ahead(enabled);
    }
    /// See `GeneralFrozenPartition::set_read_ahead_reach`.
    pub fn set_read_ahead_reach(&mut self, end: u64) {
        self.source.set_read_ahead_reach(end);
    }
    /// The storage transfer profile Windows reports for the source's disk.
    pub fn io_profile(&self) -> crate::io_profile::IoProfile {
        self.source.io_profile()
    }
    /// `count` more read-only, unbuffered handles on the source, each
    /// proven to reach the same disk in the same state as this writer's own
    /// (`GeneralFrozenPartition::read_lanes`). The writer's handle shares
    /// reading and refuses every other writer; these read only, so the
    /// source has still one writer, this one. For a pass that reads what
    /// was written, after its flush, with more than one read outstanding.
    pub fn read_lanes(
        &self,
        count: usize,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Vec<super::GeneralFrozenLane>> {
        self.source.read_lanes(count, events)
    }
    pub fn sync_all(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid("cannot sync a poisoned fresh paged writer"));
        }
        if let Err(error) = self.source.file.sync_all() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
}
impl Drop for BorrowedPagedWriter<'_> {
    fn drop(&mut self) {
        self.source.set_read_ahead(false);
    }
}
impl Read for BorrowedPagedWriter<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.source.read(output)
    }
}
impl Seek for BorrowedPagedWriter<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.source.seek(from)
    }
}
impl Write for BorrowedPagedWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let attempted = self
            .requested
            .checked_add(input.len() as u64)
            .ok_or_else(|| invalid("fresh paged write accounting overflow"))?;
        if self.poisoned || input.len() > MAX_IO {
            return Err(invalid(
                "fresh paged writer is poisoned or request exceeds native I/O limit",
            ));
        }
        let (permitted, maximum) = match self
            .policy
            .permits(self.source.position, input.len() as u64)
            .and_then(|allowed| {
                self.policy
                    .facts()
                    .map(|facts| (allowed, facts.selected_bytes))
            }) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if !permitted || attempted > maximum {
            return Err(invalid(
                "fresh paged write is outside the authenticated selected range",
            ));
        }
        let offset = self
            .source
            .binding
            .identity
            .partition_offset
            .checked_add(self.source.position)
            .ok_or_else(|| invalid("fresh paged disk offset overflow"))?;
        // The device write itself, apart from the policy check above.
        let _timed = crate::perf::scope(crate::perf::Point::DeviceWrite);
        crate::perf::add_bytes(crate::perf::Point::DeviceWrite, input.len() as u64);
        self.source.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
        self.requested = attempted;
        match std::os::windows::fs::FileExt::seek_write(
            &self.source.file,
            &self.source.buffer.bytes_mut()[..input.len()],
            offset,
        ) {
            Ok(count) if count == input.len() => {
                self.written += count as u64;
                let at = self.source.position;
                self.source.ahead.written(at, input);
                self.source.position += count as u64;
                Ok(count)
            }
            Ok(_) => {
                self.poisoned = true;
                self.source.ahead.clear();
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short fresh paged write; reopen through recovery",
                ))
            }
            Err(error) => {
                self.poisoned = true;
                self.source.ahead.clear();
                Err(error)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

fn verify_index_against_journal(
    file: &mut File,
    policy: &HeldPagedWritePolicy,
    pins: &PagedRecoveryPins<'_>,
) -> io::Result<()> {
    let facts = policy.facts()?;
    let (magic, end, record_size) = match facts.format_version {
        1 => (b"N2RSEL01", b"N2RSEND1", 80usize),
        2 => (b"N2RZERO1", b"N2RZEND1", 88usize),
        3 => (b"N2RCPY01", b"N2RCEND1", 96usize),
        4 => (b"N2ROLD01", b"N2ROEND1", 104usize),
        5 => (b"N2RFRE01", b"N2RFEND1", 104usize),
        _ => {
            return Err(invalid(
                "paged native recovery currently requires markerless format 1 through 5",
            ));
        }
    };
    if facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
        || facts.journal_immutable_sha256 != pins.immutable_sha256
        || (facts.format_version >= 5) != pins.old_restored_selected_sha256.is_some()
    {
        return Err(invalid("paged policy and actual recovery ticket differ"));
    }
    policy.revalidate()?;
    let mut header = [0; HEADER];
    read_at(file, BODY, &mut header)?;
    if &header[..8] != magic
        || u32_at(&header, 8) != facts.format_version
        || u32_at(&header, 12) != facts.range_count
        || u64_at(&header, 16) != facts.image_length
        || u64_at(&header, 24) != facts.selected_bytes
        || u64_at(&header, 32) != facts.journal_length
        || if let Some(restored) = pins.old_restored_selected_sha256 {
            header[40..72] != restored || u64_at(&header, 72) != facts.source_free_bytes
        } else {
            header[40..].iter().any(|&b| b != 0)
        }
    {
        return Err(invalid(
            "held recovery journal header differs from the paged policy",
        ));
    }
    const DESCRIPTOR_WINDOW: usize = 64 * 1024;
    let mut window = vec![0u8; DESCRIPTOR_WINDOW];
    let mut window_start = 0u64;
    let mut window_len = 0usize;
    let journal_end = facts.journal_length;
    for ordinal in 0..u64::from(facts.range_count) {
        let row = policy.row(ordinal)?;
        let mut descriptor = [0; 104];
        let at = row.descriptor_offset;
        let end = at
            .checked_add(record_size as u64)
            .ok_or_else(|| invalid("journal descriptor offset overflow"))?;
        if end > journal_end {
            return Err(invalid("journal descriptor escapes journal length"));
        }
        if !(at >= window_start && end <= window_start + window_len as u64) {
            let to_read = (journal_end - at).min(DESCRIPTOR_WINDOW as u64) as usize;
            read_at(file, at, &mut window[..to_read])?;
            window_start = at;
            window_len = to_read;
        }
        let rel = (at - window_start) as usize;
        descriptor[..record_size].copy_from_slice(&window[rel..rel + record_size]);
        let new_kind = if facts.format_version >= 2 {
            u64_at(&descriptor, 16)
        } else {
            0
        };
        let copy_source = if facts.format_version >= 3 {
            u64_at(&descriptor, 24)
        } else {
            0
        };
        let old_kind = if facts.format_version >= 4 {
            u64_at(&descriptor, 32)
        } else {
            0
        };
        if u64_at(&descriptor, 0) != row.offset
            || u64_at(&descriptor, 8) != row.length
            || new_kind > 2
            || old_kind > 2
            || row.flags != (old_kind | (new_kind << 2))
            || (new_kind != 2 && copy_source != 0)
            || (new_kind == 2
                && (!copy_source.is_multiple_of(GRANULE)
                    || !copy_source
                        .checked_add(row.length)
                        .is_some_and(|end| end <= row.offset)))
        {
            return Err(invalid(
                "held recovery journal descriptor differs from paged write policy",
            ));
        }
    }
    let mut footer = [0; FOOTER];
    read_at(file, facts.journal_length - FOOTER as u64, &mut footer)?;
    if &footer[..8] != end
        || footer[8..40] != pins.old_selected_sha256
        || footer[40..72] != pins.new_selected_sha256
        || u64_at(&footer, 72) != facts.journal_length
    {
        return Err(invalid(
            "held recovery journal footer differs from its ticket",
        ));
    }
    policy.revalidate()
}

/// The walk of the held index against the journal's descriptors, made again
/// right after the journal's body was hashed again (`body_read` says whether
/// that hash read the body or left it out, `bulk_digest::journal_body_reading`).
///
/// The descriptors lie in the body. Where the body's read was left out,
/// because it matched in this process and the route checks once
/// (`bulk_digest::journal_body_already_verified`), a run that verifies each
/// thing once (`verify_policy::verifies_once`) leaves out walking its
/// descriptors again on the same ground: the walk reads the same bytes of
/// the same held journal and holds them to the same held index, both
/// unchanged. The index's own owner is still revalidated (its identity,
/// timestamp and digest). `--verify thorough`, `--recheck-everything` and
/// every recovery walk as before.
fn verify_index_against_journal_again(
    file: &mut File,
    policy: &HeldPagedWritePolicy,
    pins: &PagedRecoveryPins<'_>,
    body_read: bool,
) -> io::Result<()> {
    if descriptors_walked_again(body_read, crate::verify_policy::verifies_once()) {
        verify_index_against_journal(file, policy, pins)
    } else {
        policy.revalidate()
    }
}

/// The rule of [`verify_index_against_journal_again`], apart from the switch.
fn descriptors_walked_again(body_read: bool, verifies_once: bool) -> bool {
    body_read || !verifies_once
}

type VerifiedNewBytes = ([u8; 32], [u8; 32]);
static NEW_BYTES_VERIFIED: std::sync::Mutex<Vec<VerifiedNewBytes>> =
    std::sync::Mutex::new(Vec::new());

/// Records that every range the journal changes was read back from the source
/// in this process and matched the journal's NEW digest. After the handoff
/// marker nothing writes to the source until it is brought online, so the
/// read-back need not be repeated at each later step of the same process.
pub fn note_selected_new_bytes_verified(
    immutable_sha256: &[u8; 32],
    new_selected_sha256: &[u8; 32],
) {
    let mut verified = NEW_BYTES_VERIFIED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !verified.contains(&(*immutable_sha256, *new_selected_sha256)) {
        verified.push((*immutable_sha256, *new_selected_sha256));
    }
}

fn selected_new_bytes_already_verified(pins: &PagedRecoveryPins<'_>) -> bool {
    selected_new_bytes_verified(&pins.immutable_sha256, &pins.new_selected_sha256)
}

/// Whether [`note_selected_new_bytes_verified`] was called for this journal in
/// this process and the route checks once. A recovery has read nothing back
/// when it starts and checks once only from its finalizer on, so there this
/// is false until that finalizer has read the bytes back itself. (What a
/// recovery repeats before then is `verify_policy::repeat_once`'s to say:
/// the journal's body, which it reads in full once while it holds it.)
pub fn selected_new_bytes_verified(
    immutable_sha256: &[u8; 32],
    new_selected_sha256: &[u8; 32],
) -> bool {
    crate::verify_policy::checks_once()
        && NEW_BYTES_VERIFIED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&(*immutable_sha256, *new_selected_sha256))
}

/// What a frozen source under the apply intent may hold before recovery
/// makes it writable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FrozenSelected {
    /// Exactly the old selected bytes: every run.
    Old,
    /// Exactly the old or exactly the new: only a run recorded as stopping
    /// for a review, whose source is sealed again after every new byte.
    OldOrNew,
}

impl FrozenSelected {
    /// Whether the digest of the frozen source's selected ranges is one this
    /// run may make writable for recovery.
    fn admits(self, actual: [u8; 32], pins: &PagedRecoveryPins<'_>) -> bool {
        match self {
            Self::Old => actual == pins.old_selected_sha256,
            Self::OldOrNew => {
                actual == pins.old_selected_sha256 || actual == pins.new_selected_sha256
            }
        }
    }
}

/// The durable state beside which the selected NEW bytes are authenticated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NewBytesState {
    /// The handoff marker beside the apply intent: rollback is closed.
    Handoff,
    /// The apply intent alone, for a run whose authenticated records say it
    /// stops for a review before its handoff. Rollback is still open.
    ReviewApply,
}

impl NewBytesState {
    fn check(self, journal: &mut File, pins: &PagedRecoveryPins<'_>) -> io::Result<()> {
        match self {
            Self::Handoff => check_handoff_lifecycle(journal, pins),
            Self::ReviewApply => check_lifecycle(journal, pins, PagedRecoveryDirection::Resume)
                .map_err(|_| invalid("a stop before the handoff requires the apply intent alone")),
        }
    }
    /// The refusal: the handoff's words, which every run before the review
    /// had, or the review's.
    fn say(self, handoff: &'static str, review: &'static str) -> io::Error {
        invalid(match self {
            Self::Handoff => handoff,
            Self::ReviewApply => review,
        })
    }
}

/// Authenticate HND and the complete selected NEW bytes using held owners.
/// The caller brackets this with actual source device-state observations.
fn verify_paged_handoff<R: Read + Seek>(
    source: &mut R,
    source_length: u64,
    source_binding: &crate::general_layout::GeneralDiskBinding,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
) -> io::Result<()> {
    verify_paged_new_bytes(
        source,
        source_length,
        source_binding,
        policy,
        journal,
        pins,
        NewBytesState::Handoff,
    )
}

/// The same for a review stop: the apply intent alone, with every selected
/// byte exactly NEW.
fn verify_paged_review_stop<R: Read + Seek>(
    source: &mut R,
    source_length: u64,
    source_binding: &crate::general_layout::GeneralDiskBinding,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
) -> io::Result<()> {
    verify_paged_new_bytes(
        source,
        source_length,
        source_binding,
        policy,
        journal,
        pins,
        NewBytesState::ReviewApply,
    )
}

fn verify_paged_new_bytes<R: Read + Seek>(
    source: &mut R,
    source_length: u64,
    source_binding: &crate::general_layout::GeneralDiskBinding,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
    state: NewBytesState,
) -> io::Result<()> {
    pins.journal_binding.validate()?;
    if source_binding.disk_number == pins.journal_binding.disk.disk_number
        || crate::layout::guid_bytes(&source_binding.identity.disk_guid)?
            == crate::layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?
    {
        return Err(state.say(
            "handoff journal must be on a different physical disk",
            "the journal of a stop before the handoff must be on a different physical disk",
        ));
    }
    let facts = policy.facts()?;
    if pins.journal_profile.version() != 3
        || !(1..=5).contains(&facts.format_version)
        || facts.image_length != source_length
        || facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
        || facts.journal_length > pins.journal_profile.max_journal_bytes()
        || facts.journal_immutable_sha256 != pins.immutable_sha256
    {
        return Err(state.say(
            "handoff policy, source geometry or journal capacity differs",
            "before the handoff: policy, source geometry or journal capacity differs",
        ));
    }
    let before = verify_journal_owner(journal, pins, facts.journal_length)?;
    let modified = journal.metadata()?.modified()?;
    state.check(journal, pins)?;
    let (body, body_read) = crate::bulk_digest::journal_body_reading(
        pins.digest,
        journal,
        BODY,
        facts.journal_length - BODY,
        &pins.immutable_sha256,
    )?;
    if body != pins.immutable_sha256 {
        return Err(state.say(
            "handoff journal immutable body differs",
            "before the handoff: the journal immutable body differs",
        ));
    }
    verify_index_against_journal_again(journal, policy, pins, body_read)?;
    let checked_now = !selected_new_bytes_already_verified(pins);
    if checked_now {
        verify_selected_digest(source, policy, pins.digest, pins.new_selected_sha256)?;
        note_selected_new_bytes_verified(&pins.immutable_sha256, &pins.new_selected_sha256);
    }
    state.check(journal, pins)?;
    if checked_now {
        let (body, body_read) = crate::bulk_digest::journal_body_reading(
            pins.digest,
            journal,
            BODY,
            facts.journal_length - BODY,
            &pins.immutable_sha256,
        )?;
        if body != pins.immutable_sha256 {
            return Err(state.say(
                "handoff journal changed during selected-byte verification",
                "before the handoff: the journal changed during selected-byte verification",
            ));
        }
        verify_index_against_journal_again(journal, policy, pins, body_read)?;
        state.check(journal, pins)?;
    }
    let after = verify_journal_owner(journal, pins, facts.journal_length)?;
    if before.identity != after.identity
        || before.file_bytes != after.file_bytes
        || !before.final_path.eq_ignore_ascii_case(&after.final_path)
        || journal.metadata()?.modified()? != modified
    {
        return Err(state.say(
            "handoff held journal identity changed",
            "before the handoff: the held journal identity changed",
        ));
    }
    Ok(())
}

/// Reauthenticate the held rollback journal and every restore-required byte.
/// The caller separately checks source-free granules against their admitted
/// old/new forms while holding the same offline source and journal owners.
fn verify_paged_abort<R: Read + Seek>(
    source: &mut R,
    source_length: u64,
    binding: &crate::general_layout::GeneralDiskBinding,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
) -> io::Result<()> {
    verify_paged_abort_reaching(
        source,
        source_length,
        binding,
        policy,
        journal,
        pins,
        |_, _| (),
    )
}

fn verify_paged_abort_reaching<R: Read + Seek>(
    source: &mut R,
    source_length: u64,
    binding: &crate::general_layout::GeneralDiskBinding,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
    reach: impl FnMut(&mut R, u64),
) -> io::Result<()> {
    pins.journal_binding.validate()?;
    let facts = policy.facts()?;
    if binding.disk_number == pins.journal_binding.disk.disk_number
        || crate::layout::guid_bytes(&binding.identity.disk_guid)?
            == crate::layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?
        || pins.journal_profile.version() != 3
        || !(1..=5).contains(&facts.format_version)
        || facts.image_length != source_length
        || facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
        || facts.journal_length > pins.journal_profile.max_journal_bytes()
        || facts.journal_immutable_sha256 != pins.immutable_sha256
    {
        return Err(invalid(
            "rollback device, policy or journal profile differs",
        ));
    }
    let before = verify_journal_owner(journal, pins, facts.journal_length)?;
    let modified = journal.metadata()?.modified()?;
    let abandoned = check_aborted_lifecycle(journal, pins)?;
    if crate::bulk_digest::journal_body(
        pins.digest,
        journal,
        BODY,
        facts.journal_length - BODY,
        &pins.immutable_sha256,
    )? != pins.immutable_sha256
    {
        return Err(invalid("rollback journal immutable body differs"));
    }
    verify_index_against_journal(journal, policy, pins)?;
    if abandoned {
        if selected_digest_reaching(source, policy, pins.digest, false, reach)?
            != pins.old_selected_sha256
        {
            return Err(invalid("actual excluded source selected bytes differ"));
        }
    } else {
        verify_restored_digest_reaching(source, policy, pins, reach)?;
    }
    // The restored boot identity must itself still be NTFS. It is also covered
    // by the authenticated restored-range digest when selected for writing.
    let old_position = source.stream_position()?;
    let mut boot = [0u8; 512];
    source.seek(SeekFrom::Start(0))?;
    source.read_exact(&mut boot)?;
    source.seek(SeekFrom::Start(old_position))?;
    if &boot[3..11] != b"NTFS    " || boot[510..512] != [0x55, 0xaa] {
        return Err(invalid(
            "restored source does not contain an NTFS boot sector",
        ));
    }
    if check_aborted_lifecycle(journal, pins)? != abandoned {
        return Err(invalid(
            "rollback intent changed during source verification",
        ));
    }
    if crate::bulk_digest::journal_body(
        pins.digest,
        journal,
        BODY,
        facts.journal_length - BODY,
        &pins.immutable_sha256,
    )? != pins.immutable_sha256
    {
        return Err(invalid(
            "rollback journal changed during source verification",
        ));
    }
    verify_index_against_journal(journal, policy, pins)?;
    if check_aborted_lifecycle(journal, pins)? != abandoned {
        return Err(invalid(
            "rollback intent changed during journal verification",
        ));
    }
    let after = verify_journal_owner(journal, pins, facts.journal_length)?;
    if before.identity != after.identity
        || before.file_bytes != after.file_bytes
        || !before.final_path.eq_ignore_ascii_case(&after.final_path)
        || journal.metadata()?.modified()? != modified
    {
        return Err(invalid("rollback held journal identity changed"));
    }
    Ok(())
}

impl GeneralFrozenPartition {
    /// Consume the same excluded source only after durable rollback and exact
    /// restored allocated-range authentication. The journal remains held by
    /// the caller; no reconstructed or serialized authority is accepted.
    pub fn bring_online_after_paged_abort(
        mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE && before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("rollback mount requires an excluded source"));
        }
        let binding = self.binding.clone();
        let length = self.byte_len();
        self.with_read_ahead(|source| {
            verify_paged_abort_reaching(
                source,
                length,
                &binding,
                policy,
                journal,
                pins,
                GeneralFrozenPartition::set_read_ahead_reach,
            )
        })?;
        if self.state(events)? != before {
            return Err(invalid("rollback source changed during verification"));
        }
        if before.disk_attributes == OFFLINE | READ_ONLY {
            let path = format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number);
            let gate = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(1)
                .custom_flags(0xa000_0000)
                .open(&path)?;
            if general_disk_state(&gate, &self.binding, events)? != before {
                return Err(invalid("rollback mount gate differs from frozen source"));
            }
            match device_file(&path, true, true) {
                Ok(file) => {
                    close_file(file, "close-unexpected-rollback-writer-probe", events)?;
                    return Err(invalid("rollback mount gate allowed a second raw writer"));
                }
                Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => (),
                Err(error) => return Err(error),
            }
            self.file = gate;
        }
        self.freeze_observation = None;
        GeneralJournaledPartition {
            inner: self,
            policy: None,
            paged_policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        }
        .bring_online(events)
    }

    /// Collect complete converted metadata/maps and all known stream digests
    /// under one physical READ_ONLY volume lease. The source is restored to
    /// OFFLINE|READ_ONLY before returning the opaque actual observation.
    pub fn observe_converted_protected_with_memory(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        expected_label: Option<&crate::volume_label::VolumeLabel>,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: crate::attestation::ResourceProfile,
        memory: &dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveConvertedObservation> {
        pair.validate_with_resource_profile(Some(resource_profile))?;
        if pair.source != self.binding {
            return Err(invalid(
                "protected converted observer source binding differs",
            ));
        }
        let admission = resource_profile
            .resource_admission()?
            .ok_or_else(|| invalid("protected converted observer requires V4 admission"))?;
        let (report, before, observed_readonly, after) = self
            .with_readonly_refs_binding_observation(events, |protected| {
                crate::lab_hold::reached_in_verification(
                    "verify-source-readonly",
                    "finalize-source-readonly",
                );
                let actual_label = protected_refs_label(protected.volume())?;
                let enrollment_label = crate::volume_label::VolumeLabel::from_text("n2r-retained-shadow")?;
                let effective_label = match expected_label {
                    Some(desired) if *desired == actual_label => Some(desired),
                    _ if actual_label == enrollment_label => None,
                    _ => return Err(invalid("protected converted label is neither enrollment nor the original source label")),
                };
                let report = crate::shadow_native::observe_general_converted_metadata_domain_readonly_with_memory(
                    pair.clone(), input, effective_label, &same_security, resource_profile, memory, protected,
                )?;
                crate::shadow_native::verify_known_contents_in_accounted_report_with_lease(
                    report, input, admission, memory, &same_security, Some(protected),
                )
            })?;
        if before != after
            || before.disk_attributes != OFFLINE | READ_ONLY
            || observed_readonly.disk_attributes != READ_ONLY
            || report.pair != pair
        {
            return Err(invalid(
                "protected converted observer changed source identity or exclusion",
            ));
        }
        Ok(GeneralLiveConvertedObservation {
            report,
            before,
            observed_readonly,
            after,
        })
    }

    /// Native Windows alias-aware finalization on the converted original
    /// partition. Canonical rows and known-content checks remain unchanged;
    /// the separate alias witness is issued only by the actual readonly lease.
    pub fn observe_converted_protected_with_memory_windows_aliases(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        expected_label: Option<&crate::volume_label::VolumeLabel>,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: crate::attestation::ResourceProfile,
        memory: &dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
        aliases: &crate::shadow_native::windows_aliases::VerifiedWindowsAliases,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<(
        GeneralLiveConvertedObservation,
        crate::shadow_native::windows_aliases::ObservedWindowsAliases,
    )> {
        pair.validate_with_resource_profile(Some(resource_profile))?;
        if pair.source != self.binding
            || pair.source.layout_profile
                != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        {
            return Err(invalid(
                "converted Windows alias observer source binding differs",
            ));
        }
        let admission = resource_profile
            .resource_admission()?
            .ok_or_else(|| invalid("converted alias observer requires actual V4 admission"))?;
        aliases.require_scope(
            &pair,
            admission.source_inspection_sha256,
            aliases.plan_digest(),
        )?;
        let ((report,observed_aliases),before,observed_readonly,after)=self.with_readonly_refs_binding_observation(events,|protected|{
            crate::lab_hold::reached_in_verification(
                    "verify-source-readonly",
                    "finalize-source-readonly",
                );
            let actual_label=protected_refs_label(protected.volume())?;
            let enrollment_label=crate::volume_label::VolumeLabel::from_text("n2r-retained-shadow")?;
            let effective_label=match expected_label{
                Some(desired)if *desired==actual_label=>Some(desired),
                _ if actual_label==enrollment_label=>None,
                _=>return Err(invalid("converted label is neither enrollment nor original source label")),
            };
            let (report,observed_aliases)=crate::shadow_native::observe_general_converted_metadata_domain_readonly_with_windows_aliases(
                pair.clone(),input,effective_label,&same_security,resource_profile,memory,protected,aliases)?;
            let report=crate::shadow_native::verify_known_contents_in_accounted_report_with_lease_windows_aliases(
                report,input,admission,memory,&same_security,Some(protected),aliases)?;
            observed_aliases.require_converted_scope(&pair,admission.source_inspection_sha256,aliases.plan_digest())?;
            observed_aliases.require_input(input)?;
            Ok((report,observed_aliases))
        })?;
        if before != after
            || before.disk_attributes != OFFLINE | READ_ONLY
            || observed_readonly.disk_attributes != READ_ONLY
            || report.pair != pair
        {
            return Err(invalid(
                "converted alias observation changed source identity/exclusion",
            ));
        }
        Ok((
            GeneralLiveConvertedObservation {
                report,
                before,
                observed_readonly,
                after,
            },
            observed_aliases,
        ))
    }

    /// Restart finalization from authenticated alias expectations, never a
    /// deserialized constructor witness. Actual alias identities, metadata,
    /// points and security are checked within this owner's physical READ_ONLY
    /// ReFS lease before the complete canonical-plus-alias namespace/content
    /// validators can issue the returned opaque native observations.
    pub fn observe_converted_protected_with_memory_windows_alias_expectations(
        &mut self,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        expected_label: Option<&crate::volume_label::VolumeLabel>,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: crate::attestation::ResourceProfile,
        memory: &dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
        expectations: &impl crate::shadow_native::windows_aliases::WindowsAliasInputDomain,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<(
        GeneralLiveConvertedObservation,
        crate::shadow_native::windows_aliases::ObservedWindowsAliases,
    )> {
        pair.validate_with_resource_profile(Some(resource_profile))?;
        if pair.source != self.binding
            || pair.source.layout_profile
                != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        {
            return Err(invalid(
                "recovered Windows alias observer source binding differs",
            ));
        }
        let admission = resource_profile
            .resource_admission()?
            .ok_or_else(|| invalid("recovered alias observer requires actual V4 admission"))?;
        input.require_resource_metadata(admission)?;
        expectations.require_resource_metadata(admission)?;
        if expectations.source_inspection_sha256() != admission.source_inspection_sha256 {
            return Err(invalid(
                "recovered alias expectations have another source inspection",
            ));
        }
        expectations.revalidate()?;
        let plan_digest = expectations.semantic_sha256()?;
        let ((report, observed_aliases), before, observed_readonly, after) = self
            .with_readonly_refs_binding_observation(events, |protected| {
                crate::lab_hold::reached_in_verification(
                    "verify-source-readonly",
                    "finalize-source-readonly",
                );
                let actual_label = protected_refs_label(protected.volume())?;
                let enrollment_label =
                    crate::volume_label::VolumeLabel::from_text("n2r-retained-shadow")?;
                let effective_label = match expected_label {
                    Some(desired) if *desired == actual_label => Some(desired),
                    _ if actual_label == enrollment_label => None,
                    _ => {
                        return Err(invalid(
                            "converted label is neither enrollment nor original source label",
                        ));
                    }
                };
                crate::perf::step("check recovered alias links");
                let aliases = crate::shadow_native::windows_aliases::VerifiedWindowsAliases::
                    from_recovered_expectations_readonly(
                        &pair, input, expectations, admission, protected, memory, &same_security,
                    )?;
                aliases.require_scope(&pair, admission.source_inspection_sha256, plan_digest)?;
                crate::perf::step("walk converted metadata");
                let (report, observed_aliases) = crate::shadow_native::
                    observe_general_converted_metadata_domain_readonly_with_windows_aliases(
                        pair.clone(), input, effective_label, &same_security,
                        resource_profile, memory, protected, &aliases,
                    )?;
                crate::perf::step("check converted file contents");
                let report = crate::shadow_native::
                    verify_known_contents_in_accounted_report_with_lease_windows_aliases(
                        report, input, admission, memory, &same_security, Some(protected), &aliases,
                    )?;
                crate::perf::step("close converted observation");
                observed_aliases.require_converted_scope(
                    &pair,
                    admission.source_inspection_sha256,
                    plan_digest,
                )?;
                observed_aliases.require_input(input)?;
                if observed_aliases.len() != expectations.len() {
                    return Err(invalid("recovered Windows alias coverage differs"));
                }
                expectations.revalidate()?;
                if expectations.semantic_sha256()? != plan_digest {
                    return Err(invalid(
                        "recovered alias expectation plan changed during observation",
                    ));
                }
                Ok((report, observed_aliases))
            })?;
        if before != after
            || before.disk_attributes != OFFLINE | READ_ONLY
            || observed_readonly.disk_attributes != READ_ONLY
            || report.pair != pair
        {
            return Err(invalid(
                "recovered alias observation changed source identity/exclusion",
            ));
        }
        expectations.revalidate()?;
        Ok((
            GeneralLiveConvertedObservation {
                report,
                before,
                observed_readonly,
                after,
            },
            observed_aliases,
        ))
    }

    /// Bring an actually frozen HND source online only after the exact held
    /// markerless journal, paged index and selected NEW bytes validate. This
    /// closes rollback but does not claim native ReFS/map verification.
    pub fn bring_online_after_paged_handoff(
        mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        observation: &GeneralLiveConvertedObservation,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "frozen handoff mount requires offline read-only source",
            ));
        }
        let mut readonly = before.clone();
        readonly.disk_attributes = READ_ONLY;
        let report = observation.report();
        let content = report
            .content_observation
            .as_ref()
            .ok_or_else(|| invalid("protected converted-content observation absent"))?;
        if observation.before() != &before
            || observation.after() != &before
            || observation.observed_readonly() != &readonly
            || report.pair.source != self.binding
            || report.native.binding.identity != self.binding.identity
            || !content.metadata_and_namespace_verified
            || !content.complete_stream_mappings_observed
            || !content.data_storage_validity_checked
            || content.known_content.is_none()
        {
            return Err(invalid(
                "actual protected converted observation differs from HND source",
            ));
        }
        let binding = self.binding.clone();
        let length = self.byte_len();
        verify_paged_handoff(&mut self, length, &binding, policy, journal, pins)?;
        if self.state(events)? != before {
            return Err(invalid("frozen handoff source changed during validation"));
        }
        let path = format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number);
        let gate = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(1)
            .custom_flags(0xa000_0000)
            .open(&path)?;
        if general_disk_state(&gate, &self.binding, events)? != before {
            return Err(invalid("handoff mount gate does not match frozen source"));
        }
        let probe = device_file(&path, true, true);
        match probe {
            Ok(file) => {
                close_file(file, "close-unexpected-handoff-writer-probe", events)?;
                return Err(invalid("handoff mount gate allowed a second raw writer"));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => (),
            Err(error) => return Err(error),
        }
        self.file = gate;
        self.freeze_observation = None;
        GeneralJournaledPartition {
            inner: self,
            policy: None,
            paged_policy: None,
            write_poisoned: false,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        }
        .bring_online(events)
    }

    /// Re-establish OFFLINE|READ_ONLY on the original in-place source owner
    /// after authenticating the held HND journal and selected NEW target bytes.
    /// This never mounts the filesystem and never recreates the old NTFS proof.
    pub fn seal_paged_handoff_for_observation(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE {
            return Err(invalid(
                "handoff reseal requires the same offline source owner",
            ));
        }
        let binding = self.binding.clone();
        let length = self.byte_len();
        verify_paged_handoff(self, length, &binding, policy, journal, pins)?;
        if self.state(events)? != before {
            return Err(invalid(
                "handoff source changed during selected NEW verification",
            ));
        }
        let mut expected = before;
        expected.disk_attributes = OFFLINE | READ_ONLY;
        set_attributes(&self.file, OFFLINE | READ_ONLY, events)?;
        if general_disk_state(&self.file, &self.binding, events)? != expected {
            return Err(invalid(
                "handoff read-only reseal identity or attributes differ",
            ));
        }
        // Open a separate readonly/shareable handle while the exclusive gate
        // is still held, then drop the gate. The same source object remains in
        // place and the protected ReFS observer can later open its control
        // route without accidentally keeping a write-capable alias alive.
        let path = format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number);
        let readonly = device_file(&path, false, true)?;
        if general_disk_state(&readonly, &self.binding, events)? != expected {
            return Err(invalid("handoff readonly source handle route differs"));
        }
        self.file = readonly;
        self.frozen_state = expected;
        self.freeze_observation = None;
        Ok(())
    }

    /// The reseal before the handoff (the review stop, #110, and a run whose
    /// handoff follows its verification, #148): the same as the handoff's
    /// above, but beside the apply intent alone, with every selected byte
    /// exactly NEW. Only a run whose authenticated publication records one
    /// of the two calls this; the handoff is not written and rollback stays
    /// open. This never mounts the volume.
    pub fn seal_paged_review_for_observation(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE {
            return Err(invalid(
                "the reseal before the handoff requires the same offline source owner",
            ));
        }
        let binding = self.binding.clone();
        let length = self.byte_len();
        verify_paged_review_stop(self, length, &binding, policy, journal, pins)?;
        if self.state(events)? != before {
            return Err(invalid(
                "before the handoff: the source changed during selected NEW verification",
            ));
        }
        let mut expected = before;
        expected.disk_attributes = OFFLINE | READ_ONLY;
        set_attributes(&self.file, OFFLINE | READ_ONLY, events)?;
        if general_disk_state(&self.file, &self.binding, events)? != expected {
            return Err(invalid(
                "before the handoff: read-only reseal identity or attributes differ",
            ));
        }
        let path = format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number);
        let readonly = device_file(&path, false, true)?;
        if general_disk_state(&readonly, &self.binding, events)? != expected {
            return Err(invalid(
                "before the handoff: readonly source handle route differs",
            ));
        }
        self.file = readonly;
        self.frozen_state = expected;
        self.freeze_observation = None;
        Ok(())
    }

    /// Put a sealed review stop online, read-only (#110): the disk goes from
    /// OFFLINE|READ_ONLY to READ_ONLY and stays there when this process
    /// ends, so that Windows mounts the converted volume write-protected.
    /// The apply intent alone and every selected byte exactly NEW are
    /// authenticated first. Nothing is written to the disk, and the handoff
    /// is not written: `--recover` commits, `--recover --rollback` undoes.
    pub fn present_paged_review_readonly(
        self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::GeneralDiskState> {
        let mut source = self;
        let before = source.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "a review is presented only from the offline read-only source",
            ));
        }
        let binding = source.binding.clone();
        let length = source.byte_len();
        verify_paged_review_stop(&mut source, length, &binding, policy, journal, pins)?;
        if source.state(events)? != before {
            return Err(invalid("review source changed during its verification"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", source.binding.disk_number),
            true,
            false,
        )?;
        if general_disk_state(&management, &source.binding, events)? != before {
            return Err(invalid("review presentation control-handle route differs"));
        }
        let mut expected = before;
        expected.disk_attributes = READ_ONLY;
        set_attributes(&management, READ_ONLY, events)?;
        super::control(
            &management,
            "refresh-review-readonly-refs-properties",
            super::UPDATE_PROPERTIES,
            &[],
            0,
            events,
        )?;
        let mut published = false;
        for _ in 0..60 {
            if super::attributes(&management, events)? != READ_ONLY {
                return Err(invalid("the review disk lost its read-only state"));
            }
            match device_file(&source.binding.volume_path()?, false, false) {
                Ok(volume) => {
                    close_file(volume, "close-review-presentation-volume", events)?;
                    published = true;
                    break;
                }
                Err(error) if matches!(error.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                Err(error) => return Err(error),
            }
        }
        if !published {
            return Err(invalid(
                "the read-only ReFS volume of the review was not published within 15 seconds",
            ));
        }
        let after = general_disk_state(&management, &source.binding, events)?;
        if after != expected {
            return Err(invalid("review presentation identity or attributes differ"));
        }
        close_file(management, "close-review-presentation-management", events)?;
        // The frozen owner's read handle closes here; the persistent
        // READ_ONLY attribute is what keeps the volume write-protected.
        drop(source);
        Ok(after)
    }

    /// Recover the protected crash window in which AP reached the journal but
    /// the fresh source never left OFFLINE|READ_ONLY. Require the complete OLD
    /// selected source digest before making the same actual disk writable; a
    /// partially changed target must use ordinary OFFLINE recovery instead.
    pub fn into_paged_recovery_target_from_frozen(
        self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        direction: PagedRecoveryDirection,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralExclusiveRecoveryTarget> {
        self.into_paged_recovery_target_from_frozen_accepting(
            policy,
            journal,
            pins,
            direction,
            FrozenSelected::Old,
            events,
        )
    }

    /// The same for a run whose authenticated publication records that it
    /// stops for a review before its handoff (#110). Such a run seals its
    /// source again after every new byte is written, so its frozen source
    /// under the apply intent holds either exactly the OLD selected bytes
    /// (cut before its first write) or exactly the NEW ones (the review
    /// stop). Anything else, a mixture included, is refused here as well.
    pub fn into_paged_recovery_target_from_frozen_for_review(
        self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        direction: PagedRecoveryDirection,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralExclusiveRecoveryTarget> {
        self.into_paged_recovery_target_from_frozen_accepting(
            policy,
            journal,
            pins,
            direction,
            FrozenSelected::OldOrNew,
            events,
        )
    }

    fn into_paged_recovery_target_from_frozen_accepting(
        mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        direction: PagedRecoveryDirection,
        accepted: FrozenSelected,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralExclusiveRecoveryTarget> {
        pins.journal_binding.validate()?;
        if self.binding.disk_number == pins.journal_binding.disk.disk_number
            || crate::layout::guid_bytes(&self.binding.identity.disk_guid)?
                == crate::layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?
        {
            return Err(invalid(
                "protected recovery journal must be on a different physical disk",
            ));
        }
        let facts = policy.facts()?;
        if pins.journal_profile.version() != 3
            || !(1..=5).contains(&facts.format_version)
            || facts.image_length != self.byte_len()
            || facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
            || facts.journal_length > pins.journal_profile.max_journal_bytes()
            || facts.journal_immutable_sha256 != pins.immutable_sha256
        {
            return Err(invalid(
                "protected recovery geometry or journal capacity differs",
            ));
        }
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "protected recovery requires the actual offline read-only source",
            ));
        }
        let journal_before = verify_journal_owner(journal, pins, facts.journal_length)?;
        let modified = journal.metadata()?.modified()?;
        check_lifecycle(journal, pins, direction)?;
        if crate::bulk_digest::journal_body(
            pins.digest,
            journal,
            BODY,
            facts.journal_length - BODY,
            &pins.immutable_sha256,
        )? != pins.immutable_sha256
        {
            return Err(invalid("protected recovery journal immutable body differs"));
        }
        verify_index_against_journal(journal, policy, pins)?;
        // The same ordered pass over the changed ranges as the one in front
        // of a fresh apply (`begin_paged_fresh_apply`), read ahead the same
        // way: the source is offline and read-only here, and nothing writes
        // to it during the pass.
        let actual = self.with_read_ahead(|source| {
            selected_digest_reaching(
                source,
                policy,
                pins.digest,
                false,
                GeneralFrozenPartition::set_read_ahead_reach,
            )
        })?;
        if !accepted.admits(actual, pins) {
            return Err(invalid(match accepted {
                FrozenSelected::Old => "actual excluded source selected bytes differ",
                FrozenSelected::OldOrNew => {
                    "the frozen source of a run that seals before its handoff holds neither exactly the old nor \
                     exactly the new selected bytes"
                }
            }));
        }
        if self.state(events)? != before {
            return Err(invalid(
                "protected recovery source changed during OLD verification",
            ));
        }
        check_lifecycle(journal, pins, direction)?;
        if crate::bulk_digest::journal_body(
            pins.digest,
            journal,
            BODY,
            facts.journal_length - BODY,
            &pins.immutable_sha256,
        )? != pins.immutable_sha256
        {
            return Err(invalid(
                "protected recovery journal changed during OLD verification",
            ));
        }
        verify_index_against_journal(journal, policy, pins)?;
        check_lifecycle(journal, pins, direction)?;
        let journal_after = verify_journal_owner(journal, pins, facts.journal_length)?;
        if journal_before.identity != journal_after.identity
            || journal_before.file_bytes != journal_after.file_bytes
            || !journal_before
                .final_path
                .eq_ignore_ascii_case(&journal_after.final_path)
            || journal.metadata()?.modified()? != modified
        {
            return Err(invalid("protected recovery journal identity changed"));
        }
        // The original frozen NTFS observation cannot remain a future source
        // certificate once a durable apply intent exists.
        self.freeze_observation = None;
        let writer = self.activate_for_journal_exclusive(events)?;
        if writer.state(events)?.disk_attributes != OFFLINE {
            return Err(invalid(
                "protected recovery activation lost offline exclusion",
            ));
        }
        Ok(GeneralExclusiveRecoveryTarget { inner: writer })
    }

    /// Start a one-shot markerless fresh apply from the actual held frozen
    /// source. The caller must retain the independently qualified source,
    /// protected target, arena and journal owners for the complete borrow.
    /// The journal's AP is flushed and read back before the disk becomes
    /// writable; interruption between those steps leaves OFFLINE|READ_ONLY+AP.
    ///
    /// `hashed_behind`: the caller paid for [`SELECTED_DIGEST_BEHIND_BYTES`]
    /// (spare memory), and the OLD bytes are hashed on a worker while this
    /// thread reads on. The digest, and what it is held to, are the same.
    pub fn begin_paged_fresh_apply<'a>(
        &'a mut self,
        policy: HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        hashed_behind: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<BorrowedPagedWriter<'a>> {
        pins.journal_binding.validate()?;
        if self.binding.disk_number == pins.journal_binding.disk.disk_number
            || crate::layout::guid_bytes(&self.binding.identity.disk_guid)?
                == crate::layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?
        {
            return Err(invalid(
                "fresh paged journal must be on a different physical disk",
            ));
        }
        let facts = policy.facts()?;
        if pins.journal_profile.version() != 3
            || !(1..=5).contains(&facts.format_version)
            || facts.image_length != self.byte_len()
            || facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
            || facts.journal_length > pins.journal_profile.max_journal_bytes()
            || facts.journal_immutable_sha256 != pins.immutable_sha256
        {
            return Err(invalid(
                "fresh paged policy geometry or journal capacity differs",
            ));
        }
        let before = self.state(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid(
                "fresh paged apply requires the actual offline read-only source",
            ));
        }
        let journal_before = verify_journal_owner(journal, pins, facts.journal_length)?;
        let modified = journal.metadata()?.modified()?;
        check_clear_lifecycle(journal)?;
        // The journal's body and the source's OLD bytes are on different
        // disks and are both gigabytes: hash the one on a second thread while
        // this one reads and hashes the other.
        let (body, old_bytes) = {
            let expected = pins.immutable_sha256;
            let algorithm = pins.digest;
            let length = facts.journal_length - BODY;
            let journal = &mut *journal;
            std::thread::scope(|scope| {
                let body = scope.spawn(move || {
                    let _sampled = crate::stack_sampler::helper();
                    crate::bulk_digest::journal_body(algorithm, journal, BODY, length, &expected)
                });
                let old_bytes = self.with_read_ahead(|source| {
                    let actual = selected_digest_reaching(
                        source,
                        &policy,
                        algorithm,
                        hashed_behind,
                        GeneralFrozenPartition::set_read_ahead_reach,
                    )?;
                    if actual != pins.old_selected_sha256 {
                        return Err(invalid("actual excluded source selected bytes differ"));
                    }
                    Ok(())
                });
                (body.join(), old_bytes)
            })
        };
        let body = body.map_err(|_| io::Error::other("journal hashing thread panicked"))??;
        if body != pins.immutable_sha256 {
            return Err(invalid("fresh held journal immutable body differs"));
        }
        verify_index_against_journal(journal, &policy, pins)?;
        old_bytes?;
        if self.state(events)? != before {
            return Err(invalid(
                "fresh source exclusion or identity changed during OLD verification",
            ));
        }
        check_clear_lifecycle(journal)?;
        // Ordinary sharing excludes new file writers, not privileged raw
        // aliases. Preserve a complete closing body hash before publishing AP
        // (left out under check-once, where the body matched in this gate a
        // moment ago, and with it the second walk of its descriptors under
        // `--verify fast`).
        let (closing, body_read) = crate::bulk_digest::journal_body_reading(
            pins.digest,
            journal,
            BODY,
            facts.journal_length - BODY,
            &pins.immutable_sha256,
        )?;
        if closing != pins.immutable_sha256 {
            return Err(invalid(
                "fresh held journal changed during OLD verification",
            ));
        }
        verify_index_against_journal_again(journal, &policy, pins, body_read)?;
        check_clear_lifecycle(journal)?;
        let journal_after = verify_journal_owner(journal, pins, facts.journal_length)?;
        if journal_before.identity != journal_after.identity
            || journal_before.file_bytes != journal_after.file_bytes
            || !journal_before
                .final_path
                .eq_ignore_ascii_case(&journal_after.final_path)
            || journal.metadata()?.modified()? != modified
        {
            return Err(invalid(
                "fresh journal identity changed during verification",
            ));
        }
        let path = format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number);
        // The apply writes through this handle. It is unbuffered, so every
        // read comes from the device, but not write-through: durability is
        // the apply's own barriers (`BorrowedPagedWriter::sync_all`), one
        // after every changed range but the boot granule, which is written
        // only after it, and one after the boot granule before anything is
        // read back or any marker follows. A write-through write waited for
        // the disk each time: 309,578 of them, 50 s on the full Windows
        // volume (owner's decision, 2026-11-21, #249).
        let gate = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(1)
            .custom_flags(super::UNBUFFERED_WRITER_FLAGS)
            .open(&path)?;
        if general_disk_state(&gate, &self.binding, events)? != before {
            return Err(invalid(
                "fresh exclusive source gate differs from the frozen source",
            ));
        }
        let probe = device_file(&path, true, true);
        match probe {
            Ok(file) => {
                close_file(file, "close-unexpected-fresh-paged-writer-probe", events)?;
                return Err(invalid("fresh source gate allowed a second raw writer"));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => (),
            Err(error) => return Err(error),
        }
        // Once an AP write is attempted, the journal may contain a durable or
        // torn intent even if the call fails. Never reuse the old NTFS freeze
        // observation for a fresh admission; reopen the recovery lifecycle.
        self.freeze_observation = None;
        // The exact old selected digest and clear marker were checked while
        // the source was frozen. AP is durable before any writable transition.
        let apply = marker(
            b"N2RSAP01",
            &pins.immutable_sha256,
            &pins.new_selected_sha256,
        );
        journal.seek(SeekFrom::Start(GRANULE))?;
        journal.write_all(&apply)?;
        journal.sync_all()?;
        let mut readback = [0; GRANULE as usize];
        read_at(journal, GRANULE, &mut readback)?;
        if readback != apply {
            return Err(invalid("fresh paged AP marker readback differs"));
        }
        check_lifecycle(journal, pins, PagedRecoveryDirection::Resume)?;
        events.push(NativeEvent {
            operation: "fresh-paged-apply-intent-durable".into(),
            control_code: 0,
            input: vec![],
            succeeded: true,
            native_error: None,
            output: b"AP flushed and read back before source writable transition".to_vec(),
        });
        if general_disk_state(&gate, &self.binding, events)? != before {
            return Err(invalid(
                "source changed after durable AP; reopen protected recovery",
            ));
        }
        let mut expected = before.clone();
        expected.disk_attributes = OFFLINE;
        let transition = set_attributes(&gate, OFFLINE, events).and_then(|()| {
            if general_disk_state(&gate, &self.binding, events)? != expected {
                return Err(invalid("fresh paged activation lost offline exclusion"));
            }
            Ok(())
        });
        if let Err(error) = transition {
            let restored = set_attributes(&gate, OFFLINE | READ_ONLY, events).and_then(|()| {
                if general_disk_state(&gate, &self.binding, events)? != before {
                    return Err(invalid("fresh paged activation protection restore differs"));
                }
                Ok(())
            });
            return match restored {
                Ok(()) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "fresh activation failed after durable AP; source is offline/read-only: {error}"
                    ),
                )),
                Err(restore) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "fresh activation failed after durable AP: {error}; restoring read-only protection also failed: {restore}"
                    ),
                )),
            };
        }
        self.file = gate;
        self.frozen_state = expected;
        Ok(BorrowedPagedWriter {
            source: self,
            policy,
            poisoned: false,
            requested: 0,
            written: 0,
        })
    }
}

impl GeneralExclusiveRecoveryTarget {
    pub fn bring_online_after_paged_abort(
        self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if self.inner.write_poisoned
            || self.inner.policy.is_some()
            || self.inner.paged_policy.is_some()
        {
            return Err(invalid(
                "rollback mount requires an unarmed recovery target",
            ));
        }
        self.inner
            .inner
            .bring_online_after_paged_abort(policy, journal, pins, events)
    }

    /// The same beside the apply intent alone, for a run whose authenticated
    /// publication records that its handoff follows its verification (#148):
    /// a recovery replayed every new byte and seals the source again.
    pub fn seal_paged_review_for_observation(
        self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralFrozenPartition> {
        if self.inner.write_poisoned
            || self.inner.policy.is_some()
            || self.inner.paged_policy.is_some()
        {
            return Err(invalid(
                "the reseal before the handoff requires an unarmed, unpoisoned recovery target",
            ));
        }
        let mut source = self.inner.inner;
        source.seal_paged_review_for_observation(policy, journal, pins, events)?;
        Ok(source)
    }

    /// Return the same actual HND source to OFFLINE|READ_ONLY for a protected
    /// ReFS observation. This does not mount the volume or authorize ordinary
    /// writable service.
    pub fn seal_paged_handoff_for_observation(
        self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralFrozenPartition> {
        if self.inner.write_poisoned
            || self.inner.policy.is_some()
            || self.inner.paged_policy.is_some()
        {
            return Err(invalid(
                "handoff reseal requires an unarmed, unpoisoned recovery target",
            ));
        }
        let mut source = self.inner.inner;
        source.seal_paged_handoff_for_observation(policy, journal, pins, events)?;
        Ok(source)
    }

    /// Consume the actual excluded target and arm only the exact authenticated
    /// markerless journal ranges. This does not accept PreparedClear/HND/ABT,
    /// does not mount the target, and never opens or formats a different disk.
    pub fn arm_paged_recovery(
        mut self,
        policy: HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        direction: PagedRecoveryDirection,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralJournaledPartition> {
        pins.journal_binding.validate()?;
        let target = self.binding();
        if target.disk_number == pins.journal_binding.disk.disk_number
            || crate::layout::guid_bytes(&target.identity.disk_guid)?
                == crate::layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?
        {
            return Err(invalid(
                "recovery journal must be on a different physical disk",
            ));
        }
        let facts = policy.facts()?;
        if pins.journal_profile.version() != 3
            || !(1..=5).contains(&facts.format_version)
            || facts.image_length != self.byte_len()
            || facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
            || facts.journal_length > pins.journal_profile.max_journal_bytes()
            || facts.journal_immutable_sha256 != pins.immutable_sha256
        {
            return Err(invalid(
                "paged recovery geometry or pinned journal capacity differs",
            ));
        }
        let state = self.state(events)?;
        if state.disk_attributes != OFFLINE {
            return Err(invalid("paged recovery target lost offline exclusion"));
        }
        let before = crate::journal_file::observe_general_journal_file_with_profile(
            journal,
            pins.journal_binding,
            pins.journal_profile,
        )?;
        if &before.identity != pins.journal_identity
            || before.file_bytes != facts.journal_length
            || !before
                .final_path
                .eq_ignore_ascii_case(&pins.journal_path.to_string_lossy())
        {
            return Err(invalid(
                "actual held native journal identity, route or length differs",
            ));
        }
        // Probe the exact same observed file route. Access-denied is not a
        // sharing proof; only a sharing violation proves this ordinary writer
        // route was refused while the original journal handle remains held.
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(pins.journal_path);
        match probe {
            Ok(_) => return Err(invalid("held recovery journal permits a second writer")),
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => (),
            Err(error) => return Err(error),
        }
        check_lifecycle(journal, pins, direction)?;
        if crate::bulk_digest::journal_body(
            pins.digest,
            journal,
            BODY,
            facts.journal_length - BODY,
            &pins.immutable_sha256,
        )? != pins.immutable_sha256
        {
            return Err(invalid(
                "actual held recovery journal immutable body differs",
            ));
        }
        verify_index_against_journal(journal, &policy, pins)?;
        check_lifecycle(journal, pins, direction)?;
        let after = crate::journal_file::observe_general_journal_file_with_profile(
            journal,
            pins.journal_binding,
            pins.journal_profile,
        )?;
        if after.identity != before.identity
            || after.file_bytes != before.file_bytes
            || !after.final_path.eq_ignore_ascii_case(&before.final_path)
            || self.state(events)? != state
        {
            return Err(invalid(
                "held recovery journal or excluded target changed during authorization",
            ));
        }
        self.inner.arm_resource_paged_writes(
            policy,
            pins.journal_profile,
            pins.journal_profile.max_journal_bytes(),
            ResourcePolicyAuthority {
                _authenticated_markerless_recovery: (),
            },
            events,
        )?;
        if self.state(events)? != state {
            return Err(invalid("excluded recovery target changed while arming"));
        }
        Ok(self.inner)
    }
}

impl GeneralJournaledPartition {
    /// Drop the armed paged write policy and return to the same held,
    /// read-only-at-the-type-boundary excluded recovery target. This does not
    /// mount the volume or by itself establish that replay has closed.
    pub fn into_unarmed_paged_recovery(
        mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralExclusiveRecoveryTarget> {
        if self.write_poisoned || self.policy.is_some() || self.paged_policy.is_none() {
            return Err(invalid(
                "paged recovery writer is absent, conflicted or poisoned",
            ));
        }
        self.sync_all()?;
        if self.state(events)?.disk_attributes != OFFLINE {
            return Err(invalid("paged recovery source lost offline exclusion"));
        }
        self.paged_policy = None;
        // A window a pass of the replay left on does not outlive the writer.
        self.set_read_ahead(false);
        Ok(GeneralExclusiveRecoveryTarget { inner: self })
    }
}

/// New private-partition gate only; legacy whole-disk paths above are unchanged.
/// This does not issue source admission, publish AP or clear exclusion. It uses
/// the existing actual journal/index/lifecycle and OLD/NEW selected-byte checks.
pub(super) fn authenticate_partition_paged_source(
    source: &mut super::partition_owner::PartitionScopedOwner,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
    require_new: bool,
) -> io::Result<()> {
    pins.journal_binding.validate()?;
    let binding = &source.binding().storage;
    // Initial foundation retains independent-disk J policy. C:-sibling journal
    // extent disjointness is a separate unimplemented source-scope change.
    if binding.disk_number == pins.journal_binding.disk.disk_number
        || crate::layout::guid_bytes(&binding.identity.disk_guid)?
            == crate::layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?
    {
        return Err(invalid(
            "partition foundation journal must remain on an independent disk",
        ));
    }
    let facts = policy.facts()?;
    if pins.journal_profile.version() != 3
        || !(1..=5).contains(&facts.format_version)
        || facts.image_length != source.byte_len()
        || facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
        || facts.journal_length > pins.journal_profile.max_journal_bytes()
        || facts.journal_immutable_sha256 != pins.immutable_sha256
    {
        return Err(invalid(
            "partition paged policy/journal/geometry binding differs",
        ));
    }
    let before = verify_journal_owner(journal, pins, facts.journal_length)?;
    let modified = journal.metadata()?.modified()?;
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(pins.journal_path);
    match probe {
        Ok(_) => {
            return Err(invalid(
                "partition journal permits a second ordinary writer",
            ));
        }
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => (),
        Err(error) => return Err(error),
    }
    check_lifecycle(journal, pins, PagedRecoveryDirection::Resume)?;
    if crate::bulk_digest::journal_body(
        pins.digest,
        journal,
        BODY,
        facts.journal_length - BODY,
        &pins.immutable_sha256,
    )? != pins.immutable_sha256
    {
        return Err(invalid("partition held journal immutable body differs"));
    }
    verify_index_against_journal(journal, policy, pins)?;
    verify_selected_digest(
        source,
        policy,
        pins.digest,
        if require_new {
            pins.new_selected_sha256
        } else {
            pins.old_selected_sha256
        },
    )?;
    check_lifecycle(journal, pins, PagedRecoveryDirection::Resume)?;
    if crate::bulk_digest::journal_body(
        pins.digest,
        journal,
        BODY,
        facts.journal_length - BODY,
        &pins.immutable_sha256,
    )? != pins.immutable_sha256
    {
        return Err(invalid(
            "partition journal changed around selected-byte gate",
        ));
    }
    let after = verify_journal_owner(journal, pins, facts.journal_length)?;
    if after.identity != before.identity
        || after.file_bytes != before.file_bytes
        || !after.final_path.eq_ignore_ascii_case(&before.final_path)
        || journal.metadata()?.modified()? != modified
    {
        return Err(invalid(
            "partition actual journal owner changed during gate",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod review_gate_tests {
    use super::*;

    fn with_pins<T>(test: impl FnOnce(&PagedRecoveryPins<'_>) -> T) -> T {
        let binding = GeneralJournalStorageBinding {
            disk: crate::general_layout::GeneralDiskBinding {
                disk_number: 5,
                volume_guid: "5f2d3e41-5555-4444-aabb-123456789abc".into(),
                identity: crate::layout::PartitionIdentity {
                    disk_guid: "12345678-1111-2222-aaaa-123456789abc".into(),
                    partition_guid: "23456789-2222-3333-bbbb-123456789abc".into(),
                    partition_number: 2,
                    disk_bytes: 8 << 30,
                    partition_offset: 1 << 20,
                    partition_bytes: 6 << 30,
                    logical_sector_bytes: 512,
                    physical_sector_bytes: 4096,
                },
                layout_profile: Default::default(),
            },
            externally_enrolled_disk_unique_id: "test".into(),
            allow_additional_partitions: false,
        };
        let identity = JournalFileIdentity {
            volume_serial_number: 1,
            file_id_128: [1; 16],
            volume_guid: [2; 16],
            disk_guid: [3; 16],
            partition_guid: [4; 16],
            partition_number: 2,
            disk_bytes: 8 << 30,
            partition_offset: 1 << 20,
            partition_bytes: 6 << 30,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        };
        let pins = PagedRecoveryPins {
            journal_binding: &binding,
            journal_identity: &identity,
            journal_path: Path::new("J:\\journal"),
            journal_profile: JournalProfile::CapacityPinnedV3 {
                max_journal_bytes: 1 << 30,
            },
            digest: crate::bulk_digest::Algorithm::WRITTEN,
            immutable_sha256: [7; 32],
            old_selected_sha256: [8; 32],
            old_restored_selected_sha256: None,
            new_selected_sha256: [9; 32],
        };
        test(&pins)
    }

    /// A journal whose completion granule and intent granule hold these.
    fn journal(completion: Option<&[u8; 8]>, intent: Option<&[u8; 8]>) -> tempfile::NamedTempFile {
        with_pins(|pins| {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            let mut body = vec![0u8; (2 * GRANULE) as usize];
            let selected = |magic: &[u8; 8]| match magic {
                b"N2RSAP01" | b"N2RSHN01" => pins.new_selected_sha256,
                _ => pins.old_selected_sha256,
            };
            if let Some(magic) = completion {
                body[..GRANULE as usize].copy_from_slice(&marker(
                    magic,
                    &pins.immutable_sha256,
                    &selected(magic),
                ));
            }
            if let Some(magic) = intent {
                body[GRANULE as usize..].copy_from_slice(&marker(
                    magic,
                    &pins.immutable_sha256,
                    &selected(magic),
                ));
            }
            file.write_all(&body).unwrap();
            file
        })
    }

    #[test]
    fn the_handoff_gate_and_the_review_gate_each_take_their_own_state_only() {
        type Case<'a> = (
            &'a str,
            Option<&'a [u8; 8]>,
            Option<&'a [u8; 8]>,
            bool,
            bool,
        );
        let cases: [Case<'_>; 5] = [
            ("clear", None, None, false, false),
            ("apply intent", None, Some(b"N2RSAP01"), false, true),
            ("handoff", Some(b"N2RSHN01"), Some(b"N2RSAP01"), true, false),
            ("rollback intent", None, Some(b"N2RSRB01"), false, false),
            ("abort", Some(b"N2RSAB01"), Some(b"N2RSRB01"), false, false),
        ];
        for (name, completion, intent, handoff, review) in cases {
            let held = journal(completion, intent);
            with_pins(|pins| {
                let mut file = File::open(held.path()).unwrap();
                assert_eq!(
                    NewBytesState::Handoff.check(&mut file, pins).is_ok(),
                    handoff,
                    "handoff gate, {name}"
                );
                assert_eq!(
                    NewBytesState::ReviewApply.check(&mut file, pins).is_ok(),
                    review,
                    "review gate, {name}"
                );
            });
        }
    }

    #[test]
    fn descriptors_are_walked_again_unless_the_body_read_was_left_out_of_a_fast_run() {
        // A body read in full is followed by its walk, whatever the run.
        assert!(descriptors_walked_again(true, true));
        assert!(descriptors_walked_again(true, false));
        // `--verify thorough`, `--recheck-everything` and a recovery walk
        // again even where the body's read was left out.
        assert!(descriptors_walked_again(false, false));
        // Only a run that verifies once leaves the walk out, beside the read.
        assert!(!descriptors_walked_again(false, true));
    }

    #[test]
    fn a_frozen_source_is_admitted_exactly_old_for_every_run_and_exactly_new_for_a_review() {
        with_pins(|pins| {
            let (old, new, mixed) = (
                pins.old_selected_sha256,
                pins.new_selected_sha256,
                [0xaa; 32],
            );
            assert!(FrozenSelected::Old.admits(old, pins));
            assert!(!FrozenSelected::Old.admits(new, pins));
            assert!(!FrozenSelected::Old.admits(mixed, pins));
            assert!(FrozenSelected::OldOrNew.admits(old, pins));
            assert!(FrozenSelected::OldOrNew.admits(new, pins));
            assert!(!FrozenSelected::OldOrNew.admits(mixed, pins));
        });
    }
}
