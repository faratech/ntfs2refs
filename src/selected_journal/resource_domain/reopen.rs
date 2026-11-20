//! Read-only, bounded reconstruction of a selected-journal record index.
//!
//! This owner authenticates bytes against an independently supplied ticket,
//! but neither the ticket nor the resulting index authorizes target writes.
//! A separately established excluded-device recovery capability is required
//! before any future replay method can be constructed.
pub(crate) mod envelope;
mod replay;
pub(crate) use replay::PartitionMixedObservation;
pub(crate) use replay::{PreparedOfflineClosedRun, PreparedOfflineReplayRun, PreparedOfflineRun};

use super::*;
use crate::{
    general_reconstruct::selected_native_journal::{
        BoundNativeJournalFacts, BoundNativeRecoveryJournal, NativeSelectedJournal,
    },
    lab_reconstruct::ReadSeek,
    selected_journal::{
        self as sj, BUFFER, PinHash, SelectedLifecycle, SelectedRange, SelectedTicket,
        aggregate_pin_hash, at, finish, frame, get_u32, get_u64, pin_hash,
    },
};

const HEADER_BYTES: u64 = 128;
const ROW_BYTES: u64 = 32;
const FOOTER_BYTES: u64 = 64;
const INDEX_MAGIC: &[u8; 8] = b"N2RRIX01";
const INDEX_END: &[u8; 8] = b"N2RRIEND";

#[derive(Clone, Copy)]
struct JournalFormat {
    version: u32,
    magic: &'static [u8; 8],
    footer: &'static [u8; 8],
    record_size: usize,
    hashes: usize,
    body: u64,
}
impl JournalFormat {
    fn decode(header: &[u8; HEADER], ticket: &SelectedTicket) -> Result<Self> {
        let version = get_u32(header, 8);
        let (magic, footer, record_size, hashes): (&[u8; 8], &[u8; 8], usize, usize) = match version
        {
            1 => (b"N2RSEL01", b"N2RSEND1", RECORD, 16),
            2 => (b"N2RZERO1", b"N2RZEND1", ZERO_RECORD, 24),
            3 => (b"N2RCPY01", b"N2RCEND1", COPY_RECORD, 32),
            4 => (b"N2ROLD01", b"N2ROEND1", OLD_ZERO_RECORD, 40),
            5 => (b"N2RFRE01", b"N2RFEND1", OLD_ZERO_RECORD, 40),
            6 => (b"N2RFRE02", b"N2RFEND2", OLD_ZERO_RECORD, 40),
            _ => anyhow::bail!("unsupported selected-journal format"),
        };
        ensure!(
            &header[..8] == magic && (version == 6) == ticket.marker_profile.is_some(),
            "selected journal format and marker profile differ"
        );
        Ok(Self {
            version,
            magic,
            footer,
            record_size,
            hashes,
            body: if version == 6 { REDUNDANT_BODY } else { BODY },
        })
    }
}

/// Derived strictly from authenticated journal bytes. Kinds use the existing
/// on-disk numbers: new 0=payload,1=zero,2=COPY; old 0=payload,1=zero,2=free.
#[derive(Clone, Copy)]
struct Record {
    offset: u64,
    length: u64,
    descriptor: u64,
    old_kind: u64,
    new_kind: u64,
    copy_source: u64,
    old_payload: u64,
    new_payload: u64,
    next: u64,
    old_hash: [u8; 32],
    new_hash: [u8; 32],
}
impl Record {
    fn decode(
        bytes: &[u8; OLD_ZERO_RECORD],
        descriptor: u64,
        fmt: JournalFormat,
        image: u64,
    ) -> Result<Self> {
        let offset = get_u64(bytes, 0);
        let length = get_u64(bytes, 8);
        let new_kind = if fmt.version >= 2 {
            get_u64(bytes, 16)
        } else {
            0
        };
        let copy_source = if fmt.version >= 3 {
            get_u64(bytes, 24)
        } else {
            0
        };
        let old_kind = if fmt.version >= 4 {
            get_u64(bytes, 32)
        } else {
            0
        };
        let end = add(offset, length)?;
        ensure!(
            length != 0
                && offset.is_multiple_of(GRANULE)
                && length.is_multiple_of(GRANULE)
                && end <= image
                && new_kind <= if fmt.version >= 3 { 2 } else { 1 }
                && old_kind <= if fmt.version >= 5 { 2 } else { 1 }
                && (new_kind == 2 || copy_source == 0),
            "resource journal record encoding or geometry differs"
        );
        if old_kind == 2 {
            ensure!(
                offset >= GRANULE && end <= image - GRANULE,
                "resource source-free record covers a protected bookend"
            );
        }
        if new_kind == 2 {
            ensure!(
                copy_source.is_multiple_of(GRANULE) && add(copy_source, length)? <= offset,
                "resource COPY source must precede the destination"
            );
        }
        let old_payload = add(descriptor, fmt.record_size as u64)?;
        let old_bytes = match old_kind {
            0 => length,
            1 => 0,
            2 => (length / GRANULE)
                .checked_mul(FREE_DIGEST)
                .context("free digest table overflow")?,
            _ => unreachable!(),
        };
        let new_payload = add(old_payload, old_bytes)?;
        let next = add(new_payload, if new_kind == 0 { length } else { 0 })?;
        Ok(Self {
            offset,
            length,
            descriptor,
            old_kind,
            new_kind,
            copy_source,
            old_payload,
            new_payload,
            next,
            old_hash: bytes[fmt.hashes..fmt.hashes + 32].try_into()?,
            new_hash: bytes[fmt.hashes + 32..fmt.hashes + 64].try_into()?,
        })
    }
    fn range(self) -> SelectedRange {
        SelectedRange {
            offset: self.offset,
            length: self.length,
        }
    }
    fn index_row(self) -> [u8; ROW_BYTES as usize] {
        let mut out = [0u8; ROW_BYTES as usize];
        out[..8].copy_from_slice(&self.offset.to_le_bytes());
        out[8..16].copy_from_slice(&self.length.to_le_bytes());
        out[16..24].copy_from_slice(&self.descriptor.to_le_bytes());
        out[24..32].copy_from_slice(&(self.old_kind | (self.new_kind << 2)).to_le_bytes());
        out
    }
}

/// Only read-only inspection and lifecycle classification are exposed. The
/// actual journal owner is retained; no raw handle or ticket getter exists.
pub(crate) struct JournalObservation<'a> {
    journal: &'a mut NativeSelectedJournal,
    ticket: &'a SelectedTicket,
    index: n2r_win32::HeldPagedWritePolicy,
    index_lease: ArtifactLease,
    format: JournalFormat,
    index_length: u64,
    _memory: SourceRamLease,
}

/// The scanner and its typed storage facts borrow the same actual native
/// owner for their entire lifetime. No serialized ticket or binding can create
/// a target-write capability through this read-only wrapper.
pub(crate) struct BoundJournalObservation<'a> {
    observation: JournalObservation<'a>,
    facts: BoundNativeJournalFacts<'a>,
}

/// The real closed index derived from one fully scanned PreparedClear native
/// journal. It retains its actual arena file and RAM owners, but is never by
/// itself source admission, activation, or replay authority.
pub(crate) struct PreparedJournalIndex {
    policy: n2r_win32::HeldPagedWritePolicy,
    lease: ArtifactLease,
    ticket_sha256: [u8; 32],
    format_version: u32,
    journal_owner: usize,
    _memory: SourceRamLease,
}

impl PreparedJournalIndex {
    /// The receipt is tied to the same live scanned journal object, whose
    /// ordinary write API now rejects body mutations. It does not exclude raw
    /// aliases; the native activation gate still hashes both boundaries.
    pub(crate) fn require_same_sealed_journal(
        &self,
        journal: &NativeSelectedJournal,
        ticket: &SelectedTicket,
    ) -> Result<()> {
        self.require_ticket(ticket)?;
        ensure!(
            std::ptr::from_ref(journal) as usize == self.journal_owner,
            "prepared index belongs to a different native journal owner"
        );
        journal.require_prepared_body_seal()
    }
    pub(crate) fn policy(&self) -> n2r_win32::HeldPagedWritePolicy {
        self.policy.clone()
    }

    pub(crate) fn artifact_lease(&self) -> &ArtifactLease {
        &self.lease
    }

    /// Recheck the same held index and the exact ticket representation. The
    /// caller separately retains and revalidates the real native journal.
    pub(crate) fn require_ticket(&self, ticket: &SelectedTicket) -> Result<()> {
        let encoded = serde_json::to_vec(ticket)?;
        ensure!(
            encoded.len() <= 4096
                && <[u8; 32]>::from(Sha256::digest(&encoded)) == self.ticket_sha256,
            "prepared index ticket differs"
        );
        self.lease.revalidate()?;
        self.policy.revalidate()?;
        let facts = self.policy.facts()?;
        ensure!(
            facts.image_length == ticket.image_length
                && facts.selected_bytes == ticket.selected_bytes
                && facts.range_count == ticket.range_count
                && facts.journal_length == ticket.journal_length
                && facts.journal_immutable_sha256 == ticket.immutable_sha256
                && facts.format_version == self.format_version,
            "prepared index does not bind the supplied actual ticket"
        );
        Ok(())
    }
}

impl<'a> BoundJournalObservation<'a> {
    pub(crate) fn open(
        owner: &'a mut BoundNativeRecoveryJournal,
        ticket: &'a SelectedTicket,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
        max_index_bytes: u64,
    ) -> Result<Self> {
        let (journal, facts) = owner.split_for_observation()?;
        ensure!(
            facts.journal_length == ticket.journal_length,
            "held native journal and diagnostic ticket lengths differ"
        );
        let observation =
            JournalObservation::open(journal, ticket, group, scratch, path, max_index_bytes)?;
        Ok(Self { observation, facts })
    }

    pub(crate) fn facts(&self) -> &BoundNativeJournalFacts<'a> {
        &self.facts
    }

    pub(super) fn diagnostic_ticket(&self) -> &SelectedTicket {
        self.observation.ticket
    }

    pub(crate) fn lifecycle(&mut self) -> Result<SelectedLifecycle> {
        self.observation.lifecycle()
    }

    pub(crate) fn retire(self) -> Result<()> {
        self.observation.retire()
    }
}

fn check_side(
    journal: &mut NativeSelectedJournal,
    length: u64,
    stored: bool,
    expected: &[u8; 32],
    range: &SelectedRange,
    mut aggregate: Option<&mut PinHash>,
    immutable: &mut PinHash,
    buffer: &mut [u8],
    descriptors_only: bool,
) -> Result<()> {
    if descriptors_only {
        if stored {
            let position = journal.stream_position()?;
            journal.seek(SeekFrom::Start(add(position, length)?))?;
        }
        return Ok(());
    }
    if let Some(aggregate) = aggregate.as_deref_mut() {
        frame(aggregate, range)?;
    }
    let mut hash = pin_hash(immutable.algorithm())?;
    let mut left = length;
    while left != 0 {
        let n = usize::try_from(left.min(buffer.len() as u64))?;
        if stored {
            journal.read_exact(&mut buffer[..n])?;
            immutable.update(&buffer[..n])?;
        } else {
            buffer[..n].fill(0);
        }
        hash.update(&buffer[..n])?;
        if let Some(aggregate) = aggregate.as_deref_mut() {
            aggregate.update(&buffer[..n])?;
        }
        left -= n as u64;
    }
    ensure!(
        finish(hash)? == *expected,
        "selected journal payload digest differs"
    );
    Ok(())
}

fn index_header(ticket: &SelectedTicket, format: JournalFormat) -> [u8; HEADER_BYTES as usize] {
    let mut out = [0u8; HEADER_BYTES as usize];
    out[..8].copy_from_slice(INDEX_MAGIC);
    out[8..12].copy_from_slice(&ticket.range_count.to_le_bytes());
    out[12..16].copy_from_slice(&format.version.to_le_bytes());
    out[16..24].copy_from_slice(&ticket.image_length.to_le_bytes());
    out[24..32].copy_from_slice(&ticket.journal_length.to_le_bytes());
    out[32..64].copy_from_slice(&ticket.immutable_sha256);
    out
}

impl<'a> JournalObservation<'a> {
    /// Finish the fully authenticated fresh-journal scan without retaining a
    /// borrow of the journal or ticket. Only actual PreparedClear state may be
    /// handed back to the live preparation owner; no write permission follows.
    pub(crate) fn into_prepared_index(mut self) -> Result<PreparedJournalIndex> {
        self.revalidate_index()?;
        ensure!(
            self.ticket.marker_profile.is_none()
                && sj::classify(self.journal, self.ticket)? == SelectedLifecycle::PreparedClear,
            "prepared paged index requires the actual clear markerless journal"
        );
        let encoded = serde_json::to_vec(self.ticket)?;
        ensure!(
            encoded.len() <= 4096,
            "prepared journal ticket exceeds bound"
        );
        let ticket_sha256 = Sha256::digest(&encoded).into();
        let journal_owner = std::ptr::from_ref(&*self.journal) as usize;
        self.journal.seal_prepared_body(self.ticket)?;
        let Self {
            index,
            index_lease,
            format,
            _memory,
            ..
        } = self;
        let result = PreparedJournalIndex {
            policy: index,
            lease: index_lease,
            ticket_sha256,
            format_version: format.version,
            journal_owner,
            _memory,
        };
        Ok(result)
    }

    /// Retains the same exclusive native journal owner for the whole scan.
    /// The ticket is treated as a hash/route input, never as authorization.
    pub(crate) fn open(
        journal: &'a mut NativeSelectedJournal,
        ticket: &'a SelectedTicket,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
        max_index_bytes: u64,
    ) -> Result<Self> {
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::JournalScan);
        ensure!(
            matches!(
                group.group(),
                ArtifactGroup::Capture | ArtifactGroup::RecoveryCopy
            ),
            "recovery index group differs"
        );
        let scratch_group = scratch
            .artifact_group()
            .context("recovery index scratch is not arena-owned")?;
        ensure!(
            scratch_group.group() == group.group()
                && scratch_group.arena().same_arena(group.arena()),
            "recovery scratch group differs"
        );
        ensure!(
            ticket.range_count > 0
                && ticket.image_length >= GRANULE
                && ticket.image_length.is_multiple_of(GRANULE)
                && ticket.selected_bytes <= ticket.image_length
                && !ticket.whole_image_verified
                && journal.byte_len()? == ticket.journal_length,
            "recovery ticket or journal geometry differs"
        );
        let bytes = HEADER_BYTES
            .checked_add(
                u64::from(ticket.range_count)
                    .checked_mul(ROW_BYTES)
                    .context("recovery index size overflow")?,
            )
            .and_then(|n| n.checked_add(FOOTER_BYTES))
            .context("recovery index total overflow")?;
        ensure!(
            bytes <= max_index_bytes,
            "recovery index exceeds its actual budget"
        );
        let memory = scratch.lease_ram(12 * BUFFER as u64)?;
        let mut header = [0u8; HEADER];
        let body = if ticket.marker_profile.is_some() {
            REDUNDANT_BODY
        } else {
            BODY
        };
        ensure!(
            ticket.journal_length >= add(add(body, HEADER as u64)?, FOOTER as u64)?,
            "recovery journal is shorter than its fixed framing"
        );
        // A body that was already read in full and matched its ticket in this
        // process does not change. Rebuilding the index then needs only the
        // record descriptors, not another pass over every payload byte.
        let algorithm = ticket.digest_algorithm();
        let descriptors_only = n2r_win32::bulk_digest::journal_body_already_verified(
            algorithm,
            &ticket.immutable_sha256,
            body,
            ticket.journal_length - body,
        );
        at(journal, body, &mut header)?;
        let fmt = JournalFormat::decode(&header, ticket)?;
        ensure!(
            fmt.body == body
                && get_u32(&header, 12) == ticket.range_count
                && get_u64(&header, 16) == ticket.image_length
                && get_u64(&header, 24) == ticket.selected_bytes
                && get_u64(&header, 32) == ticket.journal_length
                && if fmt.version >= 5 {
                    ticket
                        .old_restored_selected_sha256
                        .is_some_and(|h| header[40..72] == h)
                        && get_u64(&header, 72) > 0
                } else {
                    ticket.old_restored_selected_sha256.is_none()
                        && header[40..].iter().all(|&b| b == 0)
                },
            "recovery journal header differs from its ticket"
        );
        let permit = group.reserve_file(path, bytes)?;
        let mut builder = n2r_win32::PagedPolicyIndexBuilder::create_new(permit.path())?;
        let mut output = BufWriter::with_capacity(256 * 1024, &mut builder);
        let index_head = index_header(ticket, fmt);
        let mut index_hash = Sha256::new();
        output.write_all(&index_head)?;
        index_hash.update(index_head);
        let mut immutable = aggregate_pin_hash(algorithm)?;
        immutable.update(&header)?;
        let mut old = aggregate_pin_hash(algorithm)?;
        let mut new = Some(aggregate_pin_hash(algorithm)?);
        let mut buffer = vec![0u8; BUFFER];
        let mut selected = 0u64;
        let mut source_free = 0u64;
        let mut old_zero = 0u64;
        let mut copy_seen = false;
        let mut new_zero_seen = false;
        let mut previous_end = 0u64;
        let mut position = add(body, HEADER as u64)?;
        journal.seek(SeekFrom::Start(position))?;
        for _ in 0..ticket.range_count {
            let mut descriptor = [0u8; OLD_ZERO_RECORD];
            journal.read_exact(&mut descriptor[..fmt.record_size])?;
            immutable.update(&descriptor[..fmt.record_size])?;
            let row = Record::decode(&descriptor, position, fmt, ticket.image_length)?;
            ensure!(
                row.offset >= previous_end && row.next <= ticket.journal_length - FOOTER as u64,
                "recovery record overlaps or escapes journal"
            );
            selected = add(selected, row.length)?;
            previous_end = add(row.offset, row.length)?;
            let index_row = row.index_row();
            output.write_all(&index_row)?;
            index_hash.update(index_row);
            let range = row.range();
            if row.old_kind == 2 {
                source_free = add(source_free, row.length)?;
                check_side(
                    journal,
                    old_stored(CaptureIndexRange {
                        offset: row.offset,
                        length: row.length,
                        packed_offset: 0,
                        new_is_zero: false,
                        old_is_zero: false,
                        old_is_source_free: true,
                        copy_source_offset: None,
                    })?,
                    true,
                    &row.old_hash,
                    &range,
                    None,
                    &mut immutable,
                    &mut buffer,
                    descriptors_only,
                )?;
            } else {
                if row.old_kind == 1 {
                    old_zero = add(old_zero, row.length)?;
                }
                check_side(
                    journal,
                    row.length,
                    row.old_kind == 0,
                    &row.old_hash,
                    &range,
                    Some(&mut old),
                    &mut immutable,
                    &mut buffer,
                    descriptors_only,
                )?;
            }
            ensure!(
                journal.stream_position()? == row.new_payload,
                "recovery OLD payload position differs"
            );
            if row.new_kind == 2 {
                new = None;
                copy_seen = true;
            } else {
                new_zero_seen |= row.new_kind == 1;
                check_side(
                    journal,
                    row.length,
                    row.new_kind == 0,
                    &row.new_hash,
                    &range,
                    new.as_mut(),
                    &mut immutable,
                    &mut buffer,
                    descriptors_only,
                )?;
            }
            ensure!(
                journal.stream_position()? == row.next,
                "recovery NEW payload position differs"
            );
            position = row.next;
        }
        let mut footer = [0u8; FOOTER];
        journal.read_exact(&mut footer)?;
        immutable.update(&footer)?;
        let canonical = if ticket.marker_profile.is_some() {
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
        ensure!(
            fmt.version == canonical
                && (fmt.version != 6 || source_free != 0)
                && selected == ticket.selected_bytes
                && (fmt.version < 5 || source_free == get_u64(&header, 72))
                && &footer[..8] == fmt.footer
                && footer[8..40] == ticket.old_selected_sha256
                && footer[40..72] == ticket.new_selected_sha256
                && get_u64(&footer, 72) == ticket.journal_length
                && journal.stream_position()? == ticket.journal_length
                && (descriptors_only
                    || finish(old)?
                        == ticket
                            .old_restored_selected_sha256
                            .unwrap_or(ticket.old_selected_sha256))
                && (descriptors_only || finish(immutable)? == ticket.immutable_sha256),
            "recovery immutable body, footer or OLD aggregate differs"
        );
        if let Some(new) = new {
            ensure!(
                descriptors_only || finish(new)? == ticket.new_selected_sha256,
                "recovery NEW aggregate differs"
            );
        }
        if !descriptors_only {
            n2r_win32::bulk_digest::note_journal_body_verified(
                algorithm,
                &ticket.immutable_sha256,
                body,
                ticket.journal_length - body,
            );
        }
        let mut index_footer = [0u8; FOOTER_BYTES as usize];
        index_footer[..8].copy_from_slice(INDEX_END);
        index_footer[8..16].copy_from_slice(&u64::from(ticket.range_count).to_le_bytes());
        index_footer[16..24].copy_from_slice(&position.to_le_bytes());
        index_footer[24..56].copy_from_slice(&index_hash.clone().finalize());
        output.write_all(&index_footer)?;
        index_hash.update(index_footer);
        output.flush()?;
        drop(output);
        let index_sha: [u8; 32] = index_hash.finalize().into();
        let index = builder.finish(n2r_win32::PagedPolicyIndexFacts {
            image_length: ticket.image_length,
            selected_bytes: ticket.selected_bytes,
            old_zero_bytes: old_zero,
            source_free_bytes: source_free,
            journal_length: ticket.journal_length,
            range_count: ticket.range_count,
            format_version: fmt.version,
            journal_immutable_sha256: ticket.immutable_sha256,
            index_sha256: index_sha,
            max_index_bytes,
        })?;
        let readonly = index.take_lease_handle()?;
        let index_lease = permit.verify_closed_handle(&readonly, &hex::encode(index_sha))?;
        drop(readonly);
        let mut result = Self {
            journal,
            ticket,
            index,
            index_lease,
            format: fmt,
            index_length: bytes,
            _memory: memory,
        };
        result.revalidate_index()?;
        if copy_seen && !descriptors_only {
            result.validate_resolved_new()?;
        }
        // Enforce all ordinary lifecycle and torn-marker refusals, but do not
        // expose replay authority or mutate any marker.
        let _ = sj::classify(result.journal, result.ticket)?;
        Ok(result)
    }

    fn index_entry(&self, ordinal: u64) -> Result<(u64, u64, u64, u64)> {
        ensure!(
            ordinal < u64::from(self.ticket.range_count),
            "recovery index ordinal exceeds domain"
        );
        let row = self.index.row(ordinal)?;
        Ok((row.offset, row.length, row.descriptor_offset, row.flags))
    }

    fn record(&mut self, ordinal: u64) -> Result<Record> {
        let (offset, length, descriptor_at, flags) = self.index_entry(ordinal)?;
        let mut descriptor = [0u8; OLD_ZERO_RECORD];
        at(
            self.journal,
            descriptor_at,
            &mut descriptor[..self.format.record_size],
        )?;
        let row = Record::decode(
            &descriptor,
            descriptor_at,
            self.format,
            self.ticket.image_length,
        )?;
        ensure!(
            row.offset == offset
                && row.length == length
                && (row.old_kind | (row.new_kind << 2)) == flags,
            "recovery index row differs from held journal descriptor"
        );
        Ok(row)
    }

    fn revalidate_index(&mut self) -> Result<()> {
        self.index_lease.revalidate()?;
        ensure!(
            self.index_lease.wire_bytes() == self.index_length,
            "recovery index owner length changed"
        );
        self.index.revalidate()?;
        let facts = self.index.facts()?;
        ensure!(
            facts.image_length == self.ticket.image_length
                && facts.journal_length == self.ticket.journal_length
                && facts.range_count == self.ticket.range_count
                && facts.selected_bytes == self.ticket.selected_bytes
                && facts.format_version == self.format.version
                && facts.journal_immutable_sha256 == self.ticket.immutable_sha256,
            "recovery index journal binding differs"
        );
        let mut previous_end = 0u64;
        let mut expected_descriptor = add(self.format.body, HEADER as u64)?;
        for ordinal in 0..self.ticket.range_count {
            let item = self.index.row(u64::from(ordinal))?;
            let (offset, length, descriptor, flags) =
                (item.offset, item.length, item.descriptor_offset, item.flags);
            let mut record = [0u8; OLD_ZERO_RECORD];
            at(
                self.journal,
                descriptor,
                &mut record[..self.format.record_size],
            )?;
            let row = Record::decode(&record, descriptor, self.format, self.ticket.image_length)?;
            ensure!(
                descriptor == expected_descriptor
                    && offset == row.offset
                    && length == row.length
                    && flags == (row.old_kind | (row.new_kind << 2))
                    && offset >= previous_end,
                "recovery index ordering or descriptor differs"
            );
            previous_end = add(offset, length)?;
            expected_descriptor = row.next;
        }
        ensure!(
            add(expected_descriptor, FOOTER as u64)? == self.ticket.journal_length,
            "recovery index does not reach the journal footer"
        );
        Ok(())
    }

    /// Resolve only prior complete OLD records. Source-free digest tables are
    /// never accepted as byte sources, even if the ticket claims a COPY.
    fn read_prior_old(
        &mut self,
        mut source: u64,
        before_ordinal: u64,
        out: &mut [u8],
    ) -> Result<()> {
        let (mut low, mut high) = (0u64, before_ordinal);
        while low < high {
            let middle = low + (high - low) / 2;
            let (offset, length, _, _) = self.index_entry(middle)?;
            if add(offset, length)? <= source {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut filled = 0usize;
        while filled < out.len() {
            ensure!(
                low < before_ordinal,
                "recovery COPY source leaves prior rows"
            );
            let row = self.record(low)?;
            let end = add(row.offset, row.length)?;
            ensure!(
                row.offset <= source && source < end && row.old_kind != 2,
                "recovery COPY source crosses a gap or digest-only row"
            );
            let count = usize::try_from((end - source).min((out.len() - filled) as u64))?;
            if row.old_kind == 1 {
                out[filled..filled + count].fill(0);
            } else {
                at(
                    self.journal,
                    add(row.old_payload, source - row.offset)?,
                    &mut out[filled..filled + count],
                )?;
            }
            source = add(source, count as u64)?;
            filled += count;
            low += 1;
        }
        Ok(())
    }

    fn validate_resolved_new(&mut self) -> Result<()> {
        let algorithm = self.ticket.digest_algorithm();
        let mut selected = aggregate_pin_hash(algorithm)?;
        let mut buffer = vec![0u8; BUFFER];
        for ordinal in 0..u64::from(self.ticket.range_count) {
            let row = self.record(ordinal)?;
            frame(&mut selected, &row.range())?;
            let mut hash = pin_hash(algorithm)?;
            let mut done = 0u64;
            while done < row.length {
                let count = usize::try_from((row.length - done).min(BUFFER as u64))?;
                match row.new_kind {
                    0 => at(
                        self.journal,
                        add(row.new_payload, done)?,
                        &mut buffer[..count],
                    )?,
                    1 => buffer[..count].fill(0),
                    2 => self.read_prior_old(
                        add(row.copy_source, done)?,
                        ordinal,
                        &mut buffer[..count],
                    )?,
                    _ => unreachable!(),
                }
                hash.update(&buffer[..count])?;
                selected.update(&buffer[..count])?;
                done = add(done, count as u64)?;
            }
            ensure!(
                finish(hash)? == row.new_hash,
                "recovery resolved NEW row digest differs"
            );
        }
        ensure!(
            finish(selected)? == self.ticket.new_selected_sha256,
            "recovery resolved NEW aggregate differs"
        );
        Ok(())
    }

    /// Read marker state through the same held native owner. This is an
    /// observation only; it never repairs markers or authorizes replay.
    pub(crate) fn lifecycle(&mut self) -> Result<SelectedLifecycle> {
        self.revalidate_index()?;
        sj::classify(self.journal, self.ticket)
    }

    pub(crate) fn retire(self) -> Result<()> {
        let Self {
            index, index_lease, ..
        } = self;
        drop(index);
        index_lease.retire()
    }
}

impl<'a> BoundJournalObservation<'a> {
    /// Borrow a genuinely scanned/sealed creation J and its SAME actual index.
    /// Cloned policy/artifact references retain authority provenance; no saved
    /// ticket/path can construct the private PreparedJournalIndex owner.
    pub(crate) fn from_prepared_creation(
        journal: &'a mut NativeSelectedJournal,
        facts: &crate::general_reconstruct::selected_native_journal::BoundNativeCreationFacts<'a>,
        ticket: &'a SelectedTicket,
        index: &PreparedJournalIndex,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        index.require_same_sealed_journal(journal, ticket)?;
        journal.revalidate_resource_preparation(facts, ticket)?;
        ensure!(
            ticket.marker_profile.is_none(),
            "partition publication requires actual markerless creation journal"
        );
        let memory = scratch.lease_ram(12 * BUFFER as u64)?;
        let mut header = [0u8; HEADER];
        at(journal, BODY, &mut header)?;
        let format = JournalFormat::decode(&header, ticket)?;
        let index_length = index.lease.wire_bytes();
        let mut observation = JournalObservation {
            journal,
            ticket,
            index: index.policy.clone(),
            index_lease: index.lease.clone(),
            format,
            index_length,
            _memory: memory,
        };
        observation.revalidate_index()?;
        ensure!(
            observation.lifecycle()? == SelectedLifecycle::PreparedClear,
            "creation J is not original clear state"
        );
        Ok(Self {
            observation,
            facts: BoundNativeJournalFacts {
                path: facts.path,
                binding: facts.binding,
                identity: facts.identity,
                profile: facts.profile,
                journal_length: ticket.journal_length,
                marker_use: facts.marker_use,
                marker_native_qualified: None,
            },
        })
    }
}
