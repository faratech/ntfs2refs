//! One-shot fresh apply over the original live source admission and the same
//! prepared native journal. No saved publication can construct this owner.
use super::*;
use crate::{
    general_source_admission::resource::PreparedResourceSourceAdmission,
    selected_journal::{self as sj, JournalRecord, MarkerKind, NewBytes, OldBytes, SelectedResult},
};
use std::io::{Read, Seek, SeekFrom, Write};

pub(crate) struct ResourceFreshApply<'journal, 'domain, 'capture, 'proof, 'scope, 'expected> {
    prepared: ResourcePreparedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>,
    admission: PreparedResourceSourceAdmission,
}

/// HND closes raw replay; it does not mount or certify the converted native
/// tree. Keep all preparation owners alive until the separate native finish.
pub(crate) struct ResourceAppliedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>
{
    owner: ResourceFreshApply<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>,
    applied: SelectedResult,
    handoff: SelectedResult,
    native_bytes_written: u64,
}

pub(super) struct Buffers {
    pub(super) current: Vec<u8>,
    pub(super) old: Vec<u8>,
    pub(super) new: Vec<u8>,
}
impl Buffers {
    pub(super) fn new() -> Self {
        Self {
            current: vec![0; BUFFER],
            old: vec![0; BUFFER],
            new: vec![0; BUFFER],
        }
    }
}

pub(super) fn record<J: Read+Seek>(
    row: JournalLayoutRow,
    domain: &ResourceJournalDomain<'_>,
    journal: &mut J,
) -> Result<JournalRecord> {
    let f = domain.facts();
    let mut descriptor = [0; OLD_ZERO_RECORD];
    at(
        journal,
        row.descriptor_offset,
        &mut descriptor[..f.record_size],
    )?;
    let hashes = kind(f).3;
    let old = descriptor[hashes..hashes + 32].try_into()?;
    let new = descriptor[hashes + 32..hashes + 64].try_into()?;
    ensure!(
        descriptor == encode_record(row, f, old, new),
        "fresh apply descriptor differs from the held capture domain"
    );
    Ok(JournalRecord {
        range: SelectedRange {
            offset: row.capture.offset,
            length: row.capture.length,
        },
        before: if row.capture.old_is_source_free {
            OldBytes::SourceFree(row.old_storage_offset)
        } else if row.capture.old_is_zero {
            OldBytes::Zero
        } else {
            OldBytes::Payload(row.old_storage_offset)
        },
        after: if row.capture.new_is_zero {
            NewBytes::Zero
        } else if let Some(source) = row.capture.copy_source_offset {
            NewBytes::OldReference(source)
        } else {
            NewBytes::Payload(row.new_storage_offset)
        },
        new_sha256: new,
    })
}

pub(super) fn read_new<J:Read+Seek>(
    domain: &ResourceJournalDomain<'_>,
    journal: &mut J,
    row: JournalLayoutRow,
    ordinal: u64,
    within: u64,
    output: &mut [u8],
) -> Result<()> {
    ensure!(
        within
            .checked_add(output.len() as u64)
            .is_some_and(|end| end <= row.capture.length),
        "fresh apply NEW read escapes its actual descriptor"
    );
    if row.capture.new_is_zero {
        output.fill(0);
    } else if let Some(source) = row.capture.copy_source_offset {
        read_prior_old(domain, journal, add(source, within)?, ordinal, output)?;
    } else {
        at(journal, add(row.new_storage_offset, within)?, output)?;
    }
    Ok(())
}

pub(super) fn check_selected<T: Read + Seek>(
    target: &mut T,
    domain: &ResourceJournalDomain<'_>,
    buffer: &mut [u8],
    expected: [u8; 32],
) -> Result<[u8; 32]> {
    let mut aggregate = aggregate_pin_hash()?;
    for ordinal in 0..u64::from(domain.facts.range_count) {
        let row = domain.row(ordinal)?;
        frame(
            &mut aggregate,
            &SelectedRange {
                offset: row.capture.offset,
                length: row.capture.length,
            },
        )?;
        let mut done = 0;
        while done < row.capture.length {
            let count = usize::try_from((row.capture.length - done).min(buffer.len() as u64))?;
            at(target, add(row.capture.offset, done)?, &mut buffer[..count])?;
            aggregate.update(&buffer[..count])?;
            done = add(done, count as u64)?;
        }
    }
    let digest = finish(aggregate)?;
    ensure!(
        digest == expected,
        "fresh apply actual selected target digest differs"
    );
    Ok(digest)
}

#[derive(serde::Serialize)]
pub(crate) struct FirstFlushedWrite {
    pub offset: u64,
    pub bytes: u64,
    pub native_bytes_before: u64,
    pub native_bytes_after: u64,
    pub readback_sha256: String,
    pub remaining_different_offset: u64,
    pub remaining_different_bytes: u64,
}

/// Diagnostic-only proof that at least one other selected granule is still
/// different from NEW. This observation never grants replay authority.
fn find_remaining_difference(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    journal: &mut NativeSelectedJournal,
    domain: &ResourceJournalDomain<'_>,
    written_offset: u64,
    written_length: u64,
    buffers: &mut Buffers,
) -> Result<Option<(u64, u64)>> {
    let written_end = add(written_offset, written_length)?;
    for ordinal in 0..u64::from(domain.facts.range_count) {
        let row = domain.row(ordinal)?;
        let mut within = 0;
        while within < row.capture.length {
            let offset = add(row.capture.offset, within)?;
            let length = GRANULE.min(row.capture.length - within);
            let end = add(offset, length)?;
            if offset >= written_end || end <= written_offset {
                let n = usize::try_from(length)?;
                at(target, offset, &mut buffers.current[..n])?;
                read_new(domain, journal, row, ordinal, within, &mut buffers.new[..n])?;
                if buffers.current[..n] != buffers.new[..n] {
                    return Ok(Some((offset, length)));
                }
            }
            within = add(within, length)?;
        }
    }
    Ok(None)
}

fn write_span(
    target: &mut n2r_win32::BorrowedPagedWriter<'_>,
    journal: &mut NativeSelectedJournal,
    domain: &ResourceJournalDomain<'_>,
    ordinal: u64,
    row: JournalLayoutRow,
    start: u64,
    length: u64,
    buffers: &mut Buffers,
    first_write_fault: &mut Option<&mut dyn FnMut(&FirstFlushedWrite) -> Result<()>>,
    target_before: &n2r_win32::GeneralDiskState,
    ticket: &SelectedTicket,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    ensure!(
        start
            .checked_add(length)
            .is_some_and(|end| end <= row.capture.length),
        "fresh apply span escapes its actual descriptor"
    );
    let original = record(row, domain, journal)?;
    let mut done = 0;
    while done < length {
        let count = usize::try_from((length - done).min(BUFFER as u64))?;
        let within = add(start, done)?;
        let offset = add(row.capture.offset, within)?;
        at(target, offset, &mut buffers.current[..count])?;
        read_new(
            domain,
            journal,
            row,
            ordinal,
            within,
            &mut buffers.new[..count],
        )?;
        if row.capture.old_is_source_free {
            sj::check_free_granules(
                journal,
                &original,
                within,
                &buffers.current[..count],
                Some(&buffers.new[..count]),
            )?;
        } else {
            sj::read_before(journal, &original, within, &mut buffers.old[..count])?;
            ensure!(
                sj::bytes_are_old_or_new(
                    &buffers.current[..count],
                    &buffers.old[..count],
                    &buffers.new[..count]
                ),
                "fresh source selected bytes changed immediately before write"
            );
        }
        if buffers.current[..count] != buffers.new[..count] {
            let before = target.native_bytes_written();
            target.seek(SeekFrom::Start(offset))?;
            ensure!(
                target.write(&buffers.new[..count])? == count,
                "short fresh selected target write"
            );
            if first_write_fault.is_some() {
                let after = target.native_bytes_written();
                ensure!(before == 0 && after.checked_sub(before) == Some(count as u64),
                    "diagnostic interruption requires the first actual native write");
                target.sync_all()?;
                at(target, offset, &mut buffers.current[..count])?;
                ensure!(buffers.current[..count] == buffers.new[..count],
                    "first flushed native write readback differs");
                let hash = hex::encode(Sha256::digest(&buffers.current[..count]));
                ensure!(target.state(events)? == *target_before && target_before.disk_attributes == 1,
                    "source exclusion changed after first flushed write");
                ensure!(sj::classify(journal, ticket)? == sj::SelectedLifecycle::ApplyIntent,
                    "actual AP lifecycle absent after first flushed write");
                let (remaining_offset, remaining_bytes) = find_remaining_difference(
                    target, journal, domain, offset, count as u64, buffers,
                )?.context("no independently observed remaining changed selected granule")?;
                ensure!(target.state(events)? == *target_before
                    && sj::classify(journal, ticket)? == sj::SelectedLifecycle::ApplyIntent,
                    "source or AP changed during partial-progress observation");
                let observation = FirstFlushedWrite {
                    offset, bytes: count as u64, native_bytes_before: before,
                    native_bytes_after: after, readback_sha256: hash,
                    remaining_different_offset: remaining_offset,
                    remaining_different_bytes: remaining_bytes,
                };
                first_write_fault.take().expect("fault callback present")(&observation)?;
                anyhow::bail!("intentional diagnostic interruption after the first flushed and read-back native write");
            }
        }
        done = add(done, count as u64)?;
    }
    Ok(())
}

impl<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>
    ResourceFreshApply<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>
{
    pub(super) fn new(
        prepared: ResourcePreparedConversion<
            'journal,
            'domain,
            'capture,
            'proof,
            'scope,
            'expected,
        >,
        admission: PreparedResourceSourceAdmission,
    ) -> Self {
        Self {
            prepared,
            admission,
        }
    }

    /// Consume the original prepared conversion once. The SDK fresh gate must
    /// independently authenticate actual OLD bytes and durable AP before any
    /// policy-bound target write is possible. Errors leave the source excluded
    /// for recovery from the already durable publication; no automatic retry.
    pub(crate) fn apply_and_handoff(
        self,
        events: &mut Vec<n2r_win32::NativeEvent>,
        checkpoint_events: impl FnMut(&mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
        after_apply: impl FnOnce(&SelectedResult) -> Result<()>,
    ) -> Result<ResourceAppliedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>>
    {
        self.apply_and_handoff_with_first_write_fault(events, checkpoint_events, after_apply, None)
    }

    /// The callback can only observe a real flushed first write and request an
    /// error. It never supplies a journal marker or native write authority.
    pub(crate) fn apply_and_handoff_with_first_write_fault(
        mut self,
        events: &mut Vec<n2r_win32::NativeEvent>,
        mut checkpoint_events: impl FnMut(&mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
        after_apply: impl FnOnce(&SelectedResult) -> Result<()>,
        mut first_write_fault: Option<&mut dyn FnMut(&FirstFlushedWrite) -> Result<()>>,
    ) -> Result<ResourceAppliedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>>
    {
        checkpoint_native_events(events, &mut checkpoint_events)?;
        self.prepared.revalidate(events)?;
        checkpoint_native_events(events, &mut checkpoint_events)?;
        self.admission.require_binding(
            self.prepared.prepared.context,
            self.prepared.prepared.candidate.protected_proof(),
            self.prepared.expected,
            &self.prepared.closure,
        )?;
        // Reserve the complete fixed IO workspace before the native transition.
        // It remains live until after all raw target buffers and the writer.
        let _memory = self
            .prepared
            .closure
            .arena()
            .reserve_ram(12 * BUFFER as u64)?;
        let mut buffers = Buffers::new();
        let prepared = &mut self.prepared.prepared;
        let ticket = &prepared.inner.ticket;
        ensure!(
            sj::classify(prepared.inner._journal, ticket)? == sj::SelectedLifecycle::PreparedClear,
            "fresh resource apply requires actual PreparedClear journal"
        );
        let index = self
            .prepared
            .write_index
            .as_ref()
            .context("prepared native write index absent")?;
        index.require_ticket(ticket)?;
        let facts = &prepared.inner._facts;
        let pins = n2r_win32::PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        let (source, _) = prepared.context.source_and_inspection()?;
        let mut target = prepared.inner._journal.begin_sealed_fresh_apply(
            source, index.policy(), &pins, events,
        )?;
        ensure!(
            target.byte_len() == ticket.image_length,
            "fresh source transition changed partition geometry"
        );
        let target_before = target.state(events)?;
        ensure!(
            target_before.disk_attributes == 1
                && prepared.shadow.state(events)?
                    == *prepared.candidate.protected_proof().native().after(),
            "fresh activation changed source exclusion or the protected shadow"
        );
        checkpoint_native_events(events, &mut checkpoint_events)?;
        let domain = prepared.inner._domain;
        for ordinal in 0..u64::from(ticket.range_count) {
            let row = domain.row(ordinal)?;
            let skip = if row.capture.offset == 0 { GRANULE } else { 0 };
            write_span(
                &mut target,
                prepared.inner._journal,
                domain,
                ordinal,
                row,
                skip,
                row.capture.length - skip,
                &mut buffers,
                &mut first_write_fault,
                &target_before,
                ticket,
                events,
            )?;
        }
        target.sync_all()?;
        // Preserve the existing selected-journal protocol: boot granule last,
        // after every other target range has crossed its durability barrier.
        let first = domain.row(0)?;
        if first.capture.offset == 0 {
            write_span(
                &mut target,
                prepared.inner._journal,
                domain,
                0,
                first,
                0,
                GRANULE,
                &mut buffers,
                &mut first_write_fault,
                &target_before,
                ticket,
                events,
            )?;
        }
        ensure!(first_write_fault.is_none(), "diagnostic interruption requested but no actual changed write occurred");
        target.sync_all()?;
        let digest = check_selected(
            &mut target,
            domain,
            &mut buffers.current,
            ticket.new_selected_sha256,
        )?;
        let applied = SelectedResult {
            selected_sha256: digest,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: false,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: None,
        };
        after_apply(&applied)?;
        ensure!(
            sj::classify(prepared.inner._journal, ticket)? == sj::SelectedLifecycle::ApplyIntent,
            "fresh apply lifecycle changed before HND"
        );
        target.sync_all()?;
        // Recheck actual bytes after the callback, not just before it.
        self.prepared.closure.revalidate()?;
        index.require_ticket(ticket)?;
        let digest = check_selected(
            &mut target,
            domain,
            &mut buffers.current,
            ticket.new_selected_sha256,
        )?;
        ensure!(
            target.state(events)? == target_before,
            "fresh source identity or offline exclusion changed before HND"
        );
        ensure!(
            sj::classify(prepared.inner._journal, ticket)? == sj::SelectedLifecycle::ApplyIntent,
            "fresh journal intent changed before HND"
        );
        sj::write_lifecycle_marker(prepared.inner._journal, ticket, MarkerKind::Handoff)?;
        prepared
            .inner
            ._journal
            .require_native_mount_barriers(ticket)?;
        ensure!(
            sj::classify(prepared.inner._journal, ticket)? == sj::SelectedLifecycle::Handoff,
            "fresh journal HND did not close the original apply intent"
        );
        ensure!(
            target.state(events)? == target_before,
            "fresh source identity or offline exclusion changed across HND"
        );
        checkpoint_native_events(events, &mut checkpoint_events)?;
        let handoff = SelectedResult {
            selected_sha256: digest,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: None,
        };
        // Borrowed writer drop removes its write capability, without mounting
        // or replacing the original source owner retained by the Context.
        let native_bytes_written = target.native_bytes_written();
        drop(target);
        drop(buffers);
        Ok(ResourceAppliedConversion {
            owner: self,
            applied,
            handoff,
            native_bytes_written,
        })
    }
}

impl ResourceAppliedConversion<'_, '_, '_, '_, '_, '_> {
    /// Re-authenticate the actual terminal journal and selected postimage,
    /// then reseal the same physical owner for native readonly observation.
    /// This neither mounts the volume nor revives its old NTFS admission.
    pub(crate) fn seal_handoff_readonly(
        &mut self,
        events: &mut Vec<n2r_win32::NativeEvent>,
        mut checkpoint_events: impl FnMut(&mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
    ) -> Result<()> {
        checkpoint_native_events(events, &mut checkpoint_events)?;
        self.owner.prepared.closure.revalidate()?;
        self.owner.prepared.publication.revalidate()?;
        self.owner.prepared.checksum.revalidate()?;
        // Native immutable-J and selected-source hashes each use at most
        // 4 MiB sequentially. Pay the buffer plus bounded control events.
        let _memory = self
            .owner
            .prepared
            .closure
            .arena()
            .reserve_ram(16 * 1024 * 1024)?;
        let prepared = &mut self.owner.prepared.prepared;
        let ticket = &prepared.inner.ticket;
        let index = self
            .owner
            .prepared
            .write_index
            .as_ref()
            .context("prepared native write index absent")?;
        index.require_ticket(ticket)?;
        let facts = &prepared.inner._facts;
        let pins = n2r_win32::PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        let (source, _) = prepared.context.source_and_inspection()?;
        prepared.inner._journal.seal_sealed_handoff_for_observation(
            source, &index.policy(), &pins, events,
        )?;
        ensure!(
            source.binding() == facts.source && source.state(events)?.disk_attributes == 3,
            "terminal source did not retain its exact readonly exclusion"
        );
        checkpoint_native_events(events, &mut checkpoint_events)
    }

    pub(crate) fn applied(&self) -> &SelectedResult {
        &self.applied
    }
    pub(crate) fn handoff(&self) -> &SelectedResult {
        &self.handoff
    }
    pub(crate) fn native_bytes_written(&self) -> u64 {
        self.native_bytes_written
    }
    pub(crate) fn source(&self) -> &n2r_win32::general_layout::GeneralDiskBinding {
        self.owner.prepared.prepared.inner._facts.source
    }
    pub(crate) fn windows_aliases(&self) -> Option<&std::sync::Arc<n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>> {
        self.owner.prepared.windows_aliases.as_ref()
    }
    pub(crate) fn publication_path(&self) -> &Path {
        self.owner.prepared.publication_path()
    }
    pub(crate) fn publication_sha256(&self) -> &str {
        self.owner.prepared.publication_sha256()
    }
}
