//! Explicit partition scope. Legacy dedicated and foundation disk inequalities
//! stay in their original functions. Saved pins alone never issue a writer.
use super::*;
use crate::native::partition_isolation::PartitionSourceBinding;
use crate::native::partition_owner::{PartitionOwnerToken, PartitionScopedOwner};
use std::path::PathBuf;

pub(crate) struct OwnedPartitionJournalPins {
    binding: GeneralJournalStorageBinding,
    identity: JournalFileIdentity,
    path: PathBuf,
    profile: JournalProfile,
    immutable: [u8; 32],
    old: [u8; 32],
    restored: Option<[u8; 32]>,
    new: [u8; 32],
}
impl OwnedPartitionJournalPins {
    pub(crate) fn capture(p: &PagedRecoveryPins<'_>) -> Self {
        Self {
            binding: p.journal_binding.clone(),
            identity: p.journal_identity.clone(),
            path: p.journal_path.to_owned(),
            profile: p.journal_profile,
            immutable: p.immutable_sha256,
            old: p.old_selected_sha256,
            restored: p.old_restored_selected_sha256,
            new: p.new_selected_sha256,
        }
    }
    pub(crate) fn pins(&self) -> PagedRecoveryPins<'_> {
        PagedRecoveryPins {
            journal_binding: &self.binding,
            journal_identity: &self.identity,
            journal_path: &self.path,
            journal_profile: self.profile,
            immutable_sha256: self.immutable,
            old_selected_sha256: self.old,
            old_restored_selected_sha256: self.restored,
            new_selected_sha256: self.new,
        }
    }
    pub(crate) fn require(&self, p: &PagedRecoveryPins<'_>) -> io::Result<()> {
        if self.binding != *p.journal_binding
            || self.identity != *p.journal_identity
            || self.path != p.journal_path
            || self.profile != p.journal_profile
            || self.immutable != p.immutable_sha256
            || self.old != p.old_selected_sha256
            || self.restored != p.old_restored_selected_sha256
            || self.new != p.new_selected_sha256
        {
            return Err(invalid(
                "partition admission journal/ticket binding changed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PartitionJournalPhase {
    FreshOld,
    Applying,
    New,
    Handoff,
    Aborted,
    Mixed(PagedRecoveryDirection),
    Replaying(PagedRecoveryDirection),
    Restored,
}

fn rollback_active(j: &mut File, p: &PagedRecoveryPins<'_>) -> io::Result<()> {
    check_lifecycle(j, p, PagedRecoveryDirection::Rollback)?;
    let mut intent = [0; GRANULE as usize];
    read_at(j, GRANULE, &mut intent)?;
    if intent != marker(b"N2RSRB01", &p.immutable_sha256, &p.old_selected_sha256) {
        return Err(invalid(
            "partition rollback writer requires exact RB intent",
        ));
    }
    Ok(())
}

fn lifecycle(
    j: &mut File,
    p: &PagedRecoveryPins<'_>,
    phase: PartitionJournalPhase,
) -> io::Result<()> {
    match phase {
        PartitionJournalPhase::FreshOld => check_clear_lifecycle(j),
        PartitionJournalPhase::Applying | PartitionJournalPhase::New => {
            check_lifecycle(j, p, PagedRecoveryDirection::Resume)
        }
        PartitionJournalPhase::Handoff => check_handoff_lifecycle(j, p),
        PartitionJournalPhase::Aborted => check_aborted_lifecycle(j, p).map(|_| ()),
        PartitionJournalPhase::Mixed(direction) => check_lifecycle(j, p, direction),
        PartitionJournalPhase::Replaying(PagedRecoveryDirection::Resume) => {
            check_lifecycle(j, p, PagedRecoveryDirection::Resume)
        }
        PartitionJournalPhase::Replaying(PagedRecoveryDirection::Rollback)
        | PartitionJournalPhase::Restored => rollback_active(j, p),
    }
}

/// Observe the actual held file's native volume/disk/layout/extent data. Only
/// this explicit scope admits a sibling volume, and then only disjoint extents
/// with consistent disk-number/GPT identity. No legacy inequality is relaxed.
fn scoped_journal(
    source: &PartitionSourceBinding,
    j: &File,
    p: &PagedRecoveryPins<'_>,
    length: u64,
) -> io::Result<crate::journal_file::JournalFileSnapshot> {
    p.journal_binding.validate()?;
    let observed = verify_journal_owner(j, p, length)?;
    let s = &source.storage;
    let d = &p.journal_binding.disk;
    let same_number = s.disk_number == d.disk_number;
    let same_guid = crate::layout::guid_bytes(&s.identity.disk_guid)?
        == crate::layout::guid_bytes(&d.identity.disk_guid)?;
    if same_number != same_guid {
        return Err(invalid(
            "partition journal disk number/GPT identity disagree",
        ));
    }
    if same_number {
        let se = s
            .identity
            .partition_offset
            .checked_add(s.identity.partition_bytes)
            .ok_or_else(|| invalid("partition source extent overflow"))?;
        let je = d
            .identity
            .partition_offset
            .checked_add(d.identity.partition_bytes)
            .ok_or_else(|| invalid("partition journal extent overflow"))?;
        if crate::layout::guid_bytes(&s.identity.partition_guid)?
            == crate::layout::guid_bytes(&d.identity.partition_guid)?
            || !(se <= d.identity.partition_offset || je <= s.identity.partition_offset)
        {
            return Err(invalid("actual journal volume overlaps selected partition"));
        }
    }
    // observe_general_journal_file_with_profile above checks the actual single
    // volume extent, native disk/layout, final volume route, file ID and links.
    Ok(observed)
}

fn record_bytes(version: u32) -> io::Result<u64> {
    match version {
        1 => Ok(80),
        2 => Ok(88),
        3 => Ok(96),
        4 | 5 => Ok(104),
        _ => Err(invalid("partition selected format unsupported")),
    }
}
fn sum(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("partition journal offset overflow"))
}
fn old_payload(row: &super::super::PagedPolicyIndexRow, version: u32) -> io::Result<u64> {
    sum(row.descriptor_offset, record_bytes(version)?)
}
fn new_payload(row: &super::super::PagedPolicyIndexRow, version: u32) -> io::Result<u64> {
    let old_bytes = match row.flags & 3 {
        0 => row.length,
        1 => 0,
        2 => row.length / GRANULE * 16,
        _ => return Err(invalid("partition OLD kind differs")),
    };
    sum(old_payload(row, version)?, old_bytes)
}

/// COPY resolves only complete prior OLD literal/zero rows in the held index;
/// a digest-only source-free row is never a byte source. No target reread is
/// used to manufacture COPY bytes after a rollback has changed that source.
fn read_new(
    j: &mut File,
    policy: &HeldPagedWritePolicy,
    row: &super::super::PagedPolicyIndexRow,
    ordinal: u64,
    within: u64,
    out: &mut [u8],
    version: u32,
) -> io::Result<()> {
    match (row.flags >> 2) & 3 {
        0 => read_at(j, sum(new_payload(row, version)?, within)?, out),
        1 => {
            out.fill(0);
            Ok(())
        }
        2 => {
            let mut descriptor = [0; 32];
            read_at(j, row.descriptor_offset, &mut descriptor)?;
            let mut at = sum(u64_at(&descriptor, 24), within)?;
            let (mut low, mut high) = (0, ordinal);
            while low < high {
                let mid = low + (high - low) / 2;
                let prior = policy.row(mid)?;
                if sum(prior.offset, prior.length)? <= at {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }
            let mut done = 0;
            while done < out.len() {
                if low >= ordinal {
                    return Err(invalid("partition COPY leaves prior OLD rows"));
                }
                let prior = policy.row(low)?;
                let end = sum(prior.offset, prior.length)?;
                if at < prior.offset || at >= end || prior.flags & 3 == 2 {
                    return Err(invalid("partition COPY crosses gap/digest-only OLD"));
                }
                let n = (end - at).min((out.len() - done) as u64) as usize;
                if prior.flags & 3 == 1 {
                    out[done..done + n].fill(0);
                } else {
                    read_at(
                        j,
                        sum(old_payload(&prior, version)?, at - prior.offset)?,
                        &mut out[done..done + n],
                    )?;
                }
                at = sum(at, n as u64)?;
                done += n;
                low += 1;
            }
            Ok(())
        }
        _ => Err(invalid("partition NEW kind differs")),
    }
}

/// SAME per-byte OLD-or-NEW rule as the selected replay engine for allocated
/// rows; source-free rows use complete 4 KiB OLD digest-or-exact-NEW granules.
/// COPY comes solely from authenticated prior OLD literal/zero records above.
/// The returned digest binds the complete CURRENT mixed state, not all OLD or
/// all NEW. All ranges are visited, including spans requiring no writes.
fn verify_mixed<R: Read + Seek>(
    source: &mut R,
    policy: &HeldPagedWritePolicy,
    j: &mut File,
) -> io::Result<[u8; 32]> {
    let facts = policy.facts()?;
    let previous = source.stream_position()?;
    let result =
        (|| {
            let mut hash = crate::sha256_native::Sha256::new()?;
            // Three 64 KiB buffers plus the free table stay within the owner's
            // existing explicit 256 KiB auxiliary metadata allowance.
            const BUFFER: usize = 64 * 1024;
            let mut current = vec![0; BUFFER];
            let mut old = vec![0; BUFFER];
            let mut new = vec![0; BUFFER];
            let mut free = vec![0; BUFFER / GRANULE as usize * 16];
            for ordinal in 0..u64::from(facts.range_count) {
                let row = policy.row(ordinal)?;
                hash.update(&row.offset.to_le_bytes())?;
                hash.update(&row.length.to_le_bytes())?;
                let mut within = 0;
                while within < row.length {
                    let n = (row.length - within).min(BUFFER as u64) as usize;
                    source.seek(SeekFrom::Start(sum(row.offset, within)?))?;
                    source.read_exact(&mut current[..n])?;
                    read_new(
                        j,
                        policy,
                        &row,
                        ordinal,
                        within,
                        &mut new[..n],
                        facts.format_version,
                    )?;
                    match row.flags & 3 {
                        2 => {
                            let count = n / GRANULE as usize * 16;
                            read_at(
                                j,
                                sum(
                                    old_payload(&row, facts.format_version)?,
                                    within / GRANULE * 16,
                                )?,
                                &mut free[..count],
                            )?;
                            for (i, (actual, before)) in current[..n]
                                .chunks_exact(GRANULE as usize)
                                .zip(free[..count].chunks_exact(16))
                                .enumerate()
                            {
                                let after = &new[i * GRANULE as usize..(i + 1) * GRANULE as usize];
                                if actual != after
                                    && xxhash_rust::xxh3::xxh3_128(actual).to_le_bytes().as_slice()
                                        != before
                                {
                                    return Err(invalid(
                                        "partition MIXED source-free granule is foreign/torn",
                                    ));
                                }
                            }
                        }
                        kind => {
                            if kind == 1 {
                                old[..n].fill(0);
                            } else {
                                read_at(
                                    j,
                                    sum(old_payload(&row, facts.format_version)?, within)?,
                                    &mut old[..n],
                                )?;
                            }
                            if current[..n].iter().zip(&old[..n]).zip(&new[..n]).any(
                                |((&actual, &before), &after)| actual != before && actual != after,
                            ) {
                                return Err(invalid("partition MIXED selected byte is foreign"));
                            }
                        }
                    }
                    hash.update(&current[..n])?;
                    within += n as u64;
                }
            }
            hash.finish()
        })();
    source.seek(SeekFrom::Start(previous))?;
    result
}

/// ABT preserves source-free granules in either their authenticated OLD form or
/// their exact NEW form; foreign/torn granules refuse. Restore-required rows
/// remain covered by the existing framed restored-OLD digest.
fn verify_free_after_abort<R: Read + Seek>(
    source: &mut R,
    policy: &HeldPagedWritePolicy,
    j: &mut File,
    abandoned: bool,
) -> io::Result<()> {
    let facts = policy.facts()?;
    let previous = source.stream_position()?;
    let result = (|| {
        let mut current = [0; GRANULE as usize];
        let mut new = [0; GRANULE as usize];
        for ordinal in 0..u64::from(facts.range_count) {
            let row = policy.row(ordinal)?;
            if row.flags & 3 != 2 {
                continue;
            }
            let mut within = 0;
            while within < row.length {
                source.seek(SeekFrom::Start(sum(row.offset, within)?))?;
                source.read_exact(&mut current)?;
                let mut old = [0; 16];
                read_at(
                    j,
                    sum(
                        old_payload(&row, facts.format_version)?,
                        within / GRANULE * 16,
                    )?,
                    &mut old,
                )?;
                if !abandoned {
                    read_new(
                        j,
                        policy,
                        &row,
                        ordinal,
                        within,
                        &mut new,
                        facts.format_version,
                    )?;
                }
                if (abandoned || current != new)
                    && xxhash_rust::xxh3::xxh3_128(&current).to_le_bytes() != old
                {
                    return Err(invalid("closed ABT source-free granule is foreign"));
                }
                within += GRANULE;
            }
        }
        Ok(())
    })();
    source.seek(SeekFrom::Start(previous))?;
    result
}

pub(crate) fn authenticate_scoped_partition_paged_source(
    source: &mut PartitionScopedOwner,
    policy: &HeldPagedWritePolicy,
    j: &mut File,
    p: &PagedRecoveryPins<'_>,
    phase: PartitionJournalPhase,
) -> io::Result<()> {
    let binding = source.binding().clone();
    let length = source.byte_len();
    authenticate_scoped_partition_reader(source, length, &binding, policy, j, p, phase).map(|_| ())
}

pub(crate) fn authenticate_partition_mixed(
    source: &mut PartitionScopedOwner,
    policy: &HeldPagedWritePolicy,
    j: &mut File,
    p: &PagedRecoveryPins<'_>,
    direction: PagedRecoveryDirection,
) -> io::Result<([u8; 32], [u8; 32])> {
    let binding = source.binding().clone();
    let length = source.byte_len();
    let current = authenticate_scoped_partition_reader(
        source,
        length,
        &binding,
        policy,
        j,
        p,
        PartitionJournalPhase::Mixed(direction),
    )?
    .ok_or_else(|| invalid("partition MIXED current digest missing"))?;
    let mut blocks = [0; (2 * GRANULE) as usize];
    read_at(j, 0, &mut blocks)?;
    check_lifecycle(j, p, direction)?;
    Ok((current, Sha256::digest(blocks).into()))
}

pub(in crate::native) fn authenticate_scoped_partition_reader<R: Read + Seek>(
    source: &mut R,
    source_length: u64,
    binding: &PartitionSourceBinding,
    policy: &HeldPagedWritePolicy,
    j: &mut File,
    p: &PagedRecoveryPins<'_>,
    phase: PartitionJournalPhase,
) -> io::Result<Option<[u8; 32]>> {
    binding.validate()?;
    let facts = policy.facts()?;
    if p.journal_profile.version() != 3
        || !(1..=5).contains(&facts.format_version)
        || facts.image_length != source_length
        || source_length != binding.storage.identity.partition_bytes
        || facts.journal_length < BODY + HEADER as u64 + FOOTER as u64
        || facts.journal_length > p.journal_profile.max_journal_bytes()
        || facts.journal_immutable_sha256 != p.immutable_sha256
    {
        return Err(invalid("scoped partition policy/profile/geometry differs"));
    }
    let before = scoped_journal(binding, j, p, facts.journal_length)?;
    let modified = j.metadata()?.modified()?;
    lifecycle(j, p, phase)?;
    let mut lifecycle_before = [0; (2 * GRANULE) as usize];
    read_at(j, 0, &mut lifecycle_before)?;
    if crate::sha256_native::hash_range(j, BODY, facts.journal_length - BODY)? != p.immutable_sha256
    {
        return Err(invalid("scoped partition immutable journal differs"));
    }
    verify_index_against_journal(j, policy, p)?;
    let mut mixed = None;
    match phase {
        PartitionJournalPhase::FreshOld => {
            verify_selected_digest(source, policy, p.old_selected_sha256)?
        }
        PartitionJournalPhase::Applying | PartitionJournalPhase::Replaying(_) => (),
        PartitionJournalPhase::Mixed(_) => {
            mixed = Some(verify_mixed(source, policy, j)?);
        }
        PartitionJournalPhase::New | PartitionJournalPhase::Handoff => {
            verify_selected_digest(source, policy, p.new_selected_sha256)?
        }
        PartitionJournalPhase::Aborted => {
            let abandoned = check_aborted_lifecycle(j, p)?;
            if abandoned {
                verify_selected_digest(source, policy, p.old_selected_sha256)?;
            } else {
                verify_restored_digest(source, policy, p)?;
            }
            verify_free_after_abort(source, policy, j, abandoned)?;
            let previous = source.stream_position()?;
            let mut boot = [0; 512];
            source.seek(SeekFrom::Start(0))?;
            let read = source.read_exact(&mut boot);
            source.seek(SeekFrom::Start(previous))?;
            read?;
            if &boot[3..11] != b"NTFS    " || boot[510..512] != [0x55, 0xaa] {
                return Err(invalid("closed ABT source boot identity is not NTFS"));
            }
        }
        PartitionJournalPhase::Restored => {
            verify_restored_digest(source, policy, p)?;
            verify_free_after_abort(source, policy, j, false)?;
            let previous = source.stream_position()?;
            let mut boot = [0; 512];
            source.seek(SeekFrom::Start(0))?;
            let read = source.read_exact(&mut boot);
            source.seek(SeekFrom::Start(previous))?;
            read?;
            if &boot[3..11] != b"NTFS    " || boot[510..512] != [0x55, 0xaa] {
                return Err(invalid(
                    "partition restored source boot identity is not NTFS",
                ));
            }
        }
    }
    lifecycle(j, p, phase)?;
    if crate::sha256_native::hash_range(j, BODY, facts.journal_length - BODY)? != p.immutable_sha256
    {
        return Err(invalid(
            "scoped partition journal changed around source verification",
        ));
    }
    verify_index_against_journal(j, policy, p)?;
    lifecycle(j, p, phase)?;
    let after = scoped_journal(binding, j, p, facts.journal_length)?;
    let mut lifecycle_after = [0; (2 * GRANULE) as usize];
    read_at(j, 0, &mut lifecycle_after)?;
    if before.identity != after.identity
        || before.file_bytes != after.file_bytes
        || lifecycle_before != lifecycle_after
        || !before.final_path.eq_ignore_ascii_case(&after.final_path)
        || j.metadata()?.modified()? != modified
    {
        return Err(invalid("scoped partition held journal changed"));
    }
    Ok(mixed)
}

pub(crate) fn publish_partition_rollback_marker(
    j: &mut File,
    p: &PagedRecoveryPins<'_>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    // Closed HND/ABT and torn/foreign intents refuse before this write.
    check_lifecycle(j, p, PagedRecoveryDirection::Rollback)?;
    let rb = marker(b"N2RSRB01", &p.immutable_sha256, &p.old_selected_sha256);
    j.seek(SeekFrom::Start(GRANULE))?;
    j.write_all(&rb)?;
    j.sync_all()?;
    let mut actual = [0; GRANULE as usize];
    read_at(j, GRANULE, &mut actual)?;
    if actual != rb {
        return Err(invalid("partition RB flush/readback differs"));
    }
    rollback_active(j, p)?;
    events.push(NativeEvent {
        operation: "partition-paged-rollback-intent-durable".into(),
        control_code: 0,
        input: vec![],
        succeeded: true,
        native_error: None,
        output: b"RB flushed/read back before reopened bounded partition rollback writer".to_vec(),
    });
    Ok(())
}

pub(crate) fn publish_partition_apply_marker(
    j: &mut File,
    p: &PagedRecoveryPins<'_>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    check_clear_lifecycle(j)?;
    let ap = marker(b"N2RSAP01", &p.immutable_sha256, &p.new_selected_sha256);
    j.seek(SeekFrom::Start(GRANULE))?;
    j.write_all(&ap)?;
    j.sync_all()?;
    let mut actual = [0; GRANULE as usize];
    read_at(j, GRANULE, &mut actual)?;
    if actual != ap {
        return Err(invalid("partition AP flush/readback differs"));
    }
    check_lifecycle(j, p, PagedRecoveryDirection::Resume)?;
    events.push(NativeEvent {
        operation: "partition-paged-apply-intent-durable".into(),
        control_code: 0,
        input: vec![],
        succeeded: true,
        native_error: None,
        output: b"AP flushed/read back before bounded partition writer issuance; no device setter"
            .to_vec(),
    });
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionTerminalKind {
    Handoff,
    Aborted,
}
/// Same-owner closed lifecycle evidence, never a writer or restoration grant.
/// No Clone/Deserialize/path constructor; revalidation needs the actual owners.
pub struct PartitionClosedJournalObservation {
    owner: PartitionOwnerToken,
    binding: PartitionSourceBinding,
    pins: OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    kind: PartitionTerminalKind,
}
impl PartitionClosedJournalObservation {
    pub fn require_owner(&self, owner: &PartitionOwnerToken) -> io::Result<()> {
        if !self.owner.same_owner(owner) {
            return Err(invalid("closed partition J witness owner differs"));
        }
        Ok(())
    }
    pub fn immutable_sha256(&self) -> [u8; 32] {
        self.pins.immutable
    }
    pub fn journal_identity(&self) -> &JournalFileIdentity {
        &self.pins.identity
    }
    pub fn kind(&self) -> PartitionTerminalKind {
        self.kind
    }
    /// Only the actual native restoration guard can call this after replacing
    /// private-only owner state with its independently checked BasicRO state.
    /// Binding/token route the SAME retained RW File; they do not issue it.
    pub(in crate::native) fn revalidate_reader<R: Read + Seek>(
        &self,
        source: &mut R,
        source_length: u64,
        binding: &PartitionSourceBinding,
        token: &PartitionOwnerToken,
        policy: &HeldPagedWritePolicy,
        j: &mut File,
        pins: &PagedRecoveryPins<'_>,
    ) -> io::Result<()> {
        self.require_owner(token)?;
        if binding != &self.binding
            || source_length != self.binding.storage.identity.partition_bytes
        {
            return Err(invalid("closed partition reader source binding differs"));
        }
        self.pins.require(pins)?;
        if policy.facts()?.index_sha256 != self.index_sha256 {
            return Err(invalid("closed partition reader index differs"));
        }
        authenticate_scoped_partition_reader(
            source,
            source_length,
            binding,
            policy,
            j,
            pins,
            match self.kind {
                PartitionTerminalKind::Handoff => PartitionJournalPhase::Handoff,
                PartitionTerminalKind::Aborted => PartitionJournalPhase::Aborted,
            },
        )
        .map(|_| ())
    }
    pub fn revalidate(
        &self,
        source: &mut PartitionScopedOwner,
        policy: &HeldPagedWritePolicy,
        j: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.require_owner(&source.owner_token())?;
        if source.binding() != &self.binding {
            return Err(invalid("closed partition witness source binding differs"));
        }
        self.pins.require(pins)?;
        if policy.facts()?.index_sha256 != self.index_sha256 {
            return Err(invalid("closed partition J witness index differs"));
        }
        source.revalidate_current_critical_volume_policy(events)?;
        authenticate_scoped_partition_paged_source(
            source,
            policy,
            j,
            pins,
            match self.kind {
                PartitionTerminalKind::Handoff => PartitionJournalPhase::Handoff,
                PartitionTerminalKind::Aborted => PartitionJournalPhase::Aborted,
            },
        )?;
        source.revalidate_current_critical_volume_policy(events)
    }
}
pub fn authenticate_partition_closed_journal(
    source: &mut PartitionScopedOwner,
    policy: &HeldPagedWritePolicy,
    j: &mut File,
    pins: &PagedRecoveryPins<'_>,
    kind: PartitionTerminalKind,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionClosedJournalObservation> {
    let witness = PartitionClosedJournalObservation {
        owner: source.owner_token(),
        binding: source.binding().clone(),
        pins: OwnedPartitionJournalPins::capture(pins),
        index_sha256: policy.facts()?.index_sha256,
        kind,
    };
    witness.revalidate(source, policy, j, pins, events)?;
    Ok(witness)
}

/// Owns a readonly duplicate of the SAME journal FileObject and the actual held
/// readonly index. Only a spent fresh or Resume replay gate can issue it after
/// durable HND; neither path exposes a journal writer or raw handle.
pub struct PartitionHandoffWitness {
    closed: PartitionClosedJournalObservation,
    journal: File,
    policy: HeldPagedWritePolicy,
}
impl PartitionHandoffWitness {
    pub(in crate::native) fn into_terminal_journal_owners(
        mut self,
        source: &mut PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<crate::native::partition_restoration::PartitionLiveJournalOwners> {
        self.revalidate(source, events)?;
        let pins = OwnedPartitionJournalPins::capture(&self.closed.pins.pins());
        Ok(
            crate::native::partition_restoration::PartitionLiveJournalOwners {
                closed: self.closed,
                journal: self.journal,
                policy: self.policy,
                pins,
            },
        )
    }
    pub(crate) fn from_spent_gate(
        source: &mut PartitionScopedOwner,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        let closed = authenticate_partition_closed_journal(
            source,
            policy,
            journal,
            pins,
            PartitionTerminalKind::Handoff,
            events,
        )?;
        let readonly = crate::file_storage::duplicate_readonly(journal)?;
        let mut result = Self {
            closed,
            journal: readonly,
            policy: policy.clone(),
        };
        result.revalidate(source, events)?;
        Ok(result)
    }
    pub fn require_owner(&self, token: &PartitionOwnerToken) -> io::Result<()> {
        self.closed.require_owner(token)
    }
    pub fn revalidate(
        &mut self,
        source: &mut PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let pins = self.closed.pins.pins();
        self.closed
            .revalidate(source, &self.policy, &mut self.journal, &pins, events)
    }
}

/// Closed-J/source authentication from an actual BasicRO capability only.
/// No private owner, old FS lock or source write gate is reconstructed.
pub(in crate::native) fn authenticate_basic_ro_closed(
    source: &mut crate::native::partition_restoration::PartitionBasicReadonlyTerminal,
    policy: &HeldPagedWritePolicy,
    j: &mut File,
    pins: &PagedRecoveryPins<'_>,
    kind: PartitionTerminalKind,
    observer: &mut impl crate::native::partition_restoration::PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionClosedJournalObservation> {
    source.revalidate(observer, events)?;
    let binding = source.binding().clone();
    let token = source.owner_token().clone();
    let witness = PartitionClosedJournalObservation {
        owner: token,
        binding: binding.clone(),
        pins: OwnedPartitionJournalPins::capture(pins),
        index_sha256: policy.facts()?.index_sha256,
        kind,
    };
    {
        let mut reader = source.reader(events)?;
        authenticate_scoped_partition_reader(
            &mut reader,
            binding.storage.identity.partition_bytes,
            &binding,
            policy,
            j,
            pins,
            if kind == PartitionTerminalKind::Handoff {
                PartitionJournalPhase::Handoff
            } else {
                PartitionJournalPhase::Aborted
            },
        )?;
    }
    source.revalidate(observer, events)?;
    Ok(witness)
}
