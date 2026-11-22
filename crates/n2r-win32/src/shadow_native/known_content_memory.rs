//! Known-content reads over an already validated, accounted converted report.
//! Unknown original digests stay unknown and require the separate map proof.
use super::*;
use std::fmt;

/// Stored last in KnownContentVerification, which itself drops after the
/// native report's added hash strings. This pays retained extras on errors too.
pub(super) struct KnownContentMemory {
    lease: Box<dyn report_memory::ReportMemoryLease>,
}
impl fmt::Debug for KnownContentMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountedKnownContentMemory")
    }
}

fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("known-content RAM arithmetic overflow"))
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("known-content RAM arithmetic overflow"))
}

fn stream_workspace(item: &Input<'_>, root: &str, name: &[u16], maximum: u64) -> io::Result<u64> {
    // One current metadata snapshot (API/kernel SDs plus fixed EA/reparse
    // buffers) OR a <=4 MiB logical-read buffer, never a maximum for every row.
    // Path formatting, joining, UTF16 conversion and open-type queries are
    // bounded separately from the actual row owner's decoded metadata.
    let path = item
        .components
        .iter()
        .try_fold(root.len() as u64, |n, part| {
            add(n, add(part.len() as u64, 1)?)
        })?;
    let path = add(path, mul(name.len() as u64, 3)?)?;
    add(snapshot_or_read_workspace(maximum)?, path_workspace(path)?)
}
/// The part of [`stream_workspace`] that does not depend on the stream: one
/// metadata snapshot or one logical-read buffer.
fn snapshot_or_read_workspace(maximum: u64) -> io::Result<u64> {
    add(
        mul(
            maximum.max(crate::attestation::MAX_SECURITY_BYTES as u64),
            8,
        )?,
        8 * 1024 * 1024,
    )
}
/// The part of [`stream_workspace`] that follows the stream's path.
fn path_workspace(path: u64) -> io::Result<u64> {
    mul(add(path, 4096)?, 16)
}

/// Which optional parts of a named stream's snapshot the already validated
/// observation of that stream has: a live snapshot keeps the same ones.
#[derive(Clone, Copy)]
struct NamedScope {
    reparse: bool,
    extended_attributes: bool,
}
impl NamedScope {
    fn of(previous: &Snapshot) -> Self {
        Self {
            reparse: previous.reparse.is_some(),
            extended_attributes: previous.extended_attributes.is_some()
                || previous.extended_attributes_error.is_some(),
        }
    }
}

fn named_snapshot(file: &File, previous: &Snapshot, maximum: u64) -> io::Result<Snapshot> {
    named_snapshot_in(file, NamedScope::of(previous), maximum)
}
fn named_snapshot_in(file: &File, scope: NamedScope, maximum: u64) -> io::Result<Snapshot> {
    // Keep the exact feature scope of the already validated ADS observation,
    // while using the ORIGINAL admitted security bound for the live query.
    // What is outside that scope is not asked for.
    Ok(crate::attestation_native::source_snapshot_paged_scoped(
        file,
        false,
        usize::try_from(maximum).map_err(io::Error::other)?,
        scope.extended_attributes,
        scope.reparse,
    ))
}

/// What the check of every object shares.
struct Check<'a> {
    root: &'a str,
    /// The admitted row limit: the bound of every live security query.
    maximum: u64,
    protected: bool,
    payer: &'a dyn report_memory::ReportMemoryAccountant,
}
/// What the pass counts, in the order of the objects and of their streams.
#[derive(Default)]
struct Tally {
    count: usize,
    skipped: usize,
    bytes: u64,
    retained_bytes: u64,
}
impl Tally {
    /// A stream without an original digest.
    fn skip(&mut self) -> io::Result<()> {
        self.skipped = self
            .skipped
            .checked_add(1)
            .ok_or_else(|| invalid("unknown-content count overflow"))?;
        Ok(())
    }
    /// A stream whose bytes were held to its original digest: the default
    /// stream of the row at `index`, or its named stream at `ordinal`.
    fn hashed(
        &mut self,
        rows: &mut Rows,
        index: usize,
        ordinal: Option<usize>,
        actual: String,
        length: u64,
    ) -> io::Result<()> {
        if actual.capacity() > 128 {
            return Err(invalid(
                "known-content digest allocation exceeds prepayment",
            ));
        }
        // Rows kept in blocks are not changed: nothing reads a digest
        // from a row after this check, which has just held it to what
        // was expected, and a row may be in working storage by now.
        if !rows.in_blocks() {
            self.retained_bytes = add(self.retained_bytes, actual.capacity() as u64)?;
            match ordinal {
                None => rows.set_logical_sha256(index, Some(actual))?,
                Some(ordinal) => {
                    rows.set_named_stream_logical_sha256(index, ordinal, Some(actual))?
                }
            }
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("known-content count overflow"))?;
        self.bytes = add(self.bytes, length)?;
        Ok(())
    }
}
/// A named stream of a report row, as a helper needs it: the helper reads
/// no rows.
struct NamedWork {
    name: Vec<u16>,
    before: NamedScope,
    after: NamedScope,
}
/// One object gathered for the helpers.
struct Work<'a> {
    item: Input<'a>,
    /// The row's named streams, in the row's order.
    named: Vec<NamedWork>,
    _paid: Option<Box<dyn report_memory::ReportMemoryLease>>,
}
/// What a helper saw of one stream that has an original digest. Nothing is
/// compared on the helper: the calling thread holds this to the row and to
/// the expectation when the object's turn comes.
struct StreamAhead {
    before: Snapshot,
    digest: String,
    after: Snapshot,
    _paid: Box<dyn report_memory::ReportMemoryLease>,
}
/// What a helper saw of one object: its default stream, and its named
/// streams in the row's order. `None` is a stream without an original digest.
struct Ahead {
    unnamed: Option<StreamAhead>,
    named: Vec<Option<StreamAhead>>,
}
/// The memory a helper thread needs until its results are paid for: its
/// stack, the buffer its queries answer into, the two snapshots of one
/// stream and the buffer that stream is read through.
///
/// The snapshots are sized as every pass that observes at once sizes them
/// ([`report_memory::residual_query_peak`]: by the largest descriptor there
/// is, since a descriptor is copied at its own length), not by the row
/// limit as the reservation of a stream read in turn is: eight row limits
/// for each helper is two gigabytes on a machine with 24, which the ledger
/// would spare for a few helpers at best.
fn helper_workspace_bytes(maximum: u64) -> io::Result<u64> {
    const THREAD_STACK_BYTES: u64 = 2 * 1024 * 1024;
    // The largest request `hash_exact_stream` makes.
    const READ_BUFFER_BYTES: u64 = 4 * 1024 * 1024;
    [
        THREAD_STACK_BYTES,
        crate::query_scratch::KEPT_BYTES as u64,
        report_memory::residual_query_peak(maximum)?,
        READ_BUFFER_BYTES,
    ]
    .into_iter()
    .try_fold(0u64, add)
}
impl Check<'_> {
    fn open_unnamed(&self, item: &Input<'_>) -> io::Result<File> {
        let path = streams::path(self.root, item.components, &[])?;
        open_input(&path, item, self.protected)
    }
    fn open_named(&self, item: &Input<'_>, name: &[u16]) -> io::Result<File> {
        let path = streams::path(self.root, item.components, name)?;
        if self.protected {
            open_protected_readonly(&path, false)
        } else {
            open(&path, false, false)
        }
    }
    /// The query memory of one stream read on the calling thread. If it is
    /// refused while helpers hold workspaces, they give them up and it is
    /// asked for once more: the rest of the pass then runs without helpers,
    /// and what the reservation fails with then is the pass's error, as in a
    /// pass that never had them.
    fn reserve_in_turn(
        &self,
        helpers: &mut Vec<Box<dyn report_memory::ReportMemoryLease>>,
        bytes: u64,
    ) -> io::Result<Box<dyn report_memory::ReportMemoryLease>> {
        match self.payer.reserve(bytes) {
            Err(_) if !helpers.is_empty() => {
                helpers.clear();
                self.payer.reserve(bytes)
            }
            reserved => reserved,
        }
    }
    /// One object, stream by stream, on the calling thread. A row is read
    /// while its stream is hashed and the digest is recorded in it
    /// afterwards, stream by stream in the order the row lists them.
    fn in_turn(
        &self,
        rows: &mut Rows,
        tally: &mut Tally,
        helpers: &mut Vec<Box<dyn report_memory::ReportMemoryLease>>,
        index: usize,
        item: &Input<'_>,
    ) -> io::Result<()> {
        if item.directory {
            return Ok(());
        }
        let maximum = self.maximum;
        if let Some(expected) = item.logical_sha256() {
            let _query = self.reserve_in_turn(
                helpers,
                add(
                    stream_workspace(item, self.root, &[], maximum)?,
                    self.payer.lease_heap_bytes(),
                )?,
            )?;
            let mut file = self.open_unnamed(item)?;
            let actual = rows.with(index, |object| {
                if metadata_snapshot_with_limit(&file, item, Some(maximum)) != object.before {
                    return Err(invalid("known-content file identity or metadata changed"));
                }
                let actual = hash_exact_stream(&mut file, item.logical_length())?;
                if actual != expected
                    || metadata_snapshot_with_limit(&file, item, Some(maximum)) != object.after
                {
                    return Err(invalid("known-content bytes, metadata or EOF differ"));
                }
                Ok(actual)
            })?;
            tally.hashed(rows, index, None, actual, item.logical_length())?;
        } else {
            tally.skip()?;
        }
        let named_streams = rows.with(index, |object| Ok(object.named_streams.len()))?;
        for ordinal in 0..named_streams {
            // The digest and the length of a stream that has an original
            // digest, with the query memory its reading holds until the
            // digest is recorded; nothing for a stream that has none.
            let hashed = rows.with(index, |object| {
                let named = &object.named_streams[ordinal];
                let stream = item
                    .named_streams
                    .iter()
                    .find(|s| s.name_utf16 == named.name_utf16)
                    .ok_or_else(|| invalid("known named stream absent from actual expected row"))?;
                let Some(expected) = stream.expected_sha256 else {
                    return Ok(None);
                };
                let query = self.reserve_in_turn(
                    helpers,
                    add(
                        stream_workspace(item, self.root, stream.name_utf16, maximum)?,
                        self.payer.lease_heap_bytes(),
                    )?,
                )?;
                let mut file = self.open_named(item, stream.name_utf16)?;
                if named_snapshot(&file, &named.before, maximum)? != named.before {
                    return Err(invalid("known named-stream identity or metadata changed"));
                }
                let actual = hash_exact_stream(&mut file, stream.expected_length)?;
                if actual != expected
                    || named_snapshot(&file, &named.after, maximum)? != named.after
                {
                    return Err(invalid("known named-stream bytes, metadata or EOF differ"));
                }
                Ok(Some((query, actual, stream.expected_length)))
            })?;
            let Some((_query, actual, length)) = hashed else {
                tally.skip()?;
                continue;
            };
            tally.hashed(rows, index, Some(ordinal), actual, length)?;
        }
        Ok(())
    }
    /// What a helper needs of the object at `index`, paid for as spare
    /// memory: the names of the row's streams and room for the longest of
    /// their paths. `None` where that memory is refused or the row cannot be
    /// read: the object then waits for its turn, and whatever is wrong with
    /// it is found and reported there.
    fn gather(
        &self,
        rows: &Rows,
        index: usize,
        item: &Input<'_>,
    ) -> Option<(
        Vec<NamedWork>,
        Option<Box<dyn report_memory::ReportMemoryLease>>,
    )> {
        if item.directory {
            return Some((Vec::new(), None));
        }
        let named = rows
            .with(index, |object| {
                Ok(object
                    .named_streams
                    .iter()
                    .map(|named| NamedWork {
                        name: named.name_utf16.clone(),
                        before: NamedScope::of(&named.before),
                        after: NamedScope::of(&named.after),
                    })
                    .collect::<Vec<_>>())
            })
            .ok()?;
        let base = item
            .components
            .iter()
            .try_fold(self.root.len() as u64, |n, part| {
                add(n, add(part.len() as u64, 1)?)
            })
            .ok()?;
        let mut longest = 0u64;
        let mut held = mul(named.capacity() as u64, mem::size_of::<NamedWork>() as u64).ok()?;
        for stream in &named {
            longest = longest.max(stream.name.len() as u64);
            held = add(held, mul(stream.name.capacity() as u64, 2).ok()?).ok()?;
        }
        let path = add(base, mul(longest, 3).ok()?).ok()?;
        let bytes = add(
            add(held, path_workspace(path).ok()?).ok()?,
            self.payer.lease_heap_bytes(),
        )
        .ok()?;
        let paid = self.payer.reserve_spare(bytes).ok()?;
        Some((named, Some(paid)))
    }
    /// One stream as a helper reads it: the snapshot before, the digest of
    /// exactly `length` bytes with the end of the stream confirmed, and the
    /// snapshot after; then paid for as spare memory. `None` where anything
    /// fails: the stream is then read again in its object's turn.
    fn stream_ahead(
        &self,
        mut file: File,
        length: u64,
        snapshot: impl Fn(&File) -> io::Result<Snapshot>,
    ) -> Option<StreamAhead> {
        let before = snapshot(&file).ok()?;
        let digest = hash_exact_stream(&mut file, length).ok()?;
        let after = if crate::verify_policy::verifies_once() {
            before.clone()
        } else {
            snapshot(&file).ok()?
        };
        let held = [
            report_memory::snapshot_bytes(&before).ok()?,
            report_memory::snapshot_bytes(&after).ok()?,
            digest.capacity() as u64,
            mem::size_of::<StreamAhead>() as u64,
            self.payer.lease_heap_bytes(),
        ]
        .into_iter()
        .try_fold(0u64, add)
        .ok()?;
        let paid = self.payer.reserve_spare(held).ok()?;
        Some(StreamAhead {
            before,
            digest,
            after,
            _paid: paid,
        })
    }
    /// One object on a helper thread: every stream that has an original
    /// digest is opened, described, read to its end and described again.
    /// `None` where the object has nothing to read, or where anything fails
    /// or cannot be paid for: the object is then taken in turn.
    fn ahead(&self, work: &Work<'_>) -> Option<Ahead> {
        let item = &work.item;
        if item.directory {
            return None;
        }
        let maximum = self.maximum;
        let unnamed = if item.logical_sha256().is_some() {
            Some(self.stream_ahead(
                self.open_unnamed(item).ok()?,
                item.logical_length(),
                |file| Ok(metadata_snapshot_with_limit(file, item, Some(maximum))),
            )?)
        } else {
            None
        };
        let mut named = Vec::with_capacity(work.named.len());
        for gathered in &work.named {
            let stream = item
                .named_streams
                .iter()
                .find(|s| s.name_utf16 == gathered.name.as_slice())?;
            if stream.expected_sha256.is_none() {
                named.push(None);
                continue;
            }
            // The snapshot's scope is the row's before the read and after it,
            // as it is in the object's turn.
            let before = std::cell::Cell::new(true);
            named.push(Some(self.stream_ahead(
                self.open_named(item, stream.name_utf16).ok()?,
                stream.expected_length,
                |file| {
                    let scope = if before.replace(false) {
                        gathered.before
                    } else {
                        gathered.after
                    };
                    named_snapshot_in(file, scope, maximum)
                },
            )?));
        }
        Some(Ahead { unnamed, named })
    }
    /// Holds what a helper saw of the object at `index` to the row and to
    /// the expectation, exactly as the object's turn does, and records it.
    /// `false`, with nothing recorded, where anything differs: the object is
    /// then taken in turn, which finds what is wrong and says so.
    fn take_ahead(
        &self,
        rows: &mut Rows,
        tally: &mut Tally,
        index: usize,
        work: &Work<'_>,
        ahead: Ahead,
    ) -> io::Result<bool> {
        let item = &work.item;
        let expected = item.logical_sha256();
        // For every named stream of the row, in its order: the length of one
        // that was held to its digest, nothing for one that has none.
        let lengths = rows.with(index, |object| {
            let unnamed_same = match (&expected, &ahead.unnamed) {
                (Some(expected), Some(seen)) => {
                    seen.before == object.before
                        && seen.digest == *expected
                        && seen.after == object.after
                }
                (None, None) => true,
                _ => false,
            };
            if !unnamed_same
                || object.named_streams.len() != ahead.named.len()
                || work.named.len() != ahead.named.len()
            {
                return Ok(None);
            }
            let mut lengths = Vec::with_capacity(ahead.named.len());
            for ((named, gathered), seen) in object
                .named_streams
                .iter()
                .zip(&work.named)
                .zip(&ahead.named)
            {
                if named.name_utf16 != gathered.name {
                    return Ok(None);
                }
                let Some(stream) = item
                    .named_streams
                    .iter()
                    .find(|s| s.name_utf16 == named.name_utf16)
                else {
                    return Ok(None);
                };
                match (stream.expected_sha256, seen) {
                    (Some(expected), Some(seen))
                        if seen.before == named.before
                            && seen.digest == expected
                            && seen.after == named.after =>
                    {
                        lengths.push(Some(stream.expected_length));
                    }
                    (None, None) => lengths.push(None),
                    _ => return Ok(None),
                }
            }
            Ok(Some(lengths))
        })?;
        let Some(lengths) = lengths else {
            return Ok(false);
        };
        match ahead.unnamed {
            Some(seen) => tally.hashed(rows, index, None, seen.digest, item.logical_length())?,
            None => tally.skip()?,
        }
        for (ordinal, (seen, length)) in ahead.named.into_iter().zip(lengths).enumerate() {
            match (seen, length) {
                (Some(seen), Some(length)) => {
                    tally.hashed(rows, index, Some(ordinal), seen.digest, length)?;
                }
                _ => tally.skip()?,
            }
        }
        Ok(true)
    }
}

pub fn verify_known_contents_in_accounted_report(
    report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    verify_known_contents_in_accounted_report_with_lease(
        report,
        input,
        admission,
        payer,
        same_security,
        None,
    )
}

pub(crate) fn verify_known_contents_in_accounted_report_with_lease(
    report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: Option<&dyn native::ProtectedReadonlyRefsAccess>,
) -> io::Result<GeneralConvertedReport> {
    verify_known_contents_in_accounted_report_with_aliases(
        report,
        input,
        admission,
        payer,
        same_security,
        protected,
        None,
    )
}
pub(crate) fn verify_known_contents_in_accounted_report_with_lease_windows_aliases(
    report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: Option<&dyn native::ProtectedReadonlyRefsAccess>,
    aliases: &windows_aliases::VerifiedWindowsAliases,
) -> io::Result<GeneralConvertedReport> {
    aliases.require_canonical_input(input)?;
    verify_known_contents_in_accounted_report_with_aliases(
        report,
        input,
        admission,
        payer,
        same_security,
        protected,
        Some(aliases),
    )
}
fn verify_known_contents_in_accounted_report_with_aliases(
    mut report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: Option<&dyn native::ProtectedReadonlyRefsAccess>,
    aliases: Option<&windows_aliases::VerifiedWindowsAliases>,
) -> io::Result<GeneralConvertedReport> {
    admission.validate()?;
    input.require_resource_metadata(admission)?;
    if report.native.resource_profile
        != Some(crate::attestation::ResourceProfile::ResourceBoundedV4(
            Some(admission),
        ))
        || !report.native.retained_rows_ram_accounted()
        || report.native.objects.len() != input.len()
        || report.native.binding.disk_number != report.pair.source.disk_number
        || report.native.binding.volume_guid != report.pair.source.volume_guid
        || report.native.binding.identity != report.pair.source.identity
        || protected.is_some_and(|lease| lease.binding() != &report.pair.source)
    {
        return Err(invalid(
            "known-content report lost its actual resource or source owner",
        ));
    }
    // Reuse the complete static metadata/namespace/security validator; this
    // enumerates no native tree and cannot substitute a saved report for the
    // already held, independently accounted observation.
    validate_existing_content_domain_with_memory_and_windows_aliases(
        &report.native,
        input,
        &same_security,
        false,
        None,
        false,
        true,
        Some(payer),
        aliases,
        false,
    )?;
    let observation = report
        .content_observation
        .as_ref()
        .ok_or_else(|| invalid("known-content metadata scope absent"))?;
    if !observation.metadata_and_namespace_verified
        || !observation.complete_stream_mappings_observed
        || !observation.data_storage_validity_checked
        || observation.admitted_payload_bytes_read != 0
        || observation.known_content.is_some()
        || {
            let mut hashed = false;
            report.native.objects.for_each(|_, o| {
                hashed = hashed
                    || o.logical_sha256.is_some()
                    || o.named_streams.iter().any(|s| s.logical_sha256.is_some());
                Ok(())
            })?;
            hashed
        }
    {
        return Err(invalid(
            "known-content requires the original unhashed metadata observation",
        ));
    }
    let mut known = 0u64;
    input.for_each(|_, item| {
        if !item.directory {
            known = add(known, u64::from(item.logical_sha256().is_some()))?;
            for stream in &item.named_streams {
                known = add(known, u64::from(stream.expected_sha256.is_some()))?;
            }
        }
        Ok(())
    })?;
    // At most one fixed hexadecimal digest is added for each actual known
    // original stream. The 64 KiB allowance includes the tiny privilege audit
    // and root path, and avoids retaining a query maximum per stream.
    let retained_maximum = add(add(mul(known, 128)?, 64 * 1024)?, payer.lease_heap_bytes())?;
    let retained = payer.reserve(retained_maximum)?;
    // Attach before mutating any report field: native drops BEFORE the
    // content-observation memory owner, including on every early return.
    report
        .content_observation
        .as_mut()
        .expect("validated observation")
        .known_content = Some(KnownContentVerification {
        streams_hashed: 0,
        streams_without_content_baseline: 0,
        payload_bytes_read: 0,
        privilege_states: Vec::new(),
        memory: Some(KnownContentMemory { lease: retained }),
    });
    let _privilege_ram = payer.reserve(add(512 * 1024, payer.lease_heap_bytes())?)?;
    let root = report.pair.source.volume_path()?;
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ])?;
    let maximum = admission.budget.max_row_bytes;
    let check = Check {
        root: &root,
        maximum,
        protected: protected.is_some(),
        payer,
    };
    let mut tally = Tally::default();
    let rows = &mut report.native.objects;
    // Every stream with an original digest is opened, described, read to its
    // end and described again: a few file-system calls and one read for
    // nearly every file of the volume, which one thread made one after
    // another. The objects are gathered a batch at a time and their streams
    // read on helper threads, one workspace for each helper the ledger can
    // spare; what a helper saw is held to the row and to the expectation on
    // this thread, in the objects' order, and recorded as before. An object
    // a helper could not read, could not pay for, or saw differently is read
    // again here in its turn, exactly as a pass without helpers reads it.
    let mut helpers = Vec::new();
    let wanted = std::thread::available_parallelism()
        .map_or(1, |cores| cores.get())
        .min(rows.len());
    let helper_bytes = add(helper_workspace_bytes(maximum)?, payer.lease_heap_bytes())?;
    while helpers.len() < wanted {
        match payer.reserve_spare(helper_bytes) {
            Ok(workspace) => helpers.push(workspace),
            Err(_) => break,
        }
    }
    let mut next = 0;
    while next < rows.len() {
        if helpers.len() < 2 {
            // One helper would only make this thread wait.
            helpers.clear();
            let owner = input.object(next)?;
            check.in_turn(rows, &mut tally, &mut helpers, next, &owner.input())?;
            next += 1;
            continue;
        }
        let end = next
            .saturating_add(
                helpers
                    .len()
                    .saturating_mul(crate::ordered_observation::OBJECTS_PER_HELPER),
            )
            .min(rows.len());
        // Each object is decoded and what a helper needs of it paid for
        // before the next is decoded. Whatever fails behind at least one
        // gathered object ends the batch: that object is the first of the
        // next one.
        let mut owners = Vec::with_capacity(end - next);
        let mut gathered = Vec::with_capacity(end - next);
        for index in next..end {
            let Ok(owner) = input.object(index) else {
                break;
            };
            let Some(work) = check.gather(rows, index, &owner.input()) else {
                if owners.is_empty() {
                    // Taken by itself below, as without helpers.
                    owners.push(owner);
                }
                break;
            };
            owners.push(owner);
            gathered.push(work);
        }
        if owners.is_empty() {
            // The first object of a batch could not be decoded beside what
            // the helpers hold: it is decoded again without them, and what
            // it fails with then is the pass's error.
            helpers.clear();
            continue;
        }
        if gathered.is_empty() {
            let _timed = crate::perf::scope(crate::perf::Point::InTurn);
            check.in_turn(rows, &mut tally, &mut helpers, next, &owners[0].input())?;
            next += 1;
            continue;
        }
        let works: Vec<Work<'_>> = owners
            .iter()
            .zip(gathered)
            .map(|(owner, (named, paid))| Work {
                item: owner.input(),
                named,
                _paid: paid,
            })
            .collect();
        let observed = crate::ordered_observation::observe_batch(&works, helpers.len(), &|work| {
            check.ahead(work)
        });
        for (offset, (work, seen)) in works.iter().zip(observed).enumerate() {
            let index = next + offset;
            let taken = match seen {
                Some(seen) => check.take_ahead(rows, &mut tally, index, work, seen)?,
                None => false,
            };
            if !taken && !work.item.directory {
                let _timed = crate::perf::scope(crate::perf::Point::InTurn);
                check.in_turn(rows, &mut tally, &mut helpers, index, &work.item)?;
            }
        }
        next += works.len();
    }
    drop(helpers);
    let Tally {
        count,
        skipped,
        bytes,
        mut retained_bytes,
    } = tally;
    privileges.restore()?;
    let privilege_states = privileges.audit().to_vec();
    retained_bytes = add(
        retained_bytes,
        mul(
            privilege_states.capacity() as u64,
            mem::size_of::<PrivilegeState>() as u64,
        )?,
    )?;
    for state in &privilege_states {
        retained_bytes = add(retained_bytes, state.name.capacity() as u64)?;
    }
    retained_bytes = add(retained_bytes, payer.lease_heap_bytes())?;
    if count as u64 != known || retained_bytes > retained_maximum {
        return Err(invalid(
            "known-content retained allocations differ from prepayment",
        ));
    }
    let observation = report
        .content_observation
        .as_mut()
        .expect("validated observation");
    let verification = observation
        .known_content
        .as_mut()
        .expect("actual retained memory owner");
    // Install the paid owned values before shrinking. If shrink fails, the
    // report still drops every value before releasing its original guard.
    verification.streams_hashed = count;
    verification.streams_without_content_baseline = skipped;
    verification.payload_bytes_read = bytes;
    verification.privilege_states = privilege_states;
    verification
        .memory
        .as_mut()
        .expect("actual retained memory owner")
        .lease
        .shrink_to(retained_bytes)?;
    observation.scope = "converted-metadata-and-known-content-hashes-v1";
    observation.admitted_payload_bytes_read = bytes;
    input.require_resource_metadata(admission)?;
    Ok(report)
}
