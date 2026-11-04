//! Live V4 prepared conversion and its independently pinned recovery routing.
//! Only the actual held preparation can construct this owner. Persisted
//! routing never reconstructs its source admission or one-shot apply issuer.
use super::*;
use crate::{
    artifact_arena::{
        ArenaRamLease, ArtifactGroup, ArtifactGroupPermit, ArtifactLease, PreparedArenaClosure,
    },
    general_reconstruct::fast_verification::v4_maps::V4RecoveryMaps,
    ntfs_inspect::paged_storage::SourceScratch,
    shadow_tree::PagedExpectedTree,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::Path,
};

mod apply;
pub(crate) use apply::{FirstFlushedWrite, ResourceAppliedConversion, ResourceFreshApply};

/// A complete fresh-source/target/preparation publication, still incapable of
/// opening an activated writer. Borrowed owners cannot disappear or be replaced
/// while this capability lives; persisted copies carry routing facts only.
pub(crate) struct ResourcePreparedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>
{
    prepared: ProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope>,
    expected: &'expected PagedExpectedTree,
    maps: Option<V4RecoveryMaps>,
    locator: super::super::durable_anchor::DurableRecoveryLocator,
    publication: ArtifactLease,
    checksum: ArtifactLease,
    // Constructed while artifact creation is still admitted; no apply path
    // may create an index after the exhaustive arena closure.
    write_index: Option<super::super::reopen::PreparedJournalIndex>,
    closure: PreparedArenaClosure,
    // Covers publication path copies and the bounded serializer/IO workspace.
    // Drop after the corresponding owned values and their final revalidation.
    _memory: ArenaRamLease,
}

#[derive(Serialize)]
struct FilePin<'a> {
    path: &'a str,
    sha256: &'a str,
    bytes: u64,
}
#[derive(Serialize)]
struct ExpectedPin<'a> {
    file: FilePin<'a>,
    semantic_sha256: &'a str,
    objects: u64,
}
#[derive(Serialize)]
struct MapPin<'a> {
    file: FilePin<'a>,
    records: u64,
}
#[derive(Serialize)]
struct Publication<'a> {
    schema_version: u32,
    kind: &'static str,
    source: &'a n2r_win32::general_layout::GeneralDiskBinding,
    shadow: &'a n2r_win32::general_layout::GeneralDiskBinding,
    resource_admission: n2r_win32::tree_resources::SourceResourceAdmission,
    verification_policy: crate::verification_policy::VerificationPolicy,
    source_fingerprint_kind: &'a str,
    source_sha256: &'a str,
    source_inspection_sha256: &'a str,
    source_views_sha256: &'a str,
    locator: FilePin<'a>,
    expected: ExpectedPin<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_maps: Option<MapPin<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    early_preparation_guard: Option<crate::resource_preparation::early_guard::GuardPin>,
    ticket_sha256: String,
    expected_mount_paths: &'a [String],
    expected_source_label: &'a n2r_win32::volume_label::VolumeLabel,
    serialized_publication_grants_authority: bool,
}

struct DigestWriter {
    bytes: u64,
    maximum: u64,
    digest: Sha256,
}
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("prepared publication exceeds resource admission"))?;
        self.digest.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn serialization_pin(value: &impl Serialize, maximum: u64) -> Result<(u64, [u8; 32])> {
    let mut writer = DigestWriter {
        bytes: 0,
        maximum,
        digest: Sha256::new(),
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok((writer.bytes, writer.digest.finalize().into()))
}

fn same_ticket(a: &SelectedTicket, b: &SelectedTicket) -> Result<bool> {
    // A ticket contains scalar hashes/counts, never the selected record table.
    Ok(serialization_pin(a, 4096)? == serialization_pin(b, 4096)?)
}

fn checkpoint_native_events(
    events: &mut Vec<n2r_win32::NativeEvent>,
    checkpoint: &mut impl FnMut(&mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
) -> Result<()> {
    if !events.is_empty() {
        checkpoint(events)?;
        ensure!(events.is_empty(), "native event checkpoint did not drain");
    }
    Ok(())
}

pub(super) fn expected_requires_maps(
    expected: &PagedExpectedTree,
    policy: crate::verification_policy::VerificationPolicy,
) -> Result<bool> {
    let mut requires = false;
    for ordinal in 0..expected.len() {
        // The actual expected owner pays for the decoded row throughout this
        // check; the generic Cow<Object> helper would release that lease.
        let object = expected.object_leased(ordinal)?;
        for stream in object.data_streams() {
            ensure!(
                !policy.is_full_content() || stream.sha256.is_some(),
                "full-content policy requires an actual complete logical digest"
            );
            requires |= stream.source_evidence.is_some();
        }
    }
    Ok(requires)
}

fn require_owners(
    prepared: &mut ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
    expected: &PagedExpectedTree,
    maps: Option<&V4RecoveryMaps>,
    locator: &mut super::super::durable_anchor::DurableRecoveryLocator,
    journal_receipt: Option<&super::super::reopen::PreparedJournalIndex>,
    arena: Option<&crate::artifact_arena::PreparedArenaRevalidation<'_>>,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    let capture = prepared.candidate.protected_proof().captured();
    // The current exhaustive arena boundary hashes this exact retained literal
    // before and after all nested work. Reuse only that immediate same-owner
    // check; keep the capture index, native identity and lifecycle checks.
    match arena {
        Some(arena) => capture.with_arena_revalidation(arena, |witness| {
            require_owners_with_capture_witness(
                prepared,
                expected,
                maps,
                locator,
                journal_receipt,
                witness,
                events,
            )
        }),
        // Publication runs before the arena can close. Keep its complete
        // original capture checks; it has no enclosing immutable witness.
        None => {
            let result = capture.with_revalidation(|witness| {
                require_owners_with_capture_witness(
                    prepared,
                    expected,
                    maps,
                    locator,
                    journal_receipt,
                    witness,
                    events,
                )
            });
            capture.revalidate()?;
            result
        }
    }
}

fn require_owners_with_capture_witness(
    prepared: &mut ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
    expected: &PagedExpectedTree,
    maps: Option<&V4RecoveryMaps>,
    locator: &mut super::super::durable_anchor::DurableRecoveryLocator,
    journal_receipt: Option<&super::super::reopen::PreparedJournalIndex>,
    witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    with_frozen_preparation_revalidation(prepared, witness, events, |frozen, prepared, events| {
        require_owners_between_frozen_checks(
            frozen,
            prepared,
            expected,
            maps,
            locator,
            journal_receipt,
            events,
        )
    })
}

/// A borrow of the exact source and protected target whose complete frozen
/// bytes were checked at this boundary's opening. It supplies no writer or
/// admission authority and cannot escape the higher-ranked callback below.
pub(in crate::selected_journal::resource_domain) struct FrozenPreparedWitness<'boundary> {
    source_owner: usize,
    proof: &'boundary crate::general_composite_target::paged::ProtectedPagedTargetSelection,
}
impl FrozenPreparedWitness<'_> {
    pub(in crate::selected_journal::resource_domain) fn require(
        &self,
        prepared: &ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
    ) -> Result<()> {
        let actual = prepared.candidate.protected_proof();
        ensure!(
            self.source_owner == prepared.context.source_owner_identity()
                && std::ptr::eq(self.proof, actual)
                && actual.scope().matches_source_owner(self.source_owner),
            "read-only preparation boundary lost its actual source or protected target owner"
        );
        Ok(())
    }
}

fn finish_readonly_boundary<T>(result: Result<T>, closing: Result<()>) -> Result<T> {
    match (result, closing) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(closing)) => Err(error.context(format!(
            "read-only preparation also failed its complete closing validation: {closing:#}"
        ))),
    }
}

fn with_frozen_preparation_revalidation<'journal, 'domain, 'capture, 'proof, 'scope, T>(
    prepared: &mut ProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope>,
    witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    events: &mut Vec<n2r_win32::NativeEvent>,
    callback: impl for<'boundary> FnOnce(
        &'boundary FrozenPreparedWitness<'boundary>,
        &'boundary mut ProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope>,
        &'boundary mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<T>,
) -> Result<T> {
    prepared.revalidate_with_capture_witness(witness, events)?;
    let frozen = FrozenPreparedWitness {
        source_owner: prepared.context.source_owner_identity(),
        proof: prepared.candidate.protected_proof(),
    };
    let result = callback(&frozen, prepared, events);
    // Every callback here is read-only on source/target. Ordinary file/device
    // exclusion does not prove raw aliases absent, so always repeat the FULL
    // original source fingerprint and target consumed-range hash afterward,
    // including callback errors. Only a successful close can release T.
    let closing = prepared.revalidate_with_capture_witness(witness, events);
    finish_readonly_boundary(result, closing)
}

/// Preserve the interior metadata/native/journal checks while the exact frozen
/// byte owners remain enclosed by the complete opening and closing scans.
fn require_construction_owners(
    frozen: &FrozenPreparedWitness<'_>,
    prepared: &mut ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
    capture: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    frozen.require(prepared)?;
    let proof = prepared.candidate.protected_proof();
    capture.require_capture(proof.captured())?;
    prepared.candidate.require_domain(prepared.inner._domain)?;
    let context = &mut prepared.context;
    context.require_source_evidence()?;
    context.revalidate_evidence()?;
    let arena = context
        .arena()
        .context("construction source arena absent")?;
    ensure!(
        arena.budget() == context.resource_admission().budget,
        "construction arena admission differs"
    );
    for (seal, group) in [
        (context.source_group_seal(), ArtifactGroup::Source),
        (context.native_group_seal(), ArtifactGroup::Native),
    ] {
        let seal = seal.context("construction source/native seal absent")?;
        ensure!(
            seal.permit().group() == group && seal.permit().arena().same_arena(arena),
            "construction seal belongs to another actual arena"
        );
        seal.revalidate()?;
    }
    proof.scope().revalidate()?;
    ensure!(
        proof
            .scope()
            .matches_source_owner(context.source_owner_identity())
            && proof.scope().source_inspection_sha256() == context.inspection_sha256(),
        "construction source/scope owner differs"
    );
    let source_before = context.native().before().clone();
    {
        let (source, _) = context.source_and_inspection();
        ensure!(
            source.freeze_observation().is_some()
                && source.binding() == &proof.scope().pair().source
                && source.state(events)? == source_before
                && source_before.disk_attributes == 3
                && prepared.shadow.binding() == &proof.scope().pair().shadow
                && prepared.shadow.state(events)? == *proof.native().after()
                && proof.native().after().disk_attributes == 3,
            "construction native route or frozen exclusion changed"
        );
    }
    prepared
        .inner
        ._journal
        .revalidate_resource_preparation(&prepared.inner._facts, &prepared.inner.ticket)?;
    ensure!(
        crate::selected_journal::classify(prepared.inner._journal, &prepared.inner.ticket)?
            == crate::selected_journal::SelectedLifecycle::PreparedClear,
        "construction journal is not its original PreparedClear owner"
    );
    prepared.inner._domain.revalidate_with_witness(capture)?;
    frozen.require(prepared)
}

impl ProtectedPreparedJournal<'_, '_, '_, '_, '_> {
    /// Build only independent arena metadata. The witness cannot escape, and
    /// both full frozen/capture closes run even if a producer or checkpoint fails.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_recovery_metadata(
        &mut self,
        expected: &PagedExpectedTree,
        map_group: Option<&ArtifactGroupPermit>,
        map_scratch: &SourceScratch,
        map_path: &Path,
        locator_group: &ArtifactGroupPermit,
        locator_scratch: &SourceScratch,
        locator_path: &Path,
        events: &mut Vec<n2r_win32::NativeEvent>,
        mut checkpoint_events: impl FnMut(&'static str, &mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
    ) -> Result<(
        Option<V4RecoveryMaps>,
        super::super::durable_anchor::DurableRecoveryLocator,
    )> {
        self.require_arena(locator_group)?;
        ensure!(
            locator_group.group() == ArtifactGroup::RecoveryCopy
                && expected_requires_maps(expected, self.context.report().policy)?
                    == map_group.is_some(),
            "construction recovery groups differ from actual expected streams"
        );
        let mut phase = if map_group.is_some() {
            "recovery-map-publication"
        } else {
            "durable-locator"
        };
        checkpoint_native_events(events, &mut |batch| checkpoint_events(phase, batch))?;
        let capture = self.candidate.protected_proof().captured();
        let result = capture.with_revalidation(|capture_witness| {
            with_frozen_preparation_revalidation(
                self,
                capture_witness,
                events,
                |frozen, prepared, events| {
                    let result = (|| {
                        let maps = if let Some(group) = map_group {
                            prepared.require_arena(group)?;
                            let maps = V4RecoveryMaps::create(
                                prepared.candidate.protected_proof(),
                                expected,
                                prepared.context,
                                prepared.inner._domain,
                                &prepared.inner.ticket,
                                group,
                                map_scratch,
                                map_path,
                            )?;
                            let _map_seal = group.seal()?;
                            Some(maps)
                        } else {
                            None
                        };
                        if let Some(maps) = &maps {
                            require_construction_owners(frozen, prepared, capture_witness, events)?;
                            maps.require_binding(
                                prepared.candidate.protected_proof(), expected, prepared.context,
                                prepared.inner._domain, &prepared.inner.ticket,
                            )?;
                            checkpoint_native_events(events, &mut |batch| {
                                checkpoint_events(phase, batch)
                            })?;
                            phase = "durable-locator";
                            require_construction_owners(frozen, prepared, capture_witness, events)?;
                        }
                        let mut locator = super::super::durable_anchor::DurableRecoveryLocator::create_with_frozen_witness(
                            prepared, frozen, locator_group, locator_scratch, locator_path,
                        )?;
                        locator.revalidate()?;
                        frozen.require(prepared)?;
                        Ok((maps, locator))
                    })();
                    // Drain bounded native records on failures too, before the
                    // closing source/target observations need their own batch.
                    let drained = checkpoint_native_events(events, &mut |batch| {
                        checkpoint_events(phase, batch)
                    });
                    finish_readonly_boundary(result, drained)
                },
            )
        });
        let result = finish_readonly_boundary(result, capture.revalidate());
        let drained =
            checkpoint_native_events(events, &mut |batch| checkpoint_events(phase, batch));
        finish_readonly_boundary(result, drained)
    }
}

/// Preserve all native/identity/lifecycle, expected/map, artifact and journal
/// checks between the exact frozen-owner opening and closing byte scans.
fn require_owners_between_frozen_checks(
    frozen: &FrozenPreparedWitness<'_>,
    prepared: &mut ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
    expected: &PagedExpectedTree,
    maps: Option<&V4RecoveryMaps>,
    locator: &mut super::super::durable_anchor::DurableRecoveryLocator,
    journal_receipt: Option<&super::super::reopen::PreparedJournalIndex>,
    _events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    frozen.require(prepared)?;
    let context = &prepared.context;
    context.require_source_evidence()?;
    let admission = context.resource_admission();
    let arena = context.arena().context("prepared source arena absent")?;
    ensure!(
        arena.budget() == admission.budget,
        "prepared arena admission differs"
    );
    for (seal, group) in [
        (context.source_group_seal(), ArtifactGroup::Source),
        (context.native_group_seal(), ArtifactGroup::Native),
    ] {
        let seal = seal.context("actual source/native resource seal absent")?;
        ensure!(
            seal.permit().group() == group && seal.permit().arena().same_arena(arena),
            "source/native seal belongs to a different actual resource owner"
        );
        seal.revalidate()?;
    }
    expected.require_resource_owner(admission)?;
    expected.require_shared_memory(arena)?;
    let proof = prepared.candidate.protected_proof();
    ensure!(
        proof.scope().source_inspection_sha256() == context.inspection_sha256()
            && proof.scope().expected_tree_sha256() == expected.semantic_sha256()
            && proof
                .scope()
                .matches_source_owner(context.source_owner_identity())
            && proof
                .native()
                .report()
                .native()
                .retained_rows_ram_accounted()
            && proof.native().report().native().resource_profile
                == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                    Some(admission)
                )),
        "prepared target/expected/source or actual native report resource owner differs"
    );
    ensure!(
        expected_requires_maps(expected, context.report().policy)? == maps.is_some(),
        "extent-only expected streams require their complete actual recovery map owner"
    );
    if let Some(maps) = maps {
        maps.require_binding(
            proof,
            expected,
            context,
            prepared.inner._domain,
            &prepared.inner.ticket,
        )?;
    }
    locator.revalidate()?;
    let facts = &prepared.inner._facts;
    ensure!(
        locator.source() == facts.source
            && locator.journal_binding() == facts.binding
            && locator.journal_identity() == *facts.identity
            && locator.journal_path() == facts.path
            && same_ticket(locator.ticket(), &prepared.inner.ticket)?,
        "published locator is not the original actual prepared native journal/ticket"
    );
    if let Some(receipt) = journal_receipt {
        // The earlier complete scan produced this actual held index and
        // sealed the same native journal body against ordinary writes. A
        // separate raw alias is still possible, so the SDK rehashes the full
        // body on BOTH sides of the actual source-OLD activation boundary.
        receipt.require_same_sealed_journal(prepared.inner._journal, &prepared.inner.ticket)?;
    } else {
        // Before the live receipt exists, retain the complete original
        // payload/descriptor/COPY readback at each publication boundary.
        let _memory = prepared
            .inner
            ._domain
            .scratch
            .lease_ram(12 * BUFFER as u64)?;
        let mut buffer = vec![0; BUFFER];
        let mut compare = vec![0; BUFFER];
        let (immutable, _) = validate_readback(
            prepared.inner._domain,
            prepared.inner._journal,
            &prepared.inner.ticket,
            &mut buffer,
            &mut compare,
        )?;
        ensure!(
            immutable == prepared.inner.ticket.immutable_sha256,
            "prepared journal immutable bytes changed before qualification"
        );
    }
    frozen.require(prepared)
}

#[allow(clippy::too_many_arguments)]
fn require_published_between_frozen_checks(
    frozen: &FrozenPreparedWitness<'_>,
    prepared: &mut ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
    expected: &PagedExpectedTree,
    maps: Option<&V4RecoveryMaps>,
    locator: &mut super::super::durable_anchor::DurableRecoveryLocator,
    publication: &ArtifactLease,
    checksum: &ArtifactLease,
    journal_receipt: Option<&super::super::reopen::PreparedJournalIndex>,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    frozen.require(prepared)?;
    publication.revalidate()?;
    checksum.revalidate()?;
    prepared.context.require_preparation_delegated(
        Path::new(&publication.snapshot().final_path),
        publication.sha256(),
        events,
    )?;
    if let Some(index) = journal_receipt {
        index.require_ticket(&prepared.inner.ticket)?;
    }
    require_owners_between_frozen_checks(
        frozen,
        prepared,
        expected,
        maps,
        locator,
        journal_receipt,
        events,
    )
}

fn save_publication(
    group: &ArtifactGroupPermit,
    path: &Path,
    value: &impl Serialize,
    maximum: u64,
) -> Result<(ArtifactLease, ArtifactLease)> {
    let (bytes, digest) = serialization_pin(value, maximum)?;
    let permit = group.reserve_file(path, bytes)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(permit.path())?;
    {
        let mut writer = BufWriter::with_capacity(65536, &mut file);
        serde_json::to_writer(&mut writer, value)?;
        writer.flush()?;
    }
    file.sync_all()?;
    drop(file);
    let artifact = permit.verify_closed(&hex::encode(digest))?;
    ensure!(artifact.wire_bytes() == bytes, "publication length changed");
    let leaf = path
        .file_name()
        .context("publication filename absent")?
        .to_str()
        .context("Unicode publication filename required")?;
    let checksum_path = path.with_file_name(format!("{leaf}.sha256"));
    let checksum_bytes = format!("{}\n", artifact.sha256());
    let checksum_permit = group.reserve_file(&checksum_path, checksum_bytes.len() as u64)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(checksum_permit.path())?;
    file.write_all(checksum_bytes.as_bytes())?;
    file.sync_all()?;
    drop(file);
    let checksum =
        checksum_permit.verify_closed(&hex::encode(Sha256::digest(checksum_bytes.as_bytes())))?;
    Ok((artifact, checksum))
}

impl<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>
    ResourcePreparedConversion<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>
{
    /// Publish before closing the arena. All ordinary artifacts and the actual
    /// fixed-EOF journal must then close together, so this constructor fails
    /// while any creation, missing owner, or accounting obligation remains.
    pub(crate) fn publish(
        mut prepared: ProtectedPreparedJournal<'journal, 'domain, 'capture, 'proof, 'scope>,
        expected: &'expected PagedExpectedTree,
        maps: Option<V4RecoveryMaps>,
        mut locator: super::super::durable_anchor::DurableRecoveryLocator,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
        events: &mut Vec<n2r_win32::NativeEvent>,
        mut checkpoint_events: impl FnMut(&mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
    ) -> Result<Self> {
        prepared.require_arena(group)?;
        let scratch_group = scratch
            .artifact_group()
            .context("publication scratch is not arena-owned")?;
        ensure!(
            group.group() == ArtifactGroup::RecoveryCopy
                && scratch_group.group() == group.group()
                && scratch_group.arena().same_arena(group.arena()),
            "publication must use the actual recovery-copy arena group"
        );
        let arena = group.arena().clone();
        // The retained strings come from Windows volume-GUID paths (32K UTF16
        // units maximum). This also prepays the 64KiB streaming writer and
        // small scalar JSON/hash/checksum work before any path copy or IO.
        let memory = arena.reserve_ram(1024 * 1024)?;
        // Each owner check can issue dozens of native controls, while the
        // native event vector has a fixed 128-event limit. Stream complete
        // batches between checks; the caller must preserve them before it
        // clears the vector. This stream is not recovery authority.
        if !events.is_empty() {
            checkpoint_events(events)?;
            ensure!(events.is_empty(), "native event checkpoint did not drain");
        }
        // Only independent recovery-copy files are written here. Keep both
        // complete owner/journal checks inside one non-escaping frozen
        // source/target boundary, with full capture checks at its bookends.
        let capture = prepared.candidate.protected_proof().captured();
        let publication_result = capture.with_revalidation(|capture_witness| {
            with_frozen_preparation_revalidation(
                &mut prepared,
                capture_witness,
                events,
                |frozen, prepared, events| {
                    let result = (|| {
                        require_owners_between_frozen_checks(
                            frozen,
                            prepared,
                            expected,
                            maps.as_ref(),
                            &mut locator,
                            None,
                            events,
                        )?;
                        checkpoint_native_events(events, &mut checkpoint_events)?;
                        let expected_path = expected.final_path();
                        let map_path = maps
                            .as_ref()
                            .map(|m| m.artifact_lease().snapshot().final_path.as_str());
                        let context = &prepared.context;
                        let locator_sha = hex::encode(locator.external_sha256());
                        let publication = Publication {
                            schema_version: 1,
                            kind: "resource-allocation-recovery-envelope-v1",
                            source: prepared.inner._facts.source,
                            shadow: prepared.inner._facts.shadow,
                            resource_admission: context.resource_admission(),
                            verification_policy: context.report().policy,
                            source_fingerprint_kind: context.fingerprint().kind(),
                            source_sha256: context.source_sha256(),
                            source_inspection_sha256: context.inspection_sha256(),
                            source_views_sha256: context.source_views_sha256(),
                            locator: FilePin {
                                path: &locator.snapshot().final_path,
                                sha256: &locator_sha,
                                bytes: locator.snapshot().file_bytes,
                            },
                            expected: ExpectedPin {
                                file: FilePin {
                                    path: &expected_path,
                                    sha256: expected.file_sha256(),
                                    bytes: expected.byte_len(),
                                },
                                semantic_sha256: expected.semantic_sha256(),
                                objects: expected.len() as u64,
                            },
                            recovery_maps: maps.as_ref().zip(map_path).map(|(m, p)| MapPin {
                                file: FilePin {
                                    path: p,
                                    sha256: m.sha256(),
                                    bytes: m.bytes(),
                                },
                                records: m.records(),
                            }),
                            // Older publications may omit this guard; fresh
                            // preparation must retain its actual runtime pin.
                            early_preparation_guard: Some(
                                context.early_preparation_guard_pin().context(
                                    "fresh publication has no original preparation guard",
                                )?,
                            ),
                            ticket_sha256: hex::encode(
                                serialization_pin(&prepared.inner.ticket, 4096)?.1,
                            ),
                            expected_mount_paths: &context.mount_paths().paths,
                            expected_source_label: context.expected_label(),
                            serialized_publication_grants_authority: false,
                        };
                        let artifacts = save_publication(
                            group,
                            path,
                            &publication,
                            scratch.budget().record_bytes,
                        )?;
                        require_owners_between_frozen_checks(
                            frozen,
                            prepared,
                            expected,
                            maps.as_ref(),
                            &mut locator,
                            None,
                            events,
                        )?;
                        Ok(artifacts)
                    })();
                    // Closing source/device observations need their bounded
                    // event batch even when publication or an owner check fails.
                    let drained = checkpoint_native_events(events, &mut checkpoint_events);
                    finish_readonly_boundary(result, drained)
                },
            )
        });
        // A raw alias is not excluded by held ordinary files. Rehash the full
        // original capture after both success and failure before releasing leases.
        let (publication, checksum) =
            finish_readonly_boundary(publication_result, capture.revalidate())?;
        checkpoint_native_events(events, &mut checkpoint_events)?;
        let write_index = if prepared.inner.ticket.marker_profile.is_none() {
            let index_path = path.with_extension("write-index");
            let index_bytes = u64::from(prepared.inner.ticket.range_count)
                .checked_mul(32)
                .and_then(|n| n.checked_add(128 + 64))
                .context("fresh native write index size overflow")?;
            Some(
                super::super::reopen::JournalObservation::open(
                    prepared.inner._journal,
                    &prepared.inner.ticket,
                    group,
                    scratch,
                    &index_path,
                    index_bytes,
                )?
                .into_prepared_index()?,
            )
        } else {
            // Preserve the existing explicit lab marker diagnostic; it does
            // not gain a fresh writer from the markerless SDK transition.
            None
        };
        // Retire pre-AP cancellation before the arena closes and before any
        // public or diagnostic path can obtain a fresh apply issuer. Bind the
        // actual volume-GUID route, so later drive-letter changes cannot name
        // a different publication. This syncs and checks both real state copies.
        prepared.context.delegate_preparation_guard(
            Path::new(&publication.snapshot().final_path),
            publication.sha256(),
            events,
        )?;
        checkpoint_events(events)?;
        ensure!(events.is_empty(), "native event checkpoint did not drain");
        // All recovery producers ran above. No future ordinary artifact
        // writes/reservations/retirement may be accepted through this closure.
        let closure = arena.close_prepared(prepared.inner._facts.journal_quota)?;
        let mut result = Self {
            prepared,
            expected,
            maps,
            locator,
            publication,
            checksum,
            write_index,
            closure,
            _memory: memory,
        };
        result.revalidate(events)?;
        checkpoint_events(events)?;
        ensure!(events.is_empty(), "native event checkpoint did not drain");
        Ok(result)
    }

    pub(crate) fn revalidate(&mut self, events: &mut Vec<n2r_win32::NativeEvent>) -> Result<()> {
        self.closure.with_revalidation(|arena| {
            self.publication.revalidate()?;
            self.checksum.revalidate()?;
            self.prepared.context.require_preparation_delegated(
                Path::new(&self.publication.snapshot().final_path),
                self.publication.sha256(),
                events,
            )?;
            if let Some(index) = &self.write_index {
                index.require_ticket(&self.prepared.inner.ticket)?;
            }
            require_owners(
                &mut self.prepared,
                self.expected,
                self.maps.as_ref(),
                &mut self.locator,
                self.write_index.as_ref(),
                Some(arena),
                events,
            )
        })
    }

    /// Consume the published preparation once. Only the original live source
    /// and actual same-tree target/arena closure can construct this issuer.
    pub(crate) fn into_fresh_apply(
        mut self,
        events: &mut Vec<n2r_win32::NativeEvent>,
        mut checkpoint_events: impl FnMut(&mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
    ) -> Result<ResourceFreshApply<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>> {
        checkpoint_native_events(events, &mut checkpoint_events)?;
        // Admission is one immediate read-only operation. Keep exhaustive
        // arena/capture and frozen source/target checks on BOTH sides of the
        // whole operation instead of nesting two complete before/after scans.
        // The non-escaping witness binds the exact original live owners; only
        // the final successful close releases the owned admission result.
        let admission = self.closure.with_revalidation(|arena| {
            let capture = self.prepared.candidate.protected_proof().captured();
            capture.with_arena_revalidation(arena, |capture_witness| {
                with_frozen_preparation_revalidation(
                    &mut self.prepared,
                    capture_witness,
                    events,
                    |frozen, prepared, events| {
                        let result = (|| {
                            require_published_between_frozen_checks(
                                frozen, prepared, self.expected, self.maps.as_ref(),
                                &mut self.locator, &self.publication, &self.checksum,
                                self.write_index.as_ref(), events,
                            )?;
                            checkpoint_native_events(events, &mut checkpoint_events)?;
                            ensure!(
                                prepared.inner.ticket.marker_profile.is_none()
                                    && self.write_index.is_some(),
                                "fresh resource apply requires the actual prepared markerless write index"
                            );
                            frozen.require(prepared)?;
                            let admission = prepared.context.qualify_prepared_target(
                                prepared.candidate.protected_proof(),
                                self.expected,
                                &self.closure,
                                events,
                            )?;
                            checkpoint_native_events(events, &mut checkpoint_events)?;
                            admission.require_binding(
                                prepared.context,
                                prepared.candidate.protected_proof(),
                                self.expected,
                                &self.closure,
                            )?;
                            require_published_between_frozen_checks(
                                frozen, prepared, self.expected, self.maps.as_ref(),
                                &mut self.locator, &self.publication, &self.checksum,
                                self.write_index.as_ref(), events,
                            )?;
                            Ok(admission)
                        })();
                        // Drain even a failed callback before the closing
                        // source/device observations need their bounded batch.
                        let drained = checkpoint_native_events(events, &mut checkpoint_events);
                        match (result, drained) {
                            (Ok(admission), Ok(())) => Ok(admission),
                            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
                            (Err(error), Err(drain)) => Err(error.context(format!(
                                "read-only admission native-event checkpoint also failed: {drain:#}"
                            ))),
                        }
                    },
                )
            })
        })?;
        checkpoint_native_events(events, &mut checkpoint_events)?;
        // ResourceFreshApply still performs its separate full revalidation,
        // and the SDK independently proves OLD bytes/journal identity/body on
        // both sides of its actual AP transition before any source write.
        Ok(ResourceFreshApply::new(self, admission))
    }

    pub(crate) fn publication_path(&self) -> &Path {
        self.publication.path()
    }
    /// Save this checksum independently for later recovery. It is not source,
    /// writer or replay authorization and cannot recreate this live owner.
    pub(crate) fn publication_sha256(&self) -> &str {
        self.publication.sha256()
    }
    pub(crate) fn locator_sha256(&self) -> [u8; 32] {
        self.locator.external_sha256()
    }
}
