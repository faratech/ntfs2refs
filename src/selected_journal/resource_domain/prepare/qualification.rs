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
pub(crate) use apply::{ResourceAppliedConversion, ResourceFreshApply};

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
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    let capture = prepared.candidate.protected_proof().captured();
    // Bracket this entire read-only owner and journal check with the same
    // capture's complete content hash. Nested source/target/lifecycle checks
    // reuse this non-escaping witness; none gains write authority from it.
    capture.with_revalidation(|witness| {
        require_owners_with_capture_witness(prepared, expected, maps, locator, journal_receipt, witness, events)
    })?;
    // Ordinary share-zero handles do not rule out raw/admin aliases. Hash the
    // capture again after all nested checks, retaining the prior boundary.
    capture.revalidate()
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
    prepared.revalidate_with_capture_witness(witness, events)?;
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
        let _memory = prepared.inner._domain.scratch.lease_ram(12 * BUFFER as u64)?;
        let mut buffer = vec![0; BUFFER];
        let mut compare = vec![0; BUFFER];
        let (immutable, _) = validate_readback(
            prepared.inner._domain, prepared.inner._journal, &prepared.inner.ticket,
            &mut buffer, &mut compare,
        )?;
        ensure!(immutable == prepared.inner.ticket.immutable_sha256,
            "prepared journal immutable bytes changed before qualification");
    }
    prepared.revalidate_with_capture_witness(witness, events)
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
        require_owners(&mut prepared, expected, maps.as_ref(), &mut locator, None, events)?;
        checkpoint_events(events)?;
        ensure!(events.is_empty(), "native event checkpoint did not drain");
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
            ticket_sha256: hex::encode(serialization_pin(&prepared.inner.ticket, 4096)?.1),
            expected_mount_paths: &context.mount_paths().paths,
            expected_source_label: context.expected_label(),
            serialized_publication_grants_authority: false,
        };
        let (publication, checksum) =
            save_publication(group, path, &publication, scratch.budget().record_bytes)?;
        require_owners(&mut prepared, expected, maps.as_ref(), &mut locator, None, events)?;
        checkpoint_events(events)?;
        ensure!(events.is_empty(), "native event checkpoint did not drain");
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
        self.closure.revalidate()?;
        self.publication.revalidate()?;
        self.checksum.revalidate()?;
        if let Some(index) = &self.write_index {
            index.require_ticket(&self.prepared.inner.ticket)?;
        }
        require_owners(
            &mut self.prepared,
            self.expected,
            self.maps.as_ref(),
            &mut self.locator,
            self.write_index.as_ref(),
            events,
        )?;
        self.closure.revalidate()
    }

    /// Consume the published preparation once. Only the original live source
    /// and actual same-tree target/arena closure can construct this issuer.
    pub(crate) fn into_fresh_apply(
        mut self,
        events: &mut Vec<n2r_win32::NativeEvent>,
        mut checkpoint_events: impl FnMut(&mut Vec<n2r_win32::NativeEvent>) -> Result<()>,
    ) -> Result<ResourceFreshApply<'journal, 'domain, 'capture, 'proof, 'scope, 'expected>> {
        checkpoint_native_events(events, &mut checkpoint_events)?;
        self.revalidate(events)?;
        checkpoint_native_events(events, &mut checkpoint_events)?;
        ensure!(
            self.prepared.inner.ticket.marker_profile.is_none() && self.write_index.is_some(),
            "fresh resource apply requires the actual prepared markerless write index"
        );
        let admission = self.prepared.context.qualify_prepared_target(
            self.prepared.candidate.protected_proof(),
            self.expected,
            &self.closure,
            events,
        )?;
        checkpoint_native_events(events, &mut checkpoint_events)?;
        admission.require_binding(
            self.prepared.context,
            self.prepared.candidate.protected_proof(),
            self.expected,
            &self.closure,
        )?;
        self.revalidate(events)?;
        checkpoint_native_events(events, &mut checkpoint_events)?;
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
