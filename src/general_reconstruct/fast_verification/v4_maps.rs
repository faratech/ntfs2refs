//! Ordinal-keyed recovery-map observations from actual protected V4 owners.
//! This diagnostic artifact is not a legacy map, source certificate, ticket,
//! replay authority or a constructor for any of those capabilities.
pub(crate) mod comparator;
pub(crate) mod reopened;
use super::*;
use crate::{
    artifact_arena::{
        ArenaRamLease, ArtifactGroup, ArtifactGroupPermit, ArtifactGroupSeal, ArtifactLease,
    },
    general_composite_target::paged::{CaptureScopeIdentity, ProtectedPagedTargetSelection},
    general_source_admission::resource::ResourceSourceContext,
    ntfs_inspect::paged_storage::SourceScratch,
    selected_journal::{SelectedTicket, resource_domain::ResourceJournalDomain},
    shadow_tree::{PagedExpectedTree, SourceStreamEvidence},
};
use serde::Serialize;

const PURPOSE: [u8; 8] = *b"N2RMAPV4";

#[derive(Serialize)]
struct Header<'a> {
    schema_version: u32,
    kind: &'static str,
    source: &'a n2r_win32::general_layout::GeneralDiskBinding,
    shadow: &'a n2r_win32::general_layout::GeneralDiskBinding,
    native_base_sectors: u64,
    source_sha256: &'a str,
    source_inspection_sha256: &'a str,
    source_views_sha256: &'a str,
    expected_tree_sha256: &'a str,
    ticket_sha256: &'a str,
    selected_bytes: u64,
    journal_length: u64,
    range_count: u32,
    native_bindings: u64,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
    grants_write_authority: bool,
}

/// The reader, actual immutable artifact, scope token and RAM reservation all
/// remain live together. No pin, JSON or persisted file can construct this.
pub(crate) struct V4RecoveryMaps {
    reader: RefCell<metadata_pages::Reader>,
    artifact: ArtifactLease,
    scope: Arc<CaptureScopeIdentity>,
    expected_owner: ArtifactLease,
    source_owner: ArtifactGroupSeal,
    domain_owner: ArtifactLease,
    source_sha256: String,
    source_inspection_sha256: String,
    source_views_sha256: String,
    expected_sha256: String,
    ticket_sha256: String,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
    records: u64,
    _ram: ArenaRamLease,
}

fn key(object: usize, stream: usize) -> Result<[u8; 16]> {
    let object = u64::try_from(object)?
        .checked_add(1)
        .context("map object key overflow")?;
    let stream = u64::try_from(stream)?;
    let mut key = [0; 16];
    key[..8].copy_from_slice(&object.to_be_bytes());
    key[8..].copy_from_slice(&stream.to_be_bytes());
    Ok(key)
}

enum MapSourceContext<'a> {
    Dedicated(&'a ResourceSourceContext),
    Partition(
        &'a crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
    ),
}
struct MapSourceReport<'a> {
    binding: &'a n2r_win32::general_layout::GeneralDiskBinding,
    source_sha256: &'a str,
    source_inspection_sha256: &'a str,
    source_views_sha256: &'a str,
}
impl MapSourceContext<'_> {
    fn require_source_evidence(&self) -> Result<()> {
        match self {
            Self::Dedicated(c) => c.require_source_evidence(),
            Self::Partition(c) => c.require_source_evidence(),
        }
    }
    fn report(&self) -> MapSourceReport<'_> {
        match self {
            Self::Dedicated(c) => {
                let r = c.report();
                MapSourceReport {
                    binding: r.binding,
                    source_sha256: r.source_sha256,
                    source_inspection_sha256: r.source_inspection_sha256,
                    source_views_sha256: r.source_views_sha256,
                }
            }
            Self::Partition(c) => MapSourceReport {
                binding: &c.binding().storage,
                source_sha256: c.source_sha256(),
                source_inspection_sha256: c.inspection_sha256(),
                source_views_sha256: c.source_views_sha256(),
            },
        }
    }
    fn resource_admission(&self) -> n2r_win32::tree_resources::SourceResourceAdmission {
        match self {
            Self::Dedicated(c) => c.resource_admission(),
            Self::Partition(c) => c.resource_admission(),
        }
    }
    fn arena(&self) -> Option<&crate::artifact_arena::ArtifactArena> {
        match self {
            Self::Dedicated(c) => c.arena(),
            Self::Partition(c) => Some(c.arena()),
        }
    }
    fn source_group_seal(&self) -> Option<&ArtifactGroupSeal> {
        match self {
            Self::Dedicated(c) => c.source_group_seal(),
            Self::Partition(c) => Some(c.source_group_seal()),
        }
    }
    fn source_owner_identity(&self) -> usize {
        match self {
            Self::Dedicated(c) => c.source_owner_identity(),
            Self::Partition(c) => c.source_owner_identity(),
        }
    }
    fn require_native_source(&self, proof: &ProtectedPagedTargetSelection) -> Result<()> {
        if let Self::Partition(c) = self {
            proof
                .native()
                .require_partition_source_owner(&c.owner_token())?;
        }
        Ok(())
    }
}

fn check_binding(
    proof: &ProtectedPagedTargetSelection,
    expected: &PagedExpectedTree,
    context: &MapSourceContext<'_>,
    domain: &ResourceJournalDomain<'_>,
    ticket: &SelectedTicket,
) -> Result<()> {
    context.require_source_evidence()?;
    context.require_native_source(proof)?;
    let report = context.report();
    let facts = domain.facts();
    let admission = context.resource_admission();
    expected.require_resource_owner(admission)?;
    let arena = context.arena().context("map needs actual source arena")?;
    expected.require_shared_memory(arena)?;
    ensure!(
        expected.artifact_lease().is_some() && context.source_group_seal().is_some(),
        "V4 map requires actual held expected and source owners"
    );
    ensure!(
        std::ptr::eq(domain.capture(), proof.captured())
            && proof.captured().is_for_scope(proof.scope())
            && proof
                .scope()
                .matches_source_owner(context.source_owner_identity())
            && proof.scope().expected_tree_sha256() == expected.semantic_sha256()
            && proof.scope().source_inspection_sha256() == report.source_inspection_sha256
            && report.binding == &proof.scope().pair().source
            && proof.native().before() == proof.native().after()
            && proof.native().before().disk_attributes == 3
            && proof.native().observed_readonly().disk_attributes == 2
            && proof.native().report().pair() == proof.scope().pair()
            && proof.native().report().native().resource_profile
                == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                    Some(admission)
                ))
            && facts.image_length == report.binding.identity.partition_bytes
            && ticket.image_length == facts.image_length
            && ticket.selected_bytes == facts.selected_bytes
            && ticket.range_count == facts.range_count
            && ticket.journal_length == facts.journal_length
            && ticket.marker_profile == facts.marker_profile
            && !ticket.whole_image_verified,
        "V4 map does not bind the actual protected target/source/journal owners"
    );
    proof.scope().revalidate()?;
    // A map contains protected native metadata and ticket facts, not literal
    // payload bytes. The prepared journal owner performs the full capture
    // content check at its before/after boundaries; this metadata-only pass
    // still rechecks every live journal-index/layout row and capture identity.
    domain.revalidate_layout_only()?;
    Ok(())
}

/// Visit in original native-object order, verifying the exact held expected
/// identities and preserving every directory, unnamed and named stream. The
/// output's ordinal keys are deliberately distinct from legacy path keys.
fn visit(
    proof: &ProtectedPagedTargetSelection,
    expected: &PagedExpectedTree,
    mut emit: impl FnMut([u8; 16], &MapEntryRef<'_>) -> Result<()>,
) -> Result<u64> {
    let report = proof.native().report().native();
    ensure!(
        report.objects.len() == expected.len(),
        "V4 map object coverage differs"
    );
    let admission = expected
        .header()
        .resource_admission
        .context("map admission absent")?;
    let mut count = 0u64;
    report.objects.try_for_each(|index, native| -> Result<()> {
        let object = expected.object_leased(index)?;
        ensure!(
            native.components == object.path
                && native.before == native.after
                && native.named_streams.len() == object.named_streams.len(),
            "V4 map native object identity/coverage differs"
        );
        for ordinal in 0..=native.named_streams.len() {
            let named = ordinal.checked_sub(1);
            if let Some(i) = named {
                let actual = &native.named_streams[i];
                ensure!(
                    !actual.name_utf16.is_empty()
                        && actual.before == actual.after
                        && !native.named_streams[..i]
                            .iter()
                            .any(|s| s.name_utf16 == actual.name_utf16)
                        && object
                            .named_streams
                            .iter()
                            .filter(|s| s.name_utf16 == actual.name_utf16)
                            .count()
                            == 1,
                    "V4 named map identity/uniqueness differs"
                );
            }
            let location = StreamLocation {
                object: index,
                named,
            };
            location.view(report, |(components, name_utf16), map| {
                if let Some(stream) = object.stream(name_utf16)
                    && stream.source_evidence
                        == Some(SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
                {
                    let residual = proof
                        .native()
                        .report()
                        .residual_for(index, name_utf16)?
                        .context("V4 extent tail protected observation absent")?;
                    ensure!(
                        proof.native().report().residual_contents_verified()
                            && residual.logical_offset
                                == n2r_win32::target_cluster::floor(stream.length)
                            && residual.length
                                == stream.length % n2r_win32::target_cluster::bytes()
                            && residual.sha256.len() == 64,
                        "V4 extent tail verification differs"
                    );
                }
                let entry = MapEntryRef {
                    components,
                    name_utf16,
                    map: PagedStreamMapRef::with_resources(map, Some(admission))?,
                };
                let size = row_size(&entry, admission.budget.max_row_bytes)?;
                validate_borrowed_row_memory(&entry, size, admission.budget.max_row_bytes)?;
                emit(key(index, ordinal)?, &entry)
            })?;
            count = count.checked_add(1).context("V4 binding count overflow")?;
        }
        Ok(())
    })?;
    Ok(count)
}

struct HashSink {
    hash: Sha256,
    bytes: u64,
}

// A conservative one-page-per-record upper bound. The format header/footer,
// page frames and index entries all fit this bound even when records happen
// to share pages. It avoids reserving the whole map quota for a small map.
fn projected_record_bytes(payload_bytes: u64, key_bytes: u64) -> Result<u64> {
    payload_bytes
        .checked_add(key_bytes)
        .and_then(|n| n.checked_add(8 + 128))
        .context("V4 map projected record overflow")
}

fn projected_chunk_bytes(raw: u64, key_bytes: u64) -> Result<u64> {
    let encoded = raw
        .checked_add(2)
        .and_then(|n| n.checked_div(3))
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_add(2))
        .context("V4 map encoded chunk overflow")?;
    projected_record_bytes(
        encoded,
        key_bytes.checked_add(8).context("V4 chunk key overflow")?,
    )
}
impl Write for HashSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("V4 map hash length overflow"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl V4RecoveryMaps {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create(
        proof: &ProtectedPagedTargetSelection,
        expected: &PagedExpectedTree,
        context: &ResourceSourceContext,
        domain: &ResourceJournalDomain<'_>,
        ticket: &SelectedTicket,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
    ) -> Result<Self> {
        Self::create_scoped(
            proof,
            expected,
            &MapSourceContext::Dedicated(context),
            domain,
            ticket,
            group,
            scratch,
            path,
        )
    }
    pub(crate) fn create_partition(
        proof: &ProtectedPagedTargetSelection,
        expected: &PagedExpectedTree,
        context: &crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        domain: &ResourceJournalDomain<'_>,
        ticket: &SelectedTicket,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
    ) -> Result<Self> {
        Self::create_scoped(
            proof,
            expected,
            &MapSourceContext::Partition(context),
            domain,
            ticket,
            group,
            scratch,
            path,
        )
    }
    fn create_scoped(
        proof: &ProtectedPagedTargetSelection,
        expected: &PagedExpectedTree,
        context: &MapSourceContext<'_>,
        domain: &ResourceJournalDomain<'_>,
        ticket: &SelectedTicket,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
    ) -> Result<Self> {
        check_binding(proof, expected, context, domain, ticket)?;
        let arena = context.arena().context("map needs actual source arena")?;
        ensure!(
            group.group() == ArtifactGroup::Map
                && group.arena().same_arena(arena)
                && scratch
                    .artifact_group()
                    .is_some_and(|s| s.arena().same_arena(arena)),
            "V4 map artifact/scratch are not on the actual source arena"
        );
        let admission = context.resource_admission();
        let budget = admission.map_page_budget()?;
        let workspace = u64::from(budget.max_page_bytes)
            .checked_mul(8)
            .and_then(|n| n.checked_add(admission.budget.max_row_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .context("V4 map RAM overflow")?;
        let mut ram = arena.reserve_ram(workspace)?;
        let report = context.report();
        let source_sha256 = report.source_sha256.to_owned();
        let source_inspection_sha256 = report.source_inspection_sha256.to_owned();
        let source_views_sha256 = report.source_views_sha256.to_owned();
        let expected_sha256 = expected.semantic_sha256().to_owned();
        let ticket_sha256 = canonical_json_sha256(ticket)?;
        let mut bindings = Some(0u64);
        proof
            .native()
            .report()
            .native()
            .objects
            .for_each(|_, object| {
                bindings = bindings.and_then(|n| {
                    n.checked_add(1)?
                        .checked_add(object.named_streams.len() as u64)
                });
                Ok(())
            })?;
        let bindings = bindings.context("V4 native binding count overflow")?;
        let header = Header {
            schema_version: 4,
            kind: "protected-v4-ordinal-stream-maps",
            source: report.binding,
            shadow: &proof.scope().pair().shadow,
            native_base_sectors: proof.native().report().native().base_sectors,
            source_sha256: &source_sha256,
            source_inspection_sha256: &source_inspection_sha256,
            source_views_sha256: &source_views_sha256,
            expected_tree_sha256: &expected_sha256,
            ticket_sha256: &ticket_sha256,
            selected_bytes: ticket.selected_bytes,
            journal_length: ticket.journal_length,
            range_count: ticket.range_count,
            native_bindings: bindings,
            admission,
            grants_write_authority: false,
        };
        let encoded_header = record_json(&header)?;
        let mut reserved = 192u64
            .checked_add(projected_record_bytes(encoded_header.len() as u64, 0)?)
            .context("V4 map projected header overflow")?;
        let mut projected_records = 1u64;
        let mut semantic_bytes = 0u64;
        let projected = visit(proof, expected, |key, entry| {
            let mut remaining = row_size(entry, admission.budget.max_row_bytes)?;
            semantic_bytes = semantic_bytes
                .checked_add(remaining)
                .filter(|n| *n <= admission.semantic_byte_budget())
                .context("V4 map semantic bytes exceed admission")?;
            let chunk = chunk_capacity(budget, key.len())? as u64;
            while remaining > 0 {
                let n = remaining.min(chunk);
                reserved = reserved
                    .checked_add(projected_chunk_bytes(n, key.len() as u64)?)
                    .context("V4 map projected size overflow")?;
                projected_records = projected_records
                    .checked_add(1)
                    .context("V4 map record count overflow")?;
                remaining -= n;
            }
            Ok(())
        })?;
        ensure!(
            projected == bindings
                && projected_records <= budget.max_records
                && reserved <= budget.max_file_bytes,
            "V4 map complete projected capacity exceeds the admitted budget"
        );
        let permit = group.reserve_file(path, reserved)?;
        let mut writer = metadata_pages::Writer::new(permit.path(), PURPOSE, budget)?;
        writer.push(&[], &encoded_header)?;
        let count = visit(proof, expected, |key, entry| {
            let mut chunks = MapChunkWriter {
                writer: &mut writer,
                key: &key,
                maximum: chunk_capacity(budget, key.len())?,
                limit: admission.budget.max_row_bytes,
                buffer: Vec::new(),
                chunks: 0,
                bytes: 0,
            };
            serde_json::to_writer(&mut chunks, entry)?;
            if !chunks.buffer.is_empty() {
                chunks.emit()?;
            }
            ensure!(chunks.chunks > 0, "V4 map row empty");
            Ok(())
        })?;
        ensure!(count == bindings, "V4 map native binding count changed");
        let summary = writer.finish()?;
        let artifact = permit.verify_closed(&summary.sha256)?;
        let mut reader =
            metadata_pages::Reader::open(artifact.path(), artifact.sha256(), PURPOSE, budget)?;
        let head = reader.get(0)?;
        ensure!(
            head.key.is_empty() && head.payload == encoded_header,
            "V4 map header readback differs"
        );
        let mut record = 1u64;
        let checked = visit(proof, expected, |key, entry| {
            let mut expected_hash = HashSink {
                hash: Sha256::new(),
                bytes: 0,
            };
            serde_json::to_writer(&mut expected_hash, entry)?;
            ensure!(
                expected_hash.bytes > 0 && expected_hash.bytes <= admission.budget.max_row_bytes,
                "V4 map row readback exceeds limit"
            );
            let expected_digest = expected_hash.hash.finalize();
            let mut hash = Sha256::new();
            let mut bytes = 0u64;
            let mut ordinal = 0u64;
            while bytes < expected_hash.bytes {
                let row = reader.get(record)?;
                ensure!(
                    row.key == chunk_key(&key, ordinal),
                    "V4 map chunk order differs"
                );
                let text: &str = serde_json::from_slice(&row.payload)?;
                let data = decode_base64(text, chunk_capacity(budget, key.len())?)?;
                ensure!(!data.is_empty(), "V4 map chunk cannot be empty");
                bytes = bytes
                    .checked_add(data.len() as u64)
                    .filter(|n| *n <= expected_hash.bytes)
                    .context("V4 map chunk length differs")?;
                hash.update(&data);
                ordinal = ordinal
                    .checked_add(1)
                    .context("V4 map chunk count overflow")?;
                record = record
                    .checked_add(1)
                    .context("V4 map record count overflow")?;
            }
            ensure!(
                hash.finalize() == expected_digest,
                "V4 map native row readback differs"
            );
            Ok(())
        })?;
        ensure!(
            checked == bindings && record == reader.len() && reader.len() == summary.records,
            "V4 map readback coverage differs"
        );
        check_binding(proof, expected, context, domain, ticket)?;
        ram.shrink_to(
            u64::from(budget.max_page_bytes)
                .checked_mul(2)
                .and_then(|n| n.checked_add(65536))
                .context("V4 map retained RAM overflow")?,
        )?;
        Ok(Self {
            reader: RefCell::new(reader),
            artifact,
            scope: proof.scope().capture_identity(),
            expected_owner: expected
                .artifact_lease()
                .context("expected file owner absent")?
                .clone(),
            source_owner: context
                .source_group_seal()
                .context("source group owner absent")?
                .clone(),
            domain_owner: domain.artifact_lease().clone(),
            source_sha256,
            source_inspection_sha256,
            source_views_sha256,
            expected_sha256,
            ticket_sha256,
            admission,
            records: bindings,
            _ram: ram,
        })
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.artifact.revalidate()?;
        self.reader.borrow_mut().revalidate()?;
        Ok(())
    }
    pub(crate) fn require_binding(
        &self,
        proof: &ProtectedPagedTargetSelection,
        expected: &PagedExpectedTree,
        context: &ResourceSourceContext,
        domain: &ResourceJournalDomain<'_>,
        ticket: &SelectedTicket,
    ) -> Result<()> {
        self.require_binding_scoped(
            proof,
            expected,
            &MapSourceContext::Dedicated(context),
            domain,
            ticket,
        )
    }
    pub(crate) fn require_binding_partition(
        &self,
        proof: &ProtectedPagedTargetSelection,
        expected: &PagedExpectedTree,
        context: &crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        domain: &ResourceJournalDomain<'_>,
        ticket: &SelectedTicket,
    ) -> Result<()> {
        self.require_binding_scoped(
            proof,
            expected,
            &MapSourceContext::Partition(context),
            domain,
            ticket,
        )
    }
    fn require_binding_scoped(
        &self,
        proof: &ProtectedPagedTargetSelection,
        expected: &PagedExpectedTree,
        context: &MapSourceContext<'_>,
        domain: &ResourceJournalDomain<'_>,
        ticket: &SelectedTicket,
    ) -> Result<()> {
        check_binding(proof, expected, context, domain, ticket)?;
        let report = context.report();
        ensure!(
            Arc::ptr_eq(&self.scope, &proof.scope().capture_identity())
                && expected
                    .artifact_lease()
                    .is_some_and(|owner| self.expected_owner.same_owner(owner))
                && context
                    .source_group_seal()
                    .is_some_and(|owner| self.source_owner.same_owner(owner))
                && self.domain_owner.same_owner(domain.artifact_lease())
                && self.admission == context.resource_admission()
                && self.source_sha256 == report.source_sha256
                && self.source_inspection_sha256 == report.source_inspection_sha256
                && self.source_views_sha256 == report.source_views_sha256
                && self.expected_sha256 == expected.semantic_sha256()
                && self.ticket_sha256 == canonical_json_sha256(ticket)?,
            "V4 map live owner binding changed"
        );
        self.revalidate()
    }
    pub(crate) fn path(&self) -> &Path {
        self.artifact.path()
    }
    pub(crate) fn artifact_lease(&self) -> &ArtifactLease {
        &self.artifact
    }
    pub(crate) fn sha256(&self) -> &str {
        self.artifact.sha256()
    }
    pub(crate) fn bytes(&self) -> u64 {
        self.artifact.wire_bytes()
    }
    pub(crate) fn records(&self) -> u64 {
        self.records
    }
}

impl V4RecoveryMaps {
    pub(crate) fn compare_terminal_report(
        &self,
        expected: &PagedExpectedTree,
        ticket: &SelectedTicket,
        converted: &shadow_native::GeneralConvertedReport,
    ) -> Result<u64> {
        ensure!(
            expected
                .artifact_lease()
                .is_some_and(|owner| self.expected_owner.same_owner(owner))
                && expected.semantic_sha256() == self.expected_sha256
                && canonical_json_sha256(ticket)? == self.ticket_sha256,
            "V4 diagnostic expected owner or ticket differs"
        );
        expected.require_resource_owner(self.admission)?;
        let arena = self.source_owner.permit().arena();
        expected.require_shared_memory(arena)?;
        // Reader retains its own page lease. Pay independently for decoded
        // chunk copies, their base64 form and one bounded serialized native row.
        let budget = self.admission.map_page_budget()?;
        let bytes = u64::from(budget.max_page_bytes)
            .checked_mul(8)
            .and_then(|n| n.checked_add(self.admission.budget.max_row_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .context("V4 comparator RAM overflow")?;
        let _ram = arena.reserve_ram(bytes)?;
        self.revalidate()?;
        let mut reader = self.reader.borrow_mut();
        let first = reader.get(0)?;
        ensure!(first.key.is_empty(), "V4 map header key differs");
        let header: comparator::Header = serde_json::from_slice(&first.payload)?;
        let report = &converted.native;
        let observation = converted
            .content_observation
            .as_ref()
            .context("converted metadata observation absent")?;
        ensure!(
            header.schema_version == 4
                && header.kind == "protected-v4-ordinal-stream-maps"
                && !header.grants_write_authority
                && header.admission == self.admission
                && header.source_sha256 == self.source_sha256
                && header.source_inspection_sha256 == self.source_inspection_sha256
                && header.source_views_sha256 == self.source_views_sha256
                && header.expected_tree_sha256 == self.expected_sha256
                && header.ticket_sha256 == self.ticket_sha256
                && header.native_bindings == self.records
                && header.selected_bytes == ticket.selected_bytes
                && header.journal_length == ticket.journal_length
                && header.range_count == ticket.range_count
                && converted.pair.source.identity == header.source.identity
                && converted.pair.shadow.identity == header.shadow.identity
                && report.binding.identity == converted.pair.source.identity
                && report.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(self.admission)
                    ))
                && !converted.conversion_qualified
                && !observation.full_file_hashes
                && observation.metadata_and_namespace_verified
                && observation.complete_stream_mappings_observed
                && observation.data_storage_validity_checked,
            "V4 diagnostic header/source/metadata observation differs"
        );
        // The current native observer initializes base_sectors to zero and
        // does not actually query a nonzero retrieval base. Compare LCNs in
        // volume-relative coordinates only under the diagnostic zero-base assumption.
        // In particular, never add either disk's different GPT start offset.
        ensure!(
            header.native_base_sectors == 0 && report.base_sectors == 0,
            "nonzero or unobserved retrieval base requires native normalization evidence"
        );
        ensure!(
            report.objects.len() == expected.len(),
            "V4 converted object coverage differs"
        );
        let bindings = comparator::compare_records(
            &mut reader,
            expected,
            report,
            self.admission,
            self.records,
        )?;
        drop(reader);
        self.revalidate()?;
        Ok(bindings)
    }
}
