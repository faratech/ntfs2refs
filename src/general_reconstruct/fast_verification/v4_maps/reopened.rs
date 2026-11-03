//! Authenticated recovery metadata from an actual excluded HND observation.
//! The file owners prove metadata identity; mounting and native observation
//! remain separate operations on the same live recovery owner.
use super::*;
use crate::selected_journal::resource_domain::reopen::envelope::VerifiedResourceHandoff;
use std::{fs::File, path::Path};

pub(crate) struct ReopenedVerificationMetadata {
    expected: PagedExpectedTree,
    maps: Option<ReopenedMaps>,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
    publication_file: File,
    publication_snapshot: n2r_win32::reference_file::ReferenceFileSnapshot,
    selected_sha256: [u8; 32],
    _arena: crate::artifact_arena::ArtifactArena,
}

pub(crate) struct VerifiedMapComparison<'a> {
    metadata: &'a ReopenedVerificationMetadata,
    observation: &'a n2r_win32::GeneralLiveConvertedObservation,
    bindings: u64,
}
impl VerifiedMapComparison<'_> {
    pub(crate) fn require_same(
        &self,
        protected: &crate::selected_journal::resource_domain::reopen::envelope::VerifiedProtectedHandoff<'_>,
        observation: &n2r_win32::GeneralLiveConvertedObservation,
    ) -> Result<()> {
        let actual = protected.recovery().publication_artifact();
        ensure!(
            std::ptr::eq(self.observation, observation)
                && protected.selected_sha256() == self.metadata.selected_sha256
                && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    actual.file,
                    actual.snapshot.file_bytes,
                )? == self.metadata.publication_snapshot
                && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.metadata.publication_file,
                    self.metadata.publication_snapshot.file_bytes,
                )? == self.metadata.publication_snapshot,
            "map comparison belongs to another actual HND/publication/observation owner"
        );
        Ok(())
    }
    pub(crate) fn bindings(&self) -> u64 {
        self.bindings
    }
}

struct ReopenedMaps {
    reader: RefCell<metadata_pages::Reader>,
    // Keep the exact authenticated file object alive independently of its
    // filename. Reader destruction precedes release of its memory reservation.
    file: File,
    header: comparator::Header,
    _header_ram: ArenaRamLease,
    _ram: ArenaRamLease,
}

impl ReopenedVerificationMetadata {
    pub(crate) fn open(handoff: &VerifiedResourceHandoff<'_>) -> Result<Self> {
        let recovery = handoff.recovery();
        let scratch = recovery.runtime_scratch();
        let group = scratch.artifact_group().context("recovery arena absent")?;
        let arena = group.arena();
        let admission = recovery.resource_admission();
        let publication = recovery.publication_artifact();
        let publication_file = publication.file.try_clone()?;
        let publication_snapshot = publication.snapshot.clone();
        let artifact = recovery.expected_artifact();
        let expected = PagedExpectedTree::open_recovery_with_resources(
            artifact.file,
            artifact.snapshot,
            &hex::encode(artifact.sha256),
            recovery.expected_semantic_sha256(),
            admission,
            arena,
        )?;
        ensure!(
            expected.len() as u64 == recovery.expected_objects(),
            "recovered expected domain count differs"
        );
        let mut needs_maps = false;
        for ordinal in 0..expected.len() {
            let object = expected.object_leased(ordinal)?;
            for stream in object.data_streams() {
                ensure!(
                    stream.sha256.is_some()
                        || (!recovery.verification_policy().is_full_content()
                            && stream.source_evidence.is_some()),
                    "recovered stream has neither a content digest nor admitted extent evidence"
                );
                needs_maps |= stream.source_evidence.is_some();
                ensure!(
                    !recovery.verification_policy().is_full_content() || stream.sha256.is_some(),
                    "full-content recovery lacks an original stream digest"
                );
            }
        }
        let maps = match recovery.map_artifact() {
            Some(artifact) => {
                let budget = admission.map_page_budget()?;
                let bytes = u64::from(budget.max_page_bytes)
                    .checked_mul(8)
                    .and_then(|n| n.checked_add(admission.budget.max_row_bytes))
                    .and_then(|n| n.checked_add(1024 * 1024))
                    .context("recovered map working memory overflow")?;
                let ram = arena.reserve_ram(bytes)?;
                let mut reader = metadata_pages::Reader::open(
                    Path::new(&artifact.snapshot.final_path),
                    &hex::encode(artifact.sha256),
                    PURPOSE,
                    budget,
                )?;
                ensure!(
                    reader.same_file_as(artifact.file)?
                        && reader.byte_len() == artifact.snapshot.file_bytes,
                    "recovered map reader is not the held authenticated artifact"
                );
                let first = reader.get(0)?;
                ensure!(first.key.is_empty(), "recovered map header key differs");
                let header_ram = arena.reserve_ram(
                    (first.payload.len() as u64)
                        .checked_mul(32)
                        .context("recovered map header memory overflow")?,
                )?;
                let header: comparator::Header = serde_json::from_slice(&first.payload)?;
                ensure!(
                    header.schema_version == 4
                        && header.kind == "protected-v4-ordinal-stream-maps"
                        && !header.grants_write_authority
                        && header.source == *recovery.source()
                        && header.shadow == *recovery.shadow()
                        && header.admission == admission
                        && header.source_sha256 == recovery.source_sha256()
                        && header.source_inspection_sha256 == recovery.source_inspection_sha256()
                        && header.source_views_sha256 == recovery.source_views_sha256()
                        && header.expected_tree_sha256 == expected.semantic_sha256()
                        && header.ticket_sha256 == canonical_json_sha256(recovery.ticket())?
                        && header.selected_bytes == recovery.ticket().selected_bytes
                        && header.journal_length == recovery.ticket().journal_length
                        && header.range_count == recovery.ticket().range_count
                        && Some(header.native_bindings) == recovery.map_records()
                        && header.native_base_sectors == 0,
                    "recovered map does not bind the authenticated HND publication/ticket"
                );
                // Keep the header's conservative decode allowance alongside
                // its owner, rather than crediting memory while strings live.
                let file = artifact.file.try_clone()?;
                Some(ReopenedMaps {
                    reader: RefCell::new(reader),
                    file,
                    header,
                    _header_ram: header_ram,
                    _ram: ram,
                })
            }
            None => None,
        };
        ensure!(
            needs_maps == maps.is_some(),
            "recovery map coverage requirement differs"
        );
        Ok(Self {
            expected,
            maps,
            admission,
            publication_file,
            publication_snapshot,
            selected_sha256: handoff.selected_sha256(),
            _arena: arena.clone(),
        })
    }

    pub(crate) fn expected(&self) -> &PagedExpectedTree {
        &self.expected
    }

    /// Called only on the actual native observation produced during controlled
    /// post-HND verification. This comparison itself cannot mount or replay.
    pub(crate) fn compare_protected<'a>(
        &'a self,
        handoff: &crate::selected_journal::resource_domain::reopen::envelope::VerifiedProtectedHandoff<'_>,
        observation: &'a n2r_win32::GeneralLiveConvertedObservation,
    ) -> Result<VerifiedMapComparison<'a>> {
        ensure!(
            observation.before() == observation.after()
                && observation.before().disk_attributes == 3
                && observation.observed_readonly().disk_attributes == 2
                && observation.report().pair.source == *handoff.recovery().source()
                && observation.report().pair.shadow == *handoff.recovery().shadow()
                && handoff.selected_sha256() == self.selected_sha256,
            "native observation does not name this protected HND source"
        );
        let bindings = self.compare_actual_report(observation.report())?;
        let proof = VerifiedMapComparison {
            metadata: self,
            observation,
            bindings,
        };
        proof.require_same(handoff, observation)?;
        Ok(proof)
    }

    fn compare_actual_report(
        &self,
        converted: &shadow_native::GeneralConvertedReport,
    ) -> Result<u64> {
        self.expected.require_recovery_memory(&self._arena)?;
        let observation = converted
            .content_observation
            .as_ref()
            .context("native metadata observation absent")?;
        let known = observation
            .known_content
            .as_ref()
            .context("native known-content verification absent")?;
        ensure!(
            converted.native.resource_profile
                == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                    Some(self.admission)
                ))
                && converted.native.retained_rows_ram_accounted()
                && converted.native.objects.len() == self.expected.len()
                && converted.native.base_sectors == 0
                && observation.metadata_and_namespace_verified
                && observation.complete_stream_mappings_observed
                && observation.data_storage_validity_checked
                && !observation.full_file_hashes
                && known
                    .streams_hashed
                    .checked_add(known.streams_without_content_baseline)
                    == Some(usize::try_from(self.admission.data_streams)?)
                && known.payload_bytes_read == observation.admitted_payload_bytes_read,
            "accounted native converted metadata observation differs"
        );
        let Some(maps) = &self.maps else {
            return Ok(0);
        };
        ensure!(
            converted.pair.source == maps.header.source
                && converted.pair.shadow == maps.header.shadow
                && converted.native.binding.identity == maps.header.source.identity,
            "converted native device differs from reopened map"
        );
        let mut reader = maps.reader.borrow_mut();
        reader.revalidate()?;
        ensure!(
            reader.same_file_as(&maps.file)?,
            "recovered map file identity changed"
        );
        let count = comparator::compare_records(
            &mut reader,
            &self.expected,
            &converted.native,
            self.admission,
            maps.header.native_bindings,
        )?;
        reader.revalidate()?;
        ensure!(
            reader.same_file_as(&maps.file)?,
            "recovered map changed during comparison"
        );
        self.expected.revalidate()?;
        Ok(count)
    }
}
