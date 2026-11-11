//! Reopen authenticated Windows-prepared expected/maps with actual arena owners.
use super::*;
use crate::resource_prepared_bundle::HeldWindowsPreparedBundle;
use crate::selected_journal::resource_domain::reopen::envelope::ReopenedArtifact;
use crate::shadow_tree::{ExpectedBindingFacts, ExpectedBindingPin};
use sha2::Digest;
use std::{
    io::{Read, Seek, SeekFrom},
    os::windows::fs::OpenOptionsExt,
};
struct Held {
    file: File,
    snapshot: n2r_win32::reference_file::ReferenceFileSnapshot,
    sha: [u8; 32],
}
fn open_role(bundle: &HeldWindowsPreparedBundle, role: &str) -> Result<Held> {
    let c = bundle.core();
    let p = c
        .artifacts
        .iter()
        .find(|p| p.role == role)
        .context("prepared native artifact role absent")?;
    let path = p
        .snapshot
        .as_ref()
        .map(|s| Path::new(&s.final_path))
        .unwrap_or(&p.path);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)?;
    n2r_win32::file_storage::require_readonly_access(&file)?;
    let snapshot =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, p.bytes)?;
    let sha: [u8; 32] = hex::decode(&p.sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("prepared role digest width"))?;
    ensure!(
        snapshot.file_bytes == p.bytes
            && snapshot.volume_serial_number == c.journal_identity.volume_serial_number
            && n2r_win32::sha256_native::hash_range(&mut file, 0, p.bytes)? == sha,
        "prepared actual role length/hash/J identity differs"
    );
    Ok(Held {
        file,
        snapshot,
        sha,
    })
}
fn open_binding(
    bundle: &HeldWindowsPreparedBundle,
    scratch: &SourceScratch,
    pin: &ExpectedBindingPin,
    expected: &Held,
    semantic: &str,
) -> Result<(Held, crate::ntfs_inspect::paged_storage::SourceRamLease)> {
    let c = bundle.core();
    ensure!(
        pin.bytes > 0
            && pin.bytes <= 65536
            && pin.path.is_absolute()
            && !pin.path.components().any(|p| matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
        "prepared expected binding path/bound differs"
    );
    pin.facts.validate(
        c.source_resource_admission,
        &hex::encode(expected.sha),
        semantic,
    )?;
    let ram = scratch.lease_ram(
        pin.bytes
            .checked_mul(32)
            .and_then(|n| n.checked_add(1024 * 1024))
            .context("prepared expected binding RAM overflow")?,
    )?;
    let wire = serde_json::to_vec(&pin.facts)?;
    ensure!(
        wire.len() as u64 == pin.bytes && hex::encode(sha2::Sha256::digest(&wire)) == pin.sha256,
        "prepared expected binding canonical bytes differ"
    );
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&pin.path)?;
    n2r_win32::file_storage::require_readonly_access(&file)?;
    let snapshot =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, 65536)?;
    let sha: [u8; 32] = hex::decode(&pin.sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("binding SHA width"))?;
    let prefix = format!(
        "{}\\",
        c.journal_binding.disk.volume_path()?.trim_end_matches('\\')
    );
    ensure!(
        snapshot.file_bytes == pin.bytes
            && snapshot.number_of_links == 1
            && snapshot.volume_serial_number == c.journal_identity.volume_serial_number
            && snapshot
                .final_path
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
            && n2r_win32::sha256_native::hash_range(&mut file, 0, pin.bytes)? == sha,
        "prepared expected binding identity/hash/actual J volume differs"
    );
    file.seek(SeekFrom::Start(0))?;
    let facts: ExpectedBindingFacts = serde_json::from_reader(&mut file)?;
    ensure!(
        facts == pin.facts
            && n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, 65536)?
                == snapshot,
        "prepared actual expected binding facts/identity differ"
    );
    Ok((
        Held {
            file,
            snapshot,
            sha,
        },
        ram,
    ))
}
struct PreparedView<'a> {
    bundle: &'a HeldWindowsPreparedBundle,
    scratch: &'a SourceScratch,
    publication: Held,
    expected: Held,
    maps: Option<Held>,
    value: serde_json::Value,
    policy: crate::verification_policy::VerificationPolicy,
    binding: Option<ExpectedBindingPin>,
    _binding_file: Option<Held>,
    _binding_ram: Option<crate::ntfs_inspect::paged_storage::SourceRamLease>,
    _decode: crate::ntfs_inspect::paged_storage::SourceRamLease,
}
impl<'a> PreparedView<'a> {
    fn open(bundle: &'a HeldWindowsPreparedBundle, scratch: &'a SourceScratch) -> Result<Self> {
        bundle.require_ready_artifacts()?;
        let mut publication = open_role(bundle, "publication")?;
        let decode = scratch.lease_ram(
            publication
                .snapshot
                .file_bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(5 * 1024 * 1024))
                .context("prepared publication decode overflow")?,
        )?;
        publication.file.seek(SeekFrom::Start(0))?;
        let mut wire = vec![0; usize::try_from(publication.snapshot.file_bytes)?];
        publication.file.read_exact(&mut wire)?;
        let value: serde_json::Value = serde_json::from_slice(&wire)?;
        let policy = serde_json::from_value(value["verification_policy"].clone())?;
        ensure!(
            value["resource_admission"]
                == serde_json::to_value(bundle.core().source_resource_admission)?,
            "prepared inner and outer resource admission differ"
        );
        ensure!(
            value["source"] == serde_json::to_value(&bundle.core().source)?
                && value["shadow"] == serde_json::to_value(&bundle.core().shadow)?,
            "prepared publication source/shadow differs"
        );
        let expected = open_role(bundle, "expected-tree")?;
        let maps = if bundle
            .core()
            .artifacts
            .iter()
            .any(|p| p.role == "recovery-maps")
        {
            Some(open_role(bundle, "recovery-maps")?)
        } else {
            None
        };
        let binding: Option<ExpectedBindingPin> = match value["expected"].get("binding") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(serde_json::from_value(v.clone())?),
        };
        let (binding_file, binding_ram) = match &binding {
            Some(pin) => {
                let (f, r) = open_binding(
                    bundle,
                    scratch,
                    pin,
                    &expected,
                    value["expected"]["semantic_sha256"].as_str().unwrap_or(""),
                )?;
                (Some(f), Some(r))
            }
            None => (None, None),
        };
        Ok(Self {
            bundle,
            scratch,
            publication,
            expected,
            maps,
            value,
            policy,
            binding,
            _binding_file: binding_file,
            _binding_ram: binding_ram,
            _decode: decode,
        })
    }
    fn runtime_scratch(&self) -> &SourceScratch {
        self.scratch
    }
    fn resource_admission(&self) -> n2r_win32::tree_resources::SourceResourceAdmission {
        self.bundle.core().source_resource_admission
    }
    fn publication_artifact(&self) -> ReopenedArtifact<'_> {
        ReopenedArtifact {
            file: &self.publication.file,
            snapshot: &self.publication.snapshot,
            sha256: self.publication.sha,
        }
    }
    fn expected_artifact(&self) -> ReopenedArtifact<'_> {
        ReopenedArtifact {
            file: &self.expected.file,
            snapshot: &self.expected.snapshot,
            sha256: self.expected.sha,
        }
    }
    fn map_artifact(&self) -> Option<ReopenedArtifact<'_>> {
        self.maps.as_ref().map(|m| ReopenedArtifact {
            file: &m.file,
            snapshot: &m.snapshot,
            sha256: m.sha,
        })
    }
    fn expected_semantic_sha256(&self) -> &str {
        self.value["expected"]["semantic_sha256"]
            .as_str()
            .unwrap_or("")
    }
    fn expected_binding(&self) -> Option<&ExpectedBindingPin> {
        self.binding.as_ref()
    }
    fn expected_objects(&self) -> u64 {
        self.value["expected"]["objects"].as_u64().unwrap_or(0)
    }
    fn verification_policy(&self) -> crate::verification_policy::VerificationPolicy {
        self.policy
    }
    fn source(&self) -> &n2r_win32::general_layout::GeneralDiskBinding {
        &self.bundle.core().source
    }
    fn shadow(&self) -> &n2r_win32::general_layout::GeneralDiskBinding {
        &self.bundle.core().shadow
    }
    fn source_sha256(&self) -> &str {
        &self.bundle.core().source_sha256
    }
    fn source_inspection_sha256(&self) -> &str {
        &self.bundle.core().source_inspection_sha256
    }
    fn source_views_sha256(&self) -> &str {
        &self.bundle.core().source_views_sha256
    }
    fn ticket(&self) -> &crate::selected_journal::SelectedTicket {
        &self.bundle.core().ticket
    }
    fn map_records(&self) -> Option<u64> {
        self.value["recovery_maps"]["records"].as_u64()
    }
}
pub(crate) struct OfflinePreparedVerification {
    metadata: ReopenedVerificationMetadata,
    owner: n2r_win32::offline_environment::OfflineSourceOwnerToken,
}
impl OfflinePreparedVerification {
    pub(crate) fn open(
        bundle: &HeldWindowsPreparedBundle,
        scratch: &SourceScratch,
        owner: &n2r_win32::offline_environment::OfflineSourceOwnerToken,
    ) -> Result<Self> {
        let recovery = PreparedView::open(bundle, scratch)?;
        let metadata = ReopenedVerificationMetadata::open_prepared_view(&recovery)?;
        Ok(Self {
            metadata,
            owner: owner.clone(),
        })
    }
    pub(crate) fn expected(&self) -> &PagedExpectedTree {
        self.metadata.expected()
    }
    pub(crate) fn compare(
        &self,
        observed: &n2r_win32::shadow_native::OfflineReadonlyFidelity,
    ) -> Result<u64> {
        ensure!(
            self.owner.same_owner(&observed.owner_token()),
            "offline native report owner differs"
        );
        let count = self
            .metadata
            .compare_actual_report(observed.report(), true)?;
        ensure!(
            self.metadata.maps.is_some()
                || observed
                    .report()
                    .content_observation
                    .as_ref()
                    .and_then(|c| c.known_content.as_ref())
                    .context("native known-content report missing")?
                    .streams_without_content_baseline
                    == 0,
            "unknown retained payload requires actual saved maps"
        );
        Ok(count)
    }
}
impl ReopenedVerificationMetadata {
    fn open_prepared_view(recovery: &PreparedView<'_>) -> Result<Self> {
        let scratch = recovery.runtime_scratch();
        let group = scratch.artifact_group().context("recovery arena absent")?;
        let arena = group.arena();
        let admission = recovery.resource_admission();
        let publication = recovery.publication_artifact();
        let publication_file = publication.file.try_clone()?;
        let publication_snapshot = publication.snapshot.clone();
        let artifact = recovery.expected_artifact();
        let expected = PagedExpectedTree::open_recovery_with_binding(
            artifact.file,
            artifact.snapshot,
            &hex::encode(artifact.sha256),
            recovery.expected_semantic_sha256(),
            admission,
            arena,
            recovery.expected_binding(),
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
            selected_sha256: recovery.ticket().new_selected_sha256,
            partition_source: Some(recovery.source().clone()),
            partition_owner: None,
            _arena: arena.clone(),
        })
    }
}
