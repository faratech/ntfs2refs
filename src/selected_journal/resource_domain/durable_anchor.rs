//! Durable V4 recovery locator. Its independently supplied SHA-256 is a route
//! pin, never target-write authority. A future issuer must separately bind an
//! admitted source, preserved target, native journal and persisted route.
use super::{
    ArtifactGroup, ArtifactGroupPermit, ArtifactLease, SourceRamLease, SourceScratch,
    reopen::BoundJournalObservation,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralExclusiveRecoveryTarget, NativeEvent,
    general_layout::GeneralDiskBinding,
    journal_file::{GeneralJournalStorageBinding, JournalFileIdentity, MarkerStorageUse},
    reference_file::ReferenceFileSnapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

const MAGIC: &[u8; 8] = b"N2RANC01";
const HEADER_BYTES: u64 = 64;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityWire {
    volume_serial_number: u64,
    file_id_128: [u8; 16],
    volume_guid: [u8; 16],
    disk_guid: [u8; 16],
    partition_guid: [u8; 16],
    partition_number: u32,
    disk_bytes: u64,
    partition_offset: u64,
    partition_bytes: u64,
    logical_sector_bytes: u32,
    physical_sector_bytes: u32,
}
impl From<&JournalFileIdentity> for IdentityWire {
    fn from(id: &JournalFileIdentity) -> Self {
        Self {
            volume_serial_number: id.volume_serial_number,
            file_id_128: id.file_id_128,
            volume_guid: id.volume_guid,
            disk_guid: id.disk_guid,
            partition_guid: id.partition_guid,
            partition_number: id.partition_number,
            disk_bytes: id.disk_bytes,
            partition_offset: id.partition_offset,
            partition_bytes: id.partition_bytes,
            logical_sector_bytes: id.logical_sector_bytes,
            physical_sector_bytes: id.physical_sector_bytes,
        }
    }
}
impl From<&IdentityWire> for JournalFileIdentity {
    fn from(id: &IdentityWire) -> Self {
        Self {
            volume_serial_number: id.volume_serial_number,
            file_id_128: id.file_id_128,
            volume_guid: id.volume_guid,
            disk_guid: id.disk_guid,
            partition_guid: id.partition_guid,
            partition_number: id.partition_number,
            disk_bytes: id.disk_bytes,
            partition_offset: id.partition_offset,
            partition_bytes: id.partition_bytes,
            logical_sector_bytes: id.logical_sector_bytes,
            physical_sector_bytes: id.physical_sector_bytes,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    schema_version: u32,
    kind: String,
    #[serde(
        default,
        skip_serializing_if = "super::source_scope::ResourceRecoverySourceScope::is_dedicated"
    )]
    source_scope: super::source_scope::ResourceRecoverySourceScope,
    source: GeneralDiskBinding,
    journal_binding: GeneralJournalStorageBinding,
    journal_identity: IdentityWire,
    journal_path: PathBuf,
    journal_profile_version: u32,
    journal_profile_max_bytes: u64,
    marker_native_qualified_observation: Option<bool>,
    marker_lab_observation: bool,
    ticket: crate::selected_journal::SelectedTicket,
    serialized_locator_grants_authority: bool,
}
impl Locator {
    fn validate(&self) -> Result<()> {
        self.source.validate()?;
        self.journal_binding.validate()?;
        self.source_scope
            .require_locator_version(self.schema_version, &self.kind)?;
        self.source_scope
            .require_journal_route(&self.source, &self.journal_binding)?;
        let id = JournalFileIdentity::from(&self.journal_identity);
        let path = &self.journal_path;
        ensure!(
            !self.serialized_locator_grants_authority
                && path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                && self.ticket.image_length == self.source.identity.partition_bytes
                && self.ticket.range_count > 0
                && self.ticket.selected_bytes <= self.ticket.image_length
                && self.ticket.journal_length > 0
                && self.ticket.journal_length <= self.journal_profile_max_bytes
                && self.ticket.marker_profile.is_some()
                    == self.marker_native_qualified_observation.is_some()
                && id.disk_guid
                    == n2r_win32::layout::guid_bytes(
                        &self.journal_binding.disk.identity.disk_guid
                    )?
                && id.partition_guid
                    == n2r_win32::layout::guid_bytes(
                        &self.journal_binding.disk.identity.partition_guid
                    )?
                && id.volume_guid
                    == n2r_win32::layout::guid_bytes(&self.journal_binding.disk.volume_guid)?
                && id.partition_number == self.journal_binding.disk.identity.partition_number
                && id.disk_bytes == self.journal_binding.disk.identity.disk_bytes
                && id.partition_offset == self.journal_binding.disk.identity.partition_offset
                && id.partition_bytes == self.journal_binding.disk.identity.partition_bytes
                && id.logical_sector_bytes
                    == self.journal_binding.disk.identity.logical_sector_bytes
                && id.physical_sector_bytes
                    == self.journal_binding.disk.identity.physical_sector_bytes,
            "resource recovery locator facts differ"
        );
        let profile = n2r_win32::journal_file::JournalProfile::from_schema_and_capacity(
            self.journal_profile_version,
            (self.journal_profile_version == 3).then_some(self.journal_profile_max_bytes),
        )?;
        ensure!(
            profile.max_journal_bytes() == self.journal_profile_max_bytes,
            "resource locator journal profile differs"
        );
        Ok(())
    }
}

/// Count and hash one exact serialization without buffering it in memory.
struct Counting<W> {
    out: W,
    bytes: u64,
    maximum: u64,
    hash: Sha256,
    whole: Option<Sha256>,
}
impl<W: Write> Write for Counting<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("anchor payload budget exceeded"))?;
        self.out.write_all(bytes)?;
        self.hash.update(bytes);
        if let Some(whole) = &mut self.whole {
            whole.update(bytes);
        }
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}
fn payload_digest(value: &Locator, maximum: u64) -> Result<(u64, [u8; 32])> {
    let mut sink = Counting {
        out: io::sink(),
        bytes: 0,
        maximum,
        hash: Sha256::new(),
        whole: None,
    };
    serde_json::to_writer(&mut sink, value)?;
    Ok((sink.bytes, sink.hash.finalize().into()))
}
fn head(length: u64, digest: [u8; 32]) -> [u8; HEADER_BYTES as usize] {
    let mut bytes = [0u8; HEADER_BYTES as usize];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&length.to_le_bytes());
    bytes[24..56].copy_from_slice(&digest);
    bytes
}
fn volume_contains(path: &str, volume: &str) -> bool {
    let root = format!("{}\\", volume.trim_end_matches('\\')).to_ascii_lowercase();
    path.to_ascii_lowercase().starts_with(&root)
}

/// Actual held file, not a deserialized authorization. The expected checksum
/// must be obtained independently, like the legacy recovery bundle checksum.
pub(crate) struct DurableRecoveryLocator {
    file: File,
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    external_sha256: [u8; 32],
    payload: Locator,
    scratch: SourceScratch,
    _memory: SourceRamLease,
    arena_lease: Option<ArtifactLease>,
}
impl DurableRecoveryLocator {
    /// Explicit new-scope metadata route from an actual scanner, private owner
    /// and complete held preparation guard. No path/ticket/flag alone issues
    /// this route, and the resulting locator still grants no target writes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_partition_from_actual_owners(
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        admission: &mut n2r_win32::partition_lifecycle::PartitionNtfsAdmission,
        observation: &mut BoundJournalObservation<'_>,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        use super::source_scope::{PartitionPublicationScope, ResourceRecoverySourceScope};
        ensure!(
            group.group() == ArtifactGroup::RecoveryCopy,
            "partition locator requires actual recovery arena"
        );
        let actual_group = scratch
            .artifact_group()
            .context("partition locator arena absent")?;
        ensure!(
            actual_group.group() == group.group() && actual_group.arena().same_arena(group.arena()),
            "partition locator scratch/group owner differs"
        );
        let source_scope =
            ResourceRecoverySourceScope::from_actual_partition(owner, stable, admission, events)?;
        let binding = source_scope
            .partition_binding()
            .context("partition source binding missing")?
            .clone();
        ensure!(
            matches!(
                observation.lifecycle()?,
                crate::selected_journal::SelectedLifecycle::PreparedClear
                    | crate::selected_journal::SelectedLifecycle::ApplyIntent
                    | crate::selected_journal::SelectedLifecycle::RollbackIntent
            ),
            "closed HND/ABT cannot create a new partition replay locator"
        );
        let facts = observation.facts();
        source_scope.require_journal_route(&binding.storage, facts.binding)?;
        ensure!(
            facts.marker_native_qualified.is_none()
                && facts.marker_use == MarkerStorageUse::QualifiedProduction
                && observation.diagnostic_ticket().marker_profile.is_none(),
            "partition locator requires actual markerless production journal"
        );
        let locator = Locator {
            schema_version: source_scope.locator_protocol().0,
            kind: source_scope.locator_protocol().1.into(),
            source_scope: source_scope.clone(),
            source: binding.storage.clone(),
            journal_binding: facts.binding.clone(),
            journal_identity: IdentityWire::from(facts.identity),
            journal_path: facts.path.to_path_buf(),
            journal_profile_version: facts.profile.version(),
            journal_profile_max_bytes: facts.profile.max_journal_bytes(),
            marker_native_qualified_observation: None,
            marker_lab_observation: false,
            ticket: observation.diagnostic_ticket().clone(),
            serialized_locator_grants_authority: false,
        };
        source_scope
            .preparation_guard()?
            .require_actual(admission, owner, stable, events)?;
        // write_locator validates the held output directory's actual native
        // GUID route against this same observed J volume before CreateNew.
        let mut result = Self::write_locator(&locator, group, scratch, path)?;
        result.revalidate()?;
        source_scope
            .preparation_guard()?
            .require_actual(admission, owner, stable, events)?;
        Ok(result)
    }

    /// Persist routing from the actual still-held protected preparation before
    /// any activation. This remains diagnostic until the missing source,
    /// target and cross-stage resource certificates have real issuers.
    pub(crate) fn create_from_protected_preparation(
        prepared: &mut super::prepare::ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        prepared.require_arena(group)?;
        let facts = prepared.locator_facts(events)?;
        let mut result = Self::write_prepared_locator(facts, group, scratch, path)?;
        prepared.revalidate(events)?;
        result.revalidate()?;
        Ok(result)
    }

    /// The scoped producer retains both full source/target/capture bookends.
    /// This route cannot be used with a saved publication or copied flag.
    pub(super) fn create_with_frozen_witness(
        prepared: &super::prepare::ProtectedPreparedJournal<'_, '_, '_, '_, '_>,
        witness: &super::prepare::FrozenPreparedWitness<'_>,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
    ) -> Result<Self> {
        witness.require(prepared)?;
        prepared.require_arena(group)?;
        let facts = prepared.locator_facts_with_frozen_witness(witness)?;
        let mut result = Self::write_prepared_locator(facts, group, scratch, path)?;
        result.revalidate()?;
        witness.require(prepared)?;
        Ok(result)
    }

    fn write_prepared_locator(
        facts: super::prepare::PreparedLocatorFacts,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
    ) -> Result<Self> {
        ensure!(
            facts.source.disk_number != facts.shadow.disk_number
                && facts.journal_binding.disk.disk_number != facts.shadow.disk_number
                && n2r_win32::layout::guid_bytes(&facts.shadow.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(
                        &facts.journal_binding.disk.identity.disk_guid
                    )?,
            "prepared locator journal is not independent of its frozen shadow"
        );
        let locator = Locator {
            schema_version: 1,
            kind: "resource-recovery-locator-v1".into(),
            source_scope: super::source_scope::ResourceRecoverySourceScope::Dedicated,
            source: facts.source,
            journal_binding: facts.journal_binding,
            journal_identity: (&facts.journal_identity).into(),
            journal_path: facts.journal_path,
            journal_profile_version: facts.profile.version(),
            journal_profile_max_bytes: facts.profile.max_journal_bytes(),
            marker_native_qualified_observation: facts.marker_native_qualified,
            marker_lab_observation: facts.marker_use == MarkerStorageUse::EnrolledUnqualifiedLab,
            ticket: facts.ticket,
            serialized_locator_grants_authority: false,
        };
        Self::write_locator(&locator, group, scratch, path)
    }

    /// Experimental locator creation from actual held read-only observations.
    /// This is not a V4 conversion issuer and does not open the source for writes.
    pub(crate) fn create_diagnostic(
        observation: &mut BoundJournalObservation<'_>,
        target: &GeneralExclusiveRecoveryTarget,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        ensure!(
            matches!(
                group.group(),
                ArtifactGroup::RecoveryCopy | ArtifactGroup::Auxiliary
            ),
            "recovery locator requires its external arena group"
        );
        let actual_group = scratch
            .artifact_group()
            .context("locator scratch is not arena-owned")?;
        ensure!(
            actual_group.group() == group.group() && actual_group.arena().same_arena(group.arena()),
            "locator scratch and arena group differ"
        );
        let lifecycle = observation.lifecycle()?;
        let before = target.state(events)?;
        ensure!(
            before.disk_attributes == 1,
            "locator target is not persistently offline"
        );
        let source = target.binding().clone();
        let facts = observation.facts();
        let locator = Locator {
            schema_version: 1,
            kind: "resource-recovery-locator-v1".into(),
            source_scope: super::source_scope::ResourceRecoverySourceScope::Dedicated,
            source: source.clone(),
            journal_binding: facts.binding.clone(),
            journal_identity: facts.identity.into(),
            journal_path: facts.path.to_path_buf(),
            journal_profile_version: facts.profile.version(),
            journal_profile_max_bytes: facts.profile.max_journal_bytes(),
            marker_native_qualified_observation: facts.marker_native_qualified,
            marker_lab_observation: facts.marker_use == MarkerStorageUse::EnrolledUnqualifiedLab,
            ticket: observation.diagnostic_ticket().clone(),
            serialized_locator_grants_authority: false,
        };
        let mut result = Self::write_locator(&locator, group, scratch, path)?;
        ensure!(
            target.state(events)? == before && observation.lifecycle()? == lifecycle,
            "held source state or journal lifecycle changed while persisting locator"
        );
        result.revalidate()?;
        Ok(result)
    }

    fn write_locator(
        locator: &Locator,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        path: &Path,
    ) -> Result<Self> {
        ensure!(
            matches!(
                group.group(),
                ArtifactGroup::RecoveryCopy | ArtifactGroup::Auxiliary
            ),
            "recovery locator requires its external arena group"
        );
        let actual_group = scratch
            .artifact_group()
            .context("locator scratch is not arena-owned")?;
        ensure!(
            actual_group.group() == group.group() && actual_group.arena().same_arena(group.arena()),
            "locator scratch and arena group differ"
        );
        locator.validate()?;
        let source = &locator.source;
        // Check the real held output directory before CreateNew: staging on
        // the volume being converted would mutate its filesystem.
        let parent = path.parent().context("locator parent is absent")?;
        let parent_handle = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(parent)?;
        let parent_meta = parent_handle.metadata()?;
        ensure!(
            parent_meta.is_dir() && parent_meta.file_attributes() & 0x400 == 0,
            "locator parent must be an ordinary held directory"
        );
        let parent_route = n2r_win32::file_storage::final_path_guid(&parent_handle)?;
        ensure!(
            !volume_contains(&parent_route, &source.volume_path()?),
            "locator cannot be created on the target volume"
        );
        let root_end = parent_route
            .find("}\\")
            .context("locator parent has no volume GUID root")?
            + 1;
        let actual_volume = &parent_route[..root_end];
        ensure!(
            actual_volume.eq_ignore_ascii_case(&locator.journal_binding.disk.volume_path()?),
            "locator must use the actual held journal volume"
        );
        let volume = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(actual_volume)?;
        let maximum = scratch.budget().record_bytes;
        let (payload_bytes, payload_sha) = payload_digest(locator, maximum)?;
        let total = HEADER_BYTES
            .checked_add(payload_bytes)
            .context("locator length overflow")?;
        let working = total
            .checked_mul(4)
            .and_then(|n| n.checked_add(6 * 1024 * 1024))
            .context("locator RAM overflow")?;
        let memory = scratch.lease_ram(working)?;
        let permit = group.reserve_file(path, total)?;
        let raw = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(permit.path())?;
        let header = head(payload_bytes, payload_sha);
        let mut output = BufWriter::with_capacity(64 * 1024, raw);
        output.write_all(&header)?;
        let mut whole = Sha256::new();
        whole.update(header);
        let mut payload = Counting {
            out: &mut output,
            bytes: 0,
            maximum: payload_bytes,
            hash: Sha256::new(),
            whole: Some(whole),
        };
        serde_json::to_writer(&mut payload, locator)?;
        payload.flush()?;
        ensure!(
            payload.bytes == payload_bytes
                && <[u8; 32]>::from(payload.hash.finalize()) == payload_sha,
            "locator payload changed during serialization"
        );
        let full_sha: [u8; 32] = payload
            .whole
            .context("locator whole hash missing")?
            .finalize()
            .into();
        output.get_ref().sync_all()?;
        // Flush the actual owning filesystem too, including its directory
        // metadata. No raw volume WriteFile operation is issued.
        volume.sync_all()?;
        ensure!(
            output.get_ref().metadata()?.len() == total,
            "locator file length differs"
        );
        let readonly = n2r_win32::file_storage::duplicate_readonly(output.get_ref())?;
        drop(output);
        let lease = permit.verify_closed_handle(&readonly, &hex::encode(full_sha))?;
        let result = Self::from_held(
            readonly,
            full_sha,
            total,
            scratch.clone(),
            memory,
            Some(lease),
        )?;
        drop(parent_handle);
        Ok(result)
    }

    /// Reopen only with a checksum supplied independently of the locator. The
    /// returned owner is still a locator, never an admission or replay proof.
    pub(crate) fn open_observed(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        scratch: &SourceScratch,
        max_bytes: u64,
    ) -> Result<Self> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "recovery locator path must be absolute without traversal"
        );
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)
            .with_context(|| format!("reopening recovery locator {} read-only", path.display()))?;
        let size = file.metadata()?.len();
        ensure!(
            size >= HEADER_BYTES && size <= max_bytes,
            "recovery locator length exceeds admission"
        );
        let working = size
            .checked_mul(4)
            .and_then(|n| n.checked_add(6 * 1024 * 1024))
            .context("locator RAM overflow")?;
        let memory = scratch.lease_ram(working)?;
        Self::from_held(
            file,
            independently_supplied_sha256,
            max_bytes,
            scratch.clone(),
            memory,
            None,
        )
    }

    fn from_held(
        mut file: File,
        expected: [u8; 32],
        maximum: u64,
        scratch: SourceScratch,
        memory: SourceRamLease,
        arena_lease: Option<ArtifactLease>,
    ) -> Result<Self> {
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let snapshot =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        let modified = file.metadata()?.modified()?;
        ensure!(
            snapshot.number_of_links == 1 && snapshot.file_bytes >= HEADER_BYTES,
            "locator must be a held ordinary single-link file"
        );
        ensure!(
            n2r_win32::metadata_pages::pinning_digest(&mut file, snapshot.file_bytes)? == expected,
            "recovery locator does not match the independently supplied checksum"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_BYTES as usize];
        file.read_exact(&mut header)?;
        let size = u64::from_le_bytes(header[16..24].try_into()?);
        ensure!(
            &header[..8] == MAGIC
                && u32::from_le_bytes(header[8..12].try_into()?) == 1
                && header[12..16].iter().all(|&b| b == 0)
                && header[56..].iter().all(|&b| b == 0)
                && size > 0
                && size <= scratch.budget().record_bytes
                && HEADER_BYTES.checked_add(size) == Some(snapshot.file_bytes),
            "recovery locator framing differs"
        );
        let payload: Locator = serde_json::from_reader((&mut file).take(size))?;
        payload.validate()?;
        let (actual_size, actual_sha) = payload_digest(&payload, size)?;
        ensure!(
            actual_size == size && header[24..56] == actual_sha,
            "recovery locator payload encoding or digest differs"
        );
        ensure!(
            !volume_contains(&snapshot.final_path, &payload.source.volume_path()?),
            "recovery locator is on the source volume"
        );
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
                == snapshot
                && file.metadata()?.modified()? == modified,
            "recovery locator file changed during readback"
        );
        Ok(Self {
            file,
            snapshot,
            modified,
            external_sha256: expected,
            payload,
            scratch,
            _memory: memory,
            arena_lease,
        })
    }

    /// The caller must save this value independently; it is not write authority.
    pub(crate) fn external_sha256(&self) -> [u8; 32] {
        self.external_sha256
    }
    pub(crate) fn snapshot(&self) -> &ReferenceFileSnapshot {
        &self.snapshot
    }
    pub(crate) fn source_scope(&self) -> &super::source_scope::ResourceRecoverySourceScope {
        &self.payload.source_scope
    }
    pub(crate) fn source(&self) -> &GeneralDiskBinding {
        &self.payload.source
    }
    pub(crate) fn journal_binding(&self) -> &GeneralJournalStorageBinding {
        &self.payload.journal_binding
    }
    pub(crate) fn journal_identity(&self) -> JournalFileIdentity {
        (&self.payload.journal_identity).into()
    }
    pub(crate) fn journal_path(&self) -> &Path {
        &self.payload.journal_path
    }
    pub(crate) fn ticket(&self) -> &crate::selected_journal::SelectedTicket {
        &self.payload.ticket
    }

    /// Persisted routing facts only. The reopened native journal must still
    /// independently establish its same-handle identity and storage profile.
    pub(crate) fn journal_profile(&self) -> Result<n2r_win32::journal_file::JournalProfile> {
        let version = self.payload.journal_profile_version;
        Ok(
            n2r_win32::journal_file::JournalProfile::from_schema_and_capacity(
                version,
                (version == 3).then_some(self.payload.journal_profile_max_bytes),
            )?,
        )
    }

    pub(crate) fn marker_use(&self) -> MarkerStorageUse {
        if self.payload.marker_lab_observation {
            MarkerStorageUse::EnrolledUnqualifiedLab
        } else {
            MarkerStorageUse::QualifiedProduction
        }
    }

    pub(crate) fn marker_native_qualified(&self) -> Option<bool> {
        self.payload.marker_native_qualified_observation
    }

    pub(crate) fn revalidate(&mut self) -> Result<()> {
        let _hash_memory = self.scratch.lease_ram(4 * 1024 * 1024)?;
        if let Some(lease) = &self.arena_lease {
            lease.revalidate()?;
        }
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                self.snapshot.file_bytes
            )? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified
                && n2r_win32::metadata_pages::pinning_digest(&mut self.file, self.snapshot.file_bytes)? == self.external_sha256
                && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file,
                    self.snapshot.file_bytes
                )? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "held recovery locator identity or checksum changed"
        );
        Ok(())
    }

    pub(crate) fn retire(self) -> Result<()> {
        let Self {
            file, arena_lease, ..
        } = self;
        drop(file);
        arena_lease
            .context("only a newly created arena locator may be retired")?
            .retire()
    }
}

impl DurableRecoveryLocator {
    pub(crate) fn duplicate_readonly_origin_file(&mut self) -> Result<File> {
        self.revalidate()?;
        n2r_win32::file_storage::require_readonly_access(&self.file)?;
        Ok(self.file.try_clone()?)
    }
}
