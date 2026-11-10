//! Reopen a V4 recovery publication and its actual excluded storage owners.
//!
//! The independently pinned publication is a route to evidence, not write
//! authority. This module deliberately exposes neither a target writer nor a
//! replay operation. In particular, a successful scan does not prove that an
//! earlier fresh-source admission or writable handoff occurred.
use super::{BoundJournalObservation, BoundNativeRecoveryJournal, SelectedLifecycle};
#[path = "partition_closed.rs"]
mod partition_closed;
pub(crate) use partition_closed::{PartitionClosedTerminal, ReopenedPartitionRestart};
#[path = "partition_basic_ro.rs"]
mod partition_basic_ro;
pub(crate) use partition_basic_ro::PartitionBasicRoClosedTerminal;
#[path = "partition_operational.rs"]
mod partition_operational;
use crate::{
    artifact_arena::{ArtifactGroup, ArtifactGroupPermit},
    ntfs_inspect::paged_storage::{SourceRamLease, SourceScratch},
    selected_journal::resource_domain::durable_anchor::DurableRecoveryLocator,
    shadow_tree::{ExpectedBindingFacts, ExpectedBindingPin},
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralExclusiveRecoveryTarget, GeneralFrozenPartition, NativeEvent, PagedRecoveryDirection,
    attestation::ResourceProfile,
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    journal_file::GeneralJournalStorageBinding,
    reference_file::ReferenceFileSnapshot,
    tree_resources::SourceResourceAdmission,
    volume_label::VolumeLabel,
};
pub(crate) use partition_operational::reconcile_operational_partition;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePin {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedPin {
    file: FilePin,
    semantic_sha256: String,
    objects: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<ExpectedBindingPin>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapPin {
    file: FilePin,
    records: u64,
}

// Field order and optional encoding match prepare::qualification::Publication.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    schema_version: u32,
    kind: String,
    #[serde(
        default,
        skip_serializing_if = "super::super::source_scope::ResourceRecoverySourceScope::is_dedicated"
    )]
    source_scope: super::super::source_scope::ResourceRecoverySourceScope,
    source: GeneralDiskBinding,
    shadow: GeneralDiskBinding,
    resource_admission: SourceResourceAdmission,
    verification_policy: VerificationPolicy,
    source_fingerprint_kind: String,
    source_sha256: String,
    source_inspection_sha256: String,
    source_views_sha256: String,
    locator: FilePin,
    expected: ExpectedPin,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_maps: Option<MapPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    windows_aliases: Option<crate::ntfs_inspect::record_store::RecordStorePin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    windows_alias_plan_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    early_preparation_guard: Option<crate::resource_preparation::early_guard::GuardPin>,
    ticket_sha256: String,
    expected_mount_paths: Vec<String>,
    expected_source_label: VolumeLabel,
    serialized_publication_grants_authority: bool,
}

fn digest(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "noncanonical SHA-256 in recovery publication"
    );
    Ok(hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid SHA-256 width"))?)
}

fn guard_memory_bytes(
    pin: &crate::resource_preparation::early_guard::GuardPin,
    maximum: u64,
) -> Result<u64> {
    ensure!(
        pin.bytes > 0 && pin.bytes <= maximum,
        "early preparation guard exceeds the admitted metadata window"
    );
    digest(&pin.sha256)?;
    // Covers both 64-KiB native state slots, simultaneous decode/copy work,
    // bounded metadata serialization and the retained native guard owner.
    pin.bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add(2 * 1024 * 1024))
        .context("early preparation guard RAM overflow")
}

fn on_volume(path: &str, volume: &str) -> bool {
    let root = format!("{}\\", volume.trim_end_matches('\\'));
    path.get(..root.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(&root))
}

fn ordinary_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "recovery path must be absolute without traversal"
    );
    Ok(())
}

/// Keep the actual ordinary index directory open on the independently bound
/// journal volume. The arena still validates the complete path ancestry.
fn hold_index_parent(path: &Path, volume: &str) -> Result<File> {
    ordinary_path(path)?;
    let parent = path.parent().context("recovery index parent absent")?;
    let handle = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(parent)?;
    let meta = handle.metadata()?;
    ensure!(
        meta.is_dir()
            && meta.file_attributes() & 0x400 == 0
            && on_volume(
                &format!(
                    "{}\\",
                    n2r_win32::file_storage::final_path_guid(&handle)?.trim_end_matches('\\')
                ),
                volume
            ),
        "recovery index must be on the held journal volume"
    );
    Ok(handle)
}

struct HashSink {
    bytes: u64,
    maximum: u64,
    hash: Sha256,
}
impl Write for HashSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("canonical recovery publication exceeds its bound"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Same held handle, identity and digest for a published external file.
struct HeldFile {
    file: File,
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    sha256: [u8; 32],
    expected_binding: Option<Box<HeldFile>>,
    _binding_memory: Option<SourceRamLease>,
}

fn hold_expected_binding(
    publication: &Publication,
    volume: &str,
    expected: &mut HeldFile,
    scratch: &SourceScratch,
) -> Result<()> {
    let Some(pin) = &publication.expected.binding else {
        return Ok(());
    };
    ensure!(
        publication.source_scope.is_dedicated()
            && publication.source.layout_profile
                == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            && pin.bytes > 0
            && pin.bytes <= 65536,
        "expected binding requires a bounded dedicated Windows publication"
    );
    pin.facts.validate(
        publication.resource_admission,
        &publication.expected.file.sha256,
        &publication.expected.semantic_sha256,
    )?;
    let _decode = scratch.lease_ram(
        pin.bytes
            .checked_mul(32)
            .and_then(|n| n.checked_add(131072))
            .context("expected binding decoder RAM overflow")?,
    )?;
    let wire = serde_json::to_vec(&pin.facts)?;
    ensure!(
        wire.len() as u64 == pin.bytes && hex::encode(Sha256::digest(&wire)) == pin.sha256,
        "expected binding canonical bytes differ from publication pin"
    );
    let retained = scratch.lease_ram(
        (pin.path.as_os_str().as_encoded_bytes().len() as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add(262144))
            .context("expected binding owner RAM overflow")?,
    )?;
    ordinary_path(&pin.path)?;
    let same_j_file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&pin.path)?;
    n2r_win32::file_storage::require_readonly_access(&same_j_file)?;
    let same_j_snapshot =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&same_j_file, 65536)?;
    ensure!(
        on_volume(&same_j_snapshot.final_path, volume),
        "expected binding is not on the actual independent journal volume"
    );
    let mut held = HeldFile::open(
        &pin.path,
        digest(&pin.sha256)?,
        Some(pin.bytes),
        65536,
        scratch,
    )?;
    ensure!(
        held.snapshot == same_j_snapshot,
        "expected binding changed after its actual journal-volume check"
    );
    held.file.seek(SeekFrom::Start(0))?;
    let facts: ExpectedBindingFacts = serde_json::from_reader(&mut held.file)?;
    ensure!(
        facts == pin.facts,
        "actual expected binding facts differ from publication"
    );
    held.revalidate(scratch)?;
    held._binding_memory = Some(retained);
    expected.expected_binding = Some(Box::new(held));
    Ok(())
}

struct HeldWindowsAliasFiles {
    data: HeldFile,
    directory: HeldFile,
}
impl HeldWindowsAliasFiles {
    fn revalidate(&mut self, scratch: &SourceScratch) -> Result<()> {
        self.data.revalidate(scratch)?;
        self.directory.revalidate(scratch)
    }
}

fn open_windows_alias_files(
    publication: &Publication,
    volume: &str,
    expected: &HeldFile,
    scratch: &SourceScratch,
) -> Result<Option<HeldWindowsAliasFiles>> {
    let windows = publication.source.layout_profile
        == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows;
    let (pin, plan) = match (
        &publication.windows_aliases,
        &publication.windows_alias_plan_sha256,
    ) {
        (None, None) if !windows => return Ok(None),
        (Some(pin), Some(plan)) if windows => (pin, plan),
        _ => anyhow::bail!(
            "Windows recovery requires its authenticated complete alias expectations; legacy Windows publications cannot reconstruct them"
        ),
    };
    digest(plan)?;
    ensure!(
        pin.schema_version == 1
            && pin.purpose == *b"WINALIS1"
            && pin.records <= publication.resource_admission.maximum_namespace_names()? as u64
            && pin
                .data
                .wire_bytes
                .checked_add(pin.directory.wire_bytes)
                .is_some_and(|bytes| bytes <= publication.resource_admission.budget.scratch_bytes),
        "Windows alias publication record/storage bounds differ"
    );
    let open = |pin: &crate::ntfs_inspect::paged_storage::SourcePagePin| -> Result<HeldFile> {
        ensure!(
            pin.page_budget.max_file_bytes <= publication.resource_admission.budget.scratch_bytes
                && pin.wire_bytes <= pin.page_budget.max_file_bytes,
            "Windows alias artifact exceeds original admission"
        );
        let held = HeldFile::open(
            &pin.path,
            digest(&pin.file_sha256)?,
            Some(pin.wire_bytes),
            pin.page_budget.max_file_bytes,
            scratch,
        )?;
        ensure!(
            pin.path
                .to_str()
                .is_some_and(|path| held.snapshot.final_path.eq_ignore_ascii_case(path))
                && on_volume(&held.snapshot.final_path, volume)
                && held.snapshot.volume_serial_number == expected.snapshot.volume_serial_number,
            "Windows alias artifact differs from the actual authenticated journal volume"
        );
        Ok(held)
    };
    Ok(Some(HeldWindowsAliasFiles {
        data: open(&pin.data)?,
        directory: open(&pin.directory)?,
    }))
}
impl HeldFile {
    fn open(
        path: &Path,
        expected: [u8; 32],
        bytes: Option<u64>,
        maximum: u64,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::RecoveryFileOpen);
        ordinary_path(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)
            .with_context(|| format!("reopening recovery artifact {} read-only", path.display()))?;
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let snapshot =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        ensure!(
            snapshot.number_of_links == 1
                && snapshot.file_bytes > 0
                && bytes.is_none_or(|n| n == snapshot.file_bytes),
            "recovery artifact length or link count differs"
        );
        let modified = file.metadata()?.modified()?;
        let _ram = scratch.lease_ram(4 * 1024 * 1024)?;
        ensure!(
            n2r_win32::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)? == expected
                && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &file, maximum
                )? == snapshot
                && file.metadata()?.modified()? == modified,
            "recovery artifact identity or digest differs"
        );
        Ok(Self {
            file,
            snapshot,
            modified,
            sha256: expected,
            expected_binding: None,
            _binding_memory: None,
        })
    }
    fn revalidate(&mut self, scratch: &SourceScratch) -> Result<()> {
        if let Some(binding) = &mut self.expected_binding {
            binding.revalidate(scratch)?;
        }
        let _ram = scratch.lease_ram(4 * 1024 * 1024)?;
        // Hashed when it was reopened and held open, denying writers, since.
        if n2r_win32::verify_policy::checks_once() {
            ensure!(
                n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file,
                    self.snapshot.file_bytes
                )? == self.snapshot
                    && self.file.metadata()?.modified()? == self.modified,
                "held recovery artifact changed"
            );
            return Ok(());
        }
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                self.snapshot.file_bytes
            )? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified
                && n2r_win32::sha256_native::hash_range(
                    &mut self.file,
                    0,
                    self.snapshot.file_bytes
                )? == self.sha256
                && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file,
                    self.snapshot.file_bytes
                )? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "held recovery artifact changed"
        );
        Ok(())
    }
}

enum ObservedTarget {
    Frozen(GeneralFrozenPartition),
    Activated(GeneralExclusiveRecoveryTarget),
}
impl ObservedTarget {
    fn reopen(binding: GeneralDiskBinding, events: &mut Vec<NativeEvent>) -> Result<Self> {
        // A prepared-but-unactivated disk retains OFFLINE|READ_ONLY. A disk
        // interrupted after activation is OFFLINE only and must obtain the
        // separate deny-writer recovery handle. Neither path grants writes.
        match GeneralFrozenPartition::reopen(binding.clone(), events) {
            Ok(target) => Ok(Self::Frozen(target)),
            Err(frozen_error) => GeneralExclusiveRecoveryTarget::reopen(binding, events)
                .map(Self::Activated)
                .map_err(|error| anyhow::anyhow!("source is neither a held frozen target ({frozen_error}) nor an exclusive offline recovery target ({error})")),
        }
    }
    fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<n2r_win32::GeneralDiskState> {
        match self {
            Self::Frozen(target) => target.state(events),
            Self::Activated(target) => target.state(events),
        }
    }
    fn exclusive(&self) -> bool {
        matches!(self, Self::Activated(_))
    }
}

/// Holds the exact reopened publication, artifacts, native journal and
/// persistently offline target. It is read-only at the type boundary.
pub(crate) struct ReopenedResourceRecovery {
    publication: Publication,
    publication_file: HeldFile,
    expected: HeldFile,
    maps: Option<HeldFile>,
    windows_aliases: Option<HeldWindowsAliasFiles>,
    locator: DurableRecoveryLocator,
    journal: BoundNativeRecoveryJournal,
    target: Option<ObservedTarget>,
    initial_state: n2r_win32::GeneralDiskState,
    initial_lifecycle: SelectedLifecycle,
    mounted: Option<GeneralDiskBinding>,
    early_guard: Option<crate::resource_preparation::early_guard::RestartGuard>,
    _early_guard_memory: Option<SourceRamLease>,
    scratch: SourceScratch,
    _memory: SourceRamLease,
}

/// Same held, read-only actual artifact. The snapshot and digest alone do not
/// recreate a live owner or authorize target writes.
pub(crate) struct ReopenedArtifact<'a> {
    pub file: &'a File,
    pub snapshot: &'a ReferenceFileSnapshot,
    pub sha256: [u8; 32],
}

/// Authenticated only by the explicit scoped opener and actual held SDK guard.
/// This source is extracted only after matching the versioned scope to that guard.
/// Only this envelope owner module issues the binding after validating
/// that contract against the actual held publication, artifacts and locator.
/// No public constructor, Deserialize implementation or saved boolean exists.
struct AuthenticatedPartitionRecoveryScope {
    source: n2r_win32::partition_isolation::PartitionSourceBinding,
    actual_guard: serde_json::Value,
}

/// Borrows actual authenticated publication/artifact owners, not their JSON
/// representation. The actual SDK admission alone is also insufficient:
/// versioned scope plus all held publication/artifact/locator/J owners match it.
pub(crate) struct PartitionRecoveryPublicationBinding<'a> {
    publication: &'a Publication,
    publication_file: &'a mut HeldFile,
    expected: &'a mut HeldFile,
    maps: Option<&'a mut HeldFile>,
    locator: &'a mut DurableRecoveryLocator,
    scratch: &'a SourceScratch,
    scope: AuthenticatedPartitionRecoveryScope,
    actual_journal_owner: usize,
    actual_origin: PartitionRecoveryOrigin<'a>,
}

/// Explicit partition recovery files, independently authenticated while the
/// actual private source and complete preparation guard remain held. This is
/// intentionally not the legacy whole-disk target and has no writer accessor.
/// A process-death restart guard needs a separate SDK issuer; this API cannot
/// reconstruct one from a pin or an earlier native-RO observation.
pub(crate) struct ReopenedPartitionResourceRecovery {
    publication: Publication,
    publication_file: HeldFile,
    expected: HeldFile,
    maps: Option<HeldFile>,
    locator: DurableRecoveryLocator,
    journal: BoundNativeRecoveryJournal,
    index_parent: File,
    scratch: SourceScratch,
    _memory: SourceRamLease,
    restarted_origin: Option<n2r_win32::partition_restoration::PartitionRecoveredOrigin>,
}

fn require_partition_artifact_volume(
    owner: &mut n2r_win32::PartitionScopedOwner,
    scope: &super::super::source_scope::ResourceRecoverySourceScope,
    journal: &mut BoundNativeRecoveryJournal,
    artifacts: &[&ReferenceFileSnapshot],
    events: &mut Vec<NativeEvent>,
) -> Result<()> {
    ensure!(
        !scope.is_dedicated(),
        "same-disk policy requires explicit partition scope"
    );
    owner.revalidate(events)?;
    let (actual, facts) = journal.split_for_observation()?;
    scope.require_journal_route(&owner.binding().storage, facts.binding)?;
    // This native call observes the actual held J and its actual volume
    // extents/device/layout twice. A JSON offset or matching GUID alone is
    // insufficient to establish the C:-sibling disjointness policy.
    let observed = n2r_win32::journal_file::observe_general_journal_file_with_profile(
        actual.markerless_recovery_file()?,
        facts.binding,
        facts.profile,
    )?;
    ensure!(
        observed.identity == *facts.identity && observed.file_bytes == facts.journal_length,
        "actual scoped journal identity/extent evidence changed"
    );
    let volume = facts.binding.disk.volume_path()?;
    for artifact in artifacts {
        ensure!(
            on_volume(&artifact.final_path, &volume)
                && artifact.volume_serial_number == observed.identity.volume_serial_number
                && artifact.number_of_links == 1,
            "partition publication/expected/maps/locator artifact is not on actual disjoint J volume"
        );
    }
    owner.revalidate(events)?;
    Ok(())
}

impl ReopenedPartitionResourceRecovery {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_with_actual_guard(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        admission: &mut n2r_win32::partition_lifecycle::PartitionNtfsAdmission,
        expected_shadow: &GeneralDiskBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        ensure!(
            group.group() == ArtifactGroup::RecoveryCopy
                && maximum_publication_bytes > 0
                && maximum_publication_bytes <= scratch.budget().record_bytes,
            "scoped recovery requires its bounded actual recovery arena"
        );
        let same = scratch
            .artifact_group()
            .context("scoped scratch arena absent")?;
        ensure!(
            same.group() == group.group() && same.arena().same_arena(group.arena()),
            "scoped recovery scratch/group owner differs"
        );
        owner.revalidate(events)?;
        ensure!(
            stable.same_owner(&owner.owner_token()),
            "actual partition token differs"
        );
        let size = std::fs::symlink_metadata(path)?.len();
        ensure!(
            size > 0 && size <= maximum_publication_bytes,
            "partition publication exceeds bound"
        );
        let reserve = size
            .checked_mul(4)
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .context("partition publication RAM overflow")?;
        let memory = scratch.lease_ram(reserve)?;
        let mut publication_file = HeldFile::open(
            path,
            independently_supplied_sha256,
            Some(size),
            maximum_publication_bytes,
            scratch,
        )?;
        publication_file.file.seek(SeekFrom::Start(0))?;
        let publication: Publication = serde_json::from_reader(&mut publication_file.file)?;
        let mut canonical = HashSink {
            bytes: 0,
            maximum: size,
            hash: Sha256::new(),
        };
        serde_json::to_writer(&mut canonical, &publication)?;
        ensure!(
            canonical.bytes == size
                && <[u8; 32]>::from(canonical.hash.finalize()) == independently_supplied_sha256,
            "partition publication is not the exact canonical held encoding"
        );
        publication
            .source_scope
            .require_envelope_version(publication.schema_version, &publication.kind)?;
        let explicit = &publication.source_scope;
        explicit.require_partition()?;
        ensure!(
            explicit.partition_binding() == Some(owner.binding())
                && publication.source == owner.binding().storage
                && &publication.shadow == expected_shadow
                && !publication.serialized_publication_grants_authority
                && publication.early_preparation_guard.is_none(),
            "foreign scope or legacy whole-disk guard in partition publication"
        );
        expected_shadow.validate()?;
        ensure!(
            expected_shadow.disk_number != owner.binding().storage.disk_number
                && n2r_win32::layout::guid_bytes(&expected_shadow.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&owner.binding().storage.identity.disk_guid)?,
            "partition source and shadow physical identities overlap"
        );
        explicit
            .preparation_guard()?
            .require_actual(admission, owner, stable, events)?;
        publication.resource_admission.validate()?;
        publication.expected_source_label.validate()?;
        ensure!(
            publication.source_inspection_sha256
                == hex::encode(publication.resource_admission.source_inspection_sha256)
                && publication.expected.objects == publication.resource_admission.objects()?
                && publication.source_fingerprint_kind
                    == if publication.verification_policy.is_full_content() {
                        crate::source_fingerprint::resource::FULL_KIND
                    } else {
                        crate::source_fingerprint::resource::EXTENT_KIND
                    },
            "partition publication resource/expected contract differs"
        );
        for value in [
            &publication.source_sha256,
            &publication.source_inspection_sha256,
            &publication.source_views_sha256,
            &publication.expected.semantic_sha256,
            &publication.ticket_sha256,
        ] {
            digest(value)?;
        }
        let locator = DurableRecoveryLocator::open_observed(
            Path::new(&publication.locator.path),
            digest(&publication.locator.sha256)?,
            scratch,
            publication.locator.bytes,
        )?;
        ensure!(
            locator.source_scope() == &publication.source_scope
                && locator.source() == &publication.source
                && locator.journal_binding() == expected_journal
                && locator.snapshot().file_bytes == publication.locator.bytes
                && hex::encode(Sha256::digest(serde_json::to_vec(locator.ticket())?))
                    == publication.ticket_sha256
                && locator.ticket().marker_profile.is_none()
                && locator.marker_use()
                    == n2r_win32::journal_file::MarkerStorageUse::QualifiedProduction,
            "foreign/mixed partition publication/locator/ticket scope"
        );
        publication
            .source_scope
            .require_journal_route(&publication.source, expected_journal)?;
        // Shadow remains independently owned. The new C:-sibling allowance
        // applies only between the selected source partition and its journal.
        ensure!(
            expected_journal.disk.disk_number != expected_shadow.disk_number
                && n2r_win32::layout::guid_bytes(&expected_journal.disk.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&expected_shadow.identity.disk_guid)?,
            "partition shadow and journal are not independent"
        );
        let expected = HeldFile::open(
            Path::new(&publication.expected.file.path),
            digest(&publication.expected.file.sha256)?,
            Some(publication.expected.file.bytes),
            publication.resource_admission.expected_pages.max_file_bytes,
            scratch,
        )?;
        ensure!(
            expected
                .snapshot
                .final_path
                .eq_ignore_ascii_case(&publication.expected.file.path)
                && publication.expected.binding.is_none(),
            "partition expected artifact same-handle canonical route differs"
        );
        let maps = if let Some(pin) = &publication.recovery_maps {
            ensure!(pin.records > 0, "empty partition recovery map refused");
            let held = HeldFile::open(
                Path::new(&pin.file.path),
                digest(&pin.file.sha256)?,
                Some(pin.file.bytes),
                publication.resource_admission.map_pages.max_file_bytes,
                scratch,
            )?;
            ensure!(
                held.snapshot
                    .final_path
                    .eq_ignore_ascii_case(&pin.file.path),
                "partition recovery map same-handle canonical route differs"
            );
            Some(held)
        } else {
            None
        };
        ensure!(
            locator
                .snapshot()
                .final_path
                .eq_ignore_ascii_case(&publication.locator.path),
            "partition locator same-handle canonical route differs"
        );
        let (mut journal, _) = BoundNativeRecoveryJournal::open(
            locator.journal_path(),
            expected_journal,
            locator.journal_profile()?,
            locator.ticket(),
            None,
            locator.marker_use(),
        )?;
        {
            let (_, facts) = journal.split_for_observation()?;
            ensure!(
                facts.binding == locator.journal_binding()
                    && *facts.identity == locator.journal_identity()
                    && facts.path == locator.journal_path()
                    && facts.profile == locator.journal_profile()?
                    && facts.marker_use == locator.marker_use()
                    && facts.marker_native_qualified.is_none(),
                "actual partition journal owner differs from authenticated locator"
            );
        }
        let volume = expected_journal.disk.volume_path()?;
        let index_parent = hold_index_parent(index_path, &volume)?;
        let mut artifacts = vec![
            &publication_file.snapshot,
            &expected.snapshot,
            locator.snapshot(),
        ];
        if let Some(maps) = &maps {
            artifacts.push(&maps.snapshot);
        }
        require_partition_artifact_volume(
            owner,
            &publication.source_scope,
            &mut journal,
            &artifacts,
            events,
        )?;
        let mut observation = BoundJournalObservation::open(
            &mut journal,
            locator.ticket(),
            group,
            scratch,
            index_path,
            maximum_index_bytes,
        )?;
        ensure!(
            matches!(
                observation.lifecycle()?,
                SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
            ),
            "clear/foreign/closed HND-ABT cannot issue partition recovery binding"
        );
        observation.retire()?;
        explicit
            .preparation_guard()?
            .require_actual(admission, owner, stable, events)?;
        Ok(Self {
            publication,
            publication_file,
            expected,
            maps,
            locator,
            journal,
            index_parent,
            scratch: scratch.clone(),
            _memory: memory,
            restarted_origin: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_closed_terminal(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        observation_budget: n2r_win32::partition_isolation::PartitionObservationBudget,
        expected_shadow: &GeneralDiskBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        kind: n2r_win32::PartitionTerminalKind,
        events: &mut Vec<NativeEvent>,
    ) -> Result<PartitionClosedTerminal> {
        match Self::open_observed_restarted(
            path,
            independently_supplied_sha256,
            maximum_publication_bytes,
            owner,
            stable,
            observation_budget,
            expected_shadow,
            expected_journal,
            group,
            scratch,
            index_path,
            maximum_index_bytes,
            events,
        )? {
            ReopenedPartitionRestart::Closed(value) if value.kind() == kind => Ok(value),
            _ => anyhow::bail!(
                "actual closed lifecycle conflicts with terminal-only request; no raw replay attempted"
            ),
        }
    }

    pub(crate) fn open_restarted(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        observation_budget: n2r_win32::partition_isolation::PartitionObservationBudget,
        expected_shadow: &GeneralDiskBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        match Self::open_observed_restarted(
            path,
            independently_supplied_sha256,
            maximum_publication_bytes,
            owner,
            stable,
            observation_budget,
            expected_shadow,
            expected_journal,
            group,
            scratch,
            index_path,
            maximum_index_bytes,
            events,
        )? {
            ReopenedPartitionRestart::Replay(value) => Ok(value),
            ReopenedPartitionRestart::Closed(_) => {
                anyhow::bail!("closed HND/ABT requires terminal finalization, never raw replay")
            }
        }
    }

    pub(crate) fn open_observed_restarted(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        observation_budget: n2r_win32::partition_isolation::PartitionObservationBudget,
        expected_shadow: &GeneralDiskBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<ReopenedPartitionRestart> {
        ensure!(
            group.group() == ArtifactGroup::RecoveryCopy
                && maximum_publication_bytes > 0
                && maximum_publication_bytes <= scratch.budget().record_bytes,
            "scoped recovery requires its bounded actual recovery arena"
        );
        let same = scratch
            .artifact_group()
            .context("scoped scratch arena absent")?;
        ensure!(
            same.group() == group.group() && same.arena().same_arena(group.arena()),
            "scoped recovery scratch/group owner differs"
        );
        owner.revalidate(events)?;
        ensure!(
            stable.same_owner(&owner.owner_token()),
            "actual partition token differs"
        );
        let size = std::fs::symlink_metadata(path)?.len();
        ensure!(
            size > 0 && size <= maximum_publication_bytes,
            "partition publication exceeds bound"
        );
        let reserve = size
            .checked_mul(4)
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .context("partition publication RAM overflow")?;
        let memory = scratch.lease_ram(reserve)?;
        let mut publication_file = HeldFile::open(
            path,
            independently_supplied_sha256,
            Some(size),
            maximum_publication_bytes,
            scratch,
        )?;
        publication_file.file.seek(SeekFrom::Start(0))?;
        let publication: Publication = serde_json::from_reader(&mut publication_file.file)?;
        let mut canonical = HashSink {
            bytes: 0,
            maximum: size,
            hash: Sha256::new(),
        };
        serde_json::to_writer(&mut canonical, &publication)?;
        ensure!(
            canonical.bytes == size
                && <[u8; 32]>::from(canonical.hash.finalize()) == independently_supplied_sha256,
            "partition publication is not the exact canonical held encoding"
        );
        publication
            .source_scope
            .require_envelope_version(publication.schema_version, &publication.kind)?;
        let explicit = &publication.source_scope;
        explicit.require_partition()?;
        ensure!(
            explicit.partition_binding() == Some(owner.binding())
                && publication.source == owner.binding().storage
                && &publication.shadow == expected_shadow
                && !publication.serialized_publication_grants_authority
                && publication.early_preparation_guard.is_none(),
            "foreign scope or legacy whole-disk guard in partition publication"
        );
        expected_shadow.validate()?;
        ensure!(
            expected_shadow.disk_number != owner.binding().storage.disk_number
                && n2r_win32::layout::guid_bytes(&expected_shadow.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&owner.binding().storage.identity.disk_guid)?,
            "partition source and shadow physical identities overlap"
        );

        publication.resource_admission.validate()?;
        publication.expected_source_label.validate()?;
        ensure!(
            publication.source_inspection_sha256
                == hex::encode(publication.resource_admission.source_inspection_sha256)
                && publication.expected.objects == publication.resource_admission.objects()?
                && publication.source_fingerprint_kind
                    == if publication.verification_policy.is_full_content() {
                        crate::source_fingerprint::resource::FULL_KIND
                    } else {
                        crate::source_fingerprint::resource::EXTENT_KIND
                    },
            "partition publication resource/expected contract differs"
        );
        for value in [
            &publication.source_sha256,
            &publication.source_inspection_sha256,
            &publication.source_views_sha256,
            &publication.expected.semantic_sha256,
            &publication.ticket_sha256,
        ] {
            digest(value)?;
        }
        let mut locator = DurableRecoveryLocator::open_observed(
            Path::new(&publication.locator.path),
            digest(&publication.locator.sha256)?,
            scratch,
            publication.locator.bytes,
        )?;
        ensure!(
            locator.source_scope() == &publication.source_scope
                && locator.source() == &publication.source
                && locator.journal_binding() == expected_journal
                && locator.snapshot().file_bytes == publication.locator.bytes
                && hex::encode(Sha256::digest(serde_json::to_vec(locator.ticket())?))
                    == publication.ticket_sha256
                && locator.ticket().marker_profile.is_none()
                && locator.marker_use()
                    == n2r_win32::journal_file::MarkerStorageUse::QualifiedProduction,
            "foreign/mixed partition publication/locator/ticket scope"
        );
        publication
            .source_scope
            .require_journal_route(&publication.source, expected_journal)?;
        // Shadow remains independently owned. The new C:-sibling allowance
        // applies only between the selected source partition and its journal.
        ensure!(
            expected_journal.disk.disk_number != expected_shadow.disk_number
                && n2r_win32::layout::guid_bytes(&expected_journal.disk.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&expected_shadow.identity.disk_guid)?,
            "partition shadow and journal are not independent"
        );
        let expected = HeldFile::open(
            Path::new(&publication.expected.file.path),
            digest(&publication.expected.file.sha256)?,
            Some(publication.expected.file.bytes),
            publication.resource_admission.expected_pages.max_file_bytes,
            scratch,
        )?;
        ensure!(
            expected
                .snapshot
                .final_path
                .eq_ignore_ascii_case(&publication.expected.file.path)
                && publication.expected.binding.is_none(),
            "partition expected artifact same-handle canonical route differs"
        );
        let maps = if let Some(pin) = &publication.recovery_maps {
            ensure!(pin.records > 0, "empty partition recovery map refused");
            let held = HeldFile::open(
                Path::new(&pin.file.path),
                digest(&pin.file.sha256)?,
                Some(pin.file.bytes),
                publication.resource_admission.map_pages.max_file_bytes,
                scratch,
            )?;
            ensure!(
                held.snapshot
                    .final_path
                    .eq_ignore_ascii_case(&pin.file.path),
                "partition recovery map same-handle canonical route differs"
            );
            Some(held)
        } else {
            None
        };
        ensure!(
            locator
                .snapshot()
                .final_path
                .eq_ignore_ascii_case(&publication.locator.path),
            "partition locator same-handle canonical route differs"
        );
        let (mut journal, _) = BoundNativeRecoveryJournal::open(
            locator.journal_path(),
            expected_journal,
            locator.journal_profile()?,
            locator.ticket(),
            None,
            locator.marker_use(),
        )?;
        {
            let (_, facts) = journal.split_for_observation()?;
            ensure!(
                facts.binding == locator.journal_binding()
                    && *facts.identity == locator.journal_identity()
                    && facts.path == locator.journal_path()
                    && facts.profile == locator.journal_profile()?
                    && facts.marker_use == locator.marker_use()
                    && facts.marker_native_qualified.is_none(),
                "actual partition journal owner differs from authenticated locator"
            );
        }
        ensure!(
            explicit.partition_native_metadata()?.budget
                == publication.resource_admission.native_observation_budget()?,
            "restart native metadata budget differs from authenticated resource admission"
        );
        let intent = explicit.preparation_guard()?;
        let held_intent = HeldFile::open(
            Path::new(&intent.intent_file.final_path),
            digest(&intent.intent_prefix_sha256)?,
            Some(intent.intent_file.file_bytes),
            16 * 1024 * 1024,
            scratch,
        )?;
        let held_native = HeldFile::open(
            Path::new(&explicit.partition_native_metadata()?.path),
            digest(&explicit.partition_native_metadata()?.sha256)?,
            Some(explicit.partition_native_metadata()?.bytes),
            explicit
                .partition_native_metadata()?
                .budget
                .pages
                .max_file_bytes,
            scratch,
        )?;
        let ticket = locator.ticket();
        let actual_origin = {
            let (_, facts) = journal.split_for_observation()?;
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
            n2r_win32::partition_restoration::PartitionRecoveredOrigin::open_authenticated(
                owner,
                observation_budget,
                n2r_win32::partition_restoration::PartitionRestartFiles {
                    publication: publication_file.file.try_clone()?,
                    locator: locator.duplicate_readonly_origin_file()?,
                    preparation_intent: held_intent.file.try_clone()?,
                    native_metadata: held_native.file.try_clone()?,
                },
                independently_supplied_sha256,
                &pins,
                events,
            )?
        };
        ensure!(
            actual_origin.owner_token().same_owner(stable)
                && actual_origin.binding() == owner.binding()
                && *actual_origin.original_pin()
                    == serde_json::to_value(explicit.preparation_guard()?)?,
            "actual held restart origin differs from publication guard/owner"
        );
        let volume = expected_journal.disk.volume_path()?;
        let index_parent = hold_index_parent(index_path, &volume)?;
        let mut artifacts = vec![
            &publication_file.snapshot,
            &expected.snapshot,
            locator.snapshot(),
        ];
        if let Some(maps) = &maps {
            artifacts.push(&maps.snapshot);
        }
        require_partition_artifact_volume(
            owner,
            &publication.source_scope,
            &mut journal,
            &artifacts,
            events,
        )?;
        let mut observation = BoundJournalObservation::open(
            &mut journal,
            locator.ticket(),
            group,
            scratch,
            index_path,
            maximum_index_bytes,
        )?;
        let lifecycle = observation.lifecycle()?;
        let closed = match lifecycle {
            SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent => None,
            SelectedLifecycle::Handoff | SelectedLifecycle::Aborted => {
                let kind = if lifecycle == SelectedLifecycle::Handoff {
                    n2r_win32::PartitionTerminalKind::Handoff
                } else {
                    n2r_win32::PartitionTerminalKind::Aborted
                };
                let policy = observation.observation.index.clone();
                let index = observation.observation.index_lease.clone();
                let ticket = observation.observation.ticket;
                let facts = &observation.facts;
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
                let witness = n2r_win32::authenticate_partition_closed_journal(
                    owner,
                    &policy,
                    observation.observation.journal.markerless_recovery_file()?,
                    &pins,
                    kind,
                    events,
                )?;
                Some((witness, policy, index))
            }
            _ => anyhow::bail!(
                "clear/foreign lifecycle cannot issue private AP replay or closed terminal finalization"
            ),
        };
        if closed.is_none() {
            observation.retire()?;
        } else {
            drop(observation);
        }

        let recovery = Self {
            publication,
            publication_file,
            expected,
            maps,
            locator,
            journal,
            index_parent,
            scratch: scratch.clone(),
            _memory: memory,
            restarted_origin: Some(actual_origin),
        };
        Ok(match closed {
            Some((closed, policy, index)) => ReopenedPartitionRestart::Closed(
                PartitionClosedTerminal::from_actual(recovery, closed, policy, index),
            ),
            None => ReopenedPartitionRestart::Replay(recovery),
        })
    }

    /// Narrow issuer: actual held files, locator, J and actual SDK guard are
    /// retained through the callback. No public DTO constructor or writer.
    pub(crate) fn with_mixed_observation<T>(
        &mut self,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        admission: &mut n2r_win32::partition_lifecycle::PartitionNtfsAdmission,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
        action: impl FnOnce(
            &mut BoundJournalObservation<'_>,
            &mut PartitionRecoveryPublicationBinding<'_>,
            &mut n2r_win32::PartitionScopedOwner,
            &n2r_win32::PartitionOwnerToken,
            &mut Vec<NativeEvent>,
        ) -> Result<T>,
    ) -> Result<T> {
        self.publication_file.revalidate(&self.scratch)?;
        self.expected.revalidate(&self.scratch)?;
        if let Some(maps) = &mut self.maps {
            maps.revalidate(&self.scratch)?;
        }
        self.locator.revalidate()?;
        self.journal.revalidate()?;
        let scope = &self.publication.source_scope;
        scope.require_partition()?;
        let actual_guard = scope
            .preparation_guard()?
            .require_actual(admission, owner, stable, events)?;
        let volume = self.locator.journal_binding().disk.volume_path()?;
        let _same_output = hold_index_parent(index_path, &volume)?;
        // Retain original output directory ownership as well as the new
        // actual parent; neither directory path creates source authority.
        ensure!(
            self.index_parent.metadata()?.is_dir(),
            "held scoped output parent lost"
        );
        let mut artifacts = vec![
            &self.publication_file.snapshot,
            &self.expected.snapshot,
            self.locator.snapshot(),
        ];
        if let Some(maps) = &self.maps {
            artifacts.push(&maps.snapshot);
        }
        require_partition_artifact_volume(
            owner,
            &self.publication.source_scope,
            &mut self.journal,
            &artifacts,
            events,
        )?;
        let actual_ticket = self.locator.ticket().clone();
        let mut observation = BoundJournalObservation::open(
            &mut self.journal,
            &actual_ticket,
            group,
            &self.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        let expected_lifecycle = observation.lifecycle()?;
        ensure!(
            matches!(
                expected_lifecycle,
                SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
            ),
            "HND/ABT/clear cannot enter partition MIXED callback"
        );
        let journal_owner = std::ptr::from_ref(&*observation.observation.journal) as usize;
        // The scanner uses an independently owned ticket value so the actual
        // locator can still revalidate through its original held file.
        let mut binding = PartitionRecoveryPublicationBinding {
            publication: &self.publication,
            publication_file: &mut self.publication_file,
            expected: &mut self.expected,
            maps: self.maps.as_mut(),
            locator: &mut self.locator,
            scratch: &self.scratch,
            scope: AuthenticatedPartitionRecoveryScope {
                source: scope
                    .partition_binding()
                    .context("partition source binding absent")?
                    .clone(),
                actual_guard: serde_json::to_value(actual_guard)?,
            },
            actual_journal_owner: journal_owner,
            actual_origin: PartitionRecoveryOrigin::Live(admission),
        };
        let result = action(&mut observation, &mut binding, owner, stable, events);
        // Always close actual owner/J/artifact boundaries on callback errors.
        let closing = binding.revalidate_partition_mixed(
            owner,
            stable,
            observation.observation.journal,
            &observation.facts,
            observation.observation.ticket,
            events,
        );
        let lifecycle_closing = (|| -> Result<()> {
            ensure!(
                observation.lifecycle()? == expected_lifecycle,
                "actual partition lifecycle changed around scoped callback"
            );
            Ok(())
        })();
        let retiring = observation.retire();
        match (result, closing, lifecycle_closing, retiring) {
            (Ok(value), Ok(()), Ok(()), Ok(())) => Ok(value),
            (Err(error), _, _, _) => Err(error),
            (_, Err(error), _, _) | (_, _, Err(error), _) | (_, _, _, Err(error)) => Err(error),
        }
    }
}

impl PartitionRecoveryPublicationBinding<'_> {
    pub(super) fn publication_owner_identity(&self) -> usize {
        std::ptr::from_ref(&*self.publication_file) as usize
    }

    /// Read-only revalidation through the same live owners on both sides of
    /// the complete MIXED scan. This method issues no native writer.
    pub(super) fn revalidate_partition_mixed(
        &mut self,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        journal: &mut crate::general_reconstruct::selected_native_journal::NativeSelectedJournal,
        facts: &crate::general_reconstruct::selected_native_journal::BoundNativeJournalFacts<'_>,
        ticket: &crate::selected_journal::SelectedTicket,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        owner.revalidate(events)?;
        ensure!(
            stable.same_owner(&owner.owner_token())
                && owner.binding() == &self.scope.source
                && n2r_win32::PartitionScopedOwner::byte_len(owner) == ticket.image_length
                && self.publication.source == self.scope.source.storage
                && self.locator.source() == &self.scope.source.storage
                && std::ptr::from_ref(&*journal) as usize == self.actual_journal_owner,
            "partition MIXED observation lost actual owner/publication/journal association"
        );
        let explicit = &self.publication.source_scope;
        explicit.require_partition()?;
        ensure!(
            self.locator.source_scope() == &self.publication.source_scope,
            "partition publication/locator scope differs"
        );
        let actual = self
            .actual_origin
            .require_actual(explicit, owner, stable, events)?;
        ensure!(
            actual == self.scope.actual_guard,
            "actual complete partition guard changed after publication binding"
        );
        self.publication_file.revalidate(self.scratch)?;
        self.expected.revalidate(self.scratch)?;
        if let Some(maps) = self.maps.as_deref_mut() {
            maps.revalidate(self.scratch)?;
        }
        self.locator.revalidate()?;
        let encoded = serde_json::to_vec(ticket)?;
        let locator_ticket = serde_json::to_vec(self.locator.ticket())?;
        ensure!(
            encoded.len() <= 4096
                && encoded == locator_ticket
                && self.publication.ticket_sha256 == hex::encode(Sha256::digest(&encoded))
                && ticket.marker_profile.is_none()
                && facts.marker_native_qualified.is_none()
                && self.locator.journal_binding() == facts.binding
                && self.locator.journal_identity() == *facts.identity
                && self.locator.journal_profile()?.version() == facts.profile.version()
                && facts.journal_length == ticket.journal_length,
            "partition MIXED publication/locator/actual journal ticket binding differs"
        );
        // The same held FILE_OBJECT is inspected. Paths and JSON are never
        // reopened here to manufacture identity or replay permission.
        let file = journal.markerless_recovery_file()?;
        let before = n2r_win32::journal_file::observe_general_journal_file_with_profile(
            file,
            facts.binding,
            facts.profile,
        )?;
        let modified = file.metadata()?.modified()?;
        ensure!(
            before.identity == *facts.identity
                && before.file_bytes == ticket.journal_length
                && before
                    .final_path
                    .eq_ignore_ascii_case(&facts.path.to_string_lossy())
                && ticket.journal_length >= 8192
                && n2r_win32::sha256_native::hash_range(file, 8192, ticket.journal_length - 8192,)?
                    == ticket.immutable_sha256,
            "partition MIXED held journal identity/body differs"
        );
        let after = n2r_win32::journal_file::observe_general_journal_file_with_profile(
            file,
            facts.binding,
            facts.profile,
        )?;
        ensure!(
            after.identity == before.identity
                && after.file_bytes == before.file_bytes
                && after.final_path.eq_ignore_ascii_case(&before.final_path)
                && file.metadata()?.modified()? == modified,
            "partition MIXED held journal changed during revalidation"
        );
        owner.revalidate(events)?;
        ensure!(
            stable.same_owner(&owner.owner_token()) && owner.binding() == &self.scope.source,
            "partition MIXED owner changed around publication/journal revalidation"
        );
        Ok(())
    }
}

/// A non-serializable observation of an actual durable HND and selected target
/// digest. It retains the reopened publication, real journal and offline target
/// through the borrow; it does not itself authorize a mount.
pub(crate) struct VerifiedResourceHandoff<'a> {
    recovery: &'a mut ReopenedResourceRecovery,
    selected_sha256: [u8; 32],
}

/// Actual HND target resealed OFFLINE|READ_ONLY for the SDK's physically
/// protected converted-filesystem observer. This is not writable-service or
/// converted-namespace qualification.
pub(crate) struct VerifiedProtectedHandoff<'a> {
    recovery: &'a mut ReopenedResourceRecovery,
    selected_sha256: [u8; 32],
}

pub(crate) struct ResourceReplayResult {
    pub selected: crate::selected_journal::SelectedResult,
    pub handoff: Option<crate::selected_journal::SelectedResult>,
}

impl<'a> VerifiedResourceHandoff<'a> {
    pub(crate) fn recovery(&self) -> &ReopenedResourceRecovery {
        self.recovery
    }
    pub(crate) fn selected_sha256(&self) -> [u8; 32] {
        self.selected_sha256
    }

    /// Reseal the actual HND source for a physically read-only ReFS observer.
    /// This keeps normal writable service closed until that observer and the
    /// separate expected/map comparison have succeeded.
    pub(crate) fn seal_for_protected_verification(
        self,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<VerifiedProtectedHandoff<'a>> {
        let recovery = self.recovery;
        recovery.revalidate(events)?;
        ensure!(
            recovery.initial_lifecycle == SelectedLifecycle::Handoff
                && self.selected_sha256 == recovery.locator.ticket().new_selected_sha256,
            "actual retained HND witness differs"
        );
        let volume = recovery.locator.journal_binding().disk.volume_path()?;
        let _index_parent = hold_index_parent(index_path, &volume)?;
        let mut bound = BoundJournalObservation::open(
            &mut recovery.journal,
            recovery.locator.ticket(),
            group,
            &recovery.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        ensure!(
            bound.lifecycle()? == SelectedLifecycle::Handoff,
            "actual held journal no longer reports HND"
        );
        let BoundJournalObservation {
            mut observation,
            facts,
        } = bound;
        let ticket = observation.ticket;
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
        let policy = observation.index.clone();
        let target = recovery
            .target
            .take()
            .context("handoff target was already consumed")?;
        let result = {
            let journal = observation.journal.markerless_recovery_file()?;
            match target {
                ObservedTarget::Activated(target) => {
                    target.seal_paged_handoff_for_observation(&policy, journal, &pins, events)
                }
                ObservedTarget::Frozen(target) => Ok(target),
            }
        };
        let source = result.context("handoff read-only reseal stopped; reopen the excluded source before any further action")?;
        drop(policy);
        observation.retire()?;
        let after = source.state(events)?;
        ensure!(
            after.disk_attributes == 3,
            "handoff source did not remain offline and read-only"
        );
        recovery.initial_state = after;
        recovery.target = Some(ObservedTarget::Frozen(source));
        recovery.revalidate(events)?;
        Ok(VerifiedProtectedHandoff {
            recovery,
            selected_sha256: self.selected_sha256,
        })
    }
}

impl<'a> VerifiedProtectedHandoff<'a> {
    pub(crate) fn recovery(&self) -> &ReopenedResourceRecovery {
        self.recovery
    }
    pub(crate) fn selected_sha256(&self) -> [u8; 32] {
        self.selected_sha256
    }
    /// The SDK source exposes only the physically read-only observer route;
    /// any fresh apply still requires a different actual clear journal/owner.
    pub(crate) fn source_mut(&mut self) -> Result<&mut GeneralFrozenPartition> {
        ensure!(
            self.recovery.initial_lifecycle == SelectedLifecycle::Handoff,
            "protected converted observation requires durable HND"
        );
        match self
            .recovery
            .target
            .as_mut()
            .context("protected HND source was consumed")?
        {
            ObservedTarget::Frozen(source) => Ok(source),
            ObservedTarget::Activated(_) => {
                anyhow::bail!("protected HND source is not sealed read-only")
            }
        }
    }

    /// Enable ordinary writable service only after the same actual protected
    /// native observation and exact reopened-map comparison have succeeded.
    /// HND, journal/index and selected NEW bytes are checked again at the
    /// native transition; no saved Boolean supplies this capability.
    pub(crate) fn bring_online_after_verified_observation(
        self,
        observation: &n2r_win32::GeneralLiveConvertedObservation,
        map_proof: &crate::general_reconstruct::fast_verification::v4_maps::reopened::VerifiedMapComparison<'_>,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<&'a mut ReopenedResourceRecovery> {
        map_proof.require_same(&self, observation)?;
        let mut expected_readonly = self.recovery.initial_state.clone();
        expected_readonly.disk_attributes = 2;
        let report = observation.report();
        let content = report
            .content_observation
            .as_ref()
            .context("protected native content observation absent")?;
        let known = content
            .known_content
            .as_ref()
            .context("protected known-content proof absent")?;
        ensure!(
            self.recovery.initial_lifecycle == SelectedLifecycle::Handoff
                && self.selected_sha256 == self.recovery.locator.ticket().new_selected_sha256
                && observation.before() == &self.recovery.initial_state
                && observation.after() == &self.recovery.initial_state
                && observation.observed_readonly() == &expected_readonly
                && self.recovery.initial_state.disk_attributes == 3
                && report.pair.source == self.recovery.publication.source
                && report.pair.shadow == self.recovery.publication.shadow
                && report.native.binding.identity == self.recovery.publication.source.identity
                && !report.conversion_qualified
                && content.metadata_and_namespace_verified
                && content.complete_stream_mappings_observed
                && content.data_storage_validity_checked
                && !content.full_file_hashes
                && known
                    .streams_hashed
                    .checked_add(known.streams_without_content_baseline)
                    == Some(usize::try_from(
                        self.recovery.publication.resource_admission.data_streams
                    )?)
                && known.payload_bytes_read == content.admitted_payload_bytes_read,
            "actual protected converted observation or known-content coverage differs"
        );
        let native_observation = observation;
        let recovery = self.recovery;
        recovery.revalidate(events)?;
        let volume = recovery.locator.journal_binding().disk.volume_path()?;
        let _index_parent = hold_index_parent(index_path, &volume)?;
        let mut bound = BoundJournalObservation::open(
            &mut recovery.journal,
            recovery.locator.ticket(),
            group,
            &recovery.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        ensure!(
            bound.lifecycle()? == SelectedLifecycle::Handoff,
            "actual held journal no longer reports HND"
        );
        let BoundJournalObservation {
            mut observation,
            facts,
        } = bound;
        let ticket = observation.ticket;
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
        let policy = observation.index.clone();
        let target = recovery
            .target
            .take()
            .context("verified protected source was already consumed")?;
        let transition = {
            let journal = observation.journal.markerless_recovery_file()?;
            match target {
                ObservedTarget::Frozen(target) => target.bring_online_after_paged_handoff(
                    &policy,
                    journal,
                    &pins,
                    native_observation,
                    events,
                ),
                ObservedTarget::Activated(_) => {
                    anyhow::bail!("verified protected source lost its readonly owner")
                }
            }
        };
        drop(policy);
        let index_retirement = observation.retire();
        transition.context("verified HND online transition stopped; source may already be online and must be rediscovered")?;
        let mounted = n2r_win32::rediscover_general_volume_wait(
            recovery.publication.source.clone(),
            events,
        )
        .context(
            "verified HND source may be online but its ReFS volume could not be rediscovered",
        )?;
        n2r_win32::volume_label::validate_original_partition(
            &recovery.publication.source,
            &mounted,
        )?;
        recovery.mounted = Some(mounted);
        index_retirement
            .context("HND source is online but temporary authenticated-index retirement failed")?;
        recovery.revalidate_handoff_artifacts_after_mount(events)?;
        Ok(recovery)
    }
}

impl ReopenedResourceRecovery {
    /// The publication checksum must come from independently retained trusted
    /// storage, never from the adjacent checksum file alone. `index_path` is a
    /// fresh temporary artifact on the actual journal volume.
    pub(crate) fn open_observed(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        expected_pair: &GeneralSourceShadowBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        Self::open_observed_impl(
            path,
            independently_supplied_sha256,
            maximum_publication_bytes,
            expected_pair,
            expected_journal,
            group,
            scratch,
            index_path,
            maximum_index_bytes,
            events,
            false,
        )
    }

    /// Also admit a terminal HND/ABT that is already online. This observes
    /// the real journal first and never grants replay on a mounted source.
    pub(crate) fn open_observed_or_online_terminal(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        expected_pair: &GeneralSourceShadowBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        Self::open_observed_impl(
            path,
            independently_supplied_sha256,
            maximum_publication_bytes,
            expected_pair,
            expected_journal,
            group,
            scratch,
            index_path,
            maximum_index_bytes,
            events,
            true,
        )
    }

    fn open_observed_impl(
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        expected_pair: &GeneralSourceShadowBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
        allow_online_terminal: bool,
    ) -> Result<Self> {
        ensure!(
            group.group() == ArtifactGroup::RecoveryCopy
                && maximum_publication_bytes > 0
                && maximum_publication_bytes <= scratch.budget().record_bytes,
            "reopened publication needs its bounded recovery arena"
        );
        let same = scratch
            .artifact_group()
            .context("recovery scratch has no arena")?;
        ensure!(
            same.group() == group.group() && same.arena().same_arena(group.arena()),
            "recovery scratch and group differ"
        );
        let size = std::fs::symlink_metadata(path)?.len();
        let reserve = size
            .checked_mul(4)
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .and_then(|n| n.checked_add(GeneralFrozenPartition::read_buffer_memory_bytes()))
            .context("reopened publication RAM overflow")?;
        ensure!(
            size > 0 && size <= maximum_publication_bytes,
            "recovery publication exceeds admission"
        );
        let memory = scratch.lease_ram(reserve)?;
        n2r_win32::perf::step("reopen publication and locator");
        let mut publication_file = HeldFile::open(
            path,
            independently_supplied_sha256,
            Some(size),
            maximum_publication_bytes,
            scratch,
        )?;
        publication_file.file.seek(SeekFrom::Start(0))?;
        let publication: Publication = serde_json::from_reader(&mut publication_file.file)?;
        let mut canonical = HashSink {
            bytes: 0,
            maximum: size,
            hash: Sha256::new(),
        };
        serde_json::to_writer(&mut canonical, &publication)?;
        ensure!(
            canonical.bytes == size
                && <[u8; 32]>::from(canonical.hash.finalize()) == independently_supplied_sha256,
            "recovery publication is not the original canonical encoding"
        );
        ensure!(
            publication.source_scope.is_dedicated(),
            "partition publication requires the explicit actual-owner/held-guard recovery path"
        );
        publication.resource_admission.validate()?;
        ensure!(
            publication.source == expected_pair.source
                && publication.shadow == expected_pair.shadow,
            "recovery publication differs from the independently pinned request"
        );
        GeneralSourceShadowBinding {
            source: publication.source.clone(),
            shadow: publication.shadow.clone(),
        }
        .validate_with_resource_profile(Some(ResourceProfile::ResourceBoundedV4(Some(
            publication.resource_admission,
        ))))?;
        publication.expected_source_label.validate()?;
        ensure!(
            publication.schema_version == 1
                && publication.kind == "resource-allocation-recovery-envelope-v1"
                && !publication.serialized_publication_grants_authority
                && publication.source_inspection_sha256
                    == hex::encode(publication.resource_admission.source_inspection_sha256)
                && publication.expected.objects == publication.resource_admission.objects()?
                && publication.source_fingerprint_kind
                    == if publication.verification_policy.is_full_content() {
                        crate::source_fingerprint::resource::FULL_KIND
                    } else {
                        crate::source_fingerprint::resource::EXTENT_KIND
                    },
            "recovery publication profile or source facts differ"
        );
        for value in [
            &publication.source_sha256,
            &publication.source_inspection_sha256,
            &publication.source_views_sha256,
            &publication.expected.semantic_sha256,
            &publication.ticket_sha256,
        ] {
            digest(value)?;
        }
        let locator_sha = digest(&publication.locator.sha256)?;
        let locator = DurableRecoveryLocator::open_observed(
            Path::new(&publication.locator.path),
            locator_sha,
            scratch,
            publication.locator.bytes,
        )?;
        ensure!(
            locator.snapshot().file_bytes == publication.locator.bytes
                && locator.source() == &publication.source
                && locator.journal_binding() == expected_journal,
            "held recovery locator and publication differ"
        );
        let volume = locator.journal_binding().disk.volume_path()?;
        ensure!(
            on_volume(&publication_file.snapshot.final_path, &volume)
                && on_volume(&locator.snapshot().final_path, &volume)
                && locator.journal_binding().disk.disk_number != publication.shadow.disk_number
                && n2r_win32::layout::guid_bytes(
                    &locator.journal_binding().disk.identity.disk_guid
                )? != n2r_win32::layout::guid_bytes(&publication.shadow.identity.disk_guid)?,
            "recovery artifacts are not on the independent journal volume"
        );
        n2r_win32::perf::step("reopen expected pages, maps and alias records");
        let mut expected = HeldFile::open(
            Path::new(&publication.expected.file.path),
            digest(&publication.expected.file.sha256)?,
            Some(publication.expected.file.bytes),
            publication.resource_admission.expected_pages.max_file_bytes,
            scratch,
        )?;
        ensure!(
            expected
                .snapshot
                .final_path
                .eq_ignore_ascii_case(&publication.expected.file.path)
                && on_volume(&expected.snapshot.final_path, &volume),
            "reopened expected pages route differs"
        );
        hold_expected_binding(&publication, &volume, &mut expected, scratch)
            .context("reopening the expected-tree binding")?;
        let maps = if let Some(pin) = &publication.recovery_maps {
            ensure!(pin.records > 0, "empty V4 recovery map is invalid");
            let held = HeldFile::open(
                Path::new(&pin.file.path),
                digest(&pin.file.sha256)?,
                Some(pin.file.bytes),
                publication.resource_admission.map_pages.max_file_bytes,
                scratch,
            )?;
            ensure!(
                held.snapshot
                    .final_path
                    .eq_ignore_ascii_case(&pin.file.path)
                    && on_volume(&held.snapshot.final_path, &volume),
                "reopened recovery-map route differs"
            );
            Some(held)
        } else {
            None
        };
        let windows_aliases = open_windows_alias_files(&publication, &volume, &expected, scratch)
            .context("reopening the Windows alias records")?;
        ensure!(
            locator
                .snapshot()
                .final_path
                .eq_ignore_ascii_case(&publication.locator.path),
            "reopened locator route differs"
        );
        let ticket_bytes = serde_json::to_vec(locator.ticket())?;
        ensure!(
            ticket_bytes.len() <= 4096
                && <[u8; 32]>::from(Sha256::digest(&ticket_bytes))
                    == digest(&publication.ticket_sha256)?,
            "recovery locator ticket and publication differ"
        );
        let identity = locator.journal_identity();
        let marker_identity = locator
            .ticket()
            .marker_profile
            .is_some()
            .then_some(&identity);
        n2r_win32::perf::step("reopen journal");
        let (mut journal, _) = BoundNativeRecoveryJournal::open(
            locator.journal_path(),
            locator.journal_binding(),
            locator.journal_profile()?,
            locator.ticket(),
            marker_identity,
            locator.marker_use(),
        )
        .with_context(|| format!("reopening the recovery journal {}", locator.journal_path().display()))?;
        {
            let (_, facts) = journal.split_for_observation()?;
            ensure!(
                facts.binding == locator.journal_binding()
                    && *facts.identity == identity
                    && facts.path == locator.journal_path()
                    && facts.profile == locator.journal_profile()?
                    && facts.marker_use == locator.marker_use()
                    && facts.marker_native_qualified == locator.marker_native_qualified(),
                "native journal owner and published locator differ"
            );
        }
        let _index_parent = hold_index_parent(index_path, &volume)
            .with_context(|| format!("holding the directory of {}", index_path.display()))?;
        n2r_win32::perf::step("scan journal");
        let mut observation = BoundJournalObservation::open(
            &mut journal,
            locator.ticket(),
            group,
            scratch,
            index_path,
            maximum_index_bytes,
        )
        .context("observing the reopened recovery journal")?;
        let initial_lifecycle = observation.lifecycle()?;
        n2r_win32::perf::step("retire journal index");
        observation.retire()?;
        n2r_win32::perf::step("reopen converted source");
        let online = if allow_online_terminal
            && matches!(
                initial_lifecycle,
                SelectedLifecycle::Handoff | SelectedLifecycle::Aborted
            ) {
            let state =
                n2r_win32::observe_general_disk_state_readonly(publication.source.clone(), events)?;
            if state.disk_attributes == 0 {
                let mounted =
                    n2r_win32::rediscover_general_volume_wait(publication.source.clone(), events)?;
                n2r_win32::volume_label::validate_original_partition(
                    &publication.source,
                    &mounted,
                )?;
                let expected_fs = if initial_lifecycle == SelectedLifecycle::Handoff {
                    "ReFS"
                } else {
                    "NTFS"
                };
                ensure!(
                    n2r_win32::mounted_filesystem_general(mounted.clone(), events)? == expected_fs,
                    "online terminal source filesystem differs from durable lifecycle"
                );
                ensure!(
                    n2r_win32::observe_general_disk_state_readonly(mounted.clone(), events)?
                        == state,
                    "online terminal source identity changed during rediscovery"
                );
                Some((mounted, state))
            } else {
                None
            }
        } else {
            None
        };
        let (target, initial_state, mounted) = match online {
            Some((mounted, state)) => (None, state, Some(mounted)),
            None => {
                let target = ObservedTarget::reopen(publication.source.clone(), events)
                    .context("reopening the converted source partition")?;
                let state = target.state(events)?;
                ensure!(
                    matches!(state.disk_attributes, 1 | 3),
                    "reopened recovery source is not persistently offline"
                );
                (Some(target), state, None)
            }
        };
        n2r_win32::perf::step("reopen guards and revalidate");
        // AP/RB and terminal states are reachable only after the original
        // pre-AP cancellation guard was durably delegated. Never promote an
        // old Frozen record after AP merely because an envelope exists.
        // PreparedClear remains observable without mutating its guard; only
        // explicit clear abandonment below may retire it after restart.
        let (early_guard, early_guard_memory) = match (
            publication.early_preparation_guard.as_ref(),
            initial_lifecycle,
        ) {
            (Some(pin), lifecycle) if lifecycle != SelectedLifecycle::PreparedClear => {
                let memory =
                    scratch.lease_ram(guard_memory_bytes(pin, maximum_publication_bytes)?)?;
                let guard = crate::resource_preparation::early_guard::open_for_recovery(
                    pin,
                    Path::new(&publication_file.snapshot.final_path),
                    &hex::encode(publication_file.sha256),
                    expected_pair,
                    expected_journal,
                    false,
                    maximum_publication_bytes,
                    events,
                )?;
                (Some(guard), Some(memory))
            }
            _ => (None, None),
        };
        let mut recovered = Self {
            publication,
            publication_file,
            expected,
            maps,
            windows_aliases,
            locator,
            journal,
            target,
            initial_state,
            initial_lifecycle,
            mounted,
            early_guard,
            _early_guard_memory: early_guard_memory,
            scratch: scratch.clone(),
            _memory: memory,
        };
        // Complete the other side of the journal-scan boundary exactly once.
        // The expected and map files were hashed when opened, and remain held
        // while this rehash and the native lifecycle/state checks run.
        if recovered.mounted.is_some() {
            recovered.revalidate_online_terminal(events)?;
        } else {
            recovered.revalidate(events)?;
        }
        Ok(recovered)
    }

    /// Rechecks held files and the real excluded target; no raw writes occur.
    pub(crate) fn revalidate(&mut self, events: &mut Vec<NativeEvent>) -> Result<()> {
        self.publication_file.revalidate(&self.scratch)?;
        self.expected.revalidate(&self.scratch)?;
        if let Some(maps) = &mut self.maps {
            maps.revalidate(&self.scratch)?;
        }
        if let Some(aliases) = &mut self.windows_aliases {
            aliases.revalidate(&self.scratch)?;
        }
        self.locator.revalidate()?;
        self.journal.revalidate()?;
        if let Some(guard) = &mut self.early_guard {
            guard.require_delegated(
                Path::new(&self.publication_file.snapshot.final_path),
                &hex::encode(self.publication_file.sha256),
                events,
            )?;
        }
        let (journal, _) = self.journal.split_for_observation()?;
        ensure!(
            super::sj::classify(journal, self.locator.ticket())? == self.initial_lifecycle,
            "reopened journal lifecycle changed during observation"
        );
        ensure!(
            self.target
                .as_ref()
                .context("recovery target was consumed after a failed operation")?
                .state(events)?
                == self.initial_state,
            "reopened target exclusion or identity changed"
        );
        Ok(())
    }

    /// Legacy V4 publications have no guard reference. New publications must
    /// retain their actual already-delegated paired state before any replay.
    /// Frozen retirement is confined to the separate actual OLD proof callback
    /// inside clear abandonment below.
    fn require_preparation_guard_delegated(&mut self, events: &mut Vec<NativeEvent>) -> Result<()> {
        self.revalidate(events)?;
        if let Some(pin) = &self.publication.early_preparation_guard {
            if self.early_guard.is_none() {
                let maximum = self.scratch.budget().record_bytes;
                let memory = self.scratch.lease_ram(guard_memory_bytes(pin, maximum)?)?;
                let pair = GeneralSourceShadowBinding {
                    source: self.publication.source.clone(),
                    shadow: self.publication.shadow.clone(),
                };
                let guard = crate::resource_preparation::early_guard::open_for_recovery(
                    pin,
                    Path::new(&self.publication_file.snapshot.final_path),
                    &hex::encode(self.publication_file.sha256),
                    &pair,
                    self.locator.journal_binding(),
                    false,
                    maximum,
                    events,
                )?;
                self.early_guard = Some(guard);
                self._early_guard_memory = Some(memory);
            }
        }
        self.revalidate(events)
    }

    /// Recheck the still-held published artifacts and real HND journal after
    /// the source has crossed the online boundary. This never re-admits the
    /// old NTFS source and does not replace native ReFS/stream-map validation.
    pub(crate) fn revalidate_handoff_artifacts_after_mount(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> Result<GeneralDiskBinding> {
        ensure!(
            self.initial_lifecycle == SelectedLifecycle::Handoff,
            "online handoff revalidation requires durable HND"
        );
        self.revalidate_online_terminal(events)
    }

    /// Reauthenticate the actual terminal journal and physical partition
    /// while online. Never compare selected bytes: applications may have
    /// legitimately changed them after the terminal mount.
    pub(crate) fn revalidate_online_terminal(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> Result<GeneralDiskBinding> {
        ensure!(
            self.target.is_none()
                && matches!(
                    self.initial_lifecycle,
                    SelectedLifecycle::Handoff | SelectedLifecycle::Aborted
                ),
            "online artifact revalidation requires an actual terminal journal"
        );
        self.publication_file.revalidate(&self.scratch)?;
        self.expected.revalidate(&self.scratch)?;
        if let Some(maps) = &mut self.maps {
            maps.revalidate(&self.scratch)?;
        }
        if let Some(aliases) = &mut self.windows_aliases {
            aliases.revalidate(&self.scratch)?;
        }
        self.locator.revalidate()?;
        self.journal.revalidate()?;
        if let Some(guard) = &mut self.early_guard {
            guard.require_delegated(
                Path::new(&self.publication_file.snapshot.final_path),
                &hex::encode(self.publication_file.sha256),
                events,
            )?;
        }
        ensure!(
            self.locator.ticket().marker_profile.is_none(),
            "mounted V4 markerless terminal journal required"
        );
        let body_bytes = self
            .locator
            .ticket()
            .journal_length
            .checked_sub(super::BODY)
            .context("mounted terminal journal is shorter than its marker area")?;
        let immutable = self.locator.ticket().immutable_sha256;
        let _journal_hash_ram = self.scratch.lease_ram(4 * 1024 * 1024)?;
        let (journal, _) = self.journal.split_for_observation()?;
        ensure!(
            super::sj::classify(journal, self.locator.ticket())? == self.initial_lifecycle,
            "actual native terminal journal lifecycle changed"
        );
        ensure!(
            n2r_win32::sha256_native::journal_body(journal, super::BODY, body_bytes, &immutable)? == immutable,
            "mounted terminal journal immutable body changed"
        );
        ensure!(
            super::sj::classify(journal, self.locator.ticket())? == self.initial_lifecycle,
            "actual native terminal lifecycle changed during journal verification"
        );
        let mounted = self
            .mounted
            .as_ref()
            .context("mounted terminal source has not been rediscovered")?
            .clone();
        n2r_win32::volume_label::validate_original_partition(&self.publication.source, &mounted)?;
        let before = n2r_win32::observe_general_disk_state_readonly(mounted.clone(), events)?;
        ensure!(
            before.disk_attributes == 0,
            "terminal source is not online and writable"
        );
        let expected_fs = if self.initial_lifecycle == SelectedLifecycle::Handoff {
            "ReFS"
        } else {
            "NTFS"
        };
        ensure!(
            n2r_win32::mounted_filesystem_general(mounted.clone(), events)? == expected_fs,
            "actual terminal source filesystem differs from journal lifecycle"
        );
        let after = n2r_win32::observe_general_disk_state_readonly(mounted.clone(), events)?;
        ensure!(
            after == before,
            "mounted terminal source route changed during observation"
        );
        Ok(mounted)
    }

    /// Reconstruct the paged policy from the same fully authenticated native
    /// journal and replay only an already durable markerless AP/RB state. On
    /// every failure the source stays offline and this owner must be reopened;
    /// a successful HND/ABT returns with its raw write policy removed.
    pub(crate) fn replay_markerless<
        F: FnOnce(&crate::selected_journal::SelectedResult) -> Result<()>,
    >(
        &mut self,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        direction: PagedRecoveryDirection,
        after_resume: F,
        events: &mut Vec<NativeEvent>,
    ) -> Result<ResourceReplayResult> {
        self.revalidate(events)?;
        ensure!(
            match direction {
                PagedRecoveryDirection::Resume =>
                    self.initial_lifecycle == SelectedLifecycle::ApplyIntent,
                PagedRecoveryDirection::Rollback => matches!(
                    self.initial_lifecycle,
                    SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
                ),
            },
            "actual recovery lifecycle refuses requested replay"
        );
        self.require_preparation_guard_delegated(events)?;
        let volume = self.locator.journal_binding().disk.volume_path()?;
        let _index_parent = hold_index_parent(index_path, &volume)?;
        let observation = BoundJournalObservation::open(
            &mut self.journal,
            self.locator.ticket(),
            group,
            &self.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        let target = match self
            .target
            .take()
            .context("recovery target was previously consumed")?
        {
            ObservedTarget::Activated(target) => {
                super::replay::MarkerlessRecoveryTarget::Activated(target)
            }
            ObservedTarget::Frozen(source) => {
                super::replay::MarkerlessRecoveryTarget::Frozen(source)
            }
        };
        let replayed = observation.replay_markerless(
            target,
            self.locator.source(),
            direction,
            after_resume,
            events,
        ).context("resource replay stopped; reopen the excluded source and classify its actual journal before any further action")?;
        let after = replayed.target.state(events)?;
        ensure!(
            after.disk_attributes == 1,
            "replayed source is not persistently offline"
        );
        self.initial_state = after;
        self.target = Some(ObservedTarget::Activated(replayed.target));
        self.initial_lifecycle = match direction {
            PagedRecoveryDirection::Resume => SelectedLifecycle::Handoff,
            PagedRecoveryDirection::Rollback => SelectedLifecycle::Aborted,
        };
        self.revalidate(events)?;
        Ok(ResourceReplayResult {
            selected: replayed.selected,
            handoff: replayed.handoff,
        })
    }

    /// Re-authenticate the actual journal and the selected postimage while
    /// retaining the excluded source. This does not mount or claim that the
    /// retained file-data extents or the ReFS namespace have been verified.
    pub(crate) fn verify_handoff<'a>(
        &'a mut self,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<VerifiedResourceHandoff<'a>> {
        self.revalidate(events)?;
        ensure!(
            self.initial_lifecycle == SelectedLifecycle::Handoff,
            "durable HND required"
        );
        let volume = self.locator.journal_binding().disk.volume_path()?;
        let _index_parent = hold_index_parent(index_path, &volume)?;
        let mut observation = BoundJournalObservation::open(
            &mut self.journal,
            self.locator.ticket(),
            group,
            &self.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        let target = self
            .target
            .as_mut()
            .context("recovery target was consumed")?;
        let before = target.state(events)?;
        ensure!(
            matches!(before.disk_attributes, 1 | 3),
            "handoff source is not persistently offline"
        );
        let selected_sha256 = match &mut *target {
            ObservedTarget::Activated(target) => {
                ensure!(
                    target.binding() == self.locator.source(),
                    "handoff source binding differs"
                );
                let length = target.byte_len();
                observation.verify_handoff_data(target, length)?
            }
            ObservedTarget::Frozen(target) => {
                ensure!(
                    target.binding() == self.locator.source(),
                    "handoff source binding differs"
                );
                let length = target.byte_len();
                observation.verify_handoff_data(target, length)?
            }
        };
        ensure!(
            target.state(events)? == before,
            "handoff source identity or exclusion changed"
        );
        observation.retire()?;
        self.revalidate(events)?;
        Ok(VerifiedResourceHandoff {
            recovery: self,
            selected_sha256,
        })
    }

    /// Abandon an actual clear publication with its unchanged OLD source. No
    /// source bytes are written; ABT is durable before the source is exposed.
    pub(crate) fn abandon_clear(
        &mut self,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        self.revalidate(events)?;
        ensure!(
            self.initial_lifecycle == SelectedLifecycle::PreparedClear,
            "clear abandonment requires the actual clear lifecycle"
        );
        // Reserve and bind the guard work before borrowing the actual journal.
        // Its only possible mutable transition is invoked below, after that
        // same held journal and source have passed complete clear/OLD checks.
        let guard_pin = self.publication.early_preparation_guard.as_ref();
        let maximum = self.scratch.budget().record_bytes;
        let mut guard_memory = if self.early_guard.is_none() {
            guard_pin
                .map(|pin| self.scratch.lease_ram(guard_memory_bytes(pin, maximum)?))
                .transpose()?
        } else {
            None
        };
        let pair = GeneralSourceShadowBinding {
            source: self.publication.source.clone(),
            shadow: self.publication.shadow.clone(),
        };
        let publication = Path::new(&self.publication_file.snapshot.final_path);
        let publication_sha = hex::encode(self.publication_file.sha256);
        let early_guard = &mut self.early_guard;
        let retained_guard_memory = &mut self._early_guard_memory;
        let volume = self.locator.journal_binding().disk.volume_path()?;
        let _index_parent = hold_index_parent(index_path, &volume)?;
        let mut observation = BoundJournalObservation::open(
            &mut self.journal,
            self.locator.ticket(),
            group,
            &self.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        let target = self.target.as_mut().context("clear source was consumed")?;
        let before = target.state(events)?;
        ensure!(
            matches!(before.disk_attributes, 1 | 3),
            "clear source is not offline"
        );
        let delegate_before_abort = || -> Result<()> {
            if let Some(pin) = guard_pin {
                if early_guard.is_none() {
                    let guard = crate::resource_preparation::early_guard::open_for_recovery(
                        pin,
                        publication,
                        &publication_sha,
                        &pair,
                        self.locator.journal_binding(),
                        true,
                        maximum,
                        events,
                    )?;
                    *early_guard = Some(guard);
                    *retained_guard_memory = guard_memory.take();
                }
                early_guard
                    .as_mut()
                    .context("clear preparation guard was not retired")?
                    .require_delegated(publication, &publication_sha, events)?;
            }
            Ok(())
        };
        match &mut *target {
            ObservedTarget::Activated(source) => {
                let length = source.byte_len();
                observation.abandon_clear_data_with_before_abort(
                    source,
                    length,
                    delegate_before_abort,
                )?;
            }
            ObservedTarget::Frozen(source) => {
                let length = source.byte_len();
                observation.abandon_clear_data_with_before_abort(
                    source,
                    length,
                    delegate_before_abort,
                )?;
            }
        }
        ensure!(
            target.state(events)? == before,
            "clear source changed during abandonment"
        );
        observation.retire()?;
        self.initial_lifecycle = SelectedLifecycle::Aborted;
        self.revalidate(events)?;
        Ok(())
    }

    /// Recheck actual ABT, restore-required bytes and free-granule admissibility
    /// on the held offline device, then consume that same owner via the native
    /// rollback gate. This does not claim byte-for-byte restoration of free space.
    pub(crate) fn restore_aborted(
        &mut self,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
    ) -> Result<GeneralDiskBinding> {
        self.revalidate(events)?;
        ensure!(
            self.initial_lifecycle == SelectedLifecycle::Aborted,
            "durable ABT required"
        );
        self.require_preparation_guard_delegated(events)?;
        let volume = self.locator.journal_binding().disk.volume_path()?;
        let _index_parent = hold_index_parent(index_path, &volume)?;
        let mut bound = BoundJournalObservation::open(
            &mut self.journal,
            self.locator.ticket(),
            group,
            &self.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        let target = self
            .target
            .as_mut()
            .context("rollback target was consumed")?;
        let before = target.state(events)?;
        ensure!(
            matches!(before.disk_attributes, 1 | 3),
            "rollback source is not offline"
        );
        match &mut *target {
            ObservedTarget::Activated(source) => {
                let length = source.byte_len();
                bound.verify_aborted_data(source, length)?;
            }
            ObservedTarget::Frozen(source) => {
                let length = source.byte_len();
                bound.verify_aborted_data(source, length)?;
            }
        }
        ensure!(
            target.state(events)? == before,
            "rollback source changed during validation"
        );
        let BoundJournalObservation {
            mut observation,
            facts,
        } = bound;
        let ticket = observation.ticket;
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
        let policy = observation.index.clone();
        let target = self.target.take().context("rollback target was consumed")?;
        let transition = {
            let journal = observation.journal.markerless_recovery_file()?;
            match target {
                ObservedTarget::Activated(target) => {
                    target.bring_online_after_paged_abort(&policy, journal, &pins, events)
                }
                ObservedTarget::Frozen(target) => {
                    target.bring_online_after_paged_abort(&policy, journal, &pins, events)
                }
            }
        };
        drop(policy);
        let retirement = observation.retire();
        transition.context(
            "ABT online transition stopped; source may already be online and must be rediscovered",
        )?;
        let mounted =
            n2r_win32::rediscover_general_volume_wait(self.publication.source.clone(), events)
                .context("ABT source may be online but its volume could not be rediscovered")?;
        n2r_win32::volume_label::validate_original_partition(&self.publication.source, &mounted)?;
        ensure!(
            n2r_win32::mounted_filesystem_general(mounted.clone(), events)? == "NTFS",
            "restored source did not mount as NTFS"
        );
        self.mounted = Some(mounted.clone());
        retirement.context("ABT source is online but temporary index retirement failed")?;
        self.publication_file.revalidate(&self.scratch)?;
        self.expected.revalidate(&self.scratch)?;
        if let Some(maps) = &mut self.maps {
            maps.revalidate(&self.scratch)?;
        }
        self.locator.revalidate()?;
        self.journal.revalidate()?;
        let (journal, _) = self.journal.split_for_observation()?;
        ensure!(
            super::sj::classify(journal, self.locator.ticket())? == SelectedLifecycle::Aborted,
            "ABT journal changed after restoring NTFS"
        );
        Ok(mounted)
    }

    pub(crate) fn expected_artifact(&self) -> ReopenedArtifact<'_> {
        ReopenedArtifact {
            file: &self.expected.file,
            snapshot: &self.expected.snapshot,
            sha256: self.expected.sha256,
        }
    }
    pub(crate) fn reopen_windows_alias_expectations<'expected>(
        &self,
        expected: &'expected crate::shadow_tree::PagedExpectedTree,
        scratch: &SourceScratch,
        output: &Path,
    ) -> Result<Option<crate::boot_alias::recovery::ReopenedWindowsAliasNativeDomain<'expected>>>
    {
        let windows = self.publication.source.layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows;
        match (
            &self.publication.windows_aliases,
            &self.publication.windows_alias_plan_sha256,
            &self.windows_aliases,
        ) {
            (None, None, None) if !windows => Ok(None),
            (Some(pin), Some(plan), Some(held)) if windows => {
                ensure!(
                    expected.semantic_sha256() == self.publication.expected.semantic_sha256
                        && expected.file_sha256() == self.publication.expected.file.sha256
                        && expected.len() as u64 == self.publication.expected.objects,
                    "reopened alias expectations belong to different canonical expected pages"
                );
                let files = [
                    held.data.file.try_clone()?,
                    held.directory.file.try_clone()?,
                ];
                Ok(Some(
                    crate::boot_alias::recovery::ReopenedWindowsAliasNativeDomain::open(
                        pin,
                        digest(plan)?,
                        files,
                        expected,
                        self.publication.resource_admission,
                        scratch,
                        output,
                    )?,
                ))
            }
            _ => anyhow::bail!(
                "Windows recovery alias expectations are absent or lost their authenticated held owners"
            ),
        }
    }
    pub(crate) fn publication_artifact(&self) -> ReopenedArtifact<'_> {
        ReopenedArtifact {
            file: &self.publication_file.file,
            snapshot: &self.publication_file.snapshot,
            sha256: self.publication_file.sha256,
        }
    }
    pub(crate) fn map_artifact(&self) -> Option<ReopenedArtifact<'_>> {
        self.maps.as_ref().map(|maps| ReopenedArtifact {
            file: &maps.file,
            snapshot: &maps.snapshot,
            sha256: maps.sha256,
        })
    }
    pub(crate) fn resource_admission(&self) -> SourceResourceAdmission {
        self.publication.resource_admission
    }
    pub(crate) fn verification_policy(&self) -> VerificationPolicy {
        self.publication.verification_policy
    }
    pub(crate) fn expected_semantic_sha256(&self) -> &str {
        &self.publication.expected.semantic_sha256
    }
    pub(crate) fn expected_binding(&self) -> Option<&ExpectedBindingPin> {
        self.publication.expected.binding.as_ref()
    }
    pub(crate) fn expected_objects(&self) -> u64 {
        self.publication.expected.objects
    }
    pub(crate) fn expected_source_label(&self) -> &VolumeLabel {
        &self.publication.expected_source_label
    }
    pub(crate) fn expected_mount_paths(&self) -> &[String] {
        &self.publication.expected_mount_paths
    }
    pub(crate) fn map_records(&self) -> Option<u64> {
        self.publication.recovery_maps.as_ref().map(|m| m.records)
    }
    pub(crate) fn ticket(&self) -> &crate::selected_journal::SelectedTicket {
        self.locator.ticket()
    }

    pub(crate) fn observed_lifecycle(&self) -> SelectedLifecycle {
        self.initial_lifecycle
    }
    pub(crate) fn source(&self) -> &GeneralDiskBinding {
        &self.publication.source
    }
    pub(crate) fn mounted_source(&self) -> Option<&GeneralDiskBinding> {
        self.mounted.as_ref()
    }
    pub(crate) fn shadow(&self) -> &GeneralDiskBinding {
        &self.publication.shadow
    }
    pub(crate) fn source_sha256(&self) -> &str {
        &self.publication.source_sha256
    }
    pub(crate) fn source_inspection_sha256(&self) -> &str {
        &self.publication.source_inspection_sha256
    }
    pub(crate) fn source_views_sha256(&self) -> &str {
        &self.publication.source_views_sha256
    }
    pub(crate) fn runtime_scratch(&self) -> &SourceScratch {
        &self.scratch
    }
    pub(crate) fn source_disk_attributes(&self) -> u64 {
        self.initial_state.disk_attributes
    }
    pub(crate) fn source_route_exclusive(&self) -> bool {
        self.target.as_ref().is_some_and(ObservedTarget::exclusive)
    }
    pub(crate) fn publication_path(&self) -> PathBuf {
        PathBuf::from(&self.publication_file.snapshot.final_path)
    }
}

enum PartitionRecoveryOrigin<'a> {
    Live(&'a mut n2r_win32::partition_lifecycle::PartitionNtfsAdmission),
    Restarted(&'a mut n2r_win32::partition_restoration::PartitionRecoveredOrigin),
}
impl PartitionRecoveryOrigin<'_> {
    fn require_actual(
        &mut self,
        scope: &super::super::source_scope::ResourceRecoverySourceScope,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        events: &mut Vec<NativeEvent>,
    ) -> Result<serde_json::Value> {
        match self {
            Self::Live(admission) => Ok(serde_json::to_value(
                scope
                    .preparation_guard()?
                    .require_actual(admission, owner, stable, events)?,
            )?),
            Self::Restarted(origin) => {
                ensure!(
                    stable.same_owner(&owner.owner_token())
                        && origin.owner_token().same_owner(stable)
                        && origin.binding() == owner.binding()
                        && scope.partition_binding() == Some(owner.binding()),
                    "restarted actual source/intent owner differs"
                );
                origin.revalidate_private(owner, events)?;
                ensure!(
                    serde_json::to_value(scope)? == *origin.routing_scope(),
                    "actual recovered routing scope differs"
                );
                ensure!(
                    serde_json::to_value(scope.preparation_guard()?)? == *origin.original_pin(),
                    "actual canonical recovered intent differs from publication guard pin"
                );
                Ok(origin.original_pin().clone())
            }
        }
    }
}
impl PartitionRecoveryPublicationBinding<'_> {
    pub(super) fn scratch_memory(&self, bytes: u64) -> Result<SourceRamLease> {
        self.scratch.lease_ram(bytes)
    }
}
impl ReopenedPartitionResourceRecovery {
    /// The original process guard is absent. Actual authenticated canonical
    /// restart files and current private owner replace it, never fresh NTFS.
    pub(crate) fn replay_restarted(
        &mut self,
        owner: &mut n2r_win32::PartitionScopedOwner,
        stable: &n2r_win32::PartitionOwnerToken,
        direction: PagedRecoveryDirection,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<super::replay::PartitionReplayResult> {
        let origin = self.restarted_origin.as_mut().context(
            "actual restarted origin owner absent; live guard is not process-death recovery",
        )?;
        origin.revalidate_private(owner, events)?;
        self.publication_file.revalidate(&self.scratch)?;
        self.expected.revalidate(&self.scratch)?;
        if let Some(maps) = &mut self.maps {
            maps.revalidate(&self.scratch)?;
        }
        self.locator.revalidate()?;
        self.journal.revalidate()?;
        let scope = &self.publication.source_scope;
        scope.require_partition()?;
        let actual_guard = {
            let mut actual = PartitionRecoveryOrigin::Restarted(&mut *origin);
            actual.require_actual(scope, owner, stable, events)?
        };
        let volume = self.locator.journal_binding().disk.volume_path()?;
        let _parent = hold_index_parent(index_path, &volume)?;
        ensure!(
            self.index_parent.metadata()?.is_dir(),
            "original held index parent disappeared"
        );
        let mut artifacts = vec![
            &self.publication_file.snapshot,
            &self.expected.snapshot,
            self.locator.snapshot(),
        ];
        if let Some(maps) = &self.maps {
            artifacts.push(&maps.snapshot);
        }
        require_partition_artifact_volume(
            owner,
            &self.publication.source_scope,
            &mut self.journal,
            &artifacts,
            events,
        )?;
        checkpoint(events)?;
        ensure!(
            events.is_empty(),
            "restart checkpoint did not drain native events"
        );
        let ticket = self.locator.ticket().clone();
        let mut observation = BoundJournalObservation::open(
            &mut self.journal,
            &ticket,
            group,
            &self.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        ensure!(
            match direction {
                PagedRecoveryDirection::Resume =>
                    observation.lifecycle()? == SelectedLifecycle::ApplyIntent,
                PagedRecoveryDirection::Rollback => matches!(
                    observation.lifecycle()?,
                    SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
                ),
            },
            "actual restarted lifecycle refuses requested direction"
        );
        let facts = &observation.facts;
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
        origin.require_journal_pins(&pins)?;
        let journal_owner = std::ptr::from_ref(&*observation.observation.journal) as usize;
        let mut binding = PartitionRecoveryPublicationBinding {
            publication: &self.publication,
            publication_file: &mut self.publication_file,
            expected: &mut self.expected,
            maps: self.maps.as_mut(),
            locator: &mut self.locator,
            scratch: &self.scratch,
            scope: AuthenticatedPartitionRecoveryScope {
                source: scope
                    .partition_binding()
                    .context("partition source binding absent")?
                    .clone(),
                actual_guard,
            },
            actual_journal_owner: journal_owner,
            actual_origin: PartitionRecoveryOrigin::Restarted(&mut *origin),
        };
        let mixed = observation.observe_partition_mixed(owner, stable, &mut binding, events)?;
        checkpoint(events)?;
        ensure!(events.is_empty(), "MIXED checkpoint did not drain");
        let result = observation.replay_partition(
            owner,
            stable,
            &mut binding,
            mixed,
            direction,
            events,
            &mut checkpoint,
        );
        // After an actual replay attempt only current private/artifact/J facts
        // may close. Never inspect or hash stale original NTFS data here.
        let closing = binding.revalidate_partition_mixed(
            owner,
            stable,
            observation.observation.journal,
            &observation.facts,
            observation.observation.ticket,
            events,
        );
        let drained = checkpoint(events);
        // Keep the actual policy/index alive in the successful result while
        // its SDK terminal witness references it. Do not delete that index.
        match (result, closing, drained) {
            (Ok(value), Ok(()), Ok(())) => Ok(value),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
        }
    }
}

impl ReopenedPartitionResourceRecovery {
    pub(crate) fn expected_artifact(&self) -> ReopenedArtifact<'_> {
        ReopenedArtifact {
            file: &self.expected.file,
            snapshot: &self.expected.snapshot,
            sha256: self.expected.sha256,
        }
    }
    pub(crate) fn publication_artifact(&self) -> ReopenedArtifact<'_> {
        ReopenedArtifact {
            file: &self.publication_file.file,
            snapshot: &self.publication_file.snapshot,
            sha256: self.publication_file.sha256,
        }
    }
    pub(crate) fn map_artifact(&self) -> Option<ReopenedArtifact<'_>> {
        self.maps.as_ref().map(|maps| ReopenedArtifact {
            file: &maps.file,
            snapshot: &maps.snapshot,
            sha256: maps.sha256,
        })
    }
    pub(crate) fn resource_admission(&self) -> SourceResourceAdmission {
        self.publication.resource_admission
    }
    pub(crate) fn verification_policy(&self) -> VerificationPolicy {
        self.publication.verification_policy
    }
    pub(crate) fn expected_semantic_sha256(&self) -> &str {
        &self.publication.expected.semantic_sha256
    }
    pub(crate) fn expected_binding(&self) -> Option<&ExpectedBindingPin> {
        self.publication.expected.binding.as_ref()
    }
    pub(crate) fn expected_objects(&self) -> u64 {
        self.publication.expected.objects
    }
    pub(crate) fn expected_source_label(&self) -> &VolumeLabel {
        &self.publication.expected_source_label
    }
    pub(crate) fn expected_mount_paths(&self) -> &[String] {
        &self.publication.expected_mount_paths
    }
    pub(crate) fn map_records(&self) -> Option<u64> {
        self.publication.recovery_maps.as_ref().map(|m| m.records)
    }
    pub(crate) fn ticket(&self) -> &crate::selected_journal::SelectedTicket {
        self.locator.ticket()
    }

    pub(crate) fn source(&self) -> &GeneralDiskBinding {
        &self.publication.source
    }
    pub(crate) fn shadow(&self) -> &GeneralDiskBinding {
        &self.publication.shadow
    }
    pub(crate) fn source_sha256(&self) -> &str {
        &self.publication.source_sha256
    }
    pub(crate) fn source_inspection_sha256(&self) -> &str {
        &self.publication.source_inspection_sha256
    }
    pub(crate) fn source_views_sha256(&self) -> &str {
        &self.publication.source_views_sha256
    }
    pub(crate) fn runtime_scratch(&self) -> &SourceScratch {
        &self.scratch
    }
}

impl ReopenedPartitionResourceRecovery {
    /// Consume the actual reopened origin/J and terminal replay owner together.
    /// No file-name reopen of intent/J and no fresh NTFS admission occurs here.
    pub(crate) fn finalize_replayed_partition(
        mut self,
        mut owner: n2r_win32::PartitionScopedOwner,
        mut outcome: super::replay::PartitionReplayResult,
        group: &ArtifactGroupPermit,
        index_path: &Path,
        maximum_index_bytes: u64,
        observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<serde_json::Value> {
        use crate::general_reconstruct::fast_verification::v4_maps::reopened::ReopenedVerificationMetadata;
        use n2r_win32::PartitionTerminalKind;
        let stable = owner.owner_token();
        checkpoint("partition-recovery-terminal-opening", events)?;
        let (kind, selected) = match &mut outcome {
            super::replay::PartitionReplayResult::Resumed {
                selected, witness, ..
            } => {
                witness.require_owner(&stable)?;
                witness.revalidate(&mut owner, events)?;
                (
                    PartitionTerminalKind::Handoff,
                    serde_json::to_value(selected)?,
                )
            }
            super::replay::PartitionReplayResult::RolledBack {
                selected, closed, ..
            } => {
                closed.require_owner(&stable)?;
                ensure!(
                    closed.kind() == PartitionTerminalKind::Aborted,
                    "rollback result is not actual closed ABT"
                );
                (
                    PartitionTerminalKind::Aborted,
                    serde_json::to_value(selected)?,
                )
            }
        };
        self.publication_file.revalidate(&self.scratch)?;
        self.expected.revalidate(&self.scratch)?;
        if let Some(maps) = &mut self.maps {
            maps.revalidate(&self.scratch)?;
        }
        self.locator.revalidate()?;
        self.journal.revalidate()?;
        let metadata =
            if let super::replay::PartitionReplayResult::Resumed { witness, .. } = &outcome {
                Some(ReopenedVerificationMetadata::open_partition(
                    &self, witness, &stable,
                )?)
            } else {
                None
            };
        let ticket = self.locator.ticket().clone();
        checkpoint("partition-recovery-terminal-index", events)?;
        let mut observed = BoundJournalObservation::open(
            &mut self.journal,
            &ticket,
            group,
            &self.scratch,
            index_path,
            maximum_index_bytes,
        )?;
        ensure!(
            observed.lifecycle()?
                == if kind == PartitionTerminalKind::Handoff {
                    SelectedLifecycle::Handoff
                } else {
                    SelectedLifecycle::Aborted
                },
            "actual terminal J direction differs from completed replay"
        );
        let policy = observed.observation.index.clone();
        let _terminal_index = observed.observation.index_lease.clone();
        drop(observed);
        let origin = self
            .restarted_origin
            .take()
            .context("actual authenticated restarted origin absent")?;
        origin.require_journal_pins(&{
            let (_, facts) = self.journal.split_for_observation()?;
            n2r_win32::PagedRecoveryPins {
                journal_binding: facts.binding,
                journal_identity: facts.identity,
                journal_path: facts.path,
                journal_profile: facts.profile,
                immutable_sha256: ticket.immutable_sha256,
                old_selected_sha256: ticket.old_selected_sha256,
                old_restored_selected_sha256: ticket.old_restored_selected_sha256,
                new_selected_sha256: ticket.new_selected_sha256,
            }
        })?;
        let shadow = self.publication.shadow.clone();
        let admission = self.publication.resource_admission;
        let arena = group.arena().clone();
        let (journal, facts) = self.journal.split_for_observation()?;
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
        checkpoint("partition-recovery-terminal-private-authentication", events)?;
        let mut guard = origin.into_terminal(
            owner,
            &policy,
            journal.markerless_recovery_file()?,
            pins,
            kind,
            events,
        )?;
        checkpoint("partition-recovery-terminal-readonly", events)?;
        guard.enter_readonly(observer, events)?;
        checkpoint("partition-recovery-terminal-native-verification", events)?;
        let mut map_bindings = 0;
        let mut known_streams = 0;
        let mut extent_streams = 0;
        let restoration = if let Some(metadata) = metadata.as_ref() {
            let native = {
                let readonly = guard.readonly_volume()?;
                ensure!(
                    readonly.owner_token().same_owner(&stable),
                    "actual terminal readonly owner changed"
                );
                let pair = GeneralSourceShadowBinding {
                    source: readonly.binding().clone(),
                    shadow,
                };
                let native = readonly.observe_converted_metadata_with_memory(
                    pair,
                    &crate::general_shadow::PagedInputs(metadata.expected()),
                    None,
                    |a, b| crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b).map_err(io::Error::other),
                    n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(admission)),
                    &crate::general_composite_target::paged_memory::ArenaReportMemory(
                        arena.clone(),
                    ),
                    true,
                    events,
                )?;
                map_bindings = metadata.compare_partition(&stable, &native)?;
                let known = native
                    .report()
                    .content_observation
                    .as_ref()
                    .and_then(|c| c.known_content.as_ref())
                    .context("actual terminal known-content proof absent")?;
                known_streams = known.streams_hashed;
                extent_streams = known.streams_without_content_baseline;
                native
            };
            checkpoint(
                "partition-recovery-terminal-verified-before-writable",
                events,
            )?;
            guard.finish(native, observer, events)?
        } else {
            ensure!(
                kind == PartitionTerminalKind::Aborted,
                "resume lacks authenticated expected/maps owner"
            );
            checkpoint("partition-recovery-aborted-old-before-writable", events)?;
            guard.finish_aborted(observer, events)?
        };
        checkpoint("partition-recovery-terminal-restored", events)?;
        // Close only metadata/J facts after RW publication. Do not compare a
        // mounted operational source to stale conversion-time OLD/NEW bytes.
        self.publication_file.revalidate(&self.scratch)?;
        self.expected.revalidate(&self.scratch)?;
        if let Some(maps) = &mut self.maps {
            maps.revalidate(&self.scratch)?;
        }
        self.locator.revalidate()?;
        drop(outcome);
        Ok(
            serde_json::json!({"kind":"partition-recovery-terminal-result-v1","success":true,
            "direction":if kind==PartitionTerminalKind::Handoff{"resume"}else{"rollback"},
            "selected":selected,"restoration":restoration,"raw_replay_performed":true,
            "matching_map_bindings":map_bindings,"known_streams_hashed":known_streams,
            "extent_only_streams":extent_streams,"recovery_files_retired":false,
            "native_terminal_verified_before_writable":true,"stable_release_qualification":false}),
        )
    }
}
