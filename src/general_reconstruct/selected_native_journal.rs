//! Private journal owner used by selected allocation orchestration. Only the
//! explicit lab route currently constructs native marker storage; production
//! selection shares the compiled qualification gate below. No handle or mutable
//! inner accessor can turn a buffered File into the sealed capability.
use crate::{
    lab_reconstruct::{DurableIo, ReadSeek},
    selected_journal as sj,
};
use anyhow::{Result, ensure};
use n2r_win32::journal_file::{
    GeneralJournalStorageBinding, JournalFileIdentity, JournalProfile, LabMarkerCopyPause,
    LabMarkerFault, MARKER_STORAGE_NATIVE_QUALIFIED, MarkerJournalFile, MarkerStorageObservation,
    MarkerStorageUse, UnbufferedJournalFile, observe_general_journal_file_with_profile,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};

/// Shared production format selection, never a storage capability or fresh
/// source authority. Only a source change backed by native qualification can
/// enable this; saved requests/tickets and lab options cannot change the gate.
/// Ineligible plans retain the legacy format. The caller must still validate
/// the selected profile, so an invalid plan cannot gain a fallback write path.
pub(crate) fn production_marker_profile(
    plan: &sj::SelectedPlan,
) -> Option<sj::SelectedMarkerProfile> {
    (MARKER_STORAGE_NATIVE_QUALIFIED && plan.validate_redundant_source_free().is_ok())
        .then_some(sj::SelectedMarkerProfile::RedundantSourceFreeV1)
}

pub(crate) struct NativeSelectedJournal {
    storage: Storage,
    lab_pause: Option<LabMarkerCopyPause>,
    fixed_length: Option<u64>,
    // Set only by the actual completed PreparedClear journal scan. Once set,
    // ordinary writes may touch marker granules but never the immutable body.
    prepared_body_sealed: bool,
}

/// V4 read-only recovery evidence tied to the actual share-zero native journal
/// owner. These fields cannot be deserialized and do not authorize replay;
/// the conversion's independently trusted ticket/routing and an excluded
/// target capability must still be bound before any write path is available.
pub(crate) struct BoundNativeRecoveryJournal {
    journal: NativeSelectedJournal,
    path: PathBuf,
    binding: GeneralJournalStorageBinding,
    identity: JournalFileIdentity,
    profile: JournalProfile,
    journal_length: u64,
    marker_use: MarkerStorageUse,
    marker_native_qualified: Option<bool>,
}

pub(crate) struct BoundNativeJournalFacts<'a> {
    pub(crate) path: &'a Path,
    pub(crate) binding: &'a GeneralJournalStorageBinding,
    pub(crate) identity: &'a JournalFileIdentity,
    pub(crate) profile: JournalProfile,
    pub(crate) journal_length: u64,
    pub(crate) marker_use: MarkerStorageUse,
    pub(crate) marker_native_qualified: Option<bool>,
}

/// Actual newly created native journal owner. It cannot issue a conversion
/// certificate or make target writes; V4 preparation borrows this exact file.
pub(crate) struct BoundNativeCreationJournal {
    journal: NativeSelectedJournal,
    path: PathBuf,
    binding: GeneralJournalStorageBinding,
    identity: JournalFileIdentity,
    profile: JournalProfile,
    marker_profile: Option<sj::SelectedMarkerProfile>,
    marker_use: MarkerStorageUse,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    shadow: n2r_win32::general_layout::GeneralDiskBinding,
    preparation_borrowed: bool,
    /// Full native journal capacity plus observed allocation slack remains
    /// reserved until an actual same-file retirement path is implemented.
    journal_quota: crate::artifact_arena::ArtifactGroupPermit,
    expected_journal_length: u64,
}

pub(crate) struct BoundNativeCreationFacts<'a> {
    pub(crate) path: &'a Path,
    pub(crate) binding: &'a GeneralJournalStorageBinding,
    pub(crate) identity: &'a JournalFileIdentity,
    pub(crate) profile: JournalProfile,
    pub(crate) marker_profile: Option<sj::SelectedMarkerProfile>,
    pub(crate) marker_use: MarkerStorageUse,
    pub(crate) source: &'a n2r_win32::general_layout::GeneralDiskBinding,
    pub(crate) shadow: &'a n2r_win32::general_layout::GeneralDiskBinding,
    pub(crate) journal_quota: &'a crate::artifact_arena::ArtifactGroupPermit,
    pub(crate) expected_journal_length: u64,
}

/// Separate actual partition creation owner. No GeneralFrozenPartition is
/// constructed for its source, and legacy dedicated creation remains intact.
pub(crate) struct BoundPartitionCreationJournal {
    inner: BoundNativeCreationJournal,
    source_owner: n2r_win32::PartitionOwnerToken,
    guard_pin: n2r_win32::partition_lifecycle::PartitionPreparationPin,
}
pub(crate) struct BoundPartitionCreationFacts<'a> {
    pub(crate) native: BoundNativeCreationFacts<'a>,
    pub(crate) source_owner: &'a n2r_win32::PartitionOwnerToken,
    pub(crate) guard_pin: &'a n2r_win32::partition_lifecycle::PartitionPreparationPin,
}
impl BoundPartitionCreationFacts<'_> {
    pub(crate) fn revalidate_source(
        &self,
        context: &mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<()> {
        context.with_publication_handoff(events, |source, admission, stable, events| {
            ensure!(self.source_owner.same_owner(stable)
                && self.native.source == &source.binding().storage,
                "partition creation facts lost the actual source owner");
            admission.revalidate_publication_handoff(source, self.guard_pin, events)?;
            require_partition_journal_volume(source, stable, self.native.binding, events)
        })
    }
}

fn require_partition_journal_volume(
    source: &mut n2r_win32::PartitionScopedOwner,
    stable: &n2r_win32::PartitionOwnerToken,
    binding: &GeneralJournalStorageBinding,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<()> {
    source.revalidate(events)?;
    ensure!(stable.same_owner(&source.owner_token()), "actual partition journal owner changed");
    binding.validate()?;
    let root = format!("{}\\", binding.disk.volume_path()?.trim_end_matches('\\'));
    let actual = n2r_win32::discovery::discover(&root,
        n2r_win32::discovery::Role::Journal {allow_additional_partitions:binding.allow_additional_partitions})?;
    let s = &source.binding().storage;
    let j = &actual.binding;
    let same_number = s.disk_number == j.disk_number;
    let same_guid = n2r_win32::layout::guid_bytes(&s.identity.disk_guid)?
        == n2r_win32::layout::guid_bytes(&j.identity.disk_guid)?;
    ensure!(actual.observed_twice_unchanged && actual.read_only
        && actual.source_write_requests == 0 && j == &binding.disk
        && same_number == same_guid
        && n2r_win32::layout::guid_bytes(&s.identity.partition_guid)?
            != n2r_win32::layout::guid_bytes(&j.identity.partition_guid)?
        && n2r_win32::layout::guid_bytes(&s.volume_guid)?
            != n2r_win32::layout::guid_bytes(&j.volume_guid)?,
        "actual partition journal volume identity/GUID/extent evidence differs");
    if same_number {
        let se = s.identity.partition_offset.checked_add(s.identity.partition_bytes)
            .ok_or_else(|| anyhow::anyhow!("source extent overflow"))?;
        let je = j.identity.partition_offset.checked_add(j.identity.partition_bytes)
            .ok_or_else(|| anyhow::anyhow!("journal extent overflow"))?;
        ensure!(s.identity.disk_bytes == j.identity.disk_bytes
            && s.identity.logical_sector_bytes == j.identity.logical_sector_bytes
            && s.identity.physical_sector_bytes == j.identity.physical_sector_bytes
            && (se <= j.identity.partition_offset || je <= s.identity.partition_offset),
            "actual C/journal volume overlaps selected private partition");
    }
    source.revalidate(events)?;
    Ok(())
}

impl BoundPartitionCreationJournal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_new(
        context: &mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        shadow: &mut n2r_win32::GeneralFrozenPartition,
        arena: &crate::artifact_arena::ArtifactArena,
        expected_journal_length: u64,
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<Self> {
        context.recheck_source(events)?;
        ensure!(arena.same_arena(context.arena()) && path.is_absolute()
            && !path.components().any(|c| matches!(c, Component::ParentDir|Component::CurDir))
            && expected_journal_length > 0
            && expected_journal_length <= profile.max_journal_bytes()
            && arena.volume_guid_path()?.eq_ignore_ascii_case(&binding.disk.volume_path()?),
            "partition journal requires actual source arena/volume and bounded length");
        let shadow_before = shadow.state(events)?;
        ensure!(shadow_before.disk_attributes == 3, "actual shadow must remain frozen");
        let shadow_binding = shadow.binding().clone();
        let result = context.with_publication_handoff(events, |source, admission, stable, events| {
            let guard_pin = admission.durable_preparation_pin()?;
            admission.revalidate_publication_handoff(source, &guard_pin, events)?;
            require_partition_journal_volume(source, stable, binding, events)?;
            let source_binding = source.binding().storage.clone();
            let sg = n2r_win32::layout::guid_bytes(&source_binding.identity.disk_guid)?;
            let tg = n2r_win32::layout::guid_bytes(&shadow_binding.identity.disk_guid)?;
            let jg = n2r_win32::layout::guid_bytes(&binding.disk.identity.disk_guid)?;
            ensure!(source_binding.disk_number != shadow_binding.disk_number
                && binding.disk.disk_number != shadow_binding.disk_number && sg != tg && jg != tg,
                "partition source/J and actual frozen shadow are not independent");
            // Hold actual ordinary output ancestry before CreateNew; a
            // serialized path cannot substitute for its native GUID route.
            let parent = path.parent().ok_or_else(||anyhow::anyhow!("journal parent absent"))?;
            let directory = OpenOptions::new().access_mode(0x80).share_mode(3)
                .custom_flags(0x0200_0000|0x0020_0000).open(parent)?;
            use std::os::windows::fs::MetadataExt;
            let meta = directory.metadata()?;
            let route = n2r_win32::file_storage::final_path_guid(&directory)?;
            let prefix = format!("{}\\", binding.disk.volume_path()?.trim_end_matches('\\'));
            ensure!(meta.is_dir() && meta.file_attributes() & 0x400 == 0
                && route.get(..prefix.len()).is_some_and(|p|p.eq_ignore_ascii_case(&prefix)),
                "partition journal output directory is not actual disjoint J volume");
            let quota_bytes = expected_journal_length.checked_add(arena.allocation_slack_bytes())
                .ok_or_else(||anyhow::anyhow!("partition native journal quota overflow"))?;
            let journal_quota = arena.reserve_group(
                crate::artifact_arena::ArtifactGroup::NativeJournal, quota_bytes)?;
            let (mut journal, identity) = NativeSelectedJournal::create_new(
                path, binding, profile, None, MarkerStorageUse::QualifiedProduction, None)?;
            let actual_path = journal.observed_guid_path(binding)?;
            let Storage::Buffered(file) = &mut journal.storage else {
                anyhow::bail!("partition creation supports the actual markerless buffered owner only")
            };
            let before = observe_general_journal_file_with_profile(file, binding, profile)?;
            ensure!(before.identity == identity && before.file_bytes == 0
                && before.number_of_links == 1, "fresh partition journal identity differs");
            n2r_win32::file_storage::preallocate_empty_file(
                file, expected_journal_length, quota_bytes)?;
            let after = observe_general_journal_file_with_profile(file, binding, profile)?;
            ensure!(after.identity == identity && after.identity == before.identity
                && after.final_path == before.final_path
                && Path::new(&after.final_path) == actual_path.as_path()
                && after.file_bytes == 0 && after.file_attributes == before.file_attributes
                && after.number_of_links == 1 && after.allocation_bytes >= expected_journal_length
                && after.allocation_bytes <= quota_bytes,
                "partition journal preallocation identity/EOF/allocation changed");
            require_partition_journal_volume(source, stable, binding, events)?;
            admission.revalidate_publication_handoff(source, &guard_pin, events)?;
            ensure!(shadow.state(events)? == shadow_before, "actual frozen shadow changed");
            Ok(Self {
                inner:BoundNativeCreationJournal {journal, path:actual_path, binding:binding.clone(),
                    identity, profile, marker_profile:None, marker_use:MarkerStorageUse::QualifiedProduction,
                    source:source_binding, shadow:shadow_binding.clone(), preparation_borrowed:false,
                    journal_quota, expected_journal_length},
                source_owner:stable.clone(), guard_pin,
            })
        });
        let closing = context.recheck_source(events);
        match (result, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    pub(crate) fn split_for_partition_preparation(
        &mut self,
        context: &mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<(&mut NativeSelectedJournal, BoundPartitionCreationFacts<'_>)> {
        context.with_publication_handoff(events, |source, admission, stable, events| {
            ensure!(self.source_owner.same_owner(stable)
                && self.inner.source == source.binding().storage,
                "partition journal cannot transfer to another source owner");
            admission.revalidate_publication_handoff(source, &self.guard_pin, events)?;
            require_partition_journal_volume(source, stable, &self.inner.binding, events)
        })?;
        let Self {inner, source_owner, guard_pin} = self;
        let (journal, native) = inner.split_for_preparation()?;
        Ok((journal, BoundPartitionCreationFacts {native, source_owner, guard_pin}))
    }
}

/// A readonly duplicate of the exact native journal file object. Its fields
/// are private; only a completed, fixed-length native owner can produce it.
/// Queries use file metadata only and never call into the journal or arena.
pub(crate) struct NativeJournalAllocationOwner {
    file: File,
    expected: n2r_win32::reference_file::ReferenceFileSnapshot,
    maximum_allocation: u64,
}

impl NativeJournalAllocationOwner {
    pub(crate) fn observe(&self) -> Result<(u64, u64)> {
        let actual = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &self.file,
            self.expected.file_bytes,
        )?;
        ensure!(actual.final_path == self.expected.final_path,
            "live native journal same-file path changed");
        ensure!(actual.volume_serial_number == self.expected.volume_serial_number,
            "live native journal volume serial changed");
        ensure!(actual.file_id_128 == self.expected.file_id_128,
            "live native journal file identity changed");
        ensure!(actual.file_bytes == self.expected.file_bytes,
            "live native journal EOF changed: expected {}, actual {}",
            self.expected.file_bytes, actual.file_bytes);
        ensure!(actual.file_attributes == self.expected.file_attributes,
            "live native journal attributes changed: expected {:#x}, actual {:#x}",
            self.expected.file_attributes, actual.file_attributes);
        ensure!(actual.number_of_links == 1,
            "live native journal link count changed: {}", actual.number_of_links);
        ensure!(actual.allocation_bytes >= actual.file_bytes
            && actual.allocation_bytes <= self.maximum_allocation,
            "live native journal allocation outside reserved bounds: allocation {}, EOF {}, maximum {}, initial allocation {}",
            actual.allocation_bytes, actual.file_bytes, self.maximum_allocation,
            self.expected.allocation_bytes);
        // Credit only the fixed logical length, not the variable allocation
        // slack: this remains conservative if allocation quanta are reclaimed.
        Ok((actual.allocation_bytes, actual.file_bytes))
    }
    pub(crate) fn final_path(&self) -> &str {
        &self.expected.final_path
    }
    pub(crate) fn reservation_bytes(&self) -> u64 {
        self.maximum_allocation
    }
}

enum Storage {
    Buffered(File),
    Constructing(UnbufferedJournalFile),
    Sealed(MarkerJournalFile),
    Unavailable,
}

fn unavailable() -> io::Error {
    io::Error::other("selected journal owner unavailable after failed sealing")
}

impl NativeSelectedJournal {
    /// Borrow the same held share-zero journal used by the recovery scanner.
    /// Native paged recovery currently supports only the buffered, markerless
    /// formats. This is not a target-write capability or a reopened pathname.
    pub(crate) fn markerless_recovery_file(&mut self) -> Result<&mut File> {
        ensure!(!self.prepared_body_sealed,
            "sealed prepared journal cannot expose its writable body handle");
        match &mut self.storage {
            Storage::Buffered(file) => Ok(file),
            Storage::Constructing(_) | Storage::Sealed(_) | Storage::Unavailable => {
                anyhow::bail!("paged recovery requires the held markerless native journal")
            }
        }
    }
    /// Make the actual fixed-EOF markerless owner permanently reject ordinary
    /// writes to its body. This is an in-process capability boundary, not a
    /// claim that privileged raw-volume aliases are excluded.
    pub(crate) fn seal_prepared_body(&mut self, ticket: &sj::SelectedTicket) -> Result<()> {
        ensure!(!self.prepared_body_sealed && self.fixed_length == Some(ticket.journal_length)
            && ticket.marker_profile.is_none() && matches!(self.storage, Storage::Buffered(_)),
            "actual fixed markerless prepared owner required for body seal");
        ensure!(sj::classify(self, ticket)? == sj::SelectedLifecycle::PreparedClear,
            "body seal requires the actual clear journal");
        self.prepared_body_sealed = true;
        Ok(())
    }
    pub(crate) fn require_prepared_body_seal(&self) -> Result<()> {
        ensure!(self.prepared_body_sealed && matches!(self.storage, Storage::Buffered(_)),
            "actual prepared marker-only journal owner absent");
        Ok(())
    }
    /// The raw file is not returned: only the SDK's fixed activation gate may
    /// borrow it, and that gate rehashes the body on both sides of OLD checks.
    pub(crate) fn begin_sealed_fresh_apply<'a>(
        &mut self,
        source: &'a mut n2r_win32::GeneralFrozenPartition,
        policy: n2r_win32::HeldPagedWritePolicy,
        pins: &n2r_win32::PagedRecoveryPins<'_>,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<n2r_win32::BorrowedPagedWriter<'a>> {
        self.require_prepared_body_seal()?;
        match &mut self.storage {
            Storage::Buffered(file) => Ok(source.begin_paged_fresh_apply(policy, file, pins, events)?),
            _ => anyhow::bail!("sealed markerless journal owner absent"),
        }
    }
    pub(crate) fn seal_sealed_handoff_for_observation(
        &mut self,
        source: &mut n2r_win32::GeneralFrozenPartition,
        policy: &n2r_win32::HeldPagedWritePolicy,
        pins: &n2r_win32::PagedRecoveryPins<'_>,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<()> {
        self.require_prepared_body_seal()?;
        match &mut self.storage {
            Storage::Buffered(file) => Ok(source.seal_paged_handoff_for_observation(policy, file, pins, events)?),
            _ => anyhow::bail!("sealed markerless journal owner absent"),
        }
    }
    /// Same-handle volume-GUID route for a future recovery locator. A
    /// drive-letter alias supplied by the caller is never persisted as proof.
    fn observed_guid_path(&self, binding: &GeneralJournalStorageBinding) -> Result<PathBuf> {
        let path = match &self.storage {
            Storage::Buffered(file) => n2r_win32::file_storage::final_path_guid(file)?,
            Storage::Constructing(file) => file.observed_final_path().to_owned(),
            Storage::Sealed(file) => file.observed_final_path().to_owned(),
            Storage::Unavailable => anyhow::bail!("native journal owner unavailable"),
        };
        let prefix = format!("{}\\", binding.disk.volume_path()?);
        ensure!(
            path.to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
                && Path::new(&path).is_absolute()
                && !Path::new(&path)
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "same-handle journal route differs from bound volume"
        );
        Ok(PathBuf::from(path))
    }

    pub(crate) fn create_new(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        markers: Option<sj::SelectedMarkerProfile>,
        marker_use: MarkerStorageUse,
        lab_pause: Option<LabMarkerCopyPause>,
    ) -> Result<(Self, JournalFileIdentity)> {
        if markers.is_some() {
            let file = UnbufferedJournalFile::create_new(path, binding, profile, marker_use)?;
            let identity = file.identity().clone();
            return Ok((
                Self {
                    storage: Storage::Constructing(file),
                    lab_pause,
                    fixed_length: None,
                    prepared_body_sealed: false,
                },
                identity,
            ));
        }
        ensure!(
            lab_pause.is_none(),
            "marker pause requires explicit native format six"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let observed = observe_general_journal_file_with_profile(&file, binding, profile)?;
        ensure!(
            observed.file_bytes == 0,
            "fresh empty selected journal required"
        );
        Ok((
            Self {
                storage: Storage::Buffered(file),
                lab_pause: None,
                fixed_length: None,
                prepared_body_sealed: false,
            },
            observed.identity,
        ))
    }

    pub(crate) fn open_recovery(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        ticket: &sj::SelectedTicket,
        marker_identity: Option<&JournalFileIdentity>,
        marker_use: MarkerStorageUse,
        lab_pause: Option<LabMarkerCopyPause>,
        lab_fault: Option<LabMarkerFault>,
    ) -> Result<(Self, serde_json::Value)> {
        let (journal, _, observed) = Self::open_recovery_with_identity(
            path,
            binding,
            profile,
            ticket,
            marker_identity,
            marker_use,
            lab_pause,
            lab_fault,
        )?;
        Ok((journal, observed))
    }

    /// Returns the typed actual same-handle identity in addition to the
    /// existing diagnostic observation. It does not authorize replay.
    fn open_recovery_with_identity(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        ticket: &sj::SelectedTicket,
        marker_identity: Option<&JournalFileIdentity>,
        marker_use: MarkerStorageUse,
        lab_pause: Option<LabMarkerCopyPause>,
        lab_fault: Option<LabMarkerFault>,
    ) -> Result<(Self, JournalFileIdentity, serde_json::Value)> {
        ensure!(
            lab_pause.is_none() || lab_fault.is_none(),
            "marker pause and marker fault are mutually exclusive"
        );
        if ticket.marker_profile.is_some() {
            let identity = marker_identity.ok_or_else(|| {
                anyhow::anyhow!(
                    "native marker recovery needs its independently pinned file identity"
                )
            })?;
            let mut file = MarkerJournalFile::open_recovery(
                path,
                binding,
                profile,
                marker_use,
                identity,
                ticket.journal_length,
            )?;
            if let Some(pause) = lab_pause {
                file.attach_lab_copy_pause(pause)?;
            }
            if let Some(fault) = lab_fault {
                file.attach_lab_marker_fault(fault)?;
            }
            let actual_identity = file.observation().identity.clone();
            let observed = serde_json::to_value(file.observation())?;
            return Ok((
                Self {
                    storage: Storage::Sealed(file),
                    lab_pause: None,
                    fixed_length: None,
                    prepared_body_sealed: false,
                },
                actual_identity,
                observed,
            ));
        }
        ensure!(
            marker_identity.is_none() && lab_pause.is_none() && lab_fault.is_none(),
            "legacy journal has marker storage identity or lab control"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let observed = observe_general_journal_file_with_profile(&file, binding, profile)?;
        ensure!(
            observed.file_bytes == ticket.journal_length,
            "opened selected journal length differs from the pinned ticket"
        );
        let actual_identity = observed.identity.clone();
        Ok((
            Self {
                storage: Storage::Buffered(file),
                lab_pause: None,
                fixed_length: None,
                prepared_body_sealed: false,
            },
            actual_identity,
            serde_json::to_value(observed)?,
        ))
    }

    /// Called only before the prepared owner is published. On failure the
    /// original owner is dropped and this wrapper becomes permanently unusable.
    pub(crate) fn seal_redundant(&mut self, ticket: &sj::SelectedTicket) -> Result<()> {
        ensure!(
            ticket.marker_profile == Some(sj::SelectedMarkerProfile::RedundantSourceFreeV1),
            "native sealing requires explicit redundant source-free markers"
        );
        let construction = std::mem::replace(&mut self.storage, Storage::Unavailable);
        let Storage::Constructing(file) = construction else {
            anyhow::bail!("native marker sealing requires its actual construction owner");
        };
        let mut file = file.seal_marker_storage(ticket.journal_length)?;
        if let Some(pause) = self.lab_pause.take() {
            file.attach_lab_copy_pause(pause)?;
        }
        self.storage = Storage::Sealed(file);
        Ok(())
    }

    pub(crate) fn marker_observation(&self) -> Option<&MarkerStorageObservation> {
        match &self.storage {
            Storage::Sealed(file) => Some(file.observation()),
            _ => None,
        }
    }

    pub(crate) fn require_native_mount_barriers(
        &mut self,
        ticket: &sj::SelectedTicket,
    ) -> Result<()> {
        if ticket.marker_profile.is_none() {
            return Ok(());
        }
        ensure!(
            matches!(&self.storage, Storage::Sealed(_)),
            "native markers require actual sealed storage"
        );
        sj::require_redundant_terminal_barriers(self, ticket)
    }

    /// Revalidate a completed V4 preparation through its original native
    /// owner and observed creation facts. This reports storage continuity
    /// only; it neither publishes the ticket nor grants target authority.
    pub(crate) fn revalidate_resource_preparation(
        &mut self,
        facts: &BoundNativeCreationFacts<'_>,
        ticket: &sj::SelectedTicket,
    ) -> Result<()> {
        ensure!(
            ticket.marker_profile == facts.marker_profile
                && ticket.journal_length <= facts.profile.max_journal_bytes(),
            "prepared native journal profile differs"
        );
        match &mut self.storage {
            Storage::Buffered(file) => {
                let actual =
                    observe_general_journal_file_with_profile(file, facts.binding, facts.profile)?;
                ensure!(
                    facts.marker_profile.is_none()
                        && actual.identity == *facts.identity
                        && actual.file_bytes == ticket.journal_length,
                    "prepared native journal identity or size changed"
                );
            }
            Storage::Sealed(file) => {
                file.revalidate_storage()?;
                let actual = file.observation();
                ensure!(
                    facts.marker_profile.is_some()
                        && actual.identity == *facts.identity
                        && actual.journal_length == ticket.journal_length
                        && (facts.marker_use == MarkerStorageUse::EnrolledUnqualifiedLab
                            || actual.native_qualified),
                    "prepared native marker storage changed or is not qualified"
                );
            }
            Storage::Constructing(_) | Storage::Unavailable => {
                anyhow::bail!("prepared native journal is not in its completed storage state");
            }
        }
        ensure!(
            self.observed_guid_path(facts.binding)?.as_path() == facts.path,
            "prepared native journal same-handle route changed"
        );
        Ok(())
    }

    /// Freeze EOF for this native owner, then retain a readonly duplicate of
    /// its exact file object for live allocation queries. No caller-provided
    /// byte count or serialized snapshot can construct this capability.
    pub(crate) fn fix_length_and_observe_allocation(
        &mut self,
        facts: &BoundNativeCreationFacts<'_>,
        ticket: &sj::SelectedTicket,
    ) -> Result<NativeJournalAllocationOwner> {
        ensure!(
            self.fixed_length.is_none(),
            "native journal EOF is already fixed"
        );
        self.revalidate_resource_preparation(facts, ticket)?;
        ensure!(
            self.byte_len()? == ticket.journal_length
                && ticket.journal_length == facts.expected_journal_length,
            "fixed native journal length differs from the reserved size"
        );
        self.fixed_length = Some(ticket.journal_length);
        let file = match &mut self.storage {
            Storage::Buffered(file) => n2r_win32::file_storage::duplicate_readonly(file)?,
            Storage::Sealed(file) => file.duplicate_readonly_storage_handle()?,
            Storage::Constructing(_) | Storage::Unavailable => {
                anyhow::bail!("completed native journal owner required")
            }
        };
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let expected = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &file,
            ticket.journal_length,
        )?;
        ensure!(
            expected.file_bytes == ticket.journal_length
                && expected.volume_serial_number == facts.identity.volume_serial_number
                && expected.file_id_128 == facts.identity.file_id_128
                && Path::new(&expected.final_path) == facts.path
                && expected.number_of_links == 1,
            "allocation witness is not the actual prepared native journal file"
        );
        let owner = NativeJournalAllocationOwner {
            file,
            expected,
            maximum_allocation: facts.journal_quota.maximum_bytes()?,
        };
        owner.observe()?;
        Ok(owner)
    }
}

impl BoundNativeCreationJournal {
    pub(crate) fn create_new(
        source: &mut n2r_win32::GeneralFrozenPartition,
        shadow: &mut n2r_win32::GeneralFrozenPartition,
        arena: &crate::artifact_arena::ArtifactArena,
        expected_journal_length: u64,
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        marker_profile: Option<sj::SelectedMarkerProfile>,
        marker_use: MarkerStorageUse,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<Self> {
        binding.validate()?;
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "native creation journal path must be absolute without traversal"
        );
        ensure!(
            expected_journal_length > 0
                && expected_journal_length <= profile.max_journal_bytes()
                && arena
                    .volume_guid_path()?
                    .eq_ignore_ascii_case(&binding.disk.volume_path()?),
            "native journal quota requires its actual journal volume and bounded length"
        );
        let source_before = source.state(events)?;
        let shadow_before = shadow.state(events)?;
        ensure!(
            source_before.disk_attributes == 3 && shadow_before.disk_attributes == 3,
            "native journal creation requires frozen source and shadow"
        );
        let source_binding = source.binding().clone();
        let shadow_binding = shadow.binding().clone();
        let journal_disk = &binding.disk;
        let source_guid = n2r_win32::layout::guid_bytes(&source_binding.identity.disk_guid)?;
        let shadow_guid = n2r_win32::layout::guid_bytes(&shadow_binding.identity.disk_guid)?;
        let journal_guid = n2r_win32::layout::guid_bytes(&journal_disk.identity.disk_guid)?;
        ensure!(
            source_binding.disk_number != shadow_binding.disk_number
                && journal_disk.disk_number != source_binding.disk_number
                && journal_disk.disk_number != shadow_binding.disk_number
                && source_guid != shadow_guid
                && journal_guid != source_guid
                && journal_guid != shadow_guid,
            "native journal must be on a disk independent of frozen source and shadow"
        );
        let quota_bytes = expected_journal_length
            .checked_add(arena.allocation_slack_bytes())
            .ok_or_else(|| anyhow::anyhow!("native journal quota overflow"))?;
        let journal_quota = arena.reserve_group(
            crate::artifact_arena::ArtifactGroup::NativeJournal,
            quota_bytes,
        )?;
        let (mut journal, identity) = NativeSelectedJournal::create_new(
            path,
            binding,
            profile,
            marker_profile,
            marker_use,
            None,
        )?;
        let actual_path = journal.observed_guid_path(binding)?;
        // Reserve before streaming the body: ordinary buffered NTFS growth
        // can speculatively allocate beyond EOF until the final handle closes.
        // The group quota is already held; no allocation credit is issued here.
        if let Storage::Buffered(file) = &mut journal.storage {
            let before = observe_general_journal_file_with_profile(file, binding, profile)?;
            ensure!(marker_profile.is_none() && before.identity == identity
                && before.file_bytes == 0 && before.number_of_links == 1,
                "fresh buffered journal changed before preallocation");
            n2r_win32::file_storage::preallocate_empty_file(file, expected_journal_length, quota_bytes)?;
            let after = observe_general_journal_file_with_profile(file, binding, profile)?;
            ensure!(after.identity == identity && after.identity == before.identity
                && after.final_path == before.final_path && Path::new(&after.final_path) == actual_path.as_path()
                && after.file_bytes == 0
                && after.file_attributes == before.file_attributes && after.number_of_links == 1
                && after.allocation_bytes >= expected_journal_length && after.allocation_bytes <= quota_bytes,
                "preallocated buffered journal identity, EOF, or allocation changed");
        }
        ensure!(
            source.state(events)? == source_before && shadow.state(events)? == shadow_before,
            "frozen source or shadow changed while creating native journal"
        );
        Ok(Self {
            journal,
            path: actual_path,
            binding: binding.clone(),
            identity,
            profile,
            marker_profile,
            marker_use,
            source: source_binding,
            shadow: shadow_binding,
            preparation_borrowed: false,
            journal_quota,
            expected_journal_length,
        })
    }

    /// This one-shot borrow preserves the original created native owner and
    /// its real storage identity through preparation. A failed/incomplete
    /// preparation cannot retry through the same owner.
    pub(crate) fn split_for_preparation(
        &mut self,
    ) -> Result<(&mut NativeSelectedJournal, BoundNativeCreationFacts<'_>)> {
        ensure!(
            !self.preparation_borrowed && self.journal.byte_len()? == 0,
            "native creation journal was already used or is not empty"
        );
        match &mut self.journal.storage {
            Storage::Buffered(file) => {
                let observed =
                    observe_general_journal_file_with_profile(file, &self.binding, self.profile)?;
                ensure!(
                    self.marker_profile.is_none()
                        && observed.identity == self.identity
                        && observed.file_bytes == 0,
                    "fresh buffered native journal identity changed"
                );
            }
            Storage::Constructing(file) => {
                ensure!(
                    self.marker_profile.is_some() && file.identity() == &self.identity,
                    "fresh native marker construction identity changed"
                );
            }
            Storage::Sealed(_) | Storage::Unavailable => {
                anyhow::bail!("native creation journal is no longer fresh")
            }
        }
        ensure!(
            self.journal.observed_guid_path(&self.binding)? == self.path,
            "fresh native journal same-handle route changed"
        );
        self.preparation_borrowed = true;
        let Self {
            journal,
            path,
            binding,
            identity,
            profile,
            marker_profile,
            marker_use,
            source,
            shadow,
            journal_quota,
            expected_journal_length,
            ..
        } = self;
        Ok((
            journal,
            BoundNativeCreationFacts {
                path,
                binding,
                identity,
                profile: *profile,
                marker_profile: *marker_profile,
                marker_use: *marker_use,
                source,
                shadow,
                journal_quota,
                expected_journal_length: *expected_journal_length,
            },
        ))
    }
}

impl BoundNativeRecoveryJournal {
    /// Open the actual share-zero native owner and retain its independently
    /// observed typed storage identity. No serialized identity is accepted as
    /// a substitute for the open and the native storage observations.
    pub(crate) fn open(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        ticket: &sj::SelectedTicket,
        marker_identity: Option<&JournalFileIdentity>,
        marker_use: MarkerStorageUse,
    ) -> Result<(Self, serde_json::Value)> {
        binding.validate()?;
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "bound recovery journal path must be absolute without traversal"
        );
        let (journal, identity, diagnostic) = NativeSelectedJournal::open_recovery_with_identity(
            path,
            binding,
            profile,
            ticket,
            marker_identity,
            marker_use,
            None,
            None,
        )?;
        let marker_native_qualified = journal.marker_observation().map(|o| o.native_qualified);
        let actual_path = journal.observed_guid_path(binding)?;
        let mut result = Self {
            journal,
            path: actual_path,
            binding: binding.clone(),
            identity,
            profile,
            journal_length: ticket.journal_length,
            marker_use,
            marker_native_qualified,
        };
        result.revalidate()?;
        Ok((result, diagnostic))
    }

    /// Recheck storage through the original held file/marker owner, not a
    /// reopened pathname or the previously serialized diagnostic record.
    pub(crate) fn revalidate(&mut self) -> Result<()> {
        self.binding.validate()?;
        match &mut self.journal.storage {
            Storage::Buffered(file) => {
                let actual =
                    observe_general_journal_file_with_profile(file, &self.binding, self.profile)?;
                ensure!(
                    actual.identity == self.identity
                        && actual.file_bytes == self.journal_length
                        && self.marker_native_qualified.is_none(),
                    "held recovery journal identity, length or profile changed"
                );
            }
            Storage::Sealed(file) => {
                file.revalidate_storage()?;
                let actual = file.observation();
                ensure!(
                    actual.identity == self.identity
                        && actual.journal_length == self.journal_length
                        && Some(actual.native_qualified) == self.marker_native_qualified,
                    "held native marker storage identity or length changed"
                );
            }
            Storage::Constructing(_) | Storage::Unavailable => {
                anyhow::bail!("recovery journal owner is not in an opened recovery state");
            }
        }
        ensure!(
            self.journal.observed_guid_path(&self.binding)? == self.path,
            "held native recovery journal same-handle route changed"
        );
        Ok(())
    }

    /// Borrow the actual journal and its typed same-owner facts together.
    /// The borrow cannot outlive this owner and is not a target-write permit.
    pub(crate) fn split_for_observation(
        &mut self,
    ) -> Result<(&mut NativeSelectedJournal, BoundNativeJournalFacts<'_>)> {
        self.revalidate()?;
        let Self {
            journal,
            path,
            binding,
            identity,
            profile,
            journal_length,
            marker_use,
            marker_native_qualified,
        } = self;
        Ok((
            journal,
            BoundNativeJournalFacts {
                path,
                binding,
                identity,
                profile: *profile,
                journal_length: *journal_length,
                marker_use: *marker_use,
                marker_native_qualified: *marker_native_qualified,
            },
        ))
    }
}

impl Read for NativeSelectedJournal {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match &mut self.storage {
            Storage::Buffered(file) => file.read(bytes),
            Storage::Constructing(file) => file.read(bytes),
            Storage::Sealed(file) => file.read(bytes),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl Write for NativeSelectedJournal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.prepared_body_sealed {
            let position = self.stream_position()?;
            if !position.checked_add(bytes.len() as u64).is_some_and(|end| end <= 8192) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                    "sealed prepared journal permits marker writes only"));
            }
        }
        if let Some(length) = self.fixed_length {
            let position = self.stream_position()?;
            if !position
                .checked_add(bytes.len() as u64)
                .is_some_and(|end| end <= length)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixed native journal write exceeds its pinned length",
                ));
            }
        }
        match &mut self.storage {
            Storage::Buffered(file) => file.write(bytes),
            Storage::Constructing(file) => file.write(bytes),
            Storage::Sealed(file) => file.write(bytes),
            Storage::Unavailable => Err(unavailable()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.storage {
            Storage::Buffered(file) => file.flush(),
            Storage::Constructing(file) => file.flush(),
            Storage::Sealed(file) => file.flush(),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl Seek for NativeSelectedJournal {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        match &mut self.storage {
            Storage::Buffered(file) => file.seek(from),
            Storage::Constructing(file) => file.seek(from),
            Storage::Sealed(file) => file.seek(from),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl ReadSeek for NativeSelectedJournal {
    fn byte_len(&mut self) -> io::Result<u64> {
        match &mut self.storage {
            Storage::Buffered(file) => Ok(file.metadata()?.len()),
            Storage::Constructing(file) => file.byte_len(),
            Storage::Sealed(file) => file.byte_len(),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl DurableIo for NativeSelectedJournal {
    fn sync_all(&mut self) -> io::Result<()> {
        match &mut self.storage {
            Storage::Buffered(file) => file.sync_all(),
            Storage::Constructing(file) => file.sync_all(),
            Storage::Sealed(file) => file.sync_all(),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
