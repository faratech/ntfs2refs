//! Actual BasicRO closed-only owner. No private state, FS lock or old admission.
use super::*;
use crate::{
    artifact_arena::ArtifactLease,
    general_reconstruct::fast_verification::v4_maps::reopened::ReopenedVerificationMetadata,
};
pub(crate) struct PartitionBasicRoClosedTerminal {
    recovery: ReopenedPartitionResourceRecovery,
    source: n2r_win32::partition_restoration::PartitionBasicReadonlyTerminal,
    files: n2r_win32::partition_restoration::PartitionRestartFiles,
    published_sha: [u8; 32],
    closed: n2r_win32::PartitionClosedJournalObservation,
    policy: n2r_win32::HeldPagedWritePolicy,
    _index: ArtifactLease,
}
impl PartitionBasicRoClosedTerminal {
    pub(crate) fn kind(&self) -> n2r_win32::PartitionTerminalKind {
        self.closed.kind()
    }
    pub(crate) fn open(
        mut source: n2r_win32::partition_restoration::PartitionBasicReadonlyTerminal,
        path: &Path,
        independently_supplied_sha256: [u8; 32],
        maximum_publication_bytes: u64,
        expected_shadow: &GeneralDiskBinding,
        expected_journal: &GeneralJournalStorageBinding,
        group: &ArtifactGroupPermit,
        scratch: &SourceScratch,
        index_path: &Path,
        maximum_index_bytes: u64,
        observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        let stable = source.owner_token().clone();
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
        source.revalidate(observer, events)?;
        ensure!(
            stable.same_owner(source.owner_token()),
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
        adopt_review(publication.review_before_handoff, false)?;
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
        let explicit = match &publication.source_scope {
            super::super::source_scope::ResourceRecoverySourceScope::Partition(scope) => scope,
            _ => anyhow::bail!("missing/dedicated publication cannot enter partition recovery"),
        };
        ensure!(
            explicit.binding == *source.binding()
                && publication.source == source.binding().storage
                && &publication.shadow == expected_shadow
                && !publication.serialized_publication_grants_authority
                && publication.early_preparation_guard.is_none(),
            "foreign scope or legacy whole-disk guard in partition publication"
        );
        expected_shadow.validate()?;
        ensure!(
            expected_shadow.disk_number != source.binding().storage.disk_number
                && n2r_win32::layout::guid_bytes(&expected_shadow.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&source.binding().storage.identity.disk_guid)?,
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
                .eq_ignore_ascii_case(&publication.expected.file.path),
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
            explicit.native_metadata.budget
                == publication.resource_admission.native_observation_budget()?,
            "restart native metadata budget differs from authenticated resource admission"
        );
        let intent = &explicit.complete_preparation_guard;
        let held_intent = HeldFile::open(
            Path::new(&intent.intent_file.final_path),
            digest(&intent.intent_prefix_sha256)?,
            Some(intent.intent_file.file_bytes),
            16 * 1024 * 1024,
            scratch,
        )?;
        let held_native = HeldFile::open(
            Path::new(&explicit.native_metadata.path),
            digest(&explicit.native_metadata.sha256)?,
            Some(explicit.native_metadata.bytes),
            explicit.native_metadata.budget.pages.max_file_bytes,
            scratch,
        )?;
        let ticket = locator.ticket();
        let files = n2r_win32::partition_restoration::PartitionRestartFiles {
            publication: publication_file.file.try_clone()?,
            locator: locator.duplicate_readonly_origin_file()?,
            preparation_intent: held_intent.file.try_clone()?,
            native_metadata: held_native.file.try_clone()?,
        };
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
        require_basic_ro_artifact_volume(
            &source,
            &publication.source_scope,
            &mut journal,
            &artifacts,
            observer,
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
        let kind = match lifecycle {
            SelectedLifecycle::Handoff => n2r_win32::PartitionTerminalKind::Handoff,
            SelectedLifecycle::Aborted => n2r_win32::PartitionTerminalKind::Aborted,
            _ => anyhow::bail!(
                "actual BasicRO source admits closed HND/ABT finalization only; no raw replay"
            ),
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
        let closed = source.authenticate_closed(
            &policy,
            observation.observation.journal.markerless_recovery_file()?,
            &pins,
            kind,
            observer,
            events,
        )?;
        drop(observation);
        let recovery = ReopenedPartitionResourceRecovery {
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
        };
        Ok(Self {
            recovery,
            source,
            files,
            published_sha: independently_supplied_sha256,
            closed,
            policy,
            _index: index,
        })
    }
    pub(crate) fn finalize(
        mut self,
        observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<serde_json::Value> {
        let stable = self.source.owner_token().clone();
        let kind = self.closed.kind();
        self.closed.require_owner(&stable)?;
        checkpoint("partition-closed-private-opening", events)?;
        self.recovery
            .publication_file
            .revalidate(&self.recovery.scratch)?;
        self.recovery.expected.revalidate(&self.recovery.scratch)?;
        if let Some(maps) = &mut self.recovery.maps {
            maps.revalidate(&self.recovery.scratch)?;
        }
        self.recovery.locator.revalidate()?;
        self.recovery.journal.revalidate()?;
        let ticket = self.recovery.locator.ticket().clone();
        {
            let (journal, facts) = self.recovery.journal.split_for_observation()?;
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
            self.closed = self.source.authenticate_closed(
                &self.policy,
                journal.markerless_recovery_file()?,
                &pins,
                kind,
                observer,
                events,
            )?;
        }
        let metadata = if kind == n2r_win32::PartitionTerminalKind::Handoff {
            Some(ReopenedVerificationMetadata::open_closed_partition(
                &self.recovery,
                &self.closed,
                &stable,
            )?)
        } else {
            None
        };
        let shadow = self.recovery.publication.shadow.clone();
        let admission = self.recovery.publication.resource_admission;
        let arena = self
            .recovery
            .scratch
            .artifact_group()
            .context("actual closed recovery arena absent")?
            .arena()
            .clone();
        let (journal, facts) = self.recovery.journal.split_for_observation()?;
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
        checkpoint("partition-closed-private-authenticated", events)?;
        let mut guard = self.source.into_authenticated_terminal(
            self.files,
            self.published_sha,
            &self.policy,
            journal.markerless_recovery_file()?,
            pins,
            kind,
            observer,
            events,
        )?;
        checkpoint("partition-basic-ro-closed-native", events)?;
        let mut bindings = 0;
        let mut known_streams = 0;
        let mut extent_streams = 0;
        let restored = if let Some(metadata) = metadata.as_ref() {
            let native = {
                let readonly = guard.readonly_volume()?;
                ensure!(
                    readonly.owner_token().same_owner(&stable),
                    "actual closed terminal readonly owner changed"
                );
                let pair = GeneralSourceShadowBinding {
                    source: readonly.binding().clone(),
                    shadow,
                };
                let native = readonly.observe_converted_metadata_with_memory(
                    pair,
                    &crate::general_shadow::PagedInputs(metadata.expected()),
                    None,
                    |a, b| crate::ntfs_attestation::same_security(a, b).map_err(io::Error::other),
                    ResourceProfile::ResourceBoundedV4(Some(admission)),
                    &crate::general_composite_target::paged_memory::ArenaReportMemory(
                        arena.clone(),
                    ),
                    true,
                    events,
                )?;
                bindings = metadata.compare_partition(&stable, &native)?;
                let known = native
                    .report()
                    .content_observation
                    .as_ref()
                    .and_then(|c| c.known_content.as_ref())
                    .context("actual closed HND known-content observation absent")?;
                known_streams = known.streams_hashed;
                extent_streams = known.streams_without_content_baseline;
                native
            };
            checkpoint("partition-closed-hnd-verified-before-rw", events)?;
            guard.finish(native, observer, events)?
        } else {
            ensure!(
                kind == n2r_win32::PartitionTerminalKind::Aborted,
                "closed HND lacks actual expected/maps capability"
            );
            checkpoint("partition-closed-abt-old-before-rw", events)?;
            guard.finish_aborted(observer, events)?
        };
        checkpoint("partition-closed-original-mounts-restored", events)?;
        // After RW publication authenticate only held metadata/J facts, never stale
        // conversion-time source bytes or an operational filesystem's contents.
        self.recovery
            .publication_file
            .revalidate(&self.recovery.scratch)?;
        self.recovery.expected.revalidate(&self.recovery.scratch)?;
        if let Some(maps) = &mut self.recovery.maps {
            maps.revalidate(&self.recovery.scratch)?;
        }
        self.recovery.locator.revalidate()?;
        self.recovery.journal.revalidate()?;
        Ok(
            serde_json::json!({"kind":"partition-basic-ro-closed-terminal-finalization-v1","success":true,
   "terminal":if kind==n2r_win32::PartitionTerminalKind::Handoff{"HND"}else{"ABT"},
   "restoration":restored,"raw_replay_performed":false,"source_replay_gate_issued":false,"lifecycle_marker_written":false,
   "native_terminal_verified_before_writable":true,"matching_map_bindings":bindings,
   "known_streams_hashed":known_streams,"extent_only_streams":extent_streams,
   "recovery_files_retired":false,"operational_basic0_reconciliation_supported":false,"stable_release_qualification":false}),
        )
    }
}

fn require_basic_ro_artifact_volume(
    source: &n2r_win32::partition_restoration::PartitionBasicReadonlyTerminal,
    scope: &super::super::source_scope::ResourceRecoverySourceScope,
    journal: &mut BoundNativeRecoveryJournal,
    artifacts: &[&ReferenceFileSnapshot],
    observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> Result<()> {
    ensure!(
        !scope.is_dedicated(),
        "same-disk policy requires explicit partition scope"
    );
    source.revalidate(observer, events)?;
    let (actual, facts) = journal.split_for_observation()?;
    scope.require_journal_route(&source.binding().storage, facts.binding)?;
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
    source.revalidate(observer, events)?;
    Ok(())
}
