//! Owning preparation for a selected data partition. Every source, expected
//! tree and shadow proof below comes from the actual native owners.
use super::*;
use crate::general_source_admission::resource::partition::{
    PartitionAuxiliaryDirectory, PartitionResourceSourceContext,
};
use n2r_win32::{
    partition_isolation::{PartitionObservationBudget, PartitionSourceBinding},
    partition_lifecycle::PartitionPreparationGuard,
};
#[path = "resource_partition_finalization.rs"]
pub(crate) mod finalization;
pub(crate) use finalization::{PartitionPendingFinalization, finalize_partition_handoff};

pub(crate) struct PartitionPreparationRequest {
    pub binding: PartitionSourceBinding,
    pub observation_budget: PartitionObservationBudget,
    pub resources: ResourceBudget,
    pub verification_policy: VerificationPolicy,
    pub target: partition_target::PartitionTargetRequest,
}

/// Actual owners stay together until the later journal/publication/apply scope
/// consumes them. No field is a serializable conversion authorization.
pub(crate) struct PartitionPreparedResources {
    pub context: PartitionResourceSourceContext,
    pub expected: PagedExpectedTree,
    pub target: partition_target::PartitionPreparedTargetCapture,
    _projection_seal: crate::artifact_arena::ArtifactGroupSeal,
    _expected_seal: crate::artifact_arena::ArtifactGroupSeal,
    _projection_directory: PartitionAuxiliaryDirectory,
}

/// Owns the actual live private context when a later preparation stage fails.
/// No serialized error/receipt can recreate the context or cancel a source.
pub(crate) struct PartitionPreparationFailure {
    cause: anyhow::Error,
    context: Option<PartitionResourceSourceContext>,
}
impl PartitionPreparationFailure {
    fn before_context(cause: anyhow::Error) -> Self {
        Self {
            cause,
            context: None,
        }
    }
    pub(crate) fn cause(&self) -> &anyhow::Error {
        &self.cause
    }
    /// Cancellation consumes the retained context. Its actual fingerprint,
    /// source-gate history and held-J state remain the parent's checks.
    pub(crate) fn cancel_if_live(
        self,
        observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> Result<serde_json::Value> {
        let Self { cause, context } = self;
        let Some(context) = context else {
            return Err(cause.context(
            "preparation did not return a live private context; no caller cancellation authority"));
        };
        context
            .cancel_unactivated(observer, events)
            .map_err(|cancel| {
                cause.context(format!(
                    "actual live unactivated cancellation refused: {cancel:#}"
                ))
            })
    }
}

/// Getter-derived recovery routing preserved before AP; diagnostic only.
#[derive(Clone, serde::Serialize)]
pub(crate) struct PartitionPublicationReceipt {
    pub kind: &'static str,
    pub publication_path: std::path::PathBuf,
    pub publication_sha256: String,
    pub locator_path: String,
    pub locator_sha256: [u8; 32],
    pub observed_before_apply_intent: bool,
}
pub(crate) enum PartitionExecutionProgress<'a> {
    Accounting(&'a serde_json::Value),
    Published(&'a PartitionPublicationReceipt),
    PostFlush(&'a crate::selected_journal::resource_domain::prepare::PartitionPostFlushReceipt),
}

pub(crate) struct PartitionExecutionRequest {
    pub journal: GeneralJournalStorageBinding,
    pub maximum_journal_bytes: u64,
    pub maximum_selected_bytes: u64,
    pub maximum_index_bytes: u64,
    pub recovery_arena_bytes: u64,
}

impl PartitionPreparedResources {
    /// Release every retained target/source-query witness before the actual
    /// context is consumed by its unactivated-source cancellation lane.
    pub(crate) fn cancel_unactivated(
        self,
        observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> Result<serde_json::Value> {
        let Self {
            context, target, ..
        } = self;
        drop(target);
        context.cancel_unactivated(observer, events)
    }
    /// Drop target/capture witnesses before opening the new filesystem. They
    /// retain query duplicates of the original locked NTFS FileObject. Expected
    /// pages and the completed HND's saved maps remain independently owned.
    pub(crate) fn into_terminal_inputs(
        self,
    ) -> (
        n2r_win32::PartitionScopedOwner,
        n2r_win32::partition_lifecycle::PartitionNtfsAdmission,
        PagedExpectedTree,
    ) {
        let Self {
            context,
            expected,
            target,
            ..
        } = self;
        drop(target);
        let (source, admission) = context.into_terminal_owners();
        (source, admission, expected)
    }

    /// Publish the actual prepared journal and recovery owners, then consume
    /// the real fresh certificate. The final SDK handoff witness keeps replay
    /// permanently closed before terminal mount/restoration is attempted.
    pub(crate) fn execute_and_handoff(
        &mut self,
        request: &PartitionExecutionRequest,
        arena_root: &Path,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
        mut progress: Option<
            impl FnMut(PartitionExecutionProgress<'_>, &mut Vec<NativeEvent>) -> Result<()>,
        >,
    ) -> Result<PartitionPendingFinalization> {
        use crate::{
            general_reconstruct::selected_native_journal::BoundPartitionCreationJournal,
            selected_journal::resource_domain::prepare::{
                PartitionResourcePreparedConversion,
                prepare_native_partition_from_protected_capture,
            },
        };
        request.journal.validate()?;
        ensure!(
            request.maximum_selected_bytes > 0
                && request.maximum_index_bytes > 0
                && request.recovery_arena_bytes > 0,
            "partition execution requires actual resource budgets"
        );
        let profile =
            JournalProfile::from_schema_and_capacity(3, Some(request.maximum_journal_bytes))?;
        let arena = self.context.arena().clone();
        let source_budget = SourceMetadataBudget::from_resource_budget(arena.budget())?;
        let admission = self.context.resource_admission();
        let capture_group = self.target.capture_group().clone();
        let expected = &self.expected;
        let pair = self.target.proof().scope().pair().clone();
        let mut terminal_files = None;
        let outcome = self.target.with_execution_domain(
            &mut self.context,
            ResourceJournalBudget {
                max_selected_bytes: request.maximum_selected_bytes,
                max_journal_bytes: request.maximum_journal_bytes,
                marker_profile: None,
            },
            &arena_root.join("journal-layout.index"),
            events,
            |domain, context, shadow, candidate, events| {
                // The capture/layout producer has closed. Charge actual
                // closed backing before reserving J/index/publication capacity.
                let _capture_seal = capture_group.seal()?;
                let recovery = arena
                    .reserve_group(ArtifactGroup::RecoveryCopy, request.recovery_arena_bytes)?;
                let recovery_scratch =
                    SourceScratch::new_auxiliary_in_arena(source_budget, recovery.clone())?;
                checkpoint("partition-native-journal-create", events)?;
                let mut creation = BoundPartitionCreationJournal::create_new(
                    context,
                    shadow,
                    &arena,
                    domain.facts().journal_length,
                    &arena_root.join("selected.journal"),
                    &request.journal,
                    profile,
                    events,
                )?;
                checkpoint("partition-native-journal-prepare", events)?;
                let prepared = prepare_native_partition_from_protected_capture(
                    domain,
                    context,
                    shadow,
                    candidate,
                    &mut creation,
                    &recovery,
                    &recovery_scratch,
                    &arena_root.join("native-write.index"),
                    request.maximum_index_bytes,
                    events,
                )?;
                // Advisory metadata facts at the actual prepared-J boundary.
                // The original held owners remain; no payload/source scan.
                if let Some(observe) = progress.as_mut() {
                    let accounting = prepared.pre_apply_accounting();
                    observe(PartitionExecutionProgress::Accounting(&accounting), events)?;
                }
                let map_required = prepared.recovery_maps_required(expected)?;
                let maps = if map_required {
                    Some(arena.reserve_group(
                        ArtifactGroup::Map,
                        admission.map_page_budget()?.max_file_bytes,
                    )?)
                } else {
                    None
                };
                let map_scratch = SourceScratch::new_auxiliary_in_arena(
                    source_budget,
                    // Map output keeps its separate Map permit below. Its
                    // scratch/RAM workspace uses the admitted recovery group.
                    recovery.clone(),
                )?;
                let map_path = arena_root.join("recovery-maps.pages");
                let publication_path = arena_root.join("recovery.json");
                let mut published = PartitionResourcePreparedConversion::publish(
                    prepared,
                    expected,
                    maps.as_ref(),
                    &map_scratch,
                    map_required.then_some(map_path.as_path()),
                    &recovery,
                    &recovery_scratch,
                    &arena_root.join("recovery.locator"),
                    &publication_path,
                    events,
                    |events| checkpoint("partition-recovery-publication", events),
                )?;
                // Capture trusted publisher hashes and actual readonly file
                // owners BEFORE fresh apply can publish AP. Locator is a
                // same-FileObject duplicate, not a share-zero path reopen.
                ensure!(
                    terminal_files.is_none(),
                    "partition terminal publication captured twice"
                );
                terminal_files = Some(finalization::PartitionPublishedFiles::capture(
                    &mut published,
                    &arena,
                )?);
                if let Some(observe) = progress.as_mut() {
                    let receipt = PartitionPublicationReceipt {
                        kind: "partition-actual-publisher-before-AP-v1",
                        publication_path: published.publication_path().to_owned(),
                        publication_sha256: published.publication_sha256().to_owned(),
                        locator_path: published.locator_path().to_owned(),
                        locator_sha256: published.locator_sha256(),
                        observed_before_apply_intent: true,
                    };
                    // This callback must persist the actual publisher pin
                    // synchronously while all published owners remain held.
                    observe(PartitionExecutionProgress::Published(&receipt), events)?;
                    ensure!(
                        events.is_empty(),
                        "pre-AP publisher observer did not drain actual events"
                    );
                }
                println!("Recovery metadata: {}", publication_path.display());
                println!(
                    "Trusted recovery publication SHA256 before AP: {}",
                    published.publication_sha256()
                );
                std::io::stdout().flush()?;
                let fresh = published.into_fresh_apply(events, |events| {
                    checkpoint("partition-fresh-source-certificate", events)
                })?;
                Ok(match progress {
                    Some(mut observe) => fresh.apply_and_handoff_with_post_flush(
                        events,
                        |events| checkpoint("partition-apply-and-handoff", events),
                        |_| Ok(()),
                        |receipt, events| {
                            observe(PartitionExecutionProgress::PostFlush(receipt), events)
                        },
                    ),
                    None => fresh.apply_and_handoff(
                        events,
                        |events| checkpoint("partition-apply-and-handoff", events),
                        |_| Ok(()),
                    ),
                })
            },
        )?;
        Ok(PartitionPendingFinalization::from_actual_handoff(
            outcome,
            terminal_files.context("actual HND lacks pre-AP publication owners")?,
            pair,
        ))
    }
}

/// The arena already owns its ordinary external root. Source collection,
/// expected projection and target construction all use children of that same
/// root, preserving the actual native disjoint-volume checks and quotas.
#[derive(Clone, Copy)]
enum PreparationSourceMode {
    Private,
    ReadonlyPhysical,
}
pub(crate) fn prepare_partition_resources(
    request: PartitionPreparationRequest,
    arena_root: &Path,
    arena: &ArtifactArena,
    guard: PartitionPreparationGuard,
    events: &mut Vec<NativeEvent>,
    checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
) -> std::result::Result<PartitionPreparedResources, PartitionPreparationFailure> {
    prepare_partition_resources_with_mode(
        request,
        arena_root,
        arena,
        guard,
        events,
        checkpoint,
        PreparationSourceMode::Private,
    )
}
pub(crate) fn prepare_partition_resources_readonly_physical(
    request: PartitionPreparationRequest,
    arena_root: &Path,
    arena: &ArtifactArena,
    guard: PartitionPreparationGuard,
    events: &mut Vec<NativeEvent>,
    checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
) -> std::result::Result<PartitionPreparedResources, PartitionPreparationFailure> {
    prepare_partition_resources_with_mode(
        request,
        arena_root,
        arena,
        guard,
        events,
        checkpoint,
        PreparationSourceMode::ReadonlyPhysical,
    )
}
fn prepare_partition_resources_with_mode(
    request: PartitionPreparationRequest,
    arena_root: &Path,
    arena: &ArtifactArena,
    guard: PartitionPreparationGuard,
    events: &mut Vec<NativeEvent>,
    mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
    mode: PreparationSourceMode,
) -> std::result::Result<PartitionPreparedResources, PartitionPreparationFailure> {
    let mut context = (|| -> Result<PartitionResourceSourceContext> {
        request.binding.validate()?;
        request.observation_budget.validate()?;
        request.resources.validate()?;
        ensure!(
            request.binding.storage == request.target.pair.source
                && arena.budget() == request.resources,
            "partition preparation source/profile/arena differs"
        );
        // Check the actual root before any source protection transition.
        let root = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(arena_root)?;
        arena.require_root_directory(&root)?;
        checkpoint("partition-source-preparation", events)?;
        match mode {
            PreparationSourceMode::Private => ResourceSourceContext::prepare_partition(
                request.binding,
                request.observation_budget,
                request.resources,
                request.verification_policy,
                &arena_root.join("source-evidence"),
                arena,
                guard,
                events,
            ),
            PreparationSourceMode::ReadonlyPhysical => {
                ResourceSourceContext::prepare_partition_readonly_physical(
                    request.binding,
                    request.observation_budget,
                    request.resources,
                    request.verification_policy,
                    &arena_root.join("source-evidence"),
                    arena,
                    guard,
                    events,
                )
            }
        }
    })()
    .map_err(PartitionPreparationFailure::before_context)?;
    let prepared = (|| -> Result<_> {
        context.require_source_evidence()?;
        context.recheck_source(events)?;
        checkpoint("partition-expected-projection", events)?;
        let admission = context.resource_admission();
        let source_budget = SourceMetadataBudget::from_resource_budget(request.resources)?;
        let auxiliary =
            arena.reserve_group(ArtifactGroup::Auxiliary, source_budget.scratch_bytes)?;
        let scratch = SourceScratch::new_auxiliary_in_arena(source_budget, auxiliary)?;
        let projection_path = arena_root.join("projection");
        let projection_directory = context.create_auxiliary_directory(&projection_path, events)?;
        let projection = SourceExpectedDomain::derive(
            context.inspection(),
            context.native().domain(),
            admission,
            &projection_path,
            &scratch,
        )?;
        let expected_group = arena.reserve_group(
            ArtifactGroup::Expected,
            admission.expected_page_budget()?.max_file_bytes,
        )?;
        let expected_path = arena_root.join("expected.pages");
        let (receipt, artifact) = PagedExpectedTree::create_with_resources_in_group(
            &projection,
            &expected_path,
            admission,
            &expected_group,
        )?;
        let expected = PagedExpectedTree::open_with_resources_in_group(
            &expected_path,
            &receipt.file_sha256,
            &receipt.semantic_sha256,
            admission,
            &expected_group,
            artifact,
        )?;
        let expected_seal = expected_group.seal()?;
        expected.require_resource_owner(admission)?;
        expected.require_shared_memory(arena)?;
        // The independently reopened expected tree owns its bytes. Release the
        // projection decoding workspace before native allocation starts.
        drop(projection);
        let projection_seal = scratch.seal()?;
        projection_directory.revalidate(&mut context, events)?;
        checkpoint("partition-expected-closed", events)?;
        let target = partition_target::prepare_partition_target_capture(
            &mut context,
            &expected,
            &request.target,
            &arena_root.join("target-construction"),
            events,
            &mut checkpoint,
        )?;
        context.recheck_source(events)?;
        expected_seal.revalidate()?;
        projection_directory.revalidate(&mut context, events)?;
        checkpoint("partition-source-and-shadow-prepared", events)?;
        Ok((
            expected,
            target,
            projection_seal,
            expected_seal,
            projection_directory,
        ))
    })();
    // The borrowing stage closure has dropped its target/query objects before
    // an error moves this same context into the live cancellation owner.
    match prepared {
        Ok((expected, target, projection_seal, expected_seal, projection_directory)) => {
            Ok(PartitionPreparedResources {
                context,
                expected,
                target,
                _projection_seal: projection_seal,
                _expected_seal: expected_seal,
                _projection_directory: projection_directory,
            })
        }
        Err(cause) => Err(PartitionPreparationFailure {
            cause,
            context: Some(context),
        }),
    }
}

/// Windows-only prepare/publish result, not an apply authorization. All body,
/// index, expected/maps and native preservation checks already ran on real owners.
impl PartitionPreparedResources {
    pub(crate) fn prepare_for_offline_apply(
        mut self,
        request: &PartitionExecutionRequest,
        arena_root: &Path,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<crate::selected_journal::resource_domain::prepare::WindowsPreparedBundleCore> {
        use crate::{
            general_reconstruct::selected_native_journal::BoundPartitionCreationJournal,
            selected_journal::resource_domain::prepare::{
                PartitionResourcePreparedConversion,
                prepare_native_partition_from_protected_capture,
            },
        };
        request.journal.validate()?;
        ensure!(
            request.journal.disk.disk_number != self.context.binding().storage.disk_number
                && n2r_win32::layout::guid_bytes(&request.journal.disk.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(
                        &self.context.binding().storage.identity.disk_guid
                    )?,
            "Windows prepare-only journal/metadata must be on another physical disk"
        );
        let profile =
            JournalProfile::from_schema_and_capacity(3, Some(request.maximum_journal_bytes))?;
        let arena = self.context.arena().clone();
        let admission = self.context.resource_admission();
        let source_budget = SourceMetadataBudget::from_resource_budget(admission.budget)?;
        let capture_group = self.target.capture_group().clone();
        let expected = &self.expected;
        let bundle = self.target.with_journal_domain(
            &mut self.context,
            ResourceJournalBudget {
                max_selected_bytes: request.maximum_selected_bytes,
                max_journal_bytes: request.maximum_journal_bytes,
                marker_profile: None,
            },
            &arena_root.join("journal-layout.index"),
            events,
            |domain, context, shadow, candidate, events| {
                let _capture_seal = capture_group.seal()?;
                let recovery = arena
                    .reserve_group(ArtifactGroup::RecoveryCopy, request.recovery_arena_bytes)?;
                let recovery_scratch =
                    SourceScratch::new_auxiliary_in_arena(source_budget, recovery.clone())?;
                checkpoint("windows-offline-prepare-native-journal-create", events)?;
                let mut creation = BoundPartitionCreationJournal::create_new(
                    context,
                    shadow,
                    &arena,
                    domain.facts().journal_length,
                    &arena_root.join("selected.journal"),
                    &request.journal,
                    profile,
                    events,
                )?;
                let prepared = prepare_native_partition_from_protected_capture(
                    domain,
                    context,
                    shadow,
                    candidate,
                    &mut creation,
                    &recovery,
                    &recovery_scratch,
                    &arena_root.join("native-write.index"),
                    request.maximum_index_bytes,
                    events,
                )?;
                checkpoint("windows-offline-prepare-native-journal-closed", events)?;
                let required = prepared.recovery_maps_required(expected)?;
                let maps = if required {
                    Some(arena.reserve_group(
                        ArtifactGroup::Map,
                        admission.map_page_budget()?.max_file_bytes,
                    )?)
                } else {
                    None
                };
                let map_scratch =
                    SourceScratch::new_auxiliary_in_arena(source_budget, recovery.clone())?;
                let map_path = arena_root.join("recovery-maps.pages");
                let mut published = PartitionResourcePreparedConversion::publish(
                    prepared,
                    expected,
                    maps.as_ref(),
                    &map_scratch,
                    required.then_some(map_path.as_path()),
                    &recovery,
                    &recovery_scratch,
                    &arena_root.join("recovery.locator"),
                    &arena_root.join("recovery.json"),
                    events,
                    |events| checkpoint("windows-offline-prepare-sealed-publication", events),
                )?;
                let bundle = published.snapshot_for_offline_apply(events)?;
                checkpoint("windows-offline-prepare-clear-bundle-snapshotted", events)?;
                // No into_fresh_apply, root certificate or SDK write gate here.
                Ok(bundle)
            },
        )?;
        self.context.recheck_source(events)?;
        checkpoint("windows-offline-prepare-source-clear-closing", events)?;
        // Close all query duplicates before the original volume LOCK owner.
        // Persistent BASIC+RO remains; no cleanup/restore/retirement is called.
        let Self {
            context,
            expected,
            target,
            _projection_seal,
            _expected_seal,
            _projection_directory,
        } = self;
        drop(target);
        drop(expected);
        drop(_projection_directory);
        drop(_projection_seal);
        drop(_expected_seal);
        drop(context);
        Ok(bundle)
    }
}
