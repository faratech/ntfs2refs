//! Actual selected-partition source preparation. This parallel context never
//! manufactures GeneralDiskState/GeneralFreezeObservation or enables a CLI.
use super::*;
use n2r_win32::{
    PartitionOwnerState, PartitionOwnerToken, PartitionScopedOwner,
    attestation::NativeObservationDomain,
    attestation_partition::{PartitionPagedNtfsObservation, collect_partition_ntfs_paged},
    partition_isolation::{PartitionObservationBudget, PartitionSourceBinding},
    partition_lifecycle::{
        PartitionNtfsAdmission, PartitionPreparationGuard, PartitionReadonlyPhase,
        freeze_mounted_ntfs_partition,
    },
};

pub(crate) struct PartitionResourceSourceContext {
    source: PartitionScopedOwner,
    token: Box<PartitionOwnerToken>,
    native_admission: PartitionNtfsAdmission,
    collected: CollectedPartitionSource,
    arena: ArtifactArena,
    source_seal: ArtifactGroupSeal,
    native_seal: ArtifactGroupSeal,
    native_artifact: ArtifactLease,
    output_basis: ArenaOutputBasis,
    binding: PartitionSourceBinding,
}
struct CollectedPartitionSource {
    raw: PagedInspection,
    fingerprint: PagedSourceFingerprint,
    read_coverage: InspectionReadCoverage,
    inspection_sha: String,
    source_sha: String,
    source_views_sha: String,
    backups: ntfs_backup::VerifiedBackups,
    log: ntfs_log::VerifiedRestart,
    indexes: ntfs_internal::PagedVerifiedIndexes,
    transactions: ntfs_transactions::VerifiedTransactions,
    label: n2r_win32::volume_label::VolumeLabel,
    label_frozen: source_volume_label::FrozenLabelProof,
    mount_paths: MountPathObservation,
    comparison: PagedComparisonSummary,
    rows: SortedRecordStore,
    unresolved: SortedRecordStore,
    replacements: SortedRecordStore,
    admission: SourceResourceAdmission,
    gates: Vec<Gate>,
    scratch: SourceScratch,
    metadata: Vec<MetadataPin>,
    reservations: Vec<SourceTemporaryLease>,
    _source_io_ram: SourceRamLease,
    _native_payer_ram: SourceRamLease,
}
#[derive(Serialize)]
pub(crate) struct PartitionResourceSourceReport<'a> {
    kind: &'static str,
    scope: &'static str,
    binding: &'a PartitionSourceBinding,
    private_enrollment_state: &'a PartitionOwnerState,
    readonly_before: &'a n2r_win32::attestation_partition::PartitionReadonlyRoute,
    readonly_after: &'a n2r_win32::attestation_partition::PartitionReadonlyRoute,
    inspection_sha256: &'a str,
    source_sha256: &'a str,
    source_views_sha256: &'a str,
    comparison: &'a PagedComparisonSummary,
    comparison_rows: &'a RecordStorePin,
    unresolved: &'a RecordStorePin,
    replacements: &'a RecordStorePin,
    gates: &'a [Gate],
    source_group_allocated_bytes: u64,
    native_group_allocated_bytes: u64,
    target_preservation_complete: bool,
    certificate_issued: bool,
    execution_authorized: bool,
}
impl ResourceSourceContext {
    /// Complete bounded source collection for an ACTUAL supplied lifecycle
    /// guard. Returns a distinct context until target/capture/recovery routing
    /// is explicitly partition-scoped; never enters legacy dedicated methods.
    pub(crate) fn prepare_partition(
        binding: PartitionSourceBinding,
        observation_budget: PartitionObservationBudget,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        arena: &ArtifactArena,
        mut guard: PartitionPreparationGuard,
        events: &mut Vec<NativeEvent>,
    ) -> Result<PartitionResourceSourceContext> {
        binding.validate()?;
        observation_budget.validate()?;
        budget.validate()?;
        ensure!(
            arena.budget() == budget,
            "partition source arena resource budget differs"
        );
        let source_group = arena.reserve_group(
            ArtifactGroup::Source,
            SourceMetadataBudget::from_resource_budget(budget)?.scratch_bytes,
        )?;
        let native_group =
            arena.reserve_group(ArtifactGroup::Native, budget.page_budget()?.max_file_bytes)?;
        let scratch = SourceScratch::new_in_arena(
            SourceMetadataBudget::from_resource_budget(budget)?,
            source_group.clone(),
        )?;
        let source_io_ram = scratch.lease_ram(GeneralFrozenPartition::read_buffer_memory_bytes())?;
        let native_payer_ram =
            scratch.lease_ram(std::mem::size_of::<SourceNativeMemory>() as u64 + 128)?;
        let available = n2r_win32::resource_native::observe_available_resources(
            output.parent().context("partition output parent absent")?,
        )?;
        available.validate_budget(budget)?;
        ensure!(!output.exists(), "fresh partition source output required");
        guard.protect_basic_readonly(events)?;
        let mut collected = None;
        let mut output_basis = None;
        let mut native_artifact = None;
        let preparation=guard.collect_native_with(events,|phase,events| {
            (|| -> Result<PartitionPagedNtfsObservation> {
                ensure!(phase.binding()==&binding,"actual mounted partition guard binding differs");
                phase.revalidate(events)?;
                let mut basis=output_in_partition_arena(phase,output,arena,events)?;
                let guid_output=PathBuf::from(&basis.parent_guid).join(output.file_name().context("partition output leaf absent")?);
                basis.create_directory(output,&guid_output)?;
                let source_output=output.join("source");let native_output=output.join("native");
                basis.create_directory(&source_output,&guid_output.join("source"))?;
                basis.create_directory(&native_output,&guid_output.join("native"))?;
                validate_partition_output(&basis,&binding,arena)?;
                let mut metadata=Vec::new();let mut reservations=Vec::new();
                save(&source_output,"partition-source-intent.json",&serde_json::json!({"binding":binding,
                    "budget":budget,"available":available,"policy":policy,"scope":"selected_partition",
                    "source_admitted":false,"execution_authorized":false}),&scratch,&mut metadata,&mut reservations)?;
                let label=phase.original_label().clone();
                let mount_paths=phase.capture_mount_paths(events)?;
                ensure!(mount_paths.binding==binding.storage && mount_paths.all_paths_resolve_to_bound_volume,
                    "partition mounted path evidence differs");
                let length=binding.storage.identity.partition_bytes;
                let (raw,read_coverage,fingerprint,source_sha,backups,log,label_frozen,mut indexes)={
                    let mut source=phase.read_source(events)?;
                    let (raw,read_coverage)=fp::inspect_recorded_with_scratch(&mut source,length,budget,policy,
                        &source_output.join("recorded-source"),&scratch)?;
                    ensure!(ntfs_admission::ResourceProfile::ResourceBoundedV4(None).supports_source_geometry(&raw.header().geometry),
                        "partition NTFS geometry exceeds implemented resource profile");
                    let fingerprint=PagedSourceFingerprint::for_inspection(&raw,length,policy,&source_output.join("fingerprint"))?;
                    fingerprint.validate_inspection_reads(&read_coverage)?;
                    let source_sha=fingerprint.hash_partition_reader(&mut source,length)?;
                    let backups=ntfs_backup::verify_domain(&mut source,length,&raw)?;
                    let log=ntfs_log::verify_domain(&mut source,&raw)?;
                    let label_frozen=source_volume_label::verify_domain(&mut source,&raw,&label)?;
                    let indexes=ntfs_internal::verify_domain(&mut source,&raw,&source_output.join("internal-indexes"))?;
                    (raw,read_coverage,fingerprint,source_sha,backups,log,label_frozen,indexes)
                };
                // Borrowed raw reader and all its file handles are CLOSED before
                // native collection can acquire its own mounted source handles.
                let inspection_sha=raw.canonical_sha256()?;
                save(&source_output,"source-manifest.json",raw.pin(),&scratch,&mut metadata,&mut reservations)?;
                save(&source_output,"inspection-read-coverage.json",&read_coverage.report()?,&scratch,&mut metadata,&mut reservations)?;
                let selectors=PagedObservationRequest::new(&raw,&binding.storage,budget,policy)?;
                let admission=selectors.admission();
                let native_path=native_output.join("native.pages");
                let native_permit=native_group.reserve_file(&native_path,admission.native_page_budget()?.max_file_bytes)?;
                let native=collect_partition_ntfs_paged(phase,&selectors,native_permit.path(),
                    admission.native_observation_budget()?,true,Arc::new(SourceNativeMemory(arena.clone())),events)?;
                drop(selectors);
                ensure!(native.domain().retained_storage_ram_accounted(),"partition native pages lost actual arena memory leases");
                let artifact=native_permit.verify_closed(native.domain().sha256())?;
                indexes.bind_partition_native_quota(&native);
                let transactions=ntfs_transactions::verify_partition_domain(&raw,&log,phase,&native,events)?;
                let after_hash={let mut reader=phase.read_source(events)?;
                    fingerprint.hash_partition_reader(&mut reader,length)?};
                ensure!(source_sha==after_hash,"partition source fingerprint changed across native observation");
                let before=native.before();let after=native.after();
                let output=source_output.as_path();        let mut rows_writer =
            SortedRecordWriter::new(&output.join("source-comparison"), *b"N2RSCMP1", &scratch)?;
        let mut row_count = 0u64;
        let mut policy_rejections = 0u64;
        let mut no_dos = true;
        let (mut files, mut directories, mut streams, mut logical_bytes) = (0u64, 0u64, 0u64, 0u64);
        let (mut raw_directories, mut user_case_matched, mut internal_directories) =
            (0u64, 0u64, 0u64);
        let internal_bound = indexes.binds_domain(&raw)
            && indexes.replacement_supported
            && transactions.binds_domain(&raw)
            && backups.binds_domain(&raw)
            && log.binds_domain(&raw);
        let mut replacements_writer = SortedRecordWriter::new(
            &output.join("internal-replacements"),
            *b"N2RREPL1",
            &scratch,
        )?;
        let comparison = crate::ntfs_attestation::paged::compare_partition_domain(&raw, &binding.storage, budget, policy, &native, phase, events, |row| {
            let file = raw
                .find_record(row.record_number, Some(row.sequence_number))?
                .context("compared source identity absent")?;
            no_dos &= file.names.iter().all(|name| name.namespace != 2);
            let role = ntfs_admission::paged::internal_role(&raw, &file)?;
            ensure!(
                role == row.internal_replacement_role,
                "source replacement role changed"
            );
            let issues = if let Some(role) = &role {
                let action = match role.as_str() {
                    "$Volume" if indexes.covers_volume_object_id_domain(&raw, 3) => {
                        "replace_filesystem_internal_volume_identity"
                    }
                    "$Extend\\$ObjId" if indexes.internal_volume_object_id().is_some() => {
                        "replace_ntfs_internal_volume_identity_index"
                    }
                    "$LogFile" | "$Extend\\$UsnJrnl" => "start_new_filesystem_journal_epoch",
                    "$Extend\\$RmMetadata\\$Repair" => "replace_ntfs_runtime_diagnostics",
                    role if role.starts_with("$Extend\\$RmMetadata")
                        || role == "$Extend\\$Deleted" =>
                    {
                        "replace_idle_default_transaction_metadata"
                    }
                    _ => "replace_with_native_refs_structure",
                };
                replacements_writer.push(
                    key(file.record_number),
                    &InternalReplacement {
                        record_number: file.record_number,
                        sequence_number: file.sequence_number,
                        role: role.clone(),
                        action,
                    },
                )?;
                Vec::new()
            } else {
                if file.is_directory {
                    directories = directories
                        .checked_add(1)
                        .context("directory count overflow")?;
                } else {
                    files = files.checked_add(1).context("file count overflow")?;
                    streams = streams
                        .checked_add(file.streams.len() as u64)
                        .context("stream count overflow")?;
                    for stream in &file.streams {
                        logical_bytes = logical_bytes
                            .checked_add(stream.logical_size)
                            .context("logical total overflow")?;
                    }
                }
                ntfs_admission::paged::ordinary_user_issues(&raw, &file, admission)?
            };
            policy_rejections = policy_rejections
                .checked_add(u64::from(!issues.is_empty()))
                .context("policy refusal count overflow")?;
            if file.is_directory {
                raw_directories = raw_directories
                    .checked_add(1)
                    .context("raw directory count overflow")?;
                if role.is_some() {
                    internal_directories = internal_directories
                        .checked_add(1)
                        .context("internal directory count overflow")?;
                } else if row.directory_case.as_ref().is_some_and(|c| c.matched) {
                    user_case_matched = user_case_matched
                        .checked_add(1)
                        .context("case-match count overflow")?;
                }
            }
            rows_writer.push(
                key(file.record_number),
                &ObjectRow {
                    native: row,
                    user_issues: issues,
                    independent_internal_state_checks_passed: role.is_some() && internal_bound,
                },
            )?;
            row_count = row_count
                .checked_add(1)
                .context("comparison row count overflow")?;
            Ok(())
        })?;
        let rows_pin = rows_writer.finish()?;
        let replacements_pin = replacements_writer.finish()?;
        ensure!(
            row_count == raw.file_count(),
            "complete per-object source comparison coverage differs"
        );
        let short_policy = short_names_partition(&raw, &native, no_dos);
        let mut unresolved_writer = SortedRecordWriter::new(
            &output.join("unresolved-source-blockers"),
            *b"N2RBLOCK",
            &scratch,
        )?;
        let mut unresolved_count = 0u64;
        for ordinal in 0..raw.blocker_count() {
            let blocker = raw.blocker(ordinal)?;
            if ntfs_admission::paged::blocker_is_unresolved(
                &raw,
                &blocker,
                &backups,
                &log,
                &indexes,
                &transactions,
                short_policy,
            )? {
                unresolved_writer.push(key(unresolved_count), &blocker)?;
                unresolved_count = unresolved_count
                    .checked_add(1)
                    .context("blocker count overflow")?;
            }
        }
        let unresolved_pin = unresolved_writer.finish()?;
        let mut gates = Vec::new();
        let clean = raw.header().dirty == Some(false)
            && raw
                .header()
                .volume_flags
                .is_some_and(|flags| flags & 1 == 0)
            && raw.header().volume_version.as_deref() == Some("3.1");
        let policy_flags = raw.header().volume_flags == Some(0) || short_policy;
        let resource_counts = admission.validate_tree(files, directories, streams).is_ok()
            && files > 0
            && logical_bytes <= i64::MAX as u64;
        let source_objects =
            comparison.all_supported_user_views_compatible && policy_rejections == 0;
        for (code, satisfied, detail) in [
            (
                "geometry",
                ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission))
                    .supports_source_geometry(&raw.header().geometry),
                "actual source geometry matches the implemented profile",
            ),
            (
                "clean_volume",
                clean,
                "NTFS3.1 and clear persisted dirty state required",
            ),
            (
                "volume_policy_flags",
                policy_flags,
                "only zero flags or exact live disabled-short-name interpretation accepted",
            ),
            (
                "raw_allocation",
                raw.allocation().status
                    == ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel,
                "complete physical ownership and bitmap closure",
            ),
            (
                "raw_mft_record_coverage",
                raw.header().inventory_complete,
                "opaque producer closed canonical/physical extension and allocation domains",
            ),
            (
                "raw_namespace",
                raw.header().inventory_complete,
                "opaque producer closed every directory index/name/reference domain",
            ),
            (
                "raw_security",
                raw.header().inventory_complete,
                "opaque producer closed descriptors and every supported security binding",
            ),
            (
                "native_profile",
                native.domain().is_paged(),
                "actual paged native lease, complete selectors and resource budgets",
            ),
            (
                "native_identity_coverage",
                row_count == raw.file_count(),
                "every raw identity has one actual native row",
            ),
            (
                "native_volume_allocation",
                true,
                "compare_domain checked both complete native bitmap summaries against frozen allocation",
            ),
            (
                "objects",
                source_objects,
                "every transferred user object passes shared preservation policy and actual native views",
            ),
            (
                "resource_limits",
                resource_counts,
                "exact source counts and logical total match pinned resources",
            ),
            (
                "source_backups",
                backups.binds_domain(&raw),
                "actual boot and MFT mirror reads bind this source",
            ),
            (
                "log_restart_pages",
                log.binds_domain(&raw) && log.restart.candidate_clean_dismount,
                "actual complete LogFile and agreeing clean restart copies",
            ),
            (
                "remaining_inspection_refusals",
                unresolved_count == 0,
                "every other source blocker remains unresolved and is retained in pages",
            ),
            (
                "frozen_device_basis",
                before == after && source_sha == after_hash,
                "same actual partition-readonly bracket and complete scoped fingerprint around native reads",
            ),
            (
                "internal_indexes",
                indexes.binds_domain(&raw) && indexes.replacement_supported,
                "actual object-ID/reparse/default-quota indexes plus native disabled quota policy",
            ),
            (
                "transaction_freeze",
                transactions.binds_domain(&raw),
                "actual prefreeze RM, lock/dismount, clean restart and empty deferred namespaces",
            ),
            (
                "native_resource_profile_support",
                native.domain().header().request.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(admission),
                    )),
                "actual complete source/native/count/page profile equality",
            ),
        ] {
            gate(&mut gates, code, satisfied, detail);
        }
        let replacement_ready = internal_bound
            && clean
            && policy_flags
            && source_objects
            && resource_counts
            && unresolved_count == 0;
        gate(
            &mut gates,
            "internal_replacement_state",
            replacement_ready,
            "exact internal roles are excluded only after all independent source obligations close",
        );
        gate(
            &mut gates,
            "native_directory_case_sensitivity",
            directories > 0
                && user_case_matched == directories
                && (internal_directories == 0 || replacement_ready)
                && raw_directories == directories + internal_directories,
            "every transferred directory needs actual stable zero case flags; only exact proof-bound internals are excluded",
        );
        gate(
            &mut gates,
            "shared_artifact_arena",
            false,
            "source subgroup is bounded; cross-stage source/native/expected/plan/report/recovery arena ownership is not yet integrated",
        );
        gate(
            &mut gates,
            "security_timestamp_preservation",
            false,
            "actual same-tree native target round trip remains required",
        );
        gate(
            &mut gates,
            "target_resource_profile_support",
            false,
            "actual resource-selected target preservation remains required",
        );
        let source_views_sha = json_sha(
            &serde_json::json!({"kind":"resource-source-views-v1","inspection":inspection_sha,
            "source_fingerprint":source_sha,"native_pages_sha256":native.domain().sha256(),"comparison_rows":rows_pin}),
            scratch.budget().scratch_bytes / 2,
        )?;
        let rows = SortedRecordStore::open(&rows_pin, &scratch)?;
        let unresolved = SortedRecordStore::open(&unresolved_pin, &scratch)?;
        let replacements = SortedRecordStore::open(&replacements_pin, &scratch)?;
                require_partition_source_gates(&gates)?;
                save(output,"partition-source-evidence.json",&serde_json::json!({
                    "scope":"selected_partition","binding":binding,"inspection_sha256":inspection_sha,
                    "source_fingerprint":fingerprint.pins(),"source_sha256":source_sha,
                    "readonly_before":native.before(),"readonly_after":native.after(),
                    "backups":backups,"log":log,"indexes":indexes,"transactions":transactions,
                    "label":label,"mount_paths":mount_paths,"comparison":comparison,"gates":gates,
                    "target_preservation_complete":false,"certificate_issued":false,"execution_authorized":false
                }),&scratch,&mut metadata,&mut reservations)?;
                collected=Some(CollectedPartitionSource {raw,fingerprint,read_coverage,inspection_sha,
                    source_sha,source_views_sha,backups,log,indexes,transactions,label,label_frozen,mount_paths,
                    comparison,rows,unresolved,replacements,admission,gates,scratch,metadata,reservations,
                    _source_io_ram:source_io_ram,_native_payer_ram:native_payer_ram});
                output_basis=Some(basis);native_artifact=Some(artifact);
                native.require_phase(phase,events)?;
                Ok(native)
            })().map_err(io::Error::other)
        });
        if let Err(error) = preparation {
            // The SDK owns the same original volume and recorded intent. It
            // decides whether its actual pre-private state permits cancellation;
            // an uncertain setter state remains protected and is not masked.
            return match guard.cancel_before_private(events) {
                Ok(()) => Err(anyhow::Error::new(error).context(
                    "partition preparation failed; actual live guard restored original Basic state",
                )),
                Err(cancel) => Err(anyhow::Error::new(error).context(format!(
                    "partition preparation failed; live cancellation refused: {cancel}"
                ))),
            };
        }
        let (mut source, native_admission) =
            freeze_mounted_ntfs_partition(binding.clone(), observation_budget, guard, events)?;
        let collected = collected.context("complete partition raw/native collection absent")?;
        source.revalidate(events)?;
        ensure!(
            collected
                .fingerprint
                .hash_partition_reader(&mut source, binding.storage.identity.partition_bytes)?
                == collected.source_sha,
            "partition source changed across actual private transition"
        );
        let token = Box::new(source.owner_token());
        let source_seal = collected.scratch.seal()?;
        let native_seal = native_group.seal()?;
        let mut context = PartitionResourceSourceContext {
            source,
            token,
            native_admission,
            collected,
            arena: arena.clone(),
            source_seal,
            native_seal,
            native_artifact: native_artifact
                .context("actual partition native artifact owner absent")?,
            output_basis: output_basis
                .context("actual partition output directory owners absent")?,
            binding,
        };
        context.recheck_source(events)?;
        Ok(context)
    }
}
impl PartitionResourceSourceContext {
    /// Publication persistence only: the callback receives the actual retained
    /// owners, not copies reconstructed from a publication DTO. No source
    /// writer is exposed, and the same SDK guard pin is checked on both sides.
    pub(crate) fn with_publication_handoff<T>(
        &mut self,
        events: &mut Vec<NativeEvent>,
        action: impl FnOnce(&mut PartitionScopedOwner, &mut PartitionNtfsAdmission,
            &PartitionOwnerToken, &mut Vec<NativeEvent>)->Result<T>,
    )->Result<T> {
        self.require_source_evidence()?;
        ensure!(self.token.same_owner(&self.source.owner_token()),"publication source owner changed");
        let pin=self.native_admission.durable_preparation_pin()?;
        self.native_admission.revalidate_publication_handoff(&mut self.source,&pin,events)?;
        let result=action(&mut self.source,&mut self.native_admission,self.token.as_ref(),events)?;
        self.native_admission.revalidate_publication_handoff(&mut self.source,&pin,events)?;
        Ok(result)
    }
    pub(crate) fn binding(&self) -> &PartitionSourceBinding {
        &self.binding
    }
    pub(crate) fn owner_token(&self) -> PartitionOwnerToken {
        self.token.as_ref().clone()
    }
    pub(crate) fn source_owner_identity(&self) -> usize {
        std::ptr::from_ref(self.token.as_ref()) as usize
    }
    pub(crate) fn source_and_inspection(
        &mut self,
    ) -> (&mut PartitionScopedOwner, &PagedInspection) {
        (&mut self.source, &self.collected.raw)
    }
    pub(crate) fn native_admission(&self) -> &PartitionNtfsAdmission {
        &self.native_admission
    }
    pub(crate) fn arena(&self) -> &ArtifactArena {
        &self.arena
    }
    pub(crate) fn source_artifact_bytes(&self) -> u64 {
        self.collected.scratch.used_bytes()
    }
    pub(crate) fn native(&self) -> &PartitionPagedNtfsObservation {
        self.native_admission.native()
    }
    pub(crate) fn inspection(&self) -> &PagedInspection {
        &self.collected.raw
    }
    pub(crate) fn fingerprint(&self) -> &PagedSourceFingerprint {
        &self.collected.fingerprint
    }
    pub(crate) fn source_sha256(&self) -> &str {
        &self.collected.source_sha
    }
    pub(crate) fn source_views_sha256(&self) -> &str {
        &self.collected.source_views_sha
    }
    pub(crate) fn verification_policy(&self) -> VerificationPolicy {
        self.collected.fingerprint.pins().policy
    }
    pub(crate) fn inspection_sha256(&self) -> &str {
        &self.collected.inspection_sha
    }
    pub(crate) fn resource_admission(&self) -> SourceResourceAdmission {
        self.collected.admission
    }
    pub(crate) fn original_label(&self) -> &n2r_win32::volume_label::VolumeLabel {
        &self.collected.label
    }
    pub(crate) fn mount_paths(&self) -> &MountPathObservation {
        &self.collected.mount_paths
    }
    pub(crate) fn private_enrollment_state(&self) -> &PartitionOwnerState {
        self.source.state()
    }
    pub(crate) fn source_group_seal(&self) -> &ArtifactGroupSeal {
        &self.source_seal
    }
    pub(crate) fn native_group_seal(&self) -> &ArtifactGroupSeal {
        &self.native_seal
    }
    pub(crate) fn require_source_evidence(&self) -> Result<()> {
        require_partition_source_gates(&self.collected.gates)?;
        self.collected.raw.revalidate()?;
        self.native().domain().revalidate()?;
        self.collected
            .fingerprint
            .validate_reads(&self.collected.read_coverage)?;
        self.collected.indexes.revalidate()?;
        self.collected.rows.revalidate()?;
        self.collected.unresolved.revalidate()?;
        self.collected.replacements.revalidate()?;
        n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(
            &self.source,
            &self.native_admission,
        )?;
        self.native_artifact.revalidate()?;
        self.native_seal.revalidate()?;
        self.source_seal.revalidate()?;
        ensure!(
            self.source_seal.permit().group() == ArtifactGroup::Source
                && self.native_seal.permit().group() == ArtifactGroup::Native
                && self.source_seal.permit().arena().same_arena(&self.arena)
                && self.native_seal.permit().arena().same_arena(&self.arena)
                && self.collected.scratch.is_sealed(),
            "partition source/native arena owner or seal changed"
        );
        let _readback = self.collected.scratch.lease_ram(65536)?;
        for pin in &self.collected.metadata {
            if let Some(lease) = &pin.arena_lease {
                lease.revalidate()?;
            }
            ensure!(
                pin.held.metadata()?.len() == pin.bytes
                    && pin.held.metadata()?.file_attributes() & 0x400 == 0,
                "held partition source metadata identity changed"
            );
            let mut file = pin.held.try_clone()?;
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = [0u8; 65536];
            let mut left = pin.bytes;
            let mut digest = Sha256::new();
            while left > 0 {
                let n = left.min(bytes.len() as u64) as usize;
                file.read_exact(&mut bytes[..n])?;
                digest.update(&bytes[..n]);
                left -= n as u64;
            }
            ensure!(
                hex::encode(digest.finalize()) == pin.sha256,
                "partition source metadata contents changed"
            );
            file.seek(SeekFrom::Start(0))?;
        }
        ensure!(
            self.collected.backups.binds_domain(&self.collected.raw)
                && self.collected.log.binds_domain(&self.collected.raw)
                && self
                    .collected
                    .transactions
                    .binds_domain(&self.collected.raw)
                && self.collected.label_frozen.inspection_sha256 == self.collected.inspection_sha,
            "partition source evidence lost actual raw domain"
        );
        Ok(())
    }
    pub(crate) fn recheck_source(&mut self, events: &mut Vec<NativeEvent>) -> Result<()> {
        ensure!(
            self.token.same_owner(&self.source.owner_token()),
            "partition source actual owner token changed"
        );
        self.source.revalidate(events)?;
        validate_partition_output(&self.output_basis, &self.binding, &self.arena)?;
        self.require_source_evidence()?;
        let digest = self.collected.fingerprint.hash_partition_reader(
            &mut self.source,
            self.binding.storage.identity.partition_bytes,
        )?;
        self.source.revalidate(events)?;
        ensure!(
            digest == self.collected.source_sha,
            "partition source fingerprint changed"
        );
        Ok(())
    }
    /// Reports actual selected-partition state, never a GeneralDiskState.
    pub(crate) fn report(&self) -> PartitionResourceSourceReport<'_> {
        PartitionResourceSourceReport {
            kind: "selected-partition-resource-source",
            scope: "selected_partition",
            binding: &self.binding,
            private_enrollment_state: self.source.state(),
            readonly_before: self.native().before(),
            readonly_after: self.native().after(),
            inspection_sha256: &self.collected.inspection_sha,
            source_sha256: &self.collected.source_sha,
            source_views_sha256: &self.collected.source_views_sha,
            comparison: &self.collected.comparison,
            comparison_rows: self.collected.rows.pin(),
            unresolved: self.collected.unresolved.pin(),
            replacements: self.collected.replacements.pin(),
            gates: &self.collected.gates,
            source_group_allocated_bytes: self.source_seal.allocated_bytes(),
            native_group_allocated_bytes: self.native_seal.allocated_bytes(),
            target_preservation_complete: false,
            certificate_issued: false,
            execution_authorized: false,
        }
    }
    // Private->Basic label restoration and HND/ABT issuance must be performed
    // by the later authenticated partition finalizer, not the legacy whole-disk
    // restore_original_unchanged. There is no writer/finalizer accessor here.
}
fn require_partition_source_gates(gates: &[Gate]) -> Result<()> {
    let failed: Vec<_> = gates
        .iter()
        .filter(|g| {
            !matches!(
                g.code.as_str(),
                "security_timestamp_preservation"
                    | "target_resource_profile_support"
                    | "shared_artifact_arena"
            ) && !g.satisfied
        })
        .map(|g| g.code.as_str())
        .collect();
    ensure!(
        failed.is_empty(),
        "partition source evidence refused: {failed:?}"
    );
    Ok(())
}
fn validate_partition_output(
    basis: &ArenaOutputBasis,
    source: &PartitionSourceBinding,
    arena: &ArtifactArena,
) -> Result<()> {
    arena.require_root_directory(
        basis
            .parents
            .first()
            .context("held partition output ancestry absent")?,
    )?;
    let actual = n2r_win32::discovery::discover(
        &basis.drive_root,
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    let a = &actual.binding.identity;
    let s = &source.storage.identity;
    let same_disk = actual.binding.disk_number == source.storage.disk_number;
    let disk_guids_equal = n2r_win32::layout::guid_bytes(&a.disk_guid)?
        == n2r_win32::layout::guid_bytes(&s.disk_guid)?;
    let disjoint = if same_disk {
        disk_guids_equal
            && a.disk_bytes == s.disk_bytes
            && a.logical_sector_bytes == s.logical_sector_bytes
            && a.physical_sector_bytes == s.physical_sector_bytes
            && (a
                .partition_offset
                .checked_add(a.partition_bytes)
                .context("output extent overflow")?
                <= s.partition_offset
                || s.partition_offset
                    .checked_add(s.partition_bytes)
                    .context("source extent overflow")?
                    <= a.partition_offset)
    } else {
        !disk_guids_equal
    };
    ensure!(
        actual.observed_twice_unchanged
            && actual.read_only
            && actual.source_write_requests == 0
            && actual.binding == basis.volume
            && disjoint
            && n2r_win32::layout::guid_bytes(&a.partition_guid)?
                != n2r_win32::layout::guid_bytes(&s.partition_guid)?
            && n2r_win32::layout::guid_bytes(&actual.binding.volume_guid)?
                != n2r_win32::layout::guid_bytes(&source.storage.volume_guid)?
            && actual
                .binding
                .volume_path()?
                .eq_ignore_ascii_case(arena.volume_guid_path()?),
        "actual partition output extents alias source or held artifact volume changed"
    );
    Ok(())
}
fn output_in_partition_arena(
    phase: &mut PartitionReadonlyPhase<'_>,
    output: &Path,
    arena: &ArtifactArena,
    events: &mut Vec<NativeEvent>,
) -> Result<ArenaOutputBasis> {
    phase.revalidate(events)?;
    use std::path::{Component, Prefix};
    let text = output
        .to_str()
        .context("Unicode source output path required")?;
    let bytes = text.as_bytes();
    ensure!(
        output.is_absolute()
            && bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
            && !text[2..].contains(':')
            && matches!(output.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)))
            && !output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "arena source output requires an unambiguous ordinary local path"
    );
    let leaf = output
        .file_name()
        .and_then(|v| v.to_str())
        .context("source output leaf absent")?;
    ensure!(
        !leaf.is_empty()
            && !leaf.ends_with([' ', '.'])
            && !leaf.chars().any(|c| c.is_control()
                || matches!(c, ':' | '/' | '\\' | '"' | '<' | '>' | '|' | '?' | '*')),
        "ambiguous source output leaf refused"
    );
    let ram = arena.reserve_ram(
        (text.len() as u64)
            .checked_mul(32)
            .and_then(|n| n.checked_add(4 * 1024 * 1024))
            .context("source output route RAM overflow")?,
    )?;
    let parent = output.parent().context("source output parent absent")?;
    let mut parents = Vec::new();
    for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "ordinary arena source-output ancestry required"
        );
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(ancestor)?;
        ensure!(
            file.metadata()?.is_dir() && file.metadata()?.file_attributes() & 0x400 == 0,
            "held arena source-output ancestry differs"
        );
        parents.push(file);
    }
    let held = parents
        .first()
        .context("held arena source-output parent absent")?;
    arena.require_root_directory(held)?;
    let parent_guid = n2r_win32::file_storage::final_path_guid(held)?;
    let drive_root = text[..3].to_owned();
    let volume = n2r_win32::discovery::discover(
        &drive_root,
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?
    .binding;
    let basis = ArenaOutputBasis {
        parents,
        created: Vec::new(),
        drive_root,
        parent_guid,
        volume,
        _ram: ram,
    };
    validate_partition_output(&basis, phase.binding(), arena)?;
    phase.revalidate(events)?;
    Ok(basis)
}
fn short_names_partition(
    source: &PagedInspection,
    observed: &PartitionPagedNtfsObservation,
    no_dos: bool,
) -> bool {
    let policy = observed.txf().observation();
    source.header().volume_flags == Some(0x80)
        && source.header().dirty == Some(false)
        && source.header().volume_version.as_deref() == Some("3.1")
        && no_dos
        && source
            .canonical_sha256()
            .is_ok_and(|pin| pin == observed.domain().header().request.source_inspection_sha256)
        && observed.before() == observed.after()
        && observed.before().partition_write_protect_error == 19
        && policy.schema_version == 2
        && policy.windows_version == [10, 0, 26300]
        && policy.short_name_state_stable
        && policy
            .persistent_state_before
            .as_ref()
            .zip(policy.persistent_state_after.as_ref())
            .is_some_and(|(a, b)| {
                [a, b].into_iter().all(|s| {
                    s.queried_flags_valid
                        && s.requested_flag_mask == 1
                        && s.requested_version == 1
                        && s.short_name_creation_disabled
                })
            })
}
