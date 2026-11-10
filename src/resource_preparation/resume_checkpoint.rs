//! Durable facts around freshly reissued source and native shadow owners.
use super::*;
use crate::{
    artifact_arena::{ArtifactGroupPermit, ArtifactLease},
    preparation_resume::{
        ArtifactPin, BatchDisposition, BatchIntent, BatchOutcome, DurableBatchIntent,
        DurableResume, FormatProfiles, Limits, Origin, ResumeIntent, Stage,
    },
};
use sha2::Digest;
use std::{
    os::windows::fs::MetadataExt,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct Checkpoints {
    journal: DurableResume,
    group: ArtifactGroupPermit,
    directory: PathBuf,
    owners: Vec<ArtifactLease>,
    expected: ArtifactPin,
    placement_batch_id:u64,
}

fn accounted(arena: &ArtifactArena, path: &Path, key: &str) -> Result<ArtifactPin> {
    let lease = arena.retained_artifact(path).with_context(|| {
        format!(
            "checkpoint artifact {key} at {} lacks its actual arena owner",
            path.display()
        )
    })?;
    accounted_lease(&lease, key)
}
fn accounted_lease(lease: &ArtifactLease, key: &str) -> Result<ArtifactPin> {
    let path = lease.path();
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let s = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
        &file,
        lease.wire_bytes(),
    )?;
    ensure!(
        &s == lease.snapshot(),
        "checkpoint artifact differs from actual accounted owner"
    );
    Ok(ArtifactPin {
        key: key.to_owned(),
        path: path.to_path_buf(),
        sha256: lease.sha256().to_owned(),
        bytes: s.file_bytes,
        allocation_bytes: s.allocation_bytes,
        final_path: s.final_path,
        volume_serial_number: s.volume_serial_number,
        file_id_128: s.file_id_128,
        file_attributes: s.file_attributes,
        number_of_links: s.number_of_links,
        last_write_time: file.metadata()?.last_write_time(),
    })
}
pub(super) fn preflight_new_guard(
    guard: &early_guard::EarlyPreparationGuard,
    group: &ArtifactGroupPermit,
) -> Result<()> {
    let owner = guard.intent_artifact();
    let native = guard.pin();
    ensure!(
        owner.same_group(group)
            && owner.sha256() == native.sha256
            && owner.wire_bytes() == native.bytes,
        "preparation guard lost its paid owner before source freeze"
    );
    let actual = accounted_lease(&owner, "new-preparation")?;
    ensure!(
        actual.sha256 == native.sha256 && actual.bytes == native.bytes,
        "checkpoint guard preflight differs from the actual native intent"
    );
    Ok(())
}
fn persist(
    group: &ArtifactGroupPermit,
    path: &Path,
    key: &str,
    value: &impl Serialize,
) -> Result<(ArtifactPin, ArtifactLease)> {
    let data = serde_json::to_vec(value)?;
    ensure!(
        data.len() as u64 <= group.arena().budget().max_row_bytes,
        "checkpoint facts exceed row budget"
    );
    let _ram = group.arena().reserve_ram(
        (data.len() as u64)
            .checked_mul(2)
            .context("checkpoint RAM overflow")?,
    )?;
    let permit = group.reserve_file(path, data.len() as u64)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(permit.path())?;
    file.write_all(&data)?;
    file.sync_all()?;
    drop(file);
    let sha = hex::encode(sha2::Sha256::digest(&data));
    let lease = permit.verify_closed(&sha)?;
    Ok((accounted(group.arena(), path, key)?, lease))
}

impl Checkpoints {
    /// Start the durable journal for the initial attempt before the native
    /// allocator may change the existing empty formatter namespace.
    pub(super) fn create_fresh(
        context:&ResourceSourceContext,expected:&PagedExpectedTree,
        request:&ResourcePreparationRequest,parent:&resume_origin::ParentPublicResources,
        group:&ArtifactGroupPermit,output:&Path,
    )->Result<Self>{
        let arena=group.arena();
        let source=context.current_cache_origin(expected,None)?;
        let directory=output.join("resume");
        std::fs::create_dir(&directory)?;
        let (source_cache,source_owner)=persist(group,&directory.join("source-cache-origin.json"),"source-cache-origin",&source)?;
        let expected_pin=accounted(arena,&source.generation.as_ref().context("fresh source generation absent")?.expected.path,"expected")?;
        let native=accounted(arena,&source.native_pages.path,"source-native")?;
        let guard_owner=context.early_preparation_guard_artifact().context("fresh checkpoint actual guard absent")?;
        let guard=context.early_preparation_guard_pin().context("fresh checkpoint native guard absent")?;
        ensure!(guard_owner.same_group(group)&&guard_owner.sha256()==guard.sha256&&guard_owner.wire_bytes()==guard.bytes,
            "fresh checkpoint guard lost its actual paid owner");
        let new_guard=accounted_lease(&guard_owner,"new-preparation")?;
        let facts=super::resume_session_inputs::SavedResumeRequest::from_fresh(parent,request,output,&source,expected)?;
        let (request_pin,request_owner)=persist(group,&directory.join("resume-request.json"),"resume-request",&facts)?;
        let (source_report,report_owner)=persist(group,&directory.join("source-revalidated.json"),"source-revalidated",&context.report())?;
        let mut owners=vec![source_owner,request_owner,report_owner,guard_owner];
        let mut initial_artifacts=vec![source_cache.clone(),expected_pin.clone(),native.clone(),request_pin];
        if let Some(binding)=expected.binding_pin(){
            let owner=arena.retained_artifact(&binding.path)?;
            ensure!(owner.sha256()==binding.sha256&&owner.wire_bytes()==binding.bytes,"fresh Expected binding owner differs");
            initial_artifacts.push(accounted_lease(&owner,"expected-binding")?);owners.push(owner);
        }
        let now=SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut epoch=sha2::Sha256::new();epoch.update(new_guard.sha256.as_bytes());
        epoch.update(now.as_nanos().to_le_bytes());epoch.update(std::process::id().to_le_bytes());
        let epoch:[u8;32]=epoch.finalize().into();
        let intent=ResumeIntent{schema_version:1,kind:ResumeIntent::kind().to_owned(),epoch:hex::encode(&epoch[..16]),
            created_unix_ms:u64::try_from(now.as_millis())?,pair:request.pair.clone(),working:request.journal.clone(),
            resources:arena.budget(),profiles:FormatProfiles::current(),
            origin:Origin::FreshPreparation{source_cache_manifest:source_cache},new_preparation_intent:new_guard,initial_artifacts};
        let mut journal=DurableResume::create(&directory,group.clone(),intent,Limits::from_budget(arena.budget())?)?;
        journal.record_stage(Stage::SourceCaptured,vec![native])?;
        journal.record_stage(Stage::SourceVerified,vec![source_report])?;
        println!("Resumable preparation: {}\nResume SHA-256: {}",directory.display(),journal.intent_pin().sha256);
        std::io::stdout().flush()?;
        Ok(Self{journal,group:group.clone(),directory,owners,expected:expected_pin,placement_batch_id:1})
    }
    pub(super) fn create(
        saved: &ResumePreparation,
        context: &ResourceSourceContext,
        expected: &PagedExpectedTree,
        request: &ResourcePreparationRequest,
        group: &ArtifactGroupPermit,
        output: &Path,
    ) -> Result<Self> {
        let arena = group.arena();
        let directory = output.join("resume");
        std::fs::create_dir(&directory)?;
        let mut promoted=saved.clone();
        promoted.source=context.current_cache_origin(expected,Some(&saved.source))?;
        promoted.source_origin_sha256=promoted.source.canonical_sha256()?;
        let (source_cache, cache_owner) = persist(
            group,
            &directory.join("source-cache-origin.json"),
            "source-cache-origin",
            &promoted.source,
        )?;
        let mut owners = vec![cache_owner];
        let origin = if let Some(prior) = &saved.prior_resume_intent {
            // Only an actually retained/revalidated file can link epochs. The
            // original cancelled source-cache baseline remains in saved.source.
            let prior_owner = arena.retained_artifact(&prior.path)?;
            prior_owner.revalidate()?;
            let actual = accounted(arena, &prior.path, &prior.key)?;
            ensure!(
                &actual == prior,
                "prior resume intent differs from actual paid owner"
            );
            owners.push(prior_owner);
            if let Some((root, working)) = &saved.workspace_origin {
                Origin::WorkspaceMigration {
                    intent: actual,
                    source_cache_manifest: source_cache.clone(),
                    prior_arena_root: root.clone(),
                    prior_working: working.clone(),
                }
            } else {
                Origin::PriorEpoch {
                    intent: actual,
                    source_cache_manifest: source_cache.clone(),
                }
            }
        } else {
            let terminal = saved
                .legacy_terminal
                .as_ref()
                .context("legacy resume import lacks its original terminal pin")?;
            let terminal_owner = match arena.retained_artifact(&terminal.path) {
                Ok(lease) => {
                    ensure!(
                        lease.sha256() == terminal.sha256 && lease.wire_bytes() == terminal.bytes,
                        "existing legacy terminal owner differs"
                    );
                    lease.revalidate()?;
                    lease
                }
                Err(_) => group.adopt_existing(&terminal.path, &terminal.sha256, terminal.bytes)?,
            };
            let terminal_pin = accounted(arena, &terminal.path, "origin-terminal")?;
            let old = &saved.source.cancelled_preparation_intent;
            let old_guard = accounted(arena, &old.path, "origin-preparation")?;
            ensure!(
                old_guard.sha256 == old.sha256 && old_guard.bytes == old.bytes,
                "legacy cancelled source baseline differs from actual owner"
            );
            owners.push(terminal_owner);
            Origin::LegacyCancelledPreparation {
                preparation_intent: old_guard,
                terminal: terminal_pin,
                source_cache_manifest: source_cache.clone(),
            }
        };
        let guard = context
            .early_preparation_guard_pin()
            .context("resumed source has no NEW guard")?;
        // Native guard routes use a volume-GUID spelling; arena registry keys
        // retain the ordinary producer path. Carry the actual immutable owner
        // instead of looking that owner up through a different path spelling.
        let guard_owner = context
            .early_preparation_guard_artifact()
            .context("resumed source lost its actual new-guard artifact owner")?;
        ensure!(
            guard_owner.same_group(group)
                && guard_owner.sha256() == guard.sha256
                && guard_owner.wire_bytes() == guard.bytes,
            "actual new-guard owner differs from the native guard pin"
        );
        let new_guard = accounted_lease(&guard_owner, "new-preparation")?;
        owners.push(guard_owner);
        let expected_pin = accounted(arena, &saved.expected.path, "expected")?;
        let native = accounted(arena, &promoted.source.native_pages.path, "source-native")?;
        let (source_report, source_report_owner) = persist(
            group,
            &directory.join("source-revalidated.json"),
            "source-revalidated",
            &context.report(),
        )?;
        let facts = super::resume_session_inputs::SavedResumeRequest::from_actual(
            &saved.parent_resources,
            request,
            &promoted,
        )?;
        let (request_pin, request_owner) = persist(
            group,
            &directory.join("resume-request.json"),
            "resume-request",
            &facts,
        )?;
        let mut initial_artifacts = vec![
            source_cache,
            expected_pin.clone(),
            native.clone(),
            request_pin,
        ];
        if let Some(proof) = &saved.completed_placement {
            proof.require_arena(arena)?;
            initial_artifacts.push(proof.pin().clone());
        }
        if let Some(proof)=&saved.completed_payloads {
            proof.require_arena(arena)?;
            proof.require_expected(expected.file_sha256())?;
            initial_artifacts.push(proof.pin().clone());
        }
        if let Some(binding) = expected.binding_pin() {
            ensure!(
                saved.expected_binding.as_ref().is_some_and(
                    |saved| saved.sha256 == binding.sha256 && saved.path == binding.path
                ),
                "effective resume lost actual expected binding"
            );
            let lease = arena.retained_artifact(&binding.path)?;
            ensure!(
                lease.sha256() == binding.sha256 && lease.wire_bytes() == binding.bytes,
                "checkpoint expected binding actual owner differs"
            );
            initial_artifacts.push(accounted_lease(&lease, "expected-binding")?);
            owners.push(lease);
        }
        let intent = ResumeIntent {
            schema_version: 1,
            kind: ResumeIntent::kind().to_owned(),
            epoch: hex::encode(saved.shadow_origin.new_epoch),
            created_unix_ms: u64::try_from(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            )?,
            pair: request.pair.clone(),
            working: request.journal.clone(),
            resources: arena.budget(),
            profiles: FormatProfiles::current(),
            origin,
            new_preparation_intent: new_guard,
            initial_artifacts,
        };
        let mut journal = DurableResume::create(
            &directory,
            group.clone(),
            intent,
            Limits::from_budget(arena.budget())?,
        )?;
        journal.record_stage(Stage::SourceCaptured, vec![native])?;
        journal.record_stage(Stage::SourceVerified, vec![source_report])?;
        println!(
            "Resumable preparation: {}\nResume SHA-256: {}",
            directory.display(),
            journal.intent_pin().sha256
        );
        std::io::stdout().flush()?;
        // semantic_sha256 is computed from the existing typed tree, not guessed.
        ensure!(
            expected.file_sha256() == saved.expected.sha256,
            "resumed expected checkpoint differs"
        );
        owners.extend([source_report_owner, request_owner]);
        Ok(Self {
            journal,
            group: group.clone(),
            directory,
            owners,
            expected: expected_pin,
            placement_batch_id:1,
        })
    }
    /// Must complete durably BEFORE invoking the actual native allocator.
    pub(super) fn begin_allocation(&mut self)->Result<DurableBatchIntent>{
        ensure!(self.journal.stage()==Some(Stage::SourceVerified),"fresh allocation intent requires closed source/Expected stage");
        self.placement_batch_id=2;
        self.journal.begin_batch(Stage::ShadowAllocated,BatchIntent{id:1,
            operation:"native_allocate_shadow".to_owned(),first_ordinal:0,end_ordinal:1,
            operation_catalog:self.expected.clone(),before_state:vec![self.journal.intent().new_preparation_intent.clone(),self.expected.clone()]})
    }
    /// Called only after the native allocator returns its actual live tree.
    /// The observation records that event; it cannot reconstruct the tree.
    pub(super) fn allocated(&mut self,token:DurableBatchIntent,observation:&serde_json::Value)->Result<DurableBatchIntent>{
        let (proof,owner)=persist(&self.group,&self.directory.join("native-shadow-allocated.json"),"shadow-allocated",observation)?;
        self.owners.push(owner);
        self.journal.complete_batch(token,BatchOutcome{id:1,disposition:BatchDisposition::ObservedApplied,evidence:vec![proof.clone()]})?;
        self.journal.record_stage(Stage::Placing,vec![proof.clone()])?;
        self.journal.begin_batch(Stage::Placing,BatchIntent{id:self.placement_batch_id,
            operation:"native_reconcile_and_place_remaining".to_owned(),first_ordinal:0,end_ordinal:1,
            operation_catalog:self.expected.clone(),before_state:vec![proof]})
    }
    pub(super) fn adopted(
        &mut self,
        observation: &serde_json::Value,
    ) -> Result<DurableBatchIntent> {
        self.placement_batch_id=1;
        let (proof, owner) = persist(
            &self.group,
            &self.directory.join("native-shadow-adopted.json"),
            "shadow-adopted",
            observation,
        )?;
        self.owners.push(owner);
        self.journal
            .record_stage(Stage::ShadowAllocated, vec![proof.clone()])?;
        self.journal
            .record_stage(Stage::Placing, vec![proof.clone()])?;
        self.journal.begin_batch(
            Stage::Placing,
            BatchIntent {
                id: self.placement_batch_id,
                operation: "native_reconcile_and_place_remaining".to_owned(),
                first_ordinal: 0,
                end_ordinal: 1,
                operation_catalog: self.expected.clone(),
                before_state: vec![proof],
            },
        )
    }
    pub(super) fn placed(
        &mut self,
        token: DurableBatchIntent,
        report: &impl Serialize,
    ) -> Result<()> {
        let (proof, owner) = persist(
            &self.group,
            &self.directory.join("placement-completed.json"),
            "placement-completed",
            report,
        )?;
        self.owners.push(owner);
        self.journal.complete_batch(
            token,
            BatchOutcome {
                id: self.placement_batch_id,
                disposition: BatchDisposition::ObservedApplied,
                evidence: vec![proof],
            },
        )
    }
    pub(super) fn stage(
        &mut self,
        stage: Stage,
        name: &str,
        report: &impl Serialize,
    ) -> Result<()> {
        let (proof, owner) = persist(
            &self.group,
            &self.directory.join(format!("{name}.json")),
            name,
            report,
        )?;
        self.owners.push(owner);
        self.journal.record_stage(stage, vec![proof])
    }
    pub(super) fn published(&mut self, path: &Path) -> Result<()> {
        let proof = accounted(self.group.arena(), path, "published-conversion")?;
        self.journal.record_journal_publication(proof)
    }
}
