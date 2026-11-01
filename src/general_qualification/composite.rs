//! Owning qualification of an existing native source-backed shadow. This
//! path retains the original live source assessment through certificate issue;
//! it never reads an old qualification report or initializes duplicate payload.
use super::*;
use crate::general_composite_target::{self, FrozenCompositeTargetPreservation};
use crate::general_shadow::source_backed::{CaptureBudget, CaptureProgress};

/// These are live owning capabilities. Keeping the proof also keeps its exact
/// compact backing open read-only with write/delete sharing excluded.
pub(crate) struct QualifiedCompositeTree {
    pub source: GeneralFrozenPartition,
    pub native_target: GeneralFrozenPartition,
    pub proof: FrozenCompositeTargetPreservation,
    pub artifact: crate::refs_hybrid::delta::VerifiedDeltaArtifact,
    pub certificate: general_source_admission::SourceCertificate,
    pub comparison: crate::retained_compare::RetainedCompareRequest,
    pub tree: shadow_tree::Tree,
    pub expected: Vec<u8>,
    pub mount_paths: n2r_win32::MountPathObservation,
    pub source_label: n2r_win32::volume_label::SourceLabel,
}

/// Qualify an already constructed native shadow in the same process as fresh
/// source isolation/admission. The shadow may be mounted or frozen, but must
/// exactly reproduce the fresh source tree. No repair or JSON flag substitutes
/// for the protected post-freeze observation or original source assessment.
pub(crate) fn prepare_composite_existing(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    packed_path: &Path,
    max_change_bytes: u64,
    profile: JournalProfile,
    resources: crate::ntfs_admission::ResourceProfile,
    after_source_freeze: impl FnOnce(&GeneralFrozenPartition, &str, &str) -> Result<()>,
) -> Result<QualifiedCompositeTree> {
    prepare_composite(
        pair,
        output,
        packed_path,
        max_change_bytes,
        profile,
        resources,
        None,
        false,
        after_source_freeze,
    )
}

/// Construct from this process's newly captured source tree. The private
/// constructor retains its disposable-machine enrollment checks.
pub(crate) fn prepare_composite_fresh(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    packed_path: &Path,
    max_change_bytes: u64,
    profile: JournalProfile,
    resources: crate::ntfs_admission::ResourceProfile,
    budget: CompactConstructionBudget,
    after_source_freeze: impl FnOnce(&GeneralFrozenPartition, &str, &str) -> Result<()>,
) -> Result<QualifiedCompositeTree> {
    budget.validate(pair.source.identity.partition_bytes)?;
    prepare_composite(
        pair,
        output,
        packed_path,
        max_change_bytes,
        profile,
        resources,
        Some(budget),
        false,
        after_source_freeze,
    )
}

/// Fresh construction with actual selected-device enrollment. The original
/// source assessment and observed freeze remain owned by this process.
pub(crate) fn prepare_composite_fresh_selected(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    packed_path: &Path,
    max_change_bytes: u64,
    profile: JournalProfile,
    resources: crate::ntfs_admission::ResourceProfile,
    budget: CompactConstructionBudget,
) -> Result<QualifiedCompositeTree> {
    budget.validate(pair.source.identity.partition_bytes)?;
    prepare_composite(
        pair,
        output,
        packed_path,
        max_change_bytes,
        profile,
        resources,
        Some(budget),
        true,
        |_, _, _| Ok(()),
    )
}

fn prepare_composite(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    packed_path: &Path,
    max_change_bytes: u64,
    profile: JournalProfile,
    resources: crate::ntfs_admission::ResourceProfile,
    construction: Option<CompactConstructionBudget>,
    selected_devices: bool,
    after_source_freeze: impl FnOnce(&GeneralFrozenPartition, &str, &str) -> Result<()>,
) -> Result<QualifiedCompositeTree> {
    ensure!(
        !resources.is_envelope(),
        "object envelope is supported only by fresh allocation qualification"
    );
    pair.validate_with_resource_profile(resources.native_profile())?;
    ensure!(
        (1..=profile.max_changed_bytes()).contains(&max_change_bytes)
            && max_change_bytes <= pair.source.identity.partition_bytes,
        "composite qualification changed-byte budget differs"
    );
    create_output(output)?;
    save(
        output,
        "intent.json",
        &serde_json::json!({
            "schema_version":1,"kind":"live-composite-qualification-intent",
            "pair":pair,"source_resource_profile":resources,
            "packed_path":packed_path,"max_change_bytes":max_change_bytes,
            "existing_native_shadow":construction.is_none(),"construction_budget":construction,
            "source_payload_writes_authorized":false,
            "source_admitted":false,"execution_authorized":false,
        }),
    )?;
    let mut phase = "source-freeze";
    let attempted = (|| -> Result<QualifiedCompositeTree> {
        let mut events = Vec::<NativeEvent>::new();
        let PreparedSourceContext {
            resources,
            mut source,
            raw,
            mut assessment,
            tree,
            expected,
            expected_sha256,
            source_hash,
            mount_paths,
            source_label,
        } = prepare_source_context(
            &pair,
            output,
            resources,
            &mut events,
            &mut phase,
            after_source_freeze,
            SourceDigest::WholeImage,
            crate::verification_policy::VerificationPolicy::FullContent,
            None,
        )?;
        phase = "native-shadow-construction-or-freeze";
        let mut native_target = if let Some(budget) = construction {
            super::compact_construction::construct(
                &mut source,
                &pair,
                &raw,
                &tree,
                output,
                budget,
                resources,
                selected_devices,
            )?
        } else {
            let state =
                n2r_win32::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
            match state.disk_attributes {
                0 => GeneralFrozenPartition::isolate(pair.shadow.clone(), &mut events)?,
                3 => GeneralFrozenPartition::reopen(pair.shadow.clone(), &mut events)?,
                _ => anyhow::bail!("existing composite shadow must be mounted or frozen read-only"),
            }
        };
        save(output, "target-freeze-events.json", &events)?;
        events.clear();
        phase = "composite-target-preservation";
        let views = assessment
            .assessment
            .source_view
            .as_ref()
            .context("live composite source views absent")?;
        let mut proof = general_composite_target::verify_and_capture(
            &mut source,
            &mut native_target,
            pair.clone(),
            &raw,
            views,
            &source_hash,
            resources,
            packed_path,
            max_change_bytes,
            &mut events,
        )?;
        ensure!(
            proof.expected_tree_sha256() == expected_sha256,
            "composite proof differs from the fresh saved source expectation"
        );
        save(output, "target-preservation.json", &proof)?;
        save(output, "target-events.json", &events)?;
        events.clear();
        phase = "composite-source-certificate";
        let certificate = assessment.qualify_composite_target(&raw, &proof)?;
        let certificate_sha256 = save(output, "certificate.json", &certificate)?;
        save(output, "admitted-assessment.json", &assessment)?;
        phase = "composite-recovery-artifact";
        let artifact =
            proof.persist_delta_artifact(&output.join("composite-capture.json"), packed_path)?;
        save(output, "composite-artifact-pins.json", artifact.pins())?;
        save(
            output,
            "result.json",
            &serde_json::json!({
                "schema_version":1,"kind":"live-composite-tree-qualification",
                "success":true,"source_admitted":true,"execution_authorized":false,
                "source_payload_writes":0,"source_sha256":source_hash,
                "expected_tree_sha256":expected_sha256,"certificate_sha256":certificate_sha256,
                "objects":tree.objects.len(),"comparison":proof.comparison(),
                "packed_changed_bytes":proof.capture().layout.changed_bytes(),
                "complete_native_address_space_compared":true,
                "source_after":source.state(&mut events)?,
                "target_after":native_target.state(&mut events)?,"events":events,
            }),
        )?;
        Ok(QualifiedCompositeTree {
            source,
            native_target,
            certificate,
            artifact,
            comparison: proof.comparison().clone(),
            proof,
            tree,
            expected: serde_json::to_vec_pretty(&expected)?,
            mount_paths,
            source_label,
        })
    })();
    match attempted {
        Ok(qualified) => Ok(qualified),
        Err(error) => {
            save(
                output,
                "failed.json",
                &serde_json::json!({
                    "schema_version":1,"kind":"live-composite-qualification-failure",
                    "phase":phase,"error":format!("{error:#}"),
                    "source_payload_writes":0,"execution_authorized":false,
                }),
            )?;
            Err(error)
        }
    }
}

/// Live owning capabilities for an allocation-bounded target. Keeping the proof
/// keeps its packed backing open read-only with write/delete sharing excluded.
pub(crate) struct QualifiedAllocationTree {
    pub resources: crate::ntfs_admission::ResourceProfile,
    pub source: GeneralFrozenPartition,
    pub native_target: GeneralFrozenPartition,
    pub proof: general_composite_target::FrozenAllocationTargetPreservation,
    pub certificate: general_source_admission::AllocationCertificate,
    pub expected: Vec<u8>,
    pub mount_paths: n2r_win32::MountPathObservation,
    pub source_label: n2r_win32::volume_label::SourceLabel,
}

/// Fresh selected-device construction followed by an allocation-bounded target
/// proof, under the ntfs2btrfs-style guarantee. Source isolation, assessment and
/// shadow construction are those of the composite path.
pub(crate) fn prepare_allocation_fresh_selected(
    pair: GeneralSourceShadowBinding,
    output: &Path,
    packed_path: &Path,
    max_change_bytes: u64,
    profile: JournalProfile,
    resources: crate::ntfs_admission::ResourceProfile,
    budget: CompactConstructionBudget,
    capture_budget: Option<CaptureBudget>,
    capture_guard: Option<&mut dyn FnMut(CaptureProgress) -> Result<()>>,
    policy: crate::verification_policy::VerificationPolicy,
) -> Result<QualifiedAllocationTree> {
    budget.validate(pair.source.identity.partition_bytes)?;
    pair.validate_with_resource_profile(resources.native_profile())?;
    let actual_byte_capacity =
        capture_budget.is_some_and(|budget| !budget.selected_capacity_policy.is_conservative());
    let changed_limit = if actual_byte_capacity {
        ensure!(
            matches!(profile, JournalProfile::CapacityPinnedV3 { .. })
                && policy.is_fast()
                && capture_guard.is_some()
                && max_change_bytes == pair.source.identity.partition_bytes / 4096 * 4096,
            "actual-byte allocation qualification requires explicit pinned V3 fast capacity"
        );
        pair.source.identity.partition_bytes / 4096 * 4096
    } else {
        profile
            .max_journal_bytes()
            .saturating_sub(n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE)
    };
    ensure!(
        (1..=changed_limit).contains(&max_change_bytes)
            && max_change_bytes <= pair.source.identity.partition_bytes,
        "allocation-bounded qualification changed-byte budget differs"
    );
    ensure!(
        capture_budget.is_some() == capture_guard.is_some(),
        "capture capacity budget and live guard must be supplied together"
    );
    if let Some(capture_budget) = capture_budget {
        capture_budget.validate(pair.source.identity.partition_bytes)?;
        ensure!(
            capture_budget.max_changed_bytes == max_change_bytes
                && capture_budget.max_journal_bytes <= profile.max_journal_bytes()
                && (!actual_byte_capacity
                    || capture_budget.max_journal_bytes == profile.max_journal_bytes()),
            "allocation capture capacity differs from its journal profile"
        );
    }
    create_output(output)?;
    let mut intent = serde_json::json!({
        "schema_version":1,"kind":"live-allocation-bounded-qualification-intent",
        "pair":pair,"source_resource_profile":resources,
        "packed_path":packed_path,"max_change_bytes":max_change_bytes,
        "construction_budget":budget,"free_space_contents_compared":false,
        "source_payload_writes_authorized":false,
        "source_admitted":false,"execution_authorized":false,
    });
    if let Some(capture_budget) = capture_budget {
        intent["capture_budget"] = serde_json::to_value(capture_budget)?;
    }
    if policy.is_fast() {
        intent["verification_policy"] = serde_json::to_value(policy)?;
    }
    save(output, "intent.json", &intent)?;
    let mut phase = "source-freeze";
    let attempted = (|| -> Result<QualifiedAllocationTree> {
        let source_free_policy = capture_budget
            .is_some_and(|budget| budget.selected_capacity_policy.allows_source_free());
        let vss_before = if source_free_policy {
            phase = "source-free-vss-catalog-before-freeze";
            let observation = n2r_win32::vss_observation::observe_catalog(&format!(
                "{}\\",
                pair.source.volume_path()?
            ))?;
            save(output, "source-vss-before-freeze.json", &observation)?;
            observation.require_observed_catalog_clear()?;
            Some(observation)
        } else {
            None
        };
        phase = "source-freeze";
        let mut events = Vec::<NativeEvent>::new();
        let PreparedSourceContext {
            resources,
            mut source,
            raw,
            mut assessment,
            tree,
            expected,
            expected_sha256,
            source_hash,
            mount_paths,
            source_label,
        } = prepare_source_context(
            &pair,
            output,
            resources,
            &mut events,
            &mut phase,
            |_, _, _| Ok(()),
            SourceDigest::NtfsAllocated,
            policy,
            vss_before.as_ref(),
        )?;
        phase = "native-shadow-construction";
        let mut native_target = super::compact_construction::construct(
            &mut source,
            &pair,
            &raw,
            &tree,
            output,
            budget,
            resources,
            true,
        )?;
        save(output, "target-freeze-events.json", &events)?;
        events.clear();
        phase = "allocation-bounded-target-preservation";
        let views = assessment
            .assessment
            .source_view
            .as_ref()
            .context("live allocation-bounded source views absent")?;
        let proof = general_composite_target::verify_and_select_with_policy(
            &mut source,
            &mut native_target,
            pair.clone(),
            &raw,
            views,
            &source_hash,
            resources,
            packed_path,
            max_change_bytes,
            &mut events,
            capture_budget,
            capture_guard,
            policy,
        )?;
        ensure!(
            proof.expected_tree_sha256() == expected_sha256,
            "allocation-bounded proof differs from the fresh saved source expectation"
        );
        save(output, "target-preservation.json", &proof)?;
        save(output, "target-events.json", &events)?;
        events.clear();
        phase = "allocation-bounded-source-certificate";
        let certificate = assessment.qualify_allocation_target(&raw, &proof)?;
        let certificate_sha256 = save(output, "certificate.json", &certificate)?;
        save(output, "admitted-assessment.json", &assessment)?;
        save(
            output,
            "result.json",
            &serde_json::json!({
                "schema_version":1,"kind":"live-allocation-bounded-tree-qualification",
                "success":true,"source_admitted":true,"execution_authorized":false,
                "source_payload_writes":0,"source_sha256":source_hash,
                "expected_tree_sha256":expected_sha256,"certificate_sha256":certificate_sha256,
                "objects":tree.objects.len(),"selection_sha256":proof.selection_sha256(),
                "packed_changed_bytes":proof.capture().layout.changed_bytes(),
                "free_space_contents_compared":false,
                "source_after":source.state(&mut events)?,
                "target_after":native_target.state(&mut events)?,"events":events,
            }),
        )?;
        Ok(QualifiedAllocationTree {
            resources,
            source,
            native_target,
            proof,
            certificate,
            expected: serde_json::to_vec_pretty(&expected)?,
            mount_paths,
            source_label,
        })
    })();
    match attempted {
        Ok(qualified) => Ok(qualified),
        Err(error) => {
            save(
                output,
                "failed.json",
                &serde_json::json!({
                    "schema_version":1,"kind":"live-allocation-bounded-qualification-failure",
                    "phase":phase,"error":format!("{error:#}"),
                    "source_payload_writes":0,"execution_authorized":false,
                }),
            )?;
            Err(error)
        }
    }
}
