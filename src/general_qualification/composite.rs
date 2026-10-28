//! Owning qualification of an existing native source-backed shadow. This
//! path retains the original live source assessment through certificate issue;
//! it never reads an old qualification report or initializes duplicate payload.
use super::*;
use crate::general_composite_target::{self, FrozenCompositeTargetPreservation};

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
            "existing_native_shadow":true,"source_payload_writes_authorized":false,
            "source_admitted":false,"execution_authorized":false,
        }),
    )?;
    let mut phase = "source-freeze";
    let attempted = (|| -> Result<QualifiedCompositeTree> {
        let mut events = Vec::<NativeEvent>::new();
        let PreparedSourceContext {
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
        )?;
        phase = "existing-native-shadow-freeze";
        let state =
            n2r_win32::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
        let mut native_target = match state.disk_attributes {
            0 => GeneralFrozenPartition::isolate(pair.shadow.clone(), &mut events)?,
            3 => GeneralFrozenPartition::reopen(pair.shadow.clone(), &mut events)?,
            _ => anyhow::bail!("existing composite shadow must be mounted or frozen read-only"),
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
