//! Certificate-backed same-partition conversion. Qualification, journal
//! preparation, durable recovery inputs and cutover stay in one process.
use crate::{general_qualification as qualification, general_reconstruct as reconstruct};
use anyhow::{Result, ensure};
#[cfg(test)]
use n2r_win32::journal_file::MAX_JOURNAL_BYTES;
use n2r_win32::{
    NativeEvent,
    general_layout::GeneralSourceShadowBinding,
    journal_file::{
        GeneralJournalStorageBinding, JournalProfile, observe_general_journal_file_with_profile,
    },
    layout::guid_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

mod allocation;
pub(crate) use allocation::convert_allocation_redundant_for_lab;
#[allow(
    dead_code,
    reason = "composite orchestration awaits native qualification before CLI exposure"
)]
mod composite;
#[allow(
    unused_imports,
    reason = "experimental entry point retained for the next owning-guest integration"
)]
pub(crate) use composite::{
    convert_compact_selected_for_lab, convert_composite_existing_experimental,
    convert_composite_fresh_experimental,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    #[serde(
        default,
        skip_serializing_if = "crate::verification_policy::VerificationPolicy::is_full_content"
    )]
    pub verification_policy: crate::verification_policy::VerificationPolicy,
    #[serde(
        default,
        skip_serializing_if = "crate::selected_capacity::SelectedCapacityPolicy::is_conservative"
    )]
    pub selected_capacity_policy: crate::selected_capacity::SelectedCapacityPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_resource_profile: Option<crate::ntfs_admission::ResourceProfile>,
    pub experiment_id: String,
    pub pair: GeneralSourceShadowBinding,
    pub journal: GeneralJournalStorageBinding,
    pub max_journal_bytes: u64,
    /// Fresh capture ceiling, pinned independently of encoded journal capacity.
    /// Historical requests omit it and retain their original behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_literal_backing_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_combined_scratch_bytes: Option<u64>,
    #[serde(default)]
    pub verify_existing_shadow: bool,
}
impl Request {
    pub fn journal_profile(&self) -> Result<JournalProfile> {
        Ok(JournalProfile::from_schema_and_capacity(
            self.schema_version,
            (self.schema_version == 3).then_some(self.max_journal_bytes),
        )?)
    }
    pub fn validate(&self) -> Result<()> {
        let profile = self.journal_profile()?;
        if !self.selected_capacity_policy.is_conservative() {
            ensure!(
                self.schema_version == 3
                    && matches!(profile, JournalProfile::CapacityPinnedV3 { .. })
                    && self.verification_policy.is_fast()
                    && self
                        .source_resource_profile
                        .is_some_and(|p| p.is_streaming())
                    && self.max_literal_backing_bytes.is_some()
                    && self.max_combined_scratch_bytes.is_some()
                    && !self.verify_existing_shadow,
                "actual old-zero capacity requires fresh schema3 fast allocation with pinned scratch bounds"
            );
        }
        if let Some(
            resources @ crate::ntfs_admission::ResourceProfile::ExperimentalObjectEnvelopeV3(
                admission,
            ),
        ) = self.source_resource_profile
        {
            ensure!(
                self.schema_version == 3
                    && self.verification_policy.is_fast()
                    && !self.verify_existing_shadow,
                "object envelope requires fresh fast allocation"
            );
            if admission.is_some() {
                resources.count_admission()?;
            }
        }
        ensure!(
            self.verification_policy.is_full_content()
                || (self.schema_version == 3
                    && self
                        .source_resource_profile
                        .is_some_and(|p| p.is_streaming())
                    && !self.verify_existing_shadow),
            "extent-identity verification requires schema3 streaming fresh allocation"
        );
        ensure!(
            if self.schema_version == 3 {
                self.max_literal_backing_bytes.is_some_and(|bytes| {
                    bytes > 0
                        && bytes.is_multiple_of(4096)
                        && bytes <= n2r_win32::reference_file::MAX_REFERENCE_FILE_BYTES
                        && bytes.checked_add(self.max_journal_bytes).is_some()
                }) && self.max_combined_scratch_bytes.is_some_and(|bytes| {
                    bytes >= self.max_journal_bytes
                        && self
                            .max_literal_backing_bytes
                            .is_some_and(|literal| literal <= bytes)
                }) && !self.verify_existing_shadow
            } else {
                self.max_literal_backing_bytes.is_none()
                    && self.max_combined_scratch_bytes.is_none()
            },
            "conversion capture capacity profile differs"
        );
        if !self
            .source_resource_profile
            .is_some_and(|p| p.is_envelope())
        {
            crate::lab_reconstruct::validate_source_profile_binding(
                self.schema_version,
                self.source_resource_profile,
            )?;
        }
        self.pair.validate_with_resource_profile(
            self.source_resource_profile
                .unwrap_or_default()
                .native_profile(),
        )?;
        self.journal.validate()?;
        ensure!(
            self.experiment_id.len() == 32
                && self
                    .experiment_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && (1..=profile.max_journal_bytes()).contains(&self.max_journal_bytes),
            "conversion request profile differs"
        );
        for disk in [&self.pair.source, &self.pair.shadow] {
            ensure!(
                disk.disk_number != self.journal.disk.disk_number
                    && guid_bytes(&disk.identity.disk_guid)?
                        != guid_bytes(&self.journal.disk.identity.disk_guid)?
                    && guid_bytes(&disk.identity.partition_guid)?
                        != guid_bytes(&self.journal.disk.identity.partition_guid)?
                    && guid_bytes(&disk.volume_guid)?
                        != guid_bytes(&self.journal.disk.volume_guid)?,
                "journal storage must be independent of both data disks"
            );
        }
        crate::lab_reconstruct::changed_byte_budget_for_profile(
            profile,
            self.max_journal_bytes,
            self.pair.source.identity.partition_bytes,
        )?;
        Ok(())
    }

    pub(crate) fn maximum_selected_changed_bytes(&self) -> Result<u64> {
        let partition = self.pair.source.identity.partition_bytes / 4096 * 4096;
        if self.selected_capacity_policy.is_conservative() {
            Ok(self
                .max_journal_bytes
                .checked_sub(n2r_win32::journal_file::JOURNAL_OVERHEAD_RESERVE)
                .ok_or_else(|| anyhow::anyhow!("selected journal cannot reserve its metadata"))?
                .min(partition)
                / 4096
                * 4096)
        } else {
            Ok(partition)
        }
    }

    /// A persisted policy chooses resource accounting, never source admission.
    /// Expanded write sets must retain the authenticated format-four subset.
    pub(crate) fn validate_selected_capacity(
        &self,
        plan: &crate::selected_journal::SelectedPlan,
    ) -> Result<()> {
        let (changed, journal) = plan.validate()?;
        ensure!(
            plan.source_free_ranges.is_empty()
                || self.selected_capacity_policy.allows_source_free(),
            "source-free restoration requires its explicit pinned recovery policy"
        );
        ensure!(
            plan.image_length == self.pair.source.identity.partition_bytes
                && plan.max_journal_bytes == self.max_journal_bytes
                && journal <= self.max_journal_bytes
                && changed <= self.maximum_selected_changed_bytes()?,
            "selected plan exceeds its pinned capacity policy"
        );
        if changed > self.journal_profile()?.max_encoded_changed_bytes() {
            ensure!(
                !self.selected_capacity_policy.is_conservative()
                    && ((plan.old_zero_bytes()? > 0 && plan.encoding_version() == 4)
                        || (self.selected_capacity_policy.allows_source_free()
                            && plan.source_free_bytes()? > 0
                            && plan.encoding_version() == 5)),
                "expanded selected write set requires an explicit omitted-old-byte capacity policy"
            );
        }
        Ok(())
    }
}

pub fn convert(request: &Request, output: &Path) -> Result<()> {
    convert_profile(request, output, Interruption::None, false)
}

/// Explicit experimental compact backend for selected dedicated data disks.
/// Construction enrollment is observed from this process's original frozen
/// source and fresh native ReFS shadow. Source raw writes still require the
/// original live certificate, full candidate comparison and durable journal.
pub fn convert_compact_experimental(
    request: &Request,
    budget: qualification::CompactConstructionBudget,
    output: &Path,
) -> Result<()> {
    request.validate()?;
    budget.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        request.selected_capacity_policy.is_conservative()
            && request.source_resource_profile
                == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2)
            && !request.verify_existing_shadow,
        "selected compact conversion requires the explicit streaming profile and a fresh shadow"
    );
    composite::convert_compact_selected(request, budget, output)
}

/// Experimental allocation-bounded backend for the same selected data disks,
/// under the ntfs2btrfs-style guarantee: only the protected native allocation of
/// the frozen shadow is compared, journaled and written. Public `--recover`
/// reopens the pinned allocation recovery bundle and authenticates its journal.
pub fn convert_allocation_experimental(
    request: &Request,
    budget: qualification::CompactConstructionBudget,
    output: &Path,
) -> Result<()> {
    request.validate()?;
    budget.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        request
            .source_resource_profile
            .is_some_and(|p| p.is_streaming())
            && !request.verify_existing_shadow,
        "allocation-bounded conversion requires the explicit streaming profile and a fresh shadow"
    );
    allocation::convert_allocation_selected(request, budget, output, None, false, false)
}

/// Lab-only selected-device fault entry for the allocation-bounded backend.
/// The public drive command always passes no interruption.
pub(crate) fn convert_allocation_selected_for_lab(
    request: &Request,
    budget: qualification::CompactConstructionBudget,
    output: &Path,
    interrupt_after_writes: Option<u32>,
) -> Result<()> {
    request.validate()?;
    budget.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        request
            .source_resource_profile
            .is_some_and(|p| p.is_streaming())
            && !request.verify_existing_shadow,
        "allocation-bounded lab exercise requires the explicit streaming profile and a fresh shadow"
    );
    allocation::convert_allocation_selected(
        request,
        budget,
        output,
        interrupt_after_writes,
        false,
        false,
    )
}

/// Lab-only first flushed-write fault through exclusive preparation and the
/// private fresh writer. This never reopens a saved admission or recovery state.
pub(crate) fn convert_allocation_exclusive_v3_first_write_for_lab(
    request: &Request,
    budget: qualification::CompactConstructionBudget,
    output: &Path,
) -> Result<()> {
    request.validate()?;
    budget.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        request.schema_version == 3
            && request.verification_policy.is_fast()
            && request.source_resource_profile
                == Some(crate::ntfs_admission::ResourceProfile::ExperimentalObjectEnvelopeV3(None))
            && !request.verify_existing_shadow,
        "exclusive V3 fault requires fresh schema3 fast planning None, never restored admission"
    );
    allocation::convert_allocation_selected(request, budget, output, Some(1), false, true)
}

/// Semantic lab fault, derived from the actual qualified copy map rather than
/// a fixture-specific write count. Never exposed by the public drive command.
pub(crate) fn convert_allocation_first_copy_interrupted_for_lab(
    request: &Request,
    budget: qualification::CompactConstructionBudget,
    output: &Path,
) -> Result<()> {
    request.validate()?;
    budget.validate(request.pair.source.identity.partition_bytes)?;
    ensure!(
        request
            .source_resource_profile
            .is_some_and(|p| p.is_streaming())
            && !request.verify_existing_shadow,
        "copy-write lab exercise requires the explicit streaming profile and a fresh shadow"
    );
    allocation::convert_allocation_selected(request, budget, output, None, true, false)
}

/// Explicit owning-guest exercise: synchronize the known small source cache
/// after fresh source freeze, then run the unchanged admission/journal gates.
pub fn convert_with_existing_cache_sync(request: &Request, output: &Path) -> Result<()> {
    ensure!(
        request.verify_existing_shadow
            && request.source_resource_profile
                == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2),
        "cache synchronization requires explicit streaming shadow reuse"
    );
    convert_profile(request, output, Interruption::None, true)
}

#[derive(Clone, Copy)]
enum Interruption {
    None,
    AfterWrites(u32),
    AfterSourceFreeze,
}

/// Controlled lab fault injection after N complete, flushed target writes.
/// The public conversion CLI does not expose this path. All qualification and
/// durable recovery prerequisites are identical to an ordinary conversion.
pub fn convert_interrupted(request: &Request, output: &Path, writes: u32) -> Result<()> {
    ensure!(
        (1..=4096).contains(&writes),
        "interruption count must be 1..=4096"
    );
    convert_profile(request, output, Interruption::AfterWrites(writes), false)
}

/// Same fresh cache synchronization and admission as the normal reuse path,
/// followed by the existing controlled flushed-write interruption. No recovery
/// authority or source/target qualification gate is skipped.
pub fn convert_interrupted_with_existing_cache_sync(
    request: &Request,
    output: &Path,
    writes: u32,
) -> Result<()> {
    ensure!(
        (1..=4096).contains(&writes),
        "interruption count must be 1..=4096"
    );
    ensure!(
        request.verify_existing_shadow
            && request.source_resource_profile
                == Some(crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2),
        "cache synchronization requires explicit streaming shadow reuse"
    );
    convert_profile(request, output, Interruption::AfterWrites(writes), true)
}

/// Laboratory-only process death after the real source-frozen artifact is
/// durable, with the native source handle still live and before target work.
/// The production conversion CLI does not expose this interruption point.
pub fn convert_interrupted_after_source_freeze(request: &Request, output: &Path) -> Result<()> {
    convert_profile(request, output, Interruption::AfterSourceFreeze, false)
}

fn interrupt_after_source_freeze(
    request: &Request,
    output: &Path,
    source: &n2r_win32::GeneralFrozenPartition,
    source_sha256: &str,
    artifact_sha256: &str,
) -> Result<()> {
    let mut events = Vec::<NativeEvent>::new();
    let state = source.state(&mut events)?;
    ensure!(
        source.binding() == &request.pair.source
            && state.disk_attributes == 3
            && source.freeze_observation().is_some(),
        "source-freeze interruption requires the actual observed excluded source"
    );
    let intent = serde_json::json!({
        "schema_version":1,
        "kind":"controlled-preactivation-interruption-intent",
        "experiment_id":request.experiment_id,
        "phase":"source-frozen-artifact-durable",
        "binding":source.binding(),
        "source_sha256":source_sha256,
        "source_frozen_artifact":"qualification/source-frozen.json",
        "source_frozen_artifact_sha256":artifact_sha256,
        "source_state_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&state)?)),
        "disk_attributes":state.disk_attributes,
        "expected_process_exit_code":87,
        "target_construction_started":false,
        "journal_prepared":false,
        "reconstruction_activated":false,
        "handoff_authorized":false,
        "source_payload_writes":0,
        "ordinary_conversion_behavior_changed":false
    });
    ensure!(
        serde_json::to_vec_pretty(&intent)?.len() <= 16384,
        "preactivation interruption intent exceeds its bound"
    );
    qualification::save(output, "preactivation-interruption-intent.json", &intent)?;
    // Intentionally bypass Rust destructors. Persistent attrs3 and the real
    // public qualification artifact survive the process and handle teardown.
    std::process::exit(87);
}

fn convert_profile(
    request: &Request,
    output: &Path,
    interruption: Interruption,
    cache_sync: bool,
) -> Result<()> {
    let interrupt_after_writes = match interruption {
        Interruption::AfterWrites(writes) => Some(writes),
        Interruption::None | Interruption::AfterSourceFreeze => None,
    };
    request.validate()?;
    ensure!(
        request.selected_capacity_policy.is_conservative(),
        "actual old-zero capacity is supported only by allocation conversion"
    );
    ensure!(
        !request
            .source_resource_profile
            .is_some_and(|p| p.is_envelope()),
        "object envelope is supported only by fresh allocation conversion"
    );
    ensure!(
        request.schema_version != 3,
        "capacity-pinned conversion requires the allocation-bounded backend"
    );
    if request.source_resource_profile.is_some() {
        eprintln!(
            "Using experimental larger-source profile; native conversion and recovery have not been qualified for this profile."
        );
    }
    if request.schema_version == JournalProfile::ExperimentalLargeV2.version() {
        eprintln!(
            "Using experimental v2 journal profile; native conversion and recovery at this capacity are not yet qualified."
        );
    }
    qualification::create_output(output)?;
    qualification::save(output, "conversion-intent.json", request)?;
    if cache_sync {
        qualification::save(
            output,
            "existing-shadow-refresh-policy.json",
            &serde_json::json!({
                "known_source_cache_sync":true,"large_payload_rewrite":false,
                "requires_fresh_source_and_target_admission":true,"execution_authorized":false
            }),
        )?;
    }
    let mut phase = "qualification";
    let attempted = (|| -> Result<()> {
        let profile = request.journal_profile()?;
        let max_change_bytes = crate::lab_reconstruct::changed_byte_budget_for_profile(
            profile,
            request.max_journal_bytes,
            request.pair.source.identity.partition_bytes,
        )?;
        let qualified = qualification::prepare_with_budget_and_source_freeze_hook(
            request.pair.clone(),
            &output.join("qualification"),
            request.verify_existing_shadow,
            max_change_bytes,
            profile,
            request.source_resource_profile.unwrap_or_default(),
            cache_sync,
            |source, source_sha256, artifact_sha256| {
                if matches!(interruption, Interruption::AfterSourceFreeze) {
                    interrupt_after_source_freeze(
                        request,
                        output,
                        source,
                        source_sha256,
                        artifact_sha256,
                    )?;
                }
                Ok(())
            },
        )?;
        let qualification::QualifiedTree {
            mut source,
            mut target,
            certificate,
            comparison,
            expected,
            mount_paths,
            source_label,
        } = qualified;
        let plan = reconstruct::Request {
            schema_version: request.schema_version,
            source_resource_profile: request.source_resource_profile,
            experiment_id: request.experiment_id.clone(),
            expected_tree_sha256: hex::encode(Sha256::digest(&expected)),
            expected_mount_paths: Some(mount_paths.paths),
            expected_source_label: Some(source_label.label().clone()),
            pair: request.pair.clone(),
            comparison,
            journal: request.journal.clone(),
            max_journal_bytes: request.max_journal_bytes,
        };
        plan.validate()?;
        ensure!(
            certificate.binds_request(&plan),
            "live certificate does not bind the exact conversion plan"
        );
        qualification::save(output, "request.json", &plan)?;
        let expectation: crate::shadow_tree::ExpectedTree = serde_json::from_slice(&expected)?;
        qualification::save(output, "expectation.json", &expectation)?;
        phase = "journal-preparation";
        let parent = std::path::PathBuf::from(format!(
            "{}\\ntfs2refs-shadow",
            request.journal.disk.volume_path()?
        ));
        if !parent.exists() {
            fs::create_dir(&parent)?;
        }
        let meta = fs::symlink_metadata(&parent)?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "ordinary journal parent required"
        );
        let directory = parent.join(&request.experiment_id);
        ensure!(!directory.exists(), "fresh journal experiment required");
        fs::create_dir(&directory)?;
        let journal_path = directory.join("reconstruction.journal");
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&journal_path)?;
        let observed =
            observe_general_journal_file_with_profile(&journal, &request.journal, profile)?;
        ensure!(observed.file_bytes == 0, "fresh empty journal required");
        qualification::save(
            output,
            "journal-location.json",
            &serde_json::json!({"path":journal_path,"identity":observed.identity}),
        )?;
        let mut progress = crate::preparation_progress::SnapshotFile::create(
            &output.join("journal-progress.json"),
        );
        let prepared = reconstruct::prepare_with_progress(
            &plan,
            &mut source,
            &mut target,
            &mut journal,
            &mut |snapshot| progress.report(snapshot),
        )?;
        qualification::save(output, "prepare.json", &prepared)?;
        let ticket_pin = qualification::save(output, "ticket.json", &prepared.journal.ticket)?;
        // Read back the durable external ticket while holding its file handle
        // exclusively. Neither a JSON success flag nor an unsaved ticket arms I/O.
        let mut ticket_file = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(output.join("ticket.json"))?;
        let mut ticket_bytes = Vec::new();
        (&mut ticket_file)
            .take(65537)
            .read_to_end(&mut ticket_bytes)?;
        ensure!(
            ticket_bytes.len() <= 65536 && hex::encode(Sha256::digest(&ticket_bytes)) == ticket_pin,
            "durable ticket readback differs"
        );
        let ticket: crate::lab_reconstruct::JournalTicket = serde_json::from_slice(&ticket_bytes)?;
        if let Some(writes) = interrupt_after_writes {
            qualification::save(
                output,
                "interruption-intent.json",
                &serde_json::json!({
                    "schema_version":1,"kind":"controlled-conversion-interruption-intent",
                    "interrupt_after_writes":writes,"expected_process_exit_code":86,
                    "ticket_sha256":ticket_pin,"journal_path":journal_path,
                    "handoff_authorized":false,"ordinary_conversion_behavior_changed":false
                }),
            )?;
        }
        phase = "activate-apply";
        let mut events = Vec::<NativeEvent>::new();
        let mut original = reconstruct::activate(
            &plan,
            source,
            &mut target,
            &mut journal,
            &ticket,
            &mut events,
        )?;
        let applied = if let Some(writes) = interrupt_after_writes {
            reconstruct::execute_interrupted_apply(
                &plan,
                &mut original,
                &mut target,
                &mut journal,
                &ticket,
                &mut events,
                writes,
            )?
        } else {
            reconstruct::execute(
                reconstruct::RecoveryOperation::Apply,
                &plan,
                &mut original,
                &mut target,
                &mut journal,
                &ticket,
                &mut events,
            )?
        };
        qualification::save(output, "apply.json", &applied)?;
        phase = "handoff";
        let finalization = reconstruct::finalize(
            &plan,
            original,
            &mut target,
            &mut journal,
            &ticket,
            &expected,
        )?;
        qualification::save(output, "finalization.json", &finalization)?;
        ensure!(
            finalization.success,
            "native ReFS handoff/verification failed: {:?}",
            finalization.error
        );
        qualification::save(
            output,
            "result.json",
            &serde_json::json!({"schema_version":1,"kind":"certificate-backed-ntfs-refs-conversion",
            "success":true,"source_admitted":true,"rollback_closed":finalization.rollback_closed,
            "journal_path":journal_path,"ticket_sha256":ticket_pin,"expected_tree_sha256":plan.expected_tree_sha256,
            "comparison":plan.comparison,"events":events}),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        qualification::save(
            output,
            "failed.json",
            &serde_json::json!({"phase":phase,"error":format!("{error:#}"),
            "recovery_materials":output,"automatic_rollback_attempted":false}),
        )?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::{general_layout::GeneralDiskBinding, layout::PartitionIdentity};
    fn disk(number: u32, identity: &str, partition: &str, bytes: u64) -> GeneralDiskBinding {
        GeneralDiskBinding {
            disk_number: number,
            volume_guid: partition.into(),
            identity: PartitionIdentity {
                disk_guid: identity.into(),
                partition_guid: partition.into(),
                partition_number: 2,
                disk_bytes: bytes,
                partition_offset: 16 * 1024 * 1024,
                partition_bytes: if number == 2 {
                    bytes - 32 * 1024 * 1024
                } else {
                    52 * 1024 * 1024 * 1024
                },
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
        }
    }
    fn request() -> Request {
        Request {
            schema_version: 1,
            verification_policy: crate::verification_policy::VerificationPolicy::FullContent,
            selected_capacity_policy: Default::default(),
            source_resource_profile: None,
            experiment_id: "a".repeat(32),
            pair: GeneralSourceShadowBinding {
                source: disk(
                    1,
                    "11111111-1111-1111-1111-111111111111",
                    "12121212-1212-1212-1212-121212121212",
                    64 * 1024 * 1024 * 1024,
                ),
                shadow: disk(
                    3,
                    "33333333-3333-3333-3333-333333333333",
                    "34343434-3434-3434-3434-343434343434",
                    64 * 1024 * 1024 * 1024,
                ),
            },
            journal: GeneralJournalStorageBinding {
                disk: disk(
                    2,
                    "22222222-2222-2222-2222-222222222222",
                    "23232323-2323-2323-2323-232323232323",
                    8 * 1024 * 1024 * 1024,
                ),
                externally_enrolled_disk_unique_id: "lab-journal".into(),
                allow_additional_partitions: false,
            },
            max_journal_bytes: MAX_JOURNAL_BYTES,
            max_literal_backing_bytes: None,
            max_combined_scratch_bytes: None,
            verify_existing_shadow: false,
        }
    }
    #[test]
    fn conversion_rejects_journal_aliases_and_invalid_experiments_before_io() {
        let good = request();
        good.validate().unwrap();
        for data in [&good.pair.source, &good.pair.shadow] {
            let mut bad = good.clone();
            bad.journal.disk.disk_number = data.disk_number;
            assert!(bad.validate().is_err());
            let mut bad = good.clone();
            bad.journal.disk.identity.disk_guid = data.identity.disk_guid.clone();
            assert!(bad.validate().is_err());
            let mut bad = good.clone();
            bad.journal.disk.volume_guid = data.volume_guid.clone();
            assert!(bad.validate().is_err());
        }
        let mut bad = good.clone();
        bad.max_journal_bytes = 0;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.max_journal_bytes = 16 * 1024 * 1024 + 8191;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.max_journal_bytes = MAX_JOURNAL_BYTES + 1;
        assert!(bad.validate().is_err());
        let mut bad = good;
        bad.experiment_id = "..".repeat(16);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn large_journal_requires_explicit_v2_request() {
        let mut candidate = request();
        candidate.max_journal_bytes = 2u64 << 30;
        assert!(candidate.validate().is_err());
        candidate.schema_version = 2;
        candidate.validate().unwrap();
        candidate.max_journal_bytes = (16u64 << 30) + 1;
        assert!(candidate.validate().is_err());
        candidate.schema_version = 3;
        candidate.max_journal_bytes = 2u64 << 30;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn invalid_interruption_count_is_refused_before_output_or_device_access() {
        let request = request();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output");
        for writes in [0, 4097, u32::MAX] {
            let error = convert_interrupted(&request, &output, writes).unwrap_err();
            assert!(
                error.to_string().contains("interruption count"),
                "{error:#}"
            );
            assert!(!output.exists());
        }
    }
}
