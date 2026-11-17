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

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::{general_layout::GeneralDiskBinding, layout::PartitionIdentity};
    fn disk(number: u32, identity: &str, partition: &str, bytes: u64) -> GeneralDiskBinding {
        GeneralDiskBinding {
            layout_profile: Default::default(),
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
}
