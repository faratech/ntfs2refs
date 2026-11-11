//! Versioned routing only. No deserialized value is source/guard authority.
use anyhow::{Result, ensure};
use n2r_win32::{
    NativeEvent, PartitionOwnerToken, PartitionScopedOwner,
    general_layout::GeneralDiskBinding,
    journal_file::GeneralJournalStorageBinding,
    partition_isolation::PartitionSourceBinding,
    partition_lifecycle::{PartitionNtfsAdmission, PartitionPreparationPin},
};
use serde::{Deserialize, Serialize};

pub(crate) const PRIVATE_TYPE: &str = "b627aadb-a893-48b6-aa0b-71e5f30ee370";
const BASIC_TYPE: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardFilePin {
    pub final_path: String,
    pub volume_serial_number: u64,
    pub file_id_128: [u8; 16],
    pub file_bytes: u64,
    pub allocation_bytes: u64,
    pub file_attributes: u32,
    pub number_of_links: u32,
}

/// Exact DTO of the SDK's complete pin. It is deliberately not the SDK guard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartitionPreparationGuardPin {
    pub version: u32,
    pub kind: String,
    pub binding: PartitionSourceBinding,
    pub original_partition_info: Vec<u8>,
    pub original_gpt_sha256: String,
    pub original_mbr_sha256: String,
    pub ntfs_primary_sha256: String,
    pub intent_file: GuardFilePin,
    pub intent_prefix_sha256: String,
    pub sequence: u64,
    pub observed_stage: String,
    pub serialized_pin_grants_authority: bool,
}

fn require_sha(s: &str) -> Result<()> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical partition preparation SHA256"
    );
    Ok(())
}

impl PartitionPreparationGuardPin {
    pub(crate) fn from_actual(pin: &PartitionPreparationPin) -> Result<Self> {
        let value: Self = serde_json::from_value(serde_json::to_value(pin)?)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        for value in [
            &self.original_gpt_sha256,
            &self.original_mbr_sha256,
            &self.ntfs_primary_sha256,
            &self.intent_prefix_sha256,
        ] {
            require_sha(value)?;
        }
        ensure!(
            ((self.version == 1
                && self.kind == "partition-target-only-preparation-v1"
                && self.observed_stage == "PrivateLocked")
                || (self.version == 2
                    && self.kind == "partition-readonly-physical-preparation-v2"
                    && self.observed_stage == "ReadonlyPhysicalLocked"))
                && self.original_partition_info.len() == 144
                && (1..=4).contains(&self.sequence)
                && !self.serialized_pin_grants_authority
                && self.intent_file.file_bytes > 0
                && self.intent_file.file_bytes <= 16 * 1024 * 1024
                && self.intent_file.file_id_128 != [0; 16]
                && self.intent_file.volume_serial_number != 0
                && self.intent_file.number_of_links == 1
                && std::path::Path::new(&self.intent_file.final_path).is_absolute(),
            "incomplete/foreign partition preparation routing contract"
        );
        Ok(())
    }
    pub(crate) fn require_actual(
        &self,
        admission: &mut PartitionNtfsAdmission,
        owner: &mut PartitionScopedOwner,
        stable: &PartitionOwnerToken,
        events: &mut Vec<NativeEvent>,
    ) -> Result<PartitionPreparationPin> {
        self.validate()?;
        ensure!(
            stable.same_owner(&owner.owner_token()) && owner.binding() == &self.binding,
            "partition publication lost its actual stable owner"
        );
        let actual = admission.durable_preparation_pin()?;
        ensure!(
            serde_json::to_value(self)? == serde_json::to_value(&actual)?,
            "serialized partition pin differs from actual complete held guard"
        );
        admission.revalidate_publication_handoff(owner, &actual, events)?;
        ensure!(
            stable.same_owner(&owner.owner_token()),
            "actual partition owner changed"
        );
        Ok(actual)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartitionNativeMetadataPin {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub budget: n2r_win32::observation_pages::NativeObservationBudget,
}
impl PartitionNativeMetadataPin {
    fn validate(&self) -> Result<()> {
        self.budget.validate()?;
        require_sha(&self.sha256)?;
        let path = std::path::Path::new(&self.path);
        ensure!(
            self.bytes > 0
                && self.bytes <= self.budget.pages.max_file_bytes
                && path.is_absolute()
                && !path.components().any(|c| matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )),
            "partition native metadata route/budget differs"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartitionPublicationScope {
    pub native_metadata: PartitionNativeMetadataPin,
    pub scope_version: u32,
    pub binding: PartitionSourceBinding,
    pub private_type_guid: String,
    pub original_basic_type_guid: String,
    pub original_attributes: u64,
    /// All36 WCHARs, including unused/trailing units, without normalization.
    pub original_name_utf16le: Vec<u8>,
    pub complete_preparation_guard: PartitionPreparationGuardPin,
}
impl PartitionPublicationScope {
    pub(crate) fn from_actual(
        owner: &mut PartitionScopedOwner,
        stable: &PartitionOwnerToken,
        admission: &mut PartitionNtfsAdmission,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        owner.revalidate(events)?;
        ensure!(
            stable.same_owner(&owner.owner_token()),
            "partition owner/token differs"
        );
        let actual = admission.durable_preparation_pin()?;
        admission.revalidate_publication_handoff(owner, &actual, events)?;
        let info = admission.original_partition_info();
        ensure!(
            info.len() == 144,
            "actual original partition information length differs"
        );
        use n2r_win32::attestation::NativeObservationDomain;
        let domain = admission.native().domain();
        domain.revalidate()?;
        let native_metadata = PartitionNativeMetadataPin {
            path: domain.final_path(),
            bytes: domain.byte_len(),
            sha256: domain.sha256().into(),
            budget: domain.budget(),
        };
        let scope = Self {
            native_metadata,
            scope_version: 2,
            binding: owner.binding().clone(),
            private_type_guid: PRIVATE_TYPE.into(),
            original_basic_type_guid: BASIC_TYPE.into(),
            original_attributes: u64::from_le_bytes(info[64..72].try_into()?),
            original_name_utf16le: info[72..144].to_vec(),
            complete_preparation_guard: PartitionPreparationGuardPin::from_actual(&actual)?,
        };
        scope.validate()?;
        scope
            .complete_preparation_guard
            .require_actual(admission, owner, stable, events)?;
        Ok(scope)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.complete_preparation_guard.validate()?;
        self.native_metadata.validate()?;
        let info = &self.complete_preparation_guard.original_partition_info;
        ensure!(
            self.scope_version == 2
                && self.complete_preparation_guard.version == 1
                && self.complete_preparation_guard.kind == "partition-target-only-preparation-v1"
                && self.complete_preparation_guard.observed_stage == "PrivateLocked"
                && self.private_type_guid == PRIVATE_TYPE
                && self.original_basic_type_guid == BASIC_TYPE
                && self.original_name_utf16le.len() == 72
                && self.complete_preparation_guard.binding == self.binding
                && u32::from_le_bytes(info[0..4].try_into()?) == 1
                && info[32..48] == n2r_win32::layout::guid_bytes(BASIC_TYPE)?
                && info[48..64]
                    == n2r_win32::layout::guid_bytes(
                        &self.binding.storage.identity.partition_guid
                    )?
                && u64::from_le_bytes(info[8..16].try_into()?)
                    == self.binding.storage.identity.partition_offset
                && u64::from_le_bytes(info[16..24].try_into()?)
                    == self.binding.storage.identity.partition_bytes
                && u32::from_le_bytes(info[24..28].try_into()?)
                    == self.binding.storage.identity.partition_number
                && u64::from_le_bytes(info[64..72].try_into()?) == self.original_attributes
                && info[72..144] == self.original_name_utf16le,
            "partition publication original type/ID/extent/attrs/name contract differs"
        );
        Ok(())
    }
}

/// New explicit routing protocol, minted only from the actual BasicRO physical
/// owner/native admission. Serialized fields remain facts and never writer authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartitionReadonlyPhysicalPublicationScope {
    pub native_metadata: PartitionNativeMetadataPin,
    pub scope_version: u32,
    pub binding: PartitionSourceBinding,
    pub readonly_type_guid: String,
    pub readonly_attributes: u64,
    pub original_basic_type_guid: String,
    pub original_attributes: u64,
    pub original_name_utf16le: Vec<u8>,
    pub complete_preparation_guard: PartitionPreparationGuardPin,
}
impl PartitionReadonlyPhysicalPublicationScope {
    pub(crate) fn from_actual(
        owner: &mut PartitionScopedOwner,
        stable: &PartitionOwnerToken,
        admission: &mut PartitionNtfsAdmission,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        use n2r_win32::attestation::NativeObservationDomain;
        use n2r_win32::partition_lifecycle::PartitionDataProfile;
        ensure!(
            owner.data_profile() == PartitionDataProfile::BasicReadonlyPhysicalV3
                && stable.same_owner(&owner.owner_token()),
            "actual BasicRO physical source owner required"
        );
        owner.revalidate(events)?;
        let actual = admission.durable_preparation_pin()?;
        admission.revalidate_publication_handoff(owner, &actual, events)?;
        ensure!(
            actual.version == 2 && actual.kind == "partition-readonly-physical-preparation-v2",
            "actual readonly physical preparation pin required"
        );
        let info = admission.original_partition_info();
        ensure!(info.len() == 144, "actual original native144 absent");
        let domain = admission.native().domain();
        domain.revalidate()?;
        let result = Self {
            native_metadata: PartitionNativeMetadataPin {
                path: domain.final_path(),
                bytes: domain.byte_len(),
                sha256: domain.sha256().into(),
                budget: domain.budget(),
            },
            scope_version: 3,
            binding: owner.binding().clone(),
            readonly_type_guid: BASIC_TYPE.into(),
            readonly_attributes: 0x1000_0000_0000_0000,
            original_basic_type_guid: BASIC_TYPE.into(),
            original_attributes: u64::from_le_bytes(info[64..72].try_into()?),
            original_name_utf16le: info[72..144].to_vec(),
            complete_preparation_guard: PartitionPreparationGuardPin::from_actual(&actual)?,
        };
        result.validate()?;
        result
            .complete_preparation_guard
            .require_actual(admission, owner, stable, events)?;
        Ok(result)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.native_metadata.validate()?;
        self.complete_preparation_guard.validate()?;
        let pin = &self.complete_preparation_guard;
        let info = &pin.original_partition_info;
        ensure!(
            self.scope_version == 3
                && self.readonly_type_guid == BASIC_TYPE
                && self.readonly_attributes == 0x1000_0000_0000_0000
                && self.original_basic_type_guid == BASIC_TYPE
                && self.original_attributes == 0
                && self.original_name_utf16le.len() == 72
                && pin.version == 2
                && pin.kind == "partition-readonly-physical-preparation-v2"
                && pin.observed_stage == "ReadonlyPhysicalLocked"
                && pin.binding == self.binding
                && info.len() == 144
                && u32::from_le_bytes(info[0..4].try_into()?) == 1
                && info[32..48] == n2r_win32::layout::guid_bytes(BASIC_TYPE)?
                && info[48..64]
                    == n2r_win32::layout::guid_bytes(
                        &self.binding.storage.identity.partition_guid
                    )?
                && u64::from_le_bytes(info[8..16].try_into()?)
                    == self.binding.storage.identity.partition_offset
                && u64::from_le_bytes(info[16..24].try_into()?)
                    == self.binding.storage.identity.partition_bytes
                && u32::from_le_bytes(info[24..28].try_into()?)
                    == self.binding.storage.identity.partition_number
                && u64::from_le_bytes(info[64..72].try_into()?) == 0
                && info[72..144] == self.original_name_utf16le,
            "readonly physical publication original/protected type/ID/extent/attrs/name/pin contract differs"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum ResourceRecoverySourceScope {
    #[default]
    #[serde(rename = "dedicated-disk-v1")]
    Dedicated,
    #[serde(rename = "partition-v2")]
    Partition(PartitionPublicationScope),
    #[serde(rename = "partition-ro-physical-v3")]
    PartitionReadonlyPhysical(PartitionReadonlyPhysicalPublicationScope),
}
impl ResourceRecoverySourceScope {
    pub(crate) fn require_partition(&self) -> Result<()> {
        match self {
            Self::Dedicated => anyhow::bail!("explicit partition source scope required"),
            Self::Partition(scope) => scope.validate(),
            Self::PartitionReadonlyPhysical(scope) => scope.validate(),
        }
    }
    pub(crate) fn preparation_guard(&self) -> Result<&PartitionPreparationGuardPin> {
        self.require_partition()?;
        match self {
            Self::Partition(scope) => Ok(&scope.complete_preparation_guard),
            Self::PartitionReadonlyPhysical(scope) => Ok(&scope.complete_preparation_guard),
            Self::Dedicated => unreachable!(),
        }
    }
    pub(crate) fn partition_native_metadata(&self) -> Result<&PartitionNativeMetadataPin> {
        self.require_partition()?;
        match self {
            Self::Partition(scope) => Ok(&scope.native_metadata),
            Self::PartitionReadonlyPhysical(scope) => Ok(&scope.native_metadata),
            Self::Dedicated => unreachable!(),
        }
    }
    pub(crate) fn from_actual_partition(
        owner: &mut PartitionScopedOwner,
        stable: &PartitionOwnerToken,
        admission: &mut PartitionNtfsAdmission,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        use n2r_win32::partition_lifecycle::PartitionDataProfile;
        match owner.data_profile() {
            PartitionDataProfile::PrivateVolumeV2 => Ok(Self::Partition(
                PartitionPublicationScope::from_actual(owner, stable, admission, events)?,
            )),
            PartitionDataProfile::BasicReadonlyPhysicalV3 => Ok(Self::PartitionReadonlyPhysical(
                PartitionReadonlyPhysicalPublicationScope::from_actual(
                    owner, stable, admission, events,
                )?,
            )),
        }
    }
    pub(crate) fn envelope_protocol(&self) -> (u32, &'static str) {
        match self {
            Self::Dedicated => (1, "resource-allocation-recovery-envelope-v1"),
            Self::Partition(_) => (2, "resource-partition-recovery-envelope-v2"),
            Self::PartitionReadonlyPhysical(_) => (
                3,
                "resource-partition-readonly-physical-recovery-envelope-v3",
            ),
        }
    }
    pub(crate) fn locator_protocol(&self) -> (u32, &'static str) {
        match self {
            Self::Dedicated => (1, "resource-recovery-locator-v1"),
            Self::Partition(_) => (2, "resource-partition-recovery-locator-v2"),
            Self::PartitionReadonlyPhysical(_) => (
                3,
                "resource-partition-readonly-physical-recovery-locator-v3",
            ),
        }
    }
    /// Routing facts only: these never construct an owner, admission or writer.
    pub(crate) fn is_readonly_physical(&self) -> bool {
        matches!(self, Self::PartitionReadonlyPhysical(_))
    }
    pub(crate) fn partition_binding(&self) -> Option<&PartitionSourceBinding> {
        match self {
            Self::Dedicated => None,
            Self::Partition(p) => Some(&p.binding),
            Self::PartitionReadonlyPhysical(p) => Some(&p.binding),
        }
    }
    pub(crate) fn physical_partition_scope(
        &self,
    ) -> Option<&PartitionReadonlyPhysicalPublicationScope> {
        match self {
            Self::PartitionReadonlyPhysical(p) => Some(p),
            _ => None,
        }
    }
    pub(crate) fn is_dedicated(&self) -> bool {
        matches!(self, Self::Dedicated)
    }
    pub(crate) fn require_envelope_version(&self, version: u32, kind: &str) -> Result<()> {
        ensure!(
            match self {
                Self::Dedicated =>
                    version == 1 && kind == "resource-allocation-recovery-envelope-v1",
                Self::Partition(p) => {
                    p.validate()?;
                    version == 2 && kind == "resource-partition-recovery-envelope-v2"
                }
                Self::PartitionReadonlyPhysical(p) => {
                    p.validate()?;
                    version == 3
                        && kind == "resource-partition-readonly-physical-recovery-envelope-v3"
                }
            },
            "missing/foreign/mixed publication source scope/version"
        );
        Ok(())
    }
    pub(crate) fn require_locator_version(&self, version: u32, kind: &str) -> Result<()> {
        ensure!(
            match self {
                Self::Dedicated => version == 1 && kind == "resource-recovery-locator-v1",
                Self::Partition(p) => {
                    p.validate()?;
                    version == 2 && kind == "resource-partition-recovery-locator-v2"
                }
                Self::PartitionReadonlyPhysical(p) => {
                    p.validate()?;
                    version == 3
                        && kind == "resource-partition-readonly-physical-recovery-locator-v3"
                }
            },
            "missing/foreign/mixed locator source scope/version"
        );
        Ok(())
    }
    pub(crate) fn require_journal_route(
        &self,
        source: &GeneralDiskBinding,
        journal: &GeneralJournalStorageBinding,
    ) -> Result<()> {
        source.validate()?;
        journal.validate()?;
        let same_number = source.disk_number == journal.disk.disk_number;
        let same_guid = n2r_win32::layout::guid_bytes(&source.identity.disk_guid)?
            == n2r_win32::layout::guid_bytes(&journal.disk.identity.disk_guid)?;
        match self {
            // The legacy dedicated inequality is unchanged and cannot be
            // weakened by a missing partition tag or by different GUID syntax.
            Self::Dedicated => ensure!(
                !same_number && !same_guid,
                "legacy journal must remain on a different disk"
            ),
            Self::Partition(scope) => {
                scope.validate()?;
                ensure!(
                    &scope.binding.storage == source && same_number == same_guid,
                    "partition journal/source physical identity disagrees"
                );
                if same_number {
                    let s = &source.identity;
                    let j = &journal.disk.identity;
                    let se = s
                        .partition_offset
                        .checked_add(s.partition_bytes)
                        .ok_or_else(|| anyhow::anyhow!("source extent overflow"))?;
                    let je = j
                        .partition_offset
                        .checked_add(j.partition_bytes)
                        .ok_or_else(|| anyhow::anyhow!("journal extent overflow"))?;
                    ensure!(
                        s.partition_guid != j.partition_guid
                            && (se <= j.partition_offset || je <= s.partition_offset),
                        "same-disk partition journal extent overlaps selected source"
                    );
                }
            }
            Self::PartitionReadonlyPhysical(scope) => {
                scope.validate()?;
                ensure!(
                    &scope.binding.storage == source && same_number == same_guid,
                    "readonly physical journal/source identity disagrees"
                );
                if same_number {
                    let s = &source.identity;
                    let j = &journal.disk.identity;
                    let se = s
                        .partition_offset
                        .checked_add(s.partition_bytes)
                        .ok_or_else(|| anyhow::anyhow!("source extent overflow"))?;
                    let je = j
                        .partition_offset
                        .checked_add(j.partition_bytes)
                        .ok_or_else(|| anyhow::anyhow!("journal extent overflow"))?;
                    ensure!(
                        s.partition_guid != j.partition_guid
                            && (se <= j.partition_offset || je <= s.partition_offset),
                        "same-disk readonly physical journal overlaps selected source"
                    );
                }
            }
        }
        Ok(())
    }
}
