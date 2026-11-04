//! Explicit runtime source ownership. Serialized scope describes a route only;
//! it cannot issue a native freeze, certificate, guard or writer.
use anyhow::{Context, Result, bail};
use n2r_win32::{
    GeneralDiskState, GeneralFreezeObservation, GeneralFrozenPartition, NativeEvent,
    PartitionOwnerToken, PartitionScopedOwner, general_layout::GeneralDiskBinding,
};
use std::io::{self, Read, Seek, SeekFrom};

pub(crate) enum ResourceSourceOwner {
    Dedicated(GeneralFrozenPartition),
    /// Actual private owner/token, deliberately UNADMITTED until the new SDK
    /// target-only lifecycle/native-RO witness and complete guard are supplied.
    Partition {
        owner: PartitionScopedOwner,
        token: Box<PartitionOwnerToken>,
        admission: Option<n2r_win32::partition_lifecycle::PartitionNtfsAdmission>,
    },
}
impl ResourceSourceOwner {
    pub(crate) fn dedicated(owner: GeneralFrozenPartition) -> Self {
        Self::Dedicated(owner)
    }
    pub(crate) fn private_unadmitted(owner: PartitionScopedOwner) -> Self {
        let token = owner.owner_token();
        Self::Partition {
            owner,
            token: Box::new(token),
            admission: None,
        }
    }
    pub(crate) fn owner_identity(&self) -> usize {
        match self {
            Self::Dedicated(owner) => std::ptr::from_ref(owner) as usize,
            Self::Partition { token, .. } => std::ptr::from_ref(token.as_ref()) as usize,
        }
    }
    pub(crate) fn binding(&self) -> &GeneralDiskBinding {
        match self {
            Self::Dedicated(owner) => owner.binding(),
            Self::Partition { owner, .. } => &owner.binding().storage,
        }
    }
    pub(crate) fn byte_len(&self) -> u64 {
        match self {
            Self::Dedicated(owner) => owner.byte_len(),
            Self::Partition { owner, .. } => owner.byte_len(),
        }
    }
    pub(crate) fn partition_token(&self) -> Option<PartitionOwnerToken> {
        match self {
            Self::Dedicated(_) => None,
            Self::Partition { token, .. } => Some(token.as_ref().clone()),
        }
    }
    pub(crate) fn require_dedicated(&self) -> Result<&GeneralFrozenPartition> {
        match self {
            Self::Dedicated(owner) => Ok(owner),
            Self::Partition { .. } => {
                bail!("partition source cannot use a dedicated-disk certificate/native transition")
            }
        }
    }
    pub(crate) fn require_dedicated_mut(&mut self) -> Result<&mut GeneralFrozenPartition> {
        match self {
            Self::Dedicated(owner) => Ok(owner),
            Self::Partition { .. } => bail!(
                "partition source requires target-only SDK lifecycle/native-RO admission; no whole-disk fallback"
            ),
        }
    }
    pub(crate) fn into_dedicated(self) -> Result<GeneralFrozenPartition> {
        match self {
            Self::Dedicated(owner) => Ok(owner),
            Self::Partition { .. } => bail!(
                "partition cancellation requires its own complete target-only preparation guard; no whole-disk transition"
            ),
        }
    }
    pub(crate) fn bring_original_online_unchanged(
        self,
        sha: &str,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        self.into_dedicated()?
            .bring_original_online_unchanged(sha, events)?;
        Ok(())
    }
    pub(crate) fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        match self {
            Self::Dedicated(owner) => owner.state(events),
            Self::Partition { .. } => Err(io::Error::other(
                "partition state is not GeneralDiskState; legacy exclusion check refused",
            )),
        }
    }
    pub(crate) fn freeze_observation(&self) -> Option<&GeneralFreezeObservation> {
        match self {
            Self::Dedicated(owner) => owner.freeze_observation(),
            Self::Partition { .. } => None,
        }
    }
    pub(crate) fn require_complete_partition_admission(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        match self {
            Self::Dedicated(_) => Ok(()),
            Self::Partition {
                owner,
                token,
                admission,
            } => {
                anyhow::ensure!(
                    token.same_owner(&owner.owner_token()),
                    "actual partition owner token changed"
                );
                owner.revalidate(events)?;
                // This calls the NEW SDK interface only. No GeneralFrozen
                // witness or certificate can be synthesized from observations.
                let admission = admission
                    .as_ref()
                    .context("actual complete partition preparation/native-RO owner absent")?;
                n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(
                    owner, admission,
                )
                .context("complete partition preparation guard/freeze/native-RO evidence pending")
            }
        }
    }
}
impl Read for ResourceSourceOwner {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Dedicated(owner) => owner.read(b),
            Self::Partition { owner, .. } => owner.read(b),
        }
    }
}
impl Seek for ResourceSourceOwner {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Dedicated(owner) => owner.seek(p),
            Self::Partition { owner, .. } => owner.seek(p),
        }
    }
}

/// Actual bounded raw-NTFS inspection tied to a private owner. This intermediate
/// deliberately cannot become ResourceSourceContext or publish/apply a journal:
/// full protected native-RO collection and complete preparation guard are absent.
pub(crate) struct UnadmittedPartitionSource {
    source: ResourceSourceOwner,
    raw: crate::ntfs_inspect::PagedInspection,
    coverage: crate::source_fingerprint::resource::InspectionReadCoverage,
    inspection_sha256: String,
    scratch: crate::ntfs_inspect::paged_storage::SourceScratch,
    _io_memory: crate::ntfs_inspect::paged_storage::SourceRamLease,
}
impl UnadmittedPartitionSource {
    pub(crate) fn inspect(
        mut owner: PartitionScopedOwner,
        budget: n2r_win32::tree_resources::ResourceBudget,
        policy: crate::verification_policy::VerificationPolicy,
        fresh_root: &std::path::Path,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        owner.revalidate(events)?;
        let scratch = crate::ntfs_inspect::paged_storage::SourceScratch::new(
            crate::ntfs_inspect::SourceMetadataBudget::from_resource_budget(budget)?,
        )?;
        let io_memory = scratch.lease_ram(GeneralFrozenPartition::read_buffer_memory_bytes())?;
        let length = owner.byte_len();
        let mut source = ResourceSourceOwner::private_unadmitted(owner);
        let (raw, coverage) = crate::source_fingerprint::resource::inspect_recorded_with_scratch(
            &mut source,
            length,
            budget,
            policy,
            fresh_root,
            &scratch,
        )?;
        let inspection_sha256 = raw.canonical_sha256()?;
        if let ResourceSourceOwner::Partition { owner, token, .. } = &mut source {
            owner.revalidate(events)?;
            anyhow::ensure!(
                token.same_owner(&owner.owner_token()),
                "raw inspection owner changed"
            );
        } else {
            bail!("private inspection lost its actual partition scope");
        }
        Ok(Self {
            source,
            raw,
            coverage,
            inspection_sha256,
            scratch,
            _io_memory: io_memory,
        })
    }
    pub(crate) fn inspection(&self) -> &crate::ntfs_inspect::PagedInspection {
        &self.raw
    }
    pub(crate) fn inspection_sha256(&self) -> &str {
        &self.inspection_sha256
    }
    pub(crate) fn read_coverage(
        &self,
    ) -> &crate::source_fingerprint::resource::InspectionReadCoverage {
        &self.coverage
    }
    pub(crate) fn source_artifact_bytes(&self) -> u64 {
        self.scratch.used_bytes()
    }
    pub(crate) fn require_complete_admission(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        self.source.require_complete_partition_admission(events)
    }
}

/// Independent source cursor. The caller prepays the native I/O buffer; the
/// partition branch derives its route only from the still-held actual owner.
pub(crate) enum ResourceSourceReadLane {
    Dedicated(GeneralFrozenPartition),
    Partition(n2r_win32::partition_lifecycle::PartitionReadLane),
}
impl ResourceSourceReadLane {
    pub(crate) fn open(
        source: &mut ResourceSourceOwner,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        match source {
            ResourceSourceOwner::Dedicated(owner) => Ok(Self::Dedicated(
                GeneralFrozenPartition::reopen(owner.binding().clone(), events)?,
            )),
            ResourceSourceOwner::Partition { owner, token, .. } => {
                anyhow::ensure!(
                    token.same_owner(&owner.owner_token()),
                    "source lane owner token changed"
                );
                Ok(Self::Partition(
                    n2r_win32::partition_lifecycle::PartitionReadLane::from_owner(owner, events)?,
                ))
            }
        }
    }
    pub(crate) fn byte_len(&self) -> u64 {
        match self {
            Self::Dedicated(owner) => owner.byte_len(),
            Self::Partition(lane) => lane.byte_len(),
        }
    }
    pub(crate) fn dedicated_state(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralDiskState> {
        match self {
            Self::Dedicated(owner) => owner.state(events),
            Self::Partition(_) => Err(io::Error::other(
                "partition read lane has no whole-disk exclusion state",
            )),
        }
    }
}
impl Read for ResourceSourceReadLane {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Dedicated(owner) => owner.read(b),
            Self::Partition(lane) => lane.read(b),
        }
    }
}
impl Seek for ResourceSourceReadLane {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Dedicated(owner) => owner.seek(p),
            Self::Partition(lane) => lane.seek(p),
        }
    }
}
