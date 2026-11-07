//! Actual source-context dispatch for the shared target/capture algorithm.
//! No synthetic GeneralDiskState, JSON admission or public source selector.
use super::*;
use crate::general_source_admission::resource::{
    ResourceSourceContext, partition::PartitionResourceSourceContext,
};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, GeneralLiveRefsLayoutObservation, NativeEvent,
    PartitionOwnerToken, tree_resources::SourceResourceAdmission,
};

pub(super) enum ScopedSourceContext<'a> {
    Dedicated(&'a mut ResourceSourceContext),
    Partition(&'a mut PartitionResourceSourceContext),
}
pub(super) enum SourceExclusionSnapshot {
    Dedicated(GeneralDiskState),
    Partition(PartitionOwnerToken),
}
impl SourceExclusionSnapshot {
    pub(super) fn require_excluded(&self) -> Result<()> {
        match self {
            Self::Dedicated(state) => ensure!(
                state.disk_attributes == 3,
                "original dedicated source lost physical exclusion"
            ),
            Self::Partition(_) => {}
        }
        Ok(())
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Dedicated(a), Self::Dedicated(b)) => a == b,
            (Self::Partition(a), Self::Partition(b)) => a.same_owner(b),
            _ => false,
        }
    }
}
impl ScopedSourceContext<'_> {
    pub(super) fn resource_admission(&self) -> SourceResourceAdmission {
        match self {
            Self::Dedicated(c) => c.resource_admission(),
            Self::Partition(c) => c.resource_admission(),
        }
    }
    pub(super) fn arena(&self) -> Option<&crate::artifact_arena::ArtifactArena> {
        match self {
            Self::Dedicated(c) => c.arena(),
            Self::Partition(c) => Some(c.arena()),
        }
    }
    pub(super) fn source_group_seal(&self) -> Option<&crate::artifact_arena::ArtifactGroupSeal> {
        match self {
            Self::Dedicated(c) => c.source_group_seal(),
            Self::Partition(c) => Some(c.source_group_seal()),
        }
    }
    pub(super) fn native_group_seal(&self) -> Option<&crate::artifact_arena::ArtifactGroupSeal> {
        match self {
            Self::Dedicated(c) => c.native_group_seal(),
            Self::Partition(c) => Some(c.native_group_seal()),
        }
    }
    pub(super) fn inspection(&self) -> &crate::ntfs_inspect::PagedInspection {
        match self {
            Self::Dedicated(c) => c.inspection(),
            Self::Partition(c) => c.inspection(),
        }
    }
    pub(super) fn inspection_sha256(&self) -> &str {
        match self {
            Self::Dedicated(c) => c.inspection_sha256(),
            Self::Partition(c) => c.inspection_sha256(),
        }
    }
    pub(super) fn source_owner_identity(&self) -> usize {
        match self {
            Self::Dedicated(c) => c.source_owner_identity(),
            Self::Partition(c) => c.source_owner_identity(),
        }
    }
    pub(super) fn recheck_source(&mut self, events: &mut Vec<NativeEvent>) -> Result<()> {
        match self {
            Self::Dedicated(c) => c.recheck_source(events),
            Self::Partition(c) => c.recheck_source(events),
        }
    }
    pub(super) fn source_state(
        &mut self,
        pair: &n2r_win32::general_layout::GeneralSourceShadowBinding,
        events: &mut Vec<NativeEvent>,
    ) -> Result<SourceExclusionSnapshot> {
        match self {
            Self::Dedicated(c) => {
                let (source, _) = c.source_and_inspection()?;
                ensure!(
                    source.binding() == &pair.source,
                    "actual frozen source association differs"
                );
                Ok(SourceExclusionSnapshot::Dedicated(source.state(events)?))
            }
            Self::Partition(c) => {
                let token = c.owner_token();
                let (owner, admission, _) = c.source_admission_and_inspection();
                ensure!(
                    owner.binding().storage == pair.source
                        && token.same_owner(&owner.owner_token()),
                    "actual partition source association differs"
                );
                n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(
                    owner, admission,
                )?;
                owner.revalidate(events)?;
                Ok(SourceExclusionSnapshot::Partition(token))
            }
        }
    }
    pub(super) fn bytes(
        &mut self,
        admission: SourceResourceAdmission,
        maximum: u64,
    ) -> Result<PagedSourceByteAdapter<'_>> {
        match self {
            Self::Dedicated(c) => {
                let (source, raw) = c.source_and_inspection()?;
                PagedSourceByteAdapter::new(source, raw, admission, maximum)
            }
            Self::Partition(c) => PagedSourceByteAdapter::new_partition(c, admission, maximum),
        }
    }
    pub(super) fn derive_projection(
        &mut self,
        admission: SourceResourceAdmission,
        path: &Path,
        scratch: &SourceScratch,
    ) -> Result<crate::shadow_tree::source_pages::SourceExpectedDomain> {
        match self {
            Self::Dedicated(c) => c.derive_projection(
                admission,
                path,
                scratch,
            ),
            Self::Partition(c) => crate::shadow_tree::source_pages::SourceExpectedDomain::derive(
                c.inspection(),
                c.native().domain(),
                admission,
                path,
                scratch,
            ),
        }
    }
    pub(super) fn observe_target(
        &mut self,
        target: &mut GeneralFrozenPartition,
        pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
        input: &impl n2r_win32::shadow_native::input_domain::InputDomain,
        provider: &impl n2r_win32::layout_residual_pages::LayoutResidualProvider,
        path: &Path,
        budget: n2r_win32::metadata_pages::PageBudget,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        profile: Option<n2r_win32::attestation::ResourceProfile>,
        memory: &dyn n2r_win32::shadow_native::report_memory::ReportMemoryAccountant,
        aliases: Option<&n2r_win32::shadow_native::windows_aliases::VerifiedWindowsAliases>,
        events: &mut Vec<NativeEvent>,
    ) -> Result<(GeneralLiveRefsLayoutObservation,
        Option<n2r_win32::shadow_native::windows_aliases::ObservedWindowsAliases>)> {
        match self {
            Self::Dedicated(_) if aliases.is_some() => {
                let (native,proof)=target.observe_refs_layout_residuals_paged_domain_with_memory_windows_aliases(
                    pair,input,provider,path,budget,same_security,profile,memory,aliases.unwrap(),events,
                )?;
                Ok((native,Some(proof)))
            }
            Self::Dedicated(_) => Ok((target
                .observe_refs_layout_residuals_paged_domain_with_memory(
                    pair,
                    input,
                    provider,
                    path,
                    budget,
                    same_security,
                    profile,
                    memory,
                    events,
                )?,None)),
            Self::Partition(c) => {
                ensure!(aliases.is_none(),"Windows alias overlay cannot enter the ordinary shared-disk source path");
                let token = c.owner_token();
                let (owner, admission, _) = c.source_admission_and_inspection();
                let result = target
                    .observe_refs_layout_residuals_paged_domain_with_partition_source(
                        owner,
                        admission,
                        pair,
                        input,
                        provider,
                        path,
                        budget,
                        same_security,
                        profile,
                        memory,
                        events,
                    )?;
                result.require_partition_source_owner(&token)?;
                Ok((result,None))
            }
        }
    }
}
