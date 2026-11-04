//! Source-partition wrapper around the unchanged dedicated shadow3/2/3 lease.
//! Every GeneralDiskState in the result belongs to the TARGET. The original
//! private source is a separate actual same-FileObject/token witness.
use super::*;
impl GeneralLiveRefsLayoutObservation {
    pub fn require_partition_source_owner(&self, token: &PartitionOwnerToken) -> io::Result<()> {
        self.report.require_partition_source_owner(token)
    }
}
impl GeneralFrozenPartition {
    pub fn observe_refs_layout_residuals_paged_domain_with_partition_source(
        &mut self,
        source: &mut PartitionScopedOwner,
        admission: &partition_lifecycle::PartitionNtfsAdmission,
        pair: crate::general_layout::GeneralSourceShadowBinding,
        input: &impl crate::shadow_native::input_domain::InputDomain,
        provider: &impl crate::layout_residual_pages::LayoutResidualProvider,
        result_path: &std::path::Path,
        result_budget: crate::metadata_pages::PageBudget,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        resource_profile: Option<crate::attestation::ResourceProfile>,
        memory: &dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLiveRefsLayoutObservation> {
        pair.validate_with_resource_profile(resource_profile)?;
        if source.binding().storage != pair.source || self.binding() != &pair.shadow {
            return Err(invalid("partition-source target observer binding differs"));
        }
        partition_lifecycle::require_complete_fresh_ntfs_admission(source, admission)?;
        source.revalidate(events)?;
        let token = source.owner_token();
        let paid = memory.reserve(source.construction_metadata_memory_bytes())?;
        let witness = source
            .construction_metadata_witness(admission, events)?
            .retain_memory(paid);
        witness.require_profile(resource_profile.ok_or_else(|| {
            invalid("partition target observation requires actual resource profile")
        })?)?;
        let observed = self.observe_refs_layout_residuals_paged_domain_with_memory(
            pair,
            input,
            provider,
            result_path,
            result_budget,
            same_security,
            resource_profile,
            memory,
            events,
        );
        // Closing source checks run even when native target observation failed.
        let closing = source.revalidate(events);
        let mut observed = match (observed, closing) {
            (Ok(report), Ok(())) => report,
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        witness.require_owner(&token)?;
        witness.revalidate(events)?;
        observed.report.bind_partition_source(witness)?;
        observed.require_partition_source_owner(&token)?;
        Ok(observed)
    }
}
