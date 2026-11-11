//! Actual offline-owner readonly fidelity; no fabricated partition owner token.
use super::*;
use crate::offline_environment::{OfflineSourceOwnerToken, OfflineTerminalReadonlyVolume};
pub struct OfflineReadonlyFidelity {
    owner: OfflineSourceOwnerToken,
    binding: GeneralDiskBinding,
    label: crate::volume_label::VolumeLabel,
    report: GeneralConvertedReport,
}
impl OfflineReadonlyFidelity {
    pub fn owner_token(&self) -> OfflineSourceOwnerToken {
        self.owner.clone()
    }
    pub fn report(&self) -> &GeneralConvertedReport {
        &self.report
    }
    pub fn observed_label(&self) -> &crate::volume_label::VolumeLabel {
        &self.label
    }
    pub(crate) fn require_owner(
        &self,
        owner: &OfflineSourceOwnerToken,
        binding: &GeneralDiskBinding,
    ) -> io::Result<()> {
        if !self.owner.same_owner(owner) || &self.binding != binding {
            return Err(invalid(
                "offline fidelity belongs to another actual terminal owner",
            ));
        }
        Ok(())
    }
}
pub(crate) fn observe_offline_converted_readonly(
    protected: &OfflineTerminalReadonlyVolume<'_, '_, '_>,
    pair: GeneralSourceShadowBinding,
    input: &impl InputDomain,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    profile: crate::attestation::ResourceProfile,
    memory: &dyn report_memory::ReportMemoryAccountant,
) -> io::Result<OfflineReadonlyFidelity> {
    let admission = profile
        .resource_admission()?
        .ok_or_else(|| invalid("offline terminal requires actual bounded metadata owner"))?;
    input.require_resource_metadata(admission)?;
    if protected.binding() != &pair.source {
        return Err(invalid("offline mounted source binding differs"));
    }
    let owner = protected.owner_token();
    let label = protected.label()?;
    let report = observe_general_converted_metadata_domain_accounted(
        pair,
        input,
        None,
        &same_security,
        Some(profile),
        Some(memory),
        Some(protected),
    )?;
    let report = known_content_memory::verify_known_contents_in_accounted_report_with_lease(
        report,
        input,
        admission,
        memory,
        &same_security,
        Some(protected),
    )?;
    let mut events = Vec::new();
    protected.require_readonly(&mut events)?;
    // Protected snapshot itself durably drains native events through real source sink.
    if protected.label()? != label {
        return Err(invalid("offline readonly observed label changed"));
    }
    Ok(OfflineReadonlyFidelity {
        owner,
        binding: protected.binding().clone(),
        label,
        report,
    })
}
