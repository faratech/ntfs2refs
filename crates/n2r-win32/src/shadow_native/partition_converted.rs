//! Converted metadata under an actual target-only read-only lifecycle window.
use super::*;

/// Issued only after the shared native metadata/fidelity engine succeeds on
/// the actual protected partition. The report remains diagnostic; this owner
/// is separately tied to the live native restoration token and binding.
pub struct PartitionReadonlyFidelity {
    owner: native::PartitionOwnerToken,
    binding: GeneralDiskBinding,
    observed_label: crate::volume_label::VolumeLabel,
    report: GeneralConvertedReport,
}
impl PartitionReadonlyFidelity {
    pub fn report(&self) -> &GeneralConvertedReport {
        &self.report
    }
    pub fn filesystem(&self) -> &'static str {
        "ReFS"
    }
    pub fn observed_label(&self) -> &crate::volume_label::VolumeLabel {
        &self.observed_label
    }
    pub(crate) fn require_owner(
        &self,
        owner: &native::PartitionOwnerToken,
        binding: &GeneralDiskBinding,
    ) -> io::Result<()> {
        if !self.owner.same_owner(owner) || &self.binding != binding {
            return Err(invalid(
                "partition fidelity belongs to another actual restoration owner",
            ));
        }
        Ok(())
    }
}

fn actual_label(file: &File) -> io::Result<crate::volume_label::VolumeLabel> {
    let mut units = [0u16; 128];
    let mut filesystem = [0u16; 32];
    let (mut serial, mut component, mut flags) = (0, 0, 0);
    // SAFETY: the actual held protected volume and fixed initialized buffers
    // stay live for this read-only native query.
    check(unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            units.as_mut_ptr(),
            units.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    })?;
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("partition volume label is unterminated"))?;
    crate::volume_label::VolumeLabel::from_utf16(units[..end].to_vec())
}

pub(crate) fn observe_partition_converted_readonly_with_memory(
    protected: &dyn native::ProtectedReadonlyRefsAccess,
    pair: GeneralSourceShadowBinding,
    input: &impl InputDomain,
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: crate::attestation::ResourceProfile,
    memory: &dyn report_memory::ReportMemoryAccountant,
    verify_known_contents: bool,
) -> io::Result<PartitionReadonlyFidelity> {
    if protected.scope() != native::ReadonlyRefsScope::SelectedPartition
        || protected.binding() != &pair.source
    {
        return Err(invalid(
            "actual selected-partition read-only observation required",
        ));
    }
    let owner = protected
        .partition_owner_token()
        .ok_or_else(|| invalid("partition read-only observation lost actual owner token"))?
        .clone();
    let admission = resource_profile
        .resource_admission()?
        .ok_or_else(|| invalid("partition converted metadata requires resource-bound input"))?;
    input.require_resource_metadata(admission)?;
    let binding = pair.source.clone();
    let observed_label = actual_label(protected.volume())?;
    let report = observe_general_converted_metadata_domain_accounted(
        pair,
        input,
        expected_label,
        &same_security,
        Some(resource_profile),
        Some(memory),
        Some(protected),
    )?;
    let report = if verify_known_contents {
        known_content_memory::verify_known_contents_in_accounted_report_with_lease(
            report,
            input,
            admission,
            memory,
            &same_security,
            Some(protected),
        )?
    } else {
        report
    };
    let disk = DiskBinding {
        disk_number: binding.disk_number,
        volume_guid: binding.volume_guid.clone(),
        identity: binding.identity.clone(),
    };
    let closing = protected.snapshot(&disk, &mut Vec::new())?;
    let after = &report.native.after;
    if closing.binding != after.binding
        || closing.disk_attributes != after.disk_attributes
        || closing.device != after.device
        || closing.length != after.length
        || closing.alignment != after.alignment
        || closing.layout != after.layout
        || actual_label(protected.volume())? != observed_label
        || !protected
            .partition_owner_token()
            .is_some_and(|token| token.same_owner(&owner))
    {
        return Err(invalid(
            "actual partition changed after native converted fidelity",
        ));
    }
    Ok(PartitionReadonlyFidelity {
        owner,
        binding,
        observed_label,
        report,
    })
}
