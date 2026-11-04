//! Native fidelity entry tied to the actual terminal read-only volume borrow.
use super::{NativeEvent, PartitionTerminalNativeObservation};
use crate::{
    general_layout::GeneralSourceShadowBinding,
    native::partition_restoration::PartitionTerminalReadonlyVolume,
    shadow_native::{input_domain::InputDomain, report_memory::ReportMemoryAccountant},
};
use std::io;

impl PartitionTerminalReadonlyVolume<'_, '_, '_> {
    /// Observe every supported metadata object and complete stream mapping.
    /// Known logical hashes can be checked in the same protected mount; unknown
    /// retained payload still requires the caller's actual saved map proof.
    pub fn observe_converted_metadata_with_memory(
        &self,
        pair: GeneralSourceShadowBinding,
        input: &impl InputDomain,
        expected_label: Option<&crate::volume_label::VolumeLabel>,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        profile: crate::attestation::ResourceProfile,
        memory: &dyn ReportMemoryAccountant,
        verify_known_contents: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionTerminalNativeObservation> {
        self.require_readonly(events)?;
        let result = crate::shadow_native::observe_partition_converted_readonly_with_memory(
            self, pair, input, expected_label, same_security, profile, memory,
            verify_known_contents,
        );
        let closing = self.require_readonly(events);
        match (result, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}
