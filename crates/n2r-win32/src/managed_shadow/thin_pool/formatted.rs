//! Consuming native formatting on the original live private thin owner only.
use super::*;

#[derive(Debug, Serialize)]
pub struct FormattingObservation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub backing_profile: &'static str,
    pub target_format: TargetFormatProfile,
    pub binding: GeneralDiskBinding,
    pub provider_requested_bytes_at_constructor: u64,
    pub provider_actual_bytes: u64,
    pub nominal_member_virtual_bytes_total: u64,
    pub nominal_member_size_was_clamped: bool,
    pub logical_bytes_exceed_nominal_members: bool,
    pub provider_pool_capacity_scope: &'static str,
    pub constructor_observation_is_pre_format: bool,
    pub bounded_carrier_before_gpt: Option<CarrierObservation>,
    pub bounded_carrier_after_formatter: Option<CarrierObservation>,
    pub host_allocation_excludes_nested_member_files: bool,
    pub pool_before_gpt: PoolCapacity,
    pub pool_before_formatter: PoolCapacity,
    pub pool_after_formatter: PoolCapacity,
    pub refs_volume_data: Vec<u8>,
    pub retained_regular_file_allocation_bytes: u64,
    pub allocation_sample_precedes_this_observation_receipt: bool,
    pub available_resources: resource_native::AvailableResources,
    pub budget: Budget,
    pub target_cluster_bytes: u32,
    pub source_binding_supplied: bool,
    pub conversion_authorized: bool,
    pub public_backend_or_recovery_qualified: bool,
    pub automatic_cleanup_or_fallback: bool,
    pub sampled_capacity_is_not_a_kernel_quota_or_reservation: bool,
    pub formatter_process_memory_hard_limit_enforced: bool,
}

/// Holds the actual pool, member/provider/backing/root owners through all native
/// use. Neither this type nor ThinPool can be deserialized or route-constructed.
pub struct FormattedThinShadow {
    _owner: ThinPool,
    binding: GeneralDiskBinding,
    policy: crate::volume_policy::Observation,
    observation: FormattingObservation,
}

impl FormattedThinShadow {
    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }
    pub fn format_policy(&self) -> &crate::volume_policy::Observation {
        &self.policy
    }
    pub fn observation(&self) -> &FormattingObservation {
        &self.observation
    }
}

impl ThinPool {
    /// Initialize/format only the exact disk created by this live owner. No
    /// caller-selected disk, saved route, source or pre-existing pool is taken.
    /// All partial GPT/formatter failures preserve every created asset.
    pub fn format(
        self,
        partition_bytes: u64,
        target_format: TargetFormatProfile,
    ) -> io::Result<FormattedThinShadow> {
        // Representation/geometry and resources must pass before any GPT write.
        validate_owned_partition(&self, partition_bytes)?;
        self.verify_live()?;
        let before = self.observe_stage("format-opening", None)?;
        let carrier_before = self
            .carrier
            .as_ref()
            .map(|c| c.observe(self.budget))
            .transpose()?;
        let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
        let path = self.root.join("thin-shadow");
        let mut current_binding = None;
        let operation: io::Result<_> = (|| {
            // The WRITE-capable device owner was acquired by create_new while
            // its freshly-created provider association was still held. It is
            // retained across GPT, formatting, discovery and all closing checks.
            let binding = initialize_new_owned(&self, &self._disk, partition_bytes)?;
            let binding = rediscover_stage(binding, &path, "partition-volume")?;
            current_binding = Some(binding.clone());
            let partitioned = self.observe_stage("partitioned", Some(&binding))?;
            let (binding, policy, refs_volume_data) =
                format_new_owned(&self, binding, &path, target_format)?;
            current_binding = Some(binding.clone());
            let after = self.observe_stage("formatted", Some(&binding))?;
            let actual = native_disk(&self._disk, self.pool.number, self.pool.bytes)?;
            binding.validate_layout(&actual.layout)?;
            binding.validate_alignment(&actual.alignment)?;
            self.verify_live()?;
            let (allocated, available) = capacity(&self.root, self.budget)?;
            let carrier_after = self
                .carrier
                .as_ref()
                .map(|c| c.observe(self.budget))
                .transpose()?;
            Ok((
                binding,
                policy,
                refs_volume_data,
                partitioned,
                after,
                allocated,
                available,
                carrier_after,
            ))
        })();
        let (
            binding,
            policy,
            refs_volume_data,
            partitioned,
            after,
            allocated,
            available,
            carrier_after,
        ) = match operation {
            Ok(value) => value,
            Err(error) => {
                // Read-only closing is attempted even after a partial native
                // mutation. Unknown GPT state grants no owner or retry; retain
                // all assets and report both errors if closing also refuses.
                let closing = self.observe_stage("format-error", current_binding.as_ref());
                return match closing {
                    Ok(_) => Err(error),
                    Err(closing) => Err(io::Error::other(format!(
                        "{error}; private thin format closing also failed: {closing}; all assets preserved"
                    ))),
                };
            }
        };
        privileges.restore()?;
        let observation = FormattingObservation {
            schema_version: 1,
            kind: "live-private-thin-native-formatted-shadow",
            backing_profile: self.observation.backing_profile,
            target_format,
            binding: binding.clone(),
            provider_requested_bytes_at_constructor: self.goal,
            provider_actual_bytes: self.pool.bytes,
            nominal_member_virtual_bytes_total: self.observation.nominal_member_virtual_bytes_total,
            nominal_member_size_was_clamped: self.observation.nominal_member_size_was_clamped,
            logical_bytes_exceed_nominal_members: self
                .observation
                .logical_bytes_exceed_nominal_members,
            provider_pool_capacity_scope: POOL_CAPACITY_SCOPE,
            constructor_observation_is_pre_format: true,
            bounded_carrier_before_gpt: carrier_before,
            bounded_carrier_after_formatter: carrier_after,
            host_allocation_excludes_nested_member_files: self.carrier.is_some(),
            pool_before_gpt: before,
            pool_before_formatter: partitioned,
            pool_after_formatter: after,
            refs_volume_data,
            retained_regular_file_allocation_bytes: allocated,
            allocation_sample_precedes_this_observation_receipt: true,
            available_resources: available,
            budget: self.budget,
            target_cluster_bytes: 4096,
            source_binding_supplied: false,
            conversion_authorized: false,
            public_backend_or_recovery_qualified: false,
            automatic_cleanup_or_fallback: false,
            sampled_capacity_is_not_a_kernel_quota_or_reservation: true,
            formatter_process_memory_hard_limit_enforced: false,
        };
        let _receipt = save(
            &self.root.join("thin-formatted-observation.json"),
            &observation,
        )?;
        Ok(FormattedThinShadow {
            _owner: self,
            binding,
            policy,
            observation,
        })
    }
}
