//! Live staging-provider ownership for the confirmed drive conversion.
//! Location observations never supply formatting, source or replay authority.
use anyhow::Result;
use n2r_win32::{
    general_layout::GeneralDiskBinding,
    managed_shadow::{ManagedShadow, ShadowRetirementReceipt},
    volume_policy,
};
use serde::Serialize;
use serde_json::Value;

// No Deserialize, route-based constructor or Drop cleanup. The owner retains
// its original provider through conversion, including ordinary failure.
pub(crate) enum StageOwner {
    Vhdx(ManagedShadow),
}

impl StageOwner {
    pub(crate) fn staging_allocation_meter(
        &self,
    ) -> std::io::Result<Option<n2r_win32::managed_shadow::StagingAllocationMeter>> {
        match self {
            Self::Vhdx(owner) => owner.staging_allocation_meter().map(Some),
        }
    }

    pub(crate) fn binding(&self) -> &GeneralDiskBinding {
        match self {
            Self::Vhdx(owner) => &owner.binding,
        }
    }

    pub(crate) fn format_policy(&self) -> &volume_policy::Observation {
        match self {
            Self::Vhdx(owner) => owner.format_policy(),
        }
    }

    pub(crate) fn location(&self) -> Value {
        match self {
            // Preserve the original VHDX location schema and field values.
            Self::Vhdx(owner) => serde_json::json!({
                "schema_version": 1,
                "kind": "managed-native-shadow-location",
                "path": owner.path,
                "virtual_disk_id": owner.virtual_disk_id,
                "binding": owner.binding,
            }),
        }
    }

    pub(crate) fn initial_host_backing_commitment(&self) -> Result<u64> {
        match self {
            // Native VHDX uses a rolling, provider-quantum allowance. This is
            // pending operational growth, not the entire virtual disk size or
            // a claimed maximum for native metadata amplification.
            Self::Vhdx(owner) => Ok(n2r_win32::managed_shadow::BackingResourceGuard::new(
                owner.staging_allocation_meter()?,
                &owner.binding,
                0,
            )?
            .allocation_quantum_bytes()),
        }
    }

    /// A diagnose run's shadow was built only to be examined; nothing was
    /// published and nothing depends on it.
    pub(crate) fn retire_after_diagnose(self) -> RetirementReceipt {
        match self {
            Self::Vhdx(owner) => RetirementReceipt::Vhdx(owner.retire_unpublished()),
        }
    }

    /// Called only after live V4 HND/native finalization has succeeded and its
    /// construction/raw owners are closed. Failure never grants replay rights.
    pub(crate) fn retire_after_successful_v4(self) -> RetirementReceipt {
        match self {
            Self::Vhdx(owner) => RetirementReceipt::Vhdx(owner.retire_after_successful_v4()),
        }
    }
}

/// Serialize each concrete SDK receipt directly, without a wrapper or variant
/// tag. In particular, existing VHDX retirement JSON remains unchanged.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum RetirementReceipt {
    Vhdx(ShadowRetirementReceipt),
}

impl RetirementReceipt {
    pub(crate) fn success(&self) -> bool {
        match self {
            Self::Vhdx(receipt) => receipt.success,
        }
    }

    pub(crate) fn phase(&self) -> &str {
        match self {
            Self::Vhdx(receipt) => receipt.phase,
        }
    }

    pub(crate) fn error(&self) -> Option<&str> {
        match self {
            Self::Vhdx(receipt) => receipt.error.as_deref(),
        }
    }
}
