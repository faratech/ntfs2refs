//! Explicit resource accounting for selected capture. This policy never grants
//! source admission, raw writes, journal replay or permission to skip bytes.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedCapacityPolicy {
    /// Historical admission charges every selected old byte to journal space.
    #[default]
    ConservativeV1,
    /// Charge only stored old bytes after actual whole-range zero observation.
    /// The caller must bind this intent to CapacityPinnedV3 and the actual
    /// admitted source; preparation still checks every declared old-zero byte.
    OldZeroActualBytesV1,
    /// Preserve every selected NTFS allocation and COPY source, but leave
    /// proven-free destinations unrestored on rollback. Their actual old
    /// 4 KiB hashes remain in the journal for foreign-write detection.
    /// This requires fresh frozen allocation evidence and VSS admission.
    SourceFreeActualBytesV1,
}

impl SelectedCapacityPolicy {
    pub fn is_conservative(&self) -> bool {
        matches!(self, Self::ConservativeV1)
    }

    pub fn allows_source_free(&self) -> bool {
        matches!(self, Self::SourceFreeActualBytesV1)
    }
}
