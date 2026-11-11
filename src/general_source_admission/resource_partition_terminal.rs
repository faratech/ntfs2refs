//! Consuming ownership transfer after HND. No source fingerprint is reused.
use super::*;

impl PartitionResourceSourceContext {
    pub(crate) fn into_terminal_owners(self) -> (PartitionScopedOwner, PartitionNtfsAdmission) {
        let Self {
            source,
            native_admission,
            ..
        } = self;
        (source, native_admission)
    }
}
