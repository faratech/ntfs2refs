//! Internal access scopes issued only by actual native exclusion owners.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadonlyRefsScope {
    DedicatedDisk,
    SelectedPartition,
}

/// The implementation retains the real protected volume. A snapshot must
/// revalidate that owner's native identity and actual protection before use.
/// This interface is private to the SDK; routing data cannot implement it.
pub(crate) trait ProtectedReadonlyRefsAccess {
    fn binding(&self) -> &GeneralDiskBinding;
    fn volume(&self) -> &File;
    fn scope(&self) -> ReadonlyRefsScope;
    fn partition_owner_token(&self) -> Option<&PartitionOwnerToken> {
        None
    }
    fn snapshot(
        &self,
        binding: &DiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionSnapshot>;
}

impl ProtectedReadonlyRefsAccess for GeneralReadonlyRefsVolume<'_> {
    fn binding(&self) -> &GeneralDiskBinding {
        GeneralReadonlyRefsVolume::binding(self)
    }
    fn volume(&self) -> &File {
        GeneralReadonlyRefsVolume::volume(self)
    }
    fn scope(&self) -> ReadonlyRefsScope {
        ReadonlyRefsScope::DedicatedDisk
    }
    fn snapshot(
        &self,
        binding: &DiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionSnapshot> {
        GeneralReadonlyRefsVolume::snapshot(self, binding, events)
    }
}
