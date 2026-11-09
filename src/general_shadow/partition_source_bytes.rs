//! Borrowed actual source readers for paged supply/capture. No writer, saved
//! binding constructor or fabricated whole-disk state is exposed.
use super::*;
use n2r_win32::{
    PartitionOwnerToken, PartitionScopedOwner, partition_lifecycle::PartitionNtfsAdmission,
};

pub(crate) enum BorrowedPagedSource<'a, 'scope> {
    Dedicated(&'a mut GeneralFrozenPartition),
    DedicatedScoped(&'a mut n2r_win32::GeneralFrozenSourceReadScope<'scope>),
    Partition {
        owner: &'a mut PartitionScopedOwner,
        admission: &'a PartitionNtfsAdmission,
        token: PartitionOwnerToken,
        identity: usize,
    },
}
impl BorrowedPagedSource<'_, '_> {
    pub(super) fn binding(&self) -> &n2r_win32::general_layout::GeneralDiskBinding {
        match self {
            Self::Dedicated(owner) => owner.binding(),
            Self::DedicatedScoped(scope) => scope.binding(),
            Self::Partition { owner, .. } => &owner.binding().storage,
        }
    }
    pub(super) fn byte_len(&self) -> u64 {
        match self {
            Self::Dedicated(owner) => owner.byte_len(),
            Self::DedicatedScoped(scope) => scope.byte_len(),
            Self::Partition { owner, .. } => owner.byte_len(),
        }
    }
    pub(super) fn owner_identity(&self) -> usize {
        match self {
            Self::Dedicated(owner) => std::ptr::from_ref(&**owner) as usize,
            Self::DedicatedScoped(scope) => scope.original_owner_identity(),
            Self::Partition { identity, .. } => *identity,
        }
    }
    pub(super) fn validate(&mut self, before: Option<&n2r_win32::GeneralDiskState>) -> Result<()> {
        match self {
            Self::Dedicated(owner) => {
                let before = before.context("original dedicated state absent")?;
                ensure!(
                    owner.state(&mut Vec::new())? == *before && before.disk_attributes == 3,
                    "original source identity or physical exclusion changed"
                );
                Ok(())
            }
            Self::DedicatedScoped(scope) => {
                let before = before.context("original scoped state absent")?;
                ensure!(scope.state(&mut Vec::new())? == *before && before.disk_attributes == 3,
                    "scoped original source identity or physical exclusion changed");
                Ok(())
            }
            Self::Partition {
                owner,
                admission,
                token,
                ..
            } => {
                ensure!(
                    before.is_none() && token.same_owner(&owner.owner_token()),
                    "partition source owner/scope changed"
                );
                n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(
                    owner, admission,
                )?;
                owner.revalidate(&mut Vec::new())?;
                Ok(())
            }
        }
    }
    pub(crate) fn observe_closing(
        &mut self,
        observer: &mut dyn ClosingSourceBytes,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        match self {
            Self::Dedicated(owner) => observer.observe_original(owner, offset, bytes),
            Self::DedicatedScoped(_) => anyhow::bail!(
                "byte-supply scope cannot issue a capture closing-source witness"
            ),
            Self::Partition { .. } => anyhow::bail!(
                "legacy whole-disk closing observer cannot authorize a partition source; V4 OLD/COPY closure remains required"
            ),
        }
    }
}
impl Read for BorrowedPagedSource<'_, '_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Dedicated(owner) => owner.read(b),
            Self::DedicatedScoped(scope) => scope.read(b),
            Self::Partition { owner, .. } => owner.read(b),
        }
    }
}
impl Seek for BorrowedPagedSource<'_, '_> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Dedicated(owner) => owner.seek(p),
            Self::DedicatedScoped(scope) => scope.seek(p),
            Self::Partition { owner, .. } => owner.seek(p),
        }
    }
}

impl<'a> PagedSourceByteAdapter<'a> {
    pub(crate) fn new_partition(
        context:&'a mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        maximum_logical_reads: u64,
    ) -> Result<Self> {
        use crate::ntfs_inspect::RootFileDomain;
        use n2r_win32::attestation::NativeObservationDomain;
        let identity = context.source_owner_identity();
        let token = context.owner_token();
        let (owner, native, raw) = context.source_admission_and_inspection();
        n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(owner, native)?;
        owner.revalidate(&mut Vec::new())?;
        admission.validate()?;
        raw.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        let pin = raw.canonical_sha256()?;
        let digest: [u8; 32] = hex::decode(&pin)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("source pin length differs"))?;
        ensure!(
            digest == admission.source_inspection_sha256
                && native
                    .native()
                    .domain()
                    .header()
                    .request
                    .source_inspection_sha256
                    == pin
                && raw.file_count() == admission.raw_identities
                && raw.header().mft_record_count == admission.mft_records
                && (raw.header().geometry.volume_size == owner.byte_len()
                    || raw
                        .header()
                        .geometry
                        .volume_size
                        .checked_add(u64::from(raw.header().geometry.bytes_per_sector))
                        == Some(owner.byte_len())),
            "actual partition source differs from complete raw/native resource owner"
        );
        let session_ram = raw.lease_working_ram(
            admission
                .budget
                .max_row_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(2 * 16 * 4096))
                .context("paged DATA session RAM overflow")?,
        )?;
        Ok(Self {
            source: BorrowedPagedSource::Partition {
                owner,
                admission: native,
                token,
                identity,
            },
            raw,
            admission,
            before: None,
            budget: crate::ntfs_inspect::StreamTransferBudget::new(
                i64::MAX as u64,
                maximum_logical_reads,
            )?,
            session: None,
            sequence: None,
            allow_sparse: None,
            logical_bytes: 0,
            poisoned: false,
            _session_ram: session_ram,
        })
    }
}
