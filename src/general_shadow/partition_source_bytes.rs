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
    /// Whether a capture's reads of the original may go ahead of it on a
    /// read lane of their own: a dedicated source inside its read scope, on
    /// a device that takes more than one read at once. A partition source
    /// is one volume of a disk that stays in use and gets none, and neither
    /// does a source held without a scope: its capture has an observer that
    /// reads through the owner.
    pub(crate) fn takes_read_lane(&self) -> bool {
        self.read_lane_depth() >= 2
    }
    /// How many reads the device of a source that [`Self::takes_read_lane`]
    /// takes at once (`IoProfile::queue_depth`); zero for one that does not.
    pub(crate) fn read_lane_depth(&self) -> usize {
        match self {
            Self::DedicatedScoped(scope) => scope.io_profile().queue_depth,
            Self::Dedicated(_) | Self::Partition { .. } => 0,
        }
    }
    /// `count` read lanes of the source, where [`Self::takes_read_lane`].
    /// What they read lies between the checks that bracket the scope, so
    /// they are to be dropped before the scope ends. A lane that cannot be
    /// opened is the scope's failure (the scope remembers it) and is
    /// returned as one: it is not a reason to read without a lane.
    pub(crate) fn read_lanes(
        &mut self,
        count: usize,
    ) -> io::Result<Vec<n2r_win32::GeneralFrozenLane>> {
        match self {
            Self::DedicatedScoped(scope) => scope.read_lanes(count, &mut Vec::new()),
            Self::Dedicated(_) | Self::Partition { .. } => Ok(Vec::new()),
        }
    }
    pub(super) fn validate(&mut self, before: Option<&n2r_win32::GeneralDiskState>) -> Result<()> {
        // A dedicated source is offline, read-only and held for the whole
        // run. Supply asks this several times for every 64 KiB it copies;
        // asking a few times a second still catches a change promptly.
        static PACED: n2r_win32::verify_policy::Paced = n2r_win32::verify_policy::Paced::new();
        if !matches!(self, Self::Partition { .. }) {
            if !PACED.due(250) {
                return Ok(());
            }
            let result = self.validate_now(before);
            if result.is_ok() {
                PACED.passed();
            }
            return result;
        }
        self.validate_now(before)
    }
    fn validate_now(&mut self, before: Option<&n2r_win32::GeneralDiskState>) -> Result<()> {
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
                ensure!(
                    scope.state(&mut Vec::new())? == *before && before.disk_attributes == 3,
                    "scoped original source identity or physical exclusion changed"
                );
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
            Self::DedicatedScoped(_) => {
                anyhow::bail!("byte-supply scope cannot issue a capture closing-source witness")
            }
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
        let session_ram = raw.lease_working_ram(super::SESSION_WORKSPACE)?;
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
            read_ahead: Vec::new(),
            read_ahead_from_source_lanes: false,
            mft_cache: None,
            plain: None,
            _session_ram: session_ram,
        })
    }
}
