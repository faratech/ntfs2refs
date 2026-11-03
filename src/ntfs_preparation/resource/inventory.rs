use crate::{
    artifact_arena::{ArenaRamLease, ArtifactArena, ArtifactGroup, ArtifactGroupSeal},
    ntfs_inspect::{
        self, PagedInspection, RootFileDomain, SourceMetadataBudget,
        paged_storage::SourceScratch,
        record_store::{SortedRecordStore, SortedRecordWriter},
    },
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralPartitionReader, NativeEvent, general_layout::GeneralDiskBinding,
    tree_resources::ResourceBudget,
};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// An actual online read-only lane plus a fully reconciled immutable page set.
/// No accessor returns this as a conversion/admission context. Online writes
/// can invalidate hints; the later native mover independently checks every move.
pub(crate) struct PreparationInventory {
    pub(super) source: GeneralDiskBinding,
    pub(super) raw: PagedInspection,
    reader: GeneralPartitionReader,
    before: GeneralDiskState,
    after: GeneralDiskState,
    metadata_sha256: String,
    evidence: SortedRecordStore,
    pub(super) scratch: SourceScratch,
    pub(super) seal: ArtifactGroupSeal,
    _directory: File,
    _memory: ArenaRamLease,
}
#[derive(Serialize)]
struct Facts<'a> {
    schema_version: u32,
    kind: &'static str,
    source: &'a GeneralDiskBinding,
    before: &'a GeneralDiskState,
    after: &'a GeneralDiskState,
    inventory: &'a ntfs_inspect::SourceInspectionPin,
    metadata_sha256: &'a str,
    vss: &'a n2r_win32::vss_observation::Observation,
    logical_payload_reads_may_have_occurred: bool,
    preparation_only: bool,
    source_admission_granted: bool,
}
impl PreparationInventory {
    pub(crate) fn collect(
        source: GeneralDiskBinding,
        resources: ResourceBudget,
        output: &Path,
        arena: &ArtifactArena,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        resources.validate()?;
        source.validate()?;
        ensure!(
            arena.budget() == resources,
            "prealignment arena resource contract differs"
        );
        ensure!(
            !arena
                .volume_guid_path()?
                .eq_ignore_ascii_case(&source.volume_path()?),
            "prealignment evidence cannot be stored on the source"
        );
        let parent = output
            .parent()
            .context("prealignment inventory parent absent")?;
        let parent_handle = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(1)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(parent)?;
        arena.require_root_directory(&parent_handle)?;
        ensure!(
            !output.exists(),
            "fresh prealignment inventory output required"
        );
        fs::create_dir(output)?;
        let directory = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(1)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(output)?;
        ensure!(
            directory.metadata()?.is_dir() && directory.metadata()?.file_attributes() & 0x400 == 0,
            "prealignment inventory directory is not ordinary"
        );
        let memory = arena.reserve_ram(32 * 1024 * 1024)?;
        let root = format!("{}\\", source.volume_path()?);
        let discovered = n2r_win32::discovery::discover(&root, n2r_win32::discovery::Role::Source)?;
        ensure!(
            discovered.binding == source
                && discovered.filesystem == "NTFS"
                && discovered.source_write_requests == 0,
            "actual online NTFS source route differs"
        );
        let before = n2r_win32::observe_general_disk_state_readonly(source.clone(), events)?;
        ensure!(
            before.disk_attributes == 0,
            "NTFS preparation requires an online writable authoritative filesystem"
        );
        let native_query_ram = arena.reserve_ram(
            resources
                .max_row_bytes
                .checked_mul(4)
                .context("prealignment catalog workspace overflow")?,
        )?;
        let catalog = n2r_win32::vss_observation::observe_catalog(&root)?;
        catalog.require_observed_catalog_clear()?;
        let group = arena.reserve_group(
            ArtifactGroup::Source,
            SourceMetadataBudget::from_resource_budget(resources)?.scratch_bytes,
        )?;
        let scratch = SourceScratch::new_in_arena(
            SourceMetadataBudget::from_resource_budget(resources)?,
            group,
        )?;
        let mut reader = GeneralPartitionReader::open(source.clone(), events)?;
        let raw = ntfs_inspect::inspect_paged_with_scratch(
            &mut reader,
            source.identity.partition_bytes,
            resources,
            VerificationPolicy::ExtentIdentityV1,
            &output.join("raw"),
            &scratch,
        )?;
        ensure!(
            raw.header().inventory_complete
                && raw.header().geometry.serial_number as u32 == discovered.volume_serial_low32
                && raw.allocation().status
                    == ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel,
            "prealignment requires complete reconciled MFT and allocation ownership"
        );
        raw.revalidate()?;
        let probe = reader.revalidate_route(events)?;
        ensure!(
            probe.binding == source && probe.read_only_probe && probe.source_write_requests == 0,
            "online read-only inventory lane changed"
        );
        let after = n2r_win32::observe_general_disk_state_readonly(source.clone(), events)?;
        ensure!(
            after == before && after.disk_attributes == 0,
            "source route/state changed during planning inventory"
        );
        let metadata_sha256 = raw.canonical_sha256()?;
        let mut evidence =
            SortedRecordWriter::new(&output.join("inventory-facts"), *b"N2RPRIV1", &scratch)?;
        evidence.push(
            [0; 16],
            &Facts {
                schema_version: 1,
                kind: "preparation-only-paged-ntfs-inventory",
                source: &source,
                before: &before,
                after: &after,
                inventory: raw.pin(),
                metadata_sha256: &metadata_sha256,
                vss: &catalog,
                logical_payload_reads_may_have_occurred: true,
                preparation_only: true,
                source_admission_granted: false,
            },
        )?;
        let pin = evidence.finish()?;
        let evidence = SortedRecordStore::open(&pin, &scratch)?;
        drop(catalog);
        drop(native_query_ram);
        let seal = scratch.seal()?;
        Ok(Self {
            source,
            raw,
            reader,
            before,
            after,
            metadata_sha256,
            evidence,
            scratch,
            seal,
            _directory: directory,
            _memory: memory,
        })
    }
    pub(crate) fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }
    pub(crate) fn source(&self) -> &GeneralDiskBinding {
        &self.source
    }
    pub(crate) fn file_count(&self) -> u64 {
        self.raw.file_count()
    }
    pub(crate) fn revalidate(&self, events: &mut Vec<NativeEvent>) -> Result<()> {
        self.raw.revalidate()?;
        self.evidence.revalidate()?;
        self.seal.revalidate()?;
        let probe = self.reader.revalidate_route(events)?;
        ensure!(
            probe.binding == self.source
                && probe.read_only_probe
                && probe.source_write_requests == 0,
            "preparation read lane route changed"
        );
        let now = n2r_win32::observe_general_disk_state_readonly(self.source.clone(), events)?;
        ensure!(
            now == self.before && now == self.after && now.disk_attributes == 0,
            "preparation hint source is no longer online on the same route"
        );
        Ok(())
    }
}
