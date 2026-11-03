//! Actual paged source preparation and live-source evidence. This owns the
//! frozen reader and native witnesses; serialized results cannot recreate it.
//! V4 activation remains refused until the cross-stage artifact arena and
//! actual same-tree target preservation are supplied by their owning paths.
use crate::artifact_arena::{
    ArenaRamLease, ArtifactArena, ArtifactGroup, ArtifactGroupPermit, ArtifactGroupSeal,
    ArtifactLease,
};
use crate::{
    ntfs_admission::{self, Gate, InternalReplacement},
    ntfs_attestation::paged::{
        PagedComparisonSummary, PagedFileComparison, PagedObservationRequest, compare_domain,
    },
    ntfs_backup,
    ntfs_inspect::{
        self, PagedInspection, RootFileDomain, SourceMetadataBudget,
        paged_storage::{SourceRamLease, SourceScratch, SourceTemporaryLease},
        record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
    },
    ntfs_internal, ntfs_log, ntfs_transactions,
    source_fingerprint::resource::{self as fp, InspectionReadCoverage, PagedSourceFingerprint},
    source_volume_label,
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, GeneralLivePagedNtfsObservation,
    MountPathObservation, NativeEvent,
    attestation::NativeObservationDomain,
    general_layout::GeneralDiskBinding,
    tree_resources::{ResourceBudget, SourceResourceAdmission},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Serialize)]
struct MetadataPin {
    path: PathBuf,
    bytes: u64,
    sha256: String,
    #[serde(skip)]
    held: File,
    #[serde(skip)]
    arena_lease: Option<ArtifactLease>,
}
#[derive(Serialize)]
struct ObjectRow {
    native: PagedFileComparison,
    user_issues: Vec<String>,
    independent_internal_state_checks_passed: bool,
}
#[derive(Serialize)]
pub struct ResourceSourceReport<'a> {
    pub kind: &'static str,
    pub binding: &'a GeneralDiskBinding,
    pub budget: ResourceBudget,
    pub resource_admission: SourceResourceAdmission,
    pub policy: VerificationPolicy,
    pub source_inspection_sha256: &'a str,
    pub source_sha256: &'a str,
    pub source_fingerprint_kind: &'static str,
    pub source_views_sha256: &'a str,
    pub frozen_before: &'a GeneralDiskState,
    pub frozen_after: &'a GeneralDiskState,
    pub comparison: &'a PagedComparisonSummary,
    pub comparison_rows: &'a RecordStorePin,
    pub unresolved_blockers: &'a RecordStorePin,
    pub internal_replacements: &'a RecordStorePin,
    pub gates: &'a [Gate],
    pub source_group_bytes: u64,
    pub source_native_groups_sealed: bool,
    pub source_group_allocated_bytes: Option<u64>,
    pub native_group_allocated_bytes: Option<u64>,
    pub shared_artifact_arena_complete: bool,
    pub target_preservation_complete: bool,
    pub source_admitted: bool,
    pub certificate_issued: bool,
    pub execution_authorized: bool,
}
pub struct ResourceSourceContext {
    source: GeneralFrozenPartition,
    raw: PagedInspection,
    native: GeneralLivePagedNtfsObservation,
    fingerprint: PagedSourceFingerprint,
    read_coverage: InspectionReadCoverage,
    backups: ntfs_backup::VerifiedBackups,
    log: ntfs_log::VerifiedRestart,
    indexes: ntfs_internal::PagedVerifiedIndexes,
    transactions: ntfs_transactions::VerifiedTransactions,
    label: n2r_win32::volume_label::SourceLabel,
    label_frozen: source_volume_label::FrozenLabelProof,
    mount_paths: MountPathObservation,
    vss_before: n2r_win32::vss_observation::Observation,
    comparison: PagedComparisonSummary,
    rows: SortedRecordStore,
    unresolved: SortedRecordStore,
    replacements: SortedRecordStore,
    admission: SourceResourceAdmission,
    policy: VerificationPolicy,
    before: GeneralDiskState,
    after: GeneralDiskState,
    inspection_sha: String,
    source_sha: String,
    source_views_sha: String,
    gates: Vec<Gate>,
    scratch: SourceScratch,
    _metadata: Vec<MetadataPin>,
    _metadata_reservations: Vec<SourceTemporaryLease>,
    arena: Option<ArtifactArena>,
    source_seal: Option<ArtifactGroupSeal>,
    native_seal: Option<ArtifactGroupSeal>,
    native_artifact: Option<ArtifactLease>,
    // The Arc accountant payload is prepaid before constructing it and drops
    // after the paged native owner that retains that accountant.
    _native_payer_ram: Option<SourceRamLease>,
    // Both the temporary online reader and retained frozen source use this
    // one prepaid SDK buffer. The physical source owner drops first.
    _source_io_ram: SourceRamLease,
    _output_basis: Option<ArenaOutputBasis>,
}

/// Original live source admission closed against the actual protected target
/// and exhaustive prepared arena. This is intentionally neither serializable
/// nor Clone. It has no constructor accepting persisted hashes or flags, and
/// it cannot open a writer without the still-owned prepared journal.
pub(crate) struct PreparedResourceSourceAdmission {
    source_owner: usize,
    admission: SourceResourceAdmission,
    source_sha256: [u8; 32],
    inspection_sha256: [u8; 32],
    expected_sha256: [u8; 32],
    target_scope: Arc<crate::general_composite_target::paged::CaptureScopeIdentity>,
    expected: ArtifactLease,
    source: ArtifactGroupSeal,
    native: ArtifactGroupSeal,
    arena: ArtifactArena,
    _memory: ArenaRamLease,
}

fn source_admission_digest(value: &str) -> Result<[u8; 32]> {
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("source admission requires a complete SHA-256 pin"))?)
}

impl PreparedResourceSourceAdmission {
    /// Runtime owner checks only; the caller must also recheck the source,
    /// protected target and journal at the immediate activation boundary.
    pub(crate) fn require_binding(
        &self,
        context: &ResourceSourceContext,
        target: &crate::general_composite_target::paged::ProtectedPagedTargetSelection,
        expected: &crate::shadow_tree::PagedExpectedTree,
        closure: &crate::artifact_arena::PreparedArenaClosure,
    ) -> Result<()> {
        ensure!(
            self.source_owner == context.source_owner_identity()
                && self.admission == context.admission
                && self.arena.same_arena(closure.arena())
                && context.arena().is_some_and(|a| self.arena.same_arena(a))
                && target.scope().matches_source_owner(self.source_owner)
                && Arc::ptr_eq(&self.target_scope, &target.scope().capture_identity())
                && expected
                    .artifact_lease()
                    .is_some_and(|p| p.same_owner(&self.expected))
                && context
                    .source_group_seal()
                    .is_some_and(|p| p.same_owner(&self.source))
                && context
                    .native_group_seal()
                    .is_some_and(|p| p.same_owner(&self.native))
                && source_admission_digest(context.source_sha256())? == self.source_sha256
                && source_admission_digest(context.inspection_sha256())? == self.inspection_sha256
                && source_admission_digest(expected.semantic_sha256())? == self.expected_sha256,
            "prepared resource source admission lost its original live owners"
        );
        Ok(())
    }
}

struct SourceNativeMemory(ArtifactArena);
struct SourceNativeMemoryLease(ArenaRamLease);
impl n2r_win32::shadow_native::report_memory::ReportMemoryLease for SourceNativeMemoryLease {
    fn shrink_to(&mut self, bytes: u64) -> io::Result<()> {
        self.0.shrink_to(bytes).map_err(io::Error::other)
    }
}
impl n2r_win32::shadow_native::report_memory::ReportMemoryAccountant for SourceNativeMemory {
    fn reserve(
        &self,
        bytes: u64,
    ) -> io::Result<Box<dyn n2r_win32::shadow_native::report_memory::ReportMemoryLease>> {
        Ok(Box::new(SourceNativeMemoryLease(
            self.0.reserve_ram(bytes).map_err(io::Error::other)?,
        )))
    }
    fn lease_heap_bytes(&self) -> u64 {
        std::mem::size_of::<SourceNativeMemoryLease>() as u64
    }
}

struct Counter {
    bytes: u64,
    maximum: u64,
}
impl Write for Counter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(input.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("source metadata exceeds derived artifact budget"))?;
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct HashWriter<'a> {
    file: &'a mut File,
    hash: Sha256,
    bytes: u64,
    maximum: u64,
}
impl Write for HashWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let end = self
            .bytes
            .checked_add(input.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("source metadata changed during serialization"))?;
        self.file.write_all(input)?;
        self.hash.update(input);
        self.bytes = end;
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn save(
    root: &Path,
    name: &str,
    value: &impl Serialize,
    scratch: &SourceScratch,
    pins: &mut Vec<MetadataPin>,
    _reservations: &mut Vec<SourceTemporaryLease>,
) -> Result<()> {
    ensure!(
        !name.contains(['\\', '/', ':']) && name.ends_with(".json"),
        "literal source artifact leaf required"
    );
    let mut counter = Counter {
        bytes: 0,
        maximum: scratch.budget().scratch_bytes / 2,
    };
    serde_json::to_writer_pretty(&mut counter, value)?;
    counter.write_all(b"\n")?;
    let path = root.join(name);
    let in_arena = scratch.artifact_group().is_some();
    let reservation = if in_arena {
        scratch.reserve_temporary_file(&path, counter.bytes, 0)?
    } else {
        scratch.reserve_temporary(counter.bytes, 0)?
    };
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)?;
    let mut writer = HashWriter {
        file: &mut file,
        hash: Sha256::new(),
        bytes: 0,
        maximum: counter.bytes,
    };
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    ensure!(
        writer.bytes == counter.bytes,
        "source artifact byte count changed"
    );
    let hash = hex::encode(writer.hash.clone().finalize());
    drop(writer);
    file.sync_all()?;
    ensure!(
        file.metadata()?.len() == counter.bytes,
        "source artifact length changed"
    );
    let identity = n2r_win32::file_storage::file_id_info(&file)?;
    drop(file);
    let mut held = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&path)?;
    ensure!(
        held.metadata()?.is_file()
            && held.metadata()?.file_attributes() & 0x400 == 0
            && held.metadata()?.len() == counter.bytes
            && n2r_win32::file_storage::number_of_links(&held)? == 1
            && n2r_win32::file_storage::file_id_info(&held)? == identity,
        "source artifact handle identity changed"
    );
    let _readback_ram = scratch.lease_ram(65536)?;
    let mut digest = Sha256::new();
    let mut window = [0u8; 65536];
    let mut left = counter.bytes;
    while left > 0 {
        let count = left.min(window.len() as u64) as usize;
        held.read_exact(&mut window[..count])?;
        digest.update(&window[..count]);
        left -= count as u64;
    }
    ensure!(
        hex::encode(digest.finalize()) == hash,
        "source artifact readback changed"
    );
    held.seek(SeekFrom::Start(0))?;
    let arena_lease = if in_arena {
        Some(reservation.verify_closed(&hash)?)
    } else {
        drop(reservation);
        None
    };
    pins.push(MetadataPin {
        path,
        bytes: counter.bytes,
        sha256: hash,
        held,
        arena_lease,
    });
    Ok(())
}
fn key(number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key
}
fn gate(gates: &mut Vec<Gate>, code: &str, satisfied: bool, detail: &str) {
    gates.push(Gate {
        code: code.into(),
        satisfied,
        detail: detail.into(),
    });
}
fn output_independent(binding: &GeneralDiskBinding, output: &Path) -> Result<()> {
    let system = std::env::var("SystemRoot").context("Windows system path unavailable")?;
    let os_root = format!(
        "{}\\",
        system
            .get(..2)
            .context("Windows system drive unavailable")?
    );
    let text = output
        .to_str()
        .context("Unicode source output path required")?;
    ensure!(
        output.is_absolute()
            && text
                .get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&os_root))
            && !text[3..].contains(':')
            && !output
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "resource source artifacts must stay on the Windows OS volume"
    );
    let journal = n2r_win32::discovery::discover(
        &os_root,
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        journal.binding.disk_number != binding.disk_number,
        "source and working storage must be independent"
    );
    for ancestor in output
        .parent()
        .context("source output parent absent")?
        .ancestors()
    {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let meta = fs::symlink_metadata(ancestor)?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "ordinary source-output parent required"
        );
    }
    Ok(())
}
/// Actual ordinary directory owners, held through the source lifetime. The
/// caller's drive-letter spelling is never sufficient evidence of independence.
struct ArenaOutputBasis {
    parents: Vec<File>,
    created: Vec<File>,
    drive_root: String,
    parent_guid: String,
    volume: GeneralDiskBinding,
    _ram: ArenaRamLease,
}
impl ArenaOutputBasis {
    fn revalidate(&self, source: &GeneralDiskBinding, arena: &ArtifactArena) -> Result<()> {
        arena.require_root_directory(
            self.parents
                .first()
                .context("held source output parent absent")?,
        )?;
        let actual = n2r_win32::discovery::discover(
            &self.drive_root,
            n2r_win32::discovery::Role::Journal {
                allow_additional_partitions: true,
            },
        )?;
        ensure!(
            actual.observed_twice_unchanged
                && actual.read_only
                && actual.source_write_requests == 0
                && actual.binding == self.volume
                && actual.binding.disk_number != source.disk_number
                && n2r_win32::layout::guid_bytes(&actual.binding.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&source.identity.disk_guid)?
                && n2r_win32::layout::guid_bytes(&actual.binding.identity.partition_guid)?
                    != n2r_win32::layout::guid_bytes(&source.identity.partition_guid)?
                && n2r_win32::layout::guid_bytes(&actual.binding.volume_guid)?
                    != n2r_win32::layout::guid_bytes(&source.volume_guid)?
                && actual
                    .binding
                    .volume_path()?
                    .eq_ignore_ascii_case(arena.volume_guid_path()?),
            "actual source output volume/disk differs or aliases the source"
        );
        Ok(())
    }
    fn create_directory(&mut self, ordinary: &Path, guid_path: &Path) -> Result<()> {
        // Creation itself uses the independently observed volume-GUID route,
        // before checking the caller's ordinary path can still reach it.
        fs::create_dir(guid_path)?;
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(ordinary)?;
        ensure!(
            file.metadata()?.is_dir()
                && file.metadata()?.file_attributes() & 0x400 == 0
                && n2r_win32::file_storage::final_path_guid(&file)?.eq_ignore_ascii_case(
                    guid_path
                        .to_str()
                        .context("Unicode source output GUID route required")?
                ),
            "created source output directory changed ordinary/GUID route"
        );
        self.created.push(file);
        Ok(())
    }
}
fn output_in_arena(
    source: &GeneralDiskBinding,
    output: &Path,
    arena: &ArtifactArena,
) -> Result<ArenaOutputBasis> {
    use std::path::{Component, Prefix};
    let text = output
        .to_str()
        .context("Unicode source output path required")?;
    let bytes = text.as_bytes();
    ensure!(
        output.is_absolute()
            && bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
            && !text[2..].contains(':')
            && matches!(output.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)))
            && !output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "arena source output requires an unambiguous ordinary local path"
    );
    let leaf = output
        .file_name()
        .and_then(|v| v.to_str())
        .context("source output leaf absent")?;
    ensure!(
        !leaf.is_empty()
            && !leaf.ends_with([' ', '.'])
            && !leaf.chars().any(|c| c.is_control()
                || matches!(c, ':' | '/' | '\\' | '"' | '<' | '>' | '|' | '?' | '*')),
        "ambiguous source output leaf refused"
    );
    let ram = arena.reserve_ram(
        (text.len() as u64)
            .checked_mul(32)
            .and_then(|n| n.checked_add(4 * 1024 * 1024))
            .context("source output route RAM overflow")?,
    )?;
    let parent = output.parent().context("source output parent absent")?;
    let mut parents = Vec::new();
    for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "ordinary arena source-output ancestry required"
        );
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(ancestor)?;
        ensure!(
            file.metadata()?.is_dir() && file.metadata()?.file_attributes() & 0x400 == 0,
            "held arena source-output ancestry differs"
        );
        parents.push(file);
    }
    let held = parents
        .first()
        .context("held arena source-output parent absent")?;
    arena.require_root_directory(held)?;
    let parent_guid = n2r_win32::file_storage::final_path_guid(held)?;
    let drive_root = text[..3].to_owned();
    let volume = n2r_win32::discovery::discover(
        &drive_root,
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?
    .binding;
    // Independently bind the requested source volume to its real physical
    // disk before creating even a metadata directory. A caller-supplied disk
    // number/GUID cannot make a source-volume alias look independent.
    let source_probe = n2r_win32::probe_general(source.clone(), &mut Vec::new())?;
    ensure!(
        source_probe.binding == *source
            && source_probe.read_only_probe
            && source_probe.source_write_requests == 0,
        "actual source route was not independently observed"
    );
    let basis = ArenaOutputBasis {
        parents,
        created: Vec::new(),
        drive_root,
        parent_guid,
        volume,
        _ram: ram,
    };
    basis.revalidate(source, arena)?;
    Ok(basis)
}

fn short_names(
    source: &PagedInspection,
    observed: &GeneralLivePagedNtfsObservation,
    no_dos: bool,
) -> bool {
    let Some(txf) = observed.txf() else {
        return false;
    };
    let policy = &txf.observation;
    source.header().volume_flags == Some(0x80)
        && source.header().dirty == Some(false)
        && source.header().volume_version.as_deref() == Some("3.1")
        && no_dos
        && source
            .canonical_sha256()
            .is_ok_and(|pin| pin == observed.domain().header().request.source_inspection_sha256)
        && observed.before() == observed.after()
        && observed.before().disk_attributes == 3
        && policy.schema_version == 2
        && policy.windows_version == [10, 0, 26300]
        && policy.short_name_state_stable
        && policy
            .persistent_state_before
            .as_ref()
            .zip(policy.persistent_state_after.as_ref())
            .is_some_and(|(a, b)| {
                [a, b].into_iter().all(|s| {
                    s.queried_flags_valid
                        && s.requested_flag_mask == 1
                        && s.requested_version == 1
                        && s.short_name_creation_disabled
                })
            })
}

impl ResourceSourceContext {
    /// Real source-evidence pipeline only. It deliberately cannot clear the
    /// missing cross-stage arena/target gates or issue a source certificate.
    pub fn collect_source_evidence(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        events: &mut Vec<NativeEvent>,
        phase: &mut &'static str,
    ) -> Result<Self> {
        Self::collect(binding, budget, policy, output, events, phase, None)
    }

    /// Reserve real source and native groups before any source freeze or
    /// artifact write. The remaining cross-stage/target obligations stay false.
    pub fn prepare(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        arena: &ArtifactArena,
        events: &mut Vec<NativeEvent>,
        phase: &mut &'static str,
    ) -> Result<Self> {
        ensure!(
            arena.budget() == budget,
            "source arena differs from the observed resource budget"
        );
        let source = arena.reserve_group(
            ArtifactGroup::Source,
            SourceMetadataBudget::from_resource_budget(budget)?.scratch_bytes,
        )?;
        let native =
            arena.reserve_group(ArtifactGroup::Native, budget.page_budget()?.max_file_bytes)?;
        Self::collect(
            binding,
            budget,
            policy,
            output,
            events,
            phase,
            Some((arena.clone(), source, native)),
        )
    }
    fn collect(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        events: &mut Vec<NativeEvent>,
        phase: &mut &'static str,
        groups: Option<(ArtifactArena, ArtifactGroupPermit, ArtifactGroupPermit)>,
    ) -> Result<Self> {
        binding.validate()?;
        budget.validate()?;
        let mut output_basis = if let Some((arena, _, _)) = &groups {
            Some(output_in_arena(&binding, output, arena)?)
        } else {
            output_independent(&binding, output)?;
            None
        };
        let available = n2r_win32::resource_native::observe_available_resources(
            output.parent().context("output parent absent")?,
        )?;
        available.validate_budget(budget)?;
        ensure!(!output.exists(), "fresh resource source output required");
        let source_output = output.join("source");
        let native_output = output.join("native");
        if let Some(basis) = &mut output_basis {
            let arena = &groups.as_ref().context("source arena owner absent")?.0;
            basis.revalidate(&binding, arena)?;
            let guid_output = PathBuf::from(&basis.parent_guid)
                .join(output.file_name().context("source output leaf absent")?);
            basis.create_directory(output, &guid_output)?;
            basis.create_directory(&source_output, &guid_output.join("source"))?;
            basis.create_directory(&native_output, &guid_output.join("native"))?;
            basis.revalidate(&binding, arena)?;
        } else {
            fs::create_dir(output)?;
            fs::create_dir(&source_output)?;
            fs::create_dir(&native_output)?;
        }
        let output = source_output.as_path();
        let source_budget = SourceMetadataBudget::from_resource_budget(budget)?;
        let scratch = if let Some((_, permit, _)) = &groups {
            SourceScratch::new_in_arena(source_budget, permit.clone())?
        } else {
            SourceScratch::new(source_budget)?
        };
        let mut metadata = Vec::new();
        let mut reservations = Vec::new();
        save(
            output,
            "resource-intent.json",
            &serde_json::json!({"binding":binding,"budget":budget,
            "available":available,"policy":policy,"source_payload_writes_authorized":false,
            "shared_artifact_arena_complete":false,"execution_authorized":false}),
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        *phase = "source-vss-catalog-before-freeze";
        let volume = format!("{}\\", binding.volume_path()?);
        let vss_before = n2r_win32::vss_observation::observe_catalog(&volume)?;
        save(
            output,
            "source-vss-before-freeze.json",
            &vss_before,
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        vss_before.require_observed_catalog_clear()?;
        ensure!(
            vss_before.source_volume_guid.eq_ignore_ascii_case(&volume),
            "VSS source route differs"
        );
        let source_io_ram = scratch.lease_ram(GeneralFrozenPartition::read_buffer_memory_bytes())?;
        *phase = "source-freeze";
        let mut online = n2r_win32::GeneralPartitionReader::open(binding.clone(), events)?;
        let mut boot = [0; 512];
        online.read_exact(&mut boot)?;
        let geometry = ntfs_inspect::inspect_boot_sector(&boot, online.byte_len())?;
        ensure!(
            ntfs_admission::ResourceProfile::ResourceBoundedV4(None)
                .supports_source_geometry(&geometry),
            "source geometry exceeds the implemented resource profile"
        );
        online.revalidate_route(events)?;
        drop(online);
        let mount_paths = n2r_win32::capture_mount_paths_general(binding.clone(), events)?;
        let label = n2r_win32::volume_label::capture_source_label(binding.clone())?;
        ensure!(
            mount_paths.binding == binding
                && mount_paths.all_paths_resolve_to_bound_volume
                && label.binding() == &binding,
            "pre-freeze label/mount binding differs"
        );
        save(
            output,
            "source-mount-paths.json",
            &mount_paths,
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        save(
            output,
            "source-label.json",
            &label,
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        save(
            output,
            "preflight-events.json",
            events,
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        events.clear();
        let mut source = GeneralFrozenPartition::isolate_observed_ntfs_with_resource_budget(
            binding.clone(),
            budget,
            events,
        )?;
        let before = source.state(events)?;
        ensure!(
            before.disk_attributes == 3 && source.freeze_observation().is_some(),
            "actual observed source freeze absent"
        );
        let length = source.byte_len();
        *phase = "source-inspection";
        let (raw, read_coverage) = fp::inspect_recorded_with_scratch(
            &mut source,
            length,
            budget,
            policy,
            &output.join("recorded-source"),
            &scratch,
        )?;
        ensure!(
            raw.header().geometry == geometry,
            "frozen source geometry differs from online capture"
        );
        let inspection_sha = raw.canonical_sha256()?;
        save(
            output,
            "source-manifest.json",
            raw.pin(),
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        save(
            output,
            "inspection-read-coverage.json",
            &read_coverage.report()?,
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        let fingerprint = PagedSourceFingerprint::for_inspection(
            &raw,
            length,
            policy,
            &output.join("fingerprint"),
        )?;
        fingerprint.validate_inspection_reads(&read_coverage)?;
        *phase = "source-fingerprint";
        let source_sha = fingerprint.hash(&mut source)?;
        save(
            output,
            "source-frozen.json",
            &serde_json::json!({"binding":binding,"source_sha256":source_sha,
            "inspection_sha256":inspection_sha,"fingerprint":fingerprint.pins(),"scope":fingerprint.report(),
            "state":before,"freeze_observation":source.freeze_observation(),"source_payload_writes":0}),
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        let backups = ntfs_backup::verify_domain(&mut source, length, &raw)?;
        let log = ntfs_log::verify_domain(&mut source, &raw)?;
        let label_frozen = source_volume_label::verify_domain(&mut source, &raw, label.label())?;
        save(
            output,
            "source-basis.json",
            &serde_json::json!({"backups":backups,"log_restart":log,
            "label":label_frozen,"source_admitted":false}),
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        *phase = "source-observation";
        let selectors = PagedObservationRequest::new(&raw, &binding, budget, policy)?;
        let admission = selectors.admission();
        let native_path = native_output.join("native.pages");
        let native_permit = groups
            .as_ref()
            .map(|(_, _, group)| {
                group.reserve_file(&native_path, admission.native_page_budget()?.max_file_bytes)
            })
            .transpose()?;
        let native_destination = native_permit
            .as_ref()
            .map_or(native_path.as_path(), |p| p.path());
        let native_payer_ram = groups
            .as_ref()
            .map(|_| scratch.lease_ram(std::mem::size_of::<SourceNativeMemory>() as u64 + 128))
            .transpose()?;
        let native = if let Some((arena, _, _)) = &groups {
            source.observe_ntfs_files_paged_domain_with_memory(
                &selectors,
                native_destination,
                admission.native_observation_budget()?,
                true,
                true,
                Arc::new(SourceNativeMemory(arena.clone())),
                events,
            )?
        } else {
            source.observe_ntfs_files_paged_domain(
                &selectors,
                native_destination,
                admission.native_observation_budget()?,
                true,
                true,
                events,
            )?
        };
        ensure!(
            groups.is_none() || native.domain().retained_storage_ram_accounted(),
            "actual native source owner lost its shared memory leases"
        );
        native.domain().revalidate()?;
        let native_artifact = native_permit
            .map(|permit| permit.verify_closed(native.domain().sha256()))
            .transpose()?;
        let native_seal = groups
            .as_ref()
            .map(|(_, _, group)| group.seal())
            .transpose()?;
        save(
            output,
            "source-native-witness.json",
            &serde_json::json!({
                "schema_version":1,
                "kind":"actual-protected-resource-source-native-witness",
                "source_inspection_sha256":inspection_sha,
                "source_fingerprint_before_native":source_sha,
                "native_pages_sha256":native.domain().sha256(),
                "txf":native.txf(),
                "txf_error":native.txf_error(),
                "before":native.before(),
                "after":native.after(),
                "source_admitted":false,
                "execution_authorized":false
            }),
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        let vss_inside = native
            .vss_observation()
            .context("protected native VSS absence evidence absent")?;
        save(
            output,
            "source-vss-after-freeze.json",
            vss_inside,
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        vss_inside.require_observed_snapshot_absence()?;
        ensure!(
            vss_before.same_source_and_provider_inventory(vss_inside),
            "VSS source/provider inventory changed"
        );
        save(
            output,
            "native-source-header.json",
            native.domain().header(),
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        *phase = "source-admission";
        let after_hash = fingerprint.hash(&mut source)?;
        let after = source.state(events)?;
        ensure!(
            before == after
                && source_sha == after_hash
                && raw.canonical_sha256()? == inspection_sha,
            "frozen source changed across actual native observation"
        );
        let mut indexes =
            ntfs_internal::verify_domain(&mut source, &raw, &output.join("internal-indexes"))?;
        indexes.bind_native_quota(&native);
        let transactions = ntfs_transactions::verify_domain(
            &raw,
            &log,
            source
                .freeze_observation()
                .context("original freeze witness absent")?,
            &native,
        )?;
        save(
            output,
            "source-internal-proofs.json",
            &serde_json::json!({"indexes":indexes,"transactions":transactions}),
            &scratch,
            &mut metadata,
            &mut reservations,
        )?;
        let mut rows_writer =
            SortedRecordWriter::new(&output.join("source-comparison"), *b"N2RSCMP1", &scratch)?;
        let mut row_count = 0u64;
        let mut policy_rejections = 0u64;
        let mut no_dos = true;
        let (mut files, mut directories, mut streams, mut logical_bytes) = (0u64, 0u64, 0u64, 0u64);
        let (mut raw_directories, mut user_case_matched, mut internal_directories) =
            (0u64, 0u64, 0u64);
        let internal_bound = indexes.binds_domain(&raw)
            && indexes.replacement_supported
            && transactions.binds_domain(&raw)
            && backups.binds_domain(&raw)
            && log.binds_domain(&raw);
        let mut replacements_writer = SortedRecordWriter::new(
            &output.join("internal-replacements"),
            *b"N2RREPL1",
            &scratch,
        )?;
        let comparison = compare_domain(&raw, &binding, budget, policy, native.domain(), |row| {
            let file = raw
                .find_record(row.record_number, Some(row.sequence_number))?
                .context("compared source identity absent")?;
            no_dos &= file.names.iter().all(|name| name.namespace != 2);
            let role = ntfs_admission::paged::internal_role(&raw, &file)?;
            ensure!(
                role == row.internal_replacement_role,
                "source replacement role changed"
            );
            let issues = if let Some(role) = &role {
                let action = match role.as_str() {
                    "$Volume" if indexes.covers_volume_object_id_domain(&raw, 3) => {
                        "replace_filesystem_internal_volume_identity"
                    }
                    "$Extend\\$ObjId" if indexes.internal_volume_object_id().is_some() => {
                        "replace_ntfs_internal_volume_identity_index"
                    }
                    "$LogFile" | "$Extend\\$UsnJrnl" => "start_new_filesystem_journal_epoch",
                    "$Extend\\$RmMetadata\\$Repair" => "replace_ntfs_runtime_diagnostics",
                    role if role.starts_with("$Extend\\$RmMetadata")
                        || role == "$Extend\\$Deleted" =>
                    {
                        "replace_idle_default_transaction_metadata"
                    }
                    _ => "replace_with_native_refs_structure",
                };
                replacements_writer.push(
                    key(file.record_number),
                    &InternalReplacement {
                        record_number: file.record_number,
                        sequence_number: file.sequence_number,
                        role: role.clone(),
                        action,
                    },
                )?;
                Vec::new()
            } else {
                if file.is_directory {
                    directories = directories
                        .checked_add(1)
                        .context("directory count overflow")?;
                } else {
                    files = files.checked_add(1).context("file count overflow")?;
                    streams = streams
                        .checked_add(file.streams.len() as u64)
                        .context("stream count overflow")?;
                    for stream in &file.streams {
                        logical_bytes = logical_bytes
                            .checked_add(stream.logical_size)
                            .context("logical total overflow")?;
                    }
                }
                ntfs_admission::paged::ordinary_user_issues(&raw, &file, admission)?
            };
            policy_rejections = policy_rejections
                .checked_add(u64::from(!issues.is_empty()))
                .context("policy refusal count overflow")?;
            if file.is_directory {
                raw_directories = raw_directories
                    .checked_add(1)
                    .context("raw directory count overflow")?;
                if role.is_some() {
                    internal_directories = internal_directories
                        .checked_add(1)
                        .context("internal directory count overflow")?;
                } else if row.directory_case.as_ref().is_some_and(|c| c.matched) {
                    user_case_matched = user_case_matched
                        .checked_add(1)
                        .context("case-match count overflow")?;
                }
            }
            rows_writer.push(
                key(file.record_number),
                &ObjectRow {
                    native: row,
                    user_issues: issues,
                    independent_internal_state_checks_passed: role.is_some() && internal_bound,
                },
            )?;
            row_count = row_count
                .checked_add(1)
                .context("comparison row count overflow")?;
            Ok(())
        })?;
        let rows_pin = rows_writer.finish()?;
        let replacements_pin = replacements_writer.finish()?;
        ensure!(
            row_count == raw.file_count(),
            "complete per-object source comparison coverage differs"
        );
        let short_policy = short_names(&raw, &native, no_dos);
        let mut unresolved_writer = SortedRecordWriter::new(
            &output.join("unresolved-source-blockers"),
            *b"N2RBLOCK",
            &scratch,
        )?;
        let mut unresolved_count = 0u64;
        for ordinal in 0..raw.blocker_count() {
            let blocker = raw.blocker(ordinal)?;
            if ntfs_admission::paged::blocker_is_unresolved(
                &raw,
                &blocker,
                &backups,
                &log,
                &indexes,
                &transactions,
                short_policy,
            )? {
                unresolved_writer.push(key(unresolved_count), &blocker)?;
                unresolved_count = unresolved_count
                    .checked_add(1)
                    .context("blocker count overflow")?;
            }
        }
        let unresolved_pin = unresolved_writer.finish()?;
        let mut gates = Vec::new();
        let clean = raw.header().dirty == Some(false)
            && raw
                .header()
                .volume_flags
                .is_some_and(|flags| flags & 1 == 0)
            && raw.header().volume_version.as_deref() == Some("3.1");
        let policy_flags = raw.header().volume_flags == Some(0) || short_policy;
        let resource_counts = admission.validate_tree(files, directories, streams).is_ok()
            && files > 0
            && logical_bytes <= i64::MAX as u64;
        let source_objects =
            comparison.all_supported_user_views_compatible && policy_rejections == 0;
        for (code, satisfied, detail) in [
            (
                "geometry",
                ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission))
                    .supports_source_geometry(&raw.header().geometry),
                "actual source geometry matches the implemented profile",
            ),
            (
                "clean_volume",
                clean,
                "NTFS3.1 and clear persisted dirty state required",
            ),
            (
                "volume_policy_flags",
                policy_flags,
                "only zero flags or exact live disabled-short-name interpretation accepted",
            ),
            (
                "raw_allocation",
                raw.allocation().status
                    == ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel,
                "complete physical ownership and bitmap closure",
            ),
            (
                "raw_mft_record_coverage",
                raw.header().inventory_complete,
                "opaque producer closed canonical/physical extension and allocation domains",
            ),
            (
                "raw_namespace",
                raw.header().inventory_complete,
                "opaque producer closed every directory index/name/reference domain",
            ),
            (
                "raw_security",
                raw.header().inventory_complete,
                "opaque producer closed descriptors and every supported security binding",
            ),
            (
                "native_profile",
                native.domain().is_paged(),
                "actual paged native lease, complete selectors and resource budgets",
            ),
            (
                "native_identity_coverage",
                row_count == raw.file_count(),
                "every raw identity has one actual native row",
            ),
            (
                "native_volume_allocation",
                true,
                "compare_domain checked both complete native bitmap summaries against frozen allocation",
            ),
            (
                "objects",
                source_objects,
                "every transferred user object passes shared preservation policy and actual native views",
            ),
            (
                "resource_limits",
                resource_counts,
                "exact source counts and logical total match pinned resources",
            ),
            (
                "source_backups",
                backups.binds_domain(&raw),
                "actual boot and MFT mirror reads bind this source",
            ),
            (
                "log_restart_pages",
                log.binds_domain(&raw) && log.restart.candidate_clean_dismount,
                "actual complete LogFile and agreeing clean restart copies",
            ),
            (
                "remaining_inspection_refusals",
                unresolved_count == 0,
                "every other source blocker remains unresolved and is retained in pages",
            ),
            (
                "frozen_device_basis",
                before == after && source_sha == after_hash,
                "same observed frozen device and complete scoped fingerprint bracket native reads",
            ),
            (
                "internal_indexes",
                indexes.binds_domain(&raw) && indexes.replacement_supported,
                "actual object-ID/reparse/default-quota indexes plus native disabled quota policy",
            ),
            (
                "transaction_freeze",
                transactions.binds_domain(&raw),
                "actual prefreeze RM, lock/dismount, clean restart and empty deferred namespaces",
            ),
            (
                "native_resource_profile_support",
                native.domain().header().request.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(admission),
                    )),
                "actual complete source/native/count/page profile equality",
            ),
        ] {
            gate(&mut gates, code, satisfied, detail);
        }
        let replacement_ready = internal_bound
            && clean
            && policy_flags
            && source_objects
            && resource_counts
            && unresolved_count == 0;
        gate(
            &mut gates,
            "internal_replacement_state",
            replacement_ready,
            "exact internal roles are excluded only after all independent source obligations close",
        );
        gate(
            &mut gates,
            "native_directory_case_sensitivity",
            directories > 0
                && user_case_matched == directories
                && (internal_directories == 0 || replacement_ready)
                && raw_directories == directories + internal_directories,
            "every transferred directory needs actual stable zero case flags; only exact proof-bound internals are excluded",
        );
        gate(
            &mut gates,
            "shared_artifact_arena",
            false,
            "source subgroup is bounded; cross-stage source/native/expected/plan/report/recovery arena ownership is not yet integrated",
        );
        gate(
            &mut gates,
            "security_timestamp_preservation",
            false,
            "actual same-tree native target round trip remains required",
        );
        gate(
            &mut gates,
            "target_resource_profile_support",
            false,
            "actual resource-selected target preservation remains required",
        );
        let source_views_sha = json_sha(
            &serde_json::json!({"kind":"resource-source-views-v1","inspection":inspection_sha,
            "source_fingerprint":source_sha,"native_pages_sha256":native.domain().sha256(),"comparison_rows":rows_pin}),
            scratch.budget().scratch_bytes / 2,
        )?;
        let rows = SortedRecordStore::open(&rows_pin, &scratch)?;
        let unresolved = SortedRecordStore::open(&unresolved_pin, &scratch)?;
        let replacements = SortedRecordStore::open(&replacements_pin, &scratch)?;
        let mut context = Self {
            source,
            raw,
            native,
            fingerprint,
            read_coverage,
            backups,
            log,
            indexes,
            transactions,
            label,
            label_frozen,
            mount_paths,
            vss_before,
            comparison,
            rows,
            unresolved,
            replacements,
            admission,
            policy,
            before,
            after,
            inspection_sha,
            source_sha,
            source_views_sha,
            gates,
            scratch,
            _metadata: metadata,
            _metadata_reservations: reservations,
            arena: groups.as_ref().map(|(arena, _, _)| arena.clone()),
            source_seal: None,
            native_seal,
            native_artifact,
            _native_payer_ram: native_payer_ram,
            _source_io_ram: source_io_ram,
            _output_basis: output_basis,
        };
        context.revalidate_evidence()?;
        let mut metadata = std::mem::take(&mut context._metadata);
        let mut reservations = std::mem::take(&mut context._metadata_reservations);
        save(
            output,
            "source-resource-assessment.json",
            &context.report(),
            &context.scratch,
            &mut metadata,
            &mut reservations,
        )?;
        context._metadata = metadata;
        context._metadata_reservations = reservations;
        if context.arena.is_some() {
            context.source_seal = Some(context.scratch.seal()?);
        }
        context.revalidate_evidence()?;
        Ok(context)
    }
    pub fn report(&self) -> ResourceSourceReport<'_> {
        ResourceSourceReport {
            kind: "actual-resource-source-context-v1",
            binding: self.source.binding(),
            budget: self.admission.budget,
            resource_admission: self.admission,
            policy: self.policy,
            source_inspection_sha256: &self.inspection_sha,
            source_sha256: &self.source_sha,
            source_fingerprint_kind: self.fingerprint.kind(),
            source_views_sha256: &self.source_views_sha,
            frozen_before: &self.before,
            frozen_after: &self.after,
            comparison: &self.comparison,
            comparison_rows: self.rows.pin(),
            unresolved_blockers: self.unresolved.pin(),
            internal_replacements: self.replacements.pin(),
            gates: &self.gates,
            source_group_bytes: self.scratch.used_bytes(),
            source_native_groups_sealed: self.source_seal.is_some() && self.native_seal.is_some(),
            source_group_allocated_bytes: self.source_seal.as_ref().map(|s| s.allocated_bytes()),
            native_group_allocated_bytes: self.native_seal.as_ref().map(|s| s.allocated_bytes()),
            shared_artifact_arena_complete: false,
            target_preservation_complete: false,
            source_admitted: false,
            certificate_issued: false,
            execution_authorized: false,
        }
    }
    pub fn require_source_evidence(&self) -> Result<()> {
        let failed: Vec<_> = self
            .gates
            .iter()
            .filter(|g| {
                !matches!(
                    g.code.as_str(),
                    "security_timestamp_preservation"
                        | "target_resource_profile_support"
                        | "shared_artifact_arena"
                ) && !g.satisfied
            })
            .map(|g| g.code.as_str())
            .collect();
        ensure!(
            failed.is_empty(),
            "resource source evidence refused: {failed:?}"
        );
        Ok(())
    }
    pub fn require_source_gates(&self) -> Result<()> {
        self.require_source_evidence()?;
        ensure!(
            self.gates
                .iter()
                .any(|g| g.code == "shared_artifact_arena" && g.satisfied),
            "V4 activation requires actual shared artifact arena ownership across every phase"
        );
        Ok(())
    }
    /// Close the deferred target/resource obligations against real owners,
    /// instead of rewriting the diagnostic assessment's false gate flags.
    /// The resulting one-shot proof is usable only with this same frozen
    /// source, target scope, expected file and already closed arena.
    pub(crate) fn qualify_prepared_target(
        &mut self,
        target: &crate::general_composite_target::paged::ProtectedPagedTargetSelection,
        expected: &crate::shadow_tree::PagedExpectedTree,
        closure: &crate::artifact_arena::PreparedArenaClosure,
        events: &mut Vec<NativeEvent>,
    ) -> Result<PreparedResourceSourceAdmission> {
        self.require_source_evidence()?;
        self.recheck_source(events)?;
        let arena = self
            .arena
            .as_ref()
            .context("source admission needs its actual arena")?;
        ensure!(
            arena.same_arena(closure.arena()) && arena.budget() == self.admission.budget,
            "source admission and exhaustive prepared closure differ"
        );
        closure.revalidate()?;
        expected.require_resource_owner(self.admission)?;
        expected.require_shared_memory(arena)?;
        let scope = target.scope();
        let native = target.native();
        // The opaque native observation can be issued only by the complete
        // same-tree metadata/namespace/security/time/map validator. Residual
        // contents and the source-backed required selection close its payload
        // obligation; no free-space or whole-image equality is inferred.
        ensure!(
            scope.matches_source_owner(self.source_owner_identity())
                && scope.pair().source == *self.source.binding()
                && scope.source_inspection_sha256() == self.inspection_sha
                && scope.expected_tree_sha256() == expected.semantic_sha256()
                && target.captured().is_for_scope(scope)
                && native.report().pair() == scope.pair()
                && native.before() == native.after()
                && native.before().disk_attributes == 3
                && native.observed_readonly().disk_attributes == 2
                && native.report().residual_contents_verified()
                && native.report().paged_residuals().is_some()
                && native.report().native().retained_rows_ram_accounted()
                && native.report().native().resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(self.admission)
                    ))
                && native.report().native().objects.len() == expected.len(),
            "actual target preservation does not close this original source's obligations"
        );
        scope.revalidate()?;
        let source = self
            .source_seal
            .as_ref()
            .context("actual source seal absent")?;
        let native = self
            .native_seal
            .as_ref()
            .context("actual native source seal absent")?;
        let expected = expected
            .artifact_lease()
            .context("actual expected artifact owner absent")?;
        // Only Arc clones, fixed-size digests and the small runtime token are
        // retained here. Pay before allocating the digest decoding buffers.
        let memory = arena.reserve_ram(4096)?;
        let proof = PreparedResourceSourceAdmission {
            source_owner: self.source_owner_identity(),
            admission: self.admission,
            source_sha256: source_admission_digest(&self.source_sha)?,
            inspection_sha256: source_admission_digest(&self.inspection_sha)?,
            expected_sha256: source_admission_digest(scope.expected_tree_sha256())?,
            target_scope: scope.capture_identity(),
            expected: expected.clone(),
            source: source.clone(),
            native: native.clone(),
            arena: arena.clone(),
            _memory: memory,
        };
        // This method does not bless a cached report or mutate the context.
        // Its caller retains/rechecks the target and native journal as well.
        closure.revalidate()?;
        Ok(proof)
    }
    pub fn revalidate_evidence(&self) -> Result<()> {
        if let Some(output) = &self._output_basis {
            output.revalidate(
                self.source.binding(),
                self.arena.as_ref().context("source arena owner absent")?,
            )?;
        }
        self.raw.revalidate()?;
        self.native.domain().revalidate()?;
        self.fingerprint.revalidate()?;
        self.fingerprint.validate_reads(&self.read_coverage)?;
        self.indexes.revalidate()?;
        self.rows.revalidate()?;
        self.unresolved.revalidate()?;
        self.replacements.revalidate()?;
        self.vss_before.require_observed_catalog_clear()?;
        let inside = self
            .native
            .vss_observation()
            .context("protected VSS witness absent")?;
        inside.require_observed_snapshot_absence()?;
        ensure!(
            self.vss_before.same_source_and_provider_inventory(inside),
            "VSS witness binding changed"
        );
        let _readback_ram = self.scratch.lease_ram(65536)?;
        if let Some(artifact) = &self.native_artifact {
            artifact.revalidate()?;
        }
        if let Some(seal) = &self.native_seal {
            seal.revalidate()?;
        }
        if let Some(seal) = &self.source_seal {
            seal.revalidate()?;
        }
        if let (Some(source), Some(native)) = (&self.source_seal, &self.native_seal) {
            let arena = self.arena.as_ref().context("source arena owner absent")?;
            ensure!(
                source.permit().group() == ArtifactGroup::Source
                    && native.permit().group() == ArtifactGroup::Native
                    && source.permit().arena().same_arena(arena)
                    && native.permit().arena().same_arena(arena)
                    && self.scratch.is_sealed(),
                "source/native arena owner or source seal changed"
            );
        }
        for pin in &self._metadata {
            if let Some(lease) = &pin.arena_lease {
                lease.revalidate()?;
            }
            ensure!(
                pin.held.metadata()?.len() == pin.bytes
                    && pin.held.metadata()?.file_attributes() & 0x400 == 0,
                "held source metadata identity changed"
            );
            let mut file = pin.held.try_clone()?;
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = [0u8; 65536];
            let mut left = pin.bytes;
            let mut digest = Sha256::new();
            while left > 0 {
                let count = left.min(bytes.len() as u64) as usize;
                file.read_exact(&mut bytes[..count])?;
                digest.update(&bytes[..count]);
                left -= count as u64;
            }
            ensure!(
                hex::encode(digest.finalize()) == pin.sha256,
                "held source metadata contents changed"
            );
            file.seek(SeekFrom::Start(0))?;
        }
        ensure!(
            self.backups.binds_domain(&self.raw)
                && self.log.binds_domain(&self.raw)
                && self.transactions.binds_domain(&self.raw)
                && self.label_frozen.inspection_sha256 == self.inspection_sha,
            "source proof owner changed"
        );
        Ok(())
    }
    pub fn recheck_source(&mut self, events: &mut Vec<NativeEvent>) -> Result<()> {
        ensure!(
            self.source.freeze_observation().is_some(),
            "original live NTFS freeze witness was consumed by an apply-intent attempt"
        );
        self.revalidate_evidence()?;
        let before = self.source.state(events)?;
        ensure!(
            before == self.before && before.disk_attributes == 3,
            "original frozen source state changed"
        );
        let digest = self.fingerprint.hash(&mut self.source)?;
        let after = self.source.state(events)?;
        ensure!(
            after == before && digest == self.source_sha,
            "resource source fingerprint changed"
        );
        Ok(())
    }

    /// Consume the same live pre-AP NTFS owner on an ordinary failure. The
    /// original freeze witness is invalidated before *any* AP attempt, so it
    /// can never authorize cleanup of a source that entered journal replay.
    pub(crate) fn restore_original_unchanged(
        mut self,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<GeneralDiskBinding> {
        self.recheck_source(events)?;
        checkpoint(events)?;
        let binding = self.source.binding().clone();
        let length = self.source.byte_len();
        // The SDK repeats the entire SHA-256 while holding the same frozen
        // source. Pay the single 4 MiB hashing buffer and state-query overhead
        // before either pass; this expensive path is only used after failure.
        let _ram = self.scratch.lease_ram(5 * 1024 * 1024)?;
        let sha = hex::encode(n2r_win32::sha256_native::hash_range(&mut self.source, 0, length)?);
        self.recheck_source(events)?;
        checkpoint(events)?;
        ensure!(self.source.freeze_observation().is_some(),
            "pre-AP NTFS freeze witness was consumed");
        self.source.bring_original_online_unchanged(&sha, events)
            .context("original NTFS online transition failed; source may require rediscovery")?;
        checkpoint(events)?;
        let mounted = n2r_win32::rediscover_general_volume_wait(binding.clone(), events)?;
        n2r_win32::volume_label::validate_original_partition(&binding, &mounted)?;
        ensure!(n2r_win32::mounted_filesystem_general(mounted.clone(), events)? == "NTFS",
            "original source did not return as NTFS");
        checkpoint(events)?;
        Ok(mounted)
    }

    pub(crate) fn has_original_freeze_witness(&self) -> bool {
        self.source.freeze_observation().is_some()
    }
    pub fn inspection(&self) -> &PagedInspection {
        &self.raw
    }
    pub fn native(&self) -> &GeneralLivePagedNtfsObservation {
        &self.native
    }
    pub fn fingerprint(&self) -> &PagedSourceFingerprint {
        &self.fingerprint
    }
    pub fn resource_admission(&self) -> SourceResourceAdmission {
        self.admission
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha
    }
    pub fn inspection_sha256(&self) -> &str {
        &self.inspection_sha
    }
    pub fn source_views_sha256(&self) -> &str {
        &self.source_views_sha
    }
    pub fn mount_paths(&self) -> &MountPathObservation {
        &self.mount_paths
    }
    pub fn expected_label(&self) -> &n2r_win32::volume_label::VolumeLabel {
        self.label.label()
    }
    pub fn source_and_inspection(&mut self) -> (&mut GeneralFrozenPartition, &PagedInspection) {
        (&mut self.source, &self.raw)
    }
    /// Runtime association with this exact retained frozen source. A saved
    /// value is not an ownership, device, admission, or write capability.
    pub(crate) fn source_owner_identity(&self) -> usize {
        std::ptr::from_ref(&self.source) as usize
    }
    pub fn arena(&self) -> Option<&ArtifactArena> {
        self.arena.as_ref()
    }
    pub fn source_group_seal(&self) -> Option<&ArtifactGroupSeal> {
        self.source_seal.as_ref()
    }
    pub fn native_group_seal(&self) -> Option<&ArtifactGroupSeal> {
        self.native_seal.as_ref()
    }
    pub fn source_artifact_bytes(&self) -> u64 {
        self.scratch.used_bytes()
    }
    pub fn comparison_rows_pin(&self) -> &RecordStorePin {
        self.rows.pin()
    }
}
fn json_sha(value: &impl Serialize, maximum: u64) -> Result<String> {
    struct Sink {
        hash: Sha256,
        counter: Counter,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.counter.write_all(bytes)?;
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink {
        hash: Sha256::new(),
        counter: Counter { bytes: 0, maximum },
    };
    serde_json::to_writer(&mut sink, value)?;
    Ok(hex::encode(sink.hash.finalize()))
}
