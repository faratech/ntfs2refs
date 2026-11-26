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

// Native controls bound one operation's evidence, not the complete retained
// history. Preserve every emitted event, including a failed operation's batch.
fn native_batch<T, E>(
    history: &mut Vec<NativeEvent>,
    operation: impl FnOnce(&mut Vec<NativeEvent>) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut batch = Vec::new();
    let result = operation(&mut batch);
    history.append(&mut batch);
    result
}

#[derive(Serialize)]
struct MetadataPin {
    path: PathBuf,
    bytes: u64,
    sha256: String,
    #[serde(skip)]
    held: File,
    #[serde(skip)]
    arena_lease: Option<ArtifactLease>,
    #[serde(skip)]
    last_full: n2r_win32::verify_policy::LastFull,
}
/// An object whose 8.3 short names are not carried over.
#[derive(Serialize)]
struct ShortNamesNotCarried {
    record_number: u64,
    sequence_number: u16,
    path: Option<String>,
    short_names: Vec<String>,
}
/// A directory of the source that is marked case-sensitive. Whether the mark
/// is set on the target is in the record that lists them.
#[derive(Serialize)]
struct CaseSensitiveDirectory {
    record_number: u64,
    sequence_number: u16,
    path: Option<String>,
}
/// The run's record of the source's marked directories: which they are
/// (`records`), and whether the new volume's directories carry the mark.
fn case_mark_record(
    carry: n2r_win32::directory_case::CaseMarkCarry,
    inspection_sha: &str,
    directories: u64,
    records: serde_json::Value,
) -> serde_json::Value {
    use n2r_win32::directory_case::CaseMarkCarry;
    let (kind, policy) = match carry {
        CaseMarkCarry::Carried => (
            "case-sensitive-directory-marks-carried-over-v1",
            "every directory of the target is made with the mark its source directory has, set or not, and each observation of the target reads the mark back and holds it to the source's; a directory that holds two names differing only by case is refused when its names are reconciled".to_owned(),
        ),
        CaseMarkCarry::NotCarried(why) => (
            "case-sensitive-directory-marks-not-carried-over-v1",
            format!(
                "the mark is not set on the target; a directory that holds two names differing only by case is refused when its names are reconciled. {}",
                why.sentence()
            ),
        ),
    };
    serde_json::json!({
        "kind":kind,
        "source_inspection_sha256":inspection_sha,
        "directories":directories, "records":records,
        "names_that_differ_only_by_case":0,
        "target_has_the_mark":carry.carried(),
        "policy":policy,
    })
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_alias_plan: Option<&'a RecordStorePin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_hint_normalizations: Option<&'a RecordStorePin>,
    pub gates: &'a [Gate],
    pub source_group_bytes: u64,
    pub source_native_groups_sealed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_observation_origin: Option<&'a n2r_win32::NativeSourceObservationOrigin>,
    pub source_group_allocated_bytes: Option<u64>,
    pub native_group_allocated_bytes: Option<u64>,
    pub shared_artifact_arena_complete: bool,
    pub target_preservation_complete: bool,
    pub source_admitted: bool,
    pub certificate_issued: bool,
    pub execution_authorized: bool,
}
#[path = "resource_owner.rs"]
pub(crate) mod source_owner;
use source_owner::ResourceSourceOwner;

#[path = "resource_cache.rs"]
pub mod cache;
#[path = "resource_cache_refresh.rs"]
pub(crate) mod cache_refresh;
#[path = "resource_partition.rs"]
pub(crate) mod partition;
#[path = "raw_target_security.rs"]
mod raw_target_security;
pub use cache::{SourceCacheFilePin, SourceCacheOriginPins};

/// Where the native witness records the content reads that a run which
/// verifies once did not ask of Windows.
const WINDOWS_CONTENT_READS_SKIPPED: &str = "windows_content_reads_skipped";
pub struct ResourceSourceContext {
    early_preparation_guard:
        Option<crate::resource_preparation::early_guard::EarlyPreparationGuard>,
    source: ResourceSourceOwner,
    raw: PagedInspection,
    windows_aliases: Option<Arc<crate::boot_alias::WindowsAliasDomain>>,
    /// Whether the tree this run derives states every directory's
    /// case-sensitive mark, so that the new volume's directories are made
    /// with the source's marks and held to them: decided once, when the
    /// source is admitted, with what the run says and records. It is so
    /// where the source has a marked directory and this Windows is one the
    /// mark is carried on. A source without one has nothing to carry, and
    /// its directories are made and observed as they always were.
    carry_case_marks: bool,
    storage_hint_normalization: Option<Arc<n2r_win32::BootStorageHintNormalization>>,
    storage_hint_records: Option<SortedRecordStore>,
    _storage_hint_ram: Option<SourceRamLease>,
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
    // Newly adopted ordinary artifacts; no old arena seal or live owner.
    _cache_artifacts: Option<cache::OpenedSourceCache>,
}

/// Issued only from this invocation's actual source and typed semantic join.
/// Saved binding facts can never construct this one-operation live witness.
pub(crate) struct CachedExpectedRebind {
    facts: crate::shadow_tree::ExpectedBindingFacts,
    source_owner: usize,
}
impl CachedExpectedRebind {
    pub(crate) fn into_parts(
        self,
        body: &crate::shadow_tree::PagedExpectedTree,
    ) -> Result<(crate::shadow_tree::ExpectedBindingFacts, usize)> {
        self.facts.validate(
            self.facts.effective_admission,
            body.file_sha256(),
            body.semantic_sha256(),
        )?;
        ensure!(
            self.facts.original_admission
                == body
                    .header()
                    .resource_admission
                    .context("cached original header absent")?,
            "live expected rebind witness belongs to another original body"
        );
        Ok((self.facts, self.source_owner))
    }
}

/// Original live source admission closed against the actual protected target
/// and exhaustive prepared arena. This is intentionally neither serializable
/// nor Clone. It has no constructor accepting persisted hashes or flags, and
/// it cannot open a writer without the still-owned prepared journal.
pub(crate) struct PreparedResourceSourceAdmission {
    source_owner: usize,
    partition_owner: Option<n2r_win32::PartitionOwnerToken>,
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
                && match (&self.partition_owner, context.source.partition_token()) {
                    (None, None) => true,
                    (Some(expected), Some(actual)) => expected.same_owner(&actual),
                    _ => false,
                }
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
    fn reserve_optional(
        &self,
        bytes: u64,
    ) -> io::Result<Box<dyn n2r_win32::shadow_native::report_memory::ReportMemoryLease>> {
        Ok(Box::new(SourceNativeMemoryLease(
            self.0
                .reserve_optional_ram(bytes)
                .map_err(io::Error::other)?,
        )))
    }
    /// The source observation's helper threads ask for their workspaces as
    /// spare memory: refused while the ledger is needed for what the run
    /// cannot do without, and the observation then takes the object in turn.
    fn reserve_spare(
        &self,
        bytes: u64,
    ) -> io::Result<Box<dyn n2r_win32::shadow_native::report_memory::ReportMemoryLease>> {
        Ok(Box::new(SourceNativeMemoryLease(
            self.0.reserve_spare_ram(bytes).map_err(io::Error::other)?,
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
        last_full: n2r_win32::verify_policy::LastFull::new(),
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
    let text = output
        .to_str()
        .context("Unicode source output path required")?;
    // The working volume is whichever local drive holds the output; it is
    // bound natively below and must be on a disk other than the source.
    let work_root = text
        .get(..3)
        .filter(|root| root.as_bytes()[0].is_ascii_alphabetic() && &root[1..] == ":\\")
        .context("resource source artifacts require an absolute drive-letter path")?
        .to_ascii_uppercase();
    ensure!(
        output.is_absolute()
            && !text[3..].contains(':')
            && !output
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "resource source artifacts must be an ordinary path on their working volume"
    );
    let journal = n2r_win32::discovery::discover(
        &work_root,
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
        arena.require_directory_ancestry(&self.parents)?;
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
    arena.require_directory_ancestry(&parents)?;
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
        && n2r_win32::windows_build::supported(policy.windows_version)
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

/// 8.3 short names on a data volume, refused with how many there are, one
/// of them and what removes them. Left to the evidence pipeline, the first
/// one stopped it with "source name/link domain is unsupported or
/// incomplete". (A Windows boot volume's become links beside the long names.)
pub(crate) fn refuse_short_names(raw: &PagedInspection) -> Result<()> {
    let (count, example) = short_name_census(raw)?;
    if count == 0 {
        return Ok(());
    }
    anyhow::bail!(
        "{count} file(s) and directories on this volume have an 8.3 short name{example}. ReFS has no short names: {}",
        ntfs_admission::SHORT_NAME_REMEDY
    )
}

/// How many objects of the volume have an 8.3 short name, and one of them
/// in words (" (for example \\path, also named SHORT~1)"), or nothing.
pub(crate) fn short_name_census(raw: &PagedInspection) -> Result<(u64, String)> {
    let mut count = 0u64;
    let mut first = None;
    for ordinal in 0..raw.blocker_count() {
        let blocker = raw.blocker(ordinal)?;
        if blocker.code == "dos_short_name" {
            count = count.checked_add(1).context("short-name count overflow")?;
            if first.is_none() {
                first = blocker.file_record_number;
            }
        }
    }
    let mut example = String::new();
    if count == 0 {
        return Ok((0, example));
    }
    if let Some(file) = first
        .map(|number| raw.find_record(number, None))
        .transpose()?
        .flatten()
    {
        let short = file
            .names
            .iter()
            .find(|name| name.namespace == 2)
            .map(|name| String::from_utf16_lossy(&name.name_utf16));
        if let (Some(path), Some(short)) = (
            ntfs_admission::paged::refused_object_path(raw, &file),
            short,
        ) {
            example = format!(" (for example \\{}, also named {short})", path.join("\\"));
        }
    }
    Ok((count, example))
}

fn guarded_collection_failure(
    source: GeneralFrozenPartition,
    workspace: Option<&SourceRamLease>,
    geometry: &ntfs_inspect::NtfsGeometry,
    events: &mut Vec<NativeEvent>,
    original: anyhow::Error,
    mut guard: Option<&mut crate::resource_preparation::early_guard::EarlyPreparationGuard>,
) -> anyhow::Error {
    eprintln!(
        "Source preparation refused before apply: {original:#}. Restoring unchanged NTFS; preserve the preparation recovery records until cleanup completes."
    );
    let _ = io::stderr().flush();
    let intent_error = if workspace.is_some() {
        guard
            .as_deref_mut()
            .and_then(|g| g.mark_live_cancel_intent().err())
    } else {
        None
    };
    // Preserve the existing actual source/fingerprint/full-hash restoration.
    let mut error = crate::resource_preparation::abort::after_collection_failure(
        source, workspace, geometry, events, original,
    );
    if let Some(intent_error) = intent_error {
        error = error.context(format!(
            "durable early cancellation intent did not close: {intent_error:#}"
        ));
    } else if workspace.is_some() {
        if let Some(guard) = guard {
            if let Err(closing) = guard.mark_live_cancelled(events) {
                error = error.context(format!("early cancellation remains unresolved; inspect the actual source and guard: {closing:#}"));
            }
        }
    }
    error
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
        Self::collect(
            binding, budget, policy, output, events, phase, None, false, None, None,
        )
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
        Self::prepare_with_failure_restore(
            binding, budget, policy, output, arena, events, phase, false,
        )
    }

    pub(crate) fn prepare_with_failure_restore(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        arena: &ArtifactArena,
        events: &mut Vec<NativeEvent>,
        phase: &mut &'static str,
        restore_on_failure: bool,
    ) -> Result<Self> {
        Self::prepare_with_guard(
            binding,
            budget,
            policy,
            output,
            arena,
            events,
            phase,
            restore_on_failure,
            None,
        )
    }

    pub(crate) fn prepare_with_guard(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        arena: &ArtifactArena,
        events: &mut Vec<NativeEvent>,
        phase: &mut &'static str,
        restore_on_failure: bool,
        guard: Option<crate::resource_preparation::early_guard::EarlyPreparationGuard>,
    ) -> Result<Self> {
        ensure!(
            arena.budget() == budget,
            "source arena differs from the observed resource budget"
        );
        let source = arena.reserve_group(
            ArtifactGroup::Source,
            SourceMetadataBudget::from_resource_budget(budget)?.scratch_bytes,
        )?;
        let native = arena.reserve_group(
            ArtifactGroup::Native,
            arena.native_page_budget()?.max_file_bytes,
        )?;
        Self::collect(
            binding,
            budget,
            policy,
            output,
            events,
            phase,
            Some((arena.clone(), source, native)),
            restore_on_failure,
            guard,
            None,
        )
    }
    /// New epoch over exact unchanged cached source bytes. All original wire
    /// bounds are retained; the caller supplies a freshly admitted real arena,
    /// source exclusion guard and independent canonical origin checksum.
    pub(crate) fn prepare_cached_exact_with_guard(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        arena: &ArtifactArena,
        events: &mut Vec<NativeEvent>,
        phase: &mut &'static str,
        restore_on_failure: bool,
        guard: crate::resource_preparation::early_guard::EarlyPreparationGuard,
        origin: &SourceCacheOriginPins,
        origin_sha256: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            arena.budget() == budget
                && policy == VerificationPolicy::ExtentIdentityV1
                && origin.canonical_sha256()? == origin_sha256,
            "cached source requires exact origin pin, extent policy and new actual arena"
        );
        let native = arena.reserve_group(
            ArtifactGroup::Native,
            arena.native_page_budget()?.max_file_bytes,
        )?;
        // Existing native pages already occupy working-volume space. Hash and
        // retain their real file owner before promising fresh Source/Auxiliary
        // capacity, so check_free credits only their actual allocation.
        let native_owner = native.adopt_existing(
            &origin.native_pages.path,
            &origin.native_pages.sha256,
            origin.native_pages.bytes,
        )?;
        let source = arena.reserve_group(
            ArtifactGroup::Source,
            SourceMetadataBudget::from_resource_budget(budget)?.scratch_bytes,
        )?;
        let result = Self::collect(
            binding,
            budget,
            policy,
            output,
            events,
            phase,
            Some((arena.clone(), source, native)),
            restore_on_failure,
            Some(guard),
            Some((origin, origin_sha256)),
        );
        drop(native_owner);
        result
    }
    fn collect(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
        output: &Path,
        events: &mut Vec<NativeEvent>,
        phase: &mut &'static str,
        groups: Option<(ArtifactArena, ArtifactGroupPermit, ArtifactGroupPermit)>,
        restore_on_failure: bool,
        mut early_preparation_guard: Option<
            crate::resource_preparation::early_guard::EarlyPreparationGuard,
        >,
        cached_origin: Option<(&SourceCacheOriginPins, [u8; 32])>,
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
        if cached_origin.is_some() {
            let (arena, _, _) = groups
                .as_ref()
                .context("cached source requires actual resumed arena ownership")?;
            ensure!(
                arena.budget() == budget && budget.ram_bytes <= available.available_physical_bytes,
                "cached source wire bounds lost actual current RAM/arena admission"
            );
            // Existing ordinary cache bytes already consume physical space.
            // The actual new_resuming arena and each adopted/future group
            // retain the current-free-space checks; do not charge old S again.
        } else {
            available.validate_budget(budget)?;
        }
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
        // A provider the converter does not know and passes over is named.
        for note in vss_before.provider_notes() {
            println!("Note: {note}");
        }
        ensure!(
            vss_before.source_volume_guid.eq_ignore_ascii_case(&volume),
            "VSS source route differs"
        );
        let source_io_ram = scratch.lease_ram(
            GeneralFrozenPartition::read_buffer_memory_bytes_for(&binding),
        )?;
        *phase = "source-freeze";
        let mut online = native_batch(events, |batch| {
            n2r_win32::GeneralPartitionReader::open(binding.clone(), batch)
        })?;
        let mut boot = [0; 512];
        online.read_exact(&mut boot)?;
        let geometry = ntfs_inspect::inspect_boot_sector(&boot, online.byte_len())?;
        ensure!(
            ntfs_admission::ResourceProfile::ResourceBoundedV4(None)
                .supports_source_geometry(&geometry),
            "source geometry exceeds the implemented resource profile"
        );
        native_batch(events, |batch| online.revalidate_route(batch))?;
        drop(online);
        let mount_paths = native_batch(events, |batch| {
            n2r_win32::capture_mount_paths_general(binding.clone(), batch)
        })?;
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
        // Prepay the failure-only pair of full-image hash passes before the
        // irreversible visibility change; healthy collection performs no such
        // scan. Diagnostics explicitly opt out of automatic restoration.
        let cleanup_workspace = if restore_on_failure {
            Some(scratch.lease_ram(5 * 1024 * 1024)?)
        } else {
            None
        };
        let source = if let Some(guard) = &mut early_preparation_guard {
            native_batch(events, |batch| {
                guard.isolate(binding.clone(), budget, batch)
            })?
        } else if restore_on_failure {
            native_batch(events, |batch| {
                GeneralFrozenPartition::isolate_observed_ntfs_with_resource_budget_restore_on_error(
                    binding.clone(),
                    budget,
                    batch,
                )
            })?
        } else {
            native_batch(events, |batch| {
                GeneralFrozenPartition::isolate_observed_ntfs_with_resource_budget(
                    binding.clone(),
                    budget,
                    batch,
                )
            })?
        };
        let mut source_slot = Some(source);
        let result = (|| -> Result<Self> {
            let mut source = source_slot
                .as_mut()
                .context("isolated source owner absent")?;
            let before = native_batch(events, |batch| source.state(batch))?;
            ensure!(
                before.disk_attributes == 3 && source.freeze_observation().is_some(),
                "actual observed source freeze absent"
            );
            let length = source.byte_len();
            *phase = "source-inspection";
            let mut reopened_cache = None;
            n2r_win32::perf::step("read NTFS records");
            let (raw, read_coverage) = if let Some((origin, pin)) = cached_origin {
                *phase = "source-cache-exact-byte-revalidation";
                let (arena, group, _) = groups
                    .as_ref()
                    .context("cache reopening requires actual source/native arena permits")?;
                let (raw, coverage, opened) = origin.open_raw(
                    &mut source,
                    budget,
                    &scratch,
                    group,
                    arena,
                    output,
                    pin,
                    events,
                )?;
                reopened_cache = Some(opened);
                (raw, coverage)
            } else {
                fp::inspect_recorded_with_layout_scope(
                    &mut source,
                    length,
                    budget,
                    policy,
                    &output.join("recorded-source"),
                    &scratch,
                    binding.layout_profile,
                )?
            };
            if let Some(cache) = reopened_cache.as_ref() {
                save(
                    output,
                    "source-cache-revalidation.json",
                    &serde_json::json!({
                "kind":"fresh-source-cache-revalidation-v2",
                "origin_sha256":hex::encode(cache.origin_sha256),
                "raw_inspection_origin":if cache.refresh.is_some(){"fresh_metadata_with_revalidated_cached_native_rows"}else{"cached_revalidated"},
                "metadata_refresh_performed":cache.refresh.is_some(),
                "user_semantic_refresh":cache.refresh.as_ref().map(|refresh|refresh.report()),
                "fresh_cached_complete_streams_verified":cache.fresh_complete_streams_verified,
                "fresh_cached_complete_payload_bytes":cache.fresh_complete_payload_bytes,
                "old_owner_or_guard_reused":false,"new_source_freeze_observed":true,
                "native_per_file_recollection_performed":false,
                // The saved Windows rows are compared again, not taken
                // again; this says which contents they did not read.
                WINDOWS_CONTENT_READS_SKIPPED:cache.windows_content_reads_skipped,
                "source_admitted":false,"execution_authorized":false}),
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
            }
            ensure!(
                raw.header().geometry == geometry,
                "frozen source geometry differs from online capture"
            );
            // A Windows volume was not read before it was frozen: what it
            // needs in memory is known here first. (A data volume was asked
            // the same while it was online.)
            if binding.layout_profile
                == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            {
                crate::run_memory::refuse_frozen_source(&raw, budget.ram_bytes)?;
            }
            // A data volume's short names refuse it, unless the run was
            // asked to leave them behind: they are then listed below, in
            // the run's records, and no object gets one on the new volume.
            let short_names_dropped = binding.layout_profile
                != n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
                && crate::short_name_disposition::dropped();
            if binding.layout_profile
                != n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
                && !short_names_dropped
            {
                refuse_short_names(&raw)?;
            }
            let inspection_sha = raw.canonical_sha256()?;
            // What the frozen source makes plain files of has to be in the
            // list the user agreed to before it was frozen: the subset rule
            // (`plain_consent::bind`). The ledger is kept with the run's
            // records below. A Windows boot volume is never offered them.
            let plain = if binding.layout_profile
                != n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
                && crate::plain_consent::takes_plain()
            {
                let (frozen, rows) = crate::plain_projection::census(&raw)?;
                let agreed = crate::plain_consent::bind_frozen(&frozen)?;
                Some(n2r_win32::plain_ledger::PlainLedger {
                    kind: n2r_win32::plain_ledger::LEDGER_KIND.to_owned(),
                    agreed_list_sha256: agreed,
                    frozen_list_sha256: frozen.sha256(),
                    source_inspection_sha256: inspection_sha.clone(),
                    rows,
                })
            } else {
                None
            };
            // Every object's paths are derived several times below (the
            // short-name plan, the selector's count, the comparison and the
            // admission policy), each through every directory above it. A
            // run that verifies once remembers each directory's step of
            // those walks, in a cache, until the comparison's gates are made.
            let directory_paths = n2r_win32::verify_policy::verifies_once()
                .then(|| ntfs_admission::paged::hold_directory_paths(&raw));
            // An inspection made by this process, not reopened from the
            // source cache: its stream evidence was decided here.
            let inspected_here = reopened_cache
                .is_none()
                .then(|| crate::ntfs_attestation::inspected_here(&raw));
            let storage_hint_ram = if binding.layout_profile
                == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            {
                Some(scratch.lease_ram(16384)?)
            } else {
                None
            };
            let storage_hint_normalization = if storage_hint_ram.is_some() {
                let proof = Arc::new(native_batch(events, |batch| {
                    source.observe_boot_storage_hint_normalization(batch)
                })?);
                native_batch(events, |batch| proof.revalidate(source, batch))?;
                Some(proof)
            } else {
                None
            };
            // A run that verifies once reads the source fingerprint the first
            // time on read lanes of the frozen source, on a thread of its own,
            // beside the work below that neither reads the source through
            // them nor needs the digest (the short-name plan, the backup boot
            // sector, log and label, the selection of objects and the target
            // security preflight). The read is joined before the volume is
            // mounted for its observation through Windows and before anything
            // takes the digest; it is the digest `hash` makes of the same
            // chunks. Without the memory for the lanes and the copy of the
            // ranges, a lane, or a thread, it is read in place below, as
            // every other run reads it.
            //
            // The read and its memory are held as a cache of this thread
            // (paid as one, and an `Evictable`): a reservation the work
            // beside it cannot do without that finds no room gives it up
            // (the read stops after the chunks it is reading and is waited
            // for, and its memory is returned) before it is refused, and the
            // fingerprint is then read in place where the read would have
            // been joined.
            let early_fingerprint =
                if n2r_win32::verify_policy::verifies_once() && reopened_cache.is_none() {
                    n2r_win32::perf::step("build source fingerprint and start its read");
                    let fingerprint = PagedSourceFingerprint::for_inspection(
                        &raw,
                        length,
                        policy,
                        &output.join("fingerprint"),
                    )?;
                    fingerprint.validate_inspection_reads(&read_coverage)?;
                    // The read's own refusals (a lane whose route differs
                    // from the frozen state) are the fingerprint's, as where
                    // it was read in place; the planning goes on under the
                    // phase it had.
                    *phase = "source-fingerprint";
                    let reading = fingerprint
                        .lane_reread_as_cache(source)?
                        .and_then(|(lanes, ram)| lanes.start().ok().map(|read| (read, ram)))
                        .map(|started| n2r_win32::evict::Evictable::new(Some(started)));
                    *phase = "source-inspection";
                    Some((fingerprint, reading))
                } else {
                    None
                };
            n2r_win32::perf::step("plan short-name links");
            let mut windows_aliases = if binding.layout_profile
                == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            {
                let mut aliases = crate::boot_alias::WindowsAliasDomain::derive(
                    &raw,
                    &output.join("windows-aliases"),
                    &scratch,
                )?;
                aliases.bind_storage_hint_normalization(
                    &raw,
                    Arc::clone(
                        storage_hint_normalization
                            .as_ref()
                            .context("Windows storage normalization witness absent")?,
                    ),
                )?;
                let aliases = Arc::new(aliases);
                aliases.require_source(&raw)?;
                save(
                    output,
                    "windows-alias-source.json",
                    &serde_json::json!({
                        "kind":"frozen-Windows-derived-alias-plan-v1", "source_inspection_sha256":inspection_sha,
                        "aliases":aliases.pin(), "alias_count":aliases.len(),
                        "source_normalization_authorized":false, "target_preservation_verified":false,
                    }),
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
                Some(aliases)
            } else {
                None
            };
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
            let (fingerprint, fingerprint_reading) = if let Some(early) = early_fingerprint {
                early
            } else {
                n2r_win32::perf::step("build and read source fingerprint");
                let fingerprint = if let Some(cache) = reopened_cache.as_mut() {
                    cache
                        .fingerprint
                        .take()
                        .context("cached fingerprint owner already consumed")?
                } else {
                    PagedSourceFingerprint::for_inspection(
                        &raw,
                        length,
                        policy,
                        &output.join("fingerprint"),
                    )?
                };
                fingerprint.validate_inspection_reads(&read_coverage)?;
                (fingerprint, None)
            };
            *phase = "source-fingerprint";
            // Read here unless it is being read on lanes (joined below).
            let mut source_sha = None;
            if fingerprint_reading.is_none() {
                if reopened_cache.is_none() && n2r_win32::verify_policy::verifies_once() {
                    n2r_win32::perf::step("read source fingerprint");
                }
                let hash = fingerprint.hash(&mut source)?;
                save(
                    output,
                    "source-frozen.json",
                    &serde_json::json!({"binding":binding,"source_sha256":hash,
                "inspection_sha256":inspection_sha,"fingerprint":fingerprint.pins(),"scope":fingerprint.report(),
                "state":before,"freeze_observation":source.freeze_observation(),"source_payload_writes":0}),
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
                source_sha = Some(hash);
            }
            n2r_win32::perf::step("verify backup boot sector, log and label");
            let backups = ntfs_backup::verify_domain(&mut source, length, &raw)?;
            let log = ntfs_log::verify_domain(&mut source, &raw)?;
            let label_frozen =
                source_volume_label::verify_domain(&mut source, &raw, label.label())?;
            save(
                output,
                "source-basis.json",
                &serde_json::json!({"backups":backups,"log_restart":log,
            "label":label_frozen,"source_admitted":false}),
                &scratch,
                &mut metadata,
                &mut reservations,
            )?;
            *phase = "source-observation-selectors";
            n2r_win32::perf::step("select objects and check target security");
            let selectors = PagedObservationRequest::new(&raw, &binding, budget, policy)?;
            let admission = selectors.admission();
            if binding.layout_profile
                == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            {
                *phase = "source-raw-target-security-preflight";
                let report = raw_target_security::inspect(&raw, admission, &scratch)?;
                save(
                    output,
                    "source-raw-target-security-preflight.json",
                    &report,
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
                ensure!(
                    report.scan_complete && report.pure_security_eligible,
                    "raw Windows source security exceeds the pure target-construction profile; see source-raw-target-security-preflight.json; native source diagnostics were not started"
                );
            }
            // The fingerprint read on lanes ends before the volume is mounted.
            if let Some(reading) = fingerprint_reading {
                n2r_win32::perf::step("join source fingerprint read");
                *phase = "source-fingerprint";
                let taken = reading.get_mut().and_then(|mut held| held.take());
                drop(reading);
                let hash = match taken {
                    Some((read, _ram)) => {
                        let hash = read.finish()?;
                        // As `hash` ends: its range stores are still as written.
                        fingerprint.revalidate()?;
                        hash
                    }
                    // Given up for a reservation the run needed: read here.
                    None => fingerprint.hash(&mut source)?,
                };
                save(
                    output,
                    "source-frozen.json",
                    &serde_json::json!({"binding":binding,"source_sha256":hash,
                "inspection_sha256":inspection_sha,"fingerprint":fingerprint.pins(),"scope":fingerprint.report(),
                "state":before,"freeze_observation":source.freeze_observation(),"source_payload_writes":0}),
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
                source_sha = Some(hash);
            }
            let source_sha = source_sha.context("the source fingerprint was not read")?;
            *phase = "source-observation";
            if let Some((arena, _, _)) = &groups {
                arena.require_native_allocation(admission)?;
            }
            let native_path = native_output.join("native.pages");
            let native_permit = if reopened_cache.is_some() {
                None
            } else {
                groups
                    .as_ref()
                    .map(|(_, _, group)| {
                        group.reserve_file(
                            &native_path,
                            admission.native_page_budget()?.max_file_bytes,
                        )
                    })
                    .transpose()?
            };
            let native_destination = native_permit
                .as_ref()
                .map_or(native_path.as_path(), |p| p.path());
            let native_payer_ram = groups
                .as_ref()
                .map(|_| scratch.lease_ram(std::mem::size_of::<SourceNativeMemory>() as u64 + 128))
                .transpose()?;
            let mut cached_native_artifact = None;
            n2r_win32::perf::step("observe source through Windows");
            let native = if let Some(cache) = reopened_cache.as_mut() {
                *phase = "source-cache-fresh-protected-runtime";
                let (arena, _, native_group) = groups
                    .as_ref()
                    .context("cache native arena permit absent")?;
                let artifact = match arena.retained_artifact(&cache.native.path) {
                    Ok(owner) => {
                        ensure!(
                            owner.same_group(native_group)
                                && owner.sha256() == cache.native.sha256
                                && owner.wire_bytes() == cache.native.bytes,
                            "cached native actual owner differs"
                        );
                        owner.revalidate()?;
                        owner
                    }
                    Err(_) => native_group.adopt_existing(
                        &cache.native.path,
                        &cache.native.sha256,
                        cache.native.bytes,
                    )?,
                };
                ensure!(
                    artifact.wire_bytes() == cache.native.bytes,
                    "cached native file byte count differs"
                );
                let proof = cache
                    .continuity
                    .take()
                    .context("cached source continuity owner already consumed")?;
                let observed = if let Some(refresh) = cache.refresh.as_ref() {
                    native_batch(events, |batch| {
                        source.observe_metadata_refreshed_cached_ntfs_files_with_memory(
                            &selectors,
                            &cache.native.path,
                            &cache.native.sha256,
                            admission.native_observation_budget()?,
                            proof,
                            &fingerprint,
                            refresh,
                            Arc::new(SourceNativeMemory(arena.clone())),
                            batch,
                        )
                    })?
                } else {
                    native_batch(events, |batch| {
                        source.observe_revalidated_cached_ntfs_files_with_memory(
                            &selectors,
                            &cache.native.path,
                            &cache.native.sha256,
                            admission.native_observation_budget()?,
                            proof,
                            &fingerprint,
                            Arc::new(SourceNativeMemory(arena.clone())),
                            batch,
                        )
                    })?
                };
                cached_native_artifact = Some(artifact);
                observed
            } else {
                native_batch(events, |batch| {
                    if let Some((arena, _, _)) = &groups {
                        source.observe_ntfs_files_paged_domain_with_memory(
                            &selectors,
                            native_destination,
                            admission.native_observation_budget()?,
                            true,
                            true,
                            Arc::new(SourceNativeMemory(arena.clone())),
                            batch,
                        )
                    } else {
                        source.observe_ntfs_files_paged_domain(
                            &selectors,
                            native_destination,
                            admission.native_observation_budget()?,
                            true,
                            true,
                            batch,
                        )
                    }
                })?
            };
            ensure!(
                groups.is_none() || native.domain().retained_storage_ram_accounted(),
                "actual native source owner lost its shared memory leases"
            );
            native.domain().revalidate()?;
            let native_artifact = if let Some(artifact) = cached_native_artifact {
                Some(artifact)
            } else {
                native_permit
                    .map(|permit| permit.verify_closed(native.domain().sha256()))
                    .transpose()?
            };
            let native_seal = groups
                .as_ref()
                .map(|(_, _, group)| group.seal())
                .transpose()?;
            let mut native_witness = serde_json::json!({
                "schema_version":1,
                "kind":"actual-protected-resource-source-native-witness",
                "source_inspection_sha256":inspection_sha,
                "source_fingerprint_before_native":source_sha,
                "native_pages_sha256":native.domain().sha256(),
                "native_observation_origin":native.origin(),
                "protected_windows_txf_markers":native.windows_txf_markers().map(|proof| proof.audit()),
                "protected_windows_object_ids":native.windows_object_ids().map(|proof| proof.audit()),
                "txf":native.txf(),
                "txf_error":native.txf_error(),
                "before":native.before(),
                "after":native.after(),
                "source_admitted":false,
                "execution_authorized":false
            });
            if let Some(skipped) = native.domain().header().content_reads_skipped {
                // What this run did not ask Windows to read, and what still
                // holds those streams. A resumed preparation reads this
                // record before it starts and refuses such a view.
                native_witness[WINDOWS_CONTENT_READS_SKIPPED] = serde_json::json!({
                    "objects":skipped.objects,
                    "streams":skipped.streams,
                    "logical_bytes":skipped.logical_bytes,
                    "requested_with":"--verify fast (verify once)",
                    "streams_skipped":"plain streams: one non-resident, uncompressed, unsparse DATA attribute of a user file, not assembled from an attribute list, initialized to its end, every run on disk",
                    "still_checked_through_windows":"each stream's enumeration, sizes, identity and EOF, its retrieval pointers held to the raw run list, and that its valid data runs to its end (FSCTL_QUERY_FILE_REGIONS, without reading it; a plain stream Windows does not say that of is read); the contents of every other stream its extents do not prove; directory listings",
                    "not_confirmed_through_windows":"the attribute-header fields that make a stream plain other than its valid data length (its flags and compression unit)",
                    "contents_held_by":"the raw digest of the clusters the run list names, then the shadow and the verification of the converted volume",
                    "row_marker":"logical_hash status not_read_plain_runs_v1"
                });
            }
            save(
                output,
                "source-native-witness.json",
                &native_witness,
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
            // That the read-only mount changed nothing is proved by reading
            // the fingerprint again. A run that verifies once reads it on
            // read lanes beside the comparison below (which does not read
            // the source) and holds the source to it before anything that
            // depends on it; every other run, and one without the memory for
            // the lanes, reads it here, as before.
            let reread_beside_comparison = n2r_win32::verify_policy::verifies_once();
            let mut reread_done = None;
            if !reread_beside_comparison {
                n2r_win32::perf::step("re-read source fingerprint");
                let after_hash = fingerprint.hash(source)?;
                let after = native_batch(events, |batch| source.state(batch))?;
                ensure!(
                    before == after
                        && source_sha == after_hash
                        && raw.canonical_sha256()? == inspection_sha,
                    "frozen source changed across actual native observation"
                );
                reread_done = Some((after, after_hash));
            }
            n2r_win32::perf::step("object ids and transactions");
            let mut indexes = if let Some(proof) = native.windows_object_ids_owned() {
                ensure!(
                    raw.is_windows_conversion() && proof.binding() == &binding,
                    "Windows object-ID witness belongs to another actual frozen source"
                );
                ntfs_internal::verify_domain_windows(
                    &mut source,
                    &raw,
                    &output.join("internal-indexes"),
                    &binding,
                    proof,
                )?
            } else {
                ntfs_internal::verify_domain(&mut source, &raw, &output.join("internal-indexes"))?
            };
            indexes.bind_native_quota(&native);
            if let Some(quotas) = indexes.quotas_not_carried() {
                println!("{}", crate::quota_disposition::note(quotas));
            }
            let data_object_ids = indexes.data_object_ids_owned();
            if let Some(object_ids) = &data_object_ids {
                println!(
                    "{} file(s) and directories have an object ID (Windows gives one to the target of a shortcut). ReFS has no object IDs: they are kept in this run's records and not carried over.",
                    object_ids.len()
                );
            }
            if let (Some(aliases), Some(proof)) =
                (windows_aliases.as_mut(), indexes.windows_object_ids_owned())
            {
                Arc::get_mut(aliases)
                    .context("Windows alias owner was shared before object-ID disposition binding")?
                    .bind_windows_object_ids(&raw, &binding, proof)?;
            }
            let transactions = ntfs_transactions::verify_domain(
                &raw,
                &log,
                source
                    .freeze_observation()
                    .context("original freeze witness absent")?,
                &native,
            )?;
            if let (Some(aliases), Some(proof)) = (
                windows_aliases.as_mut(),
                transactions.windows_txf_markers_owned(),
            ) {
                Arc::get_mut(aliases)
                    .context("Windows alias owner was shared before TxF disposition binding")?
                    .bind_windows_txf_markers(&raw, &binding, proof)?;
            }
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
            let mut refused = ntfs_admission::RefusedObjects::default();
            let mut no_dos = true;
            let (mut files, mut directories, mut streams, mut logical_bytes) =
                (0u64, 0u64, 0u64, 0u64);
            let (mut raw_directories, mut user_case_matched, mut internal_directories) =
                (0u64, 0u64, 0u64);
            // Short names that are left behind: counted and all archived.
            let mut short_names_left = 0u64;
            let mut short_names_writer = SortedRecordWriter::new(
                &output.join("short-names-not-carried"),
                *b"N2RSHORT",
                &scratch,
            )?;
            // Directories marked case-sensitive: counted, one named, all archived.
            // Whether their marks are set on the new volume is decided here,
            // once, for the Windows this runs on and the kind of volume.
            let case_mark_carry = n2r_win32::directory_case::CaseMarkCarry::of_this_windows(
                windows_aliases.is_some(),
            )?;
            let (mut case_marks, mut case_mark_example) = (0u64, None::<String>);
            // Whether the root directory (FILE 5) is one of them.
            let mut case_mark_on_root = false;
            let mut case_marks_writer = SortedRecordWriter::new(
                &output.join("case-sensitive-directories"),
                *b"N2RCASE1",
                &scratch,
            )?;
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
            let mut storage_hint_writer = storage_hint_normalization
                .as_ref()
                .map(|_| {
                    SortedRecordWriter::new(
                        &output.join("storage-hint-normalizations"),
                        *b"WINDSC01",
                        &scratch,
                    )
                })
                .transpose()?;
            let mut storage_hint_count = 0u64;
            // Where the check of the Windows rows was left to the comparison
            // below, the memory it cannot do without is reserved before the
            // spare memory of the re-read beside it (and of its batches).
            n2r_win32::attestation::NativeObservationDomain::reserve_deferred_validation(
                native.domain(),
            )?;
            let reread = if reread_beside_comparison {
                n2r_win32::perf::step("re-read source fingerprint");
                // Without the memory, a lane or a thread for it, the
                // fingerprint is read in place, as before.
                let started = fingerprint
                    .lane_reread(source)?
                    .and_then(|(lanes, ram)| lanes.start().ok().map(|read| (read, ram)));
                if started.is_none() {
                    let after_hash = fingerprint.hash(source)?;
                    let after = native_batch(events, |batch| source.state(batch))?;
                    ensure!(
                        before == after
                            && source_sha == after_hash
                            && raw.canonical_sha256()? == inspection_sha,
                        "frozen source changed across actual native observation"
                    );
                    reread_done = Some((after, after_hash));
                }
                started
            } else {
                None
            };
            n2r_win32::perf::step("compare raw and Windows views");
            // The selector above counted this same held source for the
            // admission; the comparison builds its own selector and is
            // handed that count, where it counted the source once more.
            let comparison = compare_domain(
                &raw,
                &binding,
                budget,
                policy,
                Some(admission),
                native.domain(),
                |row| {
                    let (file, role) = row.source_file_and_role(&raw)?;
                    if let Some(proof) = &storage_hint_normalization {
                        if let Some(normalization) =
                            crate::ntfs_storage_class::normalize(&file, proof)?
                        {
                            storage_hint_writer
                                .as_mut()
                                .context("storage normalization archive absent")?
                                .push(key(file.record_number), &normalization)?;
                            storage_hint_count = storage_hint_count
                                .checked_add(1)
                                .context("storage normalization count overflow")?;
                        }
                    }
                    no_dos &= file.names.iter().all(|name| name.namespace != 2);
                    if short_names_dropped && file.names.iter().any(|name| name.namespace == 2) {
                        short_names_writer.push(
                            key(file.record_number),
                            &ShortNamesNotCarried {
                                record_number: file.record_number,
                                sequence_number: file.sequence_number,
                                path: ntfs_admission::paged::refused_object_path(&raw, &file)
                                    .map(|path| format!("\\{}", path.join("\\"))),
                                short_names: file
                                    .names
                                    .iter()
                                    .filter(|name| name.namespace == 2)
                                    .map(|name| String::from_utf16_lossy(&name.name_utf16))
                                    .collect(),
                            },
                        )?;
                        short_names_left = short_names_left
                            .checked_add(1)
                            .context("short-name count overflow")?;
                    }
                    let issues = if let Some(role) = &role {
                        let action = match role.as_str() {
                            "$Volume" if indexes.covers_volume_object_id_domain(&raw, 3) => {
                                "replace_filesystem_internal_volume_identity"
                            }
                            "$Extend\\$ObjId" if indexes.internal_volume_object_id().is_some() => {
                                "replace_ntfs_internal_volume_identity_index"
                            }
                            "$LogFile" | "$Extend\\$UsnJrnl" => {
                                "start_new_filesystem_journal_epoch"
                            }
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
                        if let Some(aliases) = &windows_aliases {
                            ntfs_admission::paged::ordinary_user_issues_windows(
                                &raw, &file, admission, aliases,
                            )?
                        } else {
                            ntfs_admission::paged::ordinary_user_issues_data(
                                &raw,
                                &file,
                                admission,
                                data_object_ids.as_deref(),
                            )?
                        }
                    };
                    policy_rejections = policy_rejections
                        .checked_add(u64::from(!issues.is_empty()))
                        .context("policy refusal count overflow")?;
                    if !issues.is_empty() {
                        // Kept for the refusal message: which object, and why.
                        let path = ntfs_admission::paged::refused_object_path(&raw, &file);
                        refused.note(file.record_number, path.as_deref(), &issues);
                    }
                    if role.is_none() {
                        // Likewise: which object Windows shows differently, and how.
                        let differences = row.differences();
                        if !differences.is_empty() {
                            let path = ntfs_admission::paged::refused_object_path(&raw, &file);
                            refused.note_difference(
                                file.record_number,
                                path.as_deref(),
                                &differences,
                            );
                        }
                    }
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
                            if row.case_sensitive_mark {
                                case_mark_on_root |= file.record_number == 5;
                                let path = ntfs_admission::paged::refused_object_path(&raw, &file)
                                    .map(|path| format!("\\{}", path.join("\\")));
                                case_marks_writer.push(
                                    key(file.record_number),
                                    &CaseSensitiveDirectory {
                                        record_number: file.record_number,
                                        sequence_number: file.sequence_number,
                                        path: path.clone(),
                                    },
                                )?;
                                case_marks = case_marks
                                    .checked_add(1)
                                    .context("case-mark count overflow")?;
                                if case_mark_example.is_none() {
                                    case_mark_example = path;
                                }
                            }
                        }
                    }
                    rows_writer.push(
                        key(file.record_number),
                        &ObjectRow {
                            native: row,
                            user_issues: issues,
                            independent_internal_state_checks_passed: role.is_some()
                                && internal_bound,
                        },
                    )?;
                    row_count = row_count
                        .checked_add(1)
                        .context("comparison row count overflow")?;
                    Ok(())
                },
            )?;
            if let Some((read, _ram)) = reread {
                n2r_win32::perf::step("join source fingerprint re-read");
                let after_hash = read.finish()?;
                // As `hash` ends: its range stores are still as written.
                fingerprint.revalidate()?;
                let after = native_batch(events, |batch| source.state(batch))?;
                ensure!(
                    before == after
                        && source_sha == after_hash
                        && raw.canonical_sha256()? == inspection_sha,
                    "frozen source changed across actual native observation"
                );
                reread_done = Some((after, after_hash));
            }
            let (after, after_hash) =
                reread_done.context("the source fingerprint was not read again")?;
            let rows_pin = rows_writer.finish()?;
            let replacements_pin = replacements_writer.finish()?;
            let case_marks_pin = case_marks_writer.finish()?;
            let short_names_pin = short_names_writer.finish()?;
            if short_names_left != 0 {
                let (_, example) = short_name_census(&raw)?;
                println!(
                    "{}",
                    crate::short_name_disposition::note(short_names_left, &example)
                );
                save(
                    output,
                    crate::short_name_disposition::RECORDS_FILE,
                    &serde_json::json!({
                        "kind":"short-names-not-carried-over-v1",
                        "source_inspection_sha256":inspection_sha,
                        "objects":short_names_left, "records":&short_names_pin,
                        "requested_with":"the default for a data volume (or --short-names drop), agreed to at the conversion's question",
                        "target_has_short_names":false,
                        "policy":"every object is created under its long name; its 8.3 short names are listed in the records and not carried over",
                    }),
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
            }
            if let Some(ledger) = plain.as_ref().filter(|ledger| !ledger.rows.is_empty()) {
                ledger.validate().map_err(anyhow::Error::msg)?;
                println!(
                    "{} object(s) are converted to plain files, as agreed (list sha256 {}); each is kept in the run's records ({}).",
                    ledger.rows.len(),
                    ledger.agreed_list_sha256,
                    n2r_win32::plain_ledger::LEDGER_FILE
                );
                save(
                    output,
                    n2r_win32::plain_ledger::LEDGER_FILE,
                    ledger,
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
            }
            // A marked root leaves the whole volume without the mark, as
            // every such volume was converted before: the new root is never
            // empty when its mark could be set.
            let case_mark_carry = case_mark_carry.with_source_root(case_mark_on_root);
            if case_marks != 0 {
                println!(
                    "{}",
                    ntfs_admission::case_mark_note(
                        case_marks,
                        case_mark_example.as_deref(),
                        case_mark_carry
                    )
                );
                save(
                    output,
                    "source-case-sensitive-directories.json",
                    &case_mark_record(
                        case_mark_carry,
                        &inspection_sha,
                        case_marks,
                        serde_json::to_value(&case_marks_pin)?,
                    ),
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
            }
            let storage_hint_pin = storage_hint_writer
                .map(SortedRecordWriter::finish)
                .transpose()?;
            if let Some(proof) = &storage_hint_normalization {
                native_batch(events, |batch| proof.revalidate(source, batch))?;
                save(
                    output,
                    "source-storage-hint-normalizations.json",
                    &serde_json::json!({
                        "kind":"explicit-default-Windows-storage-hint-normalization-v1",
                        "source_inspection_sha256":inspection_sha, "source_device_witness":proof.as_ref(),
                        "normalized_record_count":storage_hint_count, "records":storage_hint_pin.as_ref(),
                        "target_storage_class_property_preserved":false,
                        "policy":"archive exact default class2/flags0 placement hint on fixed non-Spaces storage; refuse all other values",
                    }),
                    &scratch,
                    &mut metadata,
                    &mut reservations,
                )?;
            }
            ensure!(
                row_count == raw.file_count(),
                "complete per-object source comparison coverage differs"
            );
            // Existing data admission still requires no DOS aliases. An explicit
            // Windows owner may account for them in its held, exact derived plan;
            // actual target preservation remains a separate final obligation.
            n2r_win32::perf::step("short names and admission gates");
            let short_policy = short_names(
                &raw,
                &native,
                no_dos || windows_aliases.is_some() || short_names_dropped,
            );
            let mut unresolved_writer = SortedRecordWriter::new(
                &output.join("unresolved-source-blockers"),
                *b"N2RBLOCK",
                &scratch,
            )?;
            let mut unresolved_count = 0u64;
            let mut unresolved_examples: Vec<String> = Vec::new();
            for ordinal in 0..raw.blocker_count() {
                let blocker = raw.blocker(ordinal)?;
                let windows_alias_covered = if blocker.code == "dos_short_name" {
                    if let (Some(aliases), Some(number)) =
                        (&windows_aliases, blocker.file_record_number)
                    {
                        // The comparison above derived the alias paths of
                        // every ordinary object (one outside the NTFS
                        // internals: its record is 16 or later and outside
                        // $Extend) and refused the run where it could not.
                        // A run that verifies once does not derive them
                        // again for each of its short names (112,609 at the
                        // full Windows volume), nor copy the object for it.
                        let derived = if n2r_win32::verify_policy::verifies_once() {
                            raw.with_record(number, None, |file| {
                                ensure!(
                                    file.names.iter().any(|name| name.namespace == 2),
                                    "Windows alias blocker has no DOS source name"
                                );
                                Ok(file.record_number >= 16
                                    && file.metadata_role
                                        == ntfs_inspect::MetadataRole::OutsideExtendCandidate)
                            })?
                            .context("Windows alias blocker identity absent")?
                        } else {
                            false
                        };
                        if !derived {
                            let file = raw
                                .find_record(number, None)?
                                .context("Windows alias blocker identity absent")?;
                            ensure!(
                                file.names.iter().any(|name| name.namespace == 2),
                                "Windows alias blocker has no DOS source name"
                            );
                            let _ = aliases.user_paths(&raw, &file)?;
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if windows_alias_covered {
                    continue;
                }
                // Left behind at the user's word, and listed above.
                if blocker.code == "dos_short_name" && short_names_dropped {
                    continue;
                }
                if blocker.code == "unsupported_attribute"
                    && blocker.message == "Attribute type 0x100 needs a preservation policy"
                {
                    if let (Some(proof), Some(number)) =
                        (&storage_hint_normalization, blocker.file_record_number)
                    {
                        let file = raw
                            .find_record(number, None)?
                            .context("storage normalization blocker identity absent")?;
                        if crate::ntfs_storage_class::normalize(&file, proof)?.is_some() {
                            let role = ntfs_admission::paged::internal_role(&raw, &file)?;
                            let windows_user_txf = if let Some(aliases) = &windows_aliases {
                                aliases.windows_txf_accounted(&raw, &file)?
                            } else {
                                false
                            };
                            let root_txf_covered = transactions.binds_domain(&raw)
                                && (number == 5
                                    || role.as_deref() == Some("$Extend\\$RmMetadata\\$Txf")
                                    || windows_user_txf);
                            let all_covered = file
                                .attributes
                                .iter()
                                .filter(|attribute| attribute.type_code == 0x100)
                                .all(|attribute| {
                                    crate::ntfs_storage_class::recognized_default(attribute)
                                        || (root_txf_covered
                                            && ntfs_admission::recognized_root_txf(attribute))
                                });
                            if all_covered {
                                continue;
                            }
                        }
                    }
                }
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
                    if unresolved_examples.len() < 6 {
                        unresolved_examples.push(match blocker.file_record_number {
                            Some(number) => {
                                format!(
                                    "{}: {} (MFT record {number})",
                                    blocker.code, blocker.message
                                )
                            }
                            None => format!("{}: {}", blocker.code, blocker.message),
                        });
                    }
                    unresolved_count = unresolved_count
                        .checked_add(1)
                        .context("blocker count overflow")?;
                }
            }
            let unresolved_pin = unresolved_writer.finish()?;
            let mut gates = Vec::new();
            if let Some(aliases) = &windows_aliases {
                aliases.require_source(&raw)?;
                gate(
                    &mut gates,
                    "windows_alias_source_coverage",
                    true,
                    "every DOS source name is bound to a canonical same-parent derived target entry; native source identities remain unchanged",
                );
                gate(
                    &mut gates,
                    "windows_alias_target_preservation",
                    aliases.is_empty(),
                    "nonempty Windows alias plans require actual complete protected-target alias verification before writer admission",
                );
            }
            if let Some(proof) = &storage_hint_normalization {
                native_batch(events, |batch| proof.revalidate(source, batch))?;
                gate(
                    &mut gates,
                    "default_storage_hint_normalization",
                    storage_hint_pin.is_some(),
                    "exact default $DSC class2/flags0 metadata archived under the original frozen fixed non-Spaces device witness; ReFS property preservation is not claimed",
                );
            }
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
            let objects_detail = refused.detail(
                "every file and directory has to be one the converter carries over, and Windows has to see it as the raw volume does",
            );
            let unresolved_detail = format!(
                "{unresolved_count} condition(s) found on the volume that the converter does not take over: {}{}",
                unresolved_examples.join(" | "),
                if unresolved_count > unresolved_examples.len() as u64 {
                    " | ..."
                } else {
                    ""
                }
            );
            let indexes_detail = {
                let mut causes = Vec::new();
                for index in indexes
                    .indexes
                    .iter()
                    .filter(|index| !index.replacement_supported)
                {
                    let cause = ntfs_admission::index_refusal_cause(&index.role);
                    if !causes.contains(&cause) {
                        causes.push(cause);
                    }
                }
                if causes.is_empty() {
                    "the quota, object-ID and reparse-point indexes were not all verified against this inspection".to_owned()
                } else {
                    causes.join("; ")
                }
            };
            let case_detail = ntfs_admission::case_answer_requirement(
                directories.saturating_sub(user_case_matched),
                directories,
            );
            for (code, satisfied, detail) in [
                (
                    "geometry",
                    ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission))
                        .supports_source_geometry(&raw.header().geometry),
                    "the volume's sector, cluster, file-record or index-record size is not one the converter handles",
                ),
                (
                    "clean_volume",
                    clean,
                    ntfs_admission::CLEAN_VOLUME_REQUIREMENT,
                ),
                (
                    "volume_policy_flags",
                    policy_flags,
                    ntfs_admission::VOLUME_FLAGS_REQUIREMENT,
                ),
                (
                    "raw_allocation",
                    raw.allocation().status
                        == ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel,
                    "the volume's allocation bitmap and what its files occupy disagree: run `chkdsk <drive>: /f`",
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
                    "Windows did not answer for every file record the raw volume has",
                ),
                (
                    "native_volume_allocation",
                    true,
                    "compare_domain checked both complete native bitmap summaries against frozen allocation",
                ),
                ("objects", source_objects, objects_detail.as_str()),
                (
                    "resource_limits",
                    resource_counts,
                    "the volume holds no file at all (an empty volume is formatted, not converted), or its counts of files, directories and streams do not fit what was reserved for this run",
                ),
                (
                    "source_backups",
                    backups.binds_domain(&raw),
                    "the backup boot sector or the MFT mirror does not match the volume: run `chkdsk <drive>: /f`",
                ),
                (
                    "log_restart_pages",
                    log.binds_domain(&raw) && log.restart.candidate_clean_dismount,
                    "the NTFS log was not closed cleanly: dismount the volume properly (or restart Windows), or run `chkdsk <drive>: /f`",
                ),
                (
                    "remaining_inspection_refusals",
                    unresolved_count == 0,
                    unresolved_detail.as_str(),
                ),
                (
                    "frozen_device_basis",
                    before == after && source_sha == after_hash,
                    "the volume changed while it was being examined, although it was held offline and read-only",
                ),
                (
                    "internal_indexes",
                    indexes.binds_domain(&raw) && indexes.replacement_supported,
                    indexes_detail.as_str(),
                ),
                (
                    "transaction_freeze",
                    transactions.binds_domain(&raw),
                    "a transaction (TxF) was open on the volume, or its transaction log did not close: restart Windows, or dismount and remount the volume, and convert then",
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
                case_detail.as_str(),
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
            let mut source_views = serde_json::json!({"kind":"resource-source-views-v1","inspection":inspection_sha,
            "source_fingerprint":source_sha,"native_pages_sha256":native.domain().sha256(),"comparison_rows":rows_pin});
            if let Some(aliases) = &windows_aliases {
                source_views["windows_alias_plan"] = serde_json::to_value(aliases.pin())?;
            }
            if let Some(pin) = &storage_hint_pin {
                source_views["storage_hint_normalizations"] = serde_json::to_value(pin)?;
            }
            if reopened_cache.is_some() {
                source_views["native_observation_origin"] = serde_json::to_value(native.origin())?;
            }
            let source_views_sha = json_sha(&source_views, scratch.budget().scratch_bytes / 2)?;
            drop(inspected_here);
            drop(directory_paths);
            n2r_win32::perf::step("reopen comparison stores");
            let rows = SortedRecordStore::open(&rows_pin, &scratch)?;
            let unresolved = SortedRecordStore::open(&unresolved_pin, &scratch)?;
            let replacements = SortedRecordStore::open(&replacements_pin, &scratch)?;
            let storage_hint_records = storage_hint_pin
                .as_ref()
                .map(|pin| SortedRecordStore::open(pin, &scratch))
                .transpose()?;
            // All preceding fallible collection used the same live source owner.
            // Move it only once the complete source context is ready to form.
            let source = source_slot.take().context("isolated source owner absent")?;
            let mut context = Self {
                early_preparation_guard: early_preparation_guard.take(),
                source: ResourceSourceOwner::dedicated(source),
                raw,
                windows_aliases,
                carry_case_marks: case_mark_carry.carried() && case_marks != 0,
                storage_hint_normalization,
                storage_hint_records,
                _storage_hint_ram: storage_hint_ram,
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
                _cache_artifacts: reopened_cache,
            };
            n2r_win32::perf::step("finish source evidence");
            let finishing = (|| -> Result<()> {
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
                Ok(())
            })();
            if let Err(error) = finishing {
                return Err(guarded_collection_failure(
                    context.source.into_dedicated()?,
                    cleanup_workspace.as_ref(),
                    &geometry,
                    events,
                    error,
                    context.early_preparation_guard.as_mut(),
                ));
            }
            Ok(context)
        })();
        match result {
            Ok(context) => Ok(context),
            Err(error) => match source_slot.take() {
                Some(source) => Err(guarded_collection_failure(
                    source,
                    cleanup_workspace.as_ref(),
                    &geometry,
                    events,
                    error,
                    early_preparation_guard.as_mut(),
                )),
                None => Err(error),
            },
        }
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
            windows_alias_plan: self.windows_aliases.as_ref().map(|aliases| aliases.pin()),
            storage_hint_normalizations: self
                .storage_hint_records
                .as_ref()
                .map(SortedRecordStore::pin),
            gates: &self.gates,
            source_group_bytes: self.scratch.used_bytes(),
            source_native_groups_sealed: self.source_seal.is_some() && self.native_seal.is_some(),
            native_observation_origin: matches!(
                self.native.origin(),
                n2r_win32::NativeSourceObservationOrigin::RevalidatedCachedRows { .. }
            )
            .then_some(self.native.origin()),
            source_group_allocated_bytes: self.source_seal.as_ref().map(|s| s.allocated_bytes()),
            native_group_allocated_bytes: self.native_seal.as_ref().map(|s| s.allocated_bytes()),
            shared_artifact_arena_complete: false,
            target_preservation_complete: false,
            source_admitted: false,
            certificate_issued: false,
            execution_authorized: false,
        }
    }
    pub(crate) fn cache_metadata_refreshed(&self) -> bool {
        self._cache_artifacts
            .as_ref()
            .is_some_and(|cache| cache.refresh.is_some())
    }
    pub(crate) fn authorize_cached_expected_rebind(
        &self,
        body: &crate::shadow_tree::PagedExpectedTree,
    ) -> Result<CachedExpectedRebind> {
        self.require_source_evidence()?;
        self.revalidate_evidence()?;
        let cache = self
            ._cache_artifacts
            .as_ref()
            .context("actual source cache owner absent")?;
        let join = cache
            .refresh
            .as_ref()
            .context("actual live user semantic refresh absent")?;
        ensure!(
            self.raw.is_windows_conversion()
                && matches!(
                    self.native.origin(),
                    n2r_win32::NativeSourceObservationOrigin::MetadataRefreshedCachedRows { .. }
                )
                && self.native.windows_txf_markers().is_some()
                && self.native.windows_object_ids().is_some(),
            "expected reuse requires actual metadata-refreshed Windows native owners"
        );
        let aliases = self
            .windows_aliases
            .as_ref()
            .context("current Windows alias owner absent")?;
        aliases.require_source(&self.raw)?;
        let facts = join.expected_reuse_facts(
            &self.inspection_sha,
            self.native.domain().sha256(),
            body,
            self.admission,
        )?;
        crate::shadow_tree::source_pages::SourceExpectedDomain::verify_cached_body(
            &self.raw,
            self.native.domain(),
            self.admission,
            aliases,
            body,
            &self.scratch,
        )?;
        Ok(CachedExpectedRebind {
            facts,
            source_owner: self.source_owner_identity(),
        })
    }
    pub(crate) fn cached_auxiliary_group(&self) -> Option<ArtifactGroupPermit> {
        self._cache_artifacts
            .as_ref()
            .map(|cache| cache.auxiliary_group.clone())
    }
    pub(crate) fn authorize_cached_expected_exact_rebind(
        &self,
        body: &crate::shadow_tree::PagedExpectedTree,
    ) -> Result<CachedExpectedRebind> {
        self.require_source_evidence()?;
        self.revalidate_evidence()?;
        ensure!(
            self._cache_artifacts.is_some()
                && self.raw.is_windows_conversion()
                && matches!(
                    self.native.origin(),
                    n2r_win32::NativeSourceObservationOrigin::RevalidatedCachedRows { .. }
                ),
            "exact expected rebind requires actual byte-continuity native cache owner"
        );
        let aliases = self
            .windows_aliases
            .as_ref()
            .context("current Windows aliases absent")?;
        crate::shadow_tree::source_pages::SourceExpectedDomain::verify_cached_body(
            &self.raw,
            self.native.domain(),
            self.admission,
            aliases,
            body,
            &self.scratch,
        )?;
        let mut hash = Sha256::new();
        hash.update(b"n2r-exact-current-source-and-current-projection-v1\0");
        hash.update(self.inspection_sha.as_bytes());
        hash.update(self.source_sha.as_bytes());
        hash.update(self.native.domain().sha256().as_bytes());
        hash.update(body.file_sha256().as_bytes());
        let facts = crate::shadow_tree::ExpectedBindingFacts {
            schema_version: 1,
            verification_kind: "exact-current-source-and-current-projection-v1".into(),
            body_file_sha256: body.file_sha256().to_owned(),
            body_semantic_sha256: body.semantic_sha256().to_owned(),
            original_admission: body
                .header()
                .resource_admission
                .context("cached original admission absent")?,
            effective_admission: self.admission,
            profile: body.profile().to_owned(),
            logical_bytes: body.logical_bytes(),
            objects: body.len() as u64,
            pending_roles: body.internal_replacement_pending().to_vec(),
            native_file_sha256: self.native.domain().sha256().to_owned(),
            user_join_sha256: hex::encode(hash.finalize()),
        };
        facts.validate(self.admission, body.file_sha256(), body.semantic_sha256())?;
        Ok(CachedExpectedRebind {
            facts,
            source_owner: self.source_owner_identity(),
        })
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
                        | "windows_alias_target_preservation"
                ) && !g.satisfied
            })
            .collect();
        ensure!(
            failed.is_empty(),
            "{}",
            ntfs_admission::source_refusal("resource", failed.iter().copied())
        );
        Ok(())
    }
    pub fn require_source_gates(&self) -> Result<()> {
        self.require_source_evidence()?;
        ensure!(
            self.windows_aliases
                .as_ref()
                .is_none_or(|aliases| aliases.is_empty()),
            "Windows alias target preservation needs its opaque protected-target witness before source writer admission"
        );
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
        native_batch(events, |batch| {
            self.source.require_complete_partition_admission(batch)
        })?;
        self.require_source_evidence()?;
        if let Some(aliases) = &self.windows_aliases {
            target.require_windows_alias_source(
                aliases,
                self.admission.source_inspection_sha256,
                expected,
            )?;
        }
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
        expected.require_rebind_source(self.source_owner_identity())?;
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
            partition_owner: self.source.partition_token(),
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
        self.admission.validate()?;
        ensure!(
            (self.admission.schema_version == 2) == self.raw.is_windows_conversion(),
            "source purpose differs from the selected native artifact allocation"
        );
        if let Some(arena) = &self.arena {
            arena.require_native_allocation(self.admission)?;
        }
        if let Some(guard) = &self.early_preparation_guard {
            guard.revalidate()?;
        }
        if let Some(output) = &self._output_basis {
            output.revalidate(
                self.source.binding(),
                self.arena.as_ref().context("source arena owner absent")?,
            )?;
        }
        self.raw.revalidate()?;
        if let Some(aliases) = &self.windows_aliases {
            aliases.require_source(&self.raw)?;
        }
        if let Some(proof) = &self.storage_hint_normalization {
            ensure!(
                proof.binding() == self.source.binding()
                    && self
                        .windows_aliases
                        .as_ref()
                        .is_some_and(|aliases| aliases.has_storage_hint_owner(proof)),
                "Windows storage normalization runtime owner changed"
            );
            self.storage_hint_records
                .as_ref()
                .context("Windows storage normalization records absent")?
                .revalidate()?;
        }
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
            // Held open since it was hashed; re-read at most once per gate.
            if !n2r_win32::verify_policy::full(&pin.last_full) {
                continue;
            }
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
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::SourceRecheck);
        ensure!(
            self.source.freeze_observation().is_some(),
            "original live NTFS freeze witness was consumed by an apply-intent attempt"
        );
        self.revalidate_evidence()?;
        self.native
            .require_cache_owner(self.source.require_dedicated()?, events)?;
        if let Some(proof) = &self.storage_hint_normalization {
            let source = self.source.require_dedicated()?;
            native_batch(events, |batch| proof.revalidate(source, batch))?;
        }
        let before = native_batch(events, |batch| self.source.state(batch))?;
        ensure!(
            before == self.before && before.disk_attributes == 3,
            "original frozen source state changed"
        );
        // The source is offline, read-only and held, which the state check
        // above confirms. Reading all of its metadata again is a full check:
        // it runs at the gate before the first write to the source.
        static LAST_FULL: n2r_win32::verify_policy::LastFull =
            n2r_win32::verify_policy::LastFull::new();
        if !n2r_win32::verify_policy::full(&LAST_FULL) {
            return Ok(());
        }
        let digest = self
            .fingerprint
            .hash(self.source.require_dedicated_mut()?)?;
        let after = native_batch(events, |batch| self.source.state(batch))?;
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
        // Giving the unchanged volume back is a point where the source is
        // verified for real: inside this gate the fingerprint is re-read.
        let _gate = n2r_win32::verify_policy::Gate::enter();
        self.recheck_source(events)?;
        checkpoint(events)?;
        let binding = self.source.binding().clone();
        let length = self.source.byte_len();
        // The SDK repeats the entire SHA-256 while holding the same frozen
        // source. Pay the single 4 MiB hashing buffer and state-query overhead
        // before either pass; this expensive path is only used after failure.
        let _ram = self.scratch.lease_ram(5 * 1024 * 1024)?;
        let sha = if n2r_win32::verify_policy::checks_once() {
            "0".repeat(64)
        } else {
            hex::encode(n2r_win32::sha256_native::hash_range(
                &mut self.source,
                0,
                length,
            )?)
        };
        self.recheck_source(events)?;
        checkpoint(events)?;
        ensure!(
            self.source.freeze_observation().is_some(),
            "pre-AP NTFS freeze witness was consumed"
        );
        if let Some(guard) = &mut self.early_preparation_guard {
            guard.mark_live_cancel_intent()?;
        }
        native_batch(events, |batch| {
            self.source.bring_original_online_unchanged(&sha, batch)
        })
        .context("original NTFS online transition failed; source may require rediscovery")?;
        checkpoint(events)?;
        let mounted = native_batch(events, |batch| {
            n2r_win32::rediscover_general_volume_wait(binding.clone(), batch)
        })?;
        n2r_win32::volume_label::validate_original_partition(&binding, &mounted)?;
        ensure!(
            native_batch(events, |batch| n2r_win32::mounted_filesystem_general(
                mounted.clone(),
                batch
            ))? == "NTFS",
            "original source did not return as NTFS"
        );
        if let Some(guard) = &mut self.early_preparation_guard {
            guard.mark_live_cancelled(events)?;
        }
        checkpoint(events)?;
        // Bringing NTFS online can leave the original letter unassigned even
        // with automount enabled. As in rollback, restore only letters still
        // absent and never claim one that now belongs to a different volume.
        match native_batch(events, |batch| {
            n2r_win32::capture_mount_paths_general(mounted.clone(), batch)
        }) {
            Ok(current) => {
                for letter in self.mount_paths.paths.iter().filter(|path| {
                    crate::resource_finalize::is_drive_letter_root(path)
                        && !current
                            .paths
                            .iter()
                            .any(|actual| actual.eq_ignore_ascii_case(path))
                }) {
                    if let Err(error) = native_batch(events, |batch| {
                        n2r_win32::restore_drive_letter_general_on(
                            mounted.clone(),
                            letter,
                            "NTFS",
                            batch,
                        )
                    }) {
                        eprintln!(
                            "NTFS is back, but drive letter {letter} could not be restored: {error}. Give the volume a letter in Disk Management."
                        );
                    }
                }
            }
            Err(error) => eprintln!(
                "NTFS is back, but its drive letters could not be checked: {error}. Check the volume in Disk Management."
            ),
        }
        Ok(mounted)
    }

    pub(crate) fn has_original_freeze_witness(&self) -> bool {
        self.source.freeze_observation().is_some()
    }
    pub(crate) fn early_preparation_guard_pin(
        &self,
    ) -> Option<crate::resource_preparation::early_guard::GuardPin> {
        self.early_preparation_guard
            .as_ref()
            .map(|guard| guard.pin())
    }
    pub(crate) fn early_preparation_guard_artifact(&self) -> Option<ArtifactLease> {
        self.early_preparation_guard
            .as_ref()
            .map(|guard| guard.intent_artifact())
    }
    pub(crate) fn delegate_preparation_guard(
        &mut self,
        publication: &Path,
        sha: &str,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        self.early_preparation_guard
            .as_mut()
            .context("fresh V4 preparation guard absent")?
            .delegate(publication, sha, events)
    }
    pub(crate) fn require_preparation_delegated(
        &self,
        publication: &Path,
        sha: &str,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        self.early_preparation_guard
            .as_ref()
            .context("fresh V4 preparation guard absent")?
            .require_delegated(publication, sha, events)
    }
    pub(crate) fn early_preparation_delegated(&self) -> Result<bool> {
        self.early_preparation_guard
            .as_ref()
            .map(|guard| guard.delegated())
            .transpose()
            .map(|s| s.unwrap_or(false))
    }
    pub fn inspection(&self) -> &PagedInspection {
        &self.raw
    }
    pub fn windows_aliases(&self) -> Option<Arc<crate::boot_alias::WindowsAliasDomain>> {
        self.windows_aliases.as_ref().map(Arc::clone)
    }
    pub fn derive_projection(
        &mut self,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
    ) -> Result<crate::shadow_tree::source_pages::SourceExpectedDomain> {
        // The frozen source evidence has already completed validation. Projection
        // walks its file domain in ordinal order, so return the optional
        // whole-inventory cache before paying for projection rows/sorters.
        // Authenticated readers, compact indexes and all proof owners remain.
        // The decoded file rows stay where the run verifies once, the
        // ledgers have room for the projection's working memory beside them
        // and its spare memory would still be granted beside both:
        // the projection would otherwise decode every row again to keep it
        // once more.
        let working = crate::shadow_tree::source_pages::SourceExpectedDomain::working_ram_bound(
            self.raw.file_count(),
            admission,
            scratch,
        );
        self.raw.release_inventory_resident_cache_before(
            scratch,
            working,
            crate::shadow_tree::source_pages::SourceExpectedDomain::largest_working_reservation(
                admission,
            ),
            crate::shadow_tree::source_pages::SourceExpectedDomain::spare_ram_bound(),
        );
        // A run that verifies once (`--verify fast`) takes what the
        // comparison evaluated of each object (its user issues, metadata and
        // security views and case mark) from the comparison's rows (owner's
        // decision D2, #250); a thorough run, a diagnosis and
        // `--recheck-everything` evaluate them again. The comparison held the
        // metadata to the Windows rules exactly where this projection does.
        let compared = (n2r_win32::verify_policy::verifies_once()
            && self.windows_aliases.is_some() == self.raw.is_windows_conversion())
        .then_some(&self.rows);
        if let Some(aliases) = &self.windows_aliases {
            crate::shadow_tree::source_pages::SourceExpectedDomain::derive_windows(
                &self.raw,
                self.native.domain(),
                compared,
                admission,
                output,
                scratch,
                aliases,
            )
        } else {
            crate::shadow_tree::source_pages::SourceExpectedDomain::derive_data(
                &self.raw,
                self.native.domain(),
                compared,
                admission,
                output,
                scratch,
                self.indexes.data_object_ids_owned().as_deref(),
                self.carry_case_marks,
            )
        }
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
    pub fn source_and_inspection(
        &mut self,
    ) -> Result<(&mut GeneralFrozenPartition, &PagedInspection)> {
        // Existing dedicated callers keep exact native guards. Partition
        // scope cannot enter whole-disk transitions through this adapter.
        Ok((self.source.require_dedicated_mut()?, &self.raw))
    }
    pub(crate) fn scoped_source_and_inspection(
        &mut self,
    ) -> (&mut ResourceSourceOwner, &PagedInspection) {
        (&mut self.source, &self.raw)
    }
    /// Runtime association with this exact retained frozen source. A saved
    /// value is not an ownership, device, admission, or write capability.
    pub(crate) fn source_owner_identity(&self) -> usize {
        self.source.owner_identity()
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

#[cfg(test)]
mod case_mark_tests {
    use super::case_mark_record;
    use n2r_win32::directory_case::{CaseMarkCarry, WhyNotCarried};

    #[test]
    fn the_record_of_marked_directories_says_whether_the_target_carries_the_mark() {
        let records = serde_json::json!({"sha256": "ab"});
        let carried = case_mark_record(CaseMarkCarry::Carried, "cd", 7, records.clone());
        assert_eq!(
            carried["kind"],
            "case-sensitive-directory-marks-carried-over-v1"
        );
        assert_eq!(carried["target_has_the_mark"], true);
        assert!(
            carried["policy"]
                .as_str()
                .unwrap()
                .contains("reads the mark back")
        );

        let not_carried = case_mark_record(
            CaseMarkCarry::NotCarried(WhyNotCarried::Windows {
                version: [10, 0, 26300],
                server: false,
            }),
            "cd",
            7,
            records.clone(),
        );
        // The kind a run wrote before the mark was carried anywhere.
        assert_eq!(
            not_carried["kind"],
            "case-sensitive-directory-marks-not-carried-over-v1"
        );
        assert_eq!(not_carried["target_has_the_mark"], false);
        let policy = not_carried["policy"].as_str().unwrap();
        assert!(
            policy.starts_with("the mark is not set on the target")
                && policy.contains("this is Windows 10.0.26300"),
            "{policy}"
        );
        // A marked root: the record of a run that sets no mark, with why.
        let marked_root = case_mark_record(
            CaseMarkCarry::Carried.with_source_root(true),
            "cd",
            7,
            records.clone(),
        );
        assert_eq!(
            marked_root["kind"],
            "case-sensitive-directory-marks-not-carried-over-v1"
        );
        assert_eq!(marked_root["target_has_the_mark"], false);
        assert!(
            marked_root["policy"]
                .as_str()
                .unwrap()
                .contains("root directory is itself marked")
        );
        // All keep the same source records, and none admits two names
        // that differ only by case.
        for record in [&carried, &not_carried, &marked_root] {
            assert_eq!(record["records"], records);
            assert_eq!(record["directories"], 7);
            assert_eq!(record["source_inspection_sha256"], "cd");
            assert_eq!(record["names_that_differ_only_by_case"], 0);
            assert!(
                record["policy"]
                    .as_str()
                    .unwrap()
                    .contains("two names differing only by case is refused")
            );
        }
    }
}
