//! Native creation on a separately bound empty ReFS volume. Never writes the
//! source disk, manufactures ReFS bytes or grants conversion authority.
pub mod cache_refresh;
mod hard_links;
pub use hard_links::Observation as HardLinkObservation;
mod evacuation;
pub mod private_tree;
mod unwritten;
pub mod valid_data_probe;
use crate::{
    attestation::{PrivilegeState, Snapshot},
    attestation_native::{Privileges, snapshot},
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    layout::{self, DiskBinding, invalid},
    namespace_layout,
    native::{self, NativeEvent},
    stream_layout,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{FILETIME, INVALID_HANDLE_VALUE},
    Security::{GetSecurityDescriptorLength, IsValidSecurityDescriptor, SECURITY_ATTRIBUTES},
    Storage::FileSystem::{
        BackupWrite, CreateDirectoryW, CreateFileW, GetDiskFreeSpaceW,
        GetFileInformationByHandleEx, GetVolumeInformationByHandleW, GetVolumeInformationW,
        SetFileInformationByHandle, SetFileTime,
    },
    System::IO::DeviceIoControl,
};

// Shared native format check for expanded observations and live construction.
fn query_refs_314_volume_data(volume: &File, partition_bytes: u64) -> io::Result<u64> {
    let data = ctl(volume, 0x000902d8, &[], 256)?;
    if data.len() < 64
        || !(64..=data.len()).contains(&(layout::u32_at(&data, 0)? as usize))
        || layout::u32_at(&data, 4)? != 3
        || layout::u32_at(&data, 8)? != 14
        || layout::u64_at(&data, 24)? != partition_bytes / 512
        || layout::u64_at(&data, 32)? != partition_bytes / 4096
        || layout::u32_at(&data, 56)? != 512
        || layout::u32_at(&data, 60)? != 4096
    {
        return Err(invalid("protected ReFS volume-data profile differs"));
    }
    Ok(layout::u64_at(&data, 32)?)
}

pub struct Input<'a> {
    pub components: &'a [String],
    pub additional_names: &'a [Vec<String>],
    pub directory: bool,
    pub times: [u64; 4],
    pub attributes: u32,
    pub security: &'a [u8],
    pub expected_api_security: Option<&'a [u8]>,
    pub payload: &'a [u8],
    /// Hash-only expectations are accepted for ordinary shadow streaming and
    /// verification. The source reader supplies bytes during construction.
    pub expected_length: Option<u64>,
    pub expected_sha256: Option<&'a str>,
    pub source_offset: Option<u64>,
    pub source_runs: Vec<SourceRun>,
}
#[derive(Clone, Debug)]
pub struct SourceRun {
    pub logical_offset: u64,
    pub physical_offset: Option<u64>,
    pub length: u64,
}
impl Input<'_> {
    fn logical_length(&self) -> u64 {
        self.expected_length.unwrap_or(self.payload.len() as u64)
    }
    /// The expected [`crate::content_digest`] (historical name).
    fn logical_sha256(&self) -> String {
        self.expected_sha256
            .map(str::to_owned)
            .unwrap_or_else(|| crate::content_digest::of(self.payload))
    }
}
fn valid_shadow_component(s: &str) -> bool {
    let stem = s
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !s.is_empty()
        && s.len() <= 100
        && !s.ends_with(['.', ' '])
        && s.bytes().all(|byte| {
            (byte == b' ' || byte.is_ascii_graphic()) && !b"<>:\"/\\|?*".contains(&byte)
        })
        && ![
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ]
        .contains(&stem.as_str())
}
/// `observe` over `items` on up to eight threads, results in item order. Items
/// are claimed in order, so after a failure every unclaimed item follows it;
/// the first failure in item order is returned.
fn observe_in_parallel<T: Sync, U: Send>(
    items: &[T],
    observe: impl Fn(&T) -> io::Result<U> + Sync,
) -> io::Result<Vec<U>> {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let workers = std::thread::available_parallelism()
        .map_or(1, |cores| cores.get())
        .clamp(1, 8)
        .min(items.len());
    if workers <= 1 {
        return items.iter().map(observe).collect();
    }
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let slots: Vec<Mutex<Option<io::Result<U>>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while !failed.load(Ordering::Acquire) {
                    let index = next.fetch_add(1, Ordering::AcqRel);
                    let Some(item) = items.get(index) else {
                        break;
                    };
                    let result = observe(item);
                    if result.is_err() {
                        failed.store(true, Ordering::Release);
                    }
                    if let Ok(mut slot) = slots[index].lock() {
                        *slot = Some(result);
                    }
                }
            });
        }
    });
    let mut reports = Vec::with_capacity(items.len());
    for slot in slots {
        let slot = slot
            .into_inner()
            .map_err(|_| io::Error::other("parallel observation slot poisoned"))?;
        match slot {
            Some(result) => reports.push(result?),
            None => return Err(io::Error::other("parallel observation stopped early")),
        }
    }
    Ok(reports)
}

/// The [`crate::content_digest`] of exactly `length` bytes, then confirmed EOF.
/// Reads are at most 4 MiB; the buffer never exceeds the stream.
fn hash_exact_stream(reader: &mut impl Read, length: u64) -> io::Result<String> {
    const REQUEST: u64 = 4 * 1024 * 1024;
    let mut hash = crate::content_digest::Hasher::new();
    let mut remaining = length;
    let mut buffer = vec![0u8; length.clamp(1, REQUEST) as usize];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| invalid("stream read bound"))?;
        reader.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if reader.read(&mut buffer[..1])? != 0 {
        return Err(invalid("converted stream has data beyond expected EOF"));
    }
    Ok(hash.finish())
}

fn resident_allocation(logical: u64, allocated: u64) -> bool {
    logical <= 4096 && allocated < 4096 && allocated >= logical
}

fn volume_label_matches(
    actual: &[u16],
    expected: Option<&crate::volume_label::VolumeLabel>,
) -> io::Result<bool> {
    if let Some(label) = expected {
        label.validate()?;
        Ok(actual == label.utf16())
    } else {
        Ok(actual == "n2r-retained-shadow".encode_utf16().collect::<Vec<_>>())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ProbeRoot,
    RestoreRootOnly,
    Construct,
    ConstructRetaining,
    Verify,
    /// Metadata-only observation; accepted only through a protected native
    /// read-only lease. It never reads or verifies placeholder payload bytes.
    ObserveLayout,
}
#[derive(Debug, Serialize)]
pub struct CandidateReport {
    pub legacy: crate::bitmap_layout::Candidate,
    pub metadata_inclusive: crate::bitmap_layout::Candidate,
    pub legacy_page_proof: crate::bitmap_paging::Proof,
    pub metadata_page_proof: crate::bitmap_paging::Proof,
}
#[derive(Debug, Serialize)]
pub struct ObjectReport {
    pub components: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_names: Vec<HardLinkObservation>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub logical_sha256: Option<String>,
    /// Explicit complete-map encoding when page proof is present; empty for
    /// the separately checked resident/empty cases.
    pub retrieval: Vec<u8>,
    /// Present for an assembled allocated map; raw page digests are separate.
    pub retrieval_page_proof: Option<crate::retrieval_paging::Proof>,
    pub resident_data: bool,
    pub cached_validity: Vec<u8>,
    pub storage_validity: Vec<u8>,
    pub integrity: Vec<u8>,
    pub namespace: Vec<namespace_layout::Entry>,
    pub source_candidate: Option<CandidateReport>,
    pub streams: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_profile: Option<crate::attestation::ResourceProfile>,
    pub binding: DiskBinding,
    pub before: crate::PartitionSnapshot,
    pub after: crate::PartitionSnapshot,
    pub objects: Vec<ObjectReport>,
    /// Complete metadata-inclusive allocation intervals observed through
    /// refs.sys on this mounted shadow. Not a stand-alone ownership proof.
    pub metadata_allocation: Option<crate::bitmap_layout::AllocationMap>,
    pub metadata_allocation_page_proof: Option<crate::bitmap_paging::Proof>,
    pub base_sectors: u64,
    pub privilege_states: Vec<PrivilegeState>,
    pub events: Vec<NativeEvent>,
    pub payload_bytes_written: u64,
    pub conversion_qualified: bool,
    pub root_security: RootSecurity,
    pub security_restorations: Vec<ObjectSecurityRestore>,
    pub security_repair_preflight_sha256: Option<String>,
    pub security_repair_privileges: Vec<PrivilegeState>,
    pub retention_attempts: Vec<RetentionAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_mount_indexer_cache: Option<PostMountIndexerCache>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shadow_user_evacuation: Vec<evacuation::Report>,
}

/// A newly generated, source-absent filesystem cache on the converted volume.
/// This records live reads; it never grants write authority or deletes a file.
#[derive(Debug, Serialize)]
pub struct PostMountIndexerCache {
    pub file_id: [u8; 16],
    pub attributes: u32,
    pub contents: Vec<u8>,
    pub streams: Vec<u8>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub observed_filetime: u64,
}

#[derive(Debug, Serialize)]
pub struct GeneralReport {
    pub pair: GeneralSourceShadowBinding,
    pub native: Report,
    pub conversion_qualified: bool,
}

/// A strict native metadata and stream-layout observation. This deliberately
/// cannot stand in for GeneralReport's complete logical-content verification.
/// Only the protected native lease can construct it; persisted JSON cannot.
#[derive(Debug, Serialize)]
pub struct GeneralLayoutReport {
    pair: GeneralSourceShadowBinding,
    native: Report,
    expected_stream_sha256: Vec<Option<String>>,
    metadata_and_namespace_verified: bool,
    complete_stream_mappings_verified: bool,
    storage_validity_verified: bool,
    data_integrity_disabled: bool,
    payload_bytes_read: u64,
    residuals: Vec<LayoutResidualExpectation>,
    residual_contents_verified: bool,
    logical_contents_verified: bool,
    raw_image_equality_verified: bool,
    complete_allocation_graph_verified: bool,
    conversion_qualified: bool,
}

impl GeneralLayoutReport {
    pub fn pair(&self) -> &GeneralSourceShadowBinding {
        &self.pair
    }
    pub fn native(&self) -> &Report {
        &self.native
    }
    pub fn residuals(&self) -> &[LayoutResidualExpectation] {
        &self.residuals
    }
    pub fn residual_contents_verified(&self) -> bool {
        self.residual_contents_verified
    }
}

/// Source-derived expectation for the initialized suffix outside the routed
/// full-cluster prefix. Never permits reading any byte before that suffix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LayoutResidualExpectation {
    pub object_index: usize,
    pub logical_offset: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct GeneralConvertedReport {
    pub pair: GeneralSourceShadowBinding,
    pub native: Report,
    pub conversion_qualified: bool,
}

#[derive(Debug, Serialize)]
pub struct SecurityProjectionProbe {
    pub binding: GeneralDiskBinding,
    pub fresh_parent: String,
    pub parent_before: Snapshot,
    pub parent_after: Snapshot,
    pub child_before: Snapshot,
    pub child_after: Snapshot,
    pub parent_matches_both_views: bool,
    pub child_matches_both_views: bool,
    pub before: crate::GeneralProbe,
    pub after: crate::GeneralProbe,
    pub privilege_states: Vec<PrivilegeState>,
    pub success: bool,
}

pub fn observe_system_directory(
    binding: GeneralDiskBinding,
    volume_root: bool,
) -> io::Result<Vec<crate::attestation::Query>> {
    let mut events = Vec::new();
    native::probe_general(binding.clone(), &mut events)?;
    if native::mounted_filesystem_general(binding.clone(), &mut events)? != "ReFS" {
        return Err(invalid("system-directory probe requires ReFS"));
    }
    let mut privileges = Privileges::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])?;
    let file = open(
        &format!(
            "{}\\{}",
            binding.volume_path()?,
            if volume_root {
                ""
            } else {
                "System Volume Information"
            }
        ),
        true,
        false,
    )?;
    let mut calls = Vec::new();
    for class in [namespace_layout::RESTART, namespace_layout::CONTINUE] {
        let query = match info(&file, class, namespace_layout::CAPACITY) {
            Ok(bytes) => {
                let (_, used) = namespace_layout::parse(&bytes)?;
                crate::attestation::Query {
                    class,
                    bytes: bytes[..used].to_vec(),
                    native_error: None,
                }
            }
            Err(error) => crate::attestation::Query {
                class,
                bytes: vec![],
                native_error: Some(error.raw_os_error().ok_or(error)?),
            },
        };
        calls.push(query);
    }
    privileges.restore()?;
    Ok(calls)
}

/// Exercise descriptor reconstruction in a newly created scratch directory on
/// a bound ReFS data disk. Never changes the volume root or existing files.
pub fn probe_security_projection(
    binding: GeneralDiskBinding,
    fresh_parent: &str,
    parent: &Input<'_>,
    child: &Input<'_>,
    same: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<SecurityProjectionProbe> {
    if !valid_shadow_component(fresh_parent)
        || !fresh_parent.starts_with("N2R-SECURITY-")
        || fresh_parent.len() != 45
        || !parent.directory
        || child.directory
    {
        return Err(invalid("fresh security-probe directory profile differs"));
    }
    descriptor(parent.security)?;
    descriptor(child.security)?;
    let mut events = Vec::new();
    let before = native::probe_general(binding.clone(), &mut events)?;
    if native::mounted_filesystem_general(binding.clone(), &mut events)? != "ReFS" {
        return Err(invalid("security projection probe requires mounted ReFS"));
    }
    let root = format!("{}\\", binding.volume_path()?);
    let parent_path = format!("{root}{fresh_parent}");
    let child_path = format!("{parent_path}\\probe.bin");
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ])?;
    create(&parent_path, parent, 0, None)?;
    let parent_handle = open(&parent_path, true, true)?;
    let parent_before = snapshot(&parent_handle);
    backup_security(&parent_handle, parent.security)?;
    create(&child_path, child, 1, None)?;
    let child_handle = open(&child_path, false, true)?;
    let child_before = snapshot(&child_handle);
    backup_security(&child_handle, child.security)?;
    basic(&child_handle, child)?;
    child_handle.sync_all()?;
    basic(&parent_handle, parent)?;
    let child_after = snapshot(&child_handle);
    let parent_after = snapshot(&parent_handle);
    let parent_matches_both_views = security_matches(parent, &parent_after, &same)?;
    let child_matches_both_views = security_matches(child, &child_after, &same)?;
    privileges.restore()?;
    let privilege_states = privileges.audit().to_vec();
    let after = native::probe_general(binding.clone(), &mut events)?;
    let success = parent_matches_both_views
        && child_matches_both_views
        && before.disk_attributes_before == 0
        && after.disk_attributes_after == 0
        && before.gpt_layout == after.gpt_layout
        && before.device == after.device;
    Ok(SecurityProjectionProbe {
        binding,
        fresh_parent: fresh_parent.into(),
        parent_before,
        parent_after,
        child_before,
        child_after,
        parent_matches_both_views,
        child_matches_both_views,
        before,
        after,
        privilege_states,
        success,
    })
}

fn observed_shadow(
    disk: &File,
    binding: &DiskBinding,
    general: Option<&GeneralDiskBinding>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<crate::PartitionSnapshot> {
    if let Some(general) = general {
        let probe = native::probe_general(general.clone(), events)?;
        Ok(crate::PartitionSnapshot {
            binding: binding.clone(),
            disk_attributes: probe.disk_attributes_after,
            device: probe.device,
            length: probe.disk_length,
            alignment: probe.alignment,
            layout: probe.gpt_layout,
        })
    } else {
        native::snapshot(disk, binding, events)
    }
}

fn observed_shadow_profile(
    disk: &File,
    binding: &DiskBinding,
    general: Option<&GeneralDiskBinding>,
    protected: Option<&native::GeneralReadonlyRefsVolume<'_>>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<crate::PartitionSnapshot> {
    match protected {
        Some(lease) => lease.snapshot(binding, events),
        None => observed_shadow(disk, binding, general, events),
    }
}
#[derive(Debug, Serialize)]
pub struct RetentionAttempt {
    pub components: Vec<String>,
    pub starting_vcn: u64,
    pub destination_lcn: u64,
    pub clusters: u32,
    pub candidate: CandidateReport,
    pub submitted: bool,
    pub native_error: Option<i32>,
    /// Canonical mappings, not individual native response buffers.
    pub mapping_before: Vec<u8>,
    pub mapping_after: Vec<u8>,
    pub mapping_before_page_proof: crate::retrieval_paging::Proof,
    pub mapping_after_page_proof: crate::retrieval_paging::Proof,
    pub all_clusters_at_source: bool,
}
const MAX_RETENTION_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
// The older tree retention path keeps its original attempt budget; the
// shared free-subrun ceiling was raised for private-tree placement only.
const MAX_RETENTION_ATTEMPTS: usize = 1024;
fn bitmap_proof_heap(proof: &crate::bitmap_paging::Proof) -> usize {
    proof.pages.iter().fold(
        proof
            .encoding
            .capacity()
            .saturating_add(proof.canonical_bitmap_sha256.capacity())
            .saturating_add(proof.streaming.as_ref().map_or(0, |streaming| {
                streaming.bitmap_data_sha256.capacity()
                    + streaming.page_transcript_sha256.capacity()
            }))
            .saturating_add(
                proof
                    .pages
                    .capacity()
                    .saturating_mul(std::mem::size_of::<crate::bitmap_paging::PageProof>()),
            ),
        |n, p| {
            n.saturating_add(p.input.capacity())
                .saturating_add(p.response_sha256.capacity())
        },
    )
}
fn retrieval_proof_heap(proof: &crate::retrieval_paging::Proof) -> usize {
    proof.pages.iter().fold(
        proof
            .encoding
            .capacity()
            .saturating_add(proof.canonical_sha256.capacity())
            .saturating_add(
                proof
                    .pages
                    .capacity()
                    .saturating_mul(std::mem::size_of::<crate::retrieval_paging::PageProof>()),
            ),
        |n, p| {
            n.saturating_add(p.input.capacity())
                .saturating_add(p.response_sha256.capacity())
        },
    )
}
fn retention_attempt_heap(attempt: &RetentionAttempt) -> usize {
    attempt
        .components
        .iter()
        .fold(
            attempt
                .components
                .capacity()
                .saturating_mul(std::mem::size_of::<String>()),
            |n, s| n.saturating_add(s.capacity()),
        )
        .saturating_add(attempt.mapping_before.capacity())
        .saturating_add(attempt.mapping_after.capacity())
        .saturating_add(attempt.candidate.legacy.bitmap_sha256.capacity())
        .saturating_add(
            attempt
                .candidate
                .metadata_inclusive
                .bitmap_sha256
                .capacity(),
        )
        .saturating_add(bitmap_proof_heap(&attempt.candidate.legacy_page_proof))
        .saturating_add(bitmap_proof_heap(&attempt.candidate.metadata_page_proof))
        .saturating_add(retrieval_proof_heap(&attempt.mapping_before_page_proof))
        .saturating_add(retrieval_proof_heap(&attempt.mapping_after_page_proof))
}
fn remaining_retention_evidence(attempts: &mut Vec<RetentionAttempt>) -> io::Result<usize> {
    if attempts.len() >= MAX_RETENTION_ATTEMPTS {
        return Err(invalid("tree retention-attempt budget exceeded"));
    }
    // Reserve the actual next slot before accounting; include spare capacity,
    // not just initialized bytes. No unbounded series of full maps is retained.
    attempts
        .try_reserve_exact(1)
        .map_err(|_| invalid("retention evidence allocation failed"))?;
    let used = attempts.iter().fold(
        attempts
            .capacity()
            .saturating_mul(std::mem::size_of::<RetentionAttempt>()),
        |n, a| n.saturating_add(retention_attempt_heap(a)),
    );
    MAX_RETENTION_EVIDENCE_BYTES
        .checked_sub(used)
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid("cumulative retention evidence budget exceeded"))
}
fn append_retention_attempt(
    attempts: &mut Vec<RetentionAttempt>,
    attempt: RetentionAttempt,
) -> io::Result<()> {
    if retention_attempt_heap(&attempt) > remaining_retention_evidence(attempts)? {
        return Err(invalid(
            "cumulative retention evidence budget exceeded; preserve shadow for inspection",
        ));
    }
    attempts.push(attempt);
    Ok(())
}
fn mapping_matches_run(
    runs: &[stream_layout::Run],
    starting_vcn: u64,
    destination_lcn: u64,
    clusters: u32,
) -> io::Result<bool> {
    let mut covered = starting_vcn;
    let limit = starting_vcn
        .checked_add(u64::from(clusters))
        .ok_or_else(|| invalid("retention range overflow"))?;
    for r in runs {
        let next = r
            .vcn
            .checked_add(r.clusters)
            .ok_or_else(|| invalid("retention mapping overflow"))?;
        let begin = r.vcn.max(starting_vcn);
        let end = next.min(limit);
        if begin < end {
            if begin != covered
                || !r
                    .lcn
                    .and_then(|lcn| lcn.checked_add(begin - r.vcn))
                    .is_some_and(|lcn| {
                        destination_lcn.checked_add(begin - starting_vcn) == Some(lcn)
                    })
            {
                return Ok(false);
            }
            covered = end;
        }
    }
    Ok(covered == limit)
}
fn retain_run_on_shadow(
    volume: &File,
    root: &str,
    i: &Input<'_>,
    partition: u64,
    run: &SourceRun,
    submit_if_free: bool,
    evidence_budget: usize,
    streaming: bool,
    planning_candidate: Option<CandidateReport>,
) -> io::Result<RetentionAttempt> {
    if planning_candidate.is_some() && (submit_if_free || !streaming) {
        return Err(invalid(
            "planning bitmap reuse is restricted to no-submit streaming diagnostics",
        ));
    }
    let offset = run
        .physical_offset
        .ok_or_else(|| invalid("source placement hole"))?;
    let starting_vcn = run.logical_offset / 4096;
    let h = open(&format!("{}{}", root, i.components.join("\\")), false, true)?;
    let before_capture = crate::stream_native::retrieval_capture(&h)?;
    let mapping_before = before_capture.canonical;
    let candidate = match planning_candidate {
        Some(candidate) => candidate,
        None => {
            let legacy = crate::bitmap_observation::Observation::capture(
                volume, &[0; 8], partition, streaming,
            )?;
            let mut ex = [0; 16];
            ex[8] = 1;
            let metadata =
                crate::bitmap_observation::Observation::capture(volume, &ex, partition, streaming)?;
            CandidateReport {
                legacy: legacy.view(partition)?.candidate(offset, run.length)?,
                metadata_inclusive: metadata.view(partition)?.candidate(offset, run.length)?,
                legacy_page_proof: legacy.proof(),
                metadata_page_proof: metadata.proof(),
            }
        }
    };
    if candidate.legacy.declared_clusters != partition / 4096
        || candidate.metadata_inclusive.declared_clusters != partition / 4096
        || candidate.legacy.start_lcn != offset / 4096
        || candidate.metadata_inclusive.start_lcn != offset / 4096
        || candidate.legacy.clusters != run.length / 4096
        || candidate.metadata_inclusive.clusters != run.length / 4096
    {
        return Err(invalid("retention bitmap domain is incomplete or changed"));
    }
    let clusters =
        u32::try_from(run.length / 4096).map_err(|_| invalid("retention cluster budget"))?;
    let destination_lcn = offset / 4096;
    let matches = |b: &[u8]| -> io::Result<bool> {
        mapping_matches_run(
            &stream_layout::parse_complete_retrieval(b)?,
            starting_vcn,
            destination_lcn,
            clusters,
        )
    };
    let already = matches(&mapping_before)?;
    let mut r = RetentionAttempt {
        components: i.components.to_vec(),
        starting_vcn,
        destination_lcn,
        clusters,
        candidate,
        submitted: false,
        native_error: None,
        mapping_after: mapping_before.clone(),
        mapping_before,
        mapping_after_page_proof: before_capture.proof.clone(),
        mapping_before_page_proof: before_capture.proof,
        all_clusters_at_source: already,
    };
    if retention_attempt_heap(&r) > evidence_budget {
        return Err(invalid("retention evidence budget exceeded before move"));
    }
    // Include the independent metadata view. Never force a move into an
    // occupied bootstrap/container range or relocate the NTFS source itself.
    if !submit_if_free
        || already
        || r.candidate.legacy.allocated_clusters != 0
        || r.candidate.metadata_inclusive.allocated_clusters != 0
    {
        return Ok(r);
    }
    let mut input = [0; 32];
    input[..8].copy_from_slice(&(h.as_raw_handle() as usize as u64).to_le_bytes());
    input[8..16].copy_from_slice(&starting_vcn.to_le_bytes());
    input[16..24].copy_from_slice(&destination_lcn.to_le_bytes());
    input[24..28].copy_from_slice(&clusters.to_le_bytes());
    r.submitted = true;
    if let Err(e) = ctl(volume, 0x00090074, &input, 0) {
        r.native_error = e.raw_os_error().or(Some(-1));
    }
    // A refusal can have partial completion. Do not retry; measure its actual
    // mapping and let the ordinary content/storage checks qualify the shadow.
    let after_capture = crate::stream_native::retrieval_capture(&h)?;
    r.mapping_after = after_capture.canonical;
    r.mapping_after_page_proof = after_capture.proof;
    r.all_clusters_at_source = matches(&r.mapping_after)?;
    if retention_attempt_heap(&r) > evidence_budget {
        return Err(invalid(
            "post-move evidence exceeds budget; preserve shadow and do not retry",
        ));
    }
    Ok(r)
}

/// Split around both bitmap views, then recheck and measure each move. An
/// earlier free-space observation alone never becomes retained-extent proof.
fn retain_source_run_on_shadow(
    volume: &File,
    root: &str,
    input: &Input<'_>,
    partition: u64,
    run: &SourceRun,
    attempts: &mut Vec<RetentionAttempt>,
    streaming: bool,
    reuse_no_submit_snapshot: bool,
    planning_cache: &mut Option<(
        crate::bitmap_observation::Observation,
        crate::bitmap_observation::Observation,
    )>,
    cascade: bool,
) -> io::Result<()> {
    let mut first_pass = true;
    loop {
        let progress = retain_source_run_once(
            volume,
            root,
            input,
            partition,
            run,
            attempts,
            streaming,
            reuse_no_submit_snapshot,
            planning_cache,
            first_pass,
        )?;
        // A confirmed move can free another part of this same source interval.
        // Replan from fresh maps instead of abandoning those newly free slots.
        // Never repeat a rejected/partial move or exhaust the fixed audit budget.
        if !reuse_no_submit_snapshot
            || !cascade
            || !progress
            || attempts.len() == MAX_RETENTION_ATTEMPTS
        {
            return Ok(());
        }
        first_pass = false;
    }
}

fn retain_source_run_once(
    volume: &File,
    root: &str,
    input: &Input<'_>,
    partition: u64,
    run: &SourceRun,
    attempts: &mut Vec<RetentionAttempt>,
    streaming: bool,
    reuse_no_submit_snapshot: bool,
    planning_cache: &mut Option<(
        crate::bitmap_observation::Observation,
        crate::bitmap_observation::Observation,
    )>,
    diagnose_blocked: bool,
) -> io::Result<bool> {
    remaining_retention_evidence(attempts)?;
    let first_attempt = attempts.len();
    // Bound the complete tree, including non-submitted collision diagnostics.
    let remaining = MAX_RETENTION_ATTEMPTS
        .checked_sub(attempts.len())
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| invalid("tree retention-attempt budget exceeded"))?;
    let physical_offset = run
        .physical_offset
        .ok_or_else(|| invalid("source placement hole"))?;
    if !reuse_no_submit_snapshot || planning_cache.is_none() {
        let legacy =
            crate::bitmap_observation::Observation::capture(volume, &[0; 8], partition, streaming)?;
        let mut ex = [0; 16];
        ex[8] = 1;
        let metadata =
            crate::bitmap_observation::Observation::capture(volume, &ex, partition, streaming)?;
        *planning_cache = Some((legacy, metadata));
    }
    // This cache selects candidates/diagnostics only. Each submitted move still
    // captures both live maps inside retain_run_on_shadow before native I/O.
    let (legacy, metadata) = planning_cache
        .as_ref()
        .ok_or_else(|| invalid("missing retention planning observations"))?;
    let plan = legacy.plan_free_subruns(
        metadata,
        crate::retention_layout::SourceRun {
            logical_offset: run.logical_offset,
            physical_offset,
            length: run.length,
        },
        partition,
        remaining,
    )?;
    if plan.subruns.is_empty() {
        if !diagnose_blocked {
            return Ok(false);
        }
        // A later free-space change must not turn this diagnostic into an
        // unplanned move. Already-correct placement is still recorded.
        let chunk_bytes = crate::retention_layout::MAX_MOVE_BYTES;
        if run.length.div_ceil(chunk_bytes) > remaining as u64 {
            return Err(invalid("retention diagnostic chunk budget exceeded"));
        }
        let mut offset = 0;
        while offset < run.length {
            let subrun = SourceRun {
                logical_offset: run.logical_offset + offset,
                physical_offset: Some(physical_offset + offset),
                length: (run.length - offset).min(chunk_bytes),
            };
            let budget = remaining_retention_evidence(attempts)?;
            let planning_candidate = if reuse_no_submit_snapshot {
                Some(CandidateReport {
                    legacy: legacy
                        .view(partition)?
                        .candidate(physical_offset + offset, subrun.length)?,
                    metadata_inclusive: metadata
                        .view(partition)?
                        .candidate(physical_offset + offset, subrun.length)?,
                    legacy_page_proof: legacy.proof(),
                    metadata_page_proof: metadata.proof(),
                })
            } else {
                None
            };
            let attempt = retain_run_on_shadow(
                volume,
                root,
                input,
                partition,
                &subrun,
                false,
                budget,
                streaming,
                planning_candidate,
            )?;
            append_retention_attempt(attempts, attempt)?;
            offset += subrun.length;
        }
    } else {
        for candidate in plan.subruns {
            let subrun = SourceRun {
                logical_offset: candidate.logical_offset,
                physical_offset: Some(candidate.physical_offset),
                length: candidate.length,
            };
            let budget = remaining_retention_evidence(attempts)?;
            let attempt = retain_run_on_shadow(
                volume, root, input, partition, &subrun, true, budget, streaming, None,
            )?;
            append_retention_attempt(attempts, attempt)?;
        }
    }
    let new_attempts = &attempts[first_attempt..];
    let progress = new_attempts
        .iter()
        .all(|attempt| attempt.native_error.is_none())
        && new_attempts
            .iter()
            .any(|attempt| attempt.submitted && attempt.all_clusters_at_source);
    if !reuse_no_submit_snapshot
        || new_attempts
            .iter()
            .any(|attempt| attempt.submitted || attempt.mapping_before != attempt.mapping_after)
    {
        // A move, even a failed/partial one, may change data or COW metadata
        // allocation. Never carry its planning snapshot into another run.
        *planning_cache = None;
    }
    Ok(progress)
}
#[derive(Debug, Serialize)]
pub struct ObjectSecurityRestore {
    pub components: Vec<String>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub backup: SecurityBackup,
}
#[derive(Debug, Serialize)]
pub struct RootSecurity {
    pub before: Snapshot,
    pub after: Snapshot,
    pub matched_before: bool,
    pub matched_after: bool,
    pub backup: Option<SecurityBackup>,
}
#[derive(Debug, Serialize)]
pub struct SecurityBackup {
    pub stream_sha256: String,
    pub submitted_bytes: u32,
    pub accepted_bytes: u32,
    pub context_released: bool,
}
fn security_stream(sd: &[u8]) -> io::Result<Vec<u8>> {
    if !(20..=65536).contains(&sd.len()) {
        return Err(invalid("security backup length"));
    }
    // WIN32_STREAM_ID ends at cStreamName (offset 20), not sizeof(struct),
    // which includes WCHAR[1] and alignment padding. This stream is unnamed.
    let mut stream = vec![0; 20];
    stream[0..4].copy_from_slice(&3u32.to_le_bytes());
    stream[4..8].copy_from_slice(&2u32.to_le_bytes());
    stream[8..16].copy_from_slice(&(sd.len() as u64).to_le_bytes());
    stream.extend_from_slice(sd);
    Ok(stream)
}
fn backup_security(file: &File, sd: &[u8]) -> io::Result<SecurityBackup> {
    descriptor(sd)?;
    let stream = security_stream(sd)?;
    let mut accepted = 0;
    let mut context = ptr::null_mut();
    // SAFETY: synchronous backup-semantics handle with WRITE_DAC, WRITE_OWNER
    // and ACCESS_SYSTEM_SECURITY; bounded initialized stream; private context
    // starts NULL and is passed unchanged to the mandatory abort/cleanup call.
    let result = check(unsafe {
        BackupWrite(
            file.as_raw_handle(),
            stream.as_ptr(),
            stream.len() as u32,
            &mut accepted,
            0,
            1,
            &mut context,
        )
    });
    let mut ignored = 0;
    let cleanup = check(unsafe {
        BackupWrite(
            file.as_raw_handle(),
            ptr::null(),
            0,
            &mut ignored,
            1,
            1,
            &mut context,
        )
    });
    result?;
    cleanup?;
    if accepted as usize != stream.len() {
        return Err(invalid("partial root backup-security restoration"));
    }
    Ok(SecurityBackup {
        stream_sha256: hex::encode(Sha256::digest(&stream)),
        submitted_bytes: stream.len() as u32,
        accepted_bytes: accepted,
        context_released: true,
    })
}
fn security_matches(
    input: &Input<'_>,
    actual: &Snapshot,
    same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<bool> {
    let kernel = actual
        .kernel_security
        .as_ref()
        .ok_or_else(|| invalid("root kernel security missing"))?;
    if actual.security_error.is_some() || kernel.native_error.is_some() {
        return Err(invalid("root security query failed"));
    }
    Ok(same(
        input.expected_api_security.unwrap_or(input.security),
        &actual.security,
    )? && same(input.security, &kernel.bytes)?)
}
fn query_bytes(s: &Snapshot, class: i32, length: usize) -> io::Result<&[u8]> {
    let q = s
        .queries
        .iter()
        .find(|q| q.class == class && q.native_error.is_none() && q.bytes.len() == length)
        .ok_or_else(|| invalid("missing native shadow metadata query"))?;
    Ok(&q.bytes)
}
fn basic_bytes(i: &Input<'_>) -> Vec<u8> {
    let mut b = Vec::with_capacity(40);
    for t in i.times {
        b.extend_from_slice(&t.to_le_bytes());
    }
    b.extend_from_slice(&i.attributes.to_le_bytes());
    b.extend_from_slice(&[0; 4]);
    b
}
// Only a pre-restoration diagnosis. Final comparisons never normalize control
// flags: BACKUP_SECURITY_DATA must restore the exact original descriptor.
fn creation_loss_only(
    expected: &[u8],
    actual: &[u8],
    same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<bool> {
    if same(expected, actual)? {
        return Ok(true);
    }
    if expected.len() < 20 || actual.len() < 20 {
        return Ok(false);
    }
    let want = u16::from_le_bytes(expected[2..4].try_into().unwrap());
    let got = u16::from_le_bytes(actual[2..4].try_into().unwrap());
    if want ^ got != 0x400 || want & 0x400 == 0 {
        return Ok(false);
    }
    let mut restored = actual.to_vec();
    restored[2..4].copy_from_slice(&want.to_le_bytes());
    same(expected, &restored)
}
fn validate_existing(
    report: &Report,
    input: &[Input<'_>],
    same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    before_restore: bool,
    root_basic_after_mutation: Option<&[u8; 40]>,
) -> io::Result<()> {
    validate_existing_profile(
        report,
        input,
        same,
        before_restore,
        root_basic_after_mutation,
        true,
    )
}

fn validate_existing_profile(
    report: &Report,
    input: &[Input<'_>],
    same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    before_restore: bool,
    root_basic_after_mutation: Option<&[u8; 40]>,
    verify_contents: bool,
) -> io::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    if report.objects.len() != input.len() {
        return Err(invalid("existing shadow object coverage differs"));
    }
    let mut identities = BTreeMap::new();
    let mut unique = BTreeSet::new();
    for (i, o) in input.iter().zip(&report.objects) {
        let expected_owned = basic_bytes(i);
        if i.components.is_empty()
            && root_basic_after_mutation.is_some_and(|after| {
                after[..8] != expected_owned[..8] || after[32..] != expected_owned[32..]
            })
        {
            return Err(invalid(
                "mutation root policy cannot change source creation time or attributes",
            ));
        }
        let expected_basic: &[u8] = if i.components.is_empty() {
            root_basic_after_mutation.map_or(&expected_owned, |bytes| bytes.as_slice())
        } else {
            &expected_owned
        };
        let actual_basic = query_bytes(&o.before, 0, 40)?;
        let cache_directory_times = if i.components == ["System Volume Information"] {
            report
                .post_mount_indexer_cache
                .as_ref()
                .is_some_and(|cache| {
                    let Ok(cache_basic) = query_bytes(&cache.before, 0, 40) else {
                        return false;
                    };
                    let Ok(created) = layout::u64_at(cache_basic, 0) else {
                        return false;
                    };
                    actual_basic[..8] == expected_basic[..8]
                        && actual_basic[32..] == expected_basic[32..]
                        && created >= layout::u64_at(expected_basic, 24).unwrap_or(u64::MAX)
                        && created <= cache.observed_filetime
                        && [8, 16, 24].into_iter().all(|at| {
                            let old = layout::u64_at(expected_basic, at).unwrap_or(u64::MAX);
                            let now = layout::u64_at(actual_basic, at).unwrap_or(0);
                            now >= old && now <= cache.observed_filetime
                        })
                })
        } else {
            false
        };
        if i.components != o.components
            || (actual_basic != expected_basic && !cache_directory_times)
            || o.before != o.after
        {
            return Err(invalid(
                "existing shadow path, basic metadata or stability differs",
            ));
        }
        let id = query_bytes(&o.before, 18, 24)?[8..24].to_vec();
        if id == [0; 16]
            || !unique.insert(id.clone())
            || identities.insert(i.components.to_vec(), id).is_some()
        {
            return Err(invalid("duplicate existing shadow identity"));
        }
        let standard = query_bytes(&o.before, 1, 24)?;
        if layout::u32_at(standard, 16)? != hard_links::count(i)?
            || standard[20] != 0
            || (standard[21] != 0) != i.directory
            || (!i.directory && layout::u64_at(standard, 8)? != i.logical_length())
            || (verify_contents && o.logical_sha256 != (!i.directory).then(|| i.logical_sha256()))
            || (!verify_contents && o.logical_sha256.is_some())
        {
            return Err(invalid(
                "existing shadow links, type, EOF or contents differ",
            ));
        }
        hard_links::verify(i, &o.before, &o.additional_names)?;
        let kernel = o
            .before
            .kernel_security
            .as_ref()
            .ok_or_else(|| invalid("existing shadow security missing"))?;
        if o.before.security_error.is_some() || kernel.native_error.is_some() {
            return Err(invalid("existing shadow security query failed"));
        }
        for (expected, actual) in [
            (
                i.expected_api_security.unwrap_or(i.security),
                o.before.security.as_slice(),
            ),
            (i.security, kernel.bytes.as_slice()),
        ] {
            let matched = if before_restore {
                creation_loss_only(expected, actual, same)?
            } else {
                same(expected, actual)?
            };
            if !matched {
                return Err(invalid(
                    "existing shadow security differs beyond the recorded creation control-bit loss",
                ));
            }
        }
    }
    if let Some(cache) = &report.post_mount_indexer_cache {
        if unique.contains(cache.file_id.as_slice()) {
            return Err(invalid(
                "post-mount indexer cache aliases an admitted source object",
            ));
        }
    }
    for (i, o) in input
        .iter()
        .zip(&report.objects)
        .filter(|(i, _)| i.directory)
    {
        let expected: BTreeMap<_, _> = input
            .iter()
            .flat_map(|c| hard_links::paths(c).map(move |path| (c, path)))
            .filter(|(_, path)| {
                path.len() == i.components.len() + 1 && path.starts_with(i.components)
            })
            .map(|(c, path)| (path.last().unwrap().encode_utf16().collect::<Vec<_>>(), c))
            .collect();
        let mut seen = BTreeSet::new();
        let mut cache_seen = false;
        for entry in &o.namespace {
            if entry.name_utf16 == [46] || entry.name_utf16 == [46, 46] {
                continue;
            }
            if i.components == ["System Volume Information"]
                && entry.name_utf16 == "IndexerVolumeGuid".encode_utf16().collect::<Vec<_>>()
                && report
                    .post_mount_indexer_cache
                    .as_ref()
                    .is_some_and(|cache| {
                        cache.file_id == entry.file_id && cache.attributes == entry.attributes
                    })
            {
                if cache_seen {
                    return Err(invalid(
                        "duplicate post-mount indexer cache directory entry",
                    ));
                }
                cache_seen = true;
                continue;
            }
            if i.components.is_empty()
                && verify_contents
                && !expected.contains_key(&entry.name_utf16)
                && entry.name_utf16
                    == "System Volume Information"
                        .encode_utf16()
                        .collect::<Vec<_>>()
                && entry.attributes & 16 != 0
                && entry.attributes & 0x400 == 0
            {
                continue;
            }
            let child = expected
                .get(&entry.name_utf16)
                .ok_or_else(|| invalid("unexpected existing shadow directory entry"))?;
            if !seen.insert(entry.name_utf16.clone())
                || entry.attributes != child.attributes
                || identities
                    .get(child.components)
                    .is_none_or(|id| id.as_slice() != entry.file_id)
            {
                return Err(invalid("existing shadow namespace identity differs"));
            }
        }
        if seen.len() != expected.len() {
            return Err(invalid("missing existing shadow directory entry"));
        }
        if i.components == ["System Volume Information"]
            && report.post_mount_indexer_cache.is_some()
            && !cache_seen
        {
            return Err(invalid("post-mount indexer cache missing from directory"));
        }
    }
    Ok(())
}
/// Repairs only the documented creation-time loss of AUTO_INHERITED, after a
/// fresh native read of every admitted shadow byte and namespace identity. The
/// preflight is a live value; no serialized `success` flag is consumed.
pub fn repair_security(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    same: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    repair_security_profile(binding, source_disk, input, same, false)
}
pub fn repair_security_ordinary(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    same: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    repair_security_profile(binding, source_disk, input, same, true)
}
fn repair_security_profile(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    same: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ordinary: bool,
) -> io::Result<Report> {
    let observed = run_role(
        binding.clone(),
        source_disk,
        input,
        Mode::Verify,
        &same,
        false,
        ordinary,
        None,
        None,
    )?;
    validate_existing(&observed, input, &same, true, None)?;
    let preflight_sha = hex::encode(Sha256::digest(
        serde_json::to_vec(&observed).map_err(io::Error::other)?,
    ));
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ])?;
    let root = format!("\\\\?\\Volume{{{}}}\\", binding.volume_guid);
    let mut restorations = vec![];
    for (i, o) in input.iter().zip(&observed.objects).rev() {
        let h = open(
            &format!("{}{}", root, i.components.join("\\")),
            i.directory,
            true,
        )?;
        let before = snapshot(&h);
        if before != o.before {
            return Err(invalid("existing shadow changed after repair preflight"));
        }
        if !security_matches(i, &before, &same)? {
            let backup = backup_security(&h, i.security)?;
            let after = snapshot(&h);
            if !security_matches(i, &after, &same)? {
                return Err(invalid("restored shadow descriptor does not exactly match"));
            }
            restorations.push(ObjectSecurityRestore {
                components: i.components.to_vec(),
                before,
                after,
                backup,
            });
        }
        basic(&h, i)?;
        if !i.directory {
            h.sync_all()?;
        }
    }
    let volume = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(root.trim_end_matches('\\'))?;
    volume.sync_all()?;
    privileges.restore()?;
    let mut verified = run_role(
        binding,
        source_disk,
        input,
        Mode::Verify,
        &same,
        false,
        ordinary,
        None,
        None,
    )?;
    validate_existing(&verified, input, &same, false, None)?;
    if observed
        .objects
        .iter()
        .zip(&verified.objects)
        .any(|(a, b)| a.retrieval != b.retrieval)
    {
        return Err(invalid(
            "payload allocation changed during security-only restoration",
        ));
    }
    verified.security_restorations = restorations;
    verified.security_repair_preflight_sha256 = Some(preflight_sha);
    verified.security_repair_privileges = privileges.audit().to_vec();
    Ok(verified)
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn ctl(file: &File, code: u32, input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    if size > 2 * 1024 * 1024 || input.len() > 64 {
        return Err(invalid("shadow control bound"));
    }
    let mut b = vec![0; size];
    let mut used = 0;
    // SAFETY: borrowed handle, initialized separate buffers, synchronous call.
    check(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            b.as_mut_ptr().cast(),
            size as u32,
            &mut used,
            ptr::null_mut(),
        )
    })?;
    if used as usize > size {
        return Err(invalid("oversized shadow control response"));
    }
    b.truncate(used as usize);
    Ok(b)
}
fn info(file: &File, class: i32, size: usize) -> io::Result<Vec<u8>> {
    let mut b = vec![0u64; size.div_ceil(8)];
    // SAFETY: aligned initialized storage of the exact class-specific size.
    check(unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            b.as_mut_ptr().cast(),
            size as u32,
        )
    })?;
    Ok(unsafe { std::slice::from_raw_parts(b.as_ptr().cast(), size) }.to_vec())
}
fn suppress_access(file: &File) -> io::Result<()> {
    let no_update = FILETIME {
        dwLowDateTime: u32::MAX,
        dwHighDateTime: u32::MAX,
    };
    // SAFETY: documented per-handle suppression, no stored timestamp supplied.
    check(unsafe { SetFileTime(file.as_raw_handle(), ptr::null(), &no_update, ptr::null()) })
}
fn open(path: &str, directory: bool, write: bool) -> io::Result<File> {
    let f = File::options()
        // Metadata handles need WRITE_DAC/WRITE_OWNER, never DELETE. Retaining
        // the root handle must not prevent its later finalization/observation.
        .access_mode(if write { 0x011e01ff } else { 0x01020181 })
        .share_mode(3)
        .custom_flags(0x02200000)
        .open(path)?;
    suppress_access(&f)?;
    validate_open_type(&f, directory)?;
    Ok(f)
}

// The protected lease already prevents persisted access-time changes. These
// handles request no write access and issue no per-handle timestamp setter;
// exact native before/after metadata remains part of verification.
fn open_protected_readonly(path: &str, directory: bool) -> io::Result<File> {
    let f = File::options()
        .access_mode(PROTECTED_READ_ACCESS)
        .share_mode(3)
        .custom_flags(0x02200000)
        .open(path)?;
    validate_open_type(&f, directory)?;
    Ok(f)
}

// ACCESS_SYSTEM_SECURITY | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA.
const PROTECTED_READ_ACCESS: u32 = 0x01020081;

fn validate_open_type(f: &File, directory: bool) -> io::Result<()> {
    let attrs = info(&f, 0, 40)?;
    let flags = u32::from_le_bytes(attrs[32..36].try_into().unwrap());
    if flags & (0x400 | 0x800 | 0x4000) != 0 || (flags & 16 != 0) != directory {
        return Err(invalid("shadow path type or encoding differs"));
    }
    Ok(())
}
fn enumerate(file: &File) -> io::Result<Vec<namespace_layout::Entry>> {
    let mut calls = vec![];
    for i in 0..namespace_layout::MAX_CALLS {
        let class = if i == 0 {
            namespace_layout::RESTART
        } else {
            namespace_layout::CONTINUE
        };
        let result = info(file, class, namespace_layout::CAPACITY);
        let q = match result {
            Ok(b) => {
                let (_, used) = namespace_layout::parse(&b)?;
                crate::attestation::Query {
                    class,
                    bytes: b[..used].to_vec(),
                    native_error: None,
                }
            }
            Err(e) => crate::attestation::Query {
                class,
                bytes: vec![],
                native_error: Some(e.raw_os_error().ok_or(e)?),
            },
        };
        let terminal = q.native_error.is_some();
        let confirm_empty = i == 0 && q.native_error == Some(namespace_layout::FIRST_EMPTY);
        calls.push(q);
        if terminal && !confirm_empty {
            return namespace_layout::decode_pass(&calls);
        }
    }
    Err(invalid("shadow namespace enumeration budget"))
}

fn formatter_cache_name(name: &str) -> bool {
    matches!(name, "WPSettings.dat" | "IndexerVolumeGuid")
}

fn observe_post_mount_indexer_cache(
    root: &str,
    input: &[Input<'_>],
    objects: &[ObjectReport],
) -> io::Result<Option<PostMountIndexerCache>> {
    let system = "System Volume Information";
    let name = "IndexerVolumeGuid";
    if input.iter().any(|i| {
        i.components.len() == 2
            && i.components[0].eq_ignore_ascii_case(system)
            && i.components[1].eq_ignore_ascii_case(name)
    }) {
        return Ok(None);
    }
    let Some(parent_observation) = objects.iter().find(|o| o.components == [system]) else {
        return Ok(None);
    };
    let names: Vec<_> = parent_observation
        .namespace
        .iter()
        .filter(|e| e.name_utf16 == name.encode_utf16().collect::<Vec<_>>())
        .collect();
    if names.is_empty() {
        return Ok(None);
    }
    if names.len() != 1 || names[0].attributes & !0x2027 != 0 {
        return Err(invalid(
            "post-mount indexer cache namespace or attributes differ",
        ));
    }
    let entry = names[0];
    let parent = open(&format!("{root}{system}"), true, false)?;
    if snapshot(&parent) != parent_observation.after {
        return Err(invalid(
            "system directory changed before post-mount cache observation",
        ));
    }
    let mut file = File::options()
        .access_mode(0x01020181)
        .share_mode(1)
        .custom_flags(0x02200000)
        .open(format!("{root}{system}\\{name}"))?;
    suppress_access(&file)?;
    validate_open_type(&file, false)?;
    let before = snapshot(&file);
    let standard = query_bytes(&before, 1, 24)?;
    let basic = query_bytes(&before, 0, 40)?;
    if query_bytes(&before, 18, 24)?[8..24] != entry.file_id
        || entry.file_id == [0; 16]
        || layout::u64_at(standard, 8)? != 76
        || layout::u64_at(standard, 0)? > 65536
        || layout::u32_at(standard, 16)? != 1
        || standard[20] != 0
        || standard[21] != 0
        || layout::u32_at(basic, 32)? != entry.attributes
        || before.security_error.is_some()
        || before
            .kernel_security
            .as_ref()
            .is_none_or(|s| s.native_error.is_some())
    {
        return Err(invalid(
            "post-mount indexer cache identity, type, size or security query differs",
        ));
    }
    let mut streams = info(&file, 7, stream_layout::MAX_STREAM_BUFFER)?;
    let (entries, used) = stream_layout::parse_streams(&streams)?;
    if entries.len() != 1 || !entries[0].name.is_empty() || entries[0].logical_size != 76 {
        return Err(invalid("post-mount indexer cache has unexpected streams"));
    }
    streams.truncate(used);
    let mut contents = vec![0; 76];
    file.read_exact(&mut contents)?;
    let guid: Vec<_> = contents
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    if guid.iter().enumerate().any(|(at, &c)| match at {
        0 => c != u16::from(b'{'),
        37 => c != u16::from(b'}'),
        9 | 14 | 19 | 24 => c != u16::from(b'-'),
        _ => c > 127 || !(c as u8).is_ascii_hexdigit(),
    }) || file.read(&mut [0u8; 1])? != 0
    {
        return Err(invalid("post-mount indexer cache GUID contents differ"));
    }
    let after = snapshot(&file);
    if before != after || snapshot(&parent) != parent_observation.after {
        return Err(invalid(
            "post-mount indexer cache or parent changed during observation",
        ));
    }
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid("system clock predates Unix epoch"))?;
    let observed_filetime = u64::try_from(since_epoch.as_nanos() / 100 + 116_444_736_000_000_000)
        .map_err(|_| invalid("post-mount cache observation clock overflow"))?;
    Ok(Some(PostMountIndexerCache {
        file_id: entry.file_id,
        attributes: entry.attributes,
        contents,
        streams,
        before,
        after,
        observed_filetime,
    }))
}

fn source_formatter_cache_bounds(input: &[Input<'_>]) -> io::Result<()> {
    // Source objects already passed the complete ordinary-tree admission and
    // bounded Input checks. Only formatter-cache replacement has this extra
    // bound; another admitted SVI file is created normally, never ignored.
    for i in input.iter().filter(|i| {
        i.components.len() == 2
            && i.components[0] == "System Volume Information"
            && !i.directory
            && formatter_cache_name(&i.components[1])
    }) {
        if i.logical_length() > 1024 * 1024 {
            return Err(invalid("source formatter cache exceeds bounded profile"));
        }
    }
    Ok(())
}

fn formatter_target_reusable(name: &str, attributes: u32, source_expected: bool) -> bool {
    formatter_cache_name(name) && attributes & (16 | 0x400 | 0x800 | 0x4000) == 0 && source_expected
}

fn existing_system_entries(
    root: &str,
    initial: &[namespace_layout::Entry],
    input: &[Input<'_>],
    normalize_indexer_cache: bool,
    events: &mut Vec<NativeEvent>,
) -> io::Result<std::collections::BTreeMap<Vec<String>, Vec<u8>>> {
    let system = "System Volume Information";
    let mut existing = std::collections::BTreeMap::new();
    if !input
        .iter()
        .any(|i| i.components == [system] && i.directory)
    {
        return Ok(existing);
    }
    source_formatter_cache_bounds(input)?;
    if !initial
        .iter()
        .any(|e| e.name_utf16 == system.encode_utf16().collect::<Vec<_>>())
    {
        return Ok(existing);
    }
    let parent = open(&format!("{root}{system}"), true, false)?;
    existing.insert(
        vec![system.into()],
        query_bytes(&snapshot(&parent), 18, 24)?[8..24].to_vec(),
    );
    let mut target_only = Vec::new();
    for entry in enumerate(&parent)? {
        if entry.name_utf16 == [46] || entry.name_utf16 == [46, 46] {
            continue;
        }
        let name = String::from_utf16(&entry.name_utf16)
            .map_err(|_| invalid("invalid target system filename"))?;
        let path = vec![system.into(), name.clone()];
        let source_expected = input.iter().any(|i| i.components == path && !i.directory);
        if normalize_indexer_cache && name == "IndexerVolumeGuid" && !source_expected {
            // Only the separately enrolled streaming shadow may discard this
            // formatter-generated identity cache. Never infer that arbitrary
            // SVI data is disposable, and never modify the frozen source.
            if entry.attributes & !0x2027 != 0 {
                return Err(invalid("target-only indexer cache attributes differ"));
            }
            let mut file = File::options()
                // SetFileTime's per-handle access-time suppression requires
                // FILE_WRITE_ATTRIBUTES, even though it changes no stored time.
                .access_mode(PROTECTED_READ_ACCESS | 0x10100)
                .share_mode(1)
                .custom_flags(0x02200000)
                .open(format!("{root}{system}\\{name}"))
                .map_err(|e| {
                    io::Error::new(e.kind(), format!("open target-only indexer cache: {e}"))
                })?;
            suppress_access(&file).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("suppress target-only indexer cache access time: {e}"),
                )
            })?;
            validate_open_type(&file, false)?;
            let state = snapshot(&file);
            let standard = query_bytes(&state, 1, 24)?;
            if query_bytes(&state, 18, 24)?[8..24] != entry.file_id
                || layout::u64_at(standard, 8)? != 76
                || u32::from_le_bytes(standard[16..20].try_into().unwrap()) != 1
                || standard[20] != 0
            {
                return Err(invalid(
                    "target-only indexer cache identity or size differs",
                ));
            }
            let stream_bytes = info(&file, 7, stream_layout::MAX_STREAM_BUFFER)?;
            let (streams, _) = stream_layout::parse_streams(&stream_bytes)?;
            if streams.len() != 1 || !streams[0].name.is_empty() || streams[0].logical_size != 76 {
                return Err(invalid("target-only indexer cache streams differ"));
            }
            let mut bytes = [0u8; 76];
            file.read_exact(&mut bytes)?;
            let guid: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            if guid.iter().enumerate().any(|(at, &c)| match at {
                0 => c != u16::from(b'{'),
                37 => c != u16::from(b'}'),
                9 | 14 | 19 | 24 => c != u16::from(b'-'),
                _ => c > 127 || !(c as u8).is_ascii_hexdigit(),
            }) || file.read(&mut [0u8; 1])? != 0
            {
                return Err(invalid("target-only indexer cache GUID contents differ"));
            }
            target_only.push((file, entry.file_id, bytes));
            continue;
        }
        if !formatter_target_reusable(&name, entry.attributes, source_expected) {
            return Err(invalid(
                "target system-volume namespace contains unknown or unexpected data",
            ));
        }
        let file = open(&format!("{root}{system}\\{name}"), false, false)?;
        let state = snapshot(&file);
        if layout::u64_at(query_bytes(&state, 1, 24)?, 8)? > 1024 * 1024 {
            return Err(invalid("target system cache exceeds bounded profile"));
        }
        existing.insert(path, query_bytes(&state, 18, 24)?[8..24].to_vec());
    }
    // Finish validating the entire directory before any deletion. These live
    // handles exclude other writers/deleters; Windows updates its own allocator.
    for (file, id, bytes) in target_only {
        let delete: u8 = 1; // FILE_DISPOSITION_INFO::DeleteFile
        // SAFETY: a live DELETE-authorized file handle and a one-byte Windows
        // BOOLEAN, with FileDispositionInfo (4). No raw filesystem edits.
        check(unsafe {
            SetFileInformationByHandle(file.as_raw_handle(), 4, (&delete as *const u8).cast(), 1)
        })
        .map_err(|e| io::Error::new(e.kind(), format!("remove target-only indexer cache: {e}")))?;
        drop(file);
        events.push(NativeEvent {
            operation: "remove-target-only-formatter-indexer-cache".into(),
            control_code: 0,
            input: format!("{root}{system}\\IndexerVolumeGuid").into_bytes(),
            succeeded: true,
            native_error: None,
            output: [id.as_slice(), bytes.as_slice()].concat(),
        });
    }
    Ok(existing)
}
fn descriptor(bytes: &[u8]) -> io::Result<Vec<u64>> {
    if !(20..=65536).contains(&bytes.len()) {
        return Err(invalid("shadow descriptor length"));
    }
    let mut aligned = vec![0u64; bytes.len().div_ceil(8)];
    // SAFETY: initialized aligned allocation covers every copied byte. Validate
    // self-relative offsets in safe code before letting Windows follow them.
    if bytes[0] != 1
        || u16::from_le_bytes(bytes[2..4].try_into().unwrap()) & 0x8004 != 0x8004
        || bytes[12..16] != [0; 4]
    {
        return Err(invalid("shadow descriptor form or SACL differs"));
    }
    for at in [4, 8, 16] {
        let p = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if p < 20 || p > bytes.len().saturating_sub(8) || !p.is_multiple_of(4) {
            return Err(invalid("shadow descriptor component bounds"));
        }
        let n = if at == 16 {
            u16::from_le_bytes(bytes[p + 2..p + 4].try_into().unwrap()) as usize
        } else {
            8 + 4 * bytes[p + 1] as usize
        };
        if n < 8 || p + n > bytes.len() {
            return Err(invalid("shadow descriptor component length"));
        }
        if at != 16 {
            if bytes[p] != 1 || bytes[p + 1] > 15 {
                return Err(invalid("shadow SID form"));
            }
        } else {
            if bytes[p] != 2 || bytes[p + 1] != 0 {
                return Err(invalid("initial shadow requires revision-two ACL"));
            }
            let count = u16::from_le_bytes(bytes[p + 4..p + 6].try_into().unwrap()) as usize;
            let mut cursor = p + 8;
            for _ in 0..count {
                if cursor + 16 > p + n || ![0, 1].contains(&bytes[cursor]) {
                    return Err(invalid("initial shadow requires bounded allow/deny ACEs"));
                }
                let size =
                    u16::from_le_bytes(bytes[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
                let sid_count = bytes[cursor + 9] as usize;
                if bytes[cursor + 8] != 1
                    || sid_count > 15
                    || size != 16 + 4 * sid_count
                    || cursor + size > p + n
                {
                    return Err(invalid("shadow ACE or SID bounds"));
                }
                cursor += size;
            }
            if cursor > p + n {
                return Err(invalid("shadow ACL overflow"));
            }
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), aligned.as_mut_ptr().cast(), bytes.len());
    }
    let p = aligned.as_mut_ptr().cast();
    if unsafe { IsValidSecurityDescriptor(p) } == 0
        || unsafe { GetSecurityDescriptorLength(p) } as usize > bytes.len()
    {
        return Err(invalid("invalid shadow security descriptor"));
    }
    Ok(aligned)
}
fn create(
    path: &str,
    i: &Input<'_>,
    index: usize,
    payload_writer: Option<&mut dyn FnMut(usize, &mut File) -> io::Result<()>>,
) -> io::Result<()> {
    let mut sd = descriptor(i.security)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    let name = wide(path);
    if i.directory {
        // SAFETY: NUL-terminated bounded path, live validated descriptor.
        return check(unsafe { CreateDirectoryW(name.as_ptr(), &sa) });
    }
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x011f01ff,
            0,
            &sa,
            1,
            0x80200000,
            ptr::null_mut(),
        )
    };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: unique handle ownership is transferred to File.
    let mut f = unsafe { File::from_raw_handle(h) };
    suppress_access(&f)?;
    ctl(&f, 0x9c280, &[0; 8], 0)?;
    if let Some(writer) = payload_writer {
        writer(index, &mut f)?;
    } else {
        f.write_all(i.payload)?;
    }
    f.sync_all()?;
    Ok(())
}
fn basic(file: &File, i: &Input<'_>) -> io::Result<()> {
    let mut b = [0u64; 5];
    b[..4].copy_from_slice(&i.times);
    b[4] = i.attributes as u64;
    // SAFETY: FILE_BASIC_INFO layout, aligned initialized forty-byte buffer.
    check(unsafe { SetFileInformationByHandle(file.as_raw_handle(), 0, b.as_ptr().cast(), 40) })
}
/// Restricted lab destination: measured disk3, not the source or Windows disk.
/// Probe/verify have no creation or stored-metadata setters; handle access-time
/// suppression is still required and is never substituted for expected times.
pub fn run(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    run_role(
        binding,
        source_disk,
        input,
        mode,
        same_security,
        false,
        false,
        None,
        None,
    )
}
/// Ordinary stream forms remain confined to the independent lab shadow.
pub fn run_ordinary(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    run_role(
        binding,
        source_disk,
        input,
        mode,
        same_security,
        false,
        true,
        None,
        None,
    )
}
/// Construct an independent native ReFS shadow with bytes supplied in bounded
/// chunks by the owning caller. The callback receives the input index and a
/// new file handle; native readback verifies the declared EOF and SHA-256.
pub fn run_ordinary_streaming(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    retain_eligible: bool,
    payload_writer: &mut impl FnMut(usize, &mut File) -> io::Result<()>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    run_role(
        binding,
        source_disk,
        input,
        if retain_eligible {
            Mode::ConstructRetaining
        } else {
            Mode::Construct
        },
        same_security,
        false,
        true,
        Some(payload_writer),
        None,
    )
}

/// Construct a Windows-created ReFS shadow on a separately bound dedicated
/// data disk. The source callback provides checked logical NTFS bytes; this
/// function never opens or writes the source disk.
pub fn run_general_ordinary_streaming(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    retain_eligible: bool,
    payload_writer: &mut impl FnMut(usize, &mut File) -> io::Result<()>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralReport> {
    run_general_ordinary_streaming_with_resource_profile(
        pair,
        input,
        retain_eligible,
        payload_writer,
        same_security,
        None,
    )
}

/// Construct a separately bound shadow under an explicitly selected resource
/// profile. This does not admit the source or authorize conversion.
pub fn run_general_ordinary_streaming_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    retain_eligible: bool,
    payload_writer: &mut impl FnMut(usize, &mut File) -> io::Result<()>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralReport> {
    pair.validate_with_resource_profile(resource_profile)?;
    let binding = DiskBinding {
        disk_number: pair.shadow.disk_number,
        volume_guid: pair.shadow.volume_guid.clone(),
        identity: pair.shadow.identity.clone(),
    };
    let native = run_role_profile(
        binding,
        pair.source.disk_number,
        input,
        if retain_eligible {
            Mode::ConstructRetaining
        } else {
            Mode::Construct
        },
        &same_security,
        false,
        true,
        Some(payload_writer),
        Some(&pair.shadow),
        None,
        None,
        resource_profile,
    )?;
    validate_existing(&native, input, &same_security, false, None)?;
    Ok(GeneralReport {
        pair,
        native,
        conversion_qualified: false,
    })
}

/// Re-observe an existing general shadow without creating files or changing
/// stored metadata. Security/namespace comparison remains caller-owned.
pub fn verify_general_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralReport> {
    verify_general_ordinary_with_resource_profile(pair, input, same_security, None)
}

pub fn verify_general_ordinary_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralReport> {
    pair.validate_with_resource_profile(resource_profile)?;
    let binding = DiskBinding {
        disk_number: pair.shadow.disk_number,
        volume_guid: pair.shadow.volume_guid.clone(),
        identity: pair.shadow.identity.clone(),
    };
    let native = run_role_profile(
        binding,
        pair.source.disk_number,
        input,
        Mode::Verify,
        &same_security,
        false,
        true,
        None,
        Some(&pair.shadow),
        None,
        None,
        resource_profile,
    )?;
    validate_existing(&native, input, &same_security, false, None)?;
    Ok(GeneralReport {
        pair,
        native,
        conversion_qualified: false,
    })
}

/// This route is callable only with an actual borrowed native read-only
/// volume capability. The enclosing freeze lease retains persistent READ_ONLY
/// storage throughout this strict semantic observation.
pub(crate) fn verify_general_ordinary_readonly_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: &native::GeneralReadonlyRefsVolume<'_>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralReport> {
    pair.validate_with_resource_profile(resource_profile)?;
    if protected.binding() != &pair.shadow {
        return Err(invalid(
            "protected ReFS lease does not bind the expected shadow",
        ));
    }
    let binding = DiskBinding {
        disk_number: pair.shadow.disk_number,
        volume_guid: pair.shadow.volume_guid.clone(),
        identity: pair.shadow.identity.clone(),
    };
    let native = run_role_profile(
        binding,
        pair.source.disk_number,
        input,
        Mode::Verify,
        &same_security,
        false,
        true,
        None,
        Some(&pair.shadow),
        None,
        Some(protected),
        resource_profile,
    )?;
    validate_existing(&native, input, &same_security, false, None)?;
    Ok(GeneralReport {
        pair,
        native,
        conversion_qualified: false,
    })
}

/// Observe exactly the expected namespace and all native stream metadata,
/// without reading a single byte of file contents. Allocation-only shadow
/// prefixes may contain unrelated scratch bytes until the composite reader
/// supplies the admitted NTFS payload. This report is not that payload proof.
pub(crate) fn observe_general_layout_readonly_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: &native::GeneralReadonlyRefsVolume<'_>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralLayoutReport> {
    pair.validate_with_resource_profile(resource_profile)?;
    if protected.binding() != &pair.shadow {
        return Err(invalid("protected ReFS layout lease binding differs"));
    }
    let binding = DiskBinding {
        disk_number: pair.shadow.disk_number,
        volume_guid: pair.shadow.volume_guid.clone(),
        identity: pair.shadow.identity.clone(),
    };
    let native = run_role_profile(
        binding,
        pair.source.disk_number,
        input,
        Mode::ObserveLayout,
        &same_security,
        false,
        true,
        None,
        Some(&pair.shadow),
        None,
        Some(protected),
        resource_profile,
    )?;
    validate_existing_profile(&native, input, &same_security, false, None, false)?;
    if native.payload_bytes_written != 0 || native.conversion_qualified {
        return Err(invalid(
            "protected layout observer granted mutation authority",
        ));
    }
    Ok(GeneralLayoutReport {
        pair,
        native,
        expected_stream_sha256: input
            .iter()
            .map(|item| (!item.directory).then(|| item.logical_sha256()))
            .collect(),
        metadata_and_namespace_verified: true,
        complete_stream_mappings_verified: true,
        storage_validity_verified: true,
        data_integrity_disabled: true,
        payload_bytes_read: 0,
        residuals: Vec::new(),
        residual_contents_verified: false,
        logical_contents_verified: false,
        raw_image_equality_verified: false,
        complete_allocation_graph_verified: false,
        conversion_qualified: false,
    })
}

/// Composite-only extension of the zero-payload layout observer. Reads exactly
/// the source-hashed initialized suffix of each file, never the placeholder
/// prefix. The raw-image bracket and source binding remain caller-owned.
pub(crate) fn observe_general_layout_residuals_readonly_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    residuals: &[LayoutResidualExpectation],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: &native::GeneralReadonlyRefsVolume<'_>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralLayoutReport> {
    let mut report = observe_general_layout_readonly_with_resource_profile(
        pair,
        input,
        &same_security,
        protected,
        resource_profile,
    )?;
    let required: Vec<_> = input
        .iter()
        .enumerate()
        .filter(|(_, item)| !item.directory && item.logical_length() % 4096 != 0)
        .collect();
    if required.len() != residuals.len() {
        return Err(invalid("composite residual stream coverage differs"));
    }
    for ((index, item), expected) in required.iter().zip(residuals) {
        let length = item.logical_length();
        if expected.object_index != *index
            || expected.logical_offset != length / 4096 * 4096
            || expected.length != length % 4096
            || expected.length == 0
            || expected.sha256.len() != 64
            || !expected
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(
                "composite residual expectation escapes initialized suffix",
            ));
        }
    }
    let binding = &report.native.binding;
    let before = protected.snapshot(binding, &mut report.native.events)?;
    if before.disk_attributes != 2
        || before.device != report.native.before.device
        || before.layout != report.native.before.layout
    {
        return Err(invalid("composite residual native binding changed"));
    }
    let mut privileges = Privileges::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])?;
    let root = format!("\\\\?\\Volume{{{}}}\\", binding.volume_guid);
    let mut buffer = [0u8; 4096];
    let mut bytes_read = 0u64;
    for expected in residuals {
        let object = &report.native.objects[expected.object_index];
        let path = format!("{}{}", root, object.components.join("\\"));
        let mut file = open_protected_readonly(&path, false)?;
        if snapshot(&file) != object.before {
            return Err(invalid(
                "composite residual identity or metadata changed before read",
            ));
        }
        file.seek(SeekFrom::Start(expected.logical_offset))?;
        let count = expected.length as usize;
        file.read_exact(&mut buffer[..count])?;
        if file.read(&mut buffer[..1])? != 0
            || hex::encode(Sha256::digest(&buffer[..count])) != expected.sha256
            || snapshot(&file) != object.after
        {
            return Err(invalid(
                "composite initialized suffix contents, EOF or metadata differ",
            ));
        }
        bytes_read = bytes_read
            .checked_add(expected.length)
            .ok_or_else(|| invalid("composite residual byte count overflow"))?;
    }
    privileges.restore()?;
    report
        .native
        .privilege_states
        .extend_from_slice(privileges.audit());
    let after = protected.snapshot(binding, &mut report.native.events)?;
    if serde_json::to_vec(&before)? != serde_json::to_vec(&after)? {
        return Err(invalid("composite residual protection changed"));
    }
    report.payload_bytes_read = bytes_read;
    report.residuals = residuals.to_vec();
    report.residual_contents_verified = true;
    Ok(report)
}

/// Inspect the original data disk after the journal handoff has been made
/// durable and it has mounted as ReFS. The caller supplies the pre-cutover
/// source tree from separately pinned recovery artifacts.
pub fn verify_general_converted_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    verify_general_converted_ordinary_with_resource_profile(pair, input, same_security, None)
}

pub fn verify_general_converted_ordinary_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralConvertedReport> {
    let report = observe_general_converted_label_profile(
        pair,
        input,
        None,
        &same_security,
        resource_profile,
    )?;
    validate_existing(&report.native, input, &same_security, false, None)?;
    Ok(report)
}

pub fn verify_general_converted_ordinary_with_label(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    expected_label: &crate::volume_label::VolumeLabel,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    verify_general_converted_ordinary_with_label_and_resource_profile(
        pair,
        input,
        expected_label,
        same_security,
        None,
    )
}

pub fn verify_general_converted_ordinary_with_label_and_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    expected_label: &crate::volume_label::VolumeLabel,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralConvertedReport> {
    expected_label.validate()?;
    let report = observe_general_converted_label_profile(
        pair,
        input,
        Some(expected_label),
        &same_security,
        resource_profile,
    )?;
    validate_existing(&report.native, input, &same_security, false, None)?;
    Ok(report)
}

/// Return the bounded native observation even when a preservation comparison
/// would fail. This diagnostic does not qualify the converted tree or write to
/// the volume; callers must keep it separate from verified results.
pub fn observe_general_converted_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    observe_general_converted_label_profile(pair, input, None, same_security, None)
}

pub fn observe_general_converted_ordinary_with_label(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    expected_label: &crate::volume_label::VolumeLabel,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    expected_label.validate()?;
    observe_general_converted_label_profile(pair, input, Some(expected_label), same_security, None)
}

pub fn observe_general_converted_ordinary_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralConvertedReport> {
    if let Some(label) = expected_label {
        label.validate()?;
    }
    observe_general_converted_label_profile(
        pair,
        input,
        expected_label,
        same_security,
        resource_profile,
    )
}

fn observe_general_converted_label_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralConvertedReport> {
    pair.validate_with_resource_profile(resource_profile)?;
    let binding = DiskBinding {
        disk_number: pair.source.disk_number,
        volume_guid: pair.source.volume_guid.clone(),
        identity: pair.source.identity.clone(),
    };
    let native = run_role_profile(
        binding,
        pair.source.disk_number,
        input,
        Mode::Verify,
        &same_security,
        true,
        true,
        None,
        Some(&pair.source),
        expected_label,
        None,
        resource_profile,
    )?;
    Ok(GeneralConvertedReport {
        pair,
        native,
        conversion_qualified: false,
    })
}

/// Capture exact FileBasicInfo for the mounted volume root using the same
/// access-time-suppressed handle policy as native tree verification.
pub fn observe_general_root_basic(binding: &GeneralDiskBinding) -> io::Result<[u8; 40]> {
    binding.validate()?;
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ])?;
    let root = format!("{}\\", binding.volume_path()?);
    let file = open(&root, true, false)?;
    let basic = info(&file, 0, 40)?;
    drop(file);
    privileges.restore()?;
    Ok(basic
        .try_into()
        .map_err(|_| invalid("root basic-info size"))?)
}

/// After a recorded namespace mutation, require the exact root basic-info
/// bytes captured by that workload. Creation time and attributes must still
/// match the NTFS source; all other objects retain exact original metadata.
pub fn verify_general_converted_after_mutation_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    root_basic_after_mutation: [u8; 40],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    verify_general_mutation_label_profile(
        pair,
        input,
        root_basic_after_mutation,
        None,
        same_security,
        None,
    )
}

pub fn verify_general_converted_after_mutation_ordinary_with_label(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    root_basic_after_mutation: [u8; 40],
    expected_label: &crate::volume_label::VolumeLabel,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    expected_label.validate()?;
    verify_general_mutation_label_profile(
        pair,
        input,
        root_basic_after_mutation,
        Some(expected_label),
        same_security,
        None,
    )
}

pub fn verify_general_converted_after_mutation_ordinary_with_resource_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    root_basic_after_mutation: [u8; 40],
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralConvertedReport> {
    if let Some(label) = expected_label {
        label.validate()?;
    }
    verify_general_mutation_label_profile(
        pair,
        input,
        root_basic_after_mutation,
        expected_label,
        same_security,
        resource_profile,
    )
}

fn verify_general_mutation_label_profile(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    root_basic_after_mutation: [u8; 40],
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<GeneralConvertedReport> {
    let root = input
        .first()
        .ok_or_else(|| invalid("missing expected root"))?;
    if !root.directory || !root.components.is_empty() {
        return Err(invalid("expected post-mutation root differs"));
    }
    let original = basic_bytes(root);
    if root_basic_after_mutation[..8] != original[..8]
        || root_basic_after_mutation[32..] != original[32..]
        || [8usize, 16, 24].into_iter().any(|at| {
            let before = u64::from_le_bytes(original[at..at + 8].try_into().unwrap());
            let after =
                u64::from_le_bytes(root_basic_after_mutation[at..at + 8].try_into().unwrap());
            after < before || after >= i64::MAX as u64
        })
    {
        return Err(invalid(
            "post-mutation root creation, attributes or time order differs",
        ));
    }
    let report = observe_general_converted_label_profile(
        pair,
        input,
        expected_label,
        &same_security,
        resource_profile,
    )?;
    validate_existing(
        &report.native,
        input,
        &same_security,
        false,
        Some(&root_basic_after_mutation),
    )?;
    Ok(report)
}
/// Observe the enrolled converted original after durable journal handoff. All
/// original shadow creation/repair entry points retain the disk3 restriction.
pub fn verify_converted(
    binding: DiskBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    if binding.disk_number != 1
        || layout::guid_bytes(&binding.identity.disk_guid)?
            != layout::guid_bytes("a01574d5-2a5c-4136-958a-dcf0d0e0f7aa")?
        || layout::guid_bytes(&binding.identity.partition_guid)?
            != layout::guid_bytes("79eaccdf-38d3-4561-97cc-9276af5d223a")?
    {
        return Err(invalid("converted natural-tree enrollment differs"));
    }
    let report = run_role(
        binding,
        1,
        input,
        Mode::Verify,
        &same_security,
        true,
        false,
        None,
        None,
    )?;
    validate_existing(&report, input, &same_security, false, None)?;
    Ok(report)
}
/// Verify an ordinary-file conversion on the owning guest after the durable
/// handoff. The caller must bind this volume to its frozen source and journal
/// ticket before bringing it online; this routine independently checks the
/// complete expected tree through the mounted ReFS driver.
pub fn verify_converted_ordinary(
    binding: DiskBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    let report = run_role(
        binding,
        1,
        input,
        Mode::Verify,
        &same_security,
        true,
        true,
        None,
        None,
    )?;
    validate_existing(&report, input, &same_security, false, None)?;
    Ok(report)
}
fn run_role(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    converted: bool,
    ordinary: bool,
    payload_writer: Option<&mut dyn FnMut(usize, &mut File) -> io::Result<()>>,
    general_shadow: Option<&GeneralDiskBinding>,
) -> io::Result<Report> {
    run_role_with_label(
        binding,
        source_disk,
        input,
        mode,
        same_security,
        converted,
        ordinary,
        payload_writer,
        general_shadow,
        None,
    )
}

fn run_role_with_label(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    converted: bool,
    ordinary: bool,
    payload_writer: Option<&mut dyn FnMut(usize, &mut File) -> io::Result<()>>,
    general_shadow: Option<&GeneralDiskBinding>,
    expected_label: Option<&crate::volume_label::VolumeLabel>,
) -> io::Result<Report> {
    run_role_profile(
        binding,
        source_disk,
        input,
        mode,
        same_security,
        converted,
        ordinary,
        payload_writer,
        general_shadow,
        expected_label,
        None,
        None,
    )
}

fn validate_protected_profile(
    mode: Mode,
    converted: bool,
    ordinary: bool,
    payload_writer: bool,
    general_shadow: bool,
    expected_label: bool,
) -> io::Result<()> {
    if !matches!(mode, Mode::Verify | Mode::ObserveLayout)
        || converted
        || !ordinary
        || payload_writer
        || !general_shadow
        || expected_label
    {
        return Err(invalid(
            "protected ReFS lease is restricted to exact shadow verification",
        ));
    }
    Ok(())
}

fn validate_observation_access(attributes: u64, flags: u32, protected: bool) -> io::Result<()> {
    let expected_attributes = if protected { 2 } else { 0 };
    let expected_readonly_flag = if protected { 0x80000 } else { 0 };
    if attributes != expected_attributes || flags & 0x80000 != expected_readonly_flag {
        return Err(invalid(
            "native observation storage/volume protection differs",
        ));
    }
    Ok(())
}

fn run_role_profile(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    converted: bool,
    ordinary: bool,
    mut payload_writer: Option<&mut dyn FnMut(usize, &mut File) -> io::Result<()>>,
    general_shadow: Option<&GeneralDiskBinding>,
    expected_label: Option<&crate::volume_label::VolumeLabel>,
    protected: Option<&native::GeneralReadonlyRefsVolume<'_>>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<Report> {
    if mode == Mode::ObserveLayout && protected.is_none() {
        return Err(invalid(
            "ReFS layout observation requires a protected native lease",
        ));
    }
    let (maximum_objects, maximum_logical_bytes) = match resource_profile {
        None => (160usize, 256u64 * 1024 * 1024),
        Some(
            profile @ (crate::attestation::ResourceProfile::ExperimentalLargeTreeV1
            | crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2),
        ) => {
            if !ordinary || general_shadow.is_none() {
                return Err(invalid(
                    "large-tree shadow profile requires an ordinary general volume",
                ));
            }
            if input.iter().filter(|item| item.directory).count() > 256
                || input.iter().filter(|item| !item.directory).count() > 1024
            {
                return Err(invalid("large-tree shadow object budget exceeded"));
            }
            (1280usize, profile.limits().maximum_stream_bytes)
        }
    };
    if protected.is_some() {
        validate_protected_profile(
            mode,
            converted,
            ordinary,
            payload_writer.is_some(),
            general_shadow.is_some(),
            expected_label.is_some(),
        )?;
    }
    if let Some(label) = expected_label {
        label.validate()?;
        if !converted || mode != Mode::Verify {
            return Err(invalid(
                "restored labels apply only to converted-source verification",
            ));
        }
    }
    if let Some(general) = general_shadow {
        general.validate()?;
        let route_mode_ok = if converted {
            source_disk == binding.disk_number && mode == Mode::Verify
        } else {
            source_disk != binding.disk_number
                && matches!(
                    mode,
                    Mode::ProbeRoot
                        | Mode::Construct
                        | Mode::ConstructRetaining
                        | Mode::Verify
                        | Mode::ObserveLayout
                )
        };
        if !route_mode_ok
            || !ordinary
            || binding.disk_number != general.disk_number
            || binding.volume_guid != general.volume_guid
            || binding.identity != general.identity
            || input.is_empty()
            || input.len() > maximum_objects
        {
            return Err(invalid("general independent shadow profile differs"));
        }
    } else {
        binding.validate()?;
        if binding.disk_number != if converted { 1 } else { 3 }
            || (converted && mode != Mode::Verify)
            || source_disk != 1
            || input.is_empty()
            || input.len() > maximum_objects
            || std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        {
            return Err(invalid("restricted tree shadow lab profile differs"));
        }
    }
    if payload_writer.is_some()
        && (!ordinary || converted || !matches!(mode, Mode::Construct | Mode::ConstructRetaining))
    {
        return Err(invalid(
            "streaming payload callback is restricted to ordinary shadow construction",
        ));
    }
    hard_links::validate(input, hard_links::MAX_NAMES, |part| {
        if resource_profile
            == Some(crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2)
        {
            crate::shadow_names::valid_unicode_component(part)
        } else {
            valid_shadow_component(part)
        }
    })?;
    let mut total = 0u64;
    let mut source_allocations = Vec::new();
    for i in input {
        if i.source_offset.is_some() && !i.source_runs.is_empty() {
            return Err(invalid("mixed single and fragmented source placement"));
        }
        if let Some(offset) = i.source_offset {
            if i.directory
                || i.logical_length() == 0
                || !i.logical_length().is_multiple_of(4096)
                || !offset.is_multiple_of(4096)
                || !offset
                    .checked_add(i.logical_length())
                    .is_some_and(|end| end <= binding.identity.partition_bytes)
            {
                return Err(invalid("single source placement differs"));
            }
            source_allocations.push((offset, i.logical_length()));
        }
        if !i.source_runs.is_empty() {
            let mut covered = 0u64;
            for run in &i.source_runs {
                let offset = run
                    .physical_offset
                    .ok_or_else(|| invalid("fragmented source hole"))?;
                if run.logical_offset != covered
                    || run.length == 0
                    || !run.length.is_multiple_of(4096)
                    || !offset.is_multiple_of(4096)
                    || !offset
                        .checked_add(run.length)
                        .is_some_and(|end| end <= binding.identity.partition_bytes)
                {
                    return Err(invalid("fragmented source placement differs"));
                }
                covered = covered
                    .checked_add(run.length)
                    .ok_or_else(|| invalid("source placement overflow"))?;
                source_allocations.push((offset, run.length));
            }
            if i.directory
                || covered == 0
                || covered > i.logical_length() / 4096 * 4096
                || i.source_runs.len() > 1024
            {
                return Err(invalid("fragmented source placement coverage differs"));
            }
        }
        let digest_only = i.expected_length.is_some() || i.expected_sha256.is_some();
        let digest_allowed = ordinary
            && !i.directory
            && ((matches!(mode, Mode::Verify | Mode::ProbeRoot | Mode::ObserveLayout)
                && payload_writer.is_none())
                || (!converted
                    && matches!(mode, Mode::Construct | Mode::ConstructRetaining)
                    && payload_writer.is_some()));
        if digest_only
            && (!digest_allowed
                || i.expected_length.is_none()
                || i.expected_sha256.is_none()
                || !i.payload.is_empty()
                || !i.expected_sha256.is_some_and(crate::content_digest::is_hex))
        {
            return Err(invalid("invalid hash-only verification input"));
        }
        if payload_writer.is_some() && !i.directory && !digest_only {
            return Err(invalid("streaming source lacks a hash-only expectation"));
        }
        if i.components.len() > 16
            || i.components.iter().any(|s| {
                if resource_profile
                    == Some(crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2)
                {
                    !crate::shadow_names::valid_unicode_component(s)
                } else {
                    !valid_shadow_component(s)
                }
            })
            || i.times.iter().any(|t| *t == 0 || *t >= i64::MAX as u64)
            || i.attributes & !0x2037 != 0
            || (i.attributes & 16 != 0) != i.directory
            || (i.directory && !i.payload.is_empty())
            || (!ordinary
                && !i.directory
                && (i.payload.is_empty() || !i.payload.len().is_multiple_of(65536)))
        {
            return Err(invalid("invalid bounded shadow input"));
        }
        total = total
            .checked_add(i.logical_length())
            .ok_or_else(|| invalid("payload overflow"))?;
        if total > maximum_logical_bytes {
            return Err(invalid("shadow payload budget"));
        }
        descriptor(i.security)?;
        if !ordinary
            && !i.components.is_empty()
            && u16::from_le_bytes(i.security[2..4].try_into().unwrap()) & 0x1000 == 0
        {
            return Err(invalid(
                "initial tree shadow requires protected child DACLs",
            ));
        }
    }
    source_allocations.sort_unstable();
    if source_allocations
        .windows(2)
        .any(|pair| pair[0].0 + pair[0].1 > pair[1].0)
    {
        return Err(invalid("source placement allocations overlap"));
    }
    if input.iter().filter(|i| i.components.is_empty()).count() != 1
        || !input[0].components.is_empty()
        || !input[0].directory
    {
        return Err(invalid("one first directory root required"));
    }
    let mut events = vec![];
    if native::current_windows_disk(&mut events)? == binding.disk_number {
        return Err(invalid("shadow routes to Windows disk"));
    }
    let disk = File::options()
        .read(true)
        .share_mode(3)
        .open(format!("\\\\.\\PhysicalDrive{}", binding.disk_number))?;
    let expected_attributes = if protected.is_some() { 2 } else { 0 };
    let before = observed_shadow_profile(&disk, &binding, general_shadow, protected, &mut events)?;
    if before.disk_attributes != expected_attributes {
        return Err(invalid(
            "shadow protection state differs from its native access route",
        ));
    }
    let root = format!("\\\\?\\Volume{{{}}}\\", binding.volume_guid);
    let opened_volume;
    let volume = if let Some(lease) = protected {
        lease.volume()
    } else {
        opened_volume = File::options()
            .read(true)
            .write(!matches!(mode, Mode::Verify | Mode::ObserveLayout))
            .share_mode(3)
            .open(root.trim_end_matches('\\'))?;
        &opened_volume
    };
    let ext = ctl(&volume, 0x560000, &[], 32)?;
    if ext.len() != 32
        || layout::u32_at(&ext, 0)? != 1
        || layout::u32_at(&ext, 8)? != binding.disk_number
        || layout::u64_at(&ext, 16)? != binding.identity.partition_offset
        || layout::u64_at(&ext, 24)? != binding.identity.partition_bytes
    {
        return Err(invalid("shadow volume physical binding differs"));
    }
    let mut fs = [0u16; 32];
    let mut label = [0u16; 128];
    let (mut serial, mut component, mut flags) = (0, 0, 0);
    let root_w = wide(&root);
    let (mut spc, mut bps, mut free, mut legacy_clusters) = (0, 0, 0, 0);
    // GetDiskFreeSpaceW exposes only a DWORD total-cluster count. Expanded
    // profiles need the same checked 64-bit ReFS data used by protected access.
    let use_volume_data = protected.is_some() || resource_profile.is_some();
    // SAFETY: initialized fixed output buffers and NUL-terminated volume path.
    unsafe {
        if protected.is_some() {
            check(GetVolumeInformationByHandleW(
                volume.as_raw_handle(),
                label.as_mut_ptr(),
                128,
                &mut serial,
                &mut component,
                &mut flags,
                fs.as_mut_ptr(),
                32,
            ))?;
        } else {
            check(GetVolumeInformationW(
                root_w.as_ptr(),
                label.as_mut_ptr(),
                128,
                &mut serial,
                &mut component,
                &mut flags,
                fs.as_mut_ptr(),
                32,
            ))?;
            if !use_volume_data {
                check(GetDiskFreeSpaceW(
                    root_w.as_ptr(),
                    &mut spc,
                    &mut bps,
                    &mut free,
                    &mut legacy_clusters,
                ))?;
            }
        }
    }
    let clusters = if use_volume_data {
        let clusters = query_refs_314_volume_data(volume, binding.identity.partition_bytes)?;
        bps = 512;
        spc = 8;
        clusters
    } else {
        u64::from(legacy_clusters)
    };
    let text = |b: &[u16]| {
        String::from_utf16_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())])
    };
    let label_end = label
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid("unterminated converted volume label"))?;
    let label_matches = volume_label_matches(&label[..label_end], expected_label)?;
    validate_observation_access(before.disk_attributes, flags, protected.is_some())?;
    if text(&fs) != "ReFS" || !label_matches || spc != 8 || bps != 512 {
        return Err(invalid(
            "shadow filesystem, label, geometry or read-only flag differs",
        ));
    }
    let base = ctl(&volume, stream_layout::GET_BASE, &[], 8)?;
    if base.len() != 8 || layout::u64_at(&base, 0)? != 0 {
        return Err(invalid("initial tree shadow requires zero retrieval base"));
    }
    let mut names = vec!["SeBackupPrivilege", "SeSecurityPrivilege"];
    if protected.is_none() {
        names.push("SeRestorePrivilege");
    }
    if mode == Mode::ConstructRetaining {
        names.push("SeManageVolumePrivilege");
    }
    let mut privileges = Privileges::enable_for(&names)?;
    let root_handle = if protected.is_some() {
        open_protected_readonly(&root, true)?
    } else {
        open(&root, true, true)?
    };
    let root_state = snapshot(&root_handle);
    let matched_before = security_matches(&input[0], &root_state, &same_security)?;
    let mut root_security = RootSecurity {
        before: root_state.clone(),
        after: root_state,
        matched_before,
        matched_after: matched_before,
        backup: None,
    };
    let mut security_restorations = vec![];
    let mut retention_attempts = vec![];
    let mut shadow_user_evacuation = Vec::new();
    let constructing = matches!(mode, Mode::Construct | Mode::ConstructRetaining);
    if matches!(mode, Mode::Verify | Mode::ObserveLayout) && !matched_before {
        return Err(invalid("root security changed before verification"));
    }
    if mode == Mode::ProbeRoot {
        let after =
            observed_shadow_profile(&disk, &binding, general_shadow, protected, &mut events)?;
        privileges.restore()?;
        return Ok(Report {
            resource_profile,
            binding,
            before,
            after,
            objects: vec![],
            metadata_allocation: None,
            metadata_allocation_page_proof: None,
            base_sectors: 0,
            privilege_states: privileges.audit().to_vec(),
            events,
            payload_bytes_written: 0,
            conversion_qualified: false,
            root_security,
            security_restorations,
            security_repair_preflight_sha256: None,
            security_repair_privileges: vec![],
            retention_attempts,
            post_mount_indexer_cache: None,
            shadow_user_evacuation: Vec::new(),
        });
    }
    if constructing || mode == Mode::RestoreRootOnly {
        let initial = enumerate(&root_handle)?;
        if initial.iter().any(|e| {
            let n = String::from_utf16_lossy(&e.name_utf16);
            n != "."
                && n != ".."
                && !(n == "System Volume Information"
                    && e.attributes & 16 != 0
                    && e.attributes & 0x400 == 0)
        }) {
            return Err(invalid("independent shadow is not empty"));
        }
        let existing_system = if constructing {
            existing_system_entries(
                &root,
                &initial,
                input,
                resource_profile
                    == Some(crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2),
                &mut events,
            )?
        } else {
            std::collections::BTreeMap::new()
        };
        if !matched_before {
            root_security.backup = Some(backup_security(&root_handle, input[0].security)?);
            root_security.after = snapshot(&root_handle);
            root_security.matched_after =
                security_matches(&input[0], &root_security.after, &same_security)?;
            if !root_security.matched_after {
                return Err(invalid(
                    "backup security restoration did not exactly preserve both descriptor views",
                ));
            }
        }
        if mode == Mode::RestoreRootOnly {
            volume.sync_all()?;
            let after = observed_shadow(&disk, &binding, general_shadow, &mut events)?;
            privileges.restore()?;
            return Ok(Report {
                resource_profile,
                binding,
                before,
                after,
                objects: vec![],
                metadata_allocation: None,
                metadata_allocation_page_proof: None,
                base_sectors: 0,
                privilege_states: privileges.audit().to_vec(),
                events,
                payload_bytes_written: 0,
                conversion_qualified: false,
                root_security,
                security_restorations,
                security_repair_preflight_sha256: None,
                security_repair_privileges: vec![],
                retention_attempts,
                post_mount_indexer_cache: None,
                shadow_user_evacuation: Vec::new(),
            });
        }
        for (index, i) in input.iter().enumerate().skip(1) {
            let path = format!("{}{}", root, i.components.join("\\"));
            if let Some(expected_id) = existing_system.get(i.components) {
                let mut file = open(&path, i.directory, true)?;
                if &query_bytes(&snapshot(&file), 18, 24)?[8..24] != expected_id {
                    return Err(invalid(
                        "target system cache identity changed after preflight",
                    ));
                }
                if !i.directory {
                    file.set_len(0)?;
                    file.seek(SeekFrom::Start(0))?;
                    if let Some(writer) = payload_writer.as_mut() {
                        writer(index, &mut file)?;
                    } else {
                        file.write_all(i.payload)?;
                    }
                    file.sync_all()?;
                }
                events.push(NativeEvent {
                    operation: "reconstruct-known-formatter-system-cache".into(),
                    control_code: 0,
                    input: path.as_bytes().to_vec(),
                    succeeded: true,
                    native_error: None,
                    output: expected_id.clone(),
                });
            } else if let Some(writer) = payload_writer.as_mut() {
                create(&path, i, index, Some(&mut **writer))?;
            } else {
                create(&path, i, index, None)?;
            }
        }
        if mode == Mode::ConstructRetaining {
            let mut evacuation_budget = crate::shadow_evacuation::LEGACY_MAX_MOVES;
            const EVACUATION_EVIDENCE_LIMIT: usize = 4 * 1024 * 1024;
            loop {
                let first_retention_attempt = retention_attempts.len();
                let mut more_evacuation = false;
                let mut evacuated_bytes = 0;
                if resource_profile
                    == Some(crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2)
                {
                    let used = shadow_user_evacuation.iter().fold(
                        0usize,
                        |bytes, report: &evacuation::Report| {
                            bytes.saturating_add(report.evidence_bytes())
                        },
                    );
                    let remaining_evidence = EVACUATION_EVIDENCE_LIMIT.saturating_sub(used);
                    if remaining_evidence >= 4096 {
                        let report = evacuation::run(
                            &volume,
                            &root,
                            input,
                            binding.identity.partition_bytes,
                            evacuation_budget,
                            remaining_evidence,
                        )?;
                        shadow_user_evacuation
                            .try_reserve_exact(1)
                            .map_err(|_| invalid("evacuation batch report storage unavailable"))?;
                        let total_evidence =
                            used.saturating_add(report.evidence_bytes()).saturating_add(
                                shadow_user_evacuation
                                    .capacity()
                                    .saturating_mul(std::mem::size_of::<evacuation::Report>()),
                            );
                        if total_evidence > EVACUATION_EVIDENCE_LIMIT {
                            return Err(invalid(
                                "global evacuation evidence budget exceeded; preserve shadow without retry",
                            ));
                        }
                        evacuation_budget -= report.attempts.len();
                        more_evacuation = report
                            .plan
                            .as_ref()
                            .is_some_and(|plan| plan.remaining_blocked_bytes != 0);
                        evacuated_bytes = report.completed_bytes;
                        shadow_user_evacuation.push(report);
                    }
                }
                let mut planning_cache = None;
                for i in input.iter().filter(|i| !i.directory) {
                    if let Some(offset) = i.source_offset
                        && i.logical_length() > 0
                        && i.logical_length().is_multiple_of(4096)
                    {
                        retain_source_run_on_shadow(
                        &volume,
                        &root,
                        i,
                        binding.identity.partition_bytes,
                        &SourceRun {
                            logical_offset: 0,
                            physical_offset: Some(offset),
                            length: i.logical_length(),
                        },
                        &mut retention_attempts,
                        resource_profile.is_some(),
                        resource_profile
                            == Some(
                                crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
                            ),
                        &mut planning_cache,
                        !more_evacuation,
                    )?;
                    }
                    for run in &i.source_runs {
                        retain_source_run_on_shadow(
                        &volume,
                        &root,
                        i,
                        binding.identity.partition_bytes,
                        run,
                        &mut retention_attempts,
                        resource_profile.is_some(),
                        resource_profile
                            == Some(
                                crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
                            ),
                        &mut planning_cache,
                        !more_evacuation,
                    )?;
                    }
                }
                let retained_progress = retention_attempts[first_retention_attempt..]
                    .iter()
                    .all(|attempt| attempt.native_error.is_none())
                    && retention_attempts[first_retention_attempt..]
                        .iter()
                        .any(|attempt| attempt.submitted && attempt.all_clusters_at_source);
                if !more_evacuation
                    || evacuated_bytes == 0
                    || !retained_progress
                    || evacuation_budget == 0
                    || retention_attempts.len() == MAX_RETENTION_ATTEMPTS
                {
                    break;
                }
            }
        }
        if input.iter().any(|i| !i.additional_names.is_empty()) {
            let mut handles = std::collections::BTreeMap::new();
            for (index, item) in input.iter().enumerate() {
                handles.insert(
                    index,
                    open(
                        &format!("{root}{}", item.components.join("\\")),
                        item.directory,
                        true,
                    )?,
                );
            }
            let links = hard_links::create_owned(input, &handles)?;
            events.push(NativeEvent {
                operation: "create-owned-hard-links".into(),
                control_code: 11,
                input: Vec::new(),
                succeeded: true,
                native_error: None,
                output: serde_json::to_vec(&links).map_err(io::Error::other)?,
            });
        }
        // Directory ACLs can propagate through any hard-link name. Finish all
        // parent-first directory security before restoring each logical file
        // once, even when its canonical name is shallower than an alias.
        let mut security_order: Vec<_> = input.iter().collect();
        security_order.sort_by_key(|i| (!i.directory, i.components.len()));
        for i in security_order {
            let h = open(
                &format!("{}{}", root, i.components.join("\\")),
                i.directory,
                true,
            )?;
            let before = snapshot(&h);
            if !security_matches(i, &before, &same_security)? {
                let backup = backup_security(&h, i.security)?;
                let after = snapshot(&h);
                if !security_matches(i, &after, &same_security)? {
                    return Err(invalid(
                        "object backup-security restoration differs from the source",
                    ));
                }
                security_restorations.push(ObjectSecurityRestore {
                    components: i.components.to_vec(),
                    before,
                    after,
                    backup,
                });
            }
        }
        // Basic metadata is independent of ACL inheritance. Restore it only
        // after all security propagation, with children before their parents.
        for i in input.iter().rev() {
            let h = open(
                &format!("{}{}", root, i.components.join("\\")),
                i.directory,
                true,
            )?;
            basic(&h, i)?;
            if !i.directory {
                h.sync_all()?;
            }
        }
        volume.sync_all()?;
    }
    // Full semantic verification retains both bitmap observations. Layout-only
    // collection queries the metadata-inclusive view through the actual
    // protected post-freeze volume; this is still not an allocation graph proof.
    let bitmaps = if mode == Mode::ObserveLayout {
        None
    } else {
        let legacy = crate::bitmap_observation::Observation::capture(
            volume,
            &[0; 8],
            binding.identity.partition_bytes,
            resource_profile.is_some(),
        )?;
        let mut ex_input = [0; 16];
        ex_input[8] = 1;
        let metadata = crate::bitmap_observation::Observation::capture(
            volume,
            &ex_input,
            binding.identity.partition_bytes,
            resource_profile.is_some(),
        )?;
        Some((legacy, metadata))
    };
    let layout_metadata = if mode == Mode::ObserveLayout {
        if protected.is_none() {
            return Err(invalid(
                "layout allocation requires the protected read-only lease",
            ));
        }
        let mut input = [0u8; 16];
        input[8] = 1; // Same existing metadata-inclusive bitmap request.
        Some(crate::bitmap_observation::Observation::capture(
            volume,
            &input,
            binding.identity.partition_bytes,
            resource_profile.is_some(),
        )?)
    } else {
        None
    };
    let metadata_view = layout_metadata
        .as_ref()
        .or_else(|| bitmaps.as_ref().map(|(_, metadata)| metadata));
    let metadata_allocation = metadata_view
        .map(|metadata| metadata.allocation_map(binding.identity.partition_bytes))
        .transpose()?;
    // These maps are immutable for the complete verification pass. Hash each
    // only once even if many files report a source-placement candidate. Move
    // attempts above still collect and recheck fresh native bitmaps separately.
    let candidate_views = if let Some((legacy_bitmap, metadata_bitmap)) = bitmaps
        .as_ref()
        .filter(|_| input.iter().any(|i| i.source_offset.is_some()))
    {
        Some((
            legacy_bitmap.view(binding.identity.partition_bytes)?,
            metadata_bitmap.view(binding.identity.partition_bytes)?,
        ))
    } else {
        None
    };
    // Objects are independent: each is opened, snapshotted, queried and, when
    // verifying, hashed under its own handle. Observe them on the available
    // cores in input order; the first failure in input order is returned.
    let observe = |i: &Input<'_>| -> io::Result<ObjectReport> {
        let path = format!("{}{}", root, i.components.join("\\"));
        let mut h = if protected.is_some() {
            open_protected_readonly(&path, i.directory)?
        } else {
            open(&path, i.directory, false)?
        };
        let before = snapshot(&h);
        let expected_allocation = layout::u64_at(query_bytes(&before, 1, 24)?, 0)?;
        let mut resident_data = false;
        let mut retrieval_page_proof = None;
        let (logical_sha256, retrieval, cached_validity, storage_validity, integrity, namespace) =
            if i.directory {
                (None, vec![], vec![], vec![], vec![], enumerate(&h)?)
            } else {
                let (first, continuation) = crate::stream_native::retrieval_queries(&h);
                let retrieval = if first.native_error.is_none()
                    && continuation.is_empty()
                    && ordinary
                    && i.logical_length() == 0
                    && expected_allocation == 0
                    && first.bytes.len() == 16
                    && layout::u32_at(&first.bytes, 0)? == 0
                    && layout::u64_at(&first.bytes, 8)? == 0
                {
                    vec![]
                } else if ordinary
                    && resident_allocation(i.logical_length(), expected_allocation)
                    && first.native_error == Some(38)
                    && first.bytes.is_empty()
                    && continuation.is_empty()
                {
                    resident_data = true;
                    vec![]
                } else {
                    let capture=crate::retrieval_paging::assemble_queries(&first,&continuation).map_err(|e|io::Error::other(format!(
                            "retrieval pointers for {:?}, allocation={expected_allocation}, logical={}: {e}",
                            i.components,
                            i.logical_length()
                        )))?;
                    retrieval_page_proof = Some(capture.proof);
                    capture.canonical
                };
                let runs = if retrieval.is_empty() {
                    vec![]
                } else {
                    stream_layout::parse_complete_retrieval(&retrieval)?
                };
                let mut end = 0u64;
                for r in runs {
                    if r.vcn != end
                        || r.lcn
                            .is_none_or(|l| l.checked_add(r.clusters).is_none_or(|e| e > clusters))
                    {
                        return Err(invalid("shadow physical mapping is invalid"));
                    }
                    end += r.clusters;
                }
                if (!ordinary && end * 4096 != i.logical_length())
                    || (ordinary
                        && !resident_data
                        && (end * 4096 != expected_allocation
                            || (expected_allocation == 0 && i.logical_length() > 4096)
                            || (expected_allocation != 0
                                && expected_allocation
                                    < i.logical_length().next_multiple_of(4096))
                            || expected_allocation > i.logical_length().next_multiple_of(65536)))
                {
                    return Err(invalid(
                        "shadow allocation differs from initialized payload",
                    ));
                }
                let mut regions = vec![];
                for usage in [1u32, 2] {
                    if ordinary && (expected_allocation == 0 || resident_data) {
                        regions.push(vec![]);
                        continue;
                    }
                    let mut q = [0; 24];
                    q[8..16].copy_from_slice(&i.logical_length().to_le_bytes());
                    q[16..20].copy_from_slice(&usage.to_le_bytes());
                    let b = ctl(&h, 0x90284, &q, 16 + 24 * 1024).map_err(|e|io::Error::other(format!("file regions for {:?}, usage={usage}, allocation={expected_allocation}: {e}",i.components)))?;
                    if ordinary {
                        crate::region_layout::validate_logical(&b, i.logical_length(), usage)?;
                    } else {
                        crate::region_layout::validate(&b, i.logical_length(), usage)?;
                    }
                    regions.push(b);
                }
                let integrity = ctl(&h, 0x9027c, &[], 16).map_err(|e| {
                    io::Error::other(format!("integrity for {:?}: {e}", i.components))
                })?;
                if integrity.len() != 16
                    || integrity[..8] != [0; 8]
                    || layout::u32_at(&integrity, 12)? != 4096
                {
                    return Err(invalid("shadow data integrity profile differs"));
                }
                let logical_hash = if mode == Mode::ObserveLayout {
                    None
                } else if let Some(expected) = i.expected_sha256 {
                    let actual = hash_exact_stream(&mut h, i.logical_length())?;
                    if actual != expected {
                        return Err(invalid("converted logical stream hash differs"));
                    }
                    Some(actual)
                } else {
                    let mut bytes = vec![];
                    (&mut h)
                        .take(i.logical_length() + 1)
                        .read_to_end(&mut bytes)?;
                    if bytes != i.payload {
                        return Err(invalid("shadow logical bytes or EOF differ"));
                    }
                    Some(crate::content_digest::of(&bytes))
                };
                (
                    logical_hash,
                    retrieval,
                    regions.remove(0),
                    regions.remove(0),
                    integrity,
                    vec![],
                )
            };
        let after = snapshot(&h);
        if before != after {
            return Err(invalid("shadow metadata changed during observation"));
        }
        let streams = if i.directory {
            vec![]
        } else {
            let mut b = info(&h, 7, stream_layout::MAX_STREAM_BUFFER)?;
            let (entries, used) = stream_layout::parse_streams(&b)?;
            if entries.len() != 1
                || !entries[0].name.is_empty()
                || entries[0].logical_size != i.logical_length()
                || entries[0].allocated_size
                    != if ordinary {
                        expected_allocation
                    } else {
                        i.logical_length()
                    }
            {
                return Err(invalid("unexpected target data stream or allocation"));
            }
            b.truncate(used);
            b
        };
        Ok(ObjectReport {
            components: i.components.to_vec(),
            additional_names: hard_links::observe(&root, i, &before, protected.is_some())?,
            before,
            after,
            logical_sha256,
            retrieval,
            retrieval_page_proof,
            resident_data,
            cached_validity,
            storage_validity,
            integrity,
            namespace,
            streams,
            source_candidate: i
                .source_offset
                .filter(|_| mode != Mode::ObserveLayout)
                .map(|offset| -> io::Result<_> {
                    let (legacy_view, metadata_view) = candidate_views
                        .as_ref()
                        .ok_or_else(|| invalid("candidate bitmap views missing"))?;
                    Ok(CandidateReport {
                        legacy: legacy_view
                            .candidate(offset, i.logical_length().next_multiple_of(4096))?,
                        metadata_inclusive: metadata_view
                            .candidate(offset, i.logical_length().next_multiple_of(4096))?,
                        legacy_page_proof: bitmaps
                            .as_ref()
                            .ok_or_else(|| invalid("candidate legacy bitmap missing"))?
                            .0
                            .proof(),
                        metadata_page_proof: bitmaps
                            .as_ref()
                            .ok_or_else(|| invalid("candidate metadata bitmap missing"))?
                            .1
                            .proof(),
                    })
                })
                .transpose()?,
        })
    };
    let objects = observe_in_parallel(input, observe)?;
    let post_mount_indexer_cache = if converted
        && resource_profile
            == Some(crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2)
    {
        observe_post_mount_indexer_cache(&root, input, &objects)?
    } else {
        None
    };
    let after = observed_shadow_profile(&disk, &binding, general_shadow, protected, &mut events)?;
    validate_observation_access(after.disk_attributes, flags, protected.is_some())?;
    privileges.restore()?;
    Ok(Report {
        resource_profile,
        binding,
        before,
        after,
        objects,
        metadata_allocation,
        metadata_allocation_page_proof: metadata_view.map(|metadata| metadata.proof()),
        base_sectors: 0,
        privilege_states: privileges.audit().to_vec(),
        events,
        payload_bytes_written: if constructing { total as u64 } else { 0 },
        conversion_qualified: false,
        root_security,
        security_restorations,
        security_repair_preflight_sha256: None,
        security_repair_privileges: vec![],
        retention_attempts,
        post_mount_indexer_cache,
        shadow_user_evacuation,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn retention_budget_fixture() -> RetentionAttempt {
        let mut bitmap = vec![0; 17];
        bitmap[8..16].copy_from_slice(&1_u64.to_le_bytes());
        let bitmap_capture = crate::bitmap_paging::assemble_queries(
            &crate::attestation::IoctlQuery {
                code: stream_layout::GET_BITMAP,
                input: vec![0; 8],
                bytes: bitmap.clone(),
                native_error: None,
            },
            &[],
            &[0; 8],
        )
        .unwrap();
        let mut retrieval = vec![0; 32];
        retrieval[..4].copy_from_slice(&1_u32.to_le_bytes());
        retrieval[16..24].copy_from_slice(&1_u64.to_le_bytes());
        let mapping = crate::retrieval_paging::assemble_queries(
            &crate::attestation::IoctlQuery {
                code: stream_layout::GET_RETRIEVAL,
                input: vec![0; 8],
                bytes: retrieval,
                native_error: None,
            },
            &[],
        )
        .unwrap();
        RetentionAttempt {
            components: vec!["fixture.bin".into()],
            starting_vcn: 0,
            destination_lcn: 0,
            clusters: 1,
            candidate: CandidateReport {
                legacy: crate::bitmap_layout::candidate(&bitmap, 0, 4096, 4096).unwrap(),
                metadata_inclusive: crate::bitmap_layout::candidate(&bitmap, 0, 4096, 4096)
                    .unwrap(),
                legacy_page_proof: bitmap_capture.proof.clone(),
                metadata_page_proof: bitmap_capture.proof,
            },
            submitted: false,
            native_error: None,
            mapping_before: mapping.canonical.clone(),
            mapping_after: mapping.canonical,
            mapping_before_page_proof: mapping.proof.clone(),
            mapping_after_page_proof: mapping.proof,
            all_clusters_at_source: true,
        }
    }
    #[test]
    fn retention_evidence_budget_counts_capacity_and_refuses_without_appending() {
        let mut attempts = vec![];
        let mut attempt = retention_budget_fixture();
        attempt
            .mapping_before
            .reserve_exact(MAX_RETENTION_EVIDENCE_BYTES);
        assert!(retention_attempt_heap(&attempt) > MAX_RETENTION_EVIDENCE_BYTES);
        assert!(append_retention_attempt(&mut attempts, attempt).is_err());
        assert!(attempts.is_empty());
    }
    #[test]
    fn retention_evidence_budget_is_cumulative_across_complete_maps_and_proofs() {
        let mut attempts = vec![];
        for index in 0..2 {
            let mut attempt = retention_budget_fixture();
            attempt
                .mapping_before
                .reserve_exact(MAX_RETENTION_EVIDENCE_BYTES / 4);
            attempt
                .mapping_after
                .reserve_exact(MAX_RETENTION_EVIDENCE_BYTES / 4);
            let result = append_retention_attempt(&mut attempts, attempt);
            if index == 0 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }
        assert_eq!(attempts.len(), 1);
        assert!(
            remaining_retention_evidence(&mut attempts).unwrap() < MAX_RETENTION_EVIDENCE_BYTES / 2
        );
        let mut attempt = retention_budget_fixture();
        let before = retention_attempt_heap(&attempt);
        attempt.mapping_after_page_proof.pages[0]
            .response_sha256
            .reserve_exact(4096);
        assert!(retention_attempt_heap(&attempt) >= before + 4096);
    }
    #[test]
    fn admitted_tracking_log_is_not_a_formatter_cache_replacement() {
        let path = vec!["System Volume Information".into(), "tracking.log".into()];
        let digest = "1fb89041274dbd08edef3d324be87aebfc4e303c7e87d01c7a29d8b547b124b1";
        let source = Input {
            components: &path,
            additional_names: &[],
            directory: false,
            times: [134374560922807180; 4],
            attributes: 0x26,
            security: &[],
            expected_api_security: None,
            payload: &[],
            expected_length: Some(20480),
            expected_sha256: Some(digest),
            source_offset: Some(25853952),
            source_runs: vec![],
        };
        source_formatter_cache_bounds(&[source]).unwrap();
        assert!(valid_shadow_component(&path[1]));
        // Even an admitted source with this name cannot authorize reuse of a
        // preexisting target entry. If absent, it follows normal CREATE_NEW.
        assert!(!formatter_target_reusable("tracking.log", 0x26, true));
        assert!(!formatter_target_reusable("unknown.bin", 0x20, true));
    }

    #[test]
    fn formatter_target_reuse_stays_explicit_bounded_and_source_matched() {
        for name in ["WPSettings.dat", "IndexerVolumeGuid"] {
            assert!(formatter_target_reusable(name, 0x20, true));
            assert!(!formatter_target_reusable(name, 0x20, false));
            for flag in [16, 0x400, 0x800, 0x4000] {
                assert!(!formatter_target_reusable(name, 0x20 | flag, true));
            }
            let path = vec!["System Volume Information".into(), name.into()];
            let make_source = |length| Input {
                components: &path,
                additional_names: &[],
                directory: false,
                times: [1; 4],
                attributes: 0x20,
                security: &[],
                expected_api_security: None,
                payload: &[],
                expected_length: Some(length),
                expected_sha256: None,
                source_offset: None,
                source_runs: vec![],
            };
            source_formatter_cache_bounds(&[make_source(1024 * 1024)]).unwrap();
            assert!(source_formatter_cache_bounds(&[make_source(1024 * 1024 + 1)]).is_err());
        }
    }
    #[test]
    fn protected_verification_rejects_writable_flags_and_mutation_modes() {
        validate_observation_access(0, 0, false).unwrap();
        validate_observation_access(2, 0x80000, true).unwrap();
        for (attributes, flags, protected) in [
            (2, 0x80000, false),
            (0, 0, true),
            (2, 0, true),
            (0, 0x80000, false),
            (3, 0x80000, true),
            (1, 0, false),
        ] {
            assert!(validate_observation_access(attributes, flags, protected).is_err());
        }
        validate_protected_profile(Mode::Verify, false, true, false, true, false).unwrap();
        for mode in [
            Mode::ProbeRoot,
            Mode::RestoreRootOnly,
            Mode::Construct,
            Mode::ConstructRetaining,
        ] {
            assert!(validate_protected_profile(mode, false, true, false, true, false).is_err());
        }
        for (converted, ordinary, writer, general, label) in [
            (true, true, false, true, false),
            (false, false, false, true, false),
            (false, true, true, true, false),
            (false, true, false, false, false),
            (false, true, false, true, true),
        ] {
            assert!(
                validate_protected_profile(
                    Mode::Verify,
                    converted,
                    ordinary,
                    writer,
                    general,
                    label
                )
                .is_err()
            );
        }
    }

    #[test]
    fn protected_file_handles_request_no_write_or_delete_rights() {
        let write_or_delete = 0x40000000
            | 0x10000000
            | 0x00010000
            | 0x00040000
            | 0x00080000
            | 0x00000002
            | 0x00000004
            | 0x00000010
            | 0x00000100;
        assert_eq!(PROTECTED_READ_ACCESS & write_or_delete, 0);
        assert_eq!(PROTECTED_READ_ACCESS & 0x01020081, 0x01020081);
    }

    #[test]
    fn converted_labels_are_explicit_and_shadow_enrollment_remains_exact() {
        let source = crate::volume_label::VolumeLabel::from_text("工程 😀").unwrap();
        assert!(volume_label_matches(source.utf16(), Some(&source)).unwrap());
        assert!(!volume_label_matches(source.utf16(), None).unwrap());
        assert!(
            volume_label_matches(
                &"n2r-retained-shadow".encode_utf16().collect::<Vec<_>>(),
                None
            )
            .unwrap()
        );
        assert!(
            !volume_label_matches(
                &"N2R-RETAINED-SHADOW".encode_utf16().collect::<Vec<_>>(),
                None
            )
            .unwrap()
        );
        let empty = crate::volume_label::VolumeLabel::from_text("").unwrap();
        assert!(volume_label_matches(&[], Some(&empty)).unwrap());
        assert!(!volume_label_matches(&[], None).unwrap());
    }
    #[test]
    fn resident_metadata_allocation_cannot_be_a_physical_data_cluster() {
        assert!(resident_allocation(76, 80));
        assert!(resident_allocation(12, 16));
        assert!(resident_allocation(0, 0));
        for (logical, allocated) in [(76, 0), (76, 64), (4096, 4096), (1, 4096), (4097, 8192)] {
            assert!(!resident_allocation(logical, allocated));
        }
    }
    #[test]
    fn api_projection_never_substitutes_for_the_stored_kernel_descriptor() {
        let input = Input {
            components: &[],
            additional_names: &[],
            directory: false,
            times: [1; 4],
            attributes: 32,
            security: &[1],
            expected_api_security: Some(&[2]),
            payload: &[],
            expected_length: None,
            expected_sha256: None,
            source_offset: None,
            source_runs: vec![],
        };
        let mut actual = Snapshot {
            queries: vec![],
            security: vec![2],
            security_error: None,
            kernel_security: Some(crate::attestation::SecurityQuery {
                bytes: vec![1],
                native_error: None,
            }),
        };
        let same = |a: &[u8], b: &[u8]| Ok(a == b);
        assert!(security_matches(&input, &actual, &same).unwrap());
        actual.kernel_security.as_mut().unwrap().bytes = vec![2];
        assert!(!security_matches(&input, &actual, &same).unwrap());
        actual.kernel_security.as_mut().unwrap().bytes = vec![1];
        actual.security = vec![1];
        assert!(!security_matches(&input, &actual, &same).unwrap());
    }
    #[test]
    fn ordinary_shadow_names_allow_internal_spaces_but_refuse_devices() {
        assert!(valid_shadow_component("Quarterly Report 1.txt"));
        assert!(valid_shadow_component("a  b.txt"));
        assert!(valid_shadow_component("Q4 (final) #1 & notes.txt"));
        for name in [
            "a ",
            "CON.txt",
            "CON .txt",
            "COM1 .dat",
            "a:b",
            "a\\b",
            "a?b",
            "a*b",
            "é",
        ] {
            assert!(!valid_shadow_component(name), "{name}");
        }
    }
    #[test]
    fn fragmented_retention_checks_only_the_requested_vcn_window() {
        let runs = vec![
            stream_layout::Run {
                vcn: 0,
                lcn: Some(40),
                clusters: 2,
            },
            stream_layout::Run {
                vcn: 2,
                lcn: Some(100),
                clusters: 3,
            },
            stream_layout::Run {
                vcn: 5,
                lcn: Some(70),
                clusters: 2,
            },
        ];
        assert!(mapping_matches_run(&runs, 2, 100, 3).unwrap());
        assert!(mapping_matches_run(&runs, 3, 101, 2).unwrap());
        assert!(!mapping_matches_run(&runs, 2, 101, 3).unwrap());
        assert!(!mapping_matches_run(&runs, 1, 41, 4).unwrap());
        assert!(!mapping_matches_run(&runs, 2, 100, 4).unwrap());
    }
    #[test]
    fn backup_security_stream_uses_sdk_name_offset_and_keeps_descriptor_bytes() {
        use windows_sys::Win32::Storage::FileSystem::WIN32_STREAM_ID;
        assert_eq!(mem::offset_of!(WIN32_STREAM_ID, cStreamName), 20);
        let sd = vec![42; 228];
        let b = security_stream(&sd).unwrap();
        assert_eq!(b.len(), 248);
        assert_eq!(&b[20..], sd);
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 228);
        assert_eq!(&b[16..20], [0; 4]);
    }
    #[test]
    fn repair_preflight_allows_only_the_measured_creation_control_bit_loss() {
        let mut expected = vec![0; 24];
        expected[0] = 1;
        expected[2..4].copy_from_slice(&0x9404u16.to_le_bytes());
        let same = |a: &[u8], b: &[u8]| Ok(a == b);
        let mut actual = expected.clone();
        actual[2..4].copy_from_slice(&0x9004u16.to_le_bytes());
        assert!(creation_loss_only(&expected, &actual, &same).unwrap());
        actual[20] = 1;
        assert!(!creation_loss_only(&expected, &actual, &same).unwrap());
        actual[20] = 0;
        actual[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        assert!(!creation_loss_only(&expected, &actual, &same).unwrap());
        assert!(!creation_loss_only(&actual, &expected, &same).unwrap());
    }
    #[test]
    fn hash_only_verification_enforces_exact_eof() {
        let bytes = vec![0x5a; 65537];
        let expected = crate::content_digest::of(&bytes);
        assert_eq!(
            hash_exact_stream(&mut bytes.as_slice(), bytes.len() as u64).unwrap(),
            expected
        );
        assert!(hash_exact_stream(&mut bytes.as_slice(), bytes.len() as u64 + 1).is_err());
        assert!(hash_exact_stream(&mut bytes.as_slice(), bytes.len() as u64 - 1).is_err());
        assert_eq!(
            hash_exact_stream(&mut &[][..], 0).unwrap(),
            crate::content_digest::of(&[])
        );
    }
}
