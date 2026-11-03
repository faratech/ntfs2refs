//! Private allocation-only construction primitive. No payload Read/Write or
//! raw handle is exposed outside the native shadow module. Failed operations
//! leave the private file for diagnosis; they never authorize target writes.
use super::{ctl, invalid, wide};
mod resource;
use crate::{bitmap_paging, bitmap_window, bitmap_window_native, bitmap_window_transport};
pub(super) use resource::ResourceTrackedHoles;
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{CreateFileW, SetFileInformationByHandle, SetFileValidData},
};

/// Per-placeholder native submissions. One large or fragmented file may use
/// most of the tree-wide budget, which remains the binding ceiling.
const MAX_FILE_SUBMISSIONS: usize = super::private_tree::MAX_PLACEMENT_SUBMISSIONS;
/// Per-placeholder tracked entries (and tracked entries plus deferred holes).
/// A retained stream has at most 1024 NTFS runs; each may end as up to four
/// coalesced pieces (placed, split by metadata, and remainders on each side).
/// Every move still matches all entries against the complete retrieval map.
/// Prepared matching skips runs outside each checked VCN interval.
const MAX_FILE_PLACEMENTS: usize = 4096;

/// An immutable, fully validated fresh retrieval map. Construction parses the
/// complete canonical response once; only then may interval matching use its
/// ordered, disjoint VCN endpoints for binary search. It never substitutes a
/// retained map for a new native capture or omits a tracked placement check.
struct PreparedMapping {
    runs: Vec<crate::stream_layout::Run>,
}
impl PreparedMapping {
    fn parse(canonical: &[u8]) -> io::Result<Self> {
        let runs = crate::stream_layout::parse_complete_retrieval(canonical)?;
        Self::from_runs(runs)
    }
    fn from_runs(runs: Vec<crate::stream_layout::Run>) -> io::Result<Self> {
        // The complete parser establishes increasing contiguous VCNs. Retain
        // the raw matcher's checked-end error before relying on those ends in
        // partition_point, including for runs outside a requested interval.
        for run in &runs {
            run.vcn
                .checked_add(run.clusters)
                .ok_or_else(|| invalid("retention mapping overflow"))?;
        }
        Ok(Self { runs })
    }

    fn matches(&self, starting_vcn: u64, destination_lcn: u64, clusters: u32) -> io::Result<bool> {
        let limit = starting_vcn
            .checked_add(u64::from(clusters))
            .ok_or_else(|| invalid("retention range overflow"))?;
        let first = self
            .runs
            .partition_point(|run| run.vcn + run.clusters <= starting_vcn);
        let mut covered = starting_vcn;
        for run in &self.runs[first..] {
            if run.vcn >= limit {
                break;
            }
            let next = run.vcn + run.clusters;
            let begin = run.vcn.max(starting_vcn);
            let end = next.min(limit);
            if begin < end {
                if begin != covered
                    || !run
                        .lcn
                        .and_then(|lcn| lcn.checked_add(begin - run.vcn))
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
}

/// Merge VCN- and LCN-contiguous neighbours of a VCN-sorted list. The covered
/// clusters and their linear VCN-to-LCN relation are unchanged, and a merged
/// entry matches the retrieval map only if both former entries would.
fn coalesce(entries: &mut Vec<(u64, u64, u32)>) {
    let mut merged: Vec<(u64, u64, u32)> = Vec::with_capacity(entries.len());
    for &(vcn, lcn, clusters) in entries.iter() {
        if let Some(last) = merged.last_mut()
            && last.0 + u64::from(last.2) == vcn
            && last.1 + u64::from(last.2) == lcn
            && let Some(total) = last.2.checked_add(clusters)
        {
            last.2 = total;
        } else {
            merged.push((vcn, lcn, clusters));
        }
    }
    *entries = merged;
}

/// Destination-only native bitmap evidence. This deliberately cannot be used
/// as a full-volume bitmap Candidate; both selectors retain lossless replayable
/// request/response transcripts under a separately versioned transport.
#[derive(Clone, Serialize)]
pub(super) struct DestinationWindows {
    pub schema_version: u32,
    pub scope: String,
    pub legacy: bitmap_window_transport::Proof,
    pub metadata: bitmap_window_transport::Proof,
}

/// Window storage follows the requested cluster count, not volume capacity.
/// Rounding may require larger native responses; allow two maximum-sized pages
/// of overhead and a finite page-growth allowance, retaining every response.
/// The collector observes actual rounding and refuses before movement if this
/// independent budget cannot reach the complete requested window.
fn destination_limits(clusters: u32) -> io::Result<bitmap_window::Limits> {
    let window_bytes = usize::try_from(u64::from(clusters).div_ceil(8))
        .map_err(|_| invalid("destination bitmap window exceeds address space"))?;
    let max_pages = window_bytes
        .div_ceil(4096 - 16)
        .checked_mul(2)
        .and_then(|n| n.checked_add(16))
        .ok_or_else(|| invalid("destination bitmap page budget overflow"))?;
    let rounding_bytes = bitmap_paging::PAGE_BYTES
        .checked_mul(2)
        .ok_or_else(|| invalid("destination bitmap rounding budget overflow"))?;
    let max_returned_bytes = window_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(rounding_bytes))
        .and_then(|n| {
            max_pages
                .checked_mul(16)
                .and_then(|headers| n.checked_add(headers))
        })
        .ok_or_else(|| invalid("destination bitmap transcript budget overflow"))?;
    Ok(bitmap_window::Limits {
        max_window_bytes: window_bytes,
        max_pages,
        max_returned_bytes,
        page_bytes: bitmap_paging::PAGE_BYTES,
    })
}

#[derive(Serialize)]
pub(super) struct Placement {
    pub destination_lcn: u64,
    pub starting_vcn: u64,
    pub clusters: u32,
    pub submitted_once: bool,
    pub before_valid_data_advance: bool,
    pub native_error: Option<i32>,
    pub mapping_matches: bool,
    pub all_placements_match: bool,
    pub reposition: bool,
    pub mapping_after: Vec<u8>,
    pub mapping_page_proof: crate::retrieval_paging::Proof,
    pub destination_bitmap: DestinationWindows,
    #[serde(skip)]
    _resource_memory: Option<Box<dyn super::report_memory::ReportMemoryLease>>,
}

#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct ResourceMoveValue {
    value: serde_json::Value,
    #[serde(skip)]
    _memory: Box<dyn super::report_memory::ReportMemoryLease>,
}
impl std::ops::Deref for ResourceMoveValue {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl Placement {
    pub(super) fn into_resource_value(mut self) -> io::Result<ResourceMoveValue> {
        if self._resource_memory.is_none() {
            return Err(invalid("actual prepaid resource proof owner absent"));
        }
        // This same guard was acquired before FSCTL_MOVE_FILE and covers
        // native capture plus both JSON copies and serialization workspace.
        let value = serde_json::to_value(&self).map_err(io::Error::other)?;
        let memory = self
            ._resource_memory
            .take()
            .expect("verified prepaid resource proof owner");
        drop(self);
        Ok(ResourceMoveValue {
            value,
            _memory: memory,
        })
    }
}

pub(super) struct PrivatePlaceholder {
    file: File,
    pub path: String,
    bytes: u64,
    partition: u64,
    placed: Vec<(u64, u64, u32)>,
    valid_data_submitted: bool,
    valid_prefix: u64,
    materialized_bytes: u64,
    readback_bytes: u64,
    verification_read_bytes: u64,
    poisoned: bool,
    move_submissions: usize,
    initial_mapping_tracked: bool,
    retrieval_extents: usize,
    retire_identity: Option<Vec<u8>>,
    resource: Option<resource::ResourcePlacement>,
}

impl PrivatePlaceholder {
    pub(super) fn enable_resource_placement(
        &mut self,
        admission: crate::tree_resources::SourceResourceAdmission,
        tracked: usize,
        moves: usize,
        move_bytes: u64,
        payer: std::sync::Arc<dyn super::report_memory::ReportMemoryAccountant>,
    ) -> io::Result<()> {
        if self.resource.is_some()
            || self.poisoned
            || self.valid_prefix != 0
            || self.valid_data_submitted
            || self.initial_mapping_tracked
            || self.move_submissions != 0
            || !self.placed.is_empty()
        {
            return Err(invalid(
                "fresh zero-VDL placeholder required for resource placement",
            ));
        }
        self.resource = Some(resource::ResourcePlacement::new(
            admission, tracked, moves, move_bytes, payer,
        )?);
        Ok(())
    }
    pub(super) fn resource_placement_enabled(&self) -> bool {
        self.resource.is_some()
    }
    pub(super) fn retained_memory_bytes(&self) -> io::Result<u64> {
        (self.path.capacity() as u64)
            .checked_add(
                (self.placed.capacity() as u64)
                    .checked_mul(mem::size_of::<(u64, u64, u32)>() as u64)
                    .ok_or_else(|| invalid("private mapping RAM overflow"))?,
            )
            .and_then(|n| {
                n.checked_add(
                    self.retire_identity
                        .as_ref()
                        .map_or(0, |v| v.capacity() as u64),
                )
            })
            .ok_or_else(|| invalid("private placeholder RAM overflow"))
    }
    /// Caller binds the independent writable ReFS shadow and enables volume
    /// privilege before this call. Security is applied atomically at creation.
    pub fn allocate(root: &str, experiment: &str, bytes: u64, partition: u64) -> io::Result<Self> {
        if experiment.len() != 32
            || !experiment.bytes().all(|b| b.is_ascii_hexdigit())
            || bytes < 4096
            || !bytes.is_multiple_of(4096)
        {
            return Err(invalid("private allocation geometry or identity differs"));
        }
        Self::allocate_named(
            root,
            &[format!("n2r-valid-data-{experiment}.bin")],
            bytes,
            partition,
        )
    }

    /// Preserve source names while retaining private permissions. No source
    /// security descriptor is restored over an uninitialized placeholder.
    pub fn allocate_named(
        root: &str,
        components: &[String],
        bytes: u64,
        partition: u64,
    ) -> io::Result<Self> {
        Self::allocate_data(root, components, &[], bytes, partition, false)
    }

    pub fn allocate_named_stream(
        root: &str,
        components: &[String],
        name: &[u16],
        bytes: u64,
        partition: u64,
        base: &File,
    ) -> io::Result<Self> {
        if !super::streams::valid_name(name) {
            return Err(invalid("invalid private stream name"));
        }
        let identity = super::info(base, 18, 24)?;
        let stream = Self::allocate_data(root, components, name, bytes, partition, false)?;
        if super::info(base, 18, 24)? != identity
            || super::info(stream.metadata_handle(), 18, 24)? != identity
        {
            return Err(invalid(
                "private named stream does not belong to its held base file",
            ));
        }
        Ok(stream)
    }

    fn allocate_data(
        root: &str,
        components: &[String],
        stream_name: &[u16],
        bytes: u64,
        partition: u64,
        retire: bool,
    ) -> io::Result<Self> {
        if components.is_empty()
            || components.len() > 16
            || components
                .iter()
                .any(|s| !crate::shadow_names::valid_unicode_component(s))
            || bytes > partition
            || partition > crate::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES
            || i64::try_from(bytes).is_err()
        {
            return Err(invalid("private named allocation geometry or path differs"));
        }
        let sddl = wide("O:SYG:SYD:P(A;;FA;;;SY)");
        let mut descriptor = ptr::null_mut();
        // SAFETY: constant NUL-terminated SDDL, allocated output freed below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let path = super::streams::path(root, components, stream_name)?;
        let name = wide(&path);
        // SAFETY: caller-bound volume root, validated components, CREATE_NEW,
        // sharing disabled and SYSTEM-only protected security descriptor.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0xc0020000 | if retire { 0x10000 } else { 0 },
                0,
                &sa,
                1,
                0x80200080,
                ptr::null_mut(),
            )
        };
        let error = io::Error::last_os_error();
        unsafe {
            LocalFree(descriptor);
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        // SAFETY: unique ownership of the successfully created native handle.
        let file = unsafe { File::from_raw_handle(handle) };
        ctl(&file, 0x9c280, &[0; 8], 0)?;
        if bytes >= 4096 {
            let allocation = bytes
                .checked_add(4095)
                .ok_or_else(|| invalid("private allocation overflow"))?
                / 4096
                * 4096;
            // SAFETY: aligned FILE_ALLOCATION_INFO and synchronous live handle.
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    5,
                    (&allocation as *const u64).cast(),
                    8,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        file.set_len(bytes)?;
        let retire_identity = if retire {
            Some(super::info(&file, 18, 24)?)
        } else {
            None
        };
        Ok(Self {
            file,
            path,
            bytes,
            partition,
            placed: vec![],
            valid_data_submitted: false,
            valid_prefix: 0,
            materialized_bytes: 0,
            readback_bytes: 0,
            verification_read_bytes: 0,
            poisoned: false,
            move_submissions: 0,
            initial_mapping_tracked: false,
            retrieval_extents: 0,
            retire_identity,
            resource: None,
        })
    }
    pub(super) fn allocate_carrier(
        root: &str,
        components: &[String],
        bytes: u64,
        partition: u64,
    ) -> io::Result<Self> {
        Self::allocate_data(root, components, &[], bytes, partition, true)
    }
    pub(super) fn retire(self) -> io::Result<()> {
        let expected = self
            .retire_identity
            .as_ref()
            .ok_or_else(|| invalid("only constructor-owned carrier may be retired"))?;
        if super::info(&self.file, 18, 24)? != *expected
            || crate::layout::u32_at(&super::info(&self.file, 1, 24)?, 16)? != 1
        {
            return Err(invalid("carrier identity changed before retirement"));
        }
        let disposition =
            windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                4,
                (&disposition
                    as *const windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO)
                    .cast(),
                mem::size_of_val(&disposition) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(self);
        Ok(())
    }

    /// Metadata-only access for the enclosing native module's existing query
    /// functions. The constructor exposes no payload interface to callers.
    pub fn metadata_handle(&self) -> &File {
        &self.file
    }

    pub fn logical_length(&self) -> u64 {
        self.bytes
    }
    pub fn materialized_bytes(&self) -> u64 {
        self.materialized_bytes
    }
    pub fn readback_bytes(&self) -> u64 {
        self.readback_bytes
    }
    pub fn valid_prefix(&self) -> u64 {
        self.valid_prefix
    }
    pub fn verification_read_bytes(&self) -> u64 {
        self.verification_read_bytes
    }

    /// Bounded initialized-data read for logical hybrid verification. Native
    /// map/shape/exclusion bracketing is performed by the owning tree/session.
    pub fn read_initialized_at(&mut self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(output.len() as u64)
            .ok_or_else(|| invalid("private verify read overflow"))?;
        if self.poisoned || output.len() > 65536 || end > self.bytes || end > self.valid_prefix {
            return Err(invalid(
                "private verification read escapes initialized bytes",
            ));
        }
        self.verification_read_bytes
            .checked_add(output.len() as u64)
            .ok_or_else(|| invalid("private verification read accounting overflow"))?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut read = 0;
        while read < output.len() {
            let n = self.file.read(&mut output[read..])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "private verification ended before EOF",
                ));
            }
            read += n;
            self.verification_read_bytes += n as u64;
        }
        Ok(())
    }

    /// Write only an explicitly supplied exception range. Never bridge an
    /// uninitialized gap: doing so could zero-fill a huge retained prefix.
    /// Sharing remains disabled and the file remains SYSTEM-only on failure.
    pub fn initialize_at(&mut self, offset: u64, data: &[u8]) -> io::Result<serde_json::Value> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| invalid("private write overflow"))?;
        if self.poisoned || data.len() > 65536 || end > self.bytes || offset > self.valid_prefix {
            return Err(invalid(
                "private exception write state, bounds or initialization gap differs",
            ));
        }
        self.materialized_bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| invalid("private write accounting overflow"))?;
        self.readback_bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| invalid("private readback accounting overflow"))?;
        self.poisoned = true;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut written = 0;
        while written < data.len() {
            let n = self.file.write(&data[written..])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "private exception made no progress",
                ));
            }
            written += n;
            self.materialized_bytes += n as u64;
            self.valid_prefix = self.valid_prefix.max(offset + written as u64);
        }
        self.file.sync_all()?;
        let mut check = [0u8; 65536];
        self.file.seek(SeekFrom::Start(offset))?;
        let mut read = 0;
        while read < data.len() {
            let n = self.file.read(&mut check[read..data.len()])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "private exception readback ended",
                ));
            }
            read += n;
            self.readback_bytes += n as u64;
        }
        if &check[..data.len()] != data {
            return Err(invalid("private exception readback differs"));
        }
        let standard = super::info(&self.file, 1, 24)?;
        if crate::layout::u64_at(&standard, 8)? != self.bytes
            || crate::layout::u32_at(&standard, 16)? != 1
            || standard[20] != 0
            || standard[21] != 0
        {
            return Err(invalid("private exception changed file shape"));
        }
        self.verify_placements()?;
        self.poisoned = false;
        use sha2::Digest;
        Ok(serde_json::json!({"offset":offset,"bytes":data.len(),
            "sha256":hex::encode(sha2::Sha256::digest(data)),"readback_verified":true,
            "valid_prefix_bytes":self.valid_prefix,"conversion_qualified":false}))
    }

    /// Place one unwritten logical range. A native refusal/partial completion
    /// poisons the placeholder; no retry or later VDL advancement is accepted.
    pub fn place(
        &mut self,
        volume: &File,
        starting_vcn: u64,
        destination_lcn: u64,
        clusters: u32,
    ) -> io::Result<Placement> {
        self.place_with_evidence(volume, starting_vcn, destination_lcn, clusters, |_| Ok(()))
    }

    /// Reserve the exact captured destination evidence before native movement.
    /// The guard cannot replace the bitmap observation or bypass its checks.
    pub(super) fn place_with_evidence(
        &mut self,
        volume: &File,
        starting_vcn: u64,
        destination_lcn: u64,
        clusters: u32,
        guard: impl FnMut(&DestinationWindows) -> io::Result<()>,
    ) -> io::Result<Placement> {
        self.move_unwritten(
            volume,
            starting_vcn,
            destination_lcn,
            clusters,
            false,
            guard,
        )
    }

    /// Planned second-stage movement, never a retry after failure. Only a
    /// completely tracked, freshly verified unwritten range may be replaced.
    pub fn reposition(
        &mut self,
        volume: &File,
        starting_vcn: u64,
        destination_lcn: u64,
        clusters: u32,
    ) -> io::Result<Placement> {
        self.reposition_with_evidence(volume, starting_vcn, destination_lcn, clusters, |_| Ok(()))
    }

    pub(super) fn reposition_with_evidence(
        &mut self,
        volume: &File,
        starting_vcn: u64,
        destination_lcn: u64,
        clusters: u32,
        guard: impl FnMut(&DestinationWindows) -> io::Result<()>,
    ) -> io::Result<Placement> {
        self.move_unwritten(volume, starting_vcn, destination_lcn, clusters, true, guard)
    }

    fn move_unwritten(
        &mut self,
        volume: &File,
        starting_vcn: u64,
        destination_lcn: u64,
        clusters: u32,
        reposition: bool,
        mut guard: impl FnMut(&DestinationWindows) -> io::Result<()>,
    ) -> io::Result<Placement> {
        let resource_memory = self
            .resource
            .as_ref()
            .map(|r| r.move_workspace(clusters, self.placed.len()))
            .transpose()?;
        let max_submissions = self
            .resource
            .as_ref()
            .map_or(MAX_FILE_SUBMISSIONS, |r| r.max_moves);
        let max_placements = self
            .resource
            .as_ref()
            .map_or(MAX_FILE_PLACEMENTS, |r| r.max_tracked_slots);
        let logical_end = starting_vcn.checked_add(u64::from(clusters));
        let physical_end = destination_lcn.checked_add(u64::from(clusters));
        if self.poisoned
            || self.valid_data_submitted
            || self.valid_prefix != 0
            || self.move_submissions >= max_submissions
            || clusters == 0
            || !self.partition.is_multiple_of(4096)
            || destination_lcn < 256
            || logical_end.is_none_or(|v| v > self.bytes / 4096)
            || physical_end.is_none_or(|v| v > self.partition / 4096)
            || self.placed.iter().any(|(v, l, n)| {
                (!reposition && starting_vcn < *v + u64::from(*n) && *v < logical_end.unwrap_or(0))
                    || destination_lcn < *l + u64::from(*n) && *l < physical_end.unwrap_or(0)
            })
        {
            return Err(invalid(
                "private unwritten placement state, overlap or bounds differ",
            ));
        }
        if let Err(error) = self.verify_placements_prepaid(self.resource.is_some()) {
            self.poisoned = true;
            return Err(error);
        }
        let end = logical_end.unwrap();
        let mut next = Vec::new();
        let mut previous = self.placed.clone();
        previous.sort_by_key(|r| r.0);
        let mut covered = starting_vcn;
        for &(v, l, n) in &previous {
            let old_end = v + u64::from(n);
            if old_end <= starting_vcn || v >= end {
                next.push((v, l, n));
                continue;
            }
            if reposition {
                let from = v.max(starting_vcn);
                let to = old_end.min(end);
                if from != covered {
                    return Err(invalid("private reposition has untracked logical gap"));
                }
                covered = to;
                if v < starting_vcn {
                    next.push((
                        v,
                        l,
                        u32::try_from(starting_vcn - v)
                            .map_err(|_| invalid("private left split overflow"))?,
                    ));
                }
                if old_end > end {
                    next.push((
                        end,
                        l + end - v,
                        u32::try_from(old_end - end)
                            .map_err(|_| invalid("private right split overflow"))?,
                    ));
                }
            }
        }
        if reposition && covered != end {
            return Err(invalid("private reposition range is not fully tracked"));
        }
        next.push((starting_vcn, destination_lcn, clusters));
        next.sort_by_key(|r| r.0);
        coalesce(&mut next);
        if next.len() > max_placements {
            return Err(invalid(&format!(
                "private reposition split budget exceeded: {} tracked entries > {}",
                next.len(),
                max_placements
            )));
        }
        // This exact future map is already known before the native move.
        // Retain its new owner now; never discover a missing RAM allowance
        // after changing the independent shadow's physical mappings.
        let placed_memory = self
            .resource
            .as_ref()
            .map(|r| r.reserve_placed(next.len(), next.capacity()))
            .transpose()?;
        let request = bitmap_window::Request {
            volume_clusters: self.partition / 4096,
            starting_lcn: destination_lcn,
            clusters: u64::from(clusters),
        };
        let limits = destination_limits(clusters)?;
        let legacy = bitmap_window_native::capture(volume, request, &[0; 8], limits)?;
        let mut ex = [0u8; 16];
        ex[8] = 1;
        let metadata = bitmap_window_native::capture(volume, request, &ex, limits)?;
        if legacy.request() != request
            || metadata.request() != request
            || legacy.proof().declared_volume_clusters != request.volume_clusters
            || metadata.proof().declared_volume_clusters != request.volume_clusters
        {
            return Err(invalid(
                "destination bitmap window binding or declared domain differs",
            ));
        }
        if legacy.allocated_clusters() != 0 || metadata.allocated_clusters() != 0 {
            // Distinct kind: nothing was submitted or poisoned, so the tree
            // planner may re-plan this step from a fresh snapshot.
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "private placement requires both current bitmap views free",
            ));
        }
        let destination_bitmap = DestinationWindows {
            schema_version: 1,
            scope: "destination-window-v1".into(),
            legacy: bitmap_window_transport::from_proof(legacy.into_proof())?,
            metadata: bitmap_window_transport::from_proof(metadata.into_proof())?,
        };
        // This charge uses the actual lossless transcripts, including native
        // rounding and every selector page, before FSCTL_MOVE_FILE can run.
        guard(&destination_bitmap)?;
        let mut input = [0u8; 32];
        input[..8].copy_from_slice(&(self.file.as_raw_handle() as usize as u64).to_le_bytes());
        input[8..16].copy_from_slice(&starting_vcn.to_le_bytes());
        input[16..24].copy_from_slice(&destination_lcn.to_le_bytes());
        input[24..28].copy_from_slice(&clusters.to_le_bytes());
        self.poisoned = true; // Any missing post-I/O evidence must fail closed.
        self.move_submissions += 1;
        let moved = ctl(volume, 0x90074, &input, 0);
        let capture = if let Some(resource) = &self.resource {
            resource.capture(&self.file)?
        } else {
            crate::stream_native::retrieval_capture(&self.file)?
        };
        self.retrieval_extents = capture.runs.len();
        let mapping = if self.resource.is_some() {
            PreparedMapping::from_runs(capture.runs)?
        } else {
            PreparedMapping::parse(&capture.canonical)?
        };
        let mapped = mapping.matches(starting_vcn, destination_lcn, clusters)?;
        let native_error = moved.err().map(|e| e.raw_os_error().unwrap_or(31));
        let mut all_placements_match = true;
        for &(v, l, n) in &next {
            all_placements_match &= mapping.matches(v, l, n)?;
        }
        if native_error.is_none() && mapped && all_placements_match {
            self.placed = next;
            if let Some(resource) = self.resource.as_mut() {
                resource.replace_placed_lease(
                    placed_memory.ok_or_else(|| invalid("actual tracked map memory absent"))?,
                );
            }
            self.poisoned = false;
        }
        Ok(Placement {
            destination_lcn,
            starting_vcn,
            clusters,
            submitted_once: true,
            before_valid_data_advance: true,
            native_error,
            mapping_matches: mapped,
            all_placements_match,
            reposition,
            mapping_after: capture.canonical,
            mapping_page_proof: capture.proof,
            destination_bitmap,
            _resource_memory: resource_memory,
        })
    }

    /// Advance once. Construction requires complete placed-prefix coverage;
    /// the old standalone allocation probe can explicitly omit that policy.
    pub fn advance_valid_data(&mut self, bytes: u64, require_placed: bool) -> io::Result<()> {
        if self.poisoned
            || self.valid_data_submitted
            || self.valid_prefix != 0
            || bytes == 0
            || bytes > self.bytes
            || !bytes.is_multiple_of(4096)
        {
            return Err(invalid("private validity state or length differs"));
        }
        if require_placed {
            let _coverage = self
                .resource
                .as_ref()
                .map(|r| r.coverage_workspace(self.placed.capacity()))
                .transpose()?;
            let mut runs = self.placed.clone();
            runs.sort_by_key(|r| r.0);
            let mut cursor = 0;
            for (vcn, _, clusters) in runs {
                if vcn >= bytes / 4096 {
                    break;
                }
                if vcn != cursor {
                    return Err(invalid("private placed prefix has a gap"));
                }
                cursor += u64::from(clusters);
            }
            if cursor < bytes / 4096 {
                return Err(invalid("private placed prefix is incomplete"));
            }
        }
        self.valid_data_submitted = true;
        self.poisoned = true;
        // SAFETY: caller enabled manage-volume privilege before creating this
        // private file; aligned positive VDL is no greater than admitted EOF.
        if unsafe { SetFileValidData(self.file.as_raw_handle(), bytes as i64) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.file.sync_all()?;
        self.verify_placements()?;
        self.valid_prefix = bytes;
        self.poisoned = false;
        Ok(())
    }

    /// Private scratch preparation only. No original physical ownership or
    /// source contents are authenticated by making this prefix storage-valid.
    pub fn prepare_unplaced_prefix(&mut self, bytes: u64) -> io::Result<()> {
        if !self.placed.is_empty() {
            return Err(invalid(
                "unplaced preparation cannot bypass placed-prefix coverage",
            ));
        }
        self.advance_valid_data(bytes, false)
    }

    fn verify_placements(&self) -> io::Result<()> {
        self.verify_placements_prepaid(false)
    }
    fn verify_placements_prepaid(&self, prepaid: bool) -> io::Result<()> {
        if self.placed.is_empty() {
            return Ok(());
        }
        let _memory = if prepaid {
            None
        } else {
            self.resource
                .as_ref()
                .map(|r| r.tracking_workspace(self.bytes))
                .transpose()?
        };
        let capture = if let Some(resource) = &self.resource {
            resource.capture(&self.file)?
        } else {
            crate::stream_native::retrieval_capture(&self.file)?
        };
        let mapping = if self.resource.is_some() {
            PreparedMapping::from_runs(capture.runs)?
        } else {
            PreparedMapping::parse(&capture.canonical)?
        };
        for &(vcn, lcn, clusters) in &self.placed {
            if !mapping.matches(vcn, lcn, clusters)? {
                return Err(invalid("private mapping changed after valid-data flush"));
            }
        }
        Ok(())
    }

    pub fn check_placements(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid("poisoned private placement cannot supply data"));
        }
        self.verify_placements()
    }

    /// Bind currently allocated unwritten runs from the live owning handle.
    /// Deferred holes are returned for explicit allocation, never invented as
    /// physical ownership or accepted as source references.
    pub fn track_current_prefix(&mut self) -> io::Result<Vec<(u64, u32)>> {
        if self.resource.is_some() {
            return Err(invalid(
                "resource tracking requires its lease-owning holes owner",
            ));
        }
        self.track_current_prefix_inner()
    }
    pub(super) fn track_current_prefix_resource(&mut self) -> io::Result<ResourceTrackedHoles> {
        let _memory = self
            .resource
            .as_ref()
            .ok_or_else(|| invalid("resource tracking state absent"))?
            .tracking_workspace(self.bytes)?;
        let holes = self.track_current_prefix_inner()?;
        match self
            .resource
            .as_ref()
            .ok_or_else(|| invalid("resource tracking state absent"))?
            .hold_holes(holes)
        {
            Ok(holes) => Ok(holes),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
    fn track_current_prefix_inner(&mut self) -> io::Result<Vec<(u64, u32)>> {
        if self.poisoned
            || self.valid_prefix != 0
            || self.valid_data_submitted
            || self.initial_mapping_tracked
            || self.move_submissions != 0
            || !self.placed.is_empty()
        {
            return Err(invalid("fresh zero-VDL mapping required for tracking"));
        }
        let clusters = self.bytes / 4096;
        self.initial_mapping_tracked = true;
        if clusters == 0 {
            return Ok(vec![]);
        }
        self.poisoned = true;
        let max_placements = self
            .resource
            .as_ref()
            .map_or(MAX_FILE_PLACEMENTS, |r| r.max_tracked_slots);
        let capture = if let Some(resource) = &self.resource {
            resource.capture(&self.file)?
        } else {
            crate::stream_native::retrieval_capture(&self.file)?
        };
        self.retrieval_extents = capture.runs.len();
        let mut tracked: Vec<(u64, u64, u32)> = Vec::new();
        let mut holes = Vec::new();
        let mut cursor = 0;
        for run in capture.runs {
            if run.vcn >= clusters {
                break;
            }
            if run.vcn != cursor {
                return Err(invalid("current private mapping has logical gap"));
            }
            let end = (run.vcn + run.clusters).min(clusters);
            let mut start = run.vcn;
            while start < end {
                let count = (end - start).min(u64::from(u32::MAX)) as u32;
                if let Some(lcn) = run.lcn {
                    let physical = lcn
                        .checked_add(start - run.vcn)
                        .ok_or_else(|| invalid("tracked LCN overflow"))?;
                    if physical
                        .checked_add(u64::from(count))
                        .is_none_or(|v| v > self.partition / 4096)
                    {
                        return Err(invalid("tracked private mapping escapes partition"));
                    }
                    // Record contiguous native runs as one tracked entry.
                    if let Some(last) = tracked.last_mut()
                        && last.0 + u64::from(last.2) == start
                        && last.1 + u64::from(last.2) == physical
                        && let Some(total) = last.2.checked_add(count)
                    {
                        last.2 = total;
                    } else {
                        tracked.push((start, physical, count));
                    }
                } else {
                    holes.push((start, count));
                }
                if tracked.len() + holes.len() > max_placements {
                    return Err(invalid(&format!(
                        "current mapping tracking budget exceeded: {} tracked entries and holes > {}",
                        tracked.len() + holes.len(),
                        max_placements
                    )));
                }
                start += u64::from(count);
            }
            cursor = end;
        }
        if cursor != clusters {
            return Err(invalid("current private mapping prefix incomplete"));
        }
        let placed_memory = self
            .resource
            .as_ref()
            .map(|r| r.reserve_placed(tracked.len(), tracked.capacity()))
            .transpose()?;
        self.placed = tracked;
        if let Some(resource) = self.resource.as_mut() {
            resource.replace_placed_lease(
                placed_memory.ok_or_else(|| invalid("resource tracked memory absent"))?,
            );
        }
        self.poisoned = false;
        Ok(holes)
    }

    pub fn tracked_mappings(&self) -> &[(u64, u64, u32)] {
        &self.placed
    }

    /// Canonical extents in this file's latest complete retrieval capture
    /// (tracking or the last move), for bounding the next move's proof.
    pub(super) fn retrieval_extents(&self) -> usize {
        self.retrieval_extents
    }
}
