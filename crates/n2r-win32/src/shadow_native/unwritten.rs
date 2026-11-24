//! Private allocation-only construction primitive. No payload Read/Write or
//! raw handle is exposed outside the native shadow module. Failed operations
//! leave the private file for diagnosis; they never authorize target writes.
use super::{ctl, invalid, wide};
pub(super) mod recovery;
mod resource;
use crate::{bitmap_paging, bitmap_window, bitmap_window_native, bitmap_window_transport};
pub(super) use resource::ResourceTrackedHoles;
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::windows::io::AsRawHandle,
    ptr,
    sync::OnceLock,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityDescriptorLength, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{SetFileInformationByHandle, SetFileValidData},
};

/// A live destination bitmap showed an allocated cluster in this move's range.
#[derive(Debug)]
pub(super) struct OccupiedDestination {
    path: String,
    vcn: u64,
    request: bitmap_window::Request,
    legacy_allocated: u64,
    metadata_allocated: u64,
    move_error: Option<String>,
}

impl std::fmt::Display for OccupiedDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "private shadow placement for {}: {} clusters from VCN {} to LCN {}, allocated clusters in legacy bitmap {}, metadata bitmap {}",
            self.path,
            self.request.clusters,
            self.vcn,
            self.request.starting_lcn,
            self.legacy_allocated,
            self.metadata_allocated
        )?;
        if let Some(error) = &self.move_error {
            write!(f, ", FSCTL_MOVE_FILE failed: {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for OccupiedDestination {}

impl OccupiedDestination {
    pub(super) fn from_error(error: &io::Error) -> Option<&Self> {
        if error.kind() != io::ErrorKind::ResourceBusy {
            return None;
        }
        error.get_ref()?.downcast_ref()
    }

    pub(super) fn before_submission(&self) -> bool {
        self.move_error.is_none()
    }
}

fn private_system_security_descriptor() -> io::Result<&'static [u64]> {
    static SD: OnceLock<Vec<u64>> = OnceLock::new();
    if let Some(cached) = SD.get() {
        return Ok(cached.as_slice());
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
    // SAFETY: `descriptor` is a valid self-relative SD returned by the call above.
    let len = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    let mut words = vec![0u64; len.div_ceil(8)];
    // SAFETY: `words` is 8-byte-aligned with at least `len` bytes; `descriptor` has `len` bytes.
    unsafe {
        ptr::copy_nonoverlapping(
            descriptor.cast::<u8>(),
            words.as_mut_ptr().cast::<u8>(),
            len,
        );
        LocalFree(descriptor);
    }
    Ok(SD.get_or_init(|| words).as_slice())
}

/// Per-placeholder native submissions. One large or fragmented file may use
/// most of the tree-wide budget, which remains the binding ceiling.
const MAX_FILE_SUBMISSIONS: usize = super::private_tree::MAX_PLACEMENT_SUBMISSIONS;
/// Per-placeholder tracked entries (and tracked entries plus deferred holes).
/// A retained stream has at most 1024 NTFS runs; each may end as up to four
/// coalesced pieces (placed, split by metadata, and remainders on each side).
/// Every move matches all entries against the complete retrieval map, except
/// in a run that verifies each thing once: there a move that landed is held
/// to the mapping of the range it moved, and all entries are matched against
/// the complete map when placement ends (`check_placements`).
/// Prepared matching skips runs outside each checked VCN interval.
const MAX_FILE_PLACEMENTS: usize = 4096;

/// An immutable, fully validated fresh retrieval map. Construction parses the
/// complete canonical response once; only then may interval matching use its
/// ordered, disjoint VCN endpoints for binary search. It never substitutes a
/// retained map for a new native capture. Built from a ranged capture
/// (`retrieval_paging::RANGE_ENCODING`) it holds only that range, and an
/// interval outside it does not match.
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

    /// What `vcn` maps to, for an error that has to say where a tracked
    /// piece is now.
    fn describe(&self, vcn: u64) -> String {
        let at = self
            .runs
            .partition_point(|run| run.vcn + run.clusters <= vcn);
        match self.runs.get(at).filter(|run| run.vcn <= vcn) {
            Some(run) => match run.lcn {
                Some(lcn) => format!(
                    "LCN {} (an extent of {} clusters from VCN {})",
                    lcn.saturating_add(vcn - run.vcn),
                    run.clusters,
                    run.vcn
                ),
                None => format!("a hole of {} clusters from VCN {}", run.clusters, run.vcn),
            },
            None => "nothing (the mapping ends before it)".into(),
        }
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

/// A resource move's proof: every field as JSON except the mapping after the
/// move, which stays as its canonical bytes. It is the file's complete
/// mapping, or in a run that verifies each thing once that of the range the
/// move landed in; `mapping_page_proof.encoding` says which. That mapping
/// is the one part of a proof that grows with the file, and as a JSON value
/// it was one value per byte, built and then copied once more for every
/// move: a file in thousands of pieces paid for both at every move. It
/// serializes exactly as the whole proof as one JSON value did, with the
/// mapping at its place among the keys in order.
pub(super) struct ResourceMoveValue {
    value: serde_json::Value,
    mapping_after: Vec<u8>,
    _memory: Box<dyn super::report_memory::ReportMemoryLease>,
}
const MAPPING_AFTER: &str = "mapping_after";
impl std::ops::Deref for ResourceMoveValue {
    type Target = serde_json::Value;
    /// The proof's fields other than `mapping_after`, which none of its
    /// readers asks for by name.
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl Serialize for ResourceMoveValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeMap};
        let fields = self
            .value
            .as_object()
            .ok_or_else(|| S::Error::custom("resource move proof is not an object"))?;
        // A JSON object's keys come out in order (serde_json without
        // preserve_order keeps them in a BTreeMap), so the mapping goes
        // before the first key that sorts after its own.
        let mut map = serializer.serialize_map(Some(fields.len() + 1))?;
        let mut mapping = Some(&self.mapping_after);
        for (key, value) in fields {
            if key.as_str() > MAPPING_AFTER
                && let Some(bytes) = mapping.take()
            {
                map.serialize_entry(MAPPING_AFTER, bytes)?;
            }
            map.serialize_entry(key, value)?;
        }
        if let Some(bytes) = mapping {
            map.serialize_entry(MAPPING_AFTER, bytes)?;
        }
        map.end()
    }
}
impl Placement {
    pub(super) fn into_resource_value(mut self) -> io::Result<ResourceMoveValue> {
        if self._resource_memory.is_none() {
            return Err(invalid("actual prepaid resource proof owner absent"));
        }
        // This same guard was acquired before FSCTL_MOVE_FILE and covers
        // native capture plus both JSON copies and serialization workspace.
        let mapping_after = mem::take(&mut self.mapping_after);
        let mut value = serde_json::to_value(&self).map_err(io::Error::other)?;
        if value
            .as_object_mut()
            .and_then(|fields| fields.remove(MAPPING_AFTER))
            != Some(serde_json::Value::Array(Vec::new()))
        {
            return Err(invalid("resource move proof mapping field differs"));
        }
        let memory = self
            ._resource_memory
            .take()
            .expect("verified prepaid resource proof owner");
        drop(self);
        Ok(ResourceMoveValue {
            value,
            mapping_after,
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
    recovered_origin: bool,
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
            || bytes < crate::target_cluster::bytes()
            || !crate::target_cluster::aligned(bytes)
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
        // The path has to fit Windows' extended-length form. How deep it may
        // be is the calling route's rule, checked when its tree was admitted:
        // a fixed sixteen components here refused, on the default route, any
        // file with allocated data that lay deeper.
        let refuse = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
        if components.is_empty() || !super::hard_links::resource_path_valid(root, components) {
            return Err(refuse(format!(
                "a path of {} components does not fit Windows' extended-length form",
                components.len()
            )));
        }
        if let Some(part) = components
            .iter()
            .find(|s| !crate::shadow_names::valid_unicode_component(s))
        {
            return Err(refuse(format!(
                "the name {part:?} is not one a private allocation can be made under"
            )));
        }
        if bytes > partition
            || partition > crate::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES
            || i64::try_from(bytes).is_err()
        {
            return Err(refuse(format!(
                "an allocation of {bytes} bytes does not fit a partition of {partition} bytes"
            )));
        }
        let sd = private_system_security_descriptor()?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr() as *mut _,
            bInheritHandle: 0,
        };
        let path = super::streams::path(root, components, stream_name)?;
        let name = wide(&path);
        // Caller-bound volume root, validated components, a fresh object only,
        // sharing disabled and SYSTEM-only protected security descriptor.
        let file = crate::shadow_native::create_fresh(
            &name,
            !stream_name.is_empty(),
            0xc0020000 | if retire { 0x10000 } else { 0 },
            &sa,
            crate::verify_policy::shadow_file_flags(
                0x80200080 | crate::shadow_native::BACKUP_INTENT,
            ),
        )?;
        ctl(&file, 0x9c280, &[0; 8], 0)?;
        if bytes >= crate::target_cluster::bytes() {
            let allocation = crate::target_cluster::ceil(bytes)
                .ok_or_else(|| invalid("private allocation overflow"))?;
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
            recovered_origin: false,
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
        self.initialize_at_with(offset, data, true)
    }

    /// [`Self::initialize_at`] for a caller that keeps no record of the
    /// write: every check is made (the range is read back and compared with
    /// `data` byte for byte), and only the digest of `data`, which nothing
    /// but the record carries, is not computed. The record has no `sha256`.
    pub fn initialize_at_unhashed(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> io::Result<serde_json::Value> {
        self.initialize_at_with(offset, data, false)
    }

    fn initialize_at_with(
        &mut self,
        offset: u64,
        data: &[u8],
        digest: bool,
    ) -> io::Result<serde_json::Value> {
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
        crate::verify_policy::flush_working_file(&self.file)?;
        // Under verify-once on the unhashed path, the closing shadow walk reads
        // every materialized tail back from the frozen READ_ONLY volume and
        // verifies its SHA-256 against the source, so re-reading from the
        // page cache and querying FileStandardInfo on every tail write is
        // redundant. Thorough runs and hashed writes keep the immediate readback.
        if digest || !crate::verify_policy::verifies_once() {
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
        }
        // Under verify-once, routed payload supply observes the stream's complete
        // retrieval map immediately after materializing it, so querying all
        // retrieval pointers on every 64 KiB chunk is redundant.
        if !crate::verify_policy::verifies_once() {
            self.verify_placements()?;
        }
        self.poisoned = false;
        if !digest {
            return Ok(serde_json::json!({"offset":offset,"bytes":data.len(),
                "readback_verified":true,
                "valid_prefix_bytes":self.valid_prefix,"conversion_qualified":false}));
        }
        let sha256 = hex::encode(crate::content_digest::sha256(data)?);
        Ok(serde_json::json!({"offset":offset,"bytes":data.len(),
            "sha256":sha256,"readback_verified":true,
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
            .map(|r| r.move_workspace(self.bytes, clusters, self.placed.len()))
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
        let cluster = crate::target_cluster::bytes();
        if self.poisoned
            || self.valid_data_submitted
            || self.valid_prefix != 0
            || self.move_submissions >= max_submissions
            || clusters == 0
            || !self.partition.is_multiple_of(cluster)
            // The first mebibyte of the volume is never a destination.
            || destination_lcn < (1 << 20) / cluster
            || logical_end.is_none_or(|v| v > self.bytes / cluster)
            || physical_end.is_none_or(|v| v > self.partition / cluster)
            || self.placed.iter().any(|(v, l, n)| {
                (!reposition && starting_vcn < *v + u64::from(*n) && *v < logical_end.unwrap_or(0))
                    || destination_lcn < *l + u64::from(*n) && *l < physical_end.unwrap_or(0)
            })
        {
            return Err(invalid(&format!(
                "private unwritten placement state, overlap or bounds differ for {}: \
                 {clusters} clusters from VCN {starting_vcn} to LCN {destination_lcn} \
                 (reposition {reposition}, {} placements, {} submissions)",
                self.path,
                self.placed.len(),
                self.move_submissions
            )));
        }
        // Before a move the file's whole mapping is read and every tracked
        // piece compared with it. From a file's second move on, that repeats
        // what its previous move ended with: a move reads the whole mapping
        // when the system call returns, compares every tracked piece, and
        // leaves the file poisoned (refused above) unless all of them match.
        // Nothing but this owner's moves changes the mapping of a file of
        // the shadow, which is attached to this process alone, and the move
        // about to be made ends with the same comparison. A file in
        // thousands of pieces was read twice for every piece moved: 25 s of
        // placing the full Windows volume's extents. A route that checks
        // once makes this comparison before a file's first move only.
        //
        // A run that verifies each thing once (`--verify fast`) holds a
        // move that landed to the mapping of the range it moved, below, so
        // its previous move did not compare every piece either. What stands
        // for both is the comparison of the file's complete mapping with
        // every tracked piece when placement ends
        // (`check_placements`, for every stream, before anything is derived
        // from the tracked pieces), and again whenever the file's validity
        // is advanced or its payload supplied.
        let compared_by_last_move =
            self.move_submissions > 0 && crate::verify_policy::checks_once();
        if !compared_by_last_move
            && let Err(error) = self.verify_placements_prepaid(self.resource.is_some())
        {
            self.poisoned = true;
            return Err(error);
        }
        let end = logical_end.unwrap();
        let mut next = Vec::with_capacity(self.placed.len() + 2);
        if !self.placed.windows(2).all(|w| w[0].0 <= w[1].0) {
            self.placed.sort_by_key(|r| r.0);
        }
        let mut covered = starting_vcn;
        for &(v, l, n) in &self.placed {
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
            volume_clusters: self.partition / cluster,
            starting_lcn: destination_lcn,
            clusters: u64::from(clusters),
        };
        let limits = destination_limits(clusters)?;
        let capture_destination_windows =
            |move_error: Option<&io::Error>| -> io::Result<DestinationWindows> {
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
                    // Preserve the native refusal when this capture follows a failed move.
                    return Err(io::Error::new(
                        io::ErrorKind::ResourceBusy,
                        OccupiedDestination {
                            path: self.path.clone(),
                            vcn: starting_vcn,
                            request,
                            legacy_allocated: legacy.allocated_clusters(),
                            metadata_allocated: metadata.allocated_clusters(),
                            move_error: move_error.map(ToString::to_string),
                        },
                    ));
                }
                Ok(DestinationWindows {
                    schema_version: 1,
                    scope: "destination-window-v1".into(),
                    legacy: bitmap_window_transport::from_proof(legacy.into_proof())?,
                    metadata: bitmap_window_transport::from_proof(metadata.into_proof())?,
                })
            };
        let fast_skip_bitmap = crate::verify_policy::verifies_once();
        let destination_bitmap = if fast_skip_bitmap {
            DestinationWindows {
                schema_version: 1,
                scope: "destination-window-omitted-fast-v1".into(),
                legacy: bitmap_window_transport::Proof::omitted_fast(request),
                metadata: bitmap_window_transport::Proof::omitted_fast(request),
            }
        } else {
            capture_destination_windows(None)?
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
        if let (true, Err(move_error)) = (fast_skip_bitmap, &moved) {
            // If FSCTL_MOVE_FILE was rejected because the destination clusters
            // became occupied since the phase bitmap snapshot, return
            // ResourceBusy so the planner re-snapshots and re-plans.
            if let Err(err) = capture_destination_windows(Some(move_error)) {
                if OccupiedDestination::from_error(&err).is_some() {
                    self.poisoned = false;
                    return Err(err);
                }
            }
        }
        // After every move the file's whole mapping was read and recorded,
        // and every tracked piece compared with it: work that grows with a
        // file's moves times its extents, and most of what placing the
        // full Windows volume's extents took. A run that verifies each
        // thing once trusts a successful `FSCTL_MOVE_FILE` until placement
        // ends, when every tracked piece of the file is verified once
        // against the file's complete mapping (`verify_placements`). Its
        // proof records `retrieval_paging::DEFERRED_ENCODING`. Any move
        // the system refused is still held to the complete mapping, and
        // recorded with it, as before.
        let narrowed = match (&moved, &self.resource) {
            (Ok(_), Some(_)) if crate::verify_policy::verifies_once() => Some((
                Vec::new(),
                crate::retrieval_paging::Proof {
                    encoding: crate::retrieval_paging::DEFERRED_ENCODING.into(),
                    canonical_sha256: String::new(),
                    extent_count: 0,
                    virtual_clusters: end,
                    pages: Vec::new(),
                },
            )),
            _ => None,
        };
        let native_error = moved.err().map(|e| e.raw_os_error().unwrap_or(31));
        let (mapped, all_placements_match, mapping_after, mapping_page_proof) =
            if let Some((canonical, proof)) = narrowed {
                // `all_placements_match` says of this form what was
                // compared: the moved range, which is where it was sent.
                (true, true, canonical, proof)
            } else {
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
                let mut all_placements_match = true;
                for &(v, l, n) in &next {
                    all_placements_match &= mapping.matches(v, l, n)?;
                }
                (
                    mapped,
                    all_placements_match,
                    capture.canonical,
                    capture.proof,
                )
            };
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
            mapping_after,
            mapping_page_proof,
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
            || !crate::target_cluster::aligned(bytes)
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
            let prefix_clusters = bytes / crate::target_cluster::bytes();
            for (vcn, _, clusters) in runs {
                if vcn >= prefix_clusters {
                    break;
                }
                if vcn != cursor {
                    return Err(invalid("private placed prefix has a gap"));
                }
                cursor += u64::from(clusters);
            }
            if cursor < prefix_clusters {
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
        crate::verify_policy::flush_working_file(&self.file)?;
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
                // In a run that verifies each thing once, the comparison
                // when placement ends (whose caller adds that phase) is
                // where a piece that no move of its own touched is first
                // compared: say which piece, and where it is now. (This
                // said "after valid-data flush", whichever check it was.)
                return Err(invalid(&format!(
                    "the complete mapping of {} differs from a piece tracked for it \
                     ({} pieces): {clusters} clusters from VCN {vcn} were placed at LCN \
                     {lcn}; VCN {vcn} now maps to {}",
                    self.path,
                    self.placed.len(),
                    mapping.describe(vcn)
                )));
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

    /// [`Self::check_placements`] for a helper thread of a batch: the same
    /// query and the same comparison, under a workspace the batch's caller
    /// reserved for it ([`Self::mapping_workspace_bytes`]). A helper never
    /// makes a reservation the pass cannot do without.
    pub(in crate::shadow_native) fn check_placements_prepaid(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid("poisoned private placement cannot supply data"));
        }
        self.verify_placements_prepaid(true)
    }

    /// What one comparison of this file's complete mapping with its tracked
    /// pieces reserves ([`Self::check_placements`] and
    /// [`Self::readonly_supply_mapping_fingerprint`] reserve the same), or
    /// `None` where it reserves nothing: no piece is tracked, so there is no
    /// query, or the file has no resource owner to reserve from.
    pub(in crate::shadow_native) fn mapping_workspace_bytes(&self) -> io::Result<Option<u64>> {
        if self.placed.is_empty() {
            return Ok(None);
        }
        self.resource
            .as_ref()
            .map(|resource| resource.tracking_workspace_bytes(self.bytes))
            .transpose()
    }

    /// Same-FileObject readonly batch evidence. The complete native mapping
    /// still checks EVERY tracked piece, then its full canonical digest binds
    /// the closing observation. No path reopen or payload read is exposed.
    ///
    /// With `prepaid` the query runs under a workspace its caller holds
    /// already ([`Self::mapping_workspace_bytes`]), as a helper thread of a
    /// batch asks for it; otherwise the workspace is reserved here.
    pub(in crate::shadow_native) fn readonly_supply_mapping_fingerprint(
        &self,
        readonly: &File,
        prepaid: bool,
    ) -> io::Result<Option<[u8; 32]>> {
        if self.poisoned {
            return Err(invalid("poisoned private supply mapping"));
        }
        if super::info(readonly, 18, 24)? != super::info(&self.file, 18, 24)? {
            return Err(invalid(
                "readonly supply query differs from actual private file",
            ));
        }
        if self.placed.is_empty() {
            return Ok(None);
        }
        let resource = self
            .resource
            .as_ref()
            .ok_or_else(|| invalid("readonly supply mapping requires actual resource owner"))?;
        let _memory = if prepaid {
            None
        } else {
            Some(resource.tracking_workspace(self.bytes)?)
        };
        let capture = resource.capture(readonly)?;
        let mapping = PreparedMapping::from_runs(capture.runs)?;
        for &(v, l, n) in &self.placed {
            if !mapping.matches(v, l, n)? {
                return Err(invalid("private supply complete mapping changed"));
            }
        }
        use sha2::Digest;
        Ok(Some(sha2::Sha256::digest(&capture.canonical).into()))
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
        self.track_current_prefix_inner(None)
    }
    pub(super) fn track_current_prefix_resource(&mut self) -> io::Result<ResourceTrackedHoles> {
        self.track_current_prefix_resource_with(None)
    }

    /// What the mapping query of [`Self::track_current_prefix_resource`]
    /// reserves while it is made, or `None` where it makes none: the file
    /// has no whole target cluster, or no resource owner.
    pub(super) fn tracking_query_bytes(&self) -> Option<io::Result<u64>> {
        if self.bytes / crate::target_cluster::bytes() == 0 {
            return None;
        }
        let resource = self.resource.as_ref()?;
        Some(resource.tracking_workspace_bytes(self.bytes))
    }

    /// The mapping query of [`Self::track_current_prefix_resource`], for a
    /// helper thread: the runs of the file's complete mapping, as that query
    /// returns them, under a workspace the helper holds
    /// ([`Self::tracking_query_bytes`]). It changes nothing; the file is
    /// tracked from them by [`Self::track_current_prefix_resource_queried`].
    /// `None` where the query is not made.
    pub(super) fn tracking_runs(&self) -> Option<io::Result<Vec<crate::stream_layout::Run>>> {
        if self.bytes / crate::target_cluster::bytes() == 0 {
            return None;
        }
        let resource = self.resource.as_ref()?;
        Some(resource.capture(&self.file).map(|capture| capture.runs))
    }

    /// [`Self::track_current_prefix_resource`], where a helper made its
    /// mapping query ([`Self::tracking_runs`]): every check and change is
    /// made here as there, in the same order, and what the query failed with
    /// is reported where the query is made.
    pub(super) fn track_current_prefix_resource_queried(
        &mut self,
        runs: io::Result<Vec<crate::stream_layout::Run>>,
    ) -> io::Result<ResourceTrackedHoles> {
        self.track_current_prefix_resource_with(Some(runs))
    }

    fn track_current_prefix_resource_with(
        &mut self,
        queried: Option<io::Result<Vec<crate::stream_layout::Run>>>,
    ) -> io::Result<ResourceTrackedHoles> {
        let _memory = self
            .resource
            .as_ref()
            .ok_or_else(|| invalid("resource tracking state absent"))?
            .tracking_workspace(self.bytes)?;
        let holes = self.track_current_prefix_inner(queried)?;
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
    /// `queried` is the file's mapping as a helper's query returned it
    /// ([`Self::tracking_runs`]); without it the query is made here.
    fn track_current_prefix_inner(
        &mut self,
        queried: Option<io::Result<Vec<crate::stream_layout::Run>>>,
    ) -> io::Result<Vec<(u64, u32)>> {
        if self.poisoned
            || self.valid_prefix != 0
            || self.valid_data_submitted
            || self.initial_mapping_tracked
            || self.move_submissions != 0
            || !self.placed.is_empty()
        {
            return Err(invalid("fresh zero-VDL mapping required for tracking"));
        }
        let clusters = self.bytes / crate::target_cluster::bytes();
        self.initial_mapping_tracked = true;
        if clusters == 0 {
            return Ok(vec![]);
        }
        self.poisoned = true;
        let max_placements = self
            .resource
            .as_ref()
            .map_or(MAX_FILE_PLACEMENTS, |r| r.max_tracked_slots);
        let runs = match queried {
            Some(runs) => runs?,
            None => {
                if let Some(resource) = &self.resource {
                    resource.capture(&self.file)?.runs
                } else {
                    crate::stream_native::retrieval_capture(&self.file)?.runs
                }
            }
        };
        self.retrieval_extents = runs.len();
        let mut tracked: Vec<(u64, u64, u32)> = Vec::new();
        let mut holes = Vec::new();
        let mut cursor = 0;
        for run in runs {
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
                        .is_none_or(|v| v > self.partition / crate::target_cluster::bytes())
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
    /// (tracking or the last move that read the complete mapping), for
    /// bounding the next move's proof. A move held to the mapping of its
    /// range does not change it; the resource route, the only one that
    /// makes such moves, bounds a proof by the most extents its queries
    /// admit and uses this count only to check it against that.
    pub(super) fn retrieval_extents(&self) -> usize {
        self.retrieval_extents
    }
}

/// Proofs shaped as a move returns them, for tests of what records them.
#[cfg(test)]
pub(in crate::shadow_native) mod proof_samples {
    use super::*;
    use crate::shadow_native::report_memory::{ReportMemoryAccountant, test_payer::Counted};

    fn buffer(bytes: usize) -> serde_json::Value {
        serde_json::json!({"codec":"rle-hex-v1","decoded_bytes":bytes,
            "decoded_sha256":"ab".repeat(32),"data_hex":"0400000000"})
    }
    fn window(lcn: u64, clusters: u64, template: usize) -> bitmap_window_transport::Proof {
        serde_json::from_value(serde_json::json!({
            "schema_version":1,"encoding":bitmap_window_transport::ENCODING,
            "window_schema_version":1,"window_encoding":"native-bitmap-window-v1",
            "request":{"volume_clusters":16_000_000u64,"starting_lcn":lcn,"clusters":clusters},
            "template":buffer(template),"declared_volume_clusters":16_000_000u64,
            "window_bits":buffer(clusters.div_ceil(8) as usize),"allocated_clusters":0,
            "window_sha256":"cd".repeat(32),"returned_bytes":4096,
            "whole_volume_complete":false,
            "queries":[{"code":0x9006f,"input":buffer(template),"bytes":buffer(4096),
                "native_error":null}]
        }))
        .expect("sample destination window")
    }

    /// The proof of a move of `clusters` to `lcn` in a file left in
    /// `extents` pieces, with its canonical mapping and one page proof per
    /// 1024 extents, as `retrieval_paging` makes them.
    pub(in crate::shadow_native) fn placement(
        extents: usize,
        lcn: u64,
        clusters: u32,
        native_error: Option<i32>,
    ) -> Placement {
        let mut mapping_after = Vec::with_capacity(16 + 16 * extents);
        mapping_after.extend_from_slice(&(extents as u32).to_le_bytes());
        mapping_after.extend_from_slice(&[0; 12]);
        for n in 0..extents as u64 {
            mapping_after.extend_from_slice(&((n + 1) * 7).to_le_bytes());
            let lcn = if n % 5 == 4 { -1 } else { (n * 9_973) as i64 };
            mapping_after.extend_from_slice(&lcn.to_le_bytes());
        }
        let pages = (0..extents.div_ceil(1024).max(1))
            .map(|n| crate::retrieval_paging::PageProof {
                input: (n as u64 * 7_168).to_le_bytes().to_vec(),
                response_header: [n as u8; 16],
                response_bytes: 16 + 16 * 1024,
                native_error: (n + 1 < extents.div_ceil(1024)).then_some(234),
                response_sha256: format!("{n:064x}"),
            })
            .collect();
        let payer = Counted::with_limit(u64::MAX);
        Placement {
            destination_lcn: lcn,
            starting_vcn: 77,
            clusters,
            submitted_once: true,
            before_valid_data_advance: true,
            native_error,
            mapping_matches: native_error.is_none(),
            all_placements_match: native_error.is_none(),
            reposition: lcn.is_multiple_of(2),
            mapping_after,
            mapping_page_proof: crate::retrieval_paging::Proof {
                encoding: crate::retrieval_paging::ENCODING.into(),
                canonical_sha256: "ef".repeat(32),
                extent_count: extents,
                virtual_clusters: extents as u64 * 7,
                pages,
            },
            destination_bitmap: DestinationWindows {
                schema_version: 1,
                scope: "destination-window-v1".into(),
                legacy: window(lcn, u64::from(clusters), 8),
                metadata: window(lcn, u64::from(clusters), 16),
            },
            _resource_memory: Some(payer.reserve(1).unwrap()),
        }
    }

    #[test]
    fn a_resource_proof_is_the_json_of_the_whole_placement() {
        for extents in [0, 1, 2, 1023, 1024, 1025, 5000] {
            for native_error in [None, Some(87)] {
                let sample = || placement(extents, 4_096 + extents as u64, 8_192, native_error);
                let whole = serde_json::to_value(sample()).unwrap();
                let proof = sample().into_resource_value().unwrap();
                // As a value and as bytes, compact and pretty.
                assert_eq!(serde_json::to_value(&proof).unwrap(), whole);
                assert_eq!(
                    serde_json::to_vec(&proof).unwrap(),
                    serde_json::to_vec(&whole).unwrap()
                );
                assert_eq!(
                    serde_json::to_vec_pretty(&proof).unwrap(),
                    serde_json::to_vec_pretty(&whole).unwrap()
                );
                // Every field it is read by is there as before.
                for (key, value) in whole.as_object().unwrap() {
                    if key != MAPPING_AFTER {
                        assert_eq!(&proof[key.as_str()], value, "{key}");
                    }
                }
                assert_eq!(
                    proof.as_object().unwrap().len() + 1,
                    whole.as_object().unwrap().len()
                );
            }
        }
    }
}

#[cfg(test)]
mod occupied_destination_tests {
    use super::*;

    #[test]
    fn only_a_confirmed_bitmap_refusal_is_classified_as_destination_drift() {
        let mut occupied = OccupiedDestination {
            path: "shadow-file:stream".into(),
            vcn: 5,
            request: bitmap_window::Request {
                volume_clusters: 1024,
                clusters: 3,
                starting_lcn: 70,
            },
            legacy_allocated: 1,
            metadata_allocated: 2,
            move_error: None,
        };
        assert!(occupied.before_submission());
        occupied.move_error = Some(io::Error::from_raw_os_error(112).to_string());
        let refusal = io::Error::new(io::ErrorKind::ResourceBusy, occupied);
        let message = refusal.to_string();
        for expected in [
            "shadow-file:stream",
            "3 clusters from VCN 5 to LCN 70",
            "legacy bitmap 1, metadata bitmap 2",
            "FSCTL_MOVE_FILE",
            "112",
        ] {
            assert!(message.contains(expected), "{message}");
        }
        assert!(
            !OccupiedDestination::from_error(&refusal)
                .unwrap()
                .before_submission()
        );
        assert!(
            OccupiedDestination::from_error(&io::Error::new(io::ErrorKind::ResourceBusy, message,))
                .is_none()
        );
    }
}
