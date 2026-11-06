//! Read-only NTFS reconnaissance. Reports are evidence, not conversion approval.
//!
//! `ntfs` validates the standard geometry. The bounded record/run-list reader below
//! also retains raw UTF-16 names and metadata that its high-level API does not yet
//! expose. Complete ordinary DATA lists and bounded MFT self-mapping are supported;
//! unsupported list forms remain explicit refusals. Raw reconciliation alone
//! never replaces native namespace/security evidence or source admission.

use crate::ntfs_allocation::{self, Assessment, AttributeKey, Limits, PhysicalInterval};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};

#[path = "ntfs_assembled_io.rs"]
mod assembled_io;
#[path = "ntfs_mft_bootstrap.rs"]
mod mft_bootstrap;
pub use assembled_io::validate_record_coverage;

#[cfg(windows)]
pub mod allocation_domain;
#[cfg(windows)]
mod checked_domain_io;
#[cfg(windows)]
pub(crate) use checked_domain_io::{CheckedMftDomain, LeasedResidentBytes, read_resident_inventory_attribute_domain};
#[cfg(windows)]
use checked_domain_io::checked_data_attribute_domain;
#[cfg(windows)]
pub mod external_sort;
#[cfg(windows)]
mod paged_files;
#[cfg(windows)]
mod paged_inspection;
#[cfg(windows)]
mod paged_roles;
#[cfg(windows)]
pub mod paged_storage;
#[cfg(windows)]
pub mod record_store;
#[cfg(windows)]
mod security_input;
pub mod source_domain;
#[cfg(windows)]
pub use paged_files::PagedRawFiles;
#[cfg(windows)]
pub use paged_inspection::{
    PagedInspection, SourceInspectionPin, inspect_paged_with_policy, inspect_paged_with_scratch,
};
pub use source_domain::{
    LegacySecurityRecord, RootDirectoryDomain, RootFileDomain, RootSecurityCaptureDomain,
    SourceDirectoryHeader, SourceHeader, SourceIndexRanges, SourceMetadataBudget,
    SourceMetadataRange,
};
mod namespace_capture;
mod security_capture;
use namespace_capture::NamespaceCapture;
use security_capture::SecurityCapture;

pub(crate) const MAX_MFT_RECORDS: u64 = 1_000_000;
const STREAM_HASH_BUFFER_BYTES: usize = 64 * 1024;
const LARGE_STREAM_HASH_BYTES: usize = 4 * 1024 * 1024;
/// Largest single read of a plain stream session; the caller owns the buffer.
pub const SESSION_READ_BYTES: usize = 4 * 1024 * 1024;
const ALPHA_MAX_PLAIN_BYTES: u64 = 256 * 1024 * 1024;

/// Bounds retained inventory data independently of the separately bounded
/// metadata read buffers. Hitting the limit returns an error, never a partial
/// report that could be mistaken for a complete inventory.
#[derive(Debug, Clone, Copy)]
pub struct InspectionLimits {
    pub max_report_bytes: u64,
    /// Cumulative logical DATA bytes, including sparse and uninitialized zeros.
    /// Repeated physical mappings are charged again for every logical stream.
    pub max_stream_hash_bytes: u64,
}

impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            max_report_bytes: 64 * 1024 * 1024,
            max_stream_hash_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Keep the alpha inventory budget unchanged. The larger source profile uses
/// a separate bounded logical-hash budget to cover ordinary data and internal
/// NTFS streams; it does not itself authorize a conversion.
pub fn limits_for_resource_profile(
    profile: crate::ntfs_admission::ResourceProfile,
) -> InspectionLimits {
    match profile {
        crate::ntfs_admission::ResourceProfile::AlphaV1 => InspectionLimits::default(),
        crate::ntfs_admission::ResourceProfile::ExperimentalLargeTreeV1 => InspectionLimits {
            max_report_bytes: 64 * 1024 * 1024,
            max_stream_hash_bytes: 16 * 1024 * 1024 * 1024,
        },
        crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2 => InspectionLimits {
            max_report_bytes: 64 * 1024 * 1024,
            max_stream_hash_bytes: n2r_win32::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES * 4,
        },
        crate::ntfs_admission::ResourceProfile::ExperimentalObjectEnvelopeV3(admission) => {
            InspectionLimits {
                max_report_bytes: admission.map_or(
                    n2r_win32::tree_resources::INSPECTION_BYTES as u64,
                    |a| {
                        u64::from(a.maximum_inspection_bytes)
                            .min(n2r_win32::tree_resources::INSPECTION_BYTES as u64)
                    },
                ),
                max_stream_hash_bytes: n2r_win32::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES
                    * 4,
            }
        }
        // The resource-bounded pipeline requires its actual paged source
        // owner. Never route it through the legacy owning-Vec inspector.
        crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(_) => InspectionLimits {
            max_report_bytes: 0,
            max_stream_hash_bytes: 0,
        },
    }
}

struct HashBudget {
    limit: u64,
    used: u64,
}

impl HashBudget {
    fn reserve(&mut self, bytes: u64) -> Result<()> {
        let used = self
            .used
            .checked_add(bytes)
            .context("stream hash accounting overflow")?;
        ensure!(
            used <= self.limit,
            "cumulative stream hash byte limit exceeded (requires {used} bytes, limit {}); no partial inventory returned",
            self.limit
        );
        self.used = used;
        Ok(())
    }
}

struct ReportBudget {
    limit: u64,
    used: u64,
}

impl ReportBudget {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        let used = self
            .used
            .checked_add(bytes)
            .context("inventory memory accounting overflow")?;
        ensure!(
            used <= self.limit,
            "inventory report budget exceeded (requires at least {used} bytes, limit {}); no partial inventory returned",
            self.limit
        );
        self.used = used;
        Ok(())
    }

    fn push<T>(&mut self, items: &mut Vec<T>, item: T, heap_bytes: u64) -> Result<()> {
        let element_bytes = std::mem::size_of::<T>() as u64;
        self.charge(heap_bytes)?;
        if items.len() == items.capacity() {
            // Grow in bounded chunks instead of allowing an implicit doubling
            // to exceed the remaining report budget. Count actual capacity.
            let slots = ((self.limit - self.used) / element_bytes).min(64);
            ensure!(
                slots > 0,
                "inventory report budget exceeded (limit {} bytes); no partial inventory returned",
                self.limit
            );
            let before = items.capacity();
            items
                .try_reserve_exact(slots as usize)
                .context("allocating bounded inventory report")?;
            let bytes = ((items.capacity() - before) as u64)
                .checked_mul(element_bytes)
                .context("inventory vector accounting overflow")?;
            self.charge(bytes)?;
        }
        items.push(item);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NtfsGeometry {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub total_sectors: u64,
    pub volume_size: u64,
    pub total_clusters: u64,
    pub mft_lcn: u64,
    pub mftmirr_lcn: u64,
    pub file_record_size: u32,
    pub index_record_size: u32,
    pub serial_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionBlocker {
    pub code: String,
    pub message: String,
    pub file_record_number: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtfsInspection {
    pub schema_version: u32,
    pub geometry: NtfsGeometry,
    pub volume_version: Option<String>,
    pub volume_flags: Option<u16>,
    pub dirty: Option<bool>,
    pub mft_record_count: u64,
    pub records_scanned: u64,
    pub allocated_clusters: Option<u64>,
    pub free_clusters: Option<u64>,
    /// Raw attribute/bitmap consistency only. Native allocation, namespace,
    /// security, clean-state and backup reconciliation remain separate gates.
    #[serde(default)]
    pub allocation_reconciliation: Option<AllocationReconciliation>,
    /// Raw $I30/MFT membership and topology only, not native enumeration or
    /// a filesystem-wide source-admission certificate.
    #[serde(default)]
    pub namespace_reconciliation: Option<crate::ntfs_namespace::Reconciliation>,
    /// Central/legacy descriptor resolution is raw evidence only; native
    /// security retrieval and target preservation remain separate gates.
    #[serde(default)]
    pub security_reconciliation: Option<crate::ntfs_security::Reconciliation>,
    pub files: Vec<FileInventory>,
    /// Original physical records for supported assembled ordinary DATA. The
    /// canonical files contain each stream once; extensions are not file IDs.
    /// Deserialized evidence never grants source/device write authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attribute_assemblies: Vec<crate::ntfs_attribute_list::Assembly>,
    pub blockers: Vec<InspectionBlocker>,
    pub inventory_complete: bool,
    /// Retained report storage, including vector spare capacity; excludes the
    /// independently bounded input buffers and temporary current MFT record.
    pub inventory_memory_bytes: u64,
    pub inventory_memory_limit_bytes: u64,
    #[serde(default)]
    pub stream_hash_bytes: u64,
    #[serde(default)]
    pub stream_hash_limit_bytes: u64,
}

impl NtfsInspection {
    /// Byte ranges NTFS owns: every nonresident attribute extent, as claimed by
    /// the allocation reconciliation, plus the sectors past the cluster domain
    /// (the backup boot sector). Valid only when the raw model reconciled exactly
    /// with the volume bitmap, so the union is the bitmap's allocated set.
    pub fn allocated_byte_ranges(&self, partition_bytes: u64) -> Result<Vec<(u64, u64)>> {
        ensure!(
            self.allocation_reconciliation
                .as_ref()
                .is_some_and(|r| r.status == AllocationReconciliationStatus::ConsistentRawModel),
            "NTFS allocated ranges need an exactly reconciled raw allocation model"
        );
        let cluster = u64::from(self.geometry.cluster_size);
        let domain = self
            .geometry
            .total_clusters
            .checked_mul(cluster)
            .context("NTFS cluster domain overflow")?;
        ensure!(
            domain <= partition_bytes,
            "NTFS cluster domain exceeds the partition"
        );
        let list_storage = self.attribute_assemblies.iter().filter_map(|assembly| {
            assembly
                .base
                .attributes
                .iter()
                .find(|a| a.type_code == 0x20 && !a.resident)
        });
        let mut ranges = Vec::new();
        for attribute in self
            .files
            .iter()
            .flat_map(|file| file.attributes.iter())
            .chain(list_storage)
        {
            if attribute.resident {
                continue;
            }
            for extent in &attribute.extents {
                let Some(physical) = extent.physical_offset else {
                    continue; // Sparse holes have no physical owner.
                };
                let end = physical
                    .checked_add(extent.length)
                    .context("NTFS extent overflow")?;
                ensure!(
                    extent.length != 0 && end <= domain,
                    "NTFS extent escapes the cluster domain"
                );
                ranges.push((physical, extent.length));
            }
        }
        if domain < partition_bytes {
            ranges.push((domain, partition_bytes - domain));
        }
        Ok(merge_ranges(ranges))
    }
}

/// Sorted, merged (offset, length) ranges; touching ranges join.
fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (offset, length) in ranges {
        match merged.last_mut() {
            Some(last) if offset <= last.0 + last.1 => {
                last.1 = last.1.max(offset + length - last.0);
            }
            _ => merged.push((offset, length)),
        }
    }
    merged
}

/// Records every byte range read through it. Wrapping an inspection proves
/// which bytes its deterministic result depends on: if those bytes are
/// unchanged, repeating the inspection reads and returns exactly the same.
pub struct ReadRecorder<R> {
    inner: R,
    position: u64,
    ranges: Vec<(u64, u64)>,
}

impl<R: Read + Seek> ReadRecorder<R> {
    pub fn new(mut inner: R) -> io::Result<Self> {
        let position = inner.stream_position()?;
        Ok(Self {
            inner,
            position,
            ranges: Vec::new(),
        })
    }

    /// The sorted, merged ranges read so far.
    pub fn ranges(&self) -> Vec<(u64, u64)> {
        merge_ranges(self.ranges.clone())
    }
}

impl<R: Read> Read for ReadRecorder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(output)?;
        if count != 0 {
            match self.ranges.last_mut() {
                Some(last) if last.0 + last.1 == self.position => last.1 += count as u64,
                _ => self.ranges.push((self.position, count as u64)),
            }
            self.position += count as u64;
        }
        Ok(count)
    }
}

impl<R: Seek> Seek for ReadRecorder<R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.position = self.inner.seek(from)?;
        Ok(self.position)
    }
}

/// Whether every range in sorted merged `inner` lies inside sorted merged `outer`.
pub fn ranges_cover(outer: &[(u64, u64)], inner: &[(u64, u64)]) -> bool {
    let mut cursor = outer.iter().peekable();
    inner.iter().all(|&(offset, length)| {
        while cursor
            .peek()
            .is_some_and(|&&(start, size)| start + size <= offset)
        {
            cursor.next();
        }
        cursor
            .peek()
            .is_some_and(|&&(start, size)| start <= offset && offset + length <= start + size)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AllocationReconciliationStatus {
    ConsistentRawModel,
    Rejected,
    IncompleteAttributeInventory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationReconciliation {
    pub status: AllocationReconciliationStatus,
    pub bitmap_sha256: String,
    pub domain_clusters: u64,
    pub physical_intervals: usize,
    /// Rejected interval indices follow file/attribute/extent inventory order.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInventory {
    pub record_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub is_directory: bool,
    /// Convenience summary: reserved record or $Extend descendant candidate.
    /// Never permission to omit, overwrite, or free this record's extents. False
    /// also covers unresolved roles; inspect metadata_role and its issue.
    pub is_metadata: bool,
    #[serde(default)]
    pub metadata_role: MetadataRole,
    #[serde(default)]
    pub metadata_role_issue: Option<MetadataRoleIssue>,
    pub base_file_reference: u64,
    pub names: Vec<NameInventory>,
    pub standard_information: Option<StandardInformation>,
    pub streams: Vec<StreamInventory>,
    pub attributes: Vec<AttributeInventory>,
    /// Raw paired EA bytes and their validated semantic set. Legacy reports
    /// without this field can establish absence only when no EA attrs exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_attributes: Option<crate::ntfs_extended_attributes::Inventory>,
    /// Exact checked Microsoft symlink/mount-point bytes. Missing legacy data
    /// proves absence only when the attribute inventory has no REPARSE_POINT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse: Option<n2r_win32::reparse_layout::Point>,
}

/// MFT ancestry evidence only. Directory indexes, allocation ownership and
/// preservation semantics remain unverified for every candidate role.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetadataRole {
    /// Legacy reports have no ancestry evidence, regardless of is_metadata.
    #[default]
    NotClassified,
    ReservedSystemRecord,
    ExtendDescendantCandidate,
    /// Outside $Extend is not proof that a file contains only ordinary user data.
    OutsideExtendCandidate,
    Unresolved,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetadataRoleIssue {
    InvalidRootAnchor,
    InvalidExtendAnchor,
    ExtensionRecord,
    AttributeListUnassembled,
    ZeroSequenceNumber,
    MissingNames,
    LinkCountMismatch,
    InvalidName,
    MissingParent,
    ParentSequenceMismatch,
    ParentNotDirectory,
    UnsupportedReservedParent,
    Cycle,
    MixedAncestry,
    AncestorUnresolved,
    DepthLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameInventory {
    pub name: String,
    pub name_utf16: Vec<u16>,
    pub namespace: u8,
    pub parent_record_number: u64,
    pub parent_sequence_number: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardInformation {
    /// Raw Windows FILETIME values; no precision or timezone conversion is applied.
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_change_time: u64,
    pub access_time: u64,
    pub file_attributes: u32,
    pub security_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Extent {
    pub logical_offset: u64,
    pub physical_offset: Option<u64>,
    /// Allocation length, possibly extending past the stream's logical EOF.
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInventory {
    pub name: String,
    pub name_utf16: Vec<u16>,
    pub resident: bool,
    pub flags: u16,
    pub logical_size: u64,
    pub initialized_size: u64,
    pub allocated_size: u64,
    pub extents: Vec<Extent>,
    /// Raw resident bytes only; not a complete logical digest for unsupported layouts.
    /// A [`n2r_win32::content_digest`] (XXH3-128; historical name).
    pub resident_sha256: Option<String>,
    /// Complete logical content [0, EOF), with holes and uninitialized tails zeroed.
    /// Present only when logical_hash_status is Complete. A
    /// [`n2r_win32::content_digest`] (XXH3-128; historical name).
    #[serde(default)]
    pub logical_sha256: Option<String>,
    #[serde(default)]
    pub logical_hash_status: LogicalHashStatus,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogicalHashStatus {
    /// Legacy reports without logical hashing evidence deserialize conservatively.
    #[default]
    NotComputed,
    Complete,
    /// Deliberately not read under the explicit extent-identity policy.
    /// The logical digest is absent; complete metadata/mappings are retained.
    NotReadExtentIdentityV1,
    UnsupportedCompression,
    UnsupportedEncryption,
    UnsupportedAttributeList,
    UnsupportedExtensionRecord,
    UnsupportedFlags,
    UnsupportedCompressionUnit,
    /// $BadClus:$Bad can have unflagged sparse runs with system-specific semantics.
    UnsupportedBadClusterMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttributeInventory {
    pub type_code: u32,
    pub instance: u16,
    pub name_utf16: Vec<u16>,
    pub flags: u16,
    pub resident: bool,
    pub logical_size: u64,
    pub initialized_size: u64,
    pub allocated_size: u64,
    pub lowest_vcn: u64,
    #[serde(default)]
    pub compression_unit: u16,
    /// Compressed base-header TotalAllocated, distinct from virtual allocation.
    /// Plain/sparse reports omit this field to retain their legacy encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_allocated_size: Option<u64>,
    pub extents: Vec<Extent>,
    pub resident_sha256: Option<String>,
    /// Exact bytes for resident semantic metadata, never file $DATA contents.
    pub resident_metadata_hex: Option<String>,
}

#[derive(Clone)]
struct Attribute {
    report: AttributeInventory,
    resident_value: Option<Vec<u8>>,
}

struct Record {
    sequence: u16,
    links: u16,
    flags: u16,
    base: u64,
    attributes: Vec<Attribute>,
}

fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2).context("truncated u16")?.try_into()?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4).context("truncated u32")?.try_into()?,
    ))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8).context("truncated u64")?.try_into()?,
    ))
}

fn record_size(encoded: u8, cluster_size: u32, label: &str) -> Result<u32> {
    let signed = encoded as i8;
    let size = if signed > 0 {
        cluster_size
            .checked_mul(signed as u32)
            .context("record size overflow")?
    } else {
        ensure!(signed != 0, "{label} size is zero");
        1u32.checked_shl(u32::from(signed.unsigned_abs()))
            .context("record size exponent overflow")?
    };
    ensure!(
        (512..=65536).contains(&size) && size.is_power_of_two(),
        "unsupported {label} size {size}"
    );
    Ok(size)
}

/// Validate a partition boot sector before allowing any dependent allocation.
/// `length` is the length of the bounded partition reader, not a VHDX container.
pub fn inspect_boot_sector(bytes: &[u8], length: u64) -> Result<NtfsGeometry> {
    ensure!(bytes.len() >= 512, "truncated NTFS boot sector");
    ensure!(
        &bytes[3..11] == b"NTFS    ",
        "not an NTFS partition boot sector"
    );
    ensure!(
        bytes[510..512] == [0x55, 0xaa],
        "invalid NTFS boot signature"
    );
    let bytes_per_sector = u16le(bytes, 11)?;
    ensure!(
        (512..=4096).contains(&bytes_per_sector) && bytes_per_sector.is_power_of_two(),
        "invalid bytes per sector"
    );
    let encoded = bytes[13];
    let sectors_per_cluster = if encoded > 128 {
        let shift = (encoded as i8).unsigned_abs() as u32;
        ensure!(shift <= 12, "invalid cluster exponent");
        1u32.checked_shl(shift)
            .context("cluster exponent overflow")?
    } else {
        ensure!(
            encoded != 0 && encoded.is_power_of_two(),
            "invalid sectors per cluster"
        );
        u32::from(encoded)
    };
    let cluster_size = u32::from(bytes_per_sector)
        .checked_mul(sectors_per_cluster)
        .context("cluster size overflow")?;
    ensure!(cluster_size <= 2 * 1024 * 1024, "unsupported cluster size");
    ensure!(
        u16le(bytes, 14)? == 0
            && bytes[16] == 0
            && u16le(bytes, 17)? == 0
            && u16le(bytes, 19)? == 0
            && u16le(bytes, 22)? == 0
            && u32le(bytes, 32)? == 0,
        "nonzero legacy FAT BPB fields in NTFS boot sector"
    );
    let total_sectors = u64le(bytes, 40)?;
    ensure!(total_sectors > 0, "empty NTFS volume");
    let volume_size = total_sectors
        .checked_mul(u64::from(bytes_per_sector))
        .context("volume size overflow")?;
    ensure!(
        volume_size <= length,
        "NTFS volume exceeds partition reader length"
    );
    // NTFS commonly excludes its final backup boot sector from TotalSectors.
    ensure!(
        length == volume_size || length - volume_size == u64::from(bytes_per_sector),
        "reader contains trailing data; provide exactly one NTFS partition"
    );
    let total_clusters = volume_size / u64::from(cluster_size);
    ensure!(total_clusters > 0, "volume is smaller than one cluster");
    let mft_lcn = u64le(bytes, 48)?;
    let mftmirr_lcn = u64le(bytes, 56)?;
    ensure!(
        mft_lcn > 0 && mft_lcn < total_clusters,
        "MFT location outside volume"
    );
    ensure!(
        mftmirr_lcn > 0 && mftmirr_lcn < total_clusters,
        "MFT mirror location outside volume"
    );
    let file_record_size = record_size(bytes[64], cluster_size, "file record")?;
    let index_record_size = record_size(bytes[68], cluster_size, "index record")?;
    for lcn in [mft_lcn, mftmirr_lcn] {
        let end = lcn
            .checked_mul(u64::from(cluster_size))
            .and_then(|n| n.checked_add(u64::from(file_record_size)))
            .context("MFT range overflow")?;
        ensure!(end <= volume_size, "MFT record crosses volume boundary");
    }
    Ok(NtfsGeometry {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size,
        total_sectors,
        volume_size,
        total_clusters,
        mft_lcn,
        mftmirr_lcn,
        file_record_size,
        index_record_size,
        serial_number: u64le(bytes, 72)?,
    })
}

fn read_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    bytes: &mut [u8],
    limit: u64,
) -> Result<()> {
    let end = offset
        .checked_add(bytes.len() as u64)
        .context("read range overflow")?;
    ensure!(end <= limit, "metadata read exceeds partition boundary");
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(bytes)?;
    Ok(())
}

fn utf16(bytes: &[u8]) -> Result<Vec<u16>> {
    ensure!(bytes.len().is_multiple_of(2), "odd UTF-16 byte length");
    Ok(bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect())
}

fn parse_runs(
    bytes: &[u8],
    first_vcn: u64,
    last_vcn: u64,
    geometry: &NtfsGeometry,
) -> Result<Vec<Extent>> {
    let mut cursor = 0usize;
    let mut lcn = 0i128;
    let mut vcn = first_vcn;
    let mut extents = Vec::new();
    let mut terminated = false;
    while cursor < bytes.len() {
        let descriptor = bytes[cursor];
        cursor += 1;
        if descriptor == 0 {
            terminated = true;
            break;
        }
        let count_bytes = usize::from(descriptor & 15);
        let delta_bytes = usize::from(descriptor >> 4);
        ensure!(
            (1..=8).contains(&count_bytes) && delta_bytes <= 8,
            "invalid run-list field width"
        );
        let fields = bytes
            .get(cursor..cursor + count_bytes + delta_bytes)
            .context("truncated run-list entry")?;
        let mut count_buffer = [0u8; 8];
        count_buffer[..count_bytes].copy_from_slice(&fields[..count_bytes]);
        let count = u64::from_le_bytes(count_buffer);
        ensure!(count > 0, "zero-length data run");
        let physical_offset = if delta_bytes == 0 {
            None
        } else {
            let delta_data = &fields[count_bytes..];
            let mut delta_buffer = if delta_data[delta_bytes - 1] & 0x80 != 0 {
                [0xff; 8]
            } else {
                [0; 8]
            };
            delta_buffer[..delta_bytes].copy_from_slice(delta_data);
            lcn += i128::from(i64::from_le_bytes(delta_buffer));
            ensure!(
                lcn >= 0 && lcn <= i128::from(u64::MAX),
                "negative or overflowing data run LCN"
            );
            let offset = (lcn as u64)
                .checked_mul(u64::from(geometry.cluster_size))
                .context("data run position overflow")?;
            Some(offset)
        };
        let length = count
            .checked_mul(u64::from(geometry.cluster_size))
            .context("data run length overflow")?;
        if let Some(offset) = physical_offset {
            ensure!(
                offset
                    .checked_add(length)
                    .is_some_and(|end| end <= geometry.volume_size),
                "data run outside volume"
            );
        }
        let logical_offset = vcn
            .checked_mul(u64::from(geometry.cluster_size))
            .context("data run VCN overflow")?;
        vcn = vcn.checked_add(count).context("data run VCN overflow")?;
        extents.push(Extent {
            logical_offset,
            physical_offset,
            length,
        });
        cursor += count_bytes + delta_bytes;
    }
    ensure!(terminated, "unterminated run list");
    if !extents.is_empty() {
        ensure!(
            last_vcn.checked_add(1) == Some(vcn),
            "run list does not match declared VCN range"
        );
    } else {
        ensure!(
            first_vcn == 0 && (last_vcn == 0 || last_vcn == u64::MAX),
            "empty run list has a nonempty VCN range"
        );
    }
    Ok(extents)
}

fn parse_record(mut bytes: Vec<u8>, geometry: &NtfsGeometry) -> Result<Record> {
    ensure!(
        bytes.len() == geometry.file_record_size as usize && bytes.len() >= 48,
        "wrong file record length"
    );
    ensure!(&bytes[..4] == b"FILE", "invalid FILE record signature");
    let usa = usize::from(u16le(&bytes, 4)?);
    let usa_count = usize::from(u16le(&bytes, 6)?);
    // The common FILE fixed header ends after next-attribute-instance at
    // 0x2a. Preserve the older 42-byte form as well as the 48-byte extended
    // form: this parser does not interpret the optional record-number field.
    // The USA may never alias the fixed fields that we decode below.
    ensure!(
        usa >= 0x2a && usa.is_multiple_of(2),
        "update sequence array overlaps the fixed FILE header or is unaligned"
    );
    ensure!(
        usa_count == bytes.len() / 512 + 1,
        "invalid update sequence array count"
    );
    let usa_end = usa
        .checked_add(usa_count * 2)
        .context("USA range overflow")?;
    ensure!(
        usa_end <= bytes.len(),
        "update sequence array outside record"
    );
    let sequence = [bytes[usa], bytes[usa + 1]];
    for index in 1..usa_count {
        let tail = index * 512 - 2;
        ensure!(
            bytes[tail..tail + 2] == sequence,
            "torn file record: update sequence mismatch"
        );
        let replacement = [bytes[usa + index * 2], bytes[usa + index * 2 + 1]];
        bytes[tail..tail + 2].copy_from_slice(&replacement);
    }
    let used = u32le(&bytes, 24)? as usize;
    let allocated = u32le(&bytes, 28)? as usize;
    ensure!(
        used <= allocated && allocated == bytes.len(),
        "invalid file record size fields"
    );
    let mut at = usize::from(u16le(&bytes, 20)?);
    ensure!(
        at >= 48 && at >= usa_end && at % 8 == 0 && at < used,
        "invalid first attribute offset"
    );
    let mut attributes = Vec::new();
    let mut terminated = false;
    while at < used {
        let type_code = u32le(&bytes[..used], at)?;
        if type_code == u32::MAX {
            terminated = true;
            break;
        }
        let size = u32le(&bytes[..used], at + 4)? as usize;
        ensure!(
            size >= 24 && size.is_multiple_of(8),
            "invalid attribute length"
        );
        let end = at.checked_add(size).context("attribute range overflow")?;
        ensure!(end <= used, "attribute extends outside used record");
        let raw = &bytes[at..end];
        ensure!(raw[8] <= 1, "invalid resident/nonresident tag");
        let resident = raw[8] == 0;
        let name_length = usize::from(raw[9]) * 2;
        let name_at = usize::from(u16le(raw, 10)?);
        let flags = u16le(raw, 12)?;
        let minimum_header = if resident {
            24
        } else if flags & 0x80ff != 0 && u64le(raw, 16)? == 0 {
            // Sparse/compressed base attributes include TotalAllocated before
            // their name and mapping pairs. Never interpret that field as runs.
            72
        } else {
            64
        };
        ensure!(raw.len() >= minimum_header, "truncated attribute header");
        if name_length > 0 {
            ensure!(name_at >= minimum_header, "attribute name overlaps header");
        }
        let name_utf16 = if name_length == 0 {
            Vec::new()
        } else {
            utf16(
                raw.get(name_at..name_at + name_length)
                    .context("attribute name outside attribute")?,
            )?
        };
        let instance = u16le(raw, 14)?;
        let (logical_size, initialized_size, allocated_size, lowest_vcn, extents, resident_value) =
            if resident {
                let value_len = u32le(raw, 16)? as usize;
                let value_at = usize::from(u16le(raw, 20)?);
                ensure!(
                    value_at >= 24 && (name_length == 0 || name_at + name_length <= value_at),
                    "resident value overlaps header or name"
                );
                let value = raw
                    .get(value_at..value_at + value_len)
                    .context("resident value outside attribute")?
                    .to_vec();
                (
                    value_len as u64,
                    value_len as u64,
                    value_len as u64,
                    0,
                    Vec::new(),
                    Some(value),
                )
            } else {
                let lowest = u64le(raw, 16)?;
                let highest = u64le(raw, 24)?;
                let runs_at = usize::from(u16le(raw, 32)?);
                ensure!(
                    runs_at >= minimum_header
                        && runs_at < raw.len()
                        && (name_length == 0 || name_at + name_length <= runs_at),
                    "invalid run-list offset"
                );
                let allocated = u64le(raw, 40)?;
                let logical = u64le(raw, 48)?;
                let initialized = u64le(raw, 56)?;
                if lowest == 0 {
                    ensure!(
                        initialized <= logical,
                        "initialized size exceeds logical size"
                    );
                }
                let extents = parse_runs(&raw[runs_at..], lowest, highest, geometry)?;
                if lowest == 0 {
                    let coverage = extents.iter().try_fold(0u64, |sum, run| {
                        sum.checked_add(run.length).context("run coverage overflow")
                    })?;
                    // An attribute-list continuation may supply the rest. It is explicitly blocked below.
                    ensure!(
                        logical == 0 || coverage > 0,
                        "nonempty stream has no data runs"
                    );
                }
                (logical, initialized, allocated, lowest, extents, None)
            };
        let resident_sha256 = resident_value
            .as_ref()
            .map(|v| n2r_win32::content_digest::of(v));
        let resident_metadata_hex = if matches!(
            type_code,
            0x10 | 0x30 | 0x40 | 0x50 | 0x70 | 0xc0 | 0xd0 | 0xe0
        ) || (type_code == 0x100 && name_utf16 == [36, 68, 83, 67]
            && resident_value.as_ref().is_some_and(|value| value.len() == 8)) {
            resident_value.as_ref().map(hex::encode)
        } else {
            None
        };
        attributes.push(Attribute {
            report: AttributeInventory {
                type_code,
                instance,
                name_utf16,
                flags,
                resident,
                logical_size,
                initialized_size,
                allocated_size,
                lowest_vcn,
                compression_unit: if resident { 0 } else { u16le(raw, 34)? },
                total_allocated_size: if !resident && flags & 0x00ff != 0 && lowest_vcn == 0 {
                    Some(u64le(raw, 64)?)
                } else {
                    None
                },
                extents,
                resident_sha256,
                resident_metadata_hex,
            },
            resident_value,
        });
        at = end;
    }
    ensure!(terminated, "missing attribute terminator");
    Ok(Record {
        sequence: u16le(&bytes, 16)?,
        links: u16le(&bytes, 18)?,
        flags: u16le(&bytes, 22)?,
        base: u64le(&bytes, 32)?,
        attributes,
    })
}

fn unnamed(record: &Record, type_code: u32) -> Result<&Attribute> {
    let mut found = record.attributes.iter().filter(|a| {
        a.report.type_code == type_code
            && a.report.name_utf16.is_empty()
            && a.report.lowest_vcn == 0
    });
    let value = found
        .next()
        .context(format!("missing unnamed attribute {type_code:#x}"))?;
    ensure!(found.next().is_none(), "duplicate unnamed base attribute");
    Ok(value)
}

fn read_attribute_range<R: Read + Seek>(
    reader: &mut R,
    attribute: &Attribute,
    offset: u64,
    output: &mut [u8],
    geometry: &NtfsGeometry,
) -> Result<()> {
    let mut compression = compression_reader(attribute, geometry)?;
    read_logical_range(
        reader,
        attribute,
        offset,
        output,
        geometry,
        &mut compression,
    )
}

fn compression_reader(
    attribute: &Attribute,
    geometry: &NtfsGeometry,
) -> Result<Option<crate::ntfs_compression::Reader>> {
    if !attribute.report.resident && attribute.report.flags & 0x00ff != 0 {
        Ok(Some(crate::ntfs_compression::Reader::new(
            &attribute.report,
            geometry,
        )?))
    } else {
        Ok(None)
    }
}

/// Dispatch encoded DATA before the plain sparse-run interpretation. A cache
/// belongs to one checked attribute and never treats compression padding as holes.
pub(crate) const MAX_DIRECT_READ_SPANS: usize = 1024;

/// Operation-local evidence of bytes actually returned by successful direct
/// physical reads. No constructor from mappings/JSON, cloning or serialization.
/// Missing spans (resident/decoded/hole/VDL bytes) prove nothing about a COPY.
pub(crate) struct DirectReadReceipt {
    spans: Vec<DirectReadSpan>,
    available: bool,
}

pub(crate) struct DirectReadSpan {
    output_offset: usize,
    source_offset: u64,
    length: usize,
}

impl DirectReadSpan {
    pub(crate) fn output_offset(&self) -> usize {
        self.output_offset
    }
    pub(crate) fn source_offset(&self) -> u64 {
        self.source_offset
    }
    pub(crate) fn length(&self) -> usize {
        self.length
    }
}

impl DirectReadReceipt {
    fn new() -> Self {
        Self {
            spans: Vec::new(),
            available: true,
        }
    }

    pub(crate) fn spans(&self) -> Option<&[DirectReadSpan]> {
        self.available.then_some(self.spans.as_slice())
    }

    fn unavailable(&mut self) {
        self.available = false;
        self.spans.clear();
    }

    fn record(&mut self, output_offset: usize, source_offset: u64, length: usize) {
        if !self.available {
            return;
        }
        if length == 0
            || source_offset.checked_add(length as u64).is_none()
            || output_offset.checked_add(length).is_none()
        {
            self.unavailable();
            return;
        }
        if let Some(last) = self.spans.last_mut() {
            if last.output_offset.checked_add(last.length) == Some(output_offset)
                && last.source_offset.checked_add(last.length as u64) == Some(source_offset)
            {
                if let Some(next) = last.length.checked_add(length) {
                    last.length = next;
                    return;
                }
                self.unavailable();
                return;
            }
        }
        // This optimization is optional: budget/allocation failure restores
        // the caller's ordinary COPY reread, never a partially accepted proof.
        if self.spans.len() == MAX_DIRECT_READ_SPANS || self.spans.try_reserve(1).is_err() {
            self.unavailable();
            return;
        }
        self.spans.push(DirectReadSpan {
            output_offset,
            source_offset,
            length,
        });
    }
}

fn read_logical_range<R: Read + Seek>(
    reader: &mut R,
    attribute: &Attribute,
    offset: u64,
    output: &mut [u8],
    geometry: &NtfsGeometry,
    compression: &mut Option<crate::ntfs_compression::Reader>,
) -> Result<()> {
    read_logical_range_observed(
        reader,
        attribute,
        offset,
        output,
        geometry,
        compression,
        None,
    )
}

fn read_logical_range_observed<R: Read + Seek>(
    reader: &mut R,
    attribute: &Attribute,
    offset: u64,
    output: &mut [u8],
    geometry: &NtfsGeometry,
    compression: &mut Option<crate::ntfs_compression::Reader>,
    mut receipt: Option<&mut DirectReadReceipt>,
) -> Result<()> {
    let end = offset
        .checked_add(output.len() as u64)
        .context("attribute read overflow")?;
    ensure!(
        end <= attribute.report.logical_size,
        "read beyond logical attribute EOF"
    );
    if let Some(compression) = compression {
        return compression.read_range(reader, offset, output);
    }
    if let Some(data) = &attribute.resident_value {
        ensure!(
            (attribute.report.flags == 0 && attribute.report.compression_unit == 0)
                || crate::ntfs_compression::supported(&attribute.report, geometry).is_ok(),
            "unsupported resident attribute encoding"
        );
        output.copy_from_slice(
            data.get(offset as usize..end as usize)
                .context("resident logical read exceeds value")?,
        );
        return Ok(());
    }
    ensure!(
        attribute.report.flags & 0x40ff == 0,
        "cannot interpret compressed or encrypted metadata"
    );
    let mut position = offset;
    let mut done = 0usize;
    while done < output.len() {
        if position >= attribute.report.initialized_size {
            output[done..].fill(0);
            break;
        }
        let extent = attribute
            .report
            .extents
            .iter()
            .find(|e| {
                e.logical_offset <= position
                    && e.logical_offset
                        .checked_add(e.length)
                        .is_some_and(|end| position < end)
            })
            .context("attribute run-list coverage gap")?;
        let in_run = position - extent.logical_offset;
        let available = (extent.length - in_run).min(attribute.report.initialized_size - position);
        let count = available.min((output.len() - done) as u64) as usize;
        ensure!(count > 0, "zero-progress attribute read");
        if let Some(physical) = extent.physical_offset {
            let physical = physical
                .checked_add(in_run)
                .context("physical read overflow")?;
            read_at(
                reader,
                physical,
                &mut output[done..done + count],
                geometry.volume_size,
            )?;
            // Mint only after this exact output slice was read successfully.
            // The transformation/synthesis branches above never reach here.
            if let Some(receipt) = receipt.as_deref_mut() {
                receipt.record(done, physical, count);
            }
        } else {
            output[done..done + count].fill(0);
        }
        done += count;
        position += count as u64;
    }
    Ok(())
}

fn read_small_attribute<R: Read + Seek>(
    reader: &mut R,
    attr: &Attribute,
    geometry: &NtfsGeometry,
    cap: u64,
) -> Result<Vec<u8>> {
    ensure!(
        attr.report.logical_size <= cap,
        "metadata exceeds inspection memory limit"
    );
    let mut value = vec![0; attr.report.logical_size as usize];
    read_attribute_range(reader, attr, 0, &mut value, geometry)?;
    Ok(value)
}

fn capture_extended_attributes<R: Read + Seek>(
    reader: &mut R,
    record: &Record,
    geometry: &NtfsGeometry,
) -> Result<crate::ntfs_extended_attributes::Inventory> {
    use crate::ntfs_extended_attributes::{Inventory, MAX_DATA_BYTES, storage_attributes};
    let Some((information, data)) =
        storage_attributes(record.attributes.iter().map(|attribute| &attribute.report))?
    else {
        return Ok(Inventory::empty());
    };
    ensure!(
        record.base == 0
            && !record
                .attributes
                .iter()
                .any(|attribute| attribute.report.type_code == 0x20),
        "EA attribute-list assembly is unsupported"
    );
    // The generic replay validator has no geometry. Validate every original
    // physical run here as well, including allocation beyond the logical EOF.
    if !data.resident {
        validate_stream_mapping(data, geometry)
            .context("validating complete EA storage mapping")?;
    }
    let information_attribute = record
        .attributes
        .iter()
        .find(|attribute| attribute.report.type_code == 0xd0)
        .context("EA_INFORMATION disappeared during capture")?;
    let data_attribute = record
        .attributes
        .iter()
        .find(|attribute| attribute.report.type_code == 0xe0)
        .context("EA disappeared during capture")?;
    let information_bytes = read_small_attribute(reader, information_attribute, geometry, 8)?;
    let data_bytes = read_small_attribute(reader, data_attribute, geometry, MAX_DATA_BYTES)?;
    Inventory::capture(information, data, &information_bytes, &data_bytes)
}

fn capture_reparse<R: Read + Seek>(
    reader: &mut R,
    record: &Record,
    geometry: &NtfsGeometry,
) -> Result<Option<n2r_win32::reparse_layout::Point>> {
    let Some(attribute) = crate::ntfs_reparse::storage_attribute(
        record.attributes.iter().map(|attribute| &attribute.report),
    )?
    else {
        return Ok(None);
    };
    ensure!(
        record.base == 0
            && !record
                .attributes
                .iter()
                .any(|attribute| attribute.report.type_code == 0x20),
        "reparse attribute-list assembly is unsupported"
    );
    if !attribute.resident {
        validate_stream_mapping(attribute, geometry)
            .context("validating complete reparse storage mapping")?;
    }
    let actual = record
        .attributes
        .iter()
        .find(|attribute| attribute.report.type_code == 0xc0)
        .context("reparse attribute disappeared during capture")?;
    let buffer = read_small_attribute(
        reader,
        actual,
        geometry,
        crate::ntfs_reparse::MAX_REPARSE_BYTES,
    )?;
    let point = n2r_win32::reparse_layout::Point { buffer };
    point.validate()?;
    ensure!(
        point.tag() != 0xa000_0003 || record.flags & 2 != 0,
        "a mount-point reparse attribute requires a directory"
    );
    Ok(Some(point))
}

/// Reuse the checked parser for additional read-only source-state checks.
pub(crate) fn validate_file_record(bytes: &[u8], geometry: &NtfsGeometry) -> Result<()> {
    parse_record(bytes.to_vec(), geometry)?;
    Ok(())
}

/// Recognize only the inactive, nameless format template observed in the
/// allocated tail of a larger-cluster $MFTMirr. This is not a live backup.
pub(crate) fn inactive_mirror_template(
    bytes: &[u8],
    geometry: &NtfsGeometry,
    slot: u32,
) -> Result<bool> {
    let record = parse_record(bytes.to_vec(), geometry)?;
    if record.flags != 0
        || record.links != 0
        || record.base != 0
        || u64le(bytes, 8)? != 0
        || u32le(bytes, 44)? != slot
        || record.attributes.len() != 3
    {
        return Ok(false);
    }
    let kinds: Vec<_> = record
        .attributes
        .iter()
        .map(|a| a.report.type_code)
        .collect();
    if kinds != [0x10, 0x50, 0x80]
        || record.attributes.iter().any(|a| {
            !a.report.resident
                || a.report.flags != 0
                || !a.report.name_utf16.is_empty()
                || a.report.lowest_vcn != 0
                || a.report.compression_unit != 0
        })
    {
        return Ok(false);
    }
    let standard = record.attributes[0]
        .resident_value
        .as_deref()
        .context("missing template standard information")?;
    let security = record.attributes[1]
        .resident_value
        .as_deref()
        .context("missing template security")?;
    let data = record.attributes[2]
        .resident_value
        .as_deref()
        .context("missing template data")?;
    if standard.len() != 48
        || !data.is_empty()
        || u32le(standard, 32)? != 6
        || standard[36..].iter().any(|byte| *byte != 0)
    {
        return Ok(false);
    }
    let time = u64le(standard, 0)?;
    if time == 0
        || time >= i64::MAX as u64
        || (1..4).any(|i| u64le(standard, i * 8).ok() != Some(time))
    {
        return Ok(false);
    }
    crate::ntfs_security::parse_descriptor(security)?;
    Ok(true)
}

/// Reread a bounded resident attribute from its actual MFT record, including
/// its extension-record origin when assembled. Inventory hashes alone are not
/// a substitute for the bytes being interpreted.
pub(crate) fn read_resident_inventory_attribute<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    file: &FileInventory,
    attribute: &AttributeInventory,
) -> Result<Vec<u8>> {
    ensure!(
        attribute.resident && attribute.logical_size <= 4096,
        "bounded resident source attribute required"
    );
    let bootstrap = mft_bootstrap::read(reader, &raw.geometry)?;
    bootstrap.verify_inventory(raw)?;
    let mut bytes = vec![0; raw.geometry.file_record_size as usize];
    let offset = file
        .record_number
        .checked_mul(u64::from(raw.geometry.file_record_size))
        .context("MFT source record offset overflow")?;
    read_nonresident_inventory_range(
        reader,
        &bootstrap.data.report,
        offset,
        &mut bytes,
        &raw.geometry,
    )?;
    let mut record = parse_record(bytes.clone(), &raw.geometry)?;
    ensure!(
        record.sequence == file.sequence_number
            && record.base == file.base_file_reference
            && record.flags & 1 != 0
            && (record.flags & 2 != 0) == file.is_directory,
        "reread MFT record identity differs"
    );
    if let Some(expected) = raw.attribute_assemblies.iter().find(|assembly| {
        assembly.base.record_number == file.record_number
            && matches!(assembly.schema_version, 1 | 2 | 5 | 6)
    }) {
        validate_record_coverage(raw)?;
        let context = assembled_io::MftContext {
            data: &bootstrap.data,
            bitmap: &bootstrap.bitmap,
            geometry: &raw.geometry,
            record_count: bootstrap.record_count,
        };
        let actual = context
            .resolve(reader, file.record_number, &bytes, &mut record)?
            .context("resident attribute assembly is no longer present")?;
        ensure!(
            &actual == expected,
            "resident attribute physical assembly changed"
        );
    }
    let mut found = record
        .attributes
        .into_iter()
        .filter(|a| a.report.instance == attribute.instance);
    let found_attribute = found
        .next()
        .context("reread resident attribute differs from inventory")?;
    ensure!(
        found.next().is_none() && found_attribute.report == *attribute,
        "reread resident attribute differs from inventory"
    );
    found_attribute
        .resident_value
        .context("resident attribute bytes absent")
}

/// Source-state checks must bind an assembled MFT through actual bootstrap and
/// bitmap reads before trusting its canonical inventory mapping.
pub(crate) fn revalidate_mft_mapping<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
) -> Result<()> {
    mft_bootstrap::read(reader, &raw.geometry)?.verify_inventory(raw)
}
pub(crate) fn read_nonresident_inventory_range<R: Read + Seek>(
    reader: &mut R,
    attribute: &AttributeInventory,
    offset: u64,
    output: &mut [u8],
    geometry: &NtfsGeometry,
) -> Result<()> {
    ensure!(
        !attribute.resident && attribute.flags == 0 && attribute.compression_unit == 0,
        "source-state attribute must be plain nonresident storage"
    );
    validate_stream_mapping(attribute, geometry)?;
    ensure!(
        attribute
            .extents
            .iter()
            .all(|e| e.physical_offset.is_some())
            && offset
                .checked_add(output.len() as u64)
                .is_some_and(|end| end <= attribute.initialized_size),
        "source-state attribute has holes or uninitialized bytes"
    );
    read_attribute_range(
        reader,
        &Attribute {
            report: attribute.clone(),
            resident_value: None,
        },
        offset,
        output,
        geometry,
    )
}

/// Validate the entire standalone mapping, including allocation past EOF and the
/// uninitialized tail. Zero filling must never conceal missing mapping pairs.
pub(crate) fn validate_stream_mapping(
    a: &AttributeInventory,
    geometry: &NtfsGeometry,
) -> Result<()> {
    if a.flags & 0x00ff != 0 {
        return crate::ntfs_compression::supported(a, geometry);
    }
    ensure!(
        a.lowest_vcn == 0,
        "standalone DATA mapping must start at VCN zero"
    );
    ensure!(
        a.initialized_size <= a.logical_size,
        "initialized size exceeds logical size"
    );
    let cluster_size = u64::from(geometry.cluster_size);
    ensure!(
        a.allocated_size.is_multiple_of(cluster_size),
        "DATA allocated size is not cluster aligned"
    );
    let mut coverage = 0u64;
    let mut physical_bytes = 0u64;
    let mut physical_ranges = Vec::new();
    for extent in &a.extents {
        ensure!(
            extent.logical_offset == coverage,
            "DATA mapping has a logical gap or overlap"
        );
        ensure!(
            extent.length > 0 && extent.length.is_multiple_of(cluster_size),
            "invalid DATA extent length"
        );
        coverage = coverage
            .checked_add(extent.length)
            .context("DATA mapping coverage overflow")?;
        if let Some(start) = extent.physical_offset {
            ensure!(
                start.is_multiple_of(cluster_size),
                "DATA physical extent is not cluster aligned"
            );
            let end = start
                .checked_add(extent.length)
                .context("DATA physical extent overflow")?;
            ensure!(
                end <= geometry.volume_size,
                "DATA extent exceeds partition boundary"
            );
            physical_bytes = physical_bytes
                .checked_add(extent.length)
                .context("DATA physical allocation overflow")?;
            physical_ranges.push((start, end));
        } else {
            ensure!(
                a.flags & 0x8000 != 0,
                "sparse DATA run lacks the sparse attribute flag"
            );
        }
    }
    ensure!(
        coverage >= a.logical_size,
        "DATA mapping has a coverage gap before logical EOF"
    );
    if a.flags & 0x8000 == 0 {
        ensure!(
            a.allocated_size == coverage,
            "DATA allocated size differs from mapped coverage"
        );
    } else {
        // Sparse logical coverage and physical allocation are different quantities.
        // Retain the raw allocation field; allocation ownership remains unverified.
        ensure!(
            physical_bytes <= a.allocated_size && a.allocated_size <= coverage,
            "sparse DATA allocated size is inconsistent with mapped coverage"
        );
    }
    physical_ranges.sort_unstable();
    ensure!(
        physical_ranges
            .windows(2)
            .all(|pair| pair[0].1 <= pair[1].0),
        "DATA mapping contains overlapping physical extents"
    );
    Ok(())
}

/// Metadata-only classification shared with the preparation inspector. It
/// performs no DATA reads and must not be treated as logical-content evidence.
fn logical_hash_metadata_status(
    a: &AttributeInventory,
    geometry: &NtfsGeometry,
    has_attribute_list: bool,
    extension_record: bool,
    record_number: u64,
) -> Option<LogicalHashStatus> {
    if has_attribute_list || a.lowest_vcn != 0 {
        Some(LogicalHashStatus::UnsupportedAttributeList)
    } else if extension_record {
        Some(LogicalHashStatus::UnsupportedExtensionRecord)
    } else if record_number == 8
        && a.name_utf16 == [0x24, 0x42, 0x61, 0x64]
        && a.flags == 0
        && a.extents
            .iter()
            .any(|extent| extent.physical_offset.is_none())
    {
        // mkntfs constructs $BadClus:$Bad using sparse mapping pairs and zero
        // attribute flags. Preserve this system metadata without treating it as
        // ordinary logical DATA or weakening the ordinary sparse-run check.
        // https://github.com/tuxera/ntfs-3g/blob/edge/ntfsprogs/mkntfs.c
        Some(LogicalHashStatus::UnsupportedBadClusterMetadata)
    } else if a.flags & 0x00ff != 0 && crate::ntfs_compression::supported(a, geometry).is_err() {
        Some(LogicalHashStatus::UnsupportedCompression)
    } else if a.flags & 0x4000 != 0 {
        Some(LogicalHashStatus::UnsupportedEncryption)
    } else if a.flags & !0xc0ff != 0
        || (a.resident && a.flags != 0 && crate::ntfs_compression::supported(a, geometry).is_err())
    {
        Some(LogicalHashStatus::UnsupportedFlags)
    } else if a.compression_unit != 0
        && !((a.flags & 0x8000 != 0 || a.flags == 1) && a.compression_unit == 4)
    {
        // Native sparse attributes can carry unit 4 without compression. The
        // compression method flags, not the unit alone, distinguish that case.
        Some(LogicalHashStatus::UnsupportedCompressionUnit)
    } else {
        None
    }
}

fn hash_stream<R: Read + Seek>(
    reader: &mut R,
    attribute: &Attribute,
    geometry: &NtfsGeometry,
    budget: &mut HashBudget,
    has_attribute_list: bool,
    extension_record: bool,
    record_number: u64,
) -> Result<(LogicalHashStatus, Option<String>)> {
    let a = &attribute.report;
    if let Some(status) = logical_hash_metadata_status(
        a,
        geometry,
        has_attribute_list,
        extension_record,
        record_number,
    ) {
        return Ok((status, None));
    }
    if let Some(value) = &attribute.resident_value {
        ensure!(
            a.logical_size == value.len() as u64 && a.initialized_size == a.logical_size,
            "resident DATA size is inconsistent"
        );
        budget.reserve(a.logical_size)?;
        return Ok((LogicalHashStatus::Complete, a.resident_sha256.clone()));
    }
    validate_stream_mapping(a, geometry)?;
    // Reserve all work before the first DATA read, including CPU work hashing
    // zeros. No partial digest or partial report is returned on exhaustion.
    budget.reserve(a.logical_size)?;
    if let Some(mut compression) = compression_reader(attribute, geometry)? {
        let mut hasher = n2r_win32::content_digest::Hasher::new();
        let mut buffer = [0u8; STREAM_HASH_BUFFER_BYTES];
        let mut offset = 0u64;
        while offset < a.logical_size {
            let count = (a.logical_size - offset).min(buffer.len() as u64) as usize;
            compression.read_range(reader, offset, &mut buffer[..count])?;
            hasher.update(&buffer[..count]);
            offset += count as u64;
        }
        return Ok((LogicalHashStatus::Complete, Some(hasher.finish())));
    }
    // Streams over 4 MiB are read in 4 MiB requests; smaller streams keep the
    // fixed 64 KiB buffer. The result is the stream's content digest.
    let large = a.logical_size > LARGE_STREAM_HASH_BYTES as u64;
    let mut hasher = n2r_win32::content_digest::Hasher::new();
    let mut small = [0u8; STREAM_HASH_BUFFER_BYTES];
    let mut large_buffer = if large {
        vec![0u8; LARGE_STREAM_HASH_BYTES]
    } else {
        Vec::new()
    };
    let buffer: &mut [u8] = if large { &mut large_buffer } else { &mut small };
    for extent in &a.extents {
        if extent.logical_offset >= a.logical_size {
            break;
        }
        let length = extent.length.min(a.logical_size - extent.logical_offset);
        let initialized = a
            .initialized_size
            .saturating_sub(extent.logical_offset)
            .min(length);
        let mut done = 0u64;
        while done < length {
            let physical = extent.physical_offset.filter(|_| done < initialized);
            let remaining = if physical.is_some() {
                initialized - done
            } else {
                length - done
            };
            let count = remaining.min(buffer.len() as u64) as usize;
            if let Some(start) = physical {
                read_at(
                    reader,
                    start
                        .checked_add(done)
                        .context("DATA read position overflow")?,
                    &mut buffer[..count],
                    geometry.volume_size,
                )?;
            } else {
                buffer[..count].fill(0);
            }
            hasher.update(&buffer[..count]);
            done += count as u64;
        }
    }
    Ok((LogicalHashStatus::Complete, Some(hasher.finish())))
}

fn blocker(
    report: &mut NtfsInspection,
    budget: &mut ReportBudget,
    code: &str,
    message: impl Into<String>,
    record: Option<u64>,
) -> Result<()> {
    let item = InspectionBlocker {
        code: code.into(),
        message: message.into(),
        file_record_number: record,
    };
    let heap_bytes = (item.code.capacity() as u64)
        .checked_add(item.message.capacity() as u64)
        .context("blocker memory accounting overflow")?;
    budget.push(&mut report.blockers, item, heap_bytes)
}

fn file_heap_bytes(file: &FileInventory) -> Result<u64> {
    let mut counter = ReportBudget {
        limit: u64::MAX,
        used: 0,
    };
    counter.charge((file.names.capacity() * std::mem::size_of::<NameInventory>()) as u64)?;
    counter.charge((file.streams.capacity() * std::mem::size_of::<StreamInventory>()) as u64)?;
    counter
        .charge((file.attributes.capacity() * std::mem::size_of::<AttributeInventory>()) as u64)?;
    for name in &file.names {
        counter.charge(name.name.capacity() as u64)?;
        counter.charge((name.name_utf16.capacity() * 2) as u64)?;
    }
    for stream in &file.streams {
        counter.charge(stream.name.capacity() as u64)?;
        counter.charge((stream.name_utf16.capacity() * 2) as u64)?;
        counter.charge((stream.extents.capacity() * std::mem::size_of::<Extent>()) as u64)?;
        if let Some(hash) = &stream.resident_sha256 {
            counter.charge(hash.capacity() as u64)?;
        }
        if let Some(hash) = &stream.logical_sha256 {
            counter.charge(hash.capacity() as u64)?;
        }
    }
    for attribute in &file.attributes {
        counter.charge((attribute.name_utf16.capacity() * 2) as u64)?;
        counter.charge((attribute.extents.capacity() * std::mem::size_of::<Extent>()) as u64)?;
        if let Some(hash) = &attribute.resident_sha256 {
            counter.charge(hash.capacity() as u64)?;
        }
        if let Some(data) = &attribute.resident_metadata_hex {
            counter.charge(data.capacity() as u64)?;
        }
    }
    if let Some(attributes) = &file.extended_attributes {
        counter.charge(attributes.heap_bytes()?)?;
    }
    if let Some(point) = &file.reparse {
        counter.charge(point.buffer.capacity() as u64)?;
    }
    Ok(counter.used)
}

const MAX_METADATA_ANCESTRY_DEPTH: usize = 4096;

#[derive(Clone, Copy)]
enum AncestryState {
    Unseen,
    Visiting,
    OutsideExtend,
    WithinExtend,
    Unresolved(MetadataRoleIssue),
}

struct AncestryFrame {
    file_index: usize,
    next_name: usize,
    /// Bit 0 = a path to the root outside $Extend; bit 1 = a path via $Extend.
    ancestry_mask: u8,
}

fn find_record(files: &[FileInventory], number: u64) -> Option<usize> {
    files
        .binary_search_by_key(&number, |file| file.record_number)
        .ok()
}

fn has_attribute_list(file: &FileInventory) -> bool {
    file.attributes.iter().any(|a| a.type_code == 0x20)
}

fn valid_role_anchor(file: &FileInventory, name: &[u16], root_sequence: u16) -> bool {
    file.is_directory
        && file.base_file_reference == 0
        && file.sequence_number != 0
        && !has_attribute_list(file)
        && file.hard_link_count == 1
        && file.names.len() == 1
        && file.names[0].namespace != 2
        && file.names[0].name_utf16 == name
        && file.names[0].parent_record_number == 5
        && file.names[0].parent_sequence_number == root_sequence
}

fn local_ancestry_issue(file: &FileInventory) -> Option<MetadataRoleIssue> {
    use MetadataRoleIssue as Issue;
    if file.base_file_reference != 0 {
        Some(Issue::ExtensionRecord)
    } else if has_attribute_list(file) {
        Some(Issue::AttributeListUnassembled)
    } else if file.sequence_number == 0 {
        Some(Issue::ZeroSequenceNumber)
    } else if file.names.is_empty() {
        Some(Issue::MissingNames)
    } else if file.hard_link_count == 0
        || usize::from(file.hard_link_count) != file.names.len()
    {
        // The physical NTFS header counts FILE_NAME attributes, including DOS
        // aliases. Native Windows link counts exclude those aliases. Neither
        // interpretation substitutes for complete I30/name reconciliation.
        Some(Issue::LinkCountMismatch)
    } else if file.names.iter().any(|name| {
        name.name_utf16.is_empty()
            || name.name_utf16 == [u16::from(b'.')]
            || name.name_utf16 == [u16::from(b'.'), u16::from(b'.')]
    }) {
        Some(Issue::InvalidName)
    } else {
        None
    }
}

/// Classify only already-inventoried MFT references; this performs no image I/O
/// and never follows a reparse target. Scratch storage is bounded by the MFT
/// record limit plus at most 4096 explicit traversal frames (no recursion).
fn classify_metadata_roles(report: &mut NtfsInspection, budget: &mut ReportBudget) -> Result<()> {
    use AncestryState as State;
    use MetadataRoleIssue as Issue;
    let files = &report.files;
    ensure!(
        files.len() as u64 <= MAX_MFT_RECORDS
            && files
                .windows(2)
                .all(|pair| pair[0].record_number < pair[1].record_number),
        "metadata role classification requires unique sorted bounded records"
    );
    let mut states = Vec::new();
    states
        .try_reserve_exact(files.len())
        .context("allocating bounded metadata ancestry state")?;
    states.resize(files.len(), State::Unseen);
    let mut stack: Vec<AncestryFrame> = Vec::new();
    stack
        .try_reserve_exact(files.len().min(MAX_METADATA_ANCESTRY_DEPTH))
        .context("allocating bounded metadata ancestry stack")?;
    let root = find_record(files, 5);
    let root_valid = root.is_some_and(|i| {
        valid_role_anchor(&files[i], &[u16::from(b'.')], files[i].sequence_number)
    });
    for (i, file) in files.iter().enumerate() {
        if file.record_number < 16 {
            states[i] = match file.record_number {
                5 if root_valid => State::OutsideExtend,
                5 => State::Unresolved(Issue::InvalidRootAnchor),
                11 if root_valid
                    && valid_role_anchor(
                        file,
                        &[36, 69, 120, 116, 101, 110, 100], // exact UTF-16 $Extend
                        files[root.expect("validated root exists")].sequence_number,
                    ) =>
                {
                    State::WithinExtend
                }
                11 => State::Unresolved(Issue::InvalidExtendAnchor),
                _ => State::Unresolved(Issue::UnsupportedReservedParent),
            };
        } else if let Some(issue) = local_ancestry_issue(file) {
            states[i] = State::Unresolved(issue);
        }
    }
    for start in 0..files.len() {
        if !matches!(states[start], State::Unseen) {
            continue;
        }
        states[start] = State::Visiting;
        stack.push(AncestryFrame {
            file_index: start,
            next_name: 0,
            ancestry_mask: 0,
        });
        while let Some(frame) = stack.last_mut() {
            let current = frame.file_index;
            let file = &files[current];
            if frame.next_name == file.names.len() {
                states[current] = match frame.ancestry_mask {
                    1 => State::OutsideExtend,
                    2 => State::WithinExtend,
                    3 => State::Unresolved(Issue::MixedAncestry),
                    _ => State::Unresolved(Issue::MissingNames),
                };
                stack.pop();
                continue;
            }
            // All names participate, including DOS aliases. An alias must not
            // silently hide a conflicting or stale parent reference.
            let name = &file.names[frame.next_name];
            let parent = find_record(files, name.parent_record_number);
            let issue = match parent {
                None => Some(Issue::MissingParent),
                Some(i) if files[i].sequence_number != name.parent_sequence_number => {
                    Some(Issue::ParentSequenceMismatch)
                }
                Some(i) if !files[i].is_directory => Some(Issue::ParentNotDirectory),
                _ => None,
            };
            if let Some(issue) = issue {
                states[current] = State::Unresolved(issue);
                stack.pop();
                continue;
            }
            let parent = parent.expect("checked parent exists");
            match states[parent] {
                State::OutsideExtend | State::WithinExtend => {
                    frame.ancestry_mask |= if matches!(states[parent], State::WithinExtend) {
                        2
                    } else {
                        1
                    };
                    frame.next_name += 1;
                }
                State::Unresolved(_) => {
                    states[current] = State::Unresolved(Issue::AncestorUnresolved);
                    stack.pop();
                }
                State::Visiting => {
                    states[current] = State::Unresolved(Issue::Cycle);
                    stack.pop();
                }
                State::Unseen => {
                    if stack.len() == MAX_METADATA_ANCESTRY_DEPTH {
                        states[current] = State::Unresolved(Issue::DepthLimit);
                        stack.pop();
                    } else {
                        states[parent] = State::Visiting;
                        stack.push(AncestryFrame {
                            file_index: parent,
                            next_name: 0,
                            ancestry_mask: 0,
                        });
                    }
                }
            }
        }
    }
    for (index, state) in states.into_iter().enumerate() {
        let file = &mut report.files[index];
        let issue = if file.record_number < 16 {
            file.metadata_role = MetadataRole::ReservedSystemRecord;
            match (file.record_number, state) {
                (5 | 11, State::Unresolved(issue)) => Some(issue),
                _ => None,
            }
        } else {
            file.metadata_role = match state {
                State::OutsideExtend => MetadataRole::OutsideExtendCandidate,
                State::WithinExtend => MetadataRole::ExtendDescendantCandidate,
                _ => MetadataRole::Unresolved,
            };
            match state {
                State::Unresolved(issue) => Some(issue),
                State::Unseen | State::Visiting => {
                    anyhow::bail!("incomplete metadata ancestry traversal")
                }
                _ => None,
            }
        };
        file.metadata_role_issue = issue;
        file.is_metadata = matches!(
            file.metadata_role,
            MetadataRole::ReservedSystemRecord | MetadataRole::ExtendDescendantCandidate
        );
        let number = file.record_number;
        if let Some(issue) = issue {
            blocker(
                report,
                budget,
                "metadata_role_ancestry_unresolved",
                format!("MFT metadata role has unresolved ancestry: {issue:?}"),
                Some(number),
            )?;
        }
    }
    Ok(())
}

fn reconcile_allocation<R: Read + Seek>(
    report: &NtfsInspection,
    bitmap: &mut R,
    original: &ntfs_allocation::BitmapSummary,
) -> Result<AllocationReconciliation> {
    let mut result = AllocationReconciliation {
        status: AllocationReconciliationStatus::Rejected,
        bitmap_sha256: original.sha256.clone(),
        domain_clusters: report.geometry.total_clusters,
        physical_intervals: 0,
        detail: String::new(),
    };
    for file in &report.files {
        if file.base_file_reference != 0
            || file
                .attributes
                .iter()
                .any(|a| a.type_code == 0x20 || a.lowest_vcn != 0)
        {
            result.status = AllocationReconciliationStatus::IncompleteAttributeInventory;
            result.detail = format!(
                "MFT record {} needs attribute-list/extension assembly; no partial allocation model assessed",
                file.record_number
            );
            return Ok(result);
        }
        if file.attributes.iter().enumerate().any(|(index, a)| {
            file.attributes[..index]
                .iter()
                .any(|b| b.instance == a.instance)
        }) {
            result.status = AllocationReconciliationStatus::IncompleteAttributeInventory;
            result.detail = format!(
                "MFT record {} repeats an attribute instance; ownership identity is ambiguous",
                file.record_number
            );
            return Ok(result);
        }
    }
    // Bitmap storage is streamed, so its logical size does not determine the
    // working-buffer allocation. Interval/name/sorting budgets stay separate.
    let limits = Limits {
        max_bitmap_bytes: usize::try_from(original.bitmap_bytes)
            .context("bitmap exceeds stream addressability")?,
        max_cluster_checks: report.geometry.total_clusters,
        ..Limits::default()
    };
    let cluster = u64::from(report.geometry.cluster_size);
    let mut intervals = Vec::new();
    let mut name_units = 0usize;
    // Canonical DATA is claimed once. An assembled nonresident list is not a
    // user stream, but its original metadata storage still needs its own owner.
    let canonical = report.files.iter().flat_map(|file| {
        file.attributes
            .iter()
            .map(move |attribute| (file.record_number, file.sequence_number, attribute))
    });
    let list_storage = report.attribute_assemblies.iter().filter_map(|assembly| {
        assembly
            .base
            .attributes
            .iter()
            .find(|a| a.type_code == 0x20 && !a.resident)
            .map(|attribute| {
                (
                    assembly.base.record_number,
                    assembly.base.sequence_number,
                    attribute,
                )
            })
    });
    for (record_number, sequence_number, attribute) in canonical.chain(list_storage) {
        if attribute.resident {
            continue; // Already contained in the MFT's allocation.
        }
        for extent in &attribute.extents {
            let Some(physical) = extent.physical_offset else {
                continue; // Sparse holes have no physical owner.
            };
            if intervals.len() >= limits.max_intervals {
                result.detail = "Allocation interval budget exceeded".into();
                return Ok(result);
            }
            name_units = match name_units.checked_add(attribute.name_utf16.len()) {
                Some(total) if total <= limits.max_total_name_units => total,
                _ => {
                    result.detail = "Allocation attribute-name budget exceeded".into();
                    return Ok(result);
                }
            };
            if !extent.logical_offset.is_multiple_of(cluster)
                || !physical.is_multiple_of(cluster)
                || extent.length == 0
                || !extent.length.is_multiple_of(cluster)
            {
                result.detail = "Attribute extent is not a nonempty cluster interval".into();
                return Ok(result);
            }
            if intervals.try_reserve(1).is_err() {
                result.detail = "Allocation interval storage unavailable".into();
                return Ok(result);
            }
            let mut name = Vec::new();
            if name.try_reserve_exact(attribute.name_utf16.len()).is_err() {
                result.detail = "Allocation attribute-name storage unavailable".into();
                return Ok(result);
            }
            name.extend_from_slice(&attribute.name_utf16);
            intervals.push(PhysicalInterval {
                owner: AttributeKey {
                    record_number,
                    sequence_number,
                    type_code: attribute.type_code,
                    name_utf16: name,
                    instance: attribute.instance,
                },
                vcn_start: extent.logical_offset / cluster,
                lcn_start: physical / cluster,
                clusters: extent.length / cluster,
            });
        }
    }
    result.physical_intervals = intervals.len();
    let (assessment, current) =
        ntfs_allocation::assess_stream(result.domain_clusters, bitmap, &intervals, limits)?;
    ensure!(
        current == *original,
        "volume bitmap changed during allocation reconciliation"
    );
    match assessment {
        Assessment::Consistent(summary) => {
            result.status = AllocationReconciliationStatus::ConsistentRawModel;
            result.detail = format!(
                "{} allocated clusters in {} attributes reconcile; native and semantic source admission remains unverified",
                summary.allocated_clusters, summary.distinct_attributes
            );
        }
        Assessment::Rejected(reason) => result.detail = format!("{reason:?}"),
    }
    Ok(result)
}

/// A bounded logical view of the initialized volume bitmap, backed by its runs.
struct AttributeBitmapReader<'a, R> {
    reader: &'a mut R,
    attribute: &'a Attribute,
    geometry: &'a NtfsGeometry,
    length: u64,
    position: u64,
}

impl<R: Read + Seek> Read for AttributeBitmapReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = (self.length - self.position).min(output.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        read_attribute_range(
            self.reader,
            self.attribute,
            self.position,
            &mut output[..count],
            self.geometry,
        )
        .map_err(io::Error::other)?;
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: Read + Seek> Seek for AttributeBitmapReader<'_, R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        if position < 0 || position > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bitmap seek escapes logical domain",
            ));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

fn require_bitmap_bytes(attribute: &AttributeInventory, needed: u64) -> Result<()> {
    ensure!(
        attribute.flags == 0
            && attribute.lowest_vcn == 0
            && attribute.initialized_size >= needed
            && attribute.logical_size >= needed
            && attribute
                .extents
                .iter()
                .all(|extent| extent.physical_offset.is_some()),
        "allocation bitmap must have initialized, unencoded, nonsparse bytes for the entire requested domain"
    );
    Ok(())
}

/// NTFS stores the directory compression policy on its resident $I30 root.
/// These bytes are still an ordinary index, never compressed payload. Bind the
/// marker to the directory's stored SI policy before parsing the full index.
fn directory_compression_root_policy(record: &Record, attribute: &Attribute) -> bool {
    let a = &attribute.report;
    if record.flags & 2 == 0
        || a.type_code != 0x90
        || !crate::ntfs_namespace::is_i30(&a.name_utf16)
        || !a.resident
        || a.flags != 1
        || a.compression_unit != 0
        || a.lowest_vcn != 0
        || a.total_allocated_size.is_some()
        || !a.extents.is_empty()
        || a.initialized_size != a.logical_size
        || a.allocated_size != a.logical_size
        || attribute
            .resident_value
            .as_ref()
            .is_none_or(|v| v.len() as u64 != a.logical_size)
    {
        return false;
    }
    let mut standard = record
        .attributes
        .iter()
        .filter(|a| a.report.type_code == 0x10);
    let Some(si) = standard.next() else {
        return false;
    };
    standard.next().is_none()
        && si.report.resident
        && si.report.flags == 0
        && si.report.name_utf16.is_empty()
        && si.resident_value.as_deref().is_some_and(|v| {
            v.len() >= 48 && u32le(v, 32).is_ok_and(|flags| flags & 0x4800 == 0x800)
        })
}

/// Inspect a raw NTFS partition without issuing writes. The report remains blocked
/// until every semantic coverage requirement has a validated implementation.
pub fn inspect<R: Read + Seek>(reader: &mut R, length: u64) -> Result<NtfsInspection> {
    inspect_with_limits(reader, length, InspectionLimits::default())
}

/// Re-read boot/MFT identity and the current attribute before any stream copy.
fn checked_plain_attribute<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    max_bytes: u64,
    alpha_limit: bool,
) -> Result<(Attribute, Option<String>)> {
    checked_data_attribute(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        max_bytes,
        alpha_limit,
        false,
    )
}

/// Shared metadata/identity checks. LZNT1 DATA is decoded into logical bytes;
/// sparse support remains explicit and neither path grants source admission.
fn checked_data_attribute<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    max_bytes: u64,
    alpha_limit: bool,
    allow_sparse: bool,
) -> Result<(Attribute, Option<String>)> {
    if !raw.attribute_assemblies.is_empty() {
        validate_record_coverage(raw)?;
    }
    let file = raw
        .files
        .iter()
        .find(|f| f.record_number == record_number)
        .context("source file missing from inventory")?;
    ensure!(
        !file.is_directory && file.base_file_reference == 0,
        "plain standalone file required"
    );
    let stream = file
        .streams
        .iter()
        .find(|s| s.name_utf16 == stream_name_utf16)
        .context("requested DATA stream absent")?;
    let mut inventoried = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x80 && a.name_utf16 == stream_name_utf16);
    let expected = inventoried.next().context("source DATA inventory absent")?;
    ensure!(inventoried.next().is_none(), "duplicate DATA inventory");
    let compressed =
        stream.flags == 1 && crate::ntfs_compression::supported(expected, &raw.geometry).is_ok();
    ensure!(
        (stream.flags == 0 || (allow_sparse && stream.flags == 0x8000) || compressed)
            && crate::ntfs_attestation::source_stream_evidence_valid(raw, file, stream)?
            && stream.logical_size <= max_bytes
            && (!alpha_limit || max_bytes <= ALPHA_MAX_PLAIN_BYTES),
        "unsupported stream or materialization budget"
    );
    let geometry = &raw.geometry;
    let mut boot = [0; 512];
    read_at(reader, 0, &mut boot, geometry.volume_size)?;
    ensure!(
        inspect_boot_sector(&boot, geometry.volume_size)? == *geometry,
        "source geometry changed"
    );
    let bootstrap = mft_bootstrap::read(reader, geometry)?;
    bootstrap.verify_inventory(raw)?;
    let mft = &bootstrap.data;
    let mut bytes = vec![0; geometry.file_record_size as usize];
    read_attribute_range(
        reader,
        mft,
        record_number
            .checked_mul(u64::from(geometry.file_record_size))
            .context("MFT record offset overflow")?,
        &mut bytes,
        geometry,
    )?;
    let mut record = parse_record(bytes.clone(), geometry)?;
    if record_number == 0
        && let Some(assembly) = &bootstrap.assembly
    {
        ensure!(
            assembly.base.raw_record_sha256 == hex::encode(Sha256::digest(&bytes)),
            "MFT base changed while rereading its DATA"
        );
        record.attributes = bootstrap.record.attributes.clone();
    }
    if let Some(expected) = raw.attribute_assemblies.iter().find(|a| {
        a.base.record_number == record_number && matches!(a.schema_version, 1 | 2 | 5 | 6)
    }) {
        let context = assembled_io::MftContext {
            data: mft,
            bitmap: &bootstrap.bitmap,
            geometry,
            record_count: bootstrap.record_count,
        };
        let actual = context
            .resolve(reader, record_number, &bytes, &mut record)?
            .context("inspected DATA assembly is no longer present")?;
        ensure!(
            &actual == expected,
            "source attribute list or physical extension evidence changed"
        );
    }
    ensure!(
        record.flags & 1 != 0
            && record.flags & 2 == 0
            && record.base == 0
            && record.sequence == file.sequence_number
            && record.links == file.hard_link_count
            && !record.attributes.iter().any(|a| a.report.type_code == 0x20),
        "source file identity changed"
    );
    let mut candidates = record
        .attributes
        .into_iter()
        .filter(|a| a.report.type_code == 0x80 && a.report.name_utf16 == stream_name_utf16);
    let data = candidates
        .next()
        .context("requested source DATA attribute absent")?;
    ensure!(
        candidates.next().is_none(),
        "duplicate requested DATA attribute"
    );
    ensure!(
        data.report == *expected
            && ((data.report.flags == 0 && data.report.compression_unit == 0)
                || (allow_sparse
                    && data.report.flags == 0x8000
                    && !data.report.resident
                    && matches!(data.report.compression_unit, 0 | 4))
                || (compressed
                    && crate::ntfs_compression::supported(&data.report, geometry).is_ok()))
            && data.report.logical_size == stream.logical_size,
        "source DATA attribute changed"
    );
    if allow_sparse
        || compressed
        || stream.logical_hash_status == LogicalHashStatus::NotReadExtentIdentityV1
    {
        ensure!(
            stream.flags == data.report.flags
                && stream.resident == data.report.resident
                && stream.initialized_size == data.report.initialized_size
                && stream.allocated_size == data.report.allocated_size
                && stream.extents == data.report.extents,
            "DATA inventory differs from the actual attribute mapping"
        );
    }
    if !data.report.resident {
        validate_stream_mapping(&data.report, geometry)?;
    }
    let digest = stream.logical_sha256.clone();
    match stream.logical_hash_status {
        LogicalHashStatus::Complete => ensure!(
            digest
                .as_deref()
                .is_some_and(n2r_win32::content_digest::is_hex),
            "invalid inspected logical stream hash"
        ),
        LogicalHashStatus::NotReadExtentIdentityV1 => ensure!(
            digest.is_none()
                && crate::ntfs_attestation::extent_identity_stream_request(raw, file, stream)?
                    .is_some(),
            "hash-free range reader requires exact extent-identity evidence"
        ),
        _ => anyhow::bail!("inspected logical stream evidence is incomplete"),
    }
    Ok((data, digest))
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamCopyProof {
    pub record_number: u64,
    pub stream_name_utf16: Vec<u16>,
    pub logical_bytes: u64,
    pub sha256: String,
}

/// Explicit cumulative logical-byte budget for the fixed-buffer streaming
/// APIs below. Every selected logical byte is charged, including holes and
/// uninitialized ranges. Metadata/bootstrap rereads are not charged; physical
/// device I/O and output overhead can differ. This budget is neither a total
/// I/O bound nor admission or conversion authority. A failed transfer still
/// consumes its reservation because partial output may exist.
#[derive(Debug)]
pub struct StreamTransferBudget {
    max_stream_bytes: u64,
    max_total_bytes: u64,
    reserved_bytes: u64,
}

impl StreamTransferBudget {
    pub fn new(max_stream_bytes: u64, max_total_bytes: u64) -> Result<Self> {
        ensure!(
            max_stream_bytes > 0 && max_total_bytes > 0,
            "positive per-stream and cumulative logical-byte budgets required"
        );
        Ok(Self {
            max_stream_bytes,
            max_total_bytes,
            reserved_bytes: 0,
        })
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    fn reserve(&mut self, bytes: u64) -> Result<()> {
        let reserved = self
            .reserved_bytes
            .checked_add(bytes)
            .context("stream transfer accounting overflow")?;
        ensure!(
            reserved <= self.max_total_bytes,
            "cumulative stream transfer budget exceeded"
        );
        self.reserved_bytes = reserved;
        Ok(())
    }
}

/// Stream one bounded plain unnamed DATA attribute through a fixed 64 KiB
/// buffer. Sparse holes and bytes beyond NTFS valid-data length are emitted as
/// zeroes. The caller must discard any partial output if this returns an error;
/// no source or destination write authority is granted by this function.
pub fn copy_plain_stream<R: Read + Seek, W: Write>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    max_bytes: u64,
    output: &mut W,
) -> Result<StreamCopyProof> {
    copy_plain_named_stream(reader, raw, record_number, &[], max_bytes, output)
}

/// Copy one explicitly named (or unnamed) DATA stream. The UTF-16 name must
/// match the inspected NTFS attribute exactly; no path or stream-name lookup
/// through the live filesystem is involved.
pub fn copy_plain_named_stream<R: Read + Seek, W: Write>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    max_bytes: u64,
    output: &mut W,
) -> Result<StreamCopyProof> {
    ensure!(
        stream_name_utf16.len() <= 255,
        "stream name exceeds NTFS limit"
    );
    let (attribute, expected) = checked_plain_attribute(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        max_bytes,
        true,
    )?;
    copy_checked_attribute(
        reader,
        &raw.geometry,
        &attribute,
        expected.as_deref(),
        record_number,
        stream_name_utf16,
        output,
    )
}

/// Copy a checked plain stream with explicit per-stream and cumulative logical
/// byte budgets. Metadata reads and physical I/O are not included in the budget.
/// Unlike `read_plain_stream`, this does not allocate a payload-sized buffer.
/// The caller chooses the output and must discard partial output on any error;
/// use a bounded/file-backed output when working with large streams.
pub fn copy_plain_stream_with_budget<R: Read + Seek, W: Write>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    budget: &mut StreamTransferBudget,
    output: &mut W,
) -> Result<StreamCopyProof> {
    copy_plain_named_stream_with_budget(reader, raw, record_number, &[], budget, output)
}

/// Copy one explicitly named (or unnamed) plain DATA stream under the same
/// streaming budget. Name matching and source checks remain exact.
pub fn copy_plain_named_stream_with_budget<R: Read + Seek, W: Write>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    budget: &mut StreamTransferBudget,
    output: &mut W,
) -> Result<StreamCopyProof> {
    ensure!(
        stream_name_utf16.len() <= 255,
        "stream name exceeds NTFS limit"
    );
    let (attribute, expected) = checked_plain_attribute(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        budget.max_stream_bytes,
        false,
    )?;
    budget.reserve(attribute.report.logical_size)?;
    copy_checked_attribute(
        reader,
        &raw.geometry,
        &attribute,
        expected.as_deref(),
        record_number,
        stream_name_utf16,
        output,
    )
}

fn copy_checked_attribute<R: Read + Seek, W: Write>(
    reader: &mut R,
    geometry: &NtfsGeometry,
    attribute: &Attribute,
    expected: Option<&str>,
    record_number: u64,
    stream_name_utf16: &[u16],
    output: &mut W,
) -> Result<StreamCopyProof> {
    let expected =
        expected.context("legacy full-stream copy requires an inspected content digest")?;
    let mut digest = n2r_win32::content_digest::Hasher::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; STREAM_HASH_BUFFER_BYTES];
    let mut compression = compression_reader(attribute, geometry)?;
    while copied < attribute.report.logical_size {
        let count = (attribute.report.logical_size - copied).min(buffer.len() as u64) as usize;
        read_logical_range(
            reader,
            attribute,
            copied,
            &mut buffer[..count],
            geometry,
            &mut compression,
        )?;
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
        copied += count as u64;
    }
    let actual = digest.finish();
    ensure!(
        actual == expected,
        "copied logical stream differs from inspected hash"
    );
    Ok(StreamCopyProof {
        record_number,
        stream_name_utf16: stream_name_utf16.to_vec(),
        logical_bytes: copied,
        sha256: actual,
    })
}

/// Hash a bounded logical subrange of the checked unnamed DATA stream. The
/// range reader applies NTFS sparse and valid-data zero semantics, so its hash
/// can describe a materialized ReFS extent even when no source LCN exists.
pub fn hash_plain_stream_range<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    offset: u64,
    length: u64,
    max_bytes: u64,
) -> Result<String> {
    hash_plain_named_stream_range(reader, raw, record_number, &[], offset, length, max_bytes)
}

/// Hash a bounded range of the exact named (or unnamed) DATA attribute.
/// The name selects an already inventoried stream, never a pathname. Source
/// identity, flags, mapping, EOF and valid-data zero semantics are unchanged.
pub fn hash_plain_named_stream_range<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    offset: u64,
    length: u64,
    max_bytes: u64,
) -> Result<String> {
    ensure!(
        stream_name_utf16.len() <= 255,
        "stream name exceeds NTFS limit"
    );
    let (attribute, expected) = checked_plain_attribute(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        max_bytes,
        true,
    )?;
    hash_checked_attribute_range(
        reader,
        &raw.geometry,
        &attribute,
        expected.as_deref(),
        offset,
        length,
    )
}

/// Hash a checked logical range using the same cumulative streaming budget.
/// Every requested byte is charged, including holes and repeated ranges.
pub fn hash_plain_stream_range_with_budget<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    offset: u64,
    length: u64,
    budget: &mut StreamTransferBudget,
) -> Result<String> {
    hash_plain_named_stream_range_with_budget(
        reader,
        raw,
        record_number,
        &[],
        offset,
        length,
        budget,
    )
}

/// Named-stream counterpart with the same per-stream and cumulative logical
/// read budget. Full stream hashes remain content digests; returned range
/// hashes remain SHA-256, including sparse and uninitialized zero bytes.
pub fn hash_plain_named_stream_range_with_budget<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    offset: u64,
    length: u64,
    budget: &mut StreamTransferBudget,
) -> Result<String> {
    ensure!(
        stream_name_utf16.len() <= 255,
        "stream name exceeds NTFS limit"
    );
    let (attribute, expected) = checked_plain_attribute(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        budget.max_stream_bytes,
        false,
    )?;
    ensure!(
        offset
            .checked_add(length)
            .is_some_and(|end| end <= attribute.report.logical_size),
        "requested logical stream range escapes EOF"
    );
    budget.reserve(length)?;
    hash_checked_attribute_range(
        reader,
        &raw.geometry,
        &attribute,
        expected.as_deref(),
        offset,
        length,
    )
}

fn hash_checked_attribute_range<R: Read + Seek>(
    reader: &mut R,
    geometry: &NtfsGeometry,
    attribute: &Attribute,
    expected: Option<&str>,
    offset: u64,
    length: u64,
) -> Result<String> {
    let expected =
        expected.context("legacy stream hashing requires an inspected content digest")?;
    ensure!(
        offset
            .checked_add(length)
            .is_some_and(|end| end <= attribute.report.logical_size),
        "requested logical stream range escapes EOF"
    );
    // The returned range hash stays SHA-256 (placement compares it with target
    // ranges); a whole-stream range is also checked against the content digest.
    let whole = offset == 0 && length == attribute.report.logical_size;
    let mut hash = Sha256::new();
    let mut content = whole.then(n2r_win32::content_digest::Hasher::new);
    let mut copied = 0u64;
    let mut buffer = [0u8; STREAM_HASH_BUFFER_BYTES];
    let mut compression = compression_reader(attribute, geometry)?;
    while copied < length {
        let count = (length - copied).min(buffer.len() as u64) as usize;
        read_logical_range(
            reader,
            attribute,
            offset + copied,
            &mut buffer[..count],
            geometry,
            &mut compression,
        )?;
        hash.update(&buffer[..count]);
        if let Some(content) = &mut content {
            content.update(&buffer[..count]);
        }
        copied += count as u64;
    }
    if let Some(content) = content {
        ensure!(
            content.finish() == expected,
            "logical stream changed from inspection"
        );
    }
    Ok(hex::encode(hash.finalize()))
}

/// Materialize the same verified stream into bounded memory for the existing
/// small laboratory shadow path.
pub fn read_plain_stream<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    copy_plain_stream(reader, raw, record_number, max_bytes, &mut payload)?;
    Ok(payload)
}

/// Raw mapping accounting, not a volume-allocation or native-ownership proof.
/// For sparse nonresident DATA, the header's allocation field and the sum of
/// physical runs are deliberately retained as different quantities.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct StreamAllocationEvidence {
    pub sparse: bool,
    pub resident: bool,
    pub initialized_bytes: u64,
    pub header_allocated_bytes: u64,
    pub mapped_logical_bytes: u64,
    pub mapped_physical_bytes: u64,
    pub allocation_ownership_reconciled: bool,
}

fn data_allocation_evidence(attribute: &AttributeInventory) -> Result<StreamAllocationEvidence> {
    let mut mapped_logical_bytes = 0u64;
    let mut mapped_physical_bytes = 0u64;
    for extent in &attribute.extents {
        mapped_logical_bytes = mapped_logical_bytes
            .checked_add(extent.length)
            .context("logical extent accounting overflow")?;
        if extent.physical_offset.is_some() {
            mapped_physical_bytes = mapped_physical_bytes
                .checked_add(extent.length)
                .context("physical extent accounting overflow")?;
        }
    }
    Ok(StreamAllocationEvidence {
        sparse: attribute.flags & 0x8000 != 0,
        resident: attribute.resident,
        initialized_bytes: attribute.initialized_size,
        header_allocated_bytes: attribute.allocated_size,
        mapped_logical_bytes,
        mapped_physical_bytes,
        allocation_ownership_reconciled: false,
    })
}

#[derive(Debug, Serialize)]
pub struct StreamRangeReadProof {
    pub record_number: u64,
    /// Empty names retain the existing unnamed-stream report encoding.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stream_name_utf16: Vec<u16>,
    pub logical_offset: u64,
    pub logical_bytes: u64,
    pub stream_logical_bytes: u64,
    pub expected_stream_sha256: Option<String>,
    pub sha256: String,
    pub whole_stream_hash_matched: bool,
    /// Present only for the explicitly opted-in sparse-aware reader.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation: Option<StreamAllocationEvidence>,
}

/// One bounded mapping cache for reads under an externally held immutable
/// source lease. Opening and finishing revalidate the actual NTFS metadata.
/// It grants no source admission and never owns a payload-sized buffer.
pub struct PlainStreamRangeSession {
    record_number: u64,
    stream_name_utf16: Vec<u16>,
    allow_sparse: bool,
    attribute: Attribute,
    compression: Option<crate::ntfs_compression::Reader>,
    expected: Option<String>,
    poisoned: bool,
    // Paged DATA mapping remains charged for the complete session lifetime.
    #[cfg(windows)]
    _domain_record_ram: Option<(paged_storage::SourceRamLease, Option<paged_storage::SourceRamLease>)>,
}
impl PlainStreamRangeSession {
    pub fn open<R: Read + Seek>(
        reader: &mut R,
        raw: &NtfsInspection,
        record_number: u64,
        max_bytes: u64,
    ) -> Result<Self> {
        Self::open_named(reader, raw, record_number, &[], max_bytes)
    }

    /// Cache exactly one inventoried DATA stream. Keeping the name in the
    /// session prevents another stream of the same file from reusing its map.
    pub fn open_named<R: Read + Seek>(
        reader: &mut R,
        raw: &NtfsInspection,
        record_number: u64,
        stream_name_utf16: &[u16],
        max_bytes: u64,
    ) -> Result<Self> {
        Self::open_policy(
            reader,
            raw,
            record_number,
            stream_name_utf16,
            max_bytes,
            false,
        )
    }

    /// Explicitly accept uncompressed sparse DATA as well as plain/LZNT1 DATA.
    /// Sparse holes and bytes after VDL read as zeros without payload-device IO.
    /// Full logical-byte hashing/budgets are unchanged, and physical ownership
    /// must still be independently reconciled before conversion.
    pub fn open_sparse_named<R: Read + Seek>(
        reader: &mut R,
        raw: &NtfsInspection,
        record_number: u64,
        stream_name_utf16: &[u16],
        max_bytes: u64,
    ) -> Result<Self> {
        Self::open_policy(
            reader,
            raw,
            record_number,
            stream_name_utf16,
            max_bytes,
            true,
        )
    }

    #[cfg(windows)]
    pub fn open_named_domain<R: Read + Seek>(
        reader: &mut R,
        raw: &PagedInspection,
        record_number: u64,
        stream_name_utf16: &[u16],
        max_bytes: u64,
    ) -> Result<Self> {
        Self::open_domain_policy(
            reader,
            raw,
            record_number,
            stream_name_utf16,
            max_bytes,
            false,
        )
    }

    #[cfg(windows)]
    pub fn open_sparse_named_domain<R: Read + Seek>(
        reader: &mut R,
        raw: &PagedInspection,
        record_number: u64,
        stream_name_utf16: &[u16],
        max_bytes: u64,
    ) -> Result<Self> {
        Self::open_domain_policy(
            reader,
            raw,
            record_number,
            stream_name_utf16,
            max_bytes,
            true,
        )
    }

    #[cfg(windows)]
    fn open_domain_policy<R: Read + Seek>(
        reader: &mut R,
        raw: &PagedInspection,
        record_number: u64,
        stream_name_utf16: &[u16],
        max_bytes: u64,
        allow_sparse: bool,
    ) -> Result<Self> {
        ensure!(
            stream_name_utf16.len() <= 255,
            "stream name exceeds NTFS limit"
        );
        let owned = checked_data_attribute_domain(
            reader,
            raw,
            record_number,
            stream_name_utf16,
            max_bytes,
            allow_sparse,
        )?;
        let compression = compression_reader(&owned.0, &raw.header().geometry)?;
        let (attribute, expected, ram, assembly_ram) = owned;
        Ok(Self {
            record_number,
            stream_name_utf16: stream_name_utf16.to_vec(),
            allow_sparse,
            attribute,
            compression,
            expected,
            poisoned: false,
            _domain_record_ram: Some((ram, assembly_ram)),
        })
    }

    fn open_policy<R: Read + Seek>(
        reader: &mut R,
        raw: &NtfsInspection,
        record_number: u64,
        stream_name_utf16: &[u16],
        max_bytes: u64,
        allow_sparse: bool,
    ) -> Result<Self> {
        ensure!(
            stream_name_utf16.len() <= 255,
            "stream name exceeds NTFS limit"
        );
        let (attribute, expected) = checked_data_attribute(
            reader,
            raw,
            record_number,
            stream_name_utf16,
            max_bytes,
            false,
            allow_sparse,
        )?;
        let compression = compression_reader(&attribute, &raw.geometry)?;
        Ok(Self {
            record_number,
            stream_name_utf16: stream_name_utf16.to_vec(),
            allow_sparse,
            attribute,
            compression,
            expected,
            poisoned: false,
            #[cfg(windows)]
            _domain_record_ram: None,
        })
    }
    pub fn record_number(&self) -> u64 {
        self.record_number
    }
    pub fn stream_name_utf16(&self) -> &[u16] {
        &self.stream_name_utf16
    }
    pub fn matches_stream(&self, record_number: u64, stream_name_utf16: &[u16]) -> bool {
        self.record_number == record_number
            && self.stream_name_utf16.as_slice() == stream_name_utf16
    }
    pub fn stream_length(&self) -> u64 {
        self.attribute.report.logical_size
    }
    pub fn expected_sha256(&self) -> Option<&str> {
        self.expected.as_deref()
    }
    pub fn allocation_evidence(&self) -> Result<StreamAllocationEvidence> {
        data_allocation_evidence(&self.attribute.report)
    }

    #[cfg(windows)]
    pub(crate) fn contiguous_physical_range(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<Option<u64>> {
        ensure!(
            !self.poisoned,
            "failed DATA session cannot suggest a COPY source"
        );
        let a = &self.attribute.report;
        let end = offset
            .checked_add(length)
            .context("COPY source logical overflow")?;
        ensure!(
            end <= a.logical_size,
            "COPY source query escapes logical stream"
        );
        if length == 0
            || a.resident
            || a.flags & !0x8000 != 0
            || a.compression_unit != 0
            || end > a.initialized_size
        {
            return Ok(None);
        }
        let mut cursor = offset;
        let mut first = None;
        for run in &a.extents {
            let run_end = run
                .logical_offset
                .checked_add(run.length)
                .context("COPY source run overflow")?;
            if run_end <= cursor {
                continue;
            }
            if cursor == end {
                break;
            }
            if run.logical_offset > cursor {
                return Ok(None);
            }
            let Some(physical) = run.physical_offset else {
                return Ok(None);
            };
            let physical = physical
                .checked_add(cursor - run.logical_offset)
                .context("COPY source physical overflow")?;
            if let Some(start) = first {
                if Some(physical) != u64::checked_add(start, cursor - offset) {
                    return Ok(None);
                }
            } else {
                first = Some(physical);
            }
            cursor = end.min(run_end);
        }
        Ok(if cursor == end { first } else { None })
    }

    /// Compare a retained native placement with the checked current DATA map.
    /// This observes no payload bytes and produces no content/EOF claim.
    #[cfg(windows)]
    pub(crate) fn require_physical_mapping(
        &self,
        offset: u64,
        physical: u64,
        length: u64,
    ) -> Result<()> {
        let a = &self.attribute.report;
        let end = offset
            .checked_add(length)
            .context("reference logical overflow")?;
        ensure!(
            !self.poisoned
                && !a.resident
                && a.flags & !0x8000 == 0
                && a.compression_unit == 0
                && end <= a.initialized_size
                && end <= a.logical_size,
            "retained reference is not initialized uncompressed source DATA"
        );
        let mut cursor = offset;
        for run in &a.extents {
            let run_end = run
                .logical_offset
                .checked_add(run.length)
                .context("source run overflow")?;
            if run_end <= cursor {
                continue;
            }
            if cursor == end {
                break;
            }
            ensure!(
                run.logical_offset <= cursor,
                "retained source mapping has a gap"
            );
            let actual = run
                .physical_offset
                .context("retained source range is a hole")?
                .checked_add(cursor - run.logical_offset)
                .context("source physical overflow")?;
            let wanted = physical
                .checked_add(cursor - offset)
                .context("reference physical overflow")?;
            ensure!(
                actual == wanted,
                "native retained reference differs from current source DATA"
            );
            cursor = end.min(run_end);
        }
        ensure!(
            cursor == end,
            "retained source mapping coverage is incomplete"
        );
        Ok(())
    }

    /// Prove logical zeros from actual sparse mapping/VDL, without claiming a
    /// payload read. The caller separately checks the native destination hole.
    #[cfg(windows)]
    pub(crate) fn require_zero_mapping(&self, offset: u64, length: u64) -> Result<()> {
        let a = &self.attribute.report;
        let end = offset
            .checked_add(length)
            .context("hole logical overflow")?;
        ensure!(
            !self.poisoned
                && self.allow_sparse
                && !a.resident
                && a.flags & !0x8000 == 0
                && a.compression_unit == 0
                && end <= a.logical_size,
            "logical hole requires checked uncompressed sparse DATA"
        );
        let initialized_end = end.min(a.initialized_size);
        let mut cursor = offset.min(initialized_end);
        for run in &a.extents {
            let run_end = run
                .logical_offset
                .checked_add(run.length)
                .context("sparse source run overflow")?;
            if run_end <= cursor {
                continue;
            }
            if cursor == initialized_end {
                break;
            }
            ensure!(
                run.logical_offset <= cursor && run.physical_offset.is_none(),
                "native hole differs from initialized source allocation"
            );
            cursor = initialized_end.min(run_end);
        }
        ensure!(
            cursor == initialized_end,
            "source hole coverage is incomplete"
        );
        Ok(())
    }
    pub fn read<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        raw: &NtfsInspection,
        offset: u64,
        output: &mut [u8],
        budget: &mut StreamTransferBudget,
    ) -> Result<()> {
        self.read_observed(reader, raw, offset, output, budget, None)
    }

    pub(crate) fn read_with_direct_receipts<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        raw: &NtfsInspection,
        offset: u64,
        output: &mut [u8],
        budget: &mut StreamTransferBudget,
    ) -> Result<DirectReadReceipt> {
        let mut receipt = DirectReadReceipt::new();
        self.read_observed(reader, raw, offset, output, budget, Some(&mut receipt))?;
        Ok(receipt)
    }

    fn read_observed<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        raw: &NtfsInspection,
        offset: u64,
        output: &mut [u8],
        budget: &mut StreamTransferBudget,
        receipt: Option<&mut DirectReadReceipt>,
    ) -> Result<()> {
        self.read_observed_geometry(reader, &raw.geometry, offset, output, budget, receipt)
    }

    fn read_observed_geometry<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        geometry: &NtfsGeometry,
        offset: u64,
        output: &mut [u8],
        budget: &mut StreamTransferBudget,
        receipt: Option<&mut DirectReadReceipt>,
    ) -> Result<()> {
        ensure!(
            !self.poisoned
                && output.len() <= SESSION_READ_BYTES
                && offset
                    .checked_add(output.len() as u64)
                    .is_some_and(|v| v <= self.stream_length()),
            "plain stream session failed or range exceeds bounds"
        );
        self.poisoned = true;
        budget.reserve(output.len() as u64)?;
        read_logical_range_observed(
            reader,
            &self.attribute,
            offset,
            output,
            geometry,
            &mut self.compression,
            receipt,
        )?;
        self.poisoned = false;
        Ok(())
    }

    #[cfg(windows)]
    pub fn read_domain<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        raw: &PagedInspection,
        offset: u64,
        output: &mut [u8],
        budget: &mut StreamTransferBudget,
    ) -> Result<()> {
        self.read_observed_geometry(reader, &raw.header().geometry, offset, output, budget, None)
    }

    #[cfg(windows)]
    pub(crate) fn read_with_direct_receipts_domain<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        raw: &PagedInspection,
        offset: u64,
        output: &mut [u8],
        budget: &mut StreamTransferBudget,
    ) -> Result<DirectReadReceipt> {
        let mut receipt = DirectReadReceipt::new();
        self.read_observed_geometry(
            reader,
            &raw.header().geometry,
            offset,
            output,
            budget,
            Some(&mut receipt),
        )?;
        Ok(receipt)
    }

    #[cfg(windows)]
    pub fn finish_domain<R: Read + Seek>(
        self,
        reader: &mut R,
        raw: &PagedInspection,
    ) -> Result<()> {
        ensure!(!self.poisoned, "failed plain stream session cannot finish");
        let after = checked_data_attribute_domain(
            reader,
            raw,
            self.record_number,
            &self.stream_name_utf16,
            self.stream_length(),
            self.allow_sparse,
        )?;
        ensure!(
            after.1 == self.expected
                && after.0.report == self.attribute.report
                && after.0.resident_value == self.attribute.resident_value,
            "plain stream mapping changed around session",
        );
        Ok(())
    }
    pub fn finish<R: Read + Seek>(self, reader: &mut R, raw: &NtfsInspection) -> Result<()> {
        ensure!(!self.poisoned, "failed plain stream session cannot finish");
        let (after, expected) = checked_data_attribute(
            reader,
            raw,
            self.record_number,
            &self.stream_name_utf16,
            self.stream_length(),
            false,
            self.allow_sparse,
        )?;
        ensure!(
            expected == self.expected
                && after.report == self.attribute.report
                && after.resident_value == self.attribute.resident_value,
            "plain stream mapping changed around session"
        );
        Ok(())
    }
}

/// Read a small resident/materialization range without scanning its large
/// prefix or allocating a stream-sized buffer. Caller must discard output on
/// error and hold source exclusion. Sparse/VDL zero semantics are unchanged;
/// metadata/bootstrap IO is separate from the charged logical-byte budget.
pub fn read_plain_stream_range_into<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    offset: u64,
    output: &mut [u8],
    budget: &mut StreamTransferBudget,
) -> Result<StreamRangeReadProof> {
    read_plain_named_stream_range_into(reader, raw, record_number, &[], offset, output, budget)
}

/// Read one named or unnamed DATA range without allocating a stream-sized
/// buffer. The exact UTF-16 name is rechecked before and after the read and is
/// included in the resulting proof. This supplies no target ADS support or
/// permission to bypass source admission.
pub fn read_plain_named_stream_range_into<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    offset: u64,
    output: &mut [u8],
    budget: &mut StreamTransferBudget,
) -> Result<StreamRangeReadProof> {
    read_data_stream_range_into(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        offset,
        output,
        budget,
        false,
    )
}

/// Sparse-aware counterpart of the named logical reader. Plain, SPARSE
/// (0x8000), and the checked LZNT1 profile are accepted; EFS remains refused.
/// Encoded compression padding is decoded rather than exposed as sparse holes.
/// The proof distinguishes header allocation from physical mapped bytes.
pub fn read_sparse_named_stream_range_into<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    offset: u64,
    output: &mut [u8],
    budget: &mut StreamTransferBudget,
) -> Result<StreamRangeReadProof> {
    read_data_stream_range_into(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        offset,
        output,
        budget,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn read_data_stream_range_into<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    record_number: u64,
    stream_name_utf16: &[u16],
    offset: u64,
    output: &mut [u8],
    budget: &mut StreamTransferBudget,
    allow_sparse: bool,
) -> Result<StreamRangeReadProof> {
    ensure!(
        stream_name_utf16.len() <= 255,
        "stream name exceeds NTFS limit"
    );
    ensure!(
        output.len() <= STREAM_HASH_BUFFER_BYTES,
        "materialization range exceeds fixed buffer"
    );
    let (attribute, expected) = checked_data_attribute(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        budget.max_stream_bytes,
        false,
        allow_sparse,
    )?;
    let length = output.len() as u64;
    ensure!(
        offset
            .checked_add(length)
            .is_some_and(|end| end <= attribute.report.logical_size),
        "materialization range escapes stream EOF"
    );
    budget.reserve(length)?;
    read_attribute_range(reader, &attribute, offset, output, &raw.geometry)?;
    // The range proof stays SHA-256 (residual tails are compared as SHA-256);
    // a whole stream is also checked against the inspected content digest.
    let actual = hex::encode(Sha256::digest(&*output));
    let whole = offset == 0 && length == attribute.report.logical_size;
    if whole && let Some(expected) = &expected {
        ensure!(
            n2r_win32::content_digest::of(output) == *expected,
            "materialized whole stream differs from inspection"
        );
    }
    // Revalidate identity, geometry, mapping and initialized-length evidence
    // after the read too. No serialized success flag supplies that evidence.
    let (_, after) = checked_data_attribute(
        reader,
        raw,
        record_number,
        stream_name_utf16,
        budget.max_stream_bytes,
        false,
        allow_sparse,
    )?;
    ensure!(
        after == expected,
        "inspected source stream changed around range read"
    );
    let whole_stream_hash_matched = whole && expected.is_some();
    Ok(StreamRangeReadProof {
        record_number,
        stream_name_utf16: stream_name_utf16.to_vec(),
        logical_offset: offset,
        logical_bytes: length,
        stream_logical_bytes: attribute.report.logical_size,
        expected_stream_sha256: expected,
        sha256: actual,
        whole_stream_hash_matched,
        allocation: if allow_sparse {
            Some(data_allocation_evidence(&attribute.report)?)
        } else {
            None
        },
    })
}

/// The report limit bounds retained inventory data, not the entire process's
/// resident set. Volume bitmap scans use a fixed 64 KiB window; parser working
/// storage is limited to one 64 KiB-or-smaller file record and its attributes.
/// Logical stream hashing uses a fixed 64 KiB buffer (streams over 4 MiB: one
/// 4 MiB read buffer and at most three 4 MiB worker buffers) and a cumulative
/// byte limit.
/// Metadata ancestry adds at most MAX_MFT_RECORDS states and 4096 stack frames.
/// Raw namespace working storage has a separate 16 MiB read budget, 16,384 keys,
/// 131,072 UTF-16 name units, 4096 directories and 64 B-tree levels.
pub fn inspect_with_limits<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    limits: InspectionLimits,
) -> Result<NtfsInspection> {
    inspect_with_limits_and_policy(
        reader,
        length,
        limits,
        crate::verification_policy::VerificationPolicy::FullContent,
    )
}

/// Explicit raw observation policy. Extent mode still captures all metadata,
/// namespaces, security and allocation; only proven eligible DATA is not read.
pub fn inspect_with_limits_and_policy<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    limits: InspectionLimits,
    policy: crate::verification_policy::VerificationPolicy,
) -> Result<NtfsInspection> {
    inspect_internal(reader, length, limits, policy, false)
}

/// Layout suggestions only: never read nonresident DATA merely to hash streams
/// which preparation may skip. All logical hashes stay explicitly unavailable;
/// a permanent blocker prevents this report from satisfying source admission.
pub fn inspect_for_preparation<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    limits: InspectionLimits,
) -> Result<NtfsInspection> {
    inspect_internal(
        reader,
        length,
        limits,
        crate::verification_policy::VerificationPolicy::ExtentIdentityV1,
        true,
    )
}

fn inventory_record<R: Read + Seek>(
    reader: &mut R,
    geometry: &NtfsGeometry,
    record: Record,
    number: u64,
    report: &mut NtfsInspection,
    budget: &mut ReportBudget,
    hash_budget: &mut HashBudget,
    policy: crate::verification_policy::VerificationPolicy,
    preparation_only: bool,
    observe: impl FnOnce(&mut R, &Record) -> Result<()>,
) -> Result<FileInventory> {
    let mut inventory = FileInventory {
        record_number: number,
        sequence_number: record.sequence,
        hard_link_count: record.links,
        is_directory: record.flags & 2 != 0,
        is_metadata: number < 16,
        metadata_role: MetadataRole::NotClassified,
        metadata_role_issue: None,
        base_file_reference: record.base,
        names: Vec::new(),
        standard_information: None,
        streams: Vec::new(),
        attributes: Vec::new(),
        extended_attributes: Some(
            capture_extended_attributes(reader, &record, geometry)
                .with_context(|| format!("capturing EAs for MFT record {number}"))?,
        ),
        reparse: capture_reparse(reader, &record, geometry)
            .with_context(|| format!("capturing reparse point for MFT record {number}"))?,
    };
    if record.base != 0 {
        blocker(
            report,
            budget,
            "extension_record_unassembled",
            "Extension-record attributes have not been reconciled with their base file",
            Some(number),
        )?;
    }
    // Attribute order must not allow a DATA hash before a later list reveals
    // that the stream is incomplete. Raw names avoid lossy UTF-16 collisions.
    let has_attribute_list = record.attributes.iter().any(|a| a.report.type_code == 0x20);
    if !has_attribute_list && record.base == 0 {
        let mut data_names = std::collections::BTreeSet::new();
        for attribute in &record.attributes {
            if attribute.report.type_code == 0x80 {
                ensure!(
                    data_names.insert(&attribute.report.name_utf16),
                    "duplicate DATA stream name without attribute-list assembly in record {number}"
                );
            }
        }
    }
    observe(reader, &record)?;
    // The SI bit is a file/directory compression policy. A resident DATA
    // value may remain ordinary bytes under that policy; only the DATA
    // encoding determines whether payload decoding is necessary.
    let compression_policy_supported = record
        .attributes
        .iter()
        .filter(|a| a.report.type_code == 0x80)
        .all(|a| {
            (a.report.flags == 0 && a.report.compression_unit == 0)
                || crate::ntfs_compression::supported(&a.report, geometry).is_ok()
        });
    let policy_root_instances: Vec<_> = record
        .attributes
        .iter()
        .filter(|a| directory_compression_root_policy(&record, a))
        .map(|a| a.report.instance)
        .collect();
    for attribute in record.attributes {
        let a = &attribute.report;
        if a.flags & 0x00ff != 0
            && crate::ntfs_compression::supported(a, geometry).is_err()
            && !(a.type_code == 0x90
                && a.resident
                && a.flags == 1
                && a.compression_unit == 0
                && crate::ntfs_namespace::is_i30(&a.name_utf16)
                && policy_root_instances.contains(&a.instance))
        {
            blocker(
                report,
                budget,
                "ntfs_compression",
                "Compressed attribute is outside the supported LZNT1 DATA profile",
                Some(number),
            )?;
        }
        if a.flags & 0x4000 != 0 {
            blocker(
                report,
                budget,
                "ntfs_encryption",
                "Encrypted attribute is outside the initial conversion scope",
                Some(number),
            )?;
        }
        match a.type_code {
            0x10 => {
                let value = attribute
                    .resident_value
                    .as_ref()
                    .context("nonresident standard information is unsupported")?;
                ensure!(value.len() >= 48, "truncated standard information");
                ensure!(
                    inventory.standard_information.is_none(),
                    "duplicate standard information"
                );
                let flags = u32le(value, 32)?;
                inventory.standard_information = Some(StandardInformation {
                    creation_time: u64le(value, 0)?,
                    modification_time: u64le(value, 8)?,
                    mft_change_time: u64le(value, 16)?,
                    access_time: u64le(value, 24)?,
                    file_attributes: flags,
                    security_id: if value.len() >= 56 {
                        Some(u32le(value, 52)?)
                    } else {
                        None
                    },
                });
                if flags & 0x800 != 0 && !compression_policy_supported {
                    blocker(
                        report,
                        budget,
                        "compressed_file_attribute",
                        "Compression policy has DATA outside the supported encoding profile",
                        Some(number),
                    )?;
                }
                if flags & 0x4000 != 0 {
                    blocker(
                        report,
                        budget,
                        "encrypted_file_attribute",
                        "File or directory carries the EFS attribute",
                        Some(number),
                    )?;
                }
            }
            0x20 => blocker(
                report,
                budget,
                "attribute_list_unassembled",
                "Attribute-list continuation mapping has not been validated",
                Some(number),
            )?,
            0x30 => {
                let value = attribute
                    .resident_value
                    .as_ref()
                    .context("nonresident filename is unsupported")?;
                ensure!(value.len() >= 66, "truncated filename attribute");
                let name_bytes = value
                    .get(66..66 + usize::from(value[64]) * 2)
                    .context("truncated UTF-16 filename")?;
                let name_utf16 = utf16(name_bytes)?;
                let name = String::from_utf16_lossy(&name_utf16);
                let parent = u64le(value, 0)?;
                if value[65] == 2 {
                    blocker(
                        report,
                        budget,
                        "dos_short_name",
                        "DOS short-name alias has no validated ReFS representation",
                        Some(number),
                    )?;
                }
                ensure!(value[65] <= 3, "unknown NTFS filename namespace");
                if name.eq_ignore_ascii_case("hiberfil.sys") {
                    blocker(
                        report,
                        budget,
                        "hibernation_state_unverified",
                        "Hibernation file is present; a fully shut-down state must be established independently",
                        Some(number),
                    )?;
                }
                inventory.names.push(NameInventory {
                    name,
                    name_utf16,
                    namespace: value[65],
                    parent_record_number: parent & 0x0000_ffff_ffff_ffff,
                    parent_sequence_number: (parent >> 48) as u16,
                });
            }
            0x40 => blocker(
                report,
                budget,
                "object_id",
                "NTFS object-ID semantics have no validated target mapping",
                Some(number),
            )?,
            0x80 => {
                // Ancestry is not known until all metadata is captured.
                // Defer fully initialized plain DATA with a complete
                // target-cluster prefix. Partial final-cluster bytes stay
                // covered by fingerprint IO and actual tail materialization;
                // every other form keeps the existing full-read fallback.
                let deferred = policy.is_fast()
                    && number >= 16
                    && record.base == 0
                    && !inventory.is_directory
                    && !has_attribute_list
                    && !a.resident
                    && a.flags == 0
                    && a.compression_unit == 0
                    && a.lowest_vcn == 0
                    && a.logical_size >= 4096
                    && a.initialized_size == a.logical_size
                    && a.extents.iter().all(|e| e.physical_offset.is_some());
                let (logical_hash_status, logical_sha256) = if deferred || preparation_only {
                    (LogicalHashStatus::NotComputed, None)
                } else {
                    hash_stream(
                        reader,
                        &attribute,
                        geometry,
                        hash_budget,
                        has_attribute_list,
                        record.base != 0,
                        number,
                    )
                    .with_context(|| {
                        format!(
                            "hashing DATA attribute {} in MFT record {number}",
                            a.instance
                        )
                    })?
                };
                if !preparation_only
                    && !deferred
                    && logical_hash_status != LogicalHashStatus::Complete
                {
                    blocker(
                        report,
                        budget,
                        "logical_stream_hash_unavailable",
                        format!(
                            "DATA attribute {} has no complete logical hash: {logical_hash_status:?}",
                            a.instance
                        ),
                        Some(number),
                    )?;
                }
                inventory.streams.push(StreamInventory {
                    name: String::from_utf16_lossy(&a.name_utf16),
                    name_utf16: a.name_utf16.clone(),
                    resident: a.resident,
                    flags: a.flags,
                    logical_size: a.logical_size,
                    initialized_size: a.initialized_size,
                    allocated_size: a.allocated_size,
                    extents: a.extents.clone(),
                    resident_sha256: a.resident_sha256.clone(),
                    logical_sha256,
                    logical_hash_status,
                });
            }
            // capture_reparse validated and retained the actual bytes
            // before attributes were consumed. Unsupported tags/layouts
            // return an error instead of losing their semantics.
            0xc0 => ensure!(inventory.reparse.is_some(), "reparse capture missing"),
            // The unique paired EA attrs were fully read and validated
            // before consuming this record. Keep both original attrs and
            // their complete allocations in the ownership inventory.
            0xd0 | 0xe0 => {}
            0x10..=0xb0 if a.type_code % 0x10 == 0 => {}
            _ => blocker(
                report,
                budget,
                "unsupported_attribute",
                format!(
                    "Attribute type {:#x} needs a preservation policy",
                    a.type_code
                ),
                Some(number),
            )?,
        }
        inventory.attributes.push(attribute.report);
    }
    Ok(inventory)
}

fn inspect_internal<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    limits: InspectionLimits,
    policy: crate::verification_policy::VerificationPolicy,
    preparation_only: bool,
) -> Result<NtfsInspection> {
    let mut budget = ReportBudget {
        limit: limits.max_report_bytes,
        used: 0,
    };
    budget.charge(std::mem::size_of::<NtfsInspection>() as u64)?;
    let mut hash_budget = HashBudget {
        limit: limits.max_stream_hash_bytes,
        used: 0,
    };
    let mut boot = [0u8; 512];
    read_at(reader, 0, &mut boot, length)?;
    let geometry = inspect_boot_sector(&boot, length)?;
    let native_parser = ntfs::Ntfs::new(reader).context("ntfs crate rejected boot geometry")?;
    ensure!(
        native_parser.cluster_size() == geometry.cluster_size
            && native_parser.file_record_size() == geometry.file_record_size,
        "independent NTFS geometry interpretations disagree"
    );
    let mft_bootstrap::Bootstrap {
        record,
        data: mft_data,
        bitmap: mft_bitmap,
        record_count: mft_record_count,
        assembly: mft_assembly,
    } = mft_bootstrap::read(reader, &geometry)?;
    let mut canonical_bootstrap = if mft_assembly.is_some() {
        Some(record)
    } else {
        None
    };
    let mut report = NtfsInspection {
        schema_version: 1,
        geometry: geometry.clone(),
        volume_version: None,
        volume_flags: None,
        dirty: None,
        mft_record_count,
        records_scanned: 0,
        allocated_clusters: None,
        free_clusters: None,
        allocation_reconciliation: None,
        namespace_reconciliation: None,
        security_reconciliation: None,
        files: Vec::new(),
        attribute_assemblies: Vec::new(),
        blockers: Vec::new(),
        inventory_complete: false,
        inventory_memory_bytes: 0,
        inventory_memory_limit_bytes: limits.max_report_bytes,
        stream_hash_bytes: 0,
        stream_hash_limit_bytes: limits.max_stream_hash_bytes,
    };
    let mut root_seen = false;
    let mut volume_bitmap = None;
    let mut namespace = NamespaceCapture::default();
    let mut security = SecurityCapture::default();
    // Base files are processed first. Extension records may precede their base
    // numerically, so defer them without caching an unbounded MFT in memory.
    let mut physical_extensions = vec![0u8; mft_record_count.div_ceil(8) as usize];
    let mut consumed = std::collections::BTreeMap::<u64, (usize, usize)>::new();
    if let Some(assembly) = mft_assembly {
        assembled_io::retain_assembly(&mut report, &mut budget, &mut consumed, assembly)?;
    }
    let mft_context = assembled_io::MftContext {
        data: &mft_data,
        bitmap: &mft_bitmap,
        geometry: &geometry,
        record_count: mft_record_count,
    };
    for (pass, number) in
        (0..2).flat_map(|pass| (0..mft_record_count).map(move |number| (pass, number)))
    {
        if mft_bitmap[number as usize / 8] & (1 << (number % 8)) == 0 {
            continue;
        }
        if pass == 1
            && (physical_extensions[number as usize / 8] & (1 << (number % 8)) == 0
                || consumed.contains_key(&number))
        {
            continue;
        }
        let mut raw = vec![0; geometry.file_record_size as usize];
        read_attribute_range(
            reader,
            &mft_data,
            number * u64::from(geometry.file_record_size),
            &mut raw,
            &geometry,
        )
        .with_context(|| format!("reading MFT record {number}"))?;
        let mut record = parse_record(raw.clone(), &geometry)
            .with_context(|| format!("parsing MFT record {number}"))?;
        ensure!(
            record.flags & 1 != 0,
            "MFT bitmap marks record {number} allocated but its header disagrees"
        );
        if pass == 0 {
            report.records_scanned += 1;
            if record.base != 0 {
                physical_extensions[number as usize / 8] |= 1 << (number % 8);
                if let Some(&(assembly, extension)) = consumed.get(&number) {
                    ensure!(
                        report.attribute_assemblies[assembly].extensions[extension]
                            .raw_record_sha256
                            == hex::encode(Sha256::digest(&raw)),
                        "consumed extension changed during inventory"
                    );
                }
                continue;
            }
            ensure!(
                !consumed.contains_key(&number),
                "extension changed into a base record during inventory"
            );
            if number == 0
                && let Some(canonical) = canonical_bootstrap.take()
            {
                let expected = &report.attribute_assemblies[0].base.raw_record_sha256;
                ensure!(
                    *expected == hex::encode(Sha256::digest(&raw)),
                    "MFT bootstrap changed during inventory"
                );
                record = canonical;
            }
            if let Some(assembly) = mft_context
                .resolve(reader, number, &raw, &mut record)
                .with_context(|| format!("assembling ordinary DATA for MFT record {number}"))?
            {
                assembled_io::retain_assembly(&mut report, &mut budget, &mut consumed, assembly)?;
            }
        } else {
            ensure!(
                record.base != 0,
                "deferred extension changed into a base file"
            );
        }
        if number == 5 {
            ensure!(record.flags & 2 != 0, "root record is not a directory");
            root_seen = true;
        }
        if number == 3 {
            let value = read_small_attribute(reader, unnamed(&record, 0x70)?, &geometry, 1024)?;
            ensure!(value.len() >= 12, "truncated volume information");
            let flags = u16le(&value, 10)?;
            let volume_version = format!("{}.{}", value[8], value[9]);
            budget.charge(volume_version.capacity() as u64)?;
            report.volume_version = Some(volume_version);
            report.volume_flags = Some(flags);
            report.dirty = Some(flags & 1 != 0);
            if flags != 0 {
                blocker(
                    &mut report,
                    &mut budget,
                    "volume_state_flags",
                    format!(
                        "Volume flags {flags:#06x} require native validation before conversion"
                    ),
                    Some(number),
                )?;
            }
            if value[8] != 3 || value[9] != 1 {
                blocker(
                    &mut report,
                    &mut budget,
                    "unsupported_ntfs_version",
                    "Only NTFS 3.1 is a conversion research target",
                    Some(number),
                )?;
            }
        }
        if number == 6 {
            let bitmap_attr = unnamed(&record, 0x80)?;
            let needed = geometry.total_clusters.div_ceil(8);
            require_bitmap_bytes(&bitmap_attr.report, needed)?;
            volume_bitmap = Some(bitmap_attr.clone());
        }
        let inventory = inventory_record(
            reader,
            &geometry,
            record,
            number,
            &mut report,
            &mut budget,
            &mut hash_budget,
            policy,
            preparation_only,
            |reader, record| {
                namespace.observe(reader, record, number, &geometry);
                security.observe(reader, record, number, &geometry);
                Ok(())
            },
        )?;
        let retained = file_heap_bytes(&inventory)?;
        budget
            .push(&mut report.files, inventory, retained)
            .with_context(|| format!("retaining MFT record {number}"))?;
    }
    report.files.sort_unstable_by_key(|file| file.record_number);
    for number in consumed.keys() {
        ensure!(
            physical_extensions[*number as usize / 8] & (1 << (*number % 8)) != 0,
            "consumed extension was not observed as an allocated physical segment"
        );
    }
    let mut bitmap_reader = AttributeBitmapReader {
        reader,
        attribute: volume_bitmap.as_ref().context("missing volume bitmap")?,
        geometry: &geometry,
        length: geometry.total_clusters.div_ceil(8),
        position: 0,
    };
    let bitmap_summary =
        ntfs_allocation::summarize_stream(geometry.total_clusters, &mut bitmap_reader)?;
    report.allocated_clusters = Some(bitmap_summary.allocated_clusters);
    report.free_clusters = Some(bitmap_summary.free_clusters);
    ensure!(
        root_seen && report.volume_flags.is_some() && report.allocated_clusters.is_some(),
        "missing allocated root, volume-information, or allocation-bitmap records"
    );
    classify_metadata_roles(&mut report, &mut budget)?;
    validate_record_coverage(&report)?;
    let allocation = reconcile_allocation(&report, &mut bitmap_reader, &bitmap_summary)?;
    budget.charge((allocation.bitmap_sha256.capacity() + allocation.detail.capacity()) as u64)?;
    report.allocation_reconciliation = Some(allocation);
    // The shared eligibility predicate resolves all file names through this
    // reconciled namespace. Establish it before deciding any deferred hash;
    // an absent namespace must never silently turn every fast stream into a
    // full-content fallback.
    let namespace = namespace.finish(&report.files);
    budget.charge((namespace.evidence_sha256.capacity() + namespace.detail.capacity()) as u64)?;
    report.namespace_reconciliation = Some(namespace);
    if policy.is_fast() && !preparation_only {
        // Reborrow the reader held by the completed bitmap pass; no bitmap
        // reads remain while deferred DATA hashes are decided below.
        let reader = &mut *bitmap_reader.reader;
        for file_index in 0..report.files.len() {
            for stream_index in 0..report.files[file_index].streams.len() {
                if report.files[file_index].streams[stream_index].logical_hash_status
                    != LogicalHashStatus::NotComputed
                {
                    continue;
                }
                let file = &report.files[file_index];
                let stream = &file.streams[stream_index];
                let eligible = report.allocation_reconciliation.as_ref().is_some_and(|a| {
                    a.status == AllocationReconciliationStatus::ConsistentRawModel
                }) && crate::ntfs_attestation::extent_identity_stream_request(
                    &report, file, stream,
                )?
                .is_some();
                let (status, digest) = if eligible {
                    (LogicalHashStatus::NotReadExtentIdentityV1, None)
                } else {
                    let attribute = file
                        .attributes
                        .iter()
                        .find(|a| a.type_code == 0x80 && a.name_utf16 == stream.name_utf16)
                        .context("deferred DATA attribute absent")?
                        .clone();
                    hash_stream(
                        reader,
                        &Attribute {
                            report: attribute,
                            resident_value: None,
                        },
                        &geometry,
                        &mut hash_budget,
                        false,
                        false,
                        file.record_number,
                    )?
                };
                if let Some(hash) = &digest {
                    budget.charge(hash.capacity() as u64)?;
                }
                let number = report.files[file_index].record_number;
                let stream = &mut report.files[file_index].streams[stream_index];
                stream.logical_hash_status = status;
                stream.logical_sha256 = digest;
                if !matches!(
                    status,
                    LogicalHashStatus::Complete | LogicalHashStatus::NotReadExtentIdentityV1
                ) {
                    blocker(
                        &mut report,
                        &mut budget,
                        "logical_stream_hash_unavailable",
                        format!("Deferred DATA has no supported source evidence: {status:?}"),
                        Some(number),
                    )?;
                }
            }
        }
    }
    let security = security.finish(&report.files);
    budget.charge(crate::ntfs_security::heap_bytes(&security) as u64)?;
    report.security_reconciliation = Some(security);
    for (code, message) in [
        (
            "security_descriptors_unresolved",
            "Raw descriptor/index reconciliation is diagnostic; native security retrieval and target preservation remain unverified",
        ),
        (
            "directory_indexes_unverified",
            "Raw I30 reconciliation is diagnostic; complete native namespace enumeration and source admission remain unverified",
        ),
        (
            "allocation_ownership_unverified",
            "Raw allocation reconciliation is diagnostic; native bitmap/extent cross-checks and complete source admission remain unverified",
        ),
        (
            "journal_state_unverified",
            "$LogFile restart state and clean-shutdown evidence have not been validated",
        ),
        (
            "backup_boot_unverified",
            "Backup boot sector and $MFTMirr consistency have not been validated",
        ),
    ] {
        blocker(&mut report, &mut budget, code, message, None)?;
    }
    report.inventory_memory_bytes = budget.used;
    if preparation_only {
        blocker(
            &mut report,
            &mut budget,
            "preparation_inventory_only",
            "Metadata-only layout hints lack logical content evidence and cannot admit conversion",
            None,
        )?;
    }
    report.stream_hash_bytes = hash_budget.used;
    Ok(report)
}
