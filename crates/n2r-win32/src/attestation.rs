//! Read-only native file-handle observations. These do not authorize conversion.
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::BTreeSet, io};

pub const MAX_FILES: usize = 256;
pub const MAX_SECURITY_BYTES: usize = 65_536;
pub const MAX_TOTAL_SECURITY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Volume pages are budgeted separately from file/stream observations.
pub const MAX_TOTAL_BITMAP_BYTES: usize = 2 * crate::bitmap_paging::MAX_RETURNED_BYTES + 4096;
/// Existing qualification/replay artifact ceiling, including JSON encoding.
pub const MAX_SERIALIZED_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// Collection resources only; this is distinct from conversion/journal profiles.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProfile {
    ExperimentalLargeTreeV1,
    ExperimentalStreamingTreeV2,
    ExperimentalObjectEnvelopeV3(Option<crate::tree_resources::CountAdmission>),
    ResourceBoundedV4(Option<crate::tree_resources::SourceResourceAdmission>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub maximum_identities: usize,
    pub maximum_stream_bytes: u64,
    pub logical_read_bytes: u64,
    pub logical_read_calls: u64,
    pub security_bytes: usize,
    pub stream_evidence_bytes: usize,
    pub namespace_evidence_bytes: usize,
}
impl ResourceProfile {
    pub fn maximum_partition_bytes(self) -> u64 {
        match self {
            Self::ExperimentalLargeTreeV1
            | Self::ExperimentalStreamingTreeV2
            | Self::ExperimentalObjectEnvelopeV3(_) => {
                crate::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES
            }
            Self::ResourceBoundedV4(Some(admission)) if admission.validate().is_ok() => {
                i64::MAX as u64
            }
            Self::ResourceBoundedV4(_) => 0,
        }
    }
    pub fn limits(self) -> ResourceLimits {
        match self {
            Self::ResourceBoundedV4(admission) => {
                let Some(admission) = admission.filter(|a| a.validate().is_ok()) else {
                    return ResourceLimits {
                        maximum_identities: 0,
                        maximum_stream_bytes: 0,
                        logical_read_bytes: 0,
                        logical_read_calls: 0,
                        security_bytes: 0,
                        stream_evidence_bytes: 0,
                        namespace_evidence_bytes: 0,
                    };
                };
                let semantic =
                    usize::try_from(admission.native_semantic_byte_budget()).unwrap_or(usize::MAX);
                ResourceLimits {
                    maximum_identities: usize::try_from(admission.raw_identities).unwrap_or(0),
                    maximum_stream_bytes: i64::MAX as u64,
                    logical_read_bytes: u64::MAX,
                    logical_read_calls: u64::MAX,
                    security_bytes: semantic,
                    stream_evidence_bytes: semantic,
                    namespace_evidence_bytes: semantic,
                }
            }
            Self::ExperimentalLargeTreeV1 => ResourceLimits {
                maximum_identities: 2048,
                maximum_stream_bytes: 4 << 30,
                logical_read_bytes: 16 << 30,
                logical_read_calls: 4 * 1024 * 1024,
                security_bytes: 32 << 20,
                stream_evidence_bytes: 64 << 20,
                namespace_evidence_bytes: 16 << 20,
            },
            Self::ExperimentalStreamingTreeV2 | Self::ExperimentalObjectEnvelopeV3(_) => {
                ResourceLimits {
                    maximum_identities: 2048,
                    maximum_stream_bytes: self.maximum_partition_bytes(),
                    logical_read_bytes: self.maximum_partition_bytes() * 4,
                    logical_read_calls: self.maximum_partition_bytes() * 4 / 65536 + 4096,
                    security_bytes: 32 << 20,
                    stream_evidence_bytes: 64 << 20,
                    namespace_evidence_bytes: 16 << 20,
                }
            }
        }
    }

    pub const fn is_streaming(self) -> bool {
        matches!(
            self,
            Self::ExperimentalStreamingTreeV2
                | Self::ExperimentalObjectEnvelopeV3(_)
                | Self::ResourceBoundedV4(_)
        )
    }

    /// Planning None is not native admission. It only permits the complete raw
    /// inventory to be counted before a versioned descriptor is selected.
    pub fn maximum_objects(self) -> usize {
        match self {
            Self::ResourceBoundedV4(Some(a)) if a.validate().is_ok() => {
                usize::try_from(a.objects().unwrap_or(0)).unwrap_or(0)
            }
            Self::ResourceBoundedV4(_) => 0,
            Self::ExperimentalObjectEnvelopeV3(Some(a)) if a.requires_paged_metadata() => {
                (a.object_slots as usize).min(crate::tree_resources::RAW_IDENTITIES)
            }
            Self::ExperimentalObjectEnvelopeV3(None) => crate::tree_resources::RAW_IDENTITIES,
            _ => crate::tree_resources::OBJECT_SLOTS,
        }
    }

    pub fn count_admission(self) -> io::Result<Option<crate::tree_resources::CountAdmission>> {
        match self {
            Self::ExperimentalObjectEnvelopeV3(Some(admission)) => {
                admission.validate()?;
                Ok(Some(admission))
            }
            Self::ExperimentalObjectEnvelopeV3(None) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tree envelope has no complete-source count admission",
            )),
            _ => Ok(None),
        }
    }
    pub fn resource_admission(
        self,
    ) -> io::Result<Option<crate::tree_resources::SourceResourceAdmission>> {
        match self {
            Self::ResourceBoundedV4(Some(admission)) => {
                admission.validate()?;
                Ok(Some(admission))
            }
            Self::ResourceBoundedV4(None) => Err(io::Error::other(
                "resource profile has no complete frozen source admission",
            )),
            _ => Ok(None),
        }
    }
}
impl Request {
    pub fn limits(&self) -> ResourceLimits {
        self.resource_profile.map_or(
            ResourceLimits {
                maximum_identities: MAX_FILES,
                maximum_stream_bytes: u64::MAX,
                logical_read_bytes: crate::logical_hash::DEFAULT_LIMIT,
                logical_read_calls: u64::MAX,
                security_bytes: MAX_TOTAL_SECURITY_BYTES,
                stream_evidence_bytes: MAX_TOTAL_STREAM_BYTES,
                namespace_evidence_bytes: crate::namespace_layout::MAX_EVIDENCE,
            },
            ResourceProfile::limits,
        )
    }
}

pub fn source_bitmap_limits(
    profile: Option<ResourceProfile>,
    clusters: u64,
) -> io::Result<crate::bitmap_streaming::Limits> {
    if let Some(admission) = profile
        .map(ResourceProfile::resource_admission)
        .transpose()?
        .flatten()
    {
        crate::bitmap_streaming::resource_source_limits(
            clusters,
            admission.budget.max_row_bytes / 2,
        )
    } else {
        crate::bitmap_streaming::source_limits(clusters)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub record_number: u64,
    pub sequence_number: u16,
}
impl FileIdentity {
    pub fn reference(&self) -> u64 {
        self.record_number | (u64::from(self.sequence_number) << 48)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_profile: Option<ResourceProfile>,
    pub source_inspection_sha256: String,
    pub volume: String,
    pub disk_number: u32,
    pub partition_offset: u64,
    pub partition_length: u64,
    pub ntfs_serial: u64,
    pub files: Vec<FileIdentity>,
    /// Explicit schema4/6 read-elision requests. These are not content digests
    /// or source-write authority. Every raw byte extent is reconciled with a
    /// complete native retrieval map before eliding the logical read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extent_identity_streams: Vec<ExtentIdentityStream>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeRequestRow {
    pub identity: FileIdentity,
    pub extent_identity_streams: Vec<ExtentIdentityStream>,
}
/// Ordered selectors supplied by the retained, completely validated raw page
/// owner. This describes reads only; neither this trait nor its JSON supplies
/// a frozen source lease or fresh conversion authority.
pub trait NativeRequestDomain {
    fn header(&self) -> &Request;
    fn len(&self) -> usize;
    fn row(&self, index: usize) -> io::Result<Cow<'_, NativeRequestRow>>;
    fn identity(&self, index: usize) -> io::Result<FileIdentity> {
        Ok(self.row(index)?.identity.clone())
    }
    /// Optional exact Windows marker identities. This selects metadata reads
    /// only; the SDK issues a witness solely inside its protected native lease.
    fn windows_txf_metadata_identity(&self, _index: usize) -> io::Result<Option<FileIdentity>> {
        Ok(None)
    }
    /// Optional ordinary Windows object-ID identities; observation only.
    fn windows_object_id_identity(&self, _index: usize) -> io::Result<Option<FileIdentity>> {
        Ok(None)
    }
    fn revalidate(&self) -> io::Result<()>;
    fn require_paged_source(
        &self,
        _budget: crate::tree_resources::MetadataPageBudget,
        _semantic_bytes: u64,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "native selector requires the retained complete raw page owner",
        ))
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl NativeRequestDomain for Request {
    fn header(&self) -> &Request {
        self
    }
    fn len(&self) -> usize {
        self.files.len()
    }
    fn row(&self, index: usize) -> io::Result<Cow<'_, NativeRequestRow>> {
        let identity = self
            .files
            .get(index)
            .ok_or_else(|| io::Error::other("native request ordinal absent"))?;
        Ok(Cow::Owned(NativeRequestRow {
            identity: identity.clone(),
            extent_identity_streams: self
                .extent_identity_streams
                .iter()
                .filter(|s| s.identity == *identity)
                .cloned()
                .collect(),
        }))
    }
    fn revalidate(&self) -> io::Result<()> {
        self.validate()
    }
}
pub fn validate_native_request_domain(domain: &impl NativeRequestDomain) -> io::Result<()> {
    let header = domain.header();
    header.validate()?;
    if domain.len() != header.selected_count()? {
        return Err(io::Error::other("native selector complete count differs"));
    }
    if header.has_paged_selectors() {
        let admission = header
            .resource_profile
            .unwrap()
            .resource_admission()?
            .unwrap();
        domain.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
    }
    let mut previous = None;
    for i in 0..domain.len() {
        let row = domain.row(i)?;
        validate_request_row(header, &row)?;
        if header.has_paged_selectors() && previous.is_some_and(|n| n >= row.identity.record_number)
        {
            return Err(io::Error::other(
                "native selectors are not strict ordered unique base records",
            ));
        }
        previous = Some(row.identity.record_number);
    }
    domain.revalidate()
}
fn validate_request_row(header: &Request, row: &NativeRequestRow) -> io::Result<()> {
    if row.identity.record_number >= 1 << 48
        || row.identity.sequence_number == 0
        || (!header.uses_extent_identity() && !row.extent_identity_streams.is_empty())
    {
        return Err(io::Error::other("invalid native selector row"));
    }
    let mut names = BTreeSet::new();
    for stream in &row.extent_identity_streams {
        if let Some(admission) = header
            .resource_profile
            .map(ResourceProfile::resource_admission)
            .transpose()?
            .flatten()
        {
            stream.validate_with_limit(
                header.partition_length,
                usize::try_from(admission.budget.max_row_bytes).map_err(io::Error::other)?
                    / std::mem::size_of::<ExtentIdentityExtent>(),
            )?;
        } else {
            stream.validate(header.partition_length)?;
        }
        if stream.identity != row.identity
            || !names.insert(&stream.name_utf16)
            || stream.logical_size > header.limits().maximum_stream_bytes
        {
            return Err(io::Error::other(
                "native selector stream identity or complete mapping differs",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtentIdentityExtent {
    pub logical_offset: u64,
    pub physical_offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtentIdentityStream {
    pub identity: FileIdentity,
    pub name_utf16: Vec<u16>,
    pub cluster_bytes: u32,
    pub logical_size: u64,
    pub allocated_size: u64,
    pub extents: Vec<ExtentIdentityExtent>,
}

impl ExtentIdentityStream {
    fn validate(&self, partition: u64) -> io::Result<()> {
        self.validate_with_limit(partition, crate::stream_layout::MAX_COMPLETE_EXTENTS)
    }
    fn validate_with_limit(&self, partition: u64, maximum_extents: usize) -> io::Result<()> {
        let fail = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid extent-identity stream request",
            )
        };
        let cluster = u64::from(self.cluster_bytes);
        if self.identity.record_number < 16
            || self.identity.record_number >= 1 << 48
            || self.identity.sequence_number == 0
            || !(4096..=2 * 1024 * 1024).contains(&self.cluster_bytes)
            || !self.cluster_bytes.is_power_of_two()
            // Source maps still cover all allocation through rounded EOF.
            // A partial logical tail is bound by exact EOF, not rounded away;
            // its target materialization is a separate semantic contract.
            || self.logical_size < 4096
            || self.logical_size > self.allocated_size
            || !self.allocated_size.is_multiple_of(cluster)
            || self.name_utf16.len() > 255
            || String::from_utf16(&self.name_utf16).is_err()
            || self
                .name_utf16
                .iter()
                .any(|n| matches!(*n, 0 | 0x2f | 0x5c | 0x3a))
            || self.extents.is_empty()
            || self.extents.len() > maximum_extents
        {
            return Err(fail());
        }
        let mut covered = 0;
        let mut physical = Vec::new();
        for e in &self.extents {
            if e.logical_offset != covered
                || e.length == 0
                || !e.length.is_multiple_of(cluster)
                || !e.physical_offset.is_multiple_of(cluster)
                || e.physical_offset
                    .checked_add(e.length)
                    .is_none_or(|end| end > partition)
            {
                return Err(fail());
            }
            covered = covered.checked_add(e.length).ok_or_else(fail)?;
            physical.push((e.physical_offset, e.physical_offset + e.length));
        }
        physical.sort_unstable();
        if covered != self.allocated_size || physical.windows(2).any(|p| p[0].1 > p[1].0) {
            return Err(fail());
        }
        Ok(())
    }
}
impl Request {
    pub fn requires_directory_case_sensitivity(&self) -> bool {
        matches!(self.schema_version, 5 | 6 | 7 | 8)
    }

    pub fn uses_extent_identity(&self) -> bool {
        matches!(self.schema_version, 4 | 6 | 8)
    }
    pub fn has_paged_selectors(&self) -> bool {
        matches!(self.schema_version, 7 | 8)
    }
    pub fn selected_count(&self) -> io::Result<usize> {
        if self.has_paged_selectors() {
            let admission = self
                .resource_profile
                .ok_or_else(|| io::Error::other("paged selection has no resource profile"))?
                .resource_admission()?
                .ok_or_else(|| io::Error::other("paged selection lacks complete admission"))?;
            usize::try_from(admission.raw_identities).map_err(io::Error::other)
        } else {
            Ok(self.files.len())
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        let guid = self
            .volume
            .strip_prefix(r"\\?\Volume{")
            .and_then(|s| s.strip_suffix("}\\"));
        let valid_guid = guid.is_some_and(|s| {
            s.len() == 36
                && s.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
                && s.bytes().any(|b| b != b'0' && b != b'-')
        });
        let mut ids = BTreeSet::new();
        let mut records = BTreeSet::new();
        let geometry_profile = match self.schema_version {
            1 => {
                self.disk_number <= 255
                    && self
                        .partition_offset
                        .checked_add(self.partition_length)
                        .is_some_and(|n| n <= 64 * 1024 * 1024 * 1024)
            }
            2 | 5 if self.resource_profile.is_none() => {
                self.disk_number <= 4095
                    && self
                        .partition_offset
                        .checked_add(self.partition_length)
                        .is_some_and(|n| n <= 64 * 1024 * 1024 * 1024 * 1024)
            }
            3 | 4 | 5 | 6 | 7 | 8 => {
                (self.disk_number <= 4095
                    || matches!(
                        self.resource_profile,
                        Some(ResourceProfile::ResourceBoundedV4(_))
                    ))
                    && self.resource_profile.is_some_and(|profile| {
                        self.partition_length <= profile.maximum_partition_bytes()
                    })
                    && self
                        .partition_offset
                        .checked_add(self.partition_length)
                        .is_some_and(|end| end <= i64::MAX as u64)
            }
            _ => false,
        };
        if !geometry_profile
            || !matches!(
                (self.schema_version, self.resource_profile),
                (1 | 2 | 5, None)
                    | (
                        3 | 4 | 5 | 6 | 7 | 8,
                        Some(
                            ResourceProfile::ExperimentalLargeTreeV1
                                | ResourceProfile::ExperimentalStreamingTreeV2
                                | ResourceProfile::ExperimentalObjectEnvelopeV3(_)
                                | ResourceProfile::ResourceBoundedV4(_)
                        )
                    )
            )
            || !valid_guid
            || (self.schema_version == 1 && self.disk_number == 0)
            || self.partition_offset == 0
            || !self.partition_offset.is_multiple_of(4096)
            || self.partition_length == 0
            || !self.partition_length.is_multiple_of(4096)
            || self.ntfs_serial == 0
            || (!self.has_paged_selectors()
                && (self.files.is_empty() || self.files.len() > self.limits().maximum_identities))
            || (self.has_paged_selectors()
                && (!self.files.is_empty()
                    || !self.extent_identity_streams.is_empty()
                    || !matches!(
                        self.resource_profile,
                        Some(ResourceProfile::ResourceBoundedV4(Some(_)))
                    )))
            || self.source_inspection_sha256.len() != 64
            || !self
                .source_inspection_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.files.iter().any(|f| {
                f.record_number >= 1 << 48
                    || f.sequence_number == 0
                    || !ids.insert(f.reference())
                    || (self.schema_version >= 3 && !records.insert(f.record_number))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded native-attestation request",
            ));
        }
        if let Some(admission) = self
            .resource_profile
            .map(ResourceProfile::count_admission)
            .transpose()?
            .flatten()
        {
            if self.files.len() != admission.raw_identities as usize
                || self.source_inspection_sha256 != hex::encode(admission.source_inspection_sha256)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "native identities or inspection pin differ from admitted source counts",
                ));
            }
        }
        if let Some(admission) = self
            .resource_profile
            .map(ResourceProfile::resource_admission)
            .transpose()?
            .flatten()
        {
            if self.selected_count()? as u64 != admission.raw_identities
                || self.source_inspection_sha256 != hex::encode(admission.source_inspection_sha256)
            {
                return Err(io::Error::other(
                    "native selection differs from resource admitted complete source",
                ));
            }
        }
        if !self.uses_extent_identity() && !self.extent_identity_streams.is_empty()
            || self.uses_extent_identity()
                && !self
                    .resource_profile
                    .is_some_and(ResourceProfile::is_streaming)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "extent read elision requires schema4/6 streaming evidence",
            ));
        }
        let mut streams = BTreeSet::new();
        let mut extent_bytes = 0usize;
        for stream in &self.extent_identity_streams {
            stream.validate(self.partition_length)?;
            if !ids.contains(&stream.identity.reference())
                || stream.logical_size > self.limits().maximum_stream_bytes
                || !streams.insert((stream.identity.reference(), stream.name_utf16.clone()))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ambiguous extent-identity stream request",
                ));
            }
            extent_bytes = stream
                .extents
                .len()
                .checked_mul(std::mem::size_of::<ExtentIdentityExtent>())
                .and_then(|n| extent_bytes.checked_add(n))
                .filter(|n| *n <= self.limits().stream_evidence_bytes)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "extent-identity request resource budget exceeded",
                    )
                })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn general_request_extends_disk_bounds_without_widening_lab_schema() {
        let mut request = Request {
            schema_version: 1,
            resource_profile: None,
            source_inspection_sha256: "a".repeat(64),
            volume: "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\".into(),
            disk_number: 300,
            partition_offset: 1 << 20,
            partition_length: 4 << 30,
            ntfs_serial: 1,
            files: vec![FileIdentity {
                record_number: 5,
                sequence_number: 1,
            }],
            extent_identity_streams: Vec::new(),
        };
        assert!(request.validate().is_err());
        request.schema_version = 2;
        request.validate().unwrap();
        request.partition_offset = u64::MAX - 4095;
        assert!(request.validate().is_err());
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Query {
    pub class: i32,
    pub bytes: Vec<u8>,
    pub native_error: Option<i32>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReparseObservation {
    /// Complete supported reparse data from this same held object. None with
    /// no error is an observed absence, not a failed query.
    pub point: Option<crate::reparse_layout::Point>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub queries: Vec<Query>,
    pub security: Vec<u8>,
    pub security_error: Option<i32>,
    #[serde(default)]
    pub kernel_security: Option<SecurityQuery>,
    /// Complete file-level EA set. Some(empty) is an observed absence; None
    /// means the caller did not query EAs or the query failed. Named stream
    /// snapshots deliberately omit this file-level observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_attributes: Option<crate::extended_attributes::Set>,
    /// Native status or structural failure is explicit and never an empty set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_attributes_error: Option<String>,
    /// Canonical file/directory observation only. Missing in legacy reports
    /// and deliberately absent on named DATA-stream payload snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse: Option<ReparseObservation>,
    /// FileCaseSensitiveInfo on this same canonical directory handle. Missing
    /// legacy evidence is Unknown, never a recorded case-insensitive result.
    /// DATA-stream snapshots and actual nondirectories deliberately omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_case_sensitivity: Option<Query>,
}

impl Snapshot {
    fn validate_case_query(query: &Query) -> io::Result<()> {
        if query.class == 23
            && match query.native_error {
                None => query.bytes.len() == 4,
                Some(_) => query.bytes.is_empty(),
            }
        {
            // Unknown flag bits remain diagnostic evidence. Fresh source
            // admission separately rejects nonzero/error/missing/unstable.
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native directory case query is contradictory or malformed",
            ))
        }
    }

    pub fn validate_directory_case_sensitivity(&self, required: bool) -> io::Result<()> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native directory case evidence does not match its report or actual object type",
            )
        };
        if !required {
            return if self.directory_case_sensitivity.is_none() {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        let mut standard = self.queries.iter().filter(|query| query.class == 1);
        let actual_directory = match (standard.next(), standard.next()) {
            (Some(query), None) if query.native_error.is_none() && query.bytes.len() == 24 => {
                Some(query.bytes[21] != 0)
            }
            // An unsuccessful type query proves neither directory nor file.
            // Its metadata error remains for higher-level refusal, and no
            // missing case observation can be interpreted as flags zero.
            _ => None,
        };
        match (actual_directory, &self.directory_case_sensitivity) {
            (Some(true), Some(query)) => Self::validate_case_query(query),
            (Some(false) | None, None) => Ok(()),
            _ => Err(invalid()),
        }
    }

    pub(crate) fn directory_case_sensitivity_bytes(&self) -> io::Result<usize> {
        match &self.directory_case_sensitivity {
            Some(query) => {
                Self::validate_case_query(query)?;
                Ok(query.bytes.len())
            }
            None => Ok(0),
        }
    }

    pub fn validate_reparse(&self, required: bool) -> io::Result<()> {
        match &self.reparse {
            Some(ReparseObservation {
                point: Some(point),
                error: None,
            }) => point.validate(),
            Some(ReparseObservation {
                point: None,
                error: None,
            }) => Ok(()),
            Some(ReparseObservation {
                point: None,
                error: Some(error),
            }) if !error.is_empty() && error.len() <= 4096 => Ok(()),
            None if !required => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native reparse observation is missing, contradictory or oversized",
            )),
        }
    }

    /// Stable retained payload accounting across JSON replay; no capacities
    /// or transient native allocation sizes become part of ResourceAudit.
    pub(crate) fn reparse_bytes(&self) -> io::Result<usize> {
        self.validate_reparse(false)?;
        let Some(observed) = &self.reparse else {
            return Ok(0);
        };
        let error_bytes = observed.error.as_ref().map_or(0, String::len);
        match &observed.point {
            Some(point) => point
                .buffer
                .len()
                .checked_add(error_bytes)
                .ok_or_else(|| io::Error::other("native reparse evidence accounting overflow")),
            None => Ok(error_bytes),
        }
    }

    /// Diagnostic consistency only; this does not authenticate saved reports
    /// or turn missing legacy evidence into a successful EA observation.
    pub fn validate_extended_attributes(&self, required: bool) -> io::Result<()> {
        match (&self.extended_attributes, &self.extended_attributes_error) {
            (Some(set), None) => set.validate(),
            (None, Some(error)) if !error.is_empty() && error.len() <= 4096 => Ok(()),
            (None, None) if !required => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native EA observation is missing, contradictory or exceeds its error bound",
            )),
        }
    }

    /// Stable payload accounting; allocation capacities are not reproducible
    /// after JSON replay and therefore cannot be part of ResourceAudit.
    pub(crate) fn extended_attribute_bytes(&self) -> io::Result<usize> {
        self.validate_extended_attributes(false)?;
        let mut bytes = self
            .extended_attributes_error
            .as_ref()
            .map_or(0, String::len);
        if let Some(set) = &self.extended_attributes {
            for entry in &set.entries {
                bytes = bytes
                    .checked_add(1)
                    .and_then(|n| n.checked_add(entry.name.len()))
                    .and_then(|n| n.checked_add(entry.value.len()))
                    .ok_or_else(|| io::Error::other("native EA evidence accounting overflow"))?;
            }
        }
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityQuery {
    pub bytes: Vec<u8>,
    pub native_error: Option<i32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub identity: FileIdentity,
    pub open_error: Option<i32>,
    pub before: Option<Snapshot>,
    pub after: Option<Snapshot>,
    #[serde(default)]
    pub streams_before: Option<StreamCapture>,
    #[serde(default)]
    pub streams_after: Option<StreamCapture>,
    /// New source-only reports may read identity/type/case with READ_ATTRIBUTES
    /// when the original broader metadata/security open failed. That original
    /// failure is retained and this never supplies security or stream evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_only_fallback: Option<DirectoryCaseFallback>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryCaseFallback {
    pub access_mask: u32,
    pub open_error: Option<i32>,
    pub before: Option<DirectoryCaseSnapshot>,
    pub after: Option<DirectoryCaseSnapshot>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryCaseSnapshot {
    pub queries: Vec<Query>,
    pub directory_case_sensitivity: Option<Query>,
}
impl DirectoryCaseFallback {
    pub(crate) fn validate(&self) -> io::Result<()> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "read-attributes-only directory case fallback is malformed",
            )
        };
        if self.access_mask != 0x80 {
            return Err(invalid());
        }
        if self.open_error.is_some() {
            return if self.before.is_none() && self.after.is_none() {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        let (Some(before), Some(after)) = (&self.before, &self.after) else {
            return Err(invalid());
        };
        for snapshot in [before, after] {
            if snapshot.queries.len() != 3 {
                return Err(invalid());
            }
            for (query, (class, length)) in
                snapshot.queries.iter().zip([(0, 40), (1, 24), (18, 24)])
            {
                if query.class != class
                    || (query.native_error.is_none() && query.bytes.len() != length)
                    || (query.native_error.is_some() && !query.bytes.is_empty())
                {
                    return Err(invalid());
                }
            }
            let standard = &snapshot.queries[1];
            let directory = standard.native_error.is_none() && standard.bytes.get(21) == Some(&1);
            match (directory, &snapshot.directory_case_sensitivity) {
                (true, Some(query)) => Snapshot::validate_case_query(query)?,
                (false, None) => (),
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }
    pub(crate) fn retained_bytes(&self) -> io::Result<usize> {
        self.validate()?;
        self.before
            .iter()
            .chain(self.after.iter())
            .try_fold(0usize, |total, snapshot| {
                snapshot
                    .queries
                    .iter()
                    .chain(snapshot.directory_case_sensitivity.iter())
                    .try_fold(total, |total, query| {
                        total.checked_add(query.bytes.len()).ok_or_else(|| {
                            io::Error::other("case fallback evidence accounting overflow")
                        })
                    })
            })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceAudit>,
    pub request: Request,
    pub volume_extents_before: Vec<u8>,
    pub volume_extents_after: Vec<u8>,
    pub ntfs_data_before: Vec<u8>,
    pub ntfs_data_after: Vec<u8>,
    pub disk_attributes_before: Vec<u8>,
    pub disk_attributes_after: Vec<u8>,
    pub write_protect_error_before: i32,
    pub write_protect_error_after: i32,
    pub privileges_restored: bool,
    pub privilege_states: Vec<PrivilegeState>,
    pub files: Vec<Observation>,
    pub conversion_qualified: bool,
    #[serde(default)]
    pub allocation: Option<VolumeAllocation>,
    #[serde(default)]
    pub logical_data: Option<LogicalData>,
    #[serde(default)]
    pub namespace: Option<NamespaceData>,
    /// 2: each stream's content is read twice through its open handle. 1: read
    /// once and mirrored, with stability proven by the caller's bracket over the
    /// frozen, physically read-only source (allocation-bounded mode).
    #[serde(default = "two_content_passes")]
    pub content_passes: u8,
}

/// Complete source evidence with one owned row at a time. The header retains
/// the exact native request, allocation and protection bracket; a paged header
/// has empty row tables. This interface itself grants no live source authority.
mod row_view;
pub use row_view::NativeObservationRow;

pub trait NativeObservationDomain {
    fn header(&self) -> &Report;
    fn len(&self) -> usize;
    fn logical_len(&self) -> usize;
    fn namespace_len(&self) -> usize;
    fn observation(&self, index: usize) -> io::Result<Cow<'_, Observation>>;
    fn logical_file(&self, index: usize) -> io::Result<Cow<'_, LogicalFile>>;
    fn namespace_file(&self, index: usize) -> io::Result<Cow<'_, NamespaceFile>>;
    /// The returned non-Clone owner retains any actual shared-memory lease
    /// through every borrowed field view. Historical Cow APIs stay available.
    fn row_view(&self, index: usize) -> io::Result<NativeObservationRow<'_>> {
        Ok(NativeObservationRow::new(
            self.request_row(index)?,
            self.observation(index)?,
            (index < self.logical_len())
                .then(|| self.logical_file(index))
                .transpose()?,
            (index < self.namespace_len())
                .then(|| self.namespace_file(index))
                .transpose()?,
        ))
    }
    fn request_row(&self, index: usize) -> io::Result<Cow<'_, NativeRequestRow>> {
        self.header().request.row(index)
    }
    fn request_len(&self) -> io::Result<usize> {
        self.header().request.selected_count()
    }
    fn revalidate(&self) -> io::Result<()>;
    fn validate_encoded_size(&self, maximum: usize) -> io::Result<()>;
    fn maximum_security_descriptor_bytes(&self) -> usize {
        MAX_SECURITY_BYTES
    }
    /// A temporary SDK validation index must use the real source accountant
    /// when this domain owns one. Historical unaccounted diagnostics retain
    /// their existing behavior; this never issues source or write authority.
    fn reserve_validation_working(&self, _bytes: u64) -> io::Result<Option<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>> {
        Ok(None)
    }
    fn is_paged(&self) -> bool {
        false
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl NativeObservationDomain for Report {
    fn header(&self) -> &Report {
        self
    }
    fn len(&self) -> usize {
        self.files.len()
    }
    fn logical_len(&self) -> usize {
        self.logical_data.as_ref().map_or(0, |d| d.files.len())
    }
    fn namespace_len(&self) -> usize {
        self.namespace.as_ref().map_or(0, |d| d.files.len())
    }
    fn observation(&self, index: usize) -> io::Result<Cow<'_, Observation>> {
        self.files
            .get(index)
            .map(Cow::Borrowed)
            .ok_or_else(|| io::Error::other("missing native observation row"))
    }
    fn logical_file(&self, index: usize) -> io::Result<Cow<'_, LogicalFile>> {
        self.logical_data
            .as_ref()
            .and_then(|d| d.files.get(index))
            .map(Cow::Borrowed)
            .ok_or_else(|| io::Error::other("missing native logical row"))
    }
    fn namespace_file(&self, index: usize) -> io::Result<Cow<'_, NamespaceFile>> {
        self.namespace
            .as_ref()
            .and_then(|d| d.files.get(index))
            .map(Cow::Borrowed)
            .ok_or_else(|| io::Error::other("missing native namespace row"))
    }
    fn revalidate(&self) -> io::Result<()> {
        Ok(())
    }
    fn validate_encoded_size(&self, maximum: usize) -> io::Result<()> {
        self.serialized_size_bounded(maximum).map(|_| ())
    }
}
fn two_content_passes() -> u8 {
    2
}
/// Retained evidence payload bytes; table counts and individual responses are
/// independently bounded. This is not a measurement of process RSS.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceAudit {
    pub profile: ResourceProfile,
    pub security_bytes: u64,
    pub stream_evidence_bytes: u64,
    pub bitmap_evidence_bytes: u64,
    pub namespace_evidence_bytes: u64,
}
impl ResourceAudit {
    pub(crate) fn merge(&mut self, row: Self) -> io::Result<()> {
        if self.profile != row.profile {
            return Err(io::Error::other("native resource profiles differ"));
        }
        let sum = |a: u64, b: u64| {
            a.checked_add(b)
                .ok_or_else(|| io::Error::other("native evidence accounting overflow"))
        };
        self.security_bytes = sum(self.security_bytes, row.security_bytes)?;
        self.stream_evidence_bytes = sum(self.stream_evidence_bytes, row.stream_evidence_bytes)?;
        self.bitmap_evidence_bytes = sum(self.bitmap_evidence_bytes, row.bitmap_evidence_bytes)?;
        self.namespace_evidence_bytes =
            sum(self.namespace_evidence_bytes, row.namespace_evidence_bytes)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamespaceData {
    pub files: Vec<NamespaceFile>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamespaceFile {
    pub identity: FileIdentity,
    pub open_error: Option<i32>,
    pub identity_before: Option<Query>,
    pub identity_after: Option<Query>,
    pub standard: Option<Query>,
    pub before: Option<DirectoryCapture>,
    pub after: Option<DirectoryCapture>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryCapture {
    pub calls: Vec<Query>,
    pub refusal: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IoctlQuery {
    pub code: u32,
    pub input: Vec<u8>,
    #[serde(with = "ioctl_bytes")]
    pub bytes: Vec<u8>,
    pub native_error: Option<i32>,
}
mod ioctl_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    const MAX: usize = crate::bitmap_paging::PAGE_BYTES;
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if bytes.len() > MAX {
            return Err(serde::ser::Error::custom("native IOCTL blob exceeds bound"));
        }
        serializer.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Hex(String),
            Legacy(Vec<u8>),
        }
        match Wire::deserialize(deserializer)? {
            Wire::Hex(text) => {
                if text.len() > MAX * 2 {
                    return Err(serde::de::Error::custom("native IOCTL hex exceeds bound"));
                }
                hex::decode(text).map_err(serde::de::Error::custom)
            }
            Wire::Legacy(bytes) => {
                if bytes.len() > MAX {
                    return Err(serde::de::Error::custom("native IOCTL bytes exceed bound"));
                }
                Ok(bytes)
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamQuery {
    pub name_utf16: Vec<u16>,
    pub logical_size: u64,
    pub allocated_size: u64,
    pub open_error: Option<i32>,
    pub binding_error: Option<String>,
    pub identity_before: Option<Query>,
    pub identity_after: Option<Query>,
    pub retrieval: Option<IoctlQuery>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retrieval_continuation: Vec<IoctlQuery>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamCapture {
    pub enumeration: Query,
    pub parse_error: Option<String>,
    pub streams: Vec<StreamQuery>,
}
impl StreamCapture {
    #[cfg(windows)]
    pub(crate) fn retained_bytes(&self) -> usize {
        let mut n = self.enumeration.bytes.capacity()
            + self.parse_error.as_ref().map_or(0, String::capacity)
            + self.streams.capacity() * std::mem::size_of::<StreamQuery>();
        for q in &self.streams {
            n = n.saturating_add(
                q.name_utf16.capacity() * 2 + q.binding_error.as_ref().map_or(0, String::capacity),
            );
            for id in [&q.identity_before, &q.identity_after]
                .into_iter()
                .flatten()
            {
                n = n.saturating_add(id.bytes.capacity());
            }
            if let Some(r) = &q.retrieval {
                n = n.saturating_add(r.bytes.capacity() + r.input.capacity());
            }
            n = n.saturating_add(
                q.retrieval_continuation.capacity() * std::mem::size_of::<IoctlQuery>(),
            );
            for r in &q.retrieval_continuation {
                n = n.saturating_add(r.bytes.capacity() + r.input.capacity());
            }
        }
        n
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VolumeAllocation {
    pub base_before: IoctlQuery,
    pub base_after: IoctlQuery,
    pub bitmap_before: IoctlQuery,
    pub bitmap_after: IoctlQuery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bitmap_before_continuation: Vec<IoctlQuery>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bitmap_after_continuation: Vec<IoctlQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streamed_before: Option<crate::bitmap_streaming::Summary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streamed_after: Option<crate::bitmap_streaming::Summary>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivilegeState {
    pub name: String,
    pub before: u32,
    pub enabled: u32,
    pub restored: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamHash {
    pub name_utf16: Vec<u16>,
    pub logical_size: u64,
    pub identity_before: Option<Query>,
    pub identity_after: Option<Query>,
    pub standard_before: Option<Query>,
    pub standard_after: Option<Query>,
    pub outcome: crate::logical_hash::Outcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogicalFile {
    pub identity: FileIdentity,
    pub before: Vec<StreamHash>,
    pub after: Vec<StreamHash>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogicalData {
    pub audit: crate::logical_hash::Audit,
    pub files: Vec<LogicalFile>,
}
#[cfg(windows)]
pub(crate) fn hash_retained_bytes(items: &Vec<StreamHash>) -> usize {
    let mut bytes = items.capacity() * std::mem::size_of::<StreamHash>();
    for h in items {
        bytes = bytes.saturating_add(
            h.name_utf16.capacity() * 2
                + h.outcome.sha256.as_ref().map_or(0, String::capacity)
                + h.outcome.detail.as_ref().map_or(0, String::capacity),
        );
        for q in [
            &h.identity_before,
            &h.identity_after,
            &h.standard_before,
            &h.standard_after,
        ]
        .into_iter()
        .flatten()
        {
            bytes = bytes.saturating_add(q.bytes.capacity());
        }
    }
    bytes
}

impl Report {
    /// Recompute payload accounting from the evidence, never from JSON success
    /// flags. Vector/table counts are checked separately by the replay paths.
    pub fn measured_resources(&self, profile: ResourceProfile) -> io::Result<ResourceAudit> {
        measured_domain_resources(self, profile)
    }
    /// Count the actual JSON encoding without materializing an output Vec.
    /// This catches numeric-array and hexadecimal expansion before the caller's
    /// existing 64 MiB artifact writer allocates the serialized report.
    pub fn serialized_size_bounded(&self, maximum: usize) -> io::Result<usize> {
        struct Counter {
            bytes: usize,
            maximum: usize,
        }
        impl io::Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let next = self
                    .bytes
                    .checked_add(bytes.len())
                    .ok_or_else(|| io::Error::other("native report encoded-size overflow"))?;
                if next > self.maximum {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "native report encoded-size limit exceeded",
                    ));
                }
                self.bytes = next;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut counter = Counter { bytes: 0, maximum };
        serde_json::to_writer_pretty(&mut counter, self).map_err(io::Error::other)?;
        Ok(counter.bytes)
    }

    pub fn validate_resources(&self) -> io::Result<()> {
        validate_domain_resources(self)
    }
}

/// Recompute complete evidence accounting without retaining row collections.
pub fn measured_domain_resources(
    domain: &impl NativeObservationDomain,
    profile: ResourceProfile,
) -> io::Result<ResourceAudit> {
    let header = domain.header();
    let mut out = ResourceAudit {
        profile,
        security_bytes: 0,
        stream_evidence_bytes: 0,
        bitmap_evidence_bytes: 0,
        namespace_evidence_bytes: 0,
    };
    // A paged row view already decodes all three parallel columns. Account
    // them together, rather than decoding that same authenticated row three
    // times. Irregular and legacy domains retain their existing traversal.
    let parallel = domain.is_paged()
        && header.logical_data.is_some() && header.namespace.is_some()
        && domain.len() == domain.logical_len() && domain.len() == domain.namespace_len();
    if parallel {
        for index in 0..domain.len() {
            let owner=domain.row_view(index)?;
            out.merge(measured_row_resources(profile,Some(owner.observation()),
                Some(owner.logical()?),Some(owner.namespace()?))?)?;
        }
    }else{
        for index in 0..domain.len() {
            let owner = domain.row_view(index)?;
            let row = owner.observation();
            out.merge(measured_row_resources(profile, Some(&row), None, None)?)?;
        }
    }
    if !parallel && header.logical_data.is_some() {
        for index in 0..domain.logical_len() {
            let owner = domain.row_view(index)?;
            let row = owner.logical()?;
            out.merge(measured_row_resources(profile, None, Some(&row), None)?)?;
        }
    }
    measured_allocation_resources(&mut out, header, profile)?;

    if !parallel && header.namespace.is_some() {
        for index in 0..domain.namespace_len() {
            let owner = domain.row_view(index)?;
            let row = owner.namespace()?;
            out.merge(measured_row_resources(profile, None, None, Some(&row))?)?;
        }
    }
    Ok(out)
}

fn measured_allocation_resources(out: &mut ResourceAudit, header: &Report, profile: ResourceProfile) -> io::Result<()> {
    fn add(total: &mut u64, n: usize) -> io::Result<()> {
        *total = total
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("native evidence accounting overflow"))?;
        Ok(())
    }
    fn ioctl(total: &mut u64, q: &IoctlQuery) -> io::Result<()> {
        add(total, q.input.len())?;
        add(total, q.bytes.len())
    }
    if let Some(a) = &header.allocation {
        ioctl(&mut out.stream_evidence_bytes, &a.base_before)?;
        ioctl(&mut out.stream_evidence_bytes, &a.base_after)?;
        for q in std::iter::once(&a.bitmap_before)
            .chain(&a.bitmap_before_continuation)
            .chain(std::iter::once(&a.bitmap_after))
            .chain(&a.bitmap_after_continuation)
        {
            ioctl(&mut out.bitmap_evidence_bytes, q)?;
        }
        for summary in a.streamed_before.iter().chain(a.streamed_after.iter()) {
            summary.validate(
                summary.cluster_count,
                source_bitmap_limits(Some(profile), summary.cluster_count)?,
            )?;
            add(
                &mut out.bitmap_evidence_bytes,
                summary.encoding.len()
                    + summary.bitmap_data_sha256.len()
                    + summary.canonical_bitmap_sha256.len()
                    + summary.page_transcript_sha256.len()
                    + 7 * 8
                    + 4,
            )?;
            add(
                &mut out.bitmap_evidence_bytes,
                summary.allocated_ranges.len()
                    * std::mem::size_of::<crate::bitmap_streaming::ClusterRange>(),
            )?;
        }
    }
    Ok(())
}


/// Validate the same native evidence rules through borrowed or paged rows.
pub fn validate_domain_resources(domain: &impl NativeObservationDomain) -> io::Result<()> {
    let h = domain.header();
    if domain.is_paged() && h.schema_version == 16 && h.request.schema_version == 8
        && h.request.resource_profile.is_some() && h.logical_data.is_some() && h.namespace.is_some()
        && domain.len() == domain.logical_len() && domain.len() == domain.namespace_len()
        && domain.request_len().is_ok_and(|n| n == domain.len()) {
        return validate_regular_paged_resources(domain, domain.len());
    }
    validate_domain_resources_irregular(domain)
}

fn mark_native_identity(identities: &mut std::collections::BTreeMap<u64, u8>, identity: u64, bit: u8, count: usize) -> io::Result<u8> {
    if let Some(flags) = identities.get_mut(&identity) {
        let old = *flags; *flags |= bit; return Ok(old);
    }
    // A union larger than the number of unique requested identities cannot
    // satisfy any of the original same_ids checks. Refuse BEFORE allocating
    // an entry beyond the prepaid count, including on malformed domains.
    if identities.len() == count {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "native report resource profile or accounting differs"));
    }
    identities.insert(identity, bit);
    Ok(0)
}

/// The regular schema8/report16 parallel form decodes each authenticated
/// file/namespace pair exactly once. Every legacy/irregular rule remains in
/// the original validator below; this path repeats its complete predicates.
fn validate_regular_paged_resources(domain: &impl NativeObservationDomain, count: usize) -> io::Result<()> {
    let header = domain.header();
    let invalid = || io::Error::new(io::ErrorKind::InvalidData,
        "native report resource profile or accounting differs");
    let Some(profile) = header.request.resource_profile else {
        let legacy = (2..=7).contains(&header.schema_version)
            && matches!(header.request.schema_version, 1 | 2);
        let canonical_case = header.schema_version == 13 && header.request.schema_version == 5;
        if canonical_case {
            header.request.validate()?;
        }
        return if (legacy || canonical_case)
            && header.resources.is_none()
            && header
                .allocation
                .as_ref()
                .is_none_or(|a| a.streamed_before.is_none() && a.streamed_after.is_none())
        {
            Ok(())
        } else {
            Err(invalid())
        };
    };
    header.request.validate()?;
    if !matches!(
        (header.request.schema_version, header.schema_version),
        (3, 8 | 9 | 10 | 11) | (4, 12) | (5, 13) | (6, 14) | (7, 15) | (8, 16)
    ) {
        return Err(invalid());
    }
    let limits = profile.limits();
    let resource_admission = profile.resource_admission()?;
    if resource_admission.is_some() && !domain.is_paged() {
        return Err(invalid());
    }
    let maximum_retrieval_pages = resource_admission
        .map(|a| {
            usize::try_from(a.budget.max_row_bytes)
                .map_err(io::Error::other)
                .and_then(crate::retrieval_paging::Limits::for_resource_bytes)
                .map(|l| l.max_pages)
        })
        .transpose()?
        .unwrap_or(crate::retrieval_paging::MAX_PAGES);
    let a = header.resources.as_ref().ok_or_else(invalid)?;
    let data = header.logical_data.as_ref().ok_or_else(invalid)?;
    let _namespace = header.namespace.as_ref().ok_or_else(invalid)?;
    let allocation = header.allocation.as_ref().ok_or_else(invalid)?;
    if matches!(header.schema_version, 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16) {
        allocation
            .streamed_before
            .as_ref()
            .ok_or_else(invalid)?
            .validate_source_first_with_limits(
                &allocation.bitmap_before,
                source_bitmap_limits(
                    Some(profile),
                    allocation.streamed_before.as_ref().unwrap().cluster_count,
                )?,
            )?;
        allocation
            .streamed_after
            .as_ref()
            .ok_or_else(invalid)?
            .validate_source_first_with_limits(
                &allocation.bitmap_after,
                source_bitmap_limits(
                    Some(profile),
                    allocation.streamed_after.as_ref().unwrap().cluster_count,
                )?,
            )?;
    }
    // Same conservative pinned-BTree bound used by domain_memory: three
    // complete internal nodes per insertion, including split/root growth.
    let per_identity = (std::mem::size_of::<u64>() + std::mem::size_of::<u8>()
        + std::mem::size_of::<usize>()) as u64;
    let identity_bytes = (count as u64).checked_mul(3)
        .and_then(|n| per_identity.checked_mul(16).and_then(|node| node.checked_add(256))
            .and_then(|node| n.checked_mul(node)))
        .and_then(|n| n.checked_add(4096)).ok_or_else(invalid)?;
    // Declared BEFORE the map so storage drops before its actual payment.
    let _identity_memory = domain.reserve_validation_working(identity_bytes)?;
    let mut identities = std::collections::BTreeMap::<u64, u8>::new();
    let mut previous = None;
    let mut observed = 0u64;
    let mut complete_reservations = 0u64;
    let mut complete_streams = 0u64;
    if !matches!(header.content_passes, 1 | 2) { return Err(invalid()); }
    let mut bad_logical = false;
    let mut bad_observation = false;
    let mut bad_namespace = false;
    let mut actual = ResourceAudit { profile, security_bytes:0, stream_evidence_bytes:0,
        bitmap_evidence_bytes:0, namespace_evidence_bytes:0 };
    for index in 0..count {
        let owner = domain.row_view(index)?;
        let row = owner.request();
        validate_request_row(&header.request, &row)?;
        let flags = mark_native_identity(&mut identities, row.identity.reference(), 1, count)?;
        if flags & 1 != 0 || (header.request.has_paged_selectors()
            && previous.is_some_and(|n| n >= row.identity.record_number)) { return Err(invalid()); }
        previous = Some(row.identity.record_number);
        let file = owner.observation();
        if let Some(fallback) = &file.case_only_fallback {
            if !matches!(header.schema_version, 13 | 14 | 15 | 16)
                || file.open_error.is_none()
                || file.before.is_some()
                || file.after.is_some()
            {
                return Err(invalid());
            }
            fallback.validate()?;
        }
        for snapshot in file.before.iter().chain(file.after.iter()) {
            snapshot.validate_extended_attributes(matches!(
                header.schema_version,
                10 | 11 | 12 | 13 | 14 | 15 | 16
            ))?;
            snapshot
                .validate_reparse(matches!(header.schema_version, 11 | 12 | 13 | 14 | 15 | 16))?;
            snapshot.validate_directory_case_sensitivity(matches!(
                header.schema_version,
                13 | 14 | 15 | 16
            ))?;
        }
        let file = owner.logical()?;
        let selected = Some(owner.request());
        // A single content pass is mirrored into `after`; count it once.
        if header.content_passes == 1 && file.after != file.before {
            return Err(invalid());
        }
        let passes: &[&Vec<StreamHash>] = if header.content_passes == 1 {
            &[&file.before]
        } else {
            &[&file.before, &file.after]
        };
        for pass in passes.iter().copied() {
            if pass.len()
                > resource_admission.map_or(crate::stream_layout::MAX_STREAMS, |a| {
                    usize::try_from(a.budget.max_row_bytes).unwrap_or(0)
                        / std::mem::size_of::<StreamHash>()
                })
            {
                return Err(invalid());
            }
            for h in pass {
                if h.outcome.status == crate::logical_hash::Status::NotReadExtentIdentityV1
                    && (!matches!(
                        (header.request.schema_version, header.schema_version),
                        (4, 12) | (6, 14) | (8, 16)
                    ) || h.outcome.bytes_read != 0
                        || h.outcome.eof_confirmed
                        || h.outcome.sha256.is_some()
                        || h.outcome.native_error.is_some()
                        || h.outcome.detail.is_some()
                        || !selected
                            .as_ref()
                            .map_or(header.request.extent_identity_streams.as_slice(), |s| {
                                s.extent_identity_streams.as_slice()
                            })
                            .iter()
                            .any(|wanted| {
                                wanted.identity == file.identity
                                    && wanted.name_utf16 == h.name_utf16
                                    && wanted.logical_size == h.logical_size
                            }))
                {
                    return Err(invalid());
                }
                observed = observed
                    .checked_add(h.outcome.bytes_read)
                    .ok_or_else(invalid)?;
                let reservation = h.logical_size.checked_add(1).ok_or_else(invalid)?;
                if h.outcome.bytes_read > reservation {
                    return Err(invalid());
                }
                if h.outcome.status == crate::logical_hash::Status::Complete {
                    complete_reservations = complete_reservations
                        .checked_add(reservation)
                        .ok_or_else(invalid)?;
                    complete_streams = complete_streams.checked_add(1).ok_or_else(invalid)?;
                    if h.outcome.bytes_read != h.logical_size
                        || !h.outcome.eof_confirmed
                        || h.outcome.native_error.is_some()
                        || h.outcome.detail.is_some()
                        || !h
                            .outcome
                            .sha256
                            .as_deref()
                            .is_some_and(crate::content_digest::is_hex)
                    {
                        return Err(invalid());
                    }
                } else if h.outcome.sha256.is_some()
                    || h.outcome.eof_confirmed
                    || (h.outcome.status == crate::logical_hash::Status::BudgetExceeded
                        && h.outcome.bytes_read != 0)
                    || (h.outcome.status == crate::logical_hash::Status::ExpectedEofMissing
                        && h.outcome.bytes_read != reservation)
                {
                    return Err(invalid());
                }
            }
        }
        bad_logical |= file.before.iter().chain(&file.after).any(|h| {
            h.logical_size > limits.maximum_stream_bytes
                || h.name_utf16.len() > 255
                || h.identity_before
                    .iter()
                    .chain(h.identity_after.iter())
                    .chain(h.standard_before.iter())
                    .chain(h.standard_after.iter())
                    .any(|q| q.bytes.len() > 24)
        });
        let file = owner.observation();
        bad_observation |= {
            file.before.iter().chain(file.after.iter()).any(|s| {
                s.queries.len() > 4
                    || s.queries.iter().any(|q| q.bytes.len() > 40)
                    || s.security.len() > domain.maximum_security_descriptor_bytes()
                    || s.kernel_security
                        .as_ref()
                        .is_some_and(|s| s.bytes.len() > domain.maximum_security_descriptor_bytes())
            }) || file
                .streams_before
                .iter()
                .chain(file.streams_after.iter())
                .any(|c| {
                    c.streams.len()
                        > resource_admission.map_or(crate::stream_layout::MAX_STREAMS, |a| {
                            usize::try_from(a.budget.max_row_bytes).unwrap_or(0)
                                / std::mem::size_of::<StreamQuery>()
                        })
                        || c.enumeration.bytes.len()
                            > resource_admission
                                .map_or(crate::stream_layout::MAX_STREAM_BUFFER, |a| {
                                    usize::try_from(a.budget.max_row_bytes).unwrap_or(0)
                                })
                        || c.streams.iter().any(|s| {
                            s.name_utf16.len() > 255
                                || s.identity_before
                                    .iter()
                                    .chain(s.identity_after.iter())
                                    .any(|q| q.bytes.len() > 24)
                                || s.retrieval_continuation.len() >= maximum_retrieval_pages
                                || s.retrieval
                                    .iter()
                                    .chain(&s.retrieval_continuation)
                                    .any(|q| {
                                        q.bytes.len() > crate::retrieval_paging::PAGE_CAPACITY
                                            || q.input.len() > 8
                                    })
                        })
                })
        };
        let f = owner.namespace()?;
        bad_namespace |= {
            f.identity_before
                .iter()
                .chain(f.identity_after.iter())
                .chain(f.standard.iter())
                .any(|q| q.bytes.len() > 24)
                || f.before.iter().chain(f.after.iter()).any(|c| {
                    (!domain.is_paged() && c.calls.len() > crate::namespace_layout::MAX_CALLS)
                        || c.calls
                            .iter()
                            .any(|q| q.bytes.len() > crate::namespace_layout::CAPACITY)
                })
        };
        actual.merge(measured_row_resources(profile, Some(owner.observation()),
            Some(owner.logical()?), Some(owner.namespace()?))?)?;
        // Preserve the old THREE same_ids set checks, including valid
        // permutations, rather than adding a stronger per-row identity rule.
        // All four columns have count rows. A union of count unique requested
        // IDs with all membership bits set is exactly those set equalities;
        // duplicate/missing/unrequested IDs necessarily fail.
        for (identity, bit) in [(owner.observation().identity.reference(), 2),
            (owner.logical()?.identity.reference(), 4), (owner.namespace()?.identity.reference(), 8)] {
            mark_native_identity(&mut identities, identity, bit, count)?;
        }
    }
    measured_allocation_resources(&mut actual, header, profile)?;
    let streaming_shape = match header.schema_version {
        8 => allocation.streamed_before.is_none() && allocation.streamed_after.is_none(),
        9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 => {
            allocation.streamed_before.is_some()
                && allocation.streamed_after.is_some()
                && allocation.bitmap_before_continuation.is_empty()
                && allocation.bitmap_after_continuation.is_empty()
        }
        _ => false,
    };
    if !streaming_shape
        || header.conversion_qualified
        || header.allocation.is_none()
        || a != &actual
        || a.security_bytes > limits.security_bytes as u64
        || a.stream_evidence_bytes > limits.stream_evidence_bytes as u64
        || a.bitmap_evidence_bytes
            > resource_admission.map_or(MAX_TOTAL_BITMAP_BYTES as u64, |a| a.native_semantic_byte_budget())
        || a.namespace_evidence_bytes > limits.namespace_evidence_bytes as u64
        || identities.len() != count
        || identities.values().any(|flags| *flags != 15)
        || data.audit.limit_bytes != limits.logical_read_bytes
        || data.audit.reserved_bytes > limits.logical_read_bytes
        || data.audit.bytes_read > data.audit.reserved_bytes
        || data.audit.bytes_read != observed
        || data.audit.reserved_bytes < complete_reservations
        || data.audit.read_calls > limits.logical_read_calls
        || data.audit.eof_probes > data.audit.read_calls
        || data.audit.eof_probes < complete_streams
        || !data
            .audit
            .read_calls
            .checked_mul(crate::logical_hash::CHUNK as u64)
            .is_some_and(|maximum| observed <= maximum)
        || bad_logical
        || bad_observation
        || bad_namespace
        || allocation.bitmap_before_continuation.len() >= crate::bitmap_paging::MAX_PAGES
        || allocation.bitmap_after_continuation.len() >= crate::bitmap_paging::MAX_PAGES
        || std::iter::once(&allocation.bitmap_before)
            .chain(&allocation.bitmap_before_continuation)
            .chain(std::iter::once(&allocation.bitmap_after))
            .chain(&allocation.bitmap_after_continuation)
            .any(|q| q.bytes.len() > crate::bitmap_paging::PAGE_BYTES || q.input.len() > 16)
    {
        return Err(invalid());
    }
    let maximum = if let Some(admission) = resource_admission {
        usize::try_from(admission.native_semantic_byte_budget()).map_err(io::Error::other)?
    } else {
        header
            .request
            .resource_profile
            .map(ResourceProfile::count_admission)
            .transpose()?
            .flatten()
            .map_or(MAX_SERIALIZED_REPORT_BYTES, |a| {
                a.maximum_native_report_bytes as usize
            })
    };
    domain.validate_encoded_size(maximum)?;
    Ok(())
}

fn validate_domain_resources_irregular(domain: &impl NativeObservationDomain) -> io::Result<()> {
    let header = domain.header();
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native report resource profile or accounting differs",
        )
    };
    for index in 0..domain.len() {
        let owner = domain.row_view(index)?;
        let file = owner.observation();
        if let Some(fallback) = &file.case_only_fallback {
            if !matches!(header.schema_version, 13 | 14 | 15 | 16)
                || file.open_error.is_none()
                || file.before.is_some()
                || file.after.is_some()
            {
                return Err(invalid());
            }
            fallback.validate()?;
        }
        for snapshot in file.before.iter().chain(file.after.iter()) {
            snapshot.validate_extended_attributes(matches!(
                header.schema_version,
                10 | 11 | 12 | 13 | 14 | 15 | 16
            ))?;
            snapshot
                .validate_reparse(matches!(header.schema_version, 11 | 12 | 13 | 14 | 15 | 16))?;
            snapshot.validate_directory_case_sensitivity(matches!(
                header.schema_version,
                13 | 14 | 15 | 16
            ))?;
        }
    }
    let Some(profile) = header.request.resource_profile else {
        let legacy = (2..=7).contains(&header.schema_version)
            && matches!(header.request.schema_version, 1 | 2);
        let canonical_case = header.schema_version == 13 && header.request.schema_version == 5;
        if canonical_case {
            header.request.validate()?;
        }
        return if (legacy || canonical_case)
            && header.resources.is_none()
            && header
                .allocation
                .as_ref()
                .is_none_or(|a| a.streamed_before.is_none() && a.streamed_after.is_none())
        {
            Ok(())
        } else {
            Err(invalid())
        };
    };
    header.request.validate()?;
    if !matches!(
        (header.request.schema_version, header.schema_version),
        (3, 8 | 9 | 10 | 11) | (4, 12) | (5, 13) | (6, 14) | (7, 15) | (8, 16)
    ) {
        return Err(invalid());
    }
    let limits = profile.limits();
    let resource_admission = profile.resource_admission()?;
    if resource_admission.is_some() && !domain.is_paged() {
        return Err(invalid());
    }
    let maximum_retrieval_pages = resource_admission
        .map(|a| {
            usize::try_from(a.budget.max_row_bytes)
                .map_err(io::Error::other)
                .and_then(crate::retrieval_paging::Limits::for_resource_bytes)
                .map(|l| l.max_pages)
        })
        .transpose()?
        .unwrap_or(crate::retrieval_paging::MAX_PAGES);
    let a = header.resources.as_ref().ok_or_else(invalid)?;
    let data = header.logical_data.as_ref().ok_or_else(invalid)?;
    let _namespace = header.namespace.as_ref().ok_or_else(invalid)?;
    let allocation = header.allocation.as_ref().ok_or_else(invalid)?;
    if matches!(header.schema_version, 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16) {
        allocation
            .streamed_before
            .as_ref()
            .ok_or_else(invalid)?
            .validate_source_first_with_limits(
                &allocation.bitmap_before,
                source_bitmap_limits(
                    Some(profile),
                    allocation.streamed_before.as_ref().unwrap().cluster_count,
                )?,
            )?;
        allocation
            .streamed_after
            .as_ref()
            .ok_or_else(invalid)?
            .validate_source_first_with_limits(
                &allocation.bitmap_after,
                source_bitmap_limits(
                    Some(profile),
                    allocation.streamed_after.as_ref().unwrap().cluster_count,
                )?,
            )?;
    }
    let mut ids = BTreeSet::new();
    let mut previous = None;
    for i in 0..domain.request_len()? {
        let owner = domain.row_view(i)?;
        let row = owner.request();
        validate_request_row(&header.request, &row)?;
        if !ids.insert(row.identity.reference())
            || (header.request.has_paged_selectors()
                && previous.is_some_and(|n| n >= row.identity.record_number))
        {
            return Err(invalid());
        }
        previous = Some(row.identity.record_number);
    }
    let same_ids = |actual: Vec<u64>| {
        actual.len() == ids.len() && actual.iter().copied().collect::<BTreeSet<_>>() == ids
    };
    let mut observed = 0u64;
    let mut complete_reservations = 0u64;
    let mut complete_streams = 0u64;
    if !matches!(header.content_passes, 1 | 2) {
        return Err(invalid());
    }
    for index in 0..domain.logical_len() {
        let owner = domain.row_view(index)?;
        let file = owner.logical()?;
        let selected = if header.request.has_paged_selectors() {
            Some(owner.request())
        } else {
            None
        };
        // A single content pass is mirrored into `after`; count it once.
        if header.content_passes == 1 && file.after != file.before {
            return Err(invalid());
        }
        let passes: &[&Vec<StreamHash>] = if header.content_passes == 1 {
            &[&file.before]
        } else {
            &[&file.before, &file.after]
        };
        for pass in passes.iter().copied() {
            if pass.len()
                > resource_admission.map_or(crate::stream_layout::MAX_STREAMS, |a| {
                    usize::try_from(a.budget.max_row_bytes).unwrap_or(0)
                        / std::mem::size_of::<StreamHash>()
                })
            {
                return Err(invalid());
            }
            for h in pass {
                if h.outcome.status == crate::logical_hash::Status::NotReadExtentIdentityV1
                    && (!matches!(
                        (header.request.schema_version, header.schema_version),
                        (4, 12) | (6, 14) | (8, 16)
                    ) || h.outcome.bytes_read != 0
                        || h.outcome.eof_confirmed
                        || h.outcome.sha256.is_some()
                        || h.outcome.native_error.is_some()
                        || h.outcome.detail.is_some()
                        || !selected
                            .as_ref()
                            .map_or(header.request.extent_identity_streams.as_slice(), |s| {
                                s.extent_identity_streams.as_slice()
                            })
                            .iter()
                            .any(|wanted| {
                                wanted.identity == file.identity
                                    && wanted.name_utf16 == h.name_utf16
                                    && wanted.logical_size == h.logical_size
                            }))
                {
                    return Err(invalid());
                }
                observed = observed
                    .checked_add(h.outcome.bytes_read)
                    .ok_or_else(invalid)?;
                let reservation = h.logical_size.checked_add(1).ok_or_else(invalid)?;
                if h.outcome.bytes_read > reservation {
                    return Err(invalid());
                }
                if h.outcome.status == crate::logical_hash::Status::Complete {
                    complete_reservations = complete_reservations
                        .checked_add(reservation)
                        .ok_or_else(invalid)?;
                    complete_streams = complete_streams.checked_add(1).ok_or_else(invalid)?;
                    if h.outcome.bytes_read != h.logical_size
                        || !h.outcome.eof_confirmed
                        || h.outcome.native_error.is_some()
                        || h.outcome.detail.is_some()
                        || !h
                            .outcome
                            .sha256
                            .as_deref()
                            .is_some_and(crate::content_digest::is_hex)
                    {
                        return Err(invalid());
                    }
                } else if h.outcome.sha256.is_some()
                    || h.outcome.eof_confirmed
                    || (h.outcome.status == crate::logical_hash::Status::BudgetExceeded
                        && h.outcome.bytes_read != 0)
                    || (h.outcome.status == crate::logical_hash::Status::ExpectedEofMissing
                        && h.outcome.bytes_read != reservation)
                {
                    return Err(invalid());
                }
            }
        }
    }
    let streaming_shape = match header.schema_version {
        8 => allocation.streamed_before.is_none() && allocation.streamed_after.is_none(),
        9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 => {
            allocation.streamed_before.is_some()
                && allocation.streamed_after.is_some()
                && allocation.bitmap_before_continuation.is_empty()
                && allocation.bitmap_after_continuation.is_empty()
        }
        _ => false,
    };
    let mut bad_logical = false;
    for i in 0..domain.logical_len() {
        let owner = domain.row_view(i)?;
        let file = owner.logical()?;
        bad_logical |= file.before.iter().chain(&file.after).any(|h| {
            h.logical_size > limits.maximum_stream_bytes
                || h.name_utf16.len() > 255
                || h.identity_before
                    .iter()
                    .chain(h.identity_after.iter())
                    .chain(h.standard_before.iter())
                    .chain(h.standard_after.iter())
                    .any(|q| q.bytes.len() > 24)
        });
    }
    let mut bad_observation = false;
    for i in 0..domain.len() {
        let owner = domain.row_view(i)?;
        let file = owner.observation();
        bad_observation |= {
            file.before.iter().chain(file.after.iter()).any(|s| {
                s.queries.len() > 4
                    || s.queries.iter().any(|q| q.bytes.len() > 40)
                    || s.security.len() > domain.maximum_security_descriptor_bytes()
                    || s.kernel_security
                        .as_ref()
                        .is_some_and(|s| s.bytes.len() > domain.maximum_security_descriptor_bytes())
            }) || file
                .streams_before
                .iter()
                .chain(file.streams_after.iter())
                .any(|c| {
                    c.streams.len()
                        > resource_admission.map_or(crate::stream_layout::MAX_STREAMS, |a| {
                            usize::try_from(a.budget.max_row_bytes).unwrap_or(0)
                                / std::mem::size_of::<StreamQuery>()
                        })
                        || c.enumeration.bytes.len()
                            > resource_admission
                                .map_or(crate::stream_layout::MAX_STREAM_BUFFER, |a| {
                                    usize::try_from(a.budget.max_row_bytes).unwrap_or(0)
                                })
                        || c.streams.iter().any(|s| {
                            s.name_utf16.len() > 255
                                || s.identity_before
                                    .iter()
                                    .chain(s.identity_after.iter())
                                    .any(|q| q.bytes.len() > 24)
                                || s.retrieval_continuation.len() >= maximum_retrieval_pages
                                || s.retrieval
                                    .iter()
                                    .chain(&s.retrieval_continuation)
                                    .any(|q| {
                                        q.bytes.len() > crate::retrieval_paging::PAGE_CAPACITY
                                            || q.input.len() > 8
                                    })
                        })
                })
        };
    }
    let mut bad_namespace = false;
    for i in 0..domain.namespace_len() {
        let owner = domain.row_view(i)?;
        let f = owner.namespace()?;
        bad_namespace |= {
            f.identity_before
                .iter()
                .chain(f.identity_after.iter())
                .chain(f.standard.iter())
                .any(|q| q.bytes.len() > 24)
                || f.before.iter().chain(f.after.iter()).any(|c| {
                    (!domain.is_paged() && c.calls.len() > crate::namespace_layout::MAX_CALLS)
                        || c.calls
                            .iter()
                            .any(|q| q.bytes.len() > crate::namespace_layout::CAPACITY)
                })
        };
    }
    if !streaming_shape
        || header.conversion_qualified
        || header.allocation.is_none()
        || a != &measured_domain_resources(domain, profile)?
        || a.security_bytes > limits.security_bytes as u64
        || a.stream_evidence_bytes > limits.stream_evidence_bytes as u64
        || a.bitmap_evidence_bytes
            > resource_admission.map_or(MAX_TOTAL_BITMAP_BYTES as u64, |a| a.native_semantic_byte_budget())
        || a.namespace_evidence_bytes > limits.namespace_evidence_bytes as u64
        || !same_ids(
            (0..domain.len())
                .map(|i| {
                    domain
                        .row_view(i)
                        .map(|row| row.observation().identity.reference())
                })
                .collect::<io::Result<Vec<_>>>()?,
        )
        || !same_ids(
            (0..domain.logical_len())
                .map(|i| {
                    domain
                        .row_view(i)
                        .and_then(|row| Ok(row.logical()?.identity.reference()))
                })
                .collect::<io::Result<Vec<_>>>()?,
        )
        || !same_ids(
            (0..domain.namespace_len())
                .map(|i| {
                    domain
                        .row_view(i)
                        .and_then(|row| Ok(row.namespace()?.identity.reference()))
                })
                .collect::<io::Result<Vec<_>>>()?,
        )
        || data.audit.limit_bytes != limits.logical_read_bytes
        || data.audit.reserved_bytes > limits.logical_read_bytes
        || data.audit.bytes_read > data.audit.reserved_bytes
        || data.audit.bytes_read != observed
        || data.audit.reserved_bytes < complete_reservations
        || data.audit.read_calls > limits.logical_read_calls
        || data.audit.eof_probes > data.audit.read_calls
        || data.audit.eof_probes < complete_streams
        || !data
            .audit
            .read_calls
            .checked_mul(crate::logical_hash::CHUNK as u64)
            .is_some_and(|maximum| observed <= maximum)
        || bad_logical
        || bad_observation
        || bad_namespace
        || allocation.bitmap_before_continuation.len() >= crate::bitmap_paging::MAX_PAGES
        || allocation.bitmap_after_continuation.len() >= crate::bitmap_paging::MAX_PAGES
        || std::iter::once(&allocation.bitmap_before)
            .chain(&allocation.bitmap_before_continuation)
            .chain(std::iter::once(&allocation.bitmap_after))
            .chain(&allocation.bitmap_after_continuation)
            .any(|q| q.bytes.len() > crate::bitmap_paging::PAGE_BYTES || q.input.len() > 16)
    {
        return Err(invalid());
    }
    let maximum = if let Some(admission) = resource_admission {
        usize::try_from(admission.native_semantic_byte_budget()).map_err(io::Error::other)?
    } else {
        header
            .request
            .resource_profile
            .map(ResourceProfile::count_admission)
            .transpose()?
            .flatten()
            .map_or(MAX_SERIALIZED_REPORT_BYTES, |a| {
                a.maximum_native_report_bytes as usize
            })
    };
    domain.validate_encoded_size(maximum)?;
    Ok(())
}

/// Identical accounting for a collector row before its buffer is released.
pub(crate) fn measured_row_resources(
    profile: ResourceProfile,
    observation: Option<&Observation>,
    logical: Option<&LogicalFile>,
    namespace: Option<&NamespaceFile>,
) -> io::Result<ResourceAudit> {
    fn add(total: &mut u64, n: usize) -> io::Result<()> {
        *total = total
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("native evidence accounting overflow"))?;
        Ok(())
    }
    fn query(total: &mut u64, q: &Query) -> io::Result<()> {
        add(total, q.bytes.len())
    }
    fn ioctl(total: &mut u64, q: &IoctlQuery) -> io::Result<()> {
        add(total, q.input.len())?;
        add(total, q.bytes.len())
    }
    let mut out = ResourceAudit {
        profile,
        security_bytes: 0,
        stream_evidence_bytes: 0,
        bitmap_evidence_bytes: 0,
        namespace_evidence_bytes: 0,
    };
    if let Some(file) = observation {
        if let Some(fallback) = &file.case_only_fallback {
            add(&mut out.stream_evidence_bytes, fallback.retained_bytes()?)?;
        }
        for snapshot in file.before.iter().chain(file.after.iter()) {
            add(&mut out.security_bytes, snapshot.security.len())?;
            if let Some(s) = &snapshot.kernel_security {
                add(&mut out.security_bytes, s.bytes.len())?;
            }
            for q in &snapshot.queries {
                query(&mut out.stream_evidence_bytes, q)?;
            }
            add(
                &mut out.stream_evidence_bytes,
                snapshot.extended_attribute_bytes()?,
            )?;
            add(&mut out.stream_evidence_bytes, snapshot.reparse_bytes()?)?;
            add(
                &mut out.stream_evidence_bytes,
                snapshot.directory_case_sensitivity_bytes()?,
            )?;
        }
        for capture in file.streams_before.iter().chain(file.streams_after.iter()) {
            query(&mut out.stream_evidence_bytes, &capture.enumeration)?;
            add(
                &mut out.stream_evidence_bytes,
                capture.parse_error.as_ref().map_or(0, String::len),
            )?;
            for stream in &capture.streams {
                add(&mut out.stream_evidence_bytes, stream.name_utf16.len() * 2)?;
                add(
                    &mut out.stream_evidence_bytes,
                    stream.binding_error.as_ref().map_or(0, String::len),
                )?;
                for q in stream
                    .identity_before
                    .iter()
                    .chain(stream.identity_after.iter())
                {
                    query(&mut out.stream_evidence_bytes, q)?;
                }
                for q in stream
                    .retrieval
                    .iter()
                    .chain(&stream.retrieval_continuation)
                {
                    ioctl(&mut out.stream_evidence_bytes, q)?;
                }
            }
        }
    }
    if let Some(file) = logical {
        for stream in file.before.iter().chain(&file.after) {
            add(&mut out.stream_evidence_bytes, stream.name_utf16.len() * 2)?;
            add(
                &mut out.stream_evidence_bytes,
                stream.outcome.sha256.as_ref().map_or(0, String::len),
            )?;
            add(
                &mut out.stream_evidence_bytes,
                stream.outcome.detail.as_ref().map_or(0, String::len),
            )?;
            for q in stream
                .identity_before
                .iter()
                .chain(stream.identity_after.iter())
                .chain(stream.standard_before.iter())
                .chain(stream.standard_after.iter())
            {
                query(&mut out.stream_evidence_bytes, q)?;
            }
        }
    }
    if let Some(file) = namespace {
        {
            for q in file
                .identity_before
                .iter()
                .chain(file.identity_after.iter())
                .chain(file.standard.iter())
            {
                query(&mut out.namespace_evidence_bytes, q)?;
            }
            for capture in file.before.iter().chain(file.after.iter()) {
                add(
                    &mut out.namespace_evidence_bytes,
                    capture.refusal.as_ref().map_or(0, String::len),
                )?;
                for q in &capture.calls {
                    query(&mut out.namespace_evidence_bytes, q)?;
                }
            }
        }
    }
    Ok(out)
}
