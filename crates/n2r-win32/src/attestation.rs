//! Read-only native file-handle observations. These do not authorize conversion.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io};

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
    pub fn limits(self) -> ResourceLimits {
        match self {
            Self::ExperimentalLargeTreeV1 => ResourceLimits {
                maximum_identities: 2048,
                maximum_stream_bytes: 4 << 30,
                logical_read_bytes: 16 << 30,
                logical_read_calls: 4 * 1024 * 1024,
                security_bytes: 32 << 20,
                stream_evidence_bytes: 64 << 20,
                namespace_evidence_bytes: 16 << 20,
            },
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
}
impl Request {
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
            2 | 3 => {
                self.disk_number <= 4095
                    && self
                        .partition_offset
                        .checked_add(self.partition_length)
                        .is_some_and(|n| n <= 64 * 1024 * 1024 * 1024 * 1024)
            }
            _ => false,
        };
        if !geometry_profile
            || !matches!(
                (self.schema_version, self.resource_profile),
                (1 | 2, None) | (3, Some(ResourceProfile::ExperimentalLargeTreeV1))
            )
            || !valid_guid
            || (self.schema_version == 1 && self.disk_number == 0)
            || self.partition_offset == 0
            || !self.partition_offset.is_multiple_of(4096)
            || self.partition_length == 0
            || !self.partition_length.is_multiple_of(4096)
            || self.ntfs_serial == 0
            || self.files.is_empty()
            || self.files.len() > self.limits().maximum_identities
            || self.source_inspection_sha256.len() != 64
            || !self
                .source_inspection_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.files.iter().any(|f| {
                f.record_number >= 1 << 48
                    || f.sequence_number == 0
                    || !ids.insert(f.reference())
                    || (self.schema_version == 3 && !records.insert(f.record_number))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded native-attestation request",
            ));
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
pub struct Snapshot {
    pub queries: Vec<Query>,
    pub security: Vec<u8>,
    pub security_error: Option<i32>,
    #[serde(default)]
    pub kernel_security: Option<SecurityQuery>,
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
        for file in &self.files {
            for snapshot in file.before.iter().chain(file.after.iter()) {
                add(&mut out.security_bytes, snapshot.security.len())?;
                if let Some(s) = &snapshot.kernel_security {
                    add(&mut out.security_bytes, s.bytes.len())?;
                }
                for q in &snapshot.queries {
                    query(&mut out.stream_evidence_bytes, q)?;
                }
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
        if let Some(data) = &self.logical_data {
            for file in &data.files {
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
        }
        if let Some(a) = &self.allocation {
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
                    crate::bitmap_streaming::source_limits(summary.cluster_count)?,
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
        if let Some(data) = &self.namespace {
            for file in &data.files {
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
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native report resource profile or accounting differs",
            )
        };
        let Some(profile) = self.request.resource_profile else {
            return if (2..=7).contains(&self.schema_version)
                && self.resources.is_none()
                && matches!(self.request.schema_version, 1 | 2)
                && self
                    .allocation
                    .as_ref()
                    .is_none_or(|a| a.streamed_before.is_none() && a.streamed_after.is_none())
            {
                Ok(())
            } else {
                Err(invalid())
            };
        };
        self.request.validate()?;
        let limits = profile.limits();
        let a = self.resources.as_ref().ok_or_else(invalid)?;
        let data = self.logical_data.as_ref().ok_or_else(invalid)?;
        let namespace = self.namespace.as_ref().ok_or_else(invalid)?;
        let allocation = self.allocation.as_ref().ok_or_else(invalid)?;
        if self.schema_version == 9 {
            allocation
                .streamed_before
                .as_ref()
                .ok_or_else(invalid)?
                .validate_source_first(&allocation.bitmap_before)?;
            allocation
                .streamed_after
                .as_ref()
                .ok_or_else(invalid)?
                .validate_source_first(&allocation.bitmap_after)?;
        }
        let ids: BTreeSet<_> = self
            .request
            .files
            .iter()
            .map(FileIdentity::reference)
            .collect();
        let same_ids = |actual: Vec<u64>| {
            actual.len() == ids.len() && actual.iter().copied().collect::<BTreeSet<_>>() == ids
        };
        let mut observed = 0u64;
        let mut complete_reservations = 0u64;
        let mut complete_streams = 0u64;
        for file in &data.files {
            for pass in [&file.before, &file.after] {
                if pass.len() > crate::stream_layout::MAX_STREAMS {
                    return Err(invalid());
                }
                for h in pass {
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
                            || !h.outcome.sha256.as_ref().is_some_and(|s| {
                                s.len() == 64
                                    && s.bytes()
                                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            })
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
        let streaming_shape = match self.schema_version {
            8 => allocation.streamed_before.is_none() && allocation.streamed_after.is_none(),
            9 => {
                allocation.streamed_before.is_some()
                    && allocation.streamed_after.is_some()
                    && allocation.bitmap_before_continuation.is_empty()
                    && allocation.bitmap_after_continuation.is_empty()
            }
            _ => false,
        };
        if !streaming_shape
            || self.conversion_qualified
            || self.allocation.is_none()
            || a != &self.measured_resources(profile)?
            || a.security_bytes > limits.security_bytes as u64
            || a.stream_evidence_bytes > limits.stream_evidence_bytes as u64
            || a.bitmap_evidence_bytes > MAX_TOTAL_BITMAP_BYTES as u64
            || a.namespace_evidence_bytes > limits.namespace_evidence_bytes as u64
            || !same_ids(self.files.iter().map(|f| f.identity.reference()).collect())
            || !same_ids(data.files.iter().map(|f| f.identity.reference()).collect())
            || !same_ids(
                namespace
                    .files
                    .iter()
                    .map(|f| f.identity.reference())
                    .collect(),
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
                .checked_mul(64 * 1024)
                .is_some_and(|maximum| observed <= maximum)
            || data
                .files
                .iter()
                .flat_map(|f| f.before.iter().chain(&f.after))
                .any(|h| {
                    h.logical_size > limits.maximum_stream_bytes
                        || h.name_utf16.len() > 255
                        || h.identity_before
                            .iter()
                            .chain(h.identity_after.iter())
                            .chain(h.standard_before.iter())
                            .chain(h.standard_after.iter())
                            .any(|q| q.bytes.len() > 24)
                })
            || self.files.iter().any(|file| {
                file.before.iter().chain(file.after.iter()).any(|s| {
                    s.queries.len() > 4
                        || s.queries.iter().any(|q| q.bytes.len() > 40)
                        || s.security.len() > MAX_SECURITY_BYTES
                        || s.kernel_security
                            .as_ref()
                            .is_some_and(|s| s.bytes.len() > MAX_SECURITY_BYTES)
                }) || file
                    .streams_before
                    .iter()
                    .chain(file.streams_after.iter())
                    .any(|c| {
                        c.streams.len() > crate::stream_layout::MAX_STREAMS
                            || c.enumeration.bytes.len() > crate::stream_layout::MAX_STREAM_BUFFER
                            || c.streams.iter().any(|s| {
                                s.name_utf16.len() > 255
                                    || s.identity_before
                                        .iter()
                                        .chain(s.identity_after.iter())
                                        .any(|q| q.bytes.len() > 24)
                                    || s.retrieval_continuation.len()
                                        >= crate::retrieval_paging::MAX_PAGES
                                    || s.retrieval.iter().chain(&s.retrieval_continuation).any(
                                        |q| {
                                            q.bytes.len() > crate::retrieval_paging::PAGE_CAPACITY
                                                || q.input.len() > 8
                                        },
                                    )
                            })
                    })
            })
            || namespace.files.iter().any(|f| {
                f.identity_before
                    .iter()
                    .chain(f.identity_after.iter())
                    .chain(f.standard.iter())
                    .any(|q| q.bytes.len() > 24)
                    || f.before.iter().chain(f.after.iter()).any(|c| {
                        c.calls.len() > crate::namespace_layout::MAX_CALLS
                            || c.calls
                                .iter()
                                .any(|q| q.bytes.len() > crate::namespace_layout::CAPACITY)
                    })
            })
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
        self.serialized_size_bounded(MAX_SERIALIZED_REPORT_BYTES)?;
        Ok(())
    }
}
