//! Read-only native file-handle observations. These do not authorize conversion.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io};

pub const MAX_FILES: usize = 256;
pub const MAX_SECURITY_BYTES: usize = 65_536;
pub const MAX_TOTAL_SECURITY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Volume pages are budgeted separately from file/stream observations.
pub const MAX_TOTAL_BITMAP_BYTES: usize = 2 * crate::bitmap_paging::MAX_RETURNED_BYTES + 4096;

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
        let geometry_profile = match self.schema_version {
            1 => {
                self.disk_number <= 255
                    && self
                        .partition_offset
                        .checked_add(self.partition_length)
                        .is_some_and(|n| n <= 64 * 1024 * 1024 * 1024)
            }
            2 => {
                self.disk_number <= 4095
                    && self
                        .partition_offset
                        .checked_add(self.partition_length)
                        .is_some_and(|n| n <= 64 * 1024 * 1024 * 1024 * 1024)
            }
            _ => false,
        };
        if !geometry_profile
            || !valid_guid
            || (self.schema_version == 1 && self.disk_number == 0)
            || self.partition_offset == 0
            || !self.partition_offset.is_multiple_of(4096)
            || self.partition_length == 0
            || !self.partition_length.is_multiple_of(4096)
            || self.ntfs_serial == 0
            || self.files.is_empty()
            || self.files.len() > MAX_FILES
            || self.source_inspection_sha256.len() != 64
            || !self
                .source_inspection_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.files.iter().any(|f| {
                f.record_number >= 1 << 48 || f.sequence_number == 0 || !ids.insert(f.reference())
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
