//! Read-only native file-handle observations. These do not authorize conversion.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io};

pub const MAX_FILES: usize = 256;
pub const MAX_SECURITY_BYTES: usize = 65_536;
pub const MAX_TOTAL_SECURITY_BYTES: usize = 4 * 1024 * 1024;

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
        if self.schema_version != 1
            || !valid_guid
            || self.disk_number == 0
            || self.disk_number > 255
            || self.partition_offset == 0
            || !self.partition_offset.is_multiple_of(4096)
            || self.partition_length == 0
            || !self.partition_length.is_multiple_of(4096)
            || self
                .partition_offset
                .checked_add(self.partition_length)
                .is_none_or(|n| n > 64 * 1024 * 1024 * 1024)
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
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivilegeState {
    pub name: String,
    pub before: u32,
    pub enabled: u32,
    pub restored: u32,
}
