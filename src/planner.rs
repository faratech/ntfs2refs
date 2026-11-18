use crate::{block_io::SourceIdentity, ntfs_inspect::NtfsInspection, refs_inspect::RefsInspection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "filesystem", content = "details")]
pub enum Filesystem {
    Ntfs(NtfsInspection),
    Refs(RefsInspection),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Inspection {
    pub schema_version: u32,
    pub source: SourceIdentity,
    pub filesystem: Filesystem,
}
