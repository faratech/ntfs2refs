//! The identity of a raw image, as an inspection records it.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub path: PathBuf,
    pub length: u64,
    pub sha256: String,
}
