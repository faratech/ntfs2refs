//! Point-in-time occupancy hints for NTFS-owned preparation. These ranges do
//! not reserve space, prove complete ReFS ownership, or authorize source writes.
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ByteInterval {
    pub offset: u64,
    pub length: u64,
}
