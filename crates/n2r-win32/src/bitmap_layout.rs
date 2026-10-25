//! Bounded candidate occupancy in legacy or metadata-inclusive native bitmaps.
//! This is not a whole-volume ownership proof.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;
#[derive(Debug, Serialize)]
pub struct Candidate {
    pub start_lcn: u64,
    pub clusters: u64,
    pub declared_clusters: u64,
    pub allocated_clusters: u64,
    pub bitmap_sha256: String,
}
pub fn candidate(bytes: &[u8], offset: u64, length: u64, partition: u64) -> io::Result<Candidate> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "candidate is outside a complete bounded bitmap",
        )
    };
    if bytes.len() < 16
        || bytes.len() > 2 * 1024 * 1024
        || bytes[..8] != [0; 8]
        || !offset.is_multiple_of(4096)
        || length == 0
        || !length.is_multiple_of(4096)
    {
        return Err(bad());
    }
    let bits = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if bits <= 0
        || bits as u64 > partition / 4096
        || ((bytes.len() - 16) as u64) < (bits as u64).div_ceil(8)
    {
        return Err(bad());
    }
    let start = offset / 4096;
    let clusters = length / 4096;
    let end = start.checked_add(clusters).ok_or_else(bad)?;
    if end > bits as u64 {
        return Err(bad());
    }
    let allocated = (start..end)
        .filter(|c| bytes[16 + (*c / 8) as usize] & (1 << (*c % 8)) != 0)
        .count() as u64;
    Ok(Candidate {
        start_lcn: start,
        clusters,
        declared_clusters: bits as u64,
        allocated_clusters: allocated,
        bitmap_sha256: hex::encode(Sha256::digest(bytes)),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn bitmap() -> Vec<u8> {
        let mut b = vec![0; 18];
        b[8..16].copy_from_slice(&16u64.to_le_bytes());
        b
    }
    #[test]
    fn metadata_occupancy_is_independent_of_legacy_free_space() {
        let legacy = bitmap();
        let mut metadata = bitmap();
        metadata[16] = 0b11110000;
        assert_eq!(
            candidate(&legacy, 4 * 4096, 4 * 4096, 16 * 4096)
                .unwrap()
                .allocated_clusters,
            0
        );
        assert_eq!(
            candidate(&metadata, 4 * 4096, 4 * 4096, 16 * 4096)
                .unwrap()
                .allocated_clusters,
            4
        );
    }
    #[test]
    fn partial_coverage_nonzero_base_overflow_and_alignment_fail() {
        assert!(candidate(&bitmap()[..17], 0, 4096, 65536).is_err());
        let mut b = bitmap();
        b[0] = 1;
        assert!(candidate(&b, 0, 4096, 65536).is_err());
        for (o, l) in [
            (1, 4096),
            (0, 0),
            (0, 1),
            (65536, 4096),
            (u64::MAX - 4095, 8192),
        ] {
            assert!(candidate(&bitmap(), o, l, 65536).is_err());
        }
    }
}
