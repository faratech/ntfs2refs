//! Complete FILE_REGION_OUTPUT coverage; cached and storage VDL are distinct.
use std::io;
pub fn validate(bytes: &[u8], length: u64, usage: u32) -> io::Result<()> {
    validate_coverage(bytes, length, usage, false)
}
/// Native regions may describe the complete final allocation cluster. Only
/// coverage through logical EOF is required; cached/storage flags stay distinct.
pub fn validate_logical(bytes: &[u8], length: u64, usage: u32) -> io::Result<()> {
    validate_coverage(bytes, length, usage, true)
}
fn validate_coverage(bytes: &[u8], length: u64, usage: u32, tail: bool) -> io::Result<()> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete native validity coverage",
        )
    };
    if ![1, 2].contains(&usage)
        || length == 0
        || length > i64::MAX as u64
        || bytes.len() < 40
        || bytes.len() > 16 + 1024 * 24
    {
        return Err(bad());
    }
    let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let total = word(4) as usize;
    if total == 0 || total > 1024 || word(8) as usize != total || bytes.len() != 16 + total * 24 {
        return Err(bad());
    }
    let mut end = 0u64;
    for row in bytes[16..].as_chunks::<24>().0 {
        let at = i64::from_le_bytes(row[0..8].try_into().unwrap());
        let count = i64::from_le_bytes(row[8..16].try_into().unwrap());
        let flags = u32::from_le_bytes(row[16..20].try_into().unwrap());
        if at < 0 || at as u64 != end || count <= 0 || flags & usage == 0 || flags & !31 != 0 {
            return Err(bad());
        }
        end = end.checked_add(count as u64).ok_or_else(bad)?;
        if end
            > if tail {
                length.next_multiple_of(crate::target_cluster::bytes())
            } else {
                length
            }
        {
            return Err(bad());
        }
    }
    if end < length || (!tail && end != length) {
        return Err(bad());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn reply() -> Vec<u8> {
        let mut b = vec![0; 40];
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[8..12].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&65536u64.to_le_bytes());
        b[32..36].copy_from_slice(&1u32.to_le_bytes());
        b
    }
    #[test]
    fn cached_validity_never_proves_storage_validity() {
        let mut b = reply();
        assert!(validate(&b, 65536, 1).is_ok());
        assert!(validate(&b, 65536, 2).is_err());
        b[32..36].copy_from_slice(&3u32.to_le_bytes());
        assert!(validate(&b, 65536, 2).is_ok());
    }
    #[test]
    fn incomplete_overlapping_overlong_and_unknown_regions_fail() {
        for at in [4, 8, 16, 24] {
            let mut b = reply();
            b[at] ^= 2;
            assert!(validate(&b, 65536, 1).is_err(), "{at}");
        }
        assert!(validate(&reply()[..39], 65536, 1).is_err());
        assert!(validate(&reply(), 131072, 1).is_err());
        let mut b = reply();
        b[32] = 32;
        assert!(validate(&b, 65536, 1).is_err());
    }
    #[test]
    fn logical_tail_accepts_only_one_cluster_of_padded_valid_storage() {
        let mut b = reply();
        b[24..32].copy_from_slice(&4096u64.to_le_bytes());
        assert!(validate_logical(&b, 1, 1).is_ok());
        assert!(validate_logical(&b, 1, 2).is_err());
        b[24..32].copy_from_slice(&8192u64.to_le_bytes());
        assert!(validate_logical(&b, 1, 1).is_err());
    }
}
