//! Bounded read-only proof of complete unwritten storage-region coverage.
use std::{fs::File, io};
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
pub(super) fn require(file: &File, bytes: u64) -> io::Result<()> {
    let rounded = crate::target_cluster::ceil(bytes).ok_or_else(|| invalid("VDL EOF overflow"))?;
    let mut cursor = 0u64;
    loop {
        let mut input = [0u8; 24];
        input[..8].copy_from_slice(&cursor.to_le_bytes());
        input[8..16].copy_from_slice(&bytes.saturating_sub(cursor).max(1).to_le_bytes());
        input[16..20].copy_from_slice(&2u32.to_le_bytes());
        let query = crate::stream_native::ioctl(file, 0x0009_0284, &input, 16 + 24 * 1024);
        if let Some(error) = query.native_error.filter(|e| *e != 234) {
            return Err(io::Error::from_raw_os_error(error));
        }
        let regions = &query.bytes;
        if regions.len() < 40 {
            return Err(invalid("native unwritten regions reply is short"));
        }
        let total = u32::from_le_bytes(regions[4..8].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(regions[8..12].try_into().unwrap()) as usize;
        if count == 0
            || count > 1024
            || total < count
            || regions.len() != 16 + 24 * count
            || (query.native_error.is_none() && total != count)
        {
            return Err(invalid("native unwritten regions reply is incomplete"));
        }
        let start = cursor;
        for region in regions[16..].chunks_exact(24) {
            let offset = i64::from_le_bytes(region[..8].try_into().unwrap());
            let length = i64::from_le_bytes(region[8..16].try_into().unwrap());
            let usage = u32::from_le_bytes(region[16..20].try_into().unwrap());
            if offset < 0
                || offset as u64 != cursor
                || length < 0
                || usage != 0
                || (length == 0 && bytes != 0)
            {
                return Err(invalid(
                    "native storage-VDL has a gap or initialized region",
                ));
            }
            cursor = cursor
                .checked_add(length as u64)
                .filter(|end| *end <= rounded)
                .ok_or_else(|| invalid("native unwritten region escapes EOF"))?;
        }
        if query.native_error.is_none() {
            if cursor < bytes {
                return Err(invalid("native unwritten region coverage ends before EOF"));
            }
            break;
        }
        if cursor <= start || cursor >= bytes {
            return Err(invalid(
                "native unwritten region pagination made no progress",
            ));
        }
    }
    Ok(())
}
