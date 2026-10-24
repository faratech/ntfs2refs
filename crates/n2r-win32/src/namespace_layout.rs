//! Bounded decoder for FILE_ID_EXTD_DIR_INFO, without native I/O.
use serde::{Deserialize, Serialize};
use std::io;

pub const CAPACITY: usize = 65_536;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_CALLS: usize = 64;
pub const MAX_EVIDENCE: usize = 2 * 1024 * 1024;
pub const RESTART: i32 = 20;
pub const CONTINUE: i32 = 19;
pub const END: i32 = 18;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub file_id: [u8; 16],
    pub name_utf16: Vec<u16>,
    pub attributes: u32,
}
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
/// Returns decoded entries and the end of the last actual record. The native
/// API supplies no byte count; initialized output padding is not evidence.
pub fn parse(bytes: &[u8]) -> io::Result<(Vec<Entry>, usize)> {
    if bytes.len() > CAPACITY {
        return Err(invalid("directory batch exceeds bound"));
    }
    let mut entries = vec![];
    let mut at = 0usize;
    loop {
        let row = bytes
            .get(at..)
            .ok_or_else(|| invalid("directory offset outside batch"))?;
        if row.len() < 88 || entries.len() == MAX_ENTRIES {
            return Err(invalid("short or excessive directory records"));
        }
        let name_len = word(row, 60) as usize;
        if name_len == 0
            || name_len > 510
            || !name_len.is_multiple_of(2)
            || 88 + name_len > row.len()
        {
            return Err(invalid("invalid directory name length"));
        }
        let name: Vec<_> = row[88..88 + name_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        if name.iter().any(|c| [0, 47, 58, 92].contains(c)) {
            return Err(invalid("invalid directory name component"));
        }
        entries.push(Entry {
            file_id: row[72..88].try_into().unwrap(),
            name_utf16: name,
            attributes: word(row, 56),
        });
        let next = word(row, 0) as usize;
        if next == 0 {
            return Ok((entries, at + 88 + name_len));
        }
        if !next.is_multiple_of(8) || next < 88 + name_len || next >= row.len() {
            return Err(invalid("invalid directory next-entry offset"));
        }
        at += next;
    }
}

/// Reconstruct a pass from the actual responses, never a `complete` JSON flag.
pub fn decode_pass(queries: &[crate::attestation::Query]) -> io::Result<Vec<Entry>> {
    if queries.is_empty() || queries.len() > MAX_CALLS {
        return Err(invalid("missing or excessive directory calls"));
    }
    let mut entries = vec![];
    let mut eof = false;
    for (i, q) in queries.iter().enumerate() {
        if eof || q.class != if i == 0 { RESTART } else { CONTINUE } {
            return Err(invalid("directory call sequence differs"));
        }
        match q.native_error {
            Some(END) if q.bytes.is_empty() => eof = true,
            Some(_) => return Err(invalid("native directory enumeration refused")),
            None => {
                let (batch, used) = parse(&q.bytes)?;
                if used != q.bytes.len() || entries.len() + batch.len() > MAX_ENTRIES {
                    return Err(invalid("directory evidence bounds differ"));
                }
                entries.extend(batch);
            }
        }
    }
    if !eof {
        return Err(invalid("directory enumeration has no terminal EOF"));
    }
    Ok(entries)
}
