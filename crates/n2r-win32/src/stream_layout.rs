//! Bounded decoders for native stream lists and retrieval pointers.
use std::{collections::BTreeSet, io};
pub const MAX_STREAMS: usize = 64;
pub const MAX_STREAM_BUFFER: usize = 65_536;
pub const MAX_EXTENTS: usize = 1024;
pub const RETRIEVAL_CAPACITY: usize = 16 + 16 * MAX_EXTENTS;
/// Aggregate mapping bound, separate from one native response's extent limit.
pub const MAX_COMPLETE_EXTENTS: usize = 65_536;
pub const COMPLETE_RETRIEVAL_CAPACITY: usize = 16 + 16 * MAX_COMPLETE_EXTENTS;
/// Per-call bitmap payload; complete assembled maps have a separate bound.
pub const MAX_BITMAP_BYTES: usize = 2 * 1024 * 1024;
pub const GET_RETRIEVAL: u32 = 0x00090073;
pub const GET_BASE: u32 = 0x00090234;
pub const GET_BITMAP: u32 = 0x0009006f;
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn u32le(b: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or_else(|| invalid("truncated stream u32"))?
            .try_into()
            .unwrap(),
    ))
}
fn i64le(b: &[u8], at: usize) -> io::Result<i64> {
    Ok(i64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or_else(|| invalid("truncated stream i64"))?
            .try_into()
            .unwrap(),
    ))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub native_name: Vec<u16>,
    pub name: Vec<u16>,
    pub logical_size: u64,
    pub allocated_size: u64,
}
/// Returns the meaningful byte end; native GetFileInformationByHandleEx has
/// no returned-length field, so initialized unused buffer bytes are excluded.
pub fn parse_streams(b: &[u8]) -> io::Result<(Vec<Entry>, usize)> {
    if b.len() < 24 || b.len() > MAX_STREAM_BUFFER {
        return Err(invalid("stream buffer bounds"));
    }
    let mut at = 0;
    let mut names = BTreeSet::new();
    let mut items = vec![];
    loop {
        if items.len() == MAX_STREAMS {
            return Err(invalid("stream count exceeds bound"));
        }
        let next = u32le(b, at)? as usize;
        let n = u32le(b, at + 4)? as usize;
        let size = i64le(b, at + 8)?;
        let allocation = i64le(b, at + 16)?;
        if !(14..=524).contains(&n) || !n.is_multiple_of(2) || size < 0 || allocation < 0 {
            return Err(invalid("invalid stream name or size"));
        }
        let end = at
            .checked_add(24 + n)
            .ok_or_else(|| invalid("stream range overflow"))?;
        let native_name: Vec<u16> = b
            .get(at + 24..end)
            .ok_or_else(|| invalid("truncated stream name"))?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let suffix: Vec<u16> = ":$DATA".encode_utf16().collect();
        if native_name.first() != Some(&58) || !native_name.ends_with(&suffix) {
            return Err(invalid("unsupported native stream type"));
        }
        let name = native_name[1..native_name.len() - suffix.len()].to_vec();
        if name.len() > 255
            || name.iter().any(|c| [0, 47, 58, 92].contains(c))
            || !names.insert(name.clone())
        {
            return Err(invalid("ambiguous or invalid data stream name"));
        }
        items.push(Entry {
            native_name,
            name,
            logical_size: size as u64,
            allocated_size: allocation as u64,
        });
        if next == 0 {
            return Ok((items, end));
        }
        if !next.is_multiple_of(8) || next < 24 + n {
            return Err(invalid("invalid next-stream offset"));
        }
        at = at
            .checked_add(next)
            .ok_or_else(|| invalid("next-stream overflow"))?;
        if at > b.len().saturating_sub(24) {
            return Err(invalid("next stream outside buffer"));
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub vcn: u64,
    pub lcn: Option<u64>,
    pub clusters: u64,
}
/// Legacy complete, zero-VCN single response; its 1,024-extent bound is retained.
pub fn parse_retrieval(b: &[u8]) -> io::Result<Vec<Run>> {
    parse_zero_vcn_retrieval(b, MAX_EXTENTS, RETRIEVAL_CAPACITY)
}
/// Decode the explicitly assembled complete-map representation, never an
/// unchecked individual native continuation response.
pub fn parse_complete_retrieval(b: &[u8]) -> io::Result<Vec<Run>> {
    parse_zero_vcn_retrieval(b, MAX_COMPLETE_EXTENTS, COMPLETE_RETRIEVAL_CAPACITY)
}
fn parse_zero_vcn_retrieval(b: &[u8], max_extents: usize, capacity: usize) -> io::Result<Vec<Run>> {
    if b.len() < 32 || b.len() > capacity {
        return Err(invalid("retrieval buffer bounds"));
    }
    let n = u32le(b, 0)? as usize;
    let mut vcn = i64le(b, 8)?;
    if n == 0 || n > max_extents || b.len() != 16 + n * 16 || vcn != 0 {
        return Err(invalid(
            "incomplete retrieval response or nonzero starting VCN",
        ));
    }
    let mut runs = vec![];
    for i in 0..n {
        let next = i64le(b, 16 + i * 16)?;
        let lcn = i64le(b, 24 + i * 16)?;
        if next <= vcn || lcn < -1 {
            return Err(invalid("invalid retrieval extent"));
        }
        runs.push(Run {
            vcn: vcn as u64,
            lcn: (lcn >= 0).then_some(lcn as u64),
            clusters: (next - vcn) as u64,
        });
        vcn = next;
    }
    Ok(runs)
}
