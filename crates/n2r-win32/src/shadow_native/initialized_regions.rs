//! Complete initialized-region observations. Every stored page is the actual
//! native input/status/output; a multi-page result is never a synthetic reply.
//! Callers hold their actual row/query workspace through capture and transfer
//! retained pages to their existing paid report owner before releasing it.
use crate::attestation::IoctlQuery;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io, mem};

const CODE: u32 = 0x0009_0284;
const CAPACITY: usize = 16 + 24 * 1024;
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn add(a: usize, b: usize) -> io::Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| bad("initialized-region memory overflow"))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Proof {
    kind: &'static str,
    length: u64,
    usage: u32,
    allow_final_cluster_tail: bool,
    pages: Vec<IoctlQuery>,
    transcript_sha256: String,
}
impl Proof {
    pub fn pages(&self) -> &[IoctlQuery] {
        &self.pages
    }
    pub fn same_transcript(&self, other: &Self) -> bool {
        self == other
    }
    pub fn retained_bytes(&self) -> io::Result<u64> {
        let mut bytes = add(
            self.transcript_sha256.capacity(),
            self.pages
                .capacity()
                .checked_mul(mem::size_of::<IoctlQuery>())
                .ok_or_else(|| bad("region page-vector RAM overflow"))?,
        )?;
        for page in &self.pages {
            bytes = add(bytes, add(page.input.capacity(), page.bytes.capacity())?)?;
        }
        u64::try_from(bytes).map_err(io::Error::other)
    }
    pub(super) fn compact(&mut self) {
        for p in &mut self.pages {
            p.input.shrink_to_fit();
            p.bytes.shrink_to_fit();
        }
        self.pages.shrink_to_fit();
        self.transcript_sha256.shrink_to_fit();
    }
    pub fn validate(&self, length: u64, usage: u32) -> io::Result<()> {
        self.validate_scope(length, usage, false)
    }
    pub fn validate_logical(&self, length: u64, usage: u32) -> io::Result<()> {
        self.validate_scope(length, usage, true)
    }
    fn validate_scope(&self, length: u64, usage: u32, tail: bool) -> io::Result<()> {
        if self.kind != "native-initialized-region-pages-v1"
            || self.length != length
            || self.usage != usage
            || (self.allow_final_cluster_tail && !tail)
            || self.pages.is_empty()
        {
            return Err(bad("initialized-region proof scope differs"));
        }
        let mut cursor = 0;
        for (index, page) in self.pages.iter().enumerate() {
            cursor = page_end(page, cursor, length, usage, self.allow_final_cluster_tail)?;
            if page.native_error.is_none() != (index + 1 == self.pages.len()) {
                return Err(bad("initialized-region terminal page order differs"));
            }
        }
        if cursor < length
            || (!self.allow_final_cluster_tail && cursor != length)
            || digest(&self.pages, length, usage, self.allow_final_cluster_tail)
                != self.transcript_sha256
        {
            return Err(bad("initialized-region complete transcript differs"));
        }
        Ok(())
    }
    /// Single-page callers keep the historical actual bytes. Paged callers
    /// explicitly carry all actual pages in the new optional report field.
    pub(super) fn into_transport(mut self) -> (Vec<u8>, Option<Self>) {
        if self.pages.len() == 1 {
            let page = self.pages.pop().expect("observed single region page");
            (page.bytes, None)
        } else {
            (Vec::new(), Some(self))
        }
    }
}
fn digest(pages: &[IoctlQuery], length: u64, usage: u32, tail: bool) -> String {
    let mut hash = Sha256::new();
    hash.update(b"n2r-native-initialized-region-transcript-v1\0");
    hash.update(length.to_le_bytes());
    hash.update(usage.to_le_bytes());
    hash.update([u8::from(tail)]);
    for p in pages {
        hash.update(p.code.to_le_bytes());
        hash.update((p.input.len() as u64).to_le_bytes());
        hash.update(&p.input);
        hash.update([u8::from(p.native_error.is_some())]);
        hash.update(p.native_error.unwrap_or(0).to_le_bytes());
        hash.update((p.bytes.len() as u64).to_le_bytes());
        hash.update(&p.bytes);
    }
    hex::encode(hash.finalize())
}
pub(super) fn validate_transport(
    single: &[u8],
    pages: Option<&Proof>,
    length: u64,
    usage: u32,
    tail: bool,
) -> io::Result<()> {
    if let Some(proof) = pages {
        if !single.is_empty() || proof.pages.len() < 2 {
            return Err(bad("single and paged native region transports contradict"));
        }
        proof.validate_scope(length, usage, tail)
    } else if single.is_empty() {
        Ok(())
    } else if tail {
        crate::region_layout::validate_logical(single, length, usage)
    } else {
        crate::region_layout::validate(single, length, usage)
    }
}
fn page_end(page: &IoctlQuery, start: u64, length: u64, usage: u32, tail: bool) -> io::Result<u64> {
    if ![1, 2].contains(&usage)
        || length == 0
        || length > i64::MAX as u64
        || start >= length
        || page.code != CODE
        || page.input.len() != 24
        || page.bytes.len() < 40
        || page.bytes.len() > CAPACITY
        || page.native_error.is_some_and(|e| e != 234)
    {
        return Err(page
            .native_error
            .filter(|e| *e != 234)
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| bad("initialized-region page scope or length differs")));
    }
    let offset = u64::from_le_bytes(page.input[..8].try_into().unwrap());
    let requested = u64::from_le_bytes(page.input[8..16].try_into().unwrap());
    let requested_usage = u32::from_le_bytes(page.input[16..20].try_into().unwrap());
    if offset != start
        || requested != length - start
        || requested_usage != usage
        || page.input[20..] != [0; 4]
    {
        return Err(bad(
            "initialized-region query does not continue the exact requested range",
        ));
    }
    let bytes = &page.bytes;
    let total = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if count == 0
        || count > 1024
        || total < count
        || bytes.len() != 16 + 24 * count
        || (page.native_error.is_none() && total != count)
    {
        return Err(bad("initialized-region returned/total counts differ"));
    }
    let maximum = if tail {
        crate::target_cluster::ceil(length).ok_or_else(|| bad("initialized EOF overflow"))?
    } else {
        length
    };
    let mut cursor = start;
    for row in bytes[16..].chunks_exact(24) {
        let offset = i64::from_le_bytes(row[..8].try_into().unwrap());
        let bytes = i64::from_le_bytes(row[8..16].try_into().unwrap());
        let flags = u32::from_le_bytes(row[16..20].try_into().unwrap());
        if offset < 0
            || offset as u64 != cursor
            || bytes <= 0
            || flags & usage == 0
            || flags & !31 != 0
        {
            return Err(bad("initialized native region has a gap or invalid usage"));
        }
        cursor = cursor
            .checked_add(bytes as u64)
            .filter(|n| *n <= maximum)
            .ok_or_else(|| bad("initialized native region escapes requested EOF"))?;
    }
    if (page.native_error == Some(234) && (cursor <= start || cursor >= length))
        || (page.native_error.is_none() && (cursor < length || (!tail && cursor != length)))
    {
        return Err(bad(
            "initialized-region pagination made no progress or ended early",
        ));
    }
    Ok(cursor)
}

pub(super) fn capture_initialized(
    file: &File,
    length: u64,
    usage: u32,
    maximum_bytes: usize,
) -> io::Result<Proof> {
    capture(file, length, usage, maximum_bytes, false)
}
pub(super) fn capture_initialized_logical(
    file: &File,
    length: u64,
    usage: u32,
    maximum_bytes: usize,
) -> io::Result<Proof> {
    capture(file, length, usage, maximum_bytes, true)
}
fn capture(
    file: &File,
    length: u64,
    usage: u32,
    maximum_bytes: usize,
    tail: bool,
) -> io::Result<Proof> {
    if length == 0 || length > i64::MAX as u64 || ![1, 2].contains(&usage) {
        return Err(bad(
            "positive initialized range and cached/storage usage required",
        ));
    }
    let mut proof = Proof {
        kind: "native-initialized-region-pages-v1",
        length,
        usage,
        allow_final_cluster_tail: tail,
        pages: Vec::new(),
        transcript_sha256: String::new(),
    };
    let mut cursor = 0u64;
    loop {
        // The caller has prepaid maximum_bytes in its actual row workspace.
        // Pay vector replacement, native aligned temporary and returned-copy
        // buffers before either allocation or the next native query.
        let next = proof
            .pages
            .len()
            .checked_add(1)
            .ok_or_else(|| bad("region page count overflow"))?;
        let vector = next
            .checked_mul(2 * mem::size_of::<IoctlQuery>())
            .ok_or_else(|| bad("region vector budget overflow"))?;
        let current = usize::try_from(proof.retained_bytes()?).map_err(io::Error::other)?;
        let needed = add(current, add(vector, 2 * CAPACITY + 24 + 512)?)?;
        if needed > maximum_bytes {
            return Err(bad(
                "initialized-region actual row budget exhausted before next query",
            ));
        }
        proof.pages.try_reserve_exact(1).map_err(io::Error::other)?;
        if proof.pages.capacity() > next.saturating_mul(2) {
            return Err(bad("region vector capacity exceeds prepaid envelope"));
        }
        let mut input = [0u8; 24];
        input[..8].copy_from_slice(&cursor.to_le_bytes());
        input[8..16].copy_from_slice(&(length - cursor).to_le_bytes());
        input[16..20].copy_from_slice(&usage.to_le_bytes());
        let page = crate::stream_native::ioctl(file, CODE, &input, CAPACITY);
        cursor = page_end(&page, cursor, length, usage, tail)?;
        let terminal = page.native_error.is_none();
        proof.pages.push(page);
        if terminal {
            break;
        }
    }
    proof.transcript_sha256 = digest(&proof.pages, length, usage, tail);
    if usize::try_from(proof.retained_bytes()?).map_err(io::Error::other)? > maximum_bytes {
        return Err(bad("initialized-region retained proof exceeds row budget"));
    }
    Ok(proof)
}
