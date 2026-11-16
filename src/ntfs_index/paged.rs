//! Complete index walking with one intrinsic INDX record per DFS frame.
//! No allocation-wide byte buffer, all-entry vector, or resident visited set.
use super::*;
use crate::ntfs_inspect::{
    paged_storage::{SourceRamLease, SourceScratch, SourceTemporaryLease},
    source_domain::{SourceIndexRanges, SourceMetadataRange},
};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, Prefix},
};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct IndexWalkSummary {
    pub entries: u64,
    pub index_blocks: u64,
}

// A per-node working charge derived from the index record's own byte
// window, not an index cardinality or B-tree-depth cap.
fn frame_ram(record_bytes: u32) -> u64 {
    u64::from(record_bytes) * 4 + 256 * std::mem::size_of::<Entry<()>>() as u64
}
struct Span {
    at: usize,
    length: usize,
    key_length: usize,
    value_at: usize,
    value_length: usize,
    last: bool,
    child: Option<u64>,
}
struct Frame {
    bytes: Vec<u8>,
    at: usize,
    end: usize,
    internal: bool,
    pending: Option<Span>,
    _ram: SourceRamLease,
}
fn frame(
    bytes: Vec<u8>,
    base: usize,
    minimum: usize,
    profile: Profile,
    ram: SourceRamLease,
) -> Result<Frame> {
    // Reuse the existing exact bounds/flags/padding/terminator decoder. Its
    // temporary unit entries fit in one intrinsic record (at most256 rows).
    let parsed = node(&bytes, base, minimum, profile.encoding, &mut |_, _, _| {
        Ok(())
    })?;
    let internal = parsed.internal;
    drop(parsed);
    Ok(Frame {
        at: base + u32le(&bytes, base)? as usize,
        end: base + u32le(&bytes, base + 4)? as usize,
        bytes,
        internal,
        pending: None,
        _ram: ram,
    })
}
fn span(frame: &Frame, encoding: Encoding) -> Result<Span> {
    let at = frame.at;
    let length = usize::from(u16le(&frame.bytes, at + 8)?);
    let flags = u16le(&frame.bytes, at + 12)?;
    let last = flags & 2 != 0;
    let (value_at, value_length) = match encoding {
        Encoding::FileReference => (0, 0),
        _ => (
            usize::from(u16le(&frame.bytes, at)?),
            usize::from(u16le(&frame.bytes, at + 2)?),
        ),
    };
    Ok(Span {
        at,
        length,
        key_length: usize::from(u16le(&frame.bytes, at + 10)?),
        value_at,
        value_length,
        last,
        child: if flags & 1 != 0 {
            Some(u64le(&frame.bytes, at + length - 8)?)
        } else {
            None
        },
    })
}

struct Bitmap<'a> {
    range: Option<&'a dyn SourceMetadataRange>,
    body: [u8; 4096],
    at: Option<u64>,
    bytes: usize,
}
impl Bitmap<'_> {
    fn set(&mut self, slot: u64) -> Result<bool> {
        let offset = slot / 8;
        let range = self.range.context("index child has no allocation bitmap")?;
        ensure!(
            offset < range.byte_len(),
            "index child escapes allocation bitmap"
        );
        let start = offset / 4096 * 4096;
        if self.at != Some(start) {
            self.bytes = (range.byte_len() - start).min(4096) as usize;
            range.read_exact_at(start, &mut self.body[..self.bytes])?;
            self.at = Some(start);
        }
        Ok(self.body[(offset - start) as usize] & (1 << (slot % 8)) != 0)
    }
}
/// Which index blocks have been visited. One bit per block: a scratch file,
/// or memory when the whole set is small (a few bytes for most directories).
enum Seen {
    File {
        file: File,
        bytes: u64,
        _lease: SourceTemporaryLease,
    },
    Memory {
        bits: Vec<u8>,
        _ram: crate::ntfs_inspect::paged_storage::SourceRamLease,
    },
}
const SEEN_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
impl Seen {
    fn new(path: &Path, slots: u64, scratch: &SourceScratch) -> Result<Option<Self>> {
        if slots == 0 {
            return Ok(None);
        }
        let bytes = slots.div_ceil(8);
        if bytes <= SEEN_MEMORY_BYTES {
            if let Ok(ram) = scratch.lease_ram_if_room(bytes + 4096) {
                let mut bits = Vec::new();
                bits.try_reserve_exact(bytes as usize)?;
                bits.resize(bytes as usize, 0);
                return Ok(Some(Self::Memory { bits, _ram: ram }));
            }
        }
        let lease = scratch.reserve_temporary_file(path, bytes, 4096)?;
        ensure!(
            path.is_absolute(),
            "absolute ordinary visited-index scratch path required"
        );
        for component in path.components() {
            match component {
                Component::Prefix(p) => ensure!(
                    matches!(p.kind(), Prefix::Disk(_)),
                    "ordinary local index scratch required"
                ),
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = name.to_str().context("Unicode index scratch required")?;
                    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                    ensure!(
                        !name.ends_with([' ', '.'])
                            && !name.chars().any(|c| c.is_control()
                                || matches!(c, ':' | '"' | '<' | '>' | '|' | '?' | '*'))
                            && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                            && !((stem.starts_with("COM") || stem.starts_with("LPT"))
                                && stem.len() == 4
                                && stem.as_bytes()[3].is_ascii_digit()),
                        "ambiguous index scratch path refused"
                    );
                }
                _ => anyhow::bail!("index scratch traversal refused"),
            }
        }
        for ancestor in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "reparse index scratch ancestry refused"
            );
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() == 0,
            "fresh visited-index scratch file required"
        );
        file.set_len(bytes)?;
        Ok(Some(Self::File {
            file,
            bytes,
            _lease: lease,
        }))
    }
    fn insert(&mut self, slot: u64) -> Result<()> {
        let at = slot / 8;
        let mask = 1 << (slot % 8);
        match self {
            Self::Memory { bits, .. } => {
                let byte = bits
                    .get_mut(usize::try_from(at)?)
                    .context("visited index escapes scratch")?;
                ensure!(*byte & mask == 0, "cycle or multiply referenced INDX block");
                *byte |= mask;
            }
            Self::File { file, bytes, .. } => {
                ensure!(at < *bytes, "visited index escapes scratch");
                file.seek(SeekFrom::Start(at))?;
                let mut byte = [0u8; 1];
                file.read_exact(&mut byte)?;
                ensure!(
                    byte[0] & mask == 0,
                    "cycle or multiply referenced INDX block"
                );
                byte[0] |= mask;
                file.seek(SeekFrom::Start(at))?;
                file.write_all(&byte)?;
            }
        }
        Ok(())
    }
}

/// The callback receives every non-terminator entry in exact in-order sequence.
/// It must keep its existing typed key/collation checks and may publish no
/// complete result until this function returns success. Every allocated slot
/// is independently USA/bounds validated, initialized and visited exactly once.
pub fn walk_ranges(
    input: SourceIndexRanges<'_>,
    profile: Profile,
    cluster_bytes: u32,
    index_record_bytes: u32,
    scratch: &SourceScratch,
    visited_path: &Path,
    mut emit: impl FnMut(&[u8], &[u8], &[u8]) -> Result<()>,
) -> Result<IndexWalkSummary> {
    // Records of the volume's own size, addressed in clusters or, where a
    // cluster is larger than a record, in 512-byte units.
    let units = units_per_index_record(cluster_bytes, index_record_bytes)?;
    let record = u64::from(index_record_bytes);
    input.root.revalidate()?;
    if let Some(range) = input.allocation {
        range.revalidate()?;
    }
    if let Some(range) = input.bitmap {
        range.revalidate()?;
    }
    let root_len = input.root.byte_len();
    ensure!((48..=4096).contains(&root_len), "invalid index root bound");
    let ram = scratch.lease_ram(frame_ram(index_record_bytes))?;
    let mut root = Vec::new();
    root.try_reserve_exact(root_len as usize)?;
    root.resize(root_len as usize, 0);
    input.root.read_exact_at(0, &mut root)?;
    ensure!(
        u32le(&root, 0)? == profile.indexed_type
            && u32le(&root, 4)? == profile.collation
            && u32le(&root, 8)? == index_record_bytes
            && u32::from(root[12]) == units
            && root[13..16] == [0, 0, 0],
        "unsupported index type/collation/geometry"
    );
    let allocation_len = input.allocation.map_or(0, SourceMetadataRange::byte_len);
    let bitmap_len = input.bitmap.map_or(0, SourceMetadataRange::byte_len);
    ensure!(
        allocation_len.is_multiple_of(record)
            && input.initialized_allocation_bytes <= allocation_len,
        "index allocation or initialized domain differs"
    );
    let slots = allocation_len / record;
    ensure!(
        bitmap_len.checked_mul(8).is_some_and(|n| n >= slots),
        "index bitmap is too short"
    );
    let root = frame(root, 16, 32, profile, ram)?;
    let read_node = |slot: u64| -> Result<Frame> {
        ensure!(slot < slots, "child references out-of-range index block");
        ensure!(
            slot.checked_add(1)
                .and_then(|n| n.checked_mul(record))
                .is_some_and(|n| n <= input.initialized_allocation_bytes),
            "allocated index block is uninitialized"
        );
        let ram = scratch.lease_ram(frame_ram(index_record_bytes))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(index_record_bytes as usize)?;
        bytes.resize(index_record_bytes as usize, 0);
        input
            .allocation
            .context("allocated index block has no stream")?
            .read_exact_at(
                slot.checked_mul(record).context("index offset overflow")?,
                &mut bytes,
            )?;
        let address = slot
            .checked_mul(u64::from(units))
            .context("index address overflow")?;
        let (bytes, usa_end) = fixup(bytes, address)?;
        frame(bytes, 24, usa_end, profile, ram)
    };
    // Validate every set physical bitmap slot, even one later found unreachable.
    // The scan also proves every trailing bitmap bit outside EOF is clear.
    let _bitmap_ram = scratch.lease_ram(8192)?;
    let mut buffer = [0u8; 4096];
    let mut offset = 0u64;
    let mut allocated = 0u64;
    if let Some(bitmap) = input.bitmap {
        while offset < bitmap_len {
            let n = (bitmap_len - offset).min(4096) as usize;
            bitmap.read_exact_at(offset, &mut buffer[..n])?;
            for (index, byte) in buffer[..n].iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << bit) == 0 {
                        continue;
                    }
                    let slot = offset
                        .checked_add(index as u64)
                        .and_then(|n| n.checked_mul(8))
                        .and_then(|n| n.checked_add(bit))
                        .context("index bitmap address overflow")?;
                    ensure!(slot < slots, "index bitmap allocates beyond stream EOF");
                    drop(read_node(slot)?);
                    allocated = allocated
                        .checked_add(1)
                        .context("allocated index count overflow")?;
                }
            }
            offset += n as u64;
        }
    }
    let mut seen = Seen::new(visited_path, slots, scratch)?;
    let mut bitmap = Bitmap {
        range: input.bitmap,
        body: [0; 4096],
        at: None,
        bytes: 0,
    };
    let mut stack = Vec::new();
    stack.try_reserve(1)?;
    stack.push(root);
    let mut leaf_depth = if stack[0].internal {
        None
    } else {
        Some(0usize)
    };
    let mut entries = 0u64;
    let mut visited = 0u64;
    while !stack.is_empty() {
        if stack.last().context("index stack absent")?.at
            == stack.last().context("index stack absent")?.end
        {
            stack.pop();
            continue;
        }
        let next = {
            let current = stack.last_mut().context("index stack absent")?;
            if let Some(pending) = current.pending.take() {
                (pending, false)
            } else {
                (span(current, profile.encoding)?, true)
            }
        };
        let (entry, descend) = next;
        if descend && let Some(address) = entry.child {
            ensure!(
                address % u64::from(units) == 0,
                "child VCN is not an index-record address"
            );
            let slot = address / u64::from(units);
            ensure!(
                slot < slots && bitmap.set(slot)?,
                "child references a free/out-of-range index block"
            );
            seen.as_mut()
                .context("index visited owner absent")?
                .insert(slot)?;
            visited = visited
                .checked_add(1)
                .context("visited index count overflow")?;
            let child = read_node(slot)?;
            let depth = stack.len();
            if !child.internal {
                if let Some(prior) = leaf_depth {
                    ensure!(depth == prior, "unbalanced index B-tree");
                } else {
                    leaf_depth = Some(depth);
                }
            }
            stack.last_mut().context("index stack absent")?.pending = Some(entry);
            stack.try_reserve(1)?;
            stack.push(child);
            continue;
        }
        let current = stack.last_mut().context("index stack absent")?;
        if !entry.last {
            emit(
                &current.bytes[entry.at..entry.at + 16],
                &current.bytes[entry.at + 16..entry.at + 16 + entry.key_length],
                &current.bytes
                    [entry.at + entry.value_at..entry.at + entry.value_at + entry.value_length],
            )?;
            entries = entries
                .checked_add(1)
                .context("index entry count overflow")?;
        }
        current.at += entry.length;
    }
    ensure!(
        visited == allocated,
        "allocated INDX block is unreachable from root"
    );
    input.root.revalidate()?;
    if let Some(range) = input.allocation {
        range.revalidate()?;
    }
    if let Some(range) = input.bitmap {
        range.revalidate()?;
    }
    Ok(IndexWalkSummary {
        entries,
        index_blocks: visited,
    })
}
