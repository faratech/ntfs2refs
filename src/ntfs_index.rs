//! Shared bounded NTFS index structure reader. Key semantics live in callers.
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 16_384;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy)]
pub enum Encoding {
    FileReference,
    DataOffset,
}
#[derive(Clone, Copy)]
pub struct Profile {
    indexed_type: u32,
    collation: u32,
    encoding: Encoding,
}
impl Profile {
    pub const OBJECT_ID: Self = Self {
        indexed_type: 0,
        collation: 0x13,
        encoding: Encoding::DataOffset,
    };
    pub const REPARSE: Self = Self {
        indexed_type: 0,
        collation: 0x13,
        encoding: Encoding::DataOffset,
    };
    pub const QUOTA_OWNER: Self = Self {
        indexed_type: 0,
        collation: 0x11,
        encoding: Encoding::DataOffset,
    };
    pub const QUOTA_ID: Self = Self {
        indexed_type: 0,
        collation: 0x10,
        encoding: Encoding::DataOffset,
    };
    pub const FILE_NAME: Self = Self {
        indexed_type: 0x30,
        collation: 1,
        encoding: Encoding::FileReference,
    };
    pub const SECURITY_ID: Self = Self {
        indexed_type: 0,
        collation: 0x10,
        encoding: Encoding::DataOffset,
    };
    pub const SECURITY_HASH: Self = Self {
        indexed_type: 0,
        collation: 0x12,
        encoding: Encoding::DataOffset,
    };
}
pub struct Input<'a> {
    pub root: &'a [u8],
    pub allocation: &'a [u8],
    pub initialized: u64,
    pub bitmap: &'a [u8],
}
pub struct Index<K> {
    pub entries: Vec<K>,
    pub index_blocks: usize,
}
struct Entry<K> {
    key: Option<K>,
    child: Option<u64>,
}
struct Node<K> {
    entries: Vec<Entry<K>>,
    internal: bool,
}

fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .context("truncated index u16")?
            .try_into()?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .context("truncated index u32")?
            .try_into()?,
    ))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .context("truncated index u64")?
            .try_into()?,
    ))
}

fn node<K, F>(
    b: &[u8],
    base: usize,
    minimum: usize,
    encoding: Encoding,
    decode: &mut F,
) -> Result<Node<K>>
where
    F: FnMut(&[u8], &[u8], &[u8]) -> Result<K>,
{
    let first = u32le(b, base)? as usize;
    let used = u32le(b, base + 4)? as usize;
    let allocated = u32le(b, base + 8)? as usize;
    ensure!(
        first >= 16
            && first.is_multiple_of(8)
            && first <= used
            && used <= allocated
            && allocated <= b.len().saturating_sub(base),
        "invalid index node bounds"
    );
    ensure!(
        base + first >= minimum,
        "index entries overlap update-sequence metadata"
    );
    let flags = *b.get(base + 12).context("truncated node flags")?;
    ensure!(
        flags <= 1 && b.get(base + 13..base + 16) == Some(&[0, 0, 0]),
        "unknown index node flags/reserved bytes"
    );
    let internal = flags == 1;
    let mut at = base + first;
    let end = base + used;
    let mut entries = Vec::new();
    let mut terminated = false;
    while at < end {
        ensure!(entries.len() < MAX_ENTRIES, "index entry limit exceeded");
        let length = usize::from(u16le(b, at + 8)?);
        let key_length = usize::from(u16le(b, at + 10)?);
        let flags = u16le(b, at + 12)?;
        ensure!(
            flags & !3 == 0 && u16le(b, at + 14)? == 0,
            "unknown index entry flags/reserved bytes"
        );
        let child = flags & 1 != 0;
        let last = flags & 2 != 0;
        ensure!(
            child == internal,
            "inconsistent index node/entry child flags"
        );
        let tail = if child { 8 } else { 0 };
        ensure!(
            length >= 16 + tail && length <= end - at && length.is_multiple_of(8),
            "invalid index entry bounds"
        );
        let payload = length - tail;
        ensure!(
            16 + key_length <= payload,
            "index key overlaps data/child boundary"
        );
        let (value_at, value_length, expected) = match encoding {
            Encoding::FileReference => (0, 0, (16 + key_length + 7) & !7),
            Encoding::DataOffset => {
                let offset = usize::from(u16le(b, at)?);
                let size = usize::from(u16le(b, at + 2)?);
                ensure!(u32le(b, at + 4)? == 0, "nonzero index data reserved field");
                if last {
                    ensure!(offset == 0 && size == 0, "index terminator has data");
                    (0, 0, 16)
                } else {
                    ensure!(
                        offset >= 16 + key_length
                            && offset.is_multiple_of(4)
                            && size > 0
                            && offset + size <= payload,
                        "index data overlaps key/child boundary"
                    );
                    (offset, size, (offset + size + 7) & !7)
                }
            }
        };
        ensure!(payload == expected, "invalid index entry padding/length");
        let key = if last {
            ensure!(
                key_length == 0 && at + length == end,
                "invalid index terminator or trailing entries"
            );
            terminated = true;
            None
        } else {
            Some(decode(
                &b[at..at + 16],
                &b[at + 16..at + 16 + key_length],
                &b[at + value_at..at + value_at + value_length],
            )?)
        };
        let child = if child {
            Some(u64le(b, at + length - 8)?)
        } else {
            None
        };
        entries.push(Entry { key, child });
        at += length;
    }
    ensure!(terminated, "index node lacks final terminator");
    Ok(Node { entries, internal })
}

fn fixup(mut b: Vec<u8>, expected_vcn: u64) -> Result<(Vec<u8>, usize)> {
    ensure!(
        b.len() == 4096 && b.get(..4) == Some(b"INDX"),
        "invalid INDX signature/size"
    );
    let usa = usize::from(u16le(&b, 4)?);
    let count = usize::from(u16le(&b, 6)?);
    ensure!(
        usa >= 40 && count == 9 && usa + 2 * count <= 510,
        "invalid INDX update-sequence array"
    );
    ensure!(
        u64le(&b, 16)? == expected_vcn,
        "INDX VCN does not match allocated slot"
    );
    let sequence = u16le(&b, usa)?;
    ensure!(sequence != 0, "zero INDX update sequence");
    for sector in 1..count {
        let tail = sector * 512 - 2;
        ensure!(u16le(&b, tail)? == sequence, "torn INDX record");
        let replacement = [b[usa + sector * 2], b[usa + sector * 2 + 1]];
        b[tail..tail + 2].copy_from_slice(&replacement);
    }
    Ok((b, usa + 2 * count))
}
fn walk<K: Clone>(
    node: &Node<K>,
    nodes: &BTreeMap<u64, Node<K>>,
    seen: &mut BTreeSet<u64>,
    output: &mut Vec<K>,
    depth: usize,
    leaf_depth: &mut Option<usize>,
) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "index B-tree depth limit exceeded");
    if !node.internal {
        if let Some(prior) = *leaf_depth {
            ensure!(depth == prior, "unbalanced index B-tree");
        } else {
            *leaf_depth = Some(depth);
        }
    }
    for entry in &node.entries {
        if let Some(vcn) = entry.child {
            ensure!(seen.insert(vcn), "cycle or multiply referenced INDX block");
            let child = nodes
                .get(&vcn)
                .context("child references a free/out-of-range index block")?;
            walk(child, nodes, seen, output, depth + 1, leaf_depth)?;
        }
        if let Some(key) = &entry.key {
            ensure!(output.len() < MAX_ENTRIES, "index entry limit exceeded");
            output.push(key.clone());
        }
    }
    Ok(())
}

/// Compatibility entry for 4 KiB clusters, 4 KiB indexes and 512-byte sectors.
/// Every set allocation-bitmap slot must be initialized and root-reachable.
pub fn parse<K: Clone, F>(input: Input<'_>, profile: Profile, decode: F) -> Result<Index<K>>
where
    F: FnMut(&[u8], &[u8], &[u8]) -> Result<K>,
{
    parse_with_cluster_size(input, profile, 4096, decode)
}

/// Whether cluster geometry can be represented by this 512-byte-sector walker.
/// Index records remain 4 KiB; this is not a conversion capability.
pub fn supports_cluster_size(cluster_bytes: u32) -> bool {
    cluster_bytes.is_power_of_two() && (512..=2 * 1024 * 1024).contains(&cluster_bytes)
}

/// Decode index addresses in clusters when an index record spans whole
/// clusters, or in 512-byte units when clusters exceed the index-record size.
/// Bitmap slots always count index records, regardless of either address unit.
pub fn parse_with_cluster_size<K: Clone, F>(
    input: Input<'_>,
    profile: Profile,
    cluster_bytes: u32,
    mut decode: F,
) -> Result<Index<K>>
where
    F: FnMut(&[u8], &[u8], &[u8]) -> Result<K>,
{
    ensure!(
        supports_cluster_size(cluster_bytes),
        "unsupported index cluster geometry"
    );
    let address_bytes = if cluster_bytes <= 4096 {
        cluster_bytes
    } else {
        512
    };
    let units_per_record = 4096 / address_bytes;
    let Input {
        root,
        allocation,
        initialized,
        bitmap,
    } = input;
    ensure!(
        root.len() >= 48 && root.len() <= 4096,
        "invalid index root bound"
    );
    ensure!(
        u32le(root, 0)? == profile.indexed_type
            && u32le(root, 4)? == profile.collation
            && u32le(root, 8)? == 4096
            && u32::from(root[12]) == units_per_record
            && root[13..16] == [0, 0, 0],
        "unsupported index type/collation/geometry"
    );
    ensure!(
        allocation.len() <= MAX_INDEX_BYTES
            && allocation.len().is_multiple_of(4096)
            && initialized <= allocation.len() as u64
            && bitmap.len() <= 4096,
        "index allocation bound exceeded"
    );
    let slots = allocation.len() / 4096;
    ensure!(bitmap.len() * 8 >= slots, "index bitmap is too short");
    ensure!(
        (slots..bitmap.len() * 8).all(|slot| bitmap[slot / 8] & (1 << (slot % 8)) == 0),
        "index bitmap allocates beyond stream EOF"
    );
    let root_node = node(root, 16, 32, profile.encoding, &mut decode)?;
    let mut nodes = BTreeMap::new();
    let mut total_entries = root_node.entries.len();
    for slot in 0..slots {
        if bitmap[slot / 8] & (1 << (slot % 8)) == 0 {
            continue;
        }
        ensure!(
            ((slot + 1) * 4096) as u64 <= initialized,
            "allocated index block is uninitialized"
        );
        let address = (slot as u64)
            .checked_mul(u64::from(units_per_record))
            .context("index address overflow")?;
        let (bytes, usa_end) = fixup(allocation[slot * 4096..(slot + 1) * 4096].to_vec(), address)?;
        let parsed = node(&bytes, 24, usa_end, profile.encoding, &mut decode)?;
        total_entries += parsed.entries.len();
        ensure!(total_entries <= MAX_ENTRIES, "index entry limit exceeded");
        nodes.insert(address, parsed);
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    walk(&root_node, &nodes, &mut seen, &mut entries, 0, &mut None)?;
    ensure!(
        seen.len() == nodes.len(),
        "allocated INDX block is unreachable from root"
    );
    Ok(Index {
        entries,
        index_blocks: nodes.len(),
    })
}
