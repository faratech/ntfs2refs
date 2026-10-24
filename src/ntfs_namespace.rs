//! Bounded raw $I30 validation and MFT/index membership reconciliation.
//! This does not establish native enumeration, security or conversion authority.
use crate::ntfs_inspect::FileInventory;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
};

pub const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 16_384;
pub const MAX_NAME_UNITS: usize = 131_072;
pub const MAX_DIRECTORIES: usize = 4096;
const MAX_DEPTH: usize = 64;
const I30: &[u16] = &[36, 73, 51, 48];

pub fn is_i30(name: &[u16]) -> bool {
    name == I30
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    ConsistentRawModel,
    Rejected,
    IncompleteAttributeInventory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reconciliation {
    pub status: Status,
    pub directories: usize,
    pub index_blocks: usize,
    pub index_entries: usize,
    pub reachable_objects: usize,
    pub index_bytes_read: usize,
    pub evidence_sha256: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub child: u64,
    pub parent: u64,
    pub namespace: u8,
    pub name: Vec<u16>,
}

#[derive(Debug)]
pub struct Directory {
    pub reference: u64,
    /// In-order traversal, including keys stored in internal nodes.
    pub entries: Vec<Link>,
    pub index_blocks: usize,
    pub evidence_sha256: String,
}

struct Entry {
    key: Option<Link>,
    child: Option<u64>,
}
struct Node {
    entries: Vec<Entry>,
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

fn name_valid(name: &[u16], root_dot: bool) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && (root_dot || name != [46])
        && name != [46, 46]
        && name.iter().all(|c| ![0, 47, 92].contains(c))
}

fn parse_node(b: &[u8], base: usize, minimum: usize, parent: u64) -> Result<Node> {
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
        ensure!(
            entries.len() < MAX_ENTRIES,
            "directory entry limit exceeded"
        );
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
        let expected = (16 + key_length + 7) & !7;
        ensure!(
            length == expected + if child { 8 } else { 0 } && length >= 16 && length <= end - at,
            "invalid index entry bounds"
        );
        let key = if last {
            ensure!(
                key_length == 0 && at + length == end,
                "invalid index terminator or trailing entries"
            );
            terminated = true;
            None
        } else {
            ensure!(key_length >= 68, "short FILE_NAME index key");
            let key = &b[at + 16..at + 16 + key_length];
            let n = usize::from(key[64]);
            ensure!(
                n > 0 && key_length == 66 + 2 * n && key[65] <= 3,
                "invalid FILE_NAME index key length/namespace"
            );
            let name = key[66..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>();
            let child_ref = u64le(b, at)?;
            ensure!(
                child_ref >> 48 != 0 && u64le(key, 0)? == parent,
                "stale or misrouted index reference"
            );
            ensure!(
                name_valid(
                    &name,
                    (parent & 0xffff_ffff_ffff) == 5 && child_ref == parent
                ),
                "invalid directory index name"
            );
            Some(Link {
                child: child_ref,
                parent,
                namespace: key[65],
                name,
            })
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
        let tail = 512 * sector - 2;
        ensure!(u16le(&b, tail)? == sequence, "torn INDX record");
        let replacement = [b[usa + 2 * sector], b[usa + 2 * sector + 1]];
        b[tail..tail + 2].copy_from_slice(&replacement);
    }
    Ok((b, usa + 2 * count))
}

fn walk(
    node: &Node,
    nodes: &BTreeMap<u64, Node>,
    seen: &mut BTreeSet<u64>,
    output: &mut Vec<Link>,
    depth: usize,
    leaf_depth: &mut Option<usize>,
) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "directory B-tree depth limit exceeded");
    if !node.internal {
        if let Some(prior) = *leaf_depth {
            ensure!(depth == prior, "unbalanced directory B-tree");
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
            ensure!(output.len() < MAX_ENTRIES, "directory entry limit exceeded");
            output.push(key.clone());
        }
    }
    Ok(())
}

/// Initial qualified geometry: 512-byte sectors, 4 KiB clusters/index records.
/// Free slots are not interpreted as live nodes; every set bitmap bit must be
/// initialized, valid, and reachable exactly once from INDEX_ROOT.
pub fn parse_directory(
    reference: u64,
    root: &[u8],
    allocation: &[u8],
    initialized: u64,
    bitmap: &[u8],
) -> Result<Directory> {
    ensure!(
        reference >> 48 != 0 && root.len() >= 48 && root.len() <= 4096,
        "invalid directory/root identity or bound"
    );
    ensure!(
        u32le(root, 0)? == 0x30
            && u32le(root, 4)? == 1
            && u32le(root, 8)? == 4096
            && root[12] == 1
            && root[13..16] == [0, 0, 0],
        "unsupported directory index type/collation/geometry"
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
    let root_node = parse_node(root, 16, 32, reference)?;
    let mut nodes = BTreeMap::new();
    let mut total_entries = root_node.entries.len();
    let mut name_units = 0usize;
    for entry in &root_node.entries {
        if let Some(k) = &entry.key {
            name_units += k.name.len();
        }
    }
    for slot in 0..slots {
        if bitmap[slot / 8] & (1 << (slot % 8)) == 0 {
            continue;
        }
        ensure!(
            ((slot + 1) * 4096) as u64 <= initialized,
            "allocated index block is uninitialized"
        );
        let (bytes, usa_end) = fixup(
            allocation[slot * 4096..(slot + 1) * 4096].to_vec(),
            slot as u64,
        )?;
        let node = parse_node(&bytes, 24, usa_end, reference)?;
        total_entries = total_entries
            .checked_add(node.entries.len())
            .context("index entry count overflow")?;
        for entry in &node.entries {
            if let Some(k) = &entry.key {
                name_units += k.name.len();
            }
        }
        ensure!(
            total_entries <= MAX_ENTRIES && name_units <= MAX_NAME_UNITS,
            "index entry/name budget exceeded"
        );
        nodes.insert(slot as u64, node);
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    walk(&root_node, &nodes, &mut seen, &mut entries, 0, &mut None)?;
    ensure!(
        seen.len() == nodes.len(),
        "allocated INDX block is unreachable from root"
    );
    ensure!(name_units <= MAX_NAME_UNITS, "index name budget exceeded");
    let mut sha = Sha256::new();
    sha.update(b"ntfs2refs-I30-v1\0");
    sha.update(reference.to_le_bytes());
    for bytes in [root, allocation, bitmap] {
        sha.update((bytes.len() as u64).to_le_bytes());
        sha.update(bytes);
    }
    Ok(Directory {
        reference,
        entries,
        index_blocks: nodes.len(),
        evidence_sha256: hex::encode(sha.finalize()),
    })
}

fn compare(a: &[u16], b: &[u16], upcase: &[u16]) -> Ordering {
    a.iter()
        .map(|c| upcase[usize::from(*c)])
        .cmp(b.iter().map(|c| upcase[usize::from(*c)]))
}

pub fn reconcile(
    files: &[FileInventory],
    directories: &[Directory],
    upcase: &[u16],
) -> Result<usize> {
    ensure!(
        files.len() <= MAX_ENTRIES && directories.len() <= MAX_DIRECTORIES,
        "namespace object/directory limit exceeded"
    );
    ensure!(upcase.len() == 65536, "complete $UpCase table required");
    ensure!(
        (0..65536).all(|i| upcase[usize::from(upcase[i])] == upcase[i]),
        "non-idempotent $UpCase table"
    );
    ensure!(
        (b'a'..=b'z').all(|c| upcase[usize::from(c)] == u16::from(c - 32)),
        "invalid ASCII $UpCase mappings"
    );
    let mut objects = BTreeMap::new();
    let mut expected = BTreeSet::new();
    let mut name_units = 0usize;
    for file in files {
        ensure!(
            file.base_file_reference == 0
                && file.sequence_number != 0
                && !file.attributes.iter().any(|a| a.type_code == 0x20),
            "incomplete MFT attribute inventory"
        );
        let reference = file.record_number | (u64::from(file.sequence_number) << 48);
        ensure!(
            file.record_number < 1 << 48 && objects.insert(reference, file).is_none(),
            "duplicate or invalid file identity"
        );
        if file.names.is_empty() {
            ensure!(
                (12..16).contains(&file.record_number)
                    && !file.is_directory
                    && file.hard_link_count == 0,
                "allocated object has no namespace name"
            );
            continue;
        }
        let links = file.names.iter().filter(|n| n.namespace != 2).count();
        ensure!(
            usize::from(file.hard_link_count) == links && (!file.is_directory || links == 1),
            "hard-link count or directory name count differs"
        );
        for name in &file.names {
            ensure!(
                name.namespace <= 3
                    && name.parent_sequence_number != 0
                    && name.parent_record_number < 1 << 48,
                "invalid MFT filename namespace/parent reference"
            );
            let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
            let root_dot =
                file.record_number == 5 && parent == reference && name.name_utf16 == [46];
            ensure!(
                name_valid(&name.name_utf16, root_dot),
                "invalid MFT namespace name"
            );
            name_units += name.name_utf16.len();
            ensure!(
                name_units <= MAX_NAME_UNITS && expected.len() < MAX_ENTRIES,
                "MFT name budget exceeded"
            );
            if root_dot {
                continue;
            }
            ensure!(
                expected.insert((
                    parent,
                    reference,
                    name.namespace,
                    name.name_utf16.as_slice()
                )),
                "duplicate MFT filename"
            );
        }
    }
    let root = files
        .iter()
        .find(|f| f.record_number == 5)
        .context("missing root directory")?;
    ensure!(
        root.is_directory
            && root.names.len() == 1
            && root.names[0].name_utf16 == [46]
            && root.names[0].parent_record_number == 5
            && root.names[0].parent_sequence_number == root.sequence_number,
        "invalid root self-reference"
    );
    let root_ref = 5 | (u64::from(root.sequence_number) << 48);
    let mut seen_directories = BTreeSet::new();
    let mut edges = BTreeMap::<u64, Vec<u64>>::new();
    let mut index_entries = 0usize;
    for dir in directories {
        let owner = objects
            .get(&dir.reference)
            .context("index owner not in allocated MFT")?;
        ensure!(
            owner.is_directory && seen_directories.insert(dir.reference),
            "duplicate/non-directory I30 owner"
        );
        let mut previous: Option<&[u16]> = None;
        for entry in &dir.entries {
            index_entries += 1;
            ensure!(
                index_entries <= MAX_ENTRIES,
                "global index entry limit exceeded"
            );
            if let Some(p) = previous {
                ensure!(
                    compare(p, &entry.name, upcase) == Ordering::Less,
                    "directory B-tree keys unordered or case-colliding"
                );
            }
            previous = Some(&entry.name);
            ensure!(entry.parent == dir.reference, "misrouted index parent");
            let child = objects
                .get(&entry.child)
                .context("index child absent or sequence stale")?;
            if dir.reference == root_ref && entry.child == root_ref && entry.name == [46] {
                ensure!(
                    entry.namespace == root.names[0].namespace,
                    "root self-entry namespace differs from MFT"
                );
                continue;
            }
            ensure!(
                expected.remove(&(
                    dir.reference,
                    entry.child,
                    entry.namespace,
                    entry.name.as_slice()
                )),
                "index/MFT name disagreement or duplicate index link"
            );
            edges.entry(dir.reference).or_default().push(entry.child);
            ensure!(
                child.base_file_reference == 0,
                "index points to extension record"
            );
        }
    }
    ensure!(
        files.iter().filter(|f| f.is_directory).count() == seen_directories.len(),
        "directory missing its I30 index"
    );
    ensure!(expected.is_empty(), "MFT name missing from directory index");
    let mut reachable = BTreeSet::from([root_ref]);
    let mut queue = VecDeque::from([root_ref]);
    while let Some(parent) = queue.pop_front() {
        if let Some(children) = edges.get(&parent) {
            for child in children {
                if reachable.insert(*child) {
                    queue.push_back(*child);
                }
            }
        }
    }
    ensure!(
        objects.iter().all(|(r, f)| reachable.contains(r)
            || ((12..16).contains(&f.record_number) && f.names.is_empty())),
        "unreachable namespace component or directory cycle"
    );
    Ok(reachable.len())
}
