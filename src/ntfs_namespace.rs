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

fn name_valid(name: &[u16], root_dot: bool) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && (root_dot || name != [46])
        && name != [46, 46]
        && name.iter().all(|c| ![0, 47, 92].contains(c))
}

/// Initial 4 KiB/512-sector profile, using the common bounded INDX walker.
pub fn parse_directory(
    reference: u64,
    root: &[u8],
    allocation: &[u8],
    initialized: u64,
    bitmap: &[u8],
) -> Result<Directory> {
    use crate::ntfs_index::{self, Input, Profile};
    ensure!(reference >> 48 != 0, "invalid directory identity");
    let mut name_units = 0usize;
    let parsed = ntfs_index::parse(
        Input {
            root,
            allocation,
            initialized,
            bitmap,
        },
        Profile::FILE_NAME,
        |header, key, _value| {
            ensure!(key.len() >= 68, "short FILE_NAME index key");
            let n = usize::from(key[64]);
            ensure!(
                n > 0 && key.len() == 66 + 2 * n && key[65] <= 3,
                "invalid FILE_NAME index key length/namespace"
            );
            name_units += n;
            ensure!(name_units <= MAX_NAME_UNITS, "index name budget exceeded");
            let name = key[66..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>();
            let child = u64::from_le_bytes(header[..8].try_into()?);
            let parent = u64::from_le_bytes(key[..8].try_into()?);
            ensure!(
                child >> 48 != 0 && parent == reference,
                "stale or misrouted index reference"
            );
            ensure!(
                name_valid(&name, (parent & 0xffff_ffff_ffff) == 5 && child == parent),
                "invalid directory index name"
            );
            Ok(Link {
                child,
                parent,
                namespace: key[65],
                name,
            })
        },
    )?;
    let mut sha = Sha256::new();
    sha.update(b"ntfs2refs-I30-v1\0");
    sha.update(reference.to_le_bytes());
    for bytes in [root, allocation, bitmap] {
        sha.update((bytes.len() as u64).to_le_bytes());
        sha.update(bytes);
    }
    Ok(Directory {
        reference,
        entries: parsed.entries,
        index_blocks: parsed.index_blocks,
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
