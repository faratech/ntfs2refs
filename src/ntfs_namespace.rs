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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    parse_directory_with_cluster_size(reference, root, allocation, initialized, bitmap, 4096)
}

/// As [`parse_directory_with_geometry`], with the 4 KiB index records
/// Windows formats.
pub fn parse_directory_with_cluster_size(
    reference: u64,
    root: &[u8],
    allocation: &[u8],
    initialized: u64,
    bitmap: &[u8],
    cluster_bytes: u32,
) -> Result<Directory> {
    parse_directory_with_geometry(
        reference,
        root,
        allocation,
        initialized,
        bitmap,
        cluster_bytes,
        crate::ntfs_index::DEFAULT_INDEX_RECORD_BYTES,
    )
}

/// Namespace decoding for the volume's cluster and index record sizes.
pub fn parse_directory_with_geometry(
    reference: u64,
    root: &[u8],
    allocation: &[u8],
    initialized: u64,
    bitmap: &[u8],
    cluster_bytes: u32,
    index_record_bytes: u32,
) -> Result<Directory> {
    use crate::ntfs_index::{self, Input, Profile};
    ensure!(reference >> 48 != 0, "invalid directory identity");
    let mut name_units = 0usize;
    let parsed = ntfs_index::parse_with_geometry(
        Input {
            root,
            allocation,
            initialized,
            bitmap,
        },
        Profile::FILE_NAME,
        cluster_bytes,
        index_record_bytes,
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
            usize::from(file.hard_link_count) == file.names.len()
                && (!file.is_directory || links == 1),
            "NTFS FILE {} header/name count differs: header={}, names={}, canonical={}",
            file.record_number,
            file.hard_link_count,
            file.names.len(),
            links
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

/// Reconcile complete owning page domains without retaining all file records,
/// names, index entries or graph edges. Every join uses the actual sorted
/// domains. Counts bound traversal by the source itself, not a fixture ceiling.
pub fn reconcile_domains(
    files: &impl crate::ntfs_inspect::RootFileDomain,
    directories: &impl crate::ntfs_inspect::RootDirectoryDomain,
) -> Result<u64> {
    reconcile_domains_with_link_counter_hint(files, directories, false)
}

/// Selected only by the actual frozen offline-Windows inspection owner.
/// Preserve the FILE counter as observed; both directions of the complete
/// name/index join and the later native canonical-link proof remain required.
pub(crate) fn reconcile_windows_domains(
    files: &impl crate::ntfs_inspect::RootFileDomain,
    directories: &impl crate::ntfs_inspect::RootDirectoryDomain,
) -> Result<u64> {
    reconcile_domains_with_link_counter_hint(files, directories, true)
}

fn reconcile_domains_with_link_counter_hint(
    files: &impl crate::ntfs_inspect::RootFileDomain,
    directories: &impl crate::ntfs_inspect::RootDirectoryDomain,
    header_is_hint: bool,
) -> Result<u64> {
    use crate::ntfs_inspect::{RootDirectoryDomain, RootFileDomain};
    files.revalidate()?;
    directories.revalidate()?;
    let upcase_range = directories.upcase();
    ensure!(
        upcase_range.byte_len() == 131_072,
        "complete $UpCase required"
    );
    let mut bytes = vec![0u8; 131_072];
    upcase_range.read_exact_at(0, &mut bytes)?;
    let upcase: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .collect();
    drop(bytes);
    ensure!(
        (0..65536).all(|i| upcase[usize::from(upcase[i])] == upcase[i])
            && (b'a'..=b'z').all(|c| upcase[usize::from(c)] == u16::from(c - 32)),
        "invalid complete $UpCase mappings"
    );
    fn reference(file: &FileInventory) -> Result<u64> {
        ensure!(
            file.record_number < 1 << 48 && file.sequence_number != 0,
            "invalid canonical MFT identity"
        );
        Ok(file.record_number | (u64::from(file.sequence_number) << 48))
    }
    fn owner(files: &impl RootFileDomain, id: u64) -> Result<std::sync::Arc<FileInventory>> {
        files
            .find_record_shared(id & 0xffff_ffff_ffff, Some((id >> 48) as u16))?
            .context("namespace identity absent or sequence stale")
    }
    fn directory(
        directories: &impl RootDirectoryDomain,
        id: u64,
    ) -> Result<(u64, crate::ntfs_inspect::SourceDirectoryHeader)> {
        let number = id & 0xffff_ffff_ffff;
        let mut low = 0;
        let mut high = directories.directory_count();
        while low < high {
            let middle = low + (high - low) / 2;
            let candidate = directories.directory(middle)?;
            match candidate.record_number.cmp(&number) {
                Ordering::Less => low = middle + 1,
                Ordering::Greater => high = middle,
                Ordering::Equal => {
                    ensure!(
                        candidate.sequence_number == (id >> 48) as u16,
                        "directory index sequence stale"
                    );
                    return Ok((middle, candidate));
                }
            }
        }
        anyhow::bail!("directory missing its complete I30 index")
    }
    let root = files
        .find_record(5, None)?
        .context("missing root directory")?;
    let root_ref = reference(&root)?;
    ensure!(
        root.is_directory
            && root.names.len() == 1
            && root.names[0].name_utf16 == [46]
            && root.names[0].parent_record_number == 5
            && root.names[0].parent_sequence_number == root.sequence_number,
        "invalid root self-reference"
    );
    let root_namespace = root.names[0].namespace;
    drop(root);
    // Establish the complete binary-search directory domain before any join.
    let mut prior_directory = None;
    for ordinal in 0..directories.directory_count() {
        let entry = directories.directory(ordinal)?;
        ensure!(
            entry.record_number < 1 << 48
                && entry.sequence_number != 0
                && prior_directory.is_none_or(|prior| prior < entry.record_number),
            "duplicate or unordered directory identity"
        );
        prior_directory = Some(entry.record_number);
        let file = owner(
            files,
            entry.record_number | (u64::from(entry.sequence_number) << 48),
        )?;
        ensure!(file.is_directory, "I30 owner is not a directory");
    }
    let mut prior_file = None;
    let mut file_directories = 0u64;
    let mut reserved_nameless = 0u64;
    for ordinal in 0..files.file_count() {
        let file = files.file_shared(ordinal)?;
        let id = reference(&file)?;
        ensure!(
            prior_file.is_none_or(|prior| prior < file.record_number)
                && file.base_file_reference == 0
                && !file.attributes.iter().any(|a| a.type_code == 0x20),
            "duplicate, unordered or incomplete MFT identity"
        );
        prior_file = Some(file.record_number);
        if file.names.is_empty() {
            ensure!(
                (12..16).contains(&file.record_number)
                    && !file.is_directory
                    && file.hard_link_count == 0,
                "allocated object has no namespace name"
            );
            reserved_nameless += 1;
            continue;
        }
        let links = file.names.iter().filter(|name| name.namespace != 2).count();
        ensure!(
            (header_is_hint || usize::from(file.hard_link_count) == file.names.len())
                && (!header_is_hint || links != 0)
                && (!file.is_directory || links == 1),
            "NTFS FILE {} header/name count differs: header={}, names={}, canonical={}",
            file.record_number,
            file.hard_link_count,
            file.names.len(),
            links
        );
        if file.is_directory {
            file_directories += 1;
            directory(directories, id)?;
        }
        for name in &file.names {
            ensure!(
                name.namespace <= 3
                    && name.parent_sequence_number != 0
                    && name.parent_record_number < 1 << 48,
                "invalid MFT parent/name namespace"
            );
            let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
            let root_dot = id == root_ref && parent == id && name.name_utf16 == [46];
            ensure!(
                name_valid(&name.name_utf16, root_dot),
                "invalid MFT namespace name"
            );
            if root_dot {
                continue;
            }
            let (parent_ordinal, parent_header) = directory(directories, parent)?;
            let mut low = 0;
            let mut high = parent_header.entries;
            let mut found = false;
            while low < high {
                let middle = low + (high - low) / 2;
                let entry = directories.entry(parent_ordinal, middle)?;
                match compare(&entry.name, &name.name_utf16, &upcase) {
                    Ordering::Less => low = middle + 1,
                    Ordering::Greater => high = middle,
                    Ordering::Equal => {
                        // Two names of one directory that are equal once case
                        // is folded: the directory is case-sensitive.
                        if entry.name != name.name_utf16 && entry.child != id {
                            // A decision about names that were read in
                            // full, not a structure that could not be read.
                            return Err(anyhow::Error::new(n2r_win32::refusal::Refusal(format!(
                                "the directory at MFT record {} holds two names that differ only by case, {:?} and {:?}: it is case-sensitive, and two such names are not carried over, whether or not the converter sets the directory's case-sensitive mark on the new volume. Rename one of them and turn case sensitivity off with `fsutil file setCaseSensitiveInfo <directory> disable`",
                                parent & 0x0000_ffff_ffff_ffff,
                                String::from_utf16_lossy(&entry.name),
                                String::from_utf16_lossy(&name.name_utf16)
                            ))));
                        }
                        ensure!(
                            entry.parent == parent
                                && entry.child == id
                                && entry.namespace == name.namespace
                                && entry.name == name.name_utf16,
                            "index/MFT name disagreement"
                        );
                        found = true;
                        break;
                    }
                }
            }
            ensure!(found, "MFT name missing from directory index");
        }
    }
    ensure!(
        file_directories == directories.directory_count(),
        "directory coverage differs"
    );
    for ordinal in 0..directories.directory_count() {
        let header = directories.directory(ordinal)?;
        let id = header.record_number | (u64::from(header.sequence_number) << 48);
        let mut previous: Option<Vec<u16>> = None;
        for position in 0..header.entries {
            let entry = directories.entry(ordinal, position)?;
            ensure!(
                entry.parent == id
                    && entry.namespace <= 3
                    && name_valid(&entry.name, id == root_ref && entry.child == root_ref),
                "invalid/misrouted index entry"
            );
            if let Some(previous) = &previous {
                ensure!(
                    compare(previous, &entry.name, &upcase) == Ordering::Less,
                    "directory keys unordered or case-colliding"
                );
            }
            previous = Some(entry.name.clone());
            let child = owner(files, entry.child)?;
            ensure!(
                child.base_file_reference == 0,
                "index points to extension record"
            );
            if id == root_ref && entry.child == root_ref && entry.name == [46] {
                ensure!(
                    entry.namespace == root_namespace,
                    "root self-entry namespace differs"
                );
            } else {
                ensure!(
                    child
                        .names
                        .iter()
                        .filter(|name| {
                            name.parent_record_number == header.record_number
                                && name.parent_sequence_number == header.sequence_number
                                && name.namespace == entry.namespace
                                && name.name_utf16 == entry.name
                        })
                        .count()
                        == 1,
                    "index child name missing or ambiguous in MFT"
                );
            }
        }
        // Directories have one canonical parent. Check that every such chain
        // reaches the root; a source-derived hop bound detects all cycles while
        // retaining only one record, rather than an all-object edge graph.
        let mut ancestor = id;
        let mut hops = 0u64;
        while ancestor != root_ref {
            ensure!(hops < files.file_count(), "unreachable directory cycle");
            let file = owner(files, ancestor)?;
            ensure!(file.is_directory, "namespace parent is not a directory");
            let mut names = file.names.iter().filter(|name| name.namespace != 2);
            let parent = names.next().context("directory has no canonical parent")?;
            ensure!(
                names.next().is_none(),
                "directory has multiple canonical parents"
            );
            ancestor =
                parent.parent_record_number | (u64::from(parent.parent_sequence_number) << 48);
            hops += 1;
        }
    }
    upcase_range.revalidate()?;
    directories.revalidate()?;
    files.revalidate()?;
    files
        .file_count()
        .checked_sub(reserved_nameless)
        .context("namespace count underflow")
}
