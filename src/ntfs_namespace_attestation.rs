//! Native directory completeness against the independently decoded I30/MFT model.
use crate::{
    ntfs_inspect::{FileInventory, NtfsInspection},
    ntfs_stream_attestation::Check,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    attestation::{NamespaceFile, Query, Report},
    namespace_layout,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct DirectoryCheck {
    pub record_number: u64,
    pub sequence_number: u16,
    pub visible_names: usize,
    /// Native enumeration returns the long name. DOS-only aliases remain
    /// separate raw semantics and must be resolved by source admission.
    pub raw_dos_aliases: usize,
    pub check: Check,
}
#[derive(Debug, Serialize)]
pub struct Reconciliation {
    pub directories: Vec<DirectoryCheck>,
    pub matched_directories: usize,
    pub all_visible_names_matched: bool,
    pub conversion_qualified: bool,
}
#[derive(Debug, Serialize)]
pub struct InternalVisibility {
    pub record_number: u64,
    pub sequence_number: u16,
    pub name_utf16: Vec<u16>,
    pub role: String,
    pub visible: bool,
}
#[derive(Debug, Serialize)]
pub struct ProjectedDirectory {
    pub visible_names: usize,
    /// Every optionally hidden entry remains explicitly identified and must
    /// still pass allocation and filesystem-internal replacement admission.
    pub internal_visibility: Vec<InternalVisibility>,
}
fn reference(f: &FileInventory) -> u64 {
    f.record_number | (u64::from(f.sequence_number) << 48)
}
fn identity(q: Option<&Query>, f: &FileInventory, serial: u64) -> Result<()> {
    let q = q.context("missing directory identity evidence")?;
    ensure!(
        q.class == 18 && q.native_error.is_none() && q.bytes.len() == 24,
        "directory identity query refused"
    );
    ensure!(
        u64::from_le_bytes(q.bytes[..8].try_into().unwrap()) == serial
            && u64::from_le_bytes(q.bytes[8..16].try_into().unwrap()) == reference(f)
            && q.bytes[16..].iter().all(|b| *b == 0),
        "directory file/volume identity differs"
    );
    Ok(())
}
pub fn check_directory(
    raw: &NtfsInspection,
    f: &FileInventory,
    n: &NamespaceFile,
) -> Result<usize> {
    Ok(check_directory_view(raw, f, n, &BTreeMap::new())?.visible_names)
}

/// A native namespace projection, not permission to omit internal objects.
/// Only the eleven exact reserved NTFS root identities can be absent. A
/// returned internal entry must still have its exact raw name, ID and type.
/// Non-root directories always use the unchanged exact-membership check.
pub fn check_projected_directory(
    raw: &NtfsInspection,
    f: &FileInventory,
    n: &NamespaceFile,
) -> Result<ProjectedDirectory> {
    let mut optional = BTreeMap::new();
    if f.record_number == 5 {
        for child in &raw.files {
            if matches!(child.record_number, 0..=4 | 6..=11) {
                let role = crate::ntfs_admission::internal_role(raw, child)
                    .context("reserved root object lacks its exact internal identity")?;
                ensure!(
                    child.names.len() == 1
                        && child.names[0].parent_record_number == f.record_number
                        && child.names[0].parent_sequence_number == f.sequence_number
                        && optional.insert(reference(child), role).is_none(),
                    "reserved root object name, ancestry or identity differs"
                );
            }
        }
        ensure!(
            optional.len() == 11,
            "reserved root object set is incomplete"
        );
    }
    check_directory_view(raw, f, n, &optional)
}

/// The same native membership check using the held paged I30 domain. Only one
/// directory's names are retained, charged before insertion against its
/// admitted row budget. Complete raw MFT/I30 reconciliation precedes this call.
#[cfg(windows)]
pub fn check_projected_directory_domain(
    files: &impl crate::ntfs_inspect::RootFileDomain,
    directories: &impl crate::ntfs_inspect::RootDirectoryDomain,
    file: &FileInventory,
    native: &NamespaceFile,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
) -> Result<ProjectedDirectory> {
    admission.validate()?;
    // The directory is found by its key, without decoding a directory header
    // at each step of the search (a paged domain searches its keys alone).
    // Where it is not there, the search by headers says which way it is not,
    // with the message it always gave.
    let low = match directories.find_directory_ordinal(file.record_number)? {
        Some(ordinal) => ordinal,
        None => {
            let mut low = 0u64;
            let mut high = directories.directory_count();
            while low < high {
                let middle = low + (high - low) / 2;
                if directories.directory(middle)?.record_number < file.record_number {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            low
        }
    };
    ensure!(
        low < directories.directory_count(),
        "raw directory index is absent"
    );
    let header = directories.directory(low)?;
    ensure!(
        header.record_number == file.record_number
            && header.sequence_number == file.sequence_number,
        "raw directory index identity differs"
    );
    let owner = reference(file);
    let mut expected = BTreeMap::new();
    let mut index_bytes = 0u64;
    for ordinal in 0..header.entries {
        // The header was decoded above: each entry is found by its key
        // (`entry` decodes the header again for every entry). Every ordinal
        // asked is one of the header's entries.
        let link = directories.entry_by_record(low, header.record_number, ordinal)?;
        ensure!(link.parent == owner, "raw I30 parent differs");
        if link.namespace == 2 || (link.child == owner && link.name == [46]) {
            continue;
        }
        // One flag of the child is read where the source holds its row,
        // not from a copy of the whole row.
        let child_is_directory = files
            .with_record(
                link.child & 0x0000_ffff_ffff_ffff,
                Some((link.child >> 48) as u16),
                |child| Ok(child.is_directory),
            )?
            .context("raw I30 child is absent or stale")?;
        index_bytes = index_bytes
            .checked_add(256)
            .and_then(|n| n.checked_add((link.name.capacity() as u64).checked_mul(2)?))
            .context("directory membership index memory overflow")?;
        ensure!(
            index_bytes <= admission.budget.max_row_bytes,
            "directory membership index exceeds admitted RAM"
        );
        ensure!(
            expected
                .insert(link.name, (link.child, child_is_directory))
                .is_none(),
            "duplicate raw directory name"
        );
    }
    let mut optional = BTreeMap::new();
    if file.record_number == 5 {
        for number in (0..=4).chain(6..=11) {
            let child = files
                .find_record(number, None)?
                .context("reserved root identity is absent")?;
            let role = crate::ntfs_admission::paged::internal_role(files, &child)?
                .context("reserved root object lacks exact internal identity")?;
            ensure!(
                child.names.len() == 1
                    && child.names[0].parent_record_number == file.record_number
                    && child.names[0].parent_sequence_number == file.sequence_number
                    && optional.insert(reference(&child), role).is_none(),
                "reserved root object name, ancestry or identity differs"
            );
        }
        ensure!(
            optional.len() == 11,
            "reserved root object set is incomplete"
        );
    }
    check_directory_entries(
        files.header().geometry.serial_number,
        file,
        native,
        &optional,
        &expected,
        Some(usize::try_from(admission.budget.max_row_bytes)?),
    )
}

fn check_directory_view(
    raw: &NtfsInspection,
    f: &FileInventory,
    n: &NamespaceFile,
    optional: &BTreeMap<u64, String>,
) -> Result<ProjectedDirectory> {
    let owner = reference(f);
    let mut expected = BTreeMap::new();
    for child in &raw.files {
        for name in child.names.iter().filter(|n| n.namespace != 2) {
            let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
            if parent == owner && !(reference(child) == owner && name.name_utf16 == [46]) {
                ensure!(
                    expected
                        .insert(
                            name.name_utf16.clone(),
                            (reference(child), child.is_directory)
                        )
                        .is_none(),
                    "duplicate raw directory name"
                );
            }
        }
    }
    check_directory_entries(raw.geometry.serial_number, f, n, optional, &expected, None)
}

/// The attributes Windows gives a ".." entry that names no parent.
const UNNAMED_PARENT_ATTRIBUTES: u32 = 0x80;

/// Checks one of the two entries Windows adds to a listing: "." is the
/// directory itself and ".." its parent, each a directory with the file ID
/// the raw volume gives it.
///
/// One other form of ".." is taken. A directory is opened here by its file
/// ID, and some builds of Windows then list ".." without the parent when
/// they do not have the directory's link to it in memory: file ID 0 and no
/// attribute but NORMAL. Windows Server 2025, build 26100.1742, does so on a
/// volume mounted a moment ago, for every directory; build 26300.9457 names
/// the parent. Such an entry says nothing of the parent, so nothing is
/// checked against it. That the directory is in its parent does not rest on
/// it: the parent's own listing has to name this directory with its file ID.
fn check_dot_entry(
    is_parent: bool,
    id: u64,
    attributes: u32,
    owner: u64,
    parent: u64,
) -> Result<()> {
    if is_parent && id == 0 && attributes == UNNAMED_PARENT_ATTRIBUTES {
        return Ok(());
    }
    let (entry, expected) = if is_parent {
        ("..", parent)
    } else {
        (".", owner)
    };
    ensure!(
        id == expected && attributes & 16 != 0,
        "Windows lists the entry \"{entry}\" with file ID {id:#018x} and attributes {attributes:#x}, where a directory with file ID {expected:#018x} is expected"
    );
    Ok(())
}

fn check_directory_entries(
    serial: u64,
    f: &FileInventory,
    n: &NamespaceFile,
    optional: &BTreeMap<u64, String>,
    expected: &BTreeMap<Vec<u16>, (u64, bool)>,
    resource_row_bytes: Option<usize>,
) -> Result<ProjectedDirectory> {
    ensure!(
        f.is_directory && n.identity.reference() == reference(f),
        "directory route differs"
    );
    ensure!(
        n.open_error.is_none(),
        "native directory open refused: {:?}",
        n.open_error
    );
    identity(n.identity_before.as_ref(), f, serial)?;
    identity(n.identity_after.as_ref(), f, serial)?;
    ensure!(
        n.identity_before == n.identity_after,
        "directory binding changed"
    );
    let standard = n
        .standard
        .as_ref()
        .context("missing directory type evidence")?;
    ensure!(
        standard.class == 1
            && standard.native_error.is_none()
            && standard.bytes.len() == 24
            && standard.bytes[20] == 0
            && standard.bytes[21] == 1,
        "native directory type/delete state differs"
    );
    let owner = reference(f);
    let parents: BTreeSet<_> = f
        .names
        .iter()
        .filter(|n| n.namespace != 2)
        .map(|n| n.parent_record_number | (u64::from(n.parent_sequence_number) << 48))
        .collect();
    ensure!(parents.len() == 1, "directory parent is ambiguous");
    let parent = *parents.first().unwrap();
    let mut snapshots = vec![];
    for pass in [&n.before, &n.after] {
        let pass = pass.as_ref().context("missing native directory pass")?;
        ensure!(
            pass.refusal.is_none(),
            "native directory enumeration refused: {:?}",
            pass.refusal
        );
        let entries = if let Some(maximum) = resource_row_bytes {
            namespace_layout::decode_pass_with_resource_budget(&pass.calls, maximum)?
        } else {
            namespace_layout::decode_pass(&pass.calls)?
        };
        let mut names = BTreeMap::new();
        let mut special = BTreeSet::new();
        for e in entries {
            ensure!(
                e.file_id[8..].iter().all(|b| *b == 0),
                "non-NTFS directory identity"
            );
            let id = u64::from_le_bytes(e.file_id[..8].try_into().unwrap());
            if e.name_utf16 == [46] || e.name_utf16 == [46, 46] {
                let is_parent = e.name_utf16 == [46, 46];
                check_dot_entry(is_parent, id, e.attributes, owner, parent)?;
                ensure!(
                    special.insert(e.name_utf16),
                    "Windows lists the entry \"{}\" twice",
                    if is_parent { ".." } else { "." }
                );
                continue;
            }
            ensure!(
                names
                    .insert(e.name_utf16, (id, e.attributes & 16 != 0))
                    .is_none(),
                "duplicate native directory name"
            );
        }
        let projected: BTreeMap<_, _> = expected
            .iter()
            .filter(|(name, (id, _))| !optional.contains_key(id) || names.contains_key(*name))
            .map(|(name, value)| (name.clone(), *value))
            .collect();
        ensure!(
            names == projected,
            "native directory names, child identities or types differ from I30/MFT"
        );
        snapshots.push(names);
    }
    ensure!(
        snapshots[0] == snapshots[1],
        "native namespace changed between passes"
    );
    let visible = &snapshots[0];
    let internal_visibility = expected
        .iter()
        .filter_map(|(name, (id, _))| {
            optional.get(id).map(|role| InternalVisibility {
                record_number: id & 0x0000_ffff_ffff_ffff,
                sequence_number: (id >> 48) as u16,
                name_utf16: name.clone(),
                role: role.clone(),
                visible: visible.contains_key(name),
            })
        })
        .collect();
    Ok(ProjectedDirectory {
        visible_names: visible.len(),
        internal_visibility,
    })
}
pub fn reconcile(raw: &NtfsInspection, native: &Report) -> Result<Reconciliation> {
    ensure!(
        matches!(native.schema_version, 5..=14),
        "native namespace evidence profile absent"
    );
    crate::ntfs_stream_attestation::validate_paging_schema(native)?;
    ensure!(
        raw.namespace_reconciliation
            .as_ref()
            .is_some_and(|n| n.status == crate::ntfs_namespace::Status::ConsistentRawModel),
        "raw namespace is incomplete"
    );
    let ns = native
        .namespace
        .as_ref()
        .context("missing native namespace evidence")?;
    let mut observations = BTreeMap::new();
    for f in &ns.files {
        ensure!(
            observations.insert(f.identity.reference(), f).is_none(),
            "duplicate native namespace identity"
        );
    }
    let ids: BTreeSet<_> = raw.files.iter().map(reference).collect();
    ensure!(
        ids.len() == raw.files.len() && ids == observations.keys().copied().collect(),
        "native namespace object coverage differs"
    );
    let mut directories = vec![];
    for f in raw.files.iter().filter(|f| f.is_directory) {
        let mut names = 0;
        let check = Check::from((|| {
            names = check_directory(raw, f, observations[&reference(f)])?;
            Ok(())
        })());
        let aliases = raw
            .files
            .iter()
            .flat_map(|f| &f.names)
            .filter(|n| {
                n.namespace == 2
                    && n.parent_record_number == f.record_number
                    && n.parent_sequence_number == f.sequence_number
            })
            .count();
        directories.push(DirectoryCheck {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            visible_names: names,
            raw_dos_aliases: aliases,
            check,
        });
    }
    let matched = directories.iter().filter(|d| d.check.matched).count();
    Ok(Reconciliation {
        all_visible_names_matched: !directories.is_empty() && matched == directories.len(),
        matched_directories: matched,
        directories,
        conversion_qualified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: u64 = 0x0001_0000_0000_0027;
    const PARENT: u64 = 0x0001_0000_0000_0026;

    #[test]
    fn the_dot_entries_are_the_directory_and_its_parent() {
        check_dot_entry(false, OWNER, 0x10, OWNER, PARENT).unwrap();
        check_dot_entry(true, PARENT, 0x10, OWNER, PARENT).unwrap();
        // Other attributes beside DIRECTORY, as the root has them.
        check_dot_entry(true, PARENT, 0x16, OWNER, PARENT).unwrap();

        // Another object, or one that is not a directory.
        let wrong = check_dot_entry(true, OWNER, 0x10, OWNER, PARENT).unwrap_err();
        let text = format!("{wrong:#}");
        assert!(
            text.contains("\"..\"")
                && text.contains("0x0001000000000027")
                && text.contains("0x0001000000000026"),
            "{text}"
        );
        assert!(check_dot_entry(false, PARENT, 0x10, OWNER, PARENT).is_err());
        assert!(check_dot_entry(false, OWNER, 0x20, OWNER, PARENT).is_err());
        assert!(check_dot_entry(true, PARENT, 0x80, OWNER, PARENT).is_err());
    }

    #[test]
    fn a_parent_entry_that_names_no_parent_is_taken_and_nothing_else() {
        // What Windows Server 2025 (26100.1742) lists for a directory opened
        // by file ID on a volume mounted a moment ago.
        check_dot_entry(true, 0, 0x80, OWNER, PARENT).unwrap();

        // Only that exact form, and only for "..".
        assert!(check_dot_entry(false, 0, 0x80, OWNER, PARENT).is_err());
        assert!(check_dot_entry(true, 0, 0x10, OWNER, PARENT).is_err());
        assert!(check_dot_entry(true, 0, 0x90, OWNER, PARENT).is_err());
        assert!(check_dot_entry(true, 0, 0, OWNER, PARENT).is_err());
        assert!(check_dot_entry(true, 1, 0x80, OWNER, PARENT).is_err());
    }
}
