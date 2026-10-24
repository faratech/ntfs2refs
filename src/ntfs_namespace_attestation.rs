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
    ensure!(
        f.is_directory && n.identity.reference() == reference(f),
        "directory route differs"
    );
    ensure!(
        n.open_error.is_none(),
        "native directory open refused: {:?}",
        n.open_error
    );
    identity(n.identity_before.as_ref(), f, raw.geometry.serial_number)?;
    identity(n.identity_after.as_ref(), f, raw.geometry.serial_number)?;
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
    let mut expected = BTreeMap::new();
    for child in &raw.files {
        for name in child.names.iter().filter(|n| n.namespace != 2) {
            let p = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
            if p == owner && !(reference(child) == owner && name.name_utf16 == [46]) {
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
    let mut snapshots = vec![];
    for pass in [&n.before, &n.after] {
        let pass = pass.as_ref().context("missing native directory pass")?;
        ensure!(
            pass.refusal.is_none(),
            "native directory enumeration refused: {:?}",
            pass.refusal
        );
        let entries = namespace_layout::decode_pass(&pass.calls)?;
        let mut names = BTreeMap::new();
        let mut special = BTreeSet::new();
        for e in entries {
            ensure!(
                e.file_id[8..].iter().all(|b| *b == 0),
                "non-NTFS directory identity"
            );
            let id = u64::from_le_bytes(e.file_id[..8].try_into().unwrap());
            if e.name_utf16 == [46] || e.name_utf16 == [46, 46] {
                let expected_id = if e.name_utf16 == [46] { owner } else { parent };
                ensure!(
                    id == expected_id && e.attributes & 16 != 0 && special.insert(e.name_utf16),
                    "invalid or duplicate dot directory entry"
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
        ensure!(
            names == expected,
            "native directory names, child identities or types differ from I30/MFT"
        );
        snapshots.push(names);
    }
    ensure!(
        snapshots[0] == snapshots[1],
        "native namespace changed between passes"
    );
    Ok(expected.len())
}
pub fn reconcile(raw: &NtfsInspection, native: &Report) -> Result<Reconciliation> {
    ensure!(
        native.schema_version == 5,
        "native namespace evidence profile absent"
    );
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
