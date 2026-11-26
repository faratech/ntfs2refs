//! Which objects of a source a conversion makes into plain files, and what
//! it does to each.
//!
//! An object is converted to plain only on a data volume, only after the
//! user agreed to a list that names it (`plain_consent`), and only by a
//! transform this module names. A [`PlainTransform`] says exactly what is
//! taken off the object; everything else is carried over as for any other
//! object, and the run's own verification holds the new volume to it.
//!
//! What this build converts: [`PlainKind::AttributesCleared`], the
//! TEMPORARY and OFFLINE attributes of a file or directory that has no
//! reparse point. ReFS keeps neither as NTFS does (OFFLINE without a
//! reparse point means nothing to any program but a hierarchical storage
//! manager, and TEMPORARY is a caching hint), so the object is carried over
//! with both cleared and its contents unchanged. An OFFLINE file with a
//! reparse point belongs to such a manager and is still refused.
use crate::{
    ntfs_admission,
    ntfs_inspect::{FileInventory, RootFileDomain},
};
use anyhow::{Context, Result};
pub(crate) use n2r_win32::plain_ledger::{
    CLEARABLE_ATTRIBUTES, ENCRYPTED, LedgerRow, LedgerState, PlainEntry, PlainKind, PlainList,
};

/// What a conversion does to one object to make it a plain file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlainTransform {
    pub kind: PlainKind,
    /// The Win32 file attributes taken off the object; never anything
    /// outside [`CLEARABLE_ATTRIBUTES`].
    pub cleared_attributes: u32,
}

impl PlainTransform {
    /// The attributes the new object is made with.
    pub(crate) fn target_attributes(self, source_attributes: u32) -> u32 {
        source_attributes & !self.cleared_attributes
    }
}

/// The transform an object with these source attributes takes, if any.
///
/// Pure: from the attributes NTFS keeps for the object and whether it has a
/// reparse point. An object with a reparse point takes none (an OFFLINE
/// file with one is a hierarchical storage manager's, and is refused), nor
/// does an EFS-encrypted one, which is refused by name.
pub(crate) fn transform_for(source_attributes: u32, reparse_point: bool) -> Option<PlainTransform> {
    let cleared = source_attributes & CLEARABLE_ATTRIBUTES;
    (cleared != 0 && !reparse_point && source_attributes & ENCRYPTED == 0).then_some(
        PlainTransform {
            kind: PlainKind::AttributesCleared,
            cleared_attributes: cleared,
        },
    )
}

/// The transform of one file or directory, from its raw record.
pub(crate) fn of_file(file: &FileInventory) -> Result<Option<PlainTransform>> {
    let projected = crate::ntfs_file_attributes::project_user(file)?;
    let reparse = crate::ntfs_reparse::file_point(file)?.is_some();
    Ok(transform_for(projected.source_attributes, reparse))
}

/// The attributes admission accepts on an object because a conversion to
/// plain takes them off: none unless this run takes objects to plain.
pub(crate) fn admitted_attributes(reparse_point: bool) -> u32 {
    if crate::plain_consent::takes_plain() && !reparse_point {
        CLEARABLE_ATTRIBUTES
    } else {
        0
    }
}

/// The attributes the new object is made without, for this run.
pub(crate) fn cleared_on_target(file: &FileInventory) -> Result<u32> {
    if !crate::plain_consent::takes_plain() {
        return Ok(0);
    }
    Ok(of_file(file)?.map_or(0, |transform| transform.cleared_attributes))
}

/// A path as a listing names it: `\` and the components.
pub(crate) fn listing_path(components: &[String]) -> String {
    format!("\\{}", components.join("\\"))
}

/// The list entry for one object.
pub(crate) fn entry(path: String, file: &FileInventory, transform: PlainTransform) -> PlainEntry {
    PlainEntry {
        kind: transform.kind,
        path,
        cleared_attributes: transform.cleared_attributes,
        bytes: file
            .streams
            .iter()
            .fold(0u64, |sum, stream| sum.saturating_add(stream.logical_size)),
        // Clearing an attribute takes no room anywhere.
        volume_extra_bytes: 0,
        working_extra_bytes: 0,
        download_bytes: 0,
    }
}

/// The objects of a frozen source that are converted to plain: the list,
/// and the ledger's rows with every name of each object. NTFS-internal
/// objects are never converted.
pub(crate) fn census(files: &impl RootFileDomain) -> Result<(PlainList, Vec<LedgerRow>)> {
    let (mut entries, mut rows) = (Vec::new(), Vec::new());
    for ordinal in 0..files.file_count() {
        let file = files.file(ordinal)?;
        if ntfs_admission::paged::internal_role(files, &file)?.is_some() {
            continue;
        }
        let Some(transform) = of_file(&file)? else {
            continue;
        };
        let paths: Vec<String> = ntfs_admission::paged::user_paths(files, &file)
            .with_context(|| {
                format!(
                    "the names of MFT record {}, which is converted to plain",
                    file.record_number
                )
            })?
            .iter()
            .map(|path| listing_path(path))
            .collect();
        let first = paths
            .first()
            .cloned()
            .with_context(|| format!("MFT record {} has no name", file.record_number))?;
        let before = crate::ntfs_file_attributes::project_user(&file)?.win32_attributes;
        entries.push(entry(first, &file, transform));
        rows.push(LedgerRow {
            kind: transform.kind,
            paths,
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            before: LedgerState {
                attributes: before,
                reparse_tag: None,
            },
            after: LedgerState {
                attributes: transform.target_attributes(before),
                reparse_tag: None,
            },
            witness: format!(
                "$STANDARD_INFORMATION of MFT record {} on the frozen source",
                file.record_number
            ),
        });
    }
    let list = PlainList::new(entries).map_err(anyhow::Error::msg)?;
    rows.sort_by(|a, b| a.paths.cmp(&b.paths));
    Ok((list, rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::plain_ledger::{OFFLINE, TEMPORARY};

    #[test]
    fn temporary_and_offline_are_cleared_and_nothing_else() {
        let archive = 0x20;
        let t = transform_for(TEMPORARY | archive, false).unwrap();
        assert_eq!(t.kind, PlainKind::AttributesCleared);
        assert_eq!(t.cleared_attributes, TEMPORARY);
        assert_eq!(t.target_attributes(TEMPORARY | archive | 1), archive | 1);
        let both = transform_for(TEMPORARY | OFFLINE, false).unwrap();
        assert_eq!(both.cleared_attributes, TEMPORARY | OFFLINE);
        assert_eq!(both.target_attributes(TEMPORARY | OFFLINE), 0);
        // Nothing to take off.
        assert_eq!(transform_for(archive | 0x2000, false), None);
    }

    #[test]
    fn a_reparse_point_or_encryption_is_never_made_plain_by_clearing() {
        // OFFLINE with a reparse point is a storage manager's file.
        assert_eq!(transform_for(OFFLINE | 0x400, true), None);
        assert_eq!(transform_for(TEMPORARY, true), None);
        // EFS is refused by name; clearing TEMPORARY would hide that.
        assert_eq!(transform_for(TEMPORARY | ENCRYPTED, false), None);
    }

    #[test]
    fn a_path_is_written_as_a_listing_writes_it() {
        assert_eq!(listing_path(&[]), "\\");
        assert_eq!(
            listing_path(&["a".into(), "temporary.tmp".into()]),
            "\\a\\temporary.tmp"
        );
    }
}
