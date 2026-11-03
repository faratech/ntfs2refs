//! Source path queries over a complete held inventory. These return semantic
//! observations only; no serialized result can grant a source certificate.
use crate::ntfs_inspect::{FileInventory, RootFileDomain};
use anyhow::{Context, Result, ensure};

fn directory_path(files: &impl RootFileDomain, mut current: u64) -> Result<Vec<String>> {
    let mut components = Vec::new();
    let mut units = 0usize;
    // A canonical parent chain cannot contain more identities than the source.
    // This detects cycles without retaining an all-source visited set.
    for _ in 0..files.file_count() {
        let number = current & 0x0000_ffff_ffff_ffff;
        let sequence = (current >> 48) as u16;
        let directory = files
            .find_record(number, Some(sequence))?
            .context("source parent identity is missing or stale")?;
        ensure!(
            directory.is_directory
                && directory.hard_link_count == 1
                && directory.names.len() == 1
                && directory.base_file_reference == 0,
            "source parent is not a canonical single-name directory"
        );
        let name = &directory.names[0];
        ensure!(
            matches!(name.namespace, 0 | 1 | 3),
            "source namespace is unsupported"
        );
        let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
        if directory.record_number == 5 {
            ensure!(
                name.name_utf16 == [u16::from(b'.')] && parent == current,
                "source root self-reference differs"
            );
            components.reverse();
            return Ok(components);
        }
        units = units
            .checked_add(name.name_utf16.len())
            .and_then(|n| n.checked_add(1))
            .context("source native path length overflow")?;
        ensure!(
            units < u16::MAX as usize / 2,
            "source path exceeds native UTF-16 representation"
        );
        components.push(String::from_utf16(&name.name_utf16)?);
        current = parent;
    }
    anyhow::bail!("source parent chain cycles or does not reach the root")
}

pub(crate) fn user_paths(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Result<Vec<Vec<String>>> {
    ensure!(
        !file.names.is_empty()
            && usize::from(file.hard_link_count) == file.names.len()
            && file.names.iter().all(|n| matches!(n.namespace, 0 | 1 | 3))
            && (!file.is_directory || file.names.len() == 1),
        "source name/link domain is unsupported or incomplete"
    );
    if file.is_directory {
        return Ok(vec![directory_path(
            files,
            file.record_number | (u64::from(file.sequence_number) << 48),
        )?]);
    }
    let mut paths = Vec::new();
    paths.try_reserve_exact(file.names.len())?;
    for name in &file.names {
        let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
        let mut path = directory_path(files, parent)?;
        path.push(String::from_utf16(&name.name_utf16)?);
        ensure!(
            crate::shadow_tree::expected_path_fits(&path, true),
            "source file path exceeds native UTF-16 representation"
        );
        paths.push(path);
    }
    paths.sort_by(|a, b| (a.len(), a).cmp(&(b.len(), b)));
    ensure!(
        !paths.windows(2).any(|p| p[0] == p[1]),
        "source name is duplicated"
    );
    Ok(paths)
}

pub(crate) fn internal_role(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Result<Option<String>> {
    // Exact internal roles have a single canonical name. Reserved nameless
    // slots are recognized before the closure is called by the shared policy.
    let path = if file.names.len() == 1 {
        user_paths(files, file)?.pop()
    } else {
        None
    };
    Ok(super::internal_role_with_path(file, || path))
}
