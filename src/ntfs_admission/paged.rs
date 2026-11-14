//! Source path queries over a complete held inventory. These return semantic
//! observations only; no serialized result can grant a source certificate.
use crate::ntfs_inspect::{FileInventory, RootFileDomain};
use anyhow::{Context, Result, ensure};

fn directory_path(files: &impl RootFileDomain, current: u64) -> Result<Vec<String>> {
    // A run that leaves short names behind walks up through directories
    // that have one; otherwise a directory with a second name ends the walk.
    directory_path_for_alias_preparation(files, current, crate::short_name_disposition::dropped())
}

fn directory_path_for_alias_preparation(
    files: &impl RootFileDomain,
    mut current: u64,
    alias_preparation: bool,
) -> Result<Vec<String>> {
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
        let names: Vec<_> = directory
            .names
            .iter()
            .filter(|n| !alias_preparation || n.namespace != 2)
            .collect();
        ensure!(
            directory.is_directory
                && (alias_preparation || directory.hard_link_count == 1)
                && names.len() == 1
                && directory.base_file_reference == 0,
            "source parent is not a canonical single-name directory"
        );
        let name = names[0];
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

/// A path to name a refused object by, in a message. The admission path
/// resolver accepts only names it would transfer, so an object that also has
/// a short name falls through to the resolver that tolerates those. This
/// names an object; it admits nothing.
pub(crate) fn refused_object_path(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Option<Vec<String>> {
    user_paths(files, file)
        .or_else(|_| canonical_paths_for_alias_preparation(files, file))
        .ok()
        .and_then(|paths| paths.into_iter().next())
}

/// Canonical long paths for a separately journaled short-name preparation.
/// This does not satisfy normal source admission or permit dropping aliases.
pub(crate) fn canonical_paths_for_alias_preparation(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Result<Vec<Vec<String>>> {
    ensure!(
        file.base_file_reference == 0,
        "canonical base required for alias preparation"
    );
    let canonical: Vec<_> = file.names.iter().filter(|n| n.namespace != 2).collect();
    // The Windows path preserves the raw FILE counter as a hint; complete
    // MFT/I30 coverage and native canonical link counts establish the names.
    ensure!(
        !canonical.is_empty()
            && canonical.iter().all(|n| matches!(n.namespace, 0 | 1 | 3))
            && (!file.is_directory || canonical.len() == 1),
        "canonical name/link coverage differs"
    );
    for alias in file.names.iter().filter(|n| n.namespace == 2) {
        ensure!(
            canonical
                .iter()
                .any(|n| n.parent_record_number == alias.parent_record_number
                    && n.parent_sequence_number == alias.parent_sequence_number),
            "DOS alias has no canonical parent identity"
        );
    }
    let mut paths = Vec::new();
    for name in canonical {
        let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
        let mut path = directory_path_for_alias_preparation(files, parent, true)?;
        if file.record_number != 5 {
            path.push(String::from_utf16(&name.name_utf16)?);
        }
        // The default route's rule for a file and a directory alike: the
        // path has to fit Windows' extended-length form. (The second
        // argument says which route's rule applies, not what the object
        // is; `!file.is_directory` held every directory of a Windows
        // volume to the older routes' sixteen components.)
        ensure!(
            crate::shadow_tree::expected_path_fits(&path, true),
            "the path \\{} does not fit Windows' extended-length form",
            path.join("\\")
        );
        paths.push(path);
    }
    Ok(paths)
}

pub(crate) fn user_paths(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Result<Vec<Vec<String>>> {
    // `--short-names drop`: an object's long names are what is transferred.
    // Its 8.3 names are listed in the run's records and left behind, so
    // they are not names to carry. NTFS counts a short name among the
    // file record's links, so the record's count is still that of all its
    // names.
    if crate::short_name_disposition::dropped() && file.names.iter().any(|n| n.namespace == 2) {
        ensure!(
            usize::from(file.hard_link_count) == file.names.len(),
            "the file record's link count is not the number of its names"
        );
        return canonical_paths_for_alias_preparation(files, file);
    }
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
    // Ordinary objects cannot be replaced as NTFS internals. Their complete
    // user paths are checked by the caller's ordinary or Windows policy.
    if file.record_number >= 16
        && file.metadata_role == crate::ntfs_inspect::MetadataRole::OutsideExtendCandidate
    {
        return Ok(None);
    }
    // Exact internal roles have a single canonical name. Reserved nameless
    // slots are recognized before the closure is called by the shared policy.
    let path = if file.names.len() == 1 {
        user_paths(files, file)
            .with_context(|| format!("NTFS internal-role path at FILE {}", file.record_number))?
            .pop()
    } else {
        None
    };
    Ok(super::internal_role_with_path(file, || path))
}

/// Classify one raw inspection blocker using the actual retained source and
/// independent internal-state proofs. This is a diagnostic, not admission:
/// native identity, namespace, security, frozen-source and target checks are
/// still required by the enclosing live conversion.
pub(crate) fn blocker_is_unresolved(
    source: &crate::ntfs_inspect::PagedInspection,
    blocker: &crate::ntfs_inspect::InspectionBlocker,
    backups: &crate::ntfs_backup::VerifiedBackups,
    log: &crate::ntfs_log::VerifiedRestart,
    indexes: &crate::ntfs_internal::PagedVerifiedIndexes,
    transactions: &crate::ntfs_transactions::VerifiedTransactions,
    native_short_names_disabled_without_dos_aliases: bool,
) -> Result<bool> {
    use crate::ntfs_inspect::LogicalHashStatus;
    if matches!(
        blocker.code.as_str(),
        "security_descriptors_unresolved"
            | "directory_indexes_unverified"
            | "allocation_ownership_unverified"
    ) {
        return Ok(false);
    }
    if blocker.code == "backup_boot_unverified" && backups.binds_domain(source) {
        return Ok(false);
    }
    if blocker.code == "journal_state_unverified"
        && log.binds_domain(source)
        && log.restart.candidate_clean_dismount
    {
        return Ok(false);
    }
    if blocker.code == "volume_state_flags"
        && source.header().volume_flags == Some(0x80)
        && native_short_names_disabled_without_dos_aliases
    {
        return Ok(false);
    }
    if blocker.code == "object_id"
        && blocker.file_record_number == Some(3)
        && indexes.covers_volume_object_id_domain(source, 3)
    {
        return Ok(false);
    }
    if blocker.code == "object_id" && source.is_windows_conversion() {
        if let (Some(number), Some(domain)) = (
            blocker.file_record_number,
            indexes.windows_object_ids_owned(),
        ) {
            if let Some(file) = source.find_record(number, None)? {
                if domain.accounted(source, &file)? {
                    return Ok(false);
                }
            }
        }
    }
    if blocker.code == "object_id" && !source.is_windows_conversion() {
        if let (Some(number), Some(domain)) =
            (blocker.file_record_number, indexes.data_object_ids_owned())
        {
            if let Some(file) = source.find_record(number, None)? {
                if domain.accounted(source, &file)? {
                    return Ok(false);
                }
            }
        }
    }
    if blocker.code == "unsupported_attribute"
        && blocker.message == "Attribute type 0x100 needs a preservation policy"
        && transactions.binds_domain(source)
    {
        if let Some(number) = blocker.file_record_number {
            if let Some(file) = source.find_record(number, None)? {
                let role = internal_role(source, &file)?;
                let windows_user_txf = if let Some(proof) = transactions.windows_txf_markers_owned()
                {
                    crate::ntfs_transactions::windows_user_marker(source, &file, &proof)?
                } else {
                    false
                };
                if (number == 5
                    || role.as_deref() == Some("$Extend\\$RmMetadata\\$Txf")
                    || windows_user_txf)
                    && file
                        .attributes
                        .iter()
                        .filter(|a| {
                            a.type_code == 0x100
                                && a.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
                        })
                        .count()
                        == 1
                    && file.attributes.iter().any(super::recognized_root_txf)
                    && file
                        .attributes
                        .iter()
                        .filter(|a| a.type_code == 0x100)
                        .all(super::recognized_root_txf)
                {
                    return Ok(false);
                }
            }
        }
    }
    if blocker.code == "logical_stream_hash_unavailable"
        && blocker.file_record_number == Some(8)
        && blocker.message
            == "DATA attribute 1 has no complete logical hash: UnsupportedBadClusterMetadata"
    {
        if let Some(file) = source.find_record(8, None)? {
            if internal_role(source, &file)?.as_deref() == Some("$BadClus")
                && file.streams.len() == 2
            {
                let unnamed = file.streams.iter().find(|s| s.name_utf16.is_empty());
                let bad = file
                    .streams
                    .iter()
                    .find(|s| s.name_utf16 == [36, 66, 97, 100]);
                if let (Some(unnamed), Some(bad)) = (unnamed, bad) {
                    let geometry = &source.header().geometry;
                    if unnamed.resident
                        && unnamed.logical_size == 0
                        && unnamed.extents.is_empty()
                        && unnamed.logical_hash_status == LogicalHashStatus::Complete
                        && !bad.resident
                        && bad.flags == 0
                        && geometry
                            .total_clusters
                            .checked_mul(u64::from(geometry.cluster_size))
                            == Some(bad.logical_size)
                        && bad.initialized_size == 0
                        && bad.allocated_size == bad.logical_size
                        && bad.logical_hash_status
                            == LogicalHashStatus::UnsupportedBadClusterMetadata
                        && bad.extents.len() == 1
                        && bad.extents[0].logical_offset == 0
                        && bad.extents[0].physical_offset.is_none()
                        && bad.extents[0].length == bad.logical_size
                    {
                        return Ok(false);
                    }
                }
            }
        }
    }
    Ok(true)
}

/// The same per-file preservation policy used by the legacy inspector, with
/// paths and security resolved from the actual held paged source owner.
/// Global page closure belongs to the enclosing producer, not one full-source
/// rescan per object. These diagnostics grant no admission or write authority.
pub(crate) fn ordinary_user_issues(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
) -> Result<Vec<String>> {
    ordinary_user_issues_scoped(source, file, resources, None, None, false)
}

/// The policy for a data volume whose object IDs have been matched and
/// archived: such an ID is not a reason to refuse its file.
pub(crate) fn ordinary_user_issues_data(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
) -> Result<Vec<String>> {
    ordinary_user_issues_scoped(source, file, resources, None, object_ids, false)
}

/// The data-volume policy applied to the inspection of a volume that is
/// still in use, for a check made before anything is frozen. Nothing has
/// been read of any stream's contents then, and that alone is not held
/// against a stream: one that the inspection found in a form the converter
/// does not read carries a status that says so, and is refused as it will
/// be. Everything else is the policy a conversion applies.
pub(crate) fn ordinary_user_issues_before_freeze(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
) -> Result<Vec<String>> {
    ensure!(
        source.is_preparation_only(),
        "the policy before the freeze applies to the inspection of a volume in use"
    );
    ordinary_user_issues_scoped(source, file, resources, None, object_ids, true)
}

pub(crate) fn ordinary_user_issues_windows(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    aliases: &crate::boot_alias::WindowsAliasDomain,
) -> Result<Vec<String>> {
    ordinary_user_issues_scoped(source, file, resources, Some(aliases), None, false)
}

fn ordinary_user_issues_scoped(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
    object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
    // The inspection was made before the freeze: no stream has been read yet.
    before_freeze: bool,
) -> Result<Vec<String>> {
    resources.validate()?;
    let budget = source.budget();
    let expected_budget =
        crate::ntfs_inspect::SourceMetadataBudget::from_resource_budget(resources.budget)?;
    ensure!(
        source.header().inventory_complete
            && source.canonical_sha256()? == hex::encode(resources.source_inspection_sha256)
            && resources.mft_records == source.header().mft_record_count
            && resources.raw_identities == source.file_count()
            && file.record_number < resources.mft_records
            && budget.ram_bytes == resources.budget.ram_bytes
            && budget.scratch_bytes == expected_budget.scratch_bytes
            && budget.record_bytes == resources.budget.max_row_bytes
            && budget.page_bytes == resources.budget.page_bytes,
        "ordinary policy source/resource identity differs"
    );
    let paths = if let Some(aliases) = aliases {
        if let Some(proof) = aliases.storage_hint_normalization() {
            let _ = crate::ntfs_storage_class::normalize(file, proof)?;
        }
        Some(aliases.user_paths(source, file)?)
    } else {
        user_paths(source, file).ok()
    };
    let names_supported = paths.is_some();
    let system_volume_information = paths.as_ref().is_some_and(|paths| {
        paths.iter().any(|path| {
            path.first()
                .is_some_and(|name| name.eq_ignore_ascii_case("System Volume Information"))
        })
    });
    let descriptor = if let Some(binding) = source.security().find_binding(file.record_number)? {
        ensure!(
            binding.sequence_number == file.sequence_number,
            "ordinary security binding has a stale file sequence"
        );
        let descriptor = if let Some(id) = binding.security_id {
            source.security().find_id(id)?
        } else {
            source.security().find_legacy(file.record_number)?
        };
        if let Some(record) = &descriptor {
            ensure!(
                record.descriptor.sha256 == binding.descriptor_sha256,
                "ordinary security descriptor differs from its complete binding"
            );
        }
        descriptor
    } else {
        None
    };
    let mut evidence = std::collections::BTreeMap::new();
    for stream in &file.streams {
        let valid = match stream.logical_hash_status {
            crate::ntfs_inspect::LogicalHashStatus::Complete => stream
                .logical_sha256
                .as_deref()
                .is_some_and(n2r_win32::content_digest::is_hex),
            crate::ntfs_inspect::LogicalHashStatus::NotReadExtentIdentityV1 => {
                stream.logical_sha256.is_none()
                    && (if aliases.is_some() {
                        crate::ntfs_attestation::extent_identity_stream_request_windows_domain(
                            source, file, stream,
                        )?
                    } else {
                        crate::ntfs_attestation::extent_identity_stream_request_domain(
                            source, file, stream, true, true,
                        )?
                    })
                    .is_some()
            }
            // Still to be read. (A stream the inspection could not read has
            // one of the other statuses, and stays refused.)
            crate::ntfs_inspect::LogicalHashStatus::NotComputed => {
                before_freeze && source.is_preparation_only() && stream.logical_sha256.is_none()
            }
            _ => false,
        };
        evidence.insert(&stream.name_utf16, valid);
    }
    let maximum_streams = usize::try_from(
        resources.budget.max_row_bytes
            / std::mem::size_of::<crate::ntfs_inspect::StreamInventory>() as u64,
    )?;
    Ok(super::user_issues_with_context_alias_scope(
        file,
        true,
        &source.header().geometry,
        names_supported,
        system_volume_information,
        descriptor.as_ref(),
        Some(resources.budget.max_row_bytes),
        maximum_streams,
        aliases.is_some(),
        aliases.is_some_and(|aliases| aliases.storage_hint_normalization().is_some()),
        if let Some(aliases) = aliases {
            aliases.windows_txf_accounted(source, file)?
        } else {
            false
        },
        if let Some(aliases) = aliases {
            aliases.windows_object_id_accounted(source, file)?
        } else if let Some(object_ids) = object_ids {
            object_ids.accounted(source, file)?
        } else {
            false
        },
        |stream| evidence.get(&stream.name_utf16).copied().unwrap_or(false),
    ))
}
