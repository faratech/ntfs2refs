//! Whole-disk exclusion for a disk that holds volumes beside the source: an
//! installed Windows disk while another Windows installation owns the
//! machine, or a data disk with several partitions. Every volume on the disk
//! is locked and dismounted before the disk is excluded, and the disk has to
//! be outside the running Windows' boot, system, paging and dump roles. A
//! requested topology is never authorization.
use super::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
use super::*;
use crate::general_layout::GeneralDiskLayoutProfile;

pub(super) fn require_detached_roles(
    disk: &File,
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    if !binding.layout_profile.has_sibling_volumes() {
        return Ok(());
    }
    let selected = PartitionSourceBinding {
        storage: binding.clone(),
    };
    let budget = PartitionObservationBudget {
        ram_bytes: 8 * 1024 * 1024,
        native_layout_bytes: 65536,
        gpt_entry_bytes: 4096,
        read_buffer_bytes: 4096,
    };
    let mut observed = Vec::new();
    let roles = partition_storage_roles::observe_detached_windows_storage_roles(
        &selected,
        budget,
        disk,
        &mut observed,
    )?;
    let paging = partition_isolation::paging(binding, budget, &mut observed)?;
    if !paging.enumeration_succeeded
        || !paging.all_locations_resolved
        || paging.locations.iter().any(|p| {
            p.extent
                .as_ref()
                .is_none_or(|e| e.disk_number == binding.disk_number)
        })
    {
        return Err(crate::refusal::io_error(
            "the source's disk holds a page file of the running Windows, on the volume to convert or on one beside it, or a page file whose place could not be found: a disk with a page file is not taken offline. Move the page file (System Properties, Advanced, Performance, Virtual memory) and restart".into(),
        ));
    }
    let dumps = partition_dump_locations::observe_configured_dump_locations(
        &selected,
        budget,
        &mut observed,
    )?;
    if !dumps.configured_locations_outside_target
        || dumps.locations.iter().any(|p| {
            p.extents.is_empty()
                || p.extents
                    .iter()
                    .any(|e| e.disk_number == binding.disk_number)
        })
    {
        return Err(crate::refusal::io_error(
            "the source's disk holds a place the running Windows writes its crash dumps to, on the volume to convert or on one beside it, or such a place could not be found: a disk with a dump destination is not taken offline. Move the dump file (System Properties, Advanced, Startup and Recovery)".into(),
        ));
    }
    let closing = partition_storage_roles::observe_detached_windows_storage_roles(
        &selected,
        budget,
        disk,
        &mut Vec::new(),
    )?;
    if !roles.same_critical_roles(&closing)
        || current_windows_disk(&mut observed)? == binding.disk_number
    {
        return Err(invalid(
            "the running Windows' boot or system roles changed while the source's disk was examined",
        ));
    }
    events.push(NativeEvent {
        operation: "offline-windows-whole-disk-critical-roles".into(),
        control_code: 0,
        input: Vec::new(),
        succeeded: true,
        native_error: None,
        output: serde_json::to_vec(&serde_json::json!({
            "storage": roles, "active_paging": paging, "configured_dumps": dumps,
            "runtime_loaded_dump_locations_verified": false,
            "grants_source_write_authority": false
        }))
        .map_err(io::Error::other)?,
    });
    Ok(())
}

/// The dedicated data path has one filesystem. An offline Windows disk has
/// three, and a shared data disk any number; none may remain mounted when
/// the whole physical disk is excluded.
pub(super) fn lock_all_volumes(
    binding: &GeneralDiskBinding,
    native_layout: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<File>> {
    lock_volumes(binding, native_layout, false, events)
}

pub(super) fn lock_sibling_volumes(
    binding: &GeneralDiskBinding,
    native_layout: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<File>> {
    lock_volumes(binding, native_layout, true, events)
}

/// A volume of the source's disk, as the survey found it.
struct Route {
    range: (u64, u64),
    path: String,
    named: String,
    own: bool,
}

/// What can be asked about shadow copies of a volume beside the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShadowQuestion {
    /// A volume Windows keeps shadow copies of, and shadow storage on:
    /// both are asked.
    CopiesAndStorage,
    /// A volume Windows cannot write to keeps no shadow storage up to
    /// date, and Windows does not answer the question about it: whether
    /// it has shadow copies is asked.
    CopiesOnly,
    /// No file system Windows knows: neither exists.
    Nothing,
}

fn shadow_question(volume: &crate::drive_inventory::VolumeInventory) -> ShadowQuestion {
    match volume.filesystem.as_deref() {
        None => ShadowQuestion::Nothing,
        Some(name)
            if volume.filesystem_read_only != Some(true)
                && (name.eq_ignore_ascii_case("NTFS") || name.eq_ignore_ascii_case("ReFS")) =>
        {
            ShadowQuestion::CopiesAndStorage
        }
        Some(_) => ShadowQuestion::CopiesOnly,
    }
}

/// Whether the catalog's errors about `volume` say only that Windows knows
/// no file system on it (a partition of another system, an unformatted
/// one, a locked BitLocker volume). Such a volume holds nothing of
/// Windows' that taking the disk offline could lose.
fn only_unrecognized(volume: &crate::drive_inventory::VolumeInventory) -> bool {
    volume.filesystem.is_none()
        && !volume.errors.is_empty()
        && volume
            .errors
            .iter()
            .all(|error| error.operation == "filesystem/label" && !error.enumeration_incomplete)
}

/// What stands against taking a disk with several volumes offline, asked
/// without changing anything: the roles the running Windows has on it, a
/// volume Windows does not describe, shadow copies of a volume beside the
/// source and shadow storage on one. A run asks this before it locks the
/// first volume; a check asks it and stops there.
pub(super) fn examine(
    binding: &GeneralDiskBinding,
    native_layout: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    survey(binding, native_layout, events).map(|_| ())
}

fn survey(
    binding: &GeneralDiskBinding,
    native_layout: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<(File, Vec<Route>)> {
    binding.validate_layout(native_layout)?;
    let disk = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
        false,
        false,
    )?;
    require_detached_roles(&disk, binding, events)?;
    let inventory = crate::drive_inventory::inventory_drives_readonly()?;
    if !inventory.enumeration_complete {
        return Err(invalid(
            "complete volume catalog required before Windows disk exclusion",
        ));
    }
    let windows = binding.layout_profile == GeneralDiskLayoutProfile::OfflineWindows;
    let msr = layout::guid_bytes("e3c9e316-0b5c-4db8-817d-f92df00215ae")?;
    let mut ranges = Vec::new();
    for row in native_layout[48..].chunks_exact(144) {
        if layout::u32_at(row, 24)? != 0 && layout::u64_at(row, 16)? != 0 && row[32..48] != msr {
            ranges.push((layout::u64_at(row, 8)?, layout::u64_at(row, 16)?));
        }
    }
    // An installed Windows has exactly its three filesystems. A shared data
    // disk has the source and at least one more partition, of any number.
    if windows && ranges.len() != 3 {
        return Err(invalid(
            "Windows source requires its OS, EFI and recovery filesystem volumes",
        ));
    }
    if !windows && ranges.len() < 2 {
        return Err(invalid(
            "a shared data disk holds at least one partition beside the source",
        ));
    }
    let selected = (
        binding.identity.partition_offset,
        binding.identity.partition_bytes,
    );
    let mut routes = Vec::new();
    for volume in &inventory.volumes {
        if !volume
            .extents
            .iter()
            .any(|e| e.disk_number == binding.disk_number)
        {
            continue;
        }
        let named = sibling_name(volume);
        if volume.extents.len() != 1
            || !(volume.errors.is_empty() || !windows && only_unrecognized(volume))
            || volume.contains_running_windows != Some(false)
        {
            return Err(invalid(&if windows {
                "ambiguous Windows source volume catalog".to_owned()
            } else {
                format!(
                    "the volume {named}, which shares disk {} with the volume to convert, is not one Windows describes in full (it spans disks, could not be queried, or may hold the running Windows){}: the disk is not taken offline",
                    binding.disk_number,
                    volume
                        .errors
                        .first()
                        .map(|error| format!(": {}: {}", error.operation, error.message))
                        .unwrap_or_default()
                )
            }));
        }
        let e = &volume.extents[0];
        let range = (e.offset_bytes, e.length_bytes);
        if !ranges.contains(&range)
            || routes
                .iter()
                .any(|(route, _): &(Route, _)| route.range == range)
        {
            return Err(invalid(
                "a volume on the source's disk does not lie on one of its partitions as the partition table has them",
            ));
        }
        routes.push((
            Route {
                range,
                path: volume.volume_guid_path.clone(),
                named,
                own: range == selected,
            },
            shadow_question(volume),
        ));
    }
    // Every filesystem of an installed Windows has to be there. On a shared
    // data disk a partition may carry no volume (one of a kind Windows does
    // not mount); the source's own always does.
    if windows && routes.len() != ranges.len() {
        return Err(invalid(
            "a Windows source filesystem is missing from the complete volume catalog",
        ));
    }
    if !routes.iter().any(|(route, _)| route.own) {
        return Err(invalid(
            "the volume to convert is missing from the complete volume catalog",
        ));
    }
    routes.sort_by_key(|(route, _)| route.range.0);
    // A volume beside the source on a data disk: nothing of it may be lost
    // by taking the disk away. Shadow copies of it, and shadow storage it
    // keeps for another volume, would be (asked while the disk is still
    // online and writable, which the query needs).
    if !windows && attributes(&disk, events)? == 0 {
        for (route, question) in routes.iter().filter(|(route, _)| !route.own) {
            refuse_sibling_shadow_storage(route, *question, binding.disk_number)?;
        }
    }
    Ok((disk, routes.into_iter().map(|(route, _)| route).collect()))
}

fn lock_volumes(
    binding: &GeneralDiskBinding,
    native_layout: &[u8],
    skip_selected: bool,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<File>> {
    let (disk, routes) = survey(binding, native_layout, events)?;
    let windows = binding.layout_profile == GeneralDiskLayoutProfile::OfflineWindows;
    let mut locks = Vec::new();
    for Route {
        range: (offset, length),
        path,
        named,
        own,
    } in routes
    {
        if skip_selected && own {
            continue;
        }
        let read_only = attributes(&disk, events)? & READ_ONLY != 0;
        let file = device_file(path.trim_end_matches('\\'), !read_only, false)?;
        let extent = control(
            &file,
            "offline-windows-lock-volume-extent",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        if extent.len() != 32
            || layout::u32_at(&extent, 0)? != 1
            || layout::u32_at(&extent, 8)? != binding.disk_number
            || layout::u64_at(&extent, 16)? != offset
            || layout::u64_at(&extent, 24)? != length
        {
            return Err(invalid("held Windows source volume changed before locking"));
        }
        // Windows refuses the lock while anything has a file or folder of
        // the volume open. A handle that is just being closed is waited
        // for; one that stays is the user's to close, by name.
        let mut attempts = 0;
        loop {
            match control(
                &file,
                "offline-windows-lock-filesystem",
                LOCK,
                &[],
                0,
                events,
            ) {
                Ok(_) => break,
                Err(error)
                    if attempts < 40 && matches!(error.raw_os_error(), Some(5) | Some(32)) =>
                {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(error) if windows => return Err(error),
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "the volume {named}, which shares disk {} with the volume to convert, could not be locked to take the disk offline, after waiting {} s: something has a file or folder on it open. Close the programs and Explorer windows that use it, then run the conversion again. Nothing was changed: {error}",
                            binding.disk_number,
                            attempts / 2
                        ),
                    ));
                }
            }
        }
        control(
            &file,
            "offline-windows-dismount-filesystem",
            DISMOUNT,
            &[],
            0,
            events,
        )?;
        locks.push(file);
    }
    Ok(locks)
}

/// A volume as its user knows it: its drive letters or mount points, or
/// else its volume name.
fn sibling_name(volume: &crate::drive_inventory::VolumeInventory) -> String {
    if volume.mount_paths.is_empty() {
        volume.volume_guid_path.clone()
    } else {
        volume.mount_paths.join(", ")
    }
}

/// Refuses a volume beside the source that has shadow copies, or keeps the
/// shadow storage of another volume: both are lost when the disk is taken
/// from under them.
fn refuse_sibling_shadow_storage(
    route: &Route,
    question: ShadowQuestion,
    disk_number: u32,
) -> io::Result<()> {
    let root = if route.path.ends_with('\\') {
        route.path.clone()
    } else {
        format!("{}\\", route.path)
    };
    let refused = |reason: String| {
        crate::refusal::io_error(format!(
            "the volume {}, which shares disk {disk_number} with the volume to convert, {reason}",
            route.named
        ))
    };
    let observed = match question {
        ShadowQuestion::Nothing => return Ok(()),
        ShadowQuestion::CopiesOnly => crate::vss_observation::observe_snapshot_presence(&root),
        ShadowQuestion::CopiesAndStorage => crate::vss_observation::observe_catalog(&root),
    }
    .map_err(|error| {
        refused(format!(
            "could not be asked about its shadow copies, and without that answer the disk is not taken offline: {error}"
        ))
    })?;
    if let Some(reason) = shadow_reason(
        &route.named,
        observed.source_snapshot_presence.snapshots_present,
        observed
            .hosted_diff_areas
            .first()
            .map(|area| (area.original_volume.as_str(), area.used_bytes)),
    ) {
        return Err(refused(reason));
    }
    // Whatever else leaves the answer incomplete: a provider the converter
    // does not know, a query Windows did not finish.
    match question {
        ShadowQuestion::CopiesAndStorage => observed.require_observed_catalog_clear(),
        _ => observed.require_observed_snapshot_absence(),
    }
    .map_err(|error| refused(format!("cannot be taken offline with it: {error}")))
}

/// What is said of a volume beside the source that has shadow copies, or
/// stores those of another volume; `None` when it does neither. The volume
/// itself is not converted, so the words are not the source's.
fn shadow_reason(named: &str, has_copies: bool, stores: Option<(&str, i64)>) -> Option<String> {
    if has_copies {
        // The first of its mount points, as vssadmin takes it.
        let first = named.split(", ").next().unwrap_or(named);
        let drive = if first.starts_with("\\\\?\\") {
            first
        } else {
            first.trim_end_matches('\\')
        };
        return Some(format!(
            "has shadow copies (restore points, previous versions, or a backup's), and Windows may discard them when the volume's disk is taken offline. Delete them (`vssadmin delete shadows /for={drive}`), or convert when they are no longer needed"
        ));
    }
    stores.map(|(original, used)| {
        format!(
            "stores shadow copies of {original} ({used} bytes in use), which are lost when the disk is taken offline. Delete those shadow copies or move their storage to another disk (`vssadmin list shadowstorage`), then convert"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drive_inventory::{InventoryError, VolumeInventory};

    fn volume(filesystem: Option<&str>, read_only: Option<bool>) -> VolumeInventory {
        VolumeInventory {
            volume_guid_path: "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\".into(),
            mount_paths: vec!["W:\\".into()],
            filesystem: filesystem.map(str::to_owned),
            label: None,
            filesystem_read_only: read_only,
            volume_serial: None,
            contains_running_windows: Some(false),
            extents: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn failed(operation: &str, incomplete: bool) -> InventoryError {
        InventoryError {
            scope: "volume".into(),
            operation: operation.into(),
            os_error: Some(1005),
            message: "The volume does not contain a recognized file system.".into(),
            enumeration_incomplete: incomplete,
        }
    }

    #[test]
    fn a_volume_beside_the_source_is_asked_what_windows_can_answer_about_it() {
        // Shadow copies and shadow storage live on NTFS and ReFS volumes
        // Windows can write to.
        for name in ["NTFS", "ReFS", "ntfs"] {
            assert_eq!(
                shadow_question(&volume(Some(name), Some(false))),
                ShadowQuestion::CopiesAndStorage
            );
        }
        // A write-protected one keeps no storage up to date; another file
        // system holds none.
        assert_eq!(
            shadow_question(&volume(Some("NTFS"), Some(true))),
            ShadowQuestion::CopiesOnly
        );
        assert_eq!(
            shadow_question(&volume(Some("FAT32"), Some(false))),
            ShadowQuestion::CopiesOnly
        );
        // Without a file system Windows knows there is nothing to ask.
        assert_eq!(
            shadow_question(&volume(None, None)),
            ShadowQuestion::Nothing
        );
    }

    #[test]
    fn a_volume_beside_the_source_with_shadow_copies_is_named_with_its_own_remedy() {
        assert_eq!(shadow_reason("W:\\", false, None), None);
        let copies = shadow_reason("W:\\, C:\\mounted\\here\\", true, None).unwrap();
        assert!(
            copies.contains("vssadmin delete shadows /for=W:`"),
            "{copies}"
        );
        // It is not converted: nothing says a conversion destroys them.
        assert!(!copies.contains("conversion in place"), "{copies}");
        let unnamed = "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\";
        let copies = shadow_reason(unnamed, true, None).unwrap();
        assert!(copies.contains(&format!("/for={unnamed}`")), "{copies}");
        let stores = shadow_reason("W:\\", false, Some(("\\\\?\\Volume{2}\\", 4096))).unwrap();
        assert!(
            stores.starts_with("stores shadow copies of \\\\?\\Volume{2}\\ (4096 bytes in use)"),
            "{stores}"
        );
        // Shadow copies of its own are named first.
        let both = shadow_reason("W:\\", true, Some(("\\\\?\\Volume{2}\\", 4096))).unwrap();
        assert!(both.starts_with("has shadow copies"), "{both}");
    }

    #[test]
    fn only_a_missing_file_system_is_passed_over_in_a_volumes_errors() {
        let mut raw = volume(None, None);
        assert!(!only_unrecognized(&raw), "no error at all is not this case");
        raw.errors.push(failed("filesystem/label", false));
        assert!(only_unrecognized(&raw));
        // A volume whose extents or mount points could not be read is not
        // described, whatever else is known of it.
        raw.errors.push(failed("volume disk extents", false));
        assert!(!only_unrecognized(&raw));
        let mut partial = volume(None, None);
        partial.errors.push(failed("filesystem/label", true));
        assert!(!only_unrecognized(&partial));
        let mut named = volume(Some("NTFS"), Some(false));
        named.errors.push(failed("filesystem/label", false));
        assert!(!only_unrecognized(&named));
    }
}
