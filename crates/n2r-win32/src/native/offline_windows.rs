//! Whole-disk exclusion for an installed Windows disk while another Windows
//! installation owns the machine. A requested topology is never authorization.
use super::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
use super::*;
use crate::general_layout::GeneralDiskLayoutProfile;

pub(super) fn require_detached_roles(
    disk: &File,
    binding: &GeneralDiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    if binding.layout_profile != GeneralDiskLayoutProfile::OfflineWindows {
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
        return Err(invalid(
            "offline Windows source disk contains an active or unresolved pagefile",
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
        return Err(invalid(
            "offline Windows source disk contains a configured or unresolved dump destination",
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
            "current Windows/system roles changed across offline Windows source observation",
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
/// three; none may remain mounted when the whole physical disk is excluded.
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

fn lock_volumes(
    binding: &GeneralDiskBinding,
    native_layout: &[u8],
    skip_selected: bool,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<File>> {
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
    let msr = layout::guid_bytes("e3c9e316-0b5c-4db8-817d-f92df00215ae")?;
    let mut ranges = Vec::new();
    for row in native_layout[48..].chunks_exact(144) {
        if layout::u32_at(row, 24)? != 0 && layout::u64_at(row, 16)? != 0 && row[32..48] != msr {
            ranges.push((layout::u64_at(row, 8)?, layout::u64_at(row, 16)?));
        }
    }
    if ranges.len() != 3 {
        return Err(invalid(
            "Windows source requires its OS, EFI and recovery filesystem volumes",
        ));
    }
    let mut routes = Vec::new();
    for volume in &inventory.volumes {
        if !volume
            .extents
            .iter()
            .any(|e| e.disk_number == binding.disk_number)
        {
            continue;
        }
        if volume.extents.len() != 1
            || !volume.errors.is_empty()
            || volume.contains_running_windows != Some(false)
        {
            return Err(invalid("ambiguous Windows source volume catalog"));
        }
        let e = &volume.extents[0];
        let range = (e.offset_bytes, e.length_bytes);
        if !ranges.contains(&range)
            || routes
                .iter()
                .any(|(r, _): &((u64, u64), String)| *r == range)
        {
            return Err(invalid(
                "Windows source volume aliases or extents differ from complete GPT",
            ));
        }
        routes.push((range, volume.volume_guid_path.clone()));
    }
    if routes.len() != ranges.len() {
        return Err(invalid(
            "a Windows source filesystem is missing from the complete volume catalog",
        ));
    }
    routes.sort_by_key(|(range, _)| range.0);
    let mut locks = Vec::new();
    for ((offset, length), path) in routes {
        if skip_selected
            && offset == binding.identity.partition_offset
            && length == binding.identity.partition_bytes
        {
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
        control(
            &file,
            "offline-windows-lock-filesystem",
            LOCK,
            &[],
            0,
            events,
        )?;
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
