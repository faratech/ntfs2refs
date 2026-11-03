//! Ordinary pre-publication failure cleanup using only the same live NTFS
//! owner and its original, never-consumed freeze witness.
use super::{EventLog, PreparationObserver};
use crate::general_source_admission::resource::ResourceSourceContext;
use anyhow::Result;
use n2r_win32::general_layout::GeneralDiskBinding;

/// Early source collection has not constructed a semantic fingerprint yet.
/// It owns the same successfully isolated, read-only NTFS handle and no code
/// on this path has authority to write source bytes or publish AP. A real
/// pre-reserved workspace and two whole-source hashes protect this ordinary
/// in-process failure path; this is not restart/crash authority.
pub(crate) fn restore_isolated_source(
    mut source: n2r_win32::GeneralFrozenPartition,
    _workspace: &crate::ntfs_inspect::paged_storage::SourceRamLease,
    expected_geometry: &crate::ntfs_inspect::NtfsGeometry,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<GeneralDiskBinding> {
    use anyhow::{Context, ensure};
    use std::io::{Read, Seek, SeekFrom};
    ensure!(source.freeze_observation().is_some(), "original freeze witness absent");
    let binding = source.binding().clone();
    let before = source.state(events)?;
    ensure!(before.disk_attributes == 3, "original source is not excluded read-only");
    let length = source.byte_len();
    let mut boot = [0u8; 512];
    source.seek(SeekFrom::Start(0))?;
    source.read_exact(&mut boot)?;
    let geometry = crate::ntfs_inspect::inspect_boot_sector(&boot, length)
        .context("isolated original no longer has valid NTFS geometry")?;
    ensure!(&geometry == expected_geometry,
        "isolated NTFS geometry or volume serial differs from the live pre-freeze source");
    let sha = hex::encode(n2r_win32::sha256_native::hash_range(&mut source, 0, length)?);
    source.seek(SeekFrom::Start(0))?;
    let mut after_boot = [0u8; 512];
    source.read_exact(&mut after_boot)?;
    ensure!(source.freeze_observation().is_some() && source.state(events)? == before
        && boot == after_boot, "isolated NTFS source or boot identity changed");
    source.bring_original_online_unchanged(&sha, events)
        .context("early original NTFS online transition failed; source may require rediscovery")?;
    let mounted = n2r_win32::rediscover_general_volume_wait(binding.clone(), events)?;
    n2r_win32::volume_label::validate_original_partition(&binding, &mounted)?;
    ensure!(n2r_win32::mounted_filesystem_general(mounted.clone(), events)? == "NTFS",
        "early original source did not return as NTFS");
    Ok(mounted)
}

pub(crate) fn after_collection_failure(
    source: n2r_win32::GeneralFrozenPartition,
    workspace: Option<&crate::ntfs_inspect::paged_storage::SourceRamLease>,
    expected_geometry: &crate::ntfs_inspect::NtfsGeometry,
    events: &mut Vec<n2r_win32::NativeEvent>,
    original: anyhow::Error,
) -> anyhow::Error {
    let Some(workspace) = workspace else { return original; };
    // A separate native event vector prevents a prior failed operation's
    // partially filled 128-event batch from blocking the cleanup controls.
    let mut cleanup_events = Vec::new();
    let cleanup = restore_isolated_source(source, workspace, expected_geometry, &mut cleanup_events);
    events.extend(cleanup_events);
    match cleanup {
        Ok(mounted) => original.context(format!(
            "source collection failed before AP; unchanged original NTFS restored on disk {}",
            mounted.disk_number
        )),
        Err(error) => original.context(format!(
            "source collection failed before AP; original NTFS cleanup did not complete and the source may remain excluded or already be online: {error:#}"
        )),
    }
}

pub(super) fn restore_live_source<O: PreparationObserver>(
    context: ResourceSourceContext,
    events: &mut EventLog<'_, O>,
) -> Result<GeneralDiskBinding> {
    events.phase("restore-unchanged-original-ntfs");
    events.checkpoint()?;
    let EventLog { observer, events: native_events, .. } = events;
    context.restore_original_unchanged(native_events, |batch| {
        observer.native_events("restore-unchanged-original-ntfs", batch)
    })
}
