//! Opt-in ordinary-error restoration during initial NTFS isolation.
//! No source payload writer or AP marker exists in this path. Process/power
//! failure remains outside this in-process recovery contract.
use super::*;

fn boot(
    disk: &mut File,
    binding: &GeneralDiskBinding,
    buffer: &mut AlignedBuffer,
) -> io::Result<[u8; 4096]> {
    disk.seek(SeekFrom::Start(binding.identity.partition_offset))?;
    disk.read_exact(&mut buffer.bytes_mut()[..4096])?;
    let bytes: [u8; 4096] = buffer.bytes_mut()[..4096].try_into().expect("fixed boot window");
    if &bytes[3..11] != b"NTFS    " || bytes[510..512] != [0x55, 0xaa] {
        return Err(invalid("locked source boot identity is not NTFS"));
    }
    Ok(bytes)
}

fn same_layout(a: &GeneralDiskState, b: &GeneralDiskState) -> bool {
    a.device == b.device && a.disk_length == b.disk_length
        && a.alignment == b.alignment && a.gpt_layout == b.gpt_layout
}

/// Restore only the device whose actual original lock/management owners,
/// post-flush boot bytes and full pre-mutation disk state still agree.
fn restore(
    disk: &mut File,
    volume: &mut Option<File>,
    binding: &GeneralDiskBinding,
    original: &GeneralDiskState,
    original_boot: &[u8; 4096],
    buffer: &mut AlignedBuffer,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    let state = general_disk_state(disk, binding, events)?;
    if !same_layout(&state, original) || state.disk_attributes & !(OFFLINE | READ_ONLY) != 0
        || boot(disk, binding, buffer)? != *original_boot {
        return Err(invalid("isolation rollback source identity, GPT or locked NTFS boot changed"));
    }
    if let Some(handle) = volume.take() {
        // Do not clear exclusion if the actual lock-handle close is uncertain.
        close_file(handle, "close-isolation-rollback-volume-lock", events)?;
    }
    if state.disk_attributes != 0 {
        if let Err(error) = set_attributes(disk, 0, events) {
            let protected = set_attributes(disk, OFFLINE | READ_ONLY, events)
                .and_then(|()| {
                    let state = general_disk_state(disk, binding, events)?;
                    if !same_layout(&state, original) || state.disk_attributes != OFFLINE | READ_ONLY {
                        return Err(invalid("isolation rollback could not re-establish exclusion"));
                    }
                    Ok(())
                });
            return Err(io::Error::new(error.kind(), format!(
                "isolation rollback online request failed: {error}; re-exclusion result: {protected:?}"
            )));
        }
        if let Err(error) = control(disk, "refresh-isolation-rollback-properties", UPDATE_PROPERTIES, &[], 0, events) {
            let protected = set_attributes(disk, OFFLINE | READ_ONLY, events).and_then(|()| {
                let after = general_disk_state(disk, binding, events)?;
                if !same_layout(&after, original) || after.disk_attributes != OFFLINE | READ_ONLY {
                    return Err(invalid("isolation rollback re-exclusion differs"));
                }
                Ok(())
            });
            return Err(io::Error::new(error.kind(), format!(
                "isolation rollback refresh failed: {error}; re-exclusion result: {protected:?}"
            )));
        }
    }
    let validation = (|| -> io::Result<()> {
        let after = general_disk_state(disk, binding, events)?;
        if !same_layout(&after, original) || after.disk_attributes != 0 {
            return Err(invalid("isolation rollback online state or disk identity differs"));
        }
        if mounted_filesystem_general(binding.clone(), events)? != "NTFS" {
            return Err(invalid("isolation rollback did not rediscover original NTFS"));
        }
        Ok(())
    })();
    if let Err(error) = validation {
        if state.disk_attributes != 0 {
            let protected = set_attributes(disk, OFFLINE | READ_ONLY, events).and_then(|()| {
                let after = general_disk_state(disk, binding, events)?;
                if !same_layout(&after, original) || after.disk_attributes != OFFLINE | READ_ONLY {
                    return Err(invalid("isolation rollback re-exclusion differs"));
                }
                Ok(())
            });
            return Err(io::Error::new(error.kind(), format!(
                "isolation rollback validation failed: {error}; re-exclusion result: {protected:?}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

impl GeneralFrozenPartition {
    /// Identical admission scope to observed NTFS isolation, but ordinary
    /// errors after a successful volume lock attempt an in-process rollback.
    /// The legacy/diagnostic isolate methods do not call this entry point.
    pub fn isolate_observed_ntfs_with_resource_budget_restore_on_error(
        binding: GeneralDiskBinding,
        budget: crate::tree_resources::ResourceBudget,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        budget.validate()?;
        if mounted_filesystem_general(binding.clone(), events)? != "NTFS" {
            return Err(invalid("observed source freeze requires mounted NTFS"));
        }
        let mounted_ntfs = crate::txf_native::observe_general(binding.clone())?;
        if mounted_ntfs.observation.default_rm_state() == crate::txf_native::DefaultRmState::Unresolved {
            return Err(invalid("default NTFS resource manager is not idle or inactive"));
        }
        let before = probe_general(binding.clone(), events)?;
        let mut management = device_file(&format!("\\\\.\\PhysicalDrive{}", binding.disk_number), true, true)?;
        let pre_lock = general_disk_state(&management, &binding, events)?;
        if pre_lock.disk_attributes != 0 || pre_lock.device != before.device
            || pre_lock.disk_length != before.disk_length || pre_lock.alignment != before.alignment
            || pre_lock.gpt_layout != before.gpt_layout {
            return Err(invalid("general disk changed before lock"));
        }
        let mut volume = Some(device_file(&binding.volume_path()?, true, false)?);
        let extents = control(volume.as_ref().expect("volume owner"), "general-lock-volume-extents", VOLUME_EXTENTS, &[], 1024, events)?;
        binding.validate_volume_extent(&extents)?;
        let mut buffer = AlignedBuffer::new()?;
        let mut locked = false;
        let mut original_boot = None;
        let result = (|| -> io::Result<(File, GeneralDiskState)> {
            control(volume.as_ref().expect("volume owner"), "general-lock-volume", LOCK, &[], 0, events)?;
            locked = true;
            // FSCTL_LOCK_VOLUME flushed cached NTFS writes before this pin.
            original_boot = Some(boot(&mut management, &binding, &mut buffer)?);
            control(volume.as_ref().expect("volume owner"), "general-dismount-volume", DISMOUNT, &[], 0, events)?;
            set_attributes(&management, OFFLINE | READ_ONLY, events)?;
            let frozen = general_disk_state(&management, &binding, events)?;
            if frozen.disk_attributes != OFFLINE | READ_ONLY || !same_layout(&frozen, &pre_lock) {
                return Err(invalid("general disk exclusion or identity changed"));
            }
            let readonly = device_file(&format!("\\\\.\\PhysicalDrive{}", binding.disk_number), false, true)?;
            if general_disk_state(&readonly, &binding, events)? != frozen {
                return Err(invalid("general read-only reopen differs after exclusion"));
            }
            Ok((readonly, frozen))
        })();
        let (file, frozen_state) = match result {
            Ok(value) => value,
            Err(original) => {
                if !locked { return Err(original); }
                let Some(original_boot) = original_boot else {
                    // No attribute mutation was attempted before the boot
                    // pin; closing the lock owner returns normal OS control.
                    return Err(io::Error::new(original.kind(), format!("source isolation stopped before its locked NTFS boot pin; no disk attributes were requested: {original}")));
                };
                let mut cleanup_events = Vec::new();
                let cleanup = restore(&mut management, &mut volume, &binding, &pre_lock,
                    &original_boot, &mut buffer, &mut cleanup_events);
                events.extend(cleanup_events);
                return match cleanup {
                    Ok(()) => Err(io::Error::new(original.kind(), format!("source isolation failed; original NTFS availability restored: {original}"))),
                    Err(error) => Err(io::Error::new(original.kind(), format!("source isolation failed: {original}; verified restoration did not complete and source may remain excluded or already be online: {error}"))),
                };
            }
        };
        // The guarded volume and management handles remain alive until the
        // exact frozen readonly route is verified. If either close fails,
        // leave the already excluded device offline rather than guessing.
        close_file(volume.take().expect("locked volume owner"), "close-general-volume-lock", events)?;
        close_file(management, "close-general-management", events)?;
        Ok(Self {
            file, binding, frozen_state: frozen_state.clone(), position: 0, buffer,
            native_bytes_read: 0, resource_budget: Some(budget),
            freeze_observation: Some(GeneralFreezeObservation { mounted_ntfs, frozen_state }),
            allocation_capture: None,
        })
    }
}
