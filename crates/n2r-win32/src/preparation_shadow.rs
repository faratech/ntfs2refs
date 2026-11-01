//! Point-in-time occupancy hints for NTFS-owned preparation. These ranges do
//! not reserve space, prove complete ReFS ownership, or authorize source writes.
use crate::{
    attestation::ResourceProfile, bitmap_observation, general_layout::GeneralDiskBinding, layout,
    native, stream_native,
};
use serde::Serialize;
use std::{fs::OpenOptions, io, os::windows::fs::OpenOptionsExt};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ByteInterval {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub binding: GeneralDiskBinding,
    pub refs_volume_data: crate::attestation::IoctlQuery,
    pub legacy_bitmap: crate::bitmap_paging::Proof,
    pub metadata_bitmap: crate::bitmap_paging::Proof,
    pub occupied: Vec<ByteInterval>,
    pub bootstrap_avoidance: Vec<ByteInterval>,
    pub before: crate::GeneralDiskState,
    pub after: crate::GeneralDiskState,
    pub final_allocation_complete: bool,
    pub reserves_target_space: bool,
    pub source_write_authority: bool,
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn observe(
    binding: GeneralDiskBinding,
    profile: Option<ResourceProfile>,
) -> io::Result<Observation> {
    let _privileges =
        crate::attestation_native::Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    binding.validate()?;
    let length = binding.identity.partition_bytes;
    if length
        > profile.map_or(
            crate::general_layout::MAX_LIVE_PARTITION_BYTES,
            ResourceProfile::maximum_partition_bytes,
        )
    {
        return Err(bad(
            "shadow occupancy exceeds its explicit resource profile",
        ));
    }
    let mut events = Vec::new();
    let before = native::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
    if before.disk_attributes != 0 {
        return Err(bad("new shadow is not online and writable"));
    }
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(binding.volume_path()?)?;
    let extents = stream_native::ioctl(&volume, 0x0056_0000, &[], 32);
    if let Some(error) = extents.native_error {
        return Err(io::Error::from_raw_os_error(error));
    }
    binding.validate_volume_extent(&extents.bytes)?;
    let geometry = stream_native::ioctl(&volume, 0x0009_02d8, &[], 256);
    if let Some(error) = geometry.native_error {
        return Err(io::Error::from_raw_os_error(error));
    }
    let b = &geometry.bytes;
    if b.len() < 64
        || !(64..=b.len()).contains(&(layout::u32_at(b, 0)? as usize))
        || layout::u32_at(b, 4)? != 3
        || layout::u32_at(b, 8)? != 14
        || layout::u32_at(b, 56)? != binding.identity.logical_sector_bytes
        || layout::u32_at(b, 60)? != 4096
        || layout::u64_at(b, 24)? != length / u64::from(binding.identity.logical_sector_bytes)
        || layout::u64_at(b, 32)? != length / 4096
    {
        return Err(bad("preparation shadow ReFS3.14/4KiB geometry differs"));
    }
    let legacy = bitmap_observation::Observation::capture(&volume, &[0; 8], length, true)?;
    let mut input = [0u8; 16];
    input[8] = 1;
    let metadata = bitmap_observation::Observation::capture(&volume, &input, length, true)?;
    let a = legacy.allocation_map(length)?;
    let m = metadata.allocation_map(length)?;
    let count = a
        .ranges
        .len()
        .checked_add(m.ranges.len())
        .ok_or_else(|| bad("shadow range count overflow"))?;
    let mut occupied = Vec::<ByteInterval>::new();
    occupied
        .try_reserve_exact(count)
        .map_err(|_| bad("shadow occupancy storage unavailable"))?;
    for range in a.ranges.into_iter().chain(m.ranges) {
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| bad("shadow range overflow"))?;
        if range.length == 0
            || !range.offset.is_multiple_of(4096)
            || !range.length.is_multiple_of(4096)
            || end > length
        {
            return Err(bad("shadow occupancy leaves its physical domain"));
        }
        occupied.push(ByteInterval {
            offset: range.offset,
            length: range.length,
        });
    }
    occupied.sort_unstable_by_key(|r| r.offset);
    let mut used = 0usize;
    for index in 0..occupied.len() {
        let next = occupied[index];
        if used > 0 && next.offset <= occupied[used - 1].offset + occupied[used - 1].length {
            let end = (next.offset + next.length)
                .max(occupied[used - 1].offset + occupied[used - 1].length);
            occupied[used - 1].length = end - occupied[used - 1].offset;
        } else {
            occupied[used] = next;
            used += 1;
        }
    }
    occupied.truncate(used);
    let again = stream_native::ioctl(&volume, 0x0009_02d8, &[], 256);
    if again.native_error.is_some()
        || again.bytes.len() < 64
        || again.bytes[..40] != geometry.bytes[..40]
        || again.bytes[56..64] != geometry.bytes[56..64]
    {
        return Err(bad(
            "shadow identity/geometry changed around occupancy observation",
        ));
    }
    let after = native::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
    if before != after {
        return Err(bad(
            "shadow route/state changed around occupancy observation",
        ));
    }
    // Conservative planning exclusions, not a normative bootstrap footprint.
    let guard = length.min(1024 * 1024);
    let bootstrap_avoidance = vec![
        ByteInterval {
            offset: 0,
            length: guard,
        },
        ByteInterval {
            offset: length - guard,
            length: guard,
        },
    ];
    Ok(Observation {
        binding,
        refs_volume_data: geometry,
        legacy_bitmap: legacy.proof(),
        metadata_bitmap: metadata.proof(),
        occupied,
        bootstrap_avoidance,
        before,
        after,
        final_allocation_complete: false,
        reserves_target_space: false,
        source_write_authority: false,
    })
}
