//! Read-only filesystem geometry, distinct from the physical GPT partition.
//! Observations cannot construct a staging owner or authorize conversion.
use super::{GeneralDiskBinding, control, invalid, layout};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

/// Versioned observation only. The uncovered tail has no filesystem allocation
/// bits and must never be inferred to be free or suitable for retained data.
#[derive(Debug, Serialize)]
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub geometry_profile: &'static str,
    pub binding: GeneralDiskBinding,
    pub physical_partition_bytes: u64,
    pub filesystem_bytes: u64,
    pub uncovered_tail_offset: u64,
    pub uncovered_tail_bytes: u64,
    pub uncovered_tail_classification: &'static str,
    pub native_total_sectors: u64,
    pub native_total_clusters: u64,
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
    pub refs_major: u32,
    pub refs_minor: u32,
    pub primary_vbr: Vec<u8>,
    pub primary_vbr_native_geometry_agree: bool,
    pub held_volume_route_unchanged: bool,
    pub filesystem_matches_partition_floor_64_mib: bool,
    pub rounding_is_a_format_contract: bool,
    pub full_partition_extent_matches: bool,
    pub filesystem_health_or_metadata_integrity_verified: bool,
    pub conversion_profile_qualified: bool,
    pub grants_source_or_replay_authority: bool,
}

/// The parent calls this only on its already formatted, constructor-owned
/// volume. No public constructor takes a saved binding or formatting request.
pub(super) fn observe_formatted(
    volume: &File,
    binding: &GeneralDiskBinding,
    data: &[u8],
) -> io::Result<Observation> {
    binding.validate()?;
    let before = control(volume, 0x0056_0000, &[], 32)?;
    binding.validate_volume_extent(&before)?;
    if data.len() < 64
        || !(64..=data.len()).contains(&(layout::u32_at(data, 0)? as usize))
        || (layout::u32_at(data, 4)?, layout::u32_at(data, 8)?) != crate::target_refs_version::get()
        || !matches!(layout::u32_at(data, 56)?, 512 | 4096)
        || layout::u32_at(data, 56)? != binding.identity.logical_sector_bytes
        || layout::u32_at(data, 60)? != crate::target_cluster::bytes_u32()
    {
        return Err(invalid(&format!(
            "observed extent is not the native ReFS {}.{} geometry profile with {}-byte clusters",
            crate::target_refs_version::get().0,
            crate::target_refs_version::get().1,
            crate::target_cluster::bytes()
        )));
    }
    let sector = layout::u32_at(data, 56)?;
    let cluster = layout::u32_at(data, 60)?;
    let sectors = layout::u64_at(data, 24)?;
    let clusters = layout::u64_at(data, 32)?;
    let filesystem_bytes = sectors
        .checked_mul(u64::from(sector))
        .filter(|bytes| *bytes > 0 && *bytes <= binding.identity.partition_bytes)
        .ok_or_else(|| invalid("native filesystem extent escapes its physical GPT partition"))?;
    if clusters.checked_mul(u64::from(cluster)) != Some(filesystem_bytes) {
        return Err(invalid(
            "native filesystem sector and cluster extents disagree",
        ));
    }
    // A volume read uses its logical sector size; the recognition header is
    // always the first 512 bytes. No partition-tail or payload scan is needed.
    let mut reader = volume.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut boot = vec![0; sector as usize];
    reader.read_exact(&mut boot)?;
    let vbr = &boot[..512];
    if vbr[3..11] != *b"ReFS\0\0\0\0"
        || vbr[16..20] != *b"FSRS"
        || u16::from_le_bytes(vbr[20..22].try_into().unwrap()) != 512
        || u32::from(vbr[40]) != layout::u32_at(data, 4)?
        || u32::from(vbr[41]) != layout::u32_at(data, 8)?
        || layout::u64_at(vbr, 24)? != sectors
        || layout::u32_at(vbr, 32)? != sector
        || layout::u32_at(vbr, 36)?.checked_mul(sector) != Some(cluster)
    {
        return Err(invalid(
            "primary ReFS VBR and native filesystem geometry disagree",
        ));
    }
    let again = control(volume, 0x0009_02d8, &[], 256)?;
    let after = control(volume, 0x0056_0000, &[], 32)?;
    binding.validate_volume_extent(&after)?;
    if again.len() < 64
        || again[..40] != data[..40]
        || again[56..64] != data[56..64]
        || after != before
    {
        return Err(invalid(
            "formatted volume route or filesystem geometry changed during observation",
        ));
    }
    let partition = binding.identity.partition_bytes;
    const CONTAINER: u64 = 64 << 20;
    Ok(Observation {
        schema_version: 1,
        kind: "observed-native-refs-filesystem-extent",
        geometry_profile: if cluster == 65536 {
            "native-refs3.14-64k-observed-extent-v1"
        } else {
            "native-refs3.14-4k-observed-extent-v1"
        },
        binding: binding.clone(),
        physical_partition_bytes: partition,
        filesystem_bytes,
        uncovered_tail_offset: filesystem_bytes,
        uncovered_tail_bytes: partition - filesystem_bytes,
        uncovered_tail_classification: "outside-observed-filesystem-domain; allocation unknown, not free",
        native_total_sectors: sectors,
        native_total_clusters: clusters,
        bytes_per_sector: sector,
        bytes_per_cluster: cluster,
        refs_major: crate::target_refs_version::get().0,
        refs_minor: crate::target_refs_version::get().1,
        primary_vbr: vbr.to_vec(),
        primary_vbr_native_geometry_agree: true,
        held_volume_route_unchanged: true,
        filesystem_matches_partition_floor_64_mib: filesystem_bytes
            == partition / CONTAINER * CONTAINER,
        rounding_is_a_format_contract: false,
        full_partition_extent_matches: filesystem_bytes == partition,
        filesystem_health_or_metadata_integrity_verified: false,
        conversion_profile_qualified: false,
        grants_source_or_replay_authority: false,
    })
}
