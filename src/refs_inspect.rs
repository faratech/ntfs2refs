//! Conservative, read-only inspection of a ReFS volume header.
//!
//! Field positions are independently described by libfsrefs' format research and
//! forefst's VBR reference. These are format observations, not a Microsoft write
//! specification. In particular, no metadata page layout, checksum algorithm,
//! native/upgraded provenance, or boot eligibility is inferred here.
//!
//! References:
//! - https://github.com/libyal/libfsrefs/blob/main/documentation/Resilient%20File%20System%20(ReFS).asciidoc
//! - https://xbpt.gitlab.io/forefst/structures/vbr/

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};

const HEADER_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefsGeometry {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub bytes_per_cluster: u32,
    pub total_sectors: u64,
    pub volume_bytes: u64,
    pub image_bytes: u64,
    pub trailing_bytes: u64,
    pub major_version: u8,
    pub minor_version: u8,
    pub volume_serial: u64,
    /// Observed value only; this reader does not validate this checksum.
    pub recognition_checksum: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupHeaderStatus {
    /// A matching header is evidence of redundant bytes, not of consistency.
    Matching,
    Different,
    NotRecognized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefsInspection {
    pub geometry: RefsGeometry,
    /// Probe the last logical sector declared by the primary header. This is
    /// deliberately not a scan or an authoritative redundant-header validator.
    pub backup_probe_offset: u64,
    pub backup_header_status: BackupHeaderStatus,
    pub native_format_provenance: String,
    pub metadata_verified: bool,
    pub checksum_verified: bool,
    pub conversion_profile_qualified: bool,
    /// Bounded research observations; never qualifies metadata or a writer.
    #[serde(default)]
    pub bootstrap: Option<crate::refs_bootstrap::BootstrapProbe>,
    pub warnings: Vec<String>,
}

/// Inspect a raw *volume* beginning at reader offset zero. `length` bounds the
/// supplied volume view. A whole-disk image must be sliced to its partition by
/// the caller; a VHDX container is not a raw volume.
pub fn inspect<R: Read + Seek>(reader: &mut R, length: u64) -> Result<RefsInspection> {
    inspect_profile(reader, length, true, false)
}

pub fn inspect_with_resource_profile<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<RefsInspection> {
    inspect_profile(
        reader,
        length,
        true,
        resources != crate::ntfs_admission::ResourceProfile::AlphaV1,
    )
}

/// Read redundant headers and physical bootstrap structures without building
/// container maps. This locates the Small root, not virtual metadata pages.
pub fn inspect_physical_bootstrap<R: Read + Seek>(
    reader: &mut R,
    length: u64,
) -> Result<RefsInspection> {
    inspect_profile(reader, length, false, false)
}

fn inspect_profile<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    include_virtual: bool,
    compact_containers: bool,
) -> Result<RefsInspection> {
    if length < HEADER_BYTES as u64 {
        bail!("ReFS header requires at least 512 bytes");
    }
    reader
        .seek(SeekFrom::Start(0))
        .context("seek ReFS primary header")?;
    let mut primary = [0_u8; HEADER_BYTES];
    reader
        .read_exact(&mut primary)
        .context("read ReFS primary header")?;
    let geometry = inspect_boot_sector(&primary, length)?;

    // inspect_boot_sector verifies at least two sectors and bounded geometry.
    let backup_probe_offset = geometry.volume_bytes - u64::from(geometry.bytes_per_sector);
    reader
        .seek(SeekFrom::Start(backup_probe_offset))
        .context("seek ReFS backup header probe")?;
    let mut backup = [0_u8; HEADER_BYTES];
    reader
        .read_exact(&mut backup)
        .context("read ReFS backup header probe (truncated volume)")?;
    let backup_header_status = if backup == primary {
        BackupHeaderStatus::Matching
    } else if backup[3..11] == *b"ReFS\0\0\0\0" && backup[16..20] == *b"FSRS" {
        BackupHeaderStatus::Different
    } else {
        BackupHeaderStatus::NotRecognized
    };
    let mut warnings = vec![
        "Header geometry and optional bounded bootstrap candidates are inspected; complete metadata, allocation, checksums, and filesystem health are not verified.".to_owned(),
        "The header version does not establish formatter provenance, native versus upgraded layout, or boot compatibility.".to_owned(),
        "No ReFS writer profile has passed the native-driver qualification gates.".to_owned(),
    ];
    if backup_header_status != BackupHeaderStatus::Matching {
        warnings.push("The header probe at the declared last sector does not match the primary header; investigate the captured image and its exact format before drawing a corruption conclusion.".to_owned());
    }
    if geometry.trailing_bytes > 0 {
        warnings.push(
            "The supplied volume view is larger than the filesystem size declared in its header."
                .to_owned(),
        );
    }
    let bootstrap = if compact_containers {
        crate::refs_bootstrap::inspect_compact(reader, &geometry, &primary)?
    } else if include_virtual {
        crate::refs_bootstrap::inspect(reader, &geometry, &primary)?
    } else {
        crate::refs_bootstrap::inspect_physical(reader, &geometry, &primary)?
    };
    Ok(RefsInspection {
        geometry,
        backup_probe_offset,
        backup_header_status,
        native_format_provenance: "unknown".to_owned(),
        metadata_verified: false,
        checksum_verified: false,
        conversion_profile_qualified: false,
        bootstrap,
        warnings,
    })
}

/// Validate the small common header grammar only. Passing this function does
/// not establish that Windows can mount or boot the filesystem.
pub fn inspect_boot_sector(bytes: &[u8], length: u64) -> Result<RefsGeometry> {
    if bytes.len() < HEADER_BYTES || length < HEADER_BYTES as u64 {
        bail!("ReFS header requires at least 512 bytes");
    }
    if bytes[3..11] == *b"-FVE-FS-" {
        bail!("BitLocker-encrypted volume: raw filesystem inspection is unsupported");
    }
    if bytes[3..11] != *b"ReFS\0\0\0\0" {
        bail!("ReFS signature not found at volume offset 3");
    }
    if bytes[16..20] != *b"FSRS" {
        bail!("ReFS recognition structure signature is invalid");
    }
    if le_u16(bytes, 20) != HEADER_BYTES as u16 {
        bail!("unsupported ReFS recognition structure size");
    }
    let total_sectors = le_u64(bytes, 24);
    let bytes_per_sector = le_u32(bytes, 32);
    if !matches!(bytes_per_sector, 512 | 4096) {
        bail!("unsupported ReFS sector size {bytes_per_sector}; expected 512 or 4096");
    }
    if total_sectors < 2 {
        bail!("ReFS volume must declare at least two sectors");
    }
    let sectors_per_cluster = le_u32(bytes, 36);
    if !sectors_per_cluster.is_power_of_two() {
        bail!("ReFS sectors per cluster must be a nonzero power of two");
    }
    let bytes_per_cluster = bytes_per_sector
        .checked_mul(sectors_per_cluster)
        .context("ReFS cluster size overflows u32")?;
    if !matches!(bytes_per_cluster, 4096 | 65536) {
        bail!(
            "unsupported ReFS cluster size {bytes_per_cluster}; this inspector handles 4096 or 65536 bytes"
        );
    }
    let volume_bytes = total_sectors
        .checked_mul(u64::from(bytes_per_sector))
        .context("ReFS volume size overflows u64")?;
    if volume_bytes > length {
        bail!("ReFS declares {volume_bytes} bytes but the supplied volume view has only {length}");
    }
    if volume_bytes < u64::from(bytes_per_cluster) {
        bail!("ReFS volume is smaller than one allocation cluster");
    }
    let major_version = bytes[40];
    if !matches!(major_version, 1..=3) {
        bail!(
            "unsupported ReFS major version {major_version}; refusing to assume its header layout"
        );
    }
    Ok(RefsGeometry {
        bytes_per_sector,
        sectors_per_cluster,
        bytes_per_cluster,
        total_sectors,
        volume_bytes,
        image_bytes: length,
        trailing_bytes: length - volume_bytes,
        major_version,
        minor_version: bytes[41],
        volume_serial: le_u64(bytes, 56),
        recognition_checksum: le_u16(bytes, 22),
    })
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated header bounds"),
    )
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated header bounds"),
    )
}
