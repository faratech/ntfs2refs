//! Strict geometry-bound backup checks against actual source reads.
#[cfg(windows)]
use crate::ntfs_inspect::RootFileDomain;
use crate::ntfs_inspect::{self as ntfs, AttributeInventory, NtfsInspection};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

/// Constructed only by successful reads and validation, never deserialized.
/// It proves these backups, not clean log state or source admission.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedBackups {
    inspection_fingerprint: String,
    partition_length: u64,
    primary_boot_sha256: String,
    backup_boot_sha256: String,
    mirrored_records: u32,
    mirrored_record_sha256: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_mirror: Option<ExtendedMirrorEvidence>,
}

#[derive(Clone, Debug, Serialize)]
struct ExtendedMirrorEvidence {
    profile: &'static str,
    declared_record_slots: u32,
    equal_extra_slots: Vec<u32>,
    inactive_format_padding_slots: Vec<u32>,
    primary_region_sha256: String,
    mirror_region_sha256: String,
}
fn fingerprint(raw: &NtfsInspection) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(raw)?)))
}
impl VerifiedBackups {
    pub fn binds(&self, raw: &NtfsInspection) -> bool {
        fingerprint(raw).is_ok_and(|hash| hash == self.inspection_fingerprint)
    }

    #[cfg(windows)]
    pub fn binds_domain(&self, source: &ntfs::PagedInspection) -> bool {
        source
            .canonical_sha256()
            .is_ok_and(|hash| hash == self.inspection_fingerprint)
    }
}
fn data(raw: &NtfsInspection, record: u64) -> Result<&AttributeInventory> {
    let files: Vec<_> = raw
        .files
        .iter()
        .filter(|f| f.record_number == record)
        .collect();
    ensure!(
        files.len() == 1 && files[0].base_file_reference == 0,
        "backup object identity is incomplete"
    );
    let attributes: Vec<_> = files[0]
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x80 && a.name_utf16.is_empty())
        .collect();
    ensure!(
        attributes.len() == 1,
        "backup object unnamed DATA is missing/duplicated"
    );
    Ok(attributes[0])
}
pub fn verify<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    raw: &NtfsInspection,
) -> Result<VerifiedBackups> {
    ntfs::revalidate_mft_mapping(reader, raw)?;
    verify_parts(
        reader,
        length,
        &raw.geometry,
        data(raw, 0)?,
        data(raw, 1)?,
        || fingerprint(raw),
    )
}

#[cfg(windows)]
pub fn verify_domain<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    source: &ntfs::PagedInspection,
) -> Result<VerifiedBackups> {
    source.revalidate()?;
    let mapping = ntfs::CheckedMftDomain::open(reader, source)?;
    let mft = mapping.data(reader, source, 0, &[])?;
    let mirror = mapping.data(reader, source, 1, &[])?;
    let result = verify_parts(
        reader,
        length,
        &source.header().geometry,
        &mft,
        &mirror,
        || source.canonical_sha256(),
    )?;
    source.revalidate()?;
    Ok(result)
}

fn verify_parts<R: Read + Seek>(
    reader: &mut R,
    length: u64,
    g: &ntfs::NtfsGeometry,
    mft: &AttributeInventory,
    mirror: &AttributeInventory,
    fingerprint: impl FnOnce() -> Result<String>,
) -> Result<VerifiedBackups> {
    ensure!(
        ntfs::supports_sector_size(g.bytes_per_sector)
            && crate::ntfs_index::supports_cluster_size(g.cluster_size)
            && ntfs::supports_file_record_size(g.file_record_size),
        "backup checks cannot read this geometry: {}-byte sectors, {}-byte clusters, {}-byte MFT records",
        g.bytes_per_sector,
        g.cluster_size,
        g.file_record_size
    );
    // NTFS leaves the partition's last sector to the backup boot sector.
    let sector = u64::from(g.bytes_per_sector);
    ensure!(
        length == g.volume_size
            || length
                == g.volume_size
                    .checked_add(sector)
                    .context("backup length overflow")?,
        "backup partition length differs"
    );
    let mut boot = vec![0; sector as usize];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut boot)?;
    let observed = ntfs::inspect_boot_sector(&boot[..512], length)?;
    ensure!(
        serde_json::to_vec(&observed)? == serde_json::to_vec(g)?,
        "source boot geometry differs from inventory"
    );
    let mut backup = vec![0; sector as usize];
    reader.seek(SeekFrom::Start(length - sector))?;
    reader.read_exact(&mut backup)?;
    ensure!(boot == backup, "primary and backup boot sectors differ");
    for (attribute, lcn) in [(mft, g.mft_lcn), (mirror, g.mftmirr_lcn)] {
        ensure!(
            attribute
                .extents
                .first()
                .is_some_and(|e| e.logical_offset == 0
                    && e.physical_offset == Some(lcn * u64::from(g.cluster_size))),
            "backup bootstrap location differs from DATA map"
        );
    }
    // Keep the complete geometry-sized stream checked and hashed, but do not
    // equate its allocation/logical length with synchronized live record count.
    // The bootstrap contract is four records; a larger stream may retain
    // inactive format templates after those records became live in the MFT.
    let mirror_bytes = u64::from(g.cluster_size).max(4 * u64::from(g.file_record_size));
    ensure!(
        mirror.logical_size == mirror_bytes && mirror.initialized_size == mirror_bytes,
        "MFT mirror length differs from the source cluster/record geometry"
    );
    let declared_slots = u32::try_from(mirror_bytes / u64::from(g.file_record_size))?;
    let mut primary = vec![0; g.file_record_size as usize];
    let mut mirrored = vec![0; g.file_record_size as usize];
    let mut hashes = vec![];
    let mut equal_extra_slots = Vec::new();
    let mut padding_slots = Vec::new();
    let mut primary_hash = Sha256::new();
    let mut mirror_hash = Sha256::new();
    for i in 0..declared_slots {
        let offset = u64::from(i) * u64::from(g.file_record_size);
        ntfs::read_nonresident_inventory_range(reader, mft, offset, &mut primary, g)?;
        ntfs::read_nonresident_inventory_range(reader, mirror, offset, &mut mirrored, g)?;
        ntfs::validate_file_record(&primary, g)
            .with_context(|| format!("primary MFT record {i}"))?;
        ntfs::validate_file_record(&mirrored, g)
            .with_context(|| format!("mirror MFT record {i}"))?;
        primary_hash.update(&primary);
        mirror_hash.update(&mirrored);
        if i < 4 {
            ensure!(
                primary == mirrored,
                "primary and mirror MFT record {i} differ"
            );
            hashes.push(hex::encode(Sha256::digest(&primary)));
        } else if primary == mirrored {
            equal_extra_slots.push(i);
        } else {
            ensure!(
                ntfs::inactive_mirror_template(&mirrored, g, i)?,
                "primary and mirror MFT record {i} differ outside the recognized inactive format padding"
            );
            padding_slots.push(i);
        }
    }
    Ok(VerifiedBackups {
        inspection_fingerprint: fingerprint()?,
        partition_length: length,
        primary_boot_sha256: hex::encode(Sha256::digest(&boot)),
        backup_boot_sha256: hex::encode(Sha256::digest(&backup)),
        mirrored_records: 4,
        mirrored_record_sha256: hashes,
        extended_mirror: (declared_slots > 4).then(|| ExtendedMirrorEvidence {
            profile: "ntfs-inactive-mirror-padding-v1",
            declared_record_slots: declared_slots,
            equal_extra_slots,
            inactive_format_padding_slots: padding_slots,
            primary_region_sha256: hex::encode(primary_hash.finalize()),
            mirror_region_sha256: hex::encode(mirror_hash.finalize()),
        }),
    })
}
