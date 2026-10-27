//! Strict geometry-bound backup checks against actual source reads.
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
}
fn fingerprint(raw: &NtfsInspection) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(raw)?)))
}
impl VerifiedBackups {
    pub fn binds(&self, raw: &NtfsInspection) -> bool {
        fingerprint(raw).is_ok_and(|hash| hash == self.inspection_fingerprint)
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
    let g = &raw.geometry;
    ensure!(
        g.bytes_per_sector == 512
            && crate::ntfs_index::supports_cluster_size(g.cluster_size)
            && g.file_record_size == 1024,
        "backup checks require supported clusters, 512-byte sectors and 1 KiB MFT records"
    );
    ensure!(
        length == g.volume_size
            || length
                == g.volume_size
                    .checked_add(512)
                    .context("backup length overflow")?,
        "backup partition length differs"
    );
    let mut boot = vec![0; 512];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut boot)?;
    let observed = ntfs::inspect_boot_sector(&boot, length)?;
    ensure!(
        serde_json::to_vec(&observed)? == serde_json::to_vec(g)?,
        "source boot geometry differs from inventory"
    );
    let mut backup = vec![0; 512];
    reader.seek(SeekFrom::Start(length - 512))?;
    reader.read_exact(&mut backup)?;
    ensure!(boot == backup, "primary and backup boot sectors differ");
    let mft = data(raw, 0)?;
    let mirror = data(raw, 1)?;
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
    // NTFS mirrors at least four file records, or one complete cluster when
    // that is larger. Validate the entire declared bootstrap mirror, using
    // fixed record buffers rather than allocating a cluster-sized pair.
    let mirror_bytes = u64::from(g.cluster_size).max(4 * u64::from(g.file_record_size));
    ensure!(
        mirror.logical_size == mirror_bytes && mirror.initialized_size == mirror_bytes,
        "MFT mirror length differs from the source cluster/record geometry"
    );
    let mirrored_records = u32::try_from(mirror_bytes / u64::from(g.file_record_size))?;
    let mut primary = [0; 1024];
    let mut mirrored = [0; 1024];
    let mut hashes = vec![];
    for i in 0..mirrored_records {
        let offset = u64::from(i) * u64::from(g.file_record_size);
        ntfs::read_nonresident_inventory_range(reader, mft, offset, &mut primary, g)?;
        ntfs::read_nonresident_inventory_range(reader, mirror, offset, &mut mirrored, g)?;
        ntfs::validate_file_record(&primary, g)
            .with_context(|| format!("primary MFT record {i}"))?;
        ntfs::validate_file_record(&mirrored, g)
            .with_context(|| format!("mirror MFT record {i}"))?;
        // Conservative: no normalization of differing LSNs, USA encodings,
        // attributes or unused bytes. Other valid layouts may be refused.
        ensure!(
            primary == mirrored,
            "primary and mirror MFT record {i} differ"
        );
        hashes.push(hex::encode(Sha256::digest(primary)));
    }
    Ok(VerifiedBackups {
        inspection_fingerprint: fingerprint(raw)?,
        partition_length: length,
        primary_boot_sha256: hex::encode(Sha256::digest(&boot)),
        backup_boot_sha256: hex::encode(Sha256::digest(&backup)),
        mirrored_records,
        mirrored_record_sha256: hashes,
    })
}
