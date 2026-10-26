//! Strict initial-profile backup checks against actual source reads.
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
        g.bytes_per_sector == 512 && g.cluster_size == 4096 && g.file_record_size == 1024,
        "backup checks require the initial 512/4K/1K profile"
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
    ensure!(
        mirror.logical_size == 4096 && mirror.initialized_size == 4096,
        "MFT mirror length exceeds the four-record initial profile"
    );
    let mut primary = vec![0; 4096];
    let mut mirrored = vec![0; 4096];
    ntfs::read_nonresident_inventory_range(reader, mft, 0, &mut primary, g)?;
    ntfs::read_nonresident_inventory_range(reader, mirror, 0, &mut mirrored, g)?;
    let mut hashes = vec![];
    for (i, (p, m)) in primary
        .as_chunks::<1024>()
        .0
        .iter()
        .zip(mirrored.as_chunks::<1024>().0)
        .enumerate()
    {
        ntfs::validate_file_record(p, g).with_context(|| format!("primary MFT record {i}"))?;
        ntfs::validate_file_record(m, g).with_context(|| format!("mirror MFT record {i}"))?;
        // Conservative: no normalization of differing LSNs, USA encodings,
        // attributes or unused bytes. Other valid layouts may be refused.
        ensure!(p == m, "primary and mirror MFT record {i} differ");
        hashes.push(hex::encode(Sha256::digest(p)));
    }
    Ok(VerifiedBackups {
        inspection_fingerprint: fingerprint(raw)?,
        partition_length: length,
        primary_boot_sha256: hex::encode(Sha256::digest(&boot)),
        backup_boot_sha256: hex::encode(Sha256::digest(&backup)),
        mirrored_records: 4,
        mirrored_record_sha256: hashes,
    })
}
