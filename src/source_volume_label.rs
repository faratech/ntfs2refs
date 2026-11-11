//! Reconcile the native pre-freeze label with the persisted frozen NTFS value.
use crate::ntfs_inspect::{self, MetadataRole, NtfsInspection};
use anyhow::{Result, ensure};
use n2r_win32::volume_label::VolumeLabel;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
#[derive(Debug, Serialize)]
pub struct FrozenLabelProof {
    pub label: VolumeLabel,
    pub volume_name_attribute_present: bool,
    pub inspection_sha256: String,
    pub resident_value_sha256: Option<String>,
}

pub fn verify<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    captured: &VolumeLabel,
) -> Result<FrozenLabelProof> {
    captured.validate()?;
    let files: Vec<_> = raw.files.iter().filter(|f| f.record_number == 3).collect();
    ensure!(files.len() == 1, "frozen $Volume identity differs");
    verify_file(
        files[0],
        captured,
        |attribute| {
            ntfs_inspect::read_resident_inventory_attribute(reader, raw, files[0], attribute)
        },
        || Ok(hex::encode(Sha256::digest(serde_json::to_vec(raw)?))),
    )
}

#[cfg(windows)]
pub fn verify_domain<R: Read + Seek>(
    reader: &mut R,
    source: &ntfs_inspect::PagedInspection,
    captured: &VolumeLabel,
) -> Result<FrozenLabelProof> {
    use crate::ntfs_inspect::RootFileDomain;
    captured.validate()?;
    source.revalidate()?;
    let file = source
        .find_record(3, None)?
        .ok_or_else(|| anyhow::anyhow!("frozen $Volume absent"))?;
    let mapping = ntfs_inspect::CheckedMftDomain::open(reader, source)?;
    mapping.verify_record(reader, source, 3)?;
    let result = verify_file(
        &file,
        captured,
        |attribute| mapping.resident_attribute(reader, source, &file, attribute),
        || source.canonical_sha256(),
    )?;
    source.revalidate()?;
    Ok(result)
}

fn verify_file<B: AsRef<[u8]>>(
    file: &ntfs_inspect::FileInventory,
    captured: &VolumeLabel,
    mut read_resident: impl FnMut(&ntfs_inspect::AttributeInventory) -> Result<B>,
    fingerprint: impl FnOnce() -> Result<String>,
) -> Result<FrozenLabelProof> {
    ensure!(
        file.metadata_role == MetadataRole::ReservedSystemRecord
            && file.base_file_reference == 0
            && !file.is_directory,
        "frozen $Volume identity differs"
    );
    let attributes: Vec<_> = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x60)
        .collect();
    ensure!(attributes.len() <= 1, "duplicate volume-name attributes");
    let (label, value_hash) = if let Some(attribute) = attributes.first() {
        ensure!(
            attribute.resident
                && attribute.name_utf16.is_empty()
                && attribute.flags == 0
                && attribute.lowest_vcn == 0
                && attribute.compression_unit == 0
                && attribute.logical_size <= 64
                && attribute.logical_size.is_multiple_of(2),
            "unsupported persisted NTFS volume-name form"
        );
        let owner = read_resident(attribute)?;
        let bytes = owner.as_ref();
        let label = VolumeLabel::from_utf16(
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| u16::from_le_bytes(*unit))
                .collect(),
        )?;
        (label, Some(hex::encode(Sha256::digest(bytes))))
    } else {
        (VolumeLabel::from_utf16(vec![])?, None)
    };
    ensure!(
        label == *captured,
        "native pre-freeze label differs from persisted frozen $VOLUME_NAME"
    );
    Ok(FrozenLabelProof {
        label,
        volume_name_attribute_present: !attributes.is_empty(),
        inspection_sha256: fingerprint()?,
        resident_value_sha256: value_hash,
    })
}
