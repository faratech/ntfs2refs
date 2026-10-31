//! Checked raw NTFS reparse-point evidence. A saved Point is consistency data,
//! not a source certificate: physical authenticity still needs frozen-source
//! reads and the independent native reparse observation.
use crate::ntfs_inspect::{AttributeInventory, FileInventory};
use anyhow::{Context, Result, ensure};
use n2r_win32::reparse_layout::Point;

pub const MAX_REPARSE_BYTES: u64 = 16 * 1024;
const MOUNT_POINT: u32 = 0xa000_0003;

pub(crate) fn storage_attribute<'a>(
    attributes: impl IntoIterator<Item = &'a AttributeInventory>,
) -> Result<Option<&'a AttributeInventory>> {
    let mut point = None;
    for attribute in attributes {
        if attribute.type_code == 0xc0 {
            ensure!(
                point.replace(attribute).is_none(),
                "duplicate or continued reparse attribute"
            );
        }
    }
    if let Some(attribute) = point {
        validate_storage(attribute)?;
    }
    Ok(point)
}

fn validate_storage(attribute: &AttributeInventory) -> Result<()> {
    ensure!(
        attribute.type_code == 0xc0
            && attribute.name_utf16.is_empty()
            && attribute.flags == 0
            && attribute.compression_unit == 0
            && attribute.lowest_vcn == 0
            && (8..=MAX_REPARSE_BYTES).contains(&attribute.logical_size)
            && attribute.initialized_size == attribute.logical_size,
        "reparse storage must be complete, plain, unnamed and bounded"
    );
    if attribute.resident {
        ensure!(
            attribute.allocated_size == attribute.logical_size
                && attribute.extents.is_empty()
                && attribute.resident_sha256.is_some()
                && attribute.resident_metadata_hex.is_some(),
            "resident reparse storage evidence is incomplete"
        );
    } else {
        ensure!(
            attribute.resident_sha256.is_none() && attribute.resident_metadata_hex.is_none(),
            "nonresident reparse storage has resident evidence"
        );
        let mut coverage = 0u64;
        let mut physical = Vec::with_capacity(attribute.extents.len());
        for extent in &attribute.extents {
            ensure!(
                extent.logical_offset == coverage && extent.length > 0,
                "reparse mapping has a gap, overlap or empty extent"
            );
            coverage = coverage
                .checked_add(extent.length)
                .context("reparse mapping coverage overflow")?;
            let start = extent
                .physical_offset
                .context("sparse reparse storage is unsupported")?;
            let end = start
                .checked_add(extent.length)
                .context("reparse physical range overflow")?;
            physical.push((start, end));
        }
        ensure!(
            coverage == attribute.allocated_size && coverage >= attribute.logical_size,
            "reparse mapping does not cover its complete allocation"
        );
        physical.sort_unstable();
        ensure!(
            physical.windows(2).all(|pair| pair[0].1 <= pair[1].0),
            "reparse storage has overlapping physical ranges"
        );
    }
    Ok(())
}

/// The actual attribute bytes are retained in Point.buffer. Older reports can
/// establish absence only when no raw reparse attribute exists.
pub fn file_point(file: &FileInventory) -> Result<Option<Point>> {
    let attribute = storage_attribute(&file.attributes)?;
    match (attribute, &file.reparse) {
        (None, None) => Ok(None),
        (Some(attribute), Some(point)) => {
            ensure!(
                file.base_file_reference == 0
                    && !file
                        .attributes
                        .iter()
                        .any(|attribute| attribute.type_code == 0x20),
                "reparse attribute-list assembly is unsupported"
            );
            point.validate()?;
            ensure!(
                point.buffer.len() as u64 == attribute.logical_size,
                "retained reparse bytes differ from the attribute length"
            );
            if attribute.resident {
                ensure!(
                    attribute.resident_metadata_hex.as_deref()
                        == Some(hex::encode(&point.buffer).as_str())
                        && attribute.resident_sha256.as_deref().is_some_and(|hash| {
                            crate::ntfs_attribute_list::resident_digest_matches(hash, &point.buffer)
                        }),
                    "resident reparse bytes differ from raw attribute evidence"
                );
            }
            ensure!(
                point.tag() != MOUNT_POINT || file.is_directory,
                "a mount-point reparse attribute requires a directory"
            );
            Ok(Some(point.clone()))
        }
        (None, Some(_)) => anyhow::bail!("retained point has no raw reparse attribute"),
        (Some(_), None) => anyhow::bail!("raw reparse attribute lacks retained point bytes"),
    }
}
