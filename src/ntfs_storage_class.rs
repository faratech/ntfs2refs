//! Exact default NTFS $DSC recognition for an explicit offline-Windows
//! normalization policy. Recognition alone never permits dropping metadata.
//! Public semantic contract: FILE_DESIRED_STORAGE_CLASS_INFORMATION (ntifs.h).
use crate::ntfs_inspect::{AttributeInventory, FileInventory};
use anyhow::{Result, ensure};
use serde::Serialize;

const DEFAULT_PERFORMANCE: [u8; 8] = [2, 0, 0, 0, 0, 0, 0, 0];

pub(crate) fn recognized_default(attribute: &AttributeInventory) -> bool {
    attribute.type_code == 0x100
        && attribute.name_utf16 == [36, 68, 83, 67]
        && attribute.resident
        && attribute.flags == 0
        && attribute.compression_unit == 0
        && attribute.lowest_vcn == 0
        && attribute.logical_size == 8
        && attribute.initialized_size == 8
        && attribute.allocated_size == 8
        && attribute.extents.is_empty()
        && attribute.total_allocated_size.is_none()
        && attribute.resident_sha256.as_deref()
            == Some(n2r_win32::content_digest::of(&DEFAULT_PERFORMANCE).as_str())
        && attribute.resident_metadata_hex.as_deref() == Some("0200000000000000")
}

#[derive(Debug, Serialize)]
pub(crate) struct Normalization {
    record_number: u64,
    sequence_number: u16,
    attribute_instance: u16,
    original_class: u32,
    original_flags: u32,
    original_value_hex: &'static str,
    original_value_content_digest: String,
    action: &'static str,
}

/// Unknown classes/flags, duplicates and nonresident utility streams remain
/// refused. The opaque SDK witness can be issued only by the original observed
/// frozen Windows source on fixed, non-Spaces storage. ReFS need not expose
/// this NTFS-specific placement hint; it is archived and explicitly normalized.
pub(crate) fn normalize(
    file: &FileInventory,
    proof: &n2r_win32::BootStorageHintNormalization,
) -> Result<Option<Normalization>> {
    ensure!(
        proof.binding().layout_profile
            == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows,
        "storage-hint normalization requires an observed offline Windows source"
    );
    let mut matches = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x100 && a.name_utf16 == [36, 68, 83, 67]);
    let Some(attribute) = matches.next() else {
        return Ok(None);
    };
    ensure!(
        matches.next().is_none() && recognized_default(attribute),
        "unknown or duplicate NTFS storage-class metadata at FILE {}",
        file.record_number
    );
    Ok(Some(Normalization {
        record_number: file.record_number,
        sequence_number: file.sequence_number,
        attribute_instance: attribute.instance,
        original_class: 2,
        original_flags: 0,
        original_value_hex: "0200000000000000",
        original_value_content_digest: n2r_win32::content_digest::of(&DEFAULT_PERFORMANCE),
        action: "archive-and-normalize-default-untiered-storage-placement-hint",
    }))
}
