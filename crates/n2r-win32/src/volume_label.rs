//! Exact source-label data and bounded post-handoff label restoration.
//! Labels are independent of filesystem serials and Mount Manager identities.
use crate::{general_layout::GeneralDiskBinding, layout::guid_bytes};
use serde::{Deserialize, Serialize};
use std::io;

pub const MAX_LABEL_UNITS: usize = 32;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeLabel {
    utf16: Vec<u16>,
}
impl VolumeLabel {
    pub fn from_utf16(utf16: Vec<u16>) -> io::Result<Self> {
        let label = Self { utf16 };
        label.validate()?;
        Ok(label)
    }
    pub fn from_text(text: &str) -> io::Result<Self> {
        Self::from_utf16(text.encode_utf16().collect())
    }
    pub fn validate(&self) -> io::Result<()> {
        if self.utf16.len() > MAX_LABEL_UNITS || self.utf16.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "label exceeds 32 UTF-16 units or contains embedded NUL",
            ));
        }
        Ok(())
    }
    pub fn utf16(&self) -> &[u16] {
        &self.utf16
    }
    pub fn text(&self) -> Option<String> {
        String::from_utf16(&self.utf16).ok()
    }
    pub fn terminated(&self) -> io::Result<Vec<u16>> {
        self.validate()?;
        Ok(self.utf16.iter().copied().chain(Some(0)).collect())
    }
}

/// Conversion may rediscover a different volume-GUID alias, but cannot
/// redirect restoration to another physical route or GPT partition extent.
pub fn validate_original_partition(
    original: &GeneralDiskBinding,
    converted: &GeneralDiskBinding,
) -> io::Result<()> {
    original.validate()?;
    converted.validate()?;
    let a = &original.identity;
    let b = &converted.identity;
    if original.disk_number != converted.disk_number
        || guid_bytes(&a.disk_guid)? != guid_bytes(&b.disk_guid)?
        || guid_bytes(&a.partition_guid)? != guid_bytes(&b.partition_guid)?
        || a.partition_number != b.partition_number
        || a.disk_bytes != b.disk_bytes
        || a.partition_offset != b.partition_offset
        || a.partition_bytes != b.partition_bytes
        || a.logical_sector_bytes != b.logical_sector_bytes
        || a.physical_sector_bytes != b.physical_sector_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "label restoration is not bound to the original partition",
        ));
    }
    Ok(())
}

pub fn require_expected_current(
    current: &VolumeLabel,
    expected_before: &VolumeLabel,
    desired: &VolumeLabel,
) -> io::Result<bool> {
    current.validate()?;
    expected_before.validate()?;
    desired.validate()?;
    if current == desired {
        return Ok(false);
    }
    if current != expected_before {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "current label differs from enrollment and desired source label",
        ));
    }
    Ok(true)
}

#[cfg(windows)]
#[path = "volume_label_native.rs"]
mod native;
#[cfg(windows)]
pub use native::{
    LabelObservation, LabelRestoration, SourceLabel, capture_source_label, observe_label,
    restore_after_handoff, restore_verified_label,
};
