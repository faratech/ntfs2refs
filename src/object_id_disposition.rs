//! Object IDs of a data volume's files and directories, which a conversion
//! records and does not carry over.
//!
//! Windows gives a file an object ID when a shortcut to it is made (link
//! tracking), so a volume that has been used has them. ReFS has no object
//! IDs: there is nowhere to put one on the target. A Windows boot volume's
//! are accounted for by `boot_alias::WindowsObjectIdDomain`, with what
//! Windows itself answers for each file. For a data volume the raw volume is
//! its own witness: every `$OBJECT_ID` attribute has exactly its entry in
//! the `$Extend\$ObjId` index and every entry its attribute. What was on the
//! source stays in the run's records, so a link can be traced afterwards.

use crate::ntfs_inspect::{
    AttributeInventory, FileInventory, MetadataRole, PagedInspection,
    paged_storage::{SourceRamLease, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

/// The record-store purpose of the archive.
pub(crate) const PURPOSE: [u8; 8] = *b"DATOID01";

/// One object ID that is not carried over, as the source held it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjectIdNotCarried {
    pub record_number: u64,
    pub sequence_number: u16,
    pub source_attribute: AttributeInventory,
    /// The index key: the 16-byte object ID.
    pub index_key_hex: String,
    /// The index value: the file reference, then the birth volume, birth
    /// object and domain IDs.
    pub index_value_hex: String,
}

pub(crate) fn key(record: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&record.to_be_bytes());
    key
}

/// Whether `file` is an ordinary file or directory of the volume: the only
/// kind whose object ID this disposition covers.
pub(crate) fn ordinary(file: &FileInventory) -> bool {
    file.record_number >= 16
        && file.sequence_number != 0
        && file.base_file_reference == 0
        && !file.is_metadata
        && file.metadata_role == MetadataRole::OutsideExtendCandidate
        && file.metadata_role_issue.is_none()
}

/// The verified, archived object IDs of one inspected data volume. Made only
/// by the internal-index verification, after every index entry and every
/// attribute has been matched; it cannot be rebuilt from a serialized pin.
pub struct DataObjectIds {
    entries: SortedRecordStore,
    source_inspection_sha256: String,
    _scratch: SourceScratch,
    _owner_ram: SourceRamLease,
}

impl DataObjectIds {
    pub(crate) fn from_verified_archive(
        source: &PagedInspection,
        pin: &RecordStorePin,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        ensure!(
            !source.is_windows_conversion(),
            "a Windows boot volume's object IDs have their own disposition"
        );
        let entries = SortedRecordStore::open(pin, scratch)?;
        ensure!(pin.purpose == PURPOSE, "object-ID archive of another kind");
        let owner_ram = scratch.lease_ram(std::mem::size_of::<Self>() as u64 + 16384)?;
        Ok(Self {
            entries,
            source_inspection_sha256: source.canonical_sha256()?,
            _scratch: scratch.clone(),
            _owner_ram: owner_ram,
        })
    }

    /// How many files and directories have an object ID that is not carried over.
    pub fn len(&self) -> u64 {
        self.entries.len()
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        self.entries.revalidate()
    }

    /// Whether `file`'s object ID is one this disposition verified and
    /// archived. A file without an object ID is not accounted; one whose
    /// attribute is not exactly what was archived is an error.
    pub(crate) fn accounted(&self, source: &PagedInspection, file: &FileInventory) -> Result<bool> {
        let mut attributes = file.attributes.iter().filter(|a| a.type_code == 0x40);
        let Some(attribute) = attributes.next() else {
            return Ok(false);
        };
        if attributes.next().is_some() || !ordinary(file) {
            return Ok(false);
        }
        ensure!(
            !source.is_windows_conversion()
                && source.canonical_sha256()? == self.source_inspection_sha256,
            "object-ID disposition belongs to another source inspection"
        );
        let Some(row) = self
            .entries
            .find::<ObjectIdNotCarried>(key(file.record_number))?
        else {
            return Ok(false);
        };
        let raw = crate::boot_alias::windows_object_id_bytes(attribute)
            .with_context(|| format!("object ID of MFT record {}", file.record_number))?;
        let indexed = hex::decode(&row.index_value_hex)?;
        let reference = file.record_number | (u64::from(file.sequence_number) << 48);
        ensure!(
            row.record_number == file.record_number
                && row.sequence_number == file.sequence_number
                && row.source_attribute == *attribute
                && row.index_key_hex == hex::encode(raw)
                && indexed.len() == 56
                && indexed[..8] == reference.to_le_bytes(),
            "the object ID of MFT record {} differs from the one archived for it",
            file.record_number
        );
        Ok(true)
    }

    pub(crate) fn audit(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": "data-volume-object-IDs-not-carried-over-v1",
            "source_inspection_sha256": self.source_inspection_sha256,
            "records": self.entries.pin(),
            "objects": self.entries.len(),
            "policy": "every raw object-ID attribute and its $Extend\\$ObjId index entry are matched and archived; the ReFS target has no object IDs",
            "target_object_ids_preserved": false,
        })
    }
}
