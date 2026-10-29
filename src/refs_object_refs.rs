//! Read-only decoding of compact ReFS 3.14 object-table leaf references.
//! The caller must authenticate the containing page and resolve every virtual
//! cluster through the correct container map. This grants no I/O or write
//! authority and does not establish a complete object table.
//! Layout facts: https://xbpt.gitlab.io/forefst/structures/object_table/ .
use crate::refs_node::NodeRowObservation;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_ROW_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectLeafReference {
    pub object_id: u64,
    pub log_sequence_number: u64,
    pub virtual_lcn_slots: [u64; 4],
    pub root_crc64_nvme: u64,
    pub trailer: Option<[u8; 8]>,
    pub referenced_page_verified: bool,
    pub whole_volume_graph_verified: bool,
    pub raw_write_authority: bool,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("bounded field"))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded field"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded field"))
}

/// Decode one row from a caller-authenticated Object Table leaf. Slot
/// translation and duplicate OID checks remain the table walker's job.
pub fn decode_object_leaf_row(row: &NodeRowObservation) -> Result<ObjectLeafReference> {
    ensure!(
        (16..=MAX_ROW_BYTES).contains(&(row.size as usize))
            && row.row_bytes_hex.len() == (row.size as usize) * 2,
        "invalid object row size"
    );
    let bytes = hex::decode(&row.row_bytes_hex).context("invalid object row hex")?;
    ensure!(
        u32_at(&bytes, 0) == row.size
            && u16_at(&bytes, 4) == row.key_offset
            && u16_at(&bytes, 6) == row.key_length
            && u16_at(&bytes, 8) == 0
            && u16_at(&bytes, 10) == row.value_offset
            && u16_at(&bytes, 12) == row.value_length
            && u16_at(&bytes, 14) == 0
            && row.reserved_at_8 == 0
            && row.reserved_at_14 == 0
            && !row.key_value_overlap
            && hex::encode(Sha256::digest(&bytes)) == row.row_sha256,
        "object row header or digest differs"
    );
    let key_start = usize::from(row.key_offset);
    let value_start = usize::from(row.value_offset);
    let key_end = key_start
        .checked_add(usize::from(row.key_length))
        .context("object key overflow")?;
    let value_end = value_start
        .checked_add(usize::from(row.value_length))
        .context("object value overflow")?;
    ensure!(
        row.key_length == 16
            && matches!(row.value_length, 80 | 88)
            && key_start >= 16
            && value_start >= 16
            && key_end <= bytes.len()
            && value_end <= bytes.len()
            && (key_end <= value_start || value_end <= key_start),
        "object row key or compact value bounds differ"
    );
    let key = &bytes[key_start..key_end];
    let value = &bytes[value_start..value_end];
    ensure!(
        hex::encode(Sha256::digest(key)) == row.key_sha256
            && hex::encode(Sha256::digest(value)) == row.value_sha256
            && u64_at(key, 0) == 0
            && u64_at(key, 8) != 0,
        "object key or observed field digest differs"
    );
    let trailer_len = usize::try_from(u32_at(value, 0x14))?;
    ensure!(
        u32_at(value, 0) == 2
            && u32_at(value, 4) == 0
            && u32_at(value, 8) == 0x18
            && u32_at(value, 0xc) == 0x30
            && u32_at(value, 0x10) == 80
            && matches!(trailer_len, 0 | 8)
            && 80 + trailer_len == value.len()
            && value[0x40..0x48] == [0, 0, 2, 8, 8, 0, 0, 0],
        "unsupported compact object record or CRC64 reference"
    );
    let slots = [
        u64_at(value, 0x20),
        u64_at(value, 0x28),
        u64_at(value, 0x30),
        u64_at(value, 0x38),
    ];
    for (index, &slot) in slots.iter().enumerate() {
        ensure!(
            slot != 0 && slot & 0x4000 == 0 && !slots[..index].contains(&slot),
            "object root virtual slots are invalid or repeated"
        );
    }
    Ok(ObjectLeafReference {
        object_id: u64_at(key, 8),
        log_sequence_number: u64_at(value, 0x18),
        virtual_lcn_slots: slots,
        root_crc64_nvme: u64_at(value, 0x48),
        trailer: (trailer_len == 8).then(|| value[80..88].try_into().expect("bounded trailer")),
        referenced_page_verified: false,
        whole_volume_graph_verified: false,
        raw_write_authority: false,
    })
}
