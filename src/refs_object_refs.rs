//! Read-only decoding of compact ReFS 3.14 object-table leaf references.
//! The caller must authenticate the containing page and resolve every virtual
//! cluster through the correct container map. This grants no I/O or write
//! authority and does not establish a complete object table.
//! Layout facts: https://xbpt.gitlab.io/forefst/structures/object_table/ .
use crate::refs_node::{NodeRow, NodeRowObservation};
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
            && hex::encode(Sha256::digest(value)) == row.value_sha256,
        "object key or observed field digest differs"
    );
    decode_compact_object_fields(key, value)
}

/// Decode a row borrowed from a caller-authenticated Object Table page.
pub(crate) fn decode_native_object_leaf_row(row: &NodeRow<'_>) -> Result<ObjectLeafReference> {
    ensure!(
        row.reserved_at_8 == 0 && row.reserved_at_14 == 0 && !row.key_value_overlap,
        "object row header differs"
    );
    decode_compact_object_fields(row.key, row.value)
}

fn decode_compact_object_fields(key: &[u8], value: &[u8]) -> Result<ObjectLeafReference> {
    ensure!(
        key.len() == 16 && matches!(value.len(), 80 | 88),
        "object row key or compact value bounds differ"
    );
    ensure!(
        u64_at(key, 0) == 0 && u64_at(key, 8) != 0,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs_node::{NativeTable, inspect_native_table_rows, inspect_system_root_node};

    const NODE: usize = 0x78;
    const ROW: usize = NODE + 0x28;
    const KEY: usize = ROW + 16;
    const VALUE: usize = KEY + 16;
    const INDEX: usize = 0x3ffc;
    const ROOT_CRC: u64 = 0x2b78_1682_a75f_de39;

    fn put(page: &mut [u8], at: usize, bytes: &[u8]) {
        page[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn object_page(trailer: Option<[u8; 8]>) -> Vec<u8> {
        let mut page = vec![0; 0x4000];
        let trailer_len: u32 = if trailer.is_some() { 8 } else { 0 };
        let value_len = 80 + trailer_len;
        put(&mut page, 0, b"MSB+");
        put(&mut page, 4, &2u32.to_le_bytes());
        put(&mut page, 0x48, &2u64.to_le_bytes());
        put(&mut page, 0x50, &0x28u32.to_le_bytes());
        put(&mut page, 0x54, &0x28u16.to_le_bytes());
        put(&mut page, 0x5c, &0xe030u32.to_le_bytes());
        put(&mut page, 0x70, &1u64.to_le_bytes());
        put(
            &mut page,
            NODE + 0x10,
            &((INDEX - NODE) as u32).to_le_bytes(),
        );
        put(&mut page, NODE + 0x14, &1u32.to_le_bytes());
        put(
            &mut page,
            NODE + 0x20,
            &((INDEX + 4 - NODE) as u32).to_le_bytes(),
        );
        put(&mut page, INDEX, &((ROW - NODE) as u16).to_le_bytes());
        put(&mut page, INDEX + 2, &u16::MAX.to_le_bytes());
        put(&mut page, ROW, &(40 + value_len).to_le_bytes());
        put(&mut page, ROW + 4, &16u16.to_le_bytes());
        put(&mut page, ROW + 6, &16u16.to_le_bytes());
        put(&mut page, ROW + 10, &32u16.to_le_bytes());
        put(&mut page, ROW + 12, &(value_len as u16).to_le_bytes());
        put(&mut page, KEY + 8, &0x530u64.to_le_bytes());
        for (offset, number) in [
            (0, 2u32),
            (8, 0x18),
            (12, 0x30),
            (16, 80),
            (20, trailer_len),
        ] {
            put(&mut page, VALUE + offset, &number.to_le_bytes());
        }
        put(&mut page, VALUE + 0x18, &33u64.to_le_bytes());
        for (index, slot) in [5u64, 6, 7, 8].into_iter().enumerate() {
            put(&mut page, VALUE + 0x20 + 8 * index, &slot.to_le_bytes());
        }
        put(&mut page, VALUE + 0x40, &[0, 0, 2, 8, 8, 0, 0, 0]);
        put(&mut page, VALUE + 0x48, &ROOT_CRC.to_le_bytes());
        if let Some(trailer) = trailer {
            put(&mut page, VALUE + 80, &trailer);
        }
        page
    }

    #[test]
    fn native_row_slices_match_observed_references_and_checksum_position() {
        for trailer in [None, Some(*b"trailer!")] {
            let page = object_page(trailer);
            let native = inspect_native_table_rows(&page, NativeTable::System(2), true).unwrap();
            let observed = inspect_system_root_node(&page, 2).unwrap();
            let row = &native.rows[0];
            let reference = decode_native_object_leaf_row(row).unwrap();
            assert_eq!(
                reference,
                decode_object_leaf_row(&observed.rows[0]).unwrap()
            );
            assert_eq!(reference.object_id, 0x530);
            assert_eq!(reference.log_sequence_number, 33);
            assert_eq!(reference.virtual_lcn_slots, [5, 6, 7, 8]);
            assert_eq!(reference.root_crc64_nvme, ROOT_CRC);
            assert_eq!(reference.trailer, trailer);
            let checksum_at = row.page_offset + usize::from(row.value_offset) + 0x48;
            assert_eq!(checksum_at, VALUE + 0x48);
            assert_eq!(&page[checksum_at..checksum_at + 8], &ROOT_CRC.to_le_bytes());
        }
    }

    #[test]
    fn native_and_observation_decoders_reject_invalid_compact_rows() {
        for (at, replacement) in [
            (ROW + 6, 15),
            (ROW + 8, 2),
            (ROW + 4, 32),
            (ROW + 12, 81),
            (ROW + 14, 1),
            (KEY, 1),
            (KEY + 8, 0),
            (VALUE, 1),
            (VALUE + 4, 2),
            (VALUE + 8, 0x20),
            (VALUE + 12, 0x20),
            (VALUE + 16, 88),
            (VALUE + 20, 8),
            (VALUE + 0x20, 0),
            (VALUE + 0x20, 0x4005),
            (VALUE + 0x28, 5),
            (VALUE + 0x42, 3),
        ] {
            let mut page = object_page(None);
            put(&mut page, at, &u16::to_le_bytes(replacement));
            let native = inspect_native_table_rows(&page, NativeTable::System(2), true).unwrap();
            let observed = inspect_system_root_node(&page, 2).unwrap();
            assert!(
                decode_native_object_leaf_row(&native.rows[0]).is_err(),
                "{at:#x}"
            );
            assert!(
                decode_object_leaf_row(&observed.rows[0]).is_err(),
                "{at:#x}"
            );
        }
    }

    #[test]
    fn decoding_a_serialized_observation_still_requires_each_digest_and_header() {
        let page = object_page(None);
        let observed = inspect_system_root_node(&page, 2).unwrap();
        let row = &observed.rows[0];
        let corruptions: [fn(&mut NodeRowObservation); 4] = [
            |row: &mut NodeRowObservation| row.row_sha256.clear(),
            |row: &mut NodeRowObservation| row.key_sha256.clear(),
            |row: &mut NodeRowObservation| row.value_sha256.clear(),
            |row: &mut NodeRowObservation| row.key_offset += 1,
        ];
        for corrupt in corruptions {
            let mut tampered = row.clone();
            corrupt(&mut tampered);
            assert!(decode_object_leaf_row(&tampered).is_err());
        }
    }
}
