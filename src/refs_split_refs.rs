//! Narrow own-record attribute nodes from caller-authenticated directory rows.
//! The outer 0x10/0x40 record is not a filename index entry or DATA extent.
//! Layout sources: forefst structures/directory_entries, concepts/attributes,
//! concepts/resident_storage and attributes/STANDARD_INFORMATION. Only the
//! explicitly declared 0xA8 / 0x00010028 long-record form is accepted here.
use crate::refs_node::{self, NodeBodyObservation, NodeRowObservation};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_ROW_BYTES: usize = 16 * 1024;
const NODE_OFFSET: usize = 0xa8;

#[derive(Debug, Clone, Serialize)]
pub struct OwnRecordAttributeNode {
    pub outer_record_type: u16,
    pub expected_attribute_rows: u64,
    pub node: NodeBodyObservation,
    pub child_pages_verified: bool,
    pub record_complete: bool,
    pub raw_write_authority: bool,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("bounded row field"))
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded record field"))
}

/// This validates the exact indexed row bytes/fields, not the enclosing page's
/// checksum or reachability. The caller must already authenticate that page.
pub fn inspect_own_record(row: &NodeRowObservation) -> Result<Option<OwnRecordAttributeNode>> {
    let size = usize::try_from(row.size)?;
    ensure!(
        (16..=MAX_ROW_BYTES).contains(&size) && row.row_bytes_hex.len() == size * 2,
        "own-record holder row exceeds bounds or its declared size"
    );
    let bytes = hex::decode(&row.row_bytes_hex)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == row.row_sha256
            && u32_at(&bytes, 0) == row.size
            && u16_at(&bytes, 4) == row.key_offset
            && u16_at(&bytes, 6) == row.key_length
            && u16_at(&bytes, 8) == row.reserved_at_8
            && u16_at(&bytes, 10) == row.value_offset
            && u16_at(&bytes, 12) == row.value_length
            && u16_at(&bytes, 14) == row.reserved_at_14,
        "own-record holder bytes/header differ from indexed observation"
    );
    let key_start = usize::from(row.key_offset);
    let key_end = key_start
        .checked_add(usize::from(row.key_length))
        .context("own-record key overflow")?;
    let value_start = usize::from(row.value_offset);
    let value_end = value_start
        .checked_add(usize::from(row.value_length))
        .context("own-record value overflow")?;
    let key = bytes
        .get(key_start..key_end)
        .context("own-record key outside row")?;
    let value = bytes
        .get(value_start..value_end)
        .context("own-record value outside row")?;
    ensure!(
        hex::encode(Sha256::digest(key)) == row.key_sha256
            && hex::encode(Sha256::digest(value)) == row.value_sha256,
        "own-record holder field digest differs"
    );
    if key.len() < 2 {
        return Ok(None);
    }
    let record_type = u16_at(key, 0);
    if !matches!(record_type, 0x10 | 0x40) {
        return Ok(None);
    }
    ensure!(
        key_start >= 16 && value_start >= 16 && !(key_start < value_end && value_start < key_end),
        "own-record key/value overlap the header or each other"
    );
    // The standalone 3.14 SI is a fixed 124-byte scalar metadata value.
    // Its data/USN placeholder slots are zero; it has no embedded node.
    if record_type == 0x10 && value.len() == 0x7c {
        ensure!(
            value[0x30..0x40].iter().all(|byte| *byte == 0),
            "standalone SI placeholder slots differ"
        );
        return Ok(None);
    }
    // A short standalone SI, an index-entry value, or an unknown record
    // descriptor cannot be treated as an empty attribute tree.
    ensure!(
        value.len() >= NODE_OFFSET + 0x28
            && u32_at(value, 0) == NODE_OFFSET as u32
            && u32_at(value, 4) == 0x0001_0028
            && u32_at(value, NODE_OFFSET) == 0x28,
        "unsupported own-record attribute-node descriptor"
    );
    let expected_attribute_rows = u64::from_le_bytes(value[0x20..0x28].try_into()?);
    let node = refs_node::inspect_embedded_node(value, NODE_OFFSET)?;
    ensure!(
        node.node_level <= 8 && (!node.index_node || !node.rows.is_empty()),
        "own-record attribute level or empty index is unsupported"
    );
    Ok(Some(OwnRecordAttributeNode {
        outer_record_type: record_type,
        expected_attribute_rows,
        node,
        child_pages_verified: false,
        record_complete: false,
        raw_write_authority: false,
    }))
}
