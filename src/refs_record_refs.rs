//! Bounded inline file-record nodes from caller-authenticated directory leaves.
//! Layout facts: https://xbpt.gitlab.io/forefst/structures/directory_entries/ .
use crate::refs_node::{self, NodeBodyObservation, NodeRowObservation};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

pub struct EmbeddedFileRecord {
    pub expected_attribute_rows: u64,
    pub node: NodeBodyObservation,
}

#[derive(Debug, Clone)]
pub struct AttributeChild {
    pub virtual_slots: [u64; 4],
    pub crc64_nvme: u64,
}

/// A bounded extent node decoded from a caller-authenticated attribute row.
/// Its children and physical allocation remain unverified.
#[derive(Debug, Clone)]
pub struct DataExtentNode {
    pub version_sub_id: u32,
    pub node: crate::refs_extent_refs::ExtentNode,
    pub stream_size: u64,
    pub valid_data_length: u64,
    pub disk_allocated_bytes: u64,
    pub stream_complete: bool,
    pub raw_write_authority: bool,
}

/// Physical log locations from one supported Logfile Information row.
/// Their control-page contents and the complete log are not verified here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogfileStorageReference {
    pub object_id: u64,
    pub data_offset: u64,
    pub data_length: u64,
    pub control_offsets: [u64; 2],
    pub unparsed_value_bytes: usize,
    pub value_sha256: String,
    pub control_pages_verified: bool,
    pub log_ownership_complete: bool,
    pub raw_write_authority: bool,
}

fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded field"))
}
fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded field"))
}

fn parts(row: &NodeRowObservation) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(
        (16..=16384).contains(&row.size) && row.row_bytes_hex.len() == row.size as usize * 2,
        "embedded holder row size differs"
    );
    let bytes = hex::decode(&row.row_bytes_hex)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == row.row_sha256,
        "embedded holder row digest differs"
    );
    let key_start = usize::from(row.key_offset);
    let key_end = key_start
        .checked_add(usize::from(row.key_length))
        .context("embedded key overflow")?;
    let value_start = usize::from(row.value_offset);
    let value_end = value_start
        .checked_add(usize::from(row.value_length))
        .context("embedded value overflow")?;
    let key = bytes
        .get(key_start..key_end)
        .context("embedded key outside row")?;
    let value = bytes
        .get(value_start..value_end)
        .context("embedded value outside row")?;
    ensure!(
        hex::encode(Sha256::digest(key)) == row.key_sha256
            && hex::encode(Sha256::digest(value)) == row.value_sha256,
        "embedded holder field digest differs"
    );
    Ok((key.to_vec(), value.to_vec()))
}

/// Recognize the embedded (key_flags=1) filename record form only. Index
/// entries contain namespace references, not embedded file-attribute trees.
pub fn inspect_embedded_file(row: &NodeRowObservation) -> Result<Option<EmbeddedFileRecord>> {
    let (key, value) = parts(row)?;
    if key.len() < 4 || key[..2] != [0x30, 0] {
        return Ok(None);
    }
    ensure!(
        key.len().is_multiple_of(2),
        "filename key has partial UTF16"
    );
    match u16::from_le_bytes(key[2..4].try_into()?) {
        2 => return Ok(None),
        1 => {}
        _ => anyhow::bail!("unknown filename record placement"),
    }
    ensure!(
        value.len() >= 0xa8 + 0x28 && u32le(&value, 0) == 0xa8 && u32le(&value, 4) == 0x00010028,
        "unsupported embedded file node descriptor"
    );
    let node = refs_node::inspect_embedded_node(&value, 0xa8)?;
    Ok(Some(EmbeddedFileRecord {
        expected_attribute_rows: u64le(&value, 0x20),
        node,
    }))
}

pub fn attribute_child(row: &NodeRowObservation) -> Result<AttributeChild> {
    let (key, value) = parts(row)?;
    ensure!(
        key.is_empty()
            && row.key_offset == 0x10
            && value.len() == 48
            && value[0x20..0x28] == [0, 0, 2, 8, 8, 0, 0, 0],
        "unsupported attribute child reference"
    );
    let slots = std::array::from_fn(|i| u64le(&value, i * 8));
    for (index, &slot) in slots.iter().enumerate() {
        ensure!(
            slot != 0 && slot != u64::MAX && slot & 0x4000 == 0 && !slots[..index].contains(&slot),
            "attribute child has unsupported or repeated virtual slots"
        );
    }
    Ok(AttributeChild {
        virtual_slots: slots,
        crc64_nvme: u64le(&value, 0x28),
    })
}

/// Whether a row is a DATA allocation record in the form this reader does
/// not interpret (version identifier 8). [`inspect_data_extent_node`] answers
/// `None` for it, exactly as it does for a row that is not a DATA record at
/// all, so a walk has to ask this to know that a stream's extents were not
/// followed.
pub fn is_uninterpreted_data_record(row: &NodeRowObservation) -> Result<bool> {
    let (key, _) = parts(row)?;
    Ok(key.len() == 40
        && u32le(&key, 8) == 0x8000_0002
        && u32le(&key, 12) == 0x000e_0080
        && u32le(&key, 16) == 8)
}

/// Recognize the compact 3.14 multi-instance DATA allocation record. The
/// enclosing record and any referenced children must be authenticated by the
/// caller; resident DATA and the separate stream-set record are not extents.
pub fn inspect_data_extent_node(row: &NodeRowObservation) -> Result<Option<DataExtentNode>> {
    let (key, value) = parts(row)?;
    if key.len() < 16 || u32le(&key, 8) != 0x8000_0002 || u32le(&key, 12) != 0x000e_0080 {
        return Ok(None);
    }
    ensure!(
        key.len() == 40,
        "unsupported multi-instance DATA key length"
    );
    let version_sub_id = u32le(&key, 16);
    if version_sub_id == 8 {
        return Ok(None);
    }
    ensure!(
        version_sub_id >= 0x1000,
        "unsupported DATA version identifier"
    );
    ensure!(
        value.len() >= 0x88 + 0x28 && u32le(&value, 0) == 0x88 && u32le(&value, 0x0c) == 0x200,
        "unsupported compact DATA extent header"
    );
    let stream_size = u64le(&value, 0x38);
    let valid_data_length = u64le(&value, 0x40);
    let disk_allocated_bytes = u64le(&value, 0x48);
    ensure!(
        valid_data_length <= stream_size,
        "DATA valid length exceeds stream size"
    );
    let node = crate::refs_extent_refs::inspect_extent_node(&value, 0x88)?;
    Ok(Some(DataExtentNode {
        version_sub_id,
        node,
        stream_size,
        valid_data_length,
        disk_allocated_bytes,
        stream_complete: false,
        raw_write_authority: false,
    }))
}

/// Decode the key-1 physical log locations from a caller-authenticated 3.14
/// Logfile Information table leaf. Primary and duplicate records must be
/// reconciled by the caller; no checkpoint or control page is authenticated.
pub fn inspect_logfile_information_row(
    object_id: u64,
    row: &NodeRowObservation,
    partition_bytes: u64,
) -> Result<Option<LogfileStorageReference>> {
    if !matches!(object_id, 0x09 | 0x0a) {
        return Ok(None);
    }
    ensure!(
        partition_bytes != 0 && partition_bytes.is_multiple_of(4096),
        "unsupported Logfile Information geometry"
    );
    let (key, value) = parts(row)?;
    ensure!(key.len() >= 4, "truncated Logfile Information key");
    if u32le(&key, 0) != 1 {
        return Ok(None);
    }
    ensure!(
        key.len() == 4 && value.len() >= 40,
        "unsupported log location record"
    );
    let start = u64le(&value, 0);
    let end = u64le(&value, 8);
    let count = u64le(&value, 16);
    let controls = [u64le(&value, 24), u64le(&value, 32)];
    let partition_clusters = partition_bytes / 4096;
    ensure!(
        start != 0
            && count != 0
            && start.checked_add(count) == Some(end)
            && end <= partition_clusters
            && controls[0] != 0
            && controls[1] != 0
            && controls[0] != controls[1]
            && controls
                .iter()
                .all(|&lcn| lcn < partition_clusters && !(start..end).contains(&lcn)),
        "log data or control cluster ranges are invalid"
    );
    Ok(Some(LogfileStorageReference {
        object_id,
        data_offset: start
            .checked_mul(4096)
            .context("log data offset overflow")?,
        data_length: count
            .checked_mul(4096)
            .context("log data length overflow")?,
        control_offsets: [controls[0] * 4096, controls[1] * 4096],
        unparsed_value_bytes: value.len() - 40,
        value_sha256: hex::encode(Sha256::digest(&value)),
        control_pages_verified: false,
        log_ownership_complete: false,
        raw_write_authority: false,
    }))
}

#[cfg(test)]
mod uninterpreted_data_tests {
    use super::*;

    /// A row with a 40-byte key carrying the given attribute tag and DATA
    /// version identifier, and an eight-byte value.
    fn row(attribute: u32, version_sub_id: u32) -> NodeRowObservation {
        let mut bytes = vec![0u8; 16 + 40 + 8];
        bytes[16 + 8..16 + 12].copy_from_slice(&0x8000_0002u32.to_le_bytes());
        bytes[16 + 12..16 + 16].copy_from_slice(&attribute.to_le_bytes());
        bytes[16 + 16..16 + 20].copy_from_slice(&version_sub_id.to_le_bytes());
        NodeRowObservation {
            index: 0,
            index_entry_offset: 0,
            relative_offset: 0,
            page_offset: 0,
            marker: 0,
            size: bytes.len() as u32,
            key_offset: 16,
            key_length: 40,
            reserved_at_8: 0,
            value_offset: 56,
            value_length: 8,
            reserved_at_14: 0,
            key_value_overlap: false,
            row_sha256: hex::encode(Sha256::digest(&bytes)),
            key_sha256: hex::encode(Sha256::digest(&bytes[16..56])),
            value_sha256: hex::encode(Sha256::digest(&bytes[56..])),
            row_bytes_hex: hex::encode(&bytes),
        }
    }

    #[test]
    fn a_data_record_that_is_not_interpreted_is_told_apart_from_a_row_that_is_not_data() {
        // Both answer `None` to the extent reader...
        let skipped = row(0x000e_0080, 8);
        let other = row(0x000e_0030, 8);
        assert!(inspect_data_extent_node(&skipped).unwrap().is_none());
        assert!(inspect_data_extent_node(&other).unwrap().is_none());
        // ...and only the first is a stream whose extents were left behind.
        assert!(is_uninterpreted_data_record(&skipped).unwrap());
        assert!(!is_uninterpreted_data_record(&other).unwrap());
        // A DATA record in the interpreted form is not counted as skipped.
        assert!(!is_uninterpreted_data_record(&row(0x000e_0080, 0x1000)).unwrap());
    }
}
