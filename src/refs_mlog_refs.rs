//! Compact 4 KiB MLog control pages, reached from authenticated OID9/A rows.
//! Layout facts: https://xbpt.gitlab.io/forefst/structures/mlog/ .
//! Validating controls does not validate/replay log transactions or prove that
//! the checkpoints include them. Log contents remain required storage.
use crate::refs_record_refs::LogfileStorageReference;
use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct ControlObservation {
    pub physical_offset: u64,
    pub page_sha256: String,
    pub format_magic: u32,
    pub log_uuid: [u8; 16],
    pub sequence: u64,
    pub oldest_lsn: u64,
    pub stored_integrity: u64,
    pub computed_integrity: u64,
    pub data_offset: u64,
    pub data_length: u64,
    pub control_verified: bool,
    pub transactions_replayed: bool,
}
fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded field"))
}
fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded field"))
}

pub fn inspect_control(
    bytes: &[u8],
    offset: u64,
    reference: &LogfileStorageReference,
) -> Result<ControlObservation> {
    ensure!(
        bytes.len() == 4096 && reference.control_offsets.contains(&offset),
        "exact referenced 4KiB log control required"
    );
    ensure!(
        &bytes[..4] == b"MLog"
            && u32le(bytes, 8) == 1
            && u32le(bytes, 12) == 4096
            && u32le(bytes, 0x38) == 1
            && u32le(bytes, 0x3c) == 1
            && u32le(bytes, 0x54) == 0x78,
        "unsupported log control header"
    );
    let entry = 0x78;
    let payload_offset = u32le(bytes, entry + 0x28) as usize;
    let payload_length = u32le(bytes, entry + 0x20) as usize;
    ensure!(
        payload_offset == 0x38 && payload_length == 0xe48 && u32le(bytes, entry + 0x30) == 1,
        "unsupported log control entry"
    );
    let payload = entry + payload_offset;
    ensure!(
        payload + payload_length <= bytes.len(),
        "log control payload escapes page"
    );
    let start = u64le(bytes, payload + 8);
    let end = u64le(bytes, payload + 16);
    ensure!(
        start.checked_mul(4096) == Some(reference.data_offset)
            && end
                .checked_sub(start)
                .and_then(|count| count.checked_mul(4096))
                == Some(reference.data_length)
            && u64le(bytes, payload + 0x18) == u64le(bytes, payload + 0x20),
        "log control data bounds or duplicate LSN differ"
    );
    let mut fold = 0u64;
    for (index, word) in bytes.chunks_exact(8).enumerate() {
        if index * 8 != entry + 8 {
            fold ^= u64::from_le_bytes(word.try_into()?);
        }
    }
    let computed = (fold >> 32) ^ (fold & 0xffff_ffff);
    let stored = u64le(bytes, entry + 8);
    ensure!(stored == computed, "log control integrity differs");
    let uuid: [u8; 16] = bytes[0x10..0x20].try_into()?;
    ensure!(uuid != [0; 16], "log instance UUID is zero");
    Ok(ControlObservation {
        physical_offset: offset,
        page_sha256: hex::encode(Sha256::digest(bytes)),
        format_magic: u32le(bytes, 4),
        log_uuid: uuid,
        sequence: u64le(bytes, 0x20),
        oldest_lsn: u64le(bytes, payload + 0x18),
        stored_integrity: stored,
        computed_integrity: computed,
        data_offset: reference.data_offset,
        data_length: reference.data_length,
        control_verified: true,
        transactions_replayed: false,
    })
}
