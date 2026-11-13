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
/// What the two control pages of one log say when set side by side. Each
/// page is validated on its own by [`inspect_control`]; this is the part
/// that needs both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlAgreement {
    pub sequences_equal: bool,
    pub oldest_lsn_equal: bool,
    /// The control with the higher sequence number; none when they are equal.
    pub newer_control_index: Option<usize>,
    /// Always false. This reader knows no expected value for the format
    /// magic, so the two pages are only required to carry the same one.
    pub format_magic_validated: bool,
}

/// Compares the two controls of one log. Unequal sequence numbers or LSNs
/// are reported, not refused: whether the two pages may lag one another is
/// not established here, and the log's transactions are not replayed.
pub fn compare_controls(
    first: &ControlObservation,
    second: &ControlObservation,
) -> ControlAgreement {
    ControlAgreement {
        sequences_equal: first.sequence == second.sequence,
        oldest_lsn_equal: first.oldest_lsn == second.oldest_lsn,
        newer_control_index: match first.sequence.cmp(&second.sequence) {
            std::cmp::Ordering::Greater => Some(0),
            std::cmp::Ordering::Less => Some(1),
            std::cmp::Ordering::Equal => None,
        },
        format_magic_validated: false,
    }
}

#[cfg(test)]
mod control_agreement_tests {
    use super::*;

    fn control(sequence: u64, oldest_lsn: u64) -> ControlObservation {
        ControlObservation {
            physical_offset: 0,
            page_sha256: String::new(),
            format_magic: 0x1234,
            log_uuid: [7; 16],
            sequence,
            oldest_lsn,
            stored_integrity: 0,
            computed_integrity: 0,
            data_offset: 0,
            data_length: 0,
            control_verified: true,
            transactions_replayed: false,
        }
    }

    #[test]
    fn two_controls_that_differ_in_sequence_or_lsn_are_reported_as_differing() {
        let same = compare_controls(&control(5, 100), &control(5, 100));
        assert!(same.sequences_equal && same.oldest_lsn_equal);
        assert_eq!(same.newer_control_index, None);

        let lagging = compare_controls(&control(5, 100), &control(9, 200));
        assert!(!lagging.sequences_equal && !lagging.oldest_lsn_equal);
        assert_eq!(lagging.newer_control_index, Some(1));
        assert_eq!(
            compare_controls(&control(9, 200), &control(5, 200)).newer_control_index,
            Some(0)
        );
        // Equal magic on both pages is all that is known about the magic.
        assert!(!same.format_magic_validated && !lagging.format_magic_validated);
    }
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
