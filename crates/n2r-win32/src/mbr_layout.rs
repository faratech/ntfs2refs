//! The identity of a partition on an MBR disk, for working storage.
//!
//! An MBR disk has no GUIDs. A run identifies every disk and partition by a
//! pair of them, compares the pairs to prove two disks distinct, and writes
//! them into records a recovery reads back. For an MBR disk the pair is
//! derived from what the disk does have: its signature, and the partition's
//! number, offset and length. The same disk gives the same pair every time,
//! and a pair so made says that it is one (`is_mbr_disk`), so that no route
//! that needs a real GPT disk takes it for one.
//!
//! Only working storage is taken from an MBR disk. A source is not.
use crate::layout::{invalid, u32_at, u64_at};
use sha2::{Digest, Sha256};
use std::io;

/// What every disk identity made here ends with: "MBR disk" in ASCII.
const DISK_SUFFIX: &str = "-4d42-5220-6469-736b00000000";

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}

/// The identity of the disk with this signature.
fn disk_identity(signature: u32) -> String {
    format!("{signature:08x}{DISK_SUFFIX}")
}

/// Whether a disk identity was made here from an MBR signature.
pub fn is_mbr_disk(disk_guid: &str) -> bool {
    let text = disk_guid.trim_matches(['{', '}']);
    text.len() == 36 && text.is_ascii() && text[8..].eq_ignore_ascii_case(DISK_SUFFIX)
}

/// The identity of a partition of that disk.
fn partition_identity(signature: u32, number: u32, offset: u64, length: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(b"ntfs2refs MBR partition identity v1");
    hash.update(signature.to_le_bytes());
    hash.update(number.to_le_bytes());
    hash.update(offset.to_le_bytes());
    hash.update(length.to_le_bytes());
    let hex = hex::encode(&hash.finalize()[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// The partition of an MBR disk that a volume lies on, from the disk's
/// layout as Windows reports it (IOCTL_DISK_GET_DRIVE_LAYOUT_EX).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MbrPartition {
    pub partition_number: u32,
    pub disk_guid: String,
    pub partition_guid: String,
}

/// Whether the layout is an MBR disk's.
pub fn is_mbr_layout(raw: &[u8]) -> bool {
    raw.len() >= 48 && u32_at(raw, 0).is_ok_and(|style| style == 0)
}

/// Find the primary partition at exactly `offset` and `length`.
///
/// Refused: a disk without a signature; a partition inside an extended
/// partition (a logical drive), a dynamic disk's, a protective one, or one
/// Windows does not recognize as holding a file system; entries that
/// overlap, repeat a number or lie outside the disk.
pub fn mbr_partition(
    raw: &[u8],
    disk_bytes: u64,
    offset: u64,
    length: u64,
) -> io::Result<MbrPartition> {
    require(
        (48..=65536).contains(&raw.len()) && u32_at(raw, 0)? == 0,
        "MBR disk layout required",
    )?;
    let count = u32_at(raw, 4)? as usize;
    require(
        (1..=128).contains(&count) && raw.len() == 48 + count * 144,
        "incomplete or excessive MBR entry array",
    )?;
    let signature = u32_at(raw, 8)?;
    require(
        signature != 0,
        "the MBR disk has no signature to identify it by",
    )?;
    // An extended partition: a container for logical drives, not a volume.
    let extended = |kind: u8| matches!(kind, 0x05 | 0x0f | 0x85);
    let mut containers = Vec::<(u64, u64)>::new();
    let mut seen = Vec::<(u32, u64, u64)>::new();
    let mut target = None;
    for index in 0..count {
        let at = 48 + index * 144;
        let number = u32_at(raw, at + 24)?;
        let start = u64_at(raw, at + 8)?;
        let size = u64_at(raw, at + 16)?;
        let kind = raw[at + 32];
        if kind == 0 || size == 0 {
            require(
                kind == 0 && size == 0 && number == 0,
                "ambiguous unused MBR entry",
            )?;
            continue;
        }
        let end = start
            .checked_add(size)
            .ok_or_else(|| invalid("MBR partition overflow"))?;
        require(
            u32_at(raw, at)? == 0
                && start >= 512
                && start.is_multiple_of(512)
                && size.is_multiple_of(512)
                && end <= disk_bytes,
            "malformed MBR entry",
        )?;
        if extended(kind) {
            containers.push((start, end));
            continue;
        }
        require(
            number > 0
                && !seen
                    .iter()
                    .any(|(n, lo, hi)| number == *n || start < *hi && *lo < end),
            "duplicate or overlapping MBR entry",
        )?;
        seen.push((number, start, end));
        if start == offset && size == length {
            // 7 is what Windows gives NTFS, ReFS and exFAT. A dynamic disk
            // (0x42) and a protective entry (0xee) are no volume's.
            require(
                target.is_none() && kind == 0x07 && raw[at + 34] != 0,
                "the volume's MBR partition is not an ordinary data partition",
            )?;
            target = Some((number, start, end));
        }
    }
    let (partition_number, start, end) =
        target.ok_or_else(|| invalid("single volume extent does not identify an MBR partition"))?;
    require(
        !containers.iter().any(|(lo, hi)| start < *hi && *lo < end),
        "the volume is a logical drive inside an extended partition; working storage takes a primary partition",
    )?;
    Ok(MbrPartition {
        partition_number,
        disk_guid: disk_identity(signature),
        partition_guid: partition_identity(signature, partition_number, offset, length),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISK: u64 = 64 << 30;
    const MIB: u64 = 1 << 20;
    fn layout(signature: u32, entries: &[(u32, u64, u64, u8)]) -> Vec<u8> {
        let mut raw = vec![0u8; 48 + 4 * 144];
        raw[4..8].copy_from_slice(&4u32.to_le_bytes());
        raw[8..12].copy_from_slice(&signature.to_le_bytes());
        for (index, (number, offset, length, kind)) in entries.iter().enumerate() {
            let at = 48 + index * 144;
            raw[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            raw[at + 16..at + 24].copy_from_slice(&length.to_le_bytes());
            raw[at + 24..at + 28].copy_from_slice(&number.to_le_bytes());
            raw[at + 32] = *kind;
            raw[at + 34] = 1;
        }
        raw
    }

    #[test]
    fn a_primary_partition_gets_an_identity_that_is_the_same_every_time_and_says_what_it_is() {
        let raw = layout(
            0x1234_abcd,
            &[
                (1, MIB, 500 * MIB, 0x07),
                (2, 501 * MIB, 20_000 * MIB, 0x07),
            ],
        );
        let found = mbr_partition(&raw, DISK, 501 * MIB, 20_000 * MIB).unwrap();
        assert_eq!(found.partition_number, 2);
        assert_eq!(found.disk_guid, "1234abcd-4d42-5220-6469-736b00000000");
        assert!(is_mbr_disk(&found.disk_guid));
        assert!(is_mbr_disk("{1234ABCD-4D42-5220-6469-736B00000000}"));
        assert!(!is_mbr_disk("1234abcd-4d42-5220-6469-736b00000001"));
        assert!(crate::layout::guid_bytes(&found.disk_guid).is_ok());
        assert!(crate::layout::guid_bytes(&found.partition_guid).is_ok());
        assert_ne!(found.disk_guid, found.partition_guid);
        assert_eq!(
            found,
            mbr_partition(&raw, DISK, 501 * MIB, 20_000 * MIB).unwrap()
        );
        // The other partition of the disk, and the same place on another
        // disk, are other identities; the disk's is the disk's alone.
        let first = mbr_partition(&raw, DISK, MIB, 500 * MIB).unwrap();
        assert_eq!(first.disk_guid, found.disk_guid);
        assert_ne!(first.partition_guid, found.partition_guid);
        let other = layout(0x1234_abce, &[(2, 501 * MIB, 20_000 * MIB, 0x07)]);
        let other = mbr_partition(&other, DISK, 501 * MIB, 20_000 * MIB).unwrap();
        assert_ne!(other.disk_guid, found.disk_guid);
        assert_ne!(other.partition_guid, found.partition_guid);
    }

    #[test]
    fn what_is_not_a_primary_data_partition_of_a_signed_mbr_disk_is_refused() {
        let ok = [(1, MIB, 500 * MIB, 0x07)];
        let refused = |raw: Vec<u8>, offset, length, said: &str| {
            let error = mbr_partition(&raw, DISK, offset, length).unwrap_err();
            assert!(error.to_string().contains(said), "{error}");
        };
        refused(layout(0, &ok), MIB, 500 * MIB, "no signature");
        let mut gpt = layout(7, &ok);
        gpt[0] = 1;
        refused(gpt, MIB, 500 * MIB, "MBR disk layout required");
        refused(layout(7, &ok), 2 * MIB, 500 * MIB, "does not identify");
        refused(
            layout(7, &[(1, MIB, 500 * MIB, 0x42)]),
            MIB,
            500 * MIB,
            "not an ordinary data partition",
        );
        refused(
            layout(7, &[(1, MIB, 500 * MIB, 0xee)]),
            MIB,
            500 * MIB,
            "not an ordinary data partition",
        );
        // A logical drive: inside the extended partition.
        refused(
            layout(
                7,
                &[(0, MIB, 1_000 * MIB, 0x0f), (5, 2 * MIB, 500 * MIB, 0x07)],
            ),
            2 * MIB,
            500 * MIB,
            "logical drive",
        );
        refused(
            layout(
                7,
                &[(1, MIB, 500 * MIB, 0x07), (2, 400 * MIB, 500 * MIB, 0x07)],
            ),
            MIB,
            500 * MIB,
            "overlapping",
        );
        refused(
            layout(7, &[(1, MIB, DISK, 0x07)]),
            MIB,
            DISK,
            "malformed MBR entry",
        );
        let mut truncated = layout(7, &ok);
        truncated.truncate(48 + 3 * 144);
        refused(truncated, MIB, 500 * MIB, "incomplete");
    }
}
