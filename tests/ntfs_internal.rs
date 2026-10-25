#[allow(dead_code, reason = "shared synthetic NTFS fixtures")]
mod support;
use ntfs2refs::{ntfs_inspect, ntfs_internal};
use std::io::Cursor;
const MFT: usize = 4 * 4096;
fn name(text: &str, parent: u64) -> Vec<u8> {
    let units: Vec<_> = text.encode_utf16().collect();
    let mut value = vec![0; 66 + 2 * units.len()];
    value[..8].copy_from_slice(&((1u64 << 48) | parent).to_le_bytes());
    value[64] = units.len() as u8;
    value[65] = 1;
    for (i, c) in units.iter().enumerate() {
        value[66 + 2 * i..68 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    support::resident(0x30, "", &value, 0)
}
fn root(collation: u32, entry: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut rows = Vec::new();
    if let Some((key, value)) = entry {
        let at = (16 + key.len() + 7) & !7;
        let length = (at + value.len() + 7) & !7;
        rows.resize(length, 0);
        rows[..2].copy_from_slice(&(at as u16).to_le_bytes());
        rows[2..4].copy_from_slice(&(value.len() as u16).to_le_bytes());
        rows[8..10].copy_from_slice(&(length as u16).to_le_bytes());
        rows[10..12].copy_from_slice(&(key.len() as u16).to_le_bytes());
        rows[16..16 + key.len()].copy_from_slice(key);
        rows[at..at + value.len()].copy_from_slice(value);
    }
    let terminal = rows.len();
    rows.resize(terminal + 16, 0);
    rows[terminal + 8] = 16;
    rows[terminal + 12] = 2;
    let mut result = vec![0; 32];
    result[4..8].copy_from_slice(&collation.to_le_bytes());
    result[8..12].copy_from_slice(&4096u32.to_le_bytes());
    result[12] = 1;
    result[16] = 16;
    let used = (16 + rows.len()) as u32;
    result[20..24].copy_from_slice(&used.to_le_bytes());
    result[24..28].copy_from_slice(&used.to_le_bytes());
    result.extend(rows);
    result
}
fn fixture() -> Vec<u8> {
    let mut image = support::image();
    let mut bitmap = [0u8; 3];
    for n in [0usize, 3, 5, 6, 11, 16, 17, 18, 19] {
        bitmap[n / 8] |= 1 << (n % 8);
    }
    let mut put = |n: usize, attrs: Vec<Vec<u8>>, directory| {
        image[MFT + n * 1024..MFT + (n + 1) * 1024].copy_from_slice(&support::record(
            &attrs,
            if directory { 3 } else { 1 },
            1,
        ));
    };
    put(
        0,
        vec![
            support::nonresident(0x80, &[0x11, 5, 4, 0], 20 * 1024, 5),
            support::resident(0xb0, "", &bitmap, 1),
        ],
        false,
    );
    put(11, vec![name("$Extend", 5)], true);
    put(
        17,
        vec![
            name("$ObjId", 11),
            support::resident(0x90, "$O", &root(0x13, None), 1),
        ],
        false,
    );
    put(
        18,
        vec![
            name("$Reparse", 11),
            support::resident(0x90, "$R", &root(0x13, None), 1),
        ],
        false,
    );
    let mut quota = vec![0; 48];
    quota[..4].copy_from_slice(&2u32.to_le_bytes());
    quota[4..8].copy_from_slice(&1u32.to_le_bytes());
    quota[24..40].fill(0xff);
    put(
        19,
        vec![
            name("$Quota", 11),
            support::resident(0x90, "$O", &root(0x11, None), 1),
            support::resident(
                0x90,
                "$Q",
                &root(0x10, Some((&1u32.to_le_bytes(), &quota))),
                2,
            ),
        ],
        false,
    );
    image
}
#[test]
fn frozen_index_proof_reads_records_and_rejects_changed_or_foreign_state() {
    let bytes = fixture();
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    let proof = ntfs_internal::verify(&mut Cursor::new(&bytes), &raw).unwrap();
    assert!(proof.binds(&raw));
    assert!(proof.default_quotas_only);
    assert!(!proof.native_quota_policy_bound);
    assert!(!proof.replacement_supported);
    assert_eq!(proof.indexes.len(), 4);
    let mut changed = bytes.clone();
    changed[MFT + 17 * 1024 + 16] ^= 1;
    assert!(ntfs_internal::verify(&mut Cursor::new(changed), &raw).is_err());
    let mut changed = raw.clone();
    changed
        .files
        .iter_mut()
        .find(|f| f.record_number == 17)
        .unwrap()
        .attributes[1]
        .resident_sha256 = Some("0".repeat(64));
    assert!(!proof.binds(&changed));
    assert!(ntfs_internal::verify(&mut Cursor::new(&bytes), &changed).is_err());
    let mut changed = raw;
    changed.files.retain(|f| f.record_number != 18);
    assert!(ntfs_internal::verify(&mut Cursor::new(&bytes), &changed).is_err());
}
