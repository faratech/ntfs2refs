#[allow(dead_code, reason = "Shared synthetic parser fixture.")]
mod support;
use ntfs2refs::{
    ntfs_inspect,
    ntfs_security::{self as sec, Status},
};
use std::io::Cursor;
const MFT: usize = 4 * 4096;
const SDS: usize = 200 * 4096;
fn p16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn descriptor() -> Vec<u8> {
    let mut b = vec![0; 20];
    b[0] = 1;
    p16(&mut b, 2, 0x8004);
    b
}
fn si(id: Option<u32>, instance: u16) -> Vec<u8> {
    let mut b = vec![0; if id.is_some() { 72 } else { 48 }];
    if let Some(id) = id {
        p32(&mut b, 52, id);
    }
    support::resident(0x10, "", &b, instance)
}
fn filename() -> Vec<u8> {
    let mut b = vec![0; 68];
    p64(&mut b, 0, (1 << 48) | 5);
    b[64] = 1;
    b[65] = 1;
    p16(&mut b, 66, 46);
    support::resident(0x30, "", &b, 0)
}
fn root(id: bool, hash: u32) -> Vec<u8> {
    let key = if id {
        256u32.to_le_bytes().to_vec()
    } else {
        [hash.to_le_bytes(), 256u32.to_le_bytes()].concat()
    };
    let data = 16 + key.len();
    let size = (data + 20 + 7) & !7;
    let mut b = vec![0; 32 + size + 16];
    p32(&mut b, 4, if id { 0x10 } else { 0x12 });
    p32(&mut b, 8, 4096);
    b[12] = 1;
    p32(&mut b, 16, 16);
    p32(&mut b, 20, (16 + size + 16) as u32);
    p32(&mut b, 24, (16 + size + 16) as u32);
    p16(&mut b, 32, data as u16);
    p16(&mut b, 34, 20);
    p16(&mut b, 40, size as u16);
    p16(&mut b, 42, key.len() as u16);
    b[48..48 + key.len()].copy_from_slice(&key);
    p32(&mut b, 32 + data, hash);
    p32(&mut b, 36 + data, 256);
    p32(&mut b, 48 + data, 40);
    p16(&mut b, 32 + size + 8, 16);
    p16(&mut b, 32 + size + 12, 2);
    b
}
fn named_sds() -> Vec<u8> {
    let logical = 0x40028;
    let old = support::nonresident(0x80, &[0x21, 65, 200, 0, 0], logical, 65);
    let mut b = vec![0; 80];
    b[..64].copy_from_slice(&old[..64]);
    p32(&mut b, 4, 80);
    b[9] = 4;
    p16(&mut b, 10, 64);
    p16(&mut b, 14, 1);
    p16(&mut b, 32, 72);
    for (i, c) in "$SDS".encode_utf16().enumerate() {
        p16(&mut b, 64 + 2 * i, c);
    }
    b[72..77].copy_from_slice(&[0x21, 65, 200, 0, 0]);
    b
}
fn record(image: &mut [u8], number: usize, attrs: &[Vec<u8>], dir: bool) {
    image[MFT + number * 1024..MFT + (number + 1) * 1024].copy_from_slice(&support::record(
        attrs,
        if dir { 3 } else { 1 },
        1,
    ));
}
// This isolates security reconciliation; missing namespace/log/backup evidence
// intentionally prevents synthetic fixtures becoming source admission.
fn fixture() -> Vec<u8> {
    let mut image = support::image();
    record(
        &mut image,
        0,
        &[
            support::nonresident(0x80, &[0x11, 5, 4, 0], 20 * 1024, 5),
            support::resident(0xb0, "", &[0x69, 2, 1], 1),
            si(Some(256), 2),
        ],
        false,
    );
    let mut vi = [0; 12];
    vi[8] = 3;
    vi[9] = 1;
    record(
        &mut image,
        3,
        &[support::resident(0x70, "", &vi, 0), si(Some(256), 1)],
        false,
    );
    record(
        &mut image,
        5,
        &[
            filename(),
            si(None, 1),
            support::resident(0x50, "", &descriptor(), 2),
        ],
        true,
    );
    let mut bitmap = [0; 64];
    for c in [0, 4, 5, 6, 7, 8, 30, 100].into_iter().chain(200..265) {
        bitmap[c / 8] |= 1 << (c % 8);
    }
    record(
        &mut image,
        6,
        &[support::resident(0x80, "", &bitmap, 0), si(Some(256), 1)],
        false,
    );
    let d = descriptor();
    let hash = sec::ntfs_hash(&d).unwrap();
    record(
        &mut image,
        9,
        &[
            si(Some(256), 0),
            named_sds(),
            support::resident(0x90, "$SII", &root(true, hash), 2),
            support::resident(0x90, "$SDH", &root(false, hash), 3),
        ],
        false,
    );
    let mut h = vec![0; 20];
    p32(&mut h, 0, hash);
    p32(&mut h, 4, 256);
    p32(&mut h, 16, 40);
    for at in [SDS, SDS + 0x40000] {
        image[at..at + 20].copy_from_slice(&h);
        image[at + 20..at + 40].copy_from_slice(&d);
    }
    image
}
fn inspect(image: &[u8]) -> ntfs_inspect::NtfsInspection {
    ntfs_inspect::inspect(&mut Cursor::new(image), image.len() as u64).unwrap()
}
fn attribute(image: &[u8], record: usize, kind: u32) -> usize {
    let base = MFT + record * 1024;
    let mut at = base
        + usize::from(u16::from_le_bytes(
            image[base + 20..base + 22].try_into().unwrap(),
        ));
    loop {
        let ty = u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        assert_ne!(ty, u32::MAX);
        if ty == kind {
            return at;
        }
        at += u32::from_le_bytes(image[at + 4..at + 8].try_into().unwrap()) as usize;
    }
}
fn value(image: &[u8], attr: usize) -> usize {
    attr + usize::from(u16::from_le_bytes(
        image[attr + 20..attr + 22].try_into().unwrap(),
    ))
}

#[test]
fn resolves_central_and_legacy_security_without_admitting_conversion() {
    let image = fixture();
    let original = image.clone();
    let r = inspect(&image);
    let s = r.security_reconciliation.unwrap();
    assert_eq!(s.status, Status::ConsistentRawModel);
    assert_eq!(s.central_descriptors, 1);
    assert_eq!(s.legacy_descriptors, 1);
    assert_eq!(s.bound_files, 6);
    assert_eq!(s.descriptors.len(), 2);
    assert_eq!(
        s.bindings
            .iter()
            .find(|b| b.record_number == 5)
            .unwrap()
            .security_id,
        None
    );
    assert!(!r.inventory_complete);
    assert!(
        r.blockers
            .iter()
            .any(|b| b.code == "security_descriptors_unresolved")
    );
    assert_eq!(image, original);
}
#[test]
fn rejects_mirror_corruption_without_partial_bindings() {
    let mut image = fixture();
    image[SDS + 0x40000 + 20] ^= 1;
    let s = inspect(&image).security_reconciliation.unwrap();
    assert_eq!(s.status, Status::Rejected);
    assert!(s.detail.contains("mirror mismatch"));
    assert!(s.descriptors.is_empty() && s.bindings.is_empty());
}
#[test]
fn refuses_matching_but_incorrectly_hashed_sds_copies() {
    let mut image = fixture();
    image[SDS + 21] = 1;
    image[SDS + 0x40000 + 21] = 1;
    let s = inspect(&image).security_reconciliation.unwrap();
    assert_eq!(s.status, Status::Rejected);
    assert!(s.detail.contains("hash mismatch"));
}
#[test]
fn detects_sii_key_value_disagreement() {
    let mut image = fixture();
    let at = attribute(&image, 9, 0x90);
    let at = value(&image, at);
    p32(&mut image, at + 48, 257);
    let s = inspect(&image).security_reconciliation.unwrap();
    assert_eq!(s.status, Status::Rejected);
    assert!(s.detail.contains("key/value"));
}
#[test]
fn rejects_unresolved_mft_security_id() {
    let mut image = fixture();
    let at = attribute(&image, 16, 0x10);
    let at = value(&image, at);
    p32(&mut image, at + 52, 257);
    let s = inspect(&image).security_reconciliation.unwrap();
    assert_eq!(s.status, Status::Rejected);
    assert!(s.detail.contains("security ID is absent"));
    assert!(s.bindings.is_empty());
}
#[test]
fn refuses_ambiguous_legacy_and_central_descriptor() {
    let mut image = fixture();
    record(
        &mut image,
        5,
        &[
            filename(),
            si(Some(256), 1),
            support::resident(0x50, "", &descriptor(), 2),
        ],
        true,
    );
    let s = inspect(&image).security_reconciliation.unwrap();
    assert_eq!(s.status, Status::Rejected);
    assert!(s.detail.contains("both legacy and central"));
}
#[test]
fn refuses_unassembled_security_source_attributes() {
    let mut image = fixture();
    p64(&mut image, MFT + 16 * 1024 + 32, (1 << 48) | 17);
    let r = inspect(&image);
    let s = r.security_reconciliation.unwrap();
    assert_eq!(s.status, Status::IncompleteAttributeInventory);
    assert!(s.descriptors.is_empty() && s.bindings.is_empty());
    assert!(!r.inventory_complete);
}
#[test]
fn uninitialized_sds_is_not_hidden_by_logical_zero_filling() {
    let mut image = fixture();
    let at = attribute(&image, 9, 0x80);
    p64(&mut image, at + 56, 0x40027);
    let s = inspect(&image).security_reconciliation.unwrap();
    assert_eq!(s.status, Status::Rejected);
    assert!(s.detail.contains("fully initialized"));
}
#[test]
fn absent_security_field_in_old_report_remains_unverified() {
    let r = inspect(&fixture());
    let mut v = serde_json::to_value(r).unwrap();
    v.as_object_mut().unwrap().remove("security_reconciliation");
    let old: ntfs_inspect::NtfsInspection = serde_json::from_value(v).unwrap();
    assert!(old.security_reconciliation.is_none());
    assert!(!old.inventory_complete);
}
