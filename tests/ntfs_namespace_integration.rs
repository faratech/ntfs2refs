#[allow(
    dead_code,
    reason = "Shared synthetic fixture also serves other suites."
)]
mod support;
use ntfs2refs::{
    ntfs_inspect::{self, AllocationReconciliationStatus},
    ntfs_namespace::Status,
};
use std::io::Cursor;
const MFT: usize = 4 * 4096;
const INDEX: usize = 200 * 4096;
const UPCASE: usize = 128 * 4096;
fn p16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn filename(name: &str, instance: u16) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let mut b = vec![0; 66 + 2 * units.len()];
    p64(&mut b, 0, (1 << 48) | 5);
    b[64] = units.len() as u8;
    b[65] = 1;
    for (i, c) in units.iter().enumerate() {
        p16(&mut b, 66 + 2 * i, *c);
    }
    support::resident(0x30, "", &b, instance)
}
fn put_record(
    image: &mut [u8],
    number: usize,
    attributes: &[Vec<u8>],
    directory: bool,
    links: u16,
) {
    image[MFT + number * 1024..MFT + (number + 1) * 1024].copy_from_slice(&support::record(
        attributes,
        if directory { 3 } else { 1 },
        links,
    ));
}
fn named_index_allocation() -> Vec<u8> {
    let old = support::nonresident(0xa0, &[0x21, 1, 200, 0, 0], 4096, 1);
    let mut b = vec![0; 80];
    b[..64].copy_from_slice(&old[..64]);
    p32(&mut b, 4, 80);
    b[9] = 4;
    p16(&mut b, 10, 64);
    p16(&mut b, 14, 2);
    p16(&mut b, 32, 72);
    for (i, c) in "$I30".encode_utf16().enumerate() {
        p16(&mut b, 64 + 2 * i, c);
    }
    b[72..77].copy_from_slice(&[0x21, 1, 200, 0, 0]);
    b
}
fn fixture() -> Vec<u8> {
    let mut image = support::image();
    let mut bitmap = [0u8; 64];
    for cluster in [0, 4, 5, 6, 7, 8, 30, 100, 200].into_iter().chain(128..160) {
        bitmap[cluster / 8] |= 1 << (cluster % 8);
    }
    put_record(
        &mut image,
        0,
        &[
            support::nonresident(0x80, &[0x11, 5, 4, 0], 20 * 1024, 5),
            support::resident(0xb0, "", &[0xeb, 4, 1], 1),
            filename("$Mft", 2),
        ],
        false,
        1,
    );
    put_record(
        &mut image,
        1,
        &[
            support::nonresident(0x80, &[0x11, 1, 30, 0], 4096, 1),
            filename("$MftMirr", 1),
        ],
        false,
        1,
    );
    let mut version = [0; 12];
    version[8] = 3;
    version[9] = 1;
    put_record(
        &mut image,
        3,
        &[
            support::resident(0x70, "", &version, 0),
            filename("$Volume", 1),
        ],
        false,
        1,
    );
    put_record(
        &mut image,
        6,
        &[
            support::resident(0x80, "", &bitmap, 0),
            filename("$Bitmap", 1),
        ],
        false,
        1,
    );
    put_record(
        &mut image,
        7,
        &[
            support::nonresident(0x80, &[0x11, 1, 0, 0], 4096, 1),
            filename("$Boot", 1),
        ],
        false,
        1,
    );
    put_record(
        &mut image,
        10,
        &[
            support::nonresident(0x80, &[0x21, 32, 128, 0, 0], 131072, 32),
            filename("$UpCase", 1),
        ],
        false,
        1,
    );
    let mut data = support::nonresident(0x80, &[0x11, 1, 100, 0], 17, 1);
    p16(&mut data, 14, 3);
    let si = [0u8; 72];
    put_record(
        &mut image,
        16,
        &[
            support::resident(0x10, "", &si, 0),
            filename("hello.txt", 1),
            filename("alias.txt", 2),
            data,
            support::resident(0x80, "note", b"metadata", 4),
        ],
        false,
        2,
    );
    for unit in 0..=u16::MAX {
        p16(
            &mut image,
            UPCASE + 2 * usize::from(unit),
            if (97..=122).contains(&unit) {
                unit - 32
            } else {
                unit
            },
        );
    }
    let mut root = [0u8; 56];
    p32(&mut root, 0, 0x30);
    p32(&mut root, 4, 1);
    p32(&mut root, 8, 4096);
    root[12] = 1;
    p32(&mut root, 16, 16);
    p32(&mut root, 20, 40);
    p32(&mut root, 24, 40);
    root[28] = 1;
    p16(&mut root, 40, 24);
    p16(&mut root, 44, 3);
    put_record(
        &mut image,
        5,
        &[
            filename(".", 0),
            support::resident(0x90, "$I30", &root, 1),
            named_index_allocation(),
            support::resident(0xb0, "$I30", &[1], 3),
        ],
        true,
        1,
    );
    let mut page = vec![0; 4096];
    page[..4].copy_from_slice(b"INDX");
    p16(&mut page, 4, 40);
    p16(&mut page, 6, 9);
    p32(&mut page, 24, 40);
    p32(&mut page, 32, 4096 - 24);
    let mut at = 64;
    for (name, child) in [
        ("$Bitmap", 6),
        ("$Boot", 7),
        ("$Mft", 0),
        ("$MftMirr", 1),
        ("$UpCase", 10),
        ("$Volume", 3),
        ("alias.txt", 16),
        ("hello.txt", 16),
    ] {
        let attr = filename(name, 0);
        let key_len = 66 + 2 * name.len();
        let size = (16 + key_len + 7) & !7;
        p64(&mut page, at, (1 << 48) | child);
        p16(&mut page, at + 8, size as u16);
        p16(&mut page, at + 10, key_len as u16);
        page[at + 16..at + 16 + key_len].copy_from_slice(&attr[24..24 + key_len]);
        at += size;
    }
    p16(&mut page, at + 8, 16);
    p16(&mut page, at + 12, 2);
    at += 16;
    p32(&mut page, 28, (at - 24) as u32);
    p16(&mut page, 40, 0xabcd);
    for sector in 1..9 {
        let old = [page[512 * sector - 2], page[512 * sector - 1]];
        page[40 + 2 * sector..42 + 2 * sector].copy_from_slice(&old);
        p16(&mut page, 512 * sector - 2, 0xabcd);
    }
    image[INDEX..INDEX + 4096].copy_from_slice(&page);
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
#[test]
fn reconciles_raw_namespace_and_allocation_without_admitting_conversion() {
    let image = fixture();
    let original = image.clone();
    let r = inspect(&image);
    let ns = r.namespace_reconciliation.unwrap();
    assert_eq!(ns.status, Status::ConsistentRawModel);
    assert_eq!(ns.directories, 1);
    assert_eq!(ns.index_blocks, 1);
    assert_eq!(ns.index_entries, 8);
    assert_eq!(ns.reachable_objects, 8);
    assert_eq!(
        r.allocation_reconciliation.unwrap().status,
        AllocationReconciliationStatus::ConsistentRawModel
    );
    assert!(!r.inventory_complete);
    assert!(
        r.blockers
            .iter()
            .any(|b| b.code == "directory_indexes_unverified")
    );
    assert!(
        r.blockers
            .iter()
            .any(|b| b.code == "security_descriptors_unresolved")
    );
    assert_eq!(image, original);
}
#[test]
fn reports_torn_index_and_keeps_independent_inventory() {
    let mut image = fixture();
    image[INDEX + 510] ^= 1;
    let r = inspect(&image);
    let ns = r.namespace_reconciliation.unwrap();
    assert_eq!(ns.status, Status::Rejected);
    assert!(ns.detail.contains("torn INDX"));
    assert!(!r.files.is_empty());
    assert!(!r.inventory_complete);
}
#[test]
fn catches_index_reference_to_a_record_omitted_from_mft_bitmap() {
    let mut image = fixture();
    let at = attribute(&image, 0, 0xb0);
    let value = at
        + usize::from(u16::from_le_bytes(
            image[at + 20..at + 22].try_into().unwrap(),
        ));
    image[value + 2] &= !1;
    let ns = inspect(&image).namespace_reconciliation.unwrap();
    assert_eq!(ns.status, Status::Rejected);
    assert!(ns.detail.contains("index child absent"));
}
#[test]
fn refuses_unassembled_extension_records() {
    let mut image = fixture();
    p64(&mut image, MFT + 16 * 1024 + 32, (1 << 48) | 17);
    let r = inspect(&image);
    assert_eq!(
        r.namespace_reconciliation.unwrap().status,
        Status::IncompleteAttributeInventory
    );
    assert!(!r.inventory_complete);
}
#[test]
fn detects_bad_volume_upcase_data() {
    let mut image = fixture();
    p16(&mut image, UPCASE + 2 * 97, 97);
    let ns = inspect(&image).namespace_reconciliation.unwrap();
    assert_eq!(ns.status, Status::Rejected);
    assert!(ns.detail.contains("ASCII $UpCase"));
}
#[test]
fn rejects_unqualified_index_geometry_without_failing_raw_mft_inventory() {
    let mut image = fixture();
    image[68] = 2;
    let r = inspect(&image);
    let ns = r.namespace_reconciliation.unwrap();
    assert_eq!(ns.status, Status::Rejected);
    assert!(ns.detail.contains("4 KiB"));
    assert!(!r.files.is_empty());
}
#[test]
fn absent_namespace_evidence_deserializes_as_unverified() {
    let r = inspect(&fixture());
    let mut value = serde_json::to_value(&r).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("namespace_reconciliation");
    let old: ntfs_inspect::NtfsInspection = serde_json::from_value(value).unwrap();
    assert!(old.namespace_reconciliation.is_none());
    assert!(!old.inventory_complete);
}
