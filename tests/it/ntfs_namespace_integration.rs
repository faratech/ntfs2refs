#[allow(
    dead_code,
    reason = "Shared synthetic fixture also serves other suites."
)]
use crate::support;
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

// Helpers for the complete assembly/namespace/security fixture below. Synthetic
// bytes exercise the converter pipeline; they are not native mount evidence.
fn assembly_attrs(image: &[u8], number: usize) -> Vec<Vec<u8>> {
    let mut raw = image[MFT + number * 1024..MFT + (number + 1) * 1024].to_vec();
    for (index, tail) in [510, 1022].into_iter().enumerate() {
        let value: [u8; 2] = raw[50 + index * 2..52 + index * 2].try_into().unwrap();
        raw[tail..tail + 2].copy_from_slice(&value);
    }
    let mut at = 56;
    let mut attrs = Vec::new();
    while u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) != u32::MAX {
        let size = u32::from_le_bytes(raw[at + 4..at + 8].try_into().unwrap()) as usize;
        attrs.push(raw[at..at + size].to_vec());
        at += size;
    }
    attrs
}
fn assembly_si(instance: u16, directory: bool) -> Vec<u8> {
    let mut value = [0u8; 72];
    for at in [0, 8, 16, 24] {
        p64(&mut value, at, 1);
    }
    // Directory identity comes from the FILE header; keep the existing stored
    // basic-attribute profile used by the shadow constructor.
    p32(&mut value, 32, if directory { 0 } else { 0x20 });
    p32(&mut value, 52, 256);
    support::resident(0x10, "", &value, instance)
}
fn assembly_security_index(by_id: bool, hash: u32) -> Vec<u8> {
    let key = if by_id {
        256u32.to_le_bytes().to_vec()
    } else {
        [hash.to_le_bytes(), 256u32.to_le_bytes()].concat()
    };
    let data = 16 + key.len();
    let size = (data + 20 + 7) & !7;
    let mut value = vec![0; 32 + size + 16];
    p32(&mut value, 4, if by_id { 0x10 } else { 0x12 });
    p32(&mut value, 8, 4096);
    value[12] = 1;
    p32(&mut value, 16, 16);
    p32(&mut value, 20, (16 + size + 16) as u32);
    p32(&mut value, 24, (16 + size + 16) as u32);
    p16(&mut value, 32, data as u16);
    p16(&mut value, 34, 20);
    p16(&mut value, 40, size as u16);
    p16(&mut value, 42, key.len() as u16);
    value[48..48 + key.len()].copy_from_slice(&key);
    p32(&mut value, 32 + data, hash);
    p32(&mut value, 36 + data, 256);
    p32(&mut value, 48 + data, 48);
    p16(&mut value, 32 + size + 8, 16);
    p16(&mut value, 32 + size + 12, 2);
    value
}
fn assembly_root_page(image: &mut [u8], base: u64) {
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
        ("$MFT", 0),
        ("$MFTMirr", 1),
        ("$Secure", 9),
        ("$UpCase", 10),
        ("$Volume", 3),
        ("hello.txt", base),
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
        let value: [u8; 2] = page[sector * 512 - 2..sector * 512].try_into().unwrap();
        page[40 + sector * 2..42 + sector * 2].copy_from_slice(&value);
        p16(&mut page, sector * 512 - 2, 0xabcd);
    }
    image[INDEX..INDEX + 4096].copy_from_slice(&page);
}

fn assembly_fixture(
    base: usize,
    extensions: [usize; 2],
    logical: u64,
    initialized: u64,
) -> Vec<u8> {
    let mut image = fixture();
    for number in [0, 1, 3, 5, 6, 7, 10] {
        let mut attrs = assembly_attrs(&image, number);
        if number == 0 || number == 1 {
            attrs.retain(|a| u32::from_le_bytes(a[..4].try_into().unwrap()) != 0x30);
            attrs.push(filename(if number == 0 { "$MFT" } else { "$MFTMirr" }, 2));
        }
        attrs.push(assembly_si(100, number == 5));
        put_record(&mut image, number, &attrs, number == 5, 1);
    }
    let bitmap_at = attribute(&image, 0, 0xb0);
    let bitmap_value = bitmap_at
        + usize::from(u16::from_le_bytes(
            image[bitmap_at + 20..bitmap_at + 22].try_into().unwrap(),
        ));
    image[bitmap_value + 1] |= 2;
    image[bitmap_value + 2] = 0;
    for number in [base, extensions[0], extensions[1]] {
        image[bitmap_value + number / 8] |= 1 << (number % 8);
    }

    let mut descriptor = vec![0; 28];
    descriptor[0] = 1;
    p16(&mut descriptor, 2, 0x8004);
    p32(&mut descriptor, 16, 20);
    descriptor[20] = 2;
    p16(&mut descriptor, 22, 8);
    let hash = ntfs2refs::ntfs_security::ntfs_hash(&descriptor).unwrap();
    let mut sds = support::nonresident(0x80, &[0x21, 65, 224, 0, 0], 0x40030, 65);
    sds.resize(80, 0);
    p32(&mut sds, 4, 80);
    sds[9] = 4;
    p16(&mut sds, 10, 64);
    p16(&mut sds, 14, 1);
    p16(&mut sds, 32, 72);
    for (i, unit) in "$SDS".encode_utf16().enumerate() {
        p16(&mut sds, 64 + i * 2, unit);
    }
    sds[72..77].copy_from_slice(&[0x21, 65, 224, 0, 0]);
    put_record(
        &mut image,
        9,
        &[
            assembly_si(0, false),
            sds,
            support::resident(0x90, "$SII", &assembly_security_index(true, hash), 2),
            support::resident(0x90, "$SDH", &assembly_security_index(false, hash), 3),
            filename("$Secure", 4),
        ],
        false,
        1,
    );
    for at in [224 * 4096, 224 * 4096 + 0x40000] {
        p32(&mut image, at, hash);
        p32(&mut image, at + 4, 256);
        p32(&mut image, at + 16, 48);
        image[at + 20..at + 48].copy_from_slice(&descriptor);
    }
    let bitmap_at = attribute(&image, 6, 0x80);
    let bitmap_value = bitmap_at
        + usize::from(u16::from_le_bytes(
            image[bitmap_at + 20..bitmap_at + 22].try_into().unwrap(),
        ));
    for cluster in [102, 104].into_iter().chain(224..289) {
        image[bitmap_value + cluster / 8] |= 1 << (cluster % 8);
    }

    let mut list = Vec::new();
    for (kind, record, vcn, instance) in [
        (0x10, base, 0, 0),
        (0x30, base, 0, 1),
        (0x80, base, 0, 3),
        (0x80, extensions[0], 1, 0),
        (0x80, extensions[1], 2, 0),
    ] {
        let mut entry = [0; 32];
        p32(&mut entry, 0, kind);
        p16(&mut entry, 4, 32);
        entry[7] = 26;
        p64(&mut entry, 8, vcn);
        p64(&mut entry, 16, (1 << 48) | record as u64);
        p16(&mut entry, 24, instance);
        list.extend_from_slice(&entry);
    }
    let mut data = support::nonresident(0x80, &[0x11, 1, 100, 0], logical, 1);
    p16(&mut data, 14, 3);
    p64(&mut data, 40, 3 * 4096);
    p64(&mut data, 56, initialized);
    put_record(
        &mut image,
        base,
        &[
            assembly_si(0, false),
            filename("hello.txt", 1),
            support::resident(0x20, "", &list, 2),
            data,
        ],
        false,
        1,
    );
    for (i, number) in extensions.into_iter().enumerate() {
        let mut data = support::nonresident(0x80, &[0x11, 1, 102 + i as u8 * 2, 0], 0, 1);
        p64(&mut data, 16, i as u64 + 1);
        p64(&mut data, 24, i as u64 + 1);
        for at in [40, 48, 56] {
            p64(&mut data, at, u64::MAX);
        }
        let mut extension = support::record(&[data], 1, 0);
        p64(&mut extension, 32, (1 << 48) | base as u64);
        image[MFT + number * 1024..MFT + (number + 1) * 1024].copy_from_slice(&extension);
    }
    for (cluster, byte) in [(100, 0x31), (102, 0x72), (104, 0xc3)] {
        image[cluster * 4096..(cluster + 1) * 4096].fill(byte);
    }
    assembly_root_page(&mut image, base as u64);
    image
}

fn fragmented_mft_fixture(island: bool, nonresident_aux: bool) -> Vec<u8> {
    let mut image = assembly_fixture(23, [16, 17], 12288, 12288);
    let user = image[MFT + 23 * 1024..MFT + 24 * 1024].to_vec();
    image[MFT + 23 * 1024..MFT + 24 * 1024].fill(0);
    let records: usize = if island { 48 } else { 24 };
    let mut bitmap = vec![0u8; records.div_ceil(8)];
    for number in [0, 1, 3, 5, 6, 7, 9, 10, 16, 17, 19, 23]
        .into_iter()
        .chain(island.then_some(30))
    {
        bitmap[number / 8] |= 1 << (number % 8);
    }
    let segments = if island {
        vec![(30usize, 5u64, 50u16, 1u8), (19, 6, 60, 6)]
    } else {
        vec![(19, 5, 50, 1)]
    };
    let mut list = Vec::new();
    let origins = [(0x10, 0, 0, 100), (0x30, 0, 0, 2), (0x80, 0, 0, 0)]
        .into_iter()
        .chain(
            segments
                .iter()
                .map(|(number, vcn, _, _)| (0x80, *number, *vcn, 0)),
        )
        .chain(std::iter::once((0xb0, 0, 0, 1)));
    for (kind, number, vcn, instance) in origins {
        let mut row = [0u8; 32];
        p32(&mut row, 0, kind);
        p16(&mut row, 4, 32);
        row[7] = 26;
        p64(&mut row, 8, vcn);
        p64(&mut row, 16, (1 << 48) | number as u64);
        p16(&mut row, 24, instance);
        list.extend(row);
    }
    let bitmap_attribute = if nonresident_aux {
        image[91 * 4096..91 * 4096 + bitmap.len()].copy_from_slice(&bitmap);
        let mut a = list_disk_attribute(0xb0, 91, bitmap.len() as u64, 1);
        p16(&mut a, 14, 1);
        a
    } else {
        support::resident(0xb0, "", &bitmap, 1)
    };
    let list_attribute = if nonresident_aux {
        image[90 * 4096..90 * 4096 + list.len()].copy_from_slice(&list);
        let mut a = list_disk_attribute(0x20, 90, list.len() as u64, 1);
        p16(&mut a, 14, 3);
        a
    } else {
        support::resident(0x20, "", &list, 3)
    };
    let mut data = list_disk_attribute(0x80, 4, (records * 1024) as u64, 5);
    p64(&mut data, 40, (records * 1024) as u64);
    put_record(
        &mut image,
        0,
        &[
            assembly_si(100, false),
            filename("$MFT", 2),
            list_attribute,
            data,
            bitmap_attribute,
        ],
        false,
        1,
    );
    image[50 * 4096 + 3 * 1024..51 * 4096].copy_from_slice(&user);
    for (number, vcn, lcn, clusters) in segments {
        let mut data = list_disk_attribute(0x80, lcn, 0, clusters);
        p64(&mut data, 16, vcn);
        p64(&mut data, 24, vcn + u64::from(clusters) - 1);
        for at in [40, 48, 56] {
            p64(&mut data, at, u64::MAX);
        }
        let mut extension = support::record(&[data], 1, 0);
        p64(&mut extension, 32, 1 << 48);
        let at = if number < 20 {
            MFT + number * 1024
        } else {
            60 * 4096 + (number - 24) * 1024
        };
        image[at..at + 1024].copy_from_slice(&extension);
    }
    let volume_bitmap = attribute(&image, 6, 0x80);
    let value = volume_bitmap
        + usize::from(u16::from_le_bytes(
            image[volume_bitmap + 20..volume_bitmap + 22]
                .try_into()
                .unwrap(),
        ));
    for cluster in std::iter::once(50)
        .chain(if island { 60..66 } else { 60..60 })
        .chain(if nonresident_aux { 90..92 } else { 90..90 })
    {
        image[value + cluster / 8] |= 1 << (cluster % 8);
    }
    image[MFT + 2 * 1024..MFT + 3 * 1024].copy_from_slice(&support::record(&[], 0, 0));
    let primary = image[MFT..MFT + 4096].to_vec();
    image[30 * 4096..31 * 4096].copy_from_slice(&primary);
    let boot = image[..512].to_vec();
    let end = image.len();
    image[end - 512..].copy_from_slice(&boot);
    image
}

#[test]
fn mft_bootstrap_reaches_user_records_outside_its_initial_map_and_rechecks_backups() {
    for island in [false, true] {
        for auxiliary in [false, true] {
            let image = fragmented_mft_fixture(island, auxiliary);
            let raw = inspect(&image);
            ntfs_inspect::validate_record_coverage(&raw).unwrap();
            let mft = raw
                .attribute_assemblies
                .iter()
                .find(|a| a.base.record_number == 0)
                .unwrap();
            assert_eq!(mft.schema_version, if auxiliary { 4 } else { 3 });
            assert_eq!(
                mft.extensions
                    .iter()
                    .map(|r| r.record_number)
                    .collect::<Vec<_>>(),
                if island { vec![19, 30] } else { vec![19] }
            );
            assert_eq!(
                raw.records_scanned,
                raw.files.len() as u64 + if island { 4 } else { 3 }
            );
            assert_eq!(
                raw.allocation_reconciliation.as_ref().unwrap().status,
                AllocationReconciliationStatus::ConsistentRawModel
            );
            assert_eq!(
                raw.namespace_reconciliation.as_ref().unwrap().status,
                Status::ConsistentRawModel
            );
            assert_eq!(
                raw.security_reconciliation.as_ref().unwrap().status,
                ntfs2refs::ntfs_security::Status::ConsistentRawModel
            );
            let expected = [vec![0x31; 4096], vec![0x72; 4096], vec![0xc3; 4096]].concat();
            assert_eq!(
                ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &raw, 23, 16384).unwrap(),
                expected
            );
            let bytes =
                ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &raw, 0, 65536).unwrap();
            assert_eq!(&bytes[23 * 1024..23 * 1024 + 4], b"FILE");
            assert_eq!(
                ntfs2refs::shadow_tree::derive_ordinary(&raw)
                    .unwrap()
                    .objects
                    .len(),
                2
            );
            assert!(
                ntfs2refs::ntfs_backup::verify(&mut Cursor::new(&image), image.len() as u64, &raw)
                    .unwrap()
                    .binds(&raw)
            );
        }
    }
}

#[test]
fn mft_bootstrap_refuses_unreachable_headers_and_changed_bitmap_evidence() {
    use std::io::{Read, Seek, SeekFrom};
    struct NoGuess<'a> {
        inner: Cursor<&'a [u8]>,
        forbidden_reads: usize,
    }
    impl Read for NoGuess<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let start = self.inner.position();
            let end = start + out.len() as u64;
            if start < 51 * 4096 && end > 50 * 4096 {
                self.forbidden_reads += 1;
                return Err(std::io::Error::other("Unlearned MFT range read"));
            }
            self.inner.read(out)
        }
    }
    impl Seek for NoGuess<'_> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }
    let mut image = fragmented_mft_fixture(false, false);
    let list = attribute(&image, 0, 0x20);
    let value = list
        + usize::from(u16::from_le_bytes(
            image[list + 20..list + 22].try_into().unwrap(),
        ));
    p64(&mut image, value + 3 * 32 + 16, (1 << 48) | 23);
    let mut guarded = NoGuess {
        inner: Cursor::new(image.as_slice()),
        forbidden_reads: 0,
    };
    let error = ntfs_inspect::inspect(&mut guarded, image.len() as u64).unwrap_err();
    assert!(format!("{error:#}").contains("no progress"));
    assert_eq!(guarded.forbidden_reads, 0);

    let image = fragmented_mft_fixture(true, true);
    let raw = inspect(&image);
    let mut stale = image.clone();
    stale[91 * 4096 + 2] |= 1 << 4; // Previously free record20, header unchanged.
    assert!(ntfs_inspect::read_plain_stream(&mut Cursor::new(&stale), &raw, 23, 16384).is_err());
    assert!(
        ntfs2refs::ntfs_backup::verify(&mut Cursor::new(&stale), stale.len() as u64, &raw).is_err()
    );
    let mut forged = raw.clone();
    let mft = forged
        .attribute_assemblies
        .iter_mut()
        .find(|a| a.base.record_number == 0)
        .unwrap();
    let mut bitmap = hex::decode(mft.mft_bitmap_hex.as_ref().unwrap()).unwrap();
    bitmap[2] |= 1 << 4;
    mft.mft_bitmap_hex = Some(hex::encode(bitmap));
    assert!(ntfs_inspect::validate_record_coverage(&forged).is_err());
    let mut missing = raw.clone();
    missing
        .attribute_assemblies
        .retain(|a| a.base.record_number != 0);
    missing.records_scanned -= 2;
    assert!(
        ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &missing, 23, 16384).is_err()
    );
}

fn list_disk_attribute(kind: u32, lcn: u16, logical: u64, clusters: u8) -> Vec<u8> {
    let [low, high] = lcn.to_le_bytes();
    support::nonresident(
        kind,
        &[0x21, clusters, low, high, 0],
        logical,
        u64::from(clusters),
    )
}

// 132 normal 32-byte entries require 4,224 bytes, across two nonadjacent
// clusters. All 129 extension records belong to the one logical user file.
fn nonresident_list_fixture() -> (Vec<u8>, Vec<u8>) {
    let mut image = assembly_fixture(16, [17, 18], 12288, 12288);
    image.resize(4 * 1024 * 1024, 0);
    p64(&mut image, 40, 8192);
    p64(&mut image, 56, 350);
    let mut mft_bitmap = vec![0u8; 146usize.div_ceil(8)];
    for n in [0, 1, 3, 5, 6, 7, 9, 10, 16].into_iter().chain(17..146) {
        mft_bitmap[n / 8] |= 1 << (n % 8);
    }
    put_record(
        &mut image,
        0,
        &[
            list_disk_attribute(0x80, 4, 146 * 1024, 37),
            support::resident(0xb0, "", &mft_bitmap, 1),
            filename("$MFT", 2),
            assembly_si(100, false),
        ],
        false,
        1,
    );
    put_record(
        &mut image,
        1,
        &[
            list_disk_attribute(0x80, 350, 4096, 1),
            filename("$MFTMirr", 2),
            assembly_si(100, false),
        ],
        false,
        1,
    );
    let mut bitmap = vec![0u8; 128];
    for n in [0, 200, 350, 700, 702]
        .into_iter()
        .chain(4..41)
        .chain(128..160)
        .chain(224..289)
        .chain((0..130).map(|n| 400 + n * 2))
    {
        bitmap[n / 8] |= 1 << (n % 8);
    }
    put_record(
        &mut image,
        6,
        &[
            support::resident(0x80, "", &bitmap, 0),
            filename("$Bitmap", 1),
            assembly_si(100, false),
        ],
        false,
        1,
    );
    let mut list = Vec::new();
    let origins = [(0x10, 16, 0, 0), (0x30, 16, 0, 1), (0x80, 16, 0, 3)]
        .into_iter()
        .chain((1..130).map(|vcn| (0x80, 16 + vcn, vcn as u64, 0)));
    for (kind, number, vcn, instance) in origins {
        let mut entry = [0u8; 32];
        p32(&mut entry, 0, kind);
        p16(&mut entry, 4, 32);
        entry[7] = 26;
        p64(&mut entry, 8, vcn);
        p64(&mut entry, 16, (1 << 48) | number as u64);
        p16(&mut entry, 24, instance);
        list.extend_from_slice(&entry);
    }
    assert_eq!(list.len(), 4224);
    let mut list_attribute = support::nonresident(
        0x20,
        &[0x21, 1, 188, 2, 0x11, 1, 2, 0],
        list.len() as u64,
        2,
    );
    p16(&mut list_attribute, 14, 2);
    let mut data = list_disk_attribute(0x80, 400, 130 * 4096, 1);
    p16(&mut data, 14, 3);
    p64(&mut data, 40, 130 * 4096);
    put_record(
        &mut image,
        16,
        &[
            assembly_si(0, false),
            filename("hello.txt", 1),
            list_attribute,
            data,
        ],
        false,
        1,
    );
    let mut expected = Vec::new();
    for vcn in 0..130 {
        let lcn = 400 + vcn * 2;
        let byte = ((vcn * 37 + 11) % 251) as u8;
        image[lcn * 4096..(lcn + 1) * 4096].fill(byte);
        expected.extend(std::iter::repeat_n(byte, 4096));
        if vcn > 0 {
            let mut data = list_disk_attribute(0x80, lcn as u16, 0, 1);
            p64(&mut data, 16, vcn as u64);
            p64(&mut data, 24, vcn as u64);
            for at in [40, 48, 56] {
                p64(&mut data, at, u64::MAX);
            }
            let mut extension = support::record(&[data], 1, 0);
            p64(&mut extension, 32, (1 << 48) | 16);
            let number = 16 + vcn;
            image[MFT + number * 1024..MFT + (number + 1) * 1024].copy_from_slice(&extension);
        }
    }
    image[700 * 4096..701 * 4096].copy_from_slice(&list[..4096]);
    image[702 * 4096..702 * 4096 + 128].copy_from_slice(&list[4096..]);
    image[702 * 4096 + 128..703 * 4096].fill(0xa5);
    (image, expected)
}

#[test]
fn assembled_data_conserves_physical_records_and_feeds_the_ordinary_shadow() {
    use ntfs2refs::{ntfs_inspect::LogicalHashStatus, ntfs_stream_plan, shadow_tree};
    use sha2::{Digest, Sha256};
    for (base, extensions) in [(16, [17, 18]), (19, [16, 17])] {
        let image = assembly_fixture(base, extensions, 3 * 4096, 3 * 4096);
        let raw = inspect(&image);
        assert_eq!(raw.attribute_assemblies.len(), 1);
        assert_eq!(raw.records_scanned, raw.files.len() as u64 + 2);
        ntfs_inspect::validate_record_coverage(&raw).unwrap();
        assert!(
            extensions
                .iter()
                .all(|n| !raw.files.iter().any(|f| f.record_number == *n as u64))
        );
        assert_eq!(
            raw.namespace_reconciliation.as_ref().unwrap().status,
            Status::ConsistentRawModel
        );
        assert_eq!(
            raw.allocation_reconciliation.as_ref().unwrap().status,
            AllocationReconciliationStatus::ConsistentRawModel
        );
        assert_eq!(
            raw.security_reconciliation.as_ref().unwrap().status,
            ntfs2refs::ntfs_security::Status::ConsistentRawModel
        );
        let file = raw
            .files
            .iter()
            .find(|f| f.record_number == base as u64)
            .unwrap();
        assert_eq!(file.streams.len(), 1);
        assert_eq!(file.streams[0].extents.len(), 3);
        assert_eq!(
            file.streams[0].logical_hash_status,
            LogicalHashStatus::Complete
        );
        let expected = [vec![0x31; 4096], vec![0x72; 4096], vec![0xc3; 4096]].concat();
        assert_eq!(
            file.streams[0].logical_sha256.as_deref(),
            Some(n2r_win32::content_digest::of(&expected).as_str())
        );
        assert_eq!(
            ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &raw, base as u64, 16384)
                .unwrap(),
            expected
        );
        let tree = shadow_tree::derive_ordinary(&raw).unwrap();
        assert_eq!(tree.objects.len(), 2);
        let plan = ntfs_stream_plan::classify(&raw);
        assert_eq!(plan.streams.len(), 1);
        assert_eq!(plan.retained_candidate_bytes, 12288);
        for at in [0, 4090, 8190] {
            assert_eq!(
                ntfs_inspect::hash_plain_stream_range(
                    &mut Cursor::new(&image),
                    &raw,
                    base as u64,
                    at,
                    32,
                    16384
                )
                .unwrap(),
                hex::encode(Sha256::digest(&expected[at as usize..at as usize + 32]))
            );
        }
    }
}

#[test]
fn assembled_data_keeps_vdl_zeroes_and_rejects_changed_segments_and_missing_ledgers() {
    let image = assembly_fixture(16, [17, 18], 8192 + 37, 4096 + 100);
    let raw = inspect(&image);
    let mut expected = vec![0; 8192 + 37];
    expected[..4096].fill(0x31);
    expected[4096..4196].fill(0x72);
    assert_eq!(
        ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &raw, 16, 16384).unwrap(),
        expected
    );
    for (offset, bit) in [
        (MFT + 17 * 1024 + 16, 1),
        (MFT + 18 * 1024 + 56 + 40, 1),
        (attribute(&image, 16, 0x20) + 24 + 3 * 32 + 24, 1),
        (100 * 4096, 1),
    ] {
        let mut changed = image.clone();
        changed[offset] ^= bit;
        assert!(
            ntfs_inspect::read_plain_stream(&mut Cursor::new(&changed), &raw, 16, 16384).is_err()
        );
    }
    let mut missing = raw.clone();
    missing.attribute_assemblies.clear();
    assert!(ntfs_inspect::validate_record_coverage(&missing).is_err());
    assert!(ntfs2refs::shadow_tree::derive_ordinary(&missing).is_err());
    let mut shared = raw.clone();
    shared
        .attribute_assemblies
        .push(shared.attribute_assemblies[0].clone());
    assert!(ntfs_inspect::validate_record_coverage(&shared).is_err());
    assert!(ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &shared, 16, 16384).is_err());
}
#[test]
fn actual_mft_allocation_and_unclaimed_extensions_still_block_qualification() {
    let image = assembly_fixture(16, [17, 18], 12288, 12288);
    let raw = inspect(&image);
    let bitmap = attribute(&image, 0, 0xb0);
    let value = bitmap
        + usize::from(u16::from_le_bytes(
            image[bitmap + 20..bitmap + 22].try_into().unwrap(),
        ));
    for number in [16, 17, 18] {
        let mut changed = image.clone();
        changed[value + number / 8] &= !(1 << (number % 8));
        assert!(
            ntfs_inspect::read_plain_stream(&mut Cursor::new(&changed), &raw, 16, 16384).is_err()
        );
        if let Ok(unqualified) =
            ntfs_inspect::inspect(&mut Cursor::new(&changed), changed.len() as u64)
        {
            // A missing base can remain a diagnostic orphan/index disagreement;
            // a diagnostic report is never equivalent to source admission.
            assert_ne!(
                unqualified
                    .allocation_reconciliation
                    .as_ref()
                    .unwrap()
                    .status,
                AllocationReconciliationStatus::ConsistentRawModel
            );
            assert!(ntfs2refs::shadow_tree::derive_ordinary(&unqualified).is_err());
        }
    }
    let mut orphan = image.clone();
    orphan[value + 2] |= 1 << 3;
    let mut segment = support::record(
        &[support::nonresident(0x80, &[0x11, 1, 106, 0], 4096, 1)],
        1,
        0,
    );
    p64(&mut segment, 32, (1 << 48) | 16);
    orphan[MFT + 19 * 1024..MFT + 20 * 1024].copy_from_slice(&segment);
    let unresolved = inspect(&orphan);
    assert_eq!(
        unresolved.records_scanned,
        unresolved.files.len() as u64 + 2
    );
    assert_eq!(
        unresolved
            .allocation_reconciliation
            .as_ref()
            .unwrap()
            .status,
        AllocationReconciliationStatus::IncompleteAttributeInventory
    );
    assert!(ntfs2refs::shadow_tree::derive_ordinary(&unresolved).is_err());
    // Forged counters cannot admit an actual list lacking its physical ledger.
    let mut counterfeit = raw.clone();
    counterfeit.attribute_assemblies.clear();
    counterfeit.records_scanned = counterfeit.files.len() as u64;
    assert!(
        ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &counterfeit, 16, 16384).is_err()
    );
}

#[test]
fn assembled_stream_agrees_with_independent_native_retrieval_page_replay() {
    use n2r_win32::{
        attestation::{IoctlQuery, Query, StreamCapture, StreamQuery},
        stream_layout,
    };
    let image = assembly_fixture(16, [17, 18], 12288, 12288);
    let raw = inspect(&image);
    let file = raw.files.iter().find(|f| f.record_number == 16).unwrap();
    let mut id = vec![0; 24];
    p64(&mut id, 0, raw.geometry.serial_number);
    p64(&mut id, 8, 16 | (1 << 48));
    let identity = Query {
        class: 18,
        bytes: id,
        native_error: None,
    };
    let name: Vec<_> = "::$DATA".encode_utf16().collect();
    let mut enumeration = vec![0; 24 + name.len() * 2];
    p32(&mut enumeration, 4, (name.len() * 2) as u32);
    p64(&mut enumeration, 8, 12288);
    p64(&mut enumeration, 16, 12288);
    for (i, unit) in name.iter().enumerate() {
        p16(&mut enumeration, 24 + i * 2, *unit);
    }
    fn page(start: u64, rows: &[(u64, u64)], error: Option<i32>) -> IoctlQuery {
        let mut bytes = vec![0; 16 + rows.len() * 16];
        p32(&mut bytes, 0, rows.len() as u32);
        p64(&mut bytes, 8, start);
        for (i, (next, lcn)) in rows.iter().enumerate() {
            p64(&mut bytes, 16 + 16 * i, *next);
            p64(&mut bytes, 24 + 16 * i, *lcn);
        }
        IoctlQuery {
            code: stream_layout::GET_RETRIEVAL,
            input: start.to_le_bytes().to_vec(),
            bytes,
            native_error: error,
        }
    }
    let mut native = StreamCapture {
        enumeration: Query {
            class: 7,
            bytes: enumeration,
            native_error: None,
        },
        parse_error: None,
        streams: vec![StreamQuery {
            name_utf16: vec![],
            logical_size: 12288,
            allocated_size: 12288,
            open_error: None,
            binding_error: None,
            identity_before: Some(identity.clone()),
            identity_after: Some(identity),
            retrieval: Some(page(0, &[(1, 100)], Some(234))),
            retrieval_continuation: vec![page(1, &[(2, 102), (3, 104)], None)],
        }],
    };
    ntfs2refs::ntfs_stream_attestation::check_file(file, &native, 0, &raw.geometry).unwrap();
    native.streams[0].retrieval_continuation[0] = page(1, &[(2, 103), (3, 104)], None);
    assert!(
        ntfs2refs::ntfs_stream_attestation::check_file(file, &native, 0, &raw.geometry).is_err()
    );
    native.streams[0].retrieval_continuation.clear();
    assert!(
        ntfs2refs::ntfs_stream_attestation::check_file(file, &native, 0, &raw.geometry).is_err()
    );
}

#[test]
fn nonresident_list_storage_is_accounted_once_and_all_segments_reconstruct() {
    let (image, expected) = nonresident_list_fixture();
    let raw = inspect(&image);
    assert_eq!(raw.attribute_assemblies.len(), 1);
    assert_eq!(raw.attribute_assemblies[0].schema_version, 2);
    assert_eq!(raw.attribute_assemblies[0].extensions.len(), 129);
    assert_eq!(raw.records_scanned, raw.files.len() as u64 + 129);
    ntfs_inspect::validate_record_coverage(&raw).unwrap();
    let allocation = raw.allocation_reconciliation.as_ref().unwrap();
    assert_eq!(
        allocation.status,
        AllocationReconciliationStatus::ConsistentRawModel
    );
    assert_eq!(allocation.physical_intervals, 138); // 6 system + 130 DATA + 2 LIST.
    assert_eq!(raw.allocated_clusters, Some(269));
    assert_eq!(
        raw.namespace_reconciliation.as_ref().unwrap().status,
        Status::ConsistentRawModel
    );
    assert_eq!(
        raw.security_reconciliation.as_ref().unwrap().status,
        ntfs2refs::ntfs_security::Status::ConsistentRawModel
    );
    assert_eq!(
        ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &raw, 16, 1024 * 1024).unwrap(),
        expected
    );
    assert_eq!(
        ntfs2refs::shadow_tree::derive_ordinary(&raw)
            .unwrap()
            .objects
            .len(),
        2
    );
    assert_eq!(
        ntfs2refs::ntfs_stream_plan::classify(&raw).retained_candidate_bytes,
        expected.len() as u64
    );

    let mut changed = image.clone();
    changed[702 * 4096 + 26] ^= 1;
    assert!(
        ntfs_inspect::read_plain_stream(&mut Cursor::new(&changed), &raw, 16, 1024 * 1024).is_err()
    );
    let mut slack = image.clone();
    slack[702 * 4096 + 500] ^= 1;
    assert_eq!(
        ntfs_inspect::read_plain_stream(&mut Cursor::new(&slack), &raw, 16, 1024 * 1024).unwrap(),
        expected
    );
    let mut old_schema = raw.clone();
    old_schema.attribute_assemblies[0].schema_version = 1;
    assert!(ntfs_inspect::validate_record_coverage(&old_schema).is_err());
}

#[test]
fn unallocated_nonresident_list_metadata_is_not_treated_as_free_space() {
    let (mut image, _) = nonresident_list_fixture();
    let bitmap = attribute(&image, 6, 0x80);
    let value = bitmap
        + usize::from(u16::from_le_bytes(
            image[bitmap + 20..bitmap + 22].try_into().unwrap(),
        ));
    image[value + 702 / 8] &= !(1 << (702 % 8));
    let raw = inspect(&image);
    assert_eq!(
        raw.allocation_reconciliation.as_ref().unwrap().status,
        AllocationReconciliationStatus::Rejected
    );
    assert!(ntfs2refs::shadow_tree::derive_ordinary(&raw).is_err());
}

#[test]
fn incomplete_nonresident_list_is_refused_before_any_list_payload_read() {
    use std::io::{Read, Seek, SeekFrom};
    struct Guard {
        inner: Cursor<Vec<u8>>,
        attempts: usize,
    }
    impl Read for Guard {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let start = self.inner.position();
            let end = start + out.len() as u64;
            if [700u64, 702]
                .iter()
                .any(|cluster| start < (cluster + 1) * 4096 && end > cluster * 4096)
            {
                self.attempts += 1;
                return Err(std::io::Error::other(
                    "List payload read was forbidden by the fixture",
                ));
            }
            self.inner.read(out)
        }
    }
    impl Seek for Guard {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }
    let (mut image, _) = nonresident_list_fixture();
    let list = attribute(&image, 16, 0x20);
    p64(&mut image, list + 56, 4223);
    let length = image.len() as u64;
    let mut guarded = Guard {
        inner: Cursor::new(image),
        attempts: 0,
    };
    assert!(ntfs_inspect::inspect(&mut guarded, length).is_err());
    assert_eq!(guarded.attempts, 0);
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
