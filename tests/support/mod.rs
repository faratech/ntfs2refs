//! Minimal synthetic NTFS corpus; never a native-format acceptance image.
fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn align8(n: usize) -> usize {
    (n + 7) & !7
}

pub fn boot() -> [u8; 512] {
    boot_geometry(512, 1024)
}

/// The boot sector of the 2 MiB synthetic volume, of 4 KiB clusters, for a
/// sector and FILE record size.
pub fn boot_geometry(sector: u16, record: u32) -> [u8; 512] {
    assert!(record.is_power_of_two() && sector.is_power_of_two());
    let mut b = [0u8; 512];
    b[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    b[3..11].copy_from_slice(b"NTFS    ");
    put16(&mut b, 11, sector);
    b[13] = (4096 / u32::from(sector)) as u8;
    put64(&mut b, 40, (2 * 1024 * 1024) / u64::from(sector));
    put64(&mut b, 48, 4);
    put64(&mut b, 56, 30);
    b[64] = (-(record.trailing_zeros() as i8)) as u8;
    b[68] = 1;
    put64(&mut b, 72, 0x1122_3344_5566_7788);
    b[510..].copy_from_slice(&[0x55, 0xaa]);
    b
}

pub fn resident(ty: u32, name: &str, value: &[u8], instance: u16) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let value_at = align8(24 + name.len() * 2);
    let mut a = vec![0; align8(value_at + value.len())];
    let size = a.len() as u32;
    put32(&mut a, 0, ty);
    put32(&mut a, 4, size);
    a[9] = name.len() as u8;
    put16(&mut a, 10, 24);
    put16(&mut a, 14, instance);
    put32(&mut a, 16, value.len() as u32);
    put16(&mut a, 20, value_at as u16);
    for (i, unit) in name.iter().enumerate() {
        put16(&mut a, 24 + i * 2, *unit);
    }
    a[value_at..value_at + value.len()].copy_from_slice(value);
    a
}

pub fn nonresident(ty: u32, runs: &[u8], logical_size: u64, clusters: u64) -> Vec<u8> {
    let mut a = vec![0; align8(64 + runs.len())];
    let size = a.len() as u32;
    put32(&mut a, 0, ty);
    put32(&mut a, 4, size);
    a[8] = 1;
    put64(&mut a, 24, clusters.wrapping_sub(1));
    put16(&mut a, 32, 64);
    put64(&mut a, 40, clusters * 4096);
    put64(&mut a, 48, logical_size);
    put64(&mut a, 56, logical_size);
    a[64..64 + runs.len()].copy_from_slice(runs);
    a
}

fn filename(name: &str, instance: u16) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let mut v = vec![0; 66 + name.len() * 2];
    put64(&mut v, 0, 5 | (1u64 << 48));
    v[64] = name.len() as u8;
    v[65] = 1;
    for (i, unit) in name.iter().enumerate() {
        put16(&mut v, 66 + i * 2, *unit);
    }
    resident(0x30, "", &v, instance)
}

pub fn record(attrs: &[Vec<u8>], flags: u16, links: u16) -> Vec<u8> {
    record_sized(attrs, flags, links, 1024)
}

/// A FILE record of `size` bytes, its update sequence array applied: one
/// word for every 512 bytes, whatever the sector size.
pub fn record_sized(attrs: &[Vec<u8>], flags: u16, links: u16, size: usize) -> Vec<u8> {
    let entries = size / 512 + 1;
    let first = align8(48 + entries * 2);
    let mut b = vec![0; size];
    b[..4].copy_from_slice(b"FILE");
    put16(&mut b, 4, 48);
    put16(&mut b, 6, entries as u16);
    put16(&mut b, 16, 1);
    put16(&mut b, 18, links);
    put16(&mut b, 20, first as u16);
    put16(&mut b, 22, flags);
    put32(&mut b, 28, size as u32);
    let mut at = first;
    for a in attrs {
        b[at..at + a.len()].copy_from_slice(a);
        at += a.len();
    }
    put32(&mut b, at, u32::MAX);
    put32(&mut b, 24, (at + 8) as u32);
    put16(&mut b, 48, 0xabcd);
    for i in 1..entries {
        let tail = i * 512 - 2;
        let old = [b[tail], b[tail + 1]];
        b[48 + i * 2..50 + i * 2].copy_from_slice(&old);
        put16(&mut b, tail, 0xabcd);
    }
    b
}

pub fn image() -> Vec<u8> {
    image_geometry(512, 1024)
}

/// Clusters the synthetic MFT takes: twenty records.
pub fn mft_clusters(record: usize) -> usize {
    (20 * record).div_ceil(4096)
}

/// The synthetic volume for a sector and FILE record size: the same files,
/// with the MFT at cluster 4 holding twenty records of that size.
pub fn image_geometry(sector: u16, record: usize) -> Vec<u8> {
    let mut image = vec![0u8; 2 * 1024 * 1024];
    image[..512].copy_from_slice(&boot_geometry(sector, record as u32));
    let clusters = mft_clusters(record);
    let mft = record_sized(
        &[
            nonresident(
                0x80,
                &[0x11, clusters as u8, 4, 0],
                (20 * record) as u64,
                clusters as u64,
            ),
            resident(0xb0, "", &[0x69, 0, 1], 1),
        ],
        1,
        1,
        record,
    );
    let mut vi = [0u8; 12];
    vi[8] = 3;
    vi[9] = 1;
    let volume = record_sized(&[resident(0x70, "", &vi, 0)], 1, 1, record);
    let root = record_sized(&[filename(".", 0)], 3, 1, record);
    let mut bitmap = [0u8; 64];
    for cluster in [0, 30, 100].into_iter().chain(4..4 + clusters) {
        bitmap[cluster / 8] |= 1 << (cluster % 8);
    }
    let bitmap_record = record_sized(&[resident(0x80, "", &bitmap, 0)], 1, 1, record);
    let mut si = [0u8; 72];
    put64(&mut si, 0, 1234);
    put32(&mut si, 32, 0x20);
    put32(&mut si, 52, 256);
    let user = record_sized(
        &[
            resident(0x10, "", &si, 0),
            filename("hello.txt", 1),
            filename("alias.txt", 2),
            nonresident(0x80, &[0x11, 1, 100, 0], 17, 1),
            resident(0x80, "note", b"metadata", 4),
        ],
        1,
        2,
        record,
    );
    for (number, bytes) in [
        (0usize, mft),
        (3, volume),
        (5, root),
        (6, bitmap_record),
        (16, user),
    ] {
        let at = 4 * 4096 + number * record;
        image[at..at + record].copy_from_slice(&bytes);
    }
    image[100 * 4096..100 * 4096 + 17].copy_from_slice(b"Synthetic content");
    image
}
