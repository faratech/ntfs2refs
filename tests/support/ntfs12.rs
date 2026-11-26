//! A synthetic NTFS 1.2 (Windows NT 4.0) volume, laid out as NT 4.0's
//! format lays one out, for the converter's tests and for the lab, where it
//! is written onto an empty partition to find out what Windows makes of it.
//!
//! What makes it 1.2 rather than 3.x: `$Volume` states 1.2; there is no
//! `$Extend` and no `$Secure` (record 9 is `$Quota`, records 11 to 15 are
//! reserved); every file carries its own `$SECURITY_DESCRIPTOR` (0x50);
//! `$STANDARD_INFORMATION` is the 48-byte form, without owner, security,
//! quota or USN fields; FILE records have the old header (update sequence
//! array at 0x2a, no record number, first attribute at 0x30); `$AttrDef`
//! has NT 4.0's fifteen definitions ($VOLUME_VERSION at 0x40,
//! $SYMBOLIC_LINK at 0xc0, $PROPERTY_SET at 0xf0); `$LogFile` is all 0xff,
//! as a format leaves it for NTFS to initialize.
//!
//! Geometry: 512-byte sectors, 4 KiB clusters, 1 KiB FILE records, 4 KiB
//! index records. Sources for the layout: ntfs-3g `layout.h` (MFT_RECORD_OLD,
//! STANDARD_INFORMATION's NTFS 1.2 form, the 1.2 attribute types) and
//! Microsoft's MFT structure notes (learn.microsoft.com/windows/win32/devnotes/
//! master-file-table). Not a format Windows made: a fixture.

const SECTOR: u64 = 512;
pub const CLUSTER: u64 = 4096;
pub const RECORD: usize = 1024;
const INDEX: usize = 4096;
/// Records in $MFT (sixteen clusters).
pub const MFT_RECORDS: usize = 64;
const MFT_LCN: u64 = 4;
const MIRROR_LCN: u64 = 2;
/// $MFT's $BITMAP: nonresident, as Windows requires of it (a resident one
/// makes Windows refuse record 0 as corrupt, NTFS event 55), in its own
/// cluster as ntfs-3g's mkntfs places it.
const MFT_BITMAP_LCN: u64 = 3;
const LOG_LCN: u64 = 20;
const LOG_CLUSTERS: u64 = 1024;
const ATTRDEF_LCN: u64 = LOG_LCN + LOG_CLUSTERS;
const UPCASE_LCN: u64 = ATTRDEF_LCN + 1;
const BITMAP_LCN: u64 = UPCASE_LCN + 32;
/// 2000-01-01T00:00:00Z.
const TIME: u64 = 125_911_584_000_000_000;

/// The files in the root besides NTFS's own, and in `SUB`.
pub const README: &[u8] = b"Written as NTFS 1.2 (Windows NT 4.0) lays a volume out.\r\n";
pub const BIG_BYTES: usize = 10_000;

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
fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// The content of a big file, recognizable in every byte.
pub fn big_content() -> Vec<u8> {
    (0..BIG_BYTES).map(|i| (i * 7 + 3) as u8).collect()
}

/// One self-relative descriptor for every file: owner and group
/// BUILTIN\Administrators, a DACL granting Everyone full control.
pub fn descriptor() -> Vec<u8> {
    let mut b = vec![0u8; 80];
    b[0] = 1;
    put16(&mut b, 2, 0x8004);
    put32(&mut b, 4, 20);
    put32(&mut b, 8, 36);
    put32(&mut b, 16, 52);
    for at in [20, 36] {
        // S-1-5-32-544
        b[at] = 1;
        b[at + 1] = 2;
        b[at + 7] = 5;
        put32(&mut b, at + 8, 32);
        put32(&mut b, at + 12, 544);
    }
    // ACL: revision 2, size 28, one ACE.
    b[52] = 2;
    put16(&mut b, 54, 28);
    put16(&mut b, 56, 1);
    // ACCESS_ALLOWED, size 20, FILE_ALL_ACCESS, S-1-1-0.
    put16(&mut b, 62, 20);
    put32(&mut b, 64, 0x001f_01ff);
    b[68] = 1;
    b[69] = 1;
    b[75] = 1;
    b
}

fn resident(type_code: u32, name: &str, value: &[u8], instance: u16, indexed: bool) -> Vec<u8> {
    let name = utf16(name);
    let value_at = align8(24 + name.len() * 2);
    let mut a = vec![0u8; align8(value_at + value.len())];
    let size = a.len() as u32;
    put32(&mut a, 0, type_code);
    put32(&mut a, 4, size);
    a[9] = name.len() as u8;
    put16(&mut a, 10, 24);
    put16(&mut a, 14, instance);
    put32(&mut a, 16, value.len() as u32);
    put16(&mut a, 20, value_at as u16);
    a[22] = u8::from(indexed);
    for (i, unit) in name.iter().enumerate() {
        put16(&mut a, 24 + i * 2, *unit);
    }
    a[value_at..value_at + value.len()].copy_from_slice(value);
    a
}

/// Mapping pairs for runs of (lcn or None for a hole, clusters).
fn mapping(runs: &[(Option<u64>, u64)]) -> Vec<u8> {
    fn bytes_signed(n: i64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = n;
        loop {
            out.push(v as u8);
            let done = (v >> 7) == 0 || (v >> 7) == -1;
            v >>= 8;
            if done {
                break;
            }
        }
        out
    }
    fn bytes_unsigned(n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = n;
        loop {
            out.push(v as u8);
            v >>= 8;
            if v == 0 {
                break;
            }
        }
        out
    }
    let mut out = Vec::new();
    let mut previous = 0i64;
    for &(lcn, clusters) in runs {
        let length = bytes_unsigned(clusters);
        let offset = match lcn {
            Some(lcn) => {
                let delta = bytes_signed(lcn as i64 - previous);
                previous = lcn as i64;
                delta
            }
            None => Vec::new(),
        };
        out.push((length.len() as u8) | ((offset.len() as u8) << 4));
        out.extend(length);
        out.extend(offset);
    }
    out.push(0);
    out
}

fn nonresident(
    type_code: u32,
    name: &str,
    runs: &[(Option<u64>, u64)],
    data_bytes: u64,
    instance: u16,
) -> Vec<u8> {
    let name = utf16(name);
    let clusters: u64 = runs.iter().map(|run| run.1).sum();
    let pairs = mapping(runs);
    let name_at = 64;
    let runs_at = align8(name_at + name.len() * 2);
    let mut a = vec![0u8; align8(runs_at + pairs.len())];
    let size = a.len() as u32;
    put32(&mut a, 0, type_code);
    put32(&mut a, 4, size);
    a[8] = 1;
    a[9] = name.len() as u8;
    // As Windows writes it, even with no name.
    put16(&mut a, 10, name_at as u16);
    put16(&mut a, 14, instance);
    put64(&mut a, 24, clusters.saturating_sub(1));
    put16(&mut a, 32, runs_at as u16);
    put64(&mut a, 40, clusters * CLUSTER);
    put64(&mut a, 48, data_bytes);
    put64(&mut a, 56, data_bytes);
    for (i, unit) in name.iter().enumerate() {
        put16(&mut a, name_at + i * 2, *unit);
    }
    a[runs_at..runs_at + pairs.len()].copy_from_slice(&pairs);
    a
}

/// $STANDARD_INFORMATION in its NTFS 1.2 form: 48 bytes.
fn standard_information(attributes: u32) -> Vec<u8> {
    let mut v = vec![0u8; 48];
    for at in [0, 8, 16, 24] {
        put64(&mut v, at, TIME);
    }
    put32(&mut v, 32, attributes);
    resident(0x10, "", &v, 0, false)
}

/// A $FILE_NAME value, in the Win32-and-DOS namespace (every name here is
/// an upper-case 8.3 name, or one of NTFS's own).
fn file_name_value(parent: u64, name: &str, allocated: u64, data: u64, flags: u32) -> Vec<u8> {
    let name = utf16(name);
    let mut v = vec![0u8; 66 + name.len() * 2];
    put64(&mut v, 0, parent);
    for at in [8, 16, 24, 32] {
        put64(&mut v, at, TIME);
    }
    put64(&mut v, 40, allocated);
    put64(&mut v, 48, data);
    put32(&mut v, 56, flags);
    v[64] = name.len() as u8;
    v[65] = 3;
    for (i, unit) in name.iter().enumerate() {
        put16(&mut v, 66 + i * 2, *unit);
    }
    v
}

/// A FILE record in the NTFS 1.2/3.0 header form, its fixups applied.
fn file_record(sequence: u16, links: u16, flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; RECORD];
    let entries = RECORD / 512 + 1;
    let usa = 0x2a;
    let first = align8(usa + entries * 2);
    b[..4].copy_from_slice(b"FILE");
    put16(&mut b, 4, usa as u16);
    put16(&mut b, 6, entries as u16);
    put16(&mut b, 16, sequence);
    put16(&mut b, 18, links);
    put16(&mut b, 20, first as u16);
    put16(&mut b, 22, flags);
    put32(&mut b, 28, RECORD as u32);
    let mut at = first;
    for attribute in attributes {
        b[at..at + attribute.len()].copy_from_slice(attribute);
        at += attribute.len();
    }
    put32(&mut b, at, u32::MAX);
    put32(&mut b, 24, (at + 8) as u32);
    put16(&mut b, 0x28, attributes.len() as u16);
    protect(&mut b, usa, 1);
    b
}

/// Applies a structure's update sequence array, sequence number `usn`.
fn protect(b: &mut [u8], usa: usize, usn: u16) {
    let entries = b.len() / 512 + 1;
    put16(b, usa, usn);
    for i in 1..entries {
        let tail = i * 512 - 2;
        let saved = [b[tail], b[tail + 1]];
        b[usa + i * 2..usa + i * 2 + 2].copy_from_slice(&saved);
        put16(b, tail, usn);
    }
}

fn reference(record: u64, sequence: u16) -> u64 {
    record | (u64::from(sequence) << 48)
}

/// The sequence number of each record: NTFS's own files have their record
/// number (the $MFT 1), ordinary ones 1.
fn sequence(record: u64) -> u16 {
    if (1..16).contains(&record) {
        record as u16
    } else {
        1
    }
}

/// An index entry for a $FILE_NAME key.
fn index_entry(file: u64, key: &[u8]) -> Vec<u8> {
    let mut e = vec![0u8; align8(16 + key.len())];
    put64(&mut e, 0, file);
    let length = e.len() as u16;
    put16(&mut e, 8, length);
    put16(&mut e, 10, key.len() as u16);
    e[16..16 + key.len()].copy_from_slice(key);
    e
}
fn end_entry(subnode: Option<u64>) -> Vec<u8> {
    let mut e = vec![0u8; if subnode.is_some() { 24 } else { 16 }];
    let length = e.len() as u16;
    put16(&mut e, 8, length);
    put16(&mut e, 12, if subnode.is_some() { 3 } else { 2 });
    if let Some(vcn) = subnode {
        put64(&mut e, 16, vcn);
    }
    e
}

/// An $INDEX_ROOT $I30 value holding `entries` (already in collation
/// order, the end entry last).
fn index_root(entries: &[u8], large: bool) -> Vec<u8> {
    let mut v = vec![0u8; 32 + entries.len()];
    put32(&mut v, 0, 0x30);
    put32(&mut v, 4, 1);
    put32(&mut v, 8, INDEX as u32);
    v[12] = (INDEX as u64 / CLUSTER) as u8;
    put32(&mut v, 16, 16);
    put32(&mut v, 20, 16 + entries.len() as u32);
    put32(&mut v, 24, 16 + entries.len() as u32);
    v[28] = u8::from(large);
    v[32..].copy_from_slice(entries);
    v
}

/// One INDX record (VCN 0, a leaf) holding `entries`.
fn index_block(entries: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; INDEX];
    let count = INDEX / 512 + 1;
    let usa = 0x28;
    let first = align8(usa + count * 2);
    b[..4].copy_from_slice(b"INDX");
    put16(&mut b, 4, usa as u16);
    put16(&mut b, 6, count as u16);
    put32(&mut b, 0x18, (first - 0x18) as u32);
    put32(&mut b, 0x1c, (first - 0x18 + entries.len()) as u32);
    put32(&mut b, 0x20, (INDEX - 0x18) as u32);
    b[first..first + entries.len()].copy_from_slice(entries);
    protect(&mut b, usa, 1);
    b
}

/// A $UpCase table: each UTF-16 unit's single upper-case mapping, where it
/// has one that is itself unchanged by upper-casing.
pub fn upcase() -> Vec<u16> {
    let mut table: Vec<u16> = (0..=0xffffu32).map(|c| c as u16).collect();
    for c in 0..=0xffffu32 {
        let Some(ch) = char::from_u32(c) else {
            continue;
        };
        let mut upper = ch.to_uppercase();
        if let (Some(u), None) = (upper.next(), upper.next())
            && (u as u32) <= 0xffff
        {
            table[c as usize] = u as u16;
        }
    }
    for c in 0..table.len() {
        if table[usize::from(table[c])] != table[c] {
            table[c] = c as u16;
        }
    }
    table
}

/// NT 4.0's fifteen attribute definitions: (name, type, flags, minimum,
/// maximum); $FILE_NAME collates as file names, the rest as binary.
fn attrdef() -> Vec<u8> {
    const NONE: u64 = u64::MAX;
    let rows: [(&str, u32, u32, u64, u64); 15] = [
        ("$STANDARD_INFORMATION", 0x10, 0x40, 0x30, 0x30),
        ("$ATTRIBUTE_LIST", 0x20, 0x80, 0, NONE),
        ("$FILE_NAME", 0x30, 0x42, 0x44, 0x242),
        ("$VOLUME_VERSION", 0x40, 0x40, 8, 8),
        ("$SECURITY_DESCRIPTOR", 0x50, 0x80, 0, NONE),
        ("$VOLUME_NAME", 0x60, 0x40, 2, 0x100),
        ("$VOLUME_INFORMATION", 0x70, 0x40, 0xc, 0xc),
        ("$DATA", 0x80, 0, 0, NONE),
        ("$INDEX_ROOT", 0x90, 0x40, 0, NONE),
        ("$INDEX_ALLOCATION", 0xa0, 0x80, 0, NONE),
        ("$BITMAP", 0xb0, 0x80, 0, NONE),
        ("$SYMBOLIC_LINK", 0xc0, 0x80, 0, NONE),
        ("$EA_INFORMATION", 0xd0, 0x40, 8, 8),
        ("$EA", 0xe0, 0, 0, 0x10000),
        ("$PROPERTY_SET", 0xf0, 0, 0, NONE),
    ];
    let mut out = vec![0u8; rows.len() * 0xa0];
    for (i, (name, kind, flags, minimum, maximum)) in rows.iter().enumerate() {
        let at = i * 0xa0;
        for (j, unit) in utf16(name).iter().enumerate() {
            put16(&mut out, at + j * 2, *unit);
        }
        put32(&mut out, at + 0x80, *kind);
        put32(&mut out, at + 0x88, u32::from(*kind == 0x30));
        put32(&mut out, at + 0x8c, *flags);
        put64(&mut out, at + 0x90, *minimum);
        put64(&mut out, at + 0x98, *maximum);
    }
    out
}

/// The volume: `head` (everything up to the last cluster in use) and the
/// backup boot sector, which goes in the partition's last sector.
pub struct Volume {
    pub partition_bytes: u64,
    pub head: Vec<u8>,
    pub backup_boot: Vec<u8>,
    pub total_clusters: u64,
}

impl Volume {
    /// The whole partition, for a test.
    pub fn image(&self) -> Vec<u8> {
        let mut image = vec![0u8; self.partition_bytes as usize];
        image[..self.head.len()].copy_from_slice(&self.head);
        let at = self.partition_bytes as usize - SECTOR as usize;
        image[at..].copy_from_slice(&self.backup_boot);
        image
    }
}

/// An NTFS 1.2 volume filling a partition of `partition_bytes` that starts
/// `hidden_sectors` sectors into its disk.
pub fn volume(partition_bytes: u64, hidden_sectors: u32, version: (u8, u8)) -> Volume {
    assert!(partition_bytes.is_multiple_of(CLUSTER) && partition_bytes >= 8 * 1024 * 1024);
    let total_sectors = partition_bytes / SECTOR - 1;
    let total_clusters = total_sectors * SECTOR / CLUSTER;
    let bitmap_bytes = (total_clusters.div_ceil(8)).next_multiple_of(8);
    let bitmap_clusters = bitmap_bytes.div_ceil(CLUSTER);
    let root_index_lcn = BITMAP_LCN + bitmap_clusters;
    let big_lcn = root_index_lcn + 1;
    let big_clusters = (BIG_BYTES as u64).div_ceil(CLUSTER);
    let used_end = big_lcn + big_clusters;
    let mut head = vec![0u8; (used_end * CLUSTER) as usize];
    let cluster_at = |lcn: u64| (lcn * CLUSTER) as usize;

    // The boot sector (and $Boot's first of sixteen sectors).
    let mut boot = vec![0u8; SECTOR as usize];
    boot[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    boot[3..11].copy_from_slice(b"NTFS    ");
    put16(&mut boot, 11, SECTOR as u16);
    boot[13] = (CLUSTER / SECTOR) as u8;
    boot[0x15] = 0xf8;
    put16(&mut boot, 0x18, 63);
    put16(&mut boot, 0x1a, 255);
    put32(&mut boot, 0x1c, hidden_sectors);
    put32(&mut boot, 0x24, 0x0080_0080);
    put64(&mut boot, 0x28, total_sectors);
    put64(&mut boot, 0x30, MFT_LCN);
    put64(&mut boot, 0x38, MIRROR_LCN);
    boot[0x40] = (-10i8) as u8;
    boot[0x44] = (INDEX as u64 / CLUSTER) as u8;
    put64(&mut boot, 0x48, 0x1234_5678_9abc_def0);
    boot[510] = 0x55;
    boot[511] = 0xaa;
    head[..SECTOR as usize].copy_from_slice(&boot);

    let sd = descriptor();
    let security = |instance| resident(0x50, "", &sd, instance, false);
    let root = reference(5, 5);
    let hidden_system = 0x06;
    // (name, record, allocated, data) of each file NTFS keeps for itself, in the root.
    let mft_bytes = (MFT_RECORDS * RECORD) as u64;
    let upcase_bytes = 0x20000u64;
    let attrdef_bytes = attrdef().len() as u64;
    let log_bytes = LOG_CLUSTERS * CLUSTER;
    let system: [(&str, u64, u64, u64); 10] = [
        ("$MFT", 0, mft_bytes, mft_bytes),
        ("$MFTMirr", 1, CLUSTER, CLUSTER),
        ("$LogFile", 2, log_bytes, log_bytes),
        ("$Volume", 3, 0, 0),
        ("$AttrDef", 4, CLUSTER, attrdef_bytes),
        ("$Bitmap", 6, bitmap_clusters * CLUSTER, bitmap_bytes),
        ("$Boot", 7, 2 * CLUSTER, 2 * CLUSTER),
        ("$BadClus", 8, 0, 0),
        ("$Quota", 9, 0, 0),
        ("$UpCase", 10, 32 * CLUSTER, upcase_bytes),
    ];
    let name_of = |name: &str, allocated, data, flags| {
        resident(
            0x30,
            "",
            &file_name_value(root, name, allocated, data, flags),
            1,
            true,
        )
    };
    let mut records: Vec<(u64, Vec<u8>)> = Vec::new();
    for &(name, number, allocated, data) in &system {
        let mut fname = name_of(name, allocated, data, hidden_system);
        let mut descriptor = security(2);
        if number == 8 {
            // As Windows numbers $BadClus's attributes: $Bad is instance 1.
            put16(&mut fname, 14, 3);
            put16(&mut descriptor, 14, 4);
        }
        let mut attributes = vec![standard_information(hidden_system), fname, descriptor];
        match number {
            0 => {
                attributes.push(nonresident(
                    0x80,
                    "",
                    &[(Some(MFT_LCN), mft_bytes / CLUSTER)],
                    mft_bytes,
                    3,
                ));
                let bits_at = cluster_at(MFT_BITMAP_LCN);
                for record in 0..20 {
                    head[bits_at + record / 8] |= 1 << (record % 8);
                }
                attributes.push(nonresident(
                    0xb0,
                    "",
                    &[(Some(MFT_BITMAP_LCN), 1)],
                    (MFT_RECORDS / 8) as u64,
                    4,
                ));
            }
            1 => attributes.push(nonresident(0x80, "", &[(Some(MIRROR_LCN), 1)], CLUSTER, 3)),
            2 => attributes.push(nonresident(
                0x80,
                "",
                &[(Some(LOG_LCN), LOG_CLUSTERS)],
                log_bytes,
                3,
            )),
            3 => {
                let label: Vec<u8> = utf16("NT4VOL")
                    .iter()
                    .flat_map(|u| u.to_le_bytes())
                    .collect();
                attributes.push(resident(0x60, "", &label, 3, false));
                let mut info = [0u8; 12];
                info[8] = version.0;
                info[9] = version.1;
                attributes.push(resident(0x70, "", &info, 4, false));
                attributes.push(resident(0x80, "", &[], 5, false));
            }
            4 => attributes.push(nonresident(
                0x80,
                "",
                &[(Some(ATTRDEF_LCN), 1)],
                attrdef_bytes,
                3,
            )),
            6 => attributes.push(nonresident(
                0x80,
                "",
                &[(Some(BITMAP_LCN), bitmap_clusters)],
                bitmap_bytes,
                3,
            )),
            7 => attributes.push(nonresident(0x80, "", &[(Some(0), 2)], 2 * CLUSTER, 3)),
            8 => {
                attributes.push(resident(0x80, "", &[], 2, false));
                // Sparse over the whole volume, nothing initialized: no bad clusters.
                let mut bad = nonresident(
                    0x80,
                    "$Bad",
                    &[(None, total_clusters)],
                    total_clusters * CLUSTER,
                    1,
                );
                put64(&mut bad, 56, 0);
                attributes.push(bad);
            }
            9 => attributes.push(resident(0x80, "", &[], 3, false)),
            10 => attributes.push(nonresident(
                0x80,
                "",
                &[(Some(UPCASE_LCN), 32)],
                upcase_bytes,
                3,
            )),
            _ => unreachable!(),
        }
        records.push((number, file_record(sequence(number), 1, 1, &attributes)));
    }

    // The user files: README.TXT, BIG.BIN, SUB\INNER.TXT.
    let big = big_content();
    let user = |parent: u64, name: &str, data: Vec<u8>, size: u64, allocated| {
        let fname = resident(
            0x30,
            "",
            &file_name_value(parent, name, allocated, size, 0x20),
            1,
            true,
        );
        file_record(
            1,
            1,
            1,
            &[standard_information(0x20), fname, security(2), data],
        )
    };
    let readme = user(
        root,
        "README.TXT",
        resident(0x80, "", README, 3, false),
        README.len() as u64,
        align8(README.len()) as u64,
    );
    let big_record = user(
        root,
        "BIG.BIN",
        nonresident(
            0x80,
            "",
            &[(Some(big_lcn), big_clusters)],
            BIG_BYTES as u64,
            3,
        ),
        BIG_BYTES as u64,
        big_clusters * CLUSTER,
    );
    let sub = reference(18, 1);
    let inner = b"Inside a directory of an NTFS 1.2 volume.\r\n";
    let inner_record = user(
        sub,
        "INNER.TXT",
        resident(0x80, "", inner, 3, false),
        inner.len() as u64,
        align8(inner.len()) as u64,
    );
    let directory_flags = 0x1000_0000;
    let sub_entries = [
        index_entry(
            reference(19, 1),
            &file_name_value(
                sub,
                "INNER.TXT",
                align8(inner.len()) as u64,
                inner.len() as u64,
                0x20,
            ),
        ),
        end_entry(None),
    ]
    .concat();
    let sub_record = file_record(
        1,
        1,
        3,
        &[
            standard_information(0),
            resident(
                0x30,
                "",
                &file_name_value(root, "SUB", 0, 0, directory_flags),
                1,
                true,
            ),
            security(2),
            resident(0x90, "$I30", &index_root(&sub_entries, false), 3, false),
        ],
    );

    // The root: every name, in collation order, in one INDX block.
    let mut names: Vec<(String, u64, Vec<u8>)> = system
        .iter()
        .map(|&(name, number, allocated, data)| {
            (
                name.to_owned(),
                reference(number, sequence(number)),
                file_name_value(root, name, allocated, data, hidden_system),
            )
        })
        .collect();
    names.push((
        ".".into(),
        root,
        file_name_value(root, ".", 0, 0, hidden_system | directory_flags),
    ));
    names.push((
        "README.TXT".into(),
        reference(16, 1),
        file_name_value(
            root,
            "README.TXT",
            align8(README.len()) as u64,
            README.len() as u64,
            0x20,
        ),
    ));
    names.push((
        "BIG.BIN".into(),
        reference(17, 1),
        file_name_value(
            root,
            "BIG.BIN",
            big_clusters * CLUSTER,
            BIG_BYTES as u64,
            0x20,
        ),
    ));
    names.push((
        "SUB".into(),
        sub,
        file_name_value(root, "SUB", 0, 0, directory_flags),
    ));
    let table = upcase();
    names.sort_by(|a, b| {
        let key = |s: &str| -> Vec<u16> {
            utf16(s)
                .into_iter()
                .map(|u| table[usize::from(u)])
                .collect()
        };
        key(&a.0).cmp(&key(&b.0))
    });
    let mut root_entries = Vec::new();
    for (_, file, key) in &names {
        root_entries.extend(index_entry(*file, key));
    }
    root_entries.extend(end_entry(None));
    let block = index_block(&root_entries);
    head[cluster_at(root_index_lcn)..cluster_at(root_index_lcn) + INDEX].copy_from_slice(&block);
    let root_record = file_record(
        5,
        1,
        3,
        &[
            standard_information(hidden_system),
            resident(
                0x30,
                "",
                &file_name_value(root, ".", 0, 0, hidden_system | directory_flags),
                1,
                true,
            ),
            security(2),
            resident(
                0x90,
                "$I30",
                &index_root(&end_entry(Some(0)), true),
                3,
                false,
            ),
            nonresident(0xa0, "$I30", &[(Some(root_index_lcn), 1)], INDEX as u64, 4),
            resident(0xb0, "$I30", &[1, 0, 0, 0, 0, 0, 0, 0], 5, false),
        ],
    );
    records.push((5, root_record));
    // Records 11 to 15: reserved, in use, nameless.
    for number in 11..16 {
        records.push((
            number,
            file_record(
                sequence(number),
                0,
                1,
                &[
                    standard_information(hidden_system),
                    security(1),
                    resident(0x80, "", &[], 2, false),
                ],
            ),
        ));
    }
    records.push((16, readme));
    records.push((17, big_record));
    records.push((18, sub_record));
    records.push((19, inner_record));
    // Every other record: formatted, not in use.
    for number in 20..MFT_RECORDS as u64 {
        records.push((number, file_record(0, 0, 0, &[])));
    }
    let mft_at = cluster_at(MFT_LCN);
    for (number, bytes) in &records {
        let at = mft_at + *number as usize * RECORD;
        head[at..at + RECORD].copy_from_slice(bytes);
    }
    // $MFTMirr: records 0 to 3.
    let mirror_at = cluster_at(MIRROR_LCN);
    let mirrored = head[mft_at..mft_at + 4 * RECORD].to_vec();
    head[mirror_at..mirror_at + 4 * RECORD].copy_from_slice(&mirrored);
    // $LogFile: as a format leaves it.
    head[cluster_at(LOG_LCN)..cluster_at(LOG_LCN + LOG_CLUSTERS)].fill(0xff);
    // $AttrDef and $UpCase.
    let definitions = attrdef();
    head[cluster_at(ATTRDEF_LCN)..cluster_at(ATTRDEF_LCN) + definitions.len()]
        .copy_from_slice(&definitions);
    for (i, unit) in table.iter().enumerate() {
        put16(&mut head, cluster_at(UPCASE_LCN) + i * 2, *unit);
    }
    // $Bitmap: every cluster in use, and none past the volume's last.
    // $Boot (0-1), $MFTMirr (2), $MFT's bitmap (3), then everything else.
    let mut used = vec![(0u64, 4u64), (MFT_LCN, used_end - MFT_LCN)];
    used.sort();
    let bitmap_at = cluster_at(BITMAP_LCN);
    for (start, count) in used {
        for cluster in start..start + count {
            head[bitmap_at + (cluster / 8) as usize] |= 1 << (cluster % 8);
        }
    }
    head[cluster_at(big_lcn)..cluster_at(big_lcn) + BIG_BYTES].copy_from_slice(&big);
    Volume {
        partition_bytes,
        head,
        backup_boot: boot,
        total_clusters,
    }
}
