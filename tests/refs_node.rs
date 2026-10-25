use ntfs2refs::refs_node::inspect_root_node;
use sha2::{Digest, Sha256};

const NODE: usize = 0x278;
const FIRST: usize = NODE + 40;
const SECOND: usize = FIRST + 64;
const INDEX: usize = 16376;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn fixture(table: u64, index_node: bool) -> Vec<u8> {
    let mut page = vec![0; 16384];
    page[..4].copy_from_slice(b"MSB+");
    put32(&mut page, 4, 2);
    put64(&mut page, 0x48, table);
    put32(&mut page, 0x50, (NODE - 0x50) as u32);
    put16(&mut page, 0x54, 0x28);
    put16(&mut page, 0x56, if table == 34 { 0xe010 } else { 0 });
    put32(&mut page, 0x5c, if table == 34 { 0xe010 } else { 0xe0c0 });
    put64(&mut page, 0x68, 10);
    put64(&mut page, 0x70, if index_node { 832 } else { 2 });
    page[0x90] = 0x7b; // retained unknown extension byte
    put32(&mut page, NODE, 40);
    page[NODE + 0xc] = u8::from(index_node);
    page[NODE + 0xd] = if index_node { 3 } else { 0xe };
    put32(&mut page, NODE + 0x10, (INDEX - NODE) as u32);
    put32(&mut page, NODE + 0x14, 2);
    put32(&mut page, NODE + 0x20, (INDEX + 8 - NODE) as u32);
    for (row, fill) in [(FIRST, 0x3a), (SECOND, 0x6c)] {
        put32(&mut page, row, 64);
        put16(&mut page, row + 4, 16);
        put16(&mut page, row + 6, 16);
        put16(&mut page, row + 8, 0x102);
        put16(&mut page, row + 10, 16);
        put16(&mut page, row + 12, 48);
        put16(&mut page, row + 14, 0x304);
        page[row + 16..row + 64].fill(fill);
    }
    // Deliberately reverse the physical order: index order is independent.
    put16(&mut page, INDEX, (SECOND - NODE) as u16);
    put16(&mut page, INDEX + 2, 1);
    put16(&mut page, INDEX + 4, (FIRST - NODE) as u16);
    put16(&mut page, INDEX + 6, 0x3fdd);
    page
}

#[test]
fn observes_all_three_profiles_with_separate_table_and_node_counts() {
    for table in [11, 12, 34] {
        let page = fixture(table, table != 34);
        let before = page.clone();
        let node = inspect_root_node(&page).unwrap();
        assert_eq!(page, before);
        assert_eq!(node.table_id_low, table);
        assert_eq!(node.schema_id, if table == 34 { 0xe010 } else { 0xe0c0 });
        assert_eq!(node.node_offset, NODE);
        assert_eq!(node.node_row_count, 2);
        assert_eq!(
            node.whole_table_row_count,
            if table == 34 { 2 } else { 832 }
        );
        assert_eq!(node.root_descriptor_size, 0x28);
        assert_eq!(
            node.root_descriptor_auxiliary,
            if table == 34 { 0xe010 } else { 0 }
        );
        assert_eq!(node.node_level, u8::from(table != 34));
        assert_eq!(node.index_node, table != 34);
        assert_eq!(node.page_sha256, hex::encode(Sha256::digest(&page)));
        assert_eq!(
            hex::decode(node.root_region_bytes_hex).unwrap(),
            page[0x50..NODE]
        );
        assert_eq!(
            hex::decode(node.node_header_bytes_hex).unwrap(),
            page[NODE..NODE + 40]
        );
        assert!(!node.children_traversed);
        assert!(
            !node.metadata_verified
                && !node.checksum_verified
                && !node.conversion_profile_qualified
        );
    }
}

#[test]
fn preserves_row_index_order_markers_unknown_fields_and_overlapping_key_value() {
    let page = fixture(34, false);
    let node = inspect_root_node(&page).unwrap();
    assert_eq!(
        node.rows
            .iter()
            .map(|row| row.page_offset)
            .collect::<Vec<_>>(),
        [SECOND, FIRST]
    );
    assert_eq!(
        node.rows.iter().map(|row| row.marker).collect::<Vec<_>>(),
        [1, 0x3fdd]
    );
    for row in node.rows {
        assert!(row.key_value_overlap);
        assert_eq!(row.reserved_at_8, 0x102);
        assert_eq!(row.reserved_at_14, 0x304);
        let raw = &page[row.page_offset..row.page_offset + row.size as usize];
        assert_eq!(row.row_bytes_hex, hex::encode(raw));
        assert_eq!(row.row_sha256, hex::encode(Sha256::digest(raw)));
        assert_eq!(row.key_sha256, hex::encode(Sha256::digest(&raw[16..32])));
        assert_eq!(row.value_sha256, hex::encode(Sha256::digest(&raw[16..64])));
    }
}

#[test]
fn permits_empty_keys_values_and_unknown_markers_without_following_them() {
    for marker in [0, 1, 0xffff, 0xcdc5] {
        let mut page = fixture(11, true);
        put16(&mut page, INDEX + 2, marker);
        put16(&mut page, SECOND + 4, 0);
        put16(&mut page, SECOND + 6, 0);
        put16(&mut page, SECOND + 10, 0);
        put16(&mut page, SECOND + 12, 0);
        let node = inspect_root_node(&page).unwrap();
        assert_eq!(node.rows[0].marker, marker);
        assert_eq!(node.rows[0].key_sha256, hex::encode(Sha256::digest([])));
        assert_eq!(node.rows[0].value_sha256, hex::encode(Sha256::digest([])));
        assert!(!node.rows[0].key_value_overlap && !node.children_traversed);
    }
}

#[test]
fn zero_row_node_requires_consistent_empty_index_and_keeps_table_count_raw() {
    let mut page = fixture(34, false);
    put32(&mut page, NODE + 0x14, 0);
    put32(&mut page, NODE + 0x20, (INDEX - NODE) as u32);
    let node = inspect_root_node(&page).unwrap();
    assert!(node.rows.is_empty());
    assert_eq!(node.whole_table_row_count, 2); // no table completeness assertion
}

#[test]
fn refuses_wrong_lengths_signatures_versions_table_ids_and_schemas() {
    let page = fixture(11, true);
    for length in [0, 4, 80, 4096, 16383] {
        assert!(inspect_root_node(&page[..length]).is_err());
    }
    let mut extended = page.clone();
    extended.push(0);
    assert!(inspect_root_node(&extended).is_err());
    for (offset, value) in [
        (0, 0),
        (4, 3),
        (0x40, 1),
        (0x48, 2),
        (0x54, 0x30),
        (0x5c, 0xe010),
    ] {
        let mut changed = page.clone();
        put32(&mut changed, offset, value);
        assert!(inspect_root_node(&changed).is_err(), "offset {offset:x}");
    }
}

#[test]
fn refuses_node_header_and_index_bounds_count_overflow_and_excess_work() {
    for offset in [0, 0x27, 16384 - 0x50 - 20, u32::MAX] {
        let mut page = fixture(11, true);
        put32(&mut page, 0x50, offset);
        assert!(inspect_root_node(&page).is_err(), "node offset {offset:x}");
    }
    for (start, end, count) in [
        (0, 8, 2),
        (100, 99, 0),
        (100, 108, 3),
        (100, 107, 2),
        (100, 1128, 257),
        (100, 104, u32::MAX),
        (16384, 16392, 2),
        (u32::MAX - 8, u32::MAX, 2),
    ] {
        let mut page = fixture(11, true);
        put32(&mut page, NODE + 0x10, start);
        put32(&mut page, NODE + 0x20, end);
        put32(&mut page, NODE + 0x14, count);
        assert!(
            inspect_root_node(&page).is_err(),
            "index {start} {end} {count}"
        );
    }
}

#[test]
fn refuses_duplicate_overlapping_and_out_of_page_rows() {
    for scenario in [
        "duplicate",
        "overlap",
        "index_overlap",
        "header",
        "outside",
        "overflow",
        "small",
    ] {
        let mut page = fixture(11, true);
        match scenario {
            "duplicate" => put16(&mut page, INDEX + 4, (SECOND - NODE) as u16),
            "overlap" => put32(&mut page, FIRST, 80),
            "index_overlap" => put32(&mut page, FIRST, (16384 - FIRST) as u32),
            "header" => put16(&mut page, INDEX, 39),
            "outside" => put16(&mut page, INDEX, u16::MAX),
            "overflow" => put32(&mut page, SECOND, u32::MAX),
            "small" => put32(&mut page, SECOND, 15),
            _ => unreachable!(),
        }
        assert!(inspect_root_node(&page).is_err(), "{scenario}");
    }
}

#[test]
fn refuses_key_or_value_header_overlap_and_out_of_row_bounds() {
    for (field, offset, length) in [
        (4, 0, 1),
        (4, 64, 1),
        (4, u16::MAX, 2),
        (10, 15, 1),
        (10, 63, 2),
    ] {
        let mut page = fixture(34, false);
        put16(&mut page, SECOND + field, offset);
        put16(&mut page, SECOND + field + 2, length);
        assert!(inspect_root_node(&page).is_err());
    }
    let mut page = fixture(34, false);
    put16(&mut page, SECOND + 4, 65);
    put16(&mut page, SECOND + 6, 0);
    assert!(inspect_root_node(&page).is_err());
}

#[test]
fn level_and_index_flag_must_agree_without_guessing_other_flags() {
    for (level, flags) in [(0, 1), (1, 0)] {
        let mut page = fixture(11, true);
        page[NODE + 0xc] = level;
        page[NODE + 0xd] = flags;
        assert!(inspect_root_node(&page).is_err());
    }
    let mut page = fixture(11, true);
    page[NODE + 0xd] = 0xfd;
    assert_eq!(inspect_root_node(&page).unwrap().node_flags, 0xfd);
}

#[test]
#[ignore = "requires N2R_NATIVE_REFS_CORPUS; reads only pinned inspection and three 16 KiB raw ranges"]
fn native_roots_match_full_capture_page_hashes_and_observed_structure() {
    use std::io::{Read, Seek, SeekFrom};
    let corpus = std::path::PathBuf::from(
        std::env::var_os("N2R_NATIVE_REFS_CORPUS").expect("explicit native corpus directory"),
    );
    let evidence =
        std::fs::read(corpus.join("analysis-20261023T233638844Z/inspection.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&evidence)),
        "5a3bee79702c3c68bfa281786090e4000bf437f2e7574892c5a6714edfc16ece"
    );
    let report: serde_json::Value = serde_json::from_slice(&evidence).unwrap();
    assert_eq!(
        report["source"]["sha256"],
        "805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9"
    );
    let roots = report["filesystem"]["details"]["bootstrap"]["physical_root_pages"]
        .as_array()
        .unwrap();
    assert_eq!(roots.len(), 3);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut source = options.open(corpus.join("devdrive.raw")).unwrap();
    assert!(source.metadata().unwrap().is_file());
    assert_eq!(source.metadata().unwrap().len(), 55834574848);
    let expected_hashes = [
        "73dc2c6545e33d81a51dec1cc712cdd499acf17983d91b7f4112c219b244e8e0",
        "46c12725ebaa3e0785b562f02e8fc23e9b07fb2680fb8cb4e647d75924e3583f",
        "4e79061385cca3fcd2e0f24067e5c18023e7569fcd80608aaa292b531c187c6a",
    ];
    let mut bytes_read = 0;
    for (index, root) in roots.iter().enumerate() {
        let mut page = [0; 16384];
        for (slot, offset) in root["byte_offsets"].as_array().unwrap().iter().enumerate() {
            source
                .seek(SeekFrom::Start(offset.as_u64().unwrap()))
                .unwrap();
            source
                .read_exact(&mut page[slot * 4096..(slot + 1) * 4096])
                .unwrap();
            bytes_read += 4096;
        }
        let hash = hex::encode(Sha256::digest(page));
        assert_eq!(hash, expected_hashes[index]);
        assert_eq!(hash, root["sha256"].as_str().unwrap());
        let node = inspect_root_node(&page).unwrap();
        assert_eq!(node.node_offset, 0x278);
        assert_eq!(node.table_id_low, [11, 12, 34][index]);
        assert_eq!(node.whole_table_row_count, if index < 2 { 832 } else { 2 });
        assert_eq!(node.node_row_count, if index < 2 { 10 } else { 2 });
        assert_eq!(node.node_level, if index < 2 { 1 } else { 0 });
        assert_eq!(
            node.root_descriptor_auxiliary,
            if index < 2 { 0 } else { 0xe010 }
        );
        if index < 2 {
            assert_eq!(node.rows[9].key_length, 0);
            assert_eq!(node.rows[9].marker, 0);
        } else {
            assert_eq!(
                node.rows.iter().map(|row| row.marker).collect::<Vec<_>>(),
                [1, 0x3fdd]
            );
            assert!(node.rows.iter().all(|row| row.key_value_overlap));
        }
        assert!(
            !node.children_traversed
                && !node.metadata_verified
                && !node.checksum_verified
                && !node.conversion_profile_qualified
        );
    }
    assert_eq!(bytes_read, 3 * 16384);
}

#[test]
#[ignore = "requires N2R_NATIVE_REFS_CORPUS; reads one pinned Medium Allocator root page"]
fn native_medium_allocator_root_has_bounded_index_structure() {
    use std::io::{Read, Seek, SeekFrom};
    let corpus = std::path::PathBuf::from(
        std::env::var_os("N2R_NATIVE_REFS_CORPUS").expect("explicit native corpus directory"),
    );
    let mut source = std::fs::File::open(corpus.join("devdrive.raw")).unwrap();
    assert_eq!(source.metadata().unwrap().len(), 55834574848);
    let mut page = [0u8; 16384];
    source.seek(SeekFrom::Start(290816 * 4096)).unwrap();
    source.read_exact(&mut page).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(page)),
        "071733eddb05f09fe37cb70d9365fe4249f1e5a266c7e02c4efdfb990205a161"
    );
    let node = inspect_root_node(&page).unwrap();
    assert_eq!(node.table_id_low, 33);
    assert_eq!(node.schema_id, 0xe010);
    assert_eq!(node.whole_table_row_count, 23);
    assert_eq!(node.node_level, 1);
    assert_eq!(node.node_row_count, 2);
    assert!(node.index_node);
}
