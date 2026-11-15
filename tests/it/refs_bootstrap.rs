use ntfs2refs::{
    refs_bootstrap::{crc32c, crc64_nvme, encode_crc64_sentinel, inspect, vbr_checksum},
    refs_inspect::inspect_boot_sector,
};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

const CLUSTER: usize = 4096;
const VOLUME: usize = CLUSTER * 128;
const SIGNATURE: u32 = 0x04030201;
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn make_header(bytes: &mut [u8], signature: &[u8; 4], lcn: u64) {
    bytes[..4].copy_from_slice(signature);
    put32(bytes, 4, 2);
    put32(bytes, 0x0c, SIGNATURE);
    put64(bytes, 0x20, lcn);
}
fn make_self_checksum(bytes: &mut [u8], descriptor: usize, lcn: u64) {
    bytes[descriptor..descriptor + 48].fill(0);
    let checksum = crc32c(&bytes[..CLUSTER]);
    put64(bytes, descriptor, lcn);
    bytes[descriptor + 0x22] = 1;
    bytes[descriptor + 0x23] = 8;
    put32(bytes, descriptor + 0x24, 4);
    put32(bytes, descriptor + 0x28, checksum);
}
fn fixture(indirect: bool) -> Vec<u8> {
    let mut image = vec![0_u8; VOLUME];
    let header = &mut image[..512];
    header[3..11].copy_from_slice(b"ReFS\0\0\0\0");
    header[16..20].copy_from_slice(b"FSRS");
    put16(header, 20, 512);
    put64(header, 24, (VOLUME / 512) as u64);
    put32(header, 32, 512);
    put32(header, 36, 8);
    header[40] = 3;
    header[41] = 14;
    put16(header, 42, 2);
    put32(header, 44, 0x66);
    let checksum = vbr_checksum(header).unwrap();
    put16(header, 22, checksum);
    for lcn in [30, 126, 125] {
        let bytes = &mut image[lcn * CLUSTER..(lcn + 1) * CLUSTER];
        make_header(bytes, b"SUPB", lcn as u64);
        put32(bytes, 0x50, SIGNATURE);
        put64(bytes, 0x68, 1);
        put32(bytes, 0x70, 0xc0);
        put32(bytes, 0x74, 2);
        put32(bytes, 0x78, 0xd0);
        put32(bytes, 0x7c, 48);
        put64(bytes, 0xc0, 40);
        put64(bytes, 0xc8, 44);
        make_self_checksum(bytes, 0xd0, lcn as u64);
    }
    for lcn in [40, 44] {
        let bytes = &mut image[lcn * CLUSTER..(lcn + 4) * CLUSTER];
        make_header(bytes, b"CHKP", lcn as u64);
        put64(bytes, 0x10, lcn as u64);
        put64(bytes, 0x60, lcn as u64);
        put64(bytes, 0x68, 30);
        put32(bytes, 0x50, 0xe0003);
        put16(bytes, 0x54, 3);
        put16(bytes, 0x56, 14);
        put32(bytes, 0x58, 0xe0);
        put32(bytes, 0x5c, 48);
        put32(bytes, 0x78, if indirect { 0x682 } else { 0x482 });
        put32(bytes, 0x90, 13);
        let list = if indirect {
            put32(bytes, 0x94, 0x380);
            0x380
        } else {
            0x94
        };
        for index in 0..13 {
            let descriptor = 0x110 + index * 48;
            put32(bytes, list + index * 4, descriptor as u32);
            for slot in 0..4 {
                put64(
                    bytes,
                    descriptor + slot * 8,
                    (200 + index * 4 + slot) as u64,
                );
            }
            bytes[descriptor + 0x22] = 2;
            bytes[descriptor + 0x23] = 8;
            put32(bytes, descriptor + 0x24, 8);
            put64(bytes, descriptor + 0x28, 0x100 + index as u64);
        }
        make_self_checksum(bytes, 0xe0, lcn as u64);
    }
    image
}
fn probe(image: Vec<u8>) -> ntfs2refs::refs_bootstrap::BootstrapProbe {
    let vbr = image[..512].to_vec();
    let geometry = inspect_boot_sector(&vbr, image.len() as u64).unwrap();
    inspect(&mut Cursor::new(image), &geometry, &vbr)
        .unwrap()
        .unwrap()
}

#[test]
fn checksum_vectors_and_recognition_exclusions() {
    assert_eq!(crc32c(b"123456789"), 0xe3069283);
    assert_eq!(crc32c(b""), 0);
    let mut vbr = [0_u8; 512];
    vbr[511] = 1;
    assert_eq!(vbr_checksum(&vbr).unwrap(), 1);
    vbr[510] = 1;
    assert_eq!(vbr_checksum(&vbr).unwrap(), 0x8001);
    let prior = vbr_checksum(&vbr).unwrap();
    vbr[..3].fill(255);
    vbr[22..24].fill(255);
    assert_eq!(vbr_checksum(&vbr).unwrap(), prior);
    assert!(vbr_checksum(&vbr[..511]).is_err());
}
#[test]
fn reports_all_copies_and_both_root_encodings_without_selecting() {
    for indirect in [false, true] {
        let report = probe(fixture(indirect));
        assert!(report.vbr_checksum_matches);
        assert_eq!(report.superblocks.len(), 3);
        assert_eq!(report.checkpoints.len(), 2);
        for anchor in report.superblocks.iter().chain(report.checkpoints.iter()) {
            assert!(anchor.rejection.is_none(), "{:?}", anchor.rejection);
            assert!(anchor.self_checksum.as_ref().unwrap().matches);
            assert_eq!(
                anchor.self_checksum.as_ref().unwrap().coverage_bytes,
                CLUSTER
            );
            assert_eq!(anchor.sha256.len(), 64);
        }
        for anchor in &report.checkpoints {
            assert_eq!(anchor.referenced_by_superblock_lcns.len(), 3);
            let fields = anchor.checkpoint.as_ref().unwrap();
            assert_eq!(fields.indirect_root_list, indirect);
            assert_eq!(fields.roots.len(), 13);
            assert!(fields.header_clock_matches);
            assert!(fields.roots.iter().all(|root| !root.addressed_page_read));
            assert_eq!(fields.roots[12].lcn_slots, [248, 249, 250, 251]);
        }
        assert!(!report.authoritative_checkpoint_selected && !report.metadata_verified);
    }
}
#[test]
fn vbr_mismatch_stops_anchor_reads() {
    let mut image = fixture(true);
    image[80] ^= 1;
    let report = probe(image);
    assert!(!report.vbr_checksum_matches);
    assert!(report.superblocks.is_empty() && report.checkpoints.is_empty());
}
#[test]
fn damaged_superblocks_never_supply_followed_pointers() {
    let mut image = fixture(true);
    for lcn in [30, 126, 125] {
        image[lcn * CLUSTER + 0x100] ^= 1;
    }
    let report = probe(image);
    assert!(
        report.superblocks.iter().all(|candidate| !candidate
            .self_checksum
            .as_ref()
            .unwrap()
            .matches)
    );
    assert!(report.checkpoints.is_empty());
}
#[test]
fn corrupt_primary_does_not_hide_other_candidates_or_choose_winner() {
    let mut image = fixture(true);
    image[30 * CLUSTER] = 0;
    let report = probe(image);
    assert!(report.superblocks[0].rejection.is_some());
    assert_eq!(report.checkpoints.len(), 2);
    assert_eq!(report.checkpoints[0].referenced_by_superblock_lcns.len(), 2);
    assert!(!report.authoritative_checkpoint_selected);
}
#[test]
fn malformed_superblock_offsets_counts_and_self_locations_are_bounded() {
    for (field, value) in [
        (0x70, u32::MAX),
        (0x74, u32::MAX),
        (0x78, u32::MAX),
        (0x7c, 72),
        (0x20, 31),
    ] {
        let mut image = fixture(true);
        put32(&mut image, 30 * CLUSTER + field, value);
        assert!(
            probe(image).superblocks[0].rejection.is_some(),
            "field {field:x}"
        );
    }
}
#[test]
fn overflowing_checkpoint_addresses_are_not_read() {
    let mut image = fixture(true);
    for lcn in [30, 126, 125] {
        let bytes = &mut image[lcn * CLUSTER..(lcn + 1) * CLUSTER];
        put64(bytes, 0xc0, u64::MAX);
        make_self_checksum(bytes, 0xd0, lcn as u64);
    }
    let report = probe(image);
    assert!(
        report
            .superblocks
            .iter()
            .all(|candidate| candidate.rejection.is_some())
    );
    assert!(report.checkpoints.is_empty());
}
#[test]
fn unsupported_self_checksum_is_observed_without_guessing() {
    let mut image = fixture(true);
    for lcn in [30, 126, 125] {
        image[lcn * CLUSTER + 0xd0 + 0x22] = 2;
    }
    let report = probe(image);
    assert!(
        report
            .superblocks
            .iter()
            .all(|candidate| candidate.self_checksum.is_none() && candidate.rejection.is_some())
    );
    assert!(report.checkpoints.is_empty());
}
#[test]
fn malformed_checkpoint_root_layouts_are_bounded() {
    for (field, value) in [
        (0x58, u32::MAX),
        (0x5c, 104),
        (0x90, u32::MAX),
        (0x94, u32::MAX),
        (0x380, u32::MAX),
        (0x380, 0xe0),
        (0x384, 0x110),
        (0x380, 0x380),
        (0x58, 0x88),
    ] {
        let mut image = fixture(true);
        put32(&mut image, 40 * CLUSTER + field, value);
        let report = probe(image);
        assert!(report.checkpoints[0].rejection.is_some(), "field {field:x}");
        assert!(report.checkpoints[0].checkpoint.is_none());
        assert!(report.checkpoints[1].rejection.is_none());
    }
}
#[test]
fn mismatch_of_header_and_checkpoint_clock_is_reported() {
    let mut image = fixture(true);
    let bytes = &mut image[40 * CLUSTER..44 * CLUSTER];
    put64(bytes, 0x60, 1);
    make_self_checksum(bytes, 0xe0, 40);
    let report = probe(image);
    assert!(
        !report.checkpoints[0]
            .checkpoint
            .as_ref()
            .unwrap()
            .header_clock_matches
    );
    assert!(!report.authoritative_checkpoint_selected);
}
struct TrackingReader {
    inner: Cursor<Vec<u8>>,
    max_read: usize,
    bytes_read: usize,
}
impl Read for TrackingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.max_read = self.max_read.max(buffer.len());
        let count = self.inner.read(buffer)?;
        self.bytes_read += count;
        Ok(count)
    }
}
impl Seek for TrackingReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}
#[test]
fn reads_only_bounded_anchors_and_propagates_truncation() {
    let image = fixture(true);
    let vbr = image[..512].to_vec();
    let geometry = inspect_boot_sector(&vbr, VOLUME as u64).unwrap();
    let mut reader = TrackingReader {
        inner: Cursor::new(image.clone()),
        max_read: 0,
        bytes_read: 0,
    };
    inspect(&mut reader, &geometry, &vbr).unwrap();
    assert_eq!(reader.max_read, 16384);
    assert_eq!(reader.bytes_read, 3 * CLUSTER + 2 * 16384);
    assert!(
        inspect(
            &mut Cursor::new(image[..VOLUME / 2].to_vec()),
            &geometry,
            &vbr
        )
        .is_err()
    );
}
#[test]
fn unsupported_profiles_do_not_probe_metadata() {
    let image = fixture(true);
    let vbr = image[..512].to_vec();
    let mut geometry = inspect_boot_sector(&vbr, VOLUME as u64).unwrap();
    geometry.bytes_per_cluster = 65536;
    assert!(
        inspect(&mut Cursor::new(Vec::<u8>::new()), &geometry, &vbr)
            .unwrap()
            .is_none()
    );
    geometry.bytes_per_cluster = 4096;
    geometry.minor_version = 10;
    assert!(
        inspect(&mut Cursor::new(Vec::<u8>::new()), &geometry, &vbr)
            .unwrap()
            .is_none()
    );
}

fn roots_fixture() -> Vec<u8> {
    let mut image = fixture(true);
    for (index, start, table) in [(7, 60, 0xb), (8, 64, 0xc), (12, 68, 0x22)] {
        let page = &mut image[start * CLUSTER..(start + 4) * CLUSTER];
        make_header(page, b"MSB+", start as u64);
        for slot in 0..4 {
            put64(page, 0x20 + slot * 8, (start + slot) as u64);
        }
        put64(page, 0x48, table);
        for (offset, byte) in page.iter_mut().enumerate().skip(0x80) {
            *byte = (offset % 251) as u8;
        }
        // A minimal empty root node; row bytes are tested independently.
        put32(page, 0x50, 0x30);
        put16(page, 0x54, 0x28);
        put16(page, 0x56, if table == 0x22 { 0xe010 } else { 0 });
        put32(page, 0x5c, if table == 0x22 { 0xe010 } else { 0xe0c0 });
        page[0x80..0xa8].fill(0);
        put32(page, 0x80, 40);
        page[0x8d] = 0xe;
        put32(page, 0x90, 16384 - 0x80);
        put32(page, 0xa0, 16384 - 0x80);
        let digest = crc64_nvme(page);
        for checkpoint in [40, 44] {
            let bytes = &mut image[checkpoint * CLUSTER..(checkpoint + 4) * CLUSTER];
            let descriptor = 0x110 + index * 48;
            for slot in 0..4 {
                put64(bytes, descriptor + slot * 8, (start + slot) as u64);
            }
            put64(bytes, descriptor + 0x28, digest);
            make_self_checksum(bytes, 0xe0, checkpoint as u64);
        }
    }
    image
}

fn change_root(image: &mut [u8], index: usize, change: impl Fn(&mut [u8])) {
    for checkpoint in [40, 44] {
        let bytes = &mut image[checkpoint * CLUSTER..(checkpoint + 4) * CLUSTER];
        let offset = 0x110 + index * 48;
        change(&mut bytes[offset..offset + 48]);
        make_self_checksum(bytes, 0xe0, checkpoint as u64);
    }
}

#[test]
fn crc64_nvme_check_vector_and_refs_sentinel() {
    assert_eq!(crc64_nvme(b"123456789"), 0xae8b14860a799888);
    assert_eq!(crc64_nvme(b""), 0);
    assert_eq!(
        encode_crc64_sentinel(0xabbaffffabbafffe),
        0xabbaffffabbaffff
    );
    assert_eq!(
        encode_crc64_sentinel(0xabbaffffabbaffff),
        0xabbaffffabbaffff
    );
    assert_eq!(encode_crc64_sentinel(17), 17);
}

#[test]
fn physical_roots_are_deduplicated_and_only_three_types_are_followed() {
    let image = roots_fixture();
    let vbr = image[..512].to_vec();
    let geometry = inspect_boot_sector(&vbr, VOLUME as u64).unwrap();
    let mut reader = TrackingReader {
        inner: Cursor::new(image),
        max_read: 0,
        bytes_read: 0,
    };
    let report = inspect(&mut reader, &geometry, &vbr).unwrap().unwrap();
    assert_eq!(report.physical_root_references.len(), 6);
    assert_eq!(report.physical_root_pages.len(), 3);
    assert_eq!(
        reader.bytes_read,
        3 * CLUSTER + 2 * 16384 + 3 * 16384 + 4 * 16384
    );
    for root in &report.physical_root_references {
        assert!(matches!(root.root_index, 7 | 8 | 12));
        assert_eq!(root.checksum_matches, Some(true));
        assert_eq!(root.header_matches, Some(true));
        assert_eq!(root.table_id_matches, Some(true));
        assert!(root.rejection.is_none());
    }
    for page in &report.physical_root_pages {
        assert_eq!(page.bytes_read, 16384);
        assert!(!page.children_traversed);
        assert_eq!(page.sha256.len(), 64);
        assert!(page.node_rejection.is_none());
        let node = page.node.as_ref().unwrap();
        assert!(node.rows.is_empty());
        assert!(!node.metadata_verified && !node.checksum_verified && !node.children_traversed);
    }
    for checkpoint in &report.checkpoints {
        for root in &checkpoint.checkpoint.as_ref().unwrap().roots {
            assert_eq!(root.addressed_page_read, matches!(root.index, 7 | 8 | 12));
        }
    }
    assert!(!report.metadata_verified && !report.authoritative_checkpoint_selected);
}

#[test]
fn malformed_node_is_a_separate_observation_even_with_matching_root_crc() {
    let mut image = roots_fixture();
    put16(&mut image, 60 * CLUSTER + 0x54, 0);
    let digest = crc64_nvme(&image[60 * CLUSTER..64 * CLUSTER]);
    change_root(&mut image, 7, |reference| put64(reference, 0x28, digest));
    let report = probe(image);
    let page = &report.physical_root_pages[0];
    assert!(page.node.is_none() && page.node_rejection.is_some());
    for reference in report
        .physical_root_references
        .iter()
        .filter(|root| root.root_index == 7)
    {
        assert_eq!(reference.checksum_matches, Some(true));
        assert!(reference.rejection.is_none());
    }
    assert!(!report.metadata_verified);
    let mut legacy = serde_json::to_value(page).unwrap();
    legacy.as_object_mut().unwrap().remove("node");
    legacy.as_object_mut().unwrap().remove("node_rejection");
    let restored: ntfs2refs::refs_bootstrap::PhysicalRootPage =
        serde_json::from_value(legacy).unwrap();
    assert!(restored.node.is_none() && restored.node_rejection.is_none());
}

#[test]
fn malformed_physical_reference_types_and_ranges_are_not_read() {
    for scenario in [
        "flags",
        "type",
        "offset",
        "length",
        "empty",
        "duplicate",
        "overflow",
        "outside",
        "anchor",
        "cross_root",
    ] {
        let mut image = roots_fixture();
        change_root(&mut image, 7, |reference| match scenario {
            "flags" => put16(reference, 0x20, 1),
            "type" => reference[0x22] = 4,
            "offset" => reference[0x23] = 9,
            "length" => put32(reference, 0x24, 32),
            "empty" => put64(reference, 0, 0),
            "duplicate" => put64(reference, 8, 60),
            "overflow" => put64(reference, 0, u64::MAX),
            "outside" => put64(reference, 0, 128),
            "anchor" => put64(reference, 0, 40),
            "cross_root" => put64(reference, 0, 64),
            _ => unreachable!(),
        });
        let report = probe(image);
        for root in report
            .physical_root_references
            .iter()
            .filter(|root| root.root_index == 7)
        {
            assert!(root.rejection.is_some(), "{scenario}");
            assert!(root.page_index.is_none(), "{scenario}");
        }
    }
}

#[test]
fn child_page_checksum_and_header_mismatches_remain_observations() {
    for (offset, value) in [
        (0, 0),
        (4, 3),
        (8, 1),
        (0xc, 0),
        (0x20, 61),
        (0x40, 1),
        (0x48, 0x22),
        (16000, 1),
    ] {
        let mut image = roots_fixture();
        image[60 * CLUSTER + offset] = value;
        let report = probe(image);
        for root in report
            .physical_root_references
            .iter()
            .filter(|root| root.root_index == 7)
        {
            assert!(root.page_index.is_some());
            assert!(root.rejection.is_some(), "offset {offset}");
        }
        assert!(!report.metadata_verified);
    }
}

#[test]
fn duplicate_container_table_ids_are_not_accepted_as_a_pair() {
    let mut image = roots_fixture();
    put64(&mut image, 64 * CLUSTER + 0x48, 0xb);
    let digest = crc64_nvme(&image[64 * CLUSTER..68 * CLUSTER]);
    change_root(&mut image, 8, |reference| put64(reference, 0x28, digest));
    let report = probe(image);
    for root in report
        .physical_root_references
        .iter()
        .filter(|root| matches!(root.root_index, 7 | 8))
    {
        assert_eq!(root.checksum_matches, Some(true));
        assert_eq!(root.header_matches, Some(true));
        assert_eq!(root.table_id_matches, Some(false));
        assert!(root.rejection.is_some());
    }
}

#[test]
fn noncontiguous_physical_slots_are_assembled_in_reference_order() {
    let mut image = roots_fixture();
    let order = [60_u64, 62, 61, 63];
    for (slot, lcn) in order.iter().enumerate() {
        put64(&mut image, 60 * CLUSTER + 0x20 + slot * 8, *lcn);
    }
    let mut assembled = Vec::new();
    for lcn in order {
        assembled.extend_from_slice(&image[lcn as usize * CLUSTER..(lcn as usize + 1) * CLUSTER]);
    }
    let digest = crc64_nvme(&assembled);
    change_root(&mut image, 7, |reference| {
        for (slot, lcn) in order.iter().enumerate() {
            put64(reference, slot * 8, *lcn);
        }
        put64(reference, 0x28, digest);
    });
    let report = probe(image);
    assert_eq!(report.physical_root_pages[0].lcn_slots, order);
    assert_eq!(
        report.physical_root_pages[0].byte_offsets,
        order.map(|lcn| lcn * 4096)
    );
    assert!(
        report
            .physical_root_references
            .iter()
            .filter(|root| root.root_index == 7)
            .all(|root| root.checksum_matches == Some(true) && root.header_matches == Some(true))
    );
}

#[test]
fn divergent_superblock_checkpoint_pairs_do_not_expand_root_budget() {
    let mut image = roots_fixture();
    for (lcn, first, second) in [(126, 48, 52), (125, 56, 72)] {
        let bytes = &mut image[lcn * CLUSTER..(lcn + 1) * CLUSTER];
        put64(bytes, 0xc0, first);
        put64(bytes, 0xc8, second);
        make_self_checksum(bytes, 0xd0, lcn as u64);
    }
    let report = probe(image);
    assert_eq!(report.checkpoints.len(), 6);
    assert!(report.physical_root_references.is_empty() && report.physical_root_pages.is_empty());
    assert!(
        report
            .physical_root_probe_skipped_reason
            .as_ref()
            .unwrap()
            .contains("More than two")
    );
}

#[test]
fn failed_checkpoint_self_checksum_never_supplies_root_addresses() {
    let mut image = roots_fixture();
    image[40 * CLUSTER + 2000] ^= 1;
    image[44 * CLUSTER + 2000] ^= 1;
    let report = probe(image);
    assert!(report.physical_root_references.is_empty());
    assert!(report.physical_root_pages.is_empty());
    assert!(report.physical_root_probe_skipped_reason.is_some());
}
