use ntfs2refs::{
    refs_bootstrap::crc64_nvme,
    refs_containers::{
        ContainerLimits, ContainerRootTarget, ContainerTablesProbe, inspect_container_tables,
    },
    refs_inspect::RefsGeometry,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Cursor, Read, Seek, SeekFrom},
};

const CLUSTER: usize = 4096;
const PAGE: usize = 16384;
const VOLUME: u64 = 4 * 16384 * 4096;
fn put16(b: &mut [u8], p: usize, x: u16) {
    b[p..p + 2].copy_from_slice(&x.to_le_bytes());
}
fn put32(b: &mut [u8], p: usize, x: u32) {
    b[p..p + 4].copy_from_slice(&x.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, x: u64) {
    b[p..p + 8].copy_from_slice(&x.to_le_bytes());
}
fn geometry() -> RefsGeometry {
    RefsGeometry {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        bytes_per_cluster: 4096,
        total_sectors: VOLUME / 512,
        volume_bytes: VOLUME,
        image_bytes: VOLUME,
        trailing_bytes: 0,
        major_version: 3,
        minor_version: 14,
        volume_serial: 1,
        recognition_checksum: 0,
    }
}
fn row(key: &[u8], value: &[u8], overlap: bool) -> Vec<u8> {
    let value_offset = if overlap { 16 } else { 16 + key.len() };
    let mut b = vec![0; value_offset + value.len()];
    let size = b.len() as u32;
    put32(&mut b, 0, size);
    put16(&mut b, 4, 16);
    put16(&mut b, 6, key.len() as u16);
    put16(&mut b, 10, value_offset as u16);
    put16(&mut b, 12, value.len() as u16);
    b[16..16 + key.len()].copy_from_slice(key);
    b[value_offset..].copy_from_slice(value);
    b
}
fn key(id: u64) -> [u8; 16] {
    let mut b = [0; 16];
    put64(&mut b, 0, id);
    put64(&mut b, 8, 0x1_0000_0000);
    b
}
fn leaf_row(id: u64, physical: u64) -> Vec<u8> {
    let k = key(id);
    let mut value = [0; 160];
    value[..16].copy_from_slice(&k);
    put32(&mut value, 0x10, 1);
    put32(&mut value, 0x14, 0x2001);
    put32(&mut value, 0x18, 16384);
    put64(&mut value, 0x20, u64::MAX);
    put32(&mut value, 0x28, u32::MAX);
    put64(&mut value, 0x90, physical);
    put32(&mut value, 0x98, 16384);
    row(&k, &value, true)
}
fn node(lcn: u64, table: u64, root: bool, level: u8, total: u64, rows: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; PAGE];
    b[..4].copy_from_slice(b"MSB+");
    put32(&mut b, 4, 2);
    put32(&mut b, 0xc, 17);
    for i in 0..4 {
        put64(&mut b, 0x20 + i * 8, lcn + i as u64);
    }
    put64(&mut b, 0x48, table);
    let n = if root { 0x80 } else { 0x58 };
    put32(&mut b, 0x50, (n - 0x50) as u32);
    if root {
        put16(&mut b, 0x54, 0x28);
        put32(&mut b, 0x5c, 0xe0c0);
        put64(&mut b, 0x70, total);
    }
    put32(&mut b, n, 40);
    b[n + 0xc] = level;
    b[n + 0xd] = if level > 0 { 3 } else { 0xe };
    let start = PAGE - rows.len() * 4;
    put32(&mut b, n + 0x10, (start - n) as u32);
    put32(&mut b, n + 0x14, rows.len() as u32);
    put32(&mut b, n + 0x20, (PAGE - n) as u32);
    let mut at = n + 40;
    for (i, r) in rows.iter().enumerate() {
        b[at..at + r.len()].copy_from_slice(r);
        put16(&mut b, start + i * 4, (at - n) as u16);
        put16(&mut b, start + i * 4 + 2, 0x3fdd);
        at += r.len();
    }
    b
}
fn reference(slots: [u64; 4], crc: u64) -> Vec<u8> {
    let mut b = vec![0; 48];
    for (i, lcn) in slots.iter().enumerate() {
        put64(&mut b, i * 8, *lcn);
    }
    b[0x22] = 2;
    b[0x23] = 8;
    put32(&mut b, 0x24, 8);
    put64(&mut b, 0x28, crc);
    b
}
fn target(page: &[u8], lcn: u64, table: u64, index: usize) -> ContainerRootTarget {
    ContainerRootTarget {
        checkpoint_lcn: 30,
        root_index: index,
        table_id: table,
        volume_signature: 17,
        lcn_slots: [lcn, lcn + 1, lcn + 2, lcn + 3],
        expected_crc64: crc64_nvme(page),
        expected_sha256: hex::encode(Sha256::digest(page)),
    }
}
struct Fixture {
    bytes: Vec<u8>,
    roots: Vec<ContainerRootTarget>,
}
fn fixture() -> Fixture {
    let mut bytes = vec![0; 128 * CLUSTER];
    let mut roots = Vec::new();
    for (table, root_lcn, child_lcn, index) in [(11, 40, 60, 7), (12, 44, 64, 8)] {
        let leaf = node(
            child_lcn,
            table,
            false,
            0,
            0,
            &[leaf_row(2, 0), leaf_row(3, 16384)],
        );
        let descriptor = reference(
            [child_lcn, child_lcn + 1, child_lcn + 2, child_lcn + 3],
            crc64_nvme(&leaf),
        );
        let root = node(root_lcn, table, true, 1, 2, &[row(&[], &descriptor, false)]);
        bytes[child_lcn as usize * CLUSTER..child_lcn as usize * CLUSTER + PAGE]
            .copy_from_slice(&leaf);
        bytes[root_lcn as usize * CLUSTER..root_lcn as usize * CLUSTER + PAGE]
            .copy_from_slice(&root);
        roots.push(target(&root, root_lcn, table, index));
    }
    Fixture { bytes, roots }
}
fn rebind_root(f: &mut Fixture, index: usize) {
    let root = &mut f.roots[index];
    let at = root.lcn_slots[0] as usize * CLUSTER;
    root.expected_crc64 = crc64_nvme(&f.bytes[at..at + PAGE]);
    root.expected_sha256 = hex::encode(Sha256::digest(&f.bytes[at..at + PAGE]));
}
fn rebind_child(f: &mut Fixture, index: usize) {
    let child = if index == 0 { 60 } else { 64 };
    let digest = crc64_nvme(&f.bytes[child * CLUSTER..child * CLUSTER + PAGE]);
    let at = f.roots[index].lcn_slots[0] as usize * CLUSTER + 0x80 + 40 + 16;
    put64(&mut f.bytes, at + 0x28, digest);
    rebind_root(f, index);
}
fn probe(f: &Fixture, limits: ContainerLimits) -> ContainerTablesProbe {
    inspect_container_tables(
        &mut Cursor::new(&f.bytes),
        &geometry(),
        &f.roots,
        &BTreeSet::new(),
        limits,
    )
    .unwrap()
}
#[test]
fn reads_two_physical_trees_and_compares_maps_without_allocation_claims() {
    let f = fixture();
    let r = probe(&f, ContainerLimits::default());
    assert_eq!(r.pages_read, 4);
    assert_eq!(r.bytes_read, 4 * PAGE as u64);
    assert_eq!(r.trees.len(), 2);
    for tree in &r.trees {
        assert!(tree.walk_finished && tree.root_count_matches == Some(true));
        assert_eq!(tree.mappings.len(), 2);
        assert!(
            tree.mappings
                .iter()
                .all(|m| m.free_clusters_64_is_sentinel && m.raw_flags == 0x2001)
        );
        assert!(
            tree.pages
                .iter()
                .all(|p| p.checksum_matches && p.header_matches)
        );
    }
    assert_eq!(r.failover_comparisons[0].mapping_entries_equal, Some(true));
    assert_eq!(r.failover_comparisons[0].raw_values_equal, Some(true));
    assert!(
        !r.metadata_verified
            && !r.allocation_verified
            && !r.conversion_profile_qualified
            && !r.authoritative_checkpoint_selected
    );
}
#[test]
fn checkpoints_are_separate_and_global_read_budget_is_shared() {
    let mut f = fixture();
    let mut more = f.roots.clone();
    for root in &mut more {
        root.checkpoint_lcn = 34;
    }
    f.roots.extend(more);
    let r = probe(&f, ContainerLimits::default());
    assert_eq!(r.trees.len(), 4);
    assert_eq!(r.failover_comparisons.len(), 2);
    assert_eq!(r.pages_read, 8);
    let limited = probe(
        &f,
        ContainerLimits {
            max_total_pages: 3,
            ..ContainerLimits::default()
        },
    );
    assert_eq!(limited.pages_read, 3);
    assert!(limited.trees.iter().any(|tree| !tree.walk_finished));
    assert!(limited.bytes_read <= 3 * PAGE as u64);
}
#[test]
fn mismatched_checksums_or_page_identities_never_supply_children_or_rows() {
    for scenario in [
        "root_crc",
        "root_sha",
        "child_crc",
        "child_table",
        "child_self",
        "child_volume",
        "child_level",
    ] {
        let mut f = fixture();
        f.roots.truncate(1);
        match scenario {
            "root_crc" => f.roots[0].expected_crc64 ^= 1,
            "root_sha" => f.roots[0].expected_sha256 = "0".repeat(64),
            "child_crc" => f.bytes[60 * CLUSTER + 1000] ^= 1,
            "child_table" => {
                put64(&mut f.bytes, 60 * CLUSTER + 0x48, 12);
                rebind_child(&mut f, 0);
            }
            "child_self" => {
                put64(&mut f.bytes, 60 * CLUSTER + 0x20, 61);
                rebind_child(&mut f, 0);
            }
            "child_volume" => {
                put32(&mut f.bytes, 60 * CLUSTER + 0xc, 18);
                rebind_child(&mut f, 0);
            }
            "child_level" => {
                f.bytes[60 * CLUSTER + 0x58 + 0xc] = 1;
                f.bytes[60 * CLUSTER + 0x58 + 0xd] = 3;
                rebind_child(&mut f, 0);
            }
            _ => unreachable!(),
        }
        let r = probe(&f, ContainerLimits::default());
        assert!(!r.trees[0].walk_finished, "{scenario}");
        assert!(r.trees[0].mappings.is_empty(), "{scenario}");
        assert_eq!(
            r.pages_read,
            if scenario.starts_with("root") { 1 } else { 2 }
        );
    }
}
#[test]
fn malformed_reference_geometry_type_and_anchor_overlap_stop_before_child_io() {
    for scenario in [
        "type",
        "flags",
        "offset",
        "length",
        "duplicate",
        "zero",
        "overflow",
        "outside",
        "cycle",
    ] {
        let mut f = fixture();
        f.roots.truncate(1);
        let at = 40 * CLUSTER + 0x80 + 40 + 16;
        match scenario {
            "type" => f.bytes[at + 0x22] = 4,
            "flags" => f.bytes[at + 0x20] = 1,
            "offset" => f.bytes[at + 0x23] = 9,
            "length" => put32(&mut f.bytes, at + 0x24, 7),
            "duplicate" => put64(&mut f.bytes, at + 8, 60),
            "zero" => put64(&mut f.bytes, at, 0),
            "overflow" => put64(&mut f.bytes, at, u64::MAX),
            "outside" => put64(&mut f.bytes, at, VOLUME / 4096),
            "cycle" => {
                for i in 0..4 {
                    put64(&mut f.bytes, at + i * 8, 40 + i as u64);
                }
            }
            _ => unreachable!(),
        }
        rebind_root(&mut f, 0);
        let r = probe(&f, ContainerLimits::default());
        assert_eq!(r.pages_read, 1, "{scenario}");
        assert!(!r.trees[0].walk_finished, "{scenario}");
    }
    let f = fixture();
    let protected = BTreeSet::from([60]);
    let r = inspect_container_tables(
        &mut Cursor::new(&f.bytes),
        &geometry(),
        &f.roots[..1],
        &protected,
        ContainerLimits::default(),
    )
    .unwrap();
    assert_eq!(r.pages_read, 1);
    assert!(!r.trees[0].walk_finished);
}
#[test]
fn duplicate_keys_overlapping_extents_and_bad_value_fields_are_refused() {
    for scenario in [
        "duplicate_key",
        "overlap",
        "outside",
        "overflow",
        "cpc",
        "trailing",
        "version",
        "tag",
        "value_size",
        "key_prefix",
    ] {
        let mut f = fixture();
        f.roots.truncate(1);
        let first = 60 * CLUSTER + 0x58 + 40;
        let second = first + 176;
        let value = first + 16;
        match scenario {
            "duplicate_key" => put64(&mut f.bytes, second + 16, 2),
            "overlap" => put64(&mut f.bytes, second + 16 + 0x90, 1),
            "outside" => put64(&mut f.bytes, value + 0x90, VOLUME / 4096 - 1),
            "overflow" => put64(&mut f.bytes, value + 0x90, u64::MAX),
            "cpc" => put32(&mut f.bytes, value + 0x18, 8192),
            "trailing" => put32(&mut f.bytes, value + 0x98, 8192),
            "version" => put32(&mut f.bytes, value + 0x10, 2),
            "tag" => put64(&mut f.bytes, value + 8, 0),
            "value_size" => put16(&mut f.bytes, first + 12, 152),
            "key_prefix" => put16(&mut f.bytes, first + 4, 24),
            _ => unreachable!(),
        }
        rebind_child(&mut f, 0);
        let r = probe(&f, ContainerLimits::default());
        assert!(!r.trees[0].walk_finished, "{scenario}");
        assert!(r.trees[0].rejection.is_some());
    }
}
#[test]
fn page_row_and_depth_limits_refuse_unfinished_walks_explicitly() {
    let f = fixture();
    for limits in [
        ContainerLimits {
            max_pages_per_tree: 1,
            ..ContainerLimits::default()
        },
        ContainerLimits {
            max_rows_per_tree: 1,
            ..ContainerLimits::default()
        },
        ContainerLimits {
            max_depth: 0,
            ..ContainerLimits::default()
        },
    ] {
        let r = probe(&f, limits);
        assert!(r.trees.iter().all(|tree| !tree.walk_finished));
        assert!(r.trees.iter().all(|tree| tree.root_count_matches.is_none()));
    }
    assert!(
        inspect_container_tables(
            &mut Cursor::new(Vec::new()),
            &geometry(),
            &[],
            &BTreeSet::new(),
            ContainerLimits {
                max_total_pages: 129,
                ..ContainerLimits::default()
            }
        )
        .is_err()
    );
}
#[test]
fn count_and_failover_differences_remain_observations_without_selecting_a_winner() {
    let mut f = fixture();
    put64(&mut f.bytes, 40 * CLUSTER + 0x70, 99);
    rebind_root(&mut f, 0);
    put64(
        &mut f.bytes,
        64 * CLUSTER + 0x58 + 40 + 176 + 16 + 0x90,
        32768,
    );
    rebind_child(&mut f, 1);
    let r = probe(&f, ContainerLimits::default());
    assert!(r.trees.iter().all(|tree| tree.walk_finished));
    assert_eq!(r.trees[0].root_count_matches, Some(false));
    assert_eq!(r.failover_comparisons[0].mapping_entries_equal, Some(false));
    assert_eq!(r.failover_comparisons[0].raw_values_equal, Some(false));
    assert!(!r.authoritative_checkpoint_selected);
}
#[test]
fn read_failure_propagates_instead_of_becoming_a_complete_mapping() {
    let mut f = fixture();
    f.roots.truncate(1);
    f.bytes.truncate(60 * CLUSTER + 100);
    let error = inspect_container_tables(
        &mut Cursor::new(&f.bytes),
        &geometry(),
        &f.roots,
        &BTreeSet::new(),
        ContainerLimits::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("read container page"));
}

#[test]
fn repeated_children_and_partially_overlapping_page_slots_are_rejected() {
    for overlap in [false, true] {
        let mut f = fixture();
        f.roots.truncate(1);
        let crc = crc64_nvme(&f.bytes[60 * CLUSTER..64 * CLUSTER]);
        let first = reference([60, 61, 62, 63], crc);
        let second = reference(
            if overlap {
                [63, 64, 65, 66]
            } else {
                [60, 61, 62, 63]
            },
            crc,
        );
        let root = node(
            40,
            11,
            true,
            1,
            4,
            &[row(&key(2), &first, false), row(&[], &second, false)],
        );
        f.bytes[40 * CLUSTER..44 * CLUSTER].copy_from_slice(&root);
        rebind_root(&mut f, 0);
        let report = probe(&f, ContainerLimits::default());
        assert_eq!(report.pages_read, 2);
        assert_eq!(report.trees[0].mappings.len(), 2);
        assert!(!report.trees[0].walk_finished);
        assert!(
            report.trees[0]
                .rejection
                .as_ref()
                .unwrap()
                .contains("overlapping page clusters")
        );
    }
}

#[test]
fn nested_index_nodes_are_bounded_and_descend_to_leaf_rows() {
    let mut f = fixture();
    f.roots.truncate(1);
    let leaf_crc = crc64_nvme(&f.bytes[60 * CLUSTER..64 * CLUSTER]);
    let intermediate = node(
        68,
        11,
        false,
        1,
        0,
        &[row(&[], &reference([60, 61, 62, 63], leaf_crc), false)],
    );
    let root = node(
        40,
        11,
        true,
        2,
        2,
        &[row(
            &[],
            &reference([68, 69, 70, 71], crc64_nvme(&intermediate)),
            false,
        )],
    );
    f.bytes[68 * CLUSTER..72 * CLUSTER].copy_from_slice(&intermediate);
    f.bytes[40 * CLUSTER..44 * CLUSTER].copy_from_slice(&root);
    rebind_root(&mut f, 0);
    let result = probe(&f, ContainerLimits::default());
    assert!(result.trees[0].walk_finished);
    assert_eq!(result.pages_read, 3);
    assert_eq!(
        result.trees[0]
            .pages
            .iter()
            .map(|p| p.node_level)
            .collect::<Vec<_>>(),
        [Some(2), Some(1), Some(0)]
    );
    let limited = probe(
        &f,
        ContainerLimits {
            max_depth: 1,
            ..ContainerLimits::default()
        },
    );
    assert!(!limited.trees[0].walk_finished);
    assert_eq!(limited.pages_read, 2);
}

#[test]
fn root_leaf_and_noncontiguous_child_clusters_use_declared_order() {
    let mut f = fixture();
    f.roots.truncate(1);
    let direct = node(40, 11, true, 0, 2, &[leaf_row(2, 0), leaf_row(3, 16384)]);
    f.bytes[40 * CLUSTER..44 * CLUSTER].copy_from_slice(&direct);
    rebind_root(&mut f, 0);
    let r = probe(&f, ContainerLimits::default());
    assert_eq!(r.pages_read, 1);
    assert!(r.trees[0].walk_finished);
    let mut f = fixture();
    f.roots.truncate(1);
    let order = [60, 62, 61, 63];
    let at = 60 * CLUSTER;
    for (slot, lcn) in order.iter().enumerate() {
        put64(&mut f.bytes, at + 0x20 + slot * 8, *lcn);
    }
    let mut assembled = Vec::new();
    for lcn in order {
        assembled.extend_from_slice(&f.bytes[lcn as usize * CLUSTER..(lcn as usize + 1) * CLUSTER]);
    }
    let descriptor = reference(order, crc64_nvme(&assembled));
    let root = node(40, 11, true, 1, 2, &[row(&[], &descriptor, false)]);
    f.bytes[40 * CLUSTER..44 * CLUSTER].copy_from_slice(&root);
    rebind_root(&mut f, 0);
    let r = probe(&f, ContainerLimits::default());
    assert!(r.trees[0].walk_finished);
    assert_eq!(r.trees[0].mappings.len(), 2);
}

#[test]
#[ignore = "requires N2R_NATIVE_REFS_CORPUS; bounded reads only, no whole-image rehash"]
fn native_container_walks_are_bound_to_verified_capture_roots() {
    let corpus = std::path::PathBuf::from(
        std::env::var_os("N2R_NATIVE_REFS_CORPUS").expect("explicit corpus path"),
    );
    let evidence =
        std::fs::read(corpus.join("analysis-20261023T233638844Z/inspection.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&evidence)),
        "5a3bee79702c3c68bfa281786090e4000bf437f2e7574892c5a6714edfc16ece"
    );
    let report: serde_json::Value = serde_json::from_slice(&evidence).unwrap();
    let geom: RefsGeometry =
        serde_json::from_value(report["filesystem"]["details"]["geometry"].clone()).unwrap();
    let bootstrap: ntfs2refs::refs_bootstrap::BootstrapProbe =
        serde_json::from_value(report["filesystem"]["details"]["bootstrap"].clone()).unwrap();
    let mut roots = Vec::new();
    for reference in &bootstrap.physical_root_references {
        if !matches!(reference.root_index, 7 | 8) {
            continue;
        }
        assert!(reference.rejection.is_none());
        assert_eq!(reference.checksum_matches, Some(true));
        assert_eq!(reference.header_matches, Some(true));
        assert_eq!(reference.table_id_matches, Some(true));
        let page = &bootstrap.physical_root_pages[reference.page_index.unwrap()];
        roots.push(ContainerRootTarget {
            checkpoint_lcn: reference.checkpoint_lcn,
            root_index: reference.root_index,
            table_id: page.table_id_low,
            volume_signature: page.volume_signature,
            lcn_slots: page.lcn_slots,
            expected_crc64: u64::from_str_radix(reference.stored_crc64_nvme.as_ref().unwrap(), 16)
                .unwrap(),
            expected_sha256: page.sha256.clone(),
        });
    }
    let mut protected = BTreeSet::new();
    for a in &bootstrap.superblocks {
        protected.insert(a.lcn);
    }
    for a in &bootstrap.checkpoints {
        for i in 0..4 {
            protected.insert(a.lcn + i);
        }
    }
    for page in &bootstrap.physical_root_pages {
        protected.extend(page.lcn_slots);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut source = options.open(corpus.join("devdrive.raw")).unwrap();
    assert_eq!(source.metadata().unwrap().len(), 55834574848);
    let result = inspect_container_tables(
        &mut source,
        &geom,
        &roots,
        &protected,
        ContainerLimits::default(),
    )
    .unwrap();
    for tree in &result.trees {
        eprintln!(
            "checkpoint={} root={} pages={} rows={} count_match={:?} finished={} rejection={:?}",
            tree.checkpoint_lcn,
            tree.root_index,
            tree.pages.len(),
            tree.mappings.len(),
            tree.root_count_matches,
            tree.walk_finished,
            tree.rejection
        );
        assert!(tree.walk_finished, "{:?}", tree.rejection);
        assert_eq!(tree.mappings.len(), 832);
        assert_eq!(tree.root_count_matches, Some(true));
    }
    assert_eq!(result.trees.len(), 4);
    assert!(
        result
            .failover_comparisons
            .iter()
            .all(|p| p.mapping_entries_equal == Some(true) && p.raw_values_equal == Some(true))
    );
    assert!(result.bytes_read <= 128 * PAGE as u64);
    assert!(!result.allocation_verified && !result.conversion_profile_qualified);
    // Also exercise the production integration through the bounded inspector.
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut vbr = [0; 512];
    source.read_exact(&mut vbr).unwrap();
    let integrated = ntfs2refs::refs_bootstrap::inspect(&mut source, &geom, &vbr)
        .unwrap()
        .unwrap();
    assert_eq!(integrated.container_tables.unwrap().trees.len(), 4);
}
