use ntfs2refs::{
    refs_bootstrap::{AnchorProbe, RootReference, crc64_nvme},
    refs_containers::{
        ContainerLimits, ContainerMapping, ContainerPageObservation, ContainerTablesProbe,
        ContainerTreeObservation,
    },
    refs_inspect::RefsGeometry,
    refs_virtual_roots::{VirtualRootLimits, inspect_virtual_roots},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Seek, SeekFrom},
};
const CLUSTER: u64 = 4096;
const TABLES: [u64; 13] = [2, 0x21, 0x20, 1, 3, 4, 5, 11, 12, 6, 14, 15, 34];
struct SparseReader {
    blocks: BTreeMap<u64, [u8; 4096]>,
    position: u64,
    len: u64,
    bytes_read: u64,
}
impl Read for SparseReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let length = out
            .len()
            .min(self.len.saturating_sub(self.position) as usize);
        for (i, byte) in out[..length].iter_mut().enumerate() {
            let p = self.position + i as u64;
            *byte = self
                .blocks
                .get(&(p / CLUSTER))
                .map_or(0, |b| b[(p % CLUSTER) as usize]);
        }
        self.position += length as u64;
        self.bytes_read += length as u64;
        Ok(length)
    }
}
impl Seek for SparseReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let p = match from {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::End(p) => i128::from(self.len) + i128::from(p),
            SeekFrom::Current(p) => i128::from(self.position) + i128::from(p),
        };
        self.position = u64::try_from(p).map_err(|_| io::Error::other("seek overflow"))?;
        Ok(self.position)
    }
}
struct Fixture {
    reader: SparseReader,
    geometry: RefsGeometry,
    checkpoints: Vec<AnchorProbe>,
    containers: ContainerTablesProbe,
    protected: BTreeSet<u64>,
}
fn put32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
fn fixture() -> Fixture {
    let mut reader = SparseReader {
        blocks: BTreeMap::new(),
        position: 0,
        len: 32768 * CLUSTER,
        bytes_read: 0,
    };
    let mut refs = Vec::new();
    for (index, table) in TABLES.into_iter().enumerate() {
        let physical = if index == 7 {
            [500, 501, 502, 503]
        } else if index == 8 {
            [508, 509, 510, 511]
        } else if index == 12 {
            [516, 517, 518, 519]
        } else {
            let p = 100 + index as u64 * 8;
            [p, p + 2, p + 1, p + 3]
        };
        let virtual_slots = if [7, 8, 12].contains(&index) {
            physical
        } else {
            physical.map(|p| 65536 + p)
        };
        let mut page = [0; 16384];
        page[..4].copy_from_slice(b"MSB+");
        put32(&mut page, 4, 2);
        put32(&mut page, 12, 42);
        for (i, v) in virtual_slots.iter().enumerate() {
            put64(&mut page, 0x20 + i * 8, *v);
        }
        put64(&mut page, 0x48, table);
        page[700] = index as u8;
        let crc = if [7, 8].contains(&index) {
            0x1234
        } else {
            crc64_nvme(&page)
        };
        for (i, p) in physical.iter().enumerate() {
            reader
                .blocks
                .insert(*p, page[i * 4096..(i + 1) * 4096].try_into().unwrap());
        }
        refs.push(RootReference {
            index,
            descriptor_offset: 256 + 48 * index,
            lcn_slots: virtual_slots,
            flags: 0,
            checksum_type: 2,
            checksum_data_offset: 8,
            checksum_data_length: 8,
            stored_checksum_bytes_hex: hex::encode(crc.to_le_bytes()),
            descriptor_sha256: "1".repeat(64),
            addressed_page_read: false,
        });
    }
    let cp:AnchorProbe=serde_json::from_value(json!({"kind":"CHKP","lcn":600,"byte_offset":600*CLUSTER,"bytes_read":16384,"sha256":"2".repeat(64),"referenced_by_superblock_lcns":[30],"header":{"signature":"CHKP","version":2,"volume_signature":42,"virtual_clock":20,"tree_update_clock":20,"lcn_slots":[600,0,0,0]},"self_checksum":{"descriptor_offset":224,"descriptor_length":48,"algorithm":"CRC32-C","coverage_bytes":4096,"stored":1,"computed":1,"matches":true},"superblock":null,"checkpoint":{"version_echo":917507,"major_version":3,"minor_version":14,"virtual_clock":20,"allocator_clock":19,"header_clock_matches":true,"flags":1666,"indirect_root_list":true,"reference_size":48,"roots":refs},"rejection":null})).unwrap();
    let mapping = ContainerMapping {
        container_id: 2,
        physical_start_lcn: 0,
        clusters_per_container: 16384,
        raw_flags: 0,
        raw_free_clusters_64: 0,
        raw_free_clusters_32: 0,
        free_clusters_64_is_sentinel: false,
        value_bytes_hex: "00".repeat(160).into(),
        row_sha256: "3".repeat(64),
        source_page_index: 0,
        source_row_index: 0,
    };
    let trees = (7..=8)
        .map(|root| {
            let slots = cp.checkpoint.as_ref().unwrap().roots[root].lcn_slots;
            ContainerTreeObservation {
                checkpoint_lcn: 600,
                root_index: root,
                table_id: TABLES[root],
                root_lcn_slots: slots,
                expected_root_rows: Some(1),
                root_count_matches: Some(true),
                walk_finished: true,
                pages: vec![ContainerPageObservation {
                    lcn_slots: slots,
                    depth: 0,
                    parent_page_index: None,
                    parent_row_index: None,
                    sha256: "4".repeat(64),
                    stored_crc64: "0000000000001234".into(),
                    computed_crc64: "0000000000001234".into(),
                    checksum_matches: true,
                    header_matches: true,
                    node_level: Some(0),
                    row_count: Some(1),
                    rejection: None,
                }],
                mappings: vec![mapping.clone()],
                rejection: None,
            }
        })
        .collect();
    let geometry:RefsGeometry=serde_json::from_value(json!({"bytes_per_sector":512,"sectors_per_cluster":8,"bytes_per_cluster":4096,"total_sectors":reader.len/512,"volume_bytes":reader.len,"image_bytes":reader.len,"trailing_bytes":0,"major_version":3,"minor_version":14,"volume_serial":1,"recognition_checksum":0})).unwrap();
    Fixture {
        reader,
        geometry,
        checkpoints: vec![cp],
        containers: ContainerTablesProbe {
            profile: "synthetic".into(),
            limits: ContainerLimits::default(),
            pages_read: 2,
            bytes_read: 32768,
            trees,
            failover_comparisons: vec![],
            authoritative_checkpoint_selected: false,
            metadata_verified: false,
            allocation_verified: false,
            conversion_profile_qualified: false,
        },
        protected: BTreeSet::from([30, 600, 601, 602, 603, 516, 517, 518, 519]),
    }
}
fn inspect(f: &mut Fixture) -> ntfs2refs::refs_virtual_roots::VirtualRootsProbe {
    inspect_virtual_roots(
        &mut f.reader,
        &f.geometry,
        &f.checkpoints,
        &f.containers,
        &f.protected,
        VirtualRootLimits::default(),
    )
    .unwrap()
}
fn add_checkpoint(f: &mut Fixture) {
    let mut cp = f.checkpoints[0].clone();
    cp.lcn = 700;
    cp.byte_offset = 700 * CLUSTER;
    cp.header.as_mut().unwrap().lcn_slots[0] = 700;
    f.checkpoints.push(cp);
    let mut trees = f.containers.trees.clone();
    for t in &mut trees {
        t.checkpoint_lcn = 700;
    }
    f.containers.trees.extend(trees);
}
fn resign(f: &mut Fixture, index: usize) {
    let slots = f.checkpoints[0].checkpoint.as_ref().unwrap().roots[index].lcn_slots;
    let mut b = [0; 16384];
    for (i, v) in slots.iter().enumerate() {
        b[i * 4096..(i + 1) * 4096].copy_from_slice(&f.reader.blocks[&(v - 65536)]);
    }
    f.checkpoints[0].checkpoint.as_mut().unwrap().roots[index].stored_checksum_bytes_hex =
        hex::encode(crc64_nvme(&b).to_le_bytes());
}

#[test]
fn translates_four_slots_in_reference_order_and_never_follows_children() {
    let mut f = fixture();
    let p = inspect(&mut f);
    assert_eq!(p.pages_read, 10);
    assert_eq!(p.bytes_read, 163840);
    assert_eq!(f.reader.bytes_read, p.bytes_read);
    assert_eq!(p.roots[0].physical_lcn_slots, Some([100, 102, 101, 103]));
    assert!(p.roots.iter().all(|r| r.rejection.is_none()
        && r.checksum_matches == Some(true)
        && r.self_virtual_slots_match == Some(true)
        && r.table_id_matches == Some(true)));
    assert!(
        !p.children_traversed
            && !p.authoritative_checkpoint_selected
            && !p.metadata_verified
            && !p.allocation_verified
            && !p.conversion_profile_qualified
    );
}
#[test]
fn unchanged_pages_are_reread_for_both_checkpoints_without_authority_selection() {
    let mut f = fixture();
    add_checkpoint(&mut f);
    let p = inspect(&mut f);
    assert_eq!(
        (
            p.pages_read,
            p.repeated_physical_page_reads,
            p.reused_page_reads
        ),
        (20, 10, 0)
    );
    assert_eq!(p.bytes_read, 327680);
    assert!(p.roots.iter().all(|r| r.rejection.is_none()));
    assert_eq!(p.checkpoint_maps.len(), 2);
}
#[test]
fn one_checkpoint_cannot_borrow_the_other_checkpoints_map() {
    let mut f = fixture();
    add_checkpoint(&mut f);
    f.containers.trees[0].walk_finished = false;
    let p = inspect(&mut f);
    assert!(p.checkpoint_maps[0].rejection.is_some());
    assert!(p.checkpoint_maps[1].rejection.is_none());
    assert_eq!(p.pages_read, 10);
    assert!(p.roots.iter().all(|r| r.checkpoint_lcn == 700));
}
#[test]
fn incomplete_unequal_or_unbound_container_maps_prohibit_every_read() {
    for scenario in [
        "walk",
        "count",
        "rows",
        "missing",
        "table",
        "root_slots",
        "root_crc",
        "child_checksum",
        "raw_values",
        "mapping",
        "cpc",
        "overflow",
        "duplicate_key",
        "overlap",
        "raw_length",
    ] {
        let mut f = fixture();
        match scenario {
            "walk" => f.containers.trees[0].walk_finished = false,
            "count" => f.containers.trees[0].root_count_matches = Some(false),
            "rows" => f.containers.trees[0].expected_root_rows = Some(2),
            "missing" => {
                f.containers.trees.pop();
            }
            "table" => f.containers.trees[0].table_id = 12,
            "root_slots" => f.containers.trees[0].root_lcn_slots[0] += 1,
            "root_crc" => f.containers.trees[0].pages[0].computed_crc64 = "0".repeat(16),
            "child_checksum" => f.containers.trees[0].pages[0].checksum_matches = false,
            "raw_values" => f.containers.trees[0].mappings[0].value_bytes_hex = "01".repeat(160).into(),
            "mapping" => f.containers.trees[0].mappings[0].physical_start_lcn = 16384,
            "cpc" => f.containers.trees[0].mappings[0].clusters_per_container = 4096,
            "overflow" => f.containers.trees[0].mappings[0].physical_start_lcn = u64::MAX,
            "raw_length" => f.containers.trees[0].mappings[0].value_bytes_hex = "00".repeat(161).into(),
            "duplicate_key" | "overlap" => {
                let mut m = f.containers.trees[0].mappings[0].clone();
                if scenario == "overlap" {
                    m.container_id = 3;
                    m.physical_start_lcn = 100;
                }
                f.containers.trees[0].mappings.push(m);
                f.containers.trees[0].expected_root_rows = Some(2);
            }
            _ => unreachable!(),
        };
        let p = inspect(&mut f);
        assert_eq!(p.pages_read, 0, "{scenario}");
        assert!(p.checkpoint_maps[0].rejection.is_some(), "{scenario}");
    }
}
#[test]
fn malformed_descriptors_and_virtual_addresses_do_not_get_read() {
    for scenario in [
        "flags",
        "type",
        "offset",
        "length",
        "crc_hex",
        "zero",
        "duplicate",
        "reserved_bit",
        "missing_container",
    ] {
        let mut f = fixture();
        let r = &mut f.checkpoints[0].checkpoint.as_mut().unwrap().roots[0];
        match scenario {
            "flags" => r.flags = 1,
            "type" => r.checksum_type = 1,
            "offset" => r.checksum_data_offset = 9,
            "length" => r.checksum_data_length = 32,
            "crc_hex" => r.stored_checksum_bytes_hex = "zz".repeat(8),
            "zero" => r.lcn_slots[0] = 0,
            "duplicate" => r.lcn_slots[1] = r.lcn_slots[0],
            "reserved_bit" => r.lcn_slots[0] |= 0x4000,
            "missing_container" => r.lcn_slots[0] = 10 << 15,
            _ => unreachable!(),
        };
        let p = inspect(&mut f);
        assert_eq!(p.roots[0].bytes_read, 0, "{scenario}");
        assert!(p.roots[0].rejection.is_some(), "{scenario}");
        assert_eq!(p.pages_read, 9);
    }
}
#[test]
fn rejects_protected_clusters_and_intra_checkpoint_aliases_before_read() {
    for scenario in ["anchor", "container", "complete_alias", "partial_alias"] {
        let mut f = fixture();
        let index = if scenario.ends_with("alias") { 1 } else { 0 };
        match scenario {
            "anchor" => {
                f.protected.insert(100);
            }
            "container" => {
                f.containers.trees[0].pages.push(ContainerPageObservation {
                    lcn_slots: [100, 900, 901, 902],
                    depth: 1,
                    parent_page_index: Some(0),
                    parent_row_index: Some(0),
                    sha256: "4".repeat(64),
                    stored_crc64: "0".repeat(16),
                    computed_crc64: "0".repeat(16),
                    checksum_matches: true,
                    header_matches: true,
                    node_level: Some(0),
                    row_count: Some(1),
                    rejection: None,
                });
            }
            "complete_alias" => {
                let a = f.checkpoints[0].checkpoint.as_ref().unwrap().roots[0].lcn_slots;
                f.checkpoints[0].checkpoint.as_mut().unwrap().roots[1].lcn_slots = a;
            }
            "partial_alias" => {
                f.checkpoints[0].checkpoint.as_mut().unwrap().roots[1].lcn_slots[3] = 65536 + 100
            }
            _ => unreachable!(),
        };
        let p = inspect(&mut f);
        assert_eq!(p.roots[index].bytes_read, 0, "{scenario}");
        assert!(p.roots[index].rejection.is_some());
        assert_eq!(p.pages_read, 9);
    }
}
#[test]
fn independently_checks_checksum_header_virtual_self_and_table_identity() {
    for scenario in [
        "crc",
        "signature",
        "version",
        "reserved",
        "volume",
        "self_physical",
        "high_table",
        "low_table",
    ] {
        let mut f = fixture();
        let b = f.reader.blocks.get_mut(&100).unwrap();
        match scenario {
            "crc" => b[700] ^= 1,
            "signature" => b[0] = 0,
            "version" => put32(b, 4, 3),
            "reserved" => put32(b, 8, 1),
            "volume" => put32(b, 12, 43),
            "self_physical" => put64(b, 0x20, 100),
            "high_table" => put64(b, 0x40, 1),
            "low_table" => put64(b, 0x48, 4),
            _ => unreachable!(),
        };
        if scenario != "crc" {
            resign(&mut f, 0);
        }
        let p = inspect(&mut f);
        assert_eq!(p.roots[0].bytes_read, 16384);
        assert!(p.roots[0].rejection.is_some(), "{scenario}");
        if scenario != "crc" {
            assert_eq!(p.roots[0].checksum_matches, Some(true));
        }
        assert_eq!(p.pages_read, 10);
    }
}
#[test]
fn bounded_reads_and_truncation_are_not_successful_full_inspections() {
    let mut f = fixture();
    add_checkpoint(&mut f);
    let p = inspect_virtual_roots(
        &mut f.reader,
        &f.geometry,
        &f.checkpoints,
        &f.containers,
        &f.protected,
        VirtualRootLimits { max_page_reads: 3 },
    )
    .unwrap();
    assert_eq!(p.pages_read, 3);
    assert_eq!(f.reader.bytes_read, 3 * 16384);
    assert_eq!(p.roots.iter().filter(|r| r.rejection.is_some()).count(), 17);
    let mut f = fixture();
    f.reader.len = 100 * CLUSTER + 3;
    assert!(
        inspect_virtual_roots(
            &mut f.reader,
            &f.geometry,
            &f.checkpoints,
            &f.containers,
            &f.protected,
            VirtualRootLimits::default()
        )
        .is_err()
    );
}
#[test]
fn unsupported_geometry_candidate_count_and_budgets_are_rejected() {
    for scenario in [
        "cluster",
        "version",
        "image",
        "zero_budget",
        "large_budget",
        "duplicate_checkpoint",
        "too_many",
    ] {
        let mut f = fixture();
        let mut limits = VirtualRootLimits::default();
        match scenario {
            "cluster" => f.geometry.bytes_per_cluster = 65536,
            "version" => f.geometry.minor_version = 10,
            "image" => f.geometry.image_bytes = f.geometry.volume_bytes - 1,
            "zero_budget" => limits.max_page_reads = 0,
            "large_budget" => limits.max_page_reads = 21,
            "duplicate_checkpoint" => f.checkpoints.push(f.checkpoints[0].clone()),
            "too_many" => {
                add_checkpoint(&mut f);
                let mut c = f.checkpoints[0].clone();
                c.lcn = 800;
                f.checkpoints.push(c);
            }
            _ => unreachable!(),
        };
        assert!(
            inspect_virtual_roots(
                &mut f.reader,
                &f.geometry,
                &f.checkpoints,
                &f.containers,
                &f.protected,
                limits
            )
            .is_err(),
            "{scenario}"
        );
        assert_eq!(f.reader.bytes_read, 0);
    }
}
#[test]
fn malformed_checkpoint_never_uses_its_container_maps() {
    for scenario in [
        "checksum",
        "rejection",
        "count",
        "index",
        "ref_size",
        "version",
        "self",
        "missing_header",
    ] {
        let mut f = fixture();
        let cp = &mut f.checkpoints[0];
        match scenario {
            "checksum" => cp.self_checksum.as_mut().unwrap().matches = false,
            "rejection" => cp.rejection = Some("bad".into()),
            "count" => {
                cp.checkpoint.as_mut().unwrap().roots.pop();
            }
            "index" => cp.checkpoint.as_mut().unwrap().roots[0].index = 1,
            "ref_size" => cp.checkpoint.as_mut().unwrap().reference_size = 104,
            "version" => cp.checkpoint.as_mut().unwrap().minor_version = 10,
            "self" => cp.header.as_mut().unwrap().lcn_slots[0] = 601,
            "missing_header" => cp.header = None,
            _ => unreachable!(),
        };
        let p = inspect(&mut f);
        assert_eq!(p.pages_read, 0, "{scenario}");
        assert!(p.checkpoint_maps[0].rejection.is_some());
    }
}
#[test]
fn bad_older_root_checksum_does_not_invalidate_or_select_the_other_candidate() {
    let mut f = fixture();
    add_checkpoint(&mut f);
    f.checkpoints[1].checkpoint.as_mut().unwrap().roots[0].stored_checksum_bytes_hex =
        "00".repeat(8);
    let p = inspect(&mut f);
    assert_eq!(p.pages_read, 20);
    assert!(p.roots[0].rejection.is_none());
    assert_eq!(p.roots[10].checksum_matches, Some(false));
    assert!(!p.authoritative_checkpoint_selected);
}

#[test]
#[ignore = "requires the pinned native 52 GiB lab corpus; performs bounded reads only"]
fn native_twenty_virtual_roots_match_independent_range_hashes() {
    use sha2::{Digest, Sha256};
    let corpus = std::path::Path::new(".lab/hyperv/corpus/devdrive-20261023T231918797Z");
    let old = std::fs::read(corpus.join("analysis-20261023T233638844Z/inspection.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&old)),
        "5a3bee79702c3c68bfa281786090e4000bf437f2e7574892c5a6714edfc16ece"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut source = options.open(corpus.join("devdrive.raw")).unwrap();
    assert_eq!(source.metadata().unwrap().len(), 55834574848);
    let mut vbr = [0; 512];
    source.read_exact(&mut vbr).unwrap();
    let geometry = ntfs2refs::refs_inspect::inspect_boot_sector(&vbr, 55834574848).unwrap();
    let probe = ntfs2refs::refs_bootstrap::inspect(&mut source, &geometry, &vbr)
        .unwrap()
        .unwrap();
    let result = probe.virtual_roots.unwrap();
    assert_eq!(
        (
            result.pages_read,
            result.repeated_physical_page_reads,
            result.reused_page_reads
        ),
        (20, 10, 0)
    );
    assert_eq!(result.bytes_read, 327680);
    assert_eq!(result.roots.len(), 20);
    assert!(
        result
            .checkpoint_maps
            .iter()
            .all(|m| m.both_complete_count_matching_maps_agree
                && m.mapping_rows == Some(832)
                && m.rejection.is_none())
    );
    for root in &result.roots {
        assert!(root.rejection.is_none(), "{:?}", root);
        let path = format!(
            ".lab/research/refs-virtual-roots-20261024/cp-{}-root-{}.bin",
            root.checkpoint_lcn, root.root_index
        );
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(bytes.len(), 16384);
        assert_eq!(root.sha256, Some(hex::encode(Sha256::digest(bytes))));
        eprintln!(
            "checkpoint={} root={} physical={:?} crc={} sha={}",
            root.checkpoint_lcn,
            root.root_index,
            root.physical_lcn_slots,
            root.computed_crc64_nvme.as_ref().unwrap(),
            root.sha256.as_ref().unwrap()
        );
    }
    assert!(
        !result.children_traversed
            && !result.metadata_verified
            && !result.allocation_verified
            && !result.conversion_profile_qualified
    );
}
