use n2r_win32::bitmap_layout::{AllocatedRange, AllocationMap};
use ntfs2refs::{
    refs_inspect::RefsInspection,
    refs_write_set::{self, ByteRange},
};
use serde_json::{Value, json};

const C: u64 = 4096;
const N: u64 = 128;

fn anchor(kind: &str, lcn: u64) -> Value {
    let roots: Vec<_> = (0..13)
        .map(|index| {
            json!({
                "index":index, "descriptor_offset":256+48*index,
                "lcn_slots":[64,65,66,67], "flags":0,"checksum_type":2,
                "checksum_data_offset":8,"checksum_data_length":8,
                "stored_checksum_bytes_hex":"0000000000000000",
                "descriptor_sha256":"a".repeat(64),"addressed_page_read":false
            })
        })
        .collect();
    json!({
        "kind":kind,"lcn":lcn,"byte_offset":lcn*C,
        "bytes_read":if kind=="SUPB" {4096} else {16384},
        "sha256":"a".repeat(64),"referenced_by_superblock_lcns":[30,125,126],
        "header":{"signature":kind,"version":2,"volume_signature":42,
            "virtual_clock":20,"tree_update_clock":20,"lcn_slots":[lcn,0,0,0]},
        "self_checksum":{"descriptor_offset":224,"descriptor_length":48,
            "algorithm":"CRC32-C","coverage_bytes":4096,"stored":1,"computed":1,"matches":true},
        "superblock":if kind=="SUPB" {json!({"volume_guid_bytes_hex":"00".repeat(16),
            "generation":1,"checkpoint_lcns":[40,44]})} else {Value::Null},
        "checkpoint":if kind=="CHKP" {json!({"version_echo":917507,"major_version":3,
            "minor_version":14,"virtual_clock":20,"allocator_clock":19,
            "header_clock_matches":true,"flags":1666,"indirect_root_list":true,
            "reference_size":48,"roots":roots})} else {Value::Null},
        "rejection":null
    })
}

fn fixture() -> Value {
    json!({
        "geometry":{"bytes_per_sector":512,"sectors_per_cluster":8,"bytes_per_cluster":4096,
            "total_sectors":N*8,"volume_bytes":N*C,"image_bytes":N*C,"trailing_bytes":0,
            "major_version":3,"minor_version":14,"volume_serial":1,"recognition_checksum":1},
        "backup_probe_offset":N*C-512,"backup_header_status":"matching",
        "native_format_provenance":"synthetic test","metadata_verified":false,
        "checksum_verified":false,"conversion_profile_qualified":false,"warnings":[],
        "bootstrap":{"profile":"synthetic test","vbr_stored_checksum":1,"vbr_computed_checksum":1,
            "vbr_checksum_matches":true,"superblocks":[anchor("SUPB",30),anchor("SUPB",126),anchor("SUPB",125)],
            "checkpoints":[anchor("CHKP",40),anchor("CHKP",44)],
            "authoritative_checkpoint_selected":false,"metadata_verified":false,"warnings":[]}
    })
}

fn inspect(value: Value) -> RefsInspection {
    serde_json::from_value(value).unwrap()
}

#[test]
fn exact_anchors_require_checked_self_checksums_and_locations() {
    assert_eq!(
        refs_write_set::observed_anchors(&inspect(fixture()))
            .unwrap()
            .len(),
        7
    );
    for (field, value) in [
        ("matches", json!(false)),
        ("computed", json!(2)),
        ("coverage_bytes", json!(512)),
    ] {
        let mut header = fixture();
        header["bootstrap"]["superblocks"][0]["self_checksum"][field] = value;
        assert!(
            refs_write_set::observed_anchors(&inspect(header)).is_err(),
            "{field}"
        );
    }
    let mut header = fixture();
    header["bootstrap"]["superblocks"][1] = anchor("SUPB", 30);
    assert!(refs_write_set::observed_anchors(&inspect(header)).is_err());
    let mut header = fixture();
    header["bootstrap"]["checkpoints"][1] = anchor("CHKP", 48);
    assert!(refs_write_set::observed_anchors(&inspect(header)).is_err());
    let mut header = fixture();
    header["bootstrap"]["checkpoints"][0]["byte_offset"] = json!(41 * C);
    assert!(refs_write_set::observed_anchors(&inspect(header)).is_err());
    let mut header = fixture();
    header["bootstrap"]["physical_root_references"] = json!([{
        "checkpoint_lcn":40,"root_index":7,"lcn_slots":[64,65,66,67],
        "page_index":null,"stored_crc64_nvme":null,"checksum_matches":false,
        "header_matches":true,"table_id_matches":true,"rejection":"damaged root"
    }]);
    assert!(refs_write_set::observed_anchors(&inspect(header)).is_err());
}

#[test]
fn observed_container_children_are_copied_and_rejections_are_not_silently_omitted() {
    let page = |slots| {
        json!({"lcn_slots":slots,"depth":0,"parent_page_index":null,
        "parent_row_index":null,"sha256":"a".repeat(64),"stored_crc64":"0000000000000000",
        "computed_crc64":"0000000000000000","checksum_matches":true,"header_matches":true,
        "node_level":0,"row_count":0,"rejection":null})
    };
    let mut header = fixture();
    header["bootstrap"]["container_tables"] = json!({
        "profile":"synthetic test","limits":{"max_pages_per_tree":32,"max_total_pages":128,
            "max_rows_per_tree":4096,"max_depth":4},"pages_read":2,"bytes_read":32768,
        "trees":[{"checkpoint_lcn":40,"root_index":7,"table_id":11,"root_lcn_slots":[64,65,66,67],
            "expected_root_rows":0,"root_count_matches":true,"walk_finished":true,
            "pages":[page([64,65,66,67]),page([68,69,70,71])],"mappings":[],"rejection":null}],
        "failover_comparisons":[],"authoritative_checkpoint_selected":false,
        "metadata_verified":false,"allocation_verified":false,"conversion_profile_qualified":false
    });
    let ranges = refs_write_set::observed_anchors(&inspect(header.clone())).unwrap();
    assert!(ranges.contains(&ByteRange {
        offset: 71 * C,
        length: C
    }));
    header["bootstrap"]["container_tables"]["trees"][0]["pages"][1]["checksum_matches"] =
        json!(false);
    assert!(refs_write_set::observed_anchors(&inspect(header)).is_err());
}

#[test]
fn payload_coverage_reports_gaps_without_claiming_inventory_or_execution() {
    let map = AllocationMap {
        bitmap_sha256: "a".repeat(64),
        cluster_count: N,
        allocated_clusters: 4,
        ranges: vec![
            AllocatedRange {
                offset: 20 * C,
                length: 2 * C,
            },
            AllocatedRange {
                offset: 24 * C,
                length: 2 * C,
            },
        ],
    };
    let plan = refs_write_set::plan(N * C, C, &map, &[]).unwrap();
    let coverage = refs_write_set::payload_coverage(
        &plan,
        &[ByteRange {
            offset: 20 * C,
            length: 6 * C,
        }],
    )
    .unwrap();
    assert_eq!(coverage.payload_bytes, 6 * C);
    assert_eq!(coverage.uncovered_bytes, 2 * C);
    assert!(!coverage.all_supplied_payloads_covered);
    let coverage = refs_write_set::payload_coverage(
        &plan,
        &[
            ByteRange {
                offset: 24 * C,
                length: C,
            },
            ByteRange {
                offset: 20 * C,
                length: 2 * C,
            },
        ],
    )
    .unwrap();
    assert!(coverage.all_supplied_payloads_covered);
    assert!(
        !coverage.complete_payload_inventory_verified && !coverage.executable && !plan.executable
    );
    for ranges in [
        vec![
            ByteRange {
                offset: 20 * C,
                length: 2 * C,
            },
            ByteRange {
                offset: 21 * C,
                length: C,
            },
        ],
        vec![ByteRange {
            offset: 1,
            length: C,
        }],
        vec![ByteRange {
            offset: N * C,
            length: C,
        }],
        vec![ByteRange {
            offset: u64::MAX - 4095,
            length: 8192,
        }],
    ] {
        assert!(refs_write_set::payload_coverage(&plan, &ranges).is_err());
    }
}
