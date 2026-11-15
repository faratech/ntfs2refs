#![cfg(windows)]
use n2r_win32::layout::{
    DISK_BYTES, DiskBinding, PARTITION_BYTES, PARTITION_OFFSET, PartitionIdentity,
};
use ntfs2refs::lab_native::{ProbeRequest, probe};

fn request() -> ProbeRequest {
    fn binding(number: u32, disk: &str, partition: &str, volume: &str) -> DiskBinding {
        DiskBinding {
            disk_number: number,
            volume_guid: volume.into(),
            identity: PartitionIdentity {
                disk_guid: disk.into(),
                partition_guid: partition.into(),
                partition_number: 2,
                disk_bytes: DISK_BYTES,
                partition_offset: PARTITION_OFFSET,
                partition_bytes: PARTITION_BYTES,
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
        }
    }
    ProbeRequest {
        schema_version: 1,
        experiment_id: "a".repeat(32),
        fixture_evidence_sha256: "b".repeat(64),
        target: binding(
            1,
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
        ),
        shadow: binding(
            3,
            "44444444-4444-4444-4444-444444444444",
            "55555555-5555-5555-5555-555555555555",
            "66666666-6666-6666-6666-666666666666",
        ),
        retained_offset: 8 * 1024 * 1024 * 1024,
        source_retained_sha256: "c".repeat(64),
        shadow_retained_sha256: "d".repeat(64),
    }
}

#[test]
fn probe_schema_rejects_foreign_routes_aliases_and_overflow_without_native_calls() {
    request().validate().unwrap();
    let mut variants = Vec::new();
    let mut bad = request();
    bad.retained_offset = u64::MAX;
    variants.push(bad);
    let mut bad = request();
    bad.retained_offset += 1;
    variants.push(bad);
    let mut bad = request();
    bad.target.disk_number = 0;
    variants.push(bad);
    let mut bad = request();
    bad.shadow.identity.disk_guid = format!("{{{}}}", bad.target.identity.disk_guid);
    variants.push(bad);
    let mut bad = request();
    bad.shadow_retained_sha256 = bad.source_retained_sha256.clone();
    variants.push(bad);
    let mut bad = request();
    bad.target.identity.partition_offset = 0;
    variants.push(bad);
    for bad in variants {
        assert!(bad.validate().is_err());
        let result = probe(bad, false, false);
        assert!(!result.success);
        assert_eq!(result.phase, "validate");
        assert!(result.events.is_empty());
        assert!(!result.payload_write_requests_issued);
        assert_eq!(result.target_bytes_read, 0);
    }
}
