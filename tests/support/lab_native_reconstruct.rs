// Pure fixtures only: no native observer, volume, device or VM call is made.
use super::*;
use crate::{lab_reconstruct::JournalPatchRange, retained_compare::RetainedRangeRequest};
use n2r_win32::{
    journal_file::{JOURNAL_DISK_BYTES, JOURNAL_PARTITION_BYTES, JOURNAL_PARTITION_OFFSET},
    layout::{DISK_BYTES, DiskBinding, PARTITION_OFFSET},
};

fn guid(first: u8) -> String {
    format!("{first:08x}-1122-3344-aabb-123456789abc")
}
fn data(disk: u32, id: u8) -> DiskBinding {
    DiskBinding {
        disk_number: disk,
        volume_guid: guid(id + 2),
        identity: PartitionIdentity {
            disk_guid: guid(id),
            partition_guid: guid(id + 1),
            partition_number: 2,
            disk_bytes: DISK_BYTES,
            partition_offset: PARTITION_OFFSET,
            partition_bytes: PARTITION_BYTES,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        },
    }
}
fn request() -> NativeReconstructRequest {
    let experiment_id = "1234567890abcdef1234567890abcdef".to_string();
    NativeReconstructRequest {
        schema_version: 1,
        experiment_id: experiment_id.clone(),
        probe: ProbeRequest {
            schema_version: 1,
            experiment_id,
            fixture_evidence_sha256: "5".repeat(64),
            target: data(1, 10),
            shadow: data(3, 20),
            retained_offset: 8 * 1024 * 1024 * 1024,
            source_retained_sha256: "3".repeat(64),
            shadow_retained_sha256: "4".repeat(64),
        },
        comparison: RetainedCompareRequest {
            schema_version: 1,
            sector_size: 4096,
            expected_length: PARTITION_BYTES,
            source_sha256: "1".repeat(64),
            shadow_sha256: "2".repeat(64),
            retained_ranges: vec![RetainedRangeRequest {
                offset: 8 * 1024 * 1024 * 1024,
                length: 65536,
                source_sha256: "3".repeat(64),
                shadow_sha256: "4".repeat(64),
            }],
            max_change_bytes: MAX_CHANGE_BYTES,
            max_ranges: 65536,
        },
        journal: JournalStorageBinding {
            disk_number: 2,
            externally_enrolled_disk_unique_id: "600224806AAC261F021F249596F332FC".into(),
            volume_guid: guid(32),
            identity: PartitionIdentity {
                disk_guid: guid(30),
                partition_guid: guid(31),
                partition_number: 2,
                disk_bytes: JOURNAL_DISK_BYTES,
                partition_offset: JOURNAL_PARTITION_OFFSET,
                partition_bytes: JOURNAL_PARTITION_BYTES,
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
        },
        max_journal_bytes: MAX_JOURNAL_BYTES,
    }
}
fn journal_id(r: &NativeReconstructRequest) -> JournalFileIdentity {
    let p = &r.journal.identity;
    JournalFileIdentity {
        volume_serial_number: 0x1234567887654321,
        file_id_128: [0x91; 16],
        volume_guid: guid_bytes(&r.journal.volume_guid).unwrap(),
        disk_guid: guid_bytes(&p.disk_guid).unwrap(),
        partition_guid: guid_bytes(&p.partition_guid).unwrap(),
        partition_number: p.partition_number,
        disk_bytes: p.disk_bytes,
        partition_offset: p.partition_offset,
        partition_bytes: p.partition_bytes,
        logical_sector_bytes: p.logical_sector_bytes,
        physical_sector_bytes: p.physical_sector_bytes,
    }
}
fn snapshot(binding: &DiskBinding, attributes: u64) -> PartitionSnapshot {
    PartitionSnapshot {
        binding: binding.clone(),
        disk_attributes: attributes,
        device: vec![],
        length: vec![],
        alignment: vec![],
        layout: vec![],
    }
}
fn binding_for(r: &NativeReconstructRequest) -> JournalBinding {
    observed_binding(
        r,
        &snapshot(&r.probe.target, 1),
        &snapshot(&r.probe.shadow, 3),
        &journal_id(r),
    )
    .unwrap()
}
fn ticket(r: &NativeReconstructRequest) -> JournalTicket {
    JournalTicket {
        schema_version: 1,
        binding: binding_for(r),
        immutable_sha256: "a".repeat(64),
        immutable_length: 8192,
        journal_length: 16384,
    }
}
fn descriptor(r: &NativeReconstructRequest) -> JournalDescriptor {
    JournalDescriptor {
        binding: binding_for(r),
        request: r.comparison.clone(),
        patches: vec![
            JournalPatchRange {
                offset: 0,
                length: 4096,
            },
            JournalPatchRange {
                offset: 8192,
                length: 4096,
            },
        ],
        changed_bytes: 8192,
        expected_postimage_sha256: "b".repeat(64),
        immutable_sha256: "a".repeat(64),
    }
}

#[test]
fn native_profile_requires_the_exact_probe_retained_proof() {
    let good = request();
    good.validate().unwrap();
    for change in 0..15 {
        let mut r = good.clone();
        match change {
            0 => r.schema_version = 2,
            1 => r.experiment_id = "e".repeat(32),
            2 => r.comparison.expected_length -= 4096,
            3 => r.comparison.sector_size = 512,
            4 => r.comparison.max_change_bytes = MAX_CHANGE_BYTES + 4096,
            5 => r.max_journal_bytes = 0,
            6 => r.max_journal_bytes = MAX_JOURNAL_BYTES + 1,
            7 => r.comparison.retained_ranges.clear(),
            8 => r.comparison.retained_ranges[0].offset += 4096,
            9 => r.comparison.retained_ranges[0].length = 32768,
            10 => r.comparison.retained_ranges[0].source_sha256 = "e".repeat(64),
            11 => r.comparison.retained_ranges[0].shadow_sha256 = "e".repeat(64),
            12 => r.probe.target.identity.physical_sector_bytes = 512,
            13 => r.journal.disk_number = 1,
            _ => {
                let mut extra = r.comparison.retained_ranges[0].clone();
                extra.offset += 65536;
                r.comparison.retained_ranges.push(extra);
            }
        }
        assert!(r.validate().is_err(), "change {change}");
    }
}

#[test]
fn external_journal_cannot_alias_enrolled_data_storage() {
    for side in 0..2 {
        for field in 0..3 {
            let mut r = request();
            let data = if side == 0 {
                &r.probe.target
            } else {
                &r.probe.shadow
            };
            match field {
                0 => r.journal.identity.disk_guid = data.identity.disk_guid.clone(),
                1 => r.journal.identity.partition_guid = data.identity.partition_guid.clone(),
                _ => r.journal.volume_guid = data.volume_guid.clone(),
            }
            assert!(r.validate().is_err());
        }
    }
}

#[test]
fn canonical_storage_hashes_survive_case_and_route_changes() {
    let r = request();
    let original = binding_for(&r);
    let mut changed = r.clone();
    changed.probe.shadow.disk_number = 8;
    changed.probe.shadow.identity.disk_guid = format!(
        "{{{}}}",
        changed.probe.shadow.identity.disk_guid.to_uppercase()
    );
    changed.probe.target.identity.partition_guid = format!(
        "{{{}}}",
        changed.probe.target.identity.partition_guid.to_uppercase()
    );
    changed.journal.externally_enrolled_disk_unique_id = "different-external-enrollment".into();
    changed.validate().unwrap();
    assert_eq!(binding_for(&changed), original);
    let mut target = snapshot(&r.probe.target, 1);
    target.binding.identity.partition_guid = guid(99);
    assert!(observed_binding(&r, &target, &snapshot(&r.probe.shadow, 3), &journal_id(&r)).is_err());
    let mut j = journal_id(&r);
    j.file_id_128[0] ^= 1;
    let different = observed_binding(
        &r,
        &snapshot(&r.probe.target, 1),
        &snapshot(&r.probe.shadow, 3),
        &j,
    )
    .unwrap();
    assert_ne!(
        different.journal_identity_sha256,
        original.journal_identity_sha256
    );
    assert_ne!(
        original.target_identity_sha256,
        original.shadow_identity_sha256
    );
    assert_ne!(
        original.target_identity_sha256,
        original.journal_identity_sha256
    );
    // The same serialized bytes in another identity domain cannot collide by
    // accidentally reusing a structurally similar ticket field.
    assert_ne!(
        identity_hash(b"partition", &j).unwrap(),
        identity_hash(b"journal", &j).unwrap()
    );
}

#[test]
fn binding_requires_both_expected_offline_attributes() {
    let r = request();
    for (target, shadow) in [(0, 3), (3, 3), (1, 0), (1, 1), (1, 2)] {
        assert!(
            observed_binding(
                &r,
                &snapshot(&r.probe.target, target),
                &snapshot(&r.probe.shadow, shadow),
                &journal_id(&r)
            )
            .is_err()
        );
    }
}

#[test]
fn ticket_preflight_rejects_foreign_experiment_geometry_pins_and_sizes() {
    let r = request();
    let good = ticket(&r);
    preflight_ticket(&r, &good).unwrap();
    for change in 0..9 {
        let mut t = good.clone();
        match change {
            0 => t.schema_version = 2,
            1 => t.binding.experiment_id = "e".repeat(32),
            2 => t.binding.target_identity_sha256 = "e".repeat(64),
            3 => t.binding.shadow_identity_sha256 = "e".repeat(64),
            4 => t.binding.journal_identity_sha256 = "A".repeat(64),
            5 => t.immutable_sha256 = "x".repeat(64),
            6 => t.journal_length = MAX_JOURNAL_BYTES + 1,
            7 => t.immutable_length = u64::MAX,
            _ => {
                t.immutable_length = 255;
                t.journal_length = 8447;
            }
        }
        assert!(preflight_ticket(&r, &t).is_err(), "change {change}");
    }
    let mut t = good;
    t.journal_length += 1;
    assert!(preflight_ticket(&r, &t).is_err());
}

#[test]
fn only_the_complete_inspected_patch_set_can_be_armed() {
    let r = request();
    let d = descriptor(&r);
    let policy = write_policy(&r, &d).unwrap().unwrap();
    assert_eq!(policy.allowed, [(0, 4096), (8192, 4096)]);
    assert_eq!(policy.retained, [(r.probe.retained_offset, 65536)]);
    assert_eq!(policy.maximum_bytes, 8192);
    for change in 0..11 {
        let mut d = descriptor(&r);
        match change {
            0 => d.request.source_sha256 = "e".repeat(64),
            1 => d.request.max_ranges -= 1,
            2 => d.changed_bytes += 4096,
            3 => d.patches[0].offset = 1,
            4 => d.patches[0].length = 1,
            5 => d.patches[0].offset = r.probe.retained_offset,
            6 => d.patches[1].offset = 0,
            7 => d.patches[1].offset = PARTITION_BYTES,
            8 => {
                d.patches[0].length = MAX_CHANGE_BYTES;
                d.changed_bytes = MAX_CHANGE_BYTES + 4096;
            }
            9 => {
                d.patches[0].length = u64::MAX;
                d.changed_bytes = u64::MAX;
            }
            _ => d.patches.clear(),
        }
        assert!(write_policy(&r, &d).is_err(), "change {change}");
    }
    let mut zero = descriptor(&r);
    zero.patches.clear();
    zero.changed_bytes = 0;
    assert!(write_policy(&r, &zero).unwrap().is_none());
    let mut retained = descriptor(&r);
    retained.patches = vec![JournalPatchRange {
        offset: r.probe.retained_offset,
        length: 4096,
    }];
    retained.changed_bytes = 4096;
    assert!(write_policy(&r, &retained).is_err());
}

#[test]
fn failed_reports_preserve_phase_and_handoff_uncertainty() {
    let r = request();
    let mut report = NativeReconstructReport::new(&r, "handoff");
    report.phase = "execute-handoff".into();
    report.handoff_request_may_have_been_issued = true;
    report.journal_write_requests_may_have_been_issued = true;
    report.finish(Err(anyhow::anyhow!("simulated torn handoff")), None, None);
    assert!(
        !report.success
            && !report.online_transition_requested
            && !report.conversion_qualified
            && !report.boot_qualified
    );
    assert!(!report.disks_observed_offline_at_end && !report.payload_write_requests_issued);
    assert!(
        report.handoff_request_may_have_been_issued
            && report.journal_write_requests_may_have_been_issued
    );
    assert_eq!(report.phase, "execute-handoff");
    assert!(report.error.unwrap().contains("simulated torn handoff"));
}
