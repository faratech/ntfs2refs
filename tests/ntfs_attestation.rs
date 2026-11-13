#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use n2r_win32::attestation::{FileIdentity, Observation, Query, Report, Request, Snapshot};
use ntfs2refs::{
    ntfs_attestation::{compare, same_security},
    ntfs_inspect, ntfs_security as sec,
};
use std::io::Cursor;
fn p32(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], o: usize, n: u64) {
    b[o..o + 8].copy_from_slice(&n.to_le_bytes());
}
fn request() -> Request {
    Request {
        extent_identity_streams: vec![],
        schema_version: 1,
        resource_profile: None,
        source_inspection_sha256: "a".repeat(64),
        volume: "\\\\?\\Volume{12345678-1234-5678-1234-567812345678}\\".into(),
        disk_number: 1,
        partition_offset: 16 * 1024 * 1024,
        partition_length: 2 * 1024 * 1024,
        ntfs_serial: 0x1122334455667788,
        files: vec![FileIdentity {
            record_number: 16,
            sequence_number: 1,
        }],
    }
}
fn descriptor(repacked: bool) -> Vec<u8> {
    let mut b = vec![0; 40];
    b[0] = 1;
    b[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let (owner, dacl) = if repacked { (28, 20) } else { (20, 32) };
    p32(&mut b, 4, owner as u32);
    p32(&mut b, 16, dacl as u32);
    b[owner..owner + 12].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    b[dacl] = 2;
    b[dacl + 2..dacl + 4].copy_from_slice(&8u16.to_le_bytes());
    b
}
#[test]
fn descriptor_repacking_preserves_semantics() {
    assert!(same_security(&descriptor(false), &descriptor(true)).unwrap());
}
#[test]
fn owner_change_is_not_equivalent() {
    let mut b = descriptor(true);
    b[36] = 19;
    assert!(!same_security(&descriptor(false), &b).unwrap());
}
#[test]
fn null_and_empty_acl_are_distinct() {
    let a = descriptor(false);
    let mut b = a.clone();
    p32(&mut b, 16, 0);
    assert!(!same_security(&a, &b).unwrap());
}
#[test]
fn malformed_descriptor_is_refused() {
    assert!(same_security(&descriptor(false), &[0; 20]).is_err());
}
#[test]
fn rejects_unbounded_or_ambiguous_requests() {
    let r = request();
    r.validate().unwrap();
    let mut cases = vec![];
    let mut b = r.clone();
    b.volume = "C:\\".into();
    cases.push(b);
    let mut b = r.clone();
    b.volume = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\".into();
    cases.push(b);
    let mut b = r.clone();
    b.disk_number = 0;
    cases.push(b);
    let mut b = r.clone();
    b.files.push(b.files[0].clone());
    cases.push(b);
    let mut b = r.clone();
    b.files[0].record_number = 1 << 48;
    cases.push(b);
    let mut b = r.clone();
    b.files[0].sequence_number = 0;
    cases.push(b);
    let mut b = r.clone();
    b.partition_offset = u64::MAX;
    cases.push(b);
    let mut b = r.clone();
    b.partition_length = 0;
    cases.push(b);
    let mut b = r.clone();
    b.source_inspection_sha256 = "A".repeat(64);
    cases.push(b);
    for b in cases {
        assert!(b.validate().is_err());
    }
}
fn fixture() -> (ntfs_inspect::NtfsInspection, Report) {
    let bytes = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    // Deliberately isolated one-file diagnostic; it never grants source admission.
    raw.files.retain(|f| f.record_number == 16);
    let r = request();
    let file = &raw.files[0];
    assert_eq!(file.sequence_number, 1);
    let d = sec::parse_descriptor(&descriptor(false)).unwrap();
    raw.security_reconciliation = Some(sec::Reconciliation {
        status: sec::Status::ConsistentRawModel,
        metadata_bytes_read: 40,
        central_descriptors: 1,
        legacy_descriptors: 0,
        sii_entries: 1,
        sdh_entries: 1,
        index_blocks: 0,
        bound_files: 1,
        evidence_sha256: "b".repeat(64),
        detail: "synthetic isolated test".into(),
        descriptors: vec![sec::DescriptorRecord {
            security_id: Some(256),
            legacy_record: None,
            sds_offset: Some(0),
            ntfs_hash: None,
            descriptor: d.clone(),
        }],
        bindings: vec![sec::Binding {
            record_number: 16,
            sequence_number: 1,
            security_id: Some(256),
            descriptor_sha256: d.sha256,
        }],
    });
    let mut basic = vec![0; 40];
    p64(&mut basic, 0, 1234);
    p32(&mut basic, 32, 32);
    let mut standard = vec![0; 24];
    p64(&mut standard, 0, 4096);
    p64(&mut standard, 8, 17);
    p32(&mut standard, 16, 2);
    let mut id = vec![0; 24];
    p64(&mut id, 0, r.ntfs_serial);
    p64(&mut id, 8, r.files[0].reference());
    let mut tag = vec![0; 8];
    p32(&mut tag, 0, 32);
    let s = Snapshot {
        // An observed absence: the raw model records one, so the native side must too.
        extended_attributes: Some(Default::default()),
        extended_attributes_error: None,
        reparse: None,
        directory_case_sensitivity: None,
        queries: vec![
            Query {
                class: 0,
                bytes: basic,
                native_error: None,
            },
            Query {
                class: 1,
                bytes: standard,
                native_error: None,
            },
            Query {
                class: 18,
                bytes: id,
                native_error: None,
            },
            Query {
                class: 9,
                bytes: tag,
                native_error: None,
            },
        ],
        security: descriptor(true),
        security_error: None,
        kernel_security: Some(n2r_win32::attestation::SecurityQuery {
            bytes: descriptor(false),
            native_error: None,
        }),
    };
    let mut ext = vec![0; 32];
    p32(&mut ext, 0, 1);
    p32(&mut ext, 8, 1);
    p64(&mut ext, 16, r.partition_offset);
    p64(&mut ext, 24, r.partition_length);
    let mut data = vec![0; 96];
    p64(&mut data, 0, r.ntfs_serial);
    p64(&mut data, 8, raw.geometry.total_sectors);
    p64(&mut data, 16, raw.geometry.total_clusters);
    p32(&mut data, 40, 512);
    p32(&mut data, 44, 4096);
    p32(&mut data, 48, 1024);
    p64(&mut data, 64, raw.geometry.mft_lcn);
    p64(&mut data, 72, raw.geometry.mftmirr_lcn);
    let mut attrs = vec![0; 16];
    p32(&mut attrs, 0, 16);
    p64(&mut attrs, 8, 2);
    let report = Report {
        content_passes: 2,
        resources: None,
        namespace: None,
        schema_version: 2,
        request: r.clone(),
        volume_extents_before: ext.clone(),
        volume_extents_after: ext,
        ntfs_data_before: data.clone(),
        ntfs_data_after: data,
        disk_attributes_before: attrs.clone(),
        disk_attributes_after: attrs,
        write_protect_error_before: 19,
        write_protect_error_after: 19,
        privileges_restored: true,
        privilege_states: ["SeBackupPrivilege", "SeSecurityPrivilege"]
            .into_iter()
            .map(|name| n2r_win32::attestation::PrivilegeState {
                name: name.into(),
                before: 0,
                enabled: 2,
                restored: 0,
            })
            .collect(),
        files: vec![Observation {
            case_only_fallback: None,
            identity: r.files[0].clone(),
            open_error: None,
            before: Some(s.clone()),
            after: Some(s),
            streams_before: None,
            streams_after: None,
        }],
        conversion_qualified: false,
        allocation: None,
        logical_data: None,
    };
    (raw, report)
}
#[test]
fn matched_native_metadata_is_still_diagnostic() {
    let (raw, r) = fixture();
    let c = compare(&raw, &"a".repeat(64), &r).unwrap();
    assert!(c.all_requested_metadata_matched, "{:?}", c.files);
    assert!(!c.conversion_qualified);
}

#[test]
fn legacy_report_schemas_cannot_smuggle_bitmap_continuations() {
    use n2r_win32::attestation::{IoctlQuery, VolumeAllocation};
    let (raw, report) = fixture();
    let query = IoctlQuery {
        code: n2r_win32::stream_layout::GET_BITMAP,
        input: vec![0; 8],
        bytes: vec![],
        native_error: None,
    };
    for schema in 2..=5 {
        for before in [false, true] {
            let mut altered = report.clone();
            altered.schema_version = schema;
            altered.allocation = Some(VolumeAllocation {
                base_before: query.clone(),
                base_after: query.clone(),
                bitmap_before: query.clone(),
                bitmap_after: query.clone(),
                bitmap_before_continuation: if before { vec![query.clone()] } else { vec![] },
                bitmap_after_continuation: if before { vec![] } else { vec![query.clone()] },
                streamed_before: None,
                streamed_after: None,
            });
            let error = compare(&raw, &"a".repeat(64), &altered)
                .unwrap_err()
                .to_string();
            assert!(error.contains("paged bitmap transcripts require native schema 6"));
        }
    }
}

#[test]
fn legacy_report_schemas_cannot_smuggle_retrieval_continuations() {
    use n2r_win32::attestation::{IoctlQuery, StreamCapture, StreamQuery};
    let (raw, report) = fixture();
    let stream = StreamCapture {
        enumeration: Query {
            class: 7,
            bytes: vec![],
            native_error: None,
        },
        parse_error: None,
        streams: vec![StreamQuery {
            name_utf16: vec![],
            logical_size: 0,
            allocated_size: 0,
            open_error: None,
            binding_error: None,
            identity_before: None,
            identity_after: None,
            retrieval: None,
            retrieval_continuation: vec![IoctlQuery {
                code: n2r_win32::stream_layout::GET_RETRIEVAL,
                input: vec![0; 8],
                bytes: vec![],
                native_error: None,
            }],
        }],
    };
    for schema in 2..=6 {
        for before in [false, true] {
            let mut altered = report.clone();
            altered.schema_version = schema;
            if before {
                altered.files[0].streams_before = Some(stream.clone());
            } else {
                altered.files[0].streams_after = Some(stream.clone());
            }
            let error = compare(&raw, &"a".repeat(64), &altered)
                .unwrap_err()
                .to_string();
            assert!(error.contains("paged retrieval transcripts require native schema 7"));
        }
    }
}

fn request_inputs() -> (
    ntfs2refs::planner::Inspection,
    n2r_win32::layout::DiskBinding,
) {
    use n2r_win32::layout::{
        DISK_BYTES, DiskBinding, PARTITION_BYTES, PARTITION_OFFSET, PartitionIdentity,
    };
    let (mut raw, _) = fixture();
    raw.geometry.volume_size = PARTITION_BYTES - 512;
    raw.geometry.serial_number = u64::MAX;
    let inspection = ntfs2refs::planner::Inspection {
        schema_version: 1,
        source: ntfs2refs::block_io::SourceIdentity {
            path: "source.raw".into(),
            length: PARTITION_BYTES,
            sha256: "b".repeat(64),
        },
        filesystem: ntfs2refs::planner::Filesystem::Ntfs(raw),
    };
    let binding = DiskBinding {
        disk_number: 1,
        volume_guid: "12345678-1234-5678-1234-567812345678".into(),
        identity: PartitionIdentity {
            disk_guid: "22345678-1234-5678-1234-567812345678".into(),
            partition_guid: "32345678-1234-5678-1234-567812345678".into(),
            partition_number: 2,
            disk_bytes: DISK_BYTES,
            partition_offset: PARTITION_OFFSET,
            partition_bytes: PARTITION_BYTES,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        },
    };
    (inspection, binding)
}
#[test]
fn generated_request_preserves_unsigned_64_bit_serial_and_all_identities() {
    let (inspection, binding) = request_inputs();
    let request =
        ntfs2refs::ntfs_attestation::request_for_inspection(&inspection, &"a".repeat(64), &binding)
            .unwrap();
    let bytes = serde_json::to_vec(&request).unwrap();
    let roundtrip: Request = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(roundtrip.ntfs_serial, u64::MAX);
    assert_eq!(roundtrip.files, request.files);
    assert_eq!(
        roundtrip.volume,
        format!("\\\\?\\Volume{{{}}}\\", binding.volume_guid)
    );
}
#[test]
fn request_generation_refuses_source_length_mismatch_and_invalid_pins() {
    let (mut inspection, binding) = request_inputs();
    assert!(
        ntfs2refs::ntfs_attestation::request_for_inspection(&inspection, "not-a-hash", &binding)
            .is_err()
    );
    inspection.source.length -= 4096;
    assert!(
        ntfs2refs::ntfs_attestation::request_for_inspection(&inspection, &"a".repeat(64), &binding)
            .is_err()
    );
}
#[test]
fn missing_file_observation_is_refused() {
    let (raw, mut r) = fixture();
    r.files.clear();
    assert!(compare(&raw, &"a".repeat(64), &r).is_err());
}
#[test]
fn stale_identity_never_matches() {
    let (raw, mut r) = fixture();
    let obs = &mut r.files[0];
    for s in [&mut obs.before, &mut obs.after].into_iter().flatten() {
        s.queries[2].bytes[14] ^= 1;
    }
    let c = compare(&raw, &"a".repeat(64), &r).unwrap();
    assert_eq!(c.matched_files, 0);
}
#[test]
fn rejected_system_open_remains_visible() {
    let (raw, mut r) = fixture();
    r.files[0].open_error = Some(5);
    r.files[0].before = None;
    r.files[0].after = None;
    let c = compare(&raw, &"a".repeat(64), &r).unwrap();
    assert_eq!(c.opened_files, 0);
    assert_eq!(c.matched_files, 0);
    assert!(c.files[0].issues[0].contains("error 5"));
}
#[test]
fn changed_native_security_never_matches() {
    let (raw, mut r) = fixture();
    r.files[0].after.as_mut().unwrap().security[36] = 19;
    assert_eq!(compare(&raw, &"a".repeat(64), &r).unwrap().matched_files, 0);
}
#[test]
fn writable_or_changed_volume_is_refused() {
    let (raw, mut r) = fixture();
    r.write_protect_error_after = 0;
    assert!(compare(&raw, &"a".repeat(64), &r).is_err());
    let (_, mut r) = fixture();
    r.disk_attributes_after[8] = 0;
    assert!(compare(&raw, &"a".repeat(64), &r).is_err());
}
#[test]
fn missing_kernel_query_does_not_pass() {
    let (raw, mut r) = fixture();
    r.files[0].before.as_mut().unwrap().kernel_security = None;
    assert_eq!(compare(&raw, &"a".repeat(64), &r).unwrap().matched_files, 0);
}
#[test]
fn changed_kernel_security_does_not_pass() {
    let (raw, mut r) = fixture();
    r.files[0]
        .after
        .as_mut()
        .unwrap()
        .kernel_security
        .as_mut()
        .unwrap()
        .bytes[28] = 19;
    assert_eq!(compare(&raw, &"a".repeat(64), &r).unwrap().matched_files, 0);
}
#[test]
fn incorrect_privilege_restoration_is_refused() {
    let (raw, mut r) = fixture();
    r.privilege_states[0].restored = 2;
    assert!(compare(&raw, &"a".repeat(64), &r).is_err());
}
#[test]
fn sacl_protection_is_not_masked() {
    let a = descriptor(false);
    let mut b = a.clone();
    b[3] |= 0x20;
    assert!(!same_security(&a, &b).unwrap());
}
#[test]
fn inherited_ace_flags_are_not_masked() {
    let mut a = descriptor(false);
    a.extend([
        0, 0, 20, 0, 0xff, 1, 0x1f, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
    ]);
    a[34..36].copy_from_slice(&28u16.to_le_bytes());
    a[36..38].copy_from_slice(&1u16.to_le_bytes());
    let mut b = a.clone();
    b[41] = 0x10;
    assert!(!same_security(&a, &b).unwrap());
}

#[test]
fn a_null_sacl_marked_present_equals_no_sacl_and_nothing_else_is_relaxed() {
    use ntfs2refs::ntfs_attestation::{
        same_security, same_security_null_sacl_as_absent as relaxed,
    };
    // \System Volume Information on the NTFS source (control 0x9004)...
    let source = hex::decode("010004903000000040000000000000001400000002001c000100000000031400ff011f0001010000000000051200000001020000000000052000000020020000010100000000000512000000").unwrap();
    // ...and on ReFS after restore: same owner, group and DACL, plus "SACL present" with a null SACL.
    let mut refs = hex::decode("01001498140000002400000000000000300000000102000000000005200000002002000001010000000000051200000002001c000100000000031400ff011f00010100000000000512000000").unwrap();
    refs[2..4].copy_from_slice(&0x9014u16.to_le_bytes());
    assert!(!same_security(&source, &refs).unwrap());
    assert!(relaxed(&source, &refs).unwrap());
    assert!(relaxed(&refs, &source).unwrap());
    assert!(relaxed(&source, &source).unwrap());
    // The auto-inherited flag is still a difference.
    let mut inherited = refs.clone();
    inherited[2..4].copy_from_slice(&0x9814u16.to_le_bytes());
    assert!(!relaxed(&source, &inherited).unwrap());
    // So is DACL protection.
    let mut unprotected = refs.clone();
    unprotected[2..4].copy_from_slice(&0x8014u16.to_le_bytes());
    assert!(!relaxed(&source, &unprotected).unwrap());
}
