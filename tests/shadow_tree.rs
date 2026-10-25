#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use ntfs2refs::{ntfs_inspect as n, ntfs_security as s, shadow_tree};
use std::io::Cursor;

// Synthetic semantic input only. Native qualification always re-inspects the
// actual excluded device and rehashes it; these flags cannot admit a volume.
fn model() -> n::NtfsInspection {
    let bytes = support::image();
    let mut raw = n::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    let mut file = raw
        .files
        .iter()
        .find(|f| f.record_number == 16)
        .unwrap()
        .clone();
    file.metadata_role = n::MetadataRole::OutsideExtendCandidate;
    file.metadata_role_issue = None;
    file.hard_link_count = 1;
    file.names.truncate(1);
    file.names[0].name = "payload.bin".into();
    file.names[0].name_utf16 = "payload.bin".encode_utf16().collect();
    file.names[0].parent_record_number = 5;
    file.names[0].parent_sequence_number = 1;
    file.streams.retain(|s| s.name_utf16.is_empty());
    let stream = &mut file.streams[0];
    stream.logical_size = 65536;
    stream.initialized_size = 65536;
    stream.allocated_size = 65536;
    stream.extents[0].length = 65536;
    stream.logical_hash_status = n::LogicalHashStatus::Complete;
    stream.logical_sha256 = Some("a".repeat(64));
    file.attributes.retain(|a| a.name_utf16.is_empty());
    let si = file.standard_information.as_mut().unwrap();
    si.creation_time = 101;
    si.access_time = 102;
    si.modification_time = 103;
    si.mft_change_time = 104;
    let mut root = file.clone();
    root.record_number = 5;
    root.is_directory = true;
    root.metadata_role = n::MetadataRole::ReservedSystemRecord;
    root.names[0].name_utf16 = vec![46];
    root.streams.clear();
    root.attributes.retain(|a| a.type_code != 0x80);
    raw.files = vec![file, root]; // Derivation must sort parent before child.
    raw.records_scanned = raw.files.len() as u64;
    raw.allocation_reconciliation.as_mut().unwrap().status =
        n::AllocationReconciliationStatus::ConsistentRawModel;
    raw.namespace_reconciliation.as_mut().unwrap().status =
        ntfs2refs::ntfs_namespace::Status::ConsistentRawModel;
    let descriptor = s::parse_descriptor(&hex::decode("0100049448000000580000000000000014000000020034000200000000001400ff011f0001010000000000051200000000001800ff011f00010200000000000520000000200200000102000000000005200000002002000001020000000000052000000020020000").unwrap()).unwrap();
    raw.security_reconciliation = Some(s::Reconciliation {
        status: s::Status::ConsistentRawModel,
        metadata_bytes_read: 0,
        central_descriptors: 1,
        legacy_descriptors: 0,
        sii_entries: 1,
        sdh_entries: 1,
        index_blocks: 0,
        bound_files: 2,
        evidence_sha256: "b".repeat(64),
        detail: "synthetic semantic test input".into(),
        bindings: raw
            .files
            .iter()
            .map(|f| s::Binding {
                record_number: f.record_number,
                sequence_number: f.sequence_number,
                security_id: None,
                descriptor_sha256: descriptor.sha256.clone(),
            })
            .collect(),
        descriptors: vec![s::DescriptorRecord {
            security_id: None,
            legacy_record: None,
            sds_offset: None,
            ntfs_hash: None,
            descriptor,
        }],
    });
    raw
}
#[test]
fn derives_stored_times_and_physical_payload_without_native_write_authority() {
    let raw = model();
    let t = shadow_tree::derive(&raw).unwrap();
    assert!(t.objects[0].path.is_empty());
    assert_eq!(t.objects[1].path, ["payload.bin"]);
    assert_eq!(t.objects[1].stored_times, [101, 102, 103, 104]);
    assert_eq!(
        t.objects[1].source_offset,
        raw.files[0].streams[0].extents[0].physical_offset
    );
    assert_eq!(t.logical_bytes, 65536);
}
#[test]
fn inconsistent_raw_views_missing_security_and_stale_parent_are_refused() {
    let raw = model();
    let mut b = raw.clone();
    b.records_scanned += 1;
    assert!(shadow_tree::derive(&b).is_err());
    let mut b = raw.clone();
    b.allocation_reconciliation.as_mut().unwrap().status =
        n::AllocationReconciliationStatus::Rejected;
    assert!(shadow_tree::derive(&b).is_err());
    let mut b = raw.clone();
    b.namespace_reconciliation.as_mut().unwrap().status =
        ntfs2refs::ntfs_namespace::Status::Rejected;
    assert!(shadow_tree::derive(&b).is_err());
    let mut b = raw.clone();
    b.security_reconciliation.as_mut().unwrap().bindings.pop();
    assert!(shadow_tree::derive(&b).is_err());
    let mut b = raw.clone();
    b.files[0].names[0].parent_sequence_number += 1;
    assert!(shadow_tree::derive(&b).is_err());
}
#[test]
fn resident_sparse_tail_and_extra_streams_do_not_become_shadow_support() {
    for mutation in 0..4 {
        let mut b = model();
        let file = &mut b.files[0];
        match mutation {
            0 => file.streams[0].resident = true,
            1 => file.streams[0].extents[0].physical_offset = None,
            2 => file.streams[0].initialized_size -= 1,
            _ => file.streams.push(file.streams[0].clone()),
        }
        assert!(shadow_tree::derive(&b).is_err());
    }
}
#[test]
fn duplicate_destination_and_overlapping_source_ownership_are_refused() {
    let mut b = model();
    let mut extra = b.files[0].clone();
    extra.record_number += 1;
    b.files.push(extra);
    assert!(shadow_tree::derive(&b).is_err());
    let mut extra = b.files.pop().unwrap();
    extra.names[0].name_utf16 = "other.bin".encode_utf16().collect();
    let mut binding = b.security_reconciliation.as_ref().unwrap().bindings[0].clone();
    binding.record_number = extra.record_number;
    b.security_reconciliation
        .as_mut()
        .unwrap()
        .bindings
        .push(binding);
    b.files.push(extra);
    assert!(shadow_tree::derive(&b).is_err());
}
#[test]
fn metadata_label_cannot_hide_unknown_objects_and_root_attributes() {
    let mut b = model();
    b.files[0].is_metadata = true;
    b.files[0].metadata_role = n::MetadataRole::NotClassified;
    assert!(shadow_tree::derive(&b).is_err());
    let mut b = model();
    b.files[1].attributes[0].type_code = 0x40;
    assert!(shadow_tree::derive(&b).is_err());
}
#[test]
#[ignore = "requires the pinned frozen natural-tree inspection; reads metadata only"]
fn pinned_existing_tree_has_four_unarranged_streams_and_all_stored_metadata() {
    use sha2::{Digest, Sha256};
    let bytes =
        std::fs::read(".lab/hyperv/existing-tree/win11-20261024T195711446Z/freeze.inspection.json")
            .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "29d97ef4498f33933ec3702a3e9aee6e81fc4084d60c797ff4d0018208b8ab5e"
    );
    let inspection: ntfs2refs::planner::Inspection = serde_json::from_slice(&bytes).unwrap();
    let ntfs2refs::planner::Filesystem::Ntfs(raw) = inspection.filesystem else {
        panic!("not NTFS")
    };
    let tree = shadow_tree::derive(&raw).unwrap();
    assert_eq!(tree.objects.len(), 8);
    assert_eq!(tree.logical_bytes, 524288);
    let offsets: Vec<_> = tree
        .objects
        .iter()
        .filter_map(|o| o.source_offset)
        .collect();
    for lcn in [6263, 6280, 6328, 6344] {
        assert!(offsets.contains(&(lcn * 4096)));
    }
    assert!(
        tree.internal_replacement_pending
            .iter()
            .any(|s| s.contains("$TXF_DATA"))
    );
}
