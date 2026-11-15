#[allow(dead_code, reason = "Shared synthetic parser fixture")]
use crate::support;
use n2r_win32::content_digest::HEX_LEN;
use ntfs2refs::{ntfs_inspect as n, ntfs_security as s, shadow_tree};
use std::io::Cursor;

// Positions in `model().files`, which are in record order as derivation requires.
const ROOT: usize = 0;
const FILE: usize = 1;

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
    stream.logical_sha256 = Some("a".repeat(HEX_LEN));
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
    raw.files = vec![root, file]; // Record 5 before record 16.
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
/// The model for a test of refusals: it must itself be accepted, or every
/// `is_err()` below would hold whatever the test went on to change.
fn valid_model() -> n::NtfsInspection {
    let raw = model();
    shadow_tree::derive(&raw).expect("the unmutated model derives");
    shadow_tree::derive_ordinary(&raw).expect("the unmutated model derives as an ordinary tree");
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
        raw.files[FILE].streams[0].extents[0].physical_offset
    );
    assert_eq!(t.logical_bytes, 65536);
}
#[test]
fn alpha_stream_plan_keeps_the_existing_serialized_contract() {
    let plan = ntfs2refs::ntfs_stream_plan::classify(&model());
    let expected = serde_json::json!({
        "schema_version": 4,
        "profile": "ntfs-4k-to-refs-4k-source-streams-v4",
        "streams": [{
            "record_number": 16,
            "sequence_number": 1,
            "name_utf16": [],
            "logical_bytes": 65536,
            "logical_sha256": "a".repeat(HEX_LEN),
            "source_offset": 100 * 4096,
            "disposition": "retain_candidate",
            "target_named_stream_support_pending": false,
            "reason": "initialized aligned physical runs may be adopted"
        }],
        "retained_candidate_bytes": 65536,
        "materialized_candidate_bytes": 0,
        "rejected_streams": 0,
        "source_admitted": false,
        "executable": false
    });
    assert_eq!(serde_json::to_value(plan).unwrap(), expected);
}

#[test]
fn larger_stream_plan_refuses_the_1025th_user_file() {
    use ntfs2refs::{ntfs_admission::ResourceProfile, ntfs_stream_plan};
    let mut raw = model();
    let template = raw.files[FILE].clone();
    for index in 0..1024 {
        let mut file = template.clone();
        file.record_number = 17 + index;
        let stream = &mut file.streams[0];
        stream.logical_size = 0;
        stream.initialized_size = 0;
        stream.allocated_size = 0;
        stream.extents.clear();
        raw.files.push(file);
    }
    let plan = ntfs_stream_plan::classify_with_resource_profile(
        &raw,
        ResourceProfile::ExperimentalLargeTreeV1,
    );
    assert_eq!(plan.streams.len(), 1025);
    assert_eq!(plan.rejected_streams, 1);
    assert_eq!(
        plan.streams[1024].disposition,
        ntfs_stream_plan::Disposition::Reject
    );
    assert!(!plan.source_admitted && !plan.executable);
}

#[test]
fn larger_tree_is_opt_in_and_rejected_by_the_legacy_target_contract() {
    use ntfs2refs::{ntfs_admission::ResourceProfile, ntfs_stream_plan};
    let mut raw = model();
    raw.geometry.volume_size = 8 << 30;
    let stream = &mut raw.files[FILE].streams[0];
    stream.logical_size = 2 << 30;
    stream.initialized_size = stream.logical_size;
    stream.allocated_size = stream.logical_size;
    stream.extents[0].physical_offset = Some(4096 * 100);
    stream.extents[0].length = stream.logical_size;
    assert!(shadow_tree::derive_ordinary(&raw).is_err());
    let selected = ResourceProfile::ExperimentalLargeTreeV1;
    let plan = ntfs_stream_plan::classify_with_resource_profile(&raw, selected);
    assert_eq!(plan.retained_candidate_bytes, 2 << 30);
    assert_eq!(plan.rejected_streams, 0);
    assert!(!plan.source_admitted && !plan.executable);
    let tree = shadow_tree::derive_ordinary_with_resource_profile(&raw, selected).unwrap();
    let expected = shadow_tree::ExpectedTree::from(&tree);
    assert_eq!(tree.profile, "native-ordinary-tree-shadow-large-v1");
    assert!(expected.validate().is_err());
    expected.validate_with_resource_profile(selected).unwrap();
    let alpha_expected =
        shadow_tree::ExpectedTree::from(&shadow_tree::derive_ordinary(&model()).unwrap());
    assert!(
        alpha_expected
            .validate_with_resource_profile(selected)
            .is_err()
    );
    let alpha = model();
    assert_eq!(
        serde_json::to_vec(&ntfs_stream_plan::classify(&alpha)).unwrap(),
        serde_json::to_vec(&ntfs_stream_plan::classify_with_resource_profile(
            &alpha,
            ResourceProfile::AlphaV1
        ))
        .unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&shadow_tree::derive_ordinary(&alpha).unwrap()).unwrap(),
        serde_json::to_vec(
            &shadow_tree::derive_ordinary_with_resource_profile(&alpha, ResourceProfile::AlphaV1)
                .unwrap()
        )
        .unwrap()
    );
}

#[test]
fn large_stream_planning_checks_aggregate_bounds_and_keeps_encoding_refusals() {
    use ntfs2refs::{
        ntfs_admission::ResourceProfile,
        ntfs_stream_plan::{self, Disposition},
    };
    let selected = ResourceProfile::ExperimentalLargeTreeV1;
    let mut raw = model();
    raw.geometry.volume_size = 16 << 30;
    let stream = &mut raw.files[FILE].streams[0];
    stream.logical_size = 3 << 30;
    stream.initialized_size = stream.logical_size;
    stream.allocated_size = stream.logical_size;
    stream.extents[0].physical_offset = Some(4096);
    stream.extents[0].length = stream.logical_size;
    let mut extra = raw.files[FILE].clone();
    extra.record_number = 17;
    extra.streams[0].extents[0].physical_offset = Some(4 << 30);
    raw.files.push(extra);
    let plan = ntfs_stream_plan::classify_with_resource_profile(&raw, selected);
    assert_eq!(plan.retained_candidate_bytes, 3 << 30);
    assert_eq!(plan.rejected_streams, 1);
    assert_eq!(plan.streams[1].disposition, Disposition::Reject);
    raw.files[FILE].streams[0].flags = 1;
    assert_eq!(
        ntfs_stream_plan::classify_with_resource_profile(&raw, selected).streams[0].disposition,
        Disposition::Reject
    );
    raw.files[FILE].streams[0].flags = 0;
    raw.files[FILE].streams[0].logical_size = 4 << 30;
    raw.files[FILE].streams[0].initialized_size = 4 << 30;
    raw.files[FILE].streams[0].allocated_size = 4 << 30;
    raw.files[FILE].streams[0].extents[0].length = 4 << 30;
    assert_eq!(
        ntfs_stream_plan::classify_with_resource_profile(&raw, selected).streams[0].disposition,
        Disposition::RetainCandidate
    );
    raw.files[FILE].streams[0].logical_size = (4 << 30) + 1;
    assert_eq!(
        ntfs_stream_plan::classify_with_resource_profile(&raw, selected).streams[0].disposition,
        Disposition::Reject
    );
}

#[test]
fn larger_expected_tree_enforces_file_directory_and_overflow_bounds() {
    use ntfs2refs::ntfs_admission::ResourceProfile;
    let selected = ResourceProfile::ExperimentalLargeTreeV1;
    let mut expected =
        shadow_tree::ExpectedTree::from(&shadow_tree::derive_ordinary(&model()).unwrap());
    expected.profile = selected.ordinary_shadow_profile().into();
    let mut template = expected.objects.pop().unwrap();
    template.source_offset = None;
    template.source_extents.clear();
    template.length = 0;
    for index in 0..1024 {
        let mut file = template.clone();
        file.record_number = 16 + index;
        file.path = vec![format!("file_{index}.bin")];
        expected.objects.push(file);
    }
    expected.logical_bytes = 0;
    expected.validate_with_resource_profile(selected).unwrap();
    let mut extra = template.clone();
    extra.record_number = 2000;
    extra.path = vec!["one_too_many.bin".into()];
    expected.objects.push(extra);
    assert!(expected.validate_with_resource_profile(selected).is_err());
    expected.objects.truncate(1);
    for index in 0..256 {
        let mut directory = expected.objects[0].clone();
        directory.record_number = 16 + index;
        directory.path = vec![format!("directory_{index}")];
        expected.objects.push(directory);
    }
    assert!(expected.validate_with_resource_profile(selected).is_err());
    expected.objects.truncate(1);
    template.length = u64::MAX;
    template.path = vec!["overflow.bin".into()];
    expected.objects.push(template);
    expected.logical_bytes = u64::MAX;
    assert!(expected.validate_with_resource_profile(selected).is_err());
}

#[test]
fn pinned_ordinary_expectation_round_trips_and_rejects_changed_digest() {
    let tree = shadow_tree::derive_ordinary(&model()).unwrap();
    let expected = shadow_tree::ExpectedTree::from(&tree);
    expected.validate().unwrap();
    let bytes = serde_json::to_vec(&expected).unwrap();
    let mut replay: shadow_tree::ExpectedTree = serde_json::from_slice(&bytes).unwrap();
    replay.validate().unwrap();
    replay
        .objects
        .iter_mut()
        .find(|o| !o.directory)
        .unwrap()
        .sha256 = Some("z".repeat(HEX_LEN));
    assert!(replay.validate().is_err());
}

#[test]
fn expected_tree_requires_parent_before_child_and_unique_source_identity() {
    let tree = shadow_tree::derive_ordinary(&model()).unwrap();
    let mut expected = shadow_tree::ExpectedTree::from(&tree);
    expected.objects[1].path = vec!["missing".into(), "payload.bin".into()];
    assert!(expected.validate().is_err());

    let mut expected = shadow_tree::ExpectedTree::from(&tree);
    let mut duplicate = expected.objects[1].clone();
    duplicate.path = vec!["copy.bin".into()];
    expected.logical_bytes += duplicate.length;
    expected.objects.push(duplicate);
    assert!(expected.validate().is_err());
}

#[test]
fn ordinary_expected_tree_accepts_internal_spaces_in_a_filename() {
    let tree = shadow_tree::derive_ordinary(&model()).unwrap();
    let mut expected = shadow_tree::ExpectedTree::from(&tree);
    expected.objects[1].path = vec!["Quarterly Report 1.bin".into()];
    expected.validate().unwrap();
}
#[test]
fn inconsistent_raw_views_missing_security_and_stale_parent_are_refused() {
    let raw = valid_model();
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
    b.files[FILE].names[0].parent_sequence_number += 1;
    assert!(shadow_tree::derive(&b).is_err());
}
#[test]
fn resident_sparse_tail_and_extra_streams_do_not_become_shadow_support() {
    for mutation in 0..4 {
        let mut b = valid_model();
        let file = &mut b.files[FILE];
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
    let mut b = valid_model();
    let mut extra = b.files[FILE].clone();
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
    let mut b = valid_model();
    b.files[FILE].is_metadata = true;
    b.files[FILE].metadata_role = n::MetadataRole::NotClassified;
    assert!(shadow_tree::derive(&b).is_err());
    let mut b = valid_model();
    b.files[ROOT].attributes[0].type_code = 0x40;
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
