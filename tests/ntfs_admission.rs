#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use ntfs2refs::{
    ntfs_admission::{self as a, Disposition},
    ntfs_attestation::{Comparison, FileComparison},
    ntfs_inspect::{self as n, MetadataRole, NameInventory},
};
use std::io::Cursor;
fn fixture() -> n::NtfsInspection {
    let b = support::image();
    let mut raw = n::inspect(&mut Cursor::new(&b), b.len() as u64).unwrap();
    let mut user = raw
        .files
        .iter()
        .find(|f| f.record_number == 16)
        .unwrap()
        .clone();
    user.metadata_role = MetadataRole::OutsideExtendCandidate;
    user.metadata_role_issue = None;
    user.is_metadata = false;
    user.names = vec![name("payload", 5)];
    let mut root = user.clone();
    root.record_number = 5;
    root.is_directory = true;
    root.metadata_role = MetadataRole::ReservedSystemRecord;
    root.names = vec![name(".", 5)];
    root.streams.clear();
    raw.files = vec![root, user];
    raw
}
fn name(text: &str, parent: u64) -> NameInventory {
    NameInventory {
        name: text.into(),
        name_utf16: text.encode_utf16().collect(),
        namespace: 3,
        parent_record_number: parent,
        parent_sequence_number: 1,
    }
}
fn comparison(r: &n::NtfsInspection) -> Comparison {
    Comparison {
        directory_case_sensitivity: None,
        schema_version: 1,
        source_inspection_sha256: "a".repeat(64),
        requested_files: r.files.len(),
        opened_files: r.files.len(),
        matched_files: r.files.len(),
        files: r
            .files
            .iter()
            .map(|f| FileComparison {
                record_number: f.record_number,
                sequence_number: f.sequence_number,
                matched: true,
                issues: vec![],
                raw_kernel_security_matched: Some(true),
                kernel_api_security_matched: Some(true),
            })
            .collect(),
        all_requested_metadata_matched: true,
        conversion_qualified: false,
        native_streams: None,
        native_logical_data: None,
        native_namespace: None,
    }
}
#[test]
fn explicit_resource_profiles_keep_alpha_serialization_and_refuse_unqualified_large_native_support()
{
    use a::ResourceProfile::{AlphaV1, ExperimentalLargeTreeV1};
    let mut raw = fixture();
    raw.files[1].streams[0].logical_size = a::MAX_LOGICAL_BYTES + 4096;
    let native = comparison(&raw);
    let default = a::assess_ordinary_with_backups(&raw, &native, 7, None);
    let explicit = a::assess_ordinary_with_resource_profile(&raw, &native, 7, None, AlphaV1);
    assert_eq!(
        serde_json::to_vec(&default).unwrap(),
        serde_json::to_vec(&explicit).unwrap()
    );
    assert!(
        !default
            .gates
            .iter()
            .find(|gate| gate.code == "resource_limits")
            .unwrap()
            .satisfied
    );
    let large =
        a::assess_ordinary_with_resource_profile(&raw, &native, 8, None, ExperimentalLargeTreeV1);
    assert_eq!(large.profile, "ordinary-data-tree-large-v1");
    assert!(
        large
            .gates
            .iter()
            .find(|gate| gate.code == "resource_limits")
            .unwrap()
            .satisfied
    );
    assert!(
        !large
            .gates
            .iter()
            .find(|gate| gate.code == "native_resource_profile_support")
            .unwrap()
            .satisfied
    );
    assert!(!large.source_admitted && !large.certificate_issued && !large.execution_authorized);
    assert_eq!(
        serde_json::to_string(&ExperimentalLargeTreeV1).unwrap(),
        "\"experimental_large_tree_v1\""
    );
    assert!(serde_json::from_str::<a::ResourceProfile>("\"journal_v2\"").is_err());
    let limits = ExperimentalLargeTreeV1.limits();
    assert_eq!(
        (limits.maximum_files, limits.maximum_directories),
        (1024, 256)
    );
    assert_eq!(
        (limits.maximum_logical_bytes, limits.maximum_stream_bytes),
        (4 << 30, 4 << 30)
    );
}

#[test]
fn larger_resource_assessment_refuses_byte_overflow_without_panicking() {
    let mut raw = fixture();
    raw.files[1].streams[0].logical_size = u64::MAX;
    let mut extra = raw.files[1].streams[0].clone();
    extra.logical_size = 1;
    raw.files[1].streams.push(extra);
    let result = a::assess_ordinary_with_resource_profile(
        &raw,
        &comparison(&raw),
        8,
        None,
        a::ResourceProfile::ExperimentalLargeTreeV1,
    );
    assert_eq!(result.user_logical_bytes, u64::MAX);
    assert!(
        !result
            .gates
            .iter()
            .find(|gate| gate.code == "resource_limits")
            .unwrap()
            .satisfied
    );
    assert!(!result.source_admitted && !result.certificate_issued);
}

#[test]
#[ignore = "stale: not maintained while tests were disabled; needs triage"]
fn larger_resource_gate_enforces_the_exact_four_gib_logical_limit() {
    let mut raw = fixture();
    for (logical_bytes, expected) in [(4u64 << 30, true), ((4u64 << 30) + 1, false)] {
        raw.files[1].streams[0].logical_size = logical_bytes;
        let result = a::assess_ordinary_with_resource_profile(
            &raw,
            &comparison(&raw),
            8,
            None,
            a::ResourceProfile::ExperimentalLargeTreeV1,
        );
        assert_eq!(
            result
                .gates
                .iter()
                .find(|gate| gate.code == "resource_limits")
                .unwrap()
                .satisfied,
            expected
        );
        assert!(
            !result
                .gates
                .iter()
                .find(|gate| gate.code == "native_resource_profile_support")
                .unwrap()
                .satisfied
        );
        assert!(!result.source_admitted && !result.certificate_issued);
    }
}
#[test]
fn internal_role_requires_exact_identity_name_type_and_ancestry() {
    let mut r = fixture();
    let mut f = r.files[1].clone();
    f.record_number = 0;
    f.metadata_role = MetadataRole::ReservedSystemRecord;
    f.names = vec![name("$MFT", 5)];
    assert_eq!(a::internal_role(&r, &f).as_deref(), Some("$MFT"));
    f.names[0].name_utf16 = "$MFT-copy".encode_utf16().collect();
    assert!(a::internal_role(&r, &f).is_none());
    f.names = vec![name("$MFT", 5)];
    f.names[0].parent_sequence_number = 2;
    assert!(a::internal_role(&r, &f).is_none());
    f.names = vec![name("$MFT", 5)];
    f.is_directory = true;
    assert!(a::internal_role(&r, &f).is_none());
    f.is_directory = false;
    f.base_file_reference = 12;
    assert!(a::internal_role(&r, &f).is_none());
    r.files[1].is_metadata = true;
    assert!(a::internal_role(&r, &r.files[1]).is_none());
}
#[test]
#[ignore = "stale: not maintained while tests were disabled; needs triage"]
fn extend_candidate_is_not_a_blanket_metadata_exemption() {
    let mut r = fixture();
    let mut extend = r.files[0].clone();
    extend.record_number = 11;
    extend.names = vec![name("$Extend", 5)];
    r.files.push(extend);
    let f = &mut r.files[1];
    f.record_number = 24;
    f.metadata_role = MetadataRole::ExtendDescendantCandidate;
    f.names = vec![name("$Quota", 11)];
    f.names[0].namespace = 0;
    assert_eq!(
        a::internal_role(&r, &r.files[1]).as_deref(),
        Some("$Extend\\$Quota")
    );
    r.files[1].names = vec![name("unrecognized", 11)];
    let result = a::assess(&r, &comparison(&r), 5);
    assert_eq!(result.objects[1].disposition, Disposition::Reject);
    assert!(!result.execution_authorized);
}

#[test]
fn reserved_empty_data_is_recognized_but_cannot_hide_owned_payload() {
    let r = fixture();
    let mut slot = r.files[1].clone();
    slot.record_number = 12;
    slot.metadata_role = MetadataRole::ReservedSystemRecord;
    slot.names.clear();
    slot.hard_link_count = 0;
    slot.attributes
        .retain(|a| matches!(a.type_code, 0x10 | 0x50));
    slot.streams.clear();
    assert!(a::internal_role(&r, &slot).is_some());
    slot.streams.push(r.files[1].streams[0].clone());
    assert!(a::internal_role(&r, &slot).is_none());
}

#[test]
#[ignore = "requires the pinned frozen native NTFS tree inspection"]
fn pinned_root_txf_has_exact_internal_form_but_replacement_is_not_admitted() {
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
    let assessed = a::assess_ordinary_with_backups(&raw, &comparison(&raw), 5, None);
    let root = assessed
        .objects
        .iter()
        .find(|object| object.record_number == 5)
        .unwrap();
    assert!(
        !root
            .issues
            .iter()
            .any(|issue| issue == "unsupported or unassembled attribute semantics")
    );
    assert!(
        !assessed
            .gates
            .iter()
            .find(|gate| gate.code == "internal_replacement_state")
            .unwrap()
            .satisfied
    );
    let remaining = assessed
        .gates
        .iter()
        .find(|gate| gate.code == "remaining_inspection_refusals")
        .unwrap();
    assert!(!remaining.detail.contains("unsupported_attribute"));
    assert!(!remaining.detail.contains("logical_stream_hash_unavailable"));
    assert!(
        remaining
            .detail
            .contains("exact internal TxF replacements still pending: 2")
    );
    assert!(
        remaining
            .detail
            .contains("empty internal $BadClus streams accounted: 1")
    );
    assert!(!assessed.source_admitted);
}
#[test]
fn older_reports_and_success_flags_cannot_supply_missing_evidence() {
    let r = fixture();
    let c = comparison(&r);
    for schema in [2, 3, 4, 5, 6, 7] {
        let result = a::assess(&r, &c, schema);
        assert!(
            !result
                .gates
                .iter()
                .find(|g| g.code == "native_profile")
                .unwrap()
                .satisfied
        );
        assert!(
            !result.source_admitted && !result.certificate_issued && !result.execution_authorized
        );
        assert!(
            result.objects[1]
                .issues
                .iter()
                .any(|s| s.contains("logical-data"))
        );
    }
}
#[test]
fn omitted_or_duplicate_native_identity_fails_coverage() {
    let r = fixture();
    let mut c = comparison(&r);
    c.files.pop();
    assert!(
        !a::assess(&r, &c, 5)
            .gates
            .iter()
            .find(|g| g.code == "native_identity_coverage")
            .unwrap()
            .satisfied
    );
    c.files.push(FileComparison {
        record_number: 5,
        sequence_number: 1,
        matched: true,
        issues: vec![],
        raw_kernel_security_matched: Some(true),
        kernel_api_security_matched: Some(true),
    });
    assert!(
        !a::assess(&r, &c, 5)
            .gates
            .iter()
            .find(|g| g.code == "native_identity_coverage")
            .unwrap()
            .satisfied
    );
}
#[test]
fn inconsistent_indexes_and_unexplained_allocation_prevent_admission() {
    let mut r = fixture();
    r.namespace_reconciliation.as_mut().unwrap().status =
        ntfs2refs::ntfs_namespace::Status::Rejected;
    r.allocation_reconciliation.as_mut().unwrap().status =
        n::AllocationReconciliationStatus::Rejected;
    let result = a::assess(&r, &comparison(&r), 5);
    for code in ["raw_namespace", "raw_allocation"] {
        assert!(
            !result
                .gates
                .iter()
                .find(|g| g.code == code)
                .unwrap()
                .satisfied
        );
    }
}
#[test]
fn unsupported_attributes_and_streams_have_explicit_object_refusals() {
    let mut r = fixture();
    r.files[1].attributes[0].type_code = 0x40;
    let result = a::assess(&r, &comparison(&r), 5);
    assert_eq!(result.objects[1].disposition, Disposition::Reject);
    assert!(
        result.objects[1]
            .issues
            .iter()
            .any(|s| s.contains("attribute semantics"))
    );
    assert!(
        result.objects[1]
            .issues
            .iter()
            .any(|s| s.contains("stream requires"))
    );
}

#[test]
fn ordinary_profile_classifies_partial_plain_stream_without_granting_writes() {
    let mut r = fixture();
    r.files[1]
        .streams
        .retain(|stream| stream.name_utf16.is_empty());
    r.files[1]
        .attributes
        .retain(|attribute| attribute.type_code != 0x80 || attribute.name_utf16.is_empty());
    let c = comparison(&r);
    let strict = a::assess(&r, &c, 5);
    let ordinary = a::assess_ordinary_with_backups(&r, &c, 5, None);
    assert!(
        strict.objects[1]
            .issues
            .iter()
            .any(|issue| issue.contains("stream requires"))
    );
    assert!(
        !ordinary.objects[1]
            .issues
            .iter()
            .any(|issue| issue.contains("stream requires")),
        "{:?} {:?}",
        ordinary.objects[1].issues,
        r.files[1].streams
    );
    assert_eq!(ordinary.profile, a::ORDINARY_PROFILE);
    assert!(!ordinary.source_admitted);
    assert!(!ordinary.certificate_issued);
    assert!(!ordinary.execution_authorized);
}
