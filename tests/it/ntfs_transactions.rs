#[allow(dead_code, reason = "shared synthetic parser fixtures")]
use crate::support;
use ntfs2refs::{
    ntfs_inspect::{self as n, AttributeInventory, MetadataRole, NameInventory},
    ntfs_transactions,
};
use std::io::Cursor;
fn name(text: &str, parent: u64) -> NameInventory {
    NameInventory {
        name: text.into(),
        name_utf16: text.encode_utf16().collect(),
        namespace: 1,
        parent_record_number: parent,
        parent_sequence_number: 1,
    }
}
fn txf() -> AttributeInventory {
    AttributeInventory {
        type_code: 0x100,
        instance: 9,
        name_utf16: "$TXF_DATA".encode_utf16().collect(),
        flags: 0,
        resident: true,
        logical_size: 56,
        initialized_size: 56,
        allocated_size: 56,
        lowest_vcn: 0,
        compression_unit: 0,
        total_allocated_size: None,
        extents: vec![],
        resident_sha256: Some("a".repeat(n2r_win32::content_digest::HEX_LEN)),
        resident_metadata_hex: None,
    }
}
fn fixture() -> n::NtfsInspection {
    let bytes = support::image();
    let mut raw = n::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    let template = raw
        .files
        .iter()
        .find(|f| f.record_number == 16)
        .unwrap()
        .clone();
    raw.files.clear();
    for (id, parent, text, directory) in [
        (5, 5, ".", true),
        (11, 5, "$Extend", true),
        (17, 11, "$RmMetadata", true),
        (18, 17, "$TxfLog", true),
        (19, 17, "$Txf", true),
        (20, 11, "$Deleted", true),
        (21, 18, "$Tops", false),
        (22, 18, "$TxfLog.blf", false),
        (23, 18, "$TxfLogContainer00000000000000000001", false),
        (24, 18, "$TxfLogContainer00000000000000000002", false),
    ] {
        let mut file = template.clone();
        file.record_number = id;
        file.sequence_number = 1;
        file.hard_link_count = 1;
        file.is_directory = directory;
        file.base_file_reference = 0;
        file.names = vec![name(text, parent)];
        file.metadata_role = if id < 16 {
            MetadataRole::ReservedSystemRecord
        } else {
            MetadataRole::ExtendDescendantCandidate
        };
        file.metadata_role_issue = None;
        file.attributes.clear();
        file.streams = if directory {
            vec![]
        } else {
            vec![template.streams[0].clone()]
        };
        if id == 5 || id == 19 {
            file.attributes.push(txf());
        }
        if id == 21 {
            let mut stream = file.streams[0].clone();
            stream.name_utf16 = "$T".encode_utf16().collect();
            file.streams.push(stream);
        }
        raw.files.push(file);
    }
    raw
}
#[test]
fn default_scope_accounts_logs_and_refuses_user_or_deferred_transaction_state() {
    let raw = fixture();
    let scope = ntfs_transactions::inspect_scope(&raw).unwrap();
    assert_eq!(scope.transactional_records, [5, 19]);
    assert_eq!(scope.default_log_records.len(), 4);
    assert_eq!(scope.default_log_stream_sha256.len(), 5);
    let mut bad = raw.clone();
    let mut user = bad.files[0].clone();
    user.record_number = 25;
    user.names = vec![name("secondary-rm", 5)];
    user.metadata_role = MetadataRole::OutsideExtendCandidate;
    bad.files.push(user);
    assert!(ntfs_transactions::inspect_scope(&bad).is_err());
    for parent in [19, 20] {
        let mut bad = raw.clone();
        let mut child = bad.files[6].clone();
        child.record_number = 25;
        child.names = vec![name("pending", parent)];
        bad.files.push(child);
        assert!(ntfs_transactions::inspect_scope(&bad).is_err());
    }
    let mut bad = raw.clone();
    bad.files.retain(|f| f.record_number != 24);
    assert!(ntfs_transactions::inspect_scope(&bad).is_err());
    let mut bad = raw.clone();
    bad.files[6].streams[0].logical_hash_status = n::LogicalHashStatus::NotComputed;
    assert!(ntfs_transactions::inspect_scope(&bad).is_err());
    let mut bad = raw.clone();
    bad.files[0].attributes[0].logical_size = 55;
    assert!(ntfs_transactions::inspect_scope(&bad).is_err());
    let mut bad = raw;
    let duplicate = bad.files[6].streams[0].clone();
    bad.files[6].streams.push(duplicate);
    assert!(ntfs_transactions::inspect_scope(&bad).is_err());
}
