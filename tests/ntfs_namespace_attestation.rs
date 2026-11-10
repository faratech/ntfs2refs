#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use n2r_win32::{
    attestation::{DirectoryCapture, FileIdentity, NamespaceFile, Query},
    namespace_layout as n,
};
use ntfs2refs::{
    ntfs_inspect::{self, NameInventory, NtfsInspection},
    ntfs_namespace_attestation::{check_directory, check_projected_directory},
};
use std::io::Cursor;
fn query(class: i32, bytes: Vec<u8>, native_error: Option<i32>) -> Query {
    Query {
        class,
        bytes,
        native_error,
    }
}
fn entry(name: &str, id: u64, attrs: u32) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let mut b = vec![0; 88 + name.len() * 2];
    b[56..60].copy_from_slice(&attrs.to_le_bytes());
    b[60..64].copy_from_slice(&(name.len() as u32 * 2).to_le_bytes());
    b[72..80].copy_from_slice(&id.to_le_bytes());
    for (i, c) in name.iter().enumerate() {
        b[88 + i * 2..90 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    b
}
fn fixture() -> (NtfsInspection, NamespaceFile) {
    let b = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(&b), b.len() as u64).unwrap();
    let mut child = raw
        .files
        .iter()
        .find(|f| f.record_number == 16)
        .unwrap()
        .clone();
    child.names = vec![NameInventory {
        name: "payload".into(),
        name_utf16: "payload".encode_utf16().collect(),
        namespace: 3,
        parent_record_number: 5,
        parent_sequence_number: 1,
    }];
    let mut root = child.clone();
    root.record_number = 5;
    root.is_directory = true;
    root.names[0].name = ".".into();
    root.names[0].name_utf16 = vec![46];
    raw.files = vec![root, child];
    let mut id = vec![0; 24];
    id[..8].copy_from_slice(&raw.geometry.serial_number.to_le_bytes());
    id[8..16].copy_from_slice(&(5 | 1u64 << 48).to_le_bytes());
    let mut standard = vec![0; 24];
    standard[21] = 1;
    let pass = DirectoryCapture {
        refusal: None,
        calls: vec![
            query(n::RESTART, entry("payload", 16 | 1u64 << 48, 32), None),
            query(n::CONTINUE, vec![], Some(n::END)),
        ],
    };
    (
        raw,
        NamespaceFile {
            identity: FileIdentity {
                record_number: 5,
                sequence_number: 1,
            },
            open_error: None,
            identity_before: Some(query(18, id.clone(), None)),
            identity_after: Some(query(18, id, None)),
            standard: Some(query(1, standard, None)),
            before: Some(pass.clone()),
            after: Some(pass),
        },
    )
}
#[test]
fn exact_names_and_identities_match() {
    let (r, n) = fixture();
    assert_eq!(check_directory(&r, &r.files[0], &n).unwrap(), 1);
}
#[test]
fn missing_unexpected_stale_and_wrong_type_entries_are_refused() {
    for replacement in [
        None,
        Some(entry("other", 16 | 1u64 << 48, 32)),
        Some(entry("payload", 16 | 2u64 << 48, 32)),
        Some(entry("payload", 16 | 1u64 << 48, 16)),
    ] {
        let (r, mut x) = fixture();
        let pass = x.after.as_mut().unwrap();
        if let Some(bytes) = replacement {
            pass.calls[0].bytes = bytes;
        } else {
            pass.calls = vec![query(n::RESTART, vec![], Some(n::END))];
        }
        assert!(check_directory(&r, &r.files[0], &x).is_err());
    }
}
#[test]
fn enumeration_failure_cannot_become_empty_directory() {
    let (mut r, mut x) = fixture();
    r.files.pop();
    for pass in [&mut x.before, &mut x.after] {
        pass.as_mut().unwrap().calls = vec![query(n::RESTART, vec![], Some(5))];
    }
    assert!(check_directory(&r, &r.files[0], &x).is_err());
    for pass in [&mut x.before, &mut x.after] {
        pass.as_mut().unwrap().calls[0].native_error = Some(n::END);
    }
    assert_eq!(check_directory(&r, &r.files[0], &x).unwrap(), 0);
}
#[test]
fn changed_or_foreign_directory_binding_is_refused() {
    let (r, mut x) = fixture();
    x.identity_after.as_mut().unwrap().bytes[0] ^= 1;
    assert!(check_directory(&r, &r.files[0], &x).is_err());
}
#[test]
fn dot_entries_are_identity_bound_and_never_used_to_hide_names() {
    let (r, mut x) = fixture();
    for pass in [&mut x.before, &mut x.after] {
        let pass = pass.as_mut().unwrap();
        pass.calls
            .insert(1, query(n::CONTINUE, entry(".", 5 | 1u64 << 48, 16), None));
        pass.calls
            .insert(2, query(n::CONTINUE, entry("..", 5 | 1u64 << 48, 16), None));
    }
    check_directory(&r, &r.files[0], &x).unwrap();
    x.after.as_mut().unwrap().calls[2].bytes = entry("..", 16 | 1u64 << 48, 16);
    assert!(check_directory(&r, &r.files[0], &x).is_err());
}
#[test]
fn duplicate_names_and_non_ntfs_identifiers_are_refused() {
    let (r, mut x) = fixture();
    let duplicate = x.after.as_ref().unwrap().calls[0].bytes.clone();
    x.after
        .as_mut()
        .unwrap()
        .calls
        .insert(1, query(n::CONTINUE, duplicate, None));
    assert!(check_directory(&r, &r.files[0], &x).is_err());
    let (r, mut x) = fixture();
    x.after.as_mut().unwrap().calls[0].bytes[80] = 1;
    assert!(check_directory(&r, &r.files[0], &x).is_err());
}
fn reserved_root_fixture() -> (NtfsInspection, NamespaceFile) {
    use ntfs2refs::ntfs_inspect::MetadataRole;
    let (mut r, n) = fixture();
    r.files[0].metadata_role = MetadataRole::ReservedSystemRecord;
    r.files[0].metadata_role_issue = None;
    for (id, name) in [
        (0, "$MFT"),
        (1, "$MFTMirr"),
        (2, "$LogFile"),
        (3, "$Volume"),
        (4, "$AttrDef"),
        (6, "$Bitmap"),
        (7, "$Boot"),
        (8, "$BadClus"),
        (9, "$Secure"),
        (10, "$UpCase"),
        (11, "$Extend"),
    ] {
        let mut f = r.files[1].clone();
        f.record_number = id;
        f.base_file_reference = 0;
        f.metadata_role = MetadataRole::ReservedSystemRecord;
        f.metadata_role_issue = None;
        f.is_directory = id == 11;
        f.names[0].name = name.into();
        f.names[0].name_utf16 = name.encode_utf16().collect();
        r.files.push(f);
    }
    (r, n)
}
#[test]
#[ignore = "stale: not maintained while tests were disabled; needs triage"]
fn optional_root_system_names_remain_identity_bound_and_reported() {
    let (r, mut n) = reserved_root_fixture();
    assert!(check_directory(&r, &r.files[0], &n).is_err());
    let p = check_projected_directory(&r, &r.files[0], &n).unwrap();
    assert_eq!(p.visible_names, 1);
    assert_eq!(p.internal_visibility.len(), 11);
    assert!(p.internal_visibility.iter().all(|i| !i.visible));
    for pass in [&mut n.before, &mut n.after] {
        pass.as_mut()
            .unwrap()
            .calls
            .insert(1, query(n::CONTINUE, entry("$MFT", 1u64 << 48, 32), None));
    }
    let p = check_projected_directory(&r, &r.files[0], &n).unwrap();
    assert_eq!(p.visible_names, 2);
    assert_eq!(
        p.internal_visibility.iter().filter(|i| i.visible).count(),
        1
    );
}
#[test]
fn projection_cannot_hide_a_user_name_or_a_failed_enumeration() {
    for error in [n::END, 5] {
        let (r, mut x) = reserved_root_fixture();
        for pass in [&mut x.before, &mut x.after] {
            pass.as_mut().unwrap().calls = vec![query(n::RESTART, vec![], Some(error))];
        }
        assert!(check_projected_directory(&r, &r.files[0], &x).is_err());
    }
}
#[test]
fn wrong_visible_internal_ids_types_and_unknown_names_are_refused() {
    for data in [
        entry("$MFT", 16 | 1u64 << 48, 32),
        entry("$MFT", 2u64 << 48, 32),
        entry("$MFT", 1u64 << 48, 16),
        entry("$unknown", 1u64 << 48, 32),
    ] {
        let (r, mut x) = reserved_root_fixture();
        for pass in [&mut x.before, &mut x.after] {
            pass.as_mut()
                .unwrap()
                .calls
                .insert(1, query(n::CONTINUE, data.clone(), None));
        }
        assert!(check_projected_directory(&r, &r.files[0], &x).is_err());
    }
}
#[test]
fn internal_visibility_changes_and_false_metadata_roles_are_refused() {
    let (r, mut x) = reserved_root_fixture();
    x.after
        .as_mut()
        .unwrap()
        .calls
        .insert(1, query(n::CONTINUE, entry("$MFT", 1u64 << 48, 32), None));
    assert!(check_projected_directory(&r, &r.files[0], &x).is_err());
    for kind in 0..4 {
        let (mut r, x) = reserved_root_fixture();
        let f = r.files.iter_mut().find(|f| f.record_number == 0).unwrap();
        match kind {
            0 => f.names[0].name_utf16 = "$MFT-copy".encode_utf16().collect(),
            1 => f.names[0].parent_sequence_number = 2,
            2 => f.metadata_role = ntfs2refs::ntfs_inspect::MetadataRole::NotClassified,
            _ => f.is_directory = true,
        }
        assert!(check_projected_directory(&r, &r.files[0], &x).is_err());
    }
}
