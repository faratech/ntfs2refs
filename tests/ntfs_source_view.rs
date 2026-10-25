#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use n2r_win32::attestation::{Query, SecurityQuery, Snapshot};
use ntfs2refs::{ntfs_inspect, ntfs_source_view::check_metadata};
use std::io::Cursor;
const SERIAL: u64 = 0x1122_3344_5566_7788;
fn fixture() -> (ntfs_inspect::FileInventory, Vec<u8>, Snapshot) {
    let image = support::image();
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&image), image.len() as u64).unwrap();
    let mut f = raw
        .files
        .iter()
        .find(|f| f.record_number == 16)
        .unwrap()
        .clone();
    f.hard_link_count = 1;
    f.sequence_number = 7;
    let si = f.standard_information.as_mut().unwrap();
    si.creation_time = 134_000_000_000_000_001;
    si.access_time = 134_000_000_000_000_002;
    si.modification_time = 134_000_000_000_000_003;
    si.mft_change_time = 134_000_000_000_000_004;
    si.file_attributes = 32;
    f.streams.truncate(1);
    f.streams[0].resident = false;
    f.streams[0].name_utf16.clear();
    f.streams[0].logical_size = 4096;
    f.streams[0].initialized_size = 4096;
    f.streams[0].allocated_size = 4096;
    let mut sd = vec![0; 40];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd[16..20].copy_from_slice(&32u32.to_le_bytes());
    sd[20..32].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    sd[32] = 2;
    sd[34..36].copy_from_slice(&8u16.to_le_bytes());
    let mut basic = vec![0; 40];
    for (i, t) in [
        si.creation_time,
        si.access_time,
        si.modification_time,
        si.mft_change_time,
    ]
    .iter()
    .enumerate()
    {
        basic[i * 8..i * 8 + 8].copy_from_slice(&t.to_le_bytes());
    }
    basic[32..36].copy_from_slice(&32u32.to_le_bytes());
    let mut standard = vec![0; 24];
    standard[..8].copy_from_slice(&4096u64.to_le_bytes());
    standard[8..16].copy_from_slice(&4096u64.to_le_bytes());
    standard[16..20].copy_from_slice(&1u32.to_le_bytes());
    let mut id = vec![0; 24];
    id[..8].copy_from_slice(&SERIAL.to_le_bytes());
    id[8..16].copy_from_slice(&(16 | 7u64 << 48).to_le_bytes());
    let mut tag = vec![0; 8];
    tag[..4].copy_from_slice(&32u32.to_le_bytes());
    let s = Snapshot {
        queries: [(0, basic), (1, standard), (18, id), (9, tag)]
            .into_iter()
            .map(|(class, bytes)| Query {
                class,
                bytes,
                native_error: None,
            })
            .collect(),
        security: sd.clone(),
        security_error: None,
        kernel_security: Some(SecurityQuery {
            bytes: sd.clone(),
            native_error: None,
        }),
    };
    (f, sd, s)
}
fn bytes(s: &mut Snapshot, class: i32) -> &mut Vec<u8> {
    &mut s
        .queries
        .iter_mut()
        .find(|q| q.class == class)
        .unwrap()
        .bytes
}
#[test]
fn exact_stored_times_keep_all_filetime_bits() {
    let (f, sd, s) = fixture();
    let v = check_metadata(&f, SERIAL, &sd, &s, &s).unwrap();
    assert!(!v.cached_access_differs);
    assert_eq!(v.stored, v.native_before);
    assert_eq!(v.stored, v.native_after);
    assert_eq!(v.stored[1], 134_000_000_000_000_002);
}
#[test]
fn cached_access_is_explicit_and_does_not_replace_the_preserved_value() {
    let (f, sd, mut a) = fixture();
    let mut b = a.clone();
    bytes(&mut a, 0)[8..16].copy_from_slice(&200u64.to_le_bytes());
    bytes(&mut b, 0)[8..16].copy_from_slice(&300u64.to_le_bytes());
    let v = check_metadata(&f, SERIAL, &sd, &a, &b).unwrap();
    assert!(v.cached_access_differs);
    assert_eq!(
        v.stored[1],
        f.standard_information.as_ref().unwrap().access_time
    );
    assert_eq!(v.native_before[1], 200);
    assert_eq!(v.native_after[1], 300);
    assert!(
        v.preservation_authority
            .contains("requires actual unchanged read-only source")
    );
}
#[test]
fn other_time_identity_size_link_attribute_and_state_changes_are_refused() {
    for (class, offset) in [
        (0, 0),
        (0, 16),
        (0, 24),
        (0, 32),
        (1, 0),
        (1, 8),
        (1, 16),
        (1, 20),
        (1, 21),
        (18, 0),
        (18, 8),
        (18, 16),
        (9, 0),
        (9, 4),
    ] {
        let (f, sd, a) = fixture();
        let mut b = a.clone();
        bytes(&mut b, class)[offset] ^= 1;
        assert!(
            check_metadata(&f, SERIAL, &sd, &a, &b).is_err(),
            "class {class} byte {offset}"
        );
    }
}
#[test]
fn unexplained_reserved_bytes_must_also_remain_stable() {
    for (class, offset) in [(0, 36), (1, 22), (9, 7)] {
        let (f, sd, a) = fixture();
        let mut b = a.clone();
        bytes(&mut b, class)[offset] ^= 1;
        assert!(check_metadata(&f, SERIAL, &sd, &a, &b).is_err());
    }
}
#[test]
fn both_security_views_and_all_queries_remain_mandatory() {
    for kind in 0..8 {
        let (f, sd, a) = fixture();
        let mut b = a.clone();
        match kind {
            0 => b.security_error = Some(5),
            1 => b.kernel_security = None,
            2 => b.kernel_security.as_mut().unwrap().native_error = Some(5),
            3 => b.kernel_security.as_mut().unwrap().bytes[28] = 19,
            4 => b.security[28] = 19,
            5 => {
                b.queries[0].bytes.pop();
            }
            6 => {
                b.queries[1] = b.queries[0].clone();
            }
            _ => b.queries[0].native_error = Some(5),
        }
        assert!(
            check_metadata(&f, SERIAL, &sd, &a, &b).is_err(),
            "case {kind}"
        );
    }
}
#[test]
#[ignore = "requires pinned live source capture; pure report replay cannot grant live admission"]
fn pinned_source_projection_explains_only_the_observed_discrepancies() {
    use sha2::{Digest, Sha256};
    let root = ".lab/hyperv/source-admission/win11-20261025T002322263Z/refreshed";
    let b = std::fs::read(format!("{root}/refreshed-inspection.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&b)),
        "29d97ef4498f33933ec3702a3e9aee6e81fc4084d60c797ff4d0018208b8ab5e"
    );
    let inspection: ntfs2refs::planner::Inspection = serde_json::from_slice(&b).unwrap();
    let canonical = hex::encode(Sha256::digest(serde_json::to_vec(&inspection).unwrap()));
    let ntfs2refs::planner::Filesystem::Ntfs(raw) = inspection.filesystem else {
        panic!("not NTFS")
    };
    let b = std::fs::read(format!("{root}/refreshed-observation.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&b)),
        "f23e946eccab739f515deaf2f989a760949f839df98eb05d7b90329f46bfbe1d"
    );
    let value: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let native: n2r_win32::attestation::Report =
        serde_json::from_value(value["observation"]["native"]["report"].clone()).unwrap();
    let strict = ntfs2refs::ntfs_attestation::compare(&raw, &canonical, &native).unwrap();
    assert_eq!(
        strict
            .files
            .iter()
            .filter(|f| f.record_number >= 39 && !f.matched)
            .count(),
        4
    );
    let v = ntfs2refs::ntfs_source_view::diagnose(&raw, &canonical, &native).unwrap();
    assert!(v.all_user_views_compatible, "{v:#?}");
    assert_eq!(v.objects.len(), 8);
    assert_eq!(
        v.objects
            .iter()
            .filter(|o| o
                .timestamps
                .as_ref()
                .is_some_and(|t| t.cached_access_differs))
            .count(),
        4
    );
    let root = v.objects.iter().find(|o| o.record_number == 5).unwrap();
    let p = root
        .directory
        .as_ref()
        .unwrap()
        .projection
        .as_ref()
        .unwrap();
    assert_eq!(p.visible_names, 3);
    assert_eq!(p.internal_visibility.len(), 11);
    assert!(p.internal_visibility.iter().all(|i| !i.visible));
    let serialized = serde_json::to_value(&v).unwrap();
    assert!(serialized["frozen_source_sha256"].is_null());
    assert_eq!(serialized["source_admitted"], false);
    assert_eq!(serialized["execution_authorized"], false);
}
