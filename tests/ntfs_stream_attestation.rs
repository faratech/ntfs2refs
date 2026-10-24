#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use n2r_win32::{
    attestation::{IoctlQuery, Query, StreamCapture, StreamQuery},
    stream_layout as layout,
};
use ntfs2refs::{
    ntfs_inspect::{
        self, AllocationReconciliation, AllocationReconciliationStatus, Extent, FileInventory,
        NtfsInspection,
    },
    ntfs_stream_attestation::{check_bitmap, check_file},
};
use sha2::{Digest, Sha256};
use std::io::Cursor;
fn p32(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], o: usize, n: u64) {
    b[o..o + 8].copy_from_slice(&n.to_le_bytes());
}
fn enumeration(items: &[(Vec<u16>, u64, u64)]) -> Vec<u8> {
    let mut b = vec![];
    for (i, (name, size, allocation)) in items.iter().enumerate() {
        let mut full = vec![58];
        full.extend(name);
        full.extend(":$DATA".encode_utf16());
        let len = 24 + 2 * full.len();
        let next = i + 1 < items.len();
        let mut row = vec![0; if next { len.next_multiple_of(8) } else { len }];
        if next {
            let n = row.len() as u32;
            p32(&mut row, 0, n);
        }
        p32(&mut row, 4, (2 * full.len()) as u32);
        p64(&mut row, 8, *size);
        p64(&mut row, 16, *allocation);
        for (j, c) in full.iter().enumerate() {
            row[24 + 2 * j..26 + 2 * j].copy_from_slice(&c.to_le_bytes());
        }
        b.extend(row);
    }
    b
}
fn rpp(runs: &[(u64, i64)]) -> IoctlQuery {
    let mut b = vec![0; 16 + 16 * runs.len()];
    p32(&mut b, 0, runs.len() as u32);
    for (i, (next, lcn)) in runs.iter().enumerate() {
        p64(&mut b, 16 + 16 * i, *next);
        p64(&mut b, 24 + 16 * i, *lcn as u64);
    }
    IoctlQuery {
        code: layout::GET_RETRIEVAL,
        input: vec![0; 8],
        bytes: b,
        native_error: None,
    }
}
fn fixture() -> (NtfsInspection, FileInventory, StreamCapture) {
    let b = support::image();
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&b), b.len() as u64).unwrap();
    let f = raw
        .files
        .iter()
        .find(|f| f.record_number == 16)
        .unwrap()
        .clone();
    let mut id = vec![0; 24];
    p64(&mut id, 0, raw.geometry.serial_number);
    p64(
        &mut id,
        8,
        f.record_number | u64::from(f.sequence_number) << 48,
    );
    let identity = Query {
        class: 18,
        bytes: id,
        native_error: None,
    };
    let streams: Vec<_> = f
        .streams
        .iter()
        .map(|s| StreamQuery {
            name_utf16: s.name_utf16.clone(),
            logical_size: s.logical_size,
            allocated_size: if s.resident { 24 } else { 4096 },
            open_error: None,
            binding_error: None,
            identity_before: Some(identity.clone()),
            identity_after: Some(identity.clone()),
            retrieval: Some(if s.resident {
                IoctlQuery {
                    code: layout::GET_RETRIEVAL,
                    input: vec![0; 8],
                    bytes: vec![],
                    native_error: Some(38),
                }
            } else {
                rpp(&[(1, 100)])
            }),
        })
        .collect();
    let entries: Vec<_> = streams
        .iter()
        .map(|s| (s.name_utf16.clone(), s.logical_size, s.allocated_size))
        .collect();
    let native = StreamCapture {
        enumeration: Query {
            class: 7,
            bytes: enumeration(&entries),
            native_error: None,
        },
        parse_error: None,
        streams,
    };
    (raw, f, native)
}
fn refresh(n: &mut StreamCapture) {
    n.enumeration.bytes = enumeration(
        &n.streams
            .iter()
            .map(|s| (s.name_utf16.clone(), s.logical_size, s.allocated_size))
            .collect::<Vec<_>>(),
    );
}
#[test]
fn matches_default_and_resident_ads() {
    let (r, f, n) = fixture();
    check_file(&f, &n, 0, &r.geometry).unwrap();
}
#[test]
fn native_base_is_in_sectors() {
    let (r, f, mut n) = fixture();
    n.streams[0].retrieval = Some(rpp(&[(1, 99)]));
    check_file(&f, &n, 8, &r.geometry).unwrap();
    assert!(check_file(&f, &n, 1, &r.geometry).is_err());
}
#[test]
fn missing_ads_is_refused() {
    let (r, f, mut n) = fixture();
    n.streams.pop();
    refresh(&mut n);
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
#[test]
fn alias_to_different_identity_is_refused() {
    let (r, f, mut n) = fixture();
    n.streams[1].identity_after.as_mut().unwrap().bytes[8] ^= 1;
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
#[test]
fn partial_retrieval_is_refused() {
    let (r, f, mut n) = fixture();
    n.streams[0].retrieval.as_mut().unwrap().native_error = Some(234);
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
#[test]
fn wrong_physical_mapping_is_refused() {
    let (r, f, mut n) = fixture();
    n.streams[0].retrieval = Some(rpp(&[(1, 101)]));
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
#[test]
fn physical_allocation_is_checked() {
    let (r, f, mut n) = fixture();
    n.streams[0].allocated_size = 8192;
    refresh(&mut n);
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
#[test]
fn unsupported_encoding_is_refused() {
    let (r, mut f, n) = fixture();
    f.streams[0].flags = 1;
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
#[test]
fn resident_stream_cannot_own_native_clusters() {
    let (r, f, mut n) = fixture();
    n.streams[1].retrieval = Some(rpp(&[(1, 100)]));
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
#[test]
fn contiguous_run_splits_are_equivalent() {
    let (r, mut f, mut n) = fixture();
    f.streams[0].logical_size = 4097;
    f.streams[0].extents[0].length = 8192;
    n.streams[0].logical_size = 4097;
    n.streams[0].allocated_size = 8192;
    n.streams[0].retrieval = Some(rpp(&[(1, 100), (2, 101)]));
    refresh(&mut n);
    check_file(&f, &n, 0, &r.geometry).unwrap();
}
#[test]
fn sparse_holes_and_physical_allocation_are_distinct() {
    let (r, mut f, mut n) = fixture();
    f.streams[0].flags = 0x8000;
    f.streams[0].logical_size = 12288;
    f.streams[0].allocated_size = 12288;
    f.streams[0].extents = vec![
        Extent {
            logical_offset: 0,
            physical_offset: None,
            length: 4096,
        },
        Extent {
            logical_offset: 4096,
            physical_offset: Some(100 * 4096),
            length: 4096,
        },
        Extent {
            logical_offset: 8192,
            physical_offset: None,
            length: 4096,
        },
    ];
    n.streams[0].logical_size = 12288;
    n.streams[0].allocated_size = 4096;
    n.streams[0].retrieval = Some(rpp(&[(1, -1), (2, 100), (3, -1)]));
    refresh(&mut n);
    check_file(&f, &n, 0, &r.geometry).unwrap();
}
#[test]
fn empty_directory_requires_explicit_eof_and_empty_raw_set() {
    let (r, mut f, _) = fixture();
    f.streams.clear();
    f.attributes.retain(|a| a.type_code != 0x80);
    let n = StreamCapture {
        enumeration: Query {
            class: 7,
            bytes: vec![],
            native_error: Some(38),
        },
        parse_error: None,
        streams: vec![],
    };
    check_file(&f, &n, 0, &r.geometry).unwrap();
    let (_, f, _) = fixture();
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}
fn bitmap_fixture() -> (NtfsInspection, IoctlQuery) {
    let (mut r, _, _) = fixture();
    let data = vec![0xa5; 64];
    r.allocation_reconciliation = Some(AllocationReconciliation {
        status: AllocationReconciliationStatus::ConsistentRawModel,
        bitmap_sha256: hex::encode(Sha256::digest(&data)),
        domain_clusters: 512,
        physical_intervals: 0,
        detail: "isolated supplied-model test".into(),
    });
    let mut b = vec![0; 16];
    p64(&mut b, 8, 512);
    b.extend(data);
    (
        r,
        IoctlQuery {
            code: layout::GET_BITMAP,
            input: vec![0; 8],
            bytes: b,
            native_error: None,
        },
    )
}
#[test]
fn bitmap_matches_the_raw_ledger_digest() {
    let (r, q) = bitmap_fixture();
    check_bitmap(&r, &q).unwrap();
}
#[test]
fn bitmap_bit_corruption_is_refused() {
    let (r, mut q) = bitmap_fixture();
    q.bytes[20] ^= 1;
    assert!(check_bitmap(&r, &q).is_err());
}
#[test]
fn partial_offset_and_short_bitmaps_are_refused() {
    let (r, mut q) = bitmap_fixture();
    q.native_error = Some(234);
    assert!(check_bitmap(&r, &q).is_err());
    let (r, mut q) = bitmap_fixture();
    p64(&mut q.bytes, 0, 8);
    assert!(check_bitmap(&r, &q).is_err());
    let (r, mut q) = bitmap_fixture();
    q.bytes.pop();
    assert!(check_bitmap(&r, &q).is_err());
}
#[test]
fn inconsistent_raw_allocation_cannot_be_certified() {
    let (mut r, q) = bitmap_fixture();
    r.allocation_reconciliation.as_mut().unwrap().status = AllocationReconciliationStatus::Rejected;
    assert!(check_bitmap(&r, &q).is_err());
}
#[test]
fn ioctl_hex_roundtrip_and_legacy_arrays_are_equivalent() {
    let q = rpp(&[(1, 100)]);
    let value = serde_json::to_value(&q).unwrap();
    assert_eq!(value["bytes"].as_str().unwrap(), hex::encode(&q.bytes));
    assert_eq!(serde_json::from_value::<IoctlQuery>(value).unwrap(), q);
    let legacy = serde_json::json!({"code":q.code,"input":q.input,"bytes":q.bytes,"native_error":q.native_error});
    assert_eq!(serde_json::from_value::<IoctlQuery>(legacy).unwrap(), q);
    for bad in ["0", "xyz"] {
        let value =
            serde_json::json!({"code":q.code,"input":q.input,"bytes":bad,"native_error":null});
        assert!(serde_json::from_value::<IoctlQuery>(value).is_err());
    }
}
#[test]
fn maximum_bitmaps_fit_the_existing_report_budget() {
    let q = IoctlQuery {
        code: layout::GET_BITMAP,
        input: vec![0; 8],
        bytes: vec![255; 16 + layout::MAX_BITMAP_BYTES],
        native_error: None,
    };
    let bytes = serde_json::to_vec_pretty(&vec![q.clone(), q]).unwrap();
    assert!(bytes.len() < 9 * 1024 * 1024);
}
