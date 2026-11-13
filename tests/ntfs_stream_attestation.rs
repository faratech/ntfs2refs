#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use n2r_win32::{
    attestation::{
        IoctlQuery, Query, Report, Request, StreamCapture, StreamQuery, VolumeAllocation,
    },
    bitmap_paging, retrieval_paging, stream_layout as layout,
};
use ntfs2refs::{
    ntfs_inspect::{
        self, AllocationReconciliation, AllocationReconciliationStatus, Extent, FileInventory,
        NtfsInspection,
    },
    ntfs_stream_attestation::{check_bitmap, check_bitmap_pages, check_file, reconcile},
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
    rpp_from(0, runs)
}
fn rpp_from(start: u64, runs: &[(u64, i64)]) -> IoctlQuery {
    let mut b = vec![0; 16 + 16 * runs.len()];
    p32(&mut b, 0, runs.len() as u32);
    p64(&mut b, 8, start);
    for (i, (next, lcn)) in runs.iter().enumerate() {
        p64(&mut b, 16 + 16 * i, *next);
        p64(&mut b, 24 + 16 * i, *lcn as u64);
    }
    IoctlQuery {
        code: layout::GET_RETRIEVAL,
        input: start.to_le_bytes().to_vec(),
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
            retrieval_continuation: vec![],
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
fn resident_eof_cannot_hide_retrieval_continuations() {
    let (r, f, mut n) = fixture();
    n.streams[1].retrieval_continuation.push(rpp(&[(1, 100)]));
    assert!(check_file(&f, &n, 0, &r.geometry).is_err());
}

fn fragmented_paged_fixture() -> (NtfsInspection, FileInventory, StreamCapture) {
    let (mut raw, mut file, mut native) = fixture();
    // Supplied in-memory stream evidence only: raw attribute-list support is
    // deliberately unchanged and this fixture grants no source admission.
    let count = layout::MAX_EXTENTS + 1;
    assert!(count <= retrieval_paging::MAX_COMPLETE_EXTENTS);
    raw.geometry.volume_size = 64 * 1024 * 1024;
    raw.geometry.total_clusters = raw.geometry.volume_size / 4096;
    let logical_size = (count as u64 - 1) * 4096 + 1;
    file.streams[0].logical_size = logical_size;
    file.streams[0].initialized_size = logical_size;
    file.streams[0].allocated_size = count as u64 * 4096;
    file.streams[0].extents = (0..count)
        .map(|index| Extent {
            logical_offset: index as u64 * 4096,
            physical_offset: Some((100 + index as u64 * 2) * 4096),
            length: 4096,
        })
        .collect();
    let runs: Vec<_> = (0..count)
        .map(|index| (index as u64 + 1, 100 + index as i64 * 2))
        .collect();
    let mut first = rpp(&runs[..layout::MAX_EXTENTS]);
    first.native_error = Some(234);
    native.streams[0].logical_size = logical_size;
    native.streams[0].allocated_size = count as u64 * 4096;
    native.streams[0].retrieval = Some(first);
    native.streams[0].retrieval_continuation = vec![rpp_from(
        layout::MAX_EXTENTS as u64,
        &runs[layout::MAX_EXTENTS..],
    )];
    refresh(&mut native);
    (raw, file, native)
}

#[test]
fn fragmented_paged_retrieval_matches_raw_mapping_through_the_partial_tail_cluster() {
    let (raw, file, native) = fragmented_paged_fixture();
    check_file(&file, &native, 0, &raw.geometry).unwrap();
    // Structural page validity does not replace the explicit MORE_DATA status.
    assert!(layout::parse_retrieval(&native.streams[0].retrieval.as_ref().unwrap().bytes).is_ok());
    let mut bad_tail = native.clone();
    p64(
        &mut bad_tail.streams[0].retrieval_continuation[0].bytes,
        24,
        7777,
    );
    assert!(check_file(&file, &bad_tail, 0, &raw.geometry).is_err());
    let mut missing_tail = native.clone();
    missing_tail.streams[0].retrieval_continuation.clear();
    assert!(check_file(&file, &missing_tail, 0, &raw.geometry).is_err());
    let mut wrong_start = native;
    wrong_start.streams[0].retrieval_continuation[0].input = 1025u64.to_le_bytes().to_vec();
    assert!(check_file(&file, &wrong_start, 0, &raw.geometry).is_err());
}

#[test]
fn retrieval_paging_does_not_bypass_raw_attribute_list_refusal() {
    let (raw, mut file, native) = fragmented_paged_fixture();
    file.attributes[0].type_code = 0x20;
    let error = check_file(&file, &native, 0, &raw.geometry)
        .unwrap_err()
        .to_string();
    assert!(error.contains("attribute-list/extension assembly required"));
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

fn bitmap_queries(data: &[u8], domain: u64, page_bytes: usize) -> Vec<IoctlQuery> {
    data.chunks(page_bytes)
        .enumerate()
        .map(|(index, bytes)| {
            let start = (index * page_bytes * 8) as u64;
            let mut response = vec![0; 16];
            p64(&mut response, 0, start);
            p64(&mut response, 8, domain - start);
            response.extend_from_slice(bytes);
            IoctlQuery {
                code: layout::GET_BITMAP,
                input: start.to_le_bytes().to_vec(),
                bytes: response,
                native_error: (start + bytes.len() as u64 * 8 < domain)
                    .then_some(bitmap_paging::MORE_DATA),
            }
        })
        .collect()
}

fn bitmap_report(raw: &NtfsInspection, before: &[IoctlQuery], after: &[IoctlQuery]) -> Report {
    let base = IoctlQuery {
        code: layout::GET_BASE,
        input: vec![],
        bytes: vec![0; 8],
        native_error: None,
    };
    Report {
        content_passes: 2,
        resources: None,
        schema_version: 6,
        request: Request {
            extent_identity_streams: vec![],
            resource_profile: None,
            schema_version: 1,
            source_inspection_sha256: "a".repeat(64),
            volume: "\\\\?\\Volume{12345678-1234-5678-1234-567812345678}\\".into(),
            disk_number: 1,
            partition_offset: 16 * 1024 * 1024,
            partition_length: raw.geometry.volume_size,
            ntfs_serial: raw.geometry.serial_number,
            files: vec![],
        },
        volume_extents_before: vec![],
        volume_extents_after: vec![],
        ntfs_data_before: vec![],
        ntfs_data_after: vec![],
        disk_attributes_before: vec![],
        disk_attributes_after: vec![],
        write_protect_error_before: 19,
        write_protect_error_after: 19,
        privileges_restored: true,
        privilege_states: vec![],
        files: vec![],
        conversion_qualified: false,
        allocation: Some(VolumeAllocation {
            base_before: base.clone(),
            base_after: base,
            bitmap_before: before[0].clone(),
            bitmap_after: after[0].clone(),
            bitmap_before_continuation: before[1..].to_vec(),
            bitmap_after_continuation: after[1..].to_vec(),
            streamed_before: None,
            streamed_after: None,
        }),
        logical_data: None,
        namespace: None,
    }
}

fn paged_stream_report() -> (NtfsInspection, Report) {
    let (mut raw, file, native) = fragmented_paged_fixture();
    raw.files = vec![file.clone()];
    let data = vec![0xa5; raw.geometry.total_clusters.div_ceil(8) as usize];
    raw.allocation_reconciliation = Some(AllocationReconciliation {
        status: AllocationReconciliationStatus::ConsistentRawModel,
        bitmap_sha256: hex::encode(Sha256::digest(&data)),
        domain_clusters: raw.geometry.total_clusters,
        physical_intervals: 0,
        detail: "isolated supplied-model paging test".into(),
    });
    let bitmap = bitmap_queries(&data, raw.geometry.total_clusters, data.len());
    let mut report = bitmap_report(&raw, &bitmap, &bitmap);
    report.schema_version = 7;
    // Every observation answers a row of the request that asked for it.
    report.request.files = vec![n2r_win32::attestation::FileIdentity {
        record_number: file.record_number,
        sequence_number: file.sequence_number,
    }];
    report.files = vec![n2r_win32::attestation::Observation {
        case_only_fallback: None,
        identity: n2r_win32::attestation::FileIdentity {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
        },
        open_error: None,
        before: None,
        after: None,
        streams_before: Some(native.clone()),
        streams_after: Some(native),
    }];
    (raw, report)
}

#[test]
fn legacy_stream_schemas_refuse_paged_retrieval_and_keep_empty_field_serialization() {
    let (raw, mut report) = paged_stream_report();
    for schema in 3..=6 {
        report.schema_version = schema;
        let error = reconcile(&raw, &report).unwrap_err().to_string();
        assert!(error.contains("paged retrieval transcripts require native schema 7"));
    }
    let (_, _, legacy) = fixture();
    for query in &legacy.streams {
        let encoded = serde_json::to_value(query).unwrap();
        assert!(encoded.get("retrieval_continuation").is_none());
        assert_eq!(
            serde_json::from_value::<StreamQuery>(encoded).unwrap(),
            *query
        );
    }
}

#[test]
fn schema_7_keeps_exact_before_and_after_retrieval_transcripts() {
    let (raw, mut report) = paged_stream_report();
    let good = reconcile(&raw, &report).unwrap();
    assert!(good.all_mappings_matched);
    assert!(!good.conversion_qualified);

    let after = report.files[0].streams_after.as_mut().unwrap();
    let runs: Vec<_> = (0..layout::MAX_EXTENTS + 1)
        .map(|index| (index as u64 + 1, 100 + index as i64 * 2))
        .collect();
    let mut first = rpp(&runs[..512]);
    first.native_error = Some(234);
    after.streams[0].retrieval = Some(first);
    after.streams[0].retrieval_continuation = vec![rpp_from(512, &runs[512..])];
    check_file(&raw.files[0], after, 0, &raw.geometry).unwrap();
    let changed = reconcile(&raw, &report).unwrap();
    assert!(changed.bitmap.matched);
    assert!(!changed.all_mappings_matched);
    assert!(
        changed.files[0]
            .check
            .detail
            .contains("native stream snapshot changed")
    );
    assert!(!changed.conversion_qualified);
}

#[test]
fn schema_7_still_requires_namespace_evidence() {
    let (raw, report) = paged_stream_report();
    assert!(ntfs2refs::ntfs_namespace_attestation::reconcile(&raw, &report).is_err());
}

#[test]
fn paged_bitmap_above_64_gib_preserves_the_raw_ntfs_tail_byte() {
    let (mut raw, _) = bitmap_fixture();
    // Only the supplied bitmap model grows; no large image or device is used.
    let count = 16 * 1024 * 1024 + 1;
    let mut data = vec![0xa5; (count as usize).div_ceil(8)];
    *data.last_mut().unwrap() = 0xe5;
    raw.geometry.total_clusters = count;
    let allocation = raw.allocation_reconciliation.as_mut().unwrap();
    allocation.domain_clusters = count;
    allocation.bitmap_sha256 = hex::encode(Sha256::digest(&data));
    // NTFS may report its byte-rounded domain. Unused tail bits still belong
    // to the raw initialized $Bitmap bytes and must not be cleared by replay.
    let mut pages = bitmap_queries(&data, count.div_ceil(8) * 8, 2 * 1024 * 1024);
    assert_eq!(pages.len(), 2);
    check_bitmap_pages(&raw, &pages[0], &pages[1..]).unwrap();
    assert!(check_bitmap(&raw, &pages[0]).is_err());
    *pages[1].bytes.last_mut().unwrap() ^= 0x80;
    assert!(check_bitmap_pages(&raw, &pages[0], &pages[1..]).is_err());
}

#[test]
fn paged_replay_rejects_missing_changed_foreign_and_gapped_continuations() {
    let (raw, q) = bitmap_fixture();
    let pages = bitmap_queries(&q.bytes[16..], 512, 32);
    check_bitmap_pages(&raw, &pages[0], &pages[1..]).unwrap();
    assert!(check_bitmap_pages(&raw, &pages[0], &[]).is_err());
    for changed in 0..5 {
        let mut bad = pages.clone();
        match changed {
            0 => bad[1].bytes[16] ^= 1,
            1 => bad[1].input = 264u64.to_le_bytes().to_vec(),
            2 => p64(&mut bad[1].bytes, 0, 264),
            3 => bad[1].native_error = Some(5),
            4 => bad[1].code ^= 1,
            _ => unreachable!(),
        }
        assert!(check_bitmap_pages(&raw, &bad[0], &bad[1..]).is_err());
    }
    let mut extra = pages.clone();
    extra.push(pages[1].clone());
    assert!(check_bitmap_pages(&raw, &extra[0], &extra[1..]).is_err());
}

#[test]
fn schema_6_requires_identical_before_and_after_raw_page_transcripts() {
    let (mut raw, q) = bitmap_fixture();
    raw.files.clear();
    let before = bitmap_queries(&q.bytes[16..], 512, 16);
    let after = bitmap_queries(&q.bytes[16..], 512, 32);
    check_bitmap_pages(&raw, &before[0], &before[1..]).unwrap();
    check_bitmap_pages(&raw, &after[0], &after[1..]).unwrap();
    let stable = reconcile(&raw, &bitmap_report(&raw, &before, &before)).unwrap();
    assert!(stable.bitmap.matched);
    assert!(stable.all_mappings_matched);
    assert!(!stable.conversion_qualified);
    let changed = reconcile(&raw, &bitmap_report(&raw, &before, &after)).unwrap();
    assert!(!changed.bitmap.matched);
    assert!(changed.bitmap.detail.contains("native bitmap changed"));
    assert!(!changed.all_mappings_matched);
    assert!(!changed.conversion_qualified);
}

#[test]
fn older_stream_schemas_only_accept_the_legacy_single_response_shape() {
    let (mut raw, q) = bitmap_fixture();
    raw.files.clear();
    let pages = bitmap_queries(&q.bytes[16..], 512, 32);
    for schema in 3..=5 {
        let mut legacy = bitmap_report(&raw, std::slice::from_ref(&q), std::slice::from_ref(&q));
        legacy.schema_version = schema;
        let encoded = serde_json::to_value(&legacy).unwrap();
        assert!(
            encoded["allocation"]
                .get("bitmap_before_continuation")
                .is_none()
        );
        assert!(
            encoded["allocation"]
                .get("bitmap_after_continuation")
                .is_none()
        );
        let decoded: Report = serde_json::from_value(encoded).unwrap();
        assert!(reconcile(&raw, &decoded).unwrap().all_mappings_matched);
        let mut paged = bitmap_report(&raw, &pages, &pages);
        paged.schema_version = schema;
        let error = reconcile(&raw, &paged).unwrap_err().to_string();
        assert!(error.contains("paged bitmap transcripts require native schema 6"));
    }
}

#[test]
fn schema_6_does_not_make_namespace_evidence_optional() {
    let (raw, q) = bitmap_fixture();
    let report = bitmap_report(&raw, std::slice::from_ref(&q), std::slice::from_ref(&q));
    let error = ntfs2refs::ntfs_namespace_attestation::reconcile(&raw, &report)
        .unwrap_err()
        .to_string();
    assert!(!error.contains("native namespace evidence profile absent"));
    assert!(
        error.contains("raw namespace is incomplete")
            || error.contains("missing native namespace evidence")
    );
}

#[test]
fn two_128_gib_bitmap_transcripts_fit_the_expanded_report_bound() {
    let (mut raw, _) = bitmap_fixture();
    raw.files.clear();
    let data = vec![0xa5; bitmap_paging::MAX_DATA_BYTES];
    let count = data.len() as u64 * 8;
    raw.geometry.total_clusters = count;
    let allocation = raw.allocation_reconciliation.as_mut().unwrap();
    allocation.domain_clusters = count;
    allocation.bitmap_sha256 = hex::encode(Sha256::digest(&data));
    let pages = bitmap_queries(&data, count, 2 * 1024 * 1024);
    check_bitmap_pages(&raw, &pages[0], &pages[1..]).unwrap();
    let encoded = serde_json::to_vec(&bitmap_report(&raw, &pages, &pages)).unwrap();
    assert!(encoded.len() > 16 * 1024 * 1024);
    assert!(encoded.len() < 64 * 1024 * 1024);
    let decoded: Report = serde_json::from_slice(&encoded).unwrap();
    let result = reconcile(&raw, &decoded).unwrap();
    assert!(result.all_mappings_matched);
    assert!(!result.conversion_qualified);
}
