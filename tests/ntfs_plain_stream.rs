#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use ntfs2refs::{
    ntfs_inspect::{self, LogicalHashStatus},
    ntfs_stream_plan::{self, Disposition},
};
use sha2::Digest;
use std::io::Cursor;

#[test]
fn logical_reader_recovers_resident_and_nonresident_bytes_and_rejects_changed_payload() {
    let image = support::image();
    let mut source = Cursor::new(&image);
    let raw = ntfs_inspect::inspect(&mut source, image.len() as u64).unwrap();
    assert_eq!(
        raw.files
            .iter()
            .find(|f| f.record_number == 16)
            .unwrap()
            .streams
            .iter()
            .find(|s| s.name_utf16.is_empty())
            .unwrap()
            .logical_hash_status,
        LogicalHashStatus::Complete
    );
    assert_eq!(
        ntfs_inspect::read_plain_stream(&mut source, &raw, 16, 1024).unwrap(),
        b"Synthetic content"
    );
    let mut streamed = Vec::new();
    let proof =
        ntfs_inspect::copy_plain_stream(&mut source, &raw, 16, 1024, &mut streamed).unwrap();
    assert_eq!(streamed, b"Synthetic content");
    assert!(proof.stream_name_utf16.is_empty());
    assert_eq!(proof.logical_bytes, 17);
    assert_eq!(
        proof.sha256,
        raw.files
            .iter()
            .find(|f| f.record_number == 16)
            .unwrap()
            .streams[0]
            .logical_sha256
            .as_deref()
            .unwrap()
    );
    let mut named = Vec::new();
    let named_proof = ntfs_inspect::copy_plain_named_stream(
        &mut source,
        &raw,
        16,
        &"note".encode_utf16().collect::<Vec<_>>(),
        1024,
        &mut named,
    )
    .unwrap();
    assert_eq!(named, b"metadata");
    assert_eq!(
        named_proof.stream_name_utf16,
        "note".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(named_proof.logical_bytes, 8);
    assert!(
        ntfs_inspect::copy_plain_named_stream(
            &mut source,
            &raw,
            16,
            &"missing".encode_utf16().collect::<Vec<_>>(),
            1024,
            &mut Vec::new(),
        )
        .is_err()
    );
    let resident = ntfs_inspect::read_plain_stream(&mut source, &raw, 6, 1024).unwrap();
    assert_eq!(resident.len(), 64);
    assert_eq!(resident[0], 0xf1);
    assert_eq!(
        ntfs_inspect::hash_plain_stream_range(&mut source, &raw, 16, 10, 7, 1024).unwrap(),
        hex::encode(sha2::Sha256::digest(b"content"))
    );
    assert!(ntfs_inspect::hash_plain_stream_range(&mut source, &raw, 16, 17, 1, 1024).is_err());

    let mut changed = image;
    changed[100 * 4096] ^= 1;
    assert!(ntfs_inspect::read_plain_stream(&mut Cursor::new(changed), &raw, 16, 1024).is_err());
}

#[test]
fn source_stream_plan_separates_retainable_payload_from_named_materialization() {
    let image = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(image), 2 * 1024 * 1024).unwrap();
    let initial = ntfs_stream_plan::classify(&raw);
    let user: Vec<_> = initial
        .streams
        .iter()
        .filter(|s| s.record_number == 16)
        .collect();
    assert_eq!(user.len(), 2);
    assert!(
        user.iter()
            .all(|s| s.disposition == Disposition::MaterializeCandidate)
    );
    assert!(user.iter().any(|s| s.target_named_stream_support_pending));
    let file = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap();
    let stream = file
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = 4096;
    stream.initialized_size = 4096;
    stream.allocated_size = 4096;
    stream.extents[0].length = 4096;
    let planned = ntfs_stream_plan::classify(&raw);
    let retained = planned
        .streams
        .iter()
        .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
        .unwrap();
    assert_eq!(retained.disposition, Disposition::RetainCandidate);
    assert_eq!(retained.source_offset, Some(100 * 4096));
    assert_eq!(planned.retained_candidate_bytes, 4096);
    assert!(!planned.executable);
}

#[test]
fn source_stream_plan_keeps_complete_fragmented_ordinary_runs() {
    let image = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(image), 2 * 1024 * 1024).unwrap();
    let stream = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap()
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = 8192;
    stream.initialized_size = 8192;
    stream.allocated_size = 8192;
    stream.extents = vec![
        ntfs_inspect::Extent {
            logical_offset: 0,
            physical_offset: Some(100 * 4096),
            length: 4096,
        },
        ntfs_inspect::Extent {
            logical_offset: 4096,
            physical_offset: Some(102 * 4096),
            length: 4096,
        },
    ];
    let expected_extents = stream.extents.clone();
    let planned = ntfs_stream_plan::classify(&raw);
    let candidate = planned
        .streams
        .iter()
        .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
        .unwrap();
    assert_eq!(candidate.disposition, Disposition::RetainCandidate);
    assert_eq!(candidate.source_offset, None);
    assert_eq!(candidate.source_extents, expected_extents);
    assert_eq!(planned.retained_candidate_bytes, 8192);

    let stream = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap()
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = 4097;
    stream.initialized_size = 4097;
    let mixed = ntfs_stream_plan::classify(&raw);
    let candidate = mixed
        .streams
        .iter()
        .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
        .unwrap();
    assert_eq!(candidate.disposition, Disposition::MixedCandidate);
    assert_eq!(candidate.source_extents.len(), 1);
    assert_eq!(candidate.source_extents[0], expected_extents[0]);
    assert_eq!(mixed.retained_candidate_bytes, 4096);
}

#[test]
fn source_stream_plan_retains_full_clusters_before_a_partial_tail() {
    let image = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(image), 2 * 1024 * 1024).unwrap();
    let stream = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap()
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = 4097;
    stream.initialized_size = 4097;
    stream.allocated_size = 8192;
    stream.extents[0].length = 8192;
    let planned = ntfs_stream_plan::classify(&raw);
    let candidate = planned
        .streams
        .iter()
        .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
        .unwrap();
    assert_eq!(candidate.disposition, Disposition::MixedCandidate);
    assert_eq!(candidate.source_offset, None);
    assert_eq!(
        candidate.source_extents,
        vec![ntfs_inspect::Extent {
            logical_offset: 0,
            physical_offset: Some(100 * 4096),
            length: 4096,
        }]
    );
    assert_eq!(planned.retained_candidate_bytes, 4096);
    assert_eq!(planned.materialized_candidate_bytes, 1 + 8);
}

#[test]
fn source_stream_plan_never_adopts_uninitialized_clusters() {
    let image = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(image), 2 * 1024 * 1024).unwrap();
    let stream = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap()
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = 16384;
    stream.initialized_size = 5000;
    stream.allocated_size = 16384;
    stream.extents[0].length = 16384;
    let planned = ntfs_stream_plan::classify(&raw);
    let candidate = planned
        .streams
        .iter()
        .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
        .unwrap();
    assert_eq!(candidate.disposition, Disposition::MixedCandidate);
    assert_eq!(candidate.source_extents.len(), 1);
    assert_eq!(candidate.source_extents[0].length, 4096);
    assert_eq!(planned.retained_candidate_bytes, 4096);
    assert_eq!(planned.materialized_candidate_bytes, 16384 - 4096 + 8);
}

#[test]
fn source_stream_plan_retains_payload_without_adopting_preallocation() {
    let image = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(image), 2 * 1024 * 1024).unwrap();
    let stream = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap()
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = 4096;
    stream.initialized_size = 4096;
    stream.allocated_size = 16384;
    stream.extents[0].length = 16384;
    let planned = ntfs_stream_plan::classify(&raw);
    let candidate = planned
        .streams
        .iter()
        .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
        .unwrap();
    assert_eq!(candidate.disposition, Disposition::RetainCandidate);
    assert_eq!(candidate.source_offset, Some(100 * 4096));
    assert!(candidate.source_extents.is_empty());
    assert_eq!(candidate.logical_bytes, 4096);
    assert_eq!(planned.retained_candidate_bytes, 4096);
    // Only the unrelated named stream contributes materialized logical bytes.
    assert_eq!(planned.materialized_candidate_bytes, 8);
    assert!(!planned.source_admitted && !planned.executable);
}

#[test]
fn preallocated_fragmented_stream_retains_only_full_initialized_prefix() {
    let image = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(image), 2 * 1024 * 1024).unwrap();
    let stream = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap()
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = 12289;
    stream.initialized_size = 9000;
    stream.allocated_size = 32768;
    stream.extents = vec![
        ntfs_inspect::Extent {
            logical_offset: 0,
            physical_offset: Some(100 * 4096),
            length: 4096,
        },
        ntfs_inspect::Extent {
            logical_offset: 4096,
            physical_offset: Some(105 * 4096),
            length: 12288,
        },
        ntfs_inspect::Extent {
            logical_offset: 16384,
            physical_offset: Some(120 * 4096),
            length: 16384,
        },
    ];
    let planned = ntfs_stream_plan::classify(&raw);
    let candidate = planned
        .streams
        .iter()
        .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
        .unwrap();
    assert_eq!(candidate.disposition, Disposition::MixedCandidate);
    assert_eq!(candidate.source_offset, None);
    assert_eq!(candidate.source_extents.len(), 2);
    assert_eq!(candidate.source_extents[0].length, 4096);
    assert_eq!(candidate.source_extents[1].logical_offset, 4096);
    assert_eq!(candidate.source_extents[1].length, 4096);
    assert_eq!(planned.retained_candidate_bytes, 8192);
    assert_eq!(planned.materialized_candidate_bytes, 12289 - 8192 + 8);
    // Missing, sparse or unaligned physical ownership never qualifies.
    for malformed in 0..4 {
        let mut changed = raw.clone();
        let stream = changed
            .files
            .iter_mut()
            .find(|f| f.record_number == 16)
            .unwrap()
            .streams
            .iter_mut()
            .find(|s| s.name_utf16.is_empty())
            .unwrap();
        match malformed {
            0 => {
                stream.extents.pop();
            }
            1 => stream.extents[2].physical_offset = None,
            2 => stream.allocated_size += 1,
            _ => stream.allocated_size = 8192,
        }
        let plan = ntfs_stream_plan::classify(&changed);
        let candidate = plan
            .streams
            .iter()
            .find(|s| s.record_number == 16 && s.name_utf16.is_empty())
            .unwrap();
        assert_eq!(candidate.disposition, Disposition::MaterializeCandidate);
        assert!(candidate.source_offset.is_none() && candidate.source_extents.is_empty());
    }
}
