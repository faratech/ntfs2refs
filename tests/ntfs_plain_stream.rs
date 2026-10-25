#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use ntfs2refs::ntfs_inspect::{self, LogicalHashStatus};
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

    let mut changed = image;
    changed[100 * 4096] ^= 1;
    assert!(ntfs_inspect::read_plain_stream(&mut Cursor::new(changed), &raw, 16, 1024).is_err());
}
