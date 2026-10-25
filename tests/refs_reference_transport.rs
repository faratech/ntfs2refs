use ntfs2refs::refs_reference_transport::{self as transport, CHUNK_BYTES, Selection};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Seek, SeekFrom};
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn fixture() -> (Vec<u8>, Selection) {
    let mut body = vec![0; 3 * CHUNK_BYTES];
    body[0] = 0x42;
    let payload = CHUNK_BYTES + 4096;
    body[payload..payload + 4096].fill(0x6d);
    let mut footer = [0u8; 512];
    footer[..8].copy_from_slice(b"conectix");
    footer[8..12].copy_from_slice(&2u32.to_be_bytes());
    footer[12..16].copy_from_slice(&0x10000u32.to_be_bytes());
    footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    footer[40..48].copy_from_slice(&(body.len() as u64).to_be_bytes());
    footer[48..56].copy_from_slice(&(body.len() as u64).to_be_bytes());
    footer[60..64].copy_from_slice(&2u32.to_be_bytes());
    footer[68..84].fill(0x31);
    let sum: u32 = footer.iter().map(|b| u32::from(*b)).sum();
    footer[64..68].copy_from_slice(&(!sum).to_be_bytes());
    let partition_sha256 = hash(&body[CHUNK_BYTES..]);
    let payload_sha256 = hash(&body[payload..payload + 4096]);
    let disk_bytes = body.len() as u64;
    body.extend_from_slice(&footer);
    let fixed_vhd_sha256 = hash(&body);
    (
        body,
        Selection {
            schema_version: 1,
            disk_bytes,
            fixed_vhd_sha256,
            partition_offset: CHUNK_BYTES as u64,
            partition_bytes: 2 * CHUNK_BYTES as u64,
            partition_sha256,
            payload_offset: 4096,
            payload_bytes: 4096,
            payload_sha256,
        },
    )
}
fn packet() -> (Vec<u8>, Vec<u8>, Selection) {
    let (source, selection) = fixture();
    let mut packet = vec![];
    transport::encode(&mut Cursor::new(&source), &mut packet, &selection).unwrap();
    (source, packet, selection)
}
#[test]
fn transport_reconstructs_every_zero_and_nonzero_byte_without_a_large_output() {
    let (source, packet, selection) = packet();
    let decoded = transport::decode(&mut Cursor::new(&packet)).unwrap();
    assert_eq!(decoded.chunks().len(), 2);
    assert_eq!(decoded.summary.nonzero_bytes, 2 * CHUNK_BYTES as u64);
    assert!((packet.len() as u64) < selection.disk_bytes);
    decoded.verify_reconstructed_contents().unwrap();
    let mut reader = decoded.reader();
    let mut actual = vec![];
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, &source[..selection.disk_bytes as usize]);
    reader
        .seek(SeekFrom::Start(2 * CHUNK_BYTES as u64))
        .unwrap();
    let mut hole = [1; 4096];
    reader.read_exact(&mut hole).unwrap();
    assert_eq!(hole, [0; 4096]);
    assert!(reader.seek(SeekFrom::End(1)).is_err());
    assert!(
        reader
            .seek(SeekFrom::Current(-1i64 - (2 * CHUNK_BYTES + 4096) as i64))
            .is_err()
    );
}
#[test]
fn damaged_record_trailer_and_extra_data_fail_closed() {
    let (_, packet, _) = packet();
    let header_len = u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize;
    let record = 12 + header_len;
    let mut damaged = packet.clone();
    damaged[record + 52] ^= 1;
    assert!(transport::decode(&mut Cursor::new(damaged)).is_err());
    assert!(transport::decode(&mut Cursor::new(&packet[..packet.len() - 3])).is_err());
    let mut extra = packet.clone();
    extra.push(1);
    assert!(transport::decode(&mut Cursor::new(extra)).is_err());
    let mut overlap = packet.clone();
    let second = record + 52 + CHUNK_BYTES;
    overlap[second + 8..second + 16].copy_from_slice(&0u64.to_le_bytes());
    assert!(transport::decode(&mut Cursor::new(overlap)).is_err());
}
#[test]
fn moving_a_valid_record_cannot_pass_full_source_reconstruction() {
    let (_, mut packet, _) = packet();
    let header_len = u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize;
    let second = 12 + header_len + 52 + CHUNK_BYTES;
    packet[second + 8..second + 16].copy_from_slice(&(2 * CHUNK_BYTES as u64).to_le_bytes());
    let parsed = transport::decode(&mut Cursor::new(packet)).unwrap();
    assert!(parsed.verify_reconstructed_contents().is_err());
}
#[test]
fn source_pins_and_footer_are_required_before_successful_trailer() {
    let (mut source, mut s) = fixture();
    s.partition_sha256 = "1".repeat(64);
    let mut output = vec![];
    assert!(transport::encode(&mut Cursor::new(&source), &mut output, &s).is_err());
    assert!(transport::decode(&mut Cursor::new(output)).is_err());
    let (_, s) = fixture();
    let end = source.len() - 512;
    source[end + 60] = 7;
    assert!(transport::encode(&mut Cursor::new(source), &mut vec![], &s).is_err());
    let (_, mut s) = fixture();
    s.payload_offset = u64::MAX;
    assert!(s.validate().is_err());
    s.payload_offset = 0;
    s.disk_bytes = u64::MAX;
    assert!(s.validate().is_err());
}
#[test]
fn file_packing_preserves_source_and_never_replaces_existing_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let (source, s) = fixture();
    let input = dir.path().join("source.vhd");
    let output = dir.path().join("reference.n2rref");
    std::fs::write(&input, &source).unwrap();
    let report = transport::pack_files(&input, &output, &s).unwrap();
    assert_eq!(report.devices_written, 0);
    assert!(!report.native_import_qualified);
    assert_eq!(report.packet_sha256, hash(&std::fs::read(&output).unwrap()));
    assert_eq!(std::fs::read(&input).unwrap(), source);
    assert!(transport::pack_files(&input, &output, &s).is_err());
    assert_eq!(report.packet_sha256, hash(&std::fs::read(&output).unwrap()));
}
