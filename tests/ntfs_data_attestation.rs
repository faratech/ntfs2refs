#[allow(dead_code, reason = "Shared synthetic parser fixture")]
mod support;
use n2r_win32::{
    attestation::{FileIdentity, LogicalFile, Query, StreamHash},
    logical_hash::{Outcome, Status},
};
use ntfs2refs::{
    ntfs_data_attestation::check_file,
    ntfs_inspect::{self, FileInventory, LogicalHashStatus},
};
use sha2::{Digest, Sha256};
use std::io::Cursor;
fn put(b: &mut [u8], o: usize, n: u64) {
    b[o..o + 8].copy_from_slice(&n.to_le_bytes());
}
fn fixture() -> (FileInventory, LogicalFile, u64) {
    let bytes = support::image();
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    let f = raw
        .files
        .into_iter()
        .find(|f| f.record_number == 16)
        .unwrap();
    let serial = raw.geometry.serial_number;
    let n = observation(&f, serial);
    (f, n, serial)
}
fn observation(f: &FileInventory, serial: u64) -> LogicalFile {
    let mut id = vec![0; 24];
    put(&mut id, 0, serial);
    put(
        &mut id,
        8,
        f.record_number | (u64::from(f.sequence_number) << 48),
    );
    let identity = Query {
        class: 18,
        bytes: id,
        native_error: None,
    };
    let data: Vec<_> = f
        .streams
        .iter()
        .map(|s| {
            let mut bytes = vec![0; 24];
            put(&mut bytes, 8, s.logical_size);
            let standard = Query {
                class: 1,
                bytes,
                native_error: None,
            };
            StreamHash {
                name_utf16: s.name_utf16.clone(),
                logical_size: s.logical_size,
                identity_before: Some(identity.clone()),
                identity_after: Some(identity.clone()),
                standard_before: Some(standard.clone()),
                standard_after: Some(standard),
                outcome: Outcome {
                    status: Status::Complete,
                    bytes_read: s.logical_size,
                    eof_confirmed: true,
                    sha256: s.logical_sha256.clone(),
                    native_error: None,
                    detail: None,
                },
            }
        })
        .collect();
    LogicalFile {
        identity: FileIdentity {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
        },
        before: data.clone(),
        after: data,
    }
}
#[test]
fn matches_default_stream_and_ads() {
    let (f, n, s) = fixture();
    assert_eq!(check_file(&f, &n, s).unwrap(), 25);
}
#[test]
fn missing_ads_is_refused() {
    let (f, mut n, s) = fixture();
    n.before.pop();
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn digest_mismatch_is_refused() {
    let (f, mut n, s) = fixture();
    n.after[0].outcome.sha256 = Some("0".repeat(64));
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn partial_native_read_is_refused() {
    let (f, mut n, s) = fixture();
    n.before[0].outcome.status = Status::UnexpectedEof;
    n.before[0].outcome.sha256 = None;
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn eof_must_be_confirmed() {
    let (f, mut n, s) = fixture();
    n.after[0].outcome.eof_confirmed = false;
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn wrong_identity_is_refused() {
    let (f, mut n, s) = fixture();
    n.after[0].identity_after.as_mut().unwrap().bytes[8] ^= 1;
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn changed_standard_information_is_refused() {
    let (f, mut n, s) = fixture();
    n.after[0].standard_after.as_mut().unwrap().bytes[0] ^= 1;
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn mismatched_native_eof_is_refused() {
    let (f, mut n, s) = fixture();
    n.after[0].standard_after.as_mut().unwrap().bytes[8] ^= 1;
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn incomplete_raw_logical_hash_does_not_pass() {
    let (mut f, n, s) = fixture();
    f.streams[0].logical_hash_status = LogicalHashStatus::NotComputed;
    assert!(check_file(&f, &n, s).is_err());
}
#[test]
fn duplicate_stream_is_refused() {
    let (f, mut n, s) = fixture();
    n.before[1] = n.before[0].clone();
    assert!(check_file(&f, &n, s).is_err());
}

#[test]
fn native_logical_zero_tail_matches_without_exposing_stale_physical_bytes() {
    let mut bytes = support::image();
    let mut data = support::nonresident(0x80, &[0x11, 2, 100, 0], 5001, 2);
    data[56..64].copy_from_slice(&4099u64.to_le_bytes());
    let record_at = 4 * 4096 + 16 * 1024;
    bytes[record_at..record_at + 1024].copy_from_slice(&support::record(&[data], 1, 1));
    bytes[100 * 4096..102 * 4096].fill(0xdd);
    bytes[100 * 4096..100 * 4096 + 4099].fill(0x41);
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    let f = raw.files.iter().find(|f| f.record_number == 16).unwrap();
    let logical = [vec![0x41; 4099], vec![0; 902]].concat();
    let logical_hash = n2r_win32::content_digest::of(&logical);
    assert_eq!(f.streams[0].logical_sha256.as_ref(), Some(&logical_hash));
    let mut n = observation(f, raw.geometry.serial_number);
    for pass in [&mut n.before, &mut n.after] {
        pass[0].outcome.sha256 = Some(logical_hash.clone());
    }
    assert_eq!(check_file(f, &n, raw.geometry.serial_number).unwrap(), 5001);
    // A native observation exposing stale disk bytes must fail reconciliation.
    n.after[0].outcome.sha256 = Some(n2r_win32::content_digest::of(
        &bytes[100 * 4096..100 * 4096 + 5001],
    ));
    assert!(check_file(f, &n, raw.geometry.serial_number).is_err());
}
