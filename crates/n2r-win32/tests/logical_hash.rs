use n2r_win32::logical_hash::{self, Budget, Status};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
#[test]
fn hashes_full_data_and_confirms_eof() {
    let data = vec![0xa5; 65537];
    let mut b = Budget::new(65538);
    let h = logical_hash::read(&mut Cursor::new(&data), 65537, &mut b);
    assert_eq!(h.status, Status::Complete);
    assert_eq!(h.sha256, Some(hex::encode(Sha256::digest(&data))));
    assert!(h.eof_confirmed);
    assert_eq!(h.bytes_read, 65537);
    assert_eq!(b.audit().reserved_bytes, 65538);
    assert_eq!(b.audit().bytes_read, 65537);
    assert_eq!(b.audit().eof_probes, 1);
}
#[test]
fn empty_stream_still_requires_eof_probe() {
    let mut b = Budget::new(1);
    let h = logical_hash::read(&mut Cursor::new([]), 0, &mut b);
    assert_eq!(h.status, Status::Complete);
    assert_eq!(h.sha256, Some(hex::encode(Sha256::digest([]))));
    assert_eq!(b.audit().read_calls, 1);
}
#[test]
fn truncated_data_has_no_digest() {
    let mut b = Budget::new(10);
    let h = logical_hash::read(&mut Cursor::new(b"ab"), 3, &mut b);
    assert_eq!(h.status, Status::UnexpectedEof);
    assert_eq!(h.bytes_read, 2);
    assert!(h.sha256.is_none());
}
#[test]
fn data_beyond_declared_eof_is_refused() {
    let mut b = Budget::new(3);
    let h = logical_hash::read(&mut Cursor::new(b"abc"), 2, &mut b);
    assert_eq!(h.status, Status::ExpectedEofMissing);
    assert_eq!(h.bytes_read, 3);
    assert!(!h.eof_confirmed);
    assert!(h.sha256.is_none());
}
#[test]
fn budget_is_cumulative_and_includes_probes() {
    let mut b = Budget::new(5);
    assert_eq!(
        logical_hash::read(&mut Cursor::new(b"ab"), 2, &mut b).status,
        Status::Complete
    );
    let h = logical_hash::read(&mut Cursor::new(b"ab"), 2, &mut b);
    assert_eq!(h.status, Status::BudgetExceeded);
    assert_eq!(b.audit().read_calls, 2);
    assert_eq!(b.audit().reserved_bytes, 3);
}
#[test]
fn overflow_and_zero_budget_do_not_read() {
    for (limit, size) in [(0, 0), (u64::MAX, u64::MAX)] {
        let mut b = Budget::new(limit);
        let h = logical_hash::read(&mut Cursor::new([]), size, &mut b);
        assert_eq!(h.status, Status::BudgetExceeded);
        assert_eq!(b.audit().read_calls, 0);
    }
}
#[test]
fn each_pass_seeks_back_to_zero() {
    let mut c = Cursor::new(b"abc");
    c.set_position(2);
    let mut b = Budget::new(8);
    let first = logical_hash::read(&mut c, 3, &mut b);
    let second = logical_hash::read(&mut c, 3, &mut b);
    assert_eq!(first, second);
    assert_eq!(first.status, Status::Complete);
}
struct Interrupted;
impl Read for Interrupted {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    }
}
impl Seek for Interrupted {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}
#[test]
fn repeated_interruptions_are_bounded() {
    let mut b = Budget::new(2);
    let h = logical_hash::read(&mut Interrupted, 1, &mut b);
    assert_eq!(h.status, Status::ReadRefused);
    assert_eq!(b.audit().read_calls, 9);
    assert!(h.sha256.is_none());
}
struct BadSeek;
impl Read for BadSeek {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("read after failed seek")
    }
}
impl Seek for BadSeek {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Err(io::Error::other("seek refused"))
    }
}
#[test]
fn failed_seek_does_not_read() {
    let mut b = Budget::new(2);
    let h = logical_hash::read(&mut BadSeek, 1, &mut b);
    assert_eq!(h.status, Status::ReadRefused);
    assert_eq!(b.audit().read_calls, 0);
    assert!(h.sha256.is_none());
}
struct Short(Cursor<Vec<u8>>);
impl Read for Short {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(&mut b[..1])
    }
}
impl Seek for Short {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.0.seek(p)
    }
}
#[test]
fn short_successful_reads_are_assembled() {
    let mut b = Budget::new(4);
    let h = logical_hash::read(&mut Short(Cursor::new(b"abc".to_vec())), 3, &mut b);
    assert_eq!(h.status, Status::Complete);
    assert_eq!(b.audit().read_calls, 4);
}

struct ReadFailure;
impl Read for ReadFailure {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(5))
    }
}
impl Seek for ReadFailure {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}
#[test]
fn read_failure_is_explicit_and_has_no_digest() {
    let mut b = Budget::new(2);
    let h = logical_hash::read(&mut ReadFailure, 1, &mut b);
    assert_eq!(h.status, Status::ReadRefused);
    assert_eq!(h.native_error, Some(5));
    assert!(h.sha256.is_none());
    assert_eq!(h.bytes_read, 0);
    assert_eq!(b.audit().read_calls, 1);
}
