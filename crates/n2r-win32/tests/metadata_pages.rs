#![cfg(windows)]
use n2r_win32::metadata_pages::{PageBudget, Reader, Writer};
use std::io::{Read, Seek, SeekFrom, Write};

const PURPOSE: [u8; 8] = *b"TESTPAGE";
const RECORDS: u64 = 500;

fn budget() -> PageBudget {
    // Small pages so a modest record count spans many of them.
    PageBudget {
        max_page_bytes: 512,
        max_records_per_page: 8,
        max_records: 10_000,
        max_pages: 10_000,
        max_file_bytes: 16 * 1024 * 1024,
    }
}
fn key(ordinal: u64) -> Vec<u8> {
    format!("key-{ordinal:08}").into_bytes()
}
fn payload(ordinal: u64) -> Vec<u8> {
    format!("{{\"ordinal\":{ordinal},\"pad\":\"{}\"}}", "x".repeat((ordinal % 23) as usize))
        .into_bytes()
}
fn write(path: &std::path::Path) -> String {
    let mut writer = Writer::new(path, PURPOSE, budget()).unwrap();
    for ordinal in 0..RECORDS {
        writer.push(&key(ordinal), &payload(ordinal)).unwrap();
    }
    let summary = writer.finish().unwrap();
    assert!(summary.pages > 8, "fixture must span many pages");
    summary.sha256
}
/// A fixed scattered order: every lookup lands on a different page.
fn scattered() -> impl Iterator<Item = u64> {
    (0..RECORDS).map(|step| (step * 211) % RECORDS)
}

#[test]
fn resident_pages_answer_scattered_lookups_without_further_page_loads() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap().join("pages.bin");
    // canonicalize yields a \\?\C:\ path; the reader wants the plain drive form.
    let path = std::path::PathBuf::from(path.to_str().unwrap().trim_start_matches(r"\\?\"));
    let sha = write(&path);

    let mut paged = Reader::open(&path, &sha, PURPOSE, budget()).unwrap();
    let opened = paged.page_cache_statistics();
    for ordinal in scattered() {
        let record = paged.get(ordinal).unwrap();
        assert_eq!((record.key, record.payload), (key(ordinal), payload(ordinal)));
    }
    let thrash = paged.page_cache_statistics().page_loads - opened.page_loads;
    assert!(thrash > RECORDS / 2, "one-page cache should reload on scattered lookups");

    let mut resident = Reader::open(&path, &sha, PURPOSE, budget()).unwrap();
    assert!(resident.resident_page_bytes().unwrap() >= resident.byte_len() / 2);
    resident.install_resident_pages().unwrap();
    assert!(resident.pages_resident());
    let installed = resident.page_cache_statistics();
    assert_eq!(
        installed.page_loads,
        opened.page_loads + resident.page_count(),
        "installing reads each page exactly once more"
    );
    for ordinal in scattered() {
        let record = resident.get(ordinal).unwrap();
        assert_eq!((record.key, record.payload), (key(ordinal), payload(ordinal)));
    }
    let after = resident.page_cache_statistics();
    assert_eq!(after.page_loads, installed.page_loads);
    assert_eq!(after.misses, installed.misses);
    assert_eq!(after.hits - installed.hits, RECORDS);
    assert!(resident.get(RECORDS).is_err());
    assert!(resident.install_resident_pages().is_err());
}

#[test]
fn a_corrupt_page_is_refused_when_opened() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap().join("pages.bin");
    let path = std::path::PathBuf::from(path.to_str().unwrap().trim_start_matches(r"\\?\"));
    let sha = write(&path);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut byte = [0];
    file.seek(SeekFrom::Start(300)).unwrap();
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Start(300)).unwrap();
    file.write_all(&[byte[0] ^ 0xff]).unwrap();
    drop(file);
    assert!(Reader::open(&path, &sha, PURPOSE, budget()).is_err());
}
