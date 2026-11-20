//! The record store under the check-once policy. The policy is a process-wide
//! switch, so these tests have a test binary of their own.
#![cfg(windows)]
use n2r_win32::metadata_pages::{PageBudget, Reader, Writer};
use n2r_win32::verify_policy;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

const PURPOSE: [u8; 8] = *b"TESTPAGE";
const RECORDS: u64 = 2_000;

fn budget() -> PageBudget {
    // Pages of about a hundred records, so in-page lookups have far to scan.
    PageBudget {
        max_page_bytes: 8 * 1024,
        max_records_per_page: 4096,
        max_records: 100_000,
        max_pages: 10_000,
        max_file_bytes: 16 * 1024 * 1024,
    }
}
fn key(ordinal: u64) -> Vec<u8> {
    format!("key-{ordinal:08}").into_bytes()
}
fn payload(ordinal: u64) -> Vec<u8> {
    format!(
        "{{\"ordinal\":{ordinal},\"pad\":\"{}\"}}",
        "x".repeat((ordinal % 23) as usize)
    )
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
fn fixture(directory: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = directory.path().canonicalize().unwrap().join(name);
    // canonicalize yields a \\?\C:\ path; the reader wants the plain drive form.
    PathBuf::from(path.to_str().unwrap().trim_start_matches(r"\\?\"))
}
/// The gate is process-wide; tests that open or need one take turns.
static GATE_TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn a_file_this_process_wrote_opens_without_being_read_and_answers_any_order() {
    let _turn = GATE_TURN.lock().unwrap();
    verify_policy::check_once();
    let directory = tempfile::tempdir().unwrap();
    let path = fixture(&directory, "pages.bin");
    let sha = write(&path);

    let mut reader = Reader::open(&path, &sha, PURPOSE, budget()).unwrap();
    assert_eq!(
        reader.page_cache_statistics().page_loads,
        0,
        "opening a file written here loads no page"
    );
    assert_eq!(reader.len(), RECORDS);
    // Backwards, then scattered, then forwards: every way of landing in a page.
    let orders: [Box<dyn Iterator<Item = u64>>; 3] = [
        Box::new((0..RECORDS).rev()),
        Box::new((0..RECORDS).map(|step| (step * 211) % RECORDS)),
        Box::new(0..RECORDS),
    ];
    for order in orders {
        for ordinal in order {
            let record = reader.get(ordinal).unwrap();
            assert_eq!(
                (record.key, record.payload),
                (key(ordinal), payload(ordinal))
            );
        }
    }
}

#[test]
fn the_sha_a_writer_reports_is_the_sha_of_the_file() {
    let _turn = GATE_TURN.lock().unwrap();
    verify_policy::check_once();
    let directory = tempfile::tempdir().unwrap();
    let path = fixture(&directory, "pages.bin");
    let sha = write(&path);
    let bytes = std::fs::read(&path).unwrap();
    // A store this build writes is pinned by BLAKE3 (`bulk_digest`).
    let actual =
        n2r_win32::bulk_digest::digest(n2r_win32::bulk_digest::Algorithm::Blake3, &bytes).unwrap();
    assert_eq!(sha, hex::encode(actual));
}

/// A second reader of the same file uses the pages the first one holds.
#[test]
fn a_second_reader_of_a_file_shares_the_pages_the_first_holds() {
    let _turn = GATE_TURN.lock().unwrap();
    verify_policy::check_once();
    let directory = tempfile::tempdir().unwrap();
    let path = fixture(&directory, "pages.bin");
    let sha = write(&path);
    let mut first = Reader::open(&path, &sha, PURPOSE, budget()).unwrap();
    // Nothing to share before a reader holds the pages.
    assert!(!first.share_resident_pages());
    first.install_resident_pages().unwrap();
    assert!(first.share_resident_pages(), "it holds them itself");

    let mut second = Reader::open(&path, &sha, PURPOSE, budget()).unwrap();
    let opened = second.page_cache_statistics().page_loads;
    assert!(second.share_resident_pages());
    assert!(second.pages_resident());
    for ordinal in (0..RECORDS).map(|step| (step * 211) % RECORDS) {
        let record = second.get(ordinal).unwrap();
        assert_eq!(
            (record.key, record.payload),
            (key(ordinal), payload(ordinal))
        );
    }
    assert_eq!(
        second.page_cache_statistics().page_loads,
        opened,
        "no page was read for the second reader"
    );
    // They are given up for both at once, and each reads its file again.
    assert!(n2r_win32::evict::evict_all());
    assert!(!first.pages_resident() && !second.pages_resident());
    assert!(!second.share_resident_pages());
    assert_eq!(first.get(7).unwrap().payload, payload(7));
    assert_eq!(second.get(7).unwrap().payload, payload(7));
    // A reader of another file shares nothing.
    let other_path = path.with_file_name("other.bin");
    let mut writer = Writer::new(&other_path, PURPOSE, budget()).unwrap();
    writer.push(&key(0), &payload(0)).unwrap();
    let other_sha = writer.finish().unwrap().sha256;
    first.install_resident_pages().unwrap();
    let mut other = Reader::open(&other_path, &other_sha, PURPOSE, budget()).unwrap();
    assert!(!other.share_resident_pages());
}

#[test]
fn inside_the_gate_a_file_written_here_is_read_in_full() {
    let _turn = GATE_TURN.lock().unwrap();
    verify_policy::check_once();
    let directory = tempfile::tempdir().unwrap();
    let path = fixture(&directory, "pages.bin");
    let sha = write(&path);
    let gate = verify_policy::Gate::enter();
    let reader = Reader::open(&path, &sha, PURPOSE, budget()).unwrap();
    assert_eq!(
        reader.page_cache_statistics().page_loads,
        reader.page_count(),
        "the gate validates every page"
    );
    drop(gate);
}

#[test]
fn a_file_changed_after_it_was_written_is_refused() {
    let _turn = GATE_TURN.lock().unwrap();
    verify_policy::check_once();
    let directory = tempfile::tempdir().unwrap();
    let path = fixture(&directory, "pages.bin");
    let sha = write(&path);
    let modified = std::fs::metadata(&path).unwrap().modified().unwrap();

    // Flip one byte inside the first page's records.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut byte = [0u8; 1];
    file.seek(SeekFrom::Start(64 + 64 + 40)).unwrap();
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x01;
    file.seek(SeekFrom::Start(64 + 64 + 40)).unwrap();
    file.write_all(&byte).unwrap();
    drop(file);

    // An ordinary write moves the timestamp, so the file is no longer the one
    // written here and is hashed in full.
    if std::fs::metadata(&path).unwrap().modified().unwrap() != modified {
        let error = Reader::open(&path, &sha, PURPOSE, budget()).err().unwrap();
        assert!(
            error.to_string().contains("complete-file digest differs"),
            "{error}"
        );
    }

    // Even with the timestamp put back, the changed page is refused the
    // moment it is loaded: each page is checked against what was written.
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_modified(modified).unwrap();
    drop(file);
    match Reader::open(&path, &sha, PURPOSE, budget()) {
        Err(error) => assert!(error.to_string().contains("SHA differs"), "{error}"),
        Ok(mut reader) => {
            let error = reader.get(0).err().unwrap();
            assert!(
                error
                    .to_string()
                    .contains("differs from the page this process wrote"),
                "{error}"
            );
        }
    }
}

#[test]
fn large_pages_hashed_on_two_threads_give_the_sha_of_the_file() {
    let _turn = GATE_TURN.lock().unwrap();
    verify_policy::check_once();
    let directory = tempfile::tempdir().unwrap();
    let path = fixture(&directory, "large.bin");
    let budget = PageBudget {
        max_page_bytes: 1024 * 1024,
        max_records_per_page: 4096,
        max_records: 100_000,
        max_pages: 10_000,
        max_file_bytes: 64 * 1024 * 1024,
    };
    let mut writer = Writer::new(&path, PURPOSE, budget).unwrap();
    // Sixty records of 100 KiB: nine to a page, seven pages.
    for ordinal in 0..60u64 {
        let payload = format!("\"{}\"", "ab".repeat(50 * 1024 + ordinal as usize));
        writer.push(&key(ordinal), payload.as_bytes()).unwrap();
    }
    let summary = writer.finish().unwrap();
    assert!(summary.pages >= 6, "fixture must span several large pages");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        summary.sha256,
        hex::encode(
            n2r_win32::bulk_digest::digest(n2r_win32::bulk_digest::Algorithm::Blake3, &bytes)
                .unwrap()
        )
    );
    let mut reader = Reader::open(&path, &summary.sha256, PURPOSE, budget).unwrap();
    for ordinal in [59u64, 0, 30, 9, 8] {
        let record = reader.get(ordinal).unwrap();
        assert_eq!(record.key, key(ordinal));
        assert_eq!(record.payload.len(), 2 + 2 * (50 * 1024 + ordinal as usize));
    }
}
