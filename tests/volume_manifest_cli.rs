//! Exit codes of `lab-volume-manifest compare`. The lab harness tells an
//! identical pair (0) from a differing one (2) from a failure of the tool
//! itself (anything else) by these alone.
use n2r_win32::volume_manifest::Record;
use std::{fs, path::Path, process::Command};

fn record(path: &str, directory: bool, sha256: Option<&str>) -> Record {
    Record {
        path: path.to_owned(),
        directory,
        attributes: if directory { 0x10 } else { 0x20 },
        created: 1,
        written: 2,
        changed: 3,
        bytes: if directory { 0 } else { 5 },
        sha256: sha256.map(str::to_owned),
        security: Some("O:SYG:SYD:(A;;FA;;;SY)".to_owned()),
        links: 1,
        ..Record::default()
    }
}

fn save(path: &Path, records: &[Record]) {
    let mut text = String::new();
    for record in records {
        text.push_str(&serde_json::to_string(record).unwrap());
        text.push('\n');
    }
    fs::write(path, text).unwrap();
}

fn compare(before: &Path, after: &Path, report: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lab-volume-manifest"))
        .arg("compare")
        .arg("--before")
        .arg(before)
        .arg("--after")
        .arg(after)
        .arg("--report")
        .arg(report)
        .output()
        .unwrap()
}

/// A backslash and nine three-byte characters: the length of
/// "\System Volume Information" falls inside the last one.
fn boundary_path() -> String {
    format!("\\{}", "\u{65e5}".repeat(9))
}

#[test]
fn identical_listings_exit_zero_and_differing_listings_exit_two() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, report) = (
        directory.path().join("before.jsonl"),
        directory.path().join("after.jsonl"),
        directory.path().join("report.json"),
    );
    let listing = [
        record("\\", true, None),
        record("\\a.txt", false, Some("aa")),
    ];
    save(&before, &listing);
    save(&after, &listing);
    let same = compare(&before, &after, &report);
    assert_eq!(
        same.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&same.stderr)
    );

    save(
        &after,
        &[
            record("\\", true, None),
            record("\\a.txt", false, Some("bb")),
        ],
    );
    let different = compare(&before, &after, &report);
    assert_eq!(
        different.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&different.stderr)
    );
    let written: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(written["difference_count"], 1);
}

#[test]
fn a_path_split_mid_character_by_the_exempt_prefix_is_a_comparison_not_a_crash() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, report) = (
        directory.path().join("before.jsonl"),
        directory.path().join("after.jsonl"),
        directory.path().join("report.json"),
    );
    let path = boundary_path();
    let listing = [record("\\", true, None), record(&path, false, Some("aa"))];
    save(&before, &listing);
    save(&after, &listing);
    let same = compare(&before, &after, &report);
    assert_eq!(
        same.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&same.stderr)
    );

    save(&after, &[record("\\", true, None)]);
    let missing = compare(&before, &after, &report);
    assert_eq!(
        missing.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    let written: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(written["differences"][0]["path"], path.as_str());
    assert_eq!(
        written["differences"][0]["what"],
        "missing after conversion"
    );
}

#[test]
fn an_unreadable_listing_is_a_tool_failure_not_a_difference() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, report) = (
        directory.path().join("before.jsonl"),
        directory.path().join("after.jsonl"),
        directory.path().join("report.json"),
    );
    save(&before, &[record("\\", true, None)]);
    fs::write(&after, "{ this is not a listing record\n").unwrap();
    let malformed = compare(&before, &after, &report);
    assert_eq!(
        malformed.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&malformed.stderr)
    );
    let stderr = String::from_utf8_lossy(&malformed.stderr);
    assert!(stderr.contains("after.jsonl line 1"), "{stderr}");
    assert!(!report.exists(), "no report is written for a failed read");

    let absent = compare(&before, &directory.path().join("absent.jsonl"), &report);
    assert_eq!(absent.status.code(), Some(1));
}
