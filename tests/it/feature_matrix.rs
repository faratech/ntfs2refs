//! docs/feature-matrix.md quotes what a refusal tells the user to do. This
//! keeps each quoted remedy equal to what the converter prints: the document
//! is read, and every command it gives has to be in the message of the code
//! path that refuses that feature.

use ntfs2refs::{ntfs_admission, ntfs_inspect};

fn document() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/feature-matrix.md"
    ))
    .expect("docs/feature-matrix.md")
}

/// The row of the document that starts with `found`, as its cells.
fn row<'a>(document: &'a str, found: &str) -> Vec<&'a str> {
    let line = document
        .lines()
        .find(|line| line.starts_with(&format!("| {found}")))
        .unwrap_or_else(|| panic!("docs/feature-matrix.md has no row for {found:?}"));
    line.trim_matches('|').split('|').map(str::trim).collect()
}

/// The commands a cell gives, which the document writes in backticks.
fn commands(cell: &str) -> Vec<&str> {
    cell.split('`').skip(1).step_by(2).collect()
}

#[test]
fn every_remedy_the_document_quotes_is_one_the_converter_prints() {
    let document = document();

    // 8.3 short names: both commands of the remedy.
    let short_names = row(&document, "8.3 short names on a data volume");
    let quoted = commands(short_names[1]);
    assert_eq!(quoted.len(), 2, "{short_names:?}");
    for command in quoted {
        assert!(
            ntfs_admission::SHORT_NAME_REMEDY.contains(command),
            "{command:?} is not in {:?}",
            ntfs_admission::SHORT_NAME_REMEDY
        );
    }

    // BitLocker: what the boot-sector check says.
    let mut boot = [0u8; 512];
    boot[3..11].copy_from_slice(b"-FVE-FS-");
    let refusal = ntfs_inspect::inspect_boot_sector(&boot, 1 << 30)
        .unwrap_err()
        .to_string();
    for command in commands(row(&document, "A BitLocker-encrypted volume")[1]) {
        assert!(
            refusal.contains(command),
            "{command:?} is not in {refusal:?}"
        );
    }

    // EFS: the attribute's name carries the remedy.
    let encrypted = ntfs_admission::file_attribute_names(0x4000);
    for command in commands(row(&document, "EFS-encrypted files")[1]) {
        assert!(
            encrypted.contains(command),
            "{command:?} is not in {encrypted:?}"
        );
    }
    // TEMPORARY and OFFLINE are named.
    assert_eq!(ntfs_admission::file_attribute_names(0x100), "TEMPORARY");
    assert_eq!(ntfs_admission::file_attribute_names(0x1000), "OFFLINE");
    assert!(row(&document, "A file with the TEMPORARY or OFFLINE attribute")[1].contains("named"));

    // compact /exe: the meaning of its reparse tag.
    let wof = n2r_win32::reparse_layout::unsupported_tag_meaning(0x8000_0017);
    for command in commands(row(&document, "A file compressed with `compact /exe`")[1]) {
        assert!(wof.contains(command), "{command:?} is not in {wof:?}");
    }
    // The tags the document says are refused like it have words of their own.
    for tag in [0x9000_001au32, 0x8000_0013] {
        assert!(
            !n2r_win32::reparse_layout::unsupported_tag_meaning(tag).is_empty(),
            "{tag:#x}"
        );
    }
}

#[test]
fn the_document_names_a_lab_case_for_every_row_it_calls_shown() {
    let document = document();
    let mut in_shown_table = false;
    let mut rows = 0;
    for line in document.lines() {
        if line.starts_with("## ") {
            in_shown_table = matches!(
                line,
                "## Carried over"
                    | "## Carried over with a stated difference"
                    | "## Refused before anything is written"
            );
            continue;
        }
        if !in_shown_table || !line.starts_with("| ") || line.starts_with("|---") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells[0] == "Feature" || cells[0] == "Found" {
            continue;
        }
        rows += 1;
        let case = cells.last().unwrap();
        assert!(
            case.contains('`') || case.contains("fixtures"),
            "the row {:?} names no lab case",
            cells[0]
        );
    }
    assert!(rows >= 25, "only {rows} rows were read");
}
