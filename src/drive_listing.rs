//! The run's own before-and-after listing (`--compare-listing`).
//!
//! The lab judges every conversion by listing the volume before and after
//! (every file's contents, streams, links, times, attributes, security,
//! reparse points and extended attributes) and comparing the two. This does
//! the same for a user's own volume, with the same code as the shipped
//! `lab-volume-manifest` tool. Both listings and the report stay with the
//! run's records. It costs two full reads of the volume.
use anyhow::{Context, Result};
use n2r_win32::volume_manifest::{self, Comparison, PlainVerdict, Record};
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    time::Instant,
};

const BEFORE: &str = "listing-before.jsonl";
const AFTER: &str = "listing-after.jsonl";
const REPORT: &str = "listing-report.json";
/// As the listing tool reads a volume by default.
const THREADS: usize = 8;
/// How many differences the run prints; the report has the first of each
/// kind and every count.
const PRINTED: usize = 8;

fn list(root: &str, path: &Path) -> Result<Vec<Record>> {
    let started = Instant::now();
    let records = volume_manifest::capture(Path::new(root), THREADS)
        .with_context(|| format!("listing the volume at {root}"))?;
    let mut out =
        BufWriter::new(File::create(path).with_context(|| format!("creating {}", path.display()))?);
    for record in &records {
        serde_json::to_writer(&mut out, record)?;
        out.write_all(b"\n")?;
    }
    out.flush()?;
    out.get_ref().sync_all()?;
    let unreadable = records
        .iter()
        .filter(|record| !record.errors.is_empty())
        .count();
    println!(
        "Listed {} object(s), {} byte(s) of data, in {:.1} s{}: {}",
        records.len(),
        records.iter().map(|record| record.bytes).sum::<u64>(),
        started.elapsed().as_secs_f64(),
        if unreadable == 0 {
            String::new()
        } else {
            format!("; {unreadable} could not be read in full")
        },
        path.display()
    );
    Ok(records)
}

fn read(path: &Path) -> Result<Vec<Record>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(&line?)
                .with_context(|| format!("{} line {}", path.display(), index + 1))
        })
        .collect()
}

/// Lists the volume as it is before the run changes anything, into the
/// run's records. Nothing is kept in memory for the length of the run.
pub(super) fn before(root: &str, run: &Path) -> Result<()> {
    println!(
        "Listing the volume before the conversion (--compare-listing): every file is read in full."
    );
    list(root, &run.join(BEFORE)).map(drop)
}

/// What the comparison found, as the lines a run prints.
fn describe(comparison: &Comparison, report: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    // Short names the run was asked to leave behind.
    let dropped = if comparison.short_names_dropped == 0 {
        String::new()
    } else {
        format!(
            " {} 8.3 short name(s) are gone, as asked with --short-names drop.",
            comparison.short_names_dropped
        )
    };
    // Marks the run said it does not set on the new volume.
    let unmarked = if comparison.case_marks_not_carried == 0 {
        String::new()
    } else {
        format!(
            " {} directory(ies) no longer carry the case-sensitive mark, as the run said before it began.",
            comparison.case_marks_not_carried
        )
    };
    let accepted = if comparison.allowed.is_empty() {
        String::new()
    } else {
        format!(
            " Accepted as what a conversion changes: {}.",
            comparison
                .allowed
                .iter()
                .map(|(kind, count)| format!("{kind} ({count})"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    if comparison.identical() {
        lines.push(format!(
            "The volume lists as it did before the conversion: {} object(s) then, {} now{}.{accepted}{dropped}{unmarked} Report: {}",
            comparison.before_objects,
            comparison.after_objects,
            if comparison.short_names_as_links == 0 {
                String::new()
            } else {
                format!(
                    ", of which {} are the 8.3 names as links",
                    comparison.short_names_as_links
                )
            },
            report.display()
        ));
        return lines;
    }
    lines.push(format!(
        "The volume does NOT list as it did before the conversion: {} difference(s) ({}).{accepted}",
        comparison.difference_count,
        comparison
            .difference_kinds
            .iter()
            .map(|(kind, count)| format!("{kind}: {count}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    for difference in comparison.differences.iter().take(PRINTED) {
        lines.push(format!("  {}: {}", difference.path, difference.what));
    }
    if comparison.difference_count > PRINTED {
        lines.push(format!(
            "  and {} more.",
            comparison.difference_count - PRINTED
        ));
    }
    lines.push(format!(
        "The conversion itself completed and its recovery records are kept. A program that wrote to the volume between the first listing and the start of the conversion shows here too. Both listings and the report: {}",
        report.display()
    ));
    lines
}

/// What the content verdict found for the objects made plain, as the lines
/// a run prints after the listing's. Nothing when the run made none.
fn describe_plain(verdict: &PlainVerdict) -> Vec<String> {
    let mut lines = Vec::new();
    if verdict.conversions.is_empty() && verdict.failure_count == 0 {
        return lines;
    }
    let converted = verdict
        .conversions
        .iter()
        .map(|(kind, count)| format!("{kind}: {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    if verdict.failure_count == 0 {
        lines.push(format!(
            "The objects converted to plain files were each verified apart from the listing, against what they were before with only the agreed feature taken off ({converted}); none failed."
        ));
        return lines;
    }
    lines.push(format!(
        "{} object(s) converted to plain files do NOT match what they were before with only the agreed feature taken off ({}).",
        verdict.failure_count,
        verdict
            .failure_kinds
            .iter()
            .map(|(kind, count)| format!("{kind}: {count}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    for failure in verdict.failures.iter().take(PRINTED) {
        lines.push(format!("  {}: {}", failure.path, failure.what));
    }
    if verdict.failure_count > PRINTED {
        lines.push(format!("  and {} more.", verdict.failure_count - PRINTED));
    }
    lines
}

/// Whether a listing shows the volume's root directory as marked
/// case-sensitive.
fn root_marked(listing: &[Record]) -> bool {
    listing
        .iter()
        .any(|record| record.path == "\\" && record.directory && record.case_sensitive)
}

/// Lists the converted volume, compares it with the listing taken before,
/// keeps the report and says what it found. `Ok(true)` when the two agree.
/// `case_marks` is whether a run on this Windows, of this kind of volume,
/// sets the directories' case-sensitive marks on the new volume; a root
/// that the listing taken before shows as marked leaves the volume without.
/// `plain_ledger` is the run's record of the objects it made plain files:
/// those are left out of the listing comparison and each is held by the
/// content verdict instead (`volume_manifest::compare_with_plain`).
pub(super) fn after(
    root: &str,
    run: &Path,
    case_marks: n2r_win32::directory_case::CaseMarkCarry,
    plain_ledger: Option<&Path>,
) -> Result<bool> {
    println!("Listing the converted volume and comparing it with the listing taken before.");
    let now = list(root, &run.join(AFTER))?;
    let then = read(&run.join(BEFORE))?;
    let case_marks = case_marks.with_source_root(root_marked(&then));
    // A run is held to exactly what it said it leaves behind: a short name
    // it was asked to drop, and a case-sensitive mark where it said it does
    // not set one, are counted when they are gone, not differences. Where
    // the mark is carried over, a directory that lost it is a difference.
    let declared = volume_manifest::Declared {
        short_names_dropped: crate::short_name_disposition::dropped(),
        case_marks_not_carried: !case_marks.carried(),
    };
    let report = run.join(REPORT);
    let mut out = BufWriter::new(
        File::create(&report).with_context(|| format!("creating {}", report.display()))?,
    );
    let verdict = match plain_ledger {
        Some(path) => {
            let ledger: n2r_win32::plain_ledger::PlainLedger =
                serde_json::from_reader(BufReader::new(
                    File::open(path).with_context(|| format!("opening {}", path.display()))?,
                ))
                .with_context(|| format!("reading {}", path.display()))?;
            let verdict = volume_manifest::compare_with_plain(&then, &now, declared, &ledger);
            serde_json::to_writer_pretty(&mut out, &verdict)?;
            verdict
        }
        None => {
            let listing = volume_manifest::compare_declared(&then, &now, declared);
            serde_json::to_writer_pretty(&mut out, &listing)?;
            volume_manifest::Verdict {
                listing,
                ..volume_manifest::Verdict::default()
            }
        }
    };
    out.flush()?;
    for line in describe(&verdict.listing, &report) {
        println!("{line}");
    }
    for line in describe_plain(&verdict.plain) {
        println!("{line}");
    }
    Ok(verdict.identical())
}

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::volume_manifest::Difference;

    #[test]
    fn the_run_says_what_the_content_verdict_found_apart() {
        assert!(describe_plain(&PlainVerdict::default()).is_empty());
        let mut passed = PlainVerdict::default();
        passed.conversions.insert("attributes_cleared".into(), 2);
        let text = describe_plain(&passed).join("\n");
        assert!(
            text.contains("verified apart from the listing")
                && text.contains("attributes_cleared: 2")
                && text.contains("none failed"),
            "{text}"
        );
        let mut failed = PlainVerdict {
            failure_count: 1,
            ..PlainVerdict::default()
        };
        failed.failure_kinds.insert("content differs".into(), 1);
        failed.failures.push(Difference {
            path: "\\t.tmp".into(),
            kind: "content differs".into(),
            what: "content differs".into(),
        });
        let text = describe_plain(&failed).join("\n");
        assert!(
            text.contains("1 object(s) converted to plain files do NOT match")
                && text.contains("content differs: 1")
                && text.contains("\\t.tmp: content differs"),
            "{text}"
        );
    }

    #[test]
    fn the_run_says_whether_the_volume_lists_as_before_and_what_differs() {
        let report = Path::new("S:\\runs\\0123\\listing-report.json");
        let mut same = Comparison {
            before_objects: 75,
            after_objects: 75,
            ..Comparison::default()
        };
        same.allowed
            .insert("NTFS compression flag removed".into(), 4);
        let text = describe(&same, report).join("\n");
        assert!(
            text.starts_with(
                "The volume lists as it did before the conversion: 75 object(s) then, 75 now."
            ),
            "{text}"
        );
        assert!(text.contains("NTFS compression flag removed (4)"), "{text}");
        assert!(text.contains("listing-report.json"), "{text}");

        // The 8.3 names of a Windows volume are there afterwards as links.
        let windows = Comparison {
            before_objects: 26_591,
            after_objects: 42_211,
            short_names_as_links: 15_620,
            ..Comparison::default()
        };
        let text = describe(&windows, report).join("\n");
        assert!(
            text.contains("of which 15620 are the 8.3 names as links"),
            "{text}"
        );

        // A root the listing shows as marked, and only the root.
        let directory = |path: &str, case_sensitive: bool| Record {
            path: path.to_owned(),
            directory: true,
            case_sensitive,
            ..Record::default()
        };
        assert!(root_marked(&[
            directory("\\", true),
            directory("\\src", false)
        ]));
        assert!(!root_marked(&[
            directory("\\", false),
            directory("\\src", true)
        ]));
        assert!(!root_marked(&[]));

        // Marks the run said it leaves behind are counted in what it says,
        // and nothing is said of them where none was left.
        assert!(!text.contains("case-sensitive"), "{text}");
        let unmarked = Comparison {
            before_objects: 75,
            after_objects: 75,
            case_marks_not_carried: 2,
            ..Comparison::default()
        };
        let text = describe(&unmarked, report).join("\n");
        assert!(
            text.starts_with("The volume lists as it did before the conversion")
                && text.contains(
                    "2 directory(ies) no longer carry the case-sensitive mark, as the run said before it began."
                ),
            "{text}"
        );

        let mut differs = Comparison {
            before_objects: 75,
            after_objects: 76,
            difference_count: 11,
            ..Comparison::default()
        };
        differs
            .difference_kinds
            .insert("only afterwards".into(), 11);
        differs.differences = (0..10)
            .map(|index| Difference {
                path: format!("\\new-{index}.txt"),
                kind: "only afterwards".into(),
                what: "is on the volume only afterwards".into(),
            })
            .collect();
        let lines = describe(&differs, report);
        assert!(
            lines[0].contains("does NOT list as it did")
                && lines[0].contains("11 difference(s) (only afterwards: 11)"),
            "{lines:?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("  \\new-"))
                .count(),
            PRINTED
        );
        assert!(
            lines.iter().any(|line| line.trim() == "and 3 more."),
            "{lines:?}"
        );
        assert!(
            lines
                .last()
                .unwrap()
                .contains("The conversion itself completed"),
            "{lines:?}"
        );
    }
}
