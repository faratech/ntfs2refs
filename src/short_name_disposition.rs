//! What a run does with the 8.3 short names of a data volume.
//!
//! ReFS has no short names. By default (owner, 2026-11-25) a data volume
//! that has them converts without them, once the user has agreed: the
//! check and the lines before the conversion's question say how many there
//! are and where the run lists them, every object is created under its
//! long name, the short names are not carried over, and each is kept in the
//! run's records. `--short-names drop` asks for the same explicitly;
//! `--short-names refuse` refuses such a volume instead, with the commands
//! that remove them. (A Windows boot volume's become links beside the long
//! names; that is the boot route's own doing and not chosen here.)
//!
//! The choice is the user's for one run, made before a disk is opened, and
//! read where the source is admitted and where it is checked.
use std::sync::atomic::{AtomicBool, Ordering};

static DROP: AtomicBool = AtomicBool::new(false);

/// Where a run that drops short names lists them, in its working directory.
pub const RECORDS_FILE: &str = "source-short-names-not-carried.json";

/// Whether a run drops a volume's short names: what it was asked
/// (`--short-names drop` or `refuse`), and otherwise whether the volume is
/// converted as a data volume, where dropping them is the default.
pub fn drops(requested: Option<&str>, data_volume: bool) -> bool {
    match requested {
        Some("drop") => true,
        Some(_) => false,
        None => data_volume,
    }
}

/// Chooses, once and before a disk is opened, what this run does with the
/// short names it finds (see [`drops`]).
pub fn choose_for_this_run(requested: Option<&str>, data_volume: bool) {
    DROP.store(drops(requested, data_volume), Ordering::SeqCst);
}

/// Whether short names are left behind rather than refused.
pub fn dropped() -> bool {
    DROP.load(Ordering::SeqCst)
}

/// What a run and a check say of the short names they leave behind, before
/// the conversion's question.
pub fn note(count: u64, example: &str) -> String {
    format!(
        "{count} file(s) and directories have an 8.3 short name{example}. ReFS has no short names: they are not carried over, and a program that stored a path in its short form will no longer find it. Each is kept in the run's records ({RECORDS_FILE} in its working directory). To refuse the volume instead, convert with --short-names refuse."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_note_says_how_many_names_are_left_behind_and_where_they_are_listed() {
        let said = note(
            9,
            " (for example \\docs\\Annual Report.docx, also named ANNUAL~1.DOC)",
        );
        assert!(said.starts_with("9 file(s) and directories have an 8.3 short name (for example \\docs\\Annual Report.docx, also named ANNUAL~1.DOC)."), "{said}");
        assert!(said.contains("not carried over"), "{said}");
        assert!(said.contains("kept in the run's records"), "{said}");
        assert!(said.contains(RECORDS_FILE), "{said}");
        assert!(said.contains("--short-names refuse"), "{said}");
    }

    #[test]
    fn a_data_volume_drops_short_names_unless_asked_to_refuse_them() {
        // The default: dropped on a data volume, never chosen for a
        // Windows boot volume (whose short names become links).
        assert!(drops(None, true));
        assert!(!drops(None, false));
        assert!(drops(Some("drop"), true));
        assert!(!drops(Some("refuse"), true));
        assert!(!drops(Some("refuse"), false));
    }
}
