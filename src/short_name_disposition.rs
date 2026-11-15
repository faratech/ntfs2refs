//! What a run does with the 8.3 short names of a data volume.
//!
//! ReFS has no short names. By default a data volume that has them is
//! refused, with the commands that remove them. With `--short-names drop`
//! the run goes ahead: every object is created under its long name, the
//! short names are not carried over, and each is kept in the run's records.
//! (A Windows boot volume's become links beside the long names; that is the
//! boot route's own doing and not chosen here.)
//!
//! The choice is the user's for one run, made before a disk is opened, and
//! read where the source is admitted and where it is checked.
use std::sync::atomic::{AtomicBool, Ordering};

static DROP: AtomicBool = AtomicBool::new(false);

/// The run was started with `--short-names drop`.
pub fn drop_for_this_run() {
    DROP.store(true, Ordering::SeqCst);
}

/// Whether short names are left behind rather than refused.
pub fn dropped() -> bool {
    DROP.load(Ordering::SeqCst)
}

/// What a run and a check say of the short names they leave behind.
pub fn note(count: u64, example: &str) -> String {
    format!(
        "{count} file(s) and directories have an 8.3 short name{example}. ReFS has no short names: with --short-names drop they are not carried over, and a program that stored a path in its short form will no longer find it. Each is kept in the run's records."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_note_says_how_many_names_are_left_behind_and_what_that_costs() {
        let said = note(
            9,
            " (for example \\docs\\Annual Report.docx, also named ANNUAL~1.DOC)",
        );
        assert!(said.starts_with("9 file(s) and directories have an 8.3 short name (for example \\docs\\Annual Report.docx, also named ANNUAL~1.DOC)."), "{said}");
        assert!(said.contains("not carried over"), "{said}");
        assert!(said.contains("kept in the run's records"), "{said}");
    }
}
