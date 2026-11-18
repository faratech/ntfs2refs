//! The warning every run of the converter starts with.
//!
//! It is written to the error stream, so that what a script reads from the
//! output stream (the JSON of `capabilities`, the rows of `--list`, the
//! version) stays as it was. DISCLAIMER.md says the same at length.

/// The lines of the warning, each at most 72 characters.
pub const LINES: &[&str] = &[
    "WARNING: NTFS2REFS IS EXPERIMENTAL SOFTWARE.",
    "",
    "IT REWRITES THE FILE SYSTEM OF A VOLUME IN PLACE, FROM NTFS TO REFS.",
    "IT HAS BEEN TESTED ONLY ON VIRTUAL DISKS IN A LABORATORY. A FAULT IN",
    "IT, IN WINDOWS OR IN THE HARDWARE CAN DESTROY EVERYTHING ON THE VOLUME.",
    "",
    "BACK UP EVERYTHING ON THE VOLUME, AND CHECK THAT YOU CAN RESTORE THE",
    "BACKUP, BEFORE YOU CONVERT. YOU USE THIS SOFTWARE ENTIRELY AT YOUR OWN",
    "RISK. IT COMES WITH NO WARRANTY OF ANY KIND. READ DISCLAIMER.md.",
];

const WIDTH: usize = 80;

/// The warning in its box, as it is printed.
pub fn banner() -> String {
    let rule = "#".repeat(WIDTH);
    let blank = format!("#{}#", " ".repeat(WIDTH - 2));
    let mut text = String::new();
    text.push_str(&rule);
    text.push('\n');
    text.push_str(&blank);
    text.push('\n');
    for line in LINES {
        text.push_str(&format!("#   {line:<72}   #\n"));
    }
    text.push_str(&blank);
    text.push('\n');
    text.push_str(&rule);
    text.push('\n');
    text
}

/// Writes the warning to the error stream. A run goes on if that fails: the
/// warning is not worth stopping a recovery for.
pub fn print() {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(banner().as_bytes());
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_warning_is_a_box_of_capitals_and_disclaimer_md_says_the_same() {
        let banner = banner();
        for line in banner.lines() {
            assert_eq!(line.chars().count(), WIDTH, "{line:?}");
            assert!(line.starts_with('#') && line.ends_with('#'), "{line:?}");
        }
        for line in LINES {
            assert!(line.chars().count() <= 72, "{line:?}");
            // Capitals, apart from the file name it points to.
            assert_eq!(
                line.replace("DISCLAIMER.md", ""),
                line.replace("DISCLAIMER.md", "").to_uppercase(),
                "{line:?}"
            );
        }
        let document = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/DISCLAIMER.md"));
        let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let said = words(&LINES.join(" "));
        assert!(
            words(document).contains(&said),
            "DISCLAIMER.md does not hold the warning the executable prints"
        );
    }
}
