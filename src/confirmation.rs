//! Where a run asks for consent, and how `--yes` gives it.
//!
//! Every question a run asks is answered here, so that an unattended run
//! answers all of them the same way and none can be missed.
use std::{
    io::{self, BufRead, Read, Write},
    sync::atomic::{AtomicBool, Ordering},
};

static ASSUME_YES: AtomicBool = AtomicBool::new(false);

/// Set once, by `--yes`: every later question of this process is answered
/// yes. The caller has already held `--yes` to what it requires (for a
/// conversion, the serial number of the volume that is meant).
pub(crate) fn assume_yes() {
    ASSUME_YES.store(true, Ordering::SeqCst);
}

pub(crate) fn assumed() -> bool {
    ASSUME_YES.load(Ordering::SeqCst)
}

/// The answer to a question that has just been printed. Anything but "y" or
/// "yes" is a no, and so is an answer longer than a line should be.
pub(crate) fn answer() -> io::Result<bool> {
    if assumed() {
        println!("yes (--yes)");
        return Ok(true);
    }
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(65).read_line(&mut answer)?;
    Ok(affirmative(&answer))
}

fn affirmative(answer: &str) -> bool {
    answer.len() < 65 && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// A volume serial number as `vol` and `--list` print it: `1A2B-3C4D`.
pub fn format_volume_serial(serial: u32) -> String {
    format!("{:04X}-{:04X}", serial >> 16, serial & 0xffff)
}

/// Accepts `1A2B-3C4D` or `1A2B3C4D`, in either case.
pub fn parse_volume_serial(text: &str) -> Result<u32, String> {
    let digits: String = text.chars().filter(|c| *c != '-').collect();
    let well_formed = digits.len() == 8
        && digits.chars().all(|c| c.is_ascii_hexdigit())
        && (text.len() == 8 || (text.len() == 9 && text.as_bytes()[4] == b'-'));
    if !well_formed {
        return Err(format!(
            "a volume serial number is eight hexadecimal digits, as `ntfs2refs --list` and `vol` print it (for example 1A2B-3C4D), not {text:?}"
        ));
    }
    u32::from_str_radix(&digits, 16).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_plain_yes_is_consent() {
        for yes in ["y\n", "Y\r\n", "yes\n", " YES \n"] {
            assert!(affirmative(yes), "{yes:?}");
        }
        for no in ["", "\n", "n\n", "yes please\n", "yy\n", &"y".repeat(65)] {
            assert!(!affirmative(no), "{no:?}");
        }
    }

    #[test]
    fn a_volume_serial_reads_as_it_is_printed() {
        assert_eq!(format_volume_serial(0x1a2b_3c4d), "1A2B-3C4D");
        assert_eq!(format_volume_serial(0x0000_00ff), "0000-00FF");
        for text in ["1A2B-3C4D", "1a2b-3c4d", "1A2B3C4D"] {
            assert_eq!(parse_volume_serial(text), Ok(0x1a2b_3c4d), "{text}");
        }
        for text in [
            "",
            "1A2B-3C4",
            "1A2B-3C4D5",
            "1A2B 3C4D",
            "1A-2B3C4D",
            "GGGG-GGGG",
            "E:",
        ] {
            assert!(parse_volume_serial(text).is_err(), "{text:?}");
        }
        assert_eq!(
            parse_volume_serial(&format_volume_serial(0xdead_beef)),
            Ok(0xdead_beef)
        );
    }
}
