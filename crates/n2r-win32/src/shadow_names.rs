//! The names of files and directories that are carried over. Names are
//! preserved verbatim; native CREATE_NEW remains the final collision
//! authority before source writes.
//!
//! A name is what NTFS and ReFS hold, not what the Win32 path syntax takes:
//! a trailing dot or space, a name of dots only, and the names of DOS
//! devices (`con`, `aux.c`, `nul`) are ordinary names to both file systems,
//! and tools that do not go through Win32 make them (the Windows Subsystem
//! for Linux, a source tree unpacked there). Every path the converter opens
//! begins with `\\?\`, which passes a name to the file system as it is.
//! Refused are what neither file system takes in a name: nothing, more than
//! 255 units, a control character, one of `< > : " / \ | ? *`, and the two
//! names that mean a directory itself and its parent.
pub fn valid_unicode_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.encode_utf16().count() <= 255
        && name
            .chars()
            .all(|character| !character.is_control() && !"<>:\"/\\|?*".contains(character))
}

/// Why a name is not carried over, for a refusal that names the file.
pub fn component_refusal(name: &str) -> &'static str {
    if name.is_empty() {
        "an empty name"
    } else if name == "." || name == ".." {
        "a name that means a directory itself or its parent"
    } else if name.encode_utf16().count() > 255 {
        "a name longer than 255 characters"
    } else if name.chars().any(char::is_control) {
        "a control character in the name"
    } else {
        "a character in the name that neither file system takes (one of < > : \" / \\ | ? *)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_file_systems_hold_are_valid_whatever_win32_makes_of_them() {
        for name in [
            "report.txt",
            "trailing-dot.",
            "trailing-space ",
            "...",
            "con",
            "CON",
            "aux.c",
            "nul",
            "COM1",
            "lpt9.log",
            ".hidden",
            " leading space",
            "caf\u{e9}",
            "\u{6587}\u{4ef6}",
            "\u{1f389}",
            "report-\u{202e}txt.exe",
        ] {
            assert!(valid_unicode_component(name), "{name:?}");
        }
        for (name, why) in [
            ("", "empty"),
            (".", "itself"),
            ("..", "itself"),
            ("a/b", "neither file system"),
            ("a\\b", "neither file system"),
            ("what?", "neither file system"),
            ("a:b", "neither file system"),
            ("tab\there", "control"),
            ("nul\0", "control"),
        ] {
            assert!(!valid_unicode_component(name), "{name:?}");
            assert!(component_refusal(name).contains(why), "{name:?}");
        }
        let long = "x".repeat(256);
        assert!(!valid_unicode_component(&long) && valid_unicode_component(&long[1..]));
        assert!(component_refusal(&long).contains("255"));
    }
}

/// Conservative duplicate detection only. This key never replaces the actual
/// path and is not a claim to implement Windows' versioned collation tables.
pub fn conservative_path_key(path: &[String]) -> String {
    path.join("\\").to_uppercase()
}
