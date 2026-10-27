//! Bounded Unicode components for the explicitly selected streaming profile.
//! Names are preserved verbatim; native CREATE_NEW remains the final collision
//! authority before source writes. This does not accept arbitrary NT names.
pub fn valid_unicode_component(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !name.is_empty()
        && name.encode_utf16().count() <= 255
        && !name.ends_with([' ', '.'])
        && name
            .chars()
            .all(|character| !character.is_control() && !"<>:\"/\\|?*".contains(character))
        && ![
            "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4",
            "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
            "LPT7", "LPT8", "LPT9", "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
        ]
        .contains(&stem.as_str())
}

/// Conservative duplicate detection only. This key never replaces the actual
/// path and is not a claim to implement Windows' versioned collation tables.
pub fn conservative_path_key(path: &[String]) -> String {
    path.join("\\").to_uppercase()
}
