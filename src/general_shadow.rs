//! Immutable request shared by general native shadow construction and freeze.
use anyhow::{Result, ensure};
use n2r_win32::general_layout::GeneralSourceShadowBinding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub fn validate_mount_paths(paths: &Option<Vec<String>>) -> Result<()> {
    let Some(paths) = paths else { return Ok(()) };
    ensure!(paths.len() <= 128, "too many source mount paths");
    let mut seen = BTreeSet::new();
    for path in paths {
        let bytes = path.as_bytes();
        ensure!(
            (3..=1024).contains(&bytes.len())
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
                && path.ends_with('\\')
                && !path.contains(['/', '\0'])
                && (bytes.len() == 3
                    || path[3..path.len() - 1].split('\\').all(|part| {
                        !part.is_empty()
                            && part != "."
                            && part != ".."
                            && !part.chars().any(|character| {
                                character.is_control()
                                    || matches!(character, ':' | '*' | '?' | '"' | '<' | '>' | '|')
                            })
                    }))
                && seen.insert(path.to_lowercase()),
            "source mount path is ambiguous or repeated"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub pair: GeneralSourceShadowBinding,
    pub source_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_mount_paths: Option<Vec<String>>,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        self.pair.validate()?;
        ensure!(
            self.schema_version == 1
                && self.source_sha256.len() == 64
                && self
                    .source_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "general shadow request profile or source pin differs"
        );
        validate_mount_paths(&self.expected_mount_paths)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_path_policy_accepts_bounded_drive_and_folder_roots() {
        validate_mount_paths(&Some(vec!["F:\\".into(), "C:\\mounted\\data\\".into()])).unwrap();
        for path in ["F:", "F:/", "C:\\..\\", "C:\\mount//", "F:\\0"] {
            assert!(validate_mount_paths(&Some(vec![path.into()])).is_err());
        }
        assert!(validate_mount_paths(&Some(vec!["F:\\".into(), "f:\\".into()])).is_err());
    }
}
