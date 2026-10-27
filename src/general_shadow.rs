//! Immutable request shared by general native shadow construction and freeze.
use anyhow::{Result, ensure};
use n2r_win32::general_layout::GeneralSourceShadowBinding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Capture both descriptor views for the canonical source tree. The returned
/// analysis is diagnostic; source admission separately binds actual image bytes.
pub fn observed_tree(
    source: &mut n2r_win32::GeneralFrozenPartition,
    raw: &crate::ntfs_inspect::NtfsInspection,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<(crate::shadow_tree::Tree, crate::ntfs_source_view::Analysis)> {
    use sha2::{Digest, Sha256};
    let before = source.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "source must remain excluded during descriptor capture"
    );
    let pin = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    let request =
        crate::ntfs_attestation::request_for_general_inspection(raw, &pin, source.binding())?;
    let observed = source.observe_ntfs_files(&request, events)?;
    let views = crate::ntfs_source_view::diagnose(raw, &pin, observed.report())?;
    let mut tree = crate::shadow_tree::derive_ordinary(raw)?;
    tree.bind_security_views(&views)?;
    ensure!(
        source.state(events)? == before,
        "source exclusion changed during descriptor capture"
    );
    Ok((tree, views))
}

pub fn native_inputs(tree: &crate::shadow_tree::Tree) -> Vec<n2r_win32::shadow_native::Input<'_>> {
    tree.objects
        .iter()
        .map(|object| n2r_win32::shadow_native::Input {
            components: &object.path,
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
            expected_api_security: object.api_security.as_deref(),
            payload: &[],
            expected_length: (!object.directory).then_some(object.length),
            expected_sha256: if object.directory {
                None
            } else {
                object.sha256.as_deref()
            },
            source_offset: object.source_offset,
            source_runs: object
                .source_extents
                .iter()
                .map(|run| n2r_win32::shadow_native::SourceRun {
                    logical_offset: run.logical_offset,
                    physical_offset: run.physical_offset,
                    length: run.length,
                })
                .collect(),
        })
        .collect()
}

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
        self.validate_with_resource_profile(crate::ntfs_admission::ResourceProfile::AlphaV1)
    }

    pub fn validate_with_resource_profile(
        &self,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<()> {
        self.pair
            .validate_with_resource_profile(resources.native_profile())?;
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
