//! The Windows installations whose boot volume this executable converts.
//!
//! `drive_boot::validate` admits a source only when it matches a row here,
//! and `capabilities` reports the same rows, so what is enforced and what is
//! announced cannot drift apart. A row is added together with the lab
//! evidence that qualified it. Nothing here relaxes a check.
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BootProfile {
    pub id: &'static str,
    /// SHA-256 of the source's `Windows\System32\winload.efi`.
    pub winload_efi_sha256: &'static str,
    /// SHA-256 of the source's `Windows\System32\drivers\refs.sys`.
    pub refs_sys_sha256: &'static str,
    /// How the source's kernel must relate to the Windows running the converter.
    pub kernel_rule: &'static str,
    pub target_format: &'static str,
    pub refs_major_version: u8,
    pub refs_minor_version: u8,
    pub cluster_bytes: u32,
    pub logical_sector_bytes: u32,
    /// The partition length must be a multiple of this. The converter has
    /// the Windows NTFS driver shrink a partition that is not.
    pub geometry_unit_bytes: u64,
    /// The record of the run that qualified conversion and boot.
    pub qualified_by: &'static str,
}

pub const QUALIFIED: &[BootProfile] = &[BootProfile {
    id: "windows-11-build-26300-dev-drive",
    winload_efi_sha256: "1c1a978448b8e0fc2284c13d6e55fde8bf9827dca432cdc8a9be66c2e729adda",
    refs_sys_sha256: "3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4",
    kernel_rule: "the source's ntoskrnl.exe is byte-identical to that of the Windows running the converter",
    target_format: "dev-drive",
    refs_major_version: 3,
    refs_minor_version: 14,
    cluster_bytes: 4096,
    logical_sector_bytes: 512,
    geometry_unit_bytes: 64 << 20,
    qualified_by: "docs/history/release-0.0.1-alpha.md (full-16)",
}];

/// The qualified profile whose loader and ReFS driver are exactly these.
pub fn matching(winload_efi_sha256: &str, refs_sys_sha256: &str) -> Option<&'static BootProfile> {
    QUALIFIED.iter().find(|profile| {
        profile.winload_efi_sha256 == winload_efi_sha256
            && profile.refs_sys_sha256 == refs_sys_sha256
    })
}

/// The identifiers of every qualified profile, for a refusal to name.
pub fn qualified_ids() -> String {
    QUALIFIED
        .iter()
        .map(|profile| profile.id)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    #[test]
    fn every_profile_is_well_formed_and_uniquely_identified() {
        assert!(!QUALIFIED.is_empty());
        for (index, profile) in QUALIFIED.iter().enumerate() {
            assert!(
                sha256_hex(profile.winload_efi_sha256) && sha256_hex(profile.refs_sys_sha256),
                "{}",
                profile.id
            );
            assert!(!profile.qualified_by.is_empty(), "{}", profile.id);
            assert!(
                QUALIFIED[..index].iter().all(|earlier| {
                    earlier.id != profile.id
                        && (earlier.winload_efi_sha256, earlier.refs_sys_sha256)
                            != (profile.winload_efi_sha256, profile.refs_sys_sha256)
                }),
                "{} repeats an earlier profile",
                profile.id
            );
        }
    }

    #[test]
    fn a_source_matches_only_with_both_exact_identities() {
        let profile = &QUALIFIED[0];
        assert_eq!(
            matching(profile.winload_efi_sha256, profile.refs_sys_sha256),
            Some(profile)
        );
        let other = "0".repeat(64);
        assert_eq!(matching(&other, profile.refs_sys_sha256), None);
        assert_eq!(matching(profile.winload_efi_sha256, &other), None);
        assert!(qualified_ids().contains(profile.id));
    }
}
