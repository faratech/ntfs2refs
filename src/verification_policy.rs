//! Requested verification policy, distinct from evidence actually acquired.
//! Historical requests default to complete logical-content verification.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub enum VerificationPolicy {
    #[default]
    #[serde(rename = "full_content")]
    FullContent,
    #[serde(rename = "extent_identity_v1")]
    ExtentIdentityV1,
}

impl VerificationPolicy {
    pub const fn is_full_content(&self) -> bool {
        matches!(self, Self::FullContent)
    }

    pub const fn is_fast(&self) -> bool {
        matches!(self, Self::ExtentIdentityV1)
    }

    /// Whether this run checks each thing once (the owner's "verify once",
    /// 2026-11-19): it was asked for `--verify fast` and its route selected
    /// the behaviour for the process (`n2r_win32::verify_policy::verify_once`,
    /// which `--recheck-everything` and every route but a conversion leave
    /// off). `--verify thorough` never does.
    pub fn verifies_once(&self) -> bool {
        self.is_fast() && n2r_win32::verify_policy::verifies_once()
    }
}
