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
}
