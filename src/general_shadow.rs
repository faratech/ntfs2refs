//! Immutable request shared by general native shadow construction and freeze.
use anyhow::{Result, ensure};
use n2r_win32::general_layout::GeneralSourceShadowBinding;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub pair: GeneralSourceShadowBinding,
    pub source_sha256: String,
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
        Ok(())
    }
}
