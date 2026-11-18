//! One byte-size contract for selected conversion and its recovery inputs.
//! These are metadata resource ceilings, never source or replay authority.
use anyhow::{Result, ensure};
use std::{fs::OpenOptions, io::Write, os::windows::fs::OpenOptionsExt, path::Path};

#[derive(Clone, Copy)]
pub(crate) enum Artifact {
    Bundle,
    Request,
    Plan,
    Ticket,
    Expectation,
    Verification,
    PayloadMap,
}

impl Artifact {
    pub(crate) const fn maximum_bytes(self) -> usize {
        match self {
            Self::Request => 128 * 1024,
            Self::Bundle | Self::Ticket | Self::Verification => 64 * 1024,
            Self::Plan | Self::Expectation | Self::PayloadMap => 64 * 1024 * 1024,
        }
    }

    const fn filename(self) -> &'static str {
        match self {
            Self::Bundle => "allocation-recovery-bundle.json",
            Self::Request => "request.json",
            Self::Plan => "selected-plan.json",
            Self::Ticket => "selected-ticket.json",
            Self::Expectation => "expectation.json",
            Self::Verification => "verification.json",
            Self::PayloadMap => "recovery-payload-manifest.json",
        }
    }

    /// Copy authenticated input bytes without reserializing or changing pins.
    /// Keep the historical recovery-side bundle filename.
    pub(crate) fn copy_for_recovery(self, root: &Path, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= self.maximum_bytes(),
            "recovery input copy exceeds its artifact bound"
        );
        let name = match self {
            Self::Bundle => "bundle.json",
            _ => self.filename(),
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(root.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
}
