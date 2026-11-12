//! Whether a run may change the source, decided once from the command line.
//!
//! `--diagnose` promises that the source is not changed. Every entry point
//! that changes it (the boot-volume geometry shrink, NTFS prealignment, the
//! journal apply of either backend, the shared-disk route) takes a
//! [`SourceChangeAuthority`]. Only a conversion can mint one, so a diagnose
//! run cannot reach them however the routes are later rearranged.
use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutionMode {
    Convert,
    Diagnose,
}

/// Proof that this run is a conversion. It is not `Clone`, `Copy` or
/// `Default` and its field is private, so
/// [`ExecutionMode::source_change_authority`] is the only way to obtain one.
#[derive(Debug)]
pub(crate) struct SourceChangeAuthority {
    _sealed: (),
}

impl ExecutionMode {
    /// `action` names what is about to change the source, for the refusal.
    pub(crate) fn source_change_authority(self, action: &str) -> Result<SourceChangeAuthority> {
        match self {
            Self::Convert => Ok(SourceChangeAuthority { _sealed: () }),
            Self::Diagnose => {
                bail!("diagnose mode never changes the source; refused: {action}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_conversion_obtains_authority_to_change_the_source() {
        assert!(
            ExecutionMode::Convert
                .source_change_authority("the journal apply")
                .is_ok()
        );
        let refusal = ExecutionMode::Diagnose
            .source_change_authority("the journal apply")
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("never changes the source") && refusal.contains("the journal apply"),
            "{refusal}"
        );
    }
}
