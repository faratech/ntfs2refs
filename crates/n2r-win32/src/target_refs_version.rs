//! The ReFS version of the volume this process builds, reads or recovers.
//!
//! Windows builds every ReFS structure of a data volume through its own
//! interfaces, so nothing in that conversion depends on the version. The
//! converter takes the version Windows formatted the shadow with, records
//! it, and requires the shadow and the converted volume to stay that
//! version. A recovery takes it from the run's records. Until then it is
//! 3.14, which every run made before this was recorded had.
//!
//! Only 3.14 has been converted in the lab: the lab's Windows formats
//! nothing else. A later 3.x is accepted on the strength of the interfaces
//! being the same; the raw trust-label patch of a Windows boot volume reads
//! ReFS structures itself and keeps its own requirement of 3.14.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

/// The version of a run that recorded none.
pub const DEFAULT: (u32, u32) = (3, 14);

static CHOSEN: AtomicU64 = AtomicU64::new(0);

fn packed(major: u32, minor: u32) -> u64 {
    (u64::from(major) << 32) | u64::from(minor)
}

/// Whether the converter works with this version: 3.14 or a later 3.x.
pub fn supported(major: u32, minor: u32) -> bool {
    major == DEFAULT.0 && minor >= DEFAULT.1
}

/// Takes the version for this process. The same version again is accepted;
/// a different one is refused, because the volume changed under the run.
pub fn choose(major: u32, minor: u32) -> io::Result<()> {
    if !supported(major, minor) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "ReFS {major}.{minor} is not a version this converter works with (3.14 or a later 3.x)"
            ),
        ));
    }
    match CHOSEN.compare_exchange(0, packed(major, minor), Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(()),
        Err(existing) if existing == packed(major, minor) => Ok(()),
        Err(existing) => Err(io::Error::other(format!(
            "this run's ReFS volume is version {}.{}, and a volume of version {major}.{minor} was found",
            existing >> 32,
            existing & 0xffff_ffff
        ))),
    }
}

/// The version of this process's ReFS volume: (major, minor).
pub fn get() -> (u32, u32) {
    match CHOSEN.load(Ordering::SeqCst) {
        0 => DEFAULT,
        chosen => ((chosen >> 32) as u32, chosen as u32),
    }
}

/// The version to write into a run's records: nothing for 3.14, so that the
/// records of such a run are what they always were.
pub fn recorded() -> Option<(u32, u32)> {
    (get() != DEFAULT).then(get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_3_14_until_taken_and_older_or_other_majors_are_refused() {
        // No test in this process takes a version other than the default.
        assert_eq!(get(), (3, 14));
        assert_eq!(recorded(), None);
        assert!(supported(3, 14) && supported(3, 15) && supported(3, 20));
        for (major, minor) in [(3, 13), (3, 10), (3, 7), (1, 2), (4, 0), (2, 14)] {
            assert!(!supported(major, minor));
            let error = choose(major, minor).unwrap_err();
            assert!(
                error.to_string().contains(&format!("ReFS {major}.{minor}")),
                "{error}"
            );
        }
        choose(3, 14).unwrap();
        choose(3, 14).unwrap();
        let error = choose(3, 15).unwrap_err();
        assert!(error.to_string().contains("version 3.14"), "{error}");
        assert_eq!(get(), (3, 14));
    }
}
