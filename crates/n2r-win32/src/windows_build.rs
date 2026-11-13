//! Which Windows builds the converter's observations of a source are
//! accepted from.
//!
//! The observations (the transaction manager's state, the quota defaults,
//! the persistent short-name state) are read through documented structures
//! that have not changed across Windows 10 and 11. They were confirmed in
//! the lab on builds 26100 and 26300. 26100 (Windows 11 24H2, Windows Server
//! 2025) is also the first build whose formatter makes the ReFS version the
//! converter builds on, so nothing older can convert in any case; an older
//! build is refused by name here rather than by a format failure later.

/// The first Windows 10.0 build accepted.
pub const MINIMUM_BUILD: u32 = 26100;

/// Whether `version` (major, minor, build, as RtlGetVersion reports them) is
/// a build these observations are accepted from.
pub fn supported(version: [u32; 3]) -> bool {
    version[0] == 10 && version[1] == 0 && version[2] >= MINIMUM_BUILD
}

/// The builds a conversion has actually been run on in the lab. A later one
/// is accepted on the strength of the structures being documented; a run on
/// it says that it is the first.
pub const LAB_BUILDS: [u32; 2] = [26100, 26300];

/// Whether `version` is a build a conversion was run on in the lab.
pub fn shown_in_lab(version: [u32; 3]) -> bool {
    version[0] == 10 && version[1] == 0 && LAB_BUILDS.contains(&version[2])
}

/// The lab's builds, for a notice: "26100 and 26300".
pub fn lab_builds() -> String {
    LAB_BUILDS
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(" and ")
}

/// `version` as Windows writes it, for a refusal.
pub fn describe(version: [u32; 3]) -> String {
    format!("{}.{}.{}", version[0], version[1], version[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lab_builds_and_later_ones_are_accepted_and_older_ones_are_not() {
        for build in [26100, 26300, 27000, 30000] {
            assert!(supported([10, 0, build]), "{build}");
        }
        for version in [
            [10, 0, 26099],
            [10, 0, 22631],
            [10, 0, 19045],
            [6, 3, 9600],
            [11, 0, 26300],
            [10, 1, 26300],
        ] {
            assert!(!supported(version), "{version:?}");
        }
        assert_eq!(describe([10, 0, 26300]), "10.0.26300");
    }

    #[test]
    fn only_the_builds_the_lab_ran_count_as_shown() {
        assert!(shown_in_lab([10, 0, 26100]) && shown_in_lab([10, 0, 26300]));
        for version in [
            [10, 0, 26200],
            [10, 0, 27000],
            [10, 0, 22631],
            [11, 0, 26300],
        ] {
            assert!(!shown_in_lab(version), "{version:?}");
        }
        assert_eq!(lab_builds(), "26100 and 26300");
    }
}
