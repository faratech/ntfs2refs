//! Which Windows builds the converter's observations of a source are
//! accepted from.
//!
//! The observations (the transaction manager's state, the quota defaults,
//! the persistent short-name state) are read through documented structures
//! that have not changed across Windows 10 and 11. They were confirmed in
//! the lab on builds 26100 (Windows Server 2025, and the installation
//! media's environment) and 26300 (Windows 11). 26100 (Windows 11 24H2, Windows Server
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

/// A Windows on which the converter sets a directory's case-sensitive mark
/// on the new volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseMarkBuild {
    /// The build, as RtlGetVersion reports it.
    pub build: u32,
    /// Whether it is a server edition. The build number alone does not say
    /// which Windows it is: 26100 is Windows Server 2025, Windows 11 24H2
    /// and the installation media's environment.
    pub server: bool,
    /// What that Windows is called, for a notice.
    pub name: &'static str,
}

/// Where Windows' own ReFS was shown to hold a directory marked
/// case-sensitive through the steps a conversion takes with its shadow
/// volume (snapshot, consistency scan, taking the volume offline and
/// mounting it again): the lab's control `casemark-control`.
///
/// It passed on Windows Server 2025 (build 26100.1742) both times it ran.
/// On Windows 11 (build 26300.9457) the same control stopped Windows with a
/// bugcheck both times, when the volume was taken offline: a Windows kernel
/// defect with nothing of this project loaded (issue #120). A conversion
/// takes its shadow volume offline, so a mark set there could stop the
/// machine in the middle of a run. The mark is therefore set only on what
/// is listed here; a Windows is added when the control has passed on it.
pub const CASE_MARK_BUILDS: [CaseMarkBuild; 1] = [CaseMarkBuild {
    build: 26100,
    server: true,
    name: "Windows Server 2025",
}];

/// Whether `version` (major, minor, build), of a server edition or not, is
/// a Windows on which the case-sensitive mark is set on the new volume.
pub fn carries_case_mark(version: [u32; 3], server: bool) -> bool {
    version[0] == 10
        && version[1] == 0
        && CASE_MARK_BUILDS
            .iter()
            .any(|shown| shown.build == version[2] && shown.server == server)
}

/// [`CASE_MARK_BUILDS`], for a notice: "Windows Server 2025 (build 26100)".
pub fn case_mark_builds() -> String {
    CASE_MARK_BUILDS
        .iter()
        .map(|shown| format!("{} (build {})", shown.name, shown.build))
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
    fn the_case_mark_is_carried_only_where_the_control_passed() {
        assert!(carries_case_mark([10, 0, 26100], true));
        for (version, server) in [
            // Windows 11 24H2 and the installation media's environment.
            ([10, 0, 26100], false),
            // The lab's Windows 11, where the control stopped Windows.
            ([10, 0, 26300], false),
            ([10, 0, 26300], true),
            // A later server: accepted for a conversion, not shown for this.
            ([10, 0, 27000], true),
            ([10, 0, 26099], true),
            ([11, 0, 26100], true),
            ([10, 1, 26100], true),
        ] {
            assert!(!carries_case_mark(version, server), "{version:?} {server}");
        }
        assert_eq!(case_mark_builds(), "Windows Server 2025 (build 26100)");
        // Every listed build is one a conversion was run on.
        for shown in CASE_MARK_BUILDS {
            assert!(shown_in_lab([10, 0, shown.build]), "{shown:?}");
        }
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
