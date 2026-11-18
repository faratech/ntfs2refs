//! Laboratory only: make a run of the restart route fail at a named point,
//! so that each way back from there can be exercised in a virtual machine.
//!
//! An armed point turns the step it marks into an error (or, for the one
//! point that is not a failure, into a skipped restart). Nothing is armed
//! unless a hidden command-line switch asks, or, inside the recovery
//! environment, unless the request that switch wrote carries the point.
use std::{io, sync::OnceLock};

/// In Windows, right after the source partition was made read-only.
pub const RESTART_AFTER_PROTECT: &str = "restart-after-protect";
/// In Windows, after the recovery image was built and before the boot
/// selection is installed.
pub const RESTART_AFTER_IMAGE: &str = "restart-after-image";
/// In Windows, after the boot selection was installed and before the restart
/// is issued. The run ends there and is not taken back automatically: it
/// leaves a prepared and armed run, to cancel by hand.
pub const RESTART_AFTER_ARM: &str = "restart-after-arm";
/// In Windows, with everything done: the restart is not requested.
pub const RESTART_SKIP_REBOOT: &str = "restart-skip-reboot";
/// In the recovery environment, before the apply starts.
pub const WINPE_BEFORE_APPLY: &str = "winpe-before-apply";

/// Every point, in the order a run reaches them.
pub const POINTS: &[&str] = &[
    RESTART_AFTER_PROTECT,
    RESTART_AFTER_IMAGE,
    RESTART_AFTER_ARM,
    RESTART_SKIP_REBOOT,
    WINPE_BEFORE_APPLY,
];

static ARMED: OnceLock<&'static str> = OnceLock::new();

/// The declared point of that name. An unknown name is refused, so a
/// mistyped point cannot let a run that was meant to fail go on to convert.
pub fn known(point: &str) -> io::Result<&'static str> {
    POINTS
        .iter()
        .copied()
        .find(|known| *known == point)
        .ok_or_else(|| {
            io::Error::other(format!(
                "unknown laboratory failure point {point:?}; known points: {}",
                POINTS.join(", ")
            ))
        })
}

/// Arms one point for the rest of the process.
pub fn arm(point: &str) -> io::Result<()> {
    let point = known(point)?;
    ARMED
        .set(point)
        .map_err(|_| io::Error::other("a laboratory failure point is already armed"))
}

/// The armed point, if any.
pub fn armed() -> Option<&'static str> {
    ARMED.get().copied()
}

/// Whether this point is the armed one.
pub fn is_armed(point: &'static str) -> bool {
    debug_assert!(POINTS.contains(&point), "undeclared failure point {point}");
    ARMED.get().copied() == Some(point)
}

/// What an armed point says when it is reached.
pub fn failure_text(point: &str) -> String {
    format!("laboratory failure at {point} (--lab-fail-at): the run was made to stop here")
}

/// Marks a named point. Does nothing unless that point is armed; then it
/// is the error of the step it marks.
pub fn reached(point: &'static str) -> io::Result<()> {
    if is_armed(point) {
        println!(
            "{{\"kind\":\"lab-fail-v1\",\"point\":\"{point}\",\"pid\":{}}}",
            std::process::id()
        );
        return Err(io::Error::other(failure_text(point)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nothing is armed here: the switch is process-wide and other tests in
    // this binary must keep running through their own named points.
    #[test]
    fn only_declared_points_are_known_and_an_unarmed_point_is_passed() {
        assert_eq!(known("restart-after-arm").unwrap(), RESTART_AFTER_ARM);
        let refusal = known("restart-after-arn").unwrap_err().to_string();
        assert!(
            refusal.contains("restart-after-arn") && refusal.contains(WINPE_BEFORE_APPLY),
            "{refusal}"
        );
        assert!(arm("no-such-point").is_err());
        assert_eq!(armed(), None);
        for &point in POINTS {
            assert!(!is_armed(point));
            reached(point).unwrap(); // passes: nothing is armed
        }
    }

    #[test]
    fn points_are_distinct_and_named_for_where_they_are() {
        for (index, point) in POINTS.iter().enumerate() {
            assert!(
                !POINTS[..index].contains(point),
                "{point} is declared twice"
            );
            assert!(
                point.starts_with("restart-") || point.starts_with("winpe-"),
                "{point}"
            );
        }
        assert!(failure_text(RESTART_AFTER_IMAGE).contains("restart-after-image"));
    }
}
