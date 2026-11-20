//! Laboratory only: stop a run at a named point, so that recovery can be
//! exercised from exactly there.
//!
//! An armed hold prints one line and then parks its thread for ever. It can
//! only stop a run: it grants nothing, skips nothing and never lets the run
//! go on, so a harness has to terminate the process (or the machine) and
//! recover. Nothing is armed unless the hidden command-line switch asks.
use std::{
    io::{self, Write},
    sync::OnceLock,
};

/// Every place a hold can be put, in the order a conversion reaches them.
pub const POINTS: &[&str] = &[
    // The apply marker is durable and the source is writable; nothing written.
    "apply-activated",
    // Half of the changed ranges are written, none of them flushed.
    "apply-mid-ranges",
    // Every range but the boot granule is written, not yet flushed.
    "apply-ranges-written",
    // Those ranges are flushed; the NTFS boot sector is still in place.
    "apply-before-boot-granule",
    // The boot granule is written, not yet flushed.
    "apply-boot-granule-written",
    // Every new byte is written, flushed and read back; no handoff marker.
    "apply-before-handoff",
    // --verify fast only (#148), where the handoff follows the verification:
    // every new byte is written and read back, and the source is sealed
    // offline and read-only again beside the apply marker alone; the seal
    // is not yet recorded.
    "apply-sealed",
    // --verify fast only: the source is sealed beside the apply marker
    // alone and the seal is recorded in verification-seal.json; the
    // verification has not started.
    "apply-seal-recorded",
    // A --review run only (#110): the source is sealed offline and
    // read-only again beside the apply marker alone; its stop is not yet
    // recorded and the volume was never mounted.
    "review-sealed",
    // A --review run only: the fingerprint of the whole converted partition
    // is recorded in review-stop.json; the disk is still offline and
    // read-only and has not been put online.
    "review-recorded",
    // --verify fast only: the finalizer has authenticated the apply marker
    // alone and every new byte; the source is sealed; no handoff marker.
    "verify-authenticated",
    // --verify fast only: the converted source is mounted read-only for its
    // verification, beside the apply marker alone; no handoff marker.
    "verify-source-readonly",
    // --verify fast only: the verification passed and the source is sealed
    // again; no handoff marker, so a rollback is still open.
    "verify-passed",
    // --verify thorough only, whose apply step writes the handoff: the
    // handoff marker is durable; the source is still writable.
    "apply-handoff-durable",
    // The handoff marker is durable and the source is sealed read-only:
    // with --verify thorough before finalization, with --verify fast after
    // the verification passed, before the volume is online.
    "handoff-sealed",
    // Finalization has authenticated the handoff; the source is still sealed
    // (with --verify fast only in the recovery of a run past its handoff).
    "finalize-authenticated",
    // The converted source is mounted read-only for its verification beside
    // the handoff (with --verify fast only in such a recovery).
    "finalize-source-readonly",
    // Verification passed and the source is sealed again; not yet online.
    "finalize-before-online",
    // The converted source is online; its label and mount paths are not
    // yet restored.
    "finalize-online",
];

static ARMED: OnceLock<&'static str> = OnceLock::new();

static BEFORE_HANDOFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Says whether the finalizer of this process is verifying a converted
/// volume before its handoff (#148). The points of the verification itself
/// are reached from code that does not know the journal; it names them
/// through [`reached_in_verification`].
pub fn verifying_before_handoff(now: bool) {
    BEFORE_HANDOFF.store(now, std::sync::atomic::Ordering::SeqCst);
}

/// A point of the verification of the converted volume, under the name it
/// has before the handoff or the one it has after it. The two are different
/// states for a recovery: rollback is open in the first.
pub fn reached_in_verification(before_handoff: &'static str, after_handoff: &'static str) {
    if BEFORE_HANDOFF.load(std::sync::atomic::Ordering::SeqCst) {
        reached(before_handoff);
    } else {
        reached(after_handoff);
    }
}

fn known(point: &str) -> Option<&'static str> {
    POINTS.iter().copied().find(|known| *known == point)
}

/// Arms one hold for the rest of the process. An unknown name is refused, so
/// a mistyped point cannot let a run that was meant to stop go on to finish.
pub fn arm(point: &str) -> io::Result<()> {
    let point = known(point).ok_or_else(|| {
        io::Error::other(format!(
            "unknown laboratory hold point {point:?}; known points: {}",
            POINTS.join(", ")
        ))
    })?;
    ARMED
        .set(point)
        .map_err(|_| io::Error::other("a laboratory hold is already armed"))
}

/// The armed point, if any.
pub fn armed() -> Option<&'static str> {
    ARMED.get().copied()
}

/// Marks a named point. Does nothing unless that point is armed; then it
/// reports the hold on standard output and never returns.
pub fn reached(point: &'static str) {
    debug_assert!(known(point).is_some(), "undeclared hold point {point}");
    if ARMED.get().copied() != Some(point) {
        return;
    }
    {
        let mut out = io::stdout().lock();
        let _ = writeln!(
            out,
            "{{\"kind\":\"lab-hold-v1\",\"point\":\"{point}\",\"pid\":{}}}",
            std::process::id()
        );
        let _ = out.flush();
    }
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nothing is armed here: the switch is process-wide and other tests in
    // this binary must keep running through their own named points.
    #[test]
    fn only_declared_points_can_be_armed_and_an_unarmed_point_is_passed() {
        assert_eq!(known("handoff-sealed"), Some("handoff-sealed"));
        assert_eq!(known("handoff-seale"), None);
        let refusal = arm("no-such-point").unwrap_err().to_string();
        assert!(
            refusal.contains("no-such-point") && refusal.contains("handoff-sealed"),
            "{refusal}"
        );
        assert_eq!(armed(), None);
        for &point in POINTS {
            reached(point); // returns: nothing is armed
        }
    }

    #[test]
    fn points_are_distinct() {
        for (index, point) in POINTS.iter().enumerate() {
            assert!(
                !POINTS[..index].contains(point),
                "{point} is declared twice"
            );
        }
    }
}
