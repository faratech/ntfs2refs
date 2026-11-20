//! How often a check that reads everything again actually does so.
//!
//! Working files are hashed when they are written and are then held open so
//! nothing else can write to them. The source is offline, read-only and held.
//! Re-reading all of it at every later checkpoint made a conversion read tens
//! of times more data than the volume holds.
//!
//! A route that runs a [`Gate`] immediately before its first write to the
//! source may call [`check_once`]. From then on a "read it all again" check
//! does so once inside each gate, and otherwise confirms only identity, size
//! and timestamps. A route that never calls `check_once` (and any run started
//! with `--recheck-everything`) keeps re-reading on every check.
//!
//! A recovery has no such gate: it writes to the source from the journal. It
//! does not call `check_once` when it starts, and it has two switches of its
//! own, [`repeat_once`] and [`repeat_once_as_verified`].

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

static ONCE: AtomicBool = AtomicBool::new(false);
static GATE: AtomicU64 = AtomicU64::new(0);
static NEXT_GATE: AtomicU64 = AtomicU64::new(1);

/// Selects the "once, at the gate" behaviour for the rest of the process.
pub fn check_once() {
    ONCE.store(true, SeqCst);
}

pub fn checks_once() -> bool {
    ONCE.load(SeqCst)
}

static VERIFY_ONCE: AtomicBool = AtomicBool::new(false);

/// Selects "each thing is verified once" for the rest of the process: the
/// run asked for `--verify fast` (the default) and not for
/// `--recheck-everything`. A pass that only looks again at what another pass
/// of the same run checks is then left out; a pass that produces something a
/// later step needs, or is the only independent check of something, never
/// is. Such a run makes one of:
///
/// - Windows reading the contents of a plain stream and the raw reading of
///   it (Windows' map of the stream is still held to the raw run list, and
///   Windows still confirms that its valid data runs to its end);
/// - the shadow's payloads and metadata read back before the capture and
///   again by the walk of the frozen shadow, and its directories listed again
///   after their metadata is restored;
/// - a move of the shadow's extents held to the mapping of the range it
///   moved, and each file's complete mapping compared once, when placement
///   ends, instead of after every one of its moves;
/// - the journal apply reading a range again immediately before writing it:
///   the range was held to its OLD digest before the apply marker and is read
///   back against its NEW digest after it is written;
/// - the short-name links of a converted Windows volume probed once.
///
/// A run with `--verify thorough`, a diagnosis and every route that never
/// calls this (and every test) keep every check as it was. A recovery never
/// calls it either: what a recovery makes once is said by [`repeat_once`]
/// and [`repeat_once_as_verified`].
pub fn verify_once() {
    VERIFY_ONCE.store(true, SeqCst);
}

pub fn verifies_once() -> bool {
    VERIFY_ONCE.load(SeqCst)
}

static REPEAT_ONCE: AtomicBool = AtomicBool::new(false);

/// Selects "an identical check is made once" for the rest of the process:
/// the process recovers a conversion, to resume it or to roll it back (the
/// cancellation a conversion makes of itself before its apply intent is one
/// too), and was not started with `--recheck-everything`.
///
/// A check may be left out under this switch only where all of this holds:
///
/// - this process has already made the same check: the same bytes of the
///   same object, held to the same expectation;
/// - this process has held the object without a break since (the journal
///   and the recovery files it reopened, the source it keeps offline), so
///   that nothing else can have written to it;
/// - this process has not itself written to those bytes since.
///
/// What another process checked, the conversion being recovered among them,
/// never stands for a check here: a recovery reads what it finds.
///
/// Made once under it:
///
/// - the complete read of the journal's body, at the scan that follows the
///   reopening of the journal. Every later step still holds the journal to
///   its identity, its lifecycle markers, its index and the refusal of a
///   second writer, and rebuilds its index from the record descriptors.
///   What one owner of the journal read never stands for another that opens
///   it again under this switch ([`crate::bulk_digest::JournalBodyHold`]);
///   the finalizer of a resumed recovery, which does open it again, checks
///   once by then and is decided by that policy's rule, as before;
/// - the complete read of each recovery file (the publication, the expected
///   pages and their binding, the maps, the alias records), when it is
///   reopened read-only, denying writers. Every later step still holds the
///   same open file to its identity, length, attributes and timestamp. The
///   finalizer of a resumed recovery reopens the same files: the recovery's
///   handles stay open until the finalizer's own are, so that the files are
///   at no moment unheld, and the finalizer compares the digest of that one
///   read with the pin it was given;
/// - the walk of the journal's index against the record descriptors in the
///   journal's body, once for each scan of the journal and not again at
///   every reading of the lifecycle. Each row a step uses is still held to
///   its descriptor when it is read.
///
/// It is not [`check_once`], and a recovery never calls that when it starts.
/// `check_once` leaves every full re-read to the [`Gate`] in front of the
/// first write to the source; a recovery has no such gate and would make
/// none of them. A resumed recovery calls it where its replay is over and
/// the finalizer takes the volume, as before.
pub fn repeat_once() {
    REPEAT_ONCE.store(true, SeqCst);
}

pub fn repeats_once() -> bool {
    REPEAT_ONCE.load(SeqCst)
}

static REPEAT_ONCE_AS_VERIFIED: AtomicBool = AtomicBool::new(false);

/// Selects, for the rest of a recovery, what [`verify_once`] selects for a
/// conversion: the run being recovered was published with `--verify fast`,
/// which the recovery reads from the authenticated publication once it has
/// reopened it, and the process was not started with
/// `--recheck-everything`. A pass that the conversion itself leaves out
/// under [`verify_once`] may then be left out of its recovery, on the same
/// condition: another pass of this recovery checks the same thing.
///
/// Left out under it:
///
/// - the second probe of the short-name links of a converted Windows volume.
///   The finalizer of a recovery issues its ledger of the links by probing
///   every one of them on the converted volume, inside the READ_ONLY lease
///   its protected verification holds: the link's point, its identity, its
///   parent's and its target's, its metadata, its streams and its security.
///   That probe is made in every recovery, whatever the switch. The
///   observation of the converted volume that follows in the same lease
///   probed each link again and held it to what the first probe had just
///   recorded; it stands on the first probe here, as it does in a
///   conversion under [`verify_once`]. It still holds the volume to its
///   extent, to its write protection and to an unchanged device state
///   around it, and a second observation with the same ledger probes
///   again.
///
/// The recovery of a run published with `--verify thorough` never selects
/// this and keeps every such pass. A `--recover` process never selects
/// [`verify_once`] itself: what it leaves out as a conversion would is
/// decided by this switch alone.
pub fn repeat_once_as_verified() {
    REPEAT_ONCE_AS_VERIFIED.store(true, SeqCst);
}

pub fn repeats_once_as_verified() -> bool {
    REPEAT_ONCE_AS_VERIFIED.load(SeqCst)
}

/// The full verification that precedes the first write to the source. While
/// one is alive, every full check runs for real, once.
pub struct Gate(u64);
impl Gate {
    pub fn enter() -> Self {
        let id = NEXT_GATE.fetch_add(1, SeqCst);
        GATE.store(id, SeqCst);
        Self(id)
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        let _ = GATE.compare_exchange(self.0, 0, SeqCst, SeqCst);
    }
}

/// When one object's full checks last ran. Starts as "never".
#[derive(Debug, Default)]
pub struct LastFull(AtomicU64);
impl LastFull {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

fn decide(once: bool, gate: u64, last: &LastFull) -> bool {
    if !once {
        return true;
    }
    gate != 0 && last.0.swap(gate, SeqCst) != gate
}

/// Whether a check that re-reads everything should do so now.
pub fn full(last: &LastFull) -> bool {
    decide(ONCE.load(SeqCst), GATE.load(SeqCst), last)
}

/// As [`full`], for a check with nowhere to remember that it already ran:
/// it runs on every call inside a gate and never outside one.
pub fn full_unremembered() -> bool {
    !ONCE.load(SeqCst) || GATE.load(SeqCst) != 0
}

/// The gate that is open now under [`check_once`], if one is. A complete
/// re-read made inside it may stand for the same held file until it closes;
/// without the policy (`--recheck-everything`) there is never such a gate.
pub fn open_gate() -> Option<u64> {
    let gate = GATE.load(SeqCst);
    (ONCE.load(SeqCst) && gate != 0).then_some(gate)
}

/// Whether bytes read earlier from the frozen source may be served again
/// from memory: the route checks once and no gate is open. Inside the gate
/// every read goes to the disk.
pub fn may_reuse_frozen_reads() -> bool {
    ONCE.load(SeqCst) && GATE.load(SeqCst) == 0
}

/// A check of state that cannot change while the converter holds its disks
/// (source offline and read-only, shadow attached to this process alone) but
/// that costs dozens of device calls. Under [`check_once`] it is repeated at
/// most once per interval, not several times for every file.
#[derive(Debug, Default)]
pub struct Paced(AtomicU64);
impl Paced {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    fn now() -> u64 {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        // Never zero, which means "has not passed yet".
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
            + 1
    }
    /// Whether the check should be made now.
    pub fn due(&self, interval_ms: u64) -> bool {
        if !ONCE.load(SeqCst) || GATE.load(SeqCst) != 0 {
            return true;
        }
        match self.0.load(SeqCst) {
            0 => true,
            last => Self::now().saturating_sub(last) >= interval_ms,
        }
    }
    /// Records that the check just passed.
    pub fn passed(&self) {
        self.0.store(Self::now(), SeqCst);
    }
}

/// Flushes one file of the disposable shadow volume, or one scratch file.
///
/// A flush forces the file system to commit its log; doing that for every
/// file dominated construction. Under [`check_once`] it is left to the volume
/// flush that ends each construction stage and to the flush of the recovery
/// volume before anything is published. Until those, nothing depends on the
/// file surviving a power cut: an interrupted run starts again.
pub fn flush_working_file(file: &std::fs::File) -> std::io::Result<()> {
    if ONCE.load(SeqCst) {
        return Ok(());
    }
    crate::perf::flush(crate::perf::Point::FileFlush, file)
}

/// `CreateFile` flags for a data file of the disposable shadow volume.
///
/// The shadow's files were opened with FILE_FLAG_WRITE_THROUGH, which makes
/// every small write wait for the disk: the full Windows volume spent 73 s
/// in 200,000 such writes while supplying payloads. Under [`check_once`] the
/// flag is dropped, for the same reason [`flush_working_file`] does nothing:
/// the volume is flushed at the end of each construction stage and again
/// when it is frozen, and nothing depends on a file surviving a power cut
/// before then.
pub fn shadow_file_flags(flags: u32) -> u32 {
    const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
    if ONCE.load(SeqCst) {
        flags & !FILE_FLAG_WRITE_THROUGH
    } else {
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The process-wide switches are left alone: other tests rely on the default.
    #[test]
    fn full_checks_run_always_by_default_and_once_per_gate_when_selected() {
        let file = LastFull::new();
        assert!(
            decide(false, 0, &file) && decide(false, 0, &file),
            "the default re-reads on every check"
        );
        assert!(decide(false, 7, &file), "with or without a gate");

        let file = LastFull::new();
        assert!(
            !decide(true, 0, &file),
            "outside a gate only identity is checked"
        );
        assert!(decide(true, 1, &file), "the gate re-reads for real");
        assert!(!decide(true, 1, &file), "but only once");
        assert!(
            decide(true, 1, &LastFull::new()),
            "each object has its own turn"
        );
        assert!(!decide(true, 0, &file));
        assert!(decide(true, 2, &file), "a later gate re-reads again");
    }

    #[test]
    fn a_gate_ends_when_it_is_dropped() {
        let first = Gate::enter();
        let id = first.0;
        assert_eq!(GATE.load(SeqCst), id);
        drop(first);
        assert_ne!(GATE.load(SeqCst), id);
    }
}
