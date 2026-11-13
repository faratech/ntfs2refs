//! The allocation unit of the ReFS volume this process builds, reads or
//! recovers.
//!
//! ReFS has two allocation units: 4 KiB and 64 KiB. One process works on one
//! conversion, so the unit is chosen once: before the shadow is formatted
//! (from the command line), or, in a recovery, from the run's own records.
//! Everything that counts in target clusters asks here. Until a unit is
//! chosen it is 4 KiB, which is what every run made before there was a
//! choice used.
//!
//! This is a number, not evidence: the formatted shadow and the converted
//! volume are each asked what unit they have, and must agree with it.

use std::cell::Cell;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

/// The unit of a run that recorded none.
pub const DEFAULT_BYTES: u64 = 4096;
/// The allocation units ReFS can be formatted with.
pub const SUPPORTED_BYTES: [u64; 2] = [4096, 65536];

static CHOSEN: AtomicU64 = AtomicU64::new(0);
thread_local! {
    /// A unit for the current thread only; see `with`.
    static SCOPED: Cell<u64> = const { Cell::new(0) };
}

/// Chooses the unit for this process. Choosing the same unit again is
/// accepted; a different one is refused, because work already done was
/// counted in the first.
pub fn choose(bytes: u64) -> io::Result<()> {
    if !SUPPORTED_BYTES.contains(&bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a ReFS allocation unit is 4096 or 65536 bytes, not {bytes}"),
        ));
    }
    match CHOSEN.compare_exchange(0, bytes, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(()),
        Err(existing) if existing == bytes => Ok(()),
        Err(existing) => Err(io::Error::other(format!(
            "this process already works with a {existing}-byte ReFS allocation unit and cannot change to {bytes}"
        ))),
    }
}

/// Bytes in one cluster of the target ReFS volume.
pub fn bytes() -> u64 {
    match SCOPED.get() {
        0 => match CHOSEN.load(Ordering::SeqCst) {
            0 => DEFAULT_BYTES,
            chosen => chosen,
        },
        scoped => scoped,
    }
}

/// The same as a `u32`, for the Windows structures that carry it so.
pub fn bytes_u32() -> u32 {
    bytes() as u32
}

/// The same as a `usize`, for buffer lengths.
pub fn bytes_usize() -> usize {
    bytes() as usize
}

/// Whether `offset` (or a length) is a whole number of target clusters.
pub fn aligned(offset: u64) -> bool {
    offset.is_multiple_of(bytes())
}

/// `offset` rounded down to a target cluster boundary.
pub fn floor(offset: u64) -> u64 {
    offset / bytes() * bytes()
}

/// `offset` rounded up to a target cluster boundary, or None on overflow.
pub fn ceil(offset: u64) -> Option<u64> {
    offset.checked_next_multiple_of(bytes())
}

/// Runs `work` with the unit set for this thread alone, leaving the process's
/// choice untouched. For tests of code that counts in target clusters; work
/// handed to other threads does not see it.
pub fn with<T>(bytes: u64, work: impl FnOnce() -> T) -> T {
    assert!(SUPPORTED_BYTES.contains(&bytes));
    struct Restore(u64);
    impl Drop for Restore {
        fn drop(&mut self) {
            SCOPED.set(self.0);
        }
    }
    let _restore = Restore(SCOPED.replace(bytes));
    work()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_is_4_kib_until_chosen_and_a_scope_changes_it_for_one_thread() {
        // Nothing in this test process chooses a unit: every other test
        // counts in the default.
        assert_eq!(bytes(), 4096);
        assert!(aligned(8192) && !aligned(8191));
        assert_eq!((floor(70_000), ceil(70_000)), (69_632, Some(73_728)));
        with(65536, || {
            assert_eq!((bytes(), bytes_u32(), bytes_usize()), (65536, 65536, 65536));
            assert!(aligned(131_072) && !aligned(69_632));
            assert_eq!((floor(70_000), ceil(70_000)), (65_536, Some(131_072)));
            assert_eq!(ceil(u64::MAX), None);
            // Another thread still sees the process's unit.
            assert_eq!(std::thread::spawn(bytes).join().unwrap(), 4096);
            with(4096, || assert_eq!(bytes(), 4096));
            assert_eq!(bytes(), 65536);
        });
        assert_eq!(bytes(), 4096);
    }

    #[test]
    fn only_the_two_units_refs_has_can_be_chosen() {
        for invalid in [0, 512, 8192, 32768, 131_072] {
            let error = choose(invalid).unwrap_err();
            assert!(error.to_string().contains("4096 or 65536"), "{error}");
        }
    }
}
