//! One response buffer per thread for the queries made of every object.
//!
//! Windows writes the answer to a query into a caller's buffer that has to be
//! large enough for the worst case: 64 KiB for a stream list, a directory
//! page or a file's extents, when the usual answer is a few dozen bytes. The
//! walks ask every object several such questions. Allocating and zeroing a
//! worst-case buffer for each one, and then shrinking it to the answer, kept
//! the walks' threads queueing for the heap, and left the heap holding
//! hundreds of thousands of small blocks cut from large ones, which made
//! every later allocation and free slower. A query made through [`with`]
//! writes into a buffer its thread keeps, and the caller copies out exactly
//! the bytes that are the answer.

use std::cell::RefCell;
use std::sync::Mutex;

/// The largest buffer kept between queries. A larger request is served by a
/// buffer of its own, as before.
pub(crate) const KEPT_BYTES: usize = 1024 * 1024;
/// Buffers of threads that have ended, for the threads that come next: the
/// walks start their threads anew for every batch of objects.
static SPARE: Mutex<Vec<Vec<u64>>> = Mutex::new(Vec::new());
const SPARE_BUFFERS: usize = 32;

struct Kept(RefCell<Vec<u64>>);
impl Drop for Kept {
    fn drop(&mut self) {
        let buffer = std::mem::take(self.0.get_mut());
        if buffer.capacity() == 0 {
            return;
        }
        if let Ok(mut spare) = SPARE.lock()
            && spare.len() < SPARE_BUFFERS
        {
            spare.push(buffer);
        }
    }
}
thread_local! {
    static KEPT: Kept = const { Kept(RefCell::new(Vec::new())) };
}

/// Calls `query` with `capacity` zeroed bytes aligned to eight, and returns
/// what it returns. The bytes are the thread's own until `query` returns.
pub(crate) fn with<R>(capacity: usize, query: impl FnOnce(&mut [u8]) -> R) -> R {
    let keep = capacity <= KEPT_BYTES;
    // Taken out of its slot for the duration: a query made from inside
    // `query` finds the slot empty and gets a buffer of its own.
    let mut buffer = if keep {
        KEPT.try_with(|kept| std::mem::take(&mut *kept.0.borrow_mut()))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if keep && buffer.capacity() == 0 {
        buffer = SPARE
            .lock()
            .ok()
            .and_then(|mut spare| spare.pop())
            .unwrap_or_default();
    }
    buffer.clear();
    buffer.resize(capacity.div_ceil(8), 0);
    // SAFETY: `buffer` holds at least `capacity` initialized bytes, every
    // byte pattern is a valid u64, and the borrow is exclusive and ends
    // before the buffer is touched again.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), capacity) };
    let result = query(bytes);
    if keep {
        // During thread teardown the slot is gone and the buffer is dropped.
        let _ = KEPT.try_with(|kept| *kept.0.borrow_mut() = buffer);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_query_starts_zeroed_and_aligned_at_the_size_asked_for() {
        for capacity in [0usize, 1, 7, 8, 24, 65_536, 16 + 24 * 1024] {
            with(capacity, |bytes| {
                assert_eq!(bytes.len(), capacity);
                assert_eq!(bytes.as_ptr() as usize % 8, 0);
                assert!(bytes.iter().all(|byte| *byte == 0));
                bytes.fill(0xa5);
            });
        }
        // What the last query left behind is not seen by the next one,
        // whether it asks for less, the same or more.
        for capacity in [100usize, 16 + 24 * 1024, 65_536, 200_000] {
            with(capacity, |bytes| {
                assert!(bytes.iter().all(|byte| *byte == 0), "capacity {capacity}");
                bytes.fill(0x5a);
            });
        }
    }

    #[test]
    fn a_query_inside_a_query_has_a_buffer_of_its_own() {
        with(4096, |outer| {
            outer.fill(1);
            with(4096, |inner| {
                assert!(inner.iter().all(|byte| *byte == 0));
                inner.fill(2);
            });
            assert!(outer.iter().all(|byte| *byte == 1));
        });
        with(4096, |bytes| assert!(bytes.iter().all(|byte| *byte == 0)));
    }

    #[test]
    fn a_request_larger_than_the_kept_buffer_is_served_and_not_kept() {
        with(KEPT_BYTES + 8, |bytes| {
            assert_eq!(bytes.len(), KEPT_BYTES + 8);
            assert!(bytes.iter().all(|byte| *byte == 0));
        });
        let kept = KEPT.with(|kept| kept.0.borrow().capacity());
        assert!(kept * 8 <= KEPT_BYTES, "kept {kept} words");
    }

    #[test]
    fn a_thread_that_ends_leaves_its_buffer_for_the_next() {
        std::thread::spawn(|| with(65_536, |bytes| bytes.fill(9)))
            .join()
            .unwrap();
        std::thread::spawn(|| {
            with(65_536, |bytes| assert!(bytes.iter().all(|byte| *byte == 0)));
        })
        .join()
        .unwrap();
    }
}
