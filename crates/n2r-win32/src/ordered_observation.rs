//! Objects observed on helper threads and taken in their order.
//!
//! A pass that observes every object of a volume and then counts, checks and
//! writes what it saw, one object after another, can do the observing on
//! several threads only if the rest still happens in order, exactly as it did
//! on one. [`in_order`] gathers a batch of objects on the calling thread,
//! hands it to helper threads to observe, and then takes each object in turn
//! on the calling thread with what its helper saw. A helper may see nothing
//! (its result could not be paid for); taking the object then observes it on
//! the calling thread, as a pass without helpers does for every object.
//!
//! What a helper saw is a guess made before the objects ahead of it were
//! taken. The caller decides, as it takes each object, whether the guess is
//! what observing the object then would have given, and observes it again if
//! it is not; this module only keeps the order.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// How many objects each helper is given in one batch, on average. A batch
/// starts its helpers and waits for the last of them to finish, which costs
/// about a millisecond whatever the batch holds; at this size that is small
/// beside the objects. The batch's results are paid for one by one as they
/// are made, so its size is no claim on memory.
pub(crate) const OBJECTS_PER_HELPER: usize = 64;

/// How many neighbouring objects a helper takes at a time. Neighbours tend to
/// share a directory, and Windows works through one directory's objects one
/// at a time for `GetSecurityInfo`: eight threads taking a directory's files
/// in turn were three times slower than eight threads in eight directories
/// (#140). Taking runs keeps the helpers apart.
pub(crate) const RUN: usize = 16;

/// Takes objects `0..count`, in order, with `state`.
///
/// `gather(state, index, first)` is called on the calling thread, in order,
/// to make object `index` ready for a helper; `first` says it would be the
/// first of its batch. `Ok(None)` ends the batch before the object (the
/// object has no room in this batch, for example its memory was refused): it
/// is gathered again as the first of the next batch, where it must be
/// gathered. An error ends the batch the same way, and is the pass's error
/// only for the first object of a batch: an object gathered after others may
/// have failed for what those others held. While helpers run, a first object
/// that fails is not yet the pass's error either: `release(state)` gives up
/// what the helpers hold, the rest of the pass runs without them, and the
/// object is gathered once more, as a pass that never had helpers gathers
/// it. Only what it fails with then is the pass's error.
///
/// `observe` runs on up to `helpers` threads, each object at most once; with
/// fewer than two helpers no thread is started and every object is taken
/// with nothing observed. `take(state, index, object, observed)` is called on
/// the calling thread for every gathered object in order; its first error
/// ends the pass, and no object after it is taken.
///
/// `point` is charged as one call per object taken, with the calling thread's
/// time: the time to gather and observe a batch is added to it as well, so
/// that its total is the pass's wall time whether helpers ran or not.
///
/// While helpers observe one batch, the calling thread takes the batch
/// before it and gathers the batch after it, so that taking (counting,
/// checking, writing) overlaps observing. Objects gathered ahead are
/// gathered while the batch before them is still held: each is gathered
/// with `first` false, and the first that is refused or fails only ends that
/// batch. Once the batches before it are taken, it is gathered again as the
/// first of its batch, with every rule above.
#[allow(clippy::too_many_arguments)]
pub(crate) fn in_order<S, R: Sync, O: Send>(
    count: usize,
    helpers: usize,
    point: crate::perf::Point,
    state: &mut S,
    mut gather: impl FnMut(&mut S, usize, bool) -> io::Result<Option<R>>,
    observe: impl Fn(&R) -> Option<O> + Sync,
    mut take: impl FnMut(&mut S, usize, R, Option<O>) -> io::Result<()>,
    mut release: impl FnMut(&mut S),
) -> io::Result<()> {
    let mut helpers = if helpers >= 2 { helpers } else { 0 };
    let mut next = 0;
    // A batch gathered and observed, waiting to be taken: its first index,
    // its objects and what the helpers saw of each.
    type Observed<R, O> = (usize, Vec<R>, Vec<Option<O>>);
    let mut take_all = |state: &mut S, (start, objects, observed): Observed<R, O>| {
        for (offset, (object, observed)) in objects.into_iter().zip(observed).enumerate() {
            let _timed = crate::perf::scope(point);
            take(state, start + offset, object, observed)?;
        }
        Ok::<(), io::Error>(())
    };
    while next < count {
        let started = Instant::now();
        let batch = helpers.saturating_mul(OBJECTS_PER_HELPER).max(1);
        let mut end = next.saturating_add(batch).min(count);
        let mut objects = Vec::with_capacity(end - next);
        let mut index = next;
        while index < end {
            let first = objects.is_empty();
            match gather(state, index, first) {
                Ok(Some(object)) => objects.push(object),
                Ok(None) if !first => break,
                Ok(None) => {
                    return Err(io::Error::other(format!(
                        "object {index} of {count} was refused as the first of its batch"
                    )));
                }
                Err(_) if !first => break,
                Err(_) if helpers > 0 => {
                    // Gathered again alone, as without helpers.
                    release(state);
                    helpers = 0;
                    end = index + 1;
                    continue;
                }
                Err(error) => return Err(error),
            }
            index += 1;
        }
        if helpers < 2 || objects.len() < 2 {
            crate::perf::add_time(point, started.elapsed());
            let gathered = objects.len();
            let observed = objects.iter().map(|_| None).collect();
            take_all(state, (next, objects, observed))?;
            next += gathered;
            continue;
        }
        // The pipeline: helpers observe `current` while this thread takes
        // `waiting` (the batch before it) and gathers the batch after it.
        let mut current = (next, objects);
        let mut waiting: Option<Observed<R, O>> = None;
        let mut started = started;
        loop {
            let after = current.0 + current.1.len();
            let mut taking = std::time::Duration::ZERO;
            let (observed, ahead, taken) = std::thread::scope(|scope| {
                let observing = spawn_batch(scope, &current.1, helpers, &observe);
                let mut ahead = Vec::new();
                let taken = (|| {
                    if let Some(waiting) = waiting.take() {
                        let at = Instant::now();
                        let result = take_all(state, waiting);
                        taking = at.elapsed();
                        result?;
                    }
                    let end = after.saturating_add(batch).min(count);
                    for index in after..end {
                        match gather(state, index, false) {
                            Ok(Some(object)) => ahead.push(object),
                            // Gathered again once the batches before it
                            // are taken, as the first of its batch.
                            Ok(None) | Err(_) => break,
                        }
                    }
                    Ok::<(), io::Error>(())
                })();
                (join_batch(observing, current.1.len()), ahead, taken)
            });
            // What the helpers did, and gathering ahead, in the pass's wall
            // time; taking was timed object by object.
            crate::perf::add_time(point, started.elapsed().saturating_sub(taking));
            started = Instant::now();
            taken?;
            let (start, objects) = current;
            let observed_batch = (start, objects, observed);
            if ahead.is_empty() {
                // Nothing gathered ahead: take what is waiting and go on
                // with the rules of a batch gathered with nothing held.
                take_all(state, observed_batch)?;
                next = after;
                break;
            }
            waiting = Some(observed_batch);
            current = (after, ahead);
        }
    }
    Ok(())
}

/// Starts `observe` for every object of `objects` on up to `helpers` scoped
/// threads that take runs of [`RUN`] neighbouring objects.
fn spawn_batch<'scope, 'env, R: Sync, O: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    objects: &'scope [R],
    helpers: usize,
    observe: &'scope (impl Fn(&R) -> Option<O> + Sync),
) -> Vec<std::thread::ScopedJoinHandle<'scope, Vec<(usize, Option<O>)>>> {
    let threads = helpers.min(objects.len().div_ceil(RUN)).max(1);
    let next = std::sync::Arc::new(AtomicUsize::new(0));
    (0..threads)
        .map(|_| {
            let next = std::sync::Arc::clone(&next);
            scope.spawn(move || {
                let _sampled = crate::stack_sampler::helper();
                let mut done = Vec::new();
                loop {
                    let start = next.fetch_add(RUN, Ordering::Relaxed);
                    if start >= objects.len() {
                        break;
                    }
                    for (index, object) in objects.iter().enumerate().skip(start).take(RUN) {
                        let _timed = crate::perf::scope(crate::perf::Point::AtOnce);
                        done.push((index, observe(object)));
                    }
                }
                done
            })
        })
        .collect()
}

/// What [`spawn_batch`]'s threads saw, in the objects' order.
fn join_batch<O>(
    handles: Vec<std::thread::ScopedJoinHandle<'_, Vec<(usize, Option<O>)>>>,
    len: usize,
) -> Vec<Option<O>> {
    let mut results: Vec<Option<O>> = (0..len).map(|_| None).collect();
    for handle in handles {
        match handle.join() {
            Ok(done) => {
                for (index, observed) in done {
                    results[index] = observed;
                }
            }
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    results
}

/// `observe` for every object, on up to `helpers` threads that take runs of
/// [`RUN`] neighbouring objects; the results in the objects' order.
pub(crate) fn observe_batch<R: Sync, O: Send>(
    objects: &[R],
    helpers: usize,
    observe: &(impl Fn(&R) -> Option<O> + Sync),
) -> Vec<Option<O>> {
    let threads = helpers.min(objects.len().div_ceil(RUN)).max(1);
    let next = AtomicUsize::new(0);
    let mut results: Vec<Option<O>> = objects.iter().map(|_| None).collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let _sampled = crate::stack_sampler::helper();
                    let mut done = Vec::new();
                    loop {
                        let start = next.fetch_add(RUN, Ordering::Relaxed);
                        if start >= objects.len() {
                            break;
                        }
                        for (index, object) in objects.iter().enumerate().skip(start).take(RUN) {
                            let _timed = crate::perf::scope(crate::perf::Point::AtOnce);
                            done.push((index, observe(object)));
                        }
                    }
                    done
                })
            })
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(done) => {
                    for (index, observed) in done {
                        results[index] = observed;
                    }
                }
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
    });
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perf::Point;
    use std::sync::atomic::AtomicUsize;

    /// A pass whose observation depends on what was taken before it: each
    /// object's value is its index plus the running total at the time it is
    /// observed, as an object's evidence limit depends on what the objects
    /// ahead of it hold. A guess made with a stale total is redone.
    #[derive(Default)]
    struct Pass {
        total: u64,
        taken: Vec<(usize, u64)>,
        redone: usize,
    }
    fn value(index: usize, total: u64) -> u64 {
        // Only some objects change the total, so that some guesses hold.
        if index.is_multiple_of(3) {
            index as u64 + total
        } else {
            index as u64
        }
    }
    fn run(count: usize, helpers: usize) -> Pass {
        let mut pass = Pass::default();
        in_order(
            count,
            helpers,
            Point::InTurn,
            &mut pass,
            |pass, index, _| Ok(Some((index, pass.total))),
            |&(index, total)| {
                // Later objects of a run finish first.
                std::thread::sleep(std::time::Duration::from_micros(
                    ((RUN - index % RUN) * 20) as u64,
                ));
                Some(value(index, total))
            },
            |pass, index, (gathered, total), observed| {
                assert_eq!(gathered, index);
                let value = match observed {
                    Some(guess) if total == pass.total => guess,
                    _ => {
                        if observed.is_some() {
                            pass.redone += 1;
                        }
                        value(index, pass.total)
                    }
                };
                pass.total += value % 7;
                pass.taken.push((index, value));
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        pass
    }

    #[test]
    fn objects_observed_at_once_are_taken_in_order_as_one_thread_takes_them() {
        let count = 4 * OBJECTS_PER_HELPER + 37;
        let alone = run(count, 0);
        assert_eq!(alone.redone, 0);
        for helpers in [1, 2, 4, 7] {
            let together = run(count, helpers);
            assert_eq!(together.taken, alone.taken, "{helpers} helpers");
            assert_eq!(together.total, alone.total);
        }
        // The guesses made before the objects ahead were taken are redone.
        assert!(run(count, 4).redone > 0);
    }

    #[test]
    fn one_helper_starts_no_thread_and_observes_nothing() {
        let observed = AtomicUsize::new(0);
        let mut taken = Vec::new();
        in_order(
            10,
            1,
            Point::InTurn,
            &mut taken,
            |_, index, _| Ok(Some(index)),
            |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Some(())
            },
            |taken, index, _, seen| {
                assert!(seen.is_none());
                taken.push(index);
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(observed.load(Ordering::Relaxed), 0);
        assert_eq!(taken, (0..10).collect::<Vec<_>>());
    }

    /// A refused object ends its batch and starts the next; a result that
    /// could not be paid for is taken with nothing observed.
    #[test]
    fn a_refused_object_starts_the_next_batch_and_an_unpaid_result_is_taken_in_turn() {
        let mut state = (Vec::new(), Vec::new());
        in_order(
            300,
            4,
            Point::InTurn,
            &mut state,
            |(gathered, _): &mut (Vec<(usize, bool)>, Vec<_>), index, first| {
                gathered.push((index, first));
                // Every fiftieth object has no room unless it comes first.
                Ok((first || index % 50 != 0).then_some(index))
            },
            |&index| (index % 5 != 0).then_some(index),
            |(_, taken), index, object, observed| {
                assert_eq!(object, index);
                assert_eq!(observed.is_some(), index % 5 != 0, "object {index}");
                taken.push(index);
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        let (gathered, taken) = state;
        assert_eq!(taken, (0..300).collect::<Vec<_>>());
        for index in (50..300).step_by(50) {
            // Refused behind others, then gathered first of the next batch.
            assert!(gathered.contains(&(index, false)), "object {index}");
            assert!(gathered.contains(&(index, true)), "object {index}");
        }
    }

    /// An object that fails to be gathered while the helpers hold memory is
    /// gathered again once they have given it up, and the pass goes on
    /// without them: as a pass that never had helpers would have.
    #[test]
    fn a_first_object_that_fails_beside_the_helpers_is_gathered_again_without_them() {
        #[derive(Default)]
        struct State {
            held: bool,
            released: usize,
            taken: Vec<(usize, bool)>,
        }
        let mut state = State {
            held: true,
            ..State::default()
        };
        in_order(
            1000,
            4,
            Point::InTurn,
            &mut state,
            |state, index, _| {
                // Object 300 needs what the helpers hold.
                if index == 300 && state.held {
                    return Err(io::Error::other("no room to decode row 300"));
                }
                Ok(Some(index))
            },
            |&index| Some(index),
            |state, index, object, observed| {
                assert_eq!(object, index);
                state.taken.push((index, observed.is_some()));
                Ok(())
            },
            |state| {
                state.held = false;
                state.released += 1;
            },
        )
        .unwrap();
        assert_eq!(state.released, 1);
        let indexes: Vec<usize> = state.taken.iter().map(|(index, _)| *index).collect();
        assert_eq!(indexes, (0..1000).collect::<Vec<_>>());
        // Observed ahead before, in turn from then on.
        assert!(state.taken[..256].iter().all(|(_, ahead)| *ahead));
        assert!(state.taken[300..].iter().all(|(_, ahead)| !*ahead));
    }

    /// An object that cannot be gathered fails the pass where a pass on one
    /// thread fails: after every object before it is taken, and only when
    /// it fails again as the first of a batch.
    #[test]
    fn a_failure_to_gather_is_the_passs_error_after_the_objects_before_it() {
        for helpers in [0, 4] {
            let mut tries = Vec::new();
            let mut state = (Vec::new(), &mut tries);
            let error = in_order(
                1000,
                helpers,
                Point::InTurn,
                &mut state,
                |(_, tries), index, first| {
                    if index == 70 {
                        tries.push(first);
                        return Err(io::Error::other("row 70 unreadable"));
                    }
                    Ok(Some(index))
                },
                |&index| Some(index),
                |(taken, _), index, _, _| {
                    taken.push(index);
                    Ok(())
                },
                |_| {},
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "row 70 unreadable");
            assert_eq!(state.0, (0..70).collect::<Vec<_>>(), "{helpers} helpers");
            assert_eq!(state.1.last(), Some(&true));
        }
    }

    /// The first object whose taking fails ends the pass; nothing after it
    /// is taken, whatever the helpers observed ahead of it.
    #[test]
    fn the_first_failure_to_take_ends_the_pass() {
        for helpers in [0, 3] {
            let mut taken = Vec::new();
            let error = in_order(
                500,
                helpers,
                Point::InTurn,
                &mut taken,
                |_, index, _| Ok(Some(index)),
                |&index| Some(index),
                |taken, index, _, _| {
                    if index == 133 || index == 260 {
                        return Err(io::Error::other(format!("object {index} over budget")));
                    }
                    taken.push(index);
                    Ok(())
                },
                |_| {},
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "object 133 over budget");
            assert_eq!(taken, (0..133).collect::<Vec<_>>());
        }
    }

    /// While one batch is observed, the batch before it is taken and the
    /// batch after it gathered (with `first` false); every object is still
    /// gathered, observed once and taken in order.
    #[test]
    fn taking_a_batch_overlaps_observing_the_next() {
        #[derive(Default)]
        struct State {
            events: Vec<(char, usize, bool)>,
            taken: Vec<usize>,
        }
        let observed: Vec<AtomicUsize> = (0..1000).map(|_| AtomicUsize::new(0)).collect();
        let mut state = State::default();
        in_order(
            1000,
            3,
            Point::InTurn,
            &mut state,
            |state, index, first| {
                state.events.push(('g', index, first));
                Ok(Some(index))
            },
            |&index| {
                observed[index].fetch_add(1, Ordering::Relaxed);
                Some(index)
            },
            |state, index, object, seen| {
                assert_eq!((object, seen), (index, Some(index)));
                state.events.push(('t', index, false));
                state.taken.push(index);
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(state.taken, (0..1000).collect::<Vec<_>>());
        assert!(observed.iter().all(|n| n.load(Ordering::Relaxed) == 1));
        let batch = 3 * OBJECTS_PER_HELPER;
        let at = |event: (char, usize, bool)| state.events.iter().position(|e| *e == event);
        // The second batch is gathered ahead before the first is taken, and
        // the third before the second is.
        assert!(at(('g', batch, false)).unwrap() < at(('t', 0, false)).unwrap());
        assert!(at(('g', 2 * batch, false)).unwrap() < at(('t', batch, false)).unwrap());
        // Only the first object of the pass is gathered as a first.
        assert_eq!(
            state.events.iter().filter(|(kind, _, first)| *kind == 'g' && *first).count(),
            1
        );
    }

    #[test]
    fn every_object_of_a_batch_is_observed_once() {
        let calls: Vec<AtomicUsize> = (0..1000).map(|_| AtomicUsize::new(0)).collect();
        let observed = observe_batch(&(0..1000).collect::<Vec<usize>>(), 6, &|&index| {
            calls[index].fetch_add(1, Ordering::Relaxed);
            Some(index * 2)
        });
        assert!(calls.iter().all(|c| c.load(Ordering::Relaxed) == 1));
        assert_eq!(
            observed,
            (0..1000).map(|index| Some(index * 2)).collect::<Vec<_>>()
        );
    }
}
