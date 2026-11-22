//! Work on source rows done by helper threads and taken back in the rows'
//! order: the readers of the held source stay on the calling thread (they
//! are not shared between threads), the helpers get only owned values.
use anyhow::{Context, Result, anyhow};
use std::sync::{Mutex, mpsc};

/// One row of a batch, as the calling thread gathered it.
pub(super) enum Slot<J, O> {
    /// Handed to a helper thread; what it makes of it is taken in this
    /// row's place.
    Work(J),
    /// Taken as it is.
    Ready(O),
}

struct Job<J> {
    items: Vec<(usize, J)>,
}
type Done<O> = std::thread::Result<Vec<(usize, O)>>;

/// Runs `gather` on this thread for one batch after another until it
/// gathers none, hands the `Work` of each batch to `helpers` threads, which
/// apply `work` to it, and gives everything to `merge` on this thread in the
/// order `gather` made it. The next batch is gathered while the helpers
/// work through the one before, so at most two batches are held at once.
/// The first error of `merge` ends the run with that error: what `merge`
/// takes before it is what one thread doing it all in turn would have taken.
///
/// `work` is expected to answer a panic of its own with a result. A panic it
/// lets through ends the run with an error, and so does a helper thread that
/// cannot be started or ends. The helpers count in the target cluster of
/// this thread.
pub(super) fn in_order<J: Send, O: Send>(
    helpers: usize,
    mut gather: impl FnMut() -> Vec<Slot<J, O>>,
    work: impl Fn(J) -> O + Sync,
    mut merge: impl FnMut(O) -> Result<()>,
) -> Result<()> {
    let helpers = helpers.max(1);
    let target_cluster = n2r_win32::target_cluster::bytes();
    let (job_tx, job_rx) = mpsc::channel::<Job<J>>();
    let job_rx = Mutex::new(job_rx);
    let (done_tx, done_rx) = mpsc::channel::<Done<O>>();
    std::thread::scope(|scope| {
        // Owned here: when this returns, on an error too, the helpers find
        // no more work and end, and the scope then waits for them.
        let (job_tx, done_rx) = (job_tx, done_rx);
        for _ in 0..helpers {
            let done_tx = done_tx.clone();
            let (job_rx, work) = (&job_rx, &work);
            std::thread::Builder::new()
                .name("projection-helper".into())
                .spawn_scoped(scope, move || {
                    let _sampled = n2r_win32::stack_sampler::helper();
                    n2r_win32::target_cluster::with(target_cluster, || {
                        loop {
                            let job = match job_rx.lock() {
                                Ok(jobs) => jobs.recv(),
                                Err(_) => return,
                            };
                            let Ok(Job { items }) = job else {
                                return;
                            };
                            let done =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    items
                                        .into_iter()
                                        .map(|(place, item)| (place, work(item)))
                                        .collect::<Vec<_>>()
                                }));
                            if done_tx.send(done).is_err() {
                                return;
                            }
                        }
                    })
                })
                .context("a helper thread of the projection could not be started")?;
        }
        drop(done_tx);
        let mut batch = gather();
        while !batch.is_empty() {
            let mut taken: Vec<Option<O>> = Vec::new();
            taken.try_reserve_exact(batch.len())?;
            let mut handed = Vec::new();
            for (place, slot) in batch.into_iter().enumerate() {
                match slot {
                    Slot::Work(item) => {
                        taken.push(None);
                        handed.push((place, item));
                    }
                    Slot::Ready(ready) => taken.push(Some(ready)),
                }
            }
            // About as many rows to each helper.
            let chunk = handed.len().div_ceil(helpers).max(1);
            let mut jobs = 0usize;
            let mut handed = handed.into_iter().peekable();
            while handed.peek().is_some() {
                let items: Vec<_> = handed.by_ref().take(chunk).collect();
                job_tx
                    .send(Job { items })
                    .map_err(|_| anyhow!("the projection's helper threads have ended"))?;
                jobs += 1;
            }
            let following = gather();
            for _ in 0..jobs {
                let done = done_rx
                    .recv()
                    .map_err(|_| anyhow!("the projection's helper threads have ended"))?;
                let done = done.map_err(|panic| {
                    anyhow!(
                        "a helper thread of the projection panicked: {}",
                        panic_text(panic.as_ref())
                    )
                })?;
                for (place, made) in done {
                    *taken
                        .get_mut(place)
                        .context("a helper of the projection answered for no row")? = Some(made);
                }
            }
            for made in taken {
                merge(made.context("a row of the projection has no answer")?)?;
            }
            batch = following;
        }
        Ok(())
    })
}

/// What a panic said, where it said it as text.
pub(super) fn panic_text(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("no message")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gathers `count` rows in batches of `batch`; every fifth is ready on
    /// this thread, the others are squared by a helper.
    fn run(
        count: u64,
        batch: usize,
        helpers: usize,
        work: impl Fn(u64) -> Result<u64> + Sync,
        mut merged: impl FnMut(u64, u64) -> Result<()>,
    ) -> Result<()> {
        let mut next = 0u64;
        in_order(
            helpers,
            || {
                let mut slots = Vec::new();
                while next < count && slots.len() < batch {
                    slots.push(if next.is_multiple_of(5) {
                        Slot::Ready((next, Ok(next)))
                    } else {
                        Slot::Work(next)
                    });
                    next += 1;
                }
                slots
            },
            |row| (row, work(row)),
            |(row, made)| merged(row, made?),
        )
    }

    #[test]
    fn rows_are_merged_in_the_order_they_were_gathered() {
        for helpers in [1, 3, 8] {
            let mut seen = Vec::new();
            run(
                1000,
                64,
                helpers,
                |row| Ok(row * row),
                |row, made| {
                    seen.push((row, made));
                    Ok(())
                },
            )
            .unwrap();
            let expected: Vec<_> = (0..1000u64)
                .map(|row| {
                    (
                        row,
                        if row.is_multiple_of(5) {
                            row
                        } else {
                            row * row
                        },
                    )
                })
                .collect();
            assert_eq!(seen, expected, "{helpers} helpers");
        }
    }

    #[test]
    fn the_first_refusal_in_order_ends_the_run_with_what_came_before() {
        let mut seen = Vec::new();
        let error = run(
            1000,
            64,
            4,
            |row| {
                if row == 337 || row == 801 || row == 902 {
                    anyhow::bail!("row {row} refused")
                }
                Ok(row)
            },
            |row, _| {
                seen.push(row);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "row 337 refused");
        assert_eq!(seen, (0..337).collect::<Vec<_>>());
        // A refusal of the merge itself ends it too.
        let error = run(1000, 64, 4, Ok, |row, _| {
            anyhow::ensure!(row != 65, "merge refused {row}");
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "merge refused 65");
    }

    #[test]
    fn a_panic_that_work_lets_through_is_an_error_not_a_hang() {
        let error = run(
            300,
            32,
            3,
            |row| {
                if row == 77 {
                    panic!("row 77 broke");
                }
                Ok(row)
            },
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("row 77 broke"), "{error}");
    }

    #[test]
    fn helpers_count_in_the_target_cluster_of_the_calling_thread() {
        n2r_win32::target_cluster::with(65536, || {
            let mut units = Vec::new();
            run(
                40,
                8,
                2,
                |_| Ok(n2r_win32::target_cluster::bytes()),
                |row, unit| {
                    if !row.is_multiple_of(5) {
                        units.push(unit);
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert!(units.iter().all(|unit| *unit == 65536), "{units:?}");
        });
    }
}
