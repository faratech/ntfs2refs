//! Where a conversion spends its time.
//!
//! A fixed table of process-wide counters, one per choke point. A [`Scope`]
//! adds one call and its elapsed time; [`add_bytes`] adds data volume.
//! [`phase`] prints what the phase that just ended cost, and [`finish`] prints
//! the totals. Points nest (a freeze check contains disk-state queries), so
//! their times overlap and do not sum to the phase time.
//!
//! The table only observes. It never changes what the converter does.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

macro_rules! points {
    ($($name:ident => $label:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(usize)]
        pub enum Point { $($name),+ }
        const LABELS: &[&str] = &[$($label),+];
    };
}
points! {
    Fence => "freeze check",
    DiskState => "disk state query",
    DetachedRoles => "storage-role check",
    ReadProtection => "read-protection check",
    BackingGuard => "backing-space check",
    RecordReaderOpen => "NTFS record reader open",
    FileFlush => "file flush",
    VolumeFlush => "volume flush",
    FileHash => "working-file hash",
    PageLoad => "metadata page load",
    SourceRecheck => "whole-source re-check",
    SourceFingerprint => "source fingerprint read",
    ShadowMetadataRead => "shadow metadata re-read",
    JournalRead => "journal read-back",
    ArenaRevalidation => "working-file re-validation",
    DeviceRead => "device read",
    DeviceWrite => "device write",
    SourceObject => "source object observation",
    ShadowObject => "shadow object observation",
}
const COUNT: usize = LABELS.len();

static CALLS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
static NANOS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
static BYTES: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];

type Row = (u64, u64, u64);
struct Current {
    name: String,
    started: Instant,
    at_start: [Row; COUNT],
}
static CURRENT: Mutex<Option<Current>> = Mutex::new(None);
static PROCESS_START: Mutex<Option<Instant>> = Mutex::new(None);

/// Adds one call and the time until it is dropped.
pub struct Scope {
    point: Point,
    started: Instant,
}
impl Drop for Scope {
    fn drop(&mut self) {
        let index = self.point as usize;
        CALLS[index].fetch_add(1, Relaxed);
        NANOS[index].fetch_add(self.started.elapsed().as_nanos() as u64, Relaxed);
    }
}

pub fn scope(point: Point) -> Scope {
    Scope {
        point,
        started: Instant::now(),
    }
}

pub fn add_bytes(point: Point, bytes: u64) {
    BYTES[point as usize].fetch_add(bytes, Relaxed);
}

/// `sync_all`, with its time recorded under `point`.
pub fn flush(point: Point, file: &std::fs::File) -> std::io::Result<()> {
    let _timed = scope(point);
    file.sync_all()
}

fn snapshot() -> [Row; COUNT] {
    std::array::from_fn(|index| {
        (
            CALLS[index].load(Relaxed),
            NANOS[index].load(Relaxed),
            BYTES[index].load(Relaxed),
        )
    })
}

fn line(name: &str, seconds: f64, from: &[Row; COUNT], to: &[Row; COUNT]) -> String {
    let mut rows: Vec<(usize, Row)> = (0..COUNT)
        .map(|index| {
            (
                index,
                (
                    to[index].0 - from[index].0,
                    to[index].1 - from[index].1,
                    to[index].2 - from[index].2,
                ),
            )
        })
        .filter(|(_, row)| row.0 > 0 || row.2 > 0)
        .collect();
    rows.sort_by_key(|(_, row)| std::cmp::Reverse(row.1));
    let mut text = format!("timing: {name} {seconds:.1}s");
    for (index, (calls, nanos, bytes)) in rows {
        text.push_str(&format!(
            " | {} {:.1}s x{calls}",
            LABELS[index],
            nanos as f64 / 1e9
        ));
        if bytes > 0 {
            text.push_str(&format!(" {:.2} GB", bytes as f64 / (1u64 << 30) as f64));
        }
    }
    text
}

/// Starts a named phase and prints what the previous one cost.
pub fn phase(name: &str) {
    let now = snapshot();
    PROCESS_START
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(Instant::now);
    let mut current = CURRENT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(previous) = current.take() {
        eprintln!(
            "{}",
            line(
                &previous.name,
                previous.started.elapsed().as_secs_f64(),
                &previous.at_start,
                &now
            )
        );
    }
    *current = Some(Current {
        name: name.to_owned(),
        started: Instant::now(),
        at_start: now,
    });
}

/// Prints the last phase and the totals. Safe to call more than once.
pub fn finish() {
    let now = snapshot();
    let previous = CURRENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(previous) = previous {
        eprintln!(
            "{}",
            line(
                &previous.name,
                previous.started.elapsed().as_secs_f64(),
                &previous.at_start,
                &now
            )
        );
    }
    let started = PROCESS_START
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(started) = started {
        eprintln!(
            "{}",
            line(
                "TOTAL",
                started.elapsed().as_secs_f64(),
                &[(0, 0, 0); COUNT],
                &now
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_counts_one_call_and_bytes_are_reported_per_point() {
        let before = snapshot();
        {
            let _timed = scope(Point::JournalRead);
            add_bytes(Point::JournalRead, 3 << 30);
        }
        let after = snapshot();
        let index = Point::JournalRead as usize;
        assert_eq!(after[index].0 - before[index].0, 1);
        let text = line("example", 2.0, &before, &after);
        assert!(text.starts_with("timing: example 2.0s"), "{text}");
        assert!(text.contains("journal read-back") && text.contains("x1 3.00 GB"), "{text}");
        assert!(!text.contains("freeze check"), "{text}");
    }
}
