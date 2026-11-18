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
    // Bytes only: what readers were handed, from the device or from the
    // read-ahead window. Against "device read" it shows what read-ahead costs.
    DeviceReadServed => "device bytes served",
    DeviceWrite => "device write",
    SourceObject => "source object observation",
    ShadowObject => "shadow object observation",
    JournalScan => "journal scan",
    TargetCheck => "changed-range check",
    ContentRead => "file content read",
    VolumeWait => "wait for volume",
    VolumeRemoval => "wait for volume removal",
    RecoveryFileOpen => "recovery file reopen",
    // What the passes that work on every core did there, and what they did
    // one object after another because a batch's workspace could not be paid
    // for (or the machine has one core). The first is the threads' time added
    // up, not wall clock.
    AtOnce => "objects at once (thread time)",
    InTurn => "objects in turn",
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

struct Steps {
    current: Option<(&'static str, Instant)>,
    done: Vec<(&'static str, f64)>,
    // What each step of the phase could not do without at its highest, and
    // what held it then.
    memory: Vec<(&'static str, u64, String)>,
}
static STEPS: Mutex<Steps> = Mutex::new(Steps {
    current: None,
    done: Vec::new(),
    memory: Vec::new(),
});
// The same for the step that is running: its highest level, and the level
// its holders were last written down at with what they were.
static STEP_NEEDED_PEAK: AtomicU64 = AtomicU64::new(0);
static STEP_HOLDERS: Mutex<(u64, String)> = Mutex::new((0, String::new()));

/// Ends the running step's memory record and files it under its name.
fn end_step_memory(steps: &mut Steps, name: &'static str) {
    let peak = STEP_NEEDED_PEAK.swap(0, Relaxed);
    let holders = STEP_HOLDERS
        .lock()
        .map(|mut holders| std::mem::take(&mut *holders).1)
        .unwrap_or_default();
    file_step_memory(&mut steps.memory, name, peak, holders);
}

/// Files what a step could not do without under its name: the highest
/// level where a step runs more than once, and nothing for a step that
/// reserved nothing.
fn file_step_memory(
    memory: &mut Vec<(&'static str, u64, String)>,
    name: &'static str,
    peak: u64,
    holders: String,
) {
    if peak == 0 {
        return;
    }
    match memory.iter_mut().find(|(done, _, _)| *done == name) {
        Some((_, highest, held)) if *highest < peak => (*highest, *held) = (peak, holders),
        Some(_) => {}
        None => memory.push((name, peak, holders)),
    }
}

/// Starts a named step inside the current phase; the previous step ends.
/// For the handful of large steps of a phase, not for anything per object.
pub fn step(name: &'static str) {
    crate::stack_sampler::note_step(name);
    let mut steps = STEPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((previous, started)) = steps.current.take() {
        let seconds = started.elapsed().as_secs_f64();
        match steps.done.iter_mut().find(|(done, _)| *done == previous) {
            Some((_, total)) => *total += seconds,
            None => steps.done.push((previous, seconds)),
        }
        end_step_memory(&mut steps, previous);
    }
    steps.current = Some((name, Instant::now()));
}

/// Ends the current step and prints every step of the phase that just ended.
fn finish_steps(phase: &str) {
    let mut steps = STEPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((previous, started)) = steps.current.take() {
        let seconds = started.elapsed().as_secs_f64();
        match steps.done.iter_mut().find(|(done, _)| *done == previous) {
            Some((_, total)) => *total += seconds,
            None => steps.done.push((previous, seconds)),
        }
        end_step_memory(&mut steps, previous);
    }
    if steps.done.is_empty() {
        return;
    }
    let mut text = format!("timing-steps: {phase}");
    for (name, seconds) in steps.done.drain(..) {
        text.push_str(&format!(" | {name} {seconds:.1}s"));
    }
    eprintln!("{text}");
    // What the steps could not do without, for those that held a sixteenth
    // of the ledger or more, each with its three largest reservations:
    // where a volume's memory goes, step by step, and not only at the one
    // moment the whole run peaked.
    let floor = LEDGER_LIMIT.load(Relaxed) / 16;
    let mut text = String::new();
    for (name, peak, holders) in steps.memory.drain(..) {
        if peak >= floor.max(1) {
            let largest: Vec<&str> = holders.split(", ").take(3).collect();
            text.push_str(&format!(
                " | {name} {} MiB ({})",
                peak >> 20,
                largest.join(", ")
            ));
        }
    }
    if !text.is_empty() {
        eprintln!("memory-steps: {phase}{text}");
    }
}

/// Starts a named phase and prints what the previous one cost.
pub fn phase(name: &str) {
    crate::stack_sampler::note_phase(name);
    let now = snapshot();
    PROCESS_START
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(Instant::now);
    let mut current = CURRENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        finish_steps(&previous.name);
    }
    *current = Some(Current {
        name: name.to_owned(),
        started: Instant::now(),
        at_start: now,
    });
}

static LEDGER_PEAK: AtomicU64 = AtomicU64::new(0);
static LEDGER_LIMIT: AtomicU64 = AtomicU64::new(0);
static LEDGER_NEEDED_PEAK: AtomicU64 = AtomicU64::new(0);
// What held the ledger's memory when the needed peak was last written down,
// and the level it was written down at.
static LEDGER_HOLDERS: Mutex<(u64, String)> = Mutex::new((0, String::new()));

/// What a run's memory ledger holds after a reservation, and what it may
/// hold: the highest level is printed with the totals, so that what a
/// volume takes of the ledger can be read off a run.
///
/// A run has more than one ledger, one after another (the preparation's,
/// then the finalization's), each with the limit the free memory gave it
/// when it was made. The limit printed is the one of the ledger that
/// reached the peak: printed with the last ledger's limit, a peak in the
/// preparation read as more than the run may hold (#149).
///
/// `needed` is the part of `held` that the conversion could not do without:
/// not the optional caches and not the spare memory of batches, both of
/// which a ledger grants only while it has room. Its highest level is what
/// a volume takes of a machine's memory (#129), and it is printed beside
/// the peak. The answer says whether the caller should now say what holds
/// the memory ([`note_ledger_holders`]): when the needed peak has grown by a
/// sixty-fourth of the limit since that was last written down, so that a
/// run pays for at most sixty-four descriptions a ledger.
pub fn note_ledger(held: u64, needed: u64, limit: u64) -> bool {
    LEDGER_NOW.0.store(held, Relaxed);
    LEDGER_NOW.1.store(needed, Relaxed);
    if LEDGER_PEAK.fetch_max(held, Relaxed) < held {
        LEDGER_LIMIT.store(limit, Relaxed);
    }
    // The running step's own highest level, and the run's.
    let step_due = STEP_NEEDED_PEAK.fetch_max(needed, Relaxed) < needed && {
        let described = STEP_HOLDERS.lock().map_or(u64::MAX, |holders| holders.0);
        holders_due(needed, described, limit)
    };
    if LEDGER_NEEDED_PEAK.fetch_max(needed, Relaxed) >= needed {
        return step_due;
    }
    let described = LEDGER_HOLDERS.lock().map_or(u64::MAX, |holders| holders.0);
    step_due || holders_due(needed, described, limit)
}

fn holders_due(needed: u64, described: u64, limit: u64) -> bool {
    described
        .checked_add((limit / 64).max(1))
        .is_some_and(|due| needed >= due)
}

/// How far a run that fits itself to the machine went beyond the memory it
/// set aside when it started, at the most.
static BEYOND_BUDGET: AtomicU64 = AtomicU64::new(0);

/// The ledger let what the run cannot do without go this far beyond its
/// budget (`ArtifactArena::go_beyond_budget`).
pub fn note_beyond_budget(bytes: u64) {
    BEYOND_BUDGET.fetch_max(bytes, Relaxed);
}

/// What held a ledger's memory when what the run could not do without stood
/// at `needed`: printed with the totals, so that a run says what a volume's
/// memory went to and not only how much it was.
pub fn note_ledger_holders(needed: u64, holders: String) {
    if let Ok(mut described) = STEP_HOLDERS.lock()
        && needed > described.0
    {
        *described = (needed, holders.clone());
    }
    if let Ok(mut described) = LEDGER_HOLDERS.lock()
        && needed > described.0
        && needed >= LEDGER_NEEDED_PEAK.load(Relaxed)
    {
        *described = (needed, holders);
    }
}

/// What the ledger holds and needs at this moment.
static LEDGER_NOW: (AtomicU64, AtomicU64) = (AtomicU64::new(0), AtomicU64::new(0));

/// What holds the run's memory so far, for a run that is ended from
/// outside and never reaches [`finish`]: written with the interim profile.
pub fn interim_memory() {
    let peak = LEDGER_PEAK.load(Relaxed);
    if peak == 0 {
        return;
    }
    let step = STEP_HOLDERS
        .lock()
        .map(|holders| format!("{} MiB: {}", holders.0 >> 20, holders.1))
        .unwrap_or_default();
    eprintln!(
        "memory-so-far: reservations peaked at {} MiB with {} MiB set aside at the start; needed at most {} MiB; in this step {}; {} caches given up",
        peak >> 20,
        LEDGER_LIMIT.load(Relaxed) >> 20,
        LEDGER_NEEDED_PEAK.load(Relaxed) >> 20,
        step,
        crate::evict::times_given_up()
    );
    eprintln!(
        "memory-now: reservations hold {} MiB, of which {} MiB are needed",
        LEDGER_NOW.0.load(Relaxed) >> 20,
        LEDGER_NOW.1.load(Relaxed) >> 20
    );
}

/// The process's own peaks, as Windows counts them: working set and private
/// (committed) memory, in bytes. What a user compares with their machine.
fn process_peaks() -> Option<(u64, u64)> {
    use windows_sys::Win32::System::{
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::GetCurrentProcess,
    };
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: the pseudo-handle of this process and an initialized structure
    // whose size is given in `cb`.
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
    (ok != 0).then_some((
        counters.PeakWorkingSetSize as u64,
        counters.PeakPagefileUsage as u64,
    ))
}

/// The summary of a run's memory (#167). What the run set aside at its start
/// is a ceiling only under `--memory-limit`; a run that fits itself to the
/// machine may hold more while memory is free, so it is called a starting
/// share there, and the caches (what the reservations held beyond what the
/// run could not do without) are named as what it gives back.
fn memory_line(
    limit: u64,
    peak: u64,
    needed: u64,
    fits_the_machine: bool,
    process: Option<(u64, u64)>,
) -> String {
    let set_aside = if fits_the_machine {
        "a starting share: the run fits itself to the machine and may hold more while memory is free"
    } else {
        "its ceiling"
    };
    let mut line = format!(
        "memory: the run set aside {} MiB at its start ({set_aside}); its reservations peaked at {} MiB, of which {} MiB it could not do without and the rest caches it gives back when memory is short",
        limit >> 20,
        peak >> 20,
        needed.min(peak) >> 20
    );
    if let Some((working_set, private)) = process {
        line.push_str(&format!(
            "; the process itself peaked at {} MiB of working set and {} MiB of private memory",
            working_set >> 20,
            private >> 20
        ));
    }
    line
}

/// Prints the last phase and the totals. Safe to call more than once.
pub fn finish() {
    crate::stack_sampler::finish();
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
        finish_steps(&previous.name);
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
        let peak = LEDGER_PEAK.load(Relaxed);
        if peak != 0 {
            eprintln!(
                "{}",
                memory_line(
                    LEDGER_LIMIT.load(Relaxed),
                    peak,
                    LEDGER_NEEDED_PEAK.load(Relaxed),
                    crate::resource_native::memory_fits_the_machine(),
                    process_peaks()
                )
            );
            let beyond = BEYOND_BUDGET.load(Relaxed);
            if beyond != 0 {
                eprintln!(
                    "memory-beyond: the run went on with {} MiB beyond what it set aside, which Windows could still give from the page file",
                    beyond >> 20
                );
            }
            if let Ok(holders) = LEDGER_HOLDERS.lock()
                && !holders.1.is_empty()
            {
                eprintln!(
                    "memory-held: with {} MiB needed, the largest reservations were {}",
                    holders.0 >> 20,
                    holders.1
                );
            }
            let given_up = crate::evict::times_given_up();
            if given_up != 0 {
                eprintln!(
                    "memory-caches: memory was short, and the run gave up {given_up} of the caches it holds only to go faster, those used longest ago first"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fitted run's set-aside share is not called a ceiling, and the line
    /// says what of the peak were caches and what the process took (#167).
    #[test]
    fn the_memory_line_does_not_read_as_an_overrun() {
        let fitted = memory_line(
            6148 << 20,
            16589 << 20,
            3149 << 20,
            true,
            Some((739 << 20, 900 << 20)),
        );
        assert!(
            fitted.contains("set aside 6148 MiB at its start (a starting share"),
            "{fitted}"
        );
        assert!(
            fitted.contains("peaked at 16589 MiB, of which 3149 MiB it could not do without"),
            "{fitted}"
        );
        assert!(
            fitted.contains("739 MiB of working set and 900 MiB of private memory"),
            "{fitted}"
        );
        assert!(!fitted.contains("may hold;"), "{fitted}");
        let limited = memory_line(1240 << 20, 1000 << 20, 664 << 20, false, None);
        assert!(
            limited.contains("(its ceiling)") && !limited.contains("process itself"),
            "{limited}"
        );
    }

    /// What holds a ledger's memory is written down as what the run needs
    /// grows, a sixty-fourth of the limit at a time, and not at every
    /// reservation.
    #[test]
    fn the_holders_of_a_ledger_are_described_a_sixty_fourth_at_a_time() {
        const LIMIT: u64 = 64 << 20;
        assert!(!holders_due((1 << 20) - 1, 0, LIMIT));
        assert!(holders_due(1 << 20, 0, LIMIT), "the first sixty-fourth");
        assert!(!holders_due((2 << 20) - 1, 1 << 20, LIMIT));
        assert!(holders_due(2 << 20, 1 << 20, LIMIT));
        // A ledger smaller than sixty-four bytes still moves on.
        assert!(holders_due(1, 0, 10) && !holders_due(1, 1, 10));
        // Nothing was written down yet and the holders cannot be read.
        assert!(!holders_due(u64::MAX, u64::MAX, LIMIT));
    }

    #[test]
    fn a_step_is_filed_with_the_most_it_could_not_do_without() {
        let mut memory = Vec::new();
        file_step_memory(&mut memory, "walk", 300, "300 at a".into());
        file_step_memory(&mut memory, "place", 0, String::new());
        file_step_memory(&mut memory, "apply", 100, "100 at b".into());
        // A step that runs again keeps its highest level and what held it.
        file_step_memory(&mut memory, "walk", 200, "200 at c".into());
        file_step_memory(&mut memory, "apply", 500, "500 at d".into());
        assert_eq!(
            memory,
            [
                ("walk", 300, "300 at a".to_owned()),
                ("apply", 500, "500 at d".to_owned())
            ]
        );
    }

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
        assert!(
            text.contains("journal read-back") && text.contains("x1 3.00 GB"),
            "{text}"
        );
        assert!(!text.contains("freeze check"), "{text}");
    }

    #[test]
    fn a_point_with_bytes_and_no_calls_is_still_reported() {
        // "device bytes served" is only ever added to, never timed.
        let before = snapshot();
        add_bytes(Point::DeviceReadServed, 1 << 30);
        let text = line("example", 1.0, &before, &snapshot());
        assert!(
            text.contains("device bytes served 0.0s x0 1.00 GB"),
            "{text}"
        );
    }
}
