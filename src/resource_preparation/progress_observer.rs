//! Throttled diagnostic output. No paths, metadata objects, or evidence frames
//! are retained here; stdout may be captured by the caller's normal log owner.
use n2r_win32::progress::{Reporter, Sink, Update};
use serde::Serialize;
use std::{io::{self, Write}, sync::{Arc, Mutex}, time::{Duration, Instant}};

const INTERVAL: Duration = Duration::from_secs(2);

struct State {
    started: Instant,
    phase_started: Instant,
    last_emitted: Instant,
    last_emitted_update: Option<Update>,
    latest: Option<Update>,
    recent_rate: Option<f64>,
    received: u64,
    emitted: u64,
    invalid: u64,
    output_errors: u64,
}
pub(super) struct ConsoleProgress { state: Mutex<State> }

#[derive(Serialize)]
struct Display {
    kind: &'static str,
    progress: Update,
    label: &'static str,
    elapsed_ms: u128,
    phase_elapsed_ms: u128,
    estimated_remaining_seconds: Option<u64>,
    estimate_basis: &'static str,
    grants_recovery_or_write_authority: bool,
}
fn same_pass(a: Update, b: Update) -> bool {
    a.phase == b.phase && a.pass == b.pass && a.unit == b.unit && a.total == b.total
}
impl ConsoleProgress {
    pub(super) fn new() -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self { state: Mutex::new(State { started: now, phase_started: now,
            last_emitted: now, last_emitted_update: None, latest: None, recent_rate: None,
            received: 0, emitted: 0, invalid: 0, output_errors: 0 }) })
    }
    pub(super) fn reporter(self: &Arc<Self>) -> Reporter { Reporter::new(self.clone()) }
    fn emit(state: &mut State, update: Update, now: Instant, changed: bool) {
        if changed { state.phase_started = now; state.recent_rate = None; }
        let interval = now.duration_since(state.last_emitted).as_secs_f64();
        if let Some(old) = state.last_emitted_update.filter(|old| same_pass(*old, update)) {
            if interval >= INTERVAL.as_secs_f64() && update.completed > old.completed {
                let current = (update.completed - old.completed) as f64 / interval;
                state.recent_rate = Some(state.recent_rate.map_or(current, |rate| rate * 0.75 + current * 0.25));
            } else if interval >= INTERVAL.as_secs_f64() && update.completed == old.completed {
                state.recent_rate = None;
            }
        }
        let eta = update.total.and_then(|total| {
            if total == update.completed { return Some(0); }
            state.recent_rate.filter(|rate| rate.is_finite() && *rate > 0.0)
                .map(|rate| ((total - update.completed) as f64 / rate).ceil() as u64)
        });
        let display = Display { kind: "conversion-progress-v1", progress: update,
            label: update.phase.label(), elapsed_ms: now.duration_since(state.started).as_millis(),
            phase_elapsed_ms: now.duration_since(state.phase_started).as_millis(),
            estimated_remaining_seconds: eta, estimate_basis: "same-phase-pass-observed-throughput",
            grants_recovery_or_write_authority: false };
        let mut out = io::stdout().lock();
        // No explicit flush/sync or evidence-ledger append per progress row.
        if serde_json::to_writer(&mut out, &display).map_err(io::Error::other)
            .and_then(|_| out.write_all(b"\n")).is_err() {
            state.output_errors = state.output_errors.saturating_add(1);
        }
        state.last_emitted = now;
        state.last_emitted_update = Some(update);
        state.emitted = state.emitted.saturating_add(1);
    }
    pub(super) fn summary(&self) -> serde_json::Value {
        let Ok(mut state) = self.state.lock() else {
            return serde_json::json!({"kind":"conversion-progress-summary-v1","available":false,
                "grants_recovery_or_write_authority":false});
        };
        if let Some(latest) = state.latest.filter(|latest| Some(*latest) != state.last_emitted_update) {
            Self::emit(&mut state, latest, Instant::now(), false);
        }
        serde_json::json!({"kind":"conversion-progress-summary-v1","latest":state.latest,
            "updates_received":state.received,"rows_emitted":state.emitted,
            "invalid_updates_omitted":state.invalid,"output_errors":state.output_errors,
            "minimum_interval_ms":INTERVAL.as_millis(),"phase_and_completion_transitions_immediate":true,
            "grants_recovery_or_write_authority":false})
    }
}
impl Sink for ConsoleProgress {
    fn report(&self, update: Update) {
        let Ok(mut state) = self.state.lock() else { return; };
        state.received = state.received.saturating_add(1);
        if !update.valid() {
            state.invalid = state.invalid.saturating_add(1);
            return;
        }
        let changed = state.latest.is_none_or(|last| !same_pass(last, update));
        if !changed && state.latest.is_some_and(|last| update.completed < last.completed) {
            state.invalid = state.invalid.saturating_add(1);
            return;
        }
        let completed_now = update.total == Some(update.completed)
            && state.latest.is_none_or(|last| last.total != Some(last.completed) || !same_pass(last, update));
        state.latest = Some(update);
        let now = Instant::now();
        if changed || completed_now || now.duration_since(state.last_emitted) >= INTERVAL {
            Self::emit(&mut state, update, now, changed);
        }
    }
}
