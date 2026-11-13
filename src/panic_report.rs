//! What a worker thread's panic said and where.
//!
//! The conversion runs on worker threads. When one panicked, the error that
//! reached the user said only that it had: the message and the source line
//! went to standard error through the default hook and nowhere else. An
//! overflow in offset arithmetic or a failed internal lookup then read as
//! "drive worker panicked", with nothing to act on.
//!
//! [`install`] keeps the default output and also remembers, per thread name,
//! what the last panic on that thread said and where. [`worker_error`] turns
//! the result of joining a panicked worker into an error that carries it.
use std::any::Any;
use std::sync::{Mutex, Once};

static INSTALL: Once = Once::new();
/// Thread name and the report of the last panic on a thread of that name.
static LAST: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

fn payload_text(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic that carried no message".to_owned())
}

/// Control characters would let a message rewrite the console line.
fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Chains onto the current panic hook once for the process. The previous
/// hook still runs, so standard error shows what it always showed.
pub(crate) fn install() {
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let name = std::thread::current()
                .name()
                .unwrap_or("<unnamed thread>")
                .to_owned();
            let message = payload_text(info.payload());
            let report = match info.location() {
                Some(location) => {
                    format!("{message} (at {}:{})", location.file(), location.line())
                }
                None => message,
            };
            if let Ok(mut last) = LAST.lock() {
                last.retain(|(known, _)| *known != name);
                last.push((name, report));
            }
            previous(info);
        }));
    });
}

fn take(thread: &str) -> Option<String> {
    let mut last = LAST.lock().ok()?;
    let position = last.iter().position(|(known, _)| known == thread)?;
    Some(last.swap_remove(position).1)
}

/// The error for a worker that panicked: which worker, what the panic said,
/// where in the source it was raised, and what to do about the run.
pub(crate) fn worker_error(
    thread: &str,
    payload: Box<dyn Any + Send>,
    advice: &str,
) -> anyhow::Error {
    let detail = take(thread).unwrap_or_else(|| payload_text(payload.as_ref()));
    anyhow::anyhow!("{thread} worker panicked: {}; {advice}", clean(&detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join_panicking(name: &str, body: impl FnOnce() + Send + 'static) -> String {
        install();
        let payload = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(body)
            .unwrap()
            .join()
            .unwrap_err();
        worker_error(name, payload, "preserve its recovery records").to_string()
    }

    #[test]
    fn an_arithmetic_overflow_in_a_worker_is_reported_with_its_source_line() {
        let text = join_panicking("panic-report-overflow", || {
            let clusters = std::hint::black_box(u64::MAX);
            let _ = std::hint::black_box(clusters.checked_mul(4096).expect("cluster offset"));
        });
        assert!(
            text.starts_with("panic-report-overflow worker panicked: cluster offset"),
            "{text}"
        );
        assert!(text.contains("panic_report.rs:"), "{text}");
        assert!(text.ends_with("; preserve its recovery records"), "{text}");
    }

    #[test]
    fn a_formatted_message_is_kept_and_control_characters_are_not() {
        let text = join_panicking("panic-report-message", || {
            panic!("no handle is held for object {}\r\nrewritten", 41)
        });
        assert!(
            text.contains("no handle is held for object 41  rewritten"),
            "{text}"
        );
        assert!(!text.contains('\r') && !text.contains('\n'), "{text}");
    }

    #[test]
    fn a_report_is_consumed_and_belongs_to_its_own_thread() {
        let first = join_panicking("panic-report-first", || panic!("first"));
        assert!(first.contains(": first (at "), "{first}");
        assert!(take("panic-report-first").is_none());
        // Without a recorded report the payload itself still names the cause.
        let fallback = worker_error("never-ran", Box::new("only the payload"), "retry");
        assert_eq!(
            fallback.to_string(),
            "never-ran worker panicked: only the payload; retry"
        );
    }
}
