//! Bounded diagnostic progress. It grants no admission or write authority and
//! is deliberately outside the comparison report and durable journal format.
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
    time::{Duration, Instant},
};

const INTERVAL: Duration = Duration::from_secs(1);
const MAX_SNAPSHOT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Subphase {
    Comparing,
    RecheckingSource,
    RecheckingShadow,
    WritingJournal,
    VerifyingJournal,
    Complete,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Progress {
    pub schema_version: u32,
    pub kind: &'static str,
    pub subphase: Subphase,
    /// Combined source/shadow bytes read in comparison and both rechecks only.
    /// Excludes journal payload copying, validation and other conversion reads.
    pub bytes_scanned: u64,
    pub total_scan_bytes: u64,
    pub elapsed_ms: u64,
    pub execution_authorized: bool,
}

pub(crate) struct Reporter<'a> {
    length: u64,
    started: Instant,
    last: Option<(Subphase, u64, Duration)>,
    sink: &'a mut dyn FnMut(Progress),
}

impl<'a> Reporter<'a> {
    pub(crate) fn new(length: u64, sink: &'a mut dyn FnMut(Progress)) -> Self {
        Self {
            length,
            started: Instant::now(),
            last: None,
            sink,
        }
    }

    pub(crate) fn update(&mut self, subphase: Subphase, scanned: u64) {
        self.update_at(subphase, scanned, self.started.elapsed());
    }

    fn update_at(&mut self, subphase: Subphase, scanned: u64, elapsed: Duration) {
        let (base, limit) = match subphase {
            Subphase::Comparing => (0, self.length.saturating_mul(2)),
            Subphase::RecheckingSource => (self.length.saturating_mul(2), self.length),
            Subphase::RecheckingShadow => (self.length.saturating_mul(3), self.length),
            _ => (self.length.saturating_mul(4), 0),
        };
        let bytes = base.saturating_add(scanned.min(limit));
        let emit = self.last.is_none_or(|(phase, previous, when)| {
            phase != subphase
                || elapsed.saturating_sub(when) >= INTERVAL
                || (limit != 0 && scanned >= limit && bytes != previous)
        });
        if emit {
            (self.sink)(Progress {
                schema_version: 1,
                kind: "journal-preparation-progress",
                subphase,
                bytes_scanned: bytes,
                total_scan_bytes: self.length.saturating_mul(4),
                elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                execution_authorized: false,
            });
            self.last = Some((subphase, bytes, elapsed));
        }
    }
}

/// Best-effort mutable sidecar in the existing fresh artifact directory.
/// Telemetry failures never hide a source/journal error or change its outcome.
/// A reader may observe a partial rewrite and must ignore that snapshot.
pub(crate) struct SnapshotFile {
    file: Option<File>,
}

impl SnapshotFile {
    pub(crate) fn create(path: &Path) -> Self {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(3);
        }
        match options.open(path) {
            Ok(file) => Self { file: Some(file) },
            Err(error) => {
                Self::warn(&error);
                Self { file: None }
            }
        }
    }

    fn warn(error: &dyn std::fmt::Display) {
        let _ = writeln!(std::io::stderr(), "journal progress unavailable: {error}");
    }

    pub(crate) fn report(&mut self, progress: Progress) {
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let result = (|| -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&progress).map_err(std::io::Error::other)?;
            if bytes.len() > MAX_SNAPSHOT_BYTES {
                return Err(std::io::Error::other("progress snapshot exceeds bound"));
            }
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&bytes)?;
            file.set_len(bytes.len() as u64)?;
            file.flush()
        })();
        if let Err(error) = result {
            Self::warn(&error);
            self.file = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_are_rate_limited_except_boundaries_and_never_grant_authority() {
        let mut events = Vec::new();
        {
            let mut sink = |p| events.push(p);
            let mut reporter = Reporter::new(10000, &mut sink);
            reporter.update_at(Subphase::Comparing, 0, Duration::ZERO);
            for i in 1..1000 {
                reporter.update_at(Subphase::Comparing, i, Duration::from_micros(i));
            }
            reporter.update_at(Subphase::Comparing, 12000, Duration::from_secs(1));
            reporter.update_at(Subphase::Comparing, 20000, Duration::from_millis(1001));
            reporter.update_at(Subphase::Comparing, 20000, Duration::from_millis(1002));
            reporter.update_at(Subphase::RecheckingSource, 0, Duration::from_millis(1003));
            reporter.update_at(
                Subphase::RecheckingSource,
                10000,
                Duration::from_millis(1004),
            );
            reporter.update_at(Subphase::RecheckingShadow, 0, Duration::from_millis(1005));
            reporter.update_at(
                Subphase::RecheckingShadow,
                10000,
                Duration::from_millis(1006),
            );
            reporter.update_at(Subphase::WritingJournal, 0, Duration::from_millis(1007));
            reporter.update_at(Subphase::VerifyingJournal, 0, Duration::from_millis(1008));
            reporter.update_at(Subphase::Complete, 0, Duration::from_millis(1009));
        }
        assert_eq!(events.len(), 10);
        assert_eq!(events[0].bytes_scanned, 0);
        assert_eq!(events.last().unwrap().bytes_scanned, 40000);
        assert!(
            events
                .windows(2)
                .all(|p| p[0].bytes_scanned <= p[1].bytes_scanned)
        );
        assert!(
            events
                .iter()
                .all(|p| !p.execution_authorized && p.total_scan_bytes == 40000)
        );
    }

    #[test]
    fn sidecar_is_bounded_and_an_existing_file_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal-progress.json");
        let mut file = SnapshotFile::create(&path);
        let mut sink = |p| file.report(p);
        let mut reporter = Reporter::new(128 * 1024 * 1024 * 1024, &mut sink);
        reporter.update(Subphase::Comparing, 0);
        reporter.update(Subphase::Complete, 0);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() <= MAX_SNAPSHOT_BYTES);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["subphase"], "complete");
        assert_eq!(value["bytes_scanned"], 512_u64 * 1024 * 1024 * 1024);
        let mut collision = SnapshotFile::create(&path);
        collision.report(Progress {
            schema_version: 1,
            kind: "ignored",
            subphase: Subphase::Comparing,
            bytes_scanned: 0,
            total_scan_bytes: 0,
            elapsed_ms: 0,
            execution_authorized: false,
        });
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
