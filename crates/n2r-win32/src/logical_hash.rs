//! Bounded logical reads. No digest is returned for partial or unbounded data.
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Seek, SeekFrom};
pub const DEFAULT_LIMIT: u64 = 1024 * 1024 * 1024;
// 4 MiB logical requests: the same bytes and digest as smaller requests, with
// far fewer calls on large streams (the lab disk read 4 MiB requests about 1.5x
// faster than 1 MiB). Call budgets are derived from this size.
pub(crate) const CHUNK: usize = 4 * 1024 * 1024;
const MAX_CALLS: u64 = 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    /// No content or EOF probe was read. Identity, EOF metadata and the full
    /// physical map are separate evidence; this outcome contains no digest.
    NotReadExtentIdentityV1,
    /// A run that verifies once did not read this stream's contents through
    /// Windows: the raw reading names it a plain stream (one non-resident,
    /// uncompressed, unsparse DATA attribute, initialized to its end, every
    /// run on disk), so its raw digest is a straight read of the clusters
    /// its run list names, and those runs are held to Windows' retrieval
    /// pointers. Identity and EOF are still queried through an open read
    /// handle, and through it Windows answered that the stream's valid data
    /// runs to its end (`StreamHash::valid_data`); a stream it does not say
    /// that of is read instead. This outcome contains no digest, EOF probe or
    /// read byte.
    NotReadPlainRunsV1,
    BudgetExceeded,
    ReadRefused,
    UnexpectedEof,
    ExpectedEofMissing,
    CallBudgetExceeded,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub bytes_read: u64,
    pub eof_confirmed: bool,
    pub sha256: Option<String>,
    pub native_error: Option<i32>,
    pub detail: Option<String>,
}
impl Outcome {
    pub fn refused(error: io::Error) -> Self {
        Self {
            status: Status::ReadRefused,
            bytes_read: 0,
            eof_confirmed: false,
            sha256: None,
            native_error: error.raw_os_error(),
            detail: Some(error.to_string()),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Audit {
    pub limit_bytes: u64,
    pub reserved_bytes: u64,
    pub bytes_read: u64,
    pub read_calls: u64,
    pub eof_probes: u64,
}
pub struct Budget {
    audit: Audit,
    maximum_stream_bytes: u64,
    maximum_read_calls: u64,
    maximum_stream_read_calls: u64,
    /// Whether a read was refused for a limit: a reservation or a call that
    /// did not fit. See [`Budget::absorb`].
    refused: bool,
}
impl Budget {
    pub fn new(limit_bytes: u64) -> Self {
        Self {
            audit: Audit {
                limit_bytes,
                reserved_bytes: 0,
                bytes_read: 0,
                read_calls: 0,
                eof_probes: 0,
            },
            maximum_stream_bytes: u64::MAX,
            maximum_read_calls: u64::MAX,
            maximum_stream_read_calls: MAX_CALLS,
            refused: false,
        }
    }
    /// Explicit collection envelope. The byte reservation includes each EOF
    /// probe, and calls are cumulative across every stream and both passes.
    pub fn with_limits(
        limit_bytes: u64,
        maximum_stream_bytes: u64,
        maximum_read_calls: u64,
    ) -> io::Result<Self> {
        if limit_bytes == 0 || maximum_stream_bytes > limit_bytes || maximum_read_calls == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid logical-read limits",
            ));
        }
        let mut budget = Self::new(limit_bytes);
        budget.maximum_stream_bytes = maximum_stream_bytes;
        budget.maximum_read_calls = maximum_read_calls;
        budget.maximum_stream_read_calls = maximum_stream_bytes
            .div_ceil(CHUNK as u64)
            .saturating_mul(2)
            .saturating_add(9)
            .max(MAX_CALLS)
            .min(maximum_read_calls);
        Ok(budget)
    }
    pub fn audit(&self) -> Audit {
        self.audit.clone()
    }
    /// Whether the run's totals are unbounded: no read can be refused for
    /// what other objects read before it, only for its own stream's limits.
    pub(crate) fn is_unbounded(&self) -> bool {
        self.audit.limit_bytes == u64::MAX && self.maximum_read_calls == u64::MAX
    }
    /// A budget with the same limits and nothing read yet: what one object
    /// is read with on a helper thread, before it is known what the objects
    /// ahead of it read.
    pub(crate) fn fresh(&self) -> Self {
        Self {
            audit: Audit {
                limit_bytes: self.audit.limit_bytes,
                reserved_bytes: 0,
                bytes_read: 0,
                read_calls: 0,
                eof_probes: 0,
            },
            maximum_stream_bytes: self.maximum_stream_bytes,
            maximum_read_calls: self.maximum_read_calls,
            maximum_stream_read_calls: self.maximum_stream_read_calls,
            refused: false,
        }
    }
    /// Adds what `object` (a [`Self::fresh`] budget of this one) read, if
    /// reading it after everything this budget has read would have read the
    /// same: no read of it was refused, and the totals fit, so that every
    /// reservation and call it made fits here as well. Otherwise nothing is
    /// added, and the object is read again against this budget.
    pub(crate) fn absorb(&mut self, object: &Self) -> bool {
        if object.refused
            || object.audit.limit_bytes != self.audit.limit_bytes
            || object.maximum_stream_bytes != self.maximum_stream_bytes
            || object.maximum_read_calls != self.maximum_read_calls
            || object.maximum_stream_read_calls != self.maximum_stream_read_calls
        {
            return false;
        }
        let total = |a: u64, b: u64| a.checked_add(b);
        let (Some(reserved), Some(bytes_read), Some(read_calls), Some(eof_probes)) = (
            total(self.audit.reserved_bytes, object.audit.reserved_bytes),
            total(self.audit.bytes_read, object.audit.bytes_read),
            total(self.audit.read_calls, object.audit.read_calls),
            total(self.audit.eof_probes, object.audit.eof_probes),
        ) else {
            return false;
        };
        if reserved > self.audit.limit_bytes || read_calls > self.maximum_read_calls {
            return false;
        }
        self.audit.reserved_bytes = reserved;
        self.audit.bytes_read = bytes_read;
        self.audit.read_calls = read_calls;
        self.audit.eof_probes = eof_probes;
        true
    }
    fn reserve(&mut self, expected: u64) -> bool {
        let granted = self.try_reserve(expected);
        if !granted {
            self.refused = true;
        }
        granted
    }
    fn try_reserve(&mut self, expected: u64) -> bool {
        if expected > self.maximum_stream_bytes {
            return false;
        }
        let Some(n) = expected
            .checked_add(1)
            .and_then(|n| self.audit.reserved_bytes.checked_add(n))
        else {
            return false;
        };
        if n > self.audit.limit_bytes {
            return false;
        }
        self.audit.reserved_bytes = n;
        true
    }
}
/// Read exactly `expected` bytes then confirm EOF; `Outcome::sha256` carries
/// the stream's [`crate::content_digest`] (historical field name).
pub fn read<R: Read + Seek>(reader: &mut R, expected: u64, budget: &mut Budget) -> Outcome {
    let _timed = crate::perf::scope(crate::perf::Point::ContentRead);
    crate::perf::add_bytes(crate::perf::Point::ContentRead, expected);
    let out = Outcome {
        status: Status::BudgetExceeded,
        bytes_read: 0,
        eof_confirmed: false,
        sha256: None,
        native_error: None,
        detail: None,
    };
    if !budget.reserve(expected) {
        return out;
    }
    match reader.seek(SeekFrom::Start(0)) {
        Ok(0) => {}
        Ok(_) => return Outcome::refused(io::Error::other("stream did not seek to zero")),
        Err(e) => return Outcome::refused(e),
    }
    // The thread's own buffer, no larger than the stream: a fresh, zeroed
    // 4 MiB allocation for each of a hundred thousand small streams is what
    // `query_scratch` exists to avoid.
    let capacity = usize::try_from(expected.min(CHUNK as u64))
        .unwrap_or(CHUNK)
        .max(1);
    #[cfg(windows)]
    {
        crate::query_scratch::with(capacity, |buffer| {
            read_chunks(reader, expected, budget, out, buffer)
        })
    }
    #[cfg(not(windows))]
    {
        read_chunks(reader, expected, budget, out, &mut vec![0; capacity])
    }
}

/// The reads of [`read`]: up to `CHUNK` bytes at a time into `buffer`, which
/// holds at least `min(expected, CHUNK)` bytes and at least one, then a
/// one-byte probe that must find the end of the stream.
fn read_chunks<R: Read>(
    reader: &mut R,
    expected: u64,
    budget: &mut Budget,
    mut out: Outcome,
    buffer: &mut [u8],
) -> Outcome {
    let mut digest = crate::content_digest::Hasher::new();
    let mut calls = 0;
    let mut interrupted = 0;
    loop {
        if calls == budget.maximum_stream_read_calls
            || budget.audit.read_calls == budget.maximum_read_calls
        {
            budget.refused = true;
            out.status = Status::CallBudgetExceeded;
            return out;
        }
        calls += 1;
        budget.audit.read_calls += 1;
        let remaining = expected - out.bytes_read;
        let probe = remaining == 0;
        let request = if probe {
            1
        } else {
            remaining.min(CHUNK as u64) as usize
        };
        if probe {
            budget.audit.eof_probes += 1;
        }
        let n = match reader.read(&mut buffer[..request]) {
            Ok(n) if n <= request => {
                interrupted = 0;
                n
            }
            Ok(_) => {
                out.status = Status::ReadRefused;
                out.detail = Some("reader exceeded requested length".into());
                return out;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted < 8 => {
                interrupted += 1;
                continue;
            }
            Err(e) => {
                out.status = Status::ReadRefused;
                out.native_error = e.raw_os_error();
                out.detail = Some(e.to_string());
                return out;
            }
        };
        budget.audit.bytes_read += n as u64;
        if probe {
            if n != 0 {
                out.status = Status::ExpectedEofMissing;
                out.bytes_read += n as u64;
                return out;
            }
            out.status = Status::Complete;
            out.eof_confirmed = true;
            out.sha256 = Some(digest.finish());
            return out;
        }
        if n == 0 {
            out.status = Status::UnexpectedEof;
            return out;
        }
        digest.update(&buffer[..n]);
        out.bytes_read += n as u64;
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    fn stream(length: usize) -> io::Cursor<Vec<u8>> {
        io::Cursor::new((0..length).map(|byte| byte as u8).collect())
    }

    /// Objects read with fresh budgets and added in order end with the
    /// audit and outcomes of reading them one after another with one.
    #[test]
    fn objects_read_apart_and_absorbed_in_order_audit_as_one_budget() {
        let lengths = [0usize, 1, 4096, CHUNK + 7, 3];
        let mut one = Budget::with_limits(u64::MAX, i64::MAX as u64, u64::MAX).unwrap();
        let alone: Vec<Outcome> = lengths
            .iter()
            .map(|&n| read(&mut stream(n), n as u64, &mut one))
            .collect();
        let mut run = Budget::with_limits(u64::MAX, i64::MAX as u64, u64::MAX).unwrap();
        assert!(run.is_unbounded());
        let mut apart = Vec::new();
        for &n in &lengths {
            let mut object = run.fresh();
            apart.push(read(&mut stream(n), n as u64, &mut object));
            assert!(run.absorb(&object));
        }
        assert_eq!(apart, alone);
        let (a, b) = (one.audit(), run.audit());
        assert_eq!(
            (a.reserved_bytes, a.bytes_read, a.read_calls, a.eof_probes),
            (b.reserved_bytes, b.bytes_read, b.read_calls, b.eof_probes)
        );
    }

    /// An object that would not have fit after the ones before it, or whose
    /// own read was refused, is not added: it is read again in its turn.
    #[test]
    fn an_object_that_would_not_have_fit_is_not_absorbed() {
        let mut run = Budget::with_limits(100, 100, 1000).unwrap();
        assert!(!run.is_unbounded());
        let mut first = run.fresh();
        assert_eq!(
            read(&mut stream(60), 60, &mut first).status,
            Status::Complete
        );
        assert!(run.absorb(&first));
        // Alone it fits; after the first it does not.
        let mut second = run.fresh();
        assert_eq!(
            read(&mut stream(50), 50, &mut second).status,
            Status::Complete
        );
        let before = run.audit();
        assert!(!run.absorb(&second));
        assert_eq!(run.audit().reserved_bytes, before.reserved_bytes);
        assert_eq!(run.audit().read_calls, before.read_calls);
        // Read in its turn, it is what one budget says of it.
        assert_eq!(
            read(&mut stream(50), 50, &mut run).status,
            Status::BudgetExceeded
        );
        // A refusal of its own is never absorbed, even with room to spare.
        let mut room = Budget::with_limits(100, 10, 1000).unwrap();
        let mut refused = room.fresh();
        assert_eq!(
            read(&mut stream(20), 20, &mut refused).status,
            Status::BudgetExceeded
        );
        assert!(!room.absorb(&refused));
        // Neither is a budget with other limits.
        let other = Budget::with_limits(200, 100, 1000).unwrap().fresh();
        assert!(!room.absorb(&other));
    }
}
