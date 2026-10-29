//! Bounded logical reads. No digest is returned for partial or unbounded data.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom};
pub const DEFAULT_LIMIT: u64 = 1024 * 1024 * 1024;
// 1 MiB logical requests: the same bytes and digest as smaller requests, with
// far fewer calls on large streams. Call budgets are derived from this size.
pub(crate) const CHUNK: usize = 1024 * 1024;
const MAX_CALLS: u64 = 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
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
    fn reserve(&mut self, expected: u64) -> bool {
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
pub fn read<R: Read + Seek>(reader: &mut R, expected: u64, budget: &mut Budget) -> Outcome {
    let mut out = Outcome {
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
    let mut digest = Sha256::new();
    let mut buffer = vec![0; CHUNK];
    let mut calls = 0;
    let mut interrupted = 0;
    loop {
        if calls == budget.maximum_stream_read_calls
            || budget.audit.read_calls == budget.maximum_read_calls
        {
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
            out.sha256 = Some(hex::encode(digest.finalize()));
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
