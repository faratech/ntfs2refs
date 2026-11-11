//! Small diagnostic progress values. They cannot certify completion, recreate
//! an owner, authorize writes, or participate in recovery decisions.
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    SourceEvidence,
    ExpectedPreparation,
    ShadowAllocation,
    Placement,
    PayloadSupply,
    PayloadVerification,
    AliasValidation,
    AliasCreation,
    MetadataRestoration,
    TargetCapture,
    RecoveryJournal,
    Apply,
    Handoff,
    Finalization,
}
impl Phase {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SourceEvidence => "Inspecting NTFS",
            Self::ExpectedPreparation => "Preparing expected metadata",
            Self::ShadowAllocation => "Creating private ReFS objects",
            Self::Placement => "Placing ReFS extents",
            Self::PayloadSupply => "Supplying ReFS payloads",
            Self::PayloadVerification => "Verifying ReFS payloads",
            Self::AliasValidation => "Validating Windows aliases",
            Self::AliasCreation => "Creating Windows aliases",
            Self::MetadataRestoration => "Restoring ReFS metadata",
            Self::TargetCapture => "Capturing target layout",
            Self::RecoveryJournal => "Preparing recovery records",
            Self::Apply => "Applying conversion",
            Self::Handoff => "Recording verified handoff",
            Self::Finalization => "Verifying completed conversion",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Objects,
    Aliases,
    Streams,
    Bytes,
    Operations,
}

/// Counters are scoped to the current phase/pass. Zero does not establish
/// that an uninstrumented layer did no I/O. Process I/O is intentionally absent.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub logical_source_bytes_read: Option<u64>,
    pub payload_bytes_written: Option<u64>,
    pub objects_decoded: Option<u64>,
    pub metadata_pages_loaded: Option<u64>,
    pub metadata_cache_hits: Option<u64>,
    pub authenticated_bytes_hashed: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Update {
    pub phase: Phase,
    pub pass: u32,
    pub unit: Unit,
    pub completed: u64,
    pub total: Option<u64>,
    pub counters: Counters,
}
impl Update {
    pub const fn new(phase: Phase, unit: Unit, completed: u64, total: Option<u64>) -> Self {
        Self {
            phase,
            pass: 0,
            unit,
            completed,
            total,
            counters: Counters {
                logical_source_bytes_read: None,
                payload_bytes_written: None,
                objects_decoded: None,
                metadata_pages_loaded: None,
                metadata_cache_hits: None,
                authenticated_bytes_hashed: None,
            },
        }
    }
    pub const fn with_pass(mut self, pass: u32) -> Self {
        self.pass = pass;
        self
    }
    pub const fn with_counters(mut self, counters: Counters) -> Self {
        self.counters = counters;
        self
    }
    pub fn valid(self) -> bool {
        self.total.is_none_or(|total| self.completed <= total)
    }
}

/// Diagnostic sinks cannot fail conversion. Their own error/omission counts
/// belong in telemetry, never in an execution or recovery guard.
pub trait Sink: Send + Sync {
    fn report(&self, update: Update);
}

#[derive(Clone, Default)]
pub struct Reporter(Option<Arc<dyn Sink>>);
impl Reporter {
    pub fn new(sink: Arc<dyn Sink>) -> Self {
        Self(Some(sink))
    }
    pub fn report(&self, update: Update) {
        if let Some(sink) = &self.0 {
            sink.report(update);
        }
    }
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }
}
