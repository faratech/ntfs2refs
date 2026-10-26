//! Actual-protocol ABT publication faults over memory only. Writes are
//! immediately visible; sync_all records calls, not physical persistence.
//! This is not a stable/volatile crash model or a native interruption test.
use ntfs2refs::{
    lab_reconstruct::{self as protocol, DurableIo, JournalBinding, JournalTicket, ReadSeek},
    retained_compare::{RetainedCompareRequest, RetainedRangeRequest},
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    rc::Rc,
};

const MARKER_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    WriteError(usize),
    ShortThenError(usize),
    SyncError,
    ReadbackError,
    ReadbackMismatch,
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Sync(&'static str),
    PublicationWrite { offset: u64, requested: usize },
    PublicationReadback,
}

struct Memory {
    bytes: Cursor<Vec<u8>>,
    role: &'static str,
    trace: Rc<RefCell<Vec<Event>>>,
    fault: Fault,
    publication_started: bool,
    publication_synced: bool,
    short_returned: bool,
    writes: usize,
    initial_marker_reads: usize,
    readback_faults: usize,
}

impl Memory {
    fn new(bytes: Vec<u8>, role: &'static str, trace: Rc<RefCell<Vec<Event>>>) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            role,
            trace,
            fault: Fault::None,
            publication_started: false,
            publication_synced: false,
            short_returned: false,
            writes: 0,
            initial_marker_reads: 0,
            readback_faults: 0,
        }
    }

    fn contents(&self) -> &[u8] {
        self.bytes.get_ref()
    }
}

impl Read for Memory {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.role == "journal" && self.bytes.position() == 0 && output.len() == MARKER_BYTES {
            if !self.publication_started {
                self.initial_marker_reads += 1;
            } else if self.publication_synced {
                self.trace.borrow_mut().push(Event::PublicationReadback);
                match self.fault {
                    Fault::ReadbackError => {
                        self.readback_faults += 1;
                        return Err(io::Error::other("injected publication readback error"));
                    }
                    Fault::ReadbackMismatch => {
                        self.readback_faults += 1;
                        let count = self.bytes.read(output)?;
                        output[0] ^= 1; // Only the reply changes, not stored bytes.
                        return Ok(count);
                    }
                    _ => {}
                }
            }
        }
        self.bytes.read(output)
    }
}

impl Seek for Memory {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(position)
    }
}

impl Write for Memory {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let offset = self.bytes.position();
        if self.role == "journal" && (offset == 0 || self.publication_started) {
            self.publication_started = true;
            self.trace.borrow_mut().push(Event::PublicationWrite {
                offset,
                requested: input.len(),
            });
            match self.fault {
                Fault::WriteError(prefix) => {
                    let count = prefix.min(input.len());
                    self.bytes.write_all(&input[..count])?;
                    return Err(io::Error::other("injected publication write error"));
                }
                Fault::ShortThenError(prefix) => {
                    if self.short_returned {
                        return Err(io::Error::other(
                            "injected error after short publication write",
                        ));
                    }
                    self.short_returned = true;
                    let count = prefix.min(input.len());
                    self.bytes.write_all(&input[..count])?;
                    return Ok(count);
                }
                _ => {}
            }
        }
        self.bytes.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ReadSeek for Memory {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.contents().len() as u64)
    }
}

impl DurableIo for Memory {
    fn sync_all(&mut self) -> io::Result<()> {
        self.trace.borrow_mut().push(Event::Sync(self.role));
        if matches!(self.fault, Fault::SyncError)
            && (self.role == "target" || self.publication_started)
        {
            return Err(io::Error::other("injected publication sync error"));
        }
        if self.role == "journal" && self.publication_started {
            self.publication_synced = true;
        }
        Ok(())
    }
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Fixture {
    source: Vec<u8>,
    shadow: Vec<u8>,
    journal: Vec<u8>,
    complete_marker: Vec<u8>,
    ticket: JournalTicket,
    binding: JournalBinding,
}

impl Fixture {
    fn new() -> Self {
        let source = vec![0x31; 16384];
        let mut shadow = source.clone();
        shadow[..4096].fill(0x72);
        shadow[8192..12288].fill(0x73);
        let request = RetainedCompareRequest {
            schema_version: 2,
            sector_size: 4096,
            expected_length: source.len() as u64,
            source_sha256: hash(&source),
            shadow_sha256: hash(&shadow),
            retained_ranges: vec![RetainedRangeRequest {
                offset: 4096,
                length: 4096,
                source_sha256: hash(&source[4096..8192]),
                shadow_sha256: hash(&shadow[4096..8192]),
            }],
            max_change_bytes: 8192,
            max_ranges: 2,
        };
        let binding = JournalBinding {
            experiment_id: "a".repeat(32),
            target_identity_sha256: "1".repeat(64),
            shadow_identity_sha256: "2".repeat(64),
            journal_identity_sha256: "3".repeat(64),
        };
        let trace = Rc::new(RefCell::new(vec![]));
        let mut before = Memory::new(source.clone(), "source", trace.clone());
        let mut after = Memory::new(shadow.clone(), "shadow", trace.clone());
        let mut journal = Memory::new(vec![], "preparation", trace.clone());
        let ticket = protocol::prepare_journal(
            &mut before,
            &mut after,
            &mut journal,
            &request,
            &binding,
            1024 * 1024,
        )
        .unwrap()
        .ticket;
        let bytes = journal.contents().to_vec();
        // Build the exact expected encoding through the public API. The tested
        // target starts at the restored preimage, not an interrupted rollback.
        let mut target = Memory::new(source.clone(), "target", trace.clone());
        let mut completed = Memory::new(bytes.clone(), "journal", trace);
        protocol::mark_rollback_complete_without_shadow(
            &mut target,
            &mut completed,
            &ticket,
            &binding,
        )
        .unwrap();
        let complete_marker = completed.contents()[..MARKER_BYTES].to_vec();
        assert_eq!(&complete_marker[..8], b"N2RABT01");
        assert_eq!(complete_marker[8], 4);
        Self {
            source,
            shadow,
            journal: bytes,
            complete_marker,
            ticket,
            binding,
        }
    }

    fn publication(&self, fault: Fault) -> (Memory, Memory, String) {
        let trace = Rc::new(RefCell::new(vec![]));
        let mut target = Memory::new(self.source.clone(), "target", trace.clone());
        let mut journal = Memory::new(self.journal.clone(), "journal", trace);
        journal.fault = fault;
        let error = protocol::mark_rollback_complete_without_shadow(
            &mut target,
            &mut journal,
            &self.ticket,
            &self.binding,
        )
        .expect_err("failed publication must not report success");
        self.assert_unchanged(&target, &journal);
        let trace = journal.trace.borrow();
        let flush = trace
            .iter()
            .position(|e| *e == Event::Sync("target"))
            .unwrap();
        let publication = trace
            .iter()
            .position(|e| matches!(e, Event::PublicationWrite { .. }))
            .unwrap();
        assert!(flush < publication, "target flush must precede publication");
        assert!(
            journal.initial_marker_reads > 0,
            "initial validation must complete"
        );
        drop(trace);
        (target, journal, error.to_string())
    }

    fn assert_unchanged(&self, target: &Memory, journal: &Memory) {
        assert_eq!(target.contents(), self.source);
        assert_eq!(target.writes, 0, "completion must not write target payload");
        assert_eq!(
            &journal.contents()[MARKER_BYTES..],
            &self.journal[MARKER_BYTES..],
            "intent sector and immutable journal body must remain unchanged"
        );
    }

    fn inspect(
        &self,
        bytes: &[u8],
        binding: &JournalBinding,
        source_hash: &str,
    ) -> anyhow::Result<protocol::CompletedMarkerProof> {
        let trace = Rc::new(RefCell::new(vec![]));
        let mut target = Memory::new(self.source.clone(), "target", trace.clone());
        let mut journal = Memory::new(bytes.to_vec(), "journal", trace);
        let result = protocol::verify_completed_rollback_marker_without_shadow(
            &mut target,
            &mut journal,
            &self.ticket,
            binding,
            self.source.len() as u64,
            source_hash,
        );
        assert_eq!(target.writes, 0);
        assert_eq!(journal.writes, 0);
        result
    }

    fn assert_closed_after_reopen(&self, bytes: &[u8]) {
        for operation in 0..4 {
            let trace = Rc::new(RefCell::new(vec![]));
            let mut target = Memory::new(self.source.clone(), "target", trace.clone());
            let mut shadow = Memory::new(self.shadow.clone(), "shadow", trace.clone());
            let mut journal = Memory::new(bytes.to_vec(), "journal", trace);
            let result = match operation {
                0 => protocol::apply(
                    &mut target,
                    &mut shadow,
                    &mut journal,
                    &self.ticket,
                    &self.binding,
                ),
                1 => protocol::resume(
                    &mut target,
                    &mut shadow,
                    &mut journal,
                    &self.ticket,
                    &self.binding,
                ),
                2 => protocol::rollback(
                    &mut target,
                    &mut shadow,
                    &mut journal,
                    &self.ticket,
                    &self.binding,
                ),
                _ => protocol::rollback_without_shadow(
                    &mut target,
                    &mut journal,
                    &self.ticket,
                    &self.binding,
                ),
            };
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("handoff may have started")
            );
            assert_eq!(target.contents(), self.source);
            assert_eq!(target.writes, 0);
            assert_eq!(journal.contents(), bytes);
            assert_eq!(journal.writes, 0);
        }
    }
}

#[test]
fn every_abt_write_error_prefix_preserves_preimage_and_replay_barrier() {
    let fixture = Fixture::new();
    for prefix in 0..=MARKER_BYTES {
        let (_, journal, error) = fixture.publication(Fault::WriteError(prefix));
        assert!(error.contains("injected publication write error"));
        assert_eq!(
            &journal.contents()[..prefix],
            &fixture.complete_marker[..prefix]
        );
        assert!(
            journal.contents()[prefix..MARKER_BYTES]
                .iter()
                .all(|b| *b == 0)
        );
        let proof = fixture.inspect(journal.contents(), &fixture.binding, &hash(&fixture.source));
        let exact = journal.contents()[..MARKER_BYTES] == fixture.complete_marker;
        assert_eq!(
            proof.is_ok(),
            exact,
            "inspection obeys exact bytes, prefix {prefix}"
        );
        if prefix == 0 {
            let trace = Rc::new(RefCell::new(vec![]));
            let mut target = Memory::new(fixture.source.clone(), "target", trace.clone());
            let mut reopened = Memory::new(journal.contents().to_vec(), "journal", trace);
            protocol::rollback_without_shadow(
                &mut target,
                &mut reopened,
                &fixture.ticket,
                &fixture.binding,
            )
            .unwrap();
            assert_eq!(target.contents(), fixture.source);
            assert!(reopened.contents()[..MARKER_BYTES].iter().all(|b| *b == 0));
        } else {
            fixture.assert_closed_after_reopen(journal.contents());
        }
    }
}

#[test]
fn short_marker_write_then_error_never_reports_completed_publication() {
    let fixture = Fixture::new();
    for prefix in [0, 1, 513, MARKER_BYTES - 1] {
        let (_, journal, _) = fixture.publication(Fault::ShortThenError(prefix));
        assert_eq!(journal.writes, if prefix == 0 { 1 } else { 2 });
        assert_eq!(
            &journal.contents()[..prefix],
            &fixture.complete_marker[..prefix]
        );
        assert!(
            journal.contents()[prefix..MARKER_BYTES]
                .iter()
                .all(|b| *b == 0)
        );
        if prefix != 0 {
            fixture.assert_closed_after_reopen(journal.contents());
        }
    }
}

#[test]
fn full_marker_sync_error_returns_error_but_exact_inspection_is_separate() {
    let fixture = Fixture::new();
    let (_, journal, error) = fixture.publication(Fault::SyncError);
    assert!(error.contains("injected publication sync error"));
    assert_eq!(&journal.contents()[..MARKER_BYTES], fixture.complete_marker);
    fixture.assert_closed_after_reopen(journal.contents());
    let proof = fixture
        .inspect(journal.contents(), &fixture.binding, &hash(&fixture.source))
        .unwrap();
    assert!(proof.marker_exact && proof.target_exact);
    assert!(!proof.shadow_exact && proof.shadow_sha256.is_none());
    // Memory visibility after an error is not proof of physical persistence.
}

#[test]
fn marker_readback_faults_occur_only_after_publication_and_journal_sync() {
    let fixture = Fixture::new();
    for fault in [Fault::ReadbackError, Fault::ReadbackMismatch] {
        let (_, journal, error) = fixture.publication(fault);
        assert!(error.contains(match fault {
            Fault::ReadbackError => "injected publication readback error",
            _ => "rollback-complete marker readback differs",
        }));
        assert_eq!(journal.readback_faults, 1);
        let trace = journal.trace.borrow();
        let sync = trace
            .iter()
            .position(|e| *e == Event::Sync("journal"))
            .unwrap();
        let readback = trace
            .iter()
            .position(|e| *e == Event::PublicationReadback)
            .unwrap();
        assert!(sync < readback);
        drop(trace);
        assert_eq!(&journal.contents()[..MARKER_BYTES], fixture.complete_marker);
        fixture.assert_closed_after_reopen(journal.contents());
        fixture
            .inspect(journal.contents(), &fixture.binding, &hash(&fixture.source))
            .unwrap();
    }
}

#[test]
fn inspection_after_failed_publication_requires_exact_source_hash_and_binding() {
    let fixture = Fixture::new();
    let (_, journal, _) = fixture.publication(Fault::SyncError);
    assert!(
        fixture
            .inspect(journal.contents(), &fixture.binding, &"0".repeat(64))
            .is_err()
    );
    let mut foreign = fixture.binding.clone();
    foreign.target_identity_sha256 = "4".repeat(64);
    assert!(
        fixture
            .inspect(journal.contents(), &foreign, &hash(&fixture.source))
            .is_err()
    );
    let trace = Rc::new(RefCell::new(vec![]));
    let mut changed = fixture.source.clone();
    changed[4096] ^= 1;
    let mut target = Memory::new(changed.clone(), "target", trace.clone());
    let mut reopened = Memory::new(journal.contents().to_vec(), "journal", trace);
    let error = protocol::verify_completed_rollback_marker_without_shadow(
        &mut target,
        &mut reopened,
        &fixture.ticket,
        &fixture.binding,
        fixture.source.len() as u64,
        &hash(&fixture.source),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("completed NTFS rollback target differs")
    );
    assert_eq!(target.contents(), changed);
    assert_eq!(target.writes, 0);
    assert_eq!(reopened.contents(), journal.contents());
    assert_eq!(reopened.writes, 0);
    // These refusals start from a full marker left by a failed call; the
    // existing completed/corrupt-marker tests cover static marker corruption.
}

#[test]
fn target_flush_error_prevents_any_marker_publication() {
    let fixture = Fixture::new();
    let trace = Rc::new(RefCell::new(vec![]));
    let mut target = Memory::new(fixture.source.clone(), "target", trace.clone());
    target.fault = Fault::SyncError;
    let mut journal = Memory::new(fixture.journal.clone(), "journal", trace.clone());
    let error = protocol::mark_rollback_complete_without_shadow(
        &mut target,
        &mut journal,
        &fixture.ticket,
        &fixture.binding,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected publication sync error")
    );
    assert_eq!(target.contents(), fixture.source);
    assert_eq!(target.writes, 0);
    assert_eq!(journal.contents(), fixture.journal);
    assert_eq!(journal.writes, 0);
    assert_eq!(*trace.borrow(), vec![Event::Sync("target")]);
}
