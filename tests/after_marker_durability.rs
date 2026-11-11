//! Actual completed-marker guard over an in-memory journal with separate
//! working/stable vectors. Only successful sync copies working to stable.
//! This qualifies this guard's model, not Windows, hardware or native mounts.
use ntfs2refs::{
    lab_reconstruct::{
        self as protocol, CompletedMarkerProof, CompletionKind, DurableIo, JournalBinding,
        JournalTicket, ReadSeek,
    },
    retained_compare::{RetainedCompareRequest, RetainedRangeRequest},
};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    rc::Rc,
};

const MARKER: usize = 4096;
const BODY: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Refs,
    NtfsWithShadow,
    NtfsWithoutShadow,
}
const CASES: [Case; 3] = [Case::Refs, Case::NtfsWithShadow, Case::NtfsWithoutShadow];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    SyncError,
    ChangeMarkerOnSync,
    ChangeBodyOnSync,
    ChangeLengthOnSync,
    ChangeBindingOnSync,
    MarkerReadErrorAfterSync,
    MarkerReadMismatchAfterSync,
    ObserveErrorBeforeSync,
    ObserveErrorAfterSync,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Write(u64, usize),
    Read {
        offset: u64,
        length: usize,
        after_guard_sync: bool,
    },
    SyncStarted,
    SyncFailed,
    SyncSucceeded,
    ExternalMutation,
    ObserveBinding {
        after_guard_sync: bool,
    },
    Mount,
}

struct Data {
    bytes: Cursor<Vec<u8>>,
    reads: usize,
    writes: usize,
    syncs: usize,
}
impl Data {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            reads: 0,
            writes: 0,
            syncs: 0,
        }
    }
}
impl Read for Data {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.bytes.read(bytes)
    }
}
impl Seek for Data {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(position)
    }
}
impl Write for Data {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.bytes.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl ReadSeek for Data {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.bytes.get_ref().len() as u64)
    }
}
impl DurableIo for Data {
    fn sync_all(&mut self) -> io::Result<()> {
        self.syncs += 1;
        Ok(())
    }
}

struct Journal {
    working: Cursor<Vec<u8>>,
    stable: Vec<u8>,
    actual_binding: JournalBinding,
    trace: Rc<RefCell<Vec<Event>>>,
    fail_setup_sync_once: bool,
    armed: bool,
    after_guard_sync: bool,
    fault: Fault,
    writes: usize,
    syncs: usize,
    marker_read_faults: usize,
    observations: usize,
}
impl Journal {
    fn new(binding: JournalBinding, trace: Rc<RefCell<Vec<Event>>>) -> Self {
        Self {
            working: Cursor::new(vec![]),
            stable: vec![],
            actual_binding: binding,
            trace,
            fail_setup_sync_once: false,
            armed: false,
            after_guard_sync: false,
            fault: Fault::None,
            writes: 0,
            syncs: 0,
            marker_read_faults: 0,
            observations: 0,
        }
    }
    fn arm(&mut self, fault: Fault) {
        self.trace.borrow_mut().clear();
        self.armed = true;
        self.after_guard_sync = false;
        self.fault = fault;
        self.writes = 0;
        self.syncs = 0;
        self.marker_read_faults = 0;
        self.observations = 0;
    }
    fn observe_binding(&mut self) -> anyhow::Result<JournalBinding> {
        self.observations += 1;
        self.trace.borrow_mut().push(Event::ObserveBinding {
            after_guard_sync: self.after_guard_sync,
        });
        if matches!(self.fault, Fault::ObserveErrorBeforeSync) && !self.after_guard_sync
            || matches!(self.fault, Fault::ObserveErrorAfterSync) && self.after_guard_sync
        {
            anyhow::bail!("injected binding observation error");
        }
        Ok(self.actual_binding.clone())
    }
}
impl Read for Journal {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let offset = self.working.position();
        self.trace.borrow_mut().push(Event::Read {
            offset,
            length: output.len(),
            after_guard_sync: self.after_guard_sync,
        });
        if self.armed && self.after_guard_sync && offset == 0 && output.len() == MARKER {
            match self.fault {
                Fault::MarkerReadErrorAfterSync => {
                    self.marker_read_faults += 1;
                    return Err(io::Error::other("injected post-sync marker read error"));
                }
                Fault::MarkerReadMismatchAfterSync => {
                    self.marker_read_faults += 1;
                    let count = self.working.read(output)?;
                    assert!(count > 0);
                    output[0] ^= 1; // Read reply only; both stored vectors stay intact.
                    return Ok(count);
                }
                _ => {}
            }
        }
        self.working.read(output)
    }
}
impl Seek for Journal {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.working.seek(position)
    }
}
impl Write for Journal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.trace
            .borrow_mut()
            .push(Event::Write(self.working.position(), bytes.len()));
        self.working.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl ReadSeek for Journal {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.working.get_ref().len() as u64)
    }
}
impl DurableIo for Journal {
    fn sync_all(&mut self) -> io::Result<()> {
        self.syncs += 1;
        self.trace.borrow_mut().push(Event::SyncStarted);
        if self.fail_setup_sync_once || self.armed && self.fault == Fault::SyncError {
            self.fail_setup_sync_once = false;
            self.trace.borrow_mut().push(Event::SyncFailed);
            return Err(io::Error::other(
                "injected non-persisting journal sync error",
            ));
        }
        if self.armed {
            match self.fault {
                Fault::ChangeMarkerOnSync => {
                    self.working.get_mut()[0] ^= 1;
                    self.trace.borrow_mut().push(Event::ExternalMutation);
                }
                Fault::ChangeBodyOnSync => {
                    self.working.get_mut()[BODY] ^= 1;
                    self.trace.borrow_mut().push(Event::ExternalMutation);
                }
                Fault::ChangeLengthOnSync => {
                    self.working.get_mut().pop();
                    self.trace.borrow_mut().push(Event::ExternalMutation);
                }
                Fault::ChangeBindingOnSync => {
                    self.actual_binding.journal_identity_sha256 = "4".repeat(64);
                    self.trace.borrow_mut().push(Event::ExternalMutation);
                }
                _ => {}
            }
        }
        self.stable.clone_from(self.working.get_ref());
        self.after_guard_sync = self.armed;
        self.trace.borrow_mut().push(Event::SyncSucceeded);
        Ok(())
    }
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Setup {
    source: Data,
    target: Data,
    shadow: Option<Data>,
    journal: Journal,
    ticket: JournalTicket,
    binding: JournalBinding,
    proof: CompletedMarkerProof,
}
impl Setup {
    fn cached_marker(case: Case) -> Self {
        let original = vec![0x31; 16384];
        let mut refs = original.clone();
        refs[..4096].fill(0x72);
        refs[8192..12288].fill(0x73);
        let binding = JournalBinding {
            journal_capacity_bytes: None,
            experiment_id: "a".repeat(32),
            source_resource_profile: None,
            target_identity_sha256: "1".repeat(64),
            shadow_identity_sha256: "2".repeat(64),
            journal_identity_sha256: "3".repeat(64),
        };
        let request = RetainedCompareRequest {
            schema_version: 2,
            sector_size: 4096,
            expected_length: original.len() as u64,
            source_sha256: hash(&original),
            shadow_sha256: hash(&refs),
            retained_ranges: vec![RetainedRangeRequest {
                offset: 4096,
                length: 4096,
                source_sha256: hash(&original[4096..8192]),
                shadow_sha256: hash(&refs[4096..8192]),
            }],
            max_change_bytes: 8192,
            max_ranges: 2,
        };
        let trace = Rc::new(RefCell::new(vec![]));
        let mut source = Data::new(original.clone());
        let mut target = Data::new(original.clone());
        let mut shadow = Data::new(refs.clone());
        let mut journal = Journal::new(binding.clone(), trace);
        let ticket = protocol::prepare_journal(
            &mut source,
            &mut shadow,
            &mut journal,
            &request,
            &binding,
            1024 * 1024,
        )
        .unwrap()
        .ticket;
        protocol::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding).unwrap();
        if case == Case::NtfsWithShadow {
            protocol::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding).unwrap();
        } else if case == Case::NtfsWithoutShadow {
            protocol::rollback_without_shadow(&mut target, &mut journal, &ticket, &binding)
                .unwrap();
        }
        journal.fail_setup_sync_once = true;
        let publication = match case {
            Case::Refs => {
                protocol::mark_handoff(&mut target, &mut shadow, &mut journal, &ticket, &binding)
            }
            Case::NtfsWithShadow => protocol::mark_rollback_complete(
                &mut target,
                &mut shadow,
                &mut journal,
                &ticket,
                &binding,
            ),
            Case::NtfsWithoutShadow => protocol::mark_rollback_complete_without_shadow(
                &mut target,
                &mut journal,
                &ticket,
                &binding,
            ),
        };
        assert!(
            publication
                .unwrap_err()
                .to_string()
                .contains("non-persisting journal sync error"),
            "{case:?}"
        );
        assert!(journal.stable[..MARKER].iter().all(|byte| *byte == 0));
        assert!(
            journal.working.get_ref()[..MARKER]
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(
            journal.stable[MARKER..],
            journal.working.get_ref()[MARKER..]
        );
        let proof = match case {
            Case::Refs | Case::NtfsWithShadow => protocol::verify_completed_marker(
                &mut target,
                &mut shadow,
                &mut journal,
                &ticket,
                &binding,
                if case == Case::Refs {
                    CompletionKind::Refs
                } else {
                    CompletionKind::NtfsRollback
                },
                original.len() as u64,
                if case == Case::Refs {
                    &request.shadow_sha256
                } else {
                    &request.source_sha256
                },
                &request.shadow_sha256,
            )
            .unwrap(),
            Case::NtfsWithoutShadow => protocol::verify_completed_rollback_marker_without_shadow(
                &mut target,
                &mut journal,
                &ticket,
                &binding,
                original.len() as u64,
                &request.source_sha256,
            )
            .unwrap(),
        };
        assert!(proof.marker_exact && proof.target_exact);
        assert_eq!(proof.shadow_exact, case != Case::NtfsWithoutShadow);
        assert_eq!(
            proof.shadow_sha256.is_none(),
            case == Case::NtfsWithoutShadow
        );
        assert_eq!(source.bytes.get_ref(), &original);
        journal.arm(Fault::None); // Only guard events and writes are tested below.
        Self {
            source,
            target,
            shadow: (case != Case::NtfsWithoutShadow).then_some(shadow),
            journal,
            ticket,
            binding,
            proof,
        }
    }
    fn data_state(&self) -> Vec<(Vec<u8>, usize, usize, usize)> {
        let mut state = vec![
            (
                self.source.bytes.get_ref().clone(),
                self.source.reads,
                self.source.writes,
                self.source.syncs,
            ),
            (
                self.target.bytes.get_ref().clone(),
                self.target.reads,
                self.target.writes,
                self.target.syncs,
            ),
        ];
        if let Some(shadow) = &self.shadow {
            state.push((
                shadow.bytes.get_ref().clone(),
                shadow.reads,
                shadow.writes,
                shadow.syncs,
            ));
        }
        state
    }
    fn guarded_mount(&mut self, mounts: &Cell<usize>) -> anyhow::Result<u8> {
        let trace = self.journal.trace.clone();
        Ok(protocol::guard_completed_marker_durability(
            &mut self.journal,
            &self.ticket,
            &self.binding,
            &self.proof,
            Journal::observe_binding,
        )?
        .with_mount(|| {
            mounts.set(mounts.get() + 1);
            trace.borrow_mut().push(Event::Mount);
            123
        }))
    }
}

#[test]
fn readable_completed_proof_can_precede_marker_persistence_in_each_case() {
    for case in CASES {
        let setup = Setup::cached_marker(case);
        assert!(setup.proof.marker_exact && setup.proof.target_exact);
        assert!(setup.journal.stable[..MARKER].iter().all(|byte| *byte == 0));
        assert_ne!(setup.journal.working.get_ref(), &setup.journal.stable);
        assert_eq!(setup.journal.writes, 0);
    }
}

#[test]
fn failed_guard_sync_never_mounts_or_persists_the_cached_marker() {
    for case in CASES {
        let mut setup = Setup::cached_marker(case);
        setup.journal.arm(Fault::SyncError);
        let data = setup.data_state();
        let working = setup.journal.working.get_ref().clone();
        let stable = setup.journal.stable.clone();
        let mounts = Cell::new(0);
        let error = setup.guarded_mount(&mounts).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("non-persisting journal sync error")
        );
        assert_eq!(mounts.get(), 0, "{case:?}");
        assert_eq!(setup.journal.syncs, 1);
        assert_eq!(setup.journal.writes, 0);
        assert_eq!(setup.journal.working.get_ref(), &working);
        assert_eq!(setup.journal.stable, stable);
        assert_eq!(setup.data_state(), data);
    }
}

#[test]
fn partial_foreign_or_changed_content_and_binding_refuse_before_guard_sync() {
    for case in CASES {
        for change in [
            "zero",
            "partial",
            "foreign-marker",
            "body",
            "binding",
            "proof",
            "proof-marker-flag",
            "proof-target-flag",
            "proof-target-hash",
            "proof-shadow-scope",
        ] {
            let mut setup = Setup::cached_marker(case);
            match change {
                "zero" => setup.journal.working.get_mut()[..MARKER].fill(0),
                "partial" => setup.journal.working.get_mut()[8..MARKER].fill(0),
                "foreign-marker" => setup.journal.working.get_mut()[0] ^= 1,
                "body" => setup.journal.working.get_mut()[BODY] ^= 1,
                "binding" => setup.journal.actual_binding.journal_identity_sha256 = "4".repeat(64),
                "proof" => setup.proof.immutable_journal_sha256 = "0".repeat(64),
                "proof-marker-flag" => setup.proof.marker_exact = false,
                "proof-target-flag" => setup.proof.target_exact = false,
                "proof-target-hash" => setup.proof.target_sha256 = "0".repeat(64),
                "proof-shadow-scope" => {
                    if case == Case::NtfsWithoutShadow {
                        setup.proof.shadow_exact = true;
                    } else {
                        setup.proof.shadow_sha256 = Some("0".repeat(64));
                    }
                }
                _ => unreachable!(),
            }
            let data = setup.data_state();
            let working = setup.journal.working.get_ref().clone();
            let stable = setup.journal.stable.clone();
            let mounts = Cell::new(0);
            assert!(setup.guarded_mount(&mounts).is_err(), "{case:?}/{change}");
            assert_eq!(mounts.get(), 0);
            assert_eq!(setup.journal.syncs, 0, "{case:?}/{change}");
            assert_eq!(setup.journal.writes, 0);
            assert_eq!(setup.journal.working.get_ref(), &working);
            assert_eq!(setup.journal.stable, stable);
            assert_eq!(setup.data_state(), data);
        }
    }
}

#[test]
fn conflicts_across_sync_and_failed_revalidation_never_mount() {
    for case in CASES {
        for fault in [
            Fault::ChangeMarkerOnSync,
            Fault::ChangeBodyOnSync,
            Fault::ChangeLengthOnSync,
            Fault::ChangeBindingOnSync,
            Fault::MarkerReadErrorAfterSync,
            Fault::MarkerReadMismatchAfterSync,
        ] {
            let mut setup = Setup::cached_marker(case);
            setup.journal.arm(fault);
            let data = setup.data_state();
            let mounts = Cell::new(0);
            assert!(setup.guarded_mount(&mounts).is_err(), "{case:?}/{fault:?}");
            assert_eq!(mounts.get(), 0);
            assert_eq!(setup.journal.syncs, 1);
            assert_eq!(setup.journal.writes, 0);
            assert_eq!(setup.journal.stable, *setup.journal.working.get_ref());
            assert_eq!(setup.data_state(), data);
            if matches!(
                fault,
                Fault::MarkerReadErrorAfterSync | Fault::MarkerReadMismatchAfterSync
            ) {
                // The loader may read the lifecycle sector before the exact
                // marker comparison; every post-sync reply is faulted.
                assert!(setup.journal.marker_read_faults > 0, "{case:?}/{fault:?}");
            }
            if fault == Fault::ChangeBindingOnSync {
                assert_eq!(setup.journal.observations, 2);
            }
        }
    }
}

#[test]
fn binding_observation_errors_fail_closed_before_or_after_sync() {
    for case in CASES {
        for fault in [Fault::ObserveErrorBeforeSync, Fault::ObserveErrorAfterSync] {
            let mut setup = Setup::cached_marker(case);
            setup.journal.arm(fault);
            let data = setup.data_state();
            let mounts = Cell::new(0);
            let error = setup.guarded_mount(&mounts).unwrap_err();
            assert!(error.to_string().contains("binding observation error"));
            assert_eq!(mounts.get(), 0);
            assert_eq!(
                setup.journal.syncs,
                usize::from(fault == Fault::ObserveErrorAfterSync)
            );
            assert_eq!(setup.journal.writes, 0);
            assert_eq!(setup.data_state(), data);
        }
    }
}

#[test]
fn guard_persists_identical_journal_then_mounts_after_binding_and_content_revalidation() {
    for case in CASES {
        let mut setup = Setup::cached_marker(case);
        let data = setup.data_state();
        let working = setup.journal.working.get_ref().clone();
        let mounts = Cell::new(0);
        assert_eq!(setup.guarded_mount(&mounts).unwrap(), 123);
        assert_eq!(mounts.get(), 1, "{case:?}");
        assert_eq!(setup.journal.syncs, 1);
        assert_eq!(setup.journal.writes, 0);
        assert_eq!(setup.journal.working.get_ref(), &working);
        assert_eq!(setup.journal.stable, working);
        assert_eq!(setup.data_state(), data); // No additional target/shadow reads or writes.
        let events = setup.journal.trace.borrow();
        let sync = events
            .iter()
            .position(|e| *e == Event::SyncSucceeded)
            .unwrap();
        let mount = events.iter().position(|e| *e == Event::Mount).unwrap();
        let first_binding = events
            .iter()
            .position(|e| {
                matches!(
                    e,
                    Event::ObserveBinding {
                        after_guard_sync: false
                    }
                )
            })
            .unwrap();
        let last_binding = events
            .iter()
            .rposition(|e| {
                matches!(
                    e,
                    Event::ObserveBinding {
                        after_guard_sync: true
                    }
                )
            })
            .unwrap();
        let marker = events
            .iter()
            .rposition(|e| {
                matches!(
                    e,
                    Event::Read {
                        offset: 0,
                        length: MARKER,
                        after_guard_sync: true
                    }
                )
            })
            .unwrap();
        let body_end = BODY as u64 + setup.ticket.immutable_length;
        let mut body_covered = vec![false; setup.ticket.immutable_length as usize];
        let mut last_body_read = None;
        for (index, event) in events.iter().enumerate() {
            if let Event::Read {
                offset,
                length,
                after_guard_sync: true,
            } = event
            {
                let start = (*offset).max(BODY as u64);
                let end = (*offset + *length as u64).min(body_end);
                if start < end {
                    body_covered[(start - BODY as u64) as usize..(end - BODY as u64) as usize]
                        .fill(true);
                    last_body_read = Some(index);
                }
            }
        }
        let body = last_body_read.unwrap();
        assert!(body_covered.iter().all(|covered| *covered));
        assert!(first_binding < sync && sync < last_binding && last_binding < mount);
        assert!(sync < marker && marker < mount && sync < body && body < mount);
        assert!(!events[mount + 1..].iter().any(|e| matches!(
            e,
            Event::Read { .. } | Event::Write(_, _) | Event::SyncStarted
        )));
    }
}
